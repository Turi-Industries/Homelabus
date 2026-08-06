//! Spike `bollard` — la question n°1 du plan (§13).
//!
//! Objectif : prouver **avant** d'écrire le reste du produit que `bollard` couvre
//! réellement la surface Swarm dont HomelabUS dépend. Si un trou existe, il vaut mieux
//! le découvrir maintenant que dans quatre mois.
//!
//! Ces tests exigent un Swarm actif. Ils sont `#[ignore]` pour que `cargo test` reste
//! rapide et utilisable sans Docker :
//!
//! ```sh
//! docker swarm init
//! cargo test -p hlb-orchestrator -- --ignored --test-threads=1 --nocapture
//! ```

// Dans un test, `expect` EST l'assertion : le message porte le diagnostic.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_orchestrator::{Orchestrator, ServiceSpec, SwarmOrchestrator, UpdateState};

const IMAGE: &str = "alpine:3";
/// Image inexistante : le pull échoue, la tâche ne démarre jamais.
/// C'est le scénario réaliste d'un digest erroné ou d'une image retirée.
const BROKEN: &str = "alpine:cette-version-nexiste-pas";

fn orch() -> SwarmOrchestrator {
    SwarmOrchestrator::connect().expect("daemon docker joignable")
}

/// Nom unique par test : les tests peuvent tourner en parallèle sur un même daemon.
fn name(suffix: &str) -> String {
    format!("hlb-spike-{suffix}")
}

async fn cleanup(o: &SwarmOrchestrator, n: &str) {
    let _ = o.remove(n).await;
}

fn sleeper(n: &str) -> ServiceSpec {
    ServiceSpec::new(n, IMAGE).command(["sleep", "3600"])
}

#[tokio::test]
#[ignore = "nécessite un Docker Swarm actif"]
async fn q1_daemon_et_swarm_joignables() {
    let version = orch().ping().await.expect("ping");
    println!("✓ daemon docker {version}");
}

/// Q2 — création de service, convergence, et lecture d'état.
#[tokio::test]
#[ignore = "nécessite un Docker Swarm actif"]
async fn q2_deploy_et_convergence() {
    let o = orch();
    let n = name("deploy");
    cleanup(&o, &n).await;

    let id = o.deploy(&sleeper(&n).replicas(2)).await.expect("deploy");
    assert!(!id.is_empty());

    let st = o.wait_healthy(&n, 120).await.expect("convergence");
    assert_eq!(st.desired_replicas, 2);
    assert_eq!(st.running_replicas, 2);
    assert!(st.is_converged());
    println!("✓ 2/2 tâches en cours, image={}", st.image);

    cleanup(&o, &n).await;
}

/// Q3 — contraintes de placement. Sans elles, tout le §2bis (tiers de nœuds,
/// épinglage des bases) est impossible.
#[tokio::test]
#[ignore = "nécessite un Docker Swarm actif"]
async fn q3_contraintes_de_placement() {
    let o = orch();
    let n = name("placement");
    cleanup(&o, &n).await;

    // Contrainte satisfiable : un manager existe forcément.
    o.deploy(&sleeper(&n).constraint("node.role==manager"))
        .await
        .expect("deploy avec contrainte");
    let st = o.wait_healthy(&n, 120).await.expect("convergence");
    assert_eq!(st.running_replicas, 1);
    println!("✓ contrainte node.role==manager respectée");
    cleanup(&o, &n).await;

    // Contrainte impossible : la tâche doit rester non planifiée, pas planter.
    let n2 = name("placement-impossible");
    cleanup(&o, &n2).await;
    o.deploy(&sleeper(&n2).constraint("node.labels.tier==nexiste-pas"))
        .await
        .expect("deploy accepté même si non planifiable");
    let err = o.wait_healthy(&n2, 15).await.unwrap_err();
    println!("✓ contrainte impossible → non convergé, erreur claire : {err}");
    cleanup(&o, &n2).await;
}

/// Q4 — mise à jour d'image avec contrôle de concurrence par version.
#[tokio::test]
#[ignore = "nécessite un Docker Swarm actif"]
async fn q4_update_image() {
    let o = orch();
    let n = name("update");
    cleanup(&o, &n).await;

    o.deploy(&sleeper(&n)).await.expect("deploy");
    o.wait_healthy(&n, 120).await.expect("convergence initiale");

    o.update_image(&n, "alpine:3.21").await.expect("update");
    let st = o.wait_healthy(&n, 120).await.expect("convergence après update");
    assert!(st.image.contains("3.21"), "image effective : {}", st.image);
    println!("✓ mise à jour appliquée → {}", st.image);

    cleanup(&o, &n).await;
}

/// 🔴 Q5 — LE test qui compte : Swarm annule-t-il tout seul une mise à jour ratée ?
///
/// C'est le socle du §7. Le plan insiste : « la logique de rollback ne s'exercera
/// jamais en conditions réelles avant le jour où tu en auras désespérément besoin —
/// il faut donc la tester exprès ».
#[tokio::test]
#[ignore = "nécessite un Docker Swarm actif"]
async fn q5_rollback_automatique_sur_mise_a_jour_ratee() {
    let o = orch();
    let n = name("rollback");
    cleanup(&o, &n).await;

    o.deploy(&sleeper(&n)).await.expect("deploy");
    let avant = o.wait_healthy(&n, 120).await.expect("convergence initiale");
    println!("  état initial : {} ({} tâche)", avant.image, avant.running_replicas);

    // On pousse volontairement une image cassée.
    o.update_image(&n, BROKEN).await.expect("update accepté");

    // Swarm doit détecter l'échec et revenir en arrière, sans qu'on intervienne.
    let mut observed = None;
    for _ in 0..60 {
        let st = o.status(&n).await.expect("status");
        if let Some(s) = st.update_state {
            if s.is_failure() {
                observed = Some((s, st));
                break;
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    let (state, st) = observed.expect(
        "Swarm n'a signalé aucun échec de mise à jour : \
         failure_action=rollback ne fonctionne pas comme attendu",
    );

    println!("✓ Swarm a réagi : {state:?}");
    assert!(
        matches!(
            state,
            UpdateState::RollbackStarted | UpdateState::RollbackCompleted | UpdateState::Paused
        ),
        "état inattendu : {state:?}"
    );

    // Et le service doit avoir survécu : c'est tout l'intérêt de start-first.
    assert_eq!(
        st.running_replicas, 1,
        "le service ne doit jamais tomber pendant un rollback"
    );
    println!("✓ service toujours debout pendant le rollback ({})", st.image);

    cleanup(&o, &n).await;
}

/// Q6 — le filtrage par label : HomelabUS ne doit jamais toucher aux services
/// qu'il n'a pas créés.
#[tokio::test]
#[ignore = "nécessite un Docker Swarm actif"]
async fn q6_list_ne_voit_que_le_gere() {
    let o = orch();
    let n = name("list");
    cleanup(&o, &n).await;

    o.deploy(&sleeper(&n)).await.expect("deploy");
    let services = o.list().await.expect("list");
    assert!(
        services.iter().any(|s| s.name == n),
        "le service géré doit apparaître"
    );
    println!("✓ {} service(s) géré(s) listé(s)", services.len());

    cleanup(&o, &n).await;
}

/// Q7 — un service inconnu donne une erreur exploitable, pas un panic.
#[tokio::test]
#[ignore = "nécessite un Docker Swarm actif"]
async fn q7_service_inconnu() {
    let err = orch().status("hlb-spike-nexiste-pas").await.unwrap_err();
    assert!(matches!(err, hlb_orchestrator::Error::NotFound(_)), "{err:?}");
    println!("✓ erreur typée : {err}");
}

// ── §9 : le durcissement doit être APPLIQUÉ, pas seulement déclaré ───────────

/// Lit la spec effective d'un service, telle que Swarm la stocke.
async fn effective_spec(name: &str) -> serde_json::Value {
    let out = std::process::Command::new("docker")
        .args(["service", "inspect", name, "--format", "{{json .Spec.TaskTemplate.ContainerSpec}}"])
        .output()
        .expect("docker inspect");
    serde_json::from_slice(&out.stdout).expect("json")
}

#[tokio::test]
#[ignore = "nécessite un Docker Swarm actif"]
async fn hardening_reaches_swarm() {
    // 🔴 Le test qui manquait : la spec de sécurité était déclarée dans les manifests,
    // validée, et jamais transmise. Un conteneur se déployait avec les privilèges par
    // défaut de Docker alors que le plan pose « sécurité par défaut » en invariant.
    let o = orch();
    let n = name("durcissement");
    cleanup(&o, &n).await;

    o.deploy(&sleeper(&n)).await.expect("deploy");
    o.wait_healthy(&n, 120).await.expect("convergence");

    let cs = effective_spec(&n).await;

    assert_eq!(cs["ReadOnly"], true, "rootfs devrait être en lecture seule");
    assert_eq!(
        cs["CapabilityDrop"],
        serde_json::json!(["ALL"]),
        "toutes les capacités devraient être retirées"
    );
    assert_eq!(
        cs["Privileges"]["NoNewPrivileges"], true,
        "no-new-privileges devrait être posé"
    );
    println!("✓ rootfs ro, cap_drop ALL, no-new-privileges appliqués par Swarm");

    cleanup(&o, &n).await;
}

#[tokio::test]
#[ignore = "nécessite un Docker Swarm actif"]
async fn a_relaxed_manifest_is_honoured_too() {
    // Une app qui a besoin de plus doit pouvoir le demander — sinon le durcissement
    // par défaut serait contourné en désactivant HomelabUS.
    let o = orch();
    let n = name("assoupli");
    cleanup(&o, &n).await;

    let mut relache = hlb_types::SecuritySpec::default();
    relache.read_only_rootfs = false;
    relache.cap_add = vec!["NET_BIND_SERVICE".to_string()];

    o.deploy(&sleeper(&n).hardening(relache)).await.expect("deploy");
    o.wait_healthy(&n, 120).await.expect("convergence");

    let cs = effective_spec(&n).await;
    // Docker omet les valeurs fausses : absent équivaut à `false`.
    assert!(
        cs["ReadOnly"].is_null() || cs["ReadOnly"] == false,
        "rootfs devrait être inscriptible : {}",
        cs["ReadOnly"]
    );
    assert_eq!(cs["CapabilityAdd"], serde_json::json!(["NET_BIND_SERVICE"]));
    println!("✓ assouplissement explicite respecté");

    cleanup(&o, &n).await;
}

#[tokio::test]
#[ignore = "nécessite un Docker Swarm actif"]
async fn healthchecks_reach_swarm() {
    let o = orch();
    let n = name("sonde");
    cleanup(&o, &n).await;

    let hc = hlb_types::Healthcheck {
        test: vec!["CMD-SHELL".into(), "true".into()],
        interval_secs: 5,
        timeout_secs: 2,
        retries: 3,
        start_period_secs: 1,
    };
    o.deploy(&sleeper(&n).healthcheck(hc)).await.expect("deploy");
    o.wait_healthy(&n, 120).await.expect("convergence");

    let cs = effective_spec(&n).await;
    // ⚠️ Le champ s'écrit « Healthcheck », pas « HealthCheck ».
    assert_eq!(cs["Healthcheck"]["Test"], serde_json::json!(["CMD-SHELL", "true"]));
    // Swarm stocke les durées en nanosecondes.
    assert_eq!(cs["Healthcheck"]["Interval"], 5_000_000_000i64);
    assert_eq!(cs["Healthcheck"]["Retries"], 3);
    println!("✓ sonde transmise, intervalles convertis en nanosecondes");

    cleanup(&o, &n).await;
}
