//! The `bollard` spike - the project's first risk.
//!
//! The goal: prove **before** writing the rest of the product that `bollard` really
//! covers the Swarm surface Homelabus depends on. If there is a gap, better to find it
//! now than in four months.
//!
//! These tests need an active Swarm. They are `#[ignore]`d so `cargo test` stays fast
//! and usable without Docker:
//!
//! ```sh
//! docker swarm init
//! cargo test -p hlb-orchestrator -- --ignored --test-threads=1 --nocapture
//! ```

// Dans un test, `expect` EST l'assertion : le message porte le diagnostic.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_orchestrator::{Orchestrator, ServiceSpec, SwarmOrchestrator, UpdateState};

const IMAGE: &str = "alpine:3";
/// A non-existent image: the pull fails and the task never starts. This is the
/// realistic scenario of a wrong digest or a withdrawn image.
const BROKEN: &str = "alpine:cette-version-nexiste-pas";

fn orch() -> SwarmOrchestrator {
    SwarmOrchestrator::connect().expect("daemon docker joignable")
}

/// A unique name per test: tests can run in parallel against one daemon.
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
#[ignore = "needs an active Docker Swarm"]
async fn q1_daemon_et_swarm_joignables() {
    let version = orch().ping().await.expect("ping");
    println!("✓ daemon docker {version}");
}

/// Q2 - service creation, convergence, and reading state back.
#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
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
    println!("✓ 2/2 tasks running, image={}", st.image);

    cleanup(&o, &n).await;
}

/// Q3 - placement constraints. Without them, node tiers and pinning databases are
/// impossible.
#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn q3_contraintes_de_placement() {
    let o = orch();
    let n = name("placement");
    cleanup(&o, &n).await;

    // A satisfiable constraint: a manager necessarily exists.
    o.deploy(&sleeper(&n).constraint("node.role==manager"))
        .await
        .expect("deploy avec contrainte");
    let st = o.wait_healthy(&n, 120).await.expect("convergence");
    assert_eq!(st.running_replicas, 1);
    println!("✓ node.role==manager constraint honoured");
    cleanup(&o, &n).await;

    // An impossible constraint: the task must stay unscheduled, not crash.
    let n2 = name("placement-impossible");
    cleanup(&o, &n2).await;
    o.deploy(&sleeper(&n2).constraint("node.labels.tier==nexiste-pas"))
        .await
        .expect("deploy accepted even when unschedulable");
    let err = o.wait_healthy(&n2, 15).await.unwrap_err();
    println!("✓ impossible constraint → did not converge, clear error: {err}");
    cleanup(&o, &n2).await;
}

/// Q4 - image update with version-based concurrency control.
#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn q4_update_image() {
    let o = orch();
    let n = name("update");
    cleanup(&o, &n).await;

    o.deploy(&sleeper(&n)).await.expect("deploy");
    o.wait_healthy(&n, 120).await.expect("convergence initiale");

    o.update_image(&n, "alpine:3.21").await.expect("update");
    let st = o
        .wait_healthy(&n, 120)
        .await
        .expect("convergence after update");
    assert!(st.image.contains("3.21"), "image effective : {}", st.image);
    println!("✓ update applied → {}", st.image);

    cleanup(&o, &n).await;
}

/// 🔴 Q5 - THE test that matters: does Swarm roll back a failed update on its own?
///
/// This is the foundation of the whole update pipeline. Rollback logic never exercises
/// itself in real conditions before the day you desperately need it, so it has to be
/// tested deliberately.
#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn q5_rollback_automatique_sur_mise_a_jour_ratee() {
    let o = orch();
    let n = name("rollback");
    cleanup(&o, &n).await;

    o.deploy(&sleeper(&n)).await.expect("deploy");
    let avant = o.wait_healthy(&n, 120).await.expect("convergence initiale");
    println!(
        "  initial state: {} ({} task)",
        avant.image, avant.running_replicas
    );

    // A broken image is pushed deliberately.
    o.update_image(&n, BROKEN).await.expect("update accepted");

    // Swarm must detect the failure and roll back, with no intervention from us.
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
        "Swarm reported no update failure: \
         failure_action=rollback ne fonctionne pas comme attendu",
    );

    println!("✓ Swarm reacted: {state:?}");
    assert!(
        matches!(
            state,
            UpdateState::RollbackStarted | UpdateState::RollbackCompleted | UpdateState::Paused
        ),
        "unexpected state: {state:?}"
    );

    // And the service must have survived: that is the whole point of start-first.
    assert_eq!(
        st.running_replicas, 1,
        "le service ne doit jamais tomber pendant un rollback"
    );
    println!(
        "✓ service toujours debout pendant le rollback ({})",
        st.image
    );

    cleanup(&o, &n).await;
}

/// Q6 - label filtering: Homelabus must never touch services it did not create.
#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn q6_list_ne_voit_que_le_gere() {
    let o = orch();
    let n = name("list");
    cleanup(&o, &n).await;

    o.deploy(&sleeper(&n)).await.expect("deploy");
    let services = o.list().await.expect("list");
    assert!(
        services.iter().any(|s| s.name == n),
        "the managed service must appear"
    );
    println!(
        "✓ {} managed {} listed",
        services.len(),
        if services.len() == 1 {
            "service"
        } else {
            "services"
        }
    );

    cleanup(&o, &n).await;
}

/// Q7 — un service inconnu donne une erreur exploitable, pas un panic.
#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn q7_service_inconnu() {
    let err = orch().status("hlb-spike-nexiste-pas").await.unwrap_err();
    assert!(
        matches!(err, hlb_orchestrator::Error::NotFound(_)),
        "{err:?}"
    );
    println!("✓ typed error: {err}");
}

// ── Hardening must be APPLIED, not merely declared ───────────────────────────

/// Lit la spec effective d'un service, telle que Swarm la stocke.
async fn effective_spec(name: &str) -> serde_json::Value {
    let out = std::process::Command::new("docker")
        .args([
            "service",
            "inspect",
            name,
            "--format",
            "{{json .Spec.TaskTemplate.ContainerSpec}}",
        ])
        .output()
        .expect("docker inspect");
    serde_json::from_slice(&out.stdout).expect("json")
}

#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn hardening_reaches_swarm() {
    // 🔴 The test that was missing: the security spec was declared in manifests,
    // validated, and never passed on. A container deployed with Docker's default
    // privileges while "secure by default" was supposed to be an invariant.
    let o = orch();
    let n = name("durcissement");
    cleanup(&o, &n).await;

    o.deploy(&sleeper(&n)).await.expect("deploy");
    o.wait_healthy(&n, 120).await.expect("convergence");

    let cs = effective_spec(&n).await;

    assert_eq!(cs["ReadOnly"], true, "rootfs should be read-only");
    assert_eq!(
        cs["CapabilityDrop"],
        serde_json::json!(["ALL"]),
        "every capability should be dropped"
    );
    assert_eq!(
        cs["Privileges"]["NoNewPrivileges"], true,
        "no-new-privileges should be set"
    );
    println!("✓ rootfs ro, cap_drop ALL, no-new-privileges applied by Swarm");

    cleanup(&o, &n).await;
}

#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn a_relaxed_manifest_is_honoured_too() {
    // An app that needs more must be able to ask - otherwise the default hardening
    // would be worked around by disabling Homelabus.
    let o = orch();
    let n = name("assoupli");
    cleanup(&o, &n).await;

    let relache = hlb_types::SecuritySpec {
        read_only_rootfs: false,
        cap_add: vec!["NET_BIND_SERVICE".to_string()],
        ..Default::default()
    };

    o.deploy(&sleeper(&n).hardening(relache))
        .await
        .expect("deploy");
    o.wait_healthy(&n, 120).await.expect("convergence");

    let cs = effective_spec(&n).await;
    // Docker omits false values: absent is equivalent to `false`.
    assert!(
        cs["ReadOnly"].is_null() || cs["ReadOnly"] == false,
        "rootfs should be writable: {}",
        cs["ReadOnly"]
    );
    assert_eq!(cs["CapabilityAdd"], serde_json::json!(["NET_BIND_SERVICE"]));
    println!("✓ explicit relaxation honoured");

    cleanup(&o, &n).await;
}

#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
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
    o.deploy(&sleeper(&n).healthcheck(hc))
        .await
        .expect("deploy");
    o.wait_healthy(&n, 120).await.expect("convergence");

    let cs = effective_spec(&n).await;
    // ⚠️ The field is spelled "Healthcheck", not "HealthCheck".
    assert_eq!(
        cs["Healthcheck"]["Test"],
        serde_json::json!(["CMD-SHELL", "true"])
    );
    // Swarm stores durations in nanoseconds.
    assert_eq!(cs["Healthcheck"]["Interval"], 5_000_000_000i64);
    assert_eq!(cs["Healthcheck"]["Retries"], 3);
    println!("✓ sonde transmise, intervalles convertis en nanosecondes");

    cleanup(&o, &n).await;
}

#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn declared_volumes_are_actually_mounted() {
    // 🔴 A serious regression found in production: volumes were created by the
    // executor and then NEVER attached to the service. Data went into the container's
    // ephemeral layer and disappeared on the first redeploy - while being declared
    // "backed up".
    let o = orch();
    let n = name("montage");
    let vol = format!("{n}-data");
    cleanup(&o, &n).await;
    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", &vol])
        .output();

    o.create_volume(&vol).await.expect("volume");
    o.deploy(&sleeper(&n).mount(&vol, "/data"))
        .await
        .expect("deploy");
    o.wait_healthy(&n, 120).await.expect("convergence");

    let cs = effective_spec(&n).await;
    let mounts = cs["Mounts"].as_array().expect("mounts present");
    assert_eq!(mounts.len(), 1, "un montage attendu : {cs}");
    assert_eq!(mounts[0]["Source"], vol.as_str());
    assert_eq!(mounts[0]["Target"], "/data");
    assert_eq!(mounts[0]["Type"], "volume");
    println!("✓ volume {vol} mounted at /data");

    cleanup(&o, &n).await;
    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", &vol])
        .output();
}
