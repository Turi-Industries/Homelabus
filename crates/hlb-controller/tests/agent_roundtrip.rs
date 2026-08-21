//! Le chemin complet controller → agent, contre un vrai binaire.
//!
//! Ce test est né d'un accident : un agent lancé à la main traînait sur le port
//! 8421, et un test censé vérifier l'échec de connexion a reçu une vraie réponse.
//! Plutôt que de simplement corriger le test, autant vérifier délibérément ce que
//! l'accident avait prouvé.
//!
//! ```sh
//! cargo test -p hlb-controller --test agent_roundtrip -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

/// Un agent qui s'arrête tout seul, même si le test panique.
///
/// Sans ce garde, un test qui échoue laisse un agent orphelin sur le port — et le
/// test suivant reçoit sa réponse. C'est exactement le piège qui m'a fait écrire ce
/// fichier : un agent oublié faisait passer un test censé vérifier une absence.
struct AgentGuard(Option<std::process::Child>);

impl AgentGuard {
    fn stop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Démarre l'agent compilé du dépôt et attend qu'il réponde.
async fn start_agent(port: u16) -> AgentGuard {
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/hlb-agent");
    assert!(
        bin.exists(),
        "binaire absent : lance `cargo build` d'abord ({})",
        bin.display()
    );

    let child = std::process::Command::new(&bin)
        .args(["--listen", &format!("127.0.0.1:{port}"), "--watch", "/"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("démarrage de l'agent");

    let mut garde = AgentGuard(Some(child));
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return garde;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    garde.stop();
    panic!("l'agent n'a pas démarré à temps");
}

#[tokio::test]
#[ignore = "démarre un vrai agent"]
async fn the_controller_reads_a_real_agent_report() {
    let port = 18421;
    let _agent = start_agent(port).await;

    let poller = hlb_controller::AgentPoller::new(port, Duration::from_secs(5));
    let statut = poller.poll("127.0.0.1").await;

    let rapport = statut
        .report()
        .unwrap_or_else(|| panic!("agent injoignable : {}", statut.describe()));

    // L'agent doit rapporter au moins un système de fichiers réel.
    assert!(!rapport.disks.is_empty(), "aucun disque rapporté");
    assert!(rapport.disks[0].total_mb > 0);
    assert!(!rapport.agent_version.is_empty());

    // Et l'occupation doit être plausible : ni 0 %, ni au-delà de 100 %.
    let p = rapport.disks[0].used_percent();
    assert!(p > 0.0 && p <= 100.0, "occupation aberrante : {p:.1} %");

    println!(
        "✓ rapport reçu : {} — {:.1} % occupé, agent {}",
        rapport.hostname, p, rapport.agent_version
    );
}

#[tokio::test]
#[ignore = "démarre un vrai agent"]
async fn a_stopped_agent_becomes_unreachable() {
    // 🔴 Ce qui compte : après l'arrêt, on doit dire « injoignable » et surtout
    // PAS continuer à servir le dernier rapport connu comme s'il était frais.
    let port = 18422;
    let mut agent = start_agent(port).await;
    let poller = hlb_controller::AgentPoller::new(port, Duration::from_secs(5));

    assert!(poller.poll("127.0.0.1").await.report().is_some());

    agent.stop();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let statut = poller.poll("127.0.0.1").await;
    assert!(statut.report().is_none(), "l'agent arrêté répond encore ?");
    assert!(!statut.allows_deploy(&hlb_agent::Thresholds::default()));
    println!("✓ agent arrêté → {}", statut.describe());
}

/// Le controller parle-t-il vraiment en mTLS à un vrai agent ? (§2)
///
/// 🔴 Le test qui compte : les deux binaires, une vraie poignée de main, et un
/// client anonyme refusé. Une configuration mTLS mal faite donne exactement les
/// mêmes apparences qu'une bonne — seule une connexion réellement refusée prouve
/// quelque chose.
#[tokio::test]
#[ignore = "démarre un vrai agent"]
async fn the_controller_polls_a_real_agent_over_mtls() {
    use hlb_agent::pki::{self, Purpose};

    let d = tempfile::tempdir().expect("répertoire");
    let ca = pki::generate_ca("CA de test").await.expect("CA");
    let agent = pki::issue(
        &ca,
        "localhost",
        &["localhost".into(), "127.0.0.1".into()],
        Purpose::Server,
    )
    .await
    .expect("certificat agent");
    let controller = pki::issue(&ca, "controller", &["controller".into()], Purpose::Client)
        .await
        .expect("certificat controller");

    let ecrire = |nom: &str, c: &str| {
        let p = d.path().join(nom);
        std::fs::write(&p, c).expect("écriture");
        p
    };
    let p_ca = ecrire("ca.crt", &ca.cert_pem);
    let p_crt = ecrire("agent.crt", &agent.cert_pem);
    let p_key = ecrire("agent.key", &agent.key_pem);

    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/hlb-agent");
    let port = 8497u16;

    let child = std::process::Command::new(&bin)
        .args([
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--watch",
            "/",
            "--cert",
            &p_crt.to_string_lossy(),
            "--key",
            &p_key.to_string_lossy(),
            "--ca",
            &p_ca.to_string_lossy(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("démarrage de l'agent");

    let mut garde = AgentGuard(Some(child));
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 1. Le controller légitime obtient bien un rapport.
    let poller = hlb_controller::AgentPoller::with_mtls(
        port,
        Duration::from_secs(5),
        &format!("{}{}", controller.cert_pem, controller.key_pem),
        &ca.cert_pem,
    )
    .expect("poller mTLS");

    assert!(poller.is_secure(), "le poller doit être en https");

    let s = poller.poll("localhost").await;
    let rapport = s.report().unwrap_or_else(|| {
        panic!(
            "le controller légitime doit obtenir un rapport : {}",
            s.describe()
        )
    });
    assert!(
        !rapport.disks.is_empty(),
        "un rapport sans disque n'est pas normal"
    );

    // 2. 🔴 Un poller SANS certificat doit être refusé. C'est le conteneur compromis
    //    de l'overlay : il voit l'agent, il ne doit rien en tirer.
    let anonyme = hlb_controller::AgentPoller::new(port, Duration::from_secs(5));
    let s = anonyme.poll("localhost").await;
    assert!(
        s.report().is_none(),
        "🔴 un client sans certificat a obtenu un rapport — le mTLS ne protège rien"
    );

    // 3. Un certificat d'une autre autorité ne vaut pas mieux.
    let autre = pki::generate_ca("CA de l'attaquant").await.expect("CA");
    let intrus = pki::issue(&autre, "intrus", &["intrus".into()], Purpose::Client)
        .await
        .expect("intrus");
    let faux = hlb_controller::AgentPoller::with_mtls(
        port,
        Duration::from_secs(5),
        &format!("{}{}", intrus.cert_pem, intrus.key_pem),
        &ca.cert_pem,
    )
    .expect("poller");
    assert!(
        faux.poll("localhost").await.report().is_none(),
        "🔴 un certificat d'une autre CA a été accepté"
    );

    garde.stop();
}
