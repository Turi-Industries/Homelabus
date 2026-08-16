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
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug/hlb-agent");
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
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
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
