//! Le tableau de bord ment-il quand le controller tombe ? (§11bis)
//!
//! 🔴 C'est LE test de cette UI. Une interface qui interroge périodiquement et garde
//! son dernier état connu affiche, quand la source disparaît, exactement l'écran d'un
//! système en bonne santé : toutes les apps vertes, les sauvegardes récentes. Au
//! moment précis où on a besoin d'elle, elle rassure à tort.
//!
//! Ces tests démarrent un vrai controller, le tuent, et vérifient que l'UI le dit.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

/// Un controller qui s'arrête tout seul, même si le test panique.
struct Controller(Option<std::process::Child>);

impl Controller {
    fn stop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.stop();
    }
}

fn demarrer(port: u16, base: &std::path::Path) -> Controller {
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug/hlb-controller");
    assert!(bin.exists(), "lance `cargo build` d'abord ({})", bin.display());

    let child = std::process::Command::new(&bin)
        .args([
            "--listen", &format!("127.0.0.1:{port}"),
            "--state", &base.to_string_lossy(),
            "--master-key", &base.with_extension("key").to_string_lossy(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("démarrage du controller");

    let mut g = Controller(Some(child));
    for _ in 0..60 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return g;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    g.stop();
    panic!("le controller n'a pas démarré");
}

#[test]
#[ignore = "démarre un vrai controller"]
fn a_dead_controller_makes_the_dashboard_say_so() {
    let d = tempfile::tempdir().expect("répertoire");
    let base = d.path().join("hlb.db");
    let port = 8433u16;

    let mut ctrl = demarrer(port, &base);

    let shared = std::sync::Arc::new(hlb_ui::client::Shared::default());
    let c = hlb_ui::client::Client::new(format!("http://127.0.0.1:{port}"), None);
    hlb_ui::client::spawn_poller(c, shared.clone(), Duration::from_millis(200), || {});

    // 1. Le controller répond : les données sont fiables.
    let mut vu_frais = false;
    for _ in 0..40 {
        if shared.read().1.is_trustworthy() {
            vu_frais = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(vu_frais, "le controller répond, les données doivent être fiables");

    // 2. 🔴 On le tue. L'UI ne doit PAS continuer à faire comme si de rien n'était.
    ctrl.stop();

    let mut vu_perime = false;
    for _ in 0..50 {
        let (_, f) = shared.read();
        if !f.is_trustworthy() {
            assert!(
                f.describe().contains("INJOIGNABLE"),
                "🔴 l'écran doit CRIER que le controller est mort : {}",
                f.describe()
            );
            vu_perime = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        vu_perime,
        "🔴 le tableau de bord affiche toujours ses données comme fiables alors que \
         le controller est mort — c'est l'écran d'un système sain au moment où il ment"
    );
}

#[test]
#[ignore = "démarre un vrai controller"]
fn the_last_known_state_is_kept_but_marked() {
    // Garder les données est utile — c'est la meilleure information disponible. Ce
    // qu'il ne faut pas, c'est les présenter comme actuelles.
    let d = tempfile::tempdir().expect("répertoire");
    let base = d.path().join("hlb.db");
    let port = 8434u16;

    let mut ctrl = demarrer(port, &base);

    let shared = std::sync::Arc::new(hlb_ui::client::Shared::default());
    let c = hlb_ui::client::Client::new(format!("http://127.0.0.1:{port}"), None);
    hlb_ui::client::spawn_poller(c, shared.clone(), Duration::from_millis(200), || {});

    let mut sante = None;
    for _ in 0..40 {
        let (d, f) = shared.read();
        if f.is_trustworthy() {
            sante = d.health.clone();
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(sante.is_some(), "le controller doit avoir répondu");

    ctrl.stop();

    for _ in 0..50 {
        let (d, f) = shared.read();
        if !f.is_trustworthy() {
            // Les données sont TOUJOURS là…
            assert!(d.health.is_some(), "le dernier état connu reste disponible");
            // …mais elles ne sont plus présentées comme fiables.
            assert!(!f.is_trustworthy());
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("la péremption n'a jamais été détectée");
}
