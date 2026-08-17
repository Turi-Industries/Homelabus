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

/// Démarre un controller.
///
/// ⚠️ `ouvert` : le controller REFUSE de démarrer sans jeton (§9ter). Les tests qui
/// portent sur la péremption des données, pas sur l'authentification, passent donc en
/// mode ouvert — sinon ils échoueraient pour une raison qui n'est pas la leur.
fn demarrer_avec(port: u16, base: &std::path::Path, ouvert: bool) -> Controller {
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/debug/hlb-controller");
    assert!(bin.exists(), "lance `cargo build` d'abord ({})", bin.display());

    let mut args = vec![
        "--listen".to_string(),
        format!("127.0.0.1:{port}"),
        "--state".to_string(),
        base.to_string_lossy().to_string(),
        "--master-key".to_string(),
        base.with_extension("key").to_string_lossy().to_string(),
    ];
    if ouvert {
        args.push("--insecure-no-auth".into());
    }

    let child = std::process::Command::new(&bin)
        .args(&args)
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

    let mut ctrl = demarrer_avec(port, &base, true);

    let shared = std::sync::Arc::new(hlb_ui::client::Shared::default());
    let mut poller =
        hlb_ui::client::Poller::new(format!("http://127.0.0.1:{port}"), None, 1.0, shared.clone());

    // Le sondage est piloté par la boucle de rendu : ici on la simule, avec une
    // horloge qui avance — exactement comme celle d'egui.
    let mut horloge = 0.0_f64;
    let avancer = |poller: &mut hlb_ui::client::Poller, horloge: &mut f64| {
        *horloge += 0.1;
        poller.tick(*horloge, || {});
        std::thread::sleep(Duration::from_millis(100));
    };

    // 1. Le controller répond : les données sont fiables.
    let mut vu_frais = false;
    for _ in 0..60 {
        avancer(&mut poller, &mut horloge);
        if shared.read(horloge).1.is_trustworthy() {
            vu_frais = true;
            break;
        }
    }
    assert!(vu_frais, "le controller répond, les données doivent être fiables");

    // 2. 🔴 On le tue. L'UI ne doit PAS continuer à faire comme si de rien n'était.
    ctrl.stop();

    let mut vu_perime = false;
    for _ in 0..80 {
        avancer(&mut poller, &mut horloge);
        let (_, f) = shared.read(horloge);
        if !f.is_trustworthy() {
            assert!(
                f.describe().contains("INJOIGNABLE"),
                "🔴 l'écran doit CRIER que le controller est mort : {}",
                f.describe()
            );
            vu_perime = true;
            break;
        }
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

    let mut ctrl = demarrer_avec(port, &base, true);

    let shared = std::sync::Arc::new(hlb_ui::client::Shared::default());
    let mut poller =
        hlb_ui::client::Poller::new(format!("http://127.0.0.1:{port}"), None, 1.0, shared.clone());

    let mut horloge = 0.0_f64;
    let avancer = |poller: &mut hlb_ui::client::Poller, horloge: &mut f64| {
        *horloge += 0.1;
        poller.tick(*horloge, || {});
        std::thread::sleep(Duration::from_millis(100));
    };

    let mut sante = None;
    for _ in 0..60 {
        avancer(&mut poller, &mut horloge);
        let (d, f) = shared.read(horloge);
        if f.is_trustworthy() {
            sante = d.health.clone();
            break;
        }
    }
    assert!(sante.is_some(), "le controller doit avoir répondu");

    ctrl.stop();

    for _ in 0..80 {
        avancer(&mut poller, &mut horloge);
        let (d, f) = shared.read(horloge);
        if !f.is_trustworthy() {
            // Les données sont TOUJOURS là…
            assert!(d.health.is_some(), "le dernier état connu reste disponible");
            // …mais elles ne sont plus présentées comme fiables.
            assert!(!f.is_trustworthy());
            return;
        }
    }
    panic!("la péremption n'a jamais été détectée");
}

/// Sans jeton, l'écran dit-il quoi faire ? (§9ter)
///
/// 🔴 Le cas le plus fréquent après un déploiement : l'API est protégée, l'UI n'a pas
/// de jeton, et l'utilisateur voit… quoi ? Un écran vide le laisserait conclure à une
/// panne du controller, et il irait chercher au mauvais endroit.
#[test]
#[ignore = "démarre un vrai controller"]
fn without_a_token_the_screen_says_how_to_get_one() {
    let d = tempfile::tempdir().expect("répertoire");
    let base = d.path().join("hlb.db");
    let port = 8435u16;

    // Un controller protégé : on lui dépose un jeton pour qu'il accepte de démarrer,
    // mais l'UI ne l'aura pas.
    {
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            let st = hlb_state::State::open(&base).await.expect("base");
            let (_, jeton) =
                hlb_types::generate_token("autre", hlb_types::Role::Viewer, [7u8; 32]);
            st.store_token(&jeton).await.expect("jeton");
        });
    }

    let mut ctrl = demarrer_avec(port, &base, false);

    let shared = std::sync::Arc::new(hlb_ui::client::Shared::default());
    let mut poller =
        hlb_ui::client::Poller::new(format!("http://127.0.0.1:{port}"), None, 1.0, shared.clone());

    let mut horloge = 0.0_f64;
    for _ in 0..60 {
        horloge += 0.1;
        poller.tick(horloge, || {});
        std::thread::sleep(Duration::from_millis(100));

        let (_, f) = shared.read(horloge);
        // ⚠️ `NeverSucceeded` et non `Stale` : il n'y a jamais eu de réussite, donc
        // pas d'« âge » des données. Les confondre laissait l'écran sur
        // « connexion en cours… » — le bug que ce test a trouvé.
        if let hlb_ui::client::Freshness::NeverSucceeded { error } = &f {
            // Le message doit porter l'ACTION, pas seulement le constat.
            assert!(
                error.contains("hlb token create"),
                "🔴 l'écran doit dire comment obtenir un jeton : « {error} »"
            );
            assert!(
                error.contains("#token="),
                "et comment le donner à l'UI web : « {error} »"
            );
            ctrl.stop();
            return;
        }
    }
    ctrl.stop();
    panic!("l'absence de jeton n'a jamais été signalée");
}
