//! La promesse « n'importe quelle distribution serveur », vérifiée.
//!
//! §12bis : « le test de bootstrap multi-distro […] c'est ce qui rend crédible la
//! promesse du §2ter. Sans lui, "ça marche sur n'importe quelle distro" est une
//! supposition. »
//!
//! On utilise des conteneurs plutôt que des VM : ils suffisent à valider la
//! détection, le choix du gestionnaire de paquets et l'installation réelle. Ce qu'ils
//! ne valident pas — systemd, cgroups, le réseau — est hors de portée de ce module
//! de toute façon.
//!
//! ```sh
//! export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
//! cargo test -p hlb-bootstrap --test multi_distro -- --ignored --test-threads=1 --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_bootstrap::runner::{Output, Result, Runner};
use hlb_bootstrap::{observe, Family};

/// Exécute dans un conteneur, comme le ferait `SshRunner` sur un nœud distant.
struct DockerRunner {
    container: String,
}

#[async_trait::async_trait]
impl Runner for DockerRunner {
    async fn run(&self, argv: &[String]) -> Result<Output> {
        let mut args = vec!["exec".to_string(), self.container.clone()];
        args.extend(argv.iter().cloned());

        let out = tokio::process::Command::new("docker")
            .args(&args)
            .output()
            .await
            .expect("docker joignable (DOCKER_HOST ?)");

        Ok(Output {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        })
    }

    async fn read_file(&self, path: &str) -> Result<Option<String>> {
        let o = self.run(&["cat".into(), path.into()]).await?;
        Ok(o.ok().then_some(o.stdout))
    }

    fn label(&self) -> String {
        self.container.clone()
    }
}

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker joignable")
}

/// L'image est-elle déjà présente localement ?
///
/// Un `docker pull` de plusieurs centaines de mégaoctets au milieu d'un test rend son
/// échec illisible : on préfère ignorer proprement et le dire.
fn image_present(image: &str) -> bool {
    docker(&["image", "inspect", image]).status.success()
}

fn start(nom: &str, image: &str) -> DockerRunner {
    let _ = docker(&["rm", "-f", nom]);
    let out = docker(&["run", "-d", "--name", nom, image, "sleep", "600"]);
    assert!(
        out.status.success(),
        "démarrage de {image} : {}",
        String::from_utf8_lossy(&out.stderr)
    );
    DockerRunner { container: nom.into() }
}

fn stop(nom: &str) {
    let _ = docker(&["rm", "-f", nom]);
}

/// Chaque famille est détectée, avec le bon gestionnaire de paquets.
#[tokio::test]
#[ignore = "nécessite Docker"]
async fn every_supported_family_is_detected() {
    // Les images sont supposées déjà présentes : un `docker pull` de plusieurs
    // centaines de mégaoctets au milieu d'un test rend son échec illisible.
    let cas = [
        ("hlb-d-debian", "debian:12", Family::Debian),
        ("hlb-d-ubuntu", "ubuntu:24.04", Family::Debian),
        ("hlb-d-alpine", "alpine:3", Family::Alpine),
        ("hlb-d-rocky", "rockylinux/rockylinux:9", Family::RedHat),
        ("hlb-d-arch", "archlinux:base", Family::Arch),
    ];

    let mut couvertes = Vec::new();
    let mut ignorees = Vec::new();

    for (nom, image, attendue) in cas {
        if !image_present(image) {
            ignorees.push(image);
            continue;
        }
        let r = start(nom, image);
        let obs = observe(&r).await.expect("observation");
        let rapport = hlb_bootstrap::preflight::run(&obs);

        let d = rapport
            .distro
            .unwrap_or_else(|| panic!("{image} : distribution non identifiée"));

        assert_eq!(d.family, attendue, "{image} mal classée");
        println!(
            "✓ {image:<28} → {} ({:?})",
            d.pretty_name,
            d.package_manager()
        );
        couvertes.push(image);
        stop(nom);
    }

    if !ignorees.is_empty() {
        println!("⚠️  non vérifiées faute d'image locale : {ignorees:?}");
        println!("    (aucun téléchargement n'est déclenché : `docker pull` reste à ta main)");
    }

    // Une image absente est une limite de l'environnement, pas un défaut du code.
    // Mais on refuse de passer pour vert sans avoir rien vérifié du tout.
    assert!(
        !couvertes.is_empty(),
        "aucune image de distribution disponible localement — ce test n'a rien prouvé"
    );
    println!("{} famille(s) vérifiée(s) : {couvertes:?}", couvertes.len());
}

/// Une distribution récente doit passer les préchecks, sauf ce qui ne s'applique pas
/// à un conteneur.
#[tokio::test]
#[ignore = "nécessite Docker"]
async fn preflight_only_blocks_on_real_problems() {
    let r = start("hlb-pf-debian", "debian:12");
    let obs = observe(&r).await.expect("observation");
    let rapport = hlb_bootstrap::preflight::run(&obs);

    // Dans un conteneur, Docker est absent : c'est normal, et ça ne doit PAS bloquer.
    assert!(
        rapport.can_proceed(),
        "blocages inattendus : {:?}",
        rapport.blocking().iter().map(|c| c.name).collect::<Vec<_>>()
    );

    // Le conteneur tourne en root, donc les privilèges passent.
    assert!(obs.is_root);
    // Et la mémoire est bien lue depuis /proc.
    assert!(obs.total_memory_mb.unwrap_or(0) > 0);
    println!("✓ préchecks : {} Mo de RAM, aucun blocage", obs.total_memory_mb.unwrap_or(0));

    stop("hlb-pf-debian");
}

/// 🔴 Le test qui prouve la promesse : installer réellement un paquet, sur trois
/// familles aux gestionnaires différents.
#[tokio::test]
#[ignore = "nécessite Docker"]
async fn a_package_is_actually_installed_on_each_family() {
    let cas = [
        ("hlb-i-debian", "debian:12"),
        ("hlb-i-alpine", "alpine:3"),
        ("hlb-i-rocky", "rockylinux/rockylinux:9"),
    ];

    let mut couvertes = 0;
    for (nom, image) in cas {
        if !image_present(image) {
            println!("⚠️  {image} absente localement — non vérifiée");
            continue;
        }
        let r = start(nom, image);
        let obs = observe(&r).await.expect("observation");
        let d = hlb_bootstrap::preflight::run(&obs)
            .distro
            .unwrap_or_else(|| panic!("{image} non identifiée"));
        let pm = d.package_manager();

        // `ca-certificates` existe sur toutes les familles et s'installe vite.
        if let Some(refresh) = pm.refresh_command() {
            let o = r.run(&refresh).await.expect("rafraîchissement");
            assert!(o.ok(), "{image} : refresh a échoué → {}", o.stderr);
        }

        let o = r
            .run(&pm.install_command(&["ca-certificates"]))
            .await
            .expect("installation");
        assert!(
            o.ok(),
            "{image} : installation échouée → {}",
            o.stderr.lines().take(3).collect::<Vec<_>>().join(" | ")
        );

        // Et on vérifie que le paquet est réellement présent, pas juste que la
        // commande a rendu 0.
        let q = r
            .run(&pm.query_command("ca-certificates"))
            .await
            .expect("interrogation");
        assert!(q.ok(), "{image} : paquet absent après installation");

        println!("✓ {image:<28} {:?} a installé et confirmé le paquet", pm);
        couvertes += 1;
        stop(nom);
    }

    assert!(
        couvertes >= 1,
        "aucune image disponible localement — ce test n'a rien prouvé"
    );
    println!("{couvertes} gestionnaire(s) de paquets vérifié(s) sur une vraie installation");
}

/// Les commandes d'installation ne doivent jamais attendre une saisie.
#[tokio::test]
#[ignore = "nécessite Docker"]
async fn installation_never_waits_for_input() {
    // Sans `-y`, apt pose une question et se bloquerait ici jusqu'au délai du test.
    let r = start("hlb-noint-debian", "debian:12");
    let d = hlb_bootstrap::preflight::run(&observe(&r).await.expect("obs"))
        .distro
        .expect("distro");

    let refresh = d.package_manager().refresh_command().expect("apt refresh");
    r.run(&refresh).await.expect("refresh");

    // `stdin` est fermé par `docker exec` sans `-i` : si la commande posait une
    // question, elle échouerait au lieu d'aboutir.
    let o = r
        .run(&d.package_manager().install_command(&["curl"]))
        .await
        .expect("installation");

    assert!(o.ok(), "installation interactive ? → {}", o.stderr);
    println!("✓ installation non interactive confirmée");

    stop("hlb-noint-debian");
}
