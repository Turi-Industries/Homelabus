//! Sauvegarde → destruction → restauration → comparaison, contre un vrai restic.
//!
//! §8.3 du plan : **« un backup non testé n'est pas un backup »**. Vérifier que restic
//! renvoie un identifiant d'instantané ne prouve rien ; la seule preuve utile est de
//! détruire les données et de constater qu'on les récupère à l'identique.
//!
//! ```sh
//! export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
//! cargo test -p hlb-backup -- --ignored --test-threads=1 --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::Path;

use hlb_backup::{ContainerRunner, Repository, RetentionPolicy};

/// Tout se passe dans un volume Docker : le dossier temporaire de l'hôte n'est pas
/// partagé avec la VM Docker sur macOS (leçon apprise sur les tests Caddy).
const WORKDIR: &str = "/travail";

fn repo_in(volume: &str) -> Repository<ContainerRunner> {
    let runner = ContainerRunner::new("restic/restic:latest").mount(volume, WORKDIR);
    Repository::new(runner, format!("{WORKDIR}/depot"), "mot-de-passe-de-test")
}

/// Exécute une commande shell dans le volume partagé.
fn in_volume(volume: &str, script: &str) -> String {
    let out = std::process::Command::new("docker")
        .args([
            "run", "--rm", "-v", &format!("{volume}:{WORKDIR}"),
            "alpine:3", "sh", "-c", script,
        ])
        .output()
        .expect("docker joignable (DOCKER_HOST ?)");
    assert!(
        out.status.success(),
        "script échoué : {}\n{}",
        script,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn make_volume(name: &str) -> String {
    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", name])
        .output();
    std::process::Command::new("docker")
        .args(["volume", "create", name])
        .output()
        .expect("création du volume");
    name.to_string()
}

fn drop_volume(name: &str) {
    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", name])
        .output();
}

/// Empreinte du contenu : chemin → somme de contrôle.
fn fingerprint(volume: &str, dir: &str) -> BTreeMap<String, String> {
    let out = in_volume(
        volume,
        &format!("cd {dir} && find . -type f | sort | xargs -I{{}} sh -c 'echo \"{{}} $(md5sum < {{}})\"'"),
    );
    out.lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(p, h)| (p.to_string(), h.trim().to_string()))
        .collect()
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn data_survives_destruction_and_comes_back_identical() {
    let vol = make_volume("hlb-test-backup");
    let repo = repo_in(&vol);

    // 1. Des données réalistes : arborescence, contenus variés, fichier binaire.
    in_volume(
        &vol,
        &format!(
            "mkdir -p {WORKDIR}/donnees/sous/dossier && \
             echo 'contenu principal' > {WORKDIR}/donnees/fichier.txt && \
             echo 'imbriqué' > {WORKDIR}/donnees/sous/dossier/profond.txt && \
             head -c 4096 /dev/urandom > {WORKDIR}/donnees/binaire.bin"
        ),
    );
    let avant = fingerprint(&vol, &format!("{WORKDIR}/donnees"));
    assert_eq!(avant.len(), 3, "trois fichiers attendus : {avant:?}");
    println!("✓ {} fichiers créés", avant.len());

    // 2. Sauvegarde.
    repo.init().await.expect("init");
    let id = repo
        .backup(&format!("{WORKDIR}/donnees"), &["app:test"])
        .await
        .expect("sauvegarde");
    println!("✓ instantané {}", &id[..8]);

    // 3. 🔴 Destruction totale.
    in_volume(&vol, &format!("rm -rf {WORKDIR}/donnees"));
    let apres_destruction = fingerprint(&vol, WORKDIR);
    assert!(
        !apres_destruction.keys().any(|k| k.contains("donnees")),
        "les données devraient avoir disparu"
    );
    println!("✓ données détruites");

    // 4. Restauration.
    repo.restore(&id, "/").await.expect("restauration");

    // 5. Comparaison, fichier par fichier.
    let apres = fingerprint(&vol, &format!("{WORKDIR}/donnees"));
    assert_eq!(
        avant, apres,
        "le contenu restauré diffère de l'original"
    );
    println!("✓ {} fichiers restaurés à l'identique", apres.len());

    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn snapshots_are_listed_and_tagged() {
    let vol = make_volume("hlb-test-snapshots");
    let repo = repo_in(&vol);

    in_volume(&vol, &format!("mkdir -p {WORKDIR}/a && echo un > {WORKDIR}/a/f.txt"));
    repo.init().await.expect("init");

    repo.backup(&format!("{WORKDIR}/a"), &["app:gitea"]).await.expect("1");
    in_volume(&vol, &format!("echo deux > {WORKDIR}/a/f.txt"));
    repo.backup(&format!("{WORKDIR}/a"), &["app:gitea"]).await.expect("2");

    let tous = repo.snapshots(None).await.expect("liste");
    assert_eq!(tous.len(), 2, "{tous:?}");

    let filtres = repo.snapshots(Some("app:gitea")).await.expect("liste filtrée");
    assert_eq!(filtres.len(), 2);

    let autres = repo.snapshots(Some("app:inexistante")).await.expect("liste filtrée");
    assert!(autres.is_empty(), "le filtre par étiquette doit être effectif");

    println!("✓ {} instantanés, filtrage par étiquette opérationnel", tous.len());
    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn point_in_time_restore_picks_the_right_version() {
    // Le cas réel : on veut la version d'AVANT la bêtise, pas la dernière.
    let vol = make_volume("hlb-test-pitr");
    let repo = repo_in(&vol);

    in_volume(&vol, &format!("mkdir -p {WORKDIR}/d && echo 'version bonne' > {WORKDIR}/d/f.txt"));
    repo.init().await.expect("init");
    let bon = repo.backup(&format!("{WORKDIR}/d"), &["app:test"]).await.expect("1");

    in_volume(&vol, &format!("echo 'version corrompue' > {WORKDIR}/d/f.txt"));
    repo.backup(&format!("{WORKDIR}/d"), &["app:test"]).await.expect("2");

    // On restaure explicitement le premier instantané.
    in_volume(&vol, &format!("rm -rf {WORKDIR}/d"));
    repo.restore(&bon, "/").await.expect("restauration");

    let contenu = in_volume(&vol, &format!("cat {WORKDIR}/d/f.txt"));
    assert!(
        contenu.contains("version bonne"),
        "on a restauré la mauvaise version : {contenu}"
    );
    println!("✓ restauration ciblée sur le bon instantané");

    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn integrity_check_passes_on_a_healthy_repository() {
    let vol = make_volume("hlb-test-check");
    let repo = repo_in(&vol);

    in_volume(&vol, &format!("mkdir -p {WORKDIR}/d && echo x > {WORKDIR}/d/f"));
    repo.init().await.expect("init");
    repo.backup(&format!("{WORKDIR}/d"), &["app:test"]).await.expect("sauvegarde");

    repo.check().await.expect("le dépôt doit être sain");
    println!("✓ intégrité vérifiée");

    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn retention_removes_old_snapshots_but_keeps_the_recent_one() {
    let vol = make_volume("hlb-test-retention");
    let repo = repo_in(&vol);

    in_volume(&vol, &format!("mkdir -p {WORKDIR}/d && echo a > {WORKDIR}/d/f"));
    repo.init().await.expect("init");

    for i in 0..3 {
        in_volume(&vol, &format!("echo {i} > {WORKDIR}/d/f"));
        repo.backup(&format!("{WORKDIR}/d"), &["app:test"]).await.expect("sauvegarde");
    }
    assert_eq!(repo.snapshots(None).await.expect("liste").len(), 3);

    // Ne garder que le dernier.
    let stricte = RetentionPolicy {
        hourly: 0,
        daily: 0,
        weekly: 0,
        monthly: 0,
        yearly: 1,
    };
    repo.forget(&stricte, true).await.expect("forget");

    let restants = repo.snapshots(None).await.expect("liste");

    // 🔴 L'assertion qui compte : la rétention doit RÉELLEMENT supprimer.
    //
    // Un `forget` qui s'exécute sans erreur mais ne supprime rien est le pire des
    // cas : la politique semble configurée, et le disque se remplit quand même.
    assert_eq!(
        restants.len(),
        1,
        "la rétention n'a rien supprimé — les instantanés sont-ils groupés par \
         des hôtes différents ? {restants:#?}"
    );
    println!("✓ 3 instantanés → 1 conservé");

    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn a_wrong_password_cannot_read_the_repository() {
    // Le chiffrement doit être réel, pas décoratif.
    let vol = make_volume("hlb-test-crypto");
    let repo = repo_in(&vol);

    in_volume(&vol, &format!("mkdir -p {WORKDIR}/d && echo secret > {WORKDIR}/d/f"));
    repo.init().await.expect("init");
    repo.backup(&format!("{WORKDIR}/d"), &["app:test"]).await.expect("sauvegarde");

    let intrus = Repository::new(
        ContainerRunner::new("restic/restic:latest").mount(&vol, WORKDIR),
        format!("{WORKDIR}/depot"),
        "mauvais-mot-de-passe",
    );
    assert!(
        intrus.snapshots(None).await.is_err(),
        "un mauvais mot de passe ne doit rien donner"
    );
    println!("✓ dépôt illisible sans le bon mot de passe");

    drop_volume(&vol);
}

/// Sanity : le chemin de test lui-même doit être valide.
#[test]
fn the_workdir_is_absolute() {
    assert!(Path::new(WORKDIR).is_absolute());
}
