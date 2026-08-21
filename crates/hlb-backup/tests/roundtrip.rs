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
            "run",
            "--rm",
            "-v",
            &format!("{volume}:{WORKDIR}"),
            "alpine:3",
            "sh",
            "-c",
            script,
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
    assert_eq!(avant, apres, "le contenu restauré diffère de l'original");
    println!("✓ {} fichiers restaurés à l'identique", apres.len());

    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn snapshots_are_listed_and_tagged() {
    let vol = make_volume("hlb-test-snapshots");
    let repo = repo_in(&vol);

    in_volume(
        &vol,
        &format!("mkdir -p {WORKDIR}/a && echo un > {WORKDIR}/a/f.txt"),
    );
    repo.init().await.expect("init");

    repo.backup(&format!("{WORKDIR}/a"), &["app:gitea"])
        .await
        .expect("1");
    in_volume(&vol, &format!("echo deux > {WORKDIR}/a/f.txt"));
    repo.backup(&format!("{WORKDIR}/a"), &["app:gitea"])
        .await
        .expect("2");

    let tous = repo.snapshots(None).await.expect("liste");
    assert_eq!(tous.len(), 2, "{tous:?}");

    let filtres = repo
        .snapshots(Some("app:gitea"))
        .await
        .expect("liste filtrée");
    assert_eq!(filtres.len(), 2);

    let autres = repo
        .snapshots(Some("app:inexistante"))
        .await
        .expect("liste filtrée");
    assert!(
        autres.is_empty(),
        "le filtre par étiquette doit être effectif"
    );

    println!(
        "✓ {} instantanés, filtrage par étiquette opérationnel",
        tous.len()
    );
    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn point_in_time_restore_picks_the_right_version() {
    // Le cas réel : on veut la version d'AVANT la bêtise, pas la dernière.
    let vol = make_volume("hlb-test-pitr");
    let repo = repo_in(&vol);

    in_volume(
        &vol,
        &format!("mkdir -p {WORKDIR}/d && echo 'version bonne' > {WORKDIR}/d/f.txt"),
    );
    repo.init().await.expect("init");
    let bon = repo
        .backup(&format!("{WORKDIR}/d"), &["app:test"])
        .await
        .expect("1");

    in_volume(
        &vol,
        &format!("echo 'version corrompue' > {WORKDIR}/d/f.txt"),
    );
    repo.backup(&format!("{WORKDIR}/d"), &["app:test"])
        .await
        .expect("2");

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

    in_volume(
        &vol,
        &format!("mkdir -p {WORKDIR}/d && echo x > {WORKDIR}/d/f"),
    );
    repo.init().await.expect("init");
    repo.backup(&format!("{WORKDIR}/d"), &["app:test"])
        .await
        .expect("sauvegarde");

    repo.check().await.expect("le dépôt doit être sain");
    println!("✓ intégrité vérifiée");

    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn retention_removes_old_snapshots_but_keeps_the_recent_one() {
    let vol = make_volume("hlb-test-retention");
    let repo = repo_in(&vol);

    in_volume(
        &vol,
        &format!("mkdir -p {WORKDIR}/d && echo a > {WORKDIR}/d/f"),
    );
    repo.init().await.expect("init");

    for i in 0..3 {
        in_volume(&vol, &format!("echo {i} > {WORKDIR}/d/f"));
        repo.backup(&format!("{WORKDIR}/d"), &["app:test"])
            .await
            .expect("sauvegarde");
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

    in_volume(
        &vol,
        &format!("mkdir -p {WORKDIR}/d && echo secret > {WORKDIR}/d/f"),
    );
    repo.init().await.expect("init");
    repo.backup(&format!("{WORKDIR}/d"), &["app:test"])
        .await
        .expect("sauvegarde");

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

// ── Vérification de restauration (§8.3) ──────────────────────────────────────

/// Compte fichiers et octets sous un chemin du volume partagé.
fn count_files(volume: &str, dir: &str) -> (u64, u64) {
    let out = in_volume(
        volume,
        &format!("find {dir} -type f 2>/dev/null | wc -l; find {dir} -type f -exec stat -c %s {{}} + 2>/dev/null | awk '{{s+=$1}} END {{print s+0}}'"),
    );
    let mut l = out.lines();
    let files = l.next().unwrap_or("0").trim().parse().unwrap_or(0);
    let bytes = l.next().unwrap_or("0").trim().parse().unwrap_or(0);
    (files, bytes)
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn verification_confirms_a_healthy_backup() {
    let vol = make_volume("hlb-test-verif-ok");
    let repo = repo_in(&vol);

    in_volume(
        &vol,
        &format!(
            "mkdir -p {WORKDIR}/d/sous && echo un > {WORKDIR}/d/a.txt && \
             echo deux > {WORKDIR}/d/sous/b.txt && head -c 2048 /dev/urandom > {WORKDIR}/d/c.bin"
        ),
    );
    repo.init().await.expect("init");
    let id = repo
        .backup(&format!("{WORKDIR}/d"), &["app:test"])
        .await
        .expect("sauvegarde");

    let v = hlb_backup::verify_by_restore(&repo, &id, &format!("{WORKDIR}/verif"), |_| async {
        Ok(count_files(&vol, &format!("{WORKDIR}/verif")))
    })
    .await
    .expect("vérification");

    assert!(v.matches(), "{}", v.describe());
    assert_eq!(v.files_restored, 3);
    println!("✓ {}", v.describe());

    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn verification_detects_an_incomplete_restore() {
    // 🔴 LE test du §8.3. Sans lui, on ne saurait pas si la vérification vérifie
    // quoi que ce soit — un contrôle qui ne dit jamais « non » ne sert à rien.
    //
    // On simule une restauration partielle en supprimant un fichier juste après.
    let vol = make_volume("hlb-test-verif-ko");
    let repo = repo_in(&vol);

    in_volume(
        &vol,
        &format!(
            "mkdir -p {WORKDIR}/d && echo un > {WORKDIR}/d/a.txt && echo deux > {WORKDIR}/d/b.txt"
        ),
    );
    repo.init().await.expect("init");
    let id = repo
        .backup(&format!("{WORKDIR}/d"), &["app:test"])
        .await
        .expect("sauvegarde");

    let cible = format!("{WORKDIR}/verif");
    let v = hlb_backup::verify_by_restore(&repo, &id, &cible, |t| {
        let vol = vol.clone();
        async move {
            // Un fichier disparaît : la restauration est incomplète.
            in_volume(&vol, &format!("find {t} -name b.txt -delete"));
            Ok(count_files(&vol, &t))
        }
    })
    .await
    .expect("vérification");

    assert!(!v.matches(), "l'écart aurait dû être détecté");
    assert!(v.describe().contains("ÉCART"), "{}", v.describe());
    println!("✓ écart détecté : {}", v.describe());

    drop_volume(&vol);
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn reading_the_data_catches_more_than_metadata() {
    // `restic check` seul ne lit que les métadonnées. --read-data-subset relit
    // réellement des blocs, ce qui attrape la corruption silencieuse.
    let vol = make_volume("hlb-test-readdata");
    let repo = repo_in(&vol);

    in_volume(
        &vol,
        &format!("mkdir -p {WORKDIR}/d && head -c 65536 /dev/urandom > {WORKDIR}/d/gros.bin"),
    );
    repo.init().await.expect("init");
    repo.backup(&format!("{WORKDIR}/d"), &["app:test"])
        .await
        .expect("sauvegarde");

    repo.check_data("100%")
        .await
        .expect("les blocs doivent être lisibles");
    println!("✓ intégrité des données vérifiée par relecture");

    drop_volume(&vol);
}

/// La vérification de bout en bout du §8.3, telle que `hlb backup verify` l'exécute.
///
/// 🔴 Ce test existe parce que la version précédente de `verify_snapshot` utilisait un
/// `tempfile::tempdir()` de l'hôte. Sur macOS, ce dossier n'est **pas partagé avec la
/// VM Docker** : le comptage y trouvait zéro fichier et déclarait un écart sur une
/// sauvegarde parfaitement saine. Le volume Docker est ce qui corrige ça — et seul un
/// test contre un vrai restic pouvait le montrer.
#[tokio::test]
#[ignore = "nécessite Docker"]
async fn a_healthy_snapshot_verifies_by_actually_restoring_it() {
    // Deux volumes distincts : `verify_snapshot` monte le dépôt seul, comme le CLI
    // le fait avec le chemin passé à `--backup-repo`.
    let depot = make_volume("hlb-test-verify-depot");
    let donnees = make_volume("hlb-test-verify-data");

    in_volume(
        &donnees,
        &format!(
            "mkdir -p {WORKDIR}/sous && \
             printf 'bonjour' > {WORKDIR}/a.txt && \
             printf 'monde12345' > {WORKDIR}/sous/b.txt"
        ),
    );

    let runner = ContainerRunner::new("restic/restic:latest")
        .mount(&depot, "/depot")
        .mount(&donnees, "/donnees");
    let repo = Repository::new(runner, "/depot", "mot-de-passe-de-test");

    repo.init().await.expect("init");
    let snap = repo
        .backup("/donnees", &["app:demo"])
        .await
        .expect("sauvegarde");

    let v = hlb_backup::verify_snapshot(&depot, "mot-de-passe-de-test", &snap).await;

    drop_volume(&depot);
    drop_volume(&donnees);

    let v = v.expect("vérification exécutable");
    assert_eq!(v.files_expected, 2, "l'instantané annonce 2 fichiers");
    assert_eq!(v.bytes_expected, 17, "7 + 10 octets");
    assert_eq!(
        v.files_restored,
        2,
        "🔴 zéro ici = l'espace jetable n'est pas partagé avec Docker : {}",
        v.describe()
    );
    assert_eq!(v.bytes_restored, 17);
    assert!(v.matches(), "{}", v.describe());

    // La relecture d'un échantillon de blocs doit avoir eu lieu : sans elle, une
    // corruption à taille identique passerait pour « conforme ».
    let d = v
        .data_checked
        .as_ref()
        .expect("relecture de blocs effectuée");
    assert!(d.ok, "blocs illisibles : {:?}", d.detail);
    assert_eq!(d.subset, "5%");
}

/// Une base SQLite survit-elle à un aller-retour complet ? (§3.4)
///
/// 🔴 C'est la preuve qui compte. La comparaison de tailles dirait « conforme » sur un
/// fichier SQLite copié à chaud et pourtant inexploitable : le fichier a la bonne
/// taille, ses octets sont fidèlement rendus, et SQLite refuse de l'ouvrir — ou pire,
/// l'ouvre en ayant silencieusement perdu les transactions du WAL.
///
/// Ce test relit donc **les données**, pas les octets.
#[tokio::test]
#[ignore = "nécessite Docker"]
async fn a_sqlite_database_survives_the_whole_pipeline() {
    use hlb_backup::pgdump::scheduled::{archive, Dump};

    let travail = tempfile::tempdir().expect("répertoire");
    let source = travail.path().join("app.db");

    // Une base en mode WAL avec assez de lignes pour que le WAL compte, et qu'on ne
    // ferme PAS proprement — comme une app qui tourne.
    {
        let opts = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&source)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("base");

        sqlx::query("CREATE TABLE users (id INTEGER PRIMARY KEY, nom TEXT)")
            .execute(&pool)
            .await
            .expect("table");
        for i in 0..1000 {
            sqlx::query("INSERT INTO users (nom) VALUES (?1)")
                .bind(format!("user{i}"))
                .execute(&pool)
                .await
                .expect("insertion");
        }
        // Pas de `pool.close()` : le WAL reste chargé.
    }

    // 1. Instantané cohérent.
    let staging = tempfile::tempdir().expect("transit");
    let produits = hlb_backup::sqlite_snapshot_all(travail.path(), staging.path())
        .await
        .expect("instantané");
    assert_eq!(produits.len(), 1, "{produits:?}");

    // 2. Archivage dans un vrai dépôt restic.
    let depot = "hlb-test-sqlite-depot";
    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", depot])
        .output();
    make_volume(depot);

    let contenu = std::fs::read(&produits[0]).expect("lecture");
    let d = Dump {
        app: "pocket-id".into(),
        database: "app".into(),
        filename: "app.db.snapshot".into(),
        bytes: contenu,
    };
    let id = archive(depot, "mot-de-passe-de-test", &d)
        .await
        .expect("archivage");

    // 3. Restauration depuis le dépôt, dans un fichier neuf.
    let restaure = travail.path().join("restaure.db");
    let out = std::process::Command::new("docker")
        .args([
            "run",
            "--rm",
            "-e",
            "RESTIC_PASSWORD=mot-de-passe-de-test",
            "-v",
            &format!("{depot}:/depot"),
            "--entrypoint",
            "sh",
            "restic/restic:latest",
            "-c",
            &format!("restic -r /depot dump {id} /staging/app.db.snapshot"),
        ])
        .output()
        .expect("restic");
    assert!(
        out.status.success(),
        "restauration impossible :\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::write(&restaure, &out.stdout).expect("écriture");

    // 4. 🔴 La preuve : les DONNÉES sont là, pas seulement les octets.
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite://{}", restaure.display()))
        .await
        .expect("🔴 la base restaurée doit s'OUVRIR — un fichier copié à chaud échoue ici");

    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&pool)
        .await
        .expect("comptage");
    assert_eq!(n, 1000, "🔴 lignes perdues : le WAL n'a pas été capturé");

    let dernier: String = sqlx::query_scalar("SELECT nom FROM users ORDER BY id DESC LIMIT 1")
        .fetch_one(&pool)
        .await
        .expect("dernière ligne");
    assert_eq!(dernier, "user999", "la dernière transaction doit être là");

    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", depot])
        .output();
}
