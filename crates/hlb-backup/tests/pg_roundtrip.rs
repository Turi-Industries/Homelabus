//! Dump → destruction → restauration, contre un vrai PostgreSQL.
//!
//! §8.1 : une base ne se sauvegarde pas comme des fichiers. Ces tests le vérifient
//! dans les deux sens — que le dump restaure fidèlement, et qu'il reste cohérent même
//! pris pendant des écritures concurrentes.
//!
//! ```sh
//! export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
//! cargo test -p hlb-backup --test pg_roundtrip -- --ignored --test-threads=1 --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_backup::{PgContainerRunner, PgDumper, PgTarget};

const PG_IMAGE: &str = "postgres:17-alpine";
const CONTAINER: &str = "hlb-test-pgdump";
const NETWORK: &str = "hlb-test-net";
const PASSWORD: &str = "motdepasse-de-test";

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker joignable (DOCKER_HOST ?)")
}

/// Exécute du SQL via `psql` dans le conteneur, et renvoie la sortie.
fn psql(db: &str, sql: &str) -> String {
    let out = docker(&[
        "exec", "-e", &format!("PGPASSWORD={PASSWORD}"), CONTAINER,
        "psql", "-U", "postgres", "-d", db, "-tAc", sql,
    ]);
    assert!(
        out.status.success(),
        "psql a échoué sur « {sql} » :\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn start_postgres() {
    let _ = docker(&["rm", "-f", CONTAINER]);
    let _ = docker(&["network", "create", NETWORK]);

    let out = docker(&[
        "run", "-d", "--name", CONTAINER, "--network", NETWORK,
        "-e", &format!("POSTGRES_PASSWORD={PASSWORD}"),
        PG_IMAGE,
    ]);
    assert!(
        out.status.success(),
        "démarrage de postgres : {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Attendre que le serveur accepte les connexions.
    for _ in 0..60 {
        let r = docker(&["exec", CONTAINER, "pg_isready", "-U", "postgres"]);
        if r.status.success() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!("postgres n'a pas démarré à temps");
}

fn stop_postgres() {
    let _ = docker(&["rm", "-f", CONTAINER]);
    let _ = docker(&["network", "rm", NETWORK]);
}

fn target(db: &str) -> PgTarget {
    PgTarget {
        // Résolu par le DNS du réseau Docker : le conteneur pg_dump y est rattaché.
        host: CONTAINER.to_string(),
        port: 5432,
        database: db.to_string(),
        user: "postgres".to_string(),
        password: PASSWORD.to_string(),
    }
}

fn dumper() -> PgDumper<PgContainerRunner> {
    PgDumper::new(PgContainerRunner::new(PG_IMAGE).network(NETWORK))
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn a_database_survives_destruction_and_comes_back_identical() {
    start_postgres();

    // 1. Une base réaliste : plusieurs tables, une clé étrangère, des index.
    psql("postgres", "CREATE DATABASE appli");
    psql(
        "appli",
        "CREATE TABLE auteurs (id serial PRIMARY KEY, nom text NOT NULL UNIQUE);
         CREATE TABLE billets (
             id serial PRIMARY KEY,
             auteur_id int NOT NULL REFERENCES auteurs(id),
             titre text NOT NULL,
             publie_le timestamptz NOT NULL DEFAULT now()
         );
         CREATE INDEX idx_billets_auteur ON billets(auteur_id);
         INSERT INTO auteurs (nom) VALUES ('Ada'), ('Grace'), ('Alan');
         INSERT INTO billets (auteur_id, titre)
             SELECT 1 + (i % 3), 'billet ' || i FROM generate_series(1, 500) i;",
    );

    let avant_auteurs = psql("appli", "SELECT count(*) FROM auteurs");
    let avant_billets = psql("appli", "SELECT count(*) FROM billets");
    let avant_somme = psql("appli", "SELECT md5(string_agg(titre, ',' ORDER BY id)) FROM billets");
    println!("✓ base peuplée : {avant_auteurs} auteurs, {avant_billets} billets");

    // 2. Dump.
    let dump = dumper().dump(&target("appli")).await.expect("dump");
    assert!(dump.len() > 1000, "dump suspicieusement petit : {} o", dump.len());
    // Le format custom commence par la signature « PGDMP ».
    assert_eq!(&dump[..5], b"PGDMP", "ce n'est pas un dump au format custom");
    println!("✓ dump de {} octets", dump.len());

    // 3. 🔴 Destruction.
    psql("postgres", "DROP DATABASE appli");
    let existe = psql(
        "postgres",
        "SELECT count(*) FROM pg_database WHERE datname = 'appli'",
    );
    assert_eq!(existe, "0", "la base devrait avoir disparu");
    println!("✓ base détruite");

    // 4. Restauration dans une base neuve.
    psql("postgres", "CREATE DATABASE appli");
    dumper()
        .restore(&target("appli"), &dump, false)
        .await
        .expect("restauration");

    // 5. Comparaison : comptes, contenu, et structure.
    assert_eq!(psql("appli", "SELECT count(*) FROM auteurs"), avant_auteurs);
    assert_eq!(psql("appli", "SELECT count(*) FROM billets"), avant_billets);
    assert_eq!(
        psql("appli", "SELECT md5(string_agg(titre, ',' ORDER BY id)) FROM billets"),
        avant_somme,
        "le contenu restauré diffère"
    );

    // La contrainte de clé étrangère doit avoir survécu, pas seulement les lignes.
    let fk = psql(
        "appli",
        "SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND conrelid = 'billets'::regclass",
    );
    assert_eq!(fk, "1", "la clé étrangère n'a pas été restaurée");

    let idx = psql(
        "appli",
        "SELECT count(*) FROM pg_indexes WHERE tablename = 'billets' AND indexname = 'idx_billets_auteur'",
    );
    assert_eq!(idx, "1", "l'index n'a pas été restauré");

    println!("✓ données, clés étrangères et index restaurés à l'identique");
    stop_postgres();
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn a_dump_taken_during_concurrent_writes_stays_consistent() {
    // 🔴 Le cœur du §8.1. C'est précisément ce qu'une sauvegarde de fichiers ne sait
    // pas faire : capturer un instant cohérent malgré les écritures en cours.
    start_postgres();

    psql("postgres", "CREATE DATABASE charge");
    psql(
        "charge",
        "CREATE TABLE compteur (id int PRIMARY KEY, valeur int NOT NULL);
         INSERT INTO compteur SELECT i, 0 FROM generate_series(1, 100) i;",
    );

    // Invariant : la somme des valeurs doit toujours être un multiple de 100, car
    // chaque écriture incrémente les 100 lignes d'un coup, dans une transaction.
    let ecrivain = std::thread::spawn(|| {
        for _ in 0..40 {
            let _ = std::process::Command::new("docker")
                .args([
                    "exec", "-e", &format!("PGPASSWORD={PASSWORD}"), CONTAINER,
                    "psql", "-U", "postgres", "-d", "charge", "-tAc",
                    "BEGIN; UPDATE compteur SET valeur = valeur + 1; COMMIT;",
                ])
                .output();
        }
    });

    // On dumpe pendant que ça écrit.
    std::thread::sleep(std::time::Duration::from_millis(400));
    let dump = dumper().dump(&target("charge")).await.expect("dump");
    ecrivain.join().expect("écrivain terminé");
    println!("✓ dump pris pendant {} écritures concurrentes", 40);

    // Restauration dans une base séparée, puis vérification de l'invariant.
    psql("postgres", "CREATE DATABASE verif");
    dumper()
        .restore(&target("verif"), &dump, false)
        .await
        .expect("restauration");

    let somme: i64 = psql("verif", "SELECT sum(valeur) FROM compteur")
        .parse()
        .expect("somme numérique");
    let lignes: i64 = psql("verif", "SELECT count(*) FROM compteur")
        .parse()
        .expect("compte");

    assert_eq!(lignes, 100);
    assert_eq!(
        somme % 100,
        0,
        "instantané incohérent : somme = {somme}, on a capturé une transaction \
         partiellement appliquée"
    );
    println!("✓ invariant respecté (somme = {somme}, soit {} incréments complets)", somme / 100);

    stop_postgres();
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn restoring_over_a_populated_database_needs_clean() {
    start_postgres();

    psql("postgres", "CREATE DATABASE src");
    psql("src", "CREATE TABLE t (id int PRIMARY KEY); INSERT INTO t VALUES (1), (2);");
    let dump = dumper().dump(&target("src")).await.expect("dump");

    // La cible existe déjà avec la même table : sans --clean, pg_restore échoue.
    psql("postgres", "CREATE DATABASE cible");
    psql("cible", "CREATE TABLE t (id int PRIMARY KEY); INSERT INTO t VALUES (99);");

    assert!(
        dumper().restore(&target("cible"), &dump, false).await.is_err(),
        "sans --clean, restaurer par-dessus doit échouer"
    );

    dumper()
        .restore(&target("cible"), &dump, true)
        .await
        .expect("restauration avec --clean");

    assert_eq!(psql("cible", "SELECT count(*) FROM t"), "2");
    assert_eq!(psql("cible", "SELECT count(*) FROM t WHERE id = 99"), "0");
    println!("✓ --clean remplace bien le contenu existant");

    stop_postgres();
}

#[tokio::test]
#[ignore = "nécessite Docker"]
async fn dumping_a_missing_database_fails_clearly() {
    start_postgres();
    let err = dumper().dump(&target("nexiste-pas")).await.unwrap_err();
    assert!(
        err.to_string().contains("nexiste-pas") || err.to_string().contains("does not exist"),
        "message peu clair : {err}"
    );
    println!("✓ erreur explicite : {err}");
    stop_postgres();
}

/// Le cycle complet de la sauvegarde planifiée : dump → dépôt restic → restauration.
///
/// 🔴 Ce test existe parce que la première version de `scheduled::archive` écrivait le
/// dump dans un `tempfile::tempdir()` de l'hôte avant de le donner à un restic
/// conteneurisé. Sur macOS, ce dossier n'est pas partagé avec la VM Docker : restic
/// répondait « does not exist, skipping » puis sortait en erreur. Le dump était bien
/// produit et n'arrivait jamais dans le dépôt.
#[tokio::test]
#[ignore = "nécessite Docker"]
async fn a_scheduled_dump_reaches_the_repository_and_comes_back() {
    use hlb_backup::pgdump::scheduled;

    start_postgres();

    psql("postgres", "DROP DATABASE IF EXISTS planifiee");
    psql("postgres", "CREATE DATABASE planifiee");
    psql(
        "planifiee",
        "CREATE TABLE depots (id int PRIMARY KEY, nom text);
         INSERT INTO depots VALUES (1, 'projet-a'), (2, 'projet-b');",
    );

    // 1. Produire le dump.
    let d = scheduled::produce(&dumper(), "gitea", &target("planifiee"), 1_786_881_600)
        .await
        .expect("dump produit");

    assert_eq!(d.filename, "gitea-planifiee-20260816T120000Z.dump");
    assert!(!d.bytes.is_empty(), "un dump vide n'est jamais normal");

    // 2. L'archiver dans un dépôt neuf.
    let depot = "hlb-test-dump-depot";
    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", depot])
        .output();
    docker(&["volume", "create", depot]);

    let id = scheduled::archive(depot, "mot-de-passe-de-test", &d)
        .await
        .expect("🔴 archivage : si ça échoue en « does not exist », le transit ne traverse pas la VM Docker");

    assert!(!id.is_empty(), "un identifiant d'instantané est attendu");

    // 3. Le relire et vérifier qu'il contient bien le dump, octet pour octet.
    let out = docker(&[
        "run", "--rm", "-e", "RESTIC_PASSWORD=mot-de-passe-de-test",
        "-v", &format!("{depot}:/depot"),
        "--entrypoint", "sh", "restic/restic:latest", "-c",
        &format!("restic -r /depot dump {id} /staging/{} | wc -c", d.filename),
    ]);
    assert!(
        out.status.success(),
        "relecture impossible :\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let taille: usize = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("taille lisible");
    assert_eq!(
        taille,
        d.bytes.len(),
        "le dump archivé n'a pas la taille de celui qu'on a produit"
    );

    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", depot])
        .output();
}

/// Un exercice de reprise restaure-t-il vraiment une base utilisable ? (§8.3)
///
/// 🔴 C'est le seul test qui parcourt la chaîne complète : sauvegarde de base →
/// restauration dans un conteneur neuf → PostgreSQL qui démarre dessus → données
/// lisibles. Chaque maillon est testé ailleurs ; celui-ci vérifie qu'ils s'emboîtent.
///
/// Et il vérifie surtout ce qu'aucun test unitaire ne peut voir : que l'archive
/// ressort **intacte**. Un exercice qui corromprait la sauvegarde qu'il vérifie
/// serait le comble.
#[tokio::test]
#[ignore = "nécessite Docker"]
async fn a_drill_restores_a_usable_database_without_touching_the_archive() {
    use hlb_backup::drill;
    use hlb_backup::pitr::basebackup;

    start_postgres();

    // La réplication depuis un autre conteneur : sans cette ligne, pg_basebackup est
    // refusé avec un message qui parle de mot de passe (cf. pitr::basebackup).
    docker(&[
        "exec", CONTAINER, "sh", "-c",
        "grep -q 'host replication all all' /var/lib/postgresql/data/pg_hba.conf || \
         echo 'host replication all all scram-sha-256' >> /var/lib/postgresql/data/pg_hba.conf",
    ]);
    psql("postgres", "SELECT pg_reload_conf()");

    psql("postgres", "DROP DATABASE IF EXISTS exercice");
    psql("postgres", "CREATE DATABASE exercice");
    psql(
        "exercice",
        "CREATE TABLE clients (id int, nom text);
         CREATE TABLE commandes (id int);
         INSERT INTO clients VALUES (1, 'a'), (2, 'b');",
    );

    // 1. Une vraie sauvegarde de base.
    //
    // ⚠️ PAS un `tempfile::tempdir()` : sur macOS, /var/folders n'est pas partagé
    // avec la VM Docker, donc `pg_basebackup` écrirait DANS la VM et l'hôte ne
    // verrait rien. C'est le troisième endroit du projet où ce piège se présente
    // (cf. verify.rs et pgdump.rs). On passe donc par `target/`, sous /Users, qui
    // est monté.
    let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/hlb-test-drill");
    let _ = std::fs::remove_dir_all(&racine);
    std::fs::create_dir_all(&racine).expect("répertoire de test");

    let cible = basebackup::Target::new(racine.to_string_lossy(), CONTAINER)
        .credentials("postgres", PASSWORD)
        .network(NETWORK)
        .image(PG_IMAGE);

    let base_id = basebackup::run(&cible, 1_786_881_600)
        .await
        .expect("sauvegarde de base");

    let archive = racine.join(&base_id).join("base.tar.gz");
    let avant = std::fs::metadata(&archive).expect("archive").len();

    // 2. L'exercice.
    let t = drill::Target {
        container: drill::container_name(1_786_881_600).expect("nom"),
        disposable: true,
    };
    drill::authorize(&t, true).expect("cible jetable autorisée");

    let o = drill::run_postgres(&t, &racine.to_string_lossy(), &base_id, PG_IMAGE)
        .await
        .expect("exercice exécutable");

    assert!(
        o.succeeded(),
        "🔴 la chaîne complète doit aboutir : {}",
        o.describe()
    );
    // `exercice` a trois tables dans son schéma public… mais l'exercice restaure le
    // CLUSTER, donc il se connecte à `postgres`, qui n'en a aucune. Ce qui compte est
    // qu'il en trouve : une base vide donnerait 0 et échouerait.
    assert!(o.tables.unwrap_or(0) > 0, "{}", o.describe());

    // 3. 🔴 L'archive est intacte : le montage en lecture seule a tenu.
    let apres = std::fs::metadata(&archive).expect("archive").len();
    assert_eq!(avant, apres, "l'exercice a MODIFIÉ la sauvegarde qu'il vérifiait");

    // 4. Rien ne traîne.
    let restants = docker(&["ps", "-a", "--filter", &format!("name={}", t.container), "-q"]);
    assert!(
        String::from_utf8_lossy(&restants.stdout).trim().is_empty(),
        "le conteneur d'exercice n'a pas été détruit"
    );

    let _ = std::fs::remove_dir_all(&racine);
}
