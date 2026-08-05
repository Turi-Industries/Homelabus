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
