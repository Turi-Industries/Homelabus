//! A real dump through a real disposable server: what a verification reports must be
//! what the dump holds, and a damaged one must fail. It leaves nothing behind.
//!
//! ```sh
//! cargo test -p hlb-backup-run --test dump_reading -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_backup_run::dump_reading::{read, Reading};
use hlb_types::DbEngine;

const POSTGRES: &str = "postgres:17";
const MARIADB: &str = "mariadb:11.8";

/// One at a time: each counts the disposable servers left, and would count the other's.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

fn ok(args: &[&str]) -> Vec<u8> {
    let out = docker(args);
    assert!(
        out.status.success(),
        "docker {args:?}:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn wait(server: &str, probe: &[&str]) {
    let mut args = vec!["exec", server];
    args.extend_from_slice(probe);
    for _ in 0..60 {
        if docker(&args).status.success() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    panic!("{server} never answered");
}

/// Removes the source server when dropped, failing or not.
struct Source(&'static str);

impl Drop for Source {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-fv", self.0]);
    }
}

fn scratch_servers() -> usize {
    let out = ok(&["ps", "-aq", "--filter", "name=hlb-verif-db-"]);
    String::from_utf8_lossy(&out).lines().count()
}

/// Two tables and a row, as the pass dumps them.
fn postgres_dump() -> Vec<u8> {
    let server = "hlb-test-reading-pg";
    let _ = docker(&["rm", "-fv", server]);
    let _source = Source(server);
    ok(&[
        "run",
        "-d",
        "--name",
        server,
        "--network",
        "none",
        "-e",
        "POSTGRES_HOST_AUTH_METHOD=trust",
        POSTGRES,
    ]);
    wait(server, &["pg_isready", "-h", "127.0.0.1", "-U", "postgres"]);
    let sql = "CREATE TABLE notes (id int PRIMARY KEY, body text); \
               CREATE TABLE tags (id int); \
               INSERT INTO notes VALUES (1, 'kept');";
    ok(&[
        "exec",
        server,
        "psql",
        "-U",
        "postgres",
        "-c",
        "CREATE ROLE notes LOGIN",
    ]);
    ok(&[
        "exec",
        server,
        "psql",
        "-U",
        "postgres",
        "-c",
        "CREATE DATABASE notes OWNER notes",
    ]);
    ok(&[
        "exec", server, "psql", "-U", "notes", "-d", "notes", "-c", sql,
    ]);
    ok(&["exec", server, "pg_dump", "-U", "postgres", "-Fc", "notes"])
}

fn mariadb_dump() -> Vec<u8> {
    let server = "hlb-test-reading-maria";
    let _ = docker(&["rm", "-fv", server]);
    let _source = Source(server);
    ok(&[
        "run",
        "-d",
        "--name",
        server,
        "--network",
        "none",
        "-e",
        "MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1",
        MARIADB,
    ]);
    wait(
        server,
        &["mariadb", "-uroot", "-h", "127.0.0.1", "-e", "SELECT 1"],
    );
    let sql = "CREATE DATABASE notes; USE notes; \
               CREATE TABLE notes (id int PRIMARY KEY, body text); \
               CREATE TABLE tags (id int); \
               INSERT INTO notes VALUES (1, 'CREATE TABLE in a row');";
    ok(&["exec", server, "mariadb", "-uroot", "-e", sql]);
    ok(&[
        "exec",
        server,
        "mariadb-dump",
        "-uroot",
        "--databases",
        "notes",
        "--single-transaction",
        "--routines",
        "--triggers",
        "--events",
    ])
}

fn reading<'a>(engine: DbEngine, image: &'a str) -> Reading<'a> {
    Reading {
        engine,
        image,
        name: "notes",
        role: "notes",
        extensions: &[],
    }
}

#[tokio::test]
#[ignore = "needs Docker and the servers' images"]
async fn a_postgres_dump_comes_back_with_its_tables_and_a_damaged_one_fails() {
    let _one = SERIAL.lock().await;
    let dump = postgres_dump();
    let r = reading(DbEngine::Postgres, POSTGRES);

    let tables = read(&r, &dump).await.expect("a good dump reads");
    assert_eq!((tables.listed, tables.restored), (2, 2));
    assert!(tables.matches());

    let cut = &dump[..dump.len() / 2];
    assert!(read(&r, cut).await.is_err(), "a dump cut in half must fail");
    assert!(read(&r, b"not a dump").await.is_err());
    assert_eq!(scratch_servers(), 0, "a disposable server was left behind");
}

#[tokio::test]
#[ignore = "needs Docker and the servers' images"]
async fn a_mariadb_dump_comes_back_with_its_tables_and_a_truncated_one_fails() {
    let _one = SERIAL.lock().await;
    let dump = mariadb_dump();
    let r = reading(DbEngine::Mariadb, MARIADB);

    let tables = read(&r, &dump).await.expect("a good dump reads");
    assert_eq!((tables.listed, tables.restored), (2, 2));
    assert!(tables.matches());

    // The trap: a truncated MariaDB dump is still valid SQL.
    let cut = &dump[..dump.len() / 2];
    assert!(read(&r, cut).await.is_err(), "a truncated dump must fail");
    assert_eq!(scratch_servers(), 0, "a disposable server was left behind");
}
