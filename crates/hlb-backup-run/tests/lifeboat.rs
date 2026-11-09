//! A database the pass dumped at home, recreated on another server — the site's — by the
//! lifeboat: the app's role signs in there with the password the app is given (one
//! carrying a quote), its rows are back and its own, and a wrong password is refused.
//!
//! The "site" is a second server on another network of this machine's daemon, reached
//! through its socket as the site's is through the forwarded one.
//!
//! ```sh
//! cargo test -p hlb-backup-run --test lifeboat -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_backup_run::lifeboat::{Server, Site};
use hlb_backup_run::restore::{Database, Restore};
use hlb_backup_run::Pass;

const HOUSE: &str = "hlb-test-lifeboat-house";
const SITE: &str = "hlb-test-lifeboat-site";
const HOUSE_PG: &str = "hlb-test-lifeboat-house-pg";
const SITE_PG: &str = "hlb-test-lifeboat-site-pg";
const REPO: &str = "hlb-test-lifeboat-repo";
const ADMIN: &str = "admin-password";
const SITE_ADMIN: &str = "the-site-s-own";
const ROLE_PASSWORD: &str = "it's-the-app's";

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", HOUSE_PG, SITE_PG]);
        let _ = docker(&["network", "rm", HOUSE, SITE]);
        let _ = docker(&["volume", "rm", "-f", REPO]);
    }
}

fn server(name: &str, network: &str, password: &str, alias: &str) {
    let up = docker(&[
        "run",
        "-d",
        "--name",
        name,
        "--network",
        network,
        "--network-alias",
        alias,
        "-e",
        &format!("POSTGRES_PASSWORD={password}"),
        hlb_backup::images::POSTGRES_CLIENT,
    ]);
    assert!(
        up.status.success(),
        "{}",
        String::from_utf8_lossy(&up.stderr)
    );
    // Over TCP: the image's first start serves its socket alone, then restarts.
    let ready = (0..60).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(500));
        docker(&[
            "exec",
            name,
            "pg_isready",
            "-h",
            "127.0.0.1",
            "-U",
            "postgres",
        ])
        .status
        .success()
    });
    assert!(ready, "{name} never answered");
}

fn psql(server: &str, user: &str, db: &str, sql: &str) -> String {
    let out = docker(&[
        "exec",
        server,
        "psql",
        "-U",
        user,
        "-d",
        db,
        "-v",
        "ON_ERROR_STOP=1",
        "-tAc",
        sql,
    ]);
    assert!(
        out.status.success(),
        "psql on {server} as {user}: \"{sql}\":\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Signs in as `chat` over the SITE's network, from another container — the server's
/// own trusts its loopback whatever the password.
fn sign_in(password: &str) -> std::process::Output {
    docker(&[
        "run",
        "--rm",
        "--network",
        SITE,
        "-e",
        &format!("PGPASSWORD={password}"),
        hlb_backup::images::POSTGRES_CLIENT,
        "psql",
        "-h",
        "postgres",
        "-U",
        "chat",
        "-d",
        "chat",
        "-tAc",
        "SELECT string_agg(k || '=' || v, ',' ORDER BY k) FROM app.kv",
    ])
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_database_crosses_to_the_site_as_the_app_s_with_the_app_s_password() {
    let _cleanup = Cleanup;
    let _ = docker(&["rm", "-f", HOUSE_PG, SITE_PG]);
    let _ = docker(&["volume", "rm", "-f", REPO]);
    docker(&["network", "create", HOUSE]);
    docker(&["network", "create", SITE]);
    docker(&["volume", "create", REPO]);
    server(HOUSE_PG, HOUSE, ADMIN, HOUSE_PG);
    psql(
        HOUSE_PG,
        "postgres",
        "postgres",
        "CREATE ROLE chat LOGIN PASSWORD 'house-password'",
    );
    for s in hlb_platform::database_statements("chat", "chat").expect("statements") {
        psql(HOUSE_PG, "postgres", "postgres", &s);
    }
    psql(
        HOUSE_PG,
        "postgres",
        "chat",
        &hlb_platform::extension_statement("citext").expect("statement"),
    );
    psql(HOUSE_PG, "chat", "chat", "CREATE SCHEMA app");
    psql(
        HOUSE_PG,
        "chat",
        "chat",
        "CREATE TABLE app.kv (k citext PRIMARY KEY, v text)",
    );
    psql(
        HOUSE_PG,
        "chat",
        "chat",
        "INSERT INTO app.kv VALUES ('a', 'été')",
    );

    let dir = tempfile::tempdir().expect("tmp");
    let state_path = dir.path().join("hlb.db");
    let state = hlb_state::State::open(&state_path).await.expect("state");
    let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");
    let manifest: hlb_types::Manifest = serde_yaml_ng::from_str(
        r#"
apiVersion: hlb/v1
kind: App
metadata: { name: chat }
spec:
  image: { repo: a/b, tag: "1" }
  requires:
    - { kind: database, engine: postgres, extensions: [citext] }
"#,
    )
    .expect("manifest");
    state
        .upsert_app("chat", &manifest, None)
        .await
        .expect("app");
    state
        .upsert_destination("nas", REPO, "critical,bulky", None)
        .await
        .expect("destination");
    let admin = format!("postgres://postgres:{ADMIN}@{HOUSE_PG}:5432/postgres");
    let pass = Pass {
        state: &state,
        vault: &vault,
        state_path: &state_path,
        fallback_repo: None,
        network: HOUSE,
        postgres_admin: Some(&admin),
        mariadb_admin: None,
        schedule: hlb_backup::Schedule::default(),
        force: true,
        only: Some("chat"),
        orchestrator: None,
        s3_endpoint: None,
    };
    let sum = pass.run(&mut |_| {}).await.expect("pass");
    assert_eq!(sum.failed, 0);

    // The site: its own server, its own administrator, never the house's.
    server(SITE_PG, SITE, SITE_ADMIN, "postgres");
    let socket = std::path::Path::new("/var/run/docker.sock");
    let docker_api = hlb_orchestrator::SwarmOrchestrator::connect_unix(socket)
        .await
        .expect("docker");
    let restore = Restore {
        state: &state,
        vault: &vault,
        fallback_repo: None,
        network: HOUSE,
        orchestrator: None,
    };
    let sent = restore
        .database_to_site(
            "chat",
            &Database {
                engine: hlb_types::DbEngine::Postgres,
                name: "chat",
                role: "chat",
                extensions: &["citext".to_string()],
            },
            ROLE_PASSWORD,
            Some(10),
            &Site {
                docker: &docker_api,
                socket,
                network: SITE,
            },
            &Server {
                image: hlb_backup::images::POSTGRES_CLIENT,
                admin_password: SITE_ADMIN,
            },
        )
        .await
        .expect("sent");
    assert!(sent.bytes > 0);

    let ok = sign_in(ROLE_PASSWORD);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&ok.stdout).trim(), "a=été");
    assert!(
        !sign_in("house-password").status.success(),
        "the house's password opens nothing on the site"
    );
    assert_eq!(
        psql(
            SITE_PG,
            "postgres",
            "chat",
            "SELECT string_agg(tableowner, ',') FROM pg_tables WHERE schemaname = 'app'"
        ),
        "chat",
        "the tables are the app's"
    );
    assert_eq!(
        psql(
            SITE_PG,
            "postgres",
            "postgres",
            "SELECT rolconnlimit FROM pg_roles WHERE rolname = 'chat'"
        ),
        "10"
    );
}

/// `python3 -c` on the host, its standard output.
fn py(script: &str) -> String {
    let out = std::process::Command::new("python3")
        .args(["-I", "-c", script])
        .output()
        .expect("python3");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A local volume bound to `dir`, so the test reads what lands in it from the host.
fn bound(volume: &str, dir: &std::path::Path) {
    let _ = docker(&["volume", "rm", "-f", volume]);
    let device = format!("device={}", dir.display());
    let made = docker(&[
        "volume",
        "create",
        "--driver",
        "local",
        "--opt",
        "type=none",
        "--opt",
        "o=bind",
        "--opt",
        &device,
        volume,
    ]);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
}

/// A volume the pass backed up at home, sent through the site's daemon into a volume of
/// the same name there: its files, its root's owner and mode, and its SQLite database
/// from the pass's consistent copy — the WAL's last rows in, a later change out.
///
/// The first run of the lifeboat on the lab failed here, on the archive's own scratch
/// file, which the database's test never reaches.
#[tokio::test]
#[ignore = "needs Docker and python3"]
async fn a_volume_crosses_to_the_site_owned_as_it_was_its_sqlite_consistent() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let (data, repo) = ("hlb-test-lifeboat-volume", "hlb-test-lifeboat-volume-repo");
    struct Gone(&'static str, &'static str);
    impl Drop for Gone {
        fn drop(&mut self) {
            let _ = docker(&["volume", "rm", "-f", self.0, self.1]);
        }
    }
    let _gone = Gone(data, repo);

    let dir = tempfile::tempdir().expect("tmp");
    let state_path = dir.path().join("hlb.db");
    let state = hlb_state::State::open(&state_path).await.expect("state");
    let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");

    let home = tempfile::tempdir().expect("house volume");
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).expect("mode");
    std::fs::create_dir(home.path().join("data")).expect("sub");
    std::fs::write(home.path().join("notes.txt"), "kept\n").expect("notes");
    bound(data, home.path());
    let _ = docker(&["volume", "rm", "-f", repo]);
    docker(&["volume", "create", repo]);
    let db = home.path().join("data/app.db").display().to_string();
    py(&format!(
        "import sqlite3; c=sqlite3.connect('{db}'); c.execute('PRAGMA journal_mode=WAL'); \
         c.execute('CREATE TABLE t (v TEXT)'); c.executemany('INSERT INTO t VALUES (?)', \
         [('good',)]*500); c.commit()"
    ));
    // Held open through the pass: its last rows are in the WAL, which restic reads live.
    let mut holder = std::process::Command::new("python3")
        .args([
            "-I",
            "-c",
            &format!(
                "import sqlite3,time; c=sqlite3.connect('{db}'); \
                 c.execute('PRAGMA wal_autocheckpoint=0'); \
                 c.executemany('INSERT INTO t VALUES (?)', [('good',)]*500); c.commit(); \
                 time.sleep(120)"
            ),
        ])
        .spawn()
        .expect("holder");
    std::thread::sleep(std::time::Duration::from_secs(1));

    let manifest: hlb_types::Manifest = serde_yaml_ng::from_str(
        "apiVersion: hlb/v1\nkind: App\nmetadata: { name: demo }\n\
         spec:\n  image: { repo: a/b, tag: \"1\" }\n",
    )
    .expect("manifest");
    state
        .upsert_app("demo", &manifest, None)
        .await
        .expect("app");
    state
        .add_volume("demo", data, &home.path().display().to_string(), true, true)
        .await
        .expect("volume");
    state
        .upsert_destination("nas", repo, "critical,bulky", None)
        .await
        .expect("destination");
    let pass = Pass {
        state: &state,
        vault: &vault,
        state_path: &state_path,
        fallback_repo: None,
        network: "bridge",
        postgres_admin: None,
        mariadb_admin: None,
        schedule: hlb_backup::Schedule::default(),
        force: true,
        only: None,
        orchestrator: None,
        s3_endpoint: None,
    };
    let mut said = Vec::new();
    let sum = pass
        .run(&mut |e| said.push(format!("{e:?}")))
        .await
        .expect("pass");
    assert_eq!(sum.failed, 0, "{said:#?}");
    let _ = holder.kill();
    let _ = holder.wait();
    py(&format!(
        "import sqlite3; c=sqlite3.connect('{db}'); c.execute(\"UPDATE t SET v='later'\"); c.commit()"
    ));

    // The site's volume of the same name: empty, bound where the test can read it.
    let site = tempfile::tempdir().expect("site volume");
    bound(data, site.path());
    let socket = std::path::Path::new("/var/run/docker.sock");
    let docker_api = hlb_orchestrator::SwarmOrchestrator::connect_unix(socket)
        .await
        .expect("docker");
    let restore = Restore {
        state: &state,
        vault: &vault,
        fallback_repo: None,
        network: "bridge",
        orchestrator: None,
    };
    let scratch = tempfile::tempdir().expect("scratch");
    let sent = restore
        .volume_to_site(
            "demo",
            data,
            &Site {
                docker: &docker_api,
                socket,
                network: "bridge",
            },
            hlb_backup::images::POSTGRES_CLIENT,
            scratch.path(),
            || async { Ok((u64::MAX / 2, u64::MAX / 2)) },
        )
        .await
        .expect("sent");
    assert!(sent.bytes > 0);
    assert_eq!(sent.sqlite, ["data/app.db"]);

    let root = std::fs::metadata(site.path()).expect("root");
    let was = std::fs::metadata(home.path()).expect("home root");
    assert_eq!(
        (root.uid(), root.mode() & 0o7777),
        (was.uid(), 0o700),
        "the volume's root keeps its owner and mode"
    );
    assert_eq!(
        std::fs::read_to_string(site.path().join("notes.txt")).expect("notes"),
        "kept\n"
    );
    let there = site.path().join("data/app.db").display().to_string();
    assert_eq!(
        std::fs::metadata(&there).expect("db").uid(),
        was.uid(),
        "the database owned as it was"
    );
    assert_eq!(
        py(&format!(
            "import sqlite3; c=sqlite3.connect('file:{there}?mode=ro', uri=True); \
             print(c.execute('PRAGMA integrity_check').fetchone()[0], \
             c.execute(\"SELECT count(*) FROM t WHERE v='good'\").fetchone()[0], \
             c.execute('SELECT count(*) FROM t').fetchone()[0])"
        )),
        "ok 1000 1000",
        "the WAL's last rows are in, the later change is not"
    );
}
