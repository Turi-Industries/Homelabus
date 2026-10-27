//! A PostgreSQL database through the pass and back, against a real server and the
//! catalog's restic: the database comes back as the pass dumped it — a table added since
//! gone, every object still the app's, shut to other roles —, and the copy the restore
//! took first undoes it.
//!
//! ```sh
//! cargo test -p hlb-backup-run --test database -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_backup_run::restore::{Database, Restore};
use hlb_backup_run::{Event, Pass};

const NETWORK: &str = "hlb-test-dbrestore";
const SERVER: &str = "hlb-test-dbrestore-pg";
const PASSWORD: &str = "admin-password";

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

/// `sql` in `db` as `user`, over the server's socket; its rows, `|`-separated.
fn psql(user: &str, db: &str, sql: &str) -> String {
    let out = docker(&[
        "exec",
        SERVER,
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
        "psql as {user} on \"{sql}\":\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Removes the server, its network and the repository when dropped, failing or not.
struct Cleanup(&'static str);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = docker(&["rm", "-f", SERVER]);
        let _ = docker(&["network", "rm", NETWORK]);
        let _ = docker(&["volume", "rm", "-f", self.0]);
    }
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_database_dumped_comes_back_as_the_app_s_and_the_copy_taken_first_undoes_it() {
    let repo = "hlb-dbrestore-repo";
    let _cleanup = Cleanup(repo);
    let _ = docker(&["rm", "-f", SERVER]);
    let _ = docker(&["volume", "rm", "-f", repo]);
    docker(&["network", "create", NETWORK]);
    docker(&["volume", "create", repo]);
    // The server is the dump client's own image: the two are one major.
    let up = docker(&[
        "run",
        "-d",
        "--name",
        SERVER,
        "--network",
        NETWORK,
        "-e",
        &format!("POSTGRES_PASSWORD={PASSWORD}"),
        hlb_backup::images::POSTGRES_CLIENT,
    ]);
    assert!(
        up.status.success(),
        "{}",
        String::from_utf8_lossy(&up.stderr)
    );
    // Over TCP: the image first runs a server for its initialisation on the socket
    // alone, then restarts — ready on the socket, a statement could land in the restart.
    let ready = (0..60).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(500));
        docker(&[
            "exec",
            SERVER,
            "pg_isready",
            "-h",
            "127.0.0.1",
            "-U",
            "postgres",
        ])
        .status
        .success()
    });
    assert!(ready, "PostgreSQL never answered");

    // The app's role and database as `ProvisionDatabase` leaves them, an extension
    // enabled by the administrator, and a schema the app made itself.
    psql(
        "postgres",
        "postgres",
        "CREATE ROLE chat LOGIN PASSWORD 'chat-password'",
    );
    psql("postgres", "postgres", "CREATE ROLE other LOGIN");
    for s in hlb_platform::database_statements("chat", "chat").expect("statements") {
        psql("postgres", "postgres", &s);
    }
    psql(
        "postgres",
        "chat",
        &hlb_platform::extension_statement("citext").expect("statement"),
    );
    psql("chat", "chat", "CREATE SCHEMA app");
    psql(
        "chat",
        "chat",
        "CREATE TABLE app.kv (k citext PRIMARY KEY, v text)",
    );
    psql("chat", "chat", "INSERT INTO app.kv VALUES ('a', 'été')");

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
        .upsert_destination("nas", repo, "critical,bulky", None)
        .await
        .expect("destination");

    let admin = format!("postgres://postgres:{PASSWORD}@{SERVER}:5432/postgres");
    let pass = Pass {
        state: &state,
        vault: &vault,
        state_path: &state_path,
        fallback_repo: None,
        network: NETWORK,
        postgres_admin: Some(&admin),
        mariadb_admin: None,
        schedule: hlb_backup::Schedule::default(),
        force: true,
        only: Some("chat"),
        orchestrator: None,
        s3_endpoint: None,
    };
    let mut events = Vec::new();
    let sum = pass.run(&mut |e| events.push(e)).await.expect("pass");
    assert_eq!(sum.failed, 0, "{events:?}");
    assert!(
        events.iter().any(
            |e| matches!(e, Event::Done { what, destination, .. } if what == "chat/chat" && destination == "nas")
        ),
        "{events:?}"
    );

    // What a failed update leaves: a row changed, one added, a table a migration made.
    psql(
        "chat",
        "chat",
        "UPDATE app.kv SET v = 'hiver' WHERE k = 'a'",
    );
    psql("chat", "chat", "INSERT INTO app.kv VALUES ('b', 'since')");
    psql("chat", "chat", "CREATE TABLE app.later (x int)");
    let rows = "SELECT string_agg(k || '=' || v, ',' ORDER BY k) FROM app.kv";
    let later = "SELECT to_regclass('app.later') IS NOT NULL";

    let restore = Restore {
        state: &state,
        vault: &vault,
        fallback_repo: None,
        network: NETWORK,
        orchestrator: None,
    };
    let db = Database {
        engine: hlb_types::DbEngine::Postgres,
        name: "chat",
        role: "chat",
        extensions: &["citext".to_string()],
    };
    let source = restore
        .find_dump("chat", hlb_types::DbEngine::Postgres, "chat", None, None)
        .await
        .expect("the pass's dump, recorded as taken");
    let before = restore
        .database_in_place("chat", &db, &admin, &source)
        .await
        .expect("restored");
    assert_eq!(psql("chat", "chat", rows), "a=été");
    assert_eq!(
        psql("chat", "chat", later),
        "f",
        "a table made since is gone"
    );
    assert_eq!(
        psql(
            "postgres",
            "chat",
            "SELECT string_agg(tableowner, ',') FROM pg_tables WHERE schemaname = 'app'"
        ),
        "chat",
        "restored by the administrator, the tables are still the app's"
    );
    psql(
        "chat",
        "chat",
        "INSERT INTO app.kv VALUES ('c', 'written after')",
    );
    assert_eq!(
        psql(
            "postgres",
            "postgres",
            "SELECT has_database_privilege('other', 'chat', 'CONNECT')"
        ),
        "f",
        "recreated, the database is still shut to other roles"
    );
    assert_eq!(
        psql("chat", "chat", "SELECT count(*) FROM app.kv WHERE k = 'A'"),
        "1",
        "the extension's type still compares"
    );

    // The copy taken first undoes the restore.
    let undo = restore
        .find_dump(
            "chat",
            hlb_types::DbEngine::Postgres,
            "chat",
            None,
            Some(&before),
        )
        .await
        .expect("the copy taken before");
    restore
        .database_in_place("chat", &db, &admin, &undo)
        .await
        .expect("undone");
    assert_eq!(psql("chat", "chat", rows), "a=hiver,b=since");
    assert_eq!(psql("chat", "chat", later), "t");

    // Asked for the latest again, the restore never takes its own copy.
    let latest = restore
        .find_dump("chat", hlb_types::DbEngine::Postgres, "chat", None, None)
        .await
        .expect("latest");
    assert_eq!(latest.snapshot.id, source.snapshot.id);
    println!("✓ chat: dumped, restored whole, and the restore undone");
}
