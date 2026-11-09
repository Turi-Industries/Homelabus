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
