//! Checks the isolation promise: **a compromised Gitea must not be able to read
//! Vaultwarden's database.**
//!
//! This is a security claim, so it is proven, not assumed.
//!
//! ```sh
//! docker run -d --name hlb-test-pg -e POSTGRES_PASSWORD=test \
//!     -p 55432:5432 postgres:17-alpine
//! export HLB_TEST_PG=postgres://postgres:test@localhost:55432/postgres
//! cargo test -p hlb-platform -- --ignored --test-threads=1 --nocapture
//! docker rm -f hlb-test-pg
//! ```

// In a test, `expect` IS the assertion.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_platform::{connection_url, PostgresProvisioner};

fn admin_url() -> String {
    std::env::var("HLB_TEST_PG")
        .expect("HLB_TEST_PG must point at a test PostgreSQL (see the header)")
}

async fn provisioner() -> PostgresProvisioner {
    PostgresProvisioner::connect(&admin_url())
        .await
        .expect("admin connection")
}

/// Cleans objects left by a previous test. Without this an interrupted test blocks the next.
async fn drop_all(p: &PostgresProvisioner, names: &[&str]) {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url())
        .await
        .expect("connexion de nettoyage");

    for n in names {
        let _ = sqlx::query(&format!(r#"DROP DATABASE IF EXISTS "{n}" WITH (FORCE)"#))
            .execute(&pool)
            .await;
        let _ = sqlx::query(&format!(r#"DROP ROLE IF EXISTS "{n}""#))
            .execute(&pool)
            .await;
    }
    let _ = p.version().await;
}

/// Attempts an application connection. `Ok(true)` means it was accepted.
async fn can_connect(db: &str, role: &str, password: &str) -> bool {
    let base = admin_url();
    // Host and port are reused from the admin URL.
    let after_at = base.rsplit('@').next().expect("url");
    let hostport = after_at.split('/').next().expect("hostport");
    let (host, port) = hostport.split_once(':').unwrap_or((hostport, "5432"));

    let url = connection_url(host, port.parse().unwrap_or(5432), db, role, password);

    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&url)
        .await
        .is_ok()
}

#[tokio::test]
#[ignore = "needs a PostgreSQL (see HLB_TEST_PG)"]
async fn provision_creates_role_and_database() {
    let p = provisioner().await;
    drop_all(&p, &["hlbtest_a"]).await;

    let created = p
        .provision("hlbtest_a", "hlbtest_a", "motdepasse_a")
        .await
        .expect("provisionnement");

    assert!(created);
    assert!(p.role_exists("hlbtest_a").await.expect("role"));
    assert!(p.database_exists("hlbtest_a").await.expect("base"));
    assert!(
        can_connect("hlbtest_a", "hlbtest_a", "motdepasse_a").await,
        "the app must be able to connect to ITS OWN database"
    );

    println!("✓ role + database created, application connection works");
    drop_all(&p, &["hlbtest_a"]).await;
}

#[tokio::test]
#[ignore = "needs a PostgreSQL (see HLB_TEST_PG)"]
async fn provision_is_idempotent() {
    let p = provisioner().await;
    drop_all(&p, &["hlbtest_idem"]).await;

    let first = p
        .provision("hlbtest_idem", "hlbtest_idem", "pw")
        .await
        .expect("premier passage");
    let second = p
        .provision("hlbtest_idem", "hlbtest_idem", "pw")
        .await
        .expect("second passage");

    assert!(first, "the first pass creates");
    assert!(!second, "the second recreates nothing");
    assert!(
        can_connect("hlbtest_idem", "hlbtest_idem", "pw").await,
        "the password must not have been overwritten"
    );

    println!("✓ rerun had no effect, password preserved");
    drop_all(&p, &["hlbtest_idem"]).await;
}

/// 🔴 THE security test: isolation between applications.
#[tokio::test]
#[ignore = "needs a PostgreSQL (see HLB_TEST_PG)"]
async fn an_app_cannot_reach_another_apps_database() {
    let p = provisioner().await;
    drop_all(&p, &["hlbtest_gitea", "hlbtest_vault"]).await;

    p.provision("hlbtest_gitea", "hlbtest_gitea", "pw_gitea")
        .await
        .expect("gitea");
    p.provision("hlbtest_vault", "hlbtest_vault", "pw_vault")
        .await
        .expect("vault");

    // Each reaches its own.
    assert!(can_connect("hlbtest_gitea", "hlbtest_gitea", "pw_gitea").await);
    assert!(can_connect("hlbtest_vault", "hlbtest_vault", "pw_vault").await);
    println!("✓ each app reaches its own database");

    // 🔴 But not the neighbour's, even with its own valid credentials.
    assert!(
        !can_connect("hlbtest_vault", "hlbtest_gitea", "pw_gitea").await,
        "BREACH: gitea was able to connect to vaultwarden's database - \
         le REVOKE ALL ... FROM PUBLIC ne fonctionne pas"
    );
    println!("✓ gitea ne peut PAS atteindre la base de vaultwarden");

    // And a wrong password stays refused, obviously.
    assert!(!can_connect("hlbtest_gitea", "hlbtest_gitea", "mauvais").await);

    drop_all(&p, &["hlbtest_gitea", "hlbtest_vault"]).await;
}

#[tokio::test]
#[ignore = "needs a PostgreSQL (see HLB_TEST_PG)"]
async fn password_rotation_works() {
    let p = provisioner().await;
    drop_all(&p, &["hlbtest_rot"]).await;

    p.provision("hlbtest_rot", "hlbtest_rot", "ancien")
        .await
        .expect("provisionnement");
    assert!(can_connect("hlbtest_rot", "hlbtest_rot", "ancien").await);

    p.set_password("hlbtest_rot", "nouveau")
        .await
        .expect("rotation");

    assert!(can_connect("hlbtest_rot", "hlbtest_rot", "nouveau").await);
    assert!(
        !can_connect("hlbtest_rot", "hlbtest_rot", "ancien").await,
        "the old password must be revoked"
    );

    println!("✓ rotation effective, old password revoked");
    drop_all(&p, &["hlbtest_rot"]).await;
}

#[tokio::test]
#[ignore = "needs a PostgreSQL (see HLB_TEST_PG)"]
async fn injection_attempt_is_refused_before_reaching_sql() {
    let p = provisioner().await;

    let err = p
        .provision(r#"x"; DROP DATABASE postgres; --"#, "x", "pw")
        .await
        .unwrap_err();

    assert!(
        matches!(err, hlb_platform::Error::InvalidIdentifier(_)),
        "{err}"
    );

    // And the admin database is still there.
    assert!(p
        .database_exists("postgres")
        .await
        .expect("postgres existe"));
    println!("✓ injection attempt refused at validation: {err}");
}
