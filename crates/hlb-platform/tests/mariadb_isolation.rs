//! The isolation promise on the MariaDB side: **a compromised Gitea must not be able
//! to read Vaultwarden's database.**
//!
//! The traps are NOT the same as for PostgreSQL, which is precisely why this file
//! exists: transposing the Postgres test would prove nothing here.
//!
//! First run against a real MariaDB 11.8 on 2026-10-17, and 12.3 on 2026-10-27.
//!
//! ```sh
//! docker run -d --name hlb-test-my -e MARIADB_ROOT_PASSWORD=test \
//!     -p 53306:3306 mariadb:12.3
//! export HLB_TEST_MYSQL=mysql://root:test@localhost:53306/mysql
//! cargo test -p hlb-platform --test mariadb_isolation -- --ignored --test-threads=1
//! docker rm -f hlb-test-my
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_platform::MariadbProvisioner;

fn admin_url() -> String {
    std::env::var("HLB_TEST_MYSQL")
        .expect("HLB_TEST_MYSQL must point at a test MariaDB (see the header)")
}

async fn provisioner() -> MariadbProvisioner {
    MariadbProvisioner::connect(&admin_url())
        .await
        .expect("signin admin")
}

/// Cleans objects left by a previous test: an interrupted test would block the next.
async fn clean_up(bases: &[&str], users: &[&str]) {
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url())
        .await
        .expect("signin de nettoyage");

    for b in bases {
        let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS `{b}`"
        )))
        .execute(&pool)
        .await;
    }
    for u in users {
        let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP USER IF EXISTS '{u}'@'%'"
        )))
        .execute(&pool)
        .await;
    }
}

#[tokio::test]
#[ignore = "needs a MariaDB (see HLB_TEST_MYSQL)"]
async fn an_app_cannot_reach_another_apps_database() {
    // 🔴 THE test. The rest of the crate only matters if this one passes.
    clean_up(&["giteatest", "vaulttest"], &["giteatest", "vaulttest"]).await;
    let p = provisioner().await;

    p.provision("giteatest", "giteatest", "mdp-gitea")
        .await
        .expect("provisionnement gitea");
    p.provision("vaulttest", "vaulttest", "mdp-vault")
        .await
        .expect("vault provisioning");

    // Gitea connects with ITS credentials and tries to read Vaultwarden's database.
    let url = admin_url();
    let host = url.split('@').nth(1).expect("host in the URL");
    let gitea_url = format!(
        "mysql://giteatest:mdp-gitea@{}",
        host.replace("/mysql", "/giteatest")
    );

    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&gitea_url)
        .await
        .expect("gitea must be able to connect to ITS OWN database");

    let r = sqlx::query("SELECT 1 FROM vaulttest.information_schema_placeholder")
        .execute(&pool)
        .await;
    assert!(
        r.is_err(),
        "gitea must be able to read NOTHING at vaulttest"
    );

    // And the positive proof: the granted list contains only its own.
    let granted = p.granted_databases("giteatest").await.expect("grants");
    assert!(
        !granted.iter().any(|b| b == "vaulttest"),
        "🔴 gitea holds a grant on vaulttest: {granted:?}"
    );

    clean_up(&["giteatest", "vaulttest"], &["giteatest", "vaulttest"]).await;
}

#[tokio::test]
#[ignore = "needs a MariaDB (see HLB_TEST_MYSQL)"]
async fn the_grant_is_scoped_to_one_database_not_all() {
    // 🔴 `GRANT ALL ON *.*` is the example found everywhere, and it grants access to
    // the WHOLE instance. The scope must be `database.*`.
    clean_up(&["scopetest"], &["scopetest"]).await;
    let p = provisioner().await;

    p.provision("scopetest", "scopetest", "mdp")
        .await
        .expect("provisionnement");

    let granted = p.granted_databases("scopetest").await.expect("grants");
    assert_eq!(
        granted,
        vec!["scopetest".to_string()],
        "exactly one database must be granted, not {granted:?}"
    );

    clean_up(&["scopetest"], &["scopetest"]).await;
}

#[tokio::test]
#[ignore = "needs a MariaDB (see HLB_TEST_MYSQL)"]
async fn the_user_can_connect_from_another_container() {
    // 🔴 MariaDB trap 1: a user created as `'name'@'localhost'` is refused from
    // another container, with a message about an incorrect password while the
    // password is fine.
    clean_up(&["hosttest"], &["hosttest"]).await;
    let p = provisioner().await;

    p.provision("hosttest", "hosttest", "mdp")
        .await
        .expect("provisionnement");
    assert!(
        p.user_exists("hosttest").await.expect("read"),
        "the user must exist as '@%', not as '@localhost'"
    );

    clean_up(&["hosttest"], &["hosttest"]).await;
}

#[tokio::test]
#[ignore = "needs a MariaDB (see HLB_TEST_MYSQL)"]
async fn provisioning_is_idempotent() {
    clean_up(&["idemtest"], &["idemtest"]).await;
    let p = provisioner().await;

    assert!(p
        .provision("idemtest", "idemtest", "mdp")
        .await
        .expect("1er"));
    assert!(
        !p.provision("idemtest", "idemtest", "mdp")
            .await
            .expect("2e"),
        "the second pass must create nothing"
    );

    clean_up(&["idemtest"], &["idemtest"]).await;
}

#[tokio::test]
#[ignore = "needs a MariaDB (see HLB_TEST_MYSQL)"]
async fn password_rotation_works() {
    clean_up(&["rottest"], &["rottest"]).await;
    let p = provisioner().await;

    p.provision("rottest", "rottest", "old")
        .await
        .expect("provisionnement");
    p.set_password("rottest", "new_one")
        .await
        .expect("rotation");

    let url = admin_url();
    let host = url.split('@').nth(1).expect("host");
    let update = format!(
        "mysql://rottest:new_one@{}",
        host.replace("/mysql", "/rottest")
    );

    sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&update)
        .await
        .expect("the new password must work");

    clean_up(&["rottest"], &["rottest"]).await;
}

#[tokio::test]
#[ignore = "needs a MariaDB (see HLB_TEST_MYSQL)"]
async fn a_wildcard_name_is_refused_before_reaching_sql() {
    // `%` in a GRANT matches every database: refused before any query.
    let p = provisioner().await;
    assert!(p.provision("my%app", "myapp", "pw").await.is_err());
    assert!(p.provision("ok", "a; DROP DATABASE x", "pw").await.is_err());
}

#[tokio::test]
#[ignore = "needs a MariaDB (see HLB_TEST_MYSQL)"]
async fn an_underscore_grants_its_own_database_and_no_lookalike() {
    // Seafile's databases carry `_`, which a GRANT reads as "any one character":
    // escaped, the grant on `ccnet_db` must not reach `ccnetXdb`.
    clean_up(&["ccnet_db", "ccnetXdb"], &["sfadm"]).await;
    let p = provisioner().await;
    p.provision("ccnet_db", "sfadm", "pw-sf")
        .await
        .expect("a name with an underscore is provisioned");

    let admin = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url())
        .await
        .expect("admin");
    sqlx::query("CREATE DATABASE `ccnetXdb`")
        .execute(&admin)
        .await
        .expect("the lookalike");

    let url = admin_url();
    let host = url.split('@').nth(1).expect("host in the URL");
    let app = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "mysql://sfadm:pw-sf@{}",
            host.replace("/mysql", "/ccnet_db")
        ))
        .await
        .expect("the app reaches its own database");
    sqlx::query("CREATE TABLE ccnet_db.t (i INT)")
        .execute(&app)
        .await
        .expect("it writes in its own");
    let lookalike = sqlx::query("CREATE TABLE ccnetXdb.t (i INT)")
        .execute(&app)
        .await;
    assert!(
        lookalike.is_err(),
        "🔴 the grant on ccnet_db reached ccnetXdb"
    );

    clean_up(&["ccnet_db", "ccnetXdb"], &["sfadm"]).await;
}

/// 🔴 An assertion's query comes from a manifest: it reads in the app's own database,
/// and a write inside it is refused.
#[tokio::test]
#[ignore = "needs a MariaDB (see the header)"]
async fn an_assertion_reads_one_value_and_writes_nothing() {
    clean_up(&["hlb_assert"], &[]).await;
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url())
        .await
        .expect("connect");
    for q in [
        "CREATE DATABASE hlb_assert",
        "CREATE TABLE hlb_assert.EmailUser (email VARCHAR(255))",
        "INSERT INTO hlb_assert.EmailUser VALUES ('me@example.com')",
    ] {
        sqlx::query(q).execute(&pool).await.expect(q);
    }
    let p = provisioner().await;
    assert_eq!(
        p.read_one(
            "hlb_assert",
            "SELECT count(*) FROM EmailUser WHERE email = 'me@example.com'"
        )
        .await
        .expect("read"),
        Some("1".into())
    );
    assert_eq!(
        p.read_one(
            "hlb_assert",
            "SELECT email FROM EmailUser WHERE email = 'nobody'"
        )
        .await
        .expect("read"),
        None
    );
    p.read_one("hlb_assert", "DELETE FROM EmailUser")
        .await
        .expect_err("a write is refused");
    assert_eq!(
        p.read_one("hlb_assert", "SELECT count(*) FROM EmailUser")
            .await
            .expect("read"),
        Some("1".into())
    );
    clean_up(&["hlb_assert"], &[]).await;
}
