//! The isolation promise on the MariaDB side: **a compromised Gitea must not be able
//! to read Vaultwarden's database.**
//!
//! The traps are NOT the same as for PostgreSQL, which is precisely why this file
//! exists: transposing the Postgres test would prove nothing here.
//!
//! ⚠️ **These tests have not been run yet**: the MariaDB image was not present on the
//! development machine and could not be pulled. They are written, gated, and waiting
//! for a real run - said plainly rather than left implied.
//!
//! ```sh
//! docker run -d --name hlb-test-my -e MARIADB_ROOT_PASSWORD=test \
//!     -p 53306:3306 mariadb:11.8
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
        .expect("connexion admin")
}

/// Cleans objects left by a previous test: an interrupted test would block the next.
async fn nettoyer(bases: &[&str], users: &[&str]) {
    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url())
        .await
        .expect("connexion de nettoyage");

    for b in bases {
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS `{b}`"))
            .execute(&pool)
            .await;
    }
    for u in users {
        let _ = sqlx::query(&format!("DROP USER IF EXISTS '{u}'@'%'"))
            .execute(&pool)
            .await;
    }
}

#[tokio::test]
#[ignore = "needs a MariaDB (see HLB_TEST_MYSQL)"]
async fn an_app_cannot_reach_another_apps_database() {
    // 🔴 THE test. The rest of the crate only matters if this one passes.
    nettoyer(&["giteatest", "vaulttest"], &["giteatest", "vaulttest"]).await;
    let p = provisioner().await;

    p.provision("giteatest", "giteatest", "mdp-gitea")
        .await
        .expect("provisionnement gitea");
    p.provision("vaulttest", "vaulttest", "mdp-vault")
        .await
        .expect("provisionnement vault");

    // Gitea se connecte avec SES identifiants et tente de lire la base de Vaultwarden.
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
    assert!(r.is_err(), "gitea ne doit RIEN pouvoir lire chez vaulttest");

    // And the positive proof: the granted list contains only its own.
    let granted = p.granted_databases("giteatest").await.expect("grants");
    assert!(
        !granted.iter().any(|b| b == "vaulttest"),
        "🔴 gitea holds a grant on vaulttest: {granted:?}"
    );

    nettoyer(&["giteatest", "vaulttest"], &["giteatest", "vaulttest"]).await;
}

#[tokio::test]
#[ignore = "needs a MariaDB (see HLB_TEST_MYSQL)"]
async fn the_grant_is_scoped_to_one_database_not_all() {
    // 🔴 `GRANT ALL ON *.*` is the example found everywhere, and it grants access to
    // the WHOLE instance. The scope must be `database.*`.
    nettoyer(&["scopetest"], &["scopetest"]).await;
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

    nettoyer(&["scopetest"], &["scopetest"]).await;
}

#[tokio::test]
#[ignore = "needs a MariaDB (see HLB_TEST_MYSQL)"]
async fn the_user_can_connect_from_another_container() {
    // 🔴 MariaDB trap 1: a user created as `'name'@'localhost'` is refused from
    // another container, with a message about the password
    // incorrect alors qu'il est bon.
    nettoyer(&["hosttest"], &["hosttest"]).await;
    let p = provisioner().await;

    p.provision("hosttest", "hosttest", "mdp")
        .await
        .expect("provisionnement");
    assert!(
        p.user_exists("hosttest").await.expect("lecture"),
        "l'utilisateur doit exister en '@%', pas en '@localhost'"
    );

    nettoyer(&["hosttest"], &["hosttest"]).await;
}

#[tokio::test]
#[ignore = "needs a MariaDB (see HLB_TEST_MYSQL)"]
async fn provisioning_is_idempotent() {
    nettoyer(&["idemtest"], &["idemtest"]).await;
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

    nettoyer(&["idemtest"], &["idemtest"]).await;
}

#[tokio::test]
#[ignore = "needs a MariaDB (see HLB_TEST_MYSQL)"]
async fn password_rotation_works() {
    nettoyer(&["rottest"], &["rottest"]).await;
    let p = provisioner().await;

    p.provision("rottest", "rottest", "ancien")
        .await
        .expect("provisionnement");
    p.set_password("rottest", "nouveau")
        .await
        .expect("rotation");

    let url = admin_url();
    let host = url.split('@').nth(1).expect("host");
    let nouvelle = format!(
        "mysql://rottest:nouveau@{}",
        host.replace("/mysql", "/rottest")
    );

    sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&nouvelle)
        .await
        .expect("le nouveau mot de passe doit fonctionner");

    nettoyer(&["rottest"], &["rottest"]).await;
}

#[tokio::test]
#[ignore = "needs a MariaDB (see HLB_TEST_MYSQL)"]
async fn a_wildcard_name_is_refused_before_reaching_sql() {
    // Validation must refuse BEFORE any query: `my_app` would grant a right
    // sur `monXapp` et toutes ses variantes.
    let p = provisioner().await;
    assert!(p.provision("mon_app", "mon_app", "mdp").await.is_err());
    assert!(p
        .provision("ok", "a; DROP DATABASE x", "mdp")
        .await
        .is_err());
}
