//! Vérifie la promesse d'isolation du §3.1 : **un Gitea compromis ne doit pas pouvoir
//! lire la base de Vaultwarden.**
//!
//! C'est une revendication de sécurité, donc elle se prouve, elle ne se suppose pas.
//!
//! ```sh
//! docker run -d --name hlb-test-pg -e POSTGRES_PASSWORD=test \
//!     -p 55432:5432 postgres:17-alpine
//! export HLB_TEST_PG=postgres://postgres:test@localhost:55432/postgres
//! cargo test -p hlb-platform -- --ignored --test-threads=1 --nocapture
//! docker rm -f hlb-test-pg
//! ```

// Dans un test, `expect` EST l'assertion.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_platform::{connection_url, PostgresProvisioner};

fn admin_url() -> String {
    std::env::var("HLB_TEST_PG")
        .expect("HLB_TEST_PG doit pointer vers un PostgreSQL de test (voir l'en-tête)")
}

async fn provisioner() -> PostgresProvisioner {
    PostgresProvisioner::connect(&admin_url())
        .await
        .expect("connexion admin")
}

/// Nettoie les objets d'un test précédent. Sans ça, un test interrompu bloque le suivant.
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

/// Tente une connexion applicative. `Ok(true)` = connexion acceptée.
async fn can_connect(db: &str, role: &str, password: &str) -> bool {
    let base = admin_url();
    // On réutilise hôte et port de l'URL d'admin.
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
#[ignore = "nécessite un PostgreSQL (voir HLB_TEST_PG)"]
async fn provision_creates_role_and_database() {
    let p = provisioner().await;
    drop_all(&p, &["hlbtest_a"]).await;

    let created = p
        .provision("hlbtest_a", "hlbtest_a", "motdepasse_a")
        .await
        .expect("provisionnement");

    assert!(created);
    assert!(p.role_exists("hlbtest_a").await.expect("rôle"));
    assert!(p.database_exists("hlbtest_a").await.expect("base"));
    assert!(
        can_connect("hlbtest_a", "hlbtest_a", "motdepasse_a").await,
        "l'app doit pouvoir se connecter à SA base"
    );

    println!("✓ rôle + base créés, connexion applicative fonctionnelle");
    drop_all(&p, &["hlbtest_a"]).await;
}

#[tokio::test]
#[ignore = "nécessite un PostgreSQL (voir HLB_TEST_PG)"]
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

    assert!(first, "le premier passage crée");
    assert!(!second, "le second ne recrée rien");
    assert!(
        can_connect("hlbtest_idem", "hlbtest_idem", "pw").await,
        "le mot de passe ne doit pas avoir été écrasé"
    );

    println!("✓ relance sans effet, mot de passe préservé");
    drop_all(&p, &["hlbtest_idem"]).await;
}

/// 🔴 LE test de sécurité : l'isolation entre applications.
#[tokio::test]
#[ignore = "nécessite un PostgreSQL (voir HLB_TEST_PG)"]
async fn an_app_cannot_reach_another_apps_database() {
    let p = provisioner().await;
    drop_all(&p, &["hlbtest_gitea", "hlbtest_vault"]).await;

    p.provision("hlbtest_gitea", "hlbtest_gitea", "pw_gitea")
        .await
        .expect("gitea");
    p.provision("hlbtest_vault", "hlbtest_vault", "pw_vault")
        .await
        .expect("vault");

    // Chacun accède à la sienne.
    assert!(can_connect("hlbtest_gitea", "hlbtest_gitea", "pw_gitea").await);
    assert!(can_connect("hlbtest_vault", "hlbtest_vault", "pw_vault").await);
    println!("✓ chaque app accède à sa propre base");

    // 🔴 Mais pas à celle du voisin, même avec ses propres identifiants valides.
    assert!(
        !can_connect("hlbtest_vault", "hlbtest_gitea", "pw_gitea").await,
        "FAILLE : gitea a pu se connecter à la base de vaultwarden — \
         le REVOKE ALL ... FROM PUBLIC ne fonctionne pas"
    );
    println!("✓ gitea ne peut PAS atteindre la base de vaultwarden");

    // Et un mauvais mot de passe reste refusé, évidemment.
    assert!(!can_connect("hlbtest_gitea", "hlbtest_gitea", "mauvais").await);

    drop_all(&p, &["hlbtest_gitea", "hlbtest_vault"]).await;
}

#[tokio::test]
#[ignore = "nécessite un PostgreSQL (voir HLB_TEST_PG)"]
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
        "l'ancien mot de passe doit être révoqué"
    );

    println!("✓ rotation effective, ancien mot de passe révoqué");
    drop_all(&p, &["hlbtest_rot"]).await;
}

#[tokio::test]
#[ignore = "nécessite un PostgreSQL (voir HLB_TEST_PG)"]
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

    // Et la base d'administration est toujours là.
    assert!(p
        .database_exists("postgres")
        .await
        .expect("postgres existe"));
    println!("✓ tentative d'injection refusée à la validation : {err}");
}
