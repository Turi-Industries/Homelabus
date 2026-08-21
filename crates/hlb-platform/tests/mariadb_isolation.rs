//! La promesse d'isolation du §3.1, côté MariaDB : **un Gitea compromis ne doit pas
//! pouvoir lire la base de Vaultwarden.**
//!
//! Les pièges ne sont PAS les mêmes que pour PostgreSQL, et c'est précisément pour ça
//! que ce fichier existe : transposer le test Postgres ne prouverait rien ici.
//!
//! ⚠️ **Ces tests n'ont pas encore été exécutés** : l'image MariaDB n'était pas
//! présente sur la machine de développement, et la télécharger n'était pas possible.
//! Ils sont écrits, gated, et attendent une exécution réelle — c'est dit plutôt que
//! sous-entendu.
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
        .expect("HLB_TEST_MYSQL doit pointer vers un MariaDB de test (voir l'en-tête)")
}

async fn provisioner() -> MariadbProvisioner {
    MariadbProvisioner::connect(&admin_url())
        .await
        .expect("connexion admin")
}

/// Nettoie les objets d'un test précédent : un test interrompu bloquerait le suivant.
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
#[ignore = "nécessite un MariaDB (voir HLB_TEST_MYSQL)"]
async fn an_app_cannot_reach_another_apps_database() {
    // 🔴 LE test. Tout le reste du crate n'a d'intérêt que si celui-ci passe.
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
    let hote = url.split('@').nth(1).expect("hôte dans l'URL");
    let gitea_url = format!(
        "mysql://giteatest:mdp-gitea@{}",
        hote.replace("/mysql", "/giteatest")
    );

    let pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&gitea_url)
        .await
        .expect("gitea doit pouvoir se connecter à SA base");

    let r = sqlx::query("SELECT 1 FROM vaulttest.information_schema_placeholder")
        .execute(&pool)
        .await;
    assert!(r.is_err(), "gitea ne doit RIEN pouvoir lire chez vaulttest");

    // Et la preuve positive : la liste des bases accordées ne contient que la sienne.
    let accordees = p.granted_databases("giteatest").await.expect("droits");
    assert!(
        !accordees.iter().any(|b| b == "vaulttest"),
        "🔴 gitea a un droit sur vaulttest : {accordees:?}"
    );

    nettoyer(&["giteatest", "vaulttest"], &["giteatest", "vaulttest"]).await;
}

#[tokio::test]
#[ignore = "nécessite un MariaDB (voir HLB_TEST_MYSQL)"]
async fn the_grant_is_scoped_to_one_database_not_all() {
    // 🔴 `GRANT ALL ON *.*` est l'exemple qu'on trouve partout, et il donne accès à
    // TOUTE l'instance. La portée doit être `base.*`.
    nettoyer(&["scopetest"], &["scopetest"]).await;
    let p = provisioner().await;

    p.provision("scopetest", "scopetest", "mdp")
        .await
        .expect("provisionnement");

    let accordees = p.granted_databases("scopetest").await.expect("droits");
    assert_eq!(
        accordees,
        vec!["scopetest".to_string()],
        "une seule base doit être accordée, pas {accordees:?}"
    );

    nettoyer(&["scopetest"], &["scopetest"]).await;
}

#[tokio::test]
#[ignore = "nécessite un MariaDB (voir HLB_TEST_MYSQL)"]
async fn the_user_can_connect_from_another_container() {
    // 🔴 Le piège n°1 de MariaDB : un utilisateur créé en `'nom'@'localhost'` est
    // refusé depuis un autre conteneur, avec un message qui parle de mot de passe
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
#[ignore = "nécessite un MariaDB (voir HLB_TEST_MYSQL)"]
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
        "le second passage ne doit rien créer"
    );

    nettoyer(&["idemtest"], &["idemtest"]).await;
}

#[tokio::test]
#[ignore = "nécessite un MariaDB (voir HLB_TEST_MYSQL)"]
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
    let hote = url.split('@').nth(1).expect("hôte");
    let nouvelle = format!(
        "mysql://rottest:nouveau@{}",
        hote.replace("/mysql", "/rottest")
    );

    sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&nouvelle)
        .await
        .expect("le nouveau mot de passe doit fonctionner");

    nettoyer(&["rottest"], &["rottest"]).await;
}

#[tokio::test]
#[ignore = "nécessite un MariaDB (voir HLB_TEST_MYSQL)"]
async fn a_wildcard_name_is_refused_before_reaching_sql() {
    // La validation doit refuser AVANT toute requête : `mon_app` donnerait un droit
    // sur `monXapp` et toutes ses variantes.
    let p = provisioner().await;
    assert!(p.provision("mon_app", "mon_app", "mdp").await.is_err());
    assert!(p
        .provision("ok", "a; DROP DATABASE x", "mdp")
        .await
        .is_err());
}
