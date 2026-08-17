//! Provisionnement MariaDB isolé (§3.1).
//!
//! Même promesse que PostgreSQL — *un Gitea compromis ne peut pas lire la base de
//! Vaultwarden* — mais les pièges sont **différents**, et transposer le code Postgres
//! tel quel donnerait une isolation qui n'en est pas une.
//!
//! ## 🔴 Piège n°1 : un utilisateur MariaDB, c'est `'nom'@'hôte'`
//!
//! Le nom seul n'identifie personne. `'gitea'@'localhost'` et `'gitea'@'%'` sont deux
//! comptes **distincts**, avec des mots de passe et des droits distincts.
//!
//! Conséquence directe : un `CREATE USER 'gitea'` sans partie hôte crée
//! `'gitea'@'%'` sur certaines versions et `'gitea'@'localhost'` sur d'autres. Dans le
//! second cas, l'app tourne dans un autre conteneur, n'est donc pas « localhost », et
//! se voit refuser l'accès avec un message qui parle de mot de passe incorrect — alors
//! que le mot de passe est bon.
//!
//! On déclare donc **toujours** l'hôte explicitement.
//!
//! ## 🔴 Piège n°2 : `GRANT ALL ON *.*` détruit l'isolation
//!
//! C'est l'exemple qu'on trouve partout. Il donne accès à **toutes** les bases de
//! l'instance, ce qui est exactement ce qu'on cherche à empêcher. La portée doit être
//! `base.*`, jamais `*.*`.
//!
//! ## 🔴 Piège n°3 : les jokers dans le nom de base
//!
//! Dans un `GRANT`, `_` et `%` sont des **jokers**. Une base nommée `mon_app` donne un
//! droit sur `monXapp`, `mon-app`, `monapp`… Il faut échapper ces caractères, ou
//! refuser les noms qui en contiennent — ce qu'on fait ici, parce qu'un nom de base
//! qui ressemble à un motif est une mauvaise idée de toute façon.

use sqlx::mysql::{MySqlPoolOptions, MySqlRow};
use sqlx::{MySqlPool, Row};

use crate::{Error, Result};

/// L'hôte depuis lequel les apps se connectent.
///
/// `%` = n'importe où. Sur un réseau overlay Docker, l'adresse d'un conteneur change
/// à chaque redéploiement : restreindre par IP casserait au premier redémarrage. C'est
/// le réseau qui isole, pas cette colonne.
const APP_HOST: &str = "%";

pub struct MariadbProvisioner {
    pool: MySqlPool,
}

impl MariadbProvisioner {
    pub async fn connect(admin_url: &str) -> Result<Self> {
        let pool = MySqlPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(admin_url)
            .await
            .map_err(|e| Error::Connect(e.to_string()))?;

        Ok(Self { pool })
    }

    /// Crée la base et son utilisateur isolé.
    ///
    /// Renvoie `true` si quelque chose a été créé.
    pub async fn provision(&self, database: &str, user: &str, password: &str) -> Result<bool> {
        validate_identifier(database)?;
        validate_identifier(user)?;

        let mut created = false;

        // `utf8mb4` explicitement : le `utf8` de MySQL ne fait que 3 octets et ne
        // stocke PAS les émojis ni certains idéogrammes. Une insertion échoue alors
        // sur « Incorrect string value » longtemps après l'installation.
        if !self.database_exists(database).await? {
            let stmt = format!(
                "CREATE DATABASE `{}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
                escape_ident(database)
            );
            sqlx::query(&stmt)
                .execute(&self.pool)
                .await
                .map_err(|e| Error::Sql(e.to_string()))?;
            created = true;
            tracing::info!(database, "base créée");
        }

        // 🔴 L'hôte fait partie de l'identité. Sans lui, l'app ne se connecte pas.
        if !self.user_exists(user).await? {
            let stmt = format!(
                "CREATE USER '{}'@'{APP_HOST}' IDENTIFIED BY '{}'",
                escape_str(user),
                escape_str(password)
            );
            sqlx::query(&stmt)
                .execute(&self.pool)
                .await
                .map_err(|e| Error::Sql(redact(&e.to_string(), password)))?;
            created = true;
            tracing::info!(user, "utilisateur créé");
        }

        // 🔴 La portée : `base.*` et JAMAIS `*.*`. C'est toute l'isolation.
        let grant = format!(
            "GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'{APP_HOST}'",
            escape_ident(database),
            escape_str(user)
        );
        sqlx::query(&grant)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;

        // MariaDB relit ses tables de droits au démarrage : sans FLUSH, un droit
        // accordé peut n'être visible qu'après un redémarrage du serveur.
        sqlx::query("FLUSH PRIVILEGES")
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;

        Ok(created)
    }

    /// Rotation du mot de passe (§9quater).
    pub async fn set_password(&self, user: &str, password: &str) -> Result<()> {
        validate_identifier(user)?;
        let stmt = format!(
            "ALTER USER '{}'@'{APP_HOST}' IDENTIFIED BY '{}'",
            escape_str(user),
            escape_str(password)
        );
        sqlx::query(&stmt)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Sql(redact(&e.to_string(), password)))?;
        Ok(())
    }

    pub async fn database_exists(&self, name: &str) -> Result<bool> {
        let r: Option<MySqlRow> = sqlx::query(
            "SELECT 1 AS x FROM information_schema.schemata WHERE schema_name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Sql(e.to_string()))?;
        Ok(r.is_some())
    }

    pub async fn user_exists(&self, user: &str) -> Result<bool> {
        let r: Option<MySqlRow> =
            sqlx::query("SELECT 1 AS x FROM mysql.user WHERE user = ? AND host = ?")
                .bind(user)
                .bind(APP_HOST)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Error::Sql(e.to_string()))?;
        Ok(r.is_some())
    }

    /// Les bases auxquelles un utilisateur a réellement accès.
    ///
    /// Sert à **prouver** l'isolation en test d'intégration plutôt qu'à la supposer.
    pub async fn granted_databases(&self, user: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT DISTINCT table_schema FROM information_schema.schema_privileges
             WHERE grantee = ? ORDER BY table_schema",
        )
        .bind(format!("'{}'@'{APP_HOST}'", escape_str(user)))
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Sql(e.to_string()))?;

        Ok(rows
            .iter()
            .filter_map(|r| r.try_get::<String, _>("table_schema").ok())
            .collect())
    }

    /// Les valeurs de la première colonne d'une requête, en texte.
    ///
    /// ⚠️ Réservé aux vues d'`information_schema`, dont la forme varie d'une version à
    /// l'autre : une requête typée figerait la version supportée.
    ///
    /// Sert notamment à lire les moteurs de stockage d'une base avant de la dumper —
    /// `--single-transaction` ne protège pas les tables non transactionnelles.
    pub async fn column_values(&self, sql: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(sql)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;

        Ok(rows
            .iter()
            .filter_map(|r| r.try_get::<String, _>(0).ok())
            .collect())
    }
}

/// Un identifiant acceptable ?
///
/// Strict **délibérément**. Les identifiants ne peuvent pas être des paramètres liés
/// en SQL : ils sont interpolés. Plutôt que d'échapper des cas exotiques, on refuse
/// tout ce qui n'est pas manifestement sûr.
///
/// 🔴 `_` et `%` sont exclus parce qu'ils sont des **jokers** dans un `GRANT` : une
/// base `mon_app` donnerait un droit sur `monXapp` et toutes ses variantes.
pub fn validate_identifier(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 64 {
        return Err(Error::InvalidIdentifier(format!(
            "« {s} » : 1 à 64 caractères (limite MariaDB)"
        )));
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(Error::InvalidIdentifier(format!(
            "« {s} » : seuls les caractères alphanumériques ASCII et « - » sont admis. \
             Les « _ » et « % » sont des JOKERS dans un GRANT : « mon_app » donnerait \
             un droit sur « monXapp »"
        )));
    }
    Ok(())
}

/// Échappe un identifiant pour un contexte `` `…` ``.
fn escape_ident(s: &str) -> String {
    s.replace('`', "``")
}

/// Échappe une chaîne pour un contexte `'…'`.
///
/// ⚠️ MariaDB traite `\` comme caractère d'échappement dans les littéraux (contrairement
/// à PostgreSQL par défaut). Un mot de passe finissant par `\` échapperait le guillemet
/// fermant et casserait la requête — ou pire, la transformerait.
fn escape_str(s: &str) -> String {
    s.replace('\\', r"\\").replace('\'', "''")
}

/// Retire un mot de passe d'un message d'erreur.
fn redact(message: &str, password: &str) -> String {
    if password.is_empty() {
        return message.to_string();
    }
    message.replace(password, "«mot de passe»")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_are_refused_in_identifiers() {
        // 🔴 Le piège propre à MariaDB : dans un GRANT, `_` et `%` sont des jokers.
        // Une base « mon_app » donnerait un droit sur « monXapp », « mon-app »…
        assert!(validate_identifier("mon_app").is_err());
        assert!(validate_identifier("mon%app").is_err());

        let e = validate_identifier("mon_app").unwrap_err().to_string();
        assert!(e.contains("JOKER"), "{e}");
        assert!(e.contains("monXapp"), "l'erreur doit montrer la conséquence : {e}");
    }

    #[test]
    fn ordinary_names_are_accepted() {
        assert!(validate_identifier("gitea").is_ok());
        assert!(validate_identifier("vault-warden").is_ok());
        assert!(validate_identifier("app1").is_ok());
    }

    #[test]
    fn injection_attempts_are_refused() {
        assert!(validate_identifier("a; DROP DATABASE x").is_err());
        assert!(validate_identifier("a`b").is_err());
        assert!(validate_identifier("a'b").is_err());
        assert!(validate_identifier("").is_err());
    }

    #[test]
    fn the_identifier_length_matches_mariadb() {
        // 64 caractères : au-delà, MariaDB refuse avec une erreur qui ne dit pas que
        // c'est la longueur.
        assert!(validate_identifier(&"a".repeat(64)).is_ok());
        assert!(validate_identifier(&"a".repeat(65)).is_err());
    }

    #[test]
    fn a_backslash_in_a_password_is_escaped() {
        // ⚠️ MariaDB traite `\` comme échappement dans les littéraux, contrairement à
        // PostgreSQL. Un mot de passe finissant par `\` échapperait le guillemet
        // fermant — et transformerait la requête.
        assert_eq!(escape_str(r"mdp\"), r"mdp\\");
        assert_eq!(escape_str("mdp'suite"), "mdp''suite");
        assert_eq!(escape_str(r"a\'b"), r"a\\''b");
    }

    #[test]
    fn passwords_never_leak_into_error_messages() {
        let m = redact("Access denied for 'x' using password 'tr3sSecret'", "tr3sSecret");
        assert!(!m.contains("tr3sSecret"), "{m}");
        assert!(m.contains("«mot de passe»"));
    }

    #[test]
    fn the_app_host_is_not_localhost() {
        // 🔴 Une app tourne dans un AUTRE conteneur : 'localhost' la ferait refuser
        // avec un message qui parle de mot de passe incorrect alors qu'il est bon.
        assert_eq!(APP_HOST, "%");
        assert_ne!(APP_HOST, "localhost");
    }
}
