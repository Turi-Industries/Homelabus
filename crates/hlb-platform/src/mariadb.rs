//! Isolated MariaDB provisioning.
//!
//! Same promise as PostgreSQL - *a compromised Gitea cannot read Vaultwarden's
//! database* - but the traps are **different**, and transposing the Postgres code
//! as-is would give an isolation that is not one.
//!
//! ## 🔴 Trap 1: a MariaDB user is `'name'@'host'`
//!
//! The name alone identifies nobody. `'gitea'@'localhost'` and `'gitea'@'%'` are two
//! **distinct** accounts, with distinct passwords and distinct grants.
//!
//! Direct consequence: a `CREATE USER 'gitea'` with no host part creates
//! `'gitea'@'%'` on some versions and `'gitea'@'localhost'` on others. In the second
//! case the app runs in another container, is therefore not "localhost", and is
//! refused access with a message about an incorrect password - while the password is
//! correct.
//!
//! So the host is **always** declared explicitly.
//!
//! ## 🔴 Trap 2: `GRANT ALL ON *.*` destroys the isolation
//!
//! It is the example found everywhere. It grants access to **every** database on the
//! instance, which is exactly what this is meant to prevent. The scope must be
//! `database.*`, never `*.*`.
//!
//! ## 🔴 Trap 3: wildcards in the database name
//!
//! In a `GRANT`, `_` and `%` are **wildcards**. A database named `my_app` grants a
//! right over `myXapp`, `my-app`, `myapp`... Either escape those characters or refuse
//! names containing them - which is what happens here, because a database name that
//! looks like a pattern is a bad idea anyway.

use sqlx::mysql::{MySqlPoolOptions, MySqlRow};
use sqlx::{MySqlPool, Row};

use crate::{Error, Result};

/// The host applications connect from.
///
/// `%` means anywhere. On a Docker overlay network a container's address changes on
/// every redeploy, so restricting by IP would break on the first restart. The network
/// is what isolates, not this column.
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

    /// Creates the database and its isolated user.
    ///
    /// Returns `true` when something was created.
    pub async fn provision(&self, database: &str, user: &str, password: &str) -> Result<bool> {
        validate_identifier(database)?;
        validate_identifier(user)?;

        let mut created = false;

        // `utf8mb4` explicitement : le `utf8` de MySQL ne fait que 3 octets et ne
        // does NOT store emoji or some ideographs. An insert then fails on
        // "Incorrect string value" long after installation.
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
            tracing::info!(database, "database created");
        }

        // 🔴 The host is part of the identity. Without it the app cannot connect.
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
            tracing::info!(user, "user created");
        }

        // 🔴 The scope: `database.*` and NEVER `*.*`. That is the whole isolation.
        let grant = format!(
            "GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'{APP_HOST}'",
            escape_ident(database),
            escape_str(user)
        );
        sqlx::query(&grant)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;

        // MariaDB reloads its grant tables at startup: without FLUSH, a granted right
        // may only become visible after a server restart.
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
        let r: Option<MySqlRow> =
            sqlx::query("SELECT 1 AS x FROM information_schema.schemata WHERE schema_name = ?")
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

    /// The databases a user actually has access to.
    ///
    /// Used to **prove** the isolation in integration tests rather than assume it.
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

    /// The first column of a query's rows, as text.
    ///
    /// ⚠️ Reserved for `information_schema` views, whose shape varies between
    /// versions: a typed query would freeze the supported version.
    ///
    /// Notably used to read a database's storage engines before dumping it -
    /// `--single-transaction` does not protect non-transactional tables.
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
/// **Deliberately** strict. Identifiers cannot be bound parameters in SQL: they are
/// interpolated. Rather than escaping exotic cases, we refuse
/// tout ce qui n'est pas manifestement sûr.
///
/// 🔴 `_` et `%` sont exclus parce qu'ils sont des **jokers** dans un `GRANT` : une
/// base `mon_app` donnerait un droit sur `monXapp` et toutes ses variantes.
pub fn validate_identifier(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 64 {
        return Err(Error::InvalidIdentifier(format!(
            "\"{s}\": 1 to 64 characters (MariaDB limit)"
        )));
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(Error::InvalidIdentifier(format!(
            "\"{s}\": only ASCII alphanumerics and \"-\" are accepted. \
             Les « _ » et « % » sont des JOKERS dans un GRANT : « mon_app » donnerait \
             un droit sur « monXapp »"
        )));
    }
    Ok(())
}

/// Escapes an identifier for a `` `...` `` context.
fn escape_ident(s: &str) -> String {
    s.replace('`', "``")
}

/// Escapes a string for a `'...'` context.
///
/// ⚠️ MariaDB treats `\` as an escape character inside literals (unlike PostgreSQL by
/// default). A password ending in `\` would escape the closing quote and break the
/// query - or worse, transform it.
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
        // 🔴 The MariaDB-specific trap: in a GRANT, `_` and `%` are wildcards.
        // Une base « mon_app » donnerait un droit sur « monXapp », « mon-app »…
        assert!(validate_identifier("mon_app").is_err());
        assert!(validate_identifier("mon%app").is_err());

        let e = validate_identifier("mon_app").unwrap_err().to_string();
        assert!(e.contains("JOKER"), "{e}");
        assert!(
            e.contains("monXapp"),
            "the error must show the consequence: {e}"
        );
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
        // 64 characters: beyond that MariaDB refuses with an error that does not say
        // c'est la longueur.
        assert!(validate_identifier(&"a".repeat(64)).is_ok());
        assert!(validate_identifier(&"a".repeat(65)).is_err());
    }

    #[test]
    fn a_backslash_in_a_password_is_escaped() {
        // ⚠️ MariaDB treats `\` as an escape inside literals, unlike PostgreSQL. A
        // password ending in `\` would escape the closing quote - and transform the
        // query.
        assert_eq!(escape_str(r"mdp\"), r"mdp\\");
        assert_eq!(escape_str("mdp'suite"), "mdp''suite");
        assert_eq!(escape_str(r"a\'b"), r"a\\''b");
    }

    #[test]
    fn passwords_never_leak_into_error_messages() {
        let m = redact(
            "Access denied for 'x' using password 'tr3sSecret'",
            "tr3sSecret",
        );
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
