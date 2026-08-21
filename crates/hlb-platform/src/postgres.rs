//! Provisionnement PostgreSQL (§3.1 du plan).
//!
//! One shared instance, **one database and one role per application**. The rule
//! d'isolation est le point important : un Gitea compromis ne doit pas pouvoir lire la
//! base de Vaultwarden.
//!
//! Every operation is idempotent: rerunning an install breaks nothing and does not
//! regenerate a password.

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

use crate::Error;

type Result<T> = std::result::Result<T, Error>;

/// Connects as an administrator to create databases and roles.
pub struct PostgresProvisioner {
    pool: PgPool,
    /// Kept so a connection can be opened to a SPECIFIC database.
    ///
    /// ⚠️ `CREATE EXTENSION` is per-database: the admin pool points at `postgres`, and
    /// installing the extension through it would leave it invisible to the app.
    admin_url: String,
}

impl PostgresProvisioner {
    /// `admin_url` est une URL de connexion superutilisateur, ex.
    /// `postgres://postgres:motdepasse@postgres:5432/postgres`.
    pub async fn connect(admin_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(admin_url)
            .await
            .map_err(|e| Error::Connect(e.to_string()))?;

        Ok(Self {
            pool,
            admin_url: admin_url.to_string(),
        })
    }

    /// The admin URL, redirected at another database.
    fn database_url(&self, database: &str) -> String {
        // On remplace le dernier segment de chemin, qui est le nom de base.
        match self.admin_url.rsplit_once('/') {
            Some((prefixe, _)) => format!("{prefixe}/{database}"),
            None => format!("{}/{database}", self.admin_url),
        }
    }

    /// Creates the role and its database if absent, and cuts public access.
    ///
    /// Returns `true` when something was created, `false` when all was already there.
    pub async fn provision(&self, database: &str, role: &str, password: &str) -> Result<bool> {
        validate_identifier(database)?;
        validate_identifier(role)?;

        let mut created = false;

        // Identifiers cannot be bound parameters in SQL, so they are validated
        // strictly above and then escaped with double quotes.
        // The password goes through an escaped literal.
        if !self.role_exists(role).await? {
            let stmt = format!(
                r#"CREATE ROLE "{}" LOGIN PASSWORD {}"#,
                escape_ident(role),
                quote_literal(password)
            );
            sqlx::query(&stmt)
                .execute(&self.pool)
                .await
                .map_err(|e| Error::Sql(redact(&e.to_string(), password)))?;
            created = true;
            tracing::info!(role, "role created");
        }

        if !self.database_exists(database).await? {
            // CREATE DATABASE is not transactional: it must stand alone.
            let stmt = format!(
                r#"CREATE DATABASE "{}" OWNER "{}""#,
                escape_ident(database),
                escape_ident(role)
            );
            sqlx::query(&stmt)
                .execute(&self.pool)
                .await
                .map_err(|e| Error::Sql(e.to_string()))?;
            created = true;
            tracing::info!(database, "database created");
        }

        // 🔴 The isolation: without this REVOKE, any role on the instance can connect
        // to this database. It is what stops a compromised app reading another's.
        let revoke = format!(
            r#"REVOKE ALL ON DATABASE "{}" FROM PUBLIC"#,
            escape_ident(database)
        );
        sqlx::query(&revoke)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;

        let grant = format!(
            r#"GRANT ALL PRIVILEGES ON DATABASE "{}" TO "{}""#,
            escape_ident(database),
            escape_ident(role)
        );
        sqlx::query(&grant)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;

        Ok(created)
    }

    /// Runs a query returning a single text column, one row per result.
    ///
    /// ⚠️ Reserved for PostgreSQL's system views (`pg_stat_replication`,
    /// `pg_replication_slots`), whose shape changes between major versions: a typed
    /// query would freeze the supported version, where a line of text
    /// laisse l'appelant s'adapter.
    pub async fn query_raw(&self, sql: &str) -> Result<String> {
        let rows = sqlx::query_scalar::<_, String>(sql)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;
        Ok(rows.join("\n"))
    }

    /// Active une extension DANS la base de l'app.
    ///
    /// 🔴 `CREATE EXTENSION` is **per-database**. Run against `postgres` - the admin
    /// database - it succeeds and the app never sees it: the failure shows up on the
    /// first vector query, as a "type vector does not exist" that says nothing about
    /// having targeted the wrong database.
    ///
    /// ⚠️ The extension must be PRESENT in the server image. Otherwise PostgreSQL
    /// answers `extension "x" is not available`, which looks like a permissions
    /// problem when it is an image problem.
    pub async fn create_extension(&self, database: &str, extension: &str) -> Result<()> {
        validate_identifier(database)?;
        validate_identifier(extension)?;

        // A connection to the TARGET database, not the admin one.
        let url = self.database_url(database);
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(&url)
            .await
            .map_err(|e| Error::Connect(e.to_string()))?;

        sqlx::query(&format!("CREATE EXTENSION IF NOT EXISTS \"{extension}\""))
            .execute(&pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;

        tracing::info!(database, extension, "extension enabled");
        Ok(())
    }

    /// Rotates an existing role's password.
    pub async fn set_password(&self, role: &str, password: &str) -> Result<()> {
        validate_identifier(role)?;
        let stmt = format!(
            r#"ALTER ROLE "{}" WITH PASSWORD {}"#,
            escape_ident(role),
            quote_literal(password)
        );
        sqlx::query(&stmt)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Sql(redact(&e.to_string(), password)))?;
        Ok(())
    }

    pub async fn role_exists(&self, role: &str) -> Result<bool> {
        let row = sqlx::query("SELECT 1 FROM pg_roles WHERE rolname = $1")
            .bind(role)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;
        Ok(row.is_some())
    }

    pub async fn database_exists(&self, database: &str) -> Result<bool> {
        let row = sqlx::query("SELECT 1 FROM pg_database WHERE datname = $1")
            .bind(database)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;
        Ok(row.is_some())
    }

    pub async fn version(&self) -> Result<String> {
        let row = sqlx::query("SELECT version()")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;
        row.try_get(0).map_err(|e| Error::Sql(e.to_string()))
    }
}

/// Builds the connection URL injected into the application.
pub fn connection_url(host: &str, port: u16, db: &str, role: &str, password: &str) -> String {
    format!("postgres://{role}:{password}@{host}:{port}/{db}")
}

/// SQL identifiers cannot be bound parameters, so they are restricted to an alphabet
/// with no surprises rather than attempting to escape the arbitrary.
///
/// Les noms viennent des manifests, donc potentiellement d'un catalogue tiers — cette
/// validation is a real trust boundary, not a formality.
fn validate_identifier(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 63 {
        return Err(Error::InvalidIdentifier(format!(
            "\"{name}\": invalid length (1 to 63 characters)"
        )));
    }

    if !name.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
        return Err(Error::InvalidIdentifier(format!(
            "« {name} » doit commencer par une lettre minuscule"
        )));
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(Error::InvalidIdentifier(format!(
            "\"{name}\": only [a-z0-9_] are accepted"
        )));
    }

    // `pg_` is reserved by PostgreSQL.
    if name.starts_with("pg_") {
        return Err(Error::InvalidIdentifier(format!(
            "\"{name}\": the pg_ prefix is reserved"
        )));
    }

    Ok(())
}

/// Belt and braces: after validation, escaping is a non-event,
/// mais il coûte une ligne.
fn escape_ident(name: &str) -> String {
    name.replace('"', "\"\"")
}

fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// A PostgreSQL error message can contain the query, and therefore the password.
fn redact(msg: &str, secret: &str) -> String {
    if secret.is_empty() {
        return msg.to_string();
    }
    msg.replace(secret, "<redacted>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_names() {
        for n in ["gitea", "vikunja", "vault_warden", "app2"] {
            assert!(validate_identifier(n).is_ok(), "{n} should be accepted");
        }
    }

    #[test]
    fn rejects_injection_attempts() {
        // Ces noms viennent potentiellement d'un catalogue tiers.
        for n in [
            r#"gitea"; DROP DATABASE postgres; --"#,
            "gitea drop",
            "gitea'--",
            "GITEA",
            "2gitea",
            "gitea-app",
            "",
        ] {
            assert!(
                validate_identifier(n).is_err(),
                "{n:?} should have been refused"
            );
        }
    }

    #[test]
    fn rejects_reserved_prefix() {
        assert!(validate_identifier("pg_catalog").is_err());
    }

    #[test]
    fn rejects_overlong_names() {
        assert!(validate_identifier(&"a".repeat(64)).is_err());
        assert!(validate_identifier(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn literals_escape_quotes() {
        assert_eq!(quote_literal("abc"), "'abc'");
        assert_eq!(quote_literal("a'b"), "'a''b'");
    }

    #[test]
    fn errors_never_carry_the_password() {
        let msg = "error near CREATE ROLE x PASSWORD 'sup3rs3cret'";
        assert!(!redact(msg, "sup3rs3cret").contains("sup3rs3cret"));
    }

    #[test]
    fn connection_url_is_wellformed() {
        let u = connection_url("postgres", 5432, "gitea", "gitea", "abc123");
        assert_eq!(u, "postgres://gitea:abc123@postgres:5432/gitea");
    }
}
