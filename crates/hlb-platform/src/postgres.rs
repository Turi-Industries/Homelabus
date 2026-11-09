//! PostgreSQL provisioning.
//!
//! One shared instance, **one database and one role per application**. The isolation
//! rule is the important part: a compromised Gitea must not be able to read
//! Vaultwarden's database.
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
    /// `admin_url` is a superuser connection URL, e.g.
    /// `postgres://postgres:password@postgres:5432/postgres`.
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
        with_database(&self.admin_url, database)
    }

    /// Creates the role and its database if absent, gives the role this password, and
    /// cuts public access.
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
            let stmt = role_statement(role, password)?;
            sqlx::query(sqlx::AssertSqlSafe(stmt.as_str()))
                .execute(&self.pool)
                .await
                .map_err(|e| Error::Sql(redact(&e.to_string(), password)))?;
            created = true;
            tracing::info!(role, "role created");
        } else {
            // A role outlives its app's removal, and the vault may hold a new password
            // by the reinstall: the app would be refused with its data one sign-in away.
            self.set_password(role, password).await?;
        }

        let [create, access @ ..] = database_statements(database, role)?;
        if !self.database_exists(database).await? {
            // CREATE DATABASE is not transactional: it must stand alone.
            sqlx::query(sqlx::AssertSqlSafe(create.as_str()))
                .execute(&self.pool)
                .await
                .map_err(|e| Error::Sql(e.to_string()))?;
            created = true;
            tracing::info!(database, "database created");
        }
        for stmt in access {
            sqlx::query(sqlx::AssertSqlSafe(stmt.as_str()))
                .execute(&self.pool)
                .await
                .map_err(|e| Error::Sql(e.to_string()))?;
        }

        Ok(created)
    }

    /// Runs a query returning a single text column, one row per result.
    ///
    /// ⚠️ Reserved for PostgreSQL's system views (`pg_stat_replication`,
    /// `pg_replication_slots`), whose shape changes between major versions: a typed
    /// query would freeze the supported version, where a line of text lets the caller
    /// adapt.
    pub async fn query_raw(&self, sql: &str) -> Result<String> {
        let rows = sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;
        Ok(rows.join("\n"))
    }

    /// The first column of the first row a query returns in one app's database, as
    /// text — `None` for no row. For the manifests' assertions: read ONLY, inside a
    /// read-only transaction that is rolled back, and bounded in time, because the
    /// query comes from a manifest.
    pub async fn read_one(&self, database: &str, query: &str) -> Result<Option<String>> {
        validate_identifier(database)?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(&self.database_url(database))
            .await
            .map_err(|e| Error::Connect(e.to_string()))?;
        let sql = |e: sqlx::Error| Error::Sql(e.to_string());
        let mut tx = pool.begin().await.map_err(sql)?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(sql)?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *tx)
            .await
            .map_err(sql)?;
        let row = sqlx::query(sqlx::AssertSqlSafe(query))
            .fetch_optional(&mut *tx)
            .await
            .map_err(sql)?;
        tx.rollback().await.map_err(sql)?;
        Ok(row.map(|r| first_as_text(&r)))
    }

    /// One write in one app's database: how many rows it changed. For a manifest's
    /// quota statement — validated as one `UPDATE`, its values checked before they are
    /// written in — and bounded in time like a read.
    pub async fn write_one(&self, database: &str, statement: &str) -> Result<u64> {
        validate_identifier(database)?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(&self.database_url(database))
            .await
            .map_err(|e| Error::Connect(e.to_string()))?;
        let sql = |e: sqlx::Error| Error::Sql(e.to_string());
        let mut tx = pool.begin().await.map_err(sql)?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *tx)
            .await
            .map_err(sql)?;
        let done = sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&mut *tx)
            .await
            .map_err(sql)?;
        tx.commit().await.map_err(sql)?;
        Ok(done.rows_affected())
    }

    /// A guide's write and its probe, their values bound as text parameters (`$1`…):
    /// a secret travels in the protocol, never in the statement, which may be logged.
    /// The probe is read in the same transaction after the write, so a write that took
    /// nothing is rolled back rather than half done. `(rows changed, probe after)`.
    pub async fn write_bound(
        &self,
        database: &str,
        statement: &str,
        probe: &str,
        params: &[String],
    ) -> Result<(u64, bool)> {
        validate_identifier(database)?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(&self.database_url(database))
            .await
            .map_err(|e| Error::Connect(e.to_string()))?;
        let sql = |e: sqlx::Error| Error::Sql(e.to_string());
        let mut tx = pool.begin().await.map_err(sql)?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *tx)
            .await
            .map_err(sql)?;
        let mut write = sqlx::query(sqlx::AssertSqlSafe(statement));
        for p in params {
            write = write.bind(p);
        }
        let done = write.execute(&mut *tx).await.map_err(sql)?;
        let held = probe_in(&mut tx, probe, params).await?;
        if held {
            tx.commit().await.map_err(sql)?;
        } else {
            tx.rollback().await.map_err(sql)?;
        }
        Ok((done.rows_affected(), held))
    }

    /// Does the probe hold now? Read-only, rolled back.
    pub async fn probe_bound(
        &self,
        database: &str,
        probe: &str,
        params: &[String],
    ) -> Result<bool> {
        validate_identifier(database)?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(&self.database_url(database))
            .await
            .map_err(|e| Error::Connect(e.to_string()))?;
        let sql = |e: sqlx::Error| Error::Sql(e.to_string());
        let mut tx = pool.begin().await.map_err(sql)?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(sql)?;
        let held = probe_in(&mut tx, probe, params).await?;
        tx.rollback().await.map_err(sql)?;
        Ok(held)
    }

    /// Enables an extension IN the app's database.
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
        validate_extension(extension)?;

        // A connection to the TARGET database, not the admin one.
        let url = self.database_url(database);
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(&url)
            .await
            .map_err(|e| Error::Connect(e.to_string()))?;

        sqlx::query(sqlx::AssertSqlSafe(extension_statement(extension)?))
            .execute(&pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;

        tracing::info!(database, extension, "extension enabled");
        Ok(())
    }

    /// The most connections the server lets the role hold. Past it the APP is refused
    /// ("too many connections for role"), where an app without one could take every
    /// connection the shared server has.
    pub async fn limit_connections(&self, role: &str, limit: u32) -> Result<()> {
        let stmt = connection_limit_statement(role, limit)?;
        sqlx::query(sqlx::AssertSqlSafe(stmt.as_str()))
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;
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
        sqlx::query(sqlx::AssertSqlSafe(stmt.as_str()))
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

/// A value of any common type, as text: `count(*)` is a `bigint`, a flag a `boolean`.
fn first_as_text(r: &sqlx::postgres::PgRow) -> String {
    if let Ok(v) = r.try_get::<Option<String>, _>(0) {
        return v.unwrap_or_else(|| "NULL".into());
    }
    if let Ok(v) = r.try_get::<Option<i64>, _>(0) {
        return v.map_or_else(|| "NULL".into(), |v| v.to_string());
    }
    if let Ok(v) = r.try_get::<Option<i32>, _>(0) {
        return v.map_or_else(|| "NULL".into(), |v| v.to_string());
    }
    if let Ok(v) = r.try_get::<Option<bool>, _>(0) {
        return v.map_or_else(|| "NULL".into(), |v| v.to_string());
    }
    "(a value of a type this reads as nothing)".into()
}

/// Builds the connection URL injected into the application.
/// An app's database as provisioning makes it — created, owned by the app's role, shut
/// to every other —, as statements: a restore recreating it runs the same ones, so the
/// two cannot drift. The `CREATE` first: it must run alone, outside a transaction.
pub fn database_statements(database: &str, role: &str) -> Result<[String; 3]> {
    validate_identifier(database)?;
    validate_identifier(role)?;
    let (database, role) = (escape_ident(database), escape_ident(role));
    Ok([
        format!(r#"CREATE DATABASE "{database}" OWNER "{role}""#),
        // 🔴 The isolation: without this REVOKE, any role on the instance can connect
        // to this database. It is what stops a compromised app reading another's.
        format!(r#"REVOKE ALL ON DATABASE "{database}" FROM PUBLIC"#),
        format!(r#"GRANT ALL PRIVILEGES ON DATABASE "{database}" TO "{role}""#),
    ])
}

/// The app's role, signing in with `password`. ⚠️ The statement carries the password:
/// it goes to the server over a connection or a standard input, never a command line.
pub fn role_statement(role: &str, password: &str) -> Result<String> {
    validate_identifier(role)?;
    Ok(format!(
        r#"CREATE ROLE "{}" LOGIN PASSWORD {}"#,
        escape_ident(role),
        quote_literal(password)
    ))
}

/// The most connections the server lets `role` hold.
pub fn connection_limit_statement(role: &str, limit: u32) -> Result<String> {
    validate_identifier(role)?;
    Ok(format!(
        r#"ALTER ROLE "{}" CONNECTION LIMIT {limit}"#,
        escape_ident(role)
    ))
}

/// The statement removing an app's database before a restore recreates it, closing the
/// connections still open on it — a restore into the old one merges: a table a later
/// migration added stays beside a schema that no longer knows it.
pub fn drop_database_statement(database: &str) -> Result<String> {
    validate_identifier(database)?;
    Ok(format!(
        r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
        escape_ident(database)
    ))
}

/// The statement enabling `extension`, run in the app's database.
pub fn extension_statement(extension: &str) -> Result<String> {
    validate_extension(extension)?;
    Ok(format!(r#"CREATE EXTENSION IF NOT EXISTS "{extension}""#))
}

pub fn connection_url(host: &str, port: u16, db: &str, role: &str, password: &str) -> String {
    format!("postgres://{role}:{password}@{host}:{port}/{db}")
}

/// SQL identifiers cannot be bound parameters, so they are restricted to an alphabet
/// with no surprises rather than attempting to escape the arbitrary.
///
/// The names come from manifests, therefore potentially from a third-party catalog —
/// this validation is a real trust boundary, not a formality.
fn validate_identifier(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 63 {
        return Err(Error::InvalidIdentifier(format!(
            "\"{name}\": invalid length (1 to 63 characters)"
        )));
    }

    if !name.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
        return Err(Error::InvalidIdentifier(format!(
            "\"{name}\" must start with a lowercase letter"
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

    // `pg_` is reserved by PostgreSQL — for roles, not for extensions.
    if name.starts_with("pg_") {
        return Err(Error::InvalidIdentifier(format!(
            "\"{name}\": the pg_ prefix is reserved"
        )));
    }

    Ok(())
}

/// An extension's name: an identifier, where `pg_` is PostgreSQL's own extensions'
/// (`pg_trgm`, `pg_stat_statements`) rather than a reserved prefix.
fn validate_extension(name: &str) -> Result<()> {
    match name.strip_prefix("pg_") {
        Some(rest) if !rest.is_empty() => validate_identifier(&format!("x{rest}")),
        _ => validate_identifier(name),
    }
}

/// Belt and braces: after validation, escaping is a non-event, but it costs one line.
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

/// A probe's first column, read as a boolean: no row, or `NULL`, is false. Only the
/// first `$n` it reads are bound — a probe may need fewer values than its write.
async fn probe_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    probe: &str,
    params: &[String],
) -> Result<bool> {
    let wanted = (1..=params.len())
        .rev()
        .find(|n| probe.contains(&format!("${n}")))
        .unwrap_or(0);
    let mut q = sqlx::query_scalar::<_, Option<bool>>(sqlx::AssertSqlSafe(probe));
    for p in &params[..wanted] {
        q = q.bind(p);
    }
    let row = q
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| Error::Sql(e.to_string()))?;
    Ok(row.flatten().unwrap_or(false))
}
/// `url` naming `database` as its path, its parameters kept.
///
/// 🔴 Cutting at the last `/` took `postgres://u:p@host:5432` (no path) for a path
/// `host:5432` and named the database there, and dropped `?sslmode=require` — the
/// connection to each app's database went in clear.
fn with_database(url: &str, database: &str) -> String {
    let (base, query) = match url.find(['?', '#']) {
        Some(at) => url.split_at(at),
        None => (url, ""),
    };
    let after_scheme = base.find("://").map_or(0, |at| at + 3);
    let authority_end = base[after_scheme..]
        .find('/')
        .map_or(base.len(), |at| after_scheme + at);
    format!("{}/{database}{query}", &base[..authority_end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_extension_may_be_one_of_postgresql_s_own() {
        // Refused as a reserved prefix, `pg_trgm` passed the catalog and failed the
        // installation.
        assert_eq!(
            extension_statement("pg_trgm").expect("pg_trgm"),
            r#"CREATE EXTENSION IF NOT EXISTS "pg_trgm""#
        );
        assert!(extension_statement("pg_").is_err());
        assert!(extension_statement("pg_Trgm").is_err());
        assert!(
            database_statements("pg_app", "app").is_err(),
            "a database is not"
        );
    }

    #[test]
    fn an_apps_database_keeps_the_admin_urls_host_and_parameters() {
        for (admin, want) in [
            (
                "postgres://postgres:pw@postgres:5432/postgres",
                "postgres://postgres:pw@postgres:5432/gitea",
            ),
            (
                "postgres://postgres:pw@postgres:5432",
                "postgres://postgres:pw@postgres:5432/gitea",
            ),
            (
                "postgres://postgres:pw@db:5432/postgres?sslmode=require&connect_timeout=5",
                "postgres://postgres:pw@db:5432/gitea?sslmode=require&connect_timeout=5",
            ),
            (
                "postgres://postgres:pw@db?sslmode=require",
                "postgres://postgres:pw@db/gitea?sslmode=require",
            ),
        ] {
            assert_eq!(with_database(admin, "gitea"), want, "{admin}");
        }
    }

    #[test]
    fn accepts_normal_names() {
        for n in ["gitea", "vikunja", "vault_warden", "app2"] {
            assert!(validate_identifier(n).is_ok(), "{n} should be accepted");
        }
    }

    #[test]
    fn rejects_injection_attempts() {
        // These names potentially come from a third-party catalog.
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
