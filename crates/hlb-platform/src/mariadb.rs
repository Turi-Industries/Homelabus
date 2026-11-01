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
//! right over `myXapp`, `my-app`, `myapp`... `_` is escaped in the `GRANT` (`my\_app`):
//! refusing it left Seafile, whose databases are `ccnet_db`, `seafile_db` and
//! `seahub_db`, impossible to install — found the first time `hlb` reached a real
//! MariaDB. `%` is refused: no name needs it.

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

    /// The first column of the first row a query returns in one app's database, as
    /// text — `None` for no row. Read ONLY, rolled back and bounded in time: the query
    /// comes from a manifest.
    pub async fn read_one(&self, database: &str, query: &str) -> Result<Option<String>> {
        validate_identifier(database)?;
        let sql = |e: sqlx::Error| Error::Sql(e.to_string());
        // Detached: `USE` would otherwise stay on a connection the pool hands out again.
        let mut conn = self.pool.acquire().await.map_err(sql)?.detach();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "USE `{}`",
            escape_ident(database)
        )))
        .execute(&mut conn)
        .await
        .map_err(sql)?;
        sqlx::query("SET SESSION max_statement_time = 5")
            .execute(&mut conn)
            .await
            .map_err(sql)?;
        sqlx::query("START TRANSACTION READ ONLY")
            .execute(&mut conn)
            .await
            .map_err(sql)?;
        let row = sqlx::query(sqlx::AssertSqlSafe(query))
            .fetch_optional(&mut conn)
            .await
            .map_err(sql)?;
        sqlx::query("ROLLBACK")
            .execute(&mut conn)
            .await
            .map_err(sql)?;
        Ok(row.map(|r| first_as_text(&r)))
    }

    /// One write in one app's database: how many rows it changed. For a manifest's
    /// quota statement, validated as one `UPDATE`, bounded in time like a read.
    pub async fn write_one(&self, database: &str, statement: &str) -> Result<u64> {
        validate_identifier(database)?;
        let sql = |e: sqlx::Error| Error::Sql(e.to_string());
        let mut conn = self.pool.acquire().await.map_err(sql)?.detach();
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "USE `{}`",
            escape_ident(database)
        )))
        .execute(&mut conn)
        .await
        .map_err(sql)?;
        sqlx::query("SET SESSION max_statement_time = 5")
            .execute(&mut conn)
            .await
            .map_err(sql)?;
        let done = sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&mut conn)
            .await
            .map_err(sql)?;
        Ok(done.rows_affected())
    }

    /// Creates the database and its isolated user.
    ///
    /// Returns `true` when something was created.
    pub async fn provision(&self, database: &str, user: &str, password: &str) -> Result<bool> {
        validate_identifier(database)?;
        validate_identifier(user)?;

        let mut created = false;

        if !self.database_exists(database).await? {
            let stmt = create_database_statement(database);
            sqlx::query(sqlx::AssertSqlSafe(stmt.as_str()))
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
            sqlx::query(sqlx::AssertSqlSafe(stmt.as_str()))
                .execute(&self.pool)
                .await
                .map_err(|e| Error::Sql(redact(&e.to_string(), password)))?;
            created = true;
            tracing::info!(user, "user created");
        }

        // 🔴 The scope: `database.*` and NEVER `*.*`. That is the whole isolation.
        let grant = grant_statement(database, user);
        sqlx::query(sqlx::AssertSqlSafe(grant.as_str()))
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

    /// The most connections the server lets the user hold at once: past it the APP
    /// is refused, where one without could take every connection the server has.
    pub async fn limit_connections(&self, user: &str, limit: u32) -> Result<()> {
        validate_identifier(user)?;
        let stmt = format!(
            "ALTER USER '{}'@'{APP_HOST}' WITH MAX_USER_CONNECTIONS {limit}",
            escape_str(user)
        );
        sqlx::query(sqlx::AssertSqlSafe(stmt.as_str()))
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;
        Ok(())
    }

    /// Password rotation.
    pub async fn set_password(&self, user: &str, password: &str) -> Result<()> {
        validate_identifier(user)?;
        let stmt = format!(
            "ALTER USER '{}'@'{APP_HOST}' IDENTIFIED BY '{}'",
            escape_str(user),
            escape_str(password)
        );
        sqlx::query(sqlx::AssertSqlSafe(stmt.as_str()))
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
        let rows = sqlx::query(sqlx::AssertSqlSafe(sql))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::Sql(e.to_string()))?;

        Ok(rows
            .iter()
            .filter_map(|r| r.try_get::<String, _>(0).ok())
            .collect())
    }
}

/// A value of any common type, as text: `count(*)` is a `BIGINT`.
fn first_as_text(r: &MySqlRow) -> String {
    if let Ok(v) = r.try_get::<Option<String>, _>(0) {
        return v.unwrap_or_else(|| "NULL".into());
    }
    if let Ok(v) = r.try_get::<Option<i64>, _>(0) {
        return v.map_or_else(|| "NULL".into(), |v| v.to_string());
    }
    if let Ok(v) = r.try_get::<Option<u64>, _>(0) {
        return v.map_or_else(|| "NULL".into(), |v| v.to_string());
    }
    if let Ok(v) = r.try_get::<Option<i32>, _>(0) {
        return v.map_or_else(|| "NULL".into(), |v| v.to_string());
    }
    "(a value of a type this reads as nothing)".into()
}

/// The statements recreating an app's database after a restore dropped it, as
/// [`MariadbProvisioner::provision`] made it — its user is left as it is.
///
/// ⚠️ MariaDB keeps a database's grants when it is dropped (`mysql.db`): granted again
/// all the same, so the restored database is the app's whatever the server did.
pub fn database_statements(database: &str, user: &str) -> Result<[String; 3]> {
    validate_identifier(database)?;
    validate_identifier(user)?;
    Ok([
        create_database_statement(database),
        grant_statement(database, user),
        // Without it, a right granted may only show after the server restarts.
        "FLUSH PRIVILEGES".to_string(),
    ])
}

/// The statement removing an app's database before a restore recreates it: restored
/// into the old one, a dump merges — `DROP TABLE IF EXISTS` covers the tables it holds,
/// and a table a later migration added stays beside a schema that no longer knows it.
pub fn drop_database_statement(database: &str) -> Result<String> {
    validate_identifier(database)?;
    Ok(format!(
        "DROP DATABASE IF EXISTS `{}`",
        escape_ident(database)
    ))
}

/// `utf8mb4` explicitly: MySQL's `utf8` is only 3 bytes and does NOT store emoji or
/// some ideographs. An insert then fails on "Incorrect string value" long after
/// installation.
fn create_database_statement(database: &str) -> String {
    format!(
        "CREATE DATABASE `{}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
        escape_ident(database)
    )
}

/// The grant of one database to one application.
///
/// 🔴 The scope is `database.*`, never `*.*`, and `_` is escaped: unescaped, the grant
/// on `my_app` reached `myXapp` too.
fn grant_statement(database: &str, user: &str) -> String {
    format!(
        "GRANT ALL PRIVILEGES ON `{}`.* TO '{}'@'{APP_HOST}'",
        escape_ident(database).replace('_', r"\_"),
        escape_str(user)
    )
}

/// An acceptable identifier?
///
/// **Deliberately** strict. Identifiers cannot be bound parameters in SQL: they are
/// interpolated. Rather than escaping exotic cases, we refuse anything not obviously
/// safe.
///
/// 🔴 `%` is excluded: in a `GRANT` it matches anything. `_` matches any one character
/// there too, and is escaped by [`grant_statement`] instead — Seafile's databases carry
/// it, and cannot be renamed.
pub fn validate_identifier(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 64 {
        return Err(Error::InvalidIdentifier(format!(
            "\"{s}\": 1 to 64 characters (MariaDB limit)"
        )));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::InvalidIdentifier(format!(
            "\"{s}\": only ASCII alphanumerics, \"-\" and \"_\" are accepted. \
             \"%\" is a WILDCARD in a GRANT: \"my%app\" would grant a right on every \
             database starting with \"my\""
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

/// Removes a password from an error message.
fn redact(message: &str, password: &str) -> String {
    if password.is_empty() {
        return message.to_string();
    }
    message.replace(password, "<password>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wildcard_never_reaches_a_grant() {
        // 🔴 In a GRANT, `%` matches anything and `_` any one character.
        let e = validate_identifier("my%app").unwrap_err().to_string();
        assert!(e.contains("WILDCARD"), "{e}");
        // `_` is accepted — Seafile's databases carry it — and escaped in the grant.
        assert!(validate_identifier("ccnet_db").is_ok());
        let g = grant_statement("ccnet_db", "seafile");
        assert!(g.contains(r"`ccnet\_db`.*"), "{g}");
        assert!(!g.contains("*.*"), "{g}");
    }

    #[test]
    fn a_database_is_recreated_as_provisioning_made_it() {
        let [create, grant, flush] = database_statements("ccnet_db", "seafile").expect("valid");
        assert!(create.contains("utf8mb4"), "{create}");
        assert_eq!(grant, grant_statement("ccnet_db", "seafile"));
        assert_eq!(flush, "FLUSH PRIVILEGES");
        assert!(database_statements("a%b", "seafile").is_err());
        assert!(drop_database_statement("a`b").is_err());
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
        // the length is the problem.
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
        assert!(m.contains("<password>"));
    }

    #[test]
    fn the_app_host_is_not_localhost() {
        // 🔴 An app runs in ANOTHER container: 'localhost' would get it refused with a
        // message about an incorrect password while the password is fine.
        assert_eq!(APP_HOST, "%");
        assert_ne!(APP_HOST, "localhost");
    }
}
