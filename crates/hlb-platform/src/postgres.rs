//! Provisionnement PostgreSQL (§3.1 du plan).
//!
//! Une instance mutualisée, **une base et un rôle par application**. La règle
//! d'isolation est le point important : un Gitea compromis ne doit pas pouvoir lire la
//! base de Vaultwarden.
//!
//! Toutes les opérations sont idempotentes : relancer une installation ne casse rien
//! et ne régénère pas de mot de passe (§2ter.5).

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

use crate::Error;

type Result<T> = std::result::Result<T, Error>;

/// Se connecte en tant qu'administrateur pour créer bases et rôles.
pub struct PostgresProvisioner {
    pool: PgPool,
    /// Conservée pour ouvrir une connexion vers une base PRÉCISE.
    ///
    /// ⚠️ `CREATE EXTENSION` est local à une base : le pool d'administration pointe
    /// sur `postgres` et poser l'extension par lui la rendrait invisible à l'app.
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

    /// L'URL d'administration, redirigée vers une autre base.
    fn database_url(&self, database: &str) -> String {
        // On remplace le dernier segment de chemin, qui est le nom de base.
        match self.admin_url.rsplit_once('/') {
            Some((prefixe, _)) => format!("{prefixe}/{database}"),
            None => format!("{}/{database}", self.admin_url),
        }
    }

    /// Crée le rôle et sa base s'ils n'existent pas, et coupe l'accès public.
    ///
    /// Renvoie `true` si quelque chose a été créé, `false` si tout était déjà en place.
    pub async fn provision(&self, database: &str, role: &str, password: &str) -> Result<bool> {
        validate_identifier(database)?;
        validate_identifier(role)?;

        let mut created = false;

        // Les identifiants ne peuvent pas être des paramètres liés en SQL — ils sont
        // donc validés strictement ci-dessus, puis échappés en guillemets doubles.
        // Le mot de passe, lui, passe par un littéral échappé.
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
            tracing::info!(role, "rôle créé");
        }

        if !self.database_exists(database).await? {
            // CREATE DATABASE n'est pas transactionnel : il doit être seul.
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
            tracing::info!(database, "base créée");
        }

        // 🔴 L'isolation : sans ce REVOKE, tout rôle de l'instance peut se connecter à
        // cette base. C'est ce qui empêche une app compromise d'en lire une autre.
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

    /// Exécute une requête qui rend une seule colonne texte, une ligne par résultat.
    ///
    /// ⚠️ Réservé aux vues système de PostgreSQL (`pg_stat_replication`,
    /// `pg_replication_slots`), dont la forme change d'une version majeure à l'autre :
    /// une requête typée figerait la version supportée, là où une ligne de texte
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
    /// 🔴 `CREATE EXTENSION` est **local à une base**. Exécutée sur `postgres` — la
    /// base d'administration — elle réussit et l'app ne la voit jamais : la panne
    /// apparaît à la première requête vectorielle, sur un « type vector does not
    /// exist » qui ne dit rien du fait qu'on a visé la mauvaise base.
    ///
    /// ⚠️ L'extension doit être PRÉSENTE dans l'image du serveur. Sinon PostgreSQL
    /// répond « extension "x" is not available », ce qui ressemble à un problème de
    /// droits alors que c'est un problème d'image.
    pub async fn create_extension(&self, database: &str, extension: &str) -> Result<()> {
        validate_identifier(database)?;
        validate_identifier(extension)?;

        // Une connexion à la base CIBLE, pas à celle d'administration.
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

        tracing::info!(database, extension, "extension activée");
        Ok(())
    }

    /// Rotation du mot de passe d'un rôle existant (§9quater).
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

/// Construit l'URL de connexion injectée dans l'application.
pub fn connection_url(host: &str, port: u16, db: &str, role: &str, password: &str) -> String {
    format!("postgres://{role}:{password}@{host}:{port}/{db}")
}

/// Les identifiants SQL ne peuvent pas être des paramètres liés : on les restreint
/// donc à un alphabet sans surprise plutôt que de tenter d'échapper l'arbitraire.
///
/// Les noms viennent des manifests, donc potentiellement d'un catalogue tiers — cette
/// validation est une vraie frontière de confiance, pas une formalité.
fn validate_identifier(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 63 {
        return Err(Error::InvalidIdentifier(format!(
            "« {name} » : longueur invalide (1 à 63 caractères)"
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
            "« {name} » : seuls [a-z0-9_] sont acceptés"
        )));
    }

    // `pg_` est réservé par PostgreSQL.
    if name.starts_with("pg_") {
        return Err(Error::InvalidIdentifier(format!(
            "« {name} » : le préfixe pg_ est réservé"
        )));
    }

    Ok(())
}

/// Ceinture et bretelles : après validation, l'échappement est un non-événement,
/// mais il coûte une ligne.
fn escape_ident(name: &str) -> String {
    name.replace('"', "\"\"")
}

fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Un message d'erreur PostgreSQL peut contenir la requête, donc le mot de passe.
fn redact(msg: &str, secret: &str) -> String {
    if secret.is_empty() {
        return msg.to_string();
    }
    msg.replace(secret, "<rédigé>")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_names() {
        for n in ["gitea", "vikunja", "vault_warden", "app2"] {
            assert!(validate_identifier(n).is_ok(), "{n} devrait être accepté");
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
                "{n:?} aurait dû être refusé"
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
        let msg = "erreur près de CREATE ROLE x PASSWORD 'sup3rs3cret'";
        assert!(!redact(msg, "sup3rs3cret").contains("sup3rs3cret"));
    }

    #[test]
    fn connection_url_is_wellformed() {
        let u = connection_url("postgres", 5432, "gitea", "gitea", "abc123");
        assert_eq!(u, "postgres://gitea:abc123@postgres:5432/gitea");
    }
}
