//! The capabilities an app **declares it needs**, without ever naming an instance.
//!
//! This is the heart of the design: a manifest says "I need a Postgres database",
//! never "connect to postgres:5432". The resolver bridges the two.
//!
//! Adding a variant here breaks compilation everywhere a `match` must be updated -
//! the main reason this is written in Rust.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The authentication portal every `proxy-only` and `proxy-header` app sits behind. Its
/// OIDC client is the one PocketID signs them in through.
pub const PORTAL_SERVICE: &str = "oauth2-proxy";

/// The vault entries an app's S3 key lives in — its id, then its secret: the one key
/// all its buckets share. ⚠️ Stored names.
pub fn s3_key_secrets(app: &str) -> (String, String) {
    (format!("{app}-s3-key-id"), format!("{app}-s3-secret"))
}

/// The bucket Garage gives an `objectStorage` need: its `bucket`, or the app's own name.
/// ⚠️ Stored in Garage: the resolver makes it, the backup, the app's variables and the
/// reconciliation read it — one rule, or a bucket is looked for where none was made.
pub fn bucket_name<'a>(bucket: Option<&'a str>, app: &'a str) -> &'a str {
    bucket.unwrap_or(app)
}

/// A need declared by an application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
// `rename_all` covers variant names, `rename_all_fields` covers fields: without the
// second one you end up with `redirect_paths` in YAML while everything else in the
// manifest is camelCase.
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Capability {
    /// A dedicated database on a shared engine.
    Database {
        engine: DbEngine,
        /// Database name. Defaults to the app's name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// Extensions to enable in the database (`vector`, `vchord`, `cube`...).
        ///
        /// 🔴 An extension cannot be installed from SQL: it must be PRESENT in the
        /// server image. Otherwise `CREATE EXTENSION` fails on "extension is not
        /// available", which looks like a permissions problem.
        ///
        /// Declaring them here makes the requirement visible in the catalog and lets
        /// the executor fail with the remedy - which image to use - instead of letting
        /// the app start against an incomplete database.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        extensions: Vec<String>,
        /// The most connections the app opens to it — every process and companion
        /// together — and what its manifest caps it to.
        ///
        /// 🔴 The server's limit is shared: left to their own defaults, Gitea's pool is
        /// unlimited, Vikunja's 100 and Roundcube's one per Apache worker (150), each
        /// able to take every connection alone. The catalog sums these against the
        /// server's limit. Optional on read: a manifest frozen before it still loads.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        connections: Option<u32>,
    },

    /// A cache. Shared by default, dedicated when the app cannot tolerate neighbours.
    Cache {
        engine: CacheEngine,
        #[serde(default)]
        dedicated: bool,
    },

    /// Single sign-on through the identity provider.
    Sso {
        mode: SsoMode,
        /// Callback paths, relative to the domain chosen at install time.
        /// Never a hard-coded URL: the domain is only known at deploy time.
        #[serde(default)]
        redirect_paths: Vec<String>,
    },

    /// A dedicated S3 bucket on the platform's object storage.
    ///
    /// ## Why this is not just another `Storage`
    ///
    /// A volume is mounted at a path; a bucket is spoken to over HTTP with access
    /// keys. The app does not need to be placed near its data, and the volume stops
    /// being a placement constraint - precisely the point on a heterogeneous cluster.
    ///
    /// 🔴 **Isolation per bucket AND per key**, like databases. One shared key would
    /// give every app read access to every other's buckets: Immich's photos readable
    /// from the wiki, and the other way round.
    ObjectStorage {
        /// Bucket name. Defaults to the app's name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bucket: Option<String>,
        /// 🔴 Is the content irreplaceable?
        ///
        /// True by default, as for volumes. A cache bucket declares it false - but
        /// forgetting must err on the side that backs up.
        #[serde(default = "default_true")]
        backup: bool,
        /// Objects older than this many days are deleted by Garage itself, and an
        /// upload left unfinished as long is abandoned: Fluxer's `uploads` is a staging
        /// bucket whose files move on once a message is sent, and the rest is litter.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expire_after_days: Option<u32>,
    },

    /// Outgoing mail through the platform's mail server, on its submission port.
    Smtp {
        /// Who the mail goes out as. By default the app itself, through an account of
        /// its own the resolver creates.
        #[serde(default)]
        sender: SmtpSender,
    },

    /// A mail account with its aliases.
    MailAccount {
        #[serde(default)]
        quota_bytes: Option<u64>,
        #[serde(default)]
        aliases: bool,
    },

    /// A persistent volume.
    Storage {
        name: String,
        path: String,
        #[serde(default)]
        tier: StorageTier,
        #[serde(default = "default_true")]
        backup: bool,
        /// A SQLite database: forces a specific backup method.
        #[serde(default)]
        sqlite: bool,
        /// How the nightly pass reads it.
        #[serde(default, skip_serializing_if = "VolumeCopy::is_live")]
        copy: VolumeCopy,
        /// Another app's volume of this `name`, mounted here: CrowdSec reading the log
        /// Caddy writes. Never created nor backed up by this app — its owner does both
        /// — and the service runs on the node that holds it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner: Option<String>,
    },
}

impl Capability {
    /// Stable identifier, used for logs and the dependency graph.
    pub fn id(&self) -> &'static str {
        match self {
            Self::Database { .. } => "database",
            Self::Cache { .. } => "cache",
            Self::Sso { .. } => "sso",
            Self::Smtp { sender: _ } => "smtp",
            Self::MailAccount { .. } => "mail-account",
            Self::Storage { .. } => "storage",
            Self::ObjectStorage { .. } => "object-storage",
        }
    }

    /// The platform service that satisfies this capability, if there is one.
    ///
    /// Used to build the dependency graph: Swarm has no `depends_on`, so ordering the
    /// deployments is on us.
    pub fn platform_service(&self) -> Option<&'static str> {
        match self {
            Self::Database { engine, .. } => Some(engine.service_name()),
            Self::Cache { engine, .. } => Some(engine.service_name()),
            // Exhaustive on the mode: an app behind the portal needs oauth2-proxy up
            // (which itself needs PocketID), and one in `none` needs nothing at all.
            Self::Sso {
                mode,
                redirect_paths: _,
            } => match mode {
                SsoMode::Native => Some("pocket-id"),
                SsoMode::ProxyOnly | SsoMode::ProxyHeader => Some(PORTAL_SERVICE),
                SsoMode::None => None,
            },
            Self::Smtp { sender: _ } | Self::MailAccount { .. } => Some("stalwart"),
            // The bucket is served by the platform's object storage: the app must
            // therefore wait for it to be up.
            Self::ObjectStorage { .. } => Some("garage"),
            Self::Storage { .. } => None,
        }
    }
}

/// The most connections an app's role may hold on one engine, as the server is told
/// it: twice what its databases there declare, since an update starts the new task
/// before the old one stops and each opens its own pool. `None` when one of them
/// declares nothing — a manifest frozen before the field, left as it was.
pub fn role_connection_limit(requires: &[Capability], on: DbEngine) -> Option<u32> {
    let mut sum = 0u32;
    let mut any = false;
    for c in requires {
        if let Capability::Database {
            engine,
            name: _,
            extensions: _,
            connections,
        } = c
        {
            if *engine == on {
                sum = sum.saturating_add((*connections)?);
                any = true;
            }
        }
    }
    any.then(|| sum.saturating_mul(2))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DbEngine {
    Postgres,
    Mariadb,
}

impl DbEngine {
    pub fn service_name(&self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Mariadb => "mariadb",
        }
    }

    /// How the server's manifest sets its connection limit, as one of its `args`.
    pub fn limit_arg(&self) -> &'static str {
        match self {
            Self::Postgres => "max_connections=",
            Self::Mariadb => "--max-connections=",
        }
    }

    /// Of the server's limit, what the apps cannot take: Homelabus connects as the
    /// administrator, for whom the server keeps room the apps' roles never reach.
    pub fn kept_for_the_administrator(&self) -> u32 {
        match self {
            // `superuser_reserved_connections`, whose default the manifest keeps.
            Self::Postgres => 3,
            // A SUPER account gets one connection PAST `max_connections` instead.
            Self::Mariadb => 0,
        }
    }
}

/// The server a database lives on. A manifest names an engine, never a server: the
/// house places it.
///
/// The vital apps get a PostgreSQL of their own once the house has a site (the owner's
/// decision, 2026-11-10), so the lifeboat streams their data and nobody else's: the
/// shared server's WAL carries Immich's, n8n's credentials and Fluxer's conversations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DbServer {
    Postgres,
    PostgresVital,
    Mariadb,
}

impl DbServer {
    /// The server every app of `engine` shares.
    pub fn shared(engine: DbEngine) -> Self {
        match engine {
            DbEngine::Postgres => Self::Postgres,
            DbEngine::Mariadb => Self::Mariadb,
        }
    }

    /// Where a new database goes: a vital app's PostgreSQL on the vital server once the
    /// house runs one, every other on its engine's shared server.
    ///
    /// ⚠️ An installed app's database stays where it was provisioned until it is moved:
    /// the executor refuses a plan placing it elsewhere, which would provision an empty
    /// one beside it.
    pub fn placed(engine: DbEngine, criticality: crate::Criticality, vital_server: bool) -> Self {
        match (engine, criticality) {
            (DbEngine::Postgres, crate::Criticality::Vital) if vital_server => Self::PostgresVital,
            (DbEngine::Postgres | DbEngine::Mariadb, _) => Self::shared(engine),
        }
    }

    pub fn engine(&self) -> DbEngine {
        match self {
            Self::Postgres | Self::PostgresVital => DbEngine::Postgres,
            Self::Mariadb => DbEngine::Mariadb,
        }
    }

    /// The platform service, which is also its host on the overlay. ⚠️ A stored value
    /// (`database_servers.server`).
    pub fn service_name(&self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::PostgresVital => VITAL_POSTGRES,
            Self::Mariadb => "mariadb",
        }
    }

    /// Every server. A list: `every_server_is_in_all` breaks on a variant added.
    pub const ALL: [Self; 3] = [Self::Postgres, Self::PostgresVital, Self::Mariadb];

    pub fn from_service_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.service_name() == name)
    }

    /// The name its manifest generates its administrator's password under.
    pub fn admin_password_name(&self) -> &'static str {
        match self.engine() {
            DbEngine::Postgres => "admin-password",
            DbEngine::Mariadb => "root-password",
        }
    }

    /// Its administrator's URL, from that password.
    pub fn admin_url(&self, password: &str) -> String {
        let host = self.service_name();
        match self.engine() {
            DbEngine::Postgres => format!("postgres://postgres:{password}@{host}:5432/postgres"),
            DbEngine::Mariadb => format!("mysql://root:{password}@{host}:3306"),
        }
    }
}

/// The vital apps' own PostgreSQL, which exists only once the house has a site.
pub const VITAL_POSTGRES: &str = "postgres-vital";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CacheEngine {
    Valkey,
}

impl CacheEngine {
    pub fn service_name(&self) -> &'static str {
        match self {
            Self::Valkey => "valkey",
        }
    }
}

/// Who an app's mail goes out as.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SmtpSender {
    /// The app, as `<app>@<mail domain>`: an account of its own, which Stalwart lets
    /// send as that address only.
    #[default]
    App,
    /// The person signed in, with their own mailbox's credentials — a webmail. No
    /// account is made for the app.
    Person,
}

/// The four SSO integration modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SsoMode {
    /// The app speaks OIDC natively. The best case.
    Native,
    /// The app reads a trusted header. ⚠️ Requires network isolation.
    ProxyHeader,
    /// The app has no notion of identity: a portal sits in front.
    ProxyOnly,
    /// Deliberately excluded, or a protocol that cannot take part.
    None,
}

impl SsoMode {
    /// `proxy-header` is dangerous when the app is reachable outside the proxy: a
    /// plain `curl -H "Remote-User: admin"` is enough to impersonate an account. The
    /// validator relies on this to refuse a published port.
    pub fn requires_network_isolation(&self) -> bool {
        matches!(self, Self::ProxyHeader)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum StorageTier {
    /// Local volume + placement constraint. Mandatory for databases.
    #[default]
    Local,
    /// NFS from the NAS. ⚠️ Never for a database.
    Nfs,
}

/// How a backed-up volume is read for its copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum VolumeCopy {
    /// While its service runs: files each written whole. A SQLite database in it is
    /// snapshotted apart, found by its header.
    #[default]
    Live,
    /// Its service stopped for the copy and started again after. 🔴 A store whose
    /// files only make sense together — RocksDB, LMDB —: restic reads them one after
    /// another, and Stalwart's copy named an SST written after restic had passed it,
    /// and did not open.
    Stopped,
    /// A PostgreSQL data directory, copied by `pg_basebackup` while the server runs:
    /// starts as a server that crashed at the copy's end. 🔴 restic reading the
    /// directory itself takes each file at another instant, and no recovery mends that.
    #[serde(rename = "pg-basebackup")]
    PgBasebackup,
    /// A MariaDB data directory, copied by `mariadb-backup` while the server runs and
    /// prepared, for the same reason.
    #[serde(rename = "mariadb-backup")]
    MariadbBackup,
}

impl VolumeCopy {
    pub fn is_live(&self) -> bool {
        *self == Self::Live
    }

    /// The engine whose own tool takes the copy.
    pub fn engine(&self) -> Option<DbEngine> {
        match self {
            Self::Live | Self::Stopped => None,
            Self::PgBasebackup => Some(DbEngine::Postgres),
            Self::MariadbBackup => Some(DbEngine::Mariadb),
        }
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Criticality;

    #[test]
    fn only_a_vital_apps_postgres_goes_to_the_vital_server_and_only_once_it_runs() {
        use DbEngine::{Mariadb, Postgres};
        let vital = Criticality::Vital;
        assert_eq!(
            DbServer::placed(Postgres, vital, true),
            DbServer::PostgresVital
        );
        assert_eq!(DbServer::placed(Postgres, vital, false), DbServer::Postgres);
        assert_eq!(
            DbServer::placed(Postgres, Criticality::Important, true),
            DbServer::Postgres
        );
        // No vital MariaDB exists: the catalog refuses a vital app asking for one.
        assert_eq!(DbServer::placed(Mariadb, vital, true), DbServer::Mariadb);
    }

    /// `ALL` is a list: a variant added to the enum breaks this match, so whoever adds
    /// one is brought here to add its arm, and its assertion.
    #[test]
    fn every_server_is_in_all() {
        fn listed(s: DbServer) -> bool {
            match s {
                DbServer::Postgres => DbServer::ALL.contains(&DbServer::Postgres),
                DbServer::PostgresVital => DbServer::ALL.contains(&DbServer::PostgresVital),
                DbServer::Mariadb => DbServer::ALL.contains(&DbServer::Mariadb),
            }
        }
        assert!(listed(DbServer::Postgres) && listed(DbServer::PostgresVital));
        assert!(listed(DbServer::Mariadb));
    }

    #[test]
    fn a_server_is_found_again_by_its_stored_name() {
        for s in DbServer::ALL {
            assert_eq!(DbServer::from_service_name(s.service_name()), Some(s));
        }
        assert_eq!(DbServer::from_service_name("valkey"), None);
        assert_eq!(
            DbServer::PostgresVital.admin_url("pw"),
            "postgres://postgres:pw@postgres-vital:5432/postgres"
        );
    }

    #[test]
    fn database_yaml_roundtrip() {
        let y = "kind: database\nengine: postgres\nname: vikunja\n";
        let c: Capability = serde_yaml_ng::from_str(y).unwrap();
        assert_eq!(
            c,
            Capability::Database {
                engine: DbEngine::Postgres,
                name: Some("vikunja".into()),
                extensions: Vec::new(),
                connections: None,
            }
        );
        assert_eq!(c.platform_service(), Some("postgres"));
    }

    #[test]
    fn unknown_field_is_rejected() {
        // deny_unknown_fields: a typo in a manifest must fail at parse time, not be
        // silently ignored.
        let y = "kind: database\nengine: postgres\nnamme: vikunja\n";
        assert!(serde_yaml_ng::from_str::<Capability>(y).is_err());
    }

    #[test]
    fn storage_defaults_to_local_with_backup() {
        let y = "kind: storage\nname: data\npath: /data\n";
        let c: Capability = serde_yaml_ng::from_str(y).unwrap();
        match c {
            Capability::Storage {
                tier,
                backup,
                sqlite,
                ..
            } => {
                assert_eq!(tier, StorageTier::Local);
                assert!(backup, "backup must be on by default");
                assert!(!sqlite);
            }
            _ => panic!("mauvaise variante"),
        }
    }

    #[test]
    fn proxy_header_demands_isolation() {
        assert!(SsoMode::ProxyHeader.requires_network_isolation());
        assert!(!SsoMode::Native.requires_network_isolation());
    }
}
