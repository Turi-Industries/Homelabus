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
}

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
