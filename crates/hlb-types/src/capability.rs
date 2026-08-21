//! The capabilities an app **declares it needs**, without ever naming an instance.
//!
//! This is the heart of the design: a manifest says "I need a Postgres database",
//! never "connect to postgres:5432". The resolver bridges the two.
//!
//! Adding a variant here breaks compilation everywhere a `match` must be updated -
//! the main reason this is written in Rust.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A need declared by an application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
// `rename_all` porte sur les noms de variantes, `rename_all_fields` sur les champs :
// sans le second, on se retrouve avec `redirect_paths` en YAML alors que tout le reste
// du manifest est en camelCase.
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
    },

    /// Envoi de mail sortant via le relais de la plateforme.
    Smtp,

    /// Un compte mail avec ses aliases (§5bis.3).
    MailAccount {
        #[serde(default)]
        quota_bytes: Option<u64>,
        #[serde(default)]
        aliases: bool,
    },

    /// Stockage persistant.
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
    },
}

impl Capability {
    /// Stable identifier, used for logs and the dependency graph.
    pub fn id(&self) -> &'static str {
        match self {
            Self::Database { .. } => "database",
            Self::Cache { .. } => "cache",
            Self::Sso { .. } => "sso",
            Self::Smtp => "smtp",
            Self::MailAccount { .. } => "mail-account",
            Self::Storage { .. } => "storage",
            Self::ObjectStorage { .. } => "object-storage",
        }
    }

    /// What this capability actually provisioned, in one sentence.
    ///
    /// Meant for an app's detail screen: `id()` returns a technical identifier
    /// (`object-storage`) which says neither what was created nor with which engine.
    ///
    /// 🔴 The `match` is **exhaustive, with no `..` over fields that carry meaning**.
    /// A `..` has the same effect as a `_ =>` arm - that is how `mode` was swallowed
    /// on `Sso`, and `quota_bytes` on `MailAccount`.
    pub fn describe(&self) -> String {
        match self {
            Self::Database {
                engine,
                name,
                extensions,
            } => {
                let base = format!(
                    "isolated {} database \"{}\" (dedicated role)",
                    engine.service_name(),
                    name.as_deref().unwrap_or("<nom de l'app>")
                );
                if extensions.is_empty() {
                    base
                } else {
                    // ⚠️ Extensions must be in the server IMAGE: naming them here
                    // makes the requirement visible before a CREATE EXTENSION fails on
                    // what looks like a permissions problem.
                    format!("{base}, extensions : {}", extensions.join(", "))
                }
            }
            Self::Cache { engine, dedicated } => format!(
                "cache {}{}",
                engine.service_name(),
                if *dedicated { " dedicated" } else { " shared" }
            ),
            Self::Sso {
                mode,
                redirect_paths,
            } => match mode {
                SsoMode::None => "SSO explicitement exclu — aucun client OIDC".to_string(),
                SsoMode::Native => {
                    format!("client OIDC natif ({} URI de rappel)", redirect_paths.len())
                }
                autre => format!("SSO par portail ({autre:?})"),
            },
            Self::Smtp => "relais SMTP".to_string(),
            Self::MailAccount {
                quota_bytes,
                aliases,
            } => {
                let mut d = "mailbox".to_string();
                if *aliases {
                    d.push_str(" avec aliases");
                }
                if let Some(q) = quota_bytes {
                    // ⚠️ Said plainly: Stalwart does not expose quotas over JMAP, so a
                    // declared quota is NOT enforced. Staying silent would suggest a
                    // limit that does not exist.
                    d.push_str(&format!(" (quota {q} B DECLARED, not enforced)"));
                }
                d
            }
            Self::Storage {
                name,
                path,
                tier,
                backup,
                sqlite,
            } => {
                let mut d = format!("volume « {name} » sur {path} (tier {tier:?})");
                d.push_str(if *backup {
                    ", backed up"
                } else {
                    ", NOT backed up"
                });
                if *sqlite {
                    d.push_str(", SQLite snapshot");
                }
                d
            }
            Self::ObjectStorage { bucket, backup } => format!(
                "S3 bucket \"{}\" with an isolated key{}",
                bucket.as_deref().unwrap_or("<nom de l'app>"),
                if *backup { "" } else { ", NOT backed up" }
            ),
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
            Self::Sso { .. } => Some("pocket-id"),
            Self::Smtp | Self::MailAccount { .. } => Some("stalwart"),
            // Le compartiment est servi par le stockage objet de la plateforme :
            // l'app doit donc attendre qu'il soit debout (§4.7).
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

/// The four SSO integration modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SsoMode {
    /// L'app parle OIDC nativement. Le meilleur cas.
    Native,
    /// The app reads a trusted header. ⚠️ Requires network isolation.
    ProxyHeader,
    /// The app has no notion of identity: a portal sits in front.
    ProxyOnly,
    /// Exclusion volontaire ou protocole incompatible.
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
    /// Volume local + contrainte de placement. Obligatoire pour les bases (§10.2).
    #[default]
    Local,
    /// NFS from the NAS. ⚠️ Never for a database.
    Nfs,
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_capability_describes_what_it_actually_provisioned() {
        // `id()` returns "object-storage", which says neither what was created nor
        // with which engine. The detail screen needs the sentence.
        let toutes = [
            Capability::Database {
                engine: DbEngine::Postgres,
                name: Some("gitea".into()),
                extensions: vec!["vector".into()],
            },
            Capability::Cache {
                engine: CacheEngine::Valkey,
                dedicated: true,
            },
            Capability::Sso {
                mode: SsoMode::Native,
                redirect_paths: vec!["/callback".into()],
            },
            Capability::Smtp,
            Capability::MailAccount {
                quota_bytes: Some(5_000_000),
                aliases: true,
            },
            Capability::Storage {
                name: "data".into(),
                path: "/data".into(),
                tier: StorageTier::default(),
                backup: true,
                sqlite: false,
            },
            Capability::ObjectStorage {
                bucket: Some("photos".into()),
                backup: true,
            },
        ];

        for c in &toutes {
            let d = c.describe();
            assert!(!d.is_empty(), "{:?} sans description", c.id());
            assert!(!d.contains(".."), "{d}");
        }
    }

    #[test]
    fn a_deliberate_sso_exclusion_says_so() {
        // 🔴 `mode: none` is a DELIBERATE EXCLUSION, not an oversight. Confusing it
        // with the other modes already produced an OIDC client with empty URIs.
        let exclu = Capability::Sso {
            mode: SsoMode::None,
            redirect_paths: Vec::new(),
        };
        assert!(exclu.describe().contains("exclu"), "{}", exclu.describe());

        let natif = Capability::Sso {
            mode: SsoMode::Native,
            redirect_paths: vec!["/cb".into()],
        };
        assert_ne!(natif.describe(), exclu.describe());
    }

    #[test]
    fn a_declared_mail_quota_says_it_is_not_enforced() {
        // ⚠️ Stalwart does not expose quotas over JMAP. Staying silent about that
        // would suggest a limit that does not exist.
        let c = Capability::MailAccount {
            quota_bytes: Some(5_368_709_120),
            aliases: false,
        };
        assert!(c.describe().contains("not enforced"), "{}", c.describe());
    }

    #[test]
    fn an_unbacked_volume_says_so_loudly() {
        // An unbacked-up volume is a choice; it must be visible, not guessed at.
        let without = Capability::Storage {
            name: "cache".into(),
            path: "/cache".into(),
            tier: StorageTier::default(),
            backup: false,
            sqlite: false,
        };
        assert!(
            without.describe().contains("NOT backed up"),
            "{}",
            without.describe()
        );
    }

    #[test]
    fn a_sqlite_volume_is_flagged_because_it_cannot_be_copied_hot() {
        // 🔴 The main file and its WAL would be captured at different instants, and
        // the restored database would be corrupt - with nothing signalling it at
        // backup time.
        let c = Capability::Storage {
            name: "db".into(),
            path: "/db".into(),
            tier: StorageTier::default(),
            backup: true,
            sqlite: true,
        };
        assert!(c.describe().contains("SQLite"), "{}", c.describe());
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
