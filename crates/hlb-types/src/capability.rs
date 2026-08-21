//! Les capacités qu'une app **déclare avoir besoin**, sans jamais nommer une instance.
//!
//! C'est le cœur du design (§4.3 du plan) : un manifest dit « j'ai besoin d'une base
//! Postgres », jamais « connecte-toi à postgres:5432 ». Le résolveur fait le pont.
//!
//! Ajouter une variante ici fait échouer la compilation partout où le `match` doit
//! être mis à jour — c'est la raison principale du choix de Rust.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Un besoin déclaré par une application.
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
    /// Une base de données dédiée sur un moteur mutualisé (§3.1).
    Database {
        engine: DbEngine,
        /// Nom de la base. Par défaut, le nom de l'app.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// Extensions à activer dans la base (`vector`, `vchord`, `cube`…).
        ///
        /// 🔴 Une extension ne s'installe pas depuis SQL : elle doit être PRÉSENTE
        /// dans l'image du serveur. `CREATE EXTENSION` échoue sinon sur « extension
        /// n'est pas disponible », ce qui ressemble à un problème de droits.
        ///
        /// Les déclarer ici rend l'exigence visible dans le catalogue et permet à
        /// l'exécuteur d'échouer avec le remède — quelle image poser — au lieu de
        /// laisser l'app démarrer sur une base incomplète.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        extensions: Vec<String>,
    },

    /// Un cache. Partagé par défaut, dédié si l'app ne supporte pas de voisins (§3.3).
    Cache {
        engine: CacheEngine,
        #[serde(default)]
        dedicated: bool,
    },

    /// Authentification unique via le fournisseur d'identité (§5).
    Sso {
        mode: SsoMode,
        /// Chemins de callback, relatifs au domaine choisi à l'installation.
        /// Jamais d'URL en dur : le domaine n'est connu qu'au déploiement.
        #[serde(default)]
        redirect_paths: Vec<String>,
    },

    /// Un compartiment S3 dédié, sur le stockage objet de la plateforme (§3.5).
    ///
    /// ## Pourquoi ce n'est pas un `Storage` de plus
    ///
    /// Un volume est monté dans un chemin ; un compartiment se parle en HTTP avec des
    /// clés d'accès. L'app n'a pas besoin d'être placée près de sa donnée, et le
    /// volume cesse d'être une contrainte de placement — c'est précisément l'intérêt
    /// sur un cluster hétérogène.
    ///
    /// 🔴 **Isolation par compartiment ET par clé**, comme les bases (§3.1). Une clé
    /// unique partagée donnerait à chaque app la lecture des compartiments de toutes
    /// les autres : les photos d'Immich lisibles depuis le wiki, et réciproquement.
    ObjectStorage {
        /// Nom du compartiment. Par défaut, le nom de l'app.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bucket: Option<String>,
        /// 🔴 Le contenu est-il irremplaçable ?
        ///
        /// Vrai par défaut, comme pour les volumes. Un compartiment de cache le
        /// déclare faux — mais l'oubli doit pencher du côté qui sauvegarde.
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
        /// Base SQLite : impose une méthode de sauvegarde spécifique (§3.4).
        #[serde(default)]
        sqlite: bool,
    },
}

impl Capability {
    /// Identifiant stable, utilisé pour les logs et le graphe de dépendances.
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

    /// Ce que cette capacité a réellement provisionné, en une phrase.
    ///
    /// Destiné à l'écran de détail d'une app : `id()` rend un identifiant technique
    /// (`object-storage`), qui ne dit pas ce qui a été créé ni avec quel moteur.
    ///
    /// 🔴 Le `match` est **exhaustif, sans `..` sur les champs qui portent du sens**.
    /// Un `..` a le même effet qu'un bras `_ =>` — c'est ainsi que `mode` a été avalé
    /// sur `Sso`, et `quota_bytes` sur `MailAccount`.
    pub fn describe(&self) -> String {
        match self {
            Self::Database {
                engine,
                name,
                extensions,
            } => {
                let base = format!(
                    "base {} « {} » isolée (rôle dédié)",
                    engine.service_name(),
                    name.as_deref().unwrap_or("<nom de l'app>")
                );
                if extensions.is_empty() {
                    base
                } else {
                    // ⚠️ Les extensions doivent être dans l'IMAGE du serveur : les
                    // nommer ici rend l'exigence visible avant qu'un CREATE EXTENSION
                    // n'échoue sur ce qui ressemble à un problème de droits.
                    format!("{base}, extensions : {}", extensions.join(", "))
                }
            }
            Self::Cache { engine, dedicated } => format!(
                "cache {}{}",
                engine.service_name(),
                if *dedicated { " dédié" } else { " partagé" }
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
                let mut d = "boîte mail".to_string();
                if *aliases {
                    d.push_str(" avec aliases");
                }
                if let Some(q) = quota_bytes {
                    // ⚠️ Dit tel quel : Stalwart n'expose pas les quotas en JMAP, donc
                    // un quota déclaré n'est PAS appliqué. Le taire ferait croire à une
                    // limite qui n'existe pas.
                    d.push_str(&format!(" (quota {q} o DÉCLARÉ, non appliqué)"));
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
                    ", sauvegardé"
                } else {
                    ", NON sauvegardé"
                });
                if *sqlite {
                    d.push_str(", instantané SQLite");
                }
                d
            }
            Self::ObjectStorage { bucket, backup } => format!(
                "compartiment S3 « {} » avec clé isolée{}",
                bucket.as_deref().unwrap_or("<nom de l'app>"),
                if *backup { "" } else { ", NON sauvegardé" }
            ),
        }
    }

    /// Le service de plateforme qui satisfait cette capacité, s'il y en a un.
    ///
    /// Sert à construire le graphe de dépendances (§4.7) : Swarm n'a pas de
    /// `depends_on`, c'est donc à nous d'ordonner les déploiements.
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

/// Les quatre modes d'intégration SSO (§5.0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SsoMode {
    /// L'app parle OIDC nativement. Le meilleur cas.
    Native,
    /// L'app lit un en-tête de confiance. ⚠️ Impose l'isolation réseau (§5.4).
    ProxyHeader,
    /// L'app n'a aucune notion d'identité : portail devant.
    ProxyOnly,
    /// Exclusion volontaire ou protocole incompatible.
    None,
}

impl SsoMode {
    /// `proxy-header` est dangereux si l'app est joignable hors du proxy :
    /// un simple `curl -H "Remote-User: admin"` suffit à usurper un compte.
    /// Le validateur s'appuie là-dessus pour refuser un port publié (§5.4).
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
    /// NFS depuis le NAS. ⚠️ Jamais pour une base de données.
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
        // `id()` rend « object-storage », qui ne dit ni ce qui a été créé ni avec quel
        // moteur. L'écran de détail a besoin de la phrase.
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
        // 🔴 `mode: none` est une EXCLUSION VOLONTAIRE, pas un oubli. La confondre avec
        // les autres modes a déjà produit un client OIDC aux URI vides.
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
        // ⚠️ Stalwart n'expose pas les quotas en JMAP. Taire ce fait ferait croire à
        // une limite qui n'existe pas.
        let c = Capability::MailAccount {
            quota_bytes: Some(5_368_709_120),
            aliases: false,
        };
        assert!(c.describe().contains("non appliqué"), "{}", c.describe());
    }

    #[test]
    fn an_unbacked_volume_says_so_loudly() {
        // Un volume non sauvegardé est un choix ; il doit se voir, pas se deviner.
        let sans = Capability::Storage {
            name: "cache".into(),
            path: "/cache".into(),
            tier: StorageTier::default(),
            backup: false,
            sqlite: false,
        };
        assert!(
            sans.describe().contains("NON sauvegardé"),
            "{}",
            sans.describe()
        );
    }

    #[test]
    fn a_sqlite_volume_is_flagged_because_it_cannot_be_copied_hot() {
        // 🔴 Le fichier principal et son WAL seraient capturés à des instants
        // différents, et la base restaurée serait corrompue — sans que rien ne le
        // signale au moment de la sauvegarde.
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
        // deny_unknown_fields : une faute de frappe dans un manifest doit
        // échouer au parsing, pas être ignorée silencieusement (§1).
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
                assert!(backup, "la sauvegarde doit être activée par défaut");
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
