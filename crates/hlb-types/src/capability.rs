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
                tier, backup, sqlite, ..
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
