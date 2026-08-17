//! Le manifest d'une application : la brique déclarative du catalogue (§4.2).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::capability::Capability;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub api_version: ApiVersion,
    pub kind: Kind,
    pub metadata: Metadata,
    pub spec: Spec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ApiVersion {
    #[serde(rename = "hlb/v1")]
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Kind {
    App,
    /// Les services mutualisés (postgres, caddy, pocket-id…), décrits par le même
    /// format mais déployés avant tout le reste.
    PlatformService,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Spec {
    pub image: Image,

    /// Là où tourne l'app. Tout n'est pas « swarmable » (§10.1).
    #[serde(default)]
    pub runtime: Runtime,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<Capability>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<Ingress>,

    #[serde(default)]
    pub swarm: SwarmSpec,

    #[serde(default)]
    pub update: UpdatePolicy,

    /// Comment l'app reçoit ce que le résolveur a provisionné (§4.3).
    ///
    /// 🔴 **La moitié manquante du résolveur de capacités.** Déclarer
    /// `kind: database` crée la base, le rôle et le mot de passe — et ne dit
    /// toujours pas à l'app comment s'y connecter. Sans ce champ, une app démarre et
    /// retombe en silence sur son SQLite interne : elle a l'air de marcher, et ses
    /// données ne sont ni dans la base provisionnée, ni sauvegardées avec elle.
    ///
    /// Les valeurs peuvent porter des **jetons** résolus au déploiement :
    /// `{{ db.host }}`, `{{ db.name }}`, `{{ db.user }}`, `{{ db.password }}`,
    /// `{{ db.url }}`, `{{ cache.host }}`, `{{ oidc.issuer }}`,
    /// `{{ oidc.client_id }}`, `{{ oidc.client_secret }}`, `{{ smtp.host }}`,
    /// `{{ smtp.user }}`, `{{ smtp.password }}`, `{{ domain }}`.
    ///
    /// 🔴 **Un jeton de secret n'est JAMAIS résolu ici.** Le plan est affiché par
    /// `hlb plan`, enregistré dans l'état et exporté vers le miroir Git : y faire
    /// entrer un mot de passe le publierait aux trois endroits. La substitution a
    /// lieu dans l'exécuteur, au moment du déploiement, et seule Swarm voit la valeur.
    ///
    /// ⚠️ `BTreeMap` et non `HashMap` : les plans doivent être reproductibles d'une
    /// exécution à l'autre, sinon les tests d'instantané deviennent inutilisables.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub env: std::collections::BTreeMap<String, String>,

    #[serde(default)]
    pub security: SecuritySpec,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Runtime {
    #[default]
    Swarm,
    /// `docker compose` sur un hôte dédié, piloté par SSH (cas mailcow).
    Compose,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Image {
    pub repo: String,
    pub tag: String,
    /// Épinglage fort. `tag` seul ne suffit pas : un tag est mutable (§7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

impl Image {
    /// Référence à passer à Docker.
    ///
    /// Quand le digest est connu, on garde **aussi** le tag : `repo:tag@digest` est la
    /// forme canonique complète, c'est celle que Swarm produit lui-même, et elle reste
    /// lisible — sans le tag, personne ne sait de quelle version vient ce digest.
    /// C'est le digest qui détermine ce qui tourne, le tag n'est plus qu'une étiquette.
    pub fn reference(&self) -> String {
        match &self.digest {
            Some(d) => format!("{}:{}@{}", self.repo, self.tag, d),
            None => format!("{}:{}", self.repo, self.tag),
        }
    }

    pub fn is_pinned(&self) -> bool {
        self.digest.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ingress {
    /// Gabarit du domaine, résolu à l'installation.
    pub host: String,
    pub port: u16,
    /// La chaîne d'entrée : caddy-front → anubis → caddy-back (§6.1).
    #[serde(default)]
    pub chain: Vec<String>,
    #[serde(default)]
    pub expose: ExposePolicy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ExposePolicy {
    /// Joignable uniquement depuis le VPN. Défaut volontaire (§9).
    #[default]
    Private,
    /// Exposition publique seulement une fois le guide validé — empêche la fenêtre
    /// « premier inscrit = admin » exploitée par les scanners (§4.6bis).
    AfterGuide,
    Public,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SwarmSpec {
    #[serde(default = "one")]
    pub replicas: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<Healthcheck>,
    /// `heavy` ou `light` — le placement découle des ressources du nœud (§2bis.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
}

impl Default for SwarmSpec {
    fn default() -> Self {
        Self { replicas: 1, healthcheck: None, tier: None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Healthcheck {
    /// Forme Docker : `["CMD", "pg_isready", "-U", "postgres"]`.
    pub test: Vec<String>,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_retries")]
    pub retries: u64,
    /// Délai de grâce au démarrage : une base de données met du temps à s'ouvrir,
    /// et compter ses échecs pendant ce temps ferait boucler le déploiement.
    #[serde(default = "default_start_period")]
    pub start_period_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdatePolicy {
    #[serde(default)]
    pub channel: UpdateChannel,
    #[serde(default = "default_true")]
    pub backup_before: bool,
    #[serde(default = "default_true")]
    pub auto_rollback: bool,
    /// Dépôt upstream à surveiller quand l'image déployée est un fork.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch_upstream: Option<String>,
    /// Fenêtre de maintenance, ex. « sun 03:00-05:00 ». Absente = à tout moment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<String>,
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        Self {
            channel: UpdateChannel::default(),
            backup_before: true,
            auto_rollback: true,
            watch_upstream: None,
            window: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    /// Jamais de mise à jour automatique. Pour Vaultwarden et tout ce qui est critique.
    Pin,
    #[default]
    Patch,
    Minor,
    /// ⚠️ Déconseillé : suit un tag mutable.
    Latest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecuritySpec {
    #[serde(default = "default_true")]
    pub read_only_rootfs: bool,
    #[serde(default = "default_true")]
    pub no_new_privileges: bool,
    #[serde(default = "cap_drop_all")]
    pub cap_drop: Vec<String>,
    /// Capacités réajoutées explicitement. Une app qui en a besoin doit le dire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cap_add: Vec<String>,
    /// `uid:gid`. Absent = ce que déclare l'image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Ports publiés sur l'hôte. Vide par défaut — et interdit en `proxy-header`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub published_ports: Vec<u16>,
}

impl Default for SecuritySpec {
    fn default() -> Self {
        Self {
            read_only_rootfs: true,
            no_new_privileges: true,
            cap_drop: cap_drop_all(),
            cap_add: Vec::new(),
            user: None,
            published_ports: Vec::new(),
        }
    }
}

fn one() -> u64 {
    1
}
fn default_true() -> bool {
    true
}
fn default_interval() -> u64 {
    30
}
fn default_timeout() -> u64 {
    5
}
fn default_retries() -> u64 {
    3
}
fn default_start_period() -> u64 {
    30
}
fn cap_drop_all() -> Vec<String> {
    vec!["ALL".to_string()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{DbEngine, SsoMode};

    const VIKUNJA: &str = r#"
apiVersion: hlb/v1
kind: App
metadata:
  name: vikunja
  displayName: Vikunja
spec:
  image:
    repo: vikunja/vikunja
    tag: "0.24.6"
    digest: "sha256:abc"
  requires:
    - kind: database
      engine: postgres
    - kind: sso
      mode: native
      redirectPaths: ["/auth/openid/pocketid"]
  ingress:
    - host: "{{ domain }}"
      port: 3456
      chain: [caddy-front, anubis, caddy-back]
"#;

    #[test]
    fn parses_a_real_manifest() {
        let m: Manifest = serde_yaml_ng::from_str(VIKUNJA).unwrap();
        assert_eq!(m.metadata.name, "vikunja");
        assert_eq!(m.spec.runtime, Runtime::Swarm);
        assert_eq!(m.spec.requires.len(), 2);
        assert!(matches!(
            m.spec.requires[0],
            Capability::Database { engine: DbEngine::Postgres, .. }
        ));
        assert!(matches!(
            m.spec.requires[1],
            Capability::Sso { mode: SsoMode::Native, .. }
        ));
    }

    #[test]
    fn a_pinned_reference_keeps_the_tag_for_readability() {
        let m: Manifest = serde_yaml_ng::from_str(VIKUNJA).unwrap();
        assert_eq!(m.spec.image.reference(), "vikunja/vikunja:0.24.6@sha256:abc");
        assert!(m.spec.image.is_pinned());
    }

    #[test]
    fn secure_and_private_by_default() {
        let m: Manifest = serde_yaml_ng::from_str(VIKUNJA).unwrap();
        assert!(m.spec.security.read_only_rootfs);
        assert_eq!(m.spec.security.cap_drop, vec!["ALL"]);
        assert!(m.spec.security.published_ports.is_empty());
        assert_eq!(m.spec.ingress[0].expose, ExposePolicy::Private);
        // Le défaut de canal ne doit jamais être `latest`.
        assert_eq!(m.spec.update.channel, UpdateChannel::Patch);
        assert!(m.spec.update.backup_before);
    }

    #[test]
    fn typo_in_manifest_is_rejected() {
        let bad = VIKUNJA.replace("displayName", "displaName");
        assert!(serde_yaml_ng::from_str::<Manifest>(&bad).is_err());
    }
}
