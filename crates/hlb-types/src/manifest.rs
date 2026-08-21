//! An application manifest: the catalog's declarative building block.

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
    /// The shared services (postgres, caddy, pocket-id...), described in the same
    /// format but deployed before everything else.
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

    /// Where the app runs. Not everything is swarmable.
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

    /// Companion containers, deployed **with** the app and for it alone.
    ///
    /// Some apps do not fit in one container: Immich needs a separate machine-learning
    /// service, Seafile an in-memory cache. These are not platform services - they are
    /// shared with nobody, and they are born and die with the app.
    ///
    /// 🔴 **A companion never has an `ingress`.** It is an internal helper, not a
    /// service: opening a route to it would publish a component designed to talk only
    /// to its app, often with no authentication whatsoever. The rule is structural -
    /// the type simply has no field for it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub companions: Vec<Companion>,

    /// How the app receives what the resolver provisioned.
    ///
    /// 🔴 **The missing half of the capability resolver.** Declaring `kind: database`
    /// creates the database, the role and the password - and still does not tell the
    /// app how to connect to it. Without this field an app starts and silently falls
    /// back to its internal SQLite: it looks like it works, and its data is neither in
    /// the provisioned database nor backed up with it.
    ///
    /// Values may carry **tokens** resolved at deploy time:
    /// `{{ db.host }}`, `{{ db.name }}`, `{{ db.user }}`, `{{ db.password }}`,
    /// `{{ db.url }}`, `{{ cache.host }}`, `{{ oidc.issuer }}`,
    /// `{{ oidc.client_id }}`, `{{ oidc.client_secret }}`, `{{ smtp.host }}`,
    /// `{{ smtp.user }}`, `{{ smtp.password }}`, `{{ domain }}`.
    ///
    /// 🔴 **A secret token is NEVER resolved here.** The plan is displayed by
    /// `hlb plan`, recorded in the state and exported to the Git mirror: letting a
    /// password in would publish it in all three places. Substitution happens in the
    /// executor, at deploy time, and only Swarm ever sees the value.
    ///
    /// ⚠️ `BTreeMap` and not `HashMap`: plans must be reproducible from one run to the
    /// next, or snapshot tests become worthless.
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
    /// `docker compose` on a dedicated host, driven over SSH.
    Compose,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Image {
    pub repo: String,
    pub tag: String,
    /// Hard pinning. `tag` alone is not enough: a tag is mutable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

impl Image {
    /// The reference handed to Docker.
    ///
    /// When the digest is known the tag is kept **too**: `repo:tag@digest` is the full
    /// canonical form, it is what Swarm produces itself, and it stays readable -
    /// without the tag, nobody knows which version this digest came from. The digest
    /// determines what runs; the tag is only a label.
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
    /// Domain template, resolved at install time.
    pub host: String,
    pub port: u16,
    /// The ingress chain: caddy-front → anubis → caddy-back.
    #[serde(default)]
    pub chain: Vec<String>,
    #[serde(default)]
    pub expose: ExposePolicy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ExposePolicy {
    /// Reachable from the VPN only. A deliberate default.
    #[default]
    Private,
    /// Public exposure only once the guide is complete - closes the "first to sign up
    /// becomes admin" window that scanners exploit.
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
    /// `heavy` or `light` - placement follows from the node's resources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
}

impl Default for SwarmSpec {
    fn default() -> Self {
        Self {
            replicas: 1,
            healthcheck: None,
            tier: None,
        }
    }
}

/// A companion container.
///
/// Deployed as `<app>-<name>`, on the same network as the app, which therefore reaches
/// it by that name. It shares the app's lifecycle: installed with it, stopped with it.
///
/// ## 🔴 What a companion does NOT have, and why
///
/// - **No `ingress`.** An internal helper exposed publicly is a component with no
///   authentication facing the internet. The rule lives in the type, not in a piece of
///   guidance: there is no field to fill in.
/// - **No `requires`.** A companion asking for its own database or its own OIDC client
///   would be an app in disguise, and should be one. Its only needs are a volume and
///   some variables.
/// - **No `replicas`.** Exactly one instance. Spreading a cache or a model across
///   several would need coordination nothing here provides, and the app would see its
///   requests land on one instance or the other at random.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Companion {
    /// Service name suffix, and the name the app reaches it by.
    ///
    /// ⚠️ Lowercase, digits and hyphens: this is a DNS name on the Swarm network.
    pub name: String,

    pub image: Image,

    /// The companion's own volumes, `(name, path)`.
    ///
    /// ⚠️ The name is prefixed with `<app>-<companion>-`. A model cache does not need
    /// backing up: it re-downloads. The flag exists anyway, because some companions
    /// carry state that cannot be rebuilt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub storage: Vec<CompanionVolume>,

    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub env: std::collections::BTreeMap<String, String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<Healthcheck>,

    /// Placement. Absent means the app's own.
    ///
    /// ⚠️ A companion doing real computation (machine learning) deserves `heavy` even
    /// when its app is `light`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,

    #[serde(default)]
    pub security: SecuritySpec,
}

/// Un volume de compagnon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompanionVolume {
    pub name: String,
    pub path: String,
    /// False by default, **the opposite of app volumes**.
    ///
    /// 🔴 The asymmetry is deliberate. An app volume holds irreplaceable data and the
    /// safe default is to back it up. A companion volume almost always holds derived
    /// content - downloaded models, caches - whose backup would bloat the repository
    /// while protecting nothing. The companion that is an exception says so.
    #[serde(default)]
    pub backup: bool,
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
    /// Startup grace period: a database takes time to open, and counting its failures
    /// during that window would make the deployment loop.
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
    /// Upstream repository to watch when the deployed image is a fork.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch_upstream: Option<String>,
    /// Maintenance window, e.g. "sun 03:00-05:00". Absent means any time.
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
    /// Never updated automatically. For Vaultwarden and anything critical.
    Pin,
    #[default]
    Patch,
    Minor,
    /// ⚠️ Discouraged: follows a mutable tag.
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
    /// Capabilities added back explicitly. An app that needs one must say so.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cap_add: Vec<String>,
    /// `uid:gid`. Absent means whatever the image declares.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Ports published on the host. Empty by default - and forbidden on `proxy-header`.
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
            Capability::Database {
                engine: DbEngine::Postgres,
                ..
            }
        ));
        assert!(matches!(
            m.spec.requires[1],
            Capability::Sso {
                mode: SsoMode::Native,
                ..
            }
        ));
    }

    #[test]
    fn a_pinned_reference_keeps_the_tag_for_readability() {
        let m: Manifest = serde_yaml_ng::from_str(VIKUNJA).unwrap();
        assert_eq!(
            m.spec.image.reference(),
            "vikunja/vikunja:0.24.6@sha256:abc"
        );
        assert!(m.spec.image.is_pinned());
    }

    #[test]
    fn secure_and_private_by_default() {
        let m: Manifest = serde_yaml_ng::from_str(VIKUNJA).unwrap();
        assert!(m.spec.security.read_only_rootfs);
        assert_eq!(m.spec.security.cap_drop, vec!["ALL"]);
        assert!(m.spec.security.published_ports.is_empty());
        assert_eq!(m.spec.ingress[0].expose, ExposePolicy::Private);
        // The default channel must never be `latest`.
        assert_eq!(m.spec.update.channel, UpdateChannel::Patch);
        assert!(m.spec.update.backup_before);
    }

    #[test]
    fn typo_in_manifest_is_rejected() {
        let bad = VIKUNJA.replace("displayName", "displaName");
        assert!(serde_yaml_ng::from_str::<Manifest>(&bad).is_err());
    }
}
