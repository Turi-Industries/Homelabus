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
    /// the type simply has no field for it. A path of the app's own route may lead to
    /// one (`ingress[].paths`): the app's decision, read where its route is.
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

    /// Variables given to every companion that says `sharedEnv: true`, beneath its own:
    /// Fluxer's thirteen services read one environment, written once here rather than
    /// thirteen times — and a copy missed would be the service that breaks.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub shared_env: std::collections::BTreeMap<String, String>,

    #[serde(default)]
    pub security: SecuritySpec,

    /// Configuration files the service reads, put in the container at their path.
    ///
    /// For software that takes no configuration from its environment: Garage refuses to
    /// start without a `garage.toml`. Delivered as Swarm secrets — encrypted at rest —
    /// and given their tokens like `env` at deploy time, so the plan never carries a
    /// value Homelabus generates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<ConfigFile>,

    /// Replaces the image's entrypoint. For an app that takes part of its configuration
    /// from its own command line only, run before it starts: Gitea's sign-in sources
    /// live in its database, and a source changed while it runs is not seen until it
    /// restarts. The script it runs is one of `files`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,

    /// What the running app must keep true — each door the configuration above
    /// closes, read back by its effect every night into the inbox.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertions: Vec<crate::assertion::Assertion>,

    /// Who may sign in, and what the app is told about them — see [`crate::access`].
    /// Absent: any role may be allowed, and the app reads nothing of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<crate::access::Access>,

    /// The sign-ins Homelabus generated that open the app WITHOUT PocketID — its own
    /// administrator. Each is deposited in the emergency vault (`hlb emergency vault`),
    /// where an owner finds it the day the SSO signs nobody in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery: Vec<RecoveryLogin>,

    /// Work the running app needs done on a schedule, inside its own container —
    /// Seafile's garbage collection, without which a deleted file's blocks are never
    /// freed. The controller runs each when it is due; a failed run is in the inbox.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jobs: Vec<Job>,
}

/// A scheduled job, run in the app's running container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Job {
    /// Lowercase letters, digits and hyphens: `hlb job <app> <id>`.
    pub id: String,
    /// What it does, said wherever its runs are listed.
    pub does: String,
    pub every: Period,
    /// Run as `docker exec` in a running task of the app; exit 0 is success.
    pub command: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Period {
    Day,
    Week,
}

impl Period {
    pub fn seconds(&self) -> i64 {
        match self {
            Self::Day => 86_400,
            Self::Week => 7 * 86_400,
        }
    }
}

/// A recovery sign-in: a generated secret, and the name it goes with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryLogin {
    /// The generated secret, as the manifest names it: `admin-password` for
    /// `{{ secret.admin-password }}`. Validation refuses one nothing generates.
    pub secret: String,
    /// The name it signs in with — literal, or `{{ smtp.from }}` for the address
    /// Homelabus gave the app. Absent: the app asks for the password alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Where it signs in, on the app's domain (`/admin`). Absent: the domain itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// How Homelabus signs in with it every night, to know it still opens the app.
    ///
    /// 🔴 A password read at an app's FIRST start only opens nothing on an
    /// installation that began without it: Seafile's lab ran on the image's own
    /// `me@example.com` while the emergency vault held a password for an account that
    /// did not exist — found the day someone tried it, which is the day PocketID is
    /// down.
    ///
    /// Required by the catalog; optional when read, or every manifest frozen before
    /// proofs existed would no longer be read at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<SignIn>,
}

/// One POST to the app itself, by its service name on the overlay, that signs in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignIn {
    /// At the first ingress's port.
    pub path: String,
    /// JSON, its `{{ username }}` and `{{ password }}` filled at run time — inside its
    /// strings only, so a password is escaped as JSON.
    pub body: String,
    /// The username and password sent as HTTP Basic instead, the body holding neither:
    /// Stalwart's administrator signs in no other way.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub basic: bool,
    /// Sent as they are: Jellyfin signs in no client that does not name itself.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub headers: std::collections::BTreeMap<String, String>,
    /// A JSON pointer the answer holds once signed in — a session, a token. A status
    /// alone is not enough: n8n answers its starting page `200` to every route.
    pub pointer: String,
}

/// One configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigFile {
    /// Absolute path inside the container.
    pub path: String,
    pub content: String,
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
    /// Built from this repository's `Dockerfile` by its release: the digest exists only
    /// once a release has built it, so the catalog cannot carry one — what pins it is
    /// the Dockerfile's own bases, each by digest.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub built_here: bool,
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

/// The node label pinning a service to the node that holds its data.
pub fn data_label(service: &str) -> String {
    format!("hlb.data.{service}")
}

/// The placement constraint that keeps a service on the node holding its data.
pub fn data_constraint(service: &str) -> String {
    format!("node.labels.{}==true", data_label(service))
}

/// The platform service every route goes through: one Caddy, its configuration
/// generated from every installed manifest.
pub const INGRESS_SERVICE: &str = "caddy";

/// The node label the ingress is placed by: the router forwards ports 80 and 443 to
/// ONE machine, and Caddy must be the thing listening there.
pub const INGRESS_NODE_LABEL: &str = "hlb.ingress";

/// The links an ingress `chain` may name. `anubis` is a service of its own — the
/// graph orders it before the app, and a catalog without it is refused.
pub const CHAIN_LINKS: &[&str] = &["caddy-front", "anubis", "caddy-back"];

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ingress {
    /// Domain template, resolved at install time.
    pub host: String,
    pub port: u16,
    /// The ingress chain: caddy-front → anubis → caddy-back. Only `anubis` changes the
    /// route; the two Caddy links name the one `caddy` service.
    #[serde(default)]
    pub chain: Vec<String>,
    #[serde(default)]
    pub expose: ExposePolicy,
    /// Paths of this host one of the app's companions answers instead of the app:
    /// Seafile's notification server at `/notification`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<PathRoute>,
    /// Where this host checks a secret — a password, a second factor, a token. Each is
    /// rate limited at the ingress, per client address, before the app sees it; and
    /// what the app answers a wrong secret with is what CrowdSec bans on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_routes: Vec<AuthRoute>,
    /// 🔴 Paths of this host reached by ANYONE: past the portal, the private ranges and
    /// Anubis — n8n's production webhooks, which a service outside calls with no
    /// session. The bouncer and the scanners' cut still stand. Exact paths, or a prefix
    /// ending in `*`; never the whole host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_paths: Vec<String>,
}

/// A place an app checks a secret.
///
/// 🔴 Matched on the DECODED, cleaned path — as the app routes it: Vaultwarden takes
/// `/identity/connect/%74oken` for its token endpoint and Gitea `//user/login` for its
/// sign-in, and a limit on the raw path let both through.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthRoute {
    /// Exact paths, or a prefix ending in `*`.
    pub paths: Vec<String>,
    /// The status the app answers a WRONG secret with, from its own source: Vaultwarden
    /// says 400, most say 401. Absent where a wrong secret looks like a success — Gitea
    /// answers 200 and shows the form again —, where only the rate limit bounds it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fails_with: Option<u16>,
}

/// A path of the app's host handed to one of its companions.
///
/// Written on the APP's route, never on the companion: whoever reads the route sees
/// what it publishes, and a companion still has no way to publish itself. The path
/// takes the route's whole chain — the bouncer, the private ranges, the portal —
/// except Anubis, whose challenge a websocket cannot solve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PathRoute {
    /// `/notification`: it and everything under it, the prefix taken off before the
    /// companion sees the request.
    pub prefix: String,
    /// The companion, by its name in `companions`.
    pub companion: String,
    pub port: u16,
    /// The companion is handed the path whole: Fluxer's api answers
    /// `/.well-known/fluxer` under that name, and its static server `/emoji/…`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keep_prefix: bool,
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
    /// Only on a node carrying this label set to `true`: for a service that must run on
    /// one chosen machine, the ingress on the one the router forwards to. A label no
    /// node carries leaves the service unplaced — the install refuses that first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_label: Option<String>,
    /// What it needs of a node's memory, and the most it may take. Required by `catalog
    /// validate`; optional here so a manifest frozen before it still reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<Memory>,
}

/// A service's memory, as Swarm holds it.
///
/// - **`reserve`** is what a node must have free for Swarm to place it there — and what
///   the capacity budget compares with what is left. Too low, and a node is filled past
///   what its services use at rest.
/// - **`limit`** is where the kernel kills it. 🔴 Too low is a NEW silent failure: the
///   app is killed under load (a thumbnail run, a migration), restarts, and looks
///   healthy between two kills. It is set for the app's peak, not its rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Memory {
    #[schemars(with = "String")]
    pub reserve: Bytes,
    #[schemars(with = "String")]
    pub limit: Bytes,
}

/// A size written `512M` or `2G` — binary units, as Docker reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Bytes(pub u64);

const MIB: u64 = 1024 * 1024;

impl Bytes {
    pub fn mib(&self) -> u64 {
        self.0 / MIB
    }
}

impl TryFrom<String> for Bytes {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        let unit = match s.chars().last() {
            Some('M') => MIB,
            Some('G') => 1024 * MIB,
            _ => {
                return Err(format!(
                    "\"{s}\": a size is a number then M or G (512M, 2G)"
                ))
            }
        };
        let n: u64 = s[..s.len() - 1]
            .parse()
            .map_err(|_| format!("\"{s}\": a size is a whole number then M or G (512M, 2G)"))?;
        if n == 0 {
            return Err(format!("\"{s}\": a size of nothing"));
        }
        // Wrapped, a size past u64 came back small — or 0, past the check above.
        n.checked_mul(unit)
            .map(Self)
            .ok_or_else(|| format!("\"{s}\": larger than any machine"))
    }
}

impl From<Bytes> for String {
    fn from(b: Bytes) -> String {
        if b.0.is_multiple_of(1024 * MIB) {
            format!("{}G", b.0 / (1024 * MIB))
        } else {
            format!("{}M", b.0 / MIB)
        }
    }
}

/// The tiers a node is given (`hlb_orchestrator::cluster::tier_for_memory`). A
/// manifest naming another is placed on no node, and its install times out on "no
/// suitable node" — `catalog validate` refuses it.
pub const TIERS: [&str; 2] = ["light", "heavy"];

/// Does a node of `node_tier` take a service that asks for `wanted`?
///
/// 🔴 A tier keeps heavy services off small machines — PostgreSQL on a 4 GB node works
/// until the OOM. It never meant keeping a light one off a big machine: matched
/// exactly, a cluster of 16 GB nodes (all `heavy`) could place none of the catalog's
/// `light` apps, and said "no suitable node".
pub fn tier_admits(node_tier: &str, wanted: &str) -> bool {
    node_tier == wanted || (wanted == "light" && node_tier == "heavy")
}

/// The placement constraint a tier asks for: none for `light`, which fits anywhere.
pub fn tier_constraint(wanted: &str) -> Option<String> {
    (wanted != "light").then(|| format!("node.labels.tier=={wanted}"))
}

impl Default for SwarmSpec {
    fn default() -> Self {
        Self {
            replicas: 1,
            healthcheck: None,
            tier: None,
            node_label: None,
            memory: None,
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
///   guidance: there is no field to fill in. The app may hand it one path of its own
///   host (`ingress[].paths`), which is the app's decision, written on its route.
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

    /// Takes the app's `sharedEnv` beneath its own `env`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shared_env: bool,

    /// Configuration files, as the app's: Swarm secrets, given their tokens at
    /// deployment. LiveKit and Fluxer's api read theirs from a file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<ConfigFile>,

    /// Replaces the image's entrypoint, as the app's does: NATS starts JetStream from
    /// its command line only. It takes no token — an argument is readable in `ps` by
    /// every account of the node —, so a secret goes in `env` or `files`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<Healthcheck>,

    /// Placement. Absent means the app's own.
    ///
    /// ⚠️ A companion doing real computation (machine learning) deserves `heavy` even
    /// when its app is `light`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,

    /// Only on a node carrying this label set to `true`, as the app's `swarm.nodeLabel`:
    /// a companion publishing ports the router forwards (LiveKit's media) runs where
    /// the router forwards them, `hlb.ingress`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_label: Option<String>,

    /// Its own: a model server and the app it serves do not share a budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<Memory>,

    #[serde(default)]
    pub security: SecuritySpec,
}

impl Companion {
    /// Its Swarm service: the app's name, then its own.
    pub fn service(&self, app: &str) -> String {
        format!("{app}-{}", self.name)
    }

    /// What it is started with: the app's shared variables when it takes them, its own
    /// over them.
    pub fn environment(&self, spec: &Spec) -> std::collections::BTreeMap<String, String> {
        let mut env = if self.shared_env {
            spec.shared_env.clone()
        } else {
            std::collections::BTreeMap::new()
        };
        env.extend(self.env.clone());
        env
    }
}

impl Spec {
    /// Every text a deployment gives its tokens to: the app's variables and files, and
    /// its companions'. One list, read wherever a token is checked or a secret is
    /// planned: it was written out at six sites, and a site that misses a text lets
    /// a token through unchecked, or a secret ungenerated, to reach the service as text.
    pub fn substituted(&self) -> impl Iterator<Item = &String> {
        self.env
            .values()
            .chain(self.shared_env.values())
            .chain(self.files.iter().map(|f| &f.content))
            .chain(
                self.companions
                    .iter()
                    .flat_map(|c| c.env.values().chain(c.files.iter().map(|f| &f.content))),
            )
    }
}

/// A companion's volume.
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
    /// Docker's form: `["CMD", "pg_isready", "-U", "postgres"]`.
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
    /// Days an image must have been published before it is proposed: a broken release
    /// is usually withdrawn or fixed within the week. Never under
    /// [`MIN_MATURATION_DAYS`].
    #[serde(default = "default_maturation")]
    pub maturation_days: u32,
}

/// The floor under `maturationDays`.
pub const MIN_MATURATION_DAYS: u32 = 7;

fn default_maturation() -> u32 {
    MIN_MATURATION_DAYS
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        Self {
            channel: UpdateChannel::default(),
            backup_before: true,
            auto_rollback: true,
            watch_upstream: None,
            window: None,
            maturation_days: MIN_MATURATION_DAYS,
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
    /// Directories given an empty in-memory filesystem at every start: what an image
    /// writes outside its volumes — a socket, a heartbeat, a rendered configuration —
    /// under a read-only root. Nothing written there survives the task.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tmpfs: Vec<String>,
    /// Ports published on the host. Empty by default - and forbidden on `proxy-header`.
    /// `25` is TCP; `"7882/udp"` says its protocol — LiveKit's media arrives over UDP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub published_ports: Vec<PublishedPort>,
}

/// A port published on the node, by its protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "PortWritten", into = "PortWritten")]
#[schemars(with = "PortWritten")]
pub struct PublishedPort {
    pub port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl PublishedPort {
    pub fn tcp(port: u16) -> Self {
        Self {
            port,
            protocol: Protocol::Tcp,
        }
    }
}

impl std::fmt::Display for PublishedPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.protocol {
            Protocol::Tcp => write!(f, "{}", self.port),
            Protocol::Udp => write!(f, "{}/udp", self.port),
        }
    }
}

/// How a port is written: a number for TCP — as every manifest frozen before UDP was —,
/// `"<port>/<protocol>"` otherwise.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum PortWritten {
    Number(u16),
    Text(String),
}

impl TryFrom<PortWritten> for PublishedPort {
    type Error = String;
    fn try_from(w: PortWritten) -> Result<Self, String> {
        let text = match w {
            PortWritten::Number(port) => return Ok(Self::tcp(port)),
            PortWritten::Text(t) => t,
        };
        let (port, protocol) = text.split_once('/').unwrap_or((&text, "tcp"));
        let port = port
            .parse()
            .map_err(|_| format!("\"{text}\": a port is a number from 1 to 65535"))?;
        let protocol = match protocol {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            other => return Err(format!("\"{text}\": protocol \"{other}\" — tcp or udp")),
        };
        Ok(Self { port, protocol })
    }
}

impl From<PublishedPort> for PortWritten {
    fn from(p: PublishedPort) -> Self {
        match p.protocol {
            Protocol::Tcp => Self::Number(p.port),
            Protocol::Udp => Self::Text(p.to_string()),
        }
    }
}

impl Default for SecuritySpec {
    fn default() -> Self {
        Self {
            read_only_rootfs: true,
            no_new_privileges: true,
            cap_drop: cap_drop_all(),
            cap_add: Vec::new(),
            user: None,
            tmpfs: Vec::new(),
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

    #[test]
    fn a_port_says_its_protocol_and_a_number_stays_tcp() {
        let read = |y: &str| serde_yaml_ng::from_str::<SecuritySpec>(y).map(|s| s.published_ports);
        let ports = read("publishedPorts: [25, \"7881/tcp\", \"7882/udp\"]").expect("read");
        assert_eq!(
            ports,
            [
                PublishedPort::tcp(25),
                PublishedPort::tcp(7881),
                PublishedPort {
                    port: 7882,
                    protocol: Protocol::Udp
                }
            ]
        );
        // Written back as every manifest frozen before UDP reads: a number for TCP.
        let back = serde_yaml_ng::to_string(&ports).expect("written");
        assert_eq!(back, "- 25\n- 7881\n- 7882/udp\n");
        for bad in ["\"7882/sctp\"", "\"x/udp\"", "\"70000/udp\"", "70000"] {
            assert!(read(&format!("publishedPorts: [{bad}]")).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_size_past_u64_is_refused_not_wrapped() {
        // 🔴 Found by review: 17179869184G is 2^64 bytes, which wrapped to 0.
        assert!(Bytes::try_from("17179869184G".to_string()).is_err());
        assert!(Bytes::try_from("18446744073709551615M".to_string()).is_err());
        assert_eq!(
            Bytes::try_from("2G".to_string()).map(|b| b.0),
            Ok(2 * 1024 * MIB)
        );
    }

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
