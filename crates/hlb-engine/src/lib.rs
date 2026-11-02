//! The executor: applies a plan, action by action.
//!
//! Three properties, present from the start rather than retrofitted:
//!
//! - **Preview by default.** Nothing is modified without an explicit `--apply`.
//! - **Idempotency.** Rerunning against an already-installed app breaks nothing.
//! - **Resumability.** A failure at action 4/10 resumes at 4, not at zero.
//!
//! And a rule of honesty: an unimplemented action is recorded as such
//! (`Unimplemented`), **never** as successful.

pub mod access;
pub mod devices;
pub mod domain;
pub mod download;
pub mod emergency;
pub mod family;
pub mod ingress;
pub mod install;
pub mod jobs;
pub mod mail_dns;
pub mod mail_queue;
pub mod mail_relay;
pub mod mail_tls;
pub mod mailbox;
pub mod pki;
pub mod prune;
pub mod reconcile;
pub mod roles;
pub mod sources;
pub mod stalwart_migrate;
pub mod submission;
pub mod termix;
pub mod trust;
pub mod upgrade;

pub use reconcile::{AppBucket, Drift, Reconciler, Report};

use hlb_identity::PocketId;
use hlb_mail::Stalwart;
use hlb_objstore::Garage;
use hlb_orchestrator::{Orchestrator, ServiceSpec};
use hlb_platform::{MariadbProvisioner, PostgresProvisioner};
use hlb_registry::{ImageRef, RegistryClient};
use hlb_resolver::{Action, Plan};
use hlb_secrets::Vault;
use hlb_state::{ActionStatus, State};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    State(#[from] hlb_state::Error),

    #[error(transparent)]
    Orchestrator(#[from] hlb_orchestrator::Error),

    #[error(transparent)]
    Secrets(#[from] hlb_secrets::Error),

    #[error(transparent)]
    Platform(#[from] hlb_platform::Error),

    /// A volume declares a tier this installation cannot provide.
    ///
    /// 🔴 An error, never a fallback: a `tier: nfs` volume quietly turned into a local
    /// one takes the data and loses it on the next redeployment.
    #[error("{0}")]
    Storage(String),

    /// A download its job could not fetch, or whose hash was not the one declared.
    #[error("download: {0}")]
    Download(String),

    #[error(transparent)]
    Registry(#[from] hlb_registry::Error),

    /// A domain named that is not one (`hlb_types::domain`).
    #[error("{0}")]
    Domain(String),

    /// An image about to be deployed by its tag alone.
    #[error(
        "{image}: deployment refused without a resolved digest — a tag names whatever \
         was pushed last; `hlb update apply {app}` pins what runs"
    )]
    Unpinned { app: String, image: String },

    #[error(transparent)]
    Identity(#[from] hlb_identity::Error),

    #[error(transparent)]
    Bitwarden(#[from] hlb_bitwarden::Error),

    #[error(transparent)]
    Termix(#[from] hlb_termix::Error),

    #[error(transparent)]
    Ingress(#[from] hlb_ingress::Error),

    /// The exposure cannot be published as configured: a credential missing, a
    /// provider not built in, Caddy refusing the file.
    #[error("{0}")]
    Exposure(String),

    #[error(transparent)]
    Mail(#[from] hlb_mail::Error),

    #[error(transparent)]
    ObjStore(#[from] hlb_objstore::Error),

    /// An app's mail cannot go out: its account was refused on the submission port, or
    /// what Stalwart needs for it could not be set up.
    #[error("🔴 outgoing mail: {0}")]
    Submission(String),

    #[error(
        "🔴 extension \"{extension}\" could not be enabled on \"{database}\". An \
             extension is NOT installed from SQL: it must be present in the PostgreSQL \
             server image. Check the `postgres` service image in the \
             catalog — for the vector extensions, \
             ghcr.io/immich-app/postgres:17-vectorchord0.4.3-pgvector0.8.0 carries \
             them. Cause: {cause}"
    )]
    MissingExtension {
        extension: String,
        database: String,
        cause: String,
    },

    #[error("secret \"{0}\" not found - was the plan executed in order?")]
    MissingSecret(String),

    /// The cluster's authority or a leaf under it could not be read or issued.
    #[error("PKI: {0}")]
    Pki(String),

    #[error("{blocking} prerequisite(s) not met — handle them then run again (hlb todo)")]
    BlockedByGuide { blocking: usize },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Where an app's Garage key id is kept: `{{ s3.access_key }}`.
fn s3_key_id(app: &str) -> String {
    hlb_types::capability::s3_key_secrets(app).0
}

/// The platform's S3 endpoint.
///
/// ⚠️ A Swarm service name, not a public URL: object traffic stays on the internal
/// network. Exposing it would send bytes out of the cluster that have no reason to
/// leave, and Garage has no authentication beyond the S3 signature.
pub const S3_ENDPOINT: &str = hlb_objstore::S3_URL;

/// Garage ignores the region, but the S3 SIGNATURE covers it: a client announcing a
/// different one has its requests refused on a signature error that says nothing about
/// the region.
const S3_REGION: &str = "garage";

/// What was done, for the report.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub executed: usize,
    pub skipped: usize,
    pub unimplemented: usize,
    pub failed: Option<(usize, String)>,
}

impl Outcome {
    pub fn is_success(&self) -> bool {
        self.failed.is_none()
    }
}

/// Where the volumes actually live on this installation.
///
/// ## 🔴 Why an absent NFS configuration is a REFUSAL, not a fallback
///
/// A manifest declaring `tier: nfs` is saying "this does not fit on the system disk".
/// Falling back to a plain Docker volume gives an app that starts, accepts uploads and
/// looks healthy — and loses them on the next redeployment, because the bytes went into
/// a volume nobody meant to create. That is the exact failure the Immich guide warns
/// about, and it is silent.
///
/// So: declared and unconfigured stops the install. You cannot fix what nothing tells
/// you about.
#[derive(Debug, Clone, Default)]
pub struct StorageConfig {
    /// Root under which `tier: local` volumes are bound, e.g. `/tank/apps`.
    ///
    /// `None` = Docker's own directory, which is the right answer on a node with no
    /// pool: small state, on the system disk, backed up by restic like the rest.
    pub local_root: Option<String>,
    /// The NFS server, as the nodes reach it.
    pub nfs_server: Option<String>,
    /// The exported root, under which each volume gets a directory.
    pub nfs_export: Option<String>,
}

/// The Swarm services an app runs: its own, then its companions'.
pub fn services_of(app: &str, manifest: &hlb_types::Manifest) -> Vec<String> {
    std::iter::once(app.to_string())
        .chain(
            manifest
                .spec
                .companions
                .iter()
                .map(|c| format!("{app}-{}", c.name)),
        )
        .collect()
}

/// Removes an app's services, its companions' included. Returns those that were
/// running; one already absent counts as removed.
///
/// 🔴 Both removals — the CLI's and the controller's — took the app's own service
/// alone: Immich's machine-learning companion stayed running, managed by nobody. And
/// an install that failed before its app's service existed could not be removed at
/// all, stopped on "service not found" (found on a real cluster).
pub async fn remove_services<O: Orchestrator + ?Sized>(
    orchestrator: &O,
    app: &str,
    manifest: &hlb_types::Manifest,
) -> hlb_orchestrator::Result<Vec<String>> {
    let mut removed = Vec::new();
    for service in services_of(app, manifest) {
        match orchestrator.remove(&service).await {
            Ok(()) => removed.push(service),
            Err(hlb_orchestrator::Error::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(removed)
}

/// Keeps what PocketID answered for an OIDC client in the vault: its secret under
/// `secret_name`, its id under `id_name`.
///
/// 🔴 A secret PocketID just made is THE secret, and replaces what the vault held: a
/// client re-created, or the placeholder the plan's own `GenerateSecret` stored while
/// PocketID was unreachable. Kept "if absent", the app was handed a secret PocketID
/// never issued, and every sign-in ended in `invalid_client`. The id follows the
/// client the same way: a re-created one has a new id.
///
/// With no secret in the answer the client already existed, and its secret must be in
/// the vault already — PocketID never hands one back: `Error::MissingSecret` says to
/// delete the client.
pub async fn keep_oidc_credentials(
    state: &State,
    vault: &Vault,
    client: &str,
    creds: &hlb_identity::Credentials,
    secret_name: &str,
    id_name: &str,
) -> Result<()> {
    let put = |name: &str, value: &str, purpose: &'static str| {
        let name = name.to_string();
        let ct = vault.encrypt(value);
        async move {
            let ct = ct?;
            if !state.store_secret_if_absent(&name, &ct, purpose).await? {
                state.rotate_secret(&name, &ct).await?;
            }
            Ok::<_, Error>(())
        }
    };
    match &creds.client_secret {
        Some(secret) => put(secret_name, secret, "OIDC client secret").await?,
        None if state.secret(secret_name).await?.is_none() => {
            return Err(Error::MissingSecret(format!(
                "{secret_name} — the OIDC client \"{client}\" exists in PocketID but its \
                 secret is absent from the vault; delete the client to reprovision it"
            )))
        }
        None => {}
    }
    put(id_name, &creds.client_id, "OIDC client id").await
}

/// What a plan's prerequisites say before anything runs.
#[derive(Debug, Default)]
pub struct Prerequisites<'p> {
    /// Blocking pre-install steps their `verify:` proves done now, not yet recorded as
    /// handled: the caller applying records them, a preview only says so.
    pub verified: Vec<&'p str>,
    /// Neither handled nor proven: the install stops on these.
    pub open: Vec<&'p Action>,
}

/// The blocking pre-install steps of `plan` for `app`: those the state holds as
/// handled are met, the others are checked by their `verify:` — under a wildcard
/// record, "create the DNS record" is true before anyone attests it. Writes nothing.
///
/// One reading for the executor and the interface's install: the interface counted
/// the plan's steps without checking them, and refused for good every app whose guide
/// starts with a DNS record — ten in the catalog.
pub async fn prerequisites<'p>(
    state: &State,
    vault: Option<&Vault>,
    app: &str,
    plan: &'p Plan,
    domain: Option<&str>,
) -> Result<Prerequisites<'p>> {
    let handled = state.verified_guides(app).await?;
    let vars = [("domain", domain.unwrap_or_default())];
    let verifier = guide_verifier(state, vault).await;
    let mut out = Prerequisites::default();
    for a in plan.pre_install_blockers() {
        let Action::PendingGuideStep { id, step, .. } = a else {
            continue;
        };
        if handled.contains(id) {
            continue;
        }
        if verifier.check(step, &vars).await.is_verified() {
            out.verified.push(id);
        } else {
            out.open.push(a);
        }
    }
    Ok(out)
}

/// What the nightly re-check found for a handled step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recheck {
    /// Still true; its age starts again.
    Holds,
    /// No longer true, twice in a row: pending again.
    Reopened(String),
    /// Still false, as when someone attested it with `--force`: left as they said.
    Forced(String),
    /// Could not be told: left as it was.
    Unknown(String),
}

/// Checks again every handled step whose guide asks for a `recheck` and was handled at
/// least that long ago — a deleted DNS record, a router that lost its rule. The steps
/// are the guide frozen with each app; `guides` gives the catalog's, for an app
/// recorded before guides were frozen.
///
/// A failure is tried a second time before the step is opened again: one lookup timing
/// out in the night must not put a working app's prerequisite back in the inbox. A step
/// attested with `--force` is not reopened by the check it overrode, and is established
/// the first night that check agrees.
pub async fn recheck_guides(
    state: &State,
    vault: Option<&Vault>,
    guides: impl Fn(&str) -> Vec<hlb_types::GuideStep>,
) -> Result<Vec<(String, String, Recheck)>> {
    let verifier = guide_verifier(state, vault).await;
    let mut out = Vec::new();
    for (app, _) in state.installed_apps().await? {
        let steps = install::installed_guide(state, &app, || {
            Some(hlb_types::Guide {
                steps: guides(&app),
            })
        })
        .await?
        .steps;
        let ages = state.verified_guide_ages(&app).await?;
        let domain = state.app_domain(&app).await?.unwrap_or_default();
        let vars = [("domain", domain.as_str())];
        for step in &steps {
            let Ok(Some(every)) = step.recheck_secs() else {
                continue;
            };
            let Some((_, age, forced)) = ages.iter().find(|(id, ..)| *id == step.id) else {
                continue;
            };
            if *age < every {
                continue;
            }
            let mut outcome = verifier.check(step, &vars).await;
            if !forced && matches!(outcome, hlb_guide::Outcome::Failed { detail: _ }) {
                outcome = verifier.check(step, &vars).await;
            }
            let found = match outcome {
                hlb_guide::Outcome::Verified { detail: _ } => {
                    state.reconfirm_guide(&app, &step.id).await?;
                    Recheck::Holds
                }
                // 🔴 Reopened, it came back every night the check still failed, over
                // a person who had already said why the machine cannot see it.
                hlb_guide::Outcome::Failed { detail } if *forced => Recheck::Forced(detail),
                hlb_guide::Outcome::Failed { detail } => {
                    state.reopen_guide(&app, &step.id).await?;
                    Recheck::Reopened(detail)
                }
                o @ (hlb_guide::Outcome::NotVerifiable
                | hlb_guide::Outcome::Unsupported { reason: _ }) => Recheck::Unknown(o.describe()),
            };
            out.push((app.clone(), step.id.clone(), found));
        }
    }
    Ok(out)
}

/// The guide verifier every caller uses: certificates verified against the public roots
/// and the installation's own ([`ingress::trusted_root`]), never accepted unseen.
pub async fn guide_verifier(state: &State, vault: Option<&Vault>) -> hlb_guide::Verifier {
    let root = ingress::trusted_root(state, vault).await;
    hlb_guide::Verifier::trusting(std::time::Duration::from_secs(10), root.as_deref())
}

/// A volume's name as the manifest declares it: `data` for the volume `gitea-data`,
/// `machine-learning-cache` for a companion's.
///
/// 🔴 The path on the pool is built from THIS name, as `hlb storage init` creates it.
/// Given the volume's own name, every NFS mount and every bind on the pool pointed at
/// `<app>/<app>-<volume>`, a directory nobody had created (found on a real export).
pub fn declared_volume<'v>(app: &str, volume: &'v str) -> &'v str {
    volume
        .strip_prefix(app)
        .and_then(|rest| rest.strip_prefix('-'))
        .unwrap_or(volume)
}

impl StorageConfig {
    /// What should hold this volume.
    ///
    /// `Err` names what is missing rather than substituting something that works.
    pub fn backing_for(
        &self,
        tier: hlb_types::StorageTier,
        app: &str,
        volume: &str,
    ) -> std::result::Result<hlb_orchestrator::VolumeBacking, String> {
        use hlb_orchestrator::VolumeBacking;
        match tier {
            // 🔴 The ingress keeps its certificates where it runs. On the pool they
            // would pin it to the storage node, while its label pins it to the machine
            // the router forwards to: two machines, and Caddy placed on neither.
            hlb_types::StorageTier::Local if app == hlb_types::manifest::INGRESS_SERVICE => {
                Ok(VolumeBacking::Docker)
            }
            hlb_types::StorageTier::Local => match &self.local_root {
                // ⚠️ One directory per app, then per volume: two apps with a volume
                // called "data" must not land on the same bytes.
                Some(root) => Ok(VolumeBacking::Bind {
                    path: format!("{root}/{app}/{volume}"),
                }),
                None => Ok(VolumeBacking::Docker),
            },
            hlb_types::StorageTier::Nfs => match (&self.nfs_server, &self.nfs_export) {
                (Some(server), Some(export)) => Ok(VolumeBacking::Nfs {
                    server: server.clone(),
                    export: format!("{export}/{app}/{volume}"),
                }),
                _ => Err(format!(
                    "volume \"{volume}\" is declared tier: nfs, and no NFS server is \
                     configured. Falling back to a local volume would take the data and \
                     lose it on the next redeployment - supply --nfs-server and \
                     --nfs-export"
                )),
            },
        }
    }
}

impl StorageConfig {
    /// What this installation cannot provide for `manifest`, before anything is written.
    ///
    /// 🔴 Checked at PREVIEW time, not at execution. Discovering it while the executor
    /// runs means the manifest is already frozen and the app already recorded — you
    /// then have a half-installed app whose first action failed. A blocker stops the
    /// install where blockers belong: before any modification.
    pub fn blockers_for(&self, manifest: &hlb_types::Manifest) -> Vec<String> {
        manifest
            .spec
            .requires
            .iter()
            .filter_map(|c| match c {
                hlb_types::Capability::Storage {
                    name, tier, owner, ..
                } => self
                    .backing_for(
                        *tier,
                        owner.as_deref().unwrap_or(&manifest.metadata.name),
                        name,
                    )
                    .err(),
                _ => None,
            })
            .collect()
    }
}

pub struct Executor<'a, O: Orchestrator + ?Sized> {
    orchestrator: &'a O,
    state: &'a State,
    /// Absent until the master key is loaded: without a vault, no secret can be
    /// generated or read back.
    vault: Option<&'a Vault>,
    /// Absent until PostgreSQL is deployed and reachable.
    postgres: Option<&'a PostgresProvisioner>,
    /// Same for MariaDB. Both can coexist: different apps have different
    /// requirements, and the resolver chooses per manifest.
    mariadb: Option<&'a MariadbProvisioner>,
    /// Absent when offline: without a registry, no digest can be resolved.
    registry: Option<&'a RegistryClient>,
    /// Absent until PocketID is deployed and an API key is available.
    identity: Option<&'a PocketId>,
    mail: Option<&'a Stalwart>,
    /// The apps' own APIs, for the guides' `api` automations — a first-run wizard
    /// that would otherwise make its first visitor the administrator.
    api: Option<&'a dyn hlb_guide::ApiClient>,
    /// Absent until Garage is deployed and its admin token is available: no bucket
    /// can be provisioned before that.
    objstore: Option<&'a Garage>,
    /// Where the volumes live. Default: Docker decides, which is right for a node with
    /// no storage pool.
    storage: StorageConfig,
    /// The overlay every service joins. Defaults to [`hlb_orchestrator::PLATFORM_NETWORK`]
    /// rather than to nothing: a caller that forgot to set it would deploy services that
    /// cannot see each other.
    network: String,
    /// False by default: nothing is written until it is asked for.
    apply: bool,
}

impl<'a, O: Orchestrator + ?Sized> Executor<'a, O> {
    pub fn new(orchestrator: &'a O, state: &'a State) -> Self {
        Self {
            orchestrator,
            state,
            vault: None,
            postgres: None,
            mariadb: None,
            registry: None,
            identity: None,
            mail: None,
            api: None,
            objstore: None,
            storage: StorageConfig::default(),
            network: hlb_orchestrator::PLATFORM_NETWORK.to_string(),
            apply: false,
        }
    }

    /// The overlay the services join, when it is not the default one.
    pub fn with_network(mut self, name: impl Into<String>) -> Self {
        self.network = name.into();
        self
    }

    /// Where the volumes should live.
    pub fn with_storage(mut self, s: StorageConfig) -> Self {
        self.storage = s;
        self
    }

    pub fn with_vault(mut self, vault: &'a Vault) -> Self {
        self.vault = Some(vault);
        self
    }

    pub fn with_postgres(mut self, pg: &'a PostgresProvisioner) -> Self {
        self.postgres = Some(pg);
        self
    }

    pub fn with_mariadb(mut self, my: &'a MariadbProvisioner) -> Self {
        self.mariadb = Some(my);
        self
    }

    pub fn with_registry(mut self, r: &'a RegistryClient) -> Self {
        self.registry = Some(r);
        self
    }

    pub fn with_identity(mut self, p: &'a PocketId) -> Self {
        self.identity = Some(p);
        self
    }

    pub fn with_mail(mut self, s: &'a Stalwart) -> Self {
        self.mail = Some(s);
        self
    }

    pub fn with_api(mut self, a: &'a dyn hlb_guide::ApiClient) -> Self {
        self.api = Some(a);
        self
    }

    pub fn with_objstore(mut self, g: &'a Garage) -> Self {
        self.objstore = Some(g);
        self
    }

    /// Switches to real application mode. The caller must ask for it explicitly.
    pub fn apply(mut self, yes: bool) -> Self {
        self.apply = yes;
        self
    }

    /// Executes the plan for `app`.
    ///
    /// Blocking manual actions stop execution **before** any modification: no point
    /// deploying an app whose DNS does not exist.
    pub async fn run(&self, app: &str, plan: &Plan) -> Result<Outcome> {
        let records: Vec<(String, String)> = plan
            .actions
            .iter()
            .map(|a| (kind_of(a).to_string(), a.to_string()))
            .collect();

        // 🔴 A preview writes NOTHING: no journal, no guide. Recorded here, a preview of
        // `hlb install` left rows a later run read as its own — and the guides it
        // records are the apply's to record, once the app is.
        if self.apply {
            self.state.record_plan(app, &records).await?;
            for a in &plan.actions {
                if let Action::PendingGuideStep {
                    id,
                    title,
                    blocking,
                    ..
                } = a
                {
                    self.state.add_guide(app, id, title, *blocking).await?;
                }
            }

            // The plan says which steps are prerequisites, the state which are handled:
            // a step the user dealt with must stop blocking. One with a check — a DNS
            // record, a port — is checked here first: under a wildcard record the
            // "create the DNS record" step is already true, and refusing on it would
            // send someone to attest what the machine can see.
            let domain = self.state.app_domain(app).await?;
            let found = prerequisites(self.state, self.vault, app, plan, domain.as_deref()).await?;
            for id in &found.verified {
                self.state.verify_guide(app, id).await?;
            }
            if !found.open.is_empty() {
                return Err(Error::BlockedByGuide {
                    blocking: found.open.len(),
                });
            }
        }

        // 🔴 A run resuming after a failure is installing again, not failed: the routes
        // leave failed apps out, so this app's own route step republished every route
        // but its own — removing the one it had — and the run ended "running" with the
        // app unreachable (found on the lab, 2026-10-18).
        if self.apply
            && self
                .state
                .installed_apps()
                .await?
                .iter()
                .any(|(name, status)| name == app && status == "failed")
        {
            self.state.set_app_status(app, "installing").await?;
        }

        let completed = self.state.completed_actions(app, &records).await?;
        let done: std::collections::HashSet<i64> = completed
            .iter()
            .enumerate()
            .filter(|(_, d)| **d)
            .map(|(seq, _)| seq as i64)
            .collect();
        let mut out = Outcome::default();

        // A service deployed once and gone since (`docker service rm`, a lost cluster)
        // is deployed again: "done" was true of a service that no longer exists, and
        // skipping it left the app installed with nothing running. The reconciliation
        // sends a missing service here rather than rebuilding it with half its spec.
        let mut vanished = std::collections::HashSet::new();
        for (seq, action) in plan.actions.iter().enumerate() {
            if let Action::DeployService { name, .. } = action {
                if done.contains(&(seq as i64))
                    && matches!(
                        self.orchestrator.status(name).await,
                        Err(hlb_orchestrator::Error::NotFound(_))
                    )
                {
                    vanished.insert(name.clone());
                }
            }
        }
        // A digest resolved once and absent from the frozen manifest since — frozen
        // again from a catalog that carries none, for an image built here — is resolved
        // again: skipped as done, the deployment after it refused as unpinned forever.
        let frozen = self.state.app_manifest(app).await.ok();
        let lost_digest = |repo: &str, tag: &str| {
            frozen.as_ref().is_some_and(|m| {
                std::iter::once(&m.spec.image)
                    .chain(m.spec.companions.iter().map(|c| &c.image))
                    .any(|i| i.repo == repo && i.tag == tag && !i.is_pinned())
            })
        };
        let redeploys = |action: &Action| match action {
            Action::DeployService { name, .. } | Action::WaitHealthy { name, .. } => {
                vanished.contains(name)
            }
            Action::ResolveDigest { repo, tag } => lost_digest(repo, tag),
            _ => false,
        };

        for (seq, action) in plan.actions.iter().enumerate() {
            if done.contains(&(seq as i64)) && !redeploys(action) {
                out.skipped += 1;
                tracing::debug!(seq, "already done, skipped");
                continue;
            }

            if !self.apply {
                out.executed += 1;
                continue;
            }

            match self.execute_one(app, action).await {
                Ok(Step::Done) => {
                    self.state
                        .set_action_status(app, seq, ActionStatus::Done, None)
                        .await?;
                    out.executed += 1;
                }
                Ok(Step::NotImplemented) => {
                    self.state
                        .set_action_status(app, seq, ActionStatus::Unimplemented, None)
                        .await?;
                    out.unimplemented += 1;
                }
                Err(e) => {
                    let msg = e.to_string();
                    self.state
                        .set_action_status(app, seq, ActionStatus::Failed, Some(&msg))
                        .await?;
                    self.state.set_app_status(app, "failed").await?;
                    out.failed = Some((seq, msg));
                    // Stop dead: continuing after a dependency failure would only
                    // produce cascading errors.
                    return Ok(out);
                }
            }
        }

        if self.apply {
            let status = if out.unimplemented > 0 {
                "partial"
            } else {
                "running"
            };
            self.state.set_app_status(app, status).await?;
        }

        Ok(out)
    }

    /// A service reading another app's volume goes where that app keeps it: if its own
    /// data was pinned to another node — before the ingress moved, or by an earlier
    /// install — that pin is released, and it starts over beside the owner.
    ///
    /// 🔴 Kept, the two constraints named two machines, and the service was placed on
    /// neither: CrowdSec reinstalled after Caddy moved sat "pending" with no reason
    /// given. What it kept on the old node stays there, untouched.
    async fn follow_owners(
        &self,
        service: &str,
        manifest: Option<&hlb_types::Manifest>,
    ) -> Result<()> {
        let owners: Vec<&str> = manifest
            .iter()
            .flat_map(|m| &m.spec.requires)
            .filter_map(|c| match c {
                hlb_types::Capability::Storage { owner: Some(o), .. } => Some(o.as_str()),
                _ => None,
            })
            .collect();
        if owners.is_empty() {
            return Ok(());
        }
        let nodes = self.orchestrator.nodes().await?;
        for owner in owners {
            let Some(home) = nodes.iter().find(|n| n.data.iter().any(|d| d == owner)) else {
                continue;
            };
            for n in nodes
                .iter()
                .filter(|n| n.id != home.id && n.data.iter().any(|d| d == service))
            {
                tracing::warn!(
                    service,
                    from = %n.hostname,
                    to = %home.hostname,
                    "follows {owner}'s volume: starts over beside it, its data on the old \
                     node is left as it was"
                );
                self.orchestrator
                    .label_node(&n.id, &hlb_types::manifest::data_label(service), "false")
                    .await?;
            }
        }
        Ok(())
    }

    /// Resolves the binding tokens of a set of variables.
    ///
    /// 🔴 **This is where, and nowhere earlier, secrets take their value.** The plan
    /// passes through `hlb plan`'s output, the SQLite state and the Git mirror: a
    /// password substituted upstream would be published in all three, one of which
    /// keeps history. Only Swarm sees the final value.
    ///
    /// ⚠️ A token we cannot fill is left **literal** rather than emptied. An empty
    /// variable looks like missing configuration: the app would complain about an
    /// incorrect password, where `{{ db.password }}` in its logs points at the real
    /// problem straight away.
    /// One text with its tokens filled, as a variable at deployment is.
    async fn resolve_one(&self, app: &str, text: &str) -> Result<String> {
        Ok(self
            .resolve_bindings(app, &[("text".to_string(), text.to_string())])
            .await?
            .into_iter()
            .next()
            .map(|(_, v)| v)
            .unwrap_or_default())
    }

    async fn resolve_bindings(
        &self,
        app: &str,
        env: &[(String, String)],
    ) -> Result<Vec<(String, String)>> {
        use hlb_types::binding::{substitute, tokens_in, Token};

        // Nothing to do when no token is used: this avoids fetching secrets for apps
        // that do not need any. ⚠️ Judged on `{{`, never on `Token` and the secrets
        // alone: companion and S3 tokens are neither.
        let used_ones: Vec<Token> = {
            let mut v: Vec<Token> = env.iter().flat_map(|(_, x)| tokens_in(x)).collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        let generated: Vec<hlb_types::binding::GeneratedSecret> = env
            .iter()
            .flat_map(|(_, x)| hlb_types::binding::generated_secrets(x))
            .filter_map(|r| r.ok())
            .collect();
        if !env.iter().any(|(_, x)| x.contains("{{")) {
            return Ok(env.to_vec());
        }
        let mut generated_values: Vec<(String, String)> = Vec::new();
        for g in &generated {
            if let Some(stored) = self.read_secret(&g.vault_name(app)).await? {
                generated_values.push((g.placeholder(), g.render(&stored)));
            }
        }

        let manifest = self.state.app_manifest(app).await.ok();
        let domain = self.state.app_domain(app).await.unwrap_or_default();

        let mut values: std::collections::BTreeMap<Token, String> = Default::default();
        // 🔴 Like companions, S3 tokens live outside the `Token` enum: the bucket and
        // the key are free strings, and forcing an open set into a closed type would
        // have weakened exhaustiveness for everything else.
        let mut s3: std::collections::BTreeMap<String, String> = Default::default();

        if let Some(d) = &domain {
            values.insert(Token::Domain, d.clone());
        }
        if let Some(z) = self.state.timezone().await? {
            values.insert(Token::Timezone, z);
        }
        if used_ones.contains(&Token::BrandLogo) {
            let logo = self.state.logo().await?;
            values.insert(
                Token::BrandLogo,
                logo.as_deref()
                    .and_then(hlb_types::binding::brand_logo_svg)
                    .unwrap_or_else(|| hlb_types::binding::NO_LOGO.to_string()),
            );
        }

        // The database's coordinates come from the declared CAPABILITY, not from a
        // constant: that is what lets the same manifest follow the topology.
        if let Some(m) = &manifest {
            for c in &m.spec.requires {
                match c {
                    hlb_types::Capability::Database { engine, name, .. } => {
                        let base = name.clone().unwrap_or_else(|| app.to_string());
                        let host = engine.service_name().to_string();
                        let port = match engine {
                            hlb_types::DbEngine::Postgres => "5432",
                            hlb_types::DbEngine::Mariadb => "3306",
                        };

                        values.insert(Token::DbHost, host.clone());
                        values.insert(Token::DbPort, port.to_string());
                        values.insert(Token::DbName, base.clone());
                        // 🔴 The role is named after the APP, not the database: an app
                        // with several databases connects with one account. Must stay
                        // aligned with the resolver's `ProvisionDatabase`.
                        values.insert(Token::DbUser, app.to_string());

                        if let Some(password) =
                            self.read_secret(&format!("{app}-db-password")).await?
                        {
                            let schema = match engine {
                                hlb_types::DbEngine::Postgres => "postgres",
                                hlb_types::DbEngine::Mariadb => "mysql",
                            };
                            values.insert(
                                Token::DbUrl,
                                format!("{schema}://{app}:{password}@{host}:{port}/{base}"),
                            );
                            values.insert(Token::DbPassword, password);
                        }
                    }

                    hlb_types::Capability::Cache { engine, dedicated } => {
                        // A dedicated instance is prefixed with the app's name.
                        let host = if *dedicated {
                            format!("{app}-{}", engine.service_name())
                        } else {
                            engine.service_name().to_string()
                        };
                        values.insert(Token::CacheHost, host.clone());
                        values.insert(Token::CachePort, "6379".into());
                        values.insert(Token::CacheUrl, format!("redis://{host}:6379"));
                    }

                    hlb_types::Capability::Sso { .. } => {
                        // 🔴 PocketID NAMES the client and generates its id; the id is
                        // what the app must present. The app's name stood here until
                        // 2026-10-14, and every OIDC sign-in would have answered
                        // "invalid client". Absent, the token stays literal.
                        if let Some(id) = self.read_secret(&format!("{app}-oidc-client-id")).await?
                        {
                            values.insert(Token::OidcClientId, id);
                        }
                        if let Some(s) = self.read_secret(&format!("{app}-oidc-secret")).await? {
                            values.insert(Token::OidcClientSecret, s);
                        }
                    }

                    hlb_types::Capability::Smtp { sender: _ } => {
                        values.insert(Token::SmtpHost, submission::host().into());
                        // 🔴 Submission: 587 was handed out for months while Stalwart
                        // did not listen on it.
                        values.insert(Token::SmtpPort, hlb_mail::SUBMISSION_PORT.to_string());
                        // 🔴 The ADDRESS, which Stalwart signs in: the app's name was
                        // here, and Stalwart refuses it. The one that was tried, kept.
                        if let Some(a) = self.read_secret(&submission::address_secret(app)).await? {
                            values.insert(Token::SmtpUser, a.clone());
                            values.insert(Token::SmtpFrom, a);
                        }
                        if let Some(s) = self.read_secret(&format!("{app}-smtp-password")).await? {
                            values.insert(Token::SmtpPassword, s);
                        }
                    }

                    hlb_types::Capability::ObjectStorage { bucket, .. } => {
                        let bucket_name =
                            hlb_types::capability::bucket_name(bucket.as_deref(), app).to_string();
                        s3.insert("{{ s3.bucket }}".to_string(), bucket_name);
                        s3.insert("{{ s3.endpoint }}".to_string(), S3_ENDPOINT.into());
                        s3.insert("{{ s3.region }}".to_string(), S3_REGION.into());
                        // Garage's own key id (`GK…`), kept when the bucket was made —
                        // never the key's name, which no S3 signature accepts.
                        if let Some(id) = self.read_secret(&s3_key_id(app)).await? {
                            s3.insert("{{ s3.access_key }}".to_string(), id);
                        }
                        if let Some(k) = self.read_secret(&format!("{app}-s3-secret")).await? {
                            s3.insert(hlb_types::binding::S3_SECRET_KEY.to_string(), k);
                        }
                    }

                    hlb_types::Capability::MailAccount { .. }
                    | hlb_types::Capability::Storage { .. } => {}
                }
            }
        }

        // The OIDC issuer depends on PocketID's domain, not the app's.
        if let Ok(Some(d)) = self.state.app_domain("pocket-id").await {
            values.insert(Token::OidcIssuer, format!("https://{d}"));
        }

        // 🔴 Companions do NOT go through the `Token` enum: their set is open - each
        // app defines its own - where `Token` is closed by design, so that adding a
        // variant breaks compilation everywhere. A parameterised token does not fit
        // that contract, and forcing it in would have weakened the enum for all the
        // others.
        let companions: Vec<(String, String)> = manifest
            .as_ref()
            .map(|m| {
                m.spec
                    .companions
                    .iter()
                    .map(|c| {
                        (
                            format!("{{{{ companion.{}.host }}}}", c.name),
                            format!("{app}-{}", c.name),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(env
            .iter()
            .map(|(k, v)| {
                let mut s = substitute(v, &values);
                for (token, value) in &s3 {
                    s = s.replace(token, value);
                }
                for (token, host) in &companions {
                    s = s.replace(token, host);
                }
                for (token, value) in &generated_values {
                    s = s.replace(token, value);
                }
                (k.clone(), s)
            })
            .collect())
    }

    /// The app's recovery sign-ins that carry a proof, with what the vault holds for
    /// each — or why it holds nothing, said by the step that wanted one.
    async fn api_sign_ins(
        &self,
        app: &str,
        m: &hlb_types::Manifest,
    ) -> Result<Vec<hlb_guide::ApiSignIn>> {
        let credentials = match self.vault {
            Some(vault) => emergency::credentials(self.state, vault, app, m).await?,
            None => m
                .spec
                .recovery
                .iter()
                .map(|r| hlb_guide::assertions::Credential {
                    secret: r.secret.clone(),
                    sign_in: Err("the vault is not open".into()),
                })
                .collect(),
        };
        Ok(m.spec
            .recovery
            .iter()
            .zip(credentials)
            .filter_map(|(r, credential)| {
                r.proof
                    .clone()
                    .map(|proof| hlb_guide::ApiSignIn { credential, proof })
            })
            .collect())
    }

    /// Reads a secret from the vault, or `None` when it does not exist yet.
    ///
    /// ⚠️ Absent is not an error here: a plan can be executed before the secret is
    /// generated, and the matching action will take care of it. The token then stays
    /// literal, which is visible.
    async fn read_secret(&self, name: &str) -> Result<Option<String>> {
        let Some(vault) = self.vault else {
            return Ok(None);
        };
        match self.state.secret(name).await? {
            Some(ct) => Ok(Some(vault.decrypt(&ct)?)),
            None => Ok(None),
        }
    }

    /// What backs one of `app`'s volumes: the same backing `CreateVolume` gave it,
    /// so that a node creating it on first use creates the same thing. A companion's
    /// volumes are named after its service, never in `requires`: local. Another app's
    /// volume takes its OWNER's backing: given this app's, a volume the owner keeps on
    /// its node would have been looked for on the pool.
    fn backing_of(
        &self,
        app: &str,
        manifest: Option<&hlb_types::Manifest>,
        vol: &str,
    ) -> Result<hlb_orchestrator::VolumeBacking> {
        let (tier, holder, declared) = manifest
            .iter()
            .flat_map(|m| &m.spec.requires)
            .find_map(|c| match c {
                hlb_types::Capability::Storage {
                    name, tier, owner, ..
                } => {
                    let holder = owner.as_deref().unwrap_or(app);
                    (format!("{holder}-{name}") == vol)
                        .then(|| (*tier, holder.to_string(), name.clone()))
                }
                _ => None,
            })
            .unwrap_or((
                hlb_types::StorageTier::Local,
                app.to_string(),
                declared_volume(app, vol).to_string(),
            ));
        self.storage
            .backing_for(tier, &holder, &declared)
            .map_err(Error::Storage)
    }

    async fn execute_one(&self, app: &str, action: &Action) -> Result<Step> {
        match action {
            Action::DeployService {
                name,
                image,
                replicas,
                constraints,
                env,
                mounts,
                hardening,
                healthcheck,
                files,
                command,
                args,
                process,
                memory,
            } => {
                // ⚠️ The plan was built BEFORE execution, so its `image` field still
                // carries the tag. The digest resolved at the previous step lives in
                // the state - and that is what is authoritative.
                // The image this service runs — the app's or a companion's — found by
                // repository and tag, never assumed to be the app's own.
                //
                // 🔴 Never the tag alone. Falling back to it deployed the lab's PostgreSQL
                // as `…pgvector0.8.0` with no digest, for days, beside sixteen services
                // that had one: whatever the tag named at each restart is what ran.
                let unpinned = image.split('@').next().unwrap_or(image);
                let resolved = self
                    .state
                    .app_manifest(app)
                    .await
                    .ok()
                    .and_then(|m| {
                        std::iter::once(&m.spec.image)
                            .chain(m.spec.companions.iter().map(|c| &c.image))
                            .find(|i| format!("{}:{}", i.repo, i.tag) == unpinned)
                            .filter(|i| i.is_pinned())
                            .map(|i| i.reference())
                    })
                    .or_else(|| image.contains("@sha256:").then(|| image.clone()))
                    .ok_or_else(|| Error::Unpinned {
                        app: app.to_string(),
                        image: image.clone(),
                    })?;

                // 🔴 Binding tokens take their value HERE, not in the plan. This is
                // what finally tells an app where its database is.
                let env = self.resolve_bindings(app, env).await?;

                // Idempotent, and cheap: the first deployment of an installation is
                // what creates the network everything else joins.
                self.orchestrator.ensure_network(&self.network).await?;

                // The count `hlb stop` / `hlb scale` decided for the app's own service:
                // a redeployment or an upgrade starting a stopped app again would undo
                // a decision nobody took back.
                let replicas = match name == app {
                    true => self.state.app_replicas(app).await?.unwrap_or(*replicas),
                    false => *replicas,
                };
                let mut spec = ServiceSpec::new(name, &resolved)
                    .replicas(replicas)
                    .network(&self.network)
                    .env(env.clone())
                    // The hardening declared in the manifest is actually applied.
                    .hardening(hardening.clone());

                if let Some(h) = healthcheck {
                    spec = spec.healthcheck(h.clone());
                }
                spec.memory = *memory;
                if !command.is_empty() {
                    spec = spec.command(command.clone());
                }
                spec.args = args.clone();
                spec.process = process.clone();
                for c in constraints {
                    spec = spec.constraint(c);
                }
                let manifest = self.state.app_manifest(app).await.ok();
                for (vol, path) in mounts {
                    let backing = self.backing_of(app, manifest.as_ref(), vol)?;
                    spec = spec.mount_backed(vol, path, backing);
                }
                // A file takes its tokens like a variable: an app configured by file
                // alone (Vikunja's OIDC providers are a list no variable can carry)
                // would otherwise read `{{ oidc.client_secret }}` literally.
                for (path, content) in self.resolve_bindings(app, files).await? {
                    spec = spec.file(&path, &content);
                }
                // The ingress is deployed with every route there already is: started on
                // the image's own Caddyfile it would serve a welcome page to the
                // internet, and a redeployment without it would drop every route
                // until the next publication.
                if name == hlb_types::manifest::INGRESS_SERVICE {
                    let rendered =
                        ingress::render(self.orchestrator, self.state, self.vault).await?;
                    ingress::write(self.orchestrator, &resolved, &rendered).await?;
                    spec = spec
                        .command(ingress::command())
                        .aliases(ingress::aliases(self.state).await?);
                }
                // The app's own service: a companion reads no other app's volume.
                if name == app {
                    self.follow_owners(name, manifest.as_ref()).await?;
                }
                // An app signing people in through PocketID fetches its issuer itself,
                // and under a private root refused its certificate: the sign-in
                // button led nowhere. The root is added to what the image trusts.
                // And an app sending mail meets Stalwart's submission port, served under
                // Homelabus's own root whatever the exposure. Every service of the app,
                // its companions too: Fluxer's api, a companion, is what signs in and
                // sends — and a root added is never one taken away.
                let mut roots = Vec::new();
                if manifest.as_ref().is_some_and(trust::verifies_issuer) {
                    roots.extend(ingress::trusted_root(self.state, self.vault).await);
                }
                if manifest.as_ref().is_some_and(trust::sends_mail) {
                    if let Some(v) = self.vault {
                        roots.extend(ingress::root(self.state, v).await?.map(|(c, _)| c));
                    }
                }
                if name == app && name == submission::host() {
                    roots.extend(submission::trusted_roots(self.state).await?);
                }
                if let Some(m) = trust::mount(&roots) {
                    for (path, content) in &m.files {
                        spec = spec.file(path, content);
                    }
                    for (k, v) in m.env {
                        // The manifest's own setting wins: it knows its image.
                        if !spec.env.iter().any(|(n, _)| *n == k) {
                            spec.env.push((k, v));
                        }
                    }
                }
                self.orchestrator.deploy(&spec).await?;
                Ok(Step::Done)
            }

            Action::FetchDownload {
                app: owner,
                volume,
                url,
                sha256,
                into,
                unzip,
                constraints,
                mounts,
            } => {
                let manifest = self.state.app_manifest(owner).await.ok();
                // The app as it will be deployed, for its placement alone: pinned to
                // its data now, the app's own deployment then finds the same node.
                let mut app_spec = ServiceSpec::new(owner, "");
                for c in constraints {
                    app_spec = app_spec.constraint(c);
                }
                for (vol, path) in mounts {
                    let backing = self.backing_of(owner, manifest.as_ref(), vol)?;
                    app_spec = app_spec.mount_backed(vol, path, backing);
                }
                let placed = self.orchestrator.place_with_data(&app_spec).await?;
                let fetch = download::Fetch {
                    app: owner,
                    volume,
                    url,
                    sha256,
                    into,
                    unzip: *unzip,
                };
                let job = download::job(
                    &fetch,
                    app_spec.backing_of(volume),
                    &placed.constraints,
                    &self.network,
                );
                let out = self.orchestrator.run_job(&job, download::TIMEOUT_S).await?;
                if !out.succeeded {
                    return Err(Error::Download(format!(
                        "{url} into {volume}/{into}: {}",
                        out.output
                            .iter()
                            .rev()
                            .take(5)
                            .rev()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" | ")
                    )));
                }
                Ok(Step::Done)
            }

            Action::WaitHealthy { name, timeout_secs } => {
                self.orchestrator.wait_healthy(name, *timeout_secs).await?;
                // Caddy up on its file: what it routes is now true, for the apps that
                // waited for it too.
                if name == hlb_types::manifest::INGRESS_SERVICE {
                    let exposure = self.state.exposure().await?;
                    let routes =
                        ingress::routes(self.orchestrator, self.state, exposure.as_ref()).await?;
                    ingress::published(self.state, &routes).await?;
                }
                // CrowdSec up: the Caddyfile gains its bouncer and its access log now.
                // It has no route of its own, so nothing else would republish until
                // the next app — and until then it would see nothing and block nothing.
                if name == hlb_ingress::crowdsec::SERVICE {
                    ingress::publish(self.orchestrator, self.state, self.vault).await?;
                }
                Ok(Step::Done)
            }

            Action::GenerateSecret { name, purpose } => {
                let Some(vault) = self.vault else {
                    return Ok(Step::NotImplemented);
                };

                let password = hlb_secrets::generate_password(hlb_secrets::DEFAULT_PASSWORD_LEN);
                let ct = vault.encrypt(&password)?;

                // `if_absent`: a password already injected into a service must never
                // change under its feet when a plan is rerun.
                let created = self
                    .state
                    .store_secret_if_absent(name, &ct, purpose)
                    .await?;
                if created {
                    tracing::info!(secret = name, "secret generated");
                }
                Ok(Step::Done)
            }

            Action::ProvisionBucket {
                bucket,
                key_name,
                secret_name,
                expire_after_days,
            } => {
                let (Some(garage), Some(vault)) = (self.objstore, self.vault) else {
                    // 🔴 Never `Done`: claiming a bucket was created would start the
                    // app against storage that does not exist, and it would write into
                    // the void.
                    return Ok(Step::NotImplemented);
                };
                // The expiry is an S3 call: without the S3 API, nothing would ever
                // delete what Fluxer stages there — said before anything is made.
                if expire_after_days.is_some() && garage.s3_endpoint().is_none() {
                    return Ok(Step::NotImplemented);
                }

                // 🔴 The vault is authoritative, not Garage. A key present in Garage
                // whose secret was lost is UNUSABLE - it is only given at creation
                // time. Asking Garage alone would restart a resumed run with no
                // secret, and the app would fail on an "invalid signature" that points
                // at nothing.
                let known = match self.state.secret(secret_name).await? {
                    Some(ct) => Some(vault.decrypt(&ct)?),
                    None => None,
                };

                let id = garage.ensure_bucket(bucket).await?;
                let key = garage.ensure_key(key_name, known.as_deref()).await?;

                // The secret goes to the vault BEFORE the grant: if the grant fails
                // we keep enough to resume; the other order would lose the key.
                let ct = vault.encrypt(&key.secret_access_key)?;
                if !self
                    .state
                    .store_secret_if_absent(secret_name, &ct, "S3 secret key")
                    .await?
                {
                    // The secret already existed: this is a resumed run, and
                    // `ensure_key` just handed back THAT secret. Rotating rewrites it
                    // identically, which is a no-op - but covers the case where Garage
                    // had lost the key and just created a fresh one.
                    self.state.rotate_secret(secret_name, &ct).await?;
                }

                // The key's id is what the app signs with: kept beside its secret.
                let key_id = vault.encrypt(&key.access_key_id)?;
                let id_name = s3_key_id(app);
                if !self
                    .state
                    .store_secret_if_absent(&id_name, &key_id, "S3 access key id")
                    .await?
                {
                    self.state.rotate_secret(&id_name, &key_id).await?;
                }

                garage.allow(&id, &key.access_key_id).await?;

                // Written with the app's own key, which Garage lets set its bucket's
                // lifecycle, and read back before the step is done.
                if let (Some(days), Some(endpoint)) = (expire_after_days, garage.s3_endpoint()) {
                    let at = hlb_objstore::s3::Location {
                        endpoint: endpoint.to_string(),
                        bucket: bucket.clone(),
                        prefix: String::new(),
                    };
                    hlb_objstore::s3::Bucket::connect(
                        at,
                        &key.access_key_id,
                        &key.secret_access_key,
                    )
                    .await?
                    .expire_after(*days)
                    .await?;
                }
                Ok(Step::Done)
            }

            Action::ProvisionDatabase {
                engine,
                database,
                role,
                password_secret,
                extensions,
                connection_limit,
            } => {
                let Some(vault) = self.vault else {
                    return Ok(Step::NotImplemented);
                };

                let ct = self
                    .state
                    .secret(password_secret)
                    .await?
                    .ok_or_else(|| Error::MissingSecret(password_secret.clone()))?;
                let password = vault.decrypt(&ct)?;

                // 🔴 The `match` is exhaustive: adding an engine to `DbEngine` breaks
                // compilation here, which forces a decision on how to provision it
                // rather than letting it fall into a default arm that would claim
                // success.
                let created = match engine {
                    hlb_types::DbEngine::Postgres => {
                        let Some(pg) = self.postgres else {
                            return Ok(Step::NotImplemented);
                        };
                        let created = pg.provision(database, role, &password).await?;
                        if let Some(n) = connection_limit {
                            pg.limit_connections(role, *n).await?;
                        }
                        created
                    }
                    hlb_types::DbEngine::Mariadb => {
                        let Some(my) = self.mariadb else {
                            return Ok(Step::NotImplemented);
                        };
                        let created = my.provision(database, role, &password).await?;
                        if let Some(n) = connection_limit {
                            my.limit_connections(role, *n).await?;
                        }
                        created
                    }
                };

                if created {
                    tracing::info!(database, role, engine = ?engine, "database provisioned");
                }

                // 🔴 Extensions AFTER the database, and on the app's database - not on
                // `postgres`. `CREATE EXTENSION` is per-database: installed in the
                // wrong place it succeeds and the app never sees it.
                if !extensions.is_empty() {
                    let Some(pg) = self.postgres else {
                        return Ok(Step::NotImplemented);
                    };
                    for ext in extensions {
                        if let Err(e) = pg.create_extension(database, ext).await {
                            // The remedy is in the message: an extension missing from
                            // the IMAGE cannot be installed from SQL, and PostgreSQL's
                            // raw error looks like a permissions problem.
                            return Err(Error::MissingExtension {
                                extension: ext.clone(),
                                database: database.clone(),
                                cause: e.to_string(),
                            });
                        }
                    }
                }
                Ok(Step::Done)
            }

            Action::PendingGuideStep {
                id, service, step, ..
            } => {
                // We try to handle it ourselves first. Many "inside the application"
                // steps can be scripted; treating them as manual by default is the
                // usual mistake.
                // An `api` call's body takes its tokens HERE, like a variable at
                // deployment: the step in the plan keeps `{{ secret.admin-password }}`.
                let mut step = step.clone();
                let mut writes_sql = false;
                let mut signs_in = false;
                for a in &mut step.automate {
                    match a {
                        // Its headers take `{{ token }}` alone, filled by the sign-in
                        // (`validate_guide`): nothing of the vault's to give them here.
                        hlb_types::Automation::Api {
                            port: _,
                            sign_in,
                            headers: _,
                            probe: _,
                            calls,
                        } => {
                            signs_in |= sign_in.is_some();
                            for c in calls {
                                if let Some(body) = &c.body {
                                    c.body = Some(self.resolve_one(app, body).await?);
                                }
                            }
                        }
                        hlb_types::Automation::Sql { params, .. } => {
                            writes_sql = true;
                            for p in params {
                                *p = self.resolve_one(app, p).await?;
                            }
                        }
                        hlb_types::Automation::Env { .. } | hlb_types::Automation::Exec { .. } => {}
                    }
                }
                let database = if writes_sql {
                    Some(
                        self.resolve_one(app, hlb_types::Token::DbName.placeholder())
                            .await?,
                    )
                } else {
                    None
                };
                let app_db = match (self.postgres, database) {
                    (Some(pg), Some(database)) => Some(AppDb { pg, database }),
                    _ => None,
                };
                let manifest = self.state.app_manifest(app).await.ok();
                let port = manifest
                    .as_ref()
                    .and_then(|m| m.spec.ingress.first().map(|i| i.port));
                // The recovery sign-ins, looked up only for a step that signs in: the
                // vault is opened for what is sent, never on the way.
                let sign_ins = match (&manifest, signs_in) {
                    (Some(m), true) => self.api_sign_ins(app, m).await?,
                    _ => Vec::new(),
                };
                let api = self.api.map(|client| hlb_guide::Api {
                    client,
                    port,
                    sign_ins: &sign_ins,
                });
                let domain = self.state.app_domain(app).await?.unwrap_or_default();
                let issue = hlb_guide::try_automate_with(
                    self.orchestrator,
                    api,
                    app_db.as_ref().map(|d| d as &dyn hlb_guide::SqlWriter),
                    service,
                    &step,
                    &[("domain", domain.as_str())],
                )
                .await;

                if issue.handled() {
                    tracing::info!(step = %id, "{}", issue.describe());
                    // The step is done: it must stop blocking.
                    self.state.verify_guide(app, id).await?;
                } else if !matches!(issue, hlb_guide::AutomationOutcome::NothingDeclared) {
                    // We say WHY it stays manual: without that, the user would not
                    // know why the system is asking them to do what it announced it
                    // would automate.
                    tracing::warn!(step = %id, "{}", issue.describe());
                }
                Ok(Step::Done)
            }

            Action::ResolveDigest { repo, tag } => {
                let Some(reg) = self.registry else {
                    return Ok(Step::NotImplemented);
                };

                let image = ImageRef::parse(&format!("{repo}:{tag}"));
                let digest = reg.resolve_digest(&image).await?;

                // The digest is frozen into the state: that is what gets deployed,
                // not the tag, which is mutable. On the image it was resolved for — and
                // an image the app no longer names is not a step done.
                if !self.state.set_image_digest(app, repo, tag, &digest).await? {
                    return Err(Error::Unpinned {
                        app: app.to_string(),
                        image: format!("{repo}:{tag}, which {app}'s manifest no longer names,"),
                    });
                }
                tracing::info!(%image, digest, "digest resolved");
                Ok(Step::Done)
            }

            Action::CreateVolume {
                name,
                backup,
                sqlite,
                tier,
                ..
            } => {
                // 🔴 The tier stops being decorative here. Until this line it was a
                // declaration nobody read, and `tier: nfs` produced the same local
                // volume as `tier: local`.
                let backing = self
                    .storage
                    .backing_for(*tier, app, declared_volume(app, name))
                    .map_err(Error::Storage)?;

                let spec = hlb_orchestrator::VolumeSpec {
                    name: name.clone(),
                    backing,
                };
                let info = self.orchestrator.create_volume(&spec).await?;

                // The REAL mount point is recorded: it is what the backup will read.
                // Without it, we do not know what to back up.
                self.state
                    .add_volume(app, &info.name, &info.mountpoint, *backup, *sqlite)
                    .await?;

                if info.existed {
                    tracing::info!(name, "existing volume kept (it holds data)");
                }
                Ok(Step::Done)
            }

            Action::AddPortalCallback { uri } => {
                let Some(pid) = self.identity else {
                    return Ok(Step::NotImplemented);
                };
                // The portal's client exists once oauth2-proxy is installed: the graph
                // orders it first. Absent, it is a failure that names it, never a
                // client created here with no portal to use it.
                pid.add_callback_url(hlb_types::capability::PORTAL_SERVICE, uri)
                    .await?;
                Ok(Step::Done)
            }

            Action::CreateOidcClient {
                app: client,
                redirect_uris,
            } => {
                let (Some(pid), Some(vault)) = (self.identity, self.vault) else {
                    return Ok(Step::NotImplemented);
                };

                // Idempotent: an existing client is kept, and its secret is NEVER
                // regenerated - it is already injected into the running app. Its
                // callbacks are brought to the ones computed from today's domain.
                let creds = pid.ensure(client, redirect_uris, true).await?;

                keep_oidc_credentials(
                    self.state,
                    vault,
                    client,
                    &creds,
                    &format!("{app}-oidc-secret"),
                    &format!("{app}-oidc-client-id"),
                )
                .await?;
                Ok(Step::Done)
            }

            Action::ConfigureIngress { .. } => {
                // ⚠️ The WHOLE configuration is regenerated, not just this app's
                // route: the file replaces the previous one, and a fragment would
                // delete the other apps' routes.
                match ingress::publish(self.orchestrator, self.state, self.vault).await? {
                    // Done when THIS app's route is among those published: one withheld
                    // — through an Anubis that is gone — is not served, and the next
                    // publication completes it when it is.
                    ingress::Published::Done { routes, restarted } => {
                        tracing::info!(routes = routes.len(), restarted, "routes published");
                        if routes.iter().any(|r| r.service == app) {
                            Ok(Step::Done)
                        } else {
                            tracing::warn!(app, "its route was not published");
                            Ok(Step::NotImplemented)
                        }
                    }
                    // Recorded as such, never as published: the ingress's own
                    // deployment completes it, and `hlb config exposure` says what
                    // is missing.
                    ingress::Published::NoIngress => {
                        tracing::warn!("no ingress yet: hlb install caddy --apply");
                        Ok(Step::NotImplemented)
                    }
                    ingress::Published::NotConfigured => {
                        tracing::warn!("no exposure configured: hlb config exposure");
                        Ok(Step::NotImplemented)
                    }
                }
            }

            Action::ProvisionSmtpAccount {
                address,
                secret_name,
            } => {
                let (Some(mail), Some(vault)) = (self.mail, self.vault) else {
                    return Ok(Step::NotImplemented);
                };
                let Some(password) = self.read_secret(secret_name).await? else {
                    return Err(Error::Submission(format!(
                        "{secret_name} is not in the vault, which the plan generates first"
                    )));
                };
                let domain = address.rsplit_once('@').map_or("", |(_, d)| d);
                let root = submission::root(self.state, vault, domain).await?;
                // The certificate before the listener: loaded without a restart, while
                // a listener started before it would serve Stalwart's own, which every
                // app refuses.
                if submission::needs_certificate(&mail.certificates().await?, chrono::Utc::now()) {
                    let leaf = hlb_agent::pki::issue_platform_server(&root, submission::host())
                        .await
                        .map_err(|e| Error::Submission(format!("Stalwart's certificate: {e}")))?;
                    mail.add_certificate(&leaf.cert_pem, &leaf.key_pem).await?;
                    tracing::info!("Stalwart's submission certificate issued");
                }
                if !mail.has_submission().await? {
                    mail.add_submission().await?;
                    submission::restart(self.orchestrator, mail, submission::host()).await?;
                    tracing::info!("Stalwart's submission port opened");
                }
                for c in submission::protect_platform(self.orchestrator, mail, true).await? {
                    tracing::info!("Stalwart: {c}");
                }
                for c in submission::trace(mail, true).await? {
                    tracing::info!("Stalwart: {c}");
                }
                // Not this app's to fail: a Stalwart installed before its resolver
                // sends as well, its spam filter blinder, which the inbox says.
                match submission::own_resolver(self.orchestrator, mail, true).await {
                    Ok(changed) => changed.iter().for_each(|c| tracing::info!("Stalwart: {c}")),
                    Err(e) => tracing::warn!("Stalwart: {e}"),
                }
                for c in submission::name_server(self.state, mail, true).await? {
                    tracing::info!("Stalwart: {c}");
                }
                // People's own clients after the apps': a certificate that cannot be had
                // yet is said, and the role pass asks again every night.
                match mail_tls::certify(self.state, vault, mail, true).await {
                    Ok(changed) => {
                        for c in changed {
                            tracing::info!("Stalwart: {c}");
                        }
                    }
                    Err(e) => tracing::warn!("Stalwart's certificate for people's clients: {e}"),
                }
                let p = mail.ensure_account(address, &password, &[]).await?;
                let stored = vault.encrypt(address)?;
                let name = submission::address_secret(app);
                if !self
                    .state
                    .store_secret_if_absent(&name, &stored, "SMTP sending address")
                    .await?
                {
                    self.state.rotate_secret(&name, &stored).await?;
                }
                let job =
                    submission::trial_job(app, address, &password, &root.cert_pem, &self.network);
                submission::try_account(self.orchestrator, &job)
                    .await
                    .map_err(|why| {
                        Error::Submission(format!(
                            "{address} {} — and was not accepted as it should be: {why}",
                            if p.created {
                                "was created"
                            } else {
                                "already existed, with a password of its own that was kept"
                            }
                        ))
                    })?;
                Ok(Step::Done)
            }

            Action::ProvisionMailAccount {
                address,
                aliases,
                quota_bytes,
            } => {
                let (Some(mail), Some(vault)) = (self.mail, self.vault) else {
                    return Ok(Step::NotImplemented);
                };

                // 🔴 A quota declared and not set is worse than no quota: the mailbox
                // would look bounded and grow without end, until it saturates the disk
                // that also carries the databases. `hlb-mail` has no quota operation,
                // Stalwart not exposing one over JMAP.
                //
                // So we refuse BEFORE creating anything, rather than creating the
                // mailbox and staying silent about the missing half - "Unimplemented is
                // never Done".
                if quota_bytes.is_some() {
                    tracing::warn!(
                        address,
                        "mailbox quota declared in the manifest but not applicable: \
                         Stalwart does not expose it over JMAP. Remove `quotaBytes` \
                         from the manifest, or set it by hand in Stalwart."
                    );
                    return Ok(Step::NotImplemented);
                }

                // The password lives in the vault, like the others. `if_absent`:
                // rerunning a plan must not manufacture a second one, which would no
                // longer match the one deposited in Stalwart.
                let secret_name = format!("{app}-mail-password");
                let password = match self.state.secret(&secret_name).await? {
                    Some(ct) => vault.decrypt(&ct)?,
                    None => {
                        let p = hlb_secrets::generate_password(hlb_secrets::DEFAULT_PASSWORD_LEN);
                        self.state
                            .store_secret_if_absent(
                                &secret_name,
                                &vault.encrypt(&p)?,
                                "IMAP/SMTP password",
                            )
                            .await?;
                        p
                    }
                };

                // The aliases declared in the manifest are a boolean: "this app is
                // allowed to have some". It asks for none at install time - they are
                // created in use.
                let requested: Vec<String> = Vec::new();
                let p = mail.ensure_account(address, &password, &requested).await?;
                for c in submission::protect_platform(self.orchestrator, mail, true).await? {
                    tracing::info!("Stalwart: {c}");
                }
                for c in submission::trace(mail, true).await? {
                    tracing::info!("Stalwart: {c}");
                }
                // Not this app's to fail: a Stalwart installed before its resolver
                // sends as well, its spam filter blinder, which the inbox says.
                match submission::own_resolver(self.orchestrator, mail, true).await {
                    Ok(changed) => changed.iter().for_each(|c| tracing::info!("Stalwart: {c}")),
                    Err(e) => tracing::warn!("Stalwart: {e}"),
                }
                for c in submission::name_server(self.state, mail, true).await? {
                    tracing::info!("Stalwart: {c}");
                }
                // People's own clients after the apps': a certificate that cannot be had
                // yet is said, and the role pass asks again every night.
                match mail_tls::certify(self.state, vault, mail, true).await {
                    Ok(changed) => {
                        for c in changed {
                            tracing::info!("Stalwart: {c}");
                        }
                    }
                    Err(e) => tracing::warn!("Stalwart's certificate for people's clients: {e}"),
                }

                if p.created {
                    tracing::info!(address = %p.address, "mailbox created");
                } else {
                    // 🔴 Concrete consequence: the vault's password is the one from
                    // before, and it was NOT touched. Changing it would cut the running
                    // app's IMAP access.
                    tracing::debug!(address = %p.address, "mailbox already present, kept");
                }
                let _ = aliases;
                Ok(Step::Done)
            }
        }
    }
}

/// An app's own PostgreSQL database, for its guide's `sql` automations.
struct AppDb<'a> {
    pg: &'a PostgresProvisioner,
    database: String,
}

#[async_trait::async_trait]
impl hlb_guide::SqlWriter for AppDb<'_> {
    async fn probe(&self, probe: &str, params: &[String]) -> std::result::Result<bool, String> {
        self.pg
            .probe_bound(&self.database, probe, params)
            .await
            .map_err(|e| e.to_string())
    }
    async fn write(
        &self,
        statement: &str,
        probe: &str,
        params: &[String],
    ) -> std::result::Result<bool, String> {
        self.pg
            .write_bound(&self.database, statement, probe, params)
            .await
            .map(|(_, held)| held)
            .map_err(|e| e.to_string())
    }
}

enum Step {
    Done,
    NotImplemented,
}

/// A short, stable label, stored in the database and shown in reports.
fn kind_of(a: &Action) -> &'static str {
    match a {
        Action::ProvisionDatabase { .. } => "ProvisionDatabase",
        Action::ProvisionBucket { .. } => "ProvisionBucket",
        Action::GenerateSecret { .. } => "GenerateSecret",
        Action::CreateOidcClient { .. } => "CreateOidcClient",
        Action::AddPortalCallback { .. } => "AddPortalCallback",
        Action::CreateVolume { .. } => "CreateVolume",
        Action::ProvisionSmtpAccount { .. } => "ProvisionSmtpAccount",
        Action::ProvisionMailAccount { .. } => "ProvisionMailAccount",
        Action::DeployService { .. } => "DeployService",
        Action::FetchDownload { .. } => "FetchDownload",
        Action::ResolveDigest { .. } => "ResolveDigest",
        Action::WaitHealthy { .. } => "WaitHealthy",
        Action::ConfigureIngress { .. } => "ConfigureIngress",
        Action::PendingGuideStep { .. } => "PendingGuideStep",
    }
}

#[cfg(test)]
mod tests {

    use hlb_orchestrator::VolumeBacking;
    use hlb_types::StorageTier;

    #[test]
    fn a_declared_nfs_volume_with_no_server_stops_the_install() {
        // 🔴 THE property of this module. A `tier: nfs` volume silently turned into a
        // local one gives an app that starts, accepts uploads and looks healthy — then
        // loses them on the next redeployment, because the bytes went somewhere nobody
        // meant to create. It is the Immich failure, and nothing signals it.
        let none = StorageConfig::default();
        let e = none
            .backing_for(StorageTier::Nfs, "immich", "data")
            .expect_err("an unconfigured NFS tier must refuse");
        assert!(e.contains("--nfs-server"), "{e}");
        assert!(
            e.contains("lose it"),
            "the reason must be in the message: {e}"
        );
    }

    #[test]
    fn a_local_volume_falls_back_to_docker_without_complaining() {
        // ⚠️ The asymmetry is deliberate. `tier: local` says "this node owns it", and
        // Docker's own directory satisfies that on a node with no pool. `tier: nfs`
        // says "this does NOT fit here", which nothing local can satisfy.
        let none = StorageConfig::default();
        assert_eq!(
            none.backing_for(StorageTier::Local, "gitea", "data"),
            Ok(VolumeBacking::Docker)
        );
    }

    #[test]
    fn two_apps_with_a_volume_of_the_same_name_never_share_bytes() {
        // "data" is the most common volume name in the catalog. Rooting them by name
        // alone would land gitea's and immich's on the same directory.
        let c = StorageConfig {
            local_root: Some("/tank/apps".into()),
            ..Default::default()
        };
        assert_eq!(
            c.backing_for(StorageTier::Local, "caddy", "data"),
            Ok(VolumeBacking::Docker),
            "the ingress stays on its node, never pinned to the pool's"
        );
        let a = c.backing_for(StorageTier::Local, "gitea", "data");
        let b = c.backing_for(StorageTier::Local, "immich", "data");
        assert_ne!(a, b);
        assert_eq!(
            a,
            Ok(VolumeBacking::Bind {
                path: "/tank/apps/gitea/data".into()
            })
        );
    }

    #[test]
    fn an_nfs_backing_pins_the_protocol_version() {
        // ⚠️ Left to negotiation, an old server answers in v3 — which is stateless and
        // loses its locks on a reconnect. SQLite on that is corruption waiting.
        let c = StorageConfig {
            nfs_server: Some("10.0.0.2".into()),
            nfs_export: Some("/tank/media".into()),
            ..Default::default()
        };
        let b = c
            .backing_for(StorageTier::Nfs, "jellyfin", "media")
            .expect("configured");
        let o = b.driver_options().expect("options");
        assert!(o["o"].contains("nfsvers=4"), "{o:?}");
        // The leading colon is Docker's syntax for an NFS device, not a typo.
        assert_eq!(o["device"], ":/tank/media/jellyfin/media");
    }

    #[test]
    fn the_refusal_lands_at_preview_time_not_mid_install() {
        // 🔴 An install that refuses on its FIRST action has already frozen the
        // manifest and recorded the app: you are left with a half-install nobody asked
        // for. `blockers_for` runs against the manifest alone, before anything writes.
        let y = "apiVersion: hlb/v1\nkind: App\nmetadata: { name: immich }\n\
                 spec:\n  image: { repo: a/b, tag: \"1\" }\n  requires:\n\
                 \x20   - kind: storage\n      name: data\n      path: /data\n\
                 \x20     tier: nfs\n";
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(y).expect("manifest");

        let none = StorageConfig::default();
        assert_eq!(none.blockers_for(&m).len(), 1, "the nfs volume must block");

        let configured = StorageConfig {
            nfs_server: Some("10.0.0.2".into()),
            nfs_export: Some("/tank".into()),
            ..Default::default()
        };
        assert!(
            configured.blockers_for(&m).is_empty(),
            "a configured installation must not block"
        );
    }

    async fn with_ca() -> (State, Vault, tempfile::TempDir) {
        let st = State::in_memory().await.expect("state");
        let dir = tempfile::tempdir().expect("tmp");
        let vault = Vault::init(dir.path().join("master.key")).expect("vault");
        pki::cluster_ca(&st, &vault, true)
            .await
            .expect("authority")
            .expect("created");
        (st, vault, dir)
    }

    #[tokio::test]
    async fn a_leaf_due_is_issued_again_and_handed_to_its_service_alone() {
        let (st, vault, _dir) = with_ca().await;
        let now = 1_800_000_000;
        st.set_leaf_expiry("hlb-agent", Some(now + 10 * 86_400))
            .await
            .expect("record");
        let o = Fake::default();
        let renewal = pki::Renewal {
            state: &st,
            vault: &vault,
            orchestrator: &o,
            agent_service: "hlb-agent",
            now,
            // The daemon's own, read from its file: fine for two months.
            observed: vec![("hlb-privd".into(), now + 60 * 86_400)],
            inside: Some("hlb-privd"),
        };

        let preview = renewal.run(false).await.expect("preview");
        assert_eq!(preview[0].outcome, pki::Outcome::WouldRenew);
        assert_eq!(preview[1].outcome, pki::Outcome::Fine);
        assert!(
            o.reconfigured.lock().expect("mutex").is_empty(),
            "a preview renewed"
        );

        let lines = renewal.run(true).await.expect("renewal");
        let pki::Outcome::Renewed { not_after } = lines[0].outcome else {
            panic!("{lines:?}");
        };
        assert_eq!(lines[1].outcome, pki::Outcome::Fine);
        let reconfigured = o.reconfigured.lock().expect("mutex").clone();
        assert_eq!(reconfigured.len(), 1);
        let (service, files, aliases) = &reconfigured[0];
        assert_eq!(service, "hlb-agent");
        assert!(aliases.is_empty());
        let paths: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, [pki::AGENT_CERT, pki::AGENT_KEY, pki::CA_FILE]);
        assert_eq!(
            hlb_agent::pki::not_after(&files[0].1).expect("readable"),
            not_after
        );
        // Waited for, so a rollback is not recorded as renewed.
        assert_eq!(*o.waited.lock().expect("mutex"), ["hlb-agent"]);
        let known = st.leaf_expiries().await.expect("expiries");
        assert!(
            known.contains(&("hlb-agent".to_string(), not_after)),
            "{known:?}"
        );
    }

    #[tokio::test]
    async fn a_leaf_of_unknown_end_is_renewed_and_an_absent_service_left_alone() {
        let (st, vault, _dir) = with_ca().await;
        let o = Fake::default();
        o.absent.lock().expect("mutex").push("hlb-agent".into());
        let lines = pki::Renewal {
            state: &st,
            vault: &vault,
            orchestrator: &o,
            agent_service: "hlb-agent",
            now: 1_800_000_000,
            observed: Vec::new(),
            inside: Some("hlb-privd"),
        }
        .run(true)
        .await
        .expect("renewal");
        assert_eq!(lines[0].outcome, pki::Outcome::Absent);
        assert!(
            matches!(lines[1].outcome, pki::Outcome::Renewed { .. }),
            "{lines:?}"
        );
        // Never waited for from inside itself: the update replaces the one waiting.
        assert!(o.waited.lock().expect("mutex").is_empty());
        let files = &o.reconfigured.lock().expect("mutex")[0].1;
        assert_eq!(files[0].0, pki::CONTROLLER_PEM);
        assert!(files[0].1.contains("BEGIN CERTIFICATE") && files[0].1.contains("PRIVATE KEY"));
    }

    #[test]
    fn a_plain_docker_volume_carries_no_driver_options() {
        // Passing empty options is not the same as passing none: Docker treats an
        // empty `type` as a bind with no device and refuses to mount it.
        assert!(VolumeBacking::Docker.driver_options().is_none());
    }
    use super::*;
    use async_trait::async_trait;
    use hlb_orchestrator::{ServiceStatus, UpdateState};
    use std::sync::Mutex;

    /// Fake orchestrator: records calls, and can fail on demand.
    /// What a deployment actually passed on: service name and variables.
    type Deployment = (String, Vec<(String, String)>);

    #[derive(Default)]
    pub(crate) struct Fake {
        deployed: Mutex<Vec<String>>,
        waited: Mutex<Vec<String>>,
        updated: Mutex<Vec<(String, String)>>,
        scaled: Mutex<Vec<(String, u64)>>,
        /// The variables actually passed to Swarm, per service.
        ///
        /// 🔴 This is the ONLY place a token can be seen to have been resolved: the
        /// plan itself must keep carrying the literal token.
        deployed_env: Mutex<Vec<Deployment>>,
        /// The networks each deployed service was attached to.
        deployed_networks: Mutex<Vec<(String, Vec<String>)>>,
        /// The networks `ensure_network` was asked for.
        ensured: Mutex<Vec<String>>,
        /// What `list()` will return: the cluster's "observed" state.
        observed: Mutex<Vec<ServiceStatus>>,
        fail_deploy: bool,
        /// Services `status` answers "not found" for; every other one exists.
        absent: Mutex<Vec<String>>,
        /// `(service, files, aliases)`, for every deployment and every reconfiguration.
        deployed_files: Mutex<Vec<Reconfigured>>,
        reconfigured: Mutex<Vec<Reconfigured>>,
        /// Every service deployed, whole.
        deployed_specs: Mutex<Vec<ServiceSpec>>,
        /// Every one-off job run, in order.
        jobs: Mutex<Vec<ServiceSpec>>,
        /// The jobs fail, as a Caddyfile the ingress refuses would.
        fail_jobs: bool,
        /// Every `exec_in_service`, and whether they exit 1.
        execs: Mutex<Vec<(String, Vec<String>)>>,
        fail_exec: bool,
        /// What every `exec_in_service` prints.
        exec_stdout: String,
        /// What `nodes` answers, and every label set.
        nodes: Mutex<Vec<hlb_orchestrator::NodeInfo>>,
        labelled: Mutex<Vec<(String, String, String)>>,
    }

    type Reconfigured = (String, Vec<(String, String)>, Vec<String>);

    impl Fake {
        /// One whose every `exec_in_service` prints `stdout`, or fails.
        pub(crate) fn exec_answering(stdout: &str, fail: bool) -> Self {
            Self {
                exec_stdout: stdout.into(),
                fail_exec: fail,
                ..Self::default()
            }
        }

        pub(crate) fn execs(&self) -> Vec<(String, Vec<String>)> {
            self.execs.lock().expect("mutex").clone()
        }
    }

    #[async_trait]
    impl Orchestrator for Fake {
        async fn ping(&self) -> hlb_orchestrator::Result<String> {
            Ok("fake".into())
        }
        async fn deploy(&self, s: &ServiceSpec) -> hlb_orchestrator::Result<String> {
            if self.fail_deploy {
                return Err(hlb_orchestrator::Error::Unexpected(
                    "simulated failure".into(),
                ));
            }
            self.deployed.lock().expect("mutex").push(s.name.clone());
            self.deployed_env
                .lock()
                .expect("mutex")
                .push((s.name.clone(), s.env.clone()));
            self.deployed_networks
                .lock()
                .expect("mutex")
                .push((s.name.clone(), s.networks.clone()));
            self.deployed_files.lock().expect("mutex").push((
                s.name.clone(),
                s.files.clone(),
                s.aliases.clone(),
            ));
            self.deployed_specs.lock().expect("mutex").push(s.clone());
            self.absent.lock().expect("mutex").retain(|a| a != &s.name);
            Ok("id".into())
        }
        async fn run_job(
            &self,
            spec: &ServiceSpec,
            _: u64,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::JobOutcome> {
            self.jobs.lock().expect("mutex").push(spec.clone());
            Ok(hlb_orchestrator::JobOutcome {
                succeeded: !self.fail_jobs,
                output: vec!["Error: adapting config: unrecognized directive".into()],
            })
        }
        async fn reconfigure(
            &self,
            name: &str,
            files: &[(String, String)],
            aliases: &[String],
        ) -> hlb_orchestrator::Result<bool> {
            self.reconfigured.lock().expect("mutex").push((
                name.into(),
                files.to_vec(),
                aliases.to_vec(),
            ));
            Ok(true)
        }
        async fn update_image(&self, name: &str, image: &str) -> hlb_orchestrator::Result<()> {
            self.updated
                .lock()
                .expect("mutex")
                .push((name.into(), image.into()));
            Ok(())
        }
        async fn scale(&self, name: &str, replicas: u64) -> hlb_orchestrator::Result<()> {
            self.scaled
                .lock()
                .expect("mutex")
                .push((name.into(), replicas));
            Ok(())
        }
        async fn enable_autolock(&self) -> hlb_orchestrator::Result<String> {
            Ok("SWMKEY-fake".into())
        }
        async fn autolock_enabled(&self) -> hlb_orchestrator::Result<bool> {
            Ok(false)
        }
        async fn cluster_init(&self, _: &str) -> hlb_orchestrator::Result<String> {
            Ok("swarm-fake".into())
        }
        async fn join_tokens(&self) -> hlb_orchestrator::Result<hlb_orchestrator::JoinTokens> {
            Ok(hlb_orchestrator::JoinTokens {
                manager: "SWMTKN-mgr".into(),
                worker: "SWMTKN-wrk".into(),
                advertise_addr: "127.0.0.1:2377".into(),
            })
        }
        async fn nodes(&self) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::NodeInfo>> {
            Ok(self.nodes.lock().expect("mutex").clone())
        }
        async fn label_node(&self, n: &str, k: &str, v: &str) -> hlb_orchestrator::Result<()> {
            self.labelled
                .lock()
                .expect("mutex")
                .push((n.into(), k.into(), v.into()));
            Ok(())
        }
        async fn set_node_availability(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn exec_in_service(
            &self,
            name: &str,
            cmd: &[String],
        ) -> hlb_orchestrator::Result<hlb_orchestrator::ExecOutput> {
            self.execs
                .lock()
                .expect("mutex")
                .push((name.into(), cmd.to_vec()));
            Ok(hlb_orchestrator::ExecOutput {
                exit_code: i64::from(self.fail_exec),
                stdout: self.exec_stdout.clone(),
                stderr: if self.fail_exec {
                    "no space left".into()
                } else {
                    String::new()
                },
            })
        }
        async fn ensure_network(&self, name: &str) -> hlb_orchestrator::Result<bool> {
            self.ensured.lock().expect("mutex").push(name.into());
            Ok(false)
        }

        async fn create_volume(
            &self,
            spec: &hlb_orchestrator::VolumeSpec,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
            Ok(hlb_orchestrator::VolumeInfo {
                name: spec.name.clone(),
                mountpoint: format!("/volumes/{}", spec.name),
                existed: false,
            })
        }
        async fn inspect_volume(
            &self,
            n: &str,
        ) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
            self.create_volume(&hlb_orchestrator::VolumeSpec::docker(n))
                .await
        }
        async fn status(&self, name: &str) -> hlb_orchestrator::Result<ServiceStatus> {
            if self.absent.lock().expect("mutex").iter().any(|a| a == name) {
                return Err(hlb_orchestrator::Error::NotFound(name.into()));
            }
            Ok(ServiceStatus {
                name: name.into(),
                id: "id".into(),
                desired_replicas: 1,
                running_replicas: 1,
                image: "img".into(),
                update_state: Some(UpdateState::Completed),
            })
        }
        async fn list(&self) -> hlb_orchestrator::Result<Vec<ServiceStatus>> {
            Ok(self.observed.lock().expect("mutex").clone())
        }
        async fn remove(&self, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn wait_healthy(
            &self,
            name: &str,
            _: u64,
        ) -> hlb_orchestrator::Result<ServiceStatus> {
            self.waited.lock().expect("mutex").push(name.into());
            self.status(name).await
        }

        async fn tasks(
            &self,
            _: Option<&str>,
        ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::TaskInfo>> {
            // A fake orchestrator has no tasks: empty is the honest answer.
            Ok(Vec::new())
        }

        async fn logs(
            &self,
            _: &str,
            _: u32,
        ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LogLine>> {
            Ok(Vec::new())
        }
    }

    const BASE: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
"#;

    const WITH_DB: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  requires:
    - kind: database
      engine: postgres
  env:
    DATABASE_URL: "{{ db.url }}"
"#;

    const WITH_GUIDE: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  ingress:
    - host: x.example.fr
      port: 80
      expose: after-guide
"#;

    fn manifest() -> hlb_types::Manifest {
        serde_yaml_ng::from_str(BASE).expect("manifest")
    }

    fn plan() -> Plan {
        hlb_resolver::resolve(&manifest(), &hlb_resolver::InstallParams::default()).expect("plan")
    }

    async fn state() -> State {
        let s = State::in_memory().await.expect("base");
        s.upsert_app("demo", &manifest(), None)
            .await
            .expect("upsert");
        s
    }

    #[tokio::test]
    async fn preview_changes_nothing() {
        let o = Fake::default();
        let s = state().await;

        let out = Executor::new(&o, &s)
            .run("demo", &plan())
            .await
            .expect("run");

        assert!(
            o.deployed.lock().unwrap().is_empty(),
            "no deployment in preview"
        );
        assert!(out.is_success());
        // Nothing is marked done: a preview does not consume the plan.
        assert!(s.completed_seqs("demo").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_handled_prerequisite_found_false_at_night_is_pending_again() {
        // 🔴 Found by review: `recheck: 24h` sat in ten guides and nothing read it — a
        // deleted DNS record stayed "handled" for ever.
        let s = state().await;
        for id in ["gone", "kept", "young"] {
            s.add_guide("demo", id, id, true).await.expect("guide");
            assert!(s.verify_guide("demo", id).await.expect("verify"));
        }
        let step = |id: &str, record: &str, every: &str| -> hlb_types::GuideStep {
            serde_yaml_ng::from_str(&format!(
                "id: {id}\ntitle: x\nphase: pre-install\nverify: {{ type: dns, record: {record} }}\n\
                 recheck: {every}\n"
            ))
            .expect("step")
        };
        let steps = vec![
            step("gone", "really-does-not-exist.invalid", "0h"),
            step("kept", "localhost", "0h"),
            // Handled a moment ago: not due for a day.
            step("young", "really-does-not-exist.invalid", "24h"),
        ];
        let found = recheck_guides(&s, None, |_| steps.clone())
            .await
            .expect("pass");

        assert!(
            matches!(&found[0], (_, id, Recheck::Reopened(_)) if id == "gone"),
            "{found:?}"
        );
        assert_eq!(found[1], ("demo".into(), "kept".into(), Recheck::Holds));
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(
            s.unverified_guides("demo").await.expect("open"),
            vec!["gone"]
        );
    }

    #[tokio::test]
    async fn the_night_rechecks_the_guide_frozen_with_the_app_not_the_catalogs() {
        // The catalog dropped the step, or the app left it: the installed app still has
        // the DNS record its frozen guide asked for, and it is still read.
        let s = state().await;
        s.add_guide("demo", "dns", "dns", true)
            .await
            .expect("guide");
        assert!(s.verify_guide("demo", "dns").await.expect("verify"));
        let frozen: hlb_types::Guide = serde_yaml_ng::from_str(
            "steps:\n  - id: dns\n    title: x\n    phase: pre-install\n    \
             verify: { type: dns, record: really-does-not-exist.invalid }\n    recheck: 0h\n",
        )
        .expect("guide");
        s.set_app_guide("demo", Some(&frozen))
            .await
            .expect("frozen");

        let found = recheck_guides(&s, None, |_| Vec::new())
            .await
            .expect("pass");
        assert!(
            matches!(&found[..], [(_, id, Recheck::Reopened(_))] if id == "dns"),
            "{found:?}"
        );
    }

    #[tokio::test]
    async fn an_attestation_forced_against_its_check_is_not_reopened_by_it() {
        // 🔴 The state did not say how a step was handled: one attested with `--force`
        // was put back in the inbox every night its check still failed.
        let s = state().await;
        s.add_guide("demo", "dns", "dns", true)
            .await
            .expect("guide");
        assert!(s.force_guide("demo", "dns").await.expect("force"));
        let step = |record: &str| -> Vec<hlb_types::GuideStep> {
            vec![serde_yaml_ng::from_str(&format!(
                "id: dns\ntitle: x\nphase: pre-install\nverify: {{ type: dns, record: {record} }}\n\
                 recheck: 0h\n"
            ))
            .expect("step")]
        };
        let gone = step("really-does-not-exist.invalid");

        let found = recheck_guides(&s, None, |_| gone.clone())
            .await
            .expect("pass");
        assert!(matches!(&found[0], (_, _, Recheck::Forced(_))), "{found:?}");
        assert!(s.unverified_guides("demo").await.expect("open").is_empty());

        // The check agrees once: established, and its next failure reopens it.
        let kept = step("localhost");
        let found = recheck_guides(&s, None, |_| kept.clone())
            .await
            .expect("pass");
        assert_eq!(found[0].2, Recheck::Holds);
        let found = recheck_guides(&s, None, |_| gone.clone())
            .await
            .expect("pass");
        assert!(
            matches!(&found[0], (_, _, Recheck::Reopened(_))),
            "{found:?}"
        );
        assert_eq!(
            s.unverified_guides("demo").await.expect("open"),
            vec!["dns"]
        );
    }

    const WITH_PREREQUISITE: &str = r#"
steps:
  - id: account
    title: Open an account at the provider
    phase: pre-install
    severity: blocking
    verify:
      type: attest
"#;

    #[tokio::test]
    async fn a_preview_records_nothing_on_an_empty_state() {
        // 🔴 `hlb install` without --apply recorded the app, its journal and its
        // guides: an `installing` row the ingress then routed, read by the next run
        // as its own.
        let o = Fake::default();
        let s = State::in_memory().await.expect("state");
        let guide: hlb_types::Guide = serde_yaml_ng::from_str(WITH_PREREQUISITE).expect("guide");
        let p = hlb_resolver::resolve_with_guide(&manifest(), &guide, &Default::default())
            .expect("plan");

        let out = Executor::new(&o, &s)
            .run("demo", &p)
            .await
            .expect("preview");
        assert_eq!(out.executed, p.actions.len());
        assert!(s.installed_apps().await.expect("apps").is_empty());
        assert!(s.plan_actions("demo").await.expect("journal").is_empty());
        assert!(s.pending_guides().await.expect("guides").is_empty());
        assert!(o.deployed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_preview_of_an_installed_app_changes_nothing() {
        let o = Fake::default();
        let s = State::in_memory().await.expect("state");
        let installed = manifest();
        s.upsert_app("demo", &installed, Some("x.example.fr"))
            .await
            .expect("app");
        let guide: hlb_types::Guide = serde_yaml_ng::from_str(WITH_PREREQUISITE).expect("guide");
        s.set_app_guide("demo", Some(&guide)).await.expect("frozen");
        let first = hlb_resolver::resolve_with_guide(&installed, &guide, &Default::default())
            .expect("plan");
        s.add_guide("demo", "account", "Open an account", true)
            .await
            .expect("guide");
        s.verify_guide("demo", "account").await.expect("verified");
        Executor::new(&o, &s)
            .apply(true)
            .run("demo", &first)
            .await
            .expect("installed");
        let journal = |s: &State| {
            let s = s.clone();
            async move {
                s.plan_actions("demo")
                    .await
                    .expect("journal")
                    .into_iter()
                    .map(|r| (r.seq, r.kind, r.description, r.status))
                    .collect::<Vec<_>>()
            }
        };
        let before = journal(&s).await;

        // The catalog moved on: no digest, one more replica.
        let mut catalog = manifest();
        catalog.spec.image.digest = None;
        catalog.spec.swarm.replicas = 3;
        // And its guide lost the prerequisite.
        let basis = install::basis(
            &s,
            "demo",
            install::Origin::default(),
            &catalog,
            &Default::default(),
            None,
            None,
        )
        .await
        .expect("read")
        .expect("resumable");
        assert_eq!(
            basis.guide.steps, guide.steps,
            "a rerun plans from the guide frozen with the app"
        );
        let yaml = |m: &hlb_types::Manifest| serde_yaml_ng::to_string(m).expect("yaml");
        assert_eq!(
            yaml(&basis.manifest),
            yaml(&installed),
            "a rerun plans from what is installed"
        );
        assert_eq!(basis.domain.as_deref(), Some("x.example.fr"));
        let p = hlb_resolver::resolve_with_guide(&basis.manifest, &guide, &Default::default())
            .expect("plan");
        let out = Executor::new(&o, &s)
            .run("demo", &p)
            .await
            .expect("preview");
        assert_eq!(out.skipped, p.actions.len(), "{out:?}");

        assert_eq!(
            yaml(&s.app_manifest("demo").await.expect("m")),
            yaml(&installed)
        );
        assert_eq!(
            s.app_domain("demo").await.expect("d").as_deref(),
            Some("x.example.fr")
        );
        assert_eq!(journal(&s).await, before);
        assert!(s.pending_guides().await.expect("guides").is_empty());

        // Even a preview of another plan — the catalog's — leaves the journal as it is.
        let other =
            hlb_resolver::resolve_with_guide(&catalog, &guide, &Default::default()).expect("plan");
        Executor::new(&o, &s)
            .run("demo", &other)
            .await
            .expect("preview");
        assert_eq!(journal(&s).await, before);

        let moved = install::basis(
            &s,
            "demo",
            install::Origin::default(),
            &catalog,
            &Default::default(),
            Some("y.example.fr".into()),
            None,
        )
        .await
        .expect("read");
        assert!(moved.is_err(), "another domain is not a resume: {moved:?}");

        // 🔴 `community/demo` installs as `demo`: it would take the official one's
        // services, volumes and databases over.
        let theirs = install::basis(
            &s,
            "demo",
            install::Origin {
                source: Some("community"),
                ..Default::default()
            },
            &catalog,
            &Default::default(),
            None,
            None,
        )
        .await
        .expect("read")
        .expect_err("another source's app of the same name");
        assert!(
            theirs.contains("installed from the official catalog")
                && theirs.contains("the source \"community\""),
            "{theirs}"
        );
    }

    #[tokio::test]
    async fn an_install_freezes_the_source_it_came_from() {
        // `state()` records the official "demo": this one is new.
        let s = state().await;
        let basis = install::basis(
            &s,
            "theirs",
            install::Origin {
                source: Some("community"),
                index: Some(7),
                version: Some("1.0.0+abc"),
            },
            &manifest(),
            &Default::default(),
            None,
            None,
        )
        .await
        .expect("read")
        .expect("a new app");
        install::record(&s, "theirs", &basis)
            .await
            .expect("recorded");
        assert_eq!(
            s.app_source("theirs").await.expect("source").as_deref(),
            Some("community")
        );
        let frozen = hlb_state::Release {
            index: Some(7),
            version: Some("1.0.0+abc".into()),
        };
        assert_eq!(s.app_release("theirs").await.expect("release"), frozen);
        // Resumed, it keeps its source; the official app of that name is refused.
        let again = install::basis(
            &s,
            "theirs",
            install::Origin {
                source: Some("community"),
                index: Some(7),
                version: Some("1.0.0+abc"),
            },
            &manifest(),
            &Default::default(),
            None,
            None,
        )
        .await
        .expect("read")
        .expect("resumed");
        assert_eq!(again.source.as_deref(), Some("community"));
        assert_eq!(
            again.release, frozen,
            "resumed, it keeps the release it came in"
        );
        let official = install::basis(
            &s,
            "theirs",
            install::Origin::default(),
            &manifest(),
            &Default::default(),
            None,
            None,
        )
        .await
        .expect("read");
        assert!(official.is_err(), "{official:?}");
    }

    #[tokio::test]
    async fn an_action_inserted_mid_plan_is_executed() {
        // 🔴 Matched by position, the inserted action landed on a done row and was
        // skipped: here, a secret the app would have been deployed without.
        let o = Fake::default();
        let s = state().await;
        let dir = tempfile::tempdir().expect("dir");
        let vault = Vault::init(dir.path().join("master.key")).expect("vault");
        let secret = |name: &str| Action::GenerateSecret {
            name: name.into(),
            purpose: "test".into(),
        };
        let exec = || Executor::new(&o, &s).with_vault(&vault).apply(true);
        let first = Plan {
            actions: vec![secret("demo-a"), secret("demo-c")],
        };
        exec().run("demo", &first).await.expect("first");

        let next = Plan {
            actions: vec![secret("demo-a"), secret("demo-b"), secret("demo-c")],
        };
        let out = exec().run("demo", &next).await.expect("next");
        assert_eq!((out.executed, out.skipped), (1, 2), "{out:?}");
        assert!(s.secret("demo-b").await.expect("read").is_some());
        assert!(s.plan_finished("demo").await.expect("read"));
    }

    #[tokio::test]
    async fn a_digest_lost_from_the_frozen_manifest_is_resolved_again() {
        // An image built here carries no digest in the catalog: frozen again after it
        // was resolved, the resolution was skipped as done and the deployment refused
        // as unpinned for good.
        let o = Fake::default();
        let s = State::in_memory().await.expect("state");
        let mut m = manifest();
        m.spec.image.digest = None;
        s.upsert_app("demo", &m, None).await.expect("app");
        let p = hlb_resolver::resolve(&m, &Default::default()).expect("plan");
        let records: Vec<(String, String)> = p
            .actions
            .iter()
            .map(|a| (kind_of(a).to_string(), a.to_string()))
            .collect();
        s.record_plan("demo", &records).await.expect("journal");
        let resolve = p
            .actions
            .iter()
            .position(|a| matches!(a, Action::ResolveDigest { .. }))
            .expect("a resolution");
        s.set_action_status("demo", resolve, ActionStatus::Done, None)
            .await
            .expect("done");

        // No registry here: re-running it is recorded, never skipped.
        let out = Executor::new(&o, &s)
            .run("demo", &p)
            .await
            .expect("preview");
        assert_eq!(out.skipped, 0, "{out:?}");
    }

    #[tokio::test]
    async fn the_secret_pocketid_made_replaces_the_placeholder_in_the_vault() {
        // 🔴 With no PocketID key the client was unimplemented and the plan's own
        // `GenerateSecret` stored a random placeholder; the client made later kept it
        // ("if absent"), and every sign-in ended in `invalid_client`.
        let s = State::in_memory().await.expect("state");
        let dir = tempfile::tempdir().expect("dir");
        let vault = Vault::init(dir.path().join("master.key")).expect("vault");
        s.store_secret_if_absent(
            "demo-oidc-secret",
            &vault.encrypt("placeholder").expect("ct"),
            "OIDC client secret",
        )
        .await
        .expect("placeholder");
        s.store_secret_if_absent(
            "demo-oidc-client-id",
            &vault.encrypt("old-id").expect("ct"),
            "OIDC client id",
        )
        .await
        .expect("old id");
        let read = |name: &'static str| {
            let (s, vault) = (s.clone(), &vault);
            async move {
                vault
                    .decrypt(&s.secret(name).await.expect("read").expect("kept"))
                    .expect("clear")
            }
        };

        let made = hlb_identity::Credentials {
            client_id: "new-id".into(),
            client_secret: Some("issued".into()),
        };
        keep_oidc_credentials(
            &s,
            &vault,
            "demo",
            &made,
            "demo-oidc-secret",
            "demo-oidc-client-id",
        )
        .await
        .expect("kept");
        assert_eq!(read("demo-oidc-secret").await, "issued");
        assert_eq!(read("demo-oidc-client-id").await, "new-id");

        // An existing client hands no secret back: the one held stays.
        let existing = hlb_identity::Credentials {
            client_id: "new-id".into(),
            client_secret: None,
        };
        keep_oidc_credentials(
            &s,
            &vault,
            "demo",
            &existing,
            "demo-oidc-secret",
            "demo-oidc-client-id",
        )
        .await
        .expect("kept");
        assert_eq!(read("demo-oidc-secret").await, "issued");
        // And with none held, it is said, never invented.
        let err = keep_oidc_credentials(&s, &vault, "demo", &existing, "other-secret", "other-id")
            .await
            .expect_err("nothing to keep");
        assert!(matches!(err, Error::MissingSecret(_)), "{err}");
    }

    #[tokio::test]
    async fn every_service_joins_the_platform_overlay_which_exists_first() {
        // The Swarm spec ignored `networks` until 2026-10-11, and nothing set it: every
        // service ran on no overlay at all, and no app could resolve `postgres`.
        let o = Fake::default();
        let s = state().await;
        Executor::new(&o, &s)
            .apply(true)
            .run("demo", &plan())
            .await
            .expect("run");

        let nets = o.deployed_networks.lock().unwrap().clone();
        assert!(!nets.is_empty());
        for (svc, n) in &nets {
            assert_eq!(
                n,
                &vec![hlb_orchestrator::PLATFORM_NETWORK.to_string()],
                "{svc}"
            );
        }
        assert!(o
            .ensured
            .lock()
            .unwrap()
            .contains(&hlb_orchestrator::PLATFORM_NETWORK.to_string()));
    }

    #[tokio::test]
    async fn the_arguments_and_process_planned_are_the_ones_deployed() {
        let o = Fake::default();
        let s = state().await;
        let mut p = plan();
        let process = hlb_types::Process {
            init: true,
            stop_grace_secs: Some(60),
            ..Default::default()
        };
        for a in &mut p.actions {
            if let Action::DeployService {
                args, process: p, ..
            } = a
            {
                *args = vec!["--port".into(), "3000".into()];
                *p = process.clone();
            }
        }
        Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .expect("run");
        let spec = o.deployed_specs.lock().unwrap().pop().expect("deployed");
        assert_eq!(spec.args, ["--port", "3000"]);
        assert_eq!(spec.process, process);
    }

    #[tokio::test]
    async fn apply_deploys_and_waits() {
        let o = Fake::default();
        let s = state().await;

        let out = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &plan())
            .await
            .expect("run");

        assert_eq!(*o.deployed.lock().unwrap(), vec!["demo"]);
        assert_eq!(*o.waited.lock().unwrap(), vec!["demo"]);
        assert!(out.is_success());
        assert_eq!(out.executed, 2, "deployment + wait");
    }

    #[tokio::test]
    async fn rerun_is_idempotent() {
        let o = Fake::default();
        let s = state().await;
        let p = plan();

        Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();
        let second = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .expect("second run");

        assert_eq!(
            o.deployed.lock().unwrap().len(),
            1,
            "the deployment must not be replayed"
        );
        assert_eq!(second.executed, 0);
        assert!(second.skipped >= 2);
    }

    #[tokio::test]
    async fn failure_stops_and_is_recorded() {
        let o = Fake {
            fail_deploy: true,
            ..Default::default()
        };
        let s = state().await;

        let out = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &plan())
            .await
            .expect("run");

        assert!(!out.is_success());
        assert!(
            o.waited.lock().unwrap().is_empty(),
            "we stop at the first failure"
        );

        let recorded = s.plan_actions("demo").await.unwrap();
        let failed = recorded
            .iter()
            .find(|a| a.status == ActionStatus::Failed)
            .expect("failure recorded");
        assert!(failed
            .error
            .as_deref()
            .unwrap()
            .contains("simulated failure"));
        assert_eq!(
            s.installed_apps().await.unwrap()[0].1,
            "failed",
            "the app is marked as failed"
        );
    }

    const WITH_DOWNLOAD: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  swarm: { tier: heavy }
  requires:
    - { kind: storage, name: config, path: /config, tier: local }
  downloads:
    - url: https://example.org/v1/plugin.zip
      sha256: "0000000000000000000000000000000000000000000000000000000000000000"
      storage: config
      into: plugins/plugin
      unzip: true
"#;

    #[tokio::test]
    async fn a_download_is_fetched_into_the_apps_volume_before_the_app_starts() {
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_DOWNLOAD).expect("manifest");
        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).expect("plan");
        let s = State::in_memory().await.expect("state");
        s.upsert_app("demo", &m, None).await.expect("upsert");
        let o = Fake::default();
        let out = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .expect("run");
        assert!(out.is_success(), "{out:?}");

        let jobs = o.jobs.lock().expect("mutex").clone();
        assert_eq!(jobs.len(), 1, "{jobs:?}");
        let job = &jobs[0];
        // The app's volume, where the app mounts it from; the app's placement.
        assert_eq!(job.mounts[0].0, "demo-config");
        assert_eq!(job.backing_of("demo-config"), VolumeBacking::Docker);
        let app = o
            .deployed_specs
            .lock()
            .expect("mutex")
            .iter()
            .find(|d| d.name == "demo")
            .cloned()
            .expect("the app deployed");
        assert_eq!(job.constraints, app.constraints);
        assert!(job
            .command
            .iter()
            .any(|a| a == "https://example.org/v1/plugin.zip"));
        // Its hash is in the task's own environment: a new one restarts the app.
        assert!(app
            .env
            .iter()
            .any(|(k, v)| k == hlb_types::manifest::DOWNLOADS_ENV && *v == "0".repeat(64)));

        // A fetch refused stops the install before the app starts on what it lacks.
        let s = State::in_memory().await.expect("state");
        s.upsert_app("demo", &m, None).await.expect("upsert");
        let refusing = Fake {
            fail_jobs: true,
            ..Default::default()
        };
        let out = Executor::new(&refusing, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .expect("run");
        assert!(!out.is_success());
        assert!(refusing.deployed.lock().expect("mutex").is_empty());
    }

    #[tokio::test]
    async fn resume_picks_up_after_the_failure() {
        let s = state().await;
        let p = plan();

        // First pass: fails at deployment.
        let failing = Fake {
            fail_deploy: true,
            ..Default::default()
        };
        Executor::new(&failing, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        // Second pass, orchestrator repaired.
        let ok = Fake::default();
        let out = Executor::new(&ok, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        assert!(out.is_success());
        assert_eq!(*ok.deployed.lock().unwrap(), vec!["demo"]);
    }

    #[tokio::test]
    async fn unimplemented_is_never_reported_as_done() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_DB).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();
        let out = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        assert!(out.unimplemented >= 2, "database + secret unimplemented");
        assert_eq!(s.installed_apps().await.unwrap()[0].1, "partial");

        // And above all: nothing is wrongly marked `done`.
        let recorded = s.plan_actions("demo").await.unwrap();
        let db = recorded
            .iter()
            .find(|a| a.kind == "ProvisionDatabase")
            .expect("action present");
        assert_eq!(db.status, ActionStatus::Unimplemented);
    }

    const WITH_MAIL: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  requires:
    - kind: mail-account
"#;

    #[tokio::test]
    async fn an_app_finally_learns_where_its_database_is() {
        // 🔴 THE defect this test guards: the resolver created the database, the
        // isolated role and the password - then deployed the app SAYING NOTHING TO IT.
        // It fell back to its internal SQLite. Healthy service, green probe, green
        // dashboard, and the data in a file nobody backed up while an empty database
        // was faithfully dumped every night.
        const WITH_BINDING: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: acme/demo, tag: "1.0", digest: "sha256:abc" }
  requires:
    - kind: database
      engine: postgres
  env:
    DB_HOST: "{{ db.host }}"
    DB_NAME: "{{ db.name }}"
    DB_USER: "{{ db.user }}"
    DB_PASSWORD: "{{ db.password }}"
    DB_URL: "postgres://{{ db.user }}:{{ db.password }}@{{ db.host }}/{{ db.name }}"
"#;
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_BINDING).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let p = hlb_resolver::resolve(&m, &Default::default()).unwrap();

        // 🔴 The PLAN must carry only the token. It is displayed by `hlb plan`,
        // recorded in the state and exported to the Git mirror: a password substituted
        // here would be published in all three, one of which keeps history.
        let plan_text = p
            .actions
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !plan_text.contains("postgres://demo:"),
            "the plan must never carry resolved credentials: {plan_text}"
        );

        Executor::new(&o, &s)
            .with_vault(&vault)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        // What reaches Swarm, on the other hand, must be RESOLVED.
        let deployments = o.deployed_env.lock().unwrap().clone();
        let (_, env) = deployments
            .iter()
            .find(|(n, _)| n == "demo")
            .expect("demo deployed");
        let table: std::collections::BTreeMap<&str, &str> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        assert_eq!(table.get("DB_HOST"), Some(&"postgres"));
        assert_eq!(table.get("DB_NAME"), Some(&"demo"));
        assert_eq!(table.get("DB_USER"), Some(&"demo"));

        let password = table.get("DB_PASSWORD").expect("password passed through");
        assert!(!password.contains("{{"), "unresolved token: {password}");
        assert!(password.len() >= 16, "password too short: {password}");

        // And the composite URL must carry the SAME password, not another draw.
        let url = table.get("DB_URL").expect("URL transmise");
        assert_eq!(*url, format!("postgres://demo:{password}@postgres/demo"));
    }

    #[tokio::test]
    async fn several_databases_share_one_role() {
        // 🔴 Seafile wants THREE databases and connects with ONE account. Naming the
        // role after the database would produce three accounts for one credential set,
        // and the app would fail on two of them - on an authentication error that would
        // not say which.
        const THREE: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: seafile }
spec:
  image: { repo: acme/seafile, tag: "1.0", digest: "sha256:abc" }
  requires:
    - kind: database
      engine: mariadb
      name: ccnet_db
    - kind: database
      engine: mariadb
      name: seafile_db
    - kind: database
      engine: mariadb
      name: seahub_db
  env:
    DB_PASSWORD: "{{ db.password }}"
"#;
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(THREE).unwrap();
        let p = hlb_resolver::resolve(&m, &Default::default()).unwrap();

        let roles: Vec<&str> = p
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::ProvisionDatabase { role, .. } => Some(role.as_str()),
                _ => None,
            })
            .collect();

        assert_eq!(
            roles,
            vec!["seafile", "seafile", "seafile"],
            "a single role"
        );

        let bases: Vec<&str> = p
            .actions
            .iter()
            .filter_map(|a| match a {
                Action::ProvisionDatabase { database, .. } => Some(database.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            bases,
            vec!["ccnet_db", "seafile_db", "seahub_db"],
            "trois bases"
        );

        // ⚠️ One role means one password: three identical generations would clutter
        // the plan and the state without changing anything.
        let secrets = p
            .actions
            .iter()
            .filter(|a| matches!(a, Action::GenerateSecret { name, .. } if name.ends_with("-db-password")))
            .count();
        assert_eq!(secrets, 1, "one password for one role");
    }

    #[tokio::test]
    async fn an_unresolvable_token_stays_visible_instead_of_becoming_empty() {
        // 🔴 Without a vault the password cannot be read. The token must stay LITERAL
        // rather than become an empty string: an empty variable looks like missing
        // configuration, and the app would complain about an incorrect password - you
        // would look at the password for a long time.
        const M: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: acme/demo, tag: "1.0", digest: "sha256:abc" }
  requires:
    - kind: database
      engine: postgres
  env:
    DB_PASSWORD: "{{ db.password }}"
    DB_HOST: "{{ db.host }}"
"#;
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(M).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let p = hlb_resolver::resolve(&m, &Default::default()).unwrap();
        // No `.with_vault(...)`: no secret is readable.
        Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        let deployments = o.deployed_env.lock().unwrap().clone();
        let (_, env) = deployments
            .iter()
            .find(|(n, _)| n == "demo")
            .expect("deployed");
        let table: std::collections::BTreeMap<&str, &str> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        assert_eq!(
            table.get("DB_PASSWORD"),
            Some(&"{{ db.password }}"),
            "an unresolved token must stay visible, never become empty"
        );
        // What is knowable without a vault still is: the host depends on no secret,
        // and hiding it would help nobody.
        assert_eq!(table.get("DB_HOST"), Some(&"postgres"));
    }

    #[tokio::test]
    async fn a_companions_host_is_filled_in_where_it_is_the_only_token() {
        // 🔴 Companion and S3 tokens sit outside `Token`: a shortcut taken when no
        // `Token` and no secret was used sent Fluxer's app `{{ companion.api.host }}`
        // as written, and Swarm refused the service ("function companion not defined").
        const M: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: acme/demo, tag: "1.0", digest: "sha256:abc" }
  requires:
    - kind: object-storage
  env:
    UPSTREAM: "http://{{ companion.api.host }}:8080"
  companions:
    - name: api
      image: { repo: acme/api, tag: "1.0", digest: "sha256:def" }
      env:
        BUCKET: "{{ s3.bucket }}"
"#;
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(M).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let p = hlb_resolver::resolve(&m, &Default::default()).unwrap();
        Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        let deployments = o.deployed_env.lock().unwrap().clone();
        let env_of = |service: &str| -> Vec<(String, String)> {
            deployments
                .iter()
                .find(|(n, _)| n == service)
                .map(|(_, e)| e.clone())
                .expect("deployed")
        };
        assert_eq!(
            env_of("demo"),
            vec![("UPSTREAM".into(), "http://demo-api:8080".into())]
        );
        assert_eq!(env_of("demo-api"), vec![("BUCKET".into(), "demo".into())]);
    }

    #[tokio::test]
    async fn a_mailbox_is_never_pretended_without_a_stalwart() {
        // 🔴 Same principle as for the database: without a Stalwart client the action
        // is recorded as "unimplemented", never "done". Reporting a mailbox that does
        // not exist would make the app fail on its first send.
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_MAIL).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let params = hlb_resolver::InstallParams {
            mail_domain: Some("example.fr".into()),
            ..Default::default()
        };
        let p = hlb_resolver::resolve(&m, &params).unwrap();

        Executor::new(&o, &s)
            .with_vault(&vault)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        let rec = s.plan_actions("demo").await.unwrap();
        let mail = rec
            .iter()
            .find(|a| a.kind == "ProvisionMailAccount")
            .expect("action present");
        assert_eq!(mail.status, ActionStatus::Unimplemented);

        // And no password was manufactured: it would have matched nothing.
        assert!(s.secret("demo-mail-password").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn secrets_need_a_vault_and_are_never_faked() {
        // Without a vault, secret generation is "unimplemented", never "done".
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_DB).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();
        Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        let rec = s.plan_actions("demo").await.unwrap();
        let secret = rec.iter().find(|a| a.kind == "GenerateSecret").unwrap();
        assert_eq!(secret.status, ActionStatus::Unimplemented);
        assert!(s.secret("demo-db-password").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn the_oidc_client_id_is_the_one_pocketid_generated() {
        const WITH_SSO: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: grafana }
spec:
  image: { repo: grafana/grafana, tag: "11", digest: "sha256:abc" }
  requires:
    - kind: sso
      mode: native
      redirectPaths: ["/login/generic_oauth"]
  env:
    CLIENT_ID: "{{ oidc.client_id }}"
  files:
    - path: /etc/app/oidc.yml
      content: "clientid: {{ oidc.client_id }}"
"#;
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_SSO).unwrap();
        s.upsert_app("grafana", &m, Some("graphs.example.org"))
            .await
            .unwrap();
        // What `CreateOidcClient` stores: PocketID's own id, never the app's name.
        s.store_secret_if_absent(
            "grafana-oidc-client-id",
            &vault.encrypt("88e0-c62d").unwrap(),
            "x",
        )
        .await
        .unwrap();
        let p = hlb_resolver::resolve(
            &m,
            &hlb_resolver::InstallParams {
                domain: Some("graphs.example.org".into()),
                ..Default::default()
            },
        )
        .unwrap();
        Executor::new(&o, &s)
            .with_vault(&vault)
            .apply(true)
            .run("grafana", &p)
            .await
            .unwrap();
        let deployments = o.deployed_env.lock().unwrap().clone();
        let (_, env) = deployments
            .iter()
            .find(|(n, _)| n == "grafana")
            .expect("deployed");
        let id = env
            .iter()
            .find(|(k, _)| k == "CLIENT_ID")
            .map(|(_, v)| v.as_str());
        assert_eq!(id, Some("88e0-c62d"));
        // A file takes its tokens like a variable: Vikunja's providers live in one.
        let spec = o.deployed_specs.lock().unwrap().pop().expect("deployed");
        assert_eq!(
            spec.files,
            vec![(
                "/etc/app/oidc.yml".to_string(),
                "clientid: 88e0-c62d".to_string()
            )]
        );
    }

    const SENDS_MAIL: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: vikunja }
spec:
  image: { repo: vikunja/vikunja, tag: "0.24", digest: "sha256:abc" }
  requires:
    - kind: smtp
  env:
    MAILER_HOST: "{{ smtp.host }}"
    MAILER_PORT: "{{ smtp.port }}"
    MAILER_USERNAME: "{{ smtp.user }}"
    MAILER_PASSWORD: "{{ smtp.password }}"
    MAILER_FROM: "{{ smtp.from }}"
"#;

    /// Runs [`SENDS_MAIL`]'s plan with a vault and no Stalwart access.
    async fn send_mail_without_stalwart(o: &Fake, s: &State, vault: &Vault) {
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(SENDS_MAIL).unwrap();
        s.upsert_app("vikunja", &m, Some("tasks.example.fr"))
            .await
            .unwrap();
        let p = hlb_resolver::resolve(
            &m,
            &hlb_resolver::InstallParams {
                domain: Some("tasks.example.fr".into()),
                mail_domain: Some("example.fr".into()),
                ..Default::default()
            },
        )
        .unwrap();
        Executor::new(o, s)
            .with_vault(vault)
            .apply(true)
            .run("vikunja", &p)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_sending_account_nobody_could_make_is_never_done() {
        let (o, s) = (Fake::default(), State::in_memory().await.unwrap());
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();
        send_mail_without_stalwart(&o, &s, &vault).await;
        let account = s
            .plan_actions("vikunja")
            .await
            .unwrap()
            .into_iter()
            .find(|a| a.kind == "ProvisionSmtpAccount")
            .expect("the account is planned");
        assert_eq!(account.status, hlb_state::ActionStatus::Unimplemented);
        // And nothing hands out an address no account holds.
        let (_, env) = o.deployed_env.lock().unwrap().pop().expect("deployed");
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("MAILER_USERNAME").as_deref(), Some("{{ smtp.user }}"));
    }

    /// 🔴 Handed out until 2026-10-18: port 587, which Stalwart did not open, and the
    /// app's NAME as its login, which Stalwart refuses.
    #[tokio::test]
    async fn an_app_sends_on_587_as_the_address_that_was_tried() {
        let (o, s) = (Fake::default(), State::in_memory().await.unwrap());
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();
        // What `ProvisionSmtpAccount` stores once the account passed its trial.
        s.store_secret_if_absent(
            "vikunja-smtp-address",
            &vault.encrypt("vikunja@example.fr").unwrap(),
            "x",
        )
        .await
        .unwrap();
        send_mail_without_stalwart(&o, &s, &vault).await;
        let (_, env) = o.deployed_env.lock().unwrap().pop().expect("deployed");
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("MAILER_HOST").as_deref(), Some("stalwart"));
        assert_eq!(get("MAILER_PORT").as_deref(), Some("587"));
        assert_eq!(
            get("MAILER_USERNAME").as_deref(),
            Some("vikunja@example.fr")
        );
        assert_eq!(get("MAILER_FROM").as_deref(), Some("vikunja@example.fr"));
        let password = get("MAILER_PASSWORD").expect("a password");
        assert!(!password.contains("{{"), "the generated one: {password}");
    }

    #[tokio::test]
    async fn an_app_sending_mail_trusts_homelabus_root_and_no_other_does() {
        let (o, s) = (Fake::default(), State::in_memory().await.unwrap());
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();
        let j = serde_json::json!({ "cert": trust::ISRG_ROOT_X1, "key": "KEY" });
        s.store_secret_if_absent(
            ingress::ROOT_SECRET,
            &vault.encrypt(&j.to_string()).unwrap(),
            "x",
        )
        .await
        .unwrap();
        send_mail_without_stalwart(&o, &s, &vault).await;
        let spec = o.deployed_specs.lock().unwrap().pop().expect("deployed");
        assert!(
            spec.files
                .iter()
                .any(|(p, c)| p == "/run/hlb/trust/4042bcee.0" && c == trust::ISRG_ROOT_X1),
            "{:?}",
            spec.files
        );
        // Never its key.
        assert!(!spec.files.iter().any(|(_, c)| c.contains("KEY")));

        install(&o, &s, PUBLIC, Some("demo.example.fr")).await;
        let spec = o.deployed_specs.lock().unwrap().pop().expect("deployed");
        assert!(spec.files.is_empty(), "{:?}", spec.files);
    }

    #[tokio::test]
    async fn a_generated_secret_reaches_the_service_and_never_the_plan() {
        const WITH_SECRETS: &str = r#"
apiVersion: hlb/v1
kind: PlatformService
metadata: { name: pg }
spec:
  image: { repo: postgres, tag: "17", digest: "sha256:abc" }
  env:
    POSTGRES_PASSWORD: "{{ secret.admin-password }}"
    RPC: "{{ secret.admin-password:hex }}"
"#;
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_SECRETS).unwrap();
        s.upsert_app("pg", &m, None).await.unwrap();
        let p = hlb_resolver::resolve(&m, &Default::default()).unwrap();

        Executor::new(&o, &s)
            .with_vault(&vault)
            .apply(true)
            .run("pg", &p)
            .await
            .unwrap();

        let stored = vault
            .decrypt(
                &s.secret("pg-admin-password")
                    .await
                    .unwrap()
                    .expect("generated"),
            )
            .unwrap();
        let deployments = o.deployed_env.lock().unwrap().clone();
        let (_, env) = deployments
            .iter()
            .find(|(n, _)| n == "pg")
            .expect("deployed");
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("POSTGRES_PASSWORD"), Some(stored.clone()));
        let rpc = get("RPC").expect("rpc");
        assert_eq!(rpc.len(), 64);
        assert_ne!(rpc, stored);
        assert!(!p.actions.iter().any(|a| a.to_string().contains(&stored)));
    }

    #[tokio::test]
    async fn with_a_vault_the_secret_is_generated_and_encrypted() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_DB).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();
        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();

        Executor::new(&o, &s)
            .with_vault(&vault)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        let ct = s
            .secret("demo-db-password")
            .await
            .unwrap()
            .expect("secret stored");
        let clear = vault.decrypt(&ct).expect("decryptable");
        assert_eq!(clear.len(), hlb_secrets::DEFAULT_PASSWORD_LEN);
        assert!(clear.chars().all(|c| c.is_ascii_alphanumeric()));

        // Provisioning stays unimplemented: no PostgreSQL supplied.
        let rec = s.plan_actions("demo").await.unwrap();
        let db = rec.iter().find(|a| a.kind == "ProvisionDatabase").unwrap();
        assert_eq!(db.status, ActionStatus::Unimplemented);
    }

    #[tokio::test]
    async fn a_replay_does_not_change_an_existing_password() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_DB).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();
        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();

        let exec = || Executor::new(&o, &s).with_vault(&vault).apply(true);
        exec().run("demo", &p).await.unwrap();
        let first = s.secret("demo-db-password").await.unwrap().unwrap();

        // A replay is forced by clearing the progress.
        s.set_action_status("demo", 0, ActionStatus::Pending, None)
            .await
            .unwrap();
        exec().run("demo", &p).await.unwrap();
        let second = s.secret("demo-db-password").await.unwrap().unwrap();

        assert_eq!(
            first, second,
            "the password must not change under the service's feet"
        );
    }

    #[tokio::test]
    async fn a_post_install_step_holds_back_the_route_not_the_install() {
        // 🔴 "Check the administrator and close sign-ups" can only be done once the app
        // runs. Blocking the install on it made every such app impossible until
        // someone attested, beforehand, work not yet doable.
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        exposed(&s).await;
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_GUIDE).unwrap();
        s.upsert_app("demo", &m, Some("x.example.fr"))
            .await
            .unwrap();
        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();

        let out = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .expect("run");
        assert!(out.is_success());
        assert_eq!(*o.deployed.lock().unwrap(), vec!["demo"]);
        assert_eq!(s.pending_guides().await.unwrap().len(), 1, "still to do");
        let caddyfile = &written(&o)[0];
        assert!(
            caddyfile.contains("@external_x_example_fr"),
            "private until then:\n{caddyfile}"
        );
    }

    #[tokio::test]
    async fn a_prerequisite_prevents_apply_until_it_is_handled() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let m = manifest();
        s.upsert_app("demo", &m, None).await.unwrap();
        let guide: hlb_types::Guide = serde_yaml_ng::from_str(
            r#"
steps:
  - id: account
    title: Open an account at the provider
    phase: pre-install
    severity: blocking
    verify:
      type: attest
"#,
        )
        .unwrap();
        let p = hlb_resolver::resolve_with_guide(&m, &guide, &Default::default()).unwrap();
        let err = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::BlockedByGuide { blocking: 1 }),
            "{err}"
        );
        assert!(
            o.deployed.lock().unwrap().is_empty(),
            "nothing deployed before it"
        );

        s.verify_guide("demo", "account").await.unwrap();
        let out = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .expect("run");
        assert!(out.is_success());
        assert_eq!(*o.deployed.lock().unwrap(), vec!["demo"]);
    }

    const PUBLIC: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  ingress:
    - host: "{{ domain }}"
      port: 80
      expose: public
"#;

    async fn exposed(s: &State) {
        s.set_exposure(&hlb_state::Exposure {
            domain: "example.fr".into(),
            certificates: hlb_state::Certificates::Internal,
            acme_email: None,
            dns_provider: None,
            staging: false,
            controller_host: None,
            acme_ca: None,
            acme_ca_root: None,
        })
        .await
        .expect("exposure");
    }

    async fn install(o: &Fake, s: &State, yaml: &str, domain: Option<&str>) -> Outcome {
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(yaml).expect("manifest");
        s.upsert_app(&m.metadata.name, &m, domain)
            .await
            .expect("upsert");
        let p = hlb_resolver::resolve(
            &m,
            &hlb_resolver::InstallParams {
                domain: domain.map(str::to_string),
                ..Default::default()
            },
        )
        .expect("plan");
        Executor::new(o, s)
            .apply(true)
            .run(&m.metadata.name, &p)
            .await
            .expect("run")
    }

    async fn app_status(s: &State, app: &str) -> Option<String> {
        s.installed_apps()
            .await
            .unwrap()
            .into_iter()
            .find(|(n, _)| n == app)
            .map(|(_, st)| st)
    }

    /// The Caddyfiles the writer jobs carried, in order.
    fn written(o: &Fake) -> Vec<String> {
        o.jobs
            .lock()
            .unwrap()
            .iter()
            .flat_map(|j| j.files.iter().map(|(_, c)| c.clone()))
            .collect()
    }

    #[tokio::test]
    async fn an_app_signing_in_natively_trusts_the_private_root_and_no_other_does() {
        const NATIVE: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  requires:
    - kind: sso
      mode: native
      redirectPaths: ["/cb"]
  env:
    CLIENT_ID: "{{ oidc.client_id }}"
  companions:
    # Fluxer's api is a companion, and it is what fetches the issuer.
    - name: api
      image: { repo: a/api, tag: "1", digest: "sha256:y" }
      command: [node, /run/start.mjs]
      files:
        - { path: /run/sso.json, content: '{"origin":"https://{{ domain }}"}' }
"#;
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        s.set_exposure(&hlb_state::Exposure {
            domain: "example.fr".into(),
            certificates: hlb_state::Certificates::Acme,
            acme_email: Some("a@example.fr".into()),
            dns_provider: None,
            staging: false,
            controller_host: None,
            acme_ca: Some("https://ca.example.fr/acme/acme/directory".into()),
            acme_ca_root: Some(trust::ISRG_ROOT_X1.into()),
        })
        .await
        .expect("exposure");

        install(&o, &s, NATIVE, Some("demo.example.fr")).await;
        let specs = o.deployed_specs.lock().unwrap().clone();
        for name in ["demo", "demo-api"] {
            let spec = specs
                .iter()
                .rfind(|s| s.name == name)
                .unwrap_or_else(|| panic!("{name} deployed"));
            assert!(
                spec.files
                    .iter()
                    .any(|(p, c)| p == "/run/hlb/trust/4042bcee.0" && c == trust::ISRG_ROOT_X1),
                "{name}: {:?}",
                spec.files
            );
            assert!(
                spec.env.contains(&(
                    "SSL_CERT_DIR".into(),
                    "/etc/ssl/certs:/run/hlb/trust".into()
                )),
                "{name}"
            );
        }
        // The companion's own command and file reached Swarm, the file's token filled.
        let api = specs.iter().rfind(|s| s.name == "demo-api").expect("api");
        assert_eq!(api.command, ["node", "/run/start.mjs"]);
        assert!(
            api.files.iter().any(
                |(p, c)| p == "/run/sso.json" && c == r#"{"origin":"https://demo.example.fr"}"#
            ),
            "{:?}",
            api.files
        );

        // An app that verifies no issuer is given no root.
        install(&o, &s, PUBLIC, Some("demo.example.fr")).await;
        let spec = o.deployed_specs.lock().unwrap().pop().expect("deployed");
        assert!(spec.files.is_empty(), "{:?}", spec.files);
        assert!(!spec.env.iter().any(|(k, _)| k == "SSL_CERT_DIR"));
    }

    #[tokio::test]
    async fn an_apps_administrators_follow_their_roles_by_command_in_its_companion() {
        const CHAT: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: chat }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  requires:
    - { kind: sso, mode: native, redirectPaths: [/cb] }
  env: { ID: "{{ oidc.client_id }}" }
  companions:
    - { name: api, image: { repo: a/api, tag: "1" } }
  access:
    admins:
      level: admin
      means: the instance
      apply:
        service: api
        grant: [node, /run/admin.mjs, grant, "{{ person.sub }}"]
        revoke: [node, /run/admin.mjs, revoke, "{{ person.sub }}"]
"#;
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().expect("tmp");
        let vault = hlb_secrets::Vault::init(dir.path().join("k.key")).expect("vault");
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(CHAT).expect("manifest");
        s.upsert_app("chat", &m, Some("chat.example.fr"))
            .await
            .expect("app");
        for (id, level) in [
            ("family", hlb_types::Role::User),
            ("owners", hlb_types::Role::Admin),
        ] {
            let r = hlb_users::RoleDef::new(id, level, hlb_users::MailLimits::standard());
            s.put_role(&r, "test").await.expect("role");
            s.allow_role("chat", id, "test").await.expect("allowed");
        }
        s.upsert_user("ada", "owners", Some("sub-ada"))
            .await
            .expect("ada");
        s.upsert_user("bob", "family", Some("sub-bob"))
            .await
            .expect("bob");
        let reach = |u: &str| u.to_string();
        let http = hlb_guide::HttpApi::default();
        let sync = |now| roles::RoleSync {
            state: &s,
            vault: &vault,
            orchestrator: &o,
            reach: &reach,
            http: &http,
            now,
        };
        let execs = || o.execs.lock().expect("mutex").clone();

        sync(1_000).run(true).await.expect("sync");
        // Ada is made one, in the companion; Bob, never one, costs no command.
        assert_eq!(
            execs(),
            [(
                "chat-api".to_string(),
                ["node", "/run/admin.mjs", "grant", "sub-ada"]
                    .map(String::from)
                    .to_vec()
            )]
        );
        // The same day: nothing again.
        sync(2_000).run(true).await.expect("sync");
        assert_eq!(execs().len(), 1);

        // Her role lowered: the right is taken back.
        s.set_user_role("ada", "family", None)
            .await
            .expect("lowered");
        sync(3_000).run(true).await.expect("sync");
        assert_eq!(
            execs().last().map(|(_, c)| c.clone()),
            Some(
                ["node", "/run/admin.mjs", "revoke", "sub-ada"]
                    .map(String::from)
                    .to_vec()
            )
        );
    }

    /// Jellyfin as its SSO plugin leaves it: three accounts linked to PocketID
    /// identities, one administrator linked to none — and a password it may refuse.
    struct Accounts {
        sent: Mutex<Vec<Sent>>,
        refuse: bool,
        disabled: Mutex<std::collections::BTreeMap<String, bool>>,
    }

    impl Accounts {
        fn new(refuse: bool) -> Self {
            let disabled = [
                ("acc-ada", true),
                ("acc-bob", false),
                ("acc-gone", false),
                ("acc-admin", false),
            ]
            .map(|(a, d)| (a.to_string(), d))
            .into();
            Self {
                sent: Mutex::default(),
                refuse,
                disabled: Mutex::new(disabled),
            }
        }
        fn writes(&self) -> Vec<(String, String)> {
            self.sent
                .lock()
                .expect("mutex")
                .iter()
                .filter(|(k, _, _)| k.starts_with("POST") && k.ends_with("/Policy"))
                .map(|(k, _, b)| (k.clone(), b.clone()))
                .collect()
        }
        fn sign_ins(&self) -> usize {
            let sent = self.sent.lock().expect("mutex");
            sent.iter()
                .filter(|(k, _, _)| k.ends_with("/signin"))
                .count()
        }
    }

    #[async_trait]
    impl hlb_guide::ApiClient for Accounts {
        async fn call(
            &self,
            verb: &str,
            url: &str,
            headers: &[(String, String)],
            body: Option<&str>,
        ) -> std::result::Result<(u16, String), String> {
            let key = format!("{verb} {url}");
            self.sent.lock().expect("mutex").push((
                key.clone(),
                headers.to_vec(),
                body.unwrap_or("").into(),
            ));
            let path = url.trim_start_matches("http://jellyfin:8096");
            if path == "/signin" {
                return Ok(if self.refuse {
                    (401, String::new())
                } else {
                    (200, r#"{"AccessToken":"tok-1"}"#.into())
                });
            }
            if headers != [("Authorization".to_string(), "Token=tok-1".to_string())] {
                return Ok((401, String::new()));
            }
            let mut disabled = self.disabled.lock().expect("mutex");
            Ok(match (verb, path) {
                ("GET", "/Plugins/sso/Configuration") => (
                    200,
                    r#"{"OidConfigs":{"PocketID":{"CanonicalLinks":
                        {"sub-ada":"acc-ada","sub-bob":"acc-bob","sub-gone":"acc-gone"}}}}"#
                        .into(),
                ),
                ("GET", p) if p.starts_with("/Users/") => {
                    let id = p.trim_start_matches("/Users/");
                    let d = disabled.get(id).copied().unwrap_or_default();
                    (
                        200,
                        format!(
                            r#"{{"Id":"{id}","Policy":{{"IsDisabled":{d},"EnableAllFolders":true}}}}"#
                        ),
                    )
                }
                ("POST", p) if p.ends_with("/Policy") => {
                    let id = p.trim_start_matches("/Users/").trim_end_matches("/Policy");
                    let v: serde_json::Value =
                        serde_json::from_str(body.unwrap_or("")).expect("a policy");
                    disabled.insert(id.into(), v["IsDisabled"] == true);
                    (204, String::new())
                }
                _ => (404, String::new()),
            })
        }
    }

    #[tokio::test]
    async fn an_account_is_enabled_while_its_person_holds_a_role_let_in() {
        const JELLYFIN: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: jellyfin }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  requires:
    - { kind: sso, mode: native, redirectPaths: [/cb] }
  env: { ID: "{{ oidc.client_id }}" }
  ingress:
    - { host: x.example.fr, port: 8096 }
  recovery:
    - secret: admin-password
      username: admin
      proof: { path: /signin, body: '{"u":"{{ username }}","p":"{{ password }}"}', pointer: /AccessToken }
  access:
    accounts:
      apply:
        type: http
        signIn: admin-password
        headers: { Authorization: "Token={{ token }}" }
        links: { path: /Plugins/sso/Configuration, pointer: /OidConfigs/PocketID/CanonicalLinks }
        read: { path: "/Users/{{ account }}", pointer: /Policy }
        disabled: /IsDisabled
        write: { verb: POST, path: "/Users/{{ account }}/Policy" }
"#;
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().expect("tmp");
        let vault = hlb_secrets::Vault::init(dir.path().join("k.key")).expect("vault");
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(JELLYFIN).expect("manifest");
        hlb_types::validate(&m).expect("a valid manifest");
        s.upsert_app("jellyfin", &m, Some("x.example.fr"))
            .await
            .expect("app");
        s.store_secret_if_absent(
            "jellyfin-admin-password",
            &vault.encrypt("pw").expect("enc"),
            "test",
        )
        .await
        .expect("stored");
        for id in ["family", "guests"] {
            let r = hlb_users::RoleDef::new(
                id,
                hlb_types::Role::User,
                hlb_users::MailLimits::standard(),
            );
            s.put_role(&r, "test").await.expect("role");
        }
        s.allow_role("jellyfin", "family", "test")
            .await
            .expect("allowed");
        s.upsert_user("ada", "family", Some("sub-ada"))
            .await
            .expect("ada");
        s.upsert_user("bob", "guests", Some("sub-bob"))
            .await
            .expect("bob");
        async fn run(
            s: &State,
            vault: &hlb_secrets::Vault,
            o: &Fake,
            http: &Accounts,
            apply: bool,
        ) -> roles::Report {
            roles::RoleSync {
                state: s,
                vault,
                orchestrator: o,
                reach: &|u: &str| u.to_string(),
                http,
                now: 1_000,
            }
            .run(apply)
            .await
            .expect("sync")
        }
        let sync = |http, apply| run(&s, &vault, &o, http, apply);

        let api = Accounts::new(false);
        let preview = sync(&api, false).await;
        assert!(api.writes().is_empty(), "a preview writes nothing");
        let said: Vec<(String, String)> = preview
            .lines
            .iter()
            .filter(|l| l.subject.ends_with(" in jellyfin"))
            .map(|l| (l.subject.clone(), l.change.clone()))
            .collect();
        assert_eq!(
            said,
            [
                ("ada in jellyfin", "enabled again: a role let in"),
                ("bob in jellyfin", "disabled: no role let in"),
                (
                    "PocketID id sub-gone, no longer in Homelabus in jellyfin",
                    "disabled: no role let in"
                ),
            ]
            .map(|(a, b)| (a.to_string(), b.to_string()))
        );

        sync(&api, true).await;
        let writes = api.writes();
        assert_eq!(writes.len(), 3, "{writes:?}");
        // 🔴 The whole policy goes back, the flag changed: Jellyfin resets what is not
        // sent — Ada would have lost every library.
        assert!(
            writes.contains(&(
                "POST http://jellyfin:8096/Users/acc-ada/Policy".into(),
                r#"{"EnableAllFolders":true,"IsDisabled":false}"#.into()
            )),
            "{writes:?}"
        );
        let state = api.disabled.lock().expect("mutex").clone();
        assert!(!state["acc-ada"], "enabled again");
        assert!(state["acc-bob"] && state["acc-gone"]);
        assert!(!state["acc-admin"], "linked to nobody: never touched");
        assert!(
            !api.sent
                .lock()
                .expect("mutex")
                .iter()
                .any(|(k, _, _)| k.contains("acc-admin")),
            "not even read"
        );
        // In step: nothing written again.
        sync(&api, true).await;
        assert_eq!(api.writes().len(), 3);

        // 🔴 A refused password is recorded as the nightly proof records it, and not
        // tried again: Jellyfin disables its administrator after five.
        let refusing = Accounts::new(true);
        let r = sync(&refusing, true).await;
        assert!(r.failed(), "{:?}", r.lines);
        let readings = s.assertion_results().await.expect("read");
        assert!(
            readings.iter().any(|(a, r)| a == "jellyfin"
                && r.id == "recovery:admin-password"
                && r.verdict == hlb_api::assertions::Verdict::Broken),
            "{readings:?}"
        );
        let r = sync(&refusing, true).await;
        assert_eq!(refusing.sign_ins(), 1, "never signed in again");
        assert!(
            r.lines.iter().any(|l| l.subject == "jellyfin"
                && matches!(l.outcome, roles::Outcome::NotConfigured(_))),
            "{:?}",
            r.lines
        );
    }

    #[tokio::test]
    async fn a_declared_command_replaces_the_images_entrypoint() {
        // Gitea's sign-in is written by the script this runs: a command left on the
        // floor deploys Gitea with none.
        const STARTED: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  command: [/usr/bin/entrypoint, bash, /run/start.sh]
  files:
    - path: /run/start.sh
      content: exec demo
"#;
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        install(&o, &s, STARTED, None).await;
        let spec = o.deployed_specs.lock().unwrap().pop().expect("deployed");
        assert_eq!(
            spec.command,
            ["/usr/bin/entrypoint", "bash", "/run/start.sh"],
            "{spec:?}"
        );

        let (o, s) = (Fake::default(), State::in_memory().await.unwrap());
        install(&o, &s, PUBLIC, Some("demo.example.fr")).await;
        let spec = o.deployed_specs.lock().unwrap().pop().expect("deployed");
        assert!(spec.command.is_empty(), "{:?}", spec.command);
    }

    #[tokio::test]
    async fn a_due_job_runs_in_its_app_and_a_failed_one_is_kept_as_failed() {
        const WITH_JOB: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  jobs:
    - { id: gc, does: frees blocks, every: week, command: [/scripts/gc.sh] }
"#;
        let s = State::in_memory().await.unwrap();
        install(&Fake::default(), &s, WITH_JOB, None).await;

        let failing = Fake {
            fail_exec: true,
            ..Default::default()
        };
        let pass = jobs::run_due(&failing, &s, 1_000_000).await;
        assert_eq!(pass.ran, 1);
        assert!(pass.failed[0].contains("no space left"), "{pass:?}");
        assert_eq!(
            *failing.execs.lock().unwrap(),
            vec![("demo".to_string(), vec!["/scripts/gc.sh".to_string()])]
        );
        let runs = s.job_runs().await.unwrap();
        assert!(
            !runs[0].succeeded && runs[0].output.contains("exit 1"),
            "{runs:?}"
        );

        // Not again within the day; then again, and done for the week.
        assert_eq!(jobs::run_due(&Fake::default(), &s, 1_003_600).await.ran, 0);
        let o = Fake::default();
        assert_eq!(
            jobs::run_due(&o, &s, 1_090_000).await,
            jobs::Pass {
                ran: 1,
                failed: vec![]
            }
        );
        assert!(s.job_runs().await.unwrap()[0].succeeded);
        assert_eq!(jobs::run_due(&o, &s, 1_180_000).await.ran, 0);
    }

    #[tokio::test]
    async fn a_run_resumed_after_a_failure_publishes_its_own_route() {
        let s = State::in_memory().await.unwrap();
        exposed(&s).await;
        let failing = Fake {
            fail_deploy: true,
            ..Default::default()
        };
        failing.absent.lock().unwrap().push("hlb-controller".into());
        install(&failing, &s, PUBLIC, Some("demo.example.fr")).await;
        assert_eq!(app_status(&s, "demo").await.as_deref(), Some("failed"));

        let o = Fake::default();
        o.absent.lock().unwrap().push("hlb-controller".into());
        let out = install(&o, &s, PUBLIC, Some("demo.example.fr")).await;
        assert!(out.is_success(), "{out:?}");
        assert!(
            written(&o)
                .last()
                .is_some_and(|c| c.contains("reverse_proxy demo:80")),
            "{:?}",
            written(&o)
        );
    }

    #[tokio::test]
    async fn a_route_reaches_the_ingress_through_its_volume_and_is_recorded_as_served() {
        let o = Fake::default();
        o.absent.lock().unwrap().push("hlb-controller".into());
        let s = State::in_memory().await.unwrap();
        exposed(&s).await;

        let out = install(&o, &s, PUBLIC, Some("demo.example.fr")).await;
        assert_eq!(out.unimplemented, 0, "{out:?}");

        let jobs = o.jobs.lock().unwrap().clone();
        assert_eq!(jobs.len(), 1, "{jobs:?}");
        let job = &jobs[0];
        assert_eq!(job.mode, hlb_orchestrator::ServiceMode::Job);
        assert_eq!(
            job.constraints,
            vec!["node.labels.hlb.ingress==true".to_string()]
        );
        assert_eq!(
            job.mounts,
            vec![
                ("caddy-config".to_string(), "/config".to_string()),
                ("caddy-logs".to_string(), "/var/log/caddy".to_string()),
            ]
        );
        // The log exists before CrowdSec looks for it: started on none, it never
        // looked again.
        assert!(
            job.command
                .join(" ")
                .contains("touch /var/log/caddy/access.log"),
            "{:?}",
            job.command
        );
        assert!(
            job.command.join(" ").contains("caddy validate"),
            "{:?}",
            job.command
        );
        assert!(
            written(&o)[0].contains("reverse_proxy demo:80"),
            "{}",
            written(&o)[0]
        );
        // 🔴 A new route restarts nothing: the service's own spec is left alone.
        let r = o.reconfigured.lock().unwrap().clone();
        assert!(r.iter().all(|(_, files, _)| files.is_empty()), "{r:?}");
        assert_eq!(
            s.published_ingress().await.unwrap(),
            vec![("demo.example.fr".into(), "demo".into(), true)]
        );
    }

    #[tokio::test]
    async fn a_configuration_caddy_refuses_changes_nothing() {
        let o = Fake {
            fail_jobs: true,
            ..Default::default()
        };
        let s = State::in_memory().await.unwrap();
        exposed(&s).await;
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(PUBLIC).unwrap();
        s.upsert_app("demo", &m, Some("demo.example.fr"))
            .await
            .unwrap();
        let err = ingress::publish(&o, &s, None).await.unwrap_err();
        assert!(err.to_string().contains("unrecognized directive"), "{err}");
        assert!(
            s.published_ingress().await.unwrap().is_empty(),
            "recorded as served while Caddy kept the old file"
        );
    }

    /// A role change republishes through the same `publish` as `hlb ingress`: given
    /// nothing but the vault, it must find the bouncer and its address on its own —
    /// the controller's passed none and took CrowdSec off every route.
    #[tokio::test]
    async fn every_publication_keeps_the_bouncer_at_the_recorded_address() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();
        exposed(&s).await;
        s.store_secret_if_absent(
            hlb_ingress::crowdsec::SECRET_NAME,
            &vault.encrypt("abcdefghijklmnop0123").unwrap(),
            "bouncer",
        )
        .await
        .unwrap();
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(PUBLIC).unwrap();
        s.upsert_app("demo", &m, Some("demo.example.fr"))
            .await
            .unwrap();

        ingress::publish(&o, &s, Some(&vault)).await.unwrap();
        assert!(
            written(&o)[0].contains("api_url http://crowdsec:8080"),
            "{}",
            written(&o)[0]
        );

        s.set_crowdsec_url(Some("http://cs.internal:8080"))
            .await
            .unwrap();
        ingress::publish(&o, &s, Some(&vault)).await.unwrap();
        let last = written(&o).pop().unwrap();
        assert!(last.contains("api_url http://cs.internal:8080"), "{last}");
    }

    #[tokio::test]
    async fn the_interface_is_routed_once_the_controller_runs() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        exposed(&s).await;
        install(&o, &s, PUBLIC, Some("demo.example.fr")).await;
        assert!(
            written(&o)[0].contains("reverse_proxy hlb-controller:8420"),
            "{}",
            written(&o)[0]
        );
    }

    #[tokio::test]
    async fn the_ingress_answers_on_the_overlay_to_the_identity_provider_s_name_only() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        exposed(&s).await;
        let pid = PUBLIC.replace("name: demo", "name: pocket-id");
        install(&o, &s, &pid, Some("id.example.fr")).await;
        install(&o, &s, PUBLIC, Some("demo.example.fr")).await;
        let r = o.reconfigured.lock().unwrap().clone();
        assert_eq!(
            r.last().map(|x| x.2.clone()),
            Some(vec!["id.example.fr".to_string()])
        );
    }

    #[tokio::test]
    async fn a_route_waits_for_the_ingress_and_its_deployment_completes_it() {
        // 🔴 Unimplemented, never done, while nothing routes; done once the ingress's
        // own deployment serves it — and the app stops reading "partial".
        let o = Fake::default();
        o.absent.lock().unwrap().push("caddy".into());
        let s = State::in_memory().await.unwrap();
        exposed(&s).await;

        let out = install(&o, &s, PUBLIC, Some("demo.example.fr")).await;
        assert_eq!(out.unimplemented, 1, "{out:?}");
        assert!(o.jobs.lock().unwrap().is_empty());
        assert_eq!(app_status(&s, "demo").await.as_deref(), Some("partial"));

        // Built here, so the catalog carries no digest: its release's stands in.
        let caddy = include_str!("../../../catalog/_platform/caddy/manifest.yaml").replace(
            "builtHere: true",
            &format!("digest: \"sha256:{}\"", "c".repeat(64)),
        );
        install(&o, &s, &caddy, None).await;

        // The file is in its volume BEFORE Caddy starts: on the image's own it would
        // serve a welcome page to the internet.
        assert!(written(&o)[0].contains("demo:80"), "{:?}", written(&o));
        let specs = o.deployed_specs.lock().unwrap().clone();
        let caddy = specs
            .iter()
            .find(|s| s.name == "caddy")
            .expect("caddy deployed");
        assert_eq!(caddy.command, ingress::command());
        assert!(
            caddy.files.is_empty(),
            "no Caddyfile secret: {:?}",
            caddy.files
        );
        assert_eq!(app_status(&s, "demo").await.as_deref(), Some("running"));
    }

    #[tokio::test]
    async fn a_route_through_an_absent_anubis_is_withheld_not_published_as_a_502() {
        let o = Fake::default();
        o.absent.lock().unwrap().push("anubis".into());
        let s = State::in_memory().await.unwrap();
        exposed(&s).await;
        let through = PUBLIC.replace(
            "      expose: public",
            "      chain: [anubis]\n      expose: public",
        );
        let out = install(&o, &s, &through, Some("demo.example.fr")).await;
        assert!(
            !written(&o)[0].contains("demo.example.fr"),
            "{}",
            written(&o)[0]
        );
        // Not served, so not done: the publication that serves it completes it.
        assert_eq!(out.unimplemented, 1, "{out:?}");
        assert_eq!(app_status(&s, "demo").await.as_deref(), Some("partial"));
    }

    #[tokio::test]
    async fn a_reader_of_another_app_s_volume_follows_it_to_its_node() {
        // CrowdSec reinstalled after Caddy moved: its own pin on the old node and
        // Caddy's log on the new one named two machines, and it was placed on neither.
        let node = |id: &str, data: &[&str]| hlb_orchestrator::NodeInfo {
            id: id.into(),
            hostname: id.into(),
            role: hlb_orchestrator::NodeRole::Worker,
            status: "ready".into(),
            availability: "active".into(),
            tier: None,
            protection: None,
            disk_tangs: Vec::new(),
            is_leader: false,
            memory_mb: None,
            failure_domain: None,
            data: data.iter().map(|d| d.to_string()).collect(),
            ingress: false,
            addr: None,
        };
        let o = Fake::default();
        *o.nodes.lock().unwrap() = vec![node("old", &["reader"]), node("new", &["caddy"])];
        let s = State::in_memory().await.unwrap();
        let reader = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: reader }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  requires:
    - kind: storage
      name: logs
      path: /logs
      backup: false
      owner: caddy
"#;
        install(&o, &s, reader, None).await;
        assert_eq!(
            *o.labelled.lock().unwrap(),
            vec![(
                "old".to_string(),
                "hlb.data.reader".to_string(),
                "false".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn nothing_is_published_before_a_domain_is_configured() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let out = install(&o, &s, PUBLIC, Some("demo.example.fr")).await;
        assert_eq!(out.unimplemented, 1, "{out:?}");
        assert!(o.jobs.lock().unwrap().is_empty());
    }

    /// A request as it was sent: `VERB url`, its headers, its body.
    type Sent = (String, Vec<(String, String)>, String);

    /// An app's API that signs in its administrator and records what it was sent.
    #[derive(Default)]
    struct SignsIn {
        sent: Mutex<Vec<Sent>>,
    }

    #[async_trait]
    impl hlb_guide::ApiClient for SignsIn {
        async fn call(
            &self,
            verb: &str,
            url: &str,
            headers: &[(String, String)],
            body: Option<&str>,
        ) -> std::result::Result<(u16, String), String> {
            let key = format!("{verb} {url}");
            let mut sent = self.sent.lock().expect("mutex");
            sent.push((key.clone(), headers.to_vec(), body.unwrap_or("").into()));
            let wrote = |path: &str| sent.iter().any(|(k, _, _)| k.ends_with(path));
            Ok(match key.as_str() {
                "GET http://demo:8096/done" => (
                    200,
                    format!(r#"{{"first":{},"sso":{}}}"#, wrote("/first"), wrote("/sso")),
                ),
                "POST http://demo:8096/signin" => (200, r#"{"AccessToken":"tok-1"}"#.into()),
                _ => (204, String::new()),
            })
        }
    }

    #[tokio::test]
    async fn a_step_signs_in_with_the_vaults_password_and_sends_the_token() {
        let o = Fake::default();
        let s = State::in_memory().await.expect("state");
        let dir = tempfile::tempdir().expect("dir");
        let vault = Vault::init(dir.path().join("master.key")).expect("vault");
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  ingress:
    - { host: x.example.fr, port: 8096 }
  recovery:
    - secret: admin-password
      username: admin
      proof:
        path: /signin
        body: '{"u":"{{ username }}","p":"{{ password }}"}'
        pointer: /AccessToken
"#,
        )
        .expect("manifest");
        let guide: hlb_types::Guide = serde_yaml_ng::from_str(
            r#"
steps:
  - id: first
    title: The administrator
    automate:
      - method: api
        probe: { path: /done, pointer: /first, equals: "true" }
        calls: [{ verb: POST, path: /first, body: '{"p":"{{ secret.admin-password }}"}' }]
  - id: sso
    title: The SSO provider
    after: [first]
    automate:
      - method: api
        signIn: admin-password
        headers: { Authorization: 'Token="{{ token }}"' }
        probe: { path: /done, pointer: /sso, equals: "true" }
        calls: [{ verb: POST, path: /sso, body: '{}' }]
"#,
        )
        .expect("guide");
        hlb_types::validate_guide(&m, &guide).expect("a valid guide");
        s.upsert_app("demo", &m, None).await.expect("upsert");
        let p = hlb_resolver::resolve_with_guide(&m, &guide, &Default::default()).expect("plan");
        let api = SignsIn::default();
        let out = Executor::new(&o, &s)
            .with_vault(&vault)
            .with_api(&api)
            .apply(true)
            .run("demo", &p)
            .await
            .expect("run");
        assert!(out.is_success(), "{out:?}");
        assert!(
            s.pending_guides().await.expect("guides").is_empty(),
            "both steps done"
        );

        let password = vault
            .decrypt(
                &s.secret("demo-admin-password")
                    .await
                    .expect("read")
                    .expect("kept"),
            )
            .expect("decrypt");
        let sent = api.sent.lock().expect("mutex");
        let at = |path: &str| {
            sent.iter()
                .find(|(k, _, _)| k.ends_with(path))
                .unwrap_or_else(|| panic!("no {path}: {sent:?}"))
        };
        assert_eq!(
            at("/signin").2,
            format!(r#"{{"p":"{password}","u":"admin"}}"#),
            "signed in with what the vault holds"
        );
        let token = vec![("Authorization".to_string(), r#"Token="tok-1""#.to_string())];
        assert_eq!(at("/sso").1, token, "the call carries the token");
        assert!(
            at("/first").1.is_empty(),
            "a step that signs in nowhere sends none"
        );
    }
}
