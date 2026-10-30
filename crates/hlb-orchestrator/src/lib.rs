//! The orchestration abstraction.
//!
//! The trait exists for two reasons:
//!   1. to insulate the rest of the code from any gaps in `bollard`;
//!   2. to keep the door open to another orchestrator without rewriting the product.
//!
//! Cost today: a few hundred lines. Benefit: the Swarm implementation can be replaced
//! without touching the resolver, the catalog or the API.

/// What Swarm says about its nodes and tasks, as plain data: in `hlb-types`, so the
/// side that only READS them never links Docker.
pub use hlb_types::swarm as cluster;
pub mod swarm;

use async_trait::async_trait;
use hlb_types::{Healthcheck, SecuritySpec};

pub use cluster::{
    why_not_running, ClusterProfile, JoinTokens, NodeInfo, NodeRole, QuorumHealth, TaskInfo,
};

pub use swarm::SwarmOrchestrator;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("error docker : {0}")]
    Docker(#[from] bollard::errors::Error),

    #[error("service \"{0}\" not found")]
    NotFound(String),

    /// `why` is Swarm's own word on the last task that did not run: without it the
    /// timeout said "0/1 running" over a "no suitable node" Swarm had stated at once.
    #[error(
        "service \"{service}\" did not become healthy within {timeout_secs} s \
             ({running}/{desired} tasks running){}",
        .why.as_deref().map(|w| format!(" — Swarm says: {w}")).unwrap_or_default()
    )]
    HealthTimeout {
        service: String,
        timeout_secs: u64,
        running: usize,
        desired: u64,
        why: Option<String>,
    },

    #[error("unexpected response from the daemon: {0}")]
    Unexpected(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// What we ask to deploy. Deliberately thin: translating from the manifest is the
/// resolver's job, not the orchestrator's.
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    pub name: String,
    /// Full reference, digest included when it is known.
    pub image: String,
    pub replicas: u64,
    /// Empty means the image's own entrypoint.
    pub command: Vec<String>,
    pub env: Vec<(String, String)>,
    /// Swarm placement constraints, e.g. `node.labels.tier==heavy`.
    pub constraints: Vec<String>,
    pub labels: Vec<(String, String)>,
    pub networks: Vec<String>,
    /// More names the service answers to on its networks. The ingress answers to every
    /// public name it routes, so an app reaching PocketID at its public address from
    /// inside the overlay meets Caddy, not a router's hairpin NAT that may drop it.
    pub aliases: Vec<String>,
    /// How to replicate the service.
    pub mode: ServiceMode,
    /// Volumes to mount: `(volume name, path inside the container)`.
    ///
    /// 🔴 Without them, an app's data goes into the container's ephemeral layer and
    /// disappears on the first redeploy.
    pub mounts: Vec<(String, String)>,
    /// What backs each mounted volume, by volume name. A volume absent here is a plain
    /// Docker volume.
    ///
    /// 🔴 Carried in the mount, not only given to `create_volume`: that call reaches the
    /// daemon `hlb` runs on, and on every other node Swarm created a plain local volume
    /// under the same name — a `tier: nfs` app scheduled there wrote to that node's disk.
    pub backings: Vec<(String, VolumeBacking)>,
    /// Hardening. Comes from the manifest and is **applied**, not merely declared.
    /// The type is `hlb-types`': one definition, as for the rest of the schema.
    pub hardening: SecuritySpec,
    /// Health probe. Without it, `wait_healthy` can only count "running" tasks, which
    /// says nothing about the application itself.
    pub healthcheck: Option<Healthcheck>,
    /// Files put in the container: `(absolute path, content)`.
    pub files: Vec<(String, String)>,
    /// Paths of the HOST mounted into the container. For Homelabus's own services only
    /// — the agent reading the machine, the controller reaching Docker — never from a
    /// manifest: an app given the host's root owns the node.
    pub binds: Vec<Bind>,
    /// Swarm's reservation and limit. `None` is neither — what a frozen manifest from
    /// before the field still deploys as.
    pub memory: Option<hlb_types::Memory>,
    /// Two of its tasks must never run at once — Homelabus's privileged daemon, whose
    /// loops would run twice and whose socket the old task would remove under the new.
    pub alone: bool,
}

/// A host path mounted into a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

impl ServiceSpec {
    pub fn new(name: impl Into<String>, image: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            image: image.into(),
            replicas: 1,
            command: Vec::new(),
            env: Vec::new(),
            constraints: Vec::new(),
            labels: Vec::new(),
            networks: Vec::new(),
            aliases: Vec::new(),
            mode: ServiceMode::Replicated,
            mounts: Vec::new(),
            backings: Vec::new(),
            hardening: SecuritySpec::default(),
            healthcheck: None,
            files: Vec::new(),
            binds: Vec::new(),
            memory: None,
            alone: false,
        }
    }

    /// Mounts a host path into the container.
    pub fn bind(
        mut self,
        source: impl Into<String>,
        target: impl Into<String>,
        read_only: bool,
    ) -> Self {
        self.binds.push(Bind {
            source: source.into(),
            target: target.into(),
            read_only,
        });
        self
    }

    /// Puts a file in the container at an absolute path.
    pub fn file(mut self, path: impl Into<String>, content: impl Into<String>) -> Self {
        self.files.push((path.into(), content.into()));
        self
    }

    /// Runs once to completion — see [`Orchestrator::run_job`].
    pub fn job(mut self) -> Self {
        self.mode = ServiceMode::Job;
        self
    }

    /// One instance per node, including nodes added later.
    ///
    /// This is what separates the agent from a daemon you would have to install by
    /// hand everywhere: adding a machine to the cluster is enough for it to appear.
    pub fn global(mut self) -> Self {
        self.mode = ServiceMode::Global;
        self
    }

    /// Adds a named volume, mounted at the given path.
    pub fn mount(mut self, volume: impl Into<String>, path: impl Into<String>) -> Self {
        self.mounts.push((volume.into(), path.into()));
        self
    }

    /// Mounts a volume whose backing every node must create it with.
    pub fn mount_backed(
        mut self,
        volume: impl Into<String>,
        path: impl Into<String>,
        backing: VolumeBacking,
    ) -> Self {
        let volume = volume.into();
        self.backings.push((volume.clone(), backing));
        self.mounts.push((volume, path.into()));
        self
    }

    /// The backing of a mounted volume: a Docker volume unless said otherwise.
    pub fn backing_of(&self, volume: &str) -> VolumeBacking {
        self.backings
            .iter()
            .find(|(v, _)| v == volume)
            .map(|(_, b)| b.clone())
            .unwrap_or_default()
    }

    /// Does this service keep data on the node it runs on?
    ///
    /// 🔴 Then it must never move: pinned to a tier alone, PostgreSQL was drained off its
    /// node by `hlb node upgrade`, started on the other heavy node over an empty
    /// directory, ran `initdb` and reported healthy (found on a real cluster). Only NFS
    /// follows a service; a global service runs everywhere by definition.
    pub fn keeps_data_on_its_node(&self) -> bool {
        self.mode == ServiceMode::Replicated
            && self
                .mounts
                .iter()
                .any(|(v, _)| !matches!(self.backing_of(v), VolumeBacking::Nfs { .. }))
    }

    /// Whether its next task may start only once this one stopped: two would open the
    /// same data, or need the same port of the same node.
    pub fn stops_first(&self) -> bool {
        self.alone || self.keeps_data_on_its_node() || !self.hardening.published_ports.is_empty()
    }

    /// Never two tasks at once, wherever its data is: the next starts once this one
    /// stopped.
    pub fn alone(mut self) -> Self {
        self.alone = true;
        self
    }

    /// Replaces the service's environment variables.
    pub fn env(mut self, vars: Vec<(String, String)>) -> Self {
        self.env = vars;
        self
    }

    pub fn hardening(mut self, h: SecuritySpec) -> Self {
        self.hardening = h;
        self
    }

    pub fn healthcheck(mut self, h: Healthcheck) -> Self {
        self.healthcheck = Some(h);
        self
    }

    pub fn replicas(mut self, n: u64) -> Self {
        self.replicas = n;
        self
    }

    /// Names the service also answers to on its networks.
    pub fn aliases(mut self, names: Vec<String>) -> Self {
        self.aliases = names;
        self
    }

    /// Attaches the service to an overlay network, where the others reach it by name.
    pub fn network(mut self, name: impl Into<String>) -> Self {
        self.networks.push(name.into());
        self
    }

    pub fn command<I, S>(mut self, cmd: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command = cmd.into_iter().map(Into::into).collect();
        self
    }

    pub fn constraint(mut self, c: impl Into<String>) -> Self {
        self.constraints.push(c.into());
        self
    }
}

/// A service's observed state.
/// How Swarm spreads a service's instances.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ServiceMode {
    /// A fixed number of instances, placed wherever Swarm wants.
    #[default]
    Replicated,
    /// Exactly one per eligible node. `replicas` is then ignored.
    Global,
    /// One task run to completion, never restarted: a one-off that leaves no service
    /// behind once [`Orchestrator::run_job`] has read how it ended.
    Job,
}

/// How a one-off task ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobOutcome {
    pub succeeded: bool,
    /// Its last lines of output: the reason, when it failed.
    pub output: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    pub exit_code: i64,
    pub stdout: String,
    pub stderr: String,
}

impl ExecOutput {
    pub fn ok(&self) -> bool {
        self.exit_code == 0
    }
}

/// What actually holds a volume's bytes.
///
/// ## 🔴 Why this is not left to Docker
///
/// A Docker volume with no options lands in `/var/lib/docker/volumes`, on the system
/// disk. That is the right default for small state, and the wrong one for a photo
/// library: the disks you bought for it are not involved, and nothing says so — you
/// discover it when the system disk fills up.
///
/// It is also the failure the Immich guide warns about: a volume that was MEANT to be
/// the NAS share and silently became local storage takes uploads perfectly well, then
/// loses them on the next redeployment.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum VolumeBacking {
    /// Docker's own directory. Fine for anything small the node owns.
    #[default]
    Docker,
    /// A path on the host — a ZFS dataset, typically.
    ///
    /// ⚠️ Docker does NOT create it: `type=none,o=bind` fails if the path is absent,
    /// which is what we want. A silently created empty directory is the whole problem.
    Bind { path: String },
    /// An NFS export, mounted by Docker itself.
    Nfs {
        /// The server, as this node reaches it.
        server: String,
        /// The exported path, e.g. `/tank/media`.
        export: String,
    },
}

impl VolumeBacking {
    /// The `local` driver options Docker expects.
    ///
    /// Docker's built-in driver handles bind mounts and NFS alike; the difference is
    /// entirely in these options.
    pub fn driver_options(&self) -> Option<std::collections::HashMap<String, String>> {
        let mut o = std::collections::HashMap::new();
        match self {
            Self::Docker => return None,
            Self::Bind { path } => {
                o.insert("type".into(), "none".into());
                o.insert("o".into(), "bind".into());
                o.insert("device".into(), path.clone());
            }
            Self::Nfs { server, export } => {
                o.insert("type".into(), "nfs".into());
                // `nfsvers=4` explicitly: left to negotiation, an old server answers in
                // v3, which has no state and loses locks on a reconnect.
                o.insert("o".into(), format!("addr={server},rw,nfsvers=4"));
                // The leading colon is part of Docker's syntax, not a typo.
                o.insert("device".into(), format!(":{export}"));
            }
        }
        Some(o)
    }

    /// What it says on screen.
    pub fn describe(&self) -> String {
        match self {
            Self::Docker => "Docker volume".to_string(),
            Self::Bind { path } => format!("bind mount on {path}"),
            Self::Nfs { server, export } => format!("NFS {server}:{export}"),
        }
    }
}

/// A volume to create, and what should hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeSpec {
    pub name: String,
    pub backing: VolumeBacking,
}

impl VolumeSpec {
    /// A plain Docker volume.
    pub fn docker(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            backing: VolumeBacking::Docker,
        }
    }
}

/// A volume and its real location on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    pub name: String,
    /// Path on the node hosting it. This is what restic backs up.
    pub mountpoint: String,
    /// Did the volume already exist?
    pub existed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub name: String,
    pub id: String,
    pub desired_replicas: u64,
    pub running_replicas: usize,
    /// The image the service's SPEC names, with the digest resolved by Swarm.
    ///
    /// ⚠️ Not what runs: it names the new image the moment an update is accepted, while
    /// the old tasks still serve. [`TaskInfo::image`] is what each task runs.
    pub image: String,
    pub update_state: Option<UpdateState>,
}

impl ServiceStatus {
    pub fn is_converged(&self) -> bool {
        self.running_replicas as u64 == self.desired_replicas
    }

    /// Has the service come up on what its spec now says — an in-place update
    /// included?
    ///
    /// 🔴 Counting running tasks is not enough for an update: on a `start-first`
    /// service the OLD task is still running while the new one starts, "1/1" read as
    /// healthy, the plan went on — and Swarm rolled the update back after it was
    /// recorded done. Swarm must have finished watching the update, and as many live
    /// tasks as asked must run the spec's image.
    pub fn rollout_concluded(&self, tasks: &[TaskInfo]) -> bool {
        if !matches!(self.update_state, None | Some(UpdateState::Completed)) || !self.is_converged()
        {
            return false;
        }
        let wanted = match self.image.split_once('@') {
            Some((_, digest)) => digest,
            None => self.image.as_str(),
        };
        let on_spec = tasks
            .iter()
            .filter(|t| t.service == self.name && t.is_alive() && t.image.contains(wanted))
            .count();
        on_spec as u64 >= self.desired_replicas
    }
}

/// The state of the last update, as Swarm reports it.
///
/// This is what makes automatic rollback possible: there is no need to guess whether
/// an update failed, Swarm says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateState {
    Updating,
    Paused,
    Completed,
    RollbackStarted,
    RollbackPaused,
    RollbackCompleted,
    Unknown,
}

impl UpdateState {
    pub fn is_failure(&self) -> bool {
        matches!(
            self,
            Self::Paused | Self::RollbackStarted | Self::RollbackPaused | Self::RollbackCompleted
        )
    }
}

/// One log line from a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// Unix timestamp. `None` when Docker did not supply one.
    pub at: Option<i64>,
    /// `true` means stderr. Many applications write everything to stderr: painting
    /// those lines red would make a normal startup look like an avalanche of
    /// errors.
    pub error: bool,
    pub line: String,
}

/// The MTU of every overlay network Homelabus creates, the ingress included.
///
/// 🔴 Overlay traffic is VXLAN, 50 bytes of headers, and between nodes it rides the
/// WireGuard mesh, whose own MTU is 1420. At Docker's default of 1500 the encapsulated
/// packets no longer fit: small requests work, and large responses stall with nothing in
/// any log. 1420 − 50 = 1370.
///
/// Applied even where there is no mesh: it costs about 1 % of throughput on a plain LAN,
/// and an overlay's MTU cannot be changed once services are attached to it — adding the
/// mesh later would otherwise mean recreating every network under running services.
pub const OVERLAY_MTU: u32 = 1370;

/// The prefix of Homelabus's OWN services — the agent, the controller. They are managed
/// but belong to no app: reconciliation leaves them alone, and the catalog refuses an
/// app named into this space, or one would be taken for the other.
pub const SYSTEM_PREFIX: &str = "hlb-";

/// The overlay every managed service joins, platform and apps alike: it is where an
/// app resolves `postgres`, and where Caddy resolves the app.
pub const PLATFORM_NETWORK: &str = "hlb_platform";

#[async_trait]
pub trait Orchestrator: Send + Sync {
    async fn ping(&self) -> Result<String>;

    /// Creates the service, or updates it in place when it exists.
    async fn deploy(&self, spec: &ServiceSpec) -> Result<String>;

    /// Updates the image of an existing service.
    ///
    /// Must apply `order: start-first` and `failure_action: rollback` - without those,
    /// the whole update pipeline collapses.
    async fn update_image(&self, name: &str, image: &str) -> Result<()>;

    /// Adjusts an existing service's replica count.
    async fn scale(&self, name: &str, replicas: u64) -> Result<()>;

    /// Gives a running service new files, and the names it answers on its networks,
    /// under its update policy. Everything else in its spec is kept.
    ///
    /// `Ok(false)`: both were already so, and nothing restarts — a file is a secret
    /// named after its content, so an unchanged file is the same secret.
    ///
    /// This is how the ingress is configured: Caddy's admin API has no authentication,
    /// and listening on the overlay it would take a configuration from any app.
    /// Runs `spec` once, where its constraints place it, waits for it to end, and
    /// removes it with the files it was given.
    ///
    /// The one way to act on a volume of another node: `exec` and the daemon `hlb`
    /// talks to only reach this one.
    async fn run_job(&self, spec: &ServiceSpec, timeout_secs: u64) -> Result<JobOutcome> {
        let _ = timeout_secs;
        Err(Error::Unexpected(format!(
            "this orchestrator cannot run the job \"{}\"",
            spec.name
        )))
    }

    async fn reconfigure(
        &self,
        name: &str,
        files: &[(String, String)],
        aliases: &[String],
    ) -> Result<bool> {
        let _ = (files, aliases);
        Err(Error::Unexpected(format!(
            "this orchestrator cannot reconfigure \"{name}\""
        )))
    }

    // ── The cluster itself ───────────────────────────────────

    /// Initialises a Swarm on this machine, advertising `advertise_addr` to the other
    /// nodes and listening there alone. Idempotent: an already active Swarm is not
    /// reinitialised - that would destroy the existing cluster.
    ///
    /// Not optional: Docker's own pick is often the wrong interface on a multi-homed
    /// machine, and any default here would hand out join tokens nobody can reach.
    async fn cluster_init(&self, advertise_addr: &str) -> Result<String>;

    /// Enables Swarm autolock and returns the key.
    ///
    /// 🔴 Without autolock, the cluster's Raft keys sit **in clear on the disk** of
    /// every manager. Anyone who recovers a disk recovers enough to take over the
    /// cluster. With autolock, a restarted manager stays locked until it is given the
    /// key.
    async fn enable_autolock(&self) -> Result<String>;

    /// Is autolock enabled?
    async fn autolock_enabled(&self) -> Result<bool>;

    /// The join tokens, and the address to connect to.
    async fn join_tokens(&self) -> Result<cluster::JoinTokens>;

    /// The cluster nodes, with their role and their tier.
    async fn nodes(&self) -> Result<Vec<cluster::NodeInfo>>;

    /// The Swarm id of the node whose daemon this talks to — where a `docker run`, and
    /// a volume mounted by name, land. `None` where it cannot tell.
    async fn local_node(&self) -> Result<Option<String>> {
        Ok(None)
    }

    /// Sets a label on a node - this is how a tier becomes an effective placement
    /// constraint.
    async fn label_node(&self, node: &str, key: &str, value: &str) -> Result<()>;

    /// Moves a node to `active`, `pause` or `drain`.
    ///
    /// 🔴 Draining is what you reach for before a reboot: Swarm reschedules the tasks
    /// elsewhere instead of killing them where they are. It is also the one call that
    /// can empty a cluster — Swarm accepts draining the last active node without
    /// complaint, so the REFUSAL belongs to the caller, not here.
    async fn set_node_availability(&self, node: &str, availability: &str) -> Result<()>;

    /// Runs a command inside a running container of a service.
    ///
    /// Used by the guides' `method: exec` automations: many apps can only be
    /// configured through their CLI (`gitea admin`, `occ`...).
    async fn exec_in_service(&self, name: &str, cmd: &[String]) -> Result<ExecOutput>;

    /// The environment a running task of the service was started with, as `NAME=value`
    /// — Swarm's record of the task, which the manager holds for a task on any node.
    /// `None` when no task runs. An assertion reads THIS, never the manifest: a
    /// `docker service update --env-rm` changes the one and not the other.
    async fn running_env(&self, name: &str) -> Result<Option<Vec<String>>> {
        let _ = name;
        Err(Error::Unexpected(
            "this orchestrator does not read a task's environment".into(),
        ))
    }

    /// Creates an attachable overlay network, with [`OVERLAY_MTU`]. Idempotent: an
    /// existing network is kept as it is, and `false` says so.
    async fn ensure_network(&self, name: &str) -> Result<bool>;

    /// The subnets a network gives its containers' addresses from, as CIDR — what a
    /// connection from one of them arrives from.
    async fn network_subnets(&self, name: &str) -> Result<Vec<String>> {
        let _ = name;
        Err(Error::Unexpected(
            "this orchestrator does not read a network's subnets".into(),
        ))
    }

    /// The address a service answers at on a network — its virtual IP, which Swarm
    /// keeps while the service exists, updates included. `None` when it is not there.
    async fn service_address(&self, service: &str, network: &str) -> Result<Option<String>> {
        let _ = (service, network);
        Err(Error::Unexpected(
            "this orchestrator does not read a service's address".into(),
        ))
    }

    /// Creates a named volume, labelled as managed by Homelabus.
    ///
    /// Idempotent: an existing volume is kept as-is - it holds data.
    ///
    /// ⚠️ An existing volume is NOT re-pointed at a new backing. Docker cannot change a
    /// volume's driver options, and recreating it would drop the data it holds. The
    /// caller is told it already existed, and deciding what to do about it is theirs.
    async fn create_volume(&self, spec: &VolumeSpec) -> Result<VolumeInfo>;

    /// Describes an existing volume.
    async fn inspect_volume(&self, name: &str) -> Result<VolumeInfo>;

    async fn status(&self, name: &str) -> Result<ServiceStatus>;

    async fn list(&self) -> Result<Vec<ServiceStatus>>;

    async fn remove(&self, name: &str) -> Result<()>;

    /// Waits for the service to converge. Used by the deployment ordering: Swarm has
    /// no `depends_on`, so we do the sequencing.
    async fn wait_healthy(&self, name: &str, timeout_secs: u64) -> Result<ServiceStatus>;

    /// The tasks, with their placement and their error.
    ///
    /// `service = None` returns those of every managed service. **With no state
    /// filter**: dead tasks are what explains an outage, and hiding them here would
    /// force you to go and read `docker service ps` by hand.
    async fn tasks(&self, service: Option<&str>) -> Result<Vec<TaskInfo>>;

    /// The last log lines of a service.
    ///
    /// ⚠️ The line count is bounded in the implementation: a chatty service left
    /// unbounded would fill the controller's memory, and the controller is what would
    /// fall over - not the service being diagnosed.
    async fn logs(&self, service: &str, rows: u32) -> Result<Vec<LogLine>>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_update_in_flight_is_not_healthy_while_the_old_task_serves() {
        // 🔴 start-first: the old task runs while the new one starts, and "1/1" was
        // read as an update done — Swarm then rolled it back after the plan moved on.
        let task = |image: &str, state: &str| TaskInfo {
            id: "t".into(),
            service: "gitea".into(),
            slot: Some(1),
            node_id: None,
            desired_state: "running".into(),
            state: state.into(),
            image: image.into(),
            message: None,
            err: None,
            updated_at: None,
        };
        let status = |update_state| ServiceStatus {
            name: "gitea".into(),
            id: "s".into(),
            desired_replicas: 1,
            running_replicas: 1,
            image: "gitea/gitea:1.27@sha256:new".into(),
            update_state,
        };
        let old = task("gitea/gitea:1.27@sha256:old", "running");
        let new = task("gitea/gitea:1.27@sha256:new", "running");
        let starting = task("gitea/gitea:1.27@sha256:new", "starting");

        assert!(!status(Some(UpdateState::Updating)).rollout_concluded(&[old.clone(), starting]));
        // Swarm not yet started on it, the old task still serving: not concluded either.
        assert!(!status(Some(UpdateState::Completed)).rollout_concluded(std::slice::from_ref(&old)));
        assert!(!status(None).rollout_concluded(std::slice::from_ref(&old)));
        assert!(!status(Some(UpdateState::RollbackCompleted))
            .rollout_concluded(std::slice::from_ref(&old)));
        assert!(status(Some(UpdateState::Completed)).rollout_concluded(&[old, new.clone()]));
        // A first deployment: no update status at all.
        assert!(status(None).rollout_concluded(&[new]));
    }

    use super::*;

    fn task(desired: &str, state: &str) -> TaskInfo {
        TaskInfo {
            id: "t1".into(),
            service: "gitea".into(),
            slot: Some(1),
            node_id: Some("n1".into()),
            desired_state: desired.into(),
            state: state.into(),
            image: "gitea/gitea:1.24".into(),
            message: None,
            err: None,
            updated_at: Some(1_000),
        }
    }

    #[test]
    fn a_timeout_names_what_swarm_said_about_the_last_task() {
        // Found on a real cluster with no heavy node: the install waited 120 s and
        // said "0/1 tasks running", over a reason Swarm had given at once.
        let old = TaskInfo {
            err: Some("task: non-zero exit (1)".into()),
            updated_at: Some(500),
            ..task("shutdown", "failed")
        };
        let pending = TaskInfo {
            message: Some(
                "no suitable node (scheduling constraints not satisfied on 4 nodes)".into(),
            ),
            ..task("running", "pending")
        };
        let why = why_not_running(&[old, pending, task("running", "running")]);
        assert_eq!(
            why.as_deref(),
            Some("no suitable node (scheduling constraints not satisfied on 4 nodes)")
        );
        let e = Error::HealthTimeout {
            service: "valkey".into(),
            timeout_secs: 120,
            running: 0,
            desired: 1,
            why,
        };
        assert!(e.to_string().ends_with(
            "— Swarm says: no suitable node (scheduling constraints not satisfied on 4 nodes)"
        ));
        assert_eq!(why_not_running(&[task("running", "running")]), None);
    }

    #[test]
    fn a_dead_task_is_never_counted_as_alive() {
        // 🔴 Swarm keeps the history of dead tasks. A task Swarm WANTS running but
        // that has failed is not alive - and neither is the reverse: a task still
        // running while Swarm wants it stopped is on its way out.
        assert!(task("running", "running").is_alive());
        assert!(!task("running", "failed").is_alive());
        assert!(!task("shutdown", "running").is_alive());
        assert!(!task("shutdown", "shutdown").is_alive());
    }

    #[test]
    fn a_deliberate_shutdown_is_not_a_failure() {
        // A task stopped for an update or a scale-down is not a failure. Counting it
        // as one would make the dashboard blink on every normal deployment - and people
        // would stop looking at it.
        assert!(!task("shutdown", "shutdown").has_failed());
        assert!(!task("shutdown", "complete").has_failed());
        assert!(task("running", "failed").has_failed());
        assert!(task("running", "rejected").has_failed());
        assert!(task("running", "orphaned").has_failed());
    }

    #[test]
    fn the_error_is_preferred_to_the_status_message() {
        // The two often coexist: `message` says "started", `err` says why it did not
        // work. The error is what you are looking for.
        let mut t = task("running", "failed");
        t.message = Some("started".into());
        t.err = Some("no such image".into());
        assert_eq!(t.explanation(), Some("no such image"));

        t.err = None;
        assert_eq!(t.explanation(), Some("started"));
    }

    #[test]
    fn an_empty_explanation_is_none_rather_than_blank() {
        // An empty string would render an explanation line with no explanation, which
        // sends you looking for a display bug.
        let mut t = task("running", "pending");
        t.err = Some(String::new());
        t.message = Some(String::new());
        assert_eq!(t.explanation(), None);
    }

    #[test]
    fn a_log_line_knows_which_stream_it_came_from() {
        // Many applications write EVERYTHING to stderr: painting those lines red
        // would make a normal startup look like an avalanche of errors. The field
        // exists to be displayed with judgement, not to colour.
        let l = LogLine {
            at: Some(1_000),
            error: true,
            line: "listening on :3000".into(),
        };
        assert!(l.error);
        assert!(!l.line.is_empty());
    }
}
