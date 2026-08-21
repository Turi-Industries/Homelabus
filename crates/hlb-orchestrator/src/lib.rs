//! The orchestration abstraction.
//!
//! The trait exists for two reasons:
//!   1. to insulate the rest of the code from any gaps in `bollard`;
//!   2. to keep the door open to another orchestrator without rewriting the product.
//!
//! Cost today: a few hundred lines. Benefit: the Swarm implementation can be replaced
//! without touching the resolver, the catalog or the API.

pub mod cluster;
pub mod swarm;

use async_trait::async_trait;
use hlb_types::{Healthcheck, SecuritySpec};

pub use cluster::{ClusterProfile, JoinTokens, NodeInfo, NodeRole, QuorumHealth};

pub use swarm::SwarmOrchestrator;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("erreur docker : {0}")]
    Docker(#[from] bollard::errors::Error),

    #[error("service \"{0}\" not found")]
    NotFound(String),

    #[error(
        "service \"{service}\" did not become healthy within {timeout_secs} s \
             ({running}/{desired} tasks running)"
    )]
    HealthTimeout {
        service: String,
        timeout_secs: u64,
        running: usize,
        desired: u64,
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
    /// Contraintes de placement Swarm, ex. `node.labels.tier==heavy`.
    pub constraints: Vec<String>,
    pub labels: Vec<(String, String)>,
    pub networks: Vec<String>,
    /// How to replicate the service.
    pub mode: ServiceMode,
    /// Volumes to mount: `(volume name, path inside the container)`.
    ///
    /// 🔴 Without them, an app's data goes into the container's ephemeral layer and
    /// disappears on the first redeploy.
    pub mounts: Vec<(String, String)>,
    /// Hardening. Comes from the manifest and is **applied**, not merely declared.
    /// The type is `hlb-types`': one definition, as for the rest of the schema.
    pub hardening: SecuritySpec,
    /// Health probe. Without it, `wait_healthy` can only count "running" tasks, which
    /// says nothing about the application itself.
    pub healthcheck: Option<Healthcheck>,
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
            mode: ServiceMode::Replicated,
            mounts: Vec::new(),
            hardening: SecuritySpec::default(),
            healthcheck: None,
        }
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

    /// Remplace les variables d'environnement du service.
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
    /// The image the service actually uses, with the digest resolved by Swarm.
    pub image: String,
    pub update_state: Option<UpdateState>,
}

impl ServiceStatus {
    pub fn is_converged(&self) -> bool {
        self.running_replicas as u64 == self.desired_replicas
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

/// A Swarm task: **one** replica, on **one** node.
///
/// ## Why it exists
///
/// `running_tasks()` already queried Swarm and reduced everything to a `usize`. The
/// assigned node, the error message and the timestamps were thrown away - which is
/// exactly what is needed to answer "why is this app red?" and to draw the topology
/// view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskInfo {
    pub id: String,
    pub service: String,
    /// The replica number. `None` for a service in global mode.
    pub slot: Option<u64>,
    pub node_id: Option<String>,
    /// The state Swarm wants: `running`, `shutdown`, `accepted`...
    pub desired_state: String,
    /// The actual state: `running`, `failed`, `rejected`, `pending`...
    pub state: String,
    pub image: String,
    /// What Swarm says about the task ("started", "no suitable node"...).
    pub message: Option<String>,
    /// 🔴 The error, when there is one. This is THE field that explains a failed app,
    /// and it is the one the old counter threw away.
    pub err: Option<String>,
    /// Unix timestamp of the last state change.
    pub updated_at: Option<i64>,
}

impl TaskInfo {
    /// Is this task really running?
    ///
    /// ⚠️ BOTH conditions. Swarm keeps the history of dead tasks: filtering on the
    /// desired state alone would count corpses.
    pub fn est_vivante(&self) -> bool {
        self.desired_state == "running" && self.state == "running"
    }

    /// Did this task fail?
    ///
    /// Distinct from "not alive": a deliberately stopped task (an update, a
    /// scale-down) is not a failure, and counting it as one would make the dashboard
    /// blink on every normal deployment.
    pub fn a_echoue(&self) -> bool {
        matches!(self.state.as_str(), "failed" | "rejected" | "orphaned")
    }

    /// What explains the state, in one line.
    ///
    /// The error first: that is what you are looking for. Swarm's message second,
    /// which often says what the error does not ("no suitable node").
    pub fn explication(&self) -> Option<&str> {
        self.err
            .as_deref()
            .or(self.message.as_deref())
            .filter(|m| !m.is_empty())
    }
}

/// Une ligne de journal d'un service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LigneLog {
    /// Horodatage Unix. `None` si Docker ne l'a pas fourni.
    pub at: Option<i64>,
    /// `true` means stderr. Many applications write everything to stderr: painting
    /// those lines red would make a normal startup look like an avalanche of
    /// errors.
    pub erreur: bool,
    pub ligne: String,
}

#[async_trait]
pub trait Orchestrator: Send + Sync {
    async fn ping(&self) -> Result<String>;

    async fn deploy(&self, spec: &ServiceSpec) -> Result<String>;

    /// Updates the image of an existing service.
    ///
    /// Must apply `order: start-first` and `failure_action: rollback` - without those,
    /// the whole update pipeline collapses.
    async fn update_image(&self, name: &str, image: &str) -> Result<()>;

    /// Adjusts an existing service's replica count.
    async fn scale(&self, name: &str, replicas: u64) -> Result<()>;

    // ── Vie du cluster (§2ter, §10.3) ───────────────────────────────────────

    /// Initialises a Swarm on this machine. Idempotent: an already active Swarm is
    /// not reinitialised - that would destroy the existing cluster.
    async fn cluster_init(&self, advertise_addr: Option<&str>) -> Result<String>;

    /// Enables Swarm autolock and returns the key.
    ///
    /// 🔴 Without autolock, the cluster's Raft keys sit **in clear on the disk** of
    /// every manager. Anyone who recovers a disk recovers enough to take over the
    /// cluster. With autolock, a restarted manager stays locked until it is given the
    /// key.
    async fn enable_autolock(&self) -> Result<String>;

    /// L'autolock est-il actif ?
    async fn autolock_enabled(&self) -> Result<bool>;

    /// The join tokens, and the address to connect to.
    async fn join_tokens(&self) -> Result<cluster::JoinTokens>;

    /// The cluster nodes, with their role and their tier.
    async fn nodes(&self) -> Result<Vec<cluster::NodeInfo>>;

    /// Sets a label on a node - this is how a tier becomes an effective placement
    /// constraint.
    async fn label_node(&self, node: &str, key: &str, value: &str) -> Result<()>;

    /// Runs a command inside a running container of a service.
    ///
    /// Used by the guides' `method: exec` automations: many apps can only be
    /// configured through their CLI (`gitea admin`, `occ`...).
    async fn exec_in_service(&self, name: &str, cmd: &[String]) -> Result<ExecOutput>;

    /// Creates a named volume, labelled as managed by Homelabus.
    ///
    /// Idempotent: an existing volume is kept as-is - it holds data.
    async fn create_volume(&self, name: &str) -> Result<VolumeInfo>;

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
    async fn logs(&self, service: &str, lignes: u32) -> Result<Vec<LigneLog>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tache(desired: &str, etat: &str) -> TaskInfo {
        TaskInfo {
            id: "t1".into(),
            service: "gitea".into(),
            slot: Some(1),
            node_id: Some("n1".into()),
            desired_state: desired.into(),
            state: etat.into(),
            image: "gitea/gitea:1.24".into(),
            message: None,
            err: None,
            updated_at: Some(1_000),
        }
    }

    #[test]
    fn a_dead_task_is_never_counted_as_alive() {
        // 🔴 Swarm keeps the history of dead tasks. A task Swarm WANTS running but
        // that has failed is not alive - and neither is the reverse: a task still
        // running while Swarm wants it stopped is on its way out.
        assert!(tache("running", "running").est_vivante());
        assert!(!tache("running", "failed").est_vivante());
        assert!(!tache("shutdown", "running").est_vivante());
        assert!(!tache("shutdown", "shutdown").est_vivante());
    }

    #[test]
    fn a_deliberate_shutdown_is_not_a_failure() {
        // A task stopped for an update or a scale-down is not a failure. Counting it
        // as one would make the dashboard blink on every normal deployment - and people
        // would stop looking at it.
        assert!(!tache("shutdown", "shutdown").a_echoue());
        assert!(!tache("shutdown", "complete").a_echoue());
        assert!(tache("running", "failed").a_echoue());
        assert!(tache("running", "rejected").a_echoue());
        assert!(tache("running", "orphaned").a_echoue());
    }

    #[test]
    fn the_error_is_preferred_to_the_status_message() {
        // The two often coexist: `message` says "started", `err` says why it did not
        // work. The error is what you are looking for.
        let mut t = tache("running", "failed");
        t.message = Some("started".into());
        t.err = Some("no such image".into());
        assert_eq!(t.explication(), Some("no such image"));

        t.err = None;
        assert_eq!(t.explication(), Some("started"));
    }

    #[test]
    fn an_empty_explanation_is_none_rather_than_blank() {
        // An empty string would render an explanation line with no explanation, which
        // sends you looking for a display bug.
        let mut t = tache("running", "pending");
        t.err = Some(String::new());
        t.message = Some(String::new());
        assert_eq!(t.explication(), None);
    }

    #[test]
    fn a_log_line_knows_which_stream_it_came_from() {
        // Many applications write EVERYTHING to stderr: painting those lines red
        // would make a normal startup look like an avalanche of errors. The field
        // exists to be displayed with judgement, not to colour.
        let l = LigneLog {
            at: Some(1_000),
            erreur: true,
            ligne: "listening on :3000".into(),
        };
        assert!(l.erreur);
        assert!(!l.ligne.is_empty());
    }
}
