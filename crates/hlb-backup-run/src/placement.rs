//! Where an app's volumes are, and running restic there.
//!
//! 🔴 A volume is on the node that runs its service, and the pass ran restic on the
//! machine it ran on, mounting each volume BY NAME. Docker creates a volume it does not
//! have, empty: a volume of another node was backed up as an empty directory, or as
//! the stale copy an earlier placement had left behind — PostgreSQL's 39 MB on deb1
//! for its 334 MB on deb2 — and recorded as done. Each volume is now found on its node,
//! and backed up there.

use std::collections::BTreeMap;

use hlb_backup::restic::{Output, Runner};
use hlb_orchestrator::{NodeInfo, Orchestrator, ServiceSpec, TaskInfo};

/// restic, as the containers the pass runs on this machine use it.
pub const RESTIC_IMAGE: &str = hlb_backup::images::RESTIC;

/// Where the repository password is put in the job: a file, never a variable `docker
/// service inspect` would print for as long as the job runs.
const PASSWORD_FILE: &str = "/run/hlb/restic-password";

/// Where every other variable is put, one file each, for the same reason: an S3
/// secret has no `_FILE` form in restic, so a shell reads them back into the
/// environment of the restic it then becomes.
const ENV_DIR: &str = "/run/hlb/env";

/// A backup may take a while; one that does not end is said to have not ended.
const JOB_TIMEOUT_S: u64 = 3600;

/// The machine holding a set of volumes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Place {
    /// The machine the pass runs on.
    Here,
    /// Another node, by Swarm id and hostname.
    Node { id: String, hostname: String },
    /// Nobody can say: the reason.
    Unknown(String),
}

/// The service a volume belongs to: the longest of the app's services its name starts
/// with (`immich-machine-learning-cache` is the companion's, not `immich`'s). A volume
/// of another app the app reads (`owner:`) is read where the app runs.
fn owner<'a>(volume: &str, services: &'a [String]) -> &'a str {
    services
        .iter()
        .filter(|s| volume.starts_with(&format!("{s}-")))
        .max_by_key(|s| s.len())
        .or(services.first())
        .map(String::as_str)
        .unwrap_or_default()
}

/// Groups `volumes` by the machine holding them.
///
/// A service's volume is where its task runs; a service not running is placed by its
/// data pin (`hlb.data.<service>`), which is where it would start again. `local` is
/// this machine's node id: unknown — no Swarm — every volume is taken as here, which
/// is what the pass did before it could tell.
pub fn locate(
    volumes: &[String],
    services: &[String],
    tasks: &[TaskInfo],
    nodes: &[NodeInfo],
    local: Option<&str>,
) -> BTreeMap<Place, Vec<String>> {
    let mut out: BTreeMap<Place, Vec<String>> = BTreeMap::new();
    for v in volumes {
        let service = owner(v, services);
        let place = match local {
            None => Place::Here,
            Some(here) => {
                let running = tasks
                    .iter()
                    .find(|t| t.is_alive() && t.service == service)
                    .and_then(|t| t.node_id.clone());
                let pinned = || {
                    nodes
                        .iter()
                        .find(|n| n.data.iter().any(|d| d == service))
                        .map(|n| n.id.clone())
                };
                match running.or_else(pinned) {
                    Some(id) if id == here => Place::Here,
                    Some(id) => Place::Node {
                        hostname: nodes
                            .iter()
                            .find(|n| n.id == id)
                            .map(|n| n.hostname.clone())
                            .unwrap_or_else(|| id.clone()),
                        id,
                    },
                    None => Place::Unknown(format!(
                        "{service} runs nowhere and no node holds its data: which machine \
                         has {v} cannot be told"
                    )),
                }
            }
        };
        out.entry(place).or_default().push(v.clone());
    }
    out
}

/// restic on this machine, or as a job on the node holding the volumes.
pub enum PlacedRunner<'a> {
    Here(hlb_backup::ContainerRunner),
    Node(JobRunner<'a>),
}

#[async_trait::async_trait]
impl Runner for PlacedRunner<'_> {
    async fn run(&self, args: &[String], env: &[(String, String)]) -> hlb_backup::Result<Output> {
        match self {
            Self::Here(r) => r.run(args, env).await,
            Self::Node(r) => r.run(args, env).await,
        }
    }
}

/// restic run as a one-off Swarm job on the node holding the data, its volumes mounted
/// by name — where that name is the real volume.
pub struct JobRunner<'a> {
    pub orchestrator: &'a dyn Orchestrator,
    pub node: String,
    /// `(volume, path in the container)`.
    pub mounts: Vec<(String, String)>,
    /// The overlay, for a repository served inside the cluster.
    pub network: Option<String>,
    pub name: String,
    /// Writes into the volumes — a restore — rather than reading them.
    pub writes: bool,
}

impl JobRunner<'_> {
    fn spec(&self, args: &[String], env: &[(String, String)]) -> ServiceSpec {
        job_spec(
            ServiceSpec::new(&self.name, RESTIC_IMAGE)
                .job()
                .constraint(format!("node.id=={}", self.node)),
            &self.mounts,
            self.network.as_deref(),
            self.writes,
            args,
            env,
        )
    }
}

/// The job restic runs as. No value of `env` is in its environment or command: each is
/// a file.
fn job_spec(
    mut job: ServiceSpec,
    mounts: &[(String, String)],
    network: Option<&str>,
    writes: bool,
    args: &[String],
    env: &[(String, String)],
) -> ServiceSpec {
    for (volume, path) in mounts {
        job = job.mount(volume, path);
    }
    if let Some(n) = network {
        job = job.network(n);
    }
    let mut vars = Vec::new();
    let mut in_files = false;
    for (k, v) in env {
        if k == "RESTIC_PASSWORD" {
            job = job.file(PASSWORD_FILE, v);
            vars.push((
                "RESTIC_PASSWORD_FILE".to_string(),
                PASSWORD_FILE.to_string(),
            ));
        } else {
            job = job.file(format!("{ENV_DIR}/{k}"), v);
            in_files = true;
        }
    }
    let restic = std::iter::once("restic".to_string()).chain(args.iter().cloned());
    job = if in_files {
        // `$0` is the first word after the script, so `"$@"` is restic's arguments.
        let script = format!(
            "for f in {ENV_DIR}/*; do export \"${{f##*/}}=$(cat \"$f\")\"; done; \
                 exec \"$0\" \"$@\""
        );
        job.env(vars).command(
            ["sh".to_string(), "-c".to_string(), script]
                .into_iter()
                .chain(restic),
        )
    } else {
        job.env(vars).command(restic)
    };
    // Through every app's own permissions — PocketID's `keys/` is 0700 — and restic
    // keeps its cache in the container. A restore gives each file back its owner
    // and mode, which reading never needed.
    job.hardening.cap_add = if writes {
        vec!["CHOWN".into(), "DAC_OVERRIDE".into(), "FOWNER".into()]
    } else {
        vec!["DAC_READ_SEARCH".into()]
    };
    job.hardening.read_only_rootfs = false;
    job
}

#[async_trait::async_trait]
impl Runner for JobRunner<'_> {
    async fn run(&self, args: &[String], env: &[(String, String)]) -> hlb_backup::Result<Output> {
        let job = self.spec(args, env);
        let out = self
            .orchestrator
            .run_job(&job, JOB_TIMEOUT_S)
            .await
            .map_err(|e| hlb_backup::Error::Unexpected(e.to_string()))?;
        // A job's logs mix both streams: each reader looks for its own lines in them.
        let text = out.output.join("\n");
        Ok(Output {
            status: if out.succeeded { 0 } else { 1 },
            stdout: text.clone(),
            stderr: text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_secret_is_in_a_restic_jobs_environment_or_command() {
        let env = [
            ("RESTIC_PASSWORD".to_string(), "repo-pass-1".to_string()),
            ("AWS_ACCESS_KEY_ID".to_string(), "GK123".to_string()),
            (
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "s3-secret-2".to_string(),
            ),
        ];
        let job = job_spec(
            ServiceSpec::new("hlb-backup-x", RESTIC_IMAGE).job(),
            &[("app-data".into(), "/data".into())],
            Some("hlb_platform"),
            false,
            &["backup".to_string(), "/data".to_string()],
            &env,
        );
        let seen: Vec<&String> = job
            .env
            .iter()
            .flat_map(|(k, v)| [k, v])
            .chain(job.command.iter())
            .collect();
        for secret in ["repo-pass-1", "s3-secret-2"] {
            assert!(!seen.iter().any(|s| s.contains(secret)), "{seen:?}");
            assert!(
                job.files.iter().any(|(_, c)| c == secret),
                "{:?}",
                job.files
            );
        }
        assert_eq!(job.command[0], "sh", "{:?}", job.command);
        assert_eq!(&job.command[3..], ["restic", "backup", "/data"]);
    }

    #[test]
    fn a_job_with_only_the_repository_password_runs_restic_itself() {
        let env = [("RESTIC_PASSWORD".to_string(), "repo-pass-1".to_string())];
        let job = job_spec(
            ServiceSpec::new("hlb-backup-x", RESTIC_IMAGE).job(),
            &[],
            None,
            false,
            &["snapshots".to_string()],
            &env,
        );
        assert_eq!(job.command, ["restic", "snapshots"]);
        assert_eq!(
            job.env,
            [(
                "RESTIC_PASSWORD_FILE".to_string(),
                PASSWORD_FILE.to_string()
            )]
        );
    }

    fn task(service: &str, node: &str, alive: bool) -> TaskInfo {
        TaskInfo {
            id: format!("t-{service}"),
            service: service.into(),
            slot: Some(1),
            node_id: Some(node.into()),
            desired_state: if alive { "running" } else { "shutdown" }.into(),
            state: if alive { "running" } else { "failed" }.into(),
            image: "x".into(),
            message: None,
            err: None,
            updated_at: None,
        }
    }

    fn node(id: &str, hostname: &str, data: &[&str]) -> NodeInfo {
        NodeInfo {
            id: id.into(),
            hostname: hostname.into(),
            role: hlb_orchestrator::NodeRole::Manager,
            status: "ready".into(),
            availability: "active".into(),
            tier: None,
            is_leader: false,
            memory_mb: None,
            failure_domain: None,
            data: data.iter().map(|d| d.to_string()).collect(),
            ingress: false,
            addr: None,
        }
    }

    #[test]
    fn a_volume_is_where_its_service_runs_not_where_the_pass_does() {
        let nodes = [node("n1", "deb1", &[]), node("n2", "deb2", &["postgres"])];
        let tasks = [task("postgres", "n2", true)];
        let at = locate(
            &["postgres-data".into()],
            &["postgres".into()],
            &tasks,
            &nodes,
            Some("n1"),
        );
        assert_eq!(
            at,
            BTreeMap::from([(
                Place::Node {
                    id: "n2".into(),
                    hostname: "deb2".into()
                },
                vec!["postgres-data".to_string()]
            )])
        );
    }

    #[test]
    fn a_companions_volume_follows_the_companion() {
        let services = ["immich".to_string(), "immich-machine-learning".to_string()];
        let tasks = [
            task("immich", "n1", true),
            task("immich-machine-learning", "n2", true),
        ];
        let nodes = [node("n1", "deb1", &[]), node("n2", "deb2", &[])];
        let at = locate(
            &[
                "immich-upload".into(),
                "immich-machine-learning-cache".into(),
            ],
            &services,
            &tasks,
            &nodes,
            Some("n1"),
        );
        assert_eq!(at[&Place::Here], vec!["immich-upload".to_string()]);
        assert_eq!(at.len(), 2, "{at:?}");
    }

    #[test]
    fn a_stopped_service_is_placed_by_its_data_and_otherwise_said_unknown() {
        let nodes = [node("n1", "deb1", &[]), node("n2", "deb2", &["seafile"])];
        // A dead task is no placement: its node may have been left.
        let tasks = [task("seafile", "n1", false)];
        let at = locate(
            &["seafile-shared".into()],
            &["seafile".into()],
            &tasks,
            &nodes,
            Some("n1"),
        );
        assert!(at
            .keys()
            .all(|p| matches!(p, Place::Node { hostname, .. } if hostname == "deb2")));

        let at = locate(&["x-data".into()], &["x".into()], &[], &nodes, Some("n1"));
        assert!(
            matches!(at.keys().next(), Some(Place::Unknown(_))),
            "{at:?}"
        );
    }

    #[test]
    fn with_no_swarm_to_ask_everything_is_here() {
        let at = locate(&["a-data".into()], &["a".into()], &[], &[], None);
        assert_eq!(at[&Place::Here], vec!["a-data".to_string()]);
    }
}
