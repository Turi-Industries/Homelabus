//! The images no container uses, removed from every node.
//!
//! Every update pulls a new digest and leaves the previous one on the disk, on every node
//! that ever ran it: a year of weekly updates is a year of images, on the same root disk
//! as the journal and Docker's own state. Nothing else in Homelabus ever removes one.
//!
//! **What stays**: an image any container uses — running or stopped. Swarm keeps the
//! last tasks of each service (`task-history-limit`, five by default), stopped, and so
//! the image a rollback would go back to. **What goes** comes back by its digest at the
//! next deployment that needs it — a backup's restic, a drill's server image — at the
//! price of a pull. Volumes are never touched: they are data.

use hlb_orchestrator::swarm::DOCKER_CLI_IMAGE;
use hlb_orchestrator::{JobOutcome, NodeInfo, Orchestrator, ServiceSpec};

/// The line the command's exit code is printed on: a job's outcome is its log.
const EXIT_MARK: &str = "hlb-exit=";

const JOB_TIMEOUT_S: u64 = 600;

/// What happened on one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// What an apply would do.
    ToDo,
    /// Done, and what Docker said it gave back (`1.2GB`).
    Freed(String),
    /// Not ready: done at the next pass it is.
    Waiting(String),
    Failed(String),
}

/// One line per node, in the order Swarm lists them.
pub type Report = Vec<(String, Outcome)>;

/// The job that prunes `node`.
pub fn job(node: &NodeInfo) -> ServiceSpec {
    let mut job = ServiceSpec::new(
        format!("hlb-prune-{}", node.id.get(..12).unwrap_or(&node.id)),
        DOCKER_CLI_IMAGE,
    )
    .job()
    .constraint(format!("node.id=={}", node.id))
    .bind("/var/run/docker.sock", "/var/run/docker.sock", false)
    .command([
        "sh".to_string(),
        "-c".to_string(),
        // `-a`: an image pulled by its tag is not dangling, and is what piles up.
        format!("docker image prune --all --force 2>&1; echo \"{EXIT_MARK}$?\""),
    ]);
    // The CLI writes its configuration under the home directory.
    job.hardening.read_only_rootfs = false;
    job
}

/// Reads a finished job: what Docker gave back, or why it did not.
pub fn read(out: &JobOutcome) -> Outcome {
    let code = out
        .output
        .iter()
        .rev()
        .find_map(|l| l.trim().strip_prefix(EXIT_MARK)?.parse::<i64>().ok());
    let said = || {
        out.output
            .iter()
            .filter(|l| !l.trim().starts_with(EXIT_MARK))
            .cloned()
            .collect::<Vec<_>>()
            .join(" | ")
    };
    match code {
        Some(0) if out.succeeded => Outcome::Freed(
            out.output
                .iter()
                .find_map(|l| l.trim().strip_prefix("Total reclaimed space:"))
                .map(|s| s.trim().to_string())
                // An older CLI with nothing to remove says nothing at all.
                .unwrap_or_else(|| "0B".into()),
        ),
        Some(c) => Outcome::Failed(format!("exited {c}: {}", said())),
        None => Outcome::Failed(format!("the job did not say how it ended: {}", said())),
    }
}

/// Every ready node, one after the other. A preview reads the nodes and runs nothing.
pub async fn run(orchestrator: &dyn Orchestrator, apply: bool) -> Result<Report, String> {
    let nodes = orchestrator.nodes().await.map_err(|e| e.to_string())?;
    let mut report = Vec::new();
    for n in &nodes {
        let outcome = if !n.is_ready() {
            Outcome::Waiting(format!("the node is {}: done when it is back", n.status))
        } else if !apply {
            Outcome::ToDo
        } else {
            match orchestrator.run_job(&job(n), JOB_TIMEOUT_S).await {
                Ok(o) => read(&o),
                Err(e) => Outcome::Failed(e.to_string()),
            }
        };
        report.push((n.hostname.clone(), outcome));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(succeeded: bool, lines: &[&str]) -> JobOutcome {
        JobOutcome {
            succeeded,
            output: lines.iter().map(|l| l.to_string()).collect(),
        }
    }

    #[test]
    fn what_docker_gave_back_is_read_from_its_last_words() {
        let o = out(
            true,
            &[
                "Deleted Images:",
                "untagged: restic/restic@sha256:abc",
                "",
                "Total reclaimed space: 1.204GB",
                "hlb-exit=0",
            ],
        );
        assert_eq!(read(&o), Outcome::Freed("1.204GB".into()));
    }

    #[test]
    fn a_command_that_failed_is_a_failure_whatever_the_job_says() {
        let o = out(true, &["Cannot connect to the Docker daemon", "hlb-exit=1"]);
        assert!(matches!(read(&o), Outcome::Failed(why) if why.contains("Cannot connect")));
    }

    #[test]
    fn a_job_that_never_said_how_it_ended_is_not_done() {
        assert!(matches!(read(&out(true, &[])), Outcome::Failed(_)));
        assert!(matches!(
            read(&out(false, &["hlb-exit=0"])),
            Outcome::Failed(_)
        ));
    }

    #[test]
    fn the_job_reaches_the_node_s_own_daemon_and_removes_images_only() {
        let n = NodeInfo {
            id: "abcdef0123456789".into(),
            hostname: "deb1".into(),
            role: hlb_orchestrator::NodeRole::Worker,
            status: "ready".into(),
            availability: "active".into(),
            tier: None,
            is_leader: false,
            memory_mb: None,
            failure_domain: None,
            data: Vec::new(),
            ingress: false,
            addr: None,
        };
        let j = job(&n);
        assert!(j
            .constraints
            .contains(&"node.id==abcdef0123456789".to_string()));
        let cmd = j.command.join(" ");
        assert!(cmd.contains("docker image prune --all --force"), "{cmd}");
        // Volumes are data, and the other prunes reach them.
        for never in ["volume", "system prune", "container prune"] {
            assert!(!cmd.contains(never), "{never}: {cmd}");
        }
    }
}
