//! A node rebooted into the kernel it installed, at night, one at a time, with nobody
//! there — the privileged side's loop (`hlb-privd`'s `daemon::reboots`) runs these steps.
//!
//! The host is reached WITHOUT SSH: the privileged side holds no node's key. A Swarm job
//! on the node talks to its own Docker, which starts a privileged container in the host's
//! namespaces (`nsenter -t 1`) — the same reach the Docker socket already gives whoever
//! holds it, and nothing installed on the host.
//!
//! 🔴 A reboot drains nothing by itself, and a node's apps restart cold on it: a node
//! whose services can move is drained first, and put back only once Swarm sees it ready
//! and the node itself says it booted since. One whose reboot stops apps — the only node,
//! a manager without whom the others are no majority, one keeping data, the one this
//! daemon runs on — is left to a person unless the house accepted that downtime.

use hlb_orchestrator::cluster::{maintenance, Maintenance};
use hlb_orchestrator::swarm::DOCKER_CLI_IMAGE;
use hlb_orchestrator::{JobOutcome, NodeInfo, ServiceSpec};
use hlb_state::{NodeReboot, RebootPhase, RebootPolicy};

use crate::window::{MaintenanceWindow, ParseError};

/// How long a drained node's services have to leave it.
pub const DRAIN_WAIT_S: i64 = 600;
/// Swarm sees a node ready for a few seconds after the command, before it goes down.
pub const SETTLE_S: i64 = 120;
/// How long a node has to come back before a person is told.
pub const BACK_WITHIN_S: i64 = 1_800;
/// How often, inside the window, the nodes are asked whether they wait for a reboot.
pub const PROBE_EVERY_S: i64 = 3_600;

/// How long a job is waited for: a pull of the CLI image on a slow line included.
pub const JOB_TIMEOUT_S: u64 = 300;

/// What the node's kernel waits for, and how long it has been up: what proves it
/// rebooted. Swarm's "ready" proves nothing: a node is ready again seconds after the
/// command, before it ever goes down.
fn probe_script() -> String {
    format!(
        "echo \"uptime=$(cut -d' ' -f1 /proc/uptime)\"; {}",
        hlb_bootstrap::updates::REBOOT_PROBE
    )
}

/// `systemctl` first, so the services stop in order; `reboot` where systemd is not.
/// The pause lets the job end and Swarm hear it before the node goes.
const REBOOT_SCRIPT: &str = "sleep 5; systemctl reboot || reboot";

/// A job on `node` running `script` in the host's namespaces.
///
/// Exec form all the way: the script reaches the host's `sh` as one argument, never
/// through a second shell's quoting.
fn host_job(node: &NodeInfo, name: &str, detached: bool, script: &str) -> ServiceSpec {
    let mut command: Vec<String> = ["docker", "run", "--rm"]
        .into_iter()
        .map(String::from)
        .collect();
    if detached {
        command.push("-d".into());
    }
    command.extend(
        [
            "--privileged",
            "--pid=host",
            "--network=none",
            DOCKER_CLI_IMAGE,
            "nsenter",
            "-t",
            "1",
            "-m",
            "-u",
            "-i",
            "-n",
            "-p",
            "--",
            "sh",
            "-c",
            script,
        ]
        .into_iter()
        .map(String::from),
    );
    let mut job = ServiceSpec::new(
        format!("hlb-{name}-{}", node.id.get(..12).unwrap_or(&node.id)),
        DOCKER_CLI_IMAGE,
    )
    .job()
    .constraint(format!("node.id=={}", node.id))
    .bind("/var/run/docker.sock", "/var/run/docker.sock", false)
    .command(command);
    // The CLI writes its configuration under the home directory.
    job.hardening.read_only_rootfs = false;
    job
}

/// The job asking `node` whether it waits for a reboot.
pub fn probe_job(node: &NodeInfo) -> ServiceSpec {
    host_job(node, "reboot-probe", false, &probe_script())
}

/// The job rebooting `node`. Detached: the job ends before the node does.
pub fn reboot_job(node: &NodeInfo) -> ServiceSpec {
    host_job(node, "reboot", true, REBOOT_SCRIPT)
}

/// What a node said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// Seconds since it booted.
    pub uptime_s: Option<u64>,
    /// `None`: it said nothing usable — unknown, which is not "no reboot needed".
    pub required: Option<bool>,
}

/// Reads the probe's job.
pub fn read_probe(out: &JobOutcome) -> Result<Probe, String> {
    if !out.succeeded {
        return Err(said(out));
    }
    let text = out.output.join("\n");
    let uptime_s = out.output.iter().find_map(|l| {
        l.trim()
            .strip_prefix("uptime=")?
            .split('.')
            .next()?
            .parse()
            .ok()
    });
    Ok(Probe {
        uptime_s,
        required: hlb_bootstrap::updates::reboot_required(&text),
    })
}

/// Reads the reboot's job: Docker printed the detached container's id, or why it could
/// not start one.
pub fn read_reboot(out: &JobOutcome) -> Result<(), String> {
    if out.succeeded {
        Ok(())
    } else {
        Err(said(out))
    }
}

fn said(out: &JobOutcome) -> String {
    let lines = out.output.join(" | ");
    if lines.trim().is_empty() {
        "the job failed and said nothing".into()
    } else {
        format!("the job failed: {lines}")
    }
}

/// Whether the pass may look for a node to reboot now: inside the house's window, in
/// its zone, and not asked within the hour.
pub fn due(
    policy: &RebootPolicy,
    zone: Option<&str>,
    now: i64,
    last_probe: Option<i64>,
) -> Result<bool, ParseError> {
    let Some(window) = &policy.window else {
        return Ok(false);
    };
    let open = MaintenanceWindow::parse(window)?.is_open_at(&hlb_notify::local_datetime(zone, now));
    Ok(open && last_probe.is_none_or(|t| now - t >= PROBE_EVERY_S))
}

/// The node to reboot, among those waiting for it, and whether to drain it first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub node: NodeInfo,
    pub drain: bool,
}

/// Picks one node of `waiting` (Swarm ids), by hostname, and says why each other is
/// left — to a person, who `hlb node upgrade`s it.
///
/// `local`: the node this daemon runs on. Drained, it stops the daemon — pinned there
/// by the state it holds —, and nothing would put the node back: it counts as downtime.
pub fn choose(
    nodes: &[NodeInfo],
    waiting: &[String],
    local: Option<&str>,
    accept_downtime: bool,
) -> (Option<Choice>, Vec<(String, String)>) {
    let mut candidates: Vec<&NodeInfo> = nodes.iter().filter(|n| waiting.contains(&n.id)).collect();
    candidates.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    let mut chosen = None;
    let mut left = Vec::new();
    for n in candidates {
        let verdict = if chosen.is_some() {
            Err("one node at a time: its turn comes at a later pass".to_string())
        } else if !n.is_ready() || n.availability != "active" {
            // `hlb node upgrade` drains the node it works on: never reboot under it.
            Err(format!(
                "{} / {}: a person is on it",
                n.status, n.availability
            ))
        } else {
            match maintenance(nodes, &n.id) {
                Maintenance::Refused(why) => Err(why),
                Maintenance::Downtime(_) if accept_downtime => Ok(false),
                Maintenance::Downtime(why) => Err(format!("{why}; the house did not accept it")),
                Maintenance::Go if local == Some(n.id.as_str()) && accept_downtime => Ok(false),
                Maintenance::Go if local == Some(n.id.as_str()) => Err(
                    "Homelabus runs on it: its services stop while it reboots, and the \
                     house did not accept it"
                        .to_string(),
                ),
                Maintenance::Go => Ok(true),
            }
        };
        match verdict {
            Ok(drain) => {
                chosen = Some(Choice {
                    node: n.clone(),
                    drain,
                })
            }
            Err(why) => left.push((n.hostname.clone(), why)),
        }
    }
    (chosen, left)
}

/// What a reboot under way needs next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advance {
    Wait,
    /// Its services left: send the command.
    Reboot,
    /// Back and settled: ask it whether it booted since.
    Check,
    /// Tell a person, and block the next reboots. `undrain`: the node never went down,
    /// and takes its services back; one that did not come back stays drained.
    GiveUp {
        why: String,
        undrain: bool,
    },
}

/// The next step of `r`. `left`: the replicated tasks still alive on its node.
pub fn advance(r: &NodeReboot, nodes: &[NodeInfo], left: usize, now: i64) -> Advance {
    let node = nodes.iter().find(|n| n.id == r.node_id);
    let waited = now - r.phase_at;
    match r.phase {
        RebootPhase::Stopped => Advance::Wait,
        RebootPhase::Draining if node.is_none() => Advance::GiveUp {
            why: format!("{} left the cluster while it was drained", r.hostname),
            undrain: false,
        },
        RebootPhase::Draining if left == 0 => Advance::Reboot,
        RebootPhase::Draining if waited >= DRAIN_WAIT_S => Advance::GiveUp {
            why: format!(
                "{left} service(s) still ran on {} after {} min: not rebooted",
                r.hostname,
                DRAIN_WAIT_S / 60
            ),
            undrain: true,
        },
        RebootPhase::Draining => Advance::Wait,
        RebootPhase::Rebooting if node.is_some_and(|n| n.is_ready()) && waited >= SETTLE_S => {
            Advance::Check
        }
        RebootPhase::Rebooting if waited >= BACK_WITHIN_S => Advance::GiveUp {
            why: format!(
                "{} has not come back {} min after its reboot",
                r.hostname,
                BACK_WITHIN_S / 60
            ),
            undrain: false,
        },
        RebootPhase::Rebooting => Advance::Wait,
    }
}

/// Whether the node booted since the command, by its own uptime.
pub fn came_back(r: &NodeReboot, probe: &Probe, now: i64) -> Result<(), String> {
    let since = (now - r.phase_at).max(0) as u64;
    match probe.uptime_s {
        Some(up) if up < since => Ok(()),
        Some(up) => Err(format!(
            "{} did not reboot: up for {} min, the command was sent {} min ago",
            r.hostname,
            up / 60,
            since / 60
        )),
        None => Err(format!(
            "{} did not say how long it has been up",
            r.hostname
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, host: &str, role: hlb_orchestrator::NodeRole) -> NodeInfo {
        NodeInfo {
            id: id.into(),
            hostname: host.into(),
            role,
            status: "ready".into(),
            availability: "active".into(),
            tier: None,
            protection: None,
            disk_tangs: Vec::new(),
            is_leader: false,
            memory_mb: None,
            failure_domain: None,
            data: Vec::new(),
            ingress: false,
            addr: None,
        }
    }

    fn cluster() -> Vec<NodeInfo> {
        use hlb_orchestrator::NodeRole::{Manager, Worker};
        let mut deb3 = node("id-deb3", "deb3", Worker);
        deb3.data = vec!["postgres".into()];
        vec![
            node("id-deb1", "deb1", Manager),
            node("id-deb2", "deb2", Worker),
            deb3,
        ]
    }

    fn out(succeeded: bool, lines: &[&str]) -> JobOutcome {
        JobOutcome {
            succeeded,
            output: lines.iter().map(|l| l.to_string()).collect(),
        }
    }

    fn row(phase: RebootPhase, phase_at: i64) -> NodeReboot {
        NodeReboot {
            node_id: "id-deb2".into(),
            hostname: "deb2".into(),
            phase,
            drained: true,
            started_at: 0,
            phase_at,
            detail: None,
        }
    }

    #[test]
    fn the_jobs_reach_the_host_on_that_node_and_nowhere_else() {
        let n = &cluster()[1];
        for (job, detached) in [(probe_job(n), false), (reboot_job(n), true)] {
            assert_eq!(job.constraints, vec!["node.id==id-deb2".to_string()]);
            let c = &job.command;
            assert_eq!(c.iter().any(|a| a == "-d"), detached, "{c:?}");
            let at = c.iter().position(|a| a == "nsenter").expect("nsenter");
            assert_eq!(&c[at..at + 3], ["nsenter", "-t", "1"]);
            // The script is ONE argument after `sh -c`: no second shell to quote through.
            assert_eq!(&c[c.len() - 3..c.len() - 1], ["sh", "-c"]);
        }
        assert!(reboot_job(n)
            .command
            .last()
            .is_some_and(|s| s.contains("systemctl reboot")));
        assert!(probe_job(n)
            .command
            .last()
            .is_some_and(|s| s.contains("/proc/uptime")));
    }

    #[test]
    fn a_probe_says_the_kernel_waiting_and_how_long_the_node_has_been_up() {
        let waiting = out(
            true,
            &[
                "uptime=114814.61",
                "running=6.1.0-18-amd64",
                "installed=6.1.0-18-amd64",
                "installed=6.1.0-25-amd64",
            ],
        );
        assert_eq!(
            read_probe(&waiting),
            Ok(Probe {
                uptime_s: Some(114_814),
                required: Some(true)
            })
        );
        let debian = out(true, &["uptime=62.10", "yes"]);
        assert_eq!(read_probe(&debian).expect("read").required, Some(true));
        let current = out(true, &["uptime=5", "running=6.12.1", "installed=6.12.1"]);
        assert_eq!(read_probe(&current).expect("read").required, Some(false));
        // 🔴 Nothing usable is unknown, never "no reboot needed".
        assert_eq!(
            read_probe(&out(true, &["uptime=5"]))
                .expect("read")
                .required,
            None
        );
        assert!(read_probe(&out(false, &["permission denied"])).is_err());
    }

    #[test]
    fn the_window_is_the_house_s_hours_and_asks_once_an_hour() {
        let policy = RebootPolicy {
            window: Some("daily 03:00-05:00".into()),
            accept_downtime: false,
        };
        // 2026-11-09 02:30 UTC is 03:30 in Paris.
        let at = 1_794_191_400;
        assert!(!due(&policy, None, at, None).expect("parsed"));
        assert!(due(&policy, Some("Europe/Paris"), at, None).expect("parsed"));
        let paris = Some("Europe/Paris");
        assert!(!due(&policy, paris, at, Some(at - 600)).expect("parsed"));
        assert!(due(&policy, paris, at, Some(at - PROBE_EVERY_S)).expect("parsed"));
        let never = RebootPolicy {
            window: None,
            accept_downtime: true,
        };
        assert!(!due(&never, paris, at, None).expect("never"));
    }

    #[test]
    fn a_node_whose_services_can_move_is_drained_and_rebooted_alone() {
        let nodes = cluster();
        let waiting = vec!["id-deb3".to_string(), "id-deb2".to_string()];
        let (chosen, left) = choose(&nodes, &waiting, Some("id-deb1"), false);
        let chosen = chosen.expect("one");
        // deb3 is left for its data, and would be for its turn.
        // By hostname, one at a time.
        assert_eq!(
            (chosen.node.hostname.as_str(), chosen.drain),
            ("deb2", true)
        );
        assert_eq!(left.len(), 1);
        assert!(left[0].1.contains("one node at a time"), "{left:?}");
        let (chosen, _) = choose(&nodes, &waiting[1..], Some("id-deb1"), false);
        assert_eq!(chosen.map(|c| c.node.hostname), Some("deb2".into()));
    }

    #[test]
    fn a_reboot_that_stops_apps_waits_for_the_house_to_accept_it() {
        let nodes = cluster();
        // deb3 keeps PostgreSQL's data, deb1 is the only manager: their apps stop, or
        // nothing is scheduled, while either is down.
        for (id, said) in [("id-deb3", "postgres"), ("id-deb1", "managers")] {
            let one = vec![id.to_string()];
            let (chosen, left) = choose(&nodes, &one, None, false);
            assert_eq!(chosen, None);
            assert!(left[0].1.contains(said), "{left:?}");
            let (chosen, _) = choose(&nodes, &one, None, true);
            // Accepted: rebooted as it is — draining would move nothing that matters.
            assert_eq!(chosen.map(|c| c.drain), Some(false));
        }

        let alone = vec![node("id-solo", "solo", hlb_orchestrator::NodeRole::Manager)];
        let solo = vec!["id-solo".to_string()];
        assert_eq!(choose(&alone, &solo, None, false).0, None);
        assert!(choose(&alone, &solo, None, true).0.is_some());
    }

    #[test]
    fn the_node_this_daemon_runs_on_is_never_drained() {
        let nodes = cluster();
        let deb2 = vec!["id-deb2".to_string()];
        // 🔴 Drained, it stops the daemon that would put it back.
        let (chosen, left) = choose(&nodes, &deb2, Some("id-deb2"), false);
        assert_eq!(chosen, None);
        assert!(left[0].1.contains("Homelabus runs on it"), "{left:?}");
        let (chosen, _) = choose(&nodes, &deb2, Some("id-deb2"), true);
        assert_eq!(chosen.map(|c| c.drain), Some(false));
    }

    #[test]
    fn a_node_a_person_is_on_or_beside_one_down_is_left_alone() {
        let mut nodes = cluster();
        nodes[1].availability = "drain".into();
        let both = vec!["id-deb2".to_string(), "id-deb3".to_string()];
        let (chosen, left) = choose(&nodes, &both, None, true);
        assert_eq!(chosen, None, "{left:?}");
        assert!(left[0].1.contains("a person is on it"), "{left:?}");
        // deb3 would be Go, but deb2 is out: one node at a time.
        assert!(left[1].1.contains("one node at a time"), "{left:?}");
    }

    #[test]
    fn a_drained_node_reboots_once_its_services_left_or_is_put_back() {
        let nodes = cluster();
        let r = row(RebootPhase::Draining, 1_000);
        assert_eq!(advance(&r, &nodes, 3, 1_100), Advance::Wait);
        assert_eq!(advance(&r, &nodes, 0, 1_100), Advance::Reboot);
        assert!(matches!(
            advance(&r, &nodes, 1, 1_000 + DRAIN_WAIT_S),
            Advance::GiveUp { undrain: true, .. }
        ));
        assert!(matches!(
            advance(&r, &nodes[..1], 0, 1_100),
            Advance::GiveUp { undrain: false, .. }
        ));
        assert_eq!(
            advance(&row(RebootPhase::Stopped, 0), &nodes, 0, 99_999),
            Advance::Wait
        );
    }

    #[test]
    fn a_rebooted_node_is_checked_once_settled_and_reported_if_it_never_returns() {
        let mut nodes = cluster();
        let r = row(RebootPhase::Rebooting, 1_000);
        // Ready seconds after the command, before it ever went down: not yet.
        assert_eq!(advance(&r, &nodes, 0, 1_010), Advance::Wait);
        assert_eq!(advance(&r, &nodes, 0, 1_000 + SETTLE_S), Advance::Check);
        nodes[1].status = "down".into();
        assert_eq!(advance(&r, &nodes, 0, 1_000 + SETTLE_S), Advance::Wait);
        assert!(matches!(
            advance(&r, &nodes, 0, 1_000 + BACK_WITHIN_S),
            Advance::GiveUp { undrain: false, .. }
        ));
    }

    #[test]
    fn a_node_proves_it_rebooted_by_its_own_uptime() {
        let r = row(RebootPhase::Rebooting, 1_000);
        let up = |s| Probe {
            uptime_s: Some(s),
            required: Some(false),
        };
        assert!(came_back(&r, &up(150), 1_200).is_ok());
        let never = came_back(&r, &up(90_000), 1_200).expect_err("not rebooted");
        assert!(never.contains("did not reboot"), "{never}");
        let unknown = Probe {
            uptime_s: None,
            required: None,
        };
        assert!(came_back(&r, &unknown, 1_200).is_err());
    }
}
