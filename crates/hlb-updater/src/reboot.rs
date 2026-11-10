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
use std::collections::{BTreeMap, BTreeSet};

use hlb_orchestrator::{JobOutcome, NodeInfo, ServiceSpec, TaskInfo};
use hlb_resolver::graph::DependencyGraph;
use hlb_state::{NodeReboot, RebootPhase, RebootPolicy};
use hlb_types::manifest::INGRESS_SERVICE;
use hlb_types::{Criticality, Manifest};

use crate::window::{MaintenanceWindow, ParseError};

/// How long a drained node's services have to leave it.
pub const DRAIN_WAIT_S: i64 = 600;
/// How long a node's armed reboot waits for its tasks to stop before giving up by
/// itself: two minutes under [`DRAIN_WAIT_S`], so a drain the daemon gives up on and
/// puts back can never reboot after — a node's clock a minute off included.
pub const ARMED_WAIT_S: i64 = DRAIN_WAIT_S - 120;
/// What a node's clock may be off from the daemon's.
const CLOCK_SLACK_S: i64 = 60;
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
pub(crate) fn host_job(node: &NodeInfo, name: &str, detached: bool, script: &str) -> ServiceSpec {
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

/// The job arming `node`'s reboot BEFORE it is drained: a detached container waits until
/// no Swarm task runs there, then reboots it — or, at `deadline` (epoch seconds), gives up.
///
/// 🔴 Swarm schedules nothing on a drained node, a job neither: sent after the drain, the
/// reboot waited 300 s on "no suitable node" and was given up (lab, 2026-11-10). The
/// container `docker run -d` starts is no task, so the drain leaves it; it counts the
/// task containers still RUNNING, which waits for a stopping database where the tasks'
/// desired state would not.
pub fn armed_reboot_job(node: &NodeInfo, deadline: i64) -> ServiceSpec {
    let script = format!(
        "while [ -n \"$(docker ps -q --filter label=com.docker.swarm.task.id)\" ]; do \
         [ \"$(date +%s)\" -ge {deadline} ] && exit 0; sleep 5; done; {REBOOT_SCRIPT}"
    );
    host_job(node, "reboot", true, &script)
}

/// When a drained node's armed reboot has certainly either happened or given up: from
/// then on, putting the node back cannot be followed by a late reboot.
pub fn armed_until(r: &NodeReboot) -> i64 {
    armed_deadline(r) + CLOCK_SLACK_S
}

/// The deadline [`armed_reboot_job`] is given, from the reboot's own row.
pub fn armed_deadline(r: &NodeReboot) -> i64 {
    r.started_at + ARMED_WAIT_S
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

/// The services whose stop cuts a vital app, each with the first vital app (by name) it
/// cuts.
///
/// The owner's decision (2026-11-10): what the app NEEDS counts as much as the app —
/// Vaultwarden is down whether its own task or PostgreSQL's stops. So the dependency
/// graph's closure, and Caddy for an app with a route, since the router forwards to one
/// machine. On a one- or two-node house this keeps the main node's reboot a person's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vital(BTreeMap<String, String>);

impl Vital {
    pub fn of(installed: &[(String, Manifest)]) -> Self {
        let manifests: Vec<Manifest> = installed.iter().map(|(_, m)| m.clone()).collect();
        let graph = DependencyGraph::from_manifests(&manifests);
        let mut vital: Vec<&(String, Manifest)> = installed
            .iter()
            .filter(|(_, m)| m.criticality() == Criticality::Vital)
            .collect();
        vital.sort_by(|a, b| a.0.cmp(&b.0));
        let mut cuts = BTreeMap::new();
        for (app, m) in vital {
            let mut seen = BTreeSet::new();
            let mut next = vec![app.clone()];
            if !m.spec.ingress.is_empty() {
                next.push(INGRESS_SERVICE.to_string());
            }
            while let Some(name) = next.pop() {
                if !seen.insert(name.clone()) {
                    continue;
                }
                if let Some(deps) = graph.dependencies_of(&name) {
                    next.extend(deps.iter().cloned());
                }
                let companions = installed
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map(|(_, m)| m.spec.companions.as_slice())
                    .unwrap_or_default();
                // An app's companions are Swarm services `<app>-<companion>`.
                let services = std::iter::once(name.clone())
                    .chain(companions.iter().map(|c| format!("{name}-{}", c.name)));
                for service in services {
                    cuts.entry(service).or_insert_with(|| app.clone());
                }
            }
        }
        Self(cuts)
    }

    /// What `node`'s reboot stops of a vital app: (app, service), sorted. Its data and
    /// the ingress never move; when it is not `drained`, whatever runs there stops too.
    pub fn cut_by(
        &self,
        node: &NodeInfo,
        drained: bool,
        tasks: &[TaskInfo],
    ) -> Vec<(String, String)> {
        let mut stopped: BTreeSet<&str> = node.data.iter().map(String::as_str).collect();
        if node.ingress {
            stopped.insert(INGRESS_SERVICE);
        }
        if !drained {
            stopped.extend(
                tasks
                    .iter()
                    .filter(|t| t.node_id.as_deref() == Some(node.id.as_str()) && t.is_alive())
                    .map(|t| t.service.as_str()),
            );
        }
        let mut cut: Vec<(String, String)> = stopped
            .into_iter()
            .filter_map(|s| Some((self.0.get(s)?.clone(), s.to_string())))
            .collect();
        cut.sort();
        cut
    }
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
///
/// 🔴 A reboot stopping a vital app (`vital`, by what runs where: `tasks`) is a
/// person's, WHATEVER the house accepted: accepting downtime was said of the apps that
/// can wait, and the password vault is the way back into every other.
pub fn choose(
    nodes: &[NodeInfo],
    waiting: &[String],
    local: Option<&str>,
    accept_downtime: bool,
    vital: &Vital,
    tasks: &[TaskInfo],
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
        }
        .and_then(|drain| match vital.cut_by(n, drain, tasks).as_slice() {
            [] => Ok(drain),
            cut => {
                let apps: BTreeSet<&str> = cut.iter().map(|(a, _)| a.as_str()).collect();
                let services: Vec<&str> = cut.iter().map(|(_, s)| s.as_str()).collect();
                Err(format!(
                    "its reboot stops {} — vital — through {}: a person reboots it, \
                     whatever the house accepted",
                    apps.into_iter().collect::<Vec<_>>().join(", "),
                    services.join(", ")
                ))
            }
        });
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
        // A drained node is put back to be asked (a job runs nowhere else): not while
        // its armed command may still fire.
        RebootPhase::Rebooting
            if node.is_some_and(|n| n.is_ready())
                && waited >= SETTLE_S
                && (!r.drained || now >= armed_until(r)) =>
        {
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

/// Whether the node booted since its reboot began, by its own uptime.
///
/// Since it BEGAN, not since the phase changed: an armed node reboots as soon as its
/// tasks are gone, often before the next pass sees it empty.
pub fn came_back(r: &NodeReboot, probe: &Probe, now: i64) -> Result<(), String> {
    let since = (now - r.started_at).max(0) as u64;
    match probe.uptime_s {
        Some(up) if up < since => Ok(()),
        Some(up) => Err(format!(
            "{} did not reboot: up for {} min, its reboot began {} min ago",
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

    /// `choose` in a house with nothing vital.
    fn pick(
        nodes: &[NodeInfo],
        waiting: &[String],
        local: Option<&str>,
        accept_downtime: bool,
    ) -> (Option<Choice>, Vec<(String, String)>) {
        choose(
            nodes,
            waiting,
            local,
            accept_downtime,
            &Vital::default(),
            &[],
        )
    }

    fn manifest(name: &str, kind: &str, rest: &str) -> (String, Manifest) {
        let m = serde_yaml_ng::from_str(&format!(
            r#"
apiVersion: hlb/v1
kind: {kind}
metadata: {{ name: {name}{} }}
spec:
  image: {{ repo: x/{name}, tag: "1" }}
{rest}
"#,
            if name == "vaultwarden" {
                ", criticality: vital"
            } else {
                ""
            }
        ))
        .expect("manifest");
        (name.to_string(), m)
    }

    /// Vaultwarden as the catalog has it, beside what it needs and an app it does not.
    fn house() -> Vec<(String, Manifest)> {
        vec![
            manifest(
                "vaultwarden",
                "App",
                r#"  requires:
    - { kind: database, engine: postgres }
    - { kind: sso, mode: native }
    - { kind: smtp }
  companions:
    - { name: backup, image: { repo: x/b, tag: "1" } }
  ingress: [{ host: vault, port: 80 }]"#,
            ),
            manifest(
                "pocket-id",
                "PlatformService",
                "  requires: [{ kind: database, engine: postgres }]",
            ),
            manifest("postgres", "PlatformService", ""),
            manifest("stalwart", "PlatformService", ""),
            manifest(
                "gitea",
                "App",
                "  requires: [{ kind: database, engine: mariadb }]\n  ingress: [{ host: git, port: 3000 }]",
            ),
            manifest("mariadb", "PlatformService", ""),
        ]
    }

    fn task(service: &str, node: &str) -> TaskInfo {
        TaskInfo {
            id: format!("t-{service}"),
            service: service.into(),
            slot: Some(1),
            node_id: Some(node.into()),
            desired_state: "running".into(),
            state: "running".into(),
            image: String::new(),
            message: None,
            err: None,
            updated_at: None,
        }
    }

    #[test]
    fn a_vital_app_counts_what_it_needs_and_its_companions() {
        let vital = Vital::of(&house());
        let mut services: Vec<&str> = vital.0.keys().map(String::as_str).collect();
        services.sort();
        // Transitively: PocketID's own PostgreSQL. Caddy for the route. Not Gitea's.
        assert_eq!(
            services,
            [
                "caddy",
                "pocket-id",
                "postgres",
                "stalwart",
                "vaultwarden",
                "vaultwarden-backup"
            ]
        );
        assert!(vital.0.values().all(|a| a == "vaultwarden"));
        let without: Vec<_> = house()
            .into_iter()
            .filter(|(n, _)| n != "vaultwarden")
            .collect();
        assert_eq!(Vital::of(&without), Vital::default());
    }

    #[test]
    fn a_reboot_stopping_a_vital_app_is_a_person_s_whatever_the_house_accepted() {
        let vital = Vital::of(&house());
        let nodes = cluster();
        // deb3 keeps PostgreSQL's data: accepted downtime no longer reaches it.
        let deb3 = vec!["id-deb3".to_string()];
        let (chosen, left) = choose(&nodes, &deb3, None, true, &vital, &[]);
        assert_eq!(chosen, None);
        assert!(
            left[0].1.contains("vaultwarden — vital — through postgres"),
            "{left:?}"
        );

        // deb1, the only manager, is not drained: what runs there stops with it.
        let deb1 = vec!["id-deb1".to_string()];
        let gitea = [task("gitea", "id-deb1")];
        let (chosen, _) = choose(&nodes, &deb1, None, true, &vital, &gitea);
        assert_eq!(chosen.map(|c| c.drain), Some(false), "Gitea can wait");
        let both = [
            task("gitea", "id-deb1"),
            task("vaultwarden-backup", "id-deb1"),
        ];
        let (chosen, left) = choose(&nodes, &deb1, None, true, &vital, &both);
        assert_eq!(chosen, None);
        assert!(left[0].1.contains("vaultwarden-backup"), "{left:?}");
        // A task already gone stops nothing.
        let mut gone = task("vaultwarden", "id-deb1");
        gone.state = "shutdown".into();
        assert!(choose(&nodes, &deb1, None, true, &vital, &[gone])
            .0
            .is_some());

        // deb2 is drained: Vaultwarden's task moves with the rest.
        let deb2 = vec!["id-deb2".to_string()];
        let there = [task("vaultwarden", "id-deb2")];
        let (chosen, _) = choose(&nodes, &deb2, None, false, &vital, &there);
        assert_eq!(chosen.map(|c| c.drain), Some(true));
        // Unless it is the ingress: the router forwards to that one machine.
        let mut nodes = nodes;
        nodes[1].ingress = true;
        let (chosen, left) = choose(&nodes, &deb2, None, false, &vital, &[]);
        assert_eq!(chosen, None);
        assert!(left[0].1.contains("through caddy"), "{left:?}");

        // A one-node house with Vaultwarden is never rebooted by itself.
        let alone = vec![node("id-solo", "solo", hlb_orchestrator::NodeRole::Manager)];
        let solo = vec!["id-solo".to_string()];
        let runs = [task("vaultwarden", "id-solo")];
        assert_eq!(choose(&alone, &solo, None, true, &vital, &runs).0, None);
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
    fn a_drained_node_reboots_by_a_command_armed_before_the_drain() {
        let n = &cluster()[1];
        let job = armed_reboot_job(n, 1_480);
        assert_eq!(job.constraints, vec!["node.id==id-deb2".to_string()]);
        let c = &job.command;
        // Detached: the drain stops the job's task, never the container it started.
        assert!(c.iter().any(|a| a == "-d"), "{c:?}");
        let script = c.last().expect("a script");
        // It waits for the task containers still RUNNING, gives up at its deadline, and
        // only then reboots.
        let wait = script
            .find("com.docker.swarm.task.id")
            .expect("waits for the tasks");
        let deadline = script.find("-ge 1480 ] && exit 0").expect("gives up");
        let reboot = script.find("systemctl reboot").expect("reboots");
        assert!(wait < reboot && deadline < reboot, "{script}");

        // Its deadline falls before the daemon gives the drain up and puts the node back.
        let r = row(RebootPhase::Draining, 1_000);
        assert!(armed_deadline(&r) + CLOCK_SLACK_S < r.started_at + DRAIN_WAIT_S);
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
        let (chosen, left) = pick(&nodes, &waiting, Some("id-deb1"), false);
        let chosen = chosen.expect("one");
        // deb3 is left for its data, and would be for its turn.
        // By hostname, one at a time.
        assert_eq!(
            (chosen.node.hostname.as_str(), chosen.drain),
            ("deb2", true)
        );
        assert_eq!(left.len(), 1);
        assert!(left[0].1.contains("one node at a time"), "{left:?}");
        let (chosen, _) = pick(&nodes, &waiting[1..], Some("id-deb1"), false);
        assert_eq!(chosen.map(|c| c.node.hostname), Some("deb2".into()));
    }

    #[test]
    fn a_reboot_that_stops_apps_waits_for_the_house_to_accept_it() {
        let nodes = cluster();
        // deb3 keeps PostgreSQL's data, deb1 is the only manager: their apps stop, or
        // nothing is scheduled, while either is down.
        for (id, said) in [("id-deb3", "postgres"), ("id-deb1", "managers")] {
            let one = vec![id.to_string()];
            let (chosen, left) = pick(&nodes, &one, None, false);
            assert_eq!(chosen, None);
            assert!(left[0].1.contains(said), "{left:?}");
            let (chosen, _) = pick(&nodes, &one, None, true);
            // Accepted: rebooted as it is — draining would move nothing that matters.
            assert_eq!(chosen.map(|c| c.drain), Some(false));
        }

        let alone = vec![node("id-solo", "solo", hlb_orchestrator::NodeRole::Manager)];
        let solo = vec!["id-solo".to_string()];
        assert_eq!(pick(&alone, &solo, None, false).0, None);
        assert!(pick(&alone, &solo, None, true).0.is_some());
    }

    #[test]
    fn the_node_this_daemon_runs_on_is_never_drained() {
        let nodes = cluster();
        let deb2 = vec!["id-deb2".to_string()];
        // 🔴 Drained, it stops the daemon that would put it back.
        let (chosen, left) = pick(&nodes, &deb2, Some("id-deb2"), false);
        assert_eq!(chosen, None);
        assert!(left[0].1.contains("Homelabus runs on it"), "{left:?}");
        let (chosen, _) = pick(&nodes, &deb2, Some("id-deb2"), true);
        assert_eq!(chosen.map(|c| c.drain), Some(false));
    }

    #[test]
    fn a_node_a_person_is_on_or_beside_one_down_is_left_alone() {
        let mut nodes = cluster();
        nodes[1].availability = "drain".into();
        let both = vec!["id-deb2".to_string(), "id-deb3".to_string()];
        let (chosen, left) = pick(&nodes, &both, None, true);
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
    fn a_drained_node_is_not_put_back_while_its_armed_reboot_may_fire() {
        let nodes = cluster();
        // Begun at 1 000, found empty at 1 300: settled, but its command may still fire.
        let r = NodeReboot {
            started_at: 1_000,
            ..row(RebootPhase::Rebooting, 1_300)
        };
        assert_eq!(advance(&r, &nodes, 0, 1_300 + SETTLE_S), Advance::Wait);
        assert_eq!(advance(&r, &nodes, 0, armed_until(&r)), Advance::Check);
        // Not drained, nothing was armed: checked once settled.
        let sent = NodeReboot {
            drained: false,
            ..r
        };
        assert_eq!(advance(&sent, &nodes, 0, 1_300 + SETTLE_S), Advance::Check);
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

    #[test]
    fn a_node_that_rebooted_before_the_pass_saw_it_empty_came_back() {
        // Armed at 1 000, rebooted by itself at 1 100, seen empty at 1 300: asked at
        // 1 600, up 500 s — after the reboot began, before the phase changed.
        let r = NodeReboot {
            started_at: 1_000,
            ..row(RebootPhase::Rebooting, 1_300)
        };
        let up = Probe {
            uptime_s: Some(500),
            required: Some(false),
        };
        assert!(came_back(&r, &up, 1_600).is_ok());
    }
}
