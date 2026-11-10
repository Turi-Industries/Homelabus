//! Cluster life: nodes, tasks, tiers and quorum, as plain data and pure rules.
//!
//! Deliberately separate from service deployment: these are two different concerns,
//! and mixing "run an app" with "add a machine" makes both harder to reason about.
//!
//! Here rather than in `hlb-orchestrator`, which re-exports it as `cluster`: the web
//! side reads nodes and tasks the privileged side sends it, and judges them with these
//! rules, without linking the crate that holds Docker's socket.

use serde::{Deserialize, Serialize};

/// A node's role in Swarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    /// Takes part in the Raft quorum and can drive the cluster.
    Manager,
    /// Runs tasks, with no say in decisions.
    Worker,
}

impl NodeRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manager => "manager",
            Self::Worker => "worker",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub hostname: String,
    pub role: NodeRole,
    /// `ready`, `down`, `disconnected`…
    pub status: String,
    /// `active`, `pause`, `drain`.
    pub availability: String,
    /// The declared tier, when it is set.
    pub tier: Option<String>,
    /// The protection level detected on the machine (`A`…`D`), when it was read.
    pub protection: Option<String>,
    /// The nodes whose Tangs open this node's disk at boot (`hlb.disk.tangs`, written
    /// by `hlb node bind-disk`); empty when it is not bound.
    pub disk_tangs: Vec<String>,
    pub is_leader: bool,
    pub memory_mb: Option<u64>,
    /// 🔴 The **failure domain**: the physical hardware, not the logical machine.
    ///
    /// Two VMs on the same server are two Swarm nodes and **one** point of failure.
    /// Spreading two replicas "across two different nodes" then protects nothing -
    /// Swarm returns an illusion of redundancy, and you discover it the day the
    /// hardware dies.
    ///
    /// Swarm cannot guess it: it is declared at `hlb node add` and set as the
    /// `hlb.failureDomain` label. `None` means undeclared, which must be VISIBLE
    /// rather than let anyone assume each node is isolated.
    pub failure_domain: Option<String>,
    /// The services whose data lives on this node (`hlb.data.<service>` labels): they
    /// stop while it is drained, rather than start empty elsewhere.
    pub data: Vec<String>,
    /// Carries `hlb.ingress=true`: the machine the router forwards 80 and 443 to, and
    /// so the one Caddy runs on.
    pub ingress: bool,
    /// The address the other nodes reach it at — its mesh address where there is a
    /// mesh, since that is what it advertises. `None` when Swarm gives none.
    pub addr: Option<String>,
}

impl NodeInfo {
    pub fn is_ready(&self) -> bool {
        self.status.eq_ignore_ascii_case("ready")
    }
}

/// A failure domain: one piece of hardware, and the nodes living on it.
///
/// ## 🔴 What this structure exists to show
///
/// On the command line you see three nodes and believe you are protected. Two of them
/// are VMs on the same server: the hardware dies and two thirds of the cluster goes
/// with it. That is the illusion the topology view must dispel, and it can only do so
/// if the grouping is explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureDomain {
    /// The declared name, or `None` for nodes with no declared domain.
    pub name: Option<String>,
    /// The nodes living on it, by id.
    pub nodes: Vec<String>,
}

impl FailureDomain {
    /// Does this domain carry enough nodes for its loss to be serious?
    pub fn concentrated(&self, total_nodes: usize) -> bool {
        // More than half the cluster on one piece of hardware: losing it takes quorum.
        total_nodes > 1 && self.nodes.len() * 2 > total_nodes
    }
}

/// Groups nodes by failure domain.
///
/// ⚠️ Nodes **with no declared domain** form a group of their own, never one domain
/// per node. Assuming they are isolated would be exactly the optimistic assumption
/// that creates the illusion of redundancy - we do not know, and that must show.
pub fn group_by_domain(nodes: &[NodeInfo]) -> Vec<FailureDomain> {
    let mut known: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    let mut unknowns = Vec::new();

    for n in nodes {
        match &n.failure_domain {
            Some(d) => known.entry(d.clone()).or_default().push(n.id.clone()),
            None => unknowns.push(n.id.clone()),
        }
    }

    let mut out: Vec<FailureDomain> = known
        .into_iter()
        .map(|(name, nodes)| FailureDomain {
            name: Some(name),
            nodes,
        })
        .collect();

    // Most concentrated first: that is the one whose loss does the most damage.
    out.sort_by(|a, b| {
        b.nodes
            .len()
            .cmp(&a.nodes.len())
            .then_with(|| a.name.cmp(&b.name))
    });

    if !unknowns.is_empty() {
        out.push(FailureDomain {
            name: None,
            nodes: unknowns,
        });
    }
    out
}

/// An anti-affinity violation: several replicas of a service on the same hardware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub service: String,
    /// The domain in question. `None` means undeclared.
    pub domain: Option<String>,
    /// How many replicas are there.
    pub replicas: usize,
    /// Out of how many in total.
    pub total: usize,
}

impl Violation {
    /// Are all the replicas in the same place?
    ///
    /// 🔴 The worst case: the service looks redundant and is not at all.
    pub fn total_violation(&self) -> bool {
        self.replicas == self.total && self.total > 1
    }

    pub fn describe(&self) -> String {
        let where_ = match &self.domain {
            Some(d) => format!("domain \"{d}\""),
            // ⚠️ An undeclared domain is not a proven violation, it is ignorance.
            // Saying so avoids sending anyone after a problem that may not exist.
            None => "nodes with no declared failure domain".to_string(),
        };
        if self.total_violation() {
            format!(
                "{}: all {} of its replicas are on {where_}: the redundancy is an illusion",
                self.service, self.total
            )
        } else {
            format!(
                "{}: {} of its {} replicas share {where_}",
                self.service, self.replicas, self.total
            )
        }
    }
}

/// The services whose replicas share a failure domain.
///
/// `placements` is `(service, node id)` for each **live** replica.
pub fn anti_affinity_violations(
    placements: &[(String, String)],
    nodes: &[NodeInfo],
) -> Vec<Violation> {
    // One machine has nowhere else to put a replica: said on every one-node house, the
    // portal's two would be noise nobody can act on. Two VMs of one server still are
    // two nodes, and still flagged.
    if nodes.len() < 2 {
        return Vec::new();
    }
    let domain_of: std::collections::BTreeMap<&str, Option<&str>> = nodes
        .iter()
        .map(|n| (n.id.as_str(), n.failure_domain.as_deref()))
        .collect();

    // service → (domain → count), and the total per service.
    let mut par_service: std::collections::BTreeMap<
        &str,
        std::collections::BTreeMap<Option<&str>, usize>,
    > = Default::default();
    for (service, node) in placements {
        let d = domain_of.get(node.as_str()).copied().flatten();
        *par_service
            .entry(service.as_str())
            .or_default()
            .entry(d)
            .or_insert(0) += 1;
    }

    let mut out = Vec::new();
    for (service, domains) in par_service {
        let total: usize = domains.values().sum();
        // A single-replica service has nothing to spread: flagging it would be noise,
        // and noise makes people stop reading alerts.
        if total < 2 {
            continue;
        }
        for (domain, n) in domains {
            if n > 1 {
                out.push(Violation {
                    service: service.to_string(),
                    domain: domain.map(str::to_string),
                    replicas: n,
                    total,
                });
            }
        }
    }

    // Total violations first: those are the ones that lie the most.
    out.sort_by(|a, b| {
        b.total_violation()
            .cmp(&a.total_violation())
            .then_with(|| b.replicas.cmp(&a.replicas))
            .then_with(|| a.service.cmp(&b.service))
    });
    out
}

/// The Swarm label carrying the failure domain.
///
/// Set by `hlb node add`, which ASKS for it: this is the one piece of information
/// neither Swarm nor the agent can infer - knowing two VMs run on the same server
/// means knowing the machine room.
pub const LABEL_FAILURE_DOMAIN: &str = "hlb.failureDomain";

/// The Swarm label carrying the protection level detected on the machine — written by
/// `hlb node add` and `hlb node protection`, never typed: a level declared by hand is
/// the one a stolen machine contradicts.
pub const LABEL_PROTECTION: &str = "hlb.protection";

/// The Swarm label naming, comma-separated, the nodes whose Tangs open a node's disk —
/// written by `hlb node bind-disk`, read when a node joins or leaves, since the
/// binding pins each Tang and none follows the house by itself.
pub const LABEL_DISK_TANGS: &str = "hlb.disk.tangs";

/// The label of the node carrying the pool: where a volume bound under the storage
/// root exists, and nowhere else.
pub const LABEL_STORAGE: &str = "hlb.storage";

/// The node label naming a service whose data lives on that node: `hlb.data.<service>`.
pub fn data_label(service: &str) -> String {
    crate::manifest::data_label(service)
}

/// The placement constraint that keeps a service on the node holding its data.
pub fn data_constraint(service: &str) -> String {
    crate::manifest::data_constraint(service)
}

fn is_true(v: Option<&String>) -> bool {
    v.is_some_and(|v| v == "true")
}

/// A node as the data placement sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    pub hostname: String,
    /// Ready and `active`: a drained node takes nothing new.
    pub available: bool,
    pub labels: std::collections::BTreeMap<String, String>,
}

/// The node a service with node-local data lives on, by id.
///
/// The node already carrying its label keeps it, whatever its state: the data is
/// there, and a service waiting for that node is the honest outcome — never a fresh
/// start elsewhere. Otherwise the first available node, by hostname, that meets the
/// service's own constraints, so the same cluster always gives the same answer.
pub fn data_node(
    service: &str,
    nodes: &[Candidate],
    constraints: &[String],
) -> Result<String, String> {
    let label = data_label(service);
    // `false` is a released pin: the data was moved on purpose (the ingress, to the
    // machine the router now forwards to), and the old node must stop holding it.
    if let Some(n) = nodes.iter().find(|n| is_true(n.labels.get(&label))) {
        return Ok(n.id.clone());
    }
    let meets = |n: &Candidate| {
        constraints.iter().all(|c| match c.split_once("==") {
            Some((key, want)) => match key.trim().strip_prefix("node.labels.") {
                Some(l) => n.labels.get(l).map(String::as_str) == Some(want.trim()),
                None if key.trim() == "node.hostname" => n.hostname == want.trim(),
                // Not a form Homelabus writes: Swarm still applies it, and refuses
                // to schedule if the choice made here does not meet it.
                None => true,
            },
            None => true,
        })
    };
    let mut fit: Vec<&Candidate> = nodes.iter().filter(|n| n.available && meets(n)).collect();
    fit.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    fit.first().map(|n| n.id.clone()).ok_or_else(|| {
        format!(
            "no available node meets {} for \"{service}\", which keeps its data on the \
             node it runs on",
            if constraints.is_empty() {
                "nothing".to_string()
            } else {
                constraints.join(" and ")
            }
        )
    })
}

/// Where the `heavy` tier starts, as a node REPORTS its memory. 🔴 Not 8192: a kernel never
/// reports what is installed — a VM given 4096 MB read 3922, and firmware and a built-in GPU
/// keep more on real hardware —, so a machine sold as 8 GB stayed `light` and refused
/// PostgreSQL. Nothing is sold between 6 and 8 GB, so this cuts no real machine in the wrong
/// half.
pub const HEAVY_TIER_MIN_MB: u64 = 7168;

/// A node's tier, derived from its memory.
///
/// 🔴 Not cosmetic: this is what stops PostgreSQL landing on a 4 GB node, where it
/// would work until the day it kills the machine with an OOM.
pub fn tier_for_memory(memory_mb: u64) -> &'static str {
    if memory_mb >= HEAVY_TIER_MIN_MB {
        "heavy"
    } else {
        "light"
    }
}

/// The health of the Raft quorum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumHealth {
    /// A single manager: no fault tolerance, but coherent.
    Solo,
    /// 🔴 Two managers: **worse than one**. Losing either loses the quorum and blocks
    /// the whole cluster, whereas with a single manager you can at least restart with
    /// `--force-new-cluster`.
    Dangerous { managers: usize },
    /// An odd number ≥ 3: tolerates (n-1)/2 failures.
    Healthy { managers: usize, tolerates: usize },
    /// An even number ≥ 4: works, but the extra manager buys nothing.
    Wasteful { managers: usize, tolerates: usize },
}

impl QuorumHealth {
    pub fn assess(managers: usize) -> Self {
        match managers {
            0 | 1 => Self::Solo,
            2 => Self::Dangerous { managers: 2 },
            n if n % 2 == 1 => Self::Healthy {
                managers: n,
                tolerates: (n - 1) / 2,
            },
            n => Self::Wasteful {
                managers: n,
                tolerates: (n - 1) / 2,
            },
        }
    }

    /// Should the user be alerted?
    pub fn needs_attention(&self) -> bool {
        matches!(self, Self::Dangerous { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Solo => "1 manager - no fault tolerance, but coherent. \
                           Add two managers for a real quorum."
                .into(),
            Self::Dangerous { managers } => format!(
                "🔴 {managers} managers - WORSE than one: losing either blocks \
                 the whole cluster. Go to 3, or back down to 1."
            ),
            Self::Healthy {
                managers,
                tolerates,
            } => {
                format!(
                    "{managers} managers - tolerates {tolerates} {}",
                    if *tolerates == 1 {
                        "failure"
                    } else {
                        "failures"
                    }
                )
            }
            Self::Wasteful {
                managers,
                tolerates,
            } => format!(
                "{managers} managers - tolerates the same {tolerates} as \
                 {} would. The extra manager buys nothing.",
                managers - 1
            ),
        }
    }
}

/// Whether a node can be taken out of service now — drained, upgraded, rebooted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Maintenance {
    /// Its services move elsewhere and the cluster keeps its quorum.
    Go,
    /// Possible, but the applications stop while it is down: the only node, or the only
    /// manager. Done only when the caller accepts the downtime.
    Downtime(String),
    /// Not now, whatever is accepted.
    Refused(String),
}

/// Decides whether `target` (an id or a hostname) can go into maintenance.
///
/// 🔴 **One node at a time.** A second node going down while another is still drained
/// or unreachable is how a rolling upgrade becomes an outage: the services that moved
/// off the first one have nowhere left to go, and two managers down out of three is a
/// lost quorum — the cluster then schedules nothing until one comes back.
pub fn maintenance(nodes: &[NodeInfo], target: &str) -> Maintenance {
    let Some(me) = nodes
        .iter()
        .find(|n| n.id == target || n.hostname == target)
    else {
        return Maintenance::Refused(format!("no node \"{target}\" in the cluster"));
    };

    if let Some(other) = nodes
        .iter()
        .filter(|n| n.id != me.id)
        .find(|n| !n.is_ready() || n.availability != "active")
    {
        return Maintenance::Refused(format!(
            "{} is {} / {}: one node at a time — bring it back first",
            other.hostname, other.status, other.availability
        ));
    }

    let others_active = nodes
        .iter()
        .filter(|n| n.id != me.id && n.is_ready() && n.availability == "active")
        .count();
    if others_active == 0 {
        return Maintenance::Downtime(format!(
            "{} is the only node: every application stops while it is down",
            me.hostname
        ));
    }

    if me.role == NodeRole::Manager {
        let managers = nodes.iter().filter(|n| n.role == NodeRole::Manager).count();
        let remaining = nodes
            .iter()
            .filter(|n| n.role == NodeRole::Manager && n.id != me.id && n.is_ready())
            .count();
        // A STRICT majority of all managers, not of the reachable ones.
        if remaining * 2 <= managers {
            return Maintenance::Downtime(format!(
                "{} is one of {managers} managers and the others are not a majority \
                 without it: the running services keep running, but nothing is \
                 scheduled, updated or restarted until it is back",
                me.hostname
            ));
        }
    }
    if !me.data.is_empty() {
        return Maintenance::Downtime(format!(
            "{} keep their data on {}: they stop while it is down, rather than start \
             empty on another node",
            me.data.join(", "),
            me.hostname
        ));
    }
    Maintenance::Go
}

/// The cluster profile, derived from the node count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterProfile {
    /// A single node: everything on it, no useful placement constraint.
    Solo,
    /// Two nodes: 1 manager + 1 worker. **Never two managers.**
    Paired,
    /// Three nodes or more: a real quorum.
    Quorum,
}

impl ClusterProfile {
    pub fn for_node_count(n: usize) -> Self {
        match n {
            0 | 1 => Self::Solo,
            2 => Self::Paired,
            _ => Self::Quorum,
        }
    }

    /// How many managers does this profile recommend?
    pub fn recommended_managers(&self) -> usize {
        match self {
            // 🔴 Two nodes means ONE manager. Two managers would lose the quorum on
            // the first failure.
            Self::Solo | Self::Paired => 1,
            Self::Quorum => 3,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Solo => "solo",
            Self::Paired => "paired",
            Self::Quorum => "quorum",
        }
    }
}

/// The tokens for joining a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinTokens {
    pub manager: String,
    pub worker: String,
    /// The address new nodes must connect to.
    pub advertise_addr: String,
}

impl JoinTokens {
    pub fn for_role(&self, role: NodeRole) -> &str {
        match role {
            NodeRole::Manager => &self.manager,
            NodeRole::Worker => &self.worker,
        }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskInfo {
    pub id: String,
    /// The service's NAME, never Swarm's id for it.
    pub service: String,
    /// The replica number. `None` for a service in global mode.
    pub slot: Option<u64>,
    /// Swarm's id for the node — a hostname is [`NodeInfo::hostname`].
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
    pub fn is_alive(&self) -> bool {
        self.desired_state == "running" && self.state == "running"
    }

    /// Does this task's container still run, whatever Swarm now wants of it?
    ///
    /// ⚠️ The desired state alone: a scale to zero turns it to `shutdown` or `remove`
    /// at once, while the container runs its stop — writing — for seconds more. What
    /// waits for a stop asks this, never [`Self::is_alive`].
    pub fn still_runs(&self) -> bool {
        matches!(self.state.as_str(), "running" | "starting")
    }

    /// Did this task fail?
    ///
    /// Distinct from "not alive": a deliberately stopped task (an update, a
    /// scale-down) is not a failure, and counting it as one would make the dashboard
    /// blink on every normal deployment.
    pub fn has_failed(&self) -> bool {
        matches!(self.state.as_str(), "failed" | "rejected" | "orphaned")
    }

    /// What explains the state, in one line.
    ///
    /// The error first: that is what you are looking for. Swarm's message second,
    /// which often says what the error does not ("no suitable node").
    pub fn explanation(&self) -> Option<&str> {
        self.err
            .as_deref()
            .or(self.message.as_deref())
            .filter(|m| !m.is_empty())
    }
}

/// Why a service's tasks are not running, from the most recent one that is not.
pub fn why_not_running(tasks: &[TaskInfo]) -> Option<String> {
    tasks
        .iter()
        .filter(|t| !t.is_alive())
        .max_by_key(|t| t.updated_at)
        .and_then(|t| t.explanation())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_task_told_to_stop_still_runs_until_its_container_exits() {
        // Read on the lab right after `docker service scale librespeed=0`, for 2 s:
        // "Remove / Running".
        let task = |desired: &str, state: &str| super::TaskInfo {
            id: "t".into(),
            service: "postgres".into(),
            slot: Some(1),
            node_id: None,
            desired_state: desired.into(),
            state: state.into(),
            image: "postgres".into(),
            message: None,
            err: None,
            updated_at: None,
        };
        let stopping = task("remove", "running");
        assert!(!stopping.is_alive(), "no longer counted among the replicas");
        assert!(stopping.still_runs(), "yet its container still writes");
        assert!(task("shutdown", "starting").still_runs());
        for ended in ["complete", "shutdown", "failed", "rejected", "orphaned"] {
            assert!(!task("shutdown", ended).still_runs(), "{ended}");
        }
    }

    #[test]
    fn every_tier_a_node_is_given_is_one_a_manifest_may_name() {
        for mb in [0, 1024, 4096, 8191, 8192, 65536] {
            let t = super::tier_for_memory(mb);
            assert!(crate::manifest::TIERS.contains(&t), "{t}");
        }
    }

    use super::*;

    fn candidate(id: &str, available: bool, labels: &[(&str, &str)]) -> Candidate {
        Candidate {
            id: id.into(),
            hostname: format!("host-{id}"),
            available,
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn draining_a_node_that_holds_data_is_announced_as_downtime() {
        let mut nodes = vec![
            n("a", NodeRole::Manager, "ready", "active"),
            n("b", NodeRole::Worker, "ready", "active"),
            n("c", NodeRole::Worker, "ready", "active"),
        ];
        assert_eq!(maintenance(&nodes, "b"), Maintenance::Go);
        nodes[1].data = vec!["postgres".into(), "valkey".into()];
        match maintenance(&nodes, "b") {
            Maintenance::Downtime(why) => assert!(why.contains("postgres, valkey"), "{why}"),
            other => panic!("expected downtime, got {other:?}"),
        }
    }

    #[test]
    fn a_released_pin_holds_nothing() {
        // Moving the ingress sets its old node's label to `false`: read as present, it
        // kept Caddy there, against a constraint naming the new one — unplaceable.
        let nodes = [
            candidate("a", true, &[("hlb.data.caddy", "false")]),
            candidate("b", true, &[("hlb.ingress", "true")]),
        ];
        let at = data_node("caddy", &nodes, &["node.labels.hlb.ingress==true".into()]);
        assert_eq!(at.as_deref(), Ok("b"));
    }

    #[test]
    fn a_service_stays_on_the_node_holding_its_data_even_while_it_is_drained() {
        // Found on a real cluster: moved to the other heavy node, PostgreSQL started
        // over an empty directory. Waiting for its node is the honest outcome.
        let nodes = [
            candidate("a", true, &[("tier", "heavy")]),
            candidate(
                "b",
                false,
                &[("tier", "heavy"), ("hlb.data.postgres", "true")],
            ),
        ];
        let tier = ["node.labels.tier==heavy".to_string()];
        assert_eq!(data_node("postgres", &nodes, &tier).as_deref(), Ok("b"));
    }

    #[test]
    fn a_first_placement_is_the_same_on_every_run_and_meets_the_tier() {
        let nodes = [
            candidate("c", true, &[("tier", "heavy")]),
            candidate("a", true, &[("tier", "light")]),
            candidate("b", true, &[("tier", "heavy")]),
            candidate("d", false, &[("tier", "heavy")]),
        ];
        let tier = ["node.labels.tier==heavy".to_string()];
        assert_eq!(data_node("postgres", &nodes, &tier).as_deref(), Ok("b"));
        let none = data_node("postgres", &nodes, &["node.labels.tier==gpu".to_string()]);
        assert!(none.expect_err("no gpu node").contains("tier==gpu"));
    }

    #[test]
    fn a_volume_bound_on_the_pool_goes_to_the_storage_node() {
        let nodes = [
            candidate("a", true, &[("tier", "heavy")]),
            candidate("b", true, &[("tier", "heavy"), (LABEL_STORAGE, "true")]),
        ];
        let on_pool = [
            "node.labels.tier==heavy".to_string(),
            format!("node.labels.{LABEL_STORAGE}==true"),
        ];
        assert_eq!(data_node("gitea", &nodes, &on_pool).as_deref(), Ok("b"));
    }

    #[test]
    fn the_constraint_names_the_label_the_placement_sets() {
        assert_eq!(
            data_constraint("postgres"),
            "node.labels.hlb.data.postgres==true"
        );
        assert_eq!(
            format!("node.labels.{}==true", data_label("x")),
            data_constraint("x")
        );
    }

    fn node(id: &str, domain: Option<&str>) -> NodeInfo {
        NodeInfo {
            data: Vec::new(),
            ingress: false,
            addr: None,
            id: id.into(),
            hostname: id.into(),
            role: NodeRole::Worker,
            status: "ready".into(),
            availability: "active".into(),
            tier: None,
            protection: None,
            disk_tangs: Vec::new(),
            is_leader: false,
            memory_mb: Some(8192),
            failure_domain: domain.map(str::to_string),
        }
    }

    #[test]
    fn two_vms_on_one_box_form_one_domain() {
        // 🔴 THE case: on the command line you see three nodes and believe you are
        // protected. Two are VMs on the same server - the hardware dies, and two thirds
        // of the cluster goes with it.
        let nodes = [
            node("swarm-heavy", Some("big-01")),
            node("mailcow", Some("big-01")),
            node("small-01", Some("small-01")),
        ];
        let d = group_by_domain(&nodes);

        assert_eq!(d.len(), 2, "three nodes, two pieces of hardware");
        assert_eq!(
            d[0].name.as_deref(),
            Some("big-01"),
            "most concentrated first"
        );
        assert_eq!(d[0].nodes.len(), 2);
        assert!(
            d[0].concentrated(3),
            "two nodes out of three: losing it takes the quorum"
        );
        assert!(!d[1].concentrated(3));
    }

    #[test]
    fn undeclared_nodes_are_grouped_not_assumed_isolated() {
        // ⚠️ Assuming a node with no declared domain is isolated would be exactly the
        // optimistic assumption that creates the illusion we are trying to dispel. We
        // do not know, and that must show.
        let nodes = [node("a", None), node("b", None), node("c", Some("fer-1"))];
        let d = group_by_domain(&nodes);

        let unknown = d
            .iter()
            .find(|x| x.name.is_none())
            .expect("un groupe unknown");
        assert_eq!(unknown.nodes.len(), 2, "grouped, not one domain each");
        // And it comes last: it is not a proven violation.
        assert!(d.last().is_some_and(|x| x.name.is_none()));
    }

    #[test]
    fn all_replicas_on_one_box_is_the_worst_case() {
        // 🔴 The service looks redundant and is not at all: the lie Swarm produces
        // when anti-affinity is expressed over `node.id`.
        let nodes = [
            node("vm-a", Some("big-01")),
            node("vm-b", Some("big-01")),
            node("small-01", Some("small-01")),
        ];
        let placements = [
            ("gitea".to_string(), "vm-a".to_string()),
            ("gitea".to_string(), "vm-b".to_string()),
        ];

        let v = anti_affinity_violations(&placements, &nodes);
        assert_eq!(v.len(), 1);
        assert!(
            v[0].total_violation(),
            "BOTH replicas are on the same hardware"
        );
        assert!(v[0].describe().contains("illusion"), "{}", v[0].describe());
    }

    #[test]
    fn a_properly_spread_service_raises_nothing() {
        let nodes = [
            node("vm-a", Some("big-01")),
            node("small-01", Some("small-01")),
        ];
        let placements = [
            ("gitea".to_string(), "vm-a".to_string()),
            ("gitea".to_string(), "small-01".to_string()),
        ];
        assert!(anti_affinity_violations(&placements, &nodes).is_empty());
    }

    #[test]
    fn a_single_replica_service_is_never_flagged() {
        // A single-replica service has nothing to spread. Flagging it would be noise
        // - and noise makes people stop reading alerts.
        let nodes = [node("vm-a", Some("big-01"))];
        let placements = [("valkey".to_string(), "vm-a".to_string())];
        assert!(anti_affinity_violations(&placements, &nodes).is_empty());
    }

    #[test]
    fn replicas_on_the_only_node_are_never_flagged() {
        let nodes = [node("vm-a", Some("big-01"))];
        let placements = [
            ("oauth2-proxy".to_string(), "vm-a".to_string()),
            ("oauth2-proxy".to_string(), "vm-a".to_string()),
        ];
        assert!(anti_affinity_violations(&placements, &nodes).is_empty());
        // A second node in the same box makes it a lie again.
        let nodes = [node("vm-a", Some("big-01")), node("vm-b", Some("big-01"))];
        assert_eq!(anti_affinity_violations(&placements, &nodes).len(), 1);
    }

    #[test]
    fn a_partial_violation_is_reported_but_ranked_lower() {
        // Three replicas, two in the same place: less serious than "all in the same
        // place", but still redundancy overstated.
        let nodes = [
            node("vm-a", Some("big-01")),
            node("vm-b", Some("big-01")),
            node("small-01", Some("small-01")),
        ];
        let placements = [
            ("gitea".to_string(), "vm-a".to_string()),
            ("gitea".to_string(), "vm-b".to_string()),
            ("gitea".to_string(), "small-01".to_string()),
        ];

        let v = anti_affinity_violations(&placements, &nodes);
        assert_eq!(v.len(), 1);
        assert!(!v[0].total_violation());
        assert_eq!((v[0].replicas, v[0].total), (2, 3));
    }

    #[test]
    fn total_violations_are_listed_before_partial_ones() {
        let nodes = [
            node("vm-a", Some("big-01")),
            node("vm-b", Some("big-01")),
            node("small-01", Some("small-01")),
        ];
        let placements = [
            // vikunja: all in the same place - the worst case.
            ("vikunja".to_string(), "vm-a".to_string()),
            ("vikunja".to_string(), "vm-b".to_string()),
            // gitea: two out of three.
            ("gitea".to_string(), "vm-a".to_string()),
            ("gitea".to_string(), "vm-b".to_string()),
            ("gitea".to_string(), "small-01".to_string()),
        ];

        let v = anti_affinity_violations(&placements, &nodes);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].service, "vikunja", "the total violation first");
        assert!(v[0].total_violation());
    }

    #[test]
    fn an_undeclared_domain_is_not_reported_as_a_proven_violation() {
        // ⚠️ Two replicas on nodes with no declared domain: we do NOT KNOW whether
        // they share hardware. The message must say so, or you go looking for a problem
        // that may not exist.
        let nodes = [node("a", None), node("b", None)];
        let placements = [
            ("gitea".to_string(), "a".to_string()),
            ("gitea".to_string(), "b".to_string()),
        ];

        let v = anti_affinity_violations(&placements, &nodes);
        assert_eq!(v.len(), 1);
        assert!(v[0].domain.is_none());
        assert!(
            v[0].describe().contains("no declared failure domain"),
            "{}",
            v[0].describe()
        );
    }

    fn n(name: &str, role: NodeRole, status: &str, availability: &str) -> NodeInfo {
        NodeInfo {
            data: Vec::new(),
            ingress: false,
            addr: None,
            id: format!("id-{name}"),
            hostname: name.into(),
            role,
            status: status.into(),
            availability: availability.into(),
            tier: None,
            protection: None,
            disk_tangs: Vec::new(),
            is_leader: false,
            memory_mb: None,
            failure_domain: None,
        }
    }

    #[test]
    fn a_worker_among_healthy_nodes_can_go() {
        let nodes = [
            n("m1", NodeRole::Manager, "ready", "active"),
            n("w1", NodeRole::Worker, "ready", "active"),
        ];
        assert_eq!(maintenance(&nodes, "w1"), Maintenance::Go);
    }

    #[test]
    fn a_second_node_down_at_once_is_refused() {
        let nodes = [
            n("m1", NodeRole::Manager, "ready", "active"),
            n("w1", NodeRole::Worker, "ready", "drain"),
            n("w2", NodeRole::Worker, "ready", "active"),
        ];
        assert!(matches!(maintenance(&nodes, "w2"), Maintenance::Refused(r) if r.contains("w1")));
        let nodes = [
            n("m1", NodeRole::Manager, "ready", "active"),
            n("w1", NodeRole::Worker, "down", "active"),
            n("w2", NodeRole::Worker, "ready", "active"),
        ];
        assert!(matches!(maintenance(&nodes, "w2"), Maintenance::Refused(_)));
    }

    #[test]
    fn the_node_already_drained_can_resume_its_own_maintenance() {
        // A rerun after a reboot finds its own target drained: that is not "another
        // node in maintenance".
        let nodes = [
            n("m1", NodeRole::Manager, "ready", "active"),
            n("w1", NodeRole::Worker, "ready", "drain"),
        ];
        assert_eq!(maintenance(&nodes, "w1"), Maintenance::Go);
    }

    #[test]
    fn the_only_node_means_downtime() {
        let nodes = [n("m1", NodeRole::Manager, "ready", "active")];
        assert!(matches!(
            maintenance(&nodes, "m1"),
            Maintenance::Downtime(_)
        ));
    }

    #[test]
    fn one_manager_of_three_can_go_but_not_one_of_two() {
        let three = [
            n("m1", NodeRole::Manager, "ready", "active"),
            n("m2", NodeRole::Manager, "ready", "active"),
            n("m3", NodeRole::Manager, "ready", "active"),
        ];
        assert_eq!(maintenance(&three, "m2"), Maintenance::Go);
        let two = [
            n("m1", NodeRole::Manager, "ready", "active"),
            n("m2", NodeRole::Manager, "ready", "active"),
        ];
        assert!(matches!(maintenance(&two, "m2"), Maintenance::Downtime(_)));
    }

    #[test]
    fn a_single_manager_with_workers_means_downtime_for_scheduling() {
        let nodes = [
            n("m1", NodeRole::Manager, "ready", "active"),
            n("w1", NodeRole::Worker, "ready", "active"),
        ];
        assert!(matches!(
            maintenance(&nodes, "m1"),
            Maintenance::Downtime(_)
        ));
    }

    #[test]
    fn an_unknown_node_is_refused() {
        let nodes = [n("m1", NodeRole::Manager, "ready", "active")];
        assert!(matches!(
            maintenance(&nodes, "nope"),
            Maintenance::Refused(_)
        ));
    }

    #[test]
    fn two_managers_is_flagged_as_worse_than_one() {
        // 🔴 Swarm's most counter-intuitive trap, and its most expensive.
        let q = QuorumHealth::assess(2);
        assert!(q.needs_attention());
        assert!(q.describe().contains("WORSE than one"), "{}", q.describe());
    }

    #[test]
    fn one_manager_is_acceptable_though_fragile() {
        let q = QuorumHealth::assess(1);
        assert!(!q.needs_attention());
        assert!(q.describe().contains("no fault tolerance"));
    }

    #[test]
    fn three_managers_tolerate_one_failure() {
        assert_eq!(
            QuorumHealth::assess(3),
            QuorumHealth::Healthy {
                managers: 3,
                tolerates: 1
            }
        );
        assert_eq!(
            QuorumHealth::assess(5),
            QuorumHealth::Healthy {
                managers: 5,
                tolerates: 2
            }
        );
    }

    #[test]
    fn an_even_count_is_wasteful_but_not_dangerous() {
        // 4 managers tolerate 1 failure, exactly as 3 do.
        let q = QuorumHealth::assess(4);
        assert!(!q.needs_attention());
        assert!(q.describe().contains("buys nothing"), "{}", q.describe());
    }

    #[test]
    fn a_two_node_cluster_gets_a_single_manager() {
        // 🔴 The direct consequence of the trap above.
        assert_eq!(ClusterProfile::for_node_count(2), ClusterProfile::Paired);
        assert_eq!(ClusterProfile::Paired.recommended_managers(), 1);
    }

    #[test]
    fn three_nodes_get_a_real_quorum() {
        assert_eq!(ClusterProfile::for_node_count(3), ClusterProfile::Quorum);
        assert_eq!(ClusterProfile::Quorum.recommended_managers(), 3);
        assert_eq!(ClusterProfile::for_node_count(7), ClusterProfile::Quorum);
    }

    #[test]
    fn a_small_node_is_never_heavy() {
        // 4 GB nodes must stay "light": placing a database there would work until the
        // day of the OOM.
        assert_eq!(tier_for_memory(3900), "light");
        assert_eq!(tier_for_memory(4096), "light");
        assert_eq!(tier_for_memory(6144), "light");
        assert_eq!(tier_for_memory(8192), "heavy");
        assert_eq!(tier_for_memory(16384), "heavy");
    }

    #[test]
    fn a_machine_sold_as_8_gb_is_heavy_whatever_its_firmware_keeps() {
        assert_eq!(tier_for_memory(7900), "heavy");
        assert_eq!(tier_for_memory(7168), "heavy");
        assert_eq!(tier_for_memory(7167), "light");
    }

    #[test]
    fn tokens_are_selected_by_role() {
        let t = JoinTokens {
            manager: "SWMTKN-mgr".into(),
            worker: "SWMTKN-wrk".into(),
            advertise_addr: "10.0.0.1:2377".into(),
        };
        assert_eq!(t.for_role(NodeRole::Manager), "SWMTKN-mgr");
        assert_eq!(t.for_role(NodeRole::Worker), "SWMTKN-wrk");
    }

    #[test]
    fn readiness_is_case_insensitive() {
        let mut n = NodeInfo {
            data: Vec::new(),
            ingress: false,
            addr: None,
            id: "x".into(),
            hostname: "n1".into(),
            role: NodeRole::Manager,
            status: "Ready".into(),
            availability: "active".into(),
            tier: Some("heavy".into()),
            protection: None,
            disk_tangs: Vec::new(),
            is_leader: true,
            memory_mb: Some(16384),
            failure_domain: None,
        };
        assert!(n.is_ready());
        n.status = "down".into();
        assert!(!n.is_ready());
    }
}
