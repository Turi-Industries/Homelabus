//! Cluster life: initialisation, nodes, tiers and quorum.
//!
//! Deliberately separate from service deployment: these are two different concerns,
//! and mixing "run an app" with "add a machine" makes both harder to reason about.

use serde::{Deserialize, Serialize};

/// A node's role in Swarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    /// Participe au quorum Raft et peut piloter le cluster.
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub nom: Option<String>,
    /// The nodes living on it, by id.
    pub noeuds: Vec<String>,
}

impl FailureDomain {
    /// Does this domain carry enough nodes for its loss to be serious?
    pub fn concentre(&self, total_noeuds: usize) -> bool {
        // More than half the cluster on one piece of hardware: losing it takes quorum.
        total_noeuds > 1 && self.noeuds.len() * 2 > total_noeuds
    }
}

/// Groups nodes by failure domain.
///
/// ⚠️ Nodes **with no declared domain** form a group of their own, never one domain
/// per node. Assuming they are isolated would be exactly the optimistic assumption
/// that creates the illusion of redundancy - we do not know, and that must show.
pub fn grouper_par_domaine(noeuds: &[NodeInfo]) -> Vec<FailureDomain> {
    let mut connus: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    let mut inconnus = Vec::new();

    for n in noeuds {
        match &n.failure_domain {
            Some(d) => connus.entry(d.clone()).or_default().push(n.id.clone()),
            None => inconnus.push(n.id.clone()),
        }
    }

    let mut out: Vec<FailureDomain> = connus
        .into_iter()
        .map(|(nom, noeuds)| FailureDomain {
            nom: Some(nom),
            noeuds,
        })
        .collect();

    // Most concentrated first: that is the one whose loss does the most damage.
    out.sort_by(|a, b| {
        b.noeuds
            .len()
            .cmp(&a.noeuds.len())
            .then_with(|| a.nom.cmp(&b.nom))
    });

    if !inconnus.is_empty() {
        out.push(FailureDomain {
            nom: None,
            noeuds: inconnus,
        });
    }
    out
}

/// An anti-affinity violation: several replicas of a service on the same hardware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub service: String,
    /// The domain in question. `None` means undeclared.
    pub domaine: Option<String>,
    /// How many replicas are there.
    pub replicas: usize,
    /// Sur combien au total.
    pub total: usize,
}

impl Violation {
    /// Are all the replicas in the same place?
    ///
    /// 🔴 The worst case: the service looks redundant and is not at all.
    pub fn totale(&self) -> bool {
        self.replicas == self.total && self.total > 1
    }

    pub fn describe(&self) -> String {
        let where_ = match &self.domaine {
            Some(d) => format!("domain \"{d}\""),
            // ⚠️ An undeclared domain is not a proven violation, it is ignorance.
            // Saying so avoids sending anyone after a problem that may not exist.
            None => "nodes with no declared failure domain".to_string(),
        };
        if self.totale() {
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
pub fn violations_anti_affinite(
    placements: &[(String, String)],
    noeuds: &[NodeInfo],
) -> Vec<Violation> {
    let domaine_de: std::collections::BTreeMap<&str, Option<&str>> = noeuds
        .iter()
        .map(|n| (n.id.as_str(), n.failure_domain.as_deref()))
        .collect();

    // service → (domaine → nombre), et le total par service.
    let mut par_service: std::collections::BTreeMap<
        &str,
        std::collections::BTreeMap<Option<&str>, usize>,
    > = Default::default();
    for (service, noeud) in placements {
        let d = domaine_de.get(noeud.as_str()).copied().flatten();
        *par_service
            .entry(service.as_str())
            .or_default()
            .entry(d)
            .or_insert(0) += 1;
    }

    let mut out = Vec::new();
    for (service, domaines) in par_service {
        let total: usize = domaines.values().sum();
        // A single-replica service has nothing to spread: flagging it would be noise,
        // and noise makes people stop reading alerts.
        if total < 2 {
            continue;
        }
        for (domaine, n) in domaines {
            if n > 1 {
                out.push(Violation {
                    service: service.to_string(),
                    domaine: domaine.map(str::to_string),
                    replicas: n,
                    total,
                });
            }
        }
    }

    // Les violations totales d'abord : ce sont celles qui mentent le plus.
    out.sort_by(|a, b| {
        b.totale()
            .cmp(&a.totale())
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

/// A node's tier, derived from its memory.
///
/// 🔴 Not cosmetic: this is what stops PostgreSQL landing on a 4 GB node, where it
/// would work until the day it kills the machine with an OOM.
pub fn tier_for_memory(memory_mb: u64) -> &'static str {
    if memory_mb >= 8192 {
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

    /// Faut-il alerter l'utilisateur ?
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

    /// Combien de managers ce profil recommande-t-il ?
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

#[cfg(test)]
mod tests {
    use super::*;

    fn noeud(id: &str, domaine: Option<&str>) -> NodeInfo {
        NodeInfo {
            id: id.into(),
            hostname: id.into(),
            role: NodeRole::Worker,
            status: "ready".into(),
            availability: "active".into(),
            tier: None,
            is_leader: false,
            memory_mb: Some(8192),
            failure_domain: domaine.map(str::to_string),
        }
    }

    #[test]
    fn two_vms_on_one_box_form_one_domain() {
        // 🔴 THE case: on the command line you see three nodes and believe you are
        // protected. Two are VMs on the same server - the hardware dies, and two thirds
        // of the cluster goes with it.
        let noeuds = [
            noeud("swarm-heavy", Some("big-01")),
            noeud("mailcow", Some("big-01")),
            noeud("small-01", Some("small-01")),
        ];
        let d = grouper_par_domaine(&noeuds);

        assert_eq!(d.len(), 2, "three nodes, two pieces of hardware");
        assert_eq!(
            d[0].nom.as_deref(),
            Some("big-01"),
            "most concentrated first"
        );
        assert_eq!(d[0].noeuds.len(), 2);
        assert!(
            d[0].concentre(3),
            "two nodes out of three: losing it takes the quorum"
        );
        assert!(!d[1].concentre(3));
    }

    #[test]
    fn undeclared_nodes_are_grouped_not_assumed_isolated() {
        // ⚠️ Assuming a node with no declared domain is isolated would be exactly the
        // optimistic assumption that creates the illusion we are trying to dispel. We
        // do not know, and that must show.
        let noeuds = [
            noeud("a", None),
            noeud("b", None),
            noeud("c", Some("fer-1")),
        ];
        let d = grouper_par_domaine(&noeuds);

        let unknown = d
            .iter()
            .find(|x| x.nom.is_none())
            .expect("un groupe unknown");
        assert_eq!(unknown.noeuds.len(), 2, "grouped, not one domain each");
        // And it comes last: it is not a proven violation.
        assert!(d.last().is_some_and(|x| x.nom.is_none()));
    }

    #[test]
    fn all_replicas_on_one_box_is_the_worst_case() {
        // 🔴 The service looks redundant and is not at all: the lie Swarm produces
        // when anti-affinity is expressed over `node.id`.
        let noeuds = [
            noeud("vm-a", Some("big-01")),
            noeud("vm-b", Some("big-01")),
            noeud("small-01", Some("small-01")),
        ];
        let placements = [
            ("gitea".to_string(), "vm-a".to_string()),
            ("gitea".to_string(), "vm-b".to_string()),
        ];

        let v = violations_anti_affinite(&placements, &noeuds);
        assert_eq!(v.len(), 1);
        assert!(v[0].totale(), "BOTH replicas are on the same hardware");
        assert!(v[0].describe().contains("illusion"), "{}", v[0].describe());
    }

    #[test]
    fn a_properly_spread_service_raises_nothing() {
        let noeuds = [
            noeud("vm-a", Some("big-01")),
            noeud("small-01", Some("small-01")),
        ];
        let placements = [
            ("gitea".to_string(), "vm-a".to_string()),
            ("gitea".to_string(), "small-01".to_string()),
        ];
        assert!(violations_anti_affinite(&placements, &noeuds).is_empty());
    }

    #[test]
    fn a_single_replica_service_is_never_flagged() {
        // A single-replica service has nothing to spread. Flagging it would be noise
        // - and noise makes people stop reading alerts.
        let noeuds = [noeud("vm-a", Some("big-01"))];
        let placements = [("valkey".to_string(), "vm-a".to_string())];
        assert!(violations_anti_affinite(&placements, &noeuds).is_empty());
    }

    #[test]
    fn a_partial_violation_is_reported_but_ranked_lower() {
        // Three replicas, two in the same place: less serious than "all in the same
        // place", but still redundancy overstated.
        let noeuds = [
            noeud("vm-a", Some("big-01")),
            noeud("vm-b", Some("big-01")),
            noeud("small-01", Some("small-01")),
        ];
        let placements = [
            ("gitea".to_string(), "vm-a".to_string()),
            ("gitea".to_string(), "vm-b".to_string()),
            ("gitea".to_string(), "small-01".to_string()),
        ];

        let v = violations_anti_affinite(&placements, &noeuds);
        assert_eq!(v.len(), 1);
        assert!(!v[0].totale());
        assert_eq!((v[0].replicas, v[0].total), (2, 3));
    }

    #[test]
    fn total_violations_are_listed_before_partial_ones() {
        let noeuds = [
            noeud("vm-a", Some("big-01")),
            noeud("vm-b", Some("big-01")),
            noeud("small-01", Some("small-01")),
        ];
        let placements = [
            // vikunja: all in the same place - the worst case.
            ("vikunja".to_string(), "vm-a".to_string()),
            ("vikunja".to_string(), "vm-b".to_string()),
            // gitea : deux sur trois.
            ("gitea".to_string(), "vm-a".to_string()),
            ("gitea".to_string(), "vm-b".to_string()),
            ("gitea".to_string(), "small-01".to_string()),
        ];

        let v = violations_anti_affinite(&placements, &noeuds);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].service, "vikunja", "la violation totale d'abord");
        assert!(v[0].totale());
    }

    #[test]
    fn an_undeclared_domain_is_not_reported_as_a_proven_violation() {
        // ⚠️ Two replicas on nodes with no declared domain: we do NOT KNOW whether
        // they share hardware. The message must say so, or you go looking for a problem
        // that may not exist.
        let noeuds = [noeud("a", None), noeud("b", None)];
        let placements = [
            ("gitea".to_string(), "a".to_string()),
            ("gitea".to_string(), "b".to_string()),
        ];

        let v = violations_anti_affinite(&placements, &noeuds);
        assert_eq!(v.len(), 1);
        assert!(v[0].domaine.is_none());
        assert!(
            v[0].describe().contains("no declared failure domain"),
            "{}",
            v[0].describe()
        );
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
        assert_eq!(tier_for_memory(8192), "heavy");
        assert_eq!(tier_for_memory(16384), "heavy");
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
            id: "x".into(),
            hostname: "n1".into(),
            role: NodeRole::Manager,
            status: "Ready".into(),
            availability: "active".into(),
            tier: Some("heavy".into()),
            is_leader: true,
            memory_mb: Some(16384),
            failure_domain: None,
        };
        assert!(n.is_ready());
        n.status = "down".into();
        assert!(!n.is_ready());
    }
}
