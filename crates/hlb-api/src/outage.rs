//! "What if it went down?" — the failure simulator.
//!
//! ## What it adds
//!
//! The topology view DRAWS the failure domains; it does not say what you would lose.
//! The simulator turns the drawing into an answer: which services lose every replica,
//! which survive diminished, whether quorum holds, and which backup destinations become
//! unreachable.
//!
//! ## 🔴 A DOMAIN is simulated, not a machine
//!
//! Two VMs on the same server are two Swarm nodes and **one** point of failure.
//! Simulating the loss of "one node" on such an installation underestimates exactly
//! what anti-affinity is supposed to prevent: you would conclude "the app survives"
//! when both its replicas go out together.
//!
//! An **undeclared** domain is not an isolated domain: each node without a domain is
//! simulated alone, and the result says so — assuming isolation would be the optimistic
//! assumption that creates the illusion of redundancy.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{DomainSummary, Topology};

/// What we bring down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    /// A declared failure domain, with every node it carries.
    Domain(String),
    /// A node whose domain is undeclared: only it can be simulated.
    Node(String),
}

impl Target {
    pub fn name(&self) -> &str {
        match self {
            Self::Domain(n) | Self::Node(n) => n,
        }
    }
}

judged! {
    /// The result of a simulation.
    #[derive(Debug, Clone, PartialEq)]
    pub struct Simulation {
        pub target: Target,
        /// The nodes that disappear together.
        pub lost_nodes: Vec<String>,
        /// The nodes that remain.
        pub remaining_nodes: usize,
        /// 🔴 Services whose replicas were ALL on the target: they stop.
        pub services_lost: Vec<String>,
        /// Services that survive, but with fewer replicas.
        pub services_reduced: Vec<ReducedService>,
        /// What becomes of the Swarm quorum.
        pub quorum: Quorum,
        /// ⚠️ True when the target is a node with no declared domain: the result is then a
        /// **lower bound** on what would really be lost.
        pub unknown_domain: bool,
    }

    rules {
        attention: crate::Attention = Simulation::attention,
    }
}

/// A service that survives diminished.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ReducedService {
    pub service: String,
    pub before: usize,
    pub after: usize,
}

/// What becomes of quorum after the failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Quorum {
    /// The cluster can still be steered.
    Holds,
    /// 🔴 Quorum is lost: nothing schedules and nothing repairs any more.
    Lost,
    /// Which nodes are managers is unknown.
    Unknown,
}

impl Simulation {
    /// Is there anything to fear?
    pub fn attention(&self) -> crate::Attention {
        if !self.services_lost.is_empty() || self.quorum == Quorum::Lost {
            crate::Attention::Critical
        } else if !self.services_reduced.is_empty() || self.unknown_domain {
            crate::Attention::Notice
        } else {
            crate::Attention::Ok
        }
    }

    /// The answer in one sentence.
    pub fn verdict(&self) -> String {
        let what = match self.target {
            Target::Domain(_) => "this failure domain",
            Target::Node(_) => "this node",
        };

        // ⚠️ The warning about an undeclared domain is appended at the END, whichever
        // branch ran: a first draft placed it after an early `return`, and it vanished
        // in precisely the gravest case.
        let mut sentence = if self.remaining_nodes == 0 {
            // The case a service count would miss: nothing remains to carry anything,
            // and "0 services lost" would read as "nothing to fear".
            format!("If {what} went down, NO node would remain: everything stops.")
        } else {
            self.services_sentence(what)
        };

        match self.quorum {
            Quorum::Lost => sentence.push_str(
                " Swarm quorum would be LOST: nothing schedules and nothing repairs \
                 until a manager comes back.",
            ),
            Quorum::Holds => sentence.push_str(" Quorum would hold."),
            Quorum::Unknown => {}
        }

        if self.unknown_domain {
            sentence.push_str(
                " Careful: this node has no declared failure domain. If it shares a \
                 server or a power supply with another, the real loss would be larger \
                 than this one.",
            );
        }

        sentence
    }

    /// The "which services" part of the verdict.
    fn services_sentence(&self, what: &str) -> String {
        // ⚠️ The count agrees through `plural`: "1 services would stop" reads as a typo
        // and makes you doubt the rest of the screen. Seen exactly like that on
        // display. English needs no verb agreement here, so only the noun is agreed.
        let mut sentence = if self.services_lost.is_empty() {
            format!("If {what} went down, no service would stop")
        } else {
            format!(
                "If {what} went down, {} would stop: {}",
                crate::plural(self.services_lost.len() as u64, "service", "services"),
                self.services_lost.join(", ")
            )
        };

        if !self.services_reduced.is_empty() {
            sentence.push_str(&format!(
                ", and {} would continue with fewer replicas",
                crate::plural(self.services_reduced.len() as u64, "service", "services")
            ));
        }

        sentence.push('.');
        sentence
    }
}

/// Simulates losing each domain, and each node with no declared domain.
///
/// `managers`: the identifiers of the manager nodes, when they are known.
pub fn simulate_all(topo: &Topology, managers: &[String]) -> Vec<Simulation> {
    let mut out = Vec::new();
    for d in &topo.domains {
        match &d.name {
            Some(name) => out.push(simulate(topo, Target::Domain(name.clone()), managers)),
            // 🔴 The "we do not know" group is NOT a domain: its nodes do not fall
            // together by construction, they are merely unclassified. Simulating them
            // together would invent a correlation; ignoring them would leave those
            // machines out of the exercise. So they are simulated one by one.
            None => {
                for n in &d.nodes {
                    out.push(simulate(topo, Target::Node(n.id.clone()), managers));
                }
            }
        }
    }
    // The worst first: that is the one you want to read.
    out.sort_by(|a, b| {
        b.services_lost
            .len()
            .cmp(&a.services_lost.len())
            .then_with(|| a.target.name().cmp(b.target.name()))
    });
    out
}

/// Simulates the loss of a target.
pub fn simulate(topo: &Topology, target: Target, managers: &[String]) -> Simulation {
    let in_target = |d: &DomainSummary, id: &str| match &target {
        Target::Domain(name) => d.name.as_deref() == Some(name.as_str()),
        Target::Node(n) => n == id,
    };

    let mut lost = Vec::new();
    let mut remaining = 0usize;
    let mut before: std::collections::BTreeMap<String, usize> = Default::default();
    let mut after: std::collections::BTreeMap<String, usize> = Default::default();
    let mut unknown_domain = false;

    for d in &topo.domains {
        for n in &d.nodes {
            for s in &n.services {
                *before.entry(s.clone()).or_default() += 1;
            }
            if in_target(d, &n.id) {
                lost.push(n.id.clone());
                if d.name.is_none() {
                    unknown_domain = true;
                }
            } else {
                remaining += 1;
                for s in &n.services {
                    *after.entry(s.clone()).or_default() += 1;
                }
            }
        }
    }

    let mut services_lost = Vec::new();
    let mut services_reduced = Vec::new();
    for (service, n_before) in &before {
        let n_after = after.get(service).copied().unwrap_or(0);
        if n_after == 0 {
            services_lost.push(service.clone());
        } else if n_after < *n_before {
            services_reduced.push(ReducedService {
                service: service.clone(),
                before: *n_before,
                after: n_after,
            });
        }
    }

    let quorum = if managers.is_empty() {
        Quorum::Unknown
    } else {
        let survivors = managers.iter().filter(|m| !lost.contains(m)).count();
        // Swarm requires a STRICT MAJORITY of the declared managers, not half: out of
        // four managers, two survivors are not enough.
        if survivors * 2 > managers.len() {
            Quorum::Holds
        } else {
            Quorum::Lost
        }
    };

    Simulation {
        target,
        lost_nodes: lost,
        remaining_nodes: remaining,
        services_lost,
        services_reduced,
        quorum,
        unknown_domain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeInDomain;

    fn node(id: &str, services: &[&str]) -> NodeInDomain {
        NodeInDomain {
            id: id.into(),
            hostname: id.into(),
            tier: None,
            reachable: true,
            services: services.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn topo(domains: Vec<(Option<&str>, Vec<NodeInDomain>)>) -> Topology {
        Topology {
            managers: Vec::new(),
            total_nodes: domains.iter().map(|(_, n)| n.len()).sum(),
            domains: domains
                .into_iter()
                .map(|(name, nodes)| DomainSummary {
                    name: name.map(str::to_string),
                    concentrated: false,
                    nodes,
                })
                .collect(),
            violations: Vec::new(),
        }
    }

    #[test]
    fn two_replicas_in_the_same_domain_do_not_survive_that_domain() {
        // 🔴 The heart of the simulator. Swarm returns an illusion of redundancy: two
        // replicas "on two nodes", therefore "spread". Both nodes are two VMs of the
        // same server, and the service goes out entirely with it.
        let t = topo(vec![
            (
                Some("server-a"),
                vec![node("vm-1", &["gitea"]), node("vm-2", &["gitea"])],
            ),
            (Some("server-b"), vec![node("vm-3", &["immich"])]),
        ]);

        let s = simulate(&t, Target::Domain("server-a".into()), &[]);
        assert_eq!(s.services_lost, vec!["gitea"]);
        assert_eq!(s.lost_nodes.len(), 2);
        assert_eq!(s.attention(), crate::Attention::Critical);

        // The same installation, simulated node by node, would say the exact opposite.
        let per_node = simulate(&t, Target::Node("vm-1".into()), &[]);
        assert!(per_node.services_lost.is_empty());
        assert_eq!(per_node.services_reduced[0].after, 1);
    }

    #[test]
    fn a_surviving_service_is_not_the_same_as_an_untouched_one() {
        // A service going from 3 replicas to 1 survives, but has no margin left: calling
        // it "intact" would make you miss the next failure.
        let t = topo(vec![
            (Some("a"), vec![node("n1", &["web"]), node("n2", &["web"])]),
            (Some("b"), vec![node("n3", &["web"])]),
        ]);
        let s = simulate(&t, Target::Domain("a".into()), &[]);
        assert!(s.services_lost.is_empty());
        assert_eq!(
            s.services_reduced,
            vec![ReducedService {
                service: "web".into(),
                before: 3,
                after: 1
            }]
        );
        assert_eq!(s.attention(), crate::Attention::Notice);
    }

    #[test]
    fn an_undeclared_domain_is_simulated_alone_and_says_so() {
        // ⚠️ Assuming isolation would be the optimistic assumption that creates the
        // illusion. The result is a LOWER BOUND, and the screen must say so.
        let t = topo(vec![(None, vec![node("orphelin", &["vaultwarden"])])]);
        let s = simulate(&t, Target::Node("orphelin".into()), &[]);

        assert!(s.unknown_domain);
        assert!(
            s.verdict().contains("larger than this one"),
            "{}",
            s.verdict()
        );
        // And it cannot be "Ok": what would really be lost is unknown.
        assert_ne!(s.attention(), crate::Attention::Ok);
    }

    #[test]
    fn the_undeclared_domain_warning_survives_the_total_loss_case() {
        // 🔴 The defect as it showed up: an early `return` for "no node remains" skipped
        // the warning. It therefore vanished in the gravest case — the one where you
        // most need to know the displayed figure is a lower bound.
        let t = topo(vec![(None, vec![node("seul", &["gitea"])])]);
        let s = simulate(&t, Target::Node("seul".into()), &[]);
        assert_eq!(s.remaining_nodes, 0);
        assert!(s.verdict().contains("NO node"), "{}", s.verdict());
        assert!(
            s.verdict().contains("larger than this one"),
            "{}",
            s.verdict()
        );
    }

    #[test]
    fn undeclared_nodes_are_never_simulated_as_falling_together() {
        // They are not correlated: they are merely unclassified. Failing them together
        // would invent a correlation, and the worst case displayed would be wrong.
        let t = topo(vec![(None, vec![node("a", &["x"]), node("b", &["y"])])]);
        let sims = simulate_all(&t, &[]);
        assert_eq!(sims.len(), 2, "one per node, not one for the group");
        for s in &sims {
            assert_eq!(s.lost_nodes.len(), 1);
        }
    }

    #[test]
    fn losing_the_majority_of_managers_loses_the_quorum() {
        let t = topo(vec![
            (Some("a"), vec![node("m1", &[]), node("m2", &[])]),
            (Some("b"), vec![node("m3", &[])]),
        ]);
        let managers = vec!["m1".to_string(), "m2".into(), "m3".into()];

        let loss = simulate(&t, Target::Domain("a".into()), &managers);
        assert_eq!(loss.quorum, Quorum::Lost);
        assert!(loss.verdict().contains("LOST"), "{}", loss.verdict());

        let ok = simulate(&t, Target::Domain("b".into()), &managers);
        assert_eq!(ok.quorum, Quorum::Holds);
    }

    #[test]
    fn exactly_half_the_managers_is_not_a_majority() {
        // Swarm requires a STRICT majority. Out of four managers, two survivors are not
        // enough — and a naive `>=` would conclude the cluster holds.
        let t = topo(vec![
            (Some("a"), vec![node("m1", &[]), node("m2", &[])]),
            (Some("b"), vec![node("m3", &[]), node("m4", &[])]),
        ]);
        let managers = vec!["m1".to_string(), "m2".into(), "m3".into(), "m4".into()];
        assert_eq!(
            simulate(&t, Target::Domain("a".into()), &managers).quorum,
            Quorum::Lost
        );
    }

    #[test]
    fn an_unknown_manager_list_is_never_reported_as_a_healthy_quorum() {
        // Not knowing is not reassuring. `Unknown` is distinct from `Holds`, and the
        // verdict stays silent rather than asserting.
        let t = topo(vec![(Some("a"), vec![node("n1", &["gitea"])])]);
        let s = simulate(&t, Target::Domain("a".into()), &[]);
        assert_eq!(s.quorum, Quorum::Unknown);
        assert!(!s.verdict().contains("quorum"), "{}", s.verdict());
    }

    #[test]
    fn the_noun_agrees_with_the_number_of_services() {
        // 🔴 Seen on screen: "1 services would stop". An agreement mistake makes you
        // doubt everything else, so the count goes through `plural`.
        let t = topo(vec![
            (
                Some("gros"),
                vec![node("n1", &["a", "b"]), node("n2", &["c"])],
            ),
            (Some("other"), vec![node("n3", &["d"])]),
        ]);
        let several = simulate(&t, Target::Domain("gros".into()), &[]);
        assert!(
            several.verdict().contains("3 services would stop"),
            "{}",
            several.verdict()
        );

        let un = simulate(&t, Target::Domain("other".into()), &[]);
        assert!(
            un.verdict().contains("1 service would stop"),
            "{}",
            un.verdict()
        );
    }

    #[test]
    fn losing_everything_is_not_reported_as_losing_nothing() {
        // A single-node cluster: there is no "diminished" service, and a naive count
        // would print a reassuring sentence about a cluster that is entirely dark.
        let t = topo(vec![(Some("seul"), vec![node("n1", &["gitea"])])]);
        let s = simulate(&t, Target::Domain("seul".into()), &[]);
        assert_eq!(s.remaining_nodes, 0);
        assert!(s.verdict().contains("NO node"), "{}", s.verdict());
    }

    #[test]
    fn the_worst_case_is_listed_first() {
        // It is the one you want to read: a screen sorted by name would make you hunt.
        let t = topo(vec![
            (Some("petit"), vec![node("n1", &["a"])]),
            (
                Some("gros"),
                vec![node("n2", &["b", "c", "d"]), node("n3", &["e"])],
            ),
        ]);
        let sims = simulate_all(&t, &[]);
        assert_eq!(sims[0].target, Target::Domain("gros".into()));
    }
}
