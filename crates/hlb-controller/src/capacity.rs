//! The capacity budget, before scheduling (batch 9.6).
//!
//! ## 🔴 The symptom we want to avoid
//!
//! An app placed on a tier with no memory left does not return a clear error: Swarm
//! accepts the service, the task is scheduled, the container is killed by the kernel, and
//! `wait_healthy` **times out** — with nothing saying why. You then go looking at the
//! health probe, the image, the network. The 4 GB nodes are protected for exactly this
//! reason.
//!
//! ## What it compares
//!
//! A manifest declares what it reserves (`swarm.memory.reserve`, required in the
//! catalog since 2026-10-19), so the budget says "it needs 512 MB and 300 are left".
//! A manifest of a person's own may still leave it out: then we say what we know,
//! **what is left on the targeted tier**, and never a margin we do not have.
//!
//! ⚠️ "Left" is the agents' `MemAvailable`, not Swarm's unreserved memory: Swarm places
//! by the reservations it holds, and the kernel kills by what is really in use. A node
//! can have room by one and none by the other; this reads the one that kills.

/// What is left on a tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    pub tier: String,
    /// Cumulative available memory, in MB.
    pub available_mb: u64,
    /// The largest node of the tier: IT is what decides, not the sum.
    ///
    /// 🔴 A service is not split across two machines. Two nodes with 400 MB available do
    /// not make 800 MB usable: they make 400.
    pub best_node_mb: u64,
    pub nodes: usize,
    /// Some nodes of the tier do not answer: the budget is a LOWER BOUND.
    pub silent_nodes: usize,
    /// What the service reserves, when its manifest says.
    pub needed_mb: Option<u64>,
}

/// Below this threshold we warn: the 4 GB nodes need protecting.
pub const NARROW_THRESHOLD_MB: u64 = 512;

impl Budget {
    /// The warning to display, if any.
    pub fn warning(&self) -> Option<String> {
        if self.nodes == 0 {
            return Some(format!(
                "No node is labelled \"{}\": nothing will schedule, and the health wait \
                 will time out without explaining why. Set the label: \
                 docker node update --label-add tier={} <node>",
                self.tier, self.tier
            ));
        }

        if let Some(needed) = self.needed_mb {
            if needed > self.best_node_mb {
                return Some(format!(
                    "It reserves {needed} MB, and the largest node of tier \"{}\" has {} MB \
                     available{}. It may wait unplaced, or be killed for lack of memory \
                     with nothing saying so.",
                    self.tier,
                    self.best_node_mb,
                    if self.silent_nodes > 0 {
                        " — some nodes do not answer, so that is a lower bound"
                    } else {
                        ""
                    }
                ));
            }
            // What it needs fits: a narrow node is no news.
            return None;
        }

        if self.best_node_mb < NARROW_THRESHOLD_MB {
            return Some(format!(
                "Tier \"{}\" only has {} MB available on its largest node. A container \
                 killed for lack of memory says nothing: the install will fail on a \
                 health wait that timed out.",
                self.tier, self.best_node_mb
            ));
        }

        if self.silent_nodes > 0 {
            // We do not know what those machines have: the figure shown is a lower
            // bound, and saying so beats letting it pass for a measurement.
            return Some(format!(
                "{} of tier \"{}\" do not answer: {} MB is a LOWER BOUND, not a \
                 measurement.",
                hlb_api::plural(self.silent_nodes as u64, "node", "nodes"),
                self.tier,
                self.available_mb
            ));
        }

        None
    }
}

/// What is left on a tier.
///
/// `fleet_nodes`: for each machine, its tier (`None` = unknown) and its free
/// memory (`None` = the agent does not answer).
///
/// ⚠️ The join between the Swarm inventory and the agent reports is done by the caller:
/// it goes through the hostname, a rule that already lives in the API and that we do not
/// duplicate here.
pub fn budget(fleet_nodes: &[(Option<String>, Option<u64>)], tier: &str) -> Budget {
    let mut available_mb = 0u64;
    let mut best = 0u64;
    let mut nodes = 0usize;
    let mut silent = 0usize;

    for (its_tier, available) in fleet_nodes {
        // ⚠️ A node whose tier is unknown is NOT assumed to belong to this one: assuming
        // would announce space where there is none. A heavy node does take a light app.
        if !its_tier
            .as_deref()
            .is_some_and(|t| hlb_types::manifest::tier_admits(t, tier))
        {
            continue;
        }
        nodes += 1;

        match available {
            Some(mb) => {
                available_mb += mb;
                best = best.max(*mb);
            }
            None => silent += 1,
        }
    }

    Budget {
        tier: tier.to_string(),
        available_mb,
        best_node_mb: best,
        nodes,
        silent_nodes: silent,
        needed_mb: None,
    }
}

impl Budget {
    /// The same budget, judged against what the service reserves.
    pub fn needing(mut self, memory: Option<hlb_types::Memory>) -> Self {
        self.needed_mb = memory.map(|m| m.reserve.mib());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_heavy_node_counts_toward_a_light_app_and_never_the_reverse() {
        let f = fleet(&[("heavy", Some(6000)), ("light", Some(1000))]);
        assert_eq!(budget(&f, "light").nodes, 2);
        assert_eq!(budget(&f, "light").available_mb, 7000);
        assert_eq!(budget(&f, "heavy").nodes, 1);
        assert_eq!(budget(&f, "heavy").available_mb, 6000);
    }

    fn fleet(v: &[(&str, Option<u64>)]) -> Vec<(Option<String>, Option<u64>)> {
        v.iter()
            .map(|(tier, mb)| (Some(tier.to_string()), *mb))
            .collect()
    }

    #[test]
    fn two_small_nodes_do_not_add_up_to_one_big_one() {
        // 🔴 The heart of the calculation: a service is not split across two machines.
        // Adding up would give "800 MB available" and would let you install an app
        // neither node can carry.
        let b = budget(
            &fleet(&[("light", Some(400)), ("light", Some(400))]),
            "light",
        );

        assert_eq!(b.available_mb, 800);
        assert_eq!(b.best_node_mb, 400, "the largest one decides");
        assert!(b.warning().is_some(), "400 MB is below the threshold");
    }

    #[test]
    fn a_tier_with_no_node_is_named_as_such() {
        // ⚠️ The project's documented trap: without a tier label, nothing schedules and
        // `wait_healthy` times out without saying why.
        let b = budget(&fleet(&[("light", Some(2_000))]), "heavy");

        assert_eq!(b.nodes, 0);
        let a = b.warning().expect("a warning");
        assert!(a.contains("label-add tier=heavy"), "{a}");
    }

    #[test]
    fn a_node_of_unknown_tier_is_never_counted_in() {
        // Assuming membership would announce space where there is none.
        let b = budget(&[(None, Some(8_000))], "light");

        assert_eq!(b.nodes, 0);
        assert_eq!(b.available_mb, 0);
    }

    #[test]
    fn a_silent_node_makes_the_figure_a_lower_bound() {
        // The figure stays useful, but it must not pass for a measurement.
        let b = budget(&fleet(&[("light", Some(3_000)), ("light", None)]), "light");

        assert_eq!(b.silent_nodes, 1);
        let a = b.warning().expect("a warning");
        assert!(a.contains("LOWER BOUND"), "{a}");
    }

    fn reserving(mb: &str) -> Option<hlb_types::Memory> {
        let b = |s: &str| hlb_types::manifest::Bytes::try_from(s.to_string()).expect("size");
        Some(hlb_types::Memory {
            reserve: b(mb),
            limit: b("4G"),
        })
    }

    #[test]
    fn what_a_service_reserves_is_compared_with_the_largest_node() {
        let f = fleet(&[("light", Some(300)), ("light", Some(300))]);
        let a = budget(&f, "light")
            .needing(reserving("512M"))
            .warning()
            .expect("a warning");
        assert!(a.contains("reserves 512 MB") && a.contains("300 MB"), "{a}");
        // 300 MB left is narrow, and no news for a service reserving 64.
        assert_eq!(
            budget(&f, "light").needing(reserving("64M")).warning(),
            None
        );
        // A tier with no node is said whatever the service needs.
        let none = budget(&f, "heavy").needing(reserving("64M"));
        assert!(none.warning().expect("a warning").contains("label-add"));
    }

    #[test]
    fn a_comfortable_tier_says_nothing_at_all() {
        // 🔴 A warning displayed permanently stops being read.
        let b = budget(
            &fleet(&[("heavy", Some(12_000)), ("heavy", Some(9_000))]),
            "heavy",
        );
        assert_eq!(b.warning(), None);
    }
}
