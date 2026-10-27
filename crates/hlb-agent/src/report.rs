//! What the agent reports to the controller.
//!
//! Deliberately minimal: a report nobody knows how to use is noise costing bandwidth
//! and attention. Every field here feeds a concrete decision.

use serde::{Deserialize, Serialize};

use crate::disk::{DiskPressure, DiskUsage, Thresholds};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct NodeReport {
    pub hostname: String,
    /// Unix timestamp. Used to detect a silent agent, not merely to date the report.
    pub at: u64,
    pub disks: Vec<DiskUsage>,
    pub memory_total_mb: Option<u64>,
    pub memory_available_mb: Option<u64>,
    /// The agent's version: a cluster with mismatched agents is a trap.
    pub agent_version: String,
    /// The DIALOGUE version, distinct from the binary's.
    ///
    /// ⚠️ `serde(default)`: an agent predating this field does not send it, and its
    /// reply must stay readable. Without that, the first update would make every agent
    /// "unreachable" - exactly when they are needed.
    #[serde(default)]
    pub protocol: u32,

    // ─── Protocol 2 ─────────────────────────────────────────────────────────
    //
    // 🔴 ALL `Option` + `serde(default)`. A protocol 1 agent does not send them, and its
    // report must stay readable: that is what allows updating the controller before the
    // agents, or the other way round, without the whole fleet going "unreachable".
    //
    // And `Option` rather than `0`: "I do not know" and "zero" do not read the same. A
    // CPU at 0 % says "idle", an empty cell says "check this".
    // 🔴 Renaming a field here changes the JSON key, and the protocol must stay
    // readable BOTH ways — a new controller against old agents, and an old controller
    // against new agents. A renamed key breaks the second direction in SILENCE:
    // `serde(default)` hands back `None`, and the whole fleet reads as "no measurement"
    // precisely when you are looking at it. Safe to do today only because nothing is
    // deployed; from the first release, add a field, never rename one.
    /// Core count. Without it, load is not comparable between machines.
    #[serde(default)]
    pub cpu_cores: Option<u32>,
    #[serde(default)]
    pub load: Option<crate::system::LoadAverage>,
    /// CPU usage rate in `[0, 1]`.
    ///
    /// ⚠️ `None` on the very first reading: computing a difference needs two reads of
    /// `/proc/stat`.
    #[serde(default)]
    pub cpu_busy: Option<f64>,
    #[serde(default)]
    pub swap_total_mb: Option<u64>,
    #[serde(default)]
    pub swap_used_mb: Option<u64>,
    #[serde(default)]
    pub interfaces: Vec<crate::system::Interface>,
    #[serde(default)]
    pub system: Option<crate::system::System>,
    /// Waiting for a reboot to run its newest kernel. `None`: could not tell — a
    /// protocol 2 agent does not send it, nor one that cannot see the host.
    #[serde(default)]
    pub reboot_required: Option<bool>,
}

impl NodeReport {
    /// The strongest pressure across every filesystem.
    ///
    /// The worst is what counts: a saturated `/var/lib/docker` breaks everything, even
    /// with `/` half empty.
    pub fn worst_pressure(&self, t: &Thresholds) -> DiskPressure {
        self.disks
            .iter()
            .map(|d| d.pressure(t))
            .max()
            .unwrap_or(DiskPressure::Normal)
    }

    /// Can this node host a deployment?
    pub fn allows_deploy(&self, t: &Thresholds) -> bool {
        self.worst_pressure(t).allows_deploy()
    }

    /// The filesystems in trouble, worst first.
    pub fn problems(&self, t: &Thresholds) -> Vec<(&DiskUsage, DiskPressure)> {
        let mut p: Vec<_> = self
            .disks
            .iter()
            .map(|d| (d, d.pressure(t)))
            .filter(|(_, pr)| *pr > DiskPressure::Normal)
            .collect();
        // Descending: the most critical first, because that is what gets read first.
        p.sort_by_key(|(_, pressure)| std::cmp::Reverse(*pressure));
        p
    }

    /// The load divided by the core count - the only comparable figure across a
    /// heterogeneous fleet.
    pub fn load_per_core(&self) -> Option<f64> {
        self.load?.per_core(self.cpu_cores?)
    }

    /// Memory used, as a fraction in `[0, 1]`.
    ///
    /// ⚠️ Computed over **available** memory, not "total minus free": Linux caches
    /// everything it can, and "free" is almost always near zero on a healthy machine.
    /// Trusting "free" would cry out-of-memory permanently.
    pub fn memory_used(&self) -> Option<f64> {
        let t = self.memory_total_mb?;
        let d = self.memory_available_mb?;
        (t > 0).then(|| ((t.saturating_sub(d)) as f64 / t as f64).clamp(0.0, 1.0))
    }

    /// Is the machine swapping to disk?
    ///
    /// 🔴 Swap starting to be used is an EARLY signal: the machine slows without having
    /// failed yet, and that is the moment to act. The threshold is low (5 %) for that
    /// reason - waiting for saturation would be waiting too long.
    pub fn swap_on_disk(&self) -> bool {
        match (self.swap_total_mb, self.swap_used_mb) {
            (Some(t), Some(u)) if t > 0 => (u as f64 / t as f64) > 0.05,
            _ => false,
        }
    }

    /// Has the agent shown signs of life recently?
    ///
    /// A silent agent is information: the node may be unreachable, and its data is
    /// therefore no longer being backed up.
    pub fn is_stale(&self, now: u64, max_age_secs: u64) -> bool {
        now.saturating_sub(self.at) > max_age_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(path: &str, total: u64, used: u64) -> DiskUsage {
        DiskUsage {
            path: path.into(),
            total_mb: total,
            used_mb: used,
            free_mb: total - used,
        }
    }

    fn report(disks: Vec<DiskUsage>) -> NodeReport {
        NodeReport {
            hostname: "node1".into(),
            at: 1_000_000,
            disks,
            memory_total_mb: Some(16384),
            memory_available_mb: Some(8192),
            agent_version: "0.1.0".into(),
            protocol: 1,
            ..Default::default()
        }
    }

    #[test]
    fn the_worst_filesystem_decides() {
        // 🔴 A saturated /var/lib/docker breaks everything, even with / half empty.
        let r = report(vec![
            disk("/", 100_000, 30_000),
            // 48/50 GB = 96 %, past the critical threshold.
            disk("/var/lib/docker", 50_000, 48_000),
        ]);
        assert_eq!(
            r.worst_pressure(&Thresholds::default()),
            DiskPressure::Critical
        );
        assert!(!r.allows_deploy(&Thresholds::default()));
    }

    #[test]
    fn a_healthy_node_accepts_deployments() {
        let r = report(vec![disk("/", 100_000, 40_000)]);
        assert!(r.allows_deploy(&Thresholds::default()));
        assert!(r.problems(&Thresholds::default()).is_empty());
    }

    #[test]
    fn problems_are_sorted_worst_first() {
        let r = report(vec![
            disk("/a", 100_000, 78_000),
            disk("/b", 100_000, 96_000),
            disk("/c", 100_000, 87_000),
        ]);
        let p = r.problems(&Thresholds::default());
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].0.path, "/b", "the most critical first");
        assert_eq!(p[0].1, DiskPressure::Critical);
    }

    #[test]
    fn a_node_without_disks_is_not_assumed_broken() {
        let r = report(Vec::new());
        assert_eq!(
            r.worst_pressure(&Thresholds::default()),
            DiskPressure::Normal
        );
        assert!(r.allows_deploy(&Thresholds::default()));
    }

    #[test]
    fn a_silent_agent_is_detected() {
        // A silent agent may mean an unreachable node - whose data is therefore no
        // longer being backed up.
        let r = report(vec![disk("/", 100, 10)]);
        assert!(!r.is_stale(1_000_060, 120));
        assert!(r.is_stale(1_000_300, 120));
    }

    #[test]
    fn a_clock_going_backwards_does_not_panic() {
        // Two badly synchronised machines can produce a "now" that is in the past.
        let r = report(vec![disk("/", 100, 10)]);
        assert!(!r.is_stale(999_000, 120));
    }

    #[test]
    fn a_protocol_1_agent_stays_readable() {
        // 🔴 THE compatibility test. Without it, the first controller update would make
        // every agent "unreachable" - exactly when they need to be seen.
        let old = r#"{
            "hostname": "small-01",
            "at": 1000,
            "disks": [{"path":"/","total_mb":100,"used_mb":40,"free_mb":60}],
            "memory_total_mb": 4096,
            "memory_available_mb": 2048,
            "agent_version": "0.1.0",
            "protocol": 1
        }"#;
        let r: NodeReport = serde_json::from_str(old).expect("a v1 agent stays readable");
        assert_eq!(r.hostname, "small-01");
        assert_eq!(r.protocol, 1);
        // The protocol-2 measurements are absent — and that is what must be shown:
        // "unknown", not "0 %".
        assert_eq!(r.cpu_busy, None);
        assert_eq!(r.load, None);
        assert!(r.interfaces.is_empty());
        // But what it did send stays usable.
        assert_eq!(r.memory_used(), Some(0.5));
    }

    #[test]
    fn a_controller_that_predates_a_field_ignores_it() {
        // The other direction: a v2 report must stay readable by code that knows only
        // part of it. `deny_unknown_fields` here would break updating in the reverse
        // order.
        let future = r#"{
            "hostname": "n1", "at": 1, "disks": [],
            "memory_total_mb": null, "memory_available_mb": null,
            "agent_version": "9.9.9", "protocol": 99,
            "a_field_from_the_future": {"quelconque": true}
        }"#;
        let r: NodeReport = serde_json::from_str(future).expect("an unknown field is ignored");
        assert_eq!(r.protocol, 99);
    }

    #[test]
    fn memory_pressure_is_measured_on_available_not_free() {
        // ⚠️ Linux caches everything it can: "free" is almost always near zero on a
        // healthy machine. Trusting it would cry out-of-memory permanently, and people
        // would stop listening.
        let mut r = report(Vec::new());
        r.memory_total_mb = Some(16_000);
        r.memory_available_mb = Some(4_000);
        assert_eq!(r.memory_used(), Some(0.75));

        r.memory_available_mb = None;
        assert_eq!(r.memory_used(), None, "unknown, not 100 %");
    }

    #[test]
    fn swapping_is_detected_before_the_machine_is_stuck() {
        // 🔴 Swap starting to be used is an early signal: the machine slows without
        // having failed yet. Waiting for saturation would be waiting too long.
        let mut r = report(Vec::new());
        r.swap_total_mb = Some(2_000);

        r.swap_used_mb = Some(0);
        assert!(!r.swap_on_disk());
        r.swap_used_mb = Some(50);
        assert!(!r.swap_on_disk(), "2.5 %: noise");
        r.swap_used_mb = Some(200);
        assert!(r.swap_on_disk(), "10 %: it is starting");

        // With no swap configured, no alert - and above all no division by zero.
        r.swap_total_mb = Some(0);
        assert!(!r.swap_on_disk());
    }

    #[test]
    fn load_without_a_core_count_is_not_reported() {
        // A raw load with no core count is not comparable: better to say nothing than
        // to show a figure that will be read wrongly.
        let mut r = report(Vec::new());
        r.load = Some(crate::system::LoadAverage {
            one_min: 8.0,
            five_min: 6.0,
            fifteen_min: 4.0,
        });
        assert_eq!(r.load_per_core(), None);

        r.cpu_cores = Some(4);
        assert_eq!(r.load_per_core(), Some(2.0));
    }

    #[test]
    fn a_report_survives_a_json_roundtrip() {
        // The agent and the controller can be on different versions: the format must
        // stay readable on both sides.
        let r = report(vec![disk("/", 100_000, 50_000)]);
        let j = serde_json::to_string(&r).expect("serialisable");
        let reread: NodeReport = serde_json::from_str(&j).expect("relisible");
        assert_eq!(reread, r);
    }
}
