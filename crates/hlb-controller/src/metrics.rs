//! Metrics in Prometheus format.
//!
//! ## Why so few metrics
//!
//! The temptation is to export everything measurable. That is a mistake: a metric you
//! never use costs storage, adds noise to the dashboards, and hides the ones that
//! matter.
//!
//! So we only export what we would **act on**:
//!
//! - the age of the last successful backup — a backup that has stopped running is
//!   invisible until the day you need it;
//! - the age of the last restore **verification** — a backup never restored is not a
//!   backup;
//! - the pending blocking manual actions;
//! - disk usage per node;
//! - unreachable nodes.
//!
//! CPU and load are not here: they trigger no decision at this level. Docker and the
//! kernel already expose them for whoever wants to look.
//!
//! ## On the format
//!
//! The text is produced by hand rather than with a client library. The Prometheus
//! exposure format fits in a few lines, and one more dependency to concatenate strings
//! is not justified.

use std::fmt::Write as _;

use std::collections::BTreeMap;

use hlb_agent::{DiskPressure, Thresholds};

use crate::agents::AgentStatus;

/// A sample ready to render.
#[derive(Debug, Clone, PartialEq)]
pub struct AppMetrics {
    pub name: String,
    pub status: String,
    pub last_backup_secs: Option<i64>,
    pub last_verification_secs: Option<i64>,
    pub blocking_guides: i64,
}

/// Escapes a Prometheus label value.
///
/// An app name should never contain a quote, but a malformed metric makes the collector
/// reject the **whole** batch — not only the offending line.
fn label(v: &str) -> String {
    v.replace('\\', r"\\")
        .replace('"', "\\\"")
        .replace('\n', r"\n")
}

fn header(out: &mut String, name: &str, help: &str, kind_of: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind_of}");
}

/// Renders the whole set of metrics.
pub fn render(apps: &[AppMetrics], nodes: &BTreeMap<String, AgentStatus>) -> String {
    render_with_coverage(apps, nodes, &[])
}

/// Renders the metrics, backup coverage included.
pub fn render_with_coverage(
    apps: &[AppMetrics],
    nodes: &BTreeMap<String, AgentStatus>,
    coverages: &[hlb_backup::Coverage],
) -> String {
    let mut o = render_base(apps, nodes);

    header(
        &mut o,
        "hlb_backup_copies",
        "Number of UP-TO-DATE copies of an app holding data. This is the 3-2-1 number.",
        "gauge",
    );
    // 🔴 Only the apps holding something to back up: `backup-absent` counts the apps
    // owed a backup by this series, and `single-copy` reads its minimum — Valkey's 0
    // fired both forever.
    for c in coverages.iter().filter(|c| c.needs_backup()) {
        // 🔴 The number of DECLARED destinations says nothing about the number of
        // copies: a failing destination is a destination that protects nothing. It is
        // `up_to_date_copies()` that counts, and it is that number the `single-copy` rule
        // expected — the rule that until now queried a metric that did not exist.
        let _ = writeln!(
            o,
            "hlb_backup_copies{{app=\"{}\"}} {}",
            label(&c.app),
            c.up_to_date_copies()
        );
    }

    o
}

/// Whether `app-failed` should hold an app as up. 🔴 Read as "running" only, every
/// install longer than an alert pass raised a CRITICAL "app failed" that pierced quiet
/// hours, and a `partial` app — deployed and serving, a step left to a person, a
/// notice in the inbox — kept it raised forever. `installing` is a run under way: one
/// that fails says `failed`, and that is the one to wake someone for. A status this
/// does not know is not up.
fn is_up(status: &str) -> bool {
    matches!(status, "running" | "partial" | "installing")
}

fn render_base(apps: &[AppMetrics], nodes: &BTreeMap<String, AgentStatus>) -> String {
    let mut o = String::new();

    header(
        &mut o,
        "hlb_app_up",
        "0 if the app failed, 1 while it runs, runs partially or installs.",
        "gauge",
    );
    for a in apps {
        let _ = writeln!(
            o,
            "hlb_app_up{{app=\"{}\",status=\"{}\"}} {}",
            label(&a.name),
            label(&a.status),
            u8::from(is_up(&a.status))
        );
    }

    header(
        &mut o,
        "hlb_backup_age_seconds",
        "Age of the last successful backup. Absent if none has ever succeeded.",
        "gauge",
    );
    for a in apps {
        // 🔴 We emit NOTHING rather than a 0 or a -1 when there has never been a
        // backup. A 0 would mean "backed up just now" — exactly the opposite, and the
        // alert would never fire.
        if let Some(s) = a.last_backup_secs {
            let _ = writeln!(
                o,
                "hlb_backup_age_seconds{{app=\"{}\"}} {s}",
                label(&a.name)
            );
        }
    }

    header(
        &mut o,
        "hlb_backup_verification_age_seconds",
        "Age of the last successful restore verification.",
        "gauge",
    );
    for a in apps {
        if let Some(s) = a.last_verification_secs {
            let _ = writeln!(
                o,
                "hlb_backup_verification_age_seconds{{app=\"{}\"}} {s}",
                label(&a.name)
            );
        }
    }

    header(
        &mut o,
        "hlb_blocking_guides",
        "Blocking manual actions pending.",
        "gauge",
    );
    for a in apps {
        let _ = writeln!(
            o,
            "hlb_blocking_guides{{app=\"{}\"}} {}",
            label(&a.name),
            a.blocking_guides
        );
    }

    header(
        &mut o,
        "hlb_node_reachable",
        "1 if the node's agent answered the last poll.",
        "gauge",
    );
    for (addr, s) in nodes {
        // 🔴 The label is the address, not the hostname: an unreachable node has no
        // hostname to give. Changing the label depending on whether it answers would
        // produce two distinct series for the same machine — and the "mute node" alert
        // would never fire.
        let _ = writeln!(
            o,
            "hlb_node_reachable{{node=\"{}\"}} {}",
            label(addr),
            u8::from(s.report().is_some())
        );
    }

    header(
        &mut o,
        "hlb_disk_used_ratio",
        "Filesystem usage, over the space really usable.",
        "gauge",
    );
    for (addr, s) in nodes {
        let Some(r) = s.report() else { continue };
        for d in &r.disks {
            let _ = writeln!(
                o,
                "hlb_disk_used_ratio{{node=\"{}\",path=\"{}\"}} {:.4}",
                label(addr),
                label(&d.path),
                d.used_percent() / 100.0
            );
        }
    }

    header(
        &mut o,
        "hlb_disk_pressure",
        "Disk pressure step: 0 healthy, 1 notice, 2 reclaim, 3 freeze, 4 critical.",
        "gauge",
    );
    let thresholds = Thresholds::default();
    for (addr, s) in nodes {
        let Some(r) = s.report() else { continue };
        for d in &r.disks {
            let _ = writeln!(
                o,
                "hlb_disk_pressure{{node=\"{}\",path=\"{}\"}} {}",
                label(addr),
                label(&d.path),
                pressure_tier(d.pressure(&thresholds))
            );
        }
    }

    // ─── Protocol 2: what the agent now knows about its system ──────────────
    //
    // 🔴 Each measurement is emitted ONLY if it exists. A protocol 1 agent, or a failed
    // read, produces no series — rather than a series at zero that would read as "idle
    // machine" and would make every alert mute.

    header(
        &mut o,
        "hlb_cpu_used_ratio",
        "CPU usage over the elapsed interval. Absent on the first reading.",
        "gauge",
    );
    for (addr, s) in nodes {
        if let Some(v) = s.report().and_then(|r| r.cpu_busy) {
            let _ = writeln!(o, "hlb_cpu_used_ratio{{node=\"{}\"}} {v:.4}", label(addr));
        }
    }

    header(
        &mut o,
        "hlb_load_per_core",
        "One-minute load divided by the number of cores. 1.0 = fully loaded.",
        "gauge",
    );
    for (addr, s) in nodes {
        // Load PER CORE, never the raw figure: 4 is dramatic on one core and
        // comfortable on sixteen, and a homelab is made of heterogeneous machines.
        if let Some(v) = s.report().and_then(|r| r.load_per_core()) {
            let _ = writeln!(o, "hlb_load_per_core{{node=\"{}\"}} {v:.3}", label(addr));
        }
    }

    header(
        &mut o,
        "hlb_memory_used_ratio",
        "Memory used, measured against AVAILABLE memory and not free memory.",
        "gauge",
    );
    for (addr, s) in nodes {
        if let Some(v) = s.report().and_then(|r| r.memory_used()) {
            let _ = writeln!(
                o,
                "hlb_memory_used_ratio{{node=\"{}\"}} {v:.4}",
                label(addr)
            );
        }
    }

    header(
        &mut o,
        "hlb_swap_used_ratio",
        "Swap usage. A swap that is being used is a signal BEFORE the failure.",
        "gauge",
    );
    for (addr, s) in nodes {
        let Some(r) = s.report() else { continue };
        if let (Some(t), Some(u)) = (r.swap_total_mb, r.swap_used_mb) {
            if t > 0 {
                let _ = writeln!(
                    o,
                    "hlb_swap_used_ratio{{node=\"{}\"}} {:.4}",
                    label(addr),
                    u as f64 / t as f64
                );
            }
        }
    }

    header(
        &mut o,
        "hlb_net_bytes_total",
        "Bytes transferred since the node booted, per interface and per direction.",
        "counter",
    );
    for (addr, s) in nodes {
        let Some(r) = s.report() else { continue };
        for i in &r.interfaces {
            // A `counter` and not a `gauge`: these are cumulative, and it is `rate()`
            // that derives a throughput from them. Declaring them as gauges would make
            // VictoriaMetrics produce graphs rising to infinity.
            let _ = writeln!(
                o,
                "hlb_net_bytes_total{{node=\"{}\",interface=\"{}\",sens=\"rx\"}} {}",
                label(addr),
                label(&i.name),
                i.rx_bytes
            );
            let _ = writeln!(
                o,
                "hlb_net_bytes_total{{node=\"{}\",interface=\"{}\",sens=\"tx\"}} {}",
                label(addr),
                label(&i.name),
                i.tx_bytes
            );
        }
    }

    header(
        &mut o,
        "hlb_node_uptime_seconds",
        "How long the node has been up. A recent reboot explains a great deal.",
        "gauge",
    );
    for (addr, s) in nodes {
        if let Some(v) = s
            .report()
            .and_then(|r| r.system.as_ref())
            .and_then(|y| y.uptime_s)
        {
            let _ = writeln!(o, "hlb_node_uptime_seconds{{node=\"{}\"}} {v}", label(addr));
        }
    }

    header(
        &mut o,
        "hlb_agent_protocol",
        "Version of the agent's protocol. A mismatched fleet is a trap.",
        "gauge",
    );
    for (addr, s) in nodes {
        if let Some(r) = s.report() {
            let _ = writeln!(
                o,
                "hlb_agent_protocol{{node=\"{}\",version=\"{}\"}} {}",
                label(addr),
                label(&r.agent_version),
                r.protocol
            );
        }
    }

    o
}

/// A step as a number, so alert thresholds read naturally
/// (`hlb_disk_pressure >= 3` = "we stop deploying").
pub fn tier(p: DiskPressure) -> u8 {
    pressure_tier(p)
}

fn pressure_tier(p: DiskPressure) -> u8 {
    match p {
        DiskPressure::Normal => 0,
        DiskPressure::Notice => 1,
        DiskPressure::Reclaim => 2,
        DiskPressure::Freeze => 3,
        DiskPressure::Critical => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_measurement_emits_no_series_at_all() {
        // 🔴 This module's central rule, extended to the protocol 2 measurements. A
        // series at zero would read as "CPU idle, memory free, nothing swapping": the
        // dashboard would be green for a node we know NOTHING about, and no
        // alert would fire.
        let mut nodes = BTreeMap::new();
        nodes.insert(
            "10.0.0.9:8421".to_string(),
            AgentStatus::Reporting(Box::new(hlb_agent::report::NodeReport {
                hostname: "old".into(),
                at: 1_000,
                agent_version: "0.1.0".into(),
                protocol: 1,
                ..Default::default()
            })),
        );

        let o = render(&[], &nodes);
        for absent in [
            "hlb_cpu_used_ratio{",
            "hlb_load_per_core{",
            "hlb_memory_used_ratio{",
            "hlb_swap_used_ratio{",
            "hlb_net_bytes_total{",
            "hlb_node_uptime_seconds{",
        ] {
            assert!(!o.contains(absent), "{absent} emitted with no data:\n{o}");
        }
        // But the node stays reachable, and that must show.
        assert!(o.contains("hlb_node_reachable{node=\"10.0.0.9:8421\"} 1"));
    }

    #[test]
    fn network_counters_are_declared_as_counters() {
        // ⚠️ These are cumulative since boot. Declaring them as `gauge` would make
        // VictoriaMetrics produce graphs rising to infinity instead of a throughput —
        // and nobody would think to look at the type.
        let mut nodes = BTreeMap::new();
        nodes.insert(
            "n:1".to_string(),
            AgentStatus::Reporting(Box::new(hlb_agent::report::NodeReport {
                hostname: "n".into(),
                at: 1,
                protocol: 2,
                interfaces: vec![hlb_agent::system::Interface {
                    name: "eth0".into(),
                    rx_bytes: 100,
                    tx_bytes: 200,
                }],
                ..Default::default()
            })),
        );
        let o = render(&[], &nodes);
        assert!(o.contains("# TYPE hlb_net_bytes_total counter"), "{o}");
        assert!(
            o.contains("sens=\"rx\"}} 100".replace("}}", "}").as_str())
                || o.contains("sens=\"rx\"} 100")
        );
        assert!(o.contains("sens=\"tx\"} 200"));
    }

    #[test]
    fn a_node_that_swaps_is_visible_in_the_metrics() {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            "n:1".to_string(),
            AgentStatus::Reporting(Box::new(hlb_agent::report::NodeReport {
                hostname: "n".into(),
                at: 1,
                protocol: 2,
                swap_total_mb: Some(1_000),
                swap_used_mb: Some(600),
                ..Default::default()
            })),
        );
        let o = render(&[], &nodes);
        assert!(
            o.contains("hlb_swap_used_ratio{node=\"n:1\"} 0.6000"),
            "{o}"
        );
    }

    #[test]
    fn a_swapless_machine_does_not_divide_by_zero() {
        // Many nodes have no swap at all. Emitting a series would be false, and
        // dividing by zero would produce `NaN` — which Prometheus refuses to ingest.
        let mut nodes = BTreeMap::new();
        nodes.insert(
            "n:1".to_string(),
            AgentStatus::Reporting(Box::new(hlb_agent::report::NodeReport {
                hostname: "n".into(),
                at: 1,
                protocol: 2,
                swap_total_mb: Some(0),
                swap_used_mb: Some(0),
                ..Default::default()
            })),
        );
        let o = render(&[], &nodes);
        assert!(!o.contains("hlb_swap_used_ratio{"), "{o}");
        assert!(!o.contains("NaN"), "{o}");
    }
    use hlb_agent::{DiskUsage, NodeReport};

    fn app(name: &str) -> AppMetrics {
        AppMetrics {
            name: name.into(),
            status: "running".into(),
            last_backup_secs: Some(3600),
            last_verification_secs: Some(86_400),
            blocking_guides: 0,
        }
    }

    fn nodes(v: Vec<(&str, AgentStatus)>) -> BTreeMap<String, AgentStatus> {
        v.into_iter().map(|(a, s)| (a.to_string(), s)).collect()
    }

    fn healthy(name: &str, used: u64, free: u64) -> AgentStatus {
        AgentStatus::Reporting(Box::new(NodeReport {
            hostname: name.into(),
            at: 0,
            disks: vec![DiskUsage {
                path: "/".into(),
                total_mb: used + free,
                used_mb: used,
                free_mb: free,
            }],
            memory_total_mb: None,
            memory_available_mb: None,
            agent_version: "test".into(),
            protocol: hlb_agent::PROTOCOL,
            ..Default::default()
        }))
    }

    #[test]
    fn a_never_backed_up_app_emits_no_sample() {
        // 🔴 This module's central trap. A 0 would mean "backed up just now": the
        // "backup too old" alert would NEVER fire for precisely the apps that have
        // never been backed up.
        let mut a = app("gitea");
        a.last_backup_secs = None;

        let m = render(&[a], &BTreeMap::new());
        assert!(!m.contains("hlb_backup_age_seconds{app=\"gitea\"}"), "{m}");
        // The header stays: a collector must see the metric declared.
        assert!(m.contains("# TYPE hlb_backup_age_seconds gauge"));
    }

    #[test]
    fn an_app_holding_nothing_is_counted_by_no_backup_rule() {
        // 🔴 Found by review: Valkey's 0 copies fired `single-copy`, and its missing
        // age `backup-absent`, forever. `backup-absent` counts the apps owed a backup
        // by `hlb_backup_copies`, so it must carry those apps and only those.
        let coverage = |app: &str, classes| hlb_backup::Coverage {
            app: app.into(),
            per_destination: Vec::new(),
            classes,
        };
        let m = render_with_coverage(
            &[app("valkey"), app("gitea")],
            &BTreeMap::new(),
            &[
                coverage("valkey", Vec::new()),
                coverage("gitea", vec![hlb_backup::Class::Bulky]),
            ],
        );
        assert!(!m.contains("hlb_backup_copies{app=\"valkey\"}"), "{m}");
        assert!(m.contains("hlb_backup_copies{app=\"gitea\"} 0"), "{m}");
    }

    #[test]
    fn a_backed_up_app_emits_its_age() {
        let m = render(&[app("gitea")], &BTreeMap::new());
        assert!(
            m.contains("hlb_backup_age_seconds{app=\"gitea\"} 3600"),
            "{m}"
        );
        assert!(
            m.contains("hlb_backup_verification_age_seconds{app=\"gitea\"} 86400"),
            "{m}"
        );
    }

    #[test]
    fn only_a_failed_app_is_down() {
        for (status, up) in [
            ("running", 1),
            ("partial", 1),
            ("installing", 1),
            ("failed", 0),
            ("something-new", 0),
        ] {
            let mut a = app("gitea");
            a.status = status.into();
            let m = render(&[a], &BTreeMap::new());
            assert!(
                m.contains(&format!(
                    "hlb_app_up{{app=\"gitea\",status=\"{status}\"}} {up}"
                )),
                "{m}"
            );
        }
    }

    #[test]
    fn a_stopped_app_is_zero() {
        let mut a = app("gitea");
        a.status = "failed".into();
        let m = render(&[a], &BTreeMap::new());
        assert!(
            m.contains("hlb_app_up{app=\"gitea\",status=\"failed\"} 0"),
            "{m}"
        );
    }

    #[test]
    fn an_unreachable_node_is_reported_without_disks() {
        // A mute node must not produce a disk metric: the last known value would be
        // read as current.
        let n = AgentStatus::Unreachable {
            detail: "timed out".into(),
        };
        let m = render(&[], &nodes(vec![("node2", n)]));
        assert!(m.contains("hlb_node_reachable{node=\"node2\"} 0"), "{m}");
        assert!(!m.contains("hlb_disk_used_ratio{node=\"node2\""), "{m}");
    }

    #[test]
    fn the_disk_ratio_uses_usable_space() {
        // 12057 used, 6964 free -> 63.4 % of the usable space. Over `total_mb` (which
        // includes the 5 % root reserve), the figure would be lower.
        let m = render(
            &[],
            &nodes(vec![("node1", healthy("node1", 12_057, 6_964))]),
        );
        assert!(
            m.contains("hlb_disk_used_ratio{node=\"node1\",path=\"/\"} 0.63"),
            "{m}"
        );
    }

    #[test]
    fn the_pressure_tier_is_exported() {
        // 96 used / 4 free = 96 % -> Critical.
        let m = render(&[], &nodes(vec![("node1", healthy("node1", 96, 4))]));
        assert!(
            m.contains("hlb_disk_pressure{node=\"node1\",path=\"/\"} 4"),
            "{m}"
        );
    }

    #[test]
    fn every_metric_declares_its_help_and_type() {
        let m = render(
            &[app("gitea")],
            &nodes(vec![("node1", healthy("node1", 10, 90))]),
        );
        let names: Vec<&str> = m
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split(['{', ' ']).next())
            .filter(|s| !s.is_empty())
            .collect();

        for n in names {
            assert!(
                m.contains(&format!("# TYPE {n} ")),
                "{n} sans # TYPE :\n{m}"
            );
            assert!(
                m.contains(&format!("# HELP {n} ")),
                "{n} sans # HELP :\n{m}"
            );
        }
    }

    #[test]
    fn a_quote_in_a_name_cannot_break_the_batch() {
        // 🔴 A single malformed line makes the collector reject the WHOLE batch, not
        // just the offending line.
        let mut a = app("mechant\"name");
        a.blocking_guides = 1;
        let m = render(&[a], &BTreeMap::new());
        assert!(m.contains(r#"app="mechant\"name""#), "{m}");
    }
}
