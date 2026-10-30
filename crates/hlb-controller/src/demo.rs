//! A controller populated with plausible data, without Docker or a cluster (batch 2.6).
//!
//! ## Why this exists
//!
//! The interface has some twenty screens to write. Without a demo mode, every visual
//! iteration demands a real installation: a Swarm, deployed apps, backups several days
//! old, an account whose creation failed. You do not reproduce that to adjust a margin.
//!
//! And above all: the cases you need to *see* are the ones you never have to hand. An
//! app never backed up, an off-site stale for three weeks, an expired alias still
//! receiving, a node at 96 % disk, a half-created account. They are exactly the ones
//! whose display must be right, and exactly the ones you do not run into while
//! developing.
//!
//! What the state holds is seeded by the daemon (`hlb_privd::demo`), which alone writes
//! it; here are the views no table holds — machines, tasks, curves, the alerts and gaps
//! the daemon's loops would have found. Nothing here writes into Docker: no
//! orchestrator is wired in, no reconciliation loop runs.

use std::collections::BTreeMap;

use hlb_agent::disk::DiskUsage;
use hlb_agent::report::NodeReport;

use crate::agents::AgentStatus;

pub use hlb_privd::demo::{Scale, ADMIN, LARGE_MACHINES};

/// The machines at a scale.
pub fn nodes_at(now: u64, scale: Scale) -> BTreeMap<String, AgentStatus> {
    let mut m = nodes(now);
    if scale == Scale::Large {
        for i in 0..LARGE_MACHINES {
            // Spread over the range rather than all alike: a list of identical gauges
            // hides whether the eye can find the one that is filling up.
            let used = 20 + (i as u64 * 37) % 75;
            m.insert(
                format!("10.0.1.{}:8421", i + 1),
                AgentStatus::Reporting(Box::new(NodeReport {
                    hostname: format!("rack-{:02}", i + 1),
                    at: now,
                    disks: vec![disk("/", 400_000, 400_000 * used / 100)],
                    memory_total_mb: Some(8_192),
                    memory_available_mb: Some(8_192 * (100 - used) / 100),
                    agent_version: "0.2.0".into(),
                    protocol: 2,
                    cpu_cores: Some(4),
                    cpu_busy: Some(used as f64 / 100.0),
                    ..Default::default()
                })),
            );
        }
    }
    m
}

/// The topology, as a real cluster would return it.
///
/// 🔴 Built with **the anti-affinity trap inside**: two VMs on the same hardware, and a
/// service whose two replicas are both on it. Without that case, the screen that
/// justifies the interface's existence would have nothing to show — and we would not
/// know whether it shows it well.
pub fn topology() -> hlb_api::Topology {
    let node = |id: &str, host: &str, tier: &str, reachable: bool, services: &[&str]| {
        hlb_api::NodeInDomain {
            id: id.into(),
            hostname: host.into(),
            tier: Some(tier.into()),
            reachable,
            services: services.iter().map(|s| s.to_string()).collect(),
        }
    };

    hlb_api::Topology {
        total_nodes: 4,
        // Two managers on the SAME hardware: losing "big-01" takes the quorum on top of
        // the apps. That is the case the simulator must make legible.
        managers: vec!["n-heavy".into(), "n-mail".into(), "n-small1".into()],
        domains: vec![
            // 🔴 THE case: two Swarm nodes, a single physical server. The command line
            // shows two and lets you believe in redundancy.
            hlb_api::DomainSummary {
                name: Some("big-01 (one machine)".into()),
                concentrated: true,
                nodes: vec![
                    node(
                        "n-heavy",
                        "swarm-heavy",
                        "heavy",
                        true,
                        &["postgres", "valkey", "gitea", "immich"],
                    ),
                    node("n-mail", "mail-vm", "light", true, &["stalwart", "gitea"]),
                ],
            },
            hlb_api::DomainSummary {
                name: Some("small-01".into()),
                concentrated: false,
                nodes: vec![node("n-small1", "small-01", "light", true, &["vikunja"])],
            },
            // A node with no declared domain: we do NOT KNOW whether it shares hardware.
            hlb_api::DomainSummary {
                name: None,
                concentrated: false,
                nodes: vec![node("n-small2", "small-02", "light", false, &[])],
            },
        ],
        violations: vec![hlb_api::ViolationSummary {
            service: "gitea".into(),
            domain: Some("big-01 (one machine)".into()),
            replicas: 2,
            total: 2,
            total_violation: true,
            explanation: "gitea: its 2 replicas are ALL on domain \
                              \"big-01 (single machine)\" — the redundancy is an illusion"
                .into(),
        }],
    }
}

/// The active alerts, as the loop would produce them.
///
/// 🔴 Fabricated, because the demonstration mode has no VictoriaMetrics: without them
/// the alerts screen would be empty and could not be written. And it is precisely the
/// screen whose display must be right — a badly rendered alert is an alert you will not
/// see on the day.
///
/// The set covers the four cases that display differently: critical, important,
/// **non-evaluable** (collection is down, that is not "all is well"), and a **muted**
/// alert that must stay visible.
pub fn alerts(_now: i64) -> Vec<hlb_api::ActiveAlert> {
    vec![
        hlb_api::ActiveAlert {
            rule: "backup-absent".into(),
            level: hlb_api::AlertLevel::Critical,
            explanation: "applications have NEVER been backed up".into(),
            value: Some(4.0),
            threshold: 0.0,
            // Three days: an alert that lasts has been ignored, or its remedy does not
            // work. That is not handled like an alert that has just appeared.
            since_s: 3 * 86_400,
            muted_until: None,
            muted_by: None,
            mute_reason: None,
        },
        hlb_api::ActiveAlert {
            rule: "single-copy".into(),
            level: hlb_api::AlertLevel::Critical,
            explanation: "an application has only ONE up-to-date copy left".into(),
            value: Some(1.0),
            threshold: 2.0,
            since_s: 9 * 3_600,
            muted_until: None,
            muted_by: None,
            mute_reason: None,
        },
        hlb_api::ActiveAlert {
            rule: "disk-full".into(),
            level: hlb_api::AlertLevel::Important,
            explanation: "a filesystem is above 85 % usage".into(),
            value: Some(0.96),
            threshold: 0.85,
            since_s: 2 * 3_600,
            // 🔴 Muted — by `seed`, in the table, the way a person would — and it must
            // STAY visible: making it vanish would give a green dashboard for a known,
            // unresolved problem.
            muted_until: None,
            muted_by: None,
            mute_reason: None,
        },
        hlb_api::ActiveAlert {
            rule: "verification-stale".into(),
            level: hlb_api::AlertLevel::Unknown,
            explanation: "the rule can no longer be evaluated: no more data".into(),
            // 🔴 No value: we do not know. Putting 0 would say "threshold respected".
            value: None,
            threshold: 31.0,
            since_s: 40 * 60,
            muted_until: None,
            muted_by: None,
            mute_reason: None,
        },
    ]
}

/// The nodes as an agent would report them.
///
/// Separate from the state because these reports do not live in the database: they are
/// in memory, in `LastPoll`, and the loop → API sharing is what we want to exercise.
pub fn nodes(now: u64) -> BTreeMap<String, AgentStatus> {
    let mut m = BTreeMap::new();

    m.insert(
        "10.0.0.1:8421".to_string(),
        AgentStatus::Reporting(Box::new(NodeReport {
            hostname: "swarm-heavy".into(),
            at: now,
            disks: vec![
                disk("/", 500_000, 210_000),
                disk("/var/lib/docker", 200_000, 96_000),
            ],
            memory_total_mb: Some(16_384),
            memory_available_mb: Some(4_900),
            agent_version: "0.2.0".into(),
            protocol: 2,
            cpu_cores: Some(8),
            load: Some(hlb_agent::system::LoadAverage {
                one_min: 3.2,
                five_min: 2.8,
                fifteen_min: 2.4,
            }),
            cpu_busy: Some(0.41),
            swap_total_mb: Some(4_096),
            swap_used_mb: Some(120),
            interfaces: vec![hlb_agent::system::Interface {
                name: "eth0".into(),
                rx_bytes: 91_284_733_912,
                tx_bytes: 42_119_884_004,
            }],
            system: Some(hlb_agent::system::System {
                kernel: Some("6.1.0-18-amd64".into()),
                distro: Some("Debian GNU/Linux 12 (bookworm)".into()),
                uptime_s: Some(41 * 86_400),
            }),
            reboot_required: Some(false),
        })),
    );

    // 🔴 A node under pressure: /var/lib/docker at 96 %. A half-empty `/` is no
    // consolation — the WORST filesystem decides.
    m.insert(
        "10.0.0.2:8421".to_string(),
        AgentStatus::Reporting(Box::new(NodeReport {
            hostname: "small-01".into(),
            at: now,
            disks: vec![
                disk("/", 100_000, 30_000),
                disk("/var/lib/docker", 50_000, 48_000),
            ],
            memory_total_mb: Some(4_096),
            memory_available_mb: Some(890),
            agent_version: "0.2.0".into(),
            protocol: 2,
            cpu_cores: Some(4),
            // 🔴 Load per core above 1: the machine is overloaded.
            load: Some(hlb_agent::system::LoadAverage {
                one_min: 6.1,
                five_min: 5.4,
                fifteen_min: 4.9,
            }),
            cpu_busy: Some(0.93),
            swap_total_mb: Some(2_048),
            // 🔴 The swap IS being used: an early signal, the machine slows without
            // having fallen over yet. That is the case you need to see on screen.
            swap_used_mb: Some(1_450),
            interfaces: vec![hlb_agent::system::Interface {
                name: "eth0".into(),
                rx_bytes: 12_884_901_888,
                tx_bytes: 3_221_225_472,
            }],
            system: Some(hlb_agent::system::System {
                kernel: Some("6.1.0-18-arm64".into()),
                distro: Some("Debian GNU/Linux 12 (bookworm)".into()),
                // Rebooted twenty minutes ago: that often explains a lot, and nobody
                // thinks of it.
                uptime_s: Some(1_200),
            }),
            // A kernel waiting for its reboot: the demonstration shows the cause.
            reboot_required: Some(true),
        })),
    );

    // 🔴 An unreachable node. Distinct from a healthy node: its data is no longer
    // backed up, and showing it as "no problem reported" would be the lie this whole
    // project seeks to avoid.
    m.insert(
        "10.0.0.3:8421".to_string(),
        AgentStatus::Unreachable {
            detail: "connection refused (agent stopped?)".into(),
        },
    );

    // An agent MUTE for a long time: it answered once, not since. So the report exists,
    // but it is old — and it is up to the interface not to pass it off
    // as fresh.
    m.insert(
        "10.0.0.4:8421".to_string(),
        AgentStatus::Reporting(Box::new(NodeReport {
            hostname: "small-02".into(),
            at: now.saturating_sub(3_600),
            disks: vec![disk("/", 100_000, 19_000)],
            memory_total_mb: Some(4_096),
            memory_available_mb: Some(2_600),
            // ⚠️ Left on protocol 1: a mismatched fleet. Its system measurements
            // are absent — and must display as "unknown", not "0 %".
            agent_version: "0.1.0".into(),
            protocol: 1,
            ..Default::default()
        })),
    );

    m
}

fn disk(path: &str, total_mb: u64, used_mb: u64) -> DiskUsage {
    DiskUsage {
        path: path.into(),
        total_mb,
        used_mb,
        free_mb: total_mb - used_mb,
    }
}

/// The fleet reduced to tier and available memory, for the capacity budget.
///
/// 🔴 Consistent with `nodes()` and `topology()`: `small-01` is the protected 4 GB
/// machine, of which almost nothing is left. It is the one that must trigger the
/// warning, and not an absence of information.
pub fn fleet_per_tier() -> Vec<(Option<String>, Option<u64>)> {
    vec![
        (Some("heavy".into()), Some(11_800)),
        (Some("light".into()), Some(890)),
        // The mute node: the budget becomes a lower bound, and says so.
        (Some("light".into()), None),
    ]
}

/// An app's Swarm tasks, fabricated for the demonstration.
///
/// 🔴 They carry the cases you never have to hand at the right moment: the failure
/// Swarm gives a reason for, the failure it does not explain, and the service running
/// half-way. That is what makes the causal chain visible without a cluster.
pub fn tasks(app: &str) -> Vec<hlb_api::TaskSummary> {
    let t = |id: &str, node: &str, alive: bool, err: Option<&str>| hlb_api::TaskSummary {
        id: id.into(),
        service: app.into(),
        slot: Some(1),
        node: Some(node.into()),
        state: if alive {
            "running".into()
        } else {
            "failed".into()
        },
        desired_state: "running".into(),
        alive,
        failed: !alive,
        explanation: err.map(str::to_string),
        image: None,
    };

    match app {
        // The full chain: Swarm says why, the node is short of space, the rule flagged
        // it.
        "n8n" => vec![t(
            "tk-n8n-1",
            // ⚠️ The node UNDER PRESSURE: that is what closes the chain. Placing the
            // task on a healthy machine would give "unknown cause", which is the second
            // case — carried by seafile just below.
            "small-01",
            false,
            Some("no space left on device"),
        )],
        // 🔴 The failure nothing explains. It is the case the diagnosis must refuse to
        // invent: it stops at "unknown cause" rather than accuse the first node that
        // comes along.
        "seafile" => vec![t("tk-seafile-1", "swarm-heavy", false, Some("exit code 1"))],
        "immich" => vec![t("tk-immich-1", "swarm-heavy", true, None)],
        "gitea" => vec![
            t("tk-gitea-1", "swarm-heavy", true, None),
            t("tk-gitea-2", "mail-vm", true, None),
        ],
        _ => Vec::new(),
    }
}

/// Every demo app's tasks placed on `node` (a hostname, as `tasks`'s own fixtures use
/// — "small-01", "swarm-heavy", "mail-vm") — the SAME fabricated placements `tasks`
/// already returns, filtered by node instead of by app. Used by the per-node detail
/// endpoint's own demo branch, the same "no orchestrator, fabricate" precedent as
/// `tasks` itself.
pub fn node_tasks(node: &str) -> Vec<hlb_api::TaskSummary> {
    ["n8n", "seafile", "immich", "gitea"]
        .into_iter()
        .flat_map(tasks)
        .filter(|t| t.node.as_deref() == Some(node))
        .collect()
}

/// The Swarm side of a demo node, found by hostname in [`topology`].
///
/// 🔴 It reads `topology()` rather than carrying a second list: the demonstration's
/// cluster is described once, and a node that gains a failure domain there must not
/// keep an old identifier here.
///
/// ⚠️ `small-01` is reported as **drained** on purpose. Every other demo node is
/// active, so both halves of the availability control — "drain this node" and "put it
/// back into service" — are visible in the one mode this project recommends for
/// looking at the interface. A demonstration where every node is in the same state
/// shows one of the two buttons and hides the other.
pub fn swarm_node(hostname: Option<&str>) -> Option<hlb_api::SwarmNode> {
    let hostname = hostname?;
    topology()
        .domains
        .iter()
        .flat_map(|d| &d.nodes)
        .find(|n| n.hostname == hostname)
        .map(|n| hlb_api::SwarmNode {
            id: n.id.clone(),
            availability: if n.hostname == "small-01" {
                "drain".into()
            } else {
                "active".into()
            },
        })
}

/// The reconciliation gaps, fabricated for the demonstration.
///
/// 🔴 Without an orchestrator the loop does not run — and the screen that makes the
/// non-actions legible would be empty, therefore impossible to write. Both families are
/// there: what will be corrected, and what was deliberately left alone.
pub fn drifts() -> Vec<hlb_api::DriftSummary> {
    use hlb_engine::reconcile::Drift;

    // ⚠️ We go through the REAL `Drift` values rather than write the sentences by hand:
    // a demonstration that invents its own text ends up showing a screen the code never
    // produces.
    [
        Drift::ReplicasDiverged {
            app: "vikunja".into(),
            desired: 2,
            actual: 1,
        },
        Drift::OrphanService {
            name: "old-nextcloud".into(),
        },
        Drift::Converging {
            app: "immich".into(),
            running: 1,
            desired: 2,
        },
    ]
    .iter()
    .map(|d| hlb_api::DriftSummary {
        target: d.app().to_string(),
        description: d.to_string(),
        corrigible: d.is_correctable(),
        refusal: d.refusal().map(str::to_string),
    })
    .collect()
}

/// A day of measurements for the demonstration's machines, every five minutes, ending on
/// what each reports now: the curves the home draws, which an installation fills by
/// itself one minute at a time.
///
/// Deterministic, like the rest of the demonstration: busier in the evening, a disk that
/// fills faster when it is already nearly full, the network quiet at night, and an
/// application that stopped running three hours ago.
pub fn history(
    nodes: &BTreeMap<String, AgentStatus>,
    apps_running: usize,
    now: i64,
) -> Vec<hlb_state::Sample> {
    use hlb_api::Metric;
    const STEP: i64 = 300;
    let end = now - now.rem_euclid(60);
    let times: Vec<i64> = (0..=86_400 / STEP).rev().map(|k| end - k * STEP).collect();
    // The time of day, as a wave: -1 at four in the morning, 1 at four in the afternoon.
    let day = |t: i64| {
        ((t.rem_euclid(86_400) as f64 / 86_400.0 - 4.0 / 24.0) * std::f64::consts::TAU
            - std::f64::consts::FRAC_PI_2)
            .sin()
    };
    // Reproducible noise in [-1, 1], one value per subject, metric and moment.
    let noise = |seed: &str, t: i64| {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in seed.bytes().chain(t.to_le_bytes()) {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        (h % 2_001) as f64 / 1_000.0 - 1.0
    };
    let mut out = Vec::new();
    let mut curve = |metric: String, subject: &str, values: &mut dyn FnMut(i64) -> f64| {
        for &t in &times {
            out.push(hlb_state::Sample {
                at: t,
                subject: subject.to_string(),
                metric: metric.clone(),
                value: values(t),
            });
        }
    };

    for (address, status) in nodes {
        let Some(r) = status.report() else { continue };
        let now_wave = day(end);
        // Each curve ends on today's value, wherever the wave is now.
        let around = |current: f64, swing: f64, jitter: f64, key: &str| {
            let key = format!("{address}{key}");
            move |t: i64| {
                let shift = if t == end {
                    0.0
                } else {
                    swing * (day(t) - now_wave) + jitter * noise(&key, t)
                };
                (current + shift).clamp(0.0, 1.0)
            }
        };
        if let Some(c) = r.cpu_busy {
            curve(
                Metric::Cpu.key().into(),
                address,
                &mut around(c, 0.25, 0.08, "cpu"),
            );
        }
        if let Some(m) = r.memory_used() {
            curve(
                Metric::Memory.key().into(),
                address,
                &mut around(m, 0.06, 0.02, "memory"),
            );
        }
        if let (Some(t), Some(u)) = (r.swap_total_mb, r.swap_used_mb) {
            if t > 0 {
                curve(
                    Metric::Swap.key().into(),
                    address,
                    &mut around(u as f64 / t as f64, 0.03, 0.01, "swap"),
                );
            }
        }
        if let Some(l) = r.load_per_core() {
            let key = format!("{address}load");
            curve(Metric::Load.key().into(), address, &mut |t| {
                if t == end {
                    l
                } else {
                    (l * (1.0 + 0.4 * (day(t) - now_wave)) + 0.1 * noise(&key, t)).max(0.0)
                }
            });
        }
        for d in &r.disks {
            let used = d.used_percent() / 100.0;
            // A nearly full disk got there quickly: it fills four times as fast.
            let per_day = if used > 0.9 { 0.08 } else { 0.02 };
            curve(
                format!("{}{}", Metric::Disk.key(), d.path),
                address,
                &mut |t| (used - per_day * (end - t) as f64 / 86_400.0).max(0.0),
            );
        }
        if !r.interfaces.is_empty() {
            for (metric, total, base) in [
                (
                    Metric::NetIn,
                    r.interfaces.iter().map(|i| i.rx_bytes as f64).sum::<f64>(),
                    400_000.0,
                ),
                (
                    Metric::NetOut,
                    r.interfaces.iter().map(|i| i.tx_bytes as f64).sum::<f64>(),
                    120_000.0,
                ),
            ] {
                // Walked back from today's counter: what each five minutes carried.
                let key = format!("{address}{}", metric.key());
                let mut counter = total;
                let mut by_time = BTreeMap::new();
                for &t in times.iter().rev() {
                    by_time.insert(t, counter);
                    let rate = base * (1.2 + day(t)) * (1.0 + 0.3 * noise(&key, t));
                    counter = (counter - rate * STEP as f64).max(0.0);
                }
                curve(metric.key().into(), address, &mut |t| by_time[&t]);
            }
        }
    }

    let running = apps_running as f64;
    curve(Metric::AppsRunning.key().into(), "", &mut |t| {
        let ago = end - t;
        if (14 * 3_600..14 * 3_600 + 1_200).contains(&ago) {
            running // a restart: one application down for twenty minutes
        } else if ago > 3 * 3_600 {
            running + 1.0
        } else {
            running
        }
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_api::Attention;
    use hlb_privd::demo::{mutes, seed, seed_at, LARGE_ACCOUNTS};
    use hlb_state::State;

    /// Every alert the demo shows names a rule that `hlb-metrics` really emits.
    ///
    /// 🔴 It showed `disk-plein` while the rule was `disque-plein`: a French-to-English
    /// pass rewrote the demo's copy of the name and not the rule's — a rule name is a
    /// string, and a rename is compiler-verified only for identifiers. The one that
    /// drifted was the muted alert, whose whole reason for being in this set is that
    /// muting must not hide it.
    ///
    /// Derived from `alerts()` itself rather than from a second list of names — the two
    /// lists is the shape that let this one drift.
    #[test]
    fn every_rule_the_diagnostic_waits_for_exists() {
        // `hlb-api` cannot depend on `hlb-metrics`, so the two names its diagnostic
        // looks for are strings; this crate sees both sides.
        let known: Vec<&str> = hlb_metrics::rules::default_rules()
            .iter()
            .map(|r| r.name)
            .collect();
        for name in [
            hlb_api::diagnostic::NODE_RULE,
            hlb_api::diagnostic::DISK_RULE,
        ] {
            assert!(known.contains(&name), "no rule named \"{name}\": {known:?}");
        }
    }

    /// The demo's alerts as `/api/alerts` serves them: with the stored mutes applied.
    fn muted_alerts(now: i64) -> Vec<hlb_api::ActiveAlert> {
        let mutes = mutes(now);
        let mut a = alerts(now);
        a.iter_mut().for_each(|x| x.apply_mutes(&mutes));
        a
    }

    #[test]
    fn every_demo_mute_names_an_alert_the_demo_shows() {
        // A mute on a name nothing shows silences nothing, and the muted case — the one
        // in the set to prove muting does not hide an alert — would never render.
        let shown: Vec<String> = alerts(0).into_iter().map(|a| a.rule).collect();
        for m in mutes(0) {
            assert!(
                shown.contains(&m.rule),
                "the demo mutes `{}`, which it does not show",
                m.rule
            );
        }
    }

    #[test]
    fn every_demo_alert_names_a_rule_that_exists() {
        let known: std::collections::BTreeSet<&str> = hlb_metrics::rules::default_rules()
            .iter()
            .map(|r| r.name)
            .collect();

        let shown = alerts(0);
        // The floor under the derivation: a set built from an empty vector passes every
        // assertion below it.
        assert!(
            shown.len() >= 4,
            "only {} demo alerts — that reads as a set which stopped being built, \
             not one that shrank",
            shown.len()
        );
        for a in &shown {
            assert!(
                known.contains(a.rule.as_str()),
                "the demo shows `{}`, which no rule in hlb-metrics emits — known: {known:?}",
                a.rule
            );
        }
    }

    #[tokio::test]
    async fn the_demo_manifests_are_rich_enough_to_render_a_detail_screen() {
        // 🔴 A minimal manifest would give an EMPTY detail screen: no capabilities, no
        // variables. So we would never write the display of those sections — and they
        // are the ones that carry the traps.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        let m = s.app_manifest("gitea").await.expect("manifest");
        assert!(!m.spec.requires.is_empty(), "no capability to display");
        assert!(!m.spec.env.is_empty(), "no variable to display");

        // And the secret tokens are there, LITERAL: that is what the screen must show
        // without ever resolving them.
        assert!(
            m.spec.env.values().any(|v| v.contains("{{ db.password }}")),
            "no secret token: the literal display would not be exercised"
        );
    }

    #[tokio::test]
    async fn the_large_demo_holds_a_thousand_people_and_their_broken_few() {
        let s = State::in_memory().await.expect("state");
        seed_at(&s, Scale::Large, None).await.expect("seeding");

        let people = s.users_with_roles().await.expect("users");
        assert_eq!(people.len(), 4 + LARGE_ACCOUNTS);
        // The point of a thousand: whether the half-created few can be FOUND among them.
        let mut broken = 0;
        for h in &people {
            let account = s.account(&h.user).await.expect("account");
            if account.coherence() != hlb_users::Coherence::Complete {
                broken += 1;
            }
        }
        assert!((20..100).contains(&broken), "{broken} broken accounts");

        assert_eq!(
            nodes_at(0, Scale::Large).len(),
            nodes(0).len() + LARGE_MACHINES
        );
    }

    #[tokio::test]
    async fn the_demo_has_an_unbacked_volume_and_a_sqlite_one() {
        // The two cases that carry a trap: a volume you believe protected and that is
        // not, and a SQLite database that cannot be copied hot.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        let immich = s.app_volumes("immich").await.expect("volumes");
        assert!(
            immich.iter().any(|(_, _, backup, _)| !backup),
            "no unbacked-up volume"
        );

        let vw = s.app_volumes("vaultwarden").await.expect("volumes");
        assert!(
            vw.iter().any(|(_, _, _, sqlite)| *sqlite),
            "no SQLite volume"
        );
    }

    #[tokio::test]
    async fn the_demo_covers_every_attention_level() {
        // 🔴 A dataset showing only healthy apps is of no use: the screens that need
        // checking are the ones for the cases you never have to hand.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        let apps = s.installed_apps().await.expect("apps");
        assert!(apps.len() >= 8);

        let mut seen = std::collections::BTreeSet::new();
        for (name, status) in &apps {
            let a = hlb_api::AppSummary {
                name: name.clone(),
                status: status.clone(),
                image: String::new(),
                domain: None,
                last_backup_secs: s.backup_age(name).await.expect("backup"),
                holds_data: !s.backup_kinds(name).await.expect("kinds").is_empty(),
                last_verification_secs: None,
                blocking_guides: s.unverified_blocking(name).await.expect("guides") as i64,
            };
            seen.insert(a.attention());
        }

        for level in [Attention::Ok, Attention::Notice, Attention::Critical] {
            assert!(
                seen.contains(&level),
                "the demonstration set has no {level:?} case"
            );
        }
    }

    #[tokio::test]
    async fn the_demo_shows_all_three_causes_of_a_critical_app() {
        // 🔴 "Critical" covers three situations that are repaired differently: never
        // backed up, stale backup, service failed. A set showing only one would leave
        // the other two displays unchecked.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        assert_eq!(
            s.backup_age("seafile").await.expect("never"),
            None,
            "no \"never backed up\" case"
        );
        assert!(
            s.backup_age("vikunja").await.expect("stale").unwrap_or(0) > 86_400,
            "no \"stale backup\" case"
        );
        assert!(
            s.installed_apps()
                .await
                .expect("apps")
                .iter()
                .any(|(_, st)| st == "failed"),
            "no \"service failed\" case"
        );
    }

    #[tokio::test]
    async fn the_demo_shows_a_fresh_destination_masking_a_dead_one() {
        // The freshness trap: `MAX(finished_at)` across every destination passes an off-site
        // dead for weeks off as a two-hour-old backup.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        let immich = crate::coverage::all_of_them(&s, crate::api::STALENESS_THRESHOLD_S)
            .await
            .into_iter()
            .find(|c| c.app == "immich")
            .expect("immich holds data");
        let at = |d: &str| {
            immich
                .per_destination
                .iter()
                .find(|(n, _)| n == d)
                .map(|(_, st)| st.clone())
        };
        assert!(
            matches!(at("nas"), Some(hlb_backup::DestinationState::Fresh { .. })),
            "the NAS received: {immich:?}"
        );
        assert_eq!(
            at("offsite"),
            Some(hlb_backup::DestinationState::Never),
            "the off-site has NEVER received anything, and that must show"
        );
        assert!(
            s.consecutive_failures_on("immich", "offsite")
                .await
                .expect("failures")
                >= 4,
            "the repeated failures must show before the staleness threshold"
        );
    }

    #[tokio::test]
    async fn the_demo_has_an_app_that_looks_healthy_and_is_not() {
        // The system's worst state: the app runs and has NO backup. It is the one that
        // looks healthiest, so the one the display must catch.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        assert_eq!(s.backup_age("seafile").await.expect("backup"), None);
    }

    #[tokio::test]
    async fn the_demo_has_a_half_created_account_in_both_directions() {
        // Identity with no mailbox AND mailbox with no identity: the two halves show
        // differently and are repaired differently.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        use hlb_users::Coherence;
        assert_eq!(
            s.account("lena").await.expect("account").coherence(),
            Coherence::Complete
        );
        assert_eq!(
            s.account("dominique").await.expect("account").coherence(),
            Coherence::WithoutMailbox
        );
        assert_eq!(
            s.account("sacha").await.expect("account").coherence(),
            Coherence::WithoutIdentity
        );
    }

    #[tokio::test]
    async fn the_demo_has_an_expired_alias_that_still_receives() {
        // 🔴 The third state, the one that only exists because a mail server cannot
        // expire an alias: expired, and STILL active.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        let c = s.account("lena").await.expect("account");
        let broken = c.broken_promises(crate::auth::now());
        assert!(!broken.is_empty(), "no alias betrays its promise");
        assert!(broken
            .iter()
            .any(|(_, a)| a.local.starts_with("newsletter")));
    }

    #[tokio::test]
    async fn the_demo_distinguishes_no_folder_from_no_sorting() {
        // `NULL` = nothing was decided (we propose a default); `""` = I do NOT want
        // sorting. Confusing them re-imposes a folder on every regeneration.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        let rules = s.alias_rules("lena", "lena").await.expect("rules");
        let folder = |alias: &str| {
            rules
                .iter()
                .find(|(a, ..)| a.starts_with(alias))
                .map(|(_, d, _)| d.clone())
                .expect("alias present")
        };
        assert_eq!(folder("taxes").as_deref(), Some("Admin/Taxes"));
        assert_eq!(
            folder("contest").as_deref(),
            Some(""),
            "refusal explicite de trier"
        );
        assert_eq!(folder("newsletter"), None, "nothing decided");
    }

    #[test]
    fn the_demo_has_a_node_still_speaking_the_old_protocol() {
        // 🔴 A mismatched fleet: it is the NORMAL state during an update. Without
        // it in the demonstration set, we would never write the "unknown measurement"
        // display — and a `0 %` would end up slipping in.
        let n = nodes(1_000_000);
        let old = n
            .values()
            .filter_map(|s| s.report())
            .find(|r| r.protocol < 2)
            .expect("no agent on protocol 1");
        assert_eq!(old.cpu_busy, None);
        assert!(old.interfaces.is_empty());
        // But what it does send stays usable.
        assert!(old.memory_used().is_some());
    }

    #[test]
    fn the_demo_shows_a_machine_that_has_started_swapping() {
        // A swap in use is a signal BEFORE the failure: the machine slows without having
        // fallen over yet. That is the case we want to be able to look at on screen.
        let n = nodes(1_000_000);
        assert!(
            n.values()
                .filter_map(|s| s.report())
                .any(|r| r.swap_on_disk()),
            "no node is swapping to disk"
        );
    }

    #[test]
    fn the_demo_shows_a_machine_over_one_load_per_core() {
        // The only figure comparable across heterogeneous machines.
        let n = nodes(1_000_000);
        let overload = n
            .values()
            .filter_map(|s| s.report())
            .filter_map(|r| r.load_per_core())
            .any(|c| c > 1.0);
        assert!(overload, "no overloaded node");
    }

    #[test]
    fn the_demo_topology_contains_the_trap_it_exists_to_show() {
        // 🔴 Without two VMs on the same hardware, the screen that justifies the
        // interface's existence would have nothing to show — and we would not know it.
        let t = topology();
        assert_eq!(t.attention(), hlb_api::Attention::Critical);
        assert!(
            matches!(t.verdict(), hlb_api::TopologyVerdict::RedundancyIllusion { services } if services > 0),
            "{:?}",
            t.verdict()
        );

        let concentrated = t
            .domains
            .iter()
            .find(|d| d.concentrated)
            .expect("no concentrated domain");
        assert!(
            concentrated.nodes.len() >= 2,
            "one piece of hardware must carry several nodes"
        );

        assert!(
            t.domains.iter().any(|d| d.name.is_none()),
            "no undeclared domain: the \"we do not know\" case would not be displayed"
        );
        assert!(
            t.domains
                .iter()
                .flat_map(|d| &d.nodes)
                .any(|n| !n.reachable),
            "no unreachable node in the topology"
        );
    }

    #[tokio::test]
    async fn the_demo_has_a_followed_incident() {
        // 🔴 An incident without its thread would not show what makes the system
        // valuable: the chronology you re-read afterwards.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");

        let v = s
            .announcements(hlb_types::Role::Admin, crate::auth::now(), false)
            .await
            .expect("announcements");
        let incident = v
            .iter()
            .find(|a| a.open_incident())
            .expect("no open incident");
        assert!(
            incident.follow_ups.len() >= 2,
            "an incident with no follow-up thread"
        );
        assert_ne!(
            incident.last_update(),
            incident.body,
            "the last update must differ from the original message"
        );
    }

    #[tokio::test]
    async fn the_demo_shows_the_portal_filtering_at_work() {
        // ⚠️ Without an operations-only announcement, we would never write the filtered
        // display — and a maintenance announcement would end up on the portal.
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");
        let now = crate::auth::now();

        let portal = s
            .announcements(hlb_types::Role::User, now, false)
            .await
            .expect("announcements");
        let admin = s
            .announcements(hlb_types::Role::Admin, now, false)
            .await
            .expect("announcements");

        assert!(
            admin.len() > portal.len(),
            "no reserved announcement: the filtering would not be exercised"
        );
    }

    #[tokio::test]
    async fn the_demo_keeps_an_expired_announcement_in_the_record() {
        let s = State::in_memory().await.expect("state");
        seed(&s).await.expect("seeding");
        let now = crate::auth::now();

        let active = s
            .announcements(hlb_types::Role::Admin, now, false)
            .await
            .expect("a");
        let all_of_them = s
            .announcements(hlb_types::Role::Admin, now, true)
            .await
            .expect("a");
        assert!(
            all_of_them.len() > active.len(),
            "no expired announcement in the history"
        );
    }

    #[test]
    fn the_demo_alerts_cover_every_display_case() {
        // 🔴 Each displays differently, and each is the one you will fail to see on
        // the day it matters if it renders badly.
        let a = muted_alerts(1_000_000);

        assert!(a.iter().any(|x| x.level == hlb_api::AlertLevel::Critical));
        assert!(a.iter().any(|x| x.level == hlb_api::AlertLevel::Important));
        assert!(
            a.iter().any(|x| x.level == hlb_api::AlertLevel::Unknown),
            "\"non-evaluable\" is missing: it is the case confused with \"all is well\""
        );
        assert!(
            a.iter().any(|x| x.is_muted(1_000_000)),
            "no muted alert: the matching display would never be written"
        );
        // A non-evaluable alert has NO value: putting 0 would say "threshold
        // respected", the exact opposite.
        let unknown = a
            .iter()
            .find(|x| x.level == hlb_api::AlertLevel::Unknown)
            .expect("an unknown one");
        assert_eq!(unknown.value, None);
    }

    #[test]
    fn a_demo_silenced_alert_still_shows_its_reason() {
        let a = muted_alerts(1_000_000);
        let muted = a
            .iter()
            .find(|x| x.is_muted(1_000_000))
            .expect("a muted alert");
        let mute = muted.mute(1_000_000).expect("a mute in force");
        assert_eq!(mute.by.as_deref(), Some("lena"), "who muted it must show");
        assert!(mute.reason.is_some(), "why it was muted must show");
        assert!(!muted.explanation.is_empty(), "the reason stays visible");
    }

    #[test]
    fn the_demo_nodes_cover_reachable_saturated_and_silent() {
        let n = nodes(1_000_000);
        assert_eq!(n.len(), 4);

        let thresholds = hlb_agent::disk::Thresholds::default();
        let saturated = n
            .values()
            .filter_map(|s| s.report())
            .any(|r| !r.allows_deploy(&thresholds));
        assert!(
            saturated,
            "no node under pressure: the critical case is not shown"
        );

        let unreachable = n
            .values()
            .any(|s| matches!(s, AgentStatus::Unreachable { .. }));
        assert!(unreachable, "an unreachable node is not a healthy node");

        let silent = n
            .values()
            .filter_map(|s| s.report())
            .any(|r| r.is_stale(1_000_000, 120));
        assert!(silent, "a mute agent must be represented");
    }

    #[test]
    fn the_demonstration_has_a_day_behind_it_ending_on_today() {
        let now = 1_800_000_000;
        let nodes = nodes_at(now as u64, Scale::Household);
        let samples = history(&nodes, 9, now);
        let end = now - now % 60;
        let mut checked = 0;
        for (address, status) in &nodes {
            let Some(r) = status.report() else {
                // 🔴 An unreachable machine has no past invented for it.
                assert!(!samples.iter().any(|x| &x.subject == address), "{address}");
                continue;
            };
            // The processor is unknown on an agent's first reading: then it has no curve.
            let Some(busy) = r.cpu_busy else { continue };
            let cpu: Vec<_> = samples
                .iter()
                .filter(|x| &x.subject == address && x.metric == "cpu")
                .collect();
            assert_eq!(
                cpu.len(),
                289,
                "a day every five minutes, both ends included"
            );
            assert_eq!(cpu.last().map(|x| (x.at, x.value)), Some((end, busy)));
            checked += 1;
        }
        assert!(checked >= 2, "{checked} machines had a processor curve");
        for x in &samples {
            if ["cpu", "memory", "swap"].contains(&x.metric.as_str())
                || x.metric.starts_with("disk:")
            {
                assert!((0.0..=1.0).contains(&x.value), "{x:?}");
            }
        }
        // A counter never runs backwards inside the day it was walked back from.
        let rx: Vec<f64> = samples
            .iter()
            .filter(|x| x.metric == "net_rx" && Some(&x.subject) == nodes.keys().next())
            .map(|x| x.value)
            .collect();
        assert!(rx.windows(2).all(|w| w[0] <= w[1]));
    }

    #[tokio::test]
    async fn the_demonstration_acts_for_an_administrator_it_seeds() {
        // Acting for an account it never created, every preference would fail on the
        // foreign key — the 500 a token bound to a missing account answers.
        for scale in [Scale::Household, Scale::Large] {
            let s = State::in_memory().await.expect("state");
            seed_at(&s, scale, None).await.expect("seed");
            assert_eq!(
                s.user_role(ADMIN).await.expect("role"),
                hlb_types::Role::Admin
            );
            s.set_home_of(ADMIN, Some(&[]))
                .await
                .expect("a preference can be stored");
        }
    }
}
