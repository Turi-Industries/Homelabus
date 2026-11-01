//! "Why is this app red?" — the causal chain.
//!
//! ## What it adds
//!
//! Every link already exists, each on its own screen: the failed task carries its
//! error, the node carries its disk pressure, the `disk-full` rule fired. Nobody
//! connects them, and that is what separates a dashboard from a diagnosis.
//!
//! ## 🔴 A chain you cannot follow stops
//!
//! It stops on "unknown cause", never on a guess. A plausible but wrong diagnosis costs
//! more than no diagnosis at all: you repair the wrong thing, and then stop believing
//! the screen.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{ActiveAlert, AppDetail, NodeSummary};

/// One link of the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Link {
    /// The finding, in one sentence.
    pub finding: String,
    /// What documents it: task id, node name, rule name.
    #[serde(default)]
    pub source: Option<String>,
}

/// The result of a diagnosis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Chain {
    pub app: String,
    /// From symptom towards cause. Empty when there is nothing to explain.
    pub links: Vec<Link>,
    /// 🔴 True when the walk stopped without reaching a cause.
    ///
    /// Distinct from an empty chain: "nothing to explain" and "I cannot explain" are
    /// opposite answers.
    pub unknown_cause: bool,
    /// The action that fixes it, when there is one.
    #[serde(default)]
    pub remedy: Option<String>,
}

impl Chain {
    /// Is there anything to read?
    pub fn has_something_to_say(&self) -> bool {
        !self.links.is_empty()
    }

    /// The last line, the one that concludes.
    pub fn conclusion(&self) -> String {
        if self.links.is_empty() {
            return format!("{} shows no symptom.", self.app);
        }
        if self.unknown_cause {
            // ⚠️ Say it plainly. A chain that stops silently reads as a complete chain,
            // and the last hypothesis passes for the cause.
            return "The cause could not be traced any further. The service logs are the \
                    next step."
                .to_string();
        }
        self.links
            .last()
            .map(|m| m.finding.clone())
            .unwrap_or_default()
    }
}

/// Disk pressure level from which the disk is held responsible.
const CULPRIT_PRESSURE: u8 = 3;

/// The `hlb-metrics` rule that corroborates a node nobody can reach.
///
/// ⚠️ A name owned by another crate, which this one cannot depend on: the controller,
/// which depends on both, has a test that finds each of these in `default_rules()`.
/// Renamed on one side only, the diagnostic would stop attaching the rule and say
/// nothing about it.
pub const NODE_RULE: &str = "node-unreachable";
/// The rule that corroborates a full disk. See [`NODE_RULE`].
pub const DISK_RULE: &str = "disk-full";

/// Walks the chain, from symptom towards cause.
pub fn explain(app: &AppDetail, nodes: &[NodeSummary], alerts: &[ActiveAlert]) -> Chain {
    let name = app.summary.name.clone();
    let mut links = Vec::new();

    // --- Link 1: the symptom -------------------------------------------------
    let failed_tasks: Vec<_> = app.tasks.iter().filter(|t| t.failed).collect();
    let live_tasks = app.tasks.iter().filter(|t| t.alive).count();

    if app.summary.status == "running" && failed_tasks.is_empty() {
        // Nothing to explain. A chain fabricated for a healthy app would send you
        // looking for a problem that does not exist.
        return Chain {
            app: name,
            links: Vec::new(),
            unknown_cause: false,
            remedy: None,
        };
    }

    links.push(Link {
        finding: match (live_tasks, failed_tasks.len()) {
            (0, 0) => format!("{name} has no live replica."),
            (0, n) => format!(
                "{name} has no live replica, and {} failed.",
                crate::plural(n as u64, "replica", "replicas")
            ),
            (v, 0) => format!(
                "{name} runs with {}, but its status is \"{}\".",
                crate::plural(v as u64, "replica", "replicas"),
                app.summary.status
            ),
            (v, n) => format!(
                "{name} runs with {}, and {} failed.",
                crate::plural(v as u64, "replica", "replicas"),
                crate::plural(n as u64, "replica", "replicas")
            ),
        },
        source: None,
    });

    // --- Link 2: what Swarm says ---------------------------------------------
    //
    // 🔴 This is the field the old task counter threw away. Without it the chain
    // stopped at the first link.
    let explanation = failed_tasks.iter().find_map(|t| t.explanation.as_ref());
    if let Some(e) = explanation {
        links.push(Link {
            finding: format!("Swarm reports: {e}"),
            source: failed_tasks.first().map(|t| t.id.clone()),
        });
    }

    // --- Link 3: the node that carried the task ------------------------------
    let node_id = failed_tasks
        .iter()
        .find_map(|t| t.node.clone())
        .or_else(|| app.tasks.iter().find_map(|t| t.node.clone()));

    let node = node_id.as_ref().and_then(|id| {
        nodes
            .iter()
            .find(|n| n.address == *id || n.hostname.as_deref() == Some(id.as_str()))
    });

    let mut cause_found = false;
    let mut remedy = None;

    if let Some(n) = node {
        let node_name = n.hostname.clone().unwrap_or_else(|| n.address.clone());

        if !n.reachable {
            links.push(Link {
                finding: format!(
                    "Node {node_name} is unreachable{}.",
                    n.detail
                        .as_ref()
                        .map(|d| format!(": {d}"))
                        .unwrap_or_default()
                ),
                source: Some(n.address.clone()),
            });
            cause_found = true;
            remedy = Some(format!(
                "Check the machine and the agent: hlb node show {node_name}"
            ));
        } else if let Some(d) = n
            .disks
            .iter()
            .filter(|d| d.pressure >= CULPRIT_PRESSURE)
            .max_by_key(|d| d.pressure)
        {
            links.push(Link {
                finding: format!(
                    "Node {node_name} is short of space on {}: {} % used, {} MB free.",
                    d.path,
                    // ⚠️ `used` is a FRACTION, not a percentage. Displaying it raw
                    // would give "1 % used" on a disk that is 96 % full.
                    (d.used * 100.0).round() as i64,
                    d.free_mb
                ),
                source: Some(n.address.clone()),
            });
            cause_found = true;
            remedy = Some(format!(
                "Free space on {} of node {node_name}, or move the app.",
                d.path
            ));
        }
    }

    // --- Link 4: the alert rule that saw it ----------------------------------
    //
    // ⚠️ An alert is attached ONLY if the node's own reading corroborates it. A global
    // rule firing at the same time is not a cause, and hooking it here would fabricate
    // a link that does not exist.
    if cause_found {
        let expected_rule = if node.is_some_and(|n| !n.reachable) {
            NODE_RULE
        } else {
            DISK_RULE
        };
        if let Some(a) = alerts.iter().find(|a| a.rule == expected_rule) {
            links.push(Link {
                finding: format!("Rule \"{}\" flagged it: {}", a.rule, a.explanation),
                source: Some(a.rule.clone()),
            });
        }
    }

    Chain {
        app: name,
        links,
        unknown_cause: !cause_found,
        remedy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlertLevel, AppSummary, DiskSummary, TaskSummary};

    fn app(name: &str, status: &str, tasks: Vec<TaskSummary>) -> AppDetail {
        AppDetail {
            catalog_changes: Vec::new(),
            assertions: Vec::new(),
            jobs: Vec::new(),
            diagnostic: None,
            summary: AppSummary {
                name: name.into(),
                status: status.into(),
                image: "a/b:1".into(),
                domain: None,
                last_backup_secs: None,
                holds_data: true,
                last_verification_secs: None,
                blocking_guides: 0,
            },
            tasks,
            capabilities: Vec::new(),
            volumes: Vec::new(),
            env: Vec::new(),
            guides: Vec::new(),
            coverage: None,
            backups: Vec::new(),
            restorability: None,
            journal: Vec::new(),
            image: None,
            domain: None,
            manifest: None,
        }
    }

    fn task(id: &str, node: Option<&str>, failed: bool, err: Option<&str>) -> TaskSummary {
        TaskSummary {
            id: id.into(),
            service: "svc".into(),
            slot: Some(1),
            node: node.map(str::to_string),
            state: if failed {
                "failed".into()
            } else {
                "running".into()
            },
            desired_state: "running".into(),
            alive: !failed,
            failed,
            explanation: err.map(str::to_string),
            image: None,
        }
    }

    fn node(address: &str, reachable: bool, pressure: u8) -> NodeSummary {
        NodeSummary {
            address: address.into(),
            hostname: Some(address.into()),
            reachable,
            detail: (!reachable).then(|| "agent muet since 4 min".to_string()),
            report_age_s: Some(30),
            cpu_busy: None,
            load_per_core: None,
            memory_used: None,
            swap_used: None,
            disks: vec![DiskSummary {
                path: "/".into(),
                used: 0.96,
                total_mb: 100_000,
                free_mb: 4_000,
                pressure,
            }],
            uptime_s: None,
            distro: None,
            kernel: None,
            agent_version: None,
            protocol: Some(2),
            tasks: Vec::new(),
            reboot_pending: None,
            protection: None,
        }
    }

    fn alert(rule: &str) -> ActiveAlert {
        ActiveAlert {
            rule: rule.into(),
            level: AlertLevel::Critical,
            explanation: format!("rule {rule} is breached"),
            value: Some(1.0),
            threshold: 0.0,
            since_s: 600,
            muted_until: None,
            muted_by: None,
            mute_reason: None,
        }
    }

    #[test]
    fn a_healthy_app_gets_no_fabricated_chain() {
        // A chain invented for a healthy app would send you hunting a non-problem.
        let a = app(
            "gitea",
            "running",
            vec![task("t1", Some("n1"), false, None)],
        );
        let c = explain(&a, &[node("n1", true, 0)], &[]);
        assert!(!c.has_something_to_say());
        assert!(!c.unknown_cause);
        assert!(c.conclusion().contains("no symptom"));
    }

    #[test]
    fn the_chain_goes_from_the_symptom_all_the_way_to_the_disk() {
        // 🔴 The point: all four links already existed, each on its own screen.
        let a = app(
            "immich",
            "failed",
            vec![task(
                "t1",
                Some("n1"),
                true,
                Some("no space left on device"),
            )],
        );
        let c = explain(&a, &[node("n1", true, 4)], &[alert("disk-full")]);

        assert_eq!(c.links.len(), 4, "{:#?}", c.links);
        assert!(c.links[0].finding.contains("no live replica"));
        assert!(c.links[1].finding.contains("no space left"));
        assert!(c.links[2].finding.contains("short of space"));
        // ⚠️ The percentage, not the fraction: "1 % used" on a full disk would send you
        // looking elsewhere.
        assert!(c.links[2].finding.contains("96 %"), "{:?}", c.links[2]);
        assert!(c.links[3].finding.contains("disk-full"));
        assert!(!c.unknown_cause);
        assert!(c.remedy.is_some());
    }

    #[test]
    fn an_unexplained_failure_stops_honestly() {
        // 🔴 The heart of it: a chain you cannot follow stops on "unknown cause", never
        // on a guess. Repairing the wrong thing costs more than not knowing.
        let a = app(
            "n8n",
            "failed",
            vec![task("t1", Some("n1"), true, Some("exit code 1"))],
        );
        // The node is perfectly fine: nothing explains the failure.
        let c = explain(&a, &[node("n1", true, 0)], &[alert("app-failed")]);

        assert!(c.unknown_cause);
        assert!(c.remedy.is_none(), "no remedy must be invented");
        assert!(
            c.conclusion().contains("service logs"),
            "{}",
            c.conclusion()
        );
        // And above all: the alert that is present is NOT hooked in as a cause.
        assert!(
            !c.links.iter().any(|m| m.finding.contains("Rule")),
            "{:#?}",
            c.links
        );
    }

    #[test]
    fn an_unreachable_node_is_named_as_the_cause() {
        let a = app("gitea", "failed", vec![task("t1", Some("n1"), true, None)]);
        let c = explain(&a, &[node("n1", false, 0)], &[alert("node-unreachable")]);

        assert!(!c.unknown_cause);
        assert!(c.links.iter().any(|m| m.finding.contains("unreachable")));
        assert!(c.links.iter().any(|m| m.finding.contains("agent muet")));
        assert!(c
            .remedy
            .as_deref()
            .is_some_and(|r| r.contains("hlb node show")));
    }

    #[test]
    fn nothing_to_explain_is_not_the_same_as_cannot_explain() {
        // Two opposite answers that a single "empty chain" would conflate.
        let healthy = explain(
            &app("gitea", "running", vec![task("t", Some("n1"), false, None)]),
            &[node("n1", true, 0)],
            &[],
        );
        let opaque = explain(
            &app("gitea", "failed", vec![task("t", Some("n1"), true, None)]),
            &[node("n1", true, 0)],
            &[],
        );

        assert!(!healthy.unknown_cause && !healthy.has_something_to_say());
        assert!(opaque.unknown_cause && opaque.has_something_to_say());
        assert_ne!(healthy.conclusion(), opaque.conclusion());
    }

    #[test]
    fn a_partially_running_app_is_still_explained() {
        // "partial": some replicas live, others fail. This is the case you miss by only
        // asking "is the app running?".
        let a = app(
            "seafile",
            "partial",
            vec![
                task("t1", Some("n1"), false, None),
                task("t2", Some("n1"), true, Some("OOMKilled")),
            ],
        );
        let c = explain(&a, &[node("n1", true, 0)], &[]);
        assert!(c.has_something_to_say());
        assert!(c.links[0].finding.contains("1 replica"), "{:?}", c.links[0]);
        assert!(c.links[1].finding.contains("OOMKilled"));
    }

    #[test]
    fn an_unknown_node_never_invents_a_cause() {
        // The node has vanished from the inventory: nothing can be said about it, and
        // assuming it healthy is as wrong as assuming it dead.
        let a = app(
            "gitea",
            "failed",
            vec![task("t1", Some("parti"), true, None)],
        );
        let c = explain(&a, &[node("n1", true, 0)], &[]);
        assert!(c.unknown_cause);
        assert!(c.remedy.is_none());
    }
}
