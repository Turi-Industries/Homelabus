//! Every machine's disks and pools, read once a day: what SMART and `zpool status` say,
//! kept in the state for the inbox, and said aloud when it turns — a disk failing, an
//! error counter that grew, a pool no longer ONLINE. Nothing is repaired or scheduled.

use std::collections::{BTreeMap, BTreeSet};

use hlb_notify::Notification;
use hlb_orchestrator::{NodeInfo, Orchestrator};
use hlb_state::{Disk, NodeDisks, State, ZPool};
use hlb_updater::disks;

/// Reads every node's disks, records each reading, and returns what turned since the
/// reading before.
pub async fn pass(
    state: &State,
    orchestrator: &dyn Orchestrator,
    at: i64,
) -> hlb_state::Result<Vec<Notification>> {
    let nodes = match orchestrator.nodes().await {
        Ok(n) => n,
        Err(e) => {
            // What was read before stays, ageing until the inbox says it is not known.
            tracing::warn!("no disks read: the nodes could not be listed: {e}");
            return Ok(Vec::new());
        }
    };
    let before: BTreeMap<String, NodeDisks> = state
        .node_disks()
        .await?
        .into_iter()
        .map(|n| (n.hostname.clone(), n))
        .collect();
    let mut said = Vec::new();
    for node in &nodes {
        let previous = before.get(&node.hostname);
        match read(orchestrator, node).await {
            Ok(r) => {
                let disks = disks::carry(
                    previous.map(|p| &p.disks[..]).unwrap_or_default(),
                    r.disks,
                    at,
                );
                said.extend(turned(&node.hostname, previous, &disks, &r.pools, at));
                state
                    .record_disks(&node.hostname, at, Ok((&disks, &r.pools)))
                    .await?;
            }
            Err(why) => {
                tracing::warn!(node = %node.hostname, "its disks were not read: {why}");
                state.record_disks(&node.hostname, at, Err(&why)).await?;
            }
        }
    }
    state
        .keep_node_disks(&nodes.iter().map(|n| n.hostname.clone()).collect())
        .await?;
    Ok(said)
}

/// One node's reading. One that is not ready is not waited for: the job would wait the
/// whole timeout for a node that cannot take it.
async fn read(orchestrator: &dyn Orchestrator, node: &NodeInfo) -> Result<disks::Reading, String> {
    if !node.is_ready() {
        return Err(format!("the node is {}", node.status));
    }
    match orchestrator
        .run_job(&disks::job(node), disks::JOB_TIMEOUT_S)
        .await
    {
        Ok(out) => disks::read(&out),
        Err(e) => Err(e.to_string()),
    }
}

/// What turned on `host` since the reading before: said once, when it happens. What
/// stays wrong stays in the inbox.
pub fn turned(
    host: &str,
    before: Option<&NodeDisks>,
    disks: &[Disk],
    pools: &[ZPool],
    at: i64,
) -> Vec<Notification> {
    let mut said = Vec::new();
    let was_failing: BTreeSet<String> = before
        .map(|b| b.disks.iter().filter(|d| d.failing()).map(key).collect())
        .unwrap_or_default();
    let mut lines = Vec::new();
    for d in disks {
        if d.failing() && !was_failing.contains(&key(d)) {
            lines.push(format!("- {} says it is FAILING{}", d.name(), counts(d)));
        } else if d.grew_at == Some(at) {
            lines.push(format!("- {}: errors grew{}", d.name(), counts(d)));
        }
    }
    if !lines.is_empty() {
        said.push(Notification::important(
            &format!("disk:{host}"),
            &format!("{host}: a disk is wearing out"),
            &format!(
                "{}\n\nA disk says so before it goes, rarely long before. Check that its \
                 data has a copy elsewhere (`hlb backup status`), then replace it.",
                lines.join("\n")
            ),
        ));
    }
    let was_unhealthy: BTreeSet<&str> = before
        .map(|b| {
            b.pools
                .iter()
                .filter(|p| p.unhealthy())
                .map(|p| p.name.as_str())
                .collect()
        })
        .unwrap_or_default();
    for p in pools
        .iter()
        .filter(|p| p.unhealthy() && !was_unhealthy.contains(p.name.as_str()))
    {
        let what = if p.data_errors && p.health.eq_ignore_ascii_case("ONLINE") {
            "holds files ZFS could not repair (`zpool status -v` names them)".to_string()
        } else {
            format!(
                "is {}: a disk is gone or failing, and the redundancy that was protecting \
                 you is spent. The next failure is the one that loses data",
                p.health
            )
        };
        said.push(Notification::critical(
            &format!("pool:{host}/{}", p.name),
            &format!("{host}: the pool {} {}", p.name, p.health),
            &format!("The ZFS pool {} on {host} {what}.", p.name),
        ));
    }
    said
}

/// A disk across readings: its serial, or its device where it has none.
fn key(d: &Disk) -> String {
    d.serial.clone().unwrap_or_else(|| d.device.clone())
}

fn counts(d: &Disk) -> String {
    let named = [
        ("reallocated", d.reallocated),
        ("pending", d.pending),
        ("unreadable", d.uncorrectable),
        ("media errors", d.media_errors),
    ];
    let shown: Vec<String> = named
        .iter()
        .filter_map(|(n, v)| v.filter(|v| *v > 0).map(|v| format!("{v} {n}")))
        .collect();
    if shown.is_empty() {
        String::new()
    } else {
        format!(" ({})", shown.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sda(reallocated: u64) -> Disk {
        Disk {
            device: "/dev/sda".into(),
            model: Some("WDC WD40EFRX".into()),
            serial: Some("WD-1".into()),
            passed: Some(true),
            reallocated: Some(reallocated),
            ..Disk::default()
        }
    }

    fn node(disks: Vec<Disk>, pools: Vec<ZPool>) -> NodeDisks {
        NodeDisks {
            hostname: "deb2".into(),
            read_at: Some(1),
            failed_at: None,
            error: None,
            disks,
            pools,
        }
    }

    fn tank(health: &str) -> ZPool {
        ZPool {
            name: "tank".into(),
            health: health.into(),
            ..ZPool::default()
        }
    }

    #[test]
    fn a_disk_growing_errors_or_failing_is_said_once() {
        let grown = disks::carry(&[sda(8)], vec![sda(10)], 2);
        let said = turned("deb2", Some(&node(vec![sda(8)], vec![])), &grown, &[], 2);
        assert_eq!(said.len(), 1);
        assert!(said[0].body.contains("WD-1") && said[0].body.contains("10 reallocated"));
        // The next day nothing moved: nothing said, the inbox keeps it.
        let still = disks::carry(&grown, vec![sda(10)], 3);
        assert!(turned("deb2", Some(&node(grown.clone(), vec![])), &still, &[], 3).is_empty());

        let failing = Disk {
            passed: Some(false),
            ..sda(10)
        };
        let said = turned(
            "deb2",
            Some(&node(still, vec![])),
            std::slice::from_ref(&failing),
            &[],
            4,
        );
        assert!(said[0].body.contains("FAILING"), "{}", said[0].body);
        assert!(turned(
            "deb2",
            Some(&node(vec![failing.clone()], vec![])),
            &[failing],
            &[],
            5
        )
        .is_empty());
    }

    #[test]
    fn a_disk_seen_for_the_first_time_with_errors_is_not_a_growth() {
        // Counted errors a disk came with are the inbox's to show, not a change to shout.
        let first = disks::carry(&[], vec![sda(8)], 1);
        assert!(turned("deb2", None, &first, &[], 1).is_empty());
    }

    #[test]
    fn a_pool_leaving_online_is_said_once() {
        let said = turned(
            "deb2",
            Some(&node(vec![], vec![tank("ONLINE")])),
            &[],
            &[tank("DEGRADED")],
            2,
        );
        assert_eq!(said.len(), 1);
        assert_eq!(said[0].subject, "pool:deb2/tank");
        assert!(said[0].body.contains("redundancy"), "{}", said[0].body);
        assert!(turned(
            "deb2",
            Some(&node(vec![], vec![tank("DEGRADED")])),
            &[],
            &[tank("DEGRADED")],
            3
        )
        .is_empty());
        let errors = ZPool {
            data_errors: true,
            ..tank("ONLINE")
        };
        let said = turned(
            "deb2",
            Some(&node(vec![], vec![tank("ONLINE")])),
            &[],
            &[errors],
            4,
        );
        assert!(
            said[0].body.contains("could not repair"),
            "{}",
            said[0].body
        );
    }
}
