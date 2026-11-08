//! Each machine's disks and ZFS pools, as the daily pass read them. Read only: a disk is
//! replaced and a pool scrubbed by a person, or by the distribution's own timer.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::{Result, State};

/// One disk, as `smartctl` read it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disk {
    /// As the scan named it: `/dev/sda`, `/dev/nvme0`. Assigned at boot, so a disk is
    /// followed by its serial where it has one.
    pub device: String,
    pub model: Option<String>,
    pub serial: Option<String>,
    /// SMART's overall verdict. `None`: the disk answers no SMART (a USB bridge passing
    /// nothing through).
    pub passed: Option<bool>,
    /// ATA attribute 5, or a SCSI disk's grown defects: sectors the disk moved away from.
    pub reallocated: Option<u64>,
    /// ATA 197: sectors waiting to be reallocated.
    pub pending: Option<u64>,
    /// ATA 198: sectors no retry could read.
    pub uncorrectable: Option<u64>,
    /// NVMe's unrecovered data integrity errors.
    pub media_errors: Option<u64>,
    /// NVMe's critical warning bits: spare, temperature, reliability, read-only.
    pub critical_warning: Option<u64>,
    /// When one of the counters above last grew — a disk wearing out says so by a count
    /// that moves, not by a count that is there.
    pub grew_at: Option<i64>,
    /// Why the disk could not be read: the scan listed it, nothing opened it.
    pub error: Option<String>,
}

impl Disk {
    /// The disk says it is failing: SMART's verdict, or an NVMe critical warning.
    pub fn failing(&self) -> bool {
        self.passed == Some(false) || self.critical_warning.is_some_and(|w| w != 0)
    }

    /// The counters a growth is read on, in one order.
    pub fn counters(&self) -> [Option<u64>; 4] {
        [
            self.reallocated,
            self.pending,
            self.uncorrectable,
            self.media_errors,
        ]
    }

    /// The disk as a person finds it in the machine: its model and serial.
    pub fn name(&self) -> String {
        match (&self.model, &self.serial) {
            (Some(m), Some(s)) => format!("{} ({m}, serial {s})", self.device),
            (Some(m), None) => format!("{} ({m})", self.device),
            _ => self.device.clone(),
        }
    }
}

/// One ZFS pool, as `zpool list` and `zpool status` read it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZPool {
    pub name: String,
    /// `ONLINE`, `DEGRADED`, `FAULTED`…
    pub health: String,
    /// When the last scrub ended. `None`: none on record (never, cancelled, or a
    /// resilver since, which `zpool status` shows in its place).
    pub scrubbed_at: Option<i64>,
    pub scrubbing: bool,
    /// `errors:` said something other than "No known data errors".
    pub data_errors: bool,
    /// The `scan:` line as ZFS wrote it, for the person.
    pub scan: String,
}

impl ZPool {
    pub fn unhealthy(&self) -> bool {
        !self.health.eq_ignore_ascii_case("ONLINE") || self.data_errors
    }
}

/// The last reading of one machine's disks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDisks {
    pub hostname: String,
    /// The last reading that succeeded: `None`, never read.
    pub read_at: Option<i64>,
    /// The last that failed, and why — kept beside an older good reading.
    pub failed_at: Option<i64>,
    pub error: Option<String>,
    pub disks: Vec<Disk>,
    pub pools: Vec<ZPool>,
}

impl State {
    /// Records a reading of `hostname`'s disks: a failure keeps the last good one.
    pub async fn record_disks(
        &self,
        hostname: &str,
        at: i64,
        reading: std::result::Result<(&[Disk], &[ZPool]), &str>,
    ) -> Result<()> {
        let json = |v: serde_json::Result<String>| {
            v.map_err(|source| crate::Error::StoredDisks {
                hostname: hostname.to_string(),
                source,
            })
        };
        match reading {
            Ok((disks, pools)) => {
                sqlx::query(
                    "INSERT INTO node_disks (hostname, read_at, disks, pools)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT (hostname) DO UPDATE SET read_at = ?2, disks = ?3,
                         pools = ?4, failed_at = NULL, error = NULL",
                )
                .bind(hostname)
                .bind(at)
                .bind(json(serde_json::to_string(disks))?)
                .bind(json(serde_json::to_string(pools))?)
                .execute(&self.pool)
                .await?;
            }
            Err(why) => {
                sqlx::query(
                    "INSERT INTO node_disks (hostname, failed_at, error) VALUES (?1, ?2, ?3)
                     ON CONFLICT (hostname) DO UPDATE SET failed_at = ?2, error = ?3",
                )
                .bind(hostname)
                .bind(at)
                .bind(why)
                .execute(&self.pool)
                .await?;
            }
        }
        Ok(())
    }

    /// Every machine's last reading of its disks, by hostname.
    pub async fn node_disks(&self) -> Result<Vec<NodeDisks>> {
        let rows = sqlx::query(
            "SELECT hostname, read_at, failed_at, error, disks, pools FROM node_disks
             ORDER BY hostname",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let hostname: String = r.try_get("hostname")?;
                let stored = |column: &str| -> Result<String> { Ok(r.try_get(column)?) };
                let unreadable = |source| crate::Error::StoredDisks {
                    hostname: hostname.clone(),
                    source,
                };
                let disks = serde_json::from_str(&stored("disks")?).map_err(unreadable)?;
                let pools = serde_json::from_str(&stored("pools")?).map_err(unreadable)?;
                Ok(NodeDisks {
                    hostname: hostname.clone(),
                    read_at: r.try_get("read_at")?,
                    failed_at: r.try_get("failed_at")?,
                    error: r.try_get("error")?,
                    disks,
                    pools,
                })
            })
            .collect()
    }

    /// Forgets the machines no longer in the cluster.
    pub async fn keep_node_disks(&self, hostnames: &BTreeSet<String>) -> Result<()> {
        let all: Vec<String> = sqlx::query_scalar("SELECT hostname FROM node_disks")
            .fetch_all(&self.pool)
            .await?;
        for h in all.iter().filter(|h| !hostnames.contains(*h)) {
            sqlx::query("DELETE FROM node_disks WHERE hostname = ?1")
                .bind(h)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk() -> Disk {
        Disk {
            device: "/dev/sda".into(),
            serial: Some("WD-1".into()),
            passed: Some(true),
            reallocated: Some(8),
            ..Disk::default()
        }
    }

    fn tank() -> ZPool {
        ZPool {
            name: "tank".into(),
            health: "ONLINE".into(),
            scrubbed_at: Some(50),
            ..ZPool::default()
        }
    }

    #[tokio::test]
    async fn a_failed_reading_keeps_the_last_good_one() {
        let s = State::in_memory().await.expect("state");
        s.record_disks("deb2", 100, Ok((&[disk()], &[tank()])))
            .await
            .expect("read");
        s.record_disks("deb2", 200, Err("the node is down"))
            .await
            .expect("failed");
        let [n] = &s.node_disks().await.expect("listed")[..] else {
            panic!("one machine");
        };
        assert_eq!((n.read_at, n.failed_at), (Some(100), Some(200)));
        assert_eq!(
            (n.disks.clone(), n.pools.clone()),
            (vec![disk()], vec![tank()])
        );

        s.record_disks("deb2", 300, Ok((&[], &[])))
            .await
            .expect("read");
        let n = &s.node_disks().await.expect("listed")[0];
        assert_eq!(
            (n.read_at, n.failed_at, n.disks.len()),
            (Some(300), None, 0)
        );
    }

    #[tokio::test]
    async fn a_machine_gone_is_forgotten() {
        let s = State::in_memory().await.expect("state");
        s.record_disks("deb1", 1, Ok((&[], &[])))
            .await
            .expect("read");
        s.record_disks("deb2", 1, Err("no")).await.expect("read");
        s.keep_node_disks(&["deb2".to_string()].into())
            .await
            .expect("tidy");
        let left: Vec<String> = s
            .node_disks()
            .await
            .expect("listed")
            .into_iter()
            .map(|n| n.hostname)
            .collect();
        assert_eq!(left, ["deb2"]);
    }

    #[test]
    fn a_disk_fails_by_its_verdict_or_an_nvme_warning() {
        assert!(!disk().failing());
        let verdict = Disk {
            passed: Some(false),
            ..disk()
        };
        let spare = Disk {
            critical_warning: Some(1),
            ..disk()
        };
        assert!(verdict.failing() && spare.failing());
        assert!(!Disk {
            passed: None,
            ..disk()
        }
        .failing());
    }
}
