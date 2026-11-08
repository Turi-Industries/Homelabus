//! What each machine's firmware could move to, as fwupd said it in the daily pass.
//! Read only: Homelabus never applies a firmware update.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::{Result, State};

/// One device fwupd offers a newer firmware for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirmwareUpdate {
    /// As fwupd names it: `UEFI dbx`, `System Firmware`…
    pub device: String,
    pub version: String,
    pub latest: String,
    /// The vendor's grading of the newest release, when it gives one: `high`, `critical`…
    pub urgency: Option<String>,
}

/// The last reading of one machine's firmware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeFirmware {
    pub hostname: String,
    /// The last reading that succeeded: `None`, never read.
    pub read_at: Option<i64>,
    /// The last that failed, and why — kept beside an older good reading.
    pub failed_at: Option<i64>,
    pub error: Option<String>,
    /// What the last good reading listed.
    pub updates: Vec<FirmwareUpdate>,
}

impl State {
    /// Records a reading of `hostname`'s firmware: a failure keeps the last good one.
    pub async fn record_firmware(
        &self,
        hostname: &str,
        at: i64,
        reading: std::result::Result<&[FirmwareUpdate], &str>,
    ) -> Result<()> {
        match reading {
            Ok(updates) => {
                sqlx::query(
                    "INSERT INTO node_firmware (hostname, read_at, updates) VALUES (?1, ?2, ?3)
                     ON CONFLICT (hostname) DO UPDATE SET read_at = ?2, updates = ?3,
                         failed_at = NULL, error = NULL",
                )
                .bind(hostname)
                .bind(at)
                .bind(serde_json::to_string(updates).map_err(|source| {
                    crate::Error::StoredFirmware {
                        hostname: hostname.to_string(),
                        source,
                    }
                })?)
                .execute(&self.pool)
                .await?;
            }
            Err(why) => {
                sqlx::query(
                    "INSERT INTO node_firmware (hostname, failed_at, error) VALUES (?1, ?2, ?3)
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

    /// Every machine's last firmware reading, by hostname.
    pub async fn node_firmware(&self) -> Result<Vec<NodeFirmware>> {
        let rows = sqlx::query(
            "SELECT hostname, read_at, failed_at, error, updates FROM node_firmware
             ORDER BY hostname",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let hostname: String = r.try_get("hostname")?;
                let updates: String = r.try_get("updates")?;
                let updates = serde_json::from_str(&updates).map_err(|source| {
                    crate::Error::StoredFirmware {
                        hostname: hostname.clone(),
                        source,
                    }
                })?;
                Ok(NodeFirmware {
                    hostname,
                    read_at: r.try_get("read_at")?,
                    failed_at: r.try_get("failed_at")?,
                    error: r.try_get("error")?,
                    updates,
                })
            })
            .collect()
    }

    /// Forgets the machines no longer in the cluster.
    pub async fn keep_node_firmware(&self, hostnames: &BTreeSet<String>) -> Result<()> {
        let all: Vec<String> = sqlx::query_scalar("SELECT hostname FROM node_firmware")
            .fetch_all(&self.pool)
            .await?;
        for h in all.iter().filter(|h| !hostnames.contains(*h)) {
            sqlx::query("DELETE FROM node_firmware WHERE hostname = ?1")
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

    fn bios() -> FirmwareUpdate {
        FirmwareUpdate {
            device: "System Firmware".into(),
            version: "1.10".into(),
            latest: "1.12".into(),
            urgency: Some("high".into()),
        }
    }

    #[tokio::test]
    async fn a_failed_reading_keeps_the_last_good_one() {
        let s = State::in_memory().await.expect("state");
        s.record_firmware("deb1", 100, Ok(&[bios()]))
            .await
            .expect("read");
        s.record_firmware("deb1", 200, Err("fwupd did not answer"))
            .await
            .expect("failed");
        let [n] = &s.node_firmware().await.expect("listed")[..] else {
            panic!("one machine");
        };
        assert_eq!(n.read_at, Some(100));
        assert_eq!(n.failed_at, Some(200));
        assert_eq!(n.updates, vec![bios()]);

        s.record_firmware("deb1", 300, Ok(&[])).await.expect("read");
        let n = &s.node_firmware().await.expect("listed")[0];
        assert_eq!(
            (n.read_at, n.failed_at, n.updates.len()),
            (Some(300), None, 0)
        );
    }

    #[tokio::test]
    async fn a_machine_gone_is_forgotten() {
        let s = State::in_memory().await.expect("state");
        s.record_firmware("deb1", 1, Ok(&[])).await.expect("read");
        s.record_firmware("deb2", 1, Err("no")).await.expect("read");
        s.keep_node_firmware(&["deb2".to_string()].into())
            .await
            .expect("tidy");
        let left: Vec<String> = s
            .node_firmware()
            .await
            .expect("listed")
            .into_iter()
            .map(|n| n.hostname)
            .collect();
        assert_eq!(left, ["deb2"]);
    }
}
