//! The house's router, as `hlb router connect` declared it. Its API key is the vault's.

use sqlx::Row;

use crate::{Result, State};

/// Where the router is, how it is recognised, and where Caddy sits on its network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterConfig {
    /// `https://10.77.0.3`: its interface, whose API is under `/api`.
    pub url: String,
    /// The SHA-256 of the certificate it presents, 64 small hex digits: the only one
    /// accepted there.
    pub fingerprint: String,
    /// Caddy's address on the router's network, which the house's names resolve to
    /// inside. Not Swarm's: a node advertises its mesh address, which the router does
    /// not reach.
    pub caddy: String,
}

/// The controller's last `router sync`: when it ran, and what did not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterSync {
    pub at: i64,
    /// One line per name the router could not be made to answer, or why the run went no
    /// further; `None` when everything held.
    pub failed: Option<String>,
}

/// Stored names. ⚠️ Stored values.
const URL: &str = "router-url";
const FINGERPRINT: &str = "router-fingerprint";
const CADDY: &str = "router-caddy";
const SYNC_AT: &str = "router-sync-at";
const SYNC_FAILED: &str = "router-sync-failed";

impl State {
    pub async fn router(&self) -> Result<Option<RouterConfig>> {
        let (Some(url), Some(fingerprint), Some(caddy)) = (
            self.setting(URL).await?,
            self.setting(FINGERPRINT).await?,
            self.setting(CADDY).await?,
        ) else {
            return Ok(None);
        };
        Ok(Some(RouterConfig {
            url,
            fingerprint,
            caddy,
        }))
    }

    pub async fn set_router(&self, r: &RouterConfig) -> Result<()> {
        self.put_setting(URL, Some(&r.url)).await?;
        self.put_setting(FINGERPRINT, Some(&r.fingerprint)).await?;
        self.put_setting(CADDY, Some(&r.caddy)).await
    }

    /// `None` until the controller first ran a sync, or when the time stored is not one.
    pub async fn router_sync(&self) -> Result<Option<RouterSync>> {
        let Some(at) = self.setting(SYNC_AT).await?.and_then(|t| t.parse().ok()) else {
            return Ok(None);
        };
        Ok(Some(RouterSync {
            at,
            failed: self.setting(SYNC_FAILED).await?,
        }))
    }

    /// Each node's declared address on the house's network, by hostname, sorted.
    pub async fn router_addresses(&self) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query("SELECT node, address FROM router_addresses ORDER BY node")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("node")?, r.try_get("address")?)))
            .collect()
    }

    /// `None` forgets it.
    pub async fn set_router_address(&self, node: &str, address: Option<&str>) -> Result<()> {
        match address {
            Some(a) => {
                sqlx::query(
                    "INSERT INTO router_addresses (node, address) VALUES (?1, ?2) \
                     ON CONFLICT (node) DO UPDATE SET address = excluded.address",
                )
                .bind(node)
                .bind(a)
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM router_addresses WHERE node = ?1")
                    .bind(node)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// Each declared network beyond the trusted one — `devices`, `guests` — and the VLAN
    /// tag it is carried on, sorted by kind. A tag stored out of range reads as none.
    pub async fn router_networks(&self) -> Result<Vec<(String, u16)>> {
        let rows = sqlx::query("SELECT kind, vlan FROM router_networks ORDER BY kind")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let vlan: i64 = r.try_get("vlan")?;
            if let Ok(v) = u16::try_from(vlan) {
                out.push((r.try_get("kind")?, v));
            }
        }
        Ok(out)
    }

    /// `None` forgets it. Two kinds on one tag are refused by the table: the caller
    /// says why first.
    pub async fn set_router_network(&self, kind: &str, vlan: Option<u16>) -> Result<()> {
        match vlan {
            Some(v) => {
                sqlx::query(
                    "INSERT INTO router_networks (kind, vlan) VALUES (?1, ?2) \
                     ON CONFLICT (kind) DO UPDATE SET vlan = excluded.vlan",
                )
                .bind(kind)
                .bind(i64::from(v))
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM router_networks WHERE kind = ?1")
                    .bind(kind)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn record_router_sync(&self, r: &RouterSync) -> Result<()> {
        // The failure first: a crash between the two leaves the old time beside the
        // new verdict, read stale — never a fresh time over a failure that was fixed.
        self.put_setting(SYNC_FAILED, r.failed.as_deref()).await?;
        self.put_setting(SYNC_AT, Some(&r.at.to_string())).await
    }
}

#[cfg(test)]
mod tests {
    use super::{RouterConfig, RouterSync};
    use crate::State;

    #[tokio::test]
    async fn the_router_reads_back_as_declared() {
        let s = State::in_memory().await.expect("state");
        assert_eq!(s.router().await.expect("read"), None);
        let r = RouterConfig {
            url: "https://10.77.0.3".into(),
            fingerprint: "ab".repeat(32),
            caddy: "10.77.0.11".into(),
        };
        s.set_router(&r).await.expect("kept");
        assert_eq!(s.router().await.expect("read"), Some(r.clone()));
        let moved = RouterConfig {
            caddy: "10.77.0.12".into(),
            ..r
        };
        s.set_router(&moved).await.expect("kept");
        assert_eq!(s.router().await.expect("read"), Some(moved));
    }

    #[tokio::test]
    async fn a_nodes_address_is_declared_moved_and_forgotten() {
        let s = State::in_memory().await.expect("state");
        assert!(s.router_addresses().await.expect("read").is_empty());
        s.set_router_address("deb2", Some("10.77.0.12"))
            .await
            .expect("kept");
        s.set_router_address("deb1", Some("10.77.0.10"))
            .await
            .expect("kept");
        s.set_router_address("deb1", Some("10.77.0.11"))
            .await
            .expect("moved");
        assert_eq!(
            s.router_addresses().await.expect("read"),
            vec![
                ("deb1".to_string(), "10.77.0.11".to_string()),
                ("deb2".to_string(), "10.77.0.12".to_string())
            ]
        );
        s.set_router_address("deb2", None).await.expect("forgotten");
        assert_eq!(s.router_addresses().await.expect("read").len(), 1);
    }

    #[tokio::test]
    async fn a_network_is_declared_retagged_and_forgotten_one_tag_each() {
        let s = State::in_memory().await.expect("state");
        assert!(s.router_networks().await.expect("read").is_empty());
        s.set_router_network("guests", Some(30))
            .await
            .expect("kept");
        s.set_router_network("devices", Some(20))
            .await
            .expect("kept");
        s.set_router_network("devices", Some(21))
            .await
            .expect("retagged");
        assert_eq!(
            s.router_networks().await.expect("read"),
            vec![("devices".to_string(), 21), ("guests".to_string(), 30)]
        );
        s.set_router_network("guests", Some(21))
            .await
            .expect_err("one tag, two networks");
        s.set_router_network("devices", None)
            .await
            .expect("forgotten");
        assert_eq!(
            s.router_networks().await.expect("read"),
            vec![("guests".to_string(), 30)]
        );
    }

    #[tokio::test]
    async fn a_sync_that_failed_then_held_reads_as_held() {
        let s = State::in_memory().await.expect("state");
        assert_eq!(s.router_sync().await.expect("read"), None);
        let failed = RouterSync {
            at: 100,
            failed: Some("gitea.home.org — answered 10.77.0.11: 500".into()),
        };
        s.record_router_sync(&failed).await.expect("kept");
        assert_eq!(s.router_sync().await.expect("read"), Some(failed));
        let held = RouterSync {
            at: 200,
            failed: None,
        };
        s.record_router_sync(&held).await.expect("kept");
        assert_eq!(s.router_sync().await.expect("read"), Some(held));
    }
}
