//! The house's router, as `hlb router connect` declared it. Its API key is the vault's.

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

/// Stored names. ⚠️ Stored values.
const URL: &str = "router-url";
const FINGERPRINT: &str = "router-fingerprint";
const CADDY: &str = "router-caddy";

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
}

#[cfg(test)]
mod tests {
    use super::RouterConfig;
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
}
