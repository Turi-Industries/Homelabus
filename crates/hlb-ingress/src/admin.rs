//! Client for Caddy's admin API.
//!
//! Caddy accepts a raw Caddyfile on `POST /load` with the right `Content-Type`, which
//! avoids producing JSON or embedding the `caddy` binary to adapt it.
//!
//! Reloading is **atomic and without downtime**: if the configuration is refused, the
//! previous one stays active. That is what makes it acceptable to regenerate the config
//! on every reconciliation.

use crate::{Error, Result};

pub struct CaddyAdmin {
    base_url: String,
    client: reqwest::Client,
}

impl CaddyAdmin {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Loads a Caddyfile. Returns a detailed error if Caddy refuses it.
    pub async fn load_caddyfile(&self, caddyfile: &str) -> Result<()> {
        let url = format!("{}/load", self.base_url.trim_end_matches('/'));

        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "text/caddyfile")
            .body(caddyfile.to_string())
            .send()
            .await
            .map_err(|source| Error::Unreachable {
                url: url.clone(),
                source,
            })?;

        let status = resp.status();
        if status.is_success() {
            tracing::info!("Caddy configuration reloaded");
            return Ok(());
        }

        let body = resp.text().await.unwrap_or_default();
        Err(Error::Rejected {
            status: status.as_u16(),
            body,
        })
    }

    pub async fn ping(&self) -> Result<String> {
        let url = format!("{}/config/", self.base_url.trim_end_matches('/'));
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|source| Error::Unreachable { url, source })?;
        Ok(resp.text().await.unwrap_or_default())
    }
}
