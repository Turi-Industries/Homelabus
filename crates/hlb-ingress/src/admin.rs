//! Client de l'API d'administration de Caddy.
//!
//! Caddy accepte un Caddyfile brut sur `POST /load` avec le bon `Content-Type`, ce qui
//! évite d'avoir à produire du JSON ou à embarquer le binaire `caddy` pour l'adapter.
//!
//! Le rechargement est **atomique et sans coupure** : si la configuration est refusée,
//! l'ancienne reste active. C'est ce qui rend acceptable de régénérer la config à
//! chaque réconciliation.

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

    /// Charge un Caddyfile. Renvoie une erreur détaillée si Caddy le refuse.
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
            tracing::info!("configuration Caddy rechargée");
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
