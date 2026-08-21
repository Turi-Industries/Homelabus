//! Client de registre OCI (API Distribution v2).
//!
//! Le besoin du §7 : répondre à « ce tag pointe-t-il vers un nouveau digest ? »
//! **sans télécharger l'image**. Tirer 500 Mo toutes les heures sur un nœud à 4 Go
//! n'est pas une option.
//!
//! Deux subtilités du protocole valent la peine d'être connues :
//!
//! 1. **Une requête `HEAD` suffit.** Le digest arrive dans l'en-tête
//!    `Docker-Content-Digest` ; on n'a jamais besoin du corps du manifest.
//! 2. **L'authentification se découvre.** Un `401` porte un en-tête
//!    `WWW-Authenticate` qui indique où récupérer un jeton. On ne code donc en dur
//!    aucune URL de service de jetons.

use crate::reference::ImageRef;
use crate::{Error, Result};

/// Types de manifest acceptés, index multi-architecture inclus.
const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
                      application/vnd.oci.image.manifest.v1+json, \
                      application/vnd.docker.distribution.manifest.list.v2+json, \
                      application/vnd.docker.distribution.manifest.v2+json";

pub struct RegistryClient {
    http: reqwest::Client,
}

impl Default for RegistryClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .user_agent("homelabus/0.1")
                .build()
                .unwrap_or_default(),
        }
    }

    /// Résout un tag en digest, sans télécharger l'image.
    pub async fn resolve_digest(&self, image: &ImageRef) -> Result<String> {
        let url = image.manifest_url(&image.tag);
        let resp = self.get_authorized(&url, image, true).await?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::TagNotFound {
                image: image.to_string(),
            });
        }
        if !status.is_success() {
            return Err(Error::Registry {
                status: status.as_u16(),
                detail: format!("résolution de {image}"),
            });
        }

        resp.headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| Error::NoDigest {
                image: image.to_string(),
            })
    }

    /// Liste les tags publiés. Sert à choisir la prochaine version (§7).
    pub async fn list_tags(&self, image: &ImageRef) -> Result<Vec<String>> {
        let resp = self.get_authorized(&image.tags_url(), image, false).await?;

        if !resp.status().is_success() {
            return Err(Error::Registry {
                status: resp.status().as_u16(),
                detail: format!("liste des tags de {image}"),
            });
        }

        #[derive(serde::Deserialize)]
        struct TagList {
            #[serde(default)]
            tags: Vec<String>,
        }

        let list: TagList = resp.json().await.map_err(|e| Error::Http {
            source: e,
            context: format!("réponse tags de {image}"),
        })?;

        Ok(list.tags)
    }

    /// Effectue la requête, en négociant un jeton si le registre en demande un.
    async fn get_authorized(
        &self,
        url: &str,
        image: &ImageRef,
        head: bool,
    ) -> Result<reqwest::Response> {
        let build = |token: Option<&str>| {
            let mut req = if head {
                self.http.head(url)
            } else {
                self.http.get(url)
            }
            .header("Accept", ACCEPT);
            if let Some(t) = token {
                req = req.bearer_auth(t);
            }
            req
        };

        let first = build(None).send().await.map_err(|e| Error::Http {
            source: e,
            context: url.to_string(),
        })?;

        if first.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(first);
        }

        // Le registre nous dit lui-même où chercher un jeton.
        let challenge = first
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();

        let token = self.fetch_token(&challenge, image).await?;

        build(Some(&token)).send().await.map_err(|e| Error::Http {
            source: e,
            context: url.to_string(),
        })
    }

    /// Négocie un jeton anonyme à partir de l'en-tête `WWW-Authenticate`.
    async fn fetch_token(&self, challenge: &str, image: &ImageRef) -> Result<String> {
        let realm = extract_param(challenge, "realm").ok_or_else(|| Error::Auth {
            detail: format!("en-tête WWW-Authenticate inexploitable : « {challenge} »"),
        })?;

        let service = extract_param(challenge, "service");
        let scope = extract_param(challenge, "scope").unwrap_or_else(|| image.scope());

        let mut params: Vec<(&str, String)> = vec![("scope", scope)];
        if let Some(s) = service {
            params.push(("service", s));
        }

        #[derive(serde::Deserialize)]
        struct TokenResp {
            /// Docker Hub renvoie `token`, d'autres `access_token`.
            token: Option<String>,
            access_token: Option<String>,
        }

        let resp = self
            .http
            .get(&realm)
            .query(&params)
            .send()
            .await
            .map_err(|e| Error::Http {
                source: e,
                context: realm.clone(),
            })?;

        if !resp.status().is_success() {
            return Err(Error::Auth {
                detail: format!("le serveur de jetons a répondu {}", resp.status()),
            });
        }

        let t: TokenResp = resp.json().await.map_err(|e| Error::Http {
            source: e,
            context: "réponse du serveur de jetons".into(),
        })?;

        t.token.or(t.access_token).ok_or_else(|| Error::Auth {
            detail: "réponse sans jeton".into(),
        })
    }
}

/// Extrait `clé="valeur"` d'un en-tête `WWW-Authenticate`.
fn extract_param(header: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = header.find(&needle)? + needle.len();
    let rest = &header[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HUB_CHALLENGE: &str = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/postgres:pull""#;

    #[test]
    fn parses_the_docker_hub_challenge() {
        assert_eq!(
            extract_param(HUB_CHALLENGE, "realm").as_deref(),
            Some("https://auth.docker.io/token")
        );
        assert_eq!(
            extract_param(HUB_CHALLENGE, "service").as_deref(),
            Some("registry.docker.io")
        );
        assert_eq!(
            extract_param(HUB_CHALLENGE, "scope").as_deref(),
            Some("repository:library/postgres:pull")
        );
    }

    #[test]
    fn a_challenge_without_scope_is_tolerated() {
        // ghcr.io n'inclut pas toujours la portée : on retombe sur celle de l'image.
        let c = r#"Bearer realm="https://ghcr.io/token",service="ghcr.io""#;
        assert!(extract_param(c, "scope").is_none());
        assert_eq!(
            extract_param(c, "realm").as_deref(),
            Some("https://ghcr.io/token")
        );
    }

    #[test]
    fn a_malformed_challenge_yields_none() {
        assert!(extract_param("Basic", "realm").is_none());
        assert!(extract_param("Bearer realm=sans-guillemets", "realm").is_none());
    }
}
