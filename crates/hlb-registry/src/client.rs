//! OCI registry client (Distribution API v2).
//!
//! The need: answer "does this tag point at a new digest?" **without downloading the
//! image**. Pulling 500 MB every hour onto a 4 GB node is not an option.
//!
//! Two protocol subtleties are worth knowing:
//!
//! 1. **A `HEAD` request is enough.** The digest arrives in the
//!    `Docker-Content-Digest` header; the manifest body is never needed.
//! 2. **Authentication is discovered.** A `401` carries a `WWW-Authenticate` header
//!    saying where to fetch a token, so no token-service URL is hard-coded.

use crate::reference::ImageRef;
use crate::{Error, Result};

/// Accepted manifest types, multi-architecture index included.
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

    /// Resolves a tag to a digest, without downloading the image.
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
                detail: format!("resolving {image}"),
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

    /// Lists published tags. Used to choose the next version.
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
            context: format!("tag listing for {image}"),
        })?;

        Ok(list.tags)
    }

    /// Performs the request, negotiating a token if the registry asks for one.
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

        // The registry itself says where to look for a token.
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

    /// Negotiates an anonymous token from the `WWW-Authenticate` header.
    async fn fetch_token(&self, challenge: &str, image: &ImageRef) -> Result<String> {
        let realm = extract_param(challenge, "realm").ok_or_else(|| Error::Auth {
            detail: format!("unusable WWW-Authenticate header: \"{challenge}\""),
        })?;

        let service = extract_param(challenge, "service");
        let scope = extract_param(challenge, "scope").unwrap_or_else(|| image.scope());

        let mut params: Vec<(&str, String)> = vec![("scope", scope)];
        if let Some(s) = service {
            params.push(("service", s));
        }

        #[derive(serde::Deserialize)]
        struct TokenResp {
            /// Docker Hub returns `token`, others `access_token`.
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
                detail: format!("the token server answered {}", resp.status()),
            });
        }

        let t: TokenResp = resp.json().await.map_err(|e| Error::Http {
            source: e,
            context: "token server response".into(),
        })?;

        t.token.or(t.access_token).ok_or_else(|| Error::Auth {
            detail: "response carried no token".into(),
        })
    }
}

/// Extracts `key="value"` from a `WWW-Authenticate` header.
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
        // ghcr.io does not always include the scope: fall back to the image's own.
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
