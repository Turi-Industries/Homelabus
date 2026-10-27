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

    /// Resolves a tag to a digest, without downloading the image — or, for a reference
    /// already pinned, says whether that digest is still published.
    pub async fn resolve_digest(&self, image: &ImageRef) -> Result<String> {
        let url = image.manifest_url(image.digest.as_deref().unwrap_or(&image.tag));
        let resp = self.get_authorized(&url, image, true).await?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::TagNotFound {
                image: image.to_string(),
            });
        }
        if !status.is_success() {
            return Err(refusal(status, format!("resolving {image}")));
        }

        resp.headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| Error::NoDigest {
                image: image.to_string(),
            })
    }

    /// The platforms an image is published for, as `os/architecture`.
    ///
    /// 🔴 A tag that resolves can still be unrunnable: the catalog named an image built
    /// for FreeBSD alone, and only a pull on a Linux node said so. A multi-platform
    /// index lists its platforms; a single manifest names its own in its configuration.
    pub async fn platforms(&self, image: &ImageRef) -> Result<Vec<String>> {
        let url = image.manifest_url(image.digest.as_deref().unwrap_or(&image.tag));
        let body: serde_json::Value = self.json(&url, image).await?;

        if let Some(list) = body.get("manifests").and_then(|m| m.as_array()) {
            let mut out: Vec<String> = list
                .iter()
                .filter_map(|m| m.get("platform"))
                .filter_map(|p| {
                    let os = p.get("os")?.as_str()?;
                    let arch = p.get("architecture")?.as_str()?;
                    // Attestation manifests carry `unknown/unknown`.
                    (os != "unknown").then(|| format!("{os}/{arch}"))
                })
                .collect();
            out.sort();
            out.dedup();
            return Ok(out);
        }

        let Some(config) = body
            .get("config")
            .and_then(|c| c.get("digest"))
            .and_then(|d| d.as_str())
        else {
            return Ok(Vec::new());
        };
        let cfg: serde_json::Value = self.json(&image.blob_url(config), image).await?;
        Ok(
            match (
                cfg.get("os").and_then(|o| o.as_str()),
                cfg.get("architecture").and_then(|a| a.as_str()),
            ) {
                (Some(os), Some(arch)) => vec![format!("{os}/{arch}")],
                _ => Vec::new(),
            },
        )
    }

    async fn json(&self, url: &str, image: &ImageRef) -> Result<serde_json::Value> {
        let resp = self.get_authorized(url, image, false).await?;
        if !resp.status().is_success() {
            return Err(refusal(resp.status(), format!("reading {url}")));
        }
        let status = resp.status().as_u16();
        let body = bounded(resp, MAX_BODY)
            .await
            .map_err(|detail| Error::Registry { status, detail })?;
        serde_json::from_slice(&body).map_err(|e| Error::Registry {
            status,
            detail: format!("reading {url}: {e}"),
        })
    }

    /// Lists published tags. Used to choose the next version.
    ///
    /// 🔴 Every page, not the first. ghcr.io answers 100 tags a page (1,000 when asked)
    /// in no useful order, with the rest behind a `Link` header: read as the whole
    /// list, Immich's first page held no `v3` tag at all, and every check said it was
    /// up to date. Cut at [`MAX_TAG_PAGES`], said as an error rather than a short list.
    pub async fn list_tags(&self, image: &ImageRef) -> Result<Vec<String>> {
        #[derive(serde::Deserialize)]
        struct TagList {
            #[serde(default)]
            tags: Option<Vec<String>>,
        }

        let mut out = Vec::new();
        let mut url = image.tags_url();
        for _ in 0..MAX_TAG_PAGES {
            let resp = self.get_authorized(&url, image, false).await?;
            if !resp.status().is_success() {
                return Err(refusal(
                    resp.status(),
                    format!("listing the tags of {image}"),
                ));
            }
            let next = resp
                .headers()
                .get("link")
                .and_then(|v| v.to_str().ok())
                .and_then(next_page)
                .map(|n| absolute(&image.registry, &n));
            let status = resp.status().as_u16();
            let body = bounded(resp, MAX_BODY)
                .await
                .map_err(|detail| Error::Registry { status, detail })?;
            let list: TagList = serde_json::from_slice(&body).map_err(|e| Error::Registry {
                status,
                detail: format!("tag listing for {image}: {e}"),
            })?;
            out.extend(list.tags.unwrap_or_default());
            match next {
                Some(n) => url = n,
                None => return Ok(out),
            }
        }
        Err(Error::TooManyTags {
            image: image.to_string(),
            pages: MAX_TAG_PAGES,
        })
    }

    /// When the image was built, from its configuration's `created`; `None` when it
    /// does not say.
    ///
    /// What maturation counts from. 🔴 A missing date is not an old image: a build
    /// that leaves it out, or writes the epoch to be reproducible, would otherwise
    /// read as fifty years mature. A multi-platform index has no date of its own: its
    /// `linux/amd64` image's is read, or its first Linux one's.
    pub async fn created(&self, image: &ImageRef) -> Result<Option<i64>> {
        let reference = image.digest.clone().unwrap_or_else(|| image.tag.clone());
        let mut body: serde_json::Value = self.json(&image.manifest_url(&reference), image).await?;

        if let Some(list) = body.get("manifests").and_then(|m| m.as_array()) {
            let platform = |m: &&serde_json::Value, arch: Option<&str>| {
                let p = m.get("platform");
                let os = p.and_then(|p| p.get("os")).and_then(|o| o.as_str());
                let a = p
                    .and_then(|p| p.get("architecture"))
                    .and_then(|a| a.as_str());
                os == Some("linux") && arch.is_none_or(|want| a == Some(want))
            };
            let Some(digest) = list
                .iter()
                .find(|m| platform(m, Some("amd64")))
                .or_else(|| list.iter().find(|m| platform(m, None)))
                .and_then(|m| m.get("digest"))
                .and_then(|d| d.as_str())
            else {
                return Ok(None);
            };
            body = self.json(&image.manifest_url(digest), image).await?;
        }

        let Some(config) = body
            .get("config")
            .and_then(|c| c.get("digest"))
            .and_then(|d| d.as_str())
        else {
            return Ok(None);
        };
        let cfg: serde_json::Value = self.json(&image.blob_url(config), image).await?;
        Ok(cfg
            .get("created")
            .and_then(|c| c.as_str())
            .and_then(build_date))
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

        let body = bounded(resp, MAX_BODY)
            .await
            .map_err(|detail| Error::Auth { detail })?;
        let t: TokenResp = serde_json::from_slice(&body).map_err(|e| Error::Auth {
            detail: format!("token server response: {e}"),
        })?;

        t.token.or(t.access_token).ok_or_else(|| Error::Auth {
            detail: "response carried no token".into(),
        })
    }
}

/// How many pages of tags are read before giving up: Immich's machine-learning image
/// has 214 of 1,000, most of them builds of a commit.
pub const MAX_TAG_PAGES: usize = 400;

/// A refusal, the rate limit named: Docker Hub allows an anonymous address 100 manifest
/// reads an hour, then refuses even a `HEAD`, and a bare "429" reads as the registry
/// being down.
fn refusal(status: reqwest::StatusCode, detail: String) -> Error {
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Error::RateLimited { detail };
    }
    Error::Registry {
        status: status.as_u16(),
        detail,
    }
}

/// The next page's address in a `Link: <…>; rel="next"` header.
fn next_page(link: &str) -> Option<String> {
    link.split(',').find_map(|part| {
        let (target, params) = part.split_once(';')?;
        params
            .split(';')
            .any(|p| matches!(p.trim(), "rel=\"next\"" | "rel=next"))
            .then(|| {
                target
                    .trim()
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .to_string()
            })
    })
}

/// ghcr.io gives the next page as a path on its own host.
fn absolute(registry: &str, link: &str) -> String {
    if link.starts_with("https://") || link.starts_with("http://") {
        link.to_string()
    } else {
        format!("https://{registry}{link}")
    }
}

/// A configuration's `created`, as Unix seconds — `None` for a date that is not one.
///
/// Before 2000 is not a date: reproducible builds write the epoch, and Docker's own
/// "zero" is year 1.
fn build_date(s: &str) -> Option<i64> {
    const Y2000: i64 = 946_684_800;
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.timestamp())
        .filter(|t| *t >= Y2000)
}

/// Extracts `key="value"` from a `WWW-Authenticate` header.
fn extract_param(header: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let start = header.find(&needle)? + needle.len();
    let rest = &header[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// The most a registry's JSON is read to: a manifest, a configuration or a page of
/// tags is kilobytes to a few hundred.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// A response's body, read to `max` bytes and no further.
///
/// 🔴 `json()` and `text()` read whatever comes: a server answering without end — or
/// whatever sits on the path to it — filled the memory of the process reading it.
async fn bounded(mut resp: reqwest::Response, max: usize) -> std::result::Result<Vec<u8>, String> {
    let too_large = || format!("an answer larger than {max} bytes, not read");
    if resp.content_length().is_some_and(|n| n > max as u64) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > max {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HUB_CHALLENGE: &str = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/postgres:pull""#;

    #[test]
    fn the_next_page_is_read_from_the_link_header() {
        // ghcr.io's own header, measured on immich-server.
        let h = r#"</v2/immich-app/immich-server/tags/list?last=v1.91.1&n=1000>; rel="next""#;
        let next = next_page(h).expect("a next page");
        assert_eq!(
            next,
            "/v2/immich-app/immich-server/tags/list?last=v1.91.1&n=1000"
        );
        assert_eq!(
            absolute("ghcr.io", &next),
            "https://ghcr.io/v2/immich-app/immich-server/tags/list?last=v1.91.1&n=1000"
        );
        assert_eq!(
            absolute("ghcr.io", "https://x.io/v2/a"),
            "https://x.io/v2/a"
        );
        assert_eq!(next_page(r#"</v2/a?n=1>; rel="prev""#), None);
    }

    #[test]
    fn a_build_date_that_is_not_one_is_none() {
        assert_eq!(
            build_date("2026-10-14T09:12:00.123456789Z"),
            Some(1_791_969_120)
        );
        // Reproducible builds, and Docker's zero time: neither is an old image.
        assert_eq!(build_date("1970-01-01T00:00:00Z"), None);
        assert_eq!(build_date("0001-01-01T00:00:00Z"), None);
        assert_eq!(build_date("yesterday"), None);
    }

    #[test]
    fn the_rate_limit_is_named() {
        let e = refusal(reqwest::StatusCode::TOO_MANY_REQUESTS, "resolving x".into());
        assert!(matches!(e, Error::RateLimited { .. }), "{e}");
    }

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
        assert!(extract_param("Bearer realm=no-quotes", "realm").is_none());
    }
}
