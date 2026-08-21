//! Parsing OCI image references.
//!
//! `postgres:17-alpine` and `ghcr.io/pocket-id/pocket-id:v1` mean very different
//! things once normalised. Docker's implicit rules (default registry, `library/`
//! prefix) are a classic source of mistakes - hence a dedicated type rather than
//! string handling scattered around.

use std::fmt;

pub const DOCKER_HUB: &str = "registry-1.docker.io";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// Registry host, already normalised.
    pub registry: String,
    /// Full path, `library/` prefix included for official images.
    pub repository: String,
    pub tag: String,
    /// Present when the reference was already pinned.
    pub digest: Option<String>,
}

impl ImageRef {
    /// Parses a reference, applying Docker's implicit rules.
    pub fn parse(s: &str) -> Self {
        // The digest is split off first: it can follow a tag.
        let (rest, digest) = match s.split_once('@') {
            Some((r, d)) => (r, Some(d.to_string())),
            None => (s, None),
        };

        // A "/" before the first segment, together with a dot, a ":" or "localhost",
        // marks a registry. Otherwise it is a repository path on the Hub.
        let (registry, remainder) = match rest.split_once('/') {
            Some((head, tail))
                if head.contains('.') || head.contains(':') || head == "localhost" =>
            {
                (head.to_string(), tail.to_string())
            }
            _ => (DOCKER_HUB.to_string(), rest.to_string()),
        };

        // ⚠️ The tag's ":" must not be confused with a port's, so the tag is only
        // looked for after the last "/".
        let (repo, tag) = match remainder.rsplit_once(':') {
            Some((r, t)) if !t.contains('/') => (r.to_string(), t.to_string()),
            _ => (remainder.clone(), "latest".to_string()),
        };

        // The Hub's official images live under `library/`.
        let repository = if registry == DOCKER_HUB && !repo.contains('/') {
            format!("library/{repo}")
        } else {
            repo
        };

        Self {
            registry,
            repository,
            tag,
            digest,
        }
    }

    /// The v2 API URL for a manifest.
    pub fn manifest_url(&self, reference: &str) -> String {
        format!(
            "https://{}/v2/{}/manifests/{reference}",
            self.registry, self.repository
        )
    }

    pub fn tags_url(&self) -> String {
        format!(
            "https://{}/v2/{}/tags/list?n=1000",
            self.registry, self.repository
        )
    }

    /// The scope to request from the token server.
    pub fn scope(&self) -> String {
        format!("repository:{}:pull", self.repository)
    }

    pub fn is_pinned(&self) -> bool {
        self.digest.is_some()
    }

    /// The same image, pinned to a digest.
    pub fn pinned(&self, digest: &str) -> String {
        format!("{}:{}@{digest}", self.name(), self.tag)
    }

    /// The name as a human would write it, without a tag.
    pub fn name(&self) -> String {
        if self.registry == DOCKER_HUB {
            self.repository
                .strip_prefix("library/")
                .unwrap_or(&self.repository)
                .to_string()
        } else {
            format!("{}/{}", self.registry, self.repository)
        }
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.name(), self.tag)?;
        if let Some(d) = &self.digest {
            write!(f, "@{d}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_images_get_the_library_prefix() {
        let r = ImageRef::parse("postgres:17-alpine");
        assert_eq!(r.registry, DOCKER_HUB);
        assert_eq!(r.repository, "library/postgres");
        assert_eq!(r.tag, "17-alpine");
        assert_eq!(r.name(), "postgres");
    }

    #[test]
    fn hub_user_images_keep_their_namespace() {
        let r = ImageRef::parse("vikunja/vikunja:0.24");
        assert_eq!(r.registry, DOCKER_HUB);
        assert_eq!(r.repository, "vikunja/vikunja");
        assert_eq!(r.name(), "vikunja/vikunja");
    }

    #[test]
    fn other_registries_are_detected_by_the_dot() {
        let r = ImageRef::parse("ghcr.io/pocket-id/pocket-id:v1");
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "pocket-id/pocket-id");
        assert_eq!(r.tag, "v1");
    }

    #[test]
    fn a_registry_port_is_not_a_tag() {
        // The classic trap: ":" serves both the port AND the tag.
        let r = ImageRef::parse("registre.local:5000/mon/app:2.1");
        assert_eq!(r.registry, "registre.local:5000");
        assert_eq!(r.repository, "mon/app");
        assert_eq!(r.tag, "2.1");
    }

    #[test]
    fn a_registry_port_without_tag_defaults_to_latest() {
        let r = ImageRef::parse("registre.local:5000/mon/app");
        assert_eq!(r.registry, "registre.local:5000");
        assert_eq!(r.repository, "mon/app");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn localhost_is_a_registry() {
        let r = ImageRef::parse("localhost/test:1");
        assert_eq!(r.registry, "localhost");
        assert_eq!(r.repository, "test");
    }

    #[test]
    fn a_digest_is_extracted_and_flagged() {
        let r = ImageRef::parse("gitea/gitea:1.24@sha256:abc123");
        assert_eq!(r.tag, "1.24");
        assert_eq!(r.digest.as_deref(), Some("sha256:abc123"));
        assert!(r.is_pinned());
    }

    #[test]
    fn missing_tag_means_latest() {
        assert_eq!(ImageRef::parse("alpine").tag, "latest");
    }

    #[test]
    fn urls_are_wellformed() {
        let r = ImageRef::parse("postgres:17");
        assert_eq!(
            r.manifest_url("17"),
            "https://registry-1.docker.io/v2/library/postgres/manifests/17"
        );
        assert_eq!(r.scope(), "repository:library/postgres:pull");
    }

    #[test]
    fn pinning_keeps_the_readable_name() {
        let r = ImageRef::parse("postgres:17-alpine");
        assert_eq!(r.pinned("sha256:xyz"), "postgres:17-alpine@sha256:xyz");
    }

    #[test]
    fn display_roundtrips() {
        for s in [
            "postgres:17-alpine",
            "vikunja/vikunja:0.24",
            "ghcr.io/pocket-id/pocket-id:v1",
        ] {
            assert_eq!(ImageRef::parse(s).to_string(), s);
        }
    }
}
