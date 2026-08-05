//! Analyse des références d'image OCI.
//!
//! `postgres:17-alpine` et `ghcr.io/pocket-id/pocket-id:v1` désignent des choses très
//! différentes une fois normalisées. Les règles implicites de Docker (registre par
//! défaut, préfixe `library/`) sont une source classique d'erreurs — d'où un type
//! dédié plutôt que de la manipulation de chaînes éparpillée.

use std::fmt;

pub const DOCKER_HUB: &str = "registry-1.docker.io";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// Hôte du registre, déjà normalisé.
    pub registry: String,
    /// Chemin complet, préfixe `library/` inclus pour les images officielles.
    pub repository: String,
    pub tag: String,
    /// Présent si la référence était déjà épinglée.
    pub digest: Option<String>,
}

impl ImageRef {
    /// Analyse une référence, en appliquant les règles implicites de Docker.
    pub fn parse(s: &str) -> Self {
        // Le digest se sépare en premier : il peut suivre un tag.
        let (rest, digest) = match s.split_once('@') {
            Some((r, d)) => (r, Some(d.to_string())),
            None => (s, None),
        };

        // Un « / » avant le premier segment, avec un point, un « : » ou « localhost »,
        // désigne un registre. Sinon c'est un chemin de dépôt sur le Hub.
        let (registry, remainder) = match rest.split_once('/') {
            Some((head, tail))
                if head.contains('.') || head.contains(':') || head == "localhost" =>
            {
                (head.to_string(), tail.to_string())
            }
            _ => (DOCKER_HUB.to_string(), rest.to_string()),
        };

        // ⚠️ Le « : » du tag ne doit pas être confondu avec celui d'un port : on ne
        // cherche donc le tag qu'après le dernier « / ».
        let (repo, tag) = match remainder.rsplit_once(':') {
            Some((r, t)) if !t.contains('/') => (r.to_string(), t.to_string()),
            _ => (remainder.clone(), "latest".to_string()),
        };

        // Les images officielles du Hub vivent sous `library/`.
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

    /// URL de l'API v2 pour un manifest.
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

    /// La portée à demander au serveur de jetons.
    pub fn scope(&self) -> String {
        format!("repository:{}:pull", self.repository)
    }

    pub fn is_pinned(&self) -> bool {
        self.digest.is_some()
    }

    /// La même image, épinglée sur un digest.
    pub fn pinned(&self, digest: &str) -> String {
        format!("{}:{}@{digest}", self.name(), self.tag)
    }

    /// Le nom tel qu'un humain l'écrirait, sans tag.
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
        // Le piège classique : « : » sert au port ET au tag.
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
