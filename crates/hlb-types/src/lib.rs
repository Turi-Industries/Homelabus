//! Types partagés de HomelabUS.
//!
//! Ce crate est volontairement le seul endroit où le schéma est défini. Il alimente :
//!   - le controller et le CLI (Rust, directement) ;
//!   - l'autocomplétion YAML dans l'éditeur (via `schemars` → JSON Schema) ;
//!   - le client TypeScript de l'UI (via l'OpenAPI du controller).
//!
//! Une seule définition, trois consommateurs.

pub mod capability;
pub mod guide;
pub mod rbac;
pub mod manifest;

pub use rbac::Role;
pub use guide::{Automation, Guide, GuideStep, Phase, Severity, Verify};
pub use capability::{CacheEngine, Capability, DbEngine, SsoMode, StorageTier};
pub use manifest::{
    ApiVersion, ExposePolicy, Healthcheck, Image, Ingress, Kind, Manifest, Metadata, Runtime,
    SecuritySpec, Spec, SwarmSpec, UpdateChannel, UpdatePolicy,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("manifest invalide : {0}")]
    Parse(#[from] serde_yaml_ng::Error),

    #[error("validation échouée : {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Règles qui ne peuvent pas être exprimées par le typage seul.
///
/// Chaque règle ici correspond à un moyen concret de se tirer une balle dans le pied,
/// documenté dans le plan.
pub fn validate(m: &Manifest) -> Result<()> {
    // §5.4 — une app en `proxy-header` fait confiance à un en-tête HTTP. Si elle est
    // joignable sans passer par le proxy, `curl -H "Remote-User: admin"` suffit à
    // usurper n'importe quel compte.
    let header_auth = m
        .spec
        .requires
        .iter()
        .any(|c| matches!(c, Capability::Sso { mode, .. } if mode.requires_network_isolation()));

    if header_auth && !m.spec.security.published_ports.is_empty() {
        return Err(Error::Validation(format!(
            "{} utilise l'authentification par en-tête mais publie des ports {:?} : \
             l'app doit être joignable uniquement via le proxy",
            m.metadata.name, m.spec.security.published_ports
        )));
    }

    // §10.2 — une base sur NFS finit par se corrompre : le verrouillage de fichiers
    // n'y est pas fiable.
    for c in &m.spec.requires {
        if let Capability::Storage { tier, sqlite, name, .. } = c {
            if *sqlite && *tier == StorageTier::Nfs {
                return Err(Error::Validation(format!(
                    "volume « {name} » : une base SQLite ne doit jamais être sur NFS"
                )));
            }
        }
    }

    // §7 — `latest` suit un tag mutable : on ne peut ni détecter un changement de
    // façon fiable, ni revenir en arrière. C'est un accident programmé.
    if m.spec.update.channel == UpdateChannel::Latest {
        return Err(Error::Validation(format!(
            "{} : le canal « latest » est interdit — utilise patch, minor ou pin",
            m.metadata.name
        )));
    }

    Ok(())
}

/// Invariants qui ne valent qu'**au moment du déploiement**, pas dans le catalogue.
///
/// Un manifest de catalogue déclare une intention (`tag` + `channel`) ; le digest,
/// lui, est résolu contre le registre à l'installation puis figé dans l'état. Exiger
/// un digest dans le catalogue obligerait à le mettre à jour à chaque publication
/// amont — c'est le rôle du veilleur, pas de l'auteur du manifest.
pub fn validate_pinned(m: &Manifest) -> Result<()> {
    if !m.spec.image.is_pinned() {
        return Err(Error::Validation(format!(
            "{} : déploiement refusé sans digest résolu",
            m.metadata.name
        )));
    }
    Ok(())
}

/// Le JSON Schema du manifest, pour l'autocomplétion dans l'éditeur.
pub fn manifest_json_schema() -> String {
    let schema = schemars::schema_for!(Manifest);
    serde_json::to_string_pretty(&schema).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(yaml: &str) -> Manifest {
        serde_yaml_ng::from_str(yaml).expect("yaml de test valide")
    }

    const BASE: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: test }
spec:
  image: { repo: acme/test, tag: "1.0", digest: "sha256:abc" }
"#;

    #[test]
    fn base_manifest_is_valid() {
        assert!(validate(&manifest(BASE)).is_ok());
    }

    #[test]
    fn rejects_header_auth_with_published_ports() {
        let y = format!(
            "{BASE}  requires:\n    - kind: sso\n      mode: proxy-header\n  \
             security:\n    publishedPorts: [8080]\n"
        );
        let err = validate(&manifest(&y)).unwrap_err();
        assert!(err.to_string().contains("uniquement via le proxy"));
    }

    #[test]
    fn rejects_sqlite_on_nfs() {
        let y = format!(
            "{BASE}  requires:\n    - kind: storage\n      name: data\n      \
             path: /data\n      tier: nfs\n      sqlite: true\n"
        );
        assert!(validate(&manifest(&y)).unwrap_err().to_string().contains("NFS"));
    }

    #[test]
    fn rejects_latest_channel() {
        let y = format!("{BASE}  update: {{ channel: latest }}\n");
        assert!(validate(&manifest(&y)).unwrap_err().to_string().contains("latest"));
    }

    #[test]
    fn catalog_manifest_may_omit_the_digest() {
        // Le digest est résolu à l'installation, pas écrit à la main (§7).
        let y = BASE.replace(", digest: \"sha256:abc\"", "");
        assert!(validate(&manifest(&y)).is_ok());
        assert!(validate_pinned(&manifest(&y)).is_err());
    }

    #[test]
    fn deploy_requires_a_resolved_digest() {
        assert!(validate_pinned(&manifest(BASE)).is_ok());
    }
}
