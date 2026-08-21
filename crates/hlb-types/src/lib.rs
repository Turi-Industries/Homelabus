//! Homelabus shared types.
//!
//! This crate is deliberately the only place the schema is defined. It feeds:
//!   - the controller and the CLI (Rust, directly);
//!   - YAML autocompletion in the editor (through `schemars` → JSON Schema).
//!
//! ⚠️ The UI does NOT go through a generated client: since egui was chosen it is in
//! Rust and consumes `hlb-api` directly. An OpenAPI layer plus TypeScript generation
//! would be moot - that is the main architectural benefit of the choice, and it is
//! worth stating here.

pub mod capability;
pub mod guide;
pub mod manifest;
pub mod rbac;
pub mod token;

pub use guide::{Automation, Guide, GuideStep, Phase, Severity, Verify};
pub use rbac::Role;
pub use token::{generate as generate_token, StoredToken};
pub mod binding;

pub use binding::{redact, substitute, Token};
pub use capability::{CacheEngine, Capability, DbEngine, SsoMode, StorageTier};
pub use manifest::{
    ApiVersion, Companion, CompanionVolume, ExposePolicy, Healthcheck, Image, Ingress, Kind,
    Manifest, Metadata, Runtime, SecuritySpec, Spec, SwarmSpec, UpdateChannel, UpdatePolicy,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("manifest invalide : {0}")]
    Parse(#[from] serde_yaml_ng::Error),

    #[error("validation failed: {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Rules that types alone cannot express.
///
/// Each rule here corresponds to a concrete way of shooting yourself in the foot.
pub fn validate(m: &Manifest) -> Result<()> {
    // An app on `proxy-header` trusts an HTTP header. If it is reachable without
    // going through the proxy, `curl -H "Remote-User: admin"` is enough to impersonate
    // any account.
    let header_auth =
        m.spec.requires.iter().any(
            |c| matches!(c, Capability::Sso { mode, .. } if mode.requires_network_isolation()),
        );

    if header_auth && !m.spec.security.published_ports.is_empty() {
        return Err(Error::Validation(format!(
            "{} uses header authentication but publishes ports {:?}: the app must be \
             reachable only through the proxy",
            m.metadata.name, m.spec.security.published_ports
        )));
    }

    // 🔴 `mode: native` without `redirectPaths` produces an OIDC client with NO
    // redirect URI. PocketID then has nothing to send the user back to, and the failure
    // only shows on the return leg of the sign-in, as a message about an unregistered
    // URI that never says which one it expected.
    //
    // The manifest is refused here rather than letting a useless client be planned:
    // this is an authoring mistake, and it is reported with its line number.
    for c in &m.spec.requires {
        if let Capability::Sso {
            mode: SsoMode::Native,
            redirect_paths,
        } = c
        {
            if redirect_paths.is_empty() {
                return Err(Error::Validation(format!(
                    "{} declares \"sso: native\" with no redirectPaths: the OIDC \
                     client would have no redirect URI and sign-in would fail on the \
                     way back. Give the app's callback path, or switch to \
                     \"proxy-only\" if it does not speak OIDC",
                    m.metadata.name
                )));
            }
        }
    }

    // 🔴 A binding token requires the matching capability.
    //
    // Without this check, a `{{ db.password }}` in an app that declares no database
    // would go out to Swarm with the TOKEN TEXT as its value. The app would then
    // complain about an incorrect password, and the investigation would start at the
    // password - never at the manifest.
    for t in binding::tokens_used(&m.spec.env) {
        let Some(needed) = t.requires() else { continue };

        let declared = m.spec.requires.iter().any(|c| c.id() == needed);
        if !declared {
            return Err(Error::Validation(format!(
                "{}: \"{}\" is used in env but the app declares no \"{needed}\" \
                 capability. The variable would go out with the token text as its value",
                m.metadata.name,
                t.placeholder()
            )));
        }
    }

    // A companion becomes a DNS name on the Swarm network.
    //
    // ⚠️ An uppercase letter or a dot produces a service Swarm creates without
    // complaint and the app cannot resolve: the failure shows on the first request, as
    // a "connection refused" that says nothing about the name.
    let mut seen: Vec<&str> = Vec::new();
    for c in &m.spec.companions {
        if c.name.is_empty()
            || !c
                .name
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        {
            return Err(Error::Validation(format!(
                "{}: companion \"{}\" - the name becomes a DNS entry and accepts \
                 only lowercase letters, digits and hyphens",
                m.metadata.name, c.name
            )));
        }

        // Two companions sharing a name would produce two services with the same
        // name: the second would overwrite the first, silently.
        if seen.contains(&c.name.as_str()) {
            return Err(Error::Validation(format!(
                "{}: companion \"{}\" declared twice - the second would overwrite \
                 the first without a word",
                m.metadata.name, c.name
            )));
        }
        seen.push(&c.name);
    }

    // §10.2 — une base sur NFS finit par se corrompre : le verrouillage de fichiers
    // n'y est pas fiable.
    for c in &m.spec.requires {
        if let Capability::Storage {
            tier, sqlite, name, ..
        } = c
        {
            if *sqlite && *tier == StorageTier::Nfs {
                return Err(Error::Validation(format!(
                    "volume \"{name}\": a SQLite database must never sit on NFS"
                )));
            }
        }
    }

    // `latest` follows a mutable tag: a change cannot be detected reliably and there
    // is nothing to roll back to. It is an accident waiting to happen.
    if m.spec.update.channel == UpdateChannel::Latest {
        return Err(Error::Validation(format!(
            "{} : le canal « latest » est interdit — utilise patch, minor ou pin",
            m.metadata.name
        )));
    }

    Ok(())
}

/// Invariants that hold **at deploy time only**, not in the catalog.
///
/// A catalog manifest declares an intent (`tag` + `channel`); the digest is resolved
/// against the registry at install time and then frozen into the state. Requiring a
/// digest in the catalog would mean updating it on every upstream release - that is
/// the watcher's job, not the manifest author's.
pub fn validate_pinned(m: &Manifest) -> Result<()> {
    if !m.spec.image.is_pinned() {
        return Err(Error::Validation(format!(
            "{}: deployment refused without a resolved digest",
            m.metadata.name
        )));
    }
    Ok(())
}

/// The manifest's JSON Schema, for editor autocompletion.
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
        assert!(err.to_string().contains("only through the proxy"));
    }

    #[test]
    fn rejects_sqlite_on_nfs() {
        let y = format!(
            "{BASE}  requires:\n    - kind: storage\n      name: data\n      \
             path: /data\n      tier: nfs\n      sqlite: true\n"
        );
        assert!(validate(&manifest(&y))
            .unwrap_err()
            .to_string()
            .contains("NFS"));
    }

    #[test]
    fn rejects_a_binding_token_without_its_capability() {
        // 🔴 Without this refusal the variable would go out to Swarm with
        // "{{ db.password }}" as its value. The app would say "incorrect password", and
        // you would look at the password for a long time.
        let y = format!("{BASE}  env:\n    DB_PASSWORD: \"{{{{ db.password }}}}\"\n");
        let e = validate(&manifest(&y)).unwrap_err().to_string();
        assert!(e.contains("db.password"), "{e}");
        assert!(
            e.contains("database"),
            "the error must name the missing capability: {e}"
        );
    }

    #[test]
    fn accepts_a_binding_token_when_the_capability_is_declared() {
        let y = format!(
            "{BASE}  requires:\n    - kind: database\n      engine: postgres\n  \
             env:\n    DB_PASSWORD: \"{{{{ db.password }}}}\"\n"
        );
        validate(&manifest(&y)).expect("the capability is declared");
    }

    #[test]
    fn the_domain_token_needs_no_capability() {
        // The domain comes from the install parameters: requiring it as a capability
        // would be a false blocker on every app.
        let y = format!("{BASE}  env:\n    URL: \"https://{{{{ domain }}}}\"\n");
        validate(&manifest(&y)).expect("le domaine est toujours disponible");
    }

    #[test]
    fn rejects_latest_channel() {
        let y = format!("{BASE}  update: {{ channel: latest }}\n");
        assert!(validate(&manifest(&y))
            .unwrap_err()
            .to_string()
            .contains("latest"));
    }

    #[test]
    fn catalog_manifest_may_omit_the_digest() {
        // The digest is resolved at install time, not written by hand.
        let y = BASE.replace(", digest: \"sha256:abc\"", "");
        assert!(validate(&manifest(&y)).is_ok());
        assert!(validate_pinned(&manifest(&y)).is_err());
    }

    #[test]
    fn deploy_requires_a_resolved_digest() {
        assert!(validate_pinned(&manifest(BASE)).is_ok());
    }
}
