//! Generating the ingress configuration.
//!
//! Homelabus generates the Caddyfile **entirely** from the manifests; `hlb-engine`
//! hands it to the `caddy` service as a file.

pub mod caddyfile;
pub mod crowdsec;
pub mod dns;

pub type Result<T> = std::result::Result<T, Error>;

/// Extracts the routes from a manifest, resolving the domain template.
///
/// Whether the portal stands in front is derived from the manifest: nothing has to be
/// restated on the ingress side.
///
/// `guides_cleared` says whether the app's blocking manual actions have been handled.
/// That is what gives `expose: after-guide` its meaning: the route stays internal
/// until the administrator account is created and sign-ups closed, then opens.
pub fn routes_from_manifest(
    m: &Manifest,
    domain: Option<&str>,
    guides_cleared: bool,
) -> Vec<Route> {
    // 🔴 `proxy-header` and `proxy-only` have NO notion of identity of their own:
    // without a portal in front, the app is simply open to everyone. `native` speaks
    // OIDC itself and needs none; `none` is a deliberate exclusion.
    let needs_portal = m.spec.requires.iter().any(|c| {
        matches!(
            c,
            hlb_types::Capability::Sso {
                mode: hlb_types::SsoMode::ProxyHeader | hlb_types::SsoMode::ProxyOnly,
                ..
            }
        )
    });

    m.spec
        .ingress
        .iter()
        .map(|ing| {
            let host = match domain {
                Some(d) => ing.host.replace("{{ domain }}", d).replace("{{domain}}", d),
                None => ing.host.clone(),
            };

            Route {
                host,
                service: m.metadata.name.clone(),
                port: ing.port,
                public: match ing.expose {
                    ExposePolicy::Public => true,
                    ExposePolicy::AfterGuide => guides_cleared,
                    ExposePolicy::Private => false,
                },
                needs_forward_auth: needs_portal,
                // Filled from the roles the app allows (`hlb_engine::ingress`): closed
                // until then.
                allowed_groups: Vec::new(),
                paths: ing
                    .paths
                    .iter()
                    .map(|p| CompanionPath {
                        prefix: p.prefix.clone(),
                        upstream: format!("{}-{}:{}", m.metadata.name, p.companion, p.port),
                        keep_prefix: p.keep_prefix,
                    })
                    .collect(),
                auth_routes: ing.auth_routes.clone(),
                open_paths: ing.open_paths.clone(),
            }
        })
        .collect()
}

pub use caddyfile::{render, CompanionPath, Config, CrowdSec, Route, Tls, Wildcard};
pub use crowdsec::Cscli;

use hlb_types::{ExposePolicy, Manifest};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("CrowdSec: {0}")]
    CrowdSec(String),
}

#[cfg(test)]
mod tests;
