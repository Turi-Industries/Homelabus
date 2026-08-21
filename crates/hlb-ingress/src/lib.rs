//! Generating and reloading the ingress configuration.
//!
//! Homelabus generates the Caddyfiles **entirely** from the manifests, then reloads
//! them through Caddy's admin API - no downtime, no restart.

pub mod admin;
pub mod caddyfile;
pub mod crowdsec;

#[cfg(test)]
mod tests;

pub use admin::CaddyAdmin;
pub use caddyfile::{render_backend, render_frontend, Config, CrowdSec, Route};
pub use crowdsec::Cscli;

use hlb_types::{ExposePolicy, Manifest};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("CrowdSec : {0}")]
    CrowdSec(String),

    #[error("Caddy injoignable sur {url} : {source}")]
    Unreachable {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("Caddy refused the configuration ({status}): {body}")]
    Rejected { status: u16, body: String },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Extracts the routes from a manifest, resolving the domain template.
///
/// Whether traffic goes through Anubis, and which OIDC paths to exclude, are derived
/// from the manifest: nothing has to be restated on the ingress side.
///
/// `guides_cleared` says whether the app's blocking manual actions have been handled.
/// That is what gives `expose: after-guide` its meaning: the route stays internal
/// until the administrator account is created and sign-ups closed, then opens.
pub fn routes_from_manifest(
    m: &Manifest,
    domain: Option<&str>,
    guides_cleared: bool,
) -> Vec<Route> {
    let sso_paths: Vec<String> = m
        .spec
        .requires
        .iter()
        .filter_map(|c| match c {
            hlb_types::Capability::Sso { redirect_paths, .. } => Some(redirect_paths.clone()),
            _ => None,
        })
        .flatten()
        .collect();

    // 🔴 `proxy-header` and `proxy-only` have NO notion of identity of their own:
    // without a portal in front, the app is simply open to everyone. `native` speaks
    // OIDC itself and needs none; `none` is a deliberate exclusion.
    let besoin_portail = m.spec.requires.iter().any(|c| {
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
                through_anubis: ing.chain.iter().any(|c| c == "anubis"),
                public: match ing.expose {
                    ExposePolicy::Public => true,
                    ExposePolicy::AfterGuide => guides_cleared,
                    ExposePolicy::Private => false,
                },
                sso_paths: sso_paths.clone(),
                needs_forward_auth: besoin_portail,
            }
        })
        .collect()
}
