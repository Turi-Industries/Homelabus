//! Génération et rechargement de la configuration d'entrée (§6 du plan).
//!
//! HomelabUS génère **intégralement** les Caddyfile depuis les manifests, puis les
//! recharge par l'API d'administration de Caddy — sans coupure, sans redémarrage.

pub mod admin;
pub mod caddyfile;

#[cfg(test)]
mod tests;

pub use admin::CaddyAdmin;
pub use caddyfile::{render_backend, render_frontend, Config, Route};

use hlb_types::{ExposePolicy, Manifest};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Caddy injoignable sur {url} : {source}")]
    Unreachable {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("Caddy a refusé la configuration ({status}) : {body}")]
    Rejected { status: u16, body: String },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Extrait les routes d'un manifest, en résolvant le gabarit de domaine.
///
/// Le passage par Anubis et les chemins OIDC à exclure sont déduits du manifest :
/// rien n'est à redéclarer côté ingress.
///
/// `guides_cleared` dit si les actions manuelles bloquantes de l'app ont été traitées.
/// C'est ce qui donne son sens à `expose: after-guide` (§4.6bis) : la route reste
/// interne tant que le compte administrateur n'est pas créé et les inscriptions
/// fermées, puis s'ouvre.
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

    m.spec
        .ingress
        .iter()
        .map(|ing| {
            let host = match domain {
                Some(d) => ing
                    .host
                    .replace("{{ domain }}", d)
                    .replace("{{domain}}", d),
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
            }
        })
        .collect()
}
