//! The certificate people's mail clients meet on 465 and 993.
//!
//! 🔴 Stalwart 0.16.26 serves its own there — `CN=rcgen self signed cert`, naming only
//! `localhost` — and the certificate Homelabus issues is for the overlay name the apps
//! use. A phone set up on `mail.example.org` warned at every connection, or was told to
//! trust anything. Stalwart picks a certificate by the name the client asks for (SNI):
//! one for its public name beside the overlay's, each served to its own.
//!
//! | Exposure | The certificate |
//! |---|---|
//! | internal | signed under Homelabus's own root, the one the house's devices trust for the web |
//! | ACME, the domain's records published by a DNS provider | requested by Stalwart itself, DNS-01 through the same `DnsServer` |
//! | ACME otherwise | requested by Stalwart itself, HTTP-01: the challenge reaches it through Caddy's route — port 80, redirected to 443, proxied |
//!
//! Stalwart renews what it requested (at two thirds of its life) without Homelabus.

use hlb_state::{Certificates, Exposure};

/// Let's Encrypt, when the exposure names no other directory.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// How Stalwart's public name gets its certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wanted {
    /// Under Homelabus's own root: no public authority signs for an internal exposure.
    Internal,
    /// Requested by Stalwart from the exposure's own ACME directory.
    Acme {
        /// `Dns01` or `Http01`, as Stalwart names them.
        challenge: &'static str,
        directory: String,
        email: String,
    },
}

/// What the exposure asks for. `dns_published`: the mail domain's records go through
/// a `DnsServer` already ([`crate::mail_dns::publish_dkim`]) — then DNS-01, which needs
/// no port open; HTTP-01 otherwise, which needs the route the ingress already has.
pub fn wanted(exposure: &Exposure, dns_published: bool) -> Result<Wanted, String> {
    match exposure.certificates {
        Certificates::Internal => Ok(Wanted::Internal),
        Certificates::Acme => Ok(Wanted::Acme {
            challenge: if dns_published { "Dns01" } else { "Http01" },
            directory: match (&exposure.acme_ca, exposure.staging) {
                (Some(ca), _) => ca.clone(),
                (None, true) => hlb_ingress::caddyfile::STAGING_CA.to_string(),
                (None, false) => LETS_ENCRYPT.to_string(),
            },
            email: exposure
                .acme_email
                .clone()
                .ok_or("no ACME address: hlb config exposure --email <address>")?,
        }),
    }
}

/// Has Stalwart present a certificate for its public name. `Ok(what changed)` — or,
/// `apply` false, what would; nothing while Stalwart has no route or there is no
/// exposure. `Err` too when nothing changed and the certificate is still not there,
/// with what the last request was told: a request failing in silence is a phone
/// warning in silence.
pub async fn certify(
    state: &hlb_state::State,
    vault: &hlb_secrets::Vault,
    mail: &hlb_mail::Stalwart,
    apply: bool,
) -> crate::Result<Vec<String>> {
    let host = crate::submission::host();
    let (Some(name), Some(exposure)) = (state.app_domain(host).await?, state.exposure().await?)
    else {
        return Ok(Vec::new());
    };
    let domain = match mail
        .domains_tls()
        .await?
        .into_iter()
        .find(|d| d.name == exposure.domain)
    {
        Some(d) => d,
        // Not made yet — the role pass names Stalwart first, which makes it: a preview
        // reads it as a domain nothing was asked for yet, and writes nothing.
        None if !apply => hlb_mail::DomainTls {
            id: String::new(),
            name: exposure.domain.clone(),
            requested_by: None,
        },
        None => {
            mail.ensure_domain(&exposure.domain).await?;
            mail.domains_tls()
                .await?
                .into_iter()
                .find(|d| d.name == exposure.domain)
                .ok_or_else(|| {
                    crate::Error::Submission(format!("{} was not made", exposure.domain))
                })?
        }
    };
    let dns_published = mail
        .domains_dns()
        .await?
        .iter()
        .any(|d| d.id == domain.id && d.published_by.is_some());
    let wanted = wanted(&exposure, dns_published).map_err(crate::Error::Submission)?;
    let ours = state.mail_acme_provider().await?;
    let mut changed = Vec::new();

    if let Some((provider, _)) = &domain.requested_by {
        if ours.as_deref() != Some(provider.as_str()) {
            tracing::info!(
                domain = %domain.name,
                "certificates requested through an ACME account of someone's own: left alone"
            );
            return Ok(Vec::new());
        }
    }

    match wanted {
        Wanted::Internal => {
            if let Some(id) = &ours {
                changed.push(format!(
                    "{name}'s certificate no longer requested from an ACME directory"
                ));
                if apply {
                    if domain.requested_by.is_some() {
                        mail.set_manual_certificates(&domain.id).await?;
                    }
                    forget_provider(state, mail, id).await?;
                }
            }
            let now = chrono::Utc::now();
            if !crate::submission::holds(
                &mail.certificates().await?,
                &name,
                now + chrono::Duration::days(365),
            ) {
                changed.push(format!("a certificate for {name} under Homelabus's root"));
                if apply {
                    let root = crate::submission::root(state, vault, &exposure.domain).await?;
                    let leaf = hlb_agent::pki::issue_platform_server(&root, &name)
                        .await
                        .map_err(|e| {
                            crate::Error::Submission(format!("{name}'s certificate: {e}"))
                        })?;
                    let id = mail.add_certificate(&leaf.cert_pem, &leaf.key_pem).await?;
                    // The one it renews, gone once the new one is served.
                    if let Some(before) = state.mail_public_certificate().await? {
                        mail.destroy_certificate(&before).await.ok();
                    }
                    state.set_mail_public_certificate(Some(&id)).await?;
                }
            }
        }
        Wanted::Acme {
            challenge,
            directory,
            email,
        } => {
            let providers = mail.acme_providers().await?;
            let current = ours
                .as_deref()
                .and_then(|id| providers.iter().find(|p| p.id == id));
            let contact = format!("mailto:{email}");
            let fits = current.filter(|p| {
                p.challenge == challenge
                    && p.directory == directory
                    && p.contact == [contact.clone()]
            });
            let provider = match fits {
                Some(p) => Some(p.id.clone()),
                None => {
                    changed.push(format!(
                        "{name}'s certificate requested from {directory} over {}",
                        if challenge == "Dns01" {
                            "DNS-01"
                        } else {
                            "HTTP-01"
                        }
                    ));
                    if apply {
                        let mut tries = 1;
                        let id = loop {
                            match mail
                                .create_acme_provider(challenge, &directory, &email)
                                .await
                            {
                                Err(e) if tries < OPEN_TRIES && is_bad_nonce(&e.to_string()) => {
                                    tries += 1
                                }
                                other => break other,
                            }
                        }
                        .map_err(|e| {
                            let e = e.to_string();
                            crate::Error::Submission(
                                match refusal_hint(&e, exposure.acme_ca_root.is_some()) {
                                    Some(hint) => format!("{e} — {hint}"),
                                    None => e,
                                },
                            )
                        })?;
                        state.set_mail_acme_provider(Some(&id)).await?;
                        Some(id)
                    } else {
                        None
                    }
                }
            };
            let names = vec![name.clone()];
            let requested = |id: &str| {
                domain
                    .requested_by
                    .as_ref()
                    .is_some_and(|(p, n)| p == id && *n == names)
            };
            match &provider {
                Some(id) if requested(id) => {}
                Some(id) => {
                    if fits.is_some() {
                        changed.push(format!("{name}'s certificate requested for {name} alone"));
                    }
                    if apply {
                        mail.certify_through(&domain.id, id, &names).await?;
                    }
                }
                None => {}
            }
            // The account replaced, once nothing names it any more.
            if let (Some(old), Some(new), true) = (current, &provider, apply) {
                if old.id != *new {
                    forget_provider(state, mail, &old.id).await.ok();
                }
            }
            let certs = mail.certificates().await?;
            let leaf = state.mail_public_certificate().await?;
            // 🔴 Stalwart serves the certificate of a name that ends LAST: the ten-year
            // leaf of an internal exposure would hide every certificate ACME brings.
            // Taken back once one is there, so a client never meets Stalwart's own.
            if leaf
                .as_ref()
                .is_some_and(|id| !certs.iter().any(|c| c.id == *id))
                && apply
            {
                // Removed by hand: nothing left to take back.
                state.set_mail_public_certificate(None).await?;
            }
            let leaf = leaf.filter(|id| certs.iter().any(|c| c.id == *id));
            let acme_held = certs.iter().any(|c| {
                Some(&c.id) != leaf.as_ref()
                    && crate::submission::holds(std::slice::from_ref(c), &name, chrono::Utc::now())
            });
            if let (Some(leaf), true) = (&leaf, acme_held) {
                changed.push(format!(
                    "{name}'s certificate under Homelabus's root taken back"
                ));
                if apply {
                    mail.destroy_certificate(leaf).await?;
                    state.set_mail_public_certificate(None).await?;
                }
            }
            // Judged on ACME's own: the leaf kept meanwhile would say all is well while
            // every request fails.
            if changed.is_empty() && !acme_held {
                let why = mail
                    .acme_tasks(&domain.id)
                    .await?
                    .into_iter()
                    .find_map(|t| t.failure)
                    .unwrap_or_else(|| "requested, not issued yet".into());
                return Err(crate::Error::Submission(format!(
                    "no certificate for {name} yet: {why}"
                )));
            }
        }
    }
    Ok(changed)
}

/// Removes an ACME account Homelabus opened, and forgets it.
async fn forget_provider(
    state: &hlb_state::State,
    mail: &hlb_mail::Stalwart,
    id: &str,
) -> crate::Result<()> {
    match mail.destroy_acme_provider(id).await {
        Ok(()) => {}
        // Gone already — removed by hand: nothing left to forget but the id.
        Err(hlb_mail::Error::NotCreated { reason, .. }) if reason.starts_with("notFound") => {}
        Err(e) => return Err(e.into()),
    }
    if state.mail_acme_provider().await?.as_deref() == Some(id) {
        state.set_mail_acme_provider(None).await?;
    }
    Ok(())
}

/// How many times an ACME account is asked for before the pass gives up until the
/// next night.
const OPEN_TRIES: u32 = 3;

/// 🔴 The directory refused the request's nonce. RFC 8555 §6.5 has the client try
/// again — the answer carries a fresh one —, and Let's Encrypt does it now and then;
/// Stalwart 0.16.26 opens the account at creation and does not, so one stale nonce
/// failed the whole pass (Pebble refuses 5 % of them on purpose: measured).
fn is_bad_nonce(error: &str) -> bool {
    error.contains("urn:ietf:params:acme:error:badNonce")
}

/// What a person can do about a refused account. Only a directory Stalwart could not
/// verify is cured by handing it the private root — said of a stale nonce, the hint
/// sent the reader to redeploy for nothing. Stalwart does not say which: an unverified
/// directory and an unreachable one both read "error sending request" (measured); one
/// that ANSWERED a status was verified, and the root is not the matter.
fn refusal_hint(error: &str, private_root: bool) -> Option<&'static str> {
    (private_root && !error.contains("Unexpected status")).then_some(
        "Stalwart trusts the private ACME root from its next deployment: \
         hlb upgrade stalwart --apply",
    )
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stale_nonce_is_asked_again_and_only_an_unverified_directory_is_sent_to_redeploy() {
        // Both as Stalwart 0.16.26 reported them.
        let nonce = "Failed to create ACME account: HTTP error: Unexpected status 400 Bad \
                     Request: {\"type\": \"urn:ietf:params:acme:error:badNonce\", \
                     \"detail\": \"JWS has an invalid anti-replay nonce\"}";
        let unverified = "Failed to create ACME account: HTTP error: error sending request \
                          for url (https://pebble:14000/dir)";
        assert!(is_bad_nonce(nonce));
        assert!(!is_bad_nonce(unverified));
        assert_eq!(refusal_hint(nonce, true), None);
        assert!(refusal_hint(unverified, true).is_some());
        assert_eq!(refusal_hint(unverified, false), None, "a public authority");
    }

    fn exposure(certificates: Certificates) -> Exposure {
        Exposure {
            domain: "example.org".into(),
            certificates,
            acme_email: Some("admin@example.org".into()),
            dns_provider: None,
            staging: false,
            controller_host: None,
            acme_ca: None,
            acme_ca_root: None,
        }
    }

    #[test]
    fn the_exposure_decides_how_stalwart_s_public_name_is_certified() {
        assert_eq!(
            wanted(&exposure(Certificates::Internal), true),
            Ok(Wanted::Internal)
        );
        let acme = exposure(Certificates::Acme);
        assert_eq!(
            wanted(&acme, false),
            Ok(Wanted::Acme {
                challenge: "Http01",
                directory: LETS_ENCRYPT.into(),
                email: "admin@example.org".into(),
            })
        );
        let Ok(Wanted::Acme { challenge, .. }) = wanted(&acme, true) else {
            panic!("acme")
        };
        assert_eq!(
            challenge, "Dns01",
            "a domain a DnsServer publishes needs no port"
        );
        let staging = Exposure {
            staging: true,
            ..acme.clone()
        };
        assert!(matches!(
            wanted(&staging, false),
            Ok(Wanted::Acme { directory, .. }) if directory == hlb_ingress::caddyfile::STAGING_CA
        ));
        let own = Exposure {
            acme_ca: Some("https://ca.lab:9000/acme/acme/directory".into()),
            staging: true,
            ..acme.clone()
        };
        assert!(matches!(
            wanted(&own, false),
            Ok(Wanted::Acme { directory, .. }) if directory.starts_with("https://ca.lab")
        ));
        let anonymous = Exposure {
            acme_email: None,
            ..acme
        };
        assert!(wanted(&anonymous, false)
            .expect_err("no address")
            .contains("--email"));
    }
}
