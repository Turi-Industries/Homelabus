//! The house's domain: read every night by the daemon, said in the inbox.
//!
//! What moved, what the CAA refuses and what the logs hold are judged here from what
//! the night recorded, by `hlb_api::domain`'s rules — the ones `hlb domain watch`
//! prints with. A domain never read, or not lately, is `DomainUnknown`: a reading
//! that is missing is not a domain that did not move.

use hlb_api::assertions::STALE_AFTER_S;
use hlb_api::issues::{Cause, Finding};
use hlb_api::Attention;
use hlb_state::{Certificates, State};

/// Nothing without an exposure, or under the house's own root: no registry holds
/// those names, and no public authority certifies them.
pub async fn findings(state: &State, now: i64) -> Vec<Finding> {
    let Ok(Some(exposure)) = state.exposure().await else {
        return Vec::new();
    };
    if exposure.certificates == Certificates::Internal {
        return Vec::new();
    }
    let mut out: Vec<Finding> = Vec::new();
    let reading = state.domain_reading().await.ok().flatten();
    let zone = reading
        .as_ref()
        .map_or(exposure.domain.clone(), |r| r.zone.clone());
    match &reading {
        Some(r) if now - r.read_at <= STALE_AFTER_S && r.dns.is_ok() => {}
        _ => out.push((Cause::DomainUnknown, Attention::Notice, Some(zone.clone()))),
    }
    if let Some(r) = &reading {
        out.extend(hlb_api::domain::refused(r).into_iter().map(|a| {
            (
                Cause::CaaRefusesAccount,
                Attention::Critical,
                Some(a.who.clone()),
            )
        }));
        let baseline = state
            .domain_baseline()
            .await
            .ok()
            .flatten()
            .filter(|b| b.zone == r.zone);
        match baseline {
            None => out.push((
                Cause::DomainUnwatched,
                Attention::Notice,
                Some(zone.clone()),
            )),
            Some(b) if !hlb_api::domain::drifts(&b, r).is_empty() => {
                out.push((Cause::DomainMoved, Attention::Critical, Some(zone.clone())));
            }
            Some(_) => {}
        }
    }
    match state.domain_transparency().await {
        Ok(t) if t.after.is_none() => {
            out.push((Cause::DomainUnwatched, Attention::Notice, Some(zone)));
        }
        Ok(t) => out.extend(
            t.foreign
                .into_iter()
                .flat_map(|i| i.names)
                .map(|name| (Cause::CertificateForeign, Attention::Critical, Some(name))),
        ),
        Err(_) => out.push((Cause::DomainUnknown, Attention::Notice, Some(zone))),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_api::domain::{DnsSide, Issuance, Reading, Registry, Transparency};
    use hlb_api::issues::group;

    async fn exposed(certificates: Certificates) -> State {
        let s = State::in_memory().await.expect("state");
        s.set_exposure(&hlb_state::Exposure {
            domain: "home.org".into(),
            certificates,
            acme_email: Some("me@home.org".into()),
            dns_provider: None,
            staging: false,
            controller_host: None,
            acme_ca: None,
            acme_ca_root: None,
        })
        .await
        .expect("exposure");
        s
    }

    fn reading(ns: &str, at: i64) -> Reading {
        Reading {
            zone: "home.org".into(),
            read_at: at,
            dns: Ok(DnsSide::new(vec![ns.into()], vec![], false, vec![])),
            registry: Registry::NotRead {
                why: "no RDAP".into(),
            },
            caa_governing: None,
            accounts: vec![],
        }
    }

    fn causes(f: Vec<Finding>) -> Vec<(Cause, Attention, Vec<String>)> {
        group(f)
            .into_iter()
            .map(|i| (i.cause, i.attention, i.subjects))
            .collect()
    }

    #[tokio::test]
    async fn a_domain_never_read_is_unknown_and_unwatched_and_internal_names_nothing() {
        let s = exposed(Certificates::Internal).await;
        assert!(findings(&s, 1_000).await.is_empty());
        let s = exposed(Certificates::Acme).await;
        assert_eq!(
            causes(findings(&s, 1_000).await),
            [
                (
                    Cause::DomainUnknown,
                    Attention::Notice,
                    vec!["home.org".into()]
                ),
                (
                    Cause::DomainUnwatched,
                    Attention::Notice,
                    vec!["home.org".into()]
                ),
            ]
        );
    }

    #[tokio::test]
    async fn a_move_since_the_baseline_is_critical_and_a_stale_reading_unknown() {
        let s = exposed(Certificates::Acme).await;
        s.set_domain_baseline(&reading("ns1.desec.io", 1_000))
            .await
            .expect("baseline");
        s.set_domain_transparency(&Transparency {
            after: Some("1".into()),
            foreign: vec![],
        })
        .await
        .expect("watch");
        s.record_domain_reading(&reading("ns1.desec.io", 1_000))
            .await
            .expect("reading");
        assert!(findings(&s, 1_000).await.is_empty(), "as accepted");
        s.record_domain_reading(&reading("ns1.thief.example", 1_000))
            .await
            .expect("reading");
        assert_eq!(
            causes(findings(&s, 1_000).await),
            [(
                Cause::DomainMoved,
                Attention::Critical,
                vec!["home.org".into()]
            )]
        );
        // Read days ago, what it said still stands, and the silence since is said.
        let later = 1_000 + STALE_AFTER_S + 1;
        assert_eq!(
            causes(findings(&s, later).await)
                .into_iter()
                .map(|c| c.0)
                .collect::<Vec<_>>(),
            [Cause::DomainMoved, Cause::DomainUnknown]
        );
    }

    #[tokio::test]
    async fn a_foreign_certificate_is_critical_by_its_names_until_accepted() {
        let s = exposed(Certificates::Acme).await;
        s.set_domain_baseline(&reading("ns1.desec.io", 1_000))
            .await
            .expect("baseline");
        s.record_domain_reading(&reading("ns1.desec.io", 1_000))
            .await
            .expect("reading");
        let foreign = Issuance {
            id: "9".into(),
            names: vec!["*.home.org".into(), "home.org".into()],
            issuer: "Some CA".into(),
            not_before: "2026-10-31T00:00:00Z".into(),
            key: "aa".into(),
        };
        s.set_domain_transparency(&Transparency {
            after: Some("9".into()),
            foreign: vec![foreign],
        })
        .await
        .expect("watch");
        assert_eq!(
            causes(findings(&s, 1_000).await),
            [(
                Cause::CertificateForeign,
                Attention::Critical,
                vec!["*.home.org".into(), "home.org".into()]
            )]
        );
    }
}
