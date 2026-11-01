//! The house's domain: read every night by the daemon, said in the inbox.
//!
//! What moved, what the CAA refuses and what the logs hold are judged here from what
//! the night recorded, by `hlb_api::domain`'s rules — the ones `hlb domain watch`
//! prints with. A domain never read, or not lately, is `DomainUnknown`: a reading
//! that is missing is not a domain that did not move.

use hlb_api::domain::{CtWatch, DomainDnsRead, DomainPublic, DomainView, Verdict};
use hlb_api::issues::{Cause, Finding};
use hlb_api::Attention;
use hlb_state::{Certificates, State};

/// What the screen shows. A state that cannot be read is an error, never "no
/// exposure"; only the logs' record, kept apart, is said unread on its own.
pub async fn view(state: &State, now: i64) -> Result<DomainView, hlb_state::Error> {
    let Some(exposure) = state.exposure().await? else {
        return Ok(DomainView::NoExposure);
    };
    if exposure.certificates == Certificates::Internal {
        return Ok(DomainView::Internal {
            domain: exposure.domain,
        });
    }
    let reading = state.domain_reading().await?;
    let baseline = state.domain_baseline().await?;
    let transparency = state.domain_transparency().await.map_err(|e| e.to_string());
    Ok(DomainView::Public(Box::new(DomainPublic::judge(
        &exposure.domain,
        reading.as_ref(),
        baseline.as_ref(),
        transparency.as_ref().map_err(Clone::clone),
        now,
    ))))
}

/// Nothing without an exposure, or under the house's own root: no registry holds
/// those names, and no public authority certifies them.
pub async fn findings(state: &State, now: i64) -> Vec<Finding> {
    match view(state, now).await {
        Ok(DomainView::Public(p)) => findings_of(&p),
        Ok(DomainView::NoExposure | DomainView::Internal { .. }) => Vec::new(),
        // Unreadable is not unmoved.
        Err(_) => vec![(Cause::DomainUnknown, Attention::Notice, None)],
    }
}

/// The inbox's lines, from the view the screen shows: the two cannot disagree.
fn findings_of(p: &DomainPublic) -> Vec<Finding> {
    let zone = || Some(p.zone.clone());
    let mut out: Vec<Finding> = Vec::new();
    match &p.reading {
        Some(r) if !r.stale && matches!(r.dns, DomainDnsRead::Read(_)) => {}
        _ => out.push((Cause::DomainUnknown, Attention::Notice, zone())),
    }
    if let Some(r) = &p.reading {
        out.extend(
            r.accounts
                .iter()
                .filter(|a| a.verdict == Some(Verdict::Refused))
                .map(|a| {
                    (
                        Cause::CaaRefusesAccount,
                        Attention::Critical,
                        Some(a.account.who.clone()),
                    )
                }),
        );
        if p.baseline_at.is_none() {
            out.push((Cause::DomainUnwatched, Attention::Notice, zone()));
        } else if !p.drifts.is_empty() {
            out.push((Cause::DomainMoved, Attention::Critical, zone()));
        }
    }
    match &p.logs {
        CtWatch::NotStarted => out.push((Cause::DomainUnwatched, Attention::Notice, zone())),
        CtWatch::Watched { foreign } => out.extend(
            foreign
                .iter()
                .flat_map(|i| i.names.clone())
                .map(|name| (Cause::CertificateForeign, Attention::Critical, Some(name))),
        ),
        CtWatch::Unread { .. } => out.push((Cause::DomainUnknown, Attention::Notice, zone())),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_api::assertions::STALE_AFTER_S;
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

    #[test]
    fn the_demonstration_shows_a_move_a_pin_and_a_stranger_s_certificate() {
        use hlb_api::domain::{Advice, DomainView};
        let DomainView::Public(p) = crate::demo::domain(1_800_000_000) else {
            panic!("the demonstration's domain is public");
        };
        assert_eq!(p.drifts.len(), 1, "{:?}", p.drifts);
        let seen = p.reading.as_ref().expect("read");
        assert!(
            seen.advice.iter().any(|a| matches!(a, Advice::Pin { .. })),
            "{:?}",
            seen.advice
        );
        assert!(matches!(&p.logs, CtWatch::Watched { foreign } if !foreign.is_empty()));
        // What the inbox would say of it: each critical line the screen explains.
        let said: Vec<Cause> = group(findings_of(&p))
            .into_iter()
            .map(|i| i.cause)
            .collect();
        assert_eq!(said, [Cause::DomainMoved, Cause::CertificateForeign]);
    }
}
