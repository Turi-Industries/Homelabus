//! The mail records: read every night from a public resolver, said in the inbox.
//!
//! A record never read, or not lately, is `MailRecordUnknown` HERE — a missing row is
//! not a published record.

use hlb_api::assertions::STALE_AFTER_S;
use hlb_api::issues::{Cause, Finding};
use hlb_api::mail_dns::RecordState;
use hlb_state::State;

/// What the inbox says: records the internet does not hold as Stalwart needs them, and
/// records not looked at. Nothing where Stalwart is not installed or not exposed —
/// there, no record of it can be in any DNS.
pub async fn findings(state: &State, now: i64) -> Vec<Finding> {
    let Ok(Some(_)) = state.app_domain(hlb_engine::submission::host()).await else {
        return Vec::new();
    };
    // Each list one subject: the line names who checks nothing. A look, not an
    // emergency — mail flows, the filter is only blinder.
    let mut out: Vec<Finding> = state
        .refused_blocklists()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|tag| {
            (
                Cause::MailBlocklistsRefused,
                hlb_api::Attention::Notice,
                Some(tag),
            )
        })
        .collect();
    let read = state.mail_records().await.unwrap_or_default();
    if read.is_empty() {
        if let Ok(Some(exposure)) = state.exposure().await {
            out.push((
                Cause::MailRecordUnknown,
                hlb_api::Attention::Notice,
                Some(exposure.domain),
            ));
        }
        return out;
    }
    out.extend(read.iter().filter_map(|r| {
        let cause = if now - r.checked_at > STALE_AFTER_S {
            Cause::MailRecordUnknown
        } else {
            match r.state {
                RecordState::Published => return None,
                RecordState::Missing | RecordState::Differs => Cause::MailRecordWrong,
                RecordState::Unreadable => Cause::MailRecordUnknown,
            }
        };
        let attention = match cause {
            Cause::MailRecordWrong => r.attention(),
            _ => hlb_api::Attention::Notice,
        };
        Some((cause, attention, Some(r.name.clone())))
    }));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_api::mail_dns::MailRecord;
    use hlb_api::mail_dns::Purpose;
    use hlb_api::Attention;

    async fn exposed_stalwart() -> State {
        let s = State::in_memory().await.expect("state");
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            r#"
apiVersion: hlb/v1
kind: PlatformService
metadata: { name: stalwart }
spec:
  image: { repo: stalwartlabs/stalwart, tag: "v0.16" }
"#,
        )
        .expect("manifest");
        s.upsert_app("stalwart", &m, Some("mail.example.org"))
            .await
            .expect("app");
        s.set_exposure(&hlb_state::Exposure {
            domain: "example.org".into(),
            certificates: hlb_state::Certificates::Internal,
            acme_email: None,
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

    fn record(name: &str, state: RecordState, at: i64) -> MailRecord {
        MailRecord {
            domain: "example.org".into(),
            name: name.into(),
            purpose: Purpose::Dkim,
            expected: String::new(),
            state,
            observed: "nothing".into(),
            checked_at: at,
        }
    }

    #[tokio::test]
    async fn records_never_read_are_unknown_and_one_missing_is_critical() {
        let s = State::in_memory().await.expect("state");
        assert!(findings(&s, 1_000).await.is_empty(), "no Stalwart, no line");

        let s = exposed_stalwart().await;
        assert_eq!(
            findings(&s, 1_000).await,
            [(
                Cause::MailRecordUnknown,
                Attention::Notice,
                Some("example.org".into())
            )]
        );
        s.record_mail_records(&[
            record("a._domainkey.example.org", RecordState::Missing, 1_000),
            record("b._domainkey.example.org", RecordState::Published, 1_000),
            record("_dmarc.example.org", RecordState::Unreadable, 1_000),
        ])
        .await
        .expect("record");
        assert_eq!(
            findings(&s, 1_000).await,
            [
                (
                    Cause::MailRecordUnknown,
                    Attention::Notice,
                    Some("_dmarc.example.org".into())
                ),
                (
                    Cause::MailRecordWrong,
                    Attention::Critical,
                    Some("a._domainkey.example.org".into())
                ),
            ]
        );
    }

    #[tokio::test]
    async fn each_blocklist_refusing_the_resolver_is_a_notice() {
        let s = exposed_stalwart().await;
        s.record_mail_records(&[record(
            "a._domainkey.example.org",
            RecordState::Published,
            1_000,
        )])
        .await
        .expect("record");
        s.record_refused_blocklists(&["DBL_BLOCKED_OPENRESOLVER".into(), "URIBL_BLOCKED".into()])
            .await
            .expect("record");
        assert_eq!(
            findings(&s, 1_000).await,
            [
                (
                    Cause::MailBlocklistsRefused,
                    Attention::Notice,
                    Some("DBL_BLOCKED_OPENRESOLVER".into())
                ),
                (
                    Cause::MailBlocklistsRefused,
                    Attention::Notice,
                    Some("URIBL_BLOCKED".into())
                ),
            ]
        );
        let s = State::in_memory().await.expect("state");
        s.record_refused_blocklists(&["URIBL_BLOCKED".into()])
            .await
            .expect("record");
        assert!(
            findings(&s, 1_000).await.is_empty(),
            "Stalwart gone, its lists with it"
        );
    }

    #[tokio::test]
    async fn a_published_record_read_before_the_pass_stopped_is_unknown() {
        let s = exposed_stalwart().await;
        s.record_mail_records(&[record(
            "a._domainkey.example.org",
            RecordState::Published,
            1_000,
        )])
        .await
        .expect("record");
        assert!(findings(&s, 1_000).await.is_empty());
        assert_eq!(
            findings(&s, 1_000 + STALE_AFTER_S + 1).await,
            [(
                Cause::MailRecordUnknown,
                Attention::Notice,
                Some("a._domainkey.example.org".into())
            )]
        );
    }
}
