//! Mail that does not leave: Stalwart's queue, read by the controller and said in the
//! inbox while a recipient has waited over an hour — not by a bounce three days later.
//!
//! The inbox reads the last reading kept: a reading that fails leaves the one before,
//! so a message late then is still said rather than forgotten.

use hlb_api::issues::{Cause, Finding};
use hlb_state::State;

/// One line per recipient's domain with a message late. Nothing where Stalwart is not
/// installed: a reading left from before it was removed names no queue.
pub async fn findings(state: &State, now: i64) -> Vec<Finding> {
    if state
        .app_manifest(hlb_engine::submission::host())
        .await
        .is_err()
    {
        return Vec::new();
    }
    state
        .mail_queue()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|w| w.late(now))
        .map(|w| {
            (
                Cause::MailWaiting,
                hlb_api::Attention::Critical,
                Some(w.domain().to_string()),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_api::mail_queue::Waiting;
    use hlb_api::mail_queue::LATE_AFTER_S;
    use hlb_api::Attention;

    fn waiting(id: &str, recipient: &str, since: i64, read_at: i64) -> Waiting {
        Waiting {
            message_id: id.into(),
            recipient: recipient.into(),
            since,
            attempts: 6,
            next_retry: read_at + 600,
            expires_at: Some(since + 3 * 86_400),
            error: Some("relay.test: I/O error: Connection refused (os error 111)".into()),
            read_at,
        }
    }

    #[tokio::test]
    async fn a_recipient_waiting_over_an_hour_is_a_critical_line_named_by_its_domain() {
        let s = State::in_memory().await.expect("state");
        let late = 10_000 - LATE_AFTER_S - 1;
        s.record_mail_queue(&[
            waiting("a", "bob@example.net", late, 10_000),
            waiting("b", "carol@example.net", late, 10_000),
            waiting("c", "dan@example.com", 9_000, 10_000),
        ])
        .await
        .expect("record");
        assert!(
            findings(&s, 10_000).await.is_empty(),
            "no Stalwart installed, no queue to speak of"
        );

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
        s.upsert_app("stalwart", &m, None).await.expect("app");
        let found = findings(&s, 10_000).await;
        assert_eq!(
            found,
            [
                (
                    Cause::MailWaiting,
                    Attention::Critical,
                    Some("example.net".into())
                ),
                (
                    Cause::MailWaiting,
                    Attention::Critical,
                    Some("example.net".into())
                ),
            ],
            "the one waiting a quarter of an hour is not said yet"
        );
        let issues = hlb_api::issues::group(found);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].subjects, ["example.net"], "one line, one domain");
    }
}
