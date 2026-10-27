//! Mail that does not leave: Stalwart's queue, read by the controller and said in the
//! inbox while a recipient has waited over an hour — not by a bounce three days later.
//!
//! The inbox reads the last reading kept: a reading that fails leaves the one before,
//! so a message late then is still said rather than forgotten.

use hlb_api::issues::{Cause, Finding};
use hlb_api::mail_queue::Waiting;
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

/// What one pass found.
#[derive(Debug, Default)]
pub struct Pass {
    /// `(domain, line)` for each domain with a recipient that went late since the last
    /// reading — notified once, not at every pass while it waits.
    pub newly_late: Vec<(String, String)>,
    /// Stalwart answered only part of its queue.
    pub cut: bool,
}

/// Reads the queue and records the reading; `Err` when Stalwart could not be read,
/// the last reading then kept.
pub async fn read_and_record(
    state: &State,
    mail: &hlb_mail::Stalwart,
    now: i64,
) -> Result<Pass, String> {
    let before = state.mail_queue().await.map_err(|e| e.to_string())?;
    let (waiting, cut) = hlb_engine::mail_queue::read(mail, now)
        .await
        .map_err(|e| e.to_string())?;
    state
        .record_mail_queue(&waiting)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Pass {
        newly_late: newly_late(&before, &waiting, now),
        cut,
    })
}

/// The domains with a recipient late now and not at the reading before, each with how
/// many wait and the oldest one's last error.
fn newly_late(before: &[Waiting], now_reading: &[Waiting], now: i64) -> Vec<(String, String)> {
    let was_late = |w: &Waiting| {
        before.iter().any(|b| {
            b.message_id == w.message_id && b.recipient == w.recipient && b.late(b.read_at)
        })
    };
    let mut domains: Vec<&str> = now_reading
        .iter()
        .filter(|w| w.late(now) && !was_late(w))
        .map(Waiting::domain)
        .collect();
    domains.sort_unstable();
    domains.dedup();
    domains
        .into_iter()
        .map(|d| {
            let late: Vec<&Waiting> = now_reading
                .iter()
                .filter(|w| w.domain() == d && w.late(now))
                .collect();
            let oldest = late.iter().min_by_key(|w| w.since).copied();
            let hours = oldest.map_or(0, |w| (now - w.since) / 3_600);
            let error = oldest
                .and_then(|w| w.error.as_deref())
                .unwrap_or("never tried");
            let count = match late.len() {
                1 => "a message".to_string(),
                n => format!("{n} messages"),
            };
            (
                d.to_string(),
                format!("{d}: {count} waiting for {hours} h — {error}"),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn a_domain_is_notified_once_when_it_goes_late_not_at_every_pass() {
        let since = 0;
        let first = [waiting("a", "bob@example.net", since, 1_800)];
        let at = LATE_AFTER_S + 900;
        let second = [waiting("a", "bob@example.net", since, at)];
        assert_eq!(
            newly_late(&first, &second, at),
            [(
                "example.net".to_string(),
                "example.net: a message waiting for 1 h — relay.test: I/O error: \
                 Connection refused (os error 111)"
                    .to_string()
            )]
        );
        let third = [
            waiting("a", "bob@example.net", since, at + 900),
            waiting("b", "carol@example.org", since + 1, at + 900),
        ];
        assert_eq!(
            newly_late(&second, &third, at + 900)
                .into_iter()
                .map(|(d, _)| d)
                .collect::<Vec<_>>(),
            ["example.org"],
            "example.net was said already; example.org goes late now"
        );
    }
}
