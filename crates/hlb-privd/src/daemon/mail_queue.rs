//! Stalwart's queue, read and kept for the inbox.

use hlb_api::mail_queue::Waiting;
use hlb_state::State;

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
