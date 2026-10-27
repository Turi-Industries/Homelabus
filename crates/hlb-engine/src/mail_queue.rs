//! Stalwart's queue, read for `hlb mail queue` and the controller's pass alike.

use hlb_api::mail_queue::Waiting;

/// Every recipient still waiting, and whether Stalwart cut the list.
///
/// A date Stalwart wrote that does not parse is `now`: the recipient stays listed,
/// young, rather than vanishing or reading fifty years late.
pub async fn read(mail: &hlb_mail::Stalwart, now: i64) -> crate::Result<(Vec<Waiting>, bool)> {
    let (queued, cut) = mail.queue().await?;
    Ok((queued.into_iter().map(|q| waiting(q, now)).collect(), cut))
}

fn waiting(q: hlb_mail::Waiting, now: i64) -> Waiting {
    let at = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .map(|d| d.timestamp())
            .ok()
    };
    Waiting {
        since: at(&q.created_at).unwrap_or(now),
        next_retry: at(&q.next_retry).unwrap_or(now),
        expires_at: q.expires_at.as_deref().and_then(at),
        message_id: q.message_id,
        recipient: q.recipient,
        attempts: q.attempts,
        error: q.error,
        read_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stalwart_s_dates_become_epochs_and_an_unreadable_one_reads_as_now() {
        let w = waiting(
            hlb_mail::Waiting {
                message_id: "m".into(),
                recipient: "bob@example.net".into(),
                queue: "remote".into(),
                created_at: "2026-10-20T07:15:09Z".into(),
                attempts: 1,
                next_retry: "soon".into(),
                expires_at: Some("2026-10-23T07:15:09Z".into()),
                error: None,
            },
            1_800_000_000,
        );
        assert_eq!(w.since, 1_792_480_509);
        assert_eq!(w.expires_at, Some(1_792_480_509 + 3 * 86_400));
        assert_eq!(w.next_retry, 1_800_000_000);
        assert_eq!(w.read_at, 1_800_000_000);
    }
}
