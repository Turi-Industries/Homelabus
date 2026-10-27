//! Mail that does not leave: what Stalwart's queue still holds, as last read.
//!
//! 🔴 A message Stalwart cannot hand over is retried for three days (0.16.26's
//! default), a delay notice to its sender after one, a bounce at the end — and until
//! then the sender believes it sent. Most residential lines close port 25: every
//! message to another domain waits so. A recipient still waiting after
//! [`LATE_AFTER_S`] is in the inbox with its domain, and `hlb mail queue` says what the
//! last attempt was told.

/// Past an hour Stalwart has retried six times or so: a greylisting server has let it
/// in long before, and what is left needs a person.
pub const LATE_AFTER_S: i64 = 3_600;

/// One recipient of a queued message, not delivered yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiting {
    /// Stalwart's id of the message.
    pub message_id: String,
    pub recipient: String,
    /// When Stalwart took the message, seconds since the epoch.
    pub since: i64,
    /// Attempts made so far.
    pub attempts: u64,
    pub next_retry: i64,
    /// When Stalwart gives up and bounces it; `None` for a limit counted in attempts.
    pub expires_at: Option<i64>,
    /// What the last attempt was told, by whom; `None` while it was never tried.
    pub error: Option<String>,
    /// When the queue was read.
    pub read_at: i64,
}

impl Waiting {
    /// The recipient's domain, what the inbox names.
    pub fn domain(&self) -> &str {
        self.recipient
            .rsplit_once('@')
            .map_or(self.recipient.as_str(), |(_, d)| d)
    }

    /// Waiting longer than an hour at `now`.
    pub fn late(&self, now: i64) -> bool {
        now - self.since > LATE_AFTER_S
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waiting(recipient: &str, since: i64) -> Waiting {
        Waiting {
            message_id: "m".into(),
            recipient: recipient.into(),
            since,
            attempts: 1,
            next_retry: since + 120,
            expires_at: None,
            error: None,
            read_at: since,
        }
    }

    #[test]
    fn a_recipient_is_late_past_an_hour_and_named_by_its_domain() {
        let w = waiting("bob@Example.net", 1_000);
        assert_eq!(w.domain(), "Example.net");
        assert!(!w.late(1_000 + LATE_AFTER_S), "an hour exactly is not late");
        assert!(w.late(1_000 + LATE_AFTER_S + 1));
        assert_eq!(waiting("postmaster", 0).domain(), "postmaster");
    }
}
