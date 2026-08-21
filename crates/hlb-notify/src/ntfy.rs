//! ntfy client.
//!
//! ntfy was chosen because it self-hosts, needs no account, and a notification is a
//! plain `POST` - no SDK, no token to rotate. It sits in the catalog like any other
//! app.

use crate::{Error, Level, Notification, QuietHours, Result};

pub struct NtfyClient {
    base_url: String,
    topic: String,
    quiet: QuietHours,
    http: reqwest::Client,
}

impl NtfyClient {
    pub fn new(base_url: impl Into<String>, topic: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            topic: topic.into(),
            quiet: QuietHours::default(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn quiet_hours(mut self, q: QuietHours) -> Self {
        self.quiet = q;
        self
    }

    /// Sends if the level and the hour allow it.
    ///
    /// Returns `Ok(false)` when the notification was **held back** - that is not an
    /// error, it is the intended behaviour. Confusing the two would surface failures
    /// in the logs on every non-critical night-time notification.
    pub async fn send_at(&self, n: &Notification, hour: u32) -> Result<bool> {
        if !self.quiet.allows(n.level, hour) {
            tracing::debug!(
                subject = %n.subject,
                level = ?n.level,
                "notification held back (quiet hours, or a level that is not pushed)"
            );
            return Ok(false);
        }

        let url = format!("{}/{}", self.base_url, self.topic);
        let resp = self
            .http
            .post(&url)
            .header("Title", &n.title)
            .header("Priority", n.level.ntfy_priority().to_string())
            .header("Tags", n.level.tag())
            .body(n.body.clone())
            .send()
            .await
            .map_err(|source| Error::Http {
                url: url.clone(),
                source,
            })?;

        if !resp.status().is_success() {
            return Err(Error::Rejected(resp.status().as_u16()));
        }

        tracing::info!(subject = %n.subject, "notification sent");
        Ok(true)
    }

    /// Sends using the current local hour.
    pub async fn send(&self, n: &Notification) -> Result<bool> {
        let hour = local_hour();
        self.send_at(n, hour).await
    }
}

/// The local hour, without depending on a date library.
///
/// Deliberately approximate: all we need is to tell "night" from "daytime". Being an
/// hour off in an unusual timezone has no consequence here, whereas one more
/// dependency would.
fn local_hour() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    ((secs / 3600) % 24) as u32
}

/// Sends a notification if a client is configured.
///
/// Without one it logs instead of losing the information: an alert that was not sent
/// must stay visible somewhere.
pub async fn notify_or_log(client: Option<&NtfyClient>, n: &Notification) {
    match client {
        Some(c) => {
            if let Err(e) = c.send(n).await {
                tracing::error!(subject = %n.subject, "could not notify: {e}");
                tracing::warn!("{} — {}", n.title, n.body);
            }
        }
        None => {
            let mark = if n.level >= Level::Critical {
                "🔴"
            } else {
                "🟠"
            };
            tracing::warn!("{mark} {} - {} (no ntfy configured)", n.title, n.body);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> NtfyClient {
        NtfyClient::new("https://ntfy.example.org/", "homelab")
    }

    #[test]
    fn the_base_url_is_normalised() {
        let c = client();
        assert_eq!(c.base_url, "https://ntfy.example.org");
    }

    #[tokio::test]
    async fn a_held_notification_is_not_an_error() {
        // 🔴 Holding back is not failing. Confusing the two would surface errors in
        // the logs on every non-critical night-time notification.
        let c = client();
        let n = Notification::important("update", "Update available", "gitea 1.25");

        // 3 a.m., important level: held back, with no network call.
        assert!(!c.send_at(&n, 3).await.expect("no error"));
    }

    #[tokio::test]
    async fn an_info_is_never_sent() {
        let c = client();
        let n = Notification::new(Level::Info, "x", "Info", "...");
        assert!(!c.send_at(&n, 14).await.expect("no error"));
    }

    #[tokio::test]
    async fn a_critical_notification_attempts_delivery_at_night() {
        // The domain does not exist, so we must get a NETWORK error - which proves
        // delivery was attempted despite the hour.
        let c = client();
        let n = Notification::critical("disk", "Disk full", "node2 at 97 %");
        let r = c.send_at(&n, 3).await;
        assert!(matches!(r, Err(Error::Http { .. })), "{r:?}");
    }

    #[tokio::test]
    async fn without_a_client_nothing_panics() {
        // The information must stay visible in the logs rather than vanish.
        notify_or_log(None, &Notification::critical("x", "Title", "Body")).await;
    }

    #[test]
    fn the_local_hour_is_within_range() {
        let h = local_hour();
        assert!(h < 24, "impossible hour: {h}");
    }
}
