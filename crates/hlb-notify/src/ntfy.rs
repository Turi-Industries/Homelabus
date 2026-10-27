//! ntfy client.
//!
//! ntfy was chosen because it self-hosts and a notification is a plain `POST` - no
//! SDK. It sits in the catalog like any other app, closed to anyone without one of
//! its declared accounts: Homelabus publishes as `homelabus`.

use crate::{Delivery, Error, Notification, QuietHours, Result};

pub struct NtfyClient {
    base_url: String,
    topic: String,
    quiet: QuietHours,
    http: reqwest::Client,
    /// `(user, password)`. The catalog's ntfy refuses anyone without an account.
    account: Option<(String, String)>,
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
            account: None,
        }
    }

    pub fn signed_in_as(mut self, user: impl Into<String>, password: impl Into<String>) -> Self {
        self.account = Some((user.into(), password.into()));
        self
    }

    pub fn quiet_hours(mut self, q: QuietHours) -> Self {
        self.quiet = q;
        self
    }

    /// Sends if the level and the hour allow it — `hour` in the installation's zone
    /// ([`crate::local_hour`]).
    ///
    /// A held notification is not an error, it is the intended behaviour; nor is it
    /// sent: the caller keeps it for when quiet hours end.
    pub async fn send_at(&self, n: &Notification, hour: u32) -> Result<Delivery> {
        let decided = self.quiet.decide(n.level, hour);
        if decided != Delivery::Sent {
            tracing::debug!(
                subject = %n.subject,
                level = ?n.level,
                ?decided,
                "notification not sent now"
            );
            return Ok(decided);
        }

        let url = format!("{}/{}", self.base_url, self.topic);
        let mut req = self.http.post(&url);
        if let Some((user, password)) = &self.account {
            req = req.basic_auth(user, Some(password));
        }
        let resp = req
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
        Ok(Delivery::Sent)
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
        // 🔴 Holding back is not failing — and not sending either: the caller keeps it.
        let c = client();
        let n = Notification::important("update", "Update available", "gitea 1.25");

        // 3 a.m., important level: held back, with no network call.
        assert_eq!(c.send_at(&n, 3).await.expect("no error"), Delivery::Held);
    }

    #[tokio::test]
    async fn an_info_is_never_sent() {
        let c = client();
        let n = Notification::new(crate::Level::Info, "x", "Info", "...");
        assert_eq!(
            c.send_at(&n, 14).await.expect("no error"),
            Delivery::NotPushed
        );
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
}
