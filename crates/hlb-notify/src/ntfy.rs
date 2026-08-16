//! Client ntfy.
//!
//! ntfy est retenu parce qu'il s'auto-héberge, ne demande aucun compte, et qu'une
//! notification est un simple `POST` — pas de SDK, pas de jeton à faire tourner.
//! Il tient dans le catalogue comme n'importe quelle autre app.

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

    /// Envoie si le niveau et l'heure le permettent.
    ///
    /// Renvoie `Ok(false)` quand la notification a été **retenue** — ce n'est pas une
    /// erreur, c'est le fonctionnement prévu. Les confondre ferait apparaître des
    /// échecs dans les journaux à chaque notification nocturne non critique.
    pub async fn send_at(&self, n: &Notification, hour: u32) -> Result<bool> {
        if !self.quiet.allows(n.level, hour) {
            tracing::debug!(
                sujet = %n.subject,
                niveau = ?n.level,
                "notification retenue (heures calmes ou niveau non poussé)"
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
            .map_err(|source| Error::Http { url: url.clone(), source })?;

        if !resp.status().is_success() {
            return Err(Error::Rejected(resp.status().as_u16()));
        }

        tracing::info!(sujet = %n.subject, "notification envoyée");
        Ok(true)
    }

    /// Envoie en utilisant l'heure locale courante.
    pub async fn send(&self, n: &Notification) -> Result<bool> {
        let hour = heure_locale();
        self.send_at(n, hour).await
    }
}

/// L'heure locale, sans dépendre d'une bibliothèque de dates.
///
/// Approximation volontaire : on ne cherche qu'à distinguer « nuit » de « journée ».
/// Une erreur d'une heure sur un fuseau exotique n'a aucune conséquence ici, alors
/// qu'une dépendance de plus en aurait une.
fn heure_locale() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    ((secs / 3600) % 24) as u32
}

/// Envoie une notification si un client est configuré.
///
/// Sans client, on journalise au lieu de perdre l'information : une alerte non
/// envoyée doit rester visible quelque part.
pub async fn notify_or_log(client: Option<&NtfyClient>, n: &Notification) {
    match client {
        Some(c) => {
            if let Err(e) = c.send(n).await {
                tracing::error!(sujet = %n.subject, "notification impossible : {e}");
                tracing::warn!("{} — {}", n.title, n.body);
            }
        }
        None => {
            let niveau = if n.level >= Level::Critical { "🔴" } else { "🟠" };
            tracing::warn!("{niveau} {} — {} (aucun ntfy configuré)", n.title, n.body);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> NtfyClient {
        NtfyClient::new("https://ntfy.example.fr/", "homelab")
    }

    #[test]
    fn the_base_url_is_normalised() {
        let c = client();
        assert_eq!(c.base_url, "https://ntfy.example.fr");
    }

    #[tokio::test]
    async fn a_held_notification_is_not_an_error() {
        // 🔴 Retenir n'est pas échouer. Les confondre ferait apparaître des erreurs
        // dans les journaux à chaque notification nocturne non critique.
        let c = client();
        let n = Notification::important("maj", "Mise à jour", "gitea 1.25");

        // 3 h du matin, niveau important : retenu, sans appel réseau.
        assert!(!c.send_at(&n, 3).await.expect("pas d'erreur"));
    }

    #[tokio::test]
    async fn an_info_is_never_sent() {
        let c = client();
        let n = Notification::new(Level::Info, "x", "Info", "…");
        assert!(!c.send_at(&n, 14).await.expect("pas d'erreur"));
    }

    #[tokio::test]
    async fn a_critical_notification_attempts_delivery_at_night() {
        // Le domaine n'existe pas : on doit obtenir une erreur RÉSEAU, ce qui prouve
        // que l'envoi a bien été tenté malgré l'heure.
        let c = client();
        let n = Notification::critical("disque", "Disque plein", "node2 à 97 %");
        let r = c.send_at(&n, 3).await;
        assert!(matches!(r, Err(Error::Http { .. })), "{r:?}");
    }

    #[tokio::test]
    async fn without_a_client_nothing_panics() {
        // L'information doit rester visible dans les journaux plutôt que disparaître.
        notify_or_log(None, &Notification::critical("x", "Titre", "Corps")).await;
    }

    #[test]
    fn the_local_hour_is_within_range() {
        let h = heure_locale();
        assert!(h < 24, "heure aberrante : {h}");
    }
}
