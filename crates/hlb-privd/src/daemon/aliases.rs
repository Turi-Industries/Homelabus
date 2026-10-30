//! The temporary aliases, taken off Stalwart once expired.

use std::sync::Arc;

use hlb_state::State;

/// Purge of the expired temporary aliases.
///
/// 🔴 **Without this loop, "temporary" is a lie.** Stalwart has no notion of expiry: an
/// account's alias list is a plain list, and what is written there stays. An address
/// given to a merchant "for thirty days" keeps receiving indefinitely if nobody comes to
/// remove it.
///
/// ## 🔴 A failed purge must SHOW
///
/// This is the property that sets this loop apart from the others. A reconciliation that
/// fails leaves the cluster as it is — annoying but honest. A purge that fails leaves
/// doors **open that their owner believes closed**, and the silence sustains the belief.
/// So the report surfaces the number of addresses still open, and not only the number of
/// errors.
pub struct AliasPurgeLoop {
    state: Arc<State>,
    mail: Option<Arc<hlb_mail::Stalwart>>,
    default_domain: String,
}

/// What one purge pass produced.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PurgeReport {
    /// Expired aliases found still active.
    pub due: usize,
    /// Actually removed from the server.
    pub retires: usize,
    pub errors: Vec<String>,
}

impl PurgeReport {
    /// How many addresses stay open while believed closed.
    ///
    /// 🔴 This is THE number to watch — not the error count. An error-free purge that
    /// removed nothing leaves as many doors open as a purge that failed loudly.
    ///
    pub fn still_open(&self) -> usize {
        self.due.saturating_sub(self.retires)
    }

    pub fn is_clean(&self) -> bool {
        self.still_open() == 0
    }
}

impl AliasPurgeLoop {
    pub fn new(
        state: Arc<State>,
        mail: Option<Arc<hlb_mail::Stalwart>>,
        default_domain: impl Into<String>,
    ) -> Self {
        Self {
            state,
            mail,
            default_domain: default_domain.into(),
        }
    }

    pub async fn tick(&self) -> PurgeReport {
        let mut r = PurgeReport::default();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let due = match self.state.aliases_to_purge(now).await {
            Ok(v) => v,
            Err(e) => {
                r.errors.push(e.to_string());
                return r;
            }
        };
        r.due = due.len();

        let Some(mail) = &self.mail else {
            if r.due > 0 {
                // 🔴 We mark NOTHING as purged. Doing so without removing the alias
                // would be the worst of both worlds: the address would still receive,
                // and nothing would say so any more.
                tracing::error!(
                    open = r.due,
                    "purge impossible (Stalwart not configured): these expired addresses \
                     STILL RECEIVE, and their owner believes them closed"
                );
                r.errors.push("Stalwart not configured".into());
            }
            return r;
        };

        for (user, mailbox, local) in due {
            let dom = self
                .state
                .mailboxes(&user)
                .await
                .ok()
                .and_then(|v| {
                    v.into_iter()
                        .find(|(l, ..)| l == &mailbox)
                        .map(|(_, d, _)| d)
                })
                .unwrap_or_else(|| self.default_domain.clone());

            // The state is only marked AFTER the actual removal.
            match mail.remove_alias(&format!("{mailbox}@{dom}"), &local).await {
                Ok(_) => match self.state.deactivate_alias(&user, &local).await {
                    Ok(()) => {
                        r.retires += 1;
                        tracing::info!(user, alias = %local, "expired alias removed");
                    }
                    Err(e) => r.errors.push(format!("{local} : {e}")),
                },
                // A failure does not block the following ones: each door closed is a
                // gain, even if the next one resists.
                Err(e) => r.errors.push(format!("{local} : {e}")),
            }
        }

        if !r.is_clean() {
            tracing::error!(
                open = r.still_open(),
                "🔴 expired addresses STILL active after the purge"
            );
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_purge_without_stalwart_marks_nothing() {
        // 🔴 Marking an alias "purged" without having removed it from the server would
        // be the worst of both worlds: the address would still receive, AND nothing
        // would say so. The silence would sustain the belief that the door is closed.
        let s = Arc::new(State::in_memory().await.expect("state"));
        s.upsert_user("lena", "standard", None)
            .await
            .expect("account");
        s.add_mailbox("lena", "lena", "example.fr", true)
            .await
            .expect("mailbox");
        s.add_alias("lena", "lena", "old", Some(1), None, None)
            .await
            .expect("expired alias");

        let l = AliasPurgeLoop::new(s.clone(), None, "example.fr");
        let r = l.tick().await;

        assert_eq!(r.due, 1);
        assert_eq!(r.retires, 0);
        assert_eq!(r.still_open(), 1, "the address still receives");
        assert!(!r.is_clean());

        // And the state was NOT touched: the alias stays reported as active.
        let remaining = s.aliases_to_purge(9_999_999_999).await.expect("relecture");
        assert_eq!(remaining.len(), 1, "nothing was marked purged");
    }

    #[tokio::test]
    async fn a_clean_purge_has_nothing_left_open() {
        // No expired alias: nothing to do, and the report must say so without
        // fabricate an alert.
        let s = Arc::new(State::in_memory().await.expect("state"));
        s.upsert_user("lena", "standard", None)
            .await
            .expect("account");
        s.add_mailbox("lena", "lena", "example.fr", true)
            .await
            .expect("mailbox");
        // Permanent: never due.
        s.add_alias("lena", "lena", "contact", None, None, None)
            .await
            .expect("alias permanent");

        let r = AliasPurgeLoop::new(s, None, "example.fr").tick().await;
        assert_eq!(r.due, 0);
        assert!(r.is_clean());
        assert!(
            r.errors.is_empty(),
            "no alert for a permanent one: {:?}",
            r.errors
        );
    }

    #[test]
    fn what_matters_is_what_stays_open_not_the_error_count() {
        // 🔴 An error-free purge that removed nothing leaves as many doors open as a
        // purge that failed loudly. That is the first number
        // to watch.
        let silent = PurgeReport {
            due: 5,
            retires: 0,
            errors: vec![],
        };
        assert_eq!(silent.still_open(), 5);
        assert!(!silent.is_clean(), "no error, and yet five doors left open");

        let noisy = PurgeReport {
            due: 5,
            retires: 5,
            errors: vec!["a warning".into()],
        };
        assert!(
            noisy.is_clean(),
            "everything is closed again: the noise changes nothing"
        );
    }
}
