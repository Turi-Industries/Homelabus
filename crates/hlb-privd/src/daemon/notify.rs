//! Saying things to people: ntfy, quiet hours, and what they hold back.
//!
//! 🔴 **A notification quiet hours held back is kept, not dropped.** `send` answered a
//! `bool`, held read as said: an Important alert raised at night was never raised
//! again, an update applied at 3 a.m. was marked notified, and a daily job firing at
//! the hour the controller started told nobody if that hour was quiet. Held, it goes
//! into the state (`held_notifications`), and [`Notifier::flush`] delivers it once the
//! installation's own morning comes — read in its zone (`hlb config timezone`), never
//! UTC.

use std::sync::Arc;

use hlb_notify::{Delivery, Level, Notification, NtfyClient};
use hlb_state::State;

/// The one way the daemon notifies: every loop holds one.
#[derive(Clone)]
pub struct Notifier {
    client: Option<Arc<NtfyClient>>,
    state: Arc<State>,
}

/// What became of a notification that was said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Said {
    /// ntfy took it.
    Sent,
    /// Quiet hours: kept in the state, delivered when they end.
    Held,
    /// No ntfy configured, or a level never pushed: in the logs, which is where it is
    /// read then.
    Logged,
}

/// A notification nobody will receive unless it is said again.
#[derive(Debug, thiserror::Error)]
pub enum Unsaid {
    #[error(transparent)]
    Ntfy(#[from] hlb_notify::Error),
    #[error("could not be kept for after quiet hours: {0}")]
    Kept(#[from] hlb_state::Error),
}

/// What one delivery of the held notifications did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Flushed {
    pub sent: usize,
    /// Still held: quiet hours go on, or ntfy refused — tried at the next pass.
    pub left: usize,
}

impl Notifier {
    pub fn new(client: Option<Arc<NtfyClient>>, state: Arc<State>) -> Self {
        Self { client, state }
    }

    /// Says `n` now, holds it for the morning, or logs it.
    #[must_use = "an unsaid notification is lost unless the caller says it again"]
    pub async fn say(&self, n: &Notification, now: i64) -> Result<Said, Unsaid> {
        let Some(client) = &self.client else {
            log(n, "no ntfy configured");
            return Ok(Said::Logged);
        };
        let hour = self.hour(now).await;
        match client.send_at(n, hour).await {
            Ok(Delivery::Sent) => Ok(Said::Sent),
            Ok(Delivery::NotPushed) => Ok(Said::Logged),
            Ok(Delivery::Held) => {
                if let Err(e) = self
                    .state
                    .hold_notification(&n.subject, level_name(n.level), &n.title, &n.body, now)
                    .await
                {
                    log(n, "could not be kept for the morning");
                    return Err(e.into());
                }
                Ok(Said::Held)
            }
            Err(e) => {
                tracing::error!(subject = %n.subject, "could not notify: {e}");
                tracing::warn!("{} — {}", n.title, n.body);
                Err(e.into())
            }
        }
    }

    /// Says `n` for a caller that raises it again at its own next pass anyway: a
    /// failure is logged, with the notification.
    pub async fn tell(&self, n: &Notification) {
        let _ = self.say(n, crate::now()).await;
    }

    /// Delivers the held notifications once quiet hours are over, oldest first. Stops
    /// at the first ntfy refuses: the rest wait for the next pass, in order.
    pub async fn flush(&self, now: i64) -> Flushed {
        let mut out = Flushed::default();
        let Some(client) = &self.client else {
            return out;
        };
        let held = match self.state.held_notifications().await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("held notifications unreadable: {e}");
                return out;
            }
        };
        let zone = self.zone().await;
        let hour = hlb_notify::local_hour(zone.as_deref(), now);
        let mut pending = held.into_iter();
        for h in pending.by_ref() {
            let (hh, mm) = hlb_notify::local_time(zone.as_deref(), h.held_at);
            let n = Notification::new(
                parse_level(&h.level),
                &h.subject,
                &h.title,
                &format!(
                    "{}\n(held during quiet hours, since {hh:02}:{mm:02})",
                    h.body
                ),
            );
            match client.send_at(&n, hour).await {
                Ok(Delivery::Sent) => {
                    out.sent += 1;
                    if let Err(e) = self
                        .state
                        .release_held_notification(&h.subject, h.revision)
                        .await
                    {
                        tracing::warn!(subject = %h.subject, "sent, still held: {e}");
                    }
                }
                // Never pushed: nothing to wait for.
                Ok(Delivery::NotPushed) => {
                    let _ = self
                        .state
                        .release_held_notification(&h.subject, h.revision)
                        .await;
                }
                Ok(Delivery::Held) => {
                    out.left += 1;
                    break;
                }
                Err(e) => {
                    tracing::warn!(subject = %h.subject, "held notification kept: {e}");
                    out.left += 1;
                    break;
                }
            }
        }
        out.left += pending.count();
        out
    }

    async fn zone(&self) -> Option<String> {
        self.state.timezone().await.ok().flatten()
    }

    async fn hour(&self, now: i64) -> u32 {
        hlb_notify::local_hour(self.zone().await.as_deref(), now)
    }
}

fn log(n: &Notification, why: &str) {
    let mark = if n.level >= Level::Critical {
        "🔴"
    } else {
        "🟠"
    };
    tracing::warn!("{mark} {} - {} ({why})", n.title, n.body);
}

/// The level as it is stored — `hlb-notify`'s own serialisation, so both read alike.
fn level_name(l: Level) -> &'static str {
    match l {
        Level::Debug => "debug",
        Level::Info => "info",
        Level::Important => "important",
        Level::Critical => "critical",
    }
}

/// A level the state names; one it does not know is Important — held means pushed.
fn parse_level(s: &str) -> Level {
    match s {
        "debug" => Level::Debug,
        "info" => Level::Info,
        "critical" => Level::Critical,
        _ => Level::Important,
    }
}

/// Tells someone about every image update that ended — an applied one too: an updater
/// that stays silent when it succeeds cannot be told from one that does nothing.
///
/// A notice ntfy refused stays unsent and is tried at the next pass; one quiet hours
/// held is kept in the state for the morning and counts as said, like one logged with
/// no ntfy at all.
pub async fn notify_update_runs(state: &State, notif: &Notifier, now: i64) {
    let runs = match state.unnotified_update_runs().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("update outcomes unreadable: {e}");
            return;
        }
    };
    for run in runs {
        let n = update_notice(&run);
        if let Err(e) = notif.say(&n, now).await {
            tracing::warn!(app = %run.app, "update notice kept for the next pass: {e}");
            return;
        }
        if let Err(e) = state.mark_update_run_notified(run.id, now).await {
            tracing::warn!(app = %run.app, "update notice sent, not marked: {e}");
        }
    }
}

/// What an update's outcome says, and how loudly.
pub fn update_notice(run: &hlb_state::UpdateRun) -> hlb_notify::Notification {
    use hlb_state::UpdateRunOutcome as O;
    let subject = format!("update:{}", run.app);
    let detail = if run.detail.is_empty() {
        String::new()
    } else {
        format!(" — {}", run.detail)
    };
    match run.outcome {
        O::Applied => hlb_notify::Notification::important(
            &subject,
            &format!("{} updated", run.app),
            &format!("{} → {}", run.from_image, run.to_image),
        ),
        O::RolledBack => hlb_notify::Notification::important(
            &subject,
            &format!("{}'s update was rolled back", run.app),
            &format!(
                "it still runs {}; {} did not start{detail}",
                run.from_image, run.to_image
            ),
        ),
        // Neither image is serving: the old one would not start on what the new one
        // had already migrated.
        O::Paused => hlb_notify::Notification::critical(
            &subject,
            &format!("{}'s update stopped half-way", run.app),
            &format!(
                "{} → {}: Swarm paused it and nothing may be serving{detail}",
                run.from_image, run.to_image
            ),
        ),
        O::Inconclusive => hlb_notify::Notification::important(
            &subject,
            &format!("{}'s update did not conclude", run.app),
            &format!(
                "{} → {}: no outcome within the deadline — hlb ps says where it stands{detail}",
                run.from_image, run.to_image
            ),
        ),
    }
}

/// A fake ntfy counting every publication, and refusing them with a 500 while its
/// switch is on.
#[cfg(test)]
pub(crate) struct FakeNtfy {
    pub url: String,
    pub hits: Arc<std::sync::atomic::AtomicUsize>,
    pub refusing: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(test)]
pub(crate) async fn fake_ntfy() -> FakeNtfy {
    use std::sync::atomic::Ordering;
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let refusing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (h, r) = (hits.clone(), refusing.clone());
    let app = axum::Router::new().route(
        "/{topic}",
        axum::routing::post(move || {
            let (h, r) = (h.clone(), r.clone());
            async move {
                h.fetch_add(1, Ordering::SeqCst);
                if r.load(Ordering::SeqCst) {
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                } else {
                    axum::http::StatusCode::OK
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await });
    FakeNtfy {
        url: format!("http://{addr}"),
        hits,
        refusing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-07-01 01:00 UTC: 03:00 in Paris, quiet. 07:00 UTC: 09:00 there.
    const NIGHT: i64 = 1_782_867_600;
    const MORNING: i64 = NIGHT + 6 * 3600;

    async fn paris() -> Arc<State> {
        let s = Arc::new(State::in_memory().await.expect("state"));
        s.set_timezone("Europe/Paris").await.expect("zone");
        s
    }

    async fn ntfy() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let f = fake_ntfy().await;
        (f.url, f.hits)
    }

    #[tokio::test]
    async fn a_notice_held_at_night_is_delivered_in_the_morning() {
        let (url, hits) = ntfy().await;
        let s = paris().await;
        let n = Notifier::new(Some(Arc::new(NtfyClient::new(url, "hlb"))), s.clone());
        let notice = Notification::important("update:gitea", "gitea updated", "1.24 → 1.25");

        assert_eq!(n.say(&notice, NIGHT).await.expect("said"), Said::Held);
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(s.held_notifications().await.expect("read").len(), 1);

        // Still night: nothing leaves, nothing is lost.
        assert_eq!(n.flush(NIGHT + 600).await, Flushed { sent: 0, left: 1 });
        assert_eq!(n.flush(MORNING).await, Flushed { sent: 1, left: 0 });
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(s.held_notifications().await.expect("read").is_empty());
    }

    #[tokio::test]
    async fn quiet_hours_are_the_installation_s_not_utc() {
        // 06:30 UTC is quiet in UTC, and 08:30 in Paris: sent.
        let (url, hits) = ntfy().await;
        let s = paris().await;
        let n = Notifier::new(Some(Arc::new(NtfyClient::new(url, "hlb"))), s);
        let notice = Notification::important("x", "t", "b");
        assert_eq!(
            n.say(&notice, MORNING - 1800).await.expect("said"),
            Said::Sent
        );
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_refused_delivery_is_kept_for_the_next_pass() {
        let s = paris().await;
        s.hold_notification("x", "important", "t", "b", NIGHT)
            .await
            .expect("held");
        // Nothing listens there.
        let n = Notifier::new(
            Some(Arc::new(NtfyClient::new("http://127.0.0.1:9", "hlb"))),
            s.clone(),
        );
        assert_eq!(n.flush(MORNING).await, Flushed { sent: 0, left: 1 });
        assert_eq!(s.held_notifications().await.expect("read").len(), 1);
    }

    #[test]
    fn a_stored_level_reads_back_as_written() {
        for l in [Level::Debug, Level::Info, Level::Important, Level::Critical] {
            assert_eq!(parse_level(level_name(l)), l);
        }
    }

    fn run(outcome: hlb_state::UpdateRunOutcome) -> hlb_state::UpdateRun {
        hlb_state::UpdateRun {
            id: 0,
            app: "gitea".into(),
            ran_at: 0,
            from_image: "gitea/gitea:1.24@sha256:a".into(),
            to_image: "gitea/gitea:1.24.7@sha256:b".into(),
            outcome,
            detail: String::new(),
        }
    }

    #[test]
    fn an_applied_update_is_pushed_like_a_failed_one() {
        use hlb_state::UpdateRunOutcome as O;
        let applied = update_notice(&run(O::Applied));
        assert!(
            applied.level.is_pushed(),
            "a success said nowhere is silence"
        );
        assert!(applied.body.contains("1.24.7"), "{}", applied.body);
        assert!(update_notice(&run(O::RolledBack)).level.is_pushed());
        assert_eq!(
            update_notice(&run(O::Paused)).level,
            hlb_notify::Level::Critical,
            "nothing may be serving"
        );
    }

    #[tokio::test]
    async fn every_update_outcome_is_said_once() {
        let s = State::in_memory().await.expect("state");
        s.record_update_run(&run(hlb_state::UpdateRunOutcome::Applied))
            .await
            .expect("recorded");
        let s = Arc::new(s);
        notify_update_runs(&s, &Notifier::new(None, s.clone()), 10).await;
        assert!(s.unnotified_update_runs().await.expect("read").is_empty());
    }

    #[tokio::test]
    async fn an_update_notice_ntfy_refused_is_not_marked_said() {
        let s = Arc::new(State::in_memory().await.expect("state"));
        s.record_update_run(&run(hlb_state::UpdateRunOutcome::Applied))
            .await
            .expect("recorded");
        // Nothing listens there; noon UTC, no quiet hours.
        let client = Arc::new(hlb_notify::NtfyClient::new("http://127.0.0.1:9", "hlb"));
        let notif = Notifier::new(Some(client), s.clone());
        notify_update_runs(&s, &notif, 1_782_907_200).await;
        assert_eq!(s.unnotified_update_runs().await.expect("read").len(), 1);
    }

    #[tokio::test]
    async fn an_update_applied_at_night_is_kept_for_the_morning() {
        let s = Arc::new(State::in_memory().await.expect("state"));
        s.record_update_run(&run(hlb_state::UpdateRunOutcome::Applied))
            .await
            .expect("recorded");
        let client = Arc::new(hlb_notify::NtfyClient::new("http://127.0.0.1:9", "hlb"));
        let notif = Notifier::new(Some(client), s.clone());
        // 03:00 UTC: held, not sent — kept, so marking it said loses nothing.
        notify_update_runs(&s, &notif, 1_782_874_800).await;
        assert!(s.unnotified_update_runs().await.expect("read").is_empty());
        assert_eq!(s.held_notifications().await.expect("held").len(), 1);
    }
}
