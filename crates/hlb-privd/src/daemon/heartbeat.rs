//! The house's heartbeats, pushed to its site's Gatus: Homelabus answers, the backups
//! are up to date. Gatus alerts the owner when one stops — the house down, its
//! internet cut, the daemon dead, an app no longer backed up — through the site's own
//! ntfy, never the house's.
//!
//! And the other way round: a site the house cannot reach watches nothing. Three
//! pushes lost in a row are said through the HOUSE's notifications, the only ones
//! still leaving when it is the site that fell.

use std::sync::Arc;
use std::time::Duration;

use hlb_engine::site_watch;
use hlb_ingress::status_page::{self, Heartbeat};
use hlb_notify::Notification;
use hlb_state::State;

/// Pushes lost in a row before the house says its site does not answer: a quarter of
/// an hour, past a VPS's reboot.
const LOST_BEFORE_SAID: u32 = 3;

const TIMEOUT: Duration = Duration::from_secs(10);

/// Whether the site was reached, from one pass to the next.
#[derive(Debug, Default)]
pub struct Reaching {
    lost: u32,
    said: bool,
}

const SUBJECT: &str = "site-unreachable";

impl Reaching {
    /// What to say after a pass: once when the site stops answering, once when it
    /// answers again — never at every pass in between.
    pub fn after(&mut self, reached: Result<(), String>) -> Option<Notification> {
        match reached {
            Ok(()) => {
                self.lost = 0;
                std::mem::take(&mut self.said).then(|| {
                    Notification::important(
                        SUBJECT,
                        "The site answers again",
                        "The house's heartbeats reach its site's status page: it watches the \
                         house again.",
                    )
                })
            }
            Err(why) => {
                self.lost += 1;
                (self.lost == LOST_BEFORE_SAID && !self.said).then(|| {
                    self.said = true;
                    Notification::important(
                        SUBJECT,
                        "The site does not answer",
                        &format!(
                            "Nothing watches the house from outside: its heartbeats have not \
                             reached the site for {} minutes ({why}). The site's alerts \
                             stop with it.",
                            LOST_BEFORE_SAID as u64 * site_watch::PUSH_EVERY_SECS / 60
                        ),
                    )
                })
            }
        }
    }
}

/// One heartbeat's query: success, and why not.
pub fn query(ok: Result<(), String>) -> Vec<(&'static str, String)> {
    match ok {
        Ok(()) => vec![("success", "true".into())],
        Err(why) => vec![("success", "false".into()), ("error", why)],
    }
}

/// What the backups say: failing while any app is overdue.
fn backups(overdue: &[String]) -> Result<(), String> {
    if overdue.is_empty() {
        Ok(())
    } else {
        Err(format!("no recent backup of {}", overdue.join(", ")))
    }
}

/// One pass; `None` when the house has no watch to push to — no exposure, or no push
/// token in the vault, which `hlb site sync` draws when it puts the watch in place.
pub async fn pass(
    state: &Arc<State>,
    vault: Option<&hlb_secrets::Vault>,
) -> Option<Result<(), String>> {
    let exposure = state.exposure().await.ok()??;
    let vault = vault?;
    let ct = state.secret(site_watch::PUSH_SECRET).await.ok()??;
    let token = match vault.decrypt(&ct) {
        Ok(t) => t,
        Err(e) => return Some(Err(format!("the push token is unreadable: {e}"))),
    };
    let overdue =
        crate::daemon::schedule::BackupLoop::new(state.clone(), hlb_backup::Schedule::default())
            .overdue_apps()
            .await;
    let backed_up = match overdue {
        Ok(late) => backups(&late),
        Err(e) => Err(format!("the backups could not be read: {e}")),
    };
    let http = client(exposure.acme_ca_root.as_deref());
    let base = format!("https://{}", site_watch::status_host(&exposure.domain));
    for (beat, ok) in [
        (status_page::CONTROLLER, Ok(())),
        (status_page::BACKUPS, backed_up),
    ] {
        if let Err(e) = push(&http, &base, &beat, &token, ok).await {
            return Some(Err(e));
        }
    }
    Some(Ok(()))
}

/// The client: the public roots, and a private ACME directory's when the house has one
/// — the edge's certificate is signed by whatever signs the house's.
fn client(root_pem: Option<&str>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(pem) = root_pem {
        match reqwest::Certificate::from_pem(pem.as_bytes()) {
            Ok(root) => builder = builder.add_root_certificate(root),
            // Trusting less, never more: the push then fails, and is said.
            Err(e) => tracing::warn!(error = %e, "the ACME directory's root is unreadable"),
        }
    }
    builder.build().unwrap_or_default()
}

async fn push(
    http: &reqwest::Client,
    base: &str,
    beat: &Heartbeat,
    token: &str,
    ok: Result<(), String>,
) -> Result<(), String> {
    let url = format!("{base}{}", status_page::push_path(beat));
    let answer = http
        .post(&url)
        .bearer_auth(token)
        .query(&query(ok))
        .send()
        .await
        .map_err(|e| format!("{}: {e}", beat.name))?;
    if answer.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "{}: the site answered {}",
            beat.name,
            answer.status()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_site_lost_is_said_once_and_its_return_once() {
        let mut r = Reaching::default();
        let lost = || Err("timed out".to_string());
        assert!(r.after(lost()).is_none());
        assert!(r.after(lost()).is_none());
        let said = r.after(lost()).expect("said at the third");
        assert_eq!(said.title, "The site does not answer");
        assert!(said.body.contains("15 minutes"), "{}", said.body);
        assert!(said.body.contains("timed out"), "{}", said.body);
        for _ in 0..10 {
            assert!(r.after(lost()).is_none(), "said once, not at every pass");
        }
        let back = r.after(Ok(())).expect("its return");
        assert_eq!(back.title, "The site answers again");
        assert!(r.after(Ok(())).is_none());
    }

    #[test]
    fn a_single_lost_push_says_nothing() {
        let mut r = Reaching::default();
        assert!(r.after(Err("x".into())).is_none());
        assert!(r.after(Ok(())).is_none(), "nothing was said to take back");
        assert!(r.after(Err("x".into())).is_none());
        assert!(r.after(Err("x".into())).is_none(), "the count started over");
    }

    #[test]
    fn the_backups_fail_while_an_app_is_overdue() {
        assert_eq!(backups(&[]), Ok(()));
        assert_eq!(
            backups(&["gitea".into(), "immich".into()]),
            Err("no recent backup of gitea, immich".into())
        );
        assert_eq!(
            query(Err("why".into())),
            vec![
                ("success", "false".to_string()),
                ("error", "why".to_string())
            ]
        );
    }
}
