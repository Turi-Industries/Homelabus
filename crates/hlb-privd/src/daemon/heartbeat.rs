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
    // What the page told the internet of an outage — the house's words, or the owner's
    // from the site while the house was down — reaches the house's portal too.
    if let Err(e) = mirror_page(&http, &base, state).await {
        tracing::warn!("the site's announcements not mirrored: {e}");
    }
    Some(Ok(()))
}

/// The most of the page's answer read: Gatus's configuration is a few kilobytes, and
/// the page is the VPS's word, not the house's.
const PAGE_BYTES: usize = 1 << 20;

/// Mirrors the site's status page's announcements into the house's
/// (`hlb_engine::site_watch::mirror`). The number of entries written.
async fn mirror_page(http: &reqwest::Client, base: &str, state: &State) -> Result<usize, String> {
    let mut answer = http
        .get(format!("{base}/api/v1/config"))
        .send()
        .await
        .map_err(|e| format!("the status page: {e}"))?;
    if !answer.status().is_success() {
        return Err(format!("the status page answered {}", answer.status()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = answer
        .chunk()
        .await
        .map_err(|e| format!("the status page: {e}"))?
    {
        body.extend_from_slice(&chunk);
        if body.len() > PAGE_BYTES {
            return Err(format!(
                "the status page's answer is past {PAGE_BYTES} bytes"
            ));
        }
    }
    let page: site_watch::PageConfig =
        serde_json::from_slice(&body).map_err(|e| format!("the status page's answer: {e}"))?;
    let now = crate::now();
    let mut written = 0;
    for e in page.announcements.iter().take(site_watch::MIRRORED_ENTRIES) {
        let known = state
            .site_announcement(&e.timestamp)
            .await
            .map_err(|e| e.to_string())?;
        if let Some(m) = site_watch::mirror(e, known.as_ref()) {
            state
                .mirror_site_announcement(&m, now)
                .await
                .map_err(|e| e.to_string())?;
            written += 1;
        }
    }
    Ok(written)
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

    /// A Gatus answering `/api/v1/config` with whatever `page` holds at the time.
    async fn fake_page(page: Arc<std::sync::Mutex<String>>) -> String {
        let app = axum::Router::new().route(
            "/api/v1/config",
            axum::routing::get(move || {
                let page = page.clone();
                async move { page.lock().expect("page").clone() }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("http://{addr}")
    }

    fn config(message: &str, archived: bool) -> String {
        serde_json::json!({
            "oidc": false,
            "announcements": [{
                "timestamp": "2026-11-09T18:00:00Z", "type": "outage",
                "message": message, "archived": archived,
            }],
        })
        .to_string()
    }

    #[tokio::test]
    async fn the_page_s_incident_reaches_the_portal_and_its_history() {
        let state = State::in_memory().await.expect("state");
        let page = Arc::new(std::sync::Mutex::new(config(
            "The house cannot be reached. We know.",
            false,
        )));
        let base = fake_page(page.clone()).await;
        let http = client(None);

        assert_eq!(mirror_page(&http, &base, &state).await, Ok(1));
        assert_eq!(
            mirror_page(&http, &base, &state).await,
            Ok(0),
            "seen already"
        );
        let now = crate::now();
        let portal = state
            .announcements(hlb_types::Role::User, now, false)
            .await
            .expect("list");
        assert_eq!(portal.len(), 1);
        assert_eq!(portal[0].title, "The house cannot be reached");

        *page.lock().expect("page") = config(
            "The house cannot be reached. We know. [18:30 UTC] The house can be reached again.",
            true,
        );
        assert_eq!(mirror_page(&http, &base, &state).await, Ok(1));
        assert!(state
            .announcements(hlb_types::Role::User, now + 1, false)
            .await
            .expect("list")
            .is_empty());
        let past = state
            .announcements(hlb_types::Role::User, now + 1, true)
            .await
            .expect("list");
        assert_eq!(past.len(), 1);
        assert_eq!(
            past[0].follow_ups[0].body,
            "[18:30 UTC] The house can be reached again."
        );

        *page.lock().expect("page") = "x".repeat(PAGE_BYTES + 1);
        assert!(mirror_page(&http, &base, &state).await.is_err());
    }

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
