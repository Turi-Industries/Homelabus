//! The house's router: the names Caddy serves, answered inside by the router's Unbound,
//! and the ports forwarded from the internet, as the privileged side's nightly `router
//! sync` left them. No router connected is
//! no line — a house may have none Homelabus works on.

use hlb_api::assertions::STALE_AFTER_S;
use hlb_api::issues::{Cause, Finding};
use hlb_api::Attention;
use hlb_state::State;

pub async fn findings(state: &State, now: i64) -> Vec<Finding> {
    let config = match state.router().await {
        Ok(Some(c)) => c,
        Ok(None) => return Vec::new(),
        // Unreadable is not "no router".
        Err(_) => return vec![(Cause::RouterUnknown, Attention::Notice, None)],
    };
    let subject = Some(config.url);
    let sync = state.router_sync().await.ok().flatten();
    let mut out = Vec::new();
    // A failure stays said until a sync holds, however old: a stale reading is said
    // beside it, never instead of it.
    if sync.as_ref().is_some_and(|s| s.failed.is_some()) {
        out.push((Cause::RouterUnsynced, Attention::Critical, subject.clone()));
    }
    if sync.is_none_or(|s| now - s.at > STALE_AFTER_S) {
        out.push((Cause::RouterUnknown, Attention::Notice, subject));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_state::{RouterConfig, RouterSync};

    const URL: &str = "https://10.77.0.3";

    async fn connected() -> State {
        let s = State::in_memory().await.expect("state");
        s.set_router(&RouterConfig {
            url: URL.into(),
            fingerprint: "ab".repeat(32),
            caddy: "10.77.0.11".into(),
        })
        .await
        .expect("router");
        s
    }

    fn line(cause: Cause, attention: Attention) -> Finding {
        (cause, attention, Some(URL.into()))
    }

    #[tokio::test]
    async fn no_router_is_no_line() {
        let s = State::in_memory().await.expect("state");
        assert!(findings(&s, 1_000).await.is_empty());
    }

    #[tokio::test]
    async fn a_router_never_synced_is_unknown_and_one_synced_tonight_is_silent() {
        let s = connected().await;
        assert_eq!(
            findings(&s, 1_000).await,
            [line(Cause::RouterUnknown, Attention::Notice)]
        );
        s.record_router_sync(&RouterSync {
            at: 1_000,
            failed: None,
        })
        .await
        .expect("sync");
        assert!(findings(&s, 1_000 + STALE_AFTER_S).await.is_empty());
        assert_eq!(
            findings(&s, 1_001 + STALE_AFTER_S).await,
            [line(Cause::RouterUnknown, Attention::Notice)],
            "stale"
        );
    }

    #[tokio::test]
    async fn a_failed_sync_stays_said_until_one_holds() {
        let s = connected().await;
        s.record_router_sync(&RouterSync {
            at: 1_000,
            failed: Some("the router's API key is not in the vault".into()),
        })
        .await
        .expect("sync");
        assert_eq!(
            findings(&s, 1_000).await,
            [line(Cause::RouterUnsynced, Attention::Critical)]
        );
        assert_eq!(
            findings(&s, 1_001 + STALE_AFTER_S).await,
            [
                line(Cause::RouterUnsynced, Attention::Critical),
                line(Cause::RouterUnknown, Attention::Notice)
            ],
            "a failure is not forgotten for being old"
        );
        s.record_router_sync(&RouterSync {
            at: 2_000,
            failed: None,
        })
        .await
        .expect("sync");
        assert!(findings(&s, 2_000).await.is_empty());
    }
}
