//! The flaws in what runs, as the privileged side's daily pass read them: the inbox's
//! lines. That pass decides what is said aloud and stores it; this side reads the state
//! and runs no Grype — the inbox is polled.

use hlb_api::issues::{Cause, Finding};
use hlb_api::Attention;
use hlb_state::State;
use hlb_updater::flaws::images;

/// How old the last good reading of an image may be: the daily pass missed twice. One
/// failed night is a hiccup; the flaws known meanwhile are the ones it does not know.
pub const STALE_AFTER_S: i64 = 2 * 86_400;

/// An app whose exploitable flaw was said, and one with an image not read lately.
pub async fn findings(state: &State, now: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    for (app, _) in state.installed_apps().await.unwrap_or_default() {
        // The alerts held are those of the last reading: forgotten once the flaw is gone.
        if !state
            .alerted_flaws(&app)
            .await
            .unwrap_or_default()
            .is_empty()
        {
            out.push((
                Cause::FlawExploitable,
                Attention::Critical,
                Some(app.clone()),
            ));
        }
        let Ok(m) = state.app_manifest(&app).await else {
            continue;
        };
        let mut unread = false;
        for i in images(&m) {
            // 🔴 An image running by its tag alone has no digest to read: unknown, never
            // clean.
            let read_at = match &i.digest {
                Some(d) => state
                    .image_scan(d)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|s| s.read_at),
                None => None,
            };
            unread |= read_at.is_none_or(|r| now - r > STALE_AFTER_S);
        }
        if unread {
            out.push((Cause::FlawsUnknown, Attention::Notice, Some(app)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000001";

    async fn installed(pinned: bool) -> State {
        let s = State::in_memory().await.expect("state");
        let digest = if pinned {
            format!(", digest: \"{DIGEST}\"")
        } else {
            String::new()
        };
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(&format!(
            r#"
apiVersion: hlb/v1
kind: App
metadata: {{ name: gitea }}
spec:
  image: {{ repo: gitea, tag: "1"{digest} }}
"#
        ))
        .expect("manifest");
        s.upsert_app("gitea", &m, None).await.expect("app");
        s
    }

    #[tokio::test]
    async fn an_image_never_read_or_not_lately_is_unknown_and_a_fresh_one_says_nothing() {
        let s = installed(true).await;
        let unknown = vec![(Cause::FlawsUnknown, Attention::Notice, Some("gitea".into()))];
        assert_eq!(findings(&s, 1_000).await, unknown, "never read");

        s.record_image_scan(DIGEST, "gitea:1", 1_000, Ok(&[]))
            .await
            .expect("read");
        assert!(findings(&s, 1_000 + STALE_AFTER_S).await.is_empty());
        // A failed night keeps the last good reading, and its age.
        s.record_image_scan(DIGEST, "gitea:1", 1_000 + STALE_AFTER_S, Err("no Grype"))
            .await
            .expect("failed");
        assert!(findings(&s, 1_000 + STALE_AFTER_S).await.is_empty());
        assert_eq!(findings(&s, 1_001 + STALE_AFTER_S).await, unknown, "stale");
    }

    #[tokio::test]
    async fn an_image_running_by_its_tag_alone_is_never_read_clean() {
        let s = installed(false).await;
        assert_eq!(
            findings(&s, 1_000).await,
            vec![(Cause::FlawsUnknown, Attention::Notice, Some("gitea".into()))]
        );
    }

    #[tokio::test]
    async fn an_exploitable_flaw_said_is_critical_until_it_is_gone() {
        let s = installed(true).await;
        s.record_image_scan(DIGEST, "gitea:1", 1_000, Ok(&[]))
            .await
            .expect("read");
        let said: BTreeSet<String> = ["CVE-2025-15467".to_string()].into();
        s.set_alerted_flaws("gitea", &said, 1_000)
            .await
            .expect("said");
        assert_eq!(
            findings(&s, 1_000).await,
            vec![(
                Cause::FlawExploitable,
                Attention::Critical,
                Some("gitea".into())
            )]
        );
        s.set_alerted_flaws("gitea", &BTreeSet::new(), 2_000)
            .await
            .expect("gone");
        assert!(findings(&s, 2_000).await.is_empty());
    }
}
