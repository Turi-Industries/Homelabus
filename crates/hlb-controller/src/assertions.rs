//! The manifests' assertions: read from the running apps every night, said in the
//! inbox and on each app's page.
//!
//! ## 🔴 One builder, for the page and the inbox
//!
//! [`of_app`] merges what the frozen manifest declares with what was last read. An
//! assertion never read, or not lately, is `unknown` HERE, so neither consumer can
//! take a missing row for a closed door.

use hlb_api::assertions::{AssertionResult, Verdict, STALE_AFTER_S};
use hlb_api::issues::{Cause, Finding};
use hlb_state::State;

/// An app's assertions, as the manifest it runs declares them and as last read.
pub async fn of_app(state: &State, app: &str, now: i64) -> Vec<AssertionResult> {
    let Ok(m) = state.app_manifest(app).await else {
        return Vec::new();
    };
    let read = state.assertion_results().await.unwrap_or_default();
    hlb_guide::assertions::declared(&m)
        .into_iter()
        .map(|a| {
            let last = read
                .iter()
                .find(|(owner, r)| owner == app && r.id == a.id)
                .map(|(_, r)| r);
            let r = match last {
                Some(r) if now - r.checked_at <= STALE_AFTER_S => AssertionResult {
                    holds: a.holds.clone(),
                    ..r.clone()
                },
                Some(r) => AssertionResult {
                    holds: a.holds.clone(),
                    verdict: Verdict::Unknown,
                    observed: format!("not read for {} days", (now - r.checked_at) / 86_400),
                    ..r.clone()
                },
                None => AssertionResult {
                    id: a.id.clone(),
                    holds: a.holds.clone(),
                    verdict: Verdict::Unknown,
                    observed: "never read".into(),
                    checked_at: 0,
                    fix: None,
                },
            };
            // The manifest's of today, said while it does not hold.
            AssertionResult {
                fix: a.fix.filter(|_| r.verdict == Verdict::Broken),
                ..r
            }
        })
        .collect()
}

/// What the inbox says: an app with a door open, and one whose doors were not looked at.
pub async fn findings(state: &State, now: i64) -> Vec<Finding> {
    let mut out = Vec::new();
    for (app, _) in state.installed_apps().await.unwrap_or_default() {
        let all = of_app(state, &app, now).await;
        // The attention is the reading's own, decided once in `hlb-api`.
        for (verdict, cause) in [
            (Verdict::Broken, Cause::AssertionBroken),
            (Verdict::Unknown, Cause::AssertionUnknown),
        ] {
            if let Some(attention) = all
                .iter()
                .filter(|r| r.verdict == verdict)
                .map(AssertionResult::attention)
                .max()
            {
                out.push((cause, attention, Some(app.clone())));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hlb_api::Attention;
    use hlb_privd::daemon::assertions::read_every_app;
    use hlb_types::DbEngine;

    struct Termix {
        registration_open: bool,
    }

    #[async_trait]
    impl hlb_guide::assertions::Reader for Termix {
        async fn post(
            &self,
            _: &str,
            _: &[(String, String)],
            _: Option<(&str, &str)>,
            _: &str,
            _: &str,
        ) -> Result<(u16, String), String> {
            Err("nothing signs in here".into())
        }
        async fn get(&self, _: &str, _: Option<&str>) -> Result<(u16, String), String> {
            Ok((200, format!(r#"{{"allowed":{}}}"#, self.registration_open)))
        }
        async fn task_env(&self, _: &str) -> Result<Option<Vec<String>>, String> {
            Err("no Swarm".into())
        }
        async fn sql(&self, _: DbEngine, _: &str, _: &str) -> Result<Option<String>, String> {
            Err("no database".into())
        }
    }

    async fn installed() -> State {
        let s = State::in_memory().await.expect("state");
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            r#"
apiVersion: hlb/v1
kind: App
metadata: { name: termix }
spec:
  image: { repo: termix, tag: "1" }
  ingress: [{ host: t.example.org, port: 8080 }]
  assertions:
    - id: registration
      holds: nobody signs up
      check: { type: http, path: /users/registration-allowed, pointer: /allowed, equals: false }
"#,
        )
        .expect("manifest");
        s.upsert_app("termix", &m, None).await.expect("app");
        s
    }

    #[tokio::test]
    async fn a_door_never_read_is_unknown_and_an_open_one_is_critical() {
        let s = installed().await;
        assert_eq!(
            findings(&s, 1_000).await,
            vec![(
                Cause::AssertionUnknown,
                Attention::Notice,
                Some("termix".into())
            )]
        );

        let pass = read_every_app(
            &s,
            None,
            &Termix {
                registration_open: true,
            },
            1_000,
        )
        .await;
        assert_eq!(pass.broken, ["termix: nobody signs up — /allowed is true"]);
        assert_eq!(
            findings(&s, 1_000).await,
            vec![(
                Cause::AssertionBroken,
                Attention::Critical,
                Some("termix".into())
            )]
        );

        read_every_app(
            &s,
            None,
            &Termix {
                registration_open: false,
            },
            1_000,
        )
        .await;
        assert!(findings(&s, 1_000).await.is_empty());
    }

    #[tokio::test]
    async fn a_reading_from_before_the_pass_stopped_says_nothing_about_tonight() {
        let s = installed().await;
        read_every_app(
            &s,
            None,
            &Termix {
                registration_open: false,
            },
            1_000,
        )
        .await;
        let later = 1_000 + STALE_AFTER_S + 86_400;
        let [r] = of_app(&s, "termix", later).await.try_into().expect("one");
        assert_eq!(r.verdict, Verdict::Unknown);
        assert_eq!(r.observed, "not read for 3 days");
    }

    /// Jellyfin, refusing or accepting its administrator's sign-in.
    struct Jellyfin {
        accepts: bool,
    }

    #[async_trait]
    impl hlb_guide::assertions::Reader for Jellyfin {
        async fn post(
            &self,
            _: &str,
            _: &[(String, String)],
            _: Option<(&str, &str)>,
            _: &str,
            body: &str,
        ) -> Result<(u16, String), String> {
            assert!(body.contains("from-the-vault"), "{body}");
            Ok(if self.accepts {
                (200, r#"{"AccessToken":"t"}"#.into())
            } else {
                (401, String::new())
            })
        }
        async fn get(&self, _: &str, _: Option<&str>) -> Result<(u16, String), String> {
            Err("no".into())
        }
        async fn task_env(&self, _: &str) -> Result<Option<Vec<String>>, String> {
            Err("no Swarm".into())
        }
        async fn sql(&self, _: DbEngine, _: &str, _: &str) -> Result<Option<String>, String> {
            Err("no database".into())
        }
    }

    #[tokio::test]
    async fn a_recovery_sign_in_refused_is_in_the_inbox_with_its_fix_and_never_retried_at_night() {
        let s = State::in_memory().await.expect("state");
        let dir = tempfile::tempdir().expect("tmp");
        let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            r#"
apiVersion: hlb/v1
kind: App
metadata: { name: jellyfin }
spec:
  image: { repo: jellyfin, tag: "1" }
  ingress: [{ host: j.example.org, port: 8096 }]
  recovery:
    - secret: admin-password
      username: admin
      proof:
        path: /Users/AuthenticateByName
        body: '{"Username":"{{ username }}","Pw":"{{ password }}"}'
        pointer: /AccessToken
"#,
        )
        .expect("manifest");
        s.upsert_app("jellyfin", &m, None).await.expect("app");

        // No vault, or no secret in it: not looked at, never "refused".
        read_every_app(&s, None, &Jellyfin { accepts: false }, 1_000).await;
        read_every_app(&s, Some(&vault), &Jellyfin { accepts: false }, 1_000).await;
        let [r] = of_app(&s, "jellyfin", 1_000).await.try_into().expect("one");
        assert_eq!(
            (r.verdict, r.fix),
            (Verdict::Unknown, None),
            "{}",
            r.observed
        );

        let secret = vault.encrypt("from-the-vault").expect("encrypt");
        s.store_secret_if_absent("jellyfin-admin-password", &secret, "admin")
            .await
            .expect("secret");
        let pass = read_every_app(&s, Some(&vault), &Jellyfin { accepts: false }, 2_000).await;
        assert_eq!(pass.broken.len(), 1, "{:?}", pass.broken);
        let [r] = of_app(&s, "jellyfin", 2_000).await.try_into().expect("one");
        assert_eq!(r.id, "recovery:admin-password");
        assert_eq!(r.verdict, Verdict::Broken);
        assert!(
            r.fix
                .as_deref()
                .is_some_and(|f| f.contains("hlb secret-get jellyfin-admin-password")),
            "{:?}",
            r.fix
        );
        assert_eq!(
            findings(&s, 2_000).await,
            vec![(
                Cause::AssertionBroken,
                Attention::Critical,
                Some("jellyfin".into())
            )]
        );

        // Mended in the app: the night does not find out — a person's `hlb assert` does.
        read_every_app(&s, Some(&vault), &Jellyfin { accepts: true }, 3_000).await;
        let [r] = of_app(&s, "jellyfin", 3_000).await.try_into().expect("one");
        assert_eq!(r.verdict, Verdict::Broken, "tried again at night");
        assert!(
            r.observed.contains("`hlb assert jellyfin` tries again"),
            "{}",
            r.observed
        );
    }
}
