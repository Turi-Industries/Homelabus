//! The manifests' assertions, read from the running apps every night with the
//! vault's recovery passwords.

use hlb_api::assertions::{AssertionResult, Verdict};
use hlb_state::State;

/// What one pass found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pass {
    pub read: usize,
    pub broken: Vec<String>,
    pub unknown: usize,
}

/// Reads every installed app's assertions and records them — its recovery sign-ins
/// with the vault's passwords, a refusal kept rather than tried again.
pub async fn read_every_app(
    state: &State,
    vault: Option<&hlb_secrets::Vault>,
    reader: &dyn hlb_guide::assertions::Reader,
    now: i64,
) -> Pass {
    let mut pass = Pass::default();
    let last = state.assertion_results().await.unwrap_or_default();
    for (app, _) in state.installed_apps().await.unwrap_or_default() {
        let Ok(m) = state.app_manifest(&app).await else {
            continue;
        };
        let credentials = match vault {
            Some(v) => hlb_engine::emergency::credentials(state, v, &app, &m)
                .await
                .unwrap_or_else(|e| unread(&m, &format!("the vault was not read: {e}"))),
            None => unread(&m, "the vault is not open here"),
        };
        let last: Vec<AssertionResult> = last
            .iter()
            .filter(|(owner, _)| owner == &app)
            .map(|(_, r)| r.clone())
            .collect();
        let results = hlb_guide::assertions::read_all(
            reader,
            &m,
            &credentials,
            hlb_guide::assertions::Refused::Keep(&last),
            now,
        )
        .await;
        for r in &results {
            pass.read += 1;
            match r.verdict {
                Verdict::Holds => {}
                Verdict::Broken => pass
                    .broken
                    .push(format!("{app}: {} — {}", r.holds, r.observed)),
                Verdict::Unknown => pass.unknown += 1,
            }
        }
        if let Err(e) = state.record_assertions(&app, &results).await {
            tracing::error!(app, "assertions read and not recorded: {e}");
        }
    }
    pass
}

/// Every recovery sign-in of `m`, with why it could not be looked up.
fn unread(m: &hlb_types::Manifest, why: &str) -> Vec<hlb_guide::assertions::Credential> {
    m.spec
        .recovery
        .iter()
        .map(|r| hlb_guide::assertions::Credential {
            secret: r.secret.clone(),
            sign_in: Err(why.to_string()),
        })
        .collect()
}
