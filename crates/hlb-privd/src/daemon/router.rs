//! The house on its router, synced every night: an app installed since `hlb router
//! sync` last ran is answered inside the house too, and its ports forwarded.

use hlb_engine::router::Router;
use hlb_orchestrator::Orchestrator;
use hlb_secrets::Vault;
use hlb_state::State;

/// Syncs, recorded for the inbox (`Router::sync_recorded`). `None` with no router
/// connected — nothing to sync, nothing to say; otherwise what failed, one line each,
/// or nothing when it all held.
pub async fn sync(
    state: &State,
    vault: &Vault,
    orch: &(impl Orchestrator + ?Sized),
    catalog_dir: &std::path::Path,
    now: i64,
) -> Option<Option<String>> {
    match state.router().await {
        Ok(Some(_)) => {}
        Ok(None) => return None,
        Err(e) => {
            tracing::warn!("router not read: {e}");
            return None;
        }
    }
    // Today's catalog says which ports are the site's, whatever a manifest frozen
    // before says: unread, nothing is synced rather than a site's port forwarded.
    let catalog = match hlb_catalog::Catalog::load(catalog_dir) {
        Ok(c) => c,
        Err(e) => {
            return Some(Some(format!(
                "router sync skipped: unreadable catalog ({e})"
            )))
        }
    };
    let failed = match (Router { state, vault })
        .sync_recorded(orch, &catalog, now)
        .await
    {
        Ok(r) => r.failures(),
        Err(e) => Some(format!("router sync stopped: {e}")),
    };
    Some(failed)
}
