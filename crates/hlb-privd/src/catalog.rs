//! The catalog the daemon and the web side read: the official one and its sources.

use hlb_catalog::Catalog;
use hlb_state::State;

/// The official catalog in `dir` and the third-party sources the state names.
///
/// ⚠️ Read once, at startup: a source added since is read by the next start. An
/// unreadable source is said and left out — the official apps never go with it — and
/// an unreadable official catalog is the caller's to say, as before.
pub async fn load(dir: &std::path::Path, state: &State) -> hlb_catalog::Result<Catalog> {
    let mut c = Catalog::load(dir)?;
    let sources = match state.catalog_sources().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("catalog sources unreadable ({e}) — the official catalog alone");
            Vec::new()
        }
    };
    for (name, directory) in sources {
        match c.add_source(&name, &directory) {
            Ok(()) => tracing::info!(source = %name, %directory, "catalog source loaded"),
            Err(e) => tracing::warn!(source = %name, %directory, "catalog source left out: {e}"),
        }
    }
    Ok(c)
}
