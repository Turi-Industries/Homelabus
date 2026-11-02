//! The catalog the daemon and the web side read: the official one and its sources.

use std::sync::{Arc, RwLock};

use hlb_catalog::Catalog;
use hlb_state::State;

/// The catalog read last, shared by every reader of one process and replaced whole
/// when it is read again — a reader holds the one it took for as long as it needs it.
///
/// 🔴 Read once at startup, a source added since, a fetched index or a revocation was
/// heard by nobody until a restart, and an index expired under a process that never
/// read the fresh one.
#[derive(Clone, Default)]
pub struct SharedCatalog(Arc<RwLock<Option<Arc<Catalog>>>>);

impl SharedCatalog {
    pub fn new(c: Option<Arc<Catalog>>) -> Self {
        Self(Arc::new(RwLock::new(c)))
    }

    /// `None`: no catalog could be read yet.
    pub fn get(&self) -> Option<Arc<Catalog>> {
        // A writer that panicked left a whole catalog or the previous one: either reads.
        self.0.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set(&self, c: Arc<Catalog>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = Some(c);
    }

    /// Reads `dir` and the state's sources again. An official catalog unreadable now
    /// keeps the one read before: a half-written checkout must not empty the screens.
    pub async fn reload(&self, dir: &std::path::Path, state: &State) {
        match load(dir, state).await {
            Ok(c) => self.set(Arc::new(c)),
            Err(e) => tracing::warn!(
                directory = %dir.display(),
                "catalog unreadable ({e}) — the one read before is kept"
            ),
        }
    }
}

/// How often a process reads its catalog again: a source added, fetched or removed by
/// `hlb catalog source` reaches the interface within this.
pub const RELOAD_SECS: u64 = 600;

/// The official catalog in `dir` and the third-party sources the state names.
///
/// An unreadable source is said and left out — the official apps never go with it —
/// and an unreadable official catalog is the caller's to say.
pub async fn load(dir: &std::path::Path, state: &State) -> hlb_catalog::Result<Catalog> {
    let mut c = Catalog::load(dir)?;
    let sources = match state.catalog_sources().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("catalog sources unreadable ({e}) — the official catalog alone");
            Vec::new()
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    for src in sources {
        let (name, directory) = (&src.name, &src.directory);
        // A fetched source is held to its key again, each time it is read.
        let added = match &src.signed {
            Some(signed) => c
                .add_signed_source(name, directory, &signed.key, now)
                .map_err(|e| e.to_string()),
            None => c.add_source(name, directory).map_err(|e| e.to_string()),
        };
        match added {
            Ok(()) => tracing::info!(source = %name, %directory, "catalog source loaded"),
            Err(e) => tracing::warn!(source = %name, %directory, "catalog source left out: {e}"),
        }
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn copy(app: &str, into: &std::path::Path) {
        let official = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
        let ok = std::process::Command::new("cp")
            .arg("-r")
            .arg(official.join(app))
            .arg(into)
            .status()
            .expect("cp")
            .success();
        assert!(ok);
    }

    #[tokio::test]
    async fn a_source_added_after_the_start_is_read_by_the_next_reload() {
        let official = tempfile::tempdir().expect("official");
        copy("mealie", official.path());
        let theirs = tempfile::tempdir().expect("theirs");
        copy("librespeed", theirs.path());
        let state = State::in_memory().await.expect("state");

        let shared = SharedCatalog::new(None);
        shared.reload(official.path(), &state).await;
        let first = shared.get().expect("read");
        assert!(first.get("community/librespeed").is_err());

        state
            .add_catalog_source(&hlb_state::CatalogSource {
                name: "community".into(),
                directory: theirs.path().display().to_string(),
                signed: None,
            })
            .await
            .expect("added");
        shared.reload(official.path(), &state).await;
        assert!(shared
            .get()
            .expect("read")
            .get("community/librespeed")
            .is_ok());
        // What a reader took before stays whole.
        assert!(first.get("community/librespeed").is_err());

        // The official catalog unreadable now: the one read before is kept.
        let gone = official.path().join("missing");
        shared.reload(&gone, &state).await;
        assert!(shared.get().expect("kept").get("mealie").is_ok());
    }
}
