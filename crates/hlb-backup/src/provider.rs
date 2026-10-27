//! The bridge between the backup engine and the update pipeline.
//!
//! `hlb-updater` refuses any update requiring a backup as long as no provider is wired
//! in. This module is what lifts that refusal — and only when the backup has **really**
//! completed.

use crate::restic::{Repository, Runner};

/// Adapts a restic repository to the trait the update pipeline expects.
///
/// The repository is built **per app**, not once and for all: each app has its own
/// volumes, and the runner must be able to make them visible to restic (mounts for a
/// container, direct paths for the agent). Hence a factory rather than a frozen
/// repository.
pub struct ResticBackupProvider<R: Runner> {
    #[allow(clippy::type_complexity)]
    make: Box<dyn Fn(&str) -> Option<(Repository<R>, Vec<String>)> + Send + Sync>,
}

impl<R: Runner> ResticBackupProvider<R> {
    /// `make` returns the repository to use and the paths to back up for an app, or
    /// `None` if the app has no data to back up.
    pub fn new(
        make: impl Fn(&str) -> Option<(Repository<R>, Vec<String>)> + Send + Sync + 'static,
    ) -> Self {
        Self {
            make: Box::new(make),
        }
    }

    /// An app's repository and paths, for operations that are not backups — restore
    /// verification first and foremost.
    ///
    /// Exposed rather than duplicated: the `Repository` built here must be **exactly**
    /// the one that wrote the snapshot. A repository rebuilt alongside, with a mount or
    /// a password differing by one character, would fail to read back what it had just
    /// written.
    pub fn repository_for(&self, app: &str) -> Option<(Repository<R>, Vec<String>)> {
        (self.make)(app)
    }
}

#[async_trait::async_trait]
impl<R: Runner> hlb_updater::BackupProvider for ResticBackupProvider<R> {
    async fn snapshot(&self, app: &str) -> std::result::Result<String, String> {
        let Some((repo, paths)) = (self.make)(app) else {
            // 🔴 No "nothing to back up, so we are fine". If the manifest requires a
            // backup and we do not know what to back up, that is an error.
            return Err(format!(
                "no known volume for \"{app}\" — the backup cannot be guaranteed"
            ));
        };

        repo.init().await.map_err(|e| e.to_string())?;

        let tag = format!("app:{app}");
        let mut last = String::new();
        for p in &paths {
            // An error here must surface as is: the pipeline must above all not carry
            // on believing the backup was made.
            last = repo
                .backup(p, &[&tag, "kind:pre-update"])
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restic::Output;
    use hlb_updater::BackupProvider;
    use std::sync::Mutex;

    struct Fake(Mutex<Vec<Output>>);

    #[async_trait::async_trait]
    impl crate::restic::Runner for Fake {
        async fn run(&self, _: &[String], _: &[(String, String)]) -> crate::Result<Output> {
            Ok(self.0.lock().expect("mutex")[0].clone())
        }
    }

    fn provider(stdout: &str, status: i32) -> ResticBackupProvider<Fake> {
        let stdout = stdout.to_string();
        ResticBackupProvider::new(move |app| {
            let f = Fake(Mutex::new(vec![Output {
                status,
                stdout: stdout.clone(),
                stderr: "simulated failure".into(),
            }]));
            Some((
                Repository::new(f, "/repo", "test-password"),
                vec![format!("/volumes/{app}")],
            ))
        })
    }

    #[tokio::test]
    async fn a_successful_snapshot_returns_its_id() {
        let p = provider(r#"{"message_type":"summary","snapshot_id":"abc123"}"#, 0);
        assert_eq!(p.snapshot("gitea").await.expect("snapshot"), "abc123");
    }

    #[tokio::test]
    async fn an_app_without_known_volumes_is_an_error() {
        // 🔴 "Nothing to back up" must never count as "backup succeeded".
        let p: ResticBackupProvider<Fake> = ResticBackupProvider::new(|_| None);
        let err = p.snapshot("gitea").await.unwrap_err();
        assert!(err.contains("no known volume"), "{err}");
    }

    #[tokio::test]
    async fn a_failed_snapshot_surfaces_the_error() {
        // 🔴 The pipeline must stop dead: carrying on would mean updating without the
        // promised backup.
        let p = provider("", 1);
        let err = p.snapshot("gitea").await.unwrap_err();
        assert!(err.contains("simulated failure"), "{err}");
    }

    // The trait must stay usable behind a trait object.
    #[allow(dead_code)]
    fn is_object_safe(_: &dyn BackupProvider) {}
}
