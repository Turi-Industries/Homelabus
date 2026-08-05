//! Le pont entre le moteur de sauvegarde et le pipeline de mise à jour (§7).
//!
//! `hlb-updater` refuse toute mise à jour qui exige une sauvegarde tant qu'aucun
//! fournisseur n'est branché. Ce module est ce qui lève ce refus — et seulement quand
//! la sauvegarde a **réellement** abouti.

use crate::restic::{Repository, Runner};

/// Adapte un dépôt restic au trait attendu par le pipeline de mise à jour.
pub struct ResticBackupProvider<R: Runner> {
    repo: Repository<R>,
    /// Où trouver les données d'une app. En production, fourni par l'agent qui connaît
    /// les points de montage réels des volumes.
    resolve_path: Box<dyn Fn(&str) -> String + Send + Sync>,
}

impl<R: Runner> ResticBackupProvider<R> {
    pub fn new(
        repo: Repository<R>,
        resolve_path: impl Fn(&str) -> String + Send + Sync + 'static,
    ) -> Self {
        Self {
            repo,
            resolve_path: Box::new(resolve_path),
        }
    }
}

#[async_trait::async_trait]
impl<R: Runner> hlb_updater::BackupProvider for ResticBackupProvider<R> {
    async fn snapshot(&self, app: &str) -> std::result::Result<String, String> {
        let path = (self.resolve_path)(app);
        let tag = format!("app:{app}");

        // Une erreur ici doit remonter telle quelle : le pipeline ne doit surtout pas
        // poursuivre en croyant la sauvegarde faite.
        self.repo
            .backup(&path, &[&tag, "kind:pre-update"])
            .await
            .map_err(|e| e.to_string())
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
        async fn run(
            &self,
            _: &[String],
            _: &[(String, String)],
        ) -> crate::Result<Output> {
            Ok(self.0.lock().expect("mutex")[0].clone())
        }
    }

    fn provider(stdout: &str, status: i32) -> ResticBackupProvider<Fake> {
        let f = Fake(Mutex::new(vec![Output {
            status,
            stdout: stdout.into(),
            stderr: "échec simulé".into(),
        }]));
        ResticBackupProvider::new(
            Repository::new(f, "/depot", "mdp"),
            |app| format!("/volumes/{app}"),
        )
    }

    #[tokio::test]
    async fn a_successful_snapshot_returns_its_id() {
        let p = provider(r#"{"message_type":"summary","snapshot_id":"abc123"}"#, 0);
        assert_eq!(p.snapshot("gitea").await.expect("instantané"), "abc123");
    }

    #[tokio::test]
    async fn a_failed_snapshot_surfaces_the_error() {
        // 🔴 Le pipeline doit s'arrêter net : poursuivre reviendrait à mettre à jour
        // sans la sauvegarde promise.
        let p = provider("", 1);
        let err = p.snapshot("gitea").await.unwrap_err();
        assert!(err.contains("échec simulé"), "{err}");
    }

    // Le trait doit rester utilisable derrière un objet-trait.
    #[allow(dead_code)]
    fn is_object_safe(_: &dyn BackupProvider) {}
}
