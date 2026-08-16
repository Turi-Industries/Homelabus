//! Le pont entre le moteur de sauvegarde et le pipeline de mise à jour (§7).
//!
//! `hlb-updater` refuse toute mise à jour qui exige une sauvegarde tant qu'aucun
//! fournisseur n'est branché. Ce module est ce qui lève ce refus — et seulement quand
//! la sauvegarde a **réellement** abouti.

use crate::restic::{Repository, Runner};

/// Adapte un dépôt restic au trait attendu par le pipeline de mise à jour.
///
/// Le dépôt est construit **par app**, pas une fois pour toutes : chaque app a ses
/// propres volumes, et le runner doit pouvoir les rendre visibles à restic (montages
/// pour un conteneur, chemins directs pour l'agent). D'où une fabrique plutôt qu'un
/// dépôt figé.
pub struct ResticBackupProvider<R: Runner> {
    #[allow(clippy::type_complexity)]
    make: Box<dyn Fn(&str) -> Option<(Repository<R>, Vec<String>)> + Send + Sync>,
}

impl<R: Runner> ResticBackupProvider<R> {
    /// `make` renvoie le dépôt à utiliser et les chemins à sauvegarder pour une app,
    /// ou `None` si l'app n'a aucune donnée à sauvegarder.
    pub fn new(
        make: impl Fn(&str) -> Option<(Repository<R>, Vec<String>)> + Send + Sync + 'static,
    ) -> Self {
        Self { make: Box::new(make) }
    }

    /// Le dépôt et les chemins d'une app, pour les opérations qui ne sont pas des
    /// sauvegardes — la vérification par restauration (§8.3), au premier chef.
    ///
    /// Exposé plutôt que dupliqué : le `Repository` construit ici doit être
    /// **exactement** celui qui a écrit l'instantané. Un dépôt reconstruit à côté,
    /// avec un montage ou un mot de passe qui divergent d'un caractère, échouerait
    /// à lire ce qu'il vient pourtant d'écrire.
    pub fn repository_for(&self, app: &str) -> Option<(Repository<R>, Vec<String>)> {
        (self.make)(app)
    }
}

#[async_trait::async_trait]
impl<R: Runner> hlb_updater::BackupProvider for ResticBackupProvider<R> {
    async fn snapshot(&self, app: &str) -> std::result::Result<String, String> {
        let Some((repo, paths)) = (self.make)(app) else {
            // 🔴 Pas de « rien à sauvegarder, donc c'est bon ». Si le manifest exige
            // une sauvegarde et qu'on ne sait pas quoi sauvegarder, c'est une erreur.
            return Err(format!(
                "aucun volume connu pour « {app} » — impossible de garantir la sauvegarde"
            ));
        };

        repo.init().await.map_err(|e| e.to_string())?;

        let tag = format!("app:{app}");
        let mut last = String::new();
        for p in &paths {
            // Une erreur ici doit remonter telle quelle : le pipeline ne doit surtout
            // pas poursuivre en croyant la sauvegarde faite.
            last = repo
                .backup(p, &[&tag, "kind:pre-update"])
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(last)
    }
}

/// Construit un fournisseur pour toutes les apps ayant des volumes à sauvegarder.
///
/// Partagé entre le CLI et le controller : les deux doivent brancher restic
/// exactement de la même façon, sinon une sauvegarde faite par l'un ne serait pas
/// retrouvée par l'autre.
pub async fn provider_for_state(
    repo_location: &str,
    password: String,
    volumes_by_app: std::collections::BTreeMap<String, Vec<String>>,
) -> ResticBackupProvider<crate::ContainerRunner> {
    let location = repo_location.to_string();

    ResticBackupProvider::new(move |app| {
        let volumes = volumes_by_app.get(app)?;
        if volumes.is_empty() {
            return None;
        }

        let mut runner = crate::ContainerRunner::default().mount(&location, "/depot");
        let mut paths = Vec::new();
        for name in volumes {
            // Le volume est monté par son nom : le point de montage de l'hôte n'est
            // pas forcément accessible depuis là où tourne restic.
            runner = runner.mount(name, format!("/donnees/{name}"));
            paths.push(format!("/donnees/{name}"));
        }

        Some((
            Repository::new(runner, "/depot", password.clone()),
            paths,
        ))
    })
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
        let stdout = stdout.to_string();
        ResticBackupProvider::new(move |app| {
            let f = Fake(Mutex::new(vec![Output {
                status,
                stdout: stdout.clone(),
                stderr: "échec simulé".into(),
            }]));
            Some((
                Repository::new(f, "/depot", "mdp"),
                vec![format!("/volumes/{app}")],
            ))
        })
    }

    #[tokio::test]
    async fn a_successful_snapshot_returns_its_id() {
        let p = provider(r#"{"message_type":"summary","snapshot_id":"abc123"}"#, 0);
        assert_eq!(p.snapshot("gitea").await.expect("instantané"), "abc123");
    }

    #[tokio::test]
    async fn an_app_without_known_volumes_is_an_error() {
        // 🔴 « Rien à sauvegarder » ne doit jamais valoir « sauvegarde réussie ».
        let p: ResticBackupProvider<Fake> = ResticBackupProvider::new(|_| None);
        let err = p.snapshot("gitea").await.unwrap_err();
        assert!(err.contains("aucun volume connu"), "{err}");
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

