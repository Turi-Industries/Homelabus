//! Miroir Git de l'état désiré (§2.3).
//!
//! Chaque changement est rendu en YAML et commité. Ça donne gratuitement :
//!
//! - un **historique lisible** de toute la configuration, avec des diffs ;
//! - un **rollback** (`git revert`, puis réapplication) ;
//! - une **sauvegarde de la config indépendante du système lui-même** — si la base
//!   d'état est perdue, le dépôt suffit à reconstruire (§9quater).
//!
//! 🔴 **La base reste la source de vérité, le Git en est un miroir.**
//!
//! L'inverse — lire le Git comme source — obligerait à gérer les conflits, les
//! pushs concurrents, la réconciliation à trois voies… autrement dit à
//! réimplémenter ArgoCD. Le plan est explicite là-dessus : on veut l'historique,
//! pas le modèle GitOps complet.

use std::path::{Path, PathBuf};

use git2::{Repository, Signature};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("dépôt git : {0}")]
    Git(#[from] git2::Error),

    #[error("écriture de {path} : {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("sérialisation du manifest de « {app} » : {source}")]
    Serialize {
        app: String,
        #[source]
        source: serde_yaml_ng::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Ce qu'un export a produit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportReport {
    /// `None` si rien n'avait changé — on ne crée pas de commit vide.
    pub commit: Option<String>,
    pub written: Vec<String>,
    pub removed: Vec<String>,
}

impl ExportReport {
    pub fn changed(&self) -> bool {
        self.commit.is_some()
    }
}

pub struct GitMirror {
    repo: Repository,
    root: PathBuf,
}

impl GitMirror {
    /// Ouvre le dépôt, ou l'initialise s'il n'existe pas.
    pub fn open_or_init(path: impl AsRef<Path>) -> Result<Self> {
        let root = path.as_ref().to_path_buf();
        let repo = match Repository::open(&root) {
            Ok(r) => r,
            Err(_) => {
                std::fs::create_dir_all(&root).map_err(|source| Error::Io {
                    path: root.clone(),
                    source,
                })?;
                Repository::init(&root)?
            }
        };
        Ok(Self { repo, root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Écrit l'état désiré et commite ce qui a changé.
    ///
    /// `apps` porte, pour chaque app, son manifest **figé au déploiement** (§4.8) et
    /// son statut. C'est bien l'état déployé qu'on archive, pas le catalogue courant.
    pub fn export(
        &self,
        apps: &[(String, String, hlb_types::Manifest)],
        message: &str,
    ) -> Result<ExportReport> {
        let dossier = self.root.join("apps");
        std::fs::create_dir_all(&dossier).map_err(|source| Error::Io {
            path: dossier.clone(),
            source,
        })?;

        let mut written = Vec::new();
        let mut attendus = std::collections::BTreeSet::new();

        for (name, status, manifest) in apps {
            let fichier = dossier.join(format!("{name}.yaml"));
            attendus.insert(format!("{name}.yaml"));

            let yaml = serde_yaml_ng::to_string(manifest).map_err(|source| Error::Serialize {
                app: name.clone(),
                source,
            })?;

            // L'en-tête porte ce qui ne tient pas dans le manifest : le statut, et le
            // rappel que ce fichier est généré.
            let contenu = format!(
                "# Généré par HomelabUS — état déployé, ne pas éditer à la main.\n\
                 # app: {name}\n# statut: {status}\n\n{yaml}"
            );

            // Ne réécrire que si le contenu change : sinon chaque export produirait
            // un commit, et l'historique deviendrait illisible.
            let identique = std::fs::read_to_string(&fichier)
                .map(|ancien| ancien == contenu)
                .unwrap_or(false);

            if !identique {
                std::fs::write(&fichier, &contenu).map_err(|source| Error::Io {
                    path: fichier.clone(),
                    source,
                })?;
                written.push(name.clone());
            }
        }

        // Les apps désinstallées disparaissent du miroir — mais restent dans
        // l'historique, ce qui est précisément l'intérêt.
        let mut removed = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&dossier) {
            for e in entries.flatten() {
                let nom = e.file_name().to_string_lossy().to_string();
                if nom.ends_with(".yaml") && !attendus.contains(&nom) {
                    let _ = std::fs::remove_file(e.path());
                    removed.push(nom.trim_end_matches(".yaml").to_string());
                }
            }
        }

        let commit = self.commit_all(message)?;
        Ok(ExportReport {
            commit,
            written,
            removed,
        })
    }

    /// Indexe tout et commite, ou ne fait rien s'il n'y a aucun changement.
    fn commit_all(&self, message: &str) -> Result<Option<String>> {
        let mut index = self.repo.index()?;
        index.add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)?;
        // `add_all` n'enlève pas les fichiers supprimés : il faut le demander.
        index.update_all(["*"].iter(), None)?;
        index.write()?;

        let tree_id = index.write_tree()?;
        let tree = self.repo.find_tree(tree_id)?;

        let parent = self
            .repo
            .head()
            .ok()
            .and_then(|h| h.target())
            .and_then(|oid| self.repo.find_commit(oid).ok());

        // Rien n'a bougé : pas de commit vide, l'historique doit rester lisible.
        if let Some(p) = &parent {
            if p.tree_id() == tree_id {
                return Ok(None);
            }
        }

        let sig = Signature::now("HomelabUS", "homelabus@localhost")?;
        let parents: Vec<&git2::Commit> = parent.iter().collect();

        let oid = self
            .repo
            .commit(Some("HEAD"), &sig, &sig, message, &tree, &parents)?;
        Ok(Some(oid.to_string()))
    }

    /// Les versions successives du manifest d'une app, du plus récent au plus ancien.
    ///
    /// ## 🔴 Pourquoi ça se lit ICI et nulle part ailleurs
    ///
    /// `apps.manifest` est ÉCRASÉ à chaque mise à jour : l'état ne garde que la
    /// version courante. Répondre à « qu'est-ce qui a changé quand l'app a cessé de
    /// marcher ? » exigerait donc de stocker un historique de plus — alors que le
    /// miroir Git en tient déjà un, complet et daté.
    ///
    /// Rend `(commit court, résumé, contenu YAML)`. Une version qui ne se relit pas est
    /// **sautée** plutôt que rendue vide : un YAML vide se lit comme « le manifest ne
    /// contenait rien », soit un changement énorme qui n'a jamais eu lieu.
    pub fn versions(&self, app: &str, limite: usize) -> Result<Vec<(String, String, String)>> {
        let chemin = format!("apps/{app}.yaml");
        let mut walk = self.repo.revwalk()?;
        if walk.push_head().is_err() {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        let mut precedent: Option<String> = None;

        for oid in walk {
            if out.len() >= limite {
                break;
            }
            let commit = self.repo.find_commit(oid?)?;
            let Ok(arbre) = commit.tree() else { continue };
            let Ok(entree) = arbre.get_path(std::path::Path::new(&chemin)) else {
                continue;
            };
            let Ok(objet) = entree.to_object(&self.repo) else {
                continue;
            };
            let Some(blob) = objet.as_blob() else { continue };
            let Ok(contenu) = std::str::from_utf8(blob.content()) else {
                continue;
            };

            // ⚠️ Un commit qui ne touche PAS cette app porte quand même son fichier,
            // inchangé. Les rendre tous donnerait vingt « versions » identiques, et le
            // vrai changement se perdrait au milieu.
            if precedent.as_deref() == Some(contenu) {
                continue;
            }
            precedent = Some(contenu.to_string());

            out.push((
                commit.id().to_string()[..8].to_string(),
                commit.summary().unwrap_or("").to_string(),
                contenu.to_string(),
            ));
        }
        Ok(out)
    }

    /// L'historique récent, pour `hlb history`.
    pub fn history(&self, limit: usize) -> Result<Vec<(String, String)>> {
        let mut walk = self.repo.revwalk()?;
        if walk.push_head().is_err() {
            // Dépôt vide : pas d'historique, ce n'est pas une erreur.
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        for oid in walk.take(limit) {
            let c = self.repo.find_commit(oid?)?;
            out.push((
                c.id().to_string()[..8].to_string(),
                c.summary().unwrap_or("").to_string(),
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_the_versions_that_actually_changed_are_returned() {
        // 🔴 Le piège : un commit qui ne touche pas cette app porte QUAND MÊME son
        // fichier, inchangé. Rendre tous les commits donnerait vingt « versions »
        // identiques, et le seul vrai changement se perdrait au milieu.
        let tmp = tempfile::tempdir().expect("dossier");
        let m = GitMirror::open_or_init(tmp.path()).expect("miroir");

        m.export(
            &[("gitea".into(), "running".into(), manifest("gitea", "1.23"))],
            "installation",
        )
        .expect("export 1");

        // Un commit qui ne concerne QUE l'autre app.
        m.export(
            &[
                ("gitea".into(), "running".into(), manifest("gitea", "1.23")),
                ("immich".into(), "running".into(), manifest("immich", "1.0")),
            ],
            "ajout d'immich",
        )
        .expect("export 2");

        m.export(
            &[
                ("gitea".into(), "running".into(), manifest("gitea", "1.24")),
                ("immich".into(), "running".into(), manifest("immich", "1.0")),
            ],
            "mise à jour de gitea",
        )
        .expect("export 3");

        let v = m.versions("gitea", 10).expect("versions");
        assert_eq!(v.len(), 2, "deux contenus distincts, pas trois commits : {v:#?}");
        assert!(v[0].2.contains("1.24"), "le plus récent d'abord");
        assert!(v[1].2.contains("1.23"));
    }

    #[test]
    fn an_app_that_was_never_exported_has_no_history_and_no_error() {
        // Une app absente n'est pas une erreur : elle n'a simplement pas d'historique.
        let tmp = tempfile::tempdir().expect("dossier");
        let m = GitMirror::open_or_init(tmp.path()).expect("miroir");
        m.export(
            &[("gitea".into(), "running".into(), manifest("gitea", "1"))],
            "installation",
        )
        .expect("export");

        assert!(m.versions("inexistante", 10).expect("versions").is_empty());
    }

    #[test]
    fn an_empty_mirror_is_not_an_error_either() {
        let tmp = tempfile::tempdir().expect("dossier");
        let m = GitMirror::open_or_init(tmp.path()).expect("miroir");
        assert!(m.versions("gitea", 10).expect("versions").is_empty());
    }

    use super::*;

    fn manifest(name: &str, tag: &str) -> hlb_types::Manifest {
        let y = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {name} }}\n\
             spec:\n  image: {{ repo: a/b, tag: \"{tag}\" }}\n"
        );
        serde_yaml_ng::from_str(&y).expect("manifest de test")
    }

    fn mirror() -> (tempfile::TempDir, GitMirror) {
        let d = tempfile::tempdir().expect("dossier temporaire");
        let m = GitMirror::open_or_init(d.path()).expect("dépôt");
        (d, m)
    }

    #[test]
    fn an_export_creates_a_commit() {
        let (_d, m) = mirror();
        let apps = vec![("gitea".into(), "running".into(), manifest("gitea", "1.24"))];

        let r = m.export(&apps, "installation de gitea").expect("export");
        assert!(r.changed());
        assert_eq!(r.written, vec!["gitea"]);
        assert!(m.root().join("apps/gitea.yaml").exists());
    }

    #[test]
    fn nothing_changed_means_no_commit() {
        // 🔴 Sinon chaque passage de la boucle de réconciliation produirait un
        // commit, et l'historique deviendrait inexploitable.
        let (_d, m) = mirror();
        let apps = vec![("gitea".into(), "running".into(), manifest("gitea", "1.24"))];

        m.export(&apps, "premier").expect("export");
        let second = m.export(&apps, "second").expect("export");

        assert!(!second.changed(), "aucun commit ne devait être créé");
        assert_eq!(m.history(10).expect("historique").len(), 1);
    }

    #[test]
    fn a_changed_manifest_produces_a_new_commit() {
        let (_d, m) = mirror();
        m.export(
            &[("gitea".into(), "running".into(), manifest("gitea", "1.24"))],
            "v1",
        )
        .expect("export");

        let r = m
            .export(
                &[("gitea".into(), "running".into(), manifest("gitea", "1.25"))],
                "montée en 1.25",
            )
            .expect("export");

        assert!(r.changed());
        let h = m.history(10).expect("historique");
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].1, "montée en 1.25", "le plus récent d'abord");
    }

    #[test]
    fn an_uninstalled_app_leaves_the_mirror_but_stays_in_history() {
        let (_d, m) = mirror();
        m.export(
            &[
                ("gitea".into(), "running".into(), manifest("gitea", "1.24")),
                ("vikunja".into(), "running".into(), manifest("vikunja", "0.24")),
            ],
            "deux apps",
        )
        .expect("export");

        let r = m
            .export(
                &[("gitea".into(), "running".into(), manifest("gitea", "1.24"))],
                "désinstallation de vikunja",
            )
            .expect("export");

        assert_eq!(r.removed, vec!["vikunja"]);
        assert!(!m.root().join("apps/vikunja.yaml").exists());
        // Mais l'historique la conserve : c'est tout l'intérêt du miroir.
        assert_eq!(m.history(10).expect("historique").len(), 2);
    }

    #[test]
    fn the_written_file_is_readable_and_flagged_as_generated() {
        let (_d, m) = mirror();
        m.export(
            &[("gitea".into(), "running".into(), manifest("gitea", "1.24"))],
            "x",
        )
        .expect("export");

        let c = std::fs::read_to_string(m.root().join("apps/gitea.yaml")).expect("lecture");
        assert!(c.contains("ne pas éditer à la main"));
        assert!(c.contains("statut: running"));
        // Et le manifest doit rester relisible malgré l'en-tête.
        let relu: hlb_types::Manifest = serde_yaml_ng::from_str(&c).expect("relisible");
        assert_eq!(relu.metadata.name, "gitea");
    }

    #[test]
    fn an_empty_repository_has_no_history() {
        let (_d, m) = mirror();
        assert!(m.history(10).expect("historique").is_empty());
    }

    #[test]
    fn opening_an_existing_repository_keeps_its_history() {
        let d = tempfile::tempdir().expect("dossier");
        {
            let m = GitMirror::open_or_init(d.path()).expect("dépôt");
            m.export(
                &[("gitea".into(), "running".into(), manifest("gitea", "1.24"))],
                "premier",
            )
            .expect("export");
        }
        let m = GitMirror::open_or_init(d.path()).expect("réouverture");
        assert_eq!(m.history(10).expect("historique").len(), 1);
    }
}
