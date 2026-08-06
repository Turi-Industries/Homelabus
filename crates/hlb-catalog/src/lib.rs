//! Chargement et validation du catalogue.
//!
//! Un catalogue = un dossier de dossiers, un par app, chacun avec son `manifest.yaml`.
//! **Ajouter une app = ajouter un dossier. Aucune recompilation** (§1).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hlb_types::Manifest;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("catalogue introuvable : {0}")]
    NotFound(PathBuf),

    #[error("lecture de {path} : {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{path} : {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: hlb_types::Error,
    },

    #[error("{path} : le nom déclaré « {declared} » ne correspond pas au dossier « {dir} »")]
    NameMismatch {
        path: PathBuf,
        declared: String,
        dir: String,
    },

    #[error("app « {0} » absente du catalogue")]
    UnknownApp(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Default)]
pub struct Catalog {
    entries: BTreeMap<String, Entry>,
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub manifest: Manifest,
    pub path: PathBuf,
    /// Le `guide.yaml` voisin, s'il existe (§4.6). Une app sans guide n'en a
    /// simplement aucun — ce n'est pas une erreur.
    pub guide: hlb_types::Guide,
}

impl Catalog {
    /// Charge récursivement tous les `manifest.yaml` sous `root`.
    ///
    /// Les dossiers commençant par `_` (comme `_platform`) sont parcourus mais ne sont
    /// pas des apps eux-mêmes — ils regroupent, ils ne déclarent pas.
    pub fn load(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        if !root.is_dir() {
            return Err(Error::NotFound(root.to_path_buf()));
        }

        let mut entries = BTreeMap::new();
        collect(root, &mut entries)?;
        Ok(Self { entries })
    }

    pub fn get(&self, name: &str) -> Result<&Entry> {
        self.entries
            .get(name)
            .ok_or_else(|| Error::UnknownApp(name.to_string()))
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(|s| s.as_str())
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    pub fn manifests(&self) -> Vec<Manifest> {
        self.entries.values().map(|e| e.manifest.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Valide chaque manifest et renvoie **toutes** les erreurs, pas seulement la
    /// première : quand on répare un catalogue, on veut la liste complète.
    pub fn validate_all(&self) -> Vec<(String, hlb_types::Error)> {
        self.entries
            .iter()
            .filter_map(|(name, e)| {
                hlb_types::validate(&e.manifest)
                    .err()
                    .map(|err| (name.clone(), err))
            })
            .collect()
    }
}

fn collect(dir: &Path, out: &mut BTreeMap<String, Entry>) -> Result<()> {
    let rd = std::fs::read_dir(dir).map_err(|source| Error::Io {
        path: dir.to_path_buf(),
        source,
    })?;

    for entry in rd {
        let entry = entry.map_err(|source| Error::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();

        if path.is_dir() {
            collect(&path, out)?;
            continue;
        }

        if path.file_name().is_some_and(|f| f == "manifest.yaml") {
            let e = load_one(&path)?;
            out.insert(e.manifest.metadata.name.clone(), e);
        }
    }
    Ok(())
}

fn load_one(path: &Path) -> Result<Entry> {
    let raw = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let manifest: Manifest =
        serde_yaml_ng::from_str(&raw).map_err(|e| Error::Parse {
            path: path.to_path_buf(),
            source: hlb_types::Error::Parse(e),
        })?;

    // Le nom du dossier fait foi : sans ça, deux apps peuvent se marcher dessus
    // silencieusement en déclarant le même `metadata.name`.
    let dir = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();

    if dir != manifest.metadata.name {
        return Err(Error::NameMismatch {
            path: path.to_path_buf(),
            declared: manifest.metadata.name.clone(),
            dir,
        });
    }

    // Le guide vit à côté du manifest. Absent = pas d'étape déclarée.
    let guide_path = path.with_file_name("guide.yaml");
    let guide = if guide_path.exists() {
        let raw = std::fs::read_to_string(&guide_path).map_err(|source| Error::Io {
            path: guide_path.clone(),
            source,
        })?;
        serde_yaml_ng::from_str(&raw).map_err(|e| Error::Parse {
            path: guide_path,
            source: hlb_types::Error::Parse(e),
        })?
    } else {
        hlb_types::Guide::default()
    };

    Ok(Entry {
        manifest,
        path: path.to_path_buf(),
        guide,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_catalog() -> PathBuf {
        // CARGO_MANIFEST_DIR = crates/hlb-catalog
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("catalog")
    }

    #[test]
    fn loads_the_bundled_catalog() {
        let c = Catalog::load(repo_catalog()).expect("catalogue chargeable");
        assert!(c.len() >= 6, "{} entrées trouvées", c.len());
        for expected in ["postgres", "valkey", "pocket-id", "gitea", "vikunja", "vaultwarden"] {
            assert!(c.get(expected).is_ok(), "{expected} manquant");
        }
    }

    #[test]
    fn bundled_catalog_is_valid() {
        let c = Catalog::load(repo_catalog()).expect("catalogue chargeable");
        let errs = c.validate_all();
        assert!(errs.is_empty(), "manifests invalides : {errs:?}");
    }

    #[test]
    fn bundled_catalog_has_no_dependency_cycle() {
        let c = Catalog::load(repo_catalog()).expect("catalogue chargeable");
        let g = hlb_resolver::DependencyGraph::from_manifests(&c.manifests());
        let order = g.deployment_order().expect("ordre calculable");

        let pos = |n: &str| order.iter().position(|x| x == n).expect("présent");
        // Les services de plateforme doivent précéder leurs consommateurs.
        assert!(pos("postgres") < pos("gitea"));
        assert!(pos("pocket-id") < pos("vaultwarden"));
    }

    #[test]
    fn vaultwarden_is_never_auto_updated() {
        // §5.7bis — c'est l'accès de secours à tout le reste.
        let c = Catalog::load(repo_catalog()).expect("catalogue chargeable");
        let vw = c.get("vaultwarden").expect("vaultwarden présent");
        assert_eq!(
            vw.manifest.spec.update.channel,
            hlb_types::UpdateChannel::Pin
        );
    }

    #[test]
    fn guides_are_loaded_alongside_manifests() {
        let c = Catalog::load(repo_catalog()).expect("catalogue chargeable");
        let gitea = c.get("gitea").expect("gitea présent");
        assert!(
            !gitea.guide.steps.is_empty(),
            "gitea devrait déclarer ses étapes manuelles"
        );
    }

    #[test]
    fn an_app_without_a_guide_is_fine() {
        let c = Catalog::load(repo_catalog()).expect("catalogue chargeable");
        // valkey n'a rien à faire faire à la main.
        assert!(c.get("valkey").expect("présent").guide.steps.is_empty());
    }

    #[test]
    fn every_guide_step_has_a_unique_id() {
        // Deux étapes de même identifiant s'écraseraient dans la file (§4.6).
        let c = Catalog::load(repo_catalog()).expect("catalogue chargeable");
        for e in c.entries() {
            let mut vus = std::collections::BTreeSet::new();
            for s in &e.guide.steps {
                assert!(
                    vus.insert(&s.id),
                    "{} : identifiant « {} » en double",
                    e.manifest.metadata.name,
                    s.id
                );
            }
        }
    }

    #[test]
    fn guide_dependencies_point_to_existing_steps() {
        let c = Catalog::load(repo_catalog()).expect("catalogue chargeable");
        for e in c.entries() {
            let ids: std::collections::BTreeSet<_> =
                e.guide.steps.iter().map(|s| s.id.as_str()).collect();
            for s in &e.guide.steps {
                for dep in &s.after {
                    assert!(
                        ids.contains(dep.as_str()),
                        "{} : « {} » dépend de « {dep} », qui n'existe pas",
                        e.manifest.metadata.name,
                        s.id
                    );
                }
            }
        }
    }

    #[test]
    fn missing_catalog_is_reported_clearly() {
        let err = Catalog::load("/nexiste/pas").unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "{err}");
    }
}
