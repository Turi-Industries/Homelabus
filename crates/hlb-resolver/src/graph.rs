//! Graphe de dépendances et ordre de déploiement (§4.7 du plan).
//!
//! Docker Swarm n'a **pas** d'équivalent à `depends_on` : il démarre tous les services
//! en parallèle. Une app qui démarre avant que PostgreSQL soit prêt plante, redémarre
//! en boucle, et selon l'app corrompt son initialisation.
//!
//! C'est donc à nous d'ordonner. Le graphe se déduit des `requires` du manifest : rien
//! à déclarer à la main, aucune liste à maintenir.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use hlb_types::Manifest;

#[derive(Debug, thiserror::Error)]
pub enum GraphError {
    #[error("dépendance circulaire détectée : {}", .0.join(" → "))]
    Cycle(Vec<String>),

    #[error("« {dependent} » a besoin de « {missing} », qui n'est pas dans le catalogue")]
    MissingDependency { dependent: String, missing: String },
}

/// Un graphe orienté « X doit démarrer avant Y ».
#[derive(Debug, Default)]
pub struct DependencyGraph {
    /// nom → services dont il dépend
    deps: BTreeMap<String, BTreeSet<String>>,
}

impl DependencyGraph {
    /// Construit le graphe à partir d'un ensemble de manifests.
    ///
    /// Les arêtes viennent uniquement de `Capability::platform_service()` — ajouter une
    /// capacité qui dépend d'un nouveau service met donc le graphe à jour tout seul.
    pub fn from_manifests(manifests: &[Manifest]) -> Self {
        let mut deps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for m in manifests {
            let name = m.metadata.name.clone();
            let entry = deps.entry(name.clone()).or_default();

            for cap in &m.spec.requires {
                if let Some(svc) = cap.platform_service() {
                    // Un service de plateforme ne dépend pas de lui-même : sans ce
                    // garde-fou, Postgres qui déclare `storage` s'auto-référence.
                    if svc != name {
                        entry.insert(svc.to_string());
                    }
                }
            }
        }

        Self { deps }
    }

    pub fn dependencies_of(&self, name: &str) -> Option<&BTreeSet<String>> {
        self.deps.get(name)
    }

    /// Vérifie que toute dépendance existe dans le graphe.
    ///
    /// Séparé du tri : on veut un message qui nomme le service manquant, pas un
    /// « cycle » trompeur.
    pub fn check_complete(&self) -> Result<(), GraphError> {
        for (name, deps) in &self.deps {
            for d in deps {
                if !self.deps.contains_key(d) {
                    return Err(GraphError::MissingDependency {
                        dependent: name.clone(),
                        missing: d.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Ordre de déploiement : les dépendances d'abord.
    ///
    /// Tri topologique de Kahn. À nombre d'arêtes égal, l'ordre alphabétique départage
    /// — un plan doit être **reproductible**, sinon les tests d'instantané du §12bis
    /// deviennent inutilisables.
    pub fn deployment_order(&self) -> Result<Vec<String>, GraphError> {
        self.check_complete()?;

        // Degré entrant = nombre de dépendances restant à déployer.
        let mut indegree: BTreeMap<&str, usize> = self
            .deps
            .iter()
            .map(|(name, deps)| (name.as_str(), deps.len()))
            .collect();

        let mut ready: VecDeque<&str> = indegree
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(&n, _)| n)
            .collect();

        let mut order = Vec::with_capacity(self.deps.len());

        while let Some(n) = ready.pop_front() {
            order.push(n.to_string());

            // Tout service qui dépendait de `n` a une dépendance de moins.
            let mut newly_ready: Vec<&str> = Vec::new();
            for (name, deps) in &self.deps {
                if deps.contains(n) {
                    if let Some(d) = indegree.get_mut(name.as_str()) {
                        *d -= 1;
                        if *d == 0 {
                            newly_ready.push(name.as_str());
                        }
                    }
                }
            }
            newly_ready.sort_unstable();
            ready.extend(newly_ready);
        }

        if order.len() != self.deps.len() {
            let stuck: Vec<String> = self
                .deps
                .keys()
                .filter(|k| !order.contains(k))
                .cloned()
                .collect();
            return Err(GraphError::Cycle(stuck));
        }

        Ok(order)
    }

    /// Ordre d'arrêt : l'inverse. On ne coupe jamais Postgres avant ses consommateurs.
    pub fn shutdown_order(&self) -> Result<Vec<String>, GraphError> {
        let mut o = self.deployment_order()?;
        o.reverse();
        Ok(o)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &str, requires: &str) -> Manifest {
        let y = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {name} }}\n\
             spec:\n  image: {{ repo: a/b, tag: \"1\", digest: \"sha256:x\" }}\n{requires}"
        );
        serde_yaml_ng::from_str(&y).expect("manifest de test")
    }

    fn plain(name: &str) -> Manifest {
        m(name, "")
    }

    fn with_db(name: &str) -> Manifest {
        m(
            name,
            "  requires:\n    - kind: database\n      engine: postgres\n",
        )
    }

    #[test]
    fn deps_are_deduced_from_requires() {
        let g = DependencyGraph::from_manifests(&[with_db("gitea"), plain("postgres")]);
        let d = g.dependencies_of("gitea").expect("gitea présent");
        assert!(d.contains("postgres"));
    }

    #[test]
    fn postgres_comes_before_its_consumers() {
        let g = DependencyGraph::from_manifests(&[
            with_db("gitea"),
            with_db("vikunja"),
            plain("postgres"),
        ]);
        let order = g.deployment_order().expect("ordre calculable");
        let pos = |n: &str| order.iter().position(|x| x == n).expect("présent");
        assert!(pos("postgres") < pos("gitea"));
        assert!(pos("postgres") < pos("vikunja"));
    }

    #[test]
    fn shutdown_is_the_reverse() {
        let g = DependencyGraph::from_manifests(&[with_db("gitea"), plain("postgres")]);
        let order = g.shutdown_order().expect("ordre calculable");
        let pos = |n: &str| order.iter().position(|x| x == n).expect("présent");
        assert!(
            pos("gitea") < pos("postgres"),
            "les apps s'arrêtent en premier"
        );
    }

    #[test]
    fn order_is_reproducible() {
        let ms = || vec![with_db("gitea"), with_db("vikunja"), plain("postgres")];
        let a = DependencyGraph::from_manifests(&ms())
            .deployment_order()
            .unwrap();
        for _ in 0..20 {
            let b = DependencyGraph::from_manifests(&ms())
                .deployment_order()
                .unwrap();
            assert_eq!(a, b, "un plan doit être reproductible (§12bis)");
        }
    }

    #[test]
    fn missing_dependency_names_the_culprit() {
        // postgres absent du catalogue
        let g = DependencyGraph::from_manifests(&[with_db("gitea")]);
        let err = g.deployment_order().unwrap_err();
        assert!(
            matches!(&err, GraphError::MissingDependency { dependent, missing }
                if dependent == "gitea" && missing == "postgres"),
            "{err}"
        );
    }

    #[test]
    fn platform_service_does_not_depend_on_itself() {
        // postgres déclare un stockage ; il ne doit pas se référencer lui-même.
        let pg = m(
            "postgres",
            "  requires:\n    - kind: storage\n      name: data\n      path: /var/lib/postgresql\n",
        );
        let g = DependencyGraph::from_manifests(&[pg]);
        assert!(g.dependencies_of("postgres").expect("présent").is_empty());
        assert_eq!(g.deployment_order().unwrap(), vec!["postgres"]);
    }

    #[test]
    fn sso_app_waits_for_pocket_id() {
        let app = m(
            "gitea",
            "  requires:\n    - kind: sso\n      mode: native\n",
        );
        let g = DependencyGraph::from_manifests(&[app, plain("pocket-id")]);
        let order = g.deployment_order().unwrap();
        assert_eq!(order, vec!["pocket-id", "gitea"]);
    }
}
