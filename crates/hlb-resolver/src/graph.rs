//! Dependency graph and deployment order.
//!
//! Docker Swarm has **no** equivalent of `depends_on`: it starts every service in
//! parallel. An app that comes up before PostgreSQL is ready crashes, restarts in a
//! loop, and depending on the app corrupts its own initialisation.
//!
//! So the ordering is on us. The graph is derived from the manifest's `requires`:
//! nothing to declare by hand, no list to maintain.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use hlb_types::Manifest;

#[derive(Debug, thiserror::Error)]
pub enum GraphError {
    #[error("circular dependency detected: {}", .0.join(" → "))]
    Cycle(Vec<String>),

    #[error("\"{dependent}\" needs \"{missing}\", which is not in the catalog")]
    MissingDependency { dependent: String, missing: String },
}

/// A directed graph of "X must start before Y".
#[derive(Debug, Default)]
pub struct DependencyGraph {
    /// name → the services it depends on
    deps: BTreeMap<String, BTreeSet<String>>,
}

impl DependencyGraph {
    /// Builds the graph from a set of manifests.
    ///
    /// Edges come only from `Capability::platform_service()` - so adding a capability
    /// that depends on a new service updates the graph on its own.
    pub fn from_manifests(manifests: &[Manifest]) -> Self {
        let mut deps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for m in manifests {
            let name = m.metadata.name.clone();
            let entry = deps.entry(name.clone()).or_default();

            // Another app's volume needs that app deployed first: it creates the volume
            // and decides where it lives.
            for cap in &m.spec.requires {
                if let hlb_types::Capability::Storage {
                    owner: Some(owner), ..
                } = cap
                {
                    entry.insert(owner.clone());
                }
            }

            for cap in &m.spec.requires {
                if let Some(svc) = cap.platform_service() {
                    // A platform service does not depend on itself: without this
                    // guard, Postgres declaring `storage` would self-reference.
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

    /// Checks every dependency exists in the graph.
    ///
    /// Separate from the sort: the message must name the missing service, not report a
    /// misleading "cycle".
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

    /// Deployment order: dependencies first.
    ///
    /// Kahn's topological sort. Ties are broken alphabetically - a plan must be
    /// **reproducible**, or snapshot tests become worthless.
    pub fn deployment_order(&self) -> Result<Vec<String>, GraphError> {
        self.check_complete()?;

        // In-degree is the number of dependencies still to be deployed.
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

            // Every service that depended on `n` now has one dependency fewer.
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

    /// Shutdown order: the reverse. Postgres is never cut before its consumers.
    pub fn shutdown_order(&self) -> Result<Vec<String>, GraphError> {
        let mut o = self.deployment_order()?;
        o.reverse();
        Ok(o)
    }

    /// The shutdown in waves: each service stops once everything needing it has, and
    /// the services of one wave stop together — a battery's runtime does not leave time
    /// to stop twenty apps one after another. Started again, the waves run backwards.
    ///
    /// A dependency outside the graph is left out rather than refused: what is stopped is
    /// what is installed, and a service nobody installed has nothing to wait for.
    pub fn shutdown_waves(&self) -> Result<Vec<Vec<String>>, GraphError> {
        let mut waves = Vec::new();
        let mut stopped: BTreeSet<&str> = BTreeSet::new();
        while stopped.len() < self.deps.len() {
            // Whatever nothing still running needs: every app nobody uses goes in the
            // first wave, the databases once their last consumer is gone.
            let wave: Vec<&str> = self
                .deps
                .keys()
                .map(String::as_str)
                .filter(|n| !stopped.contains(n))
                .filter(|n| {
                    self.deps
                        .iter()
                        .filter(|(other, _)| !stopped.contains(other.as_str()))
                        .all(|(_, needs)| !needs.contains(*n))
                })
                .collect();
            if wave.is_empty() {
                return Err(GraphError::Cycle(
                    self.deps
                        .keys()
                        .filter(|k| !stopped.contains(k.as_str()))
                        .cloned()
                        .collect(),
                ));
            }
            stopped.extend(wave.iter().copied());
            waves.push(wave.into_iter().map(String::from).collect());
        }
        Ok(waves)
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
        serde_yaml_ng::from_str(&y).expect("test manifest")
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
        let d = g.dependencies_of("gitea").expect("gitea present");
        assert!(d.contains("postgres"));
    }

    #[test]
    fn postgres_comes_before_its_consumers() {
        let g = DependencyGraph::from_manifests(&[
            with_db("gitea"),
            with_db("vikunja"),
            plain("postgres"),
        ]);
        let order = g.deployment_order().expect("computable order");
        let pos = |n: &str| order.iter().position(|x| x == n).expect("present");
        assert!(pos("postgres") < pos("gitea"));
        assert!(pos("postgres") < pos("vikunja"));
    }

    #[test]
    fn shutdown_is_the_reverse() {
        let g = DependencyGraph::from_manifests(&[with_db("gitea"), plain("postgres")]);
        let order = g.shutdown_order().expect("computable order");
        let pos = |n: &str| order.iter().position(|x| x == n).expect("present");
        assert!(pos("gitea") < pos("postgres"), "apps stop first");
    }

    #[test]
    fn the_shutdown_waves_stop_consumers_before_what_they_need() {
        let app = m(
            "gitea",
            "  requires:\n    - kind: database\n      engine: postgres\n    - kind: sso\n      mode: native\n",
        );
        // pocket-id needs postgres too: three waves, the apps first.
        let g = DependencyGraph::from_manifests(&[
            app,
            with_db("vikunja"),
            with_db("pocket-id"),
            plain("postgres"),
        ]);
        assert_eq!(
            g.shutdown_waves().expect("waves"),
            vec![
                vec!["gitea".to_string(), "vikunja".to_string()],
                vec!["pocket-id".to_string()],
                vec!["postgres".to_string()],
            ]
        );
        // A dependency nobody installed is nothing to wait for.
        let alone = DependencyGraph::from_manifests(&[with_db("gitea")]);
        assert_eq!(
            alone.shutdown_waves().expect("waves"),
            vec![vec!["gitea".to_string()]]
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
            assert_eq!(a, b, "a plan must be reproducible");
        }
    }

    #[test]
    fn missing_dependency_names_the_culprit() {
        // postgres absent from the catalog
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
        // postgres declares storage; it must not reference itself.
        let pg = m(
            "postgres",
            "  requires:\n    - kind: storage\n      name: data\n      path: /var/lib/postgresql\n",
        );
        let g = DependencyGraph::from_manifests(&[pg]);
        assert!(g.dependencies_of("postgres").expect("present").is_empty());
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
