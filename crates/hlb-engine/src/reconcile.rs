//! The reconciliation loop.
//!
//! This is what separates Homelabus from an install script. The controller does not
//! perform one-shot imperative actions: it continuously maintains
//! **desired state → drift → correction → verification**.
//!
//! Concretely: if a node goes down and comes back, if someone runs a `docker service
//! rm` by hand, or if an image is swapped live, the system converges again on its own.
//!
//! # What reconciliation NEVER does
//!
//! - **Touch an unmanaged service.** The label filter is absolute.
//! - **Delete an orphan service.** An orphan can come from a lost state database, not
//!   from an uninstall. Destroying data on that basis would be unacceptable - it is
//!   reported, and a human decides.
//! - **Restart a failed installation.** It would loop forever on the same error. That
//!   needs an explicit intervention.
//! - **Correct a convergence in flight.** If Swarm is starting tasks, it is left to
//!   finish rather than being given contradictory orders.

use std::collections::BTreeSet;

use hlb_orchestrator::Orchestrator;
use hlb_state::State;

use crate::Error;

type Result<T> = std::result::Result<T, Error>;

/// A drift between the desired state and the observed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    /// The service should exist but is gone (`docker service rm`, a lost node...).
    ServiceMissing { app: String, image: String },

    /// Someone changed the replica count outside Homelabus.
    ReplicasDiverged {
        app: String,
        desired: u64,
        actual: u64,
    },

    /// The running image is not the frozen manifest's.
    ImageDiverged {
        app: String,
        expected: String,
        actual: String,
    },

    /// A managed service with no matching app in the database.
    /// **Never deleted automatically** - only reported.
    OrphanService { name: String },

    /// Swarm est en train de converger. Informatif, pas corrigible.
    Converging {
        app: String,
        running: usize,
        desired: u64,
    },
}

impl Drift {
    /// Can reconciliation correct this drift on its own?
    pub fn is_correctable(&self) -> bool {
        matches!(
            self,
            Self::ServiceMissing { .. }
                | Self::ReplicasDiverged { .. }
                | Self::ImageDiverged { .. }
        )
    }

    /// Why this drift is **deliberately not** corrected.
    ///
    /// 🔴 Without this sentence, nothing separates "there is nothing to do" from
    /// "there is something and I chose not to touch it". The two look alike on screen,
    /// and the second makes you doubt the system - you end up correcting by hand what
    /// it deliberately left alone, or believing it saw nothing.
    ///
    /// Returns `None` when the drift IS corrected: there is then no refusal to
    /// explain.
    pub fn refus(&self) -> Option<&'static str> {
        match self {
            Self::ServiceMissing { .. }
            | Self::ReplicasDiverged { .. }
            | Self::ImageDiverged { .. } => None,
            Self::OrphanService { .. } => Some(
                "an orphan is NEVER deleted automatically: this service may hold \
                 data, and a system that over-corrects is more dangerous than one \
                 that corrects nothing",
            ),
            Self::Converging { .. } => Some(
                "Swarm is converging: progress is transient and gets left alone - \
                 only the instruction is corrected",
            ),
        }
    }

    pub fn app(&self) -> &str {
        match self {
            Self::ServiceMissing { app, .. }
            | Self::ReplicasDiverged { app, .. }
            | Self::ImageDiverged { app, .. }
            | Self::Converging { app, .. } => app,
            Self::OrphanService { name } => name,
        }
    }
}

impl std::fmt::Display for Drift {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServiceMissing { app, image } => {
                write!(f, "{app}: service missing, should be running from {image}")
            }
            Self::ReplicasDiverged {
                app,
                desired,
                actual,
            } => write!(
                f,
                "{app}: {} {} instructed, the manifest asks for {desired}",
                actual,
                if *actual == 1 { "replica" } else { "replicas" }
            ),
            Self::ImageDiverged {
                app,
                expected,
                actual,
            } => {
                write!(f, "{app}: running {actual}, expected {expected}")
            }
            Self::OrphanService { name } => write!(
                f,
                "{name}: managed service with no matching app - check before deleting"
            ),
            Self::Converging {
                app,
                running,
                desired,
            } => {
                write!(f, "{app}: converging ({running}/{desired})")
            }
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub drifts: Vec<Drift>,
    pub corrected: Vec<Drift>,
    pub failed: Vec<(Drift, String)>,
}

impl Report {
    pub fn is_clean(&self) -> bool {
        self.drifts.is_empty()
    }

    pub fn correctable(&self) -> impl Iterator<Item = &Drift> {
        self.drifts.iter().filter(|d| d.is_correctable())
    }
}

/// The app statuses reconciliation stays away from.
///
/// A failed or in-progress installation must not be "repaired": in the first case we
/// would loop on the same error, in the second we would race the installation
/// itself.
fn is_reconcilable(status: &str) -> bool {
    matches!(status, "running" | "partial")
}

pub struct Reconciler<'a, O: Orchestrator> {
    orchestrator: &'a O,
    state: &'a State,
}

impl<'a, O: Orchestrator> Reconciler<'a, O> {
    pub fn new(orchestrator: &'a O, state: &'a State) -> Self {
        Self {
            orchestrator,
            state,
        }
    }

    /// Detects drifts. **Strictly read-only.**
    pub async fn detect(&self) -> Result<Vec<Drift>> {
        let apps = self.state.installed_apps().await?;
        let observed = self.orchestrator.list().await?;

        let mut drifts = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();

        for (name, status) in &apps {
            if !is_reconcilable(status) {
                continue;
            }
            seen.insert(name.clone());

            let manifest = self.state.app_manifest(name).await?;
            let expected_image = manifest.spec.image.reference();
            let expected_replicas = manifest.spec.swarm.replicas;

            let Some(svc) = observed.iter().find(|s| &s.name == name) else {
                drifts.push(Drift::ServiceMissing {
                    app: name.clone(),
                    image: expected_image,
                });
                continue;
            };

            // The essential distinction: what Swarm has been instructed (`desired`)
            // comes from a decision - ours or a human's. What actually runs
            // (`running`) is just progress. We correct the instruction, never the
            // progress.
            if svc.desired_replicas != expected_replicas {
                drifts.push(Drift::ReplicasDiverged {
                    app: name.clone(),
                    desired: expected_replicas,
                    actual: svc.desired_replicas,
                });
            } else if !svc.is_converged() {
                drifts.push(Drift::Converging {
                    app: name.clone(),
                    running: svc.running_replicas,
                    desired: svc.desired_replicas,
                });
            }

            // The image is only compared when the manifest is pinned to a digest or a
            // precise tag; Swarm often rewrites the reference with the resolved digest,
            // hence a prefix comparison rather than a strict one.
            if !svc.image.starts_with(&expected_image) && svc.image != expected_image {
                drifts.push(Drift::ImageDiverged {
                    app: name.clone(),
                    expected: expected_image,
                    actual: svc.image.clone(),
                });
            }
        }

        // A managed service the state does not know about.
        for svc in &observed {
            if !seen.contains(&svc.name) && !apps.iter().any(|(n, _)| n == &svc.name) {
                drifts.push(Drift::OrphanService {
                    name: svc.name.clone(),
                });
            }
        }

        Ok(drifts)
    }

    /// Detects and then, when `apply`, corrects what is correctable.
    pub async fn reconcile(&self, apply: bool) -> Result<Report> {
        let drifts = self.detect().await?;
        let mut report = Report {
            drifts: drifts.clone(),
            ..Default::default()
        };

        if !apply {
            return Ok(report);
        }

        for d in drifts.into_iter().filter(Drift::is_correctable) {
            match self.correct(&d).await {
                Ok(()) => {
                    tracing::info!(app = d.app(), "drift corrected");
                    report.corrected.push(d);
                }
                Err(e) => {
                    // A failure on one service does not stop the others being
                    // repaired: unlike installation, corrections have no dependency
                    // between them.
                    tracing::warn!(app = d.app(), error = %e, "correction impossible");
                    report.failed.push((d, e.to_string()));
                }
            }
        }

        Ok(report)
    }

    async fn correct(&self, drift: &Drift) -> Result<()> {
        match drift {
            Drift::ServiceMissing { app, image } => {
                let manifest = self.state.app_manifest(app).await?;
                let mut spec = hlb_orchestrator::ServiceSpec::new(app, image)
                    .replicas(manifest.spec.swarm.replicas);
                if let Some(tier) = &manifest.spec.swarm.tier {
                    spec = spec.constraint(format!("node.labels.tier=={tier}"));
                }
                self.orchestrator.deploy(&spec).await?;
                Ok(())
            }

            Drift::ReplicasDiverged { app, desired, .. } => {
                self.orchestrator.scale(app, *desired).await?;
                Ok(())
            }

            Drift::ImageDiverged { app, expected, .. } => {
                self.orchestrator.update_image(app, expected).await?;
                Ok(())
            }

            // Deliberately inert: see the module header.
            Drift::OrphanService { .. } | Drift::Converging { .. } => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_uncorrected_drift_explains_why_it_was_left_alone() {
        // 🔴 A drift reported with no refusal reason makes you doubt: you cannot tell
        // whether the system does not know how, failed, or deliberately chose not to
        // touch it. You then correct by hand what it was protecting - or believe it saw
        // nothing.
        let tous = [
            Drift::ServiceMissing {
                app: "gitea".into(),
                image: "a/b:1".into(),
            },
            Drift::ReplicasDiverged {
                app: "gitea".into(),
                desired: 2,
                actual: 1,
            },
            Drift::ImageDiverged {
                app: "gitea".into(),
                expected: "a/b:2".into(),
                actual: "a/b:1".into(),
            },
            Drift::OrphanService {
                name: "vieux".into(),
            },
            Drift::Converging {
                app: "gitea".into(),
                running: 1,
                desired: 2,
            },
        ];

        for d in &tous {
            // The exact rule: correctable ⇔ no refusal to explain. A drift that was
            // both (or neither) would leave a hole on screen.
            assert_eq!(
                d.is_correctable(),
                d.refus().is_none(),
                "{d}: correctable and refused must be exactly complementary"
            );
        }
    }

    #[test]
    fn a_single_replica_is_not_announced_in_the_plural() {
        // The "replica(s)" tic, spotted in the drift message: this is text the CLI
        // displays, and the interface after it.
        let d = Drift::ReplicasDiverged {
            app: "gitea".into(),
            desired: 2,
            actual: 1,
        };
        let texte = d.to_string();
        let tic = format!("({})", "s");
        assert!(!texte.contains(&tic), "{texte}");
        assert!(texte.contains("1 replica instructed"), "{texte}");
    }
}
