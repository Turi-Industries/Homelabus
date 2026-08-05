//! La boucle de réconciliation (§2.1 du plan).
//!
//! C'est ce qui distingue HomelabUS d'un script d'installation. Le controller ne fait
//! pas d'actions impératives one-shot : il maintient en permanence
//! **état désiré → écart → correction → vérification**.
//!
//! Conséquence concrète : si un nœud tombe et revient, si quelqu'un fait un
//! `docker service rm` à la main, ou si une image est changée à chaud, le système
//! reconverge tout seul.
//!
//! # Ce que la réconciliation ne fait JAMAIS
//!
//! - **Toucher un service non géré.** Le filtre par label est absolu.
//! - **Supprimer un service orphelin.** Un orphelin peut venir d'une base d'état
//!   perdue, pas d'une désinstallation. Détruire des données sur cette base serait
//!   inacceptable — on signale, l'humain tranche.
//! - **Relancer une installation en échec.** Elle boucherait indéfiniment sur la même
//!   erreur. Il faut une intervention explicite.
//! - **Corriger une convergence en cours.** Si Swarm est en train de démarrer des
//!   tâches, on le laisse finir plutôt que d'empiler des ordres contradictoires.

use std::collections::BTreeSet;

use hlb_orchestrator::Orchestrator;
use hlb_state::State;

use crate::Error;

type Result<T> = std::result::Result<T, Error>;

/// Un écart entre l'état désiré et l'état observé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    /// Le service devrait exister mais a disparu (`docker service rm`, nœud perdu…).
    ServiceMissing { app: String, image: String },

    /// Quelqu'un a changé le nombre de réplicas hors de HomelabUS.
    ReplicasDiverged {
        app: String,
        desired: u64,
        actual: u64,
    },

    /// L'image tournante n'est pas celle du manifest figé.
    ImageDiverged {
        app: String,
        expected: String,
        actual: String,
    },

    /// Un service géré sans app correspondante en base.
    /// **Jamais supprimé automatiquement** — signalé seulement.
    OrphanService { name: String },

    /// Swarm est en train de converger. Informatif, pas corrigible.
    Converging {
        app: String,
        running: usize,
        desired: u64,
    },
}

impl Drift {
    /// La réconciliation sait-elle corriger cet écart toute seule ?
    pub fn is_correctable(&self) -> bool {
        matches!(
            self,
            Self::ServiceMissing { .. }
                | Self::ReplicasDiverged { .. }
                | Self::ImageDiverged { .. }
        )
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
                write!(f, "{app} : service absent, devrait tourner depuis {image}")
            }
            Self::ReplicasDiverged { app, desired, actual } => write!(
                f,
                "{app} : {actual} réplique(s) configurée(s), le manifest en demande {desired}"
            ),
            Self::ImageDiverged { app, expected, actual } => {
                write!(f, "{app} : tourne sous {actual}, attendu {expected}")
            }
            Self::OrphanService { name } => write!(
                f,
                "{name} : service géré sans app correspondante — vérifie avant de supprimer"
            ),
            Self::Converging { app, running, desired } => {
                write!(f, "{app} : convergence en cours ({running}/{desired})")
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

/// Les statuts d'app pour lesquels on ne réconcilie pas.
///
/// Une installation en échec ou en cours ne doit pas être « réparée » : dans le
/// premier cas on bouclerait sur la même erreur, dans le second on entrerait en
/// concurrence avec l'installation elle-même.
fn is_reconcilable(status: &str) -> bool {
    matches!(status, "running" | "partial")
}

pub struct Reconciler<'a, O: Orchestrator> {
    orchestrator: &'a O,
    state: &'a State,
}

impl<'a, O: Orchestrator> Reconciler<'a, O> {
    pub fn new(orchestrator: &'a O, state: &'a State) -> Self {
        Self { orchestrator, state }
    }

    /// Détecte les écarts. **Strictement en lecture seule.**
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

            // Distinction essentielle : ce que Swarm a pour consigne (`desired`) vient
            // d'une décision — la nôtre ou celle d'un humain. Ce qui tourne vraiment
            // (`running`) est juste l'avancement. On corrige la consigne, jamais
            // l'avancement.
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

            // L'image n'est comparée que si le manifest est épinglé sur un digest ou
            // un tag précis ; Swarm réécrit souvent la référence avec le digest résolu,
            // d'où la comparaison par préfixe plutôt que stricte.
            if !svc.image.starts_with(&expected_image) && svc.image != expected_image {
                drifts.push(Drift::ImageDiverged {
                    app: name.clone(),
                    expected: expected_image,
                    actual: svc.image.clone(),
                });
            }
        }

        // Un service géré que l'état ne connaît pas.
        for svc in &observed {
            if !seen.contains(&svc.name) && !apps.iter().any(|(n, _)| n == &svc.name) {
                drifts.push(Drift::OrphanService {
                    name: svc.name.clone(),
                });
            }
        }

        Ok(drifts)
    }

    /// Détecte puis, si `apply`, corrige ce qui est corrigeable.
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
                    tracing::info!(app = d.app(), "écart corrigé");
                    report.corrected.push(d);
                }
                Err(e) => {
                    // Un échec sur un service n'empêche pas de réparer les autres :
                    // contrairement à l'installation, il n'y a pas de dépendance
                    // entre les corrections.
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

            // Volontairement inertes : voir l'en-tête du module.
            Drift::OrphanService { .. } | Drift::Converging { .. } => Ok(()),
        }
    }
}
