//! L'abstraction d'orchestration.
//!
//! Le trait existe pour deux raisons (§10.4 du plan) :
//!   1. isoler le reste du code des trous éventuels de `bollard` ;
//!   2. garder ouverte la porte vers un autre orchestrateur sans réécrire le produit.
//!
//! Coût aujourd'hui : quelques centaines de lignes. Bénéfice : on peut remplacer
//! l'implémentation Swarm sans toucher au résolveur, au catalogue ni à l'API.

pub mod swarm;

use async_trait::async_trait;

pub use swarm::SwarmOrchestrator;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("erreur docker : {0}")]
    Docker(#[from] bollard::errors::Error),

    #[error("service « {0} » introuvable")]
    NotFound(String),

    #[error("le service « {service} » n'est pas devenu sain avant {timeout_secs} s \
             ({running}/{desired} tâches en cours)")]
    HealthTimeout {
        service: String,
        timeout_secs: u64,
        running: usize,
        desired: u64,
    },

    #[error("réponse inattendue du daemon : {0}")]
    Unexpected(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Ce qu'on demande à déployer. Volontairement pauvre : la traduction depuis le
/// manifest est le travail du résolveur, pas de l'orchestrateur.
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    pub name: String,
    /// Référence complète, digest inclus quand il est connu.
    pub image: String,
    pub replicas: u64,
    /// Vide = point d'entrée de l'image.
    pub command: Vec<String>,
    pub env: Vec<(String, String)>,
    /// Contraintes de placement Swarm, ex. `node.labels.tier==heavy`.
    pub constraints: Vec<String>,
    pub labels: Vec<(String, String)>,
    pub networks: Vec<String>,
}

impl ServiceSpec {
    pub fn new(name: impl Into<String>, image: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            image: image.into(),
            replicas: 1,
            command: Vec::new(),
            env: Vec::new(),
            constraints: Vec::new(),
            labels: Vec::new(),
            networks: Vec::new(),
        }
    }

    pub fn replicas(mut self, n: u64) -> Self {
        self.replicas = n;
        self
    }

    pub fn command<I, S>(mut self, cmd: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command = cmd.into_iter().map(Into::into).collect();
        self
    }

    pub fn constraint(mut self, c: impl Into<String>) -> Self {
        self.constraints.push(c.into());
        self
    }
}

/// L'état observé d'un service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub name: String,
    pub id: String,
    pub desired_replicas: u64,
    pub running_replicas: usize,
    /// Image réellement utilisée par le service, digest résolu par Swarm.
    pub image: String,
    pub update_state: Option<UpdateState>,
}

impl ServiceStatus {
    pub fn is_converged(&self) -> bool {
        self.running_replicas as u64 == self.desired_replicas
    }
}

/// L'état de la dernière mise à jour, tel que rapporté par Swarm.
///
/// C'est la brique qui rend le rollback automatique du §7 possible : on n'a pas à
/// deviner si une mise à jour a échoué, Swarm le dit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateState {
    Updating,
    Paused,
    Completed,
    RollbackStarted,
    RollbackPaused,
    RollbackCompleted,
    Unknown,
}

impl UpdateState {
    pub fn is_failure(&self) -> bool {
        matches!(
            self,
            Self::Paused | Self::RollbackStarted | Self::RollbackPaused | Self::RollbackCompleted
        )
    }
}

#[async_trait]
pub trait Orchestrator: Send + Sync {
    async fn ping(&self) -> Result<String>;

    async fn deploy(&self, spec: &ServiceSpec) -> Result<String>;

    /// Met à jour l'image d'un service existant.
    ///
    /// Doit appliquer `order: start-first` et `failure_action: rollback` — sans quoi
    /// tout le pipeline du §7 s'écroule.
    async fn update_image(&self, name: &str, image: &str) -> Result<()>;

    async fn status(&self, name: &str) -> Result<ServiceStatus>;

    async fn list(&self) -> Result<Vec<ServiceStatus>>;

    async fn remove(&self, name: &str) -> Result<()>;

    /// Attend que le service ait convergé. Utilisé par l'ordonnanceur du §4.7 :
    /// Swarm n'ayant pas de `depends_on`, c'est nous qui séquençons.
    async fn wait_healthy(&self, name: &str, timeout_secs: u64) -> Result<ServiceStatus>;
}
