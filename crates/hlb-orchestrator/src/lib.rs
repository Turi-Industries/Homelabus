//! L'abstraction d'orchestration.
//!
//! Le trait existe pour deux raisons (§10.4 du plan) :
//!   1. isoler le reste du code des trous éventuels de `bollard` ;
//!   2. garder ouverte la porte vers un autre orchestrateur sans réécrire le produit.
//!
//! Coût aujourd'hui : quelques centaines de lignes. Bénéfice : on peut remplacer
//! l'implémentation Swarm sans toucher au résolveur, au catalogue ni à l'API.

pub mod cluster;
pub mod swarm;

use async_trait::async_trait;
use hlb_types::{Healthcheck, SecuritySpec};

pub use cluster::{ClusterProfile, JoinTokens, NodeInfo, NodeRole, QuorumHealth};

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
    /// Comment répliquer le service.
    pub mode: ServiceMode,
    /// Volumes à monter : `(nom du volume, chemin dans le conteneur)`.
    ///
    /// 🔴 Sans eux, les données d'une app partent dans la couche éphémère du
    /// conteneur et disparaissent au premier redéploiement.
    pub mounts: Vec<(String, String)>,
    /// §9 — durcissement. Vient du manifest et est **appliqué**, pas seulement
    /// déclaré. Le type est celui de `hlb-types` : une seule définition, comme pour
    /// tout le reste du schéma (§11).
    pub hardening: SecuritySpec,
    /// Sonde de santé. Sans elle, `wait_healthy` ne peut que compter des tâches
    /// « en cours », ce qui ne dit rien de l'application elle-même.
    pub healthcheck: Option<Healthcheck>,
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
            mode: ServiceMode::Replicated,
            mounts: Vec::new(),
            hardening: SecuritySpec::default(),
            healthcheck: None,
        }
    }

    /// Un exemplaire par nœud, y compris les nœuds ajoutés plus tard.
    ///
    /// C'est ce qui distingue l'agent d'un démon qu'il faudrait installer à la main
    /// partout : ajouter une machine au cluster suffit à l'y faire apparaître.
    pub fn global(mut self) -> Self {
        self.mode = ServiceMode::Global;
        self
    }

    /// Ajoute un volume nommé, monté au chemin indiqué.
    pub fn mount(mut self, volume: impl Into<String>, path: impl Into<String>) -> Self {
        self.mounts.push((volume.into(), path.into()));
        self
    }

    /// Remplace les variables d'environnement du service.
    pub fn env(mut self, vars: Vec<(String, String)>) -> Self {
        self.env = vars;
        self
    }

    pub fn hardening(mut self, h: SecuritySpec) -> Self {
        self.hardening = h;
        self
    }

    pub fn healthcheck(mut self, h: Healthcheck) -> Self {
        self.healthcheck = Some(h);
        self
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
/// Comment Swarm répartit les exemplaires d'un service.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ServiceMode {
    /// Un nombre fixe d'exemplaires, placés où Swarm veut.
    #[default]
    Replicated,
    /// Exactement un par nœud éligible. `replicas` est alors ignoré.
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    pub exit_code: i64,
    pub stdout: String,
    pub stderr: String,
}

impl ExecOutput {
    pub fn ok(&self) -> bool {
        self.exit_code == 0
    }
}

/// Un volume et son emplacement réel sur l'hôte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    pub name: String,
    /// Chemin sur le nœud qui l'héberge. C'est ce que restic sauvegarde (§8).
    pub mountpoint: String,
    /// Le volume existait-il déjà ?
    pub existed: bool,
}

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

    /// Ajuste le nombre de réplicas d'un service existant.
    async fn scale(&self, name: &str, replicas: u64) -> Result<()>;

    // ── Vie du cluster (§2ter, §10.3) ───────────────────────────────────────

    /// Initialise un Swarm sur cette machine. Idempotent : un Swarm déjà actif
    /// n'est pas réinitialisé — ce serait détruire le cluster existant.
    async fn cluster_init(&self, advertise_addr: Option<&str>) -> Result<String>;

    /// Les jetons de rattachement, et l'adresse à laquelle se connecter.
    async fn join_tokens(&self) -> Result<cluster::JoinTokens>;

    /// Les nœuds du cluster, avec leur rôle et leur tier.
    async fn nodes(&self) -> Result<Vec<cluster::NodeInfo>>;

    /// Pose une étiquette sur un nœud — c'est ainsi que le tier devient une
    /// contrainte de placement effective (§2bis.2).
    async fn label_node(&self, node: &str, key: &str, value: &str) -> Result<()>;

    /// Exécute une commande dans un conteneur en cours d'un service.
    ///
    /// Sert aux automatisations `method: exec` des guides (§4.6bis) : beaucoup
    /// d'apps ne se configurent que par leur CLI (`gitea admin`, `occ`…).
    async fn exec_in_service(&self, name: &str, cmd: &[String]) -> Result<ExecOutput>;

    /// Crée un volume nommé, étiqueté comme géré par HomelabUS.
    ///
    /// Idempotent : un volume existant est conservé tel quel — il porte des données.
    async fn create_volume(&self, name: &str) -> Result<VolumeInfo>;

    /// Décrit un volume existant.
    async fn inspect_volume(&self, name: &str) -> Result<VolumeInfo>;

    async fn status(&self, name: &str) -> Result<ServiceStatus>;

    async fn list(&self) -> Result<Vec<ServiceStatus>>;

    async fn remove(&self, name: &str) -> Result<()>;

    /// Attend que le service ait convergé. Utilisé par l'ordonnanceur du §4.7 :
    /// Swarm n'ayant pas de `depends_on`, c'est nous qui séquençons.
    async fn wait_healthy(&self, name: &str, timeout_secs: u64) -> Result<ServiceStatus>;
}
