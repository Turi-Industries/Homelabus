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

/// Une tâche Swarm : **un** réplica, sur **un** nœud.
///
/// ## Pourquoi elle existe
///
/// `running_tasks()` interrogeait déjà Swarm et réduisait tout à un `usize`. Le nœud
/// d'affectation, le message d'erreur et les dates étaient jetés — or c'est exactement
/// ce qu'il faut pour répondre à « pourquoi cette app est-elle rouge ? » et pour
/// dessiner la vue topologie du §11bis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskInfo {
    pub id: String,
    pub service: String,
    /// Le numéro de réplica. `None` pour un service en mode global.
    pub slot: Option<u64>,
    pub node_id: Option<String>,
    /// L'état voulu par Swarm : `running`, `shutdown`, `accepted`…
    pub desired_state: String,
    /// L'état réel : `running`, `failed`, `rejected`, `pending`…
    pub state: String,
    pub image: String,
    /// Ce que Swarm dit de la tâche (« started », « no suitable node »…).
    pub message: Option<String>,
    /// 🔴 L'erreur, quand il y en a une. C'est LE champ qui explique une app en échec,
    /// et c'est celui que l'ancien compteur jetait.
    pub err: Option<String>,
    /// Horodatage Unix du dernier changement d'état.
    pub updated_at: Option<i64>,
}

impl TaskInfo {
    /// Cette tâche tourne-t-elle vraiment ?
    ///
    /// ⚠️ Les DEUX conditions. Swarm conserve l'historique des tâches mortes : filtrer
    /// sur le seul état voulu compterait des cadavres.
    pub fn est_vivante(&self) -> bool {
        self.desired_state == "running" && self.state == "running"
    }

    /// Cette tâche a-t-elle échoué ?
    ///
    /// Distinct de « pas vivante » : une tâche volontairement arrêtée (mise à jour,
    /// réduction d'échelle) n'est pas une panne, et la compter comme telle ferait
    /// clignoter le tableau de bord à chaque déploiement normal.
    pub fn a_echoue(&self) -> bool {
        matches!(self.state.as_str(), "failed" | "rejected" | "orphaned")
    }

    /// Ce qui explique l'état, en une ligne.
    ///
    /// L'erreur d'abord : c'est elle qu'on cherche. Le message de Swarm ensuite, qui
    /// dit souvent ce que l'erreur ne dit pas (« no suitable node »).
    pub fn explication(&self) -> Option<&str> {
        self.err
            .as_deref()
            .or(self.message.as_deref())
            .filter(|m| !m.is_empty())
    }
}

/// Une ligne de journal d'un service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LigneLog {
    /// Horodatage Unix. `None` si Docker ne l'a pas fourni.
    pub at: Option<i64>,
    /// `true` = stderr. Beaucoup d'applications écrivent tout sur stderr : afficher
    /// ces lignes en rouge ferait passer un démarrage normal pour une avalanche
    /// d'erreurs.
    pub erreur: bool,
    pub ligne: String,
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

    /// Active le verrouillage automatique du Swarm (§9) et renvoie la clé.
    ///
    /// 🔴 Sans autolock, les clés Raft du cluster sont **en clair sur le disque** de
    /// chaque manager. Quiconque récupère un disque récupère de quoi prendre le
    /// contrôle du cluster. Avec autolock, un manager redémarré reste verrouillé
    /// jusqu'à ce qu'on lui fournisse la clé.
    async fn enable_autolock(&self) -> Result<String>;

    /// L'autolock est-il actif ?
    async fn autolock_enabled(&self) -> Result<bool>;

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

    /// Les tâches, avec leur placement et leur erreur.
    ///
    /// `service = None` rend celles de tous les services gérés. **Sans filtre d'état** :
    /// les tâches mortes sont ce qui explique une panne, et les cacher ici obligerait à
    /// aller lire `docker service ps` à la main.
    async fn tasks(&self, service: Option<&str>) -> Result<Vec<TaskInfo>>;

    /// Les dernières lignes de journal d'un service.
    ///
    /// ⚠️ `lignes` est borné côté implémentation : un service bavard laissé sans limite
    /// remplirait la mémoire du controller, et c'est le controller qui tomberait — pas
    /// le service qu'on cherchait à diagnostiquer.
    async fn logs(&self, service: &str, lignes: u32) -> Result<Vec<LigneLog>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tache(desired: &str, etat: &str) -> TaskInfo {
        TaskInfo {
            id: "t1".into(),
            service: "gitea".into(),
            slot: Some(1),
            node_id: Some("n1".into()),
            desired_state: desired.into(),
            state: etat.into(),
            image: "gitea/gitea:1.24".into(),
            message: None,
            err: None,
            updated_at: Some(1_000),
        }
    }

    #[test]
    fn a_dead_task_is_never_counted_as_alive() {
        // 🔴 Swarm conserve l'historique des tâches mortes. Une tâche que Swarm VEUT
        // voir tourner mais qui a échoué n'est pas vivante — et l'inverse non plus :
        // une tâche qui tourne encore alors que Swarm veut l'arrêter est en train de
        // partir.
        assert!(tache("running", "running").est_vivante());
        assert!(!tache("running", "failed").est_vivante());
        assert!(!tache("shutdown", "running").est_vivante());
        assert!(!tache("shutdown", "shutdown").est_vivante());
    }

    #[test]
    fn a_deliberate_shutdown_is_not_a_failure() {
        // Une tâche arrêtée pour une mise à jour ou une réduction d'échelle n'est pas
        // une panne. La compter comme telle ferait clignoter le tableau de bord à
        // chaque déploiement normal — et on cesserait de le regarder.
        assert!(!tache("shutdown", "shutdown").a_echoue());
        assert!(!tache("shutdown", "complete").a_echoue());
        assert!(tache("running", "failed").a_echoue());
        assert!(tache("running", "rejected").a_echoue());
        assert!(tache("running", "orphaned").a_echoue());
    }

    #[test]
    fn the_error_is_preferred_to_the_status_message() {
        // Les deux existent souvent ensemble : `message` dit « started », `err` dit
        // pourquoi ça n'a pas marché. C'est l'erreur qu'on cherche.
        let mut t = tache("running", "failed");
        t.message = Some("started".into());
        t.err = Some("no such image".into());
        assert_eq!(t.explication(), Some("no such image"));

        t.err = None;
        assert_eq!(t.explication(), Some("started"));
    }

    #[test]
    fn an_empty_explanation_is_none_rather_than_blank() {
        // Une chaîne vide afficherait une ligne d'explication sans explication, ce qui
        // fait chercher un problème d'affichage.
        let mut t = tache("running", "pending");
        t.err = Some(String::new());
        t.message = Some(String::new());
        assert_eq!(t.explication(), None);
    }

    #[test]
    fn a_log_line_knows_which_stream_it_came_from() {
        // Beaucoup d'applications écrivent TOUT sur stderr : peindre ces lignes en
        // rouge ferait passer un démarrage normal pour une avalanche d'erreurs. Le
        // champ existe pour être affiché avec discernement, pas pour colorer.
        let l = LigneLog {
            at: Some(1_000),
            erreur: true,
            ligne: "listening on :3000".into(),
        };
        assert!(l.erreur);
        assert!(!l.ligne.is_empty());
    }
}
