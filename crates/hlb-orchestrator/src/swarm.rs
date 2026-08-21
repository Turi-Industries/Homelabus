//! Implémentation Docker Swarm, via `bollard`.
//!
//! Toute la connaissance de `bollard` est confinée ici. Le reste du produit ne voit
//! que le trait — c'est ce qui rend le pari `bollard` réversible (§10.4).

use std::collections::HashMap;

use async_trait::async_trait;
use bollard::container::LogOutput;

use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use bollard::models::VolumeCreateOptions as CreateVolumeOptions;
use bollard::models::{
    HealthConfig, Mount, MountTypeEnum, SwarmInitRequest, TaskSpecContainerSpecPrivileges,
    ServiceSpecMode, ServiceSpecModeReplicated, ServiceSpecRollbackConfig, ServiceSpecUpdateConfig,
    ServiceSpecUpdateConfigFailureActionEnum, ServiceSpecUpdateConfigOrderEnum, TaskSpec,
    TaskSpecContainerSpec, TaskSpecPlacement,
};
use bollard::query_parameters::{
    ListNodesOptions, ListServicesOptionsBuilder, ListTasksOptionsBuilder,
    UpdateNodeOptionsBuilder, UpdateServiceOptionsBuilder,
};
use bollard::Docker;

use crate::cluster;
use crate::{
    Error, ExecOutput, LigneLog, Orchestrator, Result, ServiceSpec, ServiceStatus, TaskInfo,
    UpdateState, VolumeInfo,
};

const NS: i64 = 1_000_000_000;

/// Un horodatage RFC 3339 tel que Docker les rend, en secondes Unix.
///
/// Analyse écrite à la main : `chrono` est déjà là mais pour d'autres raisons, et une
/// date Docker a toujours la même forme (`2026-08-18T10:16:04.123456789Z`). Rend `None`
/// sur tout ce qui ne colle pas — un horodatage à moitié lu placerait une ligne de
/// journal en 1970, et on chercherait un problème d'horloge.
fn horodatage_unix(s: &str) -> Option<i64> {
    let (date, reste) = s.split_once('T')?;
    let (a, reste_d) = date.split_once('-')?;
    let (m, j) = reste_d.split_once('-')?;
    let heure: String = reste.chars().take_while(|c| *c != '.' && *c != 'Z').collect();
    let mut hms = heure.split(':');
    let (h, mi, se) = (hms.next()?, hms.next()?, hms.next()?);

    let (a, m, j): (i64, i64, i64) = (a.parse().ok()?, m.parse().ok()?, j.parse().ok()?);
    let (h, mi, se): (i64, i64, i64) = (h.parse().ok()?, mi.parse().ok()?, se.parse().ok()?);

    // Jours depuis l'époque, par l'algorithme des « jours civils » de Howard Hinnant.
    // Il gère les années bissextiles séculaires, que la division naïve par 4 rate.
    let a2 = a - i64::from(m <= 2);
    let ere = if a2 >= 0 { a2 } else { a2 - 399 } / 400;
    let annee_ere = a2 - ere * 400;
    let jour_annee = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + j - 1;
    let jour_ere = annee_ere * 365 + annee_ere / 4 - annee_ere / 100 + jour_annee;
    let jours = ere * 146_097 + jour_ere - 719_468;

    Some(jours * 86_400 + h * 3_600 + mi * 60 + se)
}

/// Marque les services que Homelabus gère, pour ne jamais toucher au reste.
pub const MANAGED_LABEL: &str = "hlb.managed";

pub struct SwarmOrchestrator {
    docker: Docker,
}

impl SwarmOrchestrator {
    /// Se connecte au daemon local (socket Unix, ou `DOCKER_HOST` s'il est défini).
    pub fn connect() -> Result<Self> {
        let docker = Docker::connect_with_defaults()?;
        Ok(Self { docker })
    }

    pub fn from_docker(docker: Docker) -> Self {
        Self { docker }
    }

    /// La politique de mise à jour du §7, appliquée à **tout** service déployé.
    ///
    /// Ce n'est pas configurable par app : c'est le socle qui rend le rollback
    /// automatique possible. Une app qui ne le supporte pas doit être en `pin`.
    fn update_config() -> ServiceSpecUpdateConfig {
        ServiceSpecUpdateConfig {
            // Une tâche à la fois : on ne remplace jamais tout le service d'un coup.
            parallelism: Some(1),
            // La nouvelle tâche démarre avant l'arrêt de l'ancienne → zéro coupure.
            order: Some(ServiceSpecUpdateConfigOrderEnum::START_FIRST),
            // Le cœur du §7 : Swarm annule lui-même une mise à jour qui échoue.
            failure_action: Some(ServiceSpecUpdateConfigFailureActionEnum::ROLLBACK),
            // Surveille 30 s après démarrage : un conteneur qui meurt à la 5e seconde
            // doit compter comme un échec, pas comme un succès.
            monitor: Some(30 * NS),
            max_failure_ratio: Some(0.0),
            delay: Some(5 * NS),
        }
    }

    /// Le retour arrière doit être plus prudent que l'aller : on arrête d'abord,
    /// pour éviter que deux versions coexistent sur un schéma déjà migré.
    fn rollback_config() -> ServiceSpecRollbackConfig {
        ServiceSpecRollbackConfig {
            parallelism: Some(1),
            order: Some(bollard::models::ServiceSpecRollbackConfigOrderEnum::STOP_FIRST),
            failure_action: Some(
                bollard::models::ServiceSpecRollbackConfigFailureActionEnum::PAUSE,
            ),
            monitor: Some(30 * NS),
            max_failure_ratio: Some(0.0),
            delay: Some(5 * NS),
        }
    }

    fn to_bollard(spec: &ServiceSpec) -> bollard::models::ServiceSpec {
        let mut labels: HashMap<String, String> = spec.labels.iter().cloned().collect();
        labels.insert(MANAGED_LABEL.to_string(), "true".to_string());

        bollard::models::ServiceSpec {
            name: Some(spec.name.clone()),
            labels: Some(labels),
            task_template: Some(TaskSpec {
                container_spec: Some(TaskSpecContainerSpec {
                    image: Some(spec.image.clone()),
                    command: if spec.command.is_empty() {
                        None
                    } else {
                        Some(spec.command.clone())
                    },
                    env: Some(
                        spec.env
                            .iter()
                            .map(|(k, v)| format!("{k}={v}"))
                            .collect(),
                    ),

                    // §9 — durcissement effectivement transmis à Swarm, pas
                    // seulement déclaré dans le manifest.
                    read_only: Some(spec.hardening.read_only_rootfs),
                    user: spec.hardening.user.clone(),
                    capability_drop: if spec.hardening.cap_drop.is_empty() {
                        None
                    } else {
                        Some(spec.hardening.cap_drop.clone())
                    },
                    capability_add: if spec.hardening.cap_add.is_empty() {
                        None
                    } else {
                        Some(spec.hardening.cap_add.clone())
                    },
                    // `no-new-privileges` n'a pas de champ dédié : il passe par les
                    // options de sécurité, comme en ligne de commande Docker.
                    privileges: Some(TaskSpecContainerSpecPrivileges {
                        no_new_privileges: Some(spec.hardening.no_new_privileges),
                        ..Default::default()
                    }),

                    // Les volumes déclarés sont réellement attachés : sans ça, les
                    // données vivraient dans la couche éphémère du conteneur.
                    mounts: if spec.mounts.is_empty() {
                        None
                    } else {
                        Some(
                            spec.mounts
                                .iter()
                                .map(|(vol, path)| Mount {
                                    target: Some(path.clone()),
                                    source: Some(vol.clone()),
                                    typ: Some(MountTypeEnum::VOLUME),
                                    ..Default::default()
                                })
                                .collect(),
                        )
                    },

                    health_check: spec.healthcheck.as_ref().map(|h| HealthConfig {
                        test: Some(h.test.clone()),
                        // Swarm attend des nanosecondes.
                        interval: Some((h.interval_secs * 1_000_000_000) as i64),
                        timeout: Some((h.timeout_secs * 1_000_000_000) as i64),
                        retries: Some(h.retries as i64),
                        start_period: Some((h.start_period_secs * 1_000_000_000) as i64),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                placement: Some(TaskSpecPlacement {
                    constraints: Some(spec.constraints.clone()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            mode: Some(match spec.mode {
                crate::ServiceMode::Global => ServiceSpecMode {
                    // `replicas` n'a pas de sens ici : Swarm en place exactement un
                    // par nœud, et en ajoute un automatiquement à chaque nouveau nœud.
                    // Le mode global se signale par un objet vide dans l'API Docker.
                    global: Some(HashMap::new()),
                    ..Default::default()
                },
                crate::ServiceMode::Replicated => ServiceSpecMode {
                    replicated: Some(ServiceSpecModeReplicated {
                        replicas: Some(spec.replicas as i64),
                    }),
                    ..Default::default()
                },
            }),
            update_config: Some(Self::update_config()),
            rollback_config: Some(Self::rollback_config()),
            ..Default::default()
        }
    }

    /// Compte les tâches réellement en cours d'exécution.
    ///
    /// ⚠️ Swarm garde l'historique des tâches mortes : `TaskInfo::est_vivante` exige
    /// `desired_state` **et** `state`, sinon on compte des cadavres. La règle vit là-bas
    /// et pas ici — deux implémentations finiraient par diverger, et la divergence
    /// donnerait un service qu'on croit debout.
    async fn running_tasks(&self, service: &str) -> Result<usize> {
        Ok(self
            .lire_taches(Some(service))
            .await?
            .iter()
            .filter(|t| t.est_vivante())
            .count())
    }

    /// Les tâches, telles que Swarm les rend.
    ///
    /// Sans filtre d'état : les tâches mortes sont ce qui explique une panne.
    async fn lire_taches(&self, service: Option<&str>) -> Result<Vec<TaskInfo>> {
        let mut filters = HashMap::new();
        match service {
            Some(s) => {
                filters.insert("service".to_string(), vec![s.to_string()]);
            }
            None => {
                // Sans filtre de service, on se restreint à ce que Homelabus gère :
                // les autres services du Swarm ne nous regardent pas, et les afficher
                // laisserait croire qu'on les pilote.
                filters.insert("label".to_string(), vec![MANAGED_LABEL.to_string()]);
            }
        }

        let opts = ListTasksOptionsBuilder::default().filters(&filters).build();
        let tasks = self.docker.list_tasks(Some(opts)).await?;

        Ok(tasks.iter().map(Self::vers_task_info).collect())
    }

    fn vers_task_info(t: &bollard::models::Task) -> TaskInfo {
        let statut = t.status.as_ref();
        TaskInfo {
            id: t.id.clone().unwrap_or_default(),
            service: t
                .service_id
                .clone()
                // Le nom du service est plus utile que son identifiant, mais Swarm ne
                // le met pas dans la tâche : le label posé au déploiement le porte.
                .or_else(|| t.labels.as_ref().and_then(|l| l.get("com.docker.swarm.service.name").cloned()))
                .unwrap_or_default(),
            slot: t.slot.map(|s| s as u64),
            node_id: t.node_id.clone().filter(|n| !n.is_empty()),
            desired_state: t
                .desired_state
                .map(|d| format!("{d:?}").to_lowercase())
                .unwrap_or_default(),
            state: statut
                .and_then(|s| s.state)
                .map(|s| format!("{s:?}").to_lowercase())
                .unwrap_or_default(),
            image: t
                .spec
                .as_ref()
                .and_then(|sp| sp.container_spec.as_ref())
                .and_then(|c| c.image.clone())
                .unwrap_or_default(),
            message: statut.and_then(|s| s.message.clone()).filter(|m| !m.is_empty()),
            err: statut.and_then(|s| s.err.clone()).filter(|e| !e.is_empty()),
            updated_at: statut
                .and_then(|s| s.timestamp.as_deref())
                .and_then(horodatage_unix),
        }
    }

    fn parse_update_state(s: Option<&str>) -> Option<UpdateState> {
        s.map(|s| match s {
            "updating" => UpdateState::Updating,
            "paused" => UpdateState::Paused,
            "completed" => UpdateState::Completed,
            "rollback_started" => UpdateState::RollbackStarted,
            "rollback_paused" => UpdateState::RollbackPaused,
            "rollback_completed" => UpdateState::RollbackCompleted,
            _ => UpdateState::Unknown,
        })
    }

    async fn inspect(&self, name: &str) -> Result<bollard::models::Service> {
        self.docker
            .inspect_service(name, None::<bollard::query_parameters::InspectServiceOptions>)
            .await
            .map_err(|e| match e {
                bollard::errors::Error::DockerResponseServerError {
                    status_code: 404, ..
                } => Error::NotFound(name.to_string()),
                other => Error::Docker(other),
            })
    }

    fn to_status(svc: &bollard::models::Service, running: usize) -> ServiceStatus {
        let spec = svc.spec.as_ref();
        ServiceStatus {
            name: spec
                .and_then(|s| s.name.clone())
                .unwrap_or_default(),
            id: svc.id.clone().unwrap_or_default(),
            desired_replicas: spec
                .and_then(|s| s.mode.as_ref())
                .and_then(|m| m.replicated.as_ref())
                .and_then(|r| r.replicas)
                .unwrap_or(0) as u64,
            running_replicas: running,
            image: spec
                .and_then(|s| s.task_template.as_ref())
                .and_then(|t| t.container_spec.as_ref())
                .and_then(|c| c.image.clone())
                .unwrap_or_default(),
            update_state: Self::parse_update_state(
                svc.update_status
                    .as_ref()
                    .and_then(|u| u.state.as_ref())
                    .map(|s| s.to_string())
                    .as_deref(),
            ),
        }
    }
}

#[async_trait]
impl Orchestrator for SwarmOrchestrator {
    async fn ping(&self) -> Result<String> {
        let v = self.docker.version().await?;
        Ok(v.version.unwrap_or_else(|| "inconnue".into()))
    }

    async fn deploy(&self, spec: &ServiceSpec) -> Result<String> {
        let resp = self
            .docker
            .create_service(Self::to_bollard(spec), None)
            .await?;
        resp.id
            .ok_or_else(|| Error::Unexpected("création sans identifiant".into()))
    }

    async fn update_image(&self, name: &str, image: &str) -> Result<()> {
        let current = self.inspect(name).await?;

        // Swarm exige la version courante : c'est du contrôle de concurrence
        // optimiste. Sans elle, deux mises à jour simultanées s'écrasent.
        let version = current
            .version
            .and_then(|v| v.index)
            .ok_or_else(|| Error::Unexpected("service sans version".into()))?;

        let mut spec = current
            .spec
            .ok_or_else(|| Error::Unexpected("service sans spec".into()))?;

        // On ne remplace que l'image : tout le reste de la spec est conservé tel quel.
        if let Some(tt) = spec.task_template.as_mut() {
            if let Some(cs) = tt.container_spec.as_mut() {
                cs.image = Some(image.to_string());
            }
        }
        // Et on réaffirme la politique, au cas où le service aurait été créé ailleurs.
        spec.update_config = Some(Self::update_config());
        spec.rollback_config = Some(Self::rollback_config());

        let opts = UpdateServiceOptionsBuilder::default()
            .version(version as i32)
            .build();

        self.docker.update_service(name, spec, opts, None).await?;
        Ok(())
    }

    async fn scale(&self, name: &str, replicas: u64) -> Result<()> {
        let current = self.inspect(name).await?;
        let version = current
            .version
            .and_then(|v| v.index)
            .ok_or_else(|| Error::Unexpected("service sans version".into()))?;

        let mut spec = current
            .spec
            .ok_or_else(|| Error::Unexpected("service sans spec".into()))?;

        // On ne touche qu'au mode : le reste de la spec est conservé intact.
        spec.mode = Some(ServiceSpecMode {
            replicated: Some(ServiceSpecModeReplicated {
                replicas: Some(replicas as i64),
            }),
            ..Default::default()
        });

        let opts = UpdateServiceOptionsBuilder::default()
            .version(version as i32)
            .build();

        self.docker.update_service(name, spec, opts, None).await?;
        Ok(())
    }

    async fn cluster_init(&self, advertise_addr: Option<&str>) -> Result<String> {
        // Idempotent : réinitialiser un Swarm actif détruirait le cluster existant.
        if let Ok(s) = self.docker.inspect_swarm().await {
            if let Some(id) = s.id {
                tracing::debug!("Swarm déjà actif, conservé");
                return Ok(id);
            }
        }

        let opts = SwarmInitRequest {
            listen_addr: Some("0.0.0.0:2377".to_string()),
            // 🔴 Sans adresse annoncée explicite, Docker en choisit une — souvent la
            // mauvaise sur une machine multi-interfaces, et les nœuds tentent alors
            // de joindre une IP injoignable.
            advertise_addr: Some(advertise_addr.unwrap_or("127.0.0.1").to_string()),
            ..Default::default()
        };

        let id = self.docker.init_swarm(opts).await?;
        tracing::info!(%id, "Swarm initialisé");
        Ok(id)
    }

    async fn enable_autolock(&self) -> Result<String> {
        // ⚠️ `bollard` 0.19 n'expose ni `update_swarm` ni `get_swarm_unlock_key`.
        // On passe donc par le CLI Docker pour cette opération précise — c'est la
        // seule du crate dans ce cas, et c'est dit plutôt que masqué.
        let out = tokio::process::Command::new("docker")
            .args(["swarm", "update", "--autolock=true"])
            .output()
            .await
            .map_err(|e| Error::Unexpected(format!("docker introuvable : {e}")))?;

        if !out.status.success() {
            return Err(Error::Unexpected(format!(
                "activation de l'autolock : {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }

        // La clé n'est disponible qu'APRÈS activation : la demander avant renverrait
        // une chaîne vide, qu'on aurait rangée au coffre en croyant l'affaire faite.
        let out = tokio::process::Command::new("docker")
            .args(["swarm", "unlock-key", "-q"])
            .output()
            .await
            .map_err(|e| Error::Unexpected(format!("docker introuvable : {e}")))?;

        let cle = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if cle.is_empty() {
            return Err(Error::Unexpected(
                "Swarm n'a pas renvoyé de clé de déverrouillage".into(),
            ));
        }

        tracing::info!("autolock activé");
        Ok(cle)
    }

    async fn autolock_enabled(&self) -> Result<bool> {
        let s = self.docker.inspect_swarm().await?;
        Ok(s.spec
            .and_then(|sp| sp.encryption_config)
            .and_then(|e| e.auto_lock_managers)
            .unwrap_or(false))
    }

    async fn join_tokens(&self) -> Result<cluster::JoinTokens> {
        let s = self.docker.inspect_swarm().await?;

        let tokens = s
            .join_tokens
            .ok_or_else(|| Error::Unexpected("Swarm sans jetons de rattachement".into()))?;

        // L'adresse annoncée vit dans l'info système, pas dans l'inspection du Swarm.
        let info = self.docker.info().await?;
        let addr = info
            .swarm
            .and_then(|s| s.node_addr)
            .filter(|a| !a.is_empty())
            .unwrap_or_else(|| "127.0.0.1".to_string());

        Ok(cluster::JoinTokens {
            manager: tokens.manager.unwrap_or_default(),
            worker: tokens.worker.unwrap_or_default(),
            advertise_addr: format!("{addr}:2377"),
        })
    }

    async fn nodes(&self) -> Result<Vec<cluster::NodeInfo>> {
        let nodes = self
            .docker
            .list_nodes(None::<ListNodesOptions>)
            .await?;

        Ok(nodes
            .into_iter()
            .map(|n| {
                let spec = n.spec.unwrap_or_default();
                let desc = n.description.unwrap_or_default();
                let status = n.status.unwrap_or_default();

                let role = match spec.role.map(|r| format!("{r:?}").to_lowercase()) {
                    Some(r) if r.contains("manager") => cluster::NodeRole::Manager,
                    _ => cluster::NodeRole::Worker,
                };

                cluster::NodeInfo {
                    id: n.id.unwrap_or_default(),
                    hostname: desc.hostname.unwrap_or_default(),
                    role,
                    status: status
                        .state
                        .map(|s| format!("{s:?}").to_lowercase())
                        .unwrap_or_else(|| "inconnu".into()),
                    availability: spec
                        .availability
                        .map(|a| format!("{a:?}").to_lowercase())
                        .unwrap_or_else(|| "inconnue".into()),
                    tier: spec.labels.as_ref().and_then(|l| l.get("tier").cloned()),
                    // 🔴 Lu depuis l'étiquette, jamais deviné : Swarm ne sait pas que
                    // deux VM partagent un fer. `None` = non déclaré, et ça doit se
                    // VOIR plutôt que de faire supposer que le nœud est isolé.
                    failure_domain: spec
                        .labels
                        .as_ref()
                        .and_then(|l| l.get(cluster::LABEL_FAILURE_DOMAIN).cloned()),
                    is_leader: n
                        .manager_status
                        .and_then(|m| m.leader)
                        .unwrap_or(false),
                    memory_mb: desc
                        .resources
                        .and_then(|r| r.memory_bytes)
                        .map(|b| (b / 1_048_576) as u64),
                }
            })
            .collect())
    }

    async fn label_node(&self, node: &str, key: &str, value: &str) -> Result<()> {
        let n = self.docker.inspect_node(node).await?;
        let version = n
            .version
            .and_then(|v| v.index)
            .ok_or_else(|| Error::Unexpected("nœud sans version".into()))?;

        let mut spec = n.spec.unwrap_or_default();
        let mut labels = spec.labels.unwrap_or_default();
        labels.insert(key.to_string(), value.to_string());
        spec.labels = Some(labels);

        let opts = UpdateNodeOptionsBuilder::default().version(version as i64).build();
        self.docker.update_node(node, spec, opts).await?;

        tracing::info!(node, key, value, "étiquette posée");
        Ok(())
    }

    async fn exec_in_service(&self, name: &str, cmd: &[String]) -> Result<ExecOutput> {
        // Un service n'a pas de conteneur : ses tâches en ont. On cherche donc une
        // tâche en cours et on entre dans SON conteneur.
        let mut filtres = HashMap::new();
        filtres.insert("service".to_string(), vec![name.to_string()]);
        filtres.insert("desired-state".to_string(), vec!["running".to_string()]);

        let opts = ListTasksOptionsBuilder::default().filters(&filtres).build();
        let taches = self.docker.list_tasks(Some(opts)).await?;

        let conteneur = taches
            .iter()
            .filter(|t| {
                t.status
                    .as_ref()
                    .and_then(|s| s.state.as_ref())
                    .is_some_and(|s| format!("{s:?}").to_lowercase().contains("running"))
            })
            .find_map(|t| {
                t.status
                    .as_ref()?
                    .container_status
                    .as_ref()?
                    .container_id
                    .clone()
            })
            .ok_or_else(|| {
                Error::Unexpected(format!(
                    "aucune tâche en cours pour « {name} » : impossible d'exécuter la commande"
                ))
            })?;

        let exec = self
            .docker
            .create_exec(
                &conteneur,
                CreateExecOptions {
                    cmd: Some(cmd.to_vec()),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    ..Default::default()
                },
            )
            .await?;

        let mut stdout = String::new();
        let mut stderr = String::new();

        if let StartExecResults::Attached { mut output, .. } =
            self.docker.start_exec(&exec.id, None::<StartExecOptions>).await?
        {
            use futures::StreamExt;
            while let Some(Ok(msg)) = output.next().await {
                match msg {
                    LogOutput::StdOut { message } => {
                        stdout.push_str(&String::from_utf8_lossy(&message));
                    }
                    LogOutput::StdErr { message } => {
                        stderr.push_str(&String::from_utf8_lossy(&message));
                    }
                    _ => {}
                }
            }
        }

        let info = self.docker.inspect_exec(&exec.id).await?;
        Ok(ExecOutput {
            exit_code: info.exit_code.unwrap_or(-1),
            stdout,
            stderr,
        })
    }

    async fn create_volume(&self, name: &str) -> Result<VolumeInfo> {
        // Un volume qui existe déjà porte des données : on ne le recrée jamais.
        if let Ok(v) = self.inspect_volume(name).await {
            tracing::debug!(name, "volume déjà présent, conservé");
            return Ok(VolumeInfo { existed: true, ..v });
        }

        let opts = CreateVolumeOptions {
            name: Some(name.to_string()),
            labels: Some(HashMap::from([(
                MANAGED_LABEL.to_string(),
                "true".to_string(),
            )])),
            ..Default::default()
        };

        let v = self.docker.create_volume(opts).await?;
        tracing::info!(name, mountpoint = %v.mountpoint, "volume créé");
        Ok(VolumeInfo {
            name: v.name,
            mountpoint: v.mountpoint,
            existed: false,
        })
    }

    async fn inspect_volume(&self, name: &str) -> Result<VolumeInfo> {
        let v = self
            .docker
            .inspect_volume(name)
            .await
            .map_err(|_| Error::NotFound(name.to_string()))?;
        Ok(VolumeInfo {
            name: v.name,
            mountpoint: v.mountpoint,
            existed: true,
        })
    }

    async fn status(&self, name: &str) -> Result<ServiceStatus> {
        let svc = self.inspect(name).await?;
        let running = self.running_tasks(name).await?;
        Ok(Self::to_status(&svc, running))
    }

    async fn list(&self) -> Result<Vec<ServiceStatus>> {
        let mut filters = HashMap::new();
        filters.insert("label".to_string(), vec![format!("{MANAGED_LABEL}=true")]);
        let opts = ListServicesOptionsBuilder::default().filters(&filters).build();

        let services = self.docker.list_services(Some(opts)).await?;

        let mut out = Vec::with_capacity(services.len());
        for svc in services {
            let name = svc
                .spec
                .as_ref()
                .and_then(|s| s.name.clone())
                .unwrap_or_default();
            let running = self.running_tasks(&name).await.unwrap_or(0);
            out.push(Self::to_status(&svc, running));
        }
        Ok(out)
    }

    async fn remove(&self, name: &str) -> Result<()> {
        self.docker.delete_service(name).await.map_err(|e| match e {
            bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            } => Error::NotFound(name.to_string()),
            other => Error::Docker(other),
        })
    }

    async fn tasks(&self, service: Option<&str>) -> Result<Vec<TaskInfo>> {
        self.lire_taches(service).await
    }

    async fn logs(&self, service: &str, lignes: u32) -> Result<Vec<LigneLog>> {
        use futures::StreamExt as _;

        // 🔴 Borné. Un service bavard laissé sans limite remplirait la mémoire du
        // controller — et c'est le controller qui tomberait, pas le service qu'on
        // cherchait à diagnostiquer.
        const PLAFOND: u32 = 2_000;
        let n = lignes.clamp(1, PLAFOND);

        let opts = bollard::query_parameters::LogsOptionsBuilder::default()
            .stdout(true)
            .stderr(true)
            // Sans horodatage, une ligne de journal ne se corrèle à rien : le seul
            // usage réel des logs est de les rapprocher d'un événement daté.
            .timestamps(true)
            .tail(&n.to_string())
            .build();

        let mut flux = self.docker.logs(service, Some(opts));
        let mut out = Vec::new();

        while let Some(morceau) = flux.next().await {
            let sortie = morceau?;
            let (erreur, brut) = match &sortie {
                LogOutput::StdErr { message } => (true, message),
                LogOutput::StdOut { message }
                | LogOutput::Console { message }
                | LogOutput::StdIn { message } => (false, message),
            };
            // ⚠️ `from_utf8_lossy` : un journal applicatif contient parfois des octets
            // qui ne sont pas de l'UTF-8 (couleurs ANSI tronquées, binaire). Échouer
            // priverait de TOUT le journal à cause d'une seule ligne.
            let texte = String::from_utf8_lossy(brut);
            let texte = texte.trim_end_matches(['\n', '\r']);

            // Docker préfixe chaque ligne de son horodatage RFC 3339 quand
            // `timestamps` est actif.
            let (at, ligne) = match texte.split_once(' ') {
                Some((h, reste)) => (horodatage_unix(h), reste.to_string()),
                None => (None, texte.to_string()),
            };

            out.push(LigneLog { at, erreur, ligne });
        }

        Ok(out)
    }

    async fn wait_healthy(&self, name: &str, timeout_secs: u64) -> Result<ServiceStatus> {
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);
        let mut last = self.status(name).await?;

        while tokio::time::Instant::now() < deadline {
            last = self.status(name).await?;

            // Inutile d'attendre la fin d'un timeout si Swarm a déjà annulé.
            if last.update_state.is_some_and(|s| s.is_failure()) {
                break;
            }
            if last.is_converged() {
                return Ok(last);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }

        Err(Error::HealthTimeout {
            service: name.to_string(),
            timeout_secs,
            running: last.running_replicas,
            desired: last.desired_replicas,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_timestamps_are_read_or_refused_never_guessed() {
        // 🔴 Un horodatage à moitié lu placerait une ligne de journal en 1970, et on
        // chercherait un problème d'horloge sur le nœud.
        assert_eq!(horodatage_unix("1970-01-01T00:00:00Z"), Some(0));
        // Valeurs de référence, calculées indépendamment (pas déduites du code testé).
        assert_eq!(horodatage_unix("2026-08-18T10:16:04.123456789Z"), Some(1_787_048_164));
        // Sans fraction ni « Z » : Docker varie selon les versions.
        assert_eq!(horodatage_unix("2026-08-18T10:16:04"), Some(1_787_048_164));

        // Une année bissextile séculaire : 2000 est bissextile, 1900 ne l'est pas.
        // La division naïve par 4 se trompe ici.
        assert_eq!(horodatage_unix("2000-03-01T00:00:00Z"), Some(951_868_800));

        for mauvais in ["", "pas une date", "2026-08-18", "2026/08/18T10:16:04Z", "T10:16:04"] {
            assert_eq!(horodatage_unix(mauvais), None, "{mauvais}");
        }
    }

    #[test]
    fn a_timestamp_round_trips_against_a_known_pair() {
        // Un contrôle croisé : 86 400 s après l'époque, c'est le 2 janvier 1970.
        assert_eq!(horodatage_unix("1970-01-02T00:00:00Z"), Some(86_400));
        // Et un an plus tard, 1971 : 365 jours (1970 n'est pas bissextile).
        assert_eq!(horodatage_unix("1971-01-01T00:00:00Z"), Some(31_536_000));
    }
}
