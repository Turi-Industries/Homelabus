//! L'exécuteur : applique un plan, action par action.
//!
//! Trois propriétés imposées par le §2ter.5, dès le départ et non rétrofitées :
//!
//! - **Aperçu par défaut.** Rien n'est modifié sans `--apply` explicite.
//! - **Idempotence.** Relancer sur une app déjà installée ne casse rien.
//! - **Reprise.** Un échec à l'action 4/10 reprend à 4, pas à zéro.
//!
//! Et une règle d'honnêteté : une action non implémentée est enregistrée comme telle
//! (`Unimplemented`), **jamais** comme réussie.

pub mod reconcile;

pub use reconcile::{Drift, Reconciler, Report};

use hlb_orchestrator::{Orchestrator, ServiceSpec};
use hlb_platform::{MariadbProvisioner, PostgresProvisioner};
use hlb_identity::PocketId;
use hlb_ingress::CaddyAdmin;
use hlb_mail::Stalwart;
use hlb_registry::{ImageRef, RegistryClient};
use hlb_resolver::{Action, Plan};
use hlb_secrets::Vault;
use hlb_state::{ActionStatus, State};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    State(#[from] hlb_state::Error),

    #[error(transparent)]
    Orchestrator(#[from] hlb_orchestrator::Error),

    #[error(transparent)]
    Secrets(#[from] hlb_secrets::Error),

    #[error(transparent)]
    Platform(#[from] hlb_platform::Error),

    #[error(transparent)]
    Registry(#[from] hlb_registry::Error),

    #[error(transparent)]
    Identity(#[from] hlb_identity::Error),

    #[error(transparent)]
    Ingress(#[from] hlb_ingress::Error),

    #[error(transparent)]
    Mail(#[from] hlb_mail::Error),

    #[error("le secret « {0} » est introuvable — le plan a-t-il été exécuté dans l'ordre ?")]
    MissingSecret(String),

    #[error("{blocking} action(s) manuelle(s) bloquante(s) en attente — \
             traite-les puis relance (hlb todo)")]
    BlockedByGuide { blocking: usize },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Ce qui a été fait, pour le compte rendu.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub executed: usize,
    pub skipped: usize,
    pub unimplemented: usize,
    pub failed: Option<(usize, String)>,
}

impl Outcome {
    pub fn is_success(&self) -> bool {
        self.failed.is_none()
    }
}

pub struct Executor<'a, O: Orchestrator> {
    orchestrator: &'a O,
    state: &'a State,
    /// Absent tant que la clé maîtresse n'est pas chargée : sans coffre, aucun
    /// secret ne peut être généré ni relu.
    vault: Option<&'a Vault>,
    /// Absent tant que PostgreSQL n'est pas déployé et joignable.
    postgres: Option<&'a PostgresProvisioner>,
    /// Idem pour MariaDB. Les deux peuvent coexister : des apps différentes ont des
    /// exigences différentes, et le résolveur choisit par manifest.
    mariadb: Option<&'a MariadbProvisioner>,
    /// Absent hors ligne : sans registre, aucun digest ne peut être résolu.
    registry: Option<&'a RegistryClient>,
    /// Absent tant que PocketID n'est pas déployé et qu'on n'a pas de clé d'API.
    identity: Option<&'a PocketId>,
    /// Absent si Caddy n'est pas encore joignable : l'app est déployée mais pas
    /// encore routée, ce qui est un état légitime.
    ingress: Option<&'a CaddyAdmin>,
    mail: Option<&'a Stalwart>,
    /// URL de l'API CrowdSec. Absente : pas de filtrage réputationnel.
    crowdsec_url: Option<String>,
    /// Faux par défaut : on n'écrit rien tant que ce n'est pas demandé.
    apply: bool,
}

impl<'a, O: Orchestrator> Executor<'a, O> {
    pub fn new(orchestrator: &'a O, state: &'a State) -> Self {
        Self {
            orchestrator,
            state,
            vault: None,
            postgres: None,
            mariadb: None,
            registry: None,
            identity: None,
            ingress: None,
            mail: None,
            crowdsec_url: None,
            apply: false,
        }
    }

    pub fn with_vault(mut self, vault: &'a Vault) -> Self {
        self.vault = Some(vault);
        self
    }

    pub fn with_postgres(mut self, pg: &'a PostgresProvisioner) -> Self {
        self.postgres = Some(pg);
        self
    }

    pub fn with_mariadb(mut self, my: &'a MariadbProvisioner) -> Self {
        self.mariadb = Some(my);
        self
    }

    pub fn with_registry(mut self, r: &'a RegistryClient) -> Self {
        self.registry = Some(r);
        self
    }

    pub fn with_identity(mut self, p: &'a PocketId) -> Self {
        self.identity = Some(p);
        self
    }

    pub fn with_ingress(mut self, c: &'a CaddyAdmin) -> Self {
        self.ingress = Some(c);
        self
    }

    pub fn with_mail(mut self, s: &'a Stalwart) -> Self {
        self.mail = Some(s);
        self
    }

    pub fn with_crowdsec(mut self, url: impl Into<String>) -> Self {
        self.crowdsec_url = Some(url.into());
        self
    }

    /// Passe en mode application réelle. L'appelant doit le vouloir explicitement.
    pub fn apply(mut self, yes: bool) -> Self {
        self.apply = yes;
        self
    }

    /// Exécute le plan pour `app`.
    ///
    /// Les actions manuelles bloquantes arrêtent l'exécution **avant** toute
    /// modification (§4.6) : inutile de déployer une app dont le DNS n'existe pas.
    pub async fn run(&self, app: &str, plan: &Plan) -> Result<Outcome> {
        let records: Vec<(String, String)> = plan
            .actions
            .iter()
            .map(|a| (kind_of(a).to_string(), a.to_string()))
            .collect();
        self.state.record_plan(app, &records).await?;

        // Les guides sont enregistrés même en aperçu : ils décrivent du travail réel.
        for a in &plan.actions {
            if let Action::PendingGuideStep { id, title, blocking, .. } = a {
                self.state.add_guide(app, id, title, *blocking).await?;
            }
        }

        // On interroge l'état, pas le plan : une action déjà traitée par
        // l'utilisateur ne doit plus bloquer.
        let blocking = self.state.unverified_blocking(app).await?;
        if blocking > 0 && self.apply {
            return Err(Error::BlockedByGuide { blocking });
        }

        let done = self.state.completed_seqs(app).await?;
        let mut out = Outcome::default();

        for (seq, action) in plan.actions.iter().enumerate() {
            if done.contains(&(seq as i64)) {
                out.skipped += 1;
                tracing::debug!(seq, "déjà fait, ignoré");
                continue;
            }

            if !self.apply {
                out.executed += 1;
                continue;
            }

            match self.execute_one(app, action).await {
                Ok(Step::Done) => {
                    self.state
                        .set_action_status(app, seq, ActionStatus::Done, None)
                        .await?;
                    out.executed += 1;
                }
                Ok(Step::NotImplemented) => {
                    self.state
                        .set_action_status(app, seq, ActionStatus::Unimplemented, None)
                        .await?;
                    out.unimplemented += 1;
                }
                Err(e) => {
                    let msg = e.to_string();
                    self.state
                        .set_action_status(app, seq, ActionStatus::Failed, Some(&msg))
                        .await?;
                    self.state.set_app_status(app, "failed").await?;
                    out.failed = Some((seq, msg));
                    // On s'arrête net : continuer après un échec de dépendance ne
                    // produirait que des erreurs en cascade.
                    return Ok(out);
                }
            }
        }

        if self.apply {
            let status = if out.unimplemented > 0 { "partial" } else { "running" };
            self.state.set_app_status(app, status).await?;
        }

        Ok(out)
    }

    /// La configuration d'entrée, CrowdSec compris quand il est enrôlé.
    ///
    /// 🔴 CrowdSec n'est activé QUE si sa clé de videur est au coffre. Sans elle, on
    /// génère un Caddyfile sans videur plutôt qu'un Caddyfile avec une clé vide : ce
    /// dernier démarrerait normalement et ne bloquerait plus rien, en silence.
    async fn ingress_config(&self) -> Result<hlb_ingress::Config> {
        let mut cfg = hlb_ingress::Config::default();

        let (Some(vault), Some(url)) = (self.vault, &self.crowdsec_url) else {
            return Ok(cfg);
        };

        match self.state.secret(hlb_ingress::crowdsec::SECRET_NAME).await? {
            Some(ct) => {
                let cle = vault.decrypt(&ct)?;
                if hlb_ingress::crowdsec::looks_like_key(&cle) {
                    cfg.crowdsec = Some(hlb_ingress::CrowdSec {
                        api_url: url.clone(),
                        api_key: cle,
                    });
                } else {
                    // Une clé abîmée au coffre ne doit pas produire un videur muet.
                    tracing::error!(
                        "🔴 clé de videur CrowdSec invalide au coffre — filtrage DÉSACTIVÉ ; \
                         réenrôle avec `hlb crowdsec enroll --apply`"
                    );
                }
            }
            None => tracing::warn!(
                "CrowdSec non enrôlé : le trafic n'est pas filtré \
                 (hlb crowdsec enroll --apply)"
            ),
        }
        Ok(cfg)
    }

    /// Les routes de toutes les apps installées.
    ///
    /// Recalculées depuis l'état à chaque fois : c'est le manifest figé qui fait foi
    /// (§4.8), pas le catalogue courant.
    async fn all_routes(&self) -> Result<Vec<hlb_ingress::Route>> {
        let mut routes = Vec::new();
        for (name, status) in self.state.installed_apps().await? {
            if status == "failed" {
                continue;
            }
            let m = self.state.app_manifest(&name).await?;
            let domain = self.state.app_domain(&name).await?;
            // §4.6bis — la route ne s'ouvre qu'une fois les actions bloquantes traitées.
            let cleared = self.state.unverified_blocking(&name).await? == 0;
            routes.extend(hlb_ingress::routes_from_manifest(&m, domain.as_deref(), cleared));
        }
        Ok(routes)
    }

    async fn execute_one(&self, app: &str, action: &Action) -> Result<Step> {
        match action {
            Action::DeployService {
                name, image, replicas, constraints, env, mounts, hardening, healthcheck,
            } => {
                // ⚠️ Le plan a été construit AVANT l'exécution, donc son champ `image`
                // porte encore le tag. Le digest résolu à l'étape précédente vit dans
                // l'état — c'est lui qui fait foi (§7).
                let resolved = match self.state.app_manifest(app).await {
                    Ok(m) if m.spec.image.is_pinned() => m.spec.image.reference(),
                    _ => image.clone(),
                };

                let mut spec = ServiceSpec::new(name, &resolved)
                    .replicas(*replicas)
                    .env(env.clone())
                    // §9 — le durcissement déclaré au manifest est réellement appliqué.
                    .hardening(hardening.clone());

                if let Some(h) = healthcheck {
                    spec = spec.healthcheck(h.clone());
                }
                for c in constraints {
                    spec = spec.constraint(c);
                }
                for (vol, path) in mounts {
                    spec = spec.mount(vol, path);
                }
                self.orchestrator.deploy(&spec).await?;
                Ok(Step::Done)
            }

            Action::WaitHealthy { name, timeout_secs } => {
                self.orchestrator.wait_healthy(name, *timeout_secs).await?;
                Ok(Step::Done)
            }

            Action::GenerateSecret { name, purpose } => {
                let Some(vault) = self.vault else {
                    return Ok(Step::NotImplemented);
                };

                let password = hlb_secrets::generate_password(
                    hlb_secrets::DEFAULT_PASSWORD_LEN,
                );
                let ct = vault.encrypt(&password)?;

                // `if_absent` : un mot de passe déjà injecté dans un service ne doit
                // jamais changer sous ses pieds à la relance d'un plan.
                let created = self.state.store_secret_if_absent(name, &ct, purpose).await?;
                if created {
                    tracing::info!(secret = name, "secret généré");
                }
                Ok(Step::Done)
            }

            Action::ProvisionDatabase { engine, database, role, password_secret } => {
                let Some(vault) = self.vault else {
                    return Ok(Step::NotImplemented);
                };

                let ct = self
                    .state
                    .secret(password_secret)
                    .await?
                    .ok_or_else(|| Error::MissingSecret(password_secret.clone()))?;
                let password = vault.decrypt(&ct)?;

                // 🔴 Le `match` est exhaustif : ajouter un moteur à `DbEngine` fait
                // échouer la compilation ici, ce qui force à décider comment le
                // provisionner plutôt que de le laisser tomber dans un cas par défaut
                // qui prétendrait avoir réussi.
                let created = match engine {
                    hlb_types::DbEngine::Postgres => {
                        let Some(pg) = self.postgres else {
                            return Ok(Step::NotImplemented);
                        };
                        pg.provision(database, role, &password).await?
                    }
                    hlb_types::DbEngine::Mariadb => {
                        let Some(my) = self.mariadb else {
                            return Ok(Step::NotImplemented);
                        };
                        my.provision(database, role, &password).await?
                    }
                };

                if created {
                    tracing::info!(database, role, moteur = ?engine, "base provisionnée");
                }
                Ok(Step::Done)
            }

            Action::PendingGuideStep { id, service, step, .. } => {
                // §4.6bis — on tente d'abord de s'en occuper tout seul. Beaucoup
                // d'étapes « dans l'application » se scriptent ; les traiter comme
                // manuelles par défaut est l'erreur habituelle.
                let issue = hlb_guide::try_automate(self.orchestrator, service, step, &[]).await;

                if issue.handled() {
                    tracing::info!(step = %id, "{}", issue.describe());
                    // L'étape est faite : elle ne doit plus bloquer.
                    self.state.verify_guide(app, id).await?;
                } else if !matches!(issue, hlb_guide::AutomationOutcome::NothingDeclared) {
                    // On dit POURQUOI ça reste manuel : sans ça, l'utilisateur ne
                    // saurait pas pourquoi le système lui demande de faire ce qu'il
                    // annonçait automatiser.
                    tracing::warn!(step = %id, "{}", issue.describe());
                }
                Ok(Step::Done)
            }

            Action::ResolveDigest { repo, tag } => {
                let Some(reg) = self.registry else {
                    return Ok(Step::NotImplemented);
                };

                let image = ImageRef::parse(&format!("{repo}:{tag}"));
                let digest = reg.resolve_digest(&image).await?;

                // §7 — le digest est figé dans l'état : c'est lui qui sera déployé,
                // pas le tag, qui est mutable.
                self.state.set_app_digest(app, &digest).await?;
                tracing::info!(%image, digest, "digest résolu");
                Ok(Step::Done)
            }

            Action::CreateVolume { name, backup, .. } => {
                let info = self.orchestrator.create_volume(name).await?;

                // On mémorise le point de montage RÉEL : c'est ce que la sauvegarde
                // ira lire (§8). Sans lui, on ne sait pas quoi sauvegarder.
                self.state
                    .add_volume(app, &info.name, &info.mountpoint, *backup)
                    .await?;

                if info.existed {
                    tracing::info!(name, "volume existant conservé (il porte des données)");
                }
                Ok(Step::Done)
            }

            Action::CreateOidcClient { app: client, redirect_uris } => {
                let (Some(pid), Some(vault)) = (self.identity, self.vault) else {
                    return Ok(Step::NotImplemented);
                };

                // Idempotent : un client existant est conservé, et son secret n'est
                // JAMAIS régénéré — il est déjà injecté dans l'app qui tourne (§5.2).
                let creds = pid.ensure(client, redirect_uris, true).await?;

                let secret_name = format!("{app}-oidc-secret");
                match creds.client_secret {
                    Some(s) => {
                        let ct = vault.encrypt(&s)?;
                        self.state
                            .store_secret_if_absent(&secret_name, &ct, "client secret OIDC")
                            .await?;
                    }
                    None => {
                        // Client déjà provisionné : le secret correspondant doit être
                        // au coffre. S'il n'y est pas, on ne peut plus le retrouver —
                        // PocketID ne le redonne jamais sans le régénérer.
                        if self.state.secret(&secret_name).await?.is_none() {
                            return Err(Error::MissingSecret(format!(
                                "{secret_name} — le client OIDC « {client} » existe dans \
                                 PocketID mais son secret est absent du coffre ; \
                                 supprime le client pour le reprovisionner"
                            )));
                        }
                    }
                }

                self.state
                    .store_secret_if_absent(
                        &format!("{app}-oidc-client-id"),
                        &vault.encrypt(&creds.client_id)?,
                        "identifiant du client OIDC",
                    )
                    .await?;

                Ok(Step::Done)
            }

            Action::ConfigureIngress { .. } => {
                let Some(caddy) = self.ingress else {
                    return Ok(Step::NotImplemented);
                };

                // ⚠️ On régénère la configuration COMPLÈTE, pas seulement la route de
                // cette app. Caddy remplace toute sa config à chaque `/load` : envoyer
                // un fragment supprimerait les routes des autres apps.
                let routes = self.all_routes().await?;
                let cfg = self.ingress_config().await?;
                caddy
                    .load_caddyfile(&hlb_ingress::render_frontend(&routes, &cfg))
                    .await?;

                tracing::info!(routes = routes.len(), "configuration Caddy rechargée");
                Ok(Step::Done)
            }

            Action::ProvisionMailAccount { address, aliases } => {
                let (Some(mail), Some(vault)) = (self.mail, self.vault) else {
                    return Ok(Step::NotImplemented);
                };

                // Le mot de passe vit au coffre, comme les autres. `if_absent` :
                // relancer un plan ne doit pas en fabriquer un second, qui ne
                // correspondrait plus à celui déposé dans Stalwart.
                let secret_name = format!("{app}-mail-password");
                let password = match self.state.secret(&secret_name).await? {
                    Some(ct) => vault.decrypt(&ct)?,
                    None => {
                        let p = hlb_secrets::generate_password(
                            hlb_secrets::DEFAULT_PASSWORD_LEN,
                        );
                        self.state
                            .store_secret_if_absent(
                                &secret_name,
                                &vault.encrypt(&p)?,
                                "mot de passe IMAP/SMTP",
                            )
                            .await?;
                        p
                    }
                };

                // Les aliases déclarés au manifest sont un booléen : « cette app a
                // le droit d'en avoir ». Elle n'en réclame aucun à l'installation —
                // ils se créent à l'usage (§5.9).
                let demandes: Vec<String> = Vec::new();
                let p = mail.ensure_account(address, &password, &demandes).await?;

                if p.created {
                    tracing::info!(adresse = %p.address, "boîte mail créée");
                } else {
                    // 🔴 Conséquence concrète : le mot de passe du coffre est celui
                    // d'avant, et on n'y a PAS touché. Le changer couperait l'accès
                    // IMAP de l'app qui tourne.
                    tracing::debug!(adresse = %p.address, "boîte déjà présente, conservée");
                }
                let _ = aliases;
                Ok(Step::Done)
            }
        }
    }
}

enum Step {
    Done,
    NotImplemented,
}

/// Étiquette courte et stable, stockée en base et affichée dans les rapports.
fn kind_of(a: &Action) -> &'static str {
    match a {
        Action::ProvisionDatabase { .. } => "ProvisionDatabase",
        Action::GenerateSecret { .. } => "GenerateSecret",
        Action::CreateOidcClient { .. } => "CreateOidcClient",
        Action::CreateVolume { .. } => "CreateVolume",
        Action::ProvisionMailAccount { .. } => "ProvisionMailAccount",
        Action::DeployService { .. } => "DeployService",
        Action::ResolveDigest { .. } => "ResolveDigest",
        Action::WaitHealthy { .. } => "WaitHealthy",
        Action::ConfigureIngress { .. } => "ConfigureIngress",
        Action::PendingGuideStep { .. } => "PendingGuideStep",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hlb_orchestrator::{ServiceStatus, UpdateState};
    use std::sync::Mutex;

    /// Orchestrateur factice : enregistre les appels, peut échouer à la demande.
    #[derive(Default)]
    struct Fake {
        deployed: Mutex<Vec<String>>,
        waited: Mutex<Vec<String>>,
        updated: Mutex<Vec<(String, String)>>,
        scaled: Mutex<Vec<(String, u64)>>,
        /// Ce que `list()` renverra : l'état « observé » du cluster.
        observed: Mutex<Vec<ServiceStatus>>,
        fail_deploy: bool,
    }

    #[async_trait]
    impl Orchestrator for Fake {
        async fn ping(&self) -> hlb_orchestrator::Result<String> {
            Ok("fake".into())
        }
        async fn deploy(&self, s: &ServiceSpec) -> hlb_orchestrator::Result<String> {
            if self.fail_deploy {
                return Err(hlb_orchestrator::Error::Unexpected("échec simulé".into()));
            }
            self.deployed.lock().expect("mutex").push(s.name.clone());
            Ok("id".into())
        }
        async fn update_image(&self, name: &str, image: &str) -> hlb_orchestrator::Result<()> {
            self.updated
                .lock()
                .expect("mutex")
                .push((name.into(), image.into()));
            Ok(())
        }
        async fn scale(&self, name: &str, replicas: u64) -> hlb_orchestrator::Result<()> {
            self.scaled.lock().expect("mutex").push((name.into(), replicas));
            Ok(())
        }
        async fn enable_autolock(&self) -> hlb_orchestrator::Result<String> {
            Ok("SWMKEY-fake".into())
        }
        async fn autolock_enabled(&self) -> hlb_orchestrator::Result<bool> {
            Ok(false)
        }
        async fn cluster_init(&self, _: Option<&str>) -> hlb_orchestrator::Result<String> {
            Ok("swarm-fake".into())
        }
        async fn join_tokens(&self) -> hlb_orchestrator::Result<hlb_orchestrator::JoinTokens> {
            Ok(hlb_orchestrator::JoinTokens {
                manager: "SWMTKN-mgr".into(),
                worker: "SWMTKN-wrk".into(),
                advertise_addr: "127.0.0.1:2377".into(),
            })
        }
        async fn nodes(&self) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::NodeInfo>> {
            Ok(Vec::new())
        }
        async fn label_node(&self, _: &str, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn exec_in_service(
            &self,
            _: &str,
            _: &[String],
        ) -> hlb_orchestrator::Result<hlb_orchestrator::ExecOutput> {
            Ok(hlb_orchestrator::ExecOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
        async fn create_volume(&self, n: &str) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
            Ok(hlb_orchestrator::VolumeInfo {
            name: n.into(),
            mountpoint: format!("/volumes/{n}"),
            existed: false,
            })
        }
        async fn inspect_volume(&self, n: &str) -> hlb_orchestrator::Result<hlb_orchestrator::VolumeInfo> {
        self.create_volume(n).await
        }
        async fn status(&self, name: &str) -> hlb_orchestrator::Result<ServiceStatus> {
            Ok(ServiceStatus {
                name: name.into(),
                id: "id".into(),
                desired_replicas: 1,
                running_replicas: 1,
                image: "img".into(),
                update_state: Some(UpdateState::Completed),
            })
        }
        async fn list(&self) -> hlb_orchestrator::Result<Vec<ServiceStatus>> {
            Ok(self.observed.lock().expect("mutex").clone())
        }
        async fn remove(&self, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn wait_healthy(
            &self,
            name: &str,
            _: u64,
        ) -> hlb_orchestrator::Result<ServiceStatus> {
            self.waited.lock().expect("mutex").push(name.into());
            self.status(name).await
        }
    }

    const BASE: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
"#;

    const WITH_DB: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  requires:
    - kind: database
      engine: postgres
"#;

    const WITH_GUIDE: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  ingress:
    - host: x.example.fr
      port: 80
      expose: after-guide
"#;

    fn manifest() -> hlb_types::Manifest {
        serde_yaml_ng::from_str(BASE).expect("manifest")
    }

    fn plan() -> Plan {
        hlb_resolver::resolve(&manifest(), &hlb_resolver::InstallParams::default())
            .expect("plan")
    }

    async fn state() -> State {
        let s = State::in_memory().await.expect("base");
        s.upsert_app("demo", &manifest(), None).await.expect("upsert");
        s
    }

    #[tokio::test]
    async fn preview_changes_nothing() {
        let o = Fake::default();
        let s = state().await;

        let out = Executor::new(&o, &s).run("demo", &plan()).await.expect("run");

        assert!(o.deployed.lock().unwrap().is_empty(), "aucun déploiement en aperçu");
        assert!(out.is_success());
        // Rien n'est marqué fait : l'aperçu ne consomme pas le plan.
        assert!(s.completed_seqs("demo").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn apply_deploys_and_waits() {
        let o = Fake::default();
        let s = state().await;

        let out = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &plan())
            .await
            .expect("run");

        assert_eq!(*o.deployed.lock().unwrap(), vec!["demo"]);
        assert_eq!(*o.waited.lock().unwrap(), vec!["demo"]);
        assert!(out.is_success());
        assert_eq!(out.executed, 2, "déploiement + attente");
    }

    #[tokio::test]
    async fn rerun_is_idempotent() {
        let o = Fake::default();
        let s = state().await;
        let p = plan();

        Executor::new(&o, &s).apply(true).run("demo", &p).await.unwrap();
        let second = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &p)
            .await
            .expect("second run");

        assert_eq!(
            o.deployed.lock().unwrap().len(),
            1,
            "le déploiement ne doit pas être rejoué"
        );
        assert_eq!(second.executed, 0);
        assert!(second.skipped >= 2);
    }

    #[tokio::test]
    async fn failure_stops_and_is_recorded() {
        let o = Fake {
            fail_deploy: true,
            ..Default::default()
        };
        let s = state().await;

        let out = Executor::new(&o, &s)
            .apply(true)
            .run("demo", &plan())
            .await
            .expect("run");

        assert!(!out.is_success());
        assert!(o.waited.lock().unwrap().is_empty(), "on s'arrête au premier échec");

        let recorded = s.plan_actions("demo").await.unwrap();
        let failed = recorded
            .iter()
            .find(|a| a.status == ActionStatus::Failed)
            .expect("échec enregistré");
        assert!(failed.error.as_deref().unwrap().contains("échec simulé"));
        assert_eq!(
            s.installed_apps().await.unwrap()[0].1,
            "failed",
            "l'app est marquée en échec"
        );
    }

    #[tokio::test]
    async fn resume_picks_up_after_the_failure() {
        let s = state().await;
        let p = plan();

        // Premier passage : échoue au déploiement.
        let failing = Fake { fail_deploy: true, ..Default::default() };
        Executor::new(&failing, &s).apply(true).run("demo", &p).await.unwrap();

        // Second passage, orchestrateur réparé.
        let ok = Fake::default();
        let out = Executor::new(&ok, &s).apply(true).run("demo", &p).await.unwrap();

        assert!(out.is_success());
        assert_eq!(*ok.deployed.lock().unwrap(), vec!["demo"]);
    }

    #[tokio::test]
    async fn unimplemented_is_never_reported_as_done() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_DB).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();
        let out = Executor::new(&o, &s).apply(true).run("demo", &p).await.unwrap();

        assert!(out.unimplemented >= 2, "base + secret non implémentés");
        assert_eq!(s.installed_apps().await.unwrap()[0].1, "partial");

        // Et surtout : rien n'est marqué `done` à tort.
        let recorded = s.plan_actions("demo").await.unwrap();
        let db = recorded
            .iter()
            .find(|a| a.kind == "ProvisionDatabase")
            .expect("action présente");
        assert_eq!(db.status, ActionStatus::Unimplemented);
    }

    const WITH_MAIL: &str = r#"
apiVersion: hlb/v1
kind: App
metadata: { name: demo }
spec:
  image: { repo: a/b, tag: "1", digest: "sha256:x" }
  requires:
    - kind: mail-account
      aliases: true
"#;

    #[tokio::test]
    async fn a_mailbox_is_never_pretended_without_a_stalwart() {
        // 🔴 Le même principe que pour la base de données : sans client Stalwart,
        // l'action est enregistrée « non implémentée », jamais « faite ». Rapporter
        // une boîte créée qui n'existe pas ferait échouer l'app au premier envoi.
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_MAIL).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let params = hlb_resolver::InstallParams {
            mail_domain: Some("example.fr".into()),
            ..Default::default()
        };
        let p = hlb_resolver::resolve(&m, &params).unwrap();

        Executor::new(&o, &s)
            .with_vault(&vault)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        let rec = s.plan_actions("demo").await.unwrap();
        let mail = rec
            .iter()
            .find(|a| a.kind == "ProvisionMailAccount")
            .expect("action présente");
        assert_eq!(mail.status, ActionStatus::Unimplemented);

        // Et aucun mot de passe n'a été fabriqué : il n'aurait correspondu à rien.
        assert!(s.secret("demo-mail-password").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn secrets_need_a_vault_and_are_never_faked() {
        // Sans coffre, la génération de secret est « non implémentée », jamais « faite ».
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_DB).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();
        Executor::new(&o, &s).apply(true).run("demo", &p).await.unwrap();

        let rec = s.plan_actions("demo").await.unwrap();
        let secret = rec.iter().find(|a| a.kind == "GenerateSecret").unwrap();
        assert_eq!(secret.status, ActionStatus::Unimplemented);
        assert!(s.secret("demo-db-password").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn with_a_vault_the_secret_is_generated_and_encrypted() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_DB).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();
        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();

        Executor::new(&o, &s)
            .with_vault(&vault)
            .apply(true)
            .run("demo", &p)
            .await
            .unwrap();

        let ct = s.secret("demo-db-password").await.unwrap().expect("secret stocké");
        let clear = vault.decrypt(&ct).expect("déchiffrable");
        assert_eq!(clear.len(), hlb_secrets::DEFAULT_PASSWORD_LEN);
        assert!(clear.chars().all(|c| c.is_ascii_alphanumeric()));

        // Le provisionnement reste non implémenté : pas de PostgreSQL fourni.
        let rec = s.plan_actions("demo").await.unwrap();
        let db = rec.iter().find(|a| a.kind == "ProvisionDatabase").unwrap();
        assert_eq!(db.status, ActionStatus::Unimplemented);
    }

    #[tokio::test]
    async fn a_replay_does_not_change_an_existing_password() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::init(dir.path().join("master.key")).unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_DB).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();
        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();

        let exec = || Executor::new(&o, &s).with_vault(&vault).apply(true);
        exec().run("demo", &p).await.unwrap();
        let first = s.secret("demo-db-password").await.unwrap().unwrap();

        // On force un rejeu en effaçant la progression.
        s.set_action_status("demo", 0, ActionStatus::Pending, None).await.unwrap();
        exec().run("demo", &p).await.unwrap();
        let second = s.secret("demo-db-password").await.unwrap().unwrap();

        assert_eq!(first, second, "le mot de passe ne doit pas changer sous les pieds du service");
    }

    #[tokio::test]
    async fn blocking_guide_prevents_apply() {
        let o = Fake::default();
        let s = State::in_memory().await.unwrap();

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(WITH_GUIDE).unwrap();
        s.upsert_app("demo", &m, None).await.unwrap();

        let p = hlb_resolver::resolve(&m, &hlb_resolver::InstallParams::default()).unwrap();
        let err = Executor::new(&o, &s).apply(true).run("demo", &p).await.unwrap_err();

        assert!(matches!(err, Error::BlockedByGuide { blocking: 1 }), "{err}");
        assert!(o.deployed.lock().unwrap().is_empty(), "rien déployé avant le guide");

        // Le guide est quand même enregistré : c'est du travail réel à faire.
        assert_eq!(s.pending_guides().await.unwrap().len(), 1);

        // Une fois traité, l'installation repart.
        s.verify_guide("demo", "demo-first-admin").await.unwrap();
        let out = Executor::new(&o, &s).apply(true).run("demo", &p).await.expect("run");
        assert!(out.is_success());
        assert_eq!(*o.deployed.lock().unwrap(), vec!["demo"]);
    }
}
