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

use hlb_orchestrator::{Orchestrator, ServiceSpec};
use hlb_resolver::{Action, Plan};
use hlb_state::{ActionStatus, State};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    State(#[from] hlb_state::Error),

    #[error(transparent)]
    Orchestrator(#[from] hlb_orchestrator::Error),

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
    /// Faux par défaut : on n'écrit rien tant que ce n'est pas demandé.
    apply: bool,
}

impl<'a, O: Orchestrator> Executor<'a, O> {
    pub fn new(orchestrator: &'a O, state: &'a State) -> Self {
        Self {
            orchestrator,
            state,
            apply: false,
        }
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
            if let Action::PendingGuideStep { id, title, blocking } = a {
                self.state.add_guide(app, id, title, *blocking).await?;
            }
        }

        let blocking = plan.blocking_steps().len();
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

            match self.execute_one(action).await {
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

    async fn execute_one(&self, action: &Action) -> Result<Step> {
        match action {
            Action::DeployService { name, image, replicas, constraints } => {
                let mut spec = ServiceSpec::new(name, image).replicas(*replicas);
                for c in constraints {
                    spec = spec.constraint(c);
                }
                self.orchestrator.deploy(&spec).await?;
                Ok(Step::Done)
            }

            Action::WaitHealthy { name, timeout_secs } => {
                self.orchestrator.wait_healthy(name, *timeout_secs).await?;
                Ok(Step::Done)
            }

            // Les guides ne sont pas « exécutés » : ils sont posés dans la file et
            // c'est l'utilisateur qui agit.
            Action::PendingGuideStep { .. } => Ok(Step::Done),

            // Le reste demande des briques qui n'existent pas encore (provisionneur
            // Postgres, coffre de secrets, client PocketID, générateur Caddyfile,
            // veilleur de registre). On l'enregistre honnêtement.
            Action::ProvisionDatabase { .. }
            | Action::GenerateSecret { .. }
            | Action::CreateOidcClient { .. }
            | Action::CreateVolume { .. }
            | Action::ProvisionMailAccount { .. }
            | Action::ResolveDigest { .. }
            | Action::ConfigureIngress { .. } => Ok(Step::NotImplemented),
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
        async fn update_image(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
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
            Ok(vec![])
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
    }
}
