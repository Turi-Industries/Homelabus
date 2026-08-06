//! L'échelle d'automatisation des guides (§4.6bis).
//!
//! La plupart des étapes « dans l'application » se scriptent. Les traiter comme
//! manuelles par défaut est l'erreur habituelle : on documente une manipulation
//! alors qu'une commande suffirait.
//!
//! ## L'échelle n'est pas purement séquentielle
//!
//! | Niveau | Quand il s'applique |
//! |---|---|
//! | `env` | **au plan** — Swarm recrée la tâche, donc c'est un choix de déploiement |
//! | `exec` | après déploiement, sur un service sain |
//! | `api` | après déploiement, sur un service sain |
//!
//! Ce module ne traite donc que `exec` et `api`. Les variables d'environnement sont
//! résolues par le résolveur, parce qu'elles ne peuvent pas être appliquées après
//! coup : changer l'environnement d'un service impose de le redéployer.

use hlb_orchestrator::Orchestrator;
use hlb_types::{Automation, GuideStep};

/// Ce qu'une tentative d'automatisation a produit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutomationOutcome {
    /// Appliqué avec succès.
    Applied { method: &'static str },
    /// La sonde dit que c'était déjà fait : on ne rejoue pas.
    AlreadyDone { method: &'static str },
    /// Aucune tentative n'a abouti — l'étape reste manuelle.
    FellBackToManual { reasons: Vec<String> },
    /// Rien de déclaré : l'étape a toujours été manuelle.
    NothingDeclared,
}

impl AutomationOutcome {
    pub fn handled(&self) -> bool {
        matches!(self, Self::Applied { .. } | Self::AlreadyDone { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Applied { method } => format!("automatisée via {method}"),
            Self::AlreadyDone { method } => format!("déjà faite (détectée via {method})"),
            Self::FellBackToManual { reasons } => {
                format!("reste manuelle : {}", reasons.join(" ; "))
            }
            Self::NothingDeclared => "manuelle (aucune automatisation déclarée)".into(),
        }
    }
}

/// Tente d'exécuter une étape sans intervention humaine.
///
/// 🔴 On ne bascule en manuel qu'**après avoir essayé**, et l'échec de chaque
/// tentative est conservé : sans ça, l'utilisateur ne saurait pas pourquoi le
/// système lui demande de faire quelque chose qu'il prétendait automatiser.
pub async fn try_automate<O: Orchestrator>(
    orch: &O,
    service: &str,
    step: &GuideStep,
    vars: &[(&str, &str)],
) -> AutomationOutcome {
    if step.automate.is_empty() {
        return AutomationOutcome::NothingDeclared;
    }

    let mut raisons = Vec::new();

    for a in &step.automate {
        match a {
            // Résolu au plan : recréer le service ici serait destructeur et
            // dupliquerait la logique du résolveur.
            Automation::Env { .. } => continue,

            Automation::Exec { command, probe, probe_matches } => {
                // Sonde d'idempotence : ne pas rejouer une commande déjà appliquée.
                // Beaucoup de CLI d'apps échouent si l'objet existe déjà.
                if let Some(p) = probe {
                    let rendu: Vec<String> = p
                        .iter()
                        .map(|c| hlb_types::guide::render(c, vars))
                        .collect();
                    if let Ok(out) = orch.exec_in_service(service, &rendu).await {
                        let attendu = probe_matches.as_deref().unwrap_or("");
                        if out.ok() && (attendu.is_empty() || out.stdout.contains(attendu)) {
                            return AutomationOutcome::AlreadyDone { method: "exec" };
                        }
                    }
                }

                let rendu: Vec<String> = command
                    .iter()
                    .map(|c| hlb_types::guide::render(c, vars))
                    .collect();

                match orch.exec_in_service(service, &rendu).await {
                    Ok(out) if out.ok() => {
                        tracing::info!(step = %step.id, "étape automatisée par exec");
                        return AutomationOutcome::Applied { method: "exec" };
                    }
                    Ok(out) => raisons.push(format!(
                        "exec code {} : {}",
                        out.exit_code,
                        out.stderr.trim().lines().next().unwrap_or("").trim()
                    )),
                    Err(e) => raisons.push(format!("exec impossible : {e}")),
                }
            }

            // Demande un jeton d'API propre à l'app, qu'on n'a pas encore.
            Automation::Api { .. } => {
                raisons.push("automatisation par API non branchée".into());
            }
        }
    }

    if raisons.is_empty() {
        // Seules des automatisations `env` étaient déclarées : elles ont été
        // appliquées au déploiement, il n'y a rien à faire ici.
        return AutomationOutcome::Applied { method: "env" };
    }
    AutomationOutcome::FellBackToManual { reasons: raisons }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hlb_orchestrator::{ExecOutput, ServiceSpec, ServiceStatus, VolumeInfo};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        appels: Mutex<Vec<Vec<String>>>,
        /// Réponses successives ; la dernière est répétée.
        sorties: Mutex<Vec<ExecOutput>>,
    }

    impl Fake {
        fn with(sorties: Vec<ExecOutput>) -> Self {
            Self {
                appels: Mutex::new(Vec::new()),
                sorties: Mutex::new(sorties),
            }
        }
        fn ok() -> ExecOutput {
            ExecOutput { exit_code: 0, stdout: String::new(), stderr: String::new() }
        }
        fn ko(stderr: &str) -> ExecOutput {
            ExecOutput { exit_code: 1, stdout: String::new(), stderr: stderr.into() }
        }
        fn disant(stdout: &str) -> ExecOutput {
            ExecOutput { exit_code: 0, stdout: stdout.into(), stderr: String::new() }
        }
    }

    #[async_trait]
    impl Orchestrator for Fake {
        async fn ping(&self) -> hlb_orchestrator::Result<String> { Ok("fake".into()) }
        async fn deploy(&self, _: &ServiceSpec) -> hlb_orchestrator::Result<String> { Ok("id".into()) }
        async fn update_image(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> { Ok(()) }
        async fn scale(&self, _: &str, _: u64) -> hlb_orchestrator::Result<()> { Ok(()) }
        async fn exec_in_service(&self, _: &str, cmd: &[String]) -> hlb_orchestrator::Result<ExecOutput> {
            self.appels.lock().expect("mutex").push(cmd.to_vec());
            let mut s = self.sorties.lock().expect("mutex");
            Ok(if s.len() > 1 { s.remove(0) } else { s.first().cloned().unwrap_or(Fake::ok()) })
        }
        async fn create_volume(&self, n: &str) -> hlb_orchestrator::Result<VolumeInfo> {
            Ok(VolumeInfo { name: n.into(), mountpoint: "/v".into(), existed: false })
        }
        async fn inspect_volume(&self, n: &str) -> hlb_orchestrator::Result<VolumeInfo> {
            self.create_volume(n).await
        }
        async fn status(&self, _: &str) -> hlb_orchestrator::Result<ServiceStatus> {
            Err(hlb_orchestrator::Error::NotFound("x".into()))
        }
        async fn list(&self) -> hlb_orchestrator::Result<Vec<ServiceStatus>> { Ok(vec![]) }
        async fn remove(&self, _: &str) -> hlb_orchestrator::Result<()> { Ok(()) }
        async fn wait_healthy(&self, _: &str, _: u64) -> hlb_orchestrator::Result<ServiceStatus> {
            Err(hlb_orchestrator::Error::NotFound("x".into()))
        }
    }

    fn step(yaml: &str) -> GuideStep {
        let g: hlb_types::Guide = serde_yaml_ng::from_str(yaml).expect("guide de test");
        g.steps.into_iter().next().expect("une étape")
    }

    const AVEC_EXEC: &str = r#"
steps:
  - id: fermer
    title: Fermer les inscriptions
    automate:
      - method: exec
        command: [gitea, admin, config, set, service.DISABLE_REGISTRATION, "true"]
"#;

    #[tokio::test]
    async fn a_declared_command_is_executed() {
        let o = Fake::with(vec![Fake::ok()]);
        let r = try_automate(&o, "gitea", &step(AVEC_EXEC), &[]).await;

        assert_eq!(r, AutomationOutcome::Applied { method: "exec" });
        assert!(r.handled());
        assert_eq!(o.appels.lock().unwrap()[0][0], "gitea");
    }

    #[tokio::test]
    async fn a_failing_command_falls_back_to_manual_with_its_reason() {
        // 🔴 Sans la raison, l'utilisateur ne saurait pas pourquoi on lui demande de
        // faire à la main ce qu'on annonçait automatique.
        let o = Fake::with(vec![Fake::ko("permission refusée")]);
        let r = try_automate(&o, "gitea", &step(AVEC_EXEC), &[]).await;

        assert!(!r.handled());
        assert!(r.describe().contains("permission refusée"), "{}", r.describe());
    }

    #[tokio::test]
    async fn a_probe_prevents_replaying_what_is_done() {
        // Beaucoup de CLI échouent si l'objet existe déjà : la sonde évite ça.
        let y = r#"
steps:
  - id: sso
    title: Configurer le SSO
    automate:
      - method: exec
        probe: [gitea, admin, auth, list]
        probeMatches: PocketID
        command: [gitea, admin, auth, add-oauth]
"#;
        let o = Fake::with(vec![Fake::disant("PocketID openidConnect")]);
        let r = try_automate(&o, "gitea", &step(y), &[]).await;

        assert_eq!(r, AutomationOutcome::AlreadyDone { method: "exec" });
        assert_eq!(
            o.appels.lock().unwrap().len(),
            1,
            "seule la sonde devait tourner, pas la commande"
        );
    }

    #[tokio::test]
    async fn a_probe_that_finds_nothing_lets_the_command_run() {
        let y = r#"
steps:
  - id: sso
    title: Configurer le SSO
    automate:
      - method: exec
        probe: [gitea, admin, auth, list]
        probeMatches: PocketID
        command: [gitea, admin, auth, add-oauth]
"#;
        let o = Fake::with(vec![Fake::disant("(vide)"), Fake::ok()]);
        let r = try_automate(&o, "gitea", &step(y), &[]).await;

        assert_eq!(r, AutomationOutcome::Applied { method: "exec" });
        assert_eq!(o.appels.lock().unwrap().len(), 2, "sonde puis commande");
    }

    #[tokio::test]
    async fn env_only_steps_are_already_handled_at_plan_time() {
        // Les variables sont appliquées au déploiement : rien à faire ici, et
        // surtout pas recréer le service.
        let y = r#"
steps:
  - id: fermer
    title: Fermer
    automate:
      - method: env
        vars: { SIGNUPS_ALLOWED: "false" }
"#;
        let o = Fake::default();
        let r = try_automate(&o, "app", &step(y), &[]).await;

        assert_eq!(r, AutomationOutcome::Applied { method: "env" });
        assert!(o.appels.lock().unwrap().is_empty(), "aucune commande ne doit tourner");
    }

    #[tokio::test]
    async fn a_step_without_automation_stays_manual() {
        let y = "steps:\n  - id: dns\n    title: Créer le DNS\n";
        let r = try_automate(&Fake::default(), "app", &step(y), &[]).await;
        assert_eq!(r, AutomationOutcome::NothingDeclared);
        assert!(!r.handled());
    }

    #[tokio::test]
    async fn templates_are_rendered_in_commands() {
        let y = r#"
steps:
  - id: x
    title: x
    automate:
      - method: exec
        command: [configurer, "--domaine={{ domain }}"]
"#;
        let o = Fake::with(vec![Fake::ok()]);
        try_automate(&o, "app", &step(y), &[("domain", "git.example.fr")]).await;

        assert_eq!(o.appels.lock().unwrap()[0][1], "--domaine=git.example.fr");
    }
}
