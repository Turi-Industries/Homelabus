//! The guide automation ladder.
//!
//! Most "inside the application" steps can be scripted. Treating them as manual by
//! default is the usual mistake: you end up documenting a click-through where a
//! command would do.
//!
//! ## The ladder is not purely sequential
//!
//! | Level | When it applies |
//! |---|---|
//! | `env` | **at plan time** - Swarm recreates the task, so it is a deploy choice |
//! | `exec` | after deployment, on a healthy service |
//! | `api` | after deployment, on a healthy service |
//!
//! This module therefore handles only `exec` and `api`. Environment variables are
//! resolved by the resolver, because they cannot be applied after the fact: changing
//! a service's environment requires redeploying it.

use hlb_orchestrator::Orchestrator;
use hlb_types::{Automation, GuideStep};

/// What an automation attempt produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutomationOutcome {
    /// Applied successfully.
    Applied { method: &'static str },
    /// The probe says it was already done, so nothing is replayed.
    AlreadyDone { method: &'static str },
    /// No attempt succeeded - the step stays manual.
    FellBackToManual { reasons: Vec<String> },
    /// Nothing was declared: the step was always manual.
    NothingDeclared,
}

impl AutomationOutcome {
    pub fn handled(&self) -> bool {
        matches!(self, Self::Applied { .. } | Self::AlreadyDone { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Applied { method } => format!("automated through {method}"),
            Self::AlreadyDone { method } => format!("already done (detected through {method})"),
            Self::FellBackToManual { reasons } => {
                format!("stays manual: {}", reasons.join("; "))
            }
            Self::NothingDeclared => "manual (no automation declared)".into(),
        }
    }
}

/// Attempts to carry out a step without human intervention.
///
/// 🔴 Falling back to manual only happens **after trying**, and every attempt's
/// failure is kept: without that, the user would not know why the system is asking
/// them to do something it claimed it would automate.
pub async fn try_automate<O: Orchestrator>(
    orch: &O,
    service: &str,
    step: &GuideStep,
    vars: &[(&str, &str)],
) -> AutomationOutcome {
    if step.automate.is_empty() {
        return AutomationOutcome::NothingDeclared;
    }

    let mut reasons = Vec::new();

    for a in &step.automate {
        match a {
            // Resolved at plan time: recreating the service here would be
            // destructive and would duplicate the resolver's logic.
            Automation::Env { .. } => continue,

            Automation::Exec {
                command,
                probe,
                probe_matches,
            } => {
                // Idempotency probe: do not replay a command already applied. Many
                // app CLIs fail outright if the object already exists.
                if let Some(p) = probe {
                    let rendered: Vec<String> = p
                        .iter()
                        .map(|c| hlb_types::guide::render(c, vars))
                        .collect();
                    if let Ok(out) = orch.exec_in_service(service, &rendered).await {
                        let expected = probe_matches.as_deref().unwrap_or("");
                        if out.ok() && (expected.is_empty() || out.stdout.contains(expected)) {
                            return AutomationOutcome::AlreadyDone { method: "exec" };
                        }
                    }
                }

                let rendered: Vec<String> = command
                    .iter()
                    .map(|c| hlb_types::guide::render(c, vars))
                    .collect();

                match orch.exec_in_service(service, &rendered).await {
                    Ok(out) if out.ok() => {
                        tracing::info!(step = %step.id, "step automated through exec");
                        return AutomationOutcome::Applied { method: "exec" };
                    }
                    Ok(out) => reasons.push(format!(
                        "exec exited {}: {}",
                        out.exit_code,
                        out.stderr.trim().lines().next().unwrap_or("").trim()
                    )),
                    Err(e) => reasons.push(format!("exec failed: {e}")),
                }
            }

            // Needs an app-specific API token, which we do not have yet.
            Automation::Api { .. } => {
                reasons.push("API automation is not wired up".into());
            }
        }
    }

    if reasons.is_empty() {
        // Only `env` automations were declared: they were applied at deploy time,
        // so there is nothing to do here.
        return AutomationOutcome::Applied { method: "env" };
    }
    AutomationOutcome::FellBackToManual { reasons: reasons }
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
        /// Successive answers; the last one repeats.
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
            ExecOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }
        }
        fn ko(stderr: &str) -> ExecOutput {
            ExecOutput {
                exit_code: 1,
                stdout: String::new(),
                stderr: stderr.into(),
            }
        }
        fn disant(stdout: &str) -> ExecOutput {
            ExecOutput {
                exit_code: 0,
                stdout: stdout.into(),
                stderr: String::new(),
            }
        }
    }

    #[async_trait]
    impl Orchestrator for Fake {
        async fn ping(&self) -> hlb_orchestrator::Result<String> {
            Ok("fake".into())
        }
        async fn deploy(&self, _: &ServiceSpec) -> hlb_orchestrator::Result<String> {
            Ok("id".into())
        }
        async fn update_image(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn scale(&self, _: &str, _: u64) -> hlb_orchestrator::Result<()> {
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
            cmd: &[String],
        ) -> hlb_orchestrator::Result<ExecOutput> {
            self.appels.lock().expect("mutex").push(cmd.to_vec());
            let mut s = self.sorties.lock().expect("mutex");
            Ok(if s.len() > 1 {
                s.remove(0)
            } else {
                s.first().cloned().unwrap_or(Fake::ok())
            })
        }
        async fn create_volume(&self, n: &str) -> hlb_orchestrator::Result<VolumeInfo> {
            Ok(VolumeInfo {
                name: n.into(),
                mountpoint: "/v".into(),
                existed: false,
            })
        }
        async fn inspect_volume(&self, n: &str) -> hlb_orchestrator::Result<VolumeInfo> {
            self.create_volume(n).await
        }
        async fn status(&self, _: &str) -> hlb_orchestrator::Result<ServiceStatus> {
            Err(hlb_orchestrator::Error::NotFound("x".into()))
        }
        async fn list(&self) -> hlb_orchestrator::Result<Vec<ServiceStatus>> {
            Ok(vec![])
        }
        async fn remove(&self, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn wait_healthy(&self, _: &str, _: u64) -> hlb_orchestrator::Result<ServiceStatus> {
            Err(hlb_orchestrator::Error::NotFound("x".into()))
        }

        async fn tasks(
            &self,
            _: Option<&str>,
        ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::TaskInfo>> {
            // A fake orchestrator has no tasks: empty is the honest answer.
            Ok(Vec::new())
        }

        async fn logs(
            &self,
            _: &str,
            _: u32,
        ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LigneLog>> {
            Ok(Vec::new())
        }
    }

    fn step(yaml: &str) -> GuideStep {
        let g: hlb_types::Guide = serde_yaml_ng::from_str(yaml).expect("guide de test");
        g.steps.into_iter().next().expect("one step")
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
        // 🔴 Without the reason, the user would not know why they are being asked to
        // do by hand what was announced as automatic.
        let o = Fake::with(vec![Fake::ko("permission denied")]);
        let r = try_automate(&o, "gitea", &step(AVEC_EXEC), &[]).await;

        assert!(!r.handled());
        assert!(
            r.describe().contains("permission denied"),
            "{}",
            r.describe()
        );
    }

    #[tokio::test]
    async fn a_probe_prevents_replaying_what_is_done() {
        // Many CLIs fail if the object already exists: the probe avoids that.
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
        // Variables are applied at deploy time: nothing to do here, and above all
        // not to recreate the service.
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
        assert!(
            o.appels.lock().unwrap().is_empty(),
            "aucune commande ne doit tourner"
        );
    }

    #[tokio::test]
    async fn a_step_without_automation_stays_manual() {
        let y = "steps:\n  - id: dns\n    title: Create the DNS record\n";
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
