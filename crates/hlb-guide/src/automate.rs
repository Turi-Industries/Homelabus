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
//! | `sql` | after deployment, in the app's own database |
//!
//! This module therefore handles only `exec` and `api`. Environment variables are
//! resolved by the resolver, because they cannot be applied after the fact: changing
//! a service's environment requires redeploying it.

use async_trait::async_trait;
use hlb_orchestrator::Orchestrator;
use hlb_types::{ApiCall, ApiProbe, Automation, GuideStep};

/// How an `api` automation reaches the app: one request, its status and its body.
#[async_trait]
pub trait ApiClient: Send + Sync {
    async fn call(
        &self,
        verb: &str,
        url: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), String>;
}

/// The app's own PostgreSQL database, for its `sql` automations: the caller binds it
/// to the app, and gives the parameters their tokens.
#[async_trait]
pub trait SqlWriter: Send + Sync {
    /// Does the probe hold?
    async fn probe(&self, probe: &str, params: &[String]) -> Result<bool, String>;
    /// The write, then the probe in the same transaction — kept only if it holds.
    async fn write(&self, statement: &str, probe: &str, params: &[String]) -> Result<bool, String>;
}

/// The app's API, and the port to reach it on when the step names none.
#[derive(Clone, Copy)]
pub struct Api<'a> {
    pub client: &'a dyn ApiClient,
    pub port: Option<u16>,
}

/// The client that reaches the real installation, JSON in and out.
pub struct HttpApi {
    http: reqwest::Client,
    /// An overlay address into one this process reaches — a relay from a shell.
    reach: Box<dyn Fn(&str) -> String + Send + Sync>,
}

impl Default for HttpApi {
    fn default() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            reach: Box::new(str::to_string),
        }
    }
}

impl HttpApi {
    pub fn reaching(mut self, reach: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        self.reach = Box::new(reach);
        self
    }
}

#[async_trait]
impl ApiClient for HttpApi {
    async fn call(
        &self,
        verb: &str,
        url: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), String> {
        let method = reqwest::Method::from_bytes(verb.to_ascii_uppercase().as_bytes())
            .map_err(|e| e.to_string())?;
        let mut req = self.http.request(method, (self.reach)(url));
        if let Some(b) = body {
            req = req
                .header("content-type", "application/json")
                .body(b.to_string());
        }
        let r = req.send().await.map_err(|e| e.to_string())?;
        let code = r.status().as_u16();
        Ok((code, r.text().await.unwrap_or_default()))
    }
}

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
pub async fn try_automate<O: Orchestrator + ?Sized>(
    orch: &O,
    service: &str,
    step: &GuideStep,
    vars: &[(&str, &str)],
) -> AutomationOutcome {
    try_automate_with(orch, None, None, service, step, vars).await
}

/// The same, with the app's API for its `api` automations — whose bodies the caller
/// has given their tokens already: this module never sees the vault.
pub async fn try_automate_with<O: Orchestrator + ?Sized>(
    orch: &O,
    api: Option<Api<'_>>,
    sql: Option<&dyn SqlWriter>,
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

            Automation::Api { port, probe, calls } => {
                let Some(api) = api else {
                    reasons.push("the app's API is not reachable from here".into());
                    continue;
                };
                let Some(port) = port.or(api.port) else {
                    reasons.push("no port to reach the app's API on".into());
                    continue;
                };
                let base = format!("http://{service}:{port}");
                if let Some(p) = probe {
                    match probe_when_ready(api.client, &base, p, vars).await {
                        Some(true) => return AutomationOutcome::AlreadyDone { method: "api" },
                        Some(false) => {}
                        None => {
                            reasons.push(format!(
                                "{} never answered as its API within {} s",
                                p.path,
                                PAGE_RETRIES * PAGE_WAIT.as_secs()
                            ));
                            continue;
                        }
                    }
                }
                match run_calls(api.client, &base, calls, vars).await {
                    Ok(()) => {
                        // Judged by its effect: what the probe says now, not a status.
                        let held = match probe {
                            Some(p) => probe_says_done(api.client, &base, p, vars).await,
                            None => true,
                        };
                        if held {
                            tracing::info!(step = %step.id, "step automated through the app's API");
                            return AutomationOutcome::Applied { method: "api" };
                        }
                        reasons.push(
                            "the calls were answered, and the app still says it is not done".into(),
                        );
                    }
                    Err(why) => reasons.push(why),
                }
            }

            Automation::Sql {
                statement,
                params,
                probe,
                restart,
            } => {
                let Some(db) = sql else {
                    reasons.push("the app's database is not reachable from here".into());
                    continue;
                };
                match db.probe(probe, params).await {
                    Ok(true) => return AutomationOutcome::AlreadyDone { method: "sql" },
                    Ok(false) => {}
                    Err(e) => {
                        reasons.push(format!("sql probe: {e}"));
                        continue;
                    }
                }
                match db.write(statement, probe, params).await {
                    // Rolled back: the row it was to change is not there yet — a
                    // sign-in source the app had not created, say.
                    Ok(false) => reasons.push(
                        "the sql write did not make its probe hold, and was rolled back".into(),
                    ),
                    Err(e) => reasons.push(format!("sql write: {e}")),
                    Ok(true) => {
                        if *restart {
                            if let Err(e) = restart_service(orch, service).await {
                                reasons.push(format!(
                                    "written, but {service} was not restarted to read it: {e}"
                                ));
                                continue;
                            }
                        }
                        tracing::info!(step = %step.id, "step automated in the app's database");
                        return AutomationOutcome::Applied { method: "sql" };
                    }
                }
            }
        }
    }

    if reasons.is_empty() {
        // Only `env` automations were declared: they were applied at deploy time,
        // so there is nothing to do here.
        return AutomationOutcome::Applied { method: "env" };
    }
    AutomationOutcome::FellBackToManual { reasons }
}

/// Stopped, then started again and waited for: an app that reads a value at its start
/// only. Scaled to zero first, not updated, so no second task runs beside the first.
async fn restart_service<O: Orchestrator + ?Sized>(orch: &O, service: &str) -> Result<(), String> {
    let e = |e: hlb_orchestrator::Error| e.to_string();
    let replicas = orch
        .status(service)
        .await
        .map_err(e)?
        .desired_replicas
        .max(1);
    orch.scale(service, 0).await.map_err(e)?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
    while orch.status(service).await.map_err(e)?.running_replicas > 0 {
        if tokio::time::Instant::now() > deadline {
            return Err(format!(
                "{service} did not stop within 120 s; it is left at 0 replicas"
            ));
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    orch.scale(service, replicas).await.map_err(e)?;
    orch.wait_healthy(service, 180).await.map_err(e)?;
    Ok(())
}

/// Does the probe's answer say the work is there? An answer that cannot be read is
/// a no: the calls then run, and a first-run endpoint refusing them says why.
async fn probe_says_done(
    client: &dyn ApiClient,
    base: &str,
    p: &ApiProbe,
    vars: &[(&str, &str)],
) -> bool {
    probe_reads(client, base, p, vars).await == Some(true)
}

/// What the probe says, or `None` while the app does not answer it as its API — a
/// page, a 404 of a route not registered yet, nothing at all.
async fn probe_reads(
    client: &dyn ApiClient,
    base: &str,
    p: &ApiProbe,
    vars: &[(&str, &str)],
) -> Option<bool> {
    let path = hlb_types::guide::render(&p.path, vars);
    let Ok((200, body)) = client.call("GET", &format!("{base}{path}"), None).await else {
        return None;
    };
    let got = serde_json::from_str::<serde_json::Value>(&body).ok()?;
    let want = serde_json::from_str::<serde_json::Value>(&p.equals).ok()?;
    Some(got.pointer(&p.pointer) == Some(&want))
}

/// The probe, read once the app answers it as its API.
///
/// 🔴 Healthy is not ready: n8n 1.123 says 200 on `/healthz` and `/healthz/readiness`,
/// then answers every route with its starting page, then 404s its routes until they are
/// registered — and a first-run call made in either window did nothing, `/setup` left
/// open. A step with a probe waits until the probe reads.
async fn probe_when_ready(
    client: &dyn ApiClient,
    base: &str,
    p: &ApiProbe,
    vars: &[(&str, &str)],
) -> Option<bool> {
    for _ in 0..PAGE_RETRIES {
        if let Some(done) = probe_reads(client, base, p, vars).await {
            return Some(done);
        }
        tokio::time::sleep(PAGE_WAIT).await;
    }
    None
}

/// The calls, in order; the first that fails stops the rest, and says how.
async fn run_calls(
    client: &dyn ApiClient,
    base: &str,
    calls: &[ApiCall],
    vars: &[(&str, &str)],
) -> Result<(), String> {
    for c in calls {
        let path = hlb_types::guide::render(&c.path, vars);
        let body = c.body.as_deref().map(|b| hlb_types::guide::render(b, vars));
        let mut tries = 0;
        loop {
            match client
                .call(&c.verb, &format!("{base}{path}"), body.as_deref())
                .await
            {
                // 🔴 A page is not the API's answer. n8n 1.123 answers its starting
                // page, `200 text/html`, to every route while `/healthz` and even
                // `/healthz/readiness` already say 200: taken as done, its owner was
                // never created and `/setup` stayed open to the first visitor.
                Ok((code, answer)) if (200..300).contains(&code) && !is_api_answer(&answer) => {
                    tries += 1;
                    if tries >= PAGE_RETRIES {
                        return Err(format!(
                            "{} {path} answered {code} with a page, not its API, for {} s",
                            c.verb,
                            PAGE_RETRIES * PAGE_WAIT.as_secs()
                        ));
                    }
                    tokio::time::sleep(PAGE_WAIT).await;
                }
                Ok((code, _)) if (200..300).contains(&code) => break,
                // The body may echo what was sent — a password: only the status is told.
                Ok((code, _)) => return Err(format!("{} {path} answered {code}", c.verb)),
                Err(e) => return Err(format!("{} {path} failed: {e}", c.verb)),
            }
        }
    }
    Ok(())
}

/// How often, and how long apart, a call answered by a page is tried again: fifteen
/// minutes. A first start of n8n 2.43 ran 300 migrations before its API answered —
/// eight and a half minutes on the lab's disk.
const PAGE_RETRIES: u64 = 450;
const PAGE_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// An API's answer: nothing, or JSON — never a page.
fn is_api_answer(body: &str) -> bool {
    let b = body.trim();
    b.is_empty() || serde_json::from_str::<serde_json::Value>(b).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_orchestrator::{ExecOutput, ServiceSpec, ServiceStatus, VolumeInfo};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<Vec<String>>>,
        /// Successive answers; the last one repeats.
        outputs: Mutex<Vec<ExecOutput>>,
    }

    impl Fake {
        fn with(outputs: Vec<ExecOutput>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                outputs: Mutex::new(outputs),
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
        fn saying(stdout: &str) -> ExecOutput {
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
        async fn cluster_init(&self, _: &str) -> hlb_orchestrator::Result<String> {
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
        async fn set_node_availability(&self, _: &str, _: &str) -> hlb_orchestrator::Result<()> {
            Ok(())
        }
        async fn exec_in_service(
            &self,
            _: &str,
            cmd: &[String],
        ) -> hlb_orchestrator::Result<ExecOutput> {
            self.calls.lock().expect("mutex").push(cmd.to_vec());
            let mut s = self.outputs.lock().expect("mutex");
            Ok(if s.len() > 1 {
                s.remove(0)
            } else {
                s.first().cloned().unwrap_or(Fake::ok())
            })
        }
        async fn ensure_network(&self, _: &str) -> hlb_orchestrator::Result<bool> {
            Ok(false)
        }

        async fn create_volume(
            &self,
            spec: &hlb_orchestrator::VolumeSpec,
        ) -> hlb_orchestrator::Result<VolumeInfo> {
            Ok(VolumeInfo {
                name: spec.name.clone(),
                mountpoint: "/v".into(),
                existed: false,
            })
        }
        async fn inspect_volume(&self, n: &str) -> hlb_orchestrator::Result<VolumeInfo> {
            self.create_volume(&hlb_orchestrator::VolumeSpec::docker(n))
                .await
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
        ) -> hlb_orchestrator::Result<Vec<hlb_orchestrator::LogLine>> {
            Ok(Vec::new())
        }
    }

    fn step(yaml: &str) -> GuideStep {
        let g: hlb_types::Guide = serde_yaml_ng::from_str(yaml).expect("test guide");
        g.steps.into_iter().next().expect("one step")
    }

    const WITH_EXEC: &str = r#"
steps:
  - id: close
    title: Close signups
    automate:
      - method: exec
        command: [gitea, admin, config, set, service.DISABLE_REGISTRATION, "true"]
"#;

    #[tokio::test]
    async fn a_declared_command_is_executed() {
        let o = Fake::with(vec![Fake::ok()]);
        let r = try_automate(&o, "gitea", &step(WITH_EXEC), &[]).await;

        assert_eq!(r, AutomationOutcome::Applied { method: "exec" });
        assert!(r.handled());
        assert_eq!(o.calls.lock().unwrap()[0][0], "gitea");
    }

    #[tokio::test]
    async fn a_failing_command_falls_back_to_manual_with_its_reason() {
        // 🔴 Without the reason, the user would not know why they are being asked to
        // do by hand what was announced as automatic.
        let o = Fake::with(vec![Fake::ko("permission denied")]);
        let r = try_automate(&o, "gitea", &step(WITH_EXEC), &[]).await;

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
        let o = Fake::with(vec![Fake::saying("PocketID openidConnect")]);
        let r = try_automate(&o, "gitea", &step(y), &[]).await;

        assert_eq!(r, AutomationOutcome::AlreadyDone { method: "exec" });
        assert_eq!(
            o.calls.lock().unwrap().len(),
            1,
            "only the probe was to run, not the command"
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
        let o = Fake::with(vec![Fake::saying("(empty)"), Fake::ok()]);
        let r = try_automate(&o, "gitea", &step(y), &[]).await;

        assert_eq!(r, AutomationOutcome::Applied { method: "exec" });
        assert_eq!(o.calls.lock().unwrap().len(), 2, "sonde puis commande");
    }

    #[tokio::test]
    async fn env_only_steps_are_already_handled_at_plan_time() {
        // Variables are applied at deploy time: nothing to do here, and above all
        // not to recreate the service.
        let y = r#"
steps:
  - id: close
    title: Close
    automate:
      - method: env
        vars: { SIGNUPS_ALLOWED: "false" }
"#;
        let o = Fake::default();
        let r = try_automate(&o, "app", &step(y), &[]).await;

        assert_eq!(r, AutomationOutcome::Applied { method: "env" });
        assert!(o.calls.lock().unwrap().is_empty(), "no command must run");
    }

    #[tokio::test]
    async fn a_step_without_automation_stays_manual() {
        let y = "steps:\n  - id: dns\n    title: Create the DNS record\n";
        let r = try_automate(&Fake::default(), "app", &step(y), &[]).await;
        assert_eq!(r, AutomationOutcome::NothingDeclared);
        assert!(!r.handled());
    }

    /// An app's API: what it answers each `VERB path`, and what it was sent.
    #[derive(Default)]
    struct Answers {
        answers: Vec<(&'static str, (u16, &'static str))>,
        /// What is answered instead once a write was received: the app's new state.
        after: Vec<(&'static str, (u16, &'static str))>,
        /// The first answers of a key, before `answers` — an app still starting.
        first: Mutex<Vec<(&'static str, (u16, &'static str))>>,
        sent: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl ApiClient for Answers {
        async fn call(
            &self,
            verb: &str,
            url: &str,
            body: Option<&str>,
        ) -> Result<(u16, String), String> {
            let key = format!("{verb} {url}");
            self.sent.lock().expect("mutex").push(
                format!("{key} {}", body.unwrap_or(""))
                    .trim_end()
                    .to_string(),
            );
            {
                let mut first = self.first.lock().expect("mutex");
                if let Some(i) = first.iter().position(|(k, _)| *k == key) {
                    let (_, (c, b)) = first.remove(i);
                    return Ok((c, b.to_string()));
                }
            }
            let written = self
                .sent
                .lock()
                .expect("mutex")
                .iter()
                .any(|s| !s.starts_with("GET "));
            let after = self.after.iter().filter(|_| written);
            after
                .chain(self.answers.iter())
                .find(|(k, _)| *k == key)
                .map(|(_, (c, b))| (*c, b.to_string()))
                .ok_or_else(|| "connection refused".to_string())
        }
    }

    /// A database whose probe holds once `write` was called, if `takes`.
    #[derive(Default)]
    struct Db {
        takes: bool,
        written: std::sync::Mutex<Vec<Vec<String>>>,
    }

    #[async_trait]
    impl SqlWriter for Db {
        async fn probe(&self, _: &str, _: &[String]) -> Result<bool, String> {
            Ok(self.takes && !self.written.lock().expect("lock").is_empty())
        }
        async fn write(&self, _: &str, _: &str, params: &[String]) -> Result<bool, String> {
            self.written.lock().expect("lock").push(params.to_vec());
            Ok(self.takes)
        }
    }

    const SECRET_STEP: &str = r#"
steps:
  - id: secret
    title: The sign-in secret
    automate:
      - method: sql
        statement: "UPDATE s SET c = $1"
        params: ["the-secret"]
        probe: "SELECT c = $1 FROM s"
"#;

    #[tokio::test]
    async fn an_sql_write_is_made_once_and_only_counts_when_its_probe_holds() {
        let db = Db {
            takes: true,
            ..Default::default()
        };
        let (orch, st) = (Fake::default(), step(SECRET_STEP));
        let run = || try_automate_with(&orch, None, Some(&db), "gitea", &st, &[]);
        assert_eq!(run().await, AutomationOutcome::Applied { method: "sql" });
        assert_eq!(
            run().await,
            AutomationOutcome::AlreadyDone { method: "sql" }
        );
        assert_eq!(
            *db.written.lock().expect("lock"),
            vec![vec!["the-secret".to_string()]],
            "written once, its value bound"
        );

        // The row was not there: rolled back, and said.
        let none = Db::default();
        let r = try_automate_with(&orch, None, Some(&none), "gitea", &st, &[]).await;
        assert!(
            matches!(&r, AutomationOutcome::FellBackToManual { reasons } if reasons[0].contains("rolled back")),
            "{r:?}"
        );
        let unreachable = try_automate_with(&orch, None, None, "gitea", &st, &[]).await;
        assert!(!unreachable.handled());
    }

    const WIZARD: &str = r#"
steps:
  - id: first-account
    title: The administrator
    automate:
      - method: api
        probe: { path: /System/Info/Public, pointer: /StartupWizardCompleted, equals: "true" }
        calls:
          - { verb: POST, path: /Startup/User, body: '{"Name":"admin"}' }
          - { verb: POST, path: /Startup/Complete }
"#;

    #[tokio::test]
    async fn the_calls_run_in_order_on_the_apps_own_address() {
        let api = Answers {
            answers: vec![
                (
                    "GET http://jellyfin:8096/System/Info/Public",
                    (200, r#"{"StartupWizardCompleted":false}"#),
                ),
                ("POST http://jellyfin:8096/Startup/User", (204, "")),
                ("POST http://jellyfin:8096/Startup/Complete", (204, "")),
            ],
            after: vec![(
                "GET http://jellyfin:8096/System/Info/Public",
                (200, r#"{"StartupWizardCompleted":true}"#),
            )],
            ..Default::default()
        };
        let r = try_automate_with(
            &Fake::default(),
            Some(Api {
                client: &api,
                port: Some(8096),
            }),
            None,
            "jellyfin",
            &step(WIZARD),
            &[],
        )
        .await;
        assert_eq!(r, AutomationOutcome::Applied { method: "api" });
        assert_eq!(
            *api.sent.lock().expect("mutex"),
            [
                "GET http://jellyfin:8096/System/Info/Public",
                r#"POST http://jellyfin:8096/Startup/User {"Name":"admin"}"#,
                "POST http://jellyfin:8096/Startup/Complete",
                // Read again after: the step is done when the app says so.
                "GET http://jellyfin:8096/System/Info/Public",
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_page_answered_while_the_app_starts_is_not_its_api() {
        let api = Answers {
            answers: vec![
                (
                    "GET http://jellyfin:8096/System/Info/Public",
                    (200, r#"{"StartupWizardCompleted":false}"#),
                ),
                ("POST http://jellyfin:8096/Startup/User", (204, "")),
                ("POST http://jellyfin:8096/Startup/Complete", (204, "")),
            ],
            after: vec![(
                "GET http://jellyfin:8096/System/Info/Public",
                (200, r#"{"StartupWizardCompleted":true}"#),
            )],
            // n8n 1.123's, while its health checks already say 200: its starting page,
            // then a 404 for a route not registered yet.
            first: Mutex::new(vec![
                (
                    "GET http://jellyfin:8096/System/Info/Public",
                    (200, "n8n is starting up. Please wait"),
                ),
                ("GET http://jellyfin:8096/System/Info/Public", (404, "")),
                (
                    "POST http://jellyfin:8096/Startup/User",
                    (200, "n8n is starting up. Please wait"),
                ),
            ]),
            ..Default::default()
        };
        let r = try_automate_with(
            &Fake::default(),
            Some(Api {
                client: &api,
                port: Some(8096),
            }),
            None,
            "jellyfin",
            &step(WIZARD),
            &[],
        )
        .await;
        assert_eq!(r, AutomationOutcome::Applied { method: "api" });
        let sent = api.sent.lock().expect("mutex");
        assert_eq!(
            sent.iter()
                .filter(|s| s.starts_with("POST http://jellyfin:8096/Startup/User"))
                .count(),
            2,
            "sent again once the app answered as itself: {sent:?}"
        );
    }

    #[tokio::test]
    async fn calls_answered_with_nothing_done_are_not_a_step_done() {
        // Every call 2xx, and the probe still says the wizard is not complete.
        let api = Answers {
            answers: vec![
                (
                    "GET http://jellyfin:8096/System/Info/Public",
                    (200, r#"{"StartupWizardCompleted":false}"#),
                ),
                ("POST http://jellyfin:8096/Startup/User", (204, "")),
                ("POST http://jellyfin:8096/Startup/Complete", (204, "")),
            ],
            ..Default::default()
        };
        let r = try_automate_with(
            &Fake::default(),
            Some(Api {
                client: &api,
                port: Some(8096),
            }),
            None,
            "jellyfin",
            &step(WIZARD),
            &[],
        )
        .await;
        assert!(!r.handled(), "{r:?}");
    }

    #[tokio::test]
    async fn a_wizard_already_completed_is_never_replayed() {
        let api = Answers {
            answers: vec![(
                "GET http://jellyfin:8096/System/Info/Public",
                (200, r#"{"StartupWizardCompleted":true}"#),
            )],
            ..Default::default()
        };
        let r = try_automate_with(
            &Fake::default(),
            Some(Api {
                client: &api,
                port: Some(8096),
            }),
            None,
            "jellyfin",
            &step(WIZARD),
            &[],
        )
        .await;
        assert_eq!(r, AutomationOutcome::AlreadyDone { method: "api" });
        assert_eq!(api.sent.lock().expect("mutex").len(), 1, "the probe alone");
    }

    #[tokio::test]
    async fn a_refused_call_stops_the_rest_and_never_echoes_the_body() {
        let api = Answers {
            answers: vec![
                (
                    "GET http://jellyfin:8096/System/Info/Public",
                    (200, r#"{"StartupWizardCompleted":false}"#),
                ),
                (
                    "POST http://jellyfin:8096/Startup/User",
                    (401, r#"{"Name":"admin","Password":"hunter2"}"#),
                ),
            ],
            ..Default::default()
        };
        let r = try_automate_with(
            &Fake::default(),
            Some(Api {
                client: &api,
                port: Some(8096),
            }),
            None,
            "jellyfin",
            &step(WIZARD),
            &[],
        )
        .await;
        assert!(!r.handled());
        let said = r.describe();
        assert!(said.contains("POST /Startup/User answered 401"), "{said}");
        assert!(!said.contains("hunter2"), "{said}");
        assert_eq!(
            api.sent.lock().expect("mutex").len(),
            2,
            "probe, then the first call"
        );
        // Without the API at all, it says so rather than pretend.
        let alone = try_automate(&Fake::default(), "jellyfin", &step(WIZARD), &[]).await;
        assert!(
            alone.describe().contains("not reachable"),
            "{}",
            alone.describe()
        );
    }

    #[tokio::test]
    async fn templates_are_rendered_in_commands() {
        let y = r#"
steps:
  - id: x
    title: x
    automate:
      - method: exec
        command: [configurer, "--domain={{ domain }}"]
"#;
        let o = Fake::with(vec![Fake::ok()]);
        try_automate(&o, "app", &step(y), &[("domain", "git.example.fr")]).await;

        assert_eq!(o.calls.lock().unwrap()[0][1], "--domain=git.example.fr");
    }
}
