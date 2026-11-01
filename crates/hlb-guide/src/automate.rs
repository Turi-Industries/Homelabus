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
use hlb_types::{ApiCall, ApiProbe, Automation, GuideStep, SignIn};

use crate::assertions::{Credential, FORM, JSON};

/// How an `api` automation reaches the app: one request, its status and its body. A
/// body is JSON unless `headers` name its `content-type`.
#[async_trait]
pub trait ApiClient: Send + Sync {
    async fn call(
        &self,
        verb: &str,
        url: &str,
        headers: &[(String, String)],
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

/// The app's API, the port to reach it on when the step names none, and the recovery
/// sign-ins a step may sign in with.
#[derive(Clone, Copy)]
pub struct Api<'a> {
    pub client: &'a dyn ApiClient,
    pub port: Option<u16>,
    pub sign_ins: &'a [ApiSignIn],
}

/// A recovery sign-in an `api` step signs in with: its proof, and what the vault holds
/// for it — looked up by the caller, so this module never sees the vault.
#[derive(Debug, Clone)]
pub struct ApiSignIn {
    pub credential: Credential,
    pub proof: SignIn,
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
        headers: &[(String, String)],
        body: Option<&str>,
    ) -> Result<(u16, String), String> {
        let method = reqwest::Method::from_bytes(verb.to_ascii_uppercase().as_bytes())
            .map_err(|e| e.to_string())?;
        let mut req = self.http.request(method, (self.reach)(url));
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(b) = body {
            if !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            {
                req = req.header("content-type", JSON);
            }
            req = req.body(b.to_string());
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
                service: companion,
                probe,
                probe_matches,
            } => {
                let target = exec_target(service, companion.as_deref());
                let service = target.as_str();
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
                    Ok(out) => {
                        // A task on another node is reached through a job whose one log
                        // holds both streams: its stderr comes back empty, and Seafile's
                        // damaged block was refused as "exec exited 1: " and nothing.
                        let said = if out.stderr.trim().is_empty() {
                            &out.stdout
                        } else {
                            &out.stderr
                        };
                        reasons.push(format!(
                            "exec exited {}: {}",
                            out.exit_code,
                            said.lines()
                                .map(str::trim)
                                .find(|l| !l.is_empty())
                                .unwrap_or("")
                        ));
                    }
                    Err(e) => reasons.push(format!("exec failed: {e}")),
                }
            }

            Automation::Api {
                port,
                sign_in,
                headers,
                probe,
                calls,
            } => {
                let Some(api) = api else {
                    reasons.push("the app's API is not reachable from here".into());
                    continue;
                };
                let Some(port) = port.or(api.port) else {
                    reasons.push("no port to reach the app's API on".into());
                    continue;
                };
                let base = format!("http://{service}:{port}");
                // Before the probe, which may need it: what it reads is the
                // administrator's alone — Jellyfin's `/sso/OID/Get`.
                let token = match sign_in {
                    None => None,
                    Some(secret) => match sign_in_for(api, &base, secret).await {
                        Ok(t) => Some(t),
                        Err(why) => {
                            reasons.push(why);
                            continue;
                        }
                    },
                };
                let headers: Vec<(String, String)> = headers
                    .iter()
                    .map(|(k, v)| {
                        let v = match &token {
                            Some(t) => v.replace("{{ token }}", t),
                            None => v.clone(),
                        };
                        (k.clone(), v)
                    })
                    .collect();
                let (client, headers) = (api.client, headers.as_slice());
                if let Some(p) = probe {
                    match probe_when_ready(client, headers, &base, p, vars).await {
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
                match run_calls(client, headers, &base, calls, vars).await {
                    Ok(()) => {
                        // Judged by its effect: what the probe says now, not a status.
                        let held = match probe {
                            Some(p) => probe_says_done(client, headers, &base, p, vars).await,
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

/// Where an `exec` runs: the app's own service, or the companion it names —
/// `Companion::service`'s name, the app's then the companion's.
fn exec_target(app_service: &str, companion: Option<&str>) -> String {
    companion.map_or_else(|| app_service.to_string(), |c| format!("{app_service}-{c}"))
}

/// How long a restored app is waited for before its post-restore steps: Fluxer's api
/// migrates its schema before it answers, and its own probe allows seven minutes.
const RESTARTED_WAIT_S: u64 = 600;

/// The guide's post-restore steps, in the order written, on the app started again
/// after a restore — each once its service is healthy, since a restore starts it and
/// returns at once. They declare no probe (`validate_guide`): what an install left
/// done, a restore has undone.
pub async fn after_restore<O: Orchestrator + ?Sized>(
    orch: &O,
    api: Option<Api<'_>>,
    service: &str,
    guide: &hlb_types::Guide,
    vars: &[(&str, &str)],
) -> Vec<(GuideStep, AutomationOutcome)> {
    let mut out = Vec::new();
    for step in guide
        .steps
        .iter()
        .filter(|s| s.phase == hlb_types::Phase::PostRestore)
    {
        let mut targets: Vec<String> = Vec::new();
        for a in &step.automate {
            let t = match a {
                Automation::Exec {
                    command: _,
                    service: companion,
                    probe: _,
                    probe_matches: _,
                } => exec_target(service, companion.as_deref()),
                Automation::Api {
                    port: _,
                    sign_in: _,
                    headers: _,
                    probe: _,
                    calls: _,
                } => service.to_string(),
                // Refused on a post-restore step by `validate_guide`.
                Automation::Env { .. } | Automation::Sql { .. } => continue,
            };
            if !targets.contains(&t) {
                targets.push(t);
            }
        }
        let mut waited = Vec::new();
        for t in &targets {
            if let Err(e) = orch.wait_healthy(t, RESTARTED_WAIT_S).await {
                waited.push(format!("{t} is not healthy: {e}"));
            }
        }
        let outcome = if waited.is_empty() {
            try_automate_with(orch, api, None, service, step, vars).await
        } else {
            AutomationOutcome::FellBackToManual { reasons: waited }
        };
        out.push((step.clone(), outcome));
    }
    out
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
    headers: &[(String, String)],
    base: &str,
    p: &ApiProbe,
    vars: &[(&str, &str)],
) -> bool {
    probe_reads(client, headers, base, p, vars).await == Some(true)
}

/// What the probe says, or `None` while the app does not answer it as its API — a
/// page, a 404 of a route not registered yet, nothing at all.
async fn probe_reads(
    client: &dyn ApiClient,
    headers: &[(String, String)],
    base: &str,
    p: &ApiProbe,
    vars: &[(&str, &str)],
) -> Option<bool> {
    let path = hlb_types::guide::render(&p.path, vars);
    let Ok((200, body)) = client
        .call("GET", &format!("{base}{path}"), headers, None)
        .await
    else {
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
    headers: &[(String, String)],
    base: &str,
    p: &ApiProbe,
    vars: &[(&str, &str)],
) -> Option<bool> {
    for _ in 0..PAGE_RETRIES {
        if let Some(done) = probe_reads(client, headers, base, p, vars).await {
            return Some(done);
        }
        tokio::time::sleep(PAGE_WAIT).await;
    }
    None
}

/// The calls, in order; the first that fails stops the rest, and says how.
async fn run_calls(
    client: &dyn ApiClient,
    headers: &[(String, String)],
    base: &str,
    calls: &[ApiCall],
    vars: &[(&str, &str)],
) -> Result<(), String> {
    for c in calls {
        let path = hlb_types::guide::render(&c.path, vars);
        let mut body = c.body.as_deref().map(|b| hlb_types::guide::render(b, vars));
        if c.merge {
            body = Some(merged(client, headers, base, &path, body.as_deref()).await?);
        }
        let mut tries = 0;
        loop {
            match client
                .call(&c.verb, &format!("{base}{path}"), headers, body.as_deref())
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

/// A merged call's body: what a GET of its path answers, the body merged over it.
/// What was read is never said either — Jellyfin's holds its client secret.
async fn merged(
    client: &dyn ApiClient,
    headers: &[(String, String)],
    base: &str,
    path: &str,
    patch: Option<&str>,
) -> Result<String, String> {
    let read = |why: String| format!("GET {path}, to merge over, {why}");
    let mut doc = match client
        .call("GET", &format!("{base}{path}"), headers, None)
        .await
    {
        Ok((200, answer)) => serde_json::from_str::<serde_json::Value>(&answer)
            .ok()
            .filter(serde_json::Value::is_object)
            .ok_or_else(|| read("answered with no JSON object".into()))?,
        Ok((code, _)) => return Err(read(format!("answered {code}"))),
        Err(e) => return Err(read(format!("failed: {e}"))),
    };
    let patch = serde_json::from_str::<serde_json::Value>(patch.unwrap_or_default())
        .map_err(|e| format!("the body merged over {path} is not JSON: {e}"))?;
    merge_patch(&mut doc, &patch);
    Ok(doc.to_string())
}

/// RFC 7386: an object merges key by key, `null` removes, anything else replaces.
fn merge_patch(doc: &mut serde_json::Value, patch: &serde_json::Value) {
    let serde_json::Value::Object(p) = patch else {
        *doc = patch.clone();
        return;
    };
    if !doc.is_object() {
        *doc = serde_json::Value::Object(serde_json::Map::new());
    }
    if let serde_json::Value::Object(d) = doc {
        for (k, v) in p {
            if v.is_null() {
                d.remove(k);
            } else {
                merge_patch(d.entry(k.clone()).or_insert(serde_json::Value::Null), v);
            }
        }
    }
}

/// Signs in with the recovery sign-in a step names, as its proof does every night:
/// the string at the proof's `pointer`.
///
/// 🔴 Neither the answer nor the token is ever said: the answer may echo the password,
/// and the token opens the administrator's account.
async fn sign_in_for(api: Api<'_>, base: &str, secret: &str) -> Result<String, String> {
    let Some(s) = api.sign_ins.iter().find(|s| s.credential.secret == secret) else {
        return Err(format!(
            "no sign-in \"{secret}\" was looked up to sign in with"
        ));
    };
    for _ in 0..PAGE_RETRIES {
        match attempt(api.client, base, s).await {
            Attempt::Token(t) => return Ok(t),
            // A page: the app is still starting, as n8n does.
            Attempt::Page => tokio::time::sleep(PAGE_WAIT).await,
            Attempt::Failed(f) => return Err(f.why),
        }
    }
    Err(format!(
        "the sign-in at {} answered with a page, not its API, for {} s",
        s.proof.path,
        PAGE_RETRIES * PAGE_WAIT.as_secs()
    ))
}

/// Why a sign-in gave no token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInFailed {
    /// The app answered no to the password — what the nightly proof calls broken, and
    /// what is never tried again by itself: Jellyfin disables an administrator after
    /// five.
    pub refused: bool,
    pub why: String,
}

/// Signs in once with a recovery sign-in, as [`sign_in_for`] does but never waiting:
/// for a pass that runs every hour, a page is a failure tried at the next one.
pub async fn sign_in(
    client: &dyn ApiClient,
    base: &str,
    s: &ApiSignIn,
) -> Result<String, SignInFailed> {
    match attempt(client, base, s).await {
        Attempt::Token(t) => Ok(t),
        Attempt::Page => Err(SignInFailed {
            refused: false,
            why: format!(
                "the sign-in at {} answered with a page, not its API",
                s.proof.path
            ),
        }),
        Attempt::Failed(f) => Err(f),
    }
}

enum Attempt {
    Token(String),
    Page,
    Failed(SignInFailed),
}

async fn attempt(client: &dyn ApiClient, base: &str, s: &ApiSignIn) -> Attempt {
    let failed = |refused, why| Attempt::Failed(SignInFailed { refused, why });
    let secret = &s.credential.secret;
    let (username, password) = match &s.credential.sign_in {
        Ok((u, p)) => (u.as_str(), p.as_str()),
        Err(why) => return failed(false, format!("no sign-in with \"{secret}\": {why}")),
    };
    let p = &s.proof;
    let filled = match crate::assertions::fill(&p.body, username, password) {
        Ok(f) => f,
        Err(e) => return failed(false, e),
    };
    let (content_type, body) = if p.form {
        match crate::assertions::form(&filled) {
            Ok(b) => (FORM, b),
            Err(e) => return failed(false, e),
        }
    } else {
        (JSON, filled)
    };
    let mut headers: Vec<(String, String)> = p.headers.clone().into_iter().collect();
    headers.push(("content-type".into(), content_type.into()));
    let url = format!("{base}{}", p.path);
    match client.call("POST", &url, &headers, Some(&body)).await {
        Ok((code, answer)) if (200..300).contains(&code) => {
            let Ok(json) = serde_json::from_str::<serde_json::Value>(&answer) else {
                return Attempt::Page;
            };
            match json.pointer(&p.pointer) {
                Some(serde_json::Value::String(t)) if !t.is_empty() => Attempt::Token(t.clone()),
                _ => failed(
                    false,
                    format!(
                        "the sign-in at {} answered {code} with no {} to sign in with",
                        p.path, p.pointer
                    ),
                ),
            }
        }
        // The statuses the nightly proof reads as a refusal (`judge_sign_in`).
        Ok((code, _)) => failed(
            matches!(code, 400 | 401 | 403),
            format!("the sign-in at {} answered {code}", p.path),
        ),
        Err(e) => failed(false, format!("the sign-in at {} failed: {e}", p.path)),
    }
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
        /// The service each exec ran in, and each wait asked for.
        services: Mutex<Vec<String>>,
        waited: Mutex<Vec<String>>,
        /// Services `wait_healthy` never sees healthy.
        down: Vec<String>,
        /// Successive answers; the last one repeats.
        outputs: Mutex<Vec<ExecOutput>>,
    }

    impl Fake {
        fn with(outputs: Vec<ExecOutput>) -> Self {
            Self {
                outputs: Mutex::new(outputs),
                ..Self::default()
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
            service: &str,
            cmd: &[String],
        ) -> hlb_orchestrator::Result<ExecOutput> {
            self.calls.lock().expect("mutex").push(cmd.to_vec());
            self.services.lock().expect("mutex").push(service.into());
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
        async fn wait_healthy(
            &self,
            name: &str,
            _: u64,
        ) -> hlb_orchestrator::Result<ServiceStatus> {
            self.waited.lock().expect("mutex").push(name.into());
            if self.down.iter().any(|d| d == name) {
                return Err(hlb_orchestrator::Error::NotFound(name.into()));
            }
            Ok(ServiceStatus {
                name: name.into(),
                id: "id".into(),
                desired_replicas: 1,
                running_replicas: 1,
                image: "img".into(),
                update_state: None,
            })
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

    const AFTER_RESTORE: &str = r#"
steps:
  - id: tip
    title: Read this
    automate:
      - method: exec
        command: [install-time]
  - id: reindex
    title: Rebuild the search
    phase: post-restore
    automate:
      - method: exec
        service: api
        command: [reindex]
  - id: fsck
    title: Check the files
    phase: post-restore
    automate:
      - method: exec
        command: [fsck]
"#;

    #[tokio::test]
    async fn a_restore_runs_its_steps_alone_each_where_it_names_once_healthy() {
        let orch = Fake::with(vec![Fake::ok(), Fake::ko("Repo[abc] block x is missing.")]);
        let g: hlb_types::Guide = serde_yaml_ng::from_str(AFTER_RESTORE).expect("guide");

        let done = after_restore(&orch, None, "chat", &g, &[]).await;

        let ids: Vec<&str> = done.iter().map(|(s, _)| s.id.as_str()).collect();
        assert_eq!(
            ids,
            ["reindex", "fsck"],
            "an install's step, run by a restore"
        );
        assert_eq!(*orch.calls.lock().expect("mutex"), [["reindex"], ["fsck"]]);
        assert_eq!(
            *orch.services.lock().expect("mutex"),
            ["chat-api", "chat"],
            "each command in the container it names"
        );
        assert_eq!(*orch.waited.lock().expect("mutex"), ["chat-api", "chat"]);
        assert!(done[0].1.handled());
        assert!(
            done[1].1.describe().contains("is missing"),
            "a failed check says what it found: {}",
            done[1].1.describe()
        );
    }

    #[tokio::test]
    async fn a_failure_on_another_node_says_what_it_printed() {
        // There a job's one log holds both streams, and stderr comes back empty.
        let orch = Fake::with(vec![ExecOutput {
            exit_code: 1,
            stdout: "\n[WARNING] Repo[abc] block x is missing.\n".into(),
            stderr: String::new(),
        }]);
        let issue = try_automate(&orch, "files", &step(WITH_EXEC), &[]).await;
        assert!(
            issue
                .describe()
                .contains("exec exited 1: [WARNING] Repo[abc] block x is missing."),
            "{}",
            issue.describe()
        );
    }

    #[tokio::test]
    async fn a_step_whose_service_never_comes_back_is_not_run() {
        let orch = Fake {
            down: vec!["chat-api".into()],
            ..Fake::default()
        };
        let g: hlb_types::Guide = serde_yaml_ng::from_str(AFTER_RESTORE).expect("guide");

        let done = after_restore(&orch, None, "chat", &g, &[]).await;

        assert_eq!(*orch.calls.lock().expect("mutex"), [["fsck"]]);
        assert!(!done[0].1.handled());
        assert!(done[0].1.describe().contains("chat-api is not healthy"));
    }

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
        /// The headers each request carried, by `VERB url`.
        headers: Mutex<Vec<(String, Headers)>>,
        /// Requests that are no write, though not a GET: a sign-in.
        reads: Vec<&'static str>,
    }

    type Headers = Vec<(String, String)>;

    #[async_trait]
    impl ApiClient for Answers {
        async fn call(
            &self,
            verb: &str,
            url: &str,
            headers: &[(String, String)],
            body: Option<&str>,
        ) -> Result<(u16, String), String> {
            let key = format!("{verb} {url}");
            self.sent.lock().expect("mutex").push(
                format!("{key} {}", body.unwrap_or(""))
                    .trim_end()
                    .to_string(),
            );
            self.headers
                .lock()
                .expect("mutex")
                .push((key.clone(), headers.to_vec()));
            {
                let mut first = self.first.lock().expect("mutex");
                if let Some(i) = first.iter().position(|(k, _)| *k == key) {
                    let (_, (c, b)) = first.remove(i);
                    return Ok((c, b.to_string()));
                }
            }
            let written =
                self.sent.lock().expect("mutex").iter().any(|s| {
                    !s.starts_with("GET ") && !self.reads.iter().any(|r| s.starts_with(r))
                });
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
                sign_ins: &[],
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
                sign_ins: &[],
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
                sign_ins: &[],
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
                sign_ins: &[],
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
                sign_ins: &[],
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

    const SSO: &str = r#"
steps:
  - id: sso-provider
    title: The SSO provider
    automate:
      - method: api
        signIn: admin-password
        headers: { Authorization: 'MediaBrowser Token="{{ token }}"' }
        probe: { path: /sso/OID/GetNames, pointer: /0, equals: '"PocketID"' }
        calls:
          - { verb: POST, path: /sso/OID/Add/PocketID, body: '{"Enabled":true}' }
"#;

    fn admin(sign_in: Result<(String, String), String>) -> ApiSignIn {
        ApiSignIn {
            credential: Credential {
                secret: "admin-password".into(),
                sign_in,
            },
            proof: serde_yaml_ng::from_str(
                r#"
path: /Users/AuthenticateByName
body: '{"Username":"{{ username }}","Pw":"{{ password }}"}'
headers: { Authorization: 'MediaBrowser Client="Homelabus"' }
pointer: /AccessToken
"#,
            )
            .expect("proof"),
        }
    }

    async fn sso(api: &Answers, sign_ins: &[ApiSignIn]) -> AutomationOutcome {
        try_automate_with(
            &Fake::default(),
            Some(Api {
                client: api,
                port: Some(8096),
                sign_ins,
            }),
            None,
            "jellyfin",
            &step(SSO),
            &[],
        )
        .await
    }

    #[tokio::test]
    async fn a_step_signs_in_first_and_sends_its_token_with_the_probe_and_every_call() {
        let api = Answers {
            answers: vec![
                (
                    "POST http://jellyfin:8096/Users/AuthenticateByName",
                    (200, r#"{"AccessToken":"tok-123","User":{"Name":"admin"}}"#),
                ),
                ("GET http://jellyfin:8096/sso/OID/GetNames", (200, "[]")),
                ("POST http://jellyfin:8096/sso/OID/Add/PocketID", (204, "")),
            ],
            after: vec![(
                "GET http://jellyfin:8096/sso/OID/GetNames",
                (200, r#"["PocketID"]"#),
            )],
            reads: vec!["POST http://jellyfin:8096/Users/AuthenticateByName"],
            ..Default::default()
        };
        let sign_ins = [admin(Ok(("admin".into(), "pa\"ss".into())))];
        assert_eq!(
            sso(&api, &sign_ins).await,
            AutomationOutcome::Applied { method: "api" }
        );
        let sent = api.sent.lock().expect("mutex");
        assert_eq!(
            sent[0],
            r#"POST http://jellyfin:8096/Users/AuthenticateByName {"Pw":"pa\"ss","Username":"admin"}"#,
            "the proof's body, its password escaped as JSON"
        );
        let headers = api.headers.lock().expect("mutex");
        let token = (
            "Authorization".to_string(),
            r#"MediaBrowser Token="tok-123""#.to_string(),
        );
        assert!(
            headers[0].1.contains(&(
                "Authorization".into(),
                r#"MediaBrowser Client="Homelabus""#.into()
            )) && headers[0].1.contains(&("content-type".into(), JSON.into())),
            "the sign-in as the proof makes it: {:?}",
            headers[0]
        );
        assert_eq!(headers.len(), 4, "sign-in, probe, call, probe: {headers:?}");
        for (key, h) in &headers[1..] {
            assert_eq!(h, std::slice::from_ref(&token), "{key}");
        }
    }

    #[tokio::test]
    async fn a_refused_sign_in_sends_nothing_else_and_says_neither_answer_nor_password() {
        let api = Answers {
            answers: vec![(
                "POST http://jellyfin:8096/Users/AuthenticateByName",
                (401, r#"{"Pw":"hunter2"}"#),
            )],
            ..Default::default()
        };
        let r = sso(&api, &[admin(Ok(("admin".into(), "hunter2".into())))]).await;
        let said = r.describe();
        assert!(
            said.contains("/Users/AuthenticateByName answered 401"),
            "{said}"
        );
        assert!(!said.contains("hunter2"), "{said}");
        assert_eq!(
            api.sent.lock().expect("mutex").len(),
            1,
            "the sign-in alone"
        );

        // Signed in, and no token where the proof reads it: nothing is sent either.
        let tokenless = Answers {
            answers: vec![(
                "POST http://jellyfin:8096/Users/AuthenticateByName",
                (200, r#"{"User":{"Name":"admin"}}"#),
            )],
            ..Default::default()
        };
        let r = sso(&tokenless, &[admin(Ok(("admin".into(), "x".into())))]).await;
        assert!(r.describe().contains("no /AccessToken"), "{}", r.describe());
        assert_eq!(tokenless.sent.lock().expect("mutex").len(), 1);

        // Nothing in the vault yet, or not looked up: nothing is sent at all.
        for (sign_ins, why) in [
            (
                vec![admin(Err("its secret is not generated yet".into()))],
                "not generated yet",
            ),
            (vec![], "was looked up"),
        ] {
            let silent = Answers::default();
            let r = sso(&silent, &sign_ins).await;
            assert!(!r.handled());
            assert!(r.describe().contains(why), "{}", r.describe());
            assert!(silent.sent.lock().expect("mutex").is_empty());
        }
    }

    #[test]
    fn a_merge_keeps_what_the_body_does_not_name() {
        let mut doc = serde_json::json!({
            "EnforceSsoOnly": false,
            "OidConfigs": { "PocketID": { "OidSecret": "s", "CanonicalLinks": { "a": "b" } } },
            "Gone": 1
        });
        merge_patch(
            &mut doc,
            &serde_json::json!({
                "EnforceSsoOnly": true,
                "SsoOnlyExemptUsernames": ["admin"],
                "OidConfigs": { "PocketID": { "OidSecret": "t" } },
                "Gone": null
            }),
        );
        assert_eq!(
            doc,
            serde_json::json!({
                "EnforceSsoOnly": true,
                "SsoOnlyExemptUsernames": ["admin"],
                "OidConfigs": { "PocketID": { "OidSecret": "t", "CanonicalLinks": { "a": "b" } } }
            })
        );
    }

    #[tokio::test]
    async fn a_merged_call_sends_what_it_read_with_its_body_over_it() {
        let y = r#"
steps:
  - id: sso-only
    title: x
    automate:
      - method: api
        calls:
          - { verb: POST, path: /cfg, merge: true, body: '{"EnforceSsoOnly":true}' }
"#;
        let api = Answers {
            answers: vec![
                (
                    "GET http://jellyfin:8096/cfg",
                    (
                        200,
                        r#"{"EnforceSsoOnly":false,"OidConfigs":{"P":{"CanonicalLinks":{"a":"b"}}}}"#,
                    ),
                ),
                ("POST http://jellyfin:8096/cfg", (204, "")),
            ],
            ..Default::default()
        };
        let st = step(y);
        assert_eq!(
            on_8096(&api, &st).await,
            AutomationOutcome::Applied { method: "api" }
        );
        assert_eq!(
            api.sent.lock().expect("mutex")[1],
            r#"POST http://jellyfin:8096/cfg {"EnforceSsoOnly":true,"OidConfigs":{"P":{"CanonicalLinks":{"a":"b"}}}}"#
        );

        // Nothing read, nothing sent: a body alone would reset the rest.
        let refused = Answers {
            answers: vec![(
                "GET http://jellyfin:8096/cfg",
                (401, r#"{"OidSecret":"s"}"#),
            )],
            ..Default::default()
        };
        let r = on_8096(&refused, &st).await;
        assert!(
            r.describe().contains("to merge over, answered 401"),
            "{}",
            r.describe()
        );
        assert!(!r.describe().contains("OidSecret"));
        assert_eq!(refused.sent.lock().expect("mutex").len(), 1);
    }

    async fn on_8096(api: &Answers, st: &GuideStep) -> AutomationOutcome {
        try_automate_with(
            &Fake::default(),
            Some(Api {
                client: api,
                port: Some(8096),
                sign_ins: &[],
            }),
            None,
            "jellyfin",
            st,
            &[],
        )
        .await
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
