//! Reading a manifest's assertions from the running app.
//!
//! The judging is pure — a status and a body, an environment, a value — and tested
//! without a server; [`Reader`] is the only part that reaches one.
//!
//! ## 🔴 What cannot be read is `Unknown`, never `Holds`
//!
//! The app down, its database unreachable, an answer that is not JSON: the door was
//! not looked at, which is not the same as closed. And an answer that IS read and
//! differs is `Broken` — except a status nobody asked about while a body was to be
//! read: a `500` says nothing about whether sign-up is closed.

use std::sync::Arc;

use async_trait::async_trait;
use hlb_api::assertions::{AssertionResult, Verdict};
use hlb_orchestrator::Orchestrator;
use hlb_types::{Assertion, Capability, Check, DbEngine, Manifest, RecoveryLogin};

/// Where the app's answers come from.
#[async_trait]
pub trait Reader: Send + Sync {
    /// A GET that follows no redirect: the status, and the body.
    /// `host`: the `Host` header, when the check names one.
    async fn get(&self, url: &str, host: Option<&str>) -> Result<(u16, String), String>;
    /// A POST that follows no redirect, its body of `content_type` (JSON or a form):
    /// the status, and the body. `basic`: a username and password sent as HTTP Basic.
    async fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        basic: Option<(&str, &str)>,
        content_type: &str,
        body: &str,
    ) -> Result<(u16, String), String>;
    /// The running task's environment, `NAME=value`; `None` when no task runs.
    async fn task_env(&self, service: &str) -> Result<Option<Vec<String>>, String>;
    /// The first column of the first row, in one of the app's databases.
    async fn sql(
        &self,
        engine: DbEngine,
        database: &str,
        query: &str,
    ) -> Result<Option<String>, String>;
}

/// A recovery sign-in as its deposit holds it, looked up by the caller in the vault:
/// the username and the password — or why there is none yet.
#[derive(Debug, Clone)]
pub struct Credential {
    pub secret: String,
    pub sign_in: Result<(String, String), String>,
}

/// What becomes of a recovery sign-in the app refused last time.
#[derive(Debug, Clone, Copy)]
pub enum Refused<'a> {
    /// Tried again: a person asked for it, `hlb assert`.
    TryAgain,
    /// The last reading stands — the nightly pass, given the app's last readings.
    ///
    /// 🔴 Jellyfin disables an administrator after five refused sign-ins, Stalwart bans
    /// the address they came from: tried every night with a password that is wrong,
    /// the proof would turn a recovery sign-in that does not work into an account
    /// nobody can open, the right password included.
    Keep(&'a [AssertionResult]),
}

/// Said of a refusal the nightly pass did not try again.
const NOT_TRIED_AGAIN: &str =
    "not tried again at night: some apps lock an account after a few refusals";

/// The id a recovery sign-in's reading is stored under. A manifest's assertion ids hold
/// no `:`, so none can take it.
pub fn recovery_id(secret: &str) -> String {
    format!("recovery:{secret}")
}

/// One assertion an app answers for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declared {
    pub id: String,
    pub holds: String,
    /// What a person does when it does not hold.
    pub fix: Option<String>,
}

/// Every assertion an app answers for: its manifest's, then one per recovery sign-in —
/// each read by its effect like the others, said where they are said.
pub fn declared(m: &Manifest) -> Vec<Declared> {
    let app = m.metadata.name.as_str();
    let assertions = m.spec.assertions.iter().map(|a| Declared {
        id: a.id.clone(),
        holds: a.holds.clone(),
        fix: a.fix.clone(),
    });
    let recovery = m.spec.recovery.iter().map(|r| {
        let (signs_in, password) = match r.username.as_deref() {
            None => (String::new(), "its recovery password".to_string()),
            Some(u) if u.contains("{{") => (
                " as the address it sends mail from".to_string(),
                "the password of the address it sends mail from".to_string(),
            ),
            Some(u) => (format!(" as \"{u}\""), format!("the password of \"{u}\"")),
        };
        Declared {
            id: recovery_id(&r.secret),
            holds: format!("the emergency vault's password signs in{signs_in}"),
            fix: Some(format!(
                "The vault's password no longer opens it: changed in the app, or the \
                 account is not there. In {app}, set {password} to `hlb secret-get \
                 {app}-{}`, then `hlb assert {app}` signs in again.",
                r.secret
            )),
        }
    });
    assertions.chain(recovery).collect()
}

/// Every assertion of an installed app, read now — its recovery sign-ins with the
/// `credentials` the caller looked up.
pub async fn read_all(
    reader: &dyn Reader,
    m: &Manifest,
    credentials: &[Credential],
    refused: Refused<'_>,
    now: i64,
) -> Vec<AssertionResult> {
    let declared = declared(m);
    let fix_of = |id: &str, verdict: Verdict| {
        (verdict == Verdict::Broken)
            .then(|| {
                declared
                    .iter()
                    .find(|d| d.id == id)
                    .and_then(|d| d.fix.clone())
            })
            .flatten()
    };
    let mut out = Vec::with_capacity(declared.len());
    for a in &m.spec.assertions {
        let (verdict, observed) = read(reader, m, a).await;
        out.push(AssertionResult {
            id: a.id.clone(),
            holds: a.holds.clone(),
            verdict,
            observed,
            checked_at: now,
            fix: fix_of(&a.id, verdict),
        });
    }
    for r in &m.spec.recovery {
        let id = recovery_id(&r.secret);
        let holds = declared
            .iter()
            .find(|d| d.id == id)
            .map(|d| d.holds.clone())
            .unwrap_or_default();
        let last = match refused {
            Refused::Keep(last) => last
                .iter()
                .find(|l| l.id == id && l.verdict == Verdict::Broken),
            Refused::TryAgain => None,
        };
        let (verdict, observed) = match last {
            Some(l) if l.observed.contains(NOT_TRIED_AGAIN) => (l.verdict, l.observed.clone()),
            Some(l) => (
                l.verdict,
                format!(
                    "{} — {NOT_TRIED_AGAIN}; `hlb assert {}` tries again",
                    l.observed, m.metadata.name
                ),
            ),
            None => {
                let credential = credentials.iter().find(|c| c.secret == r.secret);
                prove(reader, m, r, credential).await
            }
        };
        out.push(AssertionResult {
            fix: fix_of(&id, verdict),
            id,
            holds,
            verdict,
            observed,
            checked_at: now,
        });
    }
    out
}

/// Signs in with a recovery sign-in, as its proof says.
async fn prove(
    reader: &dyn Reader,
    m: &Manifest,
    r: &RecoveryLogin,
    credential: Option<&Credential>,
) -> (Verdict, String) {
    let Some(credential) = credential else {
        return (Verdict::Unknown, "its password was not looked up".into());
    };
    let (username, password) = match &credential.sign_in {
        Ok((u, p)) => (u.as_str(), p.as_str()),
        Err(why) => return (Verdict::Unknown, short(why)),
    };
    let Some(port) = m.spec.ingress.first().map(|i| i.port) else {
        return (Verdict::Unknown, "no port to sign in on".into());
    };
    let Some(p) = &r.proof else {
        return (
            Verdict::Unknown,
            format!(
                "its manifest, frozen before sign-ins were proven, says no way to: `hlb \
                 upgrade {}` takes the catalog's",
                m.metadata.name
            ),
        );
    };
    let body = if p.basic {
        p.body.clone()
    } else {
        match fill(&p.body, username, password) {
            Ok(b) => b,
            Err(e) => return (Verdict::Unknown, short(&e)),
        }
    };
    let (content_type, body) = if p.form {
        match form(&body) {
            Ok(b) => (FORM, b),
            Err(e) => return (Verdict::Unknown, short(&e)),
        }
    } else {
        (JSON, body)
    };
    let headers: Vec<(String, String)> = p.headers.clone().into_iter().collect();
    let url = format!("http://{}:{port}{}", m.metadata.name, p.path);
    let basic = p.basic.then_some((username, password));
    match reader
        .post(&url, &headers, basic, content_type, &body)
        .await
    {
        Ok((code, answer)) => judge_sign_in(code, &answer, &p.pointer),
        Err(e) => (Verdict::Unknown, short(&format!("no answer: {e}"))),
    }
}

pub const JSON: &str = "application/json";
pub const FORM: &str = "application/x-www-form-urlencoded";

/// A proof's body, already filled, as a form: one JSON object of strings, each field
/// percent-encoded as browsers encode a form (WHATWG URL, `application/x-www-form-urlencoded`).
pub(crate) fn form(body: &str) -> Result<String, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("the proof's body is not JSON: {e}"))?;
    let fields = v.as_object().ok_or("a form's body is one JSON object")?;
    let encode = |s: &str| {
        let mut out = String::new();
        for b in s.bytes() {
            match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                    out.push(char::from(b));
                }
                b' ' => out.push('+'),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    };
    fields
        .iter()
        .map(|(k, v)| match v {
            serde_json::Value::String(s) => Ok(format!("{}={}", encode(k), encode(s))),
            _ => Err(format!("a form's field `{k}` is not a string")),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|f| f.join("&"))
}

/// A proof's body with the sign-in in its strings, escaped as JSON.
pub(crate) fn fill(body: &str, username: &str, password: &str) -> Result<String, String> {
    fn walk(v: &mut serde_json::Value, username: &str, password: &str) {
        match v {
            serde_json::Value::String(s) => {
                *s = s
                    .replace("{{ username }}", username)
                    .replace("{{ password }}", password);
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(|v| walk(v, username, password)),
            serde_json::Value::Object(o) => {
                o.values_mut().for_each(|v| walk(v, username, password));
            }
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            }
        }
    }
    let mut v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("the proof's body is not JSON: {e}"))?;
    walk(&mut v, username, password);
    Ok(v.to_string())
}

/// What a sign-in answered. 🔴 Its body is never said: an app may echo what it was sent.
pub fn judge_sign_in(code: u16, body: &str, pointer: &str) -> (Verdict, String) {
    match code {
        200..=299 => {
            let held = serde_json::from_str::<serde_json::Value>(body)
                .ok()
                .and_then(|j| j.pointer(pointer).cloned())
                .filter(|v| !matches!(v, serde_json::Value::Null | serde_json::Value::Bool(false)))
                .filter(|v| v.as_str() != Some(""));
            match held {
                Some(_) => (
                    Verdict::Holds,
                    format!("signed in: answered {code} with {pointer}"),
                ),
                // A page, most likely — n8n's while it starts: neither in nor refused.
                None => (
                    Verdict::Unknown,
                    format!("answered {code} without {pointer}: not known to be signed in"),
                ),
            }
        }
        400 | 401 | 403 => (Verdict::Broken, format!("refused: answered {code}")),
        429 => (
            Verdict::Unknown,
            "answered 429: too many sign-ins for it now — read again next time".into(),
        ),
        _ => (Verdict::Unknown, format!("answered {code}")),
    }
}

/// One assertion: its verdict, and what the app said.
pub async fn read(reader: &dyn Reader, m: &Manifest, a: &Assertion) -> (Verdict, String) {
    let app = m.metadata.name.as_str();
    match &a.check {
        Check::Http {
            path,
            port,
            status,
            pointer,
            equals,
            contains,
            host,
        } => {
            let Some(port) = port.or_else(|| m.spec.ingress.first().map(|i| i.port)) else {
                return (Verdict::Unknown, "no port to read it on".into());
            };
            // The service by its name on the overlay, as the ingress reaches it.
            match reader
                .get(&format!("http://{app}:{port}{path}"), host.as_deref())
                .await
            {
                Ok((code, body)) => judge_http(
                    code,
                    &body,
                    status,
                    pointer.as_deref().zip(equals.as_ref()),
                    contains.as_deref(),
                ),
                Err(e) => (Verdict::Unknown, short(&format!("no answer: {e}"))),
            }
        }
        Check::Env { name, equals } => match reader.task_env(app).await {
            Ok(env) => judge_env(env.as_deref(), name, equals),
            Err(e) => (Verdict::Unknown, short(&format!("Swarm not read: {e}"))),
        },
        Check::Sql {
            query,
            database,
            equals,
        } => {
            let Some((engine, db)) = database_of(m, database.as_deref()) else {
                return (Verdict::Unknown, "the app requires no such database".into());
            };
            match reader.sql(engine, &db, query).await {
                Ok(value) => judge_sql(value.as_deref(), equals),
                Err(e) => (Verdict::Unknown, short(&format!("not read: {e}"))),
            }
        }
    }
}

/// The engine and the name of the database an SQL assertion reads: the one it names,
/// or the app's only one, which is named after the app unless it says otherwise.
fn database_of(m: &Manifest, wanted: Option<&str>) -> Option<(DbEngine, String)> {
    m.spec.requires.iter().find_map(|c| match c {
        Capability::Database {
            engine,
            name,
            extensions: _,
            connections: _,
        } => {
            let db = name.clone().unwrap_or_else(|| m.metadata.name.clone());
            (wanted.is_none() || wanted == Some(db.as_str())).then_some((*engine, db))
        }
        _ => None,
    })
}

pub fn judge_http(
    code: u16,
    body: &str,
    expected: &[u16],
    read: Option<(&str, &serde_json::Value)>,
    contains: Option<&str>,
) -> (Verdict, String) {
    let reads_the_body = read.is_some() || contains.is_some();
    if !expected.contains(&code) {
        // A status was the whole question: the app answered it, wrongly.
        if !reads_the_body {
            return (Verdict::Broken, format!("answered {code}"));
        }
        return (
            Verdict::Unknown,
            format!("answered {code}: nothing to read in it"),
        );
    }
    if let Some((pointer, want)) = read {
        let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
            return (
                Verdict::Unknown,
                short(&format!("not JSON: {}", body.trim())),
            );
        };
        let Some(got) = json.pointer(pointer) else {
            return (Verdict::Unknown, format!("{pointer} is not in the answer"));
        };
        if got != want {
            return (Verdict::Broken, short(&format!("{pointer} is {got}")));
        }
        if contains.is_none() {
            return (Verdict::Holds, short(&format!("{pointer} is {got}")));
        }
    }
    if let Some(text) = contains {
        if !body.contains(text) {
            return (
                Verdict::Broken,
                short(&format!("the page does not say “{text}”")),
            );
        }
        return (Verdict::Holds, short(&format!("the page says “{text}”")));
    }
    (Verdict::Holds, format!("answered {code}"))
}

pub fn judge_env(env: Option<&[String]>, name: &str, equals: &str) -> (Verdict, String) {
    let Some(env) = env else {
        return (Verdict::Unknown, "no task runs".into());
    };
    let value = env.iter().find_map(|kv| {
        kv.split_once('=')
            .filter(|(k, _)| *k == name)
            .map(|(_, v)| v)
    });
    // A value the manifest expects is the manifest's, and public; any other may be a
    // secret, and is never written down — not even in a verdict.
    match value {
        None => (Verdict::Broken, format!("{name} is not set")),
        Some(v) if v != equals => (
            Verdict::Broken,
            short(&format!("{name}={}", hlb_types::redact(name, v))),
        ),
        Some(v) => (Verdict::Holds, short(&format!("{name}={v}"))),
    }
}

pub fn judge_sql(value: Option<&str>, equals: &str) -> (Verdict, String) {
    match value {
        None => (Verdict::Broken, "no row".into()),
        Some(v) if v.trim() != equals => (Verdict::Broken, short(&format!("read {}", v.trim()))),
        Some(v) => (Verdict::Holds, short(&format!("read {}", v.trim()))),
    }
}

/// What the app said, cut to what a line of the inbox holds.
fn short(s: &str) -> String {
    const MAX: usize = 160;
    let one_line = s.split_whitespace().collect::<Vec<_>>().join(" ");
    match one_line.char_indices().nth(MAX) {
        Some((at, _)) => format!("{}…", &one_line[..at]),
        None => one_line,
    }
}

/// The reader that reaches the real installation.
pub struct LiveReader {
    http: reqwest::Client,
    orchestrator: Option<Arc<dyn Orchestrator>>,
    postgres_admin: Option<String>,
    mariadb_admin: Option<String>,
    /// Rewrites an overlay address into one this process reaches: the identity on the
    /// overlay, a relay from a manager's shell.
    reach: Box<dyn Fn(&str) -> String + Send + Sync>,
}

impl LiveReader {
    pub fn new(
        orchestrator: Option<Arc<dyn Orchestrator>>,
        postgres_admin: Option<String>,
        mariadb_admin: Option<String>,
    ) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            orchestrator,
            postgres_admin,
            mariadb_admin,
            reach: Box::new(str::to_string),
        }
    }

    pub fn reaching(mut self, reach: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        self.reach = Box::new(reach);
        self
    }
}

#[async_trait]
impl Reader for LiveReader {
    async fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        basic: Option<(&str, &str)>,
        content_type: &str,
        body: &str,
    ) -> Result<(u16, String), String> {
        let mut req = self
            .http
            .post((self.reach)(url))
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body.to_string());
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some((user, password)) = basic {
            req = req.basic_auth(user, Some(password));
        }
        let r = req.send().await.map_err(|e| e.to_string())?;
        let code = r.status().as_u16();
        Ok((code, r.text().await.unwrap_or_default()))
    }

    async fn get(&self, url: &str, host: Option<&str>) -> Result<(u16, String), String> {
        let mut req = self.http.get((self.reach)(url));
        if let Some(h) = host {
            req = req.header(reqwest::header::HOST, h);
        }
        let r = req.send().await.map_err(|e| e.to_string())?;
        let code = r.status().as_u16();
        Ok((code, r.text().await.unwrap_or_default()))
    }

    async fn task_env(&self, service: &str) -> Result<Option<Vec<String>>, String> {
        match &self.orchestrator {
            Some(o) => o.running_env(service).await.map_err(|e| e.to_string()),
            None => Err("no orchestrator".into()),
        }
    }

    async fn sql(
        &self,
        engine: DbEngine,
        database: &str,
        query: &str,
    ) -> Result<Option<String>, String> {
        let admin = match engine {
            DbEngine::Postgres => &self.postgres_admin,
            DbEngine::Mariadb => &self.mariadb_admin,
        };
        let Some(url) = admin else {
            return Err(format!("no {engine:?} admin connection given"));
        };
        let url = (self.reach)(url);
        match engine {
            DbEngine::Postgres => hlb_platform::PostgresProvisioner::connect(&url)
                .await
                .map_err(|e| e.to_string())?
                .read_one(database, query)
                .await
                .map_err(|e| e.to_string()),
            DbEngine::Mariadb => hlb_platform::MariadbProvisioner::connect(&url)
                .await
                .map_err(|e| e.to_string())?
                .read_one(database, query)
                .await
                .map_err(|e| e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_json_value_is_judged_and_a_body_that_is_not_one_is_unknown() {
        let want = json!(false);
        let read = Some(("/allowed", &want));
        assert_eq!(
            judge_http(200, r#"{"allowed":false}"#, &[200], read, None).0,
            Verdict::Holds
        );
        let (v, said) = judge_http(200, r#"{"allowed":true}"#, &[200], read, None);
        assert_eq!((v, said.as_str()), (Verdict::Broken, "/allowed is true"));
        assert_eq!(
            judge_http(200, "<html>", &[200], read, None).0,
            Verdict::Unknown
        );
        assert_eq!(
            judge_http(200, "{}", &[200], read, None).0,
            Verdict::Unknown
        );
    }

    #[test]
    fn a_wrong_status_is_broken_only_when_the_status_was_the_question() {
        // Anonymous reads refused: a 200 is the door open.
        assert_eq!(judge_http(200, "", &[403], None, None).0, Verdict::Broken);
        assert_eq!(judge_http(403, "", &[403], None, None).0, Verdict::Holds);
        // A body to read and a 500: nothing is known.
        let want = json!(true);
        assert_eq!(
            judge_http(500, "", &[200], Some(("/a", &want)), None).0,
            Verdict::Unknown
        );
        assert_eq!(
            judge_http(502, "", &[200], None, Some("disabled")).0,
            Verdict::Unknown
        );
    }

    #[test]
    fn a_page_is_judged_by_what_it_says() {
        let closed = "<p>Registration is disabled. Please contact your site administrator.</p>";
        let says = Some("Registration is disabled");
        assert_eq!(
            judge_http(200, closed, &[200], None, says).0,
            Verdict::Holds
        );
        assert_eq!(
            judge_http(200, "<form>Register Account</form>", &[200], None, says).0,
            Verdict::Broken
        );
    }

    #[test]
    fn an_environment_is_judged_and_a_secret_never_shown() {
        let env = vec![
            "ALLOW_REGISTRATION=true".to_string(),
            "SSO_CLIENT_SECRET=hunter2".to_string(),
        ];
        assert_eq!(
            judge_env(Some(&env), "ALLOW_REGISTRATION", "false"),
            (Verdict::Broken, "ALLOW_REGISTRATION=true".into())
        );
        assert_eq!(
            judge_env(Some(&env), "ENABLE_TELEMETRY", "false").0,
            Verdict::Broken
        );
        let (v, said) = judge_env(Some(&env), "SSO_CLIENT_SECRET", "other");
        assert_eq!(v, Verdict::Broken);
        assert!(!said.contains("hunter2"), "{said}");
        assert_eq!(
            judge_env(None, "ALLOW_REGISTRATION", "false").0,
            Verdict::Unknown
        );
    }

    #[test]
    fn a_value_is_compared_as_read() {
        assert_eq!(judge_sql(Some("0"), "0").0, Verdict::Holds);
        assert_eq!(
            judge_sql(Some("1"), "0"),
            (Verdict::Broken, "read 1".into())
        );
        assert_eq!(judge_sql(None, "0").0, Verdict::Broken);
    }

    struct Answers;

    #[async_trait]
    impl Reader for Answers {
        async fn post(
            &self,
            _: &str,
            _: &[(String, String)],
            _: Option<(&str, &str)>,
            _: &str,
            _: &str,
        ) -> Result<(u16, String), String> {
            Err("connection refused".into())
        }
        async fn get(&self, url: &str, _: Option<&str>) -> Result<(u16, String), String> {
            match url {
                "http://termix:8080/users/registration-allowed" => {
                    Ok((200, r#"{"allowed":false}"#.into()))
                }
                _ => Err("connection refused".into()),
            }
        }
        async fn task_env(&self, _: &str) -> Result<Option<Vec<String>>, String> {
            Err("no Swarm here".into())
        }
        async fn sql(&self, _: DbEngine, db: &str, _: &str) -> Result<Option<String>, String> {
            Ok(Some(db.to_string()))
        }
    }

    #[tokio::test]
    async fn every_assertion_is_read_at_the_apps_own_address() {
        let m: Manifest = serde_yaml_ng::from_str(
            r#"
apiVersion: hlb/v1
kind: App
metadata: { name: termix }
spec:
  image: { repo: termix, tag: "1" }
  requires:
    - { kind: database, engine: mariadb, name: ccnet_db }
  ingress:
    - { host: t.example.org, port: 8080 }
  assertions:
    - id: registration
      holds: nobody signs up
      check: { type: http, path: /users/registration-allowed, pointer: /allowed, equals: false }
    - id: elsewhere
      holds: x
      check: { type: http, path: /a, port: 9 }
    - id: telemetry
      holds: y
      check: { type: env, name: ENABLE_TELEMETRY, equals: "false" }
    - id: database
      holds: z
      check: { type: sql, query: SELECT 1, equals: ccnet_db }
"#,
        )
        .expect("manifest");
        let read = read_all(&Answers, &m, &[], Refused::TryAgain, 7).await;
        assert_eq!(
            read.iter().map(|r| r.verdict).collect::<Vec<_>>(),
            [
                Verdict::Holds,
                Verdict::Unknown,
                Verdict::Unknown,
                Verdict::Holds
            ]
        );
        assert!(read.iter().all(|r| r.checked_at == 7));
    }

    #[test]
    fn a_sign_in_is_judged_and_its_answer_never_said() {
        let (v, said) = judge_sign_in(200, r#"{"token":"abc"}"#, "/token");
        assert_eq!(v, Verdict::Holds);
        assert!(!said.contains("abc"), "{said}");
        // Refused, whatever it says: an app may echo the password it was sent.
        let (v, said) = judge_sign_in(401, r#"{"error":"wrong hunter2"}"#, "/token");
        assert_eq!(v, Verdict::Broken);
        assert!(!said.contains("hunter2"), "{said}");
        assert_eq!(judge_sign_in(400, "", "/token").0, Verdict::Broken);
        // A page, n8n's while it starts: neither in nor refused.
        assert_eq!(judge_sign_in(200, "<html>", "/data/id").0, Verdict::Unknown);
        assert_eq!(
            judge_sign_in(200, r#"{"ok":false}"#, "/ok").0,
            Verdict::Unknown
        );
        assert_eq!(judge_sign_in(429, "", "/ok").0, Verdict::Unknown);
        assert_eq!(judge_sign_in(502, "", "/ok").0, Verdict::Unknown);
    }

    #[test]
    fn a_password_goes_into_the_body_escaped_as_json() {
        let body = fill(
            r#"{"user":"{{ username }}","password":"{{ password }}"}"#,
            "admin",
            r#"a"b\c"#,
        )
        .expect("filled");
        let v: serde_json::Value = serde_json::from_str(&body).expect("still JSON");
        assert_eq!(v["password"], r#"a"b\c"#);
        assert_eq!(v["user"], "admin");
    }

    #[test]
    fn a_form_is_encoded_as_a_browser_encodes_one() {
        let filled = fill(
            r#"{"username":"admin","password":"{{ password }}"}"#,
            "admin",
            "a&b=c+d é",
        )
        .expect("filled");
        assert_eq!(
            form(&filled).as_deref(),
            // serde_json sorts the fields, which a form never minds.
            Ok("password=a%26b%3Dc%2Bd+%C3%A9&username=admin")
        );
        assert!(form(r#"{"n":1}"#).is_err());
        assert!(form("[]").is_err());
    }

    /// Signs in whoever sends the form a made-up app's token endpoint takes.
    struct FormOnly;

    #[async_trait]
    impl Reader for FormOnly {
        async fn post(
            &self,
            url: &str,
            _: &[(String, String)],
            basic: Option<(&str, &str)>,
            content_type: &str,
            body: &str,
        ) -> Result<(u16, String), String> {
            assert_eq!(url, "http://recipes:9000/api/auth/token");
            assert!(basic.is_none());
            // As such an app reads a JSON body: empty fields, refused.
            Ok(
                if content_type == FORM && body == "password=s%26cret&username=admin" {
                    (200, r#"{"access_token":"t","token_type":"bearer"}"#.into())
                } else {
                    (401, String::new())
                },
            )
        }
        async fn get(&self, _: &str, _: Option<&str>) -> Result<(u16, String), String> {
            Err("no".into())
        }
        async fn task_env(&self, _: &str) -> Result<Option<Vec<String>>, String> {
            Err("no".into())
        }
        async fn sql(&self, _: DbEngine, _: &str, _: &str) -> Result<Option<String>, String> {
            Err("no".into())
        }
    }

    #[tokio::test]
    async fn a_recovery_sign_in_by_form_is_sent_as_a_form() {
        let manifest = |form: bool| -> Manifest {
            serde_yaml_ng::from_str(&format!(
                r#"
apiVersion: hlb/v1
kind: App
metadata: {{ name: recipes }}
spec:
  image: {{ repo: recipes, tag: "1" }}
  ingress:
    - {{ host: r.example.org, port: 9000 }}
  recovery:
    - secret: admin-password
      username: admin
      proof:
        path: /api/auth/token
        body: '{{"username":"{{{{ username }}}}","password":"{{{{ password }}}}"}}'
        form: {form}
        pointer: /access_token
"#
            ))
            .expect("manifest")
        };
        let credentials = [Credential {
            secret: "admin-password".into(),
            sign_in: Ok(("admin".into(), "s&cret".into())),
        }];
        let read = read_all(
            &FormOnly,
            &manifest(true),
            &credentials,
            Refused::TryAgain,
            1,
        )
        .await;
        assert_eq!(read[0].verdict, Verdict::Holds, "{}", read[0].observed);
        // The same proof sent as JSON is what the app refuses.
        let read = read_all(
            &FormOnly,
            &manifest(false),
            &credentials,
            Refused::TryAgain,
            1,
        )
        .await;
        assert_eq!(read[0].verdict, Verdict::Broken, "{}", read[0].observed);
    }

    /// Refuses every sign-in, and counts them.
    #[derive(Default)]
    struct Refusing(std::sync::Mutex<usize>);

    #[async_trait]
    impl Reader for Refusing {
        async fn post(
            &self,
            url: &str,
            _: &[(String, String)],
            basic: Option<(&str, &str)>,
            content_type: &str,
            body: &str,
        ) -> Result<(u16, String), String> {
            assert_eq!(url, "http://jellyfin:8096/Users/AuthenticateByName");
            assert_eq!(content_type, JSON);
            assert!(basic.is_none());
            assert!(body.contains("Trial-pass-1"), "{body}");
            *self.0.lock().expect("lock") += 1;
            Ok((401, "Error processing request.".into()))
        }
        async fn get(&self, _: &str, _: Option<&str>) -> Result<(u16, String), String> {
            Err("no".into())
        }
        async fn task_env(&self, _: &str) -> Result<Option<Vec<String>>, String> {
            Err("no".into())
        }
        async fn sql(&self, _: DbEngine, _: &str, _: &str) -> Result<Option<String>, String> {
            Err("no".into())
        }
    }

    fn jellyfin() -> Manifest {
        serde_yaml_ng::from_str(
            r#"
apiVersion: hlb/v1
kind: App
metadata: { name: jellyfin }
spec:
  image: { repo: jellyfin, tag: "1" }
  ingress:
    - { host: j.example.org, port: 8096 }
  recovery:
    - secret: admin-password
      username: admin
      proof:
        path: /Users/AuthenticateByName
        body: '{"Username":"{{ username }}","Pw":"{{ password }}"}'
        pointer: /AccessToken
"#,
        )
        .expect("manifest")
    }

    #[tokio::test]
    async fn a_refused_recovery_sign_in_is_not_tried_again_at_night() {
        let m = jellyfin();
        let credentials = [Credential {
            secret: "admin-password".into(),
            sign_in: Ok(("admin".into(), "Trial-pass-1".into())),
        }];
        let app = Refusing::default();
        let asked = read_all(&app, &m, &credentials, Refused::TryAgain, 1).await;
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].id, "recovery:admin-password");
        assert_eq!(asked[0].verdict, Verdict::Broken);
        assert!(asked[0]
            .fix
            .as_deref()
            .is_some_and(|f| f.contains("hlb secret-get jellyfin-admin-password")));
        // 🔴 Jellyfin disables an administrator after five refusals: the night keeps
        // the refusal it has, and says so — once.
        let night = read_all(&app, &m, &credentials, Refused::Keep(&asked), 2).await;
        let again = read_all(&app, &m, &credentials, Refused::Keep(&night), 3).await;
        assert_eq!(*app.0.lock().expect("lock"), 1, "tried again at night");
        assert_eq!(again[0].verdict, Verdict::Broken);
        assert_eq!(
            again[0].checked_at, 3,
            "a refusal kept is still known, not stale"
        );
        assert_eq!(
            again[0].observed.matches(NOT_TRIED_AGAIN).count(),
            1,
            "{}",
            again[0].observed
        );
        // One that held, or was not read, is tried.
        let unread = AssertionResult {
            verdict: Verdict::Unknown,
            ..asked[0].clone()
        };
        read_all(&app, &m, &credentials, Refused::Keep(&[unread]), 4).await;
        assert_eq!(*app.0.lock().expect("lock"), 2);
    }

    #[tokio::test]
    async fn a_sign_in_with_no_password_yet_is_unknown_never_refused() {
        let m = jellyfin();
        let waiting = [Credential {
            secret: "admin-password".into(),
            sign_in: Err("its secret is not generated yet".into()),
        }];
        let app = Refusing::default();
        for credentials in [&waiting[..], &[]] {
            let read = read_all(&app, &m, credentials, Refused::TryAgain, 1).await;
            assert_eq!(read[0].verdict, Verdict::Unknown, "{}", read[0].observed);
            assert_eq!(read[0].fix, None);
        }
        assert_eq!(*app.0.lock().expect("lock"), 0);
    }

    #[test]
    fn every_recovery_sign_in_is_declared_after_the_assertions() {
        let mut m = jellyfin();
        m.spec.assertions = serde_yaml_ng::from_str(
            "- { id: wizard-done, holds: x, check: { type: env, name: A, equals: b }, fix: do y }",
        )
        .expect("assertions");
        let d = declared(&m);
        assert_eq!(
            d.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
            ["wizard-done", "recovery:admin-password"]
        );
        assert_eq!(d[0].fix.as_deref(), Some("do y"));
        assert!(d[1].holds.contains("\"admin\""), "{}", d[1].holds);
    }

    #[tokio::test]
    async fn a_manifest_frozen_before_proofs_is_read_and_its_sign_in_not_judged() {
        let m: Manifest = serde_yaml_ng::from_str(
            r#"
apiVersion: hlb/v1
kind: App
metadata: { name: seafile }
spec:
  image: { repo: seafile, tag: "1" }
  ingress: [{ host: s.example.org, port: 80 }]
  recovery:
    - { secret: admin-password, username: admin, path: /accounts/login/ }
"#,
        )
        .expect("a frozen manifest from before proofs still reads");
        let credentials = [Credential {
            secret: "admin-password".into(),
            sign_in: Ok(("admin".into(), "Trial-pass-1".into())),
        }];
        let app = Refusing::default();
        let read = read_all(&app, &m, &credentials, Refused::TryAgain, 1).await;
        assert_eq!(read[0].verdict, Verdict::Unknown);
        assert!(
            read[0].observed.contains("hlb upgrade seafile"),
            "{}",
            read[0].observed
        );
        assert_eq!(*app.0.lock().expect("lock"), 0);
    }
}
