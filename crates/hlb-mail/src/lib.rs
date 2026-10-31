//! Client for Stalwart's administration API.
//!
//! This is what makes a mailbox as automatic as a database: installing an app creates
//! its account, its password and its aliases without ever opening Stalwart's own
//! interface.
//!
//! ## 🔴 This is not a REST API
//!
//! Contrary to what one expects from a mail server, Stalwart 0.16 exposes **no**
//! `/api/principal`. Its `/api/` surface is limited to `auth`, `account`, `schema`,
//! `token`, `live`, `telemetry` and `diagnose`; all account management goes through
//! **JMAP**, at `POST /jmap/`, with the vendor capability `urn:stalwart:jmap`.
//!
//! Methods follow the shape `x:Object/verb`:
//!
//! | Operation | JMAP call |
//! |---|---|
//! | Find a domain | `x:Domain/query` |
//! | Look up an account | `x:Account/query` |
//! | Create or modify | `x:Account/set` |
//!
//! This shape is checked against the schema Stalwart itself publishes
//! (`resources/schema/schema.json.gz`, served at `/api/schema/{hash}`) and against
//! `crates/registry/src/schema/structs.rs` upstream - not inferred from a blog post.
//!
//! ## 🔴 One filter condition carries ONE property
//!
//! Deserialising a registry filter runs `*self = RegistryFilter::Property { ... }` **on
//! every key it meets**. A condition carrying two properties therefore keeps only one -
//! the last - without the slightest warning.
//!
//! Searching for `{"name": "gitea", "domainId": "d1"}` amounts to searching for
//! `{"domainId": "d1"}`: you would match any account in the domain, or a `gitea` from
//! **another** domain depending on key order. For idempotent provisioning, this is the
//! mistake that hands an app the credentials of a mailbox that is not its own.
//!
//! The correct shape is JMAP's `AND`, one property per condition:
//!
//! ```json
//! { "filter": { "operator": "AND", "conditions": [
//!     { "name": "gitea" }, { "domainId": "d1" } ] } }
//! ```
//!
//! Only `AND` is accepted: `OR` and `NOT` are rejected by the server.
//!
//! ## About `accountId`
//!
//! Standard JMAP methods require an `accountId`. Here they do **not**: `Account` and
//! `Domain` carry the flags `OBJ_FILTER_TENANT | OBJ_SEQ_ID`, not
//! `OBJ_FILTER_ACCOUNT`. The server only reads `accountId` for objects marked with the
//! latter (`ArchivedItem`, `MaskedEmail`, `PublicKey`, `SpamTrainingSample`), and
//! `SetResponse::from_request` handles its absence without error. Omitting it is
//! deliberate, not an oversight.
//!
//! ## The three other traps in this API
//!
//! 1. **`emailAddress` is computed by the server.** You set `name` (the local part)
//!    and `domainId`; sending `emailAddress` raises no error and has no effect. You
//!    would believe you created `gitea@example.org` having created something else.
//! 2. **`domainId` is an object reference, not a string.** The domain must exist in
//!    Stalwart *before* the account, and its id has to be resolved.
//! 3. **JMAP returns HTTP 200 even when creation fails.** The failure lives in
//!    `notCreated`. A client that only looks at the HTTP code reports an imaginary
//!    success - the central trap of this module.

use serde::{Deserialize, Serialize};

pub mod public_dns;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Stalwart unreachable ({context}) : {source}")]
    Http {
        #[source]
        source: reqwest::Error,
        context: String,
    },

    #[error("Stalwart answered {status} - {detail}")]
    Api { status: u16, detail: String },

    #[error("credentials refused by Stalwart")]
    Unauthorized,

    #[error("unexpected response from Stalwart: {0}")]
    Unexpected(String),

    /// 🔴 The failure the HTTP code does not report.
    #[error("Stalwart refused to create {object}: {reason}")]
    NotCreated { object: String, reason: String },

    #[error(
        "domain \"{0}\" does not exist in Stalwart - an account cannot be created \
         on a missing domain; create it first"
    )]
    UnknownDomain(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Which of Stalwart's two schemas a server speaks.
///
/// 1.0 renamed settings Homelabus writes, and refuses the old name with `invalidPatch —
/// Invalid key for object` under HTTP 200: an alias, a listener or a relay written
/// under the other generation's name is simply not created. Every renamed field is a
/// `match` on this, so a third generation breaks the build where a name must be chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Generation {
    /// 0.16, the first with the JMAP registry (`x:Account/set`).
    V016,
    /// 1.0, a new store layout: a 0.16 store is migrated into it, never opened.
    V1,
}

impl Generation {
    /// Read from the JMAP session: 1.0 announces JMAP Object Metadata, 0.16.27 does
    /// not. No version is served anywhere else — not `/api/account`, not a header.
    fn of_session(session: &serde_json::Value) -> Result<Self> {
        let caps = session
            .get("capabilities")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                Error::Unexpected(format!("a JMAP session with no capabilities: {session}"))
            })?;
        Ok(if caps.contains_key(METADATA) {
            Self::V1
        } else {
            Self::V016
        })
    }

    /// `NetworkListener`'s implicit TLS.
    fn implicit_tls(self) -> &'static str {
        match self {
            Self::V016 => "tlsImplicit",
            Self::V1 => "implicitTls",
        }
    }

    /// `SpamClassify`'s envelope: `(sender, recipients)`.
    fn envelope(self) -> (&'static str, &'static str) {
        match self {
            Self::V016 => ("envFrom", "envRcptTo"),
            Self::V1 => ("mailFrom", "rcptTo"),
        }
    }

    /// `MtaRouteRelay`'s server.
    pub fn relay_host(self) -> &'static str {
        match self {
            Self::V016 => "address",
            Self::V1 => "host",
        }
    }

    /// `DnsServerPorkbun`'s credentials: `(key, secret)`.
    pub fn porkbun_keys(self) -> (&'static str, &'static str) {
        match self {
            Self::V016 => ("apiKey", "secretApiKey"),
            Self::V1 => ("apiKeyId", "secret"),
        }
    }
}

/// The vendor capability, without which Stalwart rejects the `x:` methods.
const CAPABILITY: &str = "urn:stalwart:jmap";
const CORE: &str = "urn:ietf:params:jmap:core";
/// `SieveScript/*` is refused as an "unknownMethod" without it in `using`.
const SIEVE: &str = "urn:ietf:params:jmap:sieve";
/// Announced by 1.0 and not by 0.16: how [`Generation`] is told.
const METADATA: &str = "urn:ietf:params:jmap:metadata";

/// A JMAP request.
#[derive(Debug, Serialize)]
struct JmapRequest {
    using: Vec<&'static str>,
    #[serde(rename = "methodCalls")]
    method_calls: Vec<serde_json::Value>,
}

impl JmapRequest {
    fn one(method: &str, args: serde_json::Value) -> Self {
        Self {
            using: vec![CORE, CAPABILITY, SIEVE],
            method_calls: vec![serde_json::json!([method, args, "c0"])],
        }
    }
}

#[derive(Debug, Deserialize)]
struct JmapResponse {
    #[serde(rename = "methodResponses", default)]
    method_responses: Vec<serde_json::Value>,
}

impl JmapResponse {
    /// The arguments of the first response.
    ///
    /// An `error` response is returned as such: JMAP encodes method errors in the
    /// response list, not in the HTTP code.
    fn first(self) -> Result<serde_json::Value> {
        let r = self
            .method_responses
            .into_iter()
            .next()
            .ok_or_else(|| Error::Unexpected("no method response".into()))?;

        let name = r.get(0).and_then(|v| v.as_str()).unwrap_or("?").to_string();
        let args = r
            .get(1)
            .cloned()
            .ok_or_else(|| Error::Unexpected("response carried no arguments".into()))?;

        if name == "error" {
            let t = args
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            return Err(Error::Api {
                status: 200,
                detail: format!("JMAP error \"{t}\": {args}"),
            });
        }
        Ok(args)
    }
}

/// An account as Stalwart describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailAccount {
    pub id: String,
    /// The local part, without the domain.
    pub name: String,
    pub domain_id: String,
}

/// What provisioning returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provisioned {
    pub account_id: String,
    pub address: String,
    /// `false` when the account already existed: its password was **not** changed.
    pub created: bool,
}

/// The creation id we hand JMAP, and read the answer back under.
///
/// 🔴 A CONSTANT, not a literal repeated three times. The key is ours to choose, but the
/// write and the two reads must agree: JMAP answers under the same id it was given. When
/// they drifted apart, `notCreated` stopped matching — and a failed creation returns
/// HTTP 200, so nothing else would have said so. The account would simply not exist.
const CREATION_ID: &str = "new";

/// How we authenticate to Stalwart.
#[derive(Debug, Clone)]
pub enum Auth {
    /// An administration account: `Authorization: Basic`.
    Basic { user: String, password: String },
    /// An API token: `Authorization: Bearer`.
    Bearer(String),
}

pub struct Stalwart {
    base_url: String,
    auth: Auth,
    http: reqwest::Client,
    /// Asked once: a server does not change schema under a running client.
    generation: std::sync::OnceLock<Generation>,
}

impl Stalwart {
    pub fn new(base_url: impl Into<String>, auth: Auth) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            auth,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                // Stalwart closes an idle connection on its side, and reusing it failed
                // "IncompleteMessage" a minute into a long run (0.16.26).
                .pool_idle_timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            generation: std::sync::OnceLock::new(),
        }
    }

    fn endpoint(&self) -> String {
        format!("{}/jmap/", self.base_url)
    }

    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            Auth::Basic { user, password } => req.basic_auth(user, Some(password)),
            Auth::Bearer(t) => req.bearer_auth(t),
        }
    }

    /// Which schema the server speaks, read from its JMAP session the first time.
    pub async fn generation(&self) -> Result<Generation> {
        if let Some(g) = self.generation.get() {
            return Ok(*g);
        }
        let context = "the JMAP session";
        let resp = self
            .authed(self.http.get(format!("{}/jmap/session", self.base_url)))
            .send()
            .await
            .map_err(|source| Error::Http {
                source,
                context: context.into(),
            })?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized);
        }
        if !resp.status().is_success() {
            return Err(Error::Api {
                status: resp.status().as_u16(),
                detail: context.into(),
            });
        }
        let body = bounded(resp, MAX_BODY)
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable session: {e}")))?;
        let session: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| Error::Unexpected(format!("unreadable session: {e}")))?;
        let g = Generation::of_session(&session)?;
        Ok(*self.generation.get_or_init(|| g))
    }

    async fn call(&self, method: &str, args: serde_json::Value) -> Result<serde_json::Value> {
        let req = self.authed(
            self.http
                .post(self.endpoint())
                .json(&JmapRequest::one(method, args)),
        );

        let resp = req.send().await.map_err(|source| Error::Http {
            source,
            context: method.to_string(),
        })?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let detail =
                String::from_utf8_lossy(&bounded(resp, MAX_ERROR).await.unwrap_or_default())
                    .into_owned();
            return Err(Error::Api { status, detail });
        }

        let body = bounded(resp, MAX_BODY)
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable response: {e}")))?;
        let body: JmapResponse = serde_json::from_slice(&body)
            .map_err(|e| Error::Unexpected(format!("unreadable response: {e}")))?;
        body.first()
    }

    /// Checks the API answers and the credentials are accepted.
    pub async fn ping(&self) -> Result<()> {
        self.call("x:Domain/query", serde_json::json!({ "limit": 1 }))
            .await
            .map(|_| ())
    }

    /// A domain's internal id.
    ///
    /// 🔴 Required: `domainId` is an object reference, not the domain's name. A domain
    /// missing from Stalwart cannot host an account, and it is better said here than
    /// left to fail obscurely at creation time.
    pub async fn domain_id(&self, domain: &str) -> Result<String> {
        // A single property: the flat shape is fine here, unlike the account lookup
        // which crosses two.
        let args = self
            .call(
                "x:Domain/query",
                serde_json::json!({ "filter": { "name": domain } }),
            )
            .await?;

        ids(&args)
            .into_iter()
            .next()
            .ok_or_else(|| Error::UnknownDomain(domain.to_string()))
    }

    /// The domain's id, creating the domain when Stalwart does not have it.
    ///
    /// A fresh Stalwart hosts no domain, and every account creation then fails on
    /// "domain does not exist": the first mailbox of an installation needs this.
    pub async fn ensure_domain(&self, domain: &str) -> Result<String> {
        match self.domain_id(domain).await {
            Ok(id) => return Ok(id),
            Err(Error::UnknownDomain(_)) => {}
            Err(e) => return Err(e),
        }
        let args = self
            .call(
                "x:Domain/set",
                serde_json::json!({ "create": { CREATION_ID: { "name": domain } } }),
            )
            .await?;
        if let Some(err) = args.get("notCreated").and_then(|v| v.get(CREATION_ID)) {
            return Err(Error::NotCreated {
                object: format!("the domain \"{domain}\""),
                reason: describe_set_error(err),
            });
        }
        let id = args
            .get("created")
            .and_then(|v| v.get(CREATION_ID))
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Unexpected(format!("domain creation returned no id: {args}")))?
            .to_string();
        tracing::info!(domain, id = %id, "mail domain created");
        Ok(id)
    }

    /// Looks up an account by its local part, within a given domain.
    ///
    /// 🔴 Both criteria are required **and** must be separate conditions (see the
    /// module header). On `name` alone, two domains each hosting a `contact@` would be
    /// confused for one another.
    pub async fn find_account(&self, local: &str, domain_id: &str) -> Result<Option<String>> {
        let args = self
            .call(
                "x:Account/query",
                serde_json::json!({ "filter": and(&[
                    serde_json::json!({ "name": local }),
                    serde_json::json!({ "domainId": domain_id }),
                ])}),
            )
            .await?;
        Ok(ids(&args).into_iter().next())
    }

    /// Creates a user account.
    ///
    /// The body follows the upstream schema: `@type` discriminator, local part in
    /// `name`, and the password in a `credentials` entry.
    pub async fn create_account(
        &self,
        local: &str,
        domain_id: &str,
        password: &str,
        aliases: &[String],
    ) -> Result<String> {
        let args = self
            .call(
                "x:Account/set",
                serde_json::json!({
                    "create": { CREATION_ID: account_body(local, domain_id, password, aliases) }
                }),
            )
            .await?;

        // 🔴 The central trap: HTTP 200 does NOT mean created.
        if let Some(err) = args.get("notCreated").and_then(|v| v.get(CREATION_ID)) {
            return Err(Error::NotCreated {
                object: format!("the account \"{local}\""),
                reason: describe_set_error(err),
            });
        }

        let id = args
            .get("created")
            .and_then(|v| v.get(CREATION_ID))
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Unexpected(format!("creation returned no id: {args}")))?
            .to_string();

        tracing::info!(account = local, id = %id, "mail account created");
        Ok(id)
    }

    /// Uploads content and returns its `blobId`.
    ///
    /// 🔴 A Sieve script's content does NOT travel in the JMAP call: `SieveScript`
    /// carries only a `blobId`. So upload first, reference second. Sending the script
    /// straight into `SieveScript/set` would fail on an unknown property - and JMAP
    /// silently ignores what it does not know, so the script would be "created" and
    /// empty.
    pub async fn upload_blob(&self, account_id: &str, content: &str) -> Result<String> {
        let url = format!("{}/jmap/upload/{account_id}/", self.base_url);
        let req = self
            .http
            .post(&url)
            .header("Content-Type", "application/sieve")
            .body(content.to_string());

        let req = match &self.auth {
            Auth::Basic { user, password } => req.basic_auth(user, Some(password)),
            Auth::Bearer(t) => req.bearer_auth(t),
        };

        let resp = req.send().await.map_err(|source| Error::Http {
            source,
            context: "script upload".into(),
        })?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let detail =
                String::from_utf8_lossy(&bounded(resp, MAX_ERROR).await.unwrap_or_default())
                    .into_owned();
            return Err(Error::Api { status, detail });
        }

        let v = bounded(resp, MAX_BODY)
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable upload response: {e}")))?;
        let v: serde_json::Value = serde_json::from_slice(&v)
            .map_err(|e| Error::Unexpected(format!("unreadable upload response: {e}")))?;

        v.get("blobId")
            .and_then(|b| b.as_str())
            .map(str::to_string)
            .ok_or_else(|| Error::Unexpected(format!("no blobId in the response: {v}")))
    }

    /// Fetches a blob's content.
    pub async fn download_blob(&self, account_id: &str, blob_id: &str) -> Result<String> {
        let url = format!(
            "{}/jmap/download/{account_id}/{blob_id}/script?accept=application/sieve",
            self.base_url
        );
        let req = self.http.get(&url);
        let req = match &self.auth {
            Auth::Basic { user, password } => req.basic_auth(user, Some(password)),
            Auth::Bearer(t) => req.bearer_auth(t),
        };

        let resp = req.send().await.map_err(|source| Error::Http {
            source,
            context: "script download".into(),
        })?;

        // 🔴 Never "" for a script that exists: the merge would build on nothing and
        // the upload replace the person's hand-written rules with Homelabus's block.
        // An account with no script is `active_sieve_script`'s `None`, never asked here.
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let detail =
                String::from_utf8_lossy(&bounded(resp, MAX_ERROR).await.unwrap_or_default())
                    .into_owned();
            return Err(Error::Api { status, detail });
        }
        let script = bounded(resp, MAX_BODY)
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable script: {e}")))?;
        String::from_utf8(script).map_err(|e| Error::Unexpected(format!("unreadable script: {e}")))
    }

    /// An account's active Sieve script: `(id, blobId)`.
    pub async fn active_sieve_script(&self, account_id: &str) -> Result<Option<(String, String)>> {
        Ok(self
            .sieve_script(account_id)
            .await?
            .map(|(id, blob, _)| (id, blob)))
    }

    /// The script Homelabus extends: `(id, blobId, isActive)` — the active one, failing
    /// that the first.
    async fn sieve_script(&self, account_id: &str) -> Result<Option<(String, String, bool)>> {
        let args = self
            .call(
                "SieveScript/get",
                serde_json::json!({
                    "accountId": account_id,
                    "properties": ["id", "name", "blobId", "isActive"]
                }),
            )
            .await?;

        Ok(args
            .get("list")
            .and_then(|l| l.as_array())
            .and_then(|l| {
                l.iter()
                    .find(|s| s.get("isActive").and_then(|a| a.as_bool()) == Some(true))
                    // Failing an active one, the first: better to extend an inactive
                    // script than to create a second that would duplicate it.
                    .or_else(|| l.first())
            })
            .and_then(|s| {
                Some((
                    s.get("id")?.as_str()?.to_string(),
                    s.get("blobId")?.as_str()?.to_string(),
                    s.get("isActive").and_then(|a| a.as_bool()) == Some(true),
                ))
            }))
    }

    /// Installs the sorting script, preserving what the user wrote.
    ///
    /// 🔴 Read-modify-write, as for aliases. Only the delimited block is replaced:
    /// hand-written rules live outside the markers and are copied across untouched.
    /// Without that, a simple alias creation would erase hours of tuning.
    ///
    /// Returns the final script so the caller can show it.
    pub async fn apply_sieve(
        &self,
        address: &str,
        render_block: &dyn Fn(&str) -> String,
    ) -> Result<String> {
        let (local, domain) = address
            .split_once('@')
            .ok_or_else(|| Error::Unexpected(format!("address with no domain: {address}")))?;
        let domain_id = self.domain_id(domain).await?;
        let account_id = self
            .find_account(local, &domain_id)
            .await?
            .ok_or_else(|| Error::Unexpected(format!("account \"{address}\" not found")))?;

        let existing = match self.sieve_script(&account_id).await? {
            Some((_, blob, _)) => self.download_blob(&account_id, &blob).await?,
            None => String::new(),
        };

        let final_ = render_block(&existing);
        let blob = self.upload_blob(&account_id, &final_).await?;

        let previous = self.sieve_script(&account_id).await?;
        let args = match &previous {
            // Updating the existing script keeps its id, and therefore its active
            // state. Creating a second one would leave the old one active, and the new
            // one would never apply.
            Some((id, _, active)) => {
                let mut set = serde_json::json!({
                    "accountId": account_id,
                    "update": { id: { "blobId": blob } }
                });
                // An inactive script — made by hand, or turned off — sorted nothing
                // before and would sort nothing after: Homelabus's rules are in it.
                if !active {
                    set["onSuccessActivateScript"] = serde_json::json!(id);
                }
                self.call("SieveScript/set", set).await?
            }
            None => {
                self.call(
                    "SieveScript/set",
                    serde_json::json!({
                        "accountId": account_id,
                        "create": { "hlb": { "name": "homelabus", "blobId": blob } },
                        // 🔴 Without activation the script exists and sorts NOTHING.
                        // The failure is completely silent: the rules are there,
                        // visible in Roundcube, and have no effect.
                        "onSuccessActivateScript": "#hlb"
                    }),
                )
                .await?
            }
        };

        // 🔴 HTTP 200 does not mean installed. The failure lives in notCreated/notUpdated.
        for key in ["notCreated", "notUpdated"] {
            if let Some(obj) = args.get(key).and_then(|v| v.as_object()) {
                if let Some((_, err)) = obj.iter().next() {
                    return Err(Error::NotCreated {
                        object: format!("the Sieve script of \"{address}\""),
                        reason: describe_set_error(err),
                    });
                }
            }
        }

        tracing::info!(account = %address, bytes = final_.len(), "Sieve script installed");
        Ok(final_)
    }

    /// The aliases currently set on an account.
    ///
    /// ⚠️ Required before any modification: JMAP `update` **replaces** the whole
    /// property. Writing a single alias would erase all the others - and the user
    /// would lose in one go every address they had handed to third parties, without a
    /// single error being raised.
    pub async fn aliases_of(&self, account_id: &str) -> Result<Vec<String>> {
        Ok(self
            .aliases_raw(account_id)
            .await?
            .iter()
            .filter_map(|x| x.get("name").and_then(|n| n.as_str()).map(str::to_string))
            .collect())
    }

    /// The account's aliases as Stalwart holds them, every field kept.
    ///
    /// 🔴 Stalwart answers a MAP keyed by index (`{"0": {…}}`), not an array. Read as an
    /// array until 2026-10-14, the list was always empty — and the next write would
    /// have replaced every alias the person had handed out with the one being added.
    async fn aliases_raw(&self, account_id: &str) -> Result<Vec<serde_json::Value>> {
        let args = self
            .call(
                "x:Account/get",
                serde_json::json!({
                    "ids": [account_id],
                    "properties": ["aliases"]
                }),
            )
            .await?;
        let aliases = args
            .get("list")
            .and_then(|l| l.as_array())
            .and_then(|l| l.first())
            .and_then(|c| c.get("aliases"));
        Ok(match aliases {
            Some(serde_json::Value::Object(m)) => {
                let mut entries: Vec<(&String, &serde_json::Value)> = m.iter().collect();
                // Keys are indices: keep their order when writing back.
                entries.sort_by_key(|(k, _)| k.parse::<u64>().unwrap_or(u64::MAX));
                entries.into_iter().map(|(_, v)| v.clone()).collect()
            }
            Some(serde_json::Value::Array(a)) => a.clone(),
            _ => Vec::new(),
        })
    }

    /// Replaces an account's alias list.
    ///
    /// 🔴 **Read-modify-write.** JMAP has no "add an alias" operation: `update`
    /// overwrites the property. So we read the existing list, modify it and write it
    /// back - and two simultaneous modifications would lose the first. On a homelab
    /// driven by one command at a time that is acceptable; noting it avoids
    /// rediscovering it the day the controller does this in parallel.
    async fn set_aliases(&self, account_id: &str, aliases: Vec<serde_json::Value>) -> Result<()> {
        let args = self
            .call(
                "x:Account/set",
                serde_json::json!({
                    "update": { account_id: { "aliases": index_map(aliases) } }
                }),
            )
            .await?;

        // 🔴 As with creation: HTTP 200 does not mean modified. The failure lives in
        // `notUpdated`, and missing it would make the alias look installed while no
        // mail would ever arrive.
        if let Some(err) = args.get("notUpdated").and_then(|v| v.get(account_id)) {
            return Err(Error::NotCreated {
                object: format!("the aliases of account \"{account_id}\""),
                reason: describe_set_error(err),
            });
        }
        Ok(())
    }

    /// Adds an alias to an existing account without touching the others.
    ///
    /// Returns `false` when the alias was already there - the operation is idempotent,
    /// which allows an interrupted run to be restarted.
    pub async fn add_alias(&self, address: &str, alias_local: &str) -> Result<bool> {
        let (local, domain) = address
            .split_once('@')
            .ok_or_else(|| Error::Unexpected(format!("address with no domain: {address}")))?;
        let domain_id = self.domain_id(domain).await?;
        let account_id = self
            .find_account(local, &domain_id)
            .await?
            .ok_or_else(|| Error::Unexpected(format!("account \"{address}\" not found")))?;

        let mut current = self.aliases_raw(&account_id).await?;
        if current
            .iter()
            .any(|a| a.get("name").and_then(|n| n.as_str()) == Some(alias_local))
        {
            return Ok(false);
        }
        current.push(alias_entry(alias_local, &domain_id));
        self.set_aliases(&account_id, current).await?;

        tracing::info!(account = %address, alias = alias_local, "alias installed");
        Ok(true)
    }

    /// Removes an alias from an account without touching the others.
    ///
    /// Returns `false` when it was not there. 🔴 This is what makes expiry REAL:
    /// without this call a "temporary" alias stays alive forever, Stalwart having no
    /// notion of a date.
    pub async fn remove_alias(&self, address: &str, alias_local: &str) -> Result<bool> {
        let (local, domain) = address
            .split_once('@')
            .ok_or_else(|| Error::Unexpected(format!("address with no domain: {address}")))?;
        let domain_id = self.domain_id(domain).await?;
        let account_id = self
            .find_account(local, &domain_id)
            .await?
            .ok_or_else(|| Error::Unexpected(format!("account \"{address}\" not found")))?;

        let current = self.aliases_raw(&account_id).await?;
        let named =
            |a: &serde_json::Value| a.get("name").and_then(|n| n.as_str()) == Some(alias_local);
        if !current.iter().any(named) {
            return Ok(false);
        }
        let remaining: Vec<serde_json::Value> = current.into_iter().filter(|a| !named(a)).collect();
        self.set_aliases(&account_id, remaining).await?;

        tracing::info!(account = %address, alias = alias_local, "alias removed");
        Ok(true)
    }

    /// The shared mailbox RFC 2142 asks every mail domain to have — `postmaster@`,
    /// which other servers write to about delivery, and its aliases (`abuse@`) — made
    /// when missing, its aliases completed. Its id.
    ///
    /// A Stalwart `Group` is a mailbox of its own that each member opens beside theirs
    /// (a second JMAP account, an IMAP shared folder): mail to it and to its aliases is
    /// delivered there once, never copied to each member (0.16.26).
    ///
    /// 🔴 A personal account already holding the name is refused, never turned into
    /// the group: whoever owns it would lose their mailbox.
    pub async fn ensure_shared_mailbox(
        &self,
        local: &str,
        domain: &str,
        aliases: &[&str],
    ) -> Result<String> {
        let domain_id = self.ensure_domain(domain).await?;
        let Some(id) = self.find_account(local, &domain_id).await? else {
            let body = serde_json::json!({
                "@type": "Group",
                "name": local,
                "domainId": domain_id,
                "aliases": index_map(aliases.iter().map(|a| alias_entry(a, &domain_id)).collect()),
            });
            let id = self
                .create(
                    "x:Account/set",
                    body,
                    &format!("the mailbox {local}@{domain}"),
                )
                .await?;
            tracing::info!(address = %format!("{local}@{domain}"), "shared mailbox created");
            return Ok(id);
        };
        let kind = self.account_kind(&id).await?;
        if kind != "Group" {
            return Err(Error::Unexpected(format!(
                "{local}@{domain} is a personal account ({kind}), not a shared mailbox: \
                 rename it in Stalwart so the address can be shared"
            )));
        }
        let mut current = self.aliases_raw(&id).await?;
        let mut missing = false;
        for a in aliases {
            if !current
                .iter()
                .any(|x| x.get("name").and_then(|n| n.as_str()) == Some(a))
            {
                current.push(alias_entry(a, &domain_id));
                missing = true;
            }
        }
        if missing {
            self.set_aliases(&id, current).await?;
        }
        Ok(id)
    }

    /// The shared mailbox's id, without creating it — what a preview reads.
    pub async fn shared_mailbox(&self, local: &str, domain: &str) -> Result<Option<String>> {
        let domain_id = match self.domain_id(domain).await {
            Ok(id) => id,
            Err(Error::UnknownDomain(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        match self.find_account(local, &domain_id).await? {
            Some(id) if self.account_kind(&id).await? == "Group" => Ok(Some(id)),
            _ => Ok(None),
        }
    }

    /// `User` or `Group`.
    async fn account_kind(&self, id: &str) -> Result<String> {
        let args = self
            .call(
                "x:Account/get",
                serde_json::json!({ "ids": [id], "properties": ["@type"] }),
            )
            .await?;
        args.get("list")
            .and_then(|l| l.as_array())
            .and_then(|l| l.first())
            .and_then(|a| a.get("@type"))
            .and_then(|t| t.as_str())
            .map(str::to_string)
            .ok_or_else(|| Error::Unexpected(format!("account {id} has no type: {args}")))
    }

    /// The accounts that open a shared mailbox, by id.
    pub async fn members_of(&self, group_id: &str) -> Result<Vec<String>> {
        let args = self
            .call(
                "x:Account/query",
                serde_json::json!({ "filter": { "memberGroupIds": group_id } }),
            )
            .await?;
        Ok(ids(&args))
    }

    /// The account of an address, if Stalwart has it.
    pub async fn account_of(&self, address: &str) -> Result<Option<String>> {
        let (local, domain) = address
            .split_once('@')
            .ok_or_else(|| Error::Unexpected(format!("address with no domain: {address}")))?;
        match self.domain_id(domain).await {
            Ok(d) => self.find_account(local, &d).await,
            Err(Error::UnknownDomain(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Lets an account open a shared mailbox, or stops it.
    ///
    /// One key of `memberGroupIds` is patched, never the whole map: the account may
    /// belong to groups Homelabus did not make, which a rewrite would drop.
    pub async fn set_member(&self, account_id: &str, group_id: &str, member: bool) -> Result<()> {
        let key = format!("memberGroupIds/{group_id}");
        let value = if member {
            serde_json::Value::Bool(true)
        } else {
            serde_json::Value::Null
        };
        let args = self
            .call(
                "x:Account/set",
                serde_json::json!({ "update": { account_id: { key: value } } }),
            )
            .await?;
        if let Some(err) = args.get("notUpdated").and_then(|v| v.get(account_id)) {
            return Err(Error::NotCreated {
                object: format!("the membership of account \"{account_id}\""),
                reason: describe_set_error(err),
            });
        }
        Ok(())
    }

    /// Never bans an address of `cidr` for failed sign-ins, and lifts a ban already
    /// on one. `true` when the exemption was added.
    ///
    /// 🔴 Stalwart bans an address after 100 failed sign-ins a day, FOR EVER by default
    /// (0.16.26: `authBanRate`, `authBanPeriod: null`), the right password refused
    /// after. A webmail signs in for everyone from its container's one address: a
    /// hundred wrong guesses through Roundcube shut every person out of it, and an app
    /// left with a rotated password was cut off for good. An exemption takes effect at
    /// `ReloadSettings`; a ban in place, at `ReloadBlockedIps`.
    pub async fn trust_network(&self, cidr: &str, reason: &str) -> Result<bool> {
        let known = self.trusts(cidr).await?;
        if !known {
            self.create(
                "x:AllowedIp/set",
                serde_json::json!({ "address": cidr, "reason": reason }),
                &format!("the exemption of {cidr}"),
            )
            .await?;
        }
        let blocked = self.call("x:BlockedIp/get", serde_json::json!({})).await?;
        let lifted: Vec<String> = listed(&blocked)
            .iter()
            .filter(|b| {
                b.get("address")
                    .and_then(|v| v.as_str())
                    .is_some_and(|a| in_subnet(a, cidr))
            })
            .filter_map(|b| b.get("id").and_then(|v| v.as_str()).map(str::to_string))
            .collect();
        if !lifted.is_empty() {
            let args = self
                .call("x:BlockedIp/set", serde_json::json!({ "destroy": lifted }))
                .await?;
            destroyed(&args, "a ban on the platform network")?;
            tracing::warn!(
                cidr,
                bans = lifted.len(),
                "bans on the platform network lifted"
            );
        }
        for action in ["ReloadSettings", "ReloadBlockedIps"] {
            self.create(
                "x:Action/set",
                serde_json::json!({ "@type": action }),
                &format!("the action {action}"),
            )
            .await?;
        }
        Ok(!known)
    }

    /// Is `cidr` exempted from bans already? Read only.
    pub async fn trusts(&self, cidr: &str) -> Result<bool> {
        let allowed = self.call("x:AllowedIp/get", serde_json::json!({})).await?;
        Ok(listed(&allowed)
            .iter()
            .any(|a| a.get("address").and_then(|v| v.as_str()) == Some(cidr)))
    }

    /// How long a ban for failed sign-ins lasts, in milliseconds; `None` is for ever.
    pub async fn auth_ban_period(&self) -> Result<Option<u64>> {
        let args = self
            .call(
                "x:Security/get",
                serde_json::json!({ "ids": ["singleton"], "properties": ["authBanPeriod"] }),
            )
            .await?;
        Ok(listed(&args)
            .first()
            .and_then(|s| s.get("authBanPeriod"))
            .and_then(serde_json::Value::as_u64))
    }

    pub async fn set_auth_ban_period(&self, ms: u64) -> Result<()> {
        let args = self
            .call(
                "x:Security/set",
                serde_json::json!({ "update": { "singleton": { "authBanPeriod": ms } } }),
            )
            .await?;
        if let Some(err) = args.get("notUpdated").and_then(|v| v.get("singleton")) {
            return Err(Error::NotCreated {
                object: "the ban period".into(),
                reason: describe_set_error(err),
            });
        }
        Ok(())
    }

    /// Does Stalwart write its traces to its standard output, where `docker service
    /// logs` reads them? Read only.
    pub async fn traces_to_stdout(&self) -> Result<bool> {
        let args = self
            .call("x:Tracer/get", serde_json::json!({ "ids": null }))
            .await?;
        Ok(listed(&args).iter().any(|t| {
            t.get("@type").and_then(|v| v.as_str()) == Some("Stdout")
                && t.get("enable").and_then(serde_json::Value::as_bool) != Some(false)
        }))
    }

    /// Adds a tracer writing to standard output, at `info`.
    ///
    /// 🔴 0.16.26's only tracer is a `Log` writing to `/var/log/stalwart`, which the
    /// image does not have: its writer is never built, and every event — a delivery
    /// refused, an ACME order failed — is dropped. Effective at `ReloadSettings`, no
    /// restart.
    pub async fn trace_to_stdout(&self) -> Result<()> {
        self.create(
            "x:Tracer/set",
            serde_json::json!({ "@type": "Stdout", "level": "info", "enable": true }),
            "the tracer to standard output",
        )
        .await?;
        self.create(
            "x:Action/set",
            serde_json::json!({ "@type": "ReloadSettings" }),
            "the reload of the settings",
        )
        .await
        .map(|_| ())
    }

    /// The servers Stalwart resolves through, as `protocol address:port` — empty when
    /// it asks the system's resolver, or a public one by name. Read only.
    pub async fn resolver_servers(&self) -> Result<Vec<String>> {
        let args = self
            .call(
                "x:DnsResolver/get",
                serde_json::json!({ "ids": ["singleton"] }),
            )
            .await?;
        let resolver = listed(&args).into_iter().next().unwrap_or_default();
        if resolver.get("@type").and_then(|v| v.as_str()) != Some("Custom") {
            return Ok(Vec::new());
        }
        let mut out: Vec<String> = resolver
            .get("servers")
            .and_then(serde_json::Value::as_object)
            .map(|m| {
                m.values()
                    .filter_map(|s| {
                        Some(format!(
                            "{} {}:{}",
                            s.get("protocol")?.as_str()?,
                            s.get("address")?.as_str()?,
                            s.get("port")?.as_u64()?
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.sort();
        Ok(out)
    }

    /// Has Stalwart resolve through `address` alone, port 53, UDP and TCP — a long
    /// answer is truncated over UDP and asked again over TCP.
    ///
    /// Effective at `ReloadSettings`, no restart (0.16.26, measured). ⚠️ What its
    /// resolver cached stays until its TTL: a blocklist refusal read before, an hour.
    pub async fn resolve_through(&self, address: &str) -> Result<()> {
        let args = self
            .call(
                "x:DnsResolver/set",
                serde_json::json!({ "update": { "singleton": {
                    "@type": "Custom",
                    // A map keyed by index, as every registry list.
                    "servers": {
                        "0": { "protocol": "udp", "address": address, "port": 53 },
                        "1": { "protocol": "tcp", "address": address, "port": 53 },
                    },
                } } }),
            )
            .await?;
        if let Some(err) = args.get("notUpdated").and_then(|v| v.get("singleton")) {
            return Err(Error::NotCreated {
                object: "the DNS resolver".into(),
                reason: describe_set_error(err),
            });
        }
        self.create(
            "x:Action/set",
            serde_json::json!({ "@type": "ReloadSettings" }),
            "the reload of the settings",
        )
        .await
        .map(|_| ())
    }

    /// The spam filter's blocklists that refuse the resolver Stalwart asks through, by
    /// the tag each answers with — empty when every one answered. Read only: a message
    /// is classified, not received.
    ///
    /// 🔴 Spamhaus, URIBL, SURBL and DNSWL answer a public resolver (1.1.1.1, 8.8.8.8,
    /// 9.9.9.9) — or one sending them too much — with a refusal code, not a listing, so
    /// behind one they check nothing and every message passes them (0.16.26, measured
    /// on the lab and through 1.1.1.1; through a router forwarding to its ISP, Spamhaus
    /// answered and URIBL refused). Stalwart's resolver is the system's: the node's.
    /// The probe comes from a documentation address and links a domain nobody owns, so
    /// the address lists and the domain lists are both asked — each a new one every
    /// time: a refusal stays an hour in Stalwart's cache, and a probe asking again what
    /// it asked before the resolver changed would read the old refusal.
    pub async fn refused_blocklists(&self) -> Result<Vec<String>> {
        let (address, domain) = probe_names(fresh());
        let (sender, recipients) = self.generation().await?.envelope();
        let message = format!(
            "From: probe@example.net\r\nTo: postmaster@example.org\r\n\
             Subject: blocklist probe\r\nMessage-ID: <probe@example.net>\r\n\
             Date: Tue, 20 Oct 2026 10:00:00 +0000\r\n\r\nhttp://{domain}/\r\n"
        );
        let args = self
            .call(
                "x:Action/set",
                serde_json::json!({ "create": { CREATION_ID: {
                    "@type": "ClassifySpam",
                    "message": message,
                    "remoteIp": address,
                    "ehloDomain": "example.net",
                    "isTls": true,
                    sender: "probe@example.net",
                    // A set: keyed by the address, `{"0": …}` is refused.
                    recipients: { "postmaster@example.org": true },
                } } }),
            )
            .await?;
        if let Some(err) = args.get("notCreated").and_then(|v| v.get(CREATION_ID)) {
            return Err(Error::NotCreated {
                object: "the blocklist probe".into(),
                reason: describe_set_error(err),
            });
        }
        let tags = args
            .get("created")
            .and_then(|v| v.get(CREATION_ID))
            .and_then(|v| v.get("tags"))
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| Error::Unexpected(format!("the probe returned no tags: {args}")))?;
        Ok(refusals(tags.keys().map(String::as_str)))
    }

    /// Every domain Stalwart hosts, and the zone it computed for it — every record the
    /// domain needs, its DKIM keys and its name included.
    pub async fn zones(&self) -> Result<Vec<(String, String)>> {
        let args = self
            .call(
                "x:Domain/get",
                serde_json::json!({ "ids": null, "properties": ["name", "dnsZoneFile"] }),
            )
            .await?;
        Ok(listed(&args)
            .iter()
            .filter_map(|d| {
                Some((
                    d.get("name")?.as_str()?.to_string(),
                    d.get("dnsZoneFile")?.as_str()?.to_string(),
                ))
            })
            .collect())
    }

    /// Every object of a registry list (`x:MtaRoute`, `x:MtaTlsStrategy`…) as Stalwart
    /// returns it, secrets masked.
    async fn all(&self, object: &str) -> Result<Vec<serde_json::Value>> {
        let args = self
            .call(
                &format!("x:{object}/get"),
                serde_json::json!({ "ids": null }),
            )
            .await?;
        Ok(listed(&args))
    }

    /// Writes the object of `object` named `name`: created, or updated in place — its
    /// kind kept, since `@type` is not an update.
    pub async fn put_named(
        &self,
        object: &str,
        name: &str,
        mut body: serde_json::Value,
    ) -> Result<String> {
        let existing = self
            .all(object)
            .await?
            .into_iter()
            .find(|o| o.get("name").and_then(|v| v.as_str()) == Some(name))
            .and_then(|o| o.get("id").and_then(|v| v.as_str()).map(str::to_string));
        body["name"] = name.into();
        let Some(id) = existing else {
            return self
                .create(
                    &format!("x:{object}/set"),
                    body,
                    &format!("{object} {name}"),
                )
                .await;
        };
        if let Some(o) = body.as_object_mut() {
            o.remove("@type");
        }
        let args = self
            .call(
                &format!("x:{object}/set"),
                serde_json::json!({ "update": { &id: body } }),
            )
            .await?;
        if let Some(err) = args.get("notUpdated").and_then(|v| v.get(&id)) {
            return Err(Error::NotCreated {
                object: format!("{object} {name}"),
                reason: describe_set_error(err),
            });
        }
        Ok(id)
    }

    /// The object of `object` named `name`, as Stalwart returns it.
    pub async fn named(&self, object: &str, name: &str) -> Result<Option<serde_json::Value>> {
        Ok(self
            .all(object)
            .await?
            .into_iter()
            .find(|o| o.get("name").and_then(|v| v.as_str()) == Some(name)))
    }

    /// Removes the object of `object` named `name`; `false` when there was none.
    pub async fn destroy_named(&self, object: &str, name: &str) -> Result<bool> {
        let Some(id) = self
            .named(object, name)
            .await?
            .and_then(|o| o.get("id").and_then(|v| v.as_str()).map(str::to_string))
        else {
            return Ok(false);
        };
        let args = self
            .call(
                &format!("x:{object}/set"),
                serde_json::json!({ "destroy": [&id] }),
            )
            .await?;
        if let Some(err) = args.get("notDestroyed").and_then(|v| v.get(&id)) {
            return Err(Error::NotCreated {
                object: format!("the removal of {object} {name}"),
                reason: describe_set_error(err),
            });
        }
        Ok(true)
    }

    /// Which route and which TLS strategy outgoing mail takes: the expressions of
    /// `x:MtaOutboundStrategy`, `(route, tls)`.
    pub async fn outbound_strategy(&self) -> Result<(serde_json::Value, serde_json::Value)> {
        let args = self
            .call(
                "x:MtaOutboundStrategy/get",
                serde_json::json!({ "ids": ["singleton"], "properties": ["route", "tls"] }),
            )
            .await?;
        let s = listed(&args).first().cloned().unwrap_or_default();
        Ok((
            s.get("route").cloned().unwrap_or_default(),
            s.get("tls").cloned().unwrap_or_default(),
        ))
    }

    /// Sets which route and TLS strategy outgoing mail takes.
    ///
    /// 🔴 Stored at once and FOLLOWED at `ReloadSettings` only (0.16.26): written
    /// alone, a message sent the next second still left by the previous route.
    pub async fn set_outbound_strategy(
        &self,
        route: serde_json::Value,
        tls: serde_json::Value,
    ) -> Result<()> {
        let args = self
            .call(
                "x:MtaOutboundStrategy/set",
                serde_json::json!({ "update": { "singleton": { "route": route, "tls": tls } } }),
            )
            .await?;
        if let Some(err) = args.get("notUpdated").and_then(|v| v.get("singleton")) {
            return Err(Error::NotCreated {
                object: "the outbound strategy".into(),
                reason: describe_set_error(err),
            });
        }
        self.reload_settings().await
    }

    pub async fn reload_settings(&self) -> Result<()> {
        self.create(
            "x:Action/set",
            serde_json::json!({ "@type": "ReloadSettings" }),
            "the action ReloadSettings",
        )
        .await
        .map(|_| ())
    }

    /// A domain's DKIM keys: their selector, their stage, when they next move.
    pub async fn dkim_keys(&self, domain_id: &str) -> Result<Vec<DkimKey>> {
        let args = self
            .call(
                "x:DkimSignature/get",
                serde_json::json!({
                    "ids": null,
                    "properties": ["domainId", "selector", "stage", "nextTransitionAt"],
                }),
            )
            .await?;
        Ok(listed(&args)
            .iter()
            .filter(|k| k.get("domainId").and_then(|v| v.as_str()) == Some(domain_id))
            .filter_map(|k| {
                Some(DkimKey {
                    selector: k.get("selector")?.as_str()?.to_string(),
                    stage: k.get("stage")?.as_str()?.to_string(),
                    next_transition: k
                        .get("nextTransitionAt")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                })
            })
            .collect())
    }

    /// The DNS servers Stalwart publishes records through. Their secrets read back as
    /// `****`: what was written is known only by what the writer recorded.
    pub async fn dns_servers(&self) -> Result<Vec<DnsServer>> {
        let args = self
            .call(
                "x:DnsServer/get",
                serde_json::json!({ "ids": null, "properties": ["@type", "description"] }),
            )
            .await?;
        Ok(listed(&args)
            .iter()
            .filter_map(|d| {
                Some(DnsServer {
                    id: d.get("id")?.as_str()?.to_string(),
                    kind: d.get("@type")?.as_str()?.to_string(),
                    description: d
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                })
            })
            .collect())
    }

    /// Adds a DNS server. Accepted offline: no credential is tried until a record is
    /// published through it (0.16.26).
    pub async fn create_dns_server(&self, body: serde_json::Value) -> Result<String> {
        self.create("x:DnsServer/set", body, "the DNS server").await
    }

    /// Replaces a DNS server's settings, its kind kept.
    pub async fn update_dns_server(&self, id: &str, mut body: serde_json::Value) -> Result<()> {
        if let Some(o) = body.as_object_mut() {
            o.remove("@type");
        }
        let args = self
            .call(
                "x:DnsServer/set",
                serde_json::json!({ "update": { id: body } }),
            )
            .await?;
        if let Some(err) = args.get("notUpdated").and_then(|v| v.get(id)) {
            return Err(Error::NotCreated {
                object: format!("the DNS server {id}"),
                reason: describe_set_error(err),
            });
        }
        Ok(())
    }

    pub async fn destroy_dns_server(&self, id: &str) -> Result<()> {
        let args = self
            .call("x:DnsServer/set", serde_json::json!({ "destroy": [id] }))
            .await?;
        if let Some(err) = args.get("notDestroyed").and_then(|v| v.get(id)) {
            return Err(Error::NotCreated {
                object: format!("the removal of the DNS server {id}"),
                reason: describe_set_error(err),
            });
        }
        Ok(())
    }

    /// How each domain's records are published: by hand, or through which server.
    pub async fn domains_dns(&self) -> Result<Vec<DomainDns>> {
        let args = self
            .call(
                "x:Domain/get",
                serde_json::json!({ "ids": null, "properties": ["name", "dnsManagement"] }),
            )
            .await?;
        Ok(listed(&args)
            .iter()
            .filter_map(|d| {
                let m = d.get("dnsManagement");
                let automatic =
                    m.and_then(|m| m.get("@type")).and_then(|t| t.as_str()) == Some("Automatic");
                Some(DomainDns {
                    id: d.get("id")?.as_str()?.to_string(),
                    name: d.get("name")?.as_str()?.to_string(),
                    published_by: automatic
                        .then(|| {
                            let m = m?;
                            let server = m.get("dnsServerId")?.as_str()?.to_string();
                            // A set: `{"dkim": true}`, like every enum map of 0.16.
                            let records = m
                                .get("publishRecords")
                                .and_then(|r| r.as_object())
                                .map(|r| r.keys().cloned().collect())
                                .unwrap_or_default();
                            Some((server, records))
                        })
                        .flatten(),
                })
            })
            .collect())
    }

    /// Has Stalwart publish `records` of a domain through a DNS server — and keep them,
    /// rotating its DKIM keys. Switched on, it publishes the keys already active at once.
    pub async fn publish_through(
        &self,
        domain_id: &str,
        server_id: &str,
        records: &[String],
    ) -> Result<()> {
        let publish: serde_json::Map<String, serde_json::Value> = records
            .iter()
            .map(|r| (r.clone(), serde_json::Value::Bool(true)))
            .collect();
        let args = self
            .call(
                "x:Domain/set",
                serde_json::json!({ "update": { domain_id: { "dnsManagement": {
                    "@type": "Automatic",
                    "dnsServerId": server_id,
                    "publishRecords": publish,
                } } } }),
            )
            .await?;
        if let Some(err) = args.get("notUpdated").and_then(|v| v.get(domain_id)) {
            return Err(Error::NotCreated {
                object: format!("the DNS publishing of domain {domain_id}"),
                reason: describe_set_error(err),
            });
        }
        Ok(())
    }

    /// Records of a domain published, publishing them by hand again.
    pub async fn set_manual_dns(&self, domain_id: &str) -> Result<()> {
        let args = self
            .call(
                "x:Domain/set",
                serde_json::json!({ "update": { domain_id: {
                    "dnsManagement": { "@type": "Manual" }
                } } }),
            )
            .await?;
        if let Some(err) = args.get("notUpdated").and_then(|v| v.get(domain_id)) {
            return Err(Error::NotCreated {
                object: format!("the DNS publishing of domain {domain_id}"),
                reason: describe_set_error(err),
            });
        }
        Ok(())
    }

    /// The publishing tasks of a domain, the latest first.
    ///
    /// 🔴 On 0.16 one that failed is FAILED for good — it retries none: a provider down
    /// the moment a domain is switched leaves its keys unpublished until something
    /// asks again ([`Self::publish_again`]). 1.0 retries a transient failure itself,
    /// for ever (`Retry`, `Stalled` past `x:TaskManager.alertAfter`, 5 by default),
    /// and keeps `Failed` for a permanent one.
    pub async fn dns_tasks(&self, domain_id: &str) -> Result<Vec<DnsTask>> {
        self.tasks(domain_id, "DnsManagement").await
    }

    /// The key tasks of a domain: making its first keys, then each rotation.
    pub async fn dkim_tasks(&self, domain_id: &str) -> Result<Vec<DnsTask>> {
        self.tasks(domain_id, "DkimManagement").await
    }

    /// The certificate requests of a domain, the latest first: one `Pending` until its
    /// next renewal once a certificate is issued, `Retry` with why while it fails.
    pub async fn acme_tasks(&self, domain_id: &str) -> Result<Vec<DnsTask>> {
        self.tasks(domain_id, "AcmeRenewal").await
    }

    async fn tasks(&self, domain_id: &str, kind: &str) -> Result<Vec<DnsTask>> {
        let args = self
            .call(
                "x:Task/get",
                serde_json::json!({ "ids": null, "properties": ["@type", "domainId", "status"] }),
            )
            .await?;
        let mut tasks: Vec<DnsTask> = listed(&args)
            .iter()
            .filter(|t| t.get("@type").and_then(|v| v.as_str()) == Some(kind))
            .filter(|t| t.get("domainId").and_then(|v| v.as_str()) == Some(domain_id))
            .filter_map(|t| {
                let status = t.get("status")?;
                Some(DnsTask {
                    id: t.get("id")?.as_str()?.to_string(),
                    state: status.get("@type")?.as_str()?.to_string(),
                    created_at: status
                        .get("createdAt")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    failure: status
                        .get("failureReason")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                })
            })
            .collect();
        tasks.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(tasks)
    }

    /// Asks for `records` of a domain to be published again, now; the failed tasks
    /// before it are removed, or every night would leave one more.
    pub async fn publish_again(&self, domain_id: &str, records: &[String]) -> Result<()> {
        let failed: Vec<String> = self
            .dns_tasks(domain_id)
            .await?
            .into_iter()
            .filter(|t| t.state == "Failed")
            .map(|t| t.id)
            .collect();
        if !failed.is_empty() {
            let args = self
                .call("x:Task/set", serde_json::json!({ "destroy": failed }))
                .await?;
            destroyed(&args, "a failed publishing task")?;
        }
        let update: serde_json::Map<String, serde_json::Value> = records
            .iter()
            .map(|r| (r.clone(), serde_json::Value::Bool(true)))
            .collect();
        self.create(
            "x:Task/set",
            serde_json::json!({
                "@type": "DnsManagement",
                "domainId": domain_id,
                "updateRecords": update,
            }),
            "the publishing task",
        )
        .await
        .map(|_| ())
    }

    /// The ACME accounts Stalwart requests certificates with.
    pub async fn acme_providers(&self) -> Result<Vec<AcmeProvider>> {
        let args = self
            .call(
                "x:AcmeProvider/get",
                serde_json::json!({
                    "ids": null,
                    "properties": ["challengeType", "directory", "contact", "accountUri"],
                }),
            )
            .await?;
        Ok(list(&args)
            .iter()
            .filter_map(|p| {
                Some(AcmeProvider {
                    id: p.get("id")?.as_str()?.to_string(),
                    challenge: p.get("challengeType")?.as_str()?.to_string(),
                    directory: p.get("directory")?.as_str()?.to_string(),
                    contact: p
                        .get("contact")
                        .and_then(|c| c.as_object())
                        .map(|c| c.keys().cloned().collect())
                        .unwrap_or_default(),
                    account_uri: p
                        .get("accountUri")
                        .and_then(|u| u.as_str())
                        .filter(|u| !u.is_empty())
                        .map(str::to_string),
                })
            })
            .collect())
    }

    /// Opens an ACME account: Stalwart registers it with the directory at once, so a
    /// directory it cannot reach — or whose certificate it does not trust — refuses
    /// the creation, the reason in the error.
    pub async fn create_acme_provider(
        &self,
        challenge: &str,
        directory: &str,
        email: &str,
    ) -> Result<String> {
        let mut body = serde_json::json!({
            "challengeType": challenge,
            "directory": directory,
            // A set, like every map of 0.16: `{"0": …}` is refused, "invalid key".
            "contact": { format!("mailto:{email}"): true },
        });
        match self.generation().await? {
            // Computed by 0.16, which refuses one given: "Cannot modify server set property".
            Generation::V016 => {}
            // 1.0 opens the account with the directory, then refuses to store it unnamed:
            // `validationFailed`, with no description of its own to say why.
            Generation::V1 => body["description"] = "Homelabus".into(),
        }
        self.create("x:AcmeProvider/set", body, "the ACME account")
            .await
    }

    pub async fn destroy_acme_provider(&self, id: &str) -> Result<()> {
        let args = self
            .call("x:AcmeProvider/set", serde_json::json!({ "destroy": [id] }))
            .await?;
        if let Some(err) = args.get("notDestroyed").and_then(|v| v.get(id)) {
            return Err(Error::NotCreated {
                object: format!("the removal of the ACME account {id}"),
                reason: describe_set_error(err),
            });
        }
        Ok(())
    }

    /// How each domain's certificate is obtained.
    pub async fn domains_tls(&self) -> Result<Vec<DomainTls>> {
        let args = self
            .call(
                "x:Domain/get",
                serde_json::json!({ "ids": null, "properties": ["name", "certificateManagement"] }),
            )
            .await?;
        Ok(list(&args)
            .iter()
            .filter_map(|d| {
                let m = d.get("certificateManagement");
                let automatic =
                    m.and_then(|m| m.get("@type")).and_then(|t| t.as_str()) == Some("Automatic");
                Some(DomainTls {
                    id: d.get("id")?.as_str()?.to_string(),
                    name: d.get("name")?.as_str()?.to_string(),
                    requested_by: automatic
                        .then(|| {
                            let m = m?;
                            let provider = m.get("acmeProviderId")?.as_str()?.to_string();
                            let names = m
                                .get("subjectAlternativeNames")
                                .and_then(|r| r.as_object())
                                .map(|r| r.keys().cloned().collect())
                                .unwrap_or_default();
                            Some((provider, names))
                        })
                        .flatten(),
                })
            })
            .collect())
    }

    /// Has Stalwart request, and renew, a certificate for exactly `names` through
    /// `provider_id`. Switched from manual, a request is scheduled at once.
    ///
    /// 🔴 The names are given: left empty over HTTP-01, 0.16.26 asks for the domain's
    /// `autoconfig.`, `mta-sts.`… too — names the house does not route, and the whole
    /// order fails on them. Over DNS-01 it asks for the wildcard and the apex.
    pub async fn certify_through(
        &self,
        domain_id: &str,
        provider_id: &str,
        names: &[String],
    ) -> Result<()> {
        let names: serde_json::Map<String, serde_json::Value> = names
            .iter()
            .map(|n| (n.clone(), serde_json::Value::Bool(true)))
            .collect();
        self.update_domain(
            domain_id,
            serde_json::json!({ "certificateManagement": {
                "@type": "Automatic",
                "acmeProviderId": provider_id,
                "subjectAlternativeNames": names,
            } }),
        )
        .await
    }

    /// No more requests for the domain: the certificates it holds are kept.
    pub async fn set_manual_certificates(&self, domain_id: &str) -> Result<()> {
        self.update_domain(
            domain_id,
            serde_json::json!({ "certificateManagement": { "@type": "Manual" } }),
        )
        .await
    }

    async fn update_domain(&self, domain_id: &str, patch: serde_json::Value) -> Result<()> {
        let args = self
            .call(
                "x:Domain/set",
                serde_json::json!({ "update": { domain_id: patch } }),
            )
            .await?;
        if let Some(err) = args.get("notUpdated").and_then(|v| v.get(domain_id)) {
            return Err(Error::NotCreated {
                object: format!("the domain {domain_id}"),
                reason: describe_set_error(err),
            });
        }
        Ok(())
    }

    /// The name Stalwart answers as, and its default domain's id.
    pub async fn identity(&self) -> Result<Identity> {
        let args = self
            .call(
                "x:SystemSettings/get",
                serde_json::json!({
                    "ids": ["singleton"],
                    "properties": ["defaultHostname", "defaultDomainId"],
                }),
            )
            .await?;
        let s = listed(&args).first().cloned().unwrap_or_default();
        let field = |k: &str| s.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        Ok(Identity {
            hostname: field("defaultHostname"),
            default_domain_id: field("defaultDomainId"),
        })
    }

    /// Names Stalwart, and makes `domain_id` its default domain.
    ///
    /// 🔴 Left empty, the name is the container's — on Swarm the task's id — in the
    /// banner, in `EHLO` and in every MX and SRV record Stalwart computes. Both fields
    /// go together: the singleton is validated whole, and a fresh 0.16.26 holds a
    /// `defaultDomainId` naming no domain, which refuses an update of the name alone.
    /// Effective at `ReloadSettings`, no restart.
    pub async fn set_identity(&self, hostname: &str, domain_id: &str) -> Result<()> {
        let args = self
            .call(
                "x:SystemSettings/set",
                serde_json::json!({ "update": { "singleton": {
                    "defaultHostname": hostname,
                    "defaultDomainId": domain_id,
                } } }),
            )
            .await?;
        if let Some(err) = args.get("notUpdated").and_then(|v| v.get("singleton")) {
            return Err(Error::NotCreated {
                object: format!("the name {hostname}"),
                reason: describe_set_error(err),
            });
        }
        self.create(
            "x:Action/set",
            serde_json::json!({ "@type": "ReloadSettings" }),
            "the action ReloadSettings",
        )
        .await
        .map(|_| ())
    }

    /// Every recipient Stalwart still has to deliver to, and whether the list was cut.
    ///
    /// A `/get` with no ids answers at most `getMaxResults` messages (500 by default in
    /// 0.16.26), in no useful order: `true` says the queue may hold more than was read.
    pub async fn queue(&self) -> Result<(Vec<Waiting>, bool)> {
        let args = self
            .call("x:QueuedMessage/get", serde_json::json!({ "ids": null }))
            .await?;
        let cut = list(&args).len() >= QUEUE_GET_MAX;
        Ok((waiting_in(&args), cut))
    }

    /// Is the submission port open? A fresh 0.16 does not open it.
    pub async fn has_submission(&self) -> Result<bool> {
        let args = self
            .call("x:NetworkListener/get", serde_json::json!({}))
            .await?;
        Ok(listens_on(&args, SUBMISSION_PORT))
    }

    /// Opens the submission port, STARTTLS on 587.
    ///
    /// 🔴 Bound at startup only: Stalwart stores the listener at once and listens on
    /// it after its next restart — `ReloadSettings` does not bind it (0.16.26). Until
    /// then the port is refused, and the caller restarts it.
    pub async fn add_submission(&self) -> Result<()> {
        self.create(
            "x:NetworkListener/set",
            submission_listener_body(self.generation().await?),
            "the submission listener",
        )
        .await
        .map(|_| ())
    }

    /// The certificates Stalwart holds, with the names each serves.
    pub async fn certificates(&self) -> Result<Vec<Certificate>> {
        let args = self
            .call("x:Certificate/get", serde_json::json!({}))
            .await?;
        Ok(certificates_in(&args))
    }

    /// Adds a certificate and has Stalwart load it: it is served from then on to a
    /// client asking for one of its names (SNI), with no restart.
    pub async fn add_certificate(&self, cert_pem: &str, key_pem: &str) -> Result<String> {
        let id = self
            .create(
                "x:Certificate/set",
                certificate_body(cert_pem, key_pem),
                "the certificate",
            )
            .await?;
        self.create(
            "x:Action/set",
            serde_json::json!({ "@type": "ReloadTlsCertificates" }),
            "the reload of the certificates",
        )
        .await?;
        Ok(id)
    }

    /// Removes a certificate and has Stalwart stop serving it.
    pub async fn destroy_certificate(&self, id: &str) -> Result<()> {
        let args = self
            .call("x:Certificate/set", serde_json::json!({ "destroy": [id] }))
            .await?;
        if let Some(err) = args.get("notDestroyed").and_then(|v| v.get(id)) {
            return Err(Error::NotCreated {
                object: format!("the removal of the certificate {id}"),
                reason: describe_set_error(err),
            });
        }
        self.create(
            "x:Action/set",
            serde_json::json!({ "@type": "ReloadTlsCertificates" }),
            "the reload of the certificates",
        )
        .await
        .map(|_| ())
    }

    /// One `/set` creation, its id — or why it was refused, which HTTP 200 hides.
    async fn create(&self, method: &str, body: serde_json::Value, what: &str) -> Result<String> {
        let args = self
            .call(
                method,
                serde_json::json!({ "create": { CREATION_ID: body } }),
            )
            .await?;
        if let Some(err) = args.get("notCreated").and_then(|v| v.get(CREATION_ID)) {
            return Err(Error::NotCreated {
                object: what.to_string(),
                reason: describe_set_error(err),
            });
        }
        args.get("created")
            .and_then(|v| v.get(CREATION_ID))
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| Error::Unexpected(format!("{what}: creation returned no id: {args}")))
    }

    /// Idempotent provisioning of a complete address.
    ///
    /// 🔴 **Never changes the password of an existing account.** Replacing it would cut
    /// the IMAP/SMTP access of the app already running with the old one - for a plain
    /// plan rerun that was supposed to change nothing. Same rule as for OIDC secrets.
    pub async fn ensure_account(
        &self,
        address: &str,
        password: &str,
        aliases: &[String],
    ) -> Result<Provisioned> {
        let (local, domain) = address
            .split_once('@')
            .ok_or_else(|| Error::Unexpected(format!("address with no domain: {address}")))?;

        // The installation's mail domain, created with its first mailbox: a fresh
        // Stalwart hosts none, and every account would fail on "unknown domain".
        let domain_id = self.ensure_domain(domain).await?;

        if let Some(id) = self.find_account(local, &domain_id).await? {
            tracing::debug!(account = local, "mail account already present, kept");
            return Ok(Provisioned {
                account_id: id,
                address: address.to_string(),
                created: false,
            });
        }

        let id = self
            .create_account(local, &domain_id, password, aliases)
            .await?;

        Ok(Provisioned {
            account_id: id,
            address: address.to_string(),
            created: true,
        })
    }
}

/// The most a JMAP answer is read to: a queue listing of 500 messages is well under it.
const MAX_BODY: usize = 32 * 1024 * 1024;
/// The most of a refusal's body kept to say why.
const MAX_ERROR: usize = 64 * 1024;

/// A response's body, read to `max` bytes and no further.
///
/// 🔴 `json()` and `text()` read whatever comes: a server answering without end — or
/// whatever sits on the path to it — filled the memory of the process reading it.
/// A `/set` destroying several objects, all of them gone: a refusal answers 200 too,
/// in `notDestroyed`, and a removal read from the status alone was never checked.
fn destroyed(args: &serde_json::Value, what: &str) -> Result<()> {
    match args
        .get("notDestroyed")
        .and_then(|v| v.as_object())
        .and_then(|m| m.iter().next())
    {
        Some((id, err)) => Err(Error::NotCreated {
            object: format!("the removal of {what} ({id})"),
            reason: describe_set_error(err),
        }),
        None => Ok(()),
    }
}

pub(crate) async fn bounded(
    mut resp: reqwest::Response,
    max: usize,
) -> std::result::Result<Vec<u8>, String> {
    let too_large = || format!("an answer larger than {max} bytes, not read");
    if resp.content_length().is_some_and(|n| n > max as u64) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > max {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The port apps send on: submission, STARTTLS.
pub const SUBMISSION_PORT: u16 = 587;

/// The shared mailbox every mail domain carries, and its aliases (RFC 2142): where
/// other servers report delivery problems and complaints about this one.
pub const POSTMASTER: &str = "postmaster";
pub const POSTMASTER_ALIASES: &[&str] = &["abuse"];

/// One DKIM key of a domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimKey {
    pub selector: String,
    /// `pending`, `active`, `retiring`, `retired`.
    pub stage: String,
    /// `None` while nothing rotates it — always, with records published by hand.
    pub next_transition: Option<String>,
}

/// A DNS server Stalwart publishes through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServer {
    pub id: String,
    /// Its provider: `Cloudflare`, `Ovh`, `Tsig`…
    pub kind: String,
    pub description: String,
}

/// How one domain's records are published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainDns {
    pub id: String,
    pub name: String,
    /// `(server, record kinds)`; `None` when published by hand.
    pub published_by: Option<(String, Vec<String>)>,
}

/// An ACME account Stalwart requests certificates with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcmeProvider {
    pub id: String,
    /// `Http01`, `Dns01`, `TlsAlpn01`…
    pub challenge: String,
    pub directory: String,
    /// `mailto:` addresses.
    pub contact: Vec<String>,
    /// The account's URL at the directory, what a CAA `accounturi` names; `None`
    /// until the directory has registered it.
    pub account_uri: Option<String>,
}

/// How one domain's certificate is obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainTls {
    pub id: String,
    pub name: String,
    /// `(ACME account, names)`; `None` when certificates are added by hand.
    pub requested_by: Option<(String, Vec<String>)>,
}

/// One task of a domain: publishing its records, or requesting its certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsTask {
    pub id: String,
    /// `Pending`, `Failed`; on 1.0 also `Retry`, `Stalled`.
    pub state: String,
    pub created_at: String,
    pub failure: Option<String>,
}

/// What Stalwart says it is: its name and its default domain. Empty where unset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub hostname: String,
    pub default_domain_id: String,
}

/// A certificate as Stalwart holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub id: String,
    /// The names it is served for, its CN included.
    pub names: Vec<String>,
    /// RFC 3339, UTC.
    pub not_valid_after: String,
    /// The certificate itself, PEM — its key masked: what says whether a certificate a
    /// log holds is this one. Empty when Stalwart gave none.
    pub pem: String,
}

/// One recipient of a queued message, not delivered yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiting {
    pub message_id: String,
    pub recipient: String,
    /// The queue it waits in: `remote`, `local`…
    pub queue: String,
    /// When Stalwart took the message, RFC 3339.
    pub created_at: String,
    /// Attempts made so far.
    pub attempts: u64,
    pub next_retry: String,
    /// When Stalwart gives up and bounces it; `None` for a limit counted in attempts.
    pub expires_at: Option<String>,
    /// What the last attempt was told, by whom; `None` while it was never tried.
    pub error: Option<String>,
}

/// `getMaxResults`' default: a `/get` with no ids is cut there.
const QUEUE_GET_MAX: usize = 500;

/// The recipients of a `x:QueuedMessage/get` still to be delivered. A completed one,
/// or one failed for good, has been answered — by the receiver, or by a bounce.
fn waiting_in(args: &serde_json::Value) -> Vec<Waiting> {
    let text =
        |v: &serde_json::Value, k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let mut out = Vec::new();
    for m in list(args) {
        let (Some(id), Some(created_at)) = (text(m, "id"), text(m, "createdAt")) else {
            continue;
        };
        let Some(recipients) = m.get("recipients").and_then(|r| r.as_object()) else {
            continue;
        };
        for (address, r) in recipients {
            let status = r.get("status");
            let error = match status.and_then(|s| text(s, "@type")).as_deref() {
                Some("Scheduled") => None,
                Some("TemporaryFailure") => status.map(delivery_error),
                _ => continue,
            };
            out.push(Waiting {
                message_id: id.clone(),
                recipient: address.clone(),
                queue: text(r, "queueName").unwrap_or_default(),
                created_at: created_at.clone(),
                attempts: r.get("retryCount").and_then(|v| v.as_u64()).unwrap_or(0),
                next_retry: text(r, "retryDue").unwrap_or_default(),
                expires_at: r.get("expires").and_then(|e| text(e, "expiresAt")),
                error,
            });
        }
    }
    out.sort_by(|a, b| (&a.created_at, &a.recipient).cmp(&(&b.created_at, &b.recipient)));
    out
}

/// A delivery error as one line: the server's reply when one came, Stalwart's own
/// words otherwise (`Connection refused`, a DNS failure).
fn delivery_error(status: &serde_json::Value) -> String {
    let field = |k: &str| {
        status.get(k).and_then(|v| match v {
            serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
    };
    let said = match (field("responseCode"), field("responseMessage")) {
        (Some(code), Some(message)) => Some(
            [Some(code), field("responseEnhanced"), Some(message)]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" "),
        ),
        _ => field("errorMessage").or_else(|| field("errorType")),
    }
    .unwrap_or_else(|| "no reason given".into());
    match field("responseHostname") {
        Some(host) => format!("{host}: {said}"),
        None => said,
    }
}

/// Does one of the listeners of a `x:NetworkListener/get` bind `port`?
fn listens_on(args: &serde_json::Value, port: u16) -> bool {
    let suffix = format!(":{port}");
    list(args).iter().any(|l| {
        l.get("bind")
            .and_then(|b| b.as_object())
            .is_some_and(|b| b.keys().any(|a| a.ends_with(&suffix)))
    })
}

fn submission_listener_body(generation: Generation) -> serde_json::Value {
    serde_json::json!({
        "name": "submission",
        // A set, as every registry list: a map to `true`.
        "bind": { format!("[::]:{SUBMISSION_PORT}"): true },
        "protocol": "smtp",
        // 🔴 TLS is what lets an app authenticate at all: Stalwart offers PLAIN and
        // LOGIN only `if local_port != 25 && is_tls` (its default `saslMechanisms`).
        "useTls": true,
        // Neither schema declares a default: said, STARTTLS is what 587 means.
        generation.implicit_tls(): false,
    })
}

fn certificate_body(cert_pem: &str, key_pem: &str) -> serde_json::Value {
    serde_json::json!({
        "certificate": { "@type": "Text", "value": cert_pem },
        "privateKey": { "@type": "Text", "secret": key_pem },
    })
}

fn certificates_in(args: &serde_json::Value) -> Vec<Certificate> {
    list(args)
        .iter()
        .filter_map(|c| {
            Some(Certificate {
                id: c.get("id")?.as_str()?.to_string(),
                names: c
                    .get("subjectAlternativeNames")
                    .and_then(|n| n.as_object())
                    .map(|n| n.keys().cloned().collect())
                    .unwrap_or_default(),
                not_valid_after: c.get("notValidAfter")?.as_str()?.to_string(),
                // `{"@type": "Text", "value": …}`, read back as it was written (0.16.27
                // and 1.0.0, 2026-10-31).
                pem: c
                    .pointer("/certificate/value")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .collect()
}

/// The objects of a `/get`.
fn list(args: &serde_json::Value) -> &[serde_json::Value] {
    args.get("list")
        .and_then(|l| l.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// The body of an account creation.
///
/// Extracted so it is testable without a network: this is the part where a typo would
/// be silent, JMAP ignoring properties it does not know.
fn account_body(
    local: &str,
    domain_id: &str,
    password: &str,
    aliases: &[String],
) -> serde_json::Value {
    serde_json::json!({
        // Upstream schema discriminator: `#[serde(tag = "@type")] enum Account`.
        "@type": "User",
        // ⚠️ The local part ONLY. `emailAddress` is computed by the server from
        // `name` and `domainId`; sending it has no effect.
        "name": local,
        "domainId": domain_id,
        // 🔴 Maps keyed by index, not arrays: Stalwart refuses an array with
        // "invalidPatch" on the property — under HTTP 200. Checked against 0.16.26.
        "credentials": index_map(vec![serde_json::json!({
            "@type": "Password",
            "secret": password
        })]),
        "aliases": index_map(
            aliases
                .iter()
                .filter_map(|a| {
                    // An alias carries its own local part and domain. Only aliases on
                    // the same domain are accepted: elsewhere a second `domainId` would
                    // have to be resolved, and guessing which one would be wrong.
                    let local = a.split('@').next()?;
                    (!local.is_empty()).then(|| alias_entry(local, domain_id))
                })
                .collect(),
        ),
        "description": "Created by Homelabus",
    })
}

/// One alias, as Stalwart stores it.
///
/// Enabled by default, and left so: 0.16 calls the switch `enabled`, 1.0 `enable`, and
/// either refuses the other's name.
fn alias_entry(local: &str, domain_id: &str) -> serde_json::Value {
    serde_json::json!({ "name": local, "domainId": domain_id })
}

/// A `/get` answer's objects.
fn listed(args: &serde_json::Value) -> Vec<serde_json::Value> {
    args.get("list")
        .and_then(|l| l.as_array())
        .cloned()
        .unwrap_or_default()
}

/// Is `address` inside `cidr`? Both of one family; anything unreadable is outside.
fn in_subnet(address: &str, cidr: &str) -> bool {
    let Some((net, bits)) = cidr.split_once('/') else {
        return address == cidr;
    };
    let Ok(bits) = bits.parse::<u32>() else {
        return false;
    };
    match (
        address.parse::<std::net::IpAddr>(),
        net.parse::<std::net::IpAddr>(),
    ) {
        (Ok(std::net::IpAddr::V4(a)), Ok(std::net::IpAddr::V4(n))) if bits <= 32 => {
            let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (Ok(std::net::IpAddr::V6(a)), Ok(std::net::IpAddr::V6(n))) if bits <= 128 => {
            let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

/// A list as Stalwart's registry holds one: an object keyed `"0"`, `"1"`…
fn index_map(items: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::Value::Object(
        items
            .into_iter()
            .enumerate()
            .map(|(i, v)| (i.to_string(), v))
            .collect(),
    )
}

/// An `AND` of conditions, each carrying exactly one property.
///
/// A single condition needs no envelope: passing it through as-is avoids a pointless
/// indirection on the server side.
fn and(conditions: &[serde_json::Value]) -> serde_json::Value {
    match conditions {
        [only] => only.clone(),
        many => serde_json::json!({ "operator": "AND", "conditions": many }),
    }
}

/// The ids returned by a `/query`.
fn ids(args: &serde_json::Value) -> Vec<String> {
    args.get("ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// A number no earlier probe drew: std's hasher keys are random per process, the clock
/// tells two calls of one process apart.
fn fresh() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    h.finish()
}

/// The probe's sender and linked domain out of `n`: an address of the three
/// documentation ranges, and a `.com` name nobody registered.
fn probe_names(n: u64) -> (String, String) {
    let range = ["192.0.2", "198.51.100", "203.0.113"][(n % 3) as usize];
    let host = 1 + (n >> 2) % 254;
    (
        format!("{range}.{host}"),
        format!("hlb-probe-{:012x}.com", (n >> 16) & 0xffff_ffff_ffff),
    )
}

/// The tags of a classification saying a blocklist refused the question, sorted.
///
/// The tags are the spam rules' own, downloaded by Stalwart: a list refusing a public
/// resolver answers `…_BLOCKED_OPENRESOLVER` (Spamhaus) or `…_BLOCKED` (URIBL, SURBL,
/// DNSWL, the rest). `IP_BLOCKED` is not one: it is Stalwart's own list of addresses.
fn refusals<'a>(tags: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = tags
        .filter(|t| *t != "IP_BLOCKED" && (t.ends_with("_BLOCKED") || t.contains("_BLOCKED_")))
        .map(str::to_string)
        .collect();
    out.sort();
    out
}

/// Makes a JMAP `SetError` readable.
fn describe_set_error(e: &serde_json::Value) -> String {
    let t = e.get("type").and_then(|v| v.as_str()).unwrap_or("unknown");
    match e.get("description").and_then(|v| v.as_str()) {
        Some(d) => format!("{t} — {d}"),
        None => t.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A server answering `head`, then `len` bytes, on a port of its own.
    async fn answering(head: &'static str, len: usize) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = l.local_addr().expect("addr");
        tokio::spawn(async move {
            if let Ok((mut c, _)) = l.accept().await {
                let mut buf = [0u8; 1024];
                let _ = c.read(&mut buf).await;
                let _ = c.write_all(head.as_bytes()).await;
                let _ = c.write_all(&vec![b'x'; len]).await;
            }
        });
        format!("http://{addr}/")
    }

    /// What the fake Stalwart below was asked to write.
    #[derive(Default)]
    struct Writes {
        uploads: Vec<String>,
        sets: Vec<serde_json::Value>,
    }

    type Answer = dyn Fn(&str, &str, &serde_json::Value) -> (u16, String) + Send + Sync;

    /// A Stalwart answering `answer(path, method, args)` — `method` and `args` those
    /// of a JMAP call, empty for an upload or a download (whose body is in `args`).
    async fn fake(answer: std::sync::Arc<Answer>) -> Stalwart {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = l.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head, body) = loop {
                    let n = c.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break (String::new(), String::new());
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let len = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if body.len() >= len {
                            break (head.to_string(), body.to_string());
                        }
                    }
                };
                let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                // The session the fakes were written from: 0.16's, no metadata.
                let (status, reply) = if path == "/jmap/session" {
                    (
                        200,
                        r#"{"capabilities":{"urn:ietf:params:jmap:core":{}}}"#.to_string(),
                    )
                } else if path == "/jmap/" {
                    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                    let call = &v["methodCalls"][0];
                    let method = call[0].as_str().unwrap_or("");
                    let (status, args) = answer(&path, method, &call[1]);
                    let args: serde_json::Value = serde_json::from_str(&args).unwrap_or_default();
                    (
                        status,
                        serde_json::json!({ "methodResponses": [[method, args, "0"]] }).to_string(),
                    )
                } else {
                    answer(&path, "", &serde_json::Value::String(body))
                };
                let _ = c
                    .write_all(
                        format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: \
                             close\r\n\r\n{reply}",
                            reply.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            }
        });
        Stalwart::new(format!("http://{addr}"), Auth::Bearer("t".into()))
    }

    /// A Stalwart holding one account with one Sieve script (`active` or not), whose
    /// download answers `download` — `(status, body)`.
    async fn sieve_server(
        active: bool,
        download: (u16, &'static str),
    ) -> (Stalwart, std::sync::Arc<std::sync::Mutex<Writes>>) {
        let writes = std::sync::Arc::new(std::sync::Mutex::new(Writes::default()));
        let w = writes.clone();
        let s = fake(std::sync::Arc::new(move |path, method, args| {
            if path.starts_with("/jmap/download/") {
                return (download.0, download.1.to_string());
            }
            if path.starts_with("/jmap/upload/") {
                let body = args.as_str().unwrap_or("").to_string();
                w.lock().expect("writes").uploads.push(body);
                return (200, r#"{"blobId":"b2"}"#.to_string());
            }
            let answer = match method {
                "x:Domain/query" => serde_json::json!({ "ids": ["d1"] }),
                "x:Account/query" => serde_json::json!({ "ids": ["a1"] }),
                "SieveScript/get" => serde_json::json!({ "list": [
                    { "id": "s1", "name": "mine", "blobId": "b1", "isActive": active }
                ]}),
                "SieveScript/set" => {
                    w.lock().expect("writes").sets.push(args.clone());
                    serde_json::json!({ "updated": { "s1": null } })
                }
                _ => serde_json::json!({}),
            };
            (200, answer.to_string())
        }))
        .await;
        (s, writes)
    }

    #[tokio::test]
    async fn a_removal_stalwart_refused_is_never_reported_done() {
        // A JMAP `/set` that fails still answers 200: the refusal is in `notDestroyed`.
        let refused = r#"{"notDestroyed": {"x1": {"type": "forbidden"}}}"#;
        let s = fake(std::sync::Arc::new(move |_, method, _| {
            let answer = match method {
                "x:AllowedIp/get" => r#"{"list": [{"id": "e1", "address": "10.0.9.0/24"}]}"#,
                "x:BlockedIp/get" => r#"{"list": [{"id": "x1", "address": "10.0.9.7"}]}"#,
                "x:Task/get" => {
                    r#"{"list": [{"id": "x1", "@type": "DnsManagement", "domainId": "d1",
                        "status": {"@type": "Failed", "createdAt": "1"}}]}"#
                }
                "x:BlockedIp/set" | "x:Task/set" => refused,
                _ => {
                    return (
                        200,
                        format!(r#"{{"created": {{"{CREATION_ID}": {{"id": "n1"}}}}}}"#),
                    )
                }
            };
            (200, answer.to_string())
        }))
        .await;
        let lifted = s.trust_network("10.0.9.0/24", "platform").await;
        assert!(
            matches!(lifted, Err(Error::NotCreated { .. })),
            "{lifted:?}"
        );
        let again = s.publish_again("d1", &["dkim".into()]).await;
        assert!(matches!(again, Err(Error::NotCreated { .. })), "{again:?}");
    }

    #[tokio::test]
    async fn a_script_that_cannot_be_read_is_never_replaced() {
        // 🔴 The download answered "" on any refusal: the merge built on nothing and
        // the upload replaced the person's own rules with Homelabus's block alone.
        let (s, writes) = sieve_server(true, (503, "busy")).await;
        let r = s
            .apply_sieve("ana@example.org", &|existing| format!("{existing}# hlb"))
            .await;
        assert!(matches!(r, Err(Error::Api { status: 503, .. })), "{r:?}");
        let w = writes.lock().expect("writes");
        assert!(w.uploads.is_empty() && w.sets.is_empty(), "nothing written");
    }

    #[tokio::test]
    async fn an_inactive_script_is_activated_once_it_carries_the_rules() {
        let (s, writes) = sieve_server(false, (200, "# mine\n")).await;
        let script = s
            .apply_sieve("ana@example.org", &|existing| format!("{existing}# hlb"))
            .await
            .expect("applied");
        assert_eq!(script, "# mine\n# hlb", "built on the script read");
        let first = writes.lock().expect("writes").sets[0].clone();
        assert_eq!(first["onSuccessActivateScript"], "s1", "{first}");

        let (s, writes) = sieve_server(true, (200, "# mine\n")).await;
        s.apply_sieve("ana@example.org", &|existing| format!("{existing}# hlb"))
            .await
            .expect("applied");
        let w = writes.lock().expect("writes");
        assert!(
            w.sets[0].get("onSuccessActivateScript").is_none(),
            "{:?}",
            w.sets
        );
    }

    #[tokio::test]
    async fn an_answer_past_its_bound_is_not_read() {
        let url = answering("HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n", 10).await;
        let r = reqwest::get(&url).await.expect("answer");
        assert!(
            bounded(r, 1024).await.is_err(),
            "a declared length past the bound"
        );

        let url = answering("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", 4096).await;
        let r = reqwest::get(&url).await.expect("answer");
        assert!(bounded(r, 1024).await.is_err(), "an undeclared one");

        let url = answering("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n", 10).await;
        let r = reqwest::get(&url).await.expect("answer");
        assert_eq!(bounded(r, 1024).await.expect("within").len(), 10);
    }

    #[test]
    fn every_probe_asks_names_never_asked() {
        let a = probe_names(fresh());
        let b = probe_names(fresh());
        assert_ne!(a, b);
        for (address, domain) in [a, b, probe_names(0), probe_names(u64::MAX)] {
            let ip: std::net::Ipv4Addr = address.parse().expect("an address");
            assert!(ip.is_documentation(), "{ip}");
            assert!(
                !address.ends_with(".0") && !address.ends_with(".255"),
                "{address}"
            );
            assert!(
                domain.starts_with("hlb-probe-") && domain.ends_with(".com"),
                "{domain}"
            );
        }
    }

    #[test]
    fn a_blocklist_refusing_the_resolver_is_told_from_a_listing() {
        // The tags 0.16.26 gave the probe through 1.1.1.1, and one listing.
        let tags = [
            "URIBL_BLOCKED",
            "RBL_SPAMHAUS_BLOCKED_OPENRESOLVER",
            "DBL_BLOCKED_OPENRESOLVER",
            "RBL_SENDERSCORE_REPUT_BLOCKED",
            "DBL_SPAM",
            "IP_BLOCKED",
            "RDNS_NONE",
        ];
        assert_eq!(
            refusals(tags.into_iter()),
            [
                "DBL_BLOCKED_OPENRESOLVER",
                "RBL_SENDERSCORE_REPUT_BLOCKED",
                "RBL_SPAMHAUS_BLOCKED_OPENRESOLVER",
                "URIBL_BLOCKED"
            ]
        );
    }

    #[test]
    fn an_address_is_inside_its_subnet_only() {
        assert!(in_subnet("10.0.1.7", "10.0.1.0/24"));
        assert!(!in_subnet("10.0.2.7", "10.0.1.0/24"));
        assert!(in_subnet("172.21.0.3", "172.16.0.0/12"));
        assert!(in_subnet("10.9.9.9", "0.0.0.0/0"));
        assert!(!in_subnet("fd00::1", "10.0.1.0/24"));
        assert!(in_subnet("fd00::1", "fd00::/8"));
        assert!(!in_subnet("garbage", "10.0.1.0/24"));
    }

    /// `x:QueuedMessage/get` from 0.16.26: a message to a relay refusing connections,
    /// and one delivered in the house to alice (as read), bounced for erin, greylisted
    /// for carol and due for fay.
    const QUEUE: &str = r#"{"list":[
        {"createdAt":"2026-10-20T07:15:09Z","nextRetry":"2026-10-20T07:17:09Z","returnPath":"alice@example.org",
         "recipients":{"bob@example.net":{"retryCount":1,"retryDue":"2026-10-20T07:17:09Z","notifyCount":0,
           "expires":{"expiresAt":"2026-10-23T07:15:09Z","@type":"Ttl"},"queueName":"remote",
           "status":{"errorType":"connectionError","errorMessage":"I/O error: Connection refused (os error 111)",
             "errorCommand":null,"responseHostname":"relay.test","responseCode":null,"responseEnhanced":null,
             "responseMessage":null,"@type":"TemporaryFailure"},"flags":{},"orcpt":null}},"id":"jkmwhe0waaaa"},
        {"createdAt":"2026-10-20T06:00:00Z","returnPath":"alice@example.org",
         "recipients":{
           "carol@example.com":{"retryCount":3,"retryDue":"2026-10-20T08:00:00Z","queueName":"remote",
             "expires":{"expiresAttempts":10,"@type":"Attempts"},
             "status":{"errorType":"unexpectedResponse","errorMessage":null,"responseHostname":"mx.example.com",
               "responseCode":451,"responseEnhanced":"4.7.1","responseMessage":"Greylisted, try later",
               "@type":"TemporaryFailure"}},
           "alice@example.org":{"retryCount":0,"retryDue":"2026-10-20T06:00:00Z","queueName":"local",
             "status":{"responseHostname":"localhost","responseCode":250,"responseEnhanced":"2.1.5",
               "responseMessage":"OK","@type":"Completed"},"flags":{"dsnSent":true}},
           "erin@example.com":{"retryCount":1,"queueName":"remote","status":{"responseHostname":"mx.example.com",
             "responseCode":550,"responseEnhanced":"5.1.1","responseMessage":"No such user",
             "@type":"PermanentFailure"}},
           "fay@example.com":{"retryCount":0,"retryDue":"2026-10-20T06:00:00Z","queueName":"remote",
             "status":{"@type":"Scheduled"}}},
         "id":"b"}]}"#;

    #[test]
    fn the_queue_lists_what_waits_with_the_last_answer_and_skips_what_was_answered() {
        let w = waiting_in(&serde_json::from_str(QUEUE).expect("json"));
        let seen: Vec<(&str, u64, Option<&str>)> = w
            .iter()
            .map(|w| (w.recipient.as_str(), w.attempts, w.error.as_deref()))
            .collect();
        assert_eq!(
            seen,
            [
                (
                    "carol@example.com",
                    3,
                    Some("mx.example.com: 451 4.7.1 Greylisted, try later")
                ),
                ("fay@example.com", 0, None),
                (
                    "bob@example.net",
                    1,
                    Some("relay.test: I/O error: Connection refused (os error 111)")
                ),
            ],
            "the oldest first; delivered and bounced recipients are not waiting"
        );
        assert_eq!(w[2].expires_at.as_deref(), Some("2026-10-23T07:15:09Z"));
        assert_eq!(w[0].expires_at, None, "a limit in attempts has no date");
        assert_eq!(w[2].queue, "remote");
    }

    /// `x:NetworkListener/get` from a fresh 0.16.26, trimmed to what is read.
    const LISTENERS: &str = r#"{"list":[
        {"name":"smtp","bind":{"[::]:25":true},"protocol":"smtp","useTls":true,"tlsImplicit":false,"id":"a"},
        {"name":"submissions","bind":{"[::]:465":true},"protocol":"smtp","useTls":true,"tlsImplicit":true,"id":"b"},
        {"name":"imaps","bind":{"[::]:993":true},"protocol":"imap","useTls":true,"tlsImplicit":true,"id":"c"}]}"#;

    #[test]
    fn a_fresh_stalwart_has_no_submission_port() {
        // 🔴 Measured: 25, 465, 993, 995, 4190, 443 and 8080 listen — not 587, the
        // port every app is handed.
        let v: serde_json::Value = serde_json::from_str(LISTENERS).expect("json");
        assert!(!listens_on(&v, SUBMISSION_PORT));
        assert!(listens_on(&v, 465));
    }

    #[test]
    fn submission_is_starttls_on_587() {
        // Each generation under its own name: the other's is refused, the port not opened.
        for (g, key) in [
            (Generation::V016, "tlsImplicit"),
            (Generation::V1, "implicitTls"),
        ] {
            let b = submission_listener_body(g);
            assert_eq!(b["bind"], serde_json::json!({ "[::]:587": true }));
            assert_eq!(b["protocol"], "smtp");
            // STARTTLS, not implicit TLS: what "587" means to every client library.
            assert_eq!(b["useTls"], true);
            assert_eq!(b[key], false, "{g:?}: {b}");
            assert_eq!(b.as_object().expect("object").len(), 5, "{g:?}: {b}");
        }
    }

    #[test]
    fn the_generation_is_read_from_the_session() {
        // Trimmed from the real sessions of 0.16.27 and 1.0.0.
        let v016 = serde_json::json!({ "capabilities": {
            "urn:ietf:params:jmap:core": {}, "urn:ietf:params:jmap:mail": {} } });
        let v1 = serde_json::json!({ "capabilities": {
            "urn:ietf:params:jmap:core": {}, "urn:ietf:params:jmap:metadata": {} } });
        assert_eq!(
            Generation::of_session(&v016).expect("0.16"),
            Generation::V016
        );
        assert_eq!(Generation::of_session(&v1).expect("1.0"), Generation::V1);
        // An answer that is not a session is not taken for the older schema.
        assert!(Generation::of_session(&serde_json::json!({})).is_err());
    }

    #[test]
    fn a_certificate_is_read_with_its_names_and_its_end() {
        // Captured from 0.16.26: the names are a SET (a map to `true`), the CN included.
        let v: serde_json::Value = serde_json::from_str(
            r#"{"list":[{"id":"x1","subjectAlternativeNames":{"stalwart":true},
                         "notValidAfter":"2029-01-20T10:39:35Z","issuer":"CN=Homelabus",
                         "certificate":{"@type":"Text","value":"PEM"},
                         "privateKey":{"@type":"Text","secret":"****"}}]}"#,
        )
        .expect("json");
        assert_eq!(
            certificates_in(&v),
            vec![Certificate {
                id: "x1".into(),
                names: vec!["stalwart".into()],
                not_valid_after: "2029-01-20T10:39:35Z".into(),
                pem: "PEM".into(),
            }]
        );
        // The PEMs travel as texts, the key as a SECRET text.
        let b = certificate_body("CERT", "KEY");
        assert_eq!(
            b["certificate"],
            serde_json::json!({ "@type": "Text", "value": "CERT" })
        );
        assert_eq!(
            b["privateKey"],
            serde_json::json!({ "@type": "Text", "secret": "KEY" })
        );
    }

    #[test]
    fn the_creation_id_is_written_and_read_under_the_same_key() {
        // 🔴 The bug this guards against is SILENT. JMAP answers under the id we gave
        // it: if the write says one thing and the failure lookup another, `notCreated`
        // never matches — and a failed creation still returns HTTP 200. The account
        // simply would not exist, and nothing would say so until the first lost email.
        //
        // Scanning the source rather than calling the client: reproducing the drift
        // needs a Stalwart, and this catches it at compile-to-test time.
        let src = include_str!("lib.rs");
        let uses = src.matches("CREATION_ID").count();
        assert!(
            uses >= 4,
            "the creation id is used {uses} times: a literal crept back in"
        );
        // ⚠️ The pattern is ASSEMBLED. Written out, this test matches its own source
        // and fails on itself — the trap the project already hit with the "action(s)"
        // scanner.
        let literal = format!("v.get({}new{})", '"', '"');
        assert!(
            !src.contains(&literal),
            "a literal creation id is back: it will drift from the write side"
        );
    }

    fn client() -> Stalwart {
        Stalwart::new(
            "https://mail.example.org/",
            Auth::Basic {
                user: "admin".into(),
                password: "secret".into(),
            },
        )
    }

    #[test]
    fn the_endpoint_is_jmap_not_api() {
        // 🔴 Stalwart 0.16 has no /api/principal: everything goes through JMAP.
        let c = client();
        assert_eq!(c.endpoint(), "https://mail.example.org/jmap/");
    }

    #[test]
    fn the_stalwart_capability_is_always_declared() {
        // Without `urn:stalwart:jmap`, the server rejects every "x:" method.
        let r = JmapRequest::one("x:Account/query", serde_json::json!({}));
        assert!(r.using.contains(&"urn:stalwart:jmap"), "{:?}", r.using);
        assert!(r.using.contains(&"urn:ietf:params:jmap:core"));
    }

    #[test]
    fn the_creation_body_never_carries_an_email_address() {
        // 🔴 `emailAddress` is computed by the server from `name` + `domainId`.
        // Sending it produces NO error and has no effect: you would believe you had
        // created gitea@example.org having created something else entirely.
        let b = account_body("gitea", "d1", "pw", &[]);
        assert!(b.get("emailAddress").is_none(), "{b}");
        assert_eq!(b["name"], "gitea", "the local part ONLY");
        assert_eq!(b["domainId"], "d1");
    }

    #[test]
    fn the_creation_body_carries_the_type_discriminator() {
        // The upstream schema uses `#[serde(tag = "@type")]` - a plain "type" would
        // be ignored and creation would fail without saying why.
        let b = account_body("gitea", "d1", "pw", &[]);
        assert_eq!(b["@type"], "User");
        // A map keyed by index, as Stalwart 0.16 holds it: an array is refused with
        // `invalidPatch` under HTTP 200 (checked against a live 0.16.26).
        assert_eq!(b["credentials"]["0"]["@type"], "Password");
        assert_eq!(b["credentials"]["0"]["secret"], "pw");
    }

    #[test]
    fn aliases_keep_only_their_local_part() {
        // An alias carries `name` + `domainId`, like the account: pasting the full
        // address in would create an alias "contact@example.org@example.org".
        let b = account_body(
            "gitea",
            "d1",
            "pw",
            &["contact@example.org".into(), "info".into()],
        );
        let a = b["aliases"].as_object().expect("a map keyed by index");
        assert_eq!(a.len(), 2);
        assert_eq!(a["0"]["name"], "contact");
        assert_eq!(a["0"]["domainId"], "d1");
        assert_eq!(a["1"]["name"], "info");
        // Nothing else: the enabled switch is named differently by 0.16 and 1.0, which
        // refuse each other's, and both default it on.
        assert_eq!(a["0"].as_object().expect("alias").len(), 2, "{b}");
    }

    #[test]
    fn an_empty_alias_is_dropped() {
        let b = account_body("gitea", "d1", "pw", &["@example.org".into(), "".into()]);
        assert!(b["aliases"].as_object().expect("map").is_empty(), "{b}");
    }

    #[test]
    fn a_two_property_filter_becomes_an_and_of_conditions() {
        // 🔴 The bug this test locks down: server-side, each key within one condition
        // OVERWRITES the previous. A flat two-property filter would keep only one, and
        // you would match the "contact@" of another domain.
        let f = and(&[
            serde_json::json!({ "name": "gitea" }),
            serde_json::json!({ "domainId": "d1" }),
        ]);

        assert_eq!(f["operator"], "AND");
        let c = f["conditions"].as_array().expect("conditions");
        assert_eq!(c.len(), 2, "each property must get ITS OWN condition");
        assert_eq!(c[0]["name"], "gitea");
        assert_eq!(c[1]["domainId"], "d1");

        // And above all: never both properties in the same object.
        assert!(c[0].get("domainId").is_none(), "{f}");
        assert!(c[1].get("name").is_none(), "{f}");
    }

    #[test]
    fn a_single_condition_needs_no_envelope() {
        let f = and(&[serde_json::json!({ "name": "gitea" })]);
        assert_eq!(f["name"], "gitea");
        assert!(f.get("operator").is_none(), "{f}");
    }

    #[test]
    fn a_query_response_yields_its_ids() {
        let args = serde_json::json!({ "ids": ["a1", "b2"], "total": 2 });
        assert_eq!(ids(&args), vec!["a1", "b2"]);
        assert!(ids(&serde_json::json!({ "ids": [] })).is_empty());
        assert!(ids(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn a_method_error_is_read_from_the_body_not_the_status() {
        // JMAP encodes method errors INSIDE the response: the HTTP code stays 200.
        let r: JmapResponse = serde_json::from_str(
            r#"{"methodResponses":[["error",{"type":"unknownMethod"},"c0"]]}"#,
        )
        .expect("parsable");

        let e = r.first().unwrap_err();
        assert!(matches!(e, Error::Api { status: 200, .. }), "{e:?}");
        assert!(e.to_string().contains("unknownMethod"), "{e}");
    }

    #[test]
    fn an_empty_response_is_an_error_not_a_success() {
        let r: JmapResponse = serde_json::from_str(r#"{"methodResponses":[]}"#).expect("parsable");
        assert!(matches!(r.first(), Err(Error::Unexpected(_))));
    }

    #[test]
    fn a_normal_response_yields_its_arguments() {
        let r: JmapResponse = serde_json::from_str(
            r#"{"methodResponses":[["x:Account/query",{"ids":["z9"]},"c0"]]}"#,
        )
        .expect("parsable");
        assert_eq!(ids(&r.first().expect("arguments")), vec!["z9"]);
    }

    #[test]
    fn a_set_error_is_rendered_with_its_reason() {
        let e = serde_json::json!({
            "type": "invalidProperties",
            "description": "name already exists"
        });
        let d = describe_set_error(&e);
        assert!(d.contains("invalidProperties"), "{d}");
        assert!(d.contains("already exists"), "{d}");
        // With no description, at least keep the type.
        assert_eq!(
            describe_set_error(&serde_json::json!({ "type": "forbidden" })),
            "forbidden"
        );
    }

    #[tokio::test]
    async fn an_address_without_a_domain_is_refused() {
        let e = client()
            .ensure_account("gitea", "pw", &[])
            .await
            .unwrap_err();
        assert!(e.to_string().contains("no domain"), "{e}");
    }

    #[test]
    fn a_missing_domain_says_what_to_do() {
        // The message must carry the action, not only the observation: without the
        // domain created first, no account is possible.
        let e = Error::UnknownDomain("example.org".into()).to_string();
        assert!(e.contains("example.org"), "{e}");
        assert!(e.contains("create it first"), "{e}");
    }

    #[test]
    fn provisioning_says_whether_it_created_anything() {
        // 🔴 The distinction carries a consequence: `created: false` means the
        // password in the vault is the one from BEFORE, and was not touched.
        let p = Provisioned {
            account_id: "a1".into(),
            address: "gitea@example.org".into(),
            created: false,
        };
        assert!(!p.created);
    }
}
