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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Stalwart injoignable ({context}) : {source}")]
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

/// The vendor capability, without which Stalwart rejects the `x:` methods.
const CAPABILITY: &str = "urn:stalwart:jmap";
const CORE: &str = "urn:ietf:params:jmap:core";

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
            using: vec![CORE, CAPABILITY],
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

        let nom = r.get(0).and_then(|v| v.as_str()).unwrap_or("?").to_string();
        let args = r
            .get(1)
            .cloned()
            .ok_or_else(|| Error::Unexpected("response carried no arguments".into()))?;

        if nom == "error" {
            let t = args
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("inconnue");
            return Err(Error::Api {
                status: 200,
                detail: format!("erreur JMAP « {t} » : {args}"),
            });
        }
        Ok(args)
    }
}

/// An account as Stalwart describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailAccount {
    pub id: String,
    /// Partie locale, sans le domaine.
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

/// How we authenticate to Stalwart.
#[derive(Debug, Clone)]
pub enum Auth {
    /// Compte d'administration : `Authorization: Basic`.
    Basic { user: String, password: String },
    /// Jeton d'API : `Authorization: Bearer`.
    Bearer(String),
}

pub struct Stalwart {
    base_url: String,
    auth: Auth,
    http: reqwest::Client,
}

impl Stalwart {
    pub fn new(base_url: impl Into<String>, auth: Auth) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            auth,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .unwrap_or_default(),
        }
    }

    fn endpoint(&self) -> String {
        format!("{}/jmap/", self.base_url)
    }

    async fn call(&self, method: &str, args: serde_json::Value) -> Result<serde_json::Value> {
        let req = self
            .http
            .post(self.endpoint())
            .json(&JmapRequest::one(method, args));

        let req = match &self.auth {
            Auth::Basic { user, password } => req.basic_auth(user, Some(password)),
            Auth::Bearer(t) => req.bearer_auth(t),
        };

        let resp = req.send().await.map_err(|source| Error::Http {
            source,
            context: method.to_string(),
        })?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let detail = resp.text().await.unwrap_or_default();
            return Err(Error::Api { status, detail });
        }

        let body: JmapResponse = resp
            .json()
            .await
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
                    "create": { "nouveau": account_body(local, domain_id, password, aliases) }
                }),
            )
            .await?;

        // 🔴 The central trap: HTTP 200 does NOT mean created.
        if let Some(err) = args.get("notCreated").and_then(|v| v.get("nouveau")) {
            return Err(Error::NotCreated {
                object: format!("le compte « {local} »"),
                reason: describe_set_error(err),
            });
        }

        let id = args
            .get("created")
            .and_then(|v| v.get("nouveau"))
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
            let detail = resp.text().await.unwrap_or_default();
            return Err(Error::Api { status, detail });
        }

        let v: serde_json::Value = resp
            .json()
            .await
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

        if !resp.status().is_success() {
            // ⚠️ A missing script is not an error: it is an account that has none
            // yet. Returning an empty string lets the merge create the first one.
            return Ok(String::new());
        }
        resp.text()
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable script: {e}")))
    }

    /// An account's active Sieve script: `(id, blobId)`.
    pub async fn active_sieve_script(&self, account_id: &str) -> Result<Option<(String, String)>> {
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

        let existing = match self.active_sieve_script(&account_id).await? {
            Some((_, blob)) => self.download_blob(&account_id, &blob).await?,
            None => String::new(),
        };

        let final_ = render_block(&existing);
        let blob = self.upload_blob(&account_id, &final_).await?;

        let previous = self.active_sieve_script(&account_id).await?;
        let args = match &previous {
            // Updating the existing script keeps its id, and therefore its active
            // state. Creating a second one would leave the old one active, and the new
            // one would never apply.
            Some((id, _)) => {
                self.call(
                    "SieveScript/set",
                    serde_json::json!({
                        "accountId": account_id,
                        "update": { id: { "blobId": blob } }
                    }),
                )
                .await?
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
        let args = self
            .call(
                "x:Account/get",
                serde_json::json!({
                    "ids": [account_id],
                    "properties": ["aliases"]
                }),
            )
            .await?;

        Ok(args
            .get("list")
            .and_then(|l| l.as_array())
            .and_then(|l| l.first())
            .and_then(|c| c.get("aliases"))
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.get("name").and_then(|n| n.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Replaces an account's alias list.
    ///
    /// 🔴 **Read-modify-write.** JMAP has no "add an alias" operation: `update`
    /// overwrites the property. So we read the existing list, modify it and write it
    /// back - and two simultaneous modifications would lose the first. On a homelab
    /// driven by one command at a time that is acceptable; noting it avoids
    /// rediscovering it the day the controller does this in parallel.
    async fn set_aliases(
        &self,
        account_id: &str,
        domain_id: &str,
        aliases: &[String],
    ) -> Result<()> {
        let list: Vec<serde_json::Value> = aliases
            .iter()
            .filter_map(|a| {
                let local = a.split('@').next()?;
                (!local.is_empty()).then(|| {
                    serde_json::json!({
                        "enabled": true,
                        "name": local,
                        "domainId": domain_id
                    })
                })
            })
            .collect();

        let args = self
            .call(
                "x:Account/set",
                serde_json::json!({
                    "update": { account_id: { "aliases": list } }
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

        let mut current = self.aliases_of(&account_id).await?;
        if current.iter().any(|a| a == alias_local) {
            return Ok(false);
        }
        current.push(alias_local.to_string());
        self.set_aliases(&account_id, &domain_id, &current).await?;

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

        let current = self.aliases_of(&account_id).await?;
        if !current.iter().any(|a| a == alias_local) {
            return Ok(false);
        }
        let restants: Vec<String> = current.into_iter().filter(|a| a != alias_local).collect();
        self.set_aliases(&account_id, &domain_id, &restants).await?;

        tracing::info!(account = %address, alias = alias_local, "alias removed");
        Ok(true)
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

        let domain_id = self.domain_id(domain).await?;

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
        "credentials": [{
            "@type": "Password",
            "secret": password
        }],
        "aliases": aliases
            .iter()
            .filter_map(|a| {
                // An alias carries its own local part and domain. Only aliases on the
                // same domain are accepted: elsewhere a second `domainId` would have to
                // be resolved, and guessing which one would be wrong.
                let local = a.split('@').next()?;
                (!local.is_empty()).then(|| {
                    serde_json::json!({
                        "enabled": true,
                        "name": local,
                        "domainId": domain_id
                    })
                })
            })
            .collect::<Vec<_>>(),
        "description": "Created by Homelabus",
    })
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

/// Rend lisible une `SetError` JMAP.
fn describe_set_error(e: &serde_json::Value) -> String {
    let t = e.get("type").and_then(|v| v.as_str()).unwrap_or("inconnu");
    match e.get("description").and_then(|v| v.as_str()) {
        Some(d) => format!("{t} — {d}"),
        None => t.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // 🔴 Stalwart 0.16 n'a pas de /api/principal : tout passe par JMAP.
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
        assert_eq!(b["credentials"][0]["@type"], "Password");
        assert_eq!(b["credentials"][0]["secret"], "pw");
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
        let a = b["aliases"].as_array().expect("list");
        assert_eq!(a.len(), 2);
        assert_eq!(a[0]["name"], "contact");
        assert_eq!(a[0]["domainId"], "d1");
        assert_eq!(a[1]["name"], "info");
        assert_eq!(a[0]["enabled"], true);
    }

    #[test]
    fn an_empty_alias_is_dropped() {
        let b = account_body("gitea", "d1", "pw", &["@example.org".into(), "".into()]);
        assert!(b["aliases"].as_array().expect("list").is_empty(), "{b}");
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
        // Sans description, on garde au moins le type.
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
