//! PocketID API client. The one other place a role's people are written — a Bitwarden
//! organisation's members — is `hlb_bitwarden::directory`.
//!
//! This is what makes SSO genuinely automatic: installing an app creates its OIDC
//! client, computes its callback URIs from the chosen domain, and fetches the secret -
//! without ever opening PocketID's interface.
//!
//! ## The API, as it is
//!
//! Established against a real instance, there being no published specification:
//!
//! | Operation | Call |
//! |---|---|
//! | List / search | `GET /api/oidc/clients?search=<name>` |
//! | Create | `POST /api/oidc/clients` |
//! | Get the secret | `POST /api/oidc/clients/{id}/secrets` (v2.15+), `…/secret` before |
//! | Delete | `DELETE /api/oidc/clients/{id}` |
//!
//! Authentication through the `X-API-KEY` header — from v2.2, a key fixed at install
//! (`STATIC_API_KEY`), so nobody has to create one by hand.
//!
//! ⚠️ **Before v2.15 the secret is not returned at creation**: it takes a second call,
//! and each call **regenerates a new one**, invalidating the previous. From v2.15 the
//! creation answers with one (`createdSecret`), and each further call ADDS an active
//! secret. Either way [`PocketId::ensure`] never asks again for an existing client.

pub mod groups;
pub mod oidc;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("PocketID unreachable ({context}) : {source}")]
    Http {
        #[source]
        source: reqwest::Error,
        context: String,
    },

    #[error("PocketID answered {status} - {detail}")]
    Api { status: u16, detail: String },

    #[error("API key refused by PocketID")]
    Unauthorized,

    #[error("unexpected response from PocketID: {0}")]
    Unexpected(String),

    /// PocketID answered success and kept the old value. It does that for an account
    /// synchronised from LDAP, whose names and address it will not let anyone change.
    #[error("PocketID accepted the change and kept the old {0} — an account synchronised from LDAP is changed in the directory, not here")]
    NotApplied(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A HUMAN account, as PocketID returns it.
///
/// ⚠️ Not to be confused with [`OidcClient`]: one is a person, the other an
/// application. Both live in the same service, and that is this API's main source of
/// confusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    /// What PocketID hands apps as `email_verified`. Fluxer refuses a sign-in without it.
    #[serde(default, rename = "emailVerified")]
    pub email_verified: bool,
    #[serde(default, rename = "firstName")]
    pub first_name: String,
    // `null` on the wire for someone who never gave one.
    #[serde(default, rename = "lastName")]
    pub last_name: Option<String>,
    #[serde(default, rename = "displayName")]
    pub display_name: String,
    #[serde(default, rename = "isAdmin")]
    pub is_admin: bool,
    #[serde(default)]
    pub disabled: bool,
}

/// What a person may change about their own identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserChange {
    Names {
        first: String,
        last: String,
        display: String,
    },
    /// The address PocketID gives applications. Always one of the person's own
    /// mailboxes, created by us: it goes in verified.
    Email(String),
}

/// The fields `PUT /api/users/{id}` reads (`UserCreateDto` upstream).
///
/// 🔴 The admin update OVERWRITES every one of them — `isAdmin`, `disabled`, `locale`,
/// `username` included — so a body carrying only the change would demote an
/// administrator and clear their language. Each is copied from what PocketID holds now,
/// and only the change is written over it.
const UPDATED_FIELDS: [&str; 9] = [
    "username",
    "email",
    "emailVerified",
    "firstName",
    "lastName",
    "displayName",
    "isAdmin",
    "locale",
    "disabled",
];

fn update_body(current: &serde_json::Value, change: &UserChange) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    for field in UPDATED_FIELDS {
        body.insert(field.into(), current[field].clone());
    }
    // `lastName` reads back `null` and is written as a string.
    if body["lastName"].is_null() {
        body.insert("lastName".into(), "".into());
    }
    match change {
        UserChange::Names {
            first,
            last,
            display,
        } => {
            body.insert("firstName".into(), first.as_str().into());
            body.insert("lastName".into(), last.as_str().into());
            body.insert("displayName".into(), display.as_str().into());
        }
        UserChange::Email(address) => {
            body.insert("email".into(), address.as_str().into());
            body.insert("emailVerified".into(), true.into());
        }
    }
    serde_json::Value::Object(body)
}

/// The field PocketID kept although it answered success, if any.
fn kept(change: &UserChange, after: &User) -> Option<&'static str> {
    match change {
        UserChange::Names {
            first,
            last,
            display,
        } => {
            if &after.first_name != first {
                Some("first name")
            } else if after.last_name.as_deref().unwrap_or_default() != last {
                Some("last name")
            } else if &after.display_name != display {
                Some("display name")
            } else {
                None
            }
        }
        UserChange::Email(address) => {
            if after.email.as_deref() != Some(address) {
                Some("address")
            } else if !after.email_verified {
                Some("address's verification")
            } else {
                None
            }
        }
    }
}

/// An OIDC client as PocketID describes it - an APPLICATION, not a person.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct OidcClient {
    pub id: String,
    pub name: String,
    #[serde(default, rename = "callbackURLs")]
    pub callback_urls: Vec<String>,
    #[serde(default, rename = "isPublic")]
    pub is_public: bool,
    #[serde(default, rename = "pkceEnabled")]
    pub pkce_enabled: bool,
}

/// What [`PocketId::drop_callback`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackDrop {
    Dropped,
    /// No such client, or it does not accept that URL.
    NotThere,
    /// The client's only URL, left in place.
    OnlyOne,
}

/// Takes `url` out of `known`, unless nothing would be left.
fn without_callback(known: &mut Vec<serde_json::Value>, url: &str) -> CallbackDrop {
    let is_it = |u: &serde_json::Value| u.as_str() == Some(url);
    if !known.iter().any(is_it) {
        CallbackDrop::NotThere
    } else if known.iter().all(is_it) {
        CallbackDrop::OnlyOne
    } else {
        known.retain(|u| !is_it(u));
        CallbackDrop::Dropped
    }
}

#[derive(Debug, Serialize)]
struct CreateRequest<'a> {
    name: &'a str,
    #[serde(rename = "callbackURLs")]
    callback_urls: &'a [String],
    #[serde(rename = "isPublic")]
    is_public: bool,
    #[serde(rename = "pkceEnabled")]
    pkce_enabled: bool,
}

#[derive(Debug, Deserialize)]
struct SecretResponse {
    secret: String,
}

/// What a creation answers: the client, and from v2.15 its first secret.
#[derive(Debug, Deserialize)]
struct Created {
    #[serde(flatten)]
    client: OidcClient,
    #[serde(default, rename = "createdSecret")]
    created_secret: Option<SecretResponse>,
}

/// What provisioning returns: enough to configure the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub client_id: String,
    /// Absent when the client already existed: a secret in service is never regenerated.
    pub client_secret: Option<String>,
}

pub struct PocketId {
    base_url: String,
    api_key: String,
    http: reqwest::Client,
}

impl PocketId {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    async fn send(&self, req: reqwest::RequestBuilder, ctx: &str) -> Result<reqwest::Response> {
        let resp = req
            .header("X-API-KEY", &self.api_key)
            .send()
            .await
            .map_err(|source| Error::Http {
                source,
                context: ctx.to_string(),
            })?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let detail = resp.text().await.unwrap_or_default();
            return Err(Error::Api { status, detail });
        }
        Ok(resp)
    }

    /// Every item a PocketID list answers for `search`, across every page.
    ///
    /// 🔴 One page was read: past it, an existing client or account was "absent", and
    /// a resumed install created a second one. And the term is a query parameter,
    /// encoded — written into the URL, a `&` or `#` in it cut the search short.
    pub(crate) async fn every_page(
        &self,
        path: &str,
        search: Option<&str>,
        what: &str,
    ) -> Result<Vec<serde_json::Value>> {
        // A list that never ends is an error, never a loop.
        const MAX_PAGES: u64 = 1000;
        let mut out = Vec::new();
        for page in 1..=MAX_PAGES {
            let mut query = vec![
                ("pagination[page]", page.to_string()),
                ("pagination[limit]", "100".to_string()),
            ];
            if let Some(s) = search {
                query.push(("search", s.to_string()));
            }
            let resp = self
                .send(self.http.get(self.url(path)).query(&query), what)
                .await?;
            let raw: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| Error::Unexpected(format!("unreadable {what}: {e}")))?;
            // ⚠️ The shape varies with the version: a bare list (all of it), or a
            // `{data, pagination}` page.
            let Some(items) = raw.get("data").and_then(|d| d.as_array()) else {
                out.extend(raw.as_array().cloned().unwrap_or_default());
                return Ok(out);
            };
            out.extend(items.iter().cloned());
            let pages = raw
                .pointer("/pagination/totalPages")
                .and_then(|n| n.as_u64())
                .unwrap_or(1);
            if page >= pages || items.is_empty() {
                return Ok(out);
            }
        }
        Err(Error::Unexpected(format!(
            "{what}: more than {MAX_PAGES} pages"
        )))
    }

    /// The discovery endpoint, to hand to apps.
    pub fn issuer(&self) -> &str {
        &self.base_url
    }

    pub async fn ping(&self) -> Result<usize> {
        Ok(self.list(None).await?.len())
    }

    /// Lists the clients, optionally filtered by name.
    pub async fn list(&self, search: Option<&str>) -> Result<Vec<OidcClient>> {
        self.every_page("/api/oidc/clients", search, "client list")
            .await?
            .into_iter()
            .map(|v| {
                serde_json::from_value(v)
                    .map_err(|e| Error::Unexpected(format!("unreadable list: {e}")))
            })
            .collect()
    }

    /// Finds a client by its exact name.
    ///
    /// `search` does a partial match, so the filtering happens here: otherwise "gitea"
    /// would also match "gitea-runner".
    pub async fn find_by_name(&self, name: &str) -> Result<Option<OidcClient>> {
        Ok(self
            .list(Some(name))
            .await?
            .into_iter()
            .find(|c| c.name == name))
    }

    pub async fn create(
        &self,
        name: &str,
        callback_urls: &[String],
        pkce: bool,
    ) -> Result<OidcClient> {
        Ok(self.create_with_secret(name, callback_urls, pkce).await?.0)
    }

    /// Creates the client, with the secret PocketID made at creation if it made one.
    async fn create_with_secret(
        &self,
        name: &str,
        callback_urls: &[String],
        pkce: bool,
    ) -> Result<(OidcClient, Option<String>)> {
        let body = CreateRequest {
            name,
            callback_urls,
            // A server-side app keeps its secret: it is never "public".
            is_public: false,
            pkce_enabled: pkce,
        };

        let resp = self
            .send(
                self.http.post(self.url("/api/oidc/clients")).json(&body),
                "client creation",
            )
            .await?;

        let c: Created = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable creation response: {e}")))?;
        tracing::info!(client = %c.client.name, id = %c.client.id, "OIDC client created");
        Ok((c.client, c.created_secret.map(|s| s.secret)))
    }

    /// Adds a callback URL to an existing client, keeping everything else it has.
    ///
    /// For the portal: ONE oauth2-proxy signs in for every app behind it, with ONE
    /// client, and each app it protects returns to `/oauth2/callback` on its own
    /// domain — so each app adds its URL to that client rather than getting a client
    /// nobody signs in with.
    ///
    /// ⚠️ The update REPLACES the client with what it is sent: the client is read, the
    /// URL added to what was read, and the whole object sent back — the same lesson as
    /// a user update, where a body carrying only the names demoted an administrator.
    /// Returns whether it was added (`false`: already there).
    pub async fn add_callback_url(&self, client: &str, url: &str) -> Result<bool> {
        let Some(found) = self.find_by_name(client).await? else {
            return Err(Error::Unexpected(format!(
                "no OIDC client \"{client}\" in PocketID"
            )));
        };
        let added = self
            .add_callback_urls(&found.id, &[url.to_string()])
            .await?;
        if added {
            tracing::info!(client, url, "callback URL added");
        }
        Ok(added)
    }

    /// Has the client named `name` accept `urls` too, when it exists: `false` when
    /// none was missing, or there is no such client — never one created, whose secret
    /// PocketID would hand to nobody.
    pub async fn accept_callbacks(&self, name: &str, urls: &[String]) -> Result<bool> {
        match self.find_by_name(name).await? {
            Some(c) => self.add_callback_urls(&c.id, urls).await,
            None => Ok(false),
        }
    }

    /// Has the client named `name` stop accepting `url`, keeping every other field and
    /// URL: the portal's client carries one per app behind it, and an update replaces
    /// what it is sent. Its last URL stays: an empty list is not left for PocketID to
    /// interpret, on the client every app behind the portal signs in with.
    pub async fn drop_callback(&self, name: &str, url: &str) -> Result<CallbackDrop> {
        let Some(found) = self.find_by_name(name).await? else {
            return Ok(CallbackDrop::NotThere);
        };
        let path = format!("/api/oidc/clients/{}", found.id);
        let mut current: serde_json::Value = self
            .send(self.http.get(self.url(&path)), "reading the client")
            .await?
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable client: {e}")))?;
        let known = current
            .get_mut("callbackURLs")
            .and_then(|u| u.as_array_mut())
            .ok_or_else(|| Error::Unexpected("client without callbackURLs".into()))?;
        let done = without_callback(known, url);
        if done == CallbackDrop::Dropped {
            self.send(
                self.http.put(self.url(&path)).json(&current),
                "updating the client",
            )
            .await?;
            tracing::info!(client = name, url, "callback URL removed");
        }
        Ok(done)
    }

    /// Adds to the client `id` those of `urls` it does not accept yet, keeping every
    /// other field — and every other URL: the portal's client carries one per app
    /// behind it. Returns whether any was added.
    async fn add_callback_urls(&self, id: &str, urls: &[String]) -> Result<bool> {
        let path = format!("/api/oidc/clients/{id}");
        let mut current: serde_json::Value = self
            .send(self.http.get(self.url(&path)), "reading the client")
            .await?
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable client: {e}")))?;

        let known = current
            .get_mut("callbackURLs")
            .and_then(|u| u.as_array_mut())
            .ok_or_else(|| Error::Unexpected("client without callbackURLs".into()))?;
        let missing = missing_callbacks(known, urls);
        if missing.is_empty() {
            return Ok(false);
        }
        known.extend(missing.into_iter().map(serde_json::Value::String));

        self.send(
            self.http.put(self.url(&path)).json(&current),
            "updating the client",
        )
        .await?;
        Ok(true)
    }

    /// Creates a HUMAN account in PocketID.
    ///
    /// ⚠️ Not to be confused with [`Self::create`], which registers an *application*.
    /// Both live in the same service and have nothing to do with each other: one says
    /// who may sign in, the other says to what.
    ///
    /// Checked against the upstream code (`UserCreateDto`): `username` is required,
    /// `email` optional but validated, and `userGroupIds` carries the groups.
    pub async fn create_user(
        &self,
        username: &str,
        email: Option<&str>,
        display_name: &str,
        groups: &[String],
    ) -> Result<User> {
        let mut body = serde_json::json!({
            "username": username,
            "displayName": display_name,
            "firstName": display_name,
            // 🔴 Never an administrator by default. An account created in one command
            // must not be able to create others or delete the cluster: elevation is
            // asked for explicitly.
            "isAdmin": false,
            "disabled": false,
            "userGroupIds": groups,
        });

        if let Some(e) = email {
            body["email"] = serde_json::Value::String(e.to_string());
            // ⚠️ The address was just created BY US in Stalwart: it is verified by
            // construction. Leaving it "unverified" would send a confirmation email to a
            // mailbox the person cannot reach yet.
            body["emailVerified"] = serde_json::Value::Bool(true);
        }

        let resp = self
            .send(
                self.http.post(self.url("/api/users")).json(&body),
                "user creation",
            )
            .await?;

        resp.json()
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable user creation response: {e}")))
    }

    /// The account with this name, if it exists.
    ///
    /// 🔴 This is what makes creation **resumable**. Without the lookup, rerunning
    /// `hlb user add` after a failure halfway would produce a duplicate - or an
    /// "already taken" error that blocks the summary instead of allowing it.
    pub async fn find_user(&self, username: &str) -> Result<Option<User>> {
        // Both shapes a version answers are read (`every_page`) rather than freezing the
        // one not verified everywhere - a lookup failing here would recreate a duplicate.
        let items = self
            .every_page("/api/users", Some(username), "user list")
            .await?;

        Ok(items
            .into_iter()
            .filter_map(|v| serde_json::from_value::<User>(v).ok())
            .find(|u| u.username == username))
    }

    /// The person PocketID knows by this id (the OIDC `sub`).
    pub async fn user(&self, id: &str) -> Result<User> {
        self.send(
            self.http.get(self.url(&format!("/api/users/{id}"))),
            "user read",
        )
        .await?
        .json()
        .await
        .map_err(|e| Error::Unexpected(format!("unreadable user: {e}")))
    }

    /// Changes a person's names or address, and nothing else.
    ///
    /// Read, then written whole: see [`UPDATED_FIELDS`]. Two changes racing each other
    /// can lose the first, as with any read-modify-write — acceptable for something a
    /// person edits about themselves, one form at a time.
    pub async fn update_user(&self, id: &str, change: &UserChange) -> Result<User> {
        let url = self.url(&format!("/api/users/{id}"));
        let current: serde_json::Value = self
            .send(self.http.get(&url), "user read")
            .await?
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable user: {e}")))?;

        let after: User = self
            .send(
                self.http.put(&url).json(&update_body(&current, change)),
                "user update",
            )
            .await?
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable user update response: {e}")))?;

        // 🔴 Success is not the change: an LDAP account comes back 200 with every field
        // as it was, and saying "done" would leave the person looking for a name
        // that never moved.
        match kept(change, &after) {
            Some(field) => Err(Error::NotApplied(field)),
            None => Ok(after),
        }
    }

    /// A single-use access token, for sign-up.
    ///
    /// 🔴 This is what replaces an initial password. PocketID authenticates with
    /// passkeys: there is **no** password to hand over, and inventing one would be both
    /// impossible and less safe.
    ///
    /// ⚠️ The token is single-use and expires. Writing it to a log or passing it as a
    /// command argument would amount to publishing a session: it is displayed once, on
    /// standard output, and never recorded.
    pub async fn one_time_token(&self, user_id: &str, ttl: &str) -> Result<String> {
        let resp = self
            .send(
                self.http
                    .post(self.url(&format!("/api/users/{user_id}/one-time-access-token")))
                    .json(&one_time_body(user_id, ttl)),
                "registration token",
            )
            .await?;

        let rep: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable token: {e}")))?;

        rep.get("token")
            .and_then(|t| t.as_str())
            .map(str::to_string)
            .ok_or_else(|| Error::Api {
                status: 200,
                detail: "no token in the response - the person could not \
                         register, and the account would stay unusable"
                    .into(),
            })
    }

    /// ⚠️ Generates a **new** secret. Before v2.15 it invalidates the old one; from
    /// v2.15 the old one stays active beside it.
    ///
    /// 🔴 v2.15 renamed the route (`/secrets`) inside the `v2` tag: an install frozen on
    /// an earlier v2, or on v1, still answers only the old one — a 404 here is that, and
    /// the old route is tried.
    pub async fn regenerate_secret(&self, id: &str) -> Result<String> {
        let current = self
            .send(
                self.http
                    .post(self.url(&format!("/api/oidc/clients/{id}/secrets"))),
                "secret generation",
            )
            .await;
        let resp = match current {
            Err(Error::Api { status: 404, .. }) => {
                self.send(
                    self.http
                        .post(self.url(&format!("/api/oidc/clients/{id}/secret"))),
                    "secret generation",
                )
                .await?
            }
            other => other?,
        };

        let s: SecretResponse = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable secret: {e}")))?;
        Ok(s.secret)
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        self.send(
            self.http
                .delete(self.url(&format!("/api/oidc/clients/{id}"))),
            "deleting the client",
        )
        .await?;
        tracing::info!(id, "OIDC client deleted");
        Ok(())
    }

    /// Idempotent provisioning: creates the client if missing, touches nothing
    /// otherwise.
    ///
    /// 🔴 **Never regenerates the secret of an existing client.** Each call to
    /// `/secret` produces a new one and invalidates the previous - the one already
    /// injected into the running app. Rerunning an install would therefore break the
    /// SSO of the app you thought you were merely re-checking.
    pub async fn ensure(
        &self,
        name: &str,
        callback_urls: &[String],
        pkce: bool,
    ) -> Result<Credentials> {
        if let Some(existing) = self.find_by_name(name).await? {
            tracing::debug!(client = name, "OIDC client already present, kept");
            // 🔴 Kept as it was, a client made for another domain — or before the
            // manifest named one more path — refused the app's redirect at every
            // sign-in. The computed callbacks are added; none is taken away, since the
            // portal's client carries the apps' own beside its own.
            let known: Vec<serde_json::Value> = existing
                .callback_urls
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect();
            if !missing_callbacks(&known, callback_urls).is_empty()
                && self.add_callback_urls(&existing.id, callback_urls).await?
            {
                tracing::info!(client = name, "callback URLs brought to the domain's");
            }
            return Ok(Credentials {
                client_id: existing.id,
                client_secret: None,
            });
        }

        let (created, secret) = self.create_with_secret(name, callback_urls, pkce).await?;
        // Asked for only when the creation did not give one: from v2.15 a second
        // call would leave an active secret nobody holds.
        let secret = match secret {
            Some(s) => s,
            None => self.regenerate_secret(&created.id).await?,
        };
        Ok(Credentials {
            client_id: created.id,
            client_secret: Some(secret),
        })
    }
}

/// Those of `wanted` a client's `callbackURLs` does not hold yet, in their order.
fn missing_callbacks(known: &[serde_json::Value], wanted: &[String]) -> Vec<String> {
    wanted
        .iter()
        .filter(|w| !known.iter().any(|k| k.as_str() == Some(w.as_str())))
        .cloned()
        .collect()
}

/// The body of a one-time token request.
///
/// 🔴 PocketID 1.16 reads the person from `userId` in the BODY and ignores the id in
/// the path: sent the path alone, it inserted a token for nobody and answered 500 on a
/// foreign key — every enrolment link, from `hlb user add` to an invitation's sign-up,
/// failed against a real server, while a stub answered whatever it was given.
fn one_time_body(user_id: &str, ttl: &str) -> serde_json::Value {
    serde_json::json!({ "userId": user_id, "ttl": ttl })
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_callback_goes_alone_and_never_the_last_one() {
        let portal = || {
            vec![
                serde_json::json!("https://auth.example.test/oauth2/callback"),
                serde_json::json!("https://wiki.example.test/oauth2/callback"),
            ]
        };
        let wiki = "https://wiki.example.test/oauth2/callback";

        let mut known = portal();
        assert_eq!(
            super::without_callback(&mut known, wiki),
            super::CallbackDrop::Dropped
        );
        assert_eq!(
            known,
            vec![serde_json::json!(
                "https://auth.example.test/oauth2/callback"
            )]
        );

        let mut known = portal();
        assert_eq!(
            super::without_callback(&mut known, "https://other.example.test/x"),
            super::CallbackDrop::NotThere
        );
        assert_eq!(known, portal());

        let mut only = vec![serde_json::json!(wiki)];
        assert_eq!(
            super::without_callback(&mut only, wiki),
            super::CallbackDrop::OnlyOne
        );
        assert_eq!(only.len(), 1);
    }

    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn a_one_time_token_names_its_person_in_the_body() {
        let b = one_time_body("u-1", "12h");
        assert_eq!(b["userId"], "u-1", "{b}");
        assert_eq!(b["ttl"], "12h", "{b}");
    }

    #[test]
    fn an_existing_client_is_given_the_callbacks_it_lacks_and_keeps_its_others() {
        let known = vec![
            serde_json::json!("https://old.example.org/cb"),
            serde_json::json!("https://tasks.example.org/oauth2/callback"),
        ];
        let wanted = vec![
            "https://tasks.example.org/oauth2/callback".to_string(),
            "https://new.example.org/cb".to_string(),
        ];
        assert_eq!(
            missing_callbacks(&known, &wanted),
            vec!["https://new.example.org/cb".to_string()]
        );
        assert!(missing_callbacks(&known, &wanted[..1]).is_empty());
    }

    #[test]
    fn the_base_url_is_normalised() {
        let p = PocketId::new("https://id.example.fr/", "k");
        assert_eq!(p.issuer(), "https://id.example.fr");
        assert_eq!(
            p.url("/api/oidc/clients"),
            "https://id.example.fr/api/oidc/clients"
        );
    }

    #[test]
    fn clients_deserialize_from_the_real_shape() {
        // Captured from a real instance.
        let json = r#"{"id":"88e0-c62d","name":"vikunja","hasLogo":false,
                       "callbackURLs":["https://tasks.example.fr/auth/openid/pocketid"],
                       "logoutCallbackURLs":[],"isPublic":false,"pkceEnabled":true,
                       "credentials":{},"allowedUserGroups":[]}"#;
        let c: OidcClient = serde_json::from_str(json).expect("analysable");
        assert_eq!(c.name, "vikunja");
        assert_eq!(c.callback_urls.len(), 1);
        assert!(c.pkce_enabled);
        assert!(!c.is_public);
    }

    #[test]
    fn a_creation_carries_its_secret_from_v2_15() {
        // Captured from 2.18: the secret made at creation, which no later call returns.
        let json = r#"{"id":"c-1","name":"gitea","callbackURLs":[],"isPublic":false,
                       "pkceEnabled":true,"credentials":{"secrets":[]},
                       "createdSecret":{"id":"s-1","prefix":"abc","createdAt":"x",
                                        "expiresAt":null,"isActive":true,
                                        "secret":"abcdefghijklmnop"}}"#;
        let c: Created = serde_json::from_str(json).expect("analysable");
        assert_eq!(c.client.name, "gitea");
        assert_eq!(c.created_secret.expect("secret").secret, "abcdefghijklmnop");

        // Before 2.15, no secret at creation.
        let old: Created =
            serde_json::from_str(r#"{"id":"c-1","name":"gitea"}"#).expect("analysable");
        assert!(old.created_secret.is_none());
    }

    /// A PocketID listing `names` as clients and users, two to a page whatever is
    /// asked, filtering on `search` partially as PocketID does; the queries it was sent.
    async fn listing(names: &'static [&'static str]) -> (PocketId, Arc<Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = l.local_addr().expect("addr");
        let asked = Arc::new(Mutex::new(Vec::new()));
        let seen = asked.clone();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                let mut buf = [0u8; 4096];
                let n = c.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let target = head.split_whitespace().nth(1).unwrap_or("").to_string();
                seen.lock().expect("asked").push(target.clone());
                let query = target.split_once('?').map_or("", |(_, q)| q).to_string();
                let param = |k: &str| {
                    query.split('&').find_map(|kv| {
                        let (a, b) = kv.split_once('=')?;
                        (a == k).then(|| b.to_string())
                    })
                };
                let page: usize = param("pagination%5Bpage%5D")
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(1);
                let search = param("search").unwrap_or_default();
                let found: Vec<&str> = names
                    .iter()
                    .copied()
                    .filter(|n| n.contains(search.as_str()))
                    .collect();
                let pages = found.len().div_ceil(2).max(1);
                let data: Vec<serde_json::Value> = found
                    .iter()
                    .skip((page - 1) * 2)
                    .take(2)
                    .map(|n| {
                        serde_json::json!({ "id": format!("id-{n}"), "name": n,
                        "username": n })
                    })
                    .collect();
                let body = serde_json::json!({ "data": data,
                    "pagination": { "totalPages": pages, "currentPage": page } })
                .to_string();
                let _ = c
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            }
        });
        (PocketId::new(format!("http://{addr}"), "k"), asked)
    }

    #[tokio::test]
    async fn a_lookup_reads_every_page_and_sends_its_term_encoded() {
        // 🔴 One page was read: a client past it was "absent", and a resumed install
        // made a second one.
        let (p, asked) = listing(&["gitea-a", "gitea-b", "gitea-c", "gitea", "a&b"]).await;
        let found = p.find_by_name("gitea").await.expect("lookup");
        assert_eq!(found.expect("on the second page").id, "id-gitea");
        assert_eq!(p.list(None).await.expect("list").len(), 5);
        assert!(p.find_user("gitea").await.expect("user").is_some());

        // `a&b` written into the URL searched for `a` and sent `b=` as a parameter.
        asked.lock().expect("asked").clear();
        p.find_user("a&b").await.expect("user");
        let sent = asked.lock().expect("asked").join(" ");
        assert!(sent.contains("search=a%26b"), "{sent}");
    }

    #[test]
    fn the_creation_body_uses_the_expected_field_names() {
        // The names are camelCase on the PocketID side: a typo here would pass
        // silently, the field simply being ignored.
        let urls = vec!["https://x.fr/cb".to_string()];
        let body = CreateRequest {
            name: "gitea",
            callback_urls: &urls,
            is_public: false,
            pkce_enabled: true,
        };
        let j = serde_json::to_value(&body).expect("serialisable");
        assert!(j.get("callbackURLs").is_some(), "{j}");
        assert!(j.get("isPublic").is_some());
        assert!(j.get("pkceEnabled").is_some());
    }

    /// A user as `GET /api/users/{id}` returns it (`UserDto` upstream).
    fn administrator() -> serde_json::Value {
        serde_json::json!({
            "id": "4f1c", "username": "lena", "email": "lena@home.example",
            "emailVerified": true, "firstName": "Léna", "lastName": null,
            "displayName": "Léna", "isAdmin": true, "locale": "fr",
            "customClaims": [], "userGroups": [{"id": "g1", "name": "family"}],
            "ldapId": null, "disabled": false
        })
    }

    #[test]
    fn a_name_change_keeps_everything_the_update_would_overwrite() {
        // 🔴 The admin update writes every field it is sent, and the empty ones too: a
        // body carrying only the names would demote an administrator and reset their
        // language, for a change of spelling.
        let change = UserChange::Names {
            first: "Léna".into(),
            last: "Martin".into(),
            display: "Léna M.".into(),
        };
        let body = update_body(&administrator(), &change);

        assert_eq!(body["isAdmin"], true);
        assert_eq!(body["locale"], "fr");
        assert_eq!(body["username"], "lena");
        assert_eq!(body["email"], "lena@home.example");
        assert_eq!(body["emailVerified"], true);
        assert_eq!(body["disabled"], false);
        assert_eq!(body["lastName"], "Martin");
        assert_eq!(body["displayName"], "Léna M.");
        // Read-only on the way back, and groups have a route of their own.
        assert!(body.get("userGroups").is_none(), "{body}");
        assert!(body.get("id").is_none(), "{body}");
    }

    #[test]
    fn a_last_name_never_given_is_written_back_as_text() {
        let body = update_body(
            &administrator(),
            &UserChange::Email("contact@home.example".into()),
        );
        assert_eq!(body["lastName"], "");
        assert_eq!(body["email"], "contact@home.example");
        assert_eq!(body["firstName"], "Léna");
    }

    #[test]
    fn a_change_answered_with_the_old_value_is_not_applied() {
        // PocketID's answer for an LDAP account: 200, and nothing moved.
        let unchanged: User = serde_json::from_value(administrator()).expect("user");
        let change = UserChange::Names {
            first: "Léna".into(),
            last: String::new(),
            display: "Léna M.".into(),
        };
        assert_eq!(kept(&change, &unchanged), Some("display name"));
        assert_eq!(
            kept(
                &UserChange::Email("contact@home.example".into()),
                &unchanged
            ),
            Some("address")
        );

        let unverified = User {
            email_verified: false,
            ..unchanged.clone()
        };
        assert_eq!(
            kept(&UserChange::Email("lena@home.example".into()), &unverified),
            Some("address's verification"),
            "an address is written verified, or it is not written as asked"
        );

        let renamed = User {
            display_name: "Léna M.".into(),
            ..unchanged
        };
        assert_eq!(kept(&change, &renamed), None);
    }

    #[test]
    fn credentials_say_when_the_secret_is_unavailable() {
        let c = Credentials {
            client_id: "abc".into(),
            client_secret: None,
        };
        assert!(c.client_secret.is_none(), "existing client: no new secret");
    }
}
