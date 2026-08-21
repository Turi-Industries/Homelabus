//! PocketID API client.
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
//! | Get the secret | `POST /api/oidc/clients/{id}/secret` |
//! | Delete | `DELETE /api/oidc/clients/{id}` |
//!
//! Authentication through the `X-API-KEY` header.
//!
//! ⚠️ **The secret is not returned at creation**: it takes a second call, and each call
//! **regenerates a new one**, invalidating the previous. Hence [`OidcClient::ensure`],
//! which never regenerates it for an existing client.

pub mod oidc;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("PocketID injoignable ({context}) : {source}")]
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
    #[serde(default, rename = "displayName")]
    pub display_name: String,
    #[serde(default, rename = "isAdmin")]
    pub is_admin: bool,
    #[serde(default)]
    pub disabled: bool,
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
struct Page<T> {
    data: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct SecretResponse {
    secret: String,
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

    /// The discovery endpoint, to hand to apps.
    pub fn issuer(&self) -> &str {
        &self.base_url
    }

    pub async fn ping(&self) -> Result<usize> {
        Ok(self.list(None).await?.len())
    }

    /// Lists the clients, optionally filtered by name.
    pub async fn list(&self, search: Option<&str>) -> Result<Vec<OidcClient>> {
        let mut url = self.url("/api/oidc/clients");
        if let Some(s) = search {
            url = format!("{url}?search={s}");
        }
        let resp = self.send(self.http.get(&url), "liste des clients").await?;
        let page: Page<OidcClient> = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("liste illisible : {e}")))?;
        Ok(page.data)
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
        let body = CreateRequest {
            name,
            callback_urls,
            // Une app serveur garde son secret : elle n'est jamais « publique ».
            is_public: false,
            pkce_enabled: pkce,
        };

        let resp = self
            .send(
                self.http.post(self.url("/api/oidc/clients")).json(&body),
                "client creation",
            )
            .await?;

        let c: OidcClient = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable creation response: {e}")))?;
        tracing::info!(client = %c.name, id = %c.id, "OIDC client created");
        Ok(c)
    }

    /// ⚠️ Generates a **new** secret and invalidates the old one.
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
        let mut corps = serde_json::json!({
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
            corps["email"] = serde_json::Value::String(e.to_string());
            // ⚠️ The address was just created BY US in Stalwart: it is verified by
            // construction. Leaving it "unverified" would send a confirmation email to a
            // mailbox the person cannot reach yet.
            corps["emailVerified"] = serde_json::Value::Bool(true);
        }

        let resp = self
            .send(
                self.http.post(self.url("/api/users")).json(&corps),
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
    /// "already taken" error that blocks the resume instead of allowing it.
    pub async fn find_user(&self, username: &str) -> Result<Option<User>> {
        let resp = self
            .send(
                self.http
                    .get(self.url(&format!("/api/users?search={username}"))),
                "recherche d'utilisateur",
            )
            .await?;

        let brut: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("liste d'utilisateurs illisible : {e}")))?;

        // ⚠️ The shape varies with the version: a bare list, or a `{data: [...]}` page.
        // Both are accepted rather than freezing the one not verified everywhere - a
        // resume failing here would recreate a duplicate.
        let items = brut
            .get("data")
            .and_then(|d| d.as_array())
            .or_else(|| brut.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(items
            .into_iter()
            .filter_map(|v| serde_json::from_value::<User>(v).ok())
            .find(|u| u.username == username))
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
                    .json(&serde_json::json!({ "ttl": ttl })),
                "jeton d'inscription",
            )
            .await?;

        let rep: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("jeton illisible : {e}")))?;

        rep.get("token")
            .and_then(|t| t.as_str())
            .map(str::to_string)
            .ok_or_else(|| Error::Api {
                status: 200,
                detail: "no token in the response - the person could not \
                         s'inscrire, et le compte resterait inutilisable"
                    .into(),
            })
    }

    pub async fn regenerate_secret(&self, id: &str) -> Result<String> {
        let resp = self
            .send(
                self.http
                    .post(self.url(&format!("/api/oidc/clients/{id}/secret"))),
                "secret generation",
            )
            .await?;

        let s: SecretResponse = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("secret illisible : {e}")))?;
        Ok(s.secret)
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        self.send(
            self.http
                .delete(self.url(&format!("/api/oidc/clients/{id}"))),
            "suppression du client",
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
            return Ok(Credentials {
                client_id: existing.id,
                client_secret: None,
            });
        }

        let created = self.create(name, callback_urls, pkce).await?;
        let secret = self.regenerate_secret(&created.id).await?;
        Ok(Credentials {
            client_id: created.id,
            client_secret: Some(secret),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn a_page_unwraps_to_its_data() {
        let json = r#"{"data":[{"id":"a","name":"gitea"}],
                       "pagination":{"totalPages":1,"totalItems":1}}"#;
        let p: Page<OidcClient> = serde_json::from_str(json).expect("analysable");
        assert_eq!(p.data.len(), 1);
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

    #[test]
    fn credentials_say_when_the_secret_is_unavailable() {
        let c = Credentials {
            client_id: "abc".into(),
            client_secret: None,
        };
        assert!(
            c.client_secret.is_none(),
            "client existant : pas de nouveau secret"
        );
    }
}
