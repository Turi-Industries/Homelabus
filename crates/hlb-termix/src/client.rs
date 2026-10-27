//! Termix's API, as Homelabus uses it.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Error, Result};

/// An account, as `/users/list` and `/users/me` describe it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct User {
    #[serde(rename = "userId")]
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub is_admin: bool,
    /// Signed in through a provider (PocketID) rather than made in Termix.
    #[serde(default)]
    pub is_external: bool,
}

/// An API key, as listed: never its token.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKey {
    pub id: String,
    pub name: String,
    pub user_id: String,
    /// The token's first twelve characters, which is how a token finds its key.
    pub token_prefix: String,
}

/// How a token finds its key in Termix: by its first twelve characters.
pub fn token_prefix(token: &str) -> String {
    token.chars().take(12).collect()
}

/// A stored credential: the public half only ever comes back.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub username: Option<String>,
    /// `ssh-ed25519 AAAA…`, without a comment.
    #[serde(default)]
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub is_system: bool,
}

/// A host as Termix stores it — what Homelabus writes and compares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    #[serde(default, skip_serializing)]
    pub id: i64,
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub username: String,
    #[serde(default)]
    pub credential_id: Option<i64>,
    /// Members of a role it is shared with connect with the owner's credential. 🔴
    /// Without it, Termix keeps the key to the owner and each member must bring one.
    #[serde(default)]
    pub share_ssh_auth: bool,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

/// One grant of a host's access.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Access {
    pub id: i64,
    #[serde(default)]
    pub role_id: Option<i64>,
    #[serde(default)]
    pub permission_level: String,
}

pub struct Termix {
    base_url: String,
    token: String,
    http: reqwest::Client,
}

impl Termix {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .unwrap_or_default(),
        }
    }

    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let mut req = self
            .http
            .request(method.clone(), format!("{}{path}", self.base_url))
            .bearer_auth(&self.token);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|source| Error::Http {
            source,
            context: format!("{method} {path}"),
        })?;
        let status = resp.status();
        let text = match bounded(resp, MAX_BODY).await {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => return Err(Error::Unexpected(format!("{method} {path}: {e}"))),
        };
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized);
        }
        if !status.is_success() {
            // Termix's errors are `{"error": "…"}`; the body is never echoed whole —
            // a key Homelabus sent could be in it.
            let detail = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v["error"].as_str().map(str::to_string))
                .unwrap_or_default();
            return Err(Error::Api {
                status: status.as_u16(),
                call: format!("{method} {path}"),
                detail,
            });
        }
        if text.is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_str(&text).map_err(|e| Error::Unexpected(format!("{method} {path}: {e}")))
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let v = self.send(reqwest::Method::GET, path, None).await?;
        serde_json::from_value(v).map_err(|e| Error::Unexpected(format!("GET {path}: {e}")))
    }

    /// Whom the token signs in as.
    pub async fn me(&self) -> Result<User> {
        self.get("/users/me").await
    }

    pub async fn users(&self) -> Result<Vec<User>> {
        #[derive(Deserialize)]
        struct Page {
            users: Vec<User>,
        }
        Ok(self.get::<Page>("/users/list").await?.users)
    }

    /// A local account. Termix asks for a password; nobody signs in with it — password
    /// sign-in is closed — so the caller draws one and keeps none.
    pub async fn create_user(&self, username: &str, password: &str) -> Result<()> {
        self.send(
            reqwest::Method::POST,
            "/users/admin-create",
            Some(json!({ "username": username, "password": password })),
        )
        .await
        .map(drop)
    }

    pub async fn make_admin(&self, user_id: &str) -> Result<()> {
        self.send(
            reqwest::Method::POST,
            "/users/make-admin",
            Some(json!({ "userId": user_id })),
        )
        .await
        .map(drop)
    }

    pub async fn api_keys(&self) -> Result<Vec<ApiKey>> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Page {
            api_keys: Vec<ApiKey>,
        }
        Ok(self.get::<Page>("/users/api-keys").await?.api_keys)
    }

    /// A key that never expires, for `user_id`. Its token is answered once.
    pub async fn create_api_key(&self, name: &str, user_id: &str) -> Result<(ApiKey, String)> {
        let v = self
            .send(
                reqwest::Method::POST,
                "/users/api-keys",
                Some(json!({ "name": name, "userId": user_id })),
            )
            .await?;
        let token = v["token"]
            .as_str()
            .ok_or_else(|| Error::Unexpected("a new API key came back without its token".into()))?
            .to_string();
        let key = serde_json::from_value(v)
            .map_err(|e| Error::Unexpected(format!("POST /users/api-keys: {e}")))?;
        Ok((key, token))
    }

    pub async fn delete_api_key(&self, id: &str) -> Result<()> {
        self.send(
            reqwest::Method::DELETE,
            &format!("/users/api-keys/{id}"),
            None,
        )
        .await
        .map(drop)
    }

    /// The token's own credentials, and those shared with its account.
    pub async fn credentials(&self) -> Result<Vec<Credential>> {
        self.get("/credentials").await
    }

    fn credential_body(name: &str, username: &str, private_key: &str) -> serde_json::Value {
        json!({
            "name": name,
            "description": "Kept by Homelabus: replaced at every rotation (`hlb termix rotate`).",
            "folder": "Homelabus",
            "tags": ["homelabus"],
            "authType": "key",
            "username": username,
            "key": private_key,
            "keyType": "ssh-ed25519",
        })
    }

    pub async fn create_credential(
        &self,
        name: &str,
        username: &str,
        private_key: &str,
    ) -> Result<Credential> {
        let v = self
            .send(
                reqwest::Method::POST,
                "/credentials",
                Some(Self::credential_body(name, username, private_key)),
            )
            .await?;
        serde_json::from_value(v).map_err(|e| Error::Unexpected(format!("POST /credentials: {e}")))
    }

    /// Replaces the key. Termix refreshes what every share of a host using it holds.
    pub async fn update_credential(
        &self,
        id: i64,
        name: &str,
        username: &str,
        private_key: &str,
    ) -> Result<()> {
        self.send(
            reqwest::Method::PUT,
            &format!("/credentials/{id}"),
            Some(Self::credential_body(name, username, private_key)),
        )
        .await
        .map(drop)
    }

    pub async fn roles(&self) -> Result<Vec<Role>> {
        #[derive(Deserialize)]
        struct Page {
            roles: Vec<Role>,
        }
        Ok(self.get::<Page>("/rbac/roles").await?.roles)
    }

    pub async fn create_role(&self, name: &str, display: &str, description: &str) -> Result<()> {
        self.send(
            reqwest::Method::POST,
            "/rbac/roles",
            Some(json!({ "name": name, "displayName": display, "description": description })),
        )
        .await
        .map(drop)
    }

    /// The token's own hosts.
    pub async fn hosts(&self) -> Result<Vec<Host>> {
        self.get("/host/db/host").await
    }

    fn host_body(h: &Host) -> serde_json::Value {
        let mut v = serde_json::to_value(h).unwrap_or_default();
        v["authType"] = "credential".into();
        v
    }

    pub async fn create_host(&self, h: &Host) -> Result<Host> {
        let v = self
            .send(
                reqwest::Method::POST,
                "/host/db/host",
                Some(Self::host_body(h)),
            )
            .await?;
        serde_json::from_value(v).map_err(|e| Error::Unexpected(format!("POST /host/db/host: {e}")))
    }

    pub async fn update_host(&self, id: i64, h: &Host) -> Result<()> {
        self.send(
            reqwest::Method::PUT,
            &format!("/host/db/host/{id}"),
            Some(Self::host_body(h)),
        )
        .await
        .map(drop)
    }

    pub async fn delete_host(&self, id: i64) -> Result<()> {
        self.send(
            reqwest::Method::DELETE,
            &format!("/host/db/host/{id}"),
            None,
        )
        .await
        .map(drop)
    }

    pub async fn host_access(&self, host: i64) -> Result<Vec<Access>> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Page {
            access_list: Vec<Access>,
        }
        Ok(self
            .get::<Page>(&format!("/rbac/host/{host}/access"))
            .await?
            .access_list)
    }

    /// Lets a role's members open the host, with its credential and nothing more: not
    /// edit it, not share it on.
    pub async fn share_host(&self, host: i64, role: i64) -> Result<()> {
        self.send(
            reqwest::Method::POST,
            &format!("/rbac/host/{host}/share"),
            Some(json!({
                "targets": [{ "type": "role", "id": role }],
                "permissionLevel": "connect",
            })),
        )
        .await
        .map(drop)
    }
}

/// The most a Termix answer is read to: a host list is kilobytes.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// A response's body, read to `max` bytes and no further.
///
/// 🔴 `json()` and `text()` read whatever comes: a server answering without end — or
/// whatever sits on the path to it — filled the memory of the process reading it.
async fn bounded(mut resp: reqwest::Response, max: usize) -> std::result::Result<Vec<u8>, String> {
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
