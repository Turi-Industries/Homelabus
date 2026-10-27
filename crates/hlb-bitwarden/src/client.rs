//! The routes an official client calls, as Vaultwarden 1.37.1 answers them
//! (`src/api/identity.rs`, `src/api/core/`).

use serde_json::Value;

use crate::crypto::{Kdf, KeyPair, MasterKey, SymmetricKey};
use crate::{Error, Result};

/// What every sign-in presents as its device. One identifier that never changes: a new
/// one at each sign-in would mail the account "new device signed in" every night.
const DEVICE_ID: &str = "homelabus-emergency-vault";
const DEVICE_NAME: &str = "homelabus";
/// Bitwarden's `LinuxCLI`.
const DEVICE_TYPE: &str = "25";

/// A Vaultwarden server.
#[derive(Clone)]
pub struct Server {
    base: String,
    http: reqwest::Client,
}

/// How a password sign-in ended.
pub enum SignIn {
    Done(Session),
    /// The account has a second factor and none was given.
    SecondFactor,
}

/// A signed-in account: its bearer token, and what it needs to unlock.
#[derive(Clone)]
pub struct Session {
    server: Server,
    token: String,
    /// The account's key, encrypted under its stretched master key.
    key: Option<String>,
    /// Its private key, encrypted under its key.
    private_key: Option<String>,
    kdf: Option<Kdf>,
}

/// An account's keys, unwrapped by its master password.
pub struct Unlocked {
    pub key: SymmetricKey,
    pub pair: KeyPair,
}

impl Server {
    pub fn new(base_url: &str) -> Self {
        Self {
            base: base_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// The account's key derivation — needed before its password can be hashed.
    pub async fn prelogin(&self, email: &str) -> Result<Kdf> {
        let v = self
            .send(
                self.http
                    .post(self.url("/identity/accounts/prelogin"))
                    .json(&serde_json::json!({ "email": email })),
                "key derivation",
            )
            .await?;
        kdf_of(&v, "kdf")
    }

    /// A sign-in with the master password's hash, and a TOTP code when the account has
    /// that second factor.
    ///
    /// ⚠️ An account WITHOUT a second factor, signing in by password, is removed from
    /// every organisation requiring two-step login whose member it is — confirmed,
    /// not owner nor admin (`twofactor_auth` → `enforce_2fa_policy`). Until its own
    /// factor is set, it signs in before an owner confirms it, never after.
    pub async fn sign_in(&self, email: &str, hash: &str, totp: Option<&str>) -> Result<SignIn> {
        let mut form = vec![
            ("grant_type", "password"),
            ("username", email),
            ("password", hash),
            ("scope", "api offline_access"),
            ("client_id", "cli"),
            ("deviceType", DEVICE_TYPE),
            ("deviceIdentifier", DEVICE_ID),
            ("deviceName", DEVICE_NAME),
        ];
        if let Some(code) = totp {
            form.extend([
                ("twoFactorToken", code),
                ("twoFactorProvider", "0"),
                ("twoFactorRemember", "0"),
            ]);
        }
        let resp = self
            .http
            .post(self.url("/identity/connect/token"))
            .form(&form)
            .send()
            .await
            .map_err(|source| Error::Http {
                source,
                context: "sign-in".into(),
            })?;
        let status = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(SignIn::Done(self.session(&v)?));
        }
        if v.get("TwoFactorProviders").is_some_and(|p| !p.is_null()) {
            return Ok(SignIn::SecondFactor);
        }
        // The body says which of the address or the password was wrong, at most:
        // never the values.
        Err(Error::Refused(format!(
            "Vaultwarden refused the sign-in of {email} ({}): {}",
            status.as_u16(),
            v["error_description"]
                .as_str()
                .or(v["message"].as_str())
                .unwrap_or("no reason given")
        )))
    }

    /// A sign-in with the account's API key: no second factor is asked — the key is
    /// one, and it unlocks nothing without the master password.
    pub async fn sign_in_with_key(&self, client_id: &str, secret: &str) -> Result<Session> {
        let resp = self
            .http
            .post(self.url("/identity/connect/token"))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", secret),
                ("scope", "api"),
                ("deviceType", DEVICE_TYPE),
                ("deviceIdentifier", DEVICE_ID),
                ("deviceName", DEVICE_NAME),
            ])
            .send()
            .await
            .map_err(|source| Error::Http {
                source,
                context: "sign-in by API key".into(),
            })?;
        let status = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            return Err(Error::Refused(format!(
                "Vaultwarden refused the emergency vault's API key ({}) — its account's key \
                 was changed or the account removed",
                status.as_u16()
            )));
        }
        self.session(&v)
    }

    fn session(&self, v: &Value) -> Result<Session> {
        let token = v["access_token"]
            .as_str()
            .ok_or_else(|| Error::Unexpected("no access_token".into()))?
            .to_string();
        let kdf = match v.get("Kdf").and_then(Value::as_i64) {
            Some(_) => Some(kdf_of(v, "Kdf")?),
            None => None,
        };
        Ok(Session {
            server: self.clone(),
            token,
            key: v["Key"].as_str().map(str::to_string),
            private_key: v["PrivateKey"].as_str().map(str::to_string),
            kdf,
        })
    }

    async fn send(&self, req: reqwest::RequestBuilder, context: &str) -> Result<Value> {
        let resp = req.send().await.map_err(|source| Error::Http {
            source,
            context: context.into(),
        })?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            // Vaultwarden's errors are `{"message": …}`; a body is never echoed whole,
            // a request carrying a secret can be answered with it.
            let detail = serde_json::from_str::<Value>(&body)
                .ok()
                .and_then(|v| v["message"].as_str().map(str::to_string))
                .unwrap_or_else(|| format!("{context} refused"));
            return Err(Error::Api {
                status: status.as_u16(),
                detail,
            });
        }
        let text = resp.text().await.map_err(|source| Error::Http {
            source,
            context: context.into(),
        })?;
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|e| Error::Unexpected(format!("{context}: {e}")))
    }
}

fn kdf_of(v: &Value, prefix: &str) -> Result<Kdf> {
    // The prelogin answers `kdf`, `kdfIterations`…; the token `Kdf`, `KdfIterations`…
    let field = |suffix: &str| v.get(format!("{prefix}{suffix}")).and_then(Value::as_i64);
    Kdf::from_server(
        field("").ok_or_else(|| Error::Unexpected("no key derivation".into()))?,
        field("Iterations").ok_or_else(|| Error::Unexpected("no iteration count".into()))?,
        field("Memory"),
        field("Parallelism"),
    )
}

impl Session {
    /// Unwraps the account's keys with its master password.
    pub fn unlock(&self, email: &str, password: &str) -> Result<Unlocked> {
        let (Some(key), Some(private), Some(kdf)) = (&self.key, &self.private_key, self.kdf) else {
            return Err(Error::Unexpected(
                "the sign-in carried no keys — the account has no master password".into(),
            ));
        };
        let stretched = MasterKey::derive(password, email, kdf)?.stretch()?;
        let key = SymmetricKey::from_bytes(&stretched.decrypt(key).map_err(|_| {
            Error::Refused(
                "the master password does not unlock the account — it was changed in the \
                 web vault; store it again"
                    .into(),
            )
        })?)?;
        let pair = KeyPair::unwrap(private, &key)?;
        Ok(Unlocked { key, pair })
    }

    async fn call(&self, req: reqwest::RequestBuilder, context: &str) -> Result<Value> {
        self.server
            .send(req.bearer_auth(&self.token), context)
            .await
    }

    fn http(&self) -> &reqwest::Client {
        &self.server.http
    }

    /// The account's id — its API key's client id is `user.<id>`.
    pub async fn account_id(&self) -> Result<String> {
        let v = self
            .call(
                self.http().get(self.server.url("/api/accounts/profile")),
                "profile",
            )
            .await?;
        v["id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Error::Unexpected("a profile without an id".into()))
    }

    /// Turns on the authenticator factor with this secret — the current code proves it.
    pub async fn enable_totp(&self, password_hash: &str, secret: &str, code: &str) -> Result<()> {
        self.call(
            self.http()
                .post(self.server.url("/api/two-factor/authenticator"))
                .json(&serde_json::json!({
                    "key": secret, "token": code, "masterPasswordHash": password_hash,
                })),
            "turning on the second factor",
        )
        .await
        .map(drop)
    }

    /// The account's API key, made on the first call and the same afterwards.
    pub async fn api_key(&self, password_hash: &str) -> Result<String> {
        let v = self
            .call(
                self.http()
                    .post(self.server.url("/api/accounts/api-key"))
                    .json(&serde_json::json!({ "masterPasswordHash": password_hash })),
                "API key",
            )
            .await?;
        v["apiKey"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Error::Unexpected("no apiKey in the answer".into()))
    }

    /// Everything the account sees: its organisations, collections, policies, items.
    pub async fn sync(&self) -> Result<Value> {
        self.call(
            self.http()
                .get(self.server.url("/api/sync?excludeDomains=true")),
            "sync",
        )
        .await
    }

    /// A new item in an organisation's collections.
    pub async fn create(&self, cipher: &Value, collections: &[String]) -> Result<String> {
        let v = self
            .call(
                self.http()
                    .post(self.server.url("/api/ciphers/create"))
                    .json(&serde_json::json!({ "cipher": cipher, "collectionIds": collections })),
                "creating an item",
            )
            .await?;
        v["id"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Error::Unexpected("a created item without an id".into()))
    }

    /// An item rewritten whole.
    pub async fn update(&self, id: &str, cipher: &Value) -> Result<()> {
        self.call(
            self.http()
                .put(self.server.url(&format!("/api/ciphers/{id}")))
                .json(cipher),
            "updating an item",
        )
        .await
        .map(drop)
    }

    /// A raw authenticated call, for what an owner's client does in the tests.
    pub async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        self.call(self.http().post(self.server.url(path)).json(body), path)
            .await
    }

    pub async fn put(&self, path: &str, body: &Value) -> Result<Value> {
        self.call(self.http().put(self.server.url(path)).json(body), path)
            .await
    }

    pub async fn get(&self, path: &str) -> Result<Value> {
        self.call(self.http().get(self.server.url(path)), path)
            .await
    }
}
