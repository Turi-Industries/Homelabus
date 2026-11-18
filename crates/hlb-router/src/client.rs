//! OPNsense's API, as Homelabus uses it.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::tls::{self, Fingerprint};
use crate::{Error, Result};

/// An API key and its secret: HTTP Basic, the key as the user name.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub key: String,
    pub secret: String,
}

/// The secret never reaches a log or a panic message.
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("key", &self.key)
            .field("secret", &"…")
            .finish()
    }
}

/// What the router says it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct System {
    /// `OPNsense.internal`: its host and domain.
    pub name: String,
    /// `OPNsense 26.7-amd64`.
    pub version: String,
}

/// An account, as `/api/auth/user/search` lists it. 🔴 The listing carries the
/// password's hash and every API key's: only these fields are ever read from it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct User {
    pub uuid: String,
    pub name: String,
    /// `page-all` among its privileges, counted by the router itself.
    #[serde(default, deserialize_with = "flag")]
    pub is_admin: bool,
    /// `system` for root, `user` for an account made since.
    #[serde(default)]
    pub scope: String,
}

/// An API key, as listed: never its secret.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ApiKey {
    pub username: String,
    pub key: String,
    /// The key in base64, as `del_api_key` wants it in its path.
    pub id: String,
}

/// One of the router's networks, as `interfaces_info` describes it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Network {
    /// `lan`, `wan`, `opt1`…
    #[serde(default)]
    pub identifier: String,
    #[serde(default)]
    pub description: String,
    pub device: String,
    /// `10.77.0.3/24`; empty when the network has no IPv4 address.
    #[serde(default)]
    pub addr4: String,
}

/// An Unbound host override — a name the router answers itself instead of asking the
/// internet. Every value is a string on the wire, `"1"`/`"0"` for a flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostOverride {
    #[serde(default, skip_serializing)]
    pub uuid: String,
    #[serde(default, with = "flag_text")]
    pub enabled: bool,
    /// The first label; the rest of the name is `domain`.
    #[serde(default)]
    pub hostname: String,
    pub domain: String,
    /// `A`, `AAAA`, `MX`, `TXT`.
    #[serde(default)]
    pub rr: String,
    /// The address answered, for `A` and `AAAA`.
    #[serde(default)]
    pub server: String,
    /// Also answer the address's reverse name. Off for Homelabus's: every name points
    /// at one Caddy, and one address cannot have a reverse name per app.
    #[serde(default, with = "flag_text")]
    pub addptr: bool,
    #[serde(default)]
    pub description: String,
}

impl HostOverride {
    /// The name it answers, in small letters and without a final dot.
    pub fn fqdn(&self) -> String {
        let name = if self.hostname.is_empty() {
            self.domain.clone()
        } else {
            format!("{}.{}", self.hostname, self.domain)
        };
        name.trim_end_matches('.').to_ascii_lowercase()
    }
}

fn flag<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<bool, D::Error> {
    flag_text::deserialize(d)
}

mod flag_text {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &bool, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(if *v { "1" } else { "0" })
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
        // Anything but "1" is off: the router writes "0" or "" for a flag never set.
        Ok(matches!(
            serde_json::Value::deserialize(d)?,
            serde_json::Value::String(ref s) if s == "1"
        ))
    }
}

/// Every row of a search: `rowCount: -1` asks for them all, where the default page
/// would cut a long list without a word.
#[derive(Deserialize)]
struct Rows<T> {
    rows: Vec<T>,
}

pub struct Opnsense {
    base_url: String,
    credentials: Credentials,
    http: reqwest::Client,
}

impl Opnsense {
    /// `base_url` is the interface's (`https://10.77.0.3`); only the certificate `pin`
    /// is accepted there.
    pub fn new(
        base_url: impl Into<String>,
        pin: Fingerprint,
        credentials: Credentials,
    ) -> Result<Self> {
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            credentials,
            http: tls::pinned(pin)?,
        })
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        let call = format!("{method} {path}");
        let mut req = self
            .http
            .request(method, format!("{}/api/{path}", self.base_url))
            .basic_auth(&self.credentials.key, Some(&self.credentials.secret));
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|e| Error::Http {
            source: e,
            context: call.clone(),
        })?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| Error::Http {
            source: e,
            context: call.clone(),
        })?;
        match status.as_u16() {
            401 => return Err(Error::Unauthorized),
            403 => return Err(Error::Forbidden(call)),
            s if !status.is_success() => {
                return Err(Error::Api {
                    status: s,
                    call,
                    detail: text.chars().take(200).collect(),
                });
            }
            _ => {}
        }
        let value: Value = serde_json::from_str(&text)
            .map_err(|_| Error::Unexpected(format!("{call} answered no JSON")))?;
        // A write OPNsense refuses is a 200 saying so — never one to count as done.
        if value.get("result").and_then(Value::as_str) == Some("failed") {
            let why = value
                .get("validations")
                .and_then(Value::as_object)
                .map(|v| {
                    v.iter()
                        .map(|(field, msg)| format!("{field}: {}", msg.as_str().unwrap_or("?")))
                        .collect::<Vec<_>>()
                        .join("; ")
                })
                .unwrap_or_default();
            return Err(Error::Refused { call, why });
        }
        Ok(value)
    }

    async fn search<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<Vec<T>> {
        let v = self
            .call(
                reqwest::Method::POST,
                path,
                Some(json!({"current": 1, "rowCount": -1, "searchPhrase": ""})),
            )
            .await?;
        let rows: Rows<T> =
            serde_json::from_value(v).map_err(|e| Error::Unexpected(format!("{path}: {e}")))?;
        Ok(rows.rows)
    }

    fn saved(v: &Value, call: &str) -> Result<String> {
        v.get("uuid")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| Error::Unexpected(format!("{call} answered no uuid")))
    }

    pub async fn system(&self) -> Result<System> {
        let v = self
            .call(
                reqwest::Method::GET,
                "diagnostics/system/system_information",
                None,
            )
            .await?;
        let name = v.get("name").and_then(Value::as_str).unwrap_or_default();
        let version = v
            .get("versions")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .unwrap_or_default();
        if version.is_empty() {
            return Err(Error::Unexpected(
                "system_information named no version: is this OPNsense?".into(),
            ));
        }
        Ok(System {
            name: name.to_string(),
            version: version.to_string(),
        })
    }

    pub async fn users(&self) -> Result<Vec<User>> {
        self.search("auth/user/search").await
    }

    /// The group whose members hold every privilege (`page-all`): `admins`, 1999.
    pub async fn admins_gid(&self) -> Result<String> {
        let rows: Vec<Value> = self.search("auth/group/search").await?;
        let text = |r: &Value, f: &str| r.get(f).and_then(Value::as_str).unwrap_or("").to_string();
        rows.iter()
            .find(|r| {
                text(r, "name") == "admins" && text(r, "priv").split(',').any(|p| p == "page-all")
            })
            .map(|r| text(r, "gid"))
            .filter(|gid| !gid.is_empty())
            .ok_or_else(|| Error::Unexpected("no group \"admins\" holding every privilege".into()))
    }

    /// An account with a password drawn by the router and shown to nobody — nobody
    /// signs in as it — in the group `gid`.
    pub async fn add_user(&self, name: &str, comment: &str, gid: &str) -> Result<String> {
        let call = "auth/user/add";
        let v = self
            .call(
                reqwest::Method::POST,
                call,
                Some(json!({"user": {
                    "name": name,
                    "scrambled_password": "1",
                    "group_memberships": gid,
                    "comment": comment,
                }})),
            )
            .await?;
        Self::saved(&v, call)
    }

    pub async fn api_keys(&self) -> Result<Vec<ApiKey>> {
        self.search("auth/user/search_api_key").await
    }

    pub async fn add_api_key(&self, username: &str) -> Result<Credentials> {
        let call = format!("auth/user/add_api_key/{username}");
        let v = self
            .call(reqwest::Method::POST, &call, Some(json!({})))
            .await?;
        let field = |f: &str| v.get(f).and_then(Value::as_str).map(str::to_string);
        match (field("key"), field("secret")) {
            (Some(key), Some(secret)) => Ok(Credentials { key, secret }),
            _ => Err(Error::Unexpected(format!("{call} answered no key"))),
        }
    }

    pub async fn del_api_key(&self, id: &str) -> Result<()> {
        let call = format!("auth/user/del_api_key/{id}");
        let v = self
            .call(reqwest::Method::POST, &call, Some(json!({})))
            .await?;
        match v.get("result").and_then(Value::as_str) {
            Some("deleted") => Ok(()),
            other => Err(Error::Unexpected(format!(
                "{call} answered {}",
                other.unwrap_or("nothing")
            ))),
        }
    }

    pub async fn networks(&self) -> Result<Vec<Network>> {
        self.search("interfaces/overview/interfaces_info").await
    }

    pub async fn host_overrides(&self) -> Result<Vec<HostOverride>> {
        self.search("unbound/settings/search_host_override").await
    }

    pub async fn add_host_override(&self, o: &HostOverride) -> Result<String> {
        let call = "unbound/settings/add_host_override";
        let v = self
            .call(reqwest::Method::POST, call, Some(json!({ "host": o })))
            .await?;
        Self::saved(&v, call)
    }

    pub async fn set_host_override(&self, uuid: &str, o: &HostOverride) -> Result<()> {
        let call = format!("unbound/settings/set_host_override/{uuid}");
        self.call(reqwest::Method::POST, &call, Some(json!({ "host": o })))
            .await?;
        Ok(())
    }

    pub async fn del_host_override(&self, uuid: &str) -> Result<()> {
        let call = format!("unbound/settings/del_host_override/{uuid}");
        self.call(reqwest::Method::POST, &call, Some(json!({})))
            .await?;
        Ok(())
    }

    /// Unbound reads what was saved only once reconfigured: a saved override answers
    /// nothing until then.
    pub async fn reconfigure_unbound(&self) -> Result<()> {
        let call = "unbound/service/reconfigure";
        let v = self
            .call(reqwest::Method::POST, call, Some(json!({})))
            .await?;
        match v.get("status").and_then(Value::as_str) {
            Some("ok") => Ok(()),
            other => Err(Error::Unexpected(format!(
                "{call} answered {}",
                other.unwrap_or("nothing")
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listed_override_reads_as_the_router_writes_it() {
        // As OPNsense 26.7 answered it on the lab.
        let row = r#"{"uuid":"511e6481-1e76-42ac-be25-5316d6c0c5df","enabled":"1","hostname":"probe","domain":"lab.test","rr":"A","%rr":"A (IPv4 address)","mxprio":"","mx":"","ttl":"","server":"10.77.0.11","txtdata":"","addptr":"1","aliases":"","description":"homelabus probe","isAlias":false}"#;
        let o: HostOverride = serde_json::from_str(row).expect("a row");
        assert!(o.enabled && o.addptr);
        assert_eq!(o.fqdn(), "probe.lab.test");
        assert_eq!(o.server, "10.77.0.11");
    }

    #[test]
    fn an_override_is_written_with_the_routers_flags_and_without_its_uuid() {
        let o = HostOverride {
            uuid: "x".into(),
            enabled: true,
            hostname: "gitea".into(),
            domain: "example.org".into(),
            rr: "A".into(),
            server: "10.0.0.2".into(),
            addptr: false,
            description: "homelabus".into(),
        };
        let v = serde_json::to_value(&o).expect("serializes");
        assert_eq!(v["enabled"], "1");
        assert_eq!(v["addptr"], "0");
        assert!(
            v.get("uuid").is_none(),
            "the uuid is the path's, never the body's"
        );
    }

    #[test]
    fn a_listed_account_reads_without_its_hashes() {
        let row = r#"{"uuid":"c2c0","uid":"0","name":"root","disabled":"0","scope":"system","password":"$2y$10$x","apikeys":"k|$6$$y","is_admin":"1"}"#;
        let u: User = serde_json::from_str(row).expect("a row");
        assert!(u.is_admin);
        assert_eq!(u.scope, "system");
        assert!(!format!("{u:?}").contains("$2y$"), "the hash is never kept");
    }

    #[test]
    fn credentials_never_print_their_secret() {
        let c = Credentials {
            key: "k".into(),
            secret: "s3cr3t".into(),
        };
        assert!(!format!("{c:?}").contains("s3cr3t"));
    }
}
