//! OPNsense's API, as Homelabus uses it.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::networks::{DhcpRange, Dnsmasq, Vlan};
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

/// A port forward — destination NAT — as `firewall/d_nat/search_rule` lists it: its
/// fields FLATTENED (`destination.port`), where a write nests them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PortForward {
    pub uuid: String,
    #[serde(default, deserialize_with = "flag")]
    pub disabled: bool,
    /// The network it listens on: `wan`.
    #[serde(default)]
    pub interface: String,
    /// `tcp`, `udp`, `tcp/udp`; empty for any.
    #[serde(default)]
    pub protocol: String,
    /// `wanip`, an address, an alias.
    #[serde(default, rename = "destination.network")]
    pub destination: String,
    /// `25`, `1000:2000`, an alias.
    #[serde(default, rename = "destination.port")]
    pub port: String,
    /// The address it forwards to.
    #[serde(default)]
    pub target: String,
    #[serde(default, rename = "local-port")]
    pub local_port: String,
    #[serde(default)]
    pub descr: String,
    /// The anti-lockout rules (`uuid: lockout_N`): the router's, listed among the rest.
    #[serde(default, deserialize_with = "truthy")]
    pub is_automatic: bool,
}

/// An outbound NAT rule, as `firewall/source_nat/search_rule` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OutboundNat {
    pub uuid: String,
    #[serde(default, deserialize_with = "flag")]
    pub enabled: bool,
    #[serde(default)]
    pub interface: String,
    /// Listed in capitals (`TCP`), whatever was written.
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub source_net: String,
    #[serde(default)]
    pub destination_net: String,
    #[serde(default)]
    pub destination_port: String,
    /// What the source becomes: `lanip`, the router's own address there.
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub description: String,
    /// The rules the router generates itself, shown beside the written ones.
    #[serde(default, deserialize_with = "truthy")]
    pub is_automatic: bool,
}

/// How the router writes its outbound NAT. 🔴 In `Automatic`, a rule written by hand is
/// SAVED and ignored: neither listed nor loaded (measured on 26.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundMode {
    /// Generated rules only.
    Automatic,
    /// Generated rules and written ones.
    Hybrid,
    /// Written rules only.
    Advanced,
    /// None at all.
    Disabled,
}

impl OutboundMode {
    pub fn wire(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::Hybrid => "hybrid",
            Self::Advanced => "advanced",
            Self::Disabled => "disabled",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [
            Self::Automatic,
            Self::Hybrid,
            Self::Advanced,
            Self::Disabled,
        ]
        .into_iter()
        .find(|m| m.wire() == s)
    }

    /// Whether a rule written by hand is loaded.
    pub fn reads_written(self) -> bool {
        matches!(self, Self::Hybrid | Self::Advanced)
    }
}

fn flag<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<bool, D::Error> {
    flag_text::deserialize(d)
}

/// `true` or `"1"`: the router lists its own rules with a JSON boolean, and every other
/// flag as text.
fn truthy<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<bool, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Bool(b) => b,
        Value::String(s) => s == "1",
        _ => false,
    })
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

    pub async fn port_forwards(&self) -> Result<Vec<PortForward>> {
        self.search("firewall/d_nat/search_rule").await
    }

    /// `rule` as [`crate::forwards::ForwardRule::body`] writes it.
    pub async fn add_port_forward(&self, rule: &Value) -> Result<String> {
        let call = "firewall/d_nat/add_rule";
        let v = self
            .call(reqwest::Method::POST, call, Some(json!({ "rule": rule })))
            .await?;
        Self::saved(&v, call)
    }

    pub async fn set_port_forward(&self, uuid: &str, rule: &Value) -> Result<()> {
        let call = format!("firewall/d_nat/set_rule/{uuid}");
        self.call(reqwest::Method::POST, &call, Some(json!({ "rule": rule })))
            .await?;
        Ok(())
    }

    pub async fn del_port_forward(&self, uuid: &str) -> Result<()> {
        self.deleted(&format!("firewall/d_nat/del_rule/{uuid}"))
            .await
    }

    pub async fn outbound_nat(&self) -> Result<Vec<OutboundNat>> {
        self.search("firewall/source_nat/search_rule").await
    }

    pub async fn add_outbound_nat(&self, rule: &Value) -> Result<String> {
        let call = "firewall/source_nat/add_rule";
        let v = self
            .call(reqwest::Method::POST, call, Some(json!({ "rule": rule })))
            .await?;
        Self::saved(&v, call)
    }

    pub async fn set_outbound_nat(&self, uuid: &str, rule: &Value) -> Result<()> {
        let call = format!("firewall/source_nat/set_rule/{uuid}");
        self.call(reqwest::Method::POST, &call, Some(json!({ "rule": rule })))
            .await?;
        Ok(())
    }

    pub async fn del_outbound_nat(&self, uuid: &str) -> Result<()> {
        self.deleted(&format!("firewall/source_nat/del_rule/{uuid}"))
            .await
    }

    /// A rule already gone is as deleted as one this call removed: a run resuming after
    /// a failure deletes again what it had.
    async fn deleted(&self, call: &str) -> Result<()> {
        let v = self
            .call(reqwest::Method::POST, call, Some(json!({})))
            .await?;
        match v.get("result").and_then(Value::as_str) {
            Some("deleted" | "not found") => Ok(()),
            other => Err(Error::Unexpected(format!(
                "{call} answered {}",
                other.unwrap_or("nothing")
            ))),
        }
    }

    pub async fn outbound_mode(&self) -> Result<OutboundMode> {
        let call = "firewall/source_nat/get";
        let v = self.call(reqwest::Method::GET, call, None).await?;
        selected(&v["filter"]["general"]["snat_mode"])
            .and_then(OutboundMode::parse)
            .ok_or_else(|| Error::Unexpected(format!("{call} named no outbound NAT mode")))
    }

    pub async fn set_outbound_mode(&self, mode: OutboundMode) -> Result<()> {
        self.call(
            reqwest::Method::POST,
            "firewall/source_nat/set",
            Some(json!({"filter": {"general": {"snat_mode": mode.wire()}}})),
        )
        .await?;
        Ok(())
    }

    /// Loads what was saved into the firewall: a saved rule forwards nothing until then.
    /// `which` is `d_nat` or `source_nat`.
    pub async fn apply_firewall(&self, which: &str) -> Result<()> {
        self.reloaded(&format!("firewall/{which}/apply")).await
    }

    /// A call that reloads a service, its answer `{"status": "ok"}`.
    async fn reloaded(&self, call: &str) -> Result<()> {
        let v = self
            .call(reqwest::Method::POST, call, Some(json!({})))
            .await?;
        // `{"status":"OK\n\n"}`: the reload's own output, newlines and all.
        match v.get("status").and_then(Value::as_str).map(str::trim) {
            Some(s) if s.eq_ignore_ascii_case("ok") => Ok(()),
            other => Err(Error::Unexpected(format!(
                "{call} answered {}",
                other.unwrap_or("nothing")
            ))),
        }
    }

    pub async fn vlans(&self) -> Result<Vec<Vlan>> {
        self.search("interfaces/vlan_settings/search_item").await
    }

    /// `vlan` as [`crate::networks::vlan_body`] writes it; the router names its device.
    pub async fn add_vlan(&self, vlan: &Value) -> Result<String> {
        let call = "interfaces/vlan_settings/add_item";
        let v = self
            .call(reqwest::Method::POST, call, Some(json!({ "vlan": vlan })))
            .await?;
        Self::saved(&v, call)
    }

    /// A saved VLAN is no device until then.
    pub async fn reconfigure_vlans(&self) -> Result<()> {
        self.reloaded("interfaces/vlan_settings/reconfigure").await
    }

    /// Makes `device` an interface of the router's, named `descr`.
    ///
    /// 🔴 The router checks the device against a list configd keeps for 30 s
    /// (`interface list assign-opts`, `cache_ttl:30`): a VLAN made since the last listing
    /// is refused, "Option [] not in list". Refused so, it is asked again until the list
    /// is fresh.
    pub async fn add_assignment(&self, device: &str, descr: &str) -> Result<()> {
        let call = "interfaces/assignment/add_item";
        let body = json!({"interface": {"if": device, "descr": descr}});
        let mut tries = 0;
        loop {
            match self
                .call(reqwest::Method::POST, call, Some(body.clone()))
                .await
            {
                Err(Error::Refused { why, .. }) if why.contains("not in list") && tries < 8 => {
                    tries += 1;
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                other => return other.map(|_| ()),
            }
        }
    }

    /// A saved assignment is no interface until then.
    pub async fn reconfigure_assignments(&self) -> Result<()> {
        self.reloaded("interfaces/assignment/reconfigure").await
    }

    pub async fn dhcp_ranges(&self) -> Result<Vec<DhcpRange>> {
        self.search("dnsmasq/settings/search_range").await
    }

    pub async fn add_dhcp_range(&self, range: &Value) -> Result<String> {
        let call = "dnsmasq/settings/add_range";
        let v = self
            .call(reqwest::Method::POST, call, Some(json!({ "range": range })))
            .await?;
        Self::saved(&v, call)
    }

    pub async fn set_dhcp_range(&self, uuid: &str, range: &Value) -> Result<()> {
        let call = format!("dnsmasq/settings/set_range/{uuid}");
        self.call(
            reqwest::Method::POST,
            &call,
            Some(json!({ "range": range })),
        )
        .await?;
        Ok(())
    }

    pub async fn del_dhcp_range(&self, uuid: &str) -> Result<()> {
        self.deleted(&format!("dnsmasq/settings/del_range/{uuid}"))
            .await
    }

    pub async fn dnsmasq(&self) -> Result<Dnsmasq> {
        let call = "dnsmasq/settings/get";
        let v = self.call(reqwest::Method::GET, call, None).await?;
        let d = &v["dnsmasq"];
        let enabled = match d["enable"].as_str() {
            Some(s) => s == "1",
            None => return Err(Error::Unexpected(format!("{call} said nothing of dnsmasq"))),
        };
        let mut interfaces: Vec<String> = d["interface"]
            .as_object()
            .map(|o| {
                o.iter()
                    .filter(|(_, v)| v.get("selected").and_then(Value::as_i64) == Some(1))
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default();
        interfaces.sort();
        Ok(Dnsmasq {
            enabled,
            interfaces,
        })
    }

    pub async fn set_dnsmasq(&self, d: &Dnsmasq) -> Result<()> {
        self.call(
            reqwest::Method::POST,
            "dnsmasq/settings/set",
            Some(json!({"dnsmasq": {
                "enable": if d.enabled { "1" } else { "0" },
                "interface": d.interfaces.join(","),
            }})),
        )
        .await?;
        Ok(())
    }

    /// Saved is not served: dnsmasq reads its settings when reconfigured.
    pub async fn reconfigure_dnsmasq(&self) -> Result<()> {
        self.reloaded("dnsmasq/service/reconfigure").await
    }
}

/// The key a `get` marks `"selected": 1` among an option field's choices.
fn selected(options: &Value) -> Option<&str> {
    options.as_object()?.iter().find_map(|(k, v)| {
        (v.get("selected").and_then(Value::as_i64) == Some(1)).then_some(k.as_str())
    })
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
