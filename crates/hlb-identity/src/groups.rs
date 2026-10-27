//! Groups, custom claims, and which groups a client lets in.
//!
//! Established against PocketID 2.18 (`tests/live_pocketid.rs` holds each):
//!
//! | Operation | Call |
//! |---|---|
//! | List / search | `GET /api/user-groups?search=…&pagination[page]=…&pagination[limit]=100` |
//! | Read (members, claims) | `GET /api/user-groups/{id}` |
//! | Create / rename | `POST /api/user-groups`, `PUT /api/user-groups/{id}` |
//! | Members | `PUT /api/user-groups/{id}/users {userIds}` — the whole set |
//! | A group's claims | `PUT /api/custom-claims/user-group/{id} [{key, value}]` — the whole set |
//! | A person's claims | `PUT /api/custom-claims/user/{id}` — the whole set |
//! | Restrict a client | `PUT /api/oidc/clients/{id}/allowed-user-groups`, then `isGroupRestricted` |
//!
//! 🔴 **A client NOT restricted lets everyone in, whatever groups it lists**, and
//! turning the restriction off CLEARS its groups (`oidc_service.go`). Restricted with no
//! group, it lets nobody in — which is what an app no role is allowed into must be.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;

use crate::{Error, PocketId, Result};

/// A group, as a list returns it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GroupSummary {
    pub id: String,
    pub name: String,
    #[serde(rename = "friendlyName")]
    pub friendly_name: String,
}

/// A group with what it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub friendly_name: String,
    /// Its members' ids.
    pub members: BTreeSet<String>,
    pub claims: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct Claim {
    key: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct Member {
    id: String,
}

#[derive(Debug, Deserialize)]
struct GroupDetail {
    id: String,
    name: String,
    #[serde(rename = "friendlyName")]
    friendly_name: String,
    #[serde(default, rename = "customClaims")]
    custom_claims: Vec<Claim>,
    #[serde(default)]
    users: Vec<Member>,
}

/// A claim as PocketID stores it: text, which it parses as JSON when it can.
///
/// ⚠️ A string that reads as JSON — `"5"`, `"true"` — would come back a number or a
/// boolean: it is written quoted, so it stays the string it was.
pub fn stored(v: &Value) -> String {
    match v {
        Value::String(s) if serde_json::from_str::<Value>(s).is_err() => s.clone(),
        other => other.to_string(),
    }
}

/// What PocketID gives an app for a stored claim — the inverse of [`stored`].
pub fn read(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_string()))
}

fn claims_body(claims: &BTreeMap<String, Value>) -> Value {
    Value::Array(
        claims
            .iter()
            .map(|(k, v)| serde_json::json!({ "key": k, "value": stored(v) }))
            .collect(),
    )
}

async fn json<T: serde::de::DeserializeOwned>(resp: reqwest::Response, what: &str) -> Result<T> {
    resp.json()
        .await
        .map_err(|e| Error::Unexpected(format!("unreadable {what}: {e}")))
}

impl PocketId {
    /// Every group whose name starts with `prefix`, across every page.
    pub async fn groups(&self, prefix: &str) -> Result<Vec<GroupSummary>> {
        let mut out = Vec::new();
        for v in self
            .every_page("/api/user-groups", Some(prefix), "group list")
            .await?
        {
            let g: GroupSummary = serde_json::from_value(v)
                .map_err(|e| Error::Unexpected(format!("unreadable group list: {e}")))?;
            if g.name.starts_with(prefix) {
                out.push(g);
            }
        }
        Ok(out)
    }

    pub async fn group(&self, id: &str) -> Result<Group> {
        let d: GroupDetail = json(
            self.send(
                self.http.get(self.url(&format!("/api/user-groups/{id}"))),
                "reading a group",
            )
            .await?,
            "group",
        )
        .await?;
        Ok(Group {
            id: d.id,
            name: d.name,
            friendly_name: d.friendly_name,
            members: d.users.into_iter().map(|u| u.id).collect(),
            claims: d
                .custom_claims
                .into_iter()
                .map(|c| (c.key, read(&c.value)))
                .collect(),
        })
    }

    /// Creates a group; returns its id. A friendly name is 2 to 50 characters.
    pub async fn create_group(&self, name: &str, friendly_name: &str) -> Result<String> {
        let d: GroupSummary = json(
            self.send(
                self.http
                    .post(self.url("/api/user-groups"))
                    .json(&serde_json::json!({ "name": name, "friendlyName": friendly_name })),
                "creating a group",
            )
            .await?,
            "created group",
        )
        .await?;
        Ok(d.id)
    }

    pub async fn rename_group(&self, id: &str, name: &str, friendly_name: &str) -> Result<()> {
        self.send(
            self.http
                .put(self.url(&format!("/api/user-groups/{id}")))
                .json(&serde_json::json!({ "name": name, "friendlyName": friendly_name })),
            "renaming a group",
        )
        .await?;
        Ok(())
    }

    pub async fn delete_group(&self, id: &str) -> Result<()> {
        self.send(
            self.http
                .delete(self.url(&format!("/api/user-groups/{id}"))),
            "deleting a group",
        )
        .await?;
        Ok(())
    }

    /// The group's members, exactly these.
    pub async fn set_members(&self, id: &str, members: &BTreeSet<String>) -> Result<()> {
        self.send(
            self.http
                .put(self.url(&format!("/api/user-groups/{id}/users")))
                .json(&serde_json::json!({ "userIds": members })),
            "setting a group's members",
        )
        .await?;
        Ok(())
    }

    /// The group's claims, exactly these.
    pub async fn set_group_claims(&self, id: &str, claims: &BTreeMap<String, Value>) -> Result<()> {
        self.send(
            self.http
                .put(self.url(&format!("/api/custom-claims/user-group/{id}")))
                .json(&claims_body(claims)),
            "setting a group's claims",
        )
        .await?;
        Ok(())
    }

    /// A person's own claims.
    pub async fn user_claims(&self, user_id: &str) -> Result<BTreeMap<String, Value>> {
        let v: Value = json(
            self.send(
                self.http.get(self.url(&format!("/api/users/{user_id}"))),
                "reading a person",
            )
            .await?,
            "person",
        )
        .await?;
        let claims: Vec<Claim> =
            serde_json::from_value(v.get("customClaims").cloned().unwrap_or(Value::Null))
                .unwrap_or_default();
        Ok(claims
            .into_iter()
            .map(|c| (c.key, read(&c.value)))
            .collect())
    }

    /// A person's own claims, exactly these — the caller keeps what is not its own.
    pub async fn set_user_claims(
        &self,
        user_id: &str,
        claims: &BTreeMap<String, Value>,
    ) -> Result<()> {
        self.send(
            self.http
                .put(self.url(&format!("/api/custom-claims/user/{user_id}")))
                .json(&claims_body(claims)),
            "setting a person's claims",
        )
        .await?;
        Ok(())
    }

    /// Whether the client is restricted, and to which groups (by id).
    pub async fn client_groups(&self, client_id: &str) -> Result<(bool, BTreeSet<String>)> {
        let v: Value = json(
            self.send(
                self.http
                    .get(self.url(&format!("/api/oidc/clients/{client_id}"))),
                "reading a client",
            )
            .await?,
            "client",
        )
        .await?;
        let restricted = v["isGroupRestricted"].as_bool().unwrap_or(false);
        let groups = v["allowedUserGroups"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|g| g["id"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Ok((restricted, groups))
    }

    /// Lets exactly these groups into the client — none: nobody.
    ///
    /// The groups are written first, then the restriction turned on: the other way
    /// round, everyone already signed in is shut out between the two calls. And the
    /// client is written back whole, as read: its update replaces every field.
    pub async fn restrict_client(&self, client_id: &str, groups: &BTreeSet<String>) -> Result<()> {
        let path = format!("/api/oidc/clients/{client_id}");
        self.send(
            self.http
                .put(self.url(&format!("{path}/allowed-user-groups")))
                .json(&serde_json::json!({ "userGroupIds": groups })),
            "setting a client's groups",
        )
        .await?;
        let mut current: Value = json(
            self.send(self.http.get(self.url(&path)), "reading a client")
                .await?,
            "client",
        )
        .await?;
        if current["isGroupRestricted"].as_bool() == Some(true) {
            return Ok(());
        }
        current["isGroupRestricted"] = Value::Bool(true);
        self.send(
            self.http.put(self.url(&path)).json(&current),
            "restricting a client",
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_claim_comes_back_as_it_was_written() {
        // PocketID parses a stored value as JSON when it can: "5" written bare would
        // reach the app as the number 5.
        for v in [
            serde_json::json!("admin"),
            serde_json::json!("5"),
            serde_json::json!("true"),
            serde_json::json!(50),
            serde_json::json!(1.5),
            Value::Null,
            serde_json::json!([{ "name": "Family", "oidcID": "hlb-family" }]),
        ] {
            assert_eq!(read(&stored(&v)), v, "{v}");
        }
        assert_eq!(
            stored(&serde_json::json!("admin")),
            "admin",
            "readable in PocketID"
        );
    }
}
