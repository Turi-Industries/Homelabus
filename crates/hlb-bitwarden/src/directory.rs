//! A Bitwarden organisation's members, written the way Bitwarden's Directory Connector
//! writes them — the one route a server-side program may use, since inviting through
//! the web vault's routes needs an owner's session.
//!
//! Read in Vaultwarden 1.37.1 (`src/api/core/public.rs`):
//!
//! - `POST /identity/connect/token` with `client_credentials`, the client being
//!   `organization.<id>` and the secret the organisation's API key — which an owner
//!   makes in the organisation's settings, once.
//! - `POST /api/public/organization/import`: a member listed who is not in the
//!   organisation is invited by address (an account made for them if none exists); with
//!   `overwriteExisting`, a member carrying an external id and NOT listed is removed —
//!   never the last owner, and never a member added by hand, who has no external id.
//!
//! ⚠️ An invited member still has to be CONFIRMED by an owner: confirming encrypts the
//! organisation's key for them, which only an owner's client can do. Homelabus never
//! holds an owner's master password — with it, a compromised controller would read the
//! organisation.

use serde::Serialize;

use crate::{Error, Result};

/// One member, keyed on the Homelabus account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Member {
    pub email: String,
    pub external_id: String,
    pub deleted: bool,
}

/// A group of members, keyed on its external id. Read only where Vaultwarden runs with
/// `ORG_GROUPS_ENABLED`, which ignores the groups otherwise with a warning in its log.
///
/// ⚠️ The import never removes or empties a group it is not sent (1.37.3, `public.rs`):
/// one to empty is sent with no member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub name: String,
    pub external_id: String,
    pub member_external_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Import<'a> {
    groups: &'a [Group],
    members: &'a [Member],
    overwrite_existing: bool,
    large_import: bool,
}

/// An organisation, reached with its API key.
pub struct Directory {
    base_url: String,
    organization: String,
    key: String,
    http: reqwest::Client,
}

impl Directory {
    pub fn new(base_url: &str, organization: &str, key: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            organization: organization.to_string(),
            key: key.to_string(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
        }
    }

    async fn token(&self) -> Result<String> {
        let resp = self
            .http
            .post(format!("{}/identity/connect/token", self.base_url))
            .form(&[
                ("grant_type", "client_credentials"),
                ("scope", "api.organization"),
                ("client_id", &format!("organization.{}", self.organization)),
                ("client_secret", &self.key),
                // Required by the token route for any client; one that never changes.
                ("device_identifier", "homelabus-directory"),
                ("device_name", "homelabus"),
                ("device_type", "14"),
            ])
            .send()
            .await
            .map_err(|source| Error::Http {
                source,
                context: "organisation token".into(),
            })?;
        if !resp.status().is_success() {
            // The body can name the key it refused: never echoed.
            return Err(Error::Refused(format!(
                "Vaultwarden refused the organisation's API key ({}) — make a new one in its \
                 settings and store it again",
                resp.status().as_u16()
            )));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable token: {e}")))?;
        v["access_token"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Error::Unexpected("no access_token in the answer".into()))
    }

    /// The organisation's members Homelabus keeps: exactly these, and each of `groups`
    /// holding exactly its members.
    pub async fn import(&self, members: &[Member], groups: &[Group]) -> Result<()> {
        let token = self.token().await?;
        let resp = self
            .http
            .post(format!("{}/api/public/organization/import", self.base_url))
            .bearer_auth(token)
            .json(&Import {
                groups,
                members,
                overwrite_existing: true,
                large_import: false,
            })
            .send()
            .await
            .map_err(|source| Error::Http {
                source,
                context: "organisation import".into(),
            })?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let detail = resp.text().await.unwrap_or_default();
            return Err(Error::Api { status, detail });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_import_is_the_directory_connector_s_shape() {
        let members = [Member {
            email: "lena@example.org".into(),
            external_id: "lena".into(),
            deleted: false,
        }];
        let body = serde_json::to_value(Import {
            groups: &[],
            members: &members,
            overwrite_existing: true,
            large_import: false,
        })
        .expect("json");
        assert_eq!(
            body,
            serde_json::json!({
                "groups": [],
                "members": [{ "email": "lena@example.org", "externalId": "lena", "deleted": false }],
                "overwriteExisting": true,
                "largeImport": false,
            })
        );
    }
}
