//! The intents that only write the state.
//!
//! 🔴 Whoever writes `hlb.db` forges a secret (encrypting needs the vault's PUBLIC key
//! only), mints a session, rewrites the audit chain or a frozen manifest root runs. So
//! the privileged side alone writes it, and the web side asks for each record by what
//! it means — never a table, a column or SQL.

use serde::{Deserialize, Serialize};

/// Append one entry to the audit chain.
///
/// The web side vouches for who acted, as it does for every intent; the chain — each
/// entry fingerprinting the one before — is written where the web side cannot reach to
/// rewrite it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audit {
    pub actor: String,
    pub role: hlb_types::Role,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub detail: Option<String>,
}

/// Open a session for a person PocketID just signed in.
///
/// The web side vouches for the sign-in, as it does for who asks any intent: it holds
/// the session's value, and the state keeps only its fingerprint.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenSession {
    /// The cookie's value. 🔴 Never printed: see the `Debug` below.
    pub presented: String,
    pub user: String,
    pub subject: Option<String>,
    pub now: i64,
    pub duration_s: i64,
    pub user_agent: Option<String>,
}

impl std::fmt::Debug for OpenSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenSession")
            .field("user", &self.user)
            .field("subject", &self.subject)
            .field("now", &self.now)
            .field("duration_s", &self.duration_s)
            .finish_non_exhaustive()
    }
}

/// Extend a session that was just used.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TouchSession {
    /// 🔴 Never printed.
    pub presented: String,
    pub now: i64,
    pub duration_s: i64,
}

impl std::fmt::Debug for TouchSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TouchSession")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Close the session a cookie carries — signing out. `true` when there was one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseSession {
    /// 🔴 Never printed.
    pub presented: String,
}

impl std::fmt::Debug for CloseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloseSession").finish_non_exhaustive()
    }
}

/// Close one of a person's sessions by its short reference ("sign out this device").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseSessionByReference {
    pub user: String,
    pub reference: String,
}

/// Bind an account to the PocketID identity signing in to it, unless another one is
/// bound already: `false` then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindIdentity {
    pub user: String,
    pub sub: String,
}

/// Record that a token was just used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TouchToken {
    pub name: String,
}

/// Keep a token for Bitwarden's alias generator: bound to an account and one of its
/// mailboxes, at the `user` role whatever is asked — the role is not the caller's to
/// choose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueAliasToken {
    pub name: String,
    pub account: String,
    pub mailbox: String,
    /// The value's fingerprint: the value itself stays with the web side, which shows
    /// it once.
    pub fingerprint: String,
}

/// Create a role, or change one's name, level and mail limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutRole {
    pub role: hlb_users::role::RoleDef,
    pub by: String,
}

/// Delete a role. `true` when there was one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteRole {
    pub id: String,
}

/// A role's storage quota in an app; `None` removes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetRoleQuota {
    pub role: String,
    pub app: String,
    pub bytes: Option<u64>,
}

/// Let a role into an app. `true` when it was not let in already.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRole {
    pub app: String,
    pub role: String,
    pub by: String,
}

/// Stop letting a role into an app. `true` when it was let in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyRole {
    pub app: String,
    pub role: String,
}

/// A person's own quota in an app, or theirs taken away so their role's applies again.
///
/// ⚠️ Two fields, not the state's `Option<Option<u64>>`: JSON says `null` for both
/// `None` and `Some(None)`, and "no quota at all" would arrive as "their role's".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetPersonQuota {
    pub user: String,
    pub app: String,
    /// `false` = their own taken away; `bytes` is then ignored.
    pub own: bool,
    /// Their own quota; `None` = none at all.
    pub bytes: Option<u64>,
    pub by: String,
}

/// Give a person a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetUserRole {
    pub user: String,
    pub role: String,
    pub granted_by: Option<String>,
}

/// Keep an invitation, by its value's fingerprint.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInvitation {
    /// The link's value. 🔴 Never printed.
    pub presented: String,
    pub created_by: String,
    pub role: String,
    pub now: i64,
    pub duration_s: i64,
    pub max_uses: i64,
    pub note: Option<String>,
}

impl std::fmt::Debug for CreateInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateInvitation")
            .field("created_by", &self.created_by)
            .field("role", &self.role)
            .field("max_uses", &self.max_uses)
            .finish_non_exhaustive()
    }
}

/// Use up a pending invitation by its short reference. `true` when one was pending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeInvitation {
    pub reference: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::Intent;

    #[test]
    fn no_quota_at_all_does_not_arrive_as_the_roles_quota() {
        let none_at_all: Intent = SetPersonQuota {
            user: "lena".into(),
            app: "immich".into(),
            own: true,
            bytes: None,
            by: "camille".into(),
        }
        .into();
        let wire = serde_json::to_value(&none_at_all).expect("serialise");
        let back: Intent = serde_json::from_value(wire).expect("deserialise");
        let Intent::SetPersonQuota(q) = back else {
            panic!("another intent came back")
        };
        assert_eq!(q.own.then_some(q.bytes), Some(None));
    }
}
