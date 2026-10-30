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
