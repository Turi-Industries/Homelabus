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
