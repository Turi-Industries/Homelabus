//! Who may sign in to an app, and what the app is told about them.
//!
//! ## One PocketID group per role, and the app reads what the group carries
//!
//! A role is Homelabus data — a name, a permission level, quotas. Each one is a group
//! in PocketID (`hlb-<role id>`), its members the people holding it. An app signing in
//! natively is restricted to the groups of the roles allowed into it; one behind the
//! portal is checked against them at every request. Neither is open by default: an
//! app no role is allowed into lets nobody in.
//!
//! What the app makes of a role — Gitea's administrator, Grafana's `Editor`, Immich's
//! quota — it reads from **custom claims** written on the role's group: PocketID gives
//! a group's claims to each member's tokens, and a person's own claims beat their
//! group's, which is where a quota given to one person goes.
//!
//! ⚠️ PocketID gives custom claims with the `profile` scope only, and the `groups`
//! claim with the `groups` scope only (2.18, `claims_service.go`).
//! ⚠️ A claim is seen by EVERY app the person signs in to, not only the one that
//! declared it: two manifests may not write the same claim (`catalog validate`).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Role;

/// The PocketID group a role is: what an app is restricted to, what the portal checks.
///
/// ⚠️ Stored in PocketID and in every restriction built from it: a role's id never
/// changes once created, its display name may.
pub fn group_of(role_id: &str) -> String {
    format!("hlb-{role_id}")
}

/// The role a PocketID group stands for, when it is one of Homelabus's.
pub fn role_of_group(group: &str) -> Option<&str> {
    group.strip_prefix("hlb-").filter(|id| valid_role_id(id))
}

/// A role id: lowercase letters, digits, hyphens, up to 40 — a group name in PocketID
/// and a word on a command line.
pub fn valid_role_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 40
        && !id.starts_with('-')
        && !id.ends_with('-')
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// What PocketID will not let a custom claim be called, or gives a meaning of its own.
pub const RESERVED_CLAIMS: [&str; 17] = [
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "nonce",
    "email",
    "email_verified",
    "name",
    "given_name",
    "family_name",
    "display_name",
    "preferred_username",
    "picture",
    "groups",
    "auth_time",
    "acr",
];

/// The tokens a [`Claim::Json`] value is filled with.
pub const ROLE_TOKENS: [&str; 3] = ["role.id", "role.name", "role.group"];
/// The tokens a quota's `apply` is filled with, per person.
pub const QUOTA_TOKENS: [&str; 2] = ["person.sub", "quota"];

/// An app's access, in its manifest's `spec.access`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Access {
    /// The lowest permission level a role must hold to be allowed in. Termix holds
    /// every machine's SSH access: `admin`. A role below it is never allowed, whatever
    /// someone asks for.
    #[serde(default)]
    pub floor: Role,
    /// Who administers the app: the roles at this level or above, when allowed in.
    /// Listed when such a role is given to someone — what the gesture really opens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admins: Option<Admins>,
    /// Custom claims written on each allowed role's group, by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, Claim>,
    /// A storage quota, set per role and per person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<Quota>,
    /// Membership Homelabus keeps inside the app itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Members>,
    /// The cluster's machines, which Homelabus keeps inside the app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Nodes>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Admins {
    pub level: Role,
    /// What administering the app gives, as a phrase: "every repository and every
    /// account".
    pub means: String,
    /// For an app no claim makes anyone its administrator: what makes a person one, and
    /// what unmakes them — kept in step with their role, person by person.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply: Option<AdminsApply>,
}

/// Fluxer's administrators are an ACL on the account, which no claim sets: the commands
/// that grant and take it back, run with `{{ person.sub }}` (their PocketID id). Each
/// exits 0 once done and [`ABSENT_EXIT`] when the person has no account in the app yet
/// — retried, not failed. Never through a shell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminsApply {
    /// The companion they run in, by name; the app's own service when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    pub grant: Vec<String>,
    pub revoke: Vec<String>,
}

/// The token an administrators' command is filled with.
pub const ADMIN_TOKENS: [&str; 1] = ["person.sub"];

/// A custom claim's value, per role: exactly one of the two.
///
/// ⚠️ Two fields rather than an enum: `serde_yaml_ng` reads an enum's variant from a
/// YAML tag (`!byLevel`), which nobody writes by hand.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Claim {
    /// By the role's level: the entry of the highest level at or below it. A role
    /// below every entry gets no claim at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_level: Option<BTreeMap<Role, String>>,
    /// A JSON value, whose strings take `{{ role.id }}`, `{{ role.name }}` and
    /// `{{ role.group }}` — filled inside the value, so a name carrying a quote stays
    /// one string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<serde_json::Value>,
}

/// What a claim is computed from: one role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleView<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub level: Role,
}

impl Claim {
    /// The value this role gets, or none.
    pub fn value_for(&self, role: RoleView<'_>) -> Option<serde_json::Value> {
        match (&self.by_level, &self.json) {
            (Some(levels), _) => levels
                .range(..=role.level)
                .next_back()
                .map(|(_, v)| serde_json::Value::String(v.clone())),
            (None, Some(v)) => Some(fill_json(v, role)),
            (None, None) => None,
        }
    }
}

fn fill_json(v: &serde_json::Value, role: RoleView<'_>) -> serde_json::Value {
    use serde_json::Value;
    match v {
        Value::String(s) => Value::String(fill(s, |t| match t {
            "role.id" => Some(role.id.to_string()),
            "role.name" => Some(role.name.to_string()),
            "role.group" => Some(group_of(role.id)),
            _ => None,
        })),
        Value::Array(a) => Value::Array(a.iter().map(|x| fill_json(x, role)).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| (k.clone(), fill_json(x, role)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The `{{ … }}` names in a text, trimmed, in order.
pub fn placeholders(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("{{") {
        let after = &rest[at + 2..];
        let Some(end) = after.find("}}") else { break };
        out.push(after[..end].trim());
        rest = &after[end + 2..];
    }
    out
}

/// Each `{{ name }}` replaced by what `value` gives; one it gives nothing for is left
/// as written, so a mistake shows as the token's own text.
pub fn fill(text: &str, value: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("{{") {
        let after = &rest[at + 2..];
        let Some(end) = after.find("}}") else { break };
        out.push_str(&rest[..at]);
        match value(after[..end].trim()) {
            Some(v) => out.push_str(&v),
            None => out.push_str(&rest[at..at + 2 + end + 2]),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// A storage quota the app enforces, set per role — and per person, over their role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Quota {
    /// A claim the app reads when it creates an account at a first sign-in — Immich's
    /// `immich_quota`. No quota means no claim, never `0`: Immich takes `0` as "no
    /// space at all".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim: Option<QuotaClaim>,
    /// What keeps an EXISTING account in step, person by person.
    ///
    /// 🔴 A claim read at creation only changes nothing afterwards: Immich v3.1.0
    /// reads its role claim at every sign-in and its quota claim never again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply: Option<QuotaApply>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuotaClaim {
    pub name: String,
    pub unit: QuotaUnit,
}

/// How a person's quota reaches an account that exists, with `{{ person.sub }}` (their
/// PocketID id, which the app keeps as its OIDC subject) and `{{ quota }}` (in `unit`;
/// `none` in a command, `NULL` in a statement, when there is no quota).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum QuotaApply {
    /// A command run in the app's running container, never through a shell. It exits
    /// 0 once the quota is set and [`ABSENT_EXIT`] when the person has no account in
    /// the app yet — they have not signed in to it — which is retried, not failed.
    Exec {
        command: Vec<String>,
        unit: QuotaUnit,
    },
    /// One `UPDATE` on the app's own database. No row updated means no account yet.
    Sql {
        statement: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        database: Option<String>,
        unit: QuotaUnit,
    },
}

/// What a quota command exits with when the person has no account in the app yet.
pub const ABSENT_EXIT: i64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum QuotaUnit {
    #[serde(rename = "bytes")]
    Bytes,
    MiB,
    GiB,
}

impl QuotaUnit {
    fn size(self) -> u64 {
        match self {
            Self::Bytes => 1,
            Self::MiB => 1 << 20,
            Self::GiB => 1 << 30,
        }
    }

    /// A quota in this unit, as a number written in full: `5`, `1.5` — never rounded
    /// to a value nobody set.
    pub fn amount(self, bytes: u64) -> String {
        let size = self.size();
        if bytes.is_multiple_of(size) {
            return (bytes / size).to_string();
        }
        let s = format!("{:.6}", bytes as f64 / size as f64);
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    }

    /// The same, as a JSON number for a claim.
    pub fn claim_value(self, bytes: u64) -> serde_json::Value {
        serde_json::from_str(&self.amount(bytes)).unwrap_or(serde_json::Value::Null)
    }
}

/// Membership Homelabus keeps inside the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Members {
    /// A Bitwarden organisation's members, through the route Bitwarden's Directory
    /// Connector imports with (`/api/public/organization/import`): whoever holds an
    /// allowed role is invited by their address, whoever no longer does is removed.
    /// Members added by hand are never touched — only those the import made carry an
    /// external id. The organisation and its API key are made by an owner, once: an
    /// organisation's key is encrypted by its owners' clients, which no server can be.
    /// The key is kept as `<app>-organization-key`, its id as `<app>-organization-id`.
    BitwardenDirectory,
}

impl Members {
    pub fn organization_id_secret(app: &str) -> String {
        format!("{app}-organization-id")
    }
    pub fn organization_key_secret(app: &str) -> String {
        format!("{app}-organization-key")
    }

    /// The emergency vault's account — the member Homelabus deposits as — by its parts:
    /// its address, chosen by whoever sets it up; its master password, generated; the
    /// second factor and API key Homelabus gives it (`user.<id>:<key>`).
    pub fn emergency_secret(app: &str, part: EmergencyPart) -> String {
        format!("{app}-emergency-{}", part.suffix())
    }
}

/// The cluster's machines, kept inside the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Nodes {
    /// A Termix host per node, removed when the node leaves, shared with the Termix
    /// roles its `OIDC_ROLE_MAP` gives at sign-in. Each node holds a dedicated Unix
    /// account — never root, no right beyond a shell — whose key Homelabus generates
    /// and authorizes from Termix's own node only. Its API key is an administrator's
    /// to hand over, once (`hlb termix connect`): making one takes a session.
    Termix,
}

impl Nodes {
    /// The API key of the Termix account Homelabus works as.
    pub fn api_key_secret(app: &str) -> String {
        format!("{app}-api-key")
    }
    /// The nodes' private key, in OpenSSH's format.
    pub fn node_key_secret(app: &str) -> String {
        format!("{app}-node-key")
    }
    /// The key a rotation is moving to, until every node and Termix hold it.
    pub fn next_node_key_secret(app: &str) -> String {
        format!("{app}-node-key-next")
    }
}

/// One of the emergency vault account's stored parts — see
/// [`Members::emergency_secret`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyPart {
    Email,
    Password,
    Totp,
    ApiKey,
}

impl EmergencyPart {
    /// ⚠️ Stored: a renamed suffix orphans the secret already kept under it.
    fn suffix(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Password => "password",
            Self::Totp => "totp",
            Self::ApiKey => "api-key",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(level: Role) -> RoleView<'static> {
        RoleView {
            id: "family",
            name: "Family \"home\"",
            level,
        }
    }

    #[test]
    fn a_level_claim_takes_the_highest_entry_at_or_below_the_role() {
        let c: Claim =
            serde_yaml_ng::from_str("byLevel: { viewer: Viewer, operator: Editor, admin: Admin }")
                .expect("claim");
        assert_eq!(
            c.value_for(role(Role::User)),
            None,
            "below every entry: none"
        );
        assert_eq!(
            c.value_for(role(Role::Viewer)),
            Some(serde_json::json!("Viewer"))
        );
        assert_eq!(
            c.value_for(role(Role::Admin)),
            Some(serde_json::json!("Admin"))
        );
        let gitea: Claim =
            serde_yaml_ng::from_str("byLevel: { user: user, admin: admin }").expect("claim");
        assert_eq!(
            gitea.value_for(role(Role::Operator)),
            Some(serde_json::json!("user")),
            "an operator of the cluster administers no app that says admin"
        );
    }

    #[test]
    fn a_json_claim_is_filled_inside_the_value() {
        // A name carrying a quote stays one string: filled as text then parsed, it
        // would have broken the claim — or written another key into it.
        let c: Claim = serde_yaml_ng::from_str(
            "json: [ { name: \"{{ role.name }}\", oidcID: \"{{ role.group }}\" } ]",
        )
        .expect("claim");
        assert_eq!(
            c.value_for(role(Role::User)),
            Some(serde_json::json!([{ "name": "Family \"home\"", "oidcID": "hlb-family" }]))
        );
    }

    #[test]
    fn a_quota_is_written_in_its_unit_without_rounding() {
        assert_eq!(QuotaUnit::GiB.amount(5 << 30), "5");
        assert_eq!(QuotaUnit::GiB.amount(3 << 29), "1.5");
        assert_eq!(QuotaUnit::Bytes.amount(1234), "1234");
        assert_eq!(QuotaUnit::GiB.claim_value(5 << 30), serde_json::json!(5));
    }

    #[test]
    fn a_token_nothing_fills_stays_as_written() {
        assert_eq!(
            fill("a {{ quota }} b {{ person.sub }} c {{ typo }}", |t| (t
                == "quota")
                .then(|| "5".into())),
            "a 5 b {{ person.sub }} c {{ typo }}"
        );
        assert_eq!(placeholders("x {{ a }}{{b}}"), ["a", "b"]);
    }

    #[test]
    fn a_role_group_names_its_role_and_nothing_else() {
        assert_eq!(group_of("admin-standard"), "hlb-admin-standard");
        assert_eq!(role_of_group("hlb-admin-standard"), Some("admin-standard"));
        assert_eq!(role_of_group("family"), None, "a group made by hand");
        assert_eq!(role_of_group("hlb-Bad Name"), None);
    }
}
