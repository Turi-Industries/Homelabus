//! Roles, the apps they open, and the quotas they carry — as the people screens read
//! them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// What a role allows of mail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct MailLimits {
    pub max_mailboxes: u32,
    pub max_permanent_aliases: u32,
    pub max_temporary_aliases: u32,
    pub max_duration_s: i64,
    /// `None`: the mail server's own.
    #[serde(default)]
    pub quota_bytes: Option<u64>,
}

/// An app a role administers, and what that gives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Opening {
    pub app: String,
    pub display_name: String,
    pub means: String,
}

/// A role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RoleSummary {
    /// 🔴 Stable: its PocketID group is `hlb-<id>`.
    pub id: String,
    pub name: String,
    /// What it may do to Homelabus: `user`, `viewer`, `operator`, `admin`.
    pub level: String,
    pub mail: MailLimits,
    /// Per app, a storage quota in bytes.
    #[serde(default)]
    pub quotas: BTreeMap<String, u64>,
    /// The people holding it.
    #[serde(default)]
    pub holders: Vec<String>,
    /// The installed apps letting it in.
    #[serde(default)]
    pub apps: Vec<String>,
    /// The apps it administers — what giving it really opens.
    #[serde(default)]
    pub opens: Vec<Opening>,
}

/// How an app is entered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Entry {
    /// Its own PocketID client, restricted to the roles' groups.
    Client,
    /// The portal, which checks the groups at every request.
    Portal,
}

/// Who may enter one installed app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AppAccess {
    pub app: String,
    pub display_name: String,
    pub entry: Entry,
    /// The lowest level a role must hold to be let in.
    pub floor: String,
    /// The roles it lets in, by id — those below the floor included, which stay out.
    #[serde(default)]
    pub allowed: Vec<String>,
    /// 🔴 Nobody gets in: no role let in, or one that does not exist.
    pub closed: bool,
    /// It takes a storage quota per role and per person.
    pub quota: bool,
}

/// The roles and the apps, side by side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AccessOverview {
    pub roles: Vec<RoleSummary>,
    pub apps: Vec<AppAccess>,
    /// What the rule could not do as asked: an unknown role closing an app, a role
    /// below an app's floor, someone not in PocketID yet.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// One person's quota in one app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AccountQuota {
    pub app: String,
    /// What applies: `None` is no quota at all.
    #[serde(default)]
    pub bytes: Option<u64>,
    /// Given to them, rather than their role's.
    pub own: bool,
    /// Who gave it, and when — for their own only.
    #[serde(default)]
    pub set_by: Option<String>,
    #[serde(default)]
    pub set_at: Option<String>,
    /// What it last became inside the app: `applied`, `absent` (they never signed in
    /// to it), `failed` — `None` when the app is told by a claim only, or never yet.
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
}

/// A role's definition, as written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleRequest {
    /// For people: 2 to 50 characters. Absent, the id.
    #[serde(default)]
    pub name: Option<String>,
    /// `user`, `viewer`, `operator` or `admin`. Absent: the role's, or `user`.
    #[serde(default)]
    pub level: Option<String>,
    /// Absent: the role's, or a standard account's.
    #[serde(default)]
    pub mail: Option<MailLimits>,
}

/// A storage quota to set: absent, none.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct QuotaRequest {
    #[serde(default)]
    pub bytes: Option<u64>,
}

/// A person's own quota in an app: `bytes`, or `none` for no quota at all — neither
/// gives them their role's again.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PersonQuotaRequest {
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default)]
    pub none: bool,
}
