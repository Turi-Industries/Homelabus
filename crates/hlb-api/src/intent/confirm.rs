//! A passkey per destruction.
//!
//! 🔴 An intruder in the web side holds every intent a signed-in person can ask. For
//! the few that destroy — an app removed, a node drained, a role deleted or given —
//! that is too much: where PocketID signs people in, the daemon acts on one only once
//! a person has just presented their passkey for it. The daemon exchanges PocketID's
//! code itself, so the web side cannot forge the answer, and the `nonce` it asked
//! with is the digest of the intents confirmed, so one passkey acts once, on those.

use hlb_types::rbac::Action;
use serde::{Deserialize, Serialize};

use super::Intent;

/// Where PocketID sends the browser back with a confirmation's code: the web side's
/// page handing it to the panel that asked.
pub const CALLBACK: &str = "/auth/confirmed";

/// What PocketID's return to [`CALLBACK`] carried.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub state: String,
    /// 🔴 Never printed: with the daemon's PKCE check it is the passkey's answer.
    pub code: String,
}

impl std::fmt::Debug for Proof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// An intent, with the passkey that confirmed it. Its answer is the intent's own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmed {
    pub proof: Proof,
    pub asked: Box<Intent>,
}

impl From<Confirmed> for Intent {
    fn from(c: Confirmed) -> Self {
        Intent::Confirmed(c)
    }
}

/// Begin confirming these intents — one action, possibly several intents (a role given
/// to a selection) — with a passkey: the PocketID address to send the browser to.
/// `None` where nothing signs in by passkey, and nothing is asked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginConfirmation {
    pub intents: Vec<Intent>,
}

impl Intent {
    /// What the person confirming this intent must be allowed to do, when it takes a
    /// passkey; `None` when it does not.
    ///
    /// 🔴 No `_ =>` arm: an intent added to the enum is decided here.
    pub fn passkey(&self) -> Option<Action> {
        match self {
            Intent::Remove(i) => i.apply.then_some(Action::Destroy),
            // Back to `active` takes nothing away.
            Intent::NodeAvailability(i) => {
                (i.apply && i.availability != "active").then_some(Action::Operate)
            }
            Intent::DeleteRole(_) | Intent::SetUserRole(_) => Some(Action::ManageAccounts),
            // A confirmation is decided for what it wraps.
            Intent::Scale(_)
            | Intent::Nodes(_)
            | Intent::Swarm(_)
            | Intent::Install(_)
            | Intent::Upgrade(_)
            | Intent::CatalogChanges(_)
            | Intent::AttestGuide(_)
            | Intent::BackUp(_)
            | Intent::PurgeAlias(_)
            | Intent::KitFingerprint(_)
            | Intent::SignInClient(_)
            | Intent::Alerts(_)
            | Intent::Drifts(_)
            | Intent::Fleet(_)
            | Intent::MyIdentity(_)
            | Intent::Rename(_)
            | Intent::DefaultMailbox(_)
            | Intent::CreateAlias(_)
            | Intent::CreateMailbox(_)
            | Intent::SignUp(_)
            | Intent::SyncRoles(_)
            | Intent::PortalRoles(_)
            | Intent::Audit(_)
            | Intent::OpenSession(_)
            | Intent::TouchSession(_)
            | Intent::CloseSession(_)
            | Intent::CloseSessionByReference(_)
            | Intent::BindIdentity(_)
            | Intent::TouchToken(_)
            | Intent::IssueAliasToken(_)
            | Intent::PutRole(_)
            | Intent::SetRoleQuota(_)
            | Intent::AllowRole(_)
            | Intent::DenyRole(_)
            | Intent::SetPersonQuota(_)
            | Intent::CreateInvitation(_)
            | Intent::RevokeInvitation(_)
            | Intent::SetDestinationClasses(_)
            | Intent::SetAliasFolder(_)
            | Intent::SaveNamedPlan(_)
            | Intent::AttestBreakglass(_)
            | Intent::SetTheme(_)
            | Intent::SetDensity(_)
            | Intent::SetHome(_)
            | Intent::PublishAnnouncement(_)
            | Intent::FollowAnnouncement(_)
            | Intent::RemoveAnnouncement(_)
            | Intent::SetBrand(_)
            | Intent::SetAside(_)
            | Intent::BringBack(_)
            | Intent::MuteAlert(_)
            | Intent::UnmuteAlert(_)
            | Intent::SetLogo(_)
            | Intent::RecordHistory(_)
            | Intent::Confirmed(_)
            | Intent::BeginConfirmation(_) => None,
        }
    }

    /// The digest a passkey confirms: of this intent as it travels.
    pub fn digest(&self) -> String {
        digest(self)
    }
}

/// The `nonce` a confirmation of `intents` is asked with.
pub fn nonce(intents: &[Intent]) -> String {
    digest(&intents)
}

fn digest<T: Serialize + ?Sized>(v: &T) -> String {
    // A struct's fields serialise in their declared order: the same intent, the same
    // bytes, on both sides of the socket.
    let bytes = serde_json::to_vec(v).unwrap_or_default();
    hlb_types::token::base64url(&hlb_types::token::sha256_bytes(&bytes))
}
