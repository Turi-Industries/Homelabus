//! What the web side may ASK the privileged side to do.
//!
//! ## Why intents, and not a narrow Docker API
//!
//! A route that relays a service specification protects nothing: a spec binds any host
//! path, and whoever writes one is root on the node. So the web side never says HOW —
//! it says "scale gitea to three", "drain this node", and the privileged side
//! re-derives everything else from the catalog and its own state, refusing what it
//! cannot derive. An intruder in the web side can then do what a signed-in person's
//! intents can, and no more: no secret read, no host path, no `exec`.
//!
//! ## 🔴 One enum, matched exhaustively
//!
//! [`Intent`] is every privileged thing a handler can ask, and the privileged side
//! dispatches it with one `match` that has no `_ =>` arm: an intent added here breaks
//! that match until it is answered. Each intent is also its own struct implementing
//! [`Ask`], which names the type of its answer — so a caller gets the answer typed,
//! while the wire carries one enum.
//!
//! Every type here is serialisable both ways, and the privileged side round-trips each
//! answer through JSON even in process: the day the two sides become two processes,
//! the wire is the one already tested.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::ActionResult;

mod confirm;
mod record;
pub use confirm::*;
pub use record::*;

/// An intent, with the type of its answer.
pub trait Ask: Into<Intent> {
    type Answer: Serialize + DeserializeOwned;
}

/// Every privileged thing the web side may ask.
///
/// `PartialEq` only: a measurement carries an `f64`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "intent", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Intent {
    Scale(Scale),
    NodeAvailability(NodeAvailability),
    Nodes(Nodes),
    Swarm(Swarm),
    Install(Install),
    Upgrade(Upgrade),
    CatalogChanges(CatalogChanges),
    AttestGuide(AttestGuide),
    Remove(Remove),
    BackUp(BackUp),
    PurgeAlias(PurgeAlias),
    KitFingerprint(KitFingerprint),
    SignInClient(SignInClient),
    Alerts(Alerts),
    Drifts(Drifts),
    Fleet(Fleet),
    MyIdentity(MyIdentity),
    Rename(Rename),
    DefaultMailbox(DefaultMailbox),
    CreateAlias(CreateAlias),
    CreateMailbox(CreateMailbox),
    SignUp(SignUp),
    SyncRoles(SyncRoles),
    PortalRoles(PortalRoles),
    Audit(Audit),
    OpenSession(OpenSession),
    TouchSession(TouchSession),
    CloseSession(CloseSession),
    CloseSessionByReference(CloseSessionByReference),
    BindIdentity(BindIdentity),
    TouchToken(TouchToken),
    IssueAliasToken(IssueAliasToken),
    PutRole(PutRole),
    DeleteRole(DeleteRole),
    SetRoleQuota(SetRoleQuota),
    AllowRole(AllowRole),
    DenyRole(DenyRole),
    SetPersonQuota(SetPersonQuota),
    SetUserRole(SetUserRole),
    CreateInvitation(CreateInvitation),
    RevokeInvitation(RevokeInvitation),
    SetDestinationClasses(SetDestinationClasses),
    SetAliasFolder(SetAliasFolder),
    SaveNamedPlan(SaveNamedPlan),
    AttestBreakglass(AttestBreakglass),
    SetTheme(SetTheme),
    SetDensity(SetDensity),
    SetHome(SetHome),
    PublishAnnouncement(PublishAnnouncement),
    FollowAnnouncement(FollowAnnouncement),
    RemoveAnnouncement(RemoveAnnouncement),
    SetBrand(SetBrand),
    SetAside(SetAside),
    BringBack(BringBack),
    MuteAlert(MuteAlert),
    UnmuteAlert(UnmuteAlert),
    SetLogo(SetLogo),
    RecordHistory(RecordHistory),
    Confirmed(Confirmed),
    BeginConfirmation(BeginConfirmation),
}

macro_rules! asks {
    ($($variant:ident => $answer:ty),* $(,)?) => {
        $(
            impl From<$variant> for Intent {
                fn from(i: $variant) -> Self {
                    Intent::$variant(i)
                }
            }

            impl Ask for $variant {
                type Answer = $answer;
            }
        )*
    };
}

asks! {
    Scale => ActionResult,
    NodeAvailability => ActionResult,
    Nodes => Option<Result<Vec<hlb_types::swarm::NodeInfo>, String>>,
    Swarm => Option<SwarmView>,
    Install => Acted,
    Upgrade => Acted,
    CatalogChanges => Vec<String>,
    AttestGuide => ActionResult,
    Remove => ActionResult,
    BackUp => ActionResult,
    PurgeAlias => ActionResult,
    KitFingerprint => Option<String>,
    SignInClient => SignInSetup,
    Alerts => Vec<crate::ActiveAlert>,
    Drifts => Vec<crate::DriftSummary>,
    Fleet => std::collections::BTreeMap<String, Result<serde_json::Value, String>>,
    MyIdentity => crate::MyIdentity,
    Rename => ActionResult,
    DefaultMailbox => Acted,
    CreateAlias => Result<String, Refusal>,
    CreateMailbox => Acted,
    SignUp => SignedUp,
    SyncRoles => Result<RolesSynced, String>,
    PortalRoles => Result<(), String>,
    Audit => Result<(), String>,
    OpenSession => Result<(), String>,
    TouchSession => Result<(), String>,
    CloseSession => Result<bool, String>,
    CloseSessionByReference => Result<bool, String>,
    BindIdentity => Result<bool, String>,
    TouchToken => Result<(), String>,
    IssueAliasToken => Result<(), Refusal>,
    PutRole => Result<(), String>,
    DeleteRole => Result<bool, String>,
    SetRoleQuota => Result<(), String>,
    AllowRole => Result<bool, String>,
    DenyRole => Result<bool, String>,
    SetPersonQuota => Result<(), String>,
    SetUserRole => Result<(), String>,
    CreateInvitation => Result<(), String>,
    RevokeInvitation => Result<bool, String>,
    SetDestinationClasses => Result<(), String>,
    SetAliasFolder => Result<(), String>,
    SaveNamedPlan => Result<(), String>,
    AttestBreakglass => Result<(), String>,
    SetTheme => Result<(), String>,
    SetDensity => Result<(), String>,
    SetHome => Result<(), String>,
    PublishAnnouncement => Result<i64, String>,
    FollowAnnouncement => Result<(), String>,
    RemoveAnnouncement => Result<bool, String>,
    SetBrand => Result<(), String>,
    SetAside => Result<(), String>,
    BringBack => Result<bool, String>,
    MuteAlert => Result<(), String>,
    UnmuteAlert => Result<bool, String>,
    SetLogo => Result<(), String>,
    RecordHistory => Result<(), String>,
    BeginConfirmation => Result<Option<String>, String>,
}

/// The answer of an action that may not even be planned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Acted {
    /// The plan, previewed or applied.
    Planned(ActionResult),
    /// Nothing could be planned — no catalog, an unknown app, a run that stopped —
    /// and this says why.
    Unplannable(String),
}

/// Run an application's service with this many replicas, and keep that decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scale {
    pub app: String,
    /// `None` = the caller sent none: refused, never defaulted.
    pub replicas: Option<u64>,
    pub apply: bool,
}

/// Set a Swarm node's availability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAvailability {
    /// Swarm's id for the node, or its hostname: Docker takes either.
    pub node: String,
    /// `active`, `pause` or `drain`; anything else is refused.
    pub availability: String,
    /// The node's name repeated, accepting the downtime a drain announces.
    pub confirmed: Option<String>,
    pub apply: bool,
}

/// The cluster's nodes as Swarm lists them; `None` when no orchestrator is reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nodes {}

/// What runs where: the nodes, and the tasks of one service or of all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Swarm {
    pub service: Option<String>,
}

/// Swarm's nodes and tasks, as read. A side that failed to read is empty: the screens
/// show the nodes without their tasks rather than nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmView {
    pub nodes: Vec<hlb_types::swarm::NodeInfo>,
    pub tasks: Vec<hlb_types::swarm::TaskInfo>,
}

/// Install an application from the catalog, or resume its interrupted install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Install {
    pub app: String,
    /// The domain a person chose; `None` takes the installation's default.
    pub domain: Option<String>,
    pub mail_domain: Option<String>,
    pub apply: bool,
}

/// Bring an installed application to its catalog manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upgrade {
    pub app: String,
    pub apply: bool,
}

/// What the catalog has changed in an installed application, field by field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogChanges {
    pub app: String,
}

/// Attest that a manual step was done — checked first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestGuide {
    pub app: String,
    pub id: String,
    /// Attest even against the step's own check.
    pub force: bool,
    pub apply: bool,
}

/// Remove an application; its volumes are kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remove {
    pub app: String,
    /// The app's name repeated: checked by the privileged side, never on trust.
    pub confirmed: Option<String>,
    pub apply: bool,
}

/// Back one application up now, whether due or not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackUp {
    pub app: String,
    pub apply: bool,
}

/// Purge one of an account's own expired-but-still-active aliases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeAlias {
    /// The account the web side vouches is asking; `None` = nobody signed in.
    pub account: Option<String>,
    pub local: String,
    pub apply: bool,
}

/// The fingerprint an emergency kit printed now would carry; `None` without a vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KitFingerprint {}

/// What the web side needs to sign people in through PocketID, as `hlb fleet
/// controller` registered it — the web side opens no vault.
///
/// 🔴 The one secret the web side is handed: its OWN client's, which it must present to
/// PocketID at every sign-in. The intent names no secret, so it can be asked for no other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignInClient {}

/// The answer to [`SignInClient`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignInSetup {
    /// The root the ingress's certificates chain to when no public authority signed
    /// them: without it PocketID's issuer is unverifiable. A certificate, not a key.
    pub trusted_root: Option<String>,
    /// `None` until PocketID is installed and the client registered.
    pub client: Option<OidcClient>,
}

/// The web side's sign-in client in PocketID.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcClient {
    pub issuer: String,
    pub id: String,
    pub secret: String,
}

// By hand: a derived `Debug` would print the secret into whatever logs an answer.
impl std::fmt::Debug for OidcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcClient")
            .field("issuer", &self.issuer)
            .field("id", &self.id)
            .field("secret", &"…")
            .finish()
    }
}

/// The alerts the daemon's last evaluation found, muted ones included, before the
/// mutes are applied: the web side applies them at answer time, so a mute set a second
/// ago shows at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alerts {}

/// The gaps reconciliation's last pass left — refused, or not corrected yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Drifts {}

/// What the agents' poller last found, by agent address: a report as JSON, or why the
/// node did not answer. JSON because this crate cannot depend on the agent's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fleet {}

/// A signed-in person's names and address, as PocketID holds them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MyIdentity {
    pub account: String,
}

/// Write a person's own names to PocketID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rename {
    /// The account the web side vouches is asking; `None` = nobody signed in.
    pub account: Option<String>,
    pub first_name: String,
    pub last_name: String,
    pub display_name: String,
    pub apply: bool,
}

/// Make one of a person's own mailboxes their default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultMailbox {
    /// The account the web side vouches is asking; `None` = nobody signed in.
    pub account: Option<String>,
    pub local: String,
    pub apply: bool,
}

/// Create an alias on an account's mailbox, for the addy.io API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAlias {
    /// The account the web side vouches is asking.
    pub account: String,
    /// The mailbox the asking token is bound to; `None` = the default mailbox.
    pub mailbox: Option<String>,
    /// The domain the client asked for: honoured only if it is the mailbox's.
    pub domain: Option<String>,
    pub description: Option<String>,
}

/// Why a request the addy.io contract answers with a status was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Refusal {
    Conflict(String),
    Unprocessable(String),
    TooMany(String),
    Internal(String),
}

/// Create a person's own mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateMailbox {
    /// The account the web side vouches is asking; `None` = nobody signed in.
    pub account: Option<String>,
    pub local: String,
}

/// Create an account from an invitation, or preview it without using the link.
///
/// 🔴 The invitation IS the authorization: nobody is signed in yet, so the privileged
/// side checks the link itself rather than take the web side's word for it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignUp {
    /// The invitation token, as the URL fragment carried it.
    pub invitation: String,
    pub name: String,
    pub display_name: Option<String>,
    pub apply: bool,
}

// By hand: a derived `Debug` would print the token into whatever logs an intent.
impl std::fmt::Debug for SignUp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignUp")
            .field("invitation", &"…")
            .field("name", &self.name)
            .field("display_name", &self.display_name)
            .field("apply", &self.apply)
            .finish()
    }
}

/// A sign-up's plan or outcome. Applied, `result.applied` false means refused before
/// anything was written; true means the account exists, whatever its steps say.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedUp {
    pub result: ActionResult,
    /// 🔴 PocketID's single-use enrolment link: shown once, never stored nor logged.
    pub enrolment_link: Option<String>,
}

/// Make PocketID and the apps hold the roles: preview what differs, or put it right.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRoles {
    pub apply: bool,
}

/// What a role sync found or did, one step per thing that differed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RolesSynced {
    pub steps: Vec<crate::ActionStep>,
    /// What the rule could not do as asked.
    pub notes: Vec<String>,
}

/// Carry an app's roles to the portal, after they changed: the groups of an app
/// behind it are in the Caddyfile, and nothing else takes them to Caddy. Nothing to do
/// for an app that signs its people in itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortalRoles {
    pub app: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_intent_travels_as_one_tagged_object() {
        let i: Intent = Scale {
            app: "gitea".into(),
            replicas: Some(3),
            apply: false,
        }
        .into();
        let wire = serde_json::to_value(&i).expect("serialise");
        assert_eq!(wire["intent"], "scale");
        assert_eq!(
            serde_json::from_value::<Intent>(wire).expect("deserialise"),
            i
        );
    }

    #[test]
    fn an_intent_with_a_field_the_daemon_does_not_know_is_refused() {
        let wire = serde_json::json!({
            "intent": "scale", "app": "gitea", "replicas": 3, "apply": true,
            "image": "evil/latest"
        });
        assert!(serde_json::from_value::<Intent>(wire).is_err());
    }
}
