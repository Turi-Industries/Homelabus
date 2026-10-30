//! Human accounts, invitations and sign-up (batch 6).
//!
//! ## 🔴 A half-created account looks functional
//!
//! This is the module's central trap. Creating an account is three operations on three
//! systems: a PocketID identity, a Stalwart mailbox, a row in the database. If the
//! second fails, the person signs in everywhere and their address receives nothing —
//! discovered on the first lost email, often a password reset.
//!
//! Hence: the state is **named** (`Coherence`), creation is **resumable**, and the
//! management screen shows the halves in red.
//!
//! ## And the invitation does not let you choose your role
//!
//! The role is fixed **at invitation time**, not by the invitee. Otherwise anyone
//! would sign up as an administrator.

use std::sync::Arc;

use crate::extract::{Json, Path, Query};
use axum::extract::State as AxumState;
use hlb_api::intent::SignedUp;
use hlb_api::{ActionResult, ActionStep, StepState};

use crate::actions::ActionQuery;
use crate::api::AppState;
use crate::auth::{Authorized, CanManageAccounts};
use crate::error::{ActionError, ActionReply};

/// ⚠️ Configurable, unlike the hard-coded `"12h"` of the PocketID link.
pub use hlb_api::invitation::{DEFAULT_S as INVITATION_DURATION_S, USES_WORTH_FLAGGING};

/// The list of accounts, with their coherence state.
#[utoipa::path(
    get,
    path = "/api/accounts",
    responses(
        (status = 200, body = Vec<hlb_api::AccountSummary>)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts"))
    )
)]
pub async fn list(
    _auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::AccountSummary>> {
    Json(resumes(&s).await)
}

/// The accounts, as the API presents them.
///
/// ⚠️ Extracted from the handler because the CSV export needs it too: two assemblies of
/// the same account would end up showing one coherence state on screen and another in
/// the file you hand to someone.
pub async fn resumes(s: &AppState) -> Vec<hlb_api::AccountSummary> {
    let now = crate::auth::now();
    let holders = s.state.users_with_roles().await.unwrap_or_default();
    // Read once for everyone: per account, this list was four queries and a scan of the
    // whole user table — 1.2 s at a thousand accounts, on a list every open page polls.
    let mut accounts: std::collections::BTreeMap<String, hlb_users::Account> = s
        .state
        .accounts()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|a| (a.name.clone(), a))
        .collect();
    let mut sessions: std::collections::BTreeMap<String, usize> = Default::default();
    for session in s.state.all_sessions(now).await.unwrap_or_default() {
        *sessions.entry(session.user).or_default() += 1;
    }
    let quotas = Quotas::read(s).await;

    let mut out = Vec::new();
    for h in holders {
        let name = h.user.clone();
        let Some(account) = accounts.remove(&name) else {
            continue;
        };

        let coherence = match account.coherence() {
            hlb_users::Coherence::Complete => hlb_api::AccountState::Complete,
            hlb_users::Coherence::WithoutMailbox => hlb_api::AccountState::WithoutMailbox,
            hlb_users::Coherence::WithoutIdentity => hlb_api::AccountState::WithoutIdentity,
            hlb_users::Coherence::Empty => hlb_api::AccountState::Empty,
        };

        let usage = account.usage(now);
        out.push(hlb_api::AccountSummary {
            explanation: account.coherence().describe().to_string(),
            coherence,
            name: name.clone(),
            role_name: h
                .role
                .as_deref()
                .and_then(|r| quotas.roles.get(r))
                .map(|r| r.name.clone()),
            quotas: quotas.of(&name, h.role.as_deref()),
            role: h.role,
            level: h.level.as_str().to_string(),
            granted_by: h.granted_by,
            pocket_id: account.pocket_id.clone(),
            mailboxes: account
                .mailboxes
                .iter()
                .map(|b| hlb_api::MailboxBrief {
                    address: b.address(),
                    default: b.default,
                })
                .collect(),
            active_aliases: (usage.permanent_aliases + usage.temporary_aliases) as usize,
            // 🔴 The expired aliases that STILL receive: the purge has not run, and the
            // address you believe closed stays open. It is the only state that betrays
            // a promise made to the user.
            broken_promises: account.broken_promises(now).len(),
            sessions: sessions.get(&name).copied().unwrap_or(0),
        });
    }

    // The broken accounts first: across twenty accounts, a half-created one would get
    // lost in the middle of an alphabetical sort.
    out.sort_by(|a, b| {
        b.coherence
            .attention()
            .cmp(&a.coherence.attention())
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

/// Everything a person's quotas are computed from, read once for the whole list.
struct Quotas {
    roles: std::collections::BTreeMap<String, hlb_users::RoleDef>,
    own: std::collections::BTreeMap<String, Vec<hlb_state::PersonQuota>>,
    applied: std::collections::BTreeMap<(String, String), hlb_state::QuotaRecord>,
    /// The apps taking a quota: `(app, floor, roles it lets in)`.
    apps: Vec<(String, hlb_types::Role, std::collections::BTreeSet<String>)>,
}

impl Quotas {
    async fn read(s: &AppState) -> Self {
        let mut allowed = s.state.app_roles().await.unwrap_or_default();
        let mut apps = Vec::new();
        for (name, _) in s.state.installed_apps().await.unwrap_or_default() {
            let Ok(m) = s.state.app_manifest(&name).await else {
                continue;
            };
            if m.spec.access.as_ref().is_some_and(|a| a.quota.is_some()) {
                let floor = hlb_users::access::floor_of(&m);
                apps.push((
                    name.clone(),
                    floor,
                    allowed.remove(&name).unwrap_or_default(),
                ));
            }
        }
        Self {
            roles: s
                .state
                .roles()
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|r| (r.id.clone(), r))
                .collect(),
            own: s.state.person_quotas().await.unwrap_or_default(),
            applied: s.state.quotas_applied().await.unwrap_or_default(),
            apps,
        }
    }

    /// One person's, in every app their role lets them into that takes one.
    fn of(&self, user: &str, role: Option<&str>) -> Vec<hlb_api::roles::AccountQuota> {
        let Some(role) = role.and_then(|r| self.roles.get(r)) else {
            return Vec::new();
        };
        self.apps
            .iter()
            .filter(|(_, floor, allowed)| allowed.contains(&role.id) && role.level >= *floor)
            .map(|(app, _, _)| {
                let own = self
                    .own
                    .get(user)
                    .and_then(|qs| qs.iter().find(|q| &q.app == app));
                let applied = self.applied.get(&(user.to_string(), app.clone()));
                hlb_api::roles::AccountQuota {
                    app: app.clone(),
                    bytes: own.map_or_else(|| role.quotas.get(app).copied(), |q| q.bytes),
                    own: own.is_some(),
                    set_by: own.map(|q| q.set_by.clone()),
                    set_at: own.map(|q| q.set_at.clone()),
                    state: applied.map(|r| match r.state {
                        hlb_state::QuotaState::Applied => "applied".to_string(),
                        hlb_state::QuotaState::Absent => "absent".to_string(),
                        hlb_state::QuotaState::Failed => "failed".to_string(),
                    }),
                    detail: applied.and_then(|r| r.detail.clone()),
                }
            })
            .collect()
    }
}

/// Invitations pending.
#[utoipa::path(
    get,
    path = "/api/invitations",
    responses(
        (status = 200, body = Vec<hlb_api::InvitationSummary>)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts"))
    )
)]
pub async fn invitations(
    _auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<Vec<hlb_api::InvitationSummary>> {
    Json(
        s.state
            .invitations(crate::auth::now())
            .await
            .unwrap_or_default(),
    )
}

#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
pub struct InvitationRequest {
    /// The role's id. Required: a link granting a role nobody chose is one nobody
    /// should send.
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    /// Lifetime in seconds.
    #[serde(default)]
    pub duration_s: Option<i64>,
    /// How many people can use it. **1 by default**, the safe case.
    #[serde(default)]
    pub max_uses: Option<i64>,
}

/// The response to creating an invitation.
///
/// 🔴 The only place in the system where an invitation link's value appears. It is not
/// stored, not logged, and will never be shown again.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct InvitationCreated {
    /// ⚠️ FLATTENED: every action route returns the same shape, with `applied`,
    /// `steps` and `blockers` at the ROOT. A special wrapping would force the
    /// interface to handle two formats — and the test that checks preview-by-default
    /// would not see this route.
    #[serde(flatten)]
    pub result: ActionResult,
    /// The full link, shown **once only**.
    pub link: Option<String>,
}

/// Creates an invitation.
#[utoipa::path(
    post,
    path = "/api/invitations",
    params(crate::actions::ActionQuery),
    request_body = Option<InvitationRequest>,
    responses(
        (status = 200, body = InvitationCreated),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = InvitationCreated)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn create_invitation(
    auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<InvitationRequest>>,
) -> ActionReply<InvitationCreated> {
    let d = body.map(|Json(d)| d).unwrap_or_default();
    let mut blockers = Vec::new();

    let role = match d.role.as_deref() {
        None => {
            blockers
                .push("say which role the account will hold — `hlb role list` names them".into());
            None
        }
        Some(id) => match s.state.role(id).await.ok().flatten() {
            Some(r) => Some(r),
            None => {
                blockers.push(format!("no role \"{id}\" — `hlb role list` names them"));
                None
            }
        },
    };
    let Some(role) = role else {
        return render(
            &s,
            auth.identity(),
            "invitation",
            "-",
            ActionResult {
                applied: false,
                summary: "create an invitation".into(),
                steps: Vec::new(),
                cli_command: "hlb user invite --role <role> --apply".into(),
                blockers,
                warnings: Vec::new(),
                confirmation_required: None,
            },
            None,
        )
        .await;
    };

    // 🔴 These WARN, they do not block. Inviting a second administrator or a team
    // of five are legitimate choices; filing them among the blockers
    // would make them impossible.
    let mut warnings = Vec::new();
    if role.level == hlb_types::Role::Admin {
        warnings.push(
            "this invitation will grant an ADMIN role: the person will be able to \
             grant roles and destroy data"
                .to_string(),
        );
    }
    for o in hlb_engine::roles::opened_by(&s.state, &role)
        .await
        .unwrap_or_default()
    {
        warnings.push(format!("it administers {}: {}", o.display_name, o.means));
    }

    // Bounded on both sides by `limits::BOUNDS`, refused before this handler runs: an
    // hour at least, thirty days and fifty people at most.
    let duration = d.duration_s.unwrap_or(INVITATION_DURATION_S);
    let uses = d.max_uses.unwrap_or(1);
    if uses > USES_WORTH_FLAGGING {
        warnings.push(format!(
            "this link will let {} in: if it leaks, that is as many accounts created",
            hlb_api::plural(uses as u64, "person", "people")
        ));
    }

    let applied = q.apply && blockers.is_empty();

    let mut step = ActionStep {
        description: format!(
            "create a \"{}\" invitation, valid {}, for {}",
            role.label(),
            hlb_api::humanise(duration),
            hlb_api::plural(uses as u64, "person", "people")
        ),
        state: StepState::Planned,
        error: None,
    };

    let mut link = None;
    if applied {
        let mut raw = [0u8; 32];
        hlb_secrets::fill_random(&mut raw);
        let value = hlb_types::token::base32(&raw);

        let asked = hlb_api::intent::CreateInvitation {
            presented: value.clone(),
            created_by: auth.actor().name().to_string(),
            role: role.id.clone(),
            now: crate::auth::now(),
            duration_s: duration,
            max_uses: uses,
            note: d.note.clone(),
        };
        match s.record(asked).await {
            Ok(()) => {
                step.state = StepState::Done;
                link = Some(hlb_api::invitation::link_path(&value));
            }
            Err(e) => {
                step.state = StepState::Failed;
                step.error = Some(e.to_string());
            }
        }
    }

    let r = ActionResult {
        applied,
        summary: "create an invitation".into(),
        steps: vec![step],
        cli_command: format!("hlb user invite --role {} --uses {uses} --apply", role.id),
        blockers,
        warnings,
        confirmation_required: None,
    };

    render(&s, auth.identity(), "invitation", "-", r, link).await
}

/// Revokes a pending invitation.
#[utoipa::path(
    delete,
    path = "/api/invitations/{reference}",
    params(crate::actions::ActionQuery),
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn revoke_invitation(
    auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(reference): Path<String>,
    Query(q): Query<ActionQuery>,
) -> ActionReply {
    let applied = q.apply;
    let mut step = ActionStep {
        description: format!("revoke invitation \"{reference}\""),
        state: StepState::Planned,
        error: None,
    };
    let mut blockers = Vec::new();

    if applied {
        let asked = hlb_api::intent::RevokeInvitation {
            reference: reference.clone(),
        };
        match s.record(asked).await {
            Ok(true) => step.state = StepState::Done,
            Ok(false) => {
                step.state = StepState::Failed;
                // ⚠️ A USED invitation is not erased: deleting it would erase the trace
                // of who created which account.
                step.error = Some(
                    "no pending invitation under this reference — an invitation already \
                     used stays in the register, that is the history"
                        .into(),
                );
            }
            Err(e) => {
                step.state = StepState::Failed;
                step.error = Some(e.to_string());
            }
        }
    } else {
        blockers.clear();
    }

    let r = ActionResult {
        applied,
        summary: format!("revoke invitation \"{reference}\""),
        steps: vec![step],
        cli_command: format!("hlb user revoke-invitation {reference} --apply"),
        blockers,
        warnings: Vec::new(),
        confirmation_required: None,
    };

    respond(&s, auth.identity(), "invitation-revoke", &reference, r).await
}

/// What giving a role opens, said before it is given: the ADMIN level, and every app it
/// administers — computed from the manifests.
async fn elevation_warnings(s: &AppState, role: &hlb_users::RoleDef, people: usize) -> Vec<String> {
    let mut w = Vec::new();
    if role.level == hlb_types::Role::Admin {
        w.push(format!(
            "{} the ADMIN level: they will be able to grant rights and destroy data",
            if people == 1 {
                "this gives".to_string()
            } else {
                format!("{people} people get")
            }
        ));
    }
    for o in hlb_engine::roles::opened_by(&s.state, role)
        .await
        .unwrap_or_default()
    {
        w.push(format!("it administers {}: {}", o.display_name, o.means));
    }
    w
}

fn no_role(id: &str, roles: &[hlb_users::RoleDef]) -> String {
    format!(
        "no role \"{id}\" — {}",
        roles
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Changes a person's role.
#[utoipa::path(
    post,
    path = "/api/accounts/{account}/role/{role}",
    params(crate::actions::ActionQuery),
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult),
        (status = 428, description = "Applying it needs a passkey: present one where the header says, then send it again", body = hlb_api::ErrorBody, headers(("x-hlb-passkey-url" = String, description = "Where to present the passkey")))
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn change_role(
    auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path((account, role_id)): Path<(String, String)>,
    Query(q): Query<ActionQuery>,
) -> ActionReply {
    let mut blockers = Vec::new();
    let roles = s.state.roles().await.unwrap_or_default();
    let Some(role) = roles.iter().find(|r| r.id == role_id).cloned() else {
        blockers.push(no_role(&role_id, &roles));
        return respond(
            &s,
            auth.identity(),
            "user-role",
            &account,
            ActionResult {
                applied: false,
                summary: format!("change {account}'s role"),
                steps: Vec::new(),
                cli_command: format!("hlb user role {account} <role> --apply"),
                blockers,
                warnings: Vec::new(),
                confirmation_required: None,
            },
        )
        .await;
    };

    // A role granted to a name nobody has is an orphan row, inherited by whoever is
    // created under that name later — the CLI refused it; this route did not.
    if !s
        .state
        .users()
        .await
        .unwrap_or_default()
        .iter()
        .any(|(n, _, _)| n == &account)
    {
        blockers.push(format!("unknown account \"{account}\""));
    }

    let current = s
        .state
        .role_of(&account)
        .await
        .unwrap_or_else(|_| hlb_users::RoleDef::nothing());

    // 🔴 Demoting the last administrator would leave a system where nobody can grant
    // rights: it would only be repairable by editing SQLite by hand.
    // An unreadable state is a refusal: "another admin, probably" is how the last one
    // goes.
    if current.level == hlb_types::Role::Admin && role.level != hlb_types::Role::Admin {
        match s.state.has_other_admin(&account).await {
            Ok(true) => {}
            Ok(false) => blockers.push(format!(
                "{account} is the ONLY administrator — name someone else first, \
                 or nobody will be able to grant rights any more"
            )),
            Err(e) => blockers.push(format!(
                "the other administrators cannot be read ({e}) — nothing is changed \
                 that could leave none"
            )),
        }
    }
    let warnings = if role.id == current.id {
        Vec::new()
    } else {
        elevation_warnings(&s, &role, 1).await
    };

    let applied = q.apply && blockers.is_empty();
    let mut step = ActionStep {
        description: format!(
            "{account}: \"{}\" to \"{}\"{}",
            current.label(),
            role.label(),
            if role.level > current.level {
                " (privilege ELEVATION)"
            } else {
                ""
            }
        ),
        state: StepState::Planned,
        error: None,
    };

    if applied {
        let asked = hlb_api::intent::SetUserRole {
            user: account.clone(),
            role: role.id.clone(),
            granted_by: Some(auth.actor().name().to_string()),
        };
        let proof = crate::passkey::confirm(&s, &headers, vec![asked.clone().into()]).await?;
        match s.record_confirmed(proof, asked).await {
            Ok(()) => {
                step.state = StepState::Done;
                // Its groups in PocketID now, not at the loop's next pass.
                crate::roles::sync_soon(s.clone());
            }
            Err(e) => {
                step.state = StepState::Failed;
                step.error = Some(e.to_string());
            }
        }
    }

    let r = ActionResult {
        applied,
        summary: format!("{account}: role \"{}\"", role.label()),
        steps: vec![step],
        cli_command: format!("hlb user role {account} {} --apply", role.id),
        blockers,
        warnings,
        confirmation_required: None,
    };

    respond(&s, auth.identity(), "user-role", &account, r).await
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RolesRequest {
    /// The accounts to give the role, as the list's selection named them. Absent, the
    /// selection is empty — said as a blocker, like any plan with nothing to do.
    #[serde(default)]
    pub accounts: Vec<String>,
}

/// Gives one role to several people, as ONE plan.
///
/// 🔴 One preview, one confirmation, one step per person: a preview per account would
/// make a selection of fifty accounts fifty confirmations, and the fiftieth is clicked
/// without being read. The refusals are the single route's, judged over the whole
/// selection — demoting every administrator at once is still demoting the last one.
#[utoipa::path(
    post,
    path = "/api/accounts/role/{role}",
    params(crate::actions::ActionQuery),
    request_body = RolesRequest,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult),
        (status = 428, description = "Applying it needs a passkey: present one where the header says, then send it again", body = hlb_api::ErrorBody, headers(("x-hlb-passkey-url" = String, description = "Where to present the passkey")))
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn change_roles(
    auth: Authorized<CanManageAccounts>,
    AxumState(s): AxumState<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(role_id): Path<String>,
    Query(q): Query<ActionQuery>,
    Json(d): Json<RolesRequest>,
) -> ActionReply {
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let mut accounts = d.accounts;
    accounts.sort();
    accounts.dedup();
    let target = accounts.join(", ");

    let roles = s.state.roles().await.unwrap_or_default();
    let role = roles.iter().find(|r| r.id == role_id).cloned();
    if role.is_none() {
        blockers.push(no_role(&role_id, &roles));
    }
    if accounts.is_empty() {
        blockers.push("no account selected".into());
    }

    let known: std::collections::BTreeMap<String, hlb_state::Holder> =
        match s.state.users_with_roles().await {
            Ok(h) => h.into_iter().map(|h| (h.user.clone(), h)).collect(),
            Err(e) => return Err(e.into()),
        };
    // A role granted to a name nobody has would be an orphan row, inherited later by
    // whoever is created under it — the CLI refuses it, and so does this.
    for unknown in accounts.iter().filter(|a| !known.contains_key(*a)) {
        blockers.push(format!("unknown account \"{unknown}\""));
    }

    let mut steps = Vec::new();
    if let Some(role) = &role {
        // 🔴 Over the selection, not account by account: each administrator alone has
        // another one, and all of them together leave none.
        let admins_left = known
            .values()
            .filter(|h| h.level == hlb_types::Role::Admin && !accounts.contains(&h.user))
            .count();
        let demotes_admin = accounts.iter().any(|a| {
            known
                .get(a)
                .is_some_and(|h| h.level == hlb_types::Role::Admin)
        });
        if role.level != hlb_types::Role::Admin && demotes_admin && admins_left == 0 {
            blockers.push(
                "this selection holds EVERY administrator — keep one, or nobody will be \
                 able to grant rights any more"
                    .into(),
            );
        }
        let changing = accounts
            .iter()
            .filter(|a| {
                known
                    .get(*a)
                    .is_some_and(|h| h.role.as_deref() != Some(role.id.as_str()))
            })
            .count();
        if changing > 0 {
            warnings.extend(elevation_warnings(&s, role, changing).await);
        }

        let applied = q.apply && blockers.is_empty();
        let changed = |a: &String| {
            known
                .get(a)
                .is_some_and(|h| h.role.as_deref() != Some(role.id.as_str()))
        };
        // One passkey for the whole selection: every change is asked for before the
        // first is sent, so a refusal comes before anything moved.
        let asked = |account: &String| hlb_api::intent::SetUserRole {
            user: account.clone(),
            role: role.id.clone(),
            granted_by: Some(auth.actor().name().to_string()),
        };
        let proof = if applied {
            let all = accounts
                .iter()
                .filter(|a| changed(a))
                .map(|a| asked(a).into())
                .collect();
            crate::passkey::confirm(&s, &headers, all).await?
        } else {
            None
        };
        for account in accounts.iter().filter(|a| known.contains_key(*a)) {
            let Some(h) = known.get(account) else {
                continue;
            };
            let held = h.role.clone().unwrap_or_else(|| "no role".into());
            let mut step = ActionStep {
                description: format!(
                    "{account}: \"{held}\" to \"{}\"{}",
                    role.label(),
                    if role.level > h.level {
                        " (privilege ELEVATION)"
                    } else {
                        ""
                    }
                ),
                state: StepState::Planned,
                error: None,
            };
            if h.role.as_deref() == Some(role.id.as_str()) {
                step.description = format!("{account}: already \"{}\"", role.label());
            } else if applied {
                match s.record_confirmed(proof.clone(), asked(account)).await {
                    Ok(()) => step.state = StepState::Done,
                    Err(e) => {
                        step.state = StepState::Failed;
                        step.error = Some(e.to_string());
                    }
                }
            }
            steps.push(step);
        }
        if applied {
            crate::roles::sync_soon(s.clone());
        }
    }

    let r = ActionResult {
        applied: q.apply && blockers.is_empty(),
        summary: format!("{} accounts: role \"{role_id}\"", accounts.len()),
        steps,
        cli_command: accounts
            .iter()
            // Who already has the role has nothing to run.
            .filter(|a| {
                known
                    .get(*a)
                    .is_some_and(|h| h.role.as_deref() != Some(role_id.as_str()))
            })
            .map(|a| format!("hlb user role {a} {role_id} --apply"))
            .collect::<Vec<_>>()
            .join("\n"),
        blockers,
        warnings,
        confirmation_required: None,
    };

    respond(&s, auth.identity(), "user-role", &target, r).await
}

// ---------------------------------------------------------------------------
// Signup free-service (lot 6.3)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
pub struct SignupRequest {
    /// The invitation token, as it arrives from the URL fragment.
    #[serde(default)]
    pub invitation: String,
    /// The desired account name.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// What a successful sign-up returns.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct Registered {
    #[serde(flatten)]
    pub result: ActionResult,
    /// 🔴 The PocketID enrolment link, single-use and shown ONCE.
    ///
    /// PocketID has no password: we therefore do not hand over an initial secret but
    /// this token, which serves to register a passkey. It is neither stored nor logged.
    /// logged.
    pub enrolment_link: Option<String>,
}

/// Creates an account from an invitation.
///
/// ## 🔴 The order of the three operations, and why it matters
///
/// 1. **Consume the invitation** — first, and in a transaction: two simultaneous
///    sign-ups with the same link must not both pass.
/// 2. **Create the account in the database** — that is what makes the state visible
///    even if the rest fails.
/// 3. **PocketID identity, then mailbox** — each can fail, and each failure leaves a
///    NAMED state (`WithoutIdentity`, `WithoutMailbox`) that the management screen shows in red,
///    and that a re-run repairs.
///
/// The reverse — creating everything elsewhere before recording it — would leave
/// orphan identities Homelabus would know nothing about.
///
/// ⚠️ **Without authentication**: it is the invited person who calls, and they do not
/// have an account yet. The invitation IS the authorization.
#[utoipa::path(
    post,
    path = "/api/signup",
    params(crate::actions::ActionQuery),
    request_body = Option<SignupRequest>,
    responses(
        (status = 200, body = Registered),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = Registered)
    ),
    extensions(
        ("x-hlb-public" = json!(true)),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn signup(
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<ActionQuery>,
    body: Option<Json<SignupRequest>>,
) -> ActionReply<Registered> {
    let d = body.map(|Json(d)| d).unwrap_or_default();
    let name = d.name.clone();
    let signed_up = s
        .privd()
        .ask(hlb_api::intent::SignUp {
            invitation: d.invitation,
            name: d.name,
            display_name: d.display_name,
            apply: q.apply,
        })
        .await;
    let SignedUp {
        result,
        enrolment_link,
    } = match signed_up {
        Ok(a) => a,
        Err(e) => return Err(crate::actions::privd_error(e)),
    };

    if !q.apply {
        return Ok(Json(Registered {
            result,
            enrolment_link: None,
        }));
    }
    if !result.applied {
        return refuse_signup(&s, &name, result).await;
    }
    // Their role's apps open to them now, not at the next hourly pass.
    crate::roles::sync_soon(s.clone());
    finish_signup(&s, &name, result, enrolment_link).await
}

async fn refuse_signup(s: &AppState, name: &str, r: ActionResult) -> ActionReply<Registered> {
    // The name is whatever an anonymous caller sent: kept short and printable, it
    // cannot forge a line of the log nor fill it.
    let printable = |t: &str, max: usize| -> String {
        t.chars()
            .take(max)
            .collect::<String>()
            .escape_debug()
            .to_string()
    };
    let _ = s
        .append_audit(
            "signup",
            hlb_types::Role::User,
            "signup",
            &printable(name, 64),
            "refused",
            Some(&printable(&r.blockers.join(" · "), 500)),
        )
        .await;
    Err(ActionError::Unplannable(Box::new(Registered {
        result: r,
        enrolment_link: None,
    })))
}

async fn finish_signup(
    s: &AppState,
    name: &str,
    r: ActionResult,
    link: Option<String>,
) -> ActionReply<Registered> {
    let issue = if r.succeeded() { "ok" } else { "failed" };
    let _ = s
        .append_audit(
            "signup",
            hlb_types::Role::User,
            "signup",
            name,
            issue,
            Some(&r.verdict()),
        )
        .await;

    Ok(Json(Registered {
        result: r,
        enrolment_link: link,
    }))
}

/// Logs an action on accounts, with its real outcome.
async fn audit(
    s: &AppState,
    identity: &crate::auth::Identity,
    action: &str,
    target: &str,
    r: &ActionResult,
) {
    let issue = if !r.applied {
        "preview"
    } else if r.succeeded() {
        "ok"
    } else {
        "failed"
    };

    let _ = s
        .append_audit(
            identity.actor.name(),
            identity.role,
            action,
            target,
            issue,
            Some(&r.verdict()),
        )
        .await;
}

/// Logs and returns the response.
async fn respond(
    s: &AppState,
    identity: &crate::auth::Identity,
    action: &str,
    target: &str,
    r: ActionResult,
) -> ActionReply {
    audit(s, identity, action, target, &r).await;
    Ok(Json(r))
}

/// Logs and returns the response, with the link shown this once.
async fn render(
    s: &AppState,
    identity: &crate::auth::Identity,
    action: &str,
    target: &str,
    r: ActionResult,
    link: Option<String>,
) -> ActionReply<InvitationCreated> {
    audit(s, identity, action, target, &r).await;
    Ok(Json(InvitationCreated { result: r, link }))
}
