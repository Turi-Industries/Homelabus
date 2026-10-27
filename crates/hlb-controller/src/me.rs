//! The signed-in person's own account: their names, their default mailbox, their
//! sessions.
//!
//! 🔴 Every route here acts on `for_account()` — never on an account named in the URL or
//! the body, or one person could rename another, or sign them out.

use std::sync::Arc;

use axum::extract::State as AxumState;
use axum::http::{header, HeaderMap};
use hlb_api::{ActionResult, ActionStep, IdentityLink, StepState};

use crate::actions::{respond, ActionQuery};
use crate::api::AppState;
use crate::auth::{Authorized, CanActOnSelf, CanReadSelf};
use crate::error::ActionReply;
use crate::extract::{Json, Path, Query};

const NOBODY: &str = "this request acts on nobody's behalf — sign in first";

fn planned(description: String) -> ActionStep {
    ActionStep {
        description,
        state: StepState::Planned,
        error: None,
    }
}

/// An argument as a shell reads it: a name with a space or a quote in it is a person's
/// name, and a command line you copy must not split it.
fn quoted(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// The PocketID client and the account's id there, or why there are none.
async fn linked(
    s: &AppState,
    account: &str,
) -> Result<(Arc<hlb_identity::PocketId>, String), IdentityLink> {
    let Some(pid) = &s.identity else {
        return Err(IdentityLink::NotConfigured);
    };
    match s.state.account(account).await {
        Ok(a) => match a.pocket_id {
            Some(id) => Ok((pid.clone(), id)),
            None => Err(IdentityLink::NotLinked),
        },
        Err(_) => Err(IdentityLink::NotLinked),
    }
}

fn unlinked(link: IdentityLink, account: &str) -> String {
    match link {
        IdentityLink::NotConfigured => {
            "PocketID is not configured on this controller (--pocketid-url, --pocketid-key)".into()
        }
        IdentityLink::NotLinked => format!(
            "this account has no PocketID identity yet — an administrator finishes it \
             with \"hlb user add {account} --apply\""
        ),
        IdentityLink::Linked | IdentityLink::Unreachable => "PocketID did not answer".into(),
    }
}

/// PocketID's own account page, where passkeys live. Its PUBLIC address — the issuer
/// sign-in sends browsers to — and not the API's, which may be a name only the
/// controller resolves.
fn passkeys_url(s: &AppState) -> Option<String> {
    s.signin.get().map(|c| {
        format!(
            "{}/settings/account",
            c.oidc.endpoints().issuer.trim_end_matches('/')
        )
    })
}

/// My names and address, as PocketID holds them.
#[utoipa::path(
    get,
    path = "/api/me/identity",
    responses(
        (status = 200, body = hlb_api::MyIdentity)
    ),
    extensions(
        ("x-hlb-requires" = json!("read-self"))
    )
)]
pub async fn my_identity(
    auth: Authorized<CanReadSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<hlb_api::MyIdentity> {
    let mut out = hlb_api::MyIdentity {
        link: IdentityLink::NotLinked,
        first_name: None,
        last_name: None,
        display_name: None,
        email: None,
        passkeys_url: passkeys_url(&s),
    };
    // A service token is nobody, and has no identity to show.
    let Some(account) = auth.actor().for_account() else {
        return Json(out);
    };
    match linked(&s, account).await {
        Err(link) => out.link = link,
        Ok((pid, id)) => match pid.user(&id).await {
            Ok(u) => {
                out.link = IdentityLink::Linked;
                out.first_name = Some(u.first_name);
                out.last_name = Some(u.last_name.unwrap_or_default());
                out.display_name = Some(u.display_name);
                out.email = u.email;
            }
            Err(e) => {
                tracing::warn!(account, error = %e, "PocketID identity unreadable");
                out.link = IdentityLink::Unreachable;
            }
        },
    }
    Json(out)
}

/// Each name is written as sent: one left out is written empty, and an empty display
/// name is refused at preview.
#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NamesRequest {
    pub first_name: String,
    pub last_name: String,
    pub display_name: String,
}

/// Changes my names in PocketID — what every application signed into through it shows.
#[utoipa::path(
    put,
    path = "/api/me/identity",
    params(ActionQuery),
    request_body = NamesRequest,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("act-on-self")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn change_my_names(
    auth: Authorized<CanActOnSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<ActionQuery>,
    Json(d): Json<NamesRequest>,
) -> ActionReply {
    let account = auth.actor().for_account().map(str::to_string);
    let (first, last, display) = (
        d.first_name.trim().to_string(),
        d.last_name.trim().to_string(),
        d.display_name.trim().to_string(),
    );
    let mut blockers = Vec::new();
    let mut target = None;

    match &account {
        None => blockers.push(NOBODY.into()),
        Some(a) => match linked(&s, a).await {
            Ok(t) => target = Some(t),
            Err(link) => blockers.push(unlinked(link, a)),
        },
    }
    // The name everything shows: PocketID would store an empty one, and every
    // application would greet the person with nothing.
    if display.is_empty() {
        blockers.push("the display name cannot be empty".into());
    }

    let applied = q.apply && blockers.is_empty();
    let mut steps = vec![planned(format!(
        "write to PocketID: first name \"{first}\", last name \"{last}\", shown as \"{display}\""
    ))];

    if applied {
        if let Some((pid, id)) = &target {
            let change = hlb_identity::UserChange::Names {
                first: first.clone(),
                last: last.clone(),
                display: display.clone(),
            };
            match pid.update_user(id, &change).await {
                Ok(_) => steps[0].state = StepState::Done,
                Err(e) => {
                    steps[0].state = StepState::Failed;
                    steps[0].error = Some(e.to_string());
                }
            }
        }
    }

    let who = account.as_deref().unwrap_or("<account>");
    let r = ActionResult {
        applied,
        summary: format!("call {who} \"{display}\""),
        steps,
        cli_command: format!(
            "hlb user names {who} --first {} --last {} --display {} --apply",
            quoted(&first),
            quoted(&last),
            quoted(&display)
        ),
        blockers,
        // Read at sign-in, by PocketID's own clients as by this one.
        warnings: vec![
            "applications already signed in keep the old name until their next sign-in".into(),
        ],
        confirmation_required: None,
    };
    respond(&s, auth.identity(), "identity-names", who, r).await
}

#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct DefaultMailboxRequest {
    /// The local part of one of my mailboxes.
    pub local: String,
}

/// Makes one of my mailboxes my default — my identity, and the address PocketID gives
/// applications.
///
/// Resumable: choosing the mailbox that is already the default writes PocketID again,
/// which is how a change whose second step failed is finished.
#[utoipa::path(
    put,
    path = "/api/me/default-mailbox",
    params(ActionQuery),
    request_body = DefaultMailboxRequest,
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("act-on-self")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn choose_default_mailbox(
    auth: Authorized<CanActOnSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<ActionQuery>,
    Json(d): Json<DefaultMailboxRequest>,
) -> ActionReply {
    let account = auth.actor().for_account().map(str::to_string);
    let local = d.local.trim().to_string();
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let mut address = format!("{local}@{}", s.mail_domain);
    let mut identity = None;

    match &account {
        None => blockers.push(NOBODY.into()),
        Some(a) => {
            let boxes = s.state.mailboxes(a).await?;
            match boxes.iter().find(|(l, ..)| l == &local) {
                Some((l, domain, _)) => address = format!("{l}@{domain}"),
                None => blockers.push(format!("this account has no mailbox \"{local}\"")),
            }
            match linked(&s, a).await {
                Ok(t) => identity = Some(t),
                // Not a blocker: the default is Homelabus's own, and still worth
                // changing. But PocketID keeps handing out the old address, and that
                // must be read before applying, not discovered in an application.
                Err(link) => warnings.push(format!(
                    "{} — applications keep receiving the old address",
                    unlinked(link, a)
                )),
            }
        }
    }

    let applied = q.apply && blockers.is_empty();
    let mut steps = vec![planned(format!("make {address} the default mailbox"))];
    if identity.is_some() {
        steps.push(planned(format!(
            "give applications {address} as the address, in PocketID"
        )));
    }

    if applied {
        if let Some(a) = &account {
            match s.state.set_default_mailbox(a, &local).await {
                Ok(true) => steps[0].state = StepState::Done,
                Ok(false) => {
                    steps[0].state = StepState::Failed;
                    steps[0].error = Some(format!("no mailbox \"{local}\" any more"));
                }
                Err(e) => {
                    steps[0].state = StepState::Failed;
                    steps[0].error = Some(e.to_string());
                }
            }
        }
        // Only once the first step holds: PocketID announcing an address Homelabus
        // does not consider the default would be the two systems disagreeing.
        if let (Some((pid, id)), StepState::Done) = (&identity, steps[0].state) {
            let change = hlb_identity::UserChange::Email(address.clone());
            match pid.update_user(id, &change).await {
                Ok(_) => steps[1].state = StepState::Done,
                Err(e) => {
                    steps[1].state = StepState::Failed;
                    steps[1].error = Some(format!("{e} — choose the same mailbox again to finish"));
                }
            }
        }
    }

    let who = account.as_deref().unwrap_or("<account>");
    let r = ActionResult {
        applied,
        summary: format!("make {address} the default mailbox of {who}"),
        steps,
        cli_command: format!("hlb user mailbox default {who} {local} --apply"),
        blockers,
        warnings,
        confirmation_required: None,
    };
    respond(&s, auth.identity(), "mailbox-default", who, r).await
}

/// The reference of the session this request came with, if it came with one.
fn current_reference(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| crate::auth::cookie(v, crate::auth::COOKIE))
        .map(|v| hlb_state::session_reference_of(&v))
}

/// My open sessions, the one I am using among them.
#[utoipa::path(
    get,
    path = "/api/me/sessions",
    responses(
        (status = 200, body = Vec<hlb_api::MySession>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read-self"))
    )
)]
pub async fn my_sessions(
    auth: Authorized<CanReadSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
    headers: HeaderMap,
) -> crate::error::ApiResult<Vec<hlb_api::MySession>> {
    let Some(account) = auth.actor().for_account() else {
        return Ok(Json(Vec::new()));
    };
    let now = crate::auth::now();
    let current = current_reference(&headers);
    let sessions = s.state.sessions_of(account, now).await?;
    Ok(Json(
        sessions
            .into_iter()
            .map(|x| hlb_api::MySession {
                current: current.as_deref() == Some(x.reference.as_str()),
                reference: x.reference,
                user_agent: x.user_agent,
                seen_s: (now - x.last_seen).max(0),
                expires_in_s: (x.expires_at - now).max(0),
            })
            .collect(),
    ))
}

fn device(agent: Option<&str>) -> &str {
    agent.unwrap_or("an unnamed browser")
}

/// Signs one of my other devices out.
#[utoipa::path(
    delete,
    path = "/api/me/sessions/{reference}",
    params(ActionQuery),
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("act-on-self")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn close_my_session(
    auth: Authorized<CanActOnSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path(reference): Path<String>,
    Query(q): Query<ActionQuery>,
    headers: HeaderMap,
) -> ActionReply {
    let account = auth.actor().for_account().map(str::to_string);
    let mut blockers = Vec::new();
    let mut agent = None;

    match &account {
        None => blockers.push(NOBODY.into()),
        Some(a) => {
            let sessions = s.state.sessions_of(a, crate::auth::now()).await?;
            match sessions.into_iter().find(|x| x.reference == reference) {
                None => blockers.push(format!("no open session \"{reference}\"")),
                // Closing it here would leave the browser holding a cookie that names
                // nothing: signing out clears it too.
                Some(_) if current_reference(&headers).as_deref() == Some(&reference) => {
                    blockers.push("this is the session you are using — sign out instead".into())
                }
                Some(x) => agent = x.user_agent,
            }
        }
    }

    let applied = q.apply && blockers.is_empty();
    let mut steps = vec![planned(format!(
        "sign out {} (session {reference})",
        device(agent.as_deref())
    ))];

    if applied {
        if let Some(a) = &account {
            match s.state.close_session_by_reference(a, &reference).await {
                // `false`: expired or closed since the preview. What was asked — that
                // device signed out — holds either way.
                Ok(_) => steps[0].state = StepState::Done,
                Err(e) => {
                    steps[0].state = StepState::Failed;
                    steps[0].error = Some(e.to_string());
                }
            }
        }
    }

    let who = account.as_deref().unwrap_or("<account>");
    let r = ActionResult {
        applied,
        summary: format!("sign {who} out of {}", device(agent.as_deref())),
        steps,
        cli_command: format!("hlb user sessions {who} --close {reference}"),
        blockers,
        warnings: Vec::new(),
        confirmation_required: None,
    };
    respond(&s, auth.identity(), "session-close", who, r).await
}

/// Signs me out everywhere but here — what to do after losing a phone.
#[utoipa::path(
    delete,
    path = "/api/me/sessions",
    params(ActionQuery),
    responses(
        (status = 200, body = hlb_api::ActionResult),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = hlb_api::ActionResult)
    ),
    extensions(
        ("x-hlb-requires" = json!("act-on-self")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn close_my_other_sessions(
    auth: Authorized<CanActOnSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<ActionQuery>,
    headers: HeaderMap,
) -> ActionReply {
    let account = auth.actor().for_account().map(str::to_string);
    let current = current_reference(&headers);
    let mut blockers = Vec::new();
    let mut others = Vec::new();

    match (&account, &current) {
        (None, _) => blockers.push(NOBODY.into()),
        // "The others" is defined by the one kept. A token has none, and closing every
        // session for it is a different request: `hlb user sessions <account> --close all`.
        (Some(_), None) => blockers.push("only a browser session can sign out the others".into()),
        (Some(a), Some(c)) => {
            others = s
                .state
                .sessions_of(a, crate::auth::now())
                .await?
                .into_iter()
                .filter(|x| &x.reference != c)
                .collect();
            if others.is_empty() {
                blockers.push("no other session is open".into());
            }
        }
    }

    let applied = q.apply && blockers.is_empty();
    // One step per device, so the preview says WHICH are signed out.
    let mut steps: Vec<ActionStep> = others
        .iter()
        .map(|x| {
            planned(format!(
                "sign out {} (session {})",
                device(x.user_agent.as_deref()),
                x.reference
            ))
        })
        .collect();

    if applied {
        if let Some(a) = &account {
            for (step, x) in steps.iter_mut().zip(&others) {
                match s.state.close_session_by_reference(a, &x.reference).await {
                    // See `close_my_session`: gone since the preview is signed out.
                    Ok(_) => step.state = StepState::Done,
                    Err(e) => {
                        step.state = StepState::Failed;
                        step.error = Some(e.to_string());
                    }
                }
            }
        }
    }

    let who = account.as_deref().unwrap_or("<account>");
    let r = ActionResult {
        applied,
        summary: format!("sign {who} out everywhere but here"),
        steps,
        cli_command: if others.is_empty() {
            format!("hlb user sessions {who}")
        } else {
            others
                .iter()
                .map(|x| format!("hlb user sessions {who} --close {}", x.reference))
                .collect::<Vec<_>>()
                .join("\n")
        },
        blockers,
        warnings: Vec::new(),
        confirmation_required: None,
    };
    respond(&s, auth.identity(), "session-close", who, r).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_with_a_space_or_a_quote_survives_the_copied_command() {
        assert_eq!(quoted("Léna"), "'Léna'");
        assert_eq!(quoted("Le Gall"), "'Le Gall'");
        assert_eq!(quoted("O'Neill"), r"'O'\''Neill'");
        // An empty last name is still an argument, or `--last --display x` shifts.
        assert_eq!(quoted(""), "''");
        assert_eq!(quoted("lena"), "lena");
    }
}
