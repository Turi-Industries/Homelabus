//! The signed-in person's own account: their names, their default mailbox, their
//! sessions, their devices.
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
    // A service token is nobody, and has no identity to show.
    let Some(account) = auth.actor().for_account() else {
        return Json(hlb_api::MyIdentity {
            link: IdentityLink::NotLinked,
            first_name: None,
            last_name: None,
            display_name: None,
            email: None,
            passkeys_url: passkeys_url(&s),
        });
    };
    let mut out = s
        .privd()
        .ask(hlb_api::intent::MyIdentity {
            account: account.to_string(),
        })
        .await
        .unwrap_or(hlb_api::MyIdentity {
            link: IdentityLink::Unreachable,
            first_name: None,
            last_name: None,
            display_name: None,
            email: None,
            passkeys_url: None,
        });
    out.passkeys_url = passkeys_url(&s);
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
    let who = account.clone().unwrap_or_else(|| "<account>".into());
    let r = s
        .privd()
        .ask(hlb_api::intent::Rename {
            account,
            first_name: d.first_name,
            last_name: d.last_name,
            display_name: d.display_name,
            apply: q.apply,
        })
        .await
        .map_err(crate::actions::privd_error)?;
    respond(&s, auth.identity(), "identity-names", &who, r).await
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
    let who = account.clone().unwrap_or_else(|| "<account>".into());
    let answer = s
        .privd()
        .ask(hlb_api::intent::DefaultMailbox {
            account,
            local: d.local,
            apply: q.apply,
        })
        .await
        .map_err(crate::actions::privd_error)?;
    let r = match answer {
        hlb_api::intent::Acted::Planned(r) => r,
        hlb_api::intent::Acted::Unplannable(m) => {
            return Err(crate::error::ApiError::Internal(m).into())
        }
    };
    respond(&s, auth.identity(), "mailbox-default", &who, r).await
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
            let asked = hlb_api::intent::CloseSessionByReference {
                user: a.clone(),
                reference: reference.clone(),
            };
            match s.record(asked).await {
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
                let asked = hlb_api::intent::CloseSessionByReference {
                    user: a.clone(),
                    reference: x.reference.clone(),
                };
                match s.record(asked).await {
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

/// My devices: one password each for my mailbox, read from Stalwart.
#[utoipa::path(
    get,
    path = "/api/me/devices",
    responses(
        (status = 200, body = hlb_api::MyDevices)
    ),
    extensions(
        ("x-hlb-requires" = json!("read-self"))
    )
)]
pub async fn my_devices(
    auth: Authorized<CanReadSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> Json<hlb_api::MyDevices> {
    let unreadable = |why: String| hlb_api::MyDevices {
        devices: Vec::new(),
        unreadable: Some(why),
    };
    // A service token is nobody, and has no mailbox for a device to sign in to.
    let Some(account) = auth.actor().for_account() else {
        return Json(unreadable(NOBODY.into()));
    };
    let asked = hlb_api::intent::Devices {
        account: account.to_string(),
    };
    Json(match s.privd().ask(asked).await {
        Ok(Ok(devices)) => hlb_api::MyDevices {
            devices,
            unreadable: None,
        },
        Ok(Err(why)) => unreadable(why),
        Err(e) => unreadable(e.to_string()),
    })
}

#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct DeviceRequest {
    /// What I call the device, to tell it from the others when revoking one.
    pub name: String,
    /// The local part of one of my mailboxes; left out, my default one.
    pub mailbox: Option<String>,
}

/// The answer to making a device's password.
///
/// 🔴 The only place its password appears: Stalwart answers it once, and nothing here
/// stores or logs it.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct DeviceCreated {
    /// ⚠️ FLATTENED, like every action's answer: `applied`, `steps` and `blockers` at
    /// the root, where the interface and the preview-by-default test read them.
    #[serde(flatten)]
    pub result: ActionResult,
    /// What the device is set up with, shown **once**; `None` until it is made.
    pub setup: Option<hlb_api::DeviceSetup>,
}

/// Gives one of my devices a password for my mailbox: mail, calendars and contacts.
///
/// Applied, it takes my own passkey — the password opens the mailbox every password
/// reset lands in.
#[utoipa::path(
    post,
    path = "/api/me/devices",
    params(ActionQuery),
    request_body = DeviceRequest,
    responses(
        (status = 200, body = DeviceCreated),
        (status = 422, description = "Nothing could be planned: the body's `blockers` say why", body = DeviceCreated),
        (status = 428, description = "Applying it needs a passkey: present one where the header says, then send it again", body = hlb_api::ErrorBody, headers(("x-hlb-passkey-url" = String, description = "Where to present the passkey")))
    ),
    extensions(
        ("x-hlb-requires" = json!("act-on-self")),
        ("x-hlb-preview" = json!(true))
    )
)]
pub async fn add_my_device(
    auth: Authorized<CanActOnSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ActionQuery>,
    Json(d): Json<DeviceRequest>,
) -> ActionReply<DeviceCreated> {
    let account = auth.actor().for_account().map(str::to_string);
    let who = account.clone().unwrap_or_else(|| "<account>".into());
    let asked = hlb_api::intent::AddDevice {
        account,
        name: d.name,
        mailbox: d.mailbox,
        apply: q.apply,
    };
    let proof = crate::passkey::confirm(&s, &headers, vec![asked.clone().into()]).await?;
    let made = s
        .privd()
        .ask_confirmed(proof, asked)
        .await
        .map_err(crate::actions::privd_error)?;
    // The result alone: `setup` carries the password, which no log ever holds.
    crate::actions::audit(&s, auth.identity(), "device-add", &who, &made.result).await;
    Ok(Json(DeviceCreated {
        result: made.result,
        setup: made.setup,
    }))
}

/// Revokes one of my devices' password: refused from its next request on.
#[utoipa::path(
    delete,
    path = "/api/me/devices/{mailbox}/{id}",
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
pub async fn revoke_my_device(
    auth: Authorized<CanActOnSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
    Path((mailbox, id)): Path<(String, String)>,
    Query(q): Query<ActionQuery>,
) -> ActionReply {
    let account = auth.actor().for_account().map(str::to_string);
    let who = account.clone().unwrap_or_else(|| "<account>".into());
    let answer = s
        .privd()
        .ask(hlb_api::intent::RevokeDevice {
            account,
            mailbox,
            id,
            apply: q.apply,
        })
        .await
        .map_err(crate::actions::privd_error)?;
    let r = match answer {
        hlb_api::intent::Acted::Planned(r) => r,
        hlb_api::intent::Acted::Unplannable(m) => {
            return Err(crate::error::ApiError::Internal(m).into())
        }
    };
    respond(&s, auth.identity(), "device-revoke", &who, r).await
}
