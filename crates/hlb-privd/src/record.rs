//! The state's records the web side asks for, written here because only this side
//! writes `hlb.db`.

use hlb_api::intent::{
    Audit, BindIdentity, CloseSession, CloseSessionByReference, IssueAliasToken, OpenSession,
    Refusal, TouchSession, TouchToken,
};

use crate::Privd;

pub(crate) async fn audit(p: &Privd, i: Audit) -> Result<(), String> {
    p.state
        .audit(
            &i.actor,
            i.role,
            &i.action,
            &i.target,
            &i.outcome,
            i.detail.as_deref(),
        )
        .await
        .map_err(|e| e.to_string())
}

pub(crate) async fn open_session(p: &Privd, i: OpenSession) -> Result<(), String> {
    p.state
        .open_session(
            &i.presented,
            &i.user,
            i.subject.as_deref(),
            i.now,
            i.duration_s,
            i.user_agent.as_deref(),
        )
        .await
        .map_err(|e| e.to_string())
}

pub(crate) async fn touch_session(p: &Privd, i: TouchSession) -> Result<(), String> {
    p.state
        .touch_session(&i.presented, i.now, i.duration_s)
        .await
        .map_err(|e| e.to_string())
}

pub(crate) async fn close_session(p: &Privd, i: CloseSession) -> Result<bool, String> {
    p.state
        .close_session(&i.presented)
        .await
        .map_err(|e| e.to_string())
}

pub(crate) async fn close_session_by_reference(
    p: &Privd,
    i: CloseSessionByReference,
) -> Result<bool, String> {
    p.state
        .close_session_by_reference(&i.user, &i.reference)
        .await
        .map_err(|e| e.to_string())
}

pub(crate) async fn bind_identity(p: &Privd, i: BindIdentity) -> Result<bool, String> {
    p.state
        .upsert_user_pocket_id(&i.user, &i.sub)
        .await
        .map_err(|e| e.to_string())
}

pub(crate) async fn touch_token(p: &Privd, i: TouchToken) -> Result<(), String> {
    p.state
        .touch_token(&i.name)
        .await
        .map_err(|e| e.to_string())
}

pub(crate) async fn issue_alias_token(p: &Privd, i: IssueAliasToken) -> Result<(), Refusal> {
    let internal = |e: hlb_state::Error| Refusal::Internal(e.to_string());
    // 🔴 `store_token` replaces a token of the same name: a name that is a service
    // token's — the deadman's, an operator's — would silently become a `user` token for
    // aliases. Only this account's own is issued again.
    let taken = p
        .state
        .list_tokens()
        .await
        .map_err(internal)?
        .iter()
        .any(|(n, ..)| *n == i.name);
    if taken
        && p.state
            .token_user(&i.name)
            .await
            .map_err(internal)?
            .as_deref()
            != Some(&i.account)
    {
        return Err(Refusal::Conflict(format!(
            "a token named \"{}\" exists and is not {}'s: choose another name",
            i.name, i.account
        )));
    }
    // 🔴 `user`, the least there is: creating an alias is acting on oneself. The token
    // lives in a password manager on a phone — stolen as `operator`, it installed,
    // removed and drained.
    let stored = hlb_types::StoredToken {
        name: i.name.clone(),
        role: hlb_types::Role::User,
        fingerprint: i.fingerprint,
    };
    p.state
        .store_token(&stored)
        .await
        .map_err(|e| Refusal::Conflict(e.to_string()))?;
    // 🔴 TWO bindings, and the second was forgotten in a first attempt: the token
    // carried its mailbox but no ACCOUNT, and the alias API refused it — "this request
    // does not act on anyone's behalf". A token carries a ROLE, not an identity: without
    // a binding it would create aliases on anyone's mailbox, so it creates nothing.
    p.state
        .set_token_user(&i.name, Some(&i.account))
        .await
        .map_err(internal)?;
    p.state
        .set_token_mailbox(&i.name, Some(&i.mailbox))
        .await
        .map_err(internal)
}
