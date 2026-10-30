//! The passkey a destruction takes, checked here and nowhere else.
//!
//! The web side asks [`begin`] for the intents one action sends and gets PocketID's
//! address back; the person presents their passkey there; the web side sends each
//! intent again inside a [`Confirmed`], carrying PocketID's code. The daemon exchanges
//! that code itself, with its own PKCE check, and acts only if the `nonce` is the
//! digest of what was begun, the passkey is under five minutes old, and the account it
//! belongs to may do the intent — its role read now, never vouched for by the caller.
//!
//! ⚠️ What this bounds: an intruder in the web side destroys only while someone
//! confirms, once per passkey presented. It does not bound WHAT: PocketID shows
//! nothing of the intent, and the web side chose the intents begun.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use hlb_api::intent::{Intent, Proof, CALLBACK};
use hlb_identity::oidc::{Oidc, PendingRequest, CONFIRMATION_MAX_AGE_S, REQUEST_TIMEOUT_S};

use crate::{now, Privd};

/// Confirmations waiting, past which an older one is dropped: begun without end by an
/// intruder, they would fill the daemon's memory.
const MAX_OPEN: usize = 64;

/// The confirmations begun and not yet used up, by their `state`.
#[derive(Clone, Default)]
pub(crate) struct Confirmations {
    open: Arc<Mutex<HashMap<String, Open>>>,
    /// The issuer, when given rather than read from the vault: the tests'.
    issuer: Option<Arc<Oidc>>,
    /// Whether the client accepts [`CALLBACK`] yet: asked of PocketID once a process.
    callback: Arc<std::sync::atomic::AtomicBool>,
}

struct Open {
    request: PendingRequest,
    /// The digests of the intents begun and not yet acted on.
    left: Vec<String>,
    granted: Option<Granted>,
}

/// A code exchanged: whose passkey, and when.
struct Granted {
    code: String,
    account: String,
    auth_time: i64,
}

impl Confirmations {
    pub(crate) fn with_issuer(oidc: Oidc) -> Self {
        Self {
            issuer: Some(Arc::new(oidc)),
            ..Self::default()
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Open>> {
        // A panic while held leaves a map, not a lie: keep using it.
        self.open.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// Whether a passkey is asked for here: where PocketID signs people in.
pub(crate) async fn required(p: &Privd) -> bool {
    p.confirmations.issuer.is_some() || p.sign_in_client().await.client.is_some()
}

/// The client confirmations go through, `None` where nothing signs in by passkey.
async fn client(p: &Privd) -> Result<Option<Oidc>, String> {
    if let Some(o) = &p.confirmations.issuer {
        return Ok(Some(Oidc::clone(o)));
    }
    let setup = p.sign_in_client().await;
    let Some(c) = setup.client else {
        return Ok(None);
    };
    let e = p
        .state
        .exposure()
        .await
        .map_err(|e| e.to_string())?
        .ok_or("no public address is configured: PocketID could not send the passkey back")?;
    let callback = format!("https://{}{CALLBACK}", e.controller_host());
    if !p
        .confirmations
        .callback
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        if let Some(pid) = &p.identity {
            // Refused, the confirmation fails at PocketID naming the redirect: said
            // there rather than guessed here.
            match pid
                .accept_callbacks(
                    hlb_engine::access::CONTROLLER_OIDC_CLIENT,
                    std::slice::from_ref(&callback),
                )
                .await
            {
                Ok(_) => p
                    .confirmations
                    .callback
                    .store(true, std::sync::atomic::Ordering::Relaxed),
                Err(e) => tracing::warn!("PocketID was not told the confirmations' return: {e}"),
            }
        }
    }
    Oidc::discover_trusting(
        &c.issuer,
        c.id,
        c.secret,
        callback,
        setup.trusted_root.as_deref(),
    )
    .await
    .map(Some)
    .map_err(|e| format!("PocketID cannot be reached to confirm with a passkey: {e}"))
}

/// Begins confirming `intents`: PocketID's address, or `None` where nothing signs in
/// by passkey.
pub(crate) async fn begin(p: &Privd, intents: Vec<Intent>) -> Result<Option<String>, String> {
    if intents.is_empty() || intents.iter().any(|i| i.passkey().is_none()) {
        return Err("a passkey confirms an action that destroys, and only one".into());
    }
    let Some(oidc) = client(p).await? else {
        return Ok(None);
    };
    let mut entropy = [0u8; 64];
    hlb_secrets::fill_random(&mut entropy);
    let now = now();
    let (url, request) = oidc.start_confirming(&entropy, &hlb_api::intent::nonce(&intents), now);
    let mut open = p.confirmations.lock();
    open.retain(|_, o| !o.request.is_expired(now));
    if open.len() >= MAX_OPEN {
        if let Some(oldest) = open
            .iter()
            .min_by_key(|(_, o)| o.request.created_at)
            .map(|(k, _)| k.clone())
        {
            open.remove(&oldest);
        }
    }
    open.insert(
        request.state.clone(),
        Open {
            request,
            left: intents.iter().map(Intent::digest).collect(),
            granted: None,
        },
    );
    Ok(Some(url))
}

/// Uses `proof` up for `asked`: the account whose passkey it was, or why not.
///
/// 🔴 Whatever fails drops the confirmation: a proof tried against another intent,
/// or a code that does not match, is an attack or a bug, and neither gets a second try.
pub(crate) async fn consume(p: &Privd, proof: &Proof, asked: &Intent) -> Result<String, String> {
    let Some(action) = asked.passkey() else {
        return Err("a passkey confirms an action that destroys, and this is not one".into());
    };
    let digest = asked.digest();
    let taken = p.confirmations.lock().remove(&proof.state);
    let Some(mut open) = taken else {
        return Err(format!(
            "no confirmation is waiting under that state: it expired (after \
             {REQUEST_TIMEOUT_S} s), was used, or the daemon restarted — confirm again"
        ));
    };
    if !open.left.contains(&digest) {
        return Err("the passkey confirmed another action than this one".into());
    }
    let now = now();
    let granted = match open.granted.take() {
        Some(g) if hlb_types::token::constant_eq(&g.code, &proof.code) => g,
        Some(_) => return Err("the confirmation's code is not the one exchanged".into()),
        None => {
            let oidc = client(p)
                .await?
                .ok_or("nothing signs in by passkey here any more")?;
            let c = oidc
                .finish_confirming(&open.request, &proof.state, &proof.code, now)
                .await
                .map_err(|e| e.to_string())?;
            let account = p
                .state
                .user_by_pocket_id(&c.identity.sub)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| {
                    format!(
                        "the passkey is {}'s, whom no account here is bound to",
                        c.identity.account_name()
                    )
                })?;
            Granted {
                code: proof.code.clone(),
                account,
                auth_time: c.auth_time,
            }
        }
    };
    if now.saturating_sub(granted.auth_time) > CONFIRMATION_MAX_AGE_S {
        return Err(format!(
            "the passkey was presented more than {} minutes ago — confirm again",
            CONFIRMATION_MAX_AGE_S / 60
        ));
    }
    // Read now: a role taken away since the passkey was presented counts.
    let role = p
        .state
        .user_role(&granted.account)
        .await
        .map_err(|e| e.to_string())?;
    if !role.allows(action) {
        return Err(format!(
            "{} confirmed, and their role may not {}",
            granted.account,
            action.describe()
        ));
    }
    let account = granted.account.clone();
    open.left.retain(|d| *d != digest);
    if !open.left.is_empty() {
        open.granted = Some(granted);
        p.confirmations.lock().insert(proof.state.clone(), open);
    }
    Ok(account)
}

#[cfg(test)]
mod tests {
    use hlb_api::intent::{BeginConfirmation, Confirmed, DeleteRole, SetUserRole};
    use hlb_state::State;

    use super::*;

    /// A PocketID whose every token answers `sub` with these claims.
    async fn pocketid(claims: serde_json::Value) -> Oidc {
        let sub = claims["sub"].as_str().unwrap_or("u1").to_string();
        let id_token = format!(
            "h.{}.s",
            hlb_types::token::base64url(claims.to_string().as_bytes())
        );
        let app = axum::Router::new()
            .route(
                "/token",
                axum::routing::post(move || async move {
                    axum::Json(serde_json::json!({"access_token": "a", "id_token": id_token}))
                }),
            )
            .route(
                "/userinfo",
                axum::routing::get(
                    move || async move { axum::Json(serde_json::json!({"sub": sub})) },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        tokio::spawn(async move { axum::serve(listener, app).await });
        Oidc::with_endpoints(
            hlb_identity::oidc::Endpoints {
                issuer: base.clone(),
                authorization_endpoint: format!("{base}/authorize"),
                token_endpoint: format!("{base}/token"),
                userinfo_endpoint: format!("{base}/userinfo"),
                end_session_endpoint: None,
            },
            "hlb",
            "secret",
            format!("https://hlb.example{CALLBACK}"),
        )
    }

    fn delete(id: &str) -> Intent {
        DeleteRole { id: id.into() }.into()
    }

    fn give(user: &str) -> Intent {
        SetUserRole {
            user: user.into(),
            role: "standard".into(),
            granted_by: Some("alice".into()),
        }
        .into()
    }

    /// A daemon confirming through a PocketID that answers a passkey `sub` presented
    /// `age` seconds ago for `confirmed`; alice (admin) is u1, bob (standard) is u2.
    async fn daemon(sub: &str, confirmed: &[Intent], age: i64) -> Privd {
        let state = Arc::new(State::in_memory().await.expect("state"));
        state
            .upsert_user("alice", "admin", Some("u1"))
            .await
            .expect("alice");
        state
            .upsert_user("bob", "standard", Some("u2"))
            .await
            .expect("bob");
        state
            .upsert_user("carol", "standard", None)
            .await
            .expect("carol");
        let issuer = pocketid(serde_json::json!({
            "sub": sub,
            "nonce": hlb_api::intent::nonce(confirmed),
            "auth_time": now() - age,
        }))
        .await;
        Privd::new(state).confirming_through(issuer)
    }

    /// Begins confirming `intents`: the proof PocketID's return would carry.
    async fn begun(p: &Privd, intents: &[Intent]) -> Proof {
        let asked = BeginConfirmation {
            intents: intents.to_vec(),
        };
        let url: Result<Option<String>, String> =
            serde_json::from_value(p.answer(asked.into()).await.expect("answered")).expect("read");
        let url = url.expect("begun").expect("a PocketID to go to");
        assert!(url.contains("prompt=login"), "{url}");
        let state = url
            .split('&')
            .find_map(|kv| kv.strip_prefix("state="))
            .expect("a state");
        Proof {
            state: state.into(),
            code: "the-code".into(),
        }
    }

    async fn confirmed(p: &Privd, proof: &Proof, i: &Intent) -> Result<serde_json::Value, String> {
        let c = Confirmed {
            proof: proof.clone(),
            asked: Box::new(i.clone()),
        };
        p.answer(c.into()).await.map_err(|e| e.to_string())
    }

    #[tokio::test]
    async fn a_destruction_waits_for_a_passkey_where_pocketid_signs_people_in() {
        let p = daemon("u1", &[delete("guest")], 0).await;
        let refused = p
            .answer(delete("guest"))
            .await
            .expect_err("acted unconfirmed");
        assert!(refused.to_string().contains("passkey"), "{refused}");
        // What does not destroy is not asked for one.
        p.answer(hlb_api::intent::KitFingerprint {}.into())
            .await
            .expect("answered");
        // Nor anything at all where nothing signs in by passkey.
        let bare = Privd::new(Arc::new(State::in_memory().await.expect("state")));
        bare.answer(delete("guest")).await.expect("acted");
    }

    #[tokio::test]
    async fn a_passkey_confirms_the_action_it_was_presented_for_once() {
        let p = daemon("u1", &[delete("guest")], 0).await;
        let proof = begun(&p, &[delete("guest")]).await;
        let other = confirmed(&p, &proof, &delete("standard"))
            .await
            .expect_err("confirmed another role");
        assert!(other.contains("another action"), "{other}");

        let proof = begun(&p, &[delete("guest")]).await;
        let done = confirmed(&p, &proof, &delete("guest"))
            .await
            .expect("acted");
        assert_eq!(done, serde_json::json!({"Ok": true}), "the role is gone");
        let again = confirmed(&p, &proof, &delete("guest"))
            .await
            .expect_err("a passkey used twice");
        assert!(again.contains("no confirmation is waiting"), "{again}");
    }

    #[tokio::test]
    async fn a_role_given_to_a_selection_takes_one_passkey() {
        let batch = [give("bob"), give("carol")];
        let p = daemon("u1", &batch, 0).await;
        let proof = begun(&p, &batch).await;
        for i in &batch {
            confirmed(&p, &proof, i).await.expect("acted");
        }
        confirmed(&p, &proof, &give("bob"))
            .await
            .expect_err("the selection is used up");
    }

    #[tokio::test]
    async fn a_passkey_confirms_only_what_its_owner_may_do_and_only_now() {
        // Bob is no administrator: his passkey deletes no role.
        let p = daemon("u2", &[delete("guest")], 0).await;
        let proof = begun(&p, &[delete("guest")]).await;
        let bob = confirmed(&p, &proof, &delete("guest"))
            .await
            .expect_err("bob deleted");
        assert!(bob.contains("bob confirmed"), "{bob}");

        let stale = CONFIRMATION_MAX_AGE_S + 60;
        let p = daemon("u1", &[delete("guest")], stale).await;
        let proof = begun(&p, &[delete("guest")]).await;
        let old = confirmed(&p, &proof, &delete("guest"))
            .await
            .expect_err("an old passkey");
        assert!(old.contains("minutes ago"), "{old}");

        let p = daemon("u9", &[delete("guest")], 0).await;
        let proof = begun(&p, &[delete("guest")]).await;
        let nobody = confirmed(&p, &proof, &delete("guest"))
            .await
            .expect_err("an unbound identity");
        assert!(nobody.contains("no account"), "{nobody}");
    }

    #[tokio::test]
    async fn nothing_but_a_destruction_is_begun() {
        let p = daemon("u1", &[], 0).await;
        let asked = BeginConfirmation {
            intents: vec![hlb_api::intent::KitFingerprint {}.into()],
        };
        let r: Result<Option<String>, String> =
            serde_json::from_value(p.answer(asked.into()).await.expect("answered")).expect("read");
        r.expect_err("a passkey asked for a read");
    }
}
