//! The sign-in routes: getting in and getting out.
//!
//! Three routes, and a round trip to PocketID between the first two:
//!
//! ```text
//! GET  /auth/signin?return_to=/apps   -> 302 to PocketID
//!                                       (the person authenticates with a passkey)
//! GET  /auth/return_to?code=…&state=…    → server-to-server exchange, sets the cookie,
//!                                       302 to `return_to`
//! POST /auth/signout              → closes the session, clears the cookie
//! ```
//!
//! ## 🔴 A PocketID identity is NOT enough to get in
//!
//! PocketID says *who* the person is. It does not say they are entitled to be here.
//! Without a matching Homelabus account, the sign-in is **refused** — not honoured by
//! creating an account on the fly.
//!
//! That is deliberate and consistent with the project's private-by-default exposure:
//! PocketID can serve other applications, and its directory is not the list of people
//! authorised on the controller. Opening one would open the other, silently, the day
//! someone adds an account for Jellyfin.
//!
//! Getting in therefore goes through `hlb user add`, or an invitation.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State as AxumState;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::extract::Query;
use hlb_identity::oidc::{Oidc, PendingRequest};

use crate::api::AppState;
use crate::auth::{now, Authorized, CanReadSelf, Identity, COOKIE, SESSION_DURATION_S};

/// Past this, the oldest sign-in still waiting makes room for the new one.
///
/// With no cap, hammering `/auth/signin` would grow the table of pending requests
/// until the controller runs out of memory — a total outage triggered by
/// a public route.
const MAX_REQUESTS: usize = 1024;

/// Sign-ins one client may have waiting at once. 🔴 The cap is per client first: with
/// one shared cap a couple of addresses filled the table for ten minutes and nobody
/// else could sign in.
const MAX_REQUESTS_PER_CLIENT: usize = 8;

/// The cookie binding a sign-in's return to the browser that started it.
const STATE_COOKIE: &str = "hlb_signin";

/// What the controller keeps between leaving for PocketID and coming back.
///
/// In memory and not in the database: a request lives ten minutes, and a restart between
/// the two ends in "start the sign-in again", which is acceptable. One more table is not
/// justified, and it would end up in the backups.
pub struct SignIn {
    pub oidc: Oidc,
    /// `true` = set the cookie with `Secure`.
    ///
    /// ⚠️ Derived from the public URL, not hard-coded: a `Secure` cookie is **not set at
    /// all** over `http://`, and local development would end in a sign-in loop with no
    /// error message.
    pub secure: bool,
    /// `state → (client, request)`.
    pending: tokio::sync::Mutex<HashMap<String, (String, PendingRequest)>>,
}

/// Where the controller's sign-in lives, once PocketID answered.
///
/// 🔴 Read at startup only, a cold start of the cluster disabled sign-in for good: the
/// controller came up before PocketID and Caddy, discovery failed once, and "only API
/// tokens authenticate until it does" stayed true an hour later — nothing asked again.
/// The controller now asks until it answers (`main.rs`) and fills this slot.
#[derive(Default)]
pub struct SignInSlot {
    current: std::sync::RwLock<Option<Arc<SignIn>>>,
    /// Configured, its issuer not reached yet.
    waiting: std::sync::atomic::AtomicBool,
}

impl SignInSlot {
    pub fn ready(s: SignIn) -> Self {
        let slot = Self::default();
        slot.fill(s);
        slot
    }

    /// Configured, and filled once the issuer answers.
    pub fn waiting() -> Self {
        let slot = Self::default();
        slot.waiting
            .store(true, std::sync::atomic::Ordering::Relaxed);
        slot
    }

    pub fn fill(&self, s: SignIn) {
        if let Ok(mut c) = self.current.write() {
            *c = Some(Arc::new(s));
        }
        self.waiting
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn get(&self) -> Option<Arc<SignIn>> {
        self.current.read().ok().and_then(|c| c.clone())
    }

    fn is_waiting(&self) -> bool {
        self.waiting.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl SignIn {
    pub fn new(oidc: Oidc, public_url: &str) -> Self {
        Self {
            oidc,
            secure: public_url.starts_with("https://"),
            pending: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    async fn store(&self, d: PendingRequest, client: &str) -> Result<(), &'static str> {
        let mut m = self.pending.lock().await;
        // Housekeeping first: an expired request has no reason to hold the space.
        let now = now();
        m.retain(|_, (_, d)| !d.is_expired(now));
        if m.values().filter(|(c, _)| c == client).count() >= MAX_REQUESTS_PER_CLIENT {
            return Err("too many sign-ins being established — try again in a moment");
        }
        if m.len() >= MAX_REQUESTS {
            // The oldest goes, rather than every new one being refused: whoever it was
            // starts again, where a refusal shut everyone out until it expired.
            if let Some(oldest) = m
                .iter()
                .min_by_key(|(_, (_, d))| d.created_at)
                .map(|(k, _)| k.clone())
            {
                m.remove(&oldest);
            }
        }
        m.insert(d.state.clone(), (client.to_string(), d));
        Ok(())
    }

    /// Removes and returns the request matching this state.
    ///
    /// 🔴 **Removes**, always: a consumed request must not be reusable, or an
    /// intercepted authorization code would be replayable for as long as the
    /// request lives.
    async fn consume(&self, state: &str) -> Option<PendingRequest> {
        self.pending.lock().await.remove(state).map(|(_, d)| d)
    }
}

#[derive(serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct StartQuery {
    /// Where to come back to after signing in. Filtered by `PendingRequest::return_onto`.
    pub return_to: Option<String>,
}

/// Sends the person off to authenticate at PocketID.
#[utoipa::path(
    get,
    path = "/auth/signin",
    params(StartQuery),
    responses(
        (status = 302, description = "On to PocketID"),
        (status = "default", description = "A browser navigation: refused in a line of plain text", content((String = "text/plain"), (hlb_api::ErrorBody = "application/json")))
    ),
    extensions(
        ("x-hlb-public" = json!(true))
    )
)]
pub async fn start(
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<StartQuery>,
    request: axum::extract::Request,
) -> Response {
    let Some(cx) = s.signin.get() else {
        return unavailable(&s.signin);
    };

    let mut entropy = [0u8; 96];
    hlb_secrets::fill_random(&mut entropy);
    let (url, pending) = cx.oidc.start(&entropy, q.return_to, now());
    let state = pending.state.clone();

    let pair = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip());
    let client = crate::throughput::client(request.headers(), pair, s.trusted_proxy);
    if let Err(e) = cx.store(pending, &client).await {
        return (StatusCode::SERVICE_UNAVAILABLE, format!("{e}\n")).into_response();
    }

    (
        StatusCode::FOUND,
        [
            (header::LOCATION, url),
            // A redirect must never be cached: the URL carries single-use state, and a
            // cache would serve it again after it was consumed.
            (header::CACHE_CONTROL, "no-store".to_string()),
            (header::SET_COOKIE, state_cookie(&state, cx.secure)),
        ],
    )
        .into_response()
}

/// The sign-in's state, kept by the browser that asked for it.
///
/// 🔴 Without it, a return carrying someone else's code and state signed THIS browser
/// in as them: a link sent to a victim opened a session on the sender's account, and
/// whatever they then typed — a password saved, an alias made — went to the sender.
/// `Lax`: it follows the navigation back from PocketID.
fn state_cookie(state: &str, secure: bool) -> String {
    let s = if secure { "; Secure" } else { "" };
    format!(
        "{STATE_COOKIE}={state}; Path=/auth; HttpOnly; SameSite=Lax; Max-Age={}{s}",
        hlb_identity::oidc::REQUEST_TIMEOUT_S
    )
}

fn cleared_state_cookie(secure: bool) -> String {
    let s = if secure { "; Secure" } else { "" };
    format!("{STATE_COOKIE}=; Path=/auth; HttpOnly; SameSite=Lax; Max-Age=0{s}")
}

#[derive(serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ReturnQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    /// PocketID returns an error here when the person refuses the authorization.
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// The return from PocketID: exchanges the code, opens the session.
#[utoipa::path(
    get,
    path = "/auth/return_to",
    params(ReturnQuery),
    responses(
        (status = 302, description = "Signed in: the session cookie is set, and back to where the person started"),
        (status = "default", description = "A browser navigation: refused in a line of plain text", content((String = "text/plain"), (hlb_api::ErrorBody = "application/json")))
    ),
    extensions(
        ("x-hlb-public" = json!(true))
    )
)]
pub async fn return_to(
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<ReturnQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(cx) = s.signin.get() else {
        return unavailable(&s.signin);
    };

    // The person refused, or PocketID refused for them. This is not an outage: we say so
    // as it is rather than return a technical error.
    if let Some(e) = q.error {
        let d = q.error_description.unwrap_or_default();
        return (
            StatusCode::FORBIDDEN,
            format!("sign-in refused by the identity provider: {e} {d}\n"),
        )
            .into_response();
    }

    let (Some(code), Some(state)) = (q.code, q.state) else {
        return (
            StatusCode::BAD_REQUEST,
            "incomplete sign-in return — start again from /auth/signin\n",
        )
            .into_response();
    };

    // The return must reach the browser that left: a state this browser never asked
    // for is someone else's sign-in.
    let started_here = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| crate::auth::cookie(v, STATE_COOKIE))
        .is_some_and(|kept| kept == state);
    if !started_here {
        return (
            StatusCode::BAD_REQUEST,
            [(header::SET_COOKIE, cleared_state_cookie(cx.secure))],
            "this sign-in was not started from this browser — start the sign-in again\n",
        )
            .into_response();
    }

    let Some(request) = cx.consume(&state).await else {
        // No request for this state: either it expired, or it has already been used, or
        // the request is forged. All three give the same message: distinguishing would
        // tell an attacker whether a state they tried ever existed.
        return (
            StatusCode::BAD_REQUEST,
            "sign-in expired or already used — start the sign-in again\n",
        )
            .into_response();
    };

    let identity = match cx.oidc.finish(&request, &state, &code, now()).await {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(error = %e, "OIDC sign-in failed");
            return (
                StatusCode::BAD_GATEWAY,
                format!("sign-in impossible: {e}\n"),
            )
                .into_response();
        }
    };

    // 🔴 Binding by the PocketID `sub` first: it is stable, whereas the user name can be
    // renamed — and binding by name would lose the link
    // silently on the first rename.
    //
    // 🔴 A state that cannot be read is a refusal, never "not bound yet": that fallback
    // goes by a NAME, which the identity provider lets people choose.
    let unreadable = |e: hlb_state::Error| {
        tracing::warn!(error = %e, "sign-in: the state cannot be read");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "sign-in impossible for now: the controller cannot read its state\n",
        )
            .into_response()
    };
    let account = match account_for(&s.state, &identity.sub, identity.account_name()).await {
        Ok(a) => a,
        Err(e) => return unreadable(e),
    };

    let Some(account) = account else {
        let _ = s
            .state
            .audit(
                identity.account_name(),
                hlb_types::Role::User,
                "signin",
                &identity.sub,
                "refused",
                Some("no Homelabus account for this PocketID identity"),
            )
            .await;
        return (
            StatusCode::FORBIDDEN,
            format!(
                "\"{}\" is indeed known to PocketID, but has no Homelabus account.\n\
                 \n\
                 That is intended: PocketID's directory also serves the other \
                 applications, and being in it does not grant access to the controller.\n\
                 \n\
                 An administrator can open access:  hlb user add {} --apply\n",
                identity.display_name(),
                identity.account_name()
            ),
        )
            .into_response();
    };

    // The `sub` ↔ account link is recorded on the first sign-in: a rename at PocketID
    // will no longer break anything afterwards. Bound only if still unbound — another
    // sign-in may have bound it since it was read.
    match s.state.upsert_user_pocket_id(&account, &identity.sub).await {
        Ok(true) => {}
        Ok(false) => {
            let _ = s
                .state
                .audit(
                    identity.account_name(),
                    hlb_types::Role::User,
                    "signin",
                    &identity.sub,
                    "refused",
                    Some("the account is bound to another PocketID identity"),
                )
                .await;
            return (
                StatusCode::FORBIDDEN,
                "this Homelabus account is bound to another PocketID identity\n",
            )
                .into_response();
        }
        Err(e) => return unreadable(e),
    }

    let mut raw = [0u8; 32];
    hlb_secrets::fill_random(&mut raw);
    // Base32 like the tokens: no `/`, `+` or `=` — a cookie should not have to be
    // re-encoded, and a badly escaped character would end in a session that cannot be
    let value = hlb_types::token::base32(&raw);

    let agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.chars().take(120).collect::<String>());

    if let Err(e) = s
        .state
        .open_session(
            &value,
            &account,
            Some(&identity.sub),
            now(),
            SESSION_DURATION_S,
            agent.as_deref(),
        )
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("session could not be opened: {e}\n"),
        )
            .into_response();
    }

    let role = s.state.user_role(&account).await.unwrap_or_default();
    let _ = s
        .state
        .audit(&account, role, "signin", &identity.sub, "ok", None)
        .await;

    let mut r = (
        StatusCode::FOUND,
        [
            (header::LOCATION, request.return_onto().to_string()),
            (header::SET_COOKIE, session_cookie(&value, cx.secure)),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
    )
        .into_response();
    if let Ok(v) = header::HeaderValue::from_str(&cleared_state_cookie(cx.secure)) {
        r.headers_mut().append(header::SET_COOKIE, v);
    }
    r
}

/// Gives a session's cookie the lifetime its server side was just given.
///
/// 🔴 The session slides on every use, its cookie did not: it was set for twelve hours
/// at sign-in and never again, so someone working all day was signed out mid-task by a
/// session the server still held open. Every response to a request a session
/// authenticated carries the cookie again, with a fresh `Max-Age`.
pub async fn reissue(
    AxumState(s): AxumState<Arc<AppState>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let slid = crate::auth::Slid::default();
    request.extensions_mut().insert(slid.clone());
    let mut response = next.run(request).await;
    // A response setting a cookie of its own (signing out, signing in) is left as it is.
    if let Some(value) = slid.take() {
        if !response.headers().contains_key(header::SET_COOKIE) {
            let secure = s.signin.get().map(|c| c.secure).unwrap_or(true);
            if let Ok(v) = header::HeaderValue::from_str(&session_cookie(&value, secure)) {
                response.headers_mut().append(header::SET_COOKIE, v);
            }
        }
    }
    response
}

/// Closes the current session.
#[utoipa::path(
    post,
    path = "/auth/signout",
    responses(
        (status = 204, description = "Signed out: the session is closed and its cookie cleared")
    ),
    extensions(
        ("x-hlb-requires" = json!("read-self")),
        ("x-hlb-preview" = json!(false))
    )
)]
pub async fn signout(
    identity: Identity,
    AxumState(s): AxumState<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> (StatusCode, [(header::HeaderName, String); 1]) {
    let secure = s.signin.get().map(|c| c.secure).unwrap_or(true);

    if let Some(value) = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| crate::auth::cookie(v, COOKIE))
    {
        let _ = s.state.close_session(&value).await;
    }

    let _ = s
        .state
        .audit(
            identity.actor.name(),
            identity.role,
            "signout",
            identity.actor.name(),
            "ok",
            None,
        )
        .await;

    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, cleared_cookie(secure))],
    )
}

/// Who am I?
///
/// The first request the UI makes: it decides which screens to show. Returning `403`
/// here rather than an empty object lets the interface offer to sign in instead of
/// showing a console with everything greyed out.
#[utoipa::path(
    get,
    path = "/api/me",
    responses(
        (status = 200, body = hlb_api::Me)
    ),
    extensions(
        ("x-hlb-requires" = json!("read-self"))
    )
)]
pub async fn me(
    auth: Authorized<CanReadSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> crate::extract::Json<hlb_api::Me> {
    let i = auth.identity();
    let account = i.actor.for_account().map(str::to_string);

    let mailboxes = match &account {
        Some(c) => s
            .state
            .mailboxes(c)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|(local, domain, default)| hlb_api::MailboxBrief {
                address: format!("{local}@{domain}"),
                default,
            })
            .collect(),
        None => Vec::new(),
    };

    crate::extract::Json(hlb_api::Me {
        account,
        role: i.role.as_str().to_string(),
        role_label: i.role.describe().to_string(),
        by_token: !i.actor.is_person(),
        can: hlb_api::Rights::for_role(i.role),
        mailboxes,
    })
}

/// My own aliases, with their real state.
///
/// 🔴 `CanReadSelf`, and scoped to the SIGNED-IN account — never to an account named in
/// the URL. Reading someone else's aliases would expose the map of who they write to,
/// which is precisely what compartmentalising addresses is for.
#[utoipa::path(
    get,
    path = "/api/me/aliases",
    responses(
        (status = 200, body = Vec<hlb_api::AliasSummary>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read-self"))
    )
)]
pub async fn my_aliases(
    auth: Authorized<CanReadSelf>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> crate::extract::Json<Vec<hlb_api::AliasSummary>> {
    let i = auth.identity();
    // A service token acts on nobody's behalf: it has no aliases, and inventing some
    // would mean picking an account for it.
    let Some(account) = i.actor.for_account() else {
        return crate::extract::Json(Vec::new());
    };

    let now = crate::auth::now();
    let domain = s.mail_domain.clone();
    let rows = s.state.aliases(account).await.unwrap_or_default();

    let mut out: Vec<hlb_api::AliasSummary> = rows
        .into_iter()
        .map(|(mailbox, local, expires_at, active, hint, note)| {
            let (state, seconds) = match (expires_at, active) {
                (None, _) => ("permanent", None),
                (Some(e), true) if now < e => ("valid", Some(e - now)),
                // 🔴 Expired AND still active: the purge has not run. Same date as the
                // line below, opposite reality — the address still receives.
                (Some(e), true) => ("expired-but-active", Some(now - e)),
                (Some(e), false) => ("expired", Some(now - e)),
            };
            hlb_api::AliasSummary {
                address: format!("{local}@{domain}"),
                mailbox,
                hint,
                note,
                state: state.to_string(),
                seconds,
                active,
            }
        })
        .collect();

    // The worst first: an expired address that still receives is what you came to fix.
    out.sort_by(|a, b| {
        b.attention()
            .cmp(&a.attention())
            .then_with(|| a.address.cmp(&b.address))
    });
    crate::extract::Json(out)
}

fn session_cookie(value: &str, secure: bool) -> String {
    // `SameSite=Lax`: the cookie follows a normal navigation to the site (which is
    // indispensable on the return from PocketID, where `Strict` would stop it being
    // sent and the sign-in would loop), but not a cross-site request. CSRF protection
    // for mutating requests is completed by the `X-HLB-UI` header (cf. `auth.rs`).
    let s = if secure { "; Secure" } else { "" };
    format!("{COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_DURATION_S}{s}")
}

fn cleared_cookie(secure: bool) -> String {
    let s = if secure { "; Secure" } else { "" };
    format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{s}")
}

fn unavailable(slot: &SignInSlot) -> Response {
    let why = if slot.is_waiting() {
        "sign-in through PocketID is configured, and PocketID has not answered yet.\n\
         The controller keeps asking: try again in a minute, or use an API token.\n"
    } else {
        "sign-in through PocketID is not configured on this controller.\n\
         Start it with --oidc-issuer, --oidc-client-id and --oidc-client-secret, \
         or use an API token instead.\n"
    };
    (StatusCode::SERVICE_UNAVAILABLE, why).into_response()
}

/// The account a PocketID identity signs in to: the one bound to its `sub`, or failing
/// that the one by its name — what lets an account created by `hlb user add` before the
/// first sign-in work. Only an account no identity is bound to yet: one bound to
/// another `sub` belongs to whoever holds that one, whatever name this identity
/// carries today.
async fn account_for(
    state: &hlb_state::State,
    sub: &str,
    name: &str,
) -> hlb_state::Result<Option<String>> {
    if let Some(bound) = state.user_by_pocket_id(sub).await? {
        return Ok(Some(bound));
    }
    Ok(state
        .users()
        .await?
        .into_iter()
        .find(|(n, _, bound)| n == name && bound.is_none())
        .map(|(n, _, _)| n))
}
#[cfg(test)]
mod tests {
    use super::*;

    fn sign_in() -> SignIn {
        let endpoints = hlb_identity::oidc::Endpoints {
            issuer: "https://id.example.org".into(),
            authorization_endpoint: "https://id.example.org/authorize".into(),
            token_endpoint: "https://id.example.org/api/oidc/token".into(),
            userinfo_endpoint: "https://id.example.org/api/oidc/userinfo".into(),
            end_session_endpoint: None,
        };
        let o = Oidc::with_endpoints(endpoints, "homelabus", "s", "https://hlb/auth/return_to");
        SignIn::new(o, "https://hlb.example.org")
    }

    #[tokio::test]
    async fn a_sign_in_waiting_for_its_issuer_says_so_then_opens() {
        // 🔴 After a cold start the issuer answers minutes after the controller: the
        // refusal must not send the person to configure what is configured.
        let slot = SignInSlot::waiting();
        let r = unavailable(&slot);
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(r.into_body(), 4096)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("has not answered yet"), "{text}");
        assert!(slot.get().is_none());

        slot.fill(sign_in());
        assert!(slot.get().is_some(), "filled once the issuer answered");
        assert!(!slot.is_waiting());

        let unset = SignInSlot::default();
        let body = axum::body::to_bytes(unavailable(&unset).into_body(), 4096)
            .await
            .expect("body");
        assert!(String::from_utf8_lossy(&body).contains("not configured"));
    }

    #[tokio::test]
    async fn a_name_never_signs_in_to_an_account_bound_to_another_identity() {
        let st = hlb_state::State::in_memory().await.expect("state");
        st.upsert_user("lena", "admin", None)
            .await
            .expect("account");
        st.upsert_user("new", "user", None).await.expect("account");
        st.upsert_user_pocket_id("lena", "sub-lena")
            .await
            .expect("bound");

        assert_eq!(
            account_for(&st, "sub-other", "lena").await.expect("read"),
            None,
            "an identity calling itself lena took lena's account"
        );
        assert_eq!(
            account_for(&st, "sub-lena", "renamed").await.expect("read"),
            Some("lena".into())
        );
        assert_eq!(
            account_for(&st, "sub-new", "new").await.expect("read"),
            Some("new".into()),
            "an account not bound yet is found by its name"
        );
    }

    #[test]
    fn the_session_cookie_is_unreachable_from_javascript() {
        // 🔴 Without `HttpOnly`, a single XSS flaw in a page served by the controller
        // would be enough to exfiltrate the session — and the interface is served by the
        // controller itself.
        let c = session_cookie("abc", true);
        assert!(c.contains("HttpOnly"), "{c}");
        assert!(c.contains("SameSite=Lax"), "{c}");
        assert!(c.contains("Path=/"), "{c}");
        assert!(c.contains("Secure"), "{c}");
    }

    #[test]
    fn a_plain_http_deployment_still_gets_a_cookie() {
        // ⚠️ A `Secure` cookie is NOT set over http:// — local development would loop
        // on the sign-in screen, with no error message.
        let c = session_cookie("abc", false);
        assert!(!c.contains("Secure"), "{c}");
        assert!(c.contains("HttpOnly"), "{c}");
    }

    #[test]
    fn secure_follows_the_public_url_not_a_guess() {
        let ep = hlb_identity::oidc::Endpoints {
            issuer: "https://id.home.example".into(),
            authorization_endpoint: "https://id.home.example/authorize".into(),
            token_endpoint: "https://id.home.example/token".into(),
            userinfo_endpoint: "https://id.home.example/userinfo".into(),
            end_session_endpoint: None,
        };
        let oidc = |_: ()| {
            Oidc::with_endpoints(
                ep.clone(),
                "hlb",
                "s",
                "https://hlb.home.example/auth/return_to",
            )
        };
        assert!(SignIn::new(oidc(()), "https://hlb.home.example").secure);
        assert!(!SignIn::new(oidc(()), "http://127.0.0.1:8420").secure);
    }

    #[test]
    fn logging_out_expires_the_cookie_rather_than_leaving_it() {
        // Not clearing it would let the browser send a dead value on every request: the
        // person would believe they were signed in until the next 401.
        let c = cleared_cookie(true);
        assert!(c.contains("Max-Age=0"), "{c}");
        assert!(c.starts_with(&format!("{COOKIE}=;")), "{c}");
    }

    #[tokio::test]
    async fn a_consumed_request_cannot_be_replayed() {
        // 🔴 A consumed request must not be reusable: otherwise an intercepted
        // authorization code would be replayable for as long as the request lives.
        let ep = hlb_identity::oidc::Endpoints {
            issuer: "https://id.home.example".into(),
            authorization_endpoint: "https://id.home.example/authorize".into(),
            token_endpoint: "https://id.home.example/token".into(),
            userinfo_endpoint: "https://id.home.example/userinfo".into(),
            end_session_endpoint: None,
        };
        let cx = SignIn::new(
            Oidc::with_endpoints(ep, "hlb", "s", "https://hlb.home.example/auth/return_to"),
            "https://hlb.home.example",
        );

        let (_, d) = cx.oidc.start(&[1u8; 96], None, now());
        let state = d.state.clone();
        cx.store(d, "1.2.3.4").await.expect("retenue");

        assert!(cx.consume(&state).await.is_some(), "first time");
        assert!(cx.consume(&state).await.is_none(), "not twice");
    }

    #[tokio::test]
    async fn hammering_the_login_route_does_not_exhaust_memory() {
        // With no cap, hammering /auth/signin would grow the table until failure —
        // a total outage triggered by a public route.
        let ep = hlb_identity::oidc::Endpoints {
            issuer: "https://id.home.example".into(),
            authorization_endpoint: "https://id.home.example/authorize".into(),
            token_endpoint: "https://id.home.example/token".into(),
            userinfo_endpoint: "https://id.home.example/userinfo".into(),
            end_session_endpoint: None,
        };
        let cx = SignIn::new(
            Oidc::with_endpoints(ep, "hlb", "s", "https://hlb.home.example/auth/return_to"),
            "https://hlb.home.example",
        );

        let mut refuse = false;
        for n in 0..(MAX_REQUESTS + 10) {
            let mut a = [0u8; 96];
            a[0] = (n % 251) as u8;
            a[1] = (n / 251) as u8;
            let (_, d) = cx.oidc.start(&a, None, now());
            if cx.store(d, "1.2.3.4").await.is_err() {
                refuse = true;
                break;
            }
        }
        assert!(refuse, "the request table should be capped");
    }

    #[tokio::test]
    async fn expired_requests_make_room_for_new_ones() {
        // The housekeeping must precede the cap, or a spike of abandoned sign-ins would
        // block the site until a restart.
        let ep = hlb_identity::oidc::Endpoints {
            issuer: "https://id.home.example".into(),
            authorization_endpoint: "https://id.home.example/authorize".into(),
            token_endpoint: "https://id.home.example/token".into(),
            userinfo_endpoint: "https://id.home.example/userinfo".into(),
            end_session_endpoint: None,
        };
        let cx = SignIn::new(
            Oidc::with_endpoints(ep, "hlb", "s", "https://hlb.home.example/auth/return_to"),
            "https://hlb.home.example",
        );

        // Requests already expired at the moment we file them.
        for n in 0..MAX_REQUESTS {
            let mut a = [0u8; 96];
            a[0] = (n % 251) as u8;
            a[1] = (n / 251) as u8;
            let (_, d) = cx.oidc.start(&a, None, 0);
            let _ = cx.store(d, &format!("client-{}", n % 200)).await;
        }

        let (_, fresh) = cx.oidc.start(&[9u8; 96], None, now());
        assert!(
            cx.store(fresh, "1.2.3.4").await.is_ok(),
            "the expired requests should have made room"
        );
    }
}
