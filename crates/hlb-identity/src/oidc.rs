//! Human sign-in through PocketID (OpenID Connect, authorisation code + PKCE).
//!
//! ## Why this module exists
//!
//! Until now Homelabus only authenticated **machines**: an API token in an
//! `Authorization` header. That is the right tool for the CLI, for Bitwarden and for a
//! metrics scrape. It is the wrong one for twenty people - they would have to keep and
//! paste a 52-character value, with no way to sign out and no way to know who is signed
//! in.
//!
//! Here the person authenticates at PocketID (with a passkey; there is no password) and
//! comes back with a code the controller exchanges **itself**, server to server.
//!
//! ## 🔴 Why the `id_token` signature is NOT verified
//!
//! This is the point that surprises on review, so it is written here rather than
//! discovered in six months.
//!
//! The `id_token` **never arrives through the browser**. It is fetched by a direct call
//! from the controller to PocketID's `token` endpoint, over a TLS connection whose
//! certificate already authenticates the issuer. That is exactly the case OpenID
//! Connect Core §3.1.3.7 point 6 provides for, which then waives signature validation:
//! the channel does the work the signature would.
//!
//! ⚠️ **This reasoning would NOT hold** for a token received from the browser (implicit
//! or hybrid flow), where anyone can forge one. The [`PendingRequest`] type is therefore
//! built so that the only way to obtain an [`Identity`] is through [`Oidc::finish`],
//! which performs the exchange itself.
//!
//! The identity itself is read from the `userinfo` endpoint, also called server to
//! server. The `id_token` payload is only decoded to check the `nonce`.
//!
//! ## What actually protects the exchange
//!
//! | Attack | What stops it |
//! |---|---|
//! | A request forged from another site | the `state` parameter, compared in constant time |
//! | Interception of the authorisation code | PKCE `S256`: the code alone is not enough |
//! | Replay of an old response | [`PendingRequest`]'s deadline and the `nonce` |
//! | A spoofed authorisation server | TLS to the discovered issuer |

use serde::Deserialize;

use crate::{Error, Result};

/// How long a sign-in request stays valid once started.
///
/// Long enough to register a passkey without rushing, short enough that a return URL
/// found in a browser history is no longer useful.
pub const REQUEST_TIMEOUT_S: i64 = 600;

/// How recent a passkey confirming a destruction must be: asked of PocketID as
/// `max_age`, and checked on the `auth_time` it answers.
pub const CONFIRMATION_MAX_AGE_S: i64 = 300;

/// A passkey just presented, for one action: who, and when PocketID saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation {
    pub identity: Identity,
    /// Seconds since the epoch, from the `id_token`.
    pub auth_time: i64,
}

/// The endpoints, discovered rather than guessed.
///
/// Hard-coding them would work today and break the day PocketID moves them, with a
/// `404` that would not say discovery was the thing to do.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Endpoints {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
}

/// A sign-in request in flight, waiting for the browser to come back.
///
/// 🔴 It holds the PKCE **check**, which is a secret: it must never go out to the
/// browser, or PKCE protects nothing. That is why it lives on the controller side and
/// only the `state` travels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    pub state: String,
    check: String,
    nonce: String,
    pub created_at: i64,
    /// Where to send the person once signed in (a UI route, never an absolute URL:
    /// see [`Self::return_onto`]).
    pub return_to: Option<String>,
}

impl PendingRequest {
    pub fn is_expired(&self, now: i64) -> bool {
        now.saturating_sub(self.created_at) > REQUEST_TIMEOUT_S
    }

    /// The post-sign-in destination, filtered.
    ///
    /// 🔴 Only a relative path starting with `/` is accepted. Without this filter, a
    /// link `.../auth/signin?return_to=https://elsewhere.example` would turn the sign-in
    /// screen into an open redirect - usable to make a phishing page look like it came
    /// from us. A leading `//` is refused too: that is an absolute URL in disguise
    /// (`//evil.example`). So is any backslash, whitespace or control character:
    /// browsers read `\` as `/` and drop a tab or a newline, so `/\evil.example` and
    /// `/<tab>/evil.example` both become `//evil.example` on arrival.
    pub fn return_onto(&self) -> &str {
        match self.return_to.as_deref() {
            Some(r)
                if r.starts_with('/')
                    && !r.starts_with("//")
                    && !r
                        .chars()
                        .any(|c| c == '\\' || c.is_whitespace() || c.is_control()) =>
            {
                r
            }
            _ => "/",
        }
    }
}

/// Who has just signed in.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
pub struct Identity {
    /// The stable identifier at PocketID. THIS is authoritative, not the username:
    /// the latter can be renamed, and the link would be lost.
    pub sub: String,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    /// The PocketID groups, kept for anyone preferring the group-driven scheme
    /// (`Role::from_groups`). Homelabus does not use them by default.
    #[serde(default)]
    pub groups: Vec<String>,
}

impl Identity {
    /// The account name to look up on the Homelabus side.
    ///
    /// `preferred_username` first, `sub` as a last resort: an opaque identifier is
    /// better than an account that cannot be linked at all.
    pub fn account_name(&self) -> &str {
        self.preferred_username.as_deref().unwrap_or(&self.sub)
    }

    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or_else(|| self.account_name())
    }
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    id_token: Option<String>,
}

/// The controller's OIDC client.
#[derive(Debug, Clone)]
pub struct Oidc {
    endpoints: Endpoints,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http: reqwest::Client,
}

impl Oidc {
    /// Discovers the endpoints at the issuer.
    pub async fn discover(
        issuer: &str,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<Self> {
        Self::discover_trusting(issuer, client_id, client_secret, redirect_uri, None).await
    }

    /// The same, trusting one more root (PEM): the issuer's certificate is signed by
    /// the house's own authority, which no public bundle carries. Added to the public
    /// roots, never in their place.
    pub async fn discover_trusting(
        issuer: &str,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        root_pem: Option<&str>,
    ) -> Result<Self> {
        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(15));
        if let Some(pem) = root_pem {
            let root =
                reqwest::Certificate::from_pem(pem.as_bytes()).map_err(|source| Error::Http {
                    source,
                    context: "reading the trusted root".into(),
                })?;
            builder = builder.add_root_certificate(root);
        }
        let http = builder.build().map_err(|source| Error::Http {
            source,
            context: "building the HTTP client".into(),
        })?;

        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let r = http.get(&url).send().await.map_err(|source| Error::Http {
            source,
            context: format!("OIDC discovery at {url}"),
        })?;

        let status = r.status();
        if !status.is_success() {
            return Err(Error::Api {
                status: status.as_u16(),
                detail: format!("OIDC discovery failed at {url} - is the issuer really PocketID?"),
            });
        }

        let endpoints: Endpoints = read_json(r, "OIDC discovery").await?;

        Ok(Self {
            endpoints,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http,
        })
    }

    /// Variant for tests and for an issuer that does not publish discovery.
    pub fn with_endpoints(
        endpoints: Endpoints,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            endpoints,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http: reqwest::Client::new(),
        }
    }

    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    /// Builds the URL to send the browser to, and the request to remember.
    ///
    /// `entropy` supplies the entropy for all three values (state, PKCE check, nonce) -
    /// passed in rather than drawn here, so the function stays **pure and testable**.
    ///
    /// 🔴 96 bytes, split into three thirds. Sharing them would make the `state`
    /// derivable from the check, and the other way round.
    pub fn start(
        &self,
        entropy: &[u8; 96],
        return_to: Option<String>,
        now: i64,
    ) -> (String, PendingRequest) {
        let state = hlb_types::token::base64url(&entropy[0..32]);
        let check = hlb_types::token::base64url(&entropy[32..64]);
        let nonce = hlb_types::token::base64url(&entropy[64..96]);
        let url = self.authorize_url(&state, &check, &nonce, "openid profile email groups", "");
        (
            url,
            PendingRequest {
                state,
                check,
                nonce,
                created_at: now,
                return_to,
            },
        )
    }

    /// The same, for confirming one action with a passkey: PocketID asks for it again
    /// whatever session it holds (`prompt=login`), and the `nonce` is the caller's —
    /// the digest of what is confirmed, so the answer names it.
    pub fn start_confirming(
        &self,
        entropy: &[u8; 64],
        nonce: &str,
        now: i64,
    ) -> (String, PendingRequest) {
        let state = hlb_types::token::base64url(&entropy[0..32]);
        let check = hlb_types::token::base64url(&entropy[32..64]);
        let url = self.authorize_url(
            &state,
            &check,
            nonce,
            "openid",
            &format!("&prompt=login&max_age={CONFIRMATION_MAX_AGE_S}"),
        );
        (
            url,
            PendingRequest {
                state,
                check,
                nonce: nonce.to_string(),
                created_at: now,
                return_to: None,
            },
        )
    }

    fn authorize_url(
        &self,
        state: &str,
        check: &str,
        nonce: &str,
        scope: &str,
        extra: &str,
    ) -> String {
        let challenge =
            hlb_types::token::base64url(&hlb_types::token::sha256_bytes(check.as_bytes()));
        let sep = if self.endpoints.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        format!(
            "{}{sep}response_type=code&client_id={}&redirect_uri={}&scope={}\
             &state={}&nonce={}&code_challenge={}&code_challenge_method=S256{extra}",
            self.endpoints.authorization_endpoint,
            percent_encode(&self.client_id),
            percent_encode(&self.redirect_uri),
            percent_encode(scope),
            percent_encode(state),
            percent_encode(nonce),
            percent_encode(&challenge),
        )
    }

    /// Exchanges the code for an identity.
    ///
    /// Checks, in this order: the state, the deadline, then the `id_token`'s `nonce`.
    /// The order matters - a state that does not match signals a forged request, and we
    /// definitely do not want to have already called the `token` endpoint by then.
    pub async fn finish(
        &self,
        request: &PendingRequest,
        received_state: &str,
        code: &str,
        now: i64,
    ) -> Result<Identity> {
        let (id_token, identity) = self.exchange(request, received_state, code, now).await?;
        // The nonce, when there is an id_token. See the security note at the top of
        // this module: the payload is read without verifying the signature because the
        // token was just fetched directly, over TLS - never from the browser.
        if let Some(id) = &id_token {
            match nonce_of(id) {
                Some(n) if hlb_types::token::constant_eq(&request.nonce, &n) => {}
                Some(_) => {
                    return Err(Error::Unexpected(
                        "the id_token nonce does not match: replayed response".into(),
                    ))
                }
                // An id_token with no nonce is not proof of a replay: some issuers do
                // not echo it back. We do not block on that, but we say so, because an
                // absent protection must not be silent.
                None => tracing::warn!(
                    "id_token with no nonce: replay protection then rests \
                     only on the request deadline"
                ),
            }
        }
        Ok(identity)
    }

    /// Exchanges a confirmation's code: the `id_token` must carry the request's
    /// `nonce` and an `auth_time` — no leniency here, they are what binds the passkey
    /// to the action and to the moment.
    pub async fn finish_confirming(
        &self,
        request: &PendingRequest,
        received_state: &str,
        code: &str,
        now: i64,
    ) -> Result<Confirmation> {
        let (id_token, identity) = self.exchange(request, received_state, code, now).await?;
        let claims = id_token.as_deref().and_then(claims_of).ok_or_else(|| {
            Error::Unexpected("a confirmation answered with no readable id_token".into())
        })?;
        match claims.get("nonce").and_then(|n| n.as_str()) {
            Some(n) if hlb_types::token::constant_eq(&request.nonce, n) => {}
            _ => {
                return Err(Error::Unexpected(
                    "the passkey confirmed something else: the id_token's nonce is not \
                     this action's"
                        .into(),
                ))
            }
        }
        let auth_time = claims
            .get("auth_time")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| {
                Error::Unexpected("the id_token does not say when the passkey was used".into())
            })?;
        Ok(Confirmation {
            identity,
            auth_time,
        })
    }

    /// The code exchanged for the `id_token` and the identity `userinfo` gives.
    async fn exchange(
        &self,
        request: &PendingRequest,
        received_state: &str,
        code: &str,
        now: i64,
    ) -> Result<(Option<String>, Identity)> {
        if !hlb_types::token::constant_eq(&request.state, received_state) {
            return Err(Error::Unexpected(
                "invalid sign-in state: the response does not match a request \
                 started here (a forged request, or a sign-in begun in another tab)"
                    .into(),
            ));
        }
        if request.is_expired(now) {
            return Err(Error::Unexpected(format!(
                "sign-in request expired (beyond {REQUEST_TIMEOUT_S} s) - start again"
            )));
        }

        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code_verifier", request.check.as_str()),
        ];

        let r = self
            .http
            .post(&self.endpoints.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|source| Error::Http {
                source,
                context: "authorisation code exchange".into(),
            })?;

        let status = r.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized);
        }
        if !status.is_success() {
            let detail = read_text(r).await;
            return Err(Error::Api {
                status: status.as_u16(),
                detail: format!("code exchange refused: {detail}"),
            });
        }

        let token: TokenResponse = read_json(r, "the token endpoint's response").await?;

        let r = self
            .http
            .get(&self.endpoints.userinfo_endpoint)
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|source| Error::Http {
                source,
                context: "reading userinfo".into(),
            })?;

        let status = r.status();
        if !status.is_success() {
            let detail = read_text(r).await;
            return Err(Error::Api {
                status: status.as_u16(),
                detail: format!("userinfo refused: {detail}"),
            });
        }

        let identity: Identity = read_json(r, "userinfo").await?;

        if identity.sub.is_empty() {
            return Err(Error::Unexpected(
                "userinfo with no \"sub\": an account cannot be linked to an identity \
                 stable"
                    .into(),
            ));
        }

        Ok((token.id_token, identity))
    }
}

/// The `nonce` carried in a JWT's payload.
///
/// Decoded without verifying the signature: see the security note at the top of this
/// module. Returns `None` as soon as anything does not fit - a malformed JWT is not
/// "nearly right".
fn nonce_of(jwt: &str) -> Option<String> {
    claims_of(jwt)?.get("nonce")?.as_str().map(str::to_string)
}

/// A JWT's payload, read the same way.
fn claims_of(jwt: &str) -> Option<serde_json::Value> {
    let load = jwt.split('.').nth(1)?;
    let raw = hlb_types::token::base64url_decode(load)?;
    serde_json::from_slice(&raw).ok()
}

/// Percent-encoding for a query parameter (RFC 3986 §2.3, unreserved characters).
///
/// Written by hand for the same reason as the base64url: ten lines against one more
/// dependency in a path that handles secrets.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The most an OIDC answer is read to: discovery, a token and a userinfo are a few
/// kilobytes.
const MAX_BODY: usize = 1024 * 1024;

async fn read_json<T: serde::de::DeserializeOwned>(r: reqwest::Response, what: &str) -> Result<T> {
    let body = bounded(r, MAX_BODY)
        .await
        .map_err(|e| Error::Unexpected(format!("{what}: {e}")))?;
    serde_json::from_slice(&body).map_err(|e| Error::Unexpected(format!("unreadable {what}: {e}")))
}

/// A refusal's body, to say why — cut, and empty when it cannot be read.
async fn read_text(r: reqwest::Response) -> String {
    String::from_utf8_lossy(&bounded(r, 64 * 1024).await.unwrap_or_default()).into_owned()
}

/// A response's body, read to `max` bytes and no further.
///
/// 🔴 `json()` and `text()` read whatever comes: a server answering without end — or
/// whatever sits on the path to it — filled the memory of the process reading it.
async fn bounded(mut resp: reqwest::Response, max: usize) -> std::result::Result<Vec<u8>, String> {
    let too_large = || format!("an answer larger than {max} bytes, not read");
    if resp.content_length().is_some_and(|n| n > max as u64) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if body.len() + chunk.len() > max {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oidc() -> Oidc {
        Oidc::with_endpoints(
            Endpoints {
                issuer: "https://id.home.example".into(),
                authorization_endpoint: "https://id.home.example/authorize".into(),
                token_endpoint: "https://id.home.example/api/oidc/token".into(),
                userinfo_endpoint: "https://id.home.example/api/oidc/userinfo".into(),
                end_session_endpoint: None,
            },
            "hlb",
            "secret",
            "https://hlb.home.example/auth/return_to",
        )
    }

    fn entropy(seed: u8) -> [u8; 96] {
        let mut a = [0u8; 96];
        for (i, o) in a.iter_mut().enumerate() {
            *o = seed.wrapping_add((i * 31) as u8);
        }
        a
    }

    #[test]
    fn the_verifier_never_leaves_the_controller() {
        // 🔴 If the PKCE check went out in the URL, PKCE would protect nothing:
        // whoever intercepts the code would also intercept the means to exchange it.
        let (url, d) = oidc().start(&entropy(1), None, 0);
        assert!(!url.contains(&d.check), "the check is in the URL: {url}");
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
    }

    /// A PocketID whose token endpoint answers an `id_token` carrying `claims`, and
    /// whose userinfo answers `sub` u1.
    async fn issuer(claims: serde_json::Value) -> Oidc {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", l.local_addr().expect("addr"));
        let id_token = format!(
            "h.{}.s",
            hlb_types::token::base64url(claims.to_string().as_bytes())
        );
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                let mut buf = [0u8; 8192];
                let n = c.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let body = if head.starts_with("POST /token") {
                    format!(r#"{{"access_token":"a","id_token":"{id_token}"}}"#)
                } else {
                    r#"{"sub":"u1","preferred_username":"alice"}"#.to_string()
                };
                let _ = c
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                             content-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            }
        });
        Oidc::with_endpoints(
            Endpoints {
                issuer: base.clone(),
                authorization_endpoint: format!("{base}/authorize"),
                token_endpoint: format!("{base}/token"),
                userinfo_endpoint: format!("{base}/userinfo"),
                end_session_endpoint: None,
            },
            "hlb",
            "secret",
            "https://hlb.home.example/auth/confirmed",
        )
    }

    #[test]
    fn a_confirmation_asks_for_the_passkey_again_and_names_the_action() {
        let mut e = [0u8; 64];
        e[..].copy_from_slice(&entropy(9)[..64]);
        let (url, d) = oidc().start_confirming(&e, "digest-of-the-action", 0);
        assert_ne!(d.state, d.check);
        assert!(url.contains("&prompt=login"), "{url}");
        assert!(
            url.contains(&format!("&max_age={CONFIRMATION_MAX_AGE_S}")),
            "{url}"
        );
        assert!(url.contains("&nonce=digest-of-the-action&"), "{url}");
        assert!(url.contains("&scope=openid&"), "{url}");
        assert!(!url.contains(&d.check), "the check is in the URL: {url}");
    }

    #[tokio::test]
    async fn a_confirmation_says_who_and_when() {
        let o = issuer(serde_json::json!({"nonce": "n1", "auth_time": 1000, "sub": "u1"})).await;
        let (_, d) = o.start_confirming(&[3; 64], "n1", 1000);
        let c = o
            .finish_confirming(&d, &d.state, "code", 1010)
            .await
            .expect("confirmed");
        assert_eq!(c.identity.sub, "u1");
        assert_eq!(c.auth_time, 1000);
    }

    #[tokio::test]
    async fn a_passkey_given_for_another_action_confirms_nothing() {
        // 🔴 The nonce is the digest of what is confirmed: an answer for another
        // action, or one saying nothing, never passes — unlike a sign-in's.
        for claims in [
            serde_json::json!({"nonce": "other", "auth_time": 1000}),
            serde_json::json!({"auth_time": 1000}),
            serde_json::json!({"nonce": "n1"}),
        ] {
            let o = issuer(claims.clone()).await;
            let (_, d) = o.start_confirming(&[3; 64], "n1", 1000);
            o.finish_confirming(&d, &d.state, "code", 1010)
                .await
                .expect_err(&format!("{claims} confirmed"));
        }
    }

    #[test]
    fn the_three_secrets_are_independent() {
        // Drawing them from the same third of entropy would make the state derivable.
        let (_, d) = oidc().start(&entropy(7), None, 0);
        assert_ne!(d.state, d.check);
        assert_ne!(d.state, d.nonce);
        assert_ne!(d.check, d.nonce);
    }

    #[test]
    fn two_logins_never_share_a_state() {
        let (_, a) = oidc().start(&entropy(1), None, 0);
        let (_, b) = oidc().start(&entropy(2), None, 0);
        assert_ne!(a.state, b.state);
    }

    #[tokio::test]
    async fn a_forged_state_is_refused_before_any_network_call() {
        // 🔴 Order matters: we do not want to have already called the token endpoint
        // when discovering the request is forged. The test checks this in effect, since
        // the test URL does not exist - a network call would fail on a transport error,
        // not on the invalid-state message.
        let d = oidc().start(&entropy(3), None, 0).1;
        let e = oidc()
            .finish(&d, "un-other-state", "code", 0)
            .await
            .expect_err("a different state must be refused");
        assert!(format!("{e}").contains("invalid sign-in state"), "{e}");
    }

    #[tokio::test]
    async fn an_expired_request_is_refused_before_any_network_call() {
        let d = oidc().start(&entropy(3), None, 0).1;
        let e = oidc()
            .finish(&d, &d.state, "code", REQUEST_TIMEOUT_S + 1)
            .await
            .expect_err("an expired request must be refused");
        assert!(format!("{e}").contains("expired"), "{e}");
    }

    #[test]
    fn an_absolute_return_url_is_never_honoured() {
        // 🔴 Without this filter the sign-in screen becomes an open redirect: a
        // phishing link would route through our domain to look credible.
        for malicious in [
            "https://ailleurs.example",
            "//ailleurs.example",
            "javascript:alert(1)",
            "ailleurs.example",
            "/\\ailleurs.example",
            "/\t/ailleurs.example",
            "/\n/ailleurs.example",
            "/ /ailleurs.example",
        ] {
            let d = PendingRequest {
                state: "s".into(),
                check: "v".into(),
                nonce: "n".into(),
                created_at: 0,
                return_to: Some(malicious.to_string()),
            };
            assert_eq!(d.return_onto(), "/", "would still honour {malicious}");
        }
    }

    #[test]
    fn a_relative_return_url_is_honoured() {
        let d = PendingRequest {
            state: "s".into(),
            check: "v".into(),
            nonce: "n".into(),
            created_at: 0,
            return_to: Some("/apps/gitea".into()),
        };
        assert_eq!(d.return_onto(), "/apps/gitea");
    }

    #[test]
    fn the_nonce_is_read_from_a_jwt_payload() {
        // Payload only: neither header nor signature is needed to read it, and that is
        // precisely what this module assumes and documents.
        let load = hlb_types::token::base64url(br#"{"nonce":"abc","sub":"u1"}"#);
        assert_eq!(
            nonce_of(&format!("header.{load}.signature")),
            Some("abc".into())
        );
    }

    #[test]
    fn a_malformed_jwt_yields_nothing_rather_than_a_guess() {
        assert_eq!(nonce_of("not-a-jwt"), None);
        assert_eq!(nonce_of("a.b.c"), None);
        let without_nonce = hlb_types::token::base64url(br#"{"sub":"u1"}"#);
        assert_eq!(nonce_of(&format!("e.{without_nonce}.s")), None);
    }

    #[test]
    fn query_parameters_are_escaped() {
        // An unescaped `redirect_uri` would cut the URL at the first `&`, and the
        // authorisation server would redirect to a truncated address.
        assert_eq!(
            percent_encode("https://a/b?c=d&e"),
            "https%3A%2F%2Fa%2Fb%3Fc%3Dd%26e"
        );
        assert_eq!(percent_encode("openid profile"), "openid%20profile");
        assert_eq!(percent_encode("aZ0-._~"), "aZ0-._~");
    }

    #[test]
    fn the_authorization_url_carries_everything_the_flow_needs() {
        let (url, d) = oidc().start(&entropy(9), None, 0);
        for expected in [
            "response_type=code",
            "client_id=hlb",
            "scope=openid%20profile%20email%20groups",
            "code_challenge_method=S256",
        ] {
            assert!(url.contains(expected), "{expected} missing from {url}");
        }
        assert!(url.contains(&format!("state={}", percent_encode(&d.state))));
    }

    #[test]
    fn the_subject_is_what_identifies_a_person_not_the_username() {
        // A username gets renamed; the `sub` does not move. Keying on the name would
        // lose the link on the first rename, silently.
        let i = Identity {
            sub: "abc-123".into(),
            preferred_username: None,
            ..Default::default()
        };
        assert_eq!(i.account_name(), "abc-123");

        let i = Identity {
            sub: "abc-123".into(),
            preferred_username: Some("lena".into()),
            ..Default::default()
        };
        assert_eq!(i.account_name(), "lena");
        assert_eq!(
            i.display_name(),
            "lena",
            "falling back when no display name"
        );
    }
}
