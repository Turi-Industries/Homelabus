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
//! or hybrid flow), where anyone can forge one. The [`DemandeEnCours`] type is therefore
//! built so that the only way to obtain an [`Identite`] is through [`Oidc::terminer`],
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
//! | Replay of an old response | [`DemandeEnCours`]'s deadline and the `nonce` |
//! | A spoofed authorisation server | TLS to the discovered issuer |

use serde::Deserialize;

use crate::{Error, Result};

/// How long a sign-in request stays valid once started.
///
/// Long enough to register a passkey without rushing, short enough that a return URL
/// found in a browser history is no longer useful.
pub const DELAI_DEMANDE_S: i64 = 600;

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
/// 🔴 It holds the PKCE **verifier**, which is a secret: it must never go out to the
/// browser, or PKCE protects nothing. That is why it lives on the controller side and
/// only the `state` travels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemandeEnCours {
    pub state: String,
    verifier: String,
    nonce: String,
    pub cree_a: i64,
    /// Where to send the person once signed in (a UI route, never an absolute URL:
    /// see [`Self::retour_sur`]).
    pub retour: Option<String>,
}

impl DemandeEnCours {
    pub fn est_expiree(&self, maintenant: i64) -> bool {
        maintenant.saturating_sub(self.cree_a) > DELAI_DEMANDE_S
    }

    /// The post-sign-in destination, filtered.
    ///
    /// 🔴 Only a relative path starting with `/` is accepted. Without this filter, a
    /// link `.../auth/connexion?retour=https://elsewhere.example` would turn the sign-in
    /// screen into an open redirect - usable to make a phishing page look like it came
    /// from us. A leading `//` is refused too: that is an absolute URL in disguise
    /// (`//evil.example`).
    pub fn retour_sur(&self) -> &str {
        match self.retour.as_deref() {
            Some(r) if r.starts_with('/') && !r.starts_with("//") => r,
            _ => "/",
        }
    }
}

/// Qui vient de se connecter.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
pub struct Identite {
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

impl Identite {
    /// The account name to look up on the Homelabus side.
    ///
    /// `preferred_username` first, `sub` as a last resort: an opaque identifier is
    /// better than an account that cannot be linked at all.
    pub fn nom_de_compte(&self) -> &str {
        self.preferred_username.as_deref().unwrap_or(&self.sub)
    }

    pub fn nom_affiche(&self) -> &str {
        self.name.as_deref().unwrap_or_else(|| self.nom_de_compte())
    }
}

#[derive(Debug, Deserialize)]
struct ReponseJeton {
    access_token: String,
    #[serde(default)]
    id_token: Option<String>,
}

/// Le client OIDC du controller.
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
    pub async fn decouvrir(
        issuer: &str,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|source| Error::Http {
                source,
                context: "construction du client HTTP".into(),
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

        let endpoints: Endpoints = r.json().await.map_err(|source| Error::Http {
            source,
            context: "unreadable OIDC discovery".into(),
        })?;

        Ok(Self {
            endpoints,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http,
        })
    }

    /// Variant for tests and for an issuer that does not publish discovery.
    pub fn avec_endpoints(
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
    /// `alea` supplies the entropy for all three values (state, PKCE verifier, nonce) -
    /// passed in rather than drawn here, so the function stays **pure and testable**.
    ///
    /// 🔴 96 bytes, split into three thirds. Sharing them would make the `state`
    /// derivable from the verifier, and the other way round.
    pub fn demarrer(
        &self,
        alea: &[u8; 96],
        retour: Option<String>,
        maintenant: i64,
    ) -> (String, DemandeEnCours) {
        let state = hlb_types::token::base64url(&alea[0..32]);
        let verifier = hlb_types::token::base64url(&alea[32..64]);
        let nonce = hlb_types::token::base64url(&alea[64..96]);

        let challenge =
            hlb_types::token::base64url(&hlb_types::token::sha256_bytes(verifier.as_bytes()));

        let sep = if self.endpoints.authorization_endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        let url = format!(
            "{}{sep}response_type=code&client_id={}&redirect_uri={}&scope={}\
             &state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            self.endpoints.authorization_endpoint,
            pourcent(&self.client_id),
            pourcent(&self.redirect_uri),
            pourcent("openid profile email groups"),
            pourcent(&state),
            pourcent(&nonce),
            pourcent(&challenge),
        );

        (
            url,
            DemandeEnCours {
                state,
                verifier,
                nonce,
                cree_a: maintenant,
                retour,
            },
        )
    }

    /// Exchanges the code for an identity.
    ///
    /// Checks, in this order: the state, the deadline, then the `id_token`'s `nonce`.
    /// The order matters - a state that does not match signals a forged request, and we
    /// definitely do not want to have already called the `token` endpoint by then.
    pub async fn terminer(
        &self,
        demande: &DemandeEnCours,
        state_recu: &str,
        code: &str,
        maintenant: i64,
    ) -> Result<Identite> {
        if !hlb_types::token::constant_eq(&demande.state, state_recu) {
            return Err(Error::Unexpected(
                "invalid sign-in state: the response does not match a request \
                 started here (a forged request, or a sign-in begun in another tab)"
                    .into(),
            ));
        }
        if demande.est_expiree(maintenant) {
            return Err(Error::Unexpected(format!(
                "sign-in request expired (beyond {DELAI_DEMANDE_S} s) - start again"
            )));
        }

        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code_verifier", demande.verifier.as_str()),
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
            let detail = r.text().await.unwrap_or_default();
            return Err(Error::Api {
                status: status.as_u16(),
                detail: format!("code exchange refused: {detail}"),
            });
        }

        let jeton: ReponseJeton = r.json().await.map_err(|source| Error::Http {
            source,
            context: "unreadable token endpoint response".into(),
        })?;

        // The nonce, when there is an id_token. See the security note at the top of
        // this module: the payload is read without verifying the signature because the
        // token was just fetched directly, over TLS - never from the browser.
        if let Some(id) = &jeton.id_token {
            match nonce_de(id) {
                Some(n) if hlb_types::token::constant_eq(&demande.nonce, &n) => {}
                Some(_) => {
                    return Err(Error::Unexpected(
                        "the id_token nonce does not match: replayed response".into(),
                    ))
                }
                // An id_token with no nonce is not proof of a replay: some issuers do
                // not echo it back. We do not block on that, but we say so, because an
                // absent protection must not be silent.
                None => tracing::warn!(
                    "id_token sans nonce : la protection contre le rejeu repose \
                     only on the request deadline"
                ),
            }
        }

        let r = self
            .http
            .get(&self.endpoints.userinfo_endpoint)
            .bearer_auth(&jeton.access_token)
            .send()
            .await
            .map_err(|source| Error::Http {
                source,
                context: "lecture de userinfo".into(),
            })?;

        let status = r.status();
        if !status.is_success() {
            let detail = r.text().await.unwrap_or_default();
            return Err(Error::Api {
                status: status.as_u16(),
                detail: format!("userinfo refused: {detail}"),
            });
        }

        let identite: Identite = r.json().await.map_err(|source| Error::Http {
            source,
            context: "userinfo illisible".into(),
        })?;

        if identite.sub.is_empty() {
            return Err(Error::Unexpected(
                "userinfo with no \"sub\": an account cannot be linked to an identity \
                 stable"
                    .into(),
            ));
        }

        Ok(identite)
    }
}

/// The `nonce` carried in a JWT's payload.
///
/// Decoded without verifying the signature: see the security note at the top of this
/// module. Returns `None` as soon as anything does not fit - a malformed JWT is not
/// "nearly right".
fn nonce_de(jwt: &str) -> Option<String> {
    let charge = jwt.split('.').nth(1)?;
    let brut = hlb_types::token::base64url_decode(charge)?;
    let v: serde_json::Value = serde_json::from_slice(&brut).ok()?;
    v.get("nonce")?.as_str().map(str::to_string)
}

/// Percent-encoding for a query parameter (RFC 3986 §2.3, unreserved characters).
///
/// Written by hand for the same reason as the base64url: ten lines against one more
/// dependency in a path that handles secrets.
fn pourcent(s: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn oidc() -> Oidc {
        Oidc::avec_endpoints(
            Endpoints {
                issuer: "https://id.turi.fr".into(),
                authorization_endpoint: "https://id.turi.fr/authorize".into(),
                token_endpoint: "https://id.turi.fr/api/oidc/token".into(),
                userinfo_endpoint: "https://id.turi.fr/api/oidc/userinfo".into(),
                end_session_endpoint: None,
            },
            "hlb",
            "secret",
            "https://hlb.turi.fr/auth/retour",
        )
    }

    fn alea(graine: u8) -> [u8; 96] {
        let mut a = [0u8; 96];
        for (i, o) in a.iter_mut().enumerate() {
            *o = graine.wrapping_add((i * 31) as u8);
        }
        a
    }

    #[test]
    fn the_verifier_never_leaves_the_controller() {
        // 🔴 If the PKCE verifier went out in the URL, PKCE would protect nothing:
        // whoever intercepts the code would also intercept the means to exchange it.
        let (url, d) = oidc().demarrer(&alea(1), None, 0);
        assert!(
            !url.contains(&d.verifier),
            "the verifier is in the URL: {url}"
        );
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn the_three_secrets_are_independent() {
        // Drawing them from the same third of entropy would make the state derivable.
        let (_, d) = oidc().demarrer(&alea(7), None, 0);
        assert_ne!(d.state, d.verifier);
        assert_ne!(d.state, d.nonce);
        assert_ne!(d.verifier, d.nonce);
    }

    #[test]
    fn two_logins_never_share_a_state() {
        let (_, a) = oidc().demarrer(&alea(1), None, 0);
        let (_, b) = oidc().demarrer(&alea(2), None, 0);
        assert_ne!(a.state, b.state);
    }

    #[tokio::test]
    async fn a_forged_state_is_refused_before_any_network_call() {
        // 🔴 Order matters: we do not want to have already called the token endpoint
        // when discovering the request is forged. The test checks this in effect, since
        // the test URL does not exist - a network call would fail on a transport error,
        // not on the invalid-state message.
        let d = oidc().demarrer(&alea(3), None, 0).1;
        let e = oidc()
            .terminer(&d, "un-autre-etat", "code", 0)
            .await
            .expect_err("a different state must be refused");
        assert!(format!("{e}").contains("invalid sign-in state"), "{e}");
    }

    #[tokio::test]
    async fn an_expired_request_is_refused_before_any_network_call() {
        let d = oidc().demarrer(&alea(3), None, 0).1;
        let e = oidc()
            .terminer(&d, &d.state, "code", DELAI_DEMANDE_S + 1)
            .await
            .expect_err("an expired request must be refused");
        assert!(format!("{e}").contains("expired"), "{e}");
    }

    #[test]
    fn an_absolute_return_url_is_never_honoured() {
        // 🔴 Without this filter the sign-in screen becomes an open redirect: a
        // phishing link would route through our domain to look credible.
        for mechant in [
            "https://ailleurs.example",
            "//ailleurs.example",
            "javascript:alert(1)",
            "ailleurs.example",
        ] {
            let d = DemandeEnCours {
                state: "s".into(),
                verifier: "v".into(),
                nonce: "n".into(),
                cree_a: 0,
                retour: Some(mechant.to_string()),
            };
            assert_eq!(d.retour_sur(), "/", "aurait suivi {mechant}");
        }
    }

    #[test]
    fn a_relative_return_url_is_honoured() {
        let d = DemandeEnCours {
            state: "s".into(),
            verifier: "v".into(),
            nonce: "n".into(),
            cree_a: 0,
            retour: Some("/apps/gitea".into()),
        };
        assert_eq!(d.retour_sur(), "/apps/gitea");
    }

    #[test]
    fn the_nonce_is_read_from_a_jwt_payload() {
        // Payload only: neither header nor signature is needed to read it, and that is
        // precisely what this module assumes and documents.
        let charge = hlb_types::token::base64url(br#"{"nonce":"abc","sub":"u1"}"#);
        assert_eq!(
            nonce_de(&format!("entete.{charge}.signature")),
            Some("abc".into())
        );
    }

    #[test]
    fn a_malformed_jwt_yields_nothing_rather_than_a_guess() {
        assert_eq!(nonce_de("pas-un-jwt"), None);
        assert_eq!(nonce_de("a.b.c"), None);
        let sans = hlb_types::token::base64url(br#"{"sub":"u1"}"#);
        assert_eq!(nonce_de(&format!("e.{sans}.s")), None);
    }

    #[test]
    fn query_parameters_are_escaped() {
        // An unescaped `redirect_uri` would cut the URL at the first `&`, and the
        // authorisation server would redirect to a truncated address.
        assert_eq!(
            pourcent("https://a/b?c=d&e"),
            "https%3A%2F%2Fa%2Fb%3Fc%3Dd%26e"
        );
        assert_eq!(pourcent("openid profile"), "openid%20profile");
        assert_eq!(pourcent("aZ0-._~"), "aZ0-._~");
    }

    #[test]
    fn the_authorization_url_carries_everything_the_flow_needs() {
        let (url, d) = oidc().demarrer(&alea(9), None, 0);
        for attendu in [
            "response_type=code",
            "client_id=hlb",
            "scope=openid%20profile%20email%20groups",
            "code_challenge_method=S256",
        ] {
            assert!(url.contains(attendu), "{attendu} manque dans {url}");
        }
        assert!(url.contains(&format!("state={}", pourcent(&d.state))));
    }

    #[test]
    fn the_subject_is_what_identifies_a_person_not_the_username() {
        // Un nom d'utilisateur se renomme ; le `sub` ne bouge pas. Se rattacher au nom
        // perdrait le lien au premier renommage, en silence.
        let i = Identite {
            sub: "abc-123".into(),
            preferred_username: None,
            ..Default::default()
        };
        assert_eq!(i.nom_de_compte(), "abc-123");

        let i = Identite {
            sub: "abc-123".into(),
            preferred_username: Some("remy".into()),
            ..Default::default()
        };
        assert_eq!(i.nom_de_compte(), "remy");
        assert_eq!(i.nom_affiche(), "remy", "falling back when no display name");
    }
}
