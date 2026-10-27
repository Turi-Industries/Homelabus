//! Who is making the request, and are they entitled to.
//!
//! ## Two ways of being authenticated, one way of being authorized
//!
//! | Bearer | Mechanism | For whom |
//! |---|---|---|
//! | `Authorization: Bearer hlb_…` | API token, fingerprint in the database | the CLI, Bitwarden, a scrape |
//! | `Cookie: hlb_session=…` | session set after PocketID OIDC | a person, in a browser |
//!
//! Both produce an [`Identity`]. From there the check is the same: the role is matched
//! against an [`Action`](hlb_types::rbac::Action) by [`Authorized`].
//!
//! ## 🔴 Why a person's role is re-read on every request
//!
//! It would be cheaper to freeze the role into the session at sign-in. But then, taking
//! someone's administrator rights away would have no effect for as long as their
//! session lives — up to twelve hours. And you take rights away precisely when you are
//! in a hurry to. So the role is re-read from `user_roles` on every request.
//!
//! A token carries its own role: it does not belong to a person but to a purpose, and
//! you revoke it by deleting it.

use std::marker::PhantomData;
use std::sync::Arc;

use hlb_types::rbac::Action;

use crate::api::AppState;
use crate::error::ApiError;

/// Name of the session cookie.
pub const COOKIE: &str = "hlb_session";

/// A session's lifetime, sliding: every request pushes it back.
pub const SESSION_DURATION_S: i64 = 12 * 3600;

/// 🔴 Header required on every mutating request authenticated by COOKIE.
///
/// `SameSite=Lax` stops the cookie leaving on a cross-site navigation, but **not** on a
/// form `POST` triggered from another site in some browsers and configurations. A custom
/// header does: the browser only adds it to a same-origin `fetch` request, and a
/// cross-origin request carrying it would trigger a CORS preflight the controller does
/// not satisfy.
///
/// Token calls are exempt: with no cookie there is no ambient authority to hijack, so no
/// CSRF.
pub const UI_HEADER: &str = "x-hlb-ui";

/// The actor every request of `--demo` is, acting for [`crate::demo::ADMIN`].
pub const DEMONSTRATION: &str = "demonstration";

/// Who is acting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Actor {
    /// A machine. `user` is the account the token may act on behalf of —
    /// `None` for a service token, which acts on nobody's behalf.
    Token { name: String, user: Option<String> },
    /// A person, signed in from a browser.
    Person { user: String },
    /// `--insecure-no-auth` mode. Named, so the audit log does not pretend an identified
    /// administrator acted.
    Anonymous,
}

impl Actor {
    /// The name to write to the audit log.
    pub fn name(&self) -> &str {
        match self {
            Self::Token { name, .. } => name,
            Self::Person { user } => user,
            Self::Anonymous => "anonymous",
        }
    }

    /// The account this request acts on behalf of, if there is one.
    ///
    /// 🔴 This is what everything touching a person's data consults (aliases, mailboxes,
    /// Sieve). A service token returns `None`, and the caller must refuse: privilege
    /// does not replace identity — a stolen `admin` token must not be able to create
    /// addresses on anyone's mailbox.
    pub fn for_account(&self) -> Option<&str> {
        match self {
            Self::Token { user, .. } => user.as_deref(),
            Self::Person { user } => Some(user),
            Self::Anonymous => None,
        }
    }

    pub fn is_person(&self) -> bool {
        matches!(self, Self::Person { .. })
    }
}

/// The identity behind a request: who, and with what role.
///
/// 🔴 An extractor, so a route that needs it cannot forget to ask for it: the compiler
/// demands it in the signature. A check written by hand in every handler always ends up
/// missing somewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub role: hlb_types::Role,
    pub actor: Actor,
}

impl Identity {
    pub fn can(&self, action: Action) -> bool {
        self.role.allows(action)
    }

    /// The message of a refusal, or `None` if the action is allowed.
    pub fn refusal(&self, action: Action) -> Option<String> {
        self.role.refusal(action)
    }
}

/// L'horloge murale en secondes Unix.
///
/// ⚠️ Never `Instant`: here we compare against deadlines stored in the database, not
/// durations. An `Instant` does not survive a restart.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The value of one cookie in a `Cookie` header.
///
/// Parsing written by hand: the header is a `name=value` list separated by `; `, and one
/// more dependency for that is not justified.
///
/// ⚠️ We compare the name **exactly**. Without that, an `xhlb_session` cookie set by a
/// third-party subdomain would be accepted in place of ours.
/// The session a request was authenticated by, handed to `signin::reissue` so the
/// response carries its cookie again.
#[derive(Clone, Default)]
pub struct Slid(Arc<std::sync::Mutex<Option<String>>>);

impl Slid {
    fn set(&self, value: &str) {
        if let Ok(mut v) = self.0.lock() {
            *v = Some(value.to_string());
        }
    }

    pub fn take(&self) -> Option<String> {
        self.0.lock().ok().and_then(|mut v| v.take())
    }
}

pub fn cookie(header: &str, name: &str) -> Option<String> {
    header.split(';').find_map(|part| {
        let part = part.trim();
        let (k, v) = part.split_once('=')?;
        (k.trim() == name).then(|| v.trim().to_string())
    })
}

impl axum::extract::FromRequestParts<Arc<AppState>> for Identity {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        s: &Arc<AppState>,
    ) -> std::result::Result<Self, Self::Rejection> {
        if s.demo {
            // The demonstration acts for its own administrator, so that what only a
            // signed-in person is offered — arranging the home, setting a problem aside,
            // one's own mailbox — is there to see and to test. Through a token named for
            // what it is: the audit log names "demonstration", never a person.
            return Ok(Self {
                role: hlb_types::Role::Admin,
                actor: Actor::Token {
                    name: DEMONSTRATION.into(),
                    user: Some(crate::demo::ADMIN.into()),
                },
            });
        }
        if s.no_auth {
            // Open mode, deliberately: the startup announced it loudly. The actor stays
            // named `anonymous` so the audit log does not claim better.
            return Ok(Self {
                role: hlb_types::Role::Admin,
                actor: Actor::Anonymous,
            });
        }

        // 1. The session cookie first: the common case from a browser.
        let raw = parts
            .headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| cookie(v, COOKIE));

        if let Some(value) = raw {
            let now = now();
            if let Ok(Some((user, _sub))) = s.state.find_session(&value, now).await {
                // 🔴 CSRF: a mutating request carried by a cookie must prove
                // that it comes from our own interface.
                if mutates(&parts.method) && !parts.headers.contains_key(UI_HEADER) {
                    return Err(ApiError::Forbidden(format!(
                        "request refused: an action authenticated by session must carry the \
                         \"{UI_HEADER}\" header. That is the protection against requests \
                         triggered from another site."
                    )));
                }

                // Extends the session without waiting: recording the use must neither
                // slow the request down nor make it fail.
                let st = s.state.clone();
                let v = value.clone();
                tokio::spawn(async move {
                    let _ = st.touch_session(&v, now, SESSION_DURATION_S).await;
                });
                if let Some(slid) = parts.extensions.get::<Slid>() {
                    slid.set(&value);
                }

                // 🔴 The role is re-read here, not read from the session: see the header.
                let role = s.state.user_role(&user).await.unwrap_or_default();
                return Ok(Self {
                    role,
                    actor: Actor::Person { user },
                });
            }
        }

        // 2. Otherwise an API token.
        let presented = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");

        // ⚠️ The same answer for "no token", "unknown token" and "expired session".
        // Distinguishing would tell an attacker whether a value they tried exists.
        match s.state.find_token(presented).await {
            Ok(Some(t)) => {
                let st = s.state.clone();
                let name = t.name.clone();
                tokio::spawn(async move {
                    let _ = st.touch_token(&name).await;
                });

                let user = s.state.token_user(&t.name).await.unwrap_or(None);
                // 🔴 A token bound to a person never does more than that person may:
                // made while they were admin, it kept admin after they were demoted.
                // Their role is re-read here, as a session's is.
                let role = match &user {
                    Some(u) => t.role.min(s.state.user_role(u).await.unwrap_or_default()),
                    None => t.role,
                };
                Ok(Self {
                    role,
                    actor: Actor::Token { name: t.name, user },
                })
            }
            _ => Err(ApiError::Unauthenticated),
        }
    }
}

/// Does the request change anything?
fn mutates(m: &axum::http::Method) -> bool {
    !matches!(
        *m,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    )
}

// ---------------------------------------------------------------------------
// Authorization, carried by the type of the handler's argument
// ---------------------------------------------------------------------------

/// What a route requires.
///
/// 🔴 Rust does not accept an enum variant as a const generic parameter. Hence one
/// marker per action rather than an `Authorized<{Action::Operate}>`. The benefit is the
/// same: the requirement is **in the handler's signature**, so visible on review and
/// impossible to forget.
pub trait Requires {
    const ACTION: Action;
}

macro_rules! marker {
    ($($name:ident => $action:ident, $doc:literal;)*) => {
        $(
            #[doc = $doc]
            pub struct $name;
            impl Requires for $name {
                const ACTION: Action = Action::$action;
            }
        )*

        /// Every marker and the action it requires.
        ///
        /// Used by the exhaustiveness test: an action with no marker would be an action
        /// no route can require.
        #[cfg(test)]
        pub(crate) const MARKERS: &[Action] = &[$(Action::$action),*];
    };
}

marker! {
    CanReadSelf => ReadSelf, "See your own data.";
    CanActOnSelf => ActOnSelf, "Change your own data: aliases, sorting, theme.";
    CanRead => Read, "See operations: cluster, nodes, logs, metrics.";
    CanPublish => Publish, "Publish an announcement, open or close an incident.";
    CanOperate => Operate, "Install, update, back up, drain.";
    CanManageAccounts => ManageAccounts, "Create an account, guest, change a role.";
    CanDestroy => Destroy, "🔴 Destroy, purge, restore in production.";
}

/// An identity **whose right has been checked**.
///
/// 🔴 The guarantee is structural: a handler taking `Authorized<CanOperate>`
/// cannot run without the check having happened, because the extraction fails before it.
/// It is the same idea as `Freshness` on the UI side — the type forces you to
/// look.
pub struct Authorized<E: Requires>(pub Identity, PhantomData<E>);

impl<E: Requires> Authorized<E> {
    pub fn identity(&self) -> &Identity {
        &self.0
    }

    pub fn actor(&self) -> &Actor {
        &self.0.actor
    }
}

impl<E: Requires> axum::extract::FromRequestParts<Arc<AppState>> for Authorized<E> {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        s: &Arc<AppState>,
    ) -> std::result::Result<Self, Self::Rejection> {
        let identity = Identity::from_request_parts(parts, s).await?;

        match identity.refusal(E::ACTION) {
            None => Ok(Self(identity, PhantomData)),
            // 🔴 The refusal names the action, the required role, the held role and the
            // remedy. A bare `403` would leave you guessing whether you are on the wrong
            // screen, the system is broken, or a right is missing.
            Some(message) => {
                // 🔴 And it is LOGGED. Found by trying: a viewer attempting to delete an
                // app received a 403 and left no trace — someone probing what they can
                // destroy went invisible, which is precisely what an audit log exists to
                // show.
                //
                // ⚠️ The outcome is "refused", distinct from "failed": the system
                // protected, it did not break down. Painting them the same would send
                // you looking for an incident where a guard worked.
                let _ = s
                    .state
                    .audit(
                        identity.actor.name(),
                        identity.role,
                        E::ACTION.name(),
                        // The exact target requires knowing the route; the path carries
                        // it, and that is what we want to re-read afterwards.
                        parts.uri.path(),
                        "refused",
                        Some(&message),
                    )
                    .await;

                Err(ApiError::Forbidden(message))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_types::Role;

    #[test]
    fn every_action_can_be_demanded_by_some_route() {
        // 🔴 An action with no marker would be an action no route can require: it would
        // exist in the model and protect nothing. The exhaustive `match` below makes
        // compilation fail if a variant is added without
        // its matching marker.
        for a in [
            Action::ReadSelf,
            Action::ActOnSelf,
            Action::Read,
            Action::Publish,
            Action::Operate,
            Action::ManageAccounts,
            Action::Destroy,
        ] {
            // The match forces this list to be updated when `Action` changes.
            let _name = match a {
                Action::ReadSelf => "ReadSelf",
                Action::ActOnSelf => "ActOnSelf",
                Action::Read => "Read",
                Action::Publish => "Publish",
                Action::Operate => "Operate",
                Action::ManageAccounts => "ManageAccounts",
                Action::Destroy => "Destroy",
            };
            assert!(MARKERS.contains(&a), "{_name} has no capability marker");
        }
        assert_eq!(MARKERS.len(), 7);
    }

    #[test]
    fn markers_demand_what_they_are_named_after() {
        assert_eq!(CanRead::ACTION, Action::Read);
        assert_eq!(CanOperate::ACTION, Action::Operate);
        assert_eq!(CanDestroy::ACTION, Action::Destroy);
        assert_eq!(CanManageAccounts::ACTION, Action::ManageAccounts);
    }

    #[test]
    fn a_service_token_acts_for_nobody() {
        // 🔴 Privilege does not replace identity: an unbound admin token must not be
        // able to create aliases on someone's mailbox.
        let a = Actor::Token {
            name: "collecte".into(),
            user: None,
        };
        assert_eq!(a.for_account(), None);
        assert_eq!(a.name(), "collecte");
        assert!(!a.is_person());
    }

    #[test]
    fn a_bound_token_acts_for_its_account() {
        let a = Actor::Token {
            name: "bitwarden".into(),
            user: Some("lena".into()),
        };
        assert_eq!(a.for_account(), Some("lena"));
    }

    #[test]
    fn an_open_mode_actor_is_never_passed_off_as_a_person() {
        // The audit log must not suggest an identified administrator acted when the API
        // was open.
        let a = Actor::Anonymous;
        assert_eq!(a.name(), "anonymous");
        assert_eq!(a.for_account(), None);
        assert!(!a.is_person());
    }

    #[test]
    fn a_cookie_is_matched_by_its_exact_name() {
        // 🔴 Without an exact comparison, an `xhlb_session` set by a third-party
        // subdomain would be accepted in place of ours.
        assert_eq!(cookie("hlb_session=abc", COOKIE), Some("abc".into()));
        assert_eq!(
            cookie("other=1; hlb_session=abc; x=2", COOKIE),
            Some("abc".into())
        );
        assert_eq!(cookie(" hlb_session = abc ", COOKIE), Some("abc".into()));
        assert_eq!(cookie("xhlb_session=abc", COOKIE), None);
        assert_eq!(cookie("hlb_session_bis=abc", COOKIE), None);
        assert_eq!(cookie("", COOKIE), None);
        assert_eq!(cookie("sans-egal", COOKIE), None);
    }

    #[test]
    fn only_reading_methods_escape_the_csrf_header() {
        use axum::http::Method;
        assert!(!mutates(&Method::GET));
        assert!(!mutates(&Method::HEAD));
        assert!(!mutates(&Method::OPTIONS));
        for m in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            assert!(mutates(&m), "{m} should require the header");
        }
    }

    #[test]
    fn a_refusal_carries_the_remedy() {
        let i = Identity {
            role: Role::Viewer,
            actor: Actor::Person {
                user: "lena".into(),
            },
        };
        assert!(i.can(Action::Read));
        let m = i
            .refusal(Action::Operate)
            .expect("a viewer does not operate");
        assert!(m.contains("operator"), "{m}");
        assert!(m.contains("viewer"), "{m}");
    }

    #[test]
    fn a_plain_user_is_not_a_viewer() {
        let i = Identity {
            role: Role::User,
            actor: Actor::Person {
                user: "guest".into(),
            },
        };
        assert!(i.can(Action::ReadSelf));
        assert!(i.can(Action::ActOnSelf));
        assert!(!i.can(Action::Read), "the portal is not the console");
    }
}
