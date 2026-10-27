//! Rate limiting (defence in depth).
//!
//! ## What this protects, concretely
//!
//! Three routes justify this module on their own:
//!
//! - **`/api/v1/aliases`** — a stolen token with no limit is an address generator. The
//!   thief creates a hundred thousand: the profile's quota eventually bites, but in the
//!   meantime the table has grown, the Sieve rules with it, and the account's Sieve
//!   script becomes too big for Stalwart. The mailbox then stops sorting — including
//!   for the hand-written rules.
//! - **`/auth/return_to`** — with no limit it is an oracle: you try states against it until
//!   one is alive.
//! - **`/api/…` with a bad token** — a token is 256 bits, it is not guessable; but every
//!   attempt costs an indexed read and a SHA-256, and nothing obliges us to offer that
//!   service for free.
//!
//! ## 🔴 Why the client address is not read from `X-Forwarded-For` by default
//!
//! Behind Caddy, the real address is in that header. But **the client can write it
//! itself**: trusting it without knowing a trusted proxy is in front hands every
//! attacker a fresh counter on every request — so a rate limit that limits nothing,
//! while giving the impression of the opposite.
//!
//! The header is therefore only read if `--trusted-proxy` was set explicitly.

use std::collections::HashMap;
use std::net::IpAddr;

/// The nature of a request, which decides its budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// Signing in and out. Generous: one OIDC round trip makes several, and a person
    /// who picks the wrong account starts again.
    SignIn,
    /// Everything that changes something.
    Write,
    /// The rest. The interface polls several resources in parallel, several times a
    /// minute: too tight a budget would break the dashboard itself.
    Read,
}

impl Class {
    /// Requests allowed per window.
    pub fn budget(&self) -> u32 {
        match self {
            Self::SignIn => 20,
            Self::Write => 60,
            Self::Read => 600,
        }
    }

    /// A request's class.
    pub fn of(method: &axum::http::Method, path: &str) -> Self {
        if path.starts_with("/auth/") {
            return Self::SignIn;
        }
        if matches!(
            *method,
            axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
        ) {
            Self::Read
        } else {
            Self::Write
        }
    }
}

/// Requests no budget counts.
///
/// - `/healthz`: Swarm's probe, which knocks at a fixed interval and from varying
///   addresses. Limiting it would make the controller restart in a loop, precisely when
///   the cluster is loaded.
/// - The interface's compiled files, `/_app/immutable/…`: named by their hash, never
///   changing, read from disk. A first load of the home asks for fifty of them; counted,
///   eight loads in a minute — a household opening the dashboard on its phones — spent
///   the 600 reads the API's polling needs, and the next page answered 429. ⚠️ Matched
///   as a prefix of the path the ROUTER sees: no API route lives under it, and the file
///   server refuses a `..` that would climb out of it.
pub fn exempt(method: &axum::http::Method, path: &str) -> bool {
    path == "/healthz"
        || (matches!(*method, axum::http::Method::GET | axum::http::Method::HEAD)
            && path.starts_with("/_app/immutable/"))
}

/// The sliding window, in seconds.
pub const WINDOW_S: i64 = 60;

/// Past this, the oldest counters are forgotten.
///
/// With no cap, a distributed attack would grow the table indefinitely — the protection
/// would itself become the outage.
const CLIENTS_MAX: usize = 10_000;

#[derive(Debug, Clone, Copy)]
struct Counter {
    start: i64,
    count: u32,
}

/// The rate counter.
///
/// A fixed window rather than a sliding one: half the memory, and the imprecision (up to
/// twice the budget when straddling two windows) does not matter here — we are
/// protecting against hammering, not against going from 60 to 61.
#[derive(Default)]
pub struct RateLimiter {
    counters: std::sync::Mutex<HashMap<(String, Class), Counter>>,
}

/// A check's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    /// 🔴 Too many requests. `retry_after_s` says how long to wait before retrying — a
    /// `429` without that hint leaves the client hammering all the harder.
    Refused {
        retry_after_s: i64,
    },
}

impl Verdict {
    pub fn allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Does this request pass?
    ///
    /// `now` is a parameter so the function is testable without waiting a minute
    /// — the same discipline as the alias randomness.
    pub fn check(&self, client: &str, class: Class, now: i64) -> Verdict {
        let Ok(mut m) = self.counters.lock() else {
            // 🔴 A poisoned lock must not close the service. We let it through: rate
            // limiting is defence in depth, not access control — that has already
            // happened. Refusing here would turn an internal incident into a total
            // outage.
            return Verdict::Allowed;
        };

        if m.len() > CLIENTS_MAX {
            // Housekeeping: everything whose window is closed.
            m.retain(|_, c| now - c.start < WINDOW_S);
        }

        let e = m.entry((client.to_string(), class)).or_insert(Counter {
            start: now,
            count: 0,
        });

        if now - e.start >= WINDOW_S {
            *e = Counter {
                start: now,
                count: 0,
            };
        }

        e.count += 1;
        if e.count > class.budget() {
            Verdict::Refused {
                retry_after_s: (WINDOW_S - (now - e.start)).max(1),
            }
        } else {
            Verdict::Allowed
        }
    }
}

/// A request's client identifier.
///
/// `trusted_proxy` must come from `--trusted-proxy`: see the module header for why it
/// is not true by default.
pub fn client(
    headers: &axum::http::HeaderMap,
    pair: Option<IpAddr>,
    trusted_proxy: bool,
) -> String {
    if trusted_proxy {
        if let Some(xff) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            // The FIRST of the list is the originating client; the ones after are the
            // proxies traversed.
            .and_then(|v| v.split(',').next())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            return match xff.parse::<IpAddr>() {
                Ok(ip) => keyed(ip),
                Err(_) => xff.to_string(),
            };
        }
    }
    pair.map(keyed).unwrap_or_else(|| "unknown".to_string())
}

/// One key per client: an IPv4 address, or an IPv6 one's /64. A single connection is
/// handed a /64 — counted address by address, it drew a fresh budget at every request.
fn keyed(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                let net = std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
                format!("{net}/64")
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue, Method};

    #[test]
    fn an_ipv6_client_is_its_64() {
        let a: IpAddr = "2001:db8:1:2::1".parse().expect("ip");
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().expect("ip");
        let c: IpAddr = "2001:db8:1:3::1".parse().expect("ip");
        let h = HeaderMap::new();
        assert_eq!(client(&h, Some(a), false), client(&h, Some(b), false));
        assert_ne!(client(&h, Some(a), false), client(&h, Some(c), false));
        let v4: IpAddr = "1.2.3.4".parse().expect("ip");
        assert_eq!(client(&h, Some(v4), false), "1.2.3.4");
    }

    #[test]
    fn a_burst_is_stopped_at_the_budget() {
        let l = RateLimiter::new();
        for n in 1..=Class::Write.budget() {
            assert!(
                l.check("1.2.3.4", Class::Write, 100).allowed(),
                "request {n} should pass"
            );
        }
        let v = l.check("1.2.3.4", Class::Write, 100);
        assert!(!v.allowed());
        match v {
            Verdict::Refused { retry_after_s } => {
                assert!(retry_after_s > 0, "it must say when to retry")
            }
            Verdict::Allowed => unreachable!(),
        }
    }

    #[test]
    fn the_window_reopens() {
        let l = RateLimiter::new();
        for _ in 0..=Class::Write.budget() {
            l.check("1.2.3.4", Class::Write, 100);
        }
        assert!(!l.check("1.2.3.4", Class::Write, 100).allowed());
        assert!(l.check("1.2.3.4", Class::Write, 100 + WINDOW_S).allowed());
    }

    #[test]
    fn one_client_does_not_starve_another() {
        // A global limit would make a single attacker an outage for everyone
        // else — the protection would become the attack.
        let l = RateLimiter::new();
        for _ in 0..=Class::Write.budget() {
            l.check("mechant", Class::Write, 100);
        }
        assert!(!l.check("mechant", Class::Write, 100).allowed());
        assert!(l.check("gentil", Class::Write, 100).allowed());
    }

    #[test]
    fn writing_does_not_eat_the_reading_budget() {
        // The interface polls several resources several times a minute:
        // sharing the budget with writes would break the dashboard on the first
        // sequence of actions.
        let l = RateLimiter::new();
        for _ in 0..=Class::Write.budget() {
            l.check("1.2.3.4", Class::Write, 100);
        }
        assert!(!l.check("1.2.3.4", Class::Write, 100).allowed());
        assert!(l.check("1.2.3.4", Class::Read, 100).allowed());
    }

    #[test]
    fn only_the_interfaces_fixed_files_and_the_probe_go_uncounted() {
        assert!(exempt(&Method::GET, "/_app/immutable/chunks/app.B1x2.js"));
        assert!(exempt(&Method::GET, "/healthz"));
        for (method, path) in [
            (Method::GET, "/"),
            (Method::GET, "/api/history"),
            (Method::GET, "/_app/version.json"),
            (Method::POST, "/_app/immutable/x.js"),
            (Method::GET, "/api/_app/immutable/x"),
        ] {
            assert!(!exempt(&method, path), "{method} {path}");
        }
    }

    #[test]
    fn login_routes_have_their_own_class() {
        assert_eq!(Class::of(&Method::GET, "/auth/signin"), Class::SignIn);
        assert_eq!(Class::of(&Method::GET, "/auth/return_to"), Class::SignIn);
        assert_eq!(Class::of(&Method::POST, "/auth/signout"), Class::SignIn);
        assert_eq!(Class::of(&Method::GET, "/api/apps"), Class::Read);
        assert_eq!(Class::of(&Method::POST, "/api/v1/aliases"), Class::Write);
        assert_eq!(Class::of(&Method::DELETE, "/api/apps/x"), Class::Write);
    }

    #[test]
    fn a_spoofable_header_is_ignored_by_default() {
        // 🔴 With no trusted proxy declared, believing `X-Forwarded-For` would hand
        // every attacker a fresh counter on every request: a rate limit that limits
        // nothing while giving the impression of the opposite.
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("9.9.9.9"));
        let pair: IpAddr = "1.2.3.4".parse().expect("ip");

        assert_eq!(client(&h, Some(pair), false), "1.2.3.4");
        assert_eq!(client(&h, Some(pair), true), "9.9.9.9");
    }

    #[test]
    fn the_original_client_is_the_first_of_the_chain() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("9.9.9.9, 10.0.0.1, 10.0.0.2"),
        );
        assert_eq!(client(&h, None, true), "9.9.9.9");
    }

    #[test]
    fn an_empty_forwarded_header_falls_back_to_the_socket() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("  "));
        let pair: IpAddr = "1.2.3.4".parse().expect("ip");
        assert_eq!(client(&h, Some(pair), true), "1.2.3.4");
    }

    #[test]
    fn the_table_does_not_grow_without_bound() {
        // With no cap, a distributed attack would make the protection the outage.
        let l = RateLimiter::new();
        for n in 0..(CLIENTS_MAX + 100) {
            l.check(&format!("client-{n}"), Class::Read, 100);
        }
        // One window later, the housekeeping must have happened.
        l.check("declencheur", Class::Read, 100 + WINDOW_S);
        let n = l.counters.lock().expect("verrou").len();
        assert!(n <= CLIENTS_MAX + 200, "unbounded table: {n} entries");
    }
}
