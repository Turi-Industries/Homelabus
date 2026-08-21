//! The guide verification engine.
//!
//! Without it, `verify:` is only a statement of intent and `hlb ack` a plain
//! attestation. This module is what makes it possible to **establish** that a manual
//! action was really carried out.
//!
//! ## What each check proves, and what it does not
//!
//! | Kind | Proves | Does not prove |
//! |---|---|---|
//! | `dns` | the name resolves | that it points at the right place (see `expectContains`) |
//! | `http` | the URL answers with the right code | that the content is correct |
//! | `tcp` | the port accepts a connection | that the service behind it is healthy |
//! | `attest` | **nothing** | everything |
//!
//! That honesty is the point: a check claiming more than it establishes would be
//! worse than an attestation openly labelled as one.

pub mod automate;

pub use automate::{try_automate, AutomationOutcome};

use std::time::Duration;

use hlb_types::{GuideStep, Verify};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Established automatically.
    Verified { detail: String },
    /// Established as NOT done.
    Failed { detail: String },
    /// 🔴 No check is possible: only the user can attest.
    NotVerifiable,
    /// The kind exists but needs context we do not have (a container, the app's API).
    Unsupported { reason: String },
}

impl Outcome {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// May the user legitimately override this with `hlb ack`?
    ///
    /// Yes for what we cannot establish; no for what we established as false -
    /// attesting to a fact just disproved makes no sense.
    pub fn may_attest(&self) -> bool {
        matches!(self, Self::NotVerifiable | Self::Unsupported { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Verified { detail } => format!("✓ {detail}"),
            Self::Failed { detail } => format!("✗ {detail}"),
            Self::NotVerifiable => "⚪ not verifiable - attestation only".into(),
            Self::Unsupported { reason } => format!("⚪ not verified: {reason}"),
        }
    }
}

pub struct Verifier {
    http: reqwest::Client,
    timeout: Duration,
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new(Duration::from_secs(10))
    }
}

impl Verifier {
    pub fn new(timeout: Duration) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(timeout)
                // A self-signed certificate during setup must not make the DNS or
                // routing check fail.
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap_or_default(),
            timeout,
        }
    }

    /// Verifies a step, with templates already resolved.
    pub async fn check(&self, step: &GuideStep, vars: &[(&str, &str)]) -> Outcome {
        match &step.verify {
            Verify::Attest => Outcome::NotVerifiable,

            Verify::Dns {
                record,
                expect_contains,
            } => {
                let name = hlb_types::guide::render(record, vars);
                self.check_dns(&name, expect_contains.as_deref()).await
            }

            Verify::Http { url, expect_status } => {
                let u = hlb_types::guide::render(url, vars);
                self.check_http(&u, expect_status).await
            }

            Verify::Tcp { target } => {
                let t = hlb_types::guide::render(target, vars);
                self.check_tcp(&t).await
            }

            // This one needs to enter the container, which the executor knows how to
            // do and this module does not. Reported as not verified, never as passed.
            Verify::Exec { .. } => Outcome::Unsupported {
                reason: "in-container command checks are not wired up".into(),
            },
        }
    }

    /// DNS resolution.
    ///
    /// ⚠️ Establishes that the name **resolves**, not that it points at the right
    /// place. For that, `expectContains` compares the resolved address to what is
    /// expected.
    async fn check_dns(&self, name: &str, expect: Option<&str>) -> Outcome {
        // `lookup_host` requires a port; it is irrelevant here.
        let cible = format!("{name}:80");

        match tokio::time::timeout(self.timeout, tokio::net::lookup_host(cible)).await {
            Err(_) => Outcome::Failed {
                detail: format!("{name}: DNS resolution timed out"),
            },
            Ok(Err(e)) => Outcome::Failed {
                detail: format!("{name} does not resolve ({e})"),
            },
            Ok(Ok(addrs)) => {
                let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                if ips.is_empty() {
                    return Outcome::Failed {
                        detail: format!("{name} resolves to no address"),
                    };
                }
                match expect {
                    Some(expected) if !ips.iter().any(|ip| ip.contains(expected)) => {
                        Outcome::Failed {
                            detail: format!(
                                "{name} resolves to {} - expected {expected}",
                                ips.join(", ")
                            ),
                        }
                    }
                    _ => Outcome::Verified {
                        detail: format!("{name} → {}", ips.join(", ")),
                    },
                }
            }
        }
    }

    async fn check_http(&self, url: &str, expect: &[u16]) -> Outcome {
        match self.http.get(url).send().await {
            Err(e) => Outcome::Failed {
                detail: format!("{url} unreachable ({})", short_cause(&e)),
            },
            Ok(r) => {
                let code = r.status().as_u16();
                if expect.contains(&code) {
                    Outcome::Verified {
                        detail: format!("{url} → {code}"),
                    }
                } else {
                    Outcome::Failed {
                        detail: format!("{url} → {code}, expected {expect:?}"),
                    }
                }
            }
        }
    }

    async fn check_tcp(&self, target: &str) -> Outcome {
        match tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(target)).await {
            Err(_) => Outcome::Failed {
                detail: format!("{target}: timed out"),
            },
            Ok(Err(e)) => Outcome::Failed {
                detail: format!("{target} unreachable ({e})"),
            },
            Ok(Ok(_)) => Outcome::Verified {
                detail: format!("{target} accepts connections"),
            },
        }
    }
}

/// A readable reqwest error message: the full chain is verbose.
fn short_cause(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "timed out".into()
    } else if e.is_connect() {
        "connection refused".into()
    } else {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(verify: Verify) -> GuideStep {
        GuideStep {
            id: "test".into(),
            title: "Test".into(),
            phase: Default::default(),
            severity: Default::default(),
            body: String::new(),
            after: Vec::new(),
            automate: Vec::new(),
            verify,
            deeplink: None,
            recheck: None,
        }
    }

    #[tokio::test]
    async fn attest_is_never_automatically_verified() {
        // 🔴 The most important point: we never claim to have established anything.
        let o = Verifier::default().check(&step(Verify::Attest), &[]).await;
        assert_eq!(o, Outcome::NotVerifiable);
        assert!(!o.is_verified());
        assert!(o.may_attest(), "l'utilisateur doit pouvoir attester");
    }

    #[tokio::test]
    async fn a_failed_check_cannot_be_attested_away() {
        // We established it is NOT done: attesting the opposite makes no sense.
        let o = Outcome::Failed { detail: "x".into() };
        assert!(!o.may_attest());
    }

    #[tokio::test]
    async fn exec_is_reported_as_unsupported_not_verified() {
        let o = Verifier::default()
            .check(
                &step(Verify::Exec {
                    command: vec!["true".into()],
                    expect_contains: None,
                }),
                &[],
            )
            .await;
        assert!(!o.is_verified(), "must never count as verified");
        assert!(matches!(o, Outcome::Unsupported { .. }));
    }

    #[tokio::test]
    async fn an_unresolvable_name_fails() {
        let v = Verifier::new(Duration::from_secs(5));
        let o = v
            .check(
                &step(Verify::Dns {
                    record: "nexiste-vraiment-pas.invalid".into(),
                    expect_contains: None,
                }),
                &[],
            )
            .await;
        assert!(!o.is_verified(), "{}", o.describe());
        assert!(!o.may_attest(), "an established failure is not attestable");
    }

    #[tokio::test]
    async fn localhost_resolves() {
        let o = Verifier::default()
            .check(
                &step(Verify::Dns {
                    record: "localhost".into(),
                    expect_contains: None,
                }),
                &[],
            )
            .await;
        assert!(o.is_verified(), "{}", o.describe());
    }

    #[tokio::test]
    async fn the_domain_template_is_resolved_before_checking() {
        let o = Verifier::default()
            .check(
                &step(Verify::Dns {
                    record: "{{ domain }}".into(),
                    expect_contains: None,
                }),
                &[("domain", "localhost")],
            )
            .await;
        assert!(o.is_verified(), "{}", o.describe());
    }

    #[tokio::test]
    async fn a_wrong_address_is_detected() {
        // Resolving is not enough: it must also point at the right place.
        let o = Verifier::default()
            .check(
                &step(Verify::Dns {
                    record: "localhost".into(),
                    expect_contains: Some("203.0.113.1".into()),
                }),
                &[],
            )
            .await;
        assert!(!o.is_verified());
        assert!(o.describe().contains("expected"), "{}", o.describe());
    }

    #[tokio::test]
    async fn a_closed_port_fails() {
        // Port 9 is reserved (discard) and nothing listens on it locally.
        let o = Verifier::new(Duration::from_secs(2))
            .check(
                &step(Verify::Tcp {
                    target: "127.0.0.1:9".into(),
                }),
                &[],
            )
            .await;
        assert!(!o.is_verified(), "{}", o.describe());
    }

    #[test]
    fn outcomes_read_clearly() {
        assert!(Outcome::Verified {
            detail: "x → y".into()
        }
        .describe()
        .starts_with('✓'));
        assert!(Outcome::Failed { detail: "z".into() }
            .describe()
            .starts_with('✗'));
        assert!(Outcome::NotVerifiable.describe().contains("attestation"));
    }
}
