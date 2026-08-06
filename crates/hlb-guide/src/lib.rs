//! Le moteur de vérification des guides (§4.6).
//!
//! Sans lui, `verify:` n'est qu'une déclaration d'intention et `hlb ack` une simple
//! attestation. C'est ce module qui permet de **constater** qu'une action manuelle a
//! réellement été faite.
//!
//! ## Ce que chaque vérification prouve, et ce qu'elle ne prouve pas
//!
//! | Type | Prouve | Ne prouve pas |
//! |---|---|---|
//! | `dns` | le nom résout | qu'il pointe au bon endroit (voir `expectContains`) |
//! | `http` | l'URL répond avec le bon code | que le contenu est correct |
//! | `tcp` | le port accepte une connexion | que le service derrière est sain |
//! | `attest` | **rien** | tout |
//!
//! Cette honnêteté est le point : une vérification qui prétendrait plus que ce
//! qu'elle établit serait pire qu'une attestation assumée.

pub mod automate;

pub use automate::{try_automate, AutomationOutcome};

use std::time::Duration;

use hlb_types::{GuideStep, Verify};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Constaté automatiquement.
    Verified { detail: String },
    /// Constaté comme NON fait.
    Failed { detail: String },
    /// 🔴 Aucune vérification possible : seul l'utilisateur peut attester.
    NotVerifiable,
    /// Le type existe mais demande un contexte absent (conteneur, API de l'app).
    Unsupported { reason: String },
}

impl Outcome {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// L'utilisateur peut-il légitimement passer outre avec `hlb ack` ?
    ///
    /// Oui pour ce qu'on ne sait pas constater ; non pour ce qu'on a constaté comme
    /// faux — attester d'un fait qu'on vient de démentir n'a aucun sens.
    pub fn may_attest(&self) -> bool {
        matches!(self, Self::NotVerifiable | Self::Unsupported { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Verified { detail } => format!("✓ {detail}"),
            Self::Failed { detail } => format!("✗ {detail}"),
            Self::NotVerifiable => "⚪ non vérifiable — attestation seulement".into(),
            Self::Unsupported { reason } => format!("⚪ non vérifié : {reason}"),
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
                // Un certificat auto-signé pendant la mise en place ne doit pas faire
                // échouer la vérification du DNS ou du routage.
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap_or_default(),
            timeout,
        }
    }

    /// Vérifie une étape, gabarits résolus au préalable.
    pub async fn check(&self, step: &GuideStep, vars: &[(&str, &str)]) -> Outcome {
        match &step.verify {
            Verify::Attest => Outcome::NotVerifiable,

            Verify::Dns { record, expect_contains } => {
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

            // Demande d'entrer dans le conteneur : c'est l'exécuteur qui sait le
            // faire, pas ce module. Rapporté comme non vérifié, jamais comme réussi.
            Verify::Exec { .. } => Outcome::Unsupported {
                reason: "vérification par commande dans le conteneur non branchée".into(),
            },
        }
    }

    /// Résolution DNS.
    ///
    /// ⚠️ Établit que le nom **résout**, pas qu'il pointe au bon endroit. Pour ça,
    /// `expectContains` compare l'adresse obtenue à ce qu'on attend.
    async fn check_dns(&self, name: &str, expect: Option<&str>) -> Outcome {
        // `lookup_host` exige un port ; il n'a aucune importance ici.
        let cible = format!("{name}:80");

        match tokio::time::timeout(self.timeout, tokio::net::lookup_host(cible)).await {
            Err(_) => Outcome::Failed {
                detail: format!("{name} : résolution DNS expirée"),
            },
            Ok(Err(e)) => Outcome::Failed {
                detail: format!("{name} ne résout pas ({e})"),
            },
            Ok(Ok(addrs)) => {
                let ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                if ips.is_empty() {
                    return Outcome::Failed {
                        detail: format!("{name} ne résout vers aucune adresse"),
                    };
                }
                match expect {
                    Some(attendu) if !ips.iter().any(|ip| ip.contains(attendu)) => {
                        Outcome::Failed {
                            detail: format!(
                                "{name} résout vers {} — attendu {attendu}",
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
                detail: format!("{url} injoignable ({})", cause_courte(&e)),
            },
            Ok(r) => {
                let code = r.status().as_u16();
                if expect.contains(&code) {
                    Outcome::Verified {
                        detail: format!("{url} → {code}"),
                    }
                } else {
                    Outcome::Failed {
                        detail: format!("{url} → {code}, attendu {expect:?}"),
                    }
                }
            }
        }
    }

    async fn check_tcp(&self, target: &str) -> Outcome {
        match tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(target)).await {
            Err(_) => Outcome::Failed {
                detail: format!("{target} : délai dépassé"),
            },
            Ok(Err(e)) => Outcome::Failed {
                detail: format!("{target} injoignable ({e})"),
            },
            Ok(Ok(_)) => Outcome::Verified {
                detail: format!("{target} accepte les connexions"),
            },
        }
    }
}

/// Message d'erreur reqwest lisible : la chaîne complète est verbeuse.
fn cause_courte(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "délai dépassé".into()
    } else if e.is_connect() {
        "connexion refusée".into()
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
        // 🔴 Le point le plus important : on ne prétend jamais avoir constaté.
        let o = Verifier::default().check(&step(Verify::Attest), &[]).await;
        assert_eq!(o, Outcome::NotVerifiable);
        assert!(!o.is_verified());
        assert!(o.may_attest(), "l'utilisateur doit pouvoir attester");
    }

    #[tokio::test]
    async fn a_failed_check_cannot_be_attested_away() {
        // On a constaté que ce n'est PAS fait : attester le contraire n'a aucun sens.
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
        assert!(!o.is_verified(), "ne jamais compter comme vérifié");
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
        assert!(!o.may_attest(), "un échec constaté n'est pas attestable");
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
        // Résoudre ne suffit pas : encore faut-il pointer au bon endroit.
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
        assert!(o.describe().contains("attendu"), "{}", o.describe());
    }

    #[tokio::test]
    async fn a_closed_port_fails() {
        // 9 est réservé (discard) et n'écoute pas en local.
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
        assert!(Outcome::Verified { detail: "x → y".into() }.describe().starts_with('✓'));
        assert!(Outcome::Failed { detail: "z".into() }.describe().starts_with('✗'));
        assert!(Outcome::NotVerifiable.describe().contains("attestation"));
    }
}
