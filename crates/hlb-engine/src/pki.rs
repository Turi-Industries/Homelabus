//! The mTLS leaves Homelabus's own services run with, and their renewal.
//!
//! ## 🔴 A leaf nobody renews ends the fleet in one morning
//!
//! The agents' and the controller's certificates live
//! [`LEAF_DAYS`](hlb_agent::pki::LEAF_DAYS) days — short on purpose,
//! that is what replaces revocation. Nothing renewed them: on day 91 every agent refused
//! the controller, and every node read "unreachable" at once. [`Renewal`] issues both
//! again [`RENEW_BEFORE_DAYS`] before they end and hands them to their services under
//! the update policy (`Orchestrator::reconfigure`): the controller runs it every night,
//! `hlb pki renew --apply` by hand.
//!
//! ## Where an end date comes from
//!
//! A Swarm secret cannot be read back, so the state keeps each leaf's end
//! (`State::leaf_expiries`), written when one is issued — and by the controller from
//! the certificate it was itself started with, which is the truth after a rollback. A
//! leaf whose end nobody wrote down is renewed: unknown, it may end tomorrow.

use hlb_agent::pki::{self, CertPair, Purpose, RENEW_BEFORE_DAYS};
use hlb_orchestrator::Orchestrator;
use hlb_secrets::Vault;
use hlb_state::State;

/// The vault's name for the cluster's authority.
pub const CA_SECRET: &str = "cluster-ca";

/// The controller's own service, as `hlb fleet controller` names it.
pub const CONTROLLER_SERVICE: &str = "hlb-controller";

/// Where each service is handed its files. The paths its command and environment name:
/// changing one here without `hlb fleet` redeploying breaks the service it renews.
pub const AGENT_CERT: &str = "/run/hlb/agent.crt";
pub const AGENT_KEY: &str = "/run/hlb/agent.key";
pub const CONTROLLER_PEM: &str = "/run/hlb/controller.pem";
pub const CA_FILE: &str = "/run/hlb/ca.crt";

/// How long the agents' rollout may take before the renewal says it did not conclude.
const ROLLOUT_S: u64 = 300;

/// The cluster's certificate authority, from the vault; created when `create` and
/// absent.
///
/// 🔴 Never replaced: a second authority invalidates every certificate in the fleet at
/// once — the agents refuse the controller, and the other way round.
pub async fn cluster_ca(
    state: &State,
    vault: &Vault,
    create: bool,
) -> crate::Result<Option<CertPair>> {
    if let Some(ct) = state.secret(CA_SECRET).await? {
        let j: serde_json::Value = serde_json::from_str(&vault.decrypt(&ct)?)
            .map_err(|e| crate::Error::Pki(format!("{CA_SECRET} is unreadable: {e}")))?;
        let field = |k: &str| j[k].as_str().map(str::to_string);
        let (Some(cert_pem), Some(key_pem)) = (field("cert"), field("key")) else {
            return Err(crate::Error::Pki(format!(
                "{CA_SECRET} lacks its certificate or its key"
            )));
        };
        return Ok(Some(CertPair { cert_pem, key_pem }));
    }
    if !create {
        return Ok(None);
    }
    let ca = pki::generate_ca("Homelabus Cluster CA")
        .await
        .map_err(|e| crate::Error::Pki(e.to_string()))?;
    let j = serde_json::json!({ "cert": ca.cert_pem, "key": ca.key_pem });
    state
        .store_secret_if_absent(
            CA_SECRET,
            &vault.encrypt(&j.to_string())?,
            "cluster certificate authority (mTLS)",
        )
        .await?;
    Ok(Some(ca))
}

/// One of the two leaves a service runs with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Leaf {
    /// The agents' server certificate, one for every task of the global service.
    Agent { service: String },
    /// The controller's client certificate.
    Controller,
}

/// A leaf issued: the files its service is handed, and when it ends.
#[derive(Debug, Clone)]
pub struct Issued {
    pub files: Vec<(String, String)>,
    pub not_after: i64,
}

impl Leaf {
    pub fn service(&self) -> &str {
        match self {
            Self::Agent { service } => service,
            Self::Controller => CONTROLLER_SERVICE,
        }
    }

    /// Issues it under `ca`, as the files its service reads.
    pub async fn issue(&self, ca: &CertPair) -> crate::Result<Issued> {
        let pki_err = |e: hlb_agent::Error| crate::Error::Pki(e.to_string());
        let files = match self {
            Self::Agent { service } => {
                let c = pki::issue(
                    ca,
                    service,
                    &pki::agent_names(service, service),
                    Purpose::Server,
                )
                .await
                .map_err(pki_err)?;
                vec![
                    (AGENT_CERT.to_string(), c.cert_pem),
                    (AGENT_KEY.to_string(), c.key_pem),
                    (CA_FILE.to_string(), ca.cert_pem.clone()),
                ]
            }
            Self::Controller => {
                let c = pki::issue(ca, "controller", &["controller".into()], Purpose::Client)
                    .await
                    .map_err(pki_err)?;
                // reqwest reads the certificate AND its key from one PEM.
                vec![
                    (
                        CONTROLLER_PEM.to_string(),
                        format!("{}{}", c.cert_pem, c.key_pem),
                    ),
                    (CA_FILE.to_string(), ca.cert_pem.clone()),
                ]
            }
        };
        let cert = &files[0].1;
        let not_after = pki::not_after(cert).map_err(pki_err)?;
        Ok(Issued { files, not_after })
    }
}

/// Whether a leaf ending at `not_after` is to be issued again at `now`.
pub fn due(not_after: Option<i64>, now: i64) -> bool {
    not_after.is_none_or(|t| t - now < i64::from(RENEW_BEFORE_DAYS) * 86_400)
}

/// What a renewal did with one leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Ends later than the renewal window: left alone.
    Fine,
    /// Its service is not deployed: nothing runs with it.
    Absent,
    /// Due, and a preview: nothing was issued.
    WouldRenew,
    /// Issued again and handed to its service, ending then.
    Renewed { not_after: i64 },
    /// Due, and could not be renewed.
    Failed(String),
}

/// One leaf's line of a renewal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub service: String,
    /// When it ended before the run, if known.
    pub before: Option<i64>,
    pub outcome: Outcome,
}

/// Everything a renewal reaches.
pub struct Renewal<'a> {
    pub state: &'a State,
    pub vault: &'a Vault,
    pub orchestrator: &'a dyn Orchestrator,
    /// The agents' global service.
    pub agent_service: &'a str,
    pub now: i64,
    /// Ends read from the certificates themselves, by service, which beat the state's
    /// — the controller's own, read from the file it was started with.
    pub observed: Vec<(String, i64)>,
    /// The service this run is part of, never waited for: it is replaced by the update
    /// it starts.
    pub inside: Option<&'a str>,
}

impl Renewal<'_> {
    /// Renews every leaf that is due, the agents' first: the controller renewing itself
    /// is restarted by it, and goes last.
    ///
    /// Preview unless `apply`. A leaf that fails does not stop the other.
    pub async fn run(&self, apply: bool) -> crate::Result<Vec<Line>> {
        for (service, at) in &self.observed {
            self.state.set_leaf_expiry(service, Some(*at)).await?;
        }
        let known = self.state.leaf_expiries().await?;
        let leaves = [
            Leaf::Agent {
                service: self.agent_service.to_string(),
            },
            Leaf::Controller,
        ];
        let mut ca = None;
        let mut lines = Vec::new();
        for leaf in leaves {
            let service = leaf.service().to_string();
            let before = known.iter().find(|(s, _)| *s == service).map(|(_, t)| *t);
            let outcome = if self.orchestrator.status(&service).await.is_err() {
                Outcome::Absent
            } else if !due(before, self.now) {
                Outcome::Fine
            } else if !apply {
                Outcome::WouldRenew
            } else {
                if ca.is_none() {
                    ca = cluster_ca(self.state, self.vault, false).await?;
                }
                match &ca {
                    None => Outcome::Failed(
                        "the cluster authority is not in the vault: hlb pki init --apply".into(),
                    ),
                    Some(ca) => match self.renew(&leaf, ca).await {
                        Ok(not_after) => Outcome::Renewed { not_after },
                        Err(e) => Outcome::Failed(e.to_string()),
                    },
                }
            };
            lines.push(Line {
                service,
                before,
                outcome,
            });
        }
        Ok(lines)
    }

    async fn renew(&self, leaf: &Leaf, ca: &CertPair) -> crate::Result<i64> {
        let service = leaf.service();
        let issued = leaf.issue(ca).await?;
        // Only the files change: the command, the mounts and the environment stay as
        // `hlb fleet` deployed them. No alias: neither service answers to one.
        self.orchestrator
            .reconfigure(service, &issued.files, &[])
            .await?;
        // A rollout that rolled back runs the OLD leaf: written as renewed, the end
        // recorded would be a lie the next pass believes.
        if self.inside != Some(service) {
            self.orchestrator.wait_healthy(service, ROLLOUT_S).await?;
        }
        self.state
            .set_leaf_expiry(service, Some(issued.not_after))
            .await?;
        self.state
            .audit(
                "pki",
                hlb_types::Role::Admin,
                "pki-renew",
                service,
                "ok",
                Some(&format!("ends {}", issued.not_after)),
            )
            .await?;
        Ok(issued.not_after)
    }
}

/// A leaf ending within the window, for the inbox and the notifications: renewed in
/// time, none is ever listed.
pub fn ending(expiries: &[(String, i64)], now: i64) -> Vec<(String, i64)> {
    expiries
        .iter()
        .filter(|(_, t)| due(Some(*t), now))
        .cloned()
        .collect()
}

/// Now, in seconds since the epoch.
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// A date as people read it, in UTC.
pub fn date(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .map_or_else(|| t.to_string(), |d| d.format("%Y-%m-%d").to_string())
}

/// Days left before `not_after`, rounded down; negative once it ended.
pub fn days_left(not_after: i64, now: i64) -> i64 {
    (not_after - now).div_euclid(86_400)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    #[test]
    fn a_leaf_is_renewed_inside_the_window_and_when_its_end_is_unknown() {
        let now = 1_800_000_000;
        assert!(!due(Some(now + 31 * DAY), now));
        assert!(due(Some(now + 29 * DAY), now));
        assert!(due(Some(now - DAY), now), "ended");
        assert!(due(None, now), "unknown may end tomorrow");
    }

    #[test]
    fn only_a_leaf_inside_the_window_is_ending() {
        let now = 1_800_000_000;
        let e = ending(
            &[
                ("hlb-agent".into(), now + 10 * DAY),
                ("hlb-controller".into(), now + 80 * DAY),
            ],
            now,
        );
        assert_eq!(e, [("hlb-agent".to_string(), now + 10 * DAY)]);
        assert_eq!(days_left(now + 10 * DAY - 1, now), 9);
        assert_eq!(days_left(now - 1, now), -1);
    }
}
