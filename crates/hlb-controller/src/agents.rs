//! Interrogation des agents de nœuds (§2, §9bis).
//!
//! Le controller interroge, les agents ne poussent pas. Deux raisons :
//!
//! - un agent qui pousserait devrait connaître l'adresse du controller, la
//!   retrouver après redémarrage, et gérer sa propre file en cas d'indisponibilité ;
//! - **un agent injoignable est en soi l'information utile** : le nœud ne répond
//!   pas, donc ses données ne sont peut-être plus sauvegardées.
//!
//! ## Comment on atteint chaque agent
//!
//! Le DNS de l'overlay Swarm résout `tasks.<service>` vers **toutes** les tâches du
//! service, pas vers une VIP unique. C'est ce qui permet d'interroger chaque nœud
//! individuellement plutôt que d'en tirer un au hasard.

use std::collections::BTreeMap;
use std::time::Duration;

use hlb_agent::{DiskPressure, NodeReport, Thresholds};

/// Ce qu'on a pu — ou pas — apprendre d'un nœud.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentStatus {
    /// L'agent a répondu.
    Reporting(Box<NodeReport>),
    /// L'agent n'a pas répondu. On ne suppose RIEN de l'état du nœud.
    Unreachable { detail: String },
}

impl AgentStatus {
    pub fn report(&self) -> Option<&NodeReport> {
        match self {
            Self::Reporting(r) => Some(r),
            Self::Unreachable { .. } => None,
        }
    }

    /// 🔴 Un nœud muet n'autorise pas un déploiement : on ne sait pas s'il a de la
    /// place. Supposer que oui, c'est risquer de saturer un disque à l'aveugle.
    pub fn allows_deploy(&self, t: &Thresholds) -> bool {
        self.report().is_some_and(|r| r.allows_deploy(t))
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Reporting(r) => {
                let p = r.worst_pressure(&Thresholds::default());
                match p {
                    DiskPressure::Normal => "✓ sain".into(),
                    _ => format!("{} — {}", marque(p), p.describe()),
                }
            }
            Self::Unreachable { detail } => format!("🔴 injoignable ({detail})"),
        }
    }
}

fn marque(p: DiskPressure) -> &'static str {
    match p {
        DiskPressure::Normal => "✓",
        DiskPressure::Notice => "🟠",
        _ => "🔴",
    }
}

pub struct AgentPoller {
    http: reqwest::Client,
    port: u16,
    /// `https` quand le mTLS est configuré. Le schéma DOIT suivre : interroger un
    /// agent mTLS en `http://` échoue sur une erreur de protocole qui ne dit pas que
    /// c'est le schéma le problème.
    scheme: &'static str,
}

impl AgentPoller {
    pub fn new(port: u16, timeout: Duration) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .unwrap_or_default(),
            port,
            scheme: "http",
        }
    }

    /// Interroge les agents en mTLS (§2).
    ///
    /// 🔴 `identity` est le certificat du controller : sans lui, les agents refusent
    /// la connexion. `ca_pem` sert à vérifier les agents — on ne fait PAS confiance
    /// aux autorités du système, seulement à la nôtre. Un agent dont le certificat
    /// serait signé par une CA publique doit être refusé comme n'importe quel autre
    /// imposteur.
    pub fn with_mtls(
        port: u16,
        timeout: Duration,
        client_pem: &str,
        ca_pem: &str,
    ) -> Result<Self, String> {
        let identity = reqwest::Identity::from_pem(client_pem.as_bytes())
            .map_err(|e| format!("certificat du controller illisible : {e}"))?;
        let ca = reqwest::Certificate::from_pem(ca_pem.as_bytes())
            .map_err(|e| format!("CA illisible : {e}"))?;

        let http = reqwest::Client::builder()
            .timeout(timeout)
            .identity(identity)
            .add_root_certificate(ca)
            // Notre CA UNIQUEMENT : les autorités publiques n'ont rien à faire ici.
            .tls_built_in_root_certs(false)
            .build()
            .map_err(|e| format!("client mTLS : {e}"))?;

        Ok(Self {
            http,
            port,
            scheme: "https",
        })
    }

    pub fn is_secure(&self) -> bool {
        self.scheme == "https"
    }

    /// Interroge un agent à une adresse donnée.
    pub async fn poll(&self, addr: &str) -> AgentStatus {
        let url = format!("{}://{addr}:{}/api/report", self.scheme, self.port);

        match self.http.get(&url).send().await {
            Err(e) => AgentStatus::Unreachable {
                detail: if e.is_timeout() {
                    "délai dépassé".into()
                } else if e.is_connect() && self.scheme == "https" {
                    // Distinguer les deux : « connexion refusée » enverrait chercher
                    // un agent arrêté, alors que le certificat est la cause la plus
                    // fréquente une fois le mTLS activé.
                    format!("connexion TLS refusée (certificat ?) : {e}")
                } else {
                    "connexion refusée".into()
                },
            },
            Ok(r) if !r.status().is_success() => AgentStatus::Unreachable {
                detail: format!("HTTP {}", r.status().as_u16()),
            },
            Ok(r) => match r.json::<NodeReport>().await {
                Ok(rep) => AgentStatus::Reporting(Box::new(rep)),
                Err(e) => AgentStatus::Unreachable {
                    detail: format!("réponse illisible : {e}"),
                },
            },
        }
    }

    /// Interroge tous les agents, en parallèle.
    ///
    /// Séquentiellement, un seul nœud injoignable ferait attendre tous les autres :
    /// avec dix nœuds et un délai de dix secondes, un tour prendrait plus d'une
    /// minute alors qu'il devrait en prendre dix secondes.
    pub async fn poll_all(&self, addrs: &[String]) -> BTreeMap<String, AgentStatus> {
        let futures = addrs.iter().map(|a| async move {
            let s = self.poll(a).await;
            (a.clone(), s)
        });

        futures::future::join_all(futures)
            .await
            .into_iter()
            .collect()
    }
}

/// Résumé exploitable pour la supervision.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClusterHealth {
    pub reporting: usize,
    pub unreachable: usize,
    /// Nœuds où l'on refuserait un déploiement.
    pub saturated: Vec<String>,
}

impl ClusterHealth {
    pub fn from_statuses(statuses: &BTreeMap<String, AgentStatus>, t: &Thresholds) -> Self {
        let mut h = Self::default();
        for (addr, s) in statuses {
            match s {
                AgentStatus::Reporting(r) => {
                    h.reporting += 1;
                    if !r.allows_deploy(t) {
                        h.saturated.push(r.hostname.clone());
                    }
                }
                AgentStatus::Unreachable { .. } => {
                    h.unreachable += 1;
                    // Un nœud muet est signalé, mais pas listé comme saturé : on ne
                    // sait pas s'il l'est, et prétendre le contraire serait faux.
                    let _ = addr;
                }
            }
        }
        h
    }

    pub fn needs_attention(&self) -> bool {
        self.unreachable > 0 || !self.saturated.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_agent::DiskUsage;

    fn rapport(hostname: &str, used: u64, free: u64) -> NodeReport {
        NodeReport {
            hostname: hostname.into(),
            at: 1_000_000,
            disks: vec![DiskUsage {
                path: "/".into(),
                total_mb: used + free,
                used_mb: used,
                free_mb: free,
            }],
            memory_total_mb: Some(8192),
            memory_available_mb: Some(4096),
            agent_version: "0.1.0".into(),
            protocol: hlb_agent::PROTOCOL,
            ..Default::default()
        }
    }

    #[test]
    fn a_plain_poller_is_not_secure() {
        // 🔴 Il doit être visible qu'on tourne en clair : c'est ce qui permet au
        // controller de le dire à chaque démarrage plutôt que de le taire.
        assert!(!AgentPoller::new(8421, Duration::from_secs(1)).is_secure());
    }

    #[test]
    fn an_unparsable_certificate_is_refused_up_front() {
        // Mieux vaut refuser de démarrer que produire un poller qui échouera sur
        // chaque agent avec une erreur de handshake incompréhensible.
        let r = AgentPoller::with_mtls(
            8421,
            Duration::from_secs(1),
            "pas du PEM",
            "pas du PEM non plus",
        );
        assert!(r.is_err());
    }

    #[test]
    fn an_unreachable_node_never_allows_a_deployment() {
        // 🔴 On ne sait pas s'il a de la place. Supposer que oui, c'est risquer de
        // saturer un disque à l'aveugle.
        let s = AgentStatus::Unreachable {
            detail: "délai dépassé".into(),
        };
        assert!(!s.allows_deploy(&Thresholds::default()));
        assert!(s.report().is_none());
        assert!(s.describe().contains("injoignable"));
    }

    #[test]
    fn a_healthy_node_allows_deployment() {
        let s = AgentStatus::Reporting(Box::new(rapport("n1", 30_000, 70_000)));
        assert!(s.allows_deploy(&Thresholds::default()));
        assert!(s.describe().contains("sain"));
    }

    #[test]
    fn a_saturated_node_refuses_deployment() {
        let s = AgentStatus::Reporting(Box::new(rapport("n1", 95_000, 5_000)));
        assert!(!s.allows_deploy(&Thresholds::default()));
    }

    #[test]
    fn health_counts_reporting_and_silent_nodes_apart() {
        let mut m = BTreeMap::new();
        m.insert(
            "10.0.0.1".into(),
            AgentStatus::Reporting(Box::new(rapport("n1", 10, 90))),
        );
        m.insert(
            "10.0.0.2".into(),
            AgentStatus::Unreachable { detail: "x".into() },
        );
        m.insert(
            "10.0.0.3".into(),
            AgentStatus::Reporting(Box::new(rapport("n3", 96, 4))),
        );

        let h = ClusterHealth::from_statuses(&m, &Thresholds::default());
        assert_eq!(h.reporting, 2);
        assert_eq!(h.unreachable, 1);
        assert_eq!(h.saturated, vec!["n3"]);
        assert!(h.needs_attention());
    }

    #[test]
    fn a_silent_node_is_not_counted_as_saturated() {
        // On ne sait pas s'il l'est : l'affirmer serait faux, et brouillerait le
        // diagnostic — « 3 nœuds saturés » alors qu'ils sont peut-être juste éteints.
        let mut m = BTreeMap::new();
        m.insert(
            "10.0.0.1".into(),
            AgentStatus::Unreachable { detail: "x".into() },
        );

        let h = ClusterHealth::from_statuses(&m, &Thresholds::default());
        assert!(h.saturated.is_empty());
        assert_eq!(h.unreachable, 1);
    }

    #[test]
    fn a_fully_healthy_cluster_needs_nothing() {
        let mut m = BTreeMap::new();
        m.insert(
            "10.0.0.1".into(),
            AgentStatus::Reporting(Box::new(rapport("n1", 10, 90))),
        );

        let h = ClusterHealth::from_statuses(&m, &Thresholds::default());
        assert!(!h.needs_attention());
    }

    /// Port réservé au service « discard » : rien n'y écoute jamais.
    ///
    /// Un port applicatif comme 8421 serait pris par un agent lancé à la main, et le
    /// test passerait ou échouerait selon ce qui tourne sur la machine — c'est
    /// exactement ce qui m'est arrivé en écrivant ce module.
    const PORT_FERME: u16 = 9;

    #[tokio::test]
    async fn an_unreachable_address_is_reported_not_retried_forever() {
        let p = AgentPoller::new(PORT_FERME, Duration::from_millis(300));
        let s = p.poll("127.0.0.1").await;
        assert!(matches!(s, AgentStatus::Unreachable { .. }), "{s:?}");
    }

    #[tokio::test]
    async fn polling_several_nodes_returns_one_entry_each() {
        let p = AgentPoller::new(PORT_FERME, Duration::from_millis(300));
        let r = p.poll_all(&["127.0.0.1".into(), "127.0.0.2".into()]).await;
        assert_eq!(r.len(), 2);
    }
}
