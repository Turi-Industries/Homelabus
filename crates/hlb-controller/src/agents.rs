//! Polling the node agents.
//!
//! The controller polls, the agents do not push. Two reasons:
//!
//! - an agent that pushed would need to know the controller's address, find it again
//!   after a restart, and manage its own queue while the controller is unavailable;
//! - **an unreachable agent is itself the useful information**: the node does not
//!   answer, so its data may no longer be backed up.
//!
//! ## How each agent is reached
//!
//! The Swarm overlay's DNS resolves `tasks.<service>` to **every** task of the service,
//! not to a single VIP. That is what allows polling each node individually rather than
//! drawing one at random.

use std::collections::BTreeMap;
use std::time::Duration;

use hlb_agent::{DiskPressure, NodeReport, Thresholds};

/// What we could — or could not — learn from a node.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentStatus {
    /// The agent answered.
    Reporting(Box<NodeReport>),
    /// The agent did not answer. We assume NOTHING about the node's state.
    Unreachable { detail: String },
}

impl AgentStatus {
    pub fn report(&self) -> Option<&NodeReport> {
        match self {
            Self::Reporting(r) => Some(r),
            Self::Unreachable { .. } => None,
        }
    }

    /// 🔴 A mute node does not authorise a deployment: we do not know whether it has
    /// room. Assuming it does risks filling a disk blind.
    pub fn allows_deploy(&self, t: &Thresholds) -> bool {
        self.report().is_some_and(|r| r.allows_deploy(t))
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Reporting(r) => {
                let p = r.worst_pressure(&Thresholds::default());
                match p {
                    DiskPressure::Normal => "✓ sain".into(),
                    _ => format!("{} — {}", brand(p), p.describe()),
                }
            }
            Self::Unreachable { detail } => format!("🔴 unreachable ({detail})"),
        }
    }
}

fn brand(p: DiskPressure) -> &'static str {
    match p {
        DiskPressure::Normal => "✓",
        DiskPressure::Notice => "🟠",
        _ => "🔴",
    }
}

pub struct AgentPoller {
    http: reqwest::Client,
    port: u16,
    /// `https` when mTLS is configured. The scheme MUST follow: polling an mTLS agent
    /// over `http://` fails on a protocol error that does not say the scheme is the
    /// problem.
    scheme: &'static str,
    /// With mTLS: what each per-agent client is built from, and the name it verifies.
    mtls: Option<Mtls>,
}

/// 🔴 The controller reaches each agent at its task's IP — `tasks.<service>` resolves to
/// all of them — but a certificate names hosts, not overlay addresses that change at
/// every reschedule. Verifying the IP against the certificate failed every connection.
/// Each poll connects to the task's IP while verifying `server_name`, which every
/// agent's certificate carries.
struct Mtls {
    client_pem: String,
    ca_pem: String,
    server_name: String,
    timeout: Duration,
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
            mtls: None,
        }
    }

    /// Polls the agents over mTLS.
    ///
    /// 🔴 `identity` is the controller's certificate: without it the agents refuse the
    /// connection. `ca_pem` serves to verify the agents — we do NOT trust the system's
    /// authorities, only our own. An agent whose certificate was signed by a public CA
    /// must be refused like any other
    /// imposteur.
    pub fn with_mtls(
        port: u16,
        timeout: Duration,
        client_pem: &str,
        ca_pem: &str,
        server_name: &str,
    ) -> Result<Self, String> {
        let identity = reqwest::Identity::from_pem(client_pem.as_bytes())
            .map_err(|e| format!("unreadable controller certificate: {e}"))?;
        let ca = reqwest::Certificate::from_pem(ca_pem.as_bytes())
            .map_err(|e| format!("unreadable CA: {e}"))?;

        let http = reqwest::Client::builder()
            .timeout(timeout)
            .identity(identity)
            .add_root_certificate(ca)
            // Our CA ONLY: public authorities have no business here.
            .tls_built_in_root_certs(false)
            .build()
            .map_err(|e| format!("client mTLS : {e}"))?;

        Ok(Self {
            http,
            port,
            scheme: "https",
            mtls: Some(Mtls {
                client_pem: client_pem.to_string(),
                ca_pem: ca_pem.to_string(),
                server_name: server_name.to_string(),
                timeout,
            }),
        })
    }

    /// The client and URL for one agent: pinned to its IP, verifying the shared name.
    fn target(&self, addr: &str) -> (reqwest::Client, String) {
        let direct = (
            self.http.clone(),
            format!("{}://{addr}:{}/api/report", self.scheme, self.port),
        );
        let (Some(m), Ok(ip)) = (&self.mtls, addr.parse::<std::net::IpAddr>()) else {
            return direct;
        };
        let built = (|| {
            reqwest::Client::builder()
                .timeout(m.timeout)
                .identity(reqwest::Identity::from_pem(m.client_pem.as_bytes()).ok()?)
                .add_root_certificate(reqwest::Certificate::from_pem(m.ca_pem.as_bytes()).ok()?)
                .tls_built_in_root_certs(false)
                .resolve(&m.server_name, std::net::SocketAddr::new(ip, self.port))
                .build()
                .ok()
        })();
        match built {
            Some(c) => (
                c,
                format!("https://{}:{}/api/report", m.server_name, self.port),
            ),
            None => direct,
        }
    }

    pub fn is_secure(&self) -> bool {
        self.scheme == "https"
    }

    /// Polls an agent at a given address.
    pub async fn poll(&self, addr: &str) -> AgentStatus {
        let (http, url) = self.target(addr);

        match http.get(&url).send().await {
            Err(e) => AgentStatus::Unreachable {
                detail: if e.is_timeout() {
                    "timed out".into()
                } else if e.is_connect() && self.scheme == "https" {
                    // Distinguish the two: "connection refused" would send you looking
                    // for a stopped agent, when the certificate is the most frequent
                    // cause once mTLS is enabled.
                    format!("TLS connection refused (certificate?): {e}")
                } else {
                    "connection refused".into()
                },
            },
            Ok(r) if !r.status().is_success() => AgentStatus::Unreachable {
                detail: format!("HTTP {}", r.status().as_u16()),
            },
            // Bounded: an agent's report is kilobytes, and a node answering without end
            // would have filled the controller's memory.
            Ok(r) => match bounded(r, MAX_REPORT)
                .await
                .and_then(|b| serde_json::from_slice::<NodeReport>(&b).map_err(|e| e.to_string()))
            {
                Ok(rep) => AgentStatus::Reporting(Box::new(rep)),
                Err(e) => AgentStatus::Unreachable {
                    detail: format!("unreadable response: {e}"),
                },
            },
        }
    }

    /// Polls every agent, in parallel.
    ///
    /// Sequentially, a single unreachable node would make all the others wait: with ten
    /// nodes and a ten-second timeout, one pass would take more than a
    /// minute when it should take ten seconds.
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

/// A summary usable for supervision.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClusterHealth {
    pub reporting: usize,
    pub unreachable: usize,
    /// Nodes where a deployment would be refused.
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
                    // A mute node is reported, but not listed as full: we do not know
                    // whether it is, and claiming otherwise would be false.
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

/// The most an agent's report is read to.
const MAX_REPORT: usize = 4 * 1024 * 1024;

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
    use hlb_agent::DiskUsage;

    fn report(hostname: &str, used: u64, free: u64) -> NodeReport {
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
        // 🔴 It must be visible that we are running in the clear: that is what lets the
        // controller say so at every start rather than keep quiet about it.
        assert!(!AgentPoller::new(8421, Duration::from_secs(1)).is_secure());
    }

    #[test]
    fn an_unparsable_certificate_is_refused_up_front() {
        // Better to refuse to start than to produce a poller that will fail on every
        // agent with an incomprehensible handshake error.
        let r = AgentPoller::with_mtls(
            8421,
            Duration::from_secs(1),
            "not PEM",
            "not PEM either",
            "tasks.hlb-agent",
        );
        assert!(r.is_err());
    }

    #[test]
    fn an_unreachable_node_never_allows_a_deployment() {
        // 🔴 We do not know whether it has room. Assuming it does risks filling a disk
        // blind.
        let s = AgentStatus::Unreachable {
            detail: "timed out".into(),
        };
        assert!(!s.allows_deploy(&Thresholds::default()));
        assert!(s.report().is_none());
        assert!(s.describe().contains("unreachable"));
    }

    #[test]
    fn a_healthy_node_allows_deployment() {
        let s = AgentStatus::Reporting(Box::new(report("n1", 30_000, 70_000)));
        assert!(s.allows_deploy(&Thresholds::default()));
        assert!(s.describe().contains("sain"));
    }

    #[test]
    fn a_saturated_node_refuses_deployment() {
        let s = AgentStatus::Reporting(Box::new(report("n1", 95_000, 5_000)));
        assert!(!s.allows_deploy(&Thresholds::default()));
    }

    #[test]
    fn health_counts_reporting_and_silent_nodes_apart() {
        let mut m = BTreeMap::new();
        m.insert(
            "10.0.0.1".into(),
            AgentStatus::Reporting(Box::new(report("n1", 10, 90))),
        );
        m.insert(
            "10.0.0.2".into(),
            AgentStatus::Unreachable { detail: "x".into() },
        );
        m.insert(
            "10.0.0.3".into(),
            AgentStatus::Reporting(Box::new(report("n3", 96, 4))),
        );

        let h = ClusterHealth::from_statuses(&m, &Thresholds::default());
        assert_eq!(h.reporting, 2);
        assert_eq!(h.unreachable, 1);
        assert_eq!(h.saturated, vec!["n3"]);
        assert!(h.needs_attention());
    }

    #[test]
    fn a_silent_node_is_not_counted_as_saturated() {
        // We do not know whether it is: asserting it would be false, and would blur the
        // diagnosis — "3 nodes full" when they may simply be switched off.
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
            AgentStatus::Reporting(Box::new(report("n1", 10, 90))),
        );

        let h = ClusterHealth::from_statuses(&m, &Thresholds::default());
        assert!(!h.needs_attention());
    }

    /// Port reserved for the "discard" service: nothing ever listens there.
    ///
    /// An application port like 8421 would be taken by an agent started by hand, and the
    /// test would pass or fail depending on what is running on the machine — which is
    /// exactly what happened to me while writing this module.
    const CLOSED_PORT: u16 = 9;

    #[tokio::test]
    async fn an_unreachable_address_is_reported_not_retried_forever() {
        let p = AgentPoller::new(CLOSED_PORT, Duration::from_millis(300));
        let s = p.poll("127.0.0.1").await;
        assert!(matches!(s, AgentStatus::Unreachable { .. }), "{s:?}");
    }

    #[tokio::test]
    async fn polling_several_nodes_returns_one_entry_each() {
        let p = AgentPoller::new(CLOSED_PORT, Duration::from_millis(300));
        let r = p.poll_all(&["127.0.0.1".into(), "127.0.0.2".into()]).await;
        assert_eq!(r.len(), 2);
    }
}
