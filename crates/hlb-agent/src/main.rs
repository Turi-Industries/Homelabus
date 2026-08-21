//! `hlb-agent` - the daemon present on every node.
//!
//! Deployed as a `global` Swarm service. It exposes its state over HTTP; the controller
//! polls it.
//!
//! ## Why the controller polls, rather than the reverse
//!
//! An agent pushing its reports would need to know the controller's address, find it
//! again after a restart, and manage its own queue when the controller is unavailable.
//! The other way round, the Swarm overlay's DNS already resolves the service name and
//! **an unreachable agent is itself the useful information**: the node is not
//! answering.
//!
//! ## On encryption
//!
//! 🔴 **mTLS by default**: the agent accepts only clients presenting a certificate
//! signed by the cluster's CA. Without it, any container on the overlay - including a
//! compromised app - could map the fleet's disks.
//!
//! Plaintext mode stays possible through `--insecure-plaintext`, but it announces
//! itself loudly on every start: a deployment using it by accident must not be able to
//! go unnoticed.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;

use hlb_agent::disk::DiskUsage;
use hlb_agent::NodeReport;

#[derive(Parser)]
#[command(name = "hlb-agent", version, about = "Homelabus node agent")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:8421", env = "HLB_AGENT_LISTEN")]
    listen: String,

    /// The agent's certificate, signed by the cluster's CA.
    #[arg(long, env = "HLB_AGENT_CERT")]
    cert: Option<std::path::PathBuf>,

    /// The matching private key.
    #[arg(long, env = "HLB_AGENT_KEY")]
    key: Option<std::path::PathBuf>,

    /// The cluster's CA: it decides which CLIENTS are accepted.
    #[arg(long, env = "HLB_AGENT_CA")]
    ca: Option<std::path::PathBuf>,

    /// 🔴 Serve plain HTTP. Only for a local diagnosis.
    #[arg(long, env = "HLB_AGENT_INSECURE")]
    insecure_plaintext: bool,

    /// Paths to watch.
    ///
    /// `/var/lib/docker` fills first: images, volumes, logs.
    ///
    /// 🔴 `/archive/wal` is there for a precise reason: a failing `archive_command`
    /// does not LOSE the journals, it keeps them. `pg_wal` then grows without limit
    /// until it stops PostgreSQL. Without this path watched, the failure is completely
    /// silent until the database falls over.
    ///
    /// A non-existent path is ignored quietly: not every node archives.
    #[arg(
        long,
        default_values = ["/", "/var/lib/docker", "/archive/wal", "/archive/base"],
        env = "HLB_AGENT_PATHS"
    )]
    watch: Vec<String>,
}

struct AgentState {
    hostname: String,
    watch: Vec<String>,
    version: &'static str,
    /// The previous CPU reading.
    ///
    /// 🔴 `/proc/stat`'s counters are **cumulative since boot**: the usage rate is a
    /// difference between two reads. Without remembering the previous reading we could
    /// only return a meaningless total - or worse, a `0` that would read as "idle
    /// machine".
    ///
    /// So the very first request returns `None`, and that is correct.
    previous_cpu: std::sync::Mutex<Option<hlb_agent::systeme::CpuReading>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("HLB_LOG")
                .unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    let hostname = tokio::fs::read_to_string("/etc/hostname")
        .await
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "inconnu".into());

    let state = Arc::new(AgentState {
        hostname: hostname.clone(),
        watch: cli.watch.clone(),
        version: env!("CARGO_PKG_VERSION"),
        previous_cpu: std::sync::Mutex::new(None),
    });

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/report", get(report))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;

    let arret = || async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("agent shutting down");
    };

    match charger_tls(&cli).await? {
        Some(config) => {
            tracing::info!(host = %hostname, address = %cli.listen, "agent listening (mTLS)");
            let tls = hlb_agent::tls::TlsListener::new(listener, config);
            axum::serve(tls, app)
                .with_graceful_shutdown(arret())
                .await?;
        }
        None => {
            // 🔴 Repeated on every start, and at `error` level: a deployment running in
            // plaintext by accident must not be able to go unnoticed.
            tracing::error!(
                "🔴 API en HTTP CLAIR — tout conteneur de l'overlay peut interroger \
                 cet agent. Fournis --cert/--key/--ca."
            );
            tracing::info!(host = %hostname, address = %cli.listen, "agent listening (plaintext)");
            axum::serve(listener, app)
                .with_graceful_shutdown(arret())
                .await?;
        }
    }

    Ok(())
}

/// Loads the TLS configuration, or says precisely what is missing.
///
/// ⚠️ Starting on a **partial** TLS configuration is refused. Two files out of three
/// would give an agent starting in plaintext while the operator believes it is secured
/// - the most expensive silent failure of the lot.
async fn charger_tls(
    cli: &Cli,
) -> Result<Option<std::sync::Arc<tokio_rustls::rustls::ServerConfig>>, Box<dyn std::error::Error>>
{
    let supplied = [&cli.cert, &cli.key, &cli.ca]
        .iter()
        .filter(|o| o.is_some())
        .count();

    if cli.insecure_plaintext {
        if supplied > 0 {
            tracing::warn!("--insecure-plaintext wins: the supplied certificates are ignored");
        }
        return Ok(None);
    }

    match (&cli.cert, &cli.key, &cli.ca) {
        (Some(c), Some(k), Some(a)) => {
            let paire = hlb_agent::CertPair {
                cert_pem: tokio::fs::read_to_string(c).await?,
                key_pem: tokio::fs::read_to_string(k).await?,
            };
            let ca = tokio::fs::read_to_string(a).await?;
            Ok(Some(hlb_agent::tls::server_config(&paire, &ca)?))
        }
        _ if supplied > 0 => Err(format!(
            "incomplete TLS configuration: {supplied}/3 files supplied. \
             --cert, --key AND --ca are all required - otherwise the agent would start \
             in plaintext while you believe it is protected."
        )
        .into()),
        _ => Ok(None),
    }
}

async fn report(State(s): State<Arc<AgentState>>) -> Json<NodeReport> {
    let mut disks = Vec::new();
    for p in &s.watch {
        if let Some(u) = disk_usage(p).await {
            disks.push(u);
        }
    }

    let (total, available) = memory().await;

    // The CPU usage rate: a difference against the previous reading, then this one is
    // kept for next time.
    let reading = hlb_agent::systeme::read_cpu();
    let occupation = match (&reading, s.previous_cpu.lock()) {
        (Some(maintenant), Ok(mut prec)) => {
            let taux = prec.as_ref().and_then(|p| maintenant.occupation(p));
            *prec = Some(*maintenant);
            taux
        }
        // A poisoned lock must not cost the WHOLE report: the CPU rate is lost, not
        // the disk space - which is what blocks a deployment.
        _ => None,
    };

    let (swap_total, swap_utilise) = hlb_agent::systeme::swap_mb();

    Json(NodeReport {
        hostname: s.hostname.clone(),
        at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        disks,
        memory_total_mb: total,
        memory_available_mb: available,
        agent_version: s.version.to_string(),
        protocol: hlb_agent::PROTOCOL,
        cpu_coeurs: hlb_agent::systeme::coeurs(),
        charge: hlb_agent::systeme::charge(),
        cpu_occupation: occupation,
        swap_total_mb: swap_total,
        swap_utilise_mb: swap_utilise,
        interfaces: hlb_agent::systeme::interfaces(),
        systeme: Some(hlb_agent::systeme::systeme()),
    })
}

/// Reads a filesystem's usage through `df`.
///
/// `-P` forces the POSIX format: without it, a long device name wraps onto the next
/// line and shifts every column.
async fn disk_usage(path: &str) -> Option<DiskUsage> {
    let out = tokio::process::Command::new("df")
        .args(["-Pm", path])
        .output()
        .await
        .ok()?;

    if !out.status.success() {
        return None;
    }
    parse_df(&String::from_utf8_lossy(&out.stdout), path)
}

fn parse_df(df: &str, path: &str) -> Option<DiskUsage> {
    let l = df.lines().nth(1)?;
    let c: Vec<&str> = l.split_whitespace().collect();
    Some(DiskUsage {
        path: path.to_string(),
        total_mb: c.get(1)?.parse().ok()?,
        used_mb: c.get(2)?.parse().ok()?,
        free_mb: c.get(3)?.parse().ok()?,
    })
}

async fn memory() -> (Option<u64>, Option<u64>) {
    let Ok(m) = tokio::fs::read_to_string("/proc/meminfo").await else {
        return (None, None);
    };
    (
        parse_meminfo(&m, "MemTotal:"),
        // `MemAvailable` is far more accurate than `MemFree`: it accounts for
        // reclaimable cache, which is often most of the "used" memory.
        parse_meminfo(&m, "MemAvailable:"),
    )
}

fn parse_meminfo(meminfo: &str, key: &str) -> Option<u64> {
    meminfo
        .lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .map(|kb| kb / 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn df_output_is_parsed() {
        let df = "Filesystem 1M-blocks Used Available Capacity Mounted on\n\
                  /dev/sda1      102400 20480     76800      21% /\n";
        let u = parse_df(df, "/").expect("analysable");
        assert_eq!(u.total_mb, 102_400);
        assert_eq!(u.used_mb, 20_480);
        assert_eq!(u.free_mb, 76_800);
        // 20480 / (20480 + 76800) = 21.05 % - computed over USABLE space, not over
        // `total`, which includes the root reserve (see DiskUsage::used_percent).
        assert!(
            (u.used_percent() - 21.05).abs() < 0.1,
            "{:.2} %",
            u.used_percent()
        );
    }

    #[test]
    fn a_truncated_df_gives_none() {
        assert!(parse_df("Filesystem 1M-blocks\n", "/").is_none());
        assert!(parse_df("", "/").is_none());
    }

    #[test]
    fn available_memory_is_preferred_over_free() {
        // `MemFree` massively underestimates: the cache is reclaimable.
        let m = "MemTotal:       16311456 kB\n\
                 MemFree:          204800 kB\n\
                 MemAvailable:   12000000 kB\n";
        assert_eq!(parse_meminfo(m, "MemTotal:"), Some(15929));
        assert_eq!(parse_meminfo(m, "MemAvailable:"), Some(11718));
    }

    #[test]
    fn a_missing_key_gives_none() {
        assert_eq!(parse_meminfo("MemTotal: 100 kB\n", "MemAvailable:"), None);
    }
}
