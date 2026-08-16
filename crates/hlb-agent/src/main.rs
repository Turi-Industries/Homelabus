//! `hlb-agent` — le démon présent sur chaque nœud.
//!
//! Déployé comme service Swarm `global`. Il expose son état sur HTTP ; le controller
//! l'interroge.
//!
//! ## Pourquoi le controller interroge, et pas l'inverse
//!
//! Un agent qui pousserait ses rapports devrait connaître l'adresse du controller,
//! la retrouver après un redémarrage, et gérer sa propre file d'attente en cas
//! d'indisponibilité. En sens inverse, le DNS de l'overlay Swarm résout déjà le nom
//! du service et **un agent injoignable est en soi l'information utile** : le nœud
//! ne répond pas.
//!
//! ## Sur le chiffrement
//!
//! ⚠️ L'API de l'agent est en HTTP clair. Elle n'écoute que sur le réseau overlay,
//! lui-même chiffré par IPsec quand il est créé avec `--opt encrypted` (§6.3). Le
//! mTLS entre agent et controller prévu au §2 **n'est pas encore en place** — c'est
//! dit ici plutôt que sous-entendu.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;

use hlb_agent::disk::DiskUsage;
use hlb_agent::NodeReport;

#[derive(Parser)]
#[command(name = "hlb-agent", version, about = "Agent de nœud HomelabUS")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:8421", env = "HLB_AGENT_LISTEN")]
    listen: String,

    /// Chemins à surveiller. `/var/lib/docker` est le plus important : c'est lui
    /// qui sature en premier (images, volumes, journaux).
    #[arg(long, default_values = ["/", "/var/lib/docker"], env = "HLB_AGENT_PATHS")]
    watch: Vec<String>,
}

struct AgentState {
    hostname: String,
    watch: Vec<String>,
    version: &'static str,
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
    });

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/report", get(report))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    tracing::info!(hôte = %hostname, adresse = %cli.listen, "agent en écoute");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("arrêt de l'agent");
        })
        .await?;

    Ok(())
}

async fn report(State(s): State<Arc<AgentState>>) -> Json<NodeReport> {
    let mut disks = Vec::new();
    for p in &s.watch {
        if let Some(u) = disk_usage(p).await {
            disks.push(u);
        }
    }

    let (total, available) = memory().await;

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
    })
}

/// Lit l'occupation d'un système de fichiers via `df`.
///
/// `-P` force le format POSIX : sans lui, un nom de périphérique long passe à la
/// ligne et décale toutes les colonnes.
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
        // `MemAvailable` est bien plus juste que `MemFree` : il tient compte du cache
        // récupérable, qui représente souvent l'essentiel de la mémoire « occupée ».
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
        // 20480 / (20480 + 76800) = 21,05 % — calculé sur l'espace UTILISABLE,
        // pas sur `total`, qui inclut la réserve root (cf. DiskUsage::used_percent).
        assert!((u.used_percent() - 21.05).abs() < 0.1, "{:.2} %", u.used_percent());
    }

    #[test]
    fn a_truncated_df_gives_none() {
        assert!(parse_df("Filesystem 1M-blocks\n", "/").is_none());
        assert!(parse_df("", "/").is_none());
    }

    #[test]
    fn available_memory_is_preferred_over_free() {
        // `MemFree` sous-estime massivement : le cache est récupérable.
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
