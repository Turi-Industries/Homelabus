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
//! 🔴 **mTLS par défaut** (§2) : l'agent n'accepte que des clients porteurs d'un
//! certificat signé par la CA du cluster. Sans ça, tout conteneur de l'overlay —
//! y compris une app compromise — pourrait cartographier les disques du parc.
//!
//! Le mode clair reste possible via `--insecure-plaintext`, mais il l'annonce
//! bruyamment à chaque démarrage : un déploiement qui l'utilise par accident ne doit
//! pas pouvoir passer inaperçu.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use clap::Parser;

use hlb_agent::disk::DiskUsage;
use hlb_agent::NodeReport;

#[derive(Parser)]
#[command(name = "hlb-agent", version, about = "Agent de nœud Homelabus")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:8421", env = "HLB_AGENT_LISTEN")]
    listen: String,

    /// Certificat de l'agent, signé par la CA du cluster.
    #[arg(long, env = "HLB_AGENT_CERT")]
    cert: Option<std::path::PathBuf>,

    /// Clé privée correspondante.
    #[arg(long, env = "HLB_AGENT_KEY")]
    key: Option<std::path::PathBuf>,

    /// CA du cluster : c'est elle qui décide quels CLIENTS sont acceptés.
    #[arg(long, env = "HLB_AGENT_CA")]
    ca: Option<std::path::PathBuf>,

    /// 🔴 Servir en HTTP clair. À n'utiliser que pour un diagnostic local.
    #[arg(long, env = "HLB_AGENT_INSECURE")]
    insecure_plaintext: bool,

    /// Chemins à surveiller.
    ///
    /// `/var/lib/docker` sature en premier : images, volumes, journaux.
    ///
    /// 🔴 `/archive/wal` est là pour une raison précise (§8.1) : un `archive_command`
    /// qui échoue ne PERD pas les journaux, il les garde. `pg_wal` grossit alors sans
    /// limite jusqu'à arrêter PostgreSQL. Sans ce chemin surveillé, la panne est
    /// totalement silencieuse jusqu'à ce que la base tombe.
    ///
    /// Un chemin inexistant est ignoré sans bruit : tous les nœuds n'archivent pas.
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
    /// Le relevé CPU précédent.
    ///
    /// 🔴 Les compteurs de `/proc/stat` sont **cumulés depuis le démarrage** : le taux
    /// d'occupation est une différence entre deux lectures. Sans mémoire du relevé
    /// précédent, on ne pourrait rendre qu'un cumul dénué de sens — ou pire, un `0`
    /// qui se lirait « machine au repos ».
    ///
    /// La toute première requête rend donc `None`, et c'est correct.
    cpu_precedent: std::sync::Mutex<Option<hlb_agent::systeme::RelevéCpu>>,
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
        cpu_precedent: std::sync::Mutex::new(None),
    });

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/report", get(report))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;

    let arret = || async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("arrêt de l'agent");
    };

    match charger_tls(&cli).await? {
        Some(config) => {
            tracing::info!(hôte = %hostname, adresse = %cli.listen, "agent en écoute (mTLS)");
            let tls = hlb_agent::tls::TlsListener::new(listener, config);
            axum::serve(tls, app)
                .with_graceful_shutdown(arret())
                .await?;
        }
        None => {
            // 🔴 Répété à chaque démarrage, et en `error` : un déploiement qui tourne
            // en clair par accident ne doit pas pouvoir passer inaperçu.
            tracing::error!(
                "🔴 API en HTTP CLAIR — tout conteneur de l'overlay peut interroger \
                 cet agent. Fournis --cert/--key/--ca."
            );
            tracing::info!(hôte = %hostname, adresse = %cli.listen, "agent en écoute (clair)");
            axum::serve(listener, app)
                .with_graceful_shutdown(arret())
                .await?;
        }
    }

    Ok(())
}

/// Charge la configuration TLS, ou explique précisément ce qui manque.
///
/// ⚠️ On refuse de démarrer sur une configuration TLS **partielle**. Deux fichiers
/// sur trois donneraient un agent qui démarre en clair alors que l'opérateur croit
/// l'avoir sécurisé — l'échec silencieux le plus coûteux du lot.
async fn charger_tls(
    cli: &Cli,
) -> Result<Option<std::sync::Arc<tokio_rustls::rustls::ServerConfig>>, Box<dyn std::error::Error>>
{
    let fournis = [&cli.cert, &cli.key, &cli.ca]
        .iter()
        .filter(|o| o.is_some())
        .count();

    if cli.insecure_plaintext {
        if fournis > 0 {
            tracing::warn!("--insecure-plaintext l'emporte : les certificats fournis sont ignorés");
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
        _ if fournis > 0 => Err(format!(
            "configuration TLS incomplète : {fournis}/3 fichiers fournis. \
             Il faut --cert, --key ET --ca — sinon l'agent démarrerait en clair \
             alors que tu le crois protégé."
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

    // Le taux d'occupation CPU : différence avec le relevé précédent, puis on garde
    // celui-ci pour la prochaine fois.
    let releve = hlb_agent::systeme::releve_cpu();
    let occupation = match (&releve, s.cpu_precedent.lock()) {
        (Some(maintenant), Ok(mut prec)) => {
            let taux = prec.as_ref().and_then(|p| maintenant.occupation(p));
            *prec = Some(*maintenant);
            taux
        }
        // Un verrou empoisonné ne doit pas priver de TOUT le rapport : on perd le
        // taux CPU, pas l'espace disque — qui est ce qui empêche un déploiement.
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
