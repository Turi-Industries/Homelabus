//! `hlb-privd` — the daemon: `hlb.db` read-write, the vault, Docker, the admin clients
//! and every loop, answering the web side's intents over a Unix socket.
//!
//! A binary of this crate rather than of `hlb-privd`: the alert rules measure through
//! the controller's PromQL allowlist, which holds the shipped rules too.

use hlb_privd::{daemon, wire};

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

#[derive(Parser)]
#[command(name = "hlb-privd", version, about = "Homelabus privileged daemon")]
struct Cli {
    /// Where the web side's intents arrive.
    #[arg(
        long,
        env = "HLB_PRIVD_SOCKET",
        default_value = "/run/homelabus/privd.sock"
    )]
    socket: PathBuf,

    /// The web side's uid, the only one answered. Required: a default would answer
    /// whoever happens to run as it.
    #[arg(long, env = "HLB_WEB_UID")]
    web_uid: u32,

    #[command(flatten)]
    daemon: daemon::Config,
}

/// The alert rules' measurements, through the PromQL relay — as `hlb-controller`
/// measures them when it runs the daemon itself.
fn measure(url: &Option<String>) -> Option<Arc<dyn daemon::Measure>> {
    let m = Arc::new(hlb_controller::promql::Metrics::new(url.as_ref()?));
    Some(Arc::new(daemon::Query(move |q: String| {
        let m = m.clone();
        async move { m.instant_samples(&q).await }
    })))
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
    if cli.web_uid == 0 {
        // Root's connections are anyone's who reaches root: the web side would hold
        // the daemon's capabilities after all.
        return Err("--web-uid 0: the web side must not run as root".into());
    }
    if cli.daemon.metrics_url.is_none() {
        tracing::info!(
            "no time-series database (--metrics-url): the alert rules are not evaluated"
        );
    }

    // Bound before the daemon starts: a socket that cannot exist is said before any
    // loop runs. The web side opens nothing early, waiting for the state's migration
    // too, and a connection waits in the backlog until the daemon answers.
    let listener = wire::listen(&cli.socket)?;
    let bound = wire::Bound::of(&cli.socket)?;
    // Open to every uid: the peer's uid is the guard, checked on each connection. An
    // owner or group on the file would need CAP_CHOWN, dropped in the container.
    std::fs::set_permissions(&cli.socket, std::fs::Permissions::from_mode(0o666))?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let started = daemon::start(
        cli.daemon.clone(),
        measure(&cli.daemon.metrics_url),
        shutdown_rx.clone(),
    )
    .await?;
    let mut tasks = started.tasks;
    tracing::info!(
        socket = %cli.socket.display(),
        web_uid = cli.web_uid,
        "answering the web side's intents"
    );
    tasks.push(tokio::spawn(wire::serve(
        listener,
        Arc::new(started.privd),
        cli.web_uid,
        shutdown_rx,
    )));

    wait_for_shutdown().await;
    tracing::info!("shutdown requested, ending the background loops");
    let _ = shutdown_tx.send(true);
    for t in tasks {
        let _ = t.await;
    }
    wire::release(&cli.socket, bound);
    tracing::info!("clean shutdown");
    Ok(())
}

/// Ctrl-C or SIGTERM (what Docker sends).
async fn wait_for_shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let sigterm = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    tokio::select! {
        _ = ctrl_c => {}
        _ = sigterm => {}
    }
}
