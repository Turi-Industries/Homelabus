//! `hlb-controller` — le daemon.
//!
//! Trois responsabilités : servir l'API de lecture, faire tourner les boucles de fond,
//! et battre le cœur que surveille le NAS (§8bis).
//!
//! 🟢 **Propriété importante (§7bis)** : le controller n'est PAS dans le chemin
//! critique du trafic. Swarm continue de faire tourner les services déployés sans lui.
//! L'arrêter fait perdre le pilotage, pas le service — ce qui rend ses mises à jour et
//! ses redémarrages beaucoup moins délicats.

mod api;
mod loops;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use hlb_orchestrator::SwarmOrchestrator;
use hlb_state::State;

#[derive(Parser)]
#[command(name = "hlb-controller", version, about = "Daemon HomelabUS")]
struct Cli {
    /// Adresse d'écoute de l'API.
    #[arg(long, default_value = "127.0.0.1:8420", env = "HLB_LISTEN")]
    listen: String,

    #[arg(long, default_value = "hlb.db", env = "HLB_STATE")]
    state: std::path::PathBuf,

    /// Intervalle de réconciliation.
    #[arg(long, default_value = "60", env = "HLB_RECONCILE_SECS")]
    reconcile_secs: u64,

    /// Corriger les écarts détectés. Sans ce drapeau : détection seule.
    #[arg(long, env = "HLB_RECONCILE_APPLY")]
    reconcile_apply: bool,

    /// Fichier de battement de cœur, à placer HORS du cluster (§8bis).
    #[arg(long, env = "HLB_HEARTBEAT")]
    heartbeat: Option<std::path::PathBuf>,

    #[arg(long, default_value = "30", env = "HLB_HEARTBEAT_SECS")]
    heartbeat_secs: u64,

    /// Dépôt restic. Absent : la boucle de sauvegarde ne démarre pas.
    #[arg(long, env = "HLB_BACKUP_REPO")]
    backup_repo: Option<String>,

    #[arg(long, default_value = "hlb-master.key", env = "HLB_MASTER_KEY")]
    master_key: std::path::PathBuf,

    /// Fréquence d'examen des échéances de sauvegarde.
    #[arg(long, default_value = "600", env = "HLB_BACKUP_CHECK_SECS")]
    backup_check_secs: u64,
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
    let state = Arc::new(State::open(&cli.state).await?);

    // L'orchestrateur peut être absent au démarrage (Docker pas encore prêt). On le
    // signale sans refuser de démarrer : l'API de lecture reste utile, et la
    // réconciliation réessaiera.
    let orchestrator = match SwarmOrchestrator::connect() {
        Ok(o) => Some(Arc::new(o)),
        Err(e) => {
            tracing::warn!("Docker injoignable au démarrage ({e}) — réconciliation suspendue");
            None
        }
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut taches = Vec::new();

    if let Some(orch) = orchestrator {
        let rl = Arc::new(
            loops::ReconcileLoop::new(orch, state.clone()).apply(cli.reconcile_apply),
        );
        let rx = shutdown_rx.clone();
        tracing::info!(
            intervalle = cli.reconcile_secs,
            correction = cli.reconcile_apply,
            "boucle de réconciliation"
        );
        taches.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.reconcile_secs),
            rx,
            move || {
                let rl = rl.clone();
                async move {
                    let r = rl.tick().await;
                    if !r.is_clean() {
                        tracing::warn!(erreurs = r.errors.len(), "réconciliation incomplète");
                    } else if r.acted > 0 {
                        tracing::info!(corrigés = r.acted, "écarts corrigés");
                    }
                }
            },
        )));
    }

    if let Some(path) = cli.heartbeat.clone() {
        let hb = Arc::new(loops::Heartbeat::new(path.clone()));
        let rx = shutdown_rx.clone();
        tracing::info!(fichier = %path.display(), "battement de cœur");
        taches.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.heartbeat_secs),
            rx,
            move || {
                let hb = hb.clone();
                async move {
                    if let Err(e) = hb.beat().await {
                        tracing::error!("battement de cœur impossible : {e}");
                    }
                }
            },
        )));
    }

    if let Some(repo) = cli.backup_repo.clone() {
        match build_provider(&repo, &cli.master_key, &state).await {
            Ok(provider) => {
                let bl = Arc::new(loops::BackupLoop::new(
                    state.clone(),
                    hlb_backup::Schedule::default(),
                ));
                let provider = Arc::new(provider);
                let st = state.clone();
                let rx = shutdown_rx.clone();
                tracing::info!(dépôt = %repo, "boucle de sauvegarde");

                taches.push(tokio::spawn(loops::every(
                    Duration::from_secs(cli.backup_check_secs),
                    rx,
                    move || {
                        let (bl, provider, st) = (bl.clone(), provider.clone(), st.clone());
                        async move {
                            use hlb_updater::BackupProvider;
                            let dues = match bl.due_apps().await {
                                Ok(d) => d,
                                Err(e) => {
                                    tracing::warn!("échéances illisibles : {e}");
                                    return;
                                }
                            };
                            for app in dues {
                                match provider.snapshot(&app).await {
                                    Ok(id) => {
                                        let _ = st
                                            .record_backup(&app, "volume", Some(&id), None)
                                            .await;
                                        tracing::info!(app, instantané = %&id[..8.min(id.len())], "sauvegardée");
                                    }
                                    Err(e) => {
                                        // L'échec est enregistré : l'échéance n'est pas
                                        // repoussée, l'app reste due (§8.1).
                                        let _ = st
                                            .record_backup(&app, "volume", None, Some(&e))
                                            .await;
                                        tracing::error!(app, "sauvegarde échouée : {e}");
                                    }
                                }
                            }
                            // Alerte sur ce qui dérive vraiment (§8bis).
                            if let Ok(tard) = bl.overdue_apps().await {
                                for app in tard {
                                    tracing::error!(app, "🔴 aucune sauvegarde réussie depuis trop longtemps");
                                }
                            }
                        }
                    },
                )));
            }
            Err(e) => tracing::error!("boucle de sauvegarde non démarrée : {e}"),
        }
    }

    let app = api::router(Arc::new(api::AppState {
        state,
        started_at: std::time::Instant::now(),
        version: env!("CARGO_PKG_VERSION"),
    }));

    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    tracing::info!(adresse = %cli.listen, "API en écoute (lecture seule)");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            attendre_arret().await;
            tracing::info!("arrêt demandé, fin des boucles de fond");
            let _ = shutdown_tx.send(true);
        })
        .await?;

    for t in taches {
        let _ = t.await;
    }
    tracing::info!("arrêt propre");
    Ok(())
}

/// Assemble le fournisseur de sauvegarde depuis l'état et le coffre.
async fn build_provider(
    repo: &str,
    master_key: &std::path::Path,
    state: &State,
) -> Result<hlb_backup::ResticBackupProvider<hlb_backup::ContainerRunner>, Box<dyn std::error::Error>>
{
    let vault = hlb_secrets::Vault::open_or_init(master_key)?;

    const SECRET: &str = "restic-repo-password";
    let password = match state.secret(SECRET).await? {
        Some(ct) => vault.decrypt(&ct)?,
        None => {
            let p = hlb_secrets::generate_password(hlb_secrets::DEFAULT_PASSWORD_LEN);
            state
                .store_secret_if_absent(SECRET, &vault.encrypt(&p)?, "chiffrement du dépôt")
                .await?;
            p
        }
    };

    let mut par_app = std::collections::BTreeMap::new();
    for (app, _) in state.installed_apps().await? {
        let noms: Vec<String> = state
            .volumes_to_backup(&app)
            .await?
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        if !noms.is_empty() {
            par_app.insert(app, noms);
        }
    }

    Ok(hlb_backup::provider_for_state(repo, password, par_app).await)
}

/// Ctrl-C ou SIGTERM (ce que Docker envoie).
async fn attendre_arret() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let sigterm = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = sigterm => {}
    }
}
