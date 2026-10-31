//! The daemon's composition: what only it may open — `hlb.db` read-write, the vault,
//! Docker, the admin clients — and every loop that runs with them.
//!
//! [`start`] hands back the [`Privd`] answering the web side: in the same process (the
//! demonstration's controller, a single-machine run) or behind [`crate::wire`]'s socket
//! (`hlb-privd`, deployed beside the web side by `hlb fleet controller`).

use std::sync::Arc;
use std::time::Duration;

use hlb_orchestrator::{Orchestrator, SwarmOrchestrator};
use hlb_state::State;

use super::schedule;
use crate::{InstallContext, Privd};

/// How often the notifications quiet hours held are looked at: within five minutes of
/// the morning, and a pass is one read of a table that is usually empty.
const HELD_NOTIFICATIONS_SECS: u64 = 300;

/// The daemon's settings. The web side reads `state`, `catalog`, `mail_domain`,
/// `metrics_url`, `heartbeat` and `git_mirror` too — read-only, from its own mounts.
#[derive(clap::Args, Debug, Clone)]
pub struct Config {
    #[arg(long, default_value = "hlb.db", env = "HLB_STATE")]
    pub state: std::path::PathBuf,

    /// ntfy server for the alerts. Without one, they stay in the logs.
    #[arg(long, env = "HLB_NTFY_URL")]
    pub ntfy_url: Option<String>,

    #[arg(long, default_value = "homelab", env = "HLB_NTFY_TOPIC")]
    pub ntfy_topic: String,

    /// PostgreSQL admin URL. Without it, the databases are NOT dumped.
    #[arg(long, env = "HLB_POSTGRES_ADMIN")]
    pub postgres_admin: Option<String>,

    /// MariaDB admin URL. Without it, the apps that need MariaDB are installed with
    /// their database recorded as unimplemented rather than silently skipped.
    #[arg(long, env = "HLB_MARIADB_ADMIN")]
    pub mariadb_admin: Option<String>,

    /// Root under which `tier: local` volumes are bound, e.g. `/tank/apps`.
    #[arg(long, env = "HLB_STORAGE_ROOT")]
    pub storage_root: Option<String>,

    /// NFS server for the `tier: nfs` volumes. 🔴 Without it, installing an app that
    /// declares one is refused rather than silently given a local volume.
    #[arg(long, env = "HLB_NFS_SERVER")]
    pub nfs_server: Option<String>,

    /// The exported root on that server, e.g. `/tank/media`.
    #[arg(long, env = "HLB_NFS_EXPORT")]
    pub nfs_export: Option<String>,

    /// Docker network where the platform services are reachable by name.
    #[arg(long, default_value = "hlb_platform", env = "HLB_PLATFORM_NETWORK")]
    pub platform_network: String,

    /// PocketID URL, to create the identities from the interface.
    #[arg(long, env = "HLB_POCKETID_URL")]
    pub pocketid_url: Option<String>,

    /// PocketID API key.
    ///
    /// ⚠️ Through an environment variable preferably: a key passed as a command argument
    /// is visible to the whole system through `ps`.
    #[arg(long, env = "HLB_POCKETID_KEY", hide_env_values = true)]
    pub pocketid_key: Option<String>,

    /// Application catalog directory.
    ///
    /// Without it, the interface can neither browse the catalog nor install: it SAYS so
    /// rather than show an empty list you would take for a catalog with no
    /// applications.
    #[arg(long, default_value = "catalog", env = "HLB_CATALOG")]
    pub catalog: std::path::PathBuf,

    /// Alert-rule evaluation interval, in seconds.
    #[arg(long, default_value = "60", env = "HLB_ALERTS_SECS")]
    pub alerts_secs: u64,

    /// VictoriaMetrics URL, for the interface's graphs.
    ///
    /// Without it, the metrics screens show "unavailable" while saying how to install it
    /// — rather than a flat curve you would take for an idle
    /// machine.
    #[arg(long, env = "HLB_METRICS_URL")]
    pub metrics_url: Option<String>,

    /// Reconciliation interval.
    #[arg(long, default_value = "60", env = "HLB_RECONCILE_SECS")]
    pub reconcile_secs: u64,

    /// Correct the detected gaps. Without this flag: detection only.
    #[arg(long, env = "HLB_RECONCILE_APPLY")]
    pub reconcile_apply: bool,

    /// Heartbeat file, to be placed OUTSIDE the cluster.
    #[arg(long, env = "HLB_HEARTBEAT")]
    pub heartbeat: Option<std::path::PathBuf>,

    #[arg(long, default_value = "30", env = "HLB_HEARTBEAT_SECS")]
    pub heartbeat_secs: u64,

    /// restic repository served when no destination is declared. The backup loop runs
    /// without it: the declared destinations are what decide.
    #[arg(long, env = "HLB_BACKUP_REPO")]
    pub backup_repo: Option<String>,

    #[arg(long, default_value = "hlb-master.key", env = "HLB_MASTER_KEY")]
    pub master_key: std::path::PathBuf,

    /// Git mirror of the desired state.
    #[arg(long, env = "HLB_GIT_MIRROR")]
    pub git_mirror: Option<std::path::PathBuf>,

    /// Name of the agents' Swarm service. The `tasks.<name>` DNS resolves to ALL the
    /// tasks, which allows polling each node individually.
    #[arg(long, default_value = "hlb-agent", env = "HLB_AGENT_SERVICE")]
    pub agent_service: String,

    #[arg(long, default_value = "8421", env = "HLB_AGENT_PORT")]
    pub agent_port: u16,

    /// The controller's CLIENT certificate (PEM: certificate + key). Enables mTLS.
    #[arg(long, env = "HLB_CONTROLLER_CERT")]
    pub controller_cert: Option<std::path::PathBuf>,

    /// The cluster CA: it, and it alone, validates the agents.
    #[arg(long, env = "HLB_CONTROLLER_CA")]
    pub controller_ca: Option<std::path::PathBuf>,

    /// How often the agents are polled.
    #[arg(long, default_value = "60", env = "HLB_AGENT_POLL_SECS")]
    pub agent_poll_secs: u64,

    /// How often the backup deadlines are examined.
    #[arg(long, default_value = "600", env = "HLB_BACKUP_CHECK_SECS")]
    pub backup_check_secs: u64,

    /// How often the manifests' assertions are read from the running apps. Once a day:
    /// a door reopened is seen by the next morning, and some reads open a database
    /// connection each.
    #[arg(long, default_value = "86400", env = "HLB_ASSERTIONS_SECS")]
    pub assertions_secs: u64,

    /// How often Stalwart's queue is read. A message waiting an hour is in the inbox
    /// within a quarter of one more.
    #[arg(long, default_value = "900", env = "HLB_MAIL_QUEUE_SECS")]
    pub mail_queue_secs: u64,

    /// How often the manifests' scheduled jobs are looked at; each runs when it is due
    /// (a day or a week after its last run), not at every look.
    #[arg(long, default_value = "3600", env = "HLB_JOBS_SECS")]
    pub jobs_secs: u64,

    /// How often PocketID's groups, the apps' restrictions, quotas and members are made
    /// to hold the roles again. Every change made here syncs at once; this catches what
    /// was changed elsewhere — a group edited in PocketID, a quota in Seafile.
    #[arg(long, default_value = "3600", env = "HLB_ROLES_SECS")]
    pub roles_secs: u64,

    /// How often the emergency vault's account is verified and every recovery sign-in
    /// deposited. Once a day: a password generated by an install reaches Vaultwarden by
    /// the next morning, and an account given too much is seen.
    #[arg(long, default_value = "86400", env = "HLB_EMERGENCY_SECS")]
    pub emergency_secs: u64,

    /// How often every node's Termix account and key, and Termix's hosts, are made to
    /// hold. Once a day: a node that joined appears in Termix by the next morning, one
    /// that left is gone from it, and an account changed by hand is put back.
    #[arg(long, default_value = "86400", env = "HLB_TERMIX_SECS")]
    pub termix_secs: u64,

    /// How often the backup destinations are looked at: each one proved more than a week
    /// ago is proved again — a policy changed since is seen —, and kept to the retention
    /// policy where it can be erased anyway.
    #[arg(long, default_value = "86400", env = "HLB_UPKEEP_SECS")]
    pub upkeep_secs: u64,

    /// How often every node's unused images are removed. Once a day: an update leaves
    /// its previous image on every node that ran it, on the root disk.
    #[arg(long, default_value = "86400", env = "HLB_PRUNE_SECS")]
    pub prune_secs: u64,

    /// How often the fleet's mTLS certificates are looked at, and those ending within
    /// 30 days issued again. Once a day leaves a month of retries before one ends.
    #[arg(long, default_value = "86400", env = "HLB_PKI_SECS")]
    pub pki_secs: u64,

    /// How often the expired temporary aliases are purged.
    ///
    /// ⚠️ One hour: an alias therefore survives at most one hour too long. Going lower
    /// would bring nothing — expiry is on the order of a day — and would multiply the
    /// calls to Stalwart.
    #[arg(long, default_value = "3600", env = "HLB_ALIAS_PURGE_SECS")]
    pub alias_purge_secs: u64,

    /// Default mail domain, for mailboxes that carry none.
    #[arg(long, env = "HLB_MAIL_DOMAIN")]
    pub mail_domain: Option<String>,

    #[arg(long, env = "HLB_STALWART_URL")]
    pub stalwart_url: Option<String>,

    #[arg(long, env = "HLB_STALWART_ADMIN")]
    pub stalwart_admin: Option<String>,

    #[arg(long, env = "HLB_STALWART_PASSWORD")]
    pub stalwart_password: Option<String>,
}

/// Why the daemon did not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    State(#[from] hlb_state::Error),
    #[error("{}: {source}", path.display())]
    Certificate {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Only one of the two mTLS files: refused rather than falling back to the clear
    /// while the operator believes they enabled mTLS.
    #[error("{0}")]
    Mtls(String),
}

/// A running daemon.
pub struct Started {
    pub state: Arc<State>,
    /// The door its own loops ask too.
    pub privd: Privd,
    /// Every loop, ending once the shutdown signal is sent.
    pub tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// What the loops that act through the install context share.
struct Held {
    state: Arc<State>,
    privd: Privd,
    install: Option<Arc<InstallContext>>,
    orchestrator: Option<Arc<dyn Orchestrator>>,
}

/// Opens the state and the vault, connects Docker and the admin clients, and starts
/// every loop. `measure` reads VictoriaMetrics for the alert rules, through the web
/// side's PromQL allowlist: a rule it refuses would read "unknown" forever.
pub async fn start(
    mut cfg: Config,
    measure: Option<Arc<dyn super::Measure>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<Started, StartError> {
    // Read before the state is opened, which creates it: the vault's key may be created
    // for a new installation only, never beside one that exists.
    let state_existed = cfg.state.exists();
    let state = Arc::new(State::open(&cfg.state).await?);
    // The one place the daemon may create the vault's key; everything after opens it,
    // so a key missing later is said rather than replaced.
    if let Err(e) = hlb_secrets::Vault::open_for_state(&cfg.master_key, state_existed) {
        tracing::error!("{e}");
    }

    // The platform's admin credentials live in the vault, generated at install: a flag
    // still wins, but none is needed for what Homelabus installed itself.
    let mut ntfy_account = None;
    if cfg.master_key.exists() {
        if let Ok(vault) = hlb_secrets::Vault::open(&cfg.master_key) {
            match hlb_engine::access::from_vault(&state, &vault).await {
                Ok(a) => {
                    ntfy_account = a.ntfy_publisher.clone();
                    if cfg.postgres_admin.is_none() {
                        cfg.postgres_admin = a.postgres_admin;
                    }
                    if cfg.mariadb_admin.is_none() {
                        cfg.mariadb_admin = a.mariadb_admin;
                    }
                    if let (None, None, Some((url, user, password))) =
                        (&cfg.stalwart_url, &cfg.stalwart_password, a.stalwart_admin)
                    {
                        cfg.stalwart_url = Some(url);
                        cfg.stalwart_admin = Some(user);
                        cfg.stalwart_password = Some(password);
                    }
                    if let (None, None, Some((url, key))) =
                        (&cfg.pocketid_url, &cfg.pocketid_key, a.pocketid)
                    {
                        cfg.pocketid_url = Some(url);
                        cfg.pocketid_key = Some(key);
                    }
                }
                Err(e) => tracing::warn!("platform credentials unreadable from the vault: {e}"),
            }
        }
    }

    // The mail domain recorded by `hlb config exposure`, unless a flag says otherwise.
    if cfg.mail_domain.is_none() {
        if let Ok(Some(e)) = state.exposure().await {
            cfg.mail_domain = Some(e.domain.clone());
        }
    }

    // The orchestrator can be absent at startup (Docker not ready yet). We report it
    // without refusing to start: reconciliation will retry.
    let orchestrator = match SwarmOrchestrator::connect().await {
        Ok(o) => Some(Arc::new(o)),
        Err(e) => {
            tracing::warn!("Docker unreachable at startup ({e}) — reconciliation suspended");
            None
        }
    };

    let mut tasks = Vec::new();
    // Written by the polling loop, read through `Intent::Fleet`.
    let last_poll: crate::fleet::Polled = Default::default();

    // With no ntfy configured, the alerts go to the logs rather than nowhere.
    let notif = cfg.ntfy_url.as_ref().map(|u| {
        tracing::info!(server = %u, subject = %cfg.ntfy_topic, "alerts ntfy active");
        let client = hlb_notify::NtfyClient::new(u, &cfg.ntfy_topic);
        // The catalog's ntfy refuses anyone without an account: without this one, every
        // alert would be a 403 in the log.
        Arc::new(match &ntfy_account {
            Some((user, password)) => client.signed_in_as(user, password),
            None => {
                tracing::warn!(
                    "no ntfy account in the vault: publishing anonymously, which the \
                     catalog's ntfy refuses"
                );
                client
            }
        })
    });
    if notif.is_none() {
        tracing::warn!("no ntfy configured: the alerts will stay in the logs");
    }
    let notif = super::Notifier::new(notif, state.clone());
    // What quiet hours held back, delivered once the installation's morning comes.
    {
        let notif = notif.clone();
        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(HELD_NOTIFICATIONS_SECS),
            shutdown_rx.clone(),
            move || {
                let notif = notif.clone();
                async move {
                    let f = notif.flush(crate::now()).await;
                    if f.sent > 0 {
                        tracing::info!(
                            sent = f.sent,
                            left = f.left,
                            "held notifications delivered"
                        );
                    }
                }
            },
        )));
    }

    // Cloned before the reconciliation loop consumes the value: the heartbeat needs its
    // own reference to CHECK that Docker answers before claiming all is well.
    //
    let orch_health = orchestrator.clone();
    // The gaps of the last pass, shared with the API: reconciliation's deliberate
    // non-actions used to come out only in the logs, that is to say
    // nowhere.
    let drift_state: super::DriftState = Default::default();
    // And a third reference for the API, which reads the Swarm tasks: the reconciliation
    // loop consumes the value right after.
    let orch_api = orchestrator
        .clone()
        .map(|o| o as Arc<dyn hlb_orchestrator::Orchestrator>);

    // Started at "now": the heartbeat grants the first pass its window, and no more.
    let reconciled: super::LastReconciled =
        Arc::new(std::sync::atomic::AtomicI64::new(crate::now()));
    if let Some(orch) = orchestrator {
        let rl = Arc::new(
            super::ReconcileLoop::new(orch, state.clone())
                .apply(cfg.reconcile_apply)
                .published_in(drift_state.clone())
                .reports_to(reconciled.clone()),
        );
        let rx = shutdown_rx.clone();
        let mirror = cfg.git_mirror.clone();
        let st = state.clone();
        tracing::info!(
            interval = cfg.reconcile_secs,
            correction = cfg.reconcile_apply,
            "reconciliation loop"
        );
        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(cfg.reconcile_secs),
            rx,
            move || {
                let (rl, mirror, st) = (rl.clone(), mirror.clone(), st.clone());
                async move {
                    let r = rl.tick().await;
                    // Each pass samples the exposed apps for the status page's history.
                    schedule::sample_uptime(&st).await;
                    if !r.is_clean() {
                        tracing::warn!(errors = r.errors.len(), "incomplete reconciliation");
                    } else if r.acted > 0 {
                        tracing::info!(corrected = r.acted, "gaps corrected");

                        // Will only produce a commit if the DESIRED state moved.
                        // A reconciliation that brings reality back into line changes
                        // nothing desired: its silence is intended.
                        if let Some(g) = &mirror {
                            if let Err(e) =
                                crate::mirror::export(g, &st, "correction by reconciliation").await
                            {
                                tracing::warn!("Git mirror not updated: {e}");
                            }
                        }
                    }
                }
            },
        )));
    }

    // 🔴 The purge of the temporary aliases. Without it, "temporary" is a lie: Stalwart
    // has no notion of expiry, and an address given "for thirty days" receives
    // indefinitely.
    {
        let mail = match (
            &cfg.stalwart_url,
            &cfg.stalwart_admin,
            &cfg.stalwart_password,
        ) {
            (Some(u), Some(a), Some(p)) => Some(Arc::new(hlb_mail::Stalwart::new(
                u,
                hlb_mail::Auth::Basic {
                    user: a.clone(),
                    password: p.clone(),
                },
            ))),
            _ => None,
        };
        if mail.is_none() {
            tracing::warn!(
                "Stalwart not configured: the expired temporary aliases will NOT be \
                 removed, and will keep receiving"
            );
        }

        let purge = Arc::new(super::AliasPurgeLoop::new(
            state.clone(),
            mail,
            cfg.mail_domain.clone().unwrap_or_else(|| "local".into()),
        ));
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(cfg.alias_purge_secs),
            rx,
            move || {
                let purge = purge.clone();
                async move {
                    let r = purge.tick().await;
                    if r.retires > 0 {
                        tracing::info!(retires = r.retires, "expired aliases removed");
                    }
                    // 🔴 We log on what stays OPEN, not on the error count: a purge
                    // with no error that removed nothing leaves as many doors open
                    // as a purge that failed loudly.
                    if !r.is_clean() {
                        tracing::error!(
                            open = r.still_open(),
                            errors = r.errors.len(),
                            "expired addresses still active"
                        );
                    }
                }
            },
        )));
    }

    // The status page's uptime history: samples are taken by the reconciliation loop
    // above (one per exposed app per tick, no new timer for that part); this is only
    // the retention side, pruning what has aged out of the 90-day window it keeps.
    // Once a day: at the sampling cadence, 90 days of history is small enough that
    // pruning does not need to be frequent.
    {
        let retention = Arc::new(schedule::UptimeRetentionLoop::new(state.clone(), 90));
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(86_400),
            rx,
            move || {
                let retention = retention.clone();
                async move {
                    match retention.tick().await {
                        Ok(removed) if removed > 0 => {
                            tracing::info!(removed, "uptime samples pruned");
                        }
                        Ok(_) => {}
                        Err(e) => tracing::warn!("uptime pruning failed this pass: {e}"),
                    }
                }
            },
        )));
    }

    // A guide's `recheck`: the prerequisites a person handled once — the DNS record, the
    // router — read again every night, and put back in the inbox when they stopped
    // being true. The catalog is the guides' source, as for `hlb ack`.
    {
        let st = state.clone();
        let rx = shutdown_rx.clone();
        let (catalog_dir, master_key) = (cfg.catalog.clone(), cfg.master_key.clone());
        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(86_400),
            rx,
            move || {
                let (st, catalog_dir, master_key) =
                    (st.clone(), catalog_dir.clone(), master_key.clone());
                async move {
                    let catalog = match hlb_catalog::Catalog::load(&catalog_dir) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("guide re-check skipped: unreadable catalog ({e})");
                            return;
                        }
                    };
                    let vault = hlb_secrets::Vault::open(&master_key).ok();
                    let guides = |app: &str| {
                        catalog
                            .get(app)
                            .map(|e| e.guide.steps.clone())
                            .unwrap_or_default()
                    };
                    match hlb_engine::recheck_guides(&st, vault.as_ref(), guides).await {
                        Ok(found) => {
                            for (app, id, r) in found {
                                match r {
                                    hlb_engine::Recheck::Reopened(why) => {
                                        tracing::error!(app, step = id, "🔴 no longer true: {why}")
                                    }
                                    hlb_engine::Recheck::Forced(why) => tracing::info!(
                                        app,
                                        step = id,
                                        "still false, kept as attested with --force: {why}"
                                    ),
                                    hlb_engine::Recheck::Holds
                                    | hlb_engine::Recheck::Unknown(_) => {}
                                }
                            }
                        }
                        Err(e) => tracing::warn!("guide re-check failed this pass: {e}"),
                    }
                }
            },
        )));
    }

    if let Some(path) = cfg.heartbeat.clone() {
        let hb = Arc::new(schedule::Heartbeat::new(path.clone()));
        let rx = shutdown_rx.clone();
        let st = state.clone();
        let orch = orch_health.clone();
        let (reconciled, reconcile_secs) = (reconciled.clone(), cfg.reconcile_secs);
        tracing::info!(file = %path.display(), "heartbeat (conditional)");

        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(cfg.heartbeat_secs),
            rx,
            move || {
                let hb = hb.clone();
                let st = st.clone();
                let orch = orch.clone();
                let reconciled = reconciled.clone();
                async move {
                    // 🔴 We CHECK before beating. An unconditional beat only proves a
                    // thread survived: the controller could have an unreadable database
                    // and a dead Docker, and leave the watchdog green over an unusable
                    // system.
                    let health = hlb_metrics::Health {
                        // A real query, not a flag: it is the read that fails when the
                        // disk is full or the database corrupted.
                        readable_state: st.installed_apps().await.is_ok(),
                        orchestrator_reachable: match &orch {
                            Some(o) => o.ping().await.is_ok(),
                            None => false,
                        },
                        // 🔴 Read from the reconciliation loop's own last pass: it is
                        // a task of its own, and one that died or hangs left this
                        // timer beating — the watchdog green over a cluster nobody
                        // reconciled.
                        recent_reconciliation: schedule::reconciled_recently(
                            reconciled.load(std::sync::atomic::Ordering::Relaxed),
                            crate::now(),
                            reconcile_secs,
                        ),
                    };

                    match hb.beat_if_healthy(&health).await {
                        Ok(true) => {}
                        Ok(false) => {} // already logged, with the shortcomings
                        Err(e) => tracing::error!("heartbeat impossible: {e}"),
                    }
                }
            },
        )));
    }

    // Git mirror initialised at startup: the repository must reflect the current state
    // even if nothing changes afterwards. Otherwise a stable cluster would leave no trace.
    if let Some(g) = &cfg.git_mirror {
        match crate::mirror::export(g, &state, "state at controller startup").await {
            Ok(()) => tracing::info!(mirror = %g.display(), "state archived in Git"),
            Err(e) => tracing::warn!("Git mirror unavailable: {e}"),
        }
    }

    // 🔴 The SAME pass as `hlb backup run`: every declared destination, the databases,
    // the SQLite files and Homelabus's own state. It starts without `--backup-repo`
    // too — the declared destinations are what decide, and an installation with none
    // hears about it on every pass rather than never. "Back up now" runs it too, held
    // to one app: the route once drove a provider of its own over `--backup-repo`.
    let pass_config = crate::backup::PassConfig {
        master_key: cfg.master_key.clone(),
        state_path: cfg.state.clone(),
        fallback_repo: cfg.backup_repo.clone(),
        network: cfg.platform_network.clone(),
        postgres_admin: cfg.postgres_admin.clone(),
        mariadb_admin: cfg.mariadb_admin.clone(),
    };
    {
        let bl = Arc::new(schedule::BackupLoop::new(
            state.clone(),
            hlb_backup::Schedule::default(),
        ));
        let st = state.clone();
        let rx = shutdown_rx.clone();
        let notif_bck = notif.clone();
        let config = pass_config.clone();
        tracing::info!("backup loop");

        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(cfg.backup_check_secs),
            rx,
            move || {
                let (bl, st, notif, config) =
                    (bl.clone(), st.clone(), notif_bck.clone(), config.clone());
                async move {
                    let mut failures = Vec::new();
                    let outcome = config
                        .run(&st, None, false, &mut |e| match e {
                            hlb_backup_run::Event::Done {
                                what, destination, ..
                            } => tracing::info!(%what, %destination, "backed up"),
                            hlb_backup_run::Event::Failed {
                                what,
                                destination,
                                error,
                            } => {
                                tracing::error!(%what, ?destination, "backup failed: {error}");
                                failures.push((what, destination, error));
                            }
                            hlb_backup_run::Event::NotCovered { what, why } => {
                                tracing::warn!(%what, "🔴 NOT backed up: {why}")
                            }
                        })
                        .await;
                    match outcome {
                        Ok(_) => {}
                        Err(hlb_backup_run::Error::Vault(e)) => {
                            tracing::error!("vault unreadable, nothing backed up: {e}");
                            return;
                        }
                        // Only the state database can still interrupt a pass: said like
                        // any failure, never a log line nobody reads.
                        Err(e) => {
                            tracing::error!("backup pass interrupted: {e}");
                            failures.push(("the backup pass".to_string(), None, e.to_string()));
                        }
                    }
                    // 🟠 Important, not critical: an isolated failure may be caught up
                    // on the next pass. What is critical is the DRIFT, just below.
                    for (what, destination, error) in failures {
                        let target = destination.unwrap_or_else(|| "-".into());
                        notif
                            .tell(&hlb_notify::Notification::important(
                                &format!("backup:{what}:{target}"),
                                &format!("Backup of {what} to {target} failed"),
                                &error,
                            ))
                            .await;
                    }

                    if let Ok(late) = bl.overdue_apps().await {
                        for app in late {
                            tracing::error!(app, "🔴 no successful backup for too long");
                            // 🔴 Critical: an app you believe backed up and that no
                            // longer is is the worst possible state.
                            notif
                                .tell(&hlb_notify::Notification::critical(
                                    &format!("overdue:{app}"),
                                    &format!("{app} is no longer backed up"),
                                    "No successful backup for too long.",
                                ))
                                .await;
                        }
                    }
                }
            },
        )));
    }

    // 🔴 The manifests' assertions, read by their EFFECT: a door the configuration
    // closes and someone — a restore, a `docker service update`, an app's own settings
    // page — reopened is in the inbox the next morning, and notified.
    {
        let reader = Arc::new(hlb_guide::assertions::LiveReader::new(
            orch_api.clone(),
            cfg.postgres_admin.clone(),
            cfg.mariadb_admin.clone(),
        ));
        // The mail records with them, judged from a public resolver: a DKIM key nobody
        // published files every mail as spam, and nothing in the house says so.
        let mail = match (
            &cfg.stalwart_url,
            &cfg.stalwart_admin,
            &cfg.stalwart_password,
        ) {
            (Some(u), Some(a), Some(p)) => Some(Arc::new(hlb_mail::Stalwart::new(
                u,
                hlb_mail::Auth::Basic {
                    user: a.clone(),
                    password: p.clone(),
                },
            ))),
            _ => None,
        };
        let dns = Arc::new(hlb_mail::public_dns::PublicDns::default());
        let internet = Arc::new(hlb_engine::domain::Public::default());
        let orch = orch_api.clone();
        let st = state.clone();
        let rx = shutdown_rx.clone();
        let notif_as = notif.clone();
        let master_key = cfg.master_key.clone();
        tracing::info!(interval = cfg.assertions_secs, "assertions loop");
        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(cfg.assertions_secs),
            rx,
            move || {
                let (reader, st, notif) = (reader.clone(), st.clone(), notif_as.clone());
                let (mail, dns, master_key) = (mail.clone(), dns.clone(), master_key.clone());
                let (internet, orch) = (internet.clone(), orch.clone());
                async move {
                    let now = crate::now();
                    // Opened at each pass, as the backup loop does: a key rotated by
                    // `hlb secrets-rekey` is read the next night.
                    let vault = hlb_secrets::Vault::open(&master_key).ok();
                    let pass = super::assertions::read_every_app(
                        &st,
                        vault.as_ref(),
                        reader.as_ref(),
                        now,
                    )
                    .await;
                    tracing::info!(
                        read = pass.read,
                        broken = pass.broken.len(),
                        unknown = pass.unknown,
                        "assertions read"
                    );
                    for door in pass.broken {
                        tracing::error!("🔴 {door}");
                        notif
                            .tell(&hlb_notify::Notification::critical(
                                &format!("assertion:{door}"),
                                "A running app does not hold what its manifest says",
                                &door,
                            ))
                            .await;
                    }
                    match super::domain::read_and_record(
                        &st,
                        internet.as_ref(),
                        orch.as_deref(),
                        mail.as_deref(),
                        now,
                    )
                    .await
                    {
                        Ok(found) => {
                            for a in found.refused {
                                let line = format!(
                                    "{}'s account {} is refused by the domain's CAA",
                                    a.who, a.uri
                                );
                                tracing::error!("🔴 {line}");
                                notif
                                    .tell(&hlb_notify::Notification::critical(
                                        &format!("caa:{}", a.who.to_lowercase()),
                                        "A certificate of the house will not renew: add \
                                         its account to the CAA",
                                        &line,
                                    ))
                                    .await;
                            }
                            for d in found.drifts {
                                let line =
                                    format!("{}: was {}, now {}", d.what.label(), d.was, d.now);
                                tracing::error!("🔴 domain {line}");
                                notif
                                    .tell(&hlb_notify::Notification::critical(
                                        // Keyed by what moved, so a second change of
                                        // the same thing is the same alert.
                                        &format!("domain:{}", d.what.key()),
                                        "The house's domain moved: if nobody here did \
                                         this, call the registrar now",
                                        &line,
                                    ))
                                    .await;
                            }
                        }
                        Err(e) => tracing::warn!("domain not read: {e}"),
                    }
                    let Some(mail) = mail else { return };
                    match super::mail_dns::read_and_record(&st, &mail, dns.as_ref(), now).await {
                        Ok(wrong) => {
                            for record in wrong {
                                tracing::error!("🔴 mail record {record}");
                                notif
                                    .tell(&hlb_notify::Notification::critical(
                                        // Keyed by the record, not by what was found.
                                        &format!(
                                            "mail-record:{}",
                                            record.split(' ').next().unwrap_or("")
                                        ),
                                        "A DNS record the house's mail needs is wrong",
                                        &record,
                                    ))
                                    .await;
                            }
                        }
                        Err(e) => tracing::warn!("mail records not read: {e}"),
                    }
                }
            },
        )));
    }

    // 🔴 Stalwart's queue: a message that cannot leave — port 25 closed, a relay
    // refusing it — is retried for three days while its sender believes it sent.
    {
        if let (Some(u), Some(a), Some(p)) = (
            &cfg.stalwart_url,
            &cfg.stalwart_admin,
            &cfg.stalwart_password,
        ) {
            let mail = Arc::new(hlb_mail::Stalwart::new(
                u,
                hlb_mail::Auth::Basic {
                    user: a.clone(),
                    password: p.clone(),
                },
            ));
            let st = state.clone();
            let rx = shutdown_rx.clone();
            let notif_mq = notif.clone();
            tracing::info!(interval = cfg.mail_queue_secs, "mail queue loop");
            tasks.push(tokio::spawn(schedule::every(
                Duration::from_secs(cfg.mail_queue_secs),
                rx,
                move || {
                    let (mail, st, notif) = (mail.clone(), st.clone(), notif_mq.clone());
                    async move {
                        let now = crate::now();
                        match super::mail_queue::read_and_record(&st, &mail, now).await {
                            Ok(pass) => {
                                if pass.cut {
                                    tracing::warn!(
                                        "Stalwart answered part of its queue: what is \
                                         late may be more than the inbox says"
                                    );
                                }
                                for (domain, line) in pass.newly_late {
                                    tracing::error!("🔴 mail waiting: {line}");
                                    notif
                                        .tell(&hlb_notify::Notification::important(
                                            &format!("mail-waiting:{domain}"),
                                            "Mail to another domain is not leaving",
                                            &line,
                                        ))
                                        .await;
                                }
                            }
                            Err(e) => tracing::warn!("mail queue not read: {e}"),
                        }
                    }
                },
            )));
        }
    }

    // The manifests' scheduled jobs, in each app's own container. A failure is
    // notified and stays in the inbox until a run succeeds.
    {
        if let Some(orch) = orch_api.clone() {
            let st = state.clone();
            let rx = shutdown_rx.clone();
            let notif_jobs = notif.clone();
            tracing::info!(interval = cfg.jobs_secs, "scheduled jobs loop");
            tasks.push(tokio::spawn(schedule::every(
                Duration::from_secs(cfg.jobs_secs),
                rx,
                move || {
                    let (orch, st, notif) = (orch.clone(), st.clone(), notif_jobs.clone());
                    async move {
                        let now = crate::now();
                        let pass = hlb_engine::jobs::run_due(orch.as_ref(), &st, now).await;
                        if pass.ran > 0 {
                            tracing::info!(ran = pass.ran, failed = pass.failed.len(), "jobs run");
                        }
                        for failed in pass.failed {
                            tracing::error!("🔴 job {failed}");
                            notif
                                .tell(&hlb_notify::Notification::important(
                                    // Keyed by the job, not by what it printed.
                                    &format!("job:{}", failed.split(':').next().unwrap_or("")),
                                    "A scheduled job of an app failed",
                                    &failed,
                                ))
                                .await;
                        }
                    }
                },
            )));
        }
    }

    // The outcome of each image update `hlb update apply` recorded, success included.
    {
        let st = state.clone();
        let rx = shutdown_rx.clone();
        let notif_updates = notif.clone();
        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(60),
            rx,
            move || {
                let (st, notif) = (st.clone(), notif_updates.clone());
                async move {
                    let now = crate::now();
                    super::notify::notify_update_runs(&st, &notif, now).await;
                }
            },
        )));
    }

    // Agent polling: this is what gives the per-node view of disk space, which
    // the controller cannot obtain otherwise.
    {
        // 🔴 mTLS as soon as both files are there. In the clear, any container on the
        // overlay can map the fleet's disks.
        let poller = match (&cfg.controller_cert, &cfg.controller_ca) {
            (Some(c), Some(a)) => {
                let (cert, ca) = (read_pem(c).await?, read_pem(a).await?);
                match crate::fleet::AgentPoller::with_mtls(
                    cfg.agent_port,
                    Duration::from_secs(10),
                    &cert,
                    &ca,
                    &format!("tasks.{}", cfg.agent_service),
                ) {
                    Ok(p) => {
                        tracing::info!("polling the agents over mTLS");
                        Arc::new(p)
                    }
                    Err(e) => return Err(StartError::Mtls(e)),
                }
            }
            (None, None) => {
                tracing::error!(
                    "🔴 agents polled over PLAIN HTTP — supply --controller-cert \
                     and --controller-ca"
                );
                Arc::new(crate::fleet::AgentPoller::new(
                    cfg.agent_port,
                    Duration::from_secs(10),
                ))
            }
            // Only one of the two: refuse rather than fall back to the clear while the
            // operator believes they enabled mTLS.
            _ => {
                return Err(StartError::Mtls(
                    "incomplete mTLS configuration: --controller-cert AND --controller-ca \
                     are required together"
                        .into(),
                ))
            }
        };
        let service = cfg.agent_service.clone();
        let rx = shutdown_rx.clone();
        let latest = last_poll.clone();
        let notif_ag = notif.clone();
        tracing::info!(service = %service, "agent polling loop");

        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(cfg.agent_poll_secs),
            rx,
            move || {
                let (poller, service, latest, notif) = (
                    poller.clone(),
                    service.clone(),
                    latest.clone(),
                    notif_ag.clone(),
                );
                async move {
                    // `tasks.<service>` resolves to every task; a VIP
                    // classic one would give only one at random.
                    let addresses = match crate::fleet::resolve_tasks(&service).await {
                        Ok(a) if !a.is_empty() => a,
                        Ok(_) => {
                            tracing::debug!("no agent deployed");
                            return;
                        }
                        Err(e) => {
                            tracing::debug!("agents not resolved: {e}");
                            return;
                        }
                    };

                    let statuses = poller.poll_all(&addresses).await;
                    // Published for `/metrics` before any analysis: even a pass where
                    // everything is wrong must be visible in supervision.
                    *latest.write().await = statuses.clone();

                    let health = crate::fleet::ClusterHealth::from_statuses(
                        &statuses,
                        &hlb_agent::Thresholds::default(),
                    );

                    for (addr, s) in &statuses {
                        if let crate::fleet::AgentStatus::Reporting(r) = s {
                            for (d, p) in r.problems(&hlb_agent::Thresholds::default()) {
                                tracing::warn!(
                                    node = %r.hostname, path = %d.path,
                                    "{:.0} % used — {}", d.used_percent(), p.describe()
                                );
                            }
                        } else {
                            tracing::warn!(address = %addr, "agent unreachable");
                        }
                    }

                    if health.needs_attention() {
                        tracing::error!(
                            unreachable = health.unreachable,
                            saturated = ?health.saturated,
                            "🔴 cluster to watch"
                        );
                        // A full disk stops the databases; a mute node can mean its data
                        // is no longer being backed up. Both deserve waking someone up.
                        //
                        notif
                            .tell(&hlb_notify::Notification::critical(
                                "cluster",
                                "Cluster to watch",
                                &format!(
                                    "{} unreachable, saturated: {}",
                                    health.unreachable,
                                    if health.saturated.is_empty() {
                                        "none".to_string()
                                    } else {
                                        health.saturated.join(", ")
                                    }
                                ),
                            ))
                            .await;
                    }
                }
            },
        )));
    }

    let alerts_state: super::AlertsState = Default::default();
    match measure {
        Some(m) => {
            let loop_body = Arc::new(super::AlertLoop::new(m, notif.clone(), state.clone()));
            // The loop and the API share the SAME structure: the API reads what the
            // loop has just written, with no copy and no extra synchronisation.
            let shared = loop_body.active.clone();
            let to_api = alerts_state.clone();
            let interval = Duration::from_secs(cfg.alerts_secs);
            tasks.push(tokio::spawn(schedule::every(
                interval,
                shutdown_rx.clone(),
                move || {
                    let (b, shared, to_api) = (loop_body.clone(), shared.clone(), to_api.clone());
                    async move {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        let r = b.tick(now).await;
                        *to_api.write().await = shared.read().await.clone();

                        if r.triggered > 0 || r.unknowns > 0 {
                            tracing::info!(
                                evaluated = r.evaluated,
                                triggered = r.triggered,
                                // Counted separately: "zero fired" with ten unknowns
                                // is NOT "all is well".
                                unknowns = r.unknowns,
                                "alert evaluation"
                            );
                        }
                    }
                },
            )));
        }
        None => tracing::info!(
            "no time-series database (--metrics-url): the alert rules are not evaluated"
        ),
    }

    // 🔴 Assembled at startup, once. An install triggered from the interface then runs
    // the SAME executor as `hlb install` — the alternative would have been to shell out
    // to the CLI, which recomputes the plan instead of replaying it, and would execute
    // something other than what was previewed.
    let vault = hlb_secrets::Vault::open(&cfg.master_key);
    let install = match vault {
        Ok(vault) => {
            let postgres = match &cfg.postgres_admin {
                Some(url) => match hlb_platform::PostgresProvisioner::connect(url).await {
                    Ok(p) => Some(p),
                    Err(e) => {
                        tracing::warn!("PostgreSQL unreachable ({e}): databases NOT provisioned");
                        None
                    }
                },
                None => None,
            };
            let mariadb = match &cfg.mariadb_admin {
                Some(url) => match hlb_platform::MariadbProvisioner::connect(url).await {
                    Ok(m) => Some(m),
                    Err(e) => {
                        tracing::warn!("MariaDB unreachable ({e}): databases NOT provisioned");
                        None
                    }
                },
                None => None,
            };
            Some(Arc::new(crate::InstallContext {
                vault,
                registry: hlb_registry::RegistryClient::new(),
                postgres,
                mariadb,
                storage: hlb_engine::StorageConfig {
                    local_root: cfg.storage_root.clone(),
                    nfs_server: cfg.nfs_server.clone(),
                    nfs_export: cfg.nfs_export.clone(),
                },
                api: hlb_guide::HttpApi::default(),
            }))
        }
        Err(e) => {
            // Not fatal: everything that does not install keeps working. But say it
            // loudly — an install attempted from the interface will refuse, and the
            // reason must already be in the logs.
            tracing::error!("vault unreadable ({e}): installing from the interface is disabled");
            None
        }
    };

    // Account provisioning. Without these two, sign-up records an account and
    // nothing else — the state is named `Empty` and a re-run from the command line
    // finishes it.
    let identity = match (&cfg.pocketid_url, &cfg.pocketid_key) {
        (Some(u), Some(k)) => {
            tracing::info!(url = %u, "PocketID configured: the identities will be created");
            Some(Arc::new(hlb_identity::PocketId::new(u, k)))
        }
        (Some(_), None) => {
            tracing::warn!(
                "--pocketid-url without --pocketid-key: the identities will NOT be created"
            );
            None
        }
        _ => {
            tracing::info!(
                "PocketID not configured: sign-up will leave the accounts without an identity"
            );
            None
        }
    };
    let mail = match (
        &cfg.stalwart_url,
        &cfg.stalwart_admin,
        &cfg.stalwart_password,
    ) {
        (Some(u), Some(a), Some(p)) => Some(Arc::new(hlb_mail::Stalwart::new(
            u,
            hlb_mail::Auth::Basic {
                user: a.clone(),
                password: p.clone(),
            },
        ))),
        _ => None,
    };
    let mail_domain = cfg.mail_domain.clone().unwrap_or_else(|| "local".into());
    // ⚠️ Loaded once at startup. An unreadable catalog must not stop the controller
    // from starting: the rest of the API keeps all its value, and the message says
    // what is missing.
    let catalog = match hlb_catalog::Catalog::load(&cfg.catalog) {
        Ok(c) => {
            tracing::info!(apps = c.len(), directory = %cfg.catalog.display(), "catalog loaded");
            Some(Arc::new(c))
        }
        Err(e) => {
            tracing::warn!(
                directory = %cfg.catalog.display(),
                "unreadable catalog ({e}) — installing from the interface will be unavailable"
            );
            None
        }
    };
    let backup = Some(Arc::new(pass_config) as Arc<dyn crate::backup::BackUpNow>);
    // 🔴 The capabilities go to the privileged side, and to the daemon's own loops
    // below: the web side's `AppState` holds none of them, only the door.
    let privd = Privd::new(state.clone())
        .with_orchestrator(orch_api.clone())
        .with_catalog(catalog.clone())
        .with_install(install.clone())
        .with_identity(identity)
        .with_mail(mail, &mail_domain)
        .with_backup(backup)
        .with_published(alerts_state, drift_state)
        .with_mirror(cfg.git_mirror.clone())
        .with_fleet(last_poll.clone());
    let held = Arc::new(Held {
        state: state.clone(),
        privd: privd.clone(),
        install,
        orchestrator: orch_api,
    });

    // 🔴 The roles, made true where they are read. A group edited by hand in PocketID,
    // a client's restriction lifted, a quota changed in Seafile: put back, and a
    // failure notified — a door the roles say is closed must not stay open quietly.
    {
        let held = held.clone();
        let notif_roles = notif.clone();
        tracing::info!(interval = cfg.roles_secs, "roles loop");
        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(cfg.roles_secs),
            shutdown_rx.clone(),
            move || {
                let (held, notif) = (held.clone(), notif_roles.clone());
                async move {
                    match held.privd.sync_roles(true).await {
                        Ok(r) => {
                            let failed: Vec<String> = r
                                .lines
                                .iter()
                                .filter_map(|l| match &l.outcome {
                                    hlb_engine::roles::Outcome::Failed(e) => {
                                        Some(format!("{} — {}: {e}", l.subject, l.change))
                                    }
                                    _ => None,
                                })
                                .collect();
                            tracing::info!(
                                changed = r.lines.len(),
                                unchanged = r.unchanged,
                                failed = failed.len(),
                                "roles synced"
                            );
                            if !failed.is_empty() {
                                notif
                                    .tell(&hlb_notify::Notification::critical(
                                        "roles-sync",
                                        "PocketID or an app does not hold the roles",
                                        &failed.join("\n"),
                                    ))
                                    .await;
                            }
                        }
                        Err(e) => tracing::warn!("roles not synced: {e}"),
                    }
                }
            },
        )));
    }

    // 🔴 The emergency vault: its account verified, every recovery sign-in deposited.
    // An account that no longer verifies withdraws the safeguard at once and is
    // notified; one never set up stays in the inbox as a safeguard never proved.
    {
        let held = held.clone();
        let notif_vault = notif.clone();
        tracing::info!(interval = cfg.emergency_secs, "emergency vault loop");
        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(cfg.emergency_secs),
            shutdown_rx.clone(),
            move || {
                let held = held.clone();
                let notif = notif_vault.clone();
                async move {
                    let Some(install) = &held.install else {
                        return;
                    };
                    let reach = |u: &str| u.to_string();
                    let run = hlb_engine::emergency::EmergencyVault {
                        state: &held.state,
                        vault: &install.vault,
                        reach: &reach,
                        now: crate::now(),
                    }
                    .run(None, true)
                    .await;
                    let r = match run {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("emergency vault not run: {e}");
                            return;
                        }
                    };
                    let mut wrong: Vec<String> = r
                        .checks
                        .iter()
                        .filter_map(|c| match &c.verdict {
                            hlb_bitwarden::emergency::Verdict::Wrong(w) => {
                                Some(format!("{}: {w}", c.what))
                            }
                            _ => None,
                        })
                        .collect();
                    wrong.extend(r.lines.iter().filter_map(|l| match &l.outcome {
                        hlb_engine::roles::Outcome::Failed(e) => {
                            Some(format!("{} — {}: {e}", l.subject, l.change))
                        }
                        _ => None,
                    }));
                    tracing::info!(
                        verified = r.verified(),
                        written = r.lines.len(),
                        unchanged = r.unchanged,
                        failed = wrong.len(),
                        "emergency vault"
                    );
                    if !wrong.is_empty() {
                        notif
                            .tell(&hlb_notify::Notification::critical(
                                "emergency-vault",
                                "The emergency vault does not hold the recovery sign-ins",
                                &wrong.join("\n"),
                            ))
                            .await;
                    } else if let Some(why) = &r.stopped {
                        tracing::info!("emergency vault: {why}");
                    }
                }
            },
        )));
    }

    // 🔴 The destinations, proved again every week, and kept to the retention policy
    // where they can be erased anyway: without it every repository only grew, until the
    // disk the databases share was full. A failure, or a destination found erasable
    // that was not, is notified.
    {
        let held = held.clone();
        let notif_upkeep = notif.clone();
        let network = cfg.platform_network.clone();
        tracing::info!(interval = cfg.upkeep_secs, "destinations upkeep loop");
        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(cfg.upkeep_secs),
            shutdown_rx.clone(),
            move || {
                let held = held.clone();
                let (notif, network) = (notif_upkeep.clone(), network.clone());
                async move {
                    let Some(install) = &held.install else {
                        return;
                    };
                    let reach = |u: &str| u.to_string();
                    let lines = match hlb_backup_run::upkeep::run(
                        &held.state,
                        &install.vault,
                        &network,
                        &reach,
                        &hlb_backup::RetentionPolicy::default(),
                        crate::now(),
                    )
                    .await
                    {
                        Ok(l) => l,
                        Err(e) => {
                            tracing::warn!("destinations not looked at: {e}");
                            return;
                        }
                    };
                    let mut said = Vec::new();
                    for l in &lines {
                        tracing::info!(
                            destination = %l.destination,
                            proof = l.proof.verdict(),
                            retention = ?l.retention,
                            "destination upkeep"
                        );
                        let _ = held
                            .state
                            .audit(
                                "controller",
                                hlb_types::Role::Admin,
                                "backup-dest-prove",
                                &l.destination,
                                l.proof.verdict(),
                                Some(l.proof.detail()),
                            )
                            .await;
                        if let hlb_backup_run::upkeep::Retention::Failed(why) = &l.retention {
                            said.push(format!("{}: the retention failed — {why}", l.destination));
                        }
                        if let hlb_backup::erasure::Erasure::Unproven { why } = &l.proof {
                            said.push(format!("{}: not proven — {why}", l.destination));
                        }
                    }
                    if !said.is_empty() {
                        notif
                            .tell(&hlb_notify::Notification::important(
                                "destinations-upkeep",
                                "A backup destination could not be proved or pruned",
                                &said.join("\n"),
                            ))
                            .await;
                    }
                }
            },
        )));
    }

    // The nodes in Termix: each node's account and key, a host per node, its shares. A
    // failure is notified — a node Termix can no longer open is found the day it is
    // needed otherwise. Not set up yet (no API key handed over) stays quiet: the guide
    // says what to do.
    {
        let held = held.clone();
        let notif_termix = notif.clone();
        tracing::info!(interval = cfg.termix_secs, "termix loop");
        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(cfg.termix_secs),
            shutdown_rx.clone(),
            move || {
                let held = held.clone();
                let notif = notif_termix.clone();
                async move {
                    let (Some(install), Some(orch)) = (&held.install, &held.orchestrator) else {
                        return;
                    };
                    let reach = |u: &str| u.to_string();
                    let run = hlb_engine::termix::NodeAccess {
                        state: &held.state,
                        vault: &install.vault,
                        orchestrator: orch.as_ref(),
                        reach: &reach,
                    }
                    .run(true)
                    .await;
                    let r = match run {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("termix not synced: {e}");
                            return;
                        }
                    };
                    let failed: Vec<String> = r
                        .lines
                        .iter()
                        .filter_map(|l| match &l.outcome {
                            hlb_engine::roles::Outcome::Failed(e)
                            | hlb_engine::roles::Outcome::NotConfigured(e) => {
                                Some(format!("{} — {}: {e}", l.subject, l.change))
                            }
                            _ => None,
                        })
                        .collect();
                    tracing::info!(
                        changed = r.lines.len(),
                        unchanged = r.unchanged,
                        failed = failed.len(),
                        "termix synced"
                    );
                    if !failed.is_empty() {
                        notif
                            .tell(&hlb_notify::Notification::critical(
                                "termix-nodes",
                                "Termix cannot open every node",
                                &failed.join("\n"),
                            ))
                            .await;
                    } else if let Some(why) = &r.stopped {
                        tracing::info!("termix: {why}");
                    }
                }
            },
        )));
    }

    // The images every update leaves behind, on every node. A failure is notified: the
    // disk it would have freed is the one the journal and Docker's state live on.
    {
        let held = held.clone();
        let notif_prune = notif.clone();
        tracing::info!(interval = cfg.prune_secs, "image prune loop");
        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(cfg.prune_secs),
            shutdown_rx.clone(),
            move || {
                let held = held.clone();
                let notif = notif_prune.clone();
                async move {
                    let Some(orch) = &held.orchestrator else {
                        return;
                    };
                    let report = match hlb_engine::prune::run(orch.as_ref(), true).await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("images not pruned: {e}");
                            return;
                        }
                    };
                    let mut failed = Vec::new();
                    for (node, outcome) in &report {
                        match outcome {
                            hlb_engine::prune::Outcome::Freed(size) => {
                                tracing::info!(node = %node, freed = %size, "images pruned")
                            }
                            hlb_engine::prune::Outcome::Failed(why) => {
                                failed.push(format!("{node}: {why}"))
                            }
                            hlb_engine::prune::Outcome::ToDo
                            | hlb_engine::prune::Outcome::Waiting(_) => {}
                        }
                    }
                    if !failed.is_empty() {
                        notif
                            .tell(&hlb_notify::Notification::important(
                                "image-prune",
                                "Unused images were not removed everywhere",
                                &failed.join("\n"),
                            ))
                            .await;
                    }
                }
            },
        )));
    }

    // 🔴 The fleet's mTLS leaves end after 90 days, and on that morning every agent
    // refuses the controller: renewed here a month before, handed to their services
    // under the update policy. A failure, or a leaf still ending after the pass, is
    // notified every day; the inbox says it too (`certificate_expiring`).
    {
        if let (Some(own), Some(_)) = (cfg.controller_cert.clone(), &cfg.controller_ca) {
            let held = held.clone();
            let notif_pki = notif.clone();
            let agent_service = cfg.agent_service.clone();
            tracing::info!(interval = cfg.pki_secs, "certificate renewal loop");
            tasks.push(tokio::spawn(schedule::every(
                Duration::from_secs(cfg.pki_secs),
                shutdown_rx.clone(),
                move || {
                    let held = held.clone();
                    let (notif, own, agent_service) =
                        (notif_pki.clone(), own.clone(), agent_service.clone());
                    async move {
                        use hlb_engine::pki;
                        let (Some(install), Some(orch)) = (&held.install, &held.orchestrator)
                        else {
                            return;
                        };
                        let now = crate::now();
                        // What this process was started with, whatever the state says:
                        // after a rollback it is the old leaf.
                        let observed = match tokio::fs::read_to_string(&own)
                            .await
                            .map_err(|e| e.to_string())
                            .and_then(|pem| {
                                hlb_agent::pki::not_after(&pem).map_err(|e| e.to_string())
                            }) {
                            Ok(t) => vec![(pki::DAEMON_SERVICE.to_string(), t)],
                            Err(e) => {
                                tracing::warn!("own certificate unreadable: {e}");
                                Vec::new()
                            }
                        };
                        let run = pki::Renewal {
                            state: &held.state,
                            vault: &install.vault,
                            orchestrator: orch.as_ref(),
                            agent_service: &agent_service,
                            now,
                            observed,
                            inside: Some(pki::DAEMON_SERVICE),
                        }
                        .run(true)
                        .await;
                        let mut said = Vec::new();
                        match run {
                            Ok(lines) => {
                                for l in lines {
                                    match l.outcome {
                                        pki::Outcome::Renewed { not_after } => tracing::info!(
                                            service = %l.service,
                                            ends = %pki::date(not_after),
                                            "certificate renewed"
                                        ),
                                        pki::Outcome::Failed(why) => {
                                            said.push(format!("{}: not renewed — {why}", l.service))
                                        }
                                        pki::Outcome::Fine
                                        | pki::Outcome::Absent
                                        | pki::Outcome::WouldRenew => {}
                                    }
                                }
                            }
                            Err(e) => said.push(format!("the renewal did not run: {e}")),
                        }
                        // Still ending after the pass: renewing failed, or nothing here
                        // can renew it.
                        if let Ok(known) = held.state.leaf_expiries().await {
                            for (service, t) in pki::ending(&known, now) {
                                said.push(format!(
                                    "{service}: ends {} ({} days left)",
                                    pki::date(t),
                                    pki::days_left(t, now)
                                ));
                            }
                        }
                        if !said.is_empty() {
                            said.push("hlb pki renew --apply".into());
                            tracing::error!("🔴 {}", said.join("; "));
                            notif
                                .tell(&hlb_notify::Notification::critical(
                                    "pki-renewal",
                                    "An mTLS certificate of the fleet is not renewed",
                                    &said.join("\n"),
                                ))
                                .await;
                        }
                    }
                },
            )));
        }
    }

    Ok(Started {
        state,
        privd,
        tasks,
    })
}

async fn read_pem(path: &std::path::Path) -> Result<String, StartError> {
    tokio::fs::read_to_string(path)
        .await
        .map_err(|source| StartError::Certificate {
            path: path.to_path_buf(),
            source,
        })
}
