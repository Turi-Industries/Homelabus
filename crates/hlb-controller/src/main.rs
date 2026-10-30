//! `hlb-controller` — the daemon.
//!
//! Three responsibilities: serving the read API, running the background loops, and
//! beating the heart the NAS watches.
//!
//! 🟢 **An important property**: the controller is NOT in the critical path of
//! traffic. Swarm keeps running the deployed services without it. Stopping it loses the
//! steering, not the service — which makes its updates and restarts far less delicate.
//!

use hlb_controller::{agents, api, loops, signin};

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use hlb_orchestrator::{Orchestrator, SwarmOrchestrator};
use hlb_state::State;

/// How often the notifications quiet hours held are looked at: within five minutes of
/// the morning, and a pass is one read of a table that is usually empty.
const HELD_NOTIFICATIONS_SECS: u64 = 300;

#[derive(Parser)]
#[command(name = "hlb-controller", version, about = "Homelabus daemon")]
struct Cli {
    /// The API's listen address.
    #[arg(long, default_value = "127.0.0.1:8420", env = "HLB_LISTEN")]
    listen: String,

    #[arg(long, default_value = "hlb.db", env = "HLB_STATE")]
    state: std::path::PathBuf,

    /// ntfy server for the alerts. Without one, they stay in the logs.
    #[arg(long, env = "HLB_NTFY_URL")]
    ntfy_url: Option<String>,

    #[arg(long, default_value = "homelab", env = "HLB_NTFY_TOPIC")]
    ntfy_topic: String,

    /// PostgreSQL admin URL. Without it, the databases are NOT dumped.
    #[arg(long, env = "HLB_POSTGRES_ADMIN", conflicts_with = "demo")]
    postgres_admin: Option<String>,

    /// MariaDB admin URL. Without it, the apps that need MariaDB are installed with
    /// their database recorded as unimplemented rather than silently skipped.
    #[arg(long, env = "HLB_MARIADB_ADMIN", conflicts_with = "demo")]
    mariadb_admin: Option<String>,

    /// Root under which `tier: local` volumes are bound, e.g. `/tank/apps`.
    #[arg(long, env = "HLB_STORAGE_ROOT")]
    storage_root: Option<String>,

    /// NFS server for the `tier: nfs` volumes. 🔴 Without it, installing an app that
    /// declares one is refused rather than silently given a local volume.
    #[arg(long, env = "HLB_NFS_SERVER")]
    nfs_server: Option<String>,

    /// The exported root on that server, e.g. `/tank/media`.
    #[arg(long, env = "HLB_NFS_EXPORT")]
    nfs_export: Option<String>,

    /// Docker network where the platform services are reachable by name.
    #[arg(long, default_value = "hlb_platform", env = "HLB_PLATFORM_NETWORK")]
    platform_network: String,

    /// Directory of the web UI. Absent: API only.
    ///
    /// Served by the controller itself, so reachable at the same address as the API —
    /// which is what lets you open the dashboard from a phone without
    /// installing anything on it.
    #[arg(long, env = "HLB_UI_DIR")]
    ui_dir: Option<std::path::PathBuf>,

    /// OIDC issuer for signing people in (PocketID).
    ///
    /// Without it, only API tokens authenticate: enough for the CLI and for a
    /// single-administrator install, not enough as soon as you open access up.
    #[arg(long, env = "HLB_OIDC_ISSUER")]
    oidc_issuer: Option<String>,

    #[arg(long, env = "HLB_OIDC_CLIENT_ID", default_value = "homelabus")]
    oidc_client_id: String,

    /// ⚠️ Through an environment variable preferably: a secret passed as a command
    /// argument is visible to the whole system through `ps`.
    #[arg(long, env = "HLB_OIDC_CLIENT_SECRET", hide_env_values = true)]
    oidc_client_secret: Option<String>,

    /// The controller's public URL, as the browser sees it.
    ///
    /// 🔴 It serves two things that fail silently if it is wrong: the OIDC callback URI
    /// (which PocketID compares byte for byte) and the cookie's `Secure` attribute
    /// (which, set over `http://`, stops the cookie existing without the slightest
    /// message).
    #[arg(long, env = "HLB_PUBLIC_URL")]
    public_url: Option<String>,

    /// PocketID URL, to create the identities from the interface.
    #[arg(long, env = "HLB_POCKETID_URL", conflicts_with = "demo")]
    pocketid_url: Option<String>,

    /// PocketID API key.
    ///
    /// ⚠️ Through an environment variable preferably: a key passed as a command argument
    /// is visible to the whole system through `ps`.
    #[arg(long, env = "HLB_POCKETID_KEY", hide_env_values = true)]
    pocketid_key: Option<String>,

    /// 🔴 Publish the status page, WITHOUT authentication.
    ///
    /// It then reveals the list of your exposed services and your open incidents. For a
    /// commercial service that is a transparency commitment; for a homelab it is free
    /// reconnaissance. Hence the closed default.
    #[arg(long, env = "HLB_PUBLIC_STATUS")]
    public_status: bool,

    /// Application catalog directory.
    ///
    /// Without it, the interface can neither browse the catalog nor install: it SAYS so
    /// rather than show an empty list you would take for a catalog with no
    /// applications.
    #[arg(long, default_value = "catalog", env = "HLB_CATALOG")]
    catalog: std::path::PathBuf,

    /// Directory of themes this installation declares, one YAML file each.
    ///
    /// Absent by default and absent without complaint: most installations use the three
    /// shipped themes and never create this directory.
    #[arg(long, default_value = "themes", env = "HLB_THEMES")]
    themes: std::path::PathBuf,

    /// Alert-rule evaluation interval, in seconds.
    #[arg(long, default_value = "60", env = "HLB_ALERTS_SECS")]
    alerts_secs: u64,

    /// VictoriaMetrics URL, for the interface's graphs.
    ///
    /// Without it, the metrics screens show "unavailable" while saying how to install it
    /// — rather than a flat curve you would take for an idle
    /// machine.
    #[arg(long, env = "HLB_METRICS_URL")]
    metrics_url: Option<String>,

    /// Start with demonstration data, in memory, without Docker.
    ///
    /// 🔴 The `--state` path is IGNORED: nothing is read or written on disk. It is said
    /// at startup, to avoid the misunderstanding of believing you lost your data. So is
    /// `--master-key`: the vault is a key held in memory, or an install from a demo
    /// started at the repository root decrypts with the real one. And every flag
    /// reaching a real system (a repository, a database, a mirror, PocketID, Stalwart)
    /// is REFUSED beside it — fictional apps would be backed up, provisioned or
    /// exported there.
    ///
    /// Used to develop the interface: the cases you need to see — an app never backed
    /// up, a dead off-site, an expired alias still receiving — are the ones
    /// you never have to hand.
    #[arg(long)]
    demo: bool,

    /// How much the demonstration holds: `large` adds 1,000 accounts, 300 invitations,
    /// 5,000 audit entries and 8 machines — what a list has to survive.
    #[arg(long, value_enum, default_value_t, requires = "demo")]
    demo_scale: hlb_controller::demo::Scale,

    /// 🔴 Believe the `X-Forwarded-For` header to identify the client.
    ///
    /// Set this ONLY if a trusted proxy (Caddy) really is in front. Without it, every
    /// attacker would give themselves a fresh rate counter on every request: the limit
    /// would limit nothing, while giving the impression of the opposite.
    #[arg(long, env = "HLB_TRUSTED_PROXY")]
    trusted_proxy: bool,

    /// 🔴 Serve the API WITHOUT authentication.
    ///
    /// The controller refuses to start if no token exists and this flag is not set: an
    /// open API must be a DECISION, never the default state of a deployment you believed
    /// protected.
    #[arg(long, env = "HLB_INSECURE_NO_AUTH")]
    insecure_no_auth: bool,

    /// Reconciliation interval.
    #[arg(long, default_value = "60", env = "HLB_RECONCILE_SECS")]
    reconcile_secs: u64,

    /// Correct the detected gaps. Without this flag: detection only.
    #[arg(long, env = "HLB_RECONCILE_APPLY")]
    reconcile_apply: bool,

    /// Heartbeat file, to be placed OUTSIDE the cluster.
    #[arg(long, env = "HLB_HEARTBEAT", conflicts_with = "demo")]
    heartbeat: Option<std::path::PathBuf>,

    #[arg(long, default_value = "30", env = "HLB_HEARTBEAT_SECS")]
    heartbeat_secs: u64,

    /// restic repository served when no destination is declared. The backup loop runs
    /// without it: the declared destinations are what decide.
    #[arg(long, env = "HLB_BACKUP_REPO", conflicts_with = "demo")]
    backup_repo: Option<String>,

    #[arg(long, default_value = "hlb-master.key", env = "HLB_MASTER_KEY")]
    master_key: std::path::PathBuf,

    /// Git mirror of the desired state.
    #[arg(long, env = "HLB_GIT_MIRROR", conflicts_with = "demo")]
    git_mirror: Option<std::path::PathBuf>,

    /// Name of the agents' Swarm service. The `tasks.<name>` DNS resolves to ALL the
    /// tasks, which allows polling each node individually.
    #[arg(long, default_value = "hlb-agent", env = "HLB_AGENT_SERVICE")]
    agent_service: String,

    #[arg(long, default_value = "8421", env = "HLB_AGENT_PORT")]
    agent_port: u16,

    /// The controller's CLIENT certificate (PEM: certificate + key). Enables mTLS.
    #[arg(long, env = "HLB_CONTROLLER_CERT")]
    controller_cert: Option<std::path::PathBuf>,

    /// The cluster CA: it, and it alone, validates the agents.
    #[arg(long, env = "HLB_CONTROLLER_CA")]
    controller_ca: Option<std::path::PathBuf>,

    /// How often the agents are polled.
    #[arg(long, default_value = "60", env = "HLB_AGENT_POLL_SECS")]
    agent_poll_secs: u64,

    /// How often the backup deadlines are examined.
    #[arg(long, default_value = "600", env = "HLB_BACKUP_CHECK_SECS")]
    backup_check_secs: u64,

    /// How often the manifests' assertions are read from the running apps. Once a day:
    /// a door reopened is seen by the next morning, and some reads open a database
    /// connection each.
    #[arg(long, default_value = "86400", env = "HLB_ASSERTIONS_SECS")]
    assertions_secs: u64,

    /// How often Stalwart's queue is read. A message waiting an hour is in the inbox
    /// within a quarter of one more.
    #[arg(long, default_value = "900", env = "HLB_MAIL_QUEUE_SECS")]
    mail_queue_secs: u64,

    /// How often the manifests' scheduled jobs are looked at; each runs when it is due
    /// (a day or a week after its last run), not at every look.
    #[arg(long, default_value = "3600", env = "HLB_JOBS_SECS")]
    jobs_secs: u64,

    /// How often PocketID's groups, the apps' restrictions, quotas and members are made
    /// to hold the roles again. Every change made here syncs at once; this catches what
    /// was changed elsewhere — a group edited in PocketID, a quota in Seafile.
    #[arg(long, default_value = "3600", env = "HLB_ROLES_SECS")]
    roles_secs: u64,

    /// How often the emergency vault's account is verified and every recovery sign-in
    /// deposited. Once a day: a password generated by an install reaches Vaultwarden by
    /// the next morning, and an account given too much is seen.
    #[arg(long, default_value = "86400", env = "HLB_EMERGENCY_SECS")]
    emergency_secs: u64,

    /// How often every node's Termix account and key, and Termix's hosts, are made to
    /// hold. Once a day: a node that joined appears in Termix by the next morning, one
    /// that left is gone from it, and an account changed by hand is put back.
    #[arg(long, default_value = "86400", env = "HLB_TERMIX_SECS")]
    termix_secs: u64,

    /// How often the backup destinations are looked at: each one proved more than a week
    /// ago is proved again — a policy changed since is seen —, and kept to the retention
    /// policy where it can be erased anyway.
    #[arg(long, default_value = "86400", env = "HLB_UPKEEP_SECS")]
    upkeep_secs: u64,

    /// How often every node's unused images are removed. Once a day: an update leaves
    /// its previous image on every node that ran it, on the root disk.
    #[arg(long, default_value = "86400", env = "HLB_PRUNE_SECS")]
    prune_secs: u64,

    /// How often the fleet's mTLS certificates are looked at, and those ending within
    /// 30 days issued again. Once a day leaves a month of retries before one ends.
    #[arg(long, default_value = "86400", env = "HLB_PKI_SECS")]
    pki_secs: u64,

    /// How often the expired temporary aliases are purged.
    ///
    /// ⚠️ One hour: an alias therefore survives at most one hour too long. Going lower
    /// would bring nothing — expiry is on the order of a day — and would multiply the
    /// calls to Stalwart.
    #[arg(long, default_value = "3600", env = "HLB_ALIAS_PURGE_SECS")]
    alias_purge_secs: u64,

    /// Default mail domain, for mailboxes that carry none.
    #[arg(long, env = "HLB_MAIL_DOMAIN")]
    mail_domain: Option<String>,

    #[arg(long, env = "HLB_STALWART_URL", conflicts_with = "demo")]
    stalwart_url: Option<String>,

    #[arg(long, env = "HLB_STALWART_ADMIN")]
    stalwart_admin: Option<String>,

    #[arg(long, env = "HLB_STALWART_PASSWORD")]
    stalwart_password: Option<String>,
}

/// Settings renamed to English, still read under their French names when the English
/// one is not given — and said, so the deployment is renamed before they go.
#[derive(Debug, Default, PartialEq, Eq)]
struct Legacy {
    alerts_secs: Option<u64>,
    public_status: Option<bool>,
}

impl Legacy {
    fn read(env: impl Fn(&str) -> Option<String>) -> Self {
        let old = |name: &str, new: &str| {
            let v = env(name).filter(|_| env(new).is_none())?;
            tracing::warn!("{name} is deprecated: name it {new}");
            Some(v)
        };
        Self {
            alerts_secs: old("HLB_ALERTES_SECS", "HLB_ALERTS_SECS").and_then(|v| v.parse().ok()),
            // As clap reads a flag's variable: anything but a "no" turns it on.
            public_status: old("HLB_STATUT_PUBLIC", "HLB_PUBLIC_STATUS").map(|v| {
                !matches!(
                    v.to_ascii_lowercase().as_str(),
                    "" | "0" | "false" | "no" | "off" | "n" | "f"
                )
            }),
        }
    }
}

/// What the daemon's own loops hold beside the privileged side, until those loops move
/// into it: the web side's `AppState` carries none of it.
struct Held {
    install: Option<Arc<hlb_privd::InstallContext>>,
    orchestrator: Option<Arc<dyn Orchestrator>>,
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

    let matches = <Cli as clap::CommandFactory>::command().get_matches();
    let mut cli = match <Cli as clap::FromArgMatches>::from_arg_matches(&matches) {
        Ok(c) => c,
        Err(e) => e.exit(),
    };
    let defaulted =
        |id: &str| matches.value_source(id) == Some(clap::parser::ValueSource::DefaultValue);
    let legacy = Legacy::read(|k| std::env::var(k).ok());
    if defaulted("alerts_secs") {
        if let Some(secs) = legacy.alerts_secs {
            cli.alerts_secs = secs;
        }
    }
    if defaulted("public_status") {
        if let Some(public) = legacy.public_status {
            cli.public_status = public;
        }
    }
    // Read before the state is opened, which creates it: the vault's key may be created
    // for a new installation only, never beside one that exists.
    let state_existed = cli.state.exists();

    let state = if cli.demo {
        tracing::warn!(
            "🎭 DEMONSTRATION MODE — in-memory database, fictional data. \
             --state is ignored, nothing is read or written on disk."
        );
        let s = State::in_memory().await?;
        let catalog = hlb_catalog::Catalog::load(&cli.catalog).ok();
        hlb_controller::demo::seed_at(&s, cli.demo_scale, catalog.as_ref()).await?;
        Arc::new(s)
    } else {
        Arc::new(State::open(&cli.state).await?)
    };
    // The one place the controller may create the vault's key; everything after opens
    // it, so a key missing later is said rather than replaced.
    if !cli.demo {
        if let Err(e) = hlb_secrets::Vault::open_for_state(&cli.master_key, state_existed) {
            tracing::error!("{e}");
        }
    }

    // The platform's admin credentials live in the vault, generated at install: a flag
    // still wins, but none is needed for what Homelabus installed itself.
    let mut ntfy_account = None;
    if !cli.demo && cli.master_key.exists() {
        if let Ok(vault) = hlb_secrets::Vault::open(&cli.master_key) {
            match hlb_engine::access::from_vault(&state, &vault).await {
                Ok(a) => {
                    ntfy_account = a.ntfy_publisher.clone();
                    if cli.postgres_admin.is_none() {
                        cli.postgres_admin = a.postgres_admin;
                    }
                    if cli.mariadb_admin.is_none() {
                        cli.mariadb_admin = a.mariadb_admin;
                    }
                    if let (None, None, Some((url, user, password))) =
                        (&cli.stalwart_url, &cli.stalwart_password, a.stalwart_admin)
                    {
                        cli.stalwart_url = Some(url);
                        cli.stalwart_admin = Some(user);
                        cli.stalwart_password = Some(password);
                    }
                    if let (None, None, Some((url, key))) =
                        (&cli.pocketid_url, &cli.pocketid_key, a.pocketid)
                    {
                        cli.pocketid_url = Some(url);
                        cli.pocketid_key = Some(key);
                    }
                }
                Err(e) => tracing::warn!("platform credentials unreadable from the vault: {e}"),
            }
        }
    }

    // Published by Homelabus's own ingress, the controller knows its address, its
    // issuer and its mail domain from the state, and its sign-in client from the vault
    // — what `hlb config exposure` and `hlb fleet controller` recorded. A flag still
    // wins. `derived` remembers which: a sign-in nobody configured by hand must not
    // stop the controller from starting.
    let mut derived_signin = false;
    // The root the ingress's certificates chain to when no public authority signed
    // them — the internal one, or a private ACME authority's: without it, PocketID's
    // issuer is unverifiable and nobody signs in.
    let mut trusted_root = None;
    if !cli.demo {
        let vault = cli
            .master_key
            .exists()
            .then(|| hlb_secrets::Vault::open(&cli.master_key).ok())
            .flatten();
        trusted_root = hlb_engine::ingress::trusted_root(&state, vault.as_ref()).await;
        if let Ok(Some(e)) = state.exposure().await {
            if cli.public_url.is_none() {
                cli.public_url = Some(format!("https://{}", e.controller_host()));
                // Caddy is in front: it replaces X-Forwarded-For with the client's own
                // address, which the rate limit then counts on.
                cli.trusted_proxy = true;
            }
            if cli.mail_domain.is_none() {
                cli.mail_domain = Some(e.domain.clone());
            }
        }
        if cli.oidc_issuer.is_none() && cli.master_key.exists() {
            let issuer = state.app_domain("pocket-id").await.ok().flatten();
            let vault = hlb_secrets::Vault::open(&cli.master_key).ok();
            let read = |name: &'static str| {
                let vault = vault.as_ref();
                let state = &state;
                async move {
                    let ct = state.secret(name).await.ok().flatten()?;
                    vault?.decrypt(&ct).ok()
                }
            };
            if let (Some(domain), Some(id), Some(secret)) = (
                issuer,
                read(hlb_engine::access::CONTROLLER_OIDC_ID).await,
                read(hlb_engine::access::CONTROLLER_OIDC_SECRET).await,
            ) {
                cli.oidc_issuer = Some(format!("https://{domain}"));
                cli.oidc_client_id = id;
                cli.oidc_client_secret = Some(secret);
                derived_signin = true;
            }
        }
    }

    // The orchestrator can be absent at startup (Docker not ready yet). We report it
    // without refusing to start: the read API stays useful, and reconciliation will
    // retry.
    //
    // ⚠️ In demonstration mode we do not even connect: finding a real Docker and
    // starting to reconcile fictional apps would delete or redeploy real
    // services.
    let orchestrator = if cli.demo {
        None
    } else {
        match SwarmOrchestrator::connect().await {
            Ok(o) => Some(Arc::new(o)),
            Err(e) => {
                tracing::warn!("Docker unreachable at startup ({e}) — reconciliation suspended");
                None
            }
        }
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut tasks = Vec::new();

    // Shared between the polling loop (which writes) and `/metrics` (which reads).
    let last_poll: api::LastPoll = Default::default();
    if cli.demo {
        // We exercise the real sharing path, not a special case: the interface reads
        // exactly the same structure as in production.
        *last_poll.write().await = hlb_controller::demo::nodes_at(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            cli.demo_scale,
        );
        // And the day behind that state, for the home's curves.
        let running = state
            .installed_apps()
            .await?
            .iter()
            .filter(|(_, st)| st == "running")
            .count();
        let now = hlb_controller::auth::now();
        state
            .record_history(&hlb_controller::demo::history(
                &*last_poll.read().await,
                running,
                now,
            ))
            .await?;
    }

    // With no ntfy configured, the alerts go to the logs rather than nowhere.
    let notif = cli.ntfy_url.as_ref().map(|u| {
        tracing::info!(server = %u, subject = %cli.ntfy_topic, "alerts ntfy active");
        let client = hlb_notify::NtfyClient::new(u, &cli.ntfy_topic);
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
    let notif = hlb_controller::notify::Notifier::new(notif, state.clone());
    // What quiet hours held back, delivered once the installation's morning comes.
    {
        let notif = notif.clone();
        tasks.push(tokio::spawn(loops::every(
            Duration::from_secs(HELD_NOTIFICATIONS_SECS),
            shutdown_rx.clone(),
            move || {
                let notif = notif.clone();
                async move {
                    let f = notif.flush(hlb_controller::auth::now()).await;
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
    let drift_state: hlb_controller::loops::DriftState = Default::default();
    // And a third reference for the API, which reads the Swarm tasks: the reconciliation
    // loop consumes the value right after.
    let orch_api = orchestrator
        .clone()
        .map(|o| o as Arc<dyn hlb_orchestrator::Orchestrator>);

    // Started at "now": the heartbeat grants the first pass its window, and no more.
    let reconciled: loops::LastReconciled = Arc::new(std::sync::atomic::AtomicI64::new(
        hlb_controller::auth::now(),
    ));
    if let Some(orch) = orchestrator {
        let rl = Arc::new(
            hlb_privd::daemon::ReconcileLoop::new(orch, state.clone())
                .apply(cli.reconcile_apply)
                .published_in(drift_state.clone())
                .reports_to(reconciled.clone()),
        );
        let rx = shutdown_rx.clone();
        let mirror = cli.git_mirror.clone();
        let st = state.clone();
        tracing::info!(
            interval = cli.reconcile_secs,
            correction = cli.reconcile_apply,
            "reconciliation loop"
        );
        tasks.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.reconcile_secs),
            rx,
            move || {
                let (rl, mirror, st) = (rl.clone(), mirror.clone(), st.clone());
                async move {
                    let r = rl.tick().await;
                    // Each pass samples the exposed apps for the status page's history.
                    loops::sample_uptime(&st).await;
                    if !r.is_clean() {
                        tracing::warn!(errors = r.errors.len(), "incomplete reconciliation");
                    } else if r.acted > 0 {
                        tracing::info!(corrected = r.acted, "gaps corrected");

                        // Will only produce a commit if the DESIRED state moved.
                        // A reconciliation that brings reality back into line changes
                        // nothing desired: its silence is intended.
                        if let Some(g) = &mirror {
                            if let Err(e) = export(g, &st, "correction by reconciliation").await {
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
            &cli.stalwart_url,
            &cli.stalwart_admin,
            &cli.stalwart_password,
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

        let purge = Arc::new(hlb_privd::daemon::AliasPurgeLoop::new(
            state.clone(),
            mail,
            cli.mail_domain.clone().unwrap_or_else(|| "local".into()),
        ));
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.alias_purge_secs),
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
        let retention = Arc::new(loops::UptimeRetentionLoop::new(state.clone(), 90));
        let rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(loops::every(
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
    if !cli.demo {
        let st = state.clone();
        let rx = shutdown_rx.clone();
        let (catalog_dir, master_key) = (cli.catalog.clone(), cli.master_key.clone());
        tasks.push(tokio::spawn(loops::every(
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

    if let Some(path) = cli.heartbeat.clone() {
        let hb = Arc::new(loops::Heartbeat::new(path.clone()));
        let rx = shutdown_rx.clone();
        let st = state.clone();
        let orch = orch_health.clone();
        let (reconciled, reconcile_secs) = (reconciled.clone(), cli.reconcile_secs);
        tracing::info!(file = %path.display(), "heartbeat (conditional)");

        tasks.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.heartbeat_secs),
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
                        recent_reconciliation: loops::reconciled_recently(
                            reconciled.load(std::sync::atomic::Ordering::Relaxed),
                            hlb_controller::auth::now(),
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
    if let Some(g) = &cli.git_mirror {
        match export(g, &state, "state at controller startup").await {
            Ok(()) => tracing::info!(mirror = %g.display(), "state archived in Git"),
            Err(e) => tracing::warn!("Git mirror unavailable: {e}"),
        }
    }

    // 🔴 The SAME pass as `hlb backup run`: every declared destination, the databases,
    // the SQLite files and Homelabus's own state. It starts without `--backup-repo`
    // too — the declared destinations are what decide, and an installation with none
    // hears about it on every pass rather than never. "Back up now" runs it too, held
    // to one app: the route once drove a provider of its own over `--backup-repo`.
    let pass_config = hlb_privd::backup::PassConfig {
        master_key: cli.master_key.clone(),
        state_path: cli.state.clone(),
        fallback_repo: cli.backup_repo.clone(),
        network: cli.platform_network.clone(),
        postgres_admin: cli.postgres_admin.clone(),
        mariadb_admin: cli.mariadb_admin.clone(),
    };
    if !cli.demo {
        let bl = Arc::new(loops::BackupLoop::new(
            state.clone(),
            hlb_backup::Schedule::default(),
        ));
        let st = state.clone();
        let rx = shutdown_rx.clone();
        let notif_bck = notif.clone();
        let config = pass_config.clone();
        tracing::info!("backup loop");

        tasks.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.backup_check_secs),
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
    if !cli.demo {
        let reader = Arc::new(hlb_guide::assertions::LiveReader::new(
            orch_api.clone(),
            cli.postgres_admin.clone(),
            cli.mariadb_admin.clone(),
        ));
        // The mail records with them, judged from a public resolver: a DKIM key nobody
        // published files every mail as spam, and nothing in the house says so.
        let mail = match (
            &cli.stalwart_url,
            &cli.stalwart_admin,
            &cli.stalwart_password,
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
        let st = state.clone();
        let rx = shutdown_rx.clone();
        let notif_as = notif.clone();
        let master_key = cli.master_key.clone();
        tracing::info!(interval = cli.assertions_secs, "assertions loop");
        tasks.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.assertions_secs),
            rx,
            move || {
                let (reader, st, notif) = (reader.clone(), st.clone(), notif_as.clone());
                let (mail, dns, master_key) = (mail.clone(), dns.clone(), master_key.clone());
                async move {
                    let now = hlb_controller::auth::now();
                    // Opened at each pass, as the backup loop does: a key rotated by
                    // `hlb secrets-rekey` is read the next night.
                    let vault = hlb_secrets::Vault::open(&master_key).ok();
                    let pass = hlb_privd::daemon::assertions::read_every_app(
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
                    let Some(mail) = mail else { return };
                    match hlb_privd::daemon::mail_dns::read_and_record(
                        &st,
                        &mail,
                        dns.as_ref(),
                        now,
                    )
                    .await
                    {
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
    if !cli.demo {
        if let (Some(u), Some(a), Some(p)) = (
            &cli.stalwart_url,
            &cli.stalwart_admin,
            &cli.stalwart_password,
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
            tracing::info!(interval = cli.mail_queue_secs, "mail queue loop");
            tasks.push(tokio::spawn(loops::every(
                Duration::from_secs(cli.mail_queue_secs),
                rx,
                move || {
                    let (mail, st, notif) = (mail.clone(), st.clone(), notif_mq.clone());
                    async move {
                        let now = hlb_controller::auth::now();
                        match hlb_privd::daemon::mail_queue::read_and_record(&st, &mail, now).await
                        {
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
    if !cli.demo {
        if let Some(orch) = orch_api.clone() {
            let st = state.clone();
            let rx = shutdown_rx.clone();
            let notif_jobs = notif.clone();
            tracing::info!(interval = cli.jobs_secs, "scheduled jobs loop");
            tasks.push(tokio::spawn(loops::every(
                Duration::from_secs(cli.jobs_secs),
                rx,
                move || {
                    let (orch, st, notif) = (orch.clone(), st.clone(), notif_jobs.clone());
                    async move {
                        let now = hlb_controller::auth::now();
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
    if !cli.demo {
        let st = state.clone();
        let rx = shutdown_rx.clone();
        let notif_updates = notif.clone();
        tasks.push(tokio::spawn(loops::every(
            Duration::from_secs(60),
            rx,
            move || {
                let (st, notif) = (st.clone(), notif_updates.clone());
                async move {
                    let now = hlb_controller::auth::now();
                    loops::notify_update_runs(&st, &notif, now).await;
                }
            },
        )));
    }

    // Agent polling: this is what gives the per-node view of disk space, which
    // the controller cannot obtain otherwise.
    {
        // 🔴 mTLS as soon as both files are there. In the clear, any container on the
        // overlay can map the fleet's disks.
        let poller = match (&cli.controller_cert, &cli.controller_ca) {
            (Some(c), Some(a)) => {
                let cert = tokio::fs::read_to_string(c).await?;
                let ca = tokio::fs::read_to_string(a).await?;
                match agents::AgentPoller::with_mtls(
                    cli.agent_port,
                    Duration::from_secs(10),
                    &cert,
                    &ca,
                    &format!("tasks.{}", cli.agent_service),
                ) {
                    Ok(p) => {
                        tracing::info!("polling the agents over mTLS");
                        Arc::new(p)
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            (None, None) => {
                tracing::error!(
                    "🔴 agents polled over PLAIN HTTP — supply --controller-cert \
                     and --controller-ca"
                );
                Arc::new(agents::AgentPoller::new(
                    cli.agent_port,
                    Duration::from_secs(10),
                ))
            }
            // Only one of the two: refuse rather than fall back to the clear while the
            // operator believes they enabled mTLS.
            _ => {
                return Err(
                    "incomplete mTLS configuration: --controller-cert AND --controller-ca \
                     are required together"
                        .into(),
                )
            }
        };
        let service = cli.agent_service.clone();
        let rx = shutdown_rx.clone();
        let latest = last_poll.clone();
        let notif_ag = notif.clone();
        tracing::info!(service = %service, "agent polling loop");

        tasks.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.agent_poll_secs),
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
                    let addresses = match resolve_tasks(&service).await {
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

                    let health = agents::ClusterHealth::from_statuses(
                        &statuses,
                        &hlb_agent::Thresholds::default(),
                    );

                    for (addr, s) in &statuses {
                        if let agents::AgentStatus::Reporting(r) = s {
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

    // 🔴 The refusal to start. An open API exposes the fleet's state, the audit log and
    // the secrets' names; discovering afterwards that it was open is
    // too late.
    // ⚠️ In demonstration mode the API opens: there is nothing to protect, and requiring
    // a token would make the first step "create a token in an in-memory database", so
    // one to redo on every launch.
    if cli.demo && !state.has_tokens().await? {
        tracing::warn!("🎭 API open (demonstration mode) — no real data behind it.");
    }
    if !cli.demo && !cli.insecure_no_auth && !state.has_tokens().await? {
        tracing::error!("🔴 no access token: the API would accept nobody.");
        tracing::error!("   Create one: hlb token create <name> --role admin --apply");
        tracing::error!("   Or accept it open: --insecure-no-auth");
        return Err("no access token".into());
    }
    if cli.insecure_no_auth {
        tracing::error!(
            "🔴 API WITHOUT AUTHENTICATION — fleet state, audit log and secret names \
             accessible to anyone who reaches this port."
        );
    }

    // The alert-rule evaluation.
    //
    // 🔴 They existed and were only evaluated by the CLI, so only when someone typed
    // `hlb metrics check`: the rules described what needed watching without anyone
    // watching it.
    let series = cli.metrics_url.as_ref().map(|u| {
        tracing::info!(url = %u, "time-series database configured");
        Arc::new(hlb_controller::promql::Metrics::new(u))
    });

    if cli.demo {
        // Same reason as the alerts: without an orchestrator, reconciliation does not
        // run, and the drift screen would be empty.
        *drift_state.write().await = hlb_controller::demo::drifts();
    }

    let alerts_state: hlb_controller::loops::AlertsState = Default::default();
    if cli.demo {
        // Without VictoriaMetrics the loop does not run: we place fabricated alerts, or
        // the alerts screen would be empty and impossible to write.
        *alerts_state.write().await = hlb_controller::demo::alerts(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        );
    }

    match &series {
        Some(m) => {
            let loop_body = Arc::new(loops::AlertLoop::new(
                m.clone(),
                notif.clone(),
                state.clone(),
            ));
            // The loop and the API share the SAME structure: the API reads what the
            // loop has just written, with no copy and no extra synchronisation.
            let shared = loop_body.active.clone();
            let to_api = alerts_state.clone();
            let interval = Duration::from_secs(cli.alerts_secs);
            tasks.push(tokio::spawn(loops::every(
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

    // Signing people in. Optional: without it, only tokens
    // authenticate, and `/auth/signin` explains how to enable it.
    let signin = match (&cli.oidc_issuer, &cli.oidc_client_secret) {
        (Some(issuer), Some(secret)) => {
            let public = cli.public_url.clone().unwrap_or_else(|| {
                // ⚠️ Guessing the public URL is an acknowledged stopgap: `--listen` is
                // often a local address behind a reverse proxy. We SAY so, because a
                // wrong callback URI ends in a refusal from PocketID whose message does
                // not name the cause.
                let guessed = format!("http://{}", cli.listen);
                tracing::warn!(
                    url = %guessed,
                    "--public-url missing: callback URI guessed. If PocketID refuses the \
                     sign-in, that is the first thing to fix."
                );
                guessed
            });
            let redirect_uri = format!("{}/auth/return_to", public.trim_end_matches('/'));

            match hlb_identity::oidc::Oidc::discover_trusting(
                issuer,
                cli.oidc_client_id.clone(),
                secret.clone(),
                redirect_uri.clone(),
                trusted_root.as_deref(),
            )
            .await
            {
                Ok(o) => {
                    tracing::info!(issuer, redirect_uri, "PocketID sign-in enabled");
                    std::sync::Arc::new(signin::SignInSlot::ready(signin::SignIn::new(o, &public)))
                }
                // Derived, it starts anyway, loudly: restarting in a loop would also
                // take away the tokens' access, which is how it gets repaired. And it
                // asks again until the issuer answers: after a cold start of the
                // cluster the controller is up before PocketID and the ingress.
                Err(e) if derived_signin => {
                    tracing::error!(
                        error = %e,
                        issuer,
                        "🔴 sign-in through PocketID is UNAVAILABLE: its issuer did not \
                         answer. Only API tokens authenticate until it does — asking again"
                    );
                    let slot = std::sync::Arc::new(signin::SignInSlot::waiting());
                    let (filled, issuer, id, secret, root) = (
                        slot.clone(),
                        issuer.clone(),
                        cli.oidc_client_id.clone(),
                        secret.clone(),
                        trusted_root.clone(),
                    );
                    tokio::spawn(async move {
                        let mut wait = std::time::Duration::from_secs(5);
                        loop {
                            tokio::time::sleep(wait).await;
                            match hlb_identity::oidc::Oidc::discover_trusting(
                                &issuer,
                                id.clone(),
                                secret.clone(),
                                redirect_uri.clone(),
                                root.as_deref(),
                            )
                            .await
                            {
                                Ok(o) => {
                                    tracing::info!(issuer, "PocketID answered: sign-in enabled");
                                    filled.fill(signin::SignIn::new(o, &public));
                                    return;
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, issuer, "PocketID still unreachable");
                                    wait = (wait * 2).min(std::time::Duration::from_secs(60));
                                }
                            }
                        }
                    });
                    slot
                }
                Err(e) => {
                    // 🔴 We refuse to start rather than carry on with no sign-in.
                    // Starting anyway would give a controller that looks normal and
                    // that nobody can sign in to — and you would go looking at the
                    // browser, not at the startup.
                    tracing::error!(error = %e, "🔴 OIDC sign-in configured but unusable");
                    return Err(e.into());
                }
            }
        }
        (Some(_), None) => {
            tracing::error!(
                "🔴 --oidc-issuer without --oidc-client-secret: signing people in would \
                 be announced and would not work."
            );
            return Err("OIDC secret missing".into());
        }
        _ => {
            tracing::info!(
                "sign-in through PocketID not configured — only API tokens authenticate"
            );
            Default::default()
        }
    };

    // 🔴 Assembled at startup, once. An install triggered from the interface then runs
    // the SAME executor as `hlb install` — the alternative would have been to shell out
    // to the CLI, which recomputes the plan instead of replaying it, and would execute
    // something other than what was previewed.
    let vault = if cli.demo {
        Ok(hlb_secrets::Vault::ephemeral())
    } else {
        hlb_secrets::Vault::open(&cli.master_key)
    };
    let install = match vault {
        Ok(vault) => {
            let postgres = match &cli.postgres_admin {
                Some(url) => match hlb_platform::PostgresProvisioner::connect(url).await {
                    Ok(p) => Some(p),
                    Err(e) => {
                        tracing::warn!("PostgreSQL unreachable ({e}): databases NOT provisioned");
                        None
                    }
                },
                None => None,
            };
            let mariadb = match &cli.mariadb_admin {
                Some(url) => match hlb_platform::MariadbProvisioner::connect(url).await {
                    Ok(m) => Some(m),
                    Err(e) => {
                        tracing::warn!("MariaDB unreachable ({e}): databases NOT provisioned");
                        None
                    }
                },
                None => None,
            };
            Some(Arc::new(hlb_privd::InstallContext {
                vault,
                registry: hlb_registry::RegistryClient::new(),
                postgres,
                mariadb,
                storage: hlb_engine::StorageConfig {
                    local_root: cli.storage_root.clone(),
                    nfs_server: cli.nfs_server.clone(),
                    nfs_export: cli.nfs_export.clone(),
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
    let identity = match (&cli.pocketid_url, &cli.pocketid_key) {
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
        &cli.stalwart_url,
        &cli.stalwart_admin,
        &cli.stalwart_password,
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
    let mail_domain = cli.mail_domain.clone().unwrap_or_else(|| "local".into());
    // ⚠️ Loaded once at startup. An unreadable catalog must not stop the controller
    // from starting: the rest of the API keeps all its value, and the message says
    // what is missing.
    let catalog = match hlb_catalog::Catalog::load(&cli.catalog) {
        Ok(c) => {
            tracing::info!(apps = c.len(), directory = %cli.catalog.display(), "catalog loaded");
            Some(Arc::new(c))
        }
        Err(e) => {
            tracing::warn!(
                directory = %cli.catalog.display(),
                "unreadable catalog ({e}) — installing from the interface will be unavailable"
            );
            None
        }
    };
    let backup =
        (!cli.demo).then(|| Arc::new(pass_config) as Arc<dyn hlb_privd::backup::BackUpNow>);
    // 🔴 The capabilities go to the privileged side, and to the daemon's own loops
    // below: the web side's `AppState` holds none of them, only the door.
    let privd = hlb_privd::Privd::new(state.clone())
        .with_orchestrator(orch_api.clone())
        .with_catalog(catalog.clone())
        .with_install(install.clone())
        .with_identity(identity)
        .with_mail(mail, &mail_domain)
        .with_backup(backup);
    let held = Arc::new(Held {
        install,
        orchestrator: orch_api,
    });

    let shared = Arc::new(api::AppState {
        state,
        privd,
        started_at: std::time::Instant::now(),
        version: env!("CARGO_PKG_VERSION"),
        last_poll,
        ui_dir: cli.ui_dir.clone(),
        no_auth: cli.insecure_no_auth || cli.demo,
        signin,
        throughput: Arc::new(hlb_controller::throughput::RateLimiter::new()),
        trusted_proxy: cli.trusted_proxy,
        series: series.clone(),
        alerts: alerts_state,
        drifts: drift_state,
        beat: cli.heartbeat.clone(),
        mirror: cli.git_mirror.clone(),
        public_url: cli.public_url.clone(),
        demo: cli.demo,
        public_status: cli.public_status,
        mail_domain,
        catalog_dir: cli.catalog.clone(),
        // ⚠️ Loaded ONCE at startup, like the catalog. A theme file edited while the
        // controller runs takes effect at the next restart — the same contract the
        // catalog already has, rather than a second, surprising one.
        custom_themes: {
            let loaded = hlb_catalog::themes::load(&cli.themes);
            for r in &loaded.refused {
                // 🔴 Named and refused, never swallowed. A theme missing from Settings
                // with nothing in the log is indistinguishable from one nobody wrote.
                tracing::warn!(file = %r.file.display(), "theme refused: {}", r.reason);
            }
            if !loaded.themes.is_empty() {
                tracing::info!(
                    count = loaded.themes.len(),
                    directory = %cli.themes.display(),
                    "custom themes loaded"
                );
            }
            loaded.themes
        },
        // Beside `custom_themes`, and for the same reason `catalog_dir` sits beside the
        // catalog: a theme may name a typeface, which is a file in this directory.
        themes_dir: cli.themes.clone(),
        catalog,
    });

    // A day of measurements for the home's curves, read from what the agents last
    // reported — in demonstration mode too, which reads the same structure.
    {
        let shared = shared.clone();
        tasks.push(tokio::spawn(loops::every(
            Duration::from_secs(60),
            shutdown_rx.clone(),
            move || {
                let shared = shared.clone();
                async move {
                    if let Err(e) =
                        hlb_controller::history::record(&shared, hlb_controller::auth::now()).await
                    {
                        tracing::warn!("measurements not recorded: {e}");
                    }
                }
            },
        )));
    }
    // 🔴 The roles, made true where they are read. A group edited by hand in PocketID,
    // a client's restriction lifted, a quota changed in Seafile: put back, and a
    // failure notified — a door the roles say is closed must not stay open quietly.
    if !cli.demo {
        let shared = shared.clone();
        let notif_roles = notif.clone();
        tracing::info!(interval = cli.roles_secs, "roles loop");
        tasks.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.roles_secs),
            shutdown_rx.clone(),
            move || {
                let (shared, notif) = (shared.clone(), notif_roles.clone());
                async move {
                    match shared.privd().sync_roles(true).await {
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
    if !cli.demo {
        let shared = shared.clone();
        let held = held.clone();
        let notif_vault = notif.clone();
        tracing::info!(interval = cli.emergency_secs, "emergency vault loop");
        tasks.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.emergency_secs),
            shutdown_rx.clone(),
            move || {
                let held = held.clone();
                let (shared, notif) = (shared.clone(), notif_vault.clone());
                async move {
                    let Some(install) = &held.install else {
                        return;
                    };
                    let reach = |u: &str| u.to_string();
                    let run = hlb_engine::emergency::EmergencyVault {
                        state: &shared.state,
                        vault: &install.vault,
                        reach: &reach,
                        now: hlb_controller::auth::now(),
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
    if !cli.demo {
        let shared = shared.clone();
        let held = held.clone();
        let notif_upkeep = notif.clone();
        let network = cli.platform_network.clone();
        tracing::info!(interval = cli.upkeep_secs, "destinations upkeep loop");
        tasks.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.upkeep_secs),
            shutdown_rx.clone(),
            move || {
                let held = held.clone();
                let (shared, notif, network) =
                    (shared.clone(), notif_upkeep.clone(), network.clone());
                async move {
                    let Some(install) = &held.install else {
                        return;
                    };
                    let reach = |u: &str| u.to_string();
                    let lines = match hlb_backup_run::upkeep::run(
                        &shared.state,
                        &install.vault,
                        &network,
                        &reach,
                        &hlb_backup::RetentionPolicy::default(),
                        hlb_controller::auth::now(),
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
                        let _ = shared
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
    if !cli.demo {
        let shared = shared.clone();
        let held = held.clone();
        let notif_termix = notif.clone();
        tracing::info!(interval = cli.termix_secs, "termix loop");
        tasks.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.termix_secs),
            shutdown_rx.clone(),
            move || {
                let held = held.clone();
                let (shared, notif) = (shared.clone(), notif_termix.clone());
                async move {
                    let (Some(install), Some(orch)) = (&held.install, &held.orchestrator) else {
                        return;
                    };
                    let reach = |u: &str| u.to_string();
                    let run = hlb_engine::termix::NodeAccess {
                        state: &shared.state,
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
    if !cli.demo {
        let held = held.clone();
        let notif_prune = notif.clone();
        tracing::info!(interval = cli.prune_secs, "image prune loop");
        tasks.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.prune_secs),
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
    if !cli.demo {
        if let (Some(own), Some(_)) = (cli.controller_cert.clone(), &cli.controller_ca) {
            let shared = shared.clone();
            let held = held.clone();
            let notif_pki = notif.clone();
            let agent_service = cli.agent_service.clone();
            tracing::info!(interval = cli.pki_secs, "certificate renewal loop");
            tasks.push(tokio::spawn(loops::every(
                Duration::from_secs(cli.pki_secs),
                shutdown_rx.clone(),
                move || {
                    let held = held.clone();
                    let (shared, notif, own, agent_service) = (
                        shared.clone(),
                        notif_pki.clone(),
                        own.clone(),
                        agent_service.clone(),
                    );
                    async move {
                        use hlb_engine::pki;
                        let (Some(install), Some(orch)) = (&held.install, &held.orchestrator)
                        else {
                            return;
                        };
                        let now = hlb_controller::auth::now();
                        // What this process was started with, whatever the state says:
                        // after a rollback it is the old leaf.
                        let observed = match tokio::fs::read_to_string(&own)
                            .await
                            .map_err(|e| e.to_string())
                            .and_then(|pem| {
                                hlb_agent::pki::not_after(&pem).map_err(|e| e.to_string())
                            }) {
                            Ok(t) => vec![(pki::CONTROLLER_SERVICE.to_string(), t)],
                            Err(e) => {
                                tracing::warn!("own certificate unreadable: {e}");
                                Vec::new()
                            }
                        };
                        let run = pki::Renewal {
                            state: &shared.state,
                            vault: &install.vault,
                            orchestrator: orch.as_ref(),
                            agent_service: &agent_service,
                            now,
                            observed,
                            inside: Some(pki::CONTROLLER_SERVICE),
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
                        if let Ok(known) = shared.state.leaf_expiries().await {
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

    let app = api::router(shared);

    match &cli.ui_dir {
        Some(d) => tracing::info!(directory = %d.display(), "web UI served"),
        None => tracing::info!("API only (--ui-dir to serve the dashboard)"),
    }

    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    tracing::info!(address = %cli.listen, "API listening");

    // ⚠️ `into_make_service_with_connect_info`: without it, the client's address is not
    // in the extensions, and rate limiting would count everyone together — a single
    // attacker would close the service to all.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        wait_for_shutdown().await;
        tracing::info!("shutdown requested, ending the background loops");
        let _ = shutdown_tx.send(true);
    })
    .await?;

    for t in tasks {
        let _ = t.await;
    }
    tracing::info!("clean shutdown");
    Ok(())
}

/// Archives the desired state into the Git mirror.
async fn export(
    path: &std::path::Path,
    state: &State,
    message: &str,
) -> Result<(), hlb_controller::diff::MirrorError> {
    hlb_controller::diff::export(path, state, message).await
}

/// Resolves `tasks.<service>` to the addresses of every task.
///
/// This is Swarm's DNS mechanism for reaching each instance of a service rather than the
/// VIP. Outside a Swarm overlay, resolution simply fails — that is not an error, just
/// the absence of agents.
async fn resolve_tasks(service: &str) -> Result<Vec<String>, std::io::Error> {
    let name = format!("tasks.{service}:0");
    let addrs = tokio::net::lookup_host(name).await?;
    Ok(addrs.map(|a| a.ip().to_string()).collect())
}

/// Ctrl-C or SIGTERM (what Docker sends).
async fn wait_for_shutdown() {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn a_french_setting_is_still_read_until_the_english_one_is_given() {
        let old = Legacy::read(env(&[
            ("HLB_ALERTES_SECS", "300"),
            ("HLB_STATUT_PUBLIC", "true"),
        ]));
        assert_eq!(
            old,
            Legacy {
                alerts_secs: Some(300),
                public_status: Some(true),
            }
        );
        let both = Legacy::read(env(&[
            ("HLB_ALERTES_SECS", "300"),
            ("HLB_ALERTS_SECS", "60"),
            ("HLB_STATUT_PUBLIC", "1"),
            ("HLB_PUBLIC_STATUS", "false"),
        ]));
        assert_eq!(both, Legacy::default(), "the English name wins");
        assert_eq!(
            Legacy::read(env(&[("HLB_STATUT_PUBLIC", "false")])).public_status,
            Some(false)
        );
    }

    #[test]
    fn the_settings_answer_to_their_english_names() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let env_of = |id: &str| {
            cmd.get_arguments()
                .find(|a| a.get_id() == id)
                .and_then(|a| a.get_env())
                .map(|e| e.to_string_lossy().into_owned())
        };
        assert_eq!(env_of("alerts_secs").as_deref(), Some("HLB_ALERTS_SECS"));
        assert_eq!(
            env_of("public_status").as_deref(),
            Some("HLB_PUBLIC_STATUS")
        );
    }
}
