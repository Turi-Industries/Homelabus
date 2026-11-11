//! `hlb-controller` — the web side: the API, the interface, signing people in.
//!
//! Given `--privd-socket`, it holds nothing privileged: it reads `hlb.db` read-only and
//! asks every privileged thing of `hlb-privd` over that socket. Without it, it starts
//! the daemon in its own process — the demonstration, the browser suite, a run by hand
//! on one machine.
//!
//! 🟢 **An important property**: the controller is NOT in the critical path of
//! traffic. Swarm keeps running the deployed services without it. Stopping it loses the
//! steering, not the service — which makes its updates and restarts far less delicate.

use hlb_controller::{api, signin};
use hlb_privd::daemon::{self, schedule};

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use hlb_state::State;

/// The settings reaching a real system: a demonstration's fictional apps would be
/// backed up, provisioned or exported there, so `--demo` refuses each of them.
const DEMO_REFUSES: [&str; 9] = [
    "postgres_admin",
    "postgres_vital_admin",
    "mariadb_admin",
    "pocketid_url",
    "heartbeat",
    "backup_repo",
    "git_mirror",
    "stalwart_url",
    "privd_socket",
];

#[derive(Parser)]
#[command(name = "hlb-controller", version, about = "Homelabus web side")]
struct Cli {
    /// The API's listen address.
    #[arg(long, default_value = "127.0.0.1:8420", env = "HLB_LISTEN")]
    listen: String,

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

    /// 🔴 Publish the status page, WITHOUT authentication.
    ///
    /// It then reveals the list of your exposed services and your open incidents. For a
    /// commercial service that is a transparency commitment; for a homelab it is free
    /// reconnaissance. Hence the closed default.
    #[arg(long, env = "HLB_PUBLIC_STATUS")]
    public_status: bool,

    /// Directory of themes this installation declares, one YAML file each.
    ///
    /// Absent by default and absent without complaint: most installations use the three
    /// shipped themes and never create this directory.
    #[arg(long, default_value = "themes", env = "HLB_THEMES")]
    themes: std::path::PathBuf,

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
    #[arg(long, conflicts_with_all = DEMO_REFUSES)]
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

    /// The daemon's socket (`hlb-privd --socket`). Given, this process holds no
    /// capability and reads the state read-only; absent, it runs the daemon itself.
    #[arg(long, env = "HLB_PRIVD_SOCKET")]
    privd_socket: Option<std::path::PathBuf>,

    #[command(flatten)]
    daemon: daemon::Config,
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

/// The alert rules' measurements, through the PromQL relay: its allowlist holds the
/// shipped rules too.
fn measure(
    series: &Option<Arc<hlb_controller::promql::Metrics>>,
) -> Option<Arc<dyn daemon::Measure>> {
    let m = series.clone()?;
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
            cli.daemon.alerts_secs = secs;
        }
    }
    if defaulted("public_status") {
        if let Some(public) = legacy.public_status {
            cli.public_status = public;
        }
    }

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut tasks = Vec::new();
    let series = cli.daemon.metrics_url.as_ref().map(|u| {
        tracing::info!(url = %u, "time-series database configured");
        Arc::new(hlb_controller::promql::Metrics::new(u))
    });

    let (state, privd) = if cli.demo {
        demonstration(&cli).await?
    } else if let Some(socket) = &cli.privd_socket {
        tracing::info!(socket = %socket.display(), "web side: the daemon answers every intent");
        let state = wait_for_daemon(&cli.daemon.state, socket).await;
        let privd = hlb_privd::Privd::new(state.clone()).through(socket);
        (state, privd)
    } else {
        tracing::warn!(
            "one process: the web side holds the daemon's capabilities — `hlb fleet \
             controller` deploys them apart (--privd-socket)"
        );
        if series.is_none() {
            tracing::info!(
                "no time-series database (--metrics-url): the alert rules are not evaluated"
            );
        }
        let started =
            daemon::start(cli.daemon.clone(), measure(&series), shutdown_rx.clone()).await?;
        tasks.extend(started.tasks);
        (started.state, started.privd)
    };

    // Published by Homelabus's own ingress, the controller knows its address, its
    // issuer and its mail domain from the state, and its sign-in client from the daemon
    // — what `hlb config exposure` and `hlb fleet controller` recorded. A flag still
    // wins. `derived` remembers which: a sign-in nobody configured by hand must not
    // stop the controller from starting.
    let mut derived_signin = false;
    // The root the ingress's certificates chain to when no public authority signed
    // them — the internal one, or a private ACME authority's: without it, PocketID's
    // issuer is unverifiable and nobody signs in.
    let mut trusted_root = None;
    if !cli.demo {
        if let Ok(Some(e)) = state.exposure().await {
            if cli.public_url.is_none() {
                cli.public_url = Some(format!("https://{}", e.controller_host()));
                // Caddy is in front: it replaces X-Forwarded-For with the client's own
                // address, which the rate limit then counts on.
                cli.trusted_proxy = true;
            }
            if cli.daemon.mail_domain.is_none() {
                cli.daemon.mail_domain = Some(e.domain.clone());
            }
        }
        match privd.ask(hlb_api::intent::SignInClient {}).await {
            Ok(setup) => {
                trusted_root = setup.trusted_root;
                if let (None, Some(c)) = (&cli.oidc_issuer, setup.client) {
                    cli.oidc_issuer = Some(c.issuer);
                    cli.oidc_client_id = c.id;
                    cli.oidc_client_secret = Some(c.secret);
                    derived_signin = true;
                }
            }
            Err(e) => tracing::warn!("the sign-in client could not be asked for: {e}"),
        }
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
        let _ = shutdown_tx.send(true);
        return Err("no access token".into());
    }
    if cli.insecure_no_auth {
        tracing::error!(
            "🔴 API WITHOUT AUTHENTICATION — fleet state, audit log and secret names \
             accessible to anyone who reaches this port."
        )
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

    let mail_domain = cli
        .daemon
        .mail_domain
        .clone()
        .unwrap_or_else(|| "local".into());
    // An unreadable catalog must not stop the controller from starting: the rest of
    // the API keeps all its value, and the message says what is missing.
    let catalog = match hlb_privd::catalog::load(&cli.daemon.catalog, &state).await {
        Ok(c) => {
            tracing::info!(apps = c.len(), directory = %cli.daemon.catalog.display(), "catalog loaded");
            Some(Arc::new(c))
        }
        Err(e) => {
            tracing::warn!(
                directory = %cli.daemon.catalog.display(),
                "unreadable catalog ({e}) — installing from the interface will be unavailable"
            );
            None
        }
    };
    let catalog = hlb_privd::catalog::SharedCatalog::new(catalog);
    // Read again as the daemon fetches its sources: this process only reads them.
    {
        let (catalog, dir, state) = (catalog.clone(), cli.daemon.catalog.clone(), state.clone());
        tasks.push(tokio::spawn(schedule::every(
            Duration::from_secs(hlb_privd::catalog::RELOAD_SECS),
            shutdown_rx.clone(),
            move || {
                let (catalog, dir, state) = (catalog.clone(), dir.clone(), state.clone());
                async move { catalog.reload(&dir, &state).await }
            },
        )));
    }

    let shared = Arc::new(api::AppState {
        state,
        privd,
        started_at: std::time::Instant::now(),
        version: env!("CARGO_PKG_VERSION"),
        ui_dir: cli.ui_dir.clone(),
        no_auth: cli.insecure_no_auth || cli.demo,
        signin,
        throughput: Arc::new(hlb_controller::throughput::RateLimiter::new()),
        trusted_proxy: cli.trusted_proxy,
        series: series.clone(),
        beat: cli.daemon.heartbeat.clone(),
        mirror: cli.daemon.git_mirror.clone(),
        public_url: cli.public_url.clone(),
        demo: cli.demo,
        public_status: cli.public_status,
        mail_domain,
        catalog_dir: cli.daemon.catalog.clone(),
        // ⚠️ Loaded ONCE at startup. A theme file edited while the controller runs
        // takes effect at the next restart.
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
        tasks.push(tokio::spawn(schedule::every(
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

/// The demonstration: an in-memory state seeded with fictional data, and a privileged
/// side holding no real system — no Docker, a vault held in memory. What its loops would
/// publish is fabricated, or the alerts, drift and fleet screens would be empty and
/// impossible to write.
async fn demonstration(
    cli: &Cli,
) -> Result<(Arc<State>, hlb_privd::Privd), Box<dyn std::error::Error>> {
    tracing::warn!(
        "🎭 DEMONSTRATION MODE — in-memory database, fictional data. \
         --state is ignored, nothing is read or written on disk."
    );
    let s = State::in_memory().await?;
    let catalog = hlb_catalog::Catalog::load(&cli.daemon.catalog).ok();
    hlb_privd::demo::seed_at(&s, cli.demo_scale, catalog.as_ref()).await?;
    let state = Arc::new(s);
    let now = hlb_controller::auth::now();

    // We exercise the real sharing path, not a special case: the interface reads
    // exactly the same structure as in production.
    let fleet: hlb_privd::fleet::Polled = Default::default();
    *fleet.write().await = hlb_controller::demo::nodes_at(now as u64, cli.demo_scale);
    // And the day behind that state, for the home's curves.
    let running = state
        .installed_apps()
        .await?
        .iter()
        .filter(|(_, st)| st == "running")
        .count();
    state
        .record_history(&hlb_controller::demo::history(
            &*fleet.read().await,
            running,
            now,
        ))
        .await?;
    let drifts: daemon::DriftState =
        Arc::new(tokio::sync::RwLock::new(hlb_controller::demo::drifts()));
    let alerts: daemon::AlertsState =
        Arc::new(tokio::sync::RwLock::new(hlb_controller::demo::alerts(now)));

    // 🔴 `--master-key` is ignored too: an install from a demo started at the
    // repository root would decrypt with the real one.
    let install = hlb_privd::InstallContext {
        vault: hlb_secrets::Vault::ephemeral(),
        registry: hlb_registry::RegistryClient::new(),
        postgres: None,
        postgres_vital: None,
        mariadb: None,
        storage: hlb_engine::StorageConfig {
            local_root: cli.daemon.storage_root.clone(),
            nfs_server: cli.daemon.nfs_server.clone(),
            nfs_export: cli.daemon.nfs_export.clone(),
        },
        api: hlb_guide::HttpApi::default(),
    };
    let mail_domain = cli.daemon.mail_domain.as_deref().unwrap_or("local");
    let privd = hlb_privd::Privd::new(state.clone())
        .with_catalog(catalog.map(Arc::new))
        .with_install(Some(Arc::new(install)))
        .with_mail(None, mail_domain)
        .with_published(alerts, drifts)
        .with_fleet(fleet);
    Ok((state, privd))
}

/// The state, once the daemon has opened and migrated it: read-only, it can be opened
/// only while the daemon holds it, and the two services start in no set order.
async fn wait_for_daemon(path: &std::path::Path, socket: &std::path::Path) -> Arc<State> {
    let mut wait = Duration::from_secs(1);
    loop {
        match State::open_read_only(path).await {
            Ok(s) if socket.exists() => return Arc::new(s),
            Ok(_) => tracing::info!(socket = %socket.display(), "waiting for the daemon's socket"),
            Err(e) => tracing::info!(state = %path.display(), "waiting for the daemon: {e}"),
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(Duration::from_secs(10));
    }
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
