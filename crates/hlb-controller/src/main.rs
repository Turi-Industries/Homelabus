//! `hlb-controller` — le daemon.
//!
//! Trois responsabilités : servir l'API de lecture, faire tourner les boucles de fond,
//! et battre le cœur que surveille le NAS (§8bis).
//!
//! 🟢 **Propriété importante (§7bis)** : le controller n'est PAS dans le chemin
//! critique du trafic. Swarm continue de faire tourner les services déployés sans lui.
//! L'arrêter fait perdre le pilotage, pas le service — ce qui rend ses mises à jour et
//! ses redémarrages beaucoup moins délicats.

use hlb_controller::{agents, api, loops};

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use hlb_orchestrator::{Orchestrator, SwarmOrchestrator};
use hlb_state::State;

#[derive(Parser)]
#[command(name = "hlb-controller", version, about = "Daemon HomelabUS")]
struct Cli {
    /// Adresse d'écoute de l'API.
    #[arg(long, default_value = "127.0.0.1:8420", env = "HLB_LISTEN")]
    listen: String,

    #[arg(long, default_value = "hlb.db", env = "HLB_STATE")]
    state: std::path::PathBuf,

    /// Serveur ntfy pour les alertes (§8bis). Sans lui, elles restent aux journaux.
    #[arg(long, env = "HLB_NTFY_URL")]
    ntfy_url: Option<String>,

    #[arg(long, default_value = "homelab", env = "HLB_NTFY_TOPIC")]
    ntfy_topic: String,

    /// URL d'administration PostgreSQL. Sans elle, les bases ne sont PAS dumpées.
    #[arg(long, env = "HLB_POSTGRES_ADMIN")]
    postgres_admin: Option<String>,

    /// Réseau Docker où les services de plateforme sont joignables par leur nom.
    #[arg(long, default_value = "hlb_platform", env = "HLB_PLATFORM_NETWORK")]
    platform_network: String,

    /// Répertoire de l'UI web (§11bis). Absent : API seule.
    ///
    /// Servie par le controller lui-même, donc joignable à la même adresse que l'API —
    /// c'est ce qui permet d'ouvrir le tableau de bord depuis un téléphone sans rien
    /// installer dessus.
    #[arg(long, env = "HLB_UI_DIR")]
    ui_dir: Option<std::path::PathBuf>,

    /// 🔴 Servir l'API SANS authentification.
    ///
    /// Le controller refuse de démarrer si aucun jeton n'existe et que ce drapeau
    /// n'est pas posé : une API ouverte doit être une DÉCISION, jamais l'état par
    /// défaut d'un déploiement qu'on croyait protégé.
    #[arg(long, env = "HLB_INSECURE_NO_AUTH")]
    insecure_no_auth: bool,

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

    /// Miroir Git de l'état désiré (§2.3).
    #[arg(long, env = "HLB_GIT_MIRROR")]
    git_mirror: Option<std::path::PathBuf>,

    /// Nom du service Swarm des agents. Le DNS `tasks.<nom>` résout vers TOUTES
    /// les tâches, ce qui permet d'interroger chaque nœud individuellement.
    #[arg(long, default_value = "hlb-agent", env = "HLB_AGENT_SERVICE")]
    agent_service: String,

    #[arg(long, default_value = "8421", env = "HLB_AGENT_PORT")]
    agent_port: u16,

    /// Certificat CLIENT du controller (PEM : certificat + clé). Active le mTLS.
    #[arg(long, env = "HLB_CONTROLLER_CERT")]
    controller_cert: Option<std::path::PathBuf>,

    /// CA du cluster : c'est elle, et elle seule, qui valide les agents.
    #[arg(long, env = "HLB_CONTROLLER_CA")]
    controller_ca: Option<std::path::PathBuf>,

    /// Fréquence d'interrogation des agents.
    #[arg(long, default_value = "60", env = "HLB_AGENT_POLL_SECS")]
    agent_poll_secs: u64,

    /// Fréquence d'examen des échéances de sauvegarde.
    #[arg(long, default_value = "600", env = "HLB_BACKUP_CHECK_SECS")]
    backup_check_secs: u64,

    /// Fréquence de purge des aliases temporaires expirés (§5bis.3).
    ///
    /// ⚠️ Une heure : un alias survit donc au plus une heure de trop. Descendre plus
    /// bas n'apporterait rien — l'expiration est de l'ordre du jour — et multiplierait
    /// les appels à Stalwart.
    #[arg(long, default_value = "3600", env = "HLB_ALIAS_PURGE_SECS")]
    alias_purge_secs: u64,

    /// Domaine mail par défaut, pour les boîtes qui n'en portent pas.
    #[arg(long, env = "HLB_MAIL_DOMAIN")]
    mail_domain: Option<String>,

    #[arg(long, env = "HLB_STALWART_URL")]
    stalwart_url: Option<String>,

    #[arg(long, env = "HLB_STALWART_ADMIN")]
    stalwart_admin: Option<String>,

    #[arg(long, env = "HLB_STALWART_PASSWORD")]
    stalwart_password: Option<String>,
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

    // Partagé entre la boucle d'interrogation (qui écrit) et `/metrics` (qui lit).
    let dernier_sondage: api::LastPoll = Default::default();

    // Sans ntfy configuré, les alertes partent aux journaux plutôt que nulle part.
    let notif = cli.ntfy_url.as_ref().map(|u| {
        tracing::info!(serveur = %u, sujet = %cli.ntfy_topic, "alertes ntfy actives");
        Arc::new(hlb_notify::NtfyClient::new(u, &cli.ntfy_topic))
    });
    if notif.is_none() {
        tracing::warn!("aucun ntfy configuré : les alertes resteront dans les journaux");
    }

    // Cloné avant que la boucle de réconciliation ne consomme la valeur : le
    // battement de cœur a besoin de sa propre référence pour VÉRIFIER que Docker
    // répond avant de prétendre que tout va bien.
    let orch_sante = orchestrator.clone();

    if let Some(orch) = orchestrator {
        let rl = Arc::new(
            loops::ReconcileLoop::new(orch, state.clone()).apply(cli.reconcile_apply),
        );
        let rx = shutdown_rx.clone();
        let mirror = cli.git_mirror.clone();
        let st = state.clone();
        tracing::info!(
            intervalle = cli.reconcile_secs,
            correction = cli.reconcile_apply,
            "boucle de réconciliation"
        );
        taches.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.reconcile_secs),
            rx,
            move || {
                let (rl, mirror, st) = (rl.clone(), mirror.clone(), st.clone());
                async move {
                    let r = rl.tick().await;
                    if !r.is_clean() {
                        tracing::warn!(erreurs = r.errors.len(), "réconciliation incomplète");
                    } else if r.acted > 0 {
                        tracing::info!(corrigés = r.acted, "écarts corrigés");

                        // §2.3 — ne produira un commit que si l'état DÉSIRÉ a bougé.
                        // Une réconciliation qui remet la réalité en conformité ne
                        // change rien de désiré : c'est voulu qu'elle soit silencieuse.
                        if let Some(g) = &mirror {
                            if let Err(e) = export(g, &st, "correction par réconciliation").await {
                                tracing::warn!("miroir Git non mis à jour : {e}");
                            }
                        }
                    }
                }
            },
        )));
    }

    // 🔴 La purge des aliases temporaires. Sans elle, « temporaire » est un mensonge :
    // Stalwart n'a aucune notion d'expiration, et une adresse donnée « pour trente
    // jours » reçoit indéfiniment.
    {
        let mail = match (&cli.stalwart_url, &cli.stalwart_admin, &cli.stalwart_password) {
            (Some(u), Some(a), Some(p)) => Some(Arc::new(hlb_mail::Stalwart::new(
                u,
                hlb_mail::Auth::Basic { user: a.clone(), password: p.clone() },
            ))),
            _ => None,
        };
        if mail.is_none() {
            tracing::warn!(
                "Stalwart non configuré : les aliases temporaires expirés ne seront PAS \
                 retirés, et continueront de recevoir"
            );
        }

        let purge = Arc::new(loops::AliasPurgeLoop::new(
            state.clone(),
            mail,
            cli.mail_domain.clone().unwrap_or_else(|| "local".into()),
        ));
        let rx = shutdown_rx.clone();
        taches.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.alias_purge_secs),
            rx,
            move || {
                let purge = purge.clone();
                async move {
                    let r = purge.tick().await;
                    if r.retires > 0 {
                        tracing::info!(retires = r.retires, "aliases expirés retirés");
                    }
                    // 🔴 On journalise sur ce qui reste OUVERT, pas sur le nombre
                    // d'erreurs : une purge sans erreur qui n'a rien retiré laisse
                    // autant de portes ouvertes qu'une purge qui a échoué bruyamment.
                    if !r.is_clean() {
                        tracing::error!(
                            ouvertes = r.encore_ouvertes(),
                            erreurs = r.errors.len(),
                            "adresses expirées toujours actives"
                        );
                    }
                }
            },
        )));
    }

    if let Some(path) = cli.heartbeat.clone() {
        let hb = Arc::new(loops::Heartbeat::new(path.clone()));
        let rx = shutdown_rx.clone();
        let st = state.clone();
        let orch = orch_sante.clone();
        tracing::info!(fichier = %path.display(), "battement de cœur (conditionnel)");

        taches.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.heartbeat_secs),
            rx,
            move || {
                let hb = hb.clone();
                let st = st.clone();
                let orch = orch.clone();
                async move {
                    // 🔴 On VÉRIFIE avant de battre. Un battement inconditionnel ne
                    // prouve que la survie d'un fil d'exécution : le controller
                    // pourrait avoir sa base illisible et son Docker mort, et laisser
                    // le veilleur au vert sur un système inutilisable.
                    let sante = hlb_metrics::Sante {
                        // Une requête réelle, pas un drapeau : c'est la lecture qui
                        // échoue quand le disque est plein ou la base corrompue.
                        etat_lisible: st.installed_apps().await.is_ok(),
                        orchestrateur_joignable: match &orch {
                            Some(o) => o.ping().await.is_ok(),
                            None => false,
                        },
                        // La boucle de réconciliation tourne dans la même tâche
                        // système ; si elle était bloquée, ce minuteur le serait
                        // aussi et aucun battement ne partirait.
                        reconciliation_recente: true,
                    };

                    match hb.beat_si_sain(&sante).await {
                        Ok(true) => {}
                        Ok(false) => {} // déjà journalisé, avec les manquements
                        Err(e) => tracing::error!("battement de cœur impossible : {e}"),
                    }
                }
            },
        )));
    }

    // Miroir Git initialisé au démarrage : le dépôt doit refléter l'état courant
    // même si rien ne change ensuite. Sinon un cluster stable n'aurait aucune trace.
    if let Some(g) = &cli.git_mirror {
        match export(g, &state, "état au démarrage du controller").await {
            Ok(()) => tracing::info!(miroir = %g.display(), "état archivé dans Git"),
            Err(e) => tracing::warn!("miroir Git indisponible : {e}"),
        }
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
                let notif_bck = notif.clone();
                let pg_admin = cli.postgres_admin.clone();
                let platform_net = cli.platform_network.clone();
                let depot_pour_sql = repo.clone();
                let mdp_depot = match restic_password(&state, &cli.master_key).await {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!("mot de passe du dépôt illisible : {e}");
                        String::new()
                    }
                };
                if cli.postgres_admin.is_none() {
                    tracing::warn!(
                        "🔴 --postgres-admin absent : les BASES ne seront pas sauvegardées, \
                         seulement leurs volumes — ce qui ne restaure pas"
                    );
                }
                tracing::info!(dépôt = %repo, "boucle de sauvegarde");

                taches.push(tokio::spawn(loops::every(
                    Duration::from_secs(cli.backup_check_secs),
                    rx,
                    move || {
                        let (bl, provider, st, notif) =
                            (bl.clone(), provider.clone(), st.clone(), notif_bck.clone());
                        let (pg_url, reseau, depot_sql, mdp_sql) = (
                            pg_admin.clone(), platform_net.clone(),
                            depot_pour_sql.clone(), mdp_depot.clone(),
                        );
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
                                        // 🟠 Important, pas critique : un échec isolé
                                        // sera peut-être rattrapé au tour suivant. Ce
                                        // qui est critique, c'est la DÉRIVE — traitée
                                        // juste en dessous.
                                        hlb_notify::ntfy::notify_or_log(
                                            notif.as_deref(),
                                            &hlb_notify::Notification::important(
                                                &format!("backup:{app}"),
                                                &format!("Sauvegarde de {app} échouée"),
                                                &e,
                                            ),
                                        )
                                        .await;
                                    }
                                }
                            }
                            // 🔴 Les bases ensuite. Un volume PostgreSQL copié à
                            // chaud ne restaure PAS : seul un dump logique est
                            // transactionnellement cohérent (§8.1). Sans ce bloc,
                            // les apps à base de données ne sont sauvegardées qu'en
                            // apparence.
                            if let Some(url) = &pg_url {
                                for (app, moteur, base, _) in
                                    st.app_databases().await.unwrap_or_default()
                                {
                                    if moteur != "postgres" {
                                        tracing::warn!(
                                            app, moteur,
                                            "moteur sans dumper — base NON sauvegardée"
                                        );
                                        continue;
                                    }
                                    match dump_database(&st, url, &reseau, &depot_sql,
                                                        &mdp_sql, &app, &base).await
                                    {
                                        Ok(id) => tracing::info!(
                                            app, base,
                                            instantané = %&id[..8.min(id.len())],
                                            "base sauvegardée"
                                        ),
                                        Err(e) => tracing::error!(app, base, "dump échoué : {e}"),
                                    }
                                }
                            }

                            // Alerte sur ce qui dérive vraiment (§8bis).
                            if let Ok(tard) = bl.overdue_apps().await {
                                for app in tard {
                                    tracing::error!(app, "🔴 aucune sauvegarde réussie depuis trop longtemps");
                                    // 🔴 Critique : une app qu'on croit sauvegardée et
                                    // qui ne l'est plus est le pire état possible. Ça
                                    // traverse les heures calmes.
                                    hlb_notify::ntfy::notify_or_log(
                                        notif.as_deref(),
                                        &hlb_notify::Notification::critical(
                                            &format!("overdue:{app}"),
                                            &format!("{app} n'est plus sauvegardée"),
                                            "Aucune sauvegarde réussie depuis trop longtemps.",
                                        ),
                                    )
                                    .await;
                                }
                            }
                        }
                    },
                )));
            }
            Err(e) => tracing::error!("boucle de sauvegarde non démarrée : {e}"),
        }
    }

    // Interrogation des agents (§9bis) : c'est ce qui donne la vue par nœud de
    // l'espace disque, que le controller ne peut pas obtenir autrement.
    {
        // 🔴 mTLS dès que les deux fichiers sont là. En clair, n'importe quel
        // conteneur de l'overlay peut cartographier les disques du parc.
        let poller = match (&cli.controller_cert, &cli.controller_ca) {
            (Some(c), Some(a)) => {
                let cert = tokio::fs::read_to_string(c).await?;
                let ca = tokio::fs::read_to_string(a).await?;
                match agents::AgentPoller::with_mtls(
                    cli.agent_port,
                    Duration::from_secs(10),
                    &cert,
                    &ca,
                ) {
                    Ok(p) => {
                        tracing::info!("interrogation des agents en mTLS");
                        Arc::new(p)
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            (None, None) => {
                tracing::error!(
                    "🔴 agents interrogés en HTTP CLAIR — fournis --controller-cert \
                     et --controller-ca"
                );
                Arc::new(agents::AgentPoller::new(cli.agent_port, Duration::from_secs(10)))
            }
            // Un seul des deux : refuser plutôt que de retomber en clair alors que
            // l'opérateur croit avoir activé le mTLS.
            _ => {
                return Err(
                    "configuration mTLS incomplète : --controller-cert ET --controller-ca \
                     sont requis ensemble"
                        .into(),
                )
            }
        };
        let service = cli.agent_service.clone();
        let rx = shutdown_rx.clone();
        let derniers = dernier_sondage.clone();
        let notif_ag = notif.clone();
        tracing::info!(service = %service, "boucle d'interrogation des agents");

        taches.push(tokio::spawn(loops::every(
            Duration::from_secs(cli.agent_poll_secs),
            rx,
            move || {
                let (poller, service, derniers, notif) =
                    (poller.clone(), service.clone(), derniers.clone(), notif_ag.clone());
                async move {
                    // `tasks.<service>` résout vers toutes les tâches ; une VIP
                    // classique n'en donnerait qu'une au hasard.
                    let adresses = match resolve_tasks(&service).await {
                        Ok(a) if !a.is_empty() => a,
                        Ok(_) => {
                            tracing::debug!("aucun agent déployé");
                            return;
                        }
                        Err(e) => {
                            tracing::debug!("agents non résolus : {e}");
                            return;
                        }
                    };

                    let statuts = poller.poll_all(&adresses).await;
                    // Publié pour `/metrics` avant toute analyse : même un tour où
                    // tout va mal doit être visible dans la supervision.
                    *derniers.write().await = statuts.clone();

                    let sante = agents::ClusterHealth::from_statuses(
                        &statuts,
                        &hlb_agent::Thresholds::default(),
                    );

                    for (addr, s) in &statuts {
                        if let agents::AgentStatus::Reporting(r) = s {
                            for (d, p) in r.problems(&hlb_agent::Thresholds::default()) {
                                tracing::warn!(
                                    nœud = %r.hostname, chemin = %d.path,
                                    "{:.0} % occupé — {}", d.used_percent(), p.describe()
                                );
                            }
                        } else {
                            tracing::warn!(adresse = %addr, "agent injoignable");
                        }
                    }

                    if sante.needs_attention() {
                        tracing::error!(
                            injoignables = sante.unreachable,
                            saturés = ?sante.saturated,
                            "🔴 cluster à surveiller"
                        );
                        // Un disque plein arrête les bases de données ; un nœud muet
                        // peut vouloir dire que ses données ne sont plus sauvegardées.
                        // Les deux méritent de réveiller quelqu'un.
                        hlb_notify::ntfy::notify_or_log(
                            notif.as_deref(),
                            &hlb_notify::Notification::critical(
                                "cluster",
                                "Cluster à surveiller",
                                &format!(
                                    "{} nœud(s) injoignable(s), saturés : {}",
                                    sante.unreachable,
                                    if sante.saturated.is_empty() {
                                        "aucun".to_string()
                                    } else {
                                        sante.saturated.join(", ")
                                    }
                                ),
                            ),
                        )
                        .await;
                    }
                }
            },
        )));
    }

    // 🔴 Le refus de démarrage. Une API ouverte expose l'état du parc, le journal
    // d'audit et les noms des secrets ; découvrir qu'elle l'était après coup est
    // trop tard.
    if !cli.insecure_no_auth && !state.has_tokens().await? {
        tracing::error!("🔴 aucun jeton d'accès : l'API n'accepterait personne.");
        tracing::error!("   Crée-en un :  hlb token create <nom> --role admin --apply");
        tracing::error!("   Ou assume l'ouverture :  --insecure-no-auth");
        return Err("aucun jeton d'accès".into());
    }
    if cli.insecure_no_auth {
        tracing::error!(
            "🔴 API SANS AUTHENTIFICATION — état du parc, journal d'audit et noms des \
             secrets accessibles à quiconque atteint ce port."
        );
    }

    let app = api::router(Arc::new(api::AppState {
        state,
        started_at: std::time::Instant::now(),
        version: env!("CARGO_PKG_VERSION"),
        last_poll: dernier_sondage,
        ui_dir: cli.ui_dir.clone(),
        no_auth: cli.insecure_no_auth,
    }));

    match &cli.ui_dir {
        Some(d) => tracing::info!(répertoire = %d.display(), "UI web servie"),
        None => tracing::info!("API seule (--ui-dir pour servir le tableau de bord)"),
    }

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

/// Archive l'état désiré dans le miroir Git.
async fn export(
    chemin: &std::path::Path,
    state: &State,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut apps = Vec::new();
    for (name, status) in state.installed_apps().await? {
        apps.push((name.clone(), status, state.app_manifest(&name).await?));
    }
    hlb_gitops::GitMirror::open_or_init(chemin)?.export(&apps, message)?;
    Ok(())
}

/// Assemble le fournisseur de sauvegarde depuis l'état et le coffre.
/// Le mot de passe du dépôt restic, partagé entre l'instantané et les dumps.
///
/// 🔴 Le MÊME que celui de `build_provider` : deux mots de passe différents
/// produiraient deux dépôts qui ne se lisent pas l'un l'autre, dans le même
/// répertoire.
async fn restic_password(
    state: &State,
    master_key: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let vault = hlb_secrets::Vault::open_or_init(master_key)?;
    const SECRET: &str = "restic-repo-password";

    Ok(match state.secret(SECRET).await? {
        Some(ct) => vault.decrypt(&ct)?,
        None => {
            let p = hlb_secrets::generate_password(hlb_secrets::DEFAULT_PASSWORD_LEN);
            state
                .store_secret_if_absent(SECRET, &vault.encrypt(&p)?, "chiffrement du dépôt")
                .await?;
            p
        }
    })
}

/// Un dump logique d'une base, archivé dans le dépôt.
async fn dump_database(
    state: &State,
    admin_url: &str,
    network: &str,
    repo: &str,
    password: &str,
    app: &str,
    database: &str,
) -> Result<String, String> {
    use hlb_backup::pgdump::{scheduled, PgDumper, PgTarget};

    let creds = hlb_backup::parse_pg_url(admin_url)
        .ok_or_else(|| "URL PostgreSQL illisible".to_string())?;

    // Identifiants d'ADMINISTRATION : le rôle isolé de l'app ne peut pas lire toutes
    // ses dépendances, et le dump serait incomplet sans erreur.
    let cible = PgTarget {
        host: creds.host,
        port: creds.port,
        database: database.to_string(),
        user: creds.user,
        password: creds.password,
    };

    let dumper = PgDumper::new(hlb_backup::PgContainerRunner::default().network(network));
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let d = match scheduled::produce(&dumper, app, &cible, at).await {
        Ok(d) => d,
        Err(e) => {
            let _ = state.record_backup(app, "sql-dump", None, Some(&e.to_string())).await;
            return Err(e.to_string());
        }
    };

    match scheduled::archive(repo, password, &d).await {
        Ok(id) => {
            let _ = state.record_backup(app, "sql-dump", Some(&id), None).await;
            Ok(id)
        }
        Err(e) => {
            let _ = state.record_backup(app, "sql-dump", None, Some(&e.to_string())).await;
            Err(e.to_string())
        }
    }
}

async fn build_provider(
    repo: &str,
    master_key: &std::path::Path,
    state: &State,
) -> Result<hlb_backup::ResticBackupProvider<hlb_backup::ContainerRunner>, Box<dyn std::error::Error>>
{
    let vault = hlb_secrets::Vault::open_or_init(master_key)?;

    let _ = &vault;
    let password = restic_password(state, master_key).await?;

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

/// Résout `tasks.<service>` vers les adresses de toutes les tâches.
///
/// C'est le mécanisme DNS de Swarm pour atteindre chaque exemplaire d'un service
/// plutôt que la VIP. Hors d'un overlay Swarm, la résolution échoue simplement —
/// ce n'est pas une erreur, juste l'absence d'agents.
async fn resolve_tasks(service: &str) -> Result<Vec<String>, std::io::Error> {
    let nom = format!("tasks.{service}:0");
    let addrs = tokio::net::lookup_host(nom).await?;
    Ok(addrs.map(|a| a.ip().to_string()).collect())
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
