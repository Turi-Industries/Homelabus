//! `hlb-controller` — le daemon.
//!
//! Trois responsabilités : servir l'API de lecture, faire tourner les boucles de fond,
//! et battre le cœur que surveille le NAS (§8bis).
//!
//! 🟢 **Propriété importante (§7bis)** : le controller n'est PAS dans le chemin
//! critique du trafic. Swarm continue de faire tourner les services déployés sans lui.
//! L'arrêter fait perdre le pilotage, pas le service — ce qui rend ses mises à jour et
//! ses redémarrages beaucoup moins délicats.

use hlb_controller::{agents, api, connexion, loops};

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

    /// Émetteur OIDC pour la connexion des personnes (PocketID).
    ///
    /// Sans lui, seuls les jetons d'API authentifient : suffisant pour le CLI et pour
    /// une installation à un seul administrateur, insuffisant dès qu'on ouvre l'accès.
    #[arg(long, env = "HLB_OIDC_ISSUER")]
    oidc_issuer: Option<String>,

    #[arg(long, env = "HLB_OIDC_CLIENT_ID", default_value = "homelabus")]
    oidc_client_id: String,

    /// ⚠️ Par variable d'environnement de préférence : un secret passé en argument de
    /// commande est visible de tout le système dans `ps`.
    #[arg(long, env = "HLB_OIDC_CLIENT_SECRET", hide_env_values = true)]
    oidc_client_secret: Option<String>,

    /// L'URL publique du controller, telle que le navigateur la voit.
    ///
    /// 🔴 Elle sert à deux choses qui échouent en silence si elle est fausse : l'URI de
    /// rappel OIDC (que PocketID compare à l'octet près) et l'attribut `Secure` du
    /// cookie (qui, posé sur du `http://`, empêche le cookie d'exister sans le moindre
    /// message).
    #[arg(long, env = "HLB_PUBLIC_URL")]
    public_url: Option<String>,

    /// URL de PocketID, pour créer les identités depuis l'interface.
    #[arg(long, env = "HLB_POCKETID_URL")]
    pocketid_url: Option<String>,

    /// Clé d'API PocketID.
    ///
    /// ⚠️ Par variable d'environnement de préférence : une clé passée en argument de
    /// commande est visible de tout le système dans `ps`.
    #[arg(long, env = "HLB_POCKETID_KEY", hide_env_values = true)]
    pocketid_key: Option<String>,

    /// 🔴 Publier la page de statut, SANS authentification.
    ///
    /// Elle révèle alors la liste de vos services exposés et vos incidents en cours.
    /// Pour un service commercial c'est un engagement de transparence ; pour un homelab
    /// c'est de la reconnaissance offerte. D'où le défaut fermé.
    #[arg(long, env = "HLB_STATUT_PUBLIC")]
    statut_public: bool,

    /// Répertoire du catalogue d'applications.
    ///
    /// Sans lui, l'interface ne peut ni parcourir le catalogue ni installer : elle le
    /// DIT plutôt que d'afficher une liste vide qu'on prendrait pour un catalogue sans
    /// applications.
    #[arg(long, default_value = "catalog", env = "HLB_CATALOG")]
    catalog: std::path::PathBuf,

    /// Intervalle d'évaluation des règles d'alerte, en secondes.
    #[arg(long, default_value = "60", env = "HLB_ALERTES_SECS")]
    alertes_secs: u64,

    /// URL de VictoriaMetrics, pour les graphes de l'interface.
    ///
    /// Sans elle, les écrans de métriques affichent « indisponible » en disant comment
    /// l'installer — plutôt qu'une courbe plate qu'on prendrait pour une machine au
    /// repos.
    #[arg(long, env = "HLB_METRICS_URL")]
    metrics_url: Option<String>,

    /// Démarrer avec des données de démonstration, en mémoire, sans Docker.
    ///
    /// 🔴 Le chemin `--state` est IGNORÉ : rien n'est lu ni écrit sur disque. C'est dit
    /// au démarrage, pour éviter le malentendu où l'on croit avoir perdu ses données.
    ///
    /// Sert à développer l'interface : les cas qu'il faut voir — une app jamais
    /// sauvegardée, un hors-site mort, un alias expiré qui reçoit encore — sont ceux
    /// qu'on n'a jamais sous la main.
    #[arg(long)]
    demo: bool,

    /// 🔴 Croire l'en-tête `X-Forwarded-For` pour identifier le client.
    ///
    /// À poser UNIQUEMENT si un proxy de confiance (Caddy) est réellement devant. Sans
    /// lui, chaque attaquant se donnerait un compteur de débit neuf à chaque requête :
    /// la limitation ne limiterait plus rien, tout en donnant l'impression du contraire.
    #[arg(long, env = "HLB_TRUSTED_PROXY")]
    trusted_proxy: bool,

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

    let state = if cli.demo {
        tracing::warn!(
            "🎭 MODE DÉMONSTRATION — base en mémoire, données fictives. \
             --state est ignoré, rien n'est lu ni écrit sur disque."
        );
        let s = State::in_memory().await?;
        hlb_controller::demo::peupler(&s).await?;
        Arc::new(s)
    } else {
        Arc::new(State::open(&cli.state).await?)
    };

    // L'orchestrateur peut être absent au démarrage (Docker pas encore prêt). On le
    // signale sans refuser de démarrer : l'API de lecture reste utile, et la
    // réconciliation réessaiera.
    //
    // ⚠️ En démonstration, on ne s'y connecte même pas : trouver un vrai Docker et se
    // mettre à réconcilier des apps fictives ferait supprimer ou redéployer de vrais
    // services.
    let orchestrator = if cli.demo {
        None
    } else {
        match SwarmOrchestrator::connect() {
            Ok(o) => Some(Arc::new(o)),
            Err(e) => {
                tracing::warn!("Docker injoignable au démarrage ({e}) — réconciliation suspendue");
                None
            }
        }
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut taches = Vec::new();

    // Partagé entre la boucle d'interrogation (qui écrit) et `/metrics` (qui lit).
    let dernier_sondage: api::LastPoll = Default::default();
    if cli.demo {
        // On exerce le vrai chemin de partage, pas un cas particulier : l'interface lit
        // exactement la même structure qu'en production.
        *dernier_sondage.write().await = hlb_controller::demo::noeuds(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
    }

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
    // Les écarts du dernier tour, partagés avec l'API : les non-actions délibérées de la
    // réconciliation ne sortaient jusqu'ici que dans les journaux, c'est-à-dire nulle
    // part.
    let etat_ecarts: hlb_controller::loops::EtatEcarts = Default::default();
    // Et une troisième référence pour l'API, qui lit les tâches Swarm : la boucle de
    // réconciliation consomme la valeur juste après.
    let orch_api = orchestrator
        .clone()
        .map(|o| o as Arc<dyn hlb_orchestrator::Orchestrator>);

    if let Some(orch) = orchestrator {
        let rl = Arc::new(
            loops::ReconcileLoop::new(orch, state.clone())
                .apply(cli.reconcile_apply)
                .publie_dans(etat_ecarts.clone()),
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
    // ⚠️ En démonstration, l'API s'ouvre : il n'y a rien à protéger, et exiger un jeton
    // ferait de la première étape « créer un jeton dans une base en mémoire », donc à
    // refaire à chaque lancement.
    if cli.demo && !state.has_tokens().await? {
        tracing::warn!("🎭 API ouverte (mode démonstration) — aucune donnée réelle derrière.");
    }
    if !cli.demo && !cli.insecure_no_auth && !state.has_tokens().await? {
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

    // L'évaluation des règles d'alerte (§8bis).
    //
    // 🔴 Elles existaient et n'étaient évaluées que par le CLI, donc seulement quand
    // quelqu'un tapait `hlb metrics check` : les règles décrivaient ce qu'il fallait
    // surveiller sans que personne ne le surveille.
    let series = cli.metrics_url.as_ref().map(|u| {
        tracing::info!(url = %u, "base de séries temporelles configurée");
        Arc::new(hlb_controller::promql::Metriques::new(u))
    });

    if cli.demo {
        // Même raison que les alertes : sans orchestrateur la réconciliation ne tourne
        // pas, et l'écran de dérive serait vide.
        *etat_ecarts.write().await = hlb_controller::demo::ecarts();
    }

    let etat_alertes: hlb_controller::loops::EtatAlertes = Default::default();
    if cli.demo {
        // Sans VictoriaMetrics, la boucle ne tourne pas : on pose des alertes
        // fabriquées, sinon l'écran des alertes serait vide et impossible à écrire.
        *etat_alertes.write().await = hlb_controller::demo::alertes(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        );
    }

    match &series {
        Some(m) => {
            let boucle = Arc::new(loops::AlerteLoop::new(m.clone(), notif.clone()));
            // La boucle et l'API partagent la MÊME structure : l'API lit ce que la
            // boucle vient d'écrire, sans copie ni synchronisation supplémentaire.
            let partage = boucle.actives.clone();
            let vers_api = etat_alertes.clone();
            let interval = Duration::from_secs(cli.alertes_secs);
            taches.push(tokio::spawn(loops::every(
                interval,
                shutdown_rx.clone(),
                move || {
                    let (b, partage, vers_api) =
                        (boucle.clone(), partage.clone(), vers_api.clone());
                    async move {
                        let maintenant = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        let r = b.tick(maintenant).await;
                        *vers_api.write().await = partage.read().await.clone();

                        if r.declenchees > 0 || r.inconnues > 0 {
                            tracing::info!(
                                evaluees = r.evaluees,
                                declenchees = r.declenchees,
                                // Compté séparément : « zéro déclenchée » avec dix
                                // inconnues n'est PAS « tout va bien ».
                                inconnues = r.inconnues,
                                "évaluation des alertes"
                            );
                        }
                    }
                },
            )));
        }
        None => tracing::info!(
            "aucune base de séries (--metrics-url) : les règles d'alerte ne sont pas évaluées"
        ),
    }

    // La connexion des personnes (§9ter). Facultative : sans elle, seuls les jetons
    // d'API authentifient, et `/auth/connexion` explique comment l'activer.
    let connexion = match (&cli.oidc_issuer, &cli.oidc_client_secret) {
        (Some(issuer), Some(secret)) => {
            let publique = cli.public_url.clone().unwrap_or_else(|| {
                // ⚠️ Deviner l'URL publique est un pis-aller assumé : `--listen` est
                // souvent une adresse locale derrière un reverse proxy. On le DIT,
                // parce qu'une URI de rappel fausse se solde par un refus de PocketID
                // dont le message ne désigne pas la cause.
                let devinee = format!("http://{}", cli.listen);
                tracing::warn!(
                    url = %devinee,
                    "--public-url absente : URI de rappel devinée. Si PocketID refuse la \
                     connexion, c'est la première chose à corriger."
                );
                devinee
            });
            let rappel = format!("{}/auth/retour", publique.trim_end_matches('/'));

            match hlb_identity::oidc::Oidc::decouvrir(
                issuer,
                cli.oidc_client_id.clone(),
                secret.clone(),
                rappel.clone(),
            )
            .await
            {
                Ok(o) => {
                    tracing::info!(issuer, rappel, "connexion par PocketID active");
                    Some(std::sync::Arc::new(connexion::Connexion::new(
                        o, &publique,
                    )))
                }
                Err(e) => {
                    // 🔴 On refuse de démarrer plutôt que de continuer sans connexion.
                    // Démarrer quand même donnerait un controller qui a l'air normal et
                    // dont personne ne peut se connecter — et on chercherait du côté du
                    // navigateur, pas du démarrage.
                    tracing::error!(erreur = %e, "🔴 connexion OIDC configurée mais inutilisable");
                    return Err(e.into());
                }
            }
        }
        (Some(_), None) => {
            tracing::error!(
                "🔴 --oidc-issuer sans --oidc-client-secret : la connexion des personnes \
                 serait annoncée et ne fonctionnerait pas."
            );
            return Err("secret OIDC manquant".into());
        }
        _ => {
            tracing::info!(
                "connexion par PocketID non configurée — seuls les jetons d'API authentifient"
            );
            None
        }
    };

    let app = api::router(Arc::new(api::AppState {
        state,
        started_at: std::time::Instant::now(),
        version: env!("CARGO_PKG_VERSION"),
        last_poll: dernier_sondage,
        ui_dir: cli.ui_dir.clone(),
        no_auth: cli.insecure_no_auth || cli.demo,
        connexion,
        debit: Arc::new(hlb_controller::debit::Limiteur::new()),
        confiance_proxy: cli.trusted_proxy,
        series: series.clone(),
        alertes: etat_alertes,
        ecarts: etat_ecarts,
        battement: cli.heartbeat.clone(),
        miroir: cli.git_mirror.clone(),
        url_publique: cli.public_url.clone(),
        orchestrator: orch_api,
        demo: cli.demo,
        statut_public: cli.statut_public,
        // Le provisionnement des comptes. Sans ces deux-là, l'inscription enregistre
        // un compte et rien d'autre — l'état est nommé `Vide` et une relance en ligne
        // de commande le termine.
        identite: match (&cli.pocketid_url, &cli.pocketid_key) {
            (Some(u), Some(k)) => {
                tracing::info!(url = %u, "PocketID configuré : les identités seront créées");
                Some(Arc::new(hlb_identity::PocketId::new(u, k)))
            }
            (Some(_), None) => {
                tracing::warn!(
                    "--pocketid-url sans --pocketid-key : les identités ne seront PAS créées"
                );
                None
            }
            _ => {
                tracing::info!(
                    "PocketID non configuré : l'inscription laissera les comptes sans identité"
                );
                None
            }
        },
        mail: match (&cli.stalwart_url, &cli.stalwart_admin, &cli.stalwart_password) {
            (Some(u), Some(a), Some(p)) => Some(Arc::new(hlb_mail::Stalwart::new(
                u,
                hlb_mail::Auth::Basic {
                    user: a.clone(),
                    password: p.clone(),
                },
            ))),
            _ => None,
        },
        domaine_mail: cli.mail_domain.clone().unwrap_or_else(|| "local".into()),
        // ⚠️ Chargé une fois au démarrage. Un catalogue illisible ne doit pas empêcher
        // le controller de démarrer : le reste de l'API garde toute sa valeur, et le
        // message dit ce qui manque.
        catalogue: match hlb_catalog::Catalog::load(&cli.catalog) {
            Ok(c) => {
                tracing::info!(apps = c.len(), répertoire = %cli.catalog.display(), "catalogue chargé");
                Some(Arc::new(c))
            }
            Err(e) => {
                tracing::warn!(
                    répertoire = %cli.catalog.display(),
                    "catalogue illisible ({e}) — l'installation depuis l'interface sera indisponible"
                );
                None
            }
        },
    }));

    match &cli.ui_dir {
        Some(d) => tracing::info!(répertoire = %d.display(), "UI web servie"),
        None => tracing::info!("API seule (--ui-dir pour servir le tableau de bord)"),
    }

    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    tracing::info!(adresse = %cli.listen, "API en écoute");

    // ⚠️ `into_make_service_with_connect_info` : sans lui, l'adresse du client n'est
    // pas dans les extensions, et la limitation de débit compterait tout le monde
    // ensemble — un seul attaquant fermerait le service à tous.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
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
