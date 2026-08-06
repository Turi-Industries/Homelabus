//! `hlb` — l'interface de première classe.
//!
//! Principe du §11bis : **le CLI fait tout, l'UI n'est qu'un client de l'API.** Ça
//! garantit la scriptabilité, et le débogage quand l'UI est cassée.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use hlb_catalog::Catalog;
use hlb_orchestrator::{Orchestrator, SwarmOrchestrator};
use hlb_engine::{Executor, Reconciler};
use hlb_ingress::{CaddyAdmin, Route};
use hlb_resolver::{DependencyGraph, InstallParams};
use hlb_secrets::Vault;
use hlb_state::State;

#[derive(Parser)]
#[command(name = "hlb", version, about = "Gestion d'un homelab sur Docker Swarm")]
struct Cli {
    /// Racine du catalogue d'applications.
    #[arg(long, global = true, default_value = "catalog", env = "HLB_CATALOG")]
    catalog: PathBuf,

    /// Base d'état locale du controller.
    #[arg(long, global = true, default_value = "hlb.db", env = "HLB_STATE")]
    state: PathBuf,

    /// Clé maîtresse age. Créée au besoin ; sa perte rend tout irrécupérable.
    #[arg(long, global = true, default_value = "hlb-master.key", env = "HLB_MASTER_KEY")]
    master_key: PathBuf,

    /// URL d'administration PostgreSQL. Sans elle, le provisionnement est ignoré.
    #[arg(long, global = true, env = "HLB_POSTGRES_ADMIN")]
    postgres_admin: Option<String>,

    /// Dépôt restic. Sans lui, toute mise à jour exigeant une sauvegarde est refusée.
    #[arg(long, global = true, env = "HLB_BACKUP_REPO")]
    backup_repo: Option<String>,

    /// URL de PocketID. Sans elle, les clients OIDC ne sont pas provisionnés.
    #[arg(long, global = true, env = "HLB_POCKETID_URL")]
    pocketid_url: Option<String>,

    /// Clé d'API PocketID.
    #[arg(long, global = true, env = "HLB_POCKETID_KEY")]
    pocketid_key: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parcourir et vérifier le catalogue.
    #[command(subcommand)]
    Catalog(CatalogCmd),

    /// Afficher le plan d'installation d'une app, sans rien modifier.
    Plan {
        app: String,
        /// Domaine complet, ex. git.example.fr
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        mail_domain: Option<String>,
    },

    /// Ordre de déploiement déduit des dépendances déclarées.
    Order,

    /// Installer une app. Aperçu par défaut : rien n'est modifié sans --apply.
    Install {
        app: String,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        mail_domain: Option<String>,
        /// Appliquer réellement le plan.
        #[arg(long)]
        apply: bool,
    },

    /// Comparer l'état désiré à l'état réel, et corriger si demandé (§2.1).
    Reconcile {
        /// Corriger les écarts. Sans ce drapeau, détection seule.
        #[arg(long)]
        apply: bool,
    },

    /// Générer la configuration Caddy des apps installées (§6.1).
    Ingress {
        /// Recharger Caddy via son API d'administration au lieu d'afficher.
        #[arg(long)]
        apply: bool,
        /// URL d'administration du Caddy frontal.
        #[arg(long, default_value = "http://localhost:2019", env = "HLB_CADDY_FRONT")]
        front_admin: String,
        /// URL d'administration du Caddy arrière.
        #[arg(long, env = "HLB_CADDY_BACK")]
        back_admin: Option<String>,
    },

    /// Mises à jour disponibles et leur application (§7).
    #[command(subcommand)]
    Update(UpdateCmd),

    /// État des services gérés par HomelabUS.
    Ps,

    /// Actions manuelles en attente, toutes apps confondues (§4.6).
    Todo,

    /// Déclarer une action manuelle traitée. ⚠️ Attestation, pas vérification.
    Ack {
        /// Format : <app>/<id>, tel qu'affiché par `hlb todo`.
        target: String,
    },

    /// Inventaire des secrets : noms et usages, jamais les valeurs.
    Secrets,
}

#[derive(Subcommand)]
enum UpdateCmd {
    /// Interroger les registres. Purement en lecture.
    Check,
    /// Appliquer la mise à jour d'une app.
    Apply {
        app: String,
        /// Passer outre la fenêtre de maintenance.
        #[arg(long)]
        force_window: bool,
    },
}

#[derive(Subcommand)]
enum CatalogCmd {
    /// Lister les apps disponibles.
    List,
    /// Valider tous les manifests et le graphe de dépendances.
    Validate,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("HLB_LOG")
                .unwrap_or_else(|_| "warn".into()),
        )
        .with_target(false)
        .init();

    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("erreur : {e}");
            // La chaîne de causes porte souvent le vrai diagnostic.
            let mut src = e.source();
            while let Some(s) = src {
                eprintln!("  ↳ {s}");
                src = s.source();
            }
            ExitCode::FAILURE
        }
    }
}

/// Construit le fournisseur de sauvegarde, s'il y a de quoi.
///
/// Renvoie `None` si aucun dépôt n'est configuré — ce qui fera refuser toute mise à
/// jour exigeant une sauvegarde (§7). C'est voulu : mieux vaut un refus clair qu'une
/// mise à jour silencieusement non sauvegardée.
async fn build_backup_provider(
    repo: Option<&str>,
    state: &State,
    vault: &Vault,
) -> Result<Option<hlb_backup::ResticBackupProvider<hlb_backup::ContainerRunner>>, Box<dyn std::error::Error>> {
    let Some(location) = repo else {
        return Ok(None);
    };

    // Le mot de passe du dépôt vit dans le coffre, comme tout le reste. Il est créé
    // au premier usage et ne change jamais : le dépôt deviendrait illisible.
    const SECRET: &str = "restic-repo-password";
    let password = match state.secret(SECRET).await? {
        Some(ct) => vault.decrypt(&ct)?,
        None => {
            let p = hlb_secrets::generate_password(hlb_secrets::DEFAULT_PASSWORD_LEN);
            let ct = vault.encrypt(&p)?;
            state
                .store_secret_if_absent(SECRET, &ct, "chiffrement du dépôt de sauvegarde")
                .await?;
            p
        }
    };

    // On capture les volumes maintenant : la fabrique doit rester synchrone.
    let mut par_app: std::collections::BTreeMap<String, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    for (app, _) in state.installed_apps().await? {
        let v = state.volumes_to_backup(&app).await?;
        if !v.is_empty() {
            par_app.insert(app, v);
        }
    }

    let location = location.to_string();
    Ok(Some(hlb_backup::ResticBackupProvider::new(move |app| {
        let volumes = par_app.get(app)?;

        // Chaque volume de l'app est monté dans le conteneur restic, sous un chemin
        // prévisible. Le dépôt lui-même est monté séparément.
        let mut runner = hlb_backup::ContainerRunner::default()
            .mount(&location, "/depot");
        let mut paths = Vec::new();
        for (name, _mountpoint) in volumes {
            // On monte le volume Docker par son nom : le point de montage de l'hôte
            // n'est pas accessible depuis la VM Docker sur macOS.
            runner = runner.mount(name, format!("/donnees/{name}"));
            paths.push(format!("/donnees/{name}"));
        }

        Some((
            hlb_backup::Repository::new(runner, "/depot", password.clone()),
            paths,
        ))
    })))
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Catalog(CatalogCmd::List) => {
            let c = Catalog::load(&cli.catalog)?;
            println!("{} application(s) dans {}\n", c.len(), cli.catalog.display());
            for e in c.entries() {
                let m = &e.manifest;
                println!(
                    "  {:<14} {:<10} {:<22} {:?}",
                    m.metadata.name,
                    format!("{:?}", m.kind).to_lowercase(),
                    m.spec.image.reference(),
                    m.spec.update.channel,
                );
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Catalog(CatalogCmd::Validate) => {
            let c = Catalog::load(&cli.catalog)?;
            let errs = c.validate_all();

            for (name, e) in &errs {
                eprintln!("✗ {name} : {e}");
            }

            // Le graphe est la seconde moitié de la validation : un manifest peut être
            // valide isolément et référencer un service absent du catalogue.
            let graph_err = DependencyGraph::from_manifests(&c.manifests())
                .deployment_order()
                .err();
            if let Some(e) = &graph_err {
                eprintln!("✗ graphe de dépendances : {e}");
            }

            if errs.is_empty() && graph_err.is_none() {
                println!("✓ {} manifest(s) valide(s), graphe cohérent", c.len());
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::FAILURE)
            }
        }

        Command::Order => {
            let c = Catalog::load(&cli.catalog)?;
            let g = DependencyGraph::from_manifests(&c.manifests());
            let order = g.deployment_order()?;

            println!("Ordre de déploiement ({} services) :\n", order.len());
            for (i, name) in order.iter().enumerate() {
                let deps = g
                    .dependencies_of(name)
                    .map(|d| d.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                let suffix = if deps.is_empty() {
                    String::new()
                } else {
                    format!("  ← {}", deps.join(", "))
                };
                println!("  {:>2}. {name}{suffix}", i + 1);
            }
            println!("\nL'arrêt se fait dans l'ordre inverse.");
            Ok(ExitCode::SUCCESS)
        }

        Command::Plan { app, domain, mail_domain } => {
            let c = Catalog::load(&cli.catalog)?;
            let entry = c.get(app)?;

            let params = InstallParams {
                domain: domain.clone(),
                mail_domain: mail_domain.clone(),
                ..Default::default()
            };

            let plan = hlb_resolver::resolve(&entry.manifest, &params)?;

            println!("Plan pour « {app} »  (aucune modification effectuée)\n");
            print!("{plan}");
            Ok(ExitCode::SUCCESS)
        }

        Command::Install { app, domain, mail_domain, apply } => {
            let c = Catalog::load(&cli.catalog)?;
            let entry = c.get(app)?;

            let params = InstallParams {
                domain: domain.clone(),
                mail_domain: mail_domain.clone(),
                ..Default::default()
            };
            let plan = hlb_resolver::resolve(&entry.manifest, &params)?;

            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = State::open(&cli.state).await?;
                // §4.8 — le manifest est figé maintenant : une évolution ultérieure du
                // catalogue ne modifiera pas cette installation.
                state.upsert_app(app, &entry.manifest, domain.as_deref()).await?;

                let orch = SwarmOrchestrator::connect()?;
                let vault = Vault::open_or_init(&cli.master_key)?;

                // PostgreSQL n'est branché que s'il est joignable : sans lui, le
                // provisionnement est marqué non implémenté, jamais simulé.
                let pg = match &cli.postgres_admin {
                    Some(url) => match hlb_platform::PostgresProvisioner::connect(url).await {
                        Ok(p) => Some(p),
                        Err(e) => {
                            eprintln!("⚠️  PostgreSQL injoignable ({e}) — provisionnement ignoré.");
                            None
                        }
                    },
                    None => None,
                };

                let registry = hlb_registry::RegistryClient::new();
                let identity = match (&cli.pocketid_url, &cli.pocketid_key) {
                    (Some(u), Some(k)) => Some(hlb_identity::PocketId::new(u, k)),
                    _ => None,
                };

                let mut exec = Executor::new(&orch, &state)
                    .with_vault(&vault)
                    .with_registry(&registry)
                    .apply(*apply);
                if let Some(p) = &pg {
                    exec = exec.with_postgres(p);
                }
                if let Some(i) = &identity {
                    exec = exec.with_identity(i);
                }
                let out = exec.run(app, &plan).await?;

                if !apply {
                    println!("Aperçu pour « {app} » — aucune modification effectuée.\n");
                    print!("{plan}");
                    println!("\nRelance avec --apply pour exécuter.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                }

                println!(
                    "{} exécutée(s), {} ignorée(s), {} non implémentée(s)",
                    out.executed, out.skipped, out.unimplemented
                );

                if let Some((seq, err)) = &out.failed {
                    eprintln!("\n✗ échec à l'action {} : {err}", seq + 1);
                    eprintln!("  relance la même commande pour reprendre à cette étape.");
                    return Ok(ExitCode::FAILURE);
                }

                if out.unimplemented > 0 {
                    println!(
                        "\n⚠️  {} action(s) nécessitent des briques non encore écrites \
                         (base de données, secrets, OIDC, ingress).",
                        out.unimplemented
                    );
                    println!("   Elles sont enregistrées comme telles, pas comme réussies.");
                }
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::Todo => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = State::open(&cli.state).await?;
                let guides = state.pending_guides().await?;

                if guides.is_empty() {
                    println!("Aucune action manuelle en attente.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                }

                println!("{} action(s) manuelle(s) en attente :\n", guides.len());
                for (app, id, title, blocking) in &guides {
                    println!(
                        "  {} {app} · {title}  [{id}]",
                        if *blocking { "🔴" } else { "🟠" }
                    );
                }
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::Ingress { apply, front_admin, back_admin } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = State::open(&cli.state).await?;

                // Les routes viennent du manifest FIGÉ, pas du catalogue courant :
                // c'est l'état déployé qui fait foi (§4.8).
                let mut routes: Vec<Route> = Vec::new();
                for (name, status) in state.installed_apps().await? {
                    if status == "failed" {
                        continue;
                    }
                    let m = state.app_manifest(&name).await?;
                    let domain = state.app_domain(&name).await?;
                    // §4.6bis — la route ne s'ouvre qu'une fois les actions
                    // manuelles bloquantes traitées.
                    let cleared = state.unverified_blocking(&name).await? == 0;
                    routes.extend(hlb_ingress::routes_from_manifest(
                        &m,
                        domain.as_deref(),
                        cleared,
                    ));
                }

                let cfg = hlb_ingress::Config::default();
                let front = hlb_ingress::render_frontend(&routes, &cfg);
                let back = hlb_ingress::render_backend(&routes, &cfg);

                if !apply {
                    println!("# ═══ Caddy frontend ═══\n{front}");
                    println!("# ═══ Caddy backend ═══\n{back}");
                    println!(
                        "\n{} route(s). Relance avec --apply pour recharger Caddy.",
                        routes.len()
                    );
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                }

                CaddyAdmin::new(front_admin).load_caddyfile(&front).await?;
                println!("✓ Caddy frontal rechargé ({} route(s))", routes.len());

                if let Some(back_url) = back_admin {
                    CaddyAdmin::new(back_url).load_caddyfile(&back).await?;
                    println!("✓ Caddy arrière rechargé");
                } else {
                    println!("ℹ️  --back-admin non fourni : le Caddy arrière n'a pas été rechargé.");
                }
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::Reconcile { apply } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = State::open(&cli.state).await?;
                let orch = SwarmOrchestrator::connect()?;

                let report = Reconciler::new(&orch, &state).reconcile(*apply).await?;

                if report.is_clean() {
                    println!("✓ aucun écart : l'état réel correspond à l'état désiré.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                }

                println!("{} écart(s) détecté(s) :\n", report.drifts.len());
                for d in &report.drifts {
                    let mark = if d.is_correctable() { "🔧" } else { "ℹ️ " };
                    println!("  {mark} {d}");
                }

                if !apply {
                    let n = report.correctable().count();
                    if n > 0 {
                        println!("\n{n} corrigeable(s). Relance avec --apply.");
                    }
                    return Ok(ExitCode::SUCCESS);
                }

                if !report.corrected.is_empty() {
                    println!("\n✓ {} écart(s) corrigé(s).", report.corrected.len());
                }
                if !report.failed.is_empty() {
                    eprintln!("\n✗ {} correction(s) impossible(s) :", report.failed.len());
                    for (d, e) in &report.failed {
                        eprintln!("  {} : {e}", d.app());
                    }
                    return Ok(ExitCode::FAILURE);
                }
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::Ack { target } => {
            let (app, id) = target
                .split_once('/')
                .ok_or("format attendu : <app>/<id> (voir `hlb todo`)")?;

            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = State::open(&cli.state).await?;
                if state.verify_guide(app, id).await? {
                    println!("✓ « {id} » de {app} marquée traitée.");
                    println!(
                        "\n⚠️  C'est une attestation : la vérification automatique \
                         (DNS, HTTP, API…) n'est pas encore implémentée."
                    );
                    Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS)
                } else {
                    eprintln!("aucune action « {id} » en attente pour {app}.");
                    Ok(ExitCode::FAILURE)
                }
            })
        }

        Command::Secrets => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = State::open(&cli.state).await?;
                let vault = Vault::open_or_init(&cli.master_key)?;
                let names = state.secret_names().await?;

                println!("Clé maîtresse : {}", cli.master_key.display());
                println!("Clé publique  : {}\n", vault.public_key());

                if names.is_empty() {
                    println!("Aucun secret stocké.");
                } else {
                    println!("{} secret(s) — les valeurs ne sont jamais affichées :\n", names.len());
                    for (name, purpose) in &names {
                        println!("  {name:<28} {purpose}");
                    }
                }
                println!(
                    "\n🔴 Sans la clé maîtresse, ces secrets et toutes les sauvegardes\n\
                        sont irrécupérables. Garde deux copies hors ligne."
                );
                Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS)
            })
        }

        Command::Update(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = State::open(&cli.state).await?;
                let registry = hlb_registry::RegistryClient::new();
                let now = chrono::Local::now().naive_local();

                let candidates = hlb_updater::check(&state, &registry, &now).await?;

                match cmd {
                    UpdateCmd::Check => {
                        if candidates.is_empty() {
                            println!("✓ tout est à jour.");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                        }
                        println!("{} mise(s) à jour disponible(s) :\n", candidates.len());
                        for c in &candidates {
                            let quand = if c.in_window { "applicable" } else { "hors fenêtre" };
                            let sauv = if c.needs_backup { ", sauvegarde requise" } else { "" };
                            println!("  • {}  [{quand}{sauv}]", c.describe());
                        }
                        println!("\n  hlb update apply <app> pour appliquer.");
                        Ok(ExitCode::SUCCESS)
                    }

                    UpdateCmd::Apply { app, force_window } => {
                        let Some(c) = candidates.iter().find(|c| &c.app == app) else {
                            println!("Rien à mettre à jour pour « {app} ».");
                            return Ok(ExitCode::SUCCESS);
                        };

                        if !c.in_window && !force_window {
                            eprintln!(
                                "« {app} » est hors de sa fenêtre de maintenance.\n                                   --force-window pour passer outre."
                            );
                            return Ok(ExitCode::FAILURE);
                        }

                        // 🔴 §7 — pas de sauvegarde disponible, pas de mise à jour.
                        let vault = Vault::open_or_init(&cli.master_key)?;
                        let provider = build_backup_provider(
                            cli.backup_repo.as_deref(),
                            &state,
                            &vault,
                        )
                        .await?;
                        hlb_updater::authorize(
                            c,
                            provider.as_ref().map(|p| p as &dyn hlb_updater::BackupProvider),
                            *force_window,
                        )?;

                        if let Some(p) = &provider {
                            use hlb_updater::BackupProvider;
                            print!("sauvegarde préalable… ");
                            match p.snapshot(app).await {
                                Ok(id) => println!("✓ {}", &id[..8.min(id.len())]),
                                Err(e) => {
                                    eprintln!("✗");
                                    eprintln!("  {e}");
                                    eprintln!("  mise à jour abandonnée : pas de sauvegarde, pas de bascule.");
                                    return Ok(ExitCode::FAILURE);
                                }
                            }
                        }

                        let orch = SwarmOrchestrator::connect()?;
                        println!("{}…", c.describe());
                        let outcome = hlb_updater::apply(&orch, &state, c, 180).await?;

                        match outcome {
                            hlb_updater::UpdateOutcome::Applied { digest } => {
                                println!("✓ appliquée — {}", &digest[..23.min(digest.len())]);
                                Ok(ExitCode::SUCCESS)
                            }
                            hlb_updater::UpdateOutcome::RolledBack { reason } => {
                                eprintln!("↩ Swarm a annulé : {reason}");
                                eprintln!("  le service tourne toujours dans son ancienne version.");
                                Ok(ExitCode::FAILURE)
                            }
                            hlb_updater::UpdateOutcome::Paused => {
                                eprintln!("⏸ bascule en pause — intervention nécessaire.");
                                Ok(ExitCode::FAILURE)
                            }
                            hlb_updater::UpdateOutcome::Inconclusive => {
                                eprintln!("? issue indéterminée dans le délai imparti.");
                                eprintln!("  vérifie avec hlb ps avant de relancer.");
                                Ok(ExitCode::FAILURE)
                            }
                        }
                    }
                }
            })
        }

        Command::Ps => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let o = SwarmOrchestrator::connect()?;
                let services = o.list().await?;

                if services.is_empty() {
                    println!("Aucun service géré par HomelabUS.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                }

                println!("{:<20} {:>9}  IMAGE", "SERVICE", "RÉPLIQUES");
                for s in services {
                    println!(
                        "{:<20} {:>4}/{:<4}  {}",
                        s.name, s.running_replicas, s.desired_replicas, s.image
                    );
                }
                Ok(ExitCode::SUCCESS)
            })
        }
    }
}
