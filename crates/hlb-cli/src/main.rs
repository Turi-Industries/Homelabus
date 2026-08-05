//! `hlb` — l'interface de première classe.
//!
//! Principe du §11bis : **le CLI fait tout, l'UI n'est qu'un client de l'API.** Ça
//! garantit la scriptabilité, et le débogage quand l'UI est cassée.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use hlb_catalog::Catalog;
use hlb_orchestrator::{Orchestrator, SwarmOrchestrator};
use hlb_resolver::{DependencyGraph, InstallParams};

#[derive(Parser)]
#[command(name = "hlb", version, about = "Gestion d'un homelab sur Docker Swarm")]
struct Cli {
    /// Racine du catalogue d'applications.
    #[arg(long, global = true, default_value = "catalog", env = "HLB_CATALOG")]
    catalog: PathBuf,

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

    /// État des services gérés par HomelabUS.
    Ps,
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
