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

    /// Miroir Git de l'état désiré (§2.3). Absent : pas d'historique.
    #[arg(long, global = true, env = "HLB_GIT_MIRROR")]
    git_mirror: Option<PathBuf>,

    /// API d'administration du Caddy frontal. Sans elle, l'app est déployée mais
    /// pas routée — ce qui est un état légitime, pas une erreur.
    #[arg(long, global = true, env = "HLB_CADDY_ADMIN")]
    caddy_admin: Option<String>,

    /// API locale de CrowdSec. Sans elle, le Caddyfile est généré sans videur.
    #[arg(long, global = true, default_value = "http://crowdsec:8080", env = "HLB_CROWDSEC_URL")]
    crowdsec_url: String,

    /// URL de Stalwart. Sans elle, les boîtes mail ne sont pas provisionnées.
    #[arg(long, global = true, env = "HLB_STALWART_URL")]
    stalwart_url: Option<String>,

    /// Compte d'administration Stalwart.
    #[arg(long, global = true, env = "HLB_STALWART_ADMIN")]
    stalwart_admin: Option<String>,

    /// Mot de passe de ce compte. ⚠️ Préfère la variable d'environnement : un mot
    /// de passe en ligne de commande est lisible par tout utilisateur de la machine.
    #[arg(long, global = true, env = "HLB_STALWART_PASSWORD")]
    stalwart_password: Option<String>,

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

    /// Sauvegardes : état, exécution et vérification (§8).
    #[command(subcommand)]
    Backup(BackupCmd),

    /// Cluster : initialisation, état et quorum (§2ter, §10.3).
    #[command(subcommand)]
    Cluster(ClusterCmd),

    /// Nœuds : préchecks et dépendances (§2ter).
    #[command(subcommand)]
    Node(NodeCmd),

    /// État des services gérés par HomelabUS.
    Ps,

    /// Actions manuelles en attente, toutes apps confondues (§4.6).
    Todo {
        /// Exécuter les vérifications déclarées et marquer ce qui est constaté fait.
        #[arg(long)]
        verify: bool,
    },

    /// Déclarer une action manuelle traitée. ⚠️ Attestation, pas vérification.
    Ack {
        /// Format : <app>/<id>, tel qu'affiché par `hlb todo`.
        target: String,
        /// Attester malgré une vérification qui dit le contraire.
        #[arg(long)]
        force: bool,
    },

    /// Mesh WireGuard entre nœuds (§2ter, §6.3).
    #[command(subcommand)]
    Mesh(MeshCmd),

    /// Videur CrowdSec : enrôlement et état (§8bis).
    #[command(subcommand)]
    Crowdsec(CrowdsecCmd),

    /// Inventaire des secrets : noms et usages, jamais les valeurs.
    Secrets,

    /// Journal d'audit : qui a fait quoi, quand (§9).
    Audit {
        #[arg(long, default_value = "30")]
        limit: usize,
    },

    /// Historique des changements de configuration (§2.3).
    History {
        #[arg(long, default_value = "20")]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum ClusterCmd {
    /// Initialiser un Swarm sur cette machine. Idempotent.
    Init {
        /// Adresse annoncée aux autres nœuds. 🔴 Indispensable en multi-interfaces.
        #[arg(long)]
        advertise_addr: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// Nœuds, rôles, tiers et santé du quorum.
    Status,
    /// 🔴 Chiffrer les secrets Swarm au repos (§9). La clé va au coffre.
    Autolock {
        #[arg(long)]
        apply: bool,
    },
    /// La commande à lancer sur une machine pour la rattacher.
    JoinCommand {
        /// `manager` ou `worker`. Par défaut : ce que le profil recommande.
        #[arg(long)]
        role: Option<String>,
    },
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Vérifier qu'une machine peut accueillir un nœud. Ne modifie RIEN.
    Check {
        /// Hôte SSH. Absent : la machine locale.
        host: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        identity: Option<String>,
    },
    /// Poser le tier d'un nœud, déduit de sa mémoire (§2bis.2).
    Tier {
        /// Nom du nœud, tel qu'affiché par `hlb cluster status`.
        node: String,
        /// Forcer une valeur au lieu de la déduire.
        #[arg(long)]
        set: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// Ce qui manque, et ce qui sera installé. Aperçu par défaut.
    Deps {
        host: Option<String>,
        #[arg(long)]
        user: Option<String>,
        /// Installer réellement les paquets manquants.
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum BackupCmd {
    /// Ce qui est dû, en retard, ou vérifié — sans rien exécuter.
    Status,
    /// Sauvegarder les apps dues (ou toutes avec --force).
    Run {
        #[arg(long)]
        force: bool,
    },
    /// 🔴 Restaurer un instantané dans un espace jetable et comparer (§8.3).
    Verify {
        /// Limiter à une app.
        app: Option<String>,
    },
    /// Archivage WAL et restauration à un instant précis (§8.1).
    #[command(subcommand)]
    Pitr(PitrCmd),
}

#[derive(Subcommand)]
enum PitrCmd {
    /// Les réglages PostgreSQL à poser pour activer l'archivage WAL.
    Config {
        /// Répertoire d'archivage, monté dans le conteneur PostgreSQL.
        #[arg(long, default_value = "/archive/wal")]
        dir: String,
    },
    /// La fenêtre réellement restaurable, d'après ce qui est conservé.
    Window {
        #[arg(long, default_value = "/archive/wal")]
        dir: String,
    },
    /// 🔴 Produire une sauvegarde de base. Sans elle, le WAL ne restaure rien.
    Base {
        /// Répertoire recevant les sauvegardes de base.
        #[arg(long, default_value = "/archive/base")]
        dest: String,
        /// Réseau Docker sur lequel l'hôte de l'URL est résolvable.
        #[arg(long, default_value = "hlb_platform")]
        network: String,
        /// Exécuter réellement. Sans ce drapeau, on n'affiche que ce qui serait fait.
        #[arg(long)]
        apply: bool,
    },
    /// Préparer une restauration à un instant donné. N'exécute RIEN.
    Plan {
        /// Instant cible en UTC : « 2026-08-16 14:04:00 ».
        target: String,
        #[arg(long, default_value = "/archive/wal")]
        dir: String,
    },
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
enum MeshCmd {
    /// Ajouter un nœud au mesh et produire sa configuration.
    Add {
        /// Nom du nœud, tel qu'affiché par `hlb cluster status`.
        node: String,
        /// Adresse publique joignable. Absente = nœud derrière NAT.
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// La configuration `wg-quick` d'un nœud déjà enregistré.
    Show { node: String },
    /// Les nœuds du mesh et leurs adresses.
    List,
}

#[derive(Subcommand)]
enum CrowdsecCmd {
    /// Enrôler le videur et déposer sa clé au coffre. Sans lui, rien n'est bloqué.
    Enroll {
        /// Service Swarm portant CrowdSec.
        #[arg(long, default_value = "crowdsec")]
        service: String,
        #[arg(long)]
        apply: bool,
    },
    /// Le filtrage est-il RÉELLEMENT actif ?
    Status {
        #[arg(long, default_value = "crowdsec")]
        service: String,
    },
}

#[derive(Subcommand)]
enum CatalogCmd {
    /// Lister les apps disponibles.
    List,
    /// Valider tous les manifests et le graphe de dépendances.
    Validate,
}

/// L'instant présent, en secondes depuis l'époque.
fn maintenant() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Nom du secret portant la clé de déverrouillage du Swarm.
const SECRET_AUTOLOCK: &str = "swarm-unlock-key";

/// Restauration à un instant précis (§8.1).
///
/// Aucun sous-verbe n'exécute quoi que ce soit : le PITR se termine par une décision
/// humaine sur une base de données de production. Le CLI prépare, affiche et vérifie
/// la faisabilité ; il ne restaure pas à votre place.
async fn pitr(
    cmd: &PitrCmd,
    state_path: &std::path::Path,
    admin_url: Option<&str>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    use hlb_backup::pitr;

    match cmd {
        PitrCmd::Base { dest, network, apply } => {
            let state = State::open(state_path).await?;

            // 🔴 Les identifiants viennent de `--postgres-admin`, la MÊME source que
            // le provisionnement des bases. Les redemander séparément ferait diverger
            // deux vérités, et la sauvegarde casserait le jour où l'une change.
            let Some(url) = admin_url else {
                eprintln!("Aucune URL PostgreSQL — utilise --postgres-admin.");
                eprintln!();
                eprintln!("  Forme attendue :");
                eprintln!("    postgres://utilisateur:motdepasse@hôte:5432/postgres");
                eprintln!();
                eprintln!("  🔴 L'utilisateur doit avoir l'attribut REPLICATION : une");
                eprintln!("     sauvegarde de base passe par le protocole de réplication,");
                eprintln!("     pas par une connexion SQL ordinaire.");
                return Ok(ExitCode::FAILURE);
            };

            let Some(creds) = pitr::parse_pg_url(url) else {
                eprintln!("URL PostgreSQL illisible : « {url} »");
                eprintln!("Attendu : postgres://utilisateur:motdepasse@hôte:5432/base");
                return Ok(ExitCode::FAILURE);
            };

            let (host, user, password) = (creds.host, creds.user, creds.password);
            let at = maintenant();
            let nom = pitr::basebackup::directory_name(at);

            if !apply {
                println!("Produirait une sauvegarde de base :");
                println!("  destination : {dest}/{nom}");
                println!("  serveur     : {user}@{host}:{} (réseau {network})", creds.port);
                println!();
                println!("  Elle streame le WAL pendant la copie, sinon le résultat");
                println!("  serait incohérent et PostgreSQL refuserait de démarrer.");
                println!();
                println!("  ⚠️  Prévois la place : c'est une copie COMPLÈTE du répertoire");
                println!("     de données, pas un incrément.");
                println!();
                println!("  Relance avec --apply.");
                return Ok(ExitCode::SUCCESS);
            }

            let cible = pitr::basebackup::Target::new(dest, &host)
                .credentials(&user, &password)
                .network(network);

            print!("Sauvegarde de base en cours… ");
            use std::io::Write as _;
            let _ = std::io::stdout().flush();

            match pitr::basebackup::run(&cible, at).await {
                Ok(id) => {
                    // 🔴 L'enregistrement est ce qui rend la base VISIBLE pour
                    // `pitr window` et `pitr plan`. Sans lui, la sauvegarde existe sur
                    // le disque et le système continue de dire qu'il n'en a aucune.
                    state
                        .record_backup("postgres", "pg-basebackup", Some(&id), None)
                        .await?;
                    state
                        .audit("cli", ACTEUR_ROLE, "pg-basebackup", &id, "ok", None)
                        .await?;
                    println!("✓ {id}");
                    println!();
                    println!("Fenêtre restaurable mise à jour : hlb backup pitr window");
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    // L'échec est enregistré : `base_backups` l'exclut, donc la
                    // fenêtre annoncée n'inclut pas une base qui n'existe pas.
                    state
                        .record_backup("postgres", "pg-basebackup", None, Some(&e.to_string()))
                        .await?;
                    println!("✗");
                    eprintln!("{e}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }

        PitrCmd::Config { dir } => {
            let a = pitr::WalArchive::new(dir);
            println!("{}", a.render_settings());
            println!("# ─────────────────────────────────────────────────────────────");
            println!("# 🔴 AVANT d'activer : {dir} doit exister, être accessible en");
            println!("#    écriture au conteneur, et avoir de la place.");
            println!("#");
            println!("#    Un archive_command qui échoue ne PERD pas les journaux :");
            println!("#    il les garde. pg_wal grossit alors sans limite jusqu'à");
            println!("#    saturer le disque, et PostgreSQL s'arrête net.");
            println!("#    Archiver vers une destination cassée est plus dangereux");
            println!("#    que ne pas archiver du tout.");
            println!("#");
            println!("#    Puis : une sauvegarde de base est OBLIGATOIRE. Le WAL seul");
            println!("#    ne restaure rien.");
            println!("#      hlb backup pitr base --apply");
            println!("#");
            println!("# 🔴 ET pg_hba.conf, que postgresql.conf ne remplace PAS :");
            println!("#      host replication all all scram-sha-256");
            println!("#");
            println!("#    pg_basebackup passe par le protocole de RÉPLICATION, que");
            println!("#    pg_hba traite comme une base à part. Un utilisateur qui se");
            println!("#    connecte très bien en psql est refusé ici. L'image postgres");
            println!("#    officielle ne l'autorise que depuis 127.0.0.1 — donc jamais");
            println!("#    depuis un autre conteneur.");
            Ok(ExitCode::SUCCESS)
        }

        PitrCmd::Window { dir } => {
            let state = State::open(state_path).await?;
            let bases = charger_bases(&state).await?;

            if bases.is_empty() {
                println!("Aucune sauvegarde de base enregistrée.");
                println!();
                println!("🔴 Sans elle, les journaux WAL ne restaurent RIEN. La fenêtre");
                println!("   restaurable est donc vide, même si l'archivage tourne.");
                println!();
                println!("   hlb backup pitr config    # les réglages à poser");
                return Ok(ExitCode::SUCCESS);
            }

            println!("{} sauvegarde(s) de base :", bases.len());
            for b in &bases {
                println!("  {}  {}", pitr::iso8601(b.finished_at), b.id);
            }
            println!();

            // La borne haute est CONSTATÉE dans l'archive, pas déduite de la dernière
            // base : sans inventaire on sous-estimerait la fenêtre, et l'on refuserait
            // des restaurations pourtant possibles.
            let (couverture, note) = match pitr::scan_archive(std::path::Path::new(dir)) {
                Ok(segs) => match pitr::wal_coverage(&segs) {
                    Some(c) => (c, format!("{} segment(s) WAL archivé(s)", segs.len())),
                    None => (
                        bases.iter().map(|b| b.finished_at).max().unwrap_or(0),
                        format!("🔴 {dir} est vide — aucun journal archivé"),
                    ),
                },
                Err(e) => (
                    bases.iter().map(|b| b.finished_at).max().unwrap_or(0),
                    format!("⚠️  archive illisible ({e}) — borne limitée à la dernière base"),
                ),
            };

            match pitr::recoverable_window(&bases, couverture) {
                Some(w) => {
                    println!("Fenêtre restaurable : {}", w.describe());
                    println!("  {note}");
                    println!();
                    println!(
                        "  Purge du WAL possible avant : {}",
                        pitr::iso8601(pitr::wal_prunable_before(&bases).unwrap_or(w.earliest))
                    );
                }
                None => {
                    println!("Aucune fenêtre restaurable.");
                    println!("  {note}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        PitrCmd::Plan { target, dir } => {
            let Some(cible) = pitr::parse_utc(target) else {
                eprintln!("Cible illisible : « {target} »");
                eprintln!("Attendu, en UTC : « 2026-08-16 14:04:00 »");
                return Ok(ExitCode::FAILURE);
            };

            let state = State::open(state_path).await?;
            let bases = charger_bases(&state).await?;

            // Même règle que pour `window` : la couverture est constatée. Une cible
            // au-delà du dernier segment archivé doit être refusée, pas acceptée en
            // silence — elle donnerait une base périmée sans le dire.
            let couverture = pitr::scan_archive(std::path::Path::new(dir))
                .ok()
                .and_then(|s| pitr::wal_coverage(&s))
                .unwrap_or_else(|| bases.iter().map(|b| b.finished_at).max().unwrap_or(0));

            let archive = pitr::WalArchive::new(dir);
            match pitr::plan_recovery(&bases, couverture, cible, &archive) {
                Ok(p) => {
                    println!("Restauration à {}", pitr::iso8601(cible));
                    println!("  {}", p.describe());
                    println!();
                    println!("Marche à suivre :");
                    println!("  1. Arrêter PostgreSQL.");
                    println!("  2. Déplacer le répertoire de données actuel — NE PAS le");
                    println!("     supprimer : c'est le seul filet si la reprise échoue.");
                    println!("  3. Restaurer la base {} à sa place.", p.base.id);
                    println!("  4. Écrire ceci dans postgresql.auto.conf :");
                    println!();
                    for l in p.config.lines() {
                        println!("     {l}");
                    }
                    println!();
                    println!("  5. Créer un fichier VIDE `recovery.signal` dans le");
                    println!("     répertoire de données. Sans lui, PostgreSQL démarre");
                    println!("     normalement et ignore tout ce qui précède.");
                    println!("  6. Démarrer et surveiller les journaux du serveur.");
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!("{e}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}

/// Les sauvegardes de base de toutes les apps confondues.
///
/// Le PITR porte sur l'instance PostgreSQL, pas sur une app : toutes les bases
/// applicatives partagent le même WAL (§4.3).
async fn charger_bases(
    state: &State,
) -> Result<Vec<hlb_backup::pitr::BaseBackup>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for (app, _) in state.installed_apps().await? {
        for (id, at) in state.base_backups(&app).await? {
            out.push(hlb_backup::pitr::BaseBackup { id, finished_at: at });
        }
    }
    for (id, at) in state.base_backups("postgres").await? {
        out.push(hlb_backup::pitr::BaseBackup { id, finished_at: at });
    }
    out.sort_by_key(|b| b.finished_at);
    out.dedup_by(|a, b| a.id == b.id);
    Ok(out)
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
/// Le mot de passe du dépôt restic.
///
/// Il vit dans le coffre, comme tout le reste. Créé au premier usage et **jamais
/// changé** : le dépôt deviendrait illisible, y compris ses instantanés déjà écrits.
///
/// Partagé entre la sauvegarde et la vérification : les deux doivent forcément
/// utiliser le même, sinon la vérification échouerait à relire ce que la sauvegarde
/// vient d'écrire — et l'on conclurait à une corruption qui n'existe pas.
async fn restic_password(
    state: &State,
    vault: &Vault,
) -> Result<String, Box<dyn std::error::Error>> {
    const SECRET: &str = "restic-repo-password";
    Ok(match state.secret(SECRET).await? {
        Some(ct) => vault.decrypt(&ct)?,
        None => {
            let p = hlb_secrets::generate_password(hlb_secrets::DEFAULT_PASSWORD_LEN);
            let ct = vault.encrypt(&p)?;
            state
                .store_secret_if_absent(SECRET, &ct, "chiffrement du dépôt de sauvegarde")
                .await?;
            p
        }
    })
}

async fn build_backup_provider(
    repo: Option<&str>,
    state: &State,
    vault: &Vault,
) -> Result<Option<hlb_backup::ResticBackupProvider<hlb_backup::ContainerRunner>>, Box<dyn std::error::Error>> {
    let Some(location) = repo else {
        return Ok(None);
    };

    let password = restic_password(state, vault).await?;

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

/// Âge lisible : « 3 h », « 2 j ».
fn fmt_age(d: std::time::Duration) -> String {
    let s = d.as_secs();
    if s < 90 {
        format!("{s} s")
    } else if s < 5400 {
        format!("{} min", s / 60)
    } else if s < 172_800 {
        format!("{} h", s / 3600)
    } else {
        format!("{} j", s / 86400)
    }
}

/// Écrit l'état désiré dans le miroir Git (§2.3).
async fn export_git(
    chemin: &std::path::Path,
    state: &State,
    message: &str,
) -> Result<hlb_gitops::ExportReport, Box<dyn std::error::Error>> {
    let mut apps = Vec::new();
    for (name, status) in state.installed_apps().await? {
        // C'est le manifest FIGÉ qu'on archive, pas le catalogue courant (§4.8).
        let m = state.app_manifest(&name).await?;
        apps.push((name, status, m));
    }
    let mirror = hlb_gitops::GitMirror::open_or_init(chemin)?;
    Ok(mirror.export(&apps, message)?)
}

/// Le CLI s'exécute localement : quiconque le lance a déjà accès à la machine et à
/// la clé maîtresse. Le RBAC (§9ter) protège l'API, pas la ligne de commande — mais
/// les actions sont journalisées de la même façon.
const ACTEUR_ROLE: hlb_types::Role = hlb_types::Role::Admin;

/// Local ou distant, selon qu'un hôte est donné.
fn build_runner(
    host: Option<&str>,
    user: Option<&str>,
    port: Option<u16>,
    identity: Option<&str>,
) -> Box<dyn hlb_bootstrap::Runner> {
    match host {
        None => Box::new(hlb_bootstrap::LocalRunner),
        Some(h) => {
            let mut r = hlb_bootstrap::SshRunner::new(h);
            if let Some(u) = user {
                r = r.user(u);
            }
            if let Some(p) = port {
                r = r.port(p);
            }
            if let Some(i) = identity {
                r = r.identity(i);
            }
            Box::new(r)
        }
    }
}

/// Sonde la version de chaque dépendance connue.
async fn observe_dependencies(
    runner: &dyn hlb_bootstrap::Runner,
) -> Result<Vec<(&'static str, Option<String>)>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for dep in hlb_bootstrap::deps::BASE {
        // `--version` est la convention la plus répandue ; on se contente de
        // constater la présence quand elle n'est pas respectée.
        let v = runner
            .run(&[dep.name.to_string(), "--version".to_string()])
            .await
            .ok()
            .filter(|o| o.ok())
            .and_then(|o| o.first_line())
            .map(|l| extract_version(&l));
        out.push((dep.name, v));
    }
    Ok(out)
}

/// Extrait le premier groupe qui ressemble à une version d'une ligne comme
/// « Docker version 27.3.1, build ce1223035a ».
fn extract_version(line: &str) -> String {
    line.split_whitespace()
        .find(|t| {
            let t = t.trim_start_matches('v').trim_end_matches(',');
            t.contains('.') && t.chars().next().is_some_and(|c| c.is_ascii_digit())
        })
        .map(|t| t.trim_start_matches('v').trim_end_matches(',').to_string())
        .unwrap_or_else(|| line.to_string())
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

            let plan = hlb_resolver::resolve_with_guide(&entry.manifest, &entry.guide, &params)?;

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
            let plan = hlb_resolver::resolve_with_guide(&entry.manifest, &entry.guide, &params)?;

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
                let caddy = cli.caddy_admin.as_ref().map(CaddyAdmin::new);

                // Stalwart : même règle que les autres. Sans identifiants, le
                // provisionnement des boîtes reste « non implémenté », jamais simulé.
                let mail = match (&cli.stalwart_url, &cli.stalwart_admin, &cli.stalwart_password) {
                    (Some(u), Some(a), Some(p)) => Some(hlb_mail::Stalwart::new(
                        u,
                        hlb_mail::Auth::Basic { user: a.clone(), password: p.clone() },
                    )),
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
                if let Some(c) = &caddy {
                    exec = exec.with_ingress(c);
                }
                if let Some(m) = &mail {
                    exec = exec.with_mail(m);
                }
                exec = exec.with_crowdsec(&cli.crowdsec_url);
                let out = match exec.run(app, &plan).await {
                    Ok(o) => o,
                    Err(e) => {
                        // Un guide bloquant n'est pas un échec : c'est un refus
                        // délibéré du système. Les confondre rendrait le journal
                        // inexploitable — on ne saurait plus distinguer « ça a
                        // planté » de « on a protégé l'utilisateur ».
                        let issue = match &e {
                            hlb_engine::Error::BlockedByGuide { .. } => "refused",
                            _ => "failed",
                        };
                        state
                            .audit("cli", ACTEUR_ROLE, "install", app, issue, Some(&e.to_string()))
                            .await?;
                        return Err(e.into());
                    }
                };

                if *apply {
                    let issue = if out.is_success() { "ok" } else { "failed" };
                    state
                        .audit("cli", ACTEUR_ROLE, "install", app, issue, None)
                        .await?;
                }

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

                // §2.3 — miroir Git : l'historique de la config, indépendant de la
                // base d'état. Un échec ici ne doit pas faire échouer l'installation :
                // l'app est déployée, c'est ce qui compte.
                if let Some(chemin) = &cli.git_mirror {
                    match export_git(chemin, &state, &format!("installation de {app}")).await {
                        Ok(r) if r.changed() => println!("✓ config archivée dans Git"),
                        Ok(_) => {}
                        Err(e) => eprintln!("⚠️  miroir Git non mis à jour : {e}"),
                    }
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

        Command::Todo { verify } => {
            let catalogue = Catalog::load(&cli.catalog).ok();
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = State::open(&cli.state).await?;
                let guides = state.pending_guides().await?;

                if guides.is_empty() {
                    println!("Aucune action manuelle en attente.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                }

                println!("{} action(s) manuelle(s) en attente :\n", guides.len());

                let verifier = hlb_guide::Verifier::default();
                let mut constatees = 0;

                for (app, id, title, blocking) in &guides {
                    let marque = if *blocking { "🔴" } else { "🟠" };

                    if !verify {
                        println!("  {marque} {app} · {title}  [{id}]");
                        continue;
                    }

                    // La déclaration de l'étape vient du catalogue ; son état, de la
                    // base. On a besoin des deux pour vérifier.
                    let etape = catalogue
                        .as_ref()
                        .and_then(|c| c.get(app).ok())
                        .and_then(|e| e.guide.steps.iter().find(|s| &s.id == id).cloned());

                    let Some(etape) = etape else {
                        println!("  {marque} {app} · {title}  [{id}]  (déclaration introuvable)");
                        continue;
                    };

                    let domaine = state.app_domain(app).await?.unwrap_or_default();
                    let vars = [("domain", domaine.as_str())];
                    let issue = verifier.check(&etape, &vars).await;

                    println!("  {marque} {app} · {title}  [{id}]");
                    println!("       {}", issue.describe());

                    if issue.is_verified() {
                        state.verify_guide(app, id).await?;
                        constatees += 1;
                    }
                }

                if *verify {
                    println!("\n{constatees} action(s) constatée(s) faite(s) et retirée(s).");
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

                // 🔴 CrowdSec n'est activé QUE si sa clé est au coffre. Générer avec
                // une clé vide donnerait un Caddyfile valide, un Caddy qui démarre, et
                // plus aucun bannissement — sans erreur nulle part.
                let mut cfg = hlb_ingress::Config::default();
                match state.secret(hlb_ingress::crowdsec::SECRET_NAME).await? {
                    Some(ct) => {
                        let vault = Vault::open_or_init(&cli.master_key)?;
                        let cle = vault.decrypt(&ct)?;
                        if hlb_ingress::crowdsec::looks_like_key(&cle) {
                            cfg.crowdsec = Some(hlb_ingress::CrowdSec {
                                api_url: cli.crowdsec_url.clone(),
                                api_key: cle,
                            });
                            println!("Videur CrowdSec : actif ({})", cli.crowdsec_url);
                        } else {
                            eprintln!("🔴 clé de videur invalide au coffre — filtrage DÉSACTIVÉ.");
                            eprintln!("   hlb crowdsec status");
                        }
                    }
                    None => {
                        eprintln!("⚠️  CrowdSec non enrôlé : le trafic ne sera pas filtré.");
                        eprintln!("   hlb crowdsec enroll --apply");
                    }
                }

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

        Command::Ack { target, force } => {
            let (app, id) = target
                .split_once('/')
                .ok_or("format attendu : <app>/<id> (voir `hlb todo`)")?;

            let catalogue = Catalog::load(&cli.catalog).ok();
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = State::open(&cli.state).await?;

                // Si l'étape est vérifiable, on vérifie AVANT d'accepter l'attestation.
                let etape = catalogue
                    .as_ref()
                    .and_then(|c| c.get(app).ok())
                    .and_then(|e| e.guide.steps.iter().find(|s| s.id == id).cloned());

                let mut atteste = true;
                if let Some(etape) = etape {
                    let domaine = state.app_domain(app).await?.unwrap_or_default();
                    let issue = hlb_guide::Verifier::default()
                        .check(&etape, &[("domain", domaine.as_str())])
                        .await;

                    match &issue {
                        o if o.is_verified() => {
                            println!("✓ constaté : {}", o.describe());
                            atteste = false;
                        }
                        // 🔴 On a constaté que ce n'est PAS fait. Attester le
                        // contraire n'a aucun sens : c'est exactement le mensonge
                        // que le système doit refuser.
                        o if !o.may_attest() && !force => {
                            eprintln!("{}", o.describe());
                            eprintln!(
                                "\nLa vérification dit que ce n'est pas fait. \
                                 --force pour attester quand même."
                            );
                            return Ok(ExitCode::FAILURE);
                        }
                        _ => {}
                    }
                }

                if state.verify_guide(app, id).await? {
                    println!("✓ « {id} » de {app} marquée traitée.");
                    if atteste {
                        println!(
                            "\n⚠️  Attestation : cette étape n'est pas vérifiable \
                             automatiquement, HomelabUS te croit sur parole."
                        );
                    }
                    Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS)
                } else {
                    eprintln!("aucune action « {id} » en attente pour {app}.");
                    Ok(ExitCode::FAILURE)
                }
            })
        }

        Command::Audit { limit } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = State::open(&cli.state).await?;
                let t = state.audit_trail(*limit).await?;

                if t.is_empty() {
                    println!("Journal d'audit vide.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                }

                println!("{:<20} {:<10} {:<12} {:<16} ISSUE", "QUAND", "ACTEUR", "ACTION", "CIBLE");
                for (at, actor, action, target, outcome) in &t {
                    let marque = match outcome.as_str() {
                        "ok" => "✓",
                        "refused" => "⛔",
                        _ => "✗",
                    };
                    println!("{at:<20} {actor:<10} {action:<12} {target:<16} {marque} {outcome}");
                }
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::History { limit } => {
            let Some(chemin) = &cli.git_mirror else {
                eprintln!(
                    "aucun miroir Git configuré — utilise --git-mirror ou HLB_GIT_MIRROR"
                );
                return Ok(ExitCode::FAILURE);
            };

            let m = hlb_gitops::GitMirror::open_or_init(chemin)?;
            let h = m.history(*limit)?;
            if h.is_empty() {
                println!("Aucun changement enregistré.");
                return Ok(ExitCode::SUCCESS);
            }

            println!("{} changement(s), du plus récent au plus ancien :\n", h.len());
            for (id, msg) in &h {
                println!("  {id}  {msg}");
            }
            println!("\n  git -C {} show <id>   pour le diff complet", chemin.display());
            Ok(ExitCode::SUCCESS)
        }

        Command::Mesh(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = State::open(&cli.state).await?;
                let vault = Vault::open_or_init(&cli.master_key)?;

                // La topologie vit au coffre comme le reste. Les clés publiques et les
                // adresses ne sont pas secrètes, mais les garder avec les clés PRIVÉES
                // évite deux sources de vérité qui divergeraient.
                const TOPOLOGIE: &str = "mesh-topology";

                let mut mesh = match state.secret(TOPOLOGIE).await? {
                    Some(ct) => {
                        let pairs: Vec<hlb_mesh::Peer> =
                            serde_json::from_str(&vault.decrypt(&ct)?)?;
                        hlb_mesh::MeshConfig::from_peers([10, 42, 0], 51820, pairs)
                    }
                    None => hlb_mesh::MeshConfig::default(),
                };

                match cmd {
                    MeshCmd::List => {
                        let pairs: Vec<_> = mesh.peers().collect();
                        if pairs.is_empty() {
                            println!("Aucun nœud dans le mesh.");
                            println!("  hlb mesh add <nœud> --endpoint <ip-publique> --apply");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                        }

                        println!("Mesh {} — {} nœud(s)", mesh.cidr(), pairs.len());
                        for p in &pairs {
                            println!(
                                "  {:<15} {}  {}",
                                p.mesh_ip.to_string(),
                                p.name,
                                match &p.endpoint {
                                    Some(e) => format!("↔ {e}:{}", mesh.port()),
                                    None => "(derrière NAT)".to_string(),
                                }
                            );
                        }

                        if pairs.iter().all(|p| p.endpoint.is_none()) {
                            println!();
                            println!("🔴 Aucun nœud n'a d'adresse publique : personne ne peut");
                            println!("   initier de tunnel. Le mesh ne s'établira jamais.");
                            return Ok(ExitCode::FAILURE);
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    MeshCmd::Show { node } => {
                        let Some(ct) = state.secret(&format!("mesh-key-{node}")).await? else {
                            eprintln!("Le nœud « {node} » n'est pas dans le mesh.");
                            eprintln!("  hlb mesh add {node} --apply");
                            return Ok(ExitCode::FAILURE);
                        };
                        let privee = vault.decrypt(&ct)?;

                        match mesh.render_for(node, &privee) {
                            Some(c) => {
                                println!("{c}");
                                println!("# À déposer en /etc/wireguard/hlb0.conf sur {node}, puis :");
                                println!("#   chmod 600 /etc/wireguard/hlb0.conf");
                                println!("#   systemctl enable --now wg-quick@hlb0");
                                println!("#");
                                println!("# 🔴 Puis faire écouter Swarm sur l'adresse du mesh :");
                                println!("#   --advertise-addr {}", mesh.advertise_addr_for(node).unwrap_or_default());
                                println!("#   Sans ça, les ports 2377/7946/4789 restent exposés");
                                println!("#   sur l'interface publique — 4789 n'a AUCUNE");
                                println!("#   authentification.");
                                Ok(ExitCode::SUCCESS)
                            }
                            None => {
                                eprintln!("Topologie incohérente : « {node} » a une clé mais pas de pair.");
                                Ok(ExitCode::FAILURE)
                            }
                        }
                    }

                    MeshCmd::Add { node, endpoint, apply } => {
                        if mesh.get(node).is_some() {
                            println!("✓ « {node} » est déjà dans le mesh.");
                            println!("  hlb mesh show {node}   # sa configuration");
                            return Ok(ExitCode::SUCCESS);
                        }

                        if !apply {
                            println!("Ajouterait « {node} » au mesh {}.", mesh.cidr());
                            match endpoint {
                                Some(e) => println!("  joignable en {e}:{}", mesh.port()),
                                None => {
                                    println!("  ⚠️  sans --endpoint : nœud considéré derrière NAT.");
                                    println!("     Il n'écoutera pas et devra initier ses tunnels.");
                                    println!("     Au moins UN nœud doit avoir une adresse publique.");
                                }
                            }
                            println!();
                            println!("  Une paire de clés sera générée ; la privée ira au coffre");
                            println!("  et n'en sortira que pour `hlb mesh show`.");
                            println!();
                            println!("  Relance avec --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        let (pair, cles) =
                            hlb_mesh::provision_node(&mut mesh, node, endpoint.clone())?;

                        // La clé privée d'abord : si la topologie était écrite en
                        // premier et que ceci échouait, le mesh porterait un nœud dont
                        // personne ne peut produire la configuration.
                        state
                            .store_secret_if_absent(
                                &format!("mesh-key-{node}"),
                                &vault.encrypt(&cles.private)?,
                                &format!("clé privée WireGuard de {node}"),
                            )
                            .await?;

                        let pairs: Vec<_> = mesh.peers().cloned().collect();
                        let json = serde_json::to_string(&pairs)?;
                        let ct = vault.encrypt(&json)?;
                        match state.secret(TOPOLOGIE).await? {
                            Some(_) => state.rotate_secret(TOPOLOGIE, &ct).await?,
                            None => {
                                state
                                    .store_secret_if_absent(TOPOLOGIE, &ct, "topologie du mesh")
                                    .await?;
                            }
                        }

                        state
                            .audit("cli", ACTEUR_ROLE, "mesh-add", node, "ok", None)
                            .await?;

                        println!("✓ « {node} » ajouté au mesh en {}", pair.mesh_ip);
                        println!();
                        println!("  hlb mesh show {node}    # sa configuration wg-quick");
                        println!();
                        println!("⚠️  Les configurations des AUTRES nœuds ont changé : elles");
                        println!("   doivent connaître ce nouveau pair. Redéploie-les toutes,");
                        println!("   sinon le nouveau nœud restera injoignable depuis eux.");
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::Crowdsec(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                use hlb_ingress::crowdsec::{self, Cscli};
                let state = State::open(&cli.state).await?;

                match cmd {
                    CrowdsecCmd::Status { service } => {
                        let au_coffre = state.secret(crowdsec::SECRET_NAME).await?.is_some();
                        let cscli = Cscli::new(service);
                        let enrole = cscli.is_enrolled().await;

                        println!("Videur CrowdSec « {} »", crowdsec::BOUNCER_NAME);
                        println!(
                            "  enrôlé côté CrowdSec : {}",
                            match &enrole {
                                Ok(true) => "oui".to_string(),
                                Ok(false) => "NON".to_string(),
                                Err(e) => format!("indéterminé ({e})"),
                            }
                        );
                        println!(
                            "  clé au coffre        : {}",
                            if au_coffre { "oui" } else { "NON" }
                        );
                        println!();

                        match (enrole.unwrap_or(false), au_coffre) {
                            (true, true) => {
                                println!("✓ Le filtrage peut être appliqué.");
                                println!("  Il ne l'est réellement qu'après un `hlb ingress --apply`.");
                            }
                            (true, false) => {
                                // 🔴 Le pire des cas : CrowdSec croit avoir un videur,
                                // et personne ne détient sa clé.
                                println!("🔴 Videur enrôlé mais clé ABSENTE du coffre.");
                                println!("   Elle n'est affichée qu'à la création : elle est perdue.");
                                println!("   Supprime le videur puis réenrôle :");
                                println!("     cscli bouncers delete {}", crowdsec::BOUNCER_NAME);
                                println!("     hlb crowdsec enroll --apply");
                                return Ok(ExitCode::FAILURE);
                            }
                            (false, _) => {
                                // 🔴 Le cas silencieux : CrowdSec détecte tout et ne
                                // bloque rien. Aucune erreur nulle part.
                                println!("🔴 Aucun videur : CrowdSec DÉTECTE mais ne BLOQUE rien.");
                                println!("   Les alertes s'accumulent, personne n'est banni.");
                                println!("     hlb crowdsec enroll --apply");
                                return Ok(ExitCode::FAILURE);
                            }
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    CrowdsecCmd::Enroll { service, apply } => {
                        if state.secret(crowdsec::SECRET_NAME).await?.is_some() {
                            println!("✓ Une clé de videur est déjà au coffre.");
                            println!("  Réenrôler en créerait un second, sans savoir lequel sert.");
                            println!("  hlb crowdsec status  # pour vérifier l'état réel");
                            return Ok(ExitCode::SUCCESS);
                        }

                        if !apply {
                            println!("Enrôlerait le videur « {} » auprès de CrowdSec.", crowdsec::BOUNCER_NAME);
                            println!();
                            println!("  Sa clé sera déposée au coffre. Elle n'est affichée");
                            println!("  qu'une fois : la perdre oblige à supprimer le videur");
                            println!("  et à recommencer.");
                            println!();
                            println!("  ⚠️  Le Caddy frontal devra être une image construite avec");
                            println!("     github.com/hslatman/caddy-crowdsec-bouncer. Une image");
                            println!("     Caddy standard refusera de démarrer sur la directive.");
                            println!();
                            println!("  Relance avec --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        let cle = Cscli::new(service).enroll().await?;
                        if !crowdsec::looks_like_key(&cle) {
                            eprintln!("cscli a renvoyé quelque chose qui n'est pas une clé :");
                            eprintln!("  « {cle} »");
                            eprintln!();
                            eprintln!("Rien n'est enregistré : une clé invalide produirait un");
                            eprintln!("Caddyfile valide qui ne bloquerait plus rien.");
                            return Ok(ExitCode::FAILURE);
                        }

                        let vault = Vault::open_or_init(&cli.master_key)?;
                        state
                            .store_secret_if_absent(
                                crowdsec::SECRET_NAME,
                                &vault.encrypt(&cle)?,
                                "clé du videur CrowdSec au frontal",
                            )
                            .await?;
                        state
                            .audit("cli", ACTEUR_ROLE, "crowdsec-enroll", crowdsec::BOUNCER_NAME, "ok", None)
                            .await?;

                        println!("✓ Videur enrôlé, clé au coffre.");
                        println!();
                        println!("Le filtrage n'est pas actif pour autant : regénère l'entrée.");
                        println!("  hlb ingress --apply");
                        Ok(ExitCode::SUCCESS)
                    }
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

        Command::Backup(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = State::open(&cli.state).await?;
                let vault = Vault::open_or_init(&cli.master_key)?;
                let sched = hlb_backup::Schedule::default();

                match cmd {
                    BackupCmd::Status => {
                        let apps = state.installed_apps().await?;
                        if apps.is_empty() {
                            println!("Aucune app installée.");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                        }
                        println!("{:<14} {:<18} {:<18} ÉTAT", "APP", "DERNIÈRE SAUVEGARDE", "VÉRIFIÉE");
                        for (app, _) in &apps {
                            let age = state.seconds_since_last_success(app).await?
                                .map(|s| std::time::Duration::from_secs(s as u64));
                            let verif = state.seconds_since_last_verification(app).await?;

                            let etat = if sched.is_overdue(age) {
                                "🔴 en retard"
                            } else if sched.is_due(age) {
                                "🟠 due"
                            } else {
                                "✓ à jour"
                            };
                            println!(
                                "{app:<14} {:<18} {:<18} {etat}",
                                age.map(fmt_age).unwrap_or_else(|| "jamais".into()),
                                verif.map(|s| fmt_age(std::time::Duration::from_secs(s as u64)))
                                    .unwrap_or_else(|| "jamais".into()),
                            );
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    BackupCmd::Run { force } => {
                        let provider = build_backup_provider(
                            cli.backup_repo.as_deref(), &state, &vault,
                        ).await?;
                        let Some(provider) = provider else {
                            eprintln!("aucun dépôt configuré — utilise --backup-repo");
                            return Ok(ExitCode::FAILURE);
                        };
                        use hlb_updater::BackupProvider;

                        let mut faites = 0;
                        for (app, statut) in state.installed_apps().await? {
                            if statut == "failed" {
                                continue;
                            }
                            let age = state.seconds_since_last_success(&app).await?
                                .map(|s| std::time::Duration::from_secs(s as u64));
                            if !force && !sched.is_due(age) {
                                continue;
                            }

                            print!("{app}… ");
                            match provider.snapshot(&app).await {
                                Ok(id) => {
                                    state.record_backup(&app, "volume", Some(&id), None).await?;
                                    println!("✓ {}", &id[..8.min(id.len())]);
                                    faites += 1;
                                }
                                Err(e) => {
                                    // Enregistré comme échec : l'échéance n'est PAS
                                    // repoussée, la sauvegarde reste due (§8.1).
                                    state.record_backup(&app, "volume", None, Some(&e)).await?;
                                    println!("✗ {e}");
                                }
                            }
                        }
                        if faites == 0 {
                            println!("Rien à faire.");
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    BackupCmd::Verify { app } => {
                        let Some(depot) = cli.backup_repo.as_deref() else {
                            eprintln!("aucun dépôt configuré — utilise --backup-repo");
                            return Ok(ExitCode::FAILURE);
                        };
                        let password = restic_password(&state, &vault).await?;

                        // Une app nommée, ou toutes celles qui ont déjà un instantané.
                        let cibles: Vec<String> = match app {
                            Some(a) => vec![a.clone()],
                            None => state
                                .installed_apps()
                                .await?
                                .into_iter()
                                .map(|(n, _)| n)
                                .collect(),
                        };

                        let mut verifiees = 0;
                        let mut ecarts = 0;

                        for a in cibles {
                            let Some(snap) = state.latest_snapshot(&a).await? else {
                                // Pas d'instantané : rien à vérifier, et surtout pas
                                // de « ✓ » qui laisserait croire le contraire.
                                if app.is_some() {
                                    println!("{a} : aucune sauvegarde à vérifier.");
                                }
                                continue;
                            };

                            print!("{a} ({})… ", &snap[..8.min(snap.len())]);
                            use std::io::Write as _;
                            let _ = std::io::stdout().flush();

                            match hlb_backup::verify_snapshot(depot, &password, &snap).await {
                                Ok(v) => {
                                    println!("{}", v.describe());
                                    // 🔴 Un écart est enregistré comme un ÉCHEC de
                                    // vérification : `hlb backup status` doit continuer
                                    // à signaler cette app comme non vérifiée.
                                    let detail = (!v.matches()).then(|| v.describe());
                                    state
                                        .record_verification(&a, &snap, detail.as_deref())
                                        .await?;
                                    verifiees += 1;
                                    if !v.matches() {
                                        ecarts += 1;
                                    }
                                }
                                Err(e) => {
                                    println!("✗ {e}");
                                    state
                                        .record_verification(&a, &snap, Some(&e.to_string()))
                                        .await?;
                                    ecarts += 1;
                                }
                            }
                        }

                        if verifiees == 0 && ecarts == 0 {
                            println!("Aucun instantané à vérifier.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        if ecarts > 0 {
                            eprintln!(
                                "\n🔴 {ecarts} vérification(s) en échec — ces sauvegardes \
                                 ne restaurent pas ce qu'elles annoncent."
                            );
                            return Ok(ExitCode::FAILURE);
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    BackupCmd::Pitr(sous) => pitr(sous, &cli.state, cli.postgres_admin.as_deref()).await,
                }
            })
        }

        Command::Cluster(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let orch = SwarmOrchestrator::connect()?;

                match cmd {
                    ClusterCmd::Init { advertise_addr, apply } => {
                        if !apply {
                            println!("Initialiserait un Swarm sur cette machine.");
                            match advertise_addr {
                                Some(a) => println!("  adresse annoncée : {a}"),
                                None => println!(
                                    "  ⚠️  aucune adresse annoncée : Docker en choisira une.\n                                          Sur une machine multi-interfaces, les autres nœuds\n                                          tenteraient de joindre une IP injoignable. Utilise\n                                          --advertise-addr."
                                ),
                            }
                            println!("\n  Relance avec --apply.");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                        }

                        let id = orch.cluster_init(advertise_addr.as_deref()).await?;
                        println!("✓ Swarm actif ({})", &id[..12.min(id.len())]);

                        let state = State::open(&cli.state).await?;
                        state
                            .audit("cli", ACTEUR_ROLE, "cluster-init", "swarm", "ok", None)
                            .await?;
                        Ok(ExitCode::SUCCESS)
                    }

                    ClusterCmd::Autolock { apply } => {
                        let state = State::open(&cli.state).await?;

                        if orch.autolock_enabled().await? {
                            println!("✓ L'autolock est déjà actif.");
                            if state.secret(SECRET_AUTOLOCK).await?.is_none() {
                                // 🔴 Le pire état possible : chiffré, mais la clé
                                // n'est nulle part. Au prochain redémarrage complet,
                                // le cluster reste verrouillé et ses secrets sont
                                // définitivement illisibles.
                                println!();
                                println!("🔴 Mais la clé de déverrouillage n'est PAS au coffre.");
                                println!("   Récupère-la maintenant et garde-la hors ligne :");
                                println!("     docker swarm unlock-key");
                                return Ok(ExitCode::FAILURE);
                            }
                            return Ok(ExitCode::SUCCESS);
                        }

                        if !apply {
                            println!("Activerait le chiffrement au repos des secrets Swarm.");
                            println!();
                            println!("  Ce que ça change : après un redémarrage, chaque manager");
                            println!("  exige la clé de déverrouillage avant de repartir. Un");
                            println!("  cluster qui redémarre seul la nuit ne repart plus seul.");
                            println!();
                            println!("  🔴 La clé sera stockée au coffre ET affichée une fois.");
                            println!("  Note-la hors ligne : si le coffre disparaît avec la");
                            println!("  machine, elle est la seule façon de récupérer le cluster.");
                            println!();
                            println!("  Relance avec --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        let cle = orch.enable_autolock().await?;
                        let vault = Vault::open_or_init(&cli.master_key)?;
                        let ct = vault.encrypt(&cle)?;
                        state
                            .store_secret_if_absent(
                                SECRET_AUTOLOCK,
                                &ct,
                                "déverrouillage du Swarm après redémarrage",
                            )
                            .await?;
                        state
                            .audit("cli", ACTEUR_ROLE, "cluster-autolock", "swarm", "ok", None)
                            .await?;

                        println!("✓ Autolock actif. Clé enregistrée au coffre.");
                        println!();
                        println!("🔴 NOTE CETTE CLÉ HORS LIGNE — elle ne sera plus réaffichée :");
                        println!();
                        println!("    {cle}");
                        println!();
                        println!("Sans elle, un manager redémarré reste verrouillé et les");
                        println!("secrets du cluster sont irrécupérables.");
                        Ok(ExitCode::SUCCESS)
                    }

                    ClusterCmd::Status => {
                        let nodes = orch.nodes().await?;
                        if nodes.is_empty() {
                            println!("Aucun nœud — le Swarm n'est pas initialisé.");
                            println!("  hlb cluster init --apply");
                            return Ok(ExitCode::SUCCESS);
                        }

                        let profil = hlb_orchestrator::ClusterProfile::for_node_count(nodes.len());
                        let managers = nodes
                            .iter()
                            .filter(|n| n.role == hlb_orchestrator::NodeRole::Manager)
                            .count();
                        let quorum = hlb_orchestrator::QuorumHealth::assess(managers);

                        println!("Profil : {} ({} nœud(s))\n", profil.as_str(), nodes.len());
                        println!("{:<20} {:<9} {:<8} {:<8} MÉMOIRE", "NŒUD", "RÔLE", "ÉTAT", "TIER");
                        for n in &nodes {
                            println!(
                                "{:<20} {:<9} {:<8} {:<8} {}",
                                format!("{}{}", n.hostname, if n.is_leader { " ★" } else { "" }),
                                n.role.as_str(),
                                if n.is_ready() { "prêt" } else { &n.status },
                                n.tier.as_deref().unwrap_or("—"),
                                n.memory_mb.map(|m| format!("{m} Mo")).unwrap_or_else(|| "?".into()),
                            );
                        }

                        println!("\nQuorum : {}", quorum.describe());

                        // 🔴 Un tier qui ment est pire que pas de tier : une base
                        // de données planifiée sur un nœud « heavy » à 4 Go
                        // fonctionne jusqu'au jour où elle tue la machine par OOM.
                        for n in &nodes {
                            let (Some(declare), Some(mem)) = (&n.tier, n.memory_mb) else {
                                continue;
                            };
                            let deduit = hlb_orchestrator::cluster::tier_for_memory(mem);
                            if declare != deduit {
                                println!(
                                    "\n🔴 {} est étiqueté « {declare} » mais n'a que {mem} Mo \
                                     — sa mémoire en fait un « {deduit} ».",
                                    n.hostname
                                );
                                println!(
                                    "   Une base planifiée dessus tiendra jusqu'au jour de l'OOM."
                                );
                                println!("   hlb node tier {} --apply", n.hostname);
                            }
                        }

                        // Un nœud sans tier ne recevra jamais de service contraint.
                        let sans_tier: Vec<&str> = nodes
                            .iter()
                            .filter(|n| n.tier.is_none())
                            .map(|n| n.hostname.as_str())
                            .collect();
                        if !sans_tier.is_empty() {
                            println!(
                                "\n⚠️  sans tier : {} — aucun service contraint ne s'y planifiera.",
                                sans_tier.join(", ")
                            );
                            println!("   hlb node tier <nœud>  pour le déduire de sa mémoire.");
                        }

                        Ok(if quorum.needs_attention() {
                            ExitCode::FAILURE
                        } else {
                            ExitCode::SUCCESS
                        })
                    }

                    ClusterCmd::JoinCommand { role } => {
                        let nodes = orch.nodes().await?;
                        let profil = hlb_orchestrator::ClusterProfile::for_node_count(nodes.len() + 1);
                        let managers = nodes
                            .iter()
                            .filter(|n| n.role == hlb_orchestrator::NodeRole::Manager)
                            .count();

                        // Par défaut, on propose le rôle qui garde le quorum sain.
                        let choisi = match role.as_deref() {
                            Some("manager") => hlb_orchestrator::NodeRole::Manager,
                            Some("worker") => hlb_orchestrator::NodeRole::Worker,
                            _ if managers < profil.recommended_managers() => {
                                hlb_orchestrator::NodeRole::Manager
                            }
                            _ => hlb_orchestrator::NodeRole::Worker,
                        };

                        // 🔴 Passer de 1 à 2 managers dégrade la tolérance de panne.
                        if choisi == hlb_orchestrator::NodeRole::Manager {
                            let apres = hlb_orchestrator::QuorumHealth::assess(managers + 1);
                            if apres.needs_attention() {
                                eprintln!("🔴 {}\n", apres.describe());
                                eprintln!("   Ajoute ce nœud en worker, ou prévois-en un troisième.");
                            }
                        }

                        let t = orch.join_tokens().await?;
                        println!("Sur la machine à rattacher, en {} :\n", choisi.as_str());
                        println!("  docker swarm join --token {} {}", t.for_role(choisi), t.advertise_addr);
                        println!("\n⚠️  Vérifie d'abord la machine :  hlb node check <hôte>");
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::Node(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                // Le tier se règle contre le cluster, pas contre une machine.
                if let NodeCmd::Tier { node, set, apply } = cmd {
                    let orch = SwarmOrchestrator::connect()?;
                    let nodes = orch.nodes().await?;
                    let n = nodes
                        .iter()
                        .find(|n| &n.hostname == node || &n.id == node)
                        .ok_or_else(|| format!("nœud « {node} » introuvable"))?;

                    let valeur = match set {
                        Some(v) => v.clone(),
                        None => {
                            let mem = n.memory_mb.ok_or(
                                "mémoire du nœud inconnue : précise --set heavy|light",
                            )?;
                            hlb_orchestrator::cluster::tier_for_memory(mem).to_string()
                        }
                    };

                    if !apply {
                        println!(
                            "Poserait tier={valeur} sur {} ({}).",
                            n.hostname,
                            n.memory_mb.map(|m| format!("{m} Mo")).unwrap_or_else(|| "?".into())
                        );
                        if n.tier.as_deref() == Some(valeur.as_str()) {
                            println!("  (déjà cette valeur — rien ne changerait)");
                        }
                        println!("\n  Relance avec --apply.");
                        return Ok(ExitCode::SUCCESS);
                    }

                    orch.label_node(&n.id, "tier", &valeur).await?;
                    println!("✓ {} → tier={valeur}", n.hostname);

                    let state = State::open(&cli.state).await?;
                    state
                        .audit("cli", ACTEUR_ROLE, "node-tier", &n.hostname, "ok", Some(&valeur))
                        .await?;
                    return Ok(ExitCode::SUCCESS);
                }

                let (runner, apply) = match cmd {
                    NodeCmd::Check { host, user, port, identity } => {
                        (build_runner(host.as_deref(), user.as_deref(), *port, identity.as_deref()), false)
                    }
                    NodeCmd::Deps { host, user, apply } => {
                        (build_runner(host.as_deref(), user.as_deref(), None, None), *apply)
                    }
                    // Traité au-dessus : il ne s'exécute pas sur une machine.
                    NodeCmd::Tier { .. } => unreachable!(),
                };

                println!("Machine : {}\n", runner.label());
                let obs = hlb_bootstrap::observe(runner.as_ref()).await?;
                let rapport = hlb_bootstrap::preflight::run(&obs);

                for c in &rapport.checks {
                    println!("  {}", c.describe());
                }

                if matches!(cmd, NodeCmd::Check { .. }) {
                    println!();
                    if rapport.can_proceed() {
                        println!("✓ cette machine peut accueillir un nœud.");
                        return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                    }
                    eprintln!(
                        "🔴 {} point(s) bloquant(s) — corrige-les avant d'ajouter ce nœud.",
                        rapport.blocking().len()
                    );
                    return Ok(ExitCode::FAILURE);
                }

                // hlb node deps : le plan des dépendances.
                let Some(distro) = rapport.distro else {
                    eprintln!("\n🔴 distribution non identifiée : impossible de planifier.");
                    return Ok(ExitCode::FAILURE);
                };

                let observees = observe_dependencies(runner.as_ref()).await?;
                let refs: Vec<(&str, Option<String>)> =
                    observees.iter().map(|(n, v)| (*n, v.clone())).collect();
                let plan = hlb_bootstrap::plan_dependencies(&distro, &refs);

                println!("\nDépendances :");
                for d in &plan.decisions {
                    println!("  {}", d.describe());
                }

                if plan.is_satisfied() {
                    println!("\n✓ rien à installer.");
                    return Ok(ExitCode::SUCCESS);
                }

                let paquets = plan.to_install();
                if !apply {
                    println!(
                        "\n{} paquet(s) à installer via {:?}.",
                        paquets.len(),
                        distro.package_manager()
                    );
                    println!("  Relance avec --apply pour les installer.");
                    return Ok(ExitCode::SUCCESS);
                }

                // 🔴 Rien n'est installé sans avoir été annoncé au-dessus (§2ter.6).
                let pm = distro.package_manager();
                if let Some(refresh) = pm.refresh_command() {
                    println!("\nrafraîchissement de l'index…");
                    let out = runner.run(&refresh).await?;
                    if !out.ok() {
                        eprintln!("⚠️  index non rafraîchi : {}", out.stderr.trim());
                    }
                }

                println!("installation de {} paquet(s)…", paquets.len());
                let out = runner.run(&pm.install_command(&paquets)).await?;
                if out.ok() {
                    println!("✓ dépendances installées.");
                    Ok(ExitCode::SUCCESS)
                } else {
                    eprintln!("✗ échec : {}", out.stderr.trim());
                    Ok(ExitCode::FAILURE)
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
