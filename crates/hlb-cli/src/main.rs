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

    /// URL d'administration MariaDB, même principe.
    #[arg(long, global = true, env = "HLB_MARIADB_ADMIN")]
    mariadb_admin: Option<String>,

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

    /// Réseau Docker où les services de plateforme sont joignables par leur nom.
    ///
    /// ⚠️ Les outils clients (pg_dump, pg_basebackup) tournent dans des conteneurs
    /// jetables : sans ce réseau, ils ne résolvent pas « postgres » et échouent sur
    /// une erreur de DNS qui ne dit pas que c'est le réseau le problème.
    #[arg(long, global = true, default_value = "hlb_platform", env = "HLB_PLATFORM_NETWORK")]
    platform_network: String,

    /// Domaine de base pour le certificat wildcard (§6.4), ex. example.fr
    #[arg(long, global = true, env = "HLB_BASE_DOMAIN")]
    base_domain: Option<String>,

    /// Module DNS de Caddy : cloudflare, ovh, desec, gandi…
    #[arg(long, global = true, env = "HLB_DNS_PROVIDER")]
    dns_provider: Option<String>,

    /// 🔴 Environnement de TEST de Let's Encrypt. À utiliser au premier essai :
    /// les quotas de production font bannir le domaine une semaine entière.
    #[arg(long, global = true, env = "HLB_ACME_STAGING")]
    acme_staging: bool,

    /// Portail d'authentification pour les apps sans SSO natif (§5.0).
    #[arg(long, global = true, default_value = "oauth2-proxy:4180", env = "HLB_FORWARD_AUTH")]
    forward_auth_upstream: String,

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

    /// Jetons d'accès à l'API et à l'UI (§9ter).
    #[command(subcommand)]
    Token(TokenCmd),

    /// Instantanés ZFS/btrfs : retour arrière en minutes (§8).
    #[command(subcommand)]
    Snapshot(SnapshotCmd),

    /// Mise à jour de HomelabUS lui-même (§7bis).
    #[command(subcommand)]
    #[command(name = "self")]
    Selfy(SelfCmd),

    /// Réplication PostgreSQL : standby en streaming (§3.2).
    #[command(subcommand)]
    Replication(ReplCmd),

    /// Observabilité : collecte, règles d'alerte, deadman switch (§8bis).
    #[command(subcommand)]
    Metrics(MetricsCmd),

    /// Comptes humains : identité, boîtes mail et aliases (§5bis.3).
    #[command(subcommand)]
    User(UserCmd),

    /// 🔴 Reprise après sinistre : basculer PostgreSQL sur un autre nœud (§2bis.5).
    #[command(subcommand)]
    Dr(DrCmd),

    /// Certificats mTLS agent ↔ controller (§2).
    #[command(subcommand)]
    Pki(PkiCmd),

    /// Accès SSH gérés : pose, révocation, inventaire (§2ter phase 0bis).
    #[command(subcommand)]
    Access(AccessCmd),

    /// Mesh WireGuard entre nœuds (§2ter, §6.3).
    #[command(subcommand)]
    Mesh(MeshCmd),

    /// Videur CrowdSec : enrôlement et état (§8bis).
    #[command(subcommand)]
    Crowdsec(CrowdsecCmd),

    /// Inventaire des secrets : noms et usages, jamais les valeurs.
    Secrets,

    /// Déposer un secret au coffre. La valeur est lue sur l'ENTRÉE STANDARD.
    ///
    /// 🔴 Jamais en argument : une ligne de commande est visible dans `ps` par tout
    /// utilisateur de la machine, et atterrit dans l'historique du shell.
    SecretSet {
        /// Nom du secret, ex. dns-provider-token
        name: String,
        /// À quoi il sert. Affiché par `hlb secrets`.
        #[arg(long, default_value = "déposé à la main")]
        purpose: String,
        /// Remplacer une valeur existante. 🔴 Sans ce drapeau, on ne l'écrase pas.
        #[arg(long)]
        rotate: bool,
    },

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
    /// Rattacher une machine au cluster, de bout en bout (§2ter).
    Add {
        /// Hôte SSH de la machine à rattacher.
        host: String,
        #[arg(long, default_value = "root")]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        /// Clé SSH pour le PREMIER contact. Ensuite HomelabUS utilise la sienne.
        #[arg(long)]
        identity: Option<String>,
        /// `manager` ou `worker`. Par défaut : ce que le profil recommande.
        #[arg(long)]
        role: Option<String>,
        /// Adresse annoncée par ce nœud aux autres. 🔴 Requise en multi-interfaces.
        #[arg(long)]
        advertise_addr: Option<String>,
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

    /// Destinations de sauvegarde : NAS, Garage, S3 hors site (§8.1).
    #[command(subcommand)]
    Dest(DestCmd),

    /// Où vont les données d'une app, classe par classe.
    Route {
        app: String,
        /// Destinations pour les données CRITIQUES : dumps SQL, état, secrets.
        /// Quelques Go — ça passe sur n'importe quelle connexion.
        #[arg(long, value_delimiter = ',')]
        critique: Option<Vec<String>>,
        /// Destinations pour les données VOLUMINEUSES : photos, fichiers, médias.
        /// ⚠️ Des centaines de Go : vérifie que la connexion suit.
        #[arg(long, value_delimiter = ',')]
        volumineux: Option<Vec<String>>,
    },
}

#[derive(Subcommand)]
enum DestCmd {
    /// Déclarer une destination.
    Add {
        /// Nom court : nas, garage, offsite.
        name: String,
        /// Chemin local, ou URL restic `s3:https://hôte/seau`.
        #[arg(long)]
        location: String,
        /// Classes acceptées par défaut : critique, volumineux.
        #[arg(long, value_delimiter = ',', default_value = "critique")]
        classes: Vec<String>,
        /// Clé d'accès S3. La clé SECRÈTE est lue sur l'ENTRÉE STANDARD.
        #[arg(long)]
        access_key: Option<String>,
    },
    /// Les destinations déclarées et ce qu'elles acceptent.
    List,
    /// Retirer une destination. Les sauvegardes déjà envoyées restent là-bas.
    Remove { name: String },
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
        /// 🔴 Appliquer malgré des vulnérabilités critiques. À justifier.
        #[arg(long)]
        force_vulnerable: bool,
    },
    /// Analyser une image sans rien appliquer : CVE et signature (§7).
    Scan {
        /// Image complète, ex. gitea/gitea:1.25
        image: String,
        /// Expression de l'identité attendue du signataire.
        #[arg(long, env = "HLB_COSIGN_IDENTITY")]
        identity: Option<String>,
        /// Émetteur OIDC attendu, ex. https://token.actions.githubusercontent.com
        #[arg(long, env = "HLB_COSIGN_ISSUER")]
        issuer: Option<String>,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Créer un jeton. Sa valeur n'est affichée QU'UNE FOIS.
    Create {
        /// Nom, pour savoir lequel révoquer plus tard.
        name: String,
        /// viewer (tout voir), operator (installer, sauvegarder), admin (tout).
        #[arg(long, default_value = "viewer")]
        role: String,
        #[arg(long)]
        apply: bool,
    },
    /// Les jetons : noms, rôles, dernier usage. Jamais les valeurs.
    List,
    /// Révoquer un jeton. Effet immédiat.
    Revoke { name: String },
}

#[derive(Subcommand)]
enum SnapshotCmd {
    /// Figer l'état d'un dataset avant une opération risquée.
    Create {
        /// Dataset ZFS ou sous-volume btrfs, ex. tank/hlb
        dataset: String,
        /// À quoi sert cet instantané, ex. avant-maj-gitea
        #[arg(long, default_value = "manuel")]
        motif: String,
        #[arg(long)]
        apply: bool,
    },
    /// Les instantanés créés par HomelabUS sur ce dataset.
    List { dataset: String },
}

#[derive(Subcommand)]
enum SelfCmd {
    /// Version installée, compatibilité du parc. Ne modifie rien.
    Status,
    /// 🔴 Revenir au schéma d'une version antérieure (§7bis). DESTRUCTEUR.
    Rollback {
        /// Restaurer le binaire précédent au lieu du schéma.
        #[arg(long)]
        binary: bool,
        /// Numéro de la dernière migration à CONSERVER, ex. 4
        #[arg(long, default_value = "0")]
        to_migration: i64,
        /// Confirmation explicite : des données seront perdues.
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        apply: bool,
    },
    /// Ce que la mise à jour ferait, et ce qui l'empêche. Aperçu par défaut.
    Update {
        /// Version cible, ex. 0.2.0
        version: String,
        /// Base des téléchargements. Le binaire et son manifeste y sont attendus.
        #[arg(long, env = "HLB_RELEASE_URL")]
        from: Option<String>,
        /// 🔴 Clé publique Ed25519 de publication, en hexadécimal.
        ///
        /// Sans elle, aucun binaire n'est installé : une mise à jour non vérifiée
        /// serait le meilleur vecteur de compromission du système.
        #[arg(long, env = "HLB_RELEASE_KEY")]
        key: Option<String>,
        /// 🔴 Nécessaire pour une version MAJEURE ou un retour arrière.
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum ReplCmd {
    /// Les réglages à poser sur la primaire et sur le standby.
    Config {
        /// Nom du nœud qui portera le standby.
        standby: String,
        /// Hôte de la primaire, tel que le standby la joindra.
        #[arg(long, default_value = "postgres")]
        primary_host: String,
        /// Rôle de réplication.
        #[arg(long, default_value = "replicant")]
        user: String,
    },
    /// 🔴 Les standbys suivent-ils, et un slot mort remplit-il le disque ?
    Status,
}

#[derive(Subcommand)]
enum UserCmd {
    /// Créer un compte : identité PocketID + boîte mail, en une fois.
    ///
    /// Reprenable : relancer après un échec termine ce qui manque.
    Add {
        /// Identifiant de connexion, qui devient aussi la partie locale par défaut.
        nom: String,
        /// Adresse par défaut. Sans elle : <nom>@<domaine mail>.
        #[arg(long)]
        email: Option<String>,
        /// Nom affiché.
        #[arg(long)]
        display_name: Option<String>,
        /// Profil de quotas : standard, invite, illimite.
        #[arg(long, default_value = "standard")]
        profil: String,
    },
    /// Les comptes, leurs boîtes et l'état de leurs aliases.
    List,
    /// Changer le profil de quotas d'un compte.
    Profile {
        nom: String,
        #[arg(long)]
        profil: String,
    },
    /// Boîtes mail supplémentaires.
    #[command(subcommand)]
    Mailbox(MailboxCmd),
    /// Aliases : permanents ou temporaires, générés ou choisis.
    #[command(subcommand)]
    Alias(AliasCmd),
}

#[derive(Subcommand)]
enum MailboxCmd {
    /// Ouvrir une boîte de plus.
    Add {
        /// Compte propriétaire.
        nom: String,
        /// Partie locale de la nouvelle boîte.
        local: String,
    },
    /// Fermer une boîte. La boîte par défaut est refusée.
    Remove { nom: String, local: String },
}

#[derive(Subcommand)]
enum AliasCmd {
    /// Créer un alias.
    ///
    /// Les trois axes sont INDÉPENDANTS :
    ///   durée   — permanent par défaut, temporaire avec `--pendant`
    ///   nom     — généré par défaut, choisi avec `--nom`
    ///   indice  — aucun par défaut, celui du site avec `--pour`
    ///
    /// Exemples :
    ///   hlb user alias add remy                          aléatoire, permanent
    ///   hlb user alias add remy --pour amazon            aléatoire lié à un site
    ///   hlb user alias add remy --pour fnac --pendant 30j jetable, attribuable
    ///   hlb user alias add remy --nom contact            choisi, permanent
    Add {
        /// Compte propriétaire.
        nom: String,
        /// Boîte de destination. Par défaut, la boîte par défaut.
        #[arg(long)]
        boite: Option<String>,
        /// 🔴 Partie locale CHOISIE. Sans elle, elle est générée et indevinable.
        #[arg(long, conflicts_with = "pour")]
        nom_alias: Option<String>,
        /// Le site ou l'usage : sert d'indice lisible, suivi d'un suffixe aléatoire.
        #[arg(long)]
        pour: Option<String>,
        /// Durée de vie : `30j`, `12h`, `90m`. Absent = permanent.
        #[arg(long)]
        pendant: Option<String>,
        /// Note libre, pour s'en souvenir dans six mois.
        #[arg(long)]
        note: Option<String>,
    },
    /// Tous les aliases d'un compte, avec leur état réel.
    List {
        nom: String,
        /// N'afficher que les problèmes.
        #[arg(long)]
        problemes: bool,
    },
    /// Désactiver un alias sans le supprimer.
    ///
    /// 🔴 Préférable à la suppression : un alias désactivé rejette le courrier ET
    /// permet de compter ce qui frappe encore à la porte — donc de savoir combien de
    /// temps un marchand a continué de vendre l'adresse après sa fermeture.
    Disable { nom: String, alias: String },
    /// 🔴 Supprimer les aliases temporaires expirés.
    ///
    /// Sans cette purge, un alias « temporaire » reste actif POUR TOUJOURS : Stalwart
    /// n'a aucune notion d'expiration. C'est la commande qui rend la promesse vraie.
    Purge {
        /// Aperçu par défaut : rien n'est supprimé sans --apply.
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum MetricsCmd {
    /// La configuration de collecte de VictoriaMetrics.
    Scrape {
        /// Adresse du controller, telle que VictoriaMetrics la joindra.
        #[arg(long, default_value = "hlb-controller:8080")]
        controller: String,
        /// Jeton de LECTURE (rôle metrics). Sans lui, la collecte reçoit des 401.
        #[arg(long)]
        token: Option<String>,
    },
    /// Les règles d'alerte livrées, et ce qu'elles surveillent.
    Rules,
    /// Évaluer les règles maintenant, contre VictoriaMetrics.
    Check {
        /// URL de VictoriaMetrics.
        #[arg(long, default_value = "http://victoria-metrics:8428")]
        url: String,
    },
    /// 🔴 Le veilleur externe : le script à poser sur le NAS (§8bis).
    Deadman {
        /// Fichier où le NAS reçoit les battements.
        #[arg(long, default_value = "/var/lib/hlb/battement")]
        heartbeat_file: String,
        /// Sujet ntfy du veilleur. DISTINCT de celui de HomelabUS.
        #[arg(long)]
        ntfy: String,
    },
}

#[derive(Subcommand)]
enum DrCmd {
    /// Promouvoir PostgreSQL sur un nœud de secours. Aperçu par défaut.
    Promote {
        /// Nœud d'accueil, tel qu'affiché par `hlb cluster status`.
        node: String,
        /// Répertoire des sauvegardes de base.
        #[arg(long, default_value = "/archive/base")]
        base_dir: String,
        /// Répertoire d'archivage WAL.
        #[arg(long, default_value = "/archive/wal")]
        wal_dir: String,
        /// 🔴 Passer outre le contrôle « l'ancien primaire répond encore ».
        #[arg(long)]
        force_split_brain: bool,
        #[arg(long)]
        apply: bool,
    },
    /// 🔴 Répéter une restauration pour de vrai, dans un conteneur jetable (§8.3).
    Exercise {
        /// Répertoire des sauvegardes de base.
        #[arg(long, default_value = "/archive/base")]
        base_dir: String,
        /// Image PostgreSQL, de version compatible avec la sauvegarde.
        #[arg(long, default_value = "postgres:17-alpine")]
        image: String,
        /// 🔴 J'affirme que la cible est jetable. Sans ça, l'exercice refuse.
        #[arg(long)]
        disposable: bool,
        #[arg(long)]
        apply: bool,
    },
    /// Suis-je prêt à basculer ? Ne modifie rien.
    Status,
}

#[derive(Subcommand)]
enum PkiCmd {
    /// Créer l'autorité du cluster. Une seule fois, pour dix ans.
    Init {
        #[arg(long)]
        apply: bool,
    },
    /// Émettre le certificat d'un agent. À refaire tous les 90 jours.
    Agent {
        /// Nom d'hôte du nœud.
        node: String,
        /// Répertoire de sortie.
        #[arg(long, default_value = ".")]
        out: std::path::PathBuf,
        /// Nom du service Swarm des agents.
        #[arg(long, default_value = "hlb-agent")]
        service: String,
    },
    /// Émettre le certificat client du controller.
    Controller {
        #[arg(long, default_value = ".")]
        out: std::path::PathBuf,
    },
    /// Ce que l'autorité a émis, et ce qui expire bientôt.
    Status,
}

#[derive(Subcommand)]
enum AccessCmd {
    /// Poser la clé de HomelabUS sur une machine.
    Grant {
        host: String,
        #[arg(long, default_value = "root")]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        /// Clé du premier contact.
        #[arg(long)]
        identity: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// 🔴 Retirer la clé de HomelabUS d'une machine. Les accès humains sont préservés.
    Revoke {
        host: String,
        #[arg(long, default_value = "root")]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        identity: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// Ce que HomelabUS voit dans l'authorized_keys d'une machine.
    List {
        host: String,
        #[arg(long, default_value = "root")]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        identity: Option<String>,
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

/// Ce que défaire une migration fait perdre, en clair.
///
/// 🔴 « Des données seront perdues » n'aide personne à décider. La correspondance est
/// EXACTE et non par mot-clé : « 0006_volumes_sqlite » n'efface qu'une colonne, alors
/// que « 0003_volumes » efface tout l'inventaire. Les confondre annoncerait une perte
/// qui n'a pas lieu — ou pire, tairait celle qui a lieu.
fn consequence_migration(nom: &str) -> Vec<String> {
    let detail: &[&str] = match nom {
        "0005_audit" => &["le JOURNAL D'AUDIT est effacé (§9 : il est append-only,",
                          "c'est le seul chemin qui l'efface)"],
        "0004_backup_runs" => &["l'historique des sauvegardes est effacé — toutes les apps",
                                "repasseront en « jamais sauvegardée » et seront dues"],
        "0003_volumes" => &["l'inventaire des volumes est effacé ; les données Docker",
                            "survivent, mais la sauvegarde ne saura plus quoi sauvegarder"],
        "0002_secrets" => &["les secrets chiffrés sont effacés, dont ceux déposés à la",
                            "main : jeton DNS, clé du videur CrowdSec"],
        "0006_volumes_sqlite" => &["le drapeau « base SQLite » des volumes est perdu — leurs",
                                   "bases repasseraient en copie à chaud, donc corrompues"],
        "0001_initial" => &["TOUT l'état : apps, plans, guides"],
        _ => &[],
    };

    let mut out = vec![nom.to_string()];
    out.extend(detail.iter().map(|l| format!("      {l}")));
    out
}

/// Télécharge un binaire et son manifeste.
///
/// ⚠️ Le manifeste d'abord : s'il est absent, inutile de tirer plusieurs mégaoctets
/// pour découvrir ensuite qu'on ne pourra rien vérifier.
async fn telecharger_version(
    base_url: &str,
    version: &hlb_selfupdate::Version,
) -> Result<(Vec<u8>, hlb_selfupdate::ReleaseManifest), String> {
    let base = base_url.trim_end_matches('/');
    let cible = format!("hlb-{version}-{}", std::env::consts::ARCH);

    let manifeste_brut = recuperer(&format!("{base}/{cible}.manifest")).await?;
    let manifeste = analyser_manifeste(&String::from_utf8_lossy(&manifeste_brut))?;

    let binaire = recuperer(&format!("{base}/{cible}")).await?;
    Ok((binaire, manifeste))
}

async fn recuperer(url: &str) -> Result<Vec<u8>, String> {
    let r = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| e.to_string())?
        .get(url)
        .send()
        .await
        .map_err(|e| format!("{url} : {e}"))?;

    if !r.status().is_success() {
        return Err(format!("{url} : HTTP {}", r.status().as_u16()));
    }
    Ok(r.bytes().await.map_err(|e| e.to_string())?.to_vec())
}

/// Analyse un manifeste de publication.
///
/// Format volontairement trivial — `clé=valeur` par ligne — pour qu'il puisse être
/// produit par trois lignes de shell dans une chaîne de publication, et relu à l'œil.
fn analyser_manifeste(
    texte: &str,
) -> Result<hlb_selfupdate::ReleaseManifest, String> {
    let mut version = None;
    let mut sha256 = None;
    let mut signature = None;

    for l in texte.lines() {
        let Some((k, v)) = l.split_once('=') else { continue };
        match k.trim() {
            "version" => version = hlb_selfupdate::Version::parse(v.trim()),
            "sha256" => sha256 = Some(v.trim().to_string()),
            "signature" => signature = Some(v.trim().to_string()),
            _ => {}
        }
    }

    Ok(hlb_selfupdate::ReleaseManifest {
        version: version.ok_or("manifeste sans version")?,
        sha256: sha256.ok_or("manifeste sans empreinte")?,
        // Une signature absente n'est PAS une erreur d'analyse : c'est un manifeste
        // non signé, et c'est `verify` qui doit le refuser, avec son message.
        signature: signature.unwrap_or_default(),
    })
}

/// Les migrations livrées avec ce binaire, et leur réversibilité.
///
/// 🔴 Lue depuis le répertoire de migrations à la compilation : une migration ajoutée
/// sans son `down` apparaît ici comme irréversible, et bloque la mise à jour. C'est
/// exactement le but — le test `every_migration_can_be_undone` l'attrape plus tôt,
/// celui-ci est le filet.
fn migrations_connues() -> Vec<hlb_selfupdate::Migration> {
    const NOMS: &[(&str, bool)] = &[
        ("0001_initial", true),
        ("0002_secrets", true),
        ("0003_volumes", true),
        ("0004_backup_runs", true),
        ("0005_audit", true),
        ("0006_volumes_sqlite", true),
    ];
    NOMS.iter()
        .map(|(n, r)| hlb_selfupdate::Migration {
            name: (*n).to_string(),
            reversible: *r,
        })
        .collect()
}

/// L'instant présent, en secondes depuis l'époque.
fn maintenant() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Écrit un PEM avec des droits restrictifs.
///
/// 🔴 Une clé privée en 644 est lisible par tout utilisateur de la machine. Les
/// outils TLS ne s'en plaignent pas — contrairement à `ssh`, qui refuse — donc rien
/// ne signalerait le problème.
fn ecrire_pem(chemin: &std::path::Path, contenu: &str) -> std::io::Result<()> {
    std::fs::write(chemin, contenu)?;

    #[cfg(unix)]
    if chemin.extension().is_some_and(|e| e == "key" || e == "pem") {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
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
    network: &str,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    use hlb_backup::pitr;

    match cmd {
        PitrCmd::Base { dest, apply } => {
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

/// Charge les destinations déclarées.
async fn charger_destinations(
    state: &State,
) -> Result<Vec<hlb_backup::Destination>, Box<dyn std::error::Error>> {
    use hlb_backup::{Classe, Destination};

    Ok(state
        .destinations()
        .await?
        .into_iter()
        .map(|(nom, location, classes, credentials_secret)| Destination {
            nom,
            location,
            classes: classes.split(',').filter_map(Classe::parse).collect(),
            credentials_secret,
        })
        .collect())
}

/// Les destinations qui doivent recevoir cette classe pour cette app.
///
/// Une route explicite l'emporte ; sinon on retombe sur ce que chaque destination
/// accepte globalement. C'est ce qui permet de dire « le volumineux d'Immich part
/// hors site » sans y envoyer celui de toutes les autres apps.
async fn destinations_pour(
    state: &State,
    app: &str,
    classe: hlb_backup::Classe,
) -> Result<Vec<hlb_backup::Destination>, Box<dyn std::error::Error>> {
    let toutes = charger_destinations(state).await?;
    let explicites = state.route(app, classe.nom()).await?;

    if explicites.is_empty() {
        return Ok(toutes.into_iter().filter(|d| d.accepte(classe)).collect());
    }
    Ok(toutes
        .into_iter()
        .filter(|d| explicites.contains(&d.nom))
        .collect())
}

/// Archive un dump vers TOUTES les destinations de la classe critique.
///
/// Renvoie le nombre de destinations servies.
///
/// 🔴 Un échec sur une destination n'empêche pas les autres. Un hors-site injoignable
/// qui interromprait la boucle supprimerait aussi la copie locale : on perdrait les
/// deux pour la panne d'une seule.
async fn archiver_partout(
    state: &State,
    vault: &Vault,
    app: &str,
    kind: &str,
    reseau: &str,
    repli: Option<&str>,
    dump: &hlb_backup::pgdump::scheduled::Dump,
) -> Result<usize, Box<dyn std::error::Error>> {
    let password = restic_password(state, vault).await?;
    let dests =
        destinations_effectives(state, app, hlb_backup::Classe::Critique, repli).await?;

    if dests.is_empty() {
        eprintln!("⚠️  {app} : aucune destination critique — le dump n'est allé NULLE PART.");
        return Ok(0);
    }

    let mut servies = 0;
    for d in &dests {
        // Les identifiants sortent du coffre ici : `archive_to` n'y touche jamais.
        let identifiants = match &d.credentials_secret {
            Some(nom) => match state.secret(nom).await? {
                Some(ct) => Some(vault.decrypt(&ct)?),
                None => None,
            },
            None => None,
        };

        match hlb_backup::pgdump::scheduled::archive_to(
            d,
            identifiants.as_deref(),
            Some(reseau),
            &password,
            dump,
        )
        .await
        {
            Ok(id) => {
                state
                    .record_backup_to(app, kind, &d.nom, Some(&id), None)
                    .await?;
                print!("✓{} ", d.nom);
                servies += 1;
            }
            Err(e) => {
                state
                    .record_backup_to(app, kind, &d.nom, None, Some(&e.to_string()))
                    .await?;
                print!("✗{}({e}) ", d.nom);
            }
        }
    }
    Ok(servies)
}

/// Le fournisseur de sauvegarde d'une destination précise.
///
/// 🔴 Le dépôt local se MONTE, le dépôt S3 se joint par le réseau — c'est
/// `Destination::runner` qui tranche, et se tromper produit un « repository does not
/// exist » qui désigne un chemin local sans rapport avec la vraie destination.
async fn provider_pour(
    dest: &hlb_backup::Destination,
    reseau: &str,
    state: &State,
    vault: &Vault,
) -> Result<hlb_backup::ResticBackupProvider<hlb_backup::ContainerRunner>, Box<dyn std::error::Error>>
{
    let password = restic_password(state, vault).await?;

    // Les identifiants S3 sortent du coffre ICI, au plus près de l'exécution.
    let identifiants = match &dest.credentials_secret {
        Some(nom) => match state.secret(nom).await? {
            Some(ct) => Some(vault.decrypt(&ct)?),
            None => None,
        },
        None => None,
    };
    let env = dest.env(identifiants.as_deref())?;

    let mut par_app: std::collections::BTreeMap<String, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    for (app, _) in state.installed_apps().await? {
        let v = state.volumes_to_backup(&app).await?;
        if !v.is_empty() {
            par_app.insert(app, v);
        }
    }

    let dest = dest.clone();
    let reseau = reseau.to_string();

    Ok(hlb_backup::ResticBackupProvider::new(move |app| {
        let volumes = par_app.get(app)?;

        let (mut runner, chemin) = dest.runner(Some(&reseau));
        let mut paths = Vec::new();
        for (name, _) in volumes {
            // Le volume Docker est monté par son NOM : le point de montage de l'hôte
            // n'est pas accessible depuis la VM Docker sur macOS.
            runner = runner.mount(name, format!("/donnees/{name}"));
            paths.push(format!("/donnees/{name}"));
        }

        Some((
            hlb_backup::Repository::new(runner, chemin, password.clone())
                .extra_env(env.clone()),
            paths,
        ))
    }))
}

/// Les destinations à servir, avec repli sur `--backup-repo`.
///
/// ⚠️ Le repli existe pour ne pas casser une installation qui n'a pas encore déclaré de
/// destination : sans lui, une mise à jour de HomelabUS arrêterait silencieusement
/// toutes les sauvegardes — le pire moment pour découvrir un changement de format.
async fn destinations_effectives(
    state: &State,
    app: &str,
    classe: hlb_backup::Classe,
    repli: Option<&str>,
) -> Result<Vec<hlb_backup::Destination>, Box<dyn std::error::Error>> {
    let d = destinations_pour(state, app, classe).await?;
    if !d.is_empty() {
        return Ok(d);
    }

    Ok(repli
        .map(|l| {
            vec![hlb_backup::Destination {
                nom: "defaut".into(),
                location: l.to_string(),
                classes: vec![hlb_backup::Classe::Critique, hlb_backup::Classe::Volumineux],
                credentials_secret: None,
            }]
        })
        .unwrap_or_default())
}

/// Les sous-commandes d'aliases.
///
/// 🔴 Les trois axes sont indépendants — durée, nom généré ou choisi, indice de site.
/// Les mêler produirait une interface où « temporaire » impliquerait « aléatoire », ce
/// qui n'a aucune raison d'être : on veut parfois `promo@` pour une semaine.
async fn gerer_alias(
    state: &State,
    domaine: &str,
    cmd: &AliasCmd,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    use hlb_users::{generation::Genere, Demande, Profil};

    match cmd {
        AliasCmd::Add { nom, boite, nom_alias, pour, pendant, note } => {
            let c = charger_compte(state, nom).await?;
            let p = Profil::par_nom(&c.profil).unwrap_or_else(Profil::standard);
            let maintenant = maintenant();

            let cible = match boite {
                Some(b) => b.clone(),
                None => match c.boite_par_defaut() {
                    Some(b) => b.local.clone(),
                    None => {
                        eprintln!("🔴 {nom} n'a aucune boîte : l'alias n'aurait nulle part où aller.");
                        return Ok(ExitCode::FAILURE);
                    }
                },
            };

            // Axe DURÉE.
            let expire_le = match pendant {
                Some(d) => {
                    let s = parse_duree(d)?;
                    p.autorise(&c.usage(maintenant), Demande::AliasTemporaire { duree_s: s })
                        .map_err(|r| r.to_string())?;
                    Some(maintenant + s)
                }
                None => {
                    p.autorise(&c.usage(maintenant), Demande::AliasPermanent)
                        .map_err(|r| r.to_string())?;
                    None
                }
            };

            // Axes NOM et INDICE.
            let (local, indice) = match nom_alias {
                // Nom choisi : l'utilisateur sait ce qu'il fait, mais il doit savoir
                // aussi ce qu'il perd.
                Some(n) => {
                    let propre = hlb_users::generation::nettoyer_indice(n);
                    if propre.is_empty() {
                        eprintln!("🔴 « {n} » ne donne aucune partie locale utilisable.");
                        return Ok(ExitCode::FAILURE);
                    }
                    (propre, None)
                }
                None => {
                    let mut alea = [0u8; hlb_users::generation::SUFFIXE_LEN];
                    hlb_secrets::fill_random(&mut alea);
                    let g = Genere::pour(pour.as_deref().unwrap_or(""), &alea);
                    let ind = (!g.indice.is_empty()).then(|| g.indice.clone());
                    (g.local, ind)
                }
            };

            state
                .add_alias(nom, &cible, &local, expire_le, indice.as_deref(), note.as_deref())
                .await?;

            let dom = c
                .boites
                .iter()
                .find(|b| b.local == cible)
                .map(|b| b.domaine.clone())
                .unwrap_or_else(|| domaine.to_string());

            println!("✓ {local}@{dom}  →  {cible}@{dom}");
            match expire_le {
                Some(e) => {
                    println!("  temporaire, expire dans {}", fmt_age(
                        std::time::Duration::from_secs((e - maintenant).max(0) as u64)
                    ));
                    // 🔴 La promesse ne tient que si la purge tourne. Le dire ici,
                    // au moment où on la fait, plutôt que de le découvrir six mois
                    // plus tard sur une adresse qu'on croyait fermée.
                    println!("  ⚠️ L'expiration n'est PAS tenue par le serveur de messagerie :");
                    println!("     il faut que « hlb user alias purge --apply » tourne.");
                }
                None => println!("  permanent"),
            }

            if nom_alias.is_some() {
                // ⚠️ Un nom choisi est devinable par construction. Acceptable pour
                // `contact@`, mauvais pour un jetable par marchand : si l'un est
                // `amazon@`, alors `paypal@` et `banque@` existent probablement aussi.
                println!("  ⚠️ Nom choisi : devinable. Pour un alias par site, préfère");
                println!("     « --pour <site> », qui ajoute un suffixe aléatoire.");
            }
            Ok(ExitCode::SUCCESS)
        }

        AliasCmd::List { nom, problemes } => {
            let c = charger_compte(state, nom).await?;
            let maintenant = maintenant();
            let mut rien = true;

            for b in &c.boites {
                for a in &b.aliases {
                    let e = a.etat(maintenant);
                    if *problemes && !e.trahit_la_promesse() {
                        continue;
                    }
                    rien = false;
                    println!("{}@{}  → {}", a.local, b.domaine, b.local);
                    println!("    {}", e.describe());
                    if let Some(n) = &a.note {
                        println!("    note : {n}");
                    }
                }
            }
            if rien {
                println!("{}", if *problemes {
                    "Aucune promesse rompue."
                } else {
                    "Aucun alias."
                });
            }
            Ok(ExitCode::SUCCESS)
        }

        AliasCmd::Disable { nom, alias } => {
            state.deactivate_alias(nom, alias).await?;
            println!("✓ {alias} désactivé.");
            // 🔴 Désactivé, pas supprimé : on continue de compter ce qui frappe à la
            // porte, donc de savoir combien de temps un marchand a vendu l'adresse.
            println!("  Il rejette le courrier mais reste visible : c'est ce qui permet");
            println!("  de voir qui continue d'écrire à une adresse fermée.");
            Ok(ExitCode::SUCCESS)
        }

        AliasCmd::Purge { apply } => {
            let maintenant = maintenant();
            let a_purger = state.aliases_to_purge(maintenant).await?;

            if a_purger.is_empty() {
                println!("Aucun alias expiré à retirer.");
                return Ok(ExitCode::SUCCESS);
            }

            println!(
                "{} alias expiré(s) et TOUJOURS ACTIF(S) :",
                a_purger.len()
            );
            for (u, b, l) in &a_purger {
                println!("  {l}  ({u} → {b})");
            }

            if !*apply {
                println!();
                println!("Aperçu : rien n'a été retiré. Ajoute --apply.");
                println!("⚠️ Tant que ce n'est pas fait, ces adresses REÇOIVENT encore.");
                return Ok(ExitCode::SUCCESS);
            }

            // ⚠️ L'état est marqué APRÈS le retrait chez Stalwart. L'inverse
            // prétendrait l'adresse fermée alors qu'elle recevrait encore — c'est
            // exactement le mensonge que ce module existe pour empêcher.
            for (u, _b, l) in &a_purger {
                state.deactivate_alias(u, l).await?;
                println!("✓ {l} retiré");
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Reconstruit un compte depuis l'état.
async fn charger_compte(
    state: &State,
    nom: &str,
) -> Result<hlb_users::Compte, Box<dyn std::error::Error>> {
    use hlb_users::{Alias, Boite, Compte, Duree};

    let profil = state
        .users()
        .await?
        .into_iter()
        .find(|(n, _, _)| n == nom)
        .map(|(_, p, _)| p)
        .unwrap_or_else(|| "standard".into());

    let mut c = Compte::nouveau(nom, profil);
    c.pocket_id = state
        .users()
        .await?
        .into_iter()
        .find(|(n, _, _)| n == nom)
        .and_then(|(_, _, id)| id);

    let aliases = state.aliases(nom).await?;

    for (local, domaine, par_defaut) in state.mailboxes(nom).await? {
        let siens: Vec<Alias> = aliases
            .iter()
            .filter(|(boite, ..)| boite == &local)
            .map(|(_, l, expire, actif, _hint, note)| Alias {
                local: l.clone(),
                duree: match expire {
                    Some(e) => Duree::Temporaire { expire_le: *e },
                    None => Duree::Permanent,
                },
                actif: *actif,
                note: note.clone(),
            })
            .collect();

        c.boites.push(Boite {
            local,
            domaine,
            par_defaut,
            aliases: siens,
        });
    }
    Ok(c)
}

/// Analyse une durée : `30j`, `12h`, `90m`.
///
/// ⚠️ Un nombre nu est refusé plutôt qu'interprété. « 30 » voudrait dire trente
/// secondes en interne — l'utilisateur pensait trente jours, et son alias serait
/// expiré avant qu'il ne l'ait donné à quiconque.
fn parse_duree(s: &str) -> Result<i64, String> {
    let s = s.trim();
    let (n, unite) = s.split_at(s.len().saturating_sub(1));
    let n: i64 = n
        .parse()
        .map_err(|_| format!("durée illisible « {s} » — attendu 30j, 12h ou 90m"))?;

    match unite {
        "j" | "d" => Ok(n * 86_400),
        "h" => Ok(n * 3_600),
        "m" => Ok(n * 60),
        _ => Err(format!(
            "durée « {s} » sans unité — écris 30j, 12h ou 90m. Un nombre nu serait \
             compris en secondes, et l'alias expirerait avant d'avoir servi"
        )),
    }
}

/// La couverture d'une app : son état sur CHAQUE destination routée.
async fn couverture_de(
    state: &State,
    app: &str,
    seuil_s: i64,
) -> Result<hlb_backup::Couverture, Box<dyn std::error::Error>> {
    use hlb_backup::{Classe, EtatDestination};

    // Une destination peut recevoir les deux classes : on la compte une seule fois.
    let mut noms: Vec<String> = Vec::new();
    for c in [Classe::Critique, Classe::Volumineux] {
        for d in destinations_pour(state, app, c).await? {
            if !noms.contains(&d.nom) {
                noms.push(d.nom);
            }
        }
    }
    noms.sort();

    let mut par_destination = Vec::new();
    for n in noms {
        let age = state.seconds_since_last_success_on(app, &n).await?;
        par_destination.push((n, EtatDestination::juger(age, seuil_s)));
    }

    Ok(hlb_backup::Couverture {
        app: app.to_string(),
        par_destination,
    })
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
/// Instantanie les bases SQLite d'un volume, puis les archive.
///
/// 🔴 On sauvegarde l'INSTANTANÉ, jamais le fichier vivant. Une base SQLite en mode
/// WAL est trois fichiers (`.db`, `.db-wal`, `.db-shm`) que restic copie l'un après
/// l'autre ; entre-temps l'app écrit, et le jeu obtenu est incohérent.
async fn snapshot_sqlite_volume(
    state: &State,
    vault: &Vault,
    repo: Option<&str>,
    network: &str,
    app: &str,
    mountpoint: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    let staging = tempfile::tempdir()?;
    let bases =
        hlb_backup::sqlite_snapshot_all(std::path::Path::new(mountpoint), staging.path()).await?;

    let mut ok = 0;

    for chemin in &bases {
        let contenu = std::fs::read(chemin)?;
        let nom = chemin
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "base.snapshot".into());

        // Le même transit par volume Docker que les dumps SQL, et pour la même
        // raison : le dossier temporaire de l'hôte n'est pas visible du conteneur.
        let d = hlb_backup::pgdump::scheduled::Dump {
            app: app.to_string(),
            database: nom.trim_end_matches(".snapshot").to_string(),
            filename: nom,
            bytes: contenu,
        };

        // 🔴 Une base SQLite est de la classe CRITIQUE : petite, irremplaçable, et
        // c'est elle qu'on veut hors site en priorité.
        match archiver_partout(state, vault, app, "sqlite-snapshot", network, repo, &d).await {
            Ok(n) if n > 0 => {
                ok += 1;
            }
            Ok(_) => {}
            Err(e) => {
                // `archiver_partout` a déjà consigné l'échec destination par
                // destination : réenregistrer ici produirait un doublon sans
                // destination, qui fausserait le compteur d'échecs consécutifs.
                return Err(e);
            }
        }
    }
    Ok(ok)
}

/// Sauvegarde logique de chaque base déclarée.
///
/// Renvoie le nombre de dumps réussis. Un échec sur une base n'interrompt pas les
/// autres : perdre le dump de gitea ne doit pas priver vaultwarden du sien.
async fn dump_databases(
    state: &State,
    vault: &Vault,
    admin_url: &str,
    repo: Option<&str>,
    network: &str,
    bases: &[(String, String, String, String)],
) -> Result<usize, Box<dyn std::error::Error>> {
    use hlb_backup::pgdump::{scheduled, PgDumper, PgTarget};


    let Some(creds) = hlb_backup::parse_pg_url(admin_url) else {
        eprintln!("🔴 URL PostgreSQL illisible : dumps ignorés.");
        return Ok(0);
    };

    let at = maintenant();
    let mut ok = 0;

    for (app, moteur, base, _secret) in bases {
        // L'appelant a déjà trié par moteur ; ce garde-fou empêche qu'un futur appel
        // envoie une base MariaDB à `pg_dump`, qui échouerait de façon obscure.
        debug_assert_eq!(moteur, "postgres");

        print!("{app}/{base} (dump)… ");
        use std::io::Write as _;
        let _ = std::io::stdout().flush();

        // 🔴 On se connecte avec les identifiants d'ADMINISTRATION, pas ceux de
        // l'app : le rôle isolé de l'app n'a pas le droit de lire ses propres
        // séquences ni ses extensions, et le dump serait incomplet sans erreur.
        let cible = PgTarget {
            host: creds.host.clone(),
            port: creds.port,
            database: base.clone(),
            user: creds.user.clone(),
            password: creds.password.clone(),
        };

        let dumper = PgDumper::new(
            hlb_backup::PgContainerRunner::default().network(network),
        );

        match scheduled::produce(&dumper, app, &cible, at).await {
            Ok(d) => {
                match archiver_partout(state, vault, app, "sql-dump", network, repo, &d).await {
                    Ok(n) if n > 0 => {
                        println!("({} Ko)", d.bytes.len() / 1024);
                        ok += 1;
                    }
                    Ok(_) => println!("aucune destination servie"),
                    Err(e) => println!("✗ archivage : {e}"),
                }
            }
            Err(e) => {
                state.record_backup(app, "sql-dump", None, Some(&e.to_string())).await?;
                println!("✗ {e}");
            }
        }
    }
    Ok(ok)
}

/// Sauvegarde logique des bases MariaDB.
///
/// Le pendant de [`dump_databases`]. Deux différences qui comptent :
///
/// 🔴 **La cohérence atteignable est mesurée avant CHAQUE dump.**
/// `--single-transaction` ne protège que les tables transactionnelles ; sur une table
/// MyISAM ou Aria il est accepté sans un mot et n'apporte rien. Une migration d'app
/// peut introduire une telle table des mois après l'installation, donc la question se
/// repose à chaque passage — pas une fois pour toutes.
///
/// ⚠️ Quand on ne peut pas lire les moteurs, on retombe sur le verrouillage plutôt que
/// de supposer l'InnoDB : un dump bloquant vaut mieux qu'un dump incohérent.
async fn dump_mariadb_databases(
    state: &State,
    vault: &Vault,
    admin_url: &str,
    repo: Option<&str>,
    network: &str,
    bases: &[(String, String, String, String)],
) -> Result<usize, Box<dyn std::error::Error>> {
    use hlb_backup::mariadump::{self, Coherence, MariaDumper, MariaTarget};


    let Some(creds) = hlb_backup::parse_maria_url(admin_url) else {
        eprintln!("🔴 URL MariaDB illisible : dumps ignorés.");
        return Ok(0);
    };

    let at = maintenant();
    let mut ok = 0;

    // Une seule connexion d'administration pour interroger les moteurs de stockage.
    let admin = match hlb_platform::MariadbProvisioner::connect(admin_url).await {
        Ok(a) => Some(a),
        Err(e) => {
            eprintln!("⚠️  MariaDB injoignable ({e}) : cohérence indéterminée.");
            None
        }
    };

    for (app, _moteur, base, _secret) in bases {
        print!("{app}/{base} (dump)… ");
        use std::io::Write as _;
        let _ = std::io::stdout().flush();

        // 🔴 Identifiants d'ADMINISTRATION, comme en PostgreSQL : le rôle isolé de
        // l'app n'a pas le droit de lire ses propres routines ni ses déclencheurs, et
        // le dump serait amputé sans la moindre erreur.
        let cible = MariaTarget {
            host: creds.host.clone(),
            port: creds.port,
            database: base.clone(),
            user: creds.user.clone(),
            password: creds.password.clone(),
        };

        let coherence = match &admin {
            Some(a) => match a.column_values(&mariadump::requete_moteurs(base)).await {
                Ok(moteurs) => mariadump::coherence_pour(&moteurs),
                Err(e) => {
                    eprintln!("(moteurs illisibles : {e}) ");
                    Coherence::VerrouillageRequis
                }
            },
            None => Coherence::VerrouillageRequis,
        };

        if coherence == Coherence::VerrouillageRequis {
            // L'app est bloquée en écriture le temps du dump : ça se dit.
            print!("[verrou] ");
        }

        let dumper = MariaDumper::new(
            hlb_backup::MariaContainerRunner::default().network(network),
        );

        match mariadump::scheduled::produce(&dumper, app, &cible, coherence, at).await {
            Ok(d) => match archiver_partout(state, vault, app, "sql-dump", network, repo, &d).await {
                Ok(n) if n > 0 => {
                    println!("({} Ko)", d.bytes.len() / 1024);
                    ok += 1;
                }
                Ok(_) => println!("aucune destination servie"),
                Err(e) => println!("✗ archivage : {e}"),
            },
            Err(e) => {
                state.record_backup(app, "sql-dump", None, Some(&e.to_string())).await?;
                println!("✗ {e}");
            }
        }
    }
    Ok(ok)
}

/// Encodage pour-cent d'une requête PromQL destinée à une chaîne de requête.
///
/// ⚠️ Une requête PromQL contient `+`, `(`, `{`, `"` et des espaces. Passée telle
/// quelle, elle est tronquée au premier `&` ou mal interprétée — et la règle rend
/// alors « aucune donnée », qu'on lirait comme un problème de métrique alors que c'est
/// l'URL qui est cassée.
fn encoder_url(s: &str) -> String {
    let mut o = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

/// Nom du secret portant la clé privée de HomelabUS.
const SECRET_SSH: &str = "homelabus-ssh-key";

/// La clé SSH du cluster, créée au premier usage.
///
/// 🔴 Elle ne change JAMAIS d'elle-même. La régénérer couperait l'accès à toutes les
/// machines déjà rattachées, qui portent l'ancienne clé publique dans leur
/// `authorized_keys` — et il faudrait repasser sur chacune à la main.
async fn cluster_ssh_key(
    state: &State,
    vault: &Vault,
) -> Result<hlb_bootstrap::access::KeyPair, Box<dyn std::error::Error>> {
    if let Some(ct) = state.secret(SECRET_SSH).await? {
        let json = vault.decrypt(&ct)?;
        let v: serde_json::Value = serde_json::from_str(&json)?;
        return Ok(hlb_bootstrap::access::KeyPair {
            private: v["private"].as_str().unwrap_or_default().to_string(),
            public: v["public"].as_str().unwrap_or_default().to_string(),
        });
    }

    let kp = hlb_bootstrap::access::generate_keypair("homelabus@cluster").await?;
    let json = serde_json::json!({ "private": kp.private, "public": kp.public });
    state
        .store_secret_if_absent(
            SECRET_SSH,
            &vault.encrypt(&json.to_string())?,
            "clé SSH de HomelabUS pour piloter les nœuds",
        )
        .await?;
    eprintln!("✓ clé SSH du cluster générée (au coffre, jamais réaffichée)");
    Ok(kp)
}

/// Écrit la clé privée dans un fichier temporaire, le temps d'une connexion.
///
/// ⚠️ `ssh` REFUSE une clé privée lisible par d'autres que son propriétaire, avec un
/// message qui ne dit pas toujours clairement que c'est la cause. D'où le 0600 posé
/// explicitement plutôt que laissé au umask.
fn ecrire_cle_temporaire(
    dir: &std::path::Path,
    privee: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let chemin = dir.join("id_hlb");
    std::fs::write(&chemin, privee)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&chemin, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(chemin)
}

/// Rattache une machine au cluster, de bout en bout.
///
/// L'ordre des étapes n'est pas cosmétique :
///
/// 1. **Préchecks d'abord**, en lecture seule. Poser une clé sur une machine qui ne
///    pourra jamais accueillir de nœud laisse une trace à nettoyer pour rien.
/// 2. **Clé ensuite** : à partir de là, HomelabUS a son propre accès et ne dépend
///    plus de la clé personnelle qui a servi au premier contact.
/// 3. **Dépendances**, puis **join**, puis **tier**.
///
/// 🔴 Le tier en DERNIER, et jamais avant que le nœud soit dans le cluster : une
/// étiquette posée sur un nœud absent n'a nulle part où aller, et un nœud sans tier
/// ne reçoit aucun service (les contraintes de placement ne matchent rien) — ce qui
/// se manifeste par des `wait_healthy` qui expirent sans explication.
#[allow(clippy::too_many_arguments)]
async fn node_add(
    cli: &Cli,
    host: &str,
    user: Option<&str>,
    port: Option<u16>,
    identity: Option<&str>,
    role: Option<&str>,
    advertise_addr: Option<&str>,
    apply: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    use hlb_bootstrap::access;

    let state = State::open(&cli.state).await?;
    let vault = Vault::open_or_init(&cli.master_key)?;

    // ── 1. Préchecks, en lecture seule ────────────────────────────────────────
    let premier = build_runner(Some(host), user, port, identity);
    println!("Machine : {}\n", premier.label());

    let obs = hlb_bootstrap::observe(premier.as_ref()).await?;
    let rapport = hlb_bootstrap::preflight::run(&obs);
    for c in &rapport.checks {
        println!("  {}", c.describe());
    }
    println!();

    if !rapport.can_proceed() {
        eprintln!(
            "🔴 {} point(s) bloquant(s) — rien n'a été posé sur cette machine.",
            rapport.blocking().len()
        );
        return Ok(ExitCode::FAILURE);
    }

    // Le rôle recommandé dépend de la taille actuelle du cluster.
    let orch = SwarmOrchestrator::connect().ok();
    let nodes = match &orch {
        Some(o) => o.nodes().await.unwrap_or_default(),
        None => Vec::new(),
    };
    let profil = hlb_orchestrator::ClusterProfile::for_node_count(nodes.len() + 1);
    let managers = nodes
        .iter()
        .filter(|n| n.role == hlb_orchestrator::NodeRole::Manager)
        .count();
    let role_final = role
        .map(|r| r.to_string())
        .unwrap_or_else(|| {
            // 🔴 Deux managers sont PIRES qu'un seul : le quorum d'un cluster à deux
            // managers est de 2, donc la panne de l'un bloque tout le cluster, alors
            // qu'avec un seul manager la panne n'en bloque qu'un (§10.3).
            if managers == 0 || managers + 1 >= 3 { "manager" } else { "worker" }.to_string()
        });

    let tier_final = obs
        .total_memory_mb
        .map(hlb_orchestrator::cluster::tier_for_memory)
        .map(|t| t.to_string());

    if !apply {
        println!("Rattacherait cette machine au cluster :");
        println!("  rôle    : {role_final}{}", if role.is_some() { " (imposé)" } else { " (déduit)" });
        match &tier_final {
            Some(t) => println!("  tier    : {t} (déduit de {} Mo)", obs.total_memory_mb.unwrap_or(0)),
            None => println!("  tier    : ⚠️  indéterminable — à poser à la main"),
        }
        println!("  profil  : {} à {} nœud(s)", profil.as_str(), nodes.len() + 1);
        if advertise_addr.is_none() {
            println!();
            println!("  ⚠️  Sans --advertise-addr, Docker choisira une interface. Sur");
            println!("     une machine multi-interfaces, les autres nœuds tenteraient");
            println!("     de joindre une IP injoignable.");
        }
        println!();
        println!("  Étapes : préchecks ✓, clé SSH, dépendances, join, tier.");
        println!("  Relance avec --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    // ── 2. La clé de HomelabUS ────────────────────────────────────────────────
    let kp = cluster_ssh_key(&state, &vault).await?;
    let cle = access::ManagedKey::new(&kp.public, "hlb");

    // Un runner concret : le trait objet ne satisfait pas les bornes `Sized`.
    let ssh_premier = ssh_runner(host, user, port, identity);
    let avant = access::read_authorized_keys(&ssh_premier, "~").await?;
    let (apres, ch) = access::grant(&avant, &cle);

    if ch.is_noop() {
        println!("✓ clé SSH déjà en place ({} autre(s) clé(s) conservée(s))", ch.kept);
    } else {
        access::write_authorized_keys(&ssh_premier, "~", &apres, &avant).await?;
        println!(
            "✓ clé SSH posée ({} ajoutée, {} remplacée(s), {} conservée(s))",
            ch.added, ch.removed, ch.kept
        );
        state
            .audit("cli", ACTEUR_ROLE, "access-grant", host, "ok", None)
            .await?;
    }

    // À partir d'ici, on passe par NOTRE clé : c'est ce qui prouve qu'elle marche,
    // maintenant, plutôt que de le découvrir au prochain redémarrage.
    let tmp = tempfile::tempdir()?;
    let chemin_cle = ecrire_cle_temporaire(tmp.path(), &kp.private)?;
    let notre = build_runner(
        Some(host),
        user,
        port,
        chemin_cle.to_str(),
    );

    match notre.run(&["true".to_string()]).await {
        Ok(o) if o.ok() => println!("✓ accès par la clé de HomelabUS vérifié"),
        _ => {
            eprintln!("🔴 La clé a été posée mais ne permet PAS de se connecter.");
            eprintln!("   Cause la plus fréquente : sshd ignore authorized_keys quand");
            eprintln!("   ~/.ssh ou le fichier sont lisibles par le groupe — sans le dire.");
            eprintln!("   Vérifie : ls -ld ~/.ssh ~/.ssh/authorized_keys");
            return Ok(ExitCode::FAILURE);
        }
    }

    // ── 3. Dépendances ────────────────────────────────────────────────────────
    let Some(distro) = rapport.distro else {
        eprintln!("🔴 distribution non identifiée : impossible d'installer les dépendances.");
        return Ok(ExitCode::FAILURE);
    };

    let observees = observe_dependencies(notre.as_ref()).await?;
    let refs: Vec<(&str, Option<String>)> =
        observees.iter().map(|(n, v)| (*n, v.clone())).collect();
    let plan = hlb_bootstrap::plan_dependencies(&distro, &refs);

    if plan.is_satisfied() {
        println!("✓ dépendances déjà présentes");
    } else {
        let paquets = plan.to_install();
        println!("Installation de {} paquet(s)…", paquets.len());

        let pm = distro.package_manager();
        if let Some(refresh) = pm.refresh_command() {
            let o = notre.run(&refresh).await?;
            if !o.ok() {
                eprintln!("⚠️  index non rafraîchi : {}", o.stderr.trim());
            }
        }
        let o = notre.run(&pm.install_command(&paquets)).await?;
        if !o.ok() {
            eprintln!("🔴 installation échouée : {}", o.stderr.trim());
            return Ok(ExitCode::FAILURE);
        }
        println!("✓ dépendances installées");
    }

    // ── 4. Rattachement au Swarm ──────────────────────────────────────────────
    let Some(orch) = orch else {
        eprintln!("🔴 Swarm injoignable localement : impossible d'obtenir un jeton.");
        eprintln!("   La machine est prête, il ne manque que le join.");
        return Ok(ExitCode::FAILURE);
    };

    let tokens = orch.join_tokens().await?;
    let role_enum = if role_final == "manager" {
        hlb_orchestrator::NodeRole::Manager
    } else {
        hlb_orchestrator::NodeRole::Worker
    };

    let mut cmd = vec![
        "docker".to_string(), "swarm".into(), "join".into(),
        "--token".into(), tokens.for_role(role_enum).to_string(),
        tokens.advertise_addr.clone(),
    ];
    if let Some(a) = advertise_addr {
        cmd.push("--advertise-addr".into());
        cmd.push(a.to_string());
    }

    let o = notre.run(&cmd).await?;
    if !o.ok() && !o.stderr.contains("already part of a swarm") {
        eprintln!("🔴 join refusé : {}", o.stderr.trim());
        return Ok(ExitCode::FAILURE);
    }
    println!("✓ rattaché au Swarm en {role_final}");

    // ── 5. Le tier, une fois le nœud visible ──────────────────────────────────
    match tier_final {
        Some(t) => {
            // Le nœud vient d'apparaître : on le retrouve par son nom d'hôte.
            let nom = notre
                .run(&["hostname".to_string()])
                .await
                .ok()
                .and_then(|o| o.first_line())
                .unwrap_or_default();

            let apres_join = orch.nodes().await?;
            match apres_join.iter().find(|n| n.hostname == nom) {
                Some(n) => {
                    orch.label_node(&n.id, "tier", &t).await?;
                    println!("✓ tier={t} posé");
                }
                None => {
                    // Swarm met parfois un instant à publier le nouveau nœud.
                    println!("⚠️  nœud pas encore visible : pose le tier dans un instant");
                    println!("     hlb node tier {nom} --apply");
                }
            }
        }
        None => {
            // 🔴 Sans tier, ce nœud ne recevra AUCUN service : les contraintes de
            // placement ne matchent rien, et les déploiements expirent en silence.
            println!("🔴 Tier indéterminable — ce nœud ne recevra aucun service tant");
            println!("   qu'il n'en a pas un :");
            println!("     hlb node tier <nom> --set heavy --apply");
        }
    }

    state
        .audit("cli", ACTEUR_ROLE, "node-add", host, "ok", Some(&role_final))
        .await?;

    println!();
    println!("✓ {host} fait partie du cluster.");
    println!("  hlb cluster status");
    Ok(ExitCode::SUCCESS)
}

/// Un `SshRunner` concret, pour les opérations qui exigent `Sized`.
fn ssh_runner(
    host: &str,
    user: Option<&str>,
    port: Option<u16>,
    identity: Option<&str>,
) -> hlb_bootstrap::SshRunner {
    let mut r = hlb_bootstrap::SshRunner::new(host);
    if let Some(u) = user {
        r = r.user(u);
    }
    if let Some(p) = port {
        r = r.port(p);
    }
    if let Some(i) = identity {
        r = r.identity(i);
    }
    r
}

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

                let mariadb = match &cli.mariadb_admin {
                    Some(url) => match hlb_platform::MariadbProvisioner::connect(url).await {
                        Ok(m) => Some(m),
                        Err(e) => {
                            eprintln!("⚠️  MariaDB injoignable ({e}) — provisionnement ignoré.");
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
                if let Some(m) = &mariadb {
                    exec = exec.with_mariadb(m);
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

                // Le portail n'est posé que si des apps en ont besoin : le déclarer
                // sans app concernée produirait un bloc mort dans la configuration.
                if routes.iter().any(|r| r.needs_forward_auth) {
                    cfg.forward_auth = Some(hlb_ingress::caddyfile::ForwardAuth {
                        upstream: cli.forward_auth_upstream.clone(),
                        ..Default::default()
                    });
                    println!(
                        "Portail d'authentification : {} ({} app(s) sans SSO natif)",
                        cli.forward_auth_upstream,
                        routes.iter().filter(|r| r.needs_forward_auth).count()
                    );
                }

                // §6.4 — le wildcard : un certificat pour tout le domaine, obtenu
                // une fois. Sans lui, Caddy tente du HTTP-01 par nom, ce qui exige
                // un enregistrement DNS par app AVANT l'installation.
                match (&cli.base_domain, &cli.dns_provider) {
                    (Some(d), Some(p)) => {
                        const SECRET_DNS: &str = "dns-provider-token";
                        match state.secret(SECRET_DNS).await? {
                            Some(ct) => {
                                let vault = Vault::open_or_init(&cli.master_key)?;
                                cfg.acme = Some(hlb_ingress::caddyfile::Acme {
                                    provider: p.clone(),
                                    api_token: vault.decrypt(&ct)?,
                                    base_domain: d.clone(),
                                    staging: cli.acme_staging,
                                });
                                if cli.acme_staging {
                                    println!("🔴 ACME en mode TEST : certificats NON reconnus.");
                                } else {
                                    println!("Certificat wildcard : *.{d} via {p}");
                                }
                            }
                            None => {
                                eprintln!("🔴 Jeton DNS absent du coffre — pas de wildcard.");
                                eprintln!("   Dépose-le : hlb secret-set {SECRET_DNS}");
                                eprintln!("   Sans lui, Caddy tentera du HTTP-01 par nom,");
                                eprintln!("   ce qui exige un enregistrement DNS par app.");
                            }
                        }
                    }
                    (None, None) => {}
                    _ => {
                        eprintln!("⚠️  --base-domain et --dns-provider vont ensemble.");
                        eprintln!("   Un seul des deux ne produit aucun wildcard.");
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

        Command::Token(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = State::open(&cli.state).await?;

                match cmd {
                    TokenCmd::List => {
                        let v = state.list_tokens().await?;
                        if v.is_empty() {
                            println!("Aucun jeton — l'API n'accepterait personne.");
                            println!("  hlb token create <nom> --role admin --apply");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                        }

                        println!("{:<20} {:<10} DERNIER USAGE", "NOM", "RÔLE");
                        for (nom, role, usage) in &v {
                            println!(
                                "{nom:<20} {role:<10} {}",
                                usage.as_deref().unwrap_or("jamais")
                            );
                        }

                        // Un jeton jamais utilisé est soit oublié, soit compromis
                        // sans qu'on le sache : dans les deux cas il vaut mieux le
                        // révoquer que le laisser traîner.
                        let inutilises = v.iter().filter(|(_, _, u)| u.is_none()).count();
                        if inutilises > 0 {
                            println!();
                            println!("⚠️  {inutilises} jeton(s) jamais utilisé(s) : oubliés, ou");
                            println!("   distribués sans qu'on s'en serve. Révoque-les.");
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    TokenCmd::Revoke { name } => {
                        if state.revoke_token(name).await? {
                            state
                                .audit("cli", ACTEUR_ROLE, "token-revoke", name, "ok", None)
                                .await?;
                            println!("✓ « {name} » révoqué — effet immédiat.");

                            if !state.has_tokens().await? {
                                println!();
                                println!("🔴 C'était le DERNIER jeton. Au prochain démarrage,");
                                println!("   le controller refusera de se lancer sans");
                                println!("   --insecure-no-auth. Crée-en un autre avant.");
                            }
                            Ok(ExitCode::SUCCESS)
                        } else {
                            eprintln!("Aucun jeton nommé « {name} ».");
                            Ok(ExitCode::FAILURE)
                        }
                    }

                    TokenCmd::Create { name, role, apply } => {
                        let Some(r) = hlb_types::Role::parse(role) else {
                            eprintln!("Rôle « {role} » inconnu.");
                            eprintln!("  viewer   : tout voir, ne rien modifier");
                            eprintln!("  operator : installer, mettre à jour, sauvegarder");
                            eprintln!("  admin    : tout, y compris ce qui détruit");
                            return Ok(ExitCode::FAILURE);
                        };

                        if !apply {
                            println!("Créerait le jeton « {name} » en rôle {}.", r.as_str());
                            println!();
                            println!("  🔴 Sa valeur sera affichée UNE SEULE FOIS : seule une");
                            println!("     empreinte est conservée. Un jeton perdu ne se");
                            println!("     retrouve pas, il se remplace.");
                            println!();
                            println!("  Relance avec --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        // L'entropie vient du même générateur que les mots de passe
                        // du coffre : un jeton faible serait le maillon le plus court.
                        let mut alea = [0u8; hlb_types::token::TOKEN_BYTES];
                        hlb_secrets::fill_random(&mut alea);

                        let (valeur, stocke) = hlb_types::generate_token(name, r, alea);
                        state.store_token(&stocke).await?;
                        state
                            .audit("cli", ACTEUR_ROLE, "token-create", name, "ok", Some(r.as_str()))
                            .await?;

                        println!("✓ jeton « {name} » créé en rôle {}.", r.as_str());
                        println!();
                        println!("🔴 NOTE-LE MAINTENANT — il ne sera plus jamais affiché :");
                        println!();
                        println!("    {valeur}");
                        println!();
                        println!("Usage :");
                        println!("    curl -H \"Authorization: Bearer {valeur}\" \\");
                        println!("         http://<controller>:8420/api/apps");
                        println!();
                        println!("    hlb-ui --token {valeur}");
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::Snapshot(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                use hlb_backup::snapshot as snap;

                let dataset = match cmd {
                    SnapshotCmd::Create { dataset, .. } | SnapshotCmd::List { dataset } => dataset,
                };

                let Some(fs) = snap::detect(dataset).await else {
                    eprintln!("« {dataset} » n'est ni un dataset ZFS ni un sous-volume btrfs.");
                    eprintln!();
                    eprintln!("  Un instantané ne peut porter que sur l'un des deux — pas");
                    eprintln!("  sur un répertoire ordinaire. Vérifie :");
                    eprintln!("    zfs list {dataset}");
                    eprintln!("    btrfs subvolume show {dataset}");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                };

                match cmd {
                    SnapshotCmd::List { .. } => {
                        let c = snap::list_command(fs, dataset);
                        let out = tokio::process::Command::new(&c[0])
                            .args(&c[1..])
                            .output()
                            .await?;

                        let v = snap::parse_list(fs, &String::from_utf8_lossy(&out.stdout));
                        if v.is_empty() {
                            println!("Aucun instantané HomelabUS sur {dataset} ({}).", fs.as_str());
                            println!("  hlb snapshot create {dataset} --apply");
                            return Ok(ExitCode::SUCCESS);
                        }

                        println!("{} instantané(s) sur {dataset} ({}) :", v.len(), fs.as_str());
                        for s in &v {
                            println!("  {}", s.label);
                        }
                        println!();
                        println!("⚠️  Ils vivent sur le MÊME pool que les données : un disque");
                        println!("   mort les emporte. Ce ne sont pas des sauvegardes.");
                        println!();
                        println!("   La suppression reste manuelle et volontaire :");
                        match fs {
                            hlb_backup::Filesystem::Zfs => {
                                println!("     zfs destroy {dataset}@<nom>")
                            }
                            hlb_backup::Filesystem::Btrfs => {
                                println!("     btrfs subvolume delete {dataset}/.snapshots/<nom>")
                            }
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    SnapshotCmd::Create { motif, apply, .. } => {
                        let label = snap::snapshot_label(motif, maintenant())?;

                        if !apply {
                            println!("Créerait sur {dataset} ({}) :", fs.as_str());
                            println!("  {label}");
                            println!();
                            println!("  Commande : {}", snap::create_command(fs, dataset, &label).join(" "));
                            println!();
                            println!("  🔴 Un instantané n'est PAS une sauvegarde : il vit sur le");
                            println!("     même pool que les données. Il protège de l'erreur");
                            println!("     logique, pas de la perte du disque.");
                            println!();
                            println!("  Relance avec --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        match snap::create(fs, dataset, &label).await {
                            Ok(_) => {
                                let state = State::open(&cli.state).await?;
                                state
                                    .audit("cli", ACTEUR_ROLE, "snapshot-create", dataset, "ok",
                                           Some(&label))
                                    .await?;
                                println!("✓ {label}");
                                println!();
                                println!("  Retour arrière :");
                                match fs {
                                    hlb_backup::Filesystem::Zfs => {
                                        println!("    zfs rollback {dataset}@{label}")
                                    }
                                    hlb_backup::Filesystem::Btrfs => {
                                        println!("    (btrfs : remplacer le sous-volume par");
                                        println!("     {dataset}/.snapshots/{label})")
                                    }
                                }
                                Ok(ExitCode::SUCCESS)
                            }
                            Err(e) => {
                                eprintln!("{e}");
                                Ok(ExitCode::FAILURE)
                            }
                        }
                    }
                }
            })
        }

        Command::Selfy(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                use hlb_selfupdate as su;

                let state = State::open(&cli.state).await?;
                let courante = su::Version::current();

                // ⚠️ Le CLI ne peut PAS interroger les agents : ils n'écoutent que
                // sur l'overlay Swarm, où seul le controller est présent. Passer par
                // lui créerait une inversion de couches, et le simuler ferait pire —
                // un parc supposé à jour est exactement ce qui casse le dialogue.
                //
                // On raisonne donc sur ce qu'on sait vraiment, et `self status` dit
                // où regarder pour le reste.
                let agents: Vec<su::AgentNode> = Vec::new();

                // Les migrations livrées avec ce binaire, et leur réversibilité.
                let migrations = migrations_connues();

                match cmd {
                    SelfCmd::Status => {
                        println!("HomelabUS {courante}  (protocole {})", su::PROTOCOL);
                        println!();

                        println!("Compatibilité du parc : à vérifier depuis le controller,");
                        println!("  qui est le seul à voir les agents sur l'overlay :");
                        println!("    curl -s http://<controller>:8420/metrics | grep hlb_node");
                        println!();
                        let irreversibles: Vec<_> =
                            migrations.iter().filter(|m| !m.reversible).collect();
                        if irreversibles.is_empty() {
                            println!("✓ {} migration(s), toutes réversibles.", migrations.len());
                        } else {
                            println!("🔴 {} migration(s) SANS retour arrière :", irreversibles.len());
                            for m in irreversibles {
                                println!("    {}", m.name);
                            }
                            println!("   Aucune mise à jour ne sera possible tant qu'elles");
                            println!("   n'auront pas leur `down`.");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                        }

                        println!();
                        println!("⚠️  La mise à jour du controller n'est JAMAIS automatique :");
                        println!("   c'est le seul composant dont la panne t'empêche de");
                        println!("   réparer les autres.");
                        Ok(ExitCode::SUCCESS)
                    }

                    SelfCmd::Rollback { binary, to_migration, confirm, apply } => {
                        if *binary {
                            let chemins = su::SwapPaths::new(std::env::current_exe()?);
                            if !apply {
                                println!("Restaurerait {}", chemins.previous().display());
                                println!();
                                println!("  ⚠️  Le SCHÉMA n'est pas touché. Si la version qu'on");
                                println!("     quitte l'avait migré, l'ancien binaire lira un");
                                println!("     schéma qu'il ne comprend pas :");
                                println!("       hlb self rollback --to-migration <n> --apply --confirm");
                                println!();
                                println!("  Relance avec --apply.");
                                return Ok(ExitCode::SUCCESS);
                            }

                            match su::swap::rollback(&chemins) {
                                Ok(()) => {
                                    state
                                        .audit("cli", ACTEUR_ROLE, "self-rollback-binary",
                                               "binaire", "ok", None)
                                        .await?;
                                    println!("✓ binaire précédent restauré.");
                                    println!();
                                    println!("⚠️  Redémarre le controller pour qu'il prenne effet.");
                                    return Ok(ExitCode::SUCCESS);
                                }
                                Err(e) => {
                                    eprintln!("{}", e.describe());
                                    return Ok(ExitCode::FAILURE);
                                }
                            }
                        }

                        if *to_migration == 0 {
                            eprintln!("Précise ce qu'il faut défaire :");
                            eprintln!("  --binary                  restaurer le binaire précédent");
                            eprintln!("  --to-migration <n>        revenir au schéma n");
                            return Ok(ExitCode::FAILURE);
                        }

                        let actuelle = state.schema_version().await?;
                        let Some(actuelle) = actuelle else {
                            eprintln!("Base non migrée — rien à défaire.");
                            return Ok(ExitCode::FAILURE);
                        };

                        if *to_migration >= actuelle {
                            println!(
                                "Le schéma est en {actuelle} : revenir à {to_migration} \
                                 ne défait rien."
                            );
                            return Ok(ExitCode::SUCCESS);
                        }

                        // 🔴 On DIT ce qui sera perdu, migration par migration.
                        // « des données seront perdues » n'aide personne à décider.
                        let perdu: Vec<&str> = migrations
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| (*i as i64) + 1 > *to_migration)
                            .map(|(_, m)| m.name.as_str())
                            .collect();

                        println!("Retour du schéma {actuelle} → {to_migration}");
                        println!();
                        println!("🔴 {} migration(s) défaite(s) :", perdu.len());
                        for m in &perdu {
                            for l in consequence_migration(m) {
                                println!("    {l}");
                            }
                        }

                        if !apply {
                            println!();
                            println!("  Rien n'a été modifié. Relance avec --apply --confirm.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        if !confirm {
                            eprintln!();
                            eprintln!("🔴 --confirm est requis : ces pertes sont définitives.");
                            return Ok(ExitCode::FAILURE);
                        }

                        state.undo_migrations(*to_migration).await?;
                        println!();
                        println!("✓ schéma en {to_migration}.");
                        println!();
                        println!("⚠️  Le BINAIRE n'a pas changé. Remplace-le par la version");
                        println!("   correspondante, sinon il remigrera au prochain démarrage.");
                        Ok(ExitCode::SUCCESS)
                    }

                    SelfCmd::Update { version, from, key, confirm, apply } => {
                        let Some(cible) = su::Version::parse(version) else {
                            eprintln!("Version illisible : « {version} » (attendu : 0.2.0)");
                            return Ok(ExitCode::FAILURE);
                        };

                        // Une sauvegarde récente de l'état : sans elle, un échec en
                        // cours de migration est définitif.
                        let sauvegarde = state
                            .seconds_since_last_success("postgres")
                            .await
                            .ok()
                            .flatten()
                            .is_some()
                            || !migrations.is_empty() && state.installed_apps().await?.is_empty();

                        let pre = su::Preflight {
                            from: courante,
                            to: cible,
                            agents,
                            migrations,
                            state_backed_up: sauvegarde,
                        };

                        let plan = match su::plan(&pre) {
                            Ok(p) => p,
                            Err(b) => {
                                println!("{}", b.describe());
                                return Ok(if b.is_refusal() {
                                    ExitCode::FAILURE
                                } else {
                                    // « Déjà à jour » n'est pas un échec : un code
                                    // d'erreur ferait croire à un problème dans un
                                    // script de mise à jour.
                                    ExitCode::SUCCESS
                                });
                            }
                        };

                        println!("{}", plan.describe());

                        if plan.jump.needs_confirmation() && !confirm {
                            eprintln!();
                            eprintln!("🔴 {} : validation explicite requise.", plan.jump.describe());
                            eprintln!("   Relis les notes de version, puis --confirm.");
                            return Ok(ExitCode::FAILURE);
                        }

                        if !apply {
                            println!();
                            println!("  Rien n'a été modifié. Relance avec --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        // 🔴 Sans source ET sans clé, on ne télécharge rien. Une mise
                        // à jour non vérifiée remplacerait le binaire qui détient la
                        // clé du coffre et pilote Docker.
                        let (Some(base_url), Some(cle_hex)) = (from, key) else {
                            println!();
                            println!("🔴 Bascule impossible : il manque la source ou la clé.");
                            println!();
                            println!("   --from <url>  où trouver le binaire et son manifeste");
                            println!("   --key <hex>   clé publique Ed25519 de publication");
                            println!();
                            println!("   Sans vérification de signature, la mise à jour serait");
                            println!("   le meilleur vecteur de compromission du système : elle");
                            println!("   remplace le binaire qui détient la clé du coffre.");
                            println!();
                            println!("   Le reste est déjà garanti : parc compatible, migrations");
                            println!("   réversibles, ordre des opérations établi.");
                            state
                                .audit("cli", ACTEUR_ROLE, "self-update-plan", version, "ok", None)
                                .await?;
                            return Ok(ExitCode::SUCCESS);
                        };

                        let cle = match su::signature::parse_key(cle_hex) {
                            Ok(k) => k,
                            Err(e) => {
                                eprintln!("{}", e.describe());
                                return Ok(ExitCode::FAILURE);
                            }
                        };

                        // La bascule doit être possible AVANT de télécharger : la
                        // découvrir impossible après aurait fait perdre du temps, et
                        // la découvrir après avoir écarté l'ancien binaire laisserait
                        // la machine sans outil.
                        let chemins = su::SwapPaths::new(std::env::current_exe()?);
                        if let Err(e) = su::swap::preflight(&chemins) {
                            eprintln!("{}", e.describe());
                            return Ok(ExitCode::FAILURE);
                        }

                        println!();
                        println!("Téléchargement depuis {base_url}…");
                        let (binaire, manifeste) =
                            match telecharger_version(base_url, &cible).await {
                                Ok(v) => v,
                                Err(e) => {
                                    eprintln!("🔴 {e}");
                                    return Ok(ExitCode::FAILURE);
                                }
                            };

                        if let Err(r) = su::verify_release(&cle, &manifeste, cible, &binaire) {
                            eprintln!("{}", r.describe());
                            state
                                .audit("cli", ACTEUR_ROLE, "self-update", version, "refused",
                                       Some(&r.describe()))
                                .await?;
                            return Ok(ExitCode::FAILURE);
                        }
                        println!("✓ signature vérifiée ({} octets)", binaire.len());

                        let garde = match su::swap(&chemins, &binaire) {
                            Ok(g) => g,
                            Err(e) => {
                                eprintln!("{}", e.describe());
                                return Ok(ExitCode::FAILURE);
                            }
                        };

                        state
                            .audit("cli", ACTEUR_ROLE, "self-update", version, "ok", None)
                            .await?;

                        println!("✓ binaire remplacé.");
                        println!();
                        println!("  Ancien conservé : {}", garde.display());
                        println!("  Retour arrière  : hlb self rollback --binary");
                        println!();
                        println!("⚠️  Le processus EN COURS tourne toujours sur l'ancien code :");
                        println!("   sous Unix, son inode reste vivant. Redémarre le controller");
                        println!("   pour que la nouvelle version prenne effet.");
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::Replication(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                use hlb_backup::replication as repl;

                match cmd {
                    ReplCmd::Config { standby, primary_host, user } => {
                        let slot = repl::slot_name(standby)?;

                        println!("═══ Sur la PRIMAIRE, dans postgresql.conf ═══");
                        println!("{}", repl::primary_settings(1));
                        println!("═══ Puis, une fois redémarrée ═══");
                        println!("  CREATE ROLE {user} WITH REPLICATION LOGIN PASSWORD '…';");
                        println!("  SELECT pg_create_physical_replication_slot('{slot}');");
                        println!();
                        println!("  Et dans pg_hba.conf — la réplication est traitée comme");
                        println!("  une base à part, se connecter en psql ne suffit pas :");
                        println!("    host replication {user} all scram-sha-256");
                        println!();
                        println!("═══ Sur le STANDBY ═══");
                        println!("  1. Copie initiale, qui pose déjà standby.signal :");
                        println!("       pg_basebackup -h {primary_host} -U {user} \\");
                        println!("         -D /var/lib/postgresql/data -R -X stream -S {slot} -P");
                        println!();
                        println!("  2. Dans postgresql.auto.conf, APRÈS le pg_basebackup :");
                        println!("{}", repl::APPLIQUER_APRES_BASEBACKUP);
                        println!();
                        println!("{}", repl::standby_settings(primary_host, 5432, &slot, user));
                        Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS)
                    }

                    ReplCmd::Status => {
                        let Some(url) = cli.postgres_admin.as_deref() else {
                            eprintln!("Aucune URL PostgreSQL — utilise --postgres-admin.");
                            return Ok(ExitCode::FAILURE);
                        };

                        let pg = hlb_platform::PostgresProvisioner::connect(url).await?;

                        let standbys = repl::parse_standbys(
                            &pg.query_raw(
                                "SELECT application_name || '|' || state || '|' ||
                                 COALESCE(pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn), 0)
                                 FROM pg_stat_replication",
                            )
                            .await?,
                        );

                        // 🔴 `wal_status = 'lost'` est l'invalidation : le slot ne
                        // retient plus rien, mais le standby est irrécupérable.
                        let slots = repl::parse_slots(
                            &pg.query_raw(
                                "SELECT slot_name || '|' || CASE WHEN active THEN 't' ELSE 'f' END
                                 || '|' || COALESCE(
                                      pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn), 0)
                                 || '|' || CASE WHEN wal_status = 'lost' THEN 't' ELSE 'f' END
                                 FROM pg_replication_slots WHERE slot_type = 'physical'",
                            )
                            .await?,
                        );

                        if standbys.is_empty() {
                            println!("Aucun standby connecté.");
                        } else {
                            println!("Standbys :");
                            for s in &standbys {
                                println!("  {}", s.describe());
                            }

                            // 🔴 Deux standbys sous le même nom rendent cette sortie
                            // inutile au pire moment : on voit qu'un nœud décroche
                            // sans pouvoir dire lequel. Cause quasi certaine : les
                            // réglages posés AVANT `pg_basebackup -R`, qui réécrit
                            // postgresql.auto.conf et emporte l'application_name.
                            for nom in repl::indistinguishable(&standbys) {
                                println!();
                                println!("⚠️ Plusieurs standbys s'annoncent « {nom} » : impossible");
                                println!("   de savoir lequel décroche. Pose un application_name");
                                println!("   distinct sur chacun (hlb replication config).");
                            }
                        }

                        let dangereux: Vec<_> =
                            slots.iter().filter(|s| s.is_dangerous()).collect();
                        if !slots.is_empty() {
                            println!();
                            println!("Slots sans consommateur :");
                            for s in &slots {
                                println!("  {}", s.describe());
                            }
                        }

                        let mauvais = standbys
                            .iter()
                            .any(|s| s.health() == hlb_backup::StandbyHealth::Lagging);

                        if !dangereux.is_empty() || mauvais {
                            println!();
                            println!("🔴 Le disque de la PRIMAIRE est en jeu : un slot sans");
                            println!("   consommateur retient le WAL jusqu'à saturation.");
                            return Ok(ExitCode::FAILURE);
                        }
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::User(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                use hlb_users::{Demande, Profil};

                let state = State::open(&cli.state).await?;
                let _vault = Vault::open_or_init(&cli.master_key)?;
                // ⚠️ Le domaine mail n'est pas un paramètre global : il vient de
                // `--mail-domain` des commandes qui en ont un. Ici, on prend le
                // domaine du cluster, à défaut « local » — et on le DIT dans la
                // sortie plutôt que de fabriquer une adresse silencieusement fausse.
                let domaine = std::env::var("HLB_MAIL_DOMAIN").unwrap_or_else(|_| "local".into());

                match cmd {
                    UserCmd::Add { nom, email, display_name, profil } => {
                        hlb_users::valider_nom(nom)?;
                        let Some(p) = Profil::par_nom(profil) else {
                            eprintln!("profil inconnu « {profil} » — standard, invite, illimite");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                        };

                        // La partie locale de l'adresse par défaut.
                        let local = match email {
                            Some(e) => e.split('@').next().unwrap_or(nom).to_string(),
                            None => nom.clone(),
                        };
                        let dom = email
                            .as_ref()
                            .and_then(|e| e.split('@').nth(1))
                            .unwrap_or(&domaine)
                            .to_string();

                        state.upsert_user(nom, &p.nom, None).await?;

                        // 🔴 L'identité d'abord, la boîte ensuite, et chaque étape est
                        // idempotente. Relancer après un échec termine ce qui manque
                        // au lieu de tout refaire — ou pire, de créer un doublon.
                        let pocket = match (&cli.pocketid_url, &cli.pocketid_key) {
                            (Some(u), Some(k)) => Some(hlb_identity::PocketId::new(u, k)),
                            _ => None,
                        };
                        let identite = match pocket {
                            Some(pid) => match pid.find_user(nom).await? {
                                Some(u) => {
                                    println!("✓ identité déjà présente");
                                    Some(u.id)
                                }
                                None => {
                                    let affiche =
                                        display_name.clone().unwrap_or_else(|| nom.clone());
                                    let u = pid
                                        .create_user(
                                            nom,
                                            Some(&format!("{local}@{dom}")),
                                            &affiche,
                                            &[],
                                        )
                                        .await?;
                                    println!("✓ identité PocketID créée");

                                    // 🔴 Aucun mot de passe : PocketID s'authentifie par
                                    // clé d'accès. C'est un lien à usage unique qui
                                    // remplace l'envoi d'un secret initial — et il est
                                    // affiché UNE fois, jamais enregistré.
                                    match pid.one_time_token(&u.id, "12h").await {
                                        Ok(jeton) => {
                                            println!();
                                            println!("  Lien d'inscription (valable 12 h, usage unique) :");
                                            println!("    {}/lc/{jeton}", pid.issuer());
                                            println!();
                                            println!("  ⚠️ Il n'est pas enregistré : note-le maintenant.");
                                        }
                                        Err(e) => {
                                            eprintln!("⚠️ jeton d'inscription non obtenu ({e})");
                                            eprintln!("   Le compte existe mais personne ne peut s'y connecter.");
                                        }
                                    }
                                    Some(u.id)
                                }
                            },
                            None => {
                                eprintln!("⚠️ PocketID non configuré : identité NON créée.");
                                None
                            }
                        };

                        if let Some(id) = &identite {
                            state.upsert_user(nom, &p.nom, Some(id)).await?;
                        }

                        // La boîte par défaut.
                        let deja = state.mailboxes(nom).await?;
                        if deja.is_empty() {
                            state.add_mailbox(nom, &local, &dom, true).await?;
                            println!("✓ boîte {local}@{dom} enregistrée");
                        } else {
                            println!("✓ boîte déjà enregistrée");
                        }

                        // 🔴 L'état à moitié créé est DIT, pas laissé à découvrir.
                        let compte = charger_compte(&state, nom).await?;
                        let c = compte.coherence();
                        if !c.est_complet() {
                            println!();
                            println!("{}", c.describe());
                            return Ok(ExitCode::FAILURE);
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    UserCmd::List => {
                        let users = state.users().await?;
                        if users.is_empty() {
                            println!("Aucun compte.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        let maintenant = maintenant();
                        for (nom, profil, _) in &users {
                            let c = charger_compte(&state, nom).await?;
                            let u = c.usage(maintenant);
                            let p = Profil::par_nom(profil).unwrap_or_else(Profil::standard);

                            println!("{nom}  [{profil}]  {}", c.coherence().describe());
                            for b in &c.boites {
                                let marque = if b.par_defaut { "★" } else { " " };
                                println!("  {marque} {}", b.adresse());
                            }
                            println!(
                                "    boîtes {}/{}  permanents {}/{}  temporaires {}/{}",
                                u.boites, p.max_boites,
                                u.aliases_permanents, p.max_aliases_permanents,
                                u.aliases_temporaires, p.max_aliases_temporaires,
                            );

                            let rompues = c.promesses_rompues(maintenant);
                            if !rompues.is_empty() {
                                println!(
                                    "    🔴 {} alias expiré(s) TOUJOURS ACTIF(S) — « hlb user alias purge »",
                                    rompues.len()
                                );
                            }
                            println!();
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    UserCmd::Profile { nom, profil } => {
                        let Some(p) = Profil::par_nom(profil) else {
                            eprintln!("profil inconnu « {profil} »");
                            return Ok(ExitCode::FAILURE);
                        };
                        let c = charger_compte(&state, nom).await?;
                        let u = c.usage(maintenant());

                        // ⚠️ Rétrécir un profil sous l'usage courant ne supprime rien —
                        // ce serait détruire des données sur un changement de réglage.
                        // On l'accepte et on le DIT : les créations futures seront
                        // refusées jusqu'à ce que l'usage repasse sous la limite.
                        if u.boites > p.max_boites {
                            println!(
                                "⚠️ {nom} a {} boîtes, le profil « {} » en autorise {}.",
                                u.boites, p.nom, p.max_boites
                            );
                            println!("   Rien n'est supprimé. Aucune nouvelle boîte ne sera acceptée.");
                        }

                        state.upsert_user(nom, &p.nom, None).await?;
                        println!("✓ {nom} → profil « {} »", p.nom);
                        Ok(ExitCode::SUCCESS)
                    }

                    UserCmd::Mailbox(sous) => match sous {
                        MailboxCmd::Add { nom, local } => {
                            let c = charger_compte(&state, nom).await?;
                            let p = Profil::par_nom(&c.profil).unwrap_or_else(Profil::standard);
                            p.autorise(&c.usage(maintenant()), Demande::Boite)
                                .map_err(|r| r.to_string())?;

                            state.add_mailbox(nom, local, &domaine, false).await?;
                            println!("✓ {local}@{domaine}");
                            Ok(ExitCode::SUCCESS)
                        }
                        MailboxCmd::Remove { nom, local } => {
                            let c = charger_compte(&state, nom).await?;
                            c.peut_supprimer_boite(local)?;
                            state.remove_mailbox(nom, local).await?;
                            println!("✓ boîte {local} retirée");
                            Ok(ExitCode::SUCCESS)
                        }
                    },

                    UserCmd::Alias(sous) => {
                        gerer_alias(&state, &domaine, sous).await
                    }
                }
            })
        }

        Command::Metrics(cmd) => {
            use hlb_metrics::{deadman, rules, scrape};

            match cmd {
                MetricsCmd::Scrape { controller, token } => {
                    if token.is_none() {
                        // 🔴 Sans jeton, VictoriaMetrics collecte des 401 en boucle et
                        // le tableau de bord reste vide — sans que rien n'indique que
                        // c'est un problème d'authentification.
                        eprintln!("⚠️  Aucun jeton : /metrics est protégé (§9ter) et la");
                        eprintln!("   collecte ne recevra que des 401. Crée-en un :");
                        eprintln!("     hlb token create collecte --role metrics");
                        eprintln!();
                    }
                    let cible = scrape::Cible::controller(controller.clone(), token.clone());
                    print!("{}", scrape::config_collecte(&[cible]));
                    println!();
                    println!("# Rétention conseillée : -retentionPeriod={}", scrape::RETENTION);
                    Ok(ExitCode::SUCCESS)
                }

                MetricsCmd::Rules => {
                    for r in rules::regles_par_defaut() {
                        println!("{} [{:?}]", r.nom, r.niveau);
                        println!("  {}", r.explication);
                        println!("  requête : {}", r.requete);
                        let sens = match r.comparaison {
                            hlb_metrics::Comparaison::Depasse => ">",
                            hlb_metrics::Comparaison::TombeSous => "<",
                        };
                        println!("  déclenche si {sens} {}", r.seuil);
                        if r.absence_alarmante {
                            println!("  ⚠️ l'absence de donnée est elle-même une alerte");
                        }
                        println!();
                    }
                    Ok(ExitCode::SUCCESS)
                }

                MetricsCmd::Check { url } => {
                    let rt = tokio::runtime::Runtime::new()?;
                    rt.block_on(async {
                    let mut alertes = 0;
                    let mut aveugles = 0;

                    for r in rules::regles_par_defaut() {
                        let point = format!(
                            "{}/api/v1/query?query={}",
                            url.trim_end_matches('/'),
                            encoder_url(r.requete)
                        );

                        let evaluation = match reqwest::get(&point).await {
                            Ok(rep) => match rep.text().await {
                                Ok(corps) => match hlb_metrics::valeurs_promql(&corps) {
                                    Ok(v) => r.juger(&v),
                                    Err(e) => hlb_metrics::Evaluation::Inconnu {
                                        raison: e.to_string(),
                                    },
                                },
                                Err(e) => hlb_metrics::Evaluation::Inconnu {
                                    raison: e.to_string(),
                                },
                            },
                            // 🔴 VictoriaMetrics injoignable n'est PAS « rien à
                            // signaler » : c'est la surveillance elle-même qui est
                            // tombée, donc toutes les règles sont aveugles.
                            Err(e) => hlb_metrics::Evaluation::Inconnu {
                                raison: format!("VictoriaMetrics injoignable : {e}"),
                            },
                        };

                        match &evaluation {
                            hlb_metrics::Evaluation::Ok => println!("✓ {}", r.nom),
                            hlb_metrics::Evaluation::Declenchee { valeur } => {
                                println!("🔴 {} — {} (mesuré {valeur:.2})", r.nom, r.explication);
                                alertes += 1;
                            }
                            hlb_metrics::Evaluation::Inconnu { raison } => {
                                println!("❓ {} — AVEUGLE : {raison}", r.nom);
                                aveugles += 1;
                            }
                        }
                    }

                    println!();
                    if aveugles > 0 {
                        // 🔴 « Je ne sais pas » ne doit jamais se lire comme « tout va
                        // bien » : c'est exactement ce que ce module existe pour
                        // empêcher. Un code de sortie 0 le ferait croire.
                        println!("🔴 {aveugles} règle(s) AVEUGLE(S) : ce n'est pas « rien à");
                        println!("   signaler », c'est « on ne sait pas ».");
                    }
                    if alertes > 0 {
                        println!("🔴 {alertes} alerte(s) active(s).");
                    }
                    if alertes == 0 && aveugles == 0 {
                        println!("Toutes les règles sont vertes, et toutes ont des données.");
                    }

                    Ok::<_, Box<dyn std::error::Error>>(if alertes + aveugles > 0 {
                        ExitCode::FAILURE
                    } else {
                        ExitCode::SUCCESS
                    })
                    })
                }

                MetricsCmd::Deadman { heartbeat_file, ntfy } => {
                    println!("{}", deadman::script_veilleur(heartbeat_file, ntfy, "HomelabUS"));
                    eprintln!("# ─────────────────────────────────────────────────────");
                    eprintln!("# 🔴 À poser sur le NAS, PAS sur le nœud du controller :");
                    eprintln!("#    un veilleur hébergé par ce qu'il surveille meurt");
                    eprintln!("#    avec lui et ne détecte rien.");
                    eprintln!("#");
                    eprintln!("# 🔴 Le sujet ntfy doit être DISTINCT de celui de");
                    eprintln!("#    HomelabUS : si le controller est mort, c'est le");
                    eprintln!("#    veilleur seul qui doit pouvoir parler.");
                    eprintln!("#");
                    eprintln!("# Battements manqués tolérés : 3 (soit {} s de silence).", deadman::SILENCE_MAX_S);
                    Ok(ExitCode::SUCCESS)
                }
            }
        }

        Command::Dr(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                use hlb_backup::dr;

                let state = State::open(&cli.state).await?;
                let orch = SwarmOrchestrator::connect().ok();

                match cmd {
                    DrCmd::Exercise { base_dir, image, disposable, apply } => {
                        use hlb_backup::drill;

                        let bases = charger_bases(&state).await?;
                        let cible = drill::Target {
                            container: drill::container_name(maintenant())?,
                            disposable: *disposable,
                        };

                        if let Err(r) = drill::authorize(&cible, !bases.is_empty()) {
                            eprintln!("{}", r.describe());
                            return Ok(ExitCode::FAILURE);
                        }

                        // `authorize` a déjà refusé le cas vide, mais on ne s'appuie
                        // pas dessus : un `expect` en production casse le binaire,
                        // là où un refus explicite reste réparable.
                        let Some(derniere) = bases.iter().max_by_key(|b| b.finished_at) else {
                            eprintln!("Aucune sauvegarde de base — rien à exercer.");
                            return Ok(ExitCode::FAILURE);
                        };

                        if !apply {
                            println!("Exercerait la restauration de {} :", derniere.id);
                            println!("  conteneur jetable : {}", cible.container);
                            println!("  source (lecture seule) : {base_dir}/{}", derniere.id);
                            println!("  image  : {image}");
                            println!();
                            println!("  L'exercice restaure la sauvegarde dans un conteneur NEUF,");
                            println!("  vérifie que PostgreSQL l'ouvre, compte les tables, puis");
                            println!("  détruit tout. La production n'est jamais touchée.");
                            println!();
                            println!("  ⚠️  Il prouve que la BASE revient. Il ne prouve pas que");
                            println!("     l'application redémarre dessus.");
                            println!();
                            println!("  Relance avec --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        println!("Exercice en cours (restauration réelle)…");
                        let o = drill::run_postgres(&cible, base_dir, &derniere.id, image).await?;

                        state
                            .record_drill(
                                "postgres",
                                o.succeeded(),
                                o.tables,
                                o.seconds as i64,
                                &o.detail,
                            )
                            .await?;
                        state
                            .audit(
                                "cli", ACTEUR_ROLE, "dr-exercise", &derniere.id,
                                if o.succeeded() { "ok" } else { "failed" },
                                Some(&o.describe()),
                            )
                            .await?;

                        println!("{}", o.describe());
                        Ok(if o.succeeded() {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::FAILURE
                        })
                    }

                    DrCmd::Status => {
                        let bases = charger_bases(&state).await?;
                        let nodes = match &orch {
                            Some(o) => o.nodes().await.unwrap_or_default(),
                            None => Vec::new(),
                        };

                        println!("Capacité de reprise :");
                        println!(
                            "  sauvegardes de base : {}",
                            if bases.is_empty() {
                                "🔴 AUCUNE — rien ne pourrait être restauré".to_string()
                            } else {
                                format!("{} (la plus récente : {})",
                                    bases.len(),
                                    hlb_backup::pitr::iso8601(
                                        bases.iter().map(|b| b.finished_at).max().unwrap_or(0)))
                            }
                        );

                        let accueil: Vec<_> = nodes
                            .iter()
                            .filter(|n| n.memory_mb.is_some_and(|m| m >= dr::MIN_MEMORY_MB))
                            .collect();
                        println!("  nœuds d'accueil     : {}", accueil.len());
                        for n in &accueil {
                            let m = n.memory_mb.unwrap_or(0);
                            println!(
                                "    {:<16} {m} Mo → profil {}",
                                n.hostname,
                                dr::Profile::for_memory(m).describe()
                            );
                        }

                        if bases.is_empty() || accueil.is_empty() {
                            println!();
                            println!("🔴 La bascule ne fonctionnerait PAS aujourd'hui.");
                            if bases.is_empty() {
                                println!("   hlb backup pitr base --apply");
                            }
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                        }

                        println!();
                        let jours = state.days_since_successful_drill().await?;
                        let etat = hlb_backup::Readiness::from_days(jours);
                        println!("Exercice de reprise : {}", etat.describe());

                        let recents = state.recent_drills(3).await?;
                        if !recents.is_empty() {
                            for (quand, portee, statut, tables) in &recents {
                                println!(
                                    "  {quand}  {portee}  {}{}",
                                    if statut == "ok" { "✓" } else { "🔴 échec" },
                                    tables.map(|n| format!(" ({n} tables)")).unwrap_or_default()
                                );
                            }
                        }

                        if etat.needs_attention() {
                            println!();
                            println!("   hlb dr exercise --disposable --apply");
                            return Ok(ExitCode::FAILURE);
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    DrCmd::Promote { node, base_dir, wal_dir, force_split_brain, apply } => {
                        let Some(orch) = orch else {
                            eprintln!("🔴 Swarm injoignable : impossible de constater l'état réel.");
                            eprintln!("   On ne bascule pas à l'aveugle.");
                            return Ok(ExitCode::FAILURE);
                        };

                        let nodes = orch.nodes().await?;
                        let Some(cible) = nodes.iter().find(|n| &n.hostname == node) else {
                            eprintln!("Nœud « {node} » introuvable dans le cluster.");
                            return Ok(ExitCode::FAILURE);
                        };

                        // 🔴 L'état de l'ancien primaire est CONSTATÉ, jamais supposé.
                        // Un nœud « heavy » encore prêt veut dire que PostgreSQL peut
                        // encore y tourner, donc qu'une promotion créerait un
                        // split-brain.
                        let primaire = nodes
                            .iter()
                            .find(|n| n.tier.as_deref() == Some("heavy") && n.hostname != *node);
                        let primaire_vivant =
                            !force_split_brain && primaire.is_some_and(|n| n.is_ready());

                        let bases = charger_bases(&state).await?;
                        let couverture = hlb_backup::scan_archive(std::path::Path::new(wal_dir))
                            .ok()
                            .and_then(|s| hlb_backup::wal_coverage(&s));

                        // Une app est « lourde » si son manifest demande plusieurs
                        // réplicas : c'est le signal le plus fiable dont on dispose.
                        let mut apps = Vec::new();
                        for (nom, statut) in state.installed_apps().await? {
                            if statut == "failed" {
                                continue;
                            }
                            let lourde = state
                                .app_manifest(&nom)
                                .await
                                .map(|m| m.spec.swarm.replicas > 1)
                                .unwrap_or(false);
                            apps.push((nom, lourde));
                        }

                        let candidat = dr::Candidate {
                            node: node.clone(),
                            memory_mb: cible.memory_mb.unwrap_or(0),
                            reachable: cible.is_ready(),
                        };

                        let plan = match dr::plan_promotion(
                            &candidat,
                            primaire.map(|n| n.hostname.as_str()),
                            primaire_vivant,
                            &bases,
                            couverture,
                            &apps,
                        ) {
                            Ok(p) => p,
                            Err(e) => {
                                eprintln!("{}", e.describe());
                                return Ok(ExitCode::FAILURE);
                            }
                        };

                        println!("{}", plan.describe());
                        for t in plan.profile.tradeoffs() {
                            println!("  ⚠️  {t}");
                        }

                        if !apply {
                            println!();
                            println!("Réglages à poser sur {node} :");
                            for l in hlb_backup::dr::render_settings(plan.profile)?.lines() {
                                println!("    {l}");
                            }
                            println!();
                            println!("Marche à suivre après --apply :");
                            println!("  1. Restaurer {} depuis {base_dir}", plan.base_backup);
                            println!("  2. Poser les réglages ci-dessus");
                            println!("  3. Rejouer le WAL depuis {wal_dir} :");
                            println!("       hlb backup pitr plan \"{}\"",
                                     hlb_backup::pitr::iso8601(plan.recover_to));
                            println!("  4. Déplacer le tier : hlb node tier {node} --set heavy --apply");
                            println!();
                            println!("  🔴 Cette commande ne restaure RIEN toute seule. Une");
                            println!("     bascule automatique sur détection de panne est le");
                            println!("     meilleur moyen de perdre des données.");
                            println!();
                            println!("  Relance avec --apply pour poser le tier et journaliser.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        // `--apply` ne fait QUE ce qui est réversible : déplacer
                        // l'étiquette de placement. La restauration reste manuelle.
                        orch.label_node(&cible.id, "tier", "heavy").await?;
                        state
                            .audit("cli", ACTEUR_ROLE, "dr-promote", node, "ok",
                                   Some(&plan.describe()))
                            .await?;

                        println!("✓ tier=heavy posé sur {node} — Swarm peut y planifier PostgreSQL.");
                        println!();
                        println!("🔴 Les DONNÉES ne sont pas restaurées. Fais les étapes 1 à 3");
                        println!("   ci-dessus, sinon PostgreSQL démarrera sur une base VIDE.");
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::Pki(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                use hlb_agent::pki::{self, Purpose};
                const SECRET_CA: &str = "cluster-ca";

                let state = State::open(&cli.state).await?;
                let vault = Vault::open_or_init(&cli.master_key)?;

                let charger_ca = || async {
                    match state.secret(SECRET_CA).await? {
                        Some(ct) => {
                            let j: serde_json::Value =
                                serde_json::from_str(&vault.decrypt(&ct)?)?;
                            Ok::<_, Box<dyn std::error::Error>>(Some(pki::CertPair {
                                cert_pem: j["cert"].as_str().unwrap_or_default().to_string(),
                                key_pem: j["key"].as_str().unwrap_or_default().to_string(),
                            }))
                        }
                        None => Ok(None),
                    }
                };

                match cmd {
                    PkiCmd::Status => {
                        match charger_ca().await? {
                            Some(_) => {
                                println!("✓ Autorité du cluster présente au coffre.");
                                println!("  validité : {} jours", pki::CA_DAYS);
                                println!("  feuilles : {} jours", pki::LEAF_DAYS);
                                println!();
                                println!("⚠️  Il n'y a PAS de révocation (ni CRL, ni OCSP).");
                                println!("   Un certificat compromis reste valide jusqu'à son");
                                println!("   expiration : c'est pour ça qu'ils sont courts.");
                                println!("   Retirer un nœud se fait par `hlb access revoke`");
                                println!("   et en le sortant du Swarm.");
                            }
                            None => {
                                println!("Aucune autorité — les agents tournent donc en clair.");
                                println!("  hlb pki init --apply");
                                return Ok(ExitCode::FAILURE);
                            }
                        }
                        Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS)
                    }

                    PkiCmd::Init { apply } => {
                        if charger_ca().await?.is_some() {
                            println!("✓ L'autorité existe déjà.");
                            println!();
                            println!("  🔴 En créer une seconde invaliderait TOUS les");
                            println!("     certificats du parc d'un coup : les agents");
                            println!("     refuseraient le controller, et réciproquement.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        if !apply {
                            println!("Créerait l'autorité de certification du cluster.");
                            println!("  validité : {} jours (longue délibérément)", pki::CA_DAYS);
                            println!();
                            println!("  La remplacer impose de redéployer tous les certificats");
                            println!("  du parc le même jour — d'où une durée qui ne surprend");
                            println!("  personne un matin.");
                            println!();
                            println!("  🔴 Sa clé privée va au coffre. La perdre oblige à");
                            println!("     tout réémettre, nœud par nœud.");
                            println!("\n  Relance avec --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        let ca = pki::generate_ca("HomelabUS Cluster CA").await?;
                        let j = serde_json::json!({
                            "cert": ca.cert_pem, "key": ca.key_pem
                        });
                        state
                            .store_secret_if_absent(
                                SECRET_CA,
                                &vault.encrypt(&j.to_string())?,
                                "autorité de certification du cluster (mTLS)",
                            )
                            .await?;
                        state.audit("cli", ACTEUR_ROLE, "pki-init", "cluster-ca", "ok", None).await?;

                        println!("✓ Autorité créée, clé au coffre.");
                        println!();
                        println!("Ensuite, pour chaque nœud :");
                        println!("  hlb pki agent <nœud> --out /etc/hlb");
                        println!("  hlb pki controller --out /etc/hlb");
                        Ok(ExitCode::SUCCESS)
                    }

                    PkiCmd::Agent { node, out, service } => {
                        let Some(ca) = charger_ca().await? else {
                            eprintln!("Aucune autorité : hlb pki init --apply");
                            return Ok(ExitCode::FAILURE);
                        };

                        let noms = pki::agent_names(node, service);
                        let c = pki::issue(&ca, node, &noms, Purpose::Server).await?;

                        std::fs::create_dir_all(out)?;
                        ecrire_pem(&out.join(format!("{node}.crt")), &c.cert_pem)?;
                        ecrire_pem(&out.join(format!("{node}.key")), &c.key_pem)?;
                        ecrire_pem(&out.join("ca.crt"), &ca.cert_pem)?;

                        println!("✓ certificat émis pour {node} ({} jours)", pki::LEAF_DAYS);
                        println!("  noms : {}", noms.join(", "));
                        println!();
                        println!("  Sur le nœud :");
                        println!("    hlb-agent --cert {node}.crt --key {node}.key --ca ca.crt");
                        println!();
                        println!("  ⚠️  La clé privée est en 600. Elle ne doit pas voyager");
                        println!("     par un canal en clair.");
                        Ok(ExitCode::SUCCESS)
                    }

                    PkiCmd::Controller { out } => {
                        let Some(ca) = charger_ca().await? else {
                            eprintln!("Aucune autorité : hlb pki init --apply");
                            return Ok(ExitCode::FAILURE);
                        };

                        let c = pki::issue(&ca, "controller", &["controller".into()], Purpose::Client)
                            .await?;

                        std::fs::create_dir_all(out)?;
                        // reqwest attend certificat ET clé dans le même PEM.
                        ecrire_pem(
                            &out.join("controller.pem"),
                            &format!("{}{}", c.cert_pem, c.key_pem),
                        )?;
                        ecrire_pem(&out.join("ca.crt"), &ca.cert_pem)?;

                        println!("✓ certificat client émis ({} jours)", pki::LEAF_DAYS);
                        println!();
                        println!("  hlb-controller --controller-cert controller.pem \\");
                        println!("                 --controller-ca ca.crt");
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::Access(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                use hlb_bootstrap::access;
                let state = State::open(&cli.state).await?;
                let vault = Vault::open_or_init(&cli.master_key)?;

                let (host, user, port, identity) = match cmd {
                    AccessCmd::Grant { host, user, port, identity, .. }
                    | AccessCmd::Revoke { host, user, port, identity, .. }
                    | AccessCmd::List { host, user, port, identity } => {
                        (host, user.as_deref(), *port, identity.as_deref())
                    }
                };

                let ssh = ssh_runner(host, user, port, identity);
                let avant = access::read_authorized_keys(&ssh, "~").await?;

                match cmd {
                    AccessCmd::List { .. } => {
                        let gerees = access::list_managed(&avant);
                        let total = avant.lines().filter(|l| {
                            let l = l.trim();
                            !l.is_empty() && !l.starts_with('#')
                        }).count();

                        println!("{host} — {total} clé(s) dans authorized_keys");
                        if gerees.is_empty() {
                            println!("  aucune gérée par HomelabUS");
                        } else {
                            for c in &gerees {
                                println!("  gérée par HomelabUS (cluster « {c} »)");
                            }
                        }
                        println!("  {} clé(s) humaine(s), auxquelles on ne touche jamais",
                                 total - gerees.len());
                        Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS)
                    }

                    AccessCmd::Grant { apply, .. } => {
                        let kp = cluster_ssh_key(&state, &vault).await?;
                        let cle = access::ManagedKey::new(&kp.public, "hlb");
                        let (apres, ch) = access::grant(&avant, &cle);

                        if ch.is_noop() {
                            println!("✓ déjà en place — rien à faire.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        if !*apply {
                            println!("Poserait la clé de HomelabUS sur {host}.");
                            println!("  {} ajoutée, {} remplacée(s)", ch.added, ch.removed);
                            println!("  {} clé(s) existante(s) PRÉSERVÉE(s)", ch.kept);
                            println!("\n  Relance avec --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        access::write_authorized_keys(&ssh, "~", &apres, &avant).await?;
                        state.audit("cli", ACTEUR_ROLE, "access-grant", host, "ok", None).await?;
                        println!("✓ clé posée ({} conservée(s))", ch.kept);
                        Ok(ExitCode::SUCCESS)
                    }

                    AccessCmd::Revoke { apply, .. } => {
                        let kp = cluster_ssh_key(&state, &vault).await?;
                        let cle = access::ManagedKey::new(&kp.public, "hlb");
                        let (apres, ch) = access::revoke(&avant, &cle);

                        if ch.is_noop() {
                            println!("✓ aucune clé HomelabUS sur {host} — rien à retirer.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        if !*apply {
                            println!("Retirerait la clé de HomelabUS de {host}.");
                            println!("  {} clé(s) humaine(s) PRÉSERVÉE(s)", ch.kept);
                            println!();
                            println!("  🔴 Après ça, HomelabUS ne pourra plus piloter cette");
                            println!("     machine : ni mise à jour, ni sauvegarde, ni");
                            println!("     réconciliation. Le nœud continuera de tourner.");
                            println!("\n  Relance avec --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        access::write_authorized_keys(&ssh, "~", &apres, &avant).await?;
                        state.audit("cli", ACTEUR_ROLE, "access-revoke", host, "ok", None).await?;
                        println!("✓ clé retirée ({} clé(s) humaine(s) intacte(s))", ch.kept);
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
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

        Command::SecretSet { name, purpose, rotate } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = State::open(&cli.state).await?;
                let vault = Vault::open_or_init(&cli.master_key)?;

                let existe = state.secret(name).await?.is_some();
                if existe && !rotate {
                    eprintln!("Le secret « {name} » existe déjà.");
                    eprintln!();
                    eprintln!("🔴 L'écraser peut casser ce qui l'utilise : un mot de passe");
                    eprintln!("   changé au coffre ne l'est pas dans le service qui tourne.");
                    eprintln!("   Si c'est voulu : --rotate");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                }

                println!("Valeur de « {name} » (entrée standard, Ctrl-D pour finir) :");
                let mut valeur = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut valeur)?;
                let valeur = valeur.trim();

                if valeur.is_empty() {
                    eprintln!("Valeur vide — rien n'a été enregistré.");
                    return Ok(ExitCode::FAILURE);
                }

                let ct = vault.encrypt(valeur)?;
                if existe {
                    state.rotate_secret(name, &ct).await?;
                    println!("✓ « {name} » remplacé.");
                } else {
                    state.store_secret_if_absent(name, &ct, purpose).await?;
                    println!("✓ « {name} » enregistré.");
                }

                // Le nom et l'usage à l'audit, jamais la valeur.
                state
                    .audit("cli", ACTEUR_ROLE, "secret-set", name, "ok", Some(purpose))
                    .await?;
                Ok(ExitCode::SUCCESS)
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

                // `Scan` ne dépend d'aucun candidat : on le traite avant d'interroger
                // les registres, qui prend du temps et de la bande passante.
                if let UpdateCmd::Scan { image, identity, issuer } = cmd {
                    println!("Analyse de {image}…\n");
                    let r = hlb_updater::audit(image, identity.as_deref(), issuer.as_deref())
                        .await?;
                    println!("{}", r.describe());

                    if r.unchecked() > 0 {
                        println!();
                        println!("⚠️  {} contrôle(s) NON effectué(s).", r.unchecked());
                        println!("   Installe trivy et cosign pour qu'ils comptent :");
                        println!("     brew install trivy cosign   # ou le paquet de ta distro");
                    }
                    return Ok::<_, Box<dyn std::error::Error>>(if r.blocks() {
                        ExitCode::FAILURE
                    } else {
                        ExitCode::SUCCESS
                    });
                }

                let candidates = hlb_updater::check(&state, &registry, &now).await?;

                match cmd {
                    // Traité au-dessus.
                    UpdateCmd::Scan { .. } => unreachable!(),
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

                    UpdateCmd::Apply { app, force_window, force_vulnerable } => {
                        let Some(c) = candidates.iter().find(|c| &c.app == app) else {
                            println!("Rien à mettre à jour pour « {app} ».");
                            return Ok(ExitCode::SUCCESS);
                        };

                        // 🔴 On analyse AVANT de déployer, pas après. Une image
                        // critique déployée puis signalée a déjà tourné.
                        let cible = match &c.kind {
                            hlb_updater::UpdateKind::NewVersion { to_tag } => {
                                let m = state.app_manifest(app).await?;
                                format!("{}:{to_tag}", m.spec.image.repo)
                            }
                            _ => state.app_manifest(app).await?.spec.image.reference(),
                        };

                        let rapport = hlb_updater::audit(
                            &cible,
                            std::env::var("HLB_COSIGN_IDENTITY").ok().as_deref(),
                            std::env::var("HLB_COSIGN_ISSUER").ok().as_deref(),
                        )
                        .await?;

                        println!("{}\n", rapport.describe());

                        if rapport.blocks() && !force_vulnerable {
                            eprintln!("🔴 Mise à jour REFUSÉE.");
                            eprintln!();
                            eprintln!("   Passer outre est parfois légitime — un correctif");
                            eprintln!("   urgent dans une image qui traîne d'autres CVE.");
                            eprintln!("   Mais ça doit être une décision, pas un défaut :");
                            eprintln!("     hlb update apply {app} --force-vulnerable");
                            state
                                .audit("cli", ACTEUR_ROLE, "update-refused", app, "refused",
                                       Some(&rapport.describe()))
                                .await?;
                            return Ok(ExitCode::FAILURE);
                        }
                        if rapport.blocks() {
                            eprintln!("⚠️  Vulnérabilités critiques ignorées sur demande.");
                            state
                                .audit("cli", ACTEUR_ROLE, "update-forced", app, "ok",
                                       Some(&rapport.describe()))
                                .await?;
                        }

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

                            // 🔴 La couverture d'abord : c'est elle qui décide de la
                            // ligne de résumé. Juger sur l'âge AGRÉGÉ afficherait
                            // « ✓ à jour » pour une app dont le hors-site est mort
                            // depuis trois semaines — le résumé contredirait le détail
                            // juste en dessous, et c'est le résumé qu'on lit.
                            let couverture =
                                couverture_de(&state, app, sched.overdue_after().as_secs() as i64)
                                    .await?;

                            // Un échec répété rend le résumé alarmant, même si la
                            // dernière réussite est récente.
                            let mut echecs_totaux = 0;
                            for (nom, _) in &couverture.par_destination {
                                echecs_totaux += state.consecutive_failures_on(app, nom).await?;
                            }

                            let etat = if echecs_totaux > 0 {
                                "🔴 des tentatives échouent"
                            } else {
                                match couverture.pire() {
                                Some(hlb_backup::EtatDestination::Jamais) => {
                                    "🔴 une destination JAMAIS servie"
                                }
                                Some(hlb_backup::EtatDestination::Perime { .. }) => {
                                    "🔴 une destination en retard"
                                }
                                // Aucune destination routée : on retombe sur le
                                // jugement global, qui reste juste dans ce cas.
                                None | Some(hlb_backup::EtatDestination::Frais { .. }) => {
                                    if sched.is_overdue(age) {
                                        "🔴 en retard"
                                    } else if sched.is_due(age) {
                                        "🟠 due"
                                    } else {
                                        "✓ à jour"
                                    }
                                }
                                }
                            };
                            println!(
                                "{app:<14} {:<18} {:<18} {etat}",
                                age.map(fmt_age).unwrap_or_else(|| "jamais".into()),
                                verif.map(|s| fmt_age(std::time::Duration::from_secs(s as u64)))
                                    .unwrap_or_else(|| "jamais".into()),
                            );

                            // Le détail par destination, sous le résumé.
                            if !couverture.par_destination.is_empty() {
                                for (nom, e) in &couverture.par_destination {
                                    let (marque, quand) = match e {
                                        hlb_backup::EtatDestination::Frais { age_s } => (
                                            "✓",
                                            fmt_age(std::time::Duration::from_secs(*age_s as u64)),
                                        ),
                                        hlb_backup::EtatDestination::Perime { age_s } => (
                                            "🔴",
                                            fmt_age(std::time::Duration::from_secs(*age_s as u64)),
                                        ),
                                        // 🔴 Distinct d'un retard : cette destination
                                        // n'a JAMAIS rien reçu, donc n'a jamais rien
                                        // protégé. La cause est ailleurs — routage
                                        // jamais branché, identifiants absents.
                                        hlb_backup::EtatDestination::Jamais => {
                                            ("🔴", "JAMAIS reçu".to_string())
                                        }
                                    };
                                    // 🔴 Un échec RÉPÉTÉ se voit tout de suite, sans
                                    // attendre le seuil de péremption. Sinon une
                                    // destination qui échoue à chaque tentative
                                    // resterait affichée « ✓ » pendant douze heures.
                                    let echecs =
                                        state.consecutive_failures_on(app, nom).await?;
                                    let suffixe = if echecs > 0 {
                                        format!("  🔴 {echecs} échec(s) depuis")
                                    } else {
                                        String::new()
                                    };
                                    println!("               └ {marque} {nom:<10} {quand}{suffixe}");
                                }

                                let a_jour = couverture.copies_a_jour();
                                if a_jour < 2 {
                                    // 🔴 Le nombre de destinations CONFIGURÉES ne dit
                                    // rien du nombre de copies. Deux destinations dont
                                    // une en échec, ce n'est pas du 3-2-1.
                                    println!(
                                        "               ⚠️ {a_jour} copie(s) réellement à jour sur {}",
                                        couverture.par_destination.len()
                                    );
                                }
                            }
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    BackupCmd::Run { force } => {
                        use hlb_updater::BackupProvider;

                        let mut faites = 0;
                        for (app, statut) in state.installed_apps().await? {
                            if statut == "failed" {
                                continue;
                            }

                            // Les volumes applicatifs : la classe VOLUMINEUSE.
                            let dests = destinations_effectives(
                                &state,
                                &app,
                                hlb_backup::Classe::Volumineux,
                                cli.backup_repo.as_deref(),
                            )
                            .await?;

                            for d in &dests {
                                // 🔴 L'échéance se juge PAR DESTINATION. La juger
                                // globalement ferait sauter le hors-site dès que le NAS
                                // vient d'être servi — et il ne recevrait jamais rien,
                                // pendant que le statut global paraîtrait frais.
                                let age = state
                                    .seconds_since_last_success_on(&app, &d.nom)
                                    .await?
                                    .map(|s| std::time::Duration::from_secs(s as u64));
                                if !force && !sched.is_due(age) {
                                    continue;
                                }

                                print!("{app} → {}… ", d.nom);
                                use std::io::Write as _;
                                let _ = std::io::stdout().flush();

                                // 🔴 Un échec sur UNE destination ne doit pas priver les
                                // autres. Un hors-site injoignable qui interromprait la
                                // boucle supprimerait aussi la sauvegarde locale — on
                                // perdrait les deux copies pour la panne d'une seule.
                                let provider =
                                    match provider_pour(d, &cli.platform_network, &state, &vault)
                                        .await
                                    {
                                        Ok(p) => p,
                                        Err(e) => {
                                            state
                                                .record_backup_to(
                                                    &app, "volume", &d.nom, None,
                                                    Some(&e.to_string()),
                                                )
                                                .await?;
                                            println!("✗ {e}");
                                            continue;
                                        }
                                    };

                                match provider.snapshot(&app).await {
                                    Ok(id) => {
                                        state
                                            .record_backup_to(
                                                &app, "volume", &d.nom, Some(&id), None,
                                            )
                                            .await?;
                                        println!("✓ {}", &id[..8.min(id.len())]);
                                        faites += 1;
                                    }
                                    Err(e) => {
                                        // Enregistré comme échec : l'échéance n'est PAS
                                        // repoussée, la sauvegarde reste due (§8.1).
                                        state
                                            .record_backup_to(
                                                &app, "volume", &d.nom, None, Some(&e),
                                            )
                                            .await?;
                                        println!("✗ {e}");
                                    }
                                }
                            }

                            if dests.is_empty() {
                                println!("{app} : aucune destination pour les volumes.");
                            }
                        }
                        // 🔴 Les bases SQLite d'abord : un volume SQLite copié à
                        // chaud donne une base restaurée CORROMPUE, sans que rien ne
                        // le signale au moment de la sauvegarde (§3.4).
                        for (app, volume, montage) in state.sqlite_volumes().await? {
                            print!("{app}/{volume} (instantané SQLite)… ");
                            use std::io::Write as _;
                            let _ = std::io::stdout().flush();

                            match snapshot_sqlite_volume(
                                &state, &vault, cli.backup_repo.as_deref(),
                                &cli.platform_network, &app, &montage,
                            )
                            .await
                            {
                                Ok(n) => {
                                    println!("✓ {n} base(s)");
                                    faites += 1;
                                }
                                Err(e) => println!("✗ {e}"),
                            }
                        }

                        // 🔴 Les bases de données ensuite. Un volume PostgreSQL copié
                        // pendant une écriture ne restaure PAS : pages, WAL et fichiers
                        // de contrôle sont capturés à des instants différents. Seul un
                        // dump logique est transactionnellement cohérent (§8.1).
                        let bases = state.app_databases().await?;

                        // 🔴 Chaque moteur a son dumper et son URL d'administration.
                        // Les traiter en bloc ferait passer les bases MariaDB pour
                        // sauvegardées dès lors qu'un PostgreSQL est joignable.
                        let (pg, autres): (Vec<_>, Vec<_>) =
                            bases.iter().cloned().partition(|(_, m, _, _)| m == "postgres");
                        let (maria, inconnues): (Vec<_>, Vec<_>) =
                            autres.into_iter().partition(|(_, m, _, _)| m == "mariadb");

                        if !pg.is_empty() {
                            match cli.postgres_admin.as_deref() {
                                None => {
                                    eprintln!();
                                    eprintln!(
                                        "🔴 {} base(s) PostgreSQL NON sauvegardée(s) : --postgres-admin absent.",
                                        pg.len()
                                    );
                                    eprintln!("   Leurs volumes le sont, mais un volume PostgreSQL");
                                    eprintln!("   copié à chaud ne restaure pas.");
                                }
                                Some(url) => {
                                    faites += dump_databases(
                                        &state, &vault, url, cli.backup_repo.as_deref(),
                                        &cli.platform_network, &pg,
                                    )
                                    .await?;
                                }
                            }
                        }

                        if !maria.is_empty() {
                            match cli.mariadb_admin.as_deref() {
                                None => {
                                    eprintln!();
                                    eprintln!(
                                        "🔴 {} base(s) MariaDB NON sauvegardée(s) : --mariadb-admin absent.",
                                        maria.len()
                                    );
                                    eprintln!("   Le volume seul ne restaure pas davantage qu'en");
                                    eprintln!("   PostgreSQL : InnoDB copié à chaud est incohérent.");
                                }
                                Some(url) => {
                                    faites += dump_mariadb_databases(
                                        &state, &vault, url, cli.backup_repo.as_deref(),
                                        &cli.platform_network, &maria,
                                    )
                                    .await?;
                                }
                            }
                        }

                        // Un moteur qu'on ne sait pas dumper se DIT, il ne se tait pas.
                        for (app, moteur, _, _) in &inconnues {
                            eprintln!(
                                "⚠️  {app} : moteur « {moteur} » — aucun dumper, base NON sauvegardée"
                            );
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

                    BackupCmd::Dest(sous) => match sous {
                        DestCmd::Add { name, location, classes, access_key } => {
                            use hlb_backup::Classe;

                            // Une classe mal orthographiée est refusée : l'accepter
                            // silencieusement produirait une destination qui n'accepte
                            // rien, et qu'on croirait configurée.
                            let mut retenues = Vec::new();
                            for c in classes {
                                match Classe::parse(c) {
                                    Some(k) => retenues.push(k.nom().to_string()),
                                    None => {
                                        eprintln!("classe inconnue « {c} » — attendu : critique, volumineux");
                                        return Ok(ExitCode::FAILURE);
                                    }
                                }
                            }

                            let secret = match access_key {
                                Some(cle) => {
                                    // 🔴 La clé secrète est lue sur l'ENTRÉE STANDARD.
                                    // En argument, elle serait lisible par `ps` pour
                                    // tout utilisateur de la machine, puis conservée
                                    // dans l'historique du shell.
                                    eprintln!("Clé secrète S3 (entrée standard, non affichée) :");
                                    let mut buf = String::new();
                                    std::io::stdin().read_line(&mut buf)?;
                                    let secrete = buf.trim();
                                    if secrete.is_empty() {
                                        eprintln!("🔴 clé secrète vide — rien n'a été enregistré.");
                                        return Ok(ExitCode::FAILURE);
                                    }

                                    let nom_secret = format!("backup-dest-{name}");
                                    let ct = vault.encrypt(&format!("{cle}:{secrete}"))?;
                                    if !state
                                        .store_secret_if_absent(&nom_secret, &ct, "identifiants S3 de sauvegarde")
                                        .await?
                                    {
                                        state.rotate_secret(&nom_secret, &ct).await?;
                                    }
                                    Some(nom_secret)
                                }
                                None => None,
                            };

                            state
                                .upsert_destination(name, location, &retenues.join(","), secret.as_deref())
                                .await?;

                            println!("✓ destination « {name} » enregistrée.");

                            // ⚠️ Une destination S3 sans identifiants échouera à la
                            // première sauvegarde, sur une erreur d'autorisation qui
                            // ne dit pas que le secret n'a jamais été déposé.
                            if location.trim_start().starts_with("s3:") && secret.is_none() {
                                println!();
                                println!("⚠️ Dépôt S3 sans identifiants : les sauvegardes échoueront.");
                                println!("   Relance avec --access-key <clé>.");
                            }
                            Ok(ExitCode::SUCCESS)
                        }

                        DestCmd::List => {
                            let destinations = charger_destinations(&state).await?;
                            if destinations.is_empty() {
                                println!("Aucune destination déclarée.");
                                println!();
                                println!("⚠️ Sans destination, `hlb backup run` n'a nulle part où écrire.");
                                println!("   hlb backup dest add nas --location /mnt/nas/restic \\");
                                println!("     --classes critique,volumineux");
                                return Ok(ExitCode::SUCCESS);
                            }
                            for d in &destinations {
                                println!("  {}", d.describe());
                            }
                            Ok(ExitCode::SUCCESS)
                        }

                        DestCmd::Remove { name } => {
                            state.remove_destination(name).await?;
                            println!("✓ destination « {name} » retirée du routage.");
                            // 🔴 On ne supprime RIEN à distance : les instantanés
                            // restent là-bas. Les effacer d'un `dest remove` serait une
                            // destruction de sauvegardes sur un geste de configuration.
                            println!("⚠️ Les instantanés déjà envoyés n'ont pas été touchés.");
                            Ok(ExitCode::SUCCESS)
                        }
                    },

                    BackupCmd::Route { app, critique, volumineux } => {
                        let connues: Vec<String> = state
                            .destinations()
                            .await?
                            .into_iter()
                            .map(|(n, _, _, _)| n)
                            .collect();

                        for (classe, choix) in
                            [("critique", critique), ("volumineux", volumineux)]
                        {
                            let Some(dests) = choix else { continue };

                            // Router vers une destination inexistante ne produirait
                            // aucune erreur au moment de la sauvegarde : elle serait
                            // simplement ignorée, et l'app paraîtrait couverte.
                            for d in dests {
                                if !connues.contains(d) {
                                    eprintln!("🔴 destination « {d} » inconnue — rien n'a été routé.");
                                    eprintln!("   hlb backup dest list");
                                    return Ok(ExitCode::FAILURE);
                                }
                            }
                            state.set_route(app, classe, dests).await?;
                            println!("✓ {app} / {classe} → {}", dests.join(", "));
                        }

                        println!();
                        for classe in ["critique", "volumineux"] {
                            let r = state.route(app, classe).await?;
                            if r.is_empty() {
                                println!("  {classe:<11} : (défaut des destinations)");
                            } else {
                                println!("  {classe:<11} : {}", r.join(", "));
                            }
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    BackupCmd::Pitr(sous) => {
                        pitr(sous, &cli.state, cli.postgres_admin.as_deref(), &cli.platform_network).await
                    }
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

                if let NodeCmd::Add {
                    host, user, port, identity, role, advertise_addr, apply,
                } = cmd
                {
                    return node_add(
                        &cli, host, user.as_deref(), *port, identity.as_deref(),
                        role.as_deref(), advertise_addr.as_deref(), *apply,
                    )
                    .await;
                }

                let (runner, apply) = match cmd {
                    NodeCmd::Check { host, user, port, identity } => {
                        (build_runner(host.as_deref(), user.as_deref(), *port, identity.as_deref()), false)
                    }
                    NodeCmd::Deps { host, user, apply } => {
                        (build_runner(host.as_deref(), user.as_deref(), None, None), *apply)
                    }
                    // Traités au-dessus.
                    NodeCmd::Tier { .. } | NodeCmd::Add { .. } => unreachable!(),
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
