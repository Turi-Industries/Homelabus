//! `hlb` — the first-class interface.
//!
//! The principle: **the CLI does everything, the UI is only a client of the API.** That
//! guarantees scriptability, and debugging when the UI is broken.

use std::path::PathBuf;

mod catalog_index;
mod devices;
mod disk;
mod domain;
mod emergency;
mod exposure;
mod mail;
mod relay;
mod restore;
mod roles;
mod seal;
mod sources;
mod storage;
mod termix;
mod verify_boot;

/// The catalog's YAML, carried in the binary by `build.rs`.
mod carried_catalog {
    include!(concat!(env!("OUT_DIR"), "/catalog.rs"));
}
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use hlb_catalog::Catalog;
use hlb_engine::{Executor, Reconciler};
use hlb_orchestrator::{Orchestrator, SwarmOrchestrator};
use hlb_resolver::{DependencyGraph, InstallParams};
use hlb_secrets::Vault;
use hlb_state::State;

#[derive(Parser)]
#[command(name = "hlb", version, about = "Managing a homelab on Docker Swarm")]
struct Cli {
    /// Root of the application catalog.
    #[arg(long, global = true, default_value = "catalog", env = "HLB_CATALOG")]
    catalog: PathBuf,

    /// The controller's local state database.
    #[arg(long, global = true, default_value = "hlb.db", env = "HLB_STATE")]
    state: PathBuf,

    /// The age master key. Created if needed; losing it makes everything unrecoverable.
    #[arg(
        long,
        global = true,
        default_value = "hlb-master.key",
        env = "HLB_MASTER_KEY"
    )]
    master_key: PathBuf,

    /// PostgreSQL admin URL. Without it, provisioning is skipped.
    #[arg(long, global = true, env = "HLB_POSTGRES_ADMIN")]
    postgres_admin: Option<String>,

    /// MariaDB admin URL, same principle.
    #[arg(long, global = true, env = "HLB_MARIADB_ADMIN")]
    mariadb_admin: Option<String>,

    /// The restic repository. Without it, any update requiring a backup is refused.
    #[arg(long, global = true, env = "HLB_BACKUP_REPO")]
    backup_repo: Option<String>,

    /// PocketID URL. Without it, OIDC clients are not provisioned.
    #[arg(long, global = true, env = "HLB_POCKETID_URL")]
    pocketid_url: Option<String>,

    /// PocketID API key.
    #[arg(long, global = true, env = "HLB_POCKETID_KEY")]
    pocketid_key: Option<String>,

    /// Git mirror of the desired state. Absent: no history.
    #[arg(long, global = true, env = "HLB_GIT_MIRROR")]
    git_mirror: Option<PathBuf>,

    /// Docker network where platform services are reachable by name.
    ///
    /// ⚠️ The client tools (pg_dump, pg_basebackup) run in disposable containers:
    /// without this network they cannot resolve "postgres" and fail on a DNS error that
    /// does not say the network is the problem.
    #[arg(
        long,
        global = true,
        default_value = hlb_orchestrator::PLATFORM_NETWORK,
        env = "HLB_PLATFORM_NETWORK"
    )]
    platform_network: String,

    /// Root under which `tier: local` volumes are bound, e.g. `/tank/apps`.
    ///
    /// Absent: Docker's own directory, which is right on a node with no pool. Set it on
    /// a node that HAS one, and the app data lands on the pool — where ZFS snapshots
    /// reach it.
    #[arg(long, global = true, env = "HLB_STORAGE_ROOT")]
    storage_root: Option<String>,

    /// NFS server for the `tier: nfs` volumes, as the nodes reach it.
    ///
    /// 🔴 Without it, installing an app that declares `tier: nfs` is REFUSED. Falling
    /// back to a local volume would take the uploads and lose them on the next
    /// redeployment, with nothing to say so.
    #[arg(long, global = true, env = "HLB_NFS_SERVER")]
    nfs_server: Option<String>,

    /// The exported root on that server, e.g. `/tank/media`.
    #[arg(long, global = true, env = "HLB_NFS_EXPORT")]
    nfs_export: Option<String>,

    /// Stalwart URL. Without it, mailboxes are not provisioned.
    #[arg(long, global = true, env = "HLB_STALWART_URL")]
    stalwart_url: Option<String>,

    /// Stalwart administration account.
    #[arg(long, global = true, env = "HLB_STALWART_ADMIN")]
    stalwart_admin: Option<String>,

    /// Password for that account. ⚠️ Prefer the environment variable: a password on
    /// the command line is readable by every user of the machine.
    #[arg(long, global = true, env = "HLB_STALWART_PASSWORD")]
    stalwart_password: Option<String>,

    /// Garage admin API, e.g. http://garage:3903. ⚠️ NOT the S3 port (3900).
    #[arg(long, global = true, env = "HLB_GARAGE_URL")]
    garage_url: Option<String>,

    /// Garage admin token. ⚠️ Prefer the environment variable.
    #[arg(long, global = true, env = "HLB_GARAGE_TOKEN")]
    garage_token: Option<String>,

    #[command(subcommand)]
    command: Command,

    /// May `--state`, and `--master-key`, be created where they point? Each decided
    /// after parsing, in `run`, on its own path: see `open_vault`.
    #[arg(skip)]
    may_create_state: bool,
    #[arg(skip)]
    may_create_key: bool,

    /// Did the state exist before this command ran? Read once, in `run`: the command
    /// may create it itself before it opens the vault.
    #[arg(skip)]
    state_existed: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Browse and validate the catalog.
    #[command(subcommand)]
    Catalog(CatalogCmd),

    /// Show an app's install plan, changing nothing.
    Plan {
        app: String,
        /// Full domain, e.g. git.example.org
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        mail_domain: Option<String>,
    },

    /// Deployment order derived from the declared dependencies.
    Order,

    /// Install an app. Preview by default: nothing changes without --apply.
    Install {
        app: String,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        mail_domain: Option<String>,
        /// Actually apply the plan.
        #[arg(long)]
        apply: bool,
    },

    /// Bring installed apps to the catalog's manifests. Preview by default.
    ///
    /// Without an app: which installed apps the catalog has changed. The images are
    /// left to `hlb update`, which backs up first.
    Upgrade {
        app: Option<String>,
        #[arg(long)]
        mail_domain: Option<String>,
        /// Actually apply the change.
        #[arg(long)]
        apply: bool,
    },

    /// The installed apps' scheduled jobs (`jobs:` in a manifest) and their last run;
    /// with an app and a job, run that one now. Preview by default.
    ///
    /// The controller runs each when it is due — a day or a week after its last run.
    Job {
        app: Option<String>,
        id: Option<String>,
        #[arg(long)]
        apply: bool,
    },

    /// Deploy an installed app again, from the manifest it was installed with.
    /// Preview by default.
    ///
    /// For what a deployment computes rather than the manifest declares — the root it
    /// trusts, a secret's value, a file's tokens: an unchanged manifest gives `hlb
    /// upgrade` nothing to apply, and rerunning `hlb install` skips what is done.
    Redeploy {
        app: String,
        #[arg(long)]
        apply: bool,
    },

    /// Change an app's replica count.
    ///
    /// 🔴 Zero is refused: that is a shutdown, not a resize, and it almost never
    /// happens on purpose from a number field.
    Scale {
        app: String,
        replicas: u64,
        #[arg(long)]
        apply: bool,
    },

    /// Stop an app without removing it: 0 replicas, everything else kept.
    ///
    /// Distinct from `remove`: the service, its volumes and its routing stay. `hlb
    /// scale <app> 1` brings it back.
    Stop {
        app: String,
        #[arg(long)]
        apply: bool,
    },

    /// Remove an app: stops its service, KEEPS its volumes and its backups.
    ///
    /// 🔴 The name must be repeated with --confirm. That is what stops a purge typed
    /// on the wrong app — the one mistake nothing else here can catch.
    Remove {
        app: String,
        /// Repeat the app's name. Required by --apply.
        #[arg(long)]
        confirm: Option<String>,
        /// Actually remove it.
        #[arg(long, requires = "confirm")]
        apply: bool,
    },

    /// Compare the desired state to the real one, and correct if asked.
    Reconcile {
        /// Correct the gaps. Without this flag, detection only.
        #[arg(long)]
        apply: bool,
    },

    /// The Caddyfile the installed apps make, and publishing it on the ingress.
    ///
    /// Every install and upgrade publishes on its own: this is for looking, and for
    /// republishing after `hlb config exposure` or a credential changed.
    Ingress {
        /// Hand it to the `caddy` service instead of displaying it.
        #[arg(long)]
        apply: bool,
    },

    /// Available updates and applying them.
    #[command(subcommand)]
    Update(UpdateCmd),

    /// Backups: status, execution and verification.
    #[command(subcommand)]
    Backup(BackupCmd),

    /// Cluster: initialisation, status and quorum.
    #[command(subcommand)]
    Cluster(ClusterCmd),

    /// Nodes: prechecks and dependencies.
    #[command(subcommand)]
    Node(NodeCmd),

    /// Status of the services Homelabus manages.
    Ps,

    /// Pending manual actions, across every app.
    Todo {
        /// Run the declared checks and mark what is observed to be done.
        #[arg(long)]
        verify: bool,
    },

    /// What the house's mail needs outside it: its DNS records, read as the internet
    /// resolves them.
    #[command(subcommand)]
    Mail(MailCmd),

    /// The house's domain, watched for the theft no machine sees: name servers moved
    /// by a registrar's support, a lock lifted, a transfer begun.
    #[command(subcommand)]
    Domain(DomainCmd),

    /// Read the manifests' assertions from the running apps now — what each must keep
    /// true, by its effect — and record them for the inbox.
    Assert {
        /// One app; every installed app by default.
        app: Option<String>,
    },

    /// Declare a manual step handled. ⚠️ An attestation, not a verification.
    Ack {
        /// Format: <app>/<id>, as shown by `hlb todo`.
        target: String,
        /// Attest despite a check that says otherwise.
        #[arg(long)]
        force: bool,
    },

    /// Access tokens for the API and the UI.
    #[command(subcommand)]
    Token(TokenCmd),

    /// ZFS/btrfs snapshots: rollback in minutes.
    #[command(subcommand)]
    Snapshot(SnapshotCmd),

    /// Updating Homelabus itself.
    #[command(subcommand)]
    #[command(name = "self")]
    Selfy(SelfCmd),

    /// PostgreSQL replication: streaming standby.
    #[command(subcommand)]
    Replication(ReplCmd),

    /// Observability: collection, alert rules, deadman switch.
    #[command(subcommand)]
    Metrics(MetricsCmd),

    /// Human accounts: identity, mailboxes and aliases.
    #[command(subcommand)]
    User(UserCmd),
    /// Roles, and the apps each one enters.
    #[command(subcommand)]
    Role(RoleCmd),

    /// 🔴 Disaster recovery: move PostgreSQL to another node.
    #[command(subcommand)]
    Dr(DrCmd),

    /// 🔴 The way back in when PocketID signs nobody in: the emergency vault, and the
    /// printed kit that restores the vault itself.
    #[command(subcommand)]
    Emergency(EmergencyCmd),

    /// Termix, given the cluster's nodes: an account on each, never root, reached by a
    /// key Homelabus generates; a host per node in Termix, shared with its admins.
    #[command(subcommand)]
    Termix(TermixCmd),

    /// mTLS certificates, agent ↔ controller.
    #[command(subcommand)]
    Pki(PkiCmd),

    /// Homelabus's own services on the cluster: the agent on every node, the
    /// controller on this one.
    #[command(subcommand)]
    Fleet(FleetCmd),

    /// Managed SSH access: install, revoke, inventory.
    #[command(subcommand)]
    Access(AccessCmd),

    /// WireGuard mesh between nodes.
    #[command(subcommand)]
    Mesh(MeshCmd),

    /// CrowdSec bouncer: enrolment and status.
    #[command(subcommand)]
    Crowdsec(CrowdsecCmd),

    /// Inventory of the secrets: names and purposes, never the values.
    /// The installation's own configuration: brand, footer, default theme.
    #[command(subcommand)]
    Config(ConfigCmd),

    /// Announcements and incidents shown on the portal and the status page.
    #[command(subcommand)]
    Announcement(AnnouncementCmd),

    /// Alert mutes: silence a rule's notification for a while, never its display.
    #[command(subcommand)]
    Alert(AlertCmd),

    /// Storage: ZFS pools, datasets and NFS exports.
    #[command(subcommand)]
    Storage(StorageCmd),

    /// Garage object storage: cluster status and data layout.
    ///
    /// 🔴 Multi-node goes through the LAYOUT, not through Swarm replicas: see
    /// `hlb_objstore`'s module documentation for why.
    #[command(subcommand)]
    Garage(GarageCmd),

    /// The portal's OIDC client, which every app behind the portal signs in through.
    #[command(subcommand)]
    Portal(PortalCmd),

    Secrets,

    /// 🔴 Re-encrypt every secret under a NEW master key.
    ///
    /// An ORDERED PROCEDURE, not a file write. Half a vault under the new key and half
    /// under the old is unrecoverable by hand: nothing in a ciphertext says which key
    /// opens it. Preview by default.
    SecretsRekey {
        /// Where to write the new key. Must not exist.
        #[arg(long)]
        new_key: std::path::PathBuf,
        /// The controller is stopped, wherever it runs. It holds the old key in memory:
        /// a secret it stores after the rewrite would be one the new key cannot open.
        /// A Swarm service still running is refused whatever this says.
        #[arg(long)]
        controller_stopped: bool,
        /// Actually re-encrypt.
        #[arg(long, requires = "controller_stopped")]
        apply: bool,
    },

    /// Seal the vault's master key to this machine: encrypted by systemd-creds with its
    /// TPM and host key, unsealed into memory at each boot by `hlb-vault.service`, its
    /// path left as a link there. Refused until the emergency kit is printed with
    /// today's material — sealed, the key is lost with the machine. Preview by default.
    SecretsSeal {
        #[arg(long)]
        apply: bool,
        /// Where the TPM seals nothing, seal with the host key alone — which a disk
        /// taken away opens. Refused otherwise.
        #[arg(long)]
        host_only: bool,
    },

    /// Store a secret in the vault. The value is read from STANDARD INPUT.
    ///
    /// 🔴 Never as an argument: a command line is visible in `ps` to every user of the
    /// machine, and lands in the shell history.
    SecretSet {
        /// Secret name, e.g. dns-cloudflare-api-token
        name: String,
        /// What it is for. Displayed by `hlb secrets`.
        #[arg(long, default_value = "deposited by hand")]
        purpose: String,
        /// Replace an existing value. 🔴 Without this flag, it is not overwritten.
        #[arg(long)]
        rotate: bool,
    },

    /// Print one secret's value — an app's administrator password Homelabus generated,
    /// to sign in when its SSO cannot. Recorded in the audit log, value excluded.
    SecretGet {
        /// Secret name, as `hlb secrets` lists it, e.g. seafile-admin-password
        name: String,
    },

    /// Delete from the vault what `hlb remove` left of an app. Preview by default.
    ///
    /// 🔴 A reinstall then draws new secrets: a volume or a backup kept from before may
    /// no longer open. Only an app this house removed, and that is not installed again:
    /// the audit log proves the name was an app's, or `secrets-forget restic` would take
    /// the password of every backup.
    SecretsForget {
        app: String,
        /// Repeat the app's name. Required by --apply.
        #[arg(long)]
        confirm: Option<String>,
        /// Actually delete them.
        #[arg(long, requires = "confirm")]
        apply: bool,
    },

    /// Audit log: who did what, when.
    Audit {
        #[arg(long, default_value = "30")]
        limit: usize,
        /// Verify the chaining rather than display the entries.
        ///
        /// Each entry carries the fingerprint of the previous one: an entry modified or
        /// removed breaks the chain. Otherwise "append-only" is only a convention, one
        /// nothing enforces on whoever opens the SQLite file.
        #[arg(long)]
        verify: bool,
    },

    /// History of the configuration changes.
    History {
        #[arg(long, default_value = "20")]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum FleetCmd {
    /// Deploy the node agent on every node, present and future, with its mTLS
    /// certificate. Preview by default.
    Agent {
        /// The agent's image: `ghcr.io/turi-industries/hlb-agent:<version>`, published
        /// by the `Images` workflow on a version tag, or built locally with
        /// `docker build --target agent .`.
        #[arg(long)]
        image: String,
        #[arg(long, default_value = "hlb-agent")]
        service: String,
        #[arg(long)]
        apply: bool,
    },
    /// Deploy the controller as a service on THIS node: it shares this machine's state
    /// and vault with `hlb`. Preview by default.
    Controller {
        /// The controller's image: `ghcr.io/turi-industries/hlb-controller:<version>`, published
        /// by the `Images` workflow on a version tag, or built locally with
        /// `docker build --target controller .`.
        #[arg(long)]
        image: String,
        #[arg(long, default_value = "hlb-agent")]
        agent_service: String,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum ClusterCmd {
    /// Make this machine the cluster's first node: dependencies, Docker, the mesh, the
    /// Swarm. Idempotent.
    Init {
        /// Where the other nodes will reach this one for the WireGuard tunnel — its
        /// LAN or public address. Swarm then listens on the mesh only.
        #[arg(long, required_unless_present = "no_mesh")]
        endpoint: Option<String>,
        /// No mesh: Swarm listens on the network the nodes share. Only for nodes on one
        /// trusted LAN — VXLAN has no authentication.
        #[arg(long, requires = "advertise_addr")]
        no_mesh: bool,
        /// Address advertised to the other nodes, without a mesh. 🔴 Required on a
        /// multi-homed host.
        #[arg(long, conflicts_with = "endpoint")]
        advertise_addr: Option<String>,
        /// The physical machine this node runs on, when it hosts other nodes too.
        #[arg(long)]
        failure_domain: Option<String>,
        /// This node will carry the ZFS pool and export it.
        #[arg(long)]
        storage_node: bool,
        #[arg(long)]
        apply: bool,
    },
    /// Nodes, roles, tiers and quorum health.
    Status,
    /// 🔴 Encrypt Swarm secrets at rest. The key goes to the vault and the emergency kit;
    /// run again once on, it is sealed to each manager, which then unlocks itself after
    /// each start of Docker.
    Autolock {
        #[arg(long)]
        apply: bool,
        /// Where a manager's TPM seals nothing, seal with its host key alone — which a
        /// disk taken away opens. Refused otherwise.
        #[arg(long)]
        host_only: bool,
    },
    /// The command to run on a machine to join it.
    JoinCommand {
        /// `manager` or `worker`. Default: whatever the profile recommends.
        #[arg(long)]
        role: Option<String>,
    },
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Check that a machine can host a node. Changes NOTHING.
    Check {
        /// SSH host. Absent: the local machine.
        host: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        identity: Option<String>,
    },
    /// Set a node's tier, derived from its memory.
    Tier {
        /// Node name, as shown by `hlb cluster status`.
        node: String,
        /// Force a value instead of deriving it.
        #[arg(long)]
        set: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// Read a node's protection level again — after its firmware, TPM or system
    /// changed — and label it with what was found. Preview by default.
    ///
    /// The level is detected, never set: a level typed by hand is the one a stolen
    /// machine contradicts.
    Protection {
        /// Node name, as shown by `hlb cluster status`.
        node: String,
        /// SSH host, when the mesh has none recorded for this node.
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        apply: bool,
    },
    /// Bind a node's encrypted disk to its TPM AND one of the house's Tangs, so it
    /// opens alone at boot — then take the install passphrase out, the kit's recovery
    /// key in its place. Preview by default.
    ///
    /// The Tangs go on the house's other nodes. Refused while the emergency kit printed
    /// does not carry the node's recovery key.
    BindDisk {
        /// Node name, as shown by `hlb cluster status`.
        node: String,
        /// SSH host, when the mesh has none recorded for this node.
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        /// The disk's current passphrase on standard input, when the vault holds none —
        /// a disk encrypted by hand.
        #[arg(long)]
        passphrase_stdin: bool,
        #[arg(long)]
        apply: bool,
    },
    /// Verify a node's boot (level A): a kernel image signed by a key of its own, and
    /// the disk `bind-disk` bound resealed to the PCRs it boots with. Preview by
    /// default.
    ///
    /// Run it once per stage, each read from the node: the key handed to shim, enrolled
    /// at the console, the image booted once (opened by the kit's key), then sealed.
    VerifyBoot {
        /// Node name, as shown by `hlb cluster status`.
        node: String,
        /// SSH host, when the mesh has none recorded for this node.
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        apply: bool,
    },
    /// Upgrade a node whole — system, kernel, Docker — then reboot it if it needs
    /// it, after moving its services away. One node at a time. Preview by default.
    ///
    /// Run it again after an interruption: a node left drained is picked up where it
    /// stopped, and put back in service at the end.
    Upgrade {
        /// Node name, as shown by `hlb cluster status`.
        node: String,
        /// SSH host, when the mesh has none recorded for this node.
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        /// Go ahead although the applications stop meanwhile: the only node, or the
        /// only manager.
        #[arg(long)]
        accept_downtime: bool,
        #[arg(long)]
        apply: bool,
    },
    /// Remove, on every node, the images no container uses — what each update leaves
    /// behind. The controller does it every night. Preview by default.
    Prune {
        #[arg(long)]
        apply: bool,
    },
    /// Attach a machine to the cluster, end to end.
    Add {
        /// SSH host of the machine to join.
        host: String,
        #[arg(long, default_value = "root")]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        /// SSH key for the FIRST contact. Afterwards Homelabus uses its own.
        #[arg(long)]
        identity: Option<String>,
        /// `manager` or `worker`. Default: whatever the profile recommends.
        #[arg(long)]
        role: Option<String>,
        /// Address this node advertises to the others, when the cluster has no mesh.
        /// With one, the node advertises its mesh address and this is refused.
        #[arg(long)]
        advertise_addr: Option<String>,
        /// Where the other nodes reach this one for the WireGuard tunnel. Default: the
        /// SSH host.
        #[arg(long, conflicts_with = "behind_nat")]
        endpoint: Option<String>,
        /// The machine is not reachable from the others: it opens its tunnels itself.
        #[arg(long)]
        behind_nat: bool,
        /// The physical machine this node runs on, when it shares one with other nodes
        /// (two VMs on one server). Without it, the node counts as "unknown", never as
        /// isolated.
        #[arg(long)]
        failure_domain: Option<String>,
        /// This node will carry the ZFS pool and export it.
        ///
        /// ⚠️ A DECISION, not a detection. It adds ZFS and the NFS server — a kernel
        /// module on a machine that will never hold a disk is what stops it booting
        /// after an upgrade.
        #[arg(long)]
        storage_node: bool,
        #[arg(long)]
        apply: bool,
    },
    /// What is missing, and what would be installed. Preview by default.
    Deps {
        host: Option<String>,
        #[arg(long)]
        user: Option<String>,
        /// This node will carry the ZFS pool and export it.
        ///
        /// ⚠️ A DECISION, not a detection. It adds ZFS and the NFS server — a kernel
        /// module on a machine that will never hold a disk is what stops it booting
        /// after an upgrade.
        #[arg(long)]
        storage_node: bool,
        /// Actually install: dependencies, Docker, unattended security updates.
        #[arg(long)]
        apply: bool,
    },
    /// A Debian preseed for an automated netinst. Printed, never written to disk.
    ///
    /// 🔴 `--disk` MUST be a `/dev/disk/by-id/...` path. Left to the installer, "the
    /// largest disk" is exactly the one you must not touch on a machine that already
    /// carries a ZFS pool elsewhere — and there is no confirmation and no way back.
    Preseed {
        /// The machine's hostname.
        hostname: String,
        #[arg(long, default_value = "local")]
        domain: String,
        /// System disk, named by /dev/disk/by-id/... — refused otherwise.
        #[arg(long)]
        disk: String,
        /// Installed as the only way in: the account's password is locked.
        #[arg(long)]
        ssh_key: String,
        /// Debian mirror hostname. Defaults to the official one.
        #[arg(long)]
        mirror: Option<String>,
        /// Encrypt the system disk, under a one-time passphrase kept in the vault until
        /// `hlb node bind-disk` takes it out — the TPM and the house's Tangs then open it.
        #[arg(long)]
        encrypt: bool,
    },
}

#[derive(Subcommand)]
enum BackupCmd {
    /// What is due, late, or verified — without running anything.
    Status,
    /// Back up the apps that are due (or all of them with --force).
    Run {
        #[arg(long)]
        force: bool,
        /// One app only — `hlb` for Homelabus's own state — rather than all of them.
        #[arg(long)]
        app: Option<String>,
    },
    /// 🔴 Restore a snapshot into a disposable space and compare.
    Verify {
        /// Limit to one app.
        app: Option<String>,
    },
    /// Put a volume back as one of its snapshots holds it, on the node holding it — a
    /// bucket, through the app's own key, or a database from its dump.
    /// Preview by default.
    ///
    /// The app is stopped meanwhile, and what the volume, bucket or database holds is
    /// backed up first.
    Restore {
        app: String,
        /// The volume or bucket, when the app backs up several.
        volume: Option<String>,
        /// Its database instead, PostgreSQL or MariaDB, from a dump: the app's one, or
        /// the one named, when it has several.
        #[arg(long, num_args = 0..=1, default_missing_value = "", conflicts_with = "volume")]
        database: Option<String>,
        /// A snapshot's id, or its first characters. The latest otherwise.
        #[arg(long)]
        snapshot: Option<String>,
        /// The destination to restore from. The first holding one otherwise.
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// WAL archiving and point-in-time restore.
    #[command(subcommand)]
    Pitr(PitrCmd),

    /// Backup destinations: NAS, Garage, off-site S3.
    #[command(subcommand)]
    Dest(DestCmd),

    /// Where an app's data goes, class by class.
    Route {
        app: String,
        /// Destinations for CRITICAL data: SQL dumps, state, secrets.
        /// A few GB — it fits on any connection.
        #[arg(long, value_delimiter = ',')]
        critical: Option<Vec<String>>,
        /// Destinations for BULKY data: photos, files, media.
        /// ⚠️ Hundreds of GB: check the connection can keep up.
        #[arg(long, value_delimiter = ',')]
        bulky: Option<Vec<String>>,
    },
}

#[derive(Subcommand)]
enum DestCmd {
    /// Declare a destination.
    Add {
        /// Short name: nas, garage, offsite.
        name: String,
        /// Local path, or restic URL `s3:https://host/bucket`.
        #[arg(long)]
        location: String,
        /// Classes accepted by default: critical, bulky.
        #[arg(long, value_delimiter = ',', default_value = "critical")]
        classes: Vec<String>,
        /// S3 access key. The SECRET key is read from STANDARD INPUT.
        #[arg(long)]
        access_key: Option<String>,
    },
    /// Back up to the cluster's own Garage: a bucket, a key that can read and write it
    /// but not delete the bucket, its credentials in the vault, and the destination
    /// declared.
    ///
    /// ⚠️ Garage keeps no versions: the key that writes the backups deletes them too.
    ///
    /// 🔴 Garage on the cluster protects against a deleted file or a dead disk, not
    /// against the house burning: it shares the machines it backs up. Pair it with an
    /// off-site destination.
    Garage {
        /// The destination's name.
        #[arg(long, default_value = "garage")]
        name: String,
        #[arg(long, default_value = "hlb-backups")]
        bucket: String,
        #[arg(long, value_delimiter = ',', default_value = "critical,bulky")]
        classes: Vec<String>,
        #[arg(long)]
        apply: bool,
    },
    /// The declared destinations, what they accept, and whether they can be erased.
    List,
    /// Prove whether whoever holds a destination's credential can erase it: a witness
    /// is written with that credential, then deleted with it. Every destination, or
    /// the one named.
    ///
    /// Writes the witness — a snapshot of nothing, or an object under `hlb-witness/` —
    /// and nothing else.
    Prove { name: Option<String> },
    /// The script that prunes a destination Homelabus cannot erase, for its owner to
    /// run from a machine of their own with a credential that may delete — the weekly
    /// upkeep's own passes. Holds no secret: the password is the emergency kit's.
    PruneScript { name: String },
    /// Remove a destination. Backups already sent stay there.
    Remove { name: String },
}

#[derive(Subcommand)]
enum PitrCmd {
    /// The PostgreSQL settings to apply to enable WAL archiving.
    Config {
        /// Archive directory, mounted into the PostgreSQL container.
        #[arg(long, default_value = "/archive/wal")]
        dir: String,
    },
    /// The window that is really restorable, based on what is retained.
    Window {
        #[arg(long, default_value = "/archive/wal")]
        dir: String,
    },
    /// 🔴 Produce a base backup. Without one, the WAL restores nothing.
    Base {
        /// Directory receiving the base backups.
        #[arg(long, default_value = "/archive/base")]
        dest: String,
        /// Actually run. Without this flag, only what would be done is shown.
        #[arg(long)]
        apply: bool,
    },
    /// Prepare a point-in-time restore. Runs NOTHING.
    Plan {
        /// Target instant in UTC: "2026-08-16 14:04:00".
        target: String,
        #[arg(long, default_value = "/archive/wal")]
        dir: String,
    },
}

#[derive(Subcommand)]
enum UpdateCmd {
    /// Query the registries. Applies nothing; records when each image was first seen.
    Check,
    /// How long updates took from first seen to applied, and what is still waiting.
    Lag,
    /// Apply an app's update.
    Apply {
        app: String,
        /// Ignore the maintenance window.
        #[arg(long)]
        force_window: bool,
        /// 🔴 Apply despite critical vulnerabilities. To be justified.
        #[arg(long)]
        force_vulnerable: bool,
        /// Apply an image published more recently than the manifest's maturation — an
        /// urgent fix. Recorded in the audit log.
        #[arg(long)]
        before_maturity: bool,
    },
    /// How far updates go with nobody there: patches by default, a minor with a click, a
    /// major by hand. Shows the settings without `--automatic`.
    Policy {
        /// The app to set; the whole house without it.
        app: Option<String>,
        /// none, patch or minor — or `manifest` to give the decision back.
        #[arg(long)]
        automatic: Option<String>,
    },
    /// Scan an image without applying anything: CVEs and signature.
    Scan {
        /// Full image, e.g. gitea/gitea:1.25
        image: String,
        /// Expression for the expected signer identity.
        #[arg(long, env = "HLB_COSIGN_IDENTITY")]
        identity: Option<String>,
        /// Expected OIDC issuer, e.g. https://token.actions.githubusercontent.com
        #[arg(long, env = "HLB_COSIGN_ISSUER")]
        issuer: Option<String>,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Create a token. Its value is shown ONLY ONCE.
    Create {
        /// Name, so you know which one to revoke later.
        name: String,
        /// viewer (see everything), operator (install, back up), admin (everything).
        #[arg(long, default_value = "viewer")]
        role: String,
        /// Bind the token to an account, for the alias API.
        ///
        /// 🔴 Without it, this is a SERVICE token: it cannot create an alias in
        /// anyone's name. Stealing it would therefore not grant the power to open
        /// addresses on someone else's mailbox.
        #[arg(long)]
        user: Option<String>,
        /// Destination mailbox for the aliases this token creates.
        ///
        /// 🔴 Absent: the default mailbox. The addy.io protocol has NO field for
        /// choosing the mailbox — so the token carries it. One token per mailbox, and
        /// changing destination means changing token in Bitwarden.
        #[arg(long, requires = "user")]
        mailbox: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// The tokens: names, roles, last use. Never the values.
    List,
    /// Revoke a token. Immediate effect.
    Revoke { name: String },
}

#[derive(Subcommand)]
enum SnapshotCmd {
    /// Freeze a dataset's state before a risky operation.
    Create {
        /// ZFS dataset or btrfs subvolume, e.g. tank/hlb
        dataset: String,
        /// What this snapshot is for, e.g. before-gitea-update
        #[arg(long, default_value = "manuel")]
        pattern: String,
        #[arg(long)]
        apply: bool,
    },
    /// The snapshots Homelabus created on this dataset.
    List { dataset: String },
}

#[derive(Subcommand)]
enum SelfCmd {
    /// Installed version, fleet compatibility. Changes nothing.
    Status,
    /// 🔴 Go back to an earlier version's schema. DESTRUCTIVE.
    Rollback {
        /// Restore the previous binary instead of the schema.
        #[arg(long)]
        binary: bool,
        /// Number of the last migration to KEEP, e.g. 4
        #[arg(long, default_value = "0")]
        to_migration: i64,
        /// Explicit confirmation: data will be lost.
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        apply: bool,
    },
    /// What the update would do, and what prevents it. Preview by default.
    Update {
        /// Target version, e.g. 0.2.0
        version: String,
        /// Download base URL. The binary and its manifest are expected there.
        ///
        /// Defaults to this project's GitHub Releases (`v<version>` tag). Set this to
        /// point at a self-hosted mirror instead.
        #[arg(long, env = "HLB_RELEASE_URL")]
        from: Option<String>,
        /// 🔴 Ed25519 release public key, in hexadecimal.
        ///
        /// Without it no binary is installed: an unverified update would be the best
        /// vector for compromising the system.
        #[arg(long, env = "HLB_RELEASE_KEY")]
        key: Option<String>,
        /// 🔴 Required for a MAJOR version or a rollback.
        #[arg(long)]
        confirm: bool,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// The house name and colours shown on every screen.
    ///
    /// 🔴 Settable from the command line on purpose: the sign-in screen carries this
    /// name, and it is what distinguishes a legitimate page from a phishing one. You
    /// must be able to set it before anyone has signed in.
    Appearance {
        /// The house, e.g. "Turi Industries".
        #[arg(long)]
        name: Option<String>,
        /// The product. Distinct from the house.
        #[arg(long)]
        product: Option<String>,
        /// Accent colour, `RRGGBB`.
        #[arg(long)]
        accent: Option<String>,
        /// Footer line: legal notice, support contact, on-call number.
        #[arg(long)]
        footer: Option<String>,
        /// Theme offered to people who have not chosen one.
        #[arg(long)]
        theme: Option<String>,
        /// Path to a PNG or SVG logo, shown in the sidebar and the sign-in page
        /// instead of the painted monogram — an SVG is rasterized on save. 256 KB
        /// max for the stored PNG (after rasterization, for an SVG).
        #[arg(long)]
        logo: Option<std::path::PathBuf>,
        /// Removes the logo, falling back to the painted monogram.
        #[arg(long)]
        remove_logo: bool,
        #[arg(long)]
        apply: bool,
    },
    /// The installation's time zone, for the apps whose manifest reads `{{ timezone }}`.
    /// Without a zone: the one set.
    ///
    /// ⚠️ Seafile reads it once, at its first start: an app installed before keeps the
    /// zone it was given then.
    Timezone {
        /// `Europe/Paris`, `America/Montreal`, `UTC`.
        zone: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// When a machine waiting for a reboot — a kernel installed, not yet running — is
    /// rebooted on its own, drained first, one at a time. Without an option: the rule,
    /// and the reboot under way or given up on.
    ///
    /// 🔴 A machine whose reboot stops applications — the only one, a manager the others
    /// are no majority without, one keeping data, the one Homelabus runs on — waits for
    /// a person unless the house accepts that downtime in its window.
    Reboots {
        /// `daily 03:00-05:00` (the default), `sun 02:00-04:00`, `sat,sun 01:00-03:00`,
        /// in the house's time zone.
        #[arg(long, conflicts_with = "never")]
        window: Option<String>,
        /// No machine reboots on its own; `hlb node upgrade` stays a person's.
        #[arg(long)]
        never: bool,
        /// Reboot a machine whose applications stop meanwhile too, in the window.
        #[arg(long, conflicts_with = "refuse_downtime")]
        accept_downtime: bool,
        /// Leave such a machine to a person (the default).
        #[arg(long)]
        refuse_downtime: bool,
        #[arg(long)]
        apply: bool,
    },
    /// The UPS the house reads through NUT, and when its apps stop for the power: on
    /// battery a while, or with little runtime left, they stop in waves — those nothing
    /// uses first, the databases last — and start again once the mains are steady.
    /// Without an option: the rule, a reading now, and a stop under way.
    ///
    /// NUT is only read (`GET VAR`, no account). The machines themselves are shut down
    /// by NUT's own `upsmon` at low battery, where it is set up: by then nothing writes.
    Ups {
        /// NUT's server, `host` or `host:port` (3493 when left out).
        #[arg(long, conflicts_with = "off")]
        server: Option<String>,
        /// The UPS's name on that server: `upsc -l <server>` lists them.
        #[arg(long, conflicts_with = "off")]
        ups: Option<String>,
        /// Seconds on battery before the apps stop (300): most outages are shorter.
        #[arg(long, conflicts_with = "off")]
        after: Option<u32>,
        /// Stop at once when the UPS says less runtime than this is left, in seconds
        /// (600): the time the waves take.
        #[arg(long, conflicts_with = "off")]
        runtime: Option<u32>,
        /// Seconds the mains must be back before the apps start again (120).
        #[arg(long, conflicts_with = "off")]
        steady: Option<u32>,
        /// Read no UPS. Apps stopped for the power start again.
        #[arg(long)]
        off: bool,
        #[arg(long)]
        apply: bool,
    },
    /// How the installation is reached from outside: its domain, its certificates, the
    /// machine the router forwards to. Without an option: what is set, and what is
    /// missing.
    ///
    /// Every option keeps what is set when left out.
    Exposure {
        /// The domain apps are published under: `gitea.<domain>` when the install names
        /// none.
        #[arg(long)]
        domain: Option<String>,
        /// Where Let's Encrypt sends expiry notices.
        #[arg(long)]
        email: Option<String>,
        /// One wildcard certificate over DNS-01 through this provider (cloudflare,
        /// desec, duckdns, gandi, hetzner, ovh, porkbun); `none` for one per name over
        /// HTTP-01. Its credentials are vault secrets, `dns-<provider>-<field>`.
        #[arg(long)]
        dns: Option<String>,
        /// Caddy's own authority instead of Let's Encrypt: for a house no public name
        /// reaches.
        #[arg(long, conflicts_with_all = ["email", "dns", "staging", "production"])]
        internal: bool,
        /// 🔴 Let's Encrypt's staging directory: untrusted certificates, the quota
        /// untouched. The first attempt belongs there.
        #[arg(long, conflicts_with = "production")]
        staging: bool,
        /// Back to trusted certificates, once staging worked.
        #[arg(long)]
        production: bool,
        /// Where the interface answers; `hlb.<domain>` by default.
        #[arg(long)]
        interface: Option<String>,
        /// The machine the router forwards 80 and 443 to: Caddy runs there.
        #[arg(long)]
        node: Option<String>,
        /// A private ACME directory (step-ca, a home PKI) instead of Let's Encrypt's;
        /// `none` to go back.
        #[arg(long, conflicts_with = "internal")]
        acme_ca: Option<String>,
        /// The PEM root of that authority, which Caddy and the controller then trust.
        #[arg(long, conflicts_with = "internal")]
        acme_ca_root: Option<std::path::PathBuf>,
        /// Print the internal authority's root certificate, to install on a device.
        #[arg(long)]
        root: bool,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum AlertCmd {
    /// Mute a rule: it stays listed, one notch lower, and stops notifying until then.
    Mute {
        /// The rule, as `hlb-metrics` names it (`disk-full`, `backup-absent`…).
        rule: String,
        /// How long: `90m`, `4h`, `2d` — at most a week, since a mute with no end is a
        /// deleted alert.
        #[arg(long = "for")]
        duration: String,
        /// Why. Required: a mute nobody can explain afterwards is the one nobody dares lift.
        #[arg(long)]
        reason: String,
    },
    /// Lift a rule's mute: it notifies again from the next evaluation.
    Unmute { rule: String },
    /// The mutes in force.
    Mutes,
}

#[derive(Subcommand)]
enum AnnouncementCmd {
    /// Publish an announcement.
    Publish {
        title: String,
        /// The body. What people need to know, in a few lines.
        body: String,
        /// `info`, `maintenance`, `warning`, `incident`.
        #[arg(long, default_value = "info")]
        level: String,
        /// Keep it at the top until it is removed.
        #[arg(long)]
        pinned: bool,
        /// Restrict it to a role: `operator`, `admin`. Absent = everyone.
        ///
        /// ⚠️ An announcement that does not concern its reader is noise, and flooding a
        /// portal user with operational messages makes them stop reading — exactly when
        /// one will matter.
        #[arg(long)]
        audience: Option<String>,
        #[arg(long)]
        apply: bool,
    },

    /// Add an update to an existing announcement.
    ///
    /// 🔴 ADDS, never rewrites. The chronology is what you re-read afterwards, and
    /// editing the original message would erase it.
    Follow {
        id: i64,
        body: String,
        #[arg(long)]
        apply: bool,
    },

    /// Remove an announcement.
    Remove {
        id: i64,
        #[arg(long)]
        apply: bool,
    },

    /// What is published today.
    List,
}

#[derive(Subcommand)]
enum StorageCmd {
    /// What pools this machine has, and what Homelabus would do about them.
    ///
    /// Changes nothing.
    Status {
        /// Which pool to use, when the machine has several.
        #[arg(long)]
        pool: Option<String>,
    },

    /// Import a pool present on the disks, and create the app datasets — encrypted
    /// under the key `hlb storage encrypt` put on this machine.
    ///
    /// ⚠️ Importing is reversible (`zpool export`). Creating a pool is NOT, and this
    /// command never does it: it tells you the `zpool create` to run, with the disks
    /// you name.
    Init {
        /// The pool. Required when the machine has more than one.
        #[arg(long)]
        pool: Option<String>,
        /// Dataset root for the app data, under the pool.
        #[arg(long, default_value = "apps")]
        root: String,
        /// Create the datasets in clear, this machine having no dataset key.
        #[arg(long)]
        unencrypted: bool,
        /// Actually import and create.
        #[arg(long)]
        apply: bool,
    },

    /// Encrypt a storage node's app datasets under a key of its own, unlocked at boot
    /// before Docker and the NFS server start. Preview by default.
    ///
    /// The preview makes the key, in the vault; nothing is done until an emergency kit
    /// printed since carries it. Each plain volume is then copied encrypted while its
    /// app is stopped, checked, swapped in, and the plain one destroyed.
    Encrypt {
        /// The storage node, as `hlb cluster status` names it.
        node: String,
        /// The pool. Required when the node has more than one.
        #[arg(long)]
        pool: Option<String>,
        /// Dataset root for the app data, under the pool.
        #[arg(long, default_value = "apps")]
        root: String,
        /// SSH host, when the mesh has none recorded for this node.
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        apply: bool,
    },

    /// The `/etc/exports` lines for the app datasets.
    ///
    /// Printed, not written: `/etc/exports` is a file you may already have edited, and
    /// rewriting it wholesale would drop what is in it.
    Export {
        #[arg(long)]
        pool: Option<String>,
        #[arg(long, default_value = "apps")]
        root: String,
        /// The network allowed to mount, e.g. `10.0.0.0/24`.
        #[arg(long)]
        network: String,
    },
}

#[derive(Subcommand)]
enum PortalCmd {
    /// Stop the portal accepting a return to this URL. An installed app's is refused;
    /// a reinstall adds its own back. Preview by default.
    DropCallback {
        url: String,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum GarageCmd {
    /// Known nodes and the current layout. Changes nothing.
    Status,
    /// Give every node that has joined a place in the layout — nine tenths of the
    /// space free on its data disk — and apply it. Until a node has one, Garage stores
    /// nothing at all. Preview by default.
    Init {
        #[arg(long, default_value = hlb_objstore::DEFAULT_ZONE)]
        zone: String,
        #[arg(long)]
        apply: bool,
    },
    /// Stage a capacity and zone for a node that has joined but carries none yet.
    ///
    /// 🔴 Only STAGES the change: nothing is redistributed until `hlb garage commit`
    /// confirms the version this prints.
    Assign {
        /// Node id, as `hlb garage status` lists it.
        node: String,
        #[arg(long)]
        zone: String,
        /// Storage this node contributes, in bytes.
        #[arg(long)]
        capacity: u64,
        #[arg(long)]
        apply: bool,
    },
    /// Apply the staged layout, redistributing data across the cluster.
    ///
    /// 🔴 `--version` must be the exact one `assign`/`status` just showed: repeating it
    /// is what stops a change staged by someone else from being applied unseen.
    Commit {
        #[arg(long)]
        version: u64,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum ReplCmd {
    /// The settings to apply on the primary and on the standby.
    Config {
        /// Name of the node that will carry the standby.
        standby: String,
        /// Host of the primary, as the standby will reach it.
        #[arg(long, default_value = "postgres")]
        primary_host: String,
        /// Replication role.
        #[arg(long, default_value = "replicant")]
        user: String,
    },
    /// 🔴 Are the standbys keeping up, and is a dead slot filling the disk?
    Status,

    /// 🔴 Assisted switchover: promote a standby to primary.
    ///
    /// Preview by default. Refuses to promote a standby that is behind — promoting one
    /// drops the transactions it never received — unless you say --force, knowing what
    /// it costs.
    Failover {
        /// The standby to promote, by its `application_name`.
        standby: String,
        /// Promote even when transactions would be lost.
        #[arg(long)]
        force: bool,
        /// Actually print the procedure to run.
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    /// Create an account: PocketID identity plus mailbox, in one go. Preview by
    /// default: nothing changes without --apply.
    ///
    /// Resumable: rerunning after a failure finishes what is missing.
    Add {
        /// Sign-in identifier, which also becomes the default local part.
        name: String,
        /// Default address. Without it: <name>@<mail domain>.
        #[arg(long)]
        email: Option<String>,
        /// Display name.
        #[arg(long)]
        display_name: Option<String>,
        /// The role it starts with — `hlb role list` names them. An account that
        /// exists keeps its own: that is `hlb user role`'s.
        #[arg(long, default_value = "standard")]
        role: String,
        /// Actually create it.
        #[arg(long)]
        apply: bool,
    },
    /// The accounts, their mailboxes and the state of their aliases.
    List,
    /// A person's role: what they may do to Homelabus, which apps they enter, how much
    /// they may hold.
    Role {
        name: String,
        /// The role's id. Without one: display the role held.
        role: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// A person's own storage quota in an app, over their role's. Preview by default.
    Quota {
        name: String,
        app: String,
        /// The quota, in GiB.
        #[arg(long, conflicts_with_all = ["none", "role"])]
        gib: Option<f64>,
        /// No quota at all, whatever their role's.
        #[arg(long, conflicts_with = "role")]
        none: bool,
        /// Their role's again.
        #[arg(long)]
        role: bool,
        #[arg(long)]
        apply: bool,
    },
    /// A person's open sessions, and what it takes to close them.
    Sessions {
        name: String,
        /// Close a session by its short reference, or "all".
        #[arg(long)]
        close: Option<String>,
    },
    /// A person's names, as PocketID gives them to every application.
    ///
    /// Each is written as given: one left out is written empty.
    Names {
        name: String,
        #[arg(long, default_value = "")]
        first: String,
        #[arg(long, default_value = "")]
        last: String,
        /// The name applications show. Required: an empty one greets nobody.
        #[arg(long)]
        display: String,
        #[arg(long)]
        apply: bool,
    },
    /// A link a person signs up with: their PocketID identity, their mailbox and their
    /// account, created when they open it. Preview by default.
    ///
    /// The link is shown ONCE — only its fingerprint is kept. Sending it is yours to do.
    Invite {
        /// The role the account will hold — `hlb role list` names them.
        #[arg(long)]
        role: String,
        /// How many people it lets in.
        #[arg(long, default_value_t = 1)]
        uses: i64,
        /// How long it stays valid, in days (thirty at most).
        #[arg(long, default_value_t = 7)]
        days: i64,
        /// Who it is for — kept beside it, shown in the list.
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// A new single-use link for a person to register a passkey with: their first, or
    /// after losing every device. Valid twelve hours.
    Link { name: String },
    /// The invitations: who created each, what it grants, how many it still lets in.
    Invitations,
    /// Close an invitation before it expires. Kept, exhausted: who came in through it
    /// stays on record.
    RevokeInvitation {
        /// Its reference, as `hlb user invitations` lists it.
        reference: String,
        #[arg(long)]
        apply: bool,
    },
    /// Additional mailboxes.
    #[command(subcommand)]
    Mailbox(MailboxCmd),
    /// Aliases: permanent or temporary, generated or chosen.
    #[command(subcommand)]
    Alias(AliasCmd),
    /// Devices: one password each for a person's mailbox — mail, calendars and
    /// contacts on a phone, which cannot sign in with a passkey.
    #[command(subcommand)]
    Device(DeviceCmd),
}

/// Roles: a name, a permission level, mail limits, a quota per app — and the apps each
/// one enters. Each is a PocketID group; `sync` makes PocketID and the apps hold them.
#[derive(Subcommand)]
enum EmergencyCmd {
    /// Every recovery sign-in Homelabus generated, deposited in Vaultwarden's "Server"
    /// collection: the account set up with an owner, what it was given verified, then
    /// each app's administrator written. Preview by default.
    Vault {
        /// The account's address — a mailbox you read: an owner's invitation is sent
        /// there.
        #[arg(long)]
        address: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// The emergency kit: the master key, the backup repository's password and how to
    /// reach each destination, to print and keep away from the cluster. Recorded in the
    /// audit log before it is shown.
    Kit {
        /// Write it to this file, readable by its owner only, rather than to standard
        /// output. An existing file is never overwritten.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Sealed to the split `hlb emergency split` made: a file safe to send to every
        /// relative, which their shares open. Print it again after any change — the
        /// shares stay as they are.
        #[arg(long)]
        sealed: bool,
    },
    /// Splits the kit's key among relatives: any THRESHOLD of the SHARES open the kit
    /// sealed to it, fewer say nothing of it. Writes a sheet per relative and the sealed
    /// kit into a new directory; the key itself is kept nowhere.
    Split {
        #[arg(long, default_value_t = 3)]
        threshold: u8,
        #[arg(long, default_value_t = 5)]
        shares: u8,
        /// A directory that does not exist yet, created readable by its owner only.
        #[arg(long)]
        out: PathBuf,
        /// Make a new split over the current one. The old shares still open every kit
        /// already sealed to them: paper cannot be revoked.
        #[arg(long)]
        replace: bool,
    },
    /// Rebuilds the kit's key from shares typed on standard input, one per line, and
    /// opens the sealed kit with it. Needs neither the state nor the vault: it runs on
    /// any machine. Without --kit, says only whether the shares open their split.
    Combine {
        /// The sealed kit, `hlb emergency kit --sealed`.
        #[arg(long)]
        kit: Option<PathBuf>,
        /// Write the opened kit to this file, readable by its owner only, rather than to
        /// standard output.
        #[arg(long, requires = "kit")]
        out: Option<PathBuf>,
    },
    /// Records the family's rehearsal: the code at the end of the sealed kit, which
    /// only those who opened it with their shares have read. Burned once given.
    Rehearsed {
        /// As read off the opened kit: four groups of four letters.
        code: String,
    },
    /// The relatives every sealed kit is mailed to, at an address of their own outside
    /// the house — mailed by `kit --sealed` and `split` each time.
    #[command(subcommand)]
    Relatives(RelativesCmd),
}

#[derive(Subcommand)]
pub(crate) enum RelativesCmd {
    List,
    /// Preview by default.
    Add {
        address: String,
        #[arg(long)]
        apply: bool,
    },
    /// Preview by default. Their copies already sent stay theirs.
    Remove {
        address: String,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum RelayCmd {
    /// Send every remote domain through a relay — a provider's submission service. Its
    /// account's password is read on standard input with --apply, and tried before
    /// anything is written. Preview by default.
    Set {
        #[arg(long)]
        host: String,
        /// 587 with STARTTLS, required; 465 with --implicit-tls.
        #[arg(long, default_value_t = 587)]
        port: u16,
        #[arg(long)]
        implicit_tls: bool,
        #[arg(long)]
        user: String,
        /// The SPF term the provider gives (`include:spf.provider.net`): the domain's
        /// SPF must name it, and the nightly reading expects it there.
        #[arg(long)]
        spf: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// Send remote domains by their MX again.
    Remove {
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum DomainCmd {
    /// Read the zone holding the exposure's domain — NS, DS, DNSSEC validation and CAA
    /// from a public resolver; registrar, locks, delegation and expiry from the
    /// registry's RDAP, or its WHOIS where the TLD has no RDAP — record it, and compare it with the
    /// baseline; and the certificates the Certificate Transparency logs hold for its
    /// names since the last night, judged by whether the house holds their key. Exits 1
    /// on anything moved, a certificate under another key, or with no baseline.
    Watch,
    /// Make the reading taken now the baseline every later one is compared with, and
    /// the certificates issued until now — those found foreign included — accepted.
    /// Preview by default.
    Accept {
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum MailCmd {
    /// Every record a mail domain needs — DKIM, SPF, MX, DMARC — as Stalwart computed
    /// it, read from a public resolver and recorded for the inbox. Prints the lines
    /// to add; exits 1 while one is missing.
    Dns {
        /// One domain; every domain Stalwart hosts by default.
        domain: Option<String>,
    },
    /// What Stalwart's queue still has to deliver, oldest first, with what the last
    /// attempt was told; recorded for the inbox. Exits 1 while one has waited an hour.
    Queue,
    /// Move an installed Stalwart 0.16.27 to the catalog's 1.0: its store copied by
    /// `stalwart-migrate` into a new volume while it serves, then stopped for the last
    /// changes, every account compared, and 1.0 started on the copy. The 0.16 volume is
    /// kept and never written. Preview by default.
    Migrate {
        #[arg(long)]
        apply: bool,
    },
    /// Where remote mail leaves through, and whether Stalwart's node reaches port 25 of
    /// the internet at all — most residential lines do not.
    Relay {
        #[command(subcommand)]
        action: Option<RelayCmd>,
    },
}

#[derive(Subcommand)]
enum TermixCmd {
    /// Let Homelabus in, once: reads an administrator's Termix API key on standard
    /// input, makes Homelabus's own account and key with it, then deletes it. With
    /// --apply, the nodes are synced right after.
    Connect {
        #[arg(long)]
        apply: bool,
    },
    /// Every node's account and key, and Termix's hosts and shares, made to hold.
    /// Preview by default: the nodes are read, not written.
    Sync {
        #[arg(long)]
        apply: bool,
    },
    /// A new key for the nodes, moved to without a moment Termix is shut out: added
    /// beside the current one everywhere, given to Termix, then the former removed.
    Rotate {
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum RoleCmd {
    /// The roles, who holds each, the apps they enter and what they administer.
    List,
    /// Create a role, or change one's name, level or mail limits. Preview by default.
    Set {
        /// Its id: lowercase letters, digits, hyphens. It names its PocketID group and
        /// never changes.
        id: String,
        /// For people, 2 to 50 characters.
        #[arg(long)]
        name: Option<String>,
        /// user | viewer | operator | admin: what it may do to Homelabus.
        #[arg(long)]
        level: Option<String>,
        /// Mailboxes, the default one included.
        #[arg(long)]
        mailboxes: Option<u32>,
        #[arg(long)]
        permanent_aliases: Option<u32>,
        #[arg(long)]
        temporary_aliases: Option<u32>,
        /// The longest a temporary alias may live, in days.
        #[arg(long)]
        alias_days: Option<i64>,
        /// Each mailbox's space, in GiB.
        #[arg(long)]
        mail_gib: Option<f64>,
        #[arg(long)]
        apply: bool,
    },
    /// Delete a role nobody holds, no app lets in and no open invitation grants.
    Delete {
        id: String,
        #[arg(long)]
        apply: bool,
    },
    /// Let a role into an installed app. Preview by default.
    Allow {
        role: String,
        app: String,
        #[arg(long)]
        apply: bool,
    },
    /// Stop letting a role into an app: with no role left, nobody enters it.
    Deny {
        role: String,
        app: String,
        #[arg(long)]
        apply: bool,
    },
    /// A role's storage quota in an app that takes one.
    Quota {
        role: String,
        app: String,
        /// In GiB.
        #[arg(long, conflicts_with = "none")]
        gib: Option<f64>,
        /// None at all.
        #[arg(long)]
        none: bool,
        #[arg(long)]
        apply: bool,
    },
    /// Make PocketID's groups and claims, each app's restriction, its quotas and its
    /// members hold the roles. Preview by default.
    Sync {
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum MailboxCmd {
    /// Open one more mailbox. Preview by default.
    Add {
        /// Owning account.
        name: String,
        /// Local part of the new mailbox.
        local: String,
        #[arg(long)]
        apply: bool,
    },
    /// Take a mailbox from an account. The default mailbox is refused. Preview by
    /// default.
    ///
    /// Its Stalwart account is NOT deleted, nor its mail: it keeps receiving.
    Remove {
        name: String,
        local: String,
        #[arg(long)]
        apply: bool,
    },
    /// Make another mailbox the account's default — its identity, and the address
    /// PocketID gives applications.
    ///
    /// Resumable: naming the current default writes PocketID again.
    Default {
        name: String,
        local: String,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// A person's devices, read from Stalwart.
    List { name: String },
    /// Make a device a password of its own. Preview by default.
    ///
    /// The password is shown ONCE: Stalwart keeps nothing anyone can read back.
    Add {
        /// The account.
        name: String,
        /// What the device is called — how it is told from the others when revoking.
        device: String,
        /// One of their mailboxes, by its local part or its address. Without it: their default one.
        #[arg(long)]
        mailbox: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// Revoke a device's password: refused from its next request on. Preview by
    /// default.
    Revoke {
        name: String,
        /// The mailbox the device signs in to, by its local part or its address.
        mailbox: String,
        /// The device's id, as `hlb user device list` shows it.
        id: String,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum AliasCmd {
    /// Create an alias.
    ///
    /// The three axes are INDEPENDENT:
    ///   lifetime — permanent by default, temporary with `--for-duration`
    ///   name     — generated by default, chosen with `--alias-name`
    ///   hint     — none by default, the site's with `--for-site`
    ///
    /// Examples:
    ///   hlb user alias add lena                                    random, permanent
    ///   hlb user alias add lena --for-site amazon                  random, tied to a site
    ///   hlb user alias add lena --for-site fnac --for-duration 30d disposable, attributable
    ///   hlb user alias add lena --alias-name contact               chosen, permanent
    Add {
        /// Owning account.
        name: String,
        /// Destination mailbox. Defaults to the account's default mailbox.
        #[arg(long)]
        mailbox: Option<String>,
        /// 🔴 A CHOSEN local part. Without it, one is generated and unguessable.
        #[arg(long, conflicts_with = "for_site")]
        alias_name: Option<String>,
        /// The site or use: serves as a readable hint, followed by a random suffix.
        #[arg(long)]
        for_site: Option<String>,
        /// Lifetime: `30d`, `12h`, `90m`. Absent = permanent.
        #[arg(long)]
        for_duration: Option<String>,
        /// Free-form note, so you remember in six months.
        #[arg(long)]
        note: Option<String>,
        /// Sorting folder. Absent: proposed from `--for-site`. Empty: no sorting.
        ///
        /// 🔴 It is YOUR filing, not ours: the system proposes, it does not impose.
        #[arg(long)]
        folder: Option<String>,
    },
    /// Every alias of an account, with its real state.
    List {
        name: String,
        /// Show only the problems.
        #[arg(long)]
        problems: bool,
    },
    /// Disable an alias without deleting it.
    ///
    /// 🔴 Preferable to deletion: a disabled alias stays present on the server, routed
    /// to a "Disabled" folder instead of the inbox — so what still knocks at the door
    /// keeps being counted, which says how long a merchant kept selling the address
    /// after it was closed. Requires `hlb user alias sieve <name> --apply` afterwards.
    Disable { name: String, alias: String },
    /// Change an alias's sorting folder.
    ///
    /// An empty string means "no sorting" — and that is honoured.
    Folder {
        name: String,
        alias: String,
        folder: String,
    },
    /// The Sieve sorting script, as it would be installed.
    ///
    /// ⚠️ Shows the block Homelabus manages. Rules written by hand outside that block
    /// are never touched.
    Sieve {
        name: String,
        /// Mailbox concerned. Defaults to the account's default mailbox.
        #[arg(long)]
        mailbox: Option<String>,
        /// Actually install the script on Stalwart. Preview by default.
        #[arg(long)]
        apply: bool,
    },
    /// 🔴 Remove expired temporary aliases.
    ///
    /// Without this purge a "temporary" alias stays active FOREVER: Stalwart has no
    /// notion of expiry. This is the command that makes the promise true.
    Purged {
        /// Restrict to one alias by its local part. Absent: every account's.
        #[arg(long)]
        alias: Option<String>,
        /// Preview by default: nothing is removed without --apply.
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum MetricsCmd {
    /// VictoriaMetrics's scrape configuration.
    Scrape {
        /// Controller address, as VictoriaMetrics will reach it.
        #[arg(long, default_value = "hlb-controller:8080")]
        controller: String,
        /// A READ token (metrics role). Without it, collection gets 401s.
        #[arg(long)]
        token: Option<String>,
    },
    /// The shipped alert rules, and what they watch.
    Rules,
    /// Evaluate the rules now, against VictoriaMetrics.
    Check {
        /// VictoriaMetrics URL.
        #[arg(long, default_value = "http://victoria-metrics:8428")]
        url: String,
    },
    /// 🔴 The external watchdog: the script to install on the NAS.
    Deadman {
        /// File where the NAS receives the beats.
        #[arg(long, default_value = "/var/lib/hlb/beat")]
        heartbeat_file: String,
        /// The watchdog's ntfy topic. DISTINCT from Homelabus's own.
        #[arg(long)]
        ntfy: String,
    },
}

#[derive(Subcommand)]
enum DrCmd {
    /// Promote PostgreSQL on a standby node. Preview by default.
    Promote {
        /// Host node, as shown by `hlb cluster status`.
        node: String,
        /// Directory holding the base backups.
        #[arg(long, default_value = "/archive/base")]
        base_dir: String,
        /// WAL archive directory.
        #[arg(long, default_value = "/archive/wal")]
        wal_dir: String,
        /// 🔴 Override the "the old primary still answers" check.
        #[arg(long)]
        force_split_brain: bool,
        #[arg(long)]
        apply: bool,
    },
    /// 🔴 Rehearse a restore for real, in a disposable container.
    Exercise {
        /// Directory holding the base backups.
        #[arg(long, default_value = "/archive/base")]
        base_dir: String,
        /// PostgreSQL image to restore into. By default the one the installed
        /// PostgreSQL runs: a base backup opens only on the same libc and extensions —
        /// the musl `postgres:17-alpine` this used to default to sorts text unlike the
        /// catalog's glibc server, and has no vectorchord.
        #[arg(long)]
        image: Option<String>,
        /// 🔴 I confirm the target is disposable. Without this, the drill refuses —
        /// and clap says so, so a line advertised without it is caught by a test.
        #[arg(long, required = true)]
        disposable: bool,
        #[arg(long)]
        apply: bool,
    },
    /// Am I ready to fail over? Changes nothing.
    Status,
}

#[derive(Subcommand)]
enum PkiCmd {
    /// Create the cluster authority. Once, for ten years.
    Init {
        #[arg(long)]
        apply: bool,
    },
    /// Issue an agent's certificate, for an agent run by hand: it ends in 90 days, and
    /// only the fleet's services are renewed by `hlb pki renew` and the controller.
    Agent {
        /// The node's hostname.
        node: String,
        /// Output directory.
        #[arg(long, default_value = ".")]
        out: std::path::PathBuf,
        /// Name of the agents' Swarm service.
        #[arg(long, default_value = "hlb-agent")]
        service: String,
    },
    /// Issue the controller's client certificate.
    Controller {
        #[arg(long, default_value = ".")]
        out: std::path::PathBuf,
    },
    /// What the authority has issued, and what expires soon.
    Status,
    /// Issue again the fleet's leaves due within 30 days — or whose end is unknown —
    /// and hand them to their services. The controller does it every night; this is
    /// the same pass, by hand. Preview by default.
    Renew {
        /// Name of the agents' Swarm service.
        #[arg(long, default_value = "hlb-agent")]
        service: String,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum AccessCmd {
    /// Install Homelabus's key on a machine.
    Grant {
        host: String,
        #[arg(long, default_value = "root")]
        user: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        /// Key for the first contact.
        #[arg(long)]
        identity: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// 🔴 Remove Homelabus's key from a machine. Human access is preserved.
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
    /// What Homelabus sees in a machine's authorized_keys.
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
    /// Add a node to the mesh and produce its configuration.
    Add {
        /// Node name, as shown by `hlb cluster status`.
        node: String,
        /// Reachable public address. Absent = node behind NAT.
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// The `wg-quick` configuration of an already registered node.
    Show { node: String },
    /// Push the current configuration to every node, after one joined or left.
    Sync {
        #[arg(long)]
        apply: bool,
    },
    /// The mesh nodes and their addresses.
    List,
    /// Take a node out of the mesh — a machine gone, or reinstalled under another name —
    /// and push every other node its configuration without it. Refused while the node
    /// is in the Swarm. Preview by default.
    Remove {
        node: String,
        #[arg(long)]
        apply: bool,
    },
}

#[derive(Subcommand)]
enum CrowdsecCmd {
    /// Enrol the bouncer and store its key in the vault. Without it, nothing is blocked.
    Enroll {
        /// Swarm service carrying CrowdSec.
        #[arg(long, default_value = "crowdsec")]
        service: String,
        /// CrowdSec's local API as the bouncer reaches it, when not the catalog's
        /// `http://crowdsec:8080`. Recorded in the state, so the controller's
        /// publications name it too; given again with a key enrolled, it is changed.
        #[arg(long, env = "HLB_CROWDSEC_URL")]
        url: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// Is the filtering REALLY active?
    Status {
        #[arg(long, default_value = "crowdsec")]
        service: String,
    },
}

#[derive(Subcommand)]
enum CatalogCmd {
    /// List the available apps.
    List,
    /// Validate every manifest and the dependency graph.
    Validate {
        /// The catalog repository's checkout: its apps validated beside the platform
        /// services of `--catalog` (this hlb's own when there is none here), in place
        /// of its apps.
        #[arg(long)]
        apps: Option<std::path::PathBuf>,
    },
    /// The newest mature version of each image's own tag shape and major, and the
    /// digest it names. Preview by default; `--apply` writes them into the manifests.
    /// A major is said, never written: a person rehearses it first.
    Images {
        #[arg(long)]
        apply: bool,
    },
    /// The third-party sources read beside the official catalog, each a directory
    /// whose apps install as `<source>/<app>`.
    #[command(subcommand)]
    Source(SourceCmd),
    /// A source's signing key, kept on the signer's machine.
    #[command(subcommand)]
    Key(KeyCmd),
    /// A source's signed index: built by CI, signed by its owner, checked by every hlb.
    #[command(subcommand)]
    Index(IndexCmd),
    /// Writes the catalog this hlb carries into a new directory: its platform is what
    /// the catalog repository's apps run over, which nothing else hands out.
    Export { dir: std::path::PathBuf },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// A new Ed25519 signing key, written encrypted under a passphrase; prints the
    /// public key installations are given.
    Generate {
        file: std::path::PathBuf,
        /// The passphrase on stdin's first line, for a script.
        #[arg(long)]
        passphrase_stdin: bool,
    },
}

#[derive(Subcommand)]
enum IndexCmd {
    /// The index of a catalog directory, built into an empty directory with every
    /// app version's files. The versions of `--previous` are kept, its counter risen.
    Build {
        catalog: std::path::PathBuf,
        out: std::path::PathBuf,
        #[arg(long)]
        source: String,
        /// The directory of the index published before this one.
        #[arg(long)]
        previous: Option<std::path::PathBuf>,
        /// The runs CI left, one `<app>.json` each, gathered into `quality-v1.json`
        /// over the previous index's.
        #[arg(long)]
        quality: Option<std::path::PathBuf>,
    },
    /// Sign a built index. Refused unless its counter rises above the published one's
    /// and its expiry is ahead, and unless every file is the one it names.
    Sign {
        dir: std::path::PathBuf,
        #[arg(long)]
        key: std::path::PathBuf,
        /// The index.json the source serves today.
        #[arg(long)]
        published: Option<std::path::PathBuf>,
        /// The source has published no index yet.
        #[arg(long)]
        first: bool,
        #[arg(long)]
        passphrase_stdin: bool,
    },
    /// Check an index directory against a source's public key.
    Verify {
        dir: std::path::PathBuf,
        #[arg(long)]
        source: String,
        /// The source's public key, 64 hexadecimal characters.
        #[arg(long)]
        key: String,
    },
}

#[derive(Subcommand)]
enum SourceCmd {
    /// The sources added, and what each holds.
    List,
    /// Read a directory of apps beside the official catalog, or a signed index served
    /// over HTTPS. Preview by default.
    Add {
        /// Lower-case letters, digits and dashes: what its apps' names start with.
        name: String,
        /// A directory, or the https:// address its index.json is served under.
        location: String,
        /// The public key an address's index is signed with: 64 hexadecimal characters.
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// Download the signed index of one source, or of every source served over HTTPS,
    /// and the files it names that moved.
    Fetch { name: Option<String> },
    /// Stop reading a source; the apps installed from it keep running.
    Remove {
        name: String,
        #[arg(long)]
        apply: bool,
    },
}

/// What undoing a migration loses, spelled out.
///
/// 🔴 "Data will be lost" helps nobody decide. The match is EXACT and not by keyword:
/// "0006_volumes_sqlite" only erases a column, while "0003_volumes" erases the whole
/// inventory. Confusing them would announce a loss that does not happen — or worse,
/// stay silent about one that does.
fn consequence_migration(name: &str) -> Vec<String> {
    let detail: &[&str] = match name {
        "0005_audit" => &[
            "the AUDIT LOG is erased (it is append-only, and this",
            "is the only path that erases it)",
        ],
        "0004_backup_runs" => &[
            "the backup history is erased — every app goes back to",
            "\"never backed up\" and becomes due immediately",
        ],
        "0003_volumes" => &[
            "the volume inventory is erased; the Docker data survives,",
            "but the backup no longer knows what to save",
        ],
        "0002_secrets" => &[
            "the encrypted secrets are erased, including those deposited",
            "by hand: DNS token, CrowdSec bouncer key",
        ],
        "0006_volumes_sqlite" => &[
            "the \"SQLite database\" flag on volumes is lost — those",
            "databases would go back to hot copies, therefore corrupt",
        ],
        "0001_initial" => &["ALL state: apps, plans, guides"],
        _ => &[],
    };

    let mut out = vec![name.to_string()];
    out.extend(detail.iter().map(|l| format!("      {l}")));
    out
}

/// Where releases live when `--from`/`HLB_RELEASE_URL` is not given.
///
/// GitHub serves a release asset at a predictable URL — no API call, no rate limit,
/// no JSON to parse — as long as the tag follows the `v<version>` convention used by
/// every tag this project cuts.
const GITHUB_RELEASES_REPO: &str = "Turi-Industries/Homelabus";

fn github_release_base(version: &hlb_selfupdate::Version) -> String {
    format!("https://github.com/{GITHUB_RELEASES_REPO}/releases/download/v{version}")
}

/// Downloads a binary and its manifest.
///
/// ⚠️ The manifest first: if it is missing, no point pulling several megabytes only to
/// discover afterwards that nothing can be verified.
async fn download_version(
    base_url: &str,
    version: &hlb_selfupdate::Version,
) -> Result<(Vec<u8>, hlb_selfupdate::ReleaseManifest), String> {
    let base = base_url.trim_end_matches('/');
    let target = format!("hlb-{version}-{}", std::env::consts::ARCH);

    let raw_manifest = fetch(&format!("{base}/{target}.manifest")).await?;
    let manifest = parse_manifest(&String::from_utf8_lossy(&raw_manifest))?;

    let binary = fetch(&format!("{base}/{target}")).await?;
    Ok((binary, manifest))
}

async fn fetch(url: &str) -> Result<Vec<u8>, String> {
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

/// Parses a release manifest.
///
/// Deliberately trivial format — `key=value` per line — so it can be produced by three
/// lines of shell in a release pipeline, and read by eye.
fn parse_manifest(text: &str) -> Result<hlb_selfupdate::ReleaseManifest, String> {
    let mut version = None;
    let mut sha256 = None;
    let mut signature = None;

    for l in text.lines() {
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        match k.trim() {
            "version" => version = hlb_selfupdate::Version::parse(v.trim()),
            "sha256" => sha256 = Some(v.trim().to_string()),
            "signature" => signature = Some(v.trim().to_string()),
            _ => {}
        }
    }

    Ok(hlb_selfupdate::ReleaseManifest {
        version: version.ok_or("manifest without a version")?,
        sha256: sha256.ok_or("manifest without a fingerprint")?,
        // A missing signature is NOT a parse error: it is an unsigned manifest, and it
        // is `verify` that must refuse it, with its own message.
        signature: signature.unwrap_or_default(),
    })
}

/// The migrations shipped with this binary, and whether they are reversible.
///
/// 🔴 Read from the migrations directory at compile time, through the state's own
/// migrator: a migration added without its `down` shows up here as irreversible, and
/// blocks the update. That is exactly the point — the `every_migration_can_be_undone`
/// test catches it earlier, this is the net.
fn known_migrations() -> Vec<(i64, hlb_selfupdate::Migration)> {
    State::shipped_migrations()
        .into_iter()
        .map(|m| {
            (
                m.version,
                hlb_selfupdate::Migration {
                    name: m.name,
                    reversible: m.reversible,
                },
            )
        })
        .collect()
}

/// The present instant, in seconds since the epoch.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Writes a PEM with restrictive permissions.
///
/// 🔴 A private key at 644 is readable by every user of the machine. TLS tools do not
/// complain about it — unlike `ssh`, which refuses — so nothing would signal the
/// problem. Created 0600 rather than chmodded after: written first, it sat at the
/// umask's mode in between.
fn write_pem(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    if path.extension().is_some_and(|e| e == "key" || e == "pem") {
        hlb_secrets::write_private_file(path, content.as_bytes(), true)
    } else {
        std::fs::write(path, content)
    }
}

/// Point-in-time restore.
///
/// No subcommand executes anything: PITR ends with a human decision on a production
/// database. The CLI prepares, displays and checks feasibility; it does not restore on
/// your behalf.
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

            // 🔴 The credentials come from `--postgres-admin`, the SAME source as
            // database provisioning. Asking for them separately would make two truths
            // diverge, and the backup would break the day one of them changed.
            let Some(url) = admin_url else {
                eprintln!("No PostgreSQL URL — use --postgres-admin.");
                eprintln!();
                eprintln!("  Expected form:");
                eprintln!("    postgres://user:password@host:5432/postgres");
                eprintln!();
                eprintln!("  🔴 The user must have the REPLICATION attribute: a base");
                eprintln!("     backup goes through the replication protocol, not");
                eprintln!("     through an ordinary SQL connection.");
                return Ok(ExitCode::FAILURE);
            };

            let Some(creds) = pitr::parse_pg_url(url) else {
                eprintln!("Unreadable PostgreSQL URL: \"{url}\"");
                eprintln!("Expected: postgres://user:password@host:5432/database");
                return Ok(ExitCode::FAILURE);
            };

            let (host, user, password) = (creds.host, creds.user, creds.password);
            let at = now();
            let name = pitr::basebackup::directory_name(at);

            if !apply {
                println!("Would produce a base backup:");
                println!("  destination : {dest}/{name}");
                println!(
                    "  server      : {user}@{host}:{} (network {network})",
                    creds.port
                );
                println!();
                println!("  It streams the WAL during the copy, or the result would be");
                println!("  inconsistent and PostgreSQL would refuse to start.");
                println!();
                println!("  ⚠️  Plan for the space: this is a COMPLETE copy of the data");
                println!("     directory, not an increment.");
                println!();
                println!("  Rerun with --apply.");
                return Ok(ExitCode::SUCCESS);
            }

            let target = pitr::basebackup::Target::new(dest, &host)
                .credentials(&user, &password)
                .network(network);

            print!("Base backup running… ");
            use std::io::Write as _;
            let _ = std::io::stdout().flush();

            match pitr::basebackup::run(&target, at).await {
                Ok(id) => {
                    // 🔴 Recording it is what makes the base VISIBLE to `pitr window`
                    // and `pitr plan`. Without it the backup exists on disk and the
                    // system keeps saying it has none.
                    state
                        .record_backup("postgres", "pg-basebackup", Some(&id), None)
                        .await?;
                    state
                        .audit("cli", ACTOR_ROLE, "pg-basebackup", &id, "ok", None)
                        .await?;
                    println!("✓ {id}");
                    println!();
                    println!("Recoverable window updated: hlb backup pitr window");
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    // The failure is recorded: `base_backups` excludes it, so the
                    // announced window does not include a base that does not exist.
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
            println!("# 🔴 BEFORE enabling: {dir} must exist, be writable by the");
            println!("#    container, and have room.");
            println!("#");
            println!("#    An archive_command that fails does not LOSE the journals:");
            println!("#    it keeps them. pg_wal then grows without limit until the");
            println!("#    disk is full, and PostgreSQL stops dead.");
            println!("#    Archiving to a broken destination is more dangerous than");
            println!("#    not archiving at all.");
            println!("#");
            println!("#    Then: a base backup is MANDATORY. WAL alone restores");
            println!("#    nothing.");
            println!("#      hlb backup pitr base --apply");
            println!("#");
            println!("# 🔴 AND pg_hba.conf, which postgresql.conf does NOT replace:");
            println!("#      host replication all all scram-sha-256");
            println!("#");
            println!("#    pg_basebackup goes through the REPLICATION protocol, which");
            println!("#    pg_hba treats as a separate database. A user who connects");
            println!("#    perfectly well with psql is refused here. The official");
            println!("#    postgres image only allows it from 127.0.0.1 — therefore");
            println!("#    never from another container.");
            Ok(ExitCode::SUCCESS)
        }

        PitrCmd::Window { dir } => {
            let state = State::open(state_path).await?;
            let bases = load_databases(&state).await?;

            if bases.is_empty() {
                println!("No base backup recorded.");
                println!();
                println!("🔴 Without one, the WAL journals restore NOTHING. The");
                println!("   recoverable window is therefore empty, even if archiving");
                println!("   is running.");
                println!();
                println!("   hlb backup pitr config    # the settings to apply");
                return Ok(ExitCode::SUCCESS);
            }

            println!(
                "{}:",
                hlb_api::plural(bases.len() as u64, "base backup", "base backups")
            );
            for b in &bases {
                println!("  {}  {}", pitr::iso8601(b.finished_at), b.id);
            }
            println!();

            // The upper bound is OBSERVED in the archive, not derived from the last
            // base: without an inventory the window would be underestimated, and
            // restores that are in fact possible would be refused.
            let (coverage, note) = match pitr::scan_archive(std::path::Path::new(dir)) {
                Ok(segs) => match pitr::wal_coverage(&segs) {
                    Some(c) => (
                        c,
                        format!(
                            "{} archived",
                            hlb_api::plural(segs.len() as u64, "WAL segment", "WAL segments")
                        ),
                    ),
                    None => (
                        bases.iter().map(|b| b.finished_at).max().unwrap_or(0),
                        format!("🔴 {dir} is empty — no journal archived"),
                    ),
                },
                Err(e) => (
                    bases.iter().map(|b| b.finished_at).max().unwrap_or(0),
                    format!("⚠️  unreadable archive ({e}) — bound limited to the last base"),
                ),
            };

            match pitr::recoverable_window(&bases, coverage) {
                Some(w) => {
                    println!("Recoverable window: {}", w.describe());
                    println!("  {note}");
                    println!();
                    println!(
                        "  WAL can be pruned before: {}",
                        pitr::iso8601(pitr::wal_prunable_before(&bases).unwrap_or(w.earliest))
                    );
                }
                None => {
                    println!("No recoverable window.");
                    println!("  {note}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        PitrCmd::Plan { target, dir } => {
            let Some(target) = pitr::parse_utc(target) else {
                eprintln!("Unreadable target: \"{target}\"");
                eprintln!("Expected, in UTC: \"2026-08-16 14:04:00\"");
                return Ok(ExitCode::FAILURE);
            };

            let state = State::open(state_path).await?;
            let bases = load_databases(&state).await?;

            // Same rule as for `window`: coverage is observed. A target beyond the last
            // archived segment must be refused, not accepted silently — it would hand
            // back a stale base without saying so.
            let coverage = pitr::scan_archive(std::path::Path::new(dir))
                .ok()
                .and_then(|s| pitr::wal_coverage(&s))
                .unwrap_or_else(|| bases.iter().map(|b| b.finished_at).max().unwrap_or(0));

            let archive = pitr::WalArchive::new(dir);
            match pitr::plan_recovery(&bases, coverage, target, &archive) {
                Ok(p) => {
                    println!("Restore to {}", pitr::iso8601(target));
                    println!("  {}", p.describe());
                    println!();
                    println!("Steps to follow:");
                    println!("  1. Stop PostgreSQL.");
                    println!("  2. Move the current data directory aside — do NOT delete");
                    println!("     it: it is the only net if the recovery fails.");
                    println!("  3. Restore base {} in its place.", p.base.id);
                    println!("  4. Write this into postgresql.auto.conf:");
                    println!();
                    for l in p.config.lines() {
                        println!("     {l}");
                    }
                    println!();
                    println!("  5. Create an EMPTY `recovery.signal` file in the data");
                    println!("     directory. Without it, PostgreSQL starts normally and");
                    println!("     ignores everything above.");
                    println!("  6. Start it and watch the server logs.");
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

/// The base backups of every app taken together.
///
/// PITR applies to the PostgreSQL instance, not to an app: every application database
/// shares the same WAL.
async fn load_databases(
    state: &State,
) -> Result<Vec<hlb_backup::pitr::BaseBackup>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    for (app, _) in state.installed_apps().await? {
        for (id, at) in state.base_backups(&app).await? {
            out.push(hlb_backup::pitr::BaseBackup {
                id,
                finished_at: at,
            });
        }
    }
    for (id, at) in state.base_backups("postgres").await? {
        out.push(hlb_backup::pitr::BaseBackup {
            id,
            finished_at: at,
        });
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

    let outcome = run();
    relay::close_all();
    match outcome {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            // The cause chain often carries the real diagnosis.
            let mut src = e.source();
            while let Some(s) = src {
                eprintln!("  ↳ {s}");
                src = s.source();
            }
            ExitCode::FAILURE
        }
    }
}

/// The provider an update's prior copy goes through: the app's first bulky destination for
/// its volumes and buckets and first critical one for its dumps, or `--backup-repo`. `None`
/// refuses the update.
async fn build_backup_provider(
    cli: &Cli,
    app: &str,
    state: &State,
    vault: &Vault,
) -> Result<Option<hlb_backup_run::PlacedProvider>, Box<dyn std::error::Error>> {
    let admins = hlb_backup_run::Admins {
        postgres: cli.postgres_admin.as_deref(),
        mariadb: cli.mariadb_admin.as_deref(),
    };
    // Garage does not resolve on a host: a relay, opened only for an app keeping a bucket.
    let s3_endpoint = if state.buckets_to_backup(app).await?.is_empty() {
        None
    } else {
        Some(relay::reach(hlb_objstore::S3_URL, &cli.platform_network))
    };
    Ok(hlb_backup_run::provider_for_update(
        state,
        vault,
        &cli.platform_network,
        admins,
        s3_endpoint.as_deref(),
        cli.backup_repo.as_deref(),
        app,
    )
    .await?)
}

/// `hlb update policy`: shows how far updates go alone, or sets it for an app or the house.
async fn update_policy(
    state: &State,
    app: Option<&str>,
    automatic: Option<&str>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let Some(automatic) = automatic else {
        let settings = state.update_automatic_settings().await?;
        let house = settings.iter().find(|(a, _)| a.is_empty()).map(|(_, a)| *a);
        match house {
            Some(a) => println!("the house: up to {} alone", a.as_str()),
            None => println!("the house: as each manifest says (patches, none on `pin`)"),
        }
        for (name, _) in state.installed_apps().await? {
            let manifest = state.app_manifest(&name).await?;
            let own = settings.iter().find(|(a, _)| *a == name).map(|(_, a)| *a);
            let (reach, whose) = match (own, house) {
                (Some(a), _) => (a, "set for it"),
                (None, Some(a)) => (a, "the house"),
                (None, None) => (manifest.spec.update.automatic(), "its manifest"),
            };
            println!("  {name:<16} {:<6} ({whose})", reach.as_str());
        }
        println!(
            "
A major move is always by hand, whatever is set."
        );
        return Ok(ExitCode::SUCCESS);
    };
    let value = match automatic {
        "manifest" => None,
        other => Some(
            hlb_types::Automatic::parse(other)
                .ok_or_else(|| format!("--automatic {other}: none, patch, minor, or manifest"))?,
        ),
    };
    if let Some(app) = app {
        if state.app_manifest(app).await.is_err() {
            return Err(format!("\"{app}\" is not installed").into());
        }
    }
    state.set_update_automatic(app, value).await?;
    let target = app.unwrap_or("house");
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "update-policy",
            target,
            "ok",
            Some(value.map_or("manifest", hlb_types::Automatic::as_str)),
        )
        .await?;
    match value {
        Some(a) => println!(
            "✓ {target}: up to {} alone, a major always by hand.",
            a.as_str()
        ),
        None => println!("✓ {target}: back to what is set above it, or the manifest."),
    }
    Ok(ExitCode::SUCCESS)
}

/// The declared destinations.
async fn load_destinations(
    state: &State,
) -> Result<Vec<hlb_backup::Destination>, Box<dyn std::error::Error>> {
    Ok(hlb_backup_run::load_destinations(state).await?)
}

/// The alias subcommands.
///
/// 🔴 The three axes are independent — lifetime, generated or chosen name, site hint.
/// Mixing them would produce an interface where "temporary" implied "random", which has
/// no reason to be: sometimes you want `promo@` for a week.
async fn manage_aliases(
    state: &State,
    domain: &str,
    mail: Option<&hlb_mail::Stalwart>,
    cmd: &AliasCmd,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    use hlb_users::{generation::Generated, Request};

    match cmd {
        AliasCmd::Add {
            name,
            mailbox,
            alias_name,
            for_site,
            for_duration,
            note,
            folder,
        } => {
            let c = load_account(state, name).await?;
            let p = state.role_of(name).await?;
            let now = now();

            let target = match mailbox {
                // One of THIS account's: another's would have counted the alias against
                // this one's quota while the mail went to someone else.
                Some(b) if c.mailboxes.iter().any(|m| &m.local == b) => b.clone(),
                Some(b) => {
                    eprintln!("🔴 {name} has no mailbox \"{b}\" — hlb user list");
                    return Ok(ExitCode::FAILURE);
                }
                None => match c.default_mailbox() {
                    Some(b) => b.local.clone(),
                    None => {
                        eprintln!("🔴 {name} has no mailbox: the alias would have nowhere to go.");
                        return Ok(ExitCode::FAILURE);
                    }
                },
            };

            // LIFETIME axis.
            let expires_at = match for_duration {
                Some(d) => {
                    let s = parse_duration(d)?;
                    p.authorized(&c.usage(now), Request::AliasTemporary { duration_s: s })
                        .map_err(|r| r.to_string())?;
                    Some(
                        now.checked_add(s)
                            .ok_or("that duration ends past any date")?,
                    )
                }
                None => {
                    p.authorized(&c.usage(now), Request::AliasPermanent)
                        .map_err(|r| r.to_string())?;
                    None
                }
            };

            // The NAME and HINT axes.
            let (local, hint) = match alias_name {
                // A chosen name: the user knows what they are doing, but they must
                // also know what they lose.
                Some(n) => {
                    let cleaned = hlb_users::generation::clean_hint(n);
                    if cleaned.is_empty() {
                        eprintln!("🔴 \"{n}\" yields no usable local part.");
                        return Ok(ExitCode::FAILURE);
                    }
                    (cleaned, None)
                }
                None => {
                    let mut entropy = [0u8; hlb_users::generation::SUFFIX_LEN];
                    hlb_secrets::fill_random(&mut entropy);
                    let g = Generated::for_site(for_site.as_deref().unwrap_or(""), &entropy);
                    let ind = (!g.hint.is_empty()).then(|| g.hint.clone());
                    (g.local, ind)
                }
            };

            let target_domain = c
                .mailboxes
                .iter()
                .find(|b| b.local == target)
                .map(|b| b.domain.clone())
                .unwrap_or_else(|| domain.to_string());

            // 🔴 On Stalwart FIRST, in the state AFTERWARDS. The reverse would record
            // an alias nothing receives: the user would hand it to a merchant, and the
            // mail would bounce back to the sender — so nobody on this side would know
            // the address does not work.
            match mail {
                Some(m) => {
                    m.add_alias(&format!("{target}@{target_domain}"), &local)
                        .await?;
                }
                None => {
                    eprintln!("🔴 Stalwart not configured: the alias is RECORDED but");
                    eprintln!("   will receive NOTHING. Rerun the command once");
                    eprintln!("   --stalwart-url is set.");
                }
            }

            state
                .add_alias(
                    name,
                    &target,
                    &local,
                    expires_at,
                    hint.as_deref(),
                    note.as_deref(),
                )
                .await?;

            // The sorting folder: the one asked for, or the default derived from the
            // hint.
            //
            // 🔴 The default is only a PROPOSAL. People file their mail by their own
            // logic, and a system that decides for them produces a tree they then have
            // to undo by hand.
            let chosen = match folder {
                Some(d) => Some(d.clone()),
                None => hlb_users::sieve::Rule::default_folder(hint.as_deref()),
            };
            if let Some(d) = &chosen {
                state.set_alias_folder(name, &local, Some(d)).await?;
            }
            state
                .audit("cli", ACTOR_ROLE, "alias-create", name, "ok", Some(&local))
                .await?;

            let dom = c
                .mailboxes
                .iter()
                .find(|b| b.local == target)
                .map(|b| b.domain.clone())
                .unwrap_or_else(|| domain.to_string());

            println!("✓ {local}@{dom}  →  {target}@{dom}");
            match expires_at {
                Some(e) => {
                    println!(
                        "  temporary, expires in {}",
                        fmt_age(std::time::Duration::from_secs((e - now).max(0) as u64))
                    );
                    // 🔴 The promise only holds if the purge runs. Say it here, at the
                    // moment you make it, rather than discovering it six months later
                    // on an address you believed was closed.
                    println!("  ⚠️ Expiry is NOT enforced by the mail server:");
                    println!("     \"hlb user alias purged --apply\" has to run.");
                }
                None => println!("  permanent"),
            }

            match &chosen {
                Some(d) if d.is_empty() => println!("  no sorting"),
                Some(d) => println!("  sorted into \"{d}\"  (change it: hlb user alias folder)"),
                None => println!("  no sorting (no hint from which to propose a folder)"),
            }

            if alias_name.is_some() {
                // ⚠️ A chosen name is guessable by construction. Acceptable for
                // `contact@`, bad for a per-merchant disposable: if one is `amazon@`,
                // then `paypal@` and `bank@` probably exist too.
                println!("  ⚠️ Chosen name: guessable. For a per-site alias, prefer");
                println!("     \"--for_site <site>\", which adds a random suffix.");
            }
            Ok(ExitCode::SUCCESS)
        }

        AliasCmd::List { name, problems } => {
            let c = load_account(state, name).await?;
            let now = now();
            let mut nothing = true;

            for b in &c.mailboxes {
                for a in &b.aliases {
                    let e = a.state(now);
                    if *problems && !e.breaks_the_promise() {
                        continue;
                    }
                    nothing = false;
                    println!("{}@{}  → {}", a.local, b.domain, b.local);
                    println!("    {}", e.describe());
                    if let Some(n) = &a.note {
                        println!("    note : {n}");
                    }
                }
            }
            if nothing {
                println!(
                    "{}",
                    if *problems {
                        "No broken promise."
                    } else {
                        "No alias."
                    }
                );
            }
            Ok(ExitCode::SUCCESS)
        }

        AliasCmd::Disable { name, alias } => {
            // 🔴 Deliberately NOT `deactivate_alias`: that flag records "actually
            // removed from Stalwart" and drives purge tracking (`to_purge`). A
            // disabled alias stays present — reusing that flag would silently exempt
            // it from the expired-but-still-active check the day it also expires.
            state
                .set_alias_folder(name, alias, Some("Disabled"))
                .await?;
            state
                .audit("cli", ACTOR_ROLE, "alias-disable", name, "ok", Some(alias))
                .await?;
            println!("{alias} routed to the \"Disabled\" folder.");
            // Not deleted: what keeps knocking at the door is still counted there,
            // so you learn how long a merchant kept selling the address.
            println!("  It stays on the server, out of the inbox, so you can see");
            println!("  who keeps writing to a closed address.");
            println!("⚠️ Apply the script for this to take effect: hlb user alias sieve {name}");
            Ok(ExitCode::SUCCESS)
        }

        AliasCmd::Folder {
            name,
            alias,
            folder,
        } => {
            // 🔴 An empty string is an EXPLICIT choice — "I do not want sorting" — not
            // the absence of a choice. Confusing them would re-impose a folder on every
            // regeneration, on someone who does not want one.
            state.set_alias_folder(name, alias, Some(folder)).await?;
            state
                .audit(
                    "cli",
                    ACTOR_ROLE,
                    "alias-folder",
                    name,
                    "ok",
                    Some(&format!("{alias} -> {folder}")),
                )
                .await?;
            if folder.is_empty() {
                println!("{alias}: no more sorting, mail stays in the inbox.");
            } else {
                println!("{alias} -> folder \"{folder}\"");
            }
            println!("⚠️ Apply the script for this to take effect: hlb user alias sieve {name}");
            Ok(ExitCode::SUCCESS)
        }

        AliasCmd::Sieve {
            name,
            mailbox,
            apply,
        } => {
            let c = load_account(state, name).await?;
            let target = match mailbox {
                Some(b) => b.clone(),
                None => match c.default_mailbox() {
                    Some(b) => b.local.clone(),
                    None => {
                        eprintln!("🔴 {name} has no mailbox.");
                        return Ok(ExitCode::FAILURE);
                    }
                },
            };

            let rules: Vec<hlb_users::sieve::Rule> = state
                .alias_rules(name, &target)
                .await?
                .into_iter()
                .filter_map(|(local, folder, hint)| {
                    // Explicit folder, otherwise the default from the hint. An empty
                    // string means "no sorting": no rule is produced.
                    let d = match folder {
                        Some(f) if f.is_empty() => return None,
                        Some(f) => f,
                        None => hlb_users::sieve::Rule::default_folder(hint.as_deref())?,
                    };
                    Some(hlb_users::sieve::Rule::new(local, d))
                })
                .collect();

            if !*apply {
                print!("{}", hlb_users::sieve::block(&rules));
                println!();
                println!("# ─────────────────────────────────────────────────────────");
                println!("# Preview: NOTHING was installed. Add --apply.");
                println!("# ⚠️ This block is inserted into the account script WITHOUT");
                println!("#    touching hand-written rules: they live outside the markers.");
                return Ok(ExitCode::SUCCESS);
            }

            let Some(m) = mail else {
                eprintln!("🔴 Stalwart not configured: the script was NOT installed.");
                eprintln!("   The rules exist in Homelabus and sort nothing.");
                return Ok(ExitCode::FAILURE);
            };

            let dom = c
                .mailboxes
                .iter()
                .find(|b| b.local == target)
                .map(|b| b.domain.clone())
                .unwrap_or_else(|| domain.to_string());

            // 🔴 The merge happens HERE, from the script actually present on Stalwart.
            // Doing it blind would overwrite rules written by hand since the last
            // generation.
            let final_ = m
                .apply_sieve(&format!("{target}@{dom}"), &|existing| {
                    hlb_users::sieve::merge(existing, &rules)
                })
                .await?;

            state
                .audit(
                    "cli",
                    ACTOR_ROLE,
                    "alias-sieve",
                    name,
                    "ok",
                    Some(&format!("{target}@{dom}")),
                )
                .await?;
            println!(
                "script installed on {target}@{dom} ({})",
                hlb_api::plural(rules.len() as u64, "rule", "rules")
            );
            println!(
                "  {} bytes in total, personal rules included.",
                final_.len()
            );
            println!();
            println!("  Read it back in Roundcube -> Settings -> Filters (managesieve plugin).");
            Ok(ExitCode::SUCCESS)
        }

        AliasCmd::Purged { alias, apply } => {
            let now = now();
            let mut to_purge = state.aliases_to_purge(now).await?;
            if let Some(target) = alias {
                to_purge.retain(|(_, _, l)| l == target);
            }

            if to_purge.is_empty() {
                println!("No expired alias to remove.");
                return Ok(ExitCode::SUCCESS);
            }

            println!(
                "{} expired and STILL ACTIVE:",
                hlb_api::plural(to_purge.len() as u64, "alias", "aliases")
            );
            for (u, b, l) in &to_purge {
                println!("  {l}  ({u} → {b})");
            }

            if !*apply {
                println!();
                println!("Preview: nothing was removed. Add --apply.");
                println!("⚠️ Until that is done, these addresses STILL receive.");
                return Ok(ExitCode::SUCCESS);
            }

            // ⚠️ The state is marked AFTER removal on Stalwart. The reverse would claim
            // the address closed while it still received — exactly the lie this module
            // exists to prevent.
            let Some(m) = mail else {
                eprintln!();
                eprintln!("🔴 Stalwart not configured: NOTHING was removed.");
                eprintln!("   Marking these aliases purged without removing them from");
                eprintln!("   the server would be the worst of both worlds: they would");
                eprintln!("   still receive, and nothing would signal it any more.");
                return Ok(ExitCode::FAILURE);
            };

            let mut removed = 0;
            for (u, b, l) in &to_purge {
                let dom = state
                    .mailboxes(u)
                    .await?
                    .into_iter()
                    .find(|(loc, ..)| loc == b)
                    .map(|(_, d, _)| d)
                    .unwrap_or_else(|| domain.to_string());

                // 🔴 The state is marked ONLY AFTER the actual removal. The reverse
                // would claim the address closed while it still received — exactly the
                // lie this whole module exists to prevent.
                match m.remove_alias(&format!("{b}@{dom}"), l).await {
                    Ok(_) => {
                        state.deactivate_alias(u, l).await?;
                        state
                            .audit("cli", ACTOR_ROLE, "alias-purge", u, "ok", Some(l))
                            .await?;
                        println!("{l} removed");
                        removed += 1;
                    }
                    Err(e) => {
                        // A failure does not block the others: every still-open address
                        // closed is a gain, even if the next one resists.
                        println!("{l}: {e}");
                    }
                }
            }

            if removed < to_purge.len() {
                println!();
                println!(
                    "⚠️ {} out of {} STILL receive.",
                    hlb_api::plural((to_purge.len() - removed) as u64, "address", "addresses"),
                    to_purge.len()
                );
                return Ok(ExitCode::FAILURE);
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Rebuilds an account from the state.
///
/// Delegates to `State::account`: the rebuild used to live here and the API had another
/// one — which is how a quota applied on the command line and not over HTTP.
async fn load_account(
    state: &State,
    name: &str,
) -> Result<hlb_users::Account, Box<dyn std::error::Error>> {
    Ok(state.account(name).await?)
}

/// Parses a duration: `30d`, `12h`, `90m`.
///
/// ⚠️ A bare number is refused rather than interpreted. "30" would mean thirty seconds
/// internally — the user meant thirty days, and their alias would have expired before
/// they gave it to anyone.
fn parse_duration(s: &str) -> Result<i64, String> {
    let s = s.trim();
    // The unit is the last CHARACTER: cut at a byte, `30é` panicked.
    let unit = s.chars().last().unwrap_or(' ');
    let n = &s[..s.len() - unit.len_utf8().min(s.len())];
    let unreadable = || format!("unreadable duration \"{s}\" — expected 30d, 12h or 90m");
    let n: i64 = n.parse().map_err(|_| unreadable())?;
    if n <= 0 {
        return Err(format!("duration \"{s}\": a duration is more than nothing"));
    }

    let seconds = match unit {
        'j' | 'd' => 86_400,
        'h' => 3_600,
        'm' => 60,
        _ => {
            return Err(format!(
                "duration \"{s}\" has no unit — write 30d, 12h or 90m. A bare number would \
                 be read as seconds, and the alias would expire before being used"
            ))
        }
    };
    n.checked_mul(seconds)
        .ok_or_else(|| format!("duration \"{s}\" is longer than anything can last"))
}

/// How `hlb backup run` ends: in failure when anything failed or was left uncovered —
/// a database nobody dumps is not backed up, whatever else went well.
fn exit_of_pass(sum: hlb_backup_run::Summary, not_covered: usize) -> ExitCode {
    if sum.failed == 0 && not_covered == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// An app's coverage: its state on EVERY routed destination, each as old as the
/// oldest of what it holds of the app.
///
/// 🔴 The controller's calculation, through the same adapter: this copy read a
/// destination's age across every kind, and the dump every pass records made a
/// destination whose volumes were backed up once read "✓ up to date".
async fn coverage_of(
    state: &State,
    app: &str,
    threshold_s: i64,
) -> Result<hlb_backup::Coverage, Box<dyn std::error::Error>> {
    Ok(hlb_backup::coverage_of(&hlb_backup_run::StateSource(state), app, threshold_s).await)
}

/// Readable age: "3 h", "2 d".
fn fmt_age(d: std::time::Duration) -> String {
    let s = d.as_secs();
    if s < 90 {
        format!("{s} s")
    } else if s < 5400 {
        format!("{} min", s / 60)
    } else if s < 172_800 {
        format!("{} h", s / 3600)
    } else {
        format!("{} d", s / 86400)
    }
}

/// Writes the desired state into the Git mirror.
async fn export_git(
    path: &std::path::Path,
    state: &State,
    message: &str,
) -> Result<hlb_gitops::ExportReport, Box<dyn std::error::Error>> {
    let mut apps = Vec::new();
    for (name, status) in state.installed_apps().await? {
        // It is the FROZEN manifest that gets archived, not the current catalog.
        let m = state.app_manifest(&name).await?;
        apps.push((name, status, m));
    }
    let mirror = hlb_gitops::GitMirror::open_or_init(path)?;
    Ok(mirror.export(&apps, message)?)
}

/// The CLI runs locally: whoever launches it already has access to the machine and to
/// the master key. RBAC protects the API, not the command line — but actions are
/// logged the same way.
const ACTOR_ROLE: hlb_types::Role = hlb_types::Role::Admin;

/// Percent-encodes a PromQL query destined for a query string.
///
/// ⚠️ A PromQL query contains `+`, `(`, `{`, `"` and spaces. Passed as is, it is
/// truncated at the first `&` or misread — and the rule then returns "no data", which
/// you would read as a metric problem when it is the URL that is broken.
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

/// Name of the secret holding Homelabus's private key.
const SECRET_SSH: &str = "homelabus-ssh-key";

/// The cluster SSH key, created on first use.
///
/// 🔴 It NEVER changes on its own. Regenerating it would cut access to every machine
/// already joined, which carry the old public key in their `authorized_keys` — and each
/// one would have to be visited by hand.
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
            "Homelabus SSH key for driving the nodes",
        )
        .await?;
    eprintln!("cluster SSH key generated (in the vault, never shown again)");
    Ok(kp)
}

// ── The mesh, applied ───────────────────────────────────────────────────────────

/// The topology lives in the vault like the rest. Public keys and addresses are not
/// secret, but keeping them with the PRIVATE keys avoids two sources of truth that would
/// diverge.
const MESH_TOPOLOGY: &str = "mesh-topology";

pub(crate) async fn load_mesh(
    state: &State,
    vault: &Vault,
) -> Result<hlb_mesh::MeshConfig, Box<dyn std::error::Error>> {
    Ok(match state.secret(MESH_TOPOLOGY).await? {
        Some(ct) => {
            let peers: Vec<hlb_mesh::Peer> = serde_json::from_str(&vault.decrypt(&ct)?)?;
            hlb_mesh::MeshConfig::from_peers([10, 42, 0], 51820, peers)
        }
        None => hlb_mesh::MeshConfig::default(),
    })
}

async fn save_mesh(
    state: &State,
    vault: &Vault,
    mesh: &hlb_mesh::MeshConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let peers: Vec<_> = mesh.peers().cloned().collect();
    let ct = vault.encrypt(&serde_json::to_string(&peers)?)?;
    match state.secret(MESH_TOPOLOGY).await? {
        Some(_) => state.rotate_secret(MESH_TOPOLOGY, &ct).await?,
        None => {
            state
                .store_secret_if_absent(MESH_TOPOLOGY, &ct, "mesh topology")
                .await?;
        }
    }
    Ok(())
}

/// Adds a node to the mesh — keys, address, topology — or returns it if already there.
///
/// The private key is stored BEFORE the topology: written the other way round, a
/// failure in between leaves a node in the mesh whose configuration nobody can produce.
async fn mesh_member(
    state: &State,
    vault: &Vault,
    mesh: &mut hlb_mesh::MeshConfig,
    node: &str,
    endpoint: Option<String>,
    ssh: Option<String>,
) -> Result<hlb_mesh::Peer, Box<dyn std::error::Error>> {
    if let Some(p) = mesh.get(node) {
        return Ok(p.clone());
    }
    let (mut peer, keys) = hlb_mesh::provision_node(mesh, node, endpoint)?;
    state
        .store_secret_if_absent(
            &format!("mesh-key-{node}"),
            &vault.encrypt(&keys.private)?,
            &format!("WireGuard private key of {node}"),
        )
        .await?;
    if ssh.is_some() {
        peer.ssh = ssh;
        let mut peers: Vec<_> = mesh.peers().cloned().collect();
        for p in peers.iter_mut().filter(|p| p.name == node) {
            p.ssh = peer.ssh.clone();
        }
        *mesh = hlb_mesh::MeshConfig::from_peers([10, 42, 0], mesh.port(), peers);
    }
    save_mesh(state, vault, mesh).await?;
    state
        .audit("cli", ACTOR_ROLE, "mesh-add", node, "ok", None)
        .await?;
    Ok(peer)
}

/// Puts `node`'s current configuration in place through `runner`, and brings the
/// interface up or synchronises it.
async fn apply_mesh(
    runner: &dyn hlb_bootstrap::Runner,
    state: &State,
    vault: &Vault,
    mesh: &hlb_mesh::MeshConfig,
    node: &str,
) -> Result<(), String> {
    let os = runner
        .read_file("/etc/os-release")
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let distro = hlb_bootstrap::Distro::parse(&os)
        .ok_or_else(|| "distribution not identified".to_string())?;
    let private = match state.secret(&format!("mesh-key-{node}")).await {
        Ok(Some(ct)) => vault.decrypt(&ct).map_err(|e| e.to_string())?,
        Ok(None) => return Err(format!("no mesh key for \"{node}\" in the vault")),
        Err(e) => return Err(e.to_string()),
    };
    let config = mesh
        .render_for(node, &private)
        .ok_or_else(|| format!("\"{node}\" is not in the mesh"))?;
    let steps = hlb_bootstrap::mesh::steps(
        hlb_bootstrap::provision::Init::for_family(distro.family),
        hlb_mesh::INTERFACE,
        hlb_mesh::CONFIG_PATH,
        &config,
        hlb_mesh::FIREWALL_PATH,
        &hlb_mesh::firewall_rules(hlb_mesh::INTERFACE),
    )?;
    let plan = hlb_bootstrap::provision::Provision {
        steps,
        notes: Vec::new(),
    };
    hlb_bootstrap::provision::execute(runner, &plan, |_| {})
        .await
        .map_err(|e| e.to_string())
}

/// `user@host:port`, each part optional, as stored on a peer.
fn ssh_target(host: &str, user: Option<&str>, port: Option<u16>) -> String {
    let mut s = String::new();
    if let Some(u) = user {
        s.push_str(u);
        s.push('@');
    }
    s.push_str(host);
    if let Some(p) = port {
        s.push_str(&format!(":{p}"));
    }
    s
}

pub(crate) fn parse_ssh_target(t: &str) -> (String, Option<String>, Option<u16>) {
    let (user, rest) = match t.split_once('@') {
        Some((u, r)) => (Some(u.to_string()), r),
        None => (None, t),
    };
    match rest.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), user, p.parse().ok()),
        _ => (rest.to_string(), user, None),
    }
}

/// This machine's hostname: the name it has in the mesh and in the Swarm.
async fn local_hostname() -> String {
    hostname_of(&hlb_bootstrap::LocalRunner)
        .await
        .unwrap_or_else(|| "localhost".into())
}

/// A machine's hostname, as the kernel holds it — the name Docker reports for the node.
///
/// Read from `/proc`, not by running `hostname`: that binary is a package of its own,
/// absent from a minimal Rocky Linux, and `node add` stopped there on a machine it had
/// just provisioned.
async fn hostname_of(runner: &dyn hlb_bootstrap::Runner) -> Option<String> {
    runner
        .read_file("/proc/sys/kernel/hostname")
        .await
        .ok()
        .flatten()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
}

/// Pushes the current configuration to every node of the mesh except `skip`, and says
/// how each one went.
///
/// 🔴 A node that was not reached keeps a configuration WITHOUT the newest peer: it
/// cannot talk to it, and Swarm traffic between the two goes nowhere. That is a failure
/// to show, with the command that retries it — never a warning lost in a scroll.
async fn sync_mesh(
    state: &State,
    vault: &Vault,
    mesh: &hlb_mesh::MeshConfig,
    skip: &[&str],
) -> Result<Vec<(String, Result<(), String>)>, Box<dyn std::error::Error>> {
    let local = local_hostname().await;
    let kp = cluster_ssh_key(state, vault).await?;
    let tmp = tempfile::tempdir()?;
    let key_path = write_temporary_key(tmp.path(), &kp.private)?;

    let mut out = Vec::new();
    for peer in mesh.peers() {
        if skip.contains(&peer.name.as_str()) {
            continue;
        }
        let result = if peer.name == local {
            apply_mesh(&hlb_bootstrap::LocalRunner, state, vault, mesh, &peer.name).await
        } else if let Some(target) = &peer.ssh {
            let (host, user, port) = parse_ssh_target(target);
            let runner = build_runner(Some(&host), user.as_deref(), port, key_path.to_str());
            apply_mesh(runner.as_ref(), state, vault, mesh, &peer.name).await
        } else {
            Err(format!(
                "no SSH address recorded: `hlb mesh show {}` on that machine, by hand",
                peer.name
            ))
        };
        out.push((peer.name.clone(), result));
    }
    Ok(out)
}

/// Writes the private key into a temporary file, for the duration of one connection.
///
/// ⚠️ `ssh` REFUSES a private key readable by anyone but its owner, with a message that
/// does not always make the cause clear. Hence the 0600 set explicitly rather than left
/// to the umask.
fn write_temporary_key(
    dir: &std::path::Path,
    private: &str,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("id_hlb");
    std::fs::write(&path, private)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

/// Does the machine wait for a reboot to run its newest kernel? `None`: could not tell.
async fn reboot_pending(r: &dyn hlb_bootstrap::Runner) -> Option<bool> {
    r.run(&[
        "sh".to_string(),
        "-c".into(),
        hlb_bootstrap::updates::REBOOT_PROBE.into(),
    ])
    .await
    .ok()
    .and_then(|o| hlb_bootstrap::updates::reboot_required(&o.stdout))
}

/// How to reach a node of the cluster: this machine, `--host`, or the SSH address the
/// mesh recorded — with the cluster's key, written under `dir`, which must outlive the
/// runner. `None` when no address is known.
pub(crate) async fn reach_node(
    state: &State,
    vault: &Vault,
    hostname: &str,
    host: Option<&str>,
    user: Option<&str>,
    port: Option<u16>,
    dir: &std::path::Path,
) -> Result<Option<Box<dyn hlb_bootstrap::Runner>>, Box<dyn std::error::Error>> {
    if hostname == local_hostname().await {
        return Ok(Some(Box::new(hlb_bootstrap::LocalRunner)));
    }
    let mesh = load_mesh(state, vault).await?;
    let kp = cluster_ssh_key(state, vault).await?;
    let key_path = write_temporary_key(dir, &kp.private)?;
    let recorded = mesh
        .get(hostname)
        .and_then(|p| p.ssh.clone())
        .map(|t| parse_ssh_target(&t));
    Ok(match (host, recorded) {
        (Some(h), _) => Some(build_runner(Some(h), user, port, key_path.to_str())),
        (None, Some((h, u, p))) => Some(build_runner(Some(&h), u.as_deref(), p, key_path.to_str())),
        (None, None) => None,
    })
}

/// Reads a node's protection level again and labels it with what was found.
async fn node_protection(
    cli: &Cli,
    node: &str,
    host: Option<&str>,
    user: Option<&str>,
    port: Option<u16>,
    apply: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let orch = SwarmOrchestrator::connect().await?;
    let Some(target) = orch
        .nodes()
        .await?
        .into_iter()
        .find(|n| n.hostname == node || n.id == node)
    else {
        eprintln!("🔴 no node \"{node}\" in the cluster — see `hlb cluster status`.");
        return Ok(ExitCode::FAILURE);
    };
    let tmp = tempfile::tempdir()?;
    let Some(runner) = reach_node(
        &state,
        &vault,
        &target.hostname,
        host,
        user,
        port,
        tmp.path(),
    )
    .await?
    else {
        eprintln!(
            "🔴 no SSH address recorded for {}: pass --host.",
            target.hostname
        );
        return Ok(ExitCode::FAILURE);
    };

    println!("Machine: {}\n", target.hostname);
    let signals = hlb_bootstrap::observe::protection(runner.as_ref()).await?;
    print_protection(&signals);
    let level = hlb_bootstrap::protection::assess(&signals).level;

    let was = target.protection.as_deref();
    if !apply {
        println!();
        match was {
            Some(w) if w == level.as_str() => {
                println!("Labelled {w} already — nothing would change.");
                return Ok(ExitCode::SUCCESS);
            }
            Some(w) => println!("Would label it {} (labelled {w}).", level.as_str()),
            None => println!("Would label it {}.", level.as_str()),
        }
        println!("\n  Re-run with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    orch.label_node(
        &target.id,
        hlb_orchestrator::cluster::LABEL_PROTECTION,
        level.as_str(),
    )
    .await?;
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "node-protection",
            &target.hostname,
            "ok",
            Some(level.as_str()),
        )
        .await?;
    println!(
        "\n✓ {} -> protection level {}",
        target.hostname,
        level.as_str()
    );
    Ok(ExitCode::SUCCESS)
}

/// `hlb config reboots`: the house's rule for rebooting its machines on their own.
async fn config_reboots(
    cli: &Cli,
    window: Option<&str>,
    never: bool,
    accept_downtime: bool,
    refuse_downtime: bool,
    apply: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let state = open_state(cli).await?;
    let mut policy = state.reboot_policy().await?;
    let describe = |p: &hlb_state::RebootPolicy| {
        let when = match &p.window {
            Some(w) => format!("in the window {w}"),
            None => "never on their own".to_string(),
        };
        let downtime = if p.accept_downtime {
            "a machine whose applications stop meanwhile included"
        } else {
            "a machine whose applications would stop is left to a person"
        };
        format!("Machines waiting for a reboot are rebooted {when}; {downtime}.")
    };
    if window.is_none() && !never && !accept_downtime && !refuse_downtime {
        println!("{}", describe(&policy));
        let zone = state.timezone().await?;
        println!(
            "  The window is read in {}.",
            zone.as_deref()
                .unwrap_or("UTC (hlb config timezone sets the house's)")
        );
        if let Some(r) = state.node_reboot().await? {
            let detail = r.detail.as_deref().unwrap_or("");
            match r.phase {
                hlb_state::RebootPhase::Stopped => {
                    println!("🔴 {} was not rebooted: {detail}", r.hostname);
                    println!(
                        "   No machine reboots on its own until hlb node upgrade {} succeeds on it.",
                        r.hostname
                    );
                }
                phase => println!("  {} is being rebooted ({phase:?}).", r.hostname),
            }
        }
        return Ok(ExitCode::SUCCESS);
    }
    if never {
        policy.window = None;
    } else if let Some(w) = window {
        if let Err(e) = hlb_updater::MaintenanceWindow::parse(w) {
            eprintln!("🔴 {e}.");
            return Ok(ExitCode::FAILURE);
        }
        policy.window = Some(w.trim().to_string());
    }
    if accept_downtime {
        policy.accept_downtime = true;
    } else if refuse_downtime {
        policy.accept_downtime = false;
    }
    if !apply {
        println!("Would set: {}", describe(&policy));
        println!("Rerun with --apply.");
        return Ok(ExitCode::SUCCESS);
    }
    state.set_reboot_policy(&policy).await?;
    let detail = describe(&policy);
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "config-reboots",
            "reboots",
            "ok",
            Some(&detail),
        )
        .await?;
    println!("✓ {detail}");
    Ok(ExitCode::SUCCESS)
}

/// What `hlb config ups` changes, each left out keeping what is set.
struct UpsChange<'a> {
    server: Option<&'a str>,
    ups: Option<&'a str>,
    after: Option<u32>,
    runtime: Option<u32>,
    steady: Option<u32>,
    off: bool,
}

impl UpsChange<'_> {
    fn is_empty(&self) -> bool {
        self.server.is_none()
            && self.ups.is_none()
            && self.after.is_none()
            && self.runtime.is_none()
            && self.steady.is_none()
            && !self.off
    }
}

/// `hlb config ups`: the UPS read, and when the apps stop for the power.
async fn config_ups(
    cli: &Cli,
    change: UpsChange<'_>,
    apply: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let state = open_state(cli).await?;
    let mut policy = state.ups_policy().await?;
    let describe = |p: &hlb_state::UpsPolicy| match &p.server {
        None => {
            "No UPS is read: a power cut stops nothing before the battery runs out.".to_string()
        }
        Some(server) => format!(
            "The UPS {} on {server} is read every 15 s. The apps stop after {} min on \
             battery, or at once under {} min of runtime or at low battery; they start \
             again once the mains have been back {} min.",
            p.ups,
            p.after_s / 60,
            p.runtime_s / 60,
            p.steady_s / 60
        ),
    };
    // What the server says now, from this machine: the daemon reads it from its own.
    let read_now = |p: &hlb_state::UpsPolicy| {
        let server = p.server.clone();
        let ups = p.ups.clone();
        async move {
            let server = server?;
            Some(match hlb_engine::power::read(&server, &ups).await {
                Ok(r) => {
                    let runtime = r
                        .runtime_s
                        .map(|s| format!(", {} min of runtime", s / 60))
                        .unwrap_or_default();
                    let charge = r.charge.map(|c| format!(", {c} %")).unwrap_or_default();
                    format!("  Read now: {}{runtime}{charge}.", r.status)
                }
                Err(e) => format!("⚠️ Not read from here: {e}."),
            })
        }
    };
    if change.is_empty() {
        println!("{}", describe(&policy));
        if let Some(line) = read_now(&policy).await {
            println!("{line}");
        }
        if let Some(u) = state.ups_state().await? {
            if let Some(e) = u.error.filter(|_| u.failed_at.is_some()) {
                println!("⚠️ The daemon's last reading failed: {e}.");
            }
        }
        if let Some(stop) = state.power_stop().await? {
            let services: usize = stop.waves.iter().map(Vec::len).sum();
            println!(
                "🔴 {services} services in {} waves are stopped for the power ({:?}): {}.",
                stop.waves.len(),
                stop.phase,
                stop.reason
            );
        }
        return Ok(ExitCode::SUCCESS);
    }
    if change.off {
        policy.server = None;
    }
    if let Some(server) = change.server {
        let server = server.trim();
        let bad = server.is_empty()
            || server.contains(char::is_whitespace)
            || server
                .rsplit_once(':')
                .is_some_and(|(_, port)| port.parse::<u16>().is_err());
        if bad {
            eprintln!("🔴 {server:?} is not a server: host or host:port.");
            return Ok(ExitCode::FAILURE);
        }
        policy.server = Some(server.to_string());
    }
    if let Some(ups) = change.ups {
        if ups.trim().is_empty() || ups.contains(char::is_whitespace) {
            eprintln!("🔴 {ups:?} is not a UPS name: `upsc -l` lists them.");
            return Ok(ExitCode::FAILURE);
        }
        policy.ups = ups.trim().to_string();
    }
    if let Some(s) = change.after {
        policy.after_s = i64::from(s);
    }
    if let Some(s) = change.runtime {
        policy.runtime_s = i64::from(s);
    }
    if let Some(s) = change.steady {
        policy.steady_s = i64::from(s);
    }
    let detail = describe(&policy);
    if !apply {
        println!("Would set: {detail}");
        if let Some(line) = read_now(&policy).await {
            println!("{line}");
        }
        println!("Rerun with --apply.");
        return Ok(ExitCode::SUCCESS);
    }
    state.set_ups_policy(&policy).await?;
    state
        .audit("cli", ACTOR_ROLE, "config-ups", "ups", "ok", Some(&detail))
        .await?;
    println!("✓ {detail}");
    if let Some(line) = read_now(&policy).await {
        println!("{line}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Upgrades one node whole, drained, and reboots it when its kernel asks for it.
///
/// The order is the point: drain, wait until its tasks have actually LEFT, upgrade,
/// reboot, wait until Swarm sees it ready again, and only then put it back in service.
/// Activating a node whose Docker is still restarting hands Swarm a node that accepts
/// tasks and cannot run them.
#[allow(clippy::too_many_arguments)]
async fn node_upgrade(
    cli: &Cli,
    node: &str,
    host: Option<&str>,
    user: Option<&str>,
    port: Option<u16>,
    accept_downtime: bool,
    apply: bool,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    use hlb_orchestrator::cluster::Maintenance;
    use std::time::Duration;

    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let orch = SwarmOrchestrator::connect().await?;

    let nodes = orch.nodes().await?;
    let Some(target) = nodes
        .iter()
        .find(|n| n.hostname == node || n.id == node)
        .cloned()
    else {
        eprintln!("🔴 no node \"{node}\" in the cluster — see `hlb cluster status`.");
        return Ok(ExitCode::FAILURE);
    };

    match hlb_orchestrator::cluster::maintenance(&nodes, node) {
        Maintenance::Go => {}
        Maintenance::Downtime(why) if accept_downtime => {
            println!("⚠️  {why} — accepted.");
        }
        Maintenance::Downtime(why) => {
            eprintln!("🔴 {why}.");
            eprintln!("   --accept-downtime to go ahead anyway.");
            return Ok(ExitCode::FAILURE);
        }
        Maintenance::Refused(why) => {
            eprintln!("🔴 {why}.");
            return Ok(ExitCode::FAILURE);
        }
    }
    // 🔴 The daemon's own reboot drains and reboots by itself: two hands on one node, or
    // on two, is the outage maintenance one at a time exists to avoid.
    if let Some(r) = state.node_reboot().await? {
        if r.phase != hlb_state::RebootPhase::Stopped {
            eprintln!(
                "🔴 Homelabus is rebooting {} on its own ({:?}): wait until it is back.",
                r.hostname, r.phase
            );
            return Ok(ExitCode::FAILURE);
        }
    }

    let is_local = target.hostname == local_hostname().await;
    let tmp = tempfile::tempdir()?;
    let Some(runner) = reach_node(
        &state,
        &vault,
        &target.hostname,
        host,
        user,
        port,
        tmp.path(),
    )
    .await?
    else {
        eprintln!(
            "🔴 no SSH address recorded for {}: pass --host.",
            target.hostname
        );
        return Ok(ExitCode::FAILURE);
    };

    let os = runner
        .read_file("/etc/os-release")
        .await?
        .unwrap_or_default();
    let Some(distro) = hlb_bootstrap::Distro::parse(&os) else {
        eprintln!("🔴 distribution not identified on {}.", target.hostname);
        return Ok(ExitCode::FAILURE);
    };
    let upgrade = hlb_bootstrap::updates::full_upgrade(&distro);
    let autoremove = hlb_bootstrap::updates::autoremove(&distro);

    if !apply {
        println!(
            "Would upgrade {} ({}), in order:",
            target.hostname, distro.pretty_name
        );
        println!("  1. drain it, and wait until its services run elsewhere");
        let mut i = 2;
        for c in &upgrade {
            println!("  {i}. {}", c.join(" "));
            i += 1;
        }
        match &autoremove {
            Some(c) => println!(
                "  {i}. {} — only what was installed as a dependency",
                c.join(" ")
            ),
            None => {
                println!("  {i}. (nothing removed: this distribution cannot tell a wanted package)")
            }
        }
        for s in hlb_bootstrap::host::steps(&distro).0 {
            i += 1;
            println!("  {i}. {}", s.describe());
        }
        println!("  then reboot it if its kernel asks for it, wait until Swarm sees it ready,");
        println!("  and put it back in service.");
        if is_local {
            println!();
            println!("  ⚠️  This is the machine Homelabus runs on: if it needs a reboot, you");
            println!("     reboot it, then run this again to put it back in service.");
        }
        println!("\n  Re-run with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    // -- 1. Drain -----------------------------------------------------------------
    if target.availability != "drain" {
        orch.set_node_availability(&target.id, "drain").await?;
    }
    println!("drained — waiting for its services to move…");
    let mut moved = false;
    for _ in 0..120 {
        // Global services (the agent) never leave a node: only replicated ones count.
        let left = orch
            .tasks(None)
            .await?
            .into_iter()
            .filter(|t| t.node_id.as_deref() == Some(target.id.as_str()))
            .filter(|t| t.slot.is_some() && t.is_alive())
            .count();
        if left == 0 {
            moved = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    if !moved {
        eprintln!(
            "🔴 services still running on {} after 10 min: not upgraded.",
            target.hostname
        );
        eprintln!("   It stays drained; `hlb ps` shows what did not move, and why.");
        return Ok(ExitCode::FAILURE);
    }
    println!("✓ nothing left running on it");

    // -- 2. Upgrade ---------------------------------------------------------------
    for c in upgrade.iter().chain(autoremove.iter()) {
        println!("  {}", c.join(" "));
        let o = runner.run(c).await?;
        if !o.ok() {
            let tail: Vec<&str> = o.stderr.trim().lines().rev().take(5).collect();
            eprintln!(
                "🔴 failed: {}",
                tail.into_iter().rev().collect::<Vec<_>>().join("\n   ")
            );
            eprintln!("   The node stays drained. Run this again once it is fixed.");
            return Ok(ExitCode::FAILURE);
        }
    }
    println!("✓ upgraded");

    // A node added before the host was hardened gets it here; on the others the files
    // are already identical and only the activation runs again.
    let (host, _) = hlb_bootstrap::host::steps(&distro);
    let host = hlb_bootstrap::provision::Provision {
        steps: host,
        notes: Vec::new(),
    };
    if let Err(e) =
        hlb_bootstrap::provision::execute(runner.as_ref(), &host, |s| println!("  {}", s.what))
            .await
    {
        eprintln!("🔴 {e}");
        eprintln!("   The node stays drained. Run this again once it is fixed.");
        return Ok(ExitCode::FAILURE);
    }

    // -- 3. Reboot, when the kernel asks for it ----------------------------------
    if reboot_pending(runner.as_ref()).await == Some(true) {
        if is_local {
            println!();
            println!("⚠️  This machine needs a reboot, and Homelabus runs on it. Reboot it,");
            println!("   then run the same command again: it stays drained until then.");
            return Ok(ExitCode::SUCCESS);
        }
        println!("rebooting…");
        if !reboot_and_wait(runner.as_ref()).await {
            eprintln!(
                "🔴 {} has not come back after 10 min. It stays drained.",
                target.hostname
            );
            return Ok(ExitCode::FAILURE);
        }
        println!("✓ back up");
        if reboot_pending(runner.as_ref()).await == Some(true) {
            println!("⚠️  it still runs an older kernel than the newest installed: check its");
            println!("   bootloader. It is put back in service regardless.");
        }
    }

    // -- 4. Back in service, once Swarm sees it ready --------------------------
    let mut ready = false;
    for _ in 0..60 {
        if orch
            .nodes()
            .await?
            .iter()
            .any(|n| n.id == target.id && n.is_ready())
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    if !ready {
        eprintln!(
            "🔴 Swarm does not see {} ready after 5 min. It stays drained.",
            target.hostname
        );
        return Ok(ExitCode::FAILURE);
    }
    orch.set_node_availability(&target.id, "active").await?;
    // A reboot the daemon gave up on this node blocked every other: a person took it over.
    let cleared = state.clear_node_reboot(&target.id).await?;
    state
        .audit(
            "cli",
            ACTOR_ROLE,
            "node-upgrade",
            &target.hostname,
            "ok",
            cleared.then_some("its stopped automatic reboot cleared"),
        )
        .await?;
    if cleared {
        println!("✓ machines reboot on their own again.");
    }
    println!("✓ {} upgraded and back in service.", target.hostname);
    println!("  Swarm does not move services back on its own: they return as they are");
    println!("  redeployed or rescheduled.");
    Ok(ExitCode::SUCCESS)
}

/// The cluster's certificate authority, from the vault; created when `create` and
/// absent (`hlb_engine::pki::cluster_ca`), and its creation audited.
async fn cluster_ca(
    state: &State,
    vault: &Vault,
    create: bool,
) -> Result<Option<hlb_agent::pki::CertPair>, Box<dyn std::error::Error>> {
    let had = state.secret(hlb_engine::pki::CA_SECRET).await?.is_some();
    let ca = hlb_engine::pki::cluster_ca(state, vault, create).await?;
    if !had && ca.is_some() {
        state
            .audit("cli", ACTOR_ROLE, "pki-init", "cluster-ca", "ok", None)
            .await?;
    }
    Ok(ca)
}

/// Deploys Homelabus's own services.
///
/// Both go on the platform overlay, where the controller resolves `tasks.<agent>` and
/// the agents answer it over mTLS — certificates issued here, delivered as Swarm
/// secrets, never written to a node's disk.
async fn fleet(cli: &Cli, cmd: &FleetCmd) -> Result<ExitCode, Box<dyn std::error::Error>> {
    use hlb_engine::pki::{self, Leaf};
    use hlb_orchestrator::{Orchestrator, ServiceSpec};

    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let mut orch = SwarmOrchestrator::connect().await?;

    if let FleetCmd::Agent { service, .. } = cmd {
        if !service.starts_with(hlb_orchestrator::SYSTEM_PREFIX) {
            eprintln!(
                "🔴 \"{service}\": Homelabus's own services are named {}…, or reconciliation \
                 takes them for an app nobody installed.",
                hlb_orchestrator::SYSTEM_PREFIX
            );
            return Ok(ExitCode::FAILURE);
        }
    }

    let (name, image, apply) = match cmd {
        FleetCmd::Agent {
            image,
            service,
            apply,
        } => (service.clone(), image.clone(), *apply),
        // The service holding the leaf: the daemon, which polls the agents. The web side
        // is deployed beside it.
        FleetCmd::Controller { image, apply, .. } => {
            (pki::DAEMON_SERVICE.to_string(), image.clone(), *apply)
        }
    };

    // A private registry: its credentials travel with the service, from the vault.
    let host = image_registry(&image);
    let registry_secret = host.map(|h| format!("registry-{h}"));
    if let Some(name) = &registry_secret {
        if let Some(ct) = state.secret(name).await? {
            let value = vault.decrypt(&ct)?;
            match value.split_once(':') {
                Some((user, token)) => {
                    orch = orch.with_registry_auth(host.unwrap_or_default(), user, token);
                }
                None => {
                    eprintln!("🔴 \"{name}\" is not in the form user:token.");
                    return Ok(ExitCode::FAILURE);
                }
            }
        }
    }

    // The controller shares this machine's state and vault with `hlb`: one SQLite file,
    // read and written by both. A copy would be two states that diverge.
    let state_path = std::fs::canonicalize(&cli.state)?;
    let key_path = std::fs::canonicalize(&cli.master_key)?;
    let local = local_hostname().await;
    let state_dir = state_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| "/".into());
    if matches!(cmd, FleetCmd::Controller { .. }) {
        if let Err(why) = web_can_mount(&state_dir, &state_path, &key_path) {
            eprintln!("🔴 {why}");
            let dir = "/var/lib/homelabus";
            eprintln!("   The web side mounts the state's directory read-only, and nothing else:");
            eprintln!("   give the state one of its own, the key outside it.");
            eprintln!("     hlb stop hlb-controller --apply    # if one runs");
            eprintln!("     install -d -m 0755 {dir}");
            eprintln!("     mv {} {dir}/", state_path.display());
            // Not a glob: `hlb.db*` takes every copy set aside beside it too.
            eprintln!(
                "     mv {0}-wal {0}-shm {dir}/    # when present: the -wal holds the last writes",
                state_path.display()
            );
            eprintln!("     export HLB_STATE={dir}/hlb.db");
            eprintln!("   then run this again.");
            return Ok(ExitCode::FAILURE);
        }
    }
    // Under the state's directory, which both services mount: `/run` is a tmpfs, and a
    // bind whose source a reboot removed stops Swarm from starting the task at all.
    let socket = state_dir.join("privd.sock");

    if !apply {
        match cmd {
            FleetCmd::Agent { .. } => {
                println!("Would deploy {name} on every node, present and future (global):");
                println!("  image    {image}");
                println!("  host     / mounted read-only at /host — disks, memory, network");
                println!("  mTLS     a certificate for tasks.{name}, from the cluster authority");
                println!("  network  {}", cli.platform_network);
            }
            FleetCmd::Controller { .. } => {
                println!("Would deploy the controller on {local}, as two services:");
                println!("  image    {image}");
                println!("  {name}  the daemon — what may write, decrypt or drive Docker");
                println!(
                    "    state    {} (read-write, shared with hlb)",
                    state_path.display()
                );
                println!("    vault    {} (read-only)", key_path.display());
                println!("    docker   /var/run/docker.sock — it drives the Swarm");
                println!("    mTLS     a client certificate for polling the agents");
                println!(
                    "    socket   {} — answers uid {WEB_UID} only",
                    socket.display()
                );
                println!("  {CONTROLLER}  the web side — the API and the interface");
                println!(
                    "    state    {} read-only, as uid {WEB_UID}, no capability",
                    state_dir.display()
                );
                println!("    no vault, no Docker socket, no volume");
                println!(
                    "    network  {} — reach it at http://{CONTROLLER}:8420",
                    cli.platform_network
                );
                match state.exposure().await? {
                    Some(e) => println!(
                        "  public   https://{}, through the ingress — sign-in registered in \
                         PocketID on --apply",
                        e.controller_host()
                    ),
                    None => {
                        println!("  public   nowhere: no domain configured (hlb config exposure)")
                    }
                }
                if !state.has_tokens().await? {
                    println!();
                    println!(
                        "  🔴 No access token yet: the controller refuses to start without one."
                    );
                    println!("     hlb token create admin --role admin --apply");
                }
            }
        }
        if let Some(name) = &registry_secret {
            if state.secret(name).await?.is_none() {
                println!();
                println!(
                    "  ⚠️  No credentials for {}: a private image cannot be pulled.",
                    host.unwrap_or_default()
                );
                println!(
                    "     printf '%s' '<user>:<token>' | hlb secret-set {name} --purpose registry"
                );
            }
        }
        println!("\n  Re-run with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    // The controller refuses to start with no access token: deployed anyway, it would
    // restart in a loop with the reason buried in its logs.
    if matches!(cmd, FleetCmd::Controller { .. }) && !state.has_tokens().await? {
        eprintln!("🔴 no access token: the controller would refuse to start.");
        eprintln!("   hlb token create admin --role admin --apply");
        return Ok(ExitCode::FAILURE);
    }

    // The interface's sign-in: its own client in PocketID, its callback on its public
    // name. The controller reads both from the vault when it starts.
    if matches!(cmd, FleetCmd::Controller { .. }) {
        controller_signin(cli, &state, &vault).await?;
    }

    let Some(ca) = cluster_ca(&state, &vault, true).await? else {
        eprintln!("🔴 the cluster authority could not be created.");
        return Ok(ExitCode::FAILURE);
    };
    orch.ensure_network(&cli.platform_network).await?;

    let leaf = match cmd {
        FleetCmd::Agent { service, .. } => Leaf::Agent {
            service: service.clone(),
        },
        FleetCmd::Controller { .. } => Leaf::Daemon,
    };
    let issued = leaf.issue(&ca).await?;
    let spec = match cmd {
        FleetCmd::Agent { service, .. } => ServiceSpec::new(service.clone(), image.clone())
            .global()
            .network(&cli.platform_network)
            .command([
                "hlb-agent",
                "--cert",
                pki::AGENT_CERT,
                "--key",
                pki::AGENT_KEY,
                "--ca",
                pki::CA_FILE,
                "--host-root",
                "/host",
            ])
            .bind("/", "/host", true),
        FleetCmd::Controller { agent_service, .. } => daemon_spec(
            cli,
            &image,
            agent_service,
            &local,
            &state_path,
            &key_path,
            &socket,
        ),
    };

    // The web side first: it waits for the daemon's socket, so the one-process
    // controller it replaces is gone before a second daemon starts beside it — two would
    // run every loop twice.
    if matches!(cmd, FleetCmd::Controller { .. }) {
        let mut web = ServiceSpec::new(CONTROLLER, image.clone())
            .network(&cli.platform_network)
            .constraint(format!("node.hostname=={local}"))
            .env(vec![
                (
                    "HLB_STATE".to_string(),
                    format!("{WEB_STATE}/{}", file_name(&state_path)),
                ),
                (
                    "HLB_PRIVD_SOCKET".to_string(),
                    format!("{WEB_STATE}/privd.sock"),
                ),
            ])
            // At a path of its own: mounted where it lies, its parents would be the
            // image's, and `/root` there is root's alone.
            .bind(state_dir.to_string_lossy().to_string(), WEB_STATE, true);
        // The default hardening holds: read-only root, every capability dropped.
        web.hardening.user = Some(format!("{WEB_UID}:{WEB_UID}"));
        let existed = orch.status(CONTROLLER).await.is_ok();
        orch.deploy(&web).await?;
        println!(
            "✓ {CONTROLLER} {} — uid {WEB_UID}, the state read-only",
            if existed {
                "updated, its capabilities dropped"
            } else {
                "deployed"
            }
        );
        state
            .audit(
                "cli",
                ACTOR_ROLE,
                "fleet-deploy",
                CONTROLLER,
                "ok",
                Some(&image),
            )
            .await?;
        // The leaf was the one-process controller's: its end, left recorded, would be
        // announced ending one day for a service holding no certificate.
        state.set_leaf_expiry(CONTROLLER, None).await?;
    }
    let spec = issued
        .files
        .iter()
        .fold(spec, |spec, (path, content)| spec.file(path, content));

    // The whole spec, updated in place under the same rolling policy as any app: moving
    // the image alone kept the mounts and the environment of the first deployment, so a
    // fix to either never reached a running controller.
    let existed = orch.status(&name).await.is_ok();
    orch.deploy(&spec).await?;
    // What renews it reads this: a Swarm secret cannot be read back.
    state
        .set_leaf_expiry(leaf.service(), Some(issued.not_after))
        .await?;
    if existed {
        println!("✓ {name} updated to {image}, its mounts and environment with it");
    } else {
        println!("✓ {name} deployed");
    }
    state
        .audit("cli", ACTOR_ROLE, "fleet-deploy", &name, "ok", Some(&image))
        .await?;
    // Its route exists once it runs: published now rather than with the next install.
    if matches!(cmd, FleetCmd::Controller { .. }) {
        if let Some(e) = state.exposure().await? {
            match hlb_engine::ingress::publish(&orch, &state, Some(&vault)).await {
                Ok(hlb_engine::ingress::Published::Done { .. }) => {
                    println!("✓ The interface answers at https://{}", e.controller_host());
                }
                Ok(_) => println!("  Its route waits for the ingress: hlb install caddy --apply"),
                Err(err) => eprintln!("⚠️  Its route could not be published: {err}"),
            }
        }
    }
    if matches!(cmd, FleetCmd::Agent { .. }) {
        println!("  Every node runs one; nodes added later get theirs on their own.");
    }
    Ok(ExitCode::SUCCESS)
}

/// The daemon's service: what may write the state, decrypt the vault and drive Docker.
fn daemon_spec(
    cli: &Cli,
    image: &str,
    agent_service: &str,
    local: &str,
    state_path: &std::path::Path,
    key_path: &std::path::Path,
    socket: &std::path::Path,
) -> hlb_orchestrator::ServiceSpec {
    use hlb_engine::pki;
    use hlb_orchestrator::ServiceSpec;
    let state_dir = state_path
        .parent()
        .map_or_else(|| "/".into(), |d| d.to_string_lossy().into_owned());
    let mut env = vec![
        (
            "HLB_STATE".to_string(),
            state_path.to_string_lossy().to_string(),
        ),
        (
            "HLB_MASTER_KEY".to_string(),
            key_path.to_string_lossy().to_string(),
        ),
        (
            "HLB_PLATFORM_NETWORK".to_string(),
            cli.platform_network.clone(),
        ),
        ("HLB_AGENT_SERVICE".to_string(), agent_service.to_string()),
        (
            "HLB_CONTROLLER_CERT".to_string(),
            pki::CONTROLLER_PEM.to_string(),
        ),
        ("HLB_CONTROLLER_CA".to_string(), pki::CA_FILE.to_string()),
        (
            "HLB_PRIVD_SOCKET".to_string(),
            socket.to_string_lossy().to_string(),
        ),
        ("HLB_WEB_UID".to_string(), WEB_UID.to_string()),
    ];
    if let Some(r) = &cli.backup_repo {
        env.push(("HLB_BACKUP_REPO".to_string(), r.clone()));
    }
    // Where volumes land: without these an install from the interface refused
    // every `tier: nfs` app, and placed `tier: local` ones off the pool.
    for (k, v) in [
        ("HLB_STORAGE_ROOT", &cli.storage_root),
        ("HLB_NFS_SERVER", &cli.nfs_server),
        ("HLB_NFS_EXPORT", &cli.nfs_export),
    ] {
        if let Some(v) = v {
            env.push((k.to_string(), v.clone()));
        }
    }
    let mut s = ServiceSpec::new(pki::DAEMON_SERVICE, image)
        .network(&cli.platform_network)
        // Its state and its vault live on THIS machine's disk.
        .constraint(format!("node.hostname=={local}"))
        // Two would run every loop twice, and the old one's shutdown would remove the
        // socket the new one bound.
        .alone()
        .command(["hlb-privd"])
        .env(env)
        .bind(state_dir.clone(), state_dir, false)
        .bind(
            key_path.to_string_lossy().to_string(),
            key_path.to_string_lossy().to_string(),
            true,
        )
        .bind("/var/run/docker.sock", "/var/run/docker.sock", false)
        // 🔴 The backup pass reads a SQLite volume where Docker keeps it, by
        // its host path: from inside the container every one failed on "No
        // such file". Read-write: `VACUUM INTO` on a WAL database writes its
        // shared-memory file beside it.
        .bind(DOCKER_VOLUMES, DOCKER_VOLUMES, false);
    // The pool's datasets, where `tier: local` volumes are bound.
    if let Some(root) = cli
        .storage_root
        .as_ref()
        .filter(|r| std::path::Path::new(r).is_dir())
    {
        s = s.bind(root.clone(), root.clone(), false);
    }
    // Writable root: backups stage snapshots in a temporary directory. No
    // privilege escalation.
    s.hardening.read_only_rootfs = false;
    // 🔴 An app's volume belongs to the app's user: PocketID's `keys/` is 0700,
    // and a SQLite file in WAL mode is read through a `-shm` its owner alone may
    // write. Root with every capability dropped could cross neither, and the
    // backup of that volume failed on "Permission denied". The socket mounted
    // above already makes the controller the node's root; these two take
    // nothing from a sandbox it was never in.
    s.hardening.cap_add = vec!["DAC_READ_SEARCH".into(), "DAC_OVERRIDE".into()];
    s
}

/// Where Docker keeps the named volumes on a node.
const DOCKER_VOLUMES: &str = "/var/lib/docker/volumes";

/// The web side's service: its routes, its scrape job and the docs keep the name.
const CONTROLLER: &str = hlb_engine::ingress::CONTROLLER_SERVICE;

/// The web side's uid. Not 65534: the agent runs as nobody on the same node, and the
/// daemon answers this uid alone.
const WEB_UID: u32 = 8420;

/// Where the web side sees the state's directory.
const WEB_STATE: &str = "/state";

fn file_name(p: &std::path::Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Whether the web side, as [`WEB_UID`], can read the state through its directory —
/// and only the state: the directory is mounted whole.
fn web_can_mount(
    dir: &std::path::Path,
    state: &std::path::Path,
    key: &std::path::Path,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &std::path::Path| {
        std::fs::metadata(p)
            .map(|m| m.permissions().mode())
            .map_err(|e| format!("{}: {e}", p.display()))
    };
    if key.parent() == Some(dir) {
        return Err(format!(
            "the vault's key lies in the state's directory {}: the web side would mount it",
            dir.display()
        ));
    }
    if dir.parent().is_none() {
        return Err("the state lies at the root: the web side would mount the whole disk".into());
    }
    // Neither owner nor group: the web side's uid is nobody's on the host.
    if mode(dir)? & 0o005 != 0o005 {
        return Err(format!(
            "{} is closed to other users: the web side could not read the state",
            dir.display()
        ));
    }
    if mode(state)? & 0o004 == 0 {
        return Err(format!(
            "{} is closed to other users: the web side could not read it",
            state.display()
        ));
    }
    // The socket's path, beside the state: a Unix socket's is 107 bytes at most.
    let socket = dir.join("privd.sock");
    if socket.as_os_str().len() > 107 {
        return Err(format!(
            "{} is too long a path for a socket",
            socket.display()
        ));
    }
    Ok(())
}

/// Registers the interface's sign-in client in PocketID, once.
///
/// Said rather than failed when it cannot be done yet: the controller then signs in by
/// token only, which is how a first installation starts anyway.
async fn controller_signin(
    cli: &Cli,
    state: &State,
    vault: &Vault,
) -> Result<(), Box<dyn std::error::Error>> {
    use hlb_engine::access::{CONTROLLER_OIDC_CLIENT, CONTROLLER_OIDC_ID, CONTROLLER_OIDC_SECRET};
    let Some(e) = state.exposure().await? else {
        println!("  sign-in  tokens only — no domain configured (hlb config exposure)");
        return Ok(());
    };
    let (Some(_), Some(url), Some(key)) = (
        state.app_domain("pocket-id").await?,
        &cli.pocketid_url,
        &cli.pocketid_key,
    ) else {
        println!("  sign-in  tokens only — PocketID is not installed, or its API key is not");
        println!("           in the vault (generated by hlb install pocket-id)");
        return Ok(());
    };
    let callback = format!("https://{}/auth/return_to", e.controller_host());
    // And where a passkey confirming a destruction comes back.
    let confirmed = format!(
        "https://{}{}",
        e.controller_host(),
        hlb_api::intent::CALLBACK
    );
    let pid = hlb_identity::PocketId::new(relay::reach(url, &cli.platform_network), key);
    let creds = pid
        .ensure(CONTROLLER_OIDC_CLIENT, &[callback.clone(), confirmed], true)
        .await?;
    // A secret PocketID just made replaces the vault's, and the id follows a client
    // re-created — the executor's own rule for every app's client.
    match hlb_engine::keep_oidc_credentials(
        state,
        vault,
        CONTROLLER_OIDC_CLIENT,
        &creds,
        CONTROLLER_OIDC_SECRET,
        CONTROLLER_OIDC_ID,
    )
    .await
    {
        Ok(()) => {}
        // 🔴 PocketID never hands a secret back: an existing client whose secret the
        // vault lost cannot sign anyone in, and only deleting it gets a new one.
        Err(hlb_engine::Error::MissingSecret(_)) => {
            eprintln!(
                "⚠️  PocketID has a \"{CONTROLLER_OIDC_CLIENT}\" client whose secret is not in \
                 the vault: delete it in PocketID and run this again"
            );
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }
    println!("  sign-in  PocketID, returning to {callback}");
    Ok(())
}

/// The registry host an image names, `None` for Docker Hub.
fn image_registry(image: &str) -> Option<&str> {
    let (first, rest) = image.split_once('/')?;
    (!rest.is_empty() && (first.contains('.') || first.contains(':') || first == "localhost"))
        .then_some(first)
}

/// What `hlb cluster init` was asked.
struct ClusterInit<'a> {
    advertise_addr: Option<&'a str>,
    endpoint: Option<&'a str>,
    no_mesh: bool,
    failure_domain: Option<&'a str>,
    storage_node: bool,
    apply: bool,
}

/// Turns this machine into the cluster's first node.
///
/// The same order as `hlb node add`, for the same reasons: the machine is provisioned
/// before anything depends on Docker, the mesh exists before Swarm is told to listen on
/// it, and the labels go on last, once the node is there to carry them.
async fn cluster_init(
    cli: &Cli,
    args: ClusterInit<'_>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let local = hlb_bootstrap::LocalRunner;
    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;
    let name = local_hostname().await;

    // -- 1. Prechecks ------------------------------------------------------------
    println!("Machine: {name} (this one)\n");
    let obs = hlb_bootstrap::observe(&local).await?;
    let report = hlb_bootstrap::preflight::run(&obs);
    for c in &report.checks {
        println!("  {}", c.describe());
    }
    let protection = hlb_bootstrap::observe::protection(&local).await?;
    println!();
    print_protection(&protection);
    if args.apply && !report.can_proceed() {
        eprintln!("\n🔴 fix the blocking points above first — nothing was changed.");
        return Ok(ExitCode::FAILURE);
    }
    let Some(distro) = report.distro.clone() else {
        eprintln!("\n🔴 distribution not identified: cannot plan.");
        return Ok(ExitCode::FAILURE);
    };

    // -- 2. Dependencies, Docker, unattended updates ----------------------------
    println!();
    if !provision_machine(&local, &distro, args.storage_node, args.apply, false).await? {
        return Ok(ExitCode::FAILURE);
    }
    // Read again for the label: provisioning brings a TPM's libraries, without which a
    // node that reaches B reads C.
    let protection = hlb_bootstrap::observe::protection(&local).await?;

    let mut mesh = load_mesh(&state, &vault).await?;
    let tier = obs
        .total_memory_mb
        .map(hlb_orchestrator::cluster::tier_for_memory);

    if !args.apply {
        println!();
        match args.endpoint {
            Some(e) => {
                println!(
                    "Would create the WireGuard mesh, with {name} reachable at {e}:{},",
                    mesh.port()
                );
                println!("  close Swarm's ports outside it, and initialise the Swarm on the");
                println!(
                    "  mesh address ({}).",
                    mesh.get(&name)
                        .map(|p| p.mesh_ip.to_string())
                        .unwrap_or_else(|| "the first free one".into())
                );
            }
            None => println!(
                "Would initialise the Swarm on {} — no mesh.",
                args.advertise_addr.unwrap_or_default()
            ),
        }
        println!(
            "  The ingress network is recreated at MTU {} before anything uses it.",
            hlb_orchestrator::OVERLAY_MTU
        );
        match tier {
            Some(t) => println!("  tier: {t}, from {} MB", obs.total_memory_mb.unwrap_or(0)),
            None => println!("  tier: ⚠️  undeterminable — set it by hand afterwards"),
        }
        println!("\n  Re-run with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    // -- 3. The mesh -------------------------------------------------------------
    let advertise = match args.endpoint {
        Some(e) if !args.no_mesh => {
            let me =
                mesh_member(&state, &vault, &mut mesh, &name, Some(e.to_string()), None).await?;
            if let Err(e) = apply_mesh(&local, &state, &vault, &mesh, &name).await {
                eprintln!("🔴 mesh not brought up: {e}");
                return Ok(ExitCode::FAILURE);
            }
            println!(
                "✓ mesh up at {} — Swarm's ports closed outside it",
                me.mesh_ip
            );
            Some(me.mesh_ip.to_string())
        }
        _ => args.advertise_addr.map(str::to_string),
    };
    // clap requires `--endpoint`, or `--no-mesh` with `--advertise-addr`: an address
    // is always there, and Docker is never left to pick one.
    let Some(advertise) = advertise else {
        eprintln!("🔴 no address to advertise: --endpoint, or --no-mesh --advertise-addr.");
        return Ok(ExitCode::FAILURE);
    };

    // -- 4. The Swarm ------------------------------------------------------------
    // Connected only now: Docker was installed a moment ago, by step 2.
    let orch = SwarmOrchestrator::connect().await?;
    let id = orch.cluster_init(&advertise).await?;
    println!("✓ Swarm active ({})", &id[..12.min(id.len())]);

    // -- 5. Labels ---------------------------------------------------------------
    // 🔴 A node with no tier receives no service: the placement constraints match
    // nothing, and the first install times out without saying why.
    let me = orch.nodes().await?.into_iter().find(|n| n.hostname == name);
    match (&me, tier) {
        (Some(n), Some(t)) => {
            orch.label_node(&n.id, "tier", t).await?;
            println!("✓ tier={t}");
        }
        _ => {
            println!("🔴 tier not set — this node receives no service until it has one:");
            println!("     hlb node tier {name} --set heavy --apply");
        }
    }
    if let (Some(n), Some(d)) = (&me, args.failure_domain) {
        orch.label_node(&n.id, hlb_orchestrator::cluster::LABEL_FAILURE_DOMAIN, d)
            .await?;
        println!("✓ failure domain {d}");
    }
    if let Some(n) = &me {
        let level = hlb_bootstrap::protection::assess(&protection).level;
        orch.label_node(
            &n.id,
            hlb_orchestrator::cluster::LABEL_PROTECTION,
            level.as_str(),
        )
        .await?;
        println!("✓ protection level {}", level.as_str());
    }
    if let (Some(n), true) = (&me, args.storage_node) {
        orch.label_node(&n.id, hlb_orchestrator::cluster::LABEL_STORAGE, "true")
            .await?;
        println!("✓ storage node");
    }

    state
        .audit("cli", ACTOR_ROLE, "cluster-init", "swarm", "ok", None)
        .await?;
    println!();
    println!("Next:");
    println!("  hlb cluster autolock --apply     # the Raft keys, encrypted at rest");
    println!("  hlb node add <host> --apply      # the other machines");
    Ok(ExitCode::SUCCESS)
}

/// What `hlb node add` was asked.
struct NodeAdd<'a> {
    host: &'a str,
    user: Option<&'a str>,
    port: Option<u16>,
    identity: Option<&'a str>,
    role: Option<&'a str>,
    advertise_addr: Option<&'a str>,
    /// `None`: behind NAT.
    endpoint: Option<&'a str>,
    failure_domain: Option<&'a str>,
    storage_node: bool,
    apply: bool,
}

/// Joins a machine to the cluster, end to end.
///
/// The order of the steps is not cosmetic:
///
/// 1. **Prechecks first**, read-only. Installing a key on a machine that can never host
///    a node leaves a trace to clean up for nothing.
/// 2. **The key next**: from then on Homelabus has its own access and no longer depends
///    on the personal key used for the first contact.
/// 3. **Dependencies**, then **join**, then **tier**.
///
/// 🔴 The tier LAST, and never before the node is in the cluster: a label set on an
/// absent node has nowhere to go, and a node with no tier receives no service (the
/// placement constraints match nothing) — which shows up as `wait_healthy` timing out
/// with no explanation.
async fn node_add(cli: &Cli, args: NodeAdd<'_>) -> Result<ExitCode, Box<dyn std::error::Error>> {
    use hlb_bootstrap::access;
    let NodeAdd {
        host,
        user,
        port,
        identity,
        role,
        advertise_addr,
        endpoint,
        failure_domain,
        storage_node,
        apply,
    } = args;

    let state = open_state(cli).await?;
    let vault = open_vault(cli)?;

    // -- 1. Prechecks, read-only ----------------------------------------------
    let first = build_runner(Some(host), user, port, identity);
    println!("Machine : {}\n", first.label());

    let obs = hlb_bootstrap::observe(first.as_ref()).await?;
    let report = hlb_bootstrap::preflight::run(&obs);
    for c in &report.checks {
        println!("  {}", c.describe());
    }
    println!();
    let protection = hlb_bootstrap::observe::protection(first.as_ref()).await?;
    print_protection(&protection);
    println!();

    if !report.can_proceed() {
        eprintln!(
            "🔴 {} — nothing was installed on this machine.",
            hlb_api::plural(
                report.blocking().len() as u64,
                "blocking point",
                "blocking points"
            )
        );
        return Ok(ExitCode::FAILURE);
    }

    // The recommended role depends on the cluster's current size.
    let orch = SwarmOrchestrator::connect().await.ok();
    let nodes = match &orch {
        Some(o) => o.nodes().await.unwrap_or_default(),
        None => Vec::new(),
    };
    let profile = hlb_orchestrator::ClusterProfile::for_node_count(nodes.len() + 1);
    let managers: Vec<Option<hlb_bootstrap::protection::Level>> = nodes
        .iter()
        .filter(|n| n.role == hlb_orchestrator::NodeRole::Manager)
        .map(|n| {
            n.protection
                .as_deref()
                .and_then(hlb_bootstrap::protection::Level::parse)
        })
        .collect();
    let level = hlb_bootstrap::protection::assess(&protection).level;
    let role_final = match role {
        Some(r) => r.to_string(),
        None => match hlb_bootstrap::protection::advise_role(&managers, level) {
            hlb_bootstrap::protection::RoleAdvice::Manager => "manager".to_string(),
            hlb_bootstrap::protection::RoleAdvice::Worker => "worker".to_string(),
            hlb_bootstrap::protection::RoleAdvice::Ask(why) => {
                eprintln!("🔴 No role derived — nothing was touched: {why}.");
                return Ok(ExitCode::FAILURE);
            }
        },
    };
    if role_final == "manager" {
        if let Some(w) = hlb_bootstrap::protection::manager_warning(&managers, level) {
            println!("⚠️  {w}\n");
        }
    }

    let tier_final = obs
        .total_memory_mb
        .map(hlb_orchestrator::cluster::tier_for_memory)
        .map(|t| t.to_string());

    // 🔴 A manager joined unsealed into a locked cluster runs fine until its first
    // restart, and then stays locked: refused before anything is touched.
    let unlock = match (&orch, role_final == "manager") {
        (Some(o), true) => seal::for_new_manager(o, &state, &vault).await?,
        _ => seal::NewManager::Unlocked,
    };
    if let seal::NewManager::Refused(why) = &unlock {
        eprintln!("🔴 Not joined as a manager: {why}.");
        return Ok(ExitCode::FAILURE);
    }

    // 🔴 An address another peer holds would get that peer's tunnel pushed over this
    // machine's own, at every push: refused before anything is touched.
    let recorded = load_mesh(&state, &vault).await?;
    let joining = hostname_of(first.as_ref()).await.unwrap_or_default();
    for address in [Some(host), endpoint].into_iter().flatten() {
        if let Some(p) = recorded.held_by(address, &joining) {
            eprintln!(
                "🔴 The mesh records {} at {address}: a machine gone, or this one under",
                p.name
            );
            eprintln!("   another name. Nothing was touched. If it is gone, take it out first:");
            eprintln!("     hlb mesh remove {} --apply", p.name);
            return Ok(ExitCode::FAILURE);
        }
    }

    if !apply {
        println!("Would join this machine to the cluster:");
        println!(
            "  role    : {role_final}{}",
            if role.is_some() {
                " (imposed)"
            } else {
                " (derived)"
            }
        );
        match &tier_final {
            Some(t) => println!(
                "  tier    : {t} (derived from {} MB)",
                obs.total_memory_mb.unwrap_or(0)
            ),
            None => println!("  tier    : ⚠️  undeterminable — set it by hand"),
        }
        println!(
            "  profile : {} at {}",
            profile.as_str(),
            hlb_api::plural((nodes.len() + 1) as u64, "node", "nodes")
        );
        let mesh = load_mesh(&state, &vault).await?;
        if mesh.get(&local_hostname().await).is_some() {
            println!();
            match endpoint {
                Some(e) => println!("  mesh    : joins it, reachable at {e}:{}", mesh.port()),
                None => println!("  mesh    : joins it from behind NAT, opening its own tunnels"),
            }
            println!("            every other node is told about it, and the tunnel is");
            println!("            verified before Swarm is joined through it.");
        } else {
            println!();
            println!("  ⚠️  This cluster has no mesh: Swarm's ports stay open on the network");
            println!("     the nodes share.");
            if advertise_addr.is_none() {
                println!("  ⚠️  Without --advertise-addr, Docker picks an interface. On a");
                println!("     multi-homed machine, the other nodes would try to reach an");
                println!("     unreachable IP.");
            }
        }
        if let seal::NewManager::Seal(_) = &unlock {
            println!();
            println!("  autolock: on — Swarm's unlock key is sealed to it once joined, so it");
            println!("            restarts alone.");
        }
        if storage_node {
            println!();
            println!("  storage: ZFS and the NFS server are added to the dependencies.");
            println!("           The pool itself is NOT touched — see `hlb storage`.");
        }
        if let Some(distro) = &report.distro {
            println!();
            if !provision_machine(first.as_ref(), distro, storage_node, false, false).await? {
                return Ok(ExitCode::FAILURE);
            }
        }
        println!();
        println!("  Steps: prechecks done, SSH key, dependencies, mesh, join, labels.");
        println!("  Rerun with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    // -- 2. Homelabus's key ----------------------------------------------------
    let kp = cluster_ssh_key(&state, &vault).await?;
    let key = access::ManagedKey::new(&kp.public, "hlb");

    // A concrete runner: the trait object does not satisfy the `Sized` bounds.
    let ssh_first = ssh_runner(host, user, port, identity);
    let before = access::read_authorized_keys(&ssh_first, "~").await?;
    let (after, ch) = access::grant(&before, &key);

    if ch.is_noop() {
        println!(
            "SSH key already in place ({} kept)",
            hlb_api::plural(ch.kept as u64, "other key", "other keys")
        );
    } else {
        access::write_authorized_keys(&ssh_first, "~", &after, &before).await?;
        println!(
            "SSH key installed ({} added, {} replaced, {} kept)",
            ch.added, ch.removed, ch.kept
        );
        state
            .audit("cli", ACTOR_ROLE, "access-grant", host, "ok", None)
            .await?;
    }

    // From here on we go through OUR key: that is what proves it works, now, rather
    // than discovering it at the next restart.
    let tmp = tempfile::tempdir()?;
    let key_path = write_temporary_key(tmp.path(), &kp.private)?;
    let ours = build_runner(Some(host), user, port, key_path.to_str());

    match ours.run(&["true".to_string()]).await {
        Ok(o) if o.ok() => println!("access through Homelabus's key verified"),
        _ => {
            eprintln!("🔴 The key was installed but does NOT allow signing in.");
            eprintln!("   Most frequent cause: sshd ignores authorized_keys when ~/.ssh");
            eprintln!("   or the file are group-readable — without saying so.");
            eprintln!("   Check: ls -ld ~/.ssh ~/.ssh/authorized_keys");
            return Ok(ExitCode::FAILURE);
        }
    }

    // -- 3. Dependencies, Docker, unattended updates --------------------------
    let Some(distro) = report.distro else {
        eprintln!("🔴 unidentified distribution: cannot install the dependencies.");
        return Ok(ExitCode::FAILURE);
    };
    // Not in the cluster yet, so nothing of ours runs on it: a reboot costs nothing.
    if !provision_machine(ours.as_ref(), &distro, storage_node, true, true).await? {
        return Ok(ExitCode::FAILURE);
    }
    // Read again for the label: provisioning brings a TPM's libraries, without which a
    // node that reaches B reads C.
    let protection = hlb_bootstrap::observe::protection(ours.as_ref()).await?;

    let Some(orch) = orch else {
        eprintln!("🔴 Swarm unreachable locally: cannot obtain a token.");
        eprintln!("   The machine is ready, only the join is missing.");
        return Ok(ExitCode::FAILURE);
    };
    let name = hostname_of(ours.as_ref()).await.unwrap_or_default();
    if name.is_empty() {
        eprintln!("🔴 the machine's hostname could not be read: it names the node.");
        return Ok(ExitCode::FAILURE);
    }

    // -- 4. The mesh -------------------------------------------------------------
    // Joined over the mesh when the cluster was created on one: Swarm then talks to
    // this node on its tunnel address, and the firewall closes its ports elsewhere.
    let mut mesh = load_mesh(&state, &vault).await?;
    let local = local_hostname().await;
    let advertise: Option<String> = match mesh.get(&local).cloned() {
        Some(manager) => {
            if advertise_addr.is_some() {
                eprintln!("🔴 --advertise-addr with a mesh: the node advertises its mesh");
                eprintln!("   address, or Swarm would talk to it outside the tunnel.");
                return Ok(ExitCode::FAILURE);
            }
            let peer = mesh_member(
                &state,
                &vault,
                &mut mesh,
                &name,
                endpoint.map(str::to_string),
                Some(ssh_target(host, user, port)),
            )
            .await?;
            if let Err(e) = apply_mesh(ours.as_ref(), &state, &vault, &mesh, &name).await {
                eprintln!("🔴 mesh not brought up on {name}: {e}");
                return Ok(ExitCode::FAILURE);
            }
            println!("mesh up on {name} at {}", peer.mesh_ip);

            // Every other node must learn the new peer: the manager first of all, or
            // the tunnel the join goes through does not exist on its end.
            let mut stale = Vec::new();
            for (node, r) in sync_mesh(&state, &vault, &mesh, &[name.as_str()]).await? {
                match r {
                    Ok(()) => println!("  ✓ {node} knows {name}"),
                    Err(e) => {
                        eprintln!("  🔴 {node} not updated: {e}");
                        stale.push(node);
                    }
                }
            }
            if stale.contains(&local) {
                eprintln!("🔴 this machine does not know {name} yet: the join cannot go");
                eprintln!("   through the tunnel. Fix the above, then run this again.");
                return Ok(ExitCode::FAILURE);
            }

            let ping = ours
                .run(&hlb_bootstrap::mesh::reachability_check(
                    &manager.mesh_ip.to_string(),
                ))
                .await?;
            if !ping.ok() {
                eprintln!("🔴 {name} cannot reach {local} through the mesh.");
                eprintln!(
                    "   Most frequent cause: UDP {} is filtered between them.",
                    mesh.port()
                );
                eprintln!("   Nothing joined; the mesh configuration stays in place.");
                return Ok(ExitCode::FAILURE);
            }
            println!("tunnel to {local} verified");
            if !stale.is_empty() {
                println!("⚠️  {} still without {name}:", stale.join(", "));
                println!("     hlb mesh sync --apply");
            }
            Some(peer.mesh_ip.to_string())
        }
        None => {
            println!("⚠️  This cluster has no mesh: Swarm's ports stay open on the");
            println!("   network the nodes share, and VXLAN has no authentication.");
            println!("   `hlb cluster init --endpoint …` creates one on a new cluster.");
            advertise_addr.map(str::to_string)
        }
    };

    // -- 5. Joining the Swarm --------------------------------------------------
    let tokens = orch.join_tokens().await?;
    let role_enum = if role_final == "manager" {
        hlb_orchestrator::NodeRole::Manager
    } else {
        hlb_orchestrator::NodeRole::Worker
    };

    let mut cmd = vec![
        "docker".to_string(),
        "swarm".into(),
        "join".into(),
        "--token".into(),
        tokens.for_role(role_enum).to_string(),
    ];
    if let Some(a) = &advertise {
        cmd.push("--advertise-addr".into());
        cmd.push(a.clone());
        // Without it the node's own cluster port listens on every interface.
        cmd.push("--listen-addr".into());
        cmd.push(format!("{a}:2377"));
    }
    cmd.push(tokens.advertise_addr.clone());

    let o = ours.run(&cmd).await?;
    if !o.ok() && !o.stderr.contains("already part of a swarm") {
        eprintln!("🔴 join refused: {}", o.stderr.trim());
        return Ok(ExitCode::FAILURE);
    }
    println!("joined the Swarm as {role_final}");
    let sealed = match &unlock {
        seal::NewManager::Seal(k) => {
            seal::seal_new_manager(ours.as_ref(), &name, k, &state, &vault).await?
        }
        _ => true,
    };

    // -- 6. Labels, once the node is visible -----------------------------------
    // Swarm takes a moment to publish a node that just joined.
    let mut joined = None;
    for _ in 0..10 {
        if let Some(n) = orch.nodes().await?.into_iter().find(|n| n.hostname == name) {
            joined = Some(n);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    match (&joined, tier_final) {
        (Some(n), Some(t)) => {
            orch.label_node(&n.id, "tier", &t).await?;
            println!("tier={t} set");
        }
        (None, _) => {
            println!("⚠️  node not visible yet: set the tier in a moment");
            println!("     hlb node tier {name} --apply");
        }
        (Some(_), None) => {
            // 🔴 Without a tier this node receives NO service: the placement
            // constraints match nothing, and deployments time out silently.
            println!("🔴 Undeterminable tier — this node will receive no service until");
            println!("   it has one:");
            println!("     hlb node tier {name} --set heavy --apply");
        }
    }
    if let Some(n) = &joined {
        let level = hlb_bootstrap::protection::assess(&protection).level;
        orch.label_node(
            &n.id,
            hlb_orchestrator::cluster::LABEL_PROTECTION,
            level.as_str(),
        )
        .await?;
        println!("protection level {} set", level.as_str());
    }
    if let (Some(n), Some(d)) = (&joined, failure_domain) {
        orch.label_node(&n.id, hlb_orchestrator::cluster::LABEL_FAILURE_DOMAIN, d)
            .await?;
        println!("failure domain {d} set");
    } else if failure_domain.is_none() {
        println!("  · no --failure-domain: counted as \"unknown hardware\", never as");
        println!("    isolated from the other nodes.");
    }
    if let (Some(n), true) = (&joined, storage_node) {
        orch.label_node(&n.id, hlb_orchestrator::cluster::LABEL_STORAGE, "true")
            .await?;
        println!("storage node set");
    }

    state
        .audit("cli", ACTOR_ROLE, "node-add", host, "ok", Some(&role_final))
        .await?;

    println!();
    println!("{host} is part of the cluster.");
    println!("  hlb cluster status");
    if protection.root_encrypted == Some(true) {
        println!("  hlb node bind-disk {name} --apply   # its disk opened at boot by the house");
    }
    let nodes = orch.nodes().await?;
    disk::print_rebinds(
        &disk::rebinds(&nodes, Some(name.as_str()), None),
        Some(name.as_str()),
        None,
    );
    if !sealed {
        eprintln!();
        eprintln!("🔴 Swarm's unlock key is NOT sealed to it: at its next restart it stays");
        eprintln!("   locked until someone unlocks it. Seal it now:");
        eprintln!("     hlb cluster autolock --apply");
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

/// A concrete `SshRunner`, for the operations that require `Sized`.
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

/// The level a machine can reach, why not higher, and whether its disk is encrypted yet.
fn print_protection(signals: &hlb_bootstrap::protection::Signals) {
    let a = hlb_bootstrap::protection::assess(signals);
    println!(
        "Protection: can reach {} — {}",
        a.level.as_str(),
        a.level.describe()
    );
    for why in &a.held_back {
        println!("  · {why}");
    }
    for w in &a.warnings {
        println!("  ⚠️  {w}");
    }
    // The level is a ceiling: until the disk is encrypted, a stolen one reads as is.
    match signals.root_encrypted {
        Some(true) => println!("  · its root is encrypted"),
        Some(false) => println!("  · its root is NOT encrypted: a disk taken away reads as is"),
        None => println!("  · whether its root is encrypted could not be read"),
    }
}

/// Plans what turns this machine into a node, prints it, and runs it with `apply`.
///
/// One path for `hlb node deps` and `hlb node add`: two would drift, and the one used
/// less would be the one that installs `docker` by the wrong name.
///
/// Returns whether the machine is (or would be) ready; a refusal is printed.
/// `reboot_allowed` only for a machine nothing of ours runs on yet: anywhere else a
/// reboot drains nothing, and `hlb node upgrade` is the verb that does.
async fn provision_machine(
    runner: &dyn hlb_bootstrap::Runner,
    distro: &hlb_bootstrap::Distro,
    storage: bool,
    apply: bool,
    reboot_allowed: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    use hlb_bootstrap::provision;

    let seen = hlb_bootstrap::observe::dependencies(runner, distro).await?;
    let tpm = hlb_bootstrap::observe::tpm_driver(runner).await;
    let deps = hlb_bootstrap::deps::plan_for(distro, &seen, storage, tpm);
    let facts = hlb_bootstrap::observe::facts(runner, distro).await?;

    println!("Dependencies:");
    for d in &deps.decisions {
        println!("  {}", d.describe());
    }

    let plan = match provision::plan(distro, &deps, &facts) {
        Ok(p) => p,
        Err(refusal) => {
            eprintln!("\n🔴 {refusal}");
            eprintln!("   Nothing was changed on this machine.");
            return Ok(false);
        }
    };

    if !plan.notes.is_empty() {
        println!();
        for n in &plan.notes {
            println!("  · {n}");
        }
    }

    if !apply {
        println!("\nWould run, in order:");
        for (i, s) in plan.steps.iter().enumerate() {
            println!("  {:>2}. {}", i + 1, s.describe());
        }
        return Ok(true);
    }

    println!();
    let total = plan.steps.len();
    let mut n = 0;
    let (services, installing): (Vec<_>, Vec<_>) = plan
        .steps
        .iter()
        .cloned()
        .partition(|s| s.phase == provision::Phase::Services);
    let mut outcome = provision::execute(
        runner,
        &provision::Provision {
            steps: installing,
            notes: Vec::new(),
        },
        |s| {
            n += 1;
            println!("  [{n}/{total}] {}", s.what);
        },
    )
    .await;

    // Arch deletes the running kernel's modules when it upgrades the kernel: Docker and
    // WireGuard then fail on the first module they load, until a reboot.
    if outcome.is_ok() && !services.is_empty() && !running_kernel_has_modules(runner).await {
        if !reboot_allowed {
            eprintln!("🔴 the kernel was upgraded and the running one lost its modules:");
            eprintln!("   nothing can start until this machine reboots. Reboot it, then run");
            eprintln!("   the same command again — what is installed is skipped.");
            return Ok(false);
        }
        println!("  the kernel was upgraded: rebooting before anything starts…");
        if !reboot_and_wait(runner).await {
            eprintln!("🔴 {} has not come back after 10 min.", runner.label());
            return Ok(false);
        }
        println!("  ✓ back up");
    }
    if outcome.is_ok() {
        outcome = provision::execute(
            runner,
            &provision::Provision {
                steps: services,
                notes: Vec::new(),
            },
            |s| {
                n += 1;
                println!("  [{n}/{total}] {}", s.what);
            },
        )
        .await;
    }
    match outcome {
        Ok(()) => {
            println!("✓ machine provisioned");
            Ok(true)
        }
        Err(e) => {
            eprintln!("🔴 {e}");
            eprintln!("   The steps before this one are done; running the command again");
            eprintln!("   skips what is already in place.");
            Ok(false)
        }
    }
}

/// Are the running kernel's modules still on disk? `true` when it cannot tell: a
/// machine is only rebooted on evidence.
async fn running_kernel_has_modules(r: &dyn hlb_bootstrap::Runner) -> bool {
    r.run(&[
        "sh".into(),
        "-c".into(),
        "test -d /lib/modules/$(uname -r)".into(),
    ])
    .await
    .map(|o| o.ok())
    .unwrap_or(true)
}

/// Reboots a remote machine and waits for its SSH to answer again, ten minutes at most.
async fn reboot_and_wait(r: &dyn hlb_bootstrap::Runner) -> bool {
    use std::time::Duration;
    // Detached, delayed: the SSH session must return before the machine goes.
    let _ = r
        .run(&[
            "sh".into(),
            "-c".into(),
            "nohup sh -c 'sleep 2; systemctl reboot || reboot' >/dev/null 2>&1 &".into(),
        ])
        .await;
    tokio::time::sleep(Duration::from_secs(15)).await;
    for _ in 0..60 {
        if matches!(r.run(&["true".to_string()]).await, Ok(o) if o.ok()) {
            return true;
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    false
}

/// Opens the vault, creating its key only where [`Cli::may_create_key`] allows.
///
/// 🔴 A new key beside an existing state is refused in every case: it cannot read one
/// secret the state holds, and every later write would mix the two.
fn open_vault(cli: &Cli) -> Result<Vault, Box<dyn std::error::Error>> {
    // A sealed key not unsealed is present: `Vault::open` says how to unseal it.
    if !hlb_secrets::key_present(&cli.master_key) {
        if cli.state_existed {
            return Err(format!(
                "{} exists but its key {} does not: a new key could not read one of its \
                 secrets. Point HLB_MASTER_KEY at the key it was created with",
                absolute(&cli.state),
                absolute(&cli.master_key)
            )
            .into());
        }
        if !cli.may_create_key {
            return Err(no_installation(&cli.master_key).into());
        }
    }
    Ok(Vault::open_or_init(&cli.master_key)?)
}

/// Stalwart's administrator, when its URL and credentials are given; `None` otherwise,
/// and what needs mail says so rather than pretending.
pub(crate) fn mail_admin(cli: &Cli) -> Option<hlb_mail::Stalwart> {
    match (
        &cli.stalwart_url,
        &cli.stalwart_admin,
        &cli.stalwart_password,
    ) {
        (Some(u), Some(a), Some(p)) => Some(hlb_mail::Stalwart::new(
            relay::reach(u, &cli.platform_network),
            hlb_mail::Auth::Basic {
                user: a.clone(),
                password: p.clone(),
            },
        )),
        _ => None,
    }
}

/// Opens the state, creating it only where [`Cli::may_create_state`] allows.
async fn open_state(cli: &Cli) -> Result<State, Box<dyn std::error::Error>> {
    if !cli.state.exists() && !cli.may_create_state {
        return Err(no_installation(&cli.state).into());
    }
    Ok(State::open(&cli.state).await?)
}

fn no_installation(missing: &std::path::Path) -> String {
    format!(
        "no installation here: {} does not exist. The state and the vault's key stay where \
         `hlb cluster init` ran — run from there, or point HLB_STATE and HLB_MASTER_KEY at \
         them (given that way, they are created if absent)",
        absolute(missing)
    )
}

fn absolute(p: &std::path::Path) -> String {
    std::path::absolute(p)
        .unwrap_or_else(|_| p.to_path_buf())
        .display()
        .to_string()
}

/// Freezes `next` as `app`'s manifest and runs its plan to the end — or puts `frozen`
/// back. `refused` is what the caller found against the move; the storage and the
/// routes are checked here, as an install checks them. `verb` names the run in the
/// journal; `again` is the command that runs it again. `entry` is the catalog's: its
/// guide and its release are frozen with `next`.
#[allow(clippy::too_many_arguments)]
async fn switch_manifest(
    cli: &Cli,
    state: &State,
    app: &str,
    entry: &hlb_catalog::Entry,
    frozen: &hlb_types::Manifest,
    next: &hlb_types::Manifest,
    refused: Vec<String>,
    mail_domain: Option<String>,
    apply: bool,
    verb: &str,
    again: &str,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let storage = hlb_engine::StorageConfig {
        local_root: cli.storage_root.clone(),
        nfs_server: cli.nfs_server.clone(),
        nfs_export: cli.nfs_export.clone(),
    };
    // What an install refuses, an upgrade refuses too: another app's volume with
    // that app gone.
    let ingress = match SwarmOrchestrator::connect().await {
        Ok(orch) => hlb_engine::ingress::app_blockers(&orch, state, next).await,
        Err(_) => Vec::new(),
    };
    let blockers: Vec<String> = refused
        .into_iter()
        .chain(storage.blockers_for(next))
        .chain(ingress)
        .collect();
    if !blockers.is_empty() {
        println!();
        for b in &blockers {
            eprintln!("🔴 {b}");
        }
        eprintln!("   Nothing was changed.");
        return Ok(ExitCode::FAILURE);
    }

    let domain = state.app_domain(app).await?;
    // The one named, else the one its install took, else the exposure's.
    let mail_domain = hlb_engine::install::mail_domain(state, app, mail_domain).await?;
    let params = InstallParams {
        domain: domain.clone(),
        mail_domain,
        timezone: state.timezone().await?,
        ..Default::default()
    };
    let guide = &entry.guide;
    let plan = hlb_resolver::resolve_with_guide(next, guide, &params)?;
    if !apply {
        println!("\nWould freeze the catalog's manifest and run its plan again,");
        println!("updating the running services in place:\n");
        print!("{plan}");
        println!("\nRerun with --apply.");
        return Ok(ExitCode::SUCCESS);
    }

    // Frozen, then the whole plan again: its actions keep what exists — a
    // database, a secret, a volume — and a deployment updates its service
    // in place rather than being skipped as done.
    let status = state
        .installed_apps()
        .await?
        .into_iter()
        .find(|(n, _)| n == app)
        .map(|(_, st)| st)
        .unwrap_or_else(|| "running".to_string());
    let frozen_guide = state.app_guide(app).await?;
    let frozen_release = state.app_release(app).await?;
    state.upsert_app(app, next, domain.as_deref()).await?;
    state.set_app_guide(app, Some(guide)).await?;
    state
        .set_app_release(
            app,
            &hlb_state::Release {
                index: entry.index,
                version: entry.version.clone(),
            },
        )
        .await?;
    state
        .set_app_mail_domain(app, params.mail_domain.as_deref())
        .await?;
    state.reset_plan(app).await?;
    println!();
    let run = execute_plan(cli, state, app, &plan, &storage, true, verb).await;
    // 🔴 The frozen manifest moves with what runs: back when nothing was
    // redeployed, kept when the new spec was — and the app keeps the status,
    // so the route, it had.
    let settled = hlb_engine::upgrade::settle(
        state,
        app,
        frozen,
        frozen_guide.as_ref(),
        &frozen_release,
        &status,
        domain.as_deref(),
    )
    .await?;
    match settled {
        hlb_engine::upgrade::Settled::Finished | hlb_engine::upgrade::Settled::Partial => run,
        hlb_engine::upgrade::Settled::Reverted => {
            eprintln!(
                "\n   The upgrade did not finish: \"{app}\" keeps the manifest it \
                 had. `{again}` runs it again."
            );
            run.map(|_| ExitCode::FAILURE)
        }
        hlb_engine::upgrade::Settled::Interrupted => {
            eprintln!(
                "\n   The upgrade stopped after redeploying: \"{app}\" runs the new \
                 manifest, which stays. `{again}` finishes it."
            );
            run.map(|_| ExitCode::FAILURE)
        }
    }
}

/// Runs an app's plan with every building block that answers wired in — `install`'s
/// path, and `upgrade`'s: two copies would drift, and the one used less would be the
/// one deploying without its database.
async fn execute_plan(
    cli: &Cli,
    state: &State,
    app: &str,
    plan: &hlb_resolver::Plan,
    storage: &hlb_engine::StorageConfig,
    apply: bool,
    verb: &str,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let orch = SwarmOrchestrator::connect().await?;
    let vault = open_vault(cli)?;

    // PostgreSQL is only wired in if it is reachable: without it,
    // provisioning is recorded as unimplemented, never simulated.
    let pg = match &cli.postgres_admin {
        Some(url) => match hlb_platform::PostgresProvisioner::connect(&relay::reach(
            url,
            &cli.platform_network,
        ))
        .await
        {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("⚠️  PostgreSQL unreachable ({e}) — provisioning skipped.");
                None
            }
        },
        None => None,
    };

    let mariadb = match &cli.mariadb_admin {
        Some(url) => match hlb_platform::MariadbProvisioner::connect(&relay::reach(
            url,
            &cli.platform_network,
        ))
        .await
        {
            Ok(m) => Some(m),
            Err(e) => {
                eprintln!("⚠️  MariaDB unreachable ({e}) — provisioning skipped.");
                None
            }
        },
        None => None,
    };

    let registry = hlb_registry::RegistryClient::new();
    let identity = match (&cli.pocketid_url, &cli.pocketid_key) {
        (Some(u), Some(k)) => Some(hlb_identity::PocketId::new(
            relay::reach(u, &cli.platform_network),
            k,
        )),
        _ => None,
    };

    // Stalwart: same rule as the others. Without credentials, mailbox
    // provisioning stays "unimplemented", never simulated.
    let mail = mail_admin(cli);

    // The guides' `api` steps reach each app by its overlay name: through a relay here.
    let network = cli.platform_network.clone();
    let api = hlb_guide::HttpApi::default().reaching(move |u| relay::reach(u, &network));
    let mut exec = Executor::new(&orch, state)
        .with_vault(&vault)
        .with_registry(&registry)
        .with_storage(storage.clone())
        .with_network(&cli.platform_network)
        .with_api(&api)
        .apply(apply);
    if let Some(p) = &pg {
        exec = exec.with_postgres(p);
    }
    if let Some(m) = &mariadb {
        exec = exec.with_mariadb(m);
    }
    if let Some(i) = &identity {
        exec = exec.with_identity(i);
    }
    if let Some(m) = &mail {
        exec = exec.with_mail(m);
    }
    // Garage: with its admin token a bucket is made, without it the step stays
    // unimplemented — never pretended.
    let garage = match (&cli.garage_url, &cli.garage_token) {
        (Some(u), Some(t)) => Some(
            hlb_objstore::Garage::new(relay::reach(u, &cli.platform_network), t.clone())
                .with_s3(relay::reach(hlb_objstore::S3_URL, &cli.platform_network)),
        ),
        _ => None,
    };
    if let Some(g) = &garage {
        exec = exec.with_objstore(g);
    }
    let out = match exec.run(app, plan).await {
        Ok(o) => o,
        Err(e) => {
            // A blocking guide is not a failure: it is a deliberate refusal
            // by the system. Confusing the two would make the log useless —
            // "it crashed" and "we protected the user" would look alike.
            let issue = match &e {
                hlb_engine::Error::BlockedByGuide { .. } => "refused",
                _ => "failed",
            };
            state
                .audit("cli", ACTOR_ROLE, verb, app, issue, Some(&e.to_string()))
                .await?;
            return Err(e.into());
        }
    };

    if apply {
        let issue = if out.is_success() { "ok" } else { "failed" };
        state
            .audit("cli", ACTOR_ROLE, verb, app, issue, None)
            .await?;
    }

    if !apply {
        println!("Preview for \"{app}\" — no change made.\n");
        print!("{plan}");
        println!("\nRerun with --apply to execute.");
        return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
    }

    println!(
        "{} executed, {} skipped, {} unimplemented",
        out.executed, out.skipped, out.unimplemented
    );

    if let Some((seq, err)) = &out.failed {
        eprintln!("\nfailed at action {}: {err}", seq + 1);
        eprintln!("  rerun the same command to resume at that step.");
        return Ok(ExitCode::FAILURE);
    }

    // Git mirror: the history of the config, independent of the state
    // database. A failure here must not fail the install: the app is
    // deployed, which is what counts.
    if let Some(path) = &cli.git_mirror {
        match export_git(path, state, &format!("{verb} {app}")).await {
            Ok(r) if r.changed() => println!("config archived in Git"),
            Ok(_) => {}
            Err(e) => eprintln!("⚠️  Git mirror not updated: {e}"),
        }
    }

    if out.unimplemented > 0 {
        println!(
            "\n⚠️  {} require building blocks that are not written yet \
                 (database, secrets, OIDC, ingress).",
            out.unimplemented
        );
        println!("   They are recorded as such, not as successful.");
    }
    Ok(ExitCode::SUCCESS)
}

/// The first destination a route names that is not declared, across every class asked.
fn unknown_destination<'a>(asked: &[(&str, &'a [String])], known: &[String]) -> Option<&'a str> {
    asked
        .iter()
        .flat_map(|(_, dests)| dests.iter())
        .find(|d| !known.contains(d))
        .map(String::as_str)
}

/// Keeps the replica count `hlb stop` / `hlb scale` gave an installed app's own
/// service, for reconciliation and the next deployment: the manifest's own count gives
/// it back to the manifest. A service that is no installed app has nothing to keep.
async fn remember_replicas(
    cli: &Cli,
    service: &str,
    replicas: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = open_state(cli).await?;
    let Ok(m) = state.app_manifest(service).await else {
        println!("  ⚠️  {service} is no installed app: reconciliation does not keep this count");
        return Ok(());
    };
    let decided = (replicas != m.spec.swarm.replicas).then_some(replicas);
    state.set_app_replicas(service, decided).await?;
    Ok(())
}

/// An installed app's plan, resolved again from the manifest it was installed with.
async fn plan_as_installed(
    cli: &Cli,
    state: &State,
    app: &str,
) -> Result<hlb_resolver::Plan, Box<dyn std::error::Error>> {
    let frozen = state.app_manifest(app).await?;
    let guide = hlb_engine::install::installed_guide(state, app, || {
        Catalog::load(&cli.catalog)
            .ok()
            .and_then(|c| c.get(app).ok().map(|e| e.guide.clone()))
    })
    .await?;
    let params = InstallParams {
        domain: state.app_domain(app).await?,
        // The one its install took: the exposure's of today may be another.
        mail_domain: hlb_engine::install::mail_domain(state, app, None).await?,
        timezone: state.timezone().await?,
        ..Default::default()
    };
    Ok(hlb_resolver::resolve_with_guide(&frozen, &guide, &params)?)
}

/// Runs an app's plan again, as installed: its actions keep what exists, and its
/// deployments update their services in place — so what a deployment computes reaches
/// them. The ingress lands where its labels now point, an app signing in through
/// PocketID trusts the root of the day.
///
/// Whether every action succeeded.
pub(crate) async fn redeploy(
    cli: &Cli,
    state: &State,
    app: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let plan = plan_as_installed(cli, state, app).await?;
    let storage = hlb_engine::StorageConfig {
        local_root: cli.storage_root.clone(),
        nfs_server: cli.nfs_server.clone(),
        nfs_export: cli.nfs_export.clone(),
    };
    state.reset_plan(app).await?;
    println!();
    execute_plan(cli, state, app, &plan, &storage, true, "redeploy").await?;
    Ok(state
        .plan_actions(app)
        .await?
        .iter()
        .all(|a| a.status != hlb_state::ActionStatus::Failed))
}

/// Fills the platform's admin access from the vault, where a flag did not give it.
///
/// Only when the state and the master key already exist: a command run on a machine
/// with no installation must not create a vault as a side effect of looking.
fn with_platform_access(mut cli: Cli) -> Cli {
    if !cli.state.exists() || !hlb_secrets::key_present(&cli.master_key) {
        return cli;
    }
    let Ok(rt) = tokio::runtime::Runtime::new() else {
        return cli;
    };
    let access = rt.block_on(async {
        let state = State::open(&cli.state).await.ok()?;
        let vault = Vault::open_or_init(&cli.master_key).ok()?;
        hlb_engine::access::from_vault(&state, &vault).await.ok()
    });
    if let Some(a) = access {
        if cli.postgres_admin.is_none() {
            cli.postgres_admin = a.postgres_admin;
        }
        if cli.mariadb_admin.is_none() {
            cli.mariadb_admin = a.mariadb_admin;
        }
        if let (None, None, Some((url, token))) =
            (&cli.garage_url, &cli.garage_token, a.garage_admin)
        {
            cli.garage_url = Some(url);
            cli.garage_token = Some(token);
        }
        if let (None, None, Some((url, user, password))) =
            (&cli.stalwart_url, &cli.stalwart_password, a.stalwart_admin)
        {
            cli.stalwart_url = Some(url);
            cli.stalwart_admin = Some(user);
            cli.stalwart_password = Some(password);
        }
        if let (None, None, Some((url, key))) = (&cli.pocketid_url, &cli.pocketid_key, a.pocketid) {
            cli.pocketid_url = Some(url);
            cli.pocketid_key = Some(key);
        }
    }
    cli
}

fn run() -> Result<ExitCode, Box<dyn std::error::Error>> {
    use clap::{CommandFactory as _, FromArgMatches as _};
    let matches = Cli::command().get_matches();
    let mut cli = Cli::from_arg_matches(&matches)?;
    // 🔴 Both default to a path relative to where `hlb` runs: from any other directory
    // the vault was created anew, empty, and the next command worked on it without a
    // word ("No node in the mesh"). A path given on purpose may be created; the default
    // only by `cluster init`, which is where an installation starts.
    let explicit = |id: &str| {
        !matches!(
            matches.value_source(id),
            None | Some(clap::parser::ValueSource::DefaultValue)
        )
    };
    // Each file on its own: requiring both explicit refused `hlb token create
    // --state <path>`, which never opens the vault (the browser suite's signed-out
    // controller is set up that way).
    let init = matches!(&cli.command, Command::Cluster(ClusterCmd::Init { .. }));
    cli.may_create_state = init || explicit("state");
    cli.may_create_key = init || explicit("master_key");
    cli.state_existed = cli.state.exists();
    // Given nowhere and absent here: the catalog this binary was built with, so that a
    // machine holding `hlb` alone can still install and lay out its datasets. Kept for
    // the whole command, removed after it.
    let _carried = if !explicit("catalog") && !cli.catalog.exists() {
        let dir = tempfile::tempdir()?;
        for (rel, content) in carried_catalog::FILES {
            let path = dir.path().join(rel);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, content)?;
        }
        cli.catalog = dir.path().to_path_buf();
        Some(dir)
    } else {
        None
    };
    let cli = with_platform_access(cli);

    match &cli.command {
        Command::Catalog(CatalogCmd::Key(cmd)) => catalog_index::key(cmd),
        Command::Catalog(CatalogCmd::Export { dir }) => {
            // Written into nothing that exists: a directory holding a catalog already
            // would come out as a mix of two, read as one.
            if dir.exists() {
                eprintln!(
                    "🔴 {} exists — the catalog is written into a new directory",
                    dir.display()
                );
                return Ok(ExitCode::FAILURE);
            }
            for (rel, content) in carried_catalog::FILES {
                let path = dir.join(rel);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, content)?;
            }
            println!(
                "✓ the catalog of hlb {} written to {} ({} files)",
                env!("CARGO_PKG_VERSION"),
                dir.display(),
                carried_catalog::FILES.len()
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Catalog(CatalogCmd::Index(cmd)) => catalog_index::run(cmd),

        Command::Catalog(CatalogCmd::Source(cmd)) => {
            tokio::runtime::Runtime::new()?.block_on(sources::run(&cli, cmd))
        }

        Command::Catalog(CatalogCmd::List) => {
            // With an installation, its sources too; a bare node has the official alone.
            let c = if cli.state.exists() {
                tokio::runtime::Runtime::new()?.block_on(async {
                    let state = open_state(&cli).await?;
                    sources::catalog_with_sources(&cli, &state).await
                })?
            } else {
                Catalog::load(&cli.catalog)?
            };
            println!(
                "{} in {}\n",
                hlb_api::plural(c.len() as u64, "application", "applications"),
                cli.catalog.display()
            );
            for e in c.entries() {
                let m = &e.manifest;
                println!(
                    "  {:<14} {:<10} {:<22} {:?}",
                    e.name(),
                    format!("{:?}", m.kind).to_lowercase(),
                    m.spec.image.reference(),
                    m.spec.update.channel,
                );
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Catalog(CatalogCmd::Images { apply }) => {
            // The carried catalog is a temporary copy: written there, nothing would stay.
            if *apply && _carried.is_some() {
                eprintln!(
                    "✗ no catalog here: --apply writes into one — run it from the repository, \
                     or name it with --catalog"
                );
                return Ok(ExitCode::FAILURE);
            }
            let c = Catalog::load(&cli.catalog)?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let registry = hlb_registry::RegistryClient::new();
                let now = chrono::Utc::now().timestamp();
                let (mut moved, mut unread) = (0u64, 0u64);
                for e in c.entries() {
                    let m = &e.manifest;
                    let name = &m.metadata.name;
                    let images = std::iter::once((name.clone(), &m.spec.image)).chain(
                        m.spec
                            .companions
                            .iter()
                            .map(|c| (format!("{name}/{}", c.name), &c.image)),
                    );
                    for (owner, image) in images {
                        let p = match hlb_updater::catalog::propose(
                            &registry,
                            &owner,
                            image,
                            m.spec.update.maturation_days,
                            now,
                        )
                        .await
                        {
                            Ok(p) => p,
                            Err(err) => {
                                unread += 1;
                                println!("✗ {owner:<28} {}:{} — {err}", image.repo, image.tag);
                                continue;
                            }
                        };
                        match &p.to {
                            Some(to) => {
                                let built = p
                                    .published
                                    .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                                    .map(|d| d.format("%Y-%m-%d").to_string())
                                    .unwrap_or_default();
                                println!(
                                    "→ {owner:<28} {}:{} → {}@{} (built {built})",
                                    image.repo,
                                    image.tag,
                                    to.tag,
                                    to.digest.as_deref().unwrap_or_default()
                                );
                                moved += 1;
                            }
                            None => println!("✓ {owner:<28} {}", image.reference()),
                        }
                        for why in &p.held {
                            println!("    held: {why}");
                        }
                        if let Some(major) = &p.major {
                            println!(
                                "    major: {major} — a person's, rehearsed on a restored \
                                 copy first"
                            );
                        }
                        let (true, Some(to)) = (*apply, &p.to) else {
                            continue;
                        };
                        let text = std::fs::read_to_string(&e.path)?;
                        let Some(new) = hlb_updater::catalog::rewrite(&text, image, to) else {
                            println!(
                                "    ✗ not written: {} holds no single `image: {{ repo: {}, \
                                 tag: \"{}\" }}` line to edit",
                                e.path.display(),
                                image.repo,
                                image.tag
                            );
                            unread += 1;
                            continue;
                        };
                        std::fs::write(&e.path, new)?;
                    }
                }
                println!();
                if moved == 0 {
                    println!("Nothing to move.");
                } else if *apply {
                    println!(
                        "{} written — hlb catalog validate, then try each on its image.",
                        hlb_api::plural(moved, "image", "images")
                    );
                } else {
                    println!(
                        "{} to move: hlb catalog images --apply writes them.",
                        hlb_api::plural(moved, "image", "images")
                    );
                }
                // An image nobody could read is not one that is up to date.
                Ok::<_, Box<dyn std::error::Error>>(if unread == 0 {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                })
            })
        }

        Command::Catalog(CatalogCmd::Validate { apps }) => {
            let c = match apps {
                Some(apps) => Catalog::load_apps_over(&cli.catalog, apps)?,
                None => Catalog::load(&cli.catalog)?,
            };
            let errs = c.validate_all();

            for (name, e) in &errs {
                eprintln!("✗ {name} : {e}");
            }

            // The graph is the second half of validation: a manifest can be valid on
            // its own and still reference a service absent from the catalog.
            let graph_err = DependencyGraph::from_manifests(&c.manifests())
                .deployment_order()
                .err();
            if let Some(e) = &graph_err {
                eprintln!("dependency graph: {e}");
            }

            if errs.is_empty() && graph_err.is_none() {
                println!(
                    "{} valid, graph coherent",
                    hlb_api::plural(c.len() as u64, "manifest", "manifests")
                );
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::FAILURE)
            }
        }

        Command::Order => {
            let c = Catalog::load(&cli.catalog)?;
            let g = DependencyGraph::from_manifests(&c.manifests());
            let order = g.deployment_order()?;

            println!("Deployment order ({} services):\n", order.len());
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
            println!("\nShutdown runs in reverse order.");
            Ok(ExitCode::SUCCESS)
        }

        Command::Plan {
            app,
            domain,
            mail_domain,
        } => {
            let c = Catalog::load(&cli.catalog)?;
            let entry = c.get(app)?;

            let canonical =
                |d: &Option<String>| d.as_deref().map(hlb_types::domain::parse).transpose();
            let (domain, mail_domain) = match (canonical(domain), canonical(mail_domain)) {
                (Ok(d), Ok(m)) => (d, m),
                (Err(refusal), _) | (_, Err(refusal)) => {
                    eprintln!("🔴 {refusal}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            let params = InstallParams {
                domain,
                mail_domain,
                ..Default::default()
            };

            let plan = hlb_resolver::resolve_with_guide(&entry.manifest, &entry.guide, &params)?;

            println!("Plan for \"{app}\"  (no change made)\n");
            print!("{plan}");
            Ok(ExitCode::SUCCESS)
        }

        Command::Stop { app, apply } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let orch = SwarmOrchestrator::connect().await?;
                let Some(current) = orch.status(app).await.ok().map(|s| s.desired_replicas) else {
                    eprintln!("🔴 \"{app}\" is not deployed, or Docker is unreachable.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                };

                if current == 0 {
                    println!("{app} is already stopped.");
                    return Ok(ExitCode::SUCCESS);
                }

                println!("Stopping {app} ({current} replicas → 0)\n");
                // ⚠️ Said before, not after: this is what separates stop from remove,
                // and it is the question you are actually asking.
                println!("  · the service definition stays");
                println!("  · the volumes stay");
                println!("  · the routing stays — the address will answer with an error");

                if !*apply {
                    println!("\nPreview: nothing was changed.");
                    println!("  hlb stop {app} --apply");
                    return Ok(ExitCode::SUCCESS);
                }

                orch.scale(app, 0).await?;
                // Kept in the state: in Swarm alone, reconciliation read the zero as
                // drift and started the app again.
                remember_replicas(&cli, app, 0).await?;
                open_state(&cli)
                    .await?
                    .audit("cli", ACTOR_ROLE, "app-scale", app, "ok", Some("0"))
                    .await?;
                println!("\n✓ stopped. hlb scale {app} 1 --apply brings it back.");
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::Scale {
            app,
            replicas,
            apply,
        } => {
            // 🔴 The same refusal as the API route, and it lives in both places
            // deliberately: the CLI does not go through the controller, so a rule
            // written only there would not protect this path.
            if *replicas == 0 {
                eprintln!("🔴 zero replicas stops \"{app}\" — that is a shutdown, not a resize.");
                eprintln!("   If that is the intent, say so: hlb remove {app} --confirm {app}");
                return Ok(ExitCode::FAILURE);
            }

            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let orch = SwarmOrchestrator::connect().await?;
                let current = orch.status(app).await.ok().map(|s| s.desired_replicas);

                match current {
                    Some(c) => println!("{app}: {c} → {replicas} replicas"),
                    None => {
                        eprintln!("🔴 \"{app}\" is not deployed, or Docker is unreachable.");
                        return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                    }
                }

                if !*apply {
                    println!("\nPreview: nothing was changed.");
                    println!("  hlb scale {app} {replicas} --apply");
                    return Ok(ExitCode::SUCCESS);
                }

                orch.scale(app, *replicas).await?;
                remember_replicas(&cli, app, *replicas).await?;
                open_state(&cli)
                    .await?
                    .audit(
                        "cli",
                        ACTOR_ROLE,
                        "app-scale",
                        app,
                        "ok",
                        Some(&replicas.to_string()),
                    )
                    .await?;
                println!("✓ scaled");
                // ⚠️ Swarm accepts the instruction immediately and converges after. The
                // replicas are NOT running yet, and saying otherwise would have you
                // check a dashboard that has not caught up.
                println!("  Swarm has accepted the instruction; convergence follows.");
                println!("  hlb ps");
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::Remove {
            app,
            confirm,
            apply,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;

                let installed = state
                    .installed_apps()
                    .await?
                    .into_iter()
                    .any(|(n, _)| &n == app);
                if !installed {
                    eprintln!("🔴 \"{app}\" is not installed.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                }

                let volumes = state.app_volumes(app).await?;
                println!("Removing \"{app}\"\n");
                println!(
                    "  · the {app} service is removed from Swarm, and the secrets its files use"
                );
                // 🔴 Said BEFORE the confirmation, not after: this is the sentence on
                // which someone decides. "0 volume kept" must not read as "the data
                // stays" — with no volume, no file of the app survives.
                if volumes.is_empty() {
                    println!("  · {}", hlb_engine::removal::NO_VOLUME);
                } else {
                    for (name, _, backup, _) in &volumes {
                        println!(
                            "  · the volume \"{name}\" is KEPT{}",
                            if *backup {
                                " (backed up)"
                            } else {
                                " — and it is NOT backed up"
                            }
                        );
                    }
                }
                let manifest = state.app_manifest(app).await?;
                for line in hlb_engine::removal::kept_elsewhere(app, &manifest) {
                    println!("  · {line}");
                }
                let secrets = hlb_engine::removal::secrets_left(&state, app).await?;
                if let Some(line) = hlb_engine::removal::secrets_line(app, secrets.len()) {
                    println!("  · {line}");
                }
                println!("  · the backups and the audit log are kept");

                if !*apply {
                    println!("\nPreview: nothing was done.");
                    println!("  hlb remove {app} --confirm {app} --apply");
                    return Ok(ExitCode::SUCCESS);
                }

                if confirm.as_deref() != Some(app.as_str()) {
                    eprintln!("\n🔴 Confirmation missing: --confirm {app}");
                    return Ok(ExitCode::FAILURE);
                }

                // The service first: forgetting the app while it still runs would leave
                // a service nobody manages, invisible to every screen.
                let orch = SwarmOrchestrator::connect().await?;
                let removed = hlb_engine::remove_services(&orch, app, &manifest).await?;
                println!();
                for service in hlb_engine::services_of(app, &manifest) {
                    if removed.contains(&service) {
                        println!("✓ {service} removed");
                    } else {
                        println!("· {service} was not running");
                    }
                }

                state.forget_app(app).await?;
                state
                    .audit("cli", ACTOR_ROLE, hlb_state::APP_REMOVED, app, "ok", None)
                    .await?;
                println!("✓ {app} forgotten: manifest, plan and guides");
                // Its route goes with it: left in the Caddyfile it would answer 502 at
                // its name, and the exposure screen would call it published.
                let vault = open_vault(&cli)?;
                if let hlb_engine::ingress::Published::Done { .. } =
                    hlb_engine::ingress::publish(&orch, &state, Some(&vault)).await?
                {
                    println!("✓ its route is no longer published");
                }
                println!("\nWhat is listed as kept is still there — a reinstall picks it up.");
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::Install {
            app: asked,
            domain,
            mail_domain,
            apply,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let c = sources::catalog_with_sources(&cli, &state).await?;
                let entry = c.get(asked)?;
                // `community/foo` installs as `foo`.
                let app = &entry.manifest.metadata.name;

                // 🔴 BEFORE freezing the manifest. A `tier: nfs` volume with no server
                // configured cannot be provisioned, and discovering it once the app is
                // recorded leaves a half-install whose first action failed.
                let storage = hlb_engine::StorageConfig {
                    local_root: cli.storage_root.clone(),
                    nfs_server: cli.nfs_server.clone(),
                    nfs_export: cli.nfs_export.clone(),
                };
                let missing = storage.blockers_for(&entry.manifest);
                if !missing.is_empty() {
                    for m in &missing {
                        eprintln!("🔴 {m}");
                    }
                    return Ok(ExitCode::FAILURE);
                }

                let exposure = state.exposure().await?;

                // The ingress refuses at preview what would leave it unplaced, or
                // serving names nobody chose; an app, a route through what is missing.
                if let Ok(orch) = SwarmOrchestrator::connect().await {
                    let mut blockers =
                        hlb_engine::ingress::app_blockers(&orch, &state, &entry.manifest).await;
                    if entry.manifest.metadata.name == hlb_types::manifest::INGRESS_SERVICE {
                        blockers.extend(hlb_engine::ingress::blockers(&orch, &state).await);
                    }
                    if !blockers.is_empty() {
                        for b in &blockers {
                            eprintln!("🔴 {b}");
                        }
                        return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                    }
                }

                // An app with a route and no domain named takes `<app>.<domain>`: the
                // template would otherwise stay `{{ domain }}`, which no DNS resolves.
                let domain = match (domain, &exposure) {
                    (Some(d), _) => Some(d.clone()),
                    (None, Some(e)) if !entry.manifest.spec.ingress.is_empty() => {
                        let d = e.default_domain(app);
                        println!("Published at {d} (--domain to choose another)\n");
                        Some(d)
                    }
                    _ => None,
                };
                // The mail domain follows the exposure's, unless named.
                let mail_domain = mail_domain
                    .clone()
                    .or_else(|| exposure.as_ref().map(|e| e.domain.clone()));

                // An app already recorded resumes from what it was installed with.
                let basis = match hlb_engine::install::basis(
                    &state,
                    app,
                    hlb_engine::install::Origin {
                        source: entry.source.as_deref(),
                        index: entry.index,
                        version: entry.version.as_deref(),
                    },
                    &entry.manifest,
                    &entry.guide,
                    domain,
                    mail_domain,
                )
                .await?
                {
                    Ok(b) => b,
                    Err(refusal) => {
                        eprintln!("🔴 {refusal}");
                        return Ok(ExitCode::FAILURE);
                    }
                };
                if let Some(status) = &basis.resumed {
                    println!(
                        "\"{app}\" is recorded ({status}): resuming it as installed — the \
                         catalog's changes reach it through `hlb upgrade {app}`\n"
                    );
                }

                let params = InstallParams {
                    domain: basis.domain.clone(),
                    mail_domain: basis.mail_domain.clone(),
                    timezone: state.timezone().await?,
                    ..Default::default()
                };
                let plan =
                    hlb_resolver::resolve_with_guide(&basis.manifest, &basis.guide, &params)?;

                // The manifest is frozen now — and only when applying: a preview records
                // nothing. A later catalog change will not modify this installation.
                if *apply {
                    hlb_engine::install::record(&state, app, &basis).await?;
                }
                let grants = basis.manifest.grants(basis.domain.as_deref());
                if !*apply && !grants.is_empty() {
                    println!("What \"{app}\" receives beyond its own container:");
                    for g in grants {
                        println!("  ⚠️  {g}");
                    }
                    println!();
                }

                execute_plan(&cli, &state, app, &plan, &storage, *apply, "install").await
            })
        }

        Command::Upgrade {
            app,
            mail_domain,
            apply,
        } => {
            use hlb_engine::upgrade;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let c = sources::catalog_with_sources(&cli, &state).await?;

                let Some(app) = app else {
                    // Which installed apps the catalog has moved since.
                    let mut behind = 0;
                    for (name, _) in state.installed_apps().await? {
                        let source = state.app_source(&name).await?;
                        let Ok(entry) = c.followed(&name, source.as_deref()) else {
                            println!("  {name}: no longer in the catalog");
                            continue;
                        };
                        let frozen = state.app_manifest(&name).await?;
                        let mut changed =
                            upgrade::changes(&frozen, &upgrade::next(&frozen, &entry.manifest));
                        changed.extend(upgrade::guide_changes(
                            state.app_guide(&name).await?.as_ref(),
                            &entry.guide,
                        ));
                        let images = upgrade::image_notes(&frozen, &entry.manifest);
                        if changed.is_empty() && images.is_empty() {
                            continue;
                        }
                        behind += 1;
                        println!(
                            "  {name}: {}{}",
                            hlb_api::plural(changed.len() as u64, "change", "changes"),
                            if images.is_empty() {
                                ""
                            } else {
                                ", and a newer image (hlb update)"
                            }
                        );
                    }
                    if behind == 0 {
                        println!("Every installed app matches the catalog.");
                    } else {
                        println!("\n  hlb upgrade <app>   shows what would change");
                    }
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                };

                let entry = c.followed(app, state.app_source(app).await?.as_deref())?;
                let frozen = state.app_manifest(app).await?;
                let next = upgrade::next(&frozen, &entry.manifest);
                let mut changed = upgrade::changes(&frozen, &next);
                changed.extend(upgrade::guide_changes(
                    state.app_guide(app).await?.as_ref(),
                    &entry.guide,
                ));
                // An upgrade that stopped after redeploying keeps the manifest it
                // deployed: the catalog matches it, and its plan still has to finish.
                let interrupted = upgrade::interrupted(&state, app).await?;

                println!("\"{app}\" against the catalog\n");
                for line in &changed {
                    println!("  {line}");
                }
                for note in upgrade::image_notes(&frozen, &entry.manifest) {
                    println!("  · {note}");
                }
                if changed.is_empty() && !interrupted {
                    println!("  its manifest and guide match the catalog — nothing to apply");
                    return Ok(ExitCode::SUCCESS);
                }
                if changed.is_empty() {
                    println!("  its last upgrade stopped before its end — its plan runs again");
                }
                let refused = upgrade::refusals(&frozen, &next);
                switch_manifest(
                    &cli,
                    &state,
                    app,
                    entry,
                    &frozen,
                    &next,
                    refused,
                    mail_domain.clone(),
                    *apply,
                    "upgrade",
                    &format!("hlb upgrade {app} --apply"),
                )
                .await
            })
        }

        Command::Job { app, id, apply } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let runs = state.job_runs().await?;
                let now = chrono::Utc::now().timestamp();
                let (Some(app), Some(id)) = (app, id) else {
                    let mut listed = 0;
                    for (name, _) in state.installed_apps().await? {
                        if app.as_ref().is_some_and(|a| *a != name) {
                            continue;
                        }
                        let m = state.app_manifest(&name).await?;
                        let due = hlb_engine::jobs::due(&m, &runs, now);
                        for j in &m.spec.jobs {
                            listed += 1;
                            let last = runs.iter().find(|r| r.app == name && r.job == j.id);
                            let said = match last {
                                None => "never run".to_string(),
                                Some(r) => format!(
                                    "{} {}",
                                    if r.succeeded { "✓" } else { "🔴 failed" },
                                    chrono::DateTime::from_timestamp(r.ran_at, 0)
                                        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
                                        .unwrap_or_default()
                                ),
                            };
                            let next = if due.iter().any(|d| d.id == j.id) {
                                ", due now"
                            } else {
                                ""
                            };
                            println!(
                                "  {name}/{}  every {:?}: {}\n      {said}{next}",
                                j.id, j.every, j.does
                            );
                            if let Some(r) = last.filter(|r| !r.succeeded) {
                                for line in r
                                    .output
                                    .lines()
                                    .rev()
                                    .take(5)
                                    .collect::<Vec<_>>()
                                    .into_iter()
                                    .rev()
                                {
                                    println!("      │ {line}");
                                }
                            }
                        }
                    }
                    if listed == 0 {
                        println!("No installed app declares a scheduled job.");
                    }
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                };
                let m = state.app_manifest(app).await?;
                let Some(job) = m.spec.jobs.iter().find(|j| j.id == *id) else {
                    eprintln!("🔴 \"{app}\" declares no job \"{id}\": hlb job {app}");
                    return Ok(ExitCode::FAILURE);
                };
                if !*apply {
                    println!(
                        "Would run in {app}'s container: {}\n  ({})\nRerun with --apply.",
                        job.command.join(" "),
                        job.does
                    );
                    return Ok(ExitCode::SUCCESS);
                }
                let orch = SwarmOrchestrator::connect().await?;
                let run = hlb_engine::jobs::run(&orch, &state, app, job, now).await?;
                println!("{}", run.output);
                state
                    .audit(
                        "cli",
                        ACTOR_ROLE,
                        "job-run",
                        &format!("{app}/{id}"),
                        if run.succeeded { "ok" } else { "failed" },
                        None,
                    )
                    .await?;
                Ok(if run.succeeded {
                    println!("✓ {app}/{id}");
                    ExitCode::SUCCESS
                } else {
                    eprintln!("🔴 {app}/{id} failed");
                    ExitCode::FAILURE
                })
            })
        }

        Command::Redeploy { app, apply } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                if state.app_manifest(app).await.is_err() {
                    eprintln!("🔴 \"{app}\" is not installed.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                }
                if !*apply {
                    let plan = plan_as_installed(&cli, &state, app).await?;
                    println!("\"{app}\" deployed again, as installed:\n");
                    print!("{plan}");
                    println!("\nWhat exists is kept; each service is updated in place.");
                    println!("Rerun with --apply.");
                    return Ok(ExitCode::SUCCESS);
                }
                Ok(if redeploy(&cli, &state, app).await? {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                })
            })
        }

        Command::Todo { verify } => {
            let catalog = Catalog::load(&cli.catalog).ok();
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let guides = state.pending_guides().await?;

                if guides.is_empty() {
                    println!("No manual action pending.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                }

                println!("{} manual action(s) pending:\n", guides.len());

                let vault = open_vault(&cli).ok();
                let check = hlb_engine::guide_verifier(&state, vault.as_ref()).await;
                let mut observed = 0;

                for (app, id, title, blocking) in &guides {
                    let brand = if *blocking { "🔴" } else { "🟠" };

                    if !verify {
                        println!("  {brand} {app} · {title}  [{id}]");
                        continue;
                    }

                    // The step's declaration comes from the app's guide; its state from
                    // the database. Both are needed to verify.
                    let step = hlb_engine::install::installed_guide(&state, app, || {
                        catalog
                            .as_ref()
                            .and_then(|c| c.get(app).ok())
                            .map(|e| e.guide.clone())
                    })
                    .await?
                    .steps
                    .into_iter()
                    .find(|s| &s.id == id);

                    let Some(step) = step else {
                        println!("  {brand} {app} · {title}  [{id}]  (declaration not found)");
                        continue;
                    };

                    let domain = state.app_domain(app).await?.unwrap_or_default();
                    let vars = [("domain", domain.as_str())];
                    let issue = check.check(&step, &vars).await;

                    println!("  {brand} {app} · {title}  [{id}]");
                    println!("       {}", issue.describe());

                    if issue.is_verified() {
                        state.verify_guide(app, id).await?;
                        observed += 1;
                    }
                }

                if *verify {
                    println!(
                        "\n{} observed done and removed.",
                        hlb_api::plural(observed as u64, "action", "actions")
                    );
                }
                // A handled step can open an `after-guide` route.
                if observed > 0 {
                    exposure::republish(&cli, &state).await;
                }
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::Assert { app } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let orch = SwarmOrchestrator::connect()
                    .await
                    .ok()
                    .map(|o| std::sync::Arc::new(o) as std::sync::Arc<dyn Orchestrator>);
                // From a manager's shell, the apps and the databases are overlay names:
                // each address is reached through a relay.
                let network = cli.platform_network.clone();
                let reader = hlb_guide::assertions::LiveReader::new(
                    orch,
                    cli.postgres_admin.clone(),
                    cli.mariadb_admin.clone(),
                )
                .reaching(move |u| relay::reach(u, &network));
                let apps: Vec<String> = state
                    .installed_apps()
                    .await?
                    .into_iter()
                    .map(|(name, _)| name)
                    .filter(|name| app.as_ref().is_none_or(|a| a == name))
                    .collect();
                if let Some(a) = app.as_ref().filter(|_| apps.is_empty()) {
                    eprintln!("{a} is not installed.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs() as i64);
                // The recovery sign-ins sign in with the vault's passwords: without it,
                // they are not looked at, and said so.
                let vault = open_vault(&cli).ok();
                let (mut broken, mut unread) = (0, 0);
                for name in apps {
                    let m = state.app_manifest(&name).await?;
                    if hlb_guide::assertions::declared(&m).is_empty() {
                        continue;
                    }
                    println!("{name}");
                    let credentials = match &vault {
                        Some(v) => hlb_engine::emergency::credentials(&state, v, &name, &m).await?,
                        None => m
                            .spec
                            .recovery
                            .iter()
                            .map(|r| hlb_guide::assertions::Credential {
                                secret: r.secret.clone(),
                                sign_in: Err("the vault does not open here".into()),
                            })
                            .collect(),
                    };
                    // A person asked: a refused sign-in is tried again, once.
                    let results = hlb_guide::assertions::read_all(
                        &reader,
                        &m,
                        &credentials,
                        hlb_guide::assertions::Refused::TryAgain,
                        now,
                    )
                    .await;
                    for r in &results {
                        let mark = match r.verdict {
                            hlb_api::assertions::Verdict::Holds => "✓",
                            hlb_api::assertions::Verdict::Broken => {
                                broken += 1;
                                "🔴"
                            }
                            hlb_api::assertions::Verdict::Unknown => {
                                unread += 1;
                                "?"
                            }
                        };
                        println!("  {mark} {}  ({})", r.holds, r.observed);
                        if let Some(fix) = &r.fix {
                            println!("      → {fix}");
                        }
                    }
                    state.record_assertions(&name, &results).await?;
                }
                Ok(if broken > 0 {
                    eprintln!(
                        "\n🔴 {} does not hold.",
                        hlb_api::plural(broken, "assertion", "assertions")
                    );
                    ExitCode::FAILURE
                } else if unread > 0 {
                    // A door nobody could look at is not a closed one: a script waiting
                    // for an app to come back reads this exit, not the marks.
                    eprintln!(
                        "\n? {} not read.",
                        hlb_api::plural(unread, "assertion", "assertions")
                    );
                    ExitCode::from(2)
                } else {
                    ExitCode::SUCCESS
                })
            })
        }

        Command::Ingress { apply } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let vault = open_vault(&cli)?;
                let orch = SwarmOrchestrator::connect().await?;
                let Some(exposure) = state.exposure().await? else {
                    eprintln!("🔴 No domain configured: nothing is published.");
                    eprintln!("   hlb config exposure --domain <domain> --email <address> --apply");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                };

                if !apply {
                    let hlb_engine::ingress::Rendered {
                        routes,
                        config: cfg,
                        ..
                    } = hlb_engine::ingress::render(&orch, &state, Some(&vault)).await?;
                    // The credentials stay out of a terminal's scrollback.
                    print!("{}", hlb_ingress::render(&routes, &cfg.redacted()));
                    println!(
                        "\n{} for {}. Re-run with --apply to publish.",
                        hlb_api::plural(routes.len() as u64, "route", "routes"),
                        exposure.domain
                    );
                    return Ok(ExitCode::SUCCESS);
                }

                match hlb_engine::ingress::publish(&orch, &state, Some(&vault)).await? {
                    hlb_engine::ingress::Published::Done { routes, restarted } => {
                        let n = hlb_api::plural(routes.len() as u64, "route", "routes");
                        state
                            .audit(
                                "cli",
                                ACTOR_ROLE,
                                "ingress-publish",
                                "caddy",
                                "ok",
                                Some(&n),
                            )
                            .await?;
                        if restarted {
                            println!(
                                "✓ Caddy serves {n} — restarted, for its names on the overlay"
                            );
                        } else {
                            println!("✓ Caddy serves {n}, reloaded without a restart");
                        }
                        for r in &routes {
                            let reach = if r.public { "public" } else { "private" };
                            println!("  {:<40} {}:{}  {reach}", r.host, r.service, r.port);
                        }
                    }
                    hlb_engine::ingress::Published::NoIngress => {
                        eprintln!("🔴 The ingress is not installed: hlb install caddy --apply");
                        return Ok(ExitCode::FAILURE);
                    }
                    hlb_engine::ingress::Published::NotConfigured => {
                        eprintln!("🔴 No domain configured: nothing is published.");
                        return Ok(ExitCode::FAILURE);
                    }
                }
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::Reconcile { apply } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let orch = SwarmOrchestrator::connect().await?;

                // Garage through its admin token, from the vault: without it the apps'
                // buckets are not looked at, and the report says so.
                let garage = match (&cli.garage_url, &cli.garage_token) {
                    (Some(u), Some(t)) => Some(hlb_objstore::Garage::new(
                        relay::reach(u, &cli.platform_network),
                        t.clone(),
                    )),
                    _ => None,
                };
                let vault = open_vault(&cli).ok();
                let identity = match (&cli.pocketid_url, &cli.pocketid_key) {
                    (Some(u), Some(k)) => Some(hlb_identity::PocketId::new(
                        relay::reach(u, &cli.platform_network),
                        k,
                    )),
                    _ => None,
                };
                let mut reconciler = Reconciler::new(&orch, &state);
                if let Some(g) = &garage {
                    reconciler = reconciler.with_store(g, vault.as_ref());
                }
                if let Some(pid) = &identity {
                    reconciler = reconciler.with_portal(pid);
                }
                let report = reconciler.reconcile(*apply).await?;
                if garage.is_none() {
                    println!("(Garage's admin token unknown: the apps' buckets were not checked)");
                }
                if *apply && !(report.corrected.is_empty() && report.failed.is_empty()) {
                    state
                        .audit(
                            "cli",
                            ACTOR_ROLE,
                            "reconcile",
                            "swarm",
                            if report.failed.is_empty() {
                                "ok"
                            } else {
                                "failed"
                            },
                            Some(&format!(
                                "{} corrected, {} failed",
                                report.corrected.len(),
                                report.failed.len()
                            )),
                        )
                        .await?;
                }

                if report.is_clean() {
                    println!("no gap: the real state matches the desired one.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                }

                println!(
                    "{} detected:\n",
                    hlb_api::plural(report.drifts.len() as u64, "gap", "gaps")
                );
                for d in &report.drifts {
                    let mark = if d.is_correctable() {
                        "🔧"
                    } else {
                        "ℹ️ "
                    };
                    println!("  {mark} {d}");
                    if let Some(fix) = d.fix() {
                        println!("       → {fix}");
                    }
                }

                if !apply {
                    let n = report.correctable().count();
                    if n > 0 {
                        println!(
                            "\n{} correctable. Rerun with --apply.",
                            hlb_api::plural(n as u64, "gap is", "gaps are")
                        );
                    }
                    return Ok(ExitCode::SUCCESS);
                }

                if !report.corrected.is_empty() {
                    println!(
                        "\n{} corrected.",
                        hlb_api::plural(report.corrected.len() as u64, "gap", "gaps")
                    );
                }
                if !report.failed.is_empty() {
                    eprintln!(
                        "\n{} impossible:",
                        hlb_api::plural(report.failed.len() as u64, "correction", "corrections")
                    );
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
                .ok_or("expected format: <app>/<id> (see `hlb todo`)")?;

            let catalog = Catalog::load(&cli.catalog).ok();
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;

                // If the step is verifiable, verify BEFORE accepting the attestation.
                let step = hlb_engine::install::installed_guide(&state, app, || {
                    catalog
                        .as_ref()
                        .and_then(|c| c.get(app).ok())
                        .map(|e| e.guide.clone())
                })
                .await?
                .steps
                .into_iter()
                .find(|s| s.id == id);

                // Before its first --apply: no row to mark, and no domain to check it
                // against. The install reads this and does not stop for the step.
                if !state.installed_apps().await?.iter().any(|(a, _)| a == app) {
                    if step.is_none() {
                        eprintln!("no step \"{id}\" in {app}'s guide.");
                        return Ok(ExitCode::FAILURE);
                    }
                    state.attest_ahead(app, id, *force).await?;
                    state
                        .audit(
                            "cli",
                            ACTOR_ROLE,
                            "guide-verify",
                            target,
                            "ok",
                            Some("attested before its install"),
                        )
                        .await?;
                    println!("\"{id}\" of {app} marked handled, ahead of its install.");
                    println!(
                        "\n⚠️  Attestation: nothing could check this yet, Homelabus takes your \
                         word for it."
                    );
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                }

                let mut attested = true;
                let mut overridden = false;
                if let Some(step) = step {
                    let domain = state.app_domain(app).await?.unwrap_or_default();
                    let vault = open_vault(&cli).ok();
                    let issue = hlb_engine::guide_verifier(&state, vault.as_ref())
                        .await
                        .check(&step, &[("domain", domain.as_str())])
                        .await;

                    match &issue {
                        o if o.is_verified() => {
                            println!("observed: {}", o.describe());
                            attested = false;
                        }
                        // 🔴 We observed that it is NOT done. Attesting the opposite
                        // makes no sense: it is exactly the lie the system must refuse.
                        o if !o.may_attest() && !force => {
                            eprintln!("{}", o.describe());
                            eprintln!(
                                "\nThe check says it is not done. Use --force to attest \
                                 anyway."
                            );
                            return Ok(ExitCode::FAILURE);
                        }
                        o if !o.may_attest() => overridden = true,
                        _ => {}
                    }
                }

                let handled = if overridden {
                    state.force_guide(app, id).await?
                } else {
                    state.verify_guide(app, id).await?
                };
                if handled {
                    // An attestation is a person's word, `--force` against a check
                    // above all: whose word, and when, is what the log is for.
                    let how = match (attested, overridden) {
                        (false, _) => "observed",
                        (true, true) => "attested --force, against its check",
                        (true, false) => "attested",
                    };
                    state
                        .audit("cli", ACTOR_ROLE, "guide-verify", target, "ok", Some(how))
                        .await?;
                    println!("\"{id}\" of {app} marked handled.");
                    if attested {
                        println!(
                            "\n⚠️  Attestation: this step cannot be verified \
                             automatically, Homelabus takes your word for it."
                        );
                    }
                    exposure::republish(&cli, &state).await;
                    Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS)
                } else {
                    eprintln!("no pending action \"{id}\" for {app}.");
                    Ok(ExitCode::FAILURE)
                }
            })
        }

        Command::Audit { limit, verify } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;

                if *verify {
                    let v = state.verify_audit_chain().await?;
                    println!("{}", v.describe());
                    if !v.is_intact() {
                        eprintln!(
                            "\n🔴 The log was modified after the fact. Compare it with the \
                             copy exported off-cluster: that one is authoritative."
                        );
                        return Ok(ExitCode::FAILURE);
                    }
                    return Ok(ExitCode::SUCCESS);
                }

                let t = state.audit_trail(*limit).await?;

                if t.is_empty() {
                    println!("Audit log empty.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                }

                println!(
                    "{:<20} {:<10} {:<12} {:<16} ISSUE",
                    "WHEN", "ACTOR", "ACTION", "TARGET"
                );
                for e in &t {
                    let brand = match e.outcome.as_str() {
                        "ok" => "✓",
                        "refused" => "⛔",
                        _ => "✗",
                    };
                    println!(
                        "{:<20} {:<10} {:<12} {:<16} {brand} {}",
                        e.at, e.actor, e.action, e.target, e.outcome
                    );
                    // The detail carries the diff: show it indented rather than in a
                    // column, or the line becomes unreadable.
                    if let Some(d) = &e.detail {
                        println!("{:<20} └─ {d}", "");
                    }
                }
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::History { limit } => {
            let Some(path) = &cli.git_mirror else {
                eprintln!("no Git mirror configured — use --git-mirror or HLB_GIT_MIRROR");
                return Ok(ExitCode::FAILURE);
            };

            let m = hlb_gitops::GitMirror::open_or_init(path)?;
            let h = m.history(*limit)?;
            if h.is_empty() {
                println!("No change recorded.");
                return Ok(ExitCode::SUCCESS);
            }

            println!(
                "{}, most recent first:\n",
                hlb_api::plural(h.len() as u64, "change", "changes")
            );
            for (id, msg) in &h {
                println!("  {id}  {msg}");
            }
            println!(
                "\n  git -C {} show <id>   for the full diff",
                path.display()
            );
            Ok(ExitCode::SUCCESS)
        }

        Command::Token(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;

                match cmd {
                    TokenCmd::List => {
                        let v = state.list_tokens().await?;
                        if v.is_empty() {
                            println!("No token — the API would accept nobody.");
                            println!("  hlb token create <name> --role admin --apply");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                        }

                        println!("{:<20} {:<10} LAST USE", "NAME", "ROLE");
                        for (name, role, usage) in &v {
                            println!(
                                "{name:<20} {role:<10} {}",
                                usage.as_deref().unwrap_or("never")
                            );
                        }

                        // A token never used is either forgotten or compromised without
                        // anyone knowing: in both cases it is better revoked than left
                        // lying around.
                        let unused = v.iter().filter(|(_, _, u)| u.is_none()).count();
                        if unused > 0 {
                            println!();
                            println!(
                                "⚠️  {} never used: forgotten, or handed out",
                                hlb_api::plural(unused as u64, "token", "tokens")
                            );
                            println!("   and never picked up. Revoke them.");
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    TokenCmd::Revoke { name } => {
                        if state.revoke_token(name).await? {
                            state
                                .audit("cli", ACTOR_ROLE, "token-revoke", name, "ok", None)
                                .await?;
                            println!("\"{name}\" revoked — immediate effect.");

                            if !state.has_tokens().await? {
                                println!();
                                println!("🔴 That was the LAST token. On the next start the");
                                println!("   controller will refuse to launch without");
                                println!("   --insecure-no-auth. Create another one first.");
                            }
                            Ok(ExitCode::SUCCESS)
                        } else {
                            eprintln!("No token named \"{name}\".");
                            Ok(ExitCode::FAILURE)
                        }
                    }

                    TokenCmd::Create {
                        name,
                        role,
                        user,
                        mailbox,
                        apply,
                    } => {
                        let Some(r) = hlb_types::Role::parse(role) else {
                            eprintln!("Unknown role \"{role}\".");
                            eprintln!("  viewer   : see everything, change nothing");
                            eprintln!("  operator : install, update, back up");
                            eprintln!("  admin    : everything, including what destroys");
                            return Ok(ExitCode::FAILURE);
                        };

                        // 🔴 The mailbox is checked BEFORE the token is created.
                        // Checking after left a token created, bound, and with NO
                        // mailbox — so it would have written to the default mailbox,
                        // precisely the silent fallback we want to forbid.
                        if let (Some(u), Some(b)) = (user, mailbox) {
                            let known = state.mailboxes(u).await?;
                            if !known.iter().any(|(l, ..)| l == b) {
                                eprintln!("🔴 \"{u}\" has no mailbox \"{b}\" — no token created.");
                                eprintln!("   hlb user mailbox add {u} {b} --apply");
                                return Ok(ExitCode::FAILURE);
                            }
                        }

                        if !apply {
                            println!("Would create token \"{name}\" with role {}.", r.as_str());
                            println!();
                            println!("  🔴 Its value is shown ONLY ONCE: only a fingerprint");
                            println!("     is kept. A lost token is not recovered, it is");
                            println!("     replaced.");
                            println!();
                            println!("  Rerun with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        // The entropy comes from the same generator as the vault
                        // passwords: a weak token would be the shortest link.
                        let mut entropy = [0u8; hlb_types::token::TOKEN_BYTES];
                        hlb_secrets::fill_random(&mut entropy);

                        let (value, stored) = hlb_types::generate_token(name, r, entropy);
                        state.store_token(&stored).await?;
                        if let Some(u) = user {
                            state.set_token_user(name, Some(u)).await?;

                            if let Some(b) = mailbox {
                                state.set_token_mailbox(name, Some(b)).await?;
                            }
                        }
                        state
                            .audit(
                                "cli",
                                ACTOR_ROLE,
                                "token-create",
                                name,
                                "ok",
                                Some(r.as_str()),
                            )
                            .await?;

                        println!("token \"{name}\" created with role {}.", r.as_str());
                        match (user, mailbox) {
                            (Some(u), Some(b)) => {
                                println!("  bound to \"{u}\", aliases -> mailbox \"{b}\"")
                            }
                            (Some(u), None) => {
                                println!("  bound to \"{u}\", aliases -> default mailbox")
                            }
                            _ => println!("  SERVICE token: cannot create aliases."),
                        }
                        println!();
                        println!("🔴 WRITE IT DOWN NOW — it will never be shown again:");
                        println!();
                        println!("    {value}");
                        println!();
                        println!("Usage:");
                        println!("    curl -H \"Authorization: Bearer {value}\" \\");
                        println!("         http://<controller>:8420/api/apps");
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
                    eprintln!("\"{dataset}\" is neither a ZFS dataset nor a btrfs subvolume.");
                    eprintln!();
                    eprintln!("  A snapshot can only cover one of those two — not an");
                    eprintln!("  ordinary directory. Check:");
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
                            println!("No Homelabus snapshot on {dataset} ({}).", fs.as_str());
                            println!("  hlb snapshot create {dataset} --apply");
                            return Ok(ExitCode::SUCCESS);
                        }

                        println!(
                            "{} on {dataset} ({}):",
                            hlb_api::plural(v.len() as u64, "snapshot", "snapshots"),
                            fs.as_str()
                        );
                        for s in &v {
                            println!("  {}", s.label);
                        }
                        println!();
                        println!("⚠️  They live on the SAME pool as the data: a dead disk");
                        println!("   takes them with it. These are not backups.");
                        println!();
                        println!("   Deletion stays manual and deliberate:");
                        match fs {
                            hlb_backup::Filesystem::Zfs => {
                                println!("     zfs destroy {dataset}@<name>")
                            }
                            hlb_backup::Filesystem::Btrfs => {
                                println!("     btrfs subvolume delete {dataset}/.snapshots/<name>")
                            }
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    SnapshotCmd::Create { pattern, apply, .. } => {
                        let label = snap::snapshot_label(pattern, now())?;

                        if !apply {
                            println!("Would create on {dataset} ({}):", fs.as_str());
                            println!("  {label}");
                            println!();
                            println!(
                                "  Command: {}",
                                snap::create_command(fs, dataset, &label).join(" ")
                            );
                            println!();
                            println!("  🔴 A snapshot is NOT a backup: it lives on the same");
                            println!("     pool as the data. It protects against a logical");
                            println!("     mistake, not against losing the disk.");
                            println!();
                            println!("  Rerun with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        match snap::create(fs, dataset, &label).await {
                            Ok(_) => {
                                let state = open_state(&cli).await?;
                                state
                                    .audit(
                                        "cli",
                                        ACTOR_ROLE,
                                        "snapshot-create",
                                        dataset,
                                        "ok",
                                        Some(&label),
                                    )
                                    .await?;
                                println!("✓ {label}");
                                println!();
                                println!("  Rollback:");
                                match fs {
                                    hlb_backup::Filesystem::Zfs => {
                                        println!("    zfs rollback {dataset}@{label}")
                                    }
                                    hlb_backup::Filesystem::Btrfs => {
                                        println!("    (btrfs: replace the subvolume with");
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

                let state = open_state(&cli).await?;
                let current = su::Version::current();

                // ⚠️ The CLI CANNOT query the agents: they only listen on the Swarm
                // overlay, where only the controller is present. Going through it would
                // invert the layers, and simulating it would be worse — a fleet assumed
                // up to date is exactly what breaks the protocol.
                //
                // So we reason on what we really know, and `self status` says where to
                // look for the rest.
                let agents: Vec<su::AgentNode> = Vec::new();

                // The migrations shipped with this binary, and their reversibility.
                let versioned = known_migrations();
                let migrations: Vec<su::Migration> =
                    versioned.iter().map(|(_, m)| m.clone()).collect();

                match cmd {
                    SelfCmd::Status => {
                        println!("Homelabus {current}  (protocol {})", hlb_agent::PROTOCOL);
                        println!();

                        println!("Fleet compatibility: to be checked from the controller,");
                        println!("  the only one that sees the agents on the overlay:");
                        println!("    curl -s http://<controller>:8420/metrics | grep hlb_node");
                        println!();
                        let irreversible: Vec<_> =
                            migrations.iter().filter(|m| !m.reversible).collect();
                        if irreversible.is_empty() {
                            println!(
                                "{}, all reversible.",
                                hlb_api::plural(migrations.len() as u64, "migration", "migrations")
                            );
                        } else {
                            println!(
                                "🔴 {} with NO rollback:",
                                hlb_api::plural(
                                    irreversible.len() as u64,
                                    "migration",
                                    "migrations"
                                )
                            );
                            for m in irreversible {
                                println!("    {}", m.name);
                            }
                            println!("   No update will be possible until they have their");
                            println!("   `down`.");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                        }

                        println!();
                        println!("⚠️  Updating the controller is NEVER automatic: it is the");
                        println!("   one component whose failure stops you repairing the");
                        println!("   others.");
                        Ok(ExitCode::SUCCESS)
                    }

                    SelfCmd::Rollback {
                        binary,
                        to_migration,
                        confirm,
                        apply,
                    } => {
                        if *binary {
                            let paths = su::SwapPaths::new(std::env::current_exe()?);
                            if !apply {
                                println!("Would restore {}", paths.previous().display());
                                println!();
                                println!("  ⚠️  The SCHEMA is not touched. If the version being");
                                println!("     left had migrated it, the old binary will read a");
                                println!("     schema it does not understand:");
                                println!(
                                    "       hlb self rollback --to-migration <n> --apply --confirm"
                                );
                                println!();
                                println!("  Rerun with --apply.");
                                return Ok(ExitCode::SUCCESS);
                            }

                            match su::swap::rollback(&paths) {
                                Ok(()) => {
                                    state
                                        .audit(
                                            "cli",
                                            ACTOR_ROLE,
                                            "self-rollback-binary",
                                            "binary",
                                            "ok",
                                            None,
                                        )
                                        .await?;
                                    println!("previous binary restored.");
                                    println!();
                                    println!("⚠️  Restart the controller for it to take effect.");
                                    return Ok(ExitCode::SUCCESS);
                                }
                                Err(e) => {
                                    eprintln!("{}", e.describe());
                                    return Ok(ExitCode::FAILURE);
                                }
                            }
                        }

                        if *to_migration == 0 {
                            eprintln!("Say what should be undone:");
                            eprintln!("  --binary                  restore the previous binary");
                            eprintln!("  --to-migration <n>        go back to schema n");
                            return Ok(ExitCode::FAILURE);
                        }

                        let current = state.schema_version().await?;
                        let Some(current) = current else {
                            eprintln!("Database not migrated — nothing to undo.");
                            return Ok(ExitCode::FAILURE);
                        };

                        if *to_migration >= current {
                            println!(
                                "The schema is at {current}: going back to \
                                 {to_migration} undoes nothing."
                            );
                            return Ok(ExitCode::SUCCESS);
                        }

                        // 🔴 SAY what will be lost, migration by migration. "Data will
                        // be lost" helps nobody decide.
                        let lost: Vec<&str> = versioned
                            .iter()
                            .filter(|(v, _)| *v > *to_migration && *v <= current)
                            .map(|(_, m)| m.name.as_str())
                            .collect();

                        println!("Schema rollback {current} -> {to_migration}");
                        println!();
                        println!(
                            "🔴 {} undone:",
                            hlb_api::plural(lost.len() as u64, "migration", "migrations")
                        );
                        for m in &lost {
                            for l in consequence_migration(m) {
                                println!("    {l}");
                            }
                        }

                        if !apply {
                            println!();
                            println!("  Nothing was changed. Rerun with --apply --confirm.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        if !confirm {
                            eprintln!();
                            eprintln!("🔴 --confirm is required: these losses are permanent.");
                            return Ok(ExitCode::FAILURE);
                        }

                        state.undo_migrations(*to_migration).await?;
                        println!();
                        println!("schema at {to_migration}.");
                        println!();
                        println!("⚠️  The BINARY has not changed. Replace it with the");
                        println!("   matching version, or it will re-migrate on next start.");
                        Ok(ExitCode::SUCCESS)
                    }

                    SelfCmd::Update {
                        version,
                        from,
                        key,
                        confirm,
                        apply,
                    } => {
                        let Some(target) = su::Version::parse(version) else {
                            eprintln!("Unreadable version: \"{version}\" (expected: 0.2.0)");
                            return Ok(ExitCode::FAILURE);
                        };

                        // A recent backup of the state ITSELF: without it, a failure
                        // mid migration is permanent.
                        let pre = su::Preflight {
                            from: current,
                            to: target,
                            agents,
                            migrations,
                            state_backup_age_s: hlb_backup_run::state_backup_age(&state).await?,
                            no_app_installed: state.installed_apps().await?.is_empty(),
                        };

                        let plan = match su::plan(&pre) {
                            Ok(p) => p,
                            Err(b) => {
                                println!("{}", b.describe());
                                return Ok(if b.is_refusal() {
                                    ExitCode::FAILURE
                                } else {
                                    // "Already up to date" is not a failure: an error
                                    // code would suggest a problem to an update script.
                                    ExitCode::SUCCESS
                                });
                            }
                        };

                        println!("{}", plan.describe());

                        if plan.jump.needs_confirmation() && !confirm {
                            eprintln!();
                            eprintln!("🔴 {}: explicit approval required.", plan.jump.describe());
                            eprintln!("   Re-read the release notes, then --confirm.");
                            return Ok(ExitCode::FAILURE);
                        }

                        if !apply {
                            println!();
                            println!("  Nothing was changed. Rerun with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        // 🔴 With no key, nothing is downloaded. An unverified update
                        // would replace the binary that holds the vault key and drives
                        // Docker.
                        let Some(key_hex) = key else {
                            println!();
                            println!("🔴 Cannot switch: the Ed25519 public key is missing.");
                            println!();
                            println!("   --key <hex>   Ed25519 release public key");
                            println!();
                            println!("   Without signature verification, the update would be");
                            println!("   the best vector for compromising the system: it");
                            println!("   replaces the binary that holds the vault key.");
                            println!();
                            println!("   The rest is already guaranteed: compatible fleet,");
                            println!("   reversible migrations, established order of steps.");
                            state
                                .audit("cli", ACTOR_ROLE, "self-update-plan", version, "ok", None)
                                .await?;
                            return Ok(ExitCode::SUCCESS);
                        };
                        // Falls back to this project's own GitHub Releases when no
                        // mirror was given — see `github_release_base`.
                        let base_url = from.clone().unwrap_or_else(|| github_release_base(&target));
                        let base_url = base_url.as_str();

                        let key = match su::signature::parse_key(key_hex) {
                            Ok(k) => k,
                            Err(e) => {
                                eprintln!("{}", e.describe());
                                return Ok(ExitCode::FAILURE);
                            }
                        };

                        // The switch must be possible BEFORE downloading: discovering
                        // it impossible afterwards would waste time, and discovering it
                        // after the old binary was moved aside would leave the machine
                        // with no tool at all.
                        let paths = su::SwapPaths::new(std::env::current_exe()?);
                        if let Err(e) = su::swap::preflight(&paths) {
                            eprintln!("{}", e.describe());
                            return Ok(ExitCode::FAILURE);
                        }

                        println!();
                        println!("Downloading from {base_url}...");
                        let (binary, manifest) = match download_version(base_url, &target).await {
                            Ok(v) => v,
                            Err(e) => {
                                eprintln!("🔴 {e}");
                                return Ok(ExitCode::FAILURE);
                            }
                        };

                        if let Err(r) = su::verify_release(&key, &manifest, target, &binary) {
                            eprintln!("{}", r.describe());
                            state
                                .audit(
                                    "cli",
                                    ACTOR_ROLE,
                                    "self-update",
                                    version,
                                    "refused",
                                    Some(&r.describe()),
                                )
                                .await?;
                            return Ok(ExitCode::FAILURE);
                        }
                        println!("signature verified ({} bytes)", binary.len());

                        let kept = match su::swap(&paths, &binary) {
                            Ok(g) => g,
                            Err(e) => {
                                eprintln!("{}", e.describe());
                                return Ok(ExitCode::FAILURE);
                            }
                        };

                        state
                            .audit("cli", ACTOR_ROLE, "self-update", version, "ok", None)
                            .await?;

                        println!("binary replaced.");
                        println!();
                        println!("  Old one kept : {}", kept.display());
                        println!("  Rollback     : hlb self rollback --binary");
                        println!();
                        println!("⚠️  The RUNNING process is still on the old code: under");
                        println!("   Unix its inode stays alive. Restart the controller for");
                        println!("   the new version to take effect.");
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
                    ReplCmd::Config {
                        standby,
                        primary_host,
                        user,
                    } => {
                        let slot = repl::slot_name(standby)?;

                        println!("=== On the PRIMARY, in postgresql.conf ===");
                        println!("{}", repl::primary_settings(1));
                        println!("=== Then, once restarted ===");
                        println!("  CREATE ROLE {user} WITH REPLICATION LOGIN PASSWORD '…';");
                        println!("  SELECT pg_create_physical_replication_slot('{slot}');");
                        println!();
                        println!("  And in pg_hba.conf — replication is treated as a");
                        println!("  separate database, connecting with psql is not enough:");
                        println!("    host replication {user} all scram-sha-256");
                        println!();
                        println!("=== On the STANDBY ===");
                        println!("  1. Initial copy, which already writes standby.signal:");
                        println!("       pg_basebackup -h {primary_host} -U {user} \\");
                        println!("         -D /var/lib/postgresql/data -R -X stream -S {slot} -P");
                        println!();
                        println!("  2. In postgresql.auto.conf, AFTER the pg_basebackup:");
                        println!("{}", repl::APPLY_AFTER_BASEBACKUP);
                        println!();
                        println!(
                            "{}",
                            repl::standby_settings(primary_host, 5432, &slot, user)
                        );
                        Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS)
                    }

                    ReplCmd::Failover {
                        standby,
                        force,
                        apply,
                    } => {
                        // 🔴 The primary is queried, and its silence is INFORMATION:
                        // it turns a switchover into a failover, and the two do not
                        // cost the same. A missing URL is a different thing again —
                        // we do not know, rather than "it is down".
                        let Some(url) = cli
                            .postgres_admin
                            .as_deref()
                            .map(|u| relay::reach(u, &cli.platform_network))
                        else {
                            eprintln!("No PostgreSQL URL — use --postgres-admin.");
                            eprintln!(
                                "Without it we cannot tell a planned switchover from a \
                                 failover, and they do not cost the same."
                            );
                            return Ok(ExitCode::FAILURE);
                        };

                        let standbys = match hlb_platform::PostgresProvisioner::connect(&url).await
                        {
                            Ok(pg) => pg
                                .query_raw(repl::STANDBYS_QUERY)
                                .await
                                .ok()
                                .map(|o| repl::parse_standbys(&o)),
                            Err(e) => {
                                println!("The primary does not answer: {e}\n");
                                None
                            }
                        };

                        let decision = repl::Promotion::decide(standbys.as_deref(), standby);
                        println!("Promoting \"{standby}\"\n");
                        println!("  {}\n", decision.describe());

                        if !decision.is_safe() && !*force {
                            eprintln!(
                                "🔴 Refused. This is a decision paid for in transactions, \
                                 not a default."
                            );
                            eprintln!("   Once you know what it costs:  --force");
                            return Ok(ExitCode::FAILURE);
                        }

                        if !*apply {
                            println!("Preview: nothing was done.");
                            println!(
                                "  hlb replication failover {standby}{} --apply",
                                if *force { " --force" } else { "" }
                            );
                            return Ok(ExitCode::SUCCESS);
                        }

                        // 🔴 We PRINT the procedure rather than run it. Promoting
                        // touches a database whose other half we cannot see from here,
                        // and the fencing step happens on a machine this command has no
                        // access to. A half-automated failover is worse than a written
                        // one: it does the easy part and leaves the dangerous one to
                        // someone who now believes it is handled.
                        // 🔴 Run on a real pair, the previous wording diverged the two:
                        // `scale postgres=0` was undone by `hlb reconcile`, which step 3
                        // asked for, and the old primary took writes again — while the
                        // apps, looking for `postgres` by name, never reached the new one.
                        println!("=== 1. FENCE the old primary ===");
                        println!("  {}\n", repl::FENCE_OLD_PRIMARY);
                        println!("    docker service rm postgres\n");
                        println!("  Removed, not scaled to zero: the reconciliation puts a");
                        println!("  replica count back, and leaves a missing service alone.");
                        println!("  Its volume stays on its node, for step 4. 🔴 Do not run");
                        println!("  `hlb install postgres` before step 4: it redeploys THAT.\n");
                        println!("=== 2. Promote the standby ===");
                        println!("  On {standby}:");
                        println!("    SELECT pg_promote(wait => true);\n");
                        println!("  It leaves recovery and starts accepting writes.\n");
                        println!("=== 3. Give it the name the applications use ===");
                        println!(
                            "  They reach `postgres` by name on {}:",
                            cli.platform_network
                        );
                        println!("  the standby's service takes it as an alias.\n");
                        println!(
                            "    docker service update --network-rm {0} \\\n        \
                             --network-add name={0},alias=postgres <standby-service>\n",
                            cli.platform_network
                        );
                        println!("  Swarm publishes the name once the service is healthy:");
                        println!("  its probe must pass (`pg_isready -U postgres`). The");
                        println!("  apps' connections died with the old primary; an app");
                        println!(
                            "  that does not reconnect: docker service update --force <app>\n"
                        );
                        println!("=== 4. Rebuild the old primary as a standby ===");
                        println!("  🔴 It CANNOT rejoin as-is: it diverged the moment the");
                        println!("  new primary accepted its first write. Rebuild it from");
                        println!("  a fresh base backup:\n");
                        println!("    hlb replication config <old-primary>\n");
                        println!("⚠️  Until step 4 is done you have NO standby: the new");
                        println!("   primary is a single copy, and the next failure has");
                        println!("   nowhere to go.");
                        Ok(ExitCode::SUCCESS)
                    }

                    ReplCmd::Status => {
                        let Some(url) = cli
                            .postgres_admin
                            .as_deref()
                            .map(|u| relay::reach(u, &cli.platform_network))
                        else {
                            eprintln!("No PostgreSQL URL — use --postgres-admin.");
                            return Ok(ExitCode::FAILURE);
                        };

                        let pg = hlb_platform::PostgresProvisioner::connect(&url).await?;

                        let standbys =
                            repl::parse_standbys(&pg.query_raw(repl::STANDBYS_QUERY).await?);

                        // 🔴 `wal_status = 'lost'` is the invalidation: the slot retains
                        // nothing any more, but the standby is unrecoverable.
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
                            println!("No standby connected.");
                        } else {
                            println!("Standbys:");
                            for s in &standbys {
                                println!("  {}", s.describe());
                            }

                            // 🔴 Two standbys under the same name make this output
                            // useless at the worst moment: you see a node falling behind
                            // without being able to say which. Near-certain cause: the
                            // settings written BEFORE `pg_basebackup -R`, which rewrites
                            // postgresql.auto.conf and takes application_name with it.
                            for name in repl::indistinguishable(&standbys) {
                                println!();
                                println!(
                                    "⚠️ Several standbys announce themselves as \"{name}\": no"
                                );
                                println!("   way to tell which is falling behind. Set a distinct");
                                println!("   application_name on each (hlb replication config).");
                            }
                        }

                        let dangerous: Vec<_> = slots.iter().filter(|s| s.is_dangerous()).collect();
                        if !slots.is_empty() {
                            println!();
                            println!("Slots with no consumer:");
                            for s in &slots {
                                println!("  {}", s.describe());
                            }
                        }

                        let bad = standbys
                            .iter()
                            .any(|s| s.health() == hlb_backup::StandbyHealth::Lagging);

                        if !dangerous.is_empty() || bad {
                            println!();
                            println!("🔴 The PRIMARY's disk is at stake: a slot with no");
                            println!("   consumer retains WAL until the disk is full.");
                            return Ok(ExitCode::FAILURE);
                        }
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::Role(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(roles::run(&cli, cmd))
        }

        Command::Emergency(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(emergency::run(&cli, cmd))
        }

        Command::SecretsSeal { apply, host_only } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(seal::run(&cli, *apply, *host_only))
        }

        Command::Termix(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(termix::run(&cli, cmd))
        }

        Command::Mail(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(mail::run(&cli, cmd))
        }

        Command::Domain(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(domain::run(&cli, cmd))
        }

        Command::User(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                use hlb_users::Request;

                let state = open_state(&cli).await?;
                let _vault = open_vault(&cli)?;
                // ⚠️ The mail domain is not a global parameter: it comes from
                // `--mail-domain` on the commands that have one. Here we take the
                // cluster domain, falling back to "local" — and SAY so in the output
                // rather than fabricating a silently wrong address.
                let domain = match std::env::var("HLB_MAIL_DOMAIN") {
                    Ok(d) => d,
                    Err(_) => state
                        .exposure()
                        .await?
                        .map(|e| e.domain)
                        .unwrap_or_else(|| "local".into()),
                };
                let mail = mail_admin(&cli);

                match cmd {
                    UserCmd::Invite { role, uses, days, note, apply } => {
                        use hlb_api::invitation as inv;
                        let mut blockers = Vec::new();
                        let parsed = state.role(role).await?;
                        if parsed.is_none() {
                            blockers.push(format!("no role \"{role}\" — `hlb role list` names them"));
                        }
                        // The interface's bounds, refused rather than trimmed to fit.
                        let duration = days.saturating_mul(86_400);
                        if !(inv::MIN_S..=inv::MAX_S).contains(&duration) {
                            blockers.push(format!("--days {days}: between 1 and {}", inv::MAX_S / 86_400));
                        }
                        if !(1..=inv::USES_MAX).contains(uses) {
                            blockers.push(format!("--uses {uses}: between 1 and {}", inv::USES_MAX));
                        }
                        let (Some(r), true) = (parsed, blockers.is_empty()) else {
                            for b in &blockers {
                                eprintln!("🔴 {b}");
                            }
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                        };

                        let exposure = state.exposure().await?;
                        println!(
                            "An invitation: \"{}\" (level {}), valid {days} days, for {}",
                            r.label(),
                            r.level.as_str(),
                            hlb_api::plural(*uses as u64, "person", "people")
                        );
                        if r.level == hlb_types::Role::Admin {
                            println!("  ⚠️  It grants ADMIN: the person will be able to grant roles and destroy data.");
                        }
                        for o in hlb_engine::roles::opened_by(&state, &r).await? {
                            println!("  ⚠️  It administers {}: {}", o.display_name, o.means);
                        }
                        if *uses > inv::USES_WORTH_FLAGGING {
                            println!("  ⚠️  If the link leaks, that is as many accounts created.");
                        }
                        if cli.pocketid_key.is_none() {
                            println!("  ⚠️  No PocketID key in the vault: the account will be created without");
                            println!("     an identity, unable to sign in until \"hlb user add <name> --apply\".");
                        }
                        if !apply {
                            println!("\nRe-run with --apply: the link is shown once, then only its fingerprint is kept.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        let mut raw = [0u8; 32];
                        hlb_secrets::fill_random(&mut raw);
                        let value = hlb_types::token::base32(&raw);
                        state
                            .create_invitation(
                                &value,
                                "cli",
                                &r.id,
                                now(),
                                duration,
                                *uses,
                                note.as_deref(),
                            )
                            .await?;
                        state
                            .audit("cli", ACTOR_ROLE, "invitation-create", &r.id, "ok", note.as_deref())
                            .await?;
                        let path = inv::link_path(&value);
                        match &exposure {
                            Some(e) => println!("\n  https://{}{path}\n", e.controller_host()),
                            None => {
                                println!("\n  {path}\n");
                                println!("  ⚠️  No domain configured: put the interface's address in front of it.");
                            }
                        }
                        println!("Shown once. Send it the way you trust — it is the key to an account.");
                        Ok(ExitCode::SUCCESS)
                    }
                    UserCmd::Link { name } => {
                        let c = load_account(&state, name).await?;
                        let (Some(u), Some(k)) = (&cli.pocketid_url, &cli.pocketid_key) else {
                            eprintln!("PocketID is not configured: its API key is not in the vault (generated by hlb install pocket-id)");
                            return Ok(ExitCode::FAILURE);
                        };
                        let Some(id) = c.pocket_id else {
                            eprintln!("{name} has no PocketID identity yet — finish it with \"hlb user add {name} --apply\"");
                            return Ok(ExitCode::FAILURE);
                        };
                        let pid = hlb_identity::PocketId::new(relay::reach(u, &cli.platform_network), k);
                        let token = pid.one_time_token(&id, "12h").await?;
                        let public = hlb_engine::access::pocketid_public(&state)
                            .await
                            .unwrap_or_else(|| pid.issuer().to_string());
                        state
                            .audit("cli", ACTOR_ROLE, "identity-link", name, "ok", None)
                            .await?;
                        println!("Single-use link for {name}, valid 12 h:\n");
                        println!("  {}\n", hlb_engine::access::enrolment_link(&public, &token));
                        println!("⚠️ Not recorded: send it now, the way you trust.");
                        Ok(ExitCode::SUCCESS)
                    }
                    UserCmd::Invitations => {
                        let list = state.invitations(now()).await?;
                        if list.is_empty() {
                            println!("No invitation.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        for i in list {
                            let left = i.max_uses.saturating_sub(i.uses);
                            let when = if left == 0 {
                                "used up".to_string()
                            } else if i.expires_in_s <= 0 {
                                "expired".to_string()
                            } else {
                                format!("{} left, {}", left, hlb_api::humanise(i.expires_in_s))
                            };
                            println!(
                                "  {}  {:<20} by {:<10} {when}{}",
                                i.reference,
                                i.role,
                                i.created_by,
                                i.note.map(|n| format!("  — {n}")).unwrap_or_default()
                            );
                        }
                        Ok(ExitCode::SUCCESS)
                    }
                    UserCmd::RevokeInvitation { reference, apply } => {
                        let known = state
                            .invitations(now())
                            .await?
                            .into_iter()
                            .any(|i| &i.reference == reference && i.uses < i.max_uses);
                        if !known {
                            eprintln!("🔴 no open invitation \"{reference}\" — hlb user invitations");
                            return Ok(ExitCode::FAILURE);
                        }
                        if !apply {
                            println!("Would close the invitation {reference}. Re-run with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        state.revoke_invitation(reference).await?;
                        state
                            .audit("cli", ACTOR_ROLE, "invitation-revoke", reference, "ok", None)
                            .await?;
                        println!("✓ {reference} closed.");
                        Ok(ExitCode::SUCCESS)
                    }
                    UserCmd::Add { name, email, display_name, role, apply } => {
                        hlb_users::validate_name(name)?;
                        let Some(p) = state.role(role).await? else {
                            eprintln!("no role \"{role}\" — `hlb role list` names them");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                        };

                        // The local part of the default address.
                        let local = match email {
                            Some(e) => e.split('@').next().unwrap_or(name).to_string(),
                            None => name.clone(),
                        };
                        let dom = match email.as_ref().and_then(|e| e.split('@').nth(1)) {
                            Some(d) => match hlb_types::domain::parse(d) {
                                Ok(d) => d,
                                Err(refusal) => {
                                    eprintln!("🔴 --email: {refusal}");
                                    return Ok(ExitCode::FAILURE);
                                }
                            },
                            None => domain.clone(),
                        };

                        // What the account would be given that is not its to have: a
                        // reserved address, an app's own account, another person's.
                        let has_mailbox = !state.mailboxes(name).await?.is_empty();
                        if !has_mailbox {
                            if let Some(refusal) =
                                hlb_engine::mailbox::refusal(&state, name, &local, &dom).await?
                            {
                                eprintln!("🔴 {refusal}");
                                return Ok(ExitCode::FAILURE);
                            }
                        }

                        let pocket = match (&cli.pocketid_url, &cli.pocketid_key) {
                            (Some(u), Some(k)) => Some(hlb_identity::PocketId::new(relay::reach(u, &cli.platform_network), k)),
                            _ => None,
                        };

                        if !apply {
                            let known = state.users().await?.iter().any(|(n, _, _)| n == name);
                            println!("Preview — nothing is changed.\n");
                            if known {
                                println!("  · {name} exists: what is missing is finished, its role kept");
                            } else {
                                println!("  · record {name}, role \"{}\"", p.label());
                            }
                            match &pocket {
                                Some(pid) => match pid.find_user(name).await? {
                                    Some(_) => println!("  · PocketID identity: already present"),
                                    None => println!("  · create the PocketID identity, and a one-time sign-up link"),
                                },
                                None => println!("  ⚠️ PocketID not configured: no identity would be created"),
                            }
                            if has_mailbox {
                                println!("  · mailbox: already recorded");
                            } else {
                                match &mail {
                                    Some(_) => println!("  · open {local}@{dom} in Stalwart, then record it"),
                                    None => println!("  🔴 Stalwart not configured: the mailbox would NOT be opened"),
                                }
                            }
                            println!("\nRe-run with --apply to create it.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        state.upsert_user(name, &p.id, None).await?;

                        // 🔴 The identity first, the mailbox next, and every step is
                        // idempotent. Rerunning after a failure finishes what is missing
                        // instead of redoing everything — or worse, creating a duplicate.
                        let identity = match pocket {
                            Some(pid) => match pid.find_user(name).await? {
                                Some(u) => {
                                    println!("identity already present");
                                    Some(u.id)
                                }
                                None => {
                                    let display_name =
                                        display_name.clone().unwrap_or_else(|| name.clone());
                                    let u = pid
                                        .create_user(
                                            name,
                                            Some(&format!("{local}@{dom}")),
                                            &display_name,
                                            &[],
                                        )
                                        .await?;
                                    println!("PocketID identity created");

                                    // 🔴 No password: PocketID authenticates with
                                    // passkeys. This is a single-use link replacing the
                                    // delivery of an initial secret — and it is shown
                                    // ONCE, never recorded.
                                    match pid.one_time_token(&u.id, "12h").await {
                                        Ok(token) => {
                                            println!();
                                            println!("  Sign-up link (valid 12 h, single use):");
                                            let public = hlb_engine::access::pocketid_public(&state)
                                                .await
                                                .unwrap_or_else(|| pid.issuer().to_string());
                                            println!(
                                                "    {}",
                                                hlb_engine::access::enrolment_link(&public, &token)
                                            );
                                            println!();
                                            println!("  ⚠️ It is not recorded: write it down now.");
                                        }
                                        Err(e) => {
                                            eprintln!("⚠️ sign-up token not obtained ({e})");
                                            eprintln!("   The account exists but nobody can sign in to it.");
                                        }
                                    }
                                    Some(u.id)
                                }
                            },
                            None => {
                                eprintln!("⚠️ PocketID not configured: identity NOT created.");
                                None
                            }
                        };

                        if let Some(id) = &identity {
                            state.upsert_user(name, &p.id, Some(id)).await?;
                        }

                        // The default mailbox — in Stalwart FIRST, recorded after. Recorded
                        // alone, the account read complete while its address received
                        // nothing: the check below reads the state, so the state only
                        // holds a mailbox Stalwart was seen to hold.
                        if has_mailbox {
                            println!("mailbox already recorded");
                        } else {
                            match &mail {
                                Some(m) => match hlb_engine::mailbox::create(
                                    &state,
                                    m,
                                    name,
                                    &local,
                                    &dom,
                                    true,
                                    hlb_engine::mailbox::Existing::Adopt,
                                )
                                .await?
                                {
                                    Ok(c) if c.adopted => println!(
                                        "mailbox {} — it existed in Stalwart already: \
                                         taken as {name}'s, its password unchanged",
                                        c.address
                                    ),
                                    Ok(c) => println!("mailbox {} opened", c.address),
                                    Err(refusal) => {
                                        eprintln!("🔴 {refusal}");
                                        return Ok(ExitCode::FAILURE);
                                    }
                                },
                                None => eprintln!(
                                    "🔴 Stalwart not configured (--stalwart-url): the mailbox \
                                     is NOT opened — rerun once it is"
                                ),
                            }
                        }
                        state
                            .audit("cli", ACTOR_ROLE, "user-add", name, "ok", Some(&p.id))
                            .await?;

                        // Their role's apps open to them now, not at the controller's
                        // next pass.
                        roles::follow(&cli, &state).await;

                        // 🔴 The half-created state is SAID, not left to be discovered.
                        let account = load_account(&state, name).await?;
                        let c = account.coherence();
                        if !c.is_complete() {
                            println!();
                            println!("{}", c.describe());
                            return Ok(ExitCode::FAILURE);
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    UserCmd::List => {
                        let users = state.users().await?;
                        if users.is_empty() {
                            println!("No account.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        let now = now();
                        for (name, _, _) in &users {
                            let c = load_account(&state, name).await?;
                            let u = c.usage(now);
                            let p = state.role_of(name).await?;

                            println!("{name}  [{}]  {}", p.label(), c.coherence().describe());
                            for b in &c.mailboxes {
                                let brand = if b.default { "★" } else { " " };
                                println!("  {brand} {}", b.address());
                            }
                            println!(
                                "    mailboxes {}/{}  permanent {}/{}  temporary {}/{}",
                                u.mailboxes, p.mail.max_mailboxes,
                                u.permanent_aliases, p.mail.max_permanent_aliases,
                                u.temporary_aliases, p.mail.max_temporary_aliases,
                            );

                            let broken = c.broken_promises(now);
                            if !broken.is_empty() {
                                println!(
                                    "    🔴 {} expired but STILL ACTIVE — \"hlb user alias purged\"",
                                    hlb_api::plural(broken.len() as u64, "alias", "aliases")
                                );
                            }
                            println!();
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    UserCmd::Names { name, first, last, display, apply } => {
                        let (first, last, display) = (first.trim(), last.trim(), display.trim());
                        if display.is_empty() {
                            eprintln!("the display name cannot be empty");
                            return Ok(ExitCode::FAILURE);
                        }
                        let c = load_account(&state, name).await?;
                        let (Some(u), Some(k)) = (&cli.pocketid_url, &cli.pocketid_key) else {
                            eprintln!("PocketID is not configured: --pocketid-url and --pocketid-key");
                            return Ok(ExitCode::FAILURE);
                        };
                        let Some(id) = c.pocket_id else {
                            eprintln!("{name} has no PocketID identity yet — finish it with \"hlb user add {name} --apply\"");
                            return Ok(ExitCode::FAILURE);
                        };
                        if !apply {
                            println!("Preview — {name}: first name \"{first}\", last name \"{last}\", shown as \"{display}\"");
                            println!("\nRe-run with --apply to apply it.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        let change = hlb_identity::UserChange::Names {
                            first: first.into(),
                            last: last.into(),
                            display: display.into(),
                        };
                        hlb_identity::PocketId::new(relay::reach(u, &cli.platform_network), k).update_user(&id, &change).await?;
                        state
                            .audit("cli", ACTOR_ROLE, "identity-names", name, "ok", Some(display))
                            .await?;
                        println!("✓ {name} is shown as \"{display}\"");
                        Ok(ExitCode::SUCCESS)
                    }

                    UserCmd::Role { name, role, apply } => {
                        roles::user_role(&cli, &state, name, role.as_deref(), *apply).await
                    }

                    UserCmd::Quota { name, app, gib, none, role, apply } => {
                        roles::user_quota(&cli, &state, name, app, *gib, *none, *role, *apply).await
                    }

                    UserCmd::Sessions { name, close } => {
                        let now = now();
                        if let Some(target) = close {
                            let n = if target == "all" {
                                state.close_all_sessions(name).await?
                            } else {
                                u64::from(state.close_session_by_reference(name, target).await?)
                            };
                            if n == 0 {
                                eprintln!("no session \"{target}\" for {name}");
                                return Ok(ExitCode::FAILURE);
                            }
                            state
                                .audit("cli", ACTOR_ROLE, "session-close", name, "ok", Some(target))
                                .await?;
                            println!(
                                "✓ {} closed",
                                hlb_api::plural(n, "session", "sessions")
                            );
                            return Ok(ExitCode::SUCCESS);
                        }

                        let sessions = state.sessions_of(name, now).await?;
                        if sessions.is_empty() {
                            println!("{name} has no open session.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        println!("{:<10} {:<12} {:<12} DEVICE", "REF", "SEEN", "EXPIRES");
                        for s in &sessions {
                            println!(
                                "{:<10} {:<12} {:<12} {}",
                                s.reference,
                                format!("{} ago", hlb_api::humanise(now - s.last_seen)),
                                format!("in {}", hlb_api::humanise(s.expires_at - now)),
                                s.user_agent.as_deref().unwrap_or("unknown")
                            );
                        }
                        println!("\nClose:  hlb user sessions {name} --close <REF>|all");
                        Ok(ExitCode::SUCCESS)
                    }

                    UserCmd::Mailbox(sub) => match sub {
                        MailboxCmd::Add { name, local, apply } => {
                            let c = load_account(&state, name).await?;
                            let p = state.role_of(name).await?;
                            p.authorized(&c.usage(now()), Request::Mailbox)
                                .map_err(|r| r.to_string())?;
                            if let Some(refusal) =
                                hlb_engine::mailbox::refusal(&state, name, local, &domain).await?
                            {
                                eprintln!("🔴 {refusal}");
                                return Ok(ExitCode::FAILURE);
                            }

                            // 🔴 Refuse rather than record a mailbox that does not exist
                            // on the server: a half-created account looks functional
                            // and only shows on the first lost email.
                            let Some(mail) = mail.as_ref() else {
                                eprintln!(
                                    "🔴 Stalwart is not configured (--stalwart-url / \
                                     --stalwart-admin / --stalwart-password)."
                                );
                                eprintln!(
                                    "   Refusing: the mailbox would be recorded but would \
                                     receive nothing."
                                );
                                return Ok(ExitCode::FAILURE);
                            };

                            let address = format!("{local}@{domain}");
                            if !apply {
                                println!("Preview — open {address} in Stalwart, then give it to {name}.");
                                println!("\nRe-run with --apply to open it.");
                                return Ok(ExitCode::SUCCESS);
                            }
                            match hlb_engine::mailbox::create(
                                &state,
                                mail,
                                name,
                                local,
                                &domain,
                                false,
                                hlb_engine::mailbox::Existing::Adopt,
                            )
                            .await?
                            {
                                Ok(c) if c.adopted => println!(
                                    "✓ {address} — it existed in Stalwart already: taken as \
                                     {name}'s, its password unchanged"
                                ),
                                Ok(_) => println!("✓ {address}"),
                                Err(refusal) => {
                                    eprintln!("🔴 {refusal}");
                                    return Ok(ExitCode::FAILURE);
                                }
                            }
                            state
                                .audit("cli", ACTOR_ROLE, "mailbox-add", name, "ok", Some(&address))
                                .await?;
                            Ok(ExitCode::SUCCESS)
                        }
                        MailboxCmd::Remove { name, local, apply } => {
                            let c = load_account(&state, name).await?;
                            let Some(b) = c.mailboxes.iter().find(|b| &b.local == local) else {
                                eprintln!("🔴 {name} has no mailbox \"{local}\"");
                                return Ok(ExitCode::FAILURE);
                            };
                            let address = b.address();
                            c.can_delete_mailbox(local)?;
                            let aliases = state
                                .aliases(name)
                                .await?
                                .into_iter()
                                .filter(|a| &a.0 == local && a.3)
                                .count();
                            // 🔴 Said before and after: the state forgets the mailbox,
                            // Stalwart does not — hlb-mail deletes no account, and its mail
                            // is not Homelabus's to destroy. It keeps receiving.
                            let stays = format!(
                                "its Stalwart account stays, with its mail{} — it keeps \
                                 receiving until it is removed in Stalwart's own console",
                                if aliases == 0 {
                                    String::new()
                                } else {
                                    format!(
                                        " and {}",
                                        hlb_api::plural(aliases as u64, "active alias", "active aliases")
                                    )
                                }
                            );
                            if !apply {
                                println!("Preview — {address} is no longer one of {name}'s mailboxes.");
                                println!("⚠️ {stays}.");
                                println!("\nRe-run with --apply to remove it.");
                                return Ok(ExitCode::SUCCESS);
                            }
                            state.remove_mailbox(name, local).await?;
                            state
                                .audit("cli", ACTOR_ROLE, "mailbox-remove", name, "ok", Some(&address))
                                .await?;
                            println!("✓ {address} is no longer one of {name}'s mailboxes");
                            println!("⚠️ {stays}.");
                            Ok(ExitCode::SUCCESS)
                        }

                        MailboxCmd::Default { name, local, apply } => {
                            let c = load_account(&state, name).await?;
                            let Some(b) = c.mailboxes.iter().find(|b| &b.local == local) else {
                                eprintln!("{name} has no mailbox \"{local}\"");
                                return Ok(ExitCode::FAILURE);
                            };
                            let address = b.address();
                            let pocket = match (&cli.pocketid_url, &cli.pocketid_key, &c.pocket_id) {
                                (Some(u), Some(k), Some(id)) => {
                                    Some((hlb_identity::PocketId::new(relay::reach(u, &cli.platform_network), k), id.clone()))
                                }
                                _ => None,
                            };
                            if !apply {
                                println!("Preview — {name}: {address} becomes the default mailbox");
                                match pocket {
                                    Some(_) => println!("   and the address PocketID gives applications"),
                                    None => println!("⚠️ PocketID not reachable from here: applications keep the old address"),
                                }
                                println!("\nRe-run with --apply to apply it.");
                                return Ok(ExitCode::SUCCESS);
                            }
                            state.set_default_mailbox(name, local).await?;
                            println!("✓ {address} is the default mailbox of {name}");
                            // After the first step only: PocketID announcing an address
                            // Homelabus does not consider the default is the two
                            // disagreeing.
                            match pocket {
                                Some((pid, id)) => {
                                    pid.update_user(&id, &hlb_identity::UserChange::Email(address.clone()))
                                        .await?;
                                    println!("✓ PocketID gives applications {address}");
                                }
                                None => println!("⚠️ PocketID not configured: applications keep the old address"),
                            }
                            state
                                .audit("cli", ACTOR_ROLE, "mailbox-default", name, "ok", Some(&address))
                                .await?;
                            Ok(ExitCode::SUCCESS)
                        }
                    },

                    UserCmd::Device(sub) => devices::run(&state, mail.as_ref(), sub).await,

                    UserCmd::Alias(sub) => {
                        manage_aliases(&state, &domain, mail.as_ref(), sub).await
                    }
                }
            })
        }

        Command::Metrics(cmd) => {
            use hlb_metrics::{deadman, rules, scrape};

            match cmd {
                MetricsCmd::Scrape { controller, token } => {
                    if token.is_none() {
                        // 🔴 Without a token, VictoriaMetrics collects 401s in a loop
                        // and the dashboard stays empty — with nothing saying it is an
                        // authentication problem.
                        eprintln!("⚠️  No token: /metrics is protected and the");
                        eprintln!("   scrape will only receive 401s. Create one:");
                        eprintln!("     hlb token create scrape --role viewer");
                        eprintln!();
                    }
                    let target = scrape::Target::controller(controller.clone(), token.clone());
                    print!("{}", scrape::scrape_config(&[target]));
                    println!();
                    println!(
                        "# Suggested retention: -retentionPeriod={}",
                        scrape::RETENTION
                    );
                    Ok(ExitCode::SUCCESS)
                }

                MetricsCmd::Rules => {
                    for r in rules::default_rules() {
                        println!("{} [{:?}]", r.name, r.level);
                        println!("  {}", r.explanation);
                        println!("  query: {}", r.query);
                        let direction = match r.comparison {
                            hlb_metrics::Comparison::Above => ">",
                            hlb_metrics::Comparison::Below => "<",
                        };
                        println!("  fires if {direction} {}", r.threshold);
                        if r.alarming_absence {
                            println!("  ⚠️ missing data is itself an alert");
                        }
                        println!();
                    }
                    Ok(ExitCode::SUCCESS)
                }

                MetricsCmd::Check { url } => {
                    let rt = tokio::runtime::Runtime::new()?;
                    rt.block_on(async {
                        let mut alerts = 0;
                        let mut blind = 0;

                        for r in rules::default_rules() {
                            let point = format!(
                                "{}/api/v1/query?query={}",
                                url.trim_end_matches('/'),
                                encoder_url(r.query)
                            );

                            let evaluation = match reqwest::get(&point).await {
                                Ok(rep) => match rep.text().await {
                                    Ok(body) => match hlb_metrics::promql_values(&body) {
                                        Ok(v) => r.judge(&v),
                                        Err(e) => hlb_metrics::Evaluation::Unknown {
                                            reason: e.to_string(),
                                        },
                                    },
                                    Err(e) => hlb_metrics::Evaluation::Unknown {
                                        reason: e.to_string(),
                                    },
                                },
                                // 🔴 An unreachable VictoriaMetrics is NOT "nothing to
                                // report": monitoring itself is down, so every rule is
                                // blind.
                                Err(e) => hlb_metrics::Evaluation::Unknown {
                                    reason: format!("VictoriaMetrics unreachable: {e}"),
                                },
                            };

                            match &evaluation {
                                hlb_metrics::Evaluation::Ok => println!("✓ {}", r.name),
                                hlb_metrics::Evaluation::Triggered { value } => {
                                    println!(
                                        "🔴 {} — {} (measured {value:.2})",
                                        r.name, r.explanation
                                    );
                                    alerts += 1;
                                }
                                hlb_metrics::Evaluation::Unknown { reason } => {
                                    println!("❓ {} — BLIND: {reason}", r.name);
                                    blind += 1;
                                }
                            }
                        }

                        println!();
                        if blind > 0 {
                            // 🔴 "I do not know" must never read as "all is well": that is
                            // exactly what this module exists to prevent. Exit code 0
                            // would suggest it.
                            println!(
                                "🔴 {} BLIND: that is not \"nothing to report\",",
                                hlb_api::plural(blind, "rule", "rules")
                            );
                            println!("   it is \"we do not know\".");
                        }
                        if alerts > 0 {
                            println!("🔴 {} active.", hlb_api::plural(alerts, "alert", "alerts"));
                        }
                        if alerts == 0 && blind == 0 {
                            println!("Every rule is green, and every one of them has data.");
                        }

                        Ok::<_, Box<dyn std::error::Error>>(if alerts + blind > 0 {
                            ExitCode::FAILURE
                        } else {
                            ExitCode::SUCCESS
                        })
                    })
                }

                MetricsCmd::Deadman {
                    heartbeat_file,
                    ntfy,
                } => {
                    // The catalog's ntfy refuses anonymous publishing: the watchdog's
                    // own account, generated at ntfy's install, goes in the script.
                    let rt = tokio::runtime::Runtime::new()?;
                    let account = rt.block_on(async {
                        let Ok(state) = open_state(&cli).await else {
                            return Ok::<_, Box<dyn std::error::Error>>(None);
                        };
                        let Ok(vault) = open_vault(&cli) else {
                            return Ok(None);
                        };
                        let Ok(access) = hlb_engine::access::from_vault(&state, &vault).await
                        else {
                            return Ok(None);
                        };
                        // The script carries the password: recorded BEFORE it is shown,
                        // like `hlb secret-get`, or this verb is the read that leaves no
                        // trace.
                        if access.ntfy_watchdog.is_some() {
                            let name = hlb_engine::access::ntfy_watchdog_secret();
                            state
                                .audit("cli", ACTOR_ROLE, "secret-read", &name, "ok", None)
                                .await?;
                        }
                        Ok(access.ntfy_watchdog)
                    })?;
                    println!(
                        "{}",
                        deadman::watchdog_script(
                            heartbeat_file,
                            ntfy,
                            "Homelabus",
                            account.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
                        )
                    );
                    if account.is_none() {
                        eprintln!("# ⚠️ No ntfy watchdog account in the vault: the script");
                        eprintln!("#    publishes anonymously, which the catalog's ntfy");
                        eprintln!("#    refuses. Install ntfy first.");
                    }
                    eprintln!("# ─────────────────────────────────────────────────────");
                    eprintln!("# 🔴 Put this on the NAS, NOT on the controller node:");
                    eprintln!("#    a watchdog hosted by what it watches dies with it");
                    eprintln!("#    and detects nothing.");
                    eprintln!("#");
                    eprintln!("# 🔴 The ntfy topic must be DISTINCT from Homelabus's own:");
                    eprintln!("#    if the controller is dead, the watchdog alone must");
                    eprintln!("#    still be able to speak.");
                    eprintln!("#");
                    eprintln!(
                        "# Missed beats tolerated: 3 (that is {} s of silence).",
                        deadman::MAX_SILENCE_S
                    );
                    Ok(ExitCode::SUCCESS)
                }
            }
        }

        Command::Dr(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                use hlb_backup::dr;

                let state = open_state(&cli).await?;
                let orch = SwarmOrchestrator::connect().await.ok();

                match cmd {
                    DrCmd::Exercise {
                        base_dir,
                        image,
                        disposable,
                        apply,
                    } => {
                        use hlb_backup::drill;

                        let bases = load_databases(&state).await?;
                        let target = drill::Target {
                            container: drill::container_name(now())?,
                            disposable: *disposable,
                        };
                        let server = hlb_types::DbEngine::Postgres.service_name();
                        let image = match image {
                            Some(i) => i.clone(),
                            None => match state.app_manifest(server).await {
                                Ok(m) => m.spec.image.reference(),
                                Err(_) => {
                                    eprintln!(
                                        "No {server} installed to take its image from: \
                                         --image names the one the backup was taken on."
                                    );
                                    return Ok(ExitCode::FAILURE);
                                }
                            },
                        };

                        if let Err(r) = drill::authorize(&target, !bases.is_empty()) {
                            eprintln!("{}", r.describe());
                            return Ok(ExitCode::FAILURE);
                        }

                        // `authorize` has already refused the empty case, but do not
                        // lean on that: an `expect` in production breaks the binary,
                        // where an explicit refusal stays repairable.
                        let Some(last) = bases.iter().max_by_key(|b| b.finished_at) else {
                            eprintln!("No base backup — nothing to drill.");
                            return Ok(ExitCode::FAILURE);
                        };

                        if !apply {
                            println!("Would drill the restore of {}:", last.id);
                            println!("  disposable container: {}", target.container);
                            println!("  source (read-only): {base_dir}/{}", last.id);
                            println!("  image : {image}");
                            println!();
                            println!("  The drill restores the backup into a BRAND-NEW container,");
                            println!("  checks that PostgreSQL opens it, counts the tables, then");
                            println!("  destroys everything. Production is never touched.");
                            println!();
                            println!("  ⚠️  It proves the DATABASE comes back. It does not prove");
                            println!("     the application restarts on top of it.");
                            println!();
                            println!("  Re-run with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        println!("Drill running (real restore)…");
                        let o = drill::run_postgres(&target, base_dir, &last.id, &image).await?;

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
                                "cli",
                                ACTOR_ROLE,
                                "dr-exercise",
                                &last.id,
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
                        let bases = load_databases(&state).await?;
                        let nodes = match &orch {
                            Some(o) => o.nodes().await.unwrap_or_default(),
                            None => Vec::new(),
                        };

                        println!("Recovery capability:");
                        println!(
                            "  base backups : {}",
                            if bases.is_empty() {
                                "🔴 NONE — nothing could be restored".to_string()
                            } else {
                                format!(
                                    "{} (most recent: {})",
                                    bases.len(),
                                    hlb_backup::pitr::iso8601(
                                        bases.iter().map(|b| b.finished_at).max().unwrap_or(0)
                                    )
                                )
                            }
                        );

                        let home: Vec<_> = nodes
                            .iter()
                            .filter(|n| n.memory_mb.is_some_and(|m| m >= dr::MIN_MEMORY_MB))
                            .collect();
                        println!("  host nodes   : {}", home.len());
                        for n in &home {
                            let m = n.memory_mb.unwrap_or(0);
                            println!(
                                "    {:<16} {m} MB -> profile {}",
                                n.hostname,
                                dr::Profile::for_memory(m).describe()
                            );
                        }

                        if bases.is_empty() || home.is_empty() {
                            println!();
                            println!("🔴 The switchover would NOT work today.");
                            if bases.is_empty() {
                                println!("   hlb backup pitr base --apply");
                            }
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                        }

                        println!();
                        let days = state.days_since_successful_drill().await?;
                        let readiness = hlb_backup::Readiness::from_days(days);
                        println!("Recovery drill: {}", readiness.describe());

                        let recent = state.recent_drills(3).await?;
                        if !recent.is_empty() {
                            for (when, scope, status, tables) in &recent {
                                println!(
                                    "  {when}  {scope}  {}{}",
                                    if status == "ok" { "✓" } else { "🔴 failed" },
                                    tables.map(|n| format!(" ({n} tables)")).unwrap_or_default()
                                );
                            }
                        }

                        if readiness.needs_attention() {
                            println!();
                            println!("   hlb dr exercise --disposable --apply");
                            return Ok(ExitCode::FAILURE);
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    DrCmd::Promote {
                        node,
                        base_dir,
                        wal_dir,
                        force_split_brain,
                        apply,
                    } => {
                        let Some(orch) = orch else {
                            eprintln!("🔴 Swarm unreachable: the real state cannot be observed.");
                            eprintln!("   We do not switch over blind.");
                            return Ok(ExitCode::FAILURE);
                        };

                        let nodes = orch.nodes().await?;
                        let Some(target) = nodes.iter().find(|n| &n.hostname == node) else {
                            eprintln!("Node \"{node}\" not found in the cluster.");
                            return Ok(ExitCode::FAILURE);
                        };

                        // 🔴 The old primary's state is OBSERVED, never assumed. A
                        // "heavy" node still ready means PostgreSQL can still run there,
                        // so a promotion would create a split-brain.
                        let primary = nodes
                            .iter()
                            .find(|n| n.tier.as_deref() == Some("heavy") && n.hostname != *node);
                        let primary_alive =
                            !force_split_brain && primary.is_some_and(|n| n.is_ready());

                        let bases = load_databases(&state).await?;
                        let coverage = hlb_backup::scan_archive(std::path::Path::new(wal_dir))
                            .ok()
                            .and_then(|s| hlb_backup::wal_coverage(&s));

                        // An app is "heavy" if its manifest asks for several replicas:
                        // that is the most reliable signal available.
                        let mut apps = Vec::new();
                        for (name, status) in state.installed_apps().await? {
                            if status == "failed" {
                                continue;
                            }
                            let heavy = state
                                .app_manifest(&name)
                                .await
                                .map(|m| m.spec.swarm.replicas > 1)
                                .unwrap_or(false);
                            apps.push((name, heavy));
                        }

                        let candidate = dr::Candidate {
                            node: node.clone(),
                            memory_mb: target.memory_mb.unwrap_or(0),
                            reachable: target.is_ready(),
                        };

                        let plan = match dr::plan_promotion(
                            &candidate,
                            primary.map(|n| n.hostname.as_str()),
                            primary_alive,
                            &bases,
                            coverage,
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
                            println!("Settings to apply on {node}:");
                            for l in hlb_backup::dr::render_settings(plan.profile)?.lines() {
                                println!("    {l}");
                            }
                            println!();
                            println!("Steps to follow after --apply:");
                            println!("  1. Restore {} from {base_dir}", plan.base_backup);
                            println!("  2. Apply the settings above");
                            println!("  3. Replay the WAL from {wal_dir}:");
                            println!(
                                "       hlb backup pitr plan \"{}\"",
                                hlb_backup::pitr::iso8601(plan.recover_to)
                            );
                            println!(
                                "  4. Move the tier: hlb node tier {node} --set heavy --apply"
                            );
                            println!();
                            println!("  🔴 This command restores NOTHING on its own. An");
                            println!("     automatic switchover on failure detection is the");
                            println!("     best way to lose data.");
                            println!();
                            println!("  Re-run with --apply to set the tier and journal it.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        // `--apply` does ONLY what is reversible: moving the placement
                        // label. The restore stays manual.
                        orch.label_node(&target.id, "tier", "heavy").await?;
                        state
                            .audit(
                                "cli",
                                ACTOR_ROLE,
                                "dr-promote",
                                node,
                                "ok",
                                Some(&plan.describe()),
                            )
                            .await?;

                        println!(
                            "✓ tier=heavy set on {node} — Swarm can schedule PostgreSQL there."
                        );
                        println!();
                        println!("🔴 The DATA is not restored. Do steps 1 to 3 above, or");
                        println!("   PostgreSQL will start on an EMPTY database.");
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::Fleet(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(fleet(&cli, cmd))
        }

        Command::Pki(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                use hlb_agent::pki::{self, Purpose};
                let state = open_state(&cli).await?;
                let vault = open_vault(&cli)?;

                let load_ca = || cluster_ca(&state, &vault, false);

                match cmd {
                    PkiCmd::Status => {
                        match load_ca().await? {
                            Some(ca) => {
                                let now = hlb_engine::pki::now();
                                println!("✓ Cluster authority present in the vault.");
                                match pki::not_after(&ca.cert_pem) {
                                    Ok(t) => println!(
                                        "  ends     : {} ({} days)",
                                        hlb_engine::pki::date(t),
                                        hlb_engine::pki::days_left(t, now)
                                    ),
                                    Err(e) => println!("  ends     : unreadable ({e})"),
                                }
                                println!(
                                    "  leaves   : {} days, renewed {} days before they end",
                                    pki::LEAF_DAYS,
                                    pki::RENEW_BEFORE_DAYS
                                );
                                let known = state.leaf_expiries().await?;
                                if known.is_empty() {
                                    println!("  no leaf deployed by `hlb fleet` is recorded");
                                }
                                let mut due = false;
                                for (service, t) in &known {
                                    let left = hlb_engine::pki::days_left(*t, now);
                                    let mark = if hlb_engine::pki::due(Some(*t), now) {
                                        due = true;
                                        "🔴"
                                    } else {
                                        "✓"
                                    };
                                    println!(
                                        "  {mark} {service:<16} ends {} ({left} days)",
                                        hlb_engine::pki::date(*t)
                                    );
                                }
                                if due {
                                    println!();
                                    println!("  🔴 Due, and the controller has not renewed it:");
                                    println!("     hlb pki renew --apply");
                                }
                                println!();
                                println!("⚠️  There is NO revocation (neither CRL nor OCSP).");
                                println!("   A compromised certificate stays valid until it");
                                println!("   expires: that is why they are short.");
                                println!("   Removing a node goes through `hlb access revoke`");
                                println!("   and taking it out of the Swarm.");
                            }
                            None => {
                                println!("No authority — the agents therefore run in the clear.");
                                println!("  hlb pki init --apply");
                                return Ok(ExitCode::FAILURE);
                            }
                        }
                        Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS)
                    }

                    PkiCmd::Renew { service, apply } => {
                        let orch = SwarmOrchestrator::connect().await?;
                        let lines = hlb_engine::pki::Renewal {
                            state: &state,
                            vault: &vault,
                            orchestrator: &orch,
                            agent_service: service,
                            now: hlb_engine::pki::now(),
                            observed: Vec::new(),
                            inside: None,
                        }
                        .run(*apply)
                        .await?;
                        let mut failed = false;
                        for l in &lines {
                            let before = l
                                .before
                                .map_or("an unknown date".to_string(), hlb_engine::pki::date);
                            match &l.outcome {
                                hlb_engine::pki::Outcome::Fine => {
                                    println!("✓ {}: ends {before}, not due", l.service)
                                }
                                hlb_engine::pki::Outcome::Absent => {
                                    println!("  {}: not deployed", l.service)
                                }
                                hlb_engine::pki::Outcome::WouldRenew => {
                                    println!(
                                        "  {}: ends {before} — would be issued again",
                                        l.service
                                    )
                                }
                                hlb_engine::pki::Outcome::Renewed { not_after } => {
                                    let ends = hlb_engine::pki::date(*not_after);
                                    state
                                        .audit(
                                            "cli",
                                            ACTOR_ROLE,
                                            "pki-renew",
                                            &l.service,
                                            "ok",
                                            Some(&ends),
                                        )
                                        .await?;
                                    println!("✓ {}: renewed, ends {ends}", l.service)
                                }
                                hlb_engine::pki::Outcome::Failed(why) => {
                                    failed = true;
                                    if *apply {
                                        state
                                            .audit(
                                                "cli",
                                                ACTOR_ROLE,
                                                "pki-renew",
                                                &l.service,
                                                "failed",
                                                Some(why),
                                            )
                                            .await?;
                                    }
                                    eprintln!("🔴 {}: {why}", l.service);
                                }
                            }
                        }
                        if !apply {
                            println!("\n  Re-run with --apply.");
                        }
                        Ok(if failed {
                            ExitCode::FAILURE
                        } else {
                            ExitCode::SUCCESS
                        })
                    }

                    PkiCmd::Init { apply } => {
                        if load_ca().await?.is_some() {
                            println!("✓ The authority already exists.");
                            println!();
                            println!("  🔴 Creating a second one would invalidate EVERY");
                            println!("     certificate in the fleet at once: the agents would");
                            println!("     refuse the controller, and the other way round.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        if !apply {
                            println!("Would create the cluster certificate authority.");
                            println!("  validity : {} days (deliberately long)", pki::CA_DAYS);
                            println!();
                            println!("  Replacing it means redeploying every certificate in the");
                            println!("  fleet on the same day — hence a lifetime that surprises");
                            println!("  nobody one morning.");
                            println!();
                            println!("  🔴 Its private key goes to the vault. Losing it means");
                            println!("     reissuing everything, node by node.");
                            println!("\n  Re-run with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        cluster_ca(&state, &vault, true).await?;

                        println!("✓ Authority created, key in the vault.");
                        println!();
                        println!("Then, for each node:");
                        println!("  hlb pki agent <node> --out /etc/hlb");
                        println!("  hlb pki controller --out /etc/hlb");
                        Ok(ExitCode::SUCCESS)
                    }

                    PkiCmd::Agent { node, out, service } => {
                        let Some(ca) = load_ca().await? else {
                            eprintln!("No authority: hlb pki init --apply");
                            return Ok(ExitCode::FAILURE);
                        };

                        let names = pki::agent_names(node, service);
                        let c = pki::issue(&ca, node, &names, Purpose::Server).await?;

                        std::fs::create_dir_all(out)?;
                        write_pem(&out.join(format!("{node}.crt")), &c.cert_pem)?;
                        write_pem(&out.join(format!("{node}.key")), &c.key_pem)?;
                        write_pem(&out.join("ca.crt"), &ca.cert_pem)?;

                        println!("✓ certificate issued for {node} ({} days)", pki::LEAF_DAYS);
                        println!("  names: {}", names.join(", "));
                        println!();
                        println!("  On the node:");
                        println!("    hlb-agent --cert {node}.crt --key {node}.key --ca ca.crt");
                        println!();
                        println!("  ⚠️  The private key is mode 600. It must not travel over");
                        println!("     a cleartext channel.");
                        Ok(ExitCode::SUCCESS)
                    }

                    PkiCmd::Controller { out } => {
                        let Some(ca) = load_ca().await? else {
                            eprintln!("No authority: hlb pki init --apply");
                            return Ok(ExitCode::FAILURE);
                        };

                        let c =
                            pki::issue(&ca, "controller", &["controller".into()], Purpose::Client)
                                .await?;

                        std::fs::create_dir_all(out)?;
                        // reqwest expects the certificate AND the key in the same PEM.
                        write_pem(
                            &out.join("controller.pem"),
                            &format!("{}{}", c.cert_pem, c.key_pem),
                        )?;
                        write_pem(&out.join("ca.crt"), &ca.cert_pem)?;

                        println!("✓ client certificate issued ({} days)", pki::LEAF_DAYS);
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
                let state = open_state(&cli).await?;
                let vault = open_vault(&cli)?;

                let (host, user, port, identity) = match cmd {
                    AccessCmd::Grant {
                        host,
                        user,
                        port,
                        identity,
                        ..
                    }
                    | AccessCmd::Revoke {
                        host,
                        user,
                        port,
                        identity,
                        ..
                    }
                    | AccessCmd::List {
                        host,
                        user,
                        port,
                        identity,
                    } => (host, user.as_deref(), *port, identity.as_deref()),
                };

                let ssh = ssh_runner(host, user, port, identity);
                let before = access::read_authorized_keys(&ssh, "~").await?;

                match cmd {
                    AccessCmd::List { .. } => {
                        let managed = access::list_managed(&before);
                        let total = before
                            .lines()
                            .filter(|l| {
                                let l = l.trim();
                                !l.is_empty() && !l.starts_with('#')
                            })
                            .count();

                        println!(
                            "{host} — {} in authorized_keys",
                            hlb_api::plural(total as u64, "key", "keys")
                        );
                        if managed.is_empty() {
                            println!("  none managed by Homelabus");
                        } else {
                            for c in &managed {
                                println!("  managed by Homelabus (cluster \"{c}\")");
                            }
                        }
                        println!(
                            "  {}, which are never touched",
                            hlb_api::plural(
                                (total - managed.len()) as u64,
                                "human key",
                                "human keys"
                            )
                        );
                        Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS)
                    }

                    AccessCmd::Grant { apply, .. } => {
                        let kp = cluster_ssh_key(&state, &vault).await?;
                        let key = access::ManagedKey::new(&kp.public, "hlb");
                        let (after, ch) = access::grant(&before, &key);

                        if ch.is_noop() {
                            println!("✓ already in place — nothing to do.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        if !*apply {
                            println!("Would install Homelabus's key on {host}.");
                            println!("  {} added, {} replaced", ch.added, ch.removed);
                            println!(
                                "  {} PRESERVED",
                                hlb_api::plural(ch.kept as u64, "existing key", "existing keys")
                            );
                            println!("\n  Re-run with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        access::write_authorized_keys(&ssh, "~", &after, &before).await?;
                        state
                            .audit("cli", ACTOR_ROLE, "access-grant", host, "ok", None)
                            .await?;
                        println!(
                            "✓ key installed ({} kept)",
                            hlb_api::plural(ch.kept as u64, "key", "keys")
                        );
                        Ok(ExitCode::SUCCESS)
                    }

                    AccessCmd::Revoke { apply, .. } => {
                        let kp = cluster_ssh_key(&state, &vault).await?;
                        let key = access::ManagedKey::new(&kp.public, "hlb");
                        let (after, ch) = access::revoke(&before, &key);

                        if ch.is_noop() {
                            println!("✓ no Homelabus key on {host} — nothing to remove.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        if !*apply {
                            println!("Would remove Homelabus's key from {host}.");
                            println!(
                                "  {} PRESERVED",
                                hlb_api::plural(ch.kept as u64, "human key", "human keys")
                            );
                            println!();
                            println!("  🔴 After that, Homelabus can no longer drive this");
                            println!("     machine: no update, no backup, no reconciliation.");
                            println!("     The node keeps running.");
                            println!("\n  Re-run with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        access::write_authorized_keys(&ssh, "~", &after, &before).await?;
                        state
                            .audit("cli", ACTOR_ROLE, "access-revoke", host, "ok", None)
                            .await?;
                        println!(
                            "✓ key removed ({} untouched)",
                            hlb_api::plural(ch.kept as u64, "human key", "human keys")
                        );
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::Mesh(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let vault = open_vault(&cli)?;

                let mut mesh = load_mesh(&state, &vault).await?;

                match cmd {
                    MeshCmd::List => {
                        let pairs: Vec<_> = mesh.peers().collect();
                        if pairs.is_empty() {
                            println!("No node in the mesh.");
                            println!("  hlb mesh add <node> --endpoint <public-ip> --apply");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                        }

                        println!(
                            "Mesh {} — {}",
                            mesh.cidr(),
                            hlb_api::plural(pairs.len() as u64, "node", "nodes")
                        );
                        for p in &pairs {
                            println!(
                                "  {:<15} {}  {}",
                                p.mesh_ip.to_string(),
                                p.name,
                                match &p.endpoint {
                                    Some(e) => format!("↔ {e}:{}", mesh.port()),
                                    None => "(behind NAT)".to_string(),
                                }
                            );
                        }

                        if pairs.iter().all(|p| p.endpoint.is_none()) {
                            println!();
                            println!("🔴 No node has a public address: nobody can initiate a");
                            println!("   tunnel. The mesh will never come up.");
                            return Ok(ExitCode::FAILURE);
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    MeshCmd::Show { node } => {
                        let Some(ct) = state.secret(&format!("mesh-key-{node}")).await? else {
                            eprintln!("Node \"{node}\" is not in the mesh.");
                            eprintln!("  hlb mesh add {node} --apply");
                            return Ok(ExitCode::FAILURE);
                        };
                        let private = vault.decrypt(&ct)?;

                        match mesh.render_for(node, &private) {
                            Some(c) => {
                                println!("{c}");
                                println!(
                                    "# Drop this at /etc/wireguard/hlb0.conf on {node}, then:"
                                );
                                println!("#   chmod 600 /etc/wireguard/hlb0.conf");
                                println!("#   systemctl enable --now wg-quick@hlb0");
                                println!("#");
                                println!("# 🔴 Then make Swarm listen on the mesh address:");
                                println!(
                                    "#   --advertise-addr {}",
                                    mesh.advertise_addr_for(node).unwrap_or_default()
                                );
                                println!("#   Without that, ports 2377/7946/4789 stay exposed on");
                                println!("#   the public interface — and 4789 has NO");
                                println!("#   authentication at all.");
                                Ok(ExitCode::SUCCESS)
                            }
                            None => {
                                eprintln!(
                                    "Inconsistent topology: \"{node}\" has a key but no peer."
                                );
                                Ok(ExitCode::FAILURE)
                            }
                        }
                    }

                    MeshCmd::Add {
                        node,
                        endpoint,
                        apply,
                    } => {
                        if mesh.get(node).is_some() {
                            println!("✓ \"{node}\" is already in the mesh.");
                            println!("  hlb mesh show {node}   # its configuration");
                            return Ok(ExitCode::SUCCESS);
                        }

                        if !apply {
                            println!("Would add \"{node}\" to mesh {}.", mesh.cidr());
                            match endpoint {
                                Some(e) => println!("  reachable at {e}:{}", mesh.port()),
                                None => {
                                    println!(
                                        "  ⚠️  without --endpoint: node treated as behind NAT."
                                    );
                                    println!(
                                        "     It will not listen and must initiate its tunnels."
                                    );
                                    println!("     At least ONE node must have a public address.");
                                }
                            }
                            println!();
                            println!("  A key pair will be generated; the private one goes to the");
                            println!("  vault and only comes out for `hlb mesh show`.");
                            println!();
                            println!("  Re-run with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        let pair =
                            mesh_member(&state, &vault, &mut mesh, node, endpoint.clone(), None)
                                .await?;

                        println!("✓ \"{node}\" added to the mesh at {}", pair.mesh_ip);
                        println!();
                        println!("  hlb mesh show {node}    # its wg-quick configuration");
                        println!();
                        println!("⚠️  The OTHER nodes' configurations have changed: they must");
                        println!("   know this new peer, or it stays unreachable from them.");
                        println!("     hlb mesh sync --apply");
                        println!("   `hlb node add` does all of this on its own.");
                        Ok(ExitCode::SUCCESS)
                    }

                    MeshCmd::Remove { node, apply } => {
                        let Some(peer) = mesh.get(node).cloned() else {
                            eprintln!("Node \"{node}\" is not in the mesh.");
                            return Ok(ExitCode::FAILURE);
                        };
                        if *node == local_hostname().await {
                            eprintln!("🔴 {node} is this machine: its tunnels carry this command.");
                            return Ok(ExitCode::FAILURE);
                        }
                        // Out of the mesh, a node still in the Swarm loses its tunnels:
                        // its tasks stop reaching the overlay, and nothing says why.
                        let orch = match SwarmOrchestrator::connect().await {
                            Ok(o) => o,
                            Err(e) => {
                                eprintln!("🔴 Swarm unreachable ({e}): whether {node} is still a");
                                eprintln!("   node of it cannot be told. Not removed.");
                                return Ok(ExitCode::FAILURE);
                            }
                        };
                        let nodes = orch.nodes().await?;
                        if nodes.iter().any(|n| n.hostname == *node) {
                            eprintln!("🔴 {node} is still a node of the Swarm. Once it has left");
                            eprintln!("   (`docker swarm leave` there), remove it, then run this again:");
                            eprintln!("     docker node rm {node}");
                            return Ok(ExitCode::FAILURE);
                        }
                        mesh.remove_node(node);
                        if !apply {
                            println!("Would take {node} ({}) out of the mesh:", peer.mesh_ip);
                            println!("  its private key forgotten, and every other node told:");
                            for p in mesh.peers() {
                                println!(
                                    "  {:<15} {}  {}",
                                    p.mesh_ip.to_string(),
                                    p.name,
                                    p.ssh.as_deref().unwrap_or("(this machine, or by hand)")
                                );
                            }
                            println!("\n  Its address is free for the next node.");
                            disk::print_rebinds(
                                &disk::rebinds(&nodes, None, Some(node)),
                                None,
                                Some(node),
                            );
                            println!("\n  Re-run with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        save_mesh(&state, &vault, &mesh).await?;
                        state.forget_secret(&format!("mesh-key-{node}")).await?;
                        state
                            .audit("cli", ACTOR_ROLE, "mesh-remove", node, "ok", None)
                            .await?;
                        println!("✓ {node} taken out of the mesh. The others, told:");
                        let mut failed = 0;
                        for (n, r) in sync_mesh(&state, &vault, &mesh, &[]).await? {
                            match r {
                                Ok(()) => println!("  ✓ {n}"),
                                Err(e) => {
                                    failed += 1;
                                    println!("  🔴 {n}: {e}");
                                }
                            }
                        }
                        // After the mesh: whoever reads this must not stop at the tunnels.
                        let orphaned = disk::print_rebinds(
                            &disk::rebinds(&nodes, None, Some(node)),
                            None,
                            Some(node),
                        );
                        if failed > 0 {
                            println!("\n  Those still list {node} until `hlb mesh sync --apply` reaches them.");
                            return Ok(ExitCode::FAILURE);
                        }
                        Ok(if orphaned {
                            ExitCode::FAILURE
                        } else {
                            ExitCode::SUCCESS
                        })
                    }

                    MeshCmd::Sync { apply } => {
                        let peers: Vec<_> = mesh.peers().collect();
                        if peers.is_empty() {
                            println!("No node in the mesh.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        if !apply {
                            println!("Would push its configuration to every node of the mesh:");
                            for p in &peers {
                                println!(
                                    "  {:<15} {}  {}",
                                    p.mesh_ip.to_string(),
                                    p.name,
                                    p.ssh.as_deref().unwrap_or("(this machine, or by hand)")
                                );
                            }
                            println!("\n  A live interface is synchronised, never restarted.");
                            println!("  Re-run with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        let results = sync_mesh(&state, &vault, &mesh, &[]).await?;
                        let mut failed = 0;
                        for (node, r) in &results {
                            match r {
                                Ok(()) => println!("  ✓ {node}"),
                                Err(e) => {
                                    failed += 1;
                                    println!("  🔴 {node}: {e}");
                                }
                            }
                        }
                        state
                            .audit(
                                "cli",
                                ACTOR_ROLE,
                                "mesh-sync",
                                "mesh",
                                if failed == 0 { "ok" } else { "partial" },
                                None,
                            )
                            .await?;
                        Ok(if failed == 0 {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::FAILURE
                        })
                    }
                }
            })
        }

        Command::Crowdsec(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                use hlb_ingress::crowdsec::{self, Cscli};
                let state = open_state(&cli).await?;

                match cmd {
                    CrowdsecCmd::Status { service } => {
                        let in_vault = state.secret(crowdsec::SECRET_NAME).await?.is_some();
                        let cscli = Cscli::new(service);
                        let enrolled = cscli.is_enrolled().await;

                        println!("CrowdSec bouncer \"{}\"", crowdsec::BOUNCER_NAME);
                        println!(
                            "  enrolled with CrowdSec : {}",
                            match &enrolled {
                                Ok(true) => "yes".to_string(),
                                Ok(false) => "NO".to_string(),
                                Err(e) => format!("undetermined ({e})"),
                            }
                        );
                        println!(
                            "  key in the vault       : {}",
                            if in_vault { "yes" } else { "NO" }
                        );
                        println!();

                        match (enrolled.unwrap_or(false), in_vault) {
                            (true, true) => {
                                println!("✓ Filtering can be applied.");
                                println!("  It only really is after an `hlb ingress --apply`.");
                            }
                            (true, false) => {
                                // 🔴 The worst case: CrowdSec believes it has a bouncer,
                                // and nobody holds its key.
                                println!("🔴 Bouncer enrolled but key ABSENT from the vault.");
                                println!("   It is only shown at creation: it is lost.");
                                println!("   Delete the bouncer then re-enroll:");
                                println!("     cscli bouncers delete {}", crowdsec::BOUNCER_NAME);
                                println!("     hlb crowdsec enroll --apply");
                                return Ok(ExitCode::FAILURE);
                            }
                            (false, _) => {
                                // 🔴 The silent case: CrowdSec detects everything and
                                // blocks nothing. No error anywhere.
                                println!("🔴 No bouncer: CrowdSec DETECTS but BLOCKS nothing.");
                                println!("   Alerts pile up, nobody gets banned.");
                                println!("     hlb crowdsec enroll --apply");
                                return Ok(ExitCode::FAILURE);
                            }
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    CrowdsecCmd::Enroll {
                        service,
                        url,
                        apply,
                    } => {
                        let url = url.clone();
                        let recorded = state.crowdsec_url().await?;
                        let url_moves = url.is_some() && url != recorded;
                        if state.secret(crowdsec::SECRET_NAME).await?.is_some() {
                            if let (true, Some(u)) = (url_moves, &url) {
                                if !apply {
                                    println!(
                                        "Would point the bouncer at {u}. Re-run with --apply."
                                    );
                                    return Ok(ExitCode::SUCCESS);
                                }
                                state.set_crowdsec_url(Some(u)).await?;
                                state
                                    .audit("cli", ACTOR_ROLE, "crowdsec-url", u, "ok", None)
                                    .await?;
                                println!("✓ The bouncer asks {u} from the next publication.");
                                println!("  hlb ingress --apply");
                                return Ok(ExitCode::SUCCESS);
                            }
                            println!("✓ A bouncer key is already in the vault.");
                            println!("  Re-enrolling would create a second one, with no way to");
                            println!("  tell which is in use.");
                            println!("  hlb crowdsec status  # to check the real state");
                            return Ok(ExitCode::SUCCESS);
                        }

                        if !apply {
                            println!(
                                "Would enroll bouncer \"{}\" with CrowdSec.",
                                crowdsec::BOUNCER_NAME
                            );
                            if let Some(u) = &url {
                                println!("  It will ask {u}.");
                            }
                            println!();
                            println!("  Its key goes to the vault. It is only shown once:");
                            println!("  losing it means deleting the bouncer and starting");
                            println!("  over.");
                            println!();
                            println!("  ⚠️  The front Caddy must be an image built with");
                            println!("     github.com/hslatman/caddy-crowdsec-bouncer. A standard");
                            println!("     Caddy image refuses to start on the directive.");
                            println!();
                            println!("  Re-run with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        let key = Cscli::new(service).enroll().await?;
                        if !crowdsec::looks_like_key(&key) {
                            eprintln!("cscli returned something that is not a key:");
                            eprintln!("  \"{key}\"");
                            eprintln!();
                            eprintln!("Nothing is recorded: an invalid key would produce a valid");
                            eprintln!("Caddyfile that no longer blocks anything.");
                            return Ok(ExitCode::FAILURE);
                        }

                        let vault = open_vault(&cli)?;
                        if url_moves {
                            state.set_crowdsec_url(url.as_deref()).await?;
                        }
                        state
                            .store_secret_if_absent(
                                crowdsec::SECRET_NAME,
                                &vault.encrypt(&key)?,
                                "CrowdSec bouncer key on the front",
                            )
                            .await?;
                        state
                            .audit(
                                "cli",
                                ACTOR_ROLE,
                                "crowdsec-enroll",
                                crowdsec::BOUNCER_NAME,
                                "ok",
                                None,
                            )
                            .await?;

                        println!("✓ Bouncer enrolled, key in the vault.");
                        println!();
                        println!("Filtering is not active for all that: regenerate the ingress.");
                        println!("  hlb ingress --apply");
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::SecretSet {
            name,
            purpose,
            rotate,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let vault = open_vault(&cli)?;

                let exists = state.secret(name).await?.is_some();
                if exists && !rotate {
                    eprintln!("Secret \"{name}\" already exists.");
                    eprintln!();
                    eprintln!("🔴 Overwriting it can break whatever uses it: a password");
                    eprintln!("   changed in the vault is not changed in the running service.");
                    eprintln!("   If that is intended: --rotate");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                }

                println!("Value of \"{name}\" (standard input, Ctrl-D to finish):");
                let mut value = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut value)?;
                let value = value.trim();

                if value.is_empty() {
                    eprintln!("Empty value — nothing was recorded.");
                    return Ok(ExitCode::FAILURE);
                }

                let ct = vault.encrypt(value)?;
                if exists {
                    state.rotate_secret(name, &ct).await?;
                    println!("✓ \"{name}\" replaced.");
                } else {
                    state.store_secret_if_absent(name, &ct, purpose).await?;
                    println!("✓ \"{name}\" recorded.");
                }

                // The name and the purpose go to the audit log, never the value.
                state
                    .audit("cli", ACTOR_ROLE, "secret-set", name, "ok", Some(purpose))
                    .await?;
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::SecretGet { name } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let vault = open_vault(&cli)?;
                let Some(ct) = state.secret(name).await? else {
                    eprintln!("No secret \"{name}\" — `hlb secrets` lists them.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                };
                let value = vault.decrypt(&ct)?;
                // Recorded BEFORE it is shown: a read that leaves no trace is the one an
                // intruder with a shell would make.
                state
                    .audit("cli", ACTOR_ROLE, "secret-read", name, "ok", None)
                    .await?;
                println!("{value}");
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::SecretsForget {
            app,
            confirm,
            apply,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let installed = state
                    .installed_apps()
                    .await?
                    .into_iter()
                    .any(|(n, _)| &n == app);
                if installed {
                    eprintln!("🔴 \"{app}\" is installed: it runs on these secrets.");
                    eprintln!("   `hlb remove {app}` first.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                }
                if !state.app_was_removed(app).await? {
                    eprintln!("🔴 The audit log holds no record of \"{app}\" being removed.");
                    eprintln!("   Nothing says these names were an app's: nothing was deleted.");
                    return Ok(ExitCode::FAILURE);
                }

                let secrets = hlb_engine::removal::secrets_left(&state, app).await?;
                let leftovers = hlb_engine::removal::leftovers_in(&state, app, &secrets).await?;
                if secrets.is_empty() && leftovers.is_empty() {
                    println!("Nothing of \"{app}\" is left in the vault or its services.");
                    return Ok(ExitCode::SUCCESS);
                }
                println!("Forgetting what \"{app}\" left\n");
                for name in &secrets {
                    println!("  · {name}");
                }
                let apps: Vec<String> = state
                    .installed_apps()
                    .await?
                    .into_iter()
                    .map(|(name, _)| name)
                    .collect();
                for leftover in &leftovers {
                    println!("  · {}", leftover.said(app, &apps));
                }
                if !secrets.is_empty() {
                    println!(
                        "\n🔴 A reinstall draws new ones: a volume or a backup kept from before \
                         may no longer open."
                    );
                }
                for line in hlb_engine::removal::forget_warnings(app, &secrets) {
                    println!("   {line}");
                }

                if !*apply {
                    println!("\nPreview: nothing was done.");
                    println!("  hlb secrets-forget {app} --confirm {app} --apply");
                    return Ok(ExitCode::SUCCESS);
                }
                if confirm.as_deref() != Some(app.as_str()) {
                    eprintln!("\n🔴 Confirmation missing: --confirm {app}");
                    return Ok(ExitCode::FAILURE);
                }

                println!();
                let mut stay: Vec<String> = Vec::new();
                let mut unfinished = false;
                let mut callback_stays = false;
                if !leftovers.is_empty() {
                    let vault = open_vault(&cli)?;
                    let identity = match (&cli.pocketid_url, &cli.pocketid_key) {
                        (Some(u), Some(k)) => Some(hlb_identity::PocketId::new(
                            relay::reach(u, &cli.platform_network),
                            k,
                        )),
                        _ => None,
                    };
                    let objstore = match (&cli.garage_url, &cli.garage_token) {
                        (Some(u), Some(t)) => Some(hlb_objstore::Garage::new(
                            relay::reach(u, &cli.platform_network),
                            t.clone(),
                        )),
                        _ => None,
                    };
                    let mail = mail_admin(&cli);
                    let services = hlb_engine::removal::Services {
                        identity: identity.as_ref(),
                        objstore: objstore.as_ref(),
                        mail: mail.as_ref(),
                    };
                    // The other half first, each secret only once it is gone: forgotten
                    // first, a refusal here would leave the door the secret opened and
                    // nothing to resume with.
                    for leftover in &leftovers {
                        let taken =
                            hlb_engine::removal::take(leftover, app, &state, &vault, services)
                                .await?;
                        let (outcome, line) = match &taken {
                            hlb_engine::removal::Taken::Gone(line) => ("ok", line),
                            hlb_engine::removal::Taken::Stays(line) => ("refused", line),
                        };
                        state
                            .audit(
                                "cli",
                                ACTOR_ROLE,
                                "leftover-forget",
                                app,
                                outcome,
                                Some(line),
                            )
                            .await?;
                        match taken {
                            hlb_engine::removal::Taken::Gone(_) => println!("✓ {line}"),
                            hlb_engine::removal::Taken::Stays(_) => {
                                eprintln!("🔴 {} stays: {line}", leftover.named(app));
                                stay.extend(leftover.secrets(app));
                                unfinished = true;
                                callback_stays |= matches!(
                                    leftover,
                                    hlb_engine::removal::Leftover::PortalCallback { .. }
                                );
                            }
                        }
                    }
                }
                for name in secrets.iter().filter(|name| !stay.contains(name)) {
                    state.forget_secret(name).await?;
                    state
                        .audit("cli", ACTOR_ROLE, "secret-forget", name, "ok", Some(app))
                        .await?;
                    println!("✓ {name} deleted");
                }
                if !callback_stays {
                    state.clear_removed_domains(app).await?;
                }
                if unfinished {
                    eprintln!(
                        "\n🔴 Not finished: what opens the above stays in the vault. Run it again."
                    );
                    return Ok(ExitCode::FAILURE);
                }
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::SecretsRekey {
            new_key,
            controller_stopped: _,
            apply,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let old = Vault::open(&cli.master_key)?;
                let entries = state.all_ciphertexts().await?;

                println!("Rekeying the vault\n");
                println!("  old key  {}", cli.master_key.display());
                println!("  new key  {}", new_key.display());
                println!(
                    "  {}\n",
                    hlb_api::plural(entries.len() as u64, "secret", "secrets")
                );

                if entries.is_empty() {
                    // Nothing to re-encrypt: rekeying reduces to generating a key, and
                    // `hlb secrets` already does that on first use. Say so rather than
                    // perform an impressive no-op.
                    println!("Nothing to re-encrypt. A new key would protect nothing yet.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                }

                // 🔴 STEP 1, before touching anything: decrypt everything with the old
                // key. A secret that will not open must stop the procedure HERE, while
                // the vault is still whole — discovering it halfway through leaves half
                // the entries under each key, which nothing can sort out afterwards.
                let mut clear = Vec::with_capacity(entries.len());
                for (name, ciphertext) in &entries {
                    match old.decrypt(ciphertext) {
                        Ok(v) => clear.push((name.clone(), v)),
                        Err(e) => {
                            eprintln!("🔴 \"{name}\" does not open with this key: {e}");
                            eprintln!("\nNothing was changed. Check --master-key first.");
                            return Ok(ExitCode::FAILURE);
                        }
                    }
                }
                println!("✓ all {} secrets open with the old key", clear.len());

                // 🔴 The daemon writes secrets (installs, rotations, the nightly
                // passes) under the key it read at start. Running, it races the rewrite
                // and keeps writing under the old key after it. The web service too, in
                // case it is one deployed before the split: that one runs the daemon.
                let holders = [
                    hlb_engine::pki::DAEMON_SERVICE,
                    hlb_engine::ingress::CONTROLLER_SERVICE,
                ];
                let mut running = Vec::new();
                if let Ok(orch) = SwarmOrchestrator::connect().await {
                    for service in holders {
                        if orch
                            .status(service)
                            .await
                            .is_ok_and(|s| s.desired_replicas > 0)
                        {
                            running.push(service);
                        }
                    }
                }
                if !running.is_empty() {
                    let names = running.join(" and ");
                    eprintln!("\n🔴 {names} running: it would write secrets under the old key.");
                    for service in running {
                        eprintln!("   hlb stop {service} --apply");
                    }
                    eprintln!("   then run this again.");
                    return Ok(ExitCode::FAILURE);
                }

                if !*apply {
                    println!("\nPreview: nothing was changed.");
                    println!(
                        "  hlb secrets-rekey --new-key {} --controller-stopped --apply",
                        new_key.display()
                    );
                    return Ok(ExitCode::SUCCESS);
                }

                // STEP 2: the new key, at its own path. `init` refuses to overwrite,
                // which is the protection we want: pointing --new-key at the current
                // key would destroy the only thing that opens the vault.
                let new = Vault::init(new_key)?;
                println!("✓ new key written to {}", new_key.display());

                // STEP 3: re-encrypt, then write in ONE transaction.
                let mut rewritten = Vec::with_capacity(clear.len());
                for ((name, value), (_, read)) in clear.iter().zip(&entries) {
                    rewritten.push((name.clone(), read.clone(), new.encrypt(value)?));
                }
                if let Err(e) = state.rewrite_ciphertexts(&rewritten).await {
                    // The new key opens nothing: left in place, it would be taken for
                    // the one the vault is under.
                    let _ = std::fs::remove_file(new_key);
                    eprintln!("🔴 {e}");
                    state
                        .audit(
                            "cli",
                            ACTOR_ROLE,
                            "secrets-rekey",
                            "vault",
                            "failed",
                            Some(&e.to_string()),
                        )
                        .await?;
                    return Ok(ExitCode::FAILURE);
                }
                state
                    .audit(
                        "cli",
                        ACTOR_ROLE,
                        "secrets-rekey",
                        "vault",
                        "ok",
                        Some(&format!("{} secrets", rewritten.len())),
                    )
                    .await?;
                println!("✓ {} secrets re-encrypted", rewritten.len());

                // 🔴 STEP 4 is YOURS, and it is deliberate. Swapping the key file here
                // would leave a window where the database is under the new key and the
                // file on disk is the old one — every service reading the vault fails,
                // and the fix is a move nobody documented.
                println!("\n🔴 The vault is now under the NEW key. Finish the procedure:");
                // 🔴 A sealed key's path is a link into memory: moved, `.old` would be
                // that link, and sealing the new key empties what it points at.
                let sealed = hlb_secrets::sealed_target(&cli.master_key).is_some();
                println!(
                    "  1. {} {} {}.old",
                    if sealed { "cp" } else { "mv" },
                    cli.master_key.display(),
                    cli.master_key.display()
                );
                println!("  2. mv {} {}", new_key.display(), cli.master_key.display());
                println!(
                    "  3. start the daemon again (hlb scale {} 1 --apply), the web side \
                     (hlb scale {} 1 --apply) and the agents",
                    hlb_engine::pki::DAEMON_SERVICE,
                    hlb_engine::ingress::CONTROLLER_SERVICE
                );
                // Moved over the link, the new key is a plain file again.
                if sealed {
                    println!("  4. seal the new key: hlb secrets-seal --apply");
                }
                println!(
                    "\n⚠️  Keep {}.old until a restore has been verified: it is what \
                     opens the backups taken before today.",
                    cli.master_key.display()
                );
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::Config(ConfigCmd::Timezone { zone, apply }) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let Some(zone) = zone else {
                    match state.timezone().await? {
                        Some(z) => println!("{z}"),
                        None => println!(
                            "No time zone set: an app reading {{{{ timezone }}}} cannot be \
                             installed. hlb config timezone Europe/Paris --apply"
                        ),
                    }
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                };
                if !hlb_types::binding::is_time_zone(zone) {
                    eprintln!(
                        "🔴 \"{zone}\" is not a time zone the tz database knows: Area/City, \
                         as Europe/Paris, or UTC."
                    );
                    return Ok(ExitCode::FAILURE);
                }
                if !*apply {
                    println!("Would set the installation's time zone to {zone}.");
                    println!("Rerun with --apply.");
                    return Ok(ExitCode::SUCCESS);
                }
                state.set_timezone(zone).await?;
                state
                    .audit("cli", ACTOR_ROLE, "config-timezone", zone, "ok", None)
                    .await?;
                println!("✓ Time zone {zone}.");
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::Config(ConfigCmd::Reboots {
            window,
            never,
            accept_downtime,
            refuse_downtime,
            apply,
        }) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(config_reboots(
                &cli,
                window.as_deref(),
                *never,
                *accept_downtime,
                *refuse_downtime,
                *apply,
            ))
        }

        Command::Config(ConfigCmd::Ups {
            server,
            ups,
            after,
            runtime,
            steady,
            off,
            apply,
        }) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(config_ups(
                &cli,
                UpsChange {
                    server: server.as_deref(),
                    ups: ups.as_deref(),
                    after: *after,
                    runtime: *runtime,
                    steady: *steady,
                    off: *off,
                },
                *apply,
            ))
        }

        Command::Config(ConfigCmd::Exposure {
            domain,
            email,
            dns,
            internal,
            staging,
            production,
            interface,
            node,
            acme_ca,
            acme_ca_root,
            root,
            apply,
        }) => {
            let acme_ca_root = match acme_ca_root {
                Some(p) => Some(std::fs::read_to_string(p)?),
                None => None,
            };
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(exposure::run(
                &cli,
                exposure::Request {
                    acme_ca: acme_ca.as_deref(),
                    acme_ca_root,
                    root: *root,
                    domain: domain.as_deref(),
                    email: email.as_deref(),
                    dns: dns.as_deref(),
                    internal: *internal,
                    staging: *staging,
                    production: *production,
                    interface: interface.as_deref(),
                    node: node.as_deref(),
                    apply: *apply,
                },
            ))
        }

        Command::Config(ConfigCmd::Appearance {
            name,
            product,
            accent,
            footer,
            theme,
            logo,
            remove_logo,
            apply,
        }) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;

                if logo.is_some() && *remove_logo {
                    eprintln!("🔴 --logo and --remove-logo cannot be combined.");
                    return Ok(ExitCode::FAILURE);
                }
                // ⚠️ Prepared here too, not only inside `set_logo` on `--apply`: an
                // SVG rasterizes to a DIFFERENT byte count than the file on disk, and
                // the preview below must show the size that will actually be stored,
                // not the source file's — printing the wrong number would make a
                // logo that gets refused on `--apply` look accepted in preview.
                let logo_bytes = match logo {
                    Some(path) => match std::fs::read(path) {
                        Ok(b) => match hlb_state::prepare_logo(&b) {
                            Ok(png) => Some(png),
                            Err(e) => {
                                eprintln!("🔴 logo: {e}");
                                return Ok(ExitCode::FAILURE);
                            }
                        },
                        Err(e) => {
                            eprintln!("🔴 \"{}\": {e}", path.display());
                            return Ok(ExitCode::FAILURE);
                        }
                    },
                    None => None,
                };

                // 🔴 Read-modify-write. Writing a fresh Brand would blank every field
                // the caller did not name — you set the footer and lose the house name,
                // on the screen that exists to prove the page is yours.
                let mut m = state.brand().await?;

                // The installation's declared themes: an accent is checked against them
                // and a default theme may name one, exactly as the controller does.
                let declared = hlb_catalog::themes::load(std::path::Path::new(
                    &std::env::var("HLB_THEMES").unwrap_or_else(|_| "themes".into()),
                ));

                if let Some(v) = name {
                    m.name = v.clone();
                }
                if let Some(v) = product {
                    m.product = v.clone();
                }
                if let Some(v) = footer {
                    m.footer = Some(v.clone());
                }
                if let Some(v) = accent {
                    let hex = v.trim_start_matches('#');
                    let Ok(bytes) = u32::from_str_radix(hex, 16) else {
                        eprintln!("🔴 accent \"{v}\": expected RRGGBB in hexadecimal.");
                        return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                    };
                    if hex.len() != 6 {
                        eprintln!("🔴 accent \"{v}\": expected six hex digits.");
                        return Ok(ExitCode::FAILURE);
                    }
                    m.accent = Some([
                        ((bytes >> 16) & 0xFF) as u8,
                        ((bytes >> 8) & 0xFF) as u8,
                        (bytes & 0xFF) as u8,
                    ]);
                    // 🔴 The controller's check, on the same palettes: an accent refused
                    // over HTTP must not get in through the terminal.
                    let shipped = hlb_api::THEMES
                        .iter()
                        .filter_map(|n| hlb_api::palette::Palette::shipped(n).map(|p| (*n, p)));
                    let own = declared
                        .themes
                        .iter()
                        .filter_map(|t| t.palette().map(|p| (t.name.as_str(), p)));
                    let problems = m.accent_problems(shipped.chain(own));
                    if !problems.is_empty() {
                        eprintln!("🔴 accent \"{v}\" would make states indistinguishable:");
                        for p in problems {
                            eprintln!("   {p}");
                        }
                        return Ok(ExitCode::FAILURE);
                    }
                }
                if let Some(v) = theme {
                    // ⚠️ An unknown theme is REFUSED, never stored: accepted, it would
                    // fall back to the default on display and you would think the
                    // choice was lost to a bug.
                    //
                    // 🔴 Shipped ∪ declared, not just shipped. This command writes the
                    // installation's default, and an installation that declared its own
                    // theme in a file must be able to make it the default — refusing it
                    // here while the controller happily serves it is the two-halves
                    // disagreement this whole feature has to avoid.
                    let known: Vec<String> = hlb_api::THEMES
                        .iter()
                        .map(|t| t.to_string())
                        .chain(declared.themes.iter().map(|t| t.name.clone()))
                        .collect();
                    if !known.iter().any(|k| k.eq_ignore_ascii_case(v)) {
                        eprintln!("🔴 unknown theme \"{v}\". Available: {}", known.join(", "));
                        for r in &declared.refused {
                            // If a theme file was meant to provide this name and was
                            // refused, saying so here is the difference between "typo"
                            // and "my file is broken".
                            eprintln!("   ⚠️ {} refused: {}", r.file.display(), r.reason);
                        }
                        return Ok(ExitCode::FAILURE);
                    }
                    m.default_theme = Some(v.clone());
                }

                println!("  name    : {}", m.name);
                println!("  product : {}", m.product);
                match m.accent {
                    Some([r, g, b]) => println!("  accent  : {r:02X}{g:02X}{b:02X}"),
                    None => println!("  accent  : the theme's"),
                }
                println!("  footer  : {}", m.footer.as_deref().unwrap_or("none"));
                println!(
                    "  theme   : {}",
                    m.default_theme
                        .as_deref()
                        .unwrap_or("the interface's default")
                );
                println!(
                    "  logo    : {}",
                    match (*remove_logo, logo, &logo_bytes) {
                        (true, _, _) => "removed".to_string(),
                        (false, Some(path), Some(b)) =>
                            format!("{} ({} KB)", path.display(), b.len() / 1024),
                        (false, _, _) => "unchanged".to_string(),
                    }
                );

                if !*apply {
                    println!("\nPreview: nothing was changed.");
                    return Ok(ExitCode::SUCCESS);
                }
                state.set_brand(&m).await?;
                if *remove_logo {
                    state.set_logo(None).await?;
                } else if let Some(bytes) = &logo_bytes {
                    state.set_logo(Some(bytes)).await?;
                }
                state
                    .audit("cli", ACTOR_ROLE, "config-appearance", &m.name, "ok", None)
                    .await?;
                println!("\n✓ appearance saved");
                Ok(ExitCode::SUCCESS)
            })
        }

        Command::Alert(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let actor = std::env::var("USER").unwrap_or_else(|_| "cli".into());
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                // 🔴 An unknown rule is refused, never stored: it would silence nothing
                // while the real one kept notifying. Read from the rules, not a list.
                let known = |rule: &str| {
                    hlb_metrics::rules::default_rules()
                        .iter()
                        .any(|r| r.name == rule)
                };
                match cmd {
                    AlertCmd::Mute {
                        rule,
                        duration,
                        reason,
                    } => {
                        if !known(rule) {
                            eprintln!("No alert rule is called \"{rule}\".");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                        }
                        let for_s = parse_duration(duration)?;
                        if for_s <= 0 || for_s > hlb_api::MUTE_MAX_S {
                            eprintln!(
                                "A mute lasts at most {} days: one with no end is a deleted alert.",
                                hlb_api::MUTE_MAX_S / 86_400
                            );
                            return Ok(ExitCode::FAILURE);
                        }
                        if reason.trim().is_empty() {
                            eprintln!(
                                "Say why: a mute nobody can explain is the one nobody dares lift."
                            );
                            return Ok(ExitCode::FAILURE);
                        }
                        state
                            .mute_alert(&hlb_api::AlertMute {
                                rule: rule.clone(),
                                until: now + for_s,
                                by: actor.clone(),
                                reason: reason.trim().to_string(),
                            })
                            .await?;
                        let detail = format!("{for_s} s: {}", reason.trim());
                        let _ = state
                            .audit(&actor, ACTOR_ROLE, "alert-mute", rule, "ok", Some(&detail))
                            .await;
                        println!(
                            "{rule} muted for {duration}. It stays listed, and notifies again \
                             when the mute ends."
                        );
                        Ok(ExitCode::SUCCESS)
                    }
                    AlertCmd::Unmute { rule } => {
                        if !state.unmute_alert(rule).await? {
                            eprintln!("\"{rule}\" is not muted.");
                            return Ok(ExitCode::FAILURE);
                        }
                        let _ = state
                            .audit(&actor, ACTOR_ROLE, "alert-unmute", rule, "ok", None)
                            .await;
                        println!("{rule} notifies again from the next evaluation.");
                        Ok(ExitCode::SUCCESS)
                    }
                    AlertCmd::Mutes => {
                        let mutes = state.alert_mutes(now).await?;
                        if mutes.is_empty() {
                            println!("No mute in force.");
                        }
                        for m in &mutes {
                            println!(
                                "  {:<24} {} min left, by {} — {}",
                                m.rule,
                                (m.until - now) / 60,
                                m.by,
                                m.reason
                            );
                        }
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::Announcement(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                // Written from the command line: the actor is whoever runs it, and the
                // audit trail says so rather than inventing a name.
                let author = std::env::var("USER").unwrap_or_else(|_| "cli".into());

                match cmd {
                    AnnouncementCmd::List => {
                        // Admin's view: everything, whatever its audience. The portal
                        // filters; the operator's console must not.
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        // Expired ones included: an operator's list that hides what has
                        // lapsed cannot tell you why the portal went quiet.
                        let all = state
                            .announcements(hlb_types::Role::Admin, now, true)
                            .await?;
                        if all.is_empty() {
                            println!("Nothing published.");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                        }
                        for a in &all {
                            println!("  #{:<4} [{}] {}", a.id, a.level.as_str(), a.title);
                            if !a.follow_ups.is_empty() {
                                println!(
                                    "        {}",
                                    hlb_api::plural(a.follow_ups.len() as u64, "update", "updates")
                                );
                            }
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    AnnouncementCmd::Publish {
                        title,
                        body,
                        level,
                        pinned,
                        audience,
                        apply,
                    } => {
                        let lvl = hlb_api::AnnouncementLevel::parse(level);
                        // 🔴 An unknown level parses to `info`, the LOWEST. Silently
                        // downgrading an incident is worse than refusing, so we check
                        // rather than trust the fallback.
                        if lvl.as_str() != level {
                            eprintln!(
                                "🔴 unknown level \"{level}\" — expected info, maintenance, \
                                 warning or incident."
                            );
                            return Ok(ExitCode::FAILURE);
                        }

                        let aud = match audience.as_deref() {
                            None => None,
                            Some(r) => match hlb_types::Role::parse(r) {
                                Some(role) => Some(role),
                                None => {
                                    eprintln!("🔴 unknown role \"{r}\".");
                                    return Ok(ExitCode::FAILURE);
                                }
                            },
                        };

                        println!("[{}] {title}", lvl.as_str());
                        println!("{body}\n");
                        match aud {
                            Some(r) => println!("  audience: {} and above", r.as_str()),
                            None => println!("  audience: everyone, portal included"),
                        }
                        if *pinned {
                            println!("  pinned to the top until removed");
                        }

                        if !*apply {
                            println!("\nPreview: nothing was published.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        let id = state
                            .publish_announcement(title, body, lvl, *pinned, aud, &author, None)
                            .await?;
                        state
                            .audit(
                                "cli",
                                ACTOR_ROLE,
                                "announcement",
                                title,
                                "ok",
                                Some(&format!("#{id}")),
                            )
                            .await?;
                        println!("\n✓ published as #{id}");
                        Ok(ExitCode::SUCCESS)
                    }

                    AnnouncementCmd::Follow { id, body, apply } => {
                        println!("Adding an update to #{id}:\n  {body}\n");
                        // ⚠️ Said explicitly: people expect "edit" and get "append".
                        println!("  The original message is untouched — this is added after it.");
                        if !*apply {
                            println!("\nPreview: nothing was added.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        state.follow_announcement(*id, body, &author).await?;
                        state
                            .audit(
                                "cli",
                                ACTOR_ROLE,
                                "announcement-follow-up",
                                &format!("#{id}"),
                                "ok",
                                None,
                            )
                            .await?;
                        println!("\n✓ added");
                        Ok(ExitCode::SUCCESS)
                    }

                    AnnouncementCmd::Remove { id, apply } => {
                        if !*apply {
                            println!("Would remove announcement #{id}.");
                            println!("  hlb announcement remove {id} --apply");
                            return Ok(ExitCode::SUCCESS);
                        }
                        if state.remove_announcement(*id).await? {
                            state
                                .audit(
                                    "cli",
                                    ACTOR_ROLE,
                                    "announcement-remove",
                                    &format!("#{id}"),
                                    "ok",
                                    None,
                                )
                                .await?;
                            println!("✓ #{id} removed");
                            Ok(ExitCode::SUCCESS)
                        } else {
                            eprintln!("🔴 no announcement #{id}.");
                            Ok(ExitCode::FAILURE)
                        }
                    }
                }
            })
        }

        Command::Storage(cmd) => {
            use hlb_bootstrap::zfs;

            if let StorageCmd::Encrypt {
                node,
                pool,
                root,
                host,
                user,
                port,
                apply,
            } = cmd
            {
                let rt = tokio::runtime::Runtime::new()?;
                return rt.block_on(storage::encrypt(
                    &cli,
                    storage::Target {
                        node,
                        pool: pool.as_deref(),
                        root,
                        host: host.as_deref(),
                        user: user.as_deref(),
                        port: *port,
                    },
                    *apply,
                ));
            }

            // Local only: the storage node is the machine you run this on. Driving it
            // over SSH would mean deciding which machine holds the pool from somewhere
            // that cannot see its disks.
            let runner = hlb_bootstrap::runner::LocalRunner;
            let rt = tokio::runtime::Runtime::new()?;

            rt.block_on(async {
                use hlb_bootstrap::runner::Runner as _;

                let (imported, importable) = match zfs::read_pools(&runner).await? {
                    Ok(pools) => pools,
                    Err(zfs::Unread::Missing) => {
                        eprintln!("🔴 `zpool` is not available on this machine.");
                        eprintln!("   ZFS is not installed, or this is not the storage node.");
                        eprintln!(
                            "   hlb node deps <host> --apply   installs it on a storage node"
                        );
                        return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                    }
                    Err(zfs::Unread::Failed(why)) => {
                        eprintln!("🔴 `zpool` failed, so what the disks hold is unknown:");
                        eprintln!("   {}", why.replace('\n', "\n   "));
                        return Ok(ExitCode::FAILURE);
                    }
                };

                match cmd {
                    StorageCmd::Status { pool } => {
                        println!("Pools on this machine\n");
                        if imported.is_empty() {
                            println!("  none imported");
                        }
                        for p in &imported {
                            println!("  {}", p.describe());
                        }
                        for p in &importable {
                            println!("  {p} is on the disks, not imported");
                        }
                        println!();
                        let d = zfs::PoolDecision::decide(&imported, &importable, pool.as_deref());
                        println!("{}", d.describe());
                        Ok(ExitCode::SUCCESS)
                    }

                    StorageCmd::Encrypt { .. } => unreachable!("handled above"),

                    StorageCmd::Init {
                        pool,
                        root,
                        unencrypted,
                        apply,
                    } => {
                        let d = zfs::PoolDecision::decide(&imported, &importable, pool.as_deref());
                        println!("{}\n", d.describe());

                        let name = match &d {
                            zfs::PoolDecision::Ready { pool } => pool.clone(),
                            zfs::PoolDecision::Importable { pool } => {
                                if !*apply {
                                    println!("Would import \"{pool}\", then create the datasets.");
                                    println!("  hlb storage init --pool {pool} --apply");
                                    return Ok(ExitCode::SUCCESS);
                                }
                                let o = runner
                                    .run(&["zpool".into(), "import".into(), pool.clone()])
                                    .await?;
                                if !o.ok() {
                                    eprintln!("🔴 import failed: {}", o.stderr.trim());
                                    return Ok(ExitCode::FAILURE);
                                }
                                println!("✓ pool \"{pool}\" imported");
                                pool.clone()
                            }
                            // 🔴 Never created from here. The command is printed with a
                            // placeholder for the disks: filling it in is a decision
                            // that destroys them, and it belongs to whoever knows which
                            // disks are spare.
                            zfs::PoolDecision::Absent => {
                                println!("To create one, name the disks yourself:");
                                println!("    zpool create -o ashift=12 tank mirror \\");
                                println!(
                                    "        /dev/disk/by-id/<disk-a> /dev/disk/by-id/<disk-b>"
                                );
                                println!();
                                println!(
                                    "  ⚠️  by-id, never /dev/sdX: the letters are assigned at"
                                );
                                println!(
                                    "     boot and change order. A pool built on /dev/sdb can"
                                );
                                println!("     come back pointing at the wrong disk.");
                                return Ok(ExitCode::FAILURE);
                            }
                            zfs::PoolDecision::Ambiguous { .. } => return Ok(ExitCode::FAILURE),
                        };

                        let base = format!("{name}/{root}");
                        println!("\nDatasets under {base}:");
                        // One dataset per app volume that the catalog declares.
                        let catalog = hlb_catalog::Catalog::load(&cli.catalog)?;
                        // With whether it is served over NFS: those belong to the
                        // NFS owner, the rest stay root's — PostgreSQL's image, for one,
                        // takes its own directory over at its first start.
                        let mut wanted: Vec<(String, bool)> = Vec::new();
                        for m in catalog.manifests() {
                            for c in &m.spec.requires {
                                // Another app's volume is its owner's dataset.
                                if let hlb_types::Capability::Storage {
                                    name: v,
                                    tier,
                                    owner: None,
                                    ..
                                } = c
                                {
                                    wanted.push((
                                        zfs::dataset_for(&base, &m.metadata.name, v),
                                        *tier == hlb_types::StorageTier::Nfs,
                                    ));
                                }
                            }
                            // A companion's volumes are local, named after it: what the
                            // engine binds on the pool, so what must exist there.
                            for c in &m.spec.companions {
                                for v in &c.storage {
                                    wanted.push((
                                        zfs::dataset_for(
                                            &base,
                                            &m.metadata.name,
                                            &format!("{}-{}", c.name, v.name),
                                        ),
                                        false,
                                    ));
                                }
                            }
                        }
                        wanted.sort();
                        wanted.dedup();

                        // Which exist already: `create -p` leaves them as they are, so a
                        // preview marking them new would promise encryption it never does.
                        let listed = runner
                            .run(&[
                                "zfs".into(),
                                "list".into(),
                                "-H".into(),
                                "-o".into(),
                                "name".into(),
                                "-r".into(),
                                base.clone(),
                            ])
                            .await?;
                        let existing: std::collections::BTreeSet<&str> = if listed.ok() {
                            listed.stdout.lines().map(str::trim).collect()
                        } else {
                            Default::default()
                        };
                        for (d, nfs) in &wanted {
                            let mark = if existing.contains(d.as_str()) {
                                "✓"
                            } else {
                                "→"
                            };
                            if *nfs {
                                println!("  {mark} {d}  (NFS, owned by uid {})", zfs::NFS_OWNER);
                            } else {
                                println!("  {mark} {d}");
                            }
                        }
                        println!("  (✓ there already, left as it is; → created)");
                        // Encryption by default, declining it explicit — decided
                        // 2026-10-29. The key is put here by `storage encrypt`, run where
                        // the vault is: this machine has none.
                        let keyed = runner
                            .run(&["test".into(), "-s".into(), zfs::KEY_FILE.into()])
                            .await?
                            .ok();
                        let encryption = if keyed {
                            println!("\nNew ones are encrypted under {}.", zfs::KEY_FILE);
                            zfs::encryption_options()
                        } else if *unencrypted {
                            println!("\n⚠️  New ones are created in clear (--unencrypted).");
                            Vec::new()
                        } else {
                            eprintln!(
                                "\n🔴 No dataset key on this machine ({}): they would be",
                                zfs::KEY_FILE
                            );
                            eprintln!("   created in clear. From a manager, where the vault is:");
                            eprintln!("     hlb storage encrypt <this node> --apply");
                            eprintln!("   then run this again — or decline: --unencrypted");
                            return Ok(ExitCode::FAILURE);
                        };
                        if !*apply {
                            println!("\nPreview: nothing was created.");
                            println!("  hlb storage init --pool {name} --apply");
                            return Ok(ExitCode::SUCCESS);
                        }

                        for (d, nfs) in &wanted {
                            // `-p` creates the parents and does NOT fail on an existing
                            // dataset: this command must be safe to rerun after adding
                            // an app to the catalog. The options reach the volume
                            // alone, never the parents `-p` makes.
                            let mut create = vec!["zfs".into(), "create".into(), "-p".into()];
                            create.extend(encryption.iter().cloned());
                            create.push(d.clone());
                            let o = runner.run(&create).await?;
                            if !o.ok() {
                                eprintln!("🔴 {d}: {}", o.stderr.trim());
                                return Ok(ExitCode::FAILURE);
                            }
                            if !*nfs {
                                continue;
                            }
                            // The directory itself, not what is in it: a rerun must not
                            // rewrite the ownership of files an app already wrote.
                            let o = runner
                                .run(&[
                                    "zfs".into(),
                                    "get".into(),
                                    "-H".into(),
                                    "-o".into(),
                                    "value".into(),
                                    "mountpoint".into(),
                                    d.clone(),
                                ])
                                .await?;
                            if !o.ok() {
                                eprintln!("🔴 {d}: {}", o.stderr.trim());
                                return Ok(ExitCode::FAILURE);
                            }
                            let path = match zfs::mountpoint(d, &o.stdout) {
                                Ok(p) => p,
                                Err(why) => {
                                    eprintln!("🔴 {why}");
                                    return Ok(ExitCode::FAILURE);
                                }
                            };
                            let owner = format!("{0}:{0}", zfs::NFS_OWNER);
                            let o = runner.run(&["chown".into(), owner, path]).await?;
                            if !o.ok() {
                                eprintln!("🔴 {d}: {}", o.stderr.trim());
                                return Ok(ExitCode::FAILURE);
                            }
                        }
                        println!("\n✓ {} datasets ready", wanted.len());

                        // 🔴 The mount point is ASKED FOR, never assumed. A dataset
                        // normally mounts at /<dataset>, but `mountpoint` can be set to
                        // anything — and a pool imported with `-R` is relocated
                        // wholesale. Printing the assumption would hand out a path that
                        // does not exist, and the bind mounts would fail at deploy time
                        // with an error naming a directory nobody chose.
                        let mp = runner
                            .run(&[
                                "zfs".into(),
                                "get".into(),
                                "-H".into(),
                                "-o".into(),
                                "value".into(),
                                "mountpoint".into(),
                                base.clone(),
                            ])
                            .await
                            .ok()
                            .filter(|o| o.ok())
                            .and_then(|o| o.first_line())
                            .map(|l| l.trim().to_string())
                            .filter(|v| v.starts_with('/'));

                        println!("\nPoint Homelabus at them:");
                        match mp {
                            Some(path) => println!("    export HLB_STORAGE_ROOT={path}"),
                            None => {
                                println!("    ⚠️  the mount point could not be read.");
                                println!("       zfs get mountpoint {base}");
                                println!("       then: export HLB_STORAGE_ROOT=<that path>");
                            }
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    StorageCmd::Export {
                        pool,
                        root,
                        network,
                    } => {
                        let d = zfs::PoolDecision::decide(&imported, &importable, pool.as_deref());
                        let zfs::PoolDecision::Ready { pool: name } = &d else {
                            eprintln!("🔴 {}", d.describe());
                            return Ok(ExitCode::FAILURE);
                        };
                        // Same rule as `init`: the mount point is read, not guessed.
                        // Exporting a path that does not exist gives clients an error
                        // naming a directory nobody chose.
                        let dataset = format!("{name}/{root}");
                        let read = runner
                            .run(&[
                                "zfs".into(),
                                "get".into(),
                                "-H".into(),
                                "-o".into(),
                                "value".into(),
                                "mountpoint".into(),
                                dataset.clone(),
                            ])
                            .await
                            .ok()
                            .filter(|o| o.ok());

                        let Some(read) = read else {
                            eprintln!("🔴 no mount point for \"{dataset}\".");
                            eprintln!(
                                "   The dataset does not exist yet: hlb storage init --apply"
                            );
                            return Ok(ExitCode::FAILURE);
                        };
                        let base = match zfs::mountpoint(&dataset, &read.stdout) {
                            Ok(p) => p,
                            Err(why) => {
                                eprintln!("🔴 {why}");
                                return Ok(ExitCode::FAILURE);
                            }
                        };

                        println!("# Add to /etc/exports, then: exportfs -ra\n");
                        println!("{}", zfs::export_line(&base, network));
                        println!();
                        println!("# Then on Homelabus:");
                        println!("#   --nfs-server <this machine> --nfs-export {base}");
                        println!("#");
                        println!("# 🔴 Printed, not written: /etc/exports may already carry");
                        println!("#    lines you added, and rewriting it would drop them.");
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::Portal(PortalCmd::DropCallback { url, apply }) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                if hlb_engine::claimed_callbacks(&state).await?.contains(url) {
                    eprintln!("🔴 An installed app is served at {url}: it stays.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::FAILURE);
                }
                println!("{url} is taken off the portal's OIDC client");
                if !*apply {
                    println!("\nPreview: nothing was done.");
                    println!("  hlb portal drop-callback {url} --apply");
                    return Ok(ExitCode::SUCCESS);
                }
                let (Some(u), Some(k)) = (&cli.pocketid_url, &cli.pocketid_key) else {
                    eprintln!(
                        "🔴 No PocketID given here (HLB_POCKETID_URL, HLB_POCKETID_KEY): nothing \
                         was done."
                    );
                    return Ok(ExitCode::FAILURE);
                };
                let pid = hlb_identity::PocketId::new(relay::reach(u, &cli.platform_network), k);
                let dropped = pid
                    .drop_callback(hlb_types::capability::PORTAL_SERVICE, url)
                    .await?;
                let (outcome, done) = match dropped {
                    hlb_identity::CallbackDrop::Dropped => ("ok", true),
                    hlb_identity::CallbackDrop::NotThere => ("absent", true),
                    hlb_identity::CallbackDrop::OnlyOne => ("refused", false),
                };
                state
                    .audit(
                        "cli",
                        ACTOR_ROLE,
                        "portal-callback-drop",
                        url,
                        outcome,
                        None,
                    )
                    .await?;
                match dropped {
                    hlb_identity::CallbackDrop::Dropped => println!("✓ taken off"),
                    hlb_identity::CallbackDrop::NotThere => {
                        println!("· the portal's client did not accept it")
                    }
                    hlb_identity::CallbackDrop::OnlyOne => eprintln!(
                        "🔴 It is the client's only callback, and it stays: an older PocketID gives \
                         a client with none to whoever asks first."
                    ),
                }
                Ok(if done {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                })
            })
        }

        Command::Garage(cmd) => {
            let (Some(url), Some(token)) = (&cli.garage_url, &cli.garage_token) else {
                eprintln!("🔴 --garage-url and --garage-token are required (or HLB_GARAGE_URL / HLB_GARAGE_TOKEN).");
                return Ok(ExitCode::FAILURE);
            };
            let g =
                hlb_objstore::Garage::new(relay::reach(url, &cli.platform_network), token.clone());
            let rt = tokio::runtime::Runtime::new()?;

            rt.block_on(async {
                match cmd {
                    GarageCmd::Init { zone, apply } => {
                        let known = g.known_nodes().await?;
                        let layout = g.layout().await?;
                        let waiting = hlb_objstore::awaiting_assignment(&known, &layout);
                        if waiting.is_empty() {
                            println!("✓ every node already has a place in the layout.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        let plan = match hlb_objstore::placement(&waiting) {
                            Ok(plan) => plan,
                            Err(e) => {
                                eprintln!("🔴 {e}");
                                return Ok(ExitCode::FAILURE);
                            }
                        };
                        for (id, c) in &plan {
                            println!("  {}  zone={zone}  {} GB", &id[..16.min(id.len())], c / 1_000_000_000);
                        }
                        if !apply {
                            println!("\nWould give these their place and apply layout version {}.", layout.next_version());
                            println!("  Re-run with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        let mut staged = layout.clone();
                        for (id, c) in &plan {
                            staged = g.assign_layout(id, zone, *c).await?;
                        }
                        g.apply_layout(staged.next_version()).await?;
                        let v = staged.next_version().to_string();
                        open_state(&cli)
                            .await?
                            .audit("cli", ACTOR_ROLE, "garage-layout", &v, "ok", Some(&format!("{} nodes placed", plan.len())))
                            .await?;
                        println!("✓ layout {v} applied — Garage can store data.");
                        Ok(ExitCode::SUCCESS)
                    }

                    GarageCmd::Status => {
                        let known = g.known_nodes().await?;
                        let layout = g.layout().await?;
                        let waiting = hlb_objstore::awaiting_assignment(&known, &layout);

                        println!("layout version {}\n", layout.version);
                        if layout.roles.is_empty() {
                            println!("No node carries any capacity yet.");
                        }
                        for r in &layout.roles {
                            match r.capacity {
                                Some(c) => println!(
                                    "  {}  zone={}  {} GB",
                                    r.id,
                                    r.zone.as_deref().unwrap_or("?"),
                                    c / 1_000_000_000
                                ),
                                None => println!(
                                    "  {}  zone={}  gateway (no capacity)",
                                    r.id,
                                    r.zone.as_deref().unwrap_or("?")
                                ),
                            }
                        }

                        if !waiting.is_empty() {
                            println!();
                            println!("Joined, awaiting a place in the layout:");
                            for n in &waiting {
                                println!(
                                    "  {}  {}  {}",
                                    n.id,
                                    n.hostname.as_deref().unwrap_or("?"),
                                    if n.is_up { "up" } else { "down" }
                                );
                            }
                            println!();
                            println!("  hlb garage assign <node> --zone <name> --capacity <bytes> --apply");
                        }
                        Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS)
                    }

                    GarageCmd::Assign {
                        node,
                        zone,
                        capacity,
                        apply,
                    } => {
                        if !apply {
                            println!("Would stage: {node} -> zone={zone}, {} GB", capacity / 1_000_000_000);
                            println!("\n  Re-run with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        let staged = g.assign_layout(node, zone, *capacity).await?;
                        open_state(&cli)
                            .await?
                            .audit("cli", ACTOR_ROLE, "garage-assign", node, "ok", Some(&format!("zone={zone} capacity={capacity}")))
                            .await?;
                        println!("✓ staged as version {}", staged.next_version());
                        println!();
                        println!(
                            "  Nothing moved yet: hlb garage commit --version {} --apply",
                            staged.next_version()
                        );
                        Ok(ExitCode::SUCCESS)
                    }

                    GarageCmd::Commit { version, apply } => {
                        if !apply {
                            println!("Would apply layout version {version}, redistributing data.");
                            println!("\n  Re-run with --apply.");
                            return Ok(ExitCode::SUCCESS);
                        }
                        g.apply_layout(*version).await?;
                        open_state(&cli)
                            .await?
                            .audit("cli", ACTOR_ROLE, "garage-layout", &version.to_string(), "ok", None)
                            .await?;
                        println!("✓ layout {version} applied");
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::Secrets => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let vault = open_vault(&cli)?;
                let names = state.secret_names().await?;

                match hlb_secrets::sealed_target(&cli.master_key) {
                    Some(t) => println!(
                        "Master key : {} — sealed to this machine, unsealed to {}",
                        cli.master_key.display(),
                        t.display()
                    ),
                    None => println!("Master key : {}", cli.master_key.display()),
                }
                println!("Public key : {}\n", vault.public_key());

                if names.is_empty() {
                    println!("No secret stored.");
                } else {
                    println!(
                        "{} — values are never displayed:\n",
                        hlb_api::plural(names.len() as u64, "secret", "secrets")
                    );
                    for (name, purpose) in &names {
                        println!("  {name:<28} {purpose}");
                    }
                }
                println!(
                    "\n🔴 Without the master key, these secrets and every backup are\n\
                        unrecoverable. Keep two offline copies."
                );
                Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS)
            })
        }

        Command::Update(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = open_state(&cli).await?;
                let registry = hlb_registry::RegistryClient::new();
                if let UpdateCmd::Policy { app, automatic } = cmd {
                    return update_policy(&state, app.as_deref(), automatic.as_deref()).await;
                }

                if matches!(cmd, UpdateCmd::Lag) {
                    print!(
                        "{}",
                        update_lag_report(
                            &state.update_lags(chrono::Utc::now().timestamp()).await?
                        )
                    );
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                }

                // `Scan` depends on no candidate: handle it before querying the
                // registries, which costs time and bandwidth.
                if let UpdateCmd::Scan {
                    image,
                    identity,
                    issuer,
                } = cmd
                {
                    println!("Analysing {image}…\n");
                    let orch = SwarmOrchestrator::connect().await?;
                    let grype = hlb_updater::grype::Grype {
                        orchestrator: &orch,
                        network: &cli.platform_network,
                    };
                    // The digest the tag names now: a scan reads one build, never a tag.
                    let pinned = if image.contains('@') {
                        image.clone()
                    } else {
                        let d = registry
                            .resolve_digest(&hlb_registry::ImageRef::parse(image))
                            .await?;
                        format!("{image}@{d}")
                    };
                    let r = hlb_updater::ScanReport {
                        image: pinned.clone(),
                        vulnerabilities: grype.vulnerabilities(&pinned, None).await,
                        signature: hlb_updater::scan::verify_signature(
                            &pinned,
                            identity.as_deref(),
                            issuer.as_deref(),
                        )
                        .await,
                    };
                    println!("{}", r.describe());

                    if r.unchecked() > 0 {
                        println!();
                        println!(
                            "⚠️  {} NOT performed.",
                            hlb_api::plural(r.unchecked() as u64, "check", "checks")
                        );
                        // The scan runs as a Swarm job; only the signature needs a binary.
                        println!("   The scan needs the Swarm and the image's digest");
                        println!("   (`repo:tag@sha256:…`); a signature needs cosign:");
                        println!("     brew install cosign   # or your distro's package");
                    }
                    return Ok::<_, Box<dyn std::error::Error>>(if r.blocks() {
                        ExitCode::FAILURE
                    } else {
                        ExitCode::SUCCESS
                    });
                }

                // Each installed app against its own source's manifest, never another
                // source's app of the same name.
                let sources = sources::catalog_with_sources(&cli, &state).await?;
                let mut catalog = std::collections::BTreeMap::new();
                for (app, _) in state.installed_apps().await? {
                    let source = state.app_source(&app).await?;
                    if let Ok(e) = sources.followed(&app, source.as_deref()) {
                        catalog.insert(app, e.manifest.clone());
                    }
                }
                let at = chrono::Utc::now().timestamp();
                let checked = hlb_updater::check(&state, &registry, at, &catalog).await?;
                hlb_updater::note_seen(&state, &checked, at).await?;
                for (app, why) in &checked.unreadable {
                    eprintln!("✗ {app}: its registry could not be read — {why}");
                }
                // Not an update, and not "up to date" either: what the catalog wants waits.
                for (app, why) in &checked.held {
                    println!("⏸ {app}: {why}");
                }
                let candidates = checked.candidates;

                match cmd {
                    // Handled above.
                    UpdateCmd::Scan { .. } => unreachable!(),
                    UpdateCmd::Lag => unreachable!(),
                    UpdateCmd::Policy { .. } => unreachable!(),
                    UpdateCmd::Check => {
                        if candidates.is_empty() && checked.unreadable.is_empty() {
                            if !checked.held.is_empty() {
                                return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                            }
                            println!("✓ everything is up to date.");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                        }
                        println!(
                            "{} available:\n",
                            hlb_api::plural(candidates.len() as u64, "update", "updates")
                        );
                        for c in &candidates {
                            let when = if c.in_window {
                                "applicable"
                            } else {
                                "outside window"
                            };
                            let backup_dir = if c.needs_backup {
                                ", backup required"
                            } else {
                                ""
                            };
                            println!("  • {}  [{when}{backup_dir}]", c.describe());
                            let installed = state.app_manifest(&c.app).await?;
                            let house = state.update_automatic(&c.app).await?;
                            let exploited =
                                hlb_updater::flaws::exploited(&state, &installed).await?;
                            if exploited {
                                println!("      urgent: what runs carries an exploited flaw");
                            }
                            match hlb_updater::policy::judge(
                                &registry,
                                c,
                                &installed,
                                catalog.get(c.app.as_str()),
                                house,
                                exploited,
                            )
                            .await
                            {
                                hlb_updater::policy::Decision::Automatic => {
                                    println!("      applies itself in its window")
                                }
                                hlb_updater::policy::Decision::OneClick { why } => {
                                    println!("      waits for a person: {why}")
                                }
                                hlb_updater::policy::Decision::Manual { why } => {
                                    println!("      by hand: {why}")
                                }
                            }
                            if let Some(why) = c.maturity.refusal(at).filter(|_| !exploited) {
                                println!("      not yet: {why}");
                            }
                        }
                        println!("\n  hlb update apply <app> to apply.");
                        // A registry nobody could read is not a pass that found nothing.
                        Ok(if checked.unreadable.is_empty() {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::FAILURE
                        })
                    }

                    UpdateCmd::Apply {
                        app,
                        force_window,
                        force_vulnerable,
                        before_maturity,
                    } => {
                        use hlb_updater::run::{Progress, Ran, Refusal};

                        let Some(c) = candidates.iter().find(|c| &c.app == app) else {
                            println!("Nothing to update for \"{app}\".");
                            return Ok(ExitCode::SUCCESS);
                        };
                        let vault = open_vault(&cli)?;
                        let provider = build_backup_provider(&cli, app, &state, &vault).await?;
                        let orch = SwarmOrchestrator::connect().await?;
                        let update = hlb_updater::run::Update {
                            orchestrator: &orch,
                            state: &state,
                            in_catalog: catalog.get(app.as_str()).map(|m| &m.spec.image),
                            backup: provider
                                .as_ref()
                                .map(|p| p as &dyn hlb_updater::BackupProvider),
                            scanner: &hlb_updater::grype::Grype {
                                orchestrator: &orch,
                                network: &cli.platform_network,
                            },
                            overrides: hlb_updater::run::Overrides {
                                force_window: *force_window,
                                force_vulnerable: *force_vulnerable,
                                before_maturity: *before_maturity,
                            },
                            actor: hlb_updater::run::Actor {
                                name: "cli",
                                role: ACTOR_ROLE,
                            },
                            now: at,
                        };
                        let ran = update
                            .run(c, &mut |p| match p {
                                Progress::Scanned { described } => println!("{described}\n"),
                                Progress::VulnerableForced => {
                                    eprintln!("⚠️  Critical vulnerabilities ignored on request.")
                                }
                                Progress::BeforeMaturity { why } => {
                                    eprintln!("⚠️  Applied before maturity: {why}.")
                                }
                                Progress::NoCopyOwed => println!(
                                    "no backup first: {app} holds nothing to copy, or asks for none."
                                ),
                                Progress::CopyStarted => print!("backup first… "),
                                Progress::Copied { snapshot } => {
                                    println!("✓ {}", &snapshot[..8.min(snapshot.len())])
                                }
                                Progress::Switching { describe } => println!("{describe}…"),
                            })
                            .await?;

                        match ran {
                            Ran::Refused(Refusal::Vulnerable { .. }) => {
                                eprintln!("🔴 Update REFUSED.");
                                eprintln!();
                                eprintln!("   Overriding is sometimes legitimate — an urgent fix in");
                                eprintln!("   an image that still carries other CVEs. But it must be");
                                eprintln!("   a decision, not a default:");
                                eprintln!("     hlb update apply {app} --force-vulnerable");
                                Ok(ExitCode::FAILURE)
                            }
                            Ran::Refused(Refusal::OutsideWindow) => {
                                eprintln!(
                                    "\"{app}\" is outside its maintenance window.\n\
                                     --force-window to override."
                                );
                                Ok(ExitCode::FAILURE)
                            }
                            Ran::Refused(Refusal::Immature { why }) => {
                                eprintln!("✗ \"{app}\": {why} - update refused.");
                                eprintln!(
                                    "   An urgent fix may not wait — a decision, not a default:"
                                );
                                eprintln!("     hlb update apply {app} --before-maturity");
                                Ok(ExitCode::FAILURE)
                            }
                            Ran::Refused(Refusal::CopyFailed { error }) => {
                                eprintln!("✗");
                                eprintln!("  {error}");
                                eprintln!("  update abandoned: no backup, no switchover.");
                                Ok(ExitCode::FAILURE)
                            }
                            Ran::Switched(hlb_updater::UpdateOutcome::Applied { digest }) => {
                                println!("✓ applied — {}", &digest[..23.min(digest.len())]);
                                Ok(ExitCode::SUCCESS)
                            }
                            Ran::Switched(hlb_updater::UpdateOutcome::RolledBack { reason }) => {
                                eprintln!("↩ Swarm rolled back: {reason}");
                                eprintln!("  the service is still running its previous version.");
                                Ok(ExitCode::FAILURE)
                            }
                            Ran::Switched(hlb_updater::UpdateOutcome::Paused) => {
                                eprintln!("⏸ switchover paused — intervention needed.");
                                Ok(ExitCode::FAILURE)
                            }
                            Ran::Switched(hlb_updater::UpdateOutcome::Inconclusive) => {
                                eprintln!("? undetermined outcome within the allotted time.");
                                eprintln!("  check with hlb ps before re-running.");
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
                let state = open_state(&cli).await?;
                let vault = open_vault(&cli)?;
                let sched = hlb_backup::Schedule::default();

                match cmd {
                    BackupCmd::Status => {
                        let apps = state.installed_apps().await?;
                        if apps.is_empty() {
                            println!("No app installed.");
                            return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                        }
                        println!("{:<14} {:<18} {:<18} STATE", "APP", "LAST BACKUP", "VERIFIED");
                        for (app, _) in &apps {
                            // An app holding nothing is owed no backup: "never" would
                            // be a red line nobody can clear.
                            if state.backup_kinds(app).await?.is_empty() {
                                println!("{app:<14} {:<18} {:<18} nothing to back up", "-", "-");
                                continue;
                            }
                            // The oldest of what it holds: a fresh dump never hides a
                            // volume no longer backed up.
                            let age = state.backup_age(app).await?
                                .map(|s| std::time::Duration::from_secs(s.max(0) as u64));
                            let verif = state.seconds_since_last_verification(app).await?;

                            // 🔴 Coverage first: it is what decides the summary line.
                            // Judging on the AGGREGATE age would show "✓ up to date" for
                            // an app whose off-site has been dead for three weeks — the
                            // summary would contradict the detail right below it, and
                            // the summary is what people read.
                            let coverage =
                                coverage_of(&state, app, sched.overdue_after().as_secs() as i64)
                                    .await?;

                            // A repeated failure makes the summary alarming, even if the
                            // last success is recent.
                            let mut total_failures = 0;
                            for (name, _) in &coverage.per_destination {
                                total_failures += state.consecutive_failures_on(app, name).await?;
                            }

                            let verdict = if total_failures > 0 {
                                "🔴 attempts are failing"
                            } else {
                                match coverage.worst() {
                                Some(hlb_backup::DestinationState::Never) => {
                                    "🔴 a destination NEVER served"
                                }
                                Some(hlb_backup::DestinationState::Stale { .. }) => {
                                    "🔴 a destination is behind"
                                }
                                // No routed destination: fall back on the global
                                // judgement, which stays correct in that case.
                                None | Some(hlb_backup::DestinationState::Fresh { .. }) => {
                                    if sched.is_overdue(age) {
                                        "🔴 overdue"
                                    } else if sched.is_due(age) {
                                        "🟠 due"
                                    } else {
                                        "✓ up to date"
                                    }
                                }
                                }
                            };
                            println!(
                                "{app:<14} {:<18} {:<18} {verdict}",
                                age.map(fmt_age).unwrap_or_else(|| "never".into()),
                                verified_column(verif, state.last_verification_failed(app).await?),
                            );

                            // The per-destination detail, under the summary.
                            if !coverage.per_destination.is_empty() {
                                for (name, e) in &coverage.per_destination {
                                    let (brand, when) = match e {
                                        hlb_backup::DestinationState::Fresh { age_s } => (
                                            "✓",
                                            fmt_age(std::time::Duration::from_secs(*age_s as u64)),
                                        ),
                                        hlb_backup::DestinationState::Stale { age_s } => (
                                            "🔴",
                                            fmt_age(std::time::Duration::from_secs(*age_s as u64)),
                                        ),
                                        // 🔴 Distinct from being behind: this destination
                                        // has NEVER received anything, so it has never
                                        // protected anything. The cause is elsewhere —
                                        // routing never wired up, missing credentials.
                                        hlb_backup::DestinationState::Never => {
                                            ("🔴", "NEVER received".to_string())
                                        }
                                    };
                                    // 🔴 A REPEATED failure shows immediately, without
                                    // waiting for the staleness threshold. Otherwise a
                                    // destination failing on every attempt would stay
                                    // displayed as "✓" for twelve hours.
                                    let failures =
                                        state.consecutive_failures_on(app, name).await?;
                                    let suffix = if failures > 0 {
                                        format!(
                                            "  🔴 {} since",
                                            hlb_api::plural(
                                                failures as u64,
                                                "failure",
                                                "failures"
                                            )
                                        )
                                    } else {
                                        String::new()
                                    };
                                    println!("               └ {brand} {name:<10} {when}{suffix}");
                                }

                                let up_to_date = coverage.up_to_date_copies();
                                if up_to_date < 2 {
                                    // 🔴 The number of CONFIGURED destinations says
                                    // nothing about the number of copies. Two
                                    // destinations, one of them failing, is not 3-2-1.
                                    println!(
                                        "               ⚠️ {} really up to date out of {}",
                                        hlb_api::plural(up_to_date as u64, "copy", "copies"),
                                        coverage.per_destination.len()
                                    );
                                }
                            }
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    BackupCmd::Run { force, app } => {
                        // One pass, the same the controller runs on its own: two copies
                        // had drifted apart — see `hlb-backup-run`.
                        let orch = SwarmOrchestrator::connect().await.ok();
                        // Garage does not resolve on a host: a relay, for this command —
                        // opened only when an app keeps a bucket the pass reads.
                        let mut buckets = false;
                        for (a, _) in state.installed_apps().await? {
                            buckets |= !state.buckets_to_backup(&a).await?.is_empty();
                        }
                        let s3_endpoint = if buckets {
                            relay::reach(hlb_objstore::S3_URL, &cli.platform_network)
                        } else {
                            hlb_objstore::S3_URL.to_string()
                        };
                        let pass = hlb_backup_run::Pass {
                            state: &state,
                            vault: &vault,
                            state_path: &cli.state,
                            fallback_repo: cli.backup_repo.as_deref(),
                            network: &cli.platform_network,
                            postgres_admin: cli.postgres_admin.as_deref(),
                            mariadb_admin: cli.mariadb_admin.as_deref(),
                            schedule: sched,
                            force: *force,
                            only: app.as_deref(),
                            orchestrator: orch.as_ref().map(|o| o as &dyn hlb_orchestrator::Orchestrator),
                            s3_endpoint: Some(&s3_endpoint),
                        };
                        let mut not_covered = 0;
                        let sum = pass
                            .run(&mut |e| match e {
                                hlb_backup_run::Event::Done {
                                    what,
                                    destination,
                                    snapshot,
                                } => println!(
                                    "✓ {what} → {destination} ({})",
                                    &snapshot[..8.min(snapshot.len())]
                                ),
                                hlb_backup_run::Event::Failed {
                                    what,
                                    destination,
                                    error,
                                } => match destination {
                                    Some(d) => println!("✗ {what} → {d}: {error}"),
                                    None => println!("✗ {what}: {error}"),
                                },
                                hlb_backup_run::Event::NotCovered { what, why } => {
                                    not_covered += 1;
                                    eprintln!("🔴 {what} NOT backed up: {why}")
                                }
                            })
                            .await?;
                        // 🔴 Something left uncovered is not "nothing was due", and a
                        // script reading the exit code must not take it for a success.
                        if sum.done == 0 && sum.failed == 0 && not_covered == 0 {
                            println!("Nothing was due.");
                        }
                        Ok(exit_of_pass(sum, not_covered))
                    }

                    BackupCmd::Restore {
                        app,
                        volume,
                        database,
                        snapshot,
                        from,
                        apply,
                    } => {
                        restore::run(
                            &cli,
                            &state,
                            &vault,
                            restore::Request {
                                app,
                                volume: volume.as_deref(),
                                database: database.as_deref(),
                                snapshot: snapshot.as_deref(),
                                from: from.as_deref(),
                                apply: *apply,
                            },
                        )
                        .await
                    }

                    BackupCmd::Verify { app } => {
                    // A named app, or every app that already has a snapshot.
                    let targets: Vec<String> = match app {
                        Some(a) => vec![a.clone()],
                        None => state
                            .installed_apps()
                            .await?
                            .into_iter()
                            .map(|(n, _)| n)
                            .collect(),
                    };
                    let mut verified = 0;
                    let mut drifts = 0;

                    for a in targets {
                        let read = hlb_backup_run::verify::app(
                            &state,
                            &vault,
                            &cli.platform_network,
                            cli.backup_repo.as_deref(),
                            &a,
                            false,
                        )
                        .await?;
                        // No backup: nothing to verify, and above all no "✓" that would
                        // suggest otherwise.
                        let Some(read) = read else {
                            if app.is_some() {
                                println!("{a}: no backup to verify.");
                            }
                            continue;
                        };
                        verified += 1;
                        if !read.matches() {
                            drifts += 1;
                        }
                        for p in &read.parts {
                            let short = &p.snapshot[..8.min(p.snapshot.len())];
                            let (mark, text) = match &p.outcome {
                                Ok(t) => ("", t),
                                Err(e) => ("✗ ", e),
                            };
                            println!("{a}, {} ({short} on {})… {mark}{text}", p.what, p.destination);
                        }
                    }

                    if verified == 0 && drifts == 0 {
                            println!("No snapshot to verify.");
                            return Ok(ExitCode::SUCCESS);
                        }

                        if drifts > 0 {
                            eprintln!(
                                "\n🔴 {} failed — those backups do not restore what \
                                 they announce.",
                                hlb_api::plural(drifts, "verification", "verifications")
                            );
                            return Ok(ExitCode::FAILURE);
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    BackupCmd::Dest(sub) => match sub {
                        DestCmd::Add { name, location, classes, access_key } => {
                            use hlb_backup::Class;

                            // A misspelled class is refused: accepting it silently would
                            // produce a destination that accepts nothing, and that you
                            // would believe configured.
                            let mut kept = Vec::new();
                            for c in classes {
                                match Class::parse(c) {
                                    Some(k) => kept.push(k.name().to_string()),
                                    None => {
                                        eprintln!("unknown class \"{c}\" — expected: critical, bulky");
                                        return Ok(ExitCode::FAILURE);
                                    }
                                }
                            }

                            let secret = match access_key {
                                Some(key) => {
                                    // 🔴 The secret key is read from STANDARD INPUT. As an
                                    // argument it would be readable through `ps` by every
                                    // user of the machine, then kept in the shell history.
                                    eprintln!("S3 secret key (standard input, not echoed):");
                                    let mut buf = String::new();
                                    std::io::stdin().read_line(&mut buf)?;
                                    let secret_value = buf.trim();
                                    if secret_value.is_empty() {
                                        eprintln!("🔴 empty secret key — nothing was recorded.");
                                        return Ok(ExitCode::FAILURE);
                                    }

                                    let secret_name = format!("backup-dest-{name}");
                                    let ct = vault.encrypt(&format!("{key}:{secret_value}"))?;
                                    if !state
                                        .store_secret_if_absent(&secret_name, &ct, "backup S3 credentials")
                                        .await?
                                    {
                                        state.rotate_secret(&secret_name, &ct).await?;
                                    }
                                    Some(secret_name)
                                }
                                None => None,
                            };

                            state
                                .upsert_destination(name, location, &kept.join(","), secret.as_deref())
                                .await?;
                            state
                                .audit("cli", ACTOR_ROLE, "backup-dest", name, "ok", Some(location))
                                .await?;

                            println!("✓ destination \"{name}\" recorded.");
                            println!(
                                "  Whether its credential can erase it: hlb backup dest prove {name}"
                            );

                            // ⚠️ An S3 destination without credentials fails on the first
                            // backup, on an authorization error that does not say the
                            // secret was never stored.
                            if location.trim_start().starts_with("s3:") && secret.is_none() {
                                println!();
                                println!("⚠️ S3 repository without credentials: backups will fail.");
                                println!("   Re-run with --access-key <key>.");
                            }
                            Ok(ExitCode::SUCCESS)
                        }

                        DestCmd::List => {
                            let destinations = load_destinations(&state).await?;
                            if destinations.is_empty() {
                                println!("No destination declared.");
                                println!();
                                println!("⚠️ Without a destination, `hlb backup run` has nowhere to write.");
                                println!("   hlb backup dest add nas --location /mnt/nas/restic \\");
                                println!("     --classes critical,bulky");
                                return Ok(ExitCode::SUCCESS);
                            }
                            for d in &destinations {
                                println!("  {}", d.describe());
                                match state.destination_proof(&d.name, &d.location).await? {
                                    Some((verdict, detail, at)) => println!(
                                        "      {} ({})",
                                        hlb_backup::erasure::Erasure::from_stored(&verdict, &detail)
                                            .describe(),
                                        hlb_backup::pitr::iso8601(at)
                                    ),
                                    None => println!(
                                        "      never proven against erasure — hlb backup dest prove {}",
                                        d.name
                                    ),
                                }
                            }
                            Ok(ExitCode::SUCCESS)
                        }

                        DestCmd::Prove { name } => {
                            let destinations: Vec<_> = load_destinations(&state)
                                .await?
                                .into_iter()
                                .filter(|d| name.as_ref().is_none_or(|n| *n == d.name))
                                .collect();
                            if destinations.is_empty() {
                                eprintln!(
                                    "🔴 {}",
                                    match name {
                                        Some(n) => format!("no destination \"{n}\""),
                                        None => "no destination declared".to_string(),
                                    }
                                );
                                return Ok(ExitCode::FAILURE);
                            }
                            let network = cli.platform_network.clone();
                            let reach = move |url: &str| relay::reach(url, &network);
                            let mut kept = 0;
                            for d in &destinations {
                                let found = hlb_backup_run::erasure::prove(
                                    &state,
                                    &vault,
                                    &cli.platform_network,
                                    &reach,
                                    d,
                                )
                                .await;
                                println!("  {}: {}", d.name, found.describe());
                                if matches!(found, hlb_backup::erasure::Erasure::Kept { .. }) {
                                    kept += 1;
                                    println!(
                                        "      its owner prunes it: hlb backup dest prune-script {}",
                                        d.name
                                    );
                                }
                                state
                                    .audit(
                                        "cli",
                                        ACTOR_ROLE,
                                        "backup-dest-prove",
                                        &d.name,
                                        found.verdict(),
                                        Some(found.detail()),
                                    )
                                    .await?;
                            }
                            relay::close_all();
                            if kept == 0 {
                                println!();
                                println!(
                                    "⚠️ No destination is proven out of reach: whoever takes this \
                                     cluster can erase every backup."
                                );
                            }
                            Ok(ExitCode::SUCCESS)
                        }

                        DestCmd::Garage {
                            name,
                            bucket,
                            classes,
                            apply,
                        } => {
                            let (Some(url), Some(token)) = (&cli.garage_url, &cli.garage_token)
                            else {
                                eprintln!("🔴 Garage's admin API is unknown: install Garage first");
                                eprintln!("   (`hlb install garage --apply`), or pass --garage-url");
                                eprintln!("   and --garage-token.");
                                return Ok(ExitCode::FAILURE);
                            };
                            let location = format!("s3:http://garage:3900/{bucket}");
                            let secret_name = format!("backup-dest-{name}");
                            if !apply {
                                println!("Would back up to Garage, on this cluster:");
                                println!("  bucket      {bucket}");
                                println!("  key         {name}-backups, read + write, never owner");
                                println!("  credentials in the vault, as \"{secret_name}\"");
                                println!("  destination \"{name}\" → {location} [{}]", classes.join(","));
                                println!();
                                println!("  ⚠️  On the cluster it backs up: add an off-site destination too.");
                            println!("  ⚠️  Garage keeps no versions: whoever holds this key can erase the");
                            println!("     backups. A destination out of reach is versioned S3 or an");
                            println!("     append-only REST server (`hlb backup dest prove`).");
                                println!("\n  Re-run with --apply.");
                                return Ok(ExitCode::SUCCESS);
                            }

                            let garage = hlb_objstore::Garage::new(relay::reach(url, &cli.platform_network), token.clone());
                            // A Garage with no layout stores nothing: every write fails
                            // with an error about a layout nobody mentioned.
                            if garage.layout().await?.roles.is_empty() {
                                eprintln!("🔴 Garage has no layout yet: it cannot store anything.");
                                eprintln!("   hlb garage init --apply    # each node: 9/10 of its free disk");
                                return Ok(ExitCode::FAILURE);
                            }
                            let bucket_id = garage.ensure_bucket(bucket).await?;

                            // The vault is authoritative for the secret: Garage never
                            // gives it twice.
                            let known = match state.secret(&secret_name).await? {
                                Some(ct) => vault
                                    .decrypt(&ct)?
                                    .split_once(':')
                                    .map(|(_, s)| s.to_string()),
                                None => None,
                            };
                            let key = garage
                                .ensure_key(&format!("{name}-backups"), known.as_deref())
                                .await?;
                            garage.allow(&bucket_id, &key.access_key_id).await?;
                            let ct = vault.encrypt(&format!(
                                "{}:{}",
                                key.access_key_id, key.secret_access_key
                            ))?;
                            if !state
                                .store_secret_if_absent(&secret_name, &ct, "backup S3 credentials")
                                .await?
                            {
                                state.rotate_secret(&secret_name, &ct).await?;
                            }
                            state
                                .upsert_destination(name, &location, &classes.join(","), Some(&secret_name))
                                .await?;
                            state
                                .audit("cli", ACTOR_ROLE, "backup-dest-garage", name, "ok", None)
                                .await?;
                            println!("✓ destination \"{name}\" → {location}");
                            println!("  The next backup pass writes there.");
                            println!("  ⚠️ Garage keeps no versions: this key can erase what it wrote.");
                            Ok(ExitCode::SUCCESS)
                        }

                        DestCmd::PruneScript { name } => {
                            let Some(d) = load_destinations(&state)
                                .await?
                                .into_iter()
                                .find(|d| d.name == *name)
                            else {
                                eprintln!("🔴 no destination \"{name}\" — hlb backup dest list");
                                return Ok(ExitCode::FAILURE);
                            };
                            let proof = state
                                .destination_proof(&d.name, &d.location)
                                .await?
                                .map(|(verdict, detail, _)| {
                                    hlb_backup::erasure::Erasure::from_stored(&verdict, &detail)
                                });
                            // Said on standard error: the script itself goes to a file.
                            match &proof {
                                Some(hlb_backup::erasure::Erasure::Erasable { .. }) => {
                                    eprintln!(
                                        "🔴 \"{name}\" can be erased with the credential Homelabus \
                                         holds: the weekly upkeep prunes it itself."
                                    );
                                    return Ok(ExitCode::FAILURE);
                                }
                                Some(_) => {}
                                None => eprintln!(
                                    "⚠️ \"{name}\" was never proven out of reach — \
                                     hlb backup dest prove {name}"
                                ),
                            }
                            // The daemon's upkeep prunes with the same default.
                            print!(
                                "{}",
                                hlb_backup_run::upkeep::owner_script(
                                    &d,
                                    &hlb_backup::RetentionPolicy::default()
                                )?
                            );
                            Ok(ExitCode::SUCCESS)
                        }

                        DestCmd::Remove { name } => {
                            state.remove_destination(name).await?;
                            state
                                .audit("cli", ACTOR_ROLE, "backup-dest-remove", name, "ok", None)
                                .await?;
                            println!("✓ destination \"{name}\" removed from routing.");
                            // 🔴 NOTHING is deleted remotely: the snapshots stay there.
                            // Erasing them on a `dest remove` would destroy backups on a
                            // configuration gesture.
                            println!("⚠️ Snapshots already sent were not touched.");
                            Ok(ExitCode::SUCCESS)
                        }
                    },

                    BackupCmd::Route { app, critical, bulky } => {
                        let known: Vec<String> = state
                            .destinations()
                            .await?
                            .into_iter()
                            .map(|(n, _, _, _)| n)
                            .collect();

                        let asked: Vec<(&str, &[String])> =
                            [("critical", critical), ("bulky", bulky)]
                                .into_iter()
                                .filter_map(|(class, c)| c.as_deref().map(|d| (class, d)))
                                .collect();
                        // Routing to a non-existent destination would produce no error at
                        // backup time: it would simply be ignored, and the app would look
                        // covered. Every class is checked before any is written, so
                        // "nothing was routed" is true when it is said.
                        if let Some(d) = unknown_destination(&asked, &known) {
                            eprintln!("🔴 unknown destination \"{d}\" — nothing was routed.");
                            eprintln!("   hlb backup dest list");
                            return Ok(ExitCode::FAILURE);
                        }
                        state.set_routes(app, &asked).await?;
                        for (class, dests) in &asked {
                            let to = dests.join(", ");
                            state
                                .audit("cli", ACTOR_ROLE, "backup-route", app, "ok", Some(&format!("{class} -> {to}")))
                                .await?;
                            println!("✓ {app} / {class} -> {to}");
                        }

                        println!();
                        for class in ["critical", "bulky"] {
                            let r = state.route(app, class).await?;
                            if r.is_empty() {
                                println!("  {class:<11} : (destination defaults)");
                            } else {
                                println!("  {class:<11} : {}", r.join(", "));
                            }
                        }
                        Ok(ExitCode::SUCCESS)
                    }

                    BackupCmd::Pitr(sub) => {
                        pitr(sub, &cli.state, cli.postgres_admin.as_deref(), &cli.platform_network).await
                    }
                }
            })
        }

        Command::Cluster(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                // Not for `init`: on a bare machine there is no Docker to connect to yet
                // — installing it is the first thing `init` does.
                if let ClusterCmd::Init {
                    advertise_addr,
                    endpoint,
                    no_mesh,
                    failure_domain,
                    storage_node,
                    apply,
                } = cmd
                {
                    return cluster_init(
                        &cli,
                        ClusterInit {
                            advertise_addr: advertise_addr.as_deref(),
                            endpoint: endpoint.as_deref(),
                            no_mesh: *no_mesh,
                            failure_domain: failure_domain.as_deref(),
                            storage_node: *storage_node,
                            apply: *apply,
                        },
                    )
                    .await;
                }
                let orch = SwarmOrchestrator::connect().await?;

                match cmd {
                    // Handled above, before connecting.
                    ClusterCmd::Init { .. } => unreachable!(),

                    ClusterCmd::Autolock { apply, host_only } => {
                        seal::autolock(&cli, &orch, *apply, *host_only).await
                    }

                    ClusterCmd::Status => {
                        let nodes = orch.nodes().await?;
                        if nodes.is_empty() {
                            println!("No node — the Swarm is not initialised.");
                            println!("  hlb cluster init --apply");
                            return Ok(ExitCode::SUCCESS);
                        }

                        let profile = hlb_orchestrator::ClusterProfile::for_node_count(nodes.len());
                        let managers = nodes
                            .iter()
                            .filter(|n| n.role == hlb_orchestrator::NodeRole::Manager)
                            .count();
                        let quorum = hlb_orchestrator::QuorumHealth::assess(managers);

                        println!(
                            "Profile: {} ({})\n",
                            profile.as_str(),
                            hlb_api::plural(nodes.len() as u64, "node", "nodes")
                        );
                        println!(
                            "{:<20} {:<9} {:<8} {:<8} {:<11} MEMORY",
                            "NODE", "ROLE", "STATE", "TIER", "PROTECTION"
                        );
                        for n in &nodes {
                            println!(
                                "{:<20} {:<9} {:<8} {:<8} {:<11} {}",
                                format!("{}{}", n.hostname, if n.is_leader { " ★" } else { "" }),
                                n.role.as_str(),
                                if n.is_ready() { "ready" } else { &n.status },
                                n.tier.as_deref().unwrap_or("—"),
                                n.protection.as_deref().unwrap_or("—"),
                                n.memory_mb
                                    .map(|m| format!("{m} MB"))
                                    .unwrap_or_else(|| "?".into()),
                            );
                        }

                        println!("\nQuorum: {}", quorum.describe());

                        // 🔴 A tier that lies is worse than no tier: a database scheduled
                        // on a 4 GB "heavy" node works right up to the day it kills the
                        // machine by OOM.
                        for n in &nodes {
                            let (Some(declared), Some(mem)) = (&n.tier, n.memory_mb) else {
                                continue;
                            };
                            let deduced = hlb_orchestrator::cluster::tier_for_memory(mem);
                            if declared != deduced {
                                println!(
                                    "\n🔴 {} is labelled \"{declared}\" but only has {mem} MB \
                                     — its memory makes it a \"{deduced}\".",
                                    n.hostname
                                );
                                println!(
                                    "   A database scheduled on it holds until the day of the OOM."
                                );
                                println!("   hlb node tier {} --apply", n.hostname);
                            }
                        }

                        // A node without a tier never receives a constrained service.
                        let sans_tier: Vec<&str> = nodes
                            .iter()
                            .filter(|n| n.tier.is_none())
                            .map(|n| n.hostname.as_str())
                            .collect();
                        if !sans_tier.is_empty() {
                            println!(
                                "\n⚠️  no tier: {} — no constrained service will schedule there.",
                                sans_tier.join(", ")
                            );
                            println!("   hlb node tier <node>  to derive it from its memory.");
                        }

                        // Not read is not protected: a node nobody looked at must show.
                        let unread: Vec<&str> = nodes
                            .iter()
                            .filter(|n| n.protection.is_none())
                            .map(|n| n.hostname.as_str())
                            .collect();
                        if !unread.is_empty() {
                            println!("\n⚠️  protection level never read: {}", unread.join(", "));
                            println!("   hlb node protection <node> --apply");
                        }
                        let levels: Vec<_> = nodes
                            .iter()
                            .map(|n| {
                                (
                                    n.hostname.as_str(),
                                    n.role == hlb_orchestrator::NodeRole::Manager,
                                    n.protection
                                        .as_deref()
                                        .and_then(hlb_bootstrap::protection::Level::parse),
                                )
                            })
                            .collect();
                        for w in hlb_bootstrap::protection::weak_managers(&levels) {
                            println!("\n⚠️  {w}");
                        }

                        Ok(if quorum.needs_attention() {
                            ExitCode::FAILURE
                        } else {
                            ExitCode::SUCCESS
                        })
                    }

                    ClusterCmd::JoinCommand { role } => {
                        let nodes = orch.nodes().await?;
                        let profile =
                            hlb_orchestrator::ClusterProfile::for_node_count(nodes.len() + 1);
                        let managers = nodes
                            .iter()
                            .filter(|n| n.role == hlb_orchestrator::NodeRole::Manager)
                            .count();

                        // By default, offer the role that keeps the quorum healthy.
                        let chosen = match role.as_deref() {
                            Some("manager") => hlb_orchestrator::NodeRole::Manager,
                            Some("worker") => hlb_orchestrator::NodeRole::Worker,
                            _ if managers < profile.recommended_managers() => {
                                hlb_orchestrator::NodeRole::Manager
                            }
                            _ => hlb_orchestrator::NodeRole::Worker,
                        };

                        // 🔴 Going from 1 to 2 managers degrades failure tolerance.
                        if chosen == hlb_orchestrator::NodeRole::Manager {
                            let after = hlb_orchestrator::QuorumHealth::assess(managers + 1);
                            if after.needs_attention() {
                                eprintln!("🔴 {}\n", after.describe());
                                eprintln!("   Add this node as a worker, or plan for a third one.");
                            }
                        }

                        let t = orch.join_tokens().await?;
                        println!("On the machine to attach, as {}:\n", chosen.as_str());
                        println!(
                            "  docker swarm join --token {} {}",
                            t.for_role(chosen),
                            t.advertise_addr
                        );
                        println!("\n⚠️  Check the machine first:  hlb node check <host>");
                        Ok(ExitCode::SUCCESS)
                    }
                }
            })
        }

        Command::Node(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                // The tier is set against the cluster, not against a machine.
                if let NodeCmd::Upgrade {
                    node,
                    host,
                    user,
                    port,
                    accept_downtime,
                    apply,
                } = cmd
                {
                    return node_upgrade(
                        &cli,
                        node,
                        host.as_deref(),
                        user.as_deref(),
                        *port,
                        *accept_downtime,
                        *apply,
                    )
                    .await;
                }

                if let NodeCmd::BindDisk {
                    node,
                    host,
                    user,
                    port,
                    passphrase_stdin,
                    apply,
                } = cmd
                {
                    let orch = SwarmOrchestrator::connect().await?;
                    return disk::run(
                        &cli,
                        &orch,
                        node,
                        host.as_deref(),
                        user.as_deref(),
                        *port,
                        *passphrase_stdin,
                        *apply,
                    )
                    .await;
                }

                if let NodeCmd::VerifyBoot {
                    node,
                    host,
                    user,
                    port,
                    apply,
                } = cmd
                {
                    let orch = SwarmOrchestrator::connect().await?;
                    return verify_boot::run(
                        &cli,
                        &orch,
                        node,
                        host.as_deref(),
                        user.as_deref(),
                        *port,
                        *apply,
                    )
                    .await;
                }

                if let NodeCmd::Protection {
                    node,
                    host,
                    user,
                    port,
                    apply,
                } = cmd
                {
                    return node_protection(
                        &cli,
                        node,
                        host.as_deref(),
                        user.as_deref(),
                        *port,
                        *apply,
                    )
                    .await;
                }

                if let NodeCmd::Prune { apply } = cmd {
                    let orch = SwarmOrchestrator::connect().await?;
                    let report = hlb_engine::prune::run(&orch, *apply).await?;
                    if *apply {
                        let state = open_state(&cli).await?;
                        for (node, outcome) in &report {
                            if let hlb_engine::prune::Outcome::Freed(size) = outcome {
                                state
                                    .audit(
                                        "cli",
                                        ACTOR_ROLE,
                                        "node-prune",
                                        node,
                                        "ok",
                                        Some(&size.to_string()),
                                    )
                                    .await?;
                            }
                        }
                    }
                    let mut failed = false;
                    for (node, outcome) in &report {
                        use hlb_engine::prune::Outcome;
                        match outcome {
                            Outcome::ToDo => {
                                println!("  {node}: would remove the images no container uses")
                            }
                            Outcome::Freed(size) => println!("  ✓ {node}: {size} given back"),
                            Outcome::Waiting(why) => println!("  ⏳ {node}: {why}"),
                            Outcome::Failed(why) => {
                                failed = true;
                                eprintln!("  🔴 {node}: {why}")
                            }
                        }
                    }
                    if !*apply {
                        println!("\n  Re-run with --apply.");
                    }
                    return Ok(if failed {
                        ExitCode::FAILURE
                    } else {
                        ExitCode::SUCCESS
                    });
                }

                if let NodeCmd::Tier { node, set, apply } = cmd {
                    let orch = SwarmOrchestrator::connect().await?;
                    let nodes = orch.nodes().await?;
                    let n = nodes
                        .iter()
                        .find(|n| &n.hostname == node || &n.id == node)
                        .ok_or_else(|| format!("node \"{node}\" not found"))?;

                    let value = match set {
                        Some(v) => v.clone(),
                        None => {
                            let mem = n
                                .memory_mb
                                .ok_or("node memory unknown: pass --set heavy|light")?;
                            hlb_orchestrator::cluster::tier_for_memory(mem).to_string()
                        }
                    };

                    if !apply {
                        println!(
                            "Would set tier={value} on {} ({}).",
                            n.hostname,
                            n.memory_mb
                                .map(|m| format!("{m} MB"))
                                .unwrap_or_else(|| "?".into())
                        );
                        if n.tier.as_deref() == Some(value.as_str()) {
                            println!("  (already this value — nothing would change)");
                        }
                        println!("\n  Re-run with --apply.");
                        return Ok(ExitCode::SUCCESS);
                    }

                    orch.label_node(&n.id, "tier", &value).await?;
                    println!("✓ {} -> tier={value}", n.hostname);

                    let state = open_state(&cli).await?;
                    state
                        .audit(
                            "cli",
                            ACTOR_ROLE,
                            "node-tier",
                            &n.hostname,
                            "ok",
                            Some(&value),
                        )
                        .await?;
                    return Ok(ExitCode::SUCCESS);
                }

                // Pure text generation: no SSH, no observation, nothing to connect to.
                if let NodeCmd::Preseed {
                    hostname,
                    domain,
                    disk,
                    ssh_key,
                    mirror,
                    encrypt,
                } = cmd
                {
                    let install_passphrase = if *encrypt {
                        Some(disk::install_passphrase(&cli, hostname).await?)
                    } else {
                        None
                    };
                    let out =
                        hlb_bootstrap::preseed::generate(&hlb_bootstrap::preseed::PreseedConfig {
                            hostname: hostname.clone(),
                            domain: domain.clone(),
                            disk_by_id: disk.clone(),
                            ssh_authorized_key: ssh_key.clone(),
                            mirror: mirror.clone(),
                            install_passphrase,
                        });
                    return match out {
                        Ok(text) => {
                            print!("{text}");
                            if *encrypt {
                                // stderr: stdout is the file the installer reads.
                                eprintln!(
                                    "⚠️  The disk's passphrase is in this file, in clear: once"
                                );
                                eprintln!(
                                    "   installed, add the node, then take it out of the disk:"
                                );
                                eprintln!("     hlb node add <host> --apply");
                                eprintln!("     hlb node bind-disk {hostname} --apply");
                            }
                            Ok(ExitCode::SUCCESS)
                        }
                        Err(e) => {
                            eprintln!("🔴 {e}");
                            Ok(ExitCode::FAILURE)
                        }
                    };
                }

                if let NodeCmd::Add {
                    host,
                    user,
                    port,
                    identity,
                    role,
                    advertise_addr,
                    endpoint,
                    behind_nat,
                    failure_domain,
                    storage_node,
                    apply,
                } = cmd
                {
                    return node_add(
                        &cli,
                        NodeAdd {
                            host,
                            user: user.as_deref(),
                            port: *port,
                            identity: identity.as_deref(),
                            role: role.as_deref(),
                            advertise_addr: advertise_addr.as_deref(),
                            endpoint: if *behind_nat {
                                None
                            } else {
                                Some(endpoint.as_deref().unwrap_or(host))
                            },
                            failure_domain: failure_domain.as_deref(),
                            storage_node: *storage_node,
                            apply: *apply,
                        },
                    )
                    .await;
                }

                let (runner, apply, storage) = match cmd {
                    NodeCmd::Check {
                        host,
                        user,
                        port,
                        identity,
                    } => (
                        build_runner(host.as_deref(), user.as_deref(), *port, identity.as_deref()),
                        false,
                        false,
                    ),
                    NodeCmd::Deps {
                        host,
                        user,
                        storage_node,
                        apply,
                    } => (
                        build_runner(host.as_deref(), user.as_deref(), None, None),
                        *apply,
                        *storage_node,
                    ),
                    // Handled above.
                    NodeCmd::Tier { .. }
                    | NodeCmd::Protection { .. }
                    | NodeCmd::BindDisk { .. }
                    | NodeCmd::VerifyBoot { .. }
                    | NodeCmd::Prune { .. }
                    | NodeCmd::Add { .. }
                    | NodeCmd::Preseed { .. }
                    | NodeCmd::Upgrade { .. } => {
                        unreachable!()
                    }
                };

                println!("Machine: {}\n", runner.label());
                let obs = hlb_bootstrap::observe(runner.as_ref()).await?;
                let report = hlb_bootstrap::preflight::run(&obs);

                for c in &report.checks {
                    println!("  {}", c.describe());
                }

                if matches!(cmd, NodeCmd::Check { .. }) {
                    println!();
                    print_protection(&hlb_bootstrap::observe::protection(runner.as_ref()).await?);
                    println!();
                    if report.can_proceed() {
                        println!("✓ this machine can host a node.");
                        return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                    }
                    eprintln!(
                        "🔴 {} — fix them before adding this node.",
                        hlb_api::plural(
                            report.blocking().len() as u64,
                            "blocking point",
                            "blocking points"
                        )
                    );
                    return Ok(ExitCode::FAILURE);
                }

                // hlb node deps: the provisioning plan.
                // A preview changes nothing, so it is shown even to a user who could
                // not apply it: that is how they learn what sudo would do.
                if apply && !report.can_proceed() {
                    eprintln!("\n🔴 fix the blocking points above first.");
                    return Ok(ExitCode::FAILURE);
                }
                let Some(distro) = report.distro else {
                    eprintln!("\n🔴 distribution not identified: cannot plan.");
                    return Ok(ExitCode::FAILURE);
                };

                println!();
                let ready =
                    provision_machine(runner.as_ref(), &distro, storage, apply, false).await?;
                if ready && !apply {
                    println!("\n  Re-run with --apply.");
                }
                Ok(if ready {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                })
            })
        }

        Command::Ps => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let o = SwarmOrchestrator::connect().await?;
                let services = o.list().await?;

                if services.is_empty() {
                    println!("No service managed by Homelabus.");
                    return Ok::<_, Box<dyn std::error::Error>>(ExitCode::SUCCESS);
                }

                println!("{:<20} {:>9}  IMAGE", "SERVICE", "REPLICAS");
                for s in services {
                    println!("{:<20} {:>9}  {}", s.name, s.replicas_text(), s.image);
                }
                Ok(ExitCode::SUCCESS)
            })
        }
    }
}

/// `hlb update lag`. Its last line is read by `scripts/drills/updates.sh`: keep its shape.
fn update_lag_report(lags: &hlb_state::UpdateLags) -> String {
    let days = |seconds: i64| seconds / 86_400;
    let mut out = String::new();
    for (title, list) in [("Applied", &lags.applied), ("Waiting", &lags.waiting)] {
        if !list.is_empty() {
            out.push_str(&format!("{title}:\n"));
        }
        for l in list {
            let short = l.digest.strip_prefix("sha256:").unwrap_or(&l.digest);
            let short = &short[..12.min(short.len())];
            out.push_str(&format!("  {:<14} {short}  {} d\n", l.app, days(l.seconds)));
        }
    }
    let slowest = lags.applied.iter().map(|l| l.seconds).max().unwrap_or(0);
    let oldest = lags.waiting.iter().map(|l| l.seconds).max().unwrap_or(0);
    out.push_str(&format!(
        "{} applied, the slowest in {} d; {} waiting, the oldest for {} d\n",
        lags.applied.len(),
        days(slowest),
        lags.waiting.len(),
        days(oldest)
    ));
    out
}

/// `hlb backup status`'s column. 🔴 The age counts successes only: an app whose reading has
/// just failed would still say "2 d", beside a green summary.
fn verified_column(age: Option<i64>, last_failed: bool) -> String {
    if last_failed {
        return "🔴 failed".to_string();
    }
    age.map(|s| fmt_age(std::time::Duration::from_secs(s.max(0) as u64)))
        .unwrap_or_else(|| "never".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_age_reads_in_english() {
        let day = std::time::Duration::from_secs(86_400);
        // "3 j" survived from the French original, past the word list: one letter is no
        // word. The lab's restores drill reads the unit, and counted no app read back.
        assert_eq!(super::fmt_age(day * 3), "3 d");
        assert_eq!(super::fmt_age(day), "24 h");
    }

    use super::*;

    #[test]
    fn the_lag_report_ends_on_the_line_a_drill_reads() {
        let lag = |app: &str, days: i64| hlb_state::UpdateLag {
            app: app.into(),
            digest: "sha256:0123456789abcdef".into(),
            seconds: days * 86_400,
        };
        let report = update_lag_report(&hlb_state::UpdateLags {
            applied: vec![lag("gitea", 4), lag("immich", 1)],
            waiting: vec![lag("n8n", 2)],
        });
        assert!(
            report.contains("gitea          0123456789ab  4 d"),
            "{report}"
        );
        assert_eq!(
            report.lines().last(),
            Some("2 applied, the slowest in 4 d; 1 waiting, the oldest for 2 d")
        );
        assert_eq!(
            update_lag_report(&hlb_state::UpdateLags::default()),
            "0 applied, the slowest in 0 d; 0 waiting, the oldest for 0 d\n"
        );
    }

    #[test]
    fn a_reading_that_failed_after_a_success_does_not_read_as_verified() {
        assert_eq!(verified_column(None, false), "never");
        assert_eq!(verified_column(Some(172_800), true), "🔴 failed");
        assert_ne!(verified_column(Some(172_800), false), "🔴 failed");
    }

    #[test]
    fn the_migrations_a_rollback_announces_are_every_one_shipped() {
        // 🔴 A list written here named six of 43: `self rollback` said "0 undone" over
        // migrations it then dropped.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../hlb-state/migrations");
        let ups = std::fs::read_dir(dir)
            .expect("migrations")
            .filter(|e| {
                e.as_ref()
                    .is_ok_and(|e| e.file_name().to_string_lossy().ends_with(".up.sql"))
            })
            .count();
        let known = known_migrations();
        assert_eq!(known.len(), ups);
        assert!(known.windows(2).all(|w| w[0].0 < w[1].0), "in order");
    }

    #[test]
    fn a_cluster_is_never_initialised_without_an_address_to_advertise() {
        // Without one Docker picked, or 127.0.0.1 was advertised: join tokens that send
        // every node to itself.
        use clap::Parser as _;
        let parses = |args: &[&str]| {
            let mut line = vec!["hlb", "cluster", "init"];
            line.extend_from_slice(args);
            Cli::try_parse_from(line).is_ok()
        };
        assert!(!parses(&[]));
        assert!(!parses(&["--no-mesh"]));
        assert!(!parses(&[
            "--endpoint",
            "203.0.113.4",
            "--advertise-addr",
            "10.0.0.1"
        ]));
        assert!(parses(&["--endpoint", "203.0.113.4"]));
        assert!(parses(&["--no-mesh", "--advertise-addr", "10.0.0.1"]));
    }

    #[test]
    fn a_duration_is_read_by_character_and_never_overflows() {
        // 🔴 Found by review: split at a byte, a multi-byte last character panicked;
        // and `n * 86_400` wrapped past i64.
        assert_eq!(parse_duration("30d"), Ok(30 * 86_400));
        assert_eq!(parse_duration(" 90m "), Ok(5_400));
        assert!(parse_duration("30é").is_err());
        assert!(parse_duration("é").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("9223372036854775807d").is_err());
        assert!(parse_duration("0d").is_err());
        assert!(parse_duration("-3h").is_err());
    }

    #[test]
    fn a_route_is_checked_whole_before_any_class_is_written() {
        // 🔴 Found by review: the critical class was written, then an unknown bulky
        // destination refused with "nothing was routed".
        let known = vec!["nas".to_string()];
        let critical = vec!["nas".to_string()];
        let bulky = vec!["ghost".to_string()];
        let asked: [(&str, &[String]); 2] = [("critical", &critical), ("bulky", &bulky)];
        assert_eq!(unknown_destination(&asked, &known), Some("ghost"));
        assert_eq!(unknown_destination(&asked[..1], &known), None);
    }

    #[test]
    fn a_pass_leaving_something_uncovered_does_not_succeed() {
        // 🔴 Found by review: `NotCovered` was counted nowhere, and a pass that dumped
        // no database said "Nothing was due." and exited 0.
        let clean = hlb_backup_run::Summary { done: 0, failed: 0 };
        assert_eq!(exit_of_pass(clean, 0), ExitCode::SUCCESS);
        assert_eq!(exit_of_pass(clean, 1), ExitCode::FAILURE);
        let failed = hlb_backup_run::Summary { done: 3, failed: 1 };
        assert_eq!(exit_of_pass(failed, 0), ExitCode::FAILURE);
    }
    use clap::CommandFactory as _;

    /// Every command line advertised to people, as written: the controller's and the
    /// engine's messages, the API's comments, the interface, and the command tour.
    fn advertised() -> Vec<String> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut text = String::new();
        let mut walked = 0;
        // The crates whose text reaches a person: the API's comments shown on the
        // access screen, and every crate answering through its types — the controller,
        // the privileged side, the engine's refusals. Derived from the manifests: the
        // privileged side's answers moved out of a list naming the controller, and the
        // lines they advertise would have left the scan without a word.
        let mut krates = vec!["hlb-api".to_string()];
        for e in std::fs::read_dir(root.join("crates")).expect("crates") {
            let dir = e.expect("entry").path();
            let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap_or_default();
            if manifest.lines().any(|l| l.starts_with("hlb-api")) {
                krates.extend(dir.file_name().and_then(|n| n.to_str()).map(str::to_string));
            }
        }
        assert!(
            ["hlb-controller", "hlb-privd", "hlb-engine"]
                .iter()
                .all(|k| krates.iter().any(|c| c == k)),
            "the walk lost a crate that answers people: {krates:?}"
        );
        for krate in &krates {
            fn rust(d: &std::path::Path, out: &mut String, n: &mut usize) {
                for e in std::fs::read_dir(d).expect("directory") {
                    let p = e.expect("entry").path();
                    if p.is_dir() {
                        rust(&p, out, n);
                    } else if p.extension().is_some_and(|e| e == "rs") {
                        let code = std::fs::read_to_string(&p).expect("source");
                        // Fixtures are advertised to nobody.
                        out.push_str(code.split("\n#[cfg(test)]").next().unwrap_or(""));
                        out.push('\n');
                        *n += 1;
                    }
                }
            }
            rust(
                &root.join("crates").join(krate).join("src"),
                &mut text,
                &mut walked,
            );
        }
        let web = root.join("web");
        let generated: Vec<std::path::PathBuf> = std::fs::read_to_string(web.join(".gitignore"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.strip_prefix("/src/"))
            .map(|l| web.join("src").join(l))
            .collect();
        fn walk(d: &std::path::Path, skip: &[std::path::PathBuf], out: &mut String, n: &mut usize) {
            for e in std::fs::read_dir(d).expect("directory") {
                let p = e.expect("entry").path();
                let name = p.to_string_lossy();
                if skip.iter().any(|g| p.starts_with(g)) || name.ends_with(".test.ts") {
                    continue;
                }
                if p.is_dir() {
                    walk(&p, skip, out, n);
                } else if let Ok(t) = std::fs::read_to_string(&p) {
                    out.push_str(&t);
                    *n += 1;
                }
            }
        }
        walk(&web.join("src"), &generated, &mut text, &mut walked);
        walk(&web.join("messages"), &generated, &mut text, &mut walked);
        assert!(walked > 150, "only {walked} sources walked");

        let mut lines = Vec::new();
        for quote in ['"', '`'] {
            let needle = format!("{quote}hlb ");
            let mut from = 0;
            while let Some(hit) = text[from..].find(&needle) {
                let start = from + hit + needle.len();
                let mut line = String::new();
                let mut quoted = false;
                let mut chars = text[start..].chars().peekable();
                while let Some(c) = chars.next() {
                    if c == quote || c == '\n' {
                        break;
                    }
                    if c == '\\' {
                        match chars.peek() {
                            // A string continued on the next line, in Rust or a JS
                            // template: the command goes on there.
                            Some('\n') => {
                                while chars.peek().is_some_and(|c| c.is_whitespace()) {
                                    chars.next();
                                }
                                line.push(' ');
                                continue;
                            }
                            // `--name \"Family\"`: a value quoted inside the string,
                            // opened after a space and closed before one.
                            Some(q)
                                if (*q == '"' || *q == '`') && (line.ends_with(' ') || quoted) =>
                            {
                                quoted = !quoted;
                                line.push(*q);
                                chars.next();
                                continue;
                            }
                            // `\"hlb dr exercise --apply\"` quoted inside a message.
                            Some(q) if *q == '"' || *q == '`' => break,
                            _ => {}
                        }
                    }
                    line.push(c);
                }
                lines.push(command_of(&line));
                from = start;
            }
        }
        // The tour's examples, run from the build directory.
        let tour = std::fs::read_to_string(root.join("docs/cli-tour.md")).expect("the tour");
        let mut pending = String::new();
        for raw in tour.lines() {
            let l = raw.trim();
            let l = if pending.is_empty() {
                match l.strip_prefix("./target/debug/hlb ") {
                    Some(rest) => rest,
                    None => continue,
                }
            } else {
                l
            };
            let l = l.split(" #").next().unwrap_or("").trim_end();
            match l.strip_suffix('\\') {
                Some(more) => {
                    pending.push_str(more);
                    pending.push(' ');
                }
                None => {
                    pending.push_str(l);
                    lines.push(std::mem::take(&mut pending));
                }
            }
        }
        lines
    }

    /// The command at the head of a sentence: `hlb dr exercise --apply, then …`.
    fn command_of(line: &str) -> String {
        let mut end = line.len();
        for stop in [", ", "; ", " — ", ": ", " (", ")", " then ", " and ", ". "] {
            if let Some(i) = line.find(stop) {
                end = end.min(i);
            }
        }
        let mut cmd = line[..end].trim().to_string();
        while cmd.ends_with(['.', ',', ':', ';']) {
            cmd.pop();
        }
        cmd
    }

    /// A line written to be run, as clap would receive it once its placeholders are
    /// filled; `None` for a verb named in passing (`hlb stop`), which the walk down the
    /// subcommands checks alone.
    fn runnable(line: &str) -> Option<Vec<String>> {
        let mut line = line;
        for shell in [" > ", " | ", " && "] {
            line = line.split(shell).next().unwrap_or("");
        }
        // Words as a shell splits them, a `<placeholder with spaces>` kept whole.
        let mut words: Vec<String> = Vec::new();
        let mut word = String::new();
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            let close = match c {
                '"' | '\'' => Some(c),
                '<' => Some('>'),
                '$' if chars.peek() == Some(&'(') => Some(')'),
                _ => None,
            };
            if let Some(close) = close {
                // A quoted value is the shell's; the quotes do not reach clap.
                let quoted = c == '"' || c == '\'';
                if !quoted {
                    word.push(c);
                }
                for n in chars.by_ref() {
                    if n == close {
                        break;
                    }
                    word.push(n);
                }
                if !quoted {
                    word.push(close);
                } else if word.is_empty() {
                    word.push('\u{2026}');
                }
            } else if c.is_whitespace() {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            } else {
                word.push(c);
            }
        }
        if !word.is_empty() {
            words.push(word);
        }
        let placeholder = |w: &str| w.contains(['{', '}', '<', '>', '\u{2026}', '$']) || w == "...";
        if !words.iter().any(|w| w.starts_with("--") || placeholder(w)) {
            return None;
        }
        let mut argv = vec!["hlb".to_string()];
        for w in &words {
            // `export${poolFlag}`: an optional fragment the page glues on.
            let w = match w.find("${") {
                Some(i) if i > 0 => &w[..i],
                _ => w.as_str(),
            };
            argv.push(if placeholder(w) {
                "1".into()
            } else {
                w.to_string()
            });
        }
        Some(argv)
    }

    #[test]
    fn the_daemon_is_never_run_twice() {
        // 🔴 Started first, the old task's clean shutdown removed the socket the new one
        // had bound, and the web side waited on it for ever (the lab, 2026-10-30).
        let cli = Cli::try_parse_from(["hlb", "ps"]).expect("a command");
        let dir = std::path::Path::new("/var/lib/homelabus");
        let spec = daemon_spec(
            &cli,
            "hlb-controller:1",
            "hlb-agent",
            "deb1",
            &dir.join("hlb.db"),
            std::path::Path::new("/etc/hlb/master.key"),
            &dir.join("privd.sock"),
        );
        assert!(spec.stops_first());
    }

    #[test]
    fn the_web_side_mounts_a_state_directory_holding_neither_the_key_nor_closed_files() {
        use std::os::unix::fs::PermissionsExt;
        let chmod = |p: &std::path::Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).expect("chmod")
        };
        let root = tempfile::tempdir().expect("tempdir");
        let dir = root.path().join("state");
        std::fs::create_dir(&dir).expect("dir");
        let state = dir.join("hlb.db");
        std::fs::write(&state, "").expect("state");
        let key = root.path().join("hlb-master.key");
        chmod(&dir, 0o755);
        chmod(&state, 0o644);
        assert_eq!(web_can_mount(&dir, &state, &key), Ok(()));

        let beside = dir.join("hlb-master.key");
        let refused = web_can_mount(&dir, &state, &beside).expect_err("the key beside it");
        assert!(refused.contains("key"), "{refused}");

        // `/root`'s shape: the web side's uid cannot even traverse it.
        chmod(&dir, 0o700);
        assert!(
            web_can_mount(&dir, &state, &key).is_err(),
            "a closed directory"
        );
        chmod(&dir, 0o755);
        chmod(&state, 0o600);
        assert!(web_can_mount(&dir, &state, &key).is_err(), "a closed state");
    }

    #[test]
    fn every_advertised_command_line_parses_as_written() {
        // 🔴 The walk below checks that each word and flag exists; a line can name
        // only real ones and still be refused when pasted. `hlb remove {app} --apply`
        // was advertised while `--apply` needs `--confirm`, and `hlb dr exercise
        // --apply` while the drill refuses without `--disposable`. clap holds those
        // requirements, so clap is asked, with the placeholders filled.
        use clap::Parser as _;
        let lines = advertised();
        assert!(
            lines.iter().any(|l| l.starts_with("remove ")),
            "the removal's command was not seen"
        );
        let mut wrong = Vec::new();
        let mut parsed = 0;
        for line in &lines {
            let Some(argv) = runnable(line) else {
                continue;
            };
            match Cli::try_parse_from(&argv) {
                Ok(_) => parsed += 1,
                Err(e) => {
                    use clap::error::ErrorKind;
                    match e.kind() {
                        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => parsed += 1,
                        // A placeholder clap cannot read as the value it wants, a
                        // number or one of a set, says nothing of the line.
                        ErrorKind::InvalidValue | ErrorKind::ValueValidation
                            if e.to_string().contains("'1'") =>
                        {
                            parsed += 1
                        }
                        _ => wrong.push(format!(
                            "hlb {line}\n    {}",
                            e.to_string().lines().next().unwrap_or("")
                        )),
                    }
                }
            }
        }
        assert!(parsed > 100, "only {parsed} lines parsed");
        wrong.sort();
        wrong.dedup();
        assert!(
            wrong.is_empty(),
            "advertised and refused when pasted:\n{}",
            wrong.join("\n")
        );
    }

    #[test]
    fn every_advertised_command_line_names_subcommands_that_exist() {
        // 🔴 `cli_command` is shown as "here is the equivalent command". The test this
        // one replaces read the first word only: `hlb user guest` passed on `user` for
        // two months, and nothing named `guest` existed. Walked down clap's own tree,
        // every word that must be a subcommand is checked to be one; a placeholder or a
        // flag ends the walk.
        let lines = advertised();
        assert!(
            lines.iter().any(|l| l.starts_with("user invite")),
            "the invitation's own command was not seen — is the walk reading the controller?"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("storage")),
            "the storage page's assembled command was not seen — is the walk reading .svelte?"
        );
        let mut wrong = Vec::new();
        let globals: Vec<String> = Cli::command()
            .get_arguments()
            .filter(|a| a.is_global_set())
            .filter_map(|a| a.get_long().map(str::to_string))
            .collect();
        for line in &lines {
            let mut cmd = Cli::command();
            // 🔴 The flags too, on the command the words reached: `hlb user add <name>
            // --apply` was advertised for months by four screens while `user add` had no
            // `--apply`, and clap refused the line pasted.
            let flags_of = |cmd: &clap::Command, wrong: &mut Vec<String>| {
                if cmd.has_subcommands() {
                    return;
                }
                for word in line.split_whitespace().filter(|w| w.starts_with("--")) {
                    let name: String = word[2..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                        .collect();
                    let known = name.is_empty()
                        || name == "help"
                        || globals.contains(&name)
                        || cmd
                            .get_arguments()
                            .any(|a| a.get_long() == Some(name.as_str()));
                    if !known {
                        wrong.push(format!(
                            "hlb {line}  (\"{}\" has no --{name})",
                            cmd.get_name()
                        ));
                    }
                }
            };
            for word in line.split_whitespace() {
                let plain = !word.is_empty()
                    && word
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                    && !word.starts_with('-');
                if !plain {
                    break;
                }
                // A leaf: a plain word is one of its positionals, or a mistake —
                // `hlb ingress apply` read as `hlb ingress` with a stray word.
                if !cmd.has_subcommands() {
                    if cmd.get_positionals().next().is_none() {
                        wrong.push(format!(
                            "hlb {line}  (\"{word}\": \"{}\" takes no argument)",
                            cmd.get_name()
                        ));
                    }
                    break;
                }
                match cmd.find_subcommand(word) {
                    Some(sub) => cmd = sub.clone(),
                    None => {
                        wrong.push(format!(
                            "hlb {line}  (no \"{word}\" under \"{}\")",
                            cmd.get_name()
                        ));
                        break;
                    }
                }
            }
            flags_of(&cmd, &mut wrong);
        }
        wrong.sort();
        wrong.dedup();
        assert!(
            wrong.is_empty(),
            "advertised and never written:\n{}",
            wrong.join("\n")
        );
    }
}
