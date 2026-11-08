//! The controller's state store.
//!
//! Two responsibilities:
//!   1. remember the **manifest frozen at deploy time** - the catalog can evolve
//!      without ever modifying a running app;
//!   2. journal the progress of plans, which gives **idempotency and resumability**
//!      for free.
//!
//! This database is not irreplaceable: it can be rebuilt from the Git repository and
//! from the Swarm itself.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use hlb_types::{Guide, Manifest};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

mod disks;
mod firmware;
mod flaws;
mod power;
mod reboots;
mod roles;
pub use disks::{Disk, NodeDisks, ZPool};
pub use firmware::{FirmwareUpdate, NodeFirmware};
pub use flaws::{host_key, Flaw, ImageScan};
pub use power::{PowerPhase, PowerStop, UpsPolicy, UpsReading, UpsState};
pub use reboots::{NodeReboot, RebootPhase, RebootPolicy, DEFAULT_REBOOT_WINDOW};
pub use roles::{AdminRecord, Holder, InUse, PersonQuota, QuotaRecord, QuotaState};

/// What a row of `backup_runs` backed up — its `kind`.
///
/// ⚠️ Stored values: renaming one orphans every row already written, and the app it
/// belongs to reads "never backed up".
pub mod backup_kind {
    /// An app's volumes, files as they are.
    pub const VOLUME: &str = "volume";
    /// A SQLite database's consistent snapshot.
    pub const SQLITE: &str = "sqlite-snapshot";
    /// A logical dump of a PostgreSQL or MariaDB database.
    pub const SQL_DUMP: &str = "sql-dump";
    /// Homelabus's own state database.
    pub const STATE: &str = "state";
    /// A bucket's objects, as one archive.
    pub const BUCKET: &str = "bucket";
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("state database: {0}")]
    Db(#[from] sqlx::Error),

    #[error("migration : {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// Opened read-only, a database its writer has not brought to this binary's schema.
    #[error("the state is at migration {applied}, this binary reads {latest}: the daemon migrates it when it starts")]
    NotMigrated { applied: i64, latest: i64 },

    #[error("unreadable stored manifest for \"{app}\": {source}")]
    StoredManifest {
        app: String,
        #[source]
        source: serde_yaml_ng::Error,
    },

    #[error("unreadable stored guide for \"{app}\": {source}")]
    StoredGuide {
        app: String,
        #[source]
        source: serde_yaml_ng::Error,
    },

    #[error("unknown app \"{0}\"")]
    UnknownApp(String),

    /// A domain reading the state holds and this binary cannot read: an error, since
    /// a baseline read as none would compare nothing, and alert on nothing.
    #[error("unreadable stored domain reading \"{key}\": {source}")]
    StoredDomain {
        key: &'static str,
        #[source]
        source: serde_json::Error,
    },

    #[error("unreadable stored power stop: {0}")]
    StoredPower(#[source] serde_json::Error),

    #[error("unreadable stored disk reading of {hostname}: {source}")]
    StoredDisks {
        hostname: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("unreadable stored firmware reading of {hostname}: {source}")]
    StoredFirmware {
        hostname: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("no role \"{0}\" — `hlb role list` names them")]
    UnknownRole(String),

    #[error("\"{0}\": a role id is lowercase letters, digits and hyphens, up to 40 — it names a PocketID group")]
    InvalidRole(String),

    #[error("logo: {0}")]
    Logo(#[from] LogoError),

    /// An address already given to another account as its mailbox.
    #[error("{address} is another account's mailbox")]
    MailboxTaken { address: String },

    /// Secrets written or removed between a rekey's reading and its rewrite.
    #[error(
        "the vault changed while it was being re-encrypted ({0}) — nothing was rewritten; \
         stop whatever writes secrets (the controller) and run it again"
    )]
    VaultChanged(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A logo larger than this would grow the database — which goes into the backups —
/// comfortably enough for an interface logo.
pub const MAX_LOGO_BYTES: usize = 256 * 1024;

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// The longer side a rasterized SVG logo is scaled to, in pixels — generous for a
/// sidebar/header mark shown well under 100 px tall, so it stays crisp on a 3x screen.
const RASTERIZED_LOGO_SIZE: f32 = 512.0;

/// What is wrong with a candidate logo, if anything.
#[derive(Debug, thiserror::Error)]
pub enum LogoError {
    #[error("{got_kb} KB, maximum {max_kb} KB")]
    TooLarge { got_kb: usize, max_kb: usize },
    #[error("not a PNG or an SVG (no matching signature)")]
    UnrecognisedFormat,
    #[error("could not parse the SVG: {0}")]
    InvalidSvg(String),
    #[error("could not rasterize the SVG: {0}")]
    RasterizeFailed(String),
}

/// Whether `bytes` open as a PNG — what may be stored without being parsed.
pub fn is_png(bytes: &[u8]) -> bool {
    bytes.starts_with(&PNG_SIGNATURE)
}

/// Accepts either PNG or SVG bytes and returns PNG bytes ready for
/// [`State::set_logo`]. Checked before the bytes reach `set_logo` so every entry
/// point — the CLI, `POST /api/appearance/logo` — accepts the same two formats, at the
/// same size limit, rather than independent copies of this logic drifting apart.
///
/// 🔴 An uploaded SVG is rasterized HERE, though every browser draws SVG: an SVG is a
/// document, it can carry `<script>`, and `/api/appearance/logo` serves it without
/// authentication from the controller's own origin. Opened directly, an operator's
/// upload would run as whoever opened it — an administrator, say. Response headers
/// (CSP `sandbox`, `nosniff`) can contain that; a PNG removes the question.
///
/// 🔴 Format is decided by SIGNATURE, never a declared extension or content-type:
/// serving an arbitrary file as `image/png` from our own origin would hand anyone
/// who found a way to set it a point of leverage.
pub fn prepare_logo(bytes: &[u8]) -> std::result::Result<Vec<u8>, LogoError> {
    let png = if bytes.starts_with(&PNG_SIGNATURE) {
        bytes.to_vec()
    } else if looks_like_svg(bytes) {
        rasterize_svg(bytes)?
    } else {
        return Err(LogoError::UnrecognisedFormat);
    };

    if png.len() > MAX_LOGO_BYTES {
        return Err(LogoError::TooLarge {
            got_kb: png.len() / 1024,
            max_kb: MAX_LOGO_BYTES / 1024,
        });
    }
    Ok(png)
}

/// XML declarations are optional and leading whitespace is legal — a bare signature
/// check on the first bytes would reject a perfectly valid SVG that happens to open
/// straight with `<svg`, or one preceded by a comment.
fn looks_like_svg(bytes: &[u8]) -> bool {
    let head: String = bytes
        .iter()
        .take(512)
        .map(|&b| b as char)
        .collect::<String>()
        .to_ascii_lowercase();
    head.contains("<svg")
}

fn rasterize_svg(svg_bytes: &[u8]) -> std::result::Result<Vec<u8>, LogoError> {
    let mut opt = resvg::usvg::Options::default();
    opt.fontdb_mut().load_system_fonts();
    let tree = resvg::usvg::Tree::from_data(svg_bytes, &opt)
        .map_err(|e| LogoError::InvalidSvg(e.to_string()))?;

    let size = tree.size();
    // Scale so the LONGER side lands on `RASTERIZED_LOGO_SIZE` — most logos are
    // wider than tall (a mark beside a wordmark), and scaling by the shorter side
    // would make those far larger than needed, defeating `MAX_LOGO_BYTES`.
    let scale = RASTERIZED_LOGO_SIZE / size.width().max(size.height());
    let width = (size.width() * scale).round().max(1.0) as u32;
    let height = (size.height() * scale).round().max(1.0) as u32;

    let mut pixmap = resvg::tiny_skia::Pixmap::new(width, height)
        .ok_or_else(|| LogoError::RasterizeFailed("empty SVG (zero size)".into()))?;
    resvg::render(
        &tree,
        resvg::tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    pixmap
        .encode_png()
        .map_err(|e| LogoError::RasterizeFailed(e.to_string()))
}

/// One backup run, as read back.
///
/// ## Why this type exists
///
/// Only the **ages** were readable (`seconds_since_last_success_of`). That is enough to
/// say "fine" or "not fine", not to answer "since when has it been broken, and what
/// changed that day". The timeline - one column per day, one row per destination -
/// needs the rows, not their summary.
/// The last run of a manifest's scheduled job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRun {
    pub app: String,
    pub job: String,
    /// Seconds since the epoch.
    pub ran_at: i64,
    pub succeeded: bool,
    /// The end of what it printed.
    pub output: String,
}

/// One image's time since this house first saw it proposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateLag {
    pub app: String,
    pub digest: String,
    pub seconds: i64,
}

/// What [`State::update_lags`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateLags {
    pub applied: Vec<UpdateLag>,
    pub waiting: Vec<UpdateLag>,
}

/// Who applies one waiting update, as the privileged side's pass last decided
/// ([`State::record_update_decision`]). `why`, `notes` and `refused` are JSON the state
/// does not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateDecision {
    pub app: String,
    /// The digest it moves to: an approval or a refusal holds for this one alone.
    pub digest: String,
    pub from_tag: String,
    /// `rebuild`, `version`, `catalog` or `companions`.
    pub kind: String,
    pub to_tag: Option<String>,
    /// `automatic`, `one-click` or `manual`.
    pub who: String,
    pub why: Option<String>,
    pub notes: Option<String>,
    pub decided_at: i64,
    /// The automatic path's last refusal of this digest, and when.
    pub refused: Option<String>,
    pub refused_at: Option<i64>,
    pub approved_by: Option<String>,
    pub approved_at: Option<i64>,
}

impl UpdateDecision {
    /// As the web side shows it. `None` for a row this version cannot read — a value a
    /// later version wrote — rather than a guess at it.
    pub fn waiting(&self) -> Option<hlb_api::updates::WaitingUpdate> {
        use hlb_api::updates::{UpdateMove, UpdateWho};
        fn json<T: serde::de::DeserializeOwned>(
            v: &Option<String>,
        ) -> serde_json::Result<Option<T>> {
            v.as_deref().map(serde_json::from_str).transpose()
        }
        Some(hlb_api::updates::WaitingUpdate {
            app: self.app.clone(),
            from_tag: self.from_tag.clone(),
            moves: UpdateMove::from_stored(&self.kind)?,
            to_tag: self.to_tag.clone(),
            who: UpdateWho::from_stored(&self.who)?,
            why: json(&self.why).ok()?,
            notes: json(&self.notes).ok()?,
            decided_at: self.decided_at,
            refused: json(&self.refused).ok()?,
            refused_at: self.refused_at,
            approved_by: self.approved_by.clone(),
            approved_at: self.approved_at,
        })
    }
}

/// A service stopped on purpose ([`State::hold_services`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceHold {
    pub service: String,
    pub why: String,
    /// What to give it back. `None`: held before this was recorded.
    pub replicas: Option<u64>,
}

/// How an image update ended. Stored by name in `update_runs.outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateRunOutcome {
    Applied,
    /// Swarm went back to the previous image by itself.
    RolledBack,
    /// Stopped half-way: the previous image would not start either.
    Paused,
    /// No conclusion within the deadline.
    Inconclusive,
}

impl UpdateRunOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::RolledBack => "rolled-back",
            Self::Paused => "paused",
            Self::Inconclusive => "inconclusive",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::Applied,
            Self::RolledBack,
            Self::Paused,
            Self::Inconclusive,
        ]
        .into_iter()
        .find(|o| o.as_str() == s)
    }
}

/// One image update's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateRun {
    pub id: i64,
    pub app: String,
    /// Seconds since the epoch.
    pub ran_at: i64,
    /// `repo:tag@digest`, before and after.
    pub from_image: String,
    pub to_image: String,
    pub outcome: UpdateRunOutcome,
    pub detail: String,
}

/// A notification quiet hours held back, waiting for them to end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldNotification {
    pub subject: String,
    /// The level as `hlb-notify` writes it (`important`).
    pub level: String,
    pub title: String,
    pub body: String,
    /// Seconds since the epoch, when the first notice on this subject was held.
    pub held_at: i64,
    /// Moves with each replacement: a delivery releases the version it sent only.
    pub revision: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRun {
    pub id: i64,
    pub app: String,
    /// `volume` | `database` | `pg-basebackup`…
    pub kind: String,
    /// `None` for rows predating multiple destinations (migration 0009).
    pub destination: Option<String>,
    pub snapshot_id: Option<String>,
    /// `ok` | `failed`.
    pub status: String,
    pub error: Option<String>,
    pub finished_at: String,
}

impl BackupRun {
    pub fn succeeded(&self) -> bool {
        self.status == "ok"
    }
}

/// A verification by real restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationRun {
    pub id: i64,
    pub app: String,
    pub snapshot_id: String,
    pub status: String,
    pub detail: Option<String>,
    pub verified_at: String,
}

/// Which signed index an app's frozen manifest came in, and which version of the app it
/// is there — both `None` for one read from a directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Release {
    pub index: Option<u64>,
    pub version: Option<String>,
}

/// Where a fetched source's cache is kept, given the directory holding the state.
pub fn source_cache(state_dir: &Path, name: &str) -> PathBuf {
    state_dir.join("catalog-sources").join(name)
}

/// The directory holding the database at `path`, made absolute without resolving
/// links: the mount a reader came through is the one its paths must go through.
fn home(path: &Path) -> Option<PathBuf> {
    std::path::absolute(path)
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
}

/// A third-party catalog source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogSource {
    pub name: String,
    /// Where its apps are read: the directory given, or a fetched source's cache.
    pub directory: String,
    /// A fetched source's: where its signed index is served, and the key it is held to.
    pub signed: Option<SignedSource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSource {
    pub url: String,
    pub key: String,
    /// The highest index counter read from it, `None` before the first fetch.
    pub counter: Option<u64>,
}

/// An audit log entry, as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub id: i64,
    pub at: String,
    pub actor: String,
    /// The role **at the time of the action**, not today's. Someone demoted since does
    /// not erase what they did while they could.
    pub role: String,
    pub action: String,
    pub target: String,
    /// `ok` | `refused` | `failed`. A refusal is not a failure: it is the system
    /// protecting the user.
    pub outcome: String,
    /// The diff, or whatever explains the outcome.
    pub detail: Option<String>,
}

/// The verdict on the log's chaining.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditIntegrity {
    Intact {
        verified: usize,
        /// Entries predating the chaining: not suspicious, simply outside the
        /// guarantee's reach.
        unchained: usize,
        /// The id of the first covered entry. `None` means none is.
        since_entry: Option<i64>,
    },
    /// 🔴 An entry was modified, removed or inserted.
    Broken { at_entry: i64, detail: String },
}

impl AuditIntegrity {
    pub fn is_intact(&self) -> bool {
        matches!(self, Self::Intact { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Intact {
                verified: 0,
                unchained,
                ..
            } => format!(
                "no chained entry ({unchained} predating the chaining, outside the \
                 guarantee)"
            ),
            Self::Intact {
                verified,
                unchained: 0,
                ..
            } => format!(
                "chain intact, {verified} {} verified",
                if *verified == 1 { "entry" } else { "entries" }
            ),
            Self::Intact {
                verified,
                unchained,
                since_entry,
            } => format!(
                "chain intact since entry {}: {verified} verified, {unchained} \
                 predating the chaining and therefore outside the guarantee",
                since_entry.unwrap_or(0)
            ),
            Self::Broken { at_entry, detail } => {
                format!("🔴 CHAIN BROKEN at entry {at_entry}: {detail}")
            }
        }
    }
}

/// One row of `backup_runs`.
fn backup_row(r: &sqlx::sqlite::SqliteRow) -> Result<BackupRun> {
    Ok(BackupRun {
        id: r.try_get("id")?,
        app: r.try_get("app")?,
        kind: r.try_get("kind")?,
        destination: r.try_get("destination")?,
        snapshot_id: r.try_get("snapshot_id")?,
        status: r.try_get("status")?,
        error: r.try_get("error")?,
        finished_at: r.try_get("finished_at")?,
    })
}

/// "7B8CFF" → `[0x7B, 0x8C, 0xFF]`.
///
/// Returns `None` on anything that is not exactly six hex digits: a half-read colour
/// would give an absurd accent, harder to diagnose than a missing one.
fn hex_rgb(s: &str) -> Option<[u8; 3]> {
    let s = s.trim().trim_start_matches('#');
    if s.len() != 6 {
        return None;
    }
    let d = |i: usize| u8::from_str_radix(&s[i..i + 2], 16).ok();
    Some([d(0)?, d(2)?, d(4)?])
}

/// A log entry's fingerprint, chained to the previous one.
///
/// `fields` is ordered: `[at, actor, role, action, target, outcome]`. Positional so the
/// two callers - the write and the verification - cannot diverge on the order without
/// the array changing shape.
///
/// 🔴 Each field is **length-prefixed** before being concatenated. A plain `|`-separated
/// concatenation would allow moving text from one field to the next without changing
/// the fingerprint: a target `gitea|ok` would become a target `gitea` with outcome
/// `ok`, and the chain would stay valid.
fn entry_fingerprint(prev: Option<&str>, fields: [&str; 6], detail: Option<&str>) -> String {
    let mut buf = String::new();
    for field in [prev.unwrap_or("")]
        .into_iter()
        .chain(fields)
        .chain([detail.unwrap_or("")])
    {
        buf.push_str(&field.len().to_string());
        buf.push(':');
        buf.push_str(field);
    }
    hlb_types::token::sha256_hex(buf.as_bytes())
}

/// The status of an action within a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionStatus {
    Pending,
    Done,
    Failed,
    /// An action recognised but not yet implemented by the executor.
    /// Explicitly distinct from `Done`: we never claim to have done it.
    Unimplemented,
}

impl ActionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Unimplemented => "unimplemented",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "done" => Self::Done,
            "failed" => Self::Failed,
            "unimplemented" => Self::Unimplemented,
            _ => Self::Pending,
        }
    }

    /// A finished action must never be replayed.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Done)
    }
}

#[derive(Debug, Clone)]
pub struct ActionRecord {
    pub seq: i64,
    pub kind: String,
    pub description: String,
    pub status: ActionStatus,
    pub error: Option<String>,
}

/// One measurement of the day kept for the home's curves: the web side measures
/// it, and asks for it to be kept.
pub use hlb_api::intent::Sample;

/// How the installation is reached from outside — `hlb config exposure`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposure {
    /// `example.org`: an app installed without a domain is published at
    /// `<name>.example.org`.
    pub domain: String,
    pub certificates: Certificates,
    /// Where Let's Encrypt sends expiry notices. Required with `Acme`.
    pub acme_email: Option<String>,
    /// The DNS module of a wildcard certificate. `None` with `Acme`: one certificate
    /// per name, over HTTP-01.
    pub dns_provider: Option<String>,
    pub staging: bool,
    /// Where the interface is published; `hlb.<domain>` when absent.
    pub controller_host: Option<String>,
    /// A private ACME directory in place of Let's Encrypt's.
    pub acme_ca: Option<String>,
    /// Its root, PEM: trusted by Caddy to talk to it, and by the controller to verify
    /// what it issued.
    pub acme_ca_root: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Certificates {
    /// Let's Encrypt.
    Acme,
    /// Caddy's own authority, for an installation no public name reaches.
    Internal,
}

impl Certificates {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Acme => "acme",
            Self::Internal => "internal",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "acme" => Some(Self::Acme),
            "internal" => Some(Self::Internal),
            _ => None,
        }
    }
}

impl Exposure {
    /// The name the interface answers at.
    pub fn controller_host(&self) -> String {
        self.controller_host
            .clone()
            .unwrap_or_else(|| format!("hlb.{}", self.domain))
    }

    /// The domain an app is published at when its install names none.
    pub fn default_domain(&self, app: &str) -> String {
        format!("{app}.{}", self.domain)
    }
}

/// A migration this binary carries: see [`State::shipped_migrations`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShippedMigration {
    pub version: i64,
    /// Its file's stem, `0004_backup_runs`.
    pub name: String,
    /// It has its `down`.
    pub reversible: bool,
}

/// The audit action of an app's removal. `hlb secrets-forget` reads it back as the proof
/// that a name was an app's, so its writers and its reader share this one spelling.
pub const APP_REMOVED: &str = "app-remove";

fn removed_domains_key(app: &str) -> String {
    format!("removed-domains:{app}")
}

/// Cheap to clone: the pool is shared.
#[derive(Clone)]
pub struct State {
    pool: SqlitePool,
    /// An in-memory database's second connection, never used: SQLite frees a shared
    /// in-memory database when its LAST connection closes.
    _keeper: Option<SqlitePool>,
    /// The directory holding the database, as THIS process sees it: the web side mounts
    /// it elsewhere than the CLI and privd, so a path one of them stores leads the other
    /// nowhere. `None` in memory.
    home: Option<PathBuf>,
}

/// `(mailbox, local, expires_at, active, hint, note)`, as `user_aliases` holds it.
type AliasRow = (
    String,
    String,
    Option<i64>,
    bool,
    Option<String>,
    Option<String>,
);

/// An account from its rows — the one assembly, for one account or for all of them.
fn assemble(
    name: &str,
    role: Option<String>,
    pocket_id: Option<String>,
    mailboxes: Vec<(String, String, bool)>,
    aliases: &[AliasRow],
) -> hlb_users::Account {
    use hlb_users::{Account, Alias, Duration, Mailbox};

    let mut c = Account::new(name, role.as_deref());
    c.pocket_id = pocket_id;
    for (local, domain, default) in mailboxes {
        let own: Vec<Alias> = aliases
            .iter()
            .filter(|(mailbox, ..)| mailbox == &local)
            .map(|(_, l, expire, active, _hint, note)| Alias {
                local: l.clone(),
                duration: match expire {
                    Some(e) => Duration::Temporary { expires_at: *e },
                    None => Duration::Permanent,
                },
                active: *active,
                note: note.clone(),
            })
            .collect();
        c.mailboxes.push(Mailbox {
            local,
            domain,
            default,
            aliases: own,
        });
    }
    c
}

/// Which recorded row each action of a new plan takes its progress from, by index.
///
/// A row is the action it recorded — kind and description — and serves one action at
/// most. The row at the action's own position is preferred, then a done one elsewhere
/// (an action moved by an insertion before it), then any other.
fn carry_progress(recorded: &[ActionRecord], plan: &[(String, String)]) -> Vec<Option<usize>> {
    let same = |r: &ActionRecord, (kind, description): &(String, String)| {
        r.kind == *kind && r.description == *description
    };
    let mut used = vec![false; recorded.len()];
    let mut out = Vec::with_capacity(plan.len());
    for (seq, action) in plan.iter().enumerate() {
        let free = |i: &usize| !used[*i] && same(&recorded[*i], action);
        let found = (0..recorded.len())
            .find(|i| recorded[*i].seq == seq as i64 && free(i))
            .or_else(|| {
                (0..recorded.len()).find(|i| recorded[*i].status == ActionStatus::Done && free(i))
            })
            .or_else(|| (0..recorded.len()).find(free));
        if let Some(i) = found {
            used[i] = true;
        }
        out.push(found);
    }
    out
}

impl State {
    /// Opens (and creates if needed) the database at `path`, then applies migrations.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let opts = SqliteConnectOptions::new()
            .filename(path.as_ref())
            .create_if_missing(true)
            // WAL: concurrent reads while a reconciliation writes.
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .foreign_keys(true);

        let mut state = Self::from_options(opts).await?;
        state.home = home(path.as_ref());
        Ok(state)
    }

    /// Opens the database at `path` for reading only — the web side's, while the daemon
    /// alone writes it.
    ///
    /// Never created and never migrated: the daemon does both. A database older than
    /// this binary's migrations is refused ([`Error::NotMigrated`]) rather than read
    /// with columns missing — the web side waits for the daemon instead.
    pub async fn open_read_only(path: impl AsRef<Path>) -> Result<Self> {
        let opts = SqliteConnectOptions::new()
            .filename(path.as_ref())
            .read_only(true)
            // No `journal_mode`: setting one is a write. WAL is the writer's, and stays.
            .foreign_keys(true);
        // Readers do not serialise: four answer four screens at once.
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await?;
        let latest = sqlx::migrate!("./migrations")
            .iter()
            .map(|m| m.version)
            .max()
            .unwrap_or(0);
        let applied: Option<i64> =
            sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success")
                .fetch_one(&pool)
                .await
                .unwrap_or(None);
        if applied.unwrap_or(0) < latest {
            return Err(Error::NotMigrated {
                applied: applied.unwrap_or(0),
                latest,
            });
        }
        Ok(Self {
            pool,
            _keeper: None,
            home: home(path.as_ref()),
        })
    }

    /// An in-memory database, for tests and the demonstration.
    pub async fn in_memory() -> Result<Self> {
        let opts = SqliteConnectOptions::from_str(":memory:")
            .map_err(Error::Db)?
            .foreign_keys(true);
        // 🔴 The database lives as long as a connection to it. `sqlx` closes one idle
        // for ten minutes and any older than thirty, and one it judges broken when it is
        // released — a request cancelled mid-query — then opens a fresh one: alone, onto
        // an empty database with no tables. Half an hour in, the demonstration answered
        // "no such table: apps"; with the lifetimes lifted, the browser suite's
        // controller still lost its tables mid-run, in CI. A second connection, held and
        // never used, keeps it whatever the pool does.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None);
        let keeper = pool.clone().connect_with(opts.clone()).await?;
        let mut state = Self::with_pool(pool, opts).await?;
        state._keeper = Some(keeper);
        Ok(state)
    }

    async fn from_options(opts: SqliteConnectOptions) -> Result<Self> {
        // One connection, as for memory: the writes are serialised by SQLite anyway.
        Self::with_pool(SqlitePoolOptions::new().max_connections(1), opts).await
    }

    async fn with_pool(pool: SqlitePoolOptions, opts: SqliteConnectOptions) -> Result<Self> {
        let pool = pool.connect_with(opts).await?;

        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self {
            pool,
            _keeper: None,
            home: None,
        })
    }

    /// Records the intention to install an app, freezing its manifest.
    pub async fn upsert_app(
        &self,
        name: &str,
        manifest: &Manifest,
        domain: Option<&str>,
    ) -> Result<()> {
        let yaml = serde_yaml_ng::to_string(manifest).map_err(|source| Error::StoredManifest {
            app: name.to_string(),
            source,
        })?;

        sqlx::query(
            "INSERT INTO apps (name, manifest, domain, status)
             VALUES (?1, ?2, ?3, 'installing')
             ON CONFLICT(name) DO UPDATE SET
                 manifest = excluded.manifest,
                 domain = excluded.domain,
                 updated_at = datetime('now')",
        )
        .bind(name)
        .bind(&yaml)
        .bind(domain)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// The manifest **as it was deployed**, not today's catalog.
    pub async fn app_manifest(&self, name: &str) -> Result<Manifest> {
        let row = sqlx::query("SELECT manifest FROM apps WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| Error::UnknownApp(name.to_string()))?;

        let yaml: String = row.try_get("manifest")?;
        serde_yaml_ng::from_str(&yaml).map_err(|source| Error::StoredManifest {
            app: name.to_string(),
            source,
        })
    }

    /// Freezes the guide an app is installed or upgraded with, beside its manifest:
    /// the steps acknowledged, re-checked and run after a restore are that guide's, not
    /// today's catalog's. `None` puts back an app recorded before guides were frozen.
    pub async fn set_app_guide(&self, name: &str, guide: Option<&Guide>) -> Result<()> {
        let yaml = guide
            .map(serde_yaml_ng::to_string)
            .transpose()
            .map_err(|source| Error::StoredGuide {
                app: name.to_string(),
                source,
            })?;
        let done = sqlx::query("UPDATE apps SET guide = ?2 WHERE name = ?1")
            .bind(name)
            .bind(yaml)
            .execute(&self.pool)
            .await?;
        if done.rows_affected() == 0 {
            return Err(Error::UnknownApp(name.to_string()));
        }
        Ok(())
    }

    /// The guide frozen with the app — `None` for one recorded before guides were, whose
    /// guide is still the catalog's.
    pub async fn app_guide(&self, name: &str) -> Result<Option<Guide>> {
        let row = sqlx::query("SELECT guide FROM apps WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| Error::UnknownApp(name.to_string()))?;
        let yaml: Option<String> = row.try_get("guide")?;
        yaml.map(|y| serde_yaml_ng::from_str(&y))
            .transpose()
            .map_err(|source| Error::StoredGuide {
                app: name.to_string(),
                source,
            })
    }

    /// Freezes the catalog source an app is installed from — `None` the official one —
    /// and the release of it, if it came in a signed index.
    pub async fn set_app_source(
        &self,
        name: &str,
        source: Option<&str>,
        release: &Release,
    ) -> Result<()> {
        let done = sqlx::query("UPDATE apps SET source = ?2 WHERE name = ?1")
            .bind(name)
            .bind(source)
            .execute(&self.pool)
            .await?;
        if done.rows_affected() == 0 {
            return Err(Error::UnknownApp(name.to_string()));
        }
        self.set_app_release(name, release).await
    }

    /// Freezes the release an app's manifest is — moved by an upgrade with the manifest,
    /// and back with it.
    pub async fn set_app_release(&self, name: &str, release: &Release) -> Result<()> {
        let done =
            sqlx::query("UPDATE apps SET source_index = ?2, source_version = ?3 WHERE name = ?1")
                .bind(name)
                .bind(release.index.map(|i| i as i64))
                .bind(release.version.as_deref())
                .execute(&self.pool)
                .await?;
        if done.rows_affected() == 0 {
            return Err(Error::UnknownApp(name.to_string()));
        }
        Ok(())
    }

    /// The catalog source an app was installed from — `None` for the official catalog.
    pub async fn app_source(&self, name: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT source FROM apps WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| Error::UnknownApp(name.to_string()))?;
        Ok(row.try_get("source")?)
    }

    /// The release an app's frozen manifest is.
    pub async fn app_release(&self, name: &str) -> Result<Release> {
        let row = sqlx::query("SELECT source_index, source_version FROM apps WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| Error::UnknownApp(name.to_string()))?;
        let index: Option<i64> = row.try_get("source_index")?;
        Ok(Release {
            index: index.map(|i| i as u64),
            version: row.try_get("source_version")?,
        })
    }

    /// Adds a third-party catalog source; `false` if one of that name exists already.
    pub async fn add_catalog_source(&self, source: &CatalogSource) -> Result<bool> {
        let (url, key) = source
            .signed
            .as_ref()
            .map(|s| (s.url.as_str(), s.key.as_str()))
            .unzip();
        let done = sqlx::query(
            "INSERT INTO catalog_sources (name, directory, url, key) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO NOTHING",
        )
        .bind(&source.name)
        .bind(&source.directory)
        .bind(url)
        .bind(key)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Records where a source this `hlb` names itself is served and the key it is held
    /// to — the official catalog's, carried by the binary. Written again at each start,
    /// so a release moving its address or rotating its key takes effect; the counter is
    /// KEPT, or a replay of an index older than the last one read would land after an
    /// upgrade.
    pub async fn set_carried_source(&self, source: &CatalogSource) -> Result<()> {
        let (url, key) = source
            .signed
            .as_ref()
            .map(|s| (s.url.as_str(), s.key.as_str()))
            .unzip();
        sqlx::query(
            "INSERT INTO catalog_sources (name, directory, url, key) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET
               directory = excluded.directory, url = excluded.url, key = excluded.key",
        )
        .bind(&source.name)
        .bind(&source.directory)
        .bind(url)
        .bind(key)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The catalog sources, by name.
    pub async fn catalog_sources(&self) -> Result<Vec<CatalogSource>> {
        let rows = sqlx::query(
            "SELECT name, directory, url, key, counter FROM catalog_sources ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let url: Option<String> = r.try_get("url")?;
                let key: Option<String> = r.try_get("key")?;
                let counter: Option<i64> = r.try_get("counter")?;
                let name: String = r.try_get("name")?;
                let signed = url.zip(key).map(|(url, key)| SignedSource {
                    url,
                    key,
                    counter: counter.map(|c| c as u64),
                });
                // A fetched source's cache is always beside the state, so it is derived
                // here rather than read: the stored path is the writer's view of it.
                let directory = match (&signed, &self.home) {
                    (Some(_), Some(home)) => source_cache(home, &name).display().to_string(),
                    _ => r.try_get("directory")?,
                };
                Ok(CatalogSource {
                    name,
                    directory,
                    signed,
                })
            })
            .collect()
    }

    /// Records the counter of the index just read from a source. Only ever up: a lower
    /// one changes nothing — `false` — since accepting it is how a replay would land.
    pub async fn raise_catalog_source_counter(&self, name: &str, counter: u64) -> Result<bool> {
        let done = sqlx::query(
            "UPDATE catalog_sources SET counter = ?2
             WHERE name = ?1 AND (counter IS NULL OR counter <= ?2)",
        )
        .bind(name)
        .bind(counter as i64)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Removes a catalog source; `false` if there was none of that name. The apps
    /// installed from it keep running from their frozen manifests.
    pub async fn remove_catalog_source(&self, name: &str) -> Result<bool> {
        let done = sqlx::query("DELETE FROM catalog_sources WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() == 1)
    }

    /// The domain chosen at install time, needed to resolve the templates.
    pub async fn app_domain(&self, name: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT domain FROM apps WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(r.try_get("domain")?),
            None => Ok(None),
        }
    }

    /// Keeps the mail domain an app's install took: an upgrade or a redeployment
    /// reading the exposure's again would give it mailboxes at another domain.
    pub async fn set_app_mail_domain(&self, name: &str, mail_domain: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE apps SET mail_domain = ?2 WHERE name = ?1")
            .bind(name)
            .bind(mail_domain)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The mail domain the app's install took, when one was kept.
    pub async fn app_mail_domain(&self, name: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT mail_domain FROM apps WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(r.try_get("mail_domain")?),
            None => Ok(None),
        }
    }

    /// The replica count decided for an app's own service by `hlb stop` / `hlb scale`;
    /// `None` gives it back to its manifest. Returns whether the app is recorded.
    pub async fn set_app_replicas(&self, name: &str, replicas: Option<u64>) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE apps SET replicas = ?2, updated_at = datetime('now') WHERE name = ?1",
        )
        .bind(name)
        .bind(replicas.map(|r| r as i64))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Adds a relative the sealed kit is mailed to; `false` when already there.
    pub async fn add_relative(&self, address: &str) -> Result<bool> {
        let r = sqlx::query(
            "INSERT INTO relatives (address, added)
             VALUES (?1, CAST(strftime('%s','now') AS INTEGER)) ON CONFLICT DO NOTHING",
        )
        .bind(address)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// `false` when `address` was not a relative.
    pub async fn remove_relative(&self, address: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM relatives WHERE address = ?1")
            .bind(address)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() == 1)
    }

    /// The relatives, in the order they were added.
    pub async fn relatives(&self) -> Result<Vec<String>> {
        Ok(
            sqlx::query_scalar("SELECT address FROM relatives ORDER BY added, address")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    /// Holds `services` stopped for `secs`: reconciliation leaves them as they are. Each
    /// comes with the replicas to give it back.
    ///
    /// 🔴 Held again, the larger count stays: a process that died holding a service left it
    /// at 0, which is what the next one reads, and it must not become what is given back.
    pub async fn hold_services(
        &self,
        services: &[(String, u64)],
        why: &str,
        secs: i64,
    ) -> Result<()> {
        for (service, replicas) in services {
            sqlx::query(
                "INSERT INTO service_holds (service, why, until, replicas)
                 VALUES (?1, ?2, CAST(strftime('%s','now') AS INTEGER) + ?3, ?4)
                 ON CONFLICT(service) DO UPDATE SET
                     why = excluded.why,
                     until = excluded.until,
                     replicas = MAX(COALESCE(service_holds.replicas, 0), excluded.replicas)",
            )
            .bind(service)
            .bind(why)
            .bind(secs)
            .bind(*replicas as i64)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Every hold, lapsed or not, by service: a lapsed one still says what to give back.
    pub async fn service_holds(&self) -> Result<Vec<ServiceHold>> {
        let rows = sqlx::query("SELECT service, why, replicas FROM service_holds ORDER BY service")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                Ok(ServiceHold {
                    service: r.try_get("service")?,
                    why: r.try_get("why")?,
                    replicas: r.try_get::<Option<i64>, _>("replicas")?.map(|n| n as u64),
                })
            })
            .collect()
    }

    /// Records the node whose volume a restore is about to write under `services`.
    pub async fn set_hold_node(&self, services: &[String], node: &str) -> Result<()> {
        for s in services {
            sqlx::query("UPDATE service_holds SET node = ?2 WHERE service = ?1")
                .bind(s)
                .bind(node)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    /// The node a hold on `service` recorded, lapsed or not: a restore that stopped halfway
    /// keeps the service down past its hold, and is what asks.
    pub async fn hold_node(&self, service: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT node FROM service_holds WHERE service = ?1")
            .bind(service)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| r.try_get("node").ok()).flatten())
    }

    pub async fn release_services(&self, services: &[String]) -> Result<()> {
        for s in services {
            sqlx::query("DELETE FROM service_holds WHERE service = ?1")
                .bind(s)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    /// Why `service` is held, while the hold lasts.
    pub async fn held(&self, service: &str) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT why FROM service_holds
             WHERE service = ?1 AND until > CAST(strftime('%s','now') AS INTEGER)",
        )
        .bind(service)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.try_get("why")).transpose()?)
    }

    /// The replica count decided for an app, over its manifest's — what reconciliation
    /// keeps and a deployment deploys.
    pub async fn app_replicas(&self, name: &str) -> Result<Option<u64>> {
        let row = sqlx::query("SELECT replicas FROM apps WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(r
                .try_get::<Option<i64>, _>("replicas")?
                .map(|n| n.max(0) as u64)),
            None => Ok(None),
        }
    }

    /// Records a volume and its real location.
    pub async fn add_volume(
        &self,
        app: &str,
        name: &str,
        mountpoint: &str,
        backup: bool,
        sqlite: bool,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO app_volumes (app, name, mountpoint, backup, sqlite)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(app, name) DO UPDATE SET
                 mountpoint = excluded.mountpoint,
                 backup = excluded.backup,
                 sqlite = excluded.sqlite",
        )
        .bind(app)
        .bind(name)
        .bind(mountpoint)
        .bind(backup as i64)
        .bind(sqlite as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The volumes containing a SQLite database.
    ///
    /// 🔴 Those can NOT be backed up by copying files: they need a consistent snapshot
    /// first. Returns `(app, name, mountpoint)`.
    pub async fn sqlite_volumes(&self) -> Result<Vec<(String, String, String)>> {
        let rows = sqlx::query(
            "SELECT app, name, mountpoint FROM app_volumes
             WHERE sqlite = 1 AND backup = 1 ORDER BY app, name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("app")?,
                    r.try_get("name")?,
                    r.try_get("mountpoint")?,
                ))
            })
            .collect()
    }

    /// Every backed-up volume: `(app, name, mountpoint, sqlite)`.
    pub async fn backed_up_volumes(&self) -> Result<Vec<(String, String, String, bool)>> {
        let rows = sqlx::query(
            "SELECT app, name, mountpoint, sqlite FROM app_volumes
             WHERE backup = 1 ORDER BY app, name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("app")?,
                    r.try_get("name")?,
                    r.try_get("mountpoint")?,
                    r.try_get::<i64, _>("sqlite")? != 0,
                ))
            })
            .collect()
    }

    /// Marks a volume as holding SQLite, found there by the pass whatever its manifest
    /// said. ⚠️ The next `add_volume` writes the manifest's word back; the next pass
    /// finds the database again.
    pub async fn mark_sqlite(&self, app: &str, name: &str) -> Result<()> {
        sqlx::query("UPDATE app_volumes SET sqlite = 1 WHERE app = ?1 AND name = ?2")
            .bind(app)
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// ALL of an app's volumes: (name, mountpoint, backed up, sqlite).
    ///
    /// ⚠️ Including those that are **not** backed up, unlike
    /// [`Self::volumes_to_backup`]. On a detail screen, a volume missing from the list
    /// reads as "it does not exist"; what needs to be seen is that it exists and is
    /// not protected.
    pub async fn app_volumes(&self, app: &str) -> Result<Vec<(String, String, bool, bool)>> {
        let rows = sqlx::query(
            "SELECT name, mountpoint, backup, sqlite FROM app_volumes
             WHERE app = ?1 ORDER BY name",
        )
        .bind(app)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("name")?,
                    r.try_get("mountpoint")?,
                    r.try_get::<i64, _>("backup")? != 0,
                    r.try_get::<i64, _>("sqlite")? != 0,
                ))
            })
            .collect()
    }

    /// Whether this house ever removed an app of this name, and it succeeded. A preview
    /// and a failure are logged under the same action, and prove nothing.
    pub async fn app_was_removed(&self, app: &str) -> Result<bool> {
        Ok(sqlx::query(
            "SELECT 1 FROM audit_log WHERE action = ?1 AND target = ?2 AND outcome = 'ok' LIMIT 1",
        )
        .bind(APP_REMOVED)
        .bind(app)
        .fetch_optional(&self.pool)
        .await?
        .is_some())
    }

    /// The audit log filtered on one target.
    pub async fn audit_for(&self, target: &str, limit: usize) -> Result<Vec<AuditRecord>> {
        let rows = sqlx::query(
            "SELECT id, at, actor, role, action, target, outcome, detail FROM audit_log
             WHERE target = ?1 ORDER BY at DESC, id DESC LIMIT ?2",
        )
        .bind(target)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok(AuditRecord {
                    id: r.try_get("id")?,
                    at: r.try_get("at")?,
                    actor: r.try_get("actor")?,
                    role: r.try_get("role")?,
                    action: r.try_get("action")?,
                    target: r.try_get("target")?,
                    outcome: r.try_get("outcome")?,
                    detail: r.try_get("detail")?,
                })
            })
            .collect()
    }

    /// The volumes of an app to back up: (name, mountpoint).
    ///
    /// Returns only those marked `backup` - a cache has no business taking space in the
    /// repository.
    pub async fn volumes_to_backup(&self, app: &str) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query(
            "SELECT name, mountpoint FROM app_volumes
             WHERE app = ?1 AND backup = 1 ORDER BY name",
        )
        .bind(app)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("name")?, r.try_get("mountpoint")?)))
            .collect()
    }

    /// Records an action in the audit log, chaining the entries.
    ///
    /// 🔴 Append-only: this crate exposes no way to delete or modify an entry. But a
    /// convention does not protect a SQLite file anyone can open: each entry therefore
    /// carries the previous one's fingerprint, so that a later modification breaks the
    /// chain and shows.
    ///
    /// The insert happens in an **immediate** transaction: without it, two simultaneous
    /// actions would read the same head fingerprint and produce two entries claiming
    /// the same predecessor - a forked chain, and therefore unverifiable.
    ///
    /// 🔴 `begin()` is DEFERRED. Under WAL the second writer then cannot upgrade its
    /// stale read and fails at once with "database is locked", busy timeout or not:
    /// the CLI's action done, its entry lost, because the controller wrote one too.
    pub async fn audit(
        &self,
        actor: &str,
        role: hlb_types::Role,
        action: &str,
        target: &str,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;

        let previous: Option<String> =
            sqlx::query("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
                .fetch_optional(&mut *tx)
                .await?
                .and_then(|r| r.try_get::<Option<String>, _>("hash").ok().flatten());

        // `datetime('now')` is computed here rather than left to the DEFAULT: the
        // fingerprint must cover the value actually recorded, and we cannot hash what
        // the database has not written yet.
        let at: String = sqlx::query("SELECT datetime('now') AS maintenant")
            .fetch_one(&mut *tx)
            .await?
            .try_get("maintenant")?;

        let fingerprint = entry_fingerprint(
            previous.as_deref(),
            [&at, actor, role.as_str(), action, target, outcome],
            detail,
        );

        sqlx::query(
            "INSERT INTO audit_log (at, actor, role, action, target, outcome, detail, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&at)
        .bind(actor)
        .bind(role.as_str())
        .bind(action)
        .bind(target)
        .bind(outcome)
        .bind(detail)
        .bind(previous.as_deref())
        .bind(&fingerprint)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// The most recent log entries, newest first.
    ///
    /// Returns a named type rather than a tuple: at seven fields, `t.4` means nothing,
    /// and swapping two columns of the same type would still compile.
    pub async fn audit_trail(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        let rows = sqlx::query(
            "SELECT id, at, actor, role, action, target, outcome, detail FROM audit_log
             ORDER BY at DESC, id DESC LIMIT ?1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok(AuditRecord {
                    id: r.try_get("id")?,
                    at: r.try_get("at")?,
                    actor: r.try_get("actor")?,
                    role: r.try_get("role")?,
                    action: r.try_get("action")?,
                    target: r.try_get("target")?,
                    outcome: r.try_get("outcome")?,
                    detail: r.try_get("detail")?,
                })
            })
            .collect()
    }

    /// One page of the log, newest first, narrowed by words and an outcome — and how
    /// many entries match, and how many there are. A log only grows: shown whole it
    /// was cut at 100 without a word, and a search over those 100 found nothing older.
    pub async fn audit_search(
        &self,
        words: &[String],
        outcome: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<AuditRecord>, u64, u64)> {
        // Each word must appear somewhere in the entry; `instr` rather than `LIKE`, so
        // a `%` or `_` typed in the search is a character, not a pattern.
        let mut filter = String::from("WHERE 1 = 1");
        for _ in words {
            filter.push_str(
                " AND instr(lower(actor || ' ' || action || ' ' || target || ' ' || \
                 coalesce(detail, '')), ?) > 0",
            );
        }
        if outcome.is_some() {
            filter.push_str(" AND outcome = ?");
        }
        let lowered: Vec<String> = words.iter().map(|w| w.to_lowercase()).collect();
        fn bind<'q>(
            sql: &'q str,
            words: &[String],
            outcome: Option<&str>,
        ) -> sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments> {
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            for w in words {
                q = q.bind(w.clone());
            }
            if let Some(o) = outcome {
                q = q.bind(o.to_string());
            }
            q
        }

        let page = format!(
            "SELECT id, at, actor, role, action, target, outcome, detail FROM audit_log
             {filter} ORDER BY at DESC, id DESC LIMIT {limit} OFFSET {offset}"
        );
        let rows = bind(&page, &lowered, outcome).fetch_all(&self.pool).await?;
        let count = format!("SELECT COUNT(*) AS n FROM audit_log {filter}");
        let matched: i64 = bind(&count, &lowered, outcome)
            .fetch_one(&self.pool)
            .await?
            .try_get("n")?;
        let total: i64 = sqlx::query("SELECT COUNT(*) AS n FROM audit_log")
            .fetch_one(&self.pool)
            .await?
            .try_get("n")?;

        let entries = rows
            .iter()
            .map(|r| {
                Ok(AuditRecord {
                    id: r.try_get("id")?,
                    at: r.try_get("at")?,
                    actor: r.try_get("actor")?,
                    role: r.try_get("role")?,
                    action: r.try_get("action")?,
                    target: r.try_get("target")?,
                    outcome: r.try_get("outcome")?,
                    detail: r.try_get("detail")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((entries, matched as u64, total as u64))
    }

    /// Checks the integrity of the log's chaining.
    ///
    /// 🔴 Returns a verdict **that says since when it holds**. Entries predating the
    /// chaining migration have no fingerprint and never will: computing them today
    /// would produce an apparently complete chain built on content that may already
    /// have been falsified. A guarantee we do not have must not look like one we do.
    pub async fn verify_audit_chain(&self) -> Result<AuditIntegrity> {
        let rows = sqlx::query(
            "SELECT id, at, actor, role, action, target, outcome, detail, prev_hash, hash
             FROM audit_log ORDER BY id ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut verified = 0usize;
        let mut unchained = 0usize;
        let mut since: Option<i64> = None;
        let mut expected: Option<String> = None;

        for r in &rows {
            let id: i64 = r.try_get("id")?;
            let hash: Option<String> = r.try_get("hash")?;
            let Some(hash) = hash else {
                // Predates the chaining: counted, and we move on.
                unchained += 1;
                continue;
            };

            let prev: Option<String> = r.try_get("prev_hash")?;
            if since.is_none() {
                // The first chained entry has no predecessor to compare against:
                // `expected` is still `None` and stays so until the end of this pass.
                since = Some(id);
            } else if prev.as_deref() != expected.as_deref() {
                return Ok(AuditIntegrity::Broken {
                    at_entry: id,
                    detail: "the entry does not name the fingerprint of the one before \
                             it: an entry was removed or inserted"
                        .to_string(),
                });
            }

            let (at, actor, role, action, target, outcome) = (
                r.try_get::<String, _>("at")?,
                r.try_get::<String, _>("actor")?,
                r.try_get::<String, _>("role")?,
                r.try_get::<String, _>("action")?,
                r.try_get::<String, _>("target")?,
                r.try_get::<String, _>("outcome")?,
            );
            let recomputed = entry_fingerprint(
                prev.as_deref(),
                [&at, &actor, &role, &action, &target, &outcome],
                r.try_get::<Option<String>, _>("detail")?.as_deref(),
            );
            if recomputed != hash {
                return Ok(AuditIntegrity::Broken {
                    at_entry: id,
                    detail: "the entry's content no longer matches its fingerprint: it \
                             was modified after the fact"
                        .to_string(),
                });
            }

            expected = Some(hash);
            verified += 1;
        }

        Ok(AuditIntegrity::Intact {
            verified,
            unchained,
            since_entry: since,
        })
    }

    /// Records a backup and its outcome.
    pub async fn record_backup(
        &self,
        app: &str,
        kind: &str,
        snapshot_id: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO backup_runs (app, kind, snapshot_id, status, error, finished_at)
             VALUES (?1, ?2, ?3, ?4, ?5, datetime('now'))",
        )
        .bind(app)
        .bind(kind)
        .bind(snapshot_id)
        .bind(if error.is_some() { "failed" } else { "ok" })
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// What a backup pass takes of `app`, as [`backup_kind`]s: its volumes, the
    /// consistent snapshot of its SQLite files, the dump of each database its frozen
    /// manifest declares. Empty: nothing to back up — Valkey, LibreSpeed — which is not
    /// "never backed up".
    /// The buckets of `app` its manifest says are backed up, by the name Garage gives
    /// them.
    pub async fn buckets_to_backup(&self, app: &str) -> Result<Vec<String>> {
        Ok(self
            .app_manifest(app)
            .await?
            .spec
            .requires
            .iter()
            .filter_map(|c| match c {
                hlb_types::Capability::ObjectStorage {
                    bucket,
                    backup: true,
                    expire_after_days: _,
                } => Some(hlb_types::capability::bucket_name(bucket.as_deref(), app).to_string()),
                _ => None,
            })
            .collect())
    }

    pub async fn backup_kinds(&self, app: &str) -> Result<Vec<&'static str>> {
        let volumes = self.volumes_to_backup(app).await?;
        let sqlite = self
            .app_volumes(app)
            .await?
            .iter()
            .any(|(_, _, b, s)| *b && *s);
        let databases = self
            .app_manifest(app)
            .await?
            .spec
            .requires
            .iter()
            .any(|c| matches!(c, hlb_types::Capability::Database { .. }));
        let buckets = !self.buckets_to_backup(app).await?.is_empty();
        Ok([
            (!volumes.is_empty(), backup_kind::VOLUME),
            (sqlite, backup_kind::SQLITE),
            (databases, backup_kind::SQL_DUMP),
            (buckets, backup_kind::BUCKET),
        ]
        .into_iter()
        .filter_map(|(has, kind)| has.then_some(kind))
        .collect())
    }

    /// Age of the last **successful** backup of each of `kinds`, on `destination` or
    /// anywhere: the OLDEST of them. `None` when one never succeeded, or `kinds` is
    /// empty.
    ///
    /// 🔴 By kind, never across them: a dump every pass made an app whose volume was
    /// backed up once read "backed up ten minutes ago" forever — and its volume was
    /// never due again. And the oldest, never the newest: a fresh dump does not make a
    /// stale volume any younger.
    ///
    /// Failures are deliberately ignored: a failure must not push the deadline back, or
    /// a broken backup would happen less and less often.
    pub async fn seconds_since_last_success_of(
        &self,
        app: &str,
        kinds: &[&str],
        destination: Option<&str>,
    ) -> Result<Option<i64>> {
        let mut oldest: Option<i64> = None;
        for kind in kinds {
            let row = sqlx::query(
                "SELECT CAST(strftime('%s','now') AS INTEGER)
                        - CAST(strftime('%s', MAX(finished_at)) AS INTEGER) AS age
                 FROM backup_runs
                 WHERE app = ?1 AND kind = ?2 AND status = 'ok'
                   AND (?3 IS NULL OR destination = ?3)",
            )
            .bind(app)
            .bind(kind)
            .bind(destination)
            .fetch_optional(&self.pool)
            .await?;
            let Some(age) = row.and_then(|r| r.try_get::<Option<i64>, _>("age").ok().flatten())
            else {
                return Ok(None);
            };
            oldest = Some(oldest.map_or(age, |o| o.max(age)));
        }
        Ok(oldest)
    }

    /// How old `app`'s backup is: every kind of its data counted, the oldest deciding
    /// (see [`Self::seconds_since_last_success_of`]). `None`: some of it was never
    /// backed up, or it has nothing to back up — [`Self::backup_kinds`] tells which.
    pub async fn backup_age(&self, app: &str) -> Result<Option<i64>> {
        let kinds = self.backup_kinds(app).await?;
        self.seconds_since_last_success_of(app, &kinds, None).await
    }

    /// Records a backup, naming its DESTINATION.
    ///
    /// 🔴 The destination is what makes the measurement honest. `record_backup` without
    /// it aggregates everything: a NAS backed up every 4 h would make an off-site dead
    /// for three weeks look like a 2 h old backup, and you would believe 3-2-1 held
    /// while only one copy remained.
    pub async fn record_backup_to(
        &self,
        app: &str,
        kind: &str,
        destination: &str,
        snapshot_id: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO backup_runs (app, kind, destination, snapshot_id, status, error, finished_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))",
        )
        .bind(app)
        .bind(kind)
        .bind(destination)
        .bind(snapshot_id)
        .bind(if error.is_some() { "failed" } else { "ok" })
        .bind(error)
        .execute(&self.pool)
        .await?;
        if let (Some(id), None) = (snapshot_id, error) {
            self.record_snapshot(app, destination, id).await?;
        }
        Ok(())
    }

    /// A restic snapshot Homelabus took: one a restore may take without being told its
    /// full id. Every one, not only the last of a pass — an app's second volume has a
    /// snapshot of its own.
    pub async fn record_snapshot(&self, app: &str, destination: &str, id: &str) -> Result<()> {
        sqlx::query(
            "INSERT OR IGNORE INTO snapshots_taken (snapshot_id, app, destination)
             VALUES (?1, ?2, ?3)",
        )
        .bind(id)
        .bind(app)
        .bind(destination)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Records what proving `destination` found. `location` is what was proved: a proof
    /// of another location says nothing about this one.
    pub async fn record_destination_proof(
        &self,
        destination: &str,
        location: &str,
        verdict: &str,
        detail: &str,
        at: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO destination_proofs (destination, location, verdict, detail, proven_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(destination) DO UPDATE SET location = excluded.location,
               verdict = excluded.verdict, detail = excluded.detail,
               proven_at = excluded.proven_at",
        )
        .bind(destination)
        .bind(location)
        .bind(verdict)
        .bind(detail)
        .bind(at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The last proof of `destination` at `location`: `(verdict, detail, proven_at)`.
    /// None when it was never proved there — moved since, it is to be proved again.
    pub async fn destination_proof(
        &self,
        destination: &str,
        location: &str,
    ) -> Result<Option<(String, String, i64)>> {
        Ok(sqlx::query_as(
            "SELECT verdict, detail, proven_at FROM destination_proofs
             WHERE destination = ?1 AND location = ?2",
        )
        .bind(destination)
        .bind(location)
        .fetch_optional(&self.pool)
        .await?)
    }

    /// The groups written into `app`'s organisation, by external id.
    pub async fn directory_groups(&self, app: &str) -> Result<std::collections::BTreeSet<String>> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT external_id FROM directory_groups WHERE app = ?1")
                .bind(app)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// After an import: `app`'s organisation holds exactly `groups` of Homelabus's.
    pub async fn set_directory_groups(
        &self,
        app: &str,
        groups: &std::collections::BTreeSet<String>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM directory_groups WHERE app = ?1")
            .bind(app)
            .execute(&mut *tx)
            .await?;
        for g in groups {
            sqlx::query("INSERT INTO directory_groups (app, external_id) VALUES (?1, ?2)")
                .bind(app)
                .bind(g)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// The ids of the snapshots Homelabus took of `app`.
    pub async fn snapshots_taken(&self, app: &str) -> Result<std::collections::HashSet<String>> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT snapshot_id FROM snapshots_taken WHERE app = ?1")
                .bind(app)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// The raw backup history of an app, newest first.
    ///
    /// 🔴 FAILURES are in it, and that is the point. Returning only successes would give
    /// a timeline where nothing ever went wrong, and a destination failing for three
    /// weeks would look like one that is simply not used.
    pub async fn backup_history(&self, app: &str, limit: usize) -> Result<Vec<BackupRun>> {
        let rows = sqlx::query(
            "SELECT id, app, kind, destination, snapshot_id, status, error, finished_at
             FROM backup_runs WHERE app = ?1
             ORDER BY finished_at DESC, id DESC LIMIT ?2",
        )
        .bind(app)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(backup_row).collect()
    }

    /// The history of EVERY app — for the global timeline.
    pub async fn backup_history_all(&self, limit: usize) -> Result<Vec<BackupRun>> {
        let rows = sqlx::query(
            "SELECT id, app, kind, destination, snapshot_id, status, error, finished_at
             FROM backup_runs ORDER BY finished_at DESC, id DESC LIMIT ?1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(backup_row).collect()
    }

    /// The restore verifications, newest first.
    ///
    /// This is the only reliable indicator that the backups really work: a backup never
    /// restored is a hypothesis, not a guarantee.
    pub async fn verifications(&self, app: &str, limit: usize) -> Result<Vec<VerificationRun>> {
        let rows = sqlx::query(
            "SELECT id, app, snapshot_id, status, detail, verified_at
             FROM restore_verifications WHERE app = ?1
             ORDER BY id DESC LIMIT ?2",
        )
        .bind(app)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok(VerificationRun {
                    id: r.try_get("id")?,
                    app: r.try_get("app")?,
                    snapshot_id: r.try_get("snapshot_id")?,
                    status: r.try_get("status")?,
                    detail: r.try_get("detail")?,
                    verified_at: r.try_get("verified_at")?,
                })
            })
            .collect()
    }

    /// Moves the timestamp of an app's last backup on a destination backwards.
    ///
    /// ⚠️ **Only for fabricating states**, in tests and in demo mode: a two-hour-old
    /// backup and a three-week-old one do not display the same, and the display is
    /// precisely what needs checking. There is no legitimate reason to backdate a real
    /// backup - doing so would lie about the one datum that says whether the data is
    /// protected.
    ///
    /// Touches only the most recent row, the one that decides freshness.
    pub async fn backdate_backup(&self, app: &str, destination: &str, seconds: i64) -> Result<()> {
        sqlx::query(
            "UPDATE backup_runs
             SET finished_at = datetime(finished_at, ?3)
             WHERE id = (SELECT id FROM backup_runs
                         WHERE app = ?1 AND destination = ?2
                         ORDER BY id DESC LIMIT 1)",
        )
        .bind(app)
        .bind(destination)
        .bind(format!("-{seconds} seconds"))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Backdates an audit log entry, by id.
    ///
    /// ⚠️ Same caveat as `backdate_backup`: **only** for fabricating a demo state. A
    /// timeline whose events all carry the same minute shows nothing - and that is
    /// exactly what it exists to show: "the app went down at 3:12" next to "update
    /// applied at 3:10".
    ///
    /// 🔴 NOT exposed by the API: rewriting an audit timestamp would break the chaining,
    /// and making that visible is the whole point of the chaining.
    pub async fn backdate_audit(&self, id: i64, seconds: i64) -> Result<()> {
        sqlx::query("UPDATE audit_log SET at = datetime(at, ?2) WHERE id = ?1")
            .bind(id)
            .bind(format!("-{seconds} seconds"))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// How many attempts HAVE FAILED since the last success?
    ///
    /// 🔴 Freshness alone is not enough. A destination failing on EVERY attempt stays
    /// "fresh" until the staleness threshold passes - twelve hours at the default
    /// interval. All that time, the dashboard shows a ✓ for a destination receiving
    /// nothing.
    ///
    /// A repeated failure is an immediate signal, not a deferred one.
    pub async fn consecutive_failures_on(&self, app: &str, destination: &str) -> Result<i64> {
        // ⚠️ Ordered by `id`, NOT by `finished_at`. `datetime('now')` has ONE SECOND
        // resolution: a success and the failure following it within the same second
        // carry the same timestamp, and a strict comparison excludes them - the counter
        // stays at zero while everything fails. The id is monotonic and has no such
        // flaw.
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM backup_runs
             WHERE app = ?1 AND destination = ?2 AND status = 'failed'
               AND id > COALESCE(
                     (SELECT MAX(id) FROM backup_runs
                      WHERE app = ?1 AND destination = ?2 AND status = 'ok'),
                     0)",
        )
        .bind(app)
        .bind(destination)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get::<i64, _>("n").unwrap_or(0))
    }

    /// Declares or updates a destination.
    pub async fn upsert_destination(
        &self,
        name: &str,
        location: &str,
        classes: &str,
        credentials_secret: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO backup_destinations (name, location, classes, credentials_secret)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET
               location = ?2, classes = ?3, credentials_secret = ?4",
        )
        .bind(name)
        .bind(location)
        .bind(classes)
        .bind(credentials_secret)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Changes the classes of a declared destination, and nothing else; `false` when no
    /// destination has that name.
    pub async fn set_destination_classes(&self, name: &str, classes: &str) -> Result<bool> {
        let r = sqlx::query("UPDATE backup_destinations SET classes = ?2 WHERE name = ?1")
            .bind(name)
            .bind(classes)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// The declared destinations: `(name, location, classes, secret)`.
    pub async fn destinations(&self) -> Result<Vec<(String, String, String, Option<String>)>> {
        let rows = sqlx::query(
            "SELECT name, location, classes, credentials_secret
             FROM backup_destinations ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("name")?,
                    r.try_get("location")?,
                    r.try_get("classes")?,
                    r.try_get("credentials_secret")?,
                ))
            })
            .collect()
    }

    pub async fn remove_destination(&self, name: &str) -> Result<()> {
        sqlx::query("DELETE FROM backup_destinations WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Routes one data class of an app to a set of destinations.
    ///
    /// Replaces the existing route for that app and class: silently adding would grow
    /// the routing on every call, and you would end up sending terabytes to a
    /// destination you believed removed.
    pub async fn set_route(&self, app: &str, class: &str, destinations: &[String]) -> Result<()> {
        self.set_routes(app, &[(class, destinations)]).await
    }

    /// Several classes' routes, all or none: a route half-written — the old one
    /// deleted, a destination refused — would leave the app backed up nowhere it was.
    pub async fn set_routes(&self, app: &str, routes: &[(&str, &[String])]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for (class, destinations) in routes {
            sqlx::query("DELETE FROM backup_routes WHERE app = ?1 AND class = ?2")
                .bind(app)
                .bind(class)
                .execute(&mut *tx)
                .await?;

            for d in destinations.iter() {
                sqlx::query(
                    "INSERT INTO backup_routes (app, class, destination) VALUES (?1, ?2, ?3)",
                )
                .bind(app)
                .bind(class)
                .bind(d)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// The destinations explicitly routed for this app and class.
    ///
    /// Empty means no explicit route; the caller then falls back to the classes each
    /// destination accepts globally.
    pub async fn route(&self, app: &str, class: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT destination FROM backup_routes
             WHERE app = ?1 AND class = ?2 ORDER BY destination",
        )
        .bind(app)
        .bind(class)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok(r.try_get("destination")?)).collect()
    }

    // ─────────────────── Accounts humains ───────────────────

    /// Registers an account, with the role it starts with.
    ///
    /// ⚠️ An account that exists keeps its role: resuming `hlb user add` with another
    /// one would change it with nobody recorded as granting it. That is
    /// [`Self::set_user_role`]'s.
    pub async fn upsert_user(&self, name: &str, role: &str, pocket_id: Option<&str>) -> Result<()> {
        sqlx::query(
            "INSERT INTO users (name, role, pocket_id) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET
               role = COALESCE(users.role, ?2),
               -- ⚠️ A known id is NEVER erased with a NULL: a resumed run passing here
               -- without the identity would lose the link to PocketID, and the account
               -- would become half-created again even though it is not.
               pocket_id = COALESCE(?3, users.pocket_id)",
        )
        .bind(name)
        .bind(role)
        .bind(pocket_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Creates an account that does not exist yet. `false` when the name is taken, and
    /// then nothing changed — two sign-ups racing for one name cannot both get it, nor
    /// the second rewrite the first's role.
    pub async fn create_user(&self, name: &str, role: &str) -> Result<bool> {
        let r = sqlx::query(
            "INSERT INTO users (name, role) VALUES (?1, ?2) ON CONFLICT(name) DO NOTHING",
        )
        .bind(name)
        .bind(role)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// `(name, role, pocket_id)`.
    pub async fn users(&self) -> Result<Vec<(String, Option<String>, Option<String>)>> {
        let rows = sqlx::query("SELECT name, role, pocket_id FROM users ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("name")?,
                    r.try_get("role")?,
                    r.try_get("pocket_id")?,
                ))
            })
            .collect()
    }

    /// Gives `user` the mailbox `local@domain` — refused with
    /// [`Error::MailboxTaken`] when it is another account's.
    pub async fn add_mailbox(
        &self,
        user: &str,
        local: &str,
        domain: &str,
        is_default: bool,
    ) -> Result<()> {
        if self
            .mailbox_owner(local, domain)
            .await?
            .is_some_and(|owner| owner != user)
        {
            return Err(Error::MailboxTaken {
                address: format!("{local}@{domain}"),
            });
        }
        // The migration's trigger refuses the same between this check and the insert.
        sqlx::query(
            "INSERT INTO user_mailboxes (user, local, domain, is_default)
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT(user, local) DO NOTHING",
        )
        .bind(user)
        .bind(local)
        .bind(domain)
        .bind(i64::from(is_default))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The account whose mailbox `local@domain` is.
    pub async fn mailbox_owner(&self, local: &str, domain: &str) -> Result<Option<String>> {
        let row = sqlx::query(
            "SELECT user FROM user_mailboxes WHERE local = ?1 AND domain = ?2
             ORDER BY created_at LIMIT 1",
        )
        .bind(local)
        .bind(domain)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(r) => Some(r.try_get("user")?),
            None => None,
        })
    }

    /// `(local, domain, default)`.
    pub async fn mailboxes(&self, user: &str) -> Result<Vec<(String, String, bool)>> {
        let rows = sqlx::query(
            "SELECT local, domain, is_default FROM user_mailboxes
             WHERE user = ?1 ORDER BY is_default DESC, local",
        )
        .bind(user)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("local")?,
                    r.try_get("domain")?,
                    r.try_get::<i64, _>("is_default")? != 0,
                ))
            })
            .collect()
    }

    /// Makes `local` the account's default mailbox — its identity. `false` when the
    /// account has no mailbox by that name, and then nothing changed.
    ///
    /// 🔴 One transaction: the schema cannot say "exactly one default", so clearing
    /// the old one and setting the new one in two statements would leave, between
    /// them, an account with none — or with two, if the second ran first.
    pub async fn set_default_mailbox(&self, user: &str, local: &str) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let owned = sqlx::query("SELECT 1 FROM user_mailboxes WHERE user = ?1 AND local = ?2")
            .bind(user)
            .bind(local)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        if !owned {
            return Ok(false);
        }
        sqlx::query("UPDATE user_mailboxes SET is_default = (local = ?2) WHERE user = ?1")
            .bind(user)
            .bind(local)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn remove_mailbox(&self, user: &str, local: &str) -> Result<()> {
        sqlx::query("DELETE FROM user_mailboxes WHERE user = ?1 AND local = ?2")
            .bind(user)
            .bind(local)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn add_alias(
        &self,
        user: &str,
        mailbox: &str,
        local: &str,
        expires_at: Option<i64>,
        hint: Option<&str>,
        note: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_aliases (user, mailbox, local, expires_at, hint, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(user)
        .bind(mailbox)
        .bind(local)
        .bind(expires_at)
        .bind(hint)
        .bind(note)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// `(mailbox, local, expires_at, active, hint, note)`.
    #[allow(clippy::type_complexity)]
    pub async fn aliases(
        &self,
        user: &str,
    ) -> Result<
        Vec<(
            String,
            String,
            Option<i64>,
            bool,
            Option<String>,
            Option<String>,
        )>,
    > {
        let rows = sqlx::query(
            "SELECT mailbox, local, expires_at, active, hint, note
             FROM user_aliases WHERE user = ?1 ORDER BY mailbox, local",
        )
        .bind(user)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("mailbox")?,
                    r.try_get("local")?,
                    r.try_get("expires_at")?,
                    r.try_get::<i64, _>("active")? != 0,
                    r.try_get("hint")?,
                    r.try_get("note")?,
                ))
            })
            .collect()
    }

    /// The expired temporary aliases THAT ARE STILL ACTIVE.
    ///
    /// 🔴 These are the broken promises: addresses their owner believes closed and that
    /// still receive. Longest-expired first - if the purge is interrupted, the doors
    /// open longest are the ones that will have been closed.
    pub async fn aliases_to_purge(&self, now: i64) -> Result<Vec<(String, String, String)>> {
        let rows = sqlx::query(
            "SELECT user, mailbox, local FROM user_aliases
             WHERE active = 1 AND expires_at IS NOT NULL AND expires_at <= ?1
             ORDER BY expires_at ASC",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("user")?,
                    r.try_get("mailbox")?,
                    r.try_get("local")?,
                ))
            })
            .collect()
    }

    /// A token's destination: `(user, mailbox)`.
    ///
    /// 🔴 The mailbox lives on the TOKEN because the addy.io protocol has no field to
    /// choose it - Bitwarden only sends `domain` and `description`. One token per
    /// mailbox, and changing destination means changing the token in the password
    /// manager's settings: explicit, and it can be read back.
    ///
    /// The mailbox is `None` for "the default one", which is the common case.
    pub async fn token_target(&self, token_name: &str) -> Result<(Option<String>, Option<String>)> {
        let row = sqlx::query("SELECT user, mailbox FROM api_tokens WHERE name = ?1")
            .bind(token_name)
            .fetch_optional(&self.pool)
            .await?;

        Ok(match row {
            Some(r) => (
                r.try_get::<Option<String>, _>("user").ok().flatten(),
                r.try_get::<Option<String>, _>("mailbox").ok().flatten(),
            ),
            None => (None, None),
        })
    }

    /// Sets the mailbox a token targets.
    pub async fn set_token_mailbox(&self, token_name: &str, mailbox: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE api_tokens SET mailbox = ?2 WHERE name = ?1")
            .bind(token_name)
            .bind(mailbox)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Binds an API token to a user.
    ///
    /// 🔴 Without this binding, the alias API would have to take the username in the
    /// request body - and a stolen token could then create aliases on anyone's
    /// mailbox.
    pub async fn set_token_user(&self, token_name: &str, user: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE api_tokens SET user = ?2 WHERE name = ?1")
            .bind(token_name)
            .bind(user)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The user this token is bound to, if any.
    ///
    /// `None` means a service token: it may not act on anyone's behalf.
    pub async fn token_user(&self, token_name: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT user FROM api_tokens WHERE name = ?1")
            .bind(token_name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| r.try_get::<Option<String>, _>("user").ok().flatten()))
    }

    /// Sets an alias's sorting folder.
    ///
    /// 🔴 `None` restores "nothing was decided" (a default will be offered); `Some("")`
    /// means "no sorting", and that is an EXPLICIT choice to be respected. Confusing
    /// the two would re-impose a folder on someone who does not want one, on every
    /// regeneration.
    pub async fn set_alias_folder(
        &self,
        user: &str,
        local: &str,
        folder: Option<&str>,
    ) -> Result<()> {
        sqlx::query("UPDATE user_aliases SET folder = ?3 WHERE user = ?1 AND local = ?2")
            .bind(user)
            .bind(local)
            .bind(folder)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// A mailbox's sorting rules: `(alias, folder, hint)`.
    ///
    /// INACTIVE aliases are excluded: sorting mail for an address that no longer exists
    /// would produce a dead rule, and the script would grow without end.
    #[allow(clippy::type_complexity)]
    pub async fn alias_rules(
        &self,
        user: &str,
        mailbox: &str,
    ) -> Result<Vec<(String, Option<String>, Option<String>)>> {
        let rows = sqlx::query(
            "SELECT local, folder, hint FROM user_aliases
             WHERE user = ?1 AND mailbox = ?2 AND active = 1 ORDER BY local",
        )
        .bind(user)
        .bind(mailbox)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("local")?,
                    r.try_get("folder")?,
                    r.try_get("hint")?,
                ))
            })
            .collect()
    }

    /// Marks an alias as removed from Stalwart.
    pub async fn deactivate_alias(&self, user: &str, local: &str) -> Result<()> {
        sqlx::query("UPDATE user_aliases SET active = 0 WHERE user = ?1 AND local = ?2")
            .bind(user)
            .bind(local)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Records a recovery drill.
    ///
    /// 🔴 Failures are recorded like successes. Keeping only successes would show a
    /// procedure "exercised last month" when the drill had failed - the exact opposite
    /// of what needs to be known.
    pub async fn record_drill(
        &self,
        scope: &str,
        ok: bool,
        tables: Option<i64>,
        duration_s: i64,
        detail: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO dr_drills (scope, status, tables, duration_s, detail)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(scope)
        .bind(if ok { "ok" } else { "failed" })
        .bind(tables)
        .bind(duration_s)
        .bind(detail)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Days since the last **SUCCESSFUL** drill.
    ///
    /// ⚠️ Successful only: a failed drill proves nothing about the ability to restore,
    /// and counting it would reset the counter for no reason.
    pub async fn days_since_successful_drill(&self) -> Result<Option<i64>> {
        let row = sqlx::query(
            "SELECT CAST((julianday('now') - julianday(MAX(finished_at))) AS INTEGER) AS d
             FROM dr_drills WHERE status = 'ok'",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.try_get::<Option<i64>, _>("d").ok().flatten()))
    }

    /// The most recent drills, newest first.
    pub async fn recent_drills(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, String, String, Option<i64>)>> {
        let rows = sqlx::query(
            "SELECT finished_at, scope, status, tables FROM dr_drills
             ORDER BY finished_at DESC, id DESC LIMIT ?1",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("finished_at")?,
                    r.try_get("scope")?,
                    r.try_get("status")?,
                    r.try_get("tables")?,
                ))
            })
            .collect()
    }

    /// Records an access token.
    ///
    /// 🔴 Only the fingerprint is kept: the value exists once, at the moment it is
    /// shown to the user. A name taken again is a NEW token: the old one's person and
    /// mailbox are cleared, or a service token reusing the name acted for them.
    pub async fn store_token(&self, t: &hlb_types::StoredToken) -> Result<()> {
        sqlx::query(
            "INSERT INTO api_tokens (name, fingerprint, role) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET
                 fingerprint = excluded.fingerprint,
                 role = excluded.role,
                 user = NULL,
                 mailbox = NULL,
                 created_at = datetime('now')",
        )
        .bind(&t.name)
        .bind(&t.fingerprint)
        .bind(t.role.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Finds the token matching a presented value.
    ///
    /// ⚠️ The lookup is by **fingerprint**, so a single indexed query: the table is not
    /// walked comparing one by one, which would make the response time depend on the
    /// number of tokens - and give away a side channel.
    pub async fn find_token(&self, presented: &str) -> Result<Option<hlb_types::StoredToken>> {
        let fingerprint = hlb_types::token::fingerprint_of(presented);

        let row =
            sqlx::query("SELECT name, fingerprint, role FROM api_tokens WHERE fingerprint = ?1")
                .bind(&fingerprint)
                .fetch_optional(&self.pool)
                .await?;

        let Some(r) = row else { return Ok(None) };
        let role: String = r.try_get("role")?;

        Ok(Some(hlb_types::StoredToken {
            name: r.try_get("name")?,
            fingerprint: r.try_get("fingerprint")?,
            // An unreadable role falls back to the LEAST permissive: a corrupt value
            // must never widen rights.
            role: hlb_types::Role::parse(&role).unwrap_or_default(),
        }))
    }

    /// Notes a token being used, to spot the forgotten ones.
    pub async fn touch_token(&self, name: &str) -> Result<()> {
        sqlx::query("UPDATE api_tokens SET last_used = datetime('now') WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The tokens: names, roles, last use. **Never the values.**
    pub async fn list_tokens(&self) -> Result<Vec<(String, String, Option<String>)>> {
        let rows = sqlx::query("SELECT name, role, last_used FROM api_tokens ORDER BY name")
            .fetch_all(&self.pool)
            .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("name")?,
                    r.try_get("role")?,
                    r.try_get("last_used")?,
                ))
            })
            .collect()
    }

    /// Revokes a token. Returns `false` when it did not exist.
    pub async fn revoke_token(&self, name: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM api_tokens WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Is there at least one token?
    ///
    /// 🔴 Used to refuse startup: an API with no token and no `--insecure-no-auth` would
    /// be wide open without anyone having decided it.
    pub async fn has_tokens(&self) -> Result<bool> {
        let row = sqlx::query("SELECT COUNT(*) AS n FROM api_tokens")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get::<i64, _>("n")? > 0)
    }

    /// Undoes migrations down to and including version `target`.
    ///
    /// 🔴 **A destructive operation.** Each `down` drops the tables its migration
    /// created: going back before `0005` erases the audit log, before `0004` the backup
    /// history. Each migration's `down` documents what is lost.
    ///
    /// ⚠️ `target` is the number of the last migration **kept**. Passing `4` undoes
    /// `0005` and `0006`, and keeps `0001` through `0004`.
    ///
    /// It exists only for a version rollback: an N binary cannot read an N+1 schema, and
    /// without this path there would be no way out.
    pub async fn undo_migrations(&self, target: i64) -> Result<()> {
        tracing::warn!(target, "🔴 schema rollback - a destructive operation");
        sqlx::migrate!("./migrations")
            .undo(&self.pool, target)
            .await?;
        Ok(())
    }

    /// Every migration compiled into this binary, and whether it can be undone.
    ///
    /// 🔴 Read from sqlx's own migrator — the migrations directory, at compile time.
    /// A list written beside it named six of 43: `hlb self rollback` announced nothing
    /// undone and dropped tables, and the self-update checked the reversibility of
    /// migrations from August only.
    pub fn shipped_migrations() -> Vec<ShippedMigration> {
        let migrator = sqlx::migrate!("./migrations");
        let undoable: std::collections::BTreeSet<i64> = migrator
            .iter()
            .filter(|m| m.migration_type.is_down_migration())
            .map(|m| m.version)
            .collect();
        migrator
            .iter()
            .filter(|m| !m.migration_type.is_down_migration())
            .map(|m| ShippedMigration {
                version: m.version,
                // sqlx reads `0004_backup_runs` as version 4, "backup runs".
                name: format!("{:04}_{}", m.version, m.description.replace(' ', "_")),
                reversible: undoable.contains(&m.version),
            })
            .collect()
    }

    /// The last applied migration.
    pub async fn schema_version(&self) -> Result<Option<i64>> {
        let row = sqlx::query("SELECT MAX(version) AS v FROM _sqlx_migrations")
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| r.try_get::<Option<i64>, _>("v").ok().flatten()))
    }

    /// Each app's databases, as its FROZEN manifest declares them.
    ///
    /// 🔴 The frozen manifest is read, not today's catalog: an app installed six months
    /// ago must be backed up according to what it asked for THEN. A catalog that had
    /// changed a database name would back up an empty database while letting the old
    /// one drift with no safety net.
    ///
    /// Returns `(app, engine, database, role, password secret)`.
    pub async fn app_databases(&self) -> Result<Vec<(String, String, String, String)>> {
        let mut out = Vec::new();

        for (app, status) in self.installed_apps().await? {
            // A failed app probably has no provisioned database; trying to back it up
            // would produce one failure per app on every pass.
            if status == "failed" {
                continue;
            }
            let Ok(m) = self.app_manifest(&app).await else {
                continue;
            };

            for c in &m.spec.requires {
                if let hlb_types::Capability::Database { engine, name, .. } = c {
                    // Same convention as the resolver: with no explicit name, the
                    // database carries the app's name. The two MUST stay aligned, or we
                    // would back up a database that does not exist.
                    let db = name.clone().unwrap_or_else(|| app.clone());
                    out.push((
                        app.clone(),
                        engine.service_name().to_string(),
                        db,
                        format!("{app}-db-password"),
                    ));
                }
            }
        }
        Ok(out)
    }

    /// The successful PostgreSQL base backups, oldest first.
    ///
    /// These are the possible starting points for a WAL replay. Failures are excluded:
    /// an incomplete base restores nothing, and listing it in the recoverable window
    /// would announce a guarantee we do not have.
    pub async fn base_backups(&self, app: &str) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query(
            "SELECT snapshot_id, CAST(strftime('%s', finished_at) AS INTEGER) AS at
             FROM backup_runs
             WHERE app = ?1 AND kind = 'pg-basebackup'
               AND status = 'ok' AND snapshot_id IS NOT NULL
             ORDER BY finished_at ASC, id ASC",
        )
        .bind(app)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|r| {
                Some((
                    r.try_get::<String, _>("snapshot_id").ok()?,
                    r.try_get::<i64, _>("at").ok()?,
                ))
            })
            .collect())
    }

    /// An app's most recent snapshot of `kind` on one of `destinations`, for
    /// verification: `(snapshot, destination)`.
    ///
    /// 🔴 Of one kind, and where it was written: the newest row of any kind was a dump,
    /// and verifying it said the app's volumes restored. A snapshot is read back from
    /// the destination holding it — another repository does not have it.
    pub async fn latest_snapshot(
        &self,
        app: &str,
        kind: &str,
        destinations: &[String],
    ) -> Result<Option<(String, String)>> {
        let rows = sqlx::query(
            "SELECT snapshot_id, destination FROM backup_runs
             WHERE app = ?1 AND kind = ?2 AND status = 'ok'
               AND snapshot_id IS NOT NULL AND destination IS NOT NULL
             -- `datetime('now')` has one-second resolution: two backups close together
             -- would carry the same timestamp. The auto-increment id breaks the tie
             -- reliably, because it follows insertion order.
             ORDER BY finished_at DESC, id DESC",
        )
        .bind(app)
        .bind(kind)
        .fetch_all(&self.pool)
        .await?;
        for r in rows {
            let destination: String = r.try_get("destination")?;
            if destinations.contains(&destination) {
                return Ok(Some((r.try_get("snapshot_id")?, destination)));
            }
        }
        Ok(None)
    }

    /// ⚠️ `succeeded` is a FIRST-CLASS argument, not inferred from `detail`.
    ///
    /// The previous signature concluded "a detail is present, therefore a failure": a
    /// caller describing a successful verification ("1,284 files read back") recorded it
    /// as a failure, and the app stayed forever "never verified" although the
    /// verification had happened. The compiler could not say so - the kind of implicit
    /// coupling this project distrusts elsewhere.
    pub async fn record_verification(
        &self,
        app: &str,
        snapshot_id: &str,
        succeeded: bool,
        detail: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO restore_verifications (app, snapshot_id, status, detail)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(app)
        .bind(snapshot_id)
        .bind(if succeeded { "ok" } else { "failed" })
        .bind(detail)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Age of the last successful verification, in seconds.
    pub async fn seconds_since_last_verification(&self, app: &str) -> Result<Option<i64>> {
        let row = sqlx::query(
            "SELECT CAST(strftime('%s','now') AS INTEGER)
                    - CAST(strftime('%s', MAX(verified_at)) AS INTEGER) AS age
             FROM restore_verifications WHERE app = ?1 AND status = 'ok'",
        )
        .bind(app)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.try_get::<Option<i64>, _>("age").ok().flatten()))
    }

    /// Age of the last verification of `app` however it ended, in seconds.
    pub async fn seconds_since_last_verification_attempt(&self, app: &str) -> Result<Option<i64>> {
        let row = sqlx::query(
            "SELECT CAST(strftime('%s','now') AS INTEGER)
                    - CAST(strftime('%s', MAX(verified_at)) AS INTEGER) AS age
             FROM restore_verifications WHERE app = ?1",
        )
        .bind(app)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.try_get::<Option<i64>, _>("age").ok().flatten()))
    }

    /// Did the latest restore verification of `app` fail?
    ///
    /// 🔴 The age above counts successes only, so a verification failing after one
    /// that worked changed nothing: the app stayed "verified" while the last attempt
    /// to read its backup back had failed.
    pub async fn last_verification_failed(&self, app: &str) -> Result<bool> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT status FROM restore_verifications WHERE app = ?1 ORDER BY id DESC LIMIT 1",
        )
        .bind(app)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some_and(|(status,)| status != "ok"))
    }

    /// Records what was ACTUALLY published.
    ///
    /// 🔴 Replaces the whole set, in a transaction: a route removed from the
    /// configuration must disappear from here too, or the exposure screen would report
    /// a divergence already fixed forever - and people would stop reading it.
    pub async fn record_ingress(&self, routes: &[(String, String, bool)]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM ingress_published")
            .execute(&mut *tx)
            .await?;
        for (host, app, public) in routes {
            sqlx::query("INSERT INTO ingress_published (host, app, public) VALUES (?1, ?2, ?3)")
                .bind(host)
                .bind(app)
                .bind(if *public { 1 } else { 0 })
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// The installation's time zone, `None` until `hlb config timezone` set it.
    pub async fn timezone(&self) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM settings WHERE key = 'timezone'")
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.try_get("value")).transpose()?)
    }

    pub async fn set_timezone(&self, zone: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES ('timezone', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')",
        )
        .bind(zone)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The SPF term of the relay mail leaves through (`include:spf.provider.net`) —
    /// what the domain's SPF must name besides Stalwart's own. `None` without a relay.
    pub async fn mail_relay_spf(&self) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM settings WHERE key = 'mail-relay-spf'")
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.try_get("value")).transpose()?)
    }

    pub async fn set_mail_relay_spf(&self, term: Option<&str>) -> Result<()> {
        match term {
            Some(t) => {
                sqlx::query(
                    "INSERT INTO settings (key, value) VALUES ('mail-relay-spf', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                                    updated_at = datetime('now')",
                )
                .bind(t)
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM settings WHERE key = 'mail-relay-spf'")
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// The domain's reading accepted by `hlb domain accept`: what later readings are
    /// compared with.
    pub async fn domain_baseline(&self) -> Result<Option<hlb_api::domain::Reading>> {
        self.domain_setting("domain-baseline").await
    }

    pub async fn set_domain_baseline(&self, r: &hlb_api::domain::Reading) -> Result<()> {
        self.put_domain_setting("domain-baseline", r).await
    }

    /// The domain's last reading, the night's or the CLI's.
    pub async fn domain_reading(&self) -> Result<Option<hlb_api::domain::Reading>> {
        self.domain_setting("domain-reading").await
    }

    pub async fn record_domain_reading(&self, r: &hlb_api::domain::Reading) -> Result<()> {
        self.put_domain_setting("domain-reading", r).await
    }

    const TRANSPARENCY: &'static str = "domain-transparency";

    /// Where the watch over the Certificate Transparency logs stands: the last issuance
    /// judged and those found foreign since the last `hlb domain accept`.
    pub async fn domain_transparency(&self) -> Result<hlb_api::domain::Transparency> {
        Ok(self
            .setting(Self::TRANSPARENCY)
            .await?
            .map(|v| {
                serde_json::from_str(&v).map_err(|source| Error::StoredDomain {
                    key: Self::TRANSPARENCY,
                    source,
                })
            })
            .transpose()?
            .unwrap_or_default())
    }

    pub async fn set_domain_transparency(&self, t: &hlb_api::domain::Transparency) -> Result<()> {
        let v = serde_json::to_string(t).map_err(|source| Error::StoredDomain {
            key: Self::TRANSPARENCY,
            source,
        })?;
        self.put_setting(Self::TRANSPARENCY, Some(&v)).await
    }

    async fn domain_setting(&self, key: &'static str) -> Result<Option<hlb_api::domain::Reading>> {
        self.setting(key)
            .await?
            .map(|v| serde_json::from_str(&v).map_err(|source| Error::StoredDomain { key, source }))
            .transpose()
    }

    async fn put_domain_setting(
        &self,
        key: &'static str,
        r: &hlb_api::domain::Reading,
    ) -> Result<()> {
        let v = serde_json::to_string(r).map_err(|source| Error::StoredDomain { key, source })?;
        self.put_setting(key, Some(&v)).await
    }

    /// The ACME account Homelabus opened in Stalwart for its public name's certificate.
    /// Kept so one a person opened is never taken for it, nor removed.
    pub async fn mail_acme_provider(&self) -> Result<Option<String>> {
        self.setting("mail-acme-provider").await
    }

    pub async fn set_mail_acme_provider(&self, id: Option<&str>) -> Result<()> {
        self.put_setting("mail-acme-provider", id).await
    }

    /// The certificate Homelabus gave Stalwart for its public name under its own root.
    /// Kept so it can be taken back once an ACME one replaces it: Stalwart serves the
    /// certificate of a name that ends LAST, and a ten-year leaf hides every renewal.
    pub async fn mail_public_certificate(&self) -> Result<Option<String>> {
        self.setting("mail-public-certificate").await
    }

    pub async fn set_mail_public_certificate(&self, id: Option<&str>) -> Result<()> {
        self.put_setting("mail-public-certificate", id).await
    }

    /// CrowdSec's local API as the bouncer reaches it, when
    /// `hlb crowdsec enroll --url <url>` recorded one other than the catalog's. Kept
    /// here, not in a flag, so every publication — the CLI's and the controller's
    /// alike — names the same one.
    pub async fn crowdsec_url(&self) -> Result<Option<String>> {
        self.setting("crowdsec-url").await
    }

    pub async fn set_crowdsec_url(&self, url: Option<&str>) -> Result<()> {
        self.put_setting("crowdsec-url", url).await
    }

    /// When each mTLS leaf deployed as a service ends, in seconds since the epoch, by
    /// service name: written when one is issued, and by the controller from the
    /// certificate it was started with. A Swarm secret cannot be read back, so this is
    /// the one place the agents' leaf is known.
    pub async fn leaf_expiries(&self) -> Result<Vec<(String, i64)>> {
        let rows =
            sqlx::query("SELECT key, value FROM settings WHERE key LIKE 'pki-leaf:%' ORDER BY key")
                .fetch_all(&self.pool)
                .await?;
        let mut out = Vec::new();
        for r in rows {
            let key: String = r.try_get("key")?;
            let value: String = r.try_get("value")?;
            // A row nobody can read says nothing: left out, the leaf reads unknown.
            if let (Some(service), Ok(at)) = (key.strip_prefix("pki-leaf:"), value.parse()) {
                out.push((service.to_string(), at));
            }
        }
        Ok(out)
    }

    pub async fn set_leaf_expiry(&self, service: &str, not_after: Option<i64>) -> Result<()> {
        let value = not_after.map(|t| t.to_string());
        self.put_setting(&format!("pki-leaf:{service}"), value.as_deref())
            .await
    }

    pub(crate) async fn setting(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM settings WHERE key = ?1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.try_get("value")).transpose()?)
    }

    pub(crate) async fn put_setting(&self, key: &str, value: Option<&str>) -> Result<()> {
        match value {
            Some(v) => {
                sqlx::query(
                    "INSERT INTO settings (key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                                    updated_at = datetime('now')",
                )
                .bind(key)
                .bind(v)
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM settings WHERE key = ?1")
                    .bind(key)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// How the installation is reached — `None` until `hlb config exposure` set it.
    pub async fn exposure(&self) -> Result<Option<Exposure>> {
        let Some(r) = sqlx::query(
            "SELECT domain, certificates, acme_email, dns_provider, staging, controller_host,
                    acme_ca, acme_ca_root
             FROM exposure WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };
        let certificates: String = r.try_get("certificates")?;
        Ok(Some(Exposure {
            domain: r.try_get("domain")?,
            // The column's CHECK holds the two values: anything else is a database
            // edited by hand, read as the one that publishes nothing to the internet.
            certificates: Certificates::parse(&certificates).unwrap_or(Certificates::Internal),
            acme_email: r.try_get("acme_email")?,
            dns_provider: r.try_get("dns_provider")?,
            staging: r.try_get::<i64, _>("staging")? != 0,
            controller_host: r.try_get("controller_host")?,
            acme_ca: r.try_get("acme_ca")?,
            acme_ca_root: r.try_get("acme_ca_root")?,
        }))
    }

    pub async fn set_exposure(&self, e: &Exposure) -> Result<()> {
        sqlx::query(
            "INSERT INTO exposure
               (id, domain, certificates, acme_email, dns_provider, staging, controller_host,
                acme_ca, acme_ca_root)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
               domain = excluded.domain, certificates = excluded.certificates,
               acme_email = excluded.acme_email, dns_provider = excluded.dns_provider,
               staging = excluded.staging, controller_host = excluded.controller_host,
               acme_ca = excluded.acme_ca, acme_ca_root = excluded.acme_ca_root,
               modified_at = datetime('now')",
        )
        .bind(&e.domain)
        .bind(e.certificates.as_str())
        .bind(&e.acme_email)
        .bind(&e.dns_provider)
        .bind(i64::from(e.staging))
        .bind(&e.controller_host)
        .bind(&e.acme_ca)
        .bind(&e.acme_ca_root)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Marks done every action of `kind` recorded as unimplemented, and moves an app
    /// whose last such action it was from `partial` to `running`. Returns those apps.
    ///
    /// For a publication: an app installed before the ingress has its route recorded
    /// unimplemented, honestly — and the ingress's first publication routes it, which
    /// makes it true. Left as it was, the app would stay "partial" forever over a route
    /// that answers.
    ///
    /// Only for `among`: the apps it is true of. A route withheld (its chain gone from hlb) or
    /// left out (a failed install) was not published, and marked done with the others
    /// it would never have been asked for again.
    pub async fn complete_unimplemented(
        &self,
        kind: &str,
        among: &[String],
    ) -> Result<Vec<String>> {
        let mut tx = self.pool.begin().await?;
        let mut apps = Vec::new();
        for app in sqlx::query(
            "SELECT DISTINCT app FROM plan_actions
             WHERE kind = ?1 AND status = 'unimplemented' ORDER BY app",
        )
        .bind(kind)
        .fetch_all(&mut *tx)
        .await?
        {
            let app: String = app.try_get("app")?;
            if among.contains(&app) {
                apps.push(app);
            }
        }
        for app in &apps {
            sqlx::query(
                "UPDATE plan_actions SET status = 'done', error = NULL, updated_at = datetime('now')
                 WHERE app = ?1 AND kind = ?2 AND status = 'unimplemented'",
            )
            .bind(app)
            .bind(kind)
            .execute(&mut *tx)
            .await?;
        }
        for app in &apps {
            sqlx::query(
                "UPDATE apps SET status = 'running', updated_at = datetime('now')
                 WHERE name = ?1 AND status = 'partial' AND NOT EXISTS (
                   SELECT 1 FROM plan_actions WHERE app = ?1 AND status = 'unimplemented')",
            )
            .bind(app)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(apps)
    }

    /// What is published according to the last apply.
    ///
    /// ⚠️ An empty list means "the ingress configuration was never applied", **not**
    /// "nothing is published". The caller must tell the two apart: confusing them would
    /// announce a closed cluster when we know nothing of the sort.
    pub async fn published_ingress(&self) -> Result<Vec<(String, String, bool)>> {
        let rows = sqlx::query("SELECT host, app, public FROM ingress_published ORDER BY host")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("host")?,
                    r.try_get("app")?,
                    r.try_get::<i64, _>("public")? != 0,
                ))
            })
            .collect()
    }

    /// Freezes the digest resolved at deploy time.
    ///
    /// The stored manifest is rewritten: the digest is what is authoritative from then
    /// on, not the tag.
    /// Freezes the digest of one of an app's images — its own or a companion's — the
    /// one whose repository and tag match. `false` when none does.
    ///
    /// 🔴 Not the app's image whatever was resolved: Immich's machine-learning digest
    /// landed on the server's image, and both were deployed as `immich-server:v3.1.0@`
    /// a digest that exists for neither (found on a real cluster).
    pub async fn set_image_digest(
        &self,
        name: &str,
        repo: &str,
        tag: &str,
        digest: &str,
    ) -> Result<bool> {
        let mut m = self.app_manifest(name).await?;
        let mut found = false;
        for image in std::iter::once(&mut m.spec.image)
            .chain(m.spec.companions.iter_mut().map(|c| &mut c.image))
        {
            if image.repo == repo && image.tag == tag {
                image.digest = Some(digest.to_string());
                found = true;
            }
        }
        if found {
            self.upsert_app(name, &m, self.app_domain(name).await?.as_deref())
                .await?;
        }
        Ok(found)
    }

    pub async fn set_app_digest(&self, name: &str, digest: &str) -> Result<()> {
        let mut m = self.app_manifest(name).await?;
        m.spec.image.digest = Some(digest.to_string());
        self.upsert_app(name, &m, self.app_domain(name).await?.as_deref())
            .await
    }

    /// Forgets an application: its manifest, its plan, its guides and its volume
    /// declarations.
    ///
    /// 🔴 Forgetting is NOT deleting. The Docker volumes stay, the backups stay, the
    /// audit log stays — this only drops what Homelabus knows about the app. The data
    /// outliving the app is the whole point: a deletion you cannot come back from is
    /// not a feature, and restoring a backup into a reinstalled app is the ordinary way
    /// out of a mistake.
    ///
    /// ⚠️ `plan_actions`, `pending_guides` and `app_volumes` go through
    /// `ON DELETE CASCADE`. Deleting them by hand here would drift the day a table is
    /// added — and the orphan rows would resurface as a ghost app on the next screen
    /// that walks them.
    ///
    /// The domain of an app behind the portal is kept apart: what the portal accepts for
    /// it is computed from the domain, which nothing else remembers once the app is gone.
    pub async fn forget_app(&self, name: &str) -> Result<()> {
        let behind_portal = self.app_manifest(name).await.is_ok_and(|m| {
            m.spec.requires.iter().any(|need| {
                matches!(
                    need,
                    hlb_types::capability::Capability::Sso {
                        mode: hlb_types::capability::SsoMode::ProxyOnly
                            | hlb_types::capability::SsoMode::ProxyHeader,
                        redirect_paths: _,
                    }
                )
            })
        });
        if let (true, Some(domain)) = (behind_portal, self.app_domain(name).await?) {
            let mut domains = self.removed_domains(name).await?;
            if !domains.contains(&domain) {
                domains.push(domain);
                self.put_setting(&removed_domains_key(name), Some(&domains.join("\n")))
                    .await?;
            }
        }
        sqlx::query("DELETE FROM apps WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The domains an app was published at when it was removed.
    pub async fn removed_domains(&self, app: &str) -> Result<Vec<String>> {
        Ok(self
            .setting(&removed_domains_key(app))
            .await?
            .map(|all| all.lines().map(str::to_string).collect())
            .unwrap_or_default())
    }

    /// Nothing is left at the domains [`Self::removed_domains`] kept for this app.
    pub async fn clear_removed_domains(&self, app: &str) -> Result<()> {
        self.put_setting(&removed_domains_key(app), None).await
    }

    pub async fn set_app_status(&self, name: &str, status: &str) -> Result<()> {
        sqlx::query("UPDATE apps SET status = ?2, updated_at = datetime('now') WHERE name = ?1")
            .bind(name)
            .bind(status)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn installed_apps(&self) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query("SELECT name, status FROM apps ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("name")?, r.try_get("status")?)))
            .collect()
    }

    /// Records one uptime sample for the status page's history. Called once
    /// per service per reconcile tick — at the default 60 s interval, 90 days is
    /// ~130k rows per service, trivial for SQLite.
    pub async fn record_uptime_sample(
        &self,
        service: &str,
        state: hlb_api::ServiceState,
    ) -> Result<()> {
        sqlx::query("INSERT INTO service_uptime_samples (service, state) VALUES (?1, ?2)")
            .bind(service)
            .bind(service_state_str(state))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The last `days` days' WORST state for `service`, oldest first.
    ///
    /// 🔴 A day with no sample is `None`, never coerced to `Operational`: "an empty
    /// series is not a zero series" — the same rule this project already applies to
    /// `Series::Unavailable` elsewhere. The summary shows the worst case for the same
    /// reason a backup destination's freshness does: it must not contradict the detail
    /// sitting right below it.
    pub async fn uptime_history(
        &self,
        service: &str,
        days: i64,
    ) -> Result<Vec<(String, Option<hlb_api::ServiceState>)>> {
        let rows = sqlx::query(
            "SELECT strftime('%Y-%m-%d', at) AS day, state FROM service_uptime_samples
             WHERE service = ?1 AND at >= datetime('now', ?2)",
        )
        .bind(service)
        .bind(format!("-{days} days"))
        .fetch_all(&self.pool)
        .await?;

        let mut worst: std::collections::HashMap<String, hlb_api::ServiceState> =
            std::collections::HashMap::new();
        for r in &rows {
            let day: String = r.try_get("day")?;
            let raw: String = r.try_get("state")?;
            let Some(state) = parse_service_state(&raw) else {
                continue;
            };
            worst
                .entry(day)
                .and_modify(|w| {
                    if severity(state) > severity(*w) {
                        *w = state;
                    }
                })
                .or_insert(state);
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let mut out = Vec::with_capacity(days as usize);
        for offset in (0..days).rev() {
            let day = civil_date(now - offset * 86_400);
            let state = worst.get(&day).copied();
            out.push((day, state));
        }
        Ok(out)
    }

    /// Prunes uptime samples older than `days` days — the retention loop's own tick,
    /// mirroring `AliasPurgeLoop`'s shape: a scheduled `DELETE ... WHERE <ts> < ?`.
    pub async fn prune_uptime_samples(&self, days: i64) -> Result<u64> {
        let r = sqlx::query("DELETE FROM service_uptime_samples WHERE at < datetime('now', ?1)")
            .bind(format!("-{days} days"))
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    /// Records the plan without overwriting progress already made.
    ///
    /// This is the heart of resumability: rerunning `apply` after a failure does not put
    /// already-finished actions back to `pending`.
    ///
    /// 🔴 Progress follows the ACTION, not its position. A row was matched by `seq`
    /// alone: a plan gaining one action in the middle — a catalog change, a capability
    /// added — put the new action on a done row and skipped it, and every action after
    /// it inherited its neighbour's status. A row carries over to the action it
    /// recorded (same kind, same description), wherever that action now sits.
    pub async fn record_plan(&self, app: &str, actions: &[(String, String)]) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        let rows = sqlx::query(
            "SELECT seq, kind, description, status, error, updated_at
             FROM plan_actions WHERE app = ?1 ORDER BY seq",
        )
        .bind(app)
        .fetch_all(&mut *tx)
        .await?;
        let mut recorded = Vec::with_capacity(rows.len());
        let mut stamps = Vec::with_capacity(rows.len());
        for r in &rows {
            let status: String = r.try_get("status")?;
            recorded.push(ActionRecord {
                seq: r.try_get("seq")?,
                kind: r.try_get("kind")?,
                description: r.try_get("description")?,
                status: ActionStatus::parse(&status),
                error: r.try_get("error")?,
            });
            stamps.push(r.try_get::<String, _>("updated_at")?);
        }
        let carried = carry_progress(&recorded, actions);

        sqlx::query("DELETE FROM plan_actions WHERE app = ?1")
            .bind(app)
            .execute(&mut *tx)
            .await?;
        for (seq, ((kind, description), from)) in actions.iter().zip(&carried).enumerate() {
            let (status, error, stamp) = match from {
                Some(i) => (
                    recorded[*i].status.as_str(),
                    recorded[*i].error.clone(),
                    Some(stamps[*i].clone()),
                ),
                None => (ActionStatus::Pending.as_str(), None, None),
            };
            sqlx::query(
                "INSERT INTO plan_actions (app, seq, kind, description, status, error, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, COALESCE(?7, datetime('now')))",
            )
            .bind(app)
            .bind(seq as i64)
            .bind(kind)
            .bind(description)
            .bind(status)
            .bind(error)
            .bind(stamp)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// For each action of `actions`, whether the journal holds it as done — the same
    /// matching [`Self::record_plan`] carries progress by, read without writing: a
    /// preview says what would be skipped, and records nothing.
    pub async fn completed_actions(
        &self,
        app: &str,
        actions: &[(String, String)],
    ) -> Result<Vec<bool>> {
        let recorded = self.plan_actions(app).await?;
        Ok(carry_progress(&recorded, actions)
            .into_iter()
            .map(|from| from.is_some_and(|i| recorded[i].status == ActionStatus::Done))
            .collect())
    }

    pub async fn set_action_status(
        &self,
        app: &str,
        seq: usize,
        status: ActionStatus,
        error: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE plan_actions
             SET status = ?3, error = ?4, updated_at = datetime('now')
             WHERE app = ?1 AND seq = ?2",
        )
        .bind(app)
        .bind(seq as i64)
        .bind(status.as_str())
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn plan_actions(&self, app: &str) -> Result<Vec<ActionRecord>> {
        let rows = sqlx::query(
            "SELECT seq, kind, description, status, error
             FROM plan_actions WHERE app = ?1 ORDER BY seq",
        )
        .bind(app)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                let status: String = r.try_get("status")?;
                Ok(ActionRecord {
                    seq: r.try_get("seq")?,
                    kind: r.try_get("kind")?,
                    description: r.try_get("description")?,
                    status: ActionStatus::parse(&status),
                    error: r.try_get("error")?,
                })
            })
            .collect()
    }

    /// The actions already finished, not to be replayed.
    /// Forgets an app's plan progress, so that its next plan runs whole.
    ///
    /// For applying a catalog change: the actions are idempotent — an existing database,
    /// secret or volume is kept — but a deployment marked done would be skipped, and
    /// the running service would never see the change.
    pub async fn reset_plan(&self, app: &str) -> Result<()> {
        sqlx::query("DELETE FROM plan_actions WHERE app = ?1")
            .bind(app)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Did the app's recorded plan run to its end — every action done, and at least one?
    /// Unimplemented is not done, and an empty journal is a plan that never started.
    pub async fn plan_finished(&self, app: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT count(*) AS n, count(*) FILTER (WHERE status != 'done') AS open
             FROM plan_actions WHERE app = ?1",
        )
        .bind(app)
        .fetch_one(&self.pool)
        .await?;
        let (n, open): (i64, i64) = (row.try_get("n")?, row.try_get("open")?);
        Ok(n > 0 && open == 0)
    }

    pub async fn completed_seqs(&self, app: &str) -> Result<Vec<i64>> {
        let rows = sqlx::query(
            "SELECT seq FROM plan_actions WHERE app = ?1 AND status = 'done' ORDER BY seq",
        )
        .bind(app)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok(r.try_get("seq")?)).collect()
    }

    /// Stores an already-encrypted secret. **Never regenerates an existing secret**: a
    /// password already injected into a service must not change under its feet.
    ///
    /// Returns `true` when the secret was created, `false` when it already existed.
    pub async fn store_secret_if_absent(
        &self,
        name: &str,
        ciphertext: &[u8],
        purpose: &str,
    ) -> Result<bool> {
        let res = sqlx::query(
            "INSERT INTO secrets (name, ciphertext, purpose) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO NOTHING",
        )
        .bind(name)
        .bind(ciphertext)
        .bind(purpose)
        .execute(&self.pool)
        .await?;

        Ok(res.rows_affected() > 0)
    }

    /// Replaces an existing secret (rotation).
    pub async fn rotate_secret(&self, name: &str, ciphertext: &[u8]) -> Result<()> {
        sqlx::query(
            "UPDATE secrets SET ciphertext = ?2, rotated_at = datetime('now')
             WHERE name = ?1",
        )
        .bind(name)
        .bind(ciphertext)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Removes a secret that has stopped being one: a rotation's next key, once it is
    /// the current one. Nothing that is still read may be forgotten.
    pub async fn forget_secret(&self, name: &str) -> Result<()> {
        sqlx::query("DELETE FROM secrets WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Every secret, name and ciphertext, for a rekey.
    ///
    /// ⚠️ The only method that hands out ciphertexts in bulk. It exists for one caller,
    /// `hlb secrets-rekey`, and the values still never leave encrypted.
    pub async fn all_ciphertexts(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let rows = sqlx::query("SELECT name, ciphertext FROM secrets ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("name")?, r.try_get("ciphertext")?)))
            .collect()
    }

    /// Rewrites every secret's ciphertext in ONE transaction.
    ///
    /// 🔴 Atomic on purpose. Half a vault re-encrypted with a new key and half with the
    /// old is unrecoverable by hand: you cannot tell, looking at a ciphertext, which key
    /// opens it. Either the whole rekey lands or none of it does.
    ///
    /// ⚠️ `rotated_at` is NOT touched: re-encrypting is not rotating. The secret's value
    /// is unchanged, so the age that says "this password has not been changed in a year"
    /// must keep counting from the real rotation.
    ///
    /// 🔴 Each entry is `(name, ciphertext read, ciphertext to write)`, and the vault
    /// must still be exactly what was read: a secret the controller stored or rotated
    /// meanwhile would stay under the old key — unreadable once the key is swapped —
    /// or be put back to its old value. Checked under the write lock, so nothing lands
    /// between the check and the rewrite.
    pub async fn rewrite_ciphertexts(&self, entries: &[(String, Vec<u8>, Vec<u8>)]) -> Result<()> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let now: Vec<(String, Vec<u8>)> =
            sqlx::query("SELECT name, ciphertext FROM secrets ORDER BY name")
                .fetch_all(&mut *tx)
                .await?
                .iter()
                .map(|r| Ok((r.try_get("name")?, r.try_get("ciphertext")?)))
                .collect::<Result<_>>()?;
        let read: std::collections::BTreeMap<&str, &[u8]> = entries
            .iter()
            .map(|(n, old, _)| (n.as_str(), old.as_slice()))
            .collect();
        let changed: Vec<&str> = now
            .iter()
            .filter(|(n, ct)| read.get(n.as_str()) != Some(&ct.as_slice()))
            .map(|(n, _)| n.as_str())
            .chain(
                read.keys()
                    .copied()
                    .filter(|n| !now.iter().any(|(m, _)| m == n)),
            )
            .collect();
        if !changed.is_empty() {
            return Err(Error::VaultChanged(changed.join(", ")));
        }
        for (name, _, ciphertext) in entries {
            sqlx::query("UPDATE secrets SET ciphertext = ?2 WHERE name = ?1")
                .bind(name)
                .bind(ciphertext)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn secret(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query("SELECT ciphertext FROM secrets WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => Ok(Some(r.try_get("ciphertext")?)),
            None => Ok(None),
        }
    }

    /// The secrets inventory: names and purposes, **never the values**.
    pub async fn secret_names(&self) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query("SELECT name, purpose FROM secrets ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| Ok((r.try_get("name")?, r.try_get("purpose")?)))
            .collect()
    }

    /// Saves a plan under a name.
    ///
    /// ⚠️ Overwrites a plan of the same name: the last one prepared is what counts.
    /// Refusing would force people to invent ever-longer names, and you would end up
    /// with "migration-2", "migration-2-again" with no idea which is right.
    #[allow(clippy::too_many_arguments)]
    pub async fn save_named_plan(
        &self,
        name: &str,
        method: &str,
        path: &str,
        body: &str,
        summary: &str,
        par: &str,
        note: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO named_plans (name, method, path, body, summary, created_by, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(name) DO UPDATE SET
                 method = excluded.method, path = excluded.path,
                 body = excluded.body, summary = excluded.summary,
                 created_by = excluded.created_by, created_at = datetime('now'),
                 note = excluded.note",
        )
        .bind(name)
        .bind(method)
        .bind(path)
        .bind(body)
        .bind(summary)
        .bind(par)
        .bind(note)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The saved plans: `(name, method, path, body, summary, by, age)`.
    pub async fn named_plans(
        &self,
    ) -> Result<Vec<(String, String, String, String, String, String, i64)>> {
        let rows = sqlx::query(
            "SELECT name, method, path, body, summary, created_by,
                    CAST(strftime('%s','now') AS INTEGER)
                      - CAST(strftime('%s', created_at) AS INTEGER) AS age
             FROM named_plans ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("name")?,
                    r.try_get("method")?,
                    r.try_get("path")?,
                    r.try_get("body")?,
                    r.try_get("summary")?,
                    r.try_get("created_by")?,
                    r.try_get::<Option<i64>, _>("age")?.unwrap_or(0),
                ))
            })
            .collect()
    }

    /// Oublie un plan.
    pub async fn forget_plan(&self, name: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM named_plans WHERE name = ?1")
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Attests to a break-glass access safeguard.
    ///
    /// ⚠️ Overwrites the previous attestation: the LAST check is what counts, not the
    /// first. Keeping the history would show "checked two years ago" next to a check
    /// from yesterday.
    pub async fn attest_breakglass(&self, id: &str, par: &str, note: Option<&str>) -> Result<()> {
        sqlx::query(
            "INSERT INTO breakglass (id, attested_by, note) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET
                 attested_at = datetime('now'),
                 attested_by = excluded.attested_by,
                 note = excluded.note",
        )
        .bind(id)
        .bind(par)
        .bind(note)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Withdraws an attestation: what it said is known not to hold any more.
    pub async fn forget_breakglass(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM breakglass WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The note an attestation was recorded with.
    pub async fn breakglass_note(&self, id: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT note FROM breakglass WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|r| r.try_get::<Option<String>, _>("note").ok().flatten()))
    }

    /// The attestations: `(id, age in seconds, who)`.
    pub async fn breakglass(&self) -> Result<Vec<(String, i64, String)>> {
        let rows = sqlx::query(
            "SELECT id, attested_by,
                    CAST(strftime('%s','now') AS INTEGER)
                      - CAST(strftime('%s', attested_at) AS INTEGER) AS age
             FROM breakglass",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("id")?,
                    r.try_get::<Option<i64>, _>("age")?.unwrap_or(0),
                    r.try_get("attested_by")?,
                ))
            })
            .collect()
    }

    /// The secrets with their age, for the rotation assistant.
    ///
    /// ⚠️ The age is that of the last ROTATION, or of creation when the secret was never
    /// rotated. Returning the creation age in both cases would make a secret rotated
    /// yesterday look three years old.
    ///
    /// 🔴 No value leaves here, encrypted or not: what this method cannot represent
    /// cannot leak.
    pub async fn secrets_ages(&self) -> Result<Vec<(String, String, i64, bool)>> {
        let rows = sqlx::query(
            "SELECT name, purpose,
                    CAST(strftime('%s','now') AS INTEGER)
                      - CAST(strftime('%s', COALESCE(rotated_at, created_at)) AS INTEGER)
                      AS age,
                    rotated_at IS NULL AS never_rotated
             FROM secrets ORDER BY age DESC, name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get("name")?,
                    r.try_get("purpose")?,
                    r.try_get::<Option<i64>, _>("age")?.unwrap_or(0),
                    r.try_get::<i64, _>("never_rotated")? != 0,
                ))
            })
            .collect()
    }

    /// Records a manual step, or brings one already recorded to what the guide says now.
    ///
    /// 🔴 `blocking` follows the guide: kept as first recorded, a step made blocking
    /// since left an `after-guide` route open before anyone had done it.
    pub async fn add_guide(&self, app: &str, id: &str, title: &str, blocking: bool) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO pending_guides (id, app, title, blocking)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(app, id) DO UPDATE SET
                 title = excluded.title,
                 blocking = excluded.blocking",
        )
        .bind(id)
        .bind(app)
        .bind(title)
        .bind(blocking as i64)
        .execute(&mut *tx)
        .await?;
        // Attested before the install: handled from its first row, as the person said.
        sqlx::query(
            "UPDATE pending_guides SET verified_at = datetime('now'), forced = a.forced
             FROM attested_ahead a
             WHERE a.app = pending_guides.app AND a.id = pending_guides.id
               AND pending_guides.app = ?1 AND pending_guides.id = ?2",
        )
        .bind(app)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM attested_ahead WHERE app = ?1 AND id = ?2")
            .bind(app)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Marks a manual step handled before its app is installed: `hlb ack` ahead of the first
    /// `--apply`, which then does not stop for it. `forced`: against its own check.
    pub async fn attest_ahead(&self, app: &str, id: &str, forced: bool) -> Result<()> {
        sqlx::query(
            "INSERT INTO attested_ahead (app, id, forced) VALUES (?1, ?2, ?3)
             ON CONFLICT(app, id) DO UPDATE SET forced = excluded.forced",
        )
        .bind(app)
        .bind(id)
        .bind(forced as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Marks a manual action as handled.
    ///
    /// ⚠️ This function checks NOTHING by itself: it records an observation made
    /// elsewhere.
    ///
    /// Two callers, with opposite guarantees:
    ///
    /// - `hlb todo --verify` first ran the manifest's `verify:` block
    ///   (`hlb_guide::Verifier`: dns, http, tcp...). The step is **established**.
    /// - `hlb ack` ran nothing. It is an **attestation**: the system takes the user at
    ///   their word, and the CLI says so on every use.
    ///
    /// Confusing the two would mean believing an app protected because someone claimed
    /// to have configured it.
    pub async fn verify_guide(&self, app: &str, id: &str) -> Result<bool> {
        self.handle_guide(app, id, false).await
    }

    /// Marks a manual action as handled AGAINST its own check (`hlb ack <app>/<id> --force`): the
    /// nightly re-check then leaves it as the person said, until the check agrees.
    pub async fn force_guide(&self, app: &str, id: &str) -> Result<bool> {
        self.handle_guide(app, id, true).await
    }

    async fn handle_guide(&self, app: &str, id: &str, forced: bool) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE pending_guides SET verified_at = datetime('now'), forced = ?3
             WHERE app = ?1 AND id = ?2 AND verified_at IS NULL",
        )
        .bind(app)
        .bind(id)
        .bind(forced as i64)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// The handled steps of an app: how long ago each was handled, in seconds, and
    /// whether it was forced against its check.
    pub async fn verified_guide_ages(&self, app: &str) -> Result<Vec<(String, i64, bool)>> {
        sqlx::query(
            "SELECT id, forced, CAST(strftime('%s','now') AS INTEGER)
                        - CAST(strftime('%s', verified_at) AS INTEGER) AS age
             FROM pending_guides WHERE app = ?1 AND verified_at IS NOT NULL ORDER BY id",
        )
        .bind(app)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(|r| {
            Ok((
                r.try_get("id")?,
                r.try_get("age")?,
                r.try_get::<i64, _>("forced")? != 0,
            ))
        })
        .collect()
    }

    /// A handled step a re-check found still true: its age counts from now, and one
    /// forced is established from here on.
    pub async fn reconfirm_guide(&self, app: &str, id: &str) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE pending_guides SET verified_at = datetime('now'), forced = 0
             WHERE app = ?1 AND id = ?2 AND verified_at IS NOT NULL",
        )
        .bind(app)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// A handled step a re-check found no longer true: pending again, in the inbox and
    /// before the next install or upgrade of the app.
    pub async fn reopen_guide(&self, app: &str, id: &str) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE pending_guides SET verified_at = NULL, forced = 0
             WHERE app = ?1 AND id = ?2 AND verified_at IS NOT NULL",
        )
        .bind(app)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// The ids of the manual actions still unhandled for an app, blocking or not.
    pub async fn unverified_guides(&self, app: &str) -> Result<Vec<String>> {
        sqlx::query("SELECT id FROM pending_guides WHERE app = ?1 AND verified_at IS NULL")
            .bind(app)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(|r| Ok(r.try_get("id")?))
            .collect()
    }

    /// The ids of the manual actions handled for an app — verified or attested.
    pub async fn verified_guides(&self, app: &str) -> Result<Vec<String>> {
        sqlx::query(
            "SELECT id FROM pending_guides WHERE app = ?1 AND verified_at IS NOT NULL
             UNION SELECT id FROM attested_ahead WHERE app = ?1",
        )
        .bind(app)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(|r| Ok(r.try_get("id")?))
        .collect()
    }

    /// The blocking actions still unhandled for a given app.
    pub async fn unverified_blocking(&self, app: &str) -> Result<usize> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS n FROM pending_guides
             WHERE app = ?1 AND blocking = 1 AND verified_at IS NULL",
        )
        .bind(app)
        .fetch_one(&self.pool)
        .await?;
        let n: i64 = row.try_get("n")?;
        Ok(n as usize)
    }

    /// The pending queue: what is left to do by hand, unverified.
    pub async fn pending_guides(&self) -> Result<Vec<(String, String, String, bool)>> {
        let rows = sqlx::query(
            "SELECT app, id, title, blocking FROM pending_guides
             WHERE verified_at IS NULL ORDER BY blocking DESC, app, id",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                let blocking: i64 = r.try_get("blocking")?;
                Ok((
                    r.try_get("app")?,
                    r.try_get("id")?,
                    r.try_get("title")?,
                    blocking != 0,
                ))
            })
            .collect()
    }
}

/// The stable identifier stored per sample — deliberately NOT `ServiceState::label()`,
/// which is a display phrase ("planned maintenance") free to be reworded. Matches the
/// same kebab-case words the wire form (`#[serde(rename_all = "kebab-case")]`) already
/// uses, so nothing new is invented.
fn service_state_str(s: hlb_api::ServiceState) -> &'static str {
    match s {
        hlb_api::ServiceState::Operational => "operational",
        hlb_api::ServiceState::Degraded => "degraded",
        hlb_api::ServiceState::Unavailable => "unavailable",
        hlb_api::ServiceState::Maintenance => "maintenance",
    }
}

fn parse_service_state(s: &str) -> Option<hlb_api::ServiceState> {
    match s {
        "operational" => Some(hlb_api::ServiceState::Operational),
        "degraded" => Some(hlb_api::ServiceState::Degraded),
        "unavailable" => Some(hlb_api::ServiceState::Unavailable),
        "maintenance" => Some(hlb_api::ServiceState::Maintenance),
        _ => None,
    }
}

/// The ordering `uptime_history` picks the WORST sample of a day by — an announced
/// maintenance is disruptive on purpose, but a real outage is worse than a planned one.
fn severity(s: hlb_api::ServiceState) -> u8 {
    match s {
        hlb_api::ServiceState::Operational => 0,
        hlb_api::ServiceState::Maintenance => 1,
        hlb_api::ServiceState::Degraded => 2,
        hlb_api::ServiceState::Unavailable => 3,
    }
}

/// The civil (`Y-M-D`) date for an epoch — no date dependency needed. The Howard
/// Hinnant civil-from-days algorithm, mirroring `hlb-controller::runbook`'s
/// `readable_timestamp` with the time-of-day dropped: `uptime_history` only ever
/// buckets by day.
fn civil_date(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let z = days + 719_468;
    let ere = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - ere * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + ere * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// How many characters of a fingerprint name a session.
pub const SESSION_REFERENCE_LEN: usize = 8;

fn update_decision_of(r: &sqlx::sqlite::SqliteRow) -> Result<UpdateDecision> {
    Ok(UpdateDecision {
        app: r.try_get("app")?,
        digest: r.try_get("digest")?,
        from_tag: r.try_get("from_tag")?,
        kind: r.try_get("kind")?,
        to_tag: r.try_get("to_tag")?,
        who: r.try_get("who")?,
        why: r.try_get("why")?,
        notes: r.try_get("notes")?,
        decided_at: r.try_get("decided_at")?,
        refused: r.try_get("refused")?,
        refused_at: r.try_get("refused_at")?,
        approved_by: r.try_get("approved_by")?,
        approved_at: r.try_get("approved_at")?,
    })
}

fn session_reference(fingerprint: &str) -> String {
    fingerprint.chars().take(SESSION_REFERENCE_LEN).collect()
}

/// The reference of the session this cookie value opens — how a request tells its own
/// session apart in [`State::sessions_of`] without the value ever being stored.
pub fn session_reference_of(presented: &str) -> String {
    session_reference(&hlb_types::token::fingerprint_of(presented))
}

/// A browser session, as presented to its owner.
///
/// 🔴 No field carries the cookie's value: you cannot leak what you cannot represent.
/// The same structural guarantee as `SecretItem` and `StoredToken`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// The first characters of the fingerprint, to name a session without naming it by
    /// a secret. Enough to tell your own apart.
    pub reference: String,
    pub user: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_seen: i64,
    pub user_agent: Option<String>,
}

impl State {
    /// Rebuilds a person's complete account: role, identity, mailboxes, aliases.
    ///
    /// 🔴 It lives here rather than in the CLI, where it used to, because **two
    /// divergent reconstructions of the same account is exactly what makes a quota
    /// apply on the command line and not in the API**. That was the case:
    /// `POST /api/v1/aliases` ignored quota profiles although a comment claimed otherwise.
    ///
    /// `hlb-users` cannot host it: that crate never touches the database, and that is
    /// what makes it testable without a server.
    pub async fn account(&self, name: &str) -> Result<hlb_users::Account> {
        let registered = sqlx::query("SELECT role, pocket_id FROM users WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        let (role, pocket_id) = match registered {
            Some(r) => (r.try_get("role")?, r.try_get("pocket_id")?),
            None => (None, None),
        };
        Ok(assemble(
            name,
            role,
            pocket_id,
            self.mailboxes(name).await?,
            &self.aliases(name).await?,
        ))
    }

    /// Every registered account, read in three queries whatever their number.
    ///
    /// 🔴 [`Self::account`] once per person read the whole user table each time to find
    /// one row: a thousand accounts cost a million rows and 1.2 s, on a list every open
    /// page polls. Assembled by the same function, so the two cannot disagree.
    pub async fn accounts(&self) -> Result<Vec<hlb_users::Account>> {
        let mut mailboxes: std::collections::BTreeMap<String, Vec<(String, String, bool)>> =
            std::collections::BTreeMap::new();
        for r in sqlx::query(
            "SELECT user, local, domain, is_default FROM user_mailboxes
             ORDER BY user, is_default DESC, local",
        )
        .fetch_all(&self.pool)
        .await?
        {
            mailboxes.entry(r.try_get("user")?).or_default().push((
                r.try_get("local")?,
                r.try_get("domain")?,
                r.try_get::<i64, _>("is_default")? != 0,
            ));
        }
        let mut aliases: std::collections::BTreeMap<String, Vec<AliasRow>> =
            std::collections::BTreeMap::new();
        for r in sqlx::query(
            "SELECT user, mailbox, local, expires_at, active, hint, note
             FROM user_aliases ORDER BY user, mailbox, local",
        )
        .fetch_all(&self.pool)
        .await?
        {
            aliases.entry(r.try_get("user")?).or_default().push((
                r.try_get("mailbox")?,
                r.try_get("local")?,
                r.try_get("expires_at")?,
                r.try_get::<i64, _>("active")? != 0,
                r.try_get("hint")?,
                r.try_get("note")?,
            ));
        }
        Ok(self
            .users()
            .await?
            .into_iter()
            .map(|(name, role, pocket_id)| {
                let boxes = mailboxes.remove(&name).unwrap_or_default();
                let own = aliases.remove(&name).unwrap_or_default();
                assemble(&name, role, pocket_id, boxes, &own)
            })
            .collect())
    }

    // ---------------------------------------------------------------------------
    // Sessions — people signing in, as opposed to machine tokens
    // ---------------------------------------------------------------------------

    /// Opens a session for someone already authenticated by PocketID.
    ///
    /// `presented` is the cookie's value; **only its fingerprint is kept**.
    pub async fn open_session(
        &self,
        presented: &str,
        user: &str,
        subject: Option<&str>,
        now: i64,
        duration_s: i64,
        user_agent: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO sessions
               (fingerprint, user, subject, created_at, expires_at, last_seen, user_agent)
             VALUES (?1, ?2, ?3, ?4, ?5, ?4, ?6)",
        )
        .bind(hlb_types::token::fingerprint_of(presented))
        .bind(user)
        .bind(subject)
        .bind(now)
        .bind(now.saturating_add(duration_s))
        .bind(user_agent)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Whose cookie is this, if it is still valid?
    ///
    /// 🔴 Expiry is filtered **in SQL**, not in the caller: an expired session must not
    /// be authenticatable by a caller who forgets the comparison. The lookup is by
    /// fingerprint, on the primary key - the response time does not depend on the number
    /// of sessions.
    ///
    /// Returns `(user, subject)`. The **role is deliberately not returned here**: it is
    /// re-read separately by [`Self::user_role`], so a revocation takes effect on the
    /// next request and not when the cookie expires.
    pub async fn find_session(
        &self,
        presented: &str,
        now: i64,
    ) -> Result<Option<(String, Option<String>)>> {
        let row = sqlx::query(
            "SELECT user, subject FROM sessions WHERE fingerprint = ?1 AND expires_at > ?2",
        )
        .bind(hlb_types::token::fingerprint_of(presented))
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            None => Ok(None),
            Some(r) => Ok(Some((r.try_get("user")?, r.try_get("subject")?))),
        }
    }

    /// Extends a live session (sliding expiry) and notes its last use.
    ///
    /// Split from [`Self::find_session`] for the same reason `touch_token` is split from
    /// `find_token`: noting a use must neither slow down nor fail a request.
    pub async fn touch_session(&self, presented: &str, now: i64, duration_s: i64) -> Result<()> {
        sqlx::query(
            "UPDATE sessions SET last_seen = ?2, expires_at = ?3
             WHERE fingerprint = ?1 AND expires_at > ?2",
        )
        .bind(hlb_types::token::fingerprint_of(presented))
        .bind(now)
        .bind(now.saturating_add(duration_s))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Closes one specific session (signing out).
    pub async fn close_session(&self, presented: &str) -> Result<bool> {
        let r = sqlx::query("DELETE FROM sessions WHERE fingerprint = ?1")
            .bind(hlb_types::token::fingerprint_of(presented))
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Closes a session named by its short reference ("sign out this device").
    ///
    /// 🔴 The reference matches as a PREFIX of the fingerprint, so a shorter one names
    /// more sessions — and an empty one names them all. Anything but a whole reference
    /// closes nothing.
    pub async fn close_session_by_reference(&self, user: &str, reference: &str) -> Result<bool> {
        if reference.chars().count() != SESSION_REFERENCE_LEN {
            return Ok(false);
        }
        let r =
            sqlx::query("DELETE FROM sessions WHERE user = ?1 AND substr(fingerprint, 1, ?3) = ?2")
                .bind(user)
                .bind(reference)
                .bind(reference.len() as i64)
                .execute(&self.pool)
                .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Closes ALL of a person's sessions.
    ///
    /// This is what you do when you suspect a compromise, and it must be reachable in
    /// one command.
    pub async fn close_all_sessions(&self, user: &str) -> Result<u64> {
        let r = sqlx::query("DELETE FROM sessions WHERE user = ?1")
            .bind(user)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    /// A person's live sessions, most recently seen first.
    pub async fn sessions_of(&self, user: &str, now: i64) -> Result<Vec<SessionInfo>> {
        let rows = sqlx::query(
            "SELECT fingerprint, user, created_at, expires_at, last_seen, user_agent
             FROM sessions WHERE user = ?1 AND expires_at > ?2
             ORDER BY last_seen DESC",
        )
        .bind(user)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                let f: String = r.try_get("fingerprint")?;
                Ok(SessionInfo {
                    reference: session_reference(&f),
                    user: r.try_get("user")?,
                    created_at: r.try_get("created_at")?,
                    expires_at: r.try_get("expires_at")?,
                    last_seen: r.try_get("last_seen")?,
                    user_agent: r.try_get("user_agent")?,
                })
            })
            .collect()
    }

    /// Every live session, across all accounts (the security screen).
    pub async fn all_sessions(&self, now: i64) -> Result<Vec<SessionInfo>> {
        let rows = sqlx::query(
            "SELECT fingerprint, user, created_at, expires_at, last_seen, user_agent
             FROM sessions WHERE expires_at > ?1 ORDER BY last_seen DESC",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                let f: String = r.try_get("fingerprint")?;
                Ok(SessionInfo {
                    reference: session_reference(&f),
                    user: r.try_get("user")?,
                    created_at: r.try_get("created_at")?,
                    expires_at: r.try_get("expires_at")?,
                    last_seen: r.try_get("last_seen")?,
                    user_agent: r.try_get("user_agent")?,
                })
            })
            .collect()
    }

    /// Deletes expired sessions.
    ///
    /// They no longer authenticate (the filter is in SQL), but keeping them forever
    /// would turn the table into a sign-in history nobody asked for - and that would go
    /// into the backups.
    pub async fn purge_expired_sessions(&self, now: i64) -> Result<u64> {
        let r = sqlx::query("DELETE FROM sessions WHERE expires_at <= ?1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    /// The Homelabus account bound to this PocketID identity.
    ///
    /// 🔴 Binding is by `sub`, not by username: `sub` is stable whereas a name can be
    /// renamed. Binding by name would lose the link on the first rename, silently - the
    /// person would sign in again and be refused with nothing explaining why.
    pub async fn user_by_pocket_id(&self, sub: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT name FROM users WHERE pocket_id = ?1")
            .bind(sub)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some(r.try_get("name")?)),
        }
    }

    /// Records the PocketID identity ↔ account link, on first sign-in. `false` when the
    /// account is bound to another identity already, and then nothing changed.
    ///
    /// 🔴 Only an unbound account is bound: an account is never moved from one `sub`
    /// to another by a name an identity provider lets people choose. Idempotent, and
    /// touches nothing else: the role and the mailboxes are none of sign-in's business.
    pub async fn upsert_user_pocket_id(&self, user: &str, sub: &str) -> Result<bool> {
        let r = sqlx::query(
            "UPDATE users SET pocket_id = ?2
             WHERE name = ?1 AND (pocket_id IS NULL OR pocket_id = ?2)",
        )
        .bind(user)
        .bind(sub)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    // ---------------------------------------------------------------------------
    // Announcements (lot 7.2)
    // ---------------------------------------------------------------------------

    /// Publishes an announcement.
    ///
    /// ⚠️ Eight parameters, and that is accepted: grouping them into a struct would
    /// force every caller to build it, for a single function. They are of distinct
    /// types, so swapping two does not compile.
    #[allow(clippy::too_many_arguments)]
    pub async fn publish_announcement(
        &self,
        title: &str,
        body: &str,
        level: hlb_api::AnnouncementLevel,
        pinned: bool,
        audience: Option<hlb_types::Role>,
        author: &str,
        expires_at: Option<i64>,
    ) -> Result<i64> {
        let r = sqlx::query(
            "INSERT INTO announcements (title, body, level, pinned, audience, author, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(title)
        .bind(body)
        .bind(level.as_str())
        .bind(i64::from(pinned))
        .bind(audience.map(|r| r.as_str()))
        .bind(author)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(r.last_insert_rowid())
    }

    /// Adds an update to an announcement's thread.
    ///
    /// 🔴 An update is APPENDED, it does not replace: the chronology is what gets
    /// re-read after an incident - what time it was known, understood, fixed. Rewriting
    /// the original body would erase it.
    pub async fn follow_announcement(
        &self,
        announcement: i64,
        body: &str,
        author: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO announcement_updates (announcement, body, author) VALUES (?1, ?2, ?3)",
        )
        .bind(announcement)
        .bind(body)
        .bind(author)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The lower-cased titles of the maintenances announced now: an app whose name a
    /// title contains is in maintenance, for the status page and the uptime samples
    /// alike. Unreadable is none — the app then shows its own status.
    pub async fn maintenance_titles(&self, now: i64) -> Vec<String> {
        self.announcements(hlb_types::Role::User, now, false)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|a| a.level == hlb_api::AnnouncementLevel::Maintenance)
            .map(|a| a.title.to_lowercase())
            .collect()
    }

    /// The announcements visible to this role.
    ///
    /// ⚠️ Filtered by audience: an operations announcement does not interest a portal
    /// user, and flooding them with messages that do not concern them makes them stop
    /// reading - at the precise moment one of them will matter.
    pub async fn announcements(
        &self,
        role: hlb_types::Role,
        now: i64,
        include_expired: bool,
    ) -> Result<Vec<hlb_api::Announcement>> {
        let rows = sqlx::query(
            "SELECT id, title, body, level, pinned, audience, author, published_at, expires_at
             FROM announcements
             WHERE (?2 = 1 OR expires_at IS NULL OR expires_at > ?1)
             ORDER BY pinned DESC, id DESC LIMIT 50",
        )
        .bind(now)
        .bind(i64::from(include_expired))
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::new();
        for r in &rows {
            // The audience: `None` means everyone. An unreadable role in the database
            // makes the announcement visible to all rather than to none - an
            // announcement nobody sees is useless, and the content is public anyway.
            let required = r
                .try_get::<Option<String>, _>("audience")?
                .and_then(|a| hlb_types::Role::parse(&a));
            if required.is_some_and(|req| role < req) {
                continue;
            }

            let id: i64 = r.try_get("id")?;
            out.push(hlb_api::Announcement {
                id,
                title: r.try_get("title")?,
                body: r.try_get("body")?,
                level: hlb_api::AnnouncementLevel::parse(&r.try_get::<String, _>("level")?),
                pinned: r.try_get::<i64, _>("pinned")? != 0,
                author: r.try_get("author")?,
                published_at: r.try_get("published_at")?,
                expires_in_s: r.try_get::<Option<i64>, _>("expires_at")?.map(|e| e - now),
                follow_ups: self.follow_ups_of(id).await?,
            });
        }
        Ok(out)
    }

    async fn follow_ups_of(&self, announcement: i64) -> Result<Vec<hlb_api::AnnouncementUpdate>> {
        let rows = sqlx::query(
            "SELECT body, author, at FROM announcement_updates WHERE announcement = ?1 ORDER BY id ASC",
        )
        .bind(announcement)
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok(hlb_api::AnnouncementUpdate {
                    body: r.try_get("body")?,
                    author: r.try_get("author")?,
                    at: r.try_get("at")?,
                })
            })
            .collect()
    }

    /// Removes an announcement.
    pub async fn remove_announcement(&self, id: i64) -> Result<bool> {
        let r = sqlx::query("DELETE FROM announcements WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    // ---------------------------------------------------------------------------
    // Invitations (lot 6.2)
    // ---------------------------------------------------------------------------

    /// Creates an invitation. **Only the fingerprint is kept.**
    ///
    /// `max_uses`: how many people may use it. **1 by default**, the safe case - an
    /// N-use link that leaks lets N people in.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_invitation(
        &self,
        presented: &str,
        created_by: &str,
        role: &str,
        now: i64,
        duration_s: i64,
        max_uses: i64,
        note: Option<&str>,
    ) -> Result<()> {
        // `domain` is a column nothing fills: an imposed mail domain was planned and
        // never read by the sign-up, so it is not carried — written NULL, it stays.
        sqlx::query(
            "INSERT INTO invitations
               (fingerprint, created_by, role, created_at, expires_at, max_uses, note)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(hlb_types::token::fingerprint_of(presented))
        .bind(created_by)
        .bind(role)
        .bind(now)
        .bind(now.saturating_add(duration_s))
        // ⚠️ Floored at 1: a `max_uses` of zero would create an invitation unusable
        // from the moment it exists, which looks like a failure.
        .bind(max_uses.max(1))
        .bind(note)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Consumes an invitation: marks it used and returns what it grants.
    ///
    /// 🔴 **Marked BEFORE any creation**, in the same query as the read: a consumed
    /// invitation must not be reusable, even if the creation then fails. The reverse
    /// would allow creating several accounts with a link believed single-use - and the
    /// second account would carry the same role.
    ///
    /// Returns the role's id, fixed when the link was made, or `None` when the invitation is unknown,
    /// expired or already used. The three cases are indistinguishable **by design**:
    /// separating them would tell whoever is trying tokens whether one of them
    /// existed.
    pub async fn consume_invitation(
        &self,
        presented: &str,
        account: &str,
        now: i64,
    ) -> Result<Option<String>> {
        let fingerprint = hlb_types::token::fingerprint_of(presented);
        let mut tx = self.pool.begin().await?;

        // 🔴 `uses < max_uses` **in the query**, not in the caller: two
        // simultaneous sign-ups would read the same counter and both get through. The
        // transaction makes the increment atomic.
        let row = sqlx::query(
            "SELECT role FROM invitations
             WHERE fingerprint = ?1 AND uses < max_uses AND expires_at > ?2",
        )
        .bind(&fingerprint)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(r) = row else {
            return Ok(None);
        };

        // The mark, in the SAME transaction: two simultaneous sign-ups with the same
        // link cannot both get through.
        sqlx::query(
            // `account` keeps the LAST person to sign up; the full trace lives in the
            // audit log, where every sign-up is recorded with its name.
            "UPDATE invitations
             SET uses = uses + 1, used_at = datetime('now'), account = ?2
             WHERE fingerprint = ?1",
        )
        .bind(&fingerprint)
        .bind(account)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(Some(r.try_get("role")?))
    }

    /// Would this invitation let someone in now? Read without consuming it: a preview
    /// says what is taken only to whoever holds a link that opens.
    pub async fn invitation_open(&self, presented: &str, now: i64) -> Result<bool> {
        let row = sqlx::query(
            "SELECT 1 FROM invitations
             WHERE fingerprint = ?1 AND uses < max_uses AND expires_at > ?2",
        )
        .bind(hlb_types::token::fingerprint_of(presented))
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    /// The invitations, newest first — all of them.
    ///
    /// ⚠️ Cut at 100 until 2026-10-07, with nothing to say so: the 101st, still open
    /// for five people, was on no screen. A household's invitations number in the
    /// hundreds over years, which a page holds.
    pub async fn invitations(&self, now: i64) -> Result<Vec<hlb_api::InvitationSummary>> {
        let rows = sqlx::query(
            "SELECT fingerprint, created_by, role, expires_at, used_at, note,
                    uses, max_uses
             FROM invitations ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                let f: String = r.try_get("fingerprint")?;
                Ok(hlb_api::InvitationSummary {
                    reference: session_reference(&f),
                    created_by: r.try_get("created_by")?,
                    role: r.try_get("role")?,
                    expires_in_s: r.try_get::<i64, _>("expires_at")? - now,
                    used_at: r.try_get("used_at")?,
                    uses: r.try_get::<i64, _>("uses")? as usize,
                    max_uses: r.try_get::<i64, _>("max_uses")? as usize,
                    note: r.try_get("note")?,
                })
            })
            .collect()
    }

    /// Revokes an invitation by its short reference.
    ///
    /// Anything but a whole reference revokes nothing, as for a session: the match is a
    /// prefix, and `a` named every invitation starting with it.
    pub async fn revoke_invitation(&self, reference: &str) -> Result<bool> {
        if reference.chars().count() != SESSION_REFERENCE_LEN {
            return Ok(false);
        }
        // ⚠️ Revoking EXHAUSTS rather than deletes: an invitation already used carries
        // the trace of who created it and who came in. Deleting it would lose that trace
        // at the precise moment it is needed - when a link has leaked.
        let r = sqlx::query(
            "UPDATE invitations SET uses = max_uses
             WHERE substr(fingerprint, 1, ?2) = ?1 AND uses < max_uses",
        )
        .bind(reference)
        .bind(reference.len() as i64)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    // ---------------------------------------------------------------------------
    // Appearance: brand and preferences
    // ---------------------------------------------------------------------------

    /// The installation's brand.
    ///
    /// ⚠️ Falls back to the default when the row is missing: a database restored from an
    /// earlier version must not leave the interface without a header.
    pub async fn brand(&self) -> Result<hlb_api::Brand> {
        let row = sqlx::query(
            "SELECT name, product, accent, footer, default_theme, logo IS NOT NULL AS a_logo
             FROM appearance WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(r) = row else {
            return Ok(hlb_api::Brand::default());
        };

        Ok(hlb_api::Brand {
            name: r.try_get("name")?,
            product: r.try_get("product")?,
            accent: r
                .try_get::<Option<String>, _>("accent")?
                .as_deref()
                .and_then(hex_rgb),
            logo: r.try_get::<i64, _>("a_logo")? != 0,
            footer: r.try_get("footer")?,
            default_theme: r.try_get("default_theme")?,
        })
    }

    /// Saves the brand. Does not touch the logo, which has its own operation.
    pub async fn set_brand(&self, m: &hlb_api::Brand) -> Result<()> {
        let accent = m.accent.map(|[r, v, b]| format!("{r:02X}{v:02X}{b:02X}"));
        sqlx::query(
            "INSERT INTO appearance (id, name, product, accent, footer, default_theme)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name, product = excluded.product,
               accent = excluded.accent, footer = excluded.footer,
               default_theme = excluded.default_theme,
               modified_at = datetime('now')",
        )
        .bind(&m.name)
        .bind(&m.product)
        .bind(accent)
        .bind(&m.footer)
        .bind(&m.default_theme)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The logo, if there is one.
    pub async fn logo(&self) -> Result<Option<Vec<u8>>> {
        let row = sqlx::query("SELECT logo FROM appearance WHERE id = 1")
            .fetch_optional(&self.pool)
            .await?;
        match row {
            None => Ok(None),
            Some(r) => Ok(r.try_get("logo")?),
        }
    }

    /// Sets or removes the logo. `logo` may be a PNG or an SVG (rasterized here) —
    /// see [`prepare_logo`].
    ///
    /// 🔴 Prepared HERE, not left to callers: `prepare_logo` is a public function
    /// precisely so a caller CAN convert/check before this point (the CLI shows the
    /// resulting size in its preview before `--apply`), but a forgotten call at one
    /// of the two entry points (the CLI, the upload route) must not be how an
    /// oversized, unconverted, or malformed logo reaches the database.
    pub async fn set_logo(&self, logo: Option<&[u8]>) -> Result<()> {
        let png = match logo {
            Some(bytes) => Some(prepare_logo(bytes)?),
            None => None,
        };
        sqlx::query("UPDATE appearance SET logo = ?1, modified_at = datetime('now') WHERE id = 1")
            .bind(png)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The theme a person chose. `None` means the installation's own.
    pub async fn theme_of(&self, user: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT theme FROM user_prefs WHERE user = ?1")
            .bind(user)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            None => Ok(None),
            Some(r) => Ok(r.try_get("theme")?),
        }
    }

    pub async fn set_theme_of(&self, user: &str, theme: Option<&str>) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_prefs (user, theme) VALUES (?1, ?2)
             ON CONFLICT(user) DO UPDATE SET theme = excluded.theme,
                                             modified_at = datetime('now')",
        )
        .bind(user)
        .bind(theme)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// How tightly a person's lists are set. A value no variant answers to any more is
    /// the default, not an error: it costs the person a setting, not their page.
    pub async fn density_of(&self, user: &str) -> Result<hlb_api::Density> {
        let row = sqlx::query("SELECT density FROM user_prefs WHERE user = ?1")
            .bind(user)
            .fetch_optional(&self.pool)
            .await?;
        let stored: Option<String> = row.map(|r| r.try_get("density")).transpose()?.flatten();
        Ok(stored
            .and_then(|d| serde_json::from_value(serde_json::Value::String(d)).ok())
            .unwrap_or_default())
    }

    /// Records measurements. A second one for the same metric, subject and minute
    /// replaces the first: the recorder may run twice in a minute after a restart.
    pub async fn record_history(&self, samples: &[Sample]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        for s in samples {
            sqlx::query(
                "INSERT OR REPLACE INTO history (metric, subject, at, value) VALUES (?1, ?2, ?3, ?4)",
            )
            .bind(&s.metric)
            .bind(&s.subject)
            .bind(s.at)
            .bind(s.value)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// The measurements of `metric` — or of every metric starting with it, for
    /// `disk:` — since `since`, oldest first.
    pub async fn history(&self, metric: &str, since: i64) -> Result<Vec<Sample>> {
        let rows = sqlx::query(
            "SELECT metric, subject, at, value FROM history
             WHERE (metric = ?1 OR (substr(?1, -1) = ':' AND substr(metric, 1, length(?1)) = ?1))
               AND at >= ?2
             ORDER BY metric, subject, at",
        )
        .bind(metric)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(Sample {
                    metric: r.try_get("metric")?,
                    subject: r.try_get("subject")?,
                    at: r.try_get("at")?,
                    value: r.try_get("value")?,
                })
            })
            .collect()
    }

    /// Forgets the measurements older than `before`.
    pub async fn prune_history(&self, before: i64) -> Result<u64> {
        let r = sqlx::query("DELETE FROM history WHERE at < ?1")
            .bind(before)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    pub async fn set_density_of(&self, user: &str, density: hlb_api::Density) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_prefs (user, density) VALUES (?1, ?2)
             ON CONFLICT(user) DO UPDATE SET density = excluded.density,
                                             modified_at = datetime('now')",
        )
        .bind(user)
        .bind(density.as_str())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The tiles a person laid out on the home. `None` = never arranged.
    ///
    /// ⚠️ A name no `HomeWidget` answers to any more is dropped, not an error: the card
    /// it named was removed from the interface, and failing here would cost the person
    /// every other card along with it. A bare name is a layout stored before tiles had
    /// a size (until 2026-10-10): it takes the size the card is added at.
    pub async fn home_of(&self, user: &str) -> Result<Option<Vec<hlb_api::HomeTile>>> {
        let row = sqlx::query("SELECT home FROM user_prefs WHERE user = ?1")
            .bind(user)
            .fetch_optional(&self.pool)
            .await?;
        let Some(text) = row
            .map(|r| r.try_get::<Option<String>, _>("home"))
            .transpose()?
            .flatten()
        else {
            return Ok(None);
        };
        let stored: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap_or_default();
        Ok(Some(
            stored
                .into_iter()
                .filter_map(|v| match v {
                    serde_json::Value::String(_) => {
                        serde_json::from_value::<hlb_api::HomeWidget>(v)
                            .ok()
                            .map(hlb_api::HomeWidget::tile)
                    }
                    // A size out of bounds is the one the card is added at, not a lost card.
                    _ => serde_json::from_value::<hlb_api::HomeTile>(v)
                        .ok()
                        .map(|t| if t.fits() { t } else { t.widget.tile() }),
                })
                .collect(),
        ))
    }

    pub async fn set_home_of(&self, user: &str, home: Option<&[hlb_api::HomeTile]>) -> Result<()> {
        let text = home.map(|h| serde_json::to_string(h).unwrap_or_else(|_| "[]".into()));
        sqlx::query(
            "INSERT INTO user_prefs (user, home) VALUES (?1, ?2)
             ON CONFLICT(user) DO UPDATE SET home = excluded.home,
                                             modified_at = datetime('now')",
        )
        .bind(user)
        .bind(text)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Sets a line of a person's inbox aside, replacing an earlier aside of the same
    /// cause. ⚠️ The cause is stored as its JSON: renaming a variant orphans the rows
    /// written under the old name, which then simply stop applying — the line comes
    /// back, which is the safe way to fail.
    pub async fn set_aside(&self, user: &str, a: &hlb_api::issues::Aside) -> Result<()> {
        let cause = serde_json::to_string(&a.cause).unwrap_or_default();
        let attention = serde_json::to_value(a.attention)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        sqlx::query(
            "INSERT INTO issue_asides (user, cause, until, attention, subjects)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(user, cause) DO UPDATE SET until = excluded.until,
                 attention = excluded.attention, subjects = excluded.subjects",
        )
        .bind(user)
        .bind(cause)
        .bind(a.until)
        .bind(attention)
        .bind(a.subjects as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Brings a line back; `false` if it was not set aside.
    pub async fn bring_back(&self, user: &str, cause: &hlb_api::issues::Cause) -> Result<bool> {
        let cause = serde_json::to_string(cause).unwrap_or_default();
        let r = sqlx::query("DELETE FROM issue_asides WHERE user = ?1 AND cause = ?2")
            .bind(user)
            .bind(cause)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// What a person set aside and has not ended. A row whose cause or attention no
    /// longer reads is skipped: the line it named comes back.
    pub async fn asides_of(&self, user: &str, now: i64) -> Result<Vec<hlb_api::issues::Aside>> {
        let rows = sqlx::query(
            "SELECT cause, until, attention, subjects FROM issue_asides
             WHERE user = ?1 AND until > ?2",
        )
        .bind(user)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .filter_map(|r| {
                let cause: String = r.try_get("cause").ok()?;
                let attention: String = r.try_get("attention").ok()?;
                Some(hlb_api::issues::Aside {
                    cause: serde_json::from_str(&cause).ok()?,
                    until: r.try_get("until").ok()?,
                    attention: serde_json::from_value(serde_json::Value::String(attention)).ok()?,
                    subjects: r.try_get::<i64, _>("subjects").ok()? as usize,
                })
            })
            .collect())
    }

    pub async fn record_job_run(&self, run: &JobRun) -> Result<()> {
        sqlx::query(
            "INSERT INTO job_runs (app, job, ran_at, succeeded, output)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(app, job) DO UPDATE SET ran_at = excluded.ran_at,
                 succeeded = excluded.succeeded, output = excluded.output",
        )
        .bind(&run.app)
        .bind(&run.job)
        .bind(run.ran_at)
        .bind(run.succeeded)
        .bind(&run.output)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Every job's last run, by app then job.
    pub async fn job_runs(&self) -> Result<Vec<JobRun>> {
        let rows = sqlx::query(
            "SELECT app, job, ran_at, succeeded, output FROM job_runs ORDER BY app, job",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(JobRun {
                    app: r.try_get("app")?,
                    job: r.try_get("job")?,
                    ran_at: r.try_get("ran_at")?,
                    succeeded: r.try_get("succeeded")?,
                    output: r.try_get("output")?,
                })
            })
            .collect()
    }

    /// How far `app` updates with nobody there, as the owner set it: the app's own
    /// setting, else the house's. `None`: the manifest decides.
    pub async fn update_automatic(&self, app: &str) -> Result<Option<hlb_types::Automatic>> {
        let row: Option<String> = sqlx::query_scalar(
            "SELECT automatic FROM update_automatic WHERE app IN (?1, '')
             ORDER BY app = '' LIMIT 1",
        )
        .bind(app)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_deref().and_then(hlb_types::Automatic::parse))
    }

    /// Sets how far updates go alone, for `app` or the whole house (`None`); `automatic`
    /// `None` gives the decision back to the app's setting, the house's, or the manifest.
    pub async fn set_update_automatic(
        &self,
        app: Option<&str>,
        automatic: Option<hlb_types::Automatic>,
    ) -> Result<()> {
        let app = app.unwrap_or("");
        match automatic {
            Some(a) => {
                sqlx::query(
                    "INSERT INTO update_automatic (app, automatic) VALUES (?1, ?2)
                     ON CONFLICT (app) DO UPDATE SET automatic = excluded.automatic",
                )
                .bind(app)
                .bind(a.as_str())
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM update_automatic WHERE app = ?1")
                    .bind(app)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// Every setting the owner made: `""` is the house's.
    pub async fn update_automatic_settings(&self) -> Result<Vec<(String, hlb_types::Automatic)>> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT app, automatic FROM update_automatic ORDER BY app")
                .fetch_all(&self.pool)
                .await?;
        Ok(rows
            .into_iter()
            .filter_map(|(app, a)| hlb_types::Automatic::parse(&a).map(|a| (app, a)))
            .collect())
    }

    /// Records who applies `d.app`'s waiting update. The approval and the refusal are kept
    /// while the digest is the same, and cleared when a newer one is proposed: a click is
    /// for the image a person looked at.
    pub async fn record_update_decision(&self, d: &UpdateDecision) -> Result<()> {
        sqlx::query(
            "INSERT INTO update_decisions
                 (app, digest, from_tag, kind, to_tag, who, why, notes, decided_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (app) DO UPDATE SET
                 refused = CASE WHEN digest = excluded.digest THEN refused END,
                 refused_at = CASE WHEN digest = excluded.digest THEN refused_at END,
                 approved_by = CASE WHEN digest = excluded.digest THEN approved_by END,
                 approved_at = CASE WHEN digest = excluded.digest THEN approved_at END,
                 digest = excluded.digest, from_tag = excluded.from_tag,
                 kind = excluded.kind, to_tag = excluded.to_tag, who = excluded.who,
                 why = excluded.why, notes = excluded.notes,
                 decided_at = excluded.decided_at",
        )
        .bind(&d.app)
        .bind(&d.digest)
        .bind(&d.from_tag)
        .bind(&d.kind)
        .bind(&d.to_tag)
        .bind(&d.who)
        .bind(&d.why)
        .bind(&d.notes)
        .bind(d.decided_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Every waiting update's decision, by app.
    pub async fn update_decisions(&self) -> Result<Vec<UpdateDecision>> {
        let rows = sqlx::query(
            "SELECT app, digest, from_tag, kind, to_tag, who, why, notes, decided_at,
                    refused, refused_at, approved_by, approved_at
             FROM update_decisions ORDER BY app",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(update_decision_of).collect()
    }

    /// `app`'s waiting update's decision, if one waits.
    pub async fn update_decision(&self, app: &str) -> Result<Option<UpdateDecision>> {
        Ok(self
            .update_decisions()
            .await?
            .into_iter()
            .find(|d| d.app == app))
    }

    /// Forgets every decision but those of `keep`: an update applied, or no longer
    /// proposed, waits for nobody.
    pub async fn keep_update_decisions(
        &self,
        keep: &std::collections::BTreeSet<String>,
    ) -> Result<()> {
        for d in self.update_decisions().await? {
            if !keep.contains(&d.app) {
                sqlx::query("DELETE FROM update_decisions WHERE app = ?1")
                    .bind(&d.app)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// The automatic path refused `digest` of `app`'s update: a person's again.
    pub async fn refuse_update(
        &self,
        app: &str,
        digest: &str,
        refused: &str,
        at: i64,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE update_decisions SET refused = ?3, refused_at = ?4
             WHERE app = ?1 AND digest = ?2",
        )
        .bind(app)
        .bind(digest)
        .bind(refused)
        .bind(at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// A person approves `digest` of `app`'s update, for the pass to apply in its window.
    /// `false` when that digest no longer waits: a newer one was proposed meanwhile, and
    /// nobody approved that one.
    pub async fn approve_update(&self, app: &str, digest: &str, by: &str, at: i64) -> Result<bool> {
        let r = sqlx::query(
            "UPDATE update_decisions SET approved_by = ?3, approved_at = ?4
             WHERE app = ?1 AND digest = ?2",
        )
        .bind(app)
        .bind(digest)
        .bind(by)
        .bind(at)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Records an update's outcome, to be notified. `id` is ignored: the row's own is
    /// returned.
    pub async fn record_update_run(&self, run: &UpdateRun) -> Result<i64> {
        let r = sqlx::query(
            "INSERT INTO update_runs (app, ran_at, from_image, to_image, outcome, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&run.app)
        .bind(run.ran_at)
        .bind(&run.from_image)
        .bind(&run.to_image)
        .bind(run.outcome.as_str())
        .bind(&run.detail)
        .execute(&self.pool)
        .await?;
        Ok(r.last_insert_rowid())
    }

    /// A pass proposed moving `app` to `digest`: its first sighting is kept, its last moves.
    pub async fn note_update_seen(&self, app: &str, digest: &str, at: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO update_first_seen (app, digest, first_seen_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(app, digest) DO UPDATE SET last_seen_at = excluded.last_seen_at",
        )
        .bind(app)
        .bind(digest)
        .bind(at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// How long each update took from first sighting to being applied, and how long the
    /// ones still proposed have waited. Oldest sighting first.
    ///
    /// An image is found in a run's `to_image`, or in its `detail` for a companion, which
    /// moves with the app's own image named elsewhere. 🔴 `applied` only: a rolled-back
    /// update is still not applied, and its lag would read as a fix delivered.
    pub async fn update_lags(&self, now: i64) -> Result<UpdateLags> {
        // Two days: a daily pass that misses one does not drop what it proposed.
        const STILL_PROPOSED_S: i64 = 2 * 86_400;
        let seen = sqlx::query(
            "SELECT app, digest, first_seen_at, last_seen_at FROM update_first_seen
             ORDER BY first_seen_at, app, digest",
        )
        .fetch_all(&self.pool)
        .await?;
        let runs = sqlx::query(
            "SELECT app, ran_at, to_image, detail FROM update_runs
             WHERE outcome = ?1 ORDER BY ran_at",
        )
        .bind(UpdateRunOutcome::Applied.as_str())
        .fetch_all(&self.pool)
        .await?;
        let mut lags = UpdateLags::default();
        for row in seen {
            let app: String = row.try_get("app")?;
            let digest: String = row.try_get("digest")?;
            let first: i64 = row.try_get("first_seen_at")?;
            let last: i64 = row.try_get("last_seen_at")?;
            let mut applied = None;
            for run in &runs {
                let to_image: String = run.try_get("to_image")?;
                let detail: String = run.try_get("detail")?;
                let run_app: String = run.try_get("app")?;
                if run_app == app && (to_image.contains(&digest) || detail.contains(&digest)) {
                    applied = Some(run.try_get::<i64, _>("ran_at")?);
                    break;
                }
            }
            match applied {
                Some(at) => lags.applied.push(UpdateLag {
                    app,
                    digest,
                    seconds: (at - first).max(0),
                }),
                None if now - last <= STILL_PROPOSED_S => lags.waiting.push(UpdateLag {
                    app,
                    digest,
                    seconds: (now - first).max(0),
                }),
                None => {}
            }
        }
        Ok(lags)
    }

    /// The updates nobody has been told about yet, oldest first.
    ///
    /// ⚠️ An outcome this version cannot read is returned as `inconclusive`, never
    /// dropped: a row skipped here would stay unnotified forever.
    pub async fn unnotified_update_runs(&self) -> Result<Vec<UpdateRun>> {
        let rows = sqlx::query(
            "SELECT id, app, ran_at, from_image, to_image, outcome, detail
             FROM update_runs WHERE notified_at IS NULL ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let outcome: String = r.try_get("outcome")?;
                Ok(UpdateRun {
                    id: r.try_get("id")?,
                    app: r.try_get("app")?,
                    ran_at: r.try_get("ran_at")?,
                    from_image: r.try_get("from_image")?,
                    to_image: r.try_get("to_image")?,
                    outcome: UpdateRunOutcome::parse(&outcome)
                        .unwrap_or(UpdateRunOutcome::Inconclusive),
                    detail: r.try_get("detail")?,
                })
            })
            .collect()
    }

    /// Keeps a notification for when quiet hours end. A newer one on the same subject
    /// replaces it, and keeps the hour the first was held at.
    pub async fn hold_notification(
        &self,
        subject: &str,
        level: &str,
        title: &str,
        body: &str,
        at: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO held_notifications (subject, level, title, body, held_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(subject) DO UPDATE SET level = excluded.level,
                 title = excluded.title, body = excluded.body,
                 revision = held_notifications.revision + 1",
        )
        .bind(subject)
        .bind(level)
        .bind(title)
        .bind(body)
        .bind(at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The held notifications, oldest first.
    pub async fn held_notifications(&self) -> Result<Vec<HeldNotification>> {
        let rows = sqlx::query(
            "SELECT subject, level, title, body, held_at, revision
             FROM held_notifications ORDER BY held_at, subject",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(HeldNotification {
                    subject: r.try_get("subject")?,
                    level: r.try_get("level")?,
                    title: r.try_get("title")?,
                    body: r.try_get("body")?,
                    held_at: r.try_get("held_at")?,
                    revision: r.try_get("revision")?,
                })
            })
            .collect()
    }

    /// Forgets a held notification once sent — that version only.
    pub async fn release_held_notification(&self, subject: &str, revision: i64) -> Result<()> {
        sqlx::query("DELETE FROM held_notifications WHERE subject = ?1 AND revision = ?2")
            .bind(subject)
            .bind(revision)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_update_run_notified(&self, id: i64, at: i64) -> Result<()> {
        sqlx::query("UPDATE update_runs SET notified_at = ?2 WHERE id = ?1")
            .bind(id)
            .bind(at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Replaces an app's assertion readings with these: an assertion the manifest no
    /// longer declares is not left reporting a door that is gone.
    pub async fn record_assertions(
        &self,
        app: &str,
        results: &[hlb_api::assertions::AssertionResult],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM assertion_results WHERE app = ?1")
            .bind(app)
            .execute(&mut *tx)
            .await?;
        for r in results {
            sqlx::query(
                "INSERT INTO assertion_results (app, id, holds, verdict, observed, checked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(app)
            .bind(&r.id)
            .bind(&r.holds)
            .bind(r.verdict.as_str())
            .bind(&r.observed)
            .bind(r.checked_at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// The last readings, app by app, in the order of their ids.
    pub async fn assertion_results(
        &self,
    ) -> Result<Vec<(String, hlb_api::assertions::AssertionResult)>> {
        let rows = sqlx::query(
            "SELECT app, id, holds, verdict, observed, checked_at FROM assertion_results
             ORDER BY app, id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .filter_map(|r| {
                let verdict: String = r.try_get("verdict").ok()?;
                Some((
                    r.try_get("app").ok()?,
                    hlb_api::assertions::AssertionResult {
                        id: r.try_get("id").ok()?,
                        holds: r.try_get("holds").ok()?,
                        verdict: hlb_api::assertions::Verdict::parse(&verdict)?,
                        observed: r.try_get("observed").ok()?,
                        checked_at: r.try_get("checked_at").ok()?,
                        // The manifest's, not the reading's: set by whoever says it.
                        fix: None,
                    },
                ))
            })
            .collect())
    }

    /// Replaces every mail record reading with these.
    pub async fn record_mail_records(
        &self,
        records: &[hlb_api::mail_dns::MailRecord],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM mail_records")
            .execute(&mut *tx)
            .await?;
        for r in records {
            sqlx::query(
                "INSERT INTO mail_records
                   (domain, name, purpose, expected, state, observed, checked_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .bind(&r.domain)
            .bind(&r.name)
            .bind(r.purpose.as_str())
            .bind(&r.expected)
            .bind(r.state.as_str())
            .bind(&r.observed)
            .bind(r.checked_at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// The last readings, by domain and name.
    pub async fn mail_records(&self) -> Result<Vec<hlb_api::mail_dns::MailRecord>> {
        use hlb_api::mail_dns::{MailRecord, Purpose, RecordState};
        let rows = sqlx::query(
            "SELECT domain, name, purpose, expected, state, observed, checked_at
             FROM mail_records ORDER BY domain, name, purpose",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .filter_map(|r| {
                let purpose: String = r.try_get("purpose").ok()?;
                let state: String = r.try_get("state").ok()?;
                Some(MailRecord {
                    domain: r.try_get("domain").ok()?,
                    name: r.try_get("name").ok()?,
                    purpose: Purpose::parse(&purpose)?,
                    expected: r.try_get("expected").ok()?,
                    state: RecordState::parse(&state)?,
                    observed: r.try_get("observed").ok()?,
                    checked_at: r.try_get("checked_at").ok()?,
                })
            })
            .collect())
    }

    /// Records the spam filter's blocklists last found refusing Stalwart's resolver, by
    /// tag; none, and nothing is kept.
    pub async fn record_refused_blocklists(&self, tags: &[String]) -> Result<()> {
        if tags.is_empty() {
            sqlx::query("DELETE FROM settings WHERE key = 'mail-refused-blocklists'")
                .execute(&self.pool)
                .await?;
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES ('mail-refused-blocklists', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                            updated_at = datetime('now')",
        )
        .bind(tags.join(" "))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The blocklists the last reading found refusing Stalwart's resolver.
    pub async fn refused_blocklists(&self) -> Result<Vec<String>> {
        let row = sqlx::query("SELECT value FROM settings WHERE key = 'mail-refused-blocklists'")
            .fetch_optional(&self.pool)
            .await?;
        let value: Option<String> = row.map(|r| r.try_get("value")).transpose()?;
        Ok(value
            .map(|v| v.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default())
    }

    /// Replaces the last reading of Stalwart's queue with this one.
    pub async fn record_mail_queue(&self, waiting: &[hlb_api::mail_queue::Waiting]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM mail_queue")
            .execute(&mut *tx)
            .await?;
        for w in waiting {
            sqlx::query(
                "INSERT INTO mail_queue
                   (message_id, recipient, since, attempts, next_retry, expires_at, error, read_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .bind(&w.message_id)
            .bind(&w.recipient)
            .bind(w.since)
            .bind(i64::try_from(w.attempts).unwrap_or(i64::MAX))
            .bind(w.next_retry)
            .bind(w.expires_at)
            .bind(&w.error)
            .bind(w.read_at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// The last reading of Stalwart's queue, the oldest first.
    pub async fn mail_queue(&self) -> Result<Vec<hlb_api::mail_queue::Waiting>> {
        let rows = sqlx::query(
            "SELECT message_id, recipient, since, attempts, next_retry, expires_at, error, read_at
             FROM mail_queue ORDER BY since, recipient",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .filter_map(|r| {
                let attempts: i64 = r.try_get("attempts").ok()?;
                Some(hlb_api::mail_queue::Waiting {
                    message_id: r.try_get("message_id").ok()?,
                    recipient: r.try_get("recipient").ok()?,
                    since: r.try_get("since").ok()?,
                    attempts: u64::try_from(attempts).unwrap_or(0),
                    next_retry: r.try_get("next_retry").ok()?,
                    expires_at: r.try_get("expires_at").ok()?,
                    error: r.try_get("error").ok()?,
                    read_at: r.try_get("read_at").ok()?,
                })
            })
            .collect())
    }

    /// Mutes an alert until `m.until`, replacing any mute the rule already had.
    pub async fn mute_alert(&self, m: &hlb_api::AlertMute) -> Result<()> {
        sqlx::query(
            "INSERT INTO alert_mutes (rule, until, muted_by, reason) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(rule) DO UPDATE SET until = excluded.until,
                                             muted_by = excluded.muted_by,
                                             reason = excluded.reason,
                                             created_at = datetime('now')",
        )
        .bind(&m.rule)
        .bind(m.until)
        .bind(&m.by)
        .bind(&m.reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Lifts a rule's mute. `false` when there was none to lift.
    pub async fn unmute_alert(&self, rule: &str) -> Result<bool> {
        let done = sqlx::query("DELETE FROM alert_mutes WHERE rule = ?1")
            .bind(rule)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    /// The mutes in force at `now`. An ended one is not returned: it stops applying
    /// the second it runs out, without waiting for anyone to clean it.
    pub async fn alert_mutes(&self, now: i64) -> Result<Vec<hlb_api::AlertMute>> {
        let rows = sqlx::query(
            "SELECT rule, until, muted_by, reason FROM alert_mutes WHERE until > ?1 ORDER BY rule",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(hlb_api::AlertMute {
                    rule: r.try_get("rule")?,
                    until: r.try_get("until")?,
                    by: r.try_get("muted_by")?,
                    reason: r.try_get("reason")?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn an_app_s_own_update_setting_wins_over_the_house_s() {
        use hlb_types::Automatic;
        let s = State::in_memory().await.expect("state");
        assert_eq!(s.update_automatic("gitea").await.expect("read"), None);
        s.set_update_automatic(None, Some(Automatic::None))
            .await
            .expect("house");
        s.set_update_automatic(Some("gitea"), Some(Automatic::Minor))
            .await
            .expect("app");
        assert_eq!(
            s.update_automatic("gitea").await.expect("read"),
            Some(Automatic::Minor)
        );
        assert_eq!(
            s.update_automatic("immich").await.expect("read"),
            Some(Automatic::None)
        );
        s.set_update_automatic(Some("gitea"), None)
            .await
            .expect("cleared");
        assert_eq!(
            s.update_automatic("gitea").await.expect("read"),
            Some(Automatic::None)
        );
        assert_eq!(s.update_automatic_settings().await.expect("all").len(), 1);
    }

    /// 🔴 A click is for the image a person looked at: a newer digest clears it, and a
    /// refusal after it takes the update back to a person.
    #[tokio::test]
    async fn an_approval_holds_for_one_digest_and_until_its_next_refusal() {
        let s = State::in_memory().await.expect("state");
        let decided = |digest: &str, at: i64| UpdateDecision {
            app: "gitea".into(),
            digest: digest.into(),
            from_tag: "1.24.3".into(),
            kind: "version".into(),
            to_tag: Some("1.25.0".into()),
            who: "one-click".into(),
            why: None,
            notes: None,
            decided_at: at,
            refused: None,
            refused_at: None,
            approved_by: None,
            approved_at: None,
        };
        s.record_update_decision(&decided("sha256:a", 10))
            .await
            .expect("decided");
        assert!(!s
            .approve_update("gitea", "sha256:other", "alice", 11)
            .await
            .expect("approve"));
        assert!(s
            .approve_update("gitea", "sha256:a", "alice", 11)
            .await
            .expect("approve"));
        // The next hour's pass decides the same digest again: the click stays.
        s.record_update_decision(&decided("sha256:a", 20))
            .await
            .expect("again");
        let d = s
            .update_decision("gitea")
            .await
            .expect("read")
            .expect("row");
        assert!(d.waiting().expect("read").approved(), "{d:?}");
        assert_eq!(d.approved_by.as_deref(), Some("alice"));

        s.refuse_update("gitea", "sha256:a", r#"{"kind":"paused"}"#, 30)
            .await
            .expect("refused");
        let d = s
            .update_decision("gitea")
            .await
            .expect("read")
            .expect("row");
        let w = d.waiting().expect("read");
        assert!(!w.approved() && w.needs().is_some(), "{d:?}");
        s.approve_update("gitea", "sha256:a", "alice", 31)
            .await
            .expect("again");
        let d = s
            .update_decision("gitea")
            .await
            .expect("read")
            .expect("row");
        let w = d.waiting().expect("read");
        assert!(w.approved() && w.needs().is_none(), "{d:?}");

        // A newer image: nobody looked at it.
        s.record_update_decision(&decided("sha256:b", 40))
            .await
            .expect("newer");
        let d = s
            .update_decision("gitea")
            .await
            .expect("read")
            .expect("row");
        assert!(!d.waiting().expect("read").approved() && d.refused.is_none());

        s.keep_update_decisions(&Default::default())
            .await
            .expect("kept none");
        assert!(s.update_decisions().await.expect("read").is_empty());
    }

    #[tokio::test]
    async fn a_service_held_again_keeps_what_it_is_to_be_given_back() {
        let s = State::in_memory().await.expect("state");
        s.hold_services(&[("mail".to_string(), 2)], "backup copy of a", 3600)
            .await
            .expect("hold");
        // The next pass reads the 0 the first one left.
        s.hold_services(&[("mail".to_string(), 0)], "backup copy of b", 3600)
            .await
            .expect("hold");
        let holds = s.service_holds().await.expect("read");
        assert_eq!(holds.len(), 1);
        assert_eq!(holds[0].replicas, Some(2));
        assert_eq!(holds[0].why, "backup copy of b");
    }

    #[tokio::test]
    async fn an_update_s_lag_runs_from_its_first_sighting_to_its_application() {
        let s = State::in_memory().await.expect("state");
        let day = 86_400;
        let run = |app: &str, at: i64, to: &str, detail: &str, outcome| UpdateRun {
            id: 0,
            app: app.into(),
            ran_at: at,
            from_image: "a:1".into(),
            to_image: to.into(),
            outcome,
            detail: detail.into(),
        };
        // Seen on day 1 and again on day 3: the first sighting counts.
        s.note_update_seen("gitea", "sha256:a", day)
            .await
            .expect("seen");
        s.note_update_seen("gitea", "sha256:a", 3 * day)
            .await
            .expect("seen");
        // A companion's image is named in the run's detail.
        s.note_update_seen("immich", "sha256:ml", day)
            .await
            .expect("seen");
        // Rolled back: not applied, still proposed.
        s.note_update_seen("n8n", "sha256:bad", 9 * day)
            .await
            .expect("seen");
        // Replaced by a newer build long ago: waiting for nothing.
        s.note_update_seen("vikunja", "sha256:old", day)
            .await
            .expect("seen");

        for r in [
            run(
                "gitea",
                5 * day,
                "gitea:2@sha256:a",
                "",
                UpdateRunOutcome::Applied,
            ),
            run(
                "immich",
                2 * day,
                "immich:3",
                "with ml → ml:3@sha256:ml",
                UpdateRunOutcome::Applied,
            ),
            run(
                "n8n",
                10 * day,
                "n8n:2@sha256:bad",
                "",
                UpdateRunOutcome::RolledBack,
            ),
            // The same digest in another app's run is not this app's.
            run("mealie", day, "x@sha256:ml", "", UpdateRunOutcome::Applied),
        ] {
            s.record_update_run(&r).await.expect("run");
        }

        let lags = s.update_lags(10 * day).await.expect("lags");
        let of = |l: &[UpdateLag]| {
            l.iter()
                .map(|x| (x.app.clone(), x.seconds / day))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            of(&lags.applied),
            [("gitea".to_string(), 4), ("immich".to_string(), 1)]
        );
        assert_eq!(of(&lags.waiting), [("n8n".to_string(), 1)]);
    }

    #[tokio::test]
    async fn a_removed_app_s_domains_outlive_it_until_cleared() {
        let s = State::in_memory().await.expect("state");
        let mut m = manifest("wiki");
        for domain in ["a.example.test", "b.example.test"] {
            s.upsert_app("wiki", &m, Some(domain)).await.expect("app");
            s.forget_app("wiki").await.expect("forgotten");
        }
        assert_eq!(
            s.removed_domains("wiki").await.expect("domains"),
            Vec::<String>::new(),
            "no portal, no callback to find again"
        );

        m.spec.requires = vec![hlb_types::capability::Capability::Sso {
            mode: hlb_types::capability::SsoMode::ProxyOnly,
            redirect_paths: Vec::new(),
        }];
        for domain in ["a.example.test", "b.example.test", "a.example.test"] {
            s.upsert_app("wiki", &m, Some(domain)).await.expect("app");
            s.forget_app("wiki").await.expect("forgotten");
        }
        assert_eq!(
            s.removed_domains("wiki").await.expect("domains"),
            vec!["a.example.test".to_string(), "b.example.test".to_string()]
        );
        s.clear_removed_domains("wiki").await.expect("cleared");
        assert_eq!(
            s.removed_domains("wiki").await.expect("domains"),
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn only_a_removal_that_succeeded_counts_as_one() {
        let s = super::State::in_memory().await.expect("state");
        assert!(!s.app_was_removed("gitea").await.expect("read"));
        for outcome in ["preview", "failed"] {
            s.audit(
                "cli",
                hlb_types::Role::Admin,
                super::APP_REMOVED,
                "gitea",
                outcome,
                None,
            )
            .await
            .expect("audit");
        }
        s.audit(
            "cli",
            hlb_types::Role::Admin,
            "app-install",
            "gitea",
            "ok",
            None,
        )
        .await
        .expect("audit");
        s.audit(
            "cli",
            hlb_types::Role::Admin,
            super::APP_REMOVED,
            "other",
            "ok",
            None,
        )
        .await
        .expect("audit");
        assert!(!s.app_was_removed("gitea").await.expect("read"));

        s.audit(
            "cli",
            hlb_types::Role::Admin,
            super::APP_REMOVED,
            "gitea",
            "ok",
            None,
        )
        .await
        .expect("audit");
        assert!(s.app_was_removed("gitea").await.expect("read"));
    }

    use super::*;

    #[tokio::test]
    async fn a_source_counter_only_ever_rises() {
        let s = State::in_memory().await.expect("state");
        let source = CatalogSource {
            name: "community".into(),
            directory: "/var/lib/homelabus/catalog/community".into(),
            signed: Some(SignedSource {
                url: "https://example.org/catalog".into(),
                key: "00".repeat(32),
                counter: None,
            }),
        };
        assert!(s.add_catalog_source(&source).await.expect("added"));
        assert!(!s.add_catalog_source(&source).await.expect("twice"));
        assert!(s
            .raise_catalog_source_counter("community", 4)
            .await
            .expect("up"));
        assert!(s
            .raise_catalog_source_counter("community", 4)
            .await
            .expect("same"));
        // 🔴 Accepted, a replayed index would set the bar back for the next one.
        assert!(!s
            .raise_catalog_source_counter("community", 3)
            .await
            .expect("down"));
        let read = s.catalog_sources().await.expect("read");
        assert_eq!(read[0].signed.as_ref().and_then(|s| s.counter), Some(4));
    }

    #[tokio::test]
    async fn a_carried_source_written_again_keeps_its_counter() {
        let s = State::in_memory().await.expect("state");
        let source = |url: &str| CatalogSource {
            name: "official".into(),
            directory: "/var/lib/homelabus/catalog-sources/official".into(),
            signed: Some(SignedSource {
                url: url.into(),
                key: "00".repeat(32),
                counter: None,
            }),
        };
        s.set_carried_source(&source("https://a.example/catalog"))
            .await
            .expect("written");
        assert!(s
            .raise_catalog_source_counter("official", 7)
            .await
            .expect("up"));
        // A release moving the address: the bar a replay must clear stays where it was.
        s.set_carried_source(&source("https://b.example/catalog"))
            .await
            .expect("again");
        let read = s.catalog_sources().await.expect("read");
        assert_eq!(read.len(), 1);
        let signed = read[0].signed.as_ref().expect("signed");
        assert_eq!(
            (signed.url.as_str(), signed.counter),
            ("https://b.example/catalog", Some(7))
        );
    }

    /// The web side mounts the state's directory at `/state`, where the CLI and privd
    /// see `/var/lib/homelabus`: a cache path one of them wrote led the other nowhere,
    /// and the interface showed the carried catalog in place of the signed index.
    #[tokio::test]
    async fn a_fetched_source_is_read_where_the_reader_sees_the_state() {
        let root = tempfile::tempdir().expect("tempdir");
        let writer = root.path().join("var-lib-homelabus");
        std::fs::create_dir(&writer).expect("writer's directory");
        let w = State::open(writer.join("hlb.db")).await.expect("written");
        w.add_catalog_source(&CatalogSource {
            name: "community".into(),
            directory: source_cache(&writer, "community").display().to_string(),
            signed: Some(SignedSource {
                url: "https://example.org/catalog".into(),
                key: "00".repeat(32),
                counter: None,
            }),
        })
        .await
        .expect("added");
        w.add_catalog_source(&CatalogSource {
            name: "mine".into(),
            directory: "/srv/my-apps".into(),
            signed: None,
        })
        .await
        .expect("added");
        drop(w);

        let mounted = root.path().join("state");
        std::os::unix::fs::symlink(&writer, &mounted).expect("the other mount");
        let r = State::open_read_only(mounted.join("hlb.db"))
            .await
            .expect("read");
        let read = r.catalog_sources().await.expect("sources");
        let dir = |n: &str| {
            read.iter()
                .find(|s| s.name == n)
                .map(|s| s.directory.clone())
                .expect("source")
        };
        assert_eq!(
            dir("community"),
            mounted
                .join("catalog-sources")
                .join("community")
                .display()
                .to_string()
        );
        // A directory someone added is theirs: nothing to derive it from.
        assert_eq!(dir("mine"), "/srv/my-apps");
    }

    fn manifest(name: &str) -> Manifest {
        let y = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {name} }}\n\
             spec:\n  image: {{ repo: a/b, tag: \"1\" }}\n"
        );
        serde_yaml_ng::from_str(&y).expect("test manifest")
    }

    async fn st() -> State {
        State::in_memory().await.expect("in-memory database")
    }

    #[tokio::test]
    async fn the_memory_database_outlives_its_connection() {
        let s = st().await;
        s.set_timezone("Europe/Paris").await.expect("written");
        // What `sqlx` does to a connection it judges broken on release — a request
        // cancelled mid-query — before opening another to keep `min_connections`.
        let mut c = s.pool.acquire().await.expect("the connection");
        c.close_on_drop();
        drop(c);
        let zone = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match s.timezone().await {
                    Ok(z) => break z,
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await;
        assert_eq!(
            zone.ok().flatten().as_deref(),
            Some("Europe/Paris"),
            "a new connection opened onto an empty database"
        );
    }

    #[tokio::test]
    async fn the_snapshots_already_in_the_history_are_known_after_the_upgrade() {
        // Otherwise every snapshot taken before it would be set aside at the next
        // restore, the one taken before yesterday's broken update included.
        let s = st().await;
        s.undo_migrations(38).await.expect("back to before 0039");
        // As the code before it wrote them: one with its destination, one without.
        sqlx::query(
            "INSERT INTO backup_runs (app, kind, destination, snapshot_id, status, finished_at)
             VALUES ('gitea', 'volume', 'nas', 'old1', 'ok', datetime('now')),
                    ('vaultwarden', 'database', NULL, 'old2', 'ok', datetime('now')),
                    ('vaultwarden', 'database', 'nas', 'cut', 'failed', datetime('now'))",
        )
        .execute(&s.pool)
        .await
        .expect("an old history");
        sqlx::migrate!("./migrations")
            .run(&s.pool)
            .await
            .expect("apply 0039");
        assert!(s
            .snapshots_taken("gitea")
            .await
            .expect("read")
            .contains("old1"));
        let vw = s.snapshots_taken("vaultwarden").await.expect("read");
        assert!(vw.contains("old2") && !vw.contains("cut"), "{vw:?}");
    }

    #[tokio::test]
    async fn a_proof_holds_for_the_location_it_was_made_against() {
        let s = st().await;
        s.record_destination_proof("offsite", "s3:https://a/b", "kept", "refused", 10)
            .await
            .expect("recorded");
        assert_eq!(
            s.destination_proof("offsite", "s3:https://a/b")
                .await
                .expect("read"),
            Some(("kept".into(), "refused".into(), 10))
        );
        // Pointed elsewhere since: nothing is known of the new place.
        assert_eq!(
            s.destination_proof("offsite", "s3:https://c/d")
                .await
                .expect("read"),
            None
        );
        s.record_destination_proof("offsite", "s3:https://c/d", "erasable", "deleted", 20)
            .await
            .expect("again");
        assert_eq!(
            s.destination_proof("offsite", "s3:https://c/d")
                .await
                .expect("read")
                .map(|p| p.0),
            Some("erasable".into())
        );
    }

    #[tokio::test]
    async fn every_snapshot_taken_is_known_by_its_app_and_none_other() {
        let s = st().await;
        s.record_backup_to("gitea", "volume", "nas", Some("aaa"), None)
            .await
            .expect("recorded");
        // A failed run names no snapshot it could vouch for.
        s.record_backup_to("gitea", "volume", "nas", Some("bbb"), Some("cut"))
            .await
            .expect("recorded");
        s.record_snapshot("gitea", "nas", "ccc")
            .await
            .expect("recorded");
        s.record_snapshot("gitea", "offsite", "ccc")
            .await
            .expect("twice is once");
        s.record_snapshot("immich", "nas", "ddd")
            .await
            .expect("recorded");
        let taken = s.snapshots_taken("gitea").await.expect("read");
        let mut taken: Vec<&str> = taken.iter().map(String::as_str).collect();
        taken.sort();
        assert_eq!(taken, ["aaa", "ccc"]);
    }

    /// A role at this level, named after it.
    async fn level(s: &State, level: hlb_types::Role) -> String {
        let r = hlb_users::RoleDef::new(level.as_str(), level, hlb_users::MailLimits::standard());
        s.put_role(&r, "test").await.expect("role");
        r.id
    }

    #[tokio::test]
    async fn an_applied_update_is_notified_once_like_a_failed_one() {
        let s = st().await;
        let run = |outcome| UpdateRun {
            id: 0,
            app: "gitea".into(),
            ran_at: 100,
            from_image: "gitea/gitea:1.24@sha256:a".into(),
            to_image: "gitea/gitea:1.24.7@sha256:b".into(),
            outcome,
            detail: String::new(),
        };
        let applied = s
            .record_update_run(&run(UpdateRunOutcome::Applied))
            .await
            .expect("recorded");
        s.record_update_run(&run(UpdateRunOutcome::RolledBack))
            .await
            .expect("recorded");

        let pending = s.unnotified_update_runs().await.expect("read");
        assert_eq!(
            pending.iter().map(|r| r.outcome).collect::<Vec<_>>(),
            [UpdateRunOutcome::Applied, UpdateRunOutcome::RolledBack]
        );
        s.mark_update_run_notified(applied, 200)
            .await
            .expect("marked");
        let pending = s.unnotified_update_runs().await.expect("read");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].outcome, UpdateRunOutcome::RolledBack);
    }

    #[tokio::test]
    async fn a_held_notification_is_released_only_in_the_version_sent() {
        let s = State::in_memory().await.expect("state");
        s.hold_notification("backup:gitea", "important", "Backup failed", "first", 100)
            .await
            .expect("held");
        let first = s.held_notifications().await.expect("read");
        assert_eq!(first.len(), 1);

        // A newer notice on the same subject replaces it, keeping when it was held.
        s.hold_notification("backup:gitea", "important", "Backup failed", "second", 200)
            .await
            .expect("held");
        s.release_held_notification("backup:gitea", first[0].revision)
            .await
            .expect("released");
        let left = s.held_notifications().await.expect("read");
        assert_eq!(left.len(), 1, "the newer version was not the one sent");
        assert_eq!((left[0].body.as_str(), left[0].held_at), ("second", 100));

        s.release_held_notification("backup:gitea", left[0].revision)
            .await
            .expect("released");
        assert!(s.held_notifications().await.expect("read").is_empty());
    }

    #[test]
    fn an_update_outcome_reads_back_what_it_wrote() {
        // A stored value: renamed on one side, every row would read back as unknown.
        for o in [
            UpdateRunOutcome::Applied,
            UpdateRunOutcome::RolledBack,
            UpdateRunOutcome::Paused,
            UpdateRunOutcome::Inconclusive,
        ] {
            assert_eq!(UpdateRunOutcome::parse(o.as_str()), Some(o));
        }
    }

    #[tokio::test]
    async fn a_successful_verification_is_never_recorded_as_a_failure() {
        // 🔴 The defect as it appeared: the signature inferred failure from the
        // presence of a detail. A successful verification that was DESCRIBED ("1,284
        // files read back") was therefore recorded as a failure, and the app stayed
        // "never verified" - a red screen over work actually done, which pushes people
        // to redo the verification forever.
        let s = State::in_memory().await.expect("in-memory state");

        s.record_verification("gitea", "a1b2c3d4", true, Some("1,284 files read back"))
            .await
            .expect("enregistrement");

        let age = s
            .seconds_since_last_verification("gitea")
            .await
            .expect("read");
        assert!(age.is_some(), "a successful verification must count");
    }

    #[tokio::test]
    async fn a_fresh_destination_never_masks_a_stale_one() {
        // 🔴 The trap the `destination` column removes. Aggregated across destinations,
        // a NAS backed up every 4 h would make an off-site dead for three weeks look
        // like a 2 h old backup. You would believe 3-2-1 held while only one copy
        // remained, on the same machines.
        let s = State::in_memory().await.expect("state");
        let volume = [backup_kind::VOLUME];

        s.record_backup_to("immich", "volume", "nas", Some("frais"), None)
            .await
            .expect("nas");

        // Anywhere, there is a recent backup...
        assert!(s
            .seconds_since_last_success_of("immich", &volume, None)
            .await
            .expect("anywhere")
            .is_some());

        // ...but the off-site has NEVER received anything, and that must show.
        assert_eq!(
            s.seconds_since_last_success_of("immich", &volume, Some("offsite"))
                .await
                .expect("per destination"),
            None,
            "a destination never served must not inherit another's freshness"
        );

        assert!(s
            .seconds_since_last_success_of("immich", &volume, Some("nas"))
            .await
            .expect("per destination")
            .is_some());
    }

    #[tokio::test]
    async fn a_failed_run_never_counts_as_a_copy() {
        // A failing destination is a configured destination protecting nothing: it must
        // not make the measurement look younger.
        let s = State::in_memory().await.expect("state");
        s.record_backup_to("immich", "volume", "offsite", None, Some("network down"))
            .await
            .expect("failure recorded");

        assert_eq!(
            s.seconds_since_last_success_of("immich", &[backup_kind::VOLUME], Some("offsite"))
                .await
                .expect("per destination"),
            None
        );
    }

    #[tokio::test]
    async fn volumes_are_due_whatever_dumps_ran() {
        // 🔴 Found by review: dumps and SQLite snapshots record a success on every pass,
        // and the volume's due check read any kind — a volume backed up once was never
        // due again, and every screen said "fresh".
        let s = st().await;
        s.record_backup_to("gitea", "volume", "nas", Some("v1"), None)
            .await
            .expect("volume");
        s.backdate_backup("gitea", "nas", 5 * 86_400)
            .await
            .expect("five days ago");
        s.record_backup_to("gitea", "sql-dump", "nas", Some("d1"), None)
            .await
            .expect("dump");
        s.record_backup_to("gitea", "sqlite-snapshot", "nas", Some("q1"), None)
            .await
            .expect("sqlite");

        let volume = s
            .seconds_since_last_success_of("gitea", &[backup_kind::VOLUME], Some("nas"))
            .await
            .expect("age")
            .expect("backed up once");
        assert!(
            volume >= 5 * 86_400,
            "the dump made the volume young: {volume}"
        );
    }

    #[tokio::test]
    async fn an_app_is_as_old_as_the_oldest_of_its_data() {
        // A fresh dump never hides a stale volume, and one kind never backed up makes
        // the app's backup incomplete — not "two minutes old".
        let s = st().await;
        let gitea: Manifest = serde_yaml_ng::from_str(
            "apiVersion: hlb/v1\nkind: App\nmetadata: { name: gitea }\n\
             spec:\n  image: { repo: a/b, tag: \"1\" }\n  \
             requires:\n    - kind: database\n      engine: postgres\n",
        )
        .expect("manifest");
        s.upsert_app("gitea", &gitea, None).await.expect("app");
        s.add_volume("gitea", "gitea-data", "/data", true, false)
            .await
            .expect("volume");
        assert_eq!(
            s.backup_kinds("gitea").await.expect("kinds"),
            [backup_kind::VOLUME, backup_kind::SQL_DUMP]
        );

        s.record_backup_to("gitea", "sql-dump", "nas", Some("d1"), None)
            .await
            .expect("dump");
        assert_eq!(
            s.backup_age("gitea").await.expect("age"),
            None,
            "its files were never backed up"
        );

        s.record_backup_to("gitea", "volume", "nas", Some("v1"), None)
            .await
            .expect("volume");
        s.backdate_backup("gitea", "nas", 3 * 86_400)
            .await
            .expect("three days ago");
        s.record_backup_to("gitea", "sql-dump", "nas", Some("d2"), None)
            .await
            .expect("dump");
        let age = s.backup_age("gitea").await.expect("age").expect("both");
        assert!(age >= 3 * 86_400, "the dump hid the stale volume: {age}");
    }

    #[tokio::test]
    async fn an_app_with_nothing_to_back_up_has_no_backup_kind() {
        // Valkey, LibreSpeed: no volume kept, no database. "Never backed up" would be
        // an alarm nobody can silence.
        let s = st().await;
        s.upsert_app("valkey", &manifest("valkey"), None)
            .await
            .expect("app");
        s.add_volume("valkey", "valkey-cache", "/data", false, false)
            .await
            .expect("a cache");
        assert!(s.backup_kinds("valkey").await.expect("kinds").is_empty());
        assert_eq!(s.backup_age("valkey").await.expect("age"), None);
    }

    #[tokio::test]
    async fn repeated_failures_show_up_before_the_staleness_threshold() {
        // 🔴 Found by running the loop for real: a destination failing on EVERY attempt
        // stays "fresh" until the staleness threshold is crossed - twelve hours at the
        // default interval. The dashboard shows a ✓ for a destination receiving
        // nothing.
        let s = State::in_memory().await.expect("state");

        s.record_backup_to("demo", "volume", "offsite", Some("ok1"), None)
            .await
            .expect("success");
        assert_eq!(
            s.consecutive_failures_on("demo", "offsite").await.unwrap(),
            0
        );

        // ⚠️ These four writes land in the SAME second. That is what broke the first
        // version, which compared timestamps: `datetime('now')` only has one-second
        // resolution. So the ordering comes from the `id`.
        for _ in 0..3 {
            s.record_backup_to("demo", "volume", "offsite", None, Some("unreachable"))
                .await
                .expect("failure");
        }
        assert_eq!(
            s.consecutive_failures_on("demo", "offsite").await.unwrap(),
            3,
            "three failures since the last success"
        );

        // And a new success resets the counter: it counts CONSECUTIVE failures, not a
        // historical total that would never come back down.
        s.record_backup_to("demo", "volume", "offsite", Some("ok2"), None)
            .await
            .expect("success");
        assert_eq!(
            s.consecutive_failures_on("demo", "offsite").await.unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn failures_on_one_destination_do_not_count_for_another() {
        let s = State::in_memory().await.expect("state");
        s.record_backup_to("demo", "volume", "offsite", None, Some("boum"))
            .await
            .expect("failure");
        assert_eq!(s.consecutive_failures_on("demo", "nas").await.unwrap(), 0);
        assert_eq!(
            s.consecutive_failures_on("demo", "offsite").await.unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn a_token_can_target_a_specific_mailbox() {
        // 🔴 The addy.io protocol has NO field for choosing the mailbox: Bitwarden only
        // sends `domain` and `description`. The token is therefore the only place left -
        // one token per mailbox, and changing destination means changing the token in
        // the password manager's settings.
        let s = State::in_memory().await.expect("state");
        s.upsert_user("lena", "standard", None)
            .await
            .expect("account");

        let (_, token) = hlb_types::generate_token(
            "bw-photo",
            hlb_types::Role::Operator,
            [7u8; hlb_types::token::TOKEN_BYTES],
        );
        s.store_token(&token).await.expect("token");
        s.set_token_user("bw-photo", Some("lena"))
            .await
            .expect("rattachement");
        s.set_token_mailbox("bw-photo", Some("photo"))
            .await
            .expect("mailbox");

        assert_eq!(
            s.token_target("bw-photo").await.expect("target"),
            (Some("lena".into()), Some("photo".into()))
        );
    }

    #[tokio::test]
    async fn a_service_token_targets_nobody() {
        // A token with no identity must not act on anyone's behalf: stealing it would
        // otherwise grant the power to create addresses on someone else's mailbox.
        let s = State::in_memory().await.expect("state");
        let (_, token) = hlb_types::generate_token(
            "service",
            // Even as ADMIN: privilege does not substitute for identity.
            hlb_types::Role::Admin,
            [3u8; hlb_types::token::TOKEN_BYTES],
        );
        s.store_token(&token).await.expect("token");

        assert_eq!(
            s.token_target("service").await.expect("target"),
            (None, None)
        );
    }

    #[tokio::test]
    async fn a_token_without_a_mailbox_falls_back_to_the_default_one() {
        // The common case: one token, the default mailbox, nothing to configure.
        let s = State::in_memory().await.expect("state");
        s.upsert_user("lena", "standard", None)
            .await
            .expect("account");
        let (_, token) = hlb_types::generate_token(
            "bw",
            hlb_types::Role::Operator,
            [9u8; hlb_types::token::TOKEN_BYTES],
        );
        s.store_token(&token).await.expect("token");
        s.set_token_user("bw", Some("lena"))
            .await
            .expect("rattachement");

        let (u, b) = s.token_target("bw").await.expect("target");
        assert_eq!(u.as_deref(), Some("lena"));
        assert!(b.is_none(), "no mailbox targeted means the default one");
    }

    #[tokio::test]
    async fn a_route_replaces_instead_of_accumulating() {
        // Adding would grow the routing on every call, and you would end up sending
        // terabytes to a destination you believed removed.
        let s = State::in_memory().await.expect("state");
        s.upsert_destination("nas", "/mnt/nas", "critical,bulky", None)
            .await
            .expect("nas");
        s.upsert_destination("offsite", "s3:https://x/y", "critical", None)
            .await
            .expect("offsite");

        s.set_route("immich", "bulky", &["nas".into(), "offsite".into()])
            .await
            .expect("route");
        assert_eq!(s.route("immich", "bulky").await.unwrap().len(), 2);

        s.set_route("immich", "bulky", &["nas".into()])
            .await
            .expect("narrowed route");
        assert_eq!(
            s.route("immich", "bulky").await.unwrap(),
            vec!["nas".to_string()],
            "the new route REPLACES, it does not add to the old one"
        );
    }

    #[tokio::test]
    async fn sqlite_volumes_are_listed_apart() {
        // 🔴 A SQLite volume cannot be backed up by copying files: the main file and
        // its WAL would be captured at different instants, and the restored database
        // would be corrupt with nothing having flagged it.
        let s = st().await;
        s.upsert_app("pocket-id", &manifest("pocket-id"), None)
            .await
            .expect("upsert");
        s.add_volume("pocket-id", "pid-data", "/mnt/pid", true, true)
            .await
            .expect("volume");
        s.add_volume("pocket-id", "pid-cache", "/mnt/cache", false, true)
            .await
            .expect("volume");
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("upsert");
        s.add_volume("gitea", "g-data", "/mnt/g", true, false)
            .await
            .expect("volume");

        let v = s.sqlite_volumes().await.expect("read");
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].1, "pid-data");
        // An unbacked-up SQLite volume needs no snapshot.
        assert!(!v.iter().any(|(_, n, _)| n == "pid-cache"));
    }

    #[tokio::test]
    async fn databases_come_from_the_frozen_manifest() {
        // 🔴 The FROZEN manifest, not today's catalog. An app installed six months ago
        // must be backed up according to what it asked for then; a catalog that had
        // renamed the database would back up nothing.
        let s = st().await;
        let y = "apiVersion: hlb/v1\nkind: App\nmetadata: { name: gitea }\n\
                 spec:\n  image: { repo: a/b, tag: \"1\" }\n\
                 \x20 requires:\n    - kind: database\n      engine: postgres\n";
        let m: Manifest = serde_yaml_ng::from_str(y).expect("manifest");
        s.upsert_app("gitea", &m, None).await.expect("upsert");
        s.set_app_status("gitea", "running").await.expect("status");

        let d = s.app_databases().await.expect("read");
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].0, "gitea");
        assert_eq!(d[0].1, "postgres");
        // With no explicit name, the database carries the app's name - the SAME
        // convention as the resolver. The two must stay aligned.
        assert_eq!(d[0].2, "gitea");
        assert_eq!(d[0].3, "gitea-db-password");
    }

    #[tokio::test]
    async fn an_app_without_a_database_is_not_listed() {
        let s = st().await;
        s.upsert_app("statique", &manifest("statique"), None)
            .await
            .expect("upsert");
        s.set_app_status("statique", "running")
            .await
            .expect("status");
        assert!(s.app_databases().await.expect("read").is_empty());
    }

    #[tokio::test]
    async fn a_failed_app_is_skipped() {
        // Its database has probably never been provisioned: backing it up would
        // produce a failure on every loop pass, for nothing.
        let s = st().await;
        let y = "apiVersion: hlb/v1\nkind: App\nmetadata: { name: casse }\n\
                 spec:\n  image: { repo: a/b, tag: \"1\" }\n\
                 \x20 requires:\n    - kind: database\n      engine: postgres\n";
        let m: Manifest = serde_yaml_ng::from_str(y).expect("manifest");
        s.upsert_app("casse", &m, None).await.expect("upsert");
        s.set_app_status("casse", "failed").await.expect("status");
        assert!(s.app_databases().await.expect("read").is_empty());
    }

    #[tokio::test]
    async fn base_backups_exclude_failures_and_other_kinds() {
        // 🔴 A failed base backup restores nothing. Counting it would widen the
        // announced PITR window by a guarantee we do not have.
        let s = st().await;
        s.record_backup("postgres", "pg-basebackup", Some("base-1"), None)
            .await
            .expect("success");
        s.record_backup("postgres", "pg-basebackup", None, Some("disk full"))
            .await
            .expect("failure");
        // A volume snapshot is not a starting point for a WAL replay.
        s.record_backup("postgres", "volume", Some("vol-9"), None)
            .await
            .expect("volume");

        let b = s.base_backups("postgres").await.expect("read");
        assert_eq!(b.len(), 1, "{b:?}");
        assert_eq!(b[0].0, "base-1");
        assert!(b[0].1 > 0, "horodatage exploitable");
    }

    #[tokio::test]
    async fn base_backups_come_oldest_first() {
        // Order matters: the WAL purge bound is the OLDEST base backup.
        let s = st().await;
        for id in ["b1", "b2", "b3"] {
            s.record_backup("postgres", "pg-basebackup", Some(id), None)
                .await
                .expect("base");
        }
        let b = s.base_backups("postgres").await.expect("read");
        assert_eq!(
            b.iter().map(|(i, _)| i.as_str()).collect::<Vec<_>>(),
            ["b1", "b2", "b3"]
        );
    }

    #[tokio::test]
    async fn a_failed_drill_does_not_reset_the_clock() {
        // 🔴 A failed drill proves NOTHING about the ability to restore. Counting it
        // would show a procedure "exercised last month" when it had failed - the
        // opposite of what needs to be known.
        let s = st().await;
        s.record_drill("postgres", false, Some(0), 12, "base empty")
            .await
            .expect("failure recorded");

        assert_eq!(
            s.days_since_successful_drill().await.expect("read"),
            None,
            "a failure must not count as a successful drill"
        );

        // But it stays VISIBLE: that is the most useful information.
        let v = s.recent_drills(10).await.expect("read");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].2, "failed");
    }

    #[tokio::test]
    async fn a_successful_drill_starts_the_clock() {
        let s = st().await;
        s.record_drill("postgres", true, Some(14), 30, "")
            .await
            .expect("success");
        assert_eq!(
            s.days_since_successful_drill().await.expect("read"),
            Some(0)
        );
    }

    #[tokio::test]
    async fn the_schema_can_actually_go_back() {
        // 🔴 Writing a `down` proves nothing: running it is what proves the rollback
        // works. Without this test, a broken `down` would be discovered at the worst
        // moment - during a rollback, after a failed update.
        let s = st().await;
        let before = s
            .schema_version()
            .await
            .expect("version")
            .expect("migrated");
        assert!(before >= 6, "every migration must be applied: {before}");

        // Roll back to before the audit-log migration.
        s.undo_migrations(4).await.expect("rollback");
        assert_eq!(s.schema_version().await.expect("version"), Some(4));

        // And the table in question is indeed gone: the `down` did its job.
        let exists: Option<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'",
        )
        .fetch_optional(&s.pool)
        .await
        .expect("read");
        assert!(exists.is_none(), "audit_log should have been dropped");
    }

    #[tokio::test]
    async fn each_level_and_profile_held_becomes_one_role_and_nobody_moves() {
        // The upgrade from levels and profiles: every account keeps its level and its
        // limits, an open invitation still grants what it said, an installed app lets
        // in whoever it did — and the audit log is not touched.
        let s = st().await;
        s.undo_migrations(34).await.expect("back to before roles");
        for q in [
            "INSERT INTO users (name, profile) VALUES ('lena', 'unlimited'),
                 ('camille', 'standard'), ('sacha', 'GUEST'), ('dominique', 'standard')",
            "INSERT INTO user_roles (user, role, granted_by) VALUES
                 ('lena', 'admin', 'bootstrap'), ('camille', 'operateur', 'lena')",
            "INSERT INTO invitations (fingerprint, created_by, profile, role, created_at,
                 expires_at) VALUES ('f-open', 'lena', 'guest', 'viewer', 0, 9999999999),
                 ('f-closed', 'lena', 'unlimited', 'admin', 0, 1)",
            "INSERT INTO apps (name, manifest, status) VALUES
                 ('gitea', 'requires:\n- kind: sso\n  mode: native\n', 'running'),
                 ('postgres', 'requires: []\n', 'running')",
        ] {
            sqlx::query(q).execute(&s.pool).await.expect(q);
        }
        s.audit(
            "lena",
            hlb_types::Role::Admin,
            "operate",
            "gitea",
            "ok",
            None,
        )
        .await
        .expect("an entry");

        sqlx::migrate!("./migrations")
            .run(&s.pool)
            .await
            .expect("apply 0035");

        let ids: Vec<String> = s
            .roles()
            .await
            .expect("roles")
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(
            ids,
            [
                "admin-unlimited",
                "guest",
                "operator-standard",
                "standard",
                "viewer-guest"
            ],
            "the closed invitation's pair is history, not a role"
        );
        let mut held = Vec::new();
        for who in ["lena", "camille", "sacha"] {
            let r = s.role_of(who).await.expect("role");
            held.push((r.id, r.level));
        }
        assert_eq!(
            held,
            [
                ("admin-unlimited".into(), hlb_types::Role::Admin),
                // The French spelling, read as it always was.
                ("operator-standard".into(), hlb_types::Role::Operator),
                ("guest".into(), hlb_types::Role::User),
            ]
        );
        assert_eq!(
            s.role("guest").await.expect("role").expect("exists").mail,
            hlb_users::MailLimits::guest()
        );
        let lena = &s.users_with_roles().await.expect("holders")[2];
        assert_eq!(lena.granted_by.as_deref(), Some("bootstrap"));
        let open: String = sqlx::query("SELECT role FROM invitations WHERE fingerprint = 'f-open'")
            .fetch_one(&s.pool)
            .await
            .expect("invitation")
            .get("role");
        assert_eq!(
            open, "viewer-guest",
            "the open link still grants what it said"
        );
        assert_eq!(
            s.app_roles().await.expect("allowed")["gitea"].len(),
            5,
            "gitea lets in every role, as it let in everyone"
        );
        assert!(!s
            .app_roles()
            .await
            .expect("allowed")
            .contains_key("postgres"));
        assert!(
            matches!(
                s.verify_audit_chain().await.expect("chain"),
                AuditIntegrity::Intact { verified: 1, .. }
            ),
            "the audit log is not rewritten"
        );
    }

    #[tokio::test]
    async fn uptime_recorded_in_french_still_reads_after_the_rename() {
        // The mapping writes and reads these words by hand, so a rename without 0025
        // fails in silence: the samples already stored stop parsing, and the status
        // page draws every day before the upgrade as missing history.
        let s = st().await;
        s.undo_migrations(24)
            .await
            .expect("back to before the rename");
        for state in ["operationnel", "degrade"] {
            sqlx::query("INSERT INTO service_uptime_samples (service, state) VALUES ('gitea', ?1)")
                .bind(state)
                .execute(&s.pool)
                .await
                .expect("an old sample");
        }

        sqlx::migrate!("./migrations")
            .run(&s.pool)
            .await
            .expect("apply 0025");

        let today = s.uptime_history("gitea", 1).await.expect("history");
        assert_eq!(
            today[0].1,
            Some(hlb_api::ServiceState::Degraded),
            "the worst of the two old samples, read back: {today:?}"
        );
    }

    #[tokio::test]
    async fn a_safeguard_attested_under_its_french_id_stays_attested() {
        // Renamed in the code alone, the ids would leave every attestation behind under
        // the old name: the recovery screen red again for checks already done. And the
        // audit log, which holds French words of its own, must come out untouched — its
        // chain covers them.
        let s = st().await;
        s.undo_migrations(25)
            .await
            .expect("back to before the rename");
        for id in ["codes-imprimes", "deux-passkeys", "pocketid-restaure"] {
            s.attest_breakglass(id, "lena", None).await.expect("attest");
            s.audit(
                "anonyme",
                hlb_types::Role::Admin,
                "breakglass-attest",
                id,
                "ok",
                None,
            )
            .await
            .expect("audit");
        }

        sqlx::migrate!("./migrations")
            .run(&s.pool)
            .await
            .expect("apply 0026");

        let mut ids: Vec<String> = s
            .breakglass()
            .await
            .expect("attestations")
            .into_iter()
            .map(|(id, _, _)| id)
            .collect();
        ids.sort();
        assert_eq!(ids, ["pocketid-restored", "printed-codes", "two-passkeys"]);
        assert!(
            s.verify_audit_chain()
                .await
                .expect("verification")
                .is_intact(),
            "the migration touched a chained entry"
        );
    }

    #[tokio::test]
    async fn renaming_a_guide_id_keeps_the_work_already_verified() {
        // 🔴 The rename that motivated migration 0024 is a SILENT REGRESSION without it.
        // `pending_guides` is keyed on (app, id) and nothing deletes a row: `add_guide`
        // upserts, so a renamed id leaves the verified row behind under the old name and
        // inserts a fresh, UNVERIFIED one. Both of n8n's steps are `blocking` and the
        // manifest exposes it `after-guide`, so the failure is not cosmetic: an owner who
        // did the work months ago would find the public route shut again, and the guide
        // asking for the same two things a second time.
        let s = st().await;
        s.undo_migrations(23)
            .await
            .expect("back to before the rename");

        // An installation that did the work, under the French ids.
        s.upsert_app("n8n", &manifest("n8n"), None)
            .await
            .expect("app");
        // Written as the schema of that time takes it: `add_guide` and `verify_guide` touch
        // what was added since.
        sqlx::query(
            "INSERT INTO pending_guides (id, app, title, blocking)
             VALUES ('cle-de-chiffrement', 'n8n', 'Back up the encryption key', 1)",
        )
        .execute(&s.pool)
        .await
        .expect("guide");
        let handled = sqlx::query(
            "UPDATE pending_guides SET verified_at = datetime('now')
             WHERE app = 'n8n' AND id = 'cle-de-chiffrement'",
        )
        .execute(&s.pool)
        .await
        .expect("verify");
        assert_eq!(
            handled.rows_affected(),
            1,
            "the fixture must start from a step that was actually handled"
        );
        assert_eq!(s.unverified_blocking("n8n").await.expect("count"), 0);

        sqlx::migrate!("./migrations")
            .run(&s.pool)
            .await
            .expect("apply 0024");

        assert_eq!(
            s.unverified_blocking("n8n").await.expect("count"),
            0,
            "the rename re-opened a blocking action that had already been verified"
        );

        // The row MOVED. A second one under the new id would mean it was re-created,
        // which is the same defect wearing a different count.
        let ids: Vec<String> =
            sqlx::query_scalar("SELECT id FROM pending_guides WHERE app = 'n8n'")
                .fetch_all(&s.pool)
                .await
                .expect("read");
        assert_eq!(ids, vec!["encryption-key".to_string()]);
    }

    #[tokio::test]
    async fn going_back_then_forward_works() {
        // The full cycle: what happens when a rollback is followed by another update
        // attempt.
        let s = st().await;
        s.undo_migrations(3).await.expect("return_to");
        assert_eq!(s.schema_version().await.expect("v"), Some(3));

        sqlx::migrate!("./migrations")
            .run(&s.pool)
            .await
            .expect("reapplication");
        assert!(s.schema_version().await.expect("v").expect("v") >= 6);

        // And the state stays usable after the round trip.
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("the database must stay functional");
    }

    #[test]
    fn every_migration_in_the_directory_is_shipped_and_named_by_its_file() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut files: Vec<String> = std::fs::read_dir(&dir)
            .expect("migrations directory")
            .filter_map(|e| {
                let name = e.expect("entry").file_name().to_string_lossy().to_string();
                name.strip_suffix(".up.sql").map(str::to_string)
            })
            .collect();
        files.sort();
        let shipped = State::shipped_migrations();
        let names: Vec<String> = shipped.iter().map(|m| m.name.clone()).collect();
        assert!(files.len() > 40, "only {} migrations found", files.len());
        assert_eq!(names, files);
        assert!(shipped.iter().all(|m| m.reversible));
    }

    #[test]
    fn every_migration_can_be_undone() {
        // 🔴 The condition that unblocks every update. Without a `down`, a failure of
        // version N+1 leaves the database in a state binary N does not understand - and
        // there is no way out. `hlb self update` REFUSES to start when this rule is
        // violated; this test catches it earlier.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut ups = Vec::new();
        let mut downs = Vec::new();

        for e in std::fs::read_dir(&dir).expect("migrations directory") {
            let name = e.expect("entry").file_name().to_string_lossy().to_string();
            if let Some(base) = name.strip_suffix(".up.sql") {
                ups.push(base.to_string());
            } else if let Some(base) = name.strip_suffix(".down.sql") {
                downs.push(base.to_string());
            } else {
                panic!("\"{name}\": a migration must be .up.sql or .down.sql");
            }
        }

        ups.sort();
        downs.sort();
        assert!(!ups.is_empty(), "no migration found");
        assert_eq!(
            ups, downs,
            "every migration must have its inverse - otherwise no update is \
             possible"
        );
    }

    #[tokio::test]
    async fn migrations_run_on_open() {
        let s = st().await;
        assert!(s.installed_apps().await.expect("read").is_empty());
    }

    #[tokio::test]
    async fn manifest_is_frozen_at_deploy_time() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), Some("git.x.fr"))
            .await
            .expect("upsert");

        let stored = s.app_manifest("gitea").await.expect("reread");
        assert_eq!(stored.metadata.name, "gitea");
        assert_eq!(stored.spec.image.tag, "1");
    }

    #[tokio::test]
    async fn the_guide_is_frozen_beside_the_manifest_and_kept_by_a_digest_pin() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("upsert");
        assert!(
            s.app_guide("gitea").await.expect("read").is_none(),
            "nothing frozen yet reads as the catalog's"
        );

        let guide: Guide = serde_yaml_ng::from_str(
            r#"
steps:
  - id: dns
    title: Create the DNS record
"#,
        )
        .expect("guide");
        s.set_app_guide("gitea", Some(&guide))
            .await
            .expect("freeze");
        // A digest pinned later freezes the manifest again, and must not drop the guide.
        s.set_app_digest("gitea", "sha256:abc").await.expect("pin");
        let read = s.app_guide("gitea").await.expect("read").expect("frozen");
        assert_eq!(read.steps, guide.steps);

        s.set_app_guide("gitea", None).await.expect("put back");
        assert!(s.app_guide("gitea").await.expect("read").is_none());
        assert!(matches!(
            s.set_app_guide("absent", Some(&guide)).await,
            Err(Error::UnknownApp(_))
        ));
    }

    #[tokio::test]
    async fn unknown_app_is_reported() {
        let err = st().await.app_manifest("does-not-exist").await.unwrap_err();
        assert!(matches!(err, Error::UnknownApp(_)), "{err}");
    }

    #[tokio::test]
    async fn completed_actions_survive_a_replan() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();

        let plan = vec![
            ("Deploy".to_string(), "deploy gitea".to_string()),
            ("Wait".to_string(), "attendre gitea".to_string()),
        ];
        s.record_plan("gitea", &plan).await.expect("plan");
        s.set_action_status("gitea", 0, ActionStatus::Done, None)
            .await
            .expect("status");

        // Replanning: the action already done must not go back to pending.
        s.record_plan("gitea", &plan).await.expect("replan");

        let done = s.completed_seqs("gitea").await.expect("read");
        assert_eq!(
            done,
            vec![0],
            "a summary must not replay what is already done"
        );
    }

    #[tokio::test]
    async fn a_plan_is_finished_only_when_every_action_is_done() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        assert!(
            !s.plan_finished("gitea").await.expect("read"),
            "never started"
        );
        let plan = vec![
            ("Deploy".to_string(), "deploy gitea".to_string()),
            ("Wait".to_string(), "wait for gitea".to_string()),
        ];
        s.record_plan("gitea", &plan).await.expect("plan");
        s.set_action_status("gitea", 0, ActionStatus::Done, None)
            .await
            .expect("status");
        s.set_action_status("gitea", 1, ActionStatus::Unimplemented, None)
            .await
            .expect("status");
        assert!(!s.plan_finished("gitea").await.expect("read"));
        s.set_action_status("gitea", 1, ActionStatus::Done, None)
            .await
            .expect("status");
        assert!(s.plan_finished("gitea").await.expect("read"));
    }

    #[tokio::test]
    async fn a_route_published_later_completes_the_app_it_left_partial() {
        let s = st().await;
        for app in ["gitea", "vikunja"] {
            s.upsert_app(app, &manifest(app), None).await.expect("app");
            let plan = vec![
                ("DeployService".to_string(), format!("deploy {app}")),
                ("ConfigureIngress".to_string(), format!("route {app}")),
            ];
            s.record_plan(app, &plan).await.expect("plan");
            s.set_action_status(app, 0, ActionStatus::Done, None)
                .await
                .expect("status");
            s.set_action_status(app, 1, ActionStatus::Unimplemented, None)
                .await
                .expect("status");
            s.set_app_status(app, "partial").await.expect("status");
        }
        // vikunja still lacks something else: it must stay partial.
        s.record_plan(
            "vikunja",
            &[
                ("DeployService".into(), "deploy vikunja".into()),
                ("ConfigureIngress".into(), "route vikunja".into()),
                ("CreateDatabase".into(), "db".into()),
            ],
        )
        .await
        .expect("plan");
        s.set_action_status("vikunja", 2, ActionStatus::Unimplemented, None)
            .await
            .expect("status");

        let done = s
            .complete_unimplemented("ConfigureIngress", &["gitea".into(), "vikunja".into()])
            .await
            .expect("complete");
        assert_eq!(done, vec!["gitea", "vikunja"]);
        let status: std::collections::HashMap<_, _> = s
            .installed_apps()
            .await
            .expect("apps")
            .into_iter()
            .collect();
        assert_eq!(status["gitea"], "running");
        assert_eq!(
            status["vikunja"], "partial",
            "its database is still missing"
        );
    }

    #[tokio::test]
    async fn a_route_is_completed_only_for_the_apps_it_was_published_for() {
        // 🔴 A route withheld — its chain gone from hlb — or left out with a failed install was
        // marked done with the others, and never asked for again.
        let s = st().await;
        for app in ["gitea", "vikunja"] {
            s.upsert_app(app, &manifest(app), None).await.expect("app");
            s.record_plan(app, &[("ConfigureIngress".into(), format!("route {app}"))])
                .await
                .expect("plan");
            s.set_action_status(app, 0, ActionStatus::Unimplemented, None)
                .await
                .expect("status");
            s.set_app_status(app, "partial").await.expect("status");
        }
        let done = s
            .complete_unimplemented("ConfigureIngress", &["gitea".into()])
            .await
            .expect("complete");
        assert_eq!(done, vec!["gitea"]);
        let vikunja = s.plan_actions("vikunja").await.expect("journal");
        assert_eq!(vikunja[0].status, ActionStatus::Unimplemented);
        let status: std::collections::HashMap<_, _> = s
            .installed_apps()
            .await
            .expect("apps")
            .into_iter()
            .collect();
        assert_eq!(status["vikunja"], "partial");
    }

    #[tokio::test]
    async fn an_action_inserted_mid_plan_is_not_taken_for_the_one_done_there() {
        // 🔴 Matched by position, the new action sat on a done row and was skipped,
        // and the one it pushed down inherited its neighbour's status.
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        let a = (
            "GenerateSecret".to_string(),
            "generate secret a".to_string(),
        );
        let b = ("DeployService".to_string(), "deploy gitea".to_string());
        let x = (
            "ProvisionDatabase".to_string(),
            "create database".to_string(),
        );
        s.record_plan("gitea", &[a.clone(), b.clone()])
            .await
            .expect("plan");
        for seq in [0, 1] {
            s.set_action_status("gitea", seq, ActionStatus::Done, None)
                .await
                .expect("done");
        }

        let next = [a.clone(), x.clone(), b.clone()];
        assert_eq!(
            s.completed_actions("gitea", &next).await.expect("read"),
            vec![true, false, true],
            "the inserted action is to run, the moved one stays done"
        );
        s.record_plan("gitea", &next).await.expect("replan");
        let journal = s.plan_actions("gitea").await.expect("journal");
        let said: Vec<_> = journal
            .iter()
            .map(|r| (r.description.as_str(), r.status))
            .collect();
        assert_eq!(
            said,
            vec![
                ("generate secret a", ActionStatus::Done),
                ("create database", ActionStatus::Pending),
                ("deploy gitea", ActionStatus::Done),
            ]
        );
        assert_eq!(s.completed_seqs("gitea").await.expect("read"), vec![0, 2]);

        // A different action at a done row's position is not done either.
        let other = [
            a,
            ("DeployService".to_string(), "deploy gitea ×2".to_string()),
        ];
        assert_eq!(
            s.completed_actions("gitea", &other).await.expect("read"),
            vec![true, false]
        );
    }

    #[tokio::test]
    async fn a_step_made_blocking_since_blocks() {
        // 🔴 The conflict kept the title only: a step the guide made blocking stayed
        // non-blocking, and its `after-guide` route opened before anyone did it.
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        s.add_guide("gitea", "sign-ups", "Close sign-ups", false)
            .await
            .expect("guide");
        assert_eq!(s.unverified_blocking("gitea").await.expect("read"), 0);
        s.add_guide("gitea", "sign-ups", "Close the sign-ups", true)
            .await
            .expect("guide");
        assert_eq!(s.unverified_blocking("gitea").await.expect("read"), 1);
        assert!(s.verified_guides("gitea").await.expect("read").is_empty());
        s.verify_guide("gitea", "sign-ups").await.expect("verify");
        assert_eq!(
            s.verified_guides("gitea").await.expect("read"),
            vec!["sign-ups"]
        );
    }

    #[tokio::test]
    async fn the_choices_made_after_the_manifest_are_kept_beside_it() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), Some("git.example.org"))
            .await
            .expect("app");
        assert_eq!(s.app_replicas("gitea").await.expect("read"), None);
        assert_eq!(s.app_mail_domain("gitea").await.expect("read"), None);
        assert!(s.set_app_replicas("gitea", Some(0)).await.expect("stop"));
        s.set_app_mail_domain("gitea", Some("example.org"))
            .await
            .expect("mail");
        // A manifest frozen again — an upgrade — keeps both.
        s.upsert_app("gitea", &manifest("gitea"), Some("git.example.org"))
            .await
            .expect("upgrade");
        assert_eq!(s.app_replicas("gitea").await.expect("read"), Some(0));
        assert_eq!(
            s.app_mail_domain("gitea").await.expect("read").as_deref(),
            Some("example.org")
        );
        assert!(s.set_app_replicas("gitea", None).await.expect("back"));
        assert_eq!(s.app_replicas("gitea").await.expect("read"), None);
        assert!(!s.set_app_replicas("absent", Some(1)).await.expect("absent"));
    }

    #[tokio::test]
    async fn the_exposure_is_absent_until_set_and_read_back_whole() {
        let s = st().await;
        assert_eq!(s.exposure().await.expect("read"), None);
        let e = Exposure {
            domain: "example.org".into(),
            certificates: Certificates::Acme,
            acme_email: Some("me@example.org".into()),
            dns_provider: Some("ovh".into()),
            staging: true,
            controller_host: None,
            acme_ca: Some("https://ca.home/acme/directory".into()),
            acme_ca_root: Some("-----BEGIN CERTIFICATE-----".into()),
        };
        s.set_exposure(&e).await.expect("set");
        assert_eq!(s.exposure().await.expect("read"), Some(e.clone()));
        assert_eq!(e.controller_host(), "hlb.example.org");
        assert_eq!(e.default_domain("gitea"), "gitea.example.org");
    }

    #[tokio::test]
    async fn shorter_plan_drops_stale_actions() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();

        let long = vec![
            ("A".to_string(), "a".to_string()),
            ("B".to_string(), "b".to_string()),
            ("C".to_string(), "c".to_string()),
        ];
        s.record_plan("gitea", &long).await.unwrap();
        assert_eq!(s.plan_actions("gitea").await.unwrap().len(), 3);

        s.record_plan("gitea", &long[..1]).await.unwrap();
        assert_eq!(s.plan_actions("gitea").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn failure_is_recorded_with_its_message() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();
        s.record_plan("gitea", &[("Deploy".into(), "deploy".into())])
            .await
            .unwrap();

        s.set_action_status("gitea", 0, ActionStatus::Failed, Some("image absent"))
            .await
            .unwrap();

        let a = &s.plan_actions("gitea").await.unwrap()[0];
        assert_eq!(a.status, ActionStatus::Failed);
        assert_eq!(a.error.as_deref(), Some("image absent"));
        // A failure is not terminal: it gets replayed on summary.
        assert!(!a.status.is_terminal());
    }

    #[tokio::test]
    async fn a_secret_is_never_silently_regenerated() {
        // A password already injected into a service must not change under its feet.
        let s = st().await;
        assert!(s
            .store_secret_if_absent("db-pw", b"chiffre-1", "base")
            .await
            .unwrap());
        assert!(!s
            .store_secret_if_absent("db-pw", b"chiffre-2", "base")
            .await
            .unwrap());
        assert_eq!(
            s.secret("db-pw").await.unwrap().as_deref(),
            Some(&b"chiffre-1"[..])
        );
    }

    #[tokio::test]
    async fn rotation_replaces_the_value() {
        let s = st().await;
        s.store_secret_if_absent("db-pw", b"old", "base")
            .await
            .unwrap();
        s.rotate_secret("db-pw", b"new_one").await.unwrap();
        assert_eq!(
            s.secret("db-pw").await.unwrap().as_deref(),
            Some(&b"new_one"[..])
        );
    }

    #[tokio::test]
    async fn a_rekey_rewrites_every_secret_or_none() {
        // 🔴 Atomic on purpose. Half a vault under a new key and half under the old is
        // unrecoverable by hand: nothing in a ciphertext says which key opens it.
        let s = st().await;
        s.store_secret_if_absent("a", b"old-a", "x").await.unwrap();
        s.store_secret_if_absent("b", b"old-b", "x").await.unwrap();

        let all = s.all_ciphertexts().await.unwrap();
        assert_eq!(all.len(), 2);

        let rewritten: Vec<(String, Vec<u8>, Vec<u8>)> = all
            .iter()
            .map(|(n, ct)| (n.clone(), ct.clone(), format!("new-{n}").into_bytes()))
            .collect();
        s.rewrite_ciphertexts(&rewritten).await.unwrap();

        assert_eq!(s.secret("a").await.unwrap().as_deref(), Some(&b"new-a"[..]));
        assert_eq!(s.secret("b").await.unwrap().as_deref(), Some(&b"new-b"[..]));
    }

    #[tokio::test]
    async fn a_refused_route_leaves_the_previous_one_in_place() {
        // 🔴 Found by review: `set_route` deleted, then inserted outside a transaction.
        // A destination refused halfway left the class routed to part of what was asked
        // — and nowhere it had been.
        let s = st().await;
        s.upsert_destination("nas", "/mnt/nas", "critical", None)
            .await
            .unwrap();
        s.upsert_destination("offsite", "/mnt/off", "critical", None)
            .await
            .unwrap();
        s.set_route("gitea", "critical", &["nas".into()])
            .await
            .unwrap();

        let asked = ["offsite".to_string(), "ghost".to_string()];
        assert!(s.set_route("gitea", "critical", &asked).await.is_err());
        assert_eq!(s.route("gitea", "critical").await.unwrap(), vec!["nas"]);

        let critical = ["offsite".to_string()];
        let bulky = ["ghost".to_string()];
        let both: [(&str, &[String]); 2] = [("critical", &critical), ("bulky", &bulky)];
        assert!(s.set_routes("gitea", &both).await.is_err());
        assert_eq!(s.route("gitea", "critical").await.unwrap(), vec!["nas"]);
    }

    #[tokio::test]
    async fn a_rekey_refuses_a_vault_written_since_it_was_read() {
        // 🔴 Found by review: `secrets-rekey` raced the running controller. A secret
        // stored between the reading and the rewrite stayed under the old key, and one
        // rotated meanwhile was put back to its old value.
        let s = st().await;
        s.store_secret_if_absent("a", b"old-a", "x").await.unwrap();
        let all = s.all_ciphertexts().await.unwrap();
        let rewritten: Vec<(String, Vec<u8>, Vec<u8>)> = all
            .iter()
            .map(|(n, ct)| (n.clone(), ct.clone(), b"new".to_vec()))
            .collect();

        s.store_secret_if_absent("b", b"old-b", "x").await.unwrap();
        let added = s.rewrite_ciphertexts(&rewritten).await;
        assert!(
            matches!(added, Err(Error::VaultChanged(ref n)) if n == "b"),
            "{added:?}"
        );

        s.rotate_secret("a", b"rotated").await.unwrap();
        let mut both = rewritten.clone();
        both.push(("b".into(), b"old-b".to_vec(), b"new".to_vec()));
        let rotated = s.rewrite_ciphertexts(&both).await;
        assert!(
            matches!(rotated, Err(Error::VaultChanged(ref n)) if n == "a"),
            "{rotated:?}"
        );
        assert_eq!(
            s.secret("a").await.unwrap().as_deref(),
            Some(&b"rotated"[..])
        );
    }

    #[tokio::test]
    async fn two_processes_auditing_at_once_lose_no_entry() {
        // 🔴 Found by review: `audit()` said immediate and opened a deferred
        // transaction. The CLI and the controller each hold their own connection; with
        // a deferred one the second writer failed "database is locked" at once.
        let path = std::env::temp_dir().join(format!(
            "hlb-audit-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let cli = State::open(&path).await.unwrap();
        let controller = State::open(&path).await.unwrap();
        let write = |s: State, who: &'static str| async move {
            let mut failed = 0;
            for i in 0..40 {
                let r = s
                    .audit(who, hlb_types::Role::Admin, "x", &i.to_string(), "ok", None)
                    .await;
                failed += usize::from(r.is_err());
            }
            failed
        };
        let (a, b) = tokio::join!(
            tokio::spawn(write(cli.clone(), "cli")),
            tokio::spawn(write(controller.clone(), "controller"))
        );
        let failed = a.unwrap() + b.unwrap();
        assert_eq!(failed, 0, "entries lost to a lock");
        assert_eq!(cli.audit_trail(1000).await.unwrap().len(), 80);
        assert!(matches!(
            cli.verify_audit_chain().await.unwrap(),
            AuditIntegrity::Intact { verified: 80, .. }
        ));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[tokio::test]
    async fn a_reader_sees_the_writer_live_and_cannot_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hlb.db");
        let empty = dir.path().join("empty.db");
        std::fs::write(&empty, b"").unwrap();
        assert!(
            matches!(
                State::open_read_only(&empty).await,
                Err(Error::NotMigrated { applied: 0, .. })
            ),
            "a database nobody migrated is read with its tables missing"
        );
        assert!(
            State::open_read_only(dir.path().join("absent.db"))
                .await
                .is_err(),
            "a reader created the database"
        );
        assert!(!dir.path().join("absent.db").exists());

        let daemon = State::open(&path).await.unwrap();
        let web = State::open_read_only(&path).await.unwrap();
        daemon
            .audit("a", hlb_types::Role::Admin, "x", "y", "ok", None)
            .await
            .unwrap();
        assert_eq!(web.audit_trail(10).await.unwrap().len(), 1);
        assert!(
            web.audit("web", hlb_types::Role::Admin, "x", "y", "ok", None)
                .await
                .is_err(),
            "the reader wrote"
        );
        daemon
            .audit("b", hlb_types::Role::Admin, "x", "y", "ok", None)
            .await
            .unwrap();
        assert_eq!(web.audit_trail(10).await.unwrap().len(), 2, "not live");
    }

    #[tokio::test]
    async fn a_rekey_is_not_a_rotation() {
        // 🔴 Re-encrypting does NOT change the value: the age that says "this password
        // has not been changed in a year" must keep counting from the real rotation.
        // Bumping it here would make every secret look freshly rotated, and the screen
        // that asks you to rotate them would go quiet.
        let s = st().await;
        s.store_secret_if_absent("a", b"old", "x").await.unwrap();
        s.rotate_secret("a", b"rotated").await.unwrap();

        let before = s.secrets_ages().await.unwrap();
        let (_, _, _, never_rotated_before) = before[0].clone();

        let read = s.secret("a").await.unwrap().expect("stored");
        s.rewrite_ciphertexts(&[("a".to_string(), read, b"re-encrypted".to_vec())])
            .await
            .unwrap();

        let after = s.secrets_ages().await.unwrap();
        let (_, _, _, never_rotated_after) = after[0].clone();
        assert_eq!(
            never_rotated_before, never_rotated_after,
            "a rekey must not look like a rotation"
        );
    }

    #[tokio::test]
    async fn inventory_never_exposes_values() {
        let s = st().await;
        s.store_secret_if_absent("db-pw", b"tres-secret", "base gitea")
            .await
            .unwrap();
        let inv = s.secret_names().await.unwrap();
        assert_eq!(inv, vec![("db-pw".to_string(), "base gitea".to_string())]);
    }

    #[tokio::test]
    async fn missing_secret_is_none_not_an_error() {
        assert!(st().await.secret("does-not-exist").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn blocking_guides_come_first() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();
        s.add_guide("gitea", "tip", "a tip", false).await.unwrap();
        s.add_guide("gitea", "admin", "create the admin", true)
            .await
            .unwrap();

        let g = s.pending_guides().await.unwrap();
        assert_eq!(g.len(), 2);
        assert!(g[0].3, "the blocking ones first");
        assert_eq!(g[0].1, "admin");
    }

    // -----------------------------------------------------------------------
    // Sessions, roles and log integrity
    // -----------------------------------------------------------------------

    /// An account, a prerequisite for any session (the table has a foreign key).
    async fn with_account(s: &State, name: &str) {
        s.upsert_user(name, "standard", Some("pid-1"))
            .await
            .expect("account");
    }

    #[tokio::test]
    async fn every_volume_is_listed_even_the_unprotected_ones() {
        // ⚠️ A volume missing from the list reads as "it does not exist". What needs to
        // be seen on a detail screen is that it exists AND is not protected.
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .expect("app");
        s.add_volume("gitea", "gitea-data", "/data", true, false)
            .await
            .expect("volume");
        s.add_volume("gitea", "gitea-cache", "/cache", false, false)
            .await
            .expect("volume");

        let all = s.app_volumes("gitea").await.expect("volumes");
        assert_eq!(all.len(), 2, "the unbacked-up cache must appear");

        let to_backup = s.volumes_to_backup("gitea").await.expect("volumes");
        assert_eq!(to_backup.len(), 1, "but it does not go to the repository");
    }

    #[tokio::test]
    async fn the_audit_can_be_filtered_on_one_app() {
        // On an app's screen the global log is unreadable: what is wanted is what
        // concerns that app.
        let s = st().await;
        s.audit(
            "cli",
            hlb_types::Role::Admin,
            "install",
            "gitea",
            "ok",
            None,
        )
        .await
        .expect("audit");
        s.audit(
            "cli",
            hlb_types::Role::Admin,
            "install",
            "vikunja",
            "ok",
            None,
        )
        .await
        .expect("audit");

        let j = s.audit_for("gitea", 10).await.expect("journal");
        assert_eq!(j.len(), 1);
        assert_eq!(j[0].target, "gitea");
    }

    #[tokio::test]
    async fn the_history_keeps_the_failures() {
        // 🔴 Returning only successes would give a timeline where nothing ever went
        // wrong - and a destination failing for three weeks would look like one that is
        // simply not used.
        let s = st().await;
        s.record_backup_to("immich", "volume", "nas", Some("abc"), None)
            .await
            .expect("success");
        s.record_backup_to("immich", "volume", "offsite", None, Some("network down"))
            .await
            .expect("failure");

        let h = s.backup_history("immich", 10).await.expect("history");
        assert_eq!(h.len(), 2);
        assert!(
            h.iter().any(|r| !r.succeeded()),
            "the failure must be there"
        );
        let failure = h.iter().find(|r| !r.succeeded()).expect("the failure");
        assert_eq!(failure.error.as_deref(), Some("network down"));
        assert_eq!(failure.destination.as_deref(), Some("offsite"));
    }

    #[tokio::test]
    async fn the_history_is_newest_first() {
        // ⚠️ Ordered by `id` and not by `finished_at`: `datetime('now')` has ONE SECOND
        // resolution, and two rows from the same second would order at random. The same
        // trap as the consecutive-failure counter.
        let s = st().await;
        for n in 0..5 {
            s.record_backup_to("gitea", "volume", "nas", Some(&format!("s{n}")), None)
                .await
                .expect("backup");
        }
        let h = s.backup_history("gitea", 10).await.expect("history");
        assert_eq!(h[0].snapshot_id.as_deref(), Some("s4"), "newest first");
        for f in h.windows(2) {
            assert!(f[0].id > f[1].id);
        }
    }

    #[tokio::test]
    async fn the_history_is_bounded() {
        // An app backed up every four hours for a year makes 2,190 rows. Returning them
        // all on every screen render would be paid for by the controller.
        let s = st().await;
        for n in 0..20 {
            s.record_backup_to("gitea", "volume", "nas", Some(&format!("s{n}")), None)
                .await
                .expect("backup");
        }
        assert_eq!(
            s.backup_history("gitea", 5).await.expect("history").len(),
            5
        );
    }

    #[tokio::test]
    async fn verifications_are_readable_not_just_their_age() {
        // This is the only reliable indicator that the backups really work. Returning
        // only the age made it impossible to know WHAT had been verified.
        let s = st().await;
        s.record_verification("gitea", "abc123", true, Some("1,284 files read back"))
            .await
            .expect("verification");

        let v = s.verifications("gitea", 10).await.expect("verifications");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].snapshot_id, "abc123");
        assert_eq!(v[0].detail.as_deref(), Some("1,284 files read back"));
    }

    #[tokio::test]
    async fn the_global_history_spans_every_app() {
        // The global timeline: one column per day, all apps together.
        let s = st().await;
        s.record_backup_to("gitea", "volume", "nas", Some("a"), None)
            .await
            .expect("backup");
        s.record_backup_to("immich", "volume", "nas", Some("b"), None)
            .await
            .expect("backup");

        let h = s.backup_history_all(10).await.expect("history");
        assert_eq!(h.len(), 2);
        let apps: std::collections::BTreeSet<&str> = h.iter().map(|r| r.app.as_str()).collect();
        assert_eq!(apps.len(), 2);
    }

    #[tokio::test]
    async fn the_history_is_newest_first_by_when_it_finished_not_by_row() {
        // The row order is the time order only while every run is recorded as it
        // finishes. The demonstration backdates rows afterwards, and its "latest runs"
        // came out shuffled under that heading.
        let s = st().await;
        s.record_backup_to("gitea", "volume", "nas", Some("a"), None)
            .await
            .expect("backup");
        s.record_backup_to("immich", "volume", "nas", Some("b"), None)
            .await
            .expect("backup");
        s.backdate_backup("immich", "nas", 3_600)
            .await
            .expect("backdate");

        let all = s.backup_history_all(10).await.expect("history");
        let apps: Vec<&str> = all.iter().map(|r| r.app.as_str()).collect();
        assert_eq!(apps, ["gitea", "immich"]);
    }

    #[tokio::test]
    async fn an_incident_is_followed_never_rewritten() {
        // 🔴 The chronology is what gets re-read afterwards: what time it was known,
        // understood, fixed. Rewriting the original body would erase it.
        let s = st().await;
        let id = s
            .publish_announcement(
                "gitea outage",
                "Looking into it.",
                hlb_api::AnnouncementLevel::Incident,
                true,
                None,
                "lena",
                None,
            )
            .await
            .expect("announcement");

        s.follow_announcement(id, "Cause: disk full.", "lena")
            .await
            .expect("follow-up");
        s.follow_announcement(id, "Resolved.", "lena")
            .await
            .expect("follow-up");

        let v = s
            .announcements(hlb_types::Role::User, 1_000, false)
            .await
            .expect("list");
        assert_eq!(v.len(), 1);
        // The original message is INTACT…
        assert_eq!(v[0].body, "Looking into it.");
        // ...and the chronology is there, in order.
        assert_eq!(v[0].follow_ups.len(), 2);
        assert_eq!(v[0].follow_ups[0].body, "Cause: disk full.");
        assert_eq!(v[0].last_update(), "Resolved.");
    }

    #[tokio::test]
    async fn an_operations_announcement_does_not_reach_the_portal() {
        // ⚠️ Flooding the user with messages that do not concern them makes them stop
        // reading - at the precise moment one of them will matter.
        let s = st().await;
        s.publish_announcement(
            "Database restart",
            "PostgreSQL restarts at 3 a.m.",
            hlb_api::AnnouncementLevel::Maintenance,
            false,
            Some(hlb_types::Role::Operator),
            "lena",
            None,
        )
        .await
        .expect("announcement");
        s.publish_announcement(
            "Nouveau webmail",
            "Bulwark is available.",
            hlb_api::AnnouncementLevel::Info,
            false,
            None,
            "lena",
            None,
        )
        .await
        .expect("announcement");

        let portal = s
            .announcements(hlb_types::Role::User, 1_000, false)
            .await
            .expect("list");
        assert_eq!(
            portal.len(),
            1,
            "the operations announcement leaked to the portal"
        );
        assert_eq!(portal[0].title, "Nouveau webmail");

        let admin = s
            .announcements(hlb_types::Role::Admin, 1_000, false)
            .await
            .expect("list");
        assert_eq!(admin.len(), 2, "the admin must see both");
    }

    #[tokio::test]
    async fn pinned_announcements_come_first() {
        let s = st().await;
        for (title, pinned) in [("previous", false), ("importante", true), ("recent", false)] {
            s.publish_announcement(
                title,
                "x",
                hlb_api::AnnouncementLevel::Info,
                pinned,
                None,
                "lena",
                None,
            )
            .await
            .expect("announcement");
        }
        let v = s
            .announcements(hlb_types::Role::User, 1_000, false)
            .await
            .expect("list");
        assert_eq!(v[0].title, "importante");
    }

    #[tokio::test]
    async fn an_expired_announcement_leaves_the_portal_but_stays_in_the_record() {
        // 🔴 This is the incident history, and it is what gets re-read afterwards.
        let s = st().await;
        s.publish_announcement(
            "A past outage",
            "x",
            hlb_api::AnnouncementLevel::Incident,
            false,
            None,
            "lena",
            Some(500),
        )
        .await
        .expect("announcement");

        let portal = s
            .announcements(hlb_types::Role::Admin, 1_000, false)
            .await
            .expect("list");
        assert!(
            portal.is_empty(),
            "an expired announcement stays on the portal"
        );

        let archive = s
            .announcements(hlb_types::Role::Admin, 1_000, true)
            .await
            .expect("list");
        assert_eq!(archive.len(), 1, "the history was lost");
    }

    #[tokio::test]
    async fn an_invitation_is_never_stored_in_clear() {
        // 🔴 The database goes into the backups, and therefore off-site. Storing usable
        // tokens in it would turn every copy into a keyring.
        let s = st().await;
        s.create_invitation(
            "link-secret-52-caracteres",
            "lena",
            "standard",
            1_000,
            604_800,
            1,
            None,
        )
        .await
        .expect("invitation");

        let raw: String = sqlx::query("SELECT group_concat(fingerprint) AS tout FROM invitations")
            .fetch_one(&s.pool)
            .await
            .expect("read")
            .try_get("tout")
            .expect("colonne");
        assert!(!raw.contains("link-secret"), "{raw}");
        assert_eq!(raw.len(), 64, "a SHA-256 fingerprint");
    }

    #[tokio::test]
    async fn an_invitation_can_only_be_used_once() {
        // 🔴 Reusing it would create a second account with the same rights, in the name
        // of someone who asked for nothing.
        let s = st().await;
        s.create_invitation("link", "lena", "standard", 1_000, 3_600, 1, None)
            .await
            .expect("invitation");

        let first = s
            .consume_invitation("link", "alice", 1_100)
            .await
            .expect("consume");
        assert!(first.is_some(), "the first time must work");

        let second = s
            .consume_invitation("link", "mallory", 1_200)
            .await
            .expect("consume");
        assert!(second.is_none(), "a single-use link was reused");
    }

    #[tokio::test]
    async fn an_expired_invitation_is_refused() {
        let s = st().await;
        s.create_invitation("link", "lena", "standard", 1_000, 60, 1, None)
            .await
            .expect("invitation");

        assert!(s
            .consume_invitation("link", "a", 1_050)
            .await
            .expect("consume")
            .is_some());

        // Another one, already expired.
        s.create_invitation("lien2", "lena", "standard", 1_000, 60, 1, None)
            .await
            .expect("invitation");
        assert!(
            s.consume_invitation("lien2", "b", 2_000)
                .await
                .expect("consume")
                .is_none(),
            "an expired invitation was accepted"
        );
    }

    #[tokio::test]
    async fn the_invited_never_chooses_their_own_role() {
        // 🔴 The role is fixed at INVITATION time. Letting the invitee choose would
        // allow signing up as an administrator.
        let s = st().await;
        s.create_invitation("link", "lena", "guest", 1_000, 3_600, 1, None)
            .await
            .expect("invitation");

        let role = s
            .consume_invitation("link", "alice", 1_100)
            .await
            .expect("consume")
            .expect("usable");
        assert_eq!(role, "guest");
    }

    #[tokio::test]
    async fn an_unknown_invitation_is_indistinguishable_from_an_expired_one() {
        // Separating them would tell whoever is trying tokens whether one existed.
        let s = st().await;
        assert!(s
            .consume_invitation("never-cree", "a", 1_000)
            .await
            .expect("consume")
            .is_none());
    }

    #[tokio::test]
    async fn listing_invitations_never_exposes_a_usable_value() {
        let s = st().await;
        s.create_invitation(
            "link",
            "lena",
            "standard",
            1_000,
            3_600,
            1,
            Some("for camille"),
        )
        .await
        .expect("invitation");

        let v = s.invitations(1_100).await.expect("list");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].reference.len(), 8, "a short reference, not the token");
        assert!(v[0].usable());
        assert_eq!(v[0].expires_in_s, 3_500);
        assert_eq!(v[0].note.as_deref(), Some("for camille"));
    }

    #[tokio::test]
    async fn a_multi_use_invitation_serves_exactly_its_quota() {
        // Invite five people with one link: not four, not six.
        let s = st().await;
        s.create_invitation("link", "lena", "standard", 1_000, 3_600, 3, None)
            .await
            .expect("invitation");

        for (n, who) in ["a", "b", "c"].iter().enumerate() {
            assert!(
                s.consume_invitation("link", who, 1_100)
                    .await
                    .expect("consume")
                    .is_some(),
                "use {} should have gone through",
                n + 1
            );
        }
        assert!(
            s.consume_invitation("link", "d", 1_100)
                .await
                .expect("consume")
                .is_none(),
            "the fourth use was accepted on a three-use link"
        );
    }

    #[tokio::test]
    async fn the_use_count_is_visible_before_it_runs_out() {
        // 🔴 A widely open link left lying around is a way in: the remaining count must
        // be visible BEFORE it is exhausted.
        let s = st().await;
        s.create_invitation("link", "lena", "standard", 1_000, 3_600, 5, None)
            .await
            .expect("invitation");
        s.consume_invitation("link", "a", 1_100)
            .await
            .expect("consume");

        let v = s.invitations(1_200).await.expect("list");
        assert_eq!(v[0].uses, 1);
        assert_eq!(v[0].max_uses, 5);
        assert_eq!(v[0].remaining(), 4);
        assert!(v[0].widely_open(), "a link with four uses left");
        assert_eq!(v[0].state(), hlb_api::InvitationState::PartlyUsed);
    }

    #[tokio::test]
    async fn zero_uses_is_corrected_to_one_rather_than_creating_a_dead_link() {
        // ⚠️ A zero-use invitation would be unusable from the moment it exists, which
        // looks like a failure - people would look for the problem elsewhere.
        let s = st().await;
        s.create_invitation("link", "lena", "standard", 1_000, 3_600, 0, None)
            .await
            .expect("invitation");

        assert!(s
            .consume_invitation("link", "a", 1_100)
            .await
            .expect("consume")
            .is_some());
    }

    #[tokio::test]
    async fn revoking_a_partially_used_link_closes_it_without_erasing_history() {
        // 🔴 What you do when a link has LEAKED: close it immediately. Deleting it would
        // lose the trace of who created it and who already came in - exactly when it is
        // needed.
        let s = st().await;
        s.create_invitation("link", "lena", "standard", 1_000, 3_600, 10, None)
            .await
            .expect("invitation");
        s.consume_invitation("link", "alice", 1_100)
            .await
            .expect("consume");

        let reference: String = hlb_types::token::fingerprint_of("link")
            .chars()
            .take(8)
            .collect();
        assert!(s.revoke_invitation(&reference).await.expect("revocation"));

        // Closed...
        assert!(s
            .consume_invitation("link", "mallory", 1_200)
            .await
            .expect("consume")
            .is_none());
        // ...but the history is there.
        let v = s.invitations(1_200).await.expect("list");
        assert_eq!(v.len(), 1, "the invitation was deleted instead of closed");
        assert_eq!(v[0].created_by, "lena");
        assert_eq!(v[0].state(), hlb_api::InvitationState::Exhausted);
    }

    #[tokio::test]
    async fn an_exhausted_invitation_has_nothing_left_to_revoke() {
        // It is already closed: "revoking" it would have no effect, and returning
        // "done" would suggest an action that changed nothing.
        let s = st().await;
        s.create_invitation("link", "lena", "standard", 1_000, 3_600, 1, None)
            .await
            .expect("invitation");
        let reference: String = hlb_types::token::fingerprint_of("link")
            .chars()
            .take(8)
            .collect();

        s.consume_invitation("link", "alice", 1_100)
            .await
            .expect("consume");
        assert!(
            !s.revoke_invitation(&reference).await.expect("revocation"),
            "a used invitation must not be deleted"
        );
    }

    #[tokio::test]
    async fn a_pending_invitation_can_be_revoked() {
        let s = st().await;
        s.create_invitation("link", "lena", "standard", 1_000, 3_600, 1, None)
            .await
            .expect("invitation");
        let reference: String = hlb_types::token::fingerprint_of("link")
            .chars()
            .take(8)
            .collect();

        assert!(s.revoke_invitation(&reference).await.expect("revocation"));
        assert!(s
            .consume_invitation("link", "a", 1_100)
            .await
            .expect("consume")
            .is_none());
    }

    #[tokio::test]
    async fn the_brand_exists_before_anyone_configures_it() {
        // On first start the interface must have something to show rather than an empty
        // header that would be taken for a loading failure.
        let s = st().await;
        let m = s.brand().await.expect("brand");
        assert_eq!(m.name, "Turi Industries");
        assert!(!m.logo);
    }

    #[tokio::test]
    async fn a_brand_survives_a_round_trip_including_its_accent() {
        let s = st().await;
        let mut m = s.brand().await.expect("brand");
        m.name = "Autre Maison".into();
        m.accent = Some([0x7B, 0x8C, 0xFF]);
        m.footer = Some("astreinte : 06 00 00 00 00".into());
        s.set_brand(&m).await.expect("write");

        let reread = s.brand().await.expect("reread");
        assert_eq!(reread.name, "Autre Maison");
        assert_eq!(reread.accent, Some([0x7B, 0x8C, 0xFF]));
        assert_eq!(reread.footer.as_deref(), Some("astreinte : 06 00 00 00 00"));
    }

    #[tokio::test]
    async fn writing_the_brand_never_drops_the_logo() {
        // The logo has its own operation: overwriting it on every name change would
        // make an image uploaded once disappear, without warning.
        let s = st().await;
        s.set_logo(Some(b"\x89PNG\r\n\x1a\n-fake-pixels"))
            .await
            .expect("logo");

        let mut m = s.brand().await.expect("brand");
        assert!(m.logo);
        m.name = "Renommee".into();
        s.set_brand(&m).await.expect("write");

        assert!(s.brand().await.expect("brand").logo, "the logo vanished");
        assert!(s.logo().await.expect("logo").is_some());
    }

    #[test]
    fn an_uploaded_svg_logo_is_rasterized_to_a_real_png() {
        const SQUARE: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#ff0000"/></svg>"##;
        let png = prepare_logo(SQUARE.as_bytes()).expect("rasterize");
        assert!(
            png.starts_with(&PNG_SIGNATURE),
            "prepare_logo did not return a real PNG"
        );
        // A 1:1 SVG must rasterize to a 1:1 PNG, at the configured longer-side size —
        // a bug that stretched or mis-scaled the canvas would not show up as an
        // error, only as a squashed logo on screen.
        let img = image_size(&png).expect("valid png dimensions");
        assert_eq!(
            img,
            (RASTERIZED_LOGO_SIZE as u32, RASTERIZED_LOGO_SIZE as u32)
        );
    }

    #[test]
    fn a_wide_svg_is_scaled_by_its_longer_side() {
        const WIDE: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 10"><rect width="20" height="10" fill="#00ff00"/></svg>"##;
        let png = prepare_logo(WIDE.as_bytes()).expect("rasterize");
        let (w, h) = image_size(&png).expect("valid png dimensions");
        assert_eq!(w, RASTERIZED_LOGO_SIZE as u32, "the longer side (width)");
        assert_eq!(
            h,
            RASTERIZED_LOGO_SIZE as u32 / 2,
            "half as tall as wide, like the source"
        );
    }

    #[test]
    fn neither_a_png_nor_an_svg_is_refused() {
        let e = prepare_logo(b"not an image").expect_err("should be refused");
        assert!(matches!(e, LogoError::UnrecognisedFormat), "{e}");
    }

    /// Reads just enough of a PNG's IHDR chunk to get its width/height — no need to
    /// pull in an image-decoding crate for a two-field test assertion.
    fn image_size(png: &[u8]) -> Option<(u32, u32)> {
        if png.len() < 24 {
            return None;
        }
        let w = u32::from_be_bytes(png[16..20].try_into().ok()?);
        let h = u32::from_be_bytes(png[20..24].try_into().ok()?);
        Some((w, h))
    }

    #[tokio::test]
    async fn there_can_only_ever_be_one_brand() {
        // 🔴 Two rows would give a brand that changes with read order - a defect that
        // would never reproduce. The constraint lives in the schema.
        let s = st().await;
        let r = sqlx::query("INSERT INTO appearance (id, name, product) VALUES (2, 'x', 'y')")
            .execute(&s.pool)
            .await;
        assert!(r.is_err(), "a second brand was accepted");
    }

    #[tokio::test]
    async fn a_theme_is_a_preference_not_a_right() {
        // Preferences are separate from roles: mixing the two would route a colour
        // change through the rights access control.
        let s = st().await;
        with_account(&s, "lena").await;
        assert_eq!(s.theme_of("lena").await.expect("theme"), None);

        s.set_theme_of("lena", Some("Light")).await.expect("write");
        assert_eq!(
            s.theme_of("lena").await.expect("theme").as_deref(),
            Some("Light")
        );
    }

    #[tokio::test]
    async fn a_day_of_history_is_read_back_by_metric_and_pruned() {
        let s = State::in_memory().await.expect("state");
        let at = |metric: &str, subject: &str, at: i64, value: f64| Sample {
            metric: metric.into(),
            subject: subject.into(),
            at,
            value,
        };
        s.record_history(&[
            at("cpu", "10.0.0.1:8421", 60, 0.2),
            at("cpu", "10.0.0.1:8421", 120, 0.4),
            at("disk:/", "10.0.0.1:8421", 60, 0.5),
            at("disk:/var", "10.0.0.1:8421", 60, 0.9),
            at("diskette", "10.0.0.1:8421", 60, 1.0),
        ])
        .await
        .expect("record");
        // The same minute again replaces, never doubles a point.
        s.record_history(&[at("cpu", "10.0.0.1:8421", 120, 0.5)])
            .await
            .expect("record");

        let cpu = s.history("cpu", 0).await.expect("read");
        assert_eq!(
            cpu.iter().map(|x| x.value).collect::<Vec<_>>(),
            vec![0.2, 0.5]
        );
        // A prefix ending in ':' reads every disk, and nothing that merely starts alike.
        let disks = s.history("disk:", 0).await.expect("read");
        assert_eq!(disks.len(), 2);
        assert_eq!(s.history("cpu", 100).await.expect("read").len(), 1);

        assert_eq!(s.prune_history(100).await.expect("prune"), 4);
        assert_eq!(s.history("cpu", 0).await.expect("read").len(), 1);
    }

    #[tokio::test]
    async fn an_in_memory_database_never_gives_its_connection_up() {
        // Recycled, the connection takes the database with it: the demonstration lost
        // every table thirty minutes after starting.
        let s = State::in_memory().await.expect("state");
        let o = s.pool.options();
        assert_eq!((o.get_idle_timeout(), o.get_max_lifetime()), (None, None));
        assert_eq!(o.get_min_connections(), 1);
    }

    #[tokio::test]
    async fn a_home_never_arranged_is_not_an_empty_home() {
        use hlb_api::{HomeTile, HomeWidget};
        let s = st().await;
        with_account(&s, "lena").await;
        assert_eq!(s.home_of("lena").await.expect("home"), None);

        s.set_home_of("lena", Some(&[])).await.expect("write");
        assert_eq!(s.home_of("lena").await.expect("home"), Some(vec![]));

        let tiles = [
            HomeTile {
                widget: HomeWidget::Nodes,
                w: 2,
                h: 3,
            },
            HomeTile {
                widget: HomeWidget::Apps,
                w: 1,
                h: 1,
            },
        ];
        s.set_home_of("lena", Some(&tiles)).await.expect("write");
        assert_eq!(s.home_of("lena").await.expect("home"), Some(tiles.to_vec()));

        // The theme is a separate column: arranging the home must not reset it.
        s.set_theme_of("lena", Some("Light")).await.expect("write");
        s.set_home_of("lena", None).await.expect("write");
        assert_eq!(s.home_of("lena").await.expect("home"), None);
        assert_eq!(
            s.theme_of("lena").await.expect("theme").as_deref(),
            Some("Light")
        );
    }

    #[tokio::test]
    async fn the_audit_is_searched_and_paged_whole_not_its_newest_hundred() {
        let s = st().await;
        for i in 0..150 {
            let target = if i == 0 { "gitea" } else { "immich" };
            let outcome = if i % 3 == 0 { "failed" } else { "ok" };
            s.audit(
                "lena",
                hlb_types::Role::Admin,
                "backup-run",
                target,
                outcome,
                Some("100% done"),
            )
            .await
            .expect("audit");
        }
        // The OLDEST entry is found: a search over the newest hundred never could.
        let (found, matched, total) = s
            .audit_search(&["GITEA".into()], None, 0, 50)
            .await
            .expect("search");
        assert_eq!((found.len(), matched, total), (1, 1, 150));

        let (page, matched, _) = s
            .audit_search(&["immich".into()], Some("failed"), 40, 50)
            .await
            .expect("search");
        assert_eq!(matched, 49);
        assert_eq!(page.len(), 9);

        // A `%` typed in the search is a character, not "anything".
        let (_, matched, _) = s
            .audit_search(&["%".into()], None, 0, 50)
            .await
            .expect("search");
        assert_eq!(matched, 150);
        let (_, matched, _) = s
            .audit_search(&["_x".into()], None, 0, 50)
            .await
            .expect("search");
        assert_eq!(matched, 0);
    }

    #[tokio::test]
    async fn every_account_read_at_once_is_the_account_read_alone() {
        let s = st().await;
        s.upsert_user("lena", "unlimited", Some("pid-lena"))
            .await
            .expect("user");
        s.add_mailbox("lena", "lena", "home.example", true)
            .await
            .expect("box");
        s.add_mailbox("lena", "contact", "home.example", false)
            .await
            .expect("box");
        s.add_alias("lena", "lena", "taxes", None, None, Some("tax office"))
            .await
            .expect("alias");
        s.add_alias("lena", "contact", "shop", Some(10), None, None)
            .await
            .expect("alias");
        s.upsert_user("dominique", "standard", Some("pid-dominique"))
            .await
            .expect("user");
        s.upsert_user("sacha", "guest", None).await.expect("user");
        s.add_mailbox("sacha", "sacha", "home.example", true)
            .await
            .expect("box");

        let all = s.accounts().await.expect("all");
        assert_eq!(all.len(), 3);
        for account in all {
            assert_eq!(account, s.account(&account.name).await.expect("one"));
        }
    }

    #[tokio::test]
    async fn a_reading_replaces_the_last_and_is_forgotten_with_its_app() {
        use hlb_api::assertions::{AssertionResult, Verdict};
        let s = st().await;
        s.upsert_app("termix", &manifest("termix"), None)
            .await
            .expect("app");
        let reading = |id: &str, verdict| AssertionResult {
            id: id.into(),
            holds: "nobody signs up".into(),
            verdict,
            observed: "{\"allowed\":true}".into(),
            checked_at: 10,
            fix: None,
        };
        s.record_assertions(
            "termix",
            &[
                reading("registration", Verdict::Broken),
                reading("reset", Verdict::Holds),
            ],
        )
        .await
        .expect("record");
        // The manifest dropped `reset`: its old "holds" must not stay behind.
        s.record_assertions("termix", &[reading("registration", Verdict::Holds)])
            .await
            .expect("record");
        assert_eq!(
            s.assertion_results().await.expect("read"),
            vec![(
                "termix".to_string(),
                reading("registration", Verdict::Holds)
            )]
        );
        s.forget_app("termix").await.expect("forget");
        assert!(s.assertion_results().await.expect("read").is_empty());
    }

    #[tokio::test]
    async fn a_mail_record_reading_replaces_the_last_whole() {
        use hlb_api::mail_dns::{MailRecord, Purpose, RecordState};
        let s = st().await;
        let reading = |name: &str, state| MailRecord {
            domain: "example.org".into(),
            name: name.into(),
            purpose: Purpose::Dkim,
            expected: format!("{name}. IN TXT \"v=DKIM1; p=AAAA\""),
            state,
            observed: "nothing".into(),
            checked_at: 10,
        };
        s.record_mail_records(&[
            reading("v1-rsa-1._domainkey.example.org", RecordState::Missing),
            reading(
                "v1-ed25519-1._domainkey.example.org",
                RecordState::Published,
            ),
        ])
        .await
        .expect("record");
        // A selector Stalwart retired must not stay behind, missing for ever.
        let now = [reading(
            "v2-rsa-2._domainkey.example.org",
            RecordState::Published,
        )];
        s.record_mail_records(&now).await.expect("record");
        assert_eq!(s.mail_records().await.expect("read"), now);
    }

    #[tokio::test]
    async fn the_domains_baseline_and_reading_are_kept_apart() {
        use hlb_api::domain::{DnsSide, Reading, Registry};
        let s = State::in_memory().await.expect("state");
        assert!(s.domain_baseline().await.expect("read").is_none());
        let reading = |ns: &str| Reading {
            zone: "home.example".into(),
            read_at: 1,
            dns: Ok(DnsSide::new(vec![ns.into()], vec![], false, vec![])),
            registry: Registry::NotRead {
                why: "no RDAP for .example".into(),
            },
            caa_governing: None,
            accounts: Vec::new(),
        };
        s.set_domain_baseline(&reading("ns1.example"))
            .await
            .expect("accept");
        s.record_domain_reading(&reading("ns1.thief.example"))
            .await
            .expect("record");
        assert_eq!(
            s.domain_baseline().await.expect("read"),
            Some(reading("ns1.example"))
        );
        assert_eq!(
            s.domain_reading().await.expect("read"),
            Some(reading("ns1.thief.example"))
        );
    }

    #[tokio::test]
    async fn a_baseline_this_binary_cannot_read_is_an_error_not_none() {
        let s = State::in_memory().await.expect("state");
        s.put_setting("domain-baseline", Some("{\"zone\": 3}"))
            .await
            .expect("write");
        assert!(matches!(
            s.domain_baseline().await,
            Err(Error::StoredDomain { .. })
        ));
    }

    #[tokio::test]
    async fn blocklists_that_answer_again_leave_nothing_behind() {
        let s = st().await;
        assert!(s.refused_blocklists().await.expect("read").is_empty());
        let refused = vec![
            "DBL_BLOCKED_OPENRESOLVER".to_string(),
            "RBL_SPAMHAUS_BLOCKED_OPENRESOLVER".to_string(),
        ];
        s.record_refused_blocklists(&refused).await.expect("record");
        assert_eq!(s.refused_blocklists().await.expect("read"), refused);
        s.record_refused_blocklists(&[]).await.expect("record");
        assert!(s.refused_blocklists().await.expect("read").is_empty());
    }

    #[tokio::test]
    async fn a_queue_reading_replaces_the_last_whole() {
        use hlb_api::mail_queue::Waiting;
        let s = st().await;
        let waiting = |id: &str, error: Option<&str>| Waiting {
            message_id: id.into(),
            recipient: "bob@example.net".into(),
            since: 10,
            attempts: 3,
            next_retry: 130,
            expires_at: error.map(|_| 259_210),
            error: error.map(str::to_string),
            read_at: 20,
        };
        s.record_mail_queue(&[
            waiting("a", Some("relay.test: Connection refused")),
            waiting("b", None),
        ])
        .await
        .expect("record");
        assert_eq!(s.mail_queue().await.expect("read").len(), 2);
        // A message delivered since is not left waiting for ever.
        let now = [waiting("b", Some("mx.example.net: 451 4.7.1 later"))];
        s.record_mail_queue(&now).await.expect("record");
        assert_eq!(s.mail_queue().await.expect("read"), now);
    }

    #[tokio::test]
    async fn an_aside_is_kept_per_person_and_ends() {
        let s = st().await;
        let aside = hlb_api::issues::Aside {
            cause: hlb_api::issues::Cause::Alert {
                rule: "disk-full".into(),
                evaluable: true,
            },
            until: 100,
            attention: hlb_api::Attention::Notice,
            subjects: 0,
        };
        s.set_aside("lena", &aside).await.expect("set");
        assert_eq!(
            s.asides_of("lena", 50).await.expect("read"),
            vec![aside.clone()]
        );
        assert!(s.asides_of("camille", 50).await.expect("read").is_empty());
        assert!(s.asides_of("lena", 100).await.expect("read").is_empty());
        assert!(s.bring_back("lena", &aside.cause).await.expect("back"));
        assert!(!s.bring_back("lena", &aside.cause).await.expect("back"));
    }

    #[tokio::test]
    async fn a_density_is_kept_and_an_unknown_one_is_the_default() {
        let s = st().await;
        s.upsert_user("lena", "unlimited", None)
            .await
            .expect("user");
        assert_eq!(
            s.density_of("lena").await.expect("read"),
            hlb_api::Density::Comfortable
        );
        s.set_density_of("lena", hlb_api::Density::Compact)
            .await
            .expect("set");
        assert_eq!(
            s.density_of("lena").await.expect("read"),
            hlb_api::Density::Compact
        );
        // The theme set beside it does not reset it.
        s.set_theme_of("lena", Some("Light")).await.expect("theme");
        assert_eq!(
            s.density_of("lena").await.expect("read"),
            hlb_api::Density::Compact
        );

        sqlx::query("UPDATE user_prefs SET density = 'cramped' WHERE user = 'lena'")
            .execute(&s.pool)
            .await
            .expect("write");
        assert_eq!(
            s.density_of("lena").await.expect("read"),
            hlb_api::Density::Comfortable
        );
    }

    #[tokio::test]
    async fn a_mute_survives_until_it_ends_and_not_after() {
        let s = st().await;
        let m = hlb_api::AlertMute {
            rule: "disk-full".into(),
            until: 1_000,
            by: "lena".into(),
            reason: "purge under way".into(),
        };
        s.mute_alert(&m).await.expect("mute");
        assert_eq!(s.alert_mutes(999).await.expect("read"), vec![m.clone()]);
        // Ended: no longer applies, though nobody deleted it.
        assert_eq!(s.alert_mutes(1_000).await.expect("read"), vec![]);

        // Muting again replaces, never stacks two mutes on one rule.
        let longer = hlb_api::AlertMute { until: 5_000, ..m };
        s.mute_alert(&longer).await.expect("mute");
        assert_eq!(s.alert_mutes(999).await.expect("read"), vec![longer]);

        assert!(s.unmute_alert("disk-full").await.expect("lift"));
        assert!(
            !s.unmute_alert("disk-full").await.expect("lift"),
            "nothing left to lift"
        );
        assert_eq!(s.alert_mutes(0).await.expect("read"), vec![]);
    }

    #[tokio::test]
    async fn a_removed_widget_costs_one_card_not_the_layout() {
        let s = st().await;
        with_account(&s, "lena").await;
        sqlx::query(
            "INSERT INTO user_prefs (user, home) VALUES ('lena', \
             '[\"gone\",{\"widget\":\"gone\",\"w\":1,\"h\":1},{\"widget\":\"nodes\",\"w\":2,\"h\":2}]')",
        )
        .execute(&s.pool)
        .await
        .expect("insert");
        assert_eq!(
            s.home_of("lena").await.expect("home"),
            Some(vec![hlb_api::HomeTile {
                widget: hlb_api::HomeWidget::Nodes,
                w: 2,
                h: 2
            }])
        );
    }

    #[tokio::test]
    async fn a_layout_stored_before_tiles_had_a_size_keeps_its_cards() {
        // Names alone until 2026-10-10: each takes the size it is added at, and a size
        // the grid cannot hold takes it too — never the whole layout lost.
        let s = st().await;
        with_account(&s, "lena").await;
        sqlx::query(
            "INSERT INTO user_prefs (user, home) VALUES ('lena', \
             '[\"activity\",{\"widget\":\"apps\",\"w\":9,\"h\":1}]')",
        )
        .execute(&s.pool)
        .await
        .expect("insert");
        use hlb_api::HomeWidget;
        assert_eq!(
            s.home_of("lena").await.expect("home"),
            Some(vec![HomeWidget::Activity.tile(), HomeWidget::Apps.tile()])
        );
    }

    #[test]
    fn a_half_read_colour_is_refused_rather_than_guessed() {
        // An absurd accent is harder to diagnose than a missing one.
        assert_eq!(hex_rgb("7B8CFF"), Some([0x7B, 0x8C, 0xFF]));
        assert_eq!(hex_rgb("#7B8CFF"), Some([0x7B, 0x8C, 0xFF]));
        assert_eq!(hex_rgb("7B8C"), None);
        assert_eq!(hex_rgb("ZZZZZZ"), None);
        assert_eq!(hex_rgb(""), None);
    }

    #[tokio::test]
    async fn a_session_cookie_is_never_stored_in_clear() {
        // 🔴 Same discipline as API tokens: a database that leaks - and it goes into
        // the backups, therefore off-site - must not be a keyring.
        let s = st().await;
        with_account(&s, "lena").await;
        s.open_session(
            "cookie-secret-52-caracteres",
            "lena",
            Some("sub-1"),
            1000,
            3600,
            None,
        )
        .await
        .expect("session");

        let raw: String = sqlx::query("SELECT group_concat(fingerprint) AS tout FROM sessions")
            .fetch_one(&s.pool)
            .await
            .expect("read")
            .try_get("tout")
            .expect("colonne");
        assert!(
            !raw.contains("cookie-secret"),
            "the cookie value must never touch the disk: {raw}"
        );
        assert_eq!(raw.len(), 64, "a hexadecimal SHA-256 fingerprint");
    }

    #[tokio::test]
    async fn an_expired_session_authenticates_nobody() {
        // 🔴 Expiry is filtered in SQL, not left to the caller: a caller who forgot the
        // comparison would authenticate a dead session.
        let s = st().await;
        with_account(&s, "lena").await;
        s.open_session("c", "lena", None, 1000, 60, None)
            .await
            .expect("session");

        assert!(s.find_session("c", 1030).await.expect("before").is_some());
        assert!(
            s.find_session("c", 1061).await.expect("after").is_none(),
            "an expired session must authenticate nothing"
        );
    }

    #[tokio::test]
    async fn a_revoked_role_takes_effect_at_the_next_request() {
        // 🔴 The role is NOT copied into the session. If it were, removing someone's
        // administrator rights would have no effect for twelve hours - and you remove
        // rights precisely when you are in a hurry to.
        let s = st().await;
        with_account(&s, "lena").await;
        s.set_user_role(
            "lena",
            &level(&s, hlb_types::Role::Admin).await,
            Some("cli"),
        )
        .await
        .expect("role");
        s.open_session("c", "lena", None, 1000, 3600, None)
            .await
            .expect("session");

        assert_eq!(
            s.user_role("lena").await.expect("role"),
            hlb_types::Role::Admin
        );

        s.set_user_role(
            "lena",
            &level(&s, hlb_types::Role::Viewer).await,
            Some("cli"),
        )
        .await
        .expect("demotion");

        // The session is still alive…
        assert!(s.find_session("c", 1010).await.expect("session").is_some());
        // ...but it no longer grants the same rights.
        assert_eq!(
            s.user_role("lena").await.expect("role"),
            hlb_types::Role::Viewer
        );
    }

    #[tokio::test]
    async fn deleting_an_account_closes_its_sessions() {
        // A revoked person must not stay signed in until their cookie expires.
        let s = st().await;
        with_account(&s, "lena").await;
        s.open_session("c", "lena", None, 1000, 3600, None)
            .await
            .expect("session");

        sqlx::query("DELETE FROM users WHERE name = 'lena'")
            .execute(&s.pool)
            .await
            .expect("suppression");

        assert!(s.find_session("c", 1010).await.expect("session").is_none());
    }

    #[tokio::test]
    async fn a_person_is_matched_by_a_stable_subject_not_by_their_name() {
        // 🔴 A username can be renamed in PocketID; the `sub` does not move. Binding to
        // the name would lose the link on the first rename, and the person would be
        // refused access with no message explaining why.
        let s = st().await;
        s.upsert_user("lena", "standard", Some("sub-stable"))
            .await
            .expect("account");

        assert_eq!(
            s.user_by_pocket_id("sub-stable").await.expect("recherche"),
            Some("lena".into())
        );
        assert_eq!(
            s.user_by_pocket_id("other-sub").await.expect("recherche"),
            None
        );
    }

    #[tokio::test]
    async fn linking_an_identity_touches_nothing_else() {
        // Signing in looks at neither the role nor the mailboxes: overwriting them in
        // passing would lose a quota on the first sign-in.
        let s = st().await;
        s.upsert_user("lena", "admin", None).await.expect("account");
        s.add_mailbox("lena", "lena", "home.example", true)
            .await
            .expect("mailbox");

        s.upsert_user_pocket_id("lena", "sub-1")
            .await
            .expect("link");

        let c = s.account("lena").await.expect("account");
        assert_eq!(c.role.as_deref(), Some("admin"));
        assert_eq!(c.pocket_id.as_deref(), Some("sub-1"));
        assert_eq!(c.mailboxes.len(), 1);
    }

    #[tokio::test]
    async fn an_account_bound_to_one_identity_is_never_moved_to_another() {
        let s = st().await;
        s.upsert_user("lena", "admin", None).await.expect("account");
        assert!(s
            .upsert_user_pocket_id("lena", "sub-1")
            .await
            .expect("link"));
        assert!(
            !s.upsert_user_pocket_id("lena", "sub-2")
                .await
                .expect("link"),
            "an account bound to sub-1 was handed to sub-2"
        );
        assert!(s
            .upsert_user_pocket_id("lena", "sub-1")
            .await
            .expect("idempotent"));
        let c = s.account("lena").await.expect("account");
        assert_eq!(c.pocket_id.as_deref(), Some("sub-1"));
    }

    #[tokio::test]
    async fn an_address_is_one_accounts_mailbox() {
        let s = st().await;
        s.upsert_user("lena", "standard", None)
            .await
            .expect("account");
        s.upsert_user("mallory", "standard", None)
            .await
            .expect("account");
        s.add_mailbox("lena", "contact", "home.example", true)
            .await
            .expect("mailbox");
        let taken = s
            .add_mailbox("mallory", "contact", "home.example", false)
            .await;
        assert!(
            matches!(taken, Err(Error::MailboxTaken { .. })),
            "{taken:?}"
        );
        assert!(s.mailboxes("mallory").await.expect("list").is_empty());
        // The same local part at another domain is another address.
        s.add_mailbox("mallory", "contact", "other.fr", true)
            .await
            .expect("another domain");
        // And the trigger holds it for whatever writes beside `add_mailbox`.
        let raw = sqlx::query(
            "INSERT INTO user_mailboxes (user, local, domain) VALUES ('mallory', 'x', 'y')",
        )
        .execute(&s.pool)
        .await;
        assert!(raw.is_ok());
        let raw = sqlx::query(
            "INSERT INTO user_mailboxes (user, local, domain) VALUES ('lena', 'x', 'y')",
        )
        .execute(&s.pool)
        .await;
        assert!(raw.is_err(), "the trigger let a second owner in");
    }

    #[tokio::test]
    async fn a_token_name_taken_again_acts_for_nobody() {
        let s = st().await;
        s.upsert_user("alice", "standard", None)
            .await
            .expect("account");
        let (_, t) = hlb_types::generate_token(
            "bw",
            hlb_types::Role::User,
            [1u8; hlb_types::token::TOKEN_BYTES],
        );
        s.store_token(&t).await.expect("token");
        s.set_token_user("bw", Some("alice")).await.expect("bind");
        s.set_token_mailbox("bw", Some("alice"))
            .await
            .expect("mailbox");

        let (_, t) = hlb_types::generate_token(
            "bw",
            hlb_types::Role::Admin,
            [2u8; hlb_types::token::TOKEN_BYTES],
        );
        s.store_token(&t).await.expect("token");
        assert_eq!(
            s.token_target("bw").await.expect("target"),
            (None, None),
            "the new token inherited alice"
        );
    }

    #[tokio::test]
    async fn a_name_is_created_once() {
        let s = st().await;
        assert!(s.create_user("lena", "admin").await.expect("created"));
        assert!(!s.create_user("lena", "user").await.expect("taken"));
        assert_eq!(
            s.user_role("lena").await.expect("role"),
            hlb_types::Role::Admin
        );
    }

    #[tokio::test]
    async fn an_invitation_is_peeked_without_being_used() {
        let s = st().await;
        s.create_invitation("link", "lena", "standard", 1_000, 3_600, 1, None)
            .await
            .expect("invitation");
        assert!(s.invitation_open("link", 1_100).await.expect("read"));
        assert!(s
            .invitation_open("link", 1_100)
            .await
            .expect("not consumed"));
        assert!(!s.invitation_open("other", 1_100).await.expect("read"));
        assert!(!s.invitation_open("link", 9_000).await.expect("expired"));
    }

    #[tokio::test]
    async fn a_partial_invitation_reference_revokes_nothing() {
        let s = st().await;
        s.create_invitation("link", "lena", "standard", 1_000, 3_600, 10, None)
            .await
            .expect("invitation");
        let reference: String = hlb_types::token::fingerprint_of("link")
            .chars()
            .take(8)
            .collect();
        for partial in ["", &reference[..1], &reference[..7]] {
            assert!(
                !s.revoke_invitation(partial).await.expect("revocation"),
                "{partial:?} revoked an invitation"
            );
        }
        assert!(s.revoke_invitation(&reference).await.expect("revocation"));
    }

    #[tokio::test]
    async fn an_unknown_person_gets_the_least_privileged_role() {
        // A PocketID identity Homelabus does not know comes in at the lowest level.
        let s = st().await;
        assert_eq!(
            s.user_role("never-vu").await.expect("role"),
            hlb_types::Role::User
        );
    }

    #[tokio::test]
    async fn an_unreadable_role_falls_back_to_the_default() {
        // A corrupted column must never grant more rights.
        let s = st().await;
        with_account(&s, "lena").await;
        sqlx::query("UPDATE users SET role = 'superadmin' WHERE name = 'lena'")
            .execute(&s.pool)
            .await
            .expect("bogus role");
        assert_eq!(
            s.user_role("lena").await.expect("role"),
            hlb_types::Role::User
        );
    }

    #[tokio::test]
    async fn accounts_without_an_explicit_role_still_appear() {
        // Omitting them would suggest they have no access, when they have a user's.
        let s = st().await;
        with_account(&s, "alice").await;
        with_account(&s, "bob").await;
        s.set_user_role("alice", &level(&s, hlb_types::Role::Operator).await, None)
            .await
            .expect("role");

        let all = s.users_with_roles().await.expect("list");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].level, hlb_types::Role::Operator, "alice");
        assert_eq!(all[1].level, hlb_types::Role::User, "bob, by their role");
    }

    #[tokio::test]
    async fn a_session_can_be_named_without_naming_a_secret() {
        // It must be possible to say "sign out this device" without touching the cookie.
        let s = st().await;
        with_account(&s, "lena").await;
        s.open_session("portable", "lena", None, 1000, 3600, Some("Firefox"))
            .await
            .expect("session");

        let seen = s.sessions_of("lena", 1010).await.expect("sessions");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].reference.len(), 8);
        assert_eq!(seen[0].user_agent.as_deref(), Some("Firefox"));

        assert!(s
            .close_session_by_reference("lena", &seen[0].reference)
            .await
            .expect("fermeture"));
        assert!(s
            .find_session("portable", 1010)
            .await
            .expect("session")
            .is_none());
    }

    #[tokio::test]
    async fn an_empty_or_partial_reference_closes_no_session() {
        // 🔴 The match is a prefix: an empty reference would have named every session the
        // person has, and a route passing on what it was sent would sign them out
        // everywhere for a request that named nothing.
        let s = st().await;
        with_account(&s, "lena").await;
        s.open_session("portable", "lena", None, 1000, 3600, None)
            .await
            .expect("session");
        let reference = s.sessions_of("lena", 1010).await.expect("sessions")[0]
            .reference
            .clone();

        for partial in ["", &reference[..3]] {
            assert!(!s
                .close_session_by_reference("lena", partial)
                .await
                .expect("close"));
        }
        assert_eq!(
            s.sessions_of("lena", 1010).await.expect("sessions").len(),
            1
        );
    }

    #[tokio::test]
    async fn an_account_has_exactly_one_default_mailbox_after_a_change() {
        let s = st().await;
        with_account(&s, "lena").await;
        s.add_mailbox("lena", "lena", "home.example", true)
            .await
            .expect("mailbox");
        s.add_mailbox("lena", "contact", "home.example", false)
            .await
            .expect("mailbox");

        assert!(s
            .set_default_mailbox("lena", "contact")
            .await
            .expect("change"));
        let defaults: Vec<String> = s
            .mailboxes("lena")
            .await
            .expect("mailboxes")
            .into_iter()
            .filter(|(.., d)| *d)
            .map(|(l, ..)| l)
            .collect();
        assert_eq!(defaults, ["contact"]);

        // A mailbox the account does not own changes nothing — not even clearing the
        // current default.
        assert!(!s
            .set_default_mailbox("lena", "someone-else")
            .await
            .expect("change"));
        assert_eq!(
            s.mailboxes("lena").await.expect("mailboxes")[0],
            ("contact".to_string(), "home.example".to_string(), true)
        );
    }

    #[tokio::test]
    async fn the_audit_chain_holds_across_entries() {
        let s = st().await;
        for n in 0..5 {
            s.audit(
                "cli",
                hlb_types::Role::Admin,
                "install",
                &format!("app{n}"),
                "ok",
                None,
            )
            .await
            .expect("audit");
        }
        let v = s.verify_audit_chain().await.expect("verification");
        assert!(v.is_intact(), "{}", v.describe());
        match v {
            AuditIntegrity::Intact {
                verified,
                unchained,
                ..
            } => {
                assert_eq!(verified, 5);
                assert_eq!(unchained, 0);
            }
            AuditIntegrity::Broken { .. } => panic!("chain broken for no reason"),
        }
    }

    #[tokio::test]
    async fn a_tampered_entry_breaks_the_chain() {
        // 🔴 The point of the chaining: "append-only" is only a convention as long as
        // the SQLite file can be opened. A rewrite stays possible, but it shows - which
        // is the only guarantee reachable without a trusted third party.
        let s = st().await;
        s.audit(
            "cli",
            hlb_types::Role::Admin,
            "install",
            "gitea",
            "ok",
            None,
        )
        .await
        .expect("audit");
        s.audit(
            "cli",
            hlb_types::Role::Admin,
            "purge",
            "vikunja",
            "ok",
            None,
        )
        .await
        .expect("audit");

        sqlx::query("UPDATE audit_log SET target = 'innocent' WHERE action = 'purge'")
            .execute(&s.pool)
            .await
            .expect("tampering");

        let v = s.verify_audit_chain().await.expect("verification");
        assert!(!v.is_intact(), "a modified entry must show");
        assert!(v.describe().contains("BROKEN"), "{}", v.describe());
    }

    #[tokio::test]
    async fn a_removed_entry_breaks_the_chain() {
        // What an attacker would try first: erasing the trace of their passage rather
        // than modifying it.
        let s = st().await;
        for n in 0..3 {
            s.audit(
                "cli",
                hlb_types::Role::Admin,
                "install",
                &format!("app{n}"),
                "ok",
                None,
            )
            .await
            .expect("audit");
        }
        sqlx::query("DELETE FROM audit_log WHERE target = 'app1'")
            .execute(&s.pool)
            .await
            .expect("suppression");

        let v = s.verify_audit_chain().await.expect("verification");
        assert!(!v.is_intact(), "a removed entry must show");
    }

    #[tokio::test]
    async fn entries_older_than_the_chain_are_named_not_hidden() {
        // 🔴 Backfilling fingerprints for old entries would produce an apparently
        // complete chain, built on content that may already have been falsified. So the
        // verdict must say SINCE WHEN it holds.
        let s = st().await;
        sqlx::query(
            "INSERT INTO audit_log (actor, role, action, target, outcome)
             VALUES ('ancien', 'admin', 'install', 'gitea', 'ok')",
        )
        .execute(&s.pool)
        .await
        .expect("pre-chaining entry");

        s.audit(
            "cli",
            hlb_types::Role::Admin,
            "install",
            "vikunja",
            "ok",
            None,
        )
        .await
        .expect("audit");

        let v = s.verify_audit_chain().await.expect("verification");
        assert!(v.is_intact());
        match v {
            AuditIntegrity::Intact {
                verified,
                unchained,
                since_entry,
            } => {
                assert_eq!(verified, 1);
                assert_eq!(unchained, 1, "the earlier entry is counted, not hidden");
                assert!(since_entry.is_some());
            }
            AuditIntegrity::Broken { .. } => panic!("no break expected"),
        }
    }

    #[tokio::test]
    async fn moving_text_between_fields_does_not_preserve_the_hash() {
        // 🔴 Without a length prefix, a target "gitea|ok" and a target "gitea" followed
        // by the outcome "ok" would give the same fingerprint: a failure could be
        // reclassified as a success without breaking the chain.
        let a = entry_fingerprint(
            None,
            ["t", "cli", "admin", "purge", "gitea|ok", "failed"],
            None,
        );
        let b = entry_fingerprint(
            None,
            ["t", "cli", "admin", "purge", "gitea", "|okfailed"],
            None,
        );
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn the_audit_trail_carries_the_role_and_the_diff() {
        // An audit entry is "who, what, when, with the diff"; the diff was missing.
        let s = st().await;
        s.audit(
            "lena",
            hlb_types::Role::Operator,
            "config",
            "backup.interval",
            "ok",
            Some("4h → 2h"),
        )
        .await
        .expect("audit");

        let t = s.audit_trail(10).await.expect("journal");
        assert_eq!(t[0].role, "operator");
        assert_eq!(t[0].detail.as_deref(), Some("4h → 2h"));
    }

    #[tokio::test]
    async fn the_last_admin_cannot_be_identified_as_replaceable() {
        // Used to refuse demoting the last admin: without one, nobody can grant rights
        // any more and the system can only be repaired by hand in SQLite.
        let s = st().await;
        with_account(&s, "lena").await;
        with_account(&s, "alice").await;
        s.set_user_role("lena", &level(&s, hlb_types::Role::Admin).await, None)
            .await
            .expect("role");

        assert!(
            !s.has_other_admin("lena").await.expect("account"),
            "they are the only one"
        );

        s.set_user_role("alice", &level(&s, hlb_types::Role::Admin).await, None)
            .await
            .expect("role");
        assert!(
            s.has_other_admin("lena").await.expect("account"),
            "alice takes over"
        );
    }

    #[tokio::test]
    async fn audited_actions_are_retrievable_in_order() {
        let s = st().await;
        s.audit(
            "cli",
            hlb_types::Role::Admin,
            "install",
            "gitea",
            "ok",
            None,
        )
        .await
        .unwrap();
        s.audit(
            "lena",
            hlb_types::Role::Operator,
            "purge",
            "vikunja",
            "refused",
            Some("insufficient role"),
        )
        .await
        .unwrap();

        let t = s.audit_trail(10).await.unwrap();
        assert_eq!(t.len(), 2);
        // Newest first: that is what you want to see during an incident.
        assert_eq!(t[0].action, "purge");
        assert_eq!(t[0].outcome, "refused");
    }

    #[tokio::test]
    async fn refusals_are_audited_too() {
        // 🔴 A refused attempt is at least as interesting as a successful one: it
        // signals a misconfigured access, or an intrusion.
        let s = st().await;
        s.audit(
            "unknown",
            hlb_types::Role::Viewer,
            "purge",
            "gitea",
            "refused",
            None,
        )
        .await
        .unwrap();
        assert_eq!(s.audit_trail(10).await.unwrap()[0].outcome, "refused");
    }

    #[tokio::test]
    async fn a_failure_does_not_push_back_the_schedule() {
        // 🔴 Otherwise a broken backup would happen less and less often.
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();
        s.add_volume("gitea", "gitea-data", "/data", true, false)
            .await
            .unwrap();

        assert_eq!(s.backup_age("gitea").await.unwrap(), None);

        s.record_backup("gitea", "volume", None, Some("disk full"))
            .await
            .unwrap();
        assert_eq!(
            s.backup_age("gitea").await.unwrap(),
            None,
            "a failure does not count as a success"
        );

        s.record_backup("gitea", "volume", Some("abc"), None)
            .await
            .unwrap();
        assert!(s.backup_age("gitea").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn the_snapshot_to_verify_is_a_volumes_on_a_destination_given() {
        // 🔴 Found by review: the newest row of ANY kind was verified — a dump, read
        // back from `--backup-repo` while it lived on the off-site — and the app's
        // volumes were then said verified.
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();

        s.record_backup_to("gitea", "volume", "nas", Some("old"), None)
            .await
            .unwrap();
        s.record_backup_to("gitea", "volume", "nas", None, Some("failure"))
            .await
            .unwrap();
        s.record_backup_to("gitea", "volume", "nas", Some("recent"), None)
            .await
            .unwrap();
        s.record_backup_to("gitea", "volume", "elsewhere", Some("not-asked"), None)
            .await
            .unwrap();
        s.record_backup_to("gitea", "sql-dump", "nas", Some("a-dump"), None)
            .await
            .unwrap();

        assert_eq!(
            s.latest_snapshot("gitea", backup_kind::VOLUME, &["nas".to_string()])
                .await
                .unwrap(),
            Some(("recent".to_string(), "nas".to_string()))
        );
        assert_eq!(
            s.latest_snapshot("gitea", backup_kind::VOLUME, &[])
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn a_verification_failed_after_a_success_is_known() {
        // 🔴 Only successes were read: a restore that failed last night left the app
        // "verified" by the one that worked a week ago.
        let s = st().await;
        assert!(!s.last_verification_failed("gitea").await.unwrap());
        s.record_verification("gitea", "abc", true, None)
            .await
            .unwrap();
        assert!(!s.last_verification_failed("gitea").await.unwrap());
        s.record_verification("gitea", "def", false, Some("content differs"))
            .await
            .unwrap();
        assert!(s.last_verification_failed("gitea").await.unwrap());
        s.record_verification("gitea", "ghi", true, None)
            .await
            .unwrap();
        assert!(!s.last_verification_failed("gitea").await.unwrap());
    }

    #[tokio::test]
    async fn verifications_track_only_successes() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();

        s.record_verification("gitea", "abc", false, Some("content differs"))
            .await
            .unwrap();
        assert_eq!(
            s.seconds_since_last_verification("gitea").await.unwrap(),
            None,
            "a failed verification proves nothing"
        );

        s.record_verification("gitea", "abc", true, None)
            .await
            .unwrap();
        assert!(s
            .seconds_since_last_verification("gitea")
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn volumes_are_recorded_with_their_real_path() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();

        s.add_volume(
            "gitea",
            "gitea-data",
            "/var/lib/docker/volumes/gitea-data/_data",
            true,
            false,
        )
        .await
        .unwrap();
        // A cache: not backed up.
        s.add_volume("gitea", "gitea-cache", "/ailleurs", false, false)
            .await
            .unwrap();

        let v = s.volumes_to_backup("gitea").await.unwrap();
        assert_eq!(v.len(), 1, "only the volume to back up must come back");
        assert_eq!(v[0].0, "gitea-data");
        assert!(v[0].1.ends_with("/_data"));
    }

    #[tokio::test]
    async fn recording_a_volume_twice_updates_it() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();
        s.add_volume("gitea", "d", "/old", true, false)
            .await
            .unwrap();
        s.add_volume("gitea", "d", "/new_one", true, false)
            .await
            .unwrap();

        let v = s.volumes_to_backup("gitea").await.unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, "/new_one");
    }

    #[tokio::test]
    async fn the_resolved_digest_is_frozen_in_the_manifest() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();
        assert!(s
            .app_manifest("gitea")
            .await
            .unwrap()
            .spec
            .image
            .digest
            .is_none());

        s.set_app_digest("gitea", "sha256:abc").await.unwrap();

        let m = s.app_manifest("gitea").await.unwrap();
        assert_eq!(m.spec.image.digest.as_deref(), Some("sha256:abc"));
        // The digest is what gets deployed, not the tag.
        assert_eq!(m.spec.image.reference(), "a/b:1@sha256:abc");
    }

    #[tokio::test]
    async fn verifying_a_guide_unblocks_it() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();
        s.add_guide("gitea", "admin", "create the admin", true)
            .await
            .unwrap();

        assert_eq!(s.unverified_blocking("gitea").await.unwrap(), 1);
        assert!(s.verify_guide("gitea", "admin").await.unwrap());
        assert_eq!(s.unverified_blocking("gitea").await.unwrap(), 0);

        // A second acknowledgement: nothing to do, no error.
        assert!(!s.verify_guide("gitea", "admin").await.unwrap());
        assert!(s.pending_guides().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn deleting_an_app_cascades() {
        let s = st().await;
        s.upsert_app("gitea", &manifest("gitea"), None)
            .await
            .unwrap();
        s.record_plan("gitea", &[("A".into(), "a".into())])
            .await
            .unwrap();
        s.add_guide("gitea", "x", "y", true).await.unwrap();

        sqlx::query("DELETE FROM apps WHERE name = 'gitea'")
            .execute(&s.pool)
            .await
            .unwrap();

        assert!(s.plan_actions("gitea").await.unwrap().is_empty());
        assert!(s.pending_guides().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_day_with_no_sample_is_absent_not_operational() {
        // 🔴 "An empty series is not a zero series": a day nothing recorded must come
        // back `None`, never silently read as `Operational`.
        let s = st().await;
        s.record_uptime_sample("gitea", hlb_api::ServiceState::Operational)
            .await
            .unwrap();

        let history = s.uptime_history("gitea", 3).await.unwrap();
        assert_eq!(history.len(), 3, "one row per day in the window");
        // Today (the last entry) has the one sample; the two days before have none.
        assert_eq!(history[2].1, Some(hlb_api::ServiceState::Operational));
        assert_eq!(history[0].1, None);
        assert_eq!(history[1].1, None);

        // And a service that never reported anything is absent on every day.
        let never = s.uptime_history("ghost", 3).await.unwrap();
        assert!(never.iter().all(|(_, state)| state.is_none()));
    }

    #[tokio::test]
    async fn the_worst_sample_of_the_day_wins() {
        // 🔴 A day is summarised by its WORST state — same discipline as backup
        // freshness: the summary must not contradict a detail that would show a real
        // outage happened that day.
        let s = st().await;
        s.record_uptime_sample("gitea", hlb_api::ServiceState::Operational)
            .await
            .unwrap();
        s.record_uptime_sample("gitea", hlb_api::ServiceState::Unavailable)
            .await
            .unwrap();
        s.record_uptime_sample("gitea", hlb_api::ServiceState::Degraded)
            .await
            .unwrap();

        let history = s.uptime_history("gitea", 1).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].1, Some(hlb_api::ServiceState::Unavailable));
    }

    #[tokio::test]
    async fn a_leaf_expiry_is_kept_per_service_and_forgotten_on_none() {
        let s = st().await;
        assert!(s.leaf_expiries().await.unwrap().is_empty());
        s.set_leaf_expiry("hlb-agent", Some(1_800_000_000))
            .await
            .unwrap();
        s.set_leaf_expiry("hlb-controller", Some(1_700_000_000))
            .await
            .unwrap();
        s.set_leaf_expiry("hlb-agent", Some(1_900_000_000))
            .await
            .unwrap();
        assert_eq!(
            s.leaf_expiries().await.unwrap(),
            [
                ("hlb-agent".to_string(), 1_900_000_000),
                ("hlb-controller".to_string(), 1_700_000_000)
            ]
        );
        s.set_leaf_expiry("hlb-controller", None).await.unwrap();
        assert_eq!(s.leaf_expiries().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_step_attested_before_its_install_is_handled_when_the_install_records_it() {
        let s = State::in_memory().await.unwrap();
        s.attest_ahead("gitea", "dns-record", true).await.unwrap();
        // Read by the preflight, before any row of the app exists.
        assert_eq!(s.verified_guides("gitea").await.unwrap(), ["dns-record"]);

        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            "apiVersion: hlb/v1\nkind: App\nmetadata: { name: gitea }\n\
             spec:\n  image: { repo: a/b, tag: \"1\" }\n",
        )
        .unwrap();
        s.upsert_app("gitea", &m, None).await.unwrap();
        s.add_guide("gitea", "dns-record", "DNS", true)
            .await
            .unwrap();
        s.add_guide("gitea", "other", "Other", true).await.unwrap();

        assert_eq!(
            s.unverified_blocking("gitea").await.unwrap(),
            1,
            "only the other"
        );
        let handled = s.verified_guide_ages("gitea").await.unwrap();
        assert_eq!(handled.len(), 1);
        assert!(handled[0].2, "forced, as the person said");
    }

    #[tokio::test]
    async fn pruning_only_removes_what_is_actually_old() {
        let s = st().await;
        s.record_uptime_sample("gitea", hlb_api::ServiceState::Operational)
            .await
            .unwrap();
        // A second sample, backdated well past any reasonable retention window.
        s.record_uptime_sample("gitea", hlb_api::ServiceState::Unavailable)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE service_uptime_samples SET at = '2020-01-01 00:00:00' \
             WHERE state = 'unavailable'",
        )
        .execute(&s.pool)
        .await
        .unwrap();

        let removed = s.prune_uptime_samples(90).await.unwrap();
        assert_eq!(removed, 1, "only the backdated sample is old enough");

        // The fresh sample survives, and is what the history now shows.
        let history = s.uptime_history("gitea", 1).await.unwrap();
        assert_eq!(history[0].1, Some(hlb_api::ServiceState::Operational));
    }

    #[test]
    fn the_civil_date_matches_known_epochs() {
        // Same known epochs `hlb-controller::runbook`'s own version is checked
        // against — this is the same algorithm, time-of-day dropped.
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(946_684_800), "2000-01-01");
        assert_eq!(civil_date(1_787_097_600), "2026-08-19");
        // And just before midnight the day before must not roll over early.
        assert_eq!(civil_date(1_787_097_600 - 1), "2026-08-18");
    }

    #[test]
    fn severity_orders_a_real_outage_above_a_planned_one() {
        // An announced maintenance is disruptive on purpose; an unannounced outage is
        // worse. The ordering `uptime_history` picks "the worst of the day" by must
        // agree.
        use hlb_api::ServiceState::*;
        assert!(severity(Unavailable) > severity(Degraded));
        assert!(severity(Degraded) > severity(Maintenance));
        assert!(severity(Maintenance) > severity(Operational));
    }
}
