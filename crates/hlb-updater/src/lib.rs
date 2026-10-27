//! The update pipeline.
//!
//! ```text
//! 1. Watch        new digest? new version?
//! 2. Policy       does the channel allow this jump?
//! 2b. Maturation  published long enough ago?
//! 3. Window       are we inside the maintenance window?
//! 4. Backup       🔴 BEFORE anything else
//! 5. Deploy       start-first, parallelism 1
//! 6. Verify       healthcheck
//! 7a. OK          freeze the new digest
//! 7b. KO          automatic rollback by Swarm
//! ```
//!
//! 🔴 **This module's most important rule**: if the manifest promises a prior backup
//! and no backup provider is wired in, the update is **refused**. A schema migration is
//! not reversible by an image rollback - claiming to have backed up would be the worst
//! possible lie.

pub mod apply;
pub mod catalog;
pub mod scan;
pub mod window;

pub use apply::{apply, UpdateOutcome};
pub use scan::{audit, Report as ScanReport, Verdict};
pub use window::MaintenanceWindow;

use std::collections::BTreeMap;

use hlb_registry::{best_upgrade, ImageRef, RegistryClient, Version};
use hlb_state::State;
use hlb_types::{Image, Manifest, UpdateChannel};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("parsing the image: {0}")]
    Scan(String),

    #[error(transparent)]
    State(#[from] hlb_state::Error),

    #[error(transparent)]
    Registry(#[from] hlb_registry::Error),

    #[error(transparent)]
    Window(#[from] window::ParseError),

    #[error(transparent)]
    Orchestrator(#[from] hlb_orchestrator::Error),

    #[error(
        "\"{app}\" requires a backup before updating, but no \
             backup provider is configured - update refused"
    )]
    BackupRequired { app: String },

    #[error("\"{app}\": {why} - update refused")]
    Immature { app: String, why: String },
}

pub type Result<T> = std::result::Result<T, Error>;

/// What differs between the deployed version and the available one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateKind {
    /// Same tag, different digest: the publisher republished (rolling tags).
    DigestOnly,
    /// A new version, allowed by the channel.
    NewVersion { to_tag: String },
    /// The catalog names another image than the one installed: its maintainers moved
    /// the app (`v1` → `v2`), whatever the channel allows on its own.
    Catalog { repo: String, tag: String },
    /// The app keeps its image; the catalog moved one of its companions.
    Companions,
}

/// A companion the catalog moved, switched before its app — the order it was
/// installed in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionMove {
    /// Its name in the manifest.
    pub name: String,
    /// Its Swarm service.
    pub service: String,
    /// The catalog's image, digest included.
    pub to: Image,
    pub maturity: Maturity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub app: String,
    pub kind: UpdateKind,
    pub from_tag: String,
    pub from_digest: Option<String>,
    pub to_digest: String,
    /// Can the update be applied **now**?
    pub in_window: bool,
    /// Does the manifest require a prior backup?
    pub needs_backup: bool,
    /// How long ago the image it moves to was published, against the manifest's
    /// `maturationDays` — the youngest of its companions' included.
    pub maturity: Maturity,
    /// The companions moving with it.
    pub companions: Vec<CompanionMove>,
}

/// Whether an image has been published long enough to be deployed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Maturity {
    Mature,
    /// Published, and proposed from `ready_at` (Unix seconds).
    Young {
        ready_at: i64,
    },
    /// 🔴 The image does not say when it was built. Not mature: a missing date is not
    /// an old image, and reading it as one would let any undated build straight in.
    Undated,
}

impl Maturity {
    pub fn of(published: Option<i64>, days: u32, now: i64) -> Self {
        match published {
            None => Self::Undated,
            Some(at) => {
                let ready_at = at + i64::from(days) * 86_400;
                if now >= ready_at {
                    Self::Mature
                } else {
                    Self::Young { ready_at }
                }
            }
        }
    }

    pub fn is_mature(&self) -> bool {
        matches!(self, Self::Mature)
    }

    /// The less mature of two: what a move of several images waits for.
    pub fn or_younger(self, other: Self) -> Self {
        match (self, other) {
            (Self::Undated, _) | (_, Self::Undated) => Self::Undated,
            (Self::Young { ready_at: a }, Self::Young { ready_at: b }) => {
                Self::Young { ready_at: a.max(b) }
            }
            (y @ Self::Young { .. }, Self::Mature) | (Self::Mature, y @ Self::Young { .. }) => y,
            (Self::Mature, Self::Mature) => Self::Mature,
        }
    }

    /// Why it is not proposed yet, `None` when it is.
    pub fn refusal(&self, now: i64) -> Option<String> {
        match self {
            Self::Mature => None,
            Self::Young { ready_at } => {
                let on = chrono::DateTime::from_timestamp(*ready_at, 0)
                    .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
                    .unwrap_or_default();
                let left = match (*ready_at - now).max(0) / 86_400 {
                    0 => "within a day".to_string(),
                    1 => "in 1 day".to_string(),
                    n => format!("in {n} days"),
                };
                Some(format!("published too recently - mature on {on}, {left}"))
            }
            Self::Undated => Some("the image does not say when it was built".into()),
        }
    }
}

impl Candidate {
    pub fn describe(&self) -> String {
        let own = match &self.kind {
            UpdateKind::DigestOnly => {
                format!("{}: {} republished", self.app, self.from_tag)
            }
            UpdateKind::NewVersion { to_tag } => {
                format!("{} : {} → {to_tag}", self.app, self.from_tag)
            }
            UpdateKind::Catalog { repo, tag } => {
                format!(
                    "{}: {} → {repo}:{tag}, from the catalog",
                    self.app, self.from_tag
                )
            }
            UpdateKind::Companions => format!("{}: its companions, from the catalog", self.app),
        };
        let with: Vec<String> = self
            .companions
            .iter()
            .map(|c| format!("{} → {}", c.name, c.to.tag))
            .collect();
        if with.is_empty() {
            own
        } else {
            format!("{own} ({})", with.join(", "))
        }
    }
}

/// The image the catalog moved an installation to, if it did — with the catalog's own
/// digest, the one it was tried with.
///
/// 🔴 `hlb upgrade` leaves images to this command, and this command used to read the
/// installed tag alone: a catalog moving PocketID from `v1` to `v2` was announced as
/// `hlb update`'s to do, and `hlb update` only ever looked for a newer `v1`. The move
/// is proposed on any channel — `pin` stops automatic updates, not a person's.
///
/// Never downward: an installation `hlb update` took to 1.24.7 is ahead of a catalog
/// still naming 1.24, not behind it. Nor for the digest alone — the registry's own
/// watch proposes a newer build of the tag, and the catalog's may be the older one.
pub fn catalog_move(installed: &Image, catalog: Option<&Image>) -> Option<Image> {
    let c = catalog?;
    // The same build under another name changes nothing that runs.
    let same_build = c.digest.is_some() && c.digest == installed.digest;
    if same_build || (c.repo == installed.repo && c.tag == installed.tag) {
        return None;
    }
    if c.repo == installed.repo {
        if let (Some(from), Some(to)) = (Version::parse(&installed.tag), Version::parse(&c.tag)) {
            if from.same_flavor(&to) && !to.is_newer_than(&from) {
                return None;
            }
        }
    }
    Some(c.clone())
}

/// What a pass over the registries found.
#[derive(Debug, Default)]
pub struct Checked {
    pub candidates: Vec<Candidate>,
    /// The apps whose registry could not be read, with why.
    ///
    /// 🔴 One unreadable image used to fail the whole pass: a catalog naming an image
    /// not published yet hid every other app's update behind a 401. Each app is
    /// checked on its own, and what could not be read is SAID — dropped, it would read
    /// as "up to date".
    pub unreadable: Vec<(String, String)>,
}

/// Queries the registries for every installed app.
///
/// `catalog` is the image each app's catalog manifest names. Read-only: nothing is
/// modified, nothing is deployed.
/// `now` is the local time the maintenance windows are read in, `at` the same instant in
/// Unix seconds, which maturation counts in.
pub async fn check<T: chrono::Datelike + chrono::Timelike>(
    state: &State,
    registry: &RegistryClient,
    now: &T,
    at: i64,
    catalog: &BTreeMap<String, Manifest>,
) -> Result<Checked> {
    let mut out = Checked::default();

    for (app, status) in state.installed_apps().await? {
        // Nothing is proposed for a failed or installing app: there is a more urgent
        // problem to deal with.
        if status != "running" && status != "partial" {
            continue;
        }

        let m = state.app_manifest(&app).await?;
        match candidate(registry, now, at, &app, &m, catalog.get(&app)).await {
            Ok(Some(c)) => out.candidates.push(c),
            Ok(None) => {}
            Err(e) => out.unreadable.push((app, e.to_string())),
        }
    }

    Ok(out)
}

/// The update one app has, if any: its own image, its companions', or both.
async fn candidate<T: chrono::Datelike + chrono::Timelike>(
    registry: &RegistryClient,
    now: &T,
    at: i64,
    app: &str,
    m: &Manifest,
    catalog: Option<&Manifest>,
) -> Result<Option<Candidate>> {
    let days = m.spec.update.maturation_days;
    let companions = companion_moves(registry, app, m, catalog, days, at).await?;
    let own = app_move(registry, at, m, catalog.map(|c| &c.spec.image)).await?;

    let (kind, to_digest, mut maturity) = match own {
        Some(o) => o,
        None if companions.is_empty() => return Ok(None),
        // The app keeps its image; only what runs beside it moves.
        None => (
            UpdateKind::Companions,
            m.spec.image.digest.clone().unwrap_or_default(),
            Maturity::Mature,
        ),
    };
    for c in &companions {
        maturity = maturity.or_younger(c.maturity);
    }

    let in_window = match &m.spec.update.window {
        Some(w) => MaintenanceWindow::parse(w)?.is_open_at(now),
        // With no declared window, the update can be applied at any time.
        None => true,
    };

    Ok(Some(Candidate {
        app: app.to_string(),
        kind,
        from_tag: m.spec.image.tag.clone(),
        from_digest: m.spec.image.digest.clone(),
        to_digest,
        in_window,
        needs_backup: m.spec.update.backup_before,
        maturity,
        companions,
    }))
}

/// The app's own image's move, dated: the catalog's, else what its channel allows.
async fn app_move(
    registry: &RegistryClient,
    at: i64,
    m: &Manifest,
    catalog: Option<&Image>,
) -> Result<Option<(UpdateKind, String, Maturity)>> {
    let channel = m.spec.update.channel;
    let image = ImageRef::parse(&format!("{}:{}", m.spec.image.repo, m.spec.image.tag));

    // The `pin` channel does not stop the watch: we want to be *informed* about a
    // new Vaultwarden release, just not to apply it automatically.
    let (kind, target) = if let Some(c) = catalog_move(&m.spec.image, catalog) {
        let target = ImageRef::parse(&c.reference());
        (
            UpdateKind::Catalog {
                repo: c.repo,
                tag: c.tag,
            },
            target,
        )
    } else {
        let candidate_tag = if channel == UpdateChannel::Pin {
            None
        } else {
            let tags = registry.list_tags(&image).await?;
            best_upgrade(&m.spec.image.tag, &tags, channel)
        };
        match candidate_tag {
            Some(t) => {
                let target = ImageRef::parse(&format!("{}:{t}", m.spec.image.repo));
                (UpdateKind::NewVersion { to_tag: t }, target)
            }
            None => (UpdateKind::DigestOnly, image.clone()),
        }
    };

    // The catalog's move carries the digest it was tried with; anything else is what
    // the tag names today.
    let to_digest = match &target.digest {
        Some(d) => d.clone(),
        None => registry.resolve_digest(&target).await?,
    };

    // Nothing new: same tag, same digest.
    if kind == UpdateKind::DigestOnly && m.spec.image.digest.as_deref() == Some(&to_digest) {
        return Ok(None);
    }

    // Dated by the digest that would run, not by the tag, which may have moved since.
    let dated = ImageRef {
        digest: Some(to_digest.clone()),
        ..target
    };
    let published = registry.created(&dated).await?;
    if matches!(kind, UpdateKind::Catalog { .. })
        && older_than_running(registry, &m.spec.image, published).await
    {
        return Ok(None);
    }
    Ok(Some((
        kind,
        to_digest,
        Maturity::of(published, m.spec.update.maturation_days, at),
    )))
}

/// The companions the catalog moved, each with the catalog's own digest.
///
/// 🔴 `hlb update` used to move the app's image alone, and `hlb upgrade` keeps every
/// image as installed: a catalog moving Immich to 3.3.1 would have run its server in
/// 3.3.1 beside a machine-learning service left in 3.1.0, for good.
async fn companion_moves(
    registry: &RegistryClient,
    app: &str,
    m: &Manifest,
    catalog: Option<&Manifest>,
    days: u32,
    at: i64,
) -> Result<Vec<CompanionMove>> {
    let Some(catalog) = catalog else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for installed in &m.spec.companions {
        let Some(c) = catalog
            .spec
            .companions
            .iter()
            .find(|c| c.name == installed.name)
        else {
            continue;
        };
        let Some(mut to) = catalog_move(&installed.image, Some(&c.image)) else {
            continue;
        };
        let digest = match &to.digest {
            Some(d) => d.clone(),
            None => {
                registry
                    .resolve_digest(&ImageRef::parse(&to.reference()))
                    .await?
            }
        };
        to.digest = Some(digest.clone());
        let published = registry.created(&ImageRef::parse(&to.reference())).await?;
        if older_than_running(registry, &installed.image, published).await {
            continue;
        }
        out.push(CompanionMove {
            name: installed.name.clone(),
            service: installed.service(app),
            to,
            maturity: Maturity::of(published, days, at),
        });
    }
    Ok(out)
}

/// 🔴 Never downward, where the versions cannot say it: an installation on `v2` runs
/// whatever `v2` named the day it was installed, and a catalog pinning `v2.29.0` would
/// take it back three releases while `catalog_move` read 2.29 as later than 2. Unknown
/// either side is not older: the version comparison stands alone then.
async fn older_than_running(
    registry: &RegistryClient,
    running: &Image,
    published: Option<i64>,
) -> bool {
    let (Some(to), Some(_)) = (published, &running.digest) else {
        return false;
    };
    matches!(
        registry.created(&ImageRef::parse(&running.reference())).await,
        Ok(Some(from)) if to < from
    )
}

/// What a backup engine must provide for an update requiring a prior backup to be
/// allowed.
#[async_trait::async_trait]
pub trait BackupProvider: Send + Sync {
    /// Takes a snapshot of the app and returns its id.
    async fn snapshot(&self, app: &str) -> std::result::Result<String, String>;
}

/// Checks an update is allowed to be applied right now.
///
/// Separate from execution so it is testable without an orchestrator. `before_maturity`
/// is a person's decision — an urgent security fix published yesterday — never a
/// default.
pub fn authorize(
    candidate: &Candidate,
    backup: Option<&dyn BackupProvider>,
    force_window: bool,
    before_maturity: bool,
    now: i64,
) -> Result<()> {
    if candidate.needs_backup && backup.is_none() {
        return Err(Error::BackupRequired {
            app: candidate.app.clone(),
        });
    }
    if let Some(why) = candidate.maturity.refusal(now) {
        if !before_maturity {
            return Err(Error::Immature {
                app: candidate.app.clone(),
                why,
            });
        }
    }
    if !candidate.in_window && !force_window {
        // Not an error: simply not now. The caller filters on this.
        tracing::debug!(app = %candidate.app, "outside the maintenance window");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(needs_backup: bool) -> Candidate {
        Candidate {
            app: "gitea".into(),
            kind: UpdateKind::NewVersion {
                to_tag: "1.25".into(),
            },
            from_tag: "1.24".into(),
            from_digest: Some("sha256:old".into()),
            to_digest: "sha256:new".into(),
            in_window: true,
            needs_backup,
            maturity: Maturity::Mature,
            companions: Vec::new(),
        }
    }

    #[test]
    fn an_update_requiring_backup_is_refused_without_a_provider() {
        // 🔴 The heart of it: a schema migration is not reversible by an image
        // rollback. Without a backup, we do not play.
        let err = authorize(&candidate(true), None, false, false, 0).unwrap_err();
        assert!(matches!(err, Error::BackupRequired { .. }), "{err}");
    }

    #[test]
    fn an_update_not_requiring_backup_passes() {
        assert!(authorize(&candidate(false), None, false, false, 0).is_ok());
    }

    #[test]
    fn an_image_younger_than_its_maturation_is_refused_unless_a_person_says() {
        const DAY: i64 = 86_400;
        let published = 100 * DAY;
        let mut c = candidate(false);
        let now = published + 6 * DAY + DAY / 2;
        c.maturity = Maturity::of(Some(published), 7, now);
        let err = authorize(&c, None, false, false, now).unwrap_err();
        assert!(err.to_string().contains("within a day"), "{err}");
        let err = authorize(&c, None, false, false, published + 4 * DAY).unwrap_err();
        assert!(err.to_string().contains("in 3 days"), "{err}");
        assert!(authorize(&c, None, false, true, now).is_ok());

        assert!(Maturity::of(Some(published), 7, published + 7 * DAY).is_mature());
        assert!(!Maturity::of(Some(published), 14, published + 7 * DAY).is_mature());
    }

    #[test]
    fn a_move_of_several_images_waits_for_the_youngest() {
        let young = |ready_at| Maturity::Young { ready_at };
        assert_eq!(Maturity::Mature.or_younger(young(5)), young(5));
        assert_eq!(young(9).or_younger(young(5)), young(9));
        assert_eq!(young(9).or_younger(Maturity::Undated), Maturity::Undated);
        assert_eq!(
            Maturity::Mature.or_younger(Maturity::Mature),
            Maturity::Mature
        );
    }

    #[test]
    fn a_companion_is_described_with_its_app() {
        let mut c = candidate(false);
        c.companions.push(CompanionMove {
            name: "machine-learning".into(),
            service: "gitea-machine-learning".into(),
            to: image(
                "ghcr.io/immich-app/immich-machine-learning",
                "v3.3.1",
                Some("sha256:b"),
            ),
            maturity: Maturity::Mature,
        });
        assert_eq!(
            c.describe(),
            "gitea : 1.24 → 1.25 (machine-learning → v3.3.1)"
        );
    }

    #[test]
    fn an_undated_image_is_not_mature() {
        // 🔴 A build that does not say when it was made is not fifty years old.
        let m = Maturity::of(None, 7, i64::MAX);
        assert_eq!(m, Maturity::Undated);
        let mut c = candidate(false);
        c.maturity = m;
        let err = authorize(&c, None, false, false, 0).unwrap_err();
        assert!(err.to_string().contains("does not say when"), "{err}");
    }

    #[test]
    fn the_description_says_what_changes() {
        assert_eq!(candidate(false).describe(), "gitea : 1.24 → 1.25");

        let mut c = candidate(false);
        c.kind = UpdateKind::DigestOnly;
        assert_eq!(c.describe(), "gitea: 1.24 republished");
    }

    fn image(repo: &str, tag: &str, digest: Option<&str>) -> Image {
        Image {
            repo: repo.into(),
            tag: tag.into(),
            digest: digest.map(Into::into),
            built_here: false,
        }
    }

    #[test]
    fn a_catalog_moving_the_tag_is_an_update_to_its_image() {
        let installed = image("ghcr.io/pocket-id/pocket-id", "v1", Some("sha256:old"));
        let catalog = image("ghcr.io/pocket-id/pocket-id", "v2", Some("sha256:tried"));
        // With the digest the catalog was tried with, not whatever `v2` names today.
        assert_eq!(
            catalog_move(&installed, Some(&catalog)),
            Some(image(
                "ghcr.io/pocket-id/pocket-id",
                "v2",
                Some("sha256:tried")
            ))
        );
        // A new repository is a move too, deployed from that repository.
        let moved = image("codeberg.org/forgejo/forgejo", "v2", None);
        assert_eq!(
            catalog_move(&installed, Some(&moved)).map(|i| i.repo),
            Some("codeberg.org/forgejo/forgejo".into())
        );
    }

    #[test]
    fn the_catalogs_own_tag_or_none_moves_nothing() {
        // Only the digest differs: the catalog names a tag, the install resolved it.
        let installed = image("vikunja/vikunja", "0.24", Some("sha256:resolved"));
        let catalog = image("vikunja/vikunja", "0.24", None);
        assert_eq!(catalog_move(&installed, Some(&catalog)), None);
        // An app the catalog no longer carries keeps what it runs.
        assert_eq!(catalog_move(&installed, None), None);
    }

    #[test]
    fn a_catalog_behind_the_installation_moves_nothing() {
        // `hlb update` took it to 1.24.7; the catalog still names 1.24.
        let installed = image("gitea/gitea", "1.24.7", Some("sha256:new"));
        let catalog = image("gitea/gitea", "1.24", Some("sha256:older"));
        assert_eq!(catalog_move(&installed, Some(&catalog)), None);
        let catalog = image("gitea/gitea", "1.24.3", Some("sha256:older"));
        assert_eq!(catalog_move(&installed, Some(&catalog)), None);

        // Forward is a move, a precision of its own included: v0.16 → v0.16.27.
        let installed = image("stalwartlabs/stalwart", "v0.16", Some("sha256:a"));
        let catalog = image("stalwartlabs/stalwart", "v0.16.27", Some("sha256:b"));
        assert!(catalog_move(&installed, Some(&catalog)).is_some());
        // The same build renamed — `v2` written `v2.18.0` — runs nothing new.
        let renamed = image("ghcr.io/pocket-id/pocket-id", "v2.18.0", Some("sha256:a"));
        let installed_v2 = image("ghcr.io/pocket-id/pocket-id", "v2", Some("sha256:a"));
        assert_eq!(catalog_move(&installed_v2, Some(&renamed)), None);
        // Another flavour cannot be compared: the catalog's maintainers chose it.
        let installed = image("valkey/valkey", "8-alpine", Some("sha256:a"));
        let catalog = image("valkey/valkey", "8.1.10-alpine", Some("sha256:b"));
        assert!(catalog_move(&installed, Some(&catalog)).is_some());
    }
}
