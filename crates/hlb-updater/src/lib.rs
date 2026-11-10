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
pub mod disks;
pub mod firmware;
pub mod flaws;
pub mod grype;
pub mod host;
pub mod policy;
pub mod reboot;
pub mod run;
pub mod scan;
pub mod undo;
pub mod window;

pub use apply::{apply, UpdateOutcome};
pub use scan::{Report as ScanReport, Verdict};
pub use window::MaintenanceWindow;

use std::collections::BTreeMap;

use hlb_registry::{best_upgrade, ImageRef, RegistryClient, Version};
use hlb_state::State;
use hlb_types::{Image, ImageSigner, Manifest, UpdateChannel};

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
    /// Every image that will start, the companions' included, as the digest that will
    /// run, each with the signer it is held to.
    ///
    /// 🔴 The signer is the CATALOG's: an installation's frozen manifest predates any
    /// signer declared since, and would let an unsigned digest through as "not
    /// checked". Matched by repository — a signer is one publisher's.
    pub fn to_verify(
        &self,
        installed: &Image,
        catalog: Option<&Image>,
    ) -> Vec<(String, Option<ImageSigner>)> {
        let (repo, tag) = match &self.kind {
            UpdateKind::NewVersion { to_tag } => (installed.repo.as_str(), to_tag.as_str()),
            UpdateKind::Catalog { repo, tag } => (repo.as_str(), tag.as_str()),
            UpdateKind::DigestOnly | UpdateKind::Companions => {
                (installed.repo.as_str(), installed.tag.as_str())
            }
        };
        let signer = match catalog {
            Some(c) if c.repo == repo => c.signed_by.clone(),
            _ if installed.repo == repo => installed.signed_by.clone(),
            _ => None,
        };
        let own = (self.kind != UpdateKind::Companions)
            .then(|| (format!("{repo}:{tag}@{}", self.to_digest), signer));
        own.into_iter()
            .chain(
                self.companions
                    .iter()
                    .map(|m| (m.to.reference(), m.to.signed_by.clone())),
            )
            .collect()
    }

    /// What each image [`Candidate::to_verify`] names replaces, in its order: what runs
    /// now, by digest — a scan compares the two. `None` when nothing pinned runs before it.
    pub fn replaced(&self, installed: &hlb_types::manifest::Spec) -> Vec<Option<String>> {
        let pinned = |i: &Image| i.is_pinned().then(|| i.reference());
        let own = (self.kind != UpdateKind::Companions).then(|| pinned(&installed.image));
        own.into_iter()
            .chain(self.companions.iter().map(|m| {
                installed
                    .companions
                    .iter()
                    .find(|c| c.name == m.name)
                    .and_then(|c| pinned(&c.image))
            }))
            .collect()
    }

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

/// Why the catalog's image cannot move alone, if it cannot: its manifest renamed the
/// app's own volumes too.
///
/// 🔴 The catalog's image was tried with the catalog's manifest. Stalwart 1.0 opens a
/// new store (`data-v1`) because it refuses a 0.16 one: moved alone, its image started
/// over the old volume and the house had no mail. The new volumes come with `hlb
/// upgrade`, which says how the data reaches them.
pub fn held_move(installed: &Manifest, catalog: &Manifest) -> Option<String> {
    catalog_move(&installed.spec.image, Some(&catalog.spec.image))?;
    let (before, after) = (own_volumes(installed), own_volumes(catalog));
    if before == after {
        return None;
    }
    Some(format!(
        "the catalog moves it to {}:{} with volumes of its own ({} → {}): its image waits \
         for `hlb upgrade {}`",
        catalog.spec.image.repo,
        catalog.spec.image.tag,
        before.join(", "),
        after.join(", "),
        catalog.metadata.name
    ))
}

fn own_volumes(m: &Manifest) -> Vec<&str> {
    let mut v: Vec<&str> = m
        .spec
        .requires
        .iter()
        .filter_map(|c| {
            if let hlb_types::Capability::Storage {
                name, owner: None, ..
            } = c
            {
                Some(name.as_str())
            } else {
                None
            }
        })
        .collect();
    v.sort_unstable();
    v
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
    /// The apps whose catalog move waits for `hlb upgrade`, with why — see
    /// [`held_move`]. Each still gets what its own channel allows meanwhile.
    pub held: Vec<(String, String)>,
}

/// Queries the registries for every installed app.
///
/// `catalog` is the image each app's catalog manifest names. Read-only: nothing is
/// modified, nothing is deployed.
/// `at` is the instant in Unix seconds: maturation counts in it, and the maintenance
/// windows read it on the house's clock.
pub async fn check(
    state: &State,
    registry: &RegistryClient,
    at: i64,
    catalog: &BTreeMap<String, Manifest>,
) -> Result<Checked> {
    check_apps(state, registry, at, catalog, None).await
}

/// [`check`], for `only` these apps when given: the registries are asked for nothing else,
/// which an hourly pass over the apps already known to wait spends little of.
pub async fn check_apps(
    state: &State,
    registry: &RegistryClient,
    at: i64,
    catalog: &BTreeMap<String, Manifest>,
    only: Option<&std::collections::BTreeSet<String>>,
) -> Result<Checked> {
    let mut out = Checked::default();
    let zone = state.timezone().await?;

    for (app, status) in state.installed_apps().await? {
        if only.is_some_and(|o| !o.contains(&app)) {
            continue;
        }
        // Nothing is proposed for a failed or installing app: there is a more urgent
        // problem to deal with.
        if status != "running" && status != "partial" {
            continue;
        }

        let m = state.app_manifest(&app).await?;
        let mut theirs = catalog.get(&app);
        if let Some(why) = theirs.and_then(|c| held_move(&m, c)) {
            out.held.push((app.clone(), why));
            theirs = None;
        }
        match candidate(state, registry, zone.as_deref(), at, &app, &m, theirs).await {
            Ok(Some(c)) => match catalog
                .get(&app)
                .and_then(|cat| policy::held_by_catalog(&c, &m, cat))
            {
                Some(why) => out.held.push((app.clone(), why)),
                None => out.candidates.push(c),
            },
            Ok(None) => {}
            Err(e) => out.unreadable.push((app, e.to_string())),
        }
    }

    Ok(out)
}

/// The daemon's daily look: what each app could move to, each image's first sighting
/// recorded. It applies nothing: what moves and when is `hlb update apply`'s.
pub async fn watch(
    state: &State,
    registry: &RegistryClient,
    catalog: &BTreeMap<String, Manifest>,
) -> Result<Checked> {
    let at = chrono::Utc::now().timestamp();
    let checked = check(state, registry, at, catalog).await?;
    note_seen(state, &checked, at).await?;
    Ok(checked)
}

/// Records when this house first saw each proposed image: no registry says when it could
/// have known, and a `hlb update check` nobody ran would otherwise date nothing.
pub async fn note_seen(state: &State, checked: &Checked, at: i64) -> Result<()> {
    for c in &checked.candidates {
        for digest in proposed_digests(c) {
            state.note_update_seen(&c.app, digest, at).await?;
        }
    }
    Ok(())
}

/// Is a manifest's maintenance window open at `at`? 🔴 Read on the house's clock (`hlb
/// config timezone`), never the process's: hlb-privd runs in a container whose clock is
/// UTC, and a Paris "sun 03:00-05:00" opened an hour or two late, on the wrong day near
/// midnight. With no window declared, an update can be applied at any time.
fn window_open(window: Option<&str>, zone: Option<&str>, at: i64) -> Result<bool> {
    Ok(match window {
        Some(w) => MaintenanceWindow::parse(w)?.is_open_at(&hlb_notify::local_datetime(zone, at)),
        None => true,
    })
}

/// What a candidate would run that does not run yet. Its `to_digest` is the image it runs
/// already when only its companions move, and it is not proposed.
fn proposed_digests(c: &Candidate) -> Vec<&str> {
    let own = (!matches!(c.kind, UpdateKind::Companions)).then_some(c.to_digest.as_str());
    own.into_iter()
        .chain(c.companions.iter().filter_map(|m| m.to.digest.as_deref()))
        .filter(|d| !d.is_empty())
        .collect()
}

/// The update one app has, if any: its own image, its companions', or both.
async fn candidate(
    state: &State,
    registry: &RegistryClient,
    zone: Option<&str>,
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

    let in_window = window_open(m.spec.update.window.as_deref(), zone, at)?;

    Ok(Some(Candidate {
        app: app.to_string(),
        kind,
        from_tag: m.spec.image.tag.clone(),
        from_digest: m.spec.image.digest.clone(),
        to_digest,
        in_window,
        needs_backup: owes_backup(state, app, m).await?,
        maturity,
        companions,
    }))
}

/// Whether an update of `app` must take a copy first: its manifest asks, and it holds
/// something to copy. A cache's only volume says `backup: false`, and its update was refused
/// for ever for lacking the copy nothing was meant to take. Known from what it declares,
/// never from a provider finding nothing: finding nothing stays a refusal.
pub async fn owes_backup(state: &State, app: &str, m: &Manifest) -> Result<bool> {
    Ok(m.spec.update.backup_before && !state.backup_kinds(app).await?.is_empty())
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
    /// Copies the app and returns every snapshot taken — volumes, buckets, dumps: an
    /// undo restores each, and the last alone names one of them.
    async fn snapshot(&self, app: &str) -> std::result::Result<Vec<String>, String>;
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

    #[test]
    fn a_maintenance_window_is_read_on_the_house_s_clock() {
        // Sunday 2026-11-08 23:30 UTC is Monday 00:30 in Paris.
        let at = 1_794_180_600;
        let monday = Some("mon 00:00-01:00");
        assert!(window_open(monday, Some("Europe/Paris"), at).expect("window"));
        assert!(!window_open(monday, None, at).expect("window"));
        assert!(window_open(None, Some("Europe/Paris"), at).expect("no window"));
    }

    #[test]
    fn what_is_proposed_is_what_would_change_and_not_what_already_runs() {
        let image = |digest: Option<&str>| Image {
            repo: "a/ml".into(),
            tag: "2".into(),
            digest: digest.map(String::from),
            built_here: false,
            signed_by: None,
        };
        let candidate = |kind, companions| Candidate {
            app: "immich".into(),
            kind,
            from_tag: "1".into(),
            from_digest: Some("sha256:runs".into()),
            to_digest: "sha256:runs".into(),
            in_window: true,
            needs_backup: false,
            maturity: Maturity::Mature,
            companions,
        };
        let companion = |digest| CompanionMove {
            name: "ml".into(),
            service: "immich-ml".into(),
            to: image(digest),
            maturity: Maturity::Mature,
        };

        let only_companion = candidate(UpdateKind::Companions, vec![companion(Some("sha256:ml"))]);
        assert_eq!(proposed_digests(&only_companion), ["sha256:ml"]);

        let own = candidate(UpdateKind::DigestOnly, vec![companion(None)]);
        assert_eq!(proposed_digests(&own), ["sha256:runs"]);
    }

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
    fn every_image_that_will_start_is_verified_against_the_catalogs_signer() {
        let signer = |repo: &str| {
            Some(ImageSigner {
                github: repo.into(),
                workflow: "release.yml".into(),
            })
        };
        // Installed before the catalog declared a signer: its frozen manifest has none.
        let installed = image("acme/gitea", "1.24", Some("sha256:old"));
        let catalog = Image {
            signed_by: signer("acme/gitea"),
            ..image("acme/gitea", "1.24", Some("sha256:catalog"))
        };
        let ml = Image {
            signed_by: signer("acme/ml"),
            ..image("acme/ml", "1.1", Some("sha256:ml"))
        };
        let mut c = candidate(false);
        c.companions.push(CompanionMove {
            name: "ml".into(),
            service: "gitea-ml".into(),
            to: ml,
            maturity: Maturity::Mature,
        });
        assert_eq!(
            c.to_verify(&installed, Some(&catalog)),
            [
                (
                    "acme/gitea:1.25@sha256:new".to_string(),
                    signer("acme/gitea")
                ),
                ("acme/ml:1.1@sha256:ml".to_string(), signer("acme/ml")),
            ]
        );
        // A signer is its publisher's: an image the catalog moved to another
        // repository is not checked against the old one's, nor the reverse.
        c.kind = UpdateKind::Catalog {
            repo: "other/gitea".into(),
            tag: "2".into(),
        };
        let frozen = Image {
            signed_by: signer("acme/gitea"),
            ..installed.clone()
        };
        assert_eq!(
            c.to_verify(&frozen, None)[0],
            ("other/gitea:2@sha256:new".into(), None)
        );
        // The companions alone: the app's own image does not start again.
        c.kind = UpdateKind::Companions;
        assert_eq!(c.to_verify(&installed, Some(&catalog)).len(), 1);
    }

    #[test]
    fn each_image_checked_is_compared_with_what_it_replaces() {
        let m: Manifest = serde_yaml_ng::from_str(
            r#"
apiVersion: hlb/v1
kind: App
metadata: { name: gitea }
spec:
  image: { repo: acme/gitea, tag: "1.24", digest: "sha256:old" }
  companions:
    - name: ml
      image: { repo: acme/ml, tag: "1.0", digest: "sha256:ml-old" }
    - name: cache
      image: { repo: acme/cache, tag: "1" }
"#,
        )
        .expect("manifest");
        let mut c = candidate(false);
        for (name, digest) in [
            ("ml", "sha256:ml"),
            ("cache", "sha256:c"),
            ("gone", "sha256:g"),
        ] {
            c.companions.push(CompanionMove {
                name: name.into(),
                service: format!("gitea-{name}"),
                to: image(&format!("acme/{name}"), "2", Some(digest)),
                maturity: Maturity::Mature,
            });
        }
        // Aligned with `to_verify`; an image running by its tag alone, or a companion
        // new to the app, has nothing to compare with.
        assert_eq!(
            c.replaced(&m.spec),
            [
                Some("acme/gitea:1.24@sha256:old".to_string()),
                Some("acme/ml:1.0@sha256:ml-old".to_string()),
                None,
                None,
            ]
        );
        assert_eq!(
            c.replaced(&m.spec).len(),
            c.to_verify(&m.spec.image, None).len()
        );
        c.kind = UpdateKind::Companions;
        assert_eq!(
            c.replaced(&m.spec)[0].as_deref(),
            Some("acme/ml:1.0@sha256:ml-old")
        );
    }

    async fn installed(requires: &str, update: &str) -> (State, Manifest) {
        let m: Manifest = serde_yaml_ng::from_str(&format!(
            r#"
apiVersion: hlb/v1
kind: App
metadata: {{ name: x }}
spec:
  image: {{ repo: a/b, tag: "1" }}
  requires: {requires}
  update: {update}
"#
        ))
        .expect("manifest");
        let state = State::in_memory().await.expect("state");
        state.upsert_app("x", &m, None).await.expect("app");
        (state, m)
    }

    #[tokio::test]
    async fn a_cache_whose_volume_says_no_backup_owes_no_copy_before_an_update() {
        let (state, m) = installed(
            "[{ kind: storage, name: data, path: /data, backup: false }]",
            "{ channel: minor }",
        )
        .await;
        state
            .add_volume("x", "x-data", "/nowhere", false, false)
            .await
            .expect("volume");
        assert!(!owes_backup(&state, "x", &m).await.expect("read"));
    }

    #[tokio::test]
    async fn an_app_with_a_volume_or_a_database_still_owes_its_copy() {
        let (state, m) = installed(
            "[{ kind: storage, name: data, path: /data }]",
            "{ channel: minor }",
        )
        .await;
        state
            .add_volume("x", "x-data", "/nowhere", true, false)
            .await
            .expect("volume");
        assert!(owes_backup(&state, "x", &m).await.expect("read"));

        // Holding no volume is no pass for a database: its dump is the copy.
        let (state, m) = installed(
            "[{ kind: database, engine: postgres }]",
            "{ channel: minor }",
        )
        .await;
        assert!(owes_backup(&state, "x", &m).await.expect("read"));
    }

    #[tokio::test]
    async fn a_manifest_asking_for_no_copy_owes_none_whatever_it_holds() {
        let (state, m) = installed(
            "[{ kind: storage, name: data, path: /data }]",
            "{ channel: minor, backupBefore: false }",
        )
        .await;
        state
            .add_volume("x", "x-data", "/nowhere", true, false)
            .await
            .expect("volume");
        assert!(!owes_backup(&state, "x", &m).await.expect("read"));
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
            signed_by: None,
        }
    }

    fn stalwart(tag: &str, storage: &str) -> Manifest {
        serde_yaml_ng::from_str(&format!(
            r#"
apiVersion: hlb/v1
kind: PlatformService
metadata: {{ name: stalwart }}
spec:
  image: {{ repo: stalwartlabs/stalwart, tag: "{tag}", digest: "sha256:{tag}" }}
  requires:
    - {{ kind: storage, name: {storage}, path: /var/lib/stalwart, tier: local }}
"#
        ))
        .expect("manifest")
    }

    #[test]
    fn a_catalog_image_moving_with_new_volumes_waits_for_the_upgrade() {
        let installed = stalwart("v0.16.27", "data");
        let why = held_move(&installed, &stalwart("v1.0.0", "data-v1")).expect("held");
        assert!(why.contains("`hlb upgrade stalwart`"), "{why}");
        assert!(why.contains("data → data-v1"), "{why}");
        // The same volumes: an ordinary move. No move at all: nothing held.
        assert_eq!(held_move(&installed, &stalwart("v0.16.28", "data")), None);
        assert_eq!(
            held_move(&installed, &stalwart("v0.16.27", "data-v1")),
            None
        );
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
