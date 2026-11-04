//! One backup pass: every volume, every database, every SQLite file and Homelabus's own
//! state, to every destination that should receive it.
//!
//! ## Why this is a crate of its own
//!
//! `hlb backup run` and the controller's backup loop each had their own version, and
//! they had drifted the way two copies do: the loop wrote to `--backup-repo` alone and
//! ignored the declared destinations — the off-site S3 copy only ever happened by hand —
//! never backed up Homelabus's state nor the SQLite databases, and mounted volumes under
//! `/data/` where the CLI mounts them under `/donnees/`. Snapshots taken by one did not
//! have the paths the other restores. There is now one pass, and both call it.
//!
//! It reports through [`Event`]s rather than printing: the CLI prints them, the
//! controller logs them and notifies.

pub mod bucket;
pub mod coverage;
pub mod engine_copy;
pub mod erasure;
pub mod kit;
pub mod placement;
pub mod restore;
pub mod upkeep;
pub mod verify;

use std::collections::BTreeMap;
use std::path::Path;

use hlb_backup::{Class, Destination, Schedule};
use hlb_secrets::Vault;
use hlb_state::{backup_kind, State};

pub use coverage::StateSource;
pub use engine_copy::Admins;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    State(#[from] hlb_state::Error),
    #[error(transparent)]
    Vault(#[from] hlb_secrets::Error),
    #[error(transparent)]
    Split(#[from] hlb_secrets::split::Error),
    #[error(transparent)]
    Backup(#[from] hlb_backup::Error),
    #[error("staging the snapshot: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The path a volume is mounted at inside the restic container.
///
/// 🔴 Recorded in every snapshot ever taken: a restore looks for the files under it.
/// Changing it splits the history in two, and the half under the old name is found on
/// the day of a restore. Kept in French on purpose — see the roadmap.
pub fn volume_path(volume: &str) -> String {
    format!("/donnees/{volume}")
}

/// Where the repository password is kept. ⚠️ A stored name.
pub const RESTIC_PASSWORD_SECRET: &str = "restic-repo-password";

/// The repository password, created on first use and never changed: a new one would
/// make every snapshot already written unreadable.
///
/// Shared by backup and verification — verifying with another password would report a
/// corruption that does not exist.
pub async fn restic_password(state: &State, vault: &Vault) -> Result<String> {
    const SECRET: &str = RESTIC_PASSWORD_SECRET;
    Ok(match state.secret(SECRET).await? {
        Some(ct) => vault.decrypt(&ct)?,
        None => {
            let p = hlb_secrets::generate_password(hlb_secrets::DEFAULT_PASSWORD_LEN);
            state
                .store_secret_if_absent(SECRET, &vault.encrypt(&p)?, "backup repository encryption")
                .await?;
            // Re-read: another process may have created it between the two calls, and
            // the one that won is the one the repository is encrypted with.
            match state.secret(SECRET).await? {
                Some(ct) => vault.decrypt(&ct)?,
                None => p,
            }
        }
    })
}

/// The declared destinations.
pub async fn load_destinations(state: &State) -> Result<Vec<Destination>> {
    Ok(state
        .destinations()
        .await?
        .into_iter()
        .map(
            |(name, location, classes, credentials_secret)| Destination {
                name,
                location,
                classes: classes.split(',').filter_map(Class::parse).collect(),
                credentials_secret,
            },
        )
        .collect())
}

/// The destinations that must receive this class for this app.
///
/// An explicit route wins; otherwise each destination's own classes decide. That is
/// what lets you say "Immich's bulky data goes off-site" without sending every other
/// app's along with it.
pub async fn destinations_for(state: &State, app: &str, class: Class) -> Result<Vec<Destination>> {
    let all = load_destinations(state).await?;
    let explicit = state.route(app, class.name()).await?;
    Ok(if explicit.is_empty() {
        all.into_iter().filter(|d| d.accepts(class)).collect()
    } else {
        all.into_iter()
            .filter(|d| explicit.contains(&d.name))
            .collect()
    })
}

/// The destinations to serve, falling back to `--backup-repo`.
///
/// ⚠️ The fallback exists so an installation that has not declared a destination yet
/// does not break: without it, a Homelabus update would silently stop every backup.
pub async fn effective_destinations(
    state: &State,
    app: &str,
    class: Class,
    fallback: Option<&str>,
) -> Result<Vec<Destination>> {
    let d = destinations_for(state, app, class).await?;
    if !d.is_empty() {
        return Ok(d);
    }
    Ok(fallback
        .map(|l| {
            vec![Destination {
                name: "default".into(),
                location: l.to_string(),
                classes: vec![Class::Critical, Class::Bulky],
                credentials_secret: None,
            }]
        })
        .unwrap_or_default())
}

/// Every destination a pass would serve `app` on, each class it holds counted once:
/// what "back up now" previews before the pass runs.
pub async fn destinations_of_app(
    state: &State,
    app: &str,
    fallback: Option<&str>,
) -> Result<Vec<Destination>> {
    let mut out: Vec<Destination> = Vec::new();
    let kinds = if app == STATE_APP {
        vec![backup_kind::STATE]
    } else {
        state.backup_kinds(app).await?
    };
    for class in [Class::Critical, Class::Bulky] {
        let held = kinds
            .iter()
            .any(|k| coverage::class_of(k).unwrap_or(Class::Critical) == class);
        if !held {
            continue;
        }
        for d in effective_destinations(state, app, class, fallback).await? {
            if !out.iter().any(|o| o.name == d.name) {
                out.push(d);
            }
        }
    }
    Ok(out)
}

/// A destination's credentials, out of the vault — as late as possible.
pub async fn credentials(
    state: &State,
    vault: &Vault,
    dest: &Destination,
) -> Result<Option<String>> {
    Ok(match &dest.credentials_secret {
        Some(name) => match state.secret(name).await? {
            Some(ct) => Some(vault.decrypt(&ct)?),
            None => None,
        },
        None => None,
    })
}

/// The volume backup provider for one destination: an update's prior backup, and the
/// interface's "back up now".
///
/// 🔴 A local repository is MOUNTED, a remote one is reached over the network —
/// [`Destination::runner`] decides, and getting it wrong produces a "repository does not
/// exist" naming a local path unrelated to the real destination. And each volume is
/// backed up where it lives: run here over a volume of another node, the prior backup
/// of an update copied an empty or stale volume, and let the update through.
pub async fn provider_for(
    dest: &Destination,
    network: &str,
    admins: Admins<'_>,
    state: &State,
    vault: &Vault,
) -> Result<PlacedProvider> {
    let password = restic_password(state, vault).await?;
    let env = dest.env(credentials(state, vault, dest).await?.as_deref())?;

    let mut volumes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut services: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (app, _) in state.installed_apps().await? {
        let v: Vec<String> = state
            .volumes_to_backup(&app)
            .await?
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        if !v.is_empty() {
            services.insert(app.clone(), services_of(state, &app).await?);
            volumes.insert(app, v);
        }
    }
    Ok(PlacedProvider {
        state: state.clone(),
        dest: dest.clone(),
        network: network.to_string(),
        postgres_admin: admins.postgres.map(str::to_string),
        mariadb_admin: admins.mariadb.map(str::to_string),
        password,
        env,
        volumes,
        services,
    })
}

/// See [`provider_for`].
pub struct PlacedProvider {
    state: State,
    dest: Destination,
    network: String,
    postgres_admin: Option<String>,
    mariadb_admin: Option<String>,
    password: String,
    env: Vec<(String, String)>,
    volumes: BTreeMap<String, Vec<String>>,
    services: BTreeMap<String, Vec<String>>,
}

#[async_trait::async_trait]
impl hlb_updater::BackupProvider for PlacedProvider {
    async fn snapshot(&self, app: &str) -> std::result::Result<String, String> {
        let Some(volumes) = self.volumes.get(app) else {
            // 🔴 No "nothing to back up, so we are fine". If the manifest requires a
            // backup and we do not know what to back up, that is an error.
            return Err(format!(
                "no known volume for \"{app}\" — the backup cannot be guaranteed"
            ));
        };
        let orch = hlb_orchestrator::SwarmOrchestrator::connect().await.ok();
        let orch = orch
            .as_ref()
            .map(|o| o as &dyn hlb_orchestrator::Orchestrator);
        let services = self.services.get(app).cloned().unwrap_or_default();
        let places = locate_volumes(orch, volumes, &services).await;
        // The copy a rollback restores: one taken live from a store that needs its
        // service stopped would not open.
        let stopped = stop_for_copy(&self.state, orch, app, volumes)
            .await
            .map_err(|e| e.to_string())??;
        let taken = self.copy_and_back_up(orch, app, &places).await;
        let Some((o, services)) = stopped else {
            return taken;
        };
        match (restore::start(o, &self.state, &services).await, taken) {
            (Ok(()), taken) => taken,
            (Err(e), Ok(_)) => Err(e),
            (Err(e), Err(t)) => Err(format!("{t}; and then {e}")),
        }
    }
}

impl PlacedProvider {
    /// An app's volumes to the destination, those its engine's tool copies read from
    /// that copy — taken here, and emptied after.
    async fn copy_and_back_up(
        &self,
        orch: Option<&dyn hlb_orchestrator::Orchestrator>,
        app: &str,
        places: &BTreeMap<placement::Place, Vec<String>>,
    ) -> std::result::Result<String, String> {
        let copies = engine_copy::declared(&self.state, app)
            .await
            .map_err(|e| e.to_string())?;
        let admins = Admins {
            postgres: self.postgres_admin.as_deref(),
            mariadb: self.mariadb_admin.as_deref(),
        };
        let sources = if copies.is_empty() {
            BTreeMap::new()
        } else {
            engine_copy::take(
                &self.state,
                orch,
                &self.network,
                admins,
                app,
                &copies,
                places,
            )
            .await
            .map_err(|e| e.to_string())??
        };
        let taken = back_up_where_they_are(
            &self.state,
            orch,
            &self.network,
            &self.dest,
            (&self.password, &self.env),
            app,
            places,
            &sources,
            None,
        )
        .await;
        // A copy left on disk costs space, not the backup: the update goes on.
        if let Err(e) = engine_copy::clear_all(&self.state, orch, app, &sources, places).await {
            tracing::warn!(app, error = %e, "the engine's copy was not emptied");
        }
        taken
    }
}

/// An app's services: its own, then its companions'.
async fn services_of(state: &State, app: &str) -> Result<Vec<String>> {
    Ok(std::iter::once(app.to_string())
        .chain(
            state
                .app_manifest(app)
                .await?
                .spec
                .companions
                .iter()
                .map(|c| format!("{app}-{}", c.name)),
        )
        .collect())
}

/// Stops the services writing a volume of `app` its frozen manifest declares
/// `copy: stopped`, held for the copy: what to start again after, `None` when
/// every volume is copied live. `Err`: no copy is taken — never a live one instead.
async fn stop_for_copy<'o>(
    state: &State,
    orchestrator: Option<&'o dyn hlb_orchestrator::Orchestrator>,
    app: &str,
    volumes: &[String],
) -> Result<std::result::Result<Option<Stopped<'o>>, String>> {
    let names = state.app_manifest(app).await?.spec.stopped_for_copy(app);
    if names.is_empty() {
        return Ok(Ok(None));
    }
    let Some(o) = orchestrator else {
        return Ok(Err(format!(
            "{} must be stopped for the copy, and no orchestrator can stop it",
            names.join(", ")
        )));
    };
    // Not `restore::replicas`, which leaves out a service it cannot read: one that
    // may be running is not copied.
    let mut services = Vec::new();
    for s in &names {
        match o.status(s).await {
            Ok(st) => services.push((s.clone(), st.desired_replicas)),
            Err(e) => {
                return Ok(Err(format!(
                    "whether {s} runs cannot be read, so it is not copied: {e}"
                )))
            }
        }
    }
    let why = format!("backup copy of {}", volumes.join(", "));
    if let Err(e) = restore::stop(o, state, &services, &why).await {
        return Ok(Err(match restore::start(o, state, &services).await {
            Ok(()) => e,
            Err(again) => format!("{e}; and then {again}"),
        }));
    }
    Ok(Ok(Some((o, services))))
}

/// Which machine holds each of `volumes`.
async fn locate_volumes(
    orch: Option<&dyn hlb_orchestrator::Orchestrator>,
    volumes: &[String],
    services: &[String],
) -> BTreeMap<placement::Place, Vec<String>> {
    let here = || BTreeMap::from([(placement::Place::Here, volumes.to_vec())]);
    let Some(o) = orch else {
        return here();
    };
    // No Swarm: one machine, and every volume on it.
    let Some(local) = o.local_node().await.ok().flatten() else {
        return here();
    };
    match (o.tasks(None).await, o.nodes().await) {
        (Ok(tasks), Ok(nodes)) => {
            placement::locate(volumes, services, &tasks, &nodes, Some(&local))
        }
        (Err(e), _) | (_, Err(e)) => BTreeMap::from([(
            placement::Place::Unknown(format!("the cluster could not say where they are: {e}")),
            volumes.to_vec(),
        )]),
    }
}

/// Backs up an app's volumes to `d`, each set on the machine holding it. The last
/// snapshot's id. `pass`: the tag of the pass taking them, `None` for an update's prior
/// backup. `sources`: a volume read from another in its place — its engine's copy —,
/// at its own path.
#[allow(clippy::too_many_arguments)]
async fn back_up_where_they_are(
    state: &State,
    orch: Option<&dyn hlb_orchestrator::Orchestrator>,
    network: &str,
    d: &Destination,
    (password, env): (&str, &[(String, String)]),
    app: &str,
    places: &BTreeMap<placement::Place, Vec<String>>,
    sources: &BTreeMap<String, String>,
    pass: Option<&str>,
) -> std::result::Result<String, String> {
    let mut last = Err(format!("no volume of {app} to back up"));
    let tags: Vec<&str> = std::iter::once(BACKED_UP).chain(pass).collect();
    for (place, volumes) in places {
        let paths: Vec<String> = volumes.iter().map(|v| volume_path(v)).collect();
        let (runner, location) = runner_at(orch, network, d, app, place, volumes, sources, false)?;
        let repo = hlb_backup::Repository::new(runner, location, password).extra_env(env.to_vec());
        last = Ok(snapshot(&repo, (state, &d.name), app, &paths, &tags).await?);
    }
    last
}

/// restic where `volumes` are, `place`, with each mounted at its [`volume_path`] —
/// from the volume `sources` names in its place, if any.
#[allow(clippy::too_many_arguments)]
fn runner_at<'a>(
    orch: Option<&'a dyn hlb_orchestrator::Orchestrator>,
    network: &str,
    d: &Destination,
    app: &str,
    place: &placement::Place,
    volumes: &[String],
    sources: &BTreeMap<String, String>,
    writes: bool,
) -> std::result::Result<(placement::PlacedRunner<'a>, String), String> {
    let source = |v: &String| sources.get(v).cloned().unwrap_or_else(|| v.clone());
    match place {
        placement::Place::Here => {
            let (mut runner, location) = d.runner(Some(network));
            for v in volumes {
                // Mounted by NAME: the host mount point is not reachable from the
                // Docker VM on macOS.
                runner = runner.mount(source(v), volume_path(v));
            }
            Ok((placement::PlacedRunner::Here(runner), location))
        }
        placement::Place::Node { id, hostname } => {
            if !d.is_remote() {
                return Err(format!(
                    "{} {} on {hostname}, and \"{}\" is a path on this machine — \
                     restic run there would use {hostname}'s own disk. Give it a \
                     destination every node reaches: S3, or a restic REST server \
                     (rest:http://…)",
                    volumes.join(", "),
                    if volumes.len() == 1 { "is" } else { "are" },
                    d.name
                ));
            }
            let Some(o) = orch else {
                return Err(format!(
                    "{} on {hostname}: no orchestrator",
                    volumes.join(", ")
                ));
            };
            Ok((
                placement::PlacedRunner::Node(placement::JobRunner {
                    orchestrator: o,
                    node: id.clone(),
                    mounts: volumes
                        .iter()
                        .map(|v| (source(v), volume_path(v)))
                        .collect(),
                    network: Some(network.to_string()),
                    name: format!("hlb-backup-{app}"),
                    writes,
                }),
                d.location.clone(),
            ))
        }
        placement::Place::Unknown(why) => Err(why.clone()),
    }
}

/// The provider an update uses for its prior backup: the first destination of the
/// app's bulky class.
///
/// `None` when there is none — and the update is then REFUSED by `hlb-updater`, which
/// is the point: a schema migration is not undone by rolling back an image.
pub async fn provider_for_update(
    state: &State,
    vault: &Vault,
    network: &str,
    admins: Admins<'_>,
    fallback: Option<&str>,
    app: &str,
) -> Result<Option<PlacedProvider>> {
    match effective_destinations(state, app, Class::Bulky, fallback)
        .await?
        .first()
    {
        Some(d) => Ok(Some(provider_for(d, network, admins, state, vault).await?)),
        None => Ok(None),
    }
}

/// What a pass did, one item at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// `what` reached `destination`.
    Done {
        what: String,
        destination: String,
        snapshot: String,
    },
    /// `what` did not reach `destination` — or never got produced, with no destination.
    Failed {
        what: String,
        destination: Option<String>,
        error: String,
    },
    /// Something deliberately not backed up, and why. 🔴 Said out loud, never skipped
    /// in silence: a database nobody dumps looks backed up as long as its volume is.
    NotCovered { what: String, why: String },
}

/// What the pass is told about the installation.
pub struct Pass<'a> {
    pub state: &'a State,
    pub vault: &'a Vault,
    /// The state database's file, for its own snapshot.
    pub state_path: &'a Path,
    /// `--backup-repo`, used when no destination is declared.
    pub fallback_repo: Option<&'a str>,
    /// The overlay where `postgres` and the S3 endpoint resolve.
    pub network: &'a str,
    pub postgres_admin: Option<&'a str>,
    pub mariadb_admin: Option<&'a str>,
    pub schedule: Schedule,
    /// Back up even what is not due.
    pub force: bool,
    /// One app only — "back up now" — rather than the installation. Homelabus's own
    /// state is the app `hlb`'s.
    pub only: Option<&'a str>,
    /// Where each volume lives, and how to run restic there. `None`: every volume is
    /// taken as on this machine.
    pub orchestrator: Option<&'a dyn hlb_orchestrator::Orchestrator>,
    /// Where this process reaches Garage's S3 API — `hlb_objstore::S3_URL` on the
    /// overlay, a relay from a host. `None`: no bucket can be read, and each is said.
    pub s3_endpoint: Option<&'a str>,
}

/// The app Homelabus's own state is backed up as. ⚠️ A stored value: every state
/// backup recorded so far carries it, and the self-update reads it back.
pub const STATE_APP: &str = "hlb";

/// How old the newest successful backup of Homelabus's own state is, on any
/// destination; `None`: never. What a self-update requires before it migrates — never
/// another app's backup, which restores nothing of the state.
pub async fn state_backup_age(state: &State) -> Result<Option<i64>> {
    Ok(state
        .seconds_since_last_success_of(STATE_APP, &[backup_kind::STATE], None)
        .await?)
}

/// The tag of a volume's snapshot, whether the pass or an update's prior backup took
/// it. ⚠️ A stored value: the snapshots already written carry it.
const BACKED_UP: &str = "kind:pre-update";

/// What every snapshot a pass takes carries, before the pass's id: the volume's and
/// its databases' snapshots of one pass carry the same, and only those go together at
/// a restore (`restore::sqlite_of_pass`). ⚠️ A stored value.
pub const PASS_TAG: &str = "pass:";

/// Initialises the repository and backs up each path, tagged with its app and `tags`
/// (its kind first). Each snapshot is recorded as taken, on `to` — the state and the
/// destination's name: a restore takes no other unless told its full id. The last
/// one's id.
async fn snapshot<R: hlb_backup::restic::Runner>(
    repo: &hlb_backup::Repository<R>,
    to: (&State, &str),
    app: &str,
    paths: &[String],
    tags: &[&str],
) -> std::result::Result<String, String> {
    repo.init().await.map_err(|e| e.to_string())?;
    let tag = format!("app:{app}");
    let all: Vec<&str> = std::iter::once(tag.as_str())
        .chain(tags.iter().copied())
        .collect();
    let mut last = String::new();
    for p in paths {
        last = repo.backup(p, &all).await.map_err(|e| e.to_string())?;
        to.0.record_snapshot(app, to.1, &last)
            .await
            .map_err(|e| format!("snapshot {last} taken, but not recorded: {e}"))?;
    }
    Ok(last)
}

/// Services stopped for a copy, and the replicas to give each back.
type Stopped<'o> = (&'o dyn hlb_orchestrator::Orchestrator, Vec<(String, u64)>);

/// The tally of a pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub done: usize,
    pub failed: usize,
}

impl Pass<'_> {
    /// The installed apps, `vital` first, then by name: a pass cut short — a full disk,
    /// a crash — has saved what the household needs most. A manifest that cannot be
    /// read sorts as `normal` rather than stop the pass; its own steps say why.
    async fn most_critical_first(&self) -> Result<Vec<(String, String)>> {
        let mut apps = Vec::new();
        for (app, status) in self.state.installed_apps().await? {
            let c = self
                .state
                .app_manifest(&app)
                .await
                .map(|m| m.criticality())
                .unwrap_or_default();
            apps.push((c, app, status));
        }
        apps.sort();
        Ok(apps
            .into_iter()
            .map(|(_, app, status)| (app, status))
            .collect())
    }

    /// Runs the pass. A failure on one item or one destination never stops the
    /// others: an unreachable off-site that aborted the loop would also skip the local
    /// copy — both copies lost for one failure. Nor does a credential the vault cannot
    /// open: that destination fails, recorded and said, and the others are served.
    pub async fn run(&self, report: &mut (dyn FnMut(Event) + Send)) -> Result<Summary> {
        let mut sum = Summary::default();
        let mut emit = |e: Event, sum: &mut Summary| {
            match &e {
                Event::Done { .. } => sum.done += 1,
                Event::Failed { .. } => sum.failed += 1,
                Event::NotCovered { .. } => {}
            }
            report(e);
        };
        let pass = format!("{PASS_TAG}{}", hlb_backup::verify::public_token());

        // -- Homelabus's own state, first ------------------------------------------
        // 🔴 Without it a restore returns running apps in an installation that no
        // longer knows who the administrator is, nor which routes it published.
        if self.includes(STATE_APP) {
            self.state_snapshot(&mut |e| emit(e, &mut sum)).await?;
        }

        // -- Volumes: the BULKY class, per destination ------------------------------
        // Where each app's volumes went in this pass: its SQLite databases follow them
        // there, so a restore of those volumes finds the same pass's databases.
        let mut reached: BTreeMap<String, Vec<Destination>> = BTreeMap::new();
        for (app, status) in self.most_critical_first().await? {
            if status == "failed" || !self.includes(&app) {
                continue;
            }
            let volumes: Vec<String> = self
                .state
                .volumes_to_backup(&app)
                .await?
                .into_iter()
                .map(|(n, _)| n)
                .collect();
            // Nothing to back up is not a failure: Valkey and LibreSpeed read "no known
            // volume" on every pass, and counted as failed backups.
            if volumes.is_empty() {
                continue;
            }
            let dests =
                effective_destinations(self.state, &app, Class::Bulky, self.fallback_repo).await?;
            if dests.is_empty() {
                emit(
                    Event::NotCovered {
                        what: format!("{app} volumes"),
                        why: "no destination accepts bulky data".into(),
                    },
                    &mut sum,
                );
                continue;
            }
            let places = self.places(&app, &volumes).await?;
            // 🔴 Due PER DESTINATION. Judged globally, the off-site would be skipped
            // whenever the NAS was just served, and never receive anything. And by the
            // VOLUMES' own age: read across kinds, the dump every pass records made a
            // volume backed up once never due again.
            let mut due = Vec::new();
            for d in &dests {
                if self.is_due(&app, backup_kind::VOLUME, d).await? {
                    due.push(d);
                }
            }
            if due.is_empty() {
                continue;
            }
            // Stopped once for every destination, and copied by an engine's tool once:
            // N stops and N copies for N destinations otherwise.
            let stopped = stop_for_copy(self.state, self.orchestrator, &app, &volumes).await?;
            let copies = engine_copy::declared(self.state, &app).await?;
            let sources = match &stopped {
                Ok(_) if copies.is_empty() => Ok(BTreeMap::new()),
                Ok(_) => {
                    engine_copy::take(
                        self.state,
                        self.orchestrator,
                        self.network,
                        self.admins(),
                        &app,
                        &copies,
                        &places,
                    )
                    .await?
                }
                Err(e) => Err(e.clone()),
            };
            let mut outcomes = Vec::new();
            for d in due {
                let outcome = match &sources {
                    Ok(sources) => self.volumes_to(&app, d, &places, sources, &pass).await,
                    Err(e) => Err(e.clone()),
                };
                outcomes.push((d, outcome));
            }
            if let Ok(sources) = &sources {
                if let Err(error) =
                    engine_copy::clear_all(self.state, self.orchestrator, &app, sources, &places)
                        .await
                {
                    emit(
                        Event::Failed {
                            what: format!("{app} copy emptied after its backup"),
                            destination: None,
                            error,
                        },
                        &mut sum,
                    );
                }
            }
            // Started again before anything is recorded: a state error there would
            // leave the service stopped until its hold ran out.
            if let Ok(Some((o, services))) = &stopped {
                if let Err(error) = restore::start(*o, self.state, services).await {
                    emit(
                        Event::Failed {
                            what: format!("{app} started again after its copy"),
                            destination: None,
                            error,
                        },
                        &mut sum,
                    );
                }
            }
            for (d, outcome) in outcomes {
                if outcome.is_ok() {
                    reached.entry(app.clone()).or_default().push(d.clone());
                }
                self.record(
                    &app,
                    backup_kind::VOLUME,
                    &format!("{app} volumes"),
                    d,
                    outcome,
                )
                .await
                .map(|e| emit(e, &mut sum))?;
            }
        }

        // -- Buckets: their objects as one archive, the BULKY class ----------------
        // Every bucket of an app in one outcome per destination, as its volumes: one
        // recorded per bucket, the one that succeeded would make the app fresh while
        // the other went unread.
        for (app, status) in self.most_critical_first().await? {
            if status == "failed" || !self.includes(&app) {
                continue;
            }
            let buckets = self.state.buckets_to_backup(&app).await?;
            if buckets.is_empty() {
                continue;
            }
            let what = format!("{app} buckets");
            let Some(endpoint) = self.s3_endpoint else {
                emit(
                    Event::NotCovered {
                        what,
                        why: "Garage's S3 API is not reachable from here".into(),
                    },
                    &mut sum,
                );
                continue;
            };
            let dests =
                effective_destinations(self.state, &app, Class::Bulky, self.fallback_repo).await?;
            if dests.is_empty() {
                emit(
                    Event::NotCovered {
                        what,
                        why: "no destination accepts bulky data".into(),
                    },
                    &mut sum,
                );
                continue;
            }
            for d in &dests {
                if !self.is_due(&app, backup_kind::BUCKET, d).await? {
                    continue;
                }
                let outcome = self.buckets_to(&app, &buckets, endpoint, d, &pass).await;
                self.record(&app, backup_kind::BUCKET, &what, d, outcome)
                    .await
                    .map(|e| emit(e, &mut sum))?;
            }
        }

        // -- SQLite: a snapshot, never the live file ---------------------------------
        // Due decided per app before any is taken: recorded, an app's first database
        // would make its second look done.
        // 🔴 Every backed-up volume is looked in, flagged or not: the flag is a list kept
        // by hand, and three of the catalog's six SQLite volumes were missing from it.
        let mut sqlite = Vec::new();
        for (app, volume, mountpoint, flagged) in self.state.backed_up_volumes().await? {
            if !self.includes(&app) {
                continue;
            }
            if !flagged {
                match self.holds_sqlite(&app, &volume, &mountpoint).await? {
                    Ok(false) => continue,
                    Ok(true) => self.state.mark_sqlite(&app, &volume).await?,
                    Err(error) => {
                        emit(
                            Event::Failed {
                                what: format!("{app}/{volume} SQLite"),
                                destination: None,
                                error,
                            },
                            &mut sum,
                        );
                        continue;
                    }
                }
            }
            sqlite.push((app, volume, mountpoint));
        }
        let mut due: BTreeMap<String, Option<Vec<Destination>>> = BTreeMap::new();
        for (app, _, _) in &sqlite {
            if !due.contains_key(app) {
                let also = reached.get(app).map(Vec::as_slice).unwrap_or_default();
                let d = self.due(app, backup_kind::SQLITE, also).await?;
                due.insert(app.clone(), d);
            }
        }
        for (app, volume, mountpoint) in &sqlite {
            let what = format!("{app}/{volume} SQLite");
            match due.get(app).cloned().flatten() {
                None => emit(
                    Event::NotCovered {
                        what,
                        why: "no destination accepts critical data: the snapshot went nowhere"
                            .into(),
                    },
                    &mut sum,
                ),
                Some(dests) if dests.is_empty() => {}
                Some(dests) => {
                    self.sqlite(app, volume, mountpoint, &dests, &pass, &mut |e| {
                        emit(e, &mut sum)
                    })
                    .await?
                }
            }
        }

        // -- Databases: a logical dump, never the volume -----------------------------
        // A PostgreSQL or InnoDB volume copied while a write is in flight does not
        // restore. Each engine has its own dumper and admin URL: treating them as one
        // would make MariaDB look backed up as soon as PostgreSQL is reachable.
        let mut databases = self.state.app_databases().await?;
        databases.retain(|(app, _, _, _)| self.includes(app));
        let mut due: BTreeMap<String, Option<Vec<Destination>>> = BTreeMap::new();
        for (app, _, _, _) in &databases {
            if !due.contains_key(app) {
                let d = self.due(app, backup_kind::SQL_DUMP, &[]).await?;
                due.insert(app.clone(), d);
            }
        }
        for (app, engine, base, _) in databases {
            let what = format!("{app}/{base}");
            let admin = match engine.as_str() {
                "postgres" => self.postgres_admin,
                "mariadb" => self.mariadb_admin,
                _ => {
                    emit(
                        Event::NotCovered {
                            what,
                            why: format!("engine \"{engine}\" has no dumper"),
                        },
                        &mut sum,
                    );
                    continue;
                }
            };
            let Some(url) = admin else {
                emit(
                    Event::NotCovered {
                        what,
                        why: format!(
                            "--{}-admin missing: the volume alone does not restore",
                            engine
                        ),
                    },
                    &mut sum,
                );
                continue;
            };
            let dests = match due.get(&app).cloned().flatten() {
                None => {
                    emit(
                        Event::NotCovered {
                            what,
                            why: "no destination accepts critical data: the dump went nowhere"
                                .into(),
                        },
                        &mut sum,
                    );
                    continue;
                }
                // Dumped on the schedule, as volumes are — not on every pass.
                Some(dests) if dests.is_empty() => continue,
                Some(dests) => dests,
            };
            let dump = match engine.as_str() {
                "postgres" => pg_dump(self.network, &app, &base, url).await,
                _ => maria_dump(self.network, &app, &base, url).await,
            };
            match dump {
                Ok(d) => {
                    self.archive_to(&app, backup_kind::SQL_DUMP, &what, &d, &dests, &mut |e| {
                        emit(e, &mut sum)
                    })
                    .await?
                }
                Err(e) => {
                    self.state
                        .record_backup(&app, backup_kind::SQL_DUMP, None, Some(&e))
                        .await?;
                    emit(
                        Event::Failed {
                            what,
                            destination: None,
                            error: e,
                        },
                        &mut sum,
                    );
                }
            }
        }

        Ok(sum)
    }

    fn admins(&self) -> Admins<'_> {
        Admins {
            postgres: self.postgres_admin,
            mariadb: self.mariadb_admin,
        }
    }

    /// Does this pass take `app`?
    fn includes(&self, app: &str) -> bool {
        self.only.is_none_or(|only| only == app)
    }

    /// Is `kind` of `app` due on `d`? By its own age there, never another kind's.
    async fn is_due(&self, app: &str, kind: &str, d: &Destination) -> Result<bool> {
        if self.force {
            return Ok(true);
        }
        let age = self
            .state
            .seconds_since_last_success_of(app, &[kind], Some(&d.name))
            .await?
            .map(|s| std::time::Duration::from_secs(s.max(0) as u64));
        Ok(self.schedule.is_due(age))
    }

    /// The critical destinations `kind` of `app` is due on, with `also` whatever its
    /// age: `None` when no destination accepts it at all.
    async fn due(
        &self,
        app: &str,
        kind: &str,
        also: &[Destination],
    ) -> Result<Option<Vec<Destination>>> {
        let dests =
            effective_destinations(self.state, app, Class::Critical, self.fallback_repo).await?;
        if dests.is_empty() && also.is_empty() {
            return Ok(None);
        }
        let mut out: Vec<Destination> = also.to_vec();
        for d in dests {
            if !out.iter().any(|o| o.name == d.name) && self.is_due(app, kind, &d).await? {
                out.push(d);
            }
        }
        Ok(Some(out))
    }

    /// The repository password and `d`'s credentials, out of the vault. An error is
    /// `d`'s to fail on — never the pass's.
    async fn access(
        &self,
        d: &Destination,
    ) -> std::result::Result<(String, Option<String>), String> {
        let password = restic_password(self.state, self.vault)
            .await
            .map_err(|e| format!("the repository password cannot be read: {e}"))?;
        let creds = credentials(self.state, self.vault, d)
            .await
            .map_err(|e| format!("the credentials of \"{}\" cannot be read: {e}", d.name))?;
        Ok((password, creds))
    }

    /// Records `outcome` of `kind` on `d`, and says it.
    async fn record(
        &self,
        app: &str,
        kind: &str,
        what: &str,
        d: &Destination,
        outcome: std::result::Result<String, String>,
    ) -> Result<Event> {
        Ok(match outcome {
            Ok(id) => {
                self.state
                    .record_backup_to(app, kind, &d.name, Some(&id), None)
                    .await?;
                Event::Done {
                    what: what.to_string(),
                    destination: d.name.clone(),
                    snapshot: id,
                }
            }
            Err(e) => {
                // Recorded: the deadline is not pushed back, the app stays due.
                self.state
                    .record_backup_to(app, kind, &d.name, None, Some(&e))
                    .await?;
                Event::Failed {
                    what: what.to_string(),
                    destination: Some(d.name.clone()),
                    error: e,
                }
            }
        })
    }

    /// Which machine holds each of `volumes`.
    async fn places(
        &self,
        app: &str,
        volumes: &[String],
    ) -> Result<BTreeMap<placement::Place, Vec<String>>> {
        let services = services_of(self.state, app).await?;
        Ok(locate_volumes(self.orchestrator, volumes, &services).await)
    }

    /// Whether a volume no manifest flagged holds a SQLite database, by its header.
    /// Only one on this machine is looked in: on another node the volume pass already
    /// says where to run, and saying it again for each volume there would bury it.
    async fn holds_sqlite(
        &self,
        app: &str,
        volume: &str,
        mountpoint: &str,
    ) -> Result<std::result::Result<bool, String>> {
        let volumes = [volume.to_string()];
        let here = self
            .places(app, &volumes)
            .await?
            .into_keys()
            .all(|p| matches!(p, placement::Place::Here));
        if !here || !Path::new(mountpoint).exists() {
            return Ok(Ok(false));
        }
        let root = Path::new(mountpoint).to_path_buf();
        // A photo library is a long walk: off the runtime's threads.
        Ok(
            match tokio::task::spawn_blocking(move || hlb_backup::sqlite::discover(&root)).await {
                Ok(Ok(found)) => Ok(!found.is_empty()),
                Ok(Err(e)) => Err(format!(
                    "{mountpoint} could not be searched for SQLite databases: {e}"
                )),
                Err(e) => Err(format!("the search for SQLite databases stopped: {e}")),
            },
        )
    }

    /// Backs up an app's volumes to `d`, where they live.
    async fn volumes_to(
        &self,
        app: &str,
        d: &Destination,
        places: &BTreeMap<placement::Place, Vec<String>>,
        sources: &BTreeMap<String, String>,
        pass: &str,
    ) -> std::result::Result<String, String> {
        let (password, creds) = self.access(d).await?;
        let env = d.env(creds.as_deref()).map_err(|e| e.to_string())?;
        back_up_where_they_are(
            self.state,
            self.orchestrator,
            self.network,
            d,
            (&password, &env),
            app,
            places,
            sources,
            Some(pass),
        )
        .await
    }

    /// Backs up each of `buckets` to `d`, each its own snapshot, recorded as taken. The
    /// last one's id; the first failure, otherwise.
    async fn buckets_to(
        &self,
        app: &str,
        buckets: &[String],
        endpoint: &str,
        d: &Destination,
        pass: &str,
    ) -> std::result::Result<String, String> {
        let (password, creds) = self.access(d).await?;
        let env = d.env(creds.as_deref()).map_err(|e| e.to_string())?;
        let (runner, location) = d.runner(Some(self.network));
        let repo = hlb_backup::Repository::new(runner, location, password).extra_env(env);
        repo.init().await.map_err(|e| e.to_string())?;
        let tag = format!("app:{app}");
        let tags = [tag.as_str(), bucket::BUCKET_TAG, pass];
        let mut last = String::new();
        for name in buckets {
            let b = bucket::open(self.state, self.vault, endpoint, app, name).await?;
            last = bucket::back_up(&repo, &b, name, &tags).await?;
            self.state
                .record_snapshot(app, &d.name, &last)
                .await
                .map_err(|e| format!("snapshot {last} taken, but not recorded: {e}"))?;
        }
        Ok(last)
    }

    async fn state_snapshot(&self, emit: &mut (dyn FnMut(Event) + Send)) -> Result<()> {
        let failed = |error: String| Event::Failed {
            what: "hlb state".into(),
            destination: None,
            error,
        };
        let staging = match tempfile::tempdir() {
            Ok(s) => s,
            Err(e) => {
                emit(failed(format!("no staging directory: {e}")));
                return Ok(());
            }
        };
        let snapshot = staging.path().join("hlb-state.snapshot");
        // `VACUUM INTO`, never a copy: in WAL mode the database is three files restic
        // would copy one after another while the controller writes.
        if let Err(e) = hlb_backup::sqlite_snapshot(self.state_path, &snapshot).await {
            emit(failed(e.to_string()));
            return Ok(());
        }
        let bytes = match tokio::fs::read(&snapshot).await {
            Ok(b) => b,
            Err(e) => {
                emit(failed(format!("reading the snapshot: {e}")));
                return Ok(());
            }
        };
        let d = hlb_backup::pgdump::scheduled::Dump {
            app: STATE_APP.to_string(),
            database: "state".to_string(),
            filename: "hlb-state.snapshot".to_string(),
            bytes,
        };
        let dests =
            effective_destinations(self.state, STATE_APP, Class::Critical, self.fallback_repo)
                .await?;
        if dests.is_empty() {
            emit(Event::NotCovered {
                what: "hlb state".into(),
                why: "no destination accepts critical data: the dump went nowhere".into(),
            });
            return Ok(());
        }
        self.archive_to(STATE_APP, backup_kind::STATE, "hlb state", &d, &dests, emit)
            .await
    }

    /// Snapshots the SQLite databases of `volume` and archives each to `dests`, tagged
    /// with the pass.
    #[allow(clippy::too_many_arguments)]
    async fn sqlite(
        &self,
        app: &str,
        volume: &str,
        mountpoint: &str,
        dests: &[Destination],
        pass: &str,
        emit: &mut (dyn FnMut(Event) + Send),
    ) -> Result<()> {
        let failed = |error: String| Event::Failed {
            what: format!("{app}/{volume} SQLite"),
            destination: None,
            error,
        };
        let staging = match tempfile::tempdir() {
            Ok(s) => s,
            Err(e) => {
                emit(failed(format!("no staging directory: {e}")));
                return Ok(());
            }
        };
        // 🔴 Present is not current: a node an app left keeps its old copy, and that
        // copy would have been snapshot as the app's database.
        let volumes = [volume.to_string()];
        let elsewhere = self
            .places(app, &volumes)
            .await?
            .into_keys()
            .find_map(|p| match p {
                placement::Place::Here => None,
                placement::Place::Node { hostname, .. } => Some(format!(
                    "{volume} is on {hostname}, which runs {app}: run \"hlb backup run\" there"
                )),
                placement::Place::Unknown(why) => Some(why),
            });
        if let Some(error) = elsewhere {
            emit(failed(error));
            return Ok(());
        }
        // A volume lives on the node that runs its app: read from any other, its path
        // is absent and the failure said "No such file", naming no machine.
        if !Path::new(mountpoint).exists() {
            emit(failed(format!(
                "{mountpoint} is not on this machine — the volume is on the node \
                 that runs {app}: run \"hlb backup run\" there"
            )));
            return Ok(());
        }
        let bases =
            match hlb_backup::sqlite_snapshot_all(Path::new(mountpoint), staging.path()).await {
                Ok(b) => b,
                Err(e) => {
                    emit(failed(e.to_string()));
                    return Ok(());
                }
            };
        // CRITICAL class: small, irreplaceable, the first thing you want off-site. Each
        // at its own path in the volume, so a restore puts it back there.
        let at = volume_path(volume);
        for b in &bases {
            let what = format!("{app}/{volume}/{}", b.relative.display());
            for d in dests {
                let outcome = match self.access(d).await {
                    Ok((password, creds)) => hlb_backup::sqlite::archive_to(
                        d,
                        creds.as_deref(),
                        Some(self.network),
                        &password,
                        app,
                        &at,
                        b,
                        &[pass],
                    )
                    .await
                    .map_err(|e| e.to_string()),
                    Err(e) => Err(e),
                };
                if let Ok(id) = &outcome {
                    // A restore takes only what Homelabus took.
                    self.state.record_snapshot(app, &d.name, id).await?;
                }
                emit(
                    self.record(app, backup_kind::SQLITE, &what, d, outcome)
                        .await?,
                );
            }
        }
        Ok(())
    }

    /// Archives a dump to each of `dests`.
    async fn archive_to(
        &self,
        app: &str,
        kind: &str,
        what: &str,
        dump: &hlb_backup::pgdump::scheduled::Dump,
        dests: &[Destination],
        emit: &mut (dyn FnMut(Event) + Send),
    ) -> Result<()> {
        for d in dests {
            let outcome = match self.access(d).await {
                Ok((password, creds)) => hlb_backup::pgdump::scheduled::archive_to(
                    d,
                    creds.as_deref(),
                    Some(self.network),
                    &password,
                    dump,
                )
                .await
                .map_err(|e| e.to_string()),
                Err(e) => Err(e),
            };
            emit(self.record(app, kind, what, d, outcome).await?);
        }
        Ok(())
    }
}

/// A PostgreSQL database's dump.
///
/// 🔴 With the ADMIN credentials, not the app's: its isolated role cannot read its own
/// sequences or extensions, and the dump would be incomplete without an error.
pub(crate) async fn pg_dump(
    network: &str,
    app: &str,
    base: &str,
    admin_url: &str,
) -> std::result::Result<hlb_backup::pgdump::scheduled::Dump, String> {
    use hlb_backup::pgdump::{scheduled, PgDumper, PgTarget};
    let creds = hlb_backup::parse_pg_url(admin_url)
        .ok_or_else(|| "unreadable PostgreSQL admin URL".to_string())?;
    let target = PgTarget {
        host: creds.host,
        port: creds.port,
        database: base.to_string(),
        user: creds.user,
        password: creds.password,
    };
    let dumper = PgDumper::new(hlb_backup::PgContainerRunner::default().network(network));
    scheduled::produce(&dumper, app, &target, now())
        .await
        .map_err(|e| e.to_string())
}

/// A MariaDB database's dump, through the server's administrator.
///
/// 🔴 The consistency is measured before EVERY dump: `--single-transaction` protects
/// InnoDB only, and a migration can add a MyISAM table months later. An unreadable
/// engine list means locking, never "probably InnoDB".
pub(crate) async fn maria_dump(
    network: &str,
    app: &str,
    base: &str,
    admin_url: &str,
) -> std::result::Result<hlb_backup::pgdump::scheduled::Dump, String> {
    use hlb_backup::mariadump::{self, Consistency, MariaDumper, MariaTarget};
    let creds = hlb_backup::parse_maria_url(admin_url)
        .ok_or_else(|| "unreadable MariaDB admin URL".to_string())?;
    let consistency = match hlb_platform::MariadbProvisioner::connect(admin_url).await {
        Ok(a) => match a.column_values(&mariadump::engines_query(base)).await {
            Ok(engines) => mariadump::consistency_for(&engines),
            Err(_) => Consistency::LockRequired,
        },
        Err(_) => Consistency::LockRequired,
    };
    let target = MariaTarget {
        host: creds.host,
        port: creds.port,
        database: base.to_string(),
        user: creds.user,
        password: creds.password,
    };
    let dumper = MariaDumper::new(hlb_backup::MariaContainerRunner::default().network(network));
    mariadump::scheduled::produce(&dumper, app, &target, consistency, now())
        .await
        .map_err(|e| e.to_string())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volumes_keep_the_path_every_existing_snapshot_was_taken_under() {
        // The controller once mounted them under `/data/`: its snapshots and the CLI's
        // did not share a layout, and a restore looks under one only.
        assert_eq!(volume_path("gitea_data"), "/donnees/gitea_data");
    }

    fn pass<'a>(state: &'a State, vault: &'a Vault, state_path: &'a Path) -> Pass<'a> {
        Pass {
            state,
            vault,
            state_path,
            fallback_repo: None,
            network: "bridge",
            postgres_admin: None,
            mariadb_admin: None,
            schedule: Schedule::default(),
            force: false,
            only: None,
            orchestrator: None,
            s3_endpoint: None,
        }
    }

    fn nas() -> Destination {
        Destination {
            name: "nas".into(),
            location: "/mnt/nas".into(),
            classes: vec![Class::Critical, Class::Bulky],
            credentials_secret: None,
        }
    }

    #[tokio::test]
    async fn a_pass_serves_the_vital_apps_first() {
        let state = State::in_memory().await.expect("state");
        let vault = Vault::ephemeral();
        for (app, criticality) in [
            ("aa", "criticality: normal, "),
            ("mm", ""),
            ("vv", "criticality: important, "),
            ("zz", "criticality: vital, "),
        ] {
            let yaml = format!(
                "apiVersion: hlb/v1\nkind: App\nmetadata: {{ {criticality}name: {app} }}\n\
                 spec:\n  image: {{ repo: a/b, tag: \"1\" }}\n"
            );
            let m = serde_yaml_ng::from_str(&yaml).expect("manifest");
            state.upsert_app(app, &m, None).await.expect("installed");
        }
        let p = pass(&state, &vault, Path::new("/unused"));
        let order: Vec<String> = p
            .most_critical_first()
            .await
            .expect("read")
            .into_iter()
            .map(|(a, _)| a)
            .collect();
        // A manifest frozen before the field reads as `normal`, after the others by name.
        assert_eq!(order, ["zz", "vv", "aa", "mm"]);
    }

    #[tokio::test]
    async fn volumes_are_due_whatever_dumps_ran() {
        // 🔴 Found by review: the due check read the age of ANY kind on the
        // destination, and the dump every pass records made a volume backed up once
        // never due again.
        let state = State::in_memory().await.expect("state");
        let vault = Vault::ephemeral();
        let p = pass(&state, &vault, Path::new("/unused"));
        state
            .record_backup_to("gitea", "volume", "nas", Some("v1"), None)
            .await
            .expect("volume");
        state
            .backdate_backup("gitea", "nas", 5 * 3_600)
            .await
            .expect("five hours ago");
        state
            .record_backup_to("gitea", "sql-dump", "nas", Some("d1"), None)
            .await
            .expect("dump");
        assert!(p
            .is_due("gitea", backup_kind::VOLUME, &nas())
            .await
            .expect("due"));
        assert!(!p
            .is_due("gitea", backup_kind::SQL_DUMP, &nas())
            .await
            .expect("not due"));
    }

    #[tokio::test]
    async fn a_database_snapshot_follows_its_volume_whatever_its_own_age() {
        // A volume restore takes the databases of the SAME pass: a pass that backed up
        // the volume and skipped its databases as "not due" left nothing to pair.
        let state = State::in_memory().await.expect("state");
        let vault = Vault::ephemeral();
        let p = pass(&state, &vault, Path::new("/unused"));
        state
            .upsert_destination("offsite", "s3:x/y", "critical", None)
            .await
            .expect("destination");
        state
            .record_backup_to("pocket-id", "sqlite-snapshot", "offsite", Some("q1"), None)
            .await
            .expect("fresh");
        let due = p
            .due("pocket-id", backup_kind::SQLITE, &[nas()])
            .await
            .expect("due")
            .expect("a destination");
        let names: Vec<&str> = due.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["nas"], "offsite is fresh, nas got the volume");

        // No destination at all is said, never "not due".
        let none = State::in_memory().await.expect("state");
        let p = pass(&none, &vault, Path::new("/unused"));
        assert_eq!(
            p.due("x", backup_kind::SQL_DUMP, &[]).await.expect("due"),
            None
        );
    }

    #[tokio::test]
    async fn an_unreadable_credential_fails_its_destination_not_the_pass() {
        // 🔴 Found by review: the secret's `?` aborted the whole pass before any
        // volume, recorded nothing, and the controller only logged it.
        let dir = tempfile::tempdir().expect("tmp");
        let state_path = dir.path().join("hlb.db");
        let state = State::open(&state_path).await.expect("state");
        let vault = Vault::ephemeral();
        // Encrypted under another key: what a rotated or lost master key leaves.
        let other = Vault::ephemeral();
        state
            .store_secret_if_absent(
                "backup-dest-offsite",
                &other.encrypt("key:secret").expect("encrypt"),
                "backup destination",
            )
            .await
            .expect("secret");
        state
            .upsert_destination(
                "offsite",
                "s3:http://garage:3900/b",
                "critical",
                Some("backup-dest-offsite"),
            )
            .await
            .expect("destination");

        let mut said = Vec::new();
        let sum = pass(&state, &vault, &state_path)
            .run(&mut |e| said.push(e))
            .await
            .expect("the pass ends");
        assert_eq!(sum.failed, 1, "{said:?}");
        assert!(
            said.iter().any(|e| matches!(
                e,
                Event::Failed { destination: Some(d), error, .. }
                    if d == "offsite" && error.contains("credentials")
            )),
            "{said:?}"
        );
        let runs = state.backup_history("hlb", 10).await.expect("history");
        assert!(
            runs.iter().any(|r| r.status == "failed"),
            "the failure is recorded, so the app stays due: {runs:?}"
        );
    }

    fn app_with_database(name: &str) -> hlb_types::Manifest {
        serde_yaml_ng::from_str(&format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {name} }}\n\
             spec:\n  image: {{ repo: a/b, tag: \"1\" }}\n  \
             requires:\n    - kind: database\n      engine: postgres\n"
        ))
        .expect("manifest")
    }

    #[tokio::test]
    async fn a_pass_for_one_app_takes_nothing_of_the_others() {
        // "Back up now" on one app ran a provider over every app's volumes, recorded
        // without a destination. The pass it runs now is the loop's, held to that app.
        let state = State::in_memory().await.expect("state");
        let vault = Vault::ephemeral();
        for app in ["gitea", "immich"] {
            state
                .upsert_app(app, &app_with_database(app), None)
                .await
                .expect("app");
        }
        nas_declared(&state).await;
        let mut p = pass(&state, &vault, Path::new("/unused"));
        p.force = true;
        p.only = Some("gitea");
        let mut events = Vec::new();
        p.run(&mut |e| events.push(e)).await.expect("pass");
        let whats: Vec<String> = events
            .iter()
            .map(|e| match e {
                Event::Done { what, .. }
                | Event::Failed { what, .. }
                | Event::NotCovered { what, .. } => what.clone(),
            })
            .collect();
        // No admin URL: the dump is said not covered, which needs no Docker.
        assert_eq!(whats, ["gitea/gitea"], "{events:?}");
    }

    #[tokio::test]
    async fn a_volume_copied_stopped_is_not_copied_live_when_nothing_can_stop_it() {
        // 🔴 Stalwart's RocksDB copied while it runs restored nothing, and restic said
        // nothing: a copy taken anyway would be recorded fresh.
        let state = State::in_memory().await.expect("state");
        let vault = Vault::ephemeral();
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            "apiVersion: hlb/v1\nkind: App\nmetadata: { name: mail }\n\
             spec:\n  image: { repo: a/b, tag: \"1\" }\n  requires:\n    \
             - { kind: storage, name: data, path: /data, copy: stopped }\n",
        )
        .expect("manifest");
        state.upsert_app("mail", &m, None).await.expect("app");
        state
            .add_volume("mail", "mail-data", "/unused", true, false)
            .await
            .expect("volume");
        nas_declared(&state).await;
        let mut p = pass(&state, &vault, Path::new("/unused"));
        p.force = true;
        p.only = Some("mail");
        let mut events = Vec::new();
        let sum = p.run(&mut |e| events.push(e)).await.expect("pass");
        assert_eq!(sum.done, 0, "{events:?}");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Failed { what, destination, error }
                if what == "mail volumes" && destination.as_deref() == Some("nas")
                    && error.contains("no orchestrator can stop it"))),
            "{events:?}"
        );
    }

    #[tokio::test]
    async fn a_volume_for_its_engine_s_tool_is_never_copied_live_without_its_administrator() {
        let state = State::in_memory().await.expect("state");
        let vault = Vault::ephemeral();
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            "apiVersion: hlb/v1\nkind: App\nmetadata: { name: postgres }\n\
             spec:\n  image: { repo: a/b, tag: \"1\" }\n  requires:\n    \
             - { kind: storage, name: data, path: /data, copy: pg-basebackup }\n",
        )
        .expect("manifest");
        state.upsert_app("postgres", &m, None).await.expect("app");
        state
            .add_volume("postgres", "postgres-data", "/unused", true, false)
            .await
            .expect("volume");
        nas_declared(&state).await;
        let mut p = pass(&state, &vault, Path::new("/unused"));
        p.force = true;
        p.only = Some("postgres");
        let mut events = Vec::new();
        let sum = p.run(&mut |e| events.push(e)).await.expect("pass");
        assert_eq!(sum.done, 0, "{events:?}");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Failed { what, error, .. }
                if what == "postgres volumes" && error.contains("not copied live instead"))),
            "{events:?}"
        );
    }

    #[tokio::test]
    async fn back_up_now_previews_each_destination_once_for_what_the_app_holds() {
        let state = State::in_memory().await.expect("state");
        state
            .upsert_app("gitea", &app_with_database("gitea"), None)
            .await
            .expect("app");
        state
            .add_volume("gitea", "gitea-data", "/data", true, false)
            .await
            .expect("volume");
        nas_declared(&state).await;
        state
            .upsert_destination("offsite", "s3:x/y", "critical", None)
            .await
            .expect("destination");
        let names = |d: Vec<Destination>| d.into_iter().map(|d| d.name).collect::<Vec<_>>();
        assert_eq!(
            names(destinations_of_app(&state, "gitea", None).await.expect("d")),
            ["nas", "offsite"]
        );
        // Holding nothing, an app is served nowhere — even with --backup-repo.
        state
            .upsert_app(
                "valkey",
                &serde_yaml_ng::from_str(
                    "apiVersion: hlb/v1\nkind: App\nmetadata: { name: valkey }\n\
                 spec:\n  image: { repo: a/b, tag: \"1\" }\n",
                )
                .expect("manifest"),
                None,
            )
            .await
            .expect("app");
        assert!(destinations_of_app(&state, "valkey", Some("/srv/repo"))
            .await
            .expect("d")
            .is_empty());
    }

    async fn nas_declared(state: &State) {
        state
            .upsert_destination("nas", "/mnt/nas", "critical,bulky", None)
            .await
            .expect("destination");
    }

    #[tokio::test]
    async fn the_state_is_as_backed_up_as_its_own_backup_and_no_other_apps() {
        // 🔴 The self-update read PostgreSQL's backup as the state's: any dump of any
        // age let a migration through, and the state's own never counted.
        let state = State::in_memory().await.expect("state");
        state
            .record_backup_to("postgres", backup_kind::SQL_DUMP, "nas", Some("d"), None)
            .await
            .expect("dump");
        assert_eq!(state_backup_age(&state).await.expect("age"), None);
        state
            .record_backup_to(STATE_APP, backup_kind::STATE, "nas", Some("s"), None)
            .await
            .expect("state");
        assert!(state_backup_age(&state).await.expect("age").is_some());
    }
}
