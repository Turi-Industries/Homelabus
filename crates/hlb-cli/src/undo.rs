//! `hlb update undo`: an app's last update taken back — its data as the copy taken
//! before it held them, its images as they were — the app stopped meanwhile.
//!
//! What may be undone is `hlb_updater::undo`'s; the restores are `hlb backup restore`'s
//! own, each backing up first what it replaces. This is the order they run in.

use std::process::ExitCode;

use hlb_backup_run::placement::Place;
use hlb_backup_run::restore::{self, Failure, Part, Restore, Source};
use hlb_orchestrator::{Orchestrator, SwarmOrchestrator};
use hlb_types::DbEngine;

/// How long each service is given to be healthy once started again.
const HEALTHY_SECS: u64 = 300;

/// What `hlb update undo` was asked.
pub struct Request<'a> {
    pub app: &'a str,
    pub confirm: Option<&'a str>,
    pub apply: bool,
}

/// One part of the app, found in the copy.
struct Found<'m> {
    what: Thing<'m>,
    source: Source,
}

enum Thing<'m> {
    Volume {
        name: String,
        place: Place,
    },
    Bucket(String),
    Database {
        engine: DbEngine,
        name: String,
        extensions: &'m [String],
        admin: String,
    },
}

impl Thing<'_> {
    fn describe(&self) -> String {
        match self {
            Self::Volume { name, .. } => format!("the volume {name}"),
            Self::Bucket(b) => format!("the bucket {b}"),
            Self::Database { name, .. } => format!("the database {name}"),
        }
    }
}

pub async fn run(
    cli: &crate::Cli,
    state: &hlb_state::State,
    vault: &hlb_secrets::Vault,
    r: Request<'_>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let app = r.app;
    let Ok(manifest) = state.app_manifest(app).await else {
        eprintln!("🔴 \"{app}\" is not installed.");
        return Ok(ExitCode::FAILURE);
    };
    let last = state.last_update_run(app).await?;
    let undo = match hlb_updater::undo::plan(app, last.as_ref(), &manifest.spec) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("🔴 {e}");
            return Ok(ExitCode::FAILURE);
        }
    };

    let orch = SwarmOrchestrator::connect().await.ok();
    let o = orch.as_ref().map(|o| o as &dyn Orchestrator);
    let restore = Restore {
        state,
        vault,
        fallback_repo: cli.backup_repo.as_deref(),
        network: &cli.platform_network,
        orchestrator: o,
    };

    // 🔴 Every part a pass backs up must be in the copy, or nothing is put back: the
    // volumes of before beside the database of after is neither day.
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for (volume, _) in state.volumes_to_backup(app).await? {
        match restore
            .find_in_copy(app, &Part::Volume(&volume), &undo.copies)
            .await
        {
            Ok(source) => {
                // Placed while the app runs: a stopped service on NFS runs nowhere.
                let place = restore
                    .place_of(app, &volume)
                    .await
                    .unwrap_or_else(Place::Unknown);
                if let Place::Unknown(why) = &place {
                    missing.push(why.clone());
                }
                found.push(Found {
                    what: Thing::Volume {
                        name: volume,
                        place,
                    },
                    source,
                });
            }
            Err(e) => missing.push(e),
        }
    }
    for bucket in state.buckets_to_backup(app).await? {
        match restore
            .find_in_copy(app, &Part::Bucket(&bucket), &undo.copies)
            .await
        {
            Ok(source) => found.push(Found {
                what: Thing::Bucket(bucket),
                source,
            }),
            Err(e) => missing.push(e),
        }
    }
    for (engine, name, extensions) in restore::databases_of(&manifest, app) {
        // 🔴 Exhaustive: an engine added to `DbEngine` must say where its admin is.
        let (admin, server, flag) = match engine {
            DbEngine::Postgres => (cli.postgres_admin.clone(), "PostgreSQL", "postgres"),
            DbEngine::Mariadb => (cli.mariadb_admin.clone(), "MariaDB", "mariadb"),
        };
        let Some(admin) = admin else {
            missing.push(format!(
                "{server}'s administrator is in no vault here (--{flag}-admin): {name} cannot \
                 be put back"
            ));
            continue;
        };
        match restore
            .find_in_copy(app, &Part::Database(engine, &name), &undo.copies)
            .await
        {
            Ok(source) => found.push(Found {
                what: Thing::Database {
                    engine,
                    name,
                    extensions,
                    admin,
                },
                source,
            }),
            Err(e) => missing.push(e),
        }
    }

    let when = |at: i64| {
        chrono::DateTime::from_timestamp(at, 0).map_or_else(
            || at.to_string(),
            |d| d.format("%Y-%m-%d %H:%M UTC").to_string(),
        )
    };
    println!("Undoing {app}'s update of {}\n", when(undo.ran_at));
    match &undo.image {
        Some(i) => println!("  {app}  {} → {}", undo.now, i.reference()),
        None => println!(
            "  {app}  stays on {}: the update moved its companions alone",
            undo.now
        ),
    }
    for c in &undo.companions {
        println!("  {}  → {}", c.service, c.image.reference());
    }
    for f in &found {
        let snap = &f.source.snapshot;
        println!(
            "  {}  from {} of {}, on {}",
            f.what.describe(),
            snap.short_id(),
            snap.time.split('.').next().unwrap_or(&snap.time),
            f.source.destination.name
        );
    }
    if !missing.is_empty() {
        eprintln!("\n🔴 The copy taken before the update cannot be put back whole:");
        for m in &missing {
            eprintln!("   · {m}");
        }
        eprintln!("   Nothing was undone.");
        return Ok(ExitCode::FAILURE);
    }
    if found.is_empty() {
        println!("  · {app} holds nothing to copy: only its images go back");
    }
    let services = match o {
        Some(o) => restore::replicas(o, &hlb_engine::services_of(app, &manifest)).await,
        None => Vec::new(),
    };
    let names: Vec<&str> = services.iter().map(|(s, _)| s.as_str()).collect();
    if !names.is_empty() {
        println!(
            "  · {} stopped meanwhile, then started again",
            names.join(", ")
        );
    }
    if !found.is_empty() {
        println!("  · what each holds now is backed up first: restoring those copies undoes this");
        println!(
            "  · 🔴 what was written since the update is LOST — and the update's migrations \
             with it"
        );
    }
    println!(
        "  · the automatic updates leave {} to a person from then on",
        undo.now
    );
    crate::restore::announce_after(cli, state, app).await?;

    if !r.apply {
        println!("\nPreview: nothing was changed.");
        println!("  hlb update undo {app} --confirm {app} --apply");
        return Ok(ExitCode::SUCCESS);
    }
    if r.confirm != Some(app) {
        eprintln!("\n🔴 Confirmation missing: --confirm {app}");
        return Ok(ExitCode::FAILURE);
    }
    let Some(o) = o else {
        eprintln!("\n🔴 Docker does not answer: {app} cannot be stopped, nothing was undone.");
        return Ok(ExitCode::FAILURE);
    };

    println!();
    // The volumes' node, recorded before anything stops, when they share one: a second
    // attempt finds them with no task left to ask.
    let mut nodes = Vec::new();
    for f in &found {
        if let Thing::Volume { place, .. } = &f.what {
            nodes.push(restore.node_of(place).await);
        }
    }
    nodes.sort();
    nodes.dedup();
    let at = match nodes.as_slice() {
        [Some(one)] => Some(one.clone()),
        _ => None,
    };
    if let Err(not) =
        restore::stop_for_restore(o, state, &services, "undo of an update", at.as_deref()).await
    {
        crate::restore::say_not_stopped(&not, app);
        audit(state, app, "refused", not.message()).await?;
        return Ok(ExitCode::FAILURE);
    }
    if !names.is_empty() {
        println!("✓ {} stopped", names.join(", "));
    }

    // 🔴 From the first write on, a failure leaves the app STOPPED: started on half the
    // copy, it would write over data of neither day. The copy is still there, by the
    // run's ids: the same command again puts it all back.
    let again = format!("hlb update undo {app} --confirm {app} --apply");
    let endpoint = crate::relay::reach(hlb_objstore::S3_URL, &cli.platform_network);
    let mut before: Vec<String> = Vec::new();
    for f in &found {
        let short = f.source.snapshot.short_id();
        let done = match &f.what {
            Thing::Volume { name, place } => {
                match restore.in_place(app, name, place, &f.source).await {
                    Ok(b) => {
                        // Copied with the app stopped: the volume's SQLite opens as it is.
                        match restore.sqlite_after(app, name, place, &f.source).await {
                            Ok(_) => Ok(b),
                            Err(e) => Err(Failure::Interrupted {
                                before: b,
                                error: format!("its SQLite databases: {e}"),
                            }),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            Thing::Bucket(b) => restore
                .bucket_in_place(app, b, &endpoint, &f.source)
                .await
                .map(|(before, _)| before),
            Thing::Database {
                engine,
                name,
                extensions,
                admin,
            } => {
                let db = restore::Database {
                    engine: *engine,
                    name,
                    // The resolver's: the role is the app's, whatever the database is called.
                    role: app,
                    extensions,
                };
                restore.database_in_place(app, &db, admin, &f.source).await
            }
        };
        match done {
            Ok(b) => {
                println!(
                    "✓ {} put back from {short} — what it held is snapshot {}",
                    f.what.describe(),
                    &b[..8.min(b.len())]
                );
                before.push(format!("{}: {b}", f.what.describe()));
            }
            // Nothing written yet: the app goes back to what it was.
            Err(Failure::Refused(e)) if before.is_empty() => {
                restore::start(o, state, &services).await?;
                eprintln!("🔴 {e}\n   Nothing was undone, and {app} is started again.");
                audit(state, app, "refused", &e).await?;
                return Ok(ExitCode::FAILURE);
            }
            Err(failed) => {
                let error = match failed {
                    Failure::Refused(e) => e,
                    // What it held before this write began: half written now.
                    Failure::Interrupted { before: b, error } => {
                        before.push(format!("{}: {b}", f.what.describe()));
                        error
                    }
                };
                eprintln!("🔴 {} could not be put back: {error}", f.what.describe());
                stopped_halfway(app, &before, &again);
                audit(state, app, "failed", &error).await?;
                return Ok(ExitCode::FAILURE);
            }
        }
    }

    // The images, while nothing runs: no task starts on the new image over the old data.
    // Companions first, the install's order; each frozen once Swarm took it.
    let mut moves: Vec<(String, String)> = undo
        .companions
        .iter()
        .map(|c| (c.service.clone(), c.image.reference()))
        .collect();
    if let Some(i) = &undo.image {
        moves.push((app.to_string(), i.reference()));
    }
    for (service, reference) in &moves {
        // Reconciliation leaves the image alone until it is frozen.
        state.begin_switch(service, reference, 600).await?;
        let pushed = o.update_image(service, reference).await;
        let frozen = match pushed {
            Ok(()) => freeze(state, app, &undo, service).await,
            Err(e) => Err(e.to_string()),
        };
        state.end_switch(service).await?;
        if let Err(e) = frozen {
            eprintln!("🔴 {service} could not go back to {reference}: {e}");
            stopped_halfway(app, &before, &again);
            audit(state, app, "failed", &e).await?;
            return Ok(ExitCode::FAILURE);
        }
        println!("✓ {service} back on {reference}");
    }

    // Recorded once the images are back, whatever the start says: a second undo would
    // restore the same copy over what this one gave back.
    let back = undo
        .image
        .as_ref()
        .map_or_else(|| undo.now.clone(), |i| i.reference());
    state
        .record_update_run(&hlb_state::UpdateRun {
            id: 0,
            app: app.to_string(),
            ran_at: chrono::Utc::now().timestamp(),
            from_image: undo.now.clone(),
            to_image: back.clone(),
            outcome: hlb_state::UpdateRunOutcome::Undone,
            detail: format!("run {} undone", undo.run),
            undo: None,
        })
        .await?;
    audit(
        state,
        app,
        "ok",
        &format!(
            "run {}: {} → {back}; {}",
            undo.run,
            undo.now,
            before.join("; ")
        ),
    )
    .await?;

    restore::start(o, state, &services).await?;
    if !names.is_empty() {
        println!("✓ {} started again", names.join(", "));
    }
    let mut healthy = true;
    for (s, replicas) in &services {
        if *replicas == 0 {
            continue;
        }
        if let Err(e) = o.wait_healthy(s, HEALTHY_SECS).await {
            eprintln!("🔴 {s} is not healthy after {HEALTHY_SECS} s: {e}");
            healthy = false;
        }
    }
    if !healthy {
        eprintln!("   The update is undone, and {app} does not run as it did: hlb ps {app}");
        return Ok(ExitCode::FAILURE);
    }
    println!("✓ {app} healthy");
    let after = crate::restore::after(cli, state, o, app, &manifest).await?;
    Ok(if after {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// `service`'s image before the update, frozen into the app's manifest.
async fn freeze(
    state: &hlb_state::State,
    app: &str,
    undo: &hlb_updater::undo::Undo,
    service: &str,
) -> Result<(), String> {
    let mut m = state.app_manifest(app).await.map_err(|e| e.to_string())?;
    if service == app {
        if let Some(i) = &undo.image {
            m.spec.image = i.clone();
        }
    } else if let Some(c) = undo.companions.iter().find(|c| c.service == service) {
        if let Some(frozen) = m.spec.companions.iter_mut().find(|f| f.name == c.name) {
            frozen.image = c.image.clone();
        }
    }
    let domain = state.app_domain(app).await.map_err(|e| e.to_string())?;
    state
        .upsert_app(app, &m, domain.as_deref())
        .await
        .map_err(|e| e.to_string())
}

/// Says what an undo stopped halfway left: the app stopped, what each part held before.
fn stopped_halfway(app: &str, before: &[String], again: &str) {
    eprintln!("   {app} is left STOPPED. The copy is still there; the same command puts it");
    eprintln!("   all back:  {again}");
    if !before.is_empty() {
        eprintln!("   What was replaced so far, as it was:");
        for b in before {
            eprintln!("     {b}");
        }
    }
}

async fn audit(
    state: &hlb_state::State,
    app: &str,
    outcome: &str,
    detail: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    state
        .audit(
            "cli",
            crate::ACTOR_ROLE,
            "update-undone",
            app,
            outcome,
            Some(detail),
        )
        .await?;
    Ok(())
}
