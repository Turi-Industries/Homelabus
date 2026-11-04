//! `hlb backup restore`: a volume, a bucket or a database put back as one of its
//! snapshots holds it.
//!
//! The decisions live in `hlb_backup_run::restore`; this is the order they run in, and
//! what is said before and after.

use std::process::ExitCode;

use hlb_backup_run::placement::Place;
use hlb_backup_run::restore::{self, Failure, Restore};
use hlb_orchestrator::SwarmOrchestrator;

/// What `hlb backup restore` was asked.
pub struct Request<'a> {
    pub app: &'a str,
    pub volume: Option<&'a str>,
    /// `--database`: `""` for the app's only one.
    pub database: Option<&'a str>,
    pub snapshot: Option<&'a str>,
    pub from: Option<&'a str>,
    pub apply: bool,
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
    if let Some(name) = r.database {
        return database(cli, state, vault, app, &manifest, name, &r).await;
    }
    let volumes: Vec<String> = state
        .volumes_to_backup(app)
        .await?
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    let buckets = state.buckets_to_backup(app).await?;
    let held: Vec<String> = volumes.iter().chain(&buckets).cloned().collect();
    let volume = match (r.volume, held.as_slice()) {
        (Some(v), _) if held.iter().any(|n| n == v) => v.to_string(),
        (Some(v), _) => {
            eprintln!(
                "🔴 {app} backs up no volume or bucket \"{v}\" — {}",
                if held.is_empty() {
                    "it backs up none".to_string()
                } else {
                    held.join(", ")
                }
            );
            return Ok(ExitCode::FAILURE);
        }
        (None, [only]) => only.clone(),
        (None, []) if !restore::databases_of(&manifest, app).is_empty() => {
            eprintln!("🔴 {app} backs up no volume and no bucket — its database: --database");
            return Ok(ExitCode::FAILURE);
        }
        (None, []) => {
            eprintln!("🔴 {app} backs up no volume and no bucket: there is nothing to restore.");
            return Ok(ExitCode::FAILURE);
        }
        (None, several) => {
            eprintln!("Which of {app}'s? {}", several.join(", "));
            if !restore::databases_of(&manifest, app).is_empty() {
                eprintln!("  its database: --database");
            }
            return Ok(ExitCode::FAILURE);
        }
    };
    if !volumes.contains(&volume) {
        return bucket(cli, state, vault, app, &manifest, &volume, &r).await;
    }

    let orch = SwarmOrchestrator::connect().await.ok();
    let o = orch
        .as_ref()
        .map(|o| o as &dyn hlb_orchestrator::Orchestrator);
    let restore = Restore {
        state,
        vault,
        fallback_repo: cli.backup_repo.as_deref(),
        network: &cli.platform_network,
        orchestrator: o,
    };
    let source = match restore.find(app, &volume, r.from, r.snapshot).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("🔴 {e}");
            return Ok(ExitCode::FAILURE);
        }
    };
    let place = restore
        .place_of(app, &volume)
        .await
        .unwrap_or_else(Place::Unknown);
    let services = match o {
        Some(o) => restore::replicas(o, &hlb_engine::services_of(app, &manifest)).await,
        None => Vec::new(),
    };

    let snap = &source.snapshot;
    println!("Restoring {volume} of {app}\n");
    println!(
        "  from  {} of {}, on {}",
        snap.short_id(),
        snap.time.split('.').next().unwrap_or(&snap.time),
        source.destination.name
    );
    for (s, why) in &source.set_aside {
        // Above what is restored: the person decides with it in front of them.
        println!(
            "  ⚠️ set aside: {} of {}, {}",
            s.short_id(),
            s.time.split('.').next().unwrap_or(&s.time),
            why.describe()
        );
    }
    if !source.set_aside.is_empty() {
        println!(
            "     a backup someone else wrote into the repository is not restored: \
             --snapshot <its full id> if it is good"
        );
    }
    match &place {
        Place::Here => println!("  on    this machine"),
        Place::Node { hostname, .. } => println!("  on    {hostname}, where {app} runs"),
        Place::Unknown(why) => {
            eprintln!("\n🔴 {why}");
            return Ok(ExitCode::FAILURE);
        }
    }
    let names: Vec<&str> = services.iter().map(|(s, _)| s.as_str()).collect();
    if !names.is_empty() {
        println!(
            "  · {} stopped meanwhile, then started again",
            names.join(", ")
        );
    }
    println!(
        "  · what {volume} holds now is backed up first, to {}: restoring it undoes this",
        source.destination.name
    );
    println!("  · 🔴 what was written since is LOST, and the files added since are deleted");
    let sqlite = state
        .sqlite_volumes()
        .await?
        .iter()
        .any(|(a, v, _)| a == app && *v == volume);
    if sqlite {
        println!(
            "  · its SQLite databases then put back from the consistent snapshot the same \
             pass took of each — one without such a snapshot stays as restic copied it, live"
        );
    }

    announce_after(cli, state, app).await?;
    if !r.apply {
        println!("\nPreview: nothing was changed.");
        // The snapshot named, in full: "the latest" may be another one by the time it
        // runs, and a full id is what pins one this installation has no record of.
        println!(
            "  hlb backup restore {app} {volume} --snapshot {} --from {} --apply",
            snap.id, source.destination.name
        );
        return Ok(ExitCode::SUCCESS);
    }
    let Some(o) = o else {
        eprintln!("\n🔴 Docker does not answer: {app} cannot be stopped, nothing was restored.");
        return Ok(ExitCode::FAILURE);
    };

    println!();
    if let Err(not) =
        restore::stop_for_restore(o, state, &services, &format!("restore of {volume}")).await
    {
        say_not_stopped(&not, app);
        audit(state, app, "refused", not.message()).await?;
        return Ok(ExitCode::FAILURE);
    }
    if !names.is_empty() {
        println!("✓ {} stopped", names.join(", "));
    }
    match restore.in_place(app, &volume, &place, &source).await {
        Ok(before) => {
            println!(
                "✓ {volume} restored from {} — what it held is snapshot {}",
                snap.short_id(),
                &before[..8.min(before.len())]
            );
            // Asked whatever the flag says: the pass snapshots a database it finds in any
            // volume, and pairs it by the pass's tag, so a volume without one gets nothing.
            match restore.sqlite_after(app, &volume, &place, &source).await {
                Ok(back) if back.is_empty() && !sqlite => {}
                Ok(back) if back.is_empty() => println!(
                    "  ⚠️ no consistent snapshot of its SQLite databases from that pass: \
                         they are as restic copied them, live"
                ),
                Ok(back) => {
                    for (db, id) in back {
                        println!(
                            "✓ {db} put back from its consistent snapshot {}",
                            &id[..8.min(id.len())]
                        );
                    }
                }
                Err(e) => {
                    // Left stopped: a database half put back is neither copy.
                    eprintln!("🔴 its SQLite databases could not be put back: {e}");
                    eprintln!("   {app} is left STOPPED. What {volume} held is snapshot {before}:");
                    eprintln!(
                        "   hlb backup restore {app} {volume} --snapshot {} --from {} --apply",
                        &before[..8.min(before.len())],
                        source.destination.name
                    );
                    audit(state, app, "failed", &e).await?;
                    return Ok(ExitCode::FAILURE);
                }
            }
            restore::start(o, state, &services).await?;
            if !names.is_empty() {
                println!("✓ {} started again", names.join(", "));
            }
            audit(state, app, "ok", &format!("{volume} from {}", snap.id)).await?;
            finished(after(cli, state, o, app, &manifest).await?)
        }
        Err(Failure::Refused(e)) => {
            restore::start(o, state, &services).await?;
            eprintln!("🔴 {e}\n   Nothing was restored, and {app} is started again.");
            audit(state, app, "refused", &e).await?;
            Ok(ExitCode::FAILURE)
        }
        Err(Failure::Interrupted { before, error }) => {
            // Left stopped: started on a half-restored volume, the app would write
            // over data that is neither the old nor the new.
            eprintln!("🔴 the restore stopped halfway: {error}");
            eprintln!("   {app} is left STOPPED. What {volume} held is snapshot {before}:");
            eprintln!(
                "   hlb backup restore {app} {volume} --snapshot {} --from {} --apply",
                &before[..8.min(before.len())],
                source.destination.name
            );
            audit(state, app, "failed", &error).await?;
            Ok(ExitCode::FAILURE)
        }
    }
}

/// The same for a bucket: its archive put back through the app's own key, the app
/// stopped meanwhile, what it holds now backed up first.
async fn bucket(
    cli: &crate::Cli,
    state: &hlb_state::State,
    vault: &hlb_secrets::Vault,
    app: &str,
    manifest: &hlb_types::Manifest,
    bucket: &str,
    r: &Request<'_>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let orch = SwarmOrchestrator::connect().await.ok();
    let o = orch
        .as_ref()
        .map(|o| o as &dyn hlb_orchestrator::Orchestrator);
    let restore = Restore {
        state,
        vault,
        fallback_repo: cli.backup_repo.as_deref(),
        network: &cli.platform_network,
        orchestrator: o,
    };
    let source = match restore.find_bucket(app, bucket, r.from, r.snapshot).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("🔴 {e}");
            return Ok(ExitCode::FAILURE);
        }
    };
    let services = match o {
        Some(o) => restore::replicas(o, &hlb_engine::services_of(app, manifest)).await,
        None => Vec::new(),
    };
    let snap = &source.snapshot;
    println!("Restoring the bucket {bucket} of {app}\n");
    println!(
        "  from  {} of {}, on {}",
        snap.short_id(),
        snap.time.split('.').next().unwrap_or(&snap.time),
        source.destination.name
    );
    for (s, why) in &source.set_aside {
        println!(
            "  ⚠️ set aside: {} of {}, {}",
            s.short_id(),
            s.time.split('.').next().unwrap_or(&s.time),
            why.describe()
        );
    }
    let names: Vec<&str> = services.iter().map(|(s, _)| s.as_str()).collect();
    if !names.is_empty() {
        println!(
            "  · {} stopped meanwhile, then started again",
            names.join(", ")
        );
    }
    println!(
        "  · what {bucket} holds now is backed up first, to {}: restoring it undoes this",
        source.destination.name
    );
    println!("  · 🔴 what was written since is LOST, and the objects added since are deleted");
    announce_after(cli, state, app).await?;
    if !r.apply {
        println!("\nPreview: nothing was changed.");
        println!(
            "  hlb backup restore {app} {bucket} --snapshot {} --from {} --apply",
            snap.id, source.destination.name
        );
        return Ok(ExitCode::SUCCESS);
    }
    let Some(o) = o else {
        eprintln!("\n🔴 Docker does not answer: {app} cannot be stopped, nothing was restored.");
        return Ok(ExitCode::FAILURE);
    };
    let endpoint = crate::relay::reach(hlb_objstore::S3_URL, &cli.platform_network);

    println!();
    if let Err(not) =
        restore::stop_for_restore(o, state, &services, &format!("restore of bucket {bucket}")).await
    {
        say_not_stopped(&not, app);
        audit_as(state, "bucket-restore", app, "refused", not.message()).await?;
        return Ok(ExitCode::FAILURE);
    }
    if !names.is_empty() {
        println!("✓ {} stopped", names.join(", "));
    }
    match restore
        .bucket_in_place(app, bucket, &endpoint, &source)
        .await
    {
        Ok((before, put)) => {
            println!(
                "✓ {bucket} restored from {}: {} objects written, {} deleted — what it held \
                 is snapshot {}",
                snap.short_id(),
                put.written,
                put.deleted,
                &before[..8.min(before.len())]
            );
            restore::start(o, state, &services).await?;
            if !names.is_empty() {
                println!("✓ {} started again", names.join(", "));
            }
            audit_as(
                state,
                "bucket-restore",
                app,
                "ok",
                &format!("{bucket} from {}", snap.id),
            )
            .await?;
            finished(after(cli, state, o, app, manifest).await?)
        }
        Err(Failure::Refused(e)) => {
            restore::start(o, state, &services).await?;
            eprintln!("🔴 {e}\n   Nothing was restored, and {app} is started again.");
            audit_as(state, "bucket-restore", app, "refused", &e).await?;
            Ok(ExitCode::FAILURE)
        }
        Err(Failure::Interrupted { before, error }) => {
            // Left stopped: started on a half-restored bucket, the app would serve
            // objects of two different days.
            eprintln!("🔴 the restore stopped halfway: {error}");
            eprintln!("   {app} is left STOPPED. What {bucket} held is snapshot {before}:");
            eprintln!(
                "   hlb backup restore {app} {bucket} --snapshot {} --from {} --apply",
                &before[..8.min(before.len())],
                source.destination.name
            );
            audit_as(state, "bucket-restore", app, "failed", &error).await?;
            Ok(ExitCode::FAILURE)
        }
    }
}

/// The same for a database: its dump restored into it, recreated as provisioning makes
/// it, the app stopped meanwhile, what it holds now dumped first.
async fn database(
    cli: &crate::Cli,
    state: &hlb_state::State,
    vault: &hlb_secrets::Vault,
    app: &str,
    manifest: &hlb_types::Manifest,
    name: &str,
    r: &Request<'_>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let all = restore::databases_of(manifest, app);
    let found = match (name, all.as_slice()) {
        ("", [only]) => only,
        ("", []) => {
            eprintln!("🔴 {app} has no database.");
            return Ok(ExitCode::FAILURE);
        }
        ("", several) => {
            let names: Vec<&str> = several.iter().map(|(_, n, _)| n.as_str()).collect();
            eprintln!("Which of {app}'s databases? --database {}", names.join("|"));
            return Ok(ExitCode::FAILURE);
        }
        (n, all) => match all.iter().find(|(_, d, _)| d == n) {
            Some(d) => d,
            None => {
                eprintln!("🔴 {app} has no database \"{n}\".");
                return Ok(ExitCode::FAILURE);
            }
        },
    };
    let (engine, db_name, extensions) = (found.0, found.1.as_str(), found.2);
    // 🔴 Exhaustive: an engine added to `DbEngine` must decide where it is restored from.
    let (admin, server, flag) = match engine {
        hlb_types::DbEngine::Postgres => (cli.postgres_admin.as_deref(), "PostgreSQL", "postgres"),
        hlb_types::DbEngine::Mariadb => (cli.mariadb_admin.as_deref(), "MariaDB", "mariadb"),
    };
    let Some(admin) = admin else {
        eprintln!(
            "🔴 {server}'s administrator is in no vault here (--{flag}-admin): nothing can \
             be restored."
        );
        return Ok(ExitCode::FAILURE);
    };

    let orch = SwarmOrchestrator::connect().await.ok();
    let o = orch
        .as_ref()
        .map(|o| o as &dyn hlb_orchestrator::Orchestrator);
    let restore = Restore {
        state,
        vault,
        fallback_repo: cli.backup_repo.as_deref(),
        network: &cli.platform_network,
        orchestrator: o,
    };
    let source = match restore
        .find_dump(app, engine, db_name, r.from, r.snapshot)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("🔴 {e}");
            return Ok(ExitCode::FAILURE);
        }
    };
    let services = match o {
        Some(o) => restore::replicas(o, &hlb_engine::services_of(app, manifest)).await,
        None => Vec::new(),
    };
    let snap = &source.snapshot;
    println!("Restoring the database {db_name} of {app}\n");
    println!(
        "  from  {} of {}, on {}",
        snap.short_id(),
        snap.time.split('.').next().unwrap_or(&snap.time),
        source.destination.name
    );
    for (s, why) in &source.set_aside {
        println!(
            "  ⚠️ set aside: {} of {}, {}",
            s.short_id(),
            s.time.split('.').next().unwrap_or(&s.time),
            why.describe()
        );
    }
    let names: Vec<&str> = services.iter().map(|(s, _)| s.as_str()).collect();
    if !names.is_empty() {
        println!(
            "  · {} stopped meanwhile, then started again",
            names.join(", ")
        );
    }
    println!(
        "  · what {db_name} holds now is dumped first, to {}: restoring it undoes this",
        source.destination.name
    );
    println!(
        "  · 🔴 {db_name} is DROPPED and recreated: what was written since is LOST, a table \
         made since included"
    );
    match engine {
        hlb_types::DbEngine::Postgres => {}
        hlb_types::DbEngine::Mariadb => println!(
            "  · MariaDB restores table by table, not in one transaction: stopped halfway, \
             {app} stays stopped and the copy taken first is named"
        ),
    }
    announce_after(cli, state, app).await?;
    if !r.apply {
        println!("\nPreview: nothing was changed.");
        println!(
            "  hlb backup restore {app} --database {db_name} --snapshot {} --from {} --apply",
            snap.id, source.destination.name
        );
        return Ok(ExitCode::SUCCESS);
    }
    let Some(o) = o else {
        eprintln!("\n🔴 Docker does not answer: {app} cannot be stopped, nothing was restored.");
        return Ok(ExitCode::FAILURE);
    };

    println!();
    if let Err(not) =
        restore::stop_for_restore(o, state, &services, &format!("restore of database {name}")).await
    {
        say_not_stopped(&not, app);
        audit_as(state, "database-restore", app, "refused", not.message()).await?;
        return Ok(ExitCode::FAILURE);
    }
    if !names.is_empty() {
        println!("✓ {} stopped", names.join(", "));
    }
    let db = restore::Database {
        engine,
        name: db_name,
        // The resolver's: the role is the app's, whatever the database is called.
        role: app,
        extensions,
    };
    match restore.database_in_place(app, &db, admin, &source).await {
        Ok(before) => {
            println!(
                "✓ {db_name} restored from {} — what it held is snapshot {}",
                snap.short_id(),
                &before[..8.min(before.len())]
            );
            restore::start(o, state, &services).await?;
            if !names.is_empty() {
                println!("✓ {} started again", names.join(", "));
            }
            audit_as(
                state,
                "database-restore",
                app,
                "ok",
                &format!("{db_name} from {}", snap.id),
            )
            .await?;
            finished(after(cli, state, o, app, manifest).await?)
        }
        Err(Failure::Refused(e)) => {
            restore::start(o, state, &services).await?;
            eprintln!("🔴 {e}\n   Nothing was restored, and {app} is started again.");
            audit_as(state, "database-restore", app, "refused", &e).await?;
            Ok(ExitCode::FAILURE)
        }
        Err(Failure::Interrupted { before, error }) => {
            // Left stopped: started on an empty or half-made database, the app would
            // migrate it as a new install and write over neither copy.
            eprintln!("🔴 the restore stopped halfway: {error}");
            eprintln!("   {app} is left STOPPED. What {db_name} held is snapshot {before}:");
            eprintln!(
                "   hlb backup restore {app} --database {db_name} --snapshot {} --from {} --apply",
                &before[..8.min(before.len())],
                source.destination.name
            );
            audit_as(state, "database-restore", app, "failed", &error).await?;
            Ok(ExitCode::FAILURE)
        }
    }
}

/// A restore done is a success only once what follows it is done too.
fn finished(after: bool) -> Result<ExitCode, Box<dyn std::error::Error>> {
    Ok(if after {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// The app's post-restore steps, from the guide frozen with it — the catalog's for an
/// app recorded before guides were frozen.
async fn post_restore_guide(
    cli: &crate::Cli,
    state: &hlb_state::State,
    app: &str,
) -> Result<hlb_types::Guide, Box<dyn std::error::Error>> {
    let mut guide = hlb_engine::install::installed_guide(state, app, || {
        hlb_catalog::Catalog::load(&cli.catalog)
            .ok()
            .and_then(|c| c.get(app).ok().map(|e| e.guide.clone()))
    })
    .await?;
    guide
        .steps
        .retain(|s| s.phase == hlb_types::Phase::PostRestore);
    Ok(guide)
}

/// What a preview says will follow the restore.
async fn announce_after(
    cli: &crate::Cli,
    state: &hlb_state::State,
    app: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for s in post_restore_guide(cli, state, app).await?.steps {
        println!("  · then: {}", s.title);
    }
    Ok(())
}

/// The post-restore steps, run on the app started again, and what each did. `false`
/// when one did not: the data is back, and what was to follow it is not done.
async fn after(
    cli: &crate::Cli,
    state: &hlb_state::State,
    o: &dyn hlb_orchestrator::Orchestrator,
    app: &str,
    manifest: &hlb_types::Manifest,
) -> Result<bool, Box<dyn std::error::Error>> {
    let guide = post_restore_guide(cli, state, app).await?;
    if guide.steps.is_empty() {
        return Ok(true);
    }
    let network = cli.platform_network.clone();
    let client = hlb_guide::HttpApi::default().reaching(move |u| crate::relay::reach(u, &network));
    let api = hlb_guide::Api {
        client: &client,
        port: manifest.spec.ingress.first().map(|i| i.port),
        // `validate_guide` refuses a post-restore step that signs in.
        sign_ins: &[],
    };
    let domain = state.app_domain(app).await?.unwrap_or_default();
    let vars = [("domain", domain.as_str())];
    let done = hlb_guide::after_restore(o, Some(api), app, &guide, &vars).await;

    let mut left = Vec::new();
    for (step, outcome) in &done {
        match outcome {
            hlb_guide::AutomationOutcome::Applied { .. }
            | hlb_guide::AutomationOutcome::AlreadyDone { .. } => {
                println!("✓ {} — {}", step.title, outcome.describe());
            }
            hlb_guide::AutomationOutcome::FellBackToManual { .. }
            | hlb_guide::AutomationOutcome::NothingDeclared => {
                eprintln!("🔴 {} — {}", step.title, outcome.describe());
                for line in hlb_types::guide::render(&step.body, &vars).lines() {
                    eprintln!("   {line}");
                }
                left.push(format!("{}: {}", step.id, outcome.describe()));
            }
        }
    }
    let ids: Vec<&str> = done.iter().map(|(s, _)| s.id.as_str()).collect();
    if left.is_empty() {
        audit_as(state, "post-restore", app, "ok", &ids.join(", ")).await?;
    } else {
        audit_as(state, "post-restore", app, "failed", &left.join("; ")).await?;
    }
    Ok(left.is_empty())
}

/// Says why a restore did not begin, and whether the app runs.
fn say_not_stopped(not: &restore::NotStopped, app: &str) {
    match not {
        restore::NotStopped::Copying(why) => eprintln!("🔴 {why}. Nothing was restored."),
        restore::NotStopped::Failed(why) => {
            eprintln!("🔴 {why}: nothing was restored, and {app} is started again.");
        }
    }
}

async fn audit(
    state: &hlb_state::State,
    app: &str,
    outcome: &str,
    detail: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    audit_as(state, "volume-restore", app, outcome, detail).await
}

async fn audit_as(
    state: &hlb_state::State,
    action: &str,
    app: &str,
    outcome: &str,
    detail: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    state
        .audit("cli", crate::ACTOR_ROLE, action, app, outcome, Some(detail))
        .await?;
    Ok(())
}
