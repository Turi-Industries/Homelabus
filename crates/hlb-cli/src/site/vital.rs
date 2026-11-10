//! The vital apps' own PostgreSQL: installed with a site, each vital app's database
//! moved into it — what the house pushes to its site continuously, and nothing else
//! of the shared server.
//!
//! A database moves only here, never by a plan: the executor refuses one planned
//! elsewhere than it lives (`DatabaseElsewhere`). Each move, the app stopped meanwhile:
//! a copy of the database as it is, archived and recorded; the role and database made
//! on the new server and the copy restored into it; the server recorded; the app
//! redeployed onto it and waited healthy; and only then the old database dropped. A
//! failure before the server is recorded starts the app again on the old one,
//! untouched.

use hlb_backup_run::restore::{self, Database, Restore};
use hlb_orchestrator::SwarmOrchestrator;
use hlb_resolver::Action;
use hlb_secrets::Vault;
use hlb_state::State;
use hlb_types::{DbEngine, DbServer};

use crate::{relay, Cli, ACTOR_ROLE};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// One database to move: where it lives, where the house places it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Move {
    pub app: String,
    pub database: String,
    pub from: DbServer,
    pub to: DbServer,
}

/// Every database of an installed app living elsewhere than the house places it,
/// `vital_server` saying whether the vital server runs. Placed by
/// [`DbServer::placed`], the resolver's own rule: a second copy of it here would move
/// databases to where no plan looks for them.
pub async fn moves(state: &State, vital_server: bool) -> Result<Vec<Move>> {
    let mut out = Vec::new();
    for (app, status) in state.installed_apps().await? {
        // Its plan never ran whole: nothing says its database holds anything.
        if status == "failed" {
            continue;
        }
        let Ok(m) = state.app_manifest(&app).await else {
            continue;
        };
        for (engine, database, _) in restore::databases_of(&m, &app) {
            let to = DbServer::placed(engine, m.criticality(), vital_server);
            let from = state
                .database_server(&app, &database)
                .await?
                .unwrap_or_else(|| DbServer::shared(engine));
            if from != to {
                out.push(Move {
                    app: app.clone(),
                    database,
                    from,
                    to,
                });
            }
        }
    }
    Ok(out)
}

/// The vital server installed if it is not, and every vital app's database moved into
/// it. Whether everything went.
pub async fn run(cli: &Cli, state: &State, vault: &Vault, apply: bool) -> Result<bool> {
    let installed = crate::site::vital::installed(state).await?;
    let todo = moves(state, true).await?;
    if !apply {
        println!("  vital   : the vital apps' own PostgreSQL, {}", VITAL);
        if installed {
            println!("            installed");
        } else {
            println!("            installed now — the shared server's image, its own volume");
        }
        for m in &todo {
            println!(
                "            {}'s database {} moved from {}: stopped meanwhile, copied to",
                m.app,
                m.database,
                m.from.service_name()
            );
            println!("            its backups first, the old one dropped once it answers");
        }
        return super::wal::ship(cli, state, vault, false).await;
    }

    if !installed {
        println!("\nThe vital apps' own PostgreSQL:");
        let code = crate::install(cli, VITAL, None, None, true).await?;
        if code != std::process::ExitCode::SUCCESS {
            eprintln!("🔴 {VITAL} was not installed: no vital database moved.");
            return Ok(false);
        }
    }
    let todo = moves(state, true).await?;
    let orch = SwarmOrchestrator::connect().await?;
    let mut ok = true;
    let mut apps: Vec<&str> = todo.iter().map(|m| m.app.as_str()).collect();
    apps.dedup();
    for app in apps {
        let mine: Vec<&Move> = todo.iter().filter(|m| m.app == app).collect();
        println!("\nMoving {app}'s database to {VITAL}:");
        match move_app(cli, state, vault, &orch, app, &mine).await {
            Ok(()) => {
                state
                    .audit("cli", ACTOR_ROLE, "database-move", app, "ok", Some(VITAL))
                    .await?;
            }
            Err(e) => {
                eprintln!("  🔴 {e}");
                state
                    .audit("cli", ACTOR_ROLE, "database-move", app, "failed", Some(&e))
                    .await?;
                ok = false;
            }
        }
    }
    // Moved or not, what the server holds goes to the site.
    Ok(super::wal::ship(cli, state, vault, true).await? && ok)
}

const VITAL: &str = hlb_types::VITAL_POSTGRES;

/// Whether the vital server is recorded.
pub async fn installed(state: &State) -> Result<bool> {
    Ok(hlb_engine::install::vital_postgres(state).await?)
}

/// One app's databases moved, the app stopped across them all.
async fn move_app(
    cli: &Cli,
    state: &State,
    vault: &Vault,
    orch: &SwarmOrchestrator,
    app: &str,
    moving: &[&Move],
) -> std::result::Result<(), String> {
    let e = |e: Box<dyn std::error::Error>| e.to_string();
    let manifest = state.app_manifest(app).await.map_err(|e| e.to_string())?;
    // The provisioning the plan makes: the role, its password, its limit, the
    // extensions — read from it, never written a second time here.
    let plan = crate::plan_as_installed(cli, state, app).await.map_err(e)?;
    let access = hlb_engine::access::from_vault(state, vault)
        .await
        .map_err(|e| e.to_string())?;
    let restore = Restore {
        state,
        vault,
        fallback_repo: cli.backup_repo.as_deref(),
        network: &cli.platform_network,
        orchestrator: Some(orch),
    };
    let services = restore::replicas(orch, &hlb_engine::services_of(app, &manifest)).await;
    if let Err(not) = restore::stop_for_restore(
        orch,
        state,
        &services,
        &format!("move of {app}'s database to {VITAL}"),
        None,
    )
    .await
    {
        return Err(not.message().to_string());
    }
    println!("  ✓ stopped");

    let copied = async {
        for m in moving {
            copy_into(&restore, &access, &cli.platform_network, &plan, app, m).await?;
        }
        Ok::<_, String>(())
    }
    .await;
    if let Err(why) = copied {
        // Nothing recorded yet: the app comes back on its old database, untouched.
        let back = restore::start(orch, state, &services).await;
        return Err(match back {
            Ok(()) => format!("{why} — {app} started again on its old database"),
            Err(e) => format!("{why} — and {app} did not start again: {e}"),
        });
    }

    for m in moving {
        state
            .record_database_server(app, &m.database, m.to)
            .await
            .map_err(|e| e.to_string())?;
    }
    let redeployed = crate::redeploy(cli, state, app).await.map_err(e)?;
    restore::start(orch, state, &services).await?;
    if !redeployed {
        // Recorded on the new server, which holds the copy: the old one stays, the
        // way back if the app does not come up.
        return Err(format!(
            "{app} did not come up on {VITAL}; its old database stays on the shared \
             server, untouched — `hlb install {app} --apply` resumes"
        ));
    }
    println!("  ✓ {app} answers on {VITAL}");

    for m in moving {
        let Some(url) = access.database_admin(m.from) else {
            eprintln!(
                "  ⚠️  {} stays on {}: its administrator is in no vault here",
                m.database,
                m.from.service_name()
            );
            continue;
        };
        let dropped = async {
            let pg = hlb_platform::PostgresProvisioner::connect(&relay::reach(
                url,
                &cli.platform_network,
            ))
            .await?;
            pg.drop_database(&m.database).await
        }
        .await;
        match dropped {
            Ok(()) => println!("  ✓ {} dropped from {}", m.database, m.from.service_name()),
            Err(e) => eprintln!(
                "  ⚠️  {} stays on {} ({e}): nothing reads it",
                m.database,
                m.from.service_name()
            ),
        }
    }
    Ok(())
}

/// `m`'s database copied as it is and restored on its new server, made first as the
/// plan provisions it.
async fn copy_into(
    restore: &Restore<'_>,
    access: &hlb_engine::access::PlatformAccess,
    network: &str,
    plan: &hlb_resolver::Plan,
    app: &str,
    m: &Move,
) -> std::result::Result<(), String> {
    if m.to.engine() != DbEngine::Postgres || m.from.engine() != DbEngine::Postgres {
        return Err(format!("{}: only PostgreSQL moves", m.database));
    }
    let Some((role, password_secret, extensions, connection_limit)) =
        plan.actions.iter().find_map(|a| match a {
            Action::ProvisionDatabase {
                server: _,
                database,
                role,
                password_secret,
                extensions,
                connection_limit,
            } if *database == m.database => {
                Some((role, password_secret, extensions, connection_limit))
            }
            _ => None,
        })
    else {
        return Err(format!("{app}'s plan provisions no {}", m.database));
    };
    let (Some(from), Some(to)) = (access.database_admin(m.from), access.database_admin(m.to))
    else {
        return Err(format!(
            "the administrators of {} and {} are not both in the vault",
            m.from.service_name(),
            m.to.service_name()
        ));
    };
    let db = Database {
        engine: DbEngine::Postgres,
        name: &m.database,
        role,
        extensions,
    };

    let copy = restore.database_copy(app, &db, from).await?;
    println!(
        "  ✓ {} copied ({} KB), snapshot {}",
        m.database,
        copy.bytes / 1024,
        copy.source.snapshot.short_id()
    );

    let password = restore
        .state
        .secret(password_secret)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no {password_secret} in the vault"))
        .and_then(|ct| restore.vault.decrypt(&ct).map_err(|e| e.to_string()))?;
    let pg = hlb_platform::PostgresProvisioner::connect(&relay::reach(to, network))
        .await
        .map_err(|e| e.to_string())?;
    pg.provision(&m.database, role, &password)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(n) = connection_limit {
        pg.limit_connections(role, *n)
            .await
            .map_err(|e| e.to_string())?;
    }
    // The restore's own: what the new server held is copied first, the database
    // recreated as provisioning makes it, the extensions enabled, the dump restored as
    // the app's role.
    restore
        .database_in_place(app, &db, to, &copy.source)
        .await
        .map_err(|f| match f {
            restore::Failure::Refused(why) => {
                format!(
                    "{} not restored on {}: {why}",
                    m.database,
                    m.to.service_name()
                )
            }
            // Half restored on the new server, which nothing reads yet.
            restore::Failure::Interrupted { error, .. } => format!(
                "{} restored on {} only in part: {error}",
                m.database,
                m.to.service_name()
            ),
        })?;
    println!("  ✓ {} restored on {}", m.database, m.to.service_name());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(app: &str, vital: bool) -> hlb_types::Manifest {
        let mut metadata = serde_json::json!({ "name": app });
        if vital {
            metadata["criticality"] = "vital".into();
        }
        serde_json::from_value(serde_json::json!({
            "apiVersion": "hlb/v1",
            "kind": "App",
            "metadata": metadata,
            "spec": {
                "image": { "repo": "a/b", "tag": "1" },
                "requires": [{ "kind": "database", "engine": "postgres" }],
            },
        }))
        .expect("manifest")
    }

    #[tokio::test]
    async fn only_a_vital_app_s_database_moves_and_only_once_the_server_runs() {
        let state = State::in_memory().await.expect("state");
        for (app, vital) in [("vaultwarden", true), ("immich", false)] {
            state
                .upsert_app(app, &manifest(app, vital), None)
                .await
                .expect("upsert");
            state.set_app_status(app, "running").await.expect("status");
        }
        assert!(moves(&state, false).await.expect("read").is_empty());
        assert_eq!(
            moves(&state, true).await.expect("read"),
            vec![Move {
                app: "vaultwarden".into(),
                database: "vaultwarden".into(),
                from: DbServer::Postgres,
                to: DbServer::PostgresVital,
            }]
        );

        // Moved: nothing left — and the server gone, it would move back.
        state
            .record_database_server("vaultwarden", "vaultwarden", DbServer::PostgresVital)
            .await
            .expect("record");
        assert!(moves(&state, true).await.expect("read").is_empty());
        assert_eq!(
            moves(&state, false).await.expect("read")[0].to,
            DbServer::Postgres
        );
    }

    #[tokio::test]
    async fn a_failed_install_moves_nothing() {
        let state = State::in_memory().await.expect("state");
        state
            .upsert_app("vaultwarden", &manifest("vaultwarden", true), None)
            .await
            .expect("upsert");
        state
            .set_app_status("vaultwarden", "failed")
            .await
            .expect("status");
        assert!(moves(&state, true).await.expect("read").is_empty());
    }
}
