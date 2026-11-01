//! A database server's data directory, copied by the engine's own tool while it runs.
//!
//! 🔴 restic reading PostgreSQL's directory takes each file at another instant, and no
//! recovery mends that: the copy would be recorded fresh and refuse to start the day it
//! is needed. `pg_basebackup` writes a directory that starts as a server crashed at the
//! copy's end — into a staging volume beside the real one, on the same machine, which
//! the pass then backs up AT THE REAL VOLUME'S PATH: the snapshot reads as the volume's
//! own, and the existing volume restore puts back a directory that starts.
use std::collections::BTreeMap;

use hlb_orchestrator::{Orchestrator, ServiceSpec};
use hlb_state::State;
use hlb_types::{Capability, DbEngine};

use crate::placement::Place;

/// Where the staging volume is mounted in the copying container.
const STAGE: &str = "/stage";
/// Where a job reads its secret variables from: a file each, never a variable
/// `docker service inspect` would print while the job runs.
const ENV_DIR: &str = "/run/hlb/env";
/// A copy that does not end is said to have not ended.
const TIMEOUT_S: u64 = 3600;

/// The engines' administrator URLs, as the pass is given them.
#[derive(Debug, Clone, Copy, Default)]
pub struct Admins<'a> {
    pub postgres: Option<&'a str>,
    pub mariadb: Option<&'a str>,
}

/// The volume a copy of `volume` is written to, beside it.
pub fn staging(volume: &str) -> String {
    format!("hlb-copy-{volume}")
}

/// One volume to copy by its engine's tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Copy {
    pub volume: String,
    pub engine: DbEngine,
}

/// The volumes of `app`'s frozen manifest declaring an engine's tool. Companions'
/// volumes cannot declare one (refused by the manifest's validation).
pub(crate) async fn declared(state: &State, app: &str) -> crate::Result<Vec<Copy>> {
    Ok(state
        .app_manifest(app)
        .await?
        .spec
        .requires
        .iter()
        .filter_map(|c| match c {
            Capability::Storage { name, copy, .. } => copy.engine().map(|engine| Copy {
                volume: format!("{app}-{name}"),
                engine,
            }),
            _ => None,
        })
        .collect())
}

/// Takes each of `copies` into its staging volume, where its volume lives: the volumes
/// to read in their place (`volume → staging`). `Err`: nothing is taken live instead.
pub(crate) async fn take(
    state: &State,
    orch: Option<&dyn Orchestrator>,
    network: &str,
    admins: Admins<'_>,
    app: &str,
    copies: &[Copy],
    places: &BTreeMap<Place, Vec<String>>,
) -> crate::Result<Result<BTreeMap<String, String>, String>> {
    let image = state.app_manifest(app).await?.spec.image.reference();
    let mut sources = BTreeMap::new();
    for c in copies {
        let Some(place) = places
            .iter()
            .find(|(_, vs)| vs.contains(&c.volume))
            .map(|(p, _)| p)
        else {
            return Ok(Err(format!("where {} is cannot be told", c.volume)));
        };
        let (script, env) = match c.engine {
            DbEngine::Postgres => {
                let Some(creds) = admins.postgres.and_then(hlb_backup::parse_pg_url) else {
                    return Ok(Err(format!(
                        "{} is copied by pg_basebackup, and no PostgreSQL administrator \
                         is known (--postgres-admin): it is not copied live instead",
                        c.volume
                    )));
                };
                // The server is the service owning the volume, on the overlay, at its
                // own port — never the admin URL's host, which may be a relay the CLI
                // reaches it through.
                (
                    pg_script(),
                    vec![
                        ("PGHOST".to_string(), app.to_string()),
                        ("PGPORT".to_string(), "5432".to_string()),
                        ("PGUSER".to_string(), creds.user),
                        ("PGPASSWORD".to_string(), creds.password),
                    ],
                )
            }
            DbEngine::Mariadb => {
                return Ok(Err(format!(
                    "{} is copied by mariadb-backup, which this pass cannot run yet",
                    c.volume
                )))
            }
        };
        let to = staging(&c.volume);
        if let Err(e) = run_at(orch, place, network, &image, &to, &script, &env).await {
            let _ = clear(orch, place, &image, &to).await;
            return Ok(Err(format!("{} not copied: {e}", c.volume)));
        }
        sources.insert(c.volume.clone(), to);
    }
    Ok(Ok(sources))
}

/// Empties every staging volume `sources` names: a copy of every database, left on
/// disk, would double what the machine holds for nothing.
pub(crate) async fn clear_all(
    state: &State,
    orch: Option<&dyn Orchestrator>,
    app: &str,
    sources: &BTreeMap<String, String>,
    places: &BTreeMap<Place, Vec<String>>,
) -> Result<(), String> {
    let image = state
        .app_manifest(app)
        .await
        .map_err(|e| e.to_string())?
        .spec
        .image
        .reference();
    let mut failed = Vec::new();
    for (volume, to) in sources {
        if let Some((place, _)) = places.iter().find(|(_, vs)| vs.contains(volume)) {
            if let Err(e) = clear(orch, place, &image, to).await {
                failed.push(format!("{to}: {e}"));
            }
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("staging not emptied — {}", failed.join("; ")))
    }
}

async fn clear(
    orch: Option<&dyn Orchestrator>,
    place: &Place,
    image: &str,
    to: &str,
) -> Result<(), String> {
    run_at(orch, place, "none", image, to, &clear_script(), &[]).await
}

fn clear_script() -> String {
    format!("find {STAGE} -mindepth 1 -delete")
}

/// Run as root in the SERVER's image — its `pg_basebackup` is the server's major, and
/// its `postgres` user the uid the restored files must belong to. The staging volume
/// emptied first: `pg_basebackup` refuses a populated directory, and a copy left by a
/// pass that died would otherwise stop every later one.
///
/// - `--wal-method=stream`: the WAL written DURING the copy, without which the
///   directory does not start.
/// - `--checkpoint=fast`: or the copy waits for the next checkpoint, minutes away.
/// - `--format=plain`: a data directory, read by restic as any volume.
/// - `--no-password`: never a prompt a container would wait on for ever.
fn pg_script() -> String {
    format!(
        "set -eu; find {STAGE} -mindepth 1 -delete; \
         pg_basebackup --pgdata={STAGE} --format=plain --wal-method=stream \
         --checkpoint=fast --no-password; \
         chown -R postgres:postgres {STAGE}; chmod 700 {STAGE}"
    )
}

/// `script` in `image` where `place` is, the volume `to` at [`STAGE`], `env` given
/// out of any command line.
async fn run_at(
    orch: Option<&dyn Orchestrator>,
    place: &Place,
    network: &str,
    image: &str,
    to: &str,
    script: &str,
    env: &[(String, String)],
) -> Result<(), String> {
    match place {
        Place::Here => {
            let mut cmd = tokio::process::Command::new("docker");
            cmd.args(["run", "--rm", "--network", network, "--entrypoint", "sh"]);
            hlb_backup::docker_env::pass_by_name(&mut cmd, env);
            cmd.arg("-v").arg(format!("{to}:{STAGE}"));
            cmd.args([image, "-c", script]);
            cmd.kill_on_drop(true);
            let out = tokio::time::timeout(std::time::Duration::from_secs(TIMEOUT_S), cmd.output())
                .await
                .map_err(|_| format!("still running after {TIMEOUT_S} s"))?
                .map_err(|e| format!("docker could not be run: {e}"))?;
            if out.status.success() {
                Ok(())
            } else {
                Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
            }
        }
        Place::Node { id, hostname } => {
            let Some(o) = orch else {
                return Err(format!("{to} is on {hostname}: no orchestrator"));
            };
            let out = o
                .run_job(&job(id, network, image, to, script, env), TIMEOUT_S)
                .await
                .map_err(|e| e.to_string())?;
            if out.succeeded {
                Ok(())
            } else {
                Err(out.output.join("\n"))
            }
        }
        Place::Unknown(why) => Err(why.clone()),
    }
}

/// The Swarm job copying on node `id`. No value of `env` is in its environment or
/// command: each is a file, read back into the shell's environment.
fn job(
    id: &str,
    network: &str,
    image: &str,
    to: &str,
    script: &str,
    env: &[(String, String)],
) -> ServiceSpec {
    let mut job = ServiceSpec::new(format!("hlb-copy-{to}"), image)
        .job()
        .constraint(format!("node.id=={id}"))
        .mount(to, STAGE);
    if network != "none" {
        job = job.network(network);
    }
    for (k, v) in env {
        job = job.file(format!("{ENV_DIR}/{k}"), v);
    }
    let read = if env.is_empty() {
        String::new()
    } else {
        format!("for f in {ENV_DIR}/*; do export \"${{f##*/}}=$(cat \"$f\")\"; done; ")
    };
    job = job.command([
        "sh".to_string(),
        "-c".to_string(),
        format!("{read}{script}"),
    ]);
    // Root through the server's 0700 directory, and the files given back to its user.
    job.hardening.cap_add = vec!["CHOWN".into(), "DAC_OVERRIDE".into(), "FOWNER".into()];
    job.hardening.read_only_rootfs = false;
    job
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_secret_is_in_a_copy_job_s_environment_or_command() {
        let env = [
            ("PGUSER".to_string(), "postgres".to_string()),
            ("PGPASSWORD".to_string(), "pg-secret-1".to_string()),
        ];
        let j = job(
            "n1",
            "hlb_platform",
            "pg:17",
            "hlb-copy-postgres-data",
            &pg_script(),
            &env,
        );
        let seen: Vec<&String> = j
            .env
            .iter()
            .flat_map(|(k, v)| [k, v])
            .chain(j.command.iter())
            .collect();
        assert!(!seen.iter().any(|s| s.contains("pg-secret-1")), "{seen:?}");
        assert!(
            j.files.iter().any(|(_, c)| c == "pg-secret-1"),
            "{:?}",
            j.files
        );
        assert!(
            j.constraints.contains(&"node.id==n1".to_string()),
            "{:?}",
            j.constraints
        );
    }

    #[test]
    fn the_copy_streams_its_wal_and_hands_the_files_to_the_server_s_user() {
        let s = pg_script();
        // Without the WAL written during the copy, the directory does not start.
        assert!(s.contains("--wal-method=stream"), "{s}");
        assert!(s.contains("chown -R postgres:postgres /stage"), "{s}");
        // Emptied first: a copy a dead pass left behind would refuse every later one.
        assert!(s.find("-delete") < s.find("pg_basebackup"), "{s}");
    }
}
