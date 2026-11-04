//! A database's dump put through a disposable server: what `hlb backup verify` does for
//! a volume, for what a volume's count cannot prove. A dump that restores on a server of
//! the same image is a database that comes back; a checksum of its bytes says neither.
//!
//! 🔴 The server has no network, and no app ever starts on it: a restored n8n would run
//! its workflows. It is removed with its data whatever happened: it holds a clear copy of
//! the database.

use std::time::{Duration, Instant};

use hlb_backup::mariadump::{check_database, check_full, MariaDumper, MariaTarget};
use hlb_backup::pgdump::{DumpRunner, RawOutput};
use hlb_backup::{PgDumper, PgTarget};
use hlb_types::DbEngine;
use tokio::io::AsyncWriteExt;

/// A server this long in starting is not starting: its image's first run takes seconds.
const READY_WITHIN: Duration = Duration::from_secs(120);
const SCRATCH_HOST: &str = "127.0.0.1";

/// What was asked of one database.
pub struct Reading<'a> {
    pub engine: DbEngine,
    /// The installed server's image: a dump is read as the server that would take it.
    pub image: &'a str,
    pub name: &'a str,
    pub role: &'a str,
    pub extensions: &'a [String],
}

/// The tables the dump names, and the tables the restored database holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tables {
    pub listed: u64,
    pub restored: u64,
}

impl Tables {
    /// An extension may add tables of its own, so more is fine. Fewer is a table lost.
    pub fn matches(self) -> bool {
        self.restored >= self.listed
    }
}

/// Restores `dump` into a disposable server and counts what came back.
pub async fn read(reading: &Reading<'_>, dump: &[u8]) -> Result<Tables, String> {
    let name = format!("hlb-verif-db-{}", hlb_backup::verify::token());
    let started = start(&name, reading).await;
    let result = match started {
        Ok(()) => restore_and_count(&name, reading, dump).await,
        Err(e) => Err(e),
    };
    // `-v`: the image's data directory is an anonymous volume, holding the clear copy.
    if let Err(e) = docker(&["rm", "-fv", &name]).await {
        tracing::warn!(server = name, "disposable server not removed: {e}");
    }
    result
}

async fn start(name: &str, r: &Reading<'_>) -> Result<(), String> {
    // Nothing here is a secret, and it goes by name all the same: `ps` shows no value of a
    // docker command, so nobody has to read this one to know.
    let settings = match r.engine {
        DbEngine::Postgres => vec![
            ("POSTGRES_PASSWORD".to_string(), "disposable".to_string()),
            ("POSTGRES_HOST_AUTH_METHOD".to_string(), "trust".to_string()),
        ],
        DbEngine::Mariadb => vec![(
            "MARIADB_ALLOW_EMPTY_ROOT_PASSWORD".to_string(),
            "1".to_string(),
        )],
    };
    let mut run = tokio::process::Command::new("docker");
    run.args(["run", "-d", "--name", name, "--network", "none"]);
    // Past this it dies, and the apps' server on the same machine does not.
    run.args(["--memory", "1g"]);
    hlb_backup::docker_env::pass_by_name(&mut run, settings.iter());
    run.arg(r.image);
    let out = run
        .output()
        .await
        .map_err(|e| format!("the disposable server did not start: docker: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "the disposable server did not start: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    // Over TCP: both images' first start runs a temporary server on its socket alone,
    // and stops it. Asked on the socket, the first answer comes from that one.
    let probe: &[&str] = match r.engine {
        DbEngine::Postgres => &["pg_isready", "-h", SCRATCH_HOST, "-U", "postgres"],
        DbEngine::Mariadb => &[
            "mariadb",
            "-uroot",
            "-h",
            SCRATCH_HOST,
            "--execute=SELECT 1",
        ],
    };
    let mut exec = vec!["exec", name];
    exec.extend_from_slice(probe);
    let since = Instant::now();
    while since.elapsed() < READY_WITHIN {
        if docker(&exec).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let logs = docker(&["logs", "--tail", "5", name])
        .await
        .unwrap_or_default();
    Err(format!(
        "the disposable server never answered: {}",
        logs.trim()
    ))
}

async fn restore_and_count(name: &str, r: &Reading<'_>, dump: &[u8]) -> Result<Tables, String> {
    match r.engine {
        DbEngine::Postgres => postgres(name, r, dump).await,
        DbEngine::Mariadb => mariadb(name, r, dump).await,
    }
}

async fn postgres(server: &str, r: &Reading<'_>, dump: &[u8]) -> Result<Tables, String> {
    if !dump.starts_with(b"PGDMP") {
        return Err("not a PostgreSQL dump".into());
    }
    let e = |e: hlb_platform::Error| e.to_string();
    // Validates both names: the role's statement below is built from one.
    let database = hlb_platform::database_statements(r.name, r.role).map_err(e)?;
    let role = format!(r#"CREATE ROLE "{}" LOGIN"#, r.role);
    let extensions = r
        .extensions
        .iter()
        .map(|x| hlb_platform::extension_statement(x))
        .collect::<Result<Vec<_>, _>>()
        .map_err(e)?;
    let at = |database: &str| PgTarget {
        host: SCRATCH_HOST.into(),
        port: 5432,
        database: database.to_string(),
        user: "postgres".into(),
        password: "disposable".into(),
    };
    let dumper = PgDumper::new(Exec(server.to_string()));
    let failed = |e: hlb_backup::Error| e.to_string();
    let mut admin = vec![role];
    admin.extend(database);
    dumper.psql(&at("postgres"), &admin).await.map_err(failed)?;
    if !extensions.is_empty() {
        dumper
            .psql(&at(r.name), &extensions)
            .await
            .map_err(failed)?;
    }
    dumper
        .restore_as(&at(r.name), dump, r.role, r.extensions)
        .await
        .map_err(failed)?;

    // `restore_as` left the dump in the server's /tmp.
    let list = docker(&["exec", server, "pg_restore", "--list", "/tmp/hlb.dump"]).await?;
    let restored = docker(&[
        "exec",
        server,
        "psql",
        "-h",
        SCRATCH_HOST,
        "-U",
        "postgres",
        "-d",
        r.name,
        "-tAc",
        "SELECT count(*) FROM information_schema.tables \
         WHERE table_schema NOT IN ('pg_catalog','information_schema') \
         AND table_type = 'BASE TABLE'",
    ])
    .await?;
    Ok(Tables {
        listed: tables_in_list(&list),
        restored: count(&restored)?,
    })
}

async fn mariadb(server: &str, r: &Reading<'_>, dump: &[u8]) -> Result<Tables, String> {
    // Refused before the server is written to: a truncated dump restores without an error.
    let refused = |e: hlb_backup::Error| e.to_string();
    check_full(r.name, dump).map_err(refused)?;
    check_database(r.name, dump).map_err(refused)?;
    let e = |e: hlb_platform::Error| e.to_string();
    let database = hlb_platform::mariadb::database_statements(r.name, r.role).map_err(e)?;
    let user = format!("CREATE USER '{}'@'%'", r.role);
    let target = MariaTarget {
        host: SCRATCH_HOST.into(),
        port: 3306,
        database: r.name.to_string(),
        user: "root".into(),
        password: String::new(),
    };
    let dumper = MariaDumper::new(Exec(server.to_string()));
    let mut admin = vec![user];
    admin.extend(database);
    dumper.sql(&target, &admin).await.map_err(refused)?;
    dumper.restore(&target, dump).await.map_err(refused)?;

    let query = format!(
        "SELECT count(*) FROM information_schema.tables \
         WHERE table_schema = '{}' AND table_type = 'BASE TABLE'",
        r.name
    );
    let restored = docker(&[
        "exec",
        server,
        "mariadb",
        "-uroot",
        "-h",
        SCRATCH_HOST,
        "-NBe",
        &query,
    ])
    .await?;
    Ok(Tables {
        listed: tables_in_mariadb_dump(dump),
        restored: count(&restored)?,
    })
}

/// The tables `pg_restore --list` names. Its lines: `215; 1259 16390 TABLE public notes
/// owner`, and `3350; 0 16390 TABLE DATA public notes owner` for the same table's rows.
fn tables_in_list(list: &str) -> u64 {
    list.lines()
        .filter(|l| !l.starts_with(';'))
        .filter_map(|l| l.split_once(';').map(|(_, rest)| rest.trim_start()))
        .filter(|rest| {
            let mut words = rest.split_whitespace().skip(2);
            words.next() == Some("TABLE") && words.next() != Some("DATA")
        })
        .count() as u64
}

/// The tables a MariaDB dump creates. At the start of a line only: a view's stand-in is
/// written `/*!50001 CREATE TABLE`, and a table's rows may hold the words.
fn tables_in_mariadb_dump(dump: &[u8]) -> u64 {
    dump.split(|b| *b == b'\n')
        .filter(|l| l.starts_with(b"CREATE TABLE "))
        .count() as u64
}

/// 🔴 Never zero by default: an unreadable answer is not an empty database, and zero
/// listed against zero read would pass.
fn count(output: &str) -> Result<u64, String> {
    output
        .trim()
        .parse()
        .map_err(|_| format!("unreadable count: \"{}\"", output.trim()))
}

async fn docker(args: &[&str]) -> Result<String, String> {
    let out = tokio::process::Command::new("docker")
        .args(args)
        .output()
        .await
        .map_err(|e| format!("docker: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// The dump tools, run inside the disposable server: it has no network to reach them by.
struct Exec(String);

#[async_trait::async_trait]
impl DumpRunner for Exec {
    async fn run(
        &self,
        args: &[String],
        env: &[(String, String)],
    ) -> hlb_backup::Result<RawOutput> {
        let quote = |a: &String| format!("'{}'", a.replace('\'', r"'\''"));
        let inner = args.iter().map(quote).collect::<Vec<_>>().join(" ");
        let payload = env
            .iter()
            .find(|(k, _)| k == "HLB_STDIN_B64")
            .map(|(_, v)| v);
        let script = match payload {
            // `base64 -d` rebuilds the binary dump, as the client's container does.
            Some(_) => format!("base64 -d | {inner}"),
            None => inner,
        };
        let mut cmd = tokio::process::Command::new("docker");
        cmd.args(["exec", "-i"]);
        hlb_backup::docker_env::pass_by_name(
            &mut cmd,
            env.iter().filter(|(k, _)| k != "HLB_STDIN_B64"),
        );
        cmd.arg(&self.0).args(["sh", "-c", &script]);
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let unexpected =
            |what: &str, e: std::io::Error| hlb_backup::Error::Unexpected(format!("{what}: {e}"));
        let mut child = cmd.spawn().map_err(|e| unexpected("docker", e))?;
        if let Some(mut stdin) = child.stdin.take() {
            if let Some(b64) = payload {
                stdin
                    .write_all(b64.as_bytes())
                    .await
                    .map_err(|e| unexpected("writing stdin", e))?;
            }
            stdin
                .shutdown()
                .await
                .map_err(|e| unexpected("closing stdin", e))?;
        }
        let out = child
            .wait_with_output()
            .await
            .map_err(|e| unexpected("waiting for the server", e))?;
        Ok(RawOutput {
            status: out.status.code().unwrap_or(-1),
            stdout: out.stdout,
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_counts_tables_and_not_their_rows_or_indexes() {
        let list = "\
;\n; Archive created at 2026-11-04\n;\n\
215; 1259 16390 TABLE public notes vikunja\n\
216; 1259 16391 TABLE public DATA vikunja\n\
217; 1259 16392 SEQUENCE public notes_id_seq vikunja\n\
3350; 0 16390 TABLE DATA public notes vikunja\n\
3351; 2606 16393 CONSTRAINT public notes notes_pkey vikunja\n\
3352; 1259 16394 INDEX public notes_idx vikunja\n";
        assert_eq!(tables_in_list(list), 2);
    }

    #[test]
    fn a_mariadb_dump_counts_tables_and_not_a_view_s_stand_in_or_a_row() {
        let dump = b"CREATE TABLE `notes` (\n`id` int\n);\n\
/*!50001 CREATE TABLE `a_view` (\n`id` int\n) */;\n\
INSERT INTO `notes` VALUES ('CREATE TABLE x');\n\
CREATE TABLE `tags` (\n`id` int\n);\n";
        assert_eq!(tables_in_mariadb_dump(dump), 2);
    }

    #[test]
    fn a_table_lost_fails_and_an_extension_s_own_table_does_not() {
        assert!(Tables {
            listed: 3,
            restored: 3
        }
        .matches());
        assert!(Tables {
            listed: 3,
            restored: 4
        }
        .matches());
        assert!(!Tables {
            listed: 3,
            restored: 2
        }
        .matches());
    }

    #[test]
    fn an_unreadable_count_is_an_error_and_never_zero() {
        assert_eq!(count(" 42\n"), Ok(42));
        assert!(count("").is_err());
        assert!(count("ERROR: no").is_err());
    }
}
