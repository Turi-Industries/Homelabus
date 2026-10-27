//! Logical PostgreSQL backup (layer L1).
//!
//! 🔴 **Why this is indispensable, and not redundant with restic.**
//!
//! Backing up the *files* of a PostgreSQL that is being written to produces a backup you
//! believe is good and that does not restore: the data pages, the WAL and the control
//! files are copied at different instants, so they are inconsistent with each other. The
//! file exists, restic returns it faithfully, and PostgreSQL refuses to start on it.
//!
//! `pg_dump`, by contrast, takes a **transactionally consistent** snapshot: it opens a
//! transaction in `REPEATABLE READ` isolation and exports the content as it stood at
//! that precise instant, whatever the concurrent writes.
//!
//! As for restic, `pg_dump` is not guaranteed present on the host: we go through the
//! same execution abstraction.

use crate::{Error, Result};

/// The tag every archived dump carries — PostgreSQL's, MariaDB's and Homelabus's own
/// state. ⚠️ A stored value: retention forgets dumps by it.
pub const DUMP_KIND: &str = "kind:sql-dump";

/// Runs `pg_dump` / `pg_restore`, wherever they live.
#[async_trait::async_trait]
pub trait DumpRunner: Send + Sync {
    /// Launches a PostgreSQL client tool and returns its **raw** standard output.
    ///
    /// The dump is binary (`custom` format): treating it as text would corrupt it.
    async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<RawOutput>;
}

pub struct RawOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

/// Where to connect, and with what.
#[derive(Debug, Clone)]
pub struct PgTarget {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: String,
}

impl PgTarget {
    fn env(&self) -> Vec<(String, String)> {
        // As for restic: the password travels through the environment, never through
        // the command line, which every user of the machine can read.
        vec![
            ("PGPASSWORD".into(), self.password.clone()),
            ("PGHOST".into(), self.host.clone()),
            ("PGPORT".into(), self.port.to_string()),
            ("PGUSER".into(), self.user.clone()),
            ("PGDATABASE".into(), self.database.clone()),
        ]
    }
}

pub struct PgDumper<R: DumpRunner> {
    runner: R,
}

impl<R: DumpRunner> PgDumper<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    /// Produces a consistent dump, in PostgreSQL's `custom` format.
    ///
    /// The `custom` format (`-Fc`) is compressed, and above all **selectively
    /// restorable**: you can pull out a single table on the day a single table is what
    /// you lost.
    pub async fn dump(&self, target: &PgTarget) -> Result<Vec<u8>> {
        let args: Vec<String> = [
            "pg_dump",
            "--format=custom",
            // Without this option, a dump restored into a fresh database fails on the
            // missing owners.
            "--no-owner",
            "--no-privileges",
            // Explicit transactional consistency.
            "--serializable-deferrable",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let out = self.runner.run(&args, &target.env()).await?;
        if out.status != 0 {
            return Err(Error::Dump {
                database: target.database.clone(),
                stderr: out.stderr.trim().to_string(),
            });
        }

        if out.stdout.is_empty() {
            // An empty dump is never normal, even for a database with no table: the
            // custom format's header alone is several bytes.
            return Err(Error::Dump {
                database: target.database.clone(),
                stderr: "empty dump".into(),
            });
        }

        tracing::info!(
            database = %target.database,
            bytes = out.stdout.len(),
            "logical dump produced"
        );
        Ok(out.stdout)
    }

    /// Restores a dump into an existing database.
    ///
    /// `clean` drops the objects before recreating them — needed to restore over an
    /// already populated database.
    pub async fn restore(&self, target: &PgTarget, dump: &[u8], clean: bool) -> Result<()> {
        let mut args = vec!["pg_restore".to_string(), "--no-owner".to_string()];
        if clean {
            args.push("--clean".into());
            args.push("--if-exists".into());
        }
        args.push("--dbname".into());
        args.push(target.database.clone());

        let mut env = target.env();
        // The content to restore travels through the runner's execution environment,
        // which knows how to route it (temporary file, stdin…).
        env.push(("HLB_STDIN_B64".into(), base64_encode(dump)));

        let out = self.runner.run(&args, &env).await?;
        if out.status != 0 {
            return Err(Error::Dump {
                database: target.database.clone(),
                stderr: out.stderr.trim().to_string(),
            });
        }
        tracing::info!(database = %target.database, "dump restored");
        Ok(())
    }

    /// Restores a dump into an EMPTY database, every object it creates owned by `role`
    /// — the app's: restored by the administrator under `--no-owner`, they were the
    /// administrator's, and the app could no longer read its own tables.
    ///
    /// `enabled` are the extensions the administrator already enabled in it, left out
    /// of the dump's list: the role may neither create them nor comment on them
    /// (`must be owner of extension`). One the app made itself is restored with it.
    ///
    /// One transaction, stopped at the first error: a dump half restored opens as a
    /// database that is neither copy, and the app would start on it.
    pub async fn restore_as(
        &self,
        target: &PgTarget,
        dump: &[u8],
        role: &str,
        enabled: &[String],
    ) -> Result<()> {
        let restore = [
            "pg_restore",
            "--no-owner",
            "--no-privileges",
            "--role",
            role,
            "--single-transaction",
            "--exit-on-error",
            "--dbname",
            &target.database,
        ]
        .map(String::from);
        let restore = restore
            .iter()
            .map(|a| crate::pgrunner::shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        // The list's lines: `2; 3079 16384 EXTENSION - citext` and `3587; 0 0 COMMENT
        // - EXTENSION citext`. A name goes into a pattern: an identifier, or refused.
        if let Some(bad) = enabled.iter().find(|e| {
            e.is_empty()
                || !e
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        }) {
            return Err(Error::Dump {
                database: target.database.clone(),
                stderr: format!("\"{bad}\" is not an extension's name"),
            });
        }
        let script = if enabled.is_empty() {
            format!("{restore} /tmp/hlb.dump")
        } else {
            format!(
                "pg_restore --list /tmp/hlb.dump | grep -Ev {} > /tmp/hlb.list && \
                 {restore} --use-list /tmp/hlb.list /tmp/hlb.dump",
                crate::pgrunner::shell_quote(&format!(
                    "^[0-9]+; [0-9]+ [0-9]+ (EXTENSION - |COMMENT - EXTENSION )({}) *$",
                    enabled.join("|")
                ))
            )
        };
        let args = [
            "sh".to_string(),
            "-c".to_string(),
            format!("set -e; cat > /tmp/hlb.dump; {script}"),
        ];
        let mut env = target.env();
        env.push(("HLB_STDIN_B64".into(), base64_encode(dump)));
        let out = self.runner.run(&args, &env).await?;
        if out.status != 0 {
            return Err(Error::Dump {
                database: target.database.clone(),
                stderr: out.stderr.trim().to_string(),
            });
        }
        tracing::info!(database = %target.database, role, "dump restored");
        Ok(())
    }

    /// Runs `statements` with `psql` in `target`'s database, each on its own — `CREATE
    /// DATABASE` refuses a transaction —, stopping at the first that fails.
    pub async fn psql(&self, target: &PgTarget, statements: &[String]) -> Result<()> {
        let mut args = vec![
            "psql".to_string(),
            "--no-psqlrc".into(),
            "--quiet".into(),
            "--set".into(),
            "ON_ERROR_STOP=1".into(),
        ];
        for s in statements {
            args.push("--command".into());
            args.push(s.clone());
        }
        let out = self.runner.run(&args, &target.env()).await?;
        if out.status != 0 {
            return Err(Error::Dump {
                database: target.database.clone(),
                stderr: out.stderr.trim().to_string(),
            });
        }
        Ok(())
    }
}

/// Minimal base64 encoding, to carry a binary through the environment.
///
/// Avoids one more dependency for a handful of lines.
pub(crate) fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);

        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Logical backup of a database, pushed into the restic repository (layer L1).
///
/// 🔴 **This is what was missing most.** Without this layer, a PostgreSQL is only backed
/// up at the file level — and a database file copied during a write does not restore:
/// pages, WAL and control files are captured at different instants. The file exists,
/// restic returns it faithfully, and PostgreSQL refuses to start on it.
pub mod scheduled {
    use super::*;

    /// A dump ready to be archived.
    pub struct Dump {
        pub app: String,
        pub database: String,
        /// Filename in the format `<app>-<database>-<timestamp>.dump`.
        pub filename: String,
        pub bytes: Vec<u8>,
    }

    impl Dump {
        /// A dump's filename.
        ///
        /// Timestamped and lexicographically sortable, like the base backups: that is
        /// what lets you find the most recent one without reading the metadata.
        pub fn name_for(app: &str, database: &str, at: i64) -> String {
            let (y, m, d, hh, mm, ss) = crate::pitr::civil_public(at);
            format!("{app}-{database}-{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z.dump")
        }
    }

    /// Produces a database's dump.
    pub async fn produce<R: DumpRunner>(
        dumper: &PgDumper<R>,
        app: &str,
        target: &PgTarget,
        at: i64,
    ) -> Result<Dump> {
        let bytes = dumper.dump(target).await?;
        Ok(Dump {
            app: app.to_string(),
            database: target.database.clone(),
            filename: Dump::name_for(app, &target.database, at),
            bytes,
        })
    }

    /// Archives a dump into the restic repository.
    ///
    /// ## 🔴 Why a Docker volume and not a temporary file
    ///
    /// Same reason as for verification: on macOS the host's temp directory **is
    /// not shared with the Docker VM**. A dump written there and mounted into the restic
    /// container does not appear in it, and restic answers "does not exist, skipping" —
    /// then exits with an error. The dump really was produced, it is simply never
    /// archived.
    ///
    /// So the file travels through a disposable volume, on the same side of the boundary
    /// as restic.
    ///
    /// ⚠️ The dump holds the data in the clear: the volume is destroyed in every case,
    /// success as well as failure.
    pub async fn archive(repo_location: &str, password: &str, dump: &Dump) -> Result<String> {
        let dest = crate::destination::Destination {
            name: "default".into(),
            location: repo_location.to_string(),
            classes: vec![crate::destination::Class::Critical],
            credentials_secret: None,
        };
        archive_to(&dest, None, None, password, dump).await
    }

    /// Archives a dump to a DESTINATION, local or S3.
    ///
    /// 🔴 An S3 repository is not mounted: `Destination::runner` decides, and confusing
    /// the two would produce a "repository does not exist" naming a local path unrelated
    /// to the real destination.
    /// `credentials` is the VALUE of the S3 secret (`key:secret`), already taken out of
    /// the vault by the caller.
    ///
    /// ⚠️ Above all not `dest.credentials_secret`, which is only the NAME of the secret:
    /// passing it through would send "backup-dest-offsite" as the access key, and S3
    /// would answer "invalid signature" — an error that points nowhere.
    pub async fn archive_to(
        dest: &crate::destination::Destination,
        credentials: Option<&str>,
        network: Option<&str>,
        password: &str,
        dump: &Dump,
    ) -> Result<String> {
        archive_as(dest, credentials, network, password, dump, super::DUMP_KIND).await
    }

    /// [`archive_to`], tagged `kind` — a restore's copy of what it replaces is not one
    /// of the schedule's dumps, which retention forgets by their kind.
    pub async fn archive_as(
        dest: &crate::destination::Destination,
        credentials: Option<&str>,
        network: Option<&str>,
        password: &str,
        dump: &Dump,
        kind: &str,
    ) -> Result<String> {
        let volume = format!("hlb-dump-{}", crate::verify::public_token());
        docker(&["volume", "create", &volume]).await?;

        let r =
            archive_to_destination(&volume, dest, credentials, network, password, dump, kind).await;

        if let Err(e) = docker(&["volume", "rm", "-f", &volume]).await {
            tracing::warn!(volume, "transit volume not removed: {e}");
        }
        r
    }

    async fn archive_to_destination(
        volume: &str,
        dest: &crate::destination::Destination,
        credentials: Option<&str>,
        network: Option<&str>,
        password: &str,
        dump: &Dump,
        kind: &str,
    ) -> Result<String> {
        use tokio::io::AsyncWriteExt;

        // 🔴 The credentials are already RESOLVED by the caller: this module never
        // touches the vault, and therefore never sees a secret's name where a value is
        // expected.
        let env = dest.env(credentials)?;

        // The dump enters the volume through a container's standard input: that is the
        // only path that crosses the host/VM boundary reliably.
        let mut child = tokio::process::Command::new("docker")
            .args([
                "run",
                "--rm",
                "-i",
                "--entrypoint",
                "sh",
                "-v",
                &format!("{volume}:/staging"),
                crate::images::RESTIC,
                "-c",
                &format!("cat > /staging/{}", dump.filename),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Unexpected(format!("docker not found: {e}")))?;

        if let Some(mut si) = child.stdin.take() {
            si.write_all(&dump.bytes)
                .await
                .map_err(|e| Error::Unexpected(format!("sending the dump: {e}")))?;
            si.shutdown()
                .await
                .map_err(|e| Error::Unexpected(format!("closing the stream: {e}")))?;
        }

        let out = child
            .wait_with_output()
            .await
            .map_err(|e| Error::Unexpected(format!("transferring the dump: {e}")))?;

        if !out.status.success() {
            return Err(Error::Unexpected(format!(
                "dump not transferred: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }

        let (runner, path) = dest.runner(network);
        let runner = runner.mount(volume, "/staging");
        let repo = crate::restic::Repository::new(runner, path, password.to_string())
            .extra_env(env.clone());

        repo.init().await?;
        repo.backup(
            &format!("/staging/{}", dump.filename),
            &[
                &format!("app:{}", dump.app),
                &format!("db:{}", dump.database),
                kind,
            ],
        )
        .await
    }

    async fn docker(args: &[&str]) -> Result<String> {
        let out = tokio::process::Command::new("docker")
            .args(args)
            .output()
            .await
            .map_err(|e| Error::Unexpected(format!("docker not found: {e}")))?;

        if !out.status.success() {
            return Err(Error::Unexpected(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }
}

#[cfg(test)]
mod tests_scheduled {
    use super::scheduled::Dump;

    const J0: i64 = 1_786_881_600;

    #[test]
    fn dump_names_sort_chronologically() {
        // Finding the most recent dump must be a plain sort on names.
        let a = Dump::name_for("gitea", "gitea", J0);
        let b = Dump::name_for("gitea", "gitea", J0 + 3600);
        assert_eq!(a, "gitea-gitea-20260816T120000Z.dump");
        assert!(a < b, "{a} < {b}");
    }

    #[test]
    fn the_name_carries_both_app_and_database() {
        // An app can have a database whose name differs from its own: both must be
        // readable without decoding restic's tags.
        let n = Dump::name_for("vikunja", "tasks", J0);
        assert!(n.starts_with("vikunja-tasks-"), "{n}");
        assert!(n.ends_with(".dump"), "{n}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fake {
        out: Mutex<RawOutput>,
        calls: Mutex<Vec<Vec<String>>>,
        envs: Mutex<Vec<Vec<(String, String)>>>,
    }

    impl Fake {
        fn new(status: i32, stdout: Vec<u8>, stderr: &str) -> Self {
            Self {
                out: Mutex::new(RawOutput {
                    status,
                    stdout,
                    stderr: stderr.into(),
                }),
                calls: Mutex::new(Vec::new()),
                envs: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl DumpRunner for Fake {
        async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<RawOutput> {
            self.calls.lock().expect("mutex").push(args.to_vec());
            self.envs.lock().expect("mutex").push(env.to_vec());
            let o = self.out.lock().expect("mutex");
            Ok(RawOutput {
                status: o.status,
                stdout: o.stdout.clone(),
                stderr: o.stderr.clone(),
            })
        }
    }

    fn target() -> PgTarget {
        PgTarget {
            host: "postgres".into(),
            port: 5432,
            database: "gitea".into(),
            user: "gitea".into(),
            password: "secret".into(),
        }
    }

    #[tokio::test]
    async fn the_password_never_reaches_the_command_line() {
        let d = PgDumper::new(Fake::new(0, b"PGDMP-fake".to_vec(), ""));
        d.dump(&target()).await.expect("dump");

        let calls = d.runner.calls.lock().expect("mutex");
        assert!(
            !calls[0].iter().any(|a| a.contains("secret")),
            "password in the arguments: {:?}",
            calls[0]
        );
        let envs = d.runner.envs.lock().expect("mutex");
        assert!(envs[0]
            .iter()
            .any(|(k, v)| k == "PGPASSWORD" && v == "secret"));
    }

    #[tokio::test]
    async fn the_dump_is_transactionally_consistent() {
        // 🔴 Without this, a dump taken during writes is inconsistent.
        let d = PgDumper::new(Fake::new(0, b"PGDMP".to_vec(), ""));
        d.dump(&target()).await.expect("dump");

        let calls = d.runner.calls.lock().expect("mutex");
        let joined = calls[0].join(" ");
        assert!(joined.contains("--serializable-deferrable"), "{joined}");
        assert!(joined.contains("--format=custom"), "{joined}");
    }

    #[tokio::test]
    async fn an_empty_dump_is_an_error() {
        // An empty dump would be silently accepted then archived as valid.
        let d = PgDumper::new(Fake::new(0, Vec::new(), ""));
        let err = d.dump(&target()).await.unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
    }

    #[tokio::test]
    async fn a_failing_dump_surfaces_the_message() {
        let d = PgDumper::new(Fake::new(1, Vec::new(), "FATAL: role does not exist"));
        let err = d.dump(&target()).await.unwrap_err();
        assert!(err.to_string().contains("role does not exist"), "{err}");
    }

    #[tokio::test]
    async fn restore_can_clean_first() {
        let d = PgDumper::new(Fake::new(0, Vec::new(), ""));
        d.restore(&target(), b"data", true).await.expect("restore");

        let calls = d.runner.calls.lock().expect("mutex");
        let joined = calls[0].join(" ");
        assert!(joined.contains("--clean"));
        assert!(
            joined.contains("--if-exists"),
            "or a missing object makes it fail"
        );
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_handles_binary() {
        // The custom format is binary: null and high bytes must survive.
        assert_eq!(base64_encode(&[0x00, 0xff, 0x80]), "AP+A");
    }
}
