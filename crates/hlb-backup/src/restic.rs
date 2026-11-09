//! Driving restic.
//!
//! restic is not a library: we invoke the binary. But **where**? Neither restic nor
//! `pg_dump` is guaranteed present on the host, and the controller can run on a
//! distribution that does not package them.
//!
//! Hence the [`Runner`] trait: the agent will use the local binary (direct access to the
//! volumes, no overhead), while development and tests go through a container. The same
//! business code on both sides.

use serde::Deserialize;

use crate::retention::RetentionPolicy;
use crate::{Error, Result};

/// How to run a restic command.
#[async_trait::async_trait]
pub trait Runner: Send + Sync {
    /// Runs `restic <args>` with the given environment variables.
    async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<Output>;

    /// The same, `input` its standard input until it ends — a bucket's archive, which no
    /// disk holds. A runner that cannot stream says so rather than reading nothing.
    async fn run_from(
        &self,
        args: &[String],
        env: &[(String, String)],
        input: &mut (dyn tokio::io::AsyncRead + Send + Unpin),
    ) -> Result<Output> {
        let _ = (args, env, input);
        Err(Error::Unexpected(
            "this runner cannot hand restic a stream".into(),
        ))
    }

    /// The same, its standard output copied into `out` as it comes rather than kept.
    async fn run_into(
        &self,
        args: &[String],
        env: &[(String, String)],
        out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    ) -> Result<Output> {
        let _ = (args, env, out);
        Err(Error::Unexpected(
            "this runner cannot stream restic's output".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == 0
    }
}

/// The snapshot id in `backup --json`'s output: one line per event, the summary last.
fn summary_id(stdout: &str) -> Result<String> {
    stdout
        .lines()
        .rev()
        .find_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).ok()?;
            if v.get("message_type")?.as_str()? == "summary" {
                Some(v.get("snapshot_id")?.as_str()?.to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| Error::Unexpected("restic returned no snapshot id".into()))
}

/// A snapshot, as restic describes it in JSON.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    pub id: String,
    pub time: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub hostname: String,
}

impl Snapshot {
    /// Short id, the one restic displays and a human copies.
    pub fn short_id(&self) -> &str {
        &self.id[..self.id.len().min(8)]
    }

    /// When restic says it was taken, in seconds since the epoch — what whoever wrote
    /// it says, so evidence of nothing but a date in the future.
    ///
    /// restic writes the taking machine's local time with its offset
    /// (`2026-10-19T14:02:03.123456789+02:00`): read without it, a snapshot from
    /// UTC+14 would look fourteen hours ahead.
    pub fn epoch(&self) -> Option<i64> {
        rfc3339_epoch(&self.time)
    }
}

/// A time as restic writes it, with its offset, in seconds since the epoch.
fn rfc3339_epoch(t: &str) -> Option<i64> {
    let t = t.trim();
    let (_, clock) = t.split_once('T')?;
    let (local, offset) = match clock.strip_suffix('Z') {
        Some(_) => (&t[..t.len() - 1], 0),
        None => {
            let at = clock.rfind(['+', '-'])?;
            let sign = if clock[at..].starts_with('-') { -1 } else { 1 };
            let (h, m) = clock[at + 1..].split_once(':')?;
            let offset = sign * (h.parse::<i64>().ok()? * 3600 + m.parse::<i64>().ok()? * 60);
            (&t[..t.len() - (clock.len() - at)], offset)
        }
    };
    let whole = local.split('.').next()?;
    Some(crate::pitr::parse_utc(whole)? - offset)
}

/// One entry of a snapshot, as `restic ls --json` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub path: String,
    /// `dir`, `file`, `symlink`…
    pub kind: String,
    pub uid: u32,
    pub gid: u32,
    /// The permission bits, setuid, setgid and sticky among them, as `chmod` reads them.
    pub mode: u32,
    pub mtime: i64,
    pub size: u64,
}

impl Node {
    /// One line of `restic ls --json`; `None` for its snapshot's line, or a line unread.
    ///
    /// ⚠️ `mode` is Go's `FileMode`: the permission bits are its low nine, and setuid,
    /// setgid and sticky sit at bits 23, 22 and 20 — not where `chmod` puts them.
    fn parse(line: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        if v.get("struct_type").and_then(|t| t.as_str()) != Some("node") {
            return None;
        }
        let num = |k: &str| v.get(k).and_then(serde_json::Value::as_u64);
        let go = num("mode")?;
        let mut mode = (go & 0o777) as u32;
        for (bit, unix) in [(1u64 << 23, 0o4000), (1 << 22, 0o2000), (1 << 20, 0o1000)] {
            if go & bit != 0 {
                mode |= unix;
            }
        }
        Some(Self {
            path: v.get("path")?.as_str()?.to_string(),
            kind: v.get("type")?.as_str()?.to_string(),
            uid: u32::try_from(num("uid")?).ok()?,
            gid: u32::try_from(num("gid")?).ok()?,
            mode,
            mtime: rfc3339_epoch(v.get("mtime")?.as_str()?)?,
            size: num("size").unwrap_or(0),
        })
    }
}

/// Default identity of the snapshots. Stable by construction.
pub const DEFAULT_HOST: &str = "homelabus";

/// How long a command waits for another's lock on the repository before failing. The
/// daemon's loops share destinations: a backup starting during the upkeep's prune
/// failed at once without it. Not for ever: a read-only mount retries its lock
/// endlessly, and a wait with no end is a pass that never reports.
pub const LOCK_WAIT: &str = "10m";

/// The NFSv4 client shows this attribute on every file of a share whose filesystem has ACLs
/// (ext4, XFS), and refuses to remove it. A restore removes each attribute the snapshot does
/// not hold, so it failed once per file, the app left stopped (0.19.1, measured on a house
/// restored over NFS). It is the server's, no file's data.
const NFS4_ACL: &str = "system.nfs4_acl";

/// `args` waiting [`LOCK_WAIT`] for a lock held by another command.
fn waiting(mut args: Vec<String>) -> Vec<String> {
    args.extend(["--retry-lock".to_string(), LOCK_WAIT.to_string()]);
    args
}

/// A restic repository, with its location and its password.
pub struct Repository<R: Runner> {
    runner: R,
    location: String,
    /// Comes from the `age` vault. Never written to disk in the clear, never logged.
    password: String,
    /// 🔴 Stable identity of the snapshots — see [`Repository::host`].
    host: String,
    /// Extra variables: S3 credentials, notably.
    ///
    /// 🔴 Through the environment, never through the command line nor the repository
    /// URL. An `s3:https://key:secret@host/bucket` URL would work — and would publish
    /// the key in `ps`, in restic's logs and in every display of the repository.
    extra_env: Vec<(String, String)>,
}

impl<R: Runner> Repository<R> {
    pub fn new(runner: R, location: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            runner,
            location: location.into(),
            password: password.into(),
            host: DEFAULT_HOST.to_string(),
            extra_env: Vec::new(),
        }
    }

    /// Adds environment variables — typically `AWS_ACCESS_KEY_ID` and
    /// `AWS_SECRET_ACCESS_KEY` for an S3 repository.
    pub fn extra_env(mut self, vars: Vec<(String, String)>) -> Self {
        self.extra_env = vars;
        self
    }

    /// Sets the identity the snapshots carry.
    ///
    /// 🔴 **Indispensable, and restic's nastiest trap.** `forget` groups snapshots by
    /// `host,paths`: each group applies the retention policy *separately*. If the host
    /// varies from one backup to the next — which happens as soon as restic runs in a
    /// container, each with a random hostname, or as soon as the agent moves node — every
    /// backup forms its own group, and **nothing is ever deleted again**.
    ///
    /// The symptom is silent: retention is configured, `forget` runs without error, and
    /// the disk fills up anyway.
    ///
    /// The host must therefore identify **the cluster**, not the machine that ran
    /// restic.
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    pub fn location(&self) -> &str {
        &self.location
    }

    /// The password travels through the environment, never as an argument: a process's
    /// command line is readable by everyone on the machine.
    fn env(&self) -> Vec<(String, String)> {
        let mut v = vec![
            ("RESTIC_REPOSITORY".into(), self.location.clone()),
            ("RESTIC_PASSWORD".into(), self.password.clone()),
        ];
        v.extend(self.extra_env.iter().cloned());
        v
    }

    async fn exec(&self, args: &[&str]) -> Result<Output> {
        let command = args.join(" ");
        let args = waiting(args.iter().map(|s| s.to_string()).collect());
        let out = self.runner.run(&args, &self.env()).await?;
        if !out.ok() {
            return Err(Error::Restic {
                command,
                stderr: out.stderr.trim().to_string(),
            });
        }
        Ok(out)
    }

    /// Controlled access for the neighbouring modules (verification).
    pub(crate) async fn exec_public(&self, args: &[&str]) -> Result<Output> {
        self.exec(args).await
    }

    /// Creates the repository. Idempotent: an already initialised repository is not an
    /// error.
    pub async fn init(&self) -> Result<()> {
        let args = vec!["init".to_string()];
        let out = self.runner.run(&args, &self.env()).await?;

        if out.ok() {
            tracing::info!(repo = %self.location, "restic repository created");
            return Ok(());
        }
        if out.stderr.contains("already initialized")
            || out.stderr.contains("already exists")
            || out.stdout.contains("already initialized")
        {
            tracing::debug!(repo = %self.location, "repository already initialised");
            return Ok(());
        }
        Err(Error::Restic {
            command: "init".into(),
            stderr: out.stderr.trim().to_string(),
        })
    }

    /// Backs up a path, tagged with the app it belongs to.
    pub async fn backup(&self, path: &str, tags: &[&str]) -> Result<String> {
        self.backup_paths(&[path], tags).await
    }

    /// Backs up several paths into one snapshot.
    pub async fn backup_paths(&self, paths: &[&str], tags: &[&str]) -> Result<String> {
        let path = paths.join(" ");
        let mut args = vec!["backup"];
        args.extend(paths);
        args.extend(["--json", "--host", &self.host]);
        for t in tags {
            args.push("--tag");
            args.push(t);
        }
        let out = self.exec(&args).await?;
        let id = summary_id(&out.stdout)?;
        tracing::info!(id = %&id[..8.min(id.len())], path, "snapshot created");
        Ok(id)
    }

    /// Backs up what `input` streams as the snapshot's one file, `/<name>`. The id.
    pub async fn backup_stdin(
        &self,
        name: &str,
        tags: &[&str],
        input: &mut (dyn tokio::io::AsyncRead + Send + Unpin),
    ) -> Result<String> {
        let mut args: Vec<String> = ["backup", "--stdin", "--stdin-filename", name, "--json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        args.extend(["--host".to_string(), self.host.clone()]);
        for t in tags {
            args.extend(["--tag".to_string(), t.to_string()]);
        }
        let out = self
            .runner
            .run_from(&waiting(args), &self.env(), input)
            .await?;
        if !out.ok() {
            return Err(Error::Restic {
                command: "backup --stdin".into(),
                stderr: out.stderr.trim().to_string(),
            });
        }
        summary_id(&out.stdout)
    }

    /// Writes `path` of `snapshot` into `out`, as it was backed up.
    pub async fn dump(
        &self,
        snapshot: &str,
        path: &str,
        out: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
    ) -> Result<()> {
        let args: Vec<String> = ["dump", snapshot, path]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let o = self
            .runner
            .run_into(&waiting(args), &self.env(), out)
            .await?;
        if !o.ok() {
            return Err(Error::Restic {
                command: format!("dump {snapshot} {path}"),
                stderr: o.stderr.trim().to_string(),
            });
        }
        Ok(())
    }

    /// `path` in `snapshot`, as restic recorded it — `None` when the snapshot does not
    /// hold it. What `dump` leaves out of a directory's archive: the directory itself.
    pub async fn node(&self, snapshot: &str, path: &str) -> Result<Option<Node>> {
        let out = self.exec(&["ls", "--json", snapshot, path]).await?;
        Ok(out
            .stdout
            .lines()
            .filter_map(Node::parse)
            .find(|n| n.path == path))
    }

    pub async fn snapshots(&self, tag: Option<&str>) -> Result<Vec<Snapshot>> {
        let mut args = vec!["snapshots", "--json"];
        if let Some(t) = tag {
            args.push("--tag");
            args.push(t);
        }
        let out = self.exec(&args).await?;
        serde_json::from_str(&out.stdout)
            .map_err(|e| Error::Unexpected(format!("unreadable snapshot list: {e}")))
    }

    /// Restores a snapshot to `target`.
    pub async fn restore(&self, snapshot: &str, target: &str) -> Result<()> {
        self.exec(&["restore", snapshot, "--target", target])
            .await?;
        tracing::info!(snapshot, target, "restore completed");
        Ok(())
    }

    /// Puts `path` back as `snapshot` holds it, in place.
    ///
    /// 🔴 `--delete`: restored over what is there, a file written since the snapshot
    /// would stay beside the ones it came back to — an app's database next to a
    /// journal from another day. And only `path`: the snapshot's other paths are not
    /// this restore's to overwrite.
    pub async fn restore_path(&self, snapshot: &str, path: &str) -> Result<()> {
        self.exec(&[
            "restore",
            &format!("{snapshot}:{path}"),
            "--target",
            path,
            "--delete",
            "--exclude-xattr",
            NFS4_ACL,
        ])
        .await?;
        tracing::info!(snapshot, path, "restored in place");
        Ok(())
    }

    /// Puts back the files `snapshot` holds under `dir`, in place — nothing else.
    ///
    /// 🔴 Restored at `--target /`, a snapshot brings back every directory above its
    /// files too, owner and mode included: a SQLite snapshot staged in a scratch volume
    /// as root made the app's own directories root's, 0755. Restored from `dir` onto
    /// `dir`, the directory is the target and keeps its metadata; and without
    /// `--delete`, the volume's other files stay.
    pub async fn restore_files_in(&self, snapshot: &str, dir: &str) -> Result<()> {
        self.exec(&[
            "restore",
            &format!("{snapshot}:{dir}"),
            "--target",
            dir,
            "--exclude-xattr",
            NFS4_ACL,
        ])
        .await?;
        tracing::info!(snapshot, dir, "files restored in place");
        Ok(())
    }

    /// Forgets one snapshot by its id: what whoever holds the credential would try.
    pub async fn forget_snapshot(&self, id: &str) -> Result<()> {
        self.exec(&["forget", id]).await?;
        Ok(())
    }

    /// Applies retention, then reclaims the space.
    ///
    /// 🔴 Refuses a policy that keeps nothing: that would be a disguised `rm -rf`.
    pub async fn forget(&self, policy: &RetentionPolicy, prune: bool) -> Result<()> {
        for args in forget_passes(policy, prune)? {
            let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            self.exec(&refs).await?;
        }
        Ok(())
    }

    /// Checks the repository's integrity.
    ///
    /// A corrupted repository discovered on the day of the restore is a backup
    /// that never existed.
    pub async fn check(&self) -> Result<()> {
        self.exec(&["check"]).await?;
        Ok(())
    }
}

/// The `restic` arguments retention runs, one pass a line — the upkeep's, and the ones
/// a destination's owner is handed to run where Homelabus cannot erase.
///
/// 🔴 Refuses a policy that keeps nothing: `restic forget` with no `--keep-*` at all
/// deletes every snapshot.
pub fn forget_passes(policy: &RetentionPolicy, prune: bool) -> Result<Vec<Vec<String>>> {
    if !policy.keeps_something() {
        return Err(Error::EmptyRetention);
    }

    // 🔴 Dumps by database, never by path. restic groups by `host,paths`, and each
    // dump was written under its own timestamped name: a group of one, which every
    // policy keeps — a dump every pass, never forgotten, until the disk was full.
    // Their tags (`app:`, `db:`, the kind) are the same from one dump of a database
    // to the next, so they are grouped by those.
    let mut passes = [
        vec!["forget".to_string()],
        vec![
            "forget".to_string(),
            "--tag".to_string(),
            crate::pgdump::DUMP_KIND.to_string(),
            "--group-by".to_string(),
            "host,tags".to_string(),
        ],
    ];
    let last = passes.len() - 1;
    for (i, args) in passes.iter_mut().enumerate() {
        args.extend(policy.to_args());
        // Reclaiming the space once, after both: pruning reads the whole repository.
        if prune && i == last {
            args.push("--prune".to_string());
        }
    }
    Ok(passes.into())
}

#[cfg(test)]
mod tests {
    /// Lines from restic 0.19.1's `ls --json`, of a directory `chmod 2750` and a file
    /// in it (measured 2026-11-09).
    #[test]
    fn a_node_reads_as_chmod_would_set_it() {
        let dir = r#"{"name":"vol","type":"dir","path":"/donnees/vol","uid":1000,"gid":1001,"mode":2151678440,"permissions":"dgrwxr-x---","mtime":"2026-11-09T13:00:00.433414426Z","message_type":"node","struct_type":"node"}"#;
        let n = super::Node::parse(dir).expect("a node");
        assert_eq!(
            (n.kind.as_str(), n.uid, n.gid, n.mode),
            ("dir", 1000, 1001, 0o2750)
        );
        assert_eq!(Some(n.mtime), crate::pitr::parse_utc("2026-11-09 13:00:00"));
        let file = r#"{"name":"a.txt","type":"file","path":"/donnees/vol/a.txt","uid":1000,"gid":1001,"size":3,"mode":416,"mtime":"2026-11-09T13:00:00Z","struct_type":"node"}"#;
        let f = super::Node::parse(file).expect("a node");
        assert_eq!((f.mode, f.size), (0o640, 3));
        let snapshot = r#"{"time":"2026-11-09T13:00:03Z","paths":["/donnees/vol"],"id":"0877","struct_type":"snapshot"}"#;
        assert_eq!(super::Node::parse(snapshot), None);
    }

    #[test]
    fn a_snapshot_s_time_is_read_with_its_offset() {
        let at = |time: &str| {
            super::Snapshot {
                id: String::new(),
                time: time.into(),
                paths: Vec::new(),
                tags: Vec::new(),
                hostname: String::new(),
            }
            .epoch()
        };
        let utc = at("2026-10-19T12:02:03Z");
        assert_eq!(utc, crate::pitr::parse_utc("2026-10-19 12:02:03"));
        assert_eq!(at("2026-10-19T14:02:03.123456789+02:00"), utc);
        assert_eq!(at("2026-10-19T07:32:03.5-04:30"), utc);
        assert_eq!(
            at("2099-01-01T00:00:00+00:00").map(|t| t > utc.unwrap_or(0)),
            Some(true)
        );
        assert_eq!(at("yesterday"), None);
    }

    use super::*;
    use std::sync::Mutex;

    /// Scriptable runner: returns dictated output, records the calls.
    struct Fake {
        outputs: Mutex<Vec<Output>>,
        calls: Mutex<Vec<Vec<String>>>,
        envs: Mutex<Vec<Vec<(String, String)>>>,
    }

    impl Fake {
        fn returning(outs: Vec<Output>) -> Self {
            Self {
                outputs: Mutex::new(outs),
                calls: Mutex::new(Vec::new()),
                envs: Mutex::new(Vec::new()),
            }
        }
        fn ok(stdout: &str) -> Self {
            Self::returning(vec![Output {
                status: 0,
                stdout: stdout.into(),
                stderr: String::new(),
            }])
        }
    }

    #[async_trait::async_trait]
    impl Runner for Fake {
        async fn run(&self, args: &[String], env: &[(String, String)]) -> Result<Output> {
            self.calls.lock().expect("mutex").push(args.to_vec());
            self.envs.lock().expect("mutex").push(env.to_vec());
            let mut o = self.outputs.lock().expect("mutex");
            Ok(if o.len() > 1 {
                o.remove(0)
            } else {
                o[0].clone()
            })
        }
        async fn run_from(
            &self,
            args: &[String],
            env: &[(String, String)],
            _: &mut (dyn tokio::io::AsyncRead + Send + Unpin),
        ) -> Result<Output> {
            self.run(args, env).await
        }
        async fn run_into(
            &self,
            args: &[String],
            env: &[(String, String)],
            _: &mut (dyn tokio::io::AsyncWrite + Send + Unpin),
        ) -> Result<Output> {
            self.run(args, env).await
        }
    }

    fn repo(f: Fake) -> Repository<Fake> {
        Repository::new(f, "/tmp/repo", "test-password")
    }

    #[tokio::test]
    async fn the_password_never_reaches_the_command_line() {
        // 🔴 A process's command line is readable by every user of the machine. The
        // password therefore travels through the environment.
        let r = repo(Fake::ok("[]"));
        r.snapshots(None).await.expect("appel");

        let calls = r.runner.calls.lock().expect("mutex");
        assert!(
            !calls[0].iter().any(|a| a.contains("test-password")),
            "password found in the arguments: {:?}",
            calls[0]
        );

        let envs = r.runner.envs.lock().expect("mutex");
        assert!(envs[0]
            .iter()
            .any(|(k, v)| k == "RESTIC_PASSWORD" && v == "test-password"));
    }

    /// 🔴 Two loops of one daemon reach a repository at once: the lab's start ran the
    /// upkeep's exclusive lock and a pre-update backup four seconds apart, and the
    /// backup failed on "repository is already locked" instead of waiting.
    #[tokio::test]
    async fn every_command_waits_for_a_lock_rather_than_failing() {
        let r = repo(Fake::ok(
            r#"{"message_type":"summary","snapshot_id":"abc"}"#,
        ));
        r.backup("/donnees/app-data", &["app:a"])
            .await
            .expect("backup");
        let _ = r.snapshots(None).await;
        r.check().await.expect("check");
        r.forget_snapshot("abc").await.expect("forget");
        r.restore_path("abc", "/donnees/app-data")
            .await
            .expect("restore");
        r.backup_stdin("dump.sql", &[], &mut tokio::io::empty())
            .await
            .expect("stdin");
        r.dump("abc", "/dump.sql", &mut tokio::io::sink())
            .await
            .expect("dump");
        let calls = r.runner.calls.lock().expect("mutex");
        assert_eq!(calls.len(), 7);
        for c in calls.iter() {
            assert!(
                c.windows(2)
                    .any(|w| w[0] == "--retry-lock" && w[1] == LOCK_WAIT),
                "no lock wait: {c:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_restore_in_place_takes_one_path_and_deletes_what_came_since() {
        let r = repo(Fake::ok(""));
        r.restore_path("3de83a48", "/donnees/app-data")
            .await
            .expect("restore");
        let calls = r.runner.calls.lock().expect("mutex");
        assert_eq!(
            calls[0],
            [
                "restore",
                "3de83a48:/donnees/app-data",
                "--target",
                "/donnees/app-data",
                "--delete",
                "--exclude-xattr",
                "system.nfs4_acl",
                "--retry-lock",
                LOCK_WAIT
            ]
        );
    }

    #[tokio::test]
    async fn init_is_idempotent() {
        let r = repo(Fake::returning(vec![Output {
            status: 1,
            stdout: String::new(),
            stderr: "Fatal: create repository at /tmp/repo failed: already initialized".into(),
        }]));
        assert!(
            r.init().await.is_ok(),
            "an already created repository is not an error"
        );
    }

    #[tokio::test]
    async fn a_real_init_failure_is_reported() {
        let r = repo(Fake::returning(vec![Output {
            status: 1,
            stdout: String::new(),
            stderr: "Fatal: permission denied".into(),
        }]));
        let err = r.init().await.unwrap_err();
        assert!(err.to_string().contains("permission denied"), "{err}");
    }

    #[tokio::test]
    async fn the_snapshot_id_is_read_from_the_summary() {
        let json = r#"{"message_type":"status","percent_done":0.5}
{"message_type":"summary","snapshot_id":"abc123def456","files_new":3}"#;
        let r = repo(Fake::ok(json));
        let id = r.backup("/data", &["app:gitea"]).await.expect("backup");
        assert_eq!(id, "abc123def456");
    }

    #[tokio::test]
    async fn backups_carry_a_stable_host() {
        // 🔴 Without a fixed `--host`, `forget` groups by host and never deletes.
        let r = repo(Fake::ok(
            r#"{"message_type":"summary","snapshot_id":"aaa"}"#,
        ));
        r.backup("/data", &[]).await.expect("backup");

        let calls = r.runner.calls.lock().expect("mutex");
        let joined = calls[0].join(" ");
        assert!(
            joined.contains("--host homelabus"),
            "host missing from the arguments: {joined}"
        );
    }

    #[tokio::test]
    async fn tags_are_passed_through() {
        let r = repo(Fake::ok(
            r#"{"message_type":"summary","snapshot_id":"aaa"}"#,
        ));
        r.backup("/data", &["app:gitea", "kind:volume"])
            .await
            .expect("backup");

        let calls = r.runner.calls.lock().expect("mutex");
        let joined = calls[0].join(" ");
        assert!(joined.contains("--tag app:gitea"));
        assert!(joined.contains("--tag kind:volume"));
    }

    #[tokio::test]
    async fn an_empty_retention_is_refused() {
        // 🔴 `restic forget` with no `--keep-*` at all deletes EVERYTHING.
        let r = repo(Fake::ok(""));
        let empty = RetentionPolicy {
            hourly: 0,
            daily: 0,
            weekly: 0,
            monthly: 0,
            yearly: 0,
        };
        let err = r.forget(&empty, true).await.unwrap_err();
        assert!(matches!(err, Error::EmptyRetention), "{err}");

        // And above all: nothing was executed.
        assert!(r.runner.calls.lock().expect("mutex").is_empty());
    }

    #[tokio::test]
    async fn forget_passes_the_policy_and_prunes() {
        let r = repo(Fake::ok(""));
        r.forget(&RetentionPolicy::default(), true)
            .await
            .expect("forget");

        let calls = r.runner.calls.lock().expect("mutex");
        assert!(calls
            .iter()
            .all(|c| c.join(" ").contains("--keep-daily 14")));
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.contains(&"--prune".to_string()))
                .count(),
            1,
            "pruned once: {calls:?}"
        );
        assert!(calls[calls.len() - 1].contains(&"--prune".to_string()));
    }

    #[tokio::test]
    async fn dumps_are_forgotten_by_database_whatever_their_file_name() {
        // 🔴 Found by review: each dump's timestamped path made a group of one, and
        // retention never removed a single dump.
        let r = repo(Fake::ok(""));
        r.forget(&RetentionPolicy::default(), true)
            .await
            .expect("forget");
        let calls = r.runner.calls.lock().expect("mutex");
        assert!(
            calls.iter().any(|c| c
                .join(" ")
                .contains("--tag kind:sql-dump --group-by host,tags")),
            "{calls:?}"
        );
        // Everything else keeps restic's grouping by path: an app's two volumes carry
        // the same tags, and grouped by them one would be forgotten for the other.
        assert!(calls
            .iter()
            .any(|c| !c.iter().any(|a| a == "--group-by" || a == "--tag")));
    }

    #[tokio::test]
    async fn a_database_is_restored_without_its_directories() {
        let r = repo(Fake::ok(""));
        r.restore_files_in("3de83a48", "/donnees/app-data/data")
            .await
            .expect("restore");
        let calls = r.runner.calls.lock().expect("mutex");
        assert_eq!(
            calls[0],
            [
                "restore",
                "3de83a48:/donnees/app-data/data",
                "--target",
                "/donnees/app-data/data",
                "--exclude-xattr",
                "system.nfs4_acl",
                "--retry-lock",
                LOCK_WAIT
            ]
        );
    }

    #[test]
    fn snapshots_deserialize_from_restic_json() {
        let json = r#"[{"id":"abcdef1234567890","time":"2026-08-05T03:00:00Z",
                        "paths":["/data"],"tags":["app:gitea"],"hostname":"node1"}]"#;
        let s: Vec<Snapshot> = serde_json::from_str(json).expect("analysable");
        assert_eq!(s[0].short_id(), "abcdef12");
        assert_eq!(s[0].tags, vec!["app:gitea"]);
    }
}
