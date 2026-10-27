//! Logical MariaDB backup (layer L1).
//!
//! The counterpart of [`crate::pgdump`] for the catalog's other engine. Until now the
//! scheduler skipped every non-PostgreSQL database and said so — honest, but a MariaDB
//! app had **no logical backup at all**.
//!
//! ## 🔴 Three ways for a MariaDB dump to succeed while being unusable
//!
//! This module exists mostly for these three traps. Each produces a plausibly sized
//! file, an exit code of 0, and a restore that *looks* like it works.
//!
//! **1. Routines, triggers and events are NOT in the dump by default.**
//! `mariadb-dump` without `--routines --triggers --events` exports the tables and the
//! data, and silently leaves out the stored procedures, the triggers and the scheduled
//! events. The dump restores without an error, the data is there, and the app is subtly
//! broken — a missing trigger only shows on the first write that should have fired it.
//!
//! **2. Without `--single-transaction`, the dump is not consistent.** `mariadb-dump`
//! defaults to `--lock-tables`, which locks one database at a time: the tables are
//! therefore captured at different instants, and the foreign keys between them can point
//! into the void. It is the same flaw as copying a PostgreSQL's files hot, only less
//! visible.
//!
//! **3. `--single-transaction` protects ONLY transactional tables.** On a MyISAM or Aria
//! table, the option is accepted without a word and provides strictly no consistency.
//! You believe you have a snapshot; you have a copy spread over time. Hence
//! [`MariaDumper::dump`] demanding to know what it is touching, and
//! [`NON_TRANSACTIONNEL`].
//!
//! ## 🔴 How we know a dump is complete
//!
//! Unlike PostgreSQL's `custom` format, a MariaDB dump is **text concatenated as it
//! goes**. A dump interrupted halfway — container killed, disk full, connection dropped
//! — leaves a perfectly valid SQL file, simply missing its end. Restored, it produces a
//! database missing tables, without a single error.
//!
//! `mariadb-dump` writes a guard line last (`-- Dump completed`). Its presence is the
//! **only** proof the process ran to completion, and [`check_full`] refuses any
//! dump that does not carry it. That is why we never pass `--skip-comments`: the option
//! would remove the guard line, and with it our only way of detecting a truncation.

use crate::pgdump::DumpRunner;
use crate::{Error, Result};

/// The line `mariadb-dump` writes last of all.
///
/// 🔴 Our only proof of completeness. See the "How we know a dump is complete" section
/// at the top of the module.
pub const GUARD_LINE: &str = "-- Dump completed";

/// The storage engines `--single-transaction` does not protect.
///
/// 🔴 The option is accepted without the slightest warning on these tables, and provides
/// no consistency. The dump looks fine.
pub const NON_TRANSACTIONNEL: &[&str] = &["MyISAM", "Aria", "MEMORY", "CSV", "ARCHIVE"];

/// Where to connect, and with what.
#[derive(Debug, Clone)]
pub struct MariaTarget {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: String,
}

impl MariaTarget {
    /// The client's environment variables.
    ///
    /// 🔴 `MYSQL_PWD` and not `--password=…`: a password on the command line is readable
    /// by any user of the machine through `ps`, and MariaDB says so itself on stderr — a
    /// warning you would notice in the logs once the secret is already exposed.
    fn env(&self) -> Vec<(String, String)> {
        vec![("MYSQL_PWD".into(), self.password.clone())]
    }

    /// Where to connect, as arguments.
    ///
    /// 🔴 Not `MYSQL_HOST`: MariaDB's clients ignore it and try the local socket, so
    /// every dump failed on "Can't connect to local server" — found against a real
    /// server, where the simulated runner had answered whatever it was given.
    fn connection(&self) -> [String; 3] {
        [
            format!("--host={}", self.host),
            format!("--port={}", self.port),
            format!("--user={}", self.user),
        ]
    }
}

/// What the caller knows of the reachable consistency.
///
/// 🔴 This is not a convenience option: it is the choice between a consistent snapshot
/// and a copy spread over time, and it must be **explicit**. A defaulted boolean would
/// have let the MyISAM case through in silence, which is precisely the one we are trying
/// not to miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consistency {
    /// Every table is transactional (InnoDB): `--single-transaction` gives a consistent
    /// snapshot, without locking the database.
    Transactional,
    /// At least one table is not. `--single-transaction` would be a lie: we take a read
    /// lock for the duration of the dump.
    ///
    /// ⚠️ The app's writes are blocked during that time. It is the price of a restorable
    /// dump, and better paid than discovering the inconsistency at restore time.
    LockRequired,
}

pub struct MariaDumper<R: DumpRunner> {
    runner: R,
}

impl<R: DumpRunner> MariaDumper<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }

    /// The dump's arguments, separated so they can be tested without a server.
    pub fn dump_args(database: &str, coherence: Consistency) -> Vec<String> {
        let mut args: Vec<String> = vec!["mariadb-dump".into()];

        match coherence {
            // Consistency without a lock: only possible on all-InnoDB.
            Consistency::Transactional => args.push("--single-transaction".into()),
            // 🔴 The lock is the only way to get a consistent snapshot of a
            // non-transactional table. `--single-transaction` here would lock nothing
            // AND provide no consistency: the worst of both.
            Consistency::LockRequired => args.push("--lock-tables".into()),
        }

        args.extend(
            [
                // 🔴 None of the three is taken by default. Without them, stored
                // procedures, triggers and scheduled events vanish from the dump without
                // a word, and the restore succeeds anyway.
                "--routines",
                "--triggers",
                "--events",
                // Includes `CREATE DATABASE IF NOT EXISTS` and `USE`: without it, the
                // dump does not say where to restore and depends on an already selected
                // database.
                "--databases",
            ]
            .iter()
            .map(|s| s.to_string()),
        );

        args.push(database.to_string());
        args
    }

    /// Produces a complete logical dump.
    ///
    /// The reachable consistency must be passed explicitly — see [`Consistency`].
    pub async fn dump(&self, target: &MariaTarget, coherence: Consistency) -> Result<Vec<u8>> {
        let env = target.env();
        let mut args = Self::dump_args(&target.database, coherence);
        args.splice(1..1, target.connection());

        let out = self.runner.run(&args, &env).await?;

        if out.status != 0 {
            return Err(Error::Dump {
                database: target.database.clone(),
                stderr: out.stderr.trim().to_string(),
            });
        }

        check_full(&target.database, &out.stdout)?;

        tracing::info!(
            database = %target.database,
            bytes = out.stdout.len(),
            coherence = ?coherence,
            "MariaDB dump produced"
        );
        Ok(out.stdout)
    }

    /// Restores a dump into the server, stopped at its first error.
    ///
    /// ⚠️ Since the dump carries `CREATE DATABASE`/`USE`, it restores at server level and
    /// recreates its database itself — into the one its `USE` names, whatever
    /// `target` says: [`check_database`] refuses another.
    ///
    /// Not one transaction: MariaDB commits every `CREATE TABLE` on its own, so a
    /// restore stopped halfway leaves the tables it reached.
    pub async fn restore(&self, target: &MariaTarget, dump: &[u8]) -> Result<()> {
        // 🔴 We refuse to restore a truncated dump. Letting it through would produce a
        // database missing tables, without a single error — the failure mode this whole
        // verification exists to prevent.
        check_full(&target.database, dump)?;
        check_database(&target.database, dump)?;

        let mut args = vec!["mariadb".to_string()];
        args.extend(target.connection());

        let mut env = target.env();
        env.push(("HLB_STDIN_B64".into(), crate::pgdump::base64_encode(dump)));

        let out = self.runner.run(&args, &env).await?;
        if out.status != 0 {
            return Err(Error::Dump {
                database: target.database.clone(),
                stderr: out.stderr.trim().to_string(),
            });
        }
        tracing::info!(database = %target.database, "MariaDB dump restored");
        Ok(())
    }

    /// Runs `statements` at server level as `target`'s user, one after the other,
    /// stopped at the first that fails.
    pub async fn sql(&self, target: &MariaTarget, statements: &[String]) -> Result<()> {
        let mut args = vec!["mariadb".to_string()];
        args.extend(target.connection());
        args.push("--execute".into());
        args.push(statements.join(";\n"));
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

/// Refuses a dump that is not `database`'s.
///
/// 🔴 A dump taken with `--databases` restores where its own `USE` says. One of another
/// database, restored "into" this one, would leave it as it was and write over the
/// other — another app's, on the shared server. The `USE` lines are the dump's
/// statements: data never starts a line, `mariadb-dump` escaping its newlines.
pub fn check_database(database: &str, dump: &[u8]) -> Result<()> {
    let wanted = format!("USE `{database}`;");
    let mut used = dump
        .split(|b| *b == b'\n')
        .filter(|l| l.starts_with(b"USE "))
        .peekable();
    let refused = |why: String| Error::Dump {
        database: database.to_string(),
        stderr: why,
    };
    if used.peek().is_none() {
        return Err(refused(
            "the dump names no database (no `USE`): it would restore into whichever one \
             the connection had"
                .into(),
        ));
    }
    match used.find(|l| l.trim_ascii_end() != wanted.as_bytes()) {
        Some(other) => Err(refused(format!(
            "the dump is another database's — \"{}\": restored, it would write over that \
             one",
            String::from_utf8_lossy(other).trim_end()
        ))),
        None => Ok(()),
    }
}

/// Refuses a dump that does not carry the final guard line.
///
/// 🔴 This is the module's central check. A MariaDB dump is text written as it goes:
/// interrupted halfway, it stays valid SQL, simply cut short. Restored, it gives an
/// incomplete database **without a single error**.
///
/// The guard line is only written after the last useful byte. Its presence is the only
/// proof the process ran to the end.
pub fn check_full(database: &str, dump: &[u8]) -> Result<()> {
    if dump.is_empty() {
        return Err(Error::Dump {
            database: database.to_string(),
            stderr: "empty dump".into(),
        });
    }

    // The guard line is at the end of the file: no point scanning a dump of several
    // gigabytes. 4 KiB covers the line and what follows it very generously.
    let tail = &dump[dump.len().saturating_sub(4096)..];

    if !String::from_utf8_lossy(tail).contains(GUARD_LINE) {
        return Err(Error::Dump {
            database: database.to_string(),
            stderr: format!(
                "TRUNCATED dump: the guard line \"{GUARD_LINE}\" is missing. The \
                 file stays valid SQL but its end is gone, and restoring it would give \
                 an incomplete database without an error. \
                 Usual causes: disk full, container killed, connection dropped."
            ),
        });
    }
    Ok(())
}

/// The query that says whether `--single-transaction` can keep its promise.
///
/// 🔴 It must be asked **before** every dump, not once and for all: an app migration can
/// introduce a MyISAM table months after the install, and the dump would silently become
/// inconsistent.
pub fn engines_query(database: &str) -> String {
    format!(
        "SELECT DISTINCT ENGINE FROM information_schema.TABLES \
         WHERE TABLE_SCHEMA = '{database}' AND ENGINE IS NOT NULL"
    )
}

/// Derives the reachable consistency from the list of engines present.
///
/// ⚠️ An **empty** list does not amount to "all is well": it means nothing could be read,
/// and we then fall back on locking. Concluding InnoDB by default would be exactly the
/// mistake this module exists to prevent.
pub fn consistency_for(engines: &[String]) -> Consistency {
    if engines.is_empty() {
        return Consistency::LockRequired;
    }

    let risk = engines.iter().any(|m| {
        NON_TRANSACTIONNEL
            .iter()
            .any(|nt| nt.eq_ignore_ascii_case(m.trim()))
    });

    if risk {
        Consistency::LockRequired
    } else {
        Consistency::Transactional
    }
}

/// Scheduled production and archiving, counterpart of [`crate::pgdump::scheduled`].
pub mod scheduled {
    use super::*;
    use crate::pgdump::scheduled::Dump;

    /// Produces a MariaDB database's dump.
    pub async fn produce<R: DumpRunner>(
        dumper: &MariaDumper<R>,
        app: &str,
        target: &MariaTarget,
        coherence: Consistency,
        at: i64,
    ) -> Result<Dump> {
        let bytes = dumper.dump(target, coherence).await?;
        Ok(Dump {
            app: app.to_string(),
            database: target.database.clone(),
            // `.sql` and not `.dump`: it is text, and the name must say so, so that
            // nobody attempts a `pg_restore` on it on the day of the incident.
            filename: file_name(app, &target.database, at),
            bytes,
        })
    }

    /// A MariaDB dump's filename.
    pub fn file_name(app: &str, database: &str, at: i64) -> String {
        let (y, m, d, hh, mm, ss) = crate::pitr::civil_public(at);
        format!("{app}-{database}-{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z.sql")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgdump::RawOutput;

    /// A runner that returns what it is told, to exercise the logic without a server.
    struct Fake {
        output: Vec<u8>,
        status: i32,
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl Fake {
        fn new_one(output: &str, status: i32) -> Self {
            Self {
                output: output.as_bytes().to_vec(),
                status,
                seen: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn arguments(&self) -> String {
            self.seen.lock().expect("lock").join(" ")
        }
    }

    #[async_trait::async_trait]
    impl DumpRunner for Fake {
        async fn run(&self, args: &[String], _env: &[(String, String)]) -> Result<RawOutput> {
            *self.seen.lock().expect("lock") = args.to_vec();
            Ok(RawOutput {
                status: self.status,
                stdout: self.output.clone(),
                stderr: String::new(),
            })
        }
    }

    fn target() -> MariaTarget {
        MariaTarget {
            host: "mariadb".into(),
            port: 3306,
            database: "app".into(),
            user: "admin".into(),
            password: "s3cr3t".into(),
        }
    }

    const DUMP_COMPLETE: &str = "-- MariaDB dump\nUSE `app`;\nCREATE TABLE t(i int);\n\
                                 -- Dump completed on 2026-08-17\n";

    #[test]
    fn a_dump_of_another_database_is_refused() {
        // 🔴 It restores where its `USE` says: into another app's database.
        check_database("app", DUMP_COMPLETE.as_bytes()).expect("its own");
        let other = DUMP_COMPLETE.replace("`app`", "`vaultwarden`");
        let e = check_database("app", other.as_bytes()).expect_err("another's");
        assert!(e.to_string().contains("vaultwarden"), "{e}");
        let both = DUMP_COMPLETE.replace("CREATE", "USE `other`;\nCREATE");
        assert!(check_database("app", both.as_bytes()).is_err());
        let none = DUMP_COMPLETE.replace("USE `app`;\n", "");
        assert!(check_database("app", none.as_bytes()).is_err());
        // A value in the data never starts a line: it is not a statement.
        let data =
            DUMP_COMPLETE.replace("CREATE", "INSERT INTO t VALUES ('x\\nUSE `b`;');\nCREATE");
        check_database("app", data.as_bytes()).expect("data, not a statement");
    }

    #[tokio::test]
    async fn statements_run_at_server_level_without_the_password_on_the_line() {
        let f = Fake::new_one("", 0);
        let d = MariaDumper::new(f);
        d.sql(
            &target(),
            &[
                "DROP DATABASE IF EXISTS `app`".into(),
                "FLUSH PRIVILEGES".into(),
            ],
        )
        .await
        .expect("run");
        let args = d.runner.arguments();
        assert!(
            args.contains("--execute DROP DATABASE IF EXISTS `app`;\nFLUSH PRIVILEGES"),
            "{args}"
        );
        assert!(!args.contains("s3cr3t"), "{args}");
    }

    #[test]
    fn routines_triggers_and_events_are_always_asked_for() {
        // 🔴 None of the three is taken by default by mariadb-dump. Without them the
        // dump succeeds, restores without error, and the app is subtly broken: a missing
        // trigger only shows on the first write concerned.
        let args = MariaDumper::<Fake>::dump_args("app", Consistency::Transactional).join(" ");
        assert!(args.contains("--routines"), "{args}");
        assert!(args.contains("--triggers"), "{args}");
        assert!(args.contains("--events"), "{args}");
    }

    #[test]
    fn comments_are_never_disabled() {
        // 🔴 `--skip-comments` would remove the final guard line, and with it our only
        // way of detecting a truncated dump. The option must never appear.
        for c in [Consistency::Transactional, Consistency::LockRequired] {
            let args = MariaDumper::<Fake>::dump_args("app", c).join(" ");
            assert!(!args.contains("skip-comments"), "{args}");
            assert!(!args.contains("--compact"), "{args}");
        }
    }

    #[test]
    fn single_transaction_is_never_used_on_non_transactional_tables() {
        // 🔴 On MyISAM, `--single-transaction` is accepted WITHOUT A WARNING and
        // provides no consistency. You believe you hold a snapshot; you have a copy
        // spread over time. The lock is needed, despite its cost.
        let t = MariaDumper::<Fake>::dump_args("app", Consistency::Transactional).join(" ");
        assert!(t.contains("--single-transaction"), "{t}");
        assert!(!t.contains("--lock-tables"), "{t}");

        let v = MariaDumper::<Fake>::dump_args("app", Consistency::LockRequired).join(" ");
        assert!(
            !v.contains("--single-transaction"),
            "a promise of consistency the option cannot keep: {v}"
        );
        assert!(v.contains("--lock-tables"), "{v}");
    }

    #[test]
    fn a_myisam_table_forces_locking() {
        assert_eq!(
            consistency_for(&["InnoDB".into()]),
            Consistency::Transactional
        );
        // A single non-transactional table is enough to contaminate the whole dump.
        assert_eq!(
            consistency_for(&["InnoDB".into(), "MyISAM".into()]),
            Consistency::LockRequired
        );
        // `information_schema`'s casing is not guaranteed.
        assert_eq!(
            consistency_for(&["myisam".into()]),
            Consistency::LockRequired
        );
        assert_eq!(consistency_for(&["Aria".into()]), Consistency::LockRequired);
    }

    #[test]
    fn an_unreadable_engine_list_is_not_a_green_light() {
        // 🔴 The same invariant as "a missing scanner is not a green light": having read
        // nothing does not mean "everything is InnoDB". Concluding consistency by default
        // means producing an inconsistent dump in silence.
        assert_eq!(consistency_for(&[]), Consistency::LockRequired);
    }

    #[test]
    fn a_truncated_dump_is_refused() {
        // 🔴 THE module's failure mode. An interrupted dump stays valid SQL, simply cut
        // short: restored, it gives a database missing tables, without a single error.
        let truncated = "-- MariaDB dump\nCREATE TABLE t(i int);\nINSERT INTO t VALUES (1),";
        let e = check_full("app", truncated.as_bytes()).expect_err("must be refused");
        let m = e.to_string();
        assert!(m.contains("TRUNCATED"), "{m}");
        assert!(m.contains("disk full"), "the cause must be suggested: {m}");

        check_full("app", DUMP_COMPLETE.as_bytes()).expect("complete dump accepted");
    }

    #[test]
    fn an_empty_dump_is_refused() {
        // Even for a database with no table, the header and the guard line are written.
        let e = check_full("app", b"").expect_err("must be refused");
        assert!(e.to_string().contains("empty"));
    }

    #[test]
    fn the_guard_line_is_looked_for_at_the_end_only() {
        // A dump where "Dump completed" appeared in the DATA, but which was truncated,
        // must stay refused: the guard line only counts at the end of the file. We bury
        // it under more than 4 KiB of content.
        let mut fake = String::from("INSERT INTO t VALUES ('-- Dump completed');\n");
        fake.push_str(&"-- padding\n".repeat(400));
        assert!(fake.len() > 4096, "the decoy must fall outside the window");
        assert!(check_full("app", fake.as_bytes()).is_err());
    }

    #[tokio::test]
    async fn the_password_never_reaches_the_command_line() {
        // 🔴 A password in an argument is readable by every user through `ps`. MariaDB
        // says so itself on stderr — too late, the secret is exposed.
        let f = Fake::new_one(DUMP_COMPLETE, 0);
        let d = MariaDumper::new(f);
        d.dump(&target(), Consistency::Transactional)
            .await
            .expect("dump");

        let args = d.runner.arguments();
        assert!(!args.contains("s3cr3t"), "password in an argument: {args}");
        assert!(!args.contains("--password"), "{args}");
    }

    #[tokio::test]
    async fn a_truncated_dump_is_refused_by_the_dumper_too() {
        // An exit code of 0 is not enough: mariadb-dump can be killed mid-write without
        // the shell reporting it.
        let f = Fake::new_one("CREATE TABLE t(i int);\n", 0);
        let d = MariaDumper::new(f);
        let e = d
            .dump(&target(), Consistency::Transactional)
            .await
            .expect_err("a dump without a guard line must be refused despite status 0");
        assert!(e.to_string().contains("TRUNCATED"));
    }

    #[tokio::test]
    async fn restoring_a_truncated_dump_is_refused() {
        // We check at restore time TOO: the dump may have been truncated after it was
        // produced, in the repository or during the transfer.
        let f = Fake::new_one("", 0);
        let d = MariaDumper::new(f);
        let e = d
            .restore(&target(), b"CREATE TABLE t(i int);")
            .await
            .expect_err("restoring a truncated dump");
        assert!(e.to_string().contains("TRUNCATED"));
    }

    #[test]
    fn the_filename_says_it_is_text() {
        // 🔴 A MariaDB dump is not in PostgreSQL's custom format. On the day of the
        // incident, the extension must stop anyone attempting a pg_restore on it.
        let n = scheduled::file_name("nextcloud", "nc", 1_755_000_000);
        assert!(n.ends_with(".sql"), "{n}");
        assert!(n.starts_with("nextcloud-nc-"), "{n}");
    }

    #[test]
    fn the_engine_query_targets_one_database() {
        // Without the filter we would read the engines of EVERY database on the server,
        // and a MyISAM table belonging to another app would force a needless lock.
        let q = engines_query("gitea");
        assert!(q.contains("TABLE_SCHEMA = 'gitea'"), "{q}");
    }
}
