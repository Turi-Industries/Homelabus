//! A base backup replayed to an instant in a throwaway container: what the vital
//! server's point-in-time restore takes a dump out of. Production is never touched.
//!
//! Started as a drill's is (`drill`): no network, the image's entrypoint replaced by a
//! `sleep`, PostgreSQL run by `pg_ctl` with [`ISOLATION`] — a restored server is
//! production's configuration, and would archive into the real archive.

use crate::drill::ISOLATION;
use crate::{pitr, wal_ship};

/// What a dump taken out of a replay is tagged. 🔴 A stored value, and never "the
/// latest": restored unasked, the next `hlb backup restore --database` would bring the
/// old state back over everyone's writes. Only its id restores it.
pub const PITR_KIND: &str = "kind:pitr";

/// Where the base is mounted, the image's own data directory.
pub const DATA: &str = "/var/lib/postgresql/data";

/// How long a replay may take before it is given up on.
pub const REPLAY_WITHIN_SECS: u64 = 600;

/// A replay's container, recognisable in a `docker ps`.
pub fn container_name(at: i64) -> String {
    let (y, m, d, hh, mm, ss) = pitr::civil_public(at);
    format!("hlb-pitr-{y:04}{m:02}{d:02}t{hh:02}{mm:02}{ss:02}")
}

/// Appended to the base's `postgresql.auto.conf`, which is read last and wins.
///
/// 🔴 `recovery_target_timeline = 'current'`, not `latest`: after a return the house
/// stays on its own timeline, while the site's promotion left a history naming the next
/// one — followed, the replay would leave the house's WAL for the site's at the switch.
/// An instant while the site was promoted is out of reach, and said.
pub fn recovery_conf(target: i64) -> String {
    format!(
        "restore_command = '{}'\n\
         recovery_target_time = '{}'\n\
         recovery_target_timeline = 'current'\n\
         recovery_target_action = 'promote'\n",
        wal_ship::restore_command(),
        pitr::pg_timestamp(target),
    )
}

/// Run as root in the container: the recovery settings and `recovery.signal` written as
/// the server's user, a standby's signal removed — the two cannot both be there —, then
/// the server started without waiting: a replay outlasts `pg_ctl`'s minute.
pub fn start_script(target: i64) -> String {
    format!(
        "set -e\n\
         cat >> {DATA}/postgresql.auto.conf <<'HLB'\n{conf}HLB\n\
         rm -f {DATA}/{standby}\n\
         : > {DATA}/recovery.signal\n\
         chown postgres:postgres {DATA}/postgresql.auto.conf {DATA}/recovery.signal\n\
         su postgres -c \"pg_ctl -D {DATA} -W -l /tmp/pg.log -o \\\"{ISOLATION}\\\" start\"\n",
        conf = recovery_conf(target),
        standby = wal_ship::STANDBY_SIGNAL,
    )
}

/// What the server's log says of where it stopped: the lines a person reads to know
/// which transaction was the last one kept.
pub fn stopped_at(log: &str) -> Vec<String> {
    log.lines()
        .filter(|l| {
            l.contains("recovery stopping")
                || l.contains("last completed transaction")
                || l.contains("recovery ended before")
        })
        .map(|l| l.trim().to_string())
        .collect()
}

/// A database name as provisioning makes them, safe inside the shell's quotes.
fn plain(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

async fn docker(args: &[&str]) -> Result<Vec<u8>, String> {
    let out = tokio::process::Command::new("docker")
        .args(args)
        .output()
        .await
        .map_err(|e| format!("docker not found: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(out.stdout)
}

/// The replay's container started, its base and WAL mounted, PostgreSQL recovering to
/// `target`. `wal_subpath`: where in `wal_volume` the segments are, if not at its root.
pub async fn start(
    container: &str,
    image: &str,
    data_volume: &str,
    wal_volume: &str,
    wal_subpath: Option<&str>,
    target: i64,
) -> Result<(), String> {
    let _ = docker(&["rm", "-f", container]).await;
    let data = format!("type=volume,src={data_volume},dst={DATA}");
    let wal = match wal_subpath {
        Some(p) => format!(
            "type=volume,src={wal_volume},dst={},readonly,volume-subpath={p}",
            wal_ship::STANDBY_DIR
        ),
        None => format!(
            "type=volume,src={wal_volume},dst={},readonly",
            wal_ship::STANDBY_DIR
        ),
    };
    docker(&[
        "run",
        "-d",
        "--name",
        container,
        "--network",
        "none",
        "--mount",
        &data,
        "--mount",
        &wal,
        "--entrypoint",
        "sleep",
        image,
        "infinity",
    ])
    .await
    .map_err(|e| format!("the replay's container did not start: {e}"))?;
    docker(&["exec", container, "sh", "-c", &start_script(target)])
        .await
        .map_err(|e| format!("the replay did not start: {e}"))?;
    Ok(())
}

async fn log(container: &str) -> String {
    docker(&["exec", container, "cat", "/tmp/pg.log"])
        .await
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// Waits for the replay to reach `target` and promote: the log's lines saying where it
/// stopped. A server that stopped instead — the WAL ending before the target, a base it
/// cannot open — is an error carrying its last lines.
pub async fn wait_promoted(container: &str) -> Result<Vec<String>, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(REPLAY_WITHIN_SECS);
    loop {
        let asked = docker(&[
            "exec",
            container,
            "su",
            "postgres",
            "-c",
            "psql -XAtc 'SELECT pg_is_in_recovery()'",
        ])
        .await
        .map(|b| String::from_utf8_lossy(&b).trim().to_string());
        if asked.as_deref() == Ok("f") {
            return Ok(stopped_at(&log(container).await));
        }
        let running = docker(&[
            "exec",
            container,
            "su",
            "postgres",
            "-c",
            &format!("pg_ctl -D {DATA} status"),
        ])
        .await
        .is_ok();
        // Starting, the socket is not there yet and `status` already says running.
        if !running {
            let l = log(container).await;
            let tail: Vec<&str> = l.lines().rev().take(8).collect();
            return Err(format!(
                "the replay stopped before the instant asked: {}",
                tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
            ));
        }
        if std::time::Instant::now() > deadline {
            return Err(format!(
                "the replay had not reached the instant asked after {REPLAY_WITHIN_SECS} s"
            ));
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// `database` dumped from the replay, in PostgreSQL's custom format — what `hlb backup
/// restore --database` reads. Checked for its signature before it is kept.
pub async fn dump(container: &str, database: &str) -> Result<Vec<u8>, String> {
    if !plain(database) {
        return Err(format!(
            "\"{database}\" is no database name provisioning makes"
        ));
    }
    let bytes = docker(&[
        "exec",
        container,
        "su",
        "postgres",
        "-c",
        &format!("pg_dump -Fc -d '{database}'"),
    ])
    .await
    .map_err(|e| format!("{database} not dumped from the replay: {e}"))?;
    if !bytes.starts_with(b"PGDMP") {
        return Err(format!("{database}'s dump from the replay is not one"));
    }
    Ok(bytes)
}

/// The replay's container gone, whatever happened to it.
pub async fn remove(container: &str) {
    let _ = docker(&["rm", "-f", container]).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_replay_follows_the_house_s_timeline_and_stops_at_the_instant() {
        let c = recovery_conf(1_762_862_960);
        assert!(c.contains("recovery_target_timeline = 'current'"), "{c}");
        assert!(
            c.contains("recovery_target_time = '2025-11-11 12:09:20+00'"),
            "{c}"
        );
        assert!(c.contains("recovery_target_action = 'promote'"), "{c}");
        assert!(c.contains(&wal_ship::restore_command()), "{c}");
    }

    #[test]
    fn the_start_is_a_script_the_shell_reads_and_it_isolates_the_server() {
        let s = start_script(1_762_862_960);
        let out = std::process::Command::new("sh")
            .args(["-n", "-c", &s])
            .output()
            .expect("sh");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            s.contains("archive_mode=off") && s.contains("listen_addresses=''"),
            "{s}"
        );
        assert!(s.contains("recovery.signal") && s.contains(" -W "), "{s}");
        assert!(
            s.find("rm -f").is_some_and(
                |i| s[i..].starts_with(&format!("rm -f {DATA}/{}", wal_ship::STANDBY_SIGNAL))
            ),
            "{s}"
        );
    }

    #[test]
    fn where_the_replay_stopped_is_read_from_its_log() {
        let log = "LOG:  starting point-in-time recovery to 2026-11-11 12:00:00+00\n\
                   LOG:  recovery stopping before commit of transaction 812, time 2026-11-11 12:00:03.1+00\n\
                   LOG:  last completed transaction was at log time 2026-11-11 11:59:58.4+00\n\
                   LOG:  database system is ready to accept connections\n";
        assert_eq!(stopped_at(log).len(), 2);
    }

    #[test]
    fn only_a_provisioned_name_reaches_the_shell() {
        assert!(plain("vaultwarden") && plain("ccnet_db") && plain("n8n-db"));
        assert!(!plain("x'; rm -rf /") && !plain(""));
    }
}
