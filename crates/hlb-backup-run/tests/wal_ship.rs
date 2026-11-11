//! The vital server's WAL from the house to its site's standby, on the catalog's own
//! image, command and arguments: archived compressed into the server's volume, received
//! by the site's forced command, replayed by a standby seeded from a base backup, and
//! promoted with every row written before the last push.
//!
//! ```sh
//! cargo test -p hlb-backup-run --test wal_ship -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{Duration, Instant};

use hlb_backup::wal_ship;

const NETWORK: &str = "hlb-test-walship";
const PRIMARY: &str = "hlb-test-walship-house";
const STANDBY: &str = "hlb-test-walship-site";
const VOLUMES: [&str; 5] = [
    "hlb-test-walship-data",
    "hlb-test-walship-wal",
    "hlb-test-walship-seed",
    "hlb-test-walship-seed-wal",
    "hlb-test-walship-site-dir",
];
const PASSWORD: &str = "admin-password";
/// The app's role, which owns its table and reads it off the promoted standby.
const APP: &str = "keeper";
const APP_PASSWORD: &str = "keeper-password";

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

fn ok(args: &[&str]) -> String {
    let out = docker(args);
    assert!(
        out.status.success(),
        "docker {}:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Over TCP, as postgres: the image's first start runs a temporary server on the socket.
fn psql(server: &str, sql: &str) -> Option<String> {
    let out = docker(&[
        "exec",
        "-e",
        &format!("PGPASSWORD={PASSWORD}"),
        server,
        "psql",
        "-h",
        "127.0.0.1",
        "-U",
        "postgres",
        "-v",
        "ON_ERROR_STOP=1",
        "-tAc",
        sql,
    ]);
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        if start.elapsed() > Duration::from_secs(secs) {
            let logs = |c: &str| {
                let o = docker(&["logs", "--tail", "25", c]);
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                )
            };
            panic!(
                "{what}: not after {secs} s\n--- house\n{}\n--- site\n{}",
                logs(PRIMARY),
                logs(STANDBY)
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        if std::env::var_os("HLB_KEEP").is_some() {
            return;
        }
        let _ = docker(&["rm", "-f", PRIMARY, STANDBY]);
        let _ = docker(&["network", "rm", NETWORK]);
        for v in VOLUMES {
            let _ = docker(&["volume", "rm", "-f", v]);
        }
    }
}

/// The catalog's postgres-vital: its image, command, arguments and files.
struct Server {
    image: String,
    command: Vec<String>,
    args: Vec<String>,
    files: Vec<(String, String)>,
}

fn catalog_server() -> Server {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../catalog/_platform/postgres-vital/manifest.yaml"
    );
    let y: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&std::fs::read_to_string(path).expect("manifest")).expect("yaml");
    let spec = &y["spec"];
    let strings = |v: &serde_yaml_ng::Value| -> Vec<String> {
        v.as_sequence()
            .expect("a list")
            .iter()
            .map(|s| s.as_str().expect("a string").to_string())
            .collect()
    };
    let image = &spec["image"];
    let files = spec["files"]
        .as_sequence()
        .expect("files")
        .iter()
        .map(|f| {
            let content = f["content"].as_str().expect("content");
            // The one token: the administrator's password.
            let content = if content.contains("{{") {
                PASSWORD.to_string()
            } else {
                content.to_string()
            };
            (f["path"].as_str().expect("path").to_string(), content)
        })
        .collect();
    Server {
        image: format!(
            "{}@{}",
            image["repo"].as_str().expect("repo"),
            image["digest"].as_str().expect("digest")
        ),
        command: strings(&spec["command"]),
        args: strings(&spec["args"]),
        files,
    }
}

/// `docker run -d` of the server, its files bound from `dir`, `extra` before the image.
fn start(name: &str, s: &Server, dir: &std::path::Path, extra: &[String], args: &[String]) {
    let mut a: Vec<String> = ["run", "-d", "--name", name, "--network", NETWORK]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for (i, (path, content)) in s.files.iter().enumerate() {
        let local = dir.join(format!("file-{i}"));
        std::fs::write(&local, content).expect("file written");
        a.push("--mount".into());
        a.push(format!(
            "type=bind,src={},dst={path},readonly",
            local.display()
        ));
    }
    a.push("-e".into());
    a.push("POSTGRES_PASSWORD_FILE=/run/secrets/admin-password".into());
    a.extend(extra.iter().cloned());
    a.push("--entrypoint".into());
    a.push(s.command[0].clone());
    a.push(s.image.clone());
    a.extend(s.command[1..].iter().cloned());
    a.extend(args.iter().cloned());
    let refs: Vec<&str> = a.iter().map(String::as_str).collect();
    ok(&refs);
}

/// What the house's archive holds, pushed through the site's forced command as the
/// pusher sends it: in name order, each file named with its digest, removed once taken.
fn push(receiver: &std::path::Path) -> usize {
    let script = format!(
        "cd /archive; n=0; for f in $(ls | grep -E '{}' | sort); do \
         sum=$(sha256sum $f | cut -d' ' -f1); \
         SSH_ORIGINAL_COMMAND=\"put $f $sum\" sh /receiver < $f || exit 1; rm $f; n=$((n+1)); \
         done; echo $n",
        wal_ship::NAME_PATTERN
    );
    let out = ok(&[
        "run",
        "--rm",
        "-v",
        &format!("{}:/archive", VOLUMES[1]),
        "-v",
        &format!("{}:/var/lib/homelabus-site", VOLUMES[4]),
        "--mount",
        &format!(
            "type=bind,src={},dst=/receiver,readonly",
            receiver.display()
        ),
        "--entrypoint",
        "sh",
        hlb_backup::images::RESTIC,
        "-c",
        &script,
    ]);
    out.lines().last().unwrap_or("0").parse().expect("a count")
}

/// The receiver given `command` and `input`: its exit code.
fn receive(receiver: &std::path::Path, command: &str, input: &str) -> i32 {
    let out = docker(&[
        "run",
        "--rm",
        "-e",
        &format!("SSH_ORIGINAL_COMMAND={command}"),
        "-e",
        &format!("INPUT={input}"),
        "-v",
        &format!("{}:/var/lib/homelabus-site", VOLUMES[4]),
        "--mount",
        &format!(
            "type=bind,src={},dst=/receiver,readonly",
            receiver.display()
        ),
        "--entrypoint",
        "sh",
        hlb_backup::images::RESTIC,
        "-c",
        "printf %s \"$INPUT\" | sh /receiver",
    ]);
    out.status.code().unwrap_or(-1)
}

#[test]
#[ignore = "needs Docker and the catalog's PostgreSQL image"]
fn the_site_s_standby_replays_what_the_house_pushed_and_promotes_with_it() {
    let _cleanup = Cleanup;
    let _ = docker(&["rm", "-f", PRIMARY, STANDBY]);
    let _ = docker(&["network", "create", NETWORK]);
    let s = catalog_server();
    let dir = tempfile::tempdir().expect("scratch");
    let receiver = dir.path().join("receiver");
    std::fs::write(&receiver, wal_ship::receiver_script()).expect("receiver written");

    // The house: the catalog's server, archiving into its own volume.
    start(
        PRIMARY,
        &s,
        dir.path(),
        &[
            "-v".into(),
            format!("{}:/var/lib/postgresql/data", VOLUMES[0]),
            "-v".into(),
            format!("{}:{}", VOLUMES[1], wal_ship::ARCHIVE_DIR),
        ],
        &s.args,
    );
    until("the house's server", 120, || {
        psql(PRIMARY, "SELECT 1").is_some()
    });
    assert_eq!(
        psql(PRIMARY, "SHOW archive_mode").as_deref(),
        Some("on"),
        "archiving on"
    );
    // The app's own role owns its table, as provisioning and the restores leave it.
    psql(
        PRIMARY,
        &format!(
            "CREATE ROLE {APP} LOGIN PASSWORD '{APP_PASSWORD}'; \
             CREATE TABLE vault (item text); ALTER TABLE vault OWNER TO {APP}; \
             INSERT INTO vault VALUES ('before-base')"
        ),
    )
    .expect("written");

    // The seed: the pass's base backup, as `engine_copy` takes it.
    ok(&[
        "run",
        "--rm",
        "--network",
        NETWORK,
        "-e",
        &format!("PGPASSWORD={PASSWORD}"),
        "-v",
        &format!("{}:/stage", VOLUMES[2]),
        "--entrypoint",
        "sh",
        &s.image,
        "-c",
        &format!(
            "set -eu; pg_basebackup -h {PRIMARY} -U postgres --pgdata=/stage --format=plain \
             --wal-method=stream --checkpoint=fast --no-password; \
             touch /stage/standby.signal; chown -R postgres:postgres /stage; chmod 700 /stage"
        ),
    ]);
    write_then_switch("after-base");
    until("a segment archived, compressed", 60, push_count_ready);
    assert!(push(&receiver) > 0, "something pushed");

    // The site: the same server, standing by on what arrived.
    let mut args = s.args.clone();
    args.extend(wal_ship::standby_args());
    start(
        STANDBY,
        &s,
        dir.path(),
        &[
            "-v".into(),
            format!("{}:/var/lib/postgresql/data", VOLUMES[2]),
            "-v".into(),
            format!("{}:{}", VOLUMES[3], wal_ship::ARCHIVE_DIR),
            "--mount".into(),
            format!(
                "type=volume,src={},dst={},volume-subpath=wal",
                VOLUMES[4],
                wal_ship::STANDBY_DIR
            ),
        ],
        &args,
    );
    until("the standby, both rows", 120, || {
        psql(STANDBY, "SELECT count(*) FROM vault").as_deref() == Some("2")
    });
    assert_eq!(
        psql(STANDBY, "SELECT pg_is_in_recovery()").as_deref(),
        Some("t")
    );
    // An app migrating at start meets a standby that takes nothing, not even a table
    // already there: why the lifeboat rehearses the apps on a copy of the base.
    assert_eq!(
        psql(STANDBY, "CREATE TABLE IF NOT EXISTS vault (item text)"),
        None,
        "a standby takes no write"
    );

    // Written at home later: it reaches the site with the next push alone.
    write_then_switch("seconds-before-the-cut");
    until("the next segment archived", 60, push_count_ready);
    push(&receiver);
    until("the standby, the third row", 60, || {
        psql(STANDBY, "SELECT count(*) FROM vault").as_deref() == Some("3")
    });

    // What the site refuses: a name it does not archive, a file damaged on the way.
    let bad_sum = "0".repeat(64);
    assert_eq!(
        receive(&receiver, &format!("put ../x.zst {bad_sum}"), "x"),
        2
    );
    assert_eq!(receive(&receiver, "rm -rf /", ""), 2);
    assert_eq!(
        receive(
            &receiver,
            &format!("put 0000000100000000000000FF.zst {bad_sum}"),
            "cut short"
        ),
        1,
        "a digest that does not match is refused"
    );

    // The cut: the site promotes, with every row the house pushed.
    assert_eq!(
        psql(STANDBY, "SELECT pg_promote(true, 60)").as_deref(),
        Some("t")
    );
    assert_eq!(
        psql(STANDBY, "SELECT pg_is_in_recovery()").as_deref(),
        Some("f")
    );
    psql(STANDBY, "INSERT INTO vault VALUES ('written-on-the-site')").expect("writable");

    // The return: what the house wrote past the takeover, said from the positions.
    let history = ok(&[
        "exec",
        STANDBY,
        "sh",
        "-c",
        "cat \"$PGDATA\"/pg_wal/*.history",
    ]);
    let at_cut = wal_ship::parse_position(
        &psql(PRIMARY, wal_ship::POSITION_SQL).expect("the house's position"),
    )
    .expect("read");
    let switch = wal_ship::switch_point(&history, at_cut.0).expect("timeline 1 followed");
    assert!(switch <= at_cut.1, "{switch:x} past {at_cut:?}");
    psql(PRIMARY, "INSERT INTO vault VALUES ('never-pushed')").expect("written");
    let after = wal_ship::parse_position(
        &psql(PRIMARY, wal_ship::POSITION_SQL).expect("the house's position"),
    )
    .expect("read");
    let said = wal_ship::written_past(after, &history);
    assert!(said.contains("past the point the site took over"), "{said}");

    // Read off the promoted standby by the app's own role, as the return dumps it: the
    // vital server's administrator never went to the site.
    let dumped = docker(&[
        "run",
        "--rm",
        "--network",
        NETWORK,
        "-e",
        &format!("PGPASSWORD={APP_PASSWORD}"),
        "--entrypoint",
        "pg_dump",
        &s.image,
        "-h",
        STANDBY,
        "-U",
        APP,
        "-d",
        "postgres",
        "--format=custom",
        "--no-password",
    ]);
    assert!(
        dumped.status.success(),
        "{}",
        String::from_utf8_lossy(&dumped.stderr)
    );
    assert!(dumped.stdout.starts_with(b"PGDMP"), "a custom-format dump");
    assert_eq!(
        psql(
            STANDBY,
            "SELECT string_agg(item, ',' ORDER BY item) FROM vault"
        )
        .as_deref(),
        Some("after-base,before-base,seconds-before-the-cut,written-on-the-site")
    );
}

/// A row committed at home, then its segment switched — in one `-c` the two would share
/// a transaction, and the switch would come before the commit it was meant to carry.
fn write_then_switch(item: &str) {
    psql(PRIMARY, &format!("INSERT INTO vault VALUES ('{item}')")).expect("written");
    psql(PRIMARY, "SELECT pg_switch_wal()").expect("switched");
}

/// Whether the house's archive holds a compressed segment.
fn push_count_ready() -> bool {
    let out = docker(&[
        "exec",
        PRIMARY,
        "sh",
        "-c",
        &format!(
            "ls {} | grep -cE '{}'",
            wal_ship::ARCHIVE_DIR,
            wal_ship::NAME_PATTERN
        ),
    ]);
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u32>()
        .unwrap_or(0)
        > 0
}
