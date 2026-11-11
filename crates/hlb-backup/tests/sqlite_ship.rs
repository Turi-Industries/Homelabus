//! A vital app's SQLite from the house to its site, as `sqlite_ship` builds it: the
//! site's account set up by its script on a Debian sshd, Litestream on its pinned image
//! as the app's own user pushing over SFTP, the pusher killed seconds after the last
//! write, and the promotion's step putting every row back over an older copy.
//!
//! ```sh
//! cargo test -p hlb-backup --test sqlite_ship -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{Duration, Instant};

use hlb_backup::{images, sqlite_ship, wal_ship::Target};

const NETWORK: &str = "hlb-test-sqliteship";
const SITE: &str = "hlb-test-sqliteship-site";
const SITE_IMAGE: &str = "hlb-test-sqliteship-site:latest";
const PUSHER: &str = "hlb-test-sqliteship-litestream";
/// The app's volume at home, and last night's copy of it on the site.
const HOUSE: &str = "hlb-test-sqliteship-house";
const COPY: &str = "hlb-test-sqliteship-copy";
const APP: &str = "pocket-id";
const DB: &str = "pocket-id.db";
/// PocketID's own user (its entrypoint's `PUID`).
const OWNER: &str = "1000:1000";

/// The VPS: Debian's sshd, and a `systemctl` reloading it as systemd would.
const SITE_DOCKERFILE: &str = r#"FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-server sqlite3 >/dev/null \
 && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd && ssh-keygen -A \
 && printf '#!/bin/sh\nkill -HUP "$(cat /run/sshd.pid)"\n' > /usr/local/bin/systemctl \
 && chmod 755 /usr/local/bin/systemctl
COPY --from=docker:28.5-cli /usr/local/bin/docker /usr/local/bin/docker
CMD ["/usr/sbin/sshd", "-D", "-e"]
"#;

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
        "docker {}:\n{}{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn site_sh(script: &str) -> std::process::Output {
    docker(&["exec", SITE, "sh", "-c", script])
}

/// Run against a volume, from the site's image: it has `sqlite3`.
fn on_volume(volume: &str, script: &str) -> String {
    ok(&[
        "run",
        "--rm",
        "--mount",
        &format!("type=volume,src={volume},dst=/data"),
        SITE_IMAGE,
        "sh",
        "-c",
        script,
    ])
}

fn sql(volume: &str, q: &str) -> String {
    on_volume(volume, &format!("sqlite3 /data/{DB} \"{q}\""))
}

fn until(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(
            start.elapsed() < Duration::from_secs(secs),
            "{what} after {secs} s:\n{}",
            String::from_utf8_lossy(&docker(&["logs", "--tail", "25", PUSHER]).stderr)
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn cleanup() {
    for c in [PUSHER, SITE] {
        let _ = docker(&["rm", "-f", c]);
    }
    for v in [HOUSE, COPY] {
        let _ = docker(&["volume", "rm", "-f", v]);
    }
    let _ = docker(&["network", "rm", NETWORK]);
}

#[test]
#[ignore = "needs Docker; pulls Litestream and builds a Debian sshd"]
fn the_site_restores_every_row_written_before_the_cut() {
    cleanup();
    let dir = std::env::temp_dir().join(format!("hlb-sqliteship-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let mut build = std::process::Command::new("docker")
        .args(["build", "-q", "-t", SITE_IMAGE, "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write as _;
    build
        .stdin
        .take()
        .unwrap()
        .write_all(SITE_DOCKERFILE.as_bytes())
        .unwrap();
    assert!(build.wait().unwrap().success(), "the site's image builds");

    ok(&["network", "create", NETWORK]);
    ok(&[
        "run",
        "-d",
        "--name",
        SITE,
        "--network",
        NETWORK,
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        SITE_IMAGE,
    ]);

    // The account, its chroot and the drop-in — twice: `site sync` runs it every time.
    let key = dir.join("key");
    let keygen = std::process::Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "hlb-litestream",
            "-f",
        ])
        .arg(&key)
        .status()
        .unwrap();
    assert!(keygen.success());
    let public = std::fs::read_to_string(dir.join("key.pub")).unwrap();
    let user = sqlite_ship::user(APP).unwrap();
    for round in 1..=2 {
        let out = site_sh(&sqlite_ship::site_setup_script(&user, &public));
        assert!(
            out.status.success(),
            "setup, round {round}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let root = String::from_utf8_lossy(
        &site_sh("/usr/sbin/sshd -T -C user=root,host=x,addr=127.0.0.1").stdout,
    )
    .to_string();
    assert!(
        root.contains("chrootdirectory none") && root.contains("forcecommand none"),
        "the drop-in reaches the Litestream accounts only:\n{root}"
    );

    let keys: Vec<Option<String>> = sqlite_ship::HOST_KEYS
        .iter()
        .map(|p| {
            let o = site_sh(&format!("cat {p}"));
            o.status
                .success()
                .then(|| String::from_utf8_lossy(&o.stdout).to_string())
        })
        .collect();
    let host_key =
        sqlite_ship::pinned_host_key(keys[0].as_deref(), keys[1].as_deref(), keys[2].as_deref())
            .expect("the site has a host key");

    // The app's volume at home, in WAL mode and owned by the app, as PocketID leaves it.
    ok(&["volume", "create", HOUSE]);
    on_volume(
        HOUSE,
        &format!(
            "sqlite3 /data/{DB} 'PRAGMA journal_mode=WAL; CREATE TABLE t(id INTEGER PRIMARY KEY, at TEXT);' \
             && chown -R {OWNER} /data"
        ),
    );
    let found = on_volume(HOUSE, &sqlite_ship::discover_script("/data"));
    let (owner, dbs) = sqlite_ship::parse_discovered(&found)
        .unwrap()
        .expect("a database found");
    assert_eq!((owner.as_str(), dbs.clone()), (OWNER, vec![DB.to_string()]));

    let target = Target {
        user: "root".into(),
        host: SITE.into(),
        port: 22,
    };
    let config = dir.join("litestream.yml");
    std::fs::write(&config, sqlite_ship::config(&dbs, &target, &user, host_key)).unwrap();
    ok(&[
        "run",
        "-d",
        "--name",
        PUSHER,
        "--network",
        NETWORK,
        "--user",
        OWNER,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--tmpfs",
        sqlite_ship::META,
        "--mount",
        &format!("type=volume,src={HOUSE},dst={}", sqlite_ship::MOUNTED_AT),
        "-v",
        &format!("{}:{}:ro", config.display(), sqlite_ship::CONFIG),
        "-v",
        &format!("{}:{}:ro", key.display(), sqlite_ship::KEY),
        images::LITESTREAM,
        "replicate",
        "-config",
        sqlite_ship::CONFIG,
    ]);
    let probe = sqlite_ship::site_probe_script(&user, &dbs);
    until("the site received nothing", 60, || {
        sqlite_ship::parse_site_newest(&String::from_utf8_lossy(&site_sh(&probe).stdout), DB)
            .is_some()
    });

    // Last night's copy, taken now: one row, a stale journal beside it.
    ok(&["volume", "create", COPY]);
    on_volume(
        COPY,
        &format!(
            "sqlite3 /data/{DB} 'PRAGMA journal_mode=WAL; CREATE TABLE t(id INTEGER PRIMARY KEY, at TEXT); \
             INSERT INTO t(at) VALUES (\"last night\");' && printf stale > /data/{DB}-wal && chown -R {OWNER} /data"
        ),
    );

    for i in 0..20 {
        sql(HOUSE, &format!("INSERT INTO t(at) VALUES ('row {i}')"));
        std::thread::sleep(Duration::from_millis(200));
    }
    sql(HOUSE, "INSERT INTO t(at) VALUES ('the last')");
    std::thread::sleep(Duration::from_secs(2));
    // The house goes, with no time to say anything.
    ok(&["kill", PUSHER]);

    let house = on_volume(HOUSE, &sqlite_ship::house_probe_script(&dbs));
    let site = String::from_utf8_lossy(&site_sh(&probe).stdout).to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let said = sqlite_ship::judge(
        DB,
        sqlite_ship::parse_site_newest(&house, DB),
        sqlite_ship::parse_site_newest(&site, DB),
        now,
    );
    assert_eq!(said.mark, hlb_backup::wal_ship::Mark::Fine, "{}", said.line);

    let step = sqlite_ship::promote_step(&user, COPY, &dbs, images::LITESTREAM);
    // A copy newer than the replica's last file serves as it is.
    let copied = |at: u64| sqlite_ship::copied_script(COPY, at as i64);
    let out = site_sh(&format!("set -eu; {}{step}", copied(now + 3600)));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("the copy serves"));
    assert_eq!(sql(COPY, "SELECT count(*) FROM t"), "1");

    // An older copy is replaced by the replica: every row, the stale journal gone.
    let out = site_sh(&format!("set -eu; {}{step}", copied(now - 3600)));
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "{stderr}");
    assert!(
        stdout.contains("restored from its replica"),
        "{stdout}\n{stderr}"
    );
    assert_eq!(sql(COPY, "SELECT count(*) FROM t"), "21");
    assert_eq!(
        sql(COPY, "SELECT at FROM t ORDER BY id DESC LIMIT 1"),
        "the last"
    );
    assert_eq!(sql(COPY, "PRAGMA integrity_check"), "ok");
    assert_eq!(
        on_volume(COPY, &format!("stat -c %u:%g /data/{DB}; ls /data")),
        format!("{OWNER}\n{DB}")
    );

    // Run again, the promotion keeps what the site wrote since: the replica may hold
    // the house's older database by then.
    sql(COPY, "INSERT INTO t(at) VALUES ('written on the site')");
    let again = site_sh(&format!("set -eu; {step}"));
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert!(String::from_utf8_lossy(&again.stdout).contains("kept"));
    assert_eq!(sql(COPY, "SELECT count(*) FROM t"), "22");

    // A replica that does not restore leaves the copy and never stops the promotion.
    let broken = site_sh(&format!(
        "set -eu; find {}/{DB} -name '*.ltx' -exec sh -c 'printf garbage > \"$1\"' sh {{}} \\;; {}{step}",
        sqlite_ship::site_replica(&user),
        copied(now - 3600)
    ));
    assert!(
        broken.status.success(),
        "{}",
        String::from_utf8_lossy(&broken.stderr)
    );
    assert!(String::from_utf8_lossy(&broken.stderr).contains("did not restore"));
    assert_eq!(sql(COPY, "SELECT count(*) FROM t"), "22");

    cleanup();
    let _ = std::fs::remove_dir_all(&dir);
}
