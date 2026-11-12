//! A vital app's volume from the house to its site, as `volume_ship` builds it: the
//! site's account set up by its script on a Debian sshd, rclone on its pinned image
//! pushing the volume's files over SFTP — its SQLite left to Litestream —, a second
//! round after the house changed them, and the promotion's step laying them over an
//! older copy with their owners and modes, sparing every SQLite file.
//!
//! ```sh
//! cargo test -p hlb-backup --test volume_ship -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::{Duration, Instant};

use hlb_backup::wal_ship::{Mark, Target};
use hlb_backup::{images, sqlite_ship, volume_ship};

const NETWORK: &str = "hlb-test-volumeship";
const SITE: &str = "hlb-test-volumeship-site";
const SITE_IMAGE: &str = "hlb-test-volumeship-site:latest";
const PUSHER: &str = "hlb-test-volumeship-rclone";
/// The app's volume at home, and last night's copy of it on the site.
const HOUSE: &str = "hlb-test-volumeship-house";
const COPY: &str = "hlb-test-volumeship-copy";
const VOLUME: &str = "vaultwarden-data";

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

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `<owner> <mode> <content or "-">` of each path, for comparing two volumes.
fn listing(volume: &str) -> String {
    on_volume(
        volume,
        "cd /data && find . | LC_ALL=C sort | while IFS= read -r p; do \
         c=-; [ -f \"$p\" ] && [ ! -L \"$p\" ] && c=$(head -c 40 \"$p\" | tr -d '\\0' | tr '\\n' ' '); \
         echo \"$p $(stat -c '%u:%g %a' \"$p\") $c\"; done",
    )
}

#[test]
#[ignore = "needs Docker; pulls rclone and builds a Debian sshd"]
fn the_site_lays_the_house_s_files_over_an_older_copy_and_spares_sqlite() {
    cleanup();
    let dir = std::env::temp_dir().join(format!("hlb-volumeship-{}", std::process::id()));
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
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "hlb-volume", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(keygen.success());
    let public = std::fs::read_to_string(dir.join("key.pub")).unwrap();
    let user = volume_ship::user(VOLUME).unwrap();
    for round in 1..=2 {
        let out = site_sh(&volume_ship::ACCOUNTS.setup_script(&user, &public));
        assert!(
            out.status.success(),
            "setup, round {round}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // Litestream's drop-in beside it: each family reaches its own accounts only.
    let ls = sqlite_ship::user("pocket-id").unwrap();
    let out = site_sh(&sqlite_ship::site_setup_script(&ls, &public));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let applied = |u: &str| {
        String::from_utf8_lossy(
            &site_sh(&format!(
                "/usr/sbin/sshd -T -C user={u},host=x,addr=127.0.0.1"
            ))
            .stdout,
        )
        .to_string()
    };
    assert!(applied(&user).contains("chrootdirectory /var/lib/homelabus-site/volumes/%u"));
    assert!(applied(&ls).contains("chrootdirectory /var/lib/homelabus-site/litestream/%u"));
    assert!(applied("root").contains("chrootdirectory none"));

    let keys: Vec<Option<String>> = sqlite_ship::HOST_KEYS
        .iter()
        .map(|p| {
            let o = site_sh(&format!("cat {p}"));
            o.status
                .success()
                .then(|| String::from_utf8_lossy(&o.stdout).to_string())
        })
        .collect();
    let host_keys = volume_ship::host_keys(&keys);
    assert!(!host_keys.is_empty());

    // The volume at home as Vaultwarden leaves it — an attachment of the app's user in
    // a 0700 directory, a key root's 0600 — plus a SQLite database in WAL mode, a file
    // about to be deleted and a link.
    ok(&["volume", "create", HOUSE]);
    on_volume(
        HOUSE,
        "set -e; cd /data; mkdir -p attachments/a; echo first > attachments/a/f1; \
         chown -R 1000:1000 attachments; chmod 700 attachments/a; \
         echo secret > rsa_key.pem; chmod 600 rsa_key.pem; echo bye > doomed; \
         ln -s rsa_key.pem link; chmod 750 /data; \
         sqlite3 db.sqlite3 'PRAGMA journal_mode=WAL; CREATE TABLE t(x); INSERT INTO t VALUES (1);'",
    );

    let target = Target {
        user: String::new(),
        host: SITE.into(),
        port: 22,
    };
    let mut run = vec![
        "run".to_string(),
        "-d".into(),
        "--name".into(),
        PUSHER.into(),
        "--network".into(),
        NETWORK.into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--cap-add".into(),
        "DAC_READ_SEARCH".into(),
        "--tmpfs".into(),
        volume_ship::SCRATCH.into(),
        "--mount".into(),
        format!(
            "type=volume,src={HOUSE},dst={},readonly",
            volume_ship::MOUNTED_AT
        ),
        "-v".into(),
        format!("{}:{}:ro", key.display(), volume_ship::KEY),
    ];
    for (k, v) in volume_ship::env(&target, &user, &host_keys) {
        run.push("-e".into());
        run.push(format!("{k}={v}"));
    }
    run.extend([
        "--entrypoint".into(),
        "sh".into(),
        images::RCLONE.into(),
        "-c".into(),
        volume_ship::push_script(),
    ]);
    ok(&run.iter().map(String::as_str).collect::<Vec<_>>());

    let probe = volume_ship::site_probe_script(std::slice::from_ref(&user));
    let pushed =
        || volume_ship::parse_probe(&String::from_utf8_lossy(&site_sh(&probe).stdout), &user);
    until("the site received no round", 60, || pushed().is_some());
    let first = pushed().unwrap();
    let tree = String::from_utf8_lossy(
        &site_sh(&format!(
            "cd {}/files && find . | sort",
            volume_ship::site_dir(&user)
        ))
        .stdout,
    )
    .to_string();
    assert!(
        tree.contains("./attachments/a/f1") && tree.contains("./rsa_key.pem"),
        "{tree}"
    );
    assert!(
        !tree.contains("db.sqlite3"),
        "SQLite is Litestream's:\n{tree}"
    );
    assert!(!tree.contains("./link"), "links are not pushed:\n{tree}");

    // The house changes: one attachment rewritten, one added, a file deleted, a row
    // written. A restart is a round at once.
    on_volume(
        HOUSE,
        "set -e; cd /data; echo second > attachments/a/f1; echo new > attachments/a/f2; \
         chown 1000:1000 attachments/a/f2; chmod 640 attachments/a/f2; rm doomed; \
         sqlite3 db.sqlite3 'INSERT INTO t VALUES (2);'",
    );
    std::thread::sleep(Duration::from_millis(1100));
    ok(&["restart", "-t", "1", PUSHER]);
    until("no second round", 60, || {
        pushed().is_some_and(|p| p > first)
    });
    // The house goes.
    ok(&["kill", PUSHER]);

    let site = String::from_utf8_lossy(&site_sh(&probe).stdout).to_string();
    let said = volume_ship::judge(
        VOLUME,
        volume_ship::parse_probe(&site, &user),
        volume_ship::parse_probe(&site, &format!("{user}.bytes")),
        true,
        now(),
    );
    assert_eq!(said.mark, Mark::Fine, "{}", said.line);

    // Last night's copy: the old attachment, the doomed file, a file and a directory
    // the house never had since, the key's mode wrong, its own database and journal.
    ok(&["volume", "create", COPY]);
    on_volume(
        COPY,
        "set -e; cd /data; mkdir -p attachments/a olddir/sub; echo first > attachments/a/f1; \
         echo bye > doomed; echo stale > olddir/sub/x; echo secret > rsa_key.pem; chmod 644 rsa_key.pem; \
         ln -s rsa_key.pem link; sqlite3 db.sqlite3 'PRAGMA journal_mode=WAL; CREATE TABLE t(x); \
         INSERT INTO t VALUES (1);' && printf stale > db.sqlite3-wal",
    );
    let before = listing(COPY);

    let step = volume_ship::promote_step(&user, COPY, images::RCLONE);
    let copied = |at: u64| sqlite_ship::copied_script(COPY, at as i64);
    // A copy newer than the last round serves as it is.
    let out = site_sh(&format!("set -eu; {}{step}", copied(now() + 3600)));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("the copy serves"));
    assert_eq!(listing(COPY), before);

    // An older one gets the house's files, owners and modes; SQLite untouched.
    let out = site_sh(&format!("set -eu; {}{step}", copied(now() - 3600)));
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "{stderr}");
    assert!(
        stdout.contains("laid over last night's copy"),
        "{stdout}\n{stderr}"
    );
    let after = listing(COPY);
    let line = |p: &str| {
        after
            .lines()
            .find(|l| l.split(' ').next() == Some(p))
            .unwrap_or_else(|| panic!("{p} missing from\n{after}"))
            .trim_end()
            .to_string()
    };
    assert_eq!(line("."), ". 0:0 750 -");
    assert_eq!(line("./attachments/a"), "./attachments/a 1000:1000 700 -");
    assert_eq!(
        line("./attachments/a/f1"),
        "./attachments/a/f1 1000:1000 644 second"
    );
    assert_eq!(
        line("./attachments/a/f2"),
        "./attachments/a/f2 1000:1000 640 new"
    );
    assert_eq!(line("./rsa_key.pem"), "./rsa_key.pem 0:0 600 secret");
    for gone in ["./doomed", "./olddir", "./olddir/sub/x"] {
        assert!(
            !after.lines().any(|l| l.split(' ').next() == Some(gone)),
            "{gone} stays:\n{after}"
        );
    }
    // The copy's database and its journal, for Litestream's step to replace.
    assert!(after.contains("./db.sqlite3 "), "{after}");
    assert!(after.contains("./db.sqlite3-wal 0:0 644 stale"), "{after}");
    assert!(after.contains("./link "), "{after}");

    // Run again, the promotion keeps what the site wrote since.
    on_volume(COPY, "echo on-the-site > /data/attachments/a/f1");
    let again = site_sh(&format!("set -eu; {step}"));
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert!(String::from_utf8_lossy(&again.stdout).contains("kept"));
    assert_eq!(on_volume(COPY, "cat /data/attachments/a/f1"), "on-the-site");

    // A push whose owners never arrived leaves the copy, and never stops the promotion.
    let half = site_sh(&format!(
        "set -eu; rm {}/owners; {}{step}",
        volume_ship::site_dir(&user),
        copied(now() - 3600)
    ));
    assert!(
        half.status.success(),
        "{}",
        String::from_utf8_lossy(&half.stderr)
    );
    assert!(String::from_utf8_lossy(&half.stderr).contains("never received a whole push"));
    assert_eq!(on_volume(COPY, "cat /data/attachments/a/f1"), "on-the-site");

    // A push of an empty volume — a name mounted fresh on the wrong node — never empties
    // the copy.
    let empty = site_sh(&format!(
        "set -eu; d={}; mkdir -p $d/files; echo '0:0 755 .' > $d/owners; {}{step}",
        volume_ship::site_dir(&user),
        copied(now() - 3600)
    ));
    assert!(
        empty.status.success(),
        "{}",
        String::from_utf8_lossy(&empty.stderr)
    );
    assert!(String::from_utf8_lossy(&empty.stderr).contains("pushed it empty"));
    assert_eq!(on_volume(COPY, "cat /data/attachments/a/f1"), "on-the-site");

    cleanup();
    let _ = std::fs::remove_dir_all(&dir);
}
