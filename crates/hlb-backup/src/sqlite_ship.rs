//! A vital app's SQLite pushed continuously to the site: Litestream beside the app, at
//! home, writing over SFTP into a directory of the VPS that only its own account reaches.
//!
//! 🔴 **Pushed, never pulled**, like the vital server's WAL (`wal_ship`). The account
//! the key opens on the VPS has no shell, no forwarding, and sees one directory: SFTP
//! only (`internal-sftp`), chrooted to its own directory (`ChrootDirectory`). A key read
//! out of the container next to PocketID can rewrite PocketID's replica and nothing else
//! of the VPS. One account per app, so it does not reach another vital app's either.
//!
//! The nightly copy stays: the lifeboat still puts last night's consistent copy on the
//! site, and the promotion replaces it with the replica only when the replica restores,
//! passes SQLite's integrity check and is newer. A replica Litestream stopped feeding a
//! week ago loses to a copy from last night.
//!
//! Measured 2026-11-11 (Litestream 0.5.18 over a chrooted `internal-sftp`, OpenSSH 9.2):
//! twenty writes, the pusher killed 1.5 s after the last, every row restored from the
//! files the site received; 18 MiB of memory idle.

use crate::sftp_account::Accounts;
use crate::wal_ship::Target;

/// Every site account of Litestream is named so, then the app: the drop-in matches them
/// all, so it is written once whatever apps come later.
pub const USER_PREFIX: &str = "hlb-ls-";

/// Where each account's chroot is, `<SITE_ROOT>/<user>`, owned by root as sshd demands.
pub const SITE_ROOT: &str = "/var/lib/homelabus-site/litestream";

/// The one directory an account may write, inside its chroot.
pub const REPLICA: &str = "replica";

/// The drop-in confining every Litestream account. Debian's `sshd_config` includes
/// `sshd_config.d/*.conf` before its own lines, and a `Match` block in an included file
/// ends with that file (OpenSSH 9.2, checked with `sshd -T -C user=root`).
pub const DROP_IN: &str = "/etc/ssh/sshd_config.d/hlb-litestream.conf";

/// Each account's public key, `<KEYS_DIR>/<user>.pub`: root's, outside the chroot, so
/// the account cannot add a key of its own.
pub const KEYS_DIR: &str = "/etc/ssh/hlb-litestream";

/// Litestream's accounts on the site.
pub const ACCOUNTS: Accounts = Accounts {
    prefix: USER_PREFIX,
    site_root: SITE_ROOT,
    writable: REPLICA,
    drop_in: DROP_IN,
    keys_dir: KEYS_DIR,
    tool: "Litestream",
};

/// Where Litestream finds what it needs, inside its container at home.
pub const MOUNTED_AT: &str = "/data";
pub const CONFIG: &str = "/etc/litestream.yml";
pub const KEY: &str = "/run/secrets/hlb-litestream-key";
/// Litestream's own position, in memory: kept in the app's volume, it would travel with
/// the nightly copy to the site and come home with the return, describing a database
/// that is no longer the one there. Lost at a restart, Litestream reads the replica's
/// position again (measured: "detected database behind replica", then on).
pub const META: &str = "/meta";

/// When the lifeboat put an app's volume on the site, `<COPIED_DIR>/<volume>`: seconds
/// since the epoch of the backup it came from — what the replica must be newer than.
pub const COPIED_DIR: &str = "/etc/hlb/site/sqlite-copied";

/// Beside [`COPIED_DIR`]'s mark, `<volume>-<database><DECIDED>`: the promotion already
/// chose between the replica and the copy. The lifeboat removes it with each new copy.
pub const DECIDED: &str = ".promoted";

/// Run on the site by the lifeboat once it put `volume` there: when the backup it came
/// from was taken, and the next promotion free to choose again.
pub fn copied_script(volume: &str, taken: i64) -> String {
    format!(
        "mkdir -p {COPIED_DIR} && echo {taken} > {COPIED_DIR}/{volume} && rm -f {COPIED_DIR}/{volume}-*{DECIDED}\n"
    )
}

/// The site account of `app`'s Litestream. An error when the name would not fit Linux.
pub fn user(app: &str) -> Result<String, String> {
    ACCOUNTS.user(app)
}

/// Where `app`'s replica lands on the site, as root sees it.
pub fn site_replica(user: &str) -> String {
    ACCOUNTS.writable_dir(user)
}

/// The drop-in itself. `%u` names the account connecting, so one block serves every app.
pub fn drop_in() -> String {
    ACCOUNTS.drop_in()
}

/// Run as root on the site: the account, its chroot, its key and the drop-in, checked
/// before the reload and proved after ([`Accounts::setup_script`]).
pub fn site_setup_script(user: &str, public_key: &str) -> String {
    ACCOUNTS.setup_script(user, public_key)
}

/// The host key Litestream will be shown, of those the site has. Go's SSH client asks
/// for ECDSA first, then RSA, then ed25519 (`golang.org/x/crypto` 0.58), and Litestream
/// pins ONE key: pinned to the ed25519 key of a server that also has an ECDSA one, it
/// refused every connection ("host key mismatch", measured).
pub fn pinned_host_key<'a>(
    ecdsa: Option<&'a str>,
    rsa: Option<&'a str>,
    ed25519: Option<&'a str>,
) -> Option<&'a str> {
    [ecdsa, rsa, ed25519]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|k| !k.is_empty())
}

/// The site's host key files, in [`pinned_host_key`]'s order.
pub const HOST_KEYS: [&str; 3] = crate::sftp_account::HOST_KEYS;

/// Litestream's configuration: each database of the volume, by its path in it, to the
/// same path under the replica.
///
/// 🔴 `host-key` is never left out: without it Litestream accepts whatever key answers
/// (`ssh.InsecureIgnoreHostKey`, read in its `sftp/replica_client.go`).
pub fn config(databases: &[String], t: &Target, user: &str, host_key: &str) -> String {
    let mut fields = host_key.split_whitespace();
    let pinned = format!(
        "{} {}",
        fields.next().unwrap_or_default(),
        fields.next().unwrap_or_default()
    );
    let mut s = String::from("# Generated by Homelabus - do not edit by hand.\ndbs:\n");
    for db in databases {
        s.push_str(&format!(
            r#"  - path: {MOUNTED_AT}/{db}
    meta-path: {META}/{meta}
    replica:
      type: sftp
      host: "{host}:{port}"
      user: {user}
      key-path: {KEY}
      host-key: "{pinned}"
      path: /{REPLICA}/{db}
"#,
            meta = db.replace('/', "__") + "-litestream",
            host = t.host,
            port = t.port,
        ));
    }
    s
}

/// Run in the app's own container: each SQLite database under `mount` — by its header,
/// as the backup pass finds them — with its owner, `<uid> <gid> <path in the volume>`.
pub fn discover_script(mount: &str) -> String {
    let mount = mount.trim_end_matches('/');
    format!(
        r#"cd {mount} || exit 1
find . -type f \( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \) | sort |
while read -r f; do
    [ "$(head -c 15 "$f" 2>/dev/null)" = "SQLite format 3" ] || continue
    echo "$(stat -c '%u %g' "$f") ${{f#./}}"
done
"#
    )
}

/// The databases a volume holds, and who owns them. An error when they are owned by
/// several: Litestream runs as one, and creates what it opens as that one.
pub fn parse_discovered(out: &str) -> Result<Option<(String, Vec<String>)>, String> {
    let mut owner: Option<String> = None;
    let mut dbs = Vec::new();
    for l in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let mut f = l.splitn(3, ' ');
        let (Some(uid), Some(gid), Some(path)) = (f.next(), f.next(), f.next()) else {
            return Err(format!("unreadable line {l:?}"));
        };
        if uid.parse::<u32>().is_err() || gid.parse::<u32>().is_err() {
            return Err(format!("unreadable owner in {l:?}"));
        }
        let o = format!("{uid}:{gid}");
        match &owner {
            Some(prev) if *prev != o => {
                return Err(format!("its databases belong to {prev} and {o}"));
            }
            _ => owner = Some(o),
        }
        dbs.push(path.to_string());
    }
    Ok(owner.map(|o| (o, dbs)))
}

/// The promotion's step before the app starts on the site: each database of `volume`
/// restored from its replica over last night's copy — when the replica holds something,
/// is newer than that copy, restores and passes the integrity check. Otherwise the copy
/// serves, and the reason is said. Never stops the promotion: the night it runs, a copy
/// a day old serves better than nothing.
///
/// 🔴 The copy's `-wal` and `-shm` go with it: a WAL left beside a database it was not
/// written for is replayed into it at the next open.
///
/// 🔴 Decided once per promotion ([`DECIDED`]): a house back up while the site serves
/// starts its Litestream, which pushes the house's own, older database as the replica's
/// newest state; a promotion run again would put that over what the site wrote since.
pub fn promote_step(user: &str, volume: &str, databases: &[String], image: &str) -> String {
    let replica = site_replica(user);
    let mut s = String::new();
    for db in databases {
        s.push_str(&format!(
            r#"from_replica {volume} {replica} {db}
"#
        ));
    }
    format!(
        r#"from_replica() {{
    vol=$1; rep=$2; db=$3
    done="{COPIED_DIR}/$vol-$(printf %s "$db" | tr / _){DECIDED}"
    if [ -f "$done" ]; then
        echo "  ✓ $db: put in place by this promotion's first run, kept"
        return 0
    fi
    # Marked once the choice is carried out, never before: a run cut mid-restore (an
    # image still downloading) chooses again, nothing having started on the copy yet.
    decided() {{ mkdir -p {COPIED_DIR} && : > "$done"; }}
    newest=$(find "$rep/$db" -name '*.ltx' -printf '%T@\n' 2>/dev/null | sort -n | tail -n 1 | cut -d. -f1)
    copied=$(cat {COPIED_DIR}/"$vol" 2>/dev/null || echo 0)
    if [ -z "$newest" ]; then
        echo "  ⚠️  $db: the site never received its replica: last night's copy serves" >&2
        decided
        return 0
    fi
    if [ "$newest" -le "$copied" ]; then
        echo "  ⚠️  $db: its replica stops at $(date -u -d "@$newest" +%H:%M), before last night's copy: the copy serves" >&2
        decided
        return 0
    fi
    # Streamed in rather than mounted: the replica's directory is its account's, 0700,
    # and the restoring container needs no capability to read it.
    if tar -C "$rep" -cf - "$db" | docker run --rm -i --network none --read-only \
        --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
        --tmpfs /tmp --mount "type=volume,src=$vol,dst={MOUNTED_AT}" \
        --entrypoint sh {image} -c '
            set -eu
            mkdir /tmp/replica
            tar -xf - -C /tmp/replica
            db={MOUNTED_AT}/$1
            out="$(dirname "$db")/.$(basename "$db").replica"
            rm -f "$out" "$out-wal" "$out-shm"
            litestream restore -integrity-check full -o "$out" "file:///tmp/replica/$1" >&2
            owner=$(stat -c %u:%g "$db" 2>/dev/null || stat -c %u:%g "$(dirname "$db")")
            rm -f "$db-wal" "$db-shm"
            chown "$owner" "$out"
            mv -f "$out" "$db"' sh "$db"; then
        echo "  ✓ $db: restored from its replica, written to $(date -u -d "@$newest" +%H:%M:%S) UTC"
    else
        echo "  🔴 $db: its replica did not restore: last night's copy serves" >&2
    fi
    decided
}}
{s}"#
    )
}

/// Run on the site: the newest file each database's replica holds, `<db>=<epoch>`
/// lines, empty when none — read by [`parse_site_newest`].
pub fn site_probe_script(user: &str, databases: &[String]) -> String {
    let replica = site_replica(user);
    databases
        .iter()
        .map(|db| {
            format!(
                "echo \"{db}=$(find {replica}/{db} -name '*.ltx' -printf '%T@\\n' 2>/dev/null | sort -n | tail -n 1 | cut -d. -f1)\"\n"
            )
        })
        .collect()
}

pub fn parse_site_newest(out: &str, db: &str) -> Option<u64> {
    out.lines()
        .find_map(|l| l.strip_prefix(db)?.strip_prefix('='))
        .and_then(|v| v.trim().parse().ok())
}

/// Run in Litestream's container at home: when each database was last written, the
/// newest of it and its WAL — `<db>=<epoch>` lines.
pub fn house_probe_script(databases: &[String]) -> String {
    databases
        .iter()
        .map(|db| {
            format!(
                "echo \"{db}=$(stat -c %Y {MOUNTED_AT}/{db} {MOUNTED_AT}/{db}-wal 2>/dev/null | sort -n | tail -n 1)\"\n"
            )
        })
        .collect()
}

/// How far behind the house the replica may be before it is said late: Litestream
/// pushes every second, and checkpoints — which touch the database without a new write —
/// every minute.
pub const LATE_AFTER_S: u64 = 300;

/// A database's replica, judged: when the house last wrote it (`None`: unread) and the
/// newest file the site holds of it (`None`: none).
pub fn judge(db: &str, house: Option<u64>, site: Option<u64>, now: u64) -> crate::wal_ship::Said {
    use crate::wal_ship::{Mark, Said};
    let say = |mark, line| Said { mark, line };
    match (house, site) {
        (_, None) => say(
            Mark::Fault,
            format!("SQLite — {db}: the site holds no replica of it"),
        ),
        (None, Some(s)) => say(
            Mark::Unknown,
            format!(
                "SQLite — {db}: replica written {} s ago; the house's own could not be read",
                now.saturating_sub(s)
            ),
        ),
        (Some(h), Some(s)) if h > s + LATE_AFTER_S => say(
            Mark::Fault,
            format!(
                "SQLite — {db}: written at home {} s after its replica's newest file: \
                 Litestream does not reach the site",
                h - s
            ),
        ),
        (Some(_), Some(s)) => say(
            Mark::Fine,
            format!(
                "SQLite — {db}: replica up to date, newest file {} s old",
                now.saturating_sub(s)
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            user: "root".into(),
            host: "203.0.113.7".into(),
            port: 22,
        }
    }

    #[test]
    fn every_app_gets_an_account_of_its_own_within_linux_s_limit() {
        assert_eq!(user("pocket-id").expect("fits"), "hlb-ls-pocket-id");
        assert!(user(&"a".repeat(26)).is_err());
    }

    #[test]
    fn the_drop_in_confines_every_account_to_sftp_in_its_own_directory() {
        let d = drop_in();
        for line in [
            "Match User hlb-ls-*",
            "ChrootDirectory /var/lib/homelabus-site/litestream/%u",
            "ForceCommand internal-sftp -d /replica",
            "AuthorizedKeysFile /etc/ssh/hlb-litestream/%u.pub",
            "AllowTcpForwarding no",
            "PermitTTY no",
        ] {
            assert!(d.contains(line), "{line} missing from\n{d}");
        }
    }

    #[test]
    fn the_drop_in_is_checked_before_the_reload_and_proved_after() {
        let s = site_setup_script("hlb-ls-pocket-id", "ssh-ed25519 AAAA hlb-litestream");
        let check = s.find("sshd -t").expect("checked");
        let reload = s.find("systemctl reload").expect("reloaded");
        let proof = s.find("sshd -T -C").expect("proved");
        assert!(check < reload && reload < proof, "{s}");
        assert!(
            s.contains("'restrict ssh-ed25519 AAAA hlb-litestream'"),
            "{s}"
        );
        assert!(s.contains(&format!("cat > {DROP_IN}.new <<'HLB_EOF'\n# Generated")));
    }

    #[test]
    fn the_host_key_pinned_is_the_one_go_asks_for_first() {
        assert_eq!(
            pinned_host_key(
                Some("ecdsa-sha2-nistp256 E h"),
                None,
                Some("ssh-ed25519 D h")
            ),
            Some("ecdsa-sha2-nistp256 E h")
        );
        assert_eq!(
            pinned_host_key(None, Some("ssh-rsa R h"), Some("ssh-ed25519 D h")),
            Some("ssh-rsa R h")
        );
        assert_eq!(
            pinned_host_key(None, None, Some("ssh-ed25519 D h")),
            Some("ssh-ed25519 D h")
        );
        assert_eq!(pinned_host_key(Some(" "), None, None), None);
    }

    #[test]
    fn the_config_always_pins_the_site_s_host_key() {
        let c = config(
            &["pocket-id.db".into()],
            &target(),
            "hlb-ls-pocket-id",
            "ecdsa-sha2-nistp256 AAAAE2 root@vps\n",
        );
        assert!(
            c.contains("host-key: \"ecdsa-sha2-nistp256 AAAAE2\""),
            "{c}"
        );
        assert!(c.contains("path: /data/pocket-id.db"), "{c}");
        assert!(c.contains("path: /replica/pocket-id.db"), "{c}");
        assert!(c.contains("meta-path: /meta/"), "{c}");
        assert!(c.contains("host: \"203.0.113.7:22\""), "{c}");
    }

    #[test]
    fn a_volume_s_databases_are_read_with_their_one_owner() {
        assert_eq!(
            parse_discovered("1000 1000 pocket-id.db\n").expect("read"),
            Some(("1000:1000".into(), vec!["pocket-id.db".into()]))
        );
        assert_eq!(parse_discovered("").expect("read"), None);
        assert!(parse_discovered("1000 1000 a.db\n0 0 b.db\n").is_err());
        assert!(parse_discovered("x 1000 a.db\n").is_err());
    }

    #[test]
    fn the_promotion_drops_the_copy_s_wal_and_never_stops_on_a_bad_replica() {
        let s = promote_step(
            "hlb-ls-pocket-id",
            "pocket-id-data",
            &["pocket-id.db".into()],
            "litestream/litestream:x",
        );
        assert!(s.contains("rm -f \"$db-wal\" \"$db-shm\""), "{s}");
        assert!(s.contains("-integrity-check full"), "{s}");
        assert!(s.contains("--network none"), "{s}");
        assert!(
            s.contains("from_replica pocket-id-data /var/lib/homelabus-site/litestream/hlb-ls-pocket-id/replica pocket-id.db"),
            "{s}"
        );
        // Under the promotion's `set -e`, a failed restore is an `if`'s condition.
        assert!(
            s.contains("if tar -C \"$rep\" -cf - \"$db\" | docker run"),
            "{s}"
        );
        assert!(!s.contains("exit"), "{s}");
        // Marked decided once the restore ran, never before: a run cut while the image
        // downloaded kept last night's copy for good on the lab.
        let restore = s.find("if tar -C").expect("restore");
        assert!(s.find("decided()").expect("defined") < restore, "{s}");
        assert!(s.rfind("    decided\n").expect("marked") > restore, "{s}");
    }

    #[test]
    fn a_replica_is_late_when_the_house_wrote_well_after_its_newest_file() {
        use crate::wal_ship::Mark;
        assert_eq!(judge("a.db", Some(1000), Some(990), 2000).mark, Mark::Fine);
        assert_eq!(
            judge("a.db", Some(2000), Some(1000), 2000).mark,
            Mark::Fault
        );
        assert_eq!(judge("a.db", None, Some(1000), 2000).mark, Mark::Unknown);
        assert_eq!(judge("a.db", Some(1000), None, 2000).mark, Mark::Fault);
    }

    #[test]
    fn the_probes_read_back_what_they_print() {
        assert_eq!(
            parse_site_newest("a.db=1700000000\nb.db=\n", "a.db"),
            Some(1_700_000_000)
        );
        assert_eq!(parse_site_newest("a.db=1700000000\nb.db=\n", "b.db"), None);
        assert!(site_probe_script("hlb-ls-x", &["a.db".into()])
            .contains("/var/lib/homelabus-site/litestream/hlb-ls-x/replica/a.db"));
        assert!(house_probe_script(&["a.db".into()]).contains("/data/a.db-wal"));
    }
}
