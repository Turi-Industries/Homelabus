//! A vital app's volume pushed to the site every minute, what changed only: rclone
//! beside the volume at home, writing over SFTP into a directory of the VPS that only
//! its own account reaches (`sftp_account`), as Litestream does for SQLite.
//!
//! What is pushed is a tree of files, never a database: every SQLite file found in the
//! volume by its header is left out, with its journals — Litestream carries it
//! (`sqlite_ship`), and a copy of its pages taken one after another restores nothing.
//! A volume whose files only make sense together (`copy: stopped`, an engine's) is not
//! pushed at all: the nightly copy alone carries it.
//!
//! SFTP keeps no owner: the files land as the account's on the VPS. Each round lists
//! every path's owner and mode beside them (`owners`), and the promotion puts those
//! back once the files are in the volume.
//!
//! The nightly copy stays: the promotion lays the pushed files over it only when the
//! last round that went through started after that copy's backup was taken, and once
//! per promotion (a house back up while the site serves pushes its own, older files).
//!
//! Measured 2026-11-12 (rclone 1.75.2, OpenSSH 9.2 `internal-sftp` chrooted): a second
//! round over an unchanged volume transfers nothing; a host key the account does not
//! pin is refused ("host key mismatch").

use crate::sftp_account::Accounts;
use crate::sqlite_ship::{COPIED_DIR, DECIDED};
use crate::wal_ship::{Mark, Said, Target};

/// The volumes' accounts on the site, one per volume: `hlb-vol-<volume>`, also the
/// pusher's service at home.
pub const ACCOUNTS: Accounts = Accounts {
    prefix: "hlb-vol-",
    site_root: "/var/lib/homelabus-site/volumes",
    writable: PUSH,
    drop_in: "/etc/ssh/sshd_config.d/hlb-volumes.conf",
    keys_dir: "/etc/ssh/hlb-volumes",
    tool: "rclone",
};

/// The one directory an account writes, inside its chroot, and what it holds: the
/// volume's tree, its owners, and when the last round began.
pub const PUSH: &str = "push";
const FILES: &str = "files";
const OWNERS: &str = "owners";
const PUSHED: &str = "pushed";

/// Where the pusher finds what it needs, inside its container at home.
pub const MOUNTED_AT: &str = "/data";
pub const KEY: &str = "/run/secrets/hlb-volume-key";
/// Its only writable place: the lists, rclone's empty configuration.
pub const SCRATCH: &str = "/tmp";

/// A round every minute, as the owner decided (2026-11-10).
pub const INTERVAL_S: u64 = 60;

/// How long since the last round's start before `site status` says the pushes stopped:
/// a round of a large change takes its time, three missed are a fault.
pub const LATE_AFTER_S: u64 = 300;

/// The account and the pusher of `volume`. An error when the name would not fit Linux.
pub fn user(volume: &str) -> Result<String, String> {
    ACCOUNTS.user(volume)
}

/// Where `user`'s pushes land on the site, as root sees it.
pub fn site_dir(user: &str) -> String {
    ACCOUNTS.writable_dir(user)
}

/// The site's host keys as rclone pins them, `<algorithm> <base64>`: every one the site
/// has, so whichever the client is offered is checked.
pub fn host_keys(files: &[Option<String>]) -> Vec<String> {
    files
        .iter()
        .flatten()
        .filter_map(|k| {
            let mut f = k.split_whitespace();
            Some(format!("{} {}", f.next()?, f.next()?))
        })
        .collect()
}

/// The pusher's remote, `site:`, given to rclone by its environment: no configuration
/// file holds the host or the key's path.
///
/// 🔴 `HOST_KEYS` is never empty: without it rclone accepts whatever key answers. The
/// caller refuses a site with none.
pub fn env(t: &Target, user: &str, host_keys: &[String]) -> Vec<(String, String)> {
    [
        ("TYPE", "sftp".to_string()),
        ("HOST", t.host.clone()),
        ("PORT", t.port.to_string()),
        ("USER", user.to_string()),
        ("KEY_FILE", KEY.to_string()),
        // `internal-sftp` runs no command: rclone asks for none, and hashes nothing.
        ("SHELL_TYPE", "none".to_string()),
        ("DISABLE_HASHCHECK", "true".to_string()),
        ("HOST_KEYS", host_keys.join(",")),
    ]
    .into_iter()
    .map(|(k, v)| (format!("RCLONE_CONFIG_SITE_{k}"), v))
    .chain([(
        "RCLONE_CONFIG".to_string(),
        format!("{SCRATCH}/rclone.conf"),
    )])
    .collect()
}

/// Shell functions of the pusher, in the current directory: the SQLite files found by
/// their header, as the backup pass finds them, and each as the anchored patterns that
/// leave it and its journals out of a sync — escaped, a `[` in a name being a glob.
/// An `if`, never `[ … ] && printf`: a last file that is no database would end the
/// loop on 1, `find` would pass it on, and every round of Vaultwarden's volume — no
/// SQLite in it — failed on the lab.
fn sqlite_functions() -> &'static str {
    r#"sqlite_here() {
    find . -type f ! -name '*.partial' -exec sh -c '
        for f; do
            if [ "$(head -c 15 "$f" 2>/dev/null)" = "SQLite format 3" ]; then printf "%s\n" "${f#.}"; fi
        done' sh {} +
}
as_patterns() {
    sed 's/[][*?{}\\]/\\&/g' | while IFS= read -r p; do
        printf '%s\n%s-wal\n%s-shm\n%s-journal\n' "$p" "$p" "$p" "$p"
    done
}
"#
}

/// The pusher's loop, run by `sh` in rclone's image with the volume read-only at
/// [`MOUNTED_AT`]. A round: the SQLite files listed and left out, what changed sent
/// (rclone compares size and time, and renames a file into place once whole), every
/// path's owner and mode listed after, and the round's start written last — a round
/// cut short leaves the previous one's time, older than what it sent.
///
/// Symbolic links are not pushed (`--skip-links`): over SFTP rclone would make each a
/// file of its own; the copy's stay.
pub fn push_script() -> String {
    let sqlite = sqlite_functions();
    format!(
        r#"set -u
: > "$RCLONE_CONFIG"
cd {MOUNTED_AT} || exit 1
{sqlite}
flags="--skip-links --contimeout 15s --timeout 60s --retries 1 --low-level-retries 3 --checkers 4 --transfers 2"
round() {{
    sqlite_here > {SCRATCH}/sqlite || return 1
    as_patterns < {SCRATCH}/sqlite > {SCRATCH}/excluded || return 1
    rclone sync . site:/{PUSH}/{FILES} $flags --exclude-from {SCRATCH}/excluded || return 1
    # After the files: what the sync sent is still here to be listed.
    find . -exec stat -c '%u:%g %a %n' {{}} + > {SCRATCH}/{OWNERS} || return 1
    rclone copyto {SCRATCH}/{OWNERS} site:/{PUSH}/{OWNERS} $flags || return 1
    echo "$1" > {SCRATCH}/{PUSHED}
    rclone copyto {SCRATCH}/{PUSHED} site:/{PUSH}/{PUSHED} $flags
}}
while :; do
    start=$(date +%s)
    round "$start" || echo "the round of $(date -u -d "@$start" +%H:%M:%S) did not reach the site" >&2
    left=$((start + {INTERVAL_S} - $(date +%s)))
    [ "$left" -le 0 ] || sleep "$left"
done
"#
    )
}

/// The decision's mark beside the copy's: `<volume>-files.promoted`, which the
/// lifeboat's [`crate::sqlite_ship::copied_script`] removes with each new copy.
fn decided_mark(volume: &str) -> String {
    format!("{COPIED_DIR}/{volume}-files{DECIDED}")
}

/// Run in the volume, its owners list on standard input: every path the house no
/// longer has deleted — children first, a directory only once empty — and every
/// listed one given its owner and mode. Held to no single quote: it is one argument.
///
/// 🔴 A SQLite file or one of its journals is never deleted, the copy's as much as one
/// the house dropped: Litestream's step puts each back from its replica, and the push
/// never carried any, so every one would read as gone.
fn settle_script() -> String {
    format!(
        r#"set -eu
cd {MOUNTED_AT}
cat > {SCRATCH}/{OWNERS}
is_sqlite() {{ [ -f "$1" ] && [ "$(head -c 15 "$1" 2>/dev/null)" = "SQLite format 3" ]; }}
kept() {{
    for base in "$1" "${{1%-wal}}" "${{1%-shm}}" "${{1%-journal}}"; do
        if is_sqlite "$base"; then return 0; fi
    done
    return 1
}}
sed "s/^[^ ]* [^ ]* //" {SCRATCH}/{OWNERS} | LC_ALL=C sort > {SCRATCH}/listed
find . -mindepth 1 | LC_ALL=C sort > {SCRATCH}/here
LC_ALL=C comm -13 {SCRATCH}/listed {SCRATCH}/here | LC_ALL=C sort -r | while IFS= read -r p; do
    if [ -d "$p" ] && [ ! -L "$p" ]; then rmdir "$p" 2>/dev/null || true
    elif ! kept "$p"; then rm -f "$p"
    fi
done
while IFS= read -r line; do
    own=${{line%% *}}; rest=${{line#* }}; mode=${{rest%% *}}; p=${{rest#* }}
    if [ -L "$p" ]; then chown -h "$own" "$p"
    elif [ -e "$p" ]; then chown "$own" "$p" && chmod "$mode" "$p"
    fi
done < {SCRATCH}/{OWNERS}
"#
    )
}

/// The promotion's step before the volume's service starts on the site: the pushed
/// files laid over last night's copy, what the house deleted deleted, owners and modes
/// put back — when the last round began after the copy's backup. Otherwise the copy
/// serves, and the reason is said. Never stops the promotion.
///
/// Streamed in rather than mounted, as SQLite's replica is: the pushed tree is its
/// account's, 0700, and the restoring container needs no bind of the host.
///
/// 🔴 Decided once per promotion, as SQLite's replica is: a house back up while the
/// site serves pushes its own, older files.
pub fn promote_step(user: &str, volume: &str, image: &str) -> String {
    let dir = site_dir(user);
    let done = decided_mark(volume);
    let settle = settle_script();
    format!(
        r#"from_push() {{
    vol=$1; push=$2
    done="{done}"
    if [ -f "$done" ]; then
        echo "  ✓ $vol: put in place by this promotion's first run, kept"
        return 0
    fi
    # Marked once the choice is carried out, never before: a run cut mid-copy chooses
    # again, nothing having started on the volume yet.
    decided() {{ mkdir -p {COPIED_DIR} && : > "$done"; }}
    pushed=$(cat "$push/{PUSHED}" 2>/dev/null || true)
    copied=$(cat {COPIED_DIR}/"$vol" 2>/dev/null || echo 0)
    if [ -z "$pushed" ] || [ ! -d "$push/{FILES}" ] || [ ! -f "$push/{OWNERS}" ]; then
        echo "  ⚠️  $vol: the site never received a whole push of it: last night's copy serves" >&2
        decided
        return 0
    fi
    # 🔴 A push of nothing but the volume's root is a volume the pusher found empty — a
    # name mounted fresh on the wrong node reads the same: laid over the copy, it would
    # delete every file the copy holds.
    if [ "$(grep -vc ' \.$' "$push/{OWNERS}" || true)" = 0 ]; then
        echo "  ⚠️  $vol: the house pushed it empty: last night's copy serves" >&2
        decided
        return 0
    fi
    if [ "$pushed" -le "$copied" ]; then
        echo "  ⚠️  $vol: its last push began at $(date -u -d "@$pushed" +%H:%M), before last night's copy: the copy serves" >&2
        decided
        return 0
    fi
    in_volume() {{
        docker run --rm -i --network none --read-only --cap-drop ALL \
            --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --tmpfs {SCRATCH} \
            --mount "type=volume,src=$vol,dst={MOUNTED_AT}" --entrypoint sh {image} -c "$1"
    }}
    # 🔴 A pipe ends alike whether its writer finished or failed: the archive's own
    # status is kept apart, and a half sent is said.
    sent=$(mktemp)
    if {{ tar -C "$push/{FILES}" --exclude='*.partial' -cf - . ; echo $? > "$sent"; }} |
        in_volume 'tar -xf - -C {MOUNTED_AT}' && [ "$(cat "$sent")" = 0 ] &&
        in_volume '{settle}' < "$push/{OWNERS}"; then
        echo "  ✓ $vol: the files pushed at $(date -u -d "@$pushed" +%H:%M:%S) UTC laid over last night's copy"
    else
        echo "  🔴 $vol: the pushed files were not all laid in place: it starts on what the copy got" >&2
    fi
    rm -f "$sent"
    decided
}}
from_push {volume} {dir}
"#
    )
}

/// Run on the site: when each account's last round began, and what its tree weighs —
/// `<user>=<epoch>` and `<user>.bytes=<n>` lines, empty when none.
pub fn site_probe_script(users: &[String]) -> String {
    users
        .iter()
        .map(|u| {
            let dir = site_dir(u);
            format!(
                "echo \"{u}=$(cat {dir}/{PUSHED} 2>/dev/null)\"\necho \"{u}.bytes=$(du -sb {dir}/{FILES} 2>/dev/null | cut -f1)\"\n"
            )
        })
        .collect()
}

/// The number a probe line gives for `key`.
pub fn parse_probe(out: &str, key: &str) -> Option<u64> {
    out.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .and_then(|v| v.trim().parse().ok())
}

/// A volume's pushes, judged: when the last round that reached the site began (`None`:
/// never), what the site holds of it, and whether its pusher runs at home.
pub fn judge(
    volume: &str,
    pushed: Option<u64>,
    bytes: Option<u64>,
    running: bool,
    now: u64,
) -> Said {
    let say = |mark, line| Said { mark, line };
    let size = bytes
        .map(|b| format!(", {} KB on the site", b / 1024))
        .unwrap_or_default();
    match pushed {
        None => say(
            Mark::Fault,
            format!("volume — {volume}: the site never received a push of it"),
        ),
        Some(p) if now.saturating_sub(p) > LATE_AFTER_S => say(
            Mark::Fault,
            format!(
                "volume — {volume}: last pushed {} s ago{size}: {}",
                now.saturating_sub(p),
                if running {
                    "its pusher does not reach the site"
                } else {
                    "its pusher does not run at home (hlb site sync --apply)"
                }
            ),
        ),
        Some(_) if !running => say(
            Mark::Fault,
            format!("volume — {volume}: its pusher does not run at home (hlb site sync --apply)"),
        ),
        Some(p) => say(
            Mark::Fine,
            format!(
                "volume — {volume}: pushed {} s ago{size}",
                now.saturating_sub(p)
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_volume_gets_an_account_of_its_own() {
        assert_eq!(
            user("vaultwarden-data").expect("fits"),
            "hlb-vol-vaultwarden-data"
        );
        assert!(user(&"a".repeat(25)).is_err());
        assert_eq!(
            site_dir("hlb-vol-x"),
            "/var/lib/homelabus-site/volumes/hlb-vol-x/push"
        );
    }

    #[test]
    fn the_volumes_drop_in_is_its_own() {
        let d = ACCOUNTS.drop_in();
        assert!(d.contains("Match User hlb-vol-*"), "{d}");
        assert!(d.contains("ForceCommand internal-sftp -d /push"), "{d}");
        assert_ne!(ACCOUNTS.drop_in, crate::sqlite_ship::DROP_IN);
    }

    #[test]
    fn every_host_key_of_the_site_is_pinned() {
        let keys = host_keys(&[
            Some("ecdsa-sha2-nistp256 E root@vps\n".into()),
            None,
            Some("ssh-ed25519 D root@vps".into()),
        ]);
        assert_eq!(keys, vec!["ecdsa-sha2-nistp256 E", "ssh-ed25519 D"]);
        let t = Target {
            user: String::new(),
            host: "203.0.113.7".into(),
            port: 22,
        };
        let env = env(&t, "hlb-vol-x", &keys);
        let get = |k: &str| {
            env.iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.as_str())
                .expect(k)
        };
        assert_eq!(
            get("RCLONE_CONFIG_SITE_HOST_KEYS"),
            "ecdsa-sha2-nistp256 E,ssh-ed25519 D"
        );
        assert_eq!(get("RCLONE_CONFIG_SITE_KEY_FILE"), KEY);
        assert_eq!(get("RCLONE_CONFIG_SITE_SHELL_TYPE"), "none");
    }

    #[test]
    fn a_round_leaves_sqlite_out_and_says_its_time_last() {
        let s = push_script();
        let excluded = s.find("--exclude-from").expect("excluded");
        let sync = s.find("rclone sync").expect("synced");
        let owners = s.find("stat -c").expect("owners listed");
        let stamp = s.find("site:/push/pushed").expect("stamped");
        assert!(s.find("sqlite_here >").expect("found") < sync, "{s}");
        assert!(
            sync < excluded && excluded < owners && owners < stamp,
            "{s}"
        );
        assert!(s.contains("sleep \"$left\""), "{s}");
    }

    fn sqlite_here_in(dir: &std::path::Path) -> std::process::Output {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{}sqlite_here", sqlite_functions()))
            .current_dir(dir)
            .output()
            .expect("sh runs")
    }

    #[test]
    fn a_volume_holding_no_sqlite_still_pushes() {
        let d = tempfile::tempdir().expect("dir");
        std::fs::create_dir(d.path().join("attachments")).expect("subdir");
        std::fs::write(d.path().join("attachments/a.bin"), b"not a database").expect("file");
        std::fs::write(d.path().join("rsa_key.pem"), b"-----BEGIN").expect("file");
        let out = sqlite_here_in(d.path());
        assert!(out.status.success(), "{out:?}");
        assert!(out.stdout.is_empty(), "{out:?}");

        std::fs::write(d.path().join("db.sqlite3"), b"SQLite format 3\0rest").expect("db");
        let out = sqlite_here_in(d.path());
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "/db.sqlite3\n");
    }

    #[test]
    fn the_promotion_spares_sqlite_and_never_stops_on_a_bad_push() {
        let s = promote_step(
            "hlb-vol-pocket-id-data",
            "pocket-id-data",
            "rclone/rclone:x",
        );
        assert!(s.contains("from_push pocket-id-data /var/lib/homelabus-site/volumes/hlb-vol-pocket-id-data/push"), "{s}");
        // Settled as one argument: a quote in it would end it.
        assert!(!settle_script().contains('\''));
        assert!(
            s.contains("kept \"$p\" || rm") || s.contains("elif ! kept \"$p\"; then rm -f"),
            "{s}"
        );
        assert!(s.contains("--network none"), "{s}");
        // Under the promotion's `set -e`, a failed copy is an `if`'s condition.
        assert!(s.contains("    if {"), "{s}");
        assert!(!s.contains("\n    exit"), "{s}");
        let copy = s.find("    if {").expect("copy");
        assert!(s.find("decided()").expect("defined") < copy, "{s}");
        assert!(s.rfind("    decided\n").expect("marked") > copy, "{s}");
        assert!(s.contains("/etc/hlb/site/sqlite-copied/pocket-id-data-files.promoted"));
    }

    #[test]
    fn the_new_copy_s_mark_clears_the_volume_s_decision_too() {
        // `copied_script` removes `<volume>-*.promoted`: the files' decision with it.
        let mark = decided_mark("v");
        assert!(mark.starts_with(&format!("{COPIED_DIR}/v-")), "{mark}");
        assert!(mark.ends_with(DECIDED), "{mark}");
        assert!(crate::sqlite_ship::copied_script("v", 1)
            .contains("rm -f /etc/hlb/site/sqlite-copied/v-*.promoted"));
    }

    #[test]
    fn pushes_are_late_past_five_minutes_or_when_the_pusher_is_gone() {
        assert_eq!(
            judge("v", Some(1000), Some(2048), true, 1100).mark,
            Mark::Fine
        );
        assert_eq!(judge("v", Some(1000), None, true, 2000).mark, Mark::Fault);
        assert_eq!(judge("v", None, None, true, 2000).mark, Mark::Fault);
        assert_eq!(judge("v", Some(1000), None, false, 1010).mark, Mark::Fault);
        assert_eq!(
            parse_probe("hlb-vol-v=1700\nhlb-vol-v.bytes=4096\n", "hlb-vol-v"),
            Some(1700)
        );
        assert_eq!(
            parse_probe("hlb-vol-v=1700\nhlb-vol-v.bytes=4096\n", "hlb-vol-v.bytes"),
            Some(4096)
        );
        assert_eq!(parse_probe("hlb-vol-v=\n", "hlb-vol-v"), None);
    }
}
