//! The vital server's WAL, shipped to its site: archived compressed beside the server,
//! pushed over SSH by a service of the house, replayed by a standby there.
//!
//! 🔴 **Pushed, never pulled.** Nothing of the house is opened to the VPS. The pushing
//! key is refused anything but [`receiver_script`] by the site's own `authorized_keys`
//! (`restrict,command=`), so a key read out of the pushing container writes WAL into one
//! directory and does nothing else.
//!
//! 🔴 **Archived locally, never straight to the site.** A failing `archive_command`
//! keeps every segment in `pg_wal` until the disk is full: archived to the VPS, a site
//! unreachable for a day would have stopped the house's PostgreSQL. The archive is a
//! volume beside the server, which the pusher empties as the site acknowledges, and
//! bounds ([`BACKLOG_CAP_MB`]): past it the oldest segments go, the standby stops at the
//! hole, and the next lifeboat seeds it again. A standby rebuilt beats a house stopped.
//!
//! Compressed as archived: [`ARCHIVE_TIMEOUT_S`] switches a segment every 30 s when
//! anything was written, and a switched segment is 16 MB on disk whatever it holds —
//! 2 to 31 KB once compressed on the lab's Vaultwarden (measured 2026-11-10).

/// Where the vital server archives, in its own volume.
pub const ARCHIVE_DIR: &str = "/var/lib/postgresql/wal";

/// A segment is switched, so archived and pushed, this often when anything was written.
/// What the site lacks at a cut is at most this, plus [`PUSH_EVERY_S`].
pub const ARCHIVE_TIMEOUT_S: u32 = 30;

/// How long the pusher sleeps between two looks at the archive.
pub const PUSH_EVERY_S: u32 = 10;

/// What may wait in the archive for the site, compressed, before the oldest goes.
pub const BACKLOG_CAP_MB: u64 = 2048;

/// Where the site keeps what it received, on the VPS.
pub const SITE_DIR: &str = "/var/lib/homelabus-site/wal";

/// When the site last received a file: seconds since the epoch, one line.
pub const SITE_RECEIVED: &str = "/var/lib/homelabus-site/wal-received";

/// Where the standby reads [`SITE_DIR`].
pub const STANDBY_DIR: &str = "/var/lib/postgresql/incoming";

/// The forced command of the pushing key, on the VPS.
pub const RECEIVER: &str = "/usr/local/sbin/hlb-wal-receive";

/// The catalog image's `postgres` user, which owns what the standby replays and cleans.
pub const POSTGRES_UID: u32 = 999;

const SUFFIX: &str = ".zst";

/// What PostgreSQL archives: a segment, a partial one at a promotion, a backup label, a
/// timeline's history — compressed. Nothing else is pushed or received.
pub const NAME_PATTERN: &str =
    "^([0-9A-F]{24}(\\.partial|\\.[0-9A-F]{8}\\.backup)?|[0-9A-F]{8}\\.history)\\.zst$";

/// Whether `name` is one of [`NAME_PATTERN`]'s, read in Rust as the scripts read it.
pub fn is_archived_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(SUFFIX) else {
        return false;
    };
    let hex = |s: &str, n: usize| {
        s.len() == n
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    };
    if let Some(tli) = stem.strip_suffix(".history") {
        return hex(tli, 8);
    }
    let (seg, rest) = stem.split_at(stem.len().min(24));
    if !hex(seg, 24) {
        return false;
    }
    match rest {
        "" | ".partial" => true,
        r => r
            .strip_prefix('.')
            .and_then(|r| r.strip_suffix(".backup"))
            .is_some_and(|off| hex(off, 8)),
    }
}

/// The primary's `archive_command`.
///
/// 🔴 A file already there is compared, never overwritten nor refused: an archiver that
/// died after the rename but before PostgreSQL heard of it is asked the same segment
/// again, and a bare `test ! -f` would then fail it for ever — `pg_wal` growing behind
/// it. A DIFFERENT file of that name (a timeline gone wrong) does fail, as it must.
/// Written under a temporary name and renamed: an interrupted `zstd` leaves no
/// truncated segment under the real one.
pub fn archive_command() -> String {
    format!(
        "d={ARCHIVE_DIR}; if [ -f $d/%f{SUFFIX} ]; then zstd -qdc $d/%f{SUFFIX} | cmp -s - %p; \
         else zstd -qf -o $d/%f{SUFFIX}.tmp %p && mv $d/%f{SUFFIX}.tmp $d/%f{SUFFIX}; fi"
    )
}

/// After the catalog's own arguments, on the vital server: archiving on. These need a
/// restart — reloaded, they are accepted and do nothing — which a deployment is.
pub fn primary_args() -> Vec<String> {
    [
        "wal_level=replica".to_string(),
        "archive_mode=on".to_string(),
        format!("archive_command={}", archive_command()),
        format!("archive_timeout={ARCHIVE_TIMEOUT_S}"),
    ]
    .into_iter()
    .flat_map(|s| ["-c".to_string(), s])
    .collect()
}

/// The standby's `restore_command`: a file not there yet fails, without leaving an
/// empty one where PostgreSQL reads.
pub fn restore_command() -> String {
    format!("f={STANDBY_DIR}/%f{SUFFIX}; [ -f $f ] && zstd -qdc $f > %p")
}

/// What the standby no longer needs, deleted as it restarts past it.
pub fn cleanup_command() -> String {
    format!("pg_archivecleanup -x {SUFFIX} {STANDBY_DIR} %r")
}

/// After the catalog's arguments, on the site's standby: it replays what arrives, and
/// archives nothing once promoted — no pusher runs there, the house is down. Given last,
/// they win over the primary's.
pub fn standby_args() -> Vec<String> {
    [
        "archive_mode=off".to_string(),
        format!("restore_command={}", restore_command()),
        format!("archive_cleanup_command={}", cleanup_command()),
    ]
    .into_iter()
    .flat_map(|s| ["-c".to_string(), s])
    .collect()
}

/// The pushing key's line in the site's `authorized_keys`.
pub fn authorized_line(public_key: &str) -> String {
    format!(
        "restrict,command=\"{RECEIVER}\" {} hlb-wal-push",
        public_key.trim()
    )
}

/// The forced command: one file named `put <name> <sha256>` on its standard input,
/// checked, and renamed into [`SITE_DIR`]. Anything else is refused.
///
/// 🔴 A connection cut mid-file ends the input as a finished one does: the digest is
/// what tells them apart. A file already received is compared, as the archive does.
pub fn receiver_script() -> String {
    format!(
        r#"#!/bin/sh
# Generated by Homelabus - do not edit by hand.
# The forced command of the house's WAL pusher: one archived file per call.
set -euf
umask 077
set -- ${{SSH_ORIGINAL_COMMAND:-}}
[ "$#" = 3 ] && [ "$1" = put ] || {{ echo "refused" >&2; exit 2; }}
name=$2
sum=$3
printf '%s\n' "$name" | grep -Eq '{NAME_PATTERN}' || {{ echo "refused: $name" >&2; exit 2; }}
printf '%s\n' "$sum" | grep -Eq '^[0-9a-f]{{64}}$' || {{ echo "refused digest" >&2; exit 2; }}
dir={SITE_DIR}
mkdir -p "$dir"
chown {POSTGRES_UID}:{POSTGRES_UID} "$dir"
chmod 700 "$dir"
tmp="$dir/.in.$$"
trap 'rm -f "$tmp"' EXIT
cat > "$tmp"
[ "$(sha256sum "$tmp" | cut -d' ' -f1)" = "$sum" ] || {{ echo "$name arrived damaged" >&2; exit 1; }}
if [ -f "$dir/$name" ]; then
    cmp -s "$tmp" "$dir/$name" || {{ echo "$name differs from the one received" >&2; exit 1; }}
else
    chown {POSTGRES_UID}:{POSTGRES_UID} "$tmp"
    mv "$tmp" "$dir/$name"
fi
date +%s > {SITE_RECEIVED}
"#
    )
}

/// Where the pusher finds what it needs, inside its container.
pub const PUSHER_ARCHIVE: &str = "/archive";
pub const PUSHER_KEY: &str = "/run/secrets/hlb-wal-key";
pub const PUSHER_KNOWN_HOSTS: &str = "/run/secrets/hlb-wal-known-hosts";

/// The site as the pusher reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub user: String,
    pub host: String,
    pub port: u16,
}

/// The pusher's loop, oldest first: each file pushed is removed, the first refused
/// stops the round — a segment pushed past a missing one would be replayed by nobody.
///
/// The key is copied out of its secret: Swarm mounts it world-readable, and `ssh`
/// refuses such a key. The site's host key is pinned, never accepted as it comes.
pub fn pusher_script(t: &Target) -> String {
    let cap_kb = BACKLOG_CAP_MB * 1024;
    format!(
        r#"set -u
install -m 600 {PUSHER_KEY} /tmp/key
cd {PUSHER_ARCHIVE}
pending() {{ ls | grep -E '{NAME_PATTERN}' | sort; }}
while :; do
    for f in $(pending); do
        sum=$(sha256sum "$f" | cut -d' ' -f1)
        if ssh -i /tmp/key -p {port} -o BatchMode=yes -o StrictHostKeyChecking=yes \
            -o UserKnownHostsFile={PUSHER_KNOWN_HOSTS} -o ConnectTimeout=10 \
            -o ServerAliveInterval=10 -o ServerAliveCountMax=3 \
            {user}@{host} "put $f $sum" < "$f"; then
            rm -f "$f"
        else
            echo "$f not pushed: kept, tried again in {PUSH_EVERY_S} s" >&2
            break
        fi
    done
    while [ "$(du -sk . | cut -f1)" -gt {cap_kb} ]; do
        f=$(pending | head -n 1)
        [ -n "$f" ] || break
        echo "$f dropped: {BACKLOG_CAP_MB} MB wait for the site; its standby stops here until the next lifeboat" >&2
        rm -f "$f"
    done
    sleep {PUSH_EVERY_S}
done
"#,
        port = t.port,
        user = t.user,
        host = t.host,
    )
}

/// The `known_hosts` line pinning the site's host key, as `ssh -p` looks it up.
pub fn known_hosts_line(t: &Target, host_key: &str) -> String {
    let host = if t.port == 22 {
        t.host.clone()
    } else {
        format!("[{}]:{}", t.host, t.port)
    };
    let mut fields = host_key.split_whitespace();
    let (kind, key) = (fields.next().unwrap_or(""), fields.next().unwrap_or(""));
    format!("{host} {kind} {key}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_postgresql_archives_is_named_and_nothing_else() {
        for ok in [
            "000000010000000000000003.zst",
            "000000010000000000000003.partial.zst",
            "000000010000000000000003.00000028.backup.zst",
            "00000002.history.zst",
        ] {
            assert!(is_archived_name(ok), "{ok}");
        }
        for no in [
            "000000010000000000000003",
            "000000010000000000000003.zst.tmp",
            "00000001000000000000000g.zst",
            "000000010000000000000003.zst/../x",
            "../000000010000000000000003.zst",
            ".in.123",
            "0000000100000000000000033.zst",
            "00000002.history",
            "",
        ] {
            assert!(!is_archived_name(no), "{no}");
        }
    }

    #[test]
    fn the_archive_compares_a_file_already_there_rather_than_refusing_it() {
        let c = archive_command();
        assert!(c.contains("cmp -s - %p"), "{c}");
        assert!(!c.contains("test ! -f"), "{c}");
        assert!(c.find(".tmp %p").is_some() && c.contains("&& mv"), "{c}");
    }

    #[test]
    fn the_standby_settings_come_after_and_turn_archiving_off() {
        let a = standby_args();
        assert_eq!(a[0], "-c");
        assert_eq!(a[1], "archive_mode=off");
        assert!(a.iter().any(|s| s.starts_with("restore_command=")));
        assert!(restore_command().contains("[ -f $f ] &&"));
    }

    #[test]
    fn the_pushing_key_runs_the_receiver_alone() {
        let l = authorized_line("ssh-ed25519 AAAAC3 house\n");
        assert!(l.starts_with("restrict,command=\"/usr/local/sbin/hlb-wal-receive\" "));
        assert!(l.ends_with(" hlb-wal-push"), "{l}");
        assert!(!l.contains('\n'));
    }

    #[test]
    fn the_pusher_pins_the_site_s_host_key() {
        let t = Target {
            user: "root".into(),
            host: "203.0.113.7".into(),
            port: 2222,
        };
        let s = pusher_script(&t);
        assert!(s.contains("StrictHostKeyChecking=yes"), "{s}");
        assert!(!s.contains("accept-new"), "{s}");
        assert_eq!(
            known_hosts_line(&t, "ssh-ed25519 AAAAkey root@vps"),
            "[203.0.113.7]:2222 ssh-ed25519 AAAAkey\n"
        );
        let t22 = Target { port: 22, ..t };
        assert!(known_hosts_line(&t22, "ssh-ed25519 K").starts_with("203.0.113.7 "));
    }
}
