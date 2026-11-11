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

/// What makes a data directory start as a standby, beside what a base backup restored.
/// Without it the server recovers what the base holds and opens for writes — on a
/// timeline of its own, which no WAL of the house follows.
pub const STANDBY_SIGNAL: &str = "standby.signal";

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

/// How far back the site's WAL reaches, at least: a point-in-time restore of the vital
/// server can be asked for any instant this recent.
pub const KEEP_HOURS: u32 = 24;

/// Run on the site after a base was seeded: the WAL older than the newest base received
/// more than [`KEEP_HOURS`] ago is removed, so every instant since stays reachable from a
/// base and what follows it. Prints the base kept, nothing when none is old enough.
///
/// 🔴 The standby never cleans: its restartpoints would remove, as it replays, every
/// segment a point-in-time restore needs (`archive_cleanup_command`, until 2026-11-11).
/// Names compared without their timeline, as `pg_archivecleanup` does — a promotion's
/// segments carry the next one, and would otherwise sort after everything for ever.
/// Timeline histories are kept: a few bytes, and a replay needs them.
pub fn prune_script() -> String {
    let minutes = KEEP_HOURS * 60;
    format!(
        r#"dir={SITE_DIR}
b=$(find "$dir" -maxdepth 1 -type f -name '*.backup{SUFFIX}' -mmin +{minutes} -printf '%f\n' |
    awk '{{ k = substr($0, 9, 16); if (k > m) {{ m = k; f = $0 }} }} END {{ print f }}')
[ -n "$b" ] || exit 0
cut=$(printf %s "$b" | cut -c9-24)
find "$dir" -maxdepth 1 -type f -printf '%f\n' |
    awk -v cut="$cut" '!/\.history\{SUFFIX}$/ && substr($0, 9, 16) "" < cut ""' |
    while read -r f; do rm -f "$dir/$f"; done
printf '%s\n' "${{b%{SUFFIX}}}"
"#
    )
}

/// After the catalog's arguments, on the site's standby: it replays what arrives, and
/// archives nothing once promoted — no pusher runs there, the house is down. Given last,
/// they win over the primary's.
pub fn standby_args() -> Vec<String> {
    [
        "archive_mode=off".to_string(),
        format!("restore_command={}", restore_command()),
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

/// What a server is asked for its position: its timeline and where it writes,
/// `psql -tA`'s `1|0/5000148`.
pub const POSITION_SQL: &str =
    "SELECT timeline_id, pg_current_wal_lsn() FROM pg_control_checkpoint()";

/// A WAL position, `0/5000148`, as one number.
pub fn parse_lsn(s: &str) -> Option<u64> {
    let (hi, lo) = s.trim().split_once('/')?;
    Some((u64::from_str_radix(hi, 16).ok()? << 32) | u64::from_str_radix(lo, 16).ok()?)
}

/// [`POSITION_SQL`]'s answer: `(timeline, position)`.
pub fn parse_position(s: &str) -> Option<(u32, u64)> {
    let (tli, lsn) = s.trim().split_once('|')?;
    Some((tli.trim().parse().ok()?, parse_lsn(lsn)?))
}

/// Where the promoted standby left `timeline`, read from its timeline history files —
/// each line `<parent timeline>\t<switch point>\t<reason>`, every file repeating its
/// ancestors'. `None`: the site never followed that timeline.
pub fn switch_point(history: &str, timeline: u32) -> Option<u64> {
    history.lines().find_map(|l| {
        let mut f = l.split_whitespace();
        (f.next()?.parse::<u32>().ok()? == timeline)
            .then(|| parse_lsn(f.next()?))
            .flatten()
    })
}

/// What the house's server wrote past the point the site took over, said for the
/// person bringing it home: replaced by the return, kept in the copy it takes first.
///
/// 🔴 Never "nothing was lost" past zero bytes: a server writes its own records — the
/// checkpoint of its restart — so a few bytes past are counted, and said as what they
/// may be, rather than kept quiet as noise.
pub fn written_past(house: (u32, u64), history: &str) -> String {
    let (tli, at) = house;
    let Some(switch) = switch_point(history, tli) else {
        return format!(
            "the house's server is on timeline {tli}, which the site never followed: what \
             it wrote past the site's copy cannot be told"
        );
    };
    // Past a segment's end the distance is no size: each switch [`ARCHIVE_TIMEOUT_S`]
    // forces jumps to the next 16 MB boundary, so four quiet minutes on the lab read
    // "32769 KB" (2026-11-11). Segments are counted instead — each holds a write.
    let segments = (at >> 24).saturating_sub(switch >> 24);
    let how_much = match at.saturating_sub(switch) {
        0 => return "the house's server wrote nothing past the point the site took over".into(),
        _ if segments > 0 => format!(
            "WAL into {segments} more segment{} (one is switched every \
             {ARCHIVE_TIMEOUT_S} s once anything was written)",
            if segments == 1 { "" } else { "s" }
        ),
        n if n < 1024 => format!("{n} bytes of WAL"),
        n => format!("{} KB of WAL", n.div_ceil(1024)),
    };
    format!(
        "the house's server wrote {how_much} past the point the site took over — its own \
         restart's records at least, and whatever its apps wrote after the last push: \
         replaced, kept in the copy each restore takes first"
    )
}

/// The segment holding `lsn` on `timeline`, as PostgreSQL names it: 16 MB segments,
/// the catalog's. Computed here: `pg_walfile_name` refuses to run on a standby.
pub fn segment_name(timeline: u32, lsn: u64) -> String {
    format!(
        "{timeline:08X}{:08X}{:08X}",
        lsn >> 32,
        (lsn & 0xFFFF_FFFF) >> 24
    )
}

/// A file waiting at home past this many minutes means the pusher does not reach the
/// site: it pushes every [`PUSH_EVERY_S`].
pub const WAITING_MINUTES: u32 = 5;

/// Counts what waits at home for the site past [`WAITING_MINUTES`], in the server's
/// container.
pub fn waiting_command() -> String {
    format!("find {ARCHIVE_DIR} -name '*{SUFFIX}' -mmin +{WAITING_MINUTES} | wc -l")
}

/// Run on the site: when it last received, the newest segment it holds, and how the
/// vital server's standby stands — `key=value` lines, read by [`parse_site`].
pub fn site_probe_script(service: &str) -> String {
    format!(
        r#"echo "received=$(cat {SITE_RECEIVED} 2>/dev/null)"
n=$(ls {SITE_DIR} 2>/dev/null | grep -E '^[0-9A-F]{{24}}\{SUFFIX}$' | sort | tail -n 1)
echo "newest=${{n%{SUFFIX}}}"
id=$(docker ps -q --filter label=com.docker.swarm.service.name={service} | head -n 1)
if [ -n "$id" ]; then
    echo "standby=$(docker exec -u postgres "$id" psql -XqtA -c '{STANDBY_SQL}' 2>&1 | tr '\n' ' ')"
else
    echo "standby="
fi
"#
    )
}

/// What the standby is asked: whether it still replays, on which timeline, and where.
const STANDBY_SQL: &str =
    "SELECT pg_is_in_recovery(), timeline_id, pg_last_wal_replay_lsn() FROM pg_control_checkpoint()";

/// The vital server's standby, as the site reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standby {
    /// No task of it runs.
    Absent,
    Replaying {
        timeline: u32,
        lsn: Option<u64>,
    },
    /// Out of recovery: the server the site serves from, or a standby gone astray.
    Writing,
    Unread(String),
}

/// What [`site_probe_script`] said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteWal {
    /// When it last received a file, seconds since the epoch.
    pub received: Option<u64>,
    /// The newest whole segment it holds.
    pub newest: Option<String>,
    pub standby: Standby,
}

pub fn parse_site(out: &str) -> SiteWal {
    let field = |k: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix('='))
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    let standby = match field("standby") {
        None => Standby::Absent,
        Some(v) => {
            let f: Vec<&str> = v.split('|').collect();
            match (f.first().copied(), f.get(1).and_then(|t| t.parse().ok())) {
                (Some("t"), Some(timeline)) => Standby::Replaying {
                    timeline,
                    lsn: f.get(2).and_then(|l| parse_lsn(l)),
                },
                (Some("f"), Some(_)) => Standby::Writing,
                _ => Standby::Unread(v.to_string()),
            }
        }
    };
    SiteWal {
        received: field("received").and_then(|v| v.parse().ok()),
        newest: field("newest").map(str::to_string),
        standby,
    }
}

/// How a line of the WAL's state reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Fine,
    /// Not read: never said fine.
    Unknown,
    Fault,
}

/// One line of the WAL's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Said {
    pub mark: Mark,
    pub line: String,
}

/// How long since `then`, for a person.
fn ago(now: u64, then: u64) -> String {
    let s = now.saturating_sub(then);
    match s {
        0..=119 => format!("{s} s ago"),
        120..=7199 => format!("{} min ago", s / 60),
        _ => format!("{} h ago", s / 3600),
    }
}

/// The WAL's way to the site, judged: what waits at home (`None`: unread), what the
/// site received, and its standby — `promoted` when the site serves from it.
///
/// 🔴 A standby that answers is not one that replays: one stopped at a missing segment
/// stays healthy and answers reads for ever. It is stopped when the site holds a newer
/// segment than the one it replays and received nothing for two minutes.
pub fn judge(waiting: Option<u64>, site: &SiteWal, promoted: bool, now: u64) -> Vec<Said> {
    let mut out = Vec::new();
    let mut say = |mark: Mark, line: String| out.push(Said { mark, line });
    match waiting {
        Some(0) => say(
            Mark::Fine,
            "WAL — nothing waits at home for the site".into(),
        ),
        Some(n) => say(
            Mark::Fault,
            format!(
                "WAL — {n} file(s) wait at home for over {WAITING_MINUTES} min: the pusher \
                 does not reach the site (docker service logs hlb-wal-push)"
            ),
        ),
        None => say(
            Mark::Unknown,
            "WAL — what waits at home could not be read".into(),
        ),
    }
    match site.received {
        Some(t) => say(
            Mark::Fine,
            format!("WAL — last file received {}", ago(now, t)),
        ),
        None => say(
            Mark::Unknown,
            "WAL — the site has received nothing yet".into(),
        ),
    }
    let quiet = site.received.is_none_or(|t| now.saturating_sub(t) > 120);
    match (&site.standby, promoted) {
        (Standby::Writing, true) => {}
        (Standby::Writing, false) => say(
            Mark::Fault,
            "standby — out of recovery with the site not promoted: it follows nothing; \
             the next lifeboat seeds another"
                .into(),
        ),
        (Standby::Absent, true) => say(
            Mark::Fault,
            "standby — promoted, and no task of it runs: the vital apps have no database".into(),
        ),
        (Standby::Absent, false) => say(
            Mark::Fault,
            "standby — none runs on the site: the next lifeboat seeds one \
             (hlb site lifeboat --apply)"
                .into(),
        ),
        (Standby::Unread(why), _) => {
            say(Mark::Fault, format!("standby — could not be read: {why}"))
        }
        (Standby::Replaying { lsn: None, .. }, _) => say(
            Mark::Fault,
            "standby — in recovery, and replayed nothing yet".into(),
        ),
        (
            Standby::Replaying {
                timeline,
                lsn: Some(lsn),
            },
            _,
        ) => {
            let at = segment_name(*timeline, *lsn);
            match &site.newest {
                Some(newest) if *newest > at && quiet => say(
                    Mark::Fault,
                    format!(
                        "standby — stopped in {at} while the site holds {newest}: a segment \
                         is missing; the next lifeboat seeds it again"
                    ),
                ),
                _ => say(
                    Mark::Fine,
                    format!(
                        "standby — replayed to {:X}/{:X} ({at})",
                        lsn >> 32,
                        lsn & 0xFFFF_FFFF
                    ),
                ),
            }
        }
    }
    out
}

/// A base label reaches the site some seconds after its base ended, and the base's
/// snapshot is dated when restic began: a base this much older than the oldest label the
/// site keeps is still the one that label belongs to. Bases are hours apart.
pub const LABEL_SLACK_S: i64 = 60;

/// Run on the site: when it last received, and when each base label it keeps arrived —
/// `received=<epoch>` and `label=<epoch>` lines, read by [`parse_site_labels`].
pub fn site_labels_script() -> String {
    format!(
        r#"echo "received=$(cat {SITE_RECEIVED} 2>/dev/null)"
find {SITE_DIR} -maxdepth 1 -type f -name '*.backup{SUFFIX}' -printf 'label=%T@\n' 2>/dev/null
"#
    )
}

/// What the site keeps for a point-in-time restore.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiteLabels {
    /// When the site last received a file: the newest instant it can replay to.
    pub received: Option<i64>,
    /// When the oldest base label it keeps arrived: no older base has its WAL there.
    pub oldest_label: Option<i64>,
}

pub fn parse_site_labels(out: &str) -> SiteLabels {
    let mut s = SiteLabels::default();
    for line in out.lines() {
        if let Some(v) = line.strip_prefix("received=") {
            s.received = v.trim().parse().ok();
        } else if let Some(v) = line.strip_prefix("label=") {
            // `find` prints the time with its fraction: `1762862960.4630000000`.
            let at = v
                .trim()
                .split('.')
                .next()
                .and_then(|n| n.parse::<i64>().ok());
            if let Some(at) = at {
                s.oldest_label = Some(s.oldest_label.map_or(at, |o| o.min(at)));
            }
        }
    }
    s
}

/// The bases a point-in-time restore of the vital server can start from: those whose
/// label, and so the WAL past their start, the site still keeps.
pub fn usable_bases(
    bases: &[crate::pitr::BaseBackup],
    site: &SiteLabels,
) -> Vec<crate::pitr::BaseBackup> {
    let Some(oldest) = site.oldest_label else {
        return Vec::new();
    };
    bases
        .iter()
        .filter(|b| b.finished_at >= oldest - LABEL_SLACK_S)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_segment_is_named_as_postgresql_names_it() {
        assert_eq!(segment_name(1, 0x500_0148), "000000010000000000000005");
        assert_eq!(
            segment_name(2, (1 << 32) | 0x1F00_0000),
            "00000002000000010000001F"
        );
    }

    #[test]
    fn the_site_s_probe_is_read_back() {
        let out = "received=1700000000\nnewest=000000010000000000000007\nstandby=t|1|0/7000060 \n";
        assert_eq!(
            parse_site(out),
            SiteWal {
                received: Some(1_700_000_000),
                newest: Some("000000010000000000000007".into()),
                standby: Standby::Replaying {
                    timeline: 1,
                    lsn: Some(0x700_0060)
                },
            }
        );
        let none = parse_site("received=\nnewest=\nstandby=\n");
        assert_eq!(none.received, None);
        assert_eq!(none.newest, None);
        assert_eq!(none.standby, Standby::Absent);
        assert!(matches!(
            parse_site("standby=psql: error: connection refused ").standby,
            Standby::Unread(_)
        ));
        assert_eq!(
            parse_site("standby=f|2|0/9000000").standby,
            Standby::Writing
        );
        let script = site_probe_script("postgres-vital");
        let out = std::process::Command::new("sh")
            .args(["-n", "-c", &script])
            .output()
            .expect("sh");
        assert!(out.status.success(), "{script}");
    }

    #[test]
    fn a_standby_stopped_at_a_missing_segment_is_a_fault_though_it_answers() {
        let now = 1_700_000_000;
        let replaying = |lsn: u64, newest: &str, received: u64| SiteWal {
            received: Some(received),
            newest: Some(newest.into()),
            standby: Standby::Replaying {
                timeline: 1,
                lsn: Some(lsn),
            },
        };
        let faults = |s: &SiteWal, promoted: bool| -> Vec<String> {
            judge(Some(0), s, promoted, now)
                .into_iter()
                .filter(|l| l.mark == Mark::Fault)
                .map(|l| l.line)
                .collect()
        };
        // Up to date: replaying the segment after the newest received.
        assert!(faults(
            &replaying(0x800_0000, "000000010000000000000007", now - 400),
            false
        )
        .is_empty());
        // Behind while files still arrive: catching up, no fault yet.
        assert!(faults(
            &replaying(0x500_0000, "000000010000000000000007", now - 10),
            false
        )
        .is_empty());
        // Behind, and nothing arrived for minutes: stopped.
        let stuck = faults(
            &replaying(0x500_0000, "000000010000000000000007", now - 400),
            false,
        );
        assert!(
            stuck.len() == 1 && stuck[0].contains("missing"),
            "{stuck:?}"
        );
        // Out of recovery without a promotion follows nothing; promoted, it serves.
        let writing = SiteWal {
            received: None,
            newest: None,
            standby: Standby::Writing,
        };
        assert_eq!(faults(&writing, false).len(), 1);
        assert!(faults(&writing, true).is_empty());
        // Files waiting at home are the pusher's fault, whatever the site says.
        let w = judge(
            Some(3),
            &replaying(0x800_0000, "000000010000000000000007", now),
            false,
            now,
        );
        assert!(
            w[0].mark == Mark::Fault && w[0].line.contains("pusher"),
            "{w:?}"
        );
        // Unread is never fine.
        let u = judge(None, &writing, true, now);
        assert_eq!(u[0].mark, Mark::Unknown, "{u:?}");
    }

    #[test]
    fn a_position_reads_as_postgresql_writes_it() {
        assert_eq!(parse_lsn("0/5000148"), Some(0x500_0148));
        assert_eq!(parse_lsn("1/0"), Some(1 << 32));
        assert_eq!(parse_lsn("5000148"), None);
        assert_eq!(parse_position("1|0/5000148\n"), Some((1, 0x500_0148)));
        assert_eq!(parse_position(""), None);
    }

    #[test]
    fn what_the_house_wrote_past_the_takeover_is_said() {
        let history = "1\t0/5000148\tno recovery target specified\n";
        assert!(
            written_past((1, 0x500_0148), history).contains("wrote nothing"),
            "at the switch point"
        );
        assert!(written_past((1, 0x500_0000), history).contains("wrote nothing"));
        let past = written_past((1, 0x500_0148 + 4096), history);
        assert!(past.contains("4 KB") && past.contains("replaced"), "{past}");
        assert!(written_past((1, 0x500_0148 + 120), history).contains("120 bytes"));
        // Past the segment's end, switches pad to 16 MB: segments are said, not a size.
        let two = written_past((1, 0x700_0060), history);
        assert!(
            two.contains("2 more segments") && !two.contains("KB"),
            "{two}"
        );
        assert!(written_past((1, 0x600_0000), history).contains("1 more segment "));
        // A timeline the site's history does not hold is not compared.
        assert!(written_past((3, 1), history).contains("cannot be told"));
        // Two history files, the second repeating the first.
        let two = "1\t0/5000148\tx\n1\t0/5000148\tx\n2\t0/7000000\ty\n";
        assert_eq!(switch_point(two, 2), Some(0x700_0000));
    }

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
        assert!(
            !a.iter().any(|s| s.starts_with("archive_cleanup_command")),
            "the site's WAL is kept for point-in-time restores: {a:?}"
        );
    }

    /// Run on a directory laid out as the site's: two bases a day and more back, one
    /// this morning, a promotion's segments on the next timeline.
    #[test]
    fn the_site_keeps_its_wal_back_to_the_newest_base_a_day_old() {
        let dir = tempfile::tempdir().expect("scratch");
        let old = "202611090300";
        let day = "202611100300";
        let files = [
            ("000000010000000000000003.zst", old),
            ("000000010000000000000004.00000028.backup.zst", old),
            ("000000010000000000000004.zst", old),
            ("000000010000000000000009.zst", day),
            ("00000001000000000000000A.00000060.backup.zst", day),
            ("00000001000000000000000A.zst", day),
            ("00000001000000000000000B.zst", day),
            ("00000002000000000000000C.zst", day),
            ("00000002.history.zst", old),
            ("00000001000000000000000D.00000028.backup.zst", ""),
            ("00000001000000000000000D.zst", ""),
        ];
        for (f, at) in files {
            let path = dir.path().join(f);
            std::fs::write(&path, b"x").expect("written");
            if !at.is_empty() {
                let out = std::process::Command::new("touch")
                    .args(["-t", at])
                    .arg(&path)
                    .output()
                    .expect("touch");
                assert!(out.status.success());
            }
        }
        let script = prune_script().replace(SITE_DIR, &dir.path().to_string_lossy());
        let out = std::process::Command::new("sh")
            .args(["-c", &script])
            .output()
            .expect("sh");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "00000001000000000000000A.00000060.backup",
            "this morning's base is not a day old: yesterday's is kept"
        );
        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .expect("read")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "00000001000000000000000A.00000060.backup.zst",
                "00000001000000000000000A.zst",
                "00000001000000000000000B.zst",
                "00000001000000000000000D.00000028.backup.zst",
                "00000001000000000000000D.zst",
                "00000002.history.zst",
                "00000002000000000000000C.zst",
            ]
        );
    }

    #[test]
    fn nothing_is_pruned_before_a_base_is_a_day_old() {
        let dir = tempfile::tempdir().expect("scratch");
        for f in [
            "000000010000000000000003.zst",
            "000000010000000000000004.00000028.backup.zst",
        ] {
            std::fs::write(dir.path().join(f), b"x").expect("written");
        }
        let script = prune_script().replace(SITE_DIR, &dir.path().to_string_lossy());
        let out = std::process::Command::new("sh")
            .args(["-c", &script])
            .output()
            .expect("sh");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout), "");
        assert_eq!(std::fs::read_dir(dir.path()).expect("read").count(), 2);
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
    #[test]
    fn the_site_s_labels_say_how_far_back_a_restore_reaches() {
        let out = "received=1762900000\nlabel=1762862960.4630000000\nlabel=1762800000.1\n";
        let site = parse_site_labels(out);
        assert_eq!(
            site,
            SiteLabels {
                received: Some(1_762_900_000),
                oldest_label: Some(1_762_800_000)
            }
        );
        let base = |id: &str, at| crate::pitr::BaseBackup {
            id: id.into(),
            finished_at: at,
        };
        let bases = [
            base("pruned", 1_762_700_000),
            base("its-label-just-after", 1_762_800_000 - 20),
            base("this-morning", 1_762_862_940),
        ];
        let usable: Vec<String> = usable_bases(&bases, &site)
            .into_iter()
            .map(|b| b.id)
            .collect();
        assert_eq!(usable, ["its-label-just-after", "this-morning"]);
        // A site with no label keeps no base's WAL.
        assert!(usable_bases(&bases, &parse_site_labels("received=\n")).is_empty());
        assert_eq!(parse_site_labels("received=\n").received, None);
    }

    #[test]
    fn the_labels_script_reads_the_site_s_own_paths() {
        let s = site_labels_script();
        assert!(s.contains(SITE_RECEIVED) && s.contains(SITE_DIR), "{s}");
        let out = std::process::Command::new("sh")
            .args(["-n", "-c", &s])
            .output()
            .expect("sh");
        assert!(out.status.success());
    }
}
