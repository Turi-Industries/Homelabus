//! ZFS pools and datasets, for a node that carries the storage.
//!
//! ## 🔴 This module NEVER creates a pool by itself
//!
//! Creating a pool writes labels to the disks and destroys whatever was on them. There
//! is no confirmation from ZFS and no way back. So the decision is split in two: this
//! module reads what is there and says what it would do; creating one is an explicit
//! command with the disks named by the operator.
//!
//! Importing, by contrast, is safe and reversible — `zpool export` puts it back — so an
//! importable pool is offered without ceremony.
//!
//! ## Why parse text rather than call a library
//!
//! There is no stable Rust binding to libzfs, and shelling out to `zpool`/`zfs` is what
//! every tool in this space does. The parsing lives here, pure, so the reasoning is
//! testable without a pool.

/// A pool as `zpool list` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pool {
    pub name: String,
    /// `ONLINE`, `DEGRADED`, `FAULTED`, `UNAVAIL`…
    pub health: String,
    /// Free space, in bytes. `None` when the field could not be read.
    pub free_bytes: Option<u64>,
}

/// How much attention a pool deserves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolHealth {
    Online,
    /// 🔴 A disk is gone and the pool still answers. It is the state you must act on:
    /// the redundancy that was protecting you is spent, and the next failure is the one
    /// that loses data.
    Degraded,
    /// 🔴 The pool cannot be read.
    Faulted,
    /// Not a health value we know. Reported as-is rather than assumed healthy.
    Unknown,
}

impl Pool {
    pub fn health(&self) -> PoolHealth {
        match self.health.to_ascii_uppercase().as_str() {
            "ONLINE" => PoolHealth::Online,
            "DEGRADED" => PoolHealth::Degraded,
            "FAULTED" | "UNAVAIL" | "REMOVED" => PoolHealth::Faulted,
            _ => PoolHealth::Unknown,
        }
    }

    pub fn describe(&self) -> String {
        let free = match self.free_bytes {
            Some(b) => format!("{} GB free", b / 1_000_000_000),
            // ⚠️ Not "0 GB": a field we could not read is not an empty pool, and the
            // difference decides whether you go and buy a disk.
            None => "free space unreadable".to_string(),
        };
        match self.health() {
            PoolHealth::Online => format!("{} is ONLINE, {free}", self.name),
            PoolHealth::Degraded => format!(
                "{} is DEGRADED, {free} - a disk is gone and the redundancy that was \
                 protecting you is spent. The next failure is the one that loses data.",
                self.name
            ),
            PoolHealth::Faulted => {
                format!("{} is {} - the pool cannot be read", self.name, self.health)
            }
            PoolHealth::Unknown => {
                format!(
                    "{} reports \"{}\", which we do not know",
                    self.name, self.health
                )
            }
        }
    }
}

/// Parses `zpool list -H -o name,health,free -p`.
///
/// `-H` drops the header and separates with tabs, `-p` gives exact bytes rather than
/// "3.62T" — a human-readable size parsed back is a rounding error waiting.
pub fn parse_pools(output: &str) -> Vec<Pool> {
    output
        .lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            let name = f.next()?.trim();
            if name.is_empty() {
                return None;
            }
            Some(Pool {
                name: name.to_string(),
                health: f.next().unwrap_or("UNKNOWN").trim().to_string(),
                free_bytes: f.next().and_then(|v| v.trim().parse().ok()),
            })
        })
        .collect()
}

/// Parses `zpool import` — the pools present on the disks but not imported.
///
/// ⚠️ Its output is prose, not a table: `pool: tank` on its own line. A pool listed
/// here is one this machine could take over — which, after an OS reinstall, is exactly
/// the pool you are looking for.
pub fn parse_importable(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pool:"))
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .collect()
}

/// What Homelabus would do about the storage on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolDecision {
    /// The pool is already imported. Nothing to do.
    Ready { pool: String },
    /// 🔴 Present on the disks, not imported. One command away, and reversible.
    Importable { pool: String },
    /// No pool at all. Creating one DESTROYS disks, so it is never done from here.
    Absent,
    /// Several pools and no way to choose. Naming one is the operator's call.
    Ambiguous { pools: Vec<String> },
}

impl PoolDecision {
    /// Decides from what the machine reports.
    ///
    /// `wanted` is the pool named by the operator, when they named one.
    pub fn decide(imported: &[Pool], importable: &[String], wanted: Option<&str>) -> Self {
        if let Some(w) = wanted {
            if imported.iter().any(|p| p.name == w) {
                return Self::Ready { pool: w.into() };
            }
            if importable.iter().any(|p| p == w) {
                return Self::Importable { pool: w.into() };
            }
            return Self::Absent;
        }

        match (imported.len(), importable.len()) {
            (1, 0) => Self::Ready {
                pool: imported[0].name.clone(),
            },
            (0, 1) => Self::Importable {
                pool: importable[0].clone(),
            },
            (0, 0) => Self::Absent,
            // 🔴 One imported AND one importable is NOT "use the imported one". After
            // an OS reinstall that is precisely the dangerous shape: a fresh empty pool
            // imported by the installer, and the real data pool still on the disks.
            // 🔴 Guessing here would import or use the wrong pool. Two pools on one
            // machine is a deliberate arrangement, and only its author knows which one
            // holds the application data.
            _ => {
                let mut pools: Vec<String> = imported.iter().map(|p| p.name.clone()).collect();
                pools.extend(importable.iter().cloned());
                pools.sort();
                pools.dedup();
                Self::Ambiguous { pools }
            }
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Ready { pool } => format!("pool \"{pool}\" is imported and ready"),
            Self::Importable { pool } => format!(
                "pool \"{pool}\" is on the disks but not imported. Importing is \
                 reversible: zpool export puts it back"
            ),
            Self::Absent => "no pool found. Creating one DESTROYS the disks it is given, \
                             so it is never done automatically"
                .to_string(),
            Self::Ambiguous { pools } => format!(
                "several pools ({}) and none named. Only you know which one holds the \
                 application data - name it with --pool",
                pools.join(", ")
            ),
        }
    }
}

/// The dataset a volume of `app` should live on, under `root`.
///
/// ⚠️ One dataset per volume, not one per app: a dataset is the unit ZFS snapshots and
/// sends. Sharing one between an app's database dump and its media would mean rolling
/// back both to undo one.
pub fn dataset_for(root: &str, app: &str, volume: &str) -> String {
    format!("{}/{app}/{volume}", root.trim_end_matches('/'))
}

/// Who owns what the NFS clients write. Every client user is squashed to it, and the
/// `tier: nfs` datasets belong to it.
///
/// 🔴 Under `root_squash` alone the apps on NFS (Immich, Jellyfin, Seafile: root in
/// their images) became `nobody` facing root-owned 755 datasets, and could write
/// nothing. `all_squash` to one owner keeps the rule — an app is never root on the NAS —
/// and lets them write. What it costs: a `chown` on the export is refused.
pub const NFS_OWNER: u32 = 10_000;

/// Where a dataset's files are, from `zfs get -H -o value mountpoint <dataset>`.
///
/// ⚠️ `none` and `legacy` are values of the property, not paths: handed to `chown` as
/// one, they failed on a relative file nobody named. Refused with what to do instead.
pub fn mountpoint(dataset: &str, value: &str) -> Result<String, String> {
    match value.trim() {
        "none" => Err(format!(
            "{dataset} has mountpoint=none: its files are mounted nowhere, so no container \
             can reach them — zfs inherit mountpoint {dataset}, or zfs set \
             mountpoint=<path> {dataset}"
        )),
        "legacy" => Err(format!(
            "{dataset} has mountpoint=legacy: it mounts through /etc/fstab, at a path ZFS \
             does not say — zfs inherit mountpoint {dataset}, or zfs set \
             mountpoint=<path> {dataset}"
        )),
        path if path.starts_with('/') => Ok(path.to_string()),
        other => Err(format!(
            "{dataset} has no mount point zfs could say (\"{other}\"): zfs get mountpoint \
             {dataset}"
        )),
    }
}

/// The `/etc/exports` line for a dataset.
///
/// 🔴 `no_subtree_check` is not decoration: without it, a client that has a file open
/// when the export is reloaded gets a stale handle, and the application sees an I/O
/// error it cannot retry. `crossmnt` because each volume is a dataset of its own, so a
/// filesystem of its own: without it a client sees an empty directory, and every
/// `tier: nfs` mount fails with "no such file or directory" (found on a real export).
/// `all_squash`: see [`NFS_OWNER`].
pub fn export_line(path: &str, network: &str) -> String {
    format!(
        "{path} {network}(rw,sync,no_subtree_check,crossmnt,all_squash,anonuid={NFS_OWNER},anongid={NFS_OWNER})"
    )
}

/// The key of a storage node's encrypted datasets: 32 random bytes in hex, root's alone.
/// One per node, and in the vault and on the emergency kit — the pool's disks carried
/// to another machine open with it and nothing else.
pub const KEY_FILE: &str = "/etc/hlb/zfs.key";
/// What a dataset encrypted by Homelabus names as its `keylocation`.
pub const KEY_LOCATION: &str = "file:///etc/hlb/zfs.key";

/// The `zfs create` / `zfs recv` options that encrypt a dataset under [`KEY_FILE`]. Each
/// dataset is its own encryption root: one encrypted in place of a plain one cannot
/// inherit from a parent that is not.
pub fn encryption_options() -> Vec<String> {
    [
        "encryption=aes-256-gcm",
        "keyformat=hex",
        &format!("keylocation={KEY_LOCATION}"),
    ]
    .iter()
    .flat_map(|o| ["-o".to_string(), o.to_string()])
    .collect()
}

pub const LOAD_KEY_UNIT: &str = "hlb-zfs-load-key.service";
pub const LOAD_KEY_UNIT_PATH: &str = "/etc/systemd/system/hlb-zfs-load-key.service";
pub const LOAD_KEY_SCRIPT: &str = "/usr/local/lib/hlb/zfs-load-key";

/// Loads the key of every dataset encrypted under [`KEY_FILE`], mounts them, and FAILS
/// unless every one is mounted.
///
/// Its own loop, never `zfs load-key -a` and `zfs mount -a`: a dataset someone else
/// encrypted, its key typed at a prompt, would fail the boot unit — and keep Docker
/// down over a pool that is not ours to judge.
pub const LOAD_KEY_SCRIPT_CONTENT: &str = r#"#!/bin/sh
# Written by Homelabus (`hlb storage encrypt`): the keys of the datasets encrypted
# under /etc/hlb/zfs.key, loaded and mounted at boot. Fails unless every one of them
# is mounted: Docker and the NFS server wait for it.
set -eu
roots=$(zfs list -H -o name,keylocation -t filesystem |
	awk -F '\t' '$2 == "file:///etc/hlb/zfs.key" { print $1 }')
[ -n "$roots" ] || exit 0
printf '%s\n' "$roots" | while IFS= read -r root; do
	[ "$(zfs get -H -o value keystatus "$root")" = available ] || zfs load-key "$root"
done
unmounted() {
	zfs list -H -o name,encryptionroot,canmount,mounted -t filesystem |
		awk -F '\t' -v roots="$roots" '
			BEGIN { n = split(roots, r, "\n"); for (i = 1; i <= n; i++) ours[r[i]] = 1 }
			($2 in ours) && $3 == "on" && $4 != "yes" { print $1 }'
}
# Listed parents first, so a child mounts on its parent and not beneath it.
unmounted | while IFS= read -r dataset; do zfs mount "$dataset"; done
left=$(unmounted)
[ -z "$left" ] || { printf 'not mounted: %s\n' "$left" >&2; exit 1; }
"#;

/// 🔴 Debian masks `zfs-load-key.service`, and `zfs-mount` runs `zfs mount -a` without
/// `-l`: an encrypted dataset stays locked and unmounted at boot, and "Finishes"
/// (measured on ZFS 2.1 and 2.3). Its mount point is then an EMPTY directory of the
/// plaintext parent — a bind mount there writes in clear, and PostgreSQL would `initdb`.
///
/// After `zfs-mount`, before `local-fs.target`, so before every ordinary service. No
/// `ConditionPathExists` on the key: a skipped unit counts as started, and Docker would
/// come up over the empty directories.
pub const LOAD_KEY_UNIT_CONTENT: &str = "\
# Written by Homelabus (`hlb storage encrypt`): the encrypted datasets' keys, loaded
# and mounted before anything writes to them.
[Unit]
Description=Homelabus encrypted datasets, unlocked and mounted
DefaultDependencies=no
After=zfs-import.target zfs-mount.service
Before=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/lib/hlb/zfs-load-key

[Install]
WantedBy=zfs.target
";

/// What must not start while a dataset is locked: it would write beneath it, in clear.
pub const GUARDED_UNITS: [&str; 2] = ["docker.service", "nfs-server.service"];

/// The drop-in keeping `unit` down unless the datasets are mounted. ⚠️ `Requires=`
/// also carries a RESTART of the load-key unit to Docker: it is never restarted, and
/// what checks it again runs [`LOAD_KEY_SCRIPT`] itself.
pub fn guard_path(unit: &str) -> String {
    format!("/etc/systemd/system/{unit}.d/hlb-zfs-load-key.conf")
}

pub const GUARD_CONTENT: &str = "\
# Written by Homelabus (`hlb storage encrypt`): never over a locked dataset.
[Unit]
Requires=hlb-zfs-load-key.service
After=hlb-zfs-load-key.service
";

/// The steps that unlock the datasets at every boot, and hold Docker and the NFS server
/// until they are. The key file is the caller's: it is compared, never overwritten.
pub fn boot_steps() -> Vec<crate::provision::Step> {
    use crate::provision::{Action, Phase, Step};
    let install = |what: &str, path: String, content: &str, mode: u32| Step {
        phase: Phase::Configuration,
        what: what.to_string(),
        action: Action::Install {
            path,
            content: content.to_string(),
            mode,
        },
    };
    let mut steps = vec![
        install(
            "the script that unlocks and mounts them",
            LOAD_KEY_SCRIPT.into(),
            LOAD_KEY_SCRIPT_CONTENT,
            0o755,
        ),
        install(
            "the unit that runs it at boot, before any service",
            LOAD_KEY_UNIT_PATH.into(),
            LOAD_KEY_UNIT_CONTENT,
            0o644,
        ),
    ];
    for unit in GUARDED_UNITS {
        steps.push(install(
            &format!("{unit} waits for it, and does not start if it fails"),
            guard_path(unit),
            GUARD_CONTENT,
            0o644,
        ));
    }
    let run = |what: &str, argv: &[&str]| Step {
        phase: Phase::Services,
        what: what.to_string(),
        action: Action::Run(argv.iter().map(|s| s.to_string()).collect()),
    };
    steps.push(run("read the units", &["systemctl", "daemon-reload"]));
    // `enable`, not `--now`: the datasets are unlocked already, and starting it is a
    // job Docker's `Requires=` would then follow on every later restart of it.
    steps.push(run(
        "run it at every boot",
        &["systemctl", "enable", LOAD_KEY_UNIT],
    ));
    steps
}

/// A filesystem dataset, as [`list_datasets`] lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dataset {
    pub name: String,
    /// `off`, or the cipher.
    pub encryption: String,
    /// `none` below an encryption root, `-` on a plain dataset.
    pub keylocation: String,
    pub mounted: bool,
    pub mountpoint: String,
    /// Bytes its files take: what a copy reads and writes.
    pub referenced: Option<u64>,
}

impl Dataset {
    /// Encrypted by Homelabus: its own root, keyed by [`KEY_FILE`].
    pub fn ours(&self) -> bool {
        self.encryption != "off" && self.keylocation == KEY_LOCATION
    }
}

/// Command line listing the datasets [`parse_datasets`] reads, under `base`.
pub fn list_datasets(base: &str) -> Vec<String> {
    [
        "zfs",
        "list",
        "-H",
        "-p",
        "-o",
        "name,encryption,keylocation,mounted,mountpoint,referenced",
        "-t",
        "filesystem",
        "-r",
        base,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub fn parse_datasets(output: &str) -> Vec<Dataset> {
    output
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            let [name, encryption, keylocation, mounted, mountpoint, referenced] = f.as_slice()
            else {
                return None;
            };
            Some(Dataset {
                name: name.to_string(),
                encryption: encryption.to_string(),
                keylocation: keylocation.to_string(),
                mounted: *mounted == "yes",
                mountpoint: mountpoint.to_string(),
                referenced: referenced.trim().parse().ok(),
            })
        })
        .collect()
}

/// The encrypted copy of a volume while it is made, and the plain one until the copy is
/// checked: both names are read back by a run that resumes.
pub const COPY_SUFFIX: &str = ".hlb-enc";
pub const PLAIN_SUFFIX: &str = ".hlb-plain";
/// The snapshot a volume is copied from.
pub const SNAPSHOT: &str = "hlb-encrypt";

/// What encrypting a volume's dataset still needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Migration {
    /// Encrypted under the node's key, nothing left over.
    Done,
    /// Encrypted, but by something else — an encrypted parent, a key typed at a prompt.
    /// Not Homelabus's to unlock at boot, nor to copy.
    Foreign,
    /// Plain: copied encrypted, swapped, the plain one destroyed. `stale` is a copy an
    /// interrupted run left, discarded first: the volume may have changed since.
    Copy { stale: bool },
    /// Interrupted between the two renames: the copy goes in place, then is checked.
    Finish,
    /// The copy is in place and checked; the plain one is left to destroy.
    Clean,
    /// A shape no run of Homelabus leaves. Nothing is done; it is said.
    Stuck(String),
}

/// What each volume dataset under `base` needs — the `<app>/<volume>` level, as
/// [`dataset_for`] names them — sorted by name.
pub fn migrations(base: &str, datasets: &[Dataset]) -> Vec<(String, Migration)> {
    let base = base.trim_end_matches('/');
    let find = |name: &str| datasets.iter().find(|d| d.name == name);
    let mut volumes: Vec<String> = datasets
        .iter()
        .filter_map(|d| {
            let rest = d.name.strip_prefix(base)?.strip_prefix('/')?;
            let (app, volume) = rest.split_once('/')?;
            if volume.contains('/') {
                return None;
            }
            let volume = volume
                .strip_suffix(COPY_SUFFIX)
                .or_else(|| volume.strip_suffix(PLAIN_SUFFIX))
                .unwrap_or(volume);
            Some(format!("{base}/{app}/{volume}"))
        })
        .collect();
    volumes.sort();
    volumes.dedup();
    volumes
        .into_iter()
        .map(|v| {
            let copy = find(&format!("{v}{COPY_SUFFIX}"));
            let plain = find(&format!("{v}{PLAIN_SUFFIX}"));
            let m = match (find(&v), copy, plain) {
                (Some(d), None, None) if d.ours() => Migration::Done,
                (Some(d), None, Some(_)) if d.ours() => Migration::Clean,
                (Some(d), None, None) if d.encryption != "off" => Migration::Foreign,
                (Some(d), copy, None) if d.encryption == "off" => Migration::Copy {
                    stale: copy.is_some(),
                },
                (None, Some(c), Some(_)) if c.ours() => Migration::Finish,
                (Some(_), _, Some(_)) => Migration::Stuck(format!(
                    "both {v} and {v}{PLAIN_SUFFIX} exist: which holds the volume is \
                     yours to say — zfs destroy -r the other"
                )),
                (None, None, Some(_)) => Migration::Stuck(format!(
                    "{v} is missing and {v}{PLAIN_SUFFIX} holds it: zfs rename \
                     {v}{PLAIN_SUFFIX} {v}"
                )),
                _ => Migration::Stuck(format!(
                    "{v}: neither it nor its encrypted copy can be used — zfs list -r {v}"
                )),
            };
            (v, m)
        })
        .collect()
}

/// A dataset's local properties a copy must carry — `zfs get -H -s local -o
/// property,value all` — as `-o` options. ⚠️ `zfs send` without `-p` carries none, and
/// with `-p` it would carry the plain dataset's `encryption=off` too. A local
/// `mountpoint` is refused: the copy would claim the path the volume still holds.
pub fn carried_properties(dataset: &str, output: &str) -> Result<Vec<String>, String> {
    let mut options = Vec::new();
    for l in output.lines().filter(|l| !l.trim().is_empty()) {
        let Some((property, value)) = l.split_once('\t') else {
            continue;
        };
        if property == "mountpoint" {
            return Err(format!(
                "{dataset} has mountpoint={value} set on it: its encrypted copy cannot \
                 take the path while it holds it — zfs inherit mountpoint {dataset}, and \
                 bind the path elsewhere if you need it"
            ));
        }
        options.push("-o".to_string());
        options.push(format!("{property}={value}"));
    }
    Ok(options)
}

/// The `sh -c` script copying `volume` encrypted, from its snapshot: `zfs send` writes
/// to a pipe. A send that stops midway ends the stream early, and `zfs recv` refuses
/// an incomplete one — the receiving side is what decides, so its status is the one
/// read. Received unmounted (`-u`): it would mount over the path the volume holds.
pub fn copy_script(volume: &str, properties: &[String]) -> String {
    let mut recv = vec!["zfs".to_string(), "recv".into(), "-u".into()];
    recv.extend(encryption_options());
    recv.extend(properties.iter().cloned());
    recv.push(format!("{volume}{COPY_SUFFIX}"));
    format!(
        "zfs send {} | {}",
        quote(&format!("{volume}@{SNAPSHOT}")),
        recv.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")
    )
}

/// The `sh -c` script that prints one line per file under `path` — its relative path,
/// size, mode, owner, group, modification time and link target — sorted, then hashed.
/// Two trees giving the same hash hold the same files as the applications see them;
/// the bytes themselves are checked by `zfs recv`, which refuses a stream whose
/// checksum does not match. ⚠️ `logicalreferenced` is NOT a check: encryption adds
/// metadata (5 163 520 bytes plain, 5 202 432 encrypted, for the same files).
pub fn tree_script(path: &str) -> String {
    format!(
        "cd {} && find . -xdev -printf '%P\\t%s\\t%m\\t%U\\t%G\\t%T@\\t%l\\n' | LC_ALL=C sort \
         | sha256sum",
        quote(path)
    )
}

/// The `sh -c` script printing every other place the dataset mounted at `path` is
/// mounted, in any mount namespace: a Docker volume binding it, a container's view.
///
/// 🔴 `zfs rename` unmounts the dataset's own mount point and nothing else — measured
/// with a container writing through a bind of it, the rename SUCCEEDED, and the
/// container kept writing into the original set aside. Only the `destroy` after it
/// failed "dataset is busy". So the copy waits until nothing else holds the volume.
pub fn holders_script(path: &str) -> String {
    format!(
        "dev=$(awk -v mp={p} '$5 == mp && $9 == \"zfs\" {{ print $3; exit }}' \
         /proc/self/mountinfo); [ -z \"$dev\" ] || cat /proc/[0-9]*/mountinfo 2>/dev/null \
         | awk -v d=\"$dev\" -v mp={p} '$3 == d && $5 != mp {{ print $5 }}' | sort -u",
        p = quote(path)
    )
}

/// Single-quoted for `sh`, unless it needs no quoting.
fn quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// Reads a `zpool` run, refusing a failed one.
///
/// 🔴 A failed `zpool` prints nothing on stdout, which parses as "no pool": with the
/// module not loaded, a machine whose pool sat on its disks was told it had none and
/// how to create one.
pub fn answered<T>(
    succeeded: bool,
    stdout: &str,
    stderr: &str,
    parse: impl Fn(&str) -> T,
) -> Result<T, String> {
    if succeeded {
        Ok(parse(stdout))
    } else {
        Err(stderr.trim().to_string())
    }
}

/// Why the pools could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unread {
    /// No `zpool` at all: ZFS is not installed — fixed with a package, not with disks.
    Missing,
    /// `zpool` answered an error, with what it said.
    Failed(String),
}

/// The pools `runner`'s machine has imported, and those on its disks it could import.
/// ⚠️ A failing `zpool` is not an empty machine: see [`answered`].
pub async fn read_pools(
    runner: &dyn crate::Runner,
) -> crate::runner::Result<Result<(Vec<Pool>, Vec<String>), Unread>> {
    let run = |args: &[&str]| -> Vec<String> { args.iter().map(|a| a.to_string()).collect() };
    // Locally a missing binary is an error; over SSH it is the shell's 127.
    let listed = match runner
        .run(&run(&[
            "zpool",
            "list",
            "-H",
            "-o",
            "name,health,free",
            "-p",
        ]))
        .await
    {
        Ok(o) if o.status != 127 => o,
        _ => return Ok(Err(Unread::Missing)),
    };
    let importing = runner.run(&run(&["zpool", "import"])).await?;
    Ok(
        answered(listed.ok(), &listed.stdout, &listed.stderr, parse_pools)
            .and_then(|imported| {
                answered(
                    importing.ok(),
                    &importing.stdout,
                    &importing.stderr,
                    parse_importable,
                )
                .map(|importable| (imported, importable))
            })
            .map_err(Unread::Failed),
    )
}

/// Where the kernel module comes from, on a storage node that lacks `zfs`.
///
/// The tools alone are not ZFS: without the module every `zpool` fails, and nothing
/// says so until the first `hlb storage init`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// A repository section to add before the index is refreshed, as (path, content).
    pub repository: Option<(String, String)>,
    /// Installed beside the tools.
    pub packages: Vec<String>,
}

/// Debian's `contrib` for this release, in a file of Homelabus's own: the machine's
/// sources may name a local mirror, and rewriting them is not ours to do.
pub const DEBIAN_CONTRIB: &str = "/etc/apt/sources.list.d/hlb-contrib.sources";

/// Decides [`Source`], or refuses with what to do instead.
///
/// `kernel` is `uname -r`; `contrib` says Debian's `contrib` is already configured for
/// this release — adding it twice makes every later `apt-get update` warn.
pub fn source(
    distro: &crate::distro::Distro,
    kernel: Option<&str>,
    contrib: bool,
) -> Result<Source, String> {
    use crate::distro::Family;
    if distro.id == "ubuntu" || distro.ubuntu_codename.is_some() {
        // Ubuntu builds the module into its kernel packages.
        return Ok(Source {
            repository: None,
            packages: Vec::new(),
        });
    }
    let kernel = kernel.ok_or("the running kernel could not be read (uname -r)")?;
    let flavour = kernel_flavour(kernel);
    match (distro.id.as_str(), distro.family) {
        ("debian", _) => {
            let codename = distro
                .codename
                .as_deref()
                .ok_or("Debian's release has no codename in /etc/os-release")?;
            let repository = (!contrib).then(|| {
                // sid has no -updates and no security archive.
                let (suites, security) = if codename == "sid" {
                    ("sid".to_string(), String::new())
                } else {
                    (
                        format!("{codename} {codename}-updates"),
                        format!(
                            "\nTypes: deb\nURIs: http://security.debian.org/debian-security\n\
                             Suites: {codename}-security\nComponents: contrib\n\
                             Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
                        ),
                    )
                };
                (
                    DEBIAN_CONTRIB.to_string(),
                    format!(
                        "# Written by Homelabus: Debian publishes ZFS in contrib.\n\
                         Types: deb\nURIs: http://deb.debian.org/debian\nSuites: {suites}\n\
                         Components: contrib\n\
                         Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg\n{security}"
                    ),
                )
            });
            // DKMS builds against headers: the running kernel's now, and the flavour's
            // metapackage so the next kernel gets its own before it boots.
            let mut packages = vec![
                "zfs-dkms".to_string(),
                "zfs-zed".to_string(),
                format!("linux-headers-{kernel}"),
            ];
            packages.extend(flavour.map(|f| format!("linux-headers-{f}")));
            Ok(Source {
                repository,
                packages,
            })
        }
        (_, Family::Alpine) => {
            // One module package per kernel flavour: `zfs-lts` for `linux-lts`.
            let flavour = flavour.ok_or_else(|| {
                format!("the kernel {kernel} names no flavour to pick ZFS's module by")
            })?;
            Ok(Source {
                repository: None,
                packages: vec![format!("zfs-{flavour}")],
            })
        }
        _ => Err(format!(
            "ZFS is not in {}'s own repositories, and Homelabus adds no third-party kernel \
             module: install OpenZFS as https://openzfs.github.io/openzfs-docs/Getting%20Started/ \
             describes for it, then run this again — once `zfs` answers, this step is skipped",
            distro.pretty_name
        )),
    }
}

/// The kernel flavour `uname -r` names, which picks the headers' metapackage on Debian
/// and the module package on Alpine.
///
/// `6.1.0-53-cloud-amd64` → `cloud-amd64`, `6.12.13-0-lts` → `lts`. ⚠️ Debian 13 dropped
/// the ABI number for a `+debNN` suffix: `6.12.43+deb13-amd64` read as three dashes gave
/// nothing, the metapackage was never installed, and the next kernel booted with no
/// headers for DKMS to build ZFS against — the pool gone after an ordinary upgrade.
pub fn kernel_flavour(kernel: &str) -> Option<&str> {
    let flavour = match kernel.split_once('+') {
        // `+deb13-amd64`, `+deb14+1-cloud-amd64`: the flavour follows the suffix's dash.
        Some((_, suffix)) => suffix.split_once('-').map(|(_, f)| f),
        None => kernel.splitn(3, '-').nth(2),
    };
    flavour.filter(|f| !f.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dataset_mounted_nowhere_is_refused_by_name() {
        assert_eq!(
            mountpoint("tank/apps/gitea/data", "/tank/apps/gitea/data\n").as_deref(),
            Ok("/tank/apps/gitea/data")
        );
        for value in ["none", "legacy", "-", ""] {
            let refusal = mountpoint("tank/apps/x", value).expect_err(value);
            assert!(refusal.contains("tank/apps/x"), "{refusal}");
        }
        assert!(mountpoint("t/x", "legacy")
            .expect_err("legacy")
            .contains("fstab"));
    }

    fn ds(name: &str, encryption: &str, keylocation: &str) -> Dataset {
        Dataset {
            name: name.into(),
            encryption: encryption.into(),
            keylocation: keylocation.into(),
            mounted: true,
            mountpoint: format!("/{name}"),
            referenced: Some(98_304),
        }
    }

    #[test]
    fn a_dataset_list_is_read_column_by_column() {
        let out = "tank/apps/a/data\taes-256-gcm\tfile:///etc/hlb/zfs.key\tyes\t/tank/apps/a/data\t81310208\n\
                   tank/apps/b/data\toff\t-\tno\t/srv/b data\t43008\n";
        let d = parse_datasets(out);
        assert_eq!(d.len(), 2);
        assert!(d[0].ours() && d[0].mounted);
        assert_eq!(d[0].referenced, Some(81_310_208));
        assert!(!d[1].ours() && !d[1].mounted);
        assert_eq!(d[1].mountpoint, "/srv/b data");
        assert_eq!(
            list_datasets("tank/apps").last().map(String::as_str),
            Some("tank/apps")
        );
    }

    #[test]
    fn each_volume_says_what_encrypting_it_still_needs() {
        let plain = |n: &str| ds(n, "off", "-");
        let ours = |n: &str| ds(n, "aes-256-gcm", KEY_LOCATION);
        let datasets = vec![
            plain("tank/apps"),
            plain("tank/apps/gitea"),
            plain("tank/apps/gitea/data"),
            plain("tank/apps/immich"),
            ours("tank/apps/immich/data"),
            ours("tank/apps/immich/cache"),
            plain("tank/apps/immich/cache.hlb-plain"),
            plain("tank/apps/jellyfin/media"),
            ours("tank/apps/jellyfin/media.hlb-enc"),
            ours("tank/apps/seafile/shared.hlb-enc"),
            plain("tank/apps/seafile/shared.hlb-plain"),
            ds("tank/apps/vault/data", "aes-256-gcm", "prompt"),
            ds("tank/apps/n8n/data", "aes-256-gcm", "none"),
            plain("tank/apps/x/lost.hlb-plain"),
            plain("tank/apps/y/both"),
            plain("tank/apps/y/both.hlb-plain"),
            // Below a volume: not a volume of its own.
            plain("tank/apps/gitea/data/deeper"),
        ];
        let got = migrations("tank/apps/", &datasets);
        let want = [
            ("tank/apps/gitea/data", Migration::Copy { stale: false }),
            ("tank/apps/immich/cache", Migration::Clean),
            ("tank/apps/immich/data", Migration::Done),
            ("tank/apps/jellyfin/media", Migration::Copy { stale: true }),
            ("tank/apps/n8n/data", Migration::Foreign),
            ("tank/apps/seafile/shared", Migration::Finish),
            ("tank/apps/vault/data", Migration::Foreign),
        ];
        for (name, m) in &want {
            assert_eq!(
                got.iter().find(|(n, _)| n == name).map(|(_, m)| m),
                Some(m),
                "{name}"
            );
        }
        for stuck in ["tank/apps/x/lost", "tank/apps/y/both"] {
            assert!(
                matches!(
                    got.iter().find(|(n, _)| n == stuck),
                    Some((_, Migration::Stuck(why))) if why.contains("zfs ")
                ),
                "{stuck} must be refused with what to run: {got:?}"
            );
        }
        assert_eq!(got.len(), want.len() + 2, "{got:?}");
    }

    #[test]
    fn a_copy_carries_the_volumes_own_properties_but_never_its_path() {
        let carried =
            carried_properties("tank/apps/a/b", "compression\tlz4\nrecordsize\t1048576\n")
                .expect("carried");
        assert_eq!(
            carried,
            ["-o", "compression=lz4", "-o", "recordsize=1048576"]
        );
        let refused = carried_properties("tank/apps/a/b", "mountpoint\t/srv/b\n")
            .expect_err("a local mountpoint");
        assert!(
            refused.contains("zfs inherit mountpoint tank/apps/a/b"),
            "{refused}"
        );

        let s = copy_script("tank/apps/a/b c", &carried);
        assert!(
            s.starts_with("zfs send 'tank/apps/a/b c@hlb-encrypt' | zfs recv -u "),
            "{s}"
        );
        for part in [
            "encryption=aes-256-gcm",
            "keyformat=hex",
            "keylocation=file:///etc/hlb/zfs.key",
            "compression=lz4",
            "'tank/apps/a/b c.hlb-enc'",
        ] {
            assert!(s.contains(part), "{part}: {s}");
        }
    }

    #[test]
    fn a_holder_is_any_other_mount_of_the_same_filesystem() {
        let s = holders_script("/tank/apps/a b/data");
        // The device is read where the dataset itself is mounted, then looked for in
        // every process's mount table — a container's included.
        assert!(s.contains("/proc/self/mountinfo"), "{s}");
        assert!(s.contains("/proc/[0-9]*/mountinfo"), "{s}");
        assert!(s.contains("$5 != mp"), "{s}");
        assert!(s.contains("'/tank/apps/a b/data'"), "{s}");
    }

    #[test]
    fn nothing_writes_beneath_a_locked_dataset() {
        // A skipped unit counts as started: the key's absence must FAIL it.
        assert!(!LOAD_KEY_UNIT_CONTENT.contains("Condition"));
        for line in [
            "DefaultDependencies=no",
            "After=zfs-import.target zfs-mount.service",
            "Before=local-fs.target",
            "RemainAfterExit=yes",
            &format!("ExecStart={LOAD_KEY_SCRIPT}"),
        ] {
            assert!(LOAD_KEY_UNIT_CONTENT.lines().any(|l| l == line), "{line}");
        }
        let steps = boot_steps();
        for unit in ["docker.service", "nfs-server.service"] {
            assert!(
                steps.iter().any(|s| matches!(&s.action,
                    crate::provision::Action::Install { path, content, .. }
                        if *path == guard_path(unit)
                        && content.contains(&format!("Requires={LOAD_KEY_UNIT}"))
                        && content.contains(&format!("After={LOAD_KEY_UNIT}")))),
                "{unit}"
            );
        }
        assert!(LOAD_KEY_SCRIPT_CONTENT.contains(KEY_LOCATION));
    }

    /// Runs the boot script against a `zfs` that answers from a table, as the real one
    /// would: `(status, table after, stderr)`.
    fn boot_script(table: &str, key_fails: bool) -> (i32, String, String) {
        let dir = tempfile::tempdir().expect("temp dir");
        let state = dir.path().join("table");
        std::fs::write(&state, table).expect("table");
        // Columns: name keylocation keystatus encryptionroot canmount mounted.
        let fake = format!(
            r#"#!/bin/sh
t={state}
col() {{ case "$1" in name) echo 1;; keylocation) echo 2;; keystatus) echo 3;; encryptionroot) echo 4;; canmount) echo 5;; mounted) echo 6;; esac; }}
set_field() {{ awk -F '\t' -v OFS='\t' -v n="$1" -v c="$2" -v v="$3" '$1 == n {{ $c = v }} {{ print }}' "$t" > "$t.new" && mv "$t.new" "$t"; }}
case "$1" in
list)
    cols=$4; idx=""
    for c in $(echo "$cols" | tr , ' '); do idx="$idx $(col "$c")"; done
    awk -F '\t' -v idx="$idx" 'BEGIN {{ n = split(idx, i, " ") }} {{ s = $i[1]; for (k = 2; k <= n; k++) s = s "\t" $i[k]; print s }}' "$t" ;;
get) awk -F '\t' -v n="$6" -v c="$(col "$5")" '$1 == n {{ print $c }}' "$t" ;;
load-key)
    [ -z "${{KEY_FAILS:-}}" ] || {{ echo "Key load error: Failed to open key material file" >&2; exit 255; }}
    set_field "$2" 3 available ;;
mount)
    root=$(awk -F '\t' -v n="$2" '$1 == n {{ print $4 }}' "$t")
    [ "$root" = - ] || [ "$(awk -F '\t' -v r="$root" '$1 == r {{ print $3 }}' "$t")" = available ] || exit 1
    set_field "$2" 6 yes ;;
esac
"#,
            state = state.display()
        );
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).expect("bin");
        std::fs::write(bin.join("zfs"), fake).expect("fake zfs");
        std::fs::write(dir.path().join("script"), LOAD_KEY_SCRIPT_CONTENT).expect("script");
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "chmod +x {0}/zfs && sh {1}",
                bin.display(),
                dir.path().join("script").display()
            ))
            .env("PATH", &path)
            .env("KEY_FAILS", if key_fails { "1" } else { "" })
            .output()
            .expect("sh runs");
        (
            out.status.code().unwrap_or(-1),
            std::fs::read_to_string(&state).expect("table after"),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    #[test]
    fn the_boot_script_unlocks_ours_and_fails_when_one_stays_locked() {
        let table = "\
tank\t-\t-\t-\ton\tyes
tank/apps/a/data\tfile:///etc/hlb/zfs.key\tunavailable\ttank/apps/a/data\ton\tno
tank/apps/a/data/sub\tnone\tunavailable\ttank/apps/a/data\ton\tno
tank/apps/b/data\tfile:///etc/hlb/zfs.key\tavailable\ttank/apps/b/data\ton\tyes
tank/private\tprompt\tunavailable\ttank/private\ton\tno
";
        let (status, after, stderr) = boot_script(table, false);
        assert_eq!(status, 0, "{stderr}\n{after}");
        for (name, unlocked) in [
            ("tank/apps/a/data\t", true),
            ("tank/apps/a/data/sub\t", true),
            ("tank/apps/b/data\t", true),
            // Someone else's, its key typed at a prompt: left alone, and not a failure.
            ("tank/private\t", false),
        ] {
            let line = after.lines().find(|l| l.starts_with(name)).expect(name);
            assert_eq!(line.ends_with("\tyes"), unlocked, "{line}");
        }

        let (status, after, stderr) = boot_script(table, true);
        assert_ne!(
            status, 0,
            "a key that does not load must fail the unit:\n{after}"
        );
        assert!(stderr.contains("Key load error"), "{stderr}");
    }

    #[test]
    fn a_kernel_names_its_flavour_whatever_debian_release_built_it() {
        for (kernel, flavour) in [
            ("6.1.0-53-cloud-amd64", Some("cloud-amd64")),
            ("6.1.0-28-amd64", Some("amd64")),
            ("6.12.43+deb13-amd64", Some("amd64")),
            ("6.12.43+deb13-cloud-amd64", Some("cloud-amd64")),
            ("6.12.43+deb13-rt-arm64", Some("rt-arm64")),
            ("6.16.12+deb14+1-amd64", Some("amd64")),
            ("6.12.13-0-lts", Some("lts")),
            ("6.6.58-0-virt", Some("virt")),
            ("6.12.43+deb13", None),
        ] {
            assert_eq!(kernel_flavour(kernel), flavour, "{kernel}");
        }
    }

    #[test]
    fn a_failing_zpool_is_not_an_empty_machine() {
        let stderr = "The ZFS modules are not loaded.\nTry running '/sbin/modprobe zfs'";
        let read = answered(false, "", stderr, parse_pools);
        assert_eq!(read, Err(stderr.to_string()));
        assert_eq!(answered(true, "", "", parse_pools), Ok(Vec::new()));
    }

    fn pool(name: &str, health: &str) -> Pool {
        Pool {
            name: name.into(),
            health: health.into(),
            free_bytes: Some(1_000_000_000),
        }
    }

    #[test]
    fn a_degraded_pool_says_what_it_costs_you() {
        // 🔴 "DEGRADED" alone reads as a warning you can postpone. It is not: the
        // redundancy is already spent, and the next disk to go takes the data.
        let d = pool("tank", "DEGRADED").describe();
        assert!(d.contains("redundancy"), "{d}");
        assert!(d.contains("next failure"), "{d}");
    }

    #[test]
    fn an_unreadable_size_is_never_shown_as_zero() {
        // ⚠️ "0 GB free" sends you to buy a disk. "unreadable" sends you to look at
        // the command. They are not the same problem.
        let p = Pool {
            name: "tank".into(),
            health: "ONLINE".into(),
            free_bytes: None,
        };
        assert!(p.describe().contains("unreadable"), "{}", p.describe());
    }

    #[test]
    fn an_unknown_health_is_never_assumed_healthy() {
        // A ZFS version reporting something we have not seen must not read as ONLINE.
        assert_eq!(pool("tank", "SUSPENDED").health(), PoolHealth::Unknown);
        assert_ne!(pool("tank", "SUSPENDED").health(), PoolHealth::Online);
    }

    #[test]
    fn zpool_list_is_parsed_from_exact_bytes() {
        let out = "tank\tONLINE\t3841982464\nbackup\tDEGRADED\t120000\n";
        let p = parse_pools(out);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, "tank");
        assert_eq!(p[0].free_bytes, Some(3_841_982_464));
        assert_eq!(p[1].health(), PoolHealth::Degraded);
    }

    #[test]
    fn an_importable_pool_is_found_in_prose_output() {
        // `zpool import` does not print a table. This is the case that matters after an
        // OS reinstall: the disks are there, the pool is not imported yet.
        let out =
            "   pool: tank\n     id: 12345\n  state: ONLINE\n action: The pool can be imported.\n";
        assert_eq!(parse_importable(out), vec!["tank".to_string()]);
    }

    #[test]
    fn no_pool_never_becomes_an_offer_to_create_one() {
        // 🔴 Creating a pool destroys the disks it is given. Nothing here decides that.
        let d = PoolDecision::decide(&[], &[], None);
        assert_eq!(d, PoolDecision::Absent);
        assert!(d.describe().contains("DESTROYS"), "{}", d.describe());
    }

    #[test]
    fn two_pools_and_no_name_is_a_question_not_a_guess() {
        // Only the person who made them knows which holds the application data.
        let d = PoolDecision::decide(&[pool("tank", "ONLINE")], &["old".into()], None);
        assert!(matches!(d, PoolDecision::Ambiguous { .. }));
        assert!(d.describe().contains("--pool"), "{}", d.describe());
    }

    #[test]
    fn a_named_pool_wins_over_the_count() {
        // With two pools, naming one resolves it — that is what the name is for.
        let d = PoolDecision::decide(
            &[pool("tank", "ONLINE"), pool("old", "ONLINE")],
            &[],
            Some("old"),
        );
        assert_eq!(d, PoolDecision::Ready { pool: "old".into() });
    }

    #[test]
    fn an_importable_pool_says_that_it_is_reversible() {
        // Importing is the one storage action that can be undone. Saying so is what
        // makes it acceptable to offer without ceremony.
        let d = PoolDecision::decide(&[], &["tank".into()], None);
        assert!(d.describe().contains("reversible"), "{}", d.describe());
    }

    #[test]
    fn each_volume_gets_its_own_dataset() {
        // 🔴 A dataset is the unit ZFS snapshots. Sharing one between an app's database
        // and its media means rolling back both to undo one.
        assert_eq!(
            dataset_for("tank/apps", "immich", "data"),
            "tank/apps/immich/data"
        );
        assert_ne!(
            dataset_for("tank/apps", "immich", "data"),
            dataset_for("tank/apps", "gitea", "data")
        );
    }

    #[test]
    fn a_trailing_slash_on_the_root_does_not_double_up() {
        assert_eq!(dataset_for("tank/apps/", "a", "b"), "tank/apps/a/b");
    }

    #[test]
    fn no_client_is_root_on_the_nas_and_every_client_can_write() {
        // all_squash: an app running as root on a node must not be root on the NAS, and
        // found on a real export, root_squash alone left the root apps unable to write.
        // no_subtree_check: without it a reload hands out stale handles. crossmnt: each
        // volume is a filesystem of its own.
        let l = export_line("/tank/media", "10.0.0.0/24");
        for option in [
            "all_squash",
            "anonuid=10000",
            "anongid=10000",
            "no_subtree_check",
            "crossmnt",
        ] {
            assert!(l.contains(option), "{option}: {l}");
        }
        assert!(!l.contains("no_root_squash"), "{l}");
    }
}
