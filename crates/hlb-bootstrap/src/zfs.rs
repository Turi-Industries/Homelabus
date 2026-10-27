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
