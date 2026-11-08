---
paths:
  - "crates/hlb-orchestrator/**/*.rs"
  - "crates/hlb-agent/**/*.rs"
  - "crates/hlb-engine/**/*.rs"
  - "crates/hlb-types/**/*.rs"
  - "crates/hlb-bootstrap/**/*.rs"
  - "crates/hlb-updater/src/disks.rs"
  - "crates/hlb-privd/src/daemon/disks.rs"
  - "crates/hlb-controller/src/disks.rs"
---

# Storage

ZFS, pools, datasets, NFS and storage tiers. The first one lost uploads while the app
stayed healthy.

- **🔴 A tier the installation cannot provide must STOP the install.** A `tier: nfs`
  volume silently given a local Docker volume takes the uploads and loses them on the
  next redeployment — the app is healthy the whole time. `tier: local` falling back to
  Docker's directory is fine, and the asymmetry is the point: "this node owns it" is
  satisfied by anything local, "this does not fit here" is satisfied by nothing local.
- **The refusal belongs at PREVIEW time.** Refusing on the executor's first action means
  the manifest is already frozen and the app already recorded: you are left with a
  half-install whose first step failed.
- **Never assume where a dataset mounts.** `tank/apps` normally mounts at `/tank/apps`,
  but the `mountpoint` property can be set to anything and a pool imported with `-R` is
  relocated wholesale. Printing the assumption hands out a path that does not exist, and
  the bind mounts then fail at deploy time naming a directory nobody chose.
- **One dataset per VOLUME, not per app.** A dataset is the unit ZFS snapshots and sends.
  Sharing one between an app's database dump and its media means rolling back both to
  undo one. And volumes are rooted per app first: `data` is the commonest name in the
  catalog, and rooting by name alone would land gitea's and immich's on the same bytes.
- **A pool is never created automatically.** `zpool create` writes labels to the disks
  with no confirmation and no way back. Importing IS offered, because `zpool export`
  undoes it. And one imported pool plus one importable is a QUESTION, not a default:
  after an OS reinstall that is exactly the dangerous shape — a fresh empty pool mounted
  by the installer, and the real data pool still on the disks.
- **`/dev/sdX` is assigned at boot.** A pool built on it can come back pointing at
  another disk. Always `/dev/disk/by-id/`.
- **`nfsvers=4` is pinned explicitly.** Left to negotiation, an old server answers in v3,
  which is stateless and loses its locks on a reconnect.
- **ZFS is a separate dependency set.** Installing it everywhere pulls a kernel module
  onto machines that will never hold a disk — and a module that fails to build against a
  new kernel is how a node stops booting.
- **A volume named in the plan is not the volume named in the manifest.** The plan's
  volume is `<app>-<volume>`; the pool's dataset is `<app>/<volume>`, as `storage init`
  creates it. The executor built paths from the first: every NFS mount and every bind
  on the pool pointed at `<app>/<app>-<volume>`, which nobody had created
  (`engine::declared_volume`). Companions' volumes are datasets too.
- **A volume's backing travels IN THE MOUNT.** `create_volume` reaches the daemon `hlb`
  runs on; on every other node Swarm created a plain local volume under the same name,
  and a `tier: nfs` app scheduled there wrote to that node's disk without an error.
  `ServiceSpec::mount_backed` puts the driver options in the mount itself.
- **Data on a node pins the service to it — not to a tier.** With two heavy nodes,
  `hlb node upgrade` drained PostgreSQL onto the other one, where it ran `initdb` over an
  empty directory and reported healthy. Deploying labels the node `hlb.data.<service>`
  and constrains the service there; draining that node is announced as downtime.
- **One export, every volume reachable, nobody root.** `crossmnt`, or a client sees each
  child dataset as an empty directory and every mount fails "no such file". And
  `all_squash` to `zfs::NFS_OWNER`, who owns the NFS datasets: under `root_squash`
  alone the root apps (Immich, Jellyfin, Seafile) became `nobody` facing root's 755 and
  wrote nothing. The cost — a `chown` on the share is refused — is why NFS mounts set
  `no_copy`: Docker's first-mount copy chowns the export.
- **An app that checks who owns its data does not run on a squashed share.** Seafile
  refuses to start as root over files it does not own, and its non-root mode demands a
  777 directory it creates as 755 itself: its volume is `tier: local`, on the storage
  node under `HLB_STORAGE_ROOT` — still a dataset of the pool.
- **An existing volume keeps the backing it was created with.** It is never recreated
  (it holds data), so a tier changed in the catalog does not reach an installed app:
  its volume stays NFS, or local, until it is moved by hand.
- **ZFS is not a package name.** Debian ships it in `contrib`, which no stock install
  enables, and the module comes from `zfs-dkms` against the running kernel's headers —
  `--no-install-recommends` alone installed tools with no module. Alpine packages a
  module per kernel flavour (`zfs-virt`) and leaves `zfs-import`/`zfs-mount` OFF: after a
  reboot the pool stayed exported and `/tank/apps` was a directory on the root disk.
  Rocky, Arch and openSUSE carry no ZFS of their own: refused at preview.
- **🔴 An encrypted dataset is NOT unlocked at boot, and says nothing.** Measured
  2026-10-30 on Debian 12 (ZFS 2.1.11) and 13 (2.3.9), `keylocation=file://`: Debian
  masks `zfs-load-key.service`, `zfs-mount` runs `zfs mount -a` without `-l` and
  "Finishes" — keystatus `unavailable`, not mounted. Its mountpoint stays an EMPTY
  directory on the parent dataset, in clear: a bind mount there writes plaintext, and
  the app sees an empty volume (PostgreSQL would `initdb`). `hlb-zfs-load-key.service`
  loads and mounts them after `zfs-mount`, before `local-fs.target`, and FAILS unless
  every one is mounted; Docker and the NFS server `Require` it. No
  `ConditionPathExists` on the key: a skipped unit counts as started. ⚠️ `Requires=`
  carries a restart of that unit to Docker — it is never restarted; a check runs its
  script.
- **ZFS cannot encrypt a dataset in place.** `hlb storage encrypt` copies each volume
  (`send | recv -u -o encryption=…`, its local properties carried by `-o`: without
  `-p` none travel, with it `encryption=off` would), swaps it in by two renames and
  destroys the original — each shape in between named, so a run resumes. 🔴
  `logicalreferenced` is NOT the check: encryption adds metadata (5 163 520 bytes
  plain, 5 202 432 encrypted, same files). The file lists (path, size, mode, owner,
  mtime) are compared; the bytes are `zfs recv`'s to check. 🔴 `zfs rename` unmounts
  the dataset's own mount point ONLY: a container writing through a Docker volume
  binding it (`o=bind`, Seafile's) kept the rename from failing and kept writing into
  the original set aside — only the `destroy` after said "busy". So every app owning a
  volume is stopped, and the copy waits until no other mount of that filesystem
  remains, in any namespace (`zfs::holders_script`). An NFS client with a file open
  does fail the rename, "dataset is busy".
- **A failed `zpool` prints nothing on stdout,** which parses as "no pool" — the shape
  that invites creating one over a pool the module simply could not see.
- **A package with no matching binary needs its own probe.** Nothing is called
  `nfs-server`. Probing by the package name reports it missing on every machine that has
  it, and a plan offering to install what is already there stops being read.

## Disks and scrubs

- **Read daily, nothing repaired, nothing scheduled** (`hlb_updater::disks`, `hlb-privd`'s
  `daemon::disks`, `HLB_DISKS_SECS`): `smartctl` and `zpool status` through the reboot
  probe's host job — a raw device opens only in the host's namespaces. One compact JSON
  line per disk (`--json=c`): pretty-printed, an ATA disk's attributes run to hundreds of
  lines, and a job's log is read back to 2,000.
- **A count that MOVES is the alarm, not a count that is there.** A disk may come with
  reallocated sectors and keep them for years; one gaining some is going. Each reading
  is compared with the one before (`disks::carry`), a disk followed by its SERIAL —
  `/dev/sdX` is assigned at boot —, the growth dated (`grew_at`), said at once and kept
  in the inbox two weeks (`disk_failing`, critical). SMART's verdict and NVMe's critical
  warning count as failing for as long as they say so. ⚠️ The ATA reading is held to
  smartctl's documented JSON, not to a measured disk: only NVMe ones were at hand.
- **🔴 A disk unread is not a disk healthy.** A physical machine without smartmontools,
  one where `smartctl` finds no disk (a controller it cannot see through), a disk the
  scan lists and nothing opens (`# /dev/sdb … open failed`, kept with its reason): all
  `disk_unknown`. A virtual machine's disks are files on its host: none found there is
  no fault. A disk answering no SMART at all (a USB bridge passing nothing) is listed
  and said nothing of — nothing a person could do would make it answer.
- **The scrub is the distribution's; what is read is whether it ran.** Debian's
  `zfsutils-linux` scrubs the second Sunday of each month, and two second Sundays can be
  37 days apart: `pool_not_scrubbed` waits SIX weeks. Alpine ships no timer and says so
  until a person schedules one. ZFS writes the scrub's end in local time, as `ctime`
  does: read under `LC_ALL=C`, with the offset `date +%z` gives. A resilver takes the
  `scan:` line's place, so the last scrub is unknown until the next. A pool not ONLINE,
  or holding files it could not repair, is `pool_unhealthy` and said when it turns.
  Not yet measured on a real pool.

## Pointing an installation at a pool

A `tier: nfs` volume is REFUSED when no NFS server is configured — that is the first
trap above, not a misconfiguration to work around.

```sh
export HLB_STORAGE_ROOT=/tank/apps     # tier: local -> bind mounts on the pool
export HLB_NFS_SERVER=10.0.0.2         # tier: nfs
export HLB_NFS_EXPORT=/tank/apps
```

On a node that carries a ZFS pool:

```sh
hlb node add <host> --storage-node --apply   # + ZFS, + NFS server
hlb storage encrypt <node> --apply           # from a manager: its key, the boot unit
hlb storage init --apply                     # import, then the datasets, encrypted
hlb storage export --network 10.0.0.0/24     # the /etc/exports lines (all_squash)
```

`storage init` refuses to create a dataset in clear unless told `--unencrypted`.
