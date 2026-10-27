---
paths:
  - "crates/hlb-orchestrator/**/*.rs"
  - "crates/hlb-agent/**/*.rs"
  - "crates/hlb-engine/**/*.rs"
  - "crates/hlb-types/**/*.rs"
  - "crates/hlb-bootstrap/**/*.rs"
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
- **A failed `zpool` prints nothing on stdout,** which parses as "no pool" — the shape
  that invites creating one over a pool the module simply could not see.
- **A package with no matching binary needs its own probe.** Nothing is called
  `nfs-server`. Probing by the package name reports it missing on every machine that has
  it, and a plan offering to install what is already there stops being read.

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
hlb storage init --apply                     # import, then the datasets
hlb storage export --network 10.0.0.0/24     # the /etc/exports lines (all_squash)
```
