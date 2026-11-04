# Changelog

What changed in each release of Homelabus, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) — before 1.0, a minor version may break.
## [0.4.5] — 2026-11-04

The daemon now reads every app's backups back each week: volumes, database dumps restored
into a disposable server, SQLite snapshots and buckets, all counted and none started. A
service a backup's copy stopped comes back at the count it ran with, whoever started it
again, where a daemon replaced during a copy could leave Termix or Stalwart at 0. Restoring
a bucket no longer reports a failure after writing every object back. An app whose services
are not installed is refused at preview, naming the command that installs each.

**Upgrading from 0.4.4:**

- Migrations 0055 and 0056 run at the first start: 0.4.4 cannot open the state after.
- Do not replace the daemon during a backup pass. A copy a 0.4.4 daemon leaves unfinished
  recorded no count, so 0.4.5 does not start that service: once its hold ends, within a
  day, `hlb reconcile --apply` does.
- The daemon reads one app an hour and needs room to do it. Unasked, it refuses a reading
  that would not leave a tenth of the disk free, a dump past 1 GiB, and an S3 destination
  past 5 GiB: those stay yours, with `hlb backup verify`.
- The daemon asks the registries daily for updates, ten minutes or more after a start, and
  applies nothing. A pass over the lab's 12 apps spent 26 of Docker Hub's 100 anonymous
  manifest reads an hour.
- A preview refusing an app it used to list means applying it would have failed: install
  what it names first.

### Added

- Restore each dump into a disposable server when reading an app's backups back

### Fixed

- Refuse an app at preview while a service it needs is not installed

### Changed

- Time a bare machine to its first app, and read the result in the scorecard
- Give the path a bare machine really takes, and record what it cost
- Read every app's volumes back each week, and refuse what would not fit
- Read SQLite snapshots and buckets back with the rest of an app's backups
- Count the apps read back in the scorecard
- Record the lab's backups read back, and what a reading leaves to do
- Record when each update was first seen, and how long it took to apply
- Give back what a backup's copy stopped, whoever started it again
- Count how long updates take in the scorecard
- Record how long the lab's updates took
- Hold bech32 on the version age uses

## [0.4.4] — 2026-11-04

Removing an app now says everything it leaves behind, and forgetting its secrets
takes what only they opened. Removing a service takes the Swarm secrets its files rode
on, and a service keeps the versions of them a rollback needs and no older. A role
found again takes the password it is given, where a reinstall after `hlb secrets-forget`
left the app refused by its own database.

**Upgrading from 0.4.3:**

- No migration: 0.4.3 and 0.4.4 open the same state.
- `hlb secrets-forget` now deletes the app's OIDC client, Garage key, SMTP account and
  portal callback before its secrets. A service installed and out of reach keeps what it
  holds, and running it again finishes. The database, the bucket and a mail account stay.
- Old versions of a service's Swarm secrets go at its next deployment or reconfiguration.
- `hlb reconcile` reports a portal callback no installed app has, such as one left by an
  app removed before this release: `hlb portal drop-callback <url> --apply` takes it off.

### Changed

- Take the catalog without the ingress chain
- Take an app's Swarm secrets with it, and say what stays
- Delete a job's secrets when its run was cut or refused
- Keep the versions of a service's secrets a rollback needs, and no older
- Give a role found again the password it is given
- Say what a removal leaves in other services
- Delete what a removed app's secrets open when they are forgotten
- Report a callback no installed app has, and stop waiting on a removed service

## [0.4.3] — 2026-11-03

Anubis is gone from Homelabus. Its built-in policy ignored the difficulty set for it
and challenged browser User-Agents only, so it protected less than it appeared to;
bot protection will come back when it can be done properly. The interface shows the
signed index again where the web side reads the state under another path, and a
backup waits for a repository's lock instead of failing on it.

**Upgrading from 0.4.2:**

- No migration: 0.4.2 and 0.4.3 open the same state.
- If Anubis is installed, remove it: `hlb remove anubis --confirm anubis --apply`.
- A route whose frozen manifest names `anubis` in its chain is no longer published,
  rather than published without the challenge it asks for: `hlb upgrade <app>` brings
  it back. The catalog now refuses a chain naming it.
- Each app's route is published once more at its next apply. Nothing restarts.

### Fixed

- Stop calling a route without a chain "direct" in a preview
- Read a fetched source's cache where the reader sees the state
- Wait for a repository's lock rather than fail the backup

### Removed

- Remove Anubis

## [0.4.2] — 2026-11-02

The first run of the catalog's CI on fresh houses found two installs that stopped on
Garage: an app's bucket expiry is now written by a key of Homelabus's own, owner of
that bucket for the one call, and a Garage installed in the same plan as its first app
is given its layout instead of refusing every bucket.

**Upgrading from 0.4.1:**

- No migration: 0.4.1 and 0.4.2 open the same state.

### Fixed

- Write a bucket's expiry as its owner, and give a fresh Garage its layout

## [0.4.1] — 2026-11-02

What the catalog's CI proves of each app now reaches the houses: installed on a fresh
house, updated from the version published, backed up, restored, removed. The results
ride beside the official index in `quality-v1.json`, signed with it and tied to its
counter, and the catalog screen shows them — *proven, maintained for N months*. The
index itself keeps the format 0.4.0 reads.

**Upgrading from 0.4.0:**

- No migration: 0.4.0 and 0.4.1 open the same state.
- `hlb assert` exits 2 when an assertion could not be read (an app just started),
  where it exited 0: a script that waited on its exit code waits for a real answer.

### Added

- Publish what CI proved of each app beside the index, signed with it
- `hlb catalog export <dir>`: the catalog this `hlb` carries, written out

### Fixed

- Retry labelling a node whose version moved while it settled

### Changed

- Exit 2 on an assertion nobody could read
- Freeze the index's format as 0.4.0 reads it

## [0.4.0] — 2026-11-02

The apps leave this repository for their own, `homelabus-catalog`: an app now enters
by a pull request there and reaches the houses through a signed index, fetched every
night over HTTPS, with no release of `hlb`. Each manifest says the `hlb` range it runs
on, an installed app keeps the guide it was deployed with, and a version can be revoked
in the index and named on the house running it. Third-party sources sit beside the
official one. PostgreSQL and MariaDB are copied by their own tools while they run, and
Stalwart is stopped for its copy; a restore runs the steps that follow it. Jellyfin
moves to 12.4 behind PocketID, a phone gets a password of its own for mail, calendars
and contacts, the family's sealed kit is mailed to each relative, and the house's
domain has a screen.

**Upgrading from 0.3.0:**

- Migrations 0049 to 0054 run at the first start: 0.3.0 cannot open the state after.
- The controller reaches `turi-industries.github.io` over HTTPS every night for the
  official index. Without it, the catalog `hlb` carries is the one read.
- PostgreSQL and MariaDB now declare a copy by `pg_basebackup` and `mariadb-backup`,
  and PostgreSQL's server takes an access file allowing replication: `hlb update apply
  postgres`, or its nightly copy fails rather than being taken live.
- Stalwart is stopped for its nightly copy: about five seconds without SMTP.
- Each app's database role is limited to twice its declared connections at its next
  deployment: an app past its budget is refused its own connections.
- Jellyfin moves to 12.4 (`hlb update apply jellyfin`, rehearsed on a 10.11.11 volume);
  its sign-in goes through PocketID and its passwords close to linked accounts, the
  recovery `admin` excepted.
- Garage's metadata is no longer backed up: a lost Garage is reinstalled, and each
  bucket restored from its own archive.

### Added

- Run what follows a restore after the restore, and judge it by its end

### Fixed

- Stop a volume's services for its copy when it says copy: stopped
- Close Jellyfin's passwords to accounts linked to PocketID

### Changed

- Measure what syncing people and nodes into an app needs: no crate it would spare
- Say that restic on a read-only repository needs --no-lock
- Measure what a live volume copy restores: Stalwart's does not, three SQLite go unflagged
- Snapshot SQLite found in any backed-up volume, flagged or not
- Hold services stopped for a restore away from reconciliation
- Measure Stalwart stopped for its copy: five seconds without SMTP
- Declare a data directory copied by its engine's own tool, refused until built
- Record the owner's calls: Vaultwarden and Termix keep their Rust, replaceable; Jellyfin's accounts in phase 3
- Back up Garage's metadata no more: it indexes blocks nobody backs up
- Copy PostgreSQL's data directory with pg_basebackup while it runs
- Keep a job run's file secrets within Swarm's 64 characters
- Copy MariaDB's data directory with mariadb-backup while it runs
- Record MariaDB's hot copy proven on the lab
- Say when Garage lost an app's buckets or key, and how to bring them back
- Paint a refused drift red when what it leaves alone is broken
- Measure the rest of gap 5: cadence, upgrade and restore steps, NATS, pools
- Hold every app to a connection budget on its shared server
- Ready Fluxer's thread index before the full search refresh
- Make, list and revoke a device's password in Stalwart
- Ask the privileged side for a person's devices and their passwords
- Let a person give each device its own password, from Me or the CLI
- Record Stalwart's app-password trap with the mail rules
- Revoke a device by the mailbox address its list shows
- Record calendars and contacts from Stalwart as proven on the lab
- Mail the family's sealed kit to each relative at every seal
- Hand a relative's bounced kit to postmaster@, not to noreply@
- Show each machine's protection level on the nodes screens
- Make the domain's advice values, ready for its screen
- Show the house's domain on its own screen
- Read the registry over WHOIS where the TLD has no RDAP
- Judge a CAA validationmethods against the challenges each account takes
- Verify Vaultwarden, Bulwark and Anubis against their release workflows
- Move Jellyfin to 12.4, rehearsed on a 10.11.11 volume
- Plan Jellyfin's sign-in through PocketID, as measured
- Fetch a manifest's downloads into its volume before the app starts
- Set Jellyfin's PocketID provider through a signed-in guide step
- Keep each Jellyfin account enabled while its person holds a role let in
- Record Jellyfin's PocketID sign-in as the lab ran it
- Freeze an app's guide beside its manifest
- Declare the hlb range each app runs on, held to its floor's schema
- Read third-party catalog sources beside the official one
- Build, sign and verify a catalog source's index offline
- Read signed catalog sources from their cache
- Fetch a signed catalog source over HTTPS into its cache
- Say what an app receives before it installs, and how critical it is
- Revoke an app version inside the signed index
- Name a revoked version on the house that runs it
- Fetch the signed sources every night and read the catalog again
- Lay the official signed index over the carried catalog
- Write the official source from what hlb carries, and fetch it with the others
- Move the apps to homelabus-catalog, mounted back as a submodule

## [0.3.0] — 2026-10-31

A machine taken away boots to nothing readable: disks bound to their TPM and the
house's Tang servers (`hlb node bind-disk`), a signed boot at level A (`hlb node
verify-boot`), the vault's key and Swarm's unlock key sealed, a storage node's ZFS
datasets encrypted, and every secret handed to its container as a file. The
controller is split in two: `hlb-privd` holds the privileges, and the web side,
holding none, asks it by intent. Stalwart moves to 1.0, the house's domain is
watched every night, and the emergency kit can be split among relatives.

**Upgrading from 0.2.1:**

- Docker 29 at least, on every node: 24 silently dropped `no_new_privileges`.
- `hlb fleet controller` now deploys two services, the daemon and the web side.
- An installed Stalwart stays on 0.16, whose store 1.0 refuses to open: `hlb update
  apply stalwart`, then `hlb mail migrate --apply`. The 0.16 volume is never written,
  so rolling back is starting 0.16 on it.

### Added

- Prove a storage node's encrypted pool on the lab, and say where its key comes back from
- Sign up through an intent
- Prove the family's yearly rehearsal by a code the opened kit ends with
- Prove a recovery sign-in that takes a form, not JSON
- Add Mealie to the catalog, with no Rust
- Run Mealie under a read-only root, proven on the lab with the rest
- Prove the five services' arguments on the lab: Valkey runs under tini again

### Fixed

- Refuse a secret in a catalog environment in `catalog validate`
- Refuse a node at another peer's address, and take dead peers out of the mesh
- Refuse a TPM that seals nothing, and fix what the sealing review found
- Close level A's two initramfs-tools holes on the lab: a PCR 11 barrier and panic=
- Refuse a backup destination naming another destination's secret
- Close plan G phase 2, recording the owner's decisions of 2026-10-31
- Keep the demonstration's database from vanishing with its connection

### Changed

- Say what a release moves besides Cargo.toml
- Give a 0.x minor its own Renovate pull request
- Record phase 1's gate passed on a bare lab VM
- Update caddy Docker tag to v2.11.6 (#2)
- Update stalwartlabs/stalwart Docker tag to v0.16.27 (#3)
- Update Swatinem/rust-cache action to v2.9.3 (#4)
- Update vaultwarden/server Docker tag to v1.37.4 (#5)
- Update victoriametrics/victoria-metrics Docker tag to v1.154.1 (#6)
- Update binwiederhier/ntfy Docker tag to v2.32.0 (#7)
- Update fluxer (#8)
- Update gitea/gitea Docker tag to v28.2 (#9)
- Update n8nio/n8n Docker tag to v2.45.0 (#11)
- Update interface packages (#10)
- Update rust Docker tag to v1.98 (#13)
- Update dependency @types/node to v26 (#14)
- Update docker Docker tag to v29 (#16)
- Update GitHub Actions (major) (#17)
- Update Rust crates (#12)
- Update Rust crate x25519-dalek to v3 (#19)
- Update mariadb Docker tag to v12 (#18)
- Lock file maintenance (#20)
- Move the release and image matrices to Ubuntu 26.04 (#21)
- Raise the Docker floor to 29 (#27)
- Update dxflrs/garage Docker tag to v2.5.0 (#22)
- Update fluxer (#23)
- Update ghcr.io/bulwarkmail/webmail Docker tag to v1.18.0 (#24)
- Update grafana/grafana Docker tag to v13.3.0 (#25)
- Update n8nio/n8n Docker tag to v2.46.0 (#26)
- Update valkey/valkey:9-alpine Docker digest to bf09d58 (#37)
- Update Rust crate jsonschema to 0.60 (#28)
- Update Rust crate resvg to 0.49 (#29)
- Update rust Docker tag to v1.99 (#30)
- Update docker Docker tag to v29.9 (#48)
- Update victoriametrics/victoria-metrics Docker tag to v1.155.0 (#31)
- Update debian:bookworm-slim Docker digest to 7ff6ba3 (#35)
- Update ghcr.io/pocket-id/pocket-id:v2 Docker digest to f085157 (#36)
- Update vikunja/vikunja:2.7 Docker digest to f7dc842 (#38)
- Update caddy Docker tag to v2.11.7 (#39)
- Update dependency @inlang/plugin-message-format to v4.5.5 (#40)
- Update ghcr.io/librespeed/speedtest Docker tag to v6.3.1 (#41)
- Update ghcr.io/lukegus/termix Docker tag to v26.10.5 (#42)
- Update klutchell/unbound Docker tag to v1.26.2 (#44)
- Update ghcr.io/techarohq/anubis Docker tag to v1.28.2 (#43)
- Update oven/bun Docker tag to v1.4.4 (#45)
- Update roundcube/roundcubemail Docker tag to v1.7.5 (#46)
- Update binwiederhier/ntfy Docker tag to v2.34.0 (#47)
- Update docker/login-action action to v4.7.0 (#49)
- Hold MariaDB on its LTS line in Renovate (#50)
- Update n8nio/n8n Docker tag to v3 (#33)
- Speak Stalwart 0.16 and 1.0 alike
- Schedule DKIM rotation on Stalwart 1.0, and say why a key is missing
- Migrate an installed Stalwart 0.16.27 to 1.0 with `hlb mail migrate`
- Put the catalog's Stalwart on 1.0, in a volume of its own
- Ignore deepmerge's prototype poisoning in bun audit, with why
- Count the secrets a container receives through its environment
- Read two of the scorecard's "never stolen" rows from what holds them
- Hand every secret but Fluxer's to its container as a file
- Hand Fluxer its secrets as files, each companion only its own
- Read the env-secrets row from the refusal once it exists
- Mark plan G's secrets-as-files step done, with its lab proof
- Register through Vaultwarden 1.37.4's two-step sign-up in its live tests
- Name the writing account in every Vaultwarden item, as 1.37.4 requires
- Seal the vault's key to the machine's TPM, in memory only
- Plan each machine's protection level, and where secrets may live
- Seal Swarm's unlock key to its manager, so a restart unlocks itself
- Seal Swarm's unlock key on every manager, the others over SSH
- Seal a manager node add joins, and take the key back from a worker
- Count the nodes at each protection level on the scorecard
- Detect each node's protection level, and label the node with it
- Say on the scorecard what the lab's nodes read, now that hlb detects a level
- Mark the detection step done in plan G's order, and date what it replaced
- Say a sealed key refused by permissions is refused, not unsealed
- Record in plan G the TPM libraries at provisioning and the refused TPM
- Take libz-sys 1.1.31, past RUSTSEC-2026-0418
- Record the owner's two decisions of 2026-10-29 in plan G
- Carry each encrypted disk's recovery key on the emergency kit
- Render an encrypted disk in the preseed, measured against re-encrypting in place
- Measure Clevis with the TPM and one Tang of two on the lab, and record the owner's two decisions
- Bind an encrypted disk to its TPM and one of the house's Tangs: hlb node bind-disk
- Read a disk's Clevis bindings from its LUKS tokens, so a Tang with new keys is bound again
- Finish binding encrypted disks: preseed --encrypt, SSH at boot, rebinds on join and leave
- Pass phase 2's gate at level B on the lab, by the verbs alone
- Measure the three ways to combine a signed boot with Tang on a Secure Boot VM
- Record the owner's choice for level A: Clevis with predicted PCRs, and Tang
- Build level A as the owner chose: hlb node verify-boot, hlb-uki and its reseal
- Pass phase 2's gate at level A on enc3, replacing a Clevis binding in place
- Handle what breaks a level A unlock before it happens: PCR 7 predicted, Setup Mode refused, DKMS signed
- Harden the running system at level A: lockdown confidentiality and the IOMMU, read back
- Say in the security model what no protection level covers
- Bring the scorecard's stolen-node row up to level A, proven on enc3
- Record that an encrypted ZFS dataset is not unlocked at boot, measured on Debian 12 and 13
- Encrypt a storage node's datasets under a key of its own, unlocked before Docker
- Never let the Bitwarden assistant take over another token's name
- Plan the controller split as a privileged executor, from a route-by-route measure
- Start the controller split: scale and drain go through a privileged executor
- Move the acting routes' privileged half behind intents
- Read Swarm's nodes and tasks through an intent
- Ask PocketID and the emergency kit through intents
- Create aliases and mailboxes through intents
- Sync the roles and republish the portal through intents
- Keep the capabilities out of AppState: it holds the Privd
- Move the daemon's capability loops into hlb-privd, and refuse capabilities in the web modules
- ROADMAP: the controller split's stage 1 is done, and what it leaves
- Write the audit chain through an intent
- Open, extend and close sessions through intents, and issue tokens there
- Write roles, quotas and invitations through intents
- Record hlb-api's dependency on hlb-users in Cargo.lock
- Write preferences, announcements, mutes and the rest of the web's records through intents
- Keep the home's measurements through an intent
- Point the security rule at hlb-api's intent directory
- Move the daemon's loops and notifier into hlb-privd
- Let the web side write nothing in the state or the Git mirror
- Carry intents over a Unix socket, answered for the web side's uid only
- Poll the agents from the daemon; the web side asks for the fleet
- Reflow the security rule's paragraph on the privileged socket
- Compose the daemon in hlb-privd; the web side can run behind its socket
- Ship hlb-privd, the daemon answering the web side over its socket
- Deploy the controller as two services: the daemon, and a web side holding nothing
- Record the controller split's stage 2, proven on the lab
- Name the controller the package's default binary
- Record the daemon's mTLS poll, proven on the lab
- Let the web side change a destination's classes, never its place or secret
- Replay a saved plan as a new preview, and let a plan name only a route that previews
- Record stage 3 proven on the lab, the passkey decision, and the daemon's start-first update
- Replace the daemon stop-first, and let it remove only the socket it bound
- Have the daemon act on a destruction only once a passkey confirmed it
- Ask a passkey for a destruction from the web side, and present it from the panel
- Box the daemon's dispatch, which release builds could no longer lay out
- Mark the controller split done, and the passkey that replaced the id_token idea
- Record how few catalog images are signed, and drop a French leftover in the scan's verdict
- Hand a destination's owner the script that prunes what Homelabus cannot erase
- Hold each signed image to its own publisher's signer
- Describe a verified signature as one, not as a clean vulnerability scan
- Warn of a Secure Boot platform key that is a manufacturer's test key
- Never propose a machine that gives the Raft log up as a manager
- Say in cluster status a manager a better node could replace
- Split the emergency kit's key among relatives, any 3 of 5
- Count the family's rehearsal only while the kit they hold is today's
- Record the dbx measurement and its design before the code
- Warn a Secure Boot node whose dbx is behind LVFS's, or not known to be current
- Count goal 4's apps from the history's restart, not from its root commit
- Give Mealie its icon, from its own repository
- Leave plan G phase 3's apps to the owner, decided when the phase starts
- Record the domain's measurement and the drift check's design before the code
- Watch the house's domain every night for a move nobody here made
- Ask one authority for every certificate, so a CAA can name its account
- Judge the domain's CAA against the house's own ACME accounts
- Record Certificate Transparency's measurement and design before the code
- Watch the Certificate Transparency logs for a key the house does not hold
- Say the domain in the inbox: moved, refused by its CAA, certified by a stranger
- Record the signed zone's secondaries: the house and the VPS, no third party
- Open plan G phase 3: the owner's choices, and its gate on the scorecard
- Measure the deploy knobs the next app will need, and design them typed
- Say a container's arguments, process and sized tmpfs in the manifest
- Start five services after their image's entrypoint, not in its place
- Measure the secret forms and install facts the next app will need: none missing
- Measure the engines the next app will run: the tail is thin, its backup is not
- Ignore minimatch's globparts amplification in bun audit, with why

## [0.2.1] — 2026-10-27

### Added

- Sign the images keylessly, with their SBOM and provenance attached

### Changed

- Audit the watchdog password hlb metrics deadman prints
- Spend CI's minutes on the tests, not on apt and cargo install
- Compare Homelabus with its neighbours, and write down its security model
- Name CI's runner image, as the other workflows do
- Let the installer download with wget when curl is absent
- Move a catalog app's images in one pull request

## [0.2.0] — 2026-10-27

The first public version. Homelabus was developed privately before this, and its
history starts over here.
