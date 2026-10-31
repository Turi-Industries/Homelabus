# Changelog

What changed in each release of Homelabus, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) — before 1.0, a minor version may break.
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
