# Roadmap

What is left to do, and what was ruled out. What was DONE lives in the commits and in
[CHANGELOG.md](CHANGELOG.md) — a "done" paragraph here is a paragraph a reader has to
check against the code before trusting the rest.

Verified on 2026-10-26, after the fixes from the review of 2026-10-21: `cargo test`
passes (**2004 tests**, plus 118 `#[ignore]`d integration tests), `cargo clippy
--all-targets` is at zero warnings, `hlb catalog validate` reports 24 manifests valid,
and in `web/` `bun run check` reports zero errors and warnings, `bun run test` passes
(53) and `bun run test:browser` 21 (two skipped by design). `bun run shots` was last run
on 2026-10-06 (1,216 images in ~50 s).

### G. The goals, and the order to reach them — decided 2026-10-27

Asked on 2026-10-27 in two steps. In the morning, four goals — deploy on any machine as
easily and fast as possible, never lose data, never have it stolen and trust nobody, add
an app without touching Rust — and a way to keep improving toward them by itself:
`scripts/scorecard.sh` states each goal as numbers, `/improve` takes one step and commits
it on a worktree's branch, `scripts/improve.sh N` runs N steps, by hand only. In the
afternoon, researched and decided point by point by the owner: goal 3 widened, three
goals added, and eight phases to get there. **Measured** the same day:

| Goal | Now |
|---|---|
| 1. deploy | `v0.2.0` has no release: the quick start begins with building thirty crates, then five commands. Time to a first app is measured nowhere |
| 2. never lose | no record anywhere of which apps' restores were rehearsed; `hlb dr exercise` rehearses PostgreSQL's base backup |
| 3. never stolen — **widened**: trust no provider (registrar, DNS host, VPS, storage), encrypt everything | CI actions pinned by commit (0 unpinned), images by digest (enforced), one `cargo audit` exception; no release is signed. **No disk is encrypted** (the preseed partitions `regular`, ZFS without its native encryption); the vault's key is sealed to the machine's TPM by `hlb secrets-seal` (2026-10-28), a `0600` file until then; no catalog variable carries a secret through the environment — `catalog validate` refuses one (2026-10-28); no DNSSEC, nothing watches the registrar. Backups are already encrypted before they leave |
| 4. no Rust | **0 of 12** apps went in without Rust in the same commit; of the last 12 commits completing an app, 8 touched Rust. No production code branches on an app's name |
| 5. always available — the vital apps reachable while the house is down, or moving | no notion of a site, of an app's criticality, of a relay: the way in is a port forward on the house's router. Every service runs `replicas: 1` |
| 6. always up to date without breaking — OS, CVEs, apps | `hlb-updater` chains registry watch, channel, maturity, window, backup, deploy, health check and rollback — and **the controller never calls it**: nothing updates without `hlb update apply`. CVEs are looked at by Trivy at update time only |
| 7. simple and beautiful for whoever runs it — install, dashboard, docs | 8 modules and 34 pages in the shell; the README (731 lines) announces 1,690 tests and says mail never ran; `docs/` holds the CLI tour and the journal |

**Who it is for** (corrected by the owner the same day): not households only —
associations, alternative hosters (CHATONS: 86 members), small businesses, schools, NGOs.
The closest prior art, Co-op Cloud, runs on Swarm too and isolates nothing between
organisations. **But never at the households' expense:** one implicit organisation, and
the words *organisation*, *quota* or *GDPR register* invisible until their module is on;
the Minimal profile's question count is capped and counted by a test — a hoster module
that raises it is a regression.

**A core, and everything else a module.** Platform services already enter a plan only
when an app requires one (`hlb-resolver/src/graph.rs`): no app sending mail, no
Stalwart. The same rule, extended to the infrastructure:
- A module is declared in the house's configuration with its dependencies — the
  lifeboat needs the VPS, the VPS's Tang share needs encrypted disks — and the preview
  refuses one whose dependency is missing, as the resolver refuses a capability with no
  service.
- **Never half on**: installed and verified, or absent and refused wherever it would be
  asked for — "a declaration nobody reads", applied to modules.
- Added or removed later, with a preview: moving from the ISP's box to OPNsense, or
  adding a VPS a year on, reinstalls nothing.
- The core works without it. No router: the box and a port forward, as today. No VPS:
  no lifeboat, the status page at home. No signed zone: the provider's DNS.
- The interface shows what is on: an infrastructure module adds its pages under
  `web/src/lib/modules/`, an absent one shows nothing; the TUI asks module by module.
- **Secure defaults stay in the core**: secrets as files and a sealed vault key are not
  modules. Disk encryption is offered by default; declining it is explicit, and the
  preview says so.
- Three presets, nothing more than presets: **Minimal** (one machine, apps, backups),
  **Household** (several machines, SSO, mail, status page), **Complete** (router and VPS
  included). One moves between them by enabling modules, never by reinstalling.
- Measured before building: what is mandatory today with nothing requiring it — the
  list to take out of the core.

The modules: the OPNsense router, the VPS (front door, lifeboat, status page), a signed
authoritative zone, disk unlocking through Tang, the UPS, Wi-Fi access points, CDN edges.
For hosters: organisations (each its own overlay, secrets and quotas; hoster, org-admin
and user roles, an org-admin never seeing another organisation or the VPS), an
exportable audit log, a GDPR register and a CHATONS transparency page generated from the
manifests and the state (optional fields on read), usage metered per organisation and
exported — Homelabus never bills.

#### Decided by the owner, 2026-10-27

- **Licence**: AGPL-3.0-or-later, adopted before the repository went public. Grants not
  wanted.
- **The house's network**: the ISP's box in bridge mode, OPNsense behind it on a machine
  of its own, driven by its API — never a service of the cluster, which needs the network
  to start.
- **App updates**: patches automatic after 7 days, in the window, a backup first; minors
  one click; majors manual, as today. An exploited CVE (CISA's KEV list) skips the
  maturity.
- **Reboots**: planned, one node at a time, drained first, in a window the owner
  authorises. This reverses "no unattended reboot" (`security.md`) only because these
  drain — the reason it was refused.
- **The VPS**: a small rented server, 4 GB the size aimed at. A separate site, never a member of the Swarm. Front door
  (a TCP relay over WireGuard that never decrypts), Gatus status page, and a lifeboat of
  Vaultwarden and PocketID, mail as a secondary MX, ntfy. Promoted by hand, never
  automatically.
- **Disks**: a node may have no TPM 2.0 — `hlb` detects it before encrypting. A Tang share on the VPS is accepted.
- **The domain**: at a registrar offering a registry lock, recommended rather than
  required.
- **The TUI installer**: yes, after security and the VPS, for the whole path from a bare
  machine to the first app — reverses the 2026-10-07 refusal, which was about one
  question.
- **Documentation** in English.
- **UX research**: the owner alone, a two-week diary of admin tasks; the family portal
  without interviews.
- **Third-party catalog sources** may request the host network or the Docker socket,
  after an explicit confirmation per app.
- **The OS**: Debian stays; no immutable OS.
- **Still ruled out**: automatic database failover, automatic major updates, `hlb`
  updating itself unattended.

#### Decided by the owner, 2026-10-28

- **Nodes move to Debian 13.** Verified boot needs it (systemd 257: `ukify`, the volume
  measured into PCR 15); Debian 12 caps a node at level B. The preseed, Docker's and
  ZFS's sources and the lab follow; existing nodes upgrade `bookworm → trixie` one at a
  time, drained.
- **Managers when protection and quorum disagree: asked each time.** `node add` and
  `cluster init` show both costs — every app's secrets on a weak machine, or a control
  plane that stops rescheduling while its one manager is away — and the person chooses;
  neither is a default.

#### The phases

In the order of risk — a theft is irreversible, a clumsy screen is not. Each phase closes
on a gate whose scorecard row is added **before** the phase starts; no durations, each
phase is estimated once the previous one is measured. Phases 2 and 3 touch disjoint
crates (`hlb-secrets`, `hlb-bootstrap` against `hlb-types` and the catalog) and can run
in two worktrees. The admin diary and the documentation site run alongside all of them.

**1. Going public.** Gate: a bare VM installs a verified `hlb` in one command.
✅ Passed 2026-10-27 on `v0.2.1`: a fresh Debian 12 cloud VM of the lab — no Docker, no
cosign — ran the README's `curl … | sh` and got `hlb 0.2.1`, signature and checksum
verified, cosign not left behind; served the same release with a byte added to the
binary, it refused and installed nothing.
- ✅ The whole history scanned on 2026-10-27 — 411 commits, every branch and tag,
  gitleaks 8.24.3 and trufflehog 3.88.0: 16 and 27 findings, none verified, every one a
  test fixture or a documentation example (`postgres://u:p@h`, `alice-password-0123…`).
  No path like the vault's key in any commit, the reflog's or a dangling one; every ref
  on `origin` is in the local, purged history. ⚠️ GitHub may still serve commits pushed
  before the August purge by their hash: ask its support to drop them before going
  public — the key was rotated, so they open nothing current. Superseded the same day:
  the repository is recreated with one commit, which drops them with it. The dead branches went
  the same day: `phase-3-roles` and `vm-lab-fixes`, wholly in `main`, deleted;
  `archive/egui-wip` and `chore/august-batch` (pull request 2, merged squashed) kept as
  the tags `archive/egui-wip` and `archive/august-batch`. `PLAN.md` stays out.
- ✅ AGPL-3.0-or-later, 2026-10-27 (`LICENSE`, the workspace's `license`, the README,
  the OpenAPI document), and the Contributor Covenant 2.1, reports to
  contact@turi-industries.eu. `GOVERNANCE.md`, 2026-10-27: one maintainer, what will
  not be merged, and no successor — twelve months silent, the repository is archived
  and the AGPL lets anyone fork it. The interface links to its source, as §13 asks of
  anyone running a modified copy for others, 2026-10-27: `/healthz` says where
  (`HLB_SOURCE` at build time, the images naming the commit of whichever repository built
  them), every screen but the kiosk shows it, and the crawl refuses a page without it.
  ✅ The repository's norms, 2026-10-27: REUSE 3.3 (`REUSE.toml`, `LICENSES/`, the
  catalog's logos and Docker's keys declared as their projects', `reuse lint` in CI),
  `SUPPORT.md`, a pull-request template, `.editorconfig`, `.gitattributes`, CodeQL and
  Scorecard workflows (skipped while private), Renovate's configuration (the catalog's
  `{ repo, tag, digest }` lines by a regex, a week's maturity, nothing merged by
  itself), `CHANGELOG.md` with `cliff.toml` sorting the history's sentences by their
  first word, and `scripts/github-settings.sh` setting the repository through the API
  — read-only tokens, named actions pinned by commit, squash only; the ruleset on
  `main`, secret scanning and private vulnerability reporting the day it is public,
  when it runs again. **The history starts over** (owner's decision): one commit by
  Turi Industries in a new repository, the owner's name and domain replaced by
  fictional ones beforehand (Léna Martin, `home.example`; the themes `Dark` and
  `Light`). Immutable releases on, 2026-10-27 — they have an API after all, which
  `github-settings.sh` sets. ✅ Renovate's app installed on the repository and run,
  2026-10-27: one pull request per catalog app; its first run grouped 0.x minors —
  breaking releases in Cargo — with the patches, so each now has its own, RustCrypto
  and rand moving as one. The OpenSSF Best Practices badge: dropped by the owner.
- ✅ Written 2026-10-27, run on `v0.2.0` the same day:
  `.github/workflows/release.yml` builds `hlb` as a static musl binary for `x86_64` and
  `aarch64` on native runners, refuses one that is not static or whose `--version` is
  not the tag's, attests each one's provenance, and signs `SHA256SUMS` keylessly with
  cosign. `scripts/install.sh`, published beside them, checks a pinned cosign by its
  checksum, the signature against this workflow's identity on a `v` tag, then the
  binary against `SHA256SUMS`; the workflow then runs it on both architectures from the
  published release, and checks it refuses a `SHA256SUMS` with a line added. Tried
  here: a forged release refused, nothing installed; the same `verify-blob` accepting
  cosign's own signed release and refusing it with a byte added. Written by hand rather
  than by cargo-dist, whose workflow names its actions by tag. The job that can push
  checks nothing out — `workflows.rs` now refuses a write given to a whole workflow and
  `contents: write` beside a checkout. ✅ The images too, the same evening: each
  architecture carries an SPDX SBOM and max-mode provenance as BuildKit attestations,
  and the multi-architecture index is signed keylessly by its digest, then verified
  against the workflow's identity before the job ends. Left: a changelog from
  git-cliff, without imposing Conventional Commits on the history's style.
- ✅ A README that is a front page, 2026-10-27: the promise in one sentence, what it
  does and is not, a quick start of four commands, the status, where each document is —
  ~100 lines where there were 735. The rest moved whole to `docs/how-it-works.md`,
  `docs/operating.md`, `docs/limitations.md` and CONTRIBUTING's integration suites.
  ✅ Against YunoHost, Cloudron and Coolify, and `docs/security-model.md` — what it
  defends against, trusts, and does not protect yet — 2026-10-27. Left: documentation in Diátaxis' four parts on Starlight (bun, an OpenAPI
  plugin, a link checker); the CLI, schema and API references generated from clap,
  schemars and OpenAPI and refused when stale, as `web/openapi.json` is; screenshots from
  `/shots` only.

**2. Never stolen.** Gate: a machine taken away from the lab boots to nothing readable;
no secret in `docker inspect`.
- ✅ Secrets as files — 2026-10-28: 60 variables moved (the count was 51 before
  Fluxer's were read), each app by its own route — `_FILE`, a config file, or a `sh -c`
  reading the file before `exec` —, and `catalog validate` refusing a secret in an
  environment, or a `/run/secrets` path the container does not mount. Proven on the lab:
  15 apps upgraded, 167 mounted secrets found in no container's environment, `hlb
  assert` green, and Fluxer used end to end — PocketID sign-in, a message, its search,
  an attachment through the media proxy.
- ✅ The vault's key sealed — 2026-10-28: `hlb secrets-seal` seals it with
  `systemd-creds` (TPM and host key; the host key alone, said, on a machine without
  one), `hlb-vault.service` unseals it at boot into a `ramfs` before Docker starts, and
  the key's path becomes a link there, so `hlb` and the controller's mount keep theirs.
  Refused until the emergency kit is printed with today's material. The binding is
  measured, not assumed: systemd 252 seals with no PCR and cannot unseal it, so PCR 7 is
  used there, and a TPM whose libraries are missing gets `tpm2-tools` first. Proven on
  the lab (deb1 given a swtpm TPM): sealed, rebooted, the controller back on its own;
  the same disk booted without its TPM opened nothing — the unit failed, `hlb` named
  the fix, Swarm refused to start the controller; the TPM given back, all returned.
  Left: Swarm's autolock, its unlock key sealed the same way so a manager restarts
  alone — today `hlb cluster autolock` keeps the key in the vault and nothing unlocks
  at boot; sealing by default at `cluster init`, once the installer prints the kit.
- **Each machine its protection level — detected, never declared** (owner's request,
  2026-10-28: every kind of machine will be met, and the best protected should carry
  what matters). What can be reached depends on the firmware, the TPM and the systemd
  version, not on the distribution's name. Measured the same day: Debian 12 (systemd
  252) has no `ukify` — not even in backports, which stop at 254 — and its cryptsetup
  knows no `tpm2-measure-pcr`; Debian 13 (257) has both, a signed `systemd-boot` and
  `pcrlock`; Clevis, Tang and `dropbear-initramfs` are in both; `sbctl` in neither;
  DKMS (3.0.10, 3.2.2) signs modules with a MOK key of its own, which a person enrols
  once at the console. Today `hlb` detects none of this: `node add` reads memory, disk
  and kernel, nothing reads the firmware, and a manager is chosen by count alone.
  - **Detection**: UEFI (`/sys/firmware/efi`), the TPM (`has-tpm2`'s `+driver`, then a
    sealed round trip — `hlb secrets-seal` showed a TPM can answer every probe and
    still not seal), Secure Boot (`mokutil --sb-state`), `systemd-detect-virt`, the
    systemd version and the tools present, the DKMS modules (ZFS). Read by the agent,
    shown by `node list`, `node add`'s preview and the interface.
  - **Four levels**, each one sentence and never above what was detected:
    **A — verified boot, disk bound to the network**: UEFI, Secure Boot, TPM 2.0,
    systemd ≥ 257 — a signed UKI built by a `kernel-install` hook, the TPM bound to
    PCR 7 and a SIGNED PCR 11 policy (a new kernel needs no reseal), unsealed in the
    initrd phase only, the volume measured into PCR 15 (`tpm2-measure-pcr=yes`, the
    fix for CVE-2026-32606), and Tang. **B — disk bound to the network, boot not
    verified**: a TPM 2.0 on systemd 252 (Debian 12, RHEL 9) or without Secure Boot —
    Clevis, the TPM and a Tang both required; the initrd and GRUB's command
    line are neither signed nor measured, so whoever has the machine INSIDE the house
    (Tang answering) gets a root shell (`rd.break`), and says so. **C — disk
    encrypted, the boot chain open**: no usable TPM 2.0 (legacy BIOS, TPM 1.2) — Tang
    alone where it must restart by itself, a FIDO2 key or a passphrase over
    `dropbear-initramfs` where someone is there; `/boot` can be changed unseen.
    **D — encrypted at rest, the host trusted**: a virtual machine — vTPM and Tang
    inside, but the host reads its memory and its vTPM's state. `systemd-detect-virt`
    tells a VM, not whose: a VM is D unless it names a node of the house as its host,
    and is then the lower of the two. **No level for a VPS**: it stays out of the
    Swarm (decided 2026-10-27); a provider's machine is promised nothing physical.
    Servers with a BMC (iDRAC, iLO, IPMI) reach A or B, their console making the MOK
    enrolment and a recovery remote — and their TPM is often an option not fitted,
    which detection says.
  - **🔴 The two halves of A do not combine as written.** A LUKS keyslot opens the disk
    on its own: a TPM-only slot beside a TPM-and-Tang slot cancels the second factor,
    and only the combined policy and the recovery key may exist. The signed PCR 11
    policy is `systemd-cryptenroll`'s, which has no Tang; Clevis has Tang and binds
    PCR values only as literals (Clevis 20's `tpm2` pin: `pcr_ids`, `pcr_digest`, no
    signed policy — read 2026-10-28). The options, to measure on the lab before
    choosing: Clevis bound to PCR 7 and 11 with values predicted by `systemd-measure`,
    resealed by the kernel hook before each reboot; `systemd-cryptenroll` with the
    signed policy and a PIN, no Tang — a person at every boot; or the disk opened by
    the signed policy alone and Tang required one level up, for the vault key and
    Swarm's unlock key — a machine stolen whole boots to a login prompt, its apps
    never start, and what it gives up is what a running, locked-down system leaks.
  - **The best protected machine carries what matters** (owner's question,
    2026-10-28). A stolen node gives up different things: a Swarm manager holds the
    whole Raft log — every app's secrets; the controller's node holds the vault's key
    and the platform's administrators; a worker holds only the secrets of the tasks it
    runs, in memory. So `cluster init` reads the level of its machine and says when
    another would serve better; the controller and the vault live on the highest
    level, and moving them later is a verb (`hlb controller move`, to write); a
    manager is chosen by level, then count — a C or D node is never proposed, and a
    manager below the best is a warning; nodes carry `hlb.protection=<level>`, and an
    app the manifest calls vital (phase 3's criticality) is constrained to B or above.
    ⚠️ One A machine and two weak ones: three managers put every secret on the weak
    ones; one manager costs only the control plane's availability — tasks keep
    running, nothing is rescheduled until it returns. Decided 2026-10-28: asked each
    time, both costs shown, no default. The constraint on vital apps dies if a
    two-node house on the lab cannot schedule them under it: then a warning only.
  - **Debian 12 caps a node at B; nodes move to Debian 13** (decided 2026-10-28). The
    preseed and the lab install Debian 12 alone today (`vm.sh`'s only Debian image):
    the preseed, Docker's and ZFS's sources for trixie, the lab's image, and an
    in-place `bookworm → trixie` upgrade drained one node at a time. A node still on
    Debian 12 reaches B and says why.
  - **The order, each step proven on the lab** — QEMU with OVMF (Debian's `ovmf`
    carries variables with Microsoft's keys enrolled) and swtpm, so Secure Boot, the
    TPM and the PCRs are real; `vm.sh` boots SeaBIOS today:
    1. Detection and the level shown, nothing changed; a scorecard row: nodes per
       level.
    2. Each node's LUKS recovery key generated and on the emergency kit — its
       fingerprint covering it — BEFORE any disk is touched: no step below runs while
       the kit is not current, as `secrets-seal` already refuses.
    3. LUKS at install (the preseed partitions `crypto`); an existing node is drained
       and reinstalled, or re-encrypted offline — which, measured first.
    4. B: Clevis, the TPM AND one Tang of two — nested, `sss` `t=2` over the TPM and an
       inner `sss` `t=1` over the Tangs. ⚠️ Not the flat "two shares of three" this
       plan first said: the two Tangs alone would open a disk taken out of its machine
       and plugged in at home. One Tang on another node of the house, one on the VPS
       answering the house's tunnel only, so a Tang down never stops a restart and no
       node needs a Tang that needs it back; after a theft, deleting the Tangs' keys
       makes the disk unreadable for good.
    5. A: the UKI, its hook, the signed policy and the PCR 15 measurement, after
       deciding the combination above. Secure Boot keys: the distribution's shim and
       Microsoft's certificates kept — `sbctl` is not packaged, and a firmware whose
       option ROMs are signed by Microsoft does not start its graphics without them;
       the UKI and DKMS's modules signed by a MOK key, enrolled once at the console.
    6. What breaks an unlock, handled before it happens: a dbx or firmware update
       changes PCR 7 (`fwupd` says when one is pending: reseal right after, or
       announce the recovery); a BIOS that resets its keys is seen in Setup Mode at
       the next boot; a ZFS module unsigned under Secure Boot does not load — the
       storage node's pool would stay away.
    7. The running system: IOMMU on, Thunderbolt off where unused, kernel lockdown in
       `confidentiality` where neither hibernation nor kexec is needed (Debian's
       Secure Boot gives `integrity`); the firmware's password, USB and PXE boot off
       — instructions, since no software sets them.
  - **What no level protects**, said in `docs/security-model.md`: a flaw exploited in
    a running service or in Homelabus; firmware implants (only Boot Guard or AMD PSB,
    set at the factory, help); a VPS's provider; a compromised hypervisor. And once
    booted the disk is open: the controller holds Docker's socket, which is root —
    splitting it into a minimal privileged daemon behind a narrow API, the interface
    unprivileged, is its own item. Backups are already encrypted before they leave.
- ZFS native encryption, whose `zfs send -w` lets a remote site keep a copy it cannot
  read.
- The domain, the weakest point (every domain theft of 2024-2026 went through a
  registrar's support): a hidden Knot primary at home signs the zone, at least two
  secondaries serve it — the signing key never leaves the house; the simple level stays
  a provider driven by its API (deSEC). CAA with `accounturi` (RFC 8657), certspotter,
  and a nightly drift check of NS, DS, CAA and the WHOIS statuses. DANE/TLSA beside
  MTA-STS.
- An append-only destination (rest-server), pruned with another credential from another
  machine, never automatically: restic handles no S3 object lock, and Garage has none.
- Upstream images' cosign signatures checked against a pinned signer before deploying;
  Secure Boot's dbx checked (PKfail).
- The family without the owner: the emergency kit's key split among relatives (3 of 5),
  and a restore they rehearse once a year.

**3. An app without Rust, then the catalog on its own.** Gate: an app enters through a
pull request to the catalog, with no `hlb` release.
- The five schema gaps below come first: while no app enters without Rust, a separate
  repository receives pull requests nobody can merge without a release.
- `homelabus-catalog`, one repository, a directory per app; platform services and
  `hlb-types` stay here, where the resolver points. The catalog leaves the controller's
  image (`/usr/share/hlb/catalog`), so a new app version stops requiring a release.
- Three levels of source — official (its key built into `hlb`), community (any URL,
  trusted explicitly per app or per source), local (a directory). An app carries its
  source's name, so `community/foo` never shadows `foo`; a third-party source may
  REQUIRE a capability and never PROVIDE one. A revocation list `hlb` reads.
- A signed `index.json` — each manifest's and image's digest, a counter that only
  rises, an expiry, so a mirror can neither replay nor freeze it — one key per source;
  the frozen install keeps its source and index number. Each app version declares the
  `hlb` range it accepts, the index keeps several versions per app, and `3.3.1~hlb2`
  counts a packaging fix as an update.
- Quality levels computed by CI, never declared: install, update from the published
  version, back up, restore, prove, uninstall — on each pull request and weekly; shown
  as *installs, updates, restores, maintained for N months*.
- Before installing, the preview shows what the app receives: host network, Docker
  socket, public exposure, a mail admin token.
- An app's criticality (vital, important, normal) in the manifest, optional on read —
  the lifeboat's input.
- Proving ground for goal 4: calendars and contacts from Stalwart (a capability and a
  phone guide), then Paperless-ngx, Actual, Mealie, Audiobookshelf, Navidrome, FreshRSS.

**4. Always available.** Gate: the moving-house drill on the lab — the house cut, minutes
until Vaultwarden and PocketID answer from the VPS, then the way back, both timed.
- OPNsense on a machine of its own (two ports or more, on the same UPS as the internet
  line): firewall,
  NAT, three networks (trusted, devices, guests), DHCP registering names, Unbound
  recursive with DNSSEC validation, blocklists, the house's names resolving to Caddy
  locally, WireGuard for the family, NTS, the UPS's NUT server. A client crate beside
  `hlb-ingress`: the preview diffs wanted against actual, apply keeps OPNsense's
  rollback, its configuration goes to restic nightly. Its NAT reflection closes plan
  0⁗'s last leftover.
- The VPS as permanent front door: DNS points at it, it relays TCP home over WireGuard
  without decrypting; moving house, a new ISP or a CGNAT change one WireGuard peer.
  Never in the Swarm — two sites cannot keep Raft through losing the bigger one, and a
  manager reads every secret — nor in Garage, read-only with a node missing.
- The lifeboat: vital apps restored nightly onto the VPS, stopped, started once by a
  health check — goal 2's rehearsal, nightly, on a real machine. `hlb site promote` and
  `hlb site return`, by hand: with two sites nothing tells "the house fell" from "the
  link broke". An app is writable on the VPS only if its manifest declares how its data
  comes home, read-only otherwise; the preview refuses a selection beyond the VPS's
  declared memory or disk, figures measured with `docker stats` on the lab first.
- Gatus on the VPS, generated from the catalog: two probes per app (through the front
  door, and straight home over WireGuard) to say where it breaks; heartbeats pushed from
  home (backup done, lifeboat verified); alerts never through the house's own Stalwart
  or ntfy; the house probes the VPS, the VPS pings Healthchecks.io. Names the family
  understands, and an announcement published when the admin acknowledges an alert.
- Downtime measured per app: seconds per update, minutes to recover a lost node.
  stop-first for a single-volume service, with a maintenance page from Caddy for the
  gap; two replicas of stateless services; three managers once there are three
  machines; a disruption budget refusing to drain a node that would cut a vital app with
  no relief. Traps already met: start-first with host ports hangs, and only restoring
  the backup taken just before undoes a database migration — that restore in one
  command, proven on the lab.
- Later, a module of its own: CDN edges — only hostnames declared public-cacheable are
  decrypted there, everything else passes through; no wildcard certificate on an edge,
  its own key, 160-hour certificates from the house over DNS-01; a shield edge so the
  house's uplink is fetched once; public content on a domain of its own; GeoDNS before
  any anycast.

**5. Always up to date.** Gate: a patch applied with nobody there; an exploited CVE
reported within 24 hours.
- The controller calls `hlb-updater`. A policy per kind of version instead of one
  channel, overridable by the manifest and by the house — patch automatic, minor one
  click from the inbox with its notes, major manual with the catalog's migration guide,
  KEV-exploited at the next window. Guards: notes saying *breaking* or *migration* stop
  the automatic path; the catalog can hold a version back for everyone; `hlb` records
  when it first saw a tag (GHCR and Quay date nothing).
- CVEs: an SBOM (Syft) at each deploy, compared daily without pulling again; the host by
  `debsecan --only-fixed`. An alert only when a fix exists, the flaw is exploited (KEV)
  or likely to be (EPSS), and the component is exposed; the rest in a weekly digest; no
  fix, never an alert.
- Planned reboots under a lock, one node at a time: drained, rebooted, waited healthy,
  in the window, never while the house is degraded or the VPS is relaying.
  `needrestart` without Docker; `fwupd` reports firmware and never applies it.
- `cargo deny` beside `cargo audit`. Disks: SMART read nightly, a scheduled scrub, an
  alert on reallocated sectors — smartmontools is installed and nothing reads it. The
  UPS: NUT stops apps, then databases, then Swarm, in that order.

**6. The TUI installer.** Gate: a bare machine to the first app, timed.
- One description of the answers, filled three ways: a Ratatui assistant; a linear
  prompt mode for a serial console or a screen reader; `hlb install --answers
  house.toml --unattended`, the file refusing unknown fields, its secrets in another.
  Proxmox's `answer.toml` is the model.
- Its summary screen IS the plan's preview: the TUI dresses the engine, it decides
  nothing. While installing, steps print as lines that survive an SSH disconnect.
- Welcome (new house, add a machine, restore from a backup), checks (failures only, each
  with its fix), this machine, storage and encryption, domain and mail (VPS or port
  forward), first admin and passkey, summary, install (resumable), done (address, a QR
  code, where the emergency kit is, three next steps).
- No network service and no default password while it waits (CVE-2025-62877,
  Harvester's installer); `NO_COLOR`, 80×24, ASCII frames outside UTF-8.

**7. The dashboard redone.** Gate: written tasks ("a backup is late, fix it", "add your
partner"), success and time measured before and after.
- Starts from the admin diary, ranked by frequency × severity; it begins now — it needs
  time, not code. The 2026-10-07 screens were drawn without watching anyone.
- For the admin, six places instead of eight modules: Home (one sentence of state, and
  the inbox), Apps, People, Machines, Backups, Settings; the action panel and Ctrl+K
  everywhere. For the family, three: Home (app tiles, and "all works" or "Photos is
  down, the admin knows"), Me (password, passkeys, devices, aliases), Help.
- Each principle a test: home answers one question; every problem names its fix or the
  exact `hlb` command; two levels of detail at most; a number comes with its reference;
  calm by default; WCAG 2.2 (24 px targets, focus never hidden); Bits UI under our
  tokens; themes from three variables. A public read-only demo (`--demo`).

#### Standing, whatever the phase

**Goal 2 — never lose.** A restore rehearsed for every app holding data — volume,
database, bucket — in a disposable copy, weekly, its result kept and alerting on
failure, and readable by `hlb` so the scorecard can count it — the lifeboat (phase 4)
does it nightly for the vital apps, the catalog's CI (phase 3) for every app's
packaging. Proposed beside it: reciprocal backups between two houses, each keeping the
other's encrypted copy append-only — an off-site copy with no provider at all.

**Goal 4 — no Rust: the schema gaps**, each a closed list a new app has had to extend,
ranked by how many apps they would have spared (audit of 2026-10-27):
1. **Deploy knobs** — tmpfs, `sharedEnv`, host-port update order, a probe-derived wait,
   keepalives: each was a Rust change. A bounded pass-through of Swarm service and mount
   options, refused at preview when it weakens isolation.
2. **Tokens and secret forms** (`binding.rs`) — timezone, logo, VAPID, RSA. A secret
   generated by a declared template or command; install facts as generic tokens.
3. **Engines** — `DbEngine` is PostgreSQL or MariaDB, the cache is Valkey: Fluxer runs
   Valkey, NATS and Meilisearch as companions, without provisioning or dump backups.
4. **Syncing people and nodes into an app** — `Members` and `Nodes` have one variant
   each, and each needed a crate. Per-person and per-node `exec`/HTTP steps, as
   `AdminsApply` and `QuotaApply` already are.
5. **Lifecycle** — jobs run daily or weekly only; no pre-upgrade or post-restore step;
   cross-app budgets (connections against `max_connections`) are Rust tests.

**The sessions themselves.**
- ✅ `interface.md` (36,187 characters) and `operations.md` (36,862), near the 40,000
  Claude Code loads of a rule in a 200K session, split by `paths:` the same day into six
  and five files of at most 12,171 — 201 entries, none lost. Worst load for one file:
  94,764 → 69,696 characters. Next to watch: `security.md`, 26,973.
- `target/` is 84 GB, 56 of them incremental caches: `cargo clean` returns them, at the
  price of a full rebuild — the owner's call, the desktop freezes under that I/O.

### S. Stalwart 1.0 — the plan (decided 2026-10-27)

Renovate proposed `v0.16.27 → v1.0.0` (#34). It is not a version bump: 1.0 has a new
database layout — **a 1.0 server refuses to open a 0.16 store**, and the data moves only
through `stalwart-migrate` into a NEW, empty store — and renamed settings that `hlb-mail`
writes over JMAP. **Measured** on both images and on the two schemas Stalwart publishes
(`stalwart-migrate`'s `mapping/schema/`), 249 properties removed or renamed, matched
against every string literal of the crates driving Stalwart:

| | Measured | Why it matters |
|---|---|---|
| **Boot** | the catalog's one-line `config.json` and `STALWART_RECOVERY_ADMIN` boot 1.0.0 as they boot 0.16.27: no setup page | nothing to change in the manifest's files |
| **Renamed fields Homelabus writes** | `EmailAlias.enabled → enable`, `NetworkListener.tlsImplicit → implicitTls`, `SpamClassify.envFrom/envRcptTo → mailFrom/rcptTo`, `DnsServerPorkbun.apiKey/secretApiKey → apiKeyId/secret`, `MtaRouteRelay.address → host` | each is refused `invalidPatch — Invalid key for object` under HTTP 200: no alias, no submission port, no postmaster on 1.0 (3 of 5 `live_stalwart` tests fail) |
| **Which one it is** | no version is served anywhere (`/api/account`, headers, logs); 1.0 announces `urn:ietf:params:jmap:metadata` in its session, 0.16.27 does not | the client has to ask before it writes a renamed field |
| **Tasks** | `TaskStatus` gains `Retry` and `Stalled`; 1.0 retries a transient failure for ever (backoff 1 min doubling to 6 h; `Stalled` after `x:TaskManager.alertAfter` = 5), `Failed` meaning permanent — where 0.16 left every failure `Failed` for good | `publish_dkim` asks again only when no task is pending: right on both, a second task on 1.0 would duplicate Stalwart's own retry |

**Decided on 2026-10-27**: an installed Stalwart stays on the major it was installed
with until it is migrated on purpose; new installs get 1.0 once phase 4 lands. So
`hlb-mail` speaks both for as long as a 0.16 can be installed somewhere.

#### Phases

| # | Phase | Ends when | Kill gate |
|---|---|---|---|
| 1 | ✅ **`hlb-mail` speaks 0.16 and 1.0** (2026-10-28) | the generation read once from the JMAP session, every renamed field written by an exhaustive `match` on it; `live_stalwart` and `live_mail` green on 0.16.27 AND on 1.0.0 (`HLB_STALWART_IMAGE`) | — |
| 2 | ✅ **What 1.0 does differently** (2026-10-28) | each trap of `mail.md` measured on 1.0 (tasks, tracer, listeners bound at restart, SNI order, ACME, DKIM publishing) and the rule rewritten with the version it holds for — probes on fresh 0.16.27 and 1.0.0, the rest held by `live_stalwart`/`live_mail` green on both. Same on 1.0: listeners, own certificate, empty name, bans, tracer, outbound TLS, schedules, SNI order, registry maps, `badNonce`. Different: tasks retried for ever (`Stalled`); an ACME order retried as a task; and **a domain switched while its first keys are made gets no DKIM rotation, ever** — `switch` waits for them, `live_mail` holds the dates. A missing DKIM key now says Stalwart's reason beside it | — |
| 3 | ✅ **Migrating an installed Stalwart** (2026-10-28) | `hlb mail migrate` — the tool runs unattended once `answers.toml` answers its four questions, so a verb, not a runbook: `prepare`, `run` while 0.16 serves, `run --final` and `verify --full` with it stopped, 1.0 frozen on `data-v1`, `data` kept. On the lab: 8 accounts with their ids, the group's alias, two messages, every app's password (IMAPS), 0 mismatches; a message sent and delivered after; `hlb assert` green; the next backup and its verification read `data-v1`. Was: a procedure through `stalwart-migrate` (`prepare`, `run`, `run --final` with 0.16 stopped, `verify`), into a new volume, the old one kept for `rollback`; rehearsed on a COPY of the lab's volume and on an empty one, mail and aliases readable after | **the tool cannot run unattended in a container**: the procedure is a printed runbook instead of a verb |
| 4 | ✅ **The catalog on 1.0** (2026-10-28) | new installs on `v1.0.0`; an upgrade from 0.16 REFUSED in place (it would start a server that refuses its store: mail down) and pointed at phase 3 | — |

### 0⁗. Fluxer, whole — the plan (decided 2026-10-26)

Asked on 2026-10-26: Fluxer (a Discord-like chat, AGPL-3.0), completely working — text,
files, voice and video, through PocketID. **Measured** on the compose bundle
`fluxer-compose-2026.1026.152924` and Fluxer's source at that release; the catalog has
no chat app, and nothing in `crates/` names Fluxer:

| | Measured | Why it matters |
|---|---|---|
| **The stack** | 18 services: 13 of Fluxer's own images (api, worker, gateway, media-proxy, push, static, app-proxy, snowflakes, users, gifs, messages, unfurl, admin), Caddy in front, PostgreSQL 16, Valkey, NATS, Meilisearch, SeaweedFS, LiveKit. Fifteen full releases between 2026-10-24 and 2026-10-26, each image pinned by digest and tagged by its own build time | one app and fourteen companions, moved together by the catalog, never by a registry watch per image |
| **Companions** | a companion takes neither `command` nor `files` (`resolver/src/lib.rs`, the plan writes both empty); NATS needs JetStream from its command line, Valkey `noeviction` and an append-only file, LiveKit its configuration | three of Fluxer's companions cannot be started as Fluxer starts them |
| **PostgreSQL** | the api, the worker, `users` and `messages` each create their schema (one `fluxer_kv` JSONB table) at start with the app's role; no extension needed, `pg_stat_statements` optional. Their pools: 25 + 25 + 20 + 20 = **90**, on a shared server at the default 100 | the first Fluxer start exhausts the connections every other app needs |
| **Valkey** | sessions, rate limits, cron locks — and `asset:deletion:queue`, not rebuilt from PostgreSQL. `noeviction` required. The shared Valkey has `backup: false`, and a dedicated cache is refused | its own Valkey, as a companion with its own volume |
| **NATS** | JetStream required: `JOBS` (seven days) and `JOBS_DLQ`; a lost store loses jobs queued and delayed, never replayed | its store is a volume, backed up |
| **Search** | Meilisearch: the admin indexes refill themselves; the message indexes come back with `POST /admin/search/indexes/all/refreshes` | a derived volume, not backed up — a restore rebuilds it |
| **Object storage** | four buckets that must EXIST before the first start: `cdn` (attachments, avatars, emoji — irreplaceable), `uploads` (staging, a day), `reports`, `harvests` (exports, seven days). Put, Get, Head, Delete, CopyObject, multipart, ListObjectsV2; no tagging, no CORS. The client never reaches S3: every upload goes through the media proxy at `/media` | Garage stays private. But `object-storage` declares ONE bucket per app, and a bucket with `backup: true` is refused — "no backup pass reads a bucket" |
| **SSO** | stored in PostgreSQL (`instance_configuration`), set by `PATCH /admin/instance/config` — no variable, no file. The api serves `/admin/*` on a socket in its container (`/run/fluxer/operator.sock`) that takes no token, through `node bin/operator-relay.mjs` reading JSON on standard input (what `rexctl` does). Callback `/auth/sso/callback`; discovery; PKCE; the secret in the body; an issuer over HTTPS only — under `FLUXER_SSO_ALLOW_PRIVATE_ADDRESSES` for the ingress's address | the client secret goes on standard input, never on a command line. "Require SSO" turns password and passkey sign-in off for everyone |
| **Administrators** | an ACL (`*`) on the user, set by `PUT /admin/users/{id}/acls`. The groups claim maps groups to COMMUNITY roles, never to the instance's administration | nothing a claim gives: Homelabus keeps it in step, person by person |
| **Voice** | LiveKit: signalling over `/livekit/`, media on 7881/tcp and 7882/udp straight to its node, no TURN, STUN to find the public address | `publishedPorts` is TCP only (`swarm.rs`), and a companion has no placement of its own: the router forwards to ONE machine |
| **Routes** | nine paths to seven services; `/.well-known/fluxer`, `/.well-known/webfinger` and the static paths (`/web/`, `/emoji/`, `/libs/`, `/avatars/`, `/badges/`, `/desktop/`) reach their service WITH their prefix | `paths` always strips its prefix |
| **Secrets** | 32 random bytes as hex (eleven of them), one as standard base64, a P-256 pair for Web Push (VAPID, unpadded base64url), an RSA-2048 key for ActivityPub signing (optional: unsigned, a server under authorized fetch shows no preview) | `:hex` exists; standard base64 and a key pair do not |

**Decided on 2026-10-26** by the maintainer:

- **Fluxer's files live in the platform's Garage, and a bucket is backed up.** The backup
  pass reads a `backup: true` bucket and hands it to restic; a restore writes it back.
  Every app that keeps files in S3 gains it — not a private SeaweedFS in a volume, whose
  hot copy nothing here has proven consistent.
- **Calls work from the internet.** LiveKit runs on the ingress's node, announces the
  public address, and the guide has the router forward 7881/tcp and 7882/udp.
- **Proven on the lab**, deb2 at 8 GB.

**Left, on 2026-10-27**, after the lab — and closed the same day, but one:

- ✅ **Read-only roots.** All seventeen services run read-only. What four of them write
  outside their volumes goes to a new `security.tmpfs` (mode 1777): the api's socket
  and probe mark, the worker's heartbeat, the static Caddy's state, the gateway's
  rendered `vm.args` (`RELX_OUT_FILE_PATH`) — and Meilisearch's document batches,
  refused behind a green probe until a search was tried. Proven by use: sign-in, a
  message, an attachment, a link's preview, a search, a call, every log read for `EROFS`.
- ✅ **MariaDB's clients** against Swarm's 900-second VIP: MariaDB does have server-side
  keepalives (`--tcp-keepalive-time=300`); a session idle 17 minutes was lost before,
  answers after.
- ✅ **Fluxer's setup token** stayed valid after an administrator was made: the api's
  configuration closes the bootstrap (`app_public.setup.configured`), which burns it,
  and the token is the vault's, so none reaches a log.
- ✅ **Attachments kept** — decided 2026-10-27: Fluxer's default deleted them by size
  (three years up to 5 MB, fourteen days at 500 MB); `attachment_decay` is off, and a
  new attachment shows no expiry.
- ✅ `swarm_spike` ran on the lab's two-node Swarm: sixteen of seventeen, the host-mode
  UDP port included; two tests assumed one node and are pinned to theirs. The private
  registry's still needs one set up on 127.0.0.1:5000, where the lab's own is.
- **Calls from inside the house need a router that loops back** — the one left, and not
  Homelabus's to remove: LiveKit announces one address, its rewrite rules REPLACE a
  candidate's (mediatransportutil `SetNAT1To1AddressRewriteRules`, read at the pinned
  release) and `node_ip` holds one. The site itself, opened by its public name from
  inside, needs the same loop; only a house DNS pointing at the ingress makes the web
  work without it while calls do not. The guide says how to tell.
- ✅ **A MariaDB database comes back from its dump** — 2026-10-27, evening: `hlb backup
  restore <app> --database` puts back MariaDB's as it does PostgreSQL's — read back and
  checked first (its guard line, and a `USE` naming that database alone: the dump
  restores at server level, where its own `USE` says), what is there dumped, the
  database dropped and recreated with provisioning's statements, the dump restored by
  the administrator, its `DEFINER`s kept. Not one transaction — MariaDB commits each
  `CREATE TABLE` —: stopped halfway, the app stays stopped and the copy is named. Held
  by an end-to-end test against the catalog's server and restic, and run on the lab:
  Seafile's three databases put back from one pass, the tables and renames made since
  gone, the escaped grants (`ccnet\_db`) and `utf8mb4` intact, its API answering
  through all three.

#### Phases

Each phase ends on a green gate and its own commit.

| # | Phase | Ends when | Kill gate |
|---|---|---|---|
| 1 | ✅ **Companions start as their image needs** — 2026-10-26 | a companion's `command` and `files` reach Swarm, its files' secrets generated before it, its files held to the app's rules; a command — the app's too — refuses a token, which nothing would fill. Every text a deployment fills is one list (`Spec::substituted`) where six sites wrote it out. The private roots reach every service of an app that verifies its issuer or sends mail, companions included | — |
| 2 | ✅ **A port by its protocol, on the node the router reaches** — 2026-10-26 | `publishedPorts` takes `7882/udp` (a number stays TCP, as every frozen manifest reads); Swarm is handed the protocol, which it was always told was TCP; a companion takes a `nodeLabel` of its own, and its ports count against header authentication and against each other — the same port twice is never placed | a host-mode UDP port refused by Swarm: `swarm_spike` asks it, run on the lab in phase 9 (no Swarm on this machine) |
| 3 | ✅ **A path that keeps its prefix** — 2026-10-26 | `paths[].keepPrefix` routes `/.well-known/fluxer` whole, accepted by the catalog's own Caddy (`caddy_validates`); a dot segment in a prefix is refused, since Caddy matches the cleaned path | — |
| 4 | ✅ **Several buckets per app, one key** — 2026-10-26 | each `object-storage` a bucket of the app's one key, its secret generated once; two of one name refused, and `{{ s3.bucket }}` with several; `expireAfterDays` written as the bucket's lifecycle (objects, and unfinished uploads) with the app's own key over the S3 API, read back — the CLI relays 3900 too; an upgrade matches buckets by name, as databases | **passed**: Garage 2.4.1 takes `Expiration` and `AbortIncompleteMultipartUpload`, with or without `Content-MD5` — and from a key that owns nothing |
| 5 | ✅ **A bucket, backed up and restored** — 2026-10-26 | `backup: true` accepted, kind `bucket` (bulky); the pass streams every object through the app's key into restic as one pax archive ending with a trailer that counts them (`hlb_backup::tarball`), no copy on a disk; `hlb backup restore <app> <bucket>` stops the app, backs up what is there, rewrites every object with its headers and deletes the ones written since. Tried end to end on Garage 2.4.1 and restic 0.19.1 (`hlb-backup-run/tests/bucket.rs`), the restore undone by its own copy. **Found**: restic saves the half of a stream that ends early, and a killed `docker` client leaves the container to do it — the container is killed by name before its input closes, proven failing without | **passed**: 25 MiB new among 1 GB added 31 MiB; unchanged, 0 |
| 6 | ✅ **Secrets Fluxer needs** — 2026-10-26 | `:base64` (32 bytes, standard alphabet), `:vapid-private` and `:vapid-public` (a P-256 pair, unpadded base64url — the public half is the private half's, by test), `:rsa` (RSA-2048, PKCS#8 DER), each derived from the stored value, as every form is; every form a manifest writes reads back as itself, and the refusal names them all. `p256` and `rsa` in `hlb-types`, generation only; the RSA arithmetic optimised in `dev` (4.5 s → 0.24 s a key) | — |
| 7 | ✅ **An app's administrators kept in step** — 2026-10-26 | `access.admins.apply`: `grant` and `revoke` with `{{ person.sub }}`, in the app's service or a companion's, run by the role sync for every person with an identity — exit 3 is "no account yet", retried; recorded per person (migration 0048, `admin_applied`), refreshed daily; a person never made one costs no command. Its companion and its tokens checked by `catalog validate` | — |
| 8 | ✅ **The manifest** — 2026-10-26 | `catalog/fluxer`: the app-proxy and seventeen companions in the compose's order, every image pinned to the release; its own Valkey and NATS behind generated secrets (the overlay is every app's); four buckets, two expiring; the api started through a script that writes the instance's configuration over its operator socket at every start — PocketID required, sign-ups closed, setup never opened — and healthy only once Fluxer accepted it; its administrators from the roles; LiveKit on the ingress's node with 7881/tcp and 7882/udp; the guide says the router's ports. Its pools a quarter of PostgreSQL's limit and its configuration JSON, by test. **Added on the way**: `sharedEnv`, the compose's anchor written once; a service waited for as long as its probe allows | — |
| 9 | ✅ **Through, on the lab** — 2026-10-27 | installed whole on deb1 + deb2; the instance's configuration accepted at start (`PATCH /admin/instance/config` 200: PocketID required, sign-ups closed); two people signed in through PocketID; the administrator's ACL `*` given by `hlb role sync` from its first sign-in; a community, a message, two attachments; the bucket backed up, its attachments deleted (404), restored — the same SHA-256; a call between two clients from the lab's internet, through its router's forwarding, UDP both ways. **Found on the way**, each fixed and held by a test or a measure: a token outside `Token` (`{{ companion.x.host }}`, `{{ s3.* }}`) left unfilled where nothing else was used — Swarm refused the app; PocketID addresses unverified, which Fluxer refuses — the role sync says a person's own mailbox verified; Swarm's VIP forgetting a connection idle 900 s (a 503) — PostgreSQL's keepalives; Valkey unable to restart over its own data — run as its user; a host-mode service's update waiting for its own port for ever — it stops first; LiveKit answering from its overlay address — excluded | **passed**: a session idle 17 min answered with the keepalives, one without lost its connection; 1,960 audio packets each way in 20 s |
| 10 | ✅ **What never ran, on the lab** — 2026-10-27 | the admin right taken back by `hlb role sync` — one open session 403 → 200 → 403 as the role moved; a whole restore — database, NATS store, `fluxer` bucket from one night, then sign-in, the message and attachment written before it (same SHA-256), the ones after gone, the search answering; both cameras and a 1920×1080 screen share in a call; a Web Push through Mozilla's autopush, shown by Firefox's service worker (Fluxer subscribes only as an installed app — the guide says so); the data-export mail in a Stalwart inbox, its link downloading the archive; `hlb update apply fluxer` moving thirteen services to release 2026.1026.223737 together, after its backup — the catalog pinned there since. **Found**: no database could be restored — the dumps were taken and verified, and `hlb backup restore` knew volumes and buckets only: `--database` drops and recreates it as provisioning does and restores as the app's role in one transaction (`COMMENT ON EXTENSION` failed under that role on PostgreSQL 17 — the declared extensions are the administrator's, left out of the dump's list; `hlb-backup-run/tests/database.rs`); an extension named `pg_*` passed the catalog and would have failed the install | **passed**: 400 frames of the shared screen in 20 s; the push accepted by autopush for both subscriptions |

### 0‴. Mail that leaves the house — the plan (decided 2026-10-19)

Every phase of 0″ done, what the roadmap still held without hardware or a person's
passkey was §3: mail to and from the internet. **Measured** on Stalwart 0.16.26 (its
image, and its source at the tag), the code counted first — DKIM, SPF and DMARC are named
nowhere in `crates/` or `catalog/`, and nothing configures an outgoing route:

| | Measured | Why it matters |
|---|---|---|
| **Its name** | `defaultHostname` is empty, so Stalwart says the container's: the banner and `EHLO` read `220 7f3a9c0e21b4`, and on Swarm that is the task's id. The zone it computes points MX and every SRV at it | a receiver checks `EHLO` against the sender's reverse DNS; a hex string is the mark of a misconfigured or hijacked host |
| **DKIM** | ✅ a domain gets an Ed25519 and an RSA key when it is created, `active`, signing at once (`dkimManagement: Automatic`). Their public halves are published by nobody | a signature whose key is in no DNS is a failed DKIM; DMARC passes on an aligned SPF or DKIM, so one mail in two goes to spam once SPF misses too |
| **Rotation** | with `dnsManagement: Manual` Stalwart NEVER rotates — `retiring` needs a DNS updater (`task_manager/dkim.rs`) and `nextTransitionAt` stays `null`. With a `DnsServer` it rotates every 90 days and publishes first | no silent rotation to break DKIM; rotating is opt-in through a provider |
| **Providers** | Stalwart's `DnsServer` knows all seven the ingress offers — Cloudflare, deSEC, DuckDNS, Gandi v5, Hetzner, OVH, Porkbun — among forty, and RFC 2136 (`Tsig`) | the credential `hlb config exposure` already keeps (`dns-<provider>-<field>`) can publish DKIM too |
| **The records** | Stalwart computes the whole zone per domain (`Domain.dnsZoneFile`): DKIM, `v=spf1 mx -all`, MX, `_dmarc` (`p=reject`), MTA-STS, TLS-RPT, SRV, autoconfig | printed by Homelabus, nothing is invented — but `p=reject` with a key nobody published rejects the house's own mail |
| **Sending out** | two routes, `mx` and `local`; the strategy sends every remote domain through `mx`. A `Relay` route takes an address, a port, implicit TLS or not, a user and a secret | most residential lines block outbound 25: the mail queues, is retried for days, and the sender learns from a bounce |
| **People's clients** | 465 and 993 present `CN=rcgen self signed cert`, `DNS:localhost` — the certificate Homelabus issues is for the overlay name, given to the apps only | a phone set up on `stalwart.example.org` warns at every connection, or is told to trust anything |

**Decided on 2026-10-19**, on the maintainer's delegation ("do as much as you can"):

- **Stalwart is named by its route.** Its public name (`{{ domain }}` of its ingress)
  is its `defaultHostname`, so `EHLO`, the banner and the zone it computes say the name
  the DNS holds.
- **Homelabus publishes DKIM only, and only through the house's own provider.** The
  selectors are Stalwart's own names, so publishing them can collide with nothing. MX,
  SPF and DMARC are the household's domain — another provider may be its mail, or its
  web — so they are printed and read every night, never written.
- **A record is judged by what the internet resolves**, through a public resolver over
  HTTPS — never the house's own resolver, which may answer for a split-horizon zone that
  Gmail never sees.
- **The relay is a person's choice, tried before it is written**: its address, its
  account, its password on standard input into the vault.

#### Phases

Each phase ends on a green gate and its own commit.

| # | Phase | Ends when | Kill gate |
|---|---|---|---|
| 1 | ✅ **Stalwart says its name** — 2026-10-19 | `defaultHostname` set from Stalwart's route at install and by the nightly role pass, corrected when the route moves; the banner, `EHLO` and the zone read on the real image (`220 b525ac2b2e65` before, `220 mail.example.org` after; MX and SRV follow). The default domain goes with it — the singleton is validated whole | — |
| 2 | ✅ **The records, printed and read** — 2026-10-19 | `hlb mail dns`: per mail domain, the records Stalwart computed, the lines to add, the rest (SRV, MTA-STS, autoconfig) printed; read every night from a public resolver over HTTPS (`hlb_mail::public_dns`) — each DKIM selector's key equal to Stalwart's, one SPF naming every term Stalwart's does, one `_dmarc`, an MX naming Stalwart — into `mail_records` and the inbox (`mail_record_wrong`, critical, and `mail_record_unknown`), notified. Tried against Stalwart's real zone and against `example.org` as the internet has it. The SPF for a relay waits for phase 4 | **passed**: the HTTP client already there reads both resolvers' JSON |
| 3 | ✅ **DKIM published and rotated by the house's provider** — 2026-10-19 | with an exposure through a DNS provider, Stalwart gets a `DnsServer` from the same vault credentials (`Homelabus: <provider> <fingerprint>`, rewritten when the vault's changes), every domain under the exposure `dnsManagement: Automatic` publishing `dkim`, a domain a person publishes through a server of their own left alone; nightly in the role pass. Six providers' servers accepted by the real image; DuckDNS refused, its one TXT a name holding the certificate's challenge. Tried against a real BIND over RFC 2136: the active keys published at the switch, and again when gone. **Found**: a failed publishing is never retried — asked again when the night reads the key missing —; over UDP the RSA update never arrives and counts as done; and at the switch one key is skipped one time in two, a race with the rotation's scheduling — asked again once it settles. **And the ingress's Hetzner provider spoke to an API Hetzner retired** — v2 now | **passed**: a `DnsServer` is accepted offline, its secret masked on read |
| 4 | ✅ **A relay where port 25 is closed** — 2026-10-19 | `hlb mail relay`: a `Relay` route and the strategy sending every remote domain through it, its password in the vault (`mail-relay-password`), AUTH and TLS tried by a job before anything is written, the provider's SPF term expected by the nightly reading; `hlb mail relay` probes port 25 from Stalwart's node. Tried on Mailpit: relayed over STARTTLS under a root Stalwart trusts, a wrong password refused at the trial, a relay offering no TLS handed nothing. **Found**: Stalwart's defaults send a relay's password in the clear when STARTTLS is not offered, and retry a TLS error accepting any certificate — the relay has its own strategy, TLS required, no fallback, MTA-STS and DANE off. "Closed and no relay" is said by the command, not the inbox: phase 5's queue says it by the effect | — |
| 5 | ✅ **A mail that does not leave is said** — 2026-10-20 | Stalwart's queue (`x:QueuedMessage`) read by the controller every quarter of an hour into `mail_queue`; a recipient waiting over an hour is `mail_waiting` in the inbox, critical, named by its domain, notified once when it goes late; `hlb mail queue` prints each one with what its last attempt was told, its next try and its bounce. Tried on the pinned image: a message to a relay nobody listens on read `relay.test: I/O error: Connection refused (os error 111)`, its recipient in the house delivered and not listed. **Measured**: Stalwart bounces at three days, not five, and tells the sender after one; a `/get` with no ids stops at 500 messages, said when reached | — |
| 6 | ✅ **Certificates for people's clients** — 2026-10-20 | 465 and 993 present a certificate for Stalwart's public name, the overlay's kept for the apps (Stalwart picks by SNI): internal, a leaf under Homelabus's root; ACME, requested by Stalwart itself from the exposure's directory — DNS-01 where the domain's records go through a `DnsServer` already, HTTP-01 otherwise — and renewed by it. Done at install and by the nightly role pass (`hlb_engine::mail_tls`); a request that keeps failing is a failed line of that pass, with Stalwart's reason. Tried on the pinned image against Pebble: HTTP-01 through the real Caddy's route (port 80, redirected, proxied), DNS-01 through BIND with no port of Stalwart's reachable, a private ACME root handed through `trust::mount`, and internal ↔ ACME both ways. **Found**: of two certificates naming one name Stalwart serves the one ending LAST — the internal ten-year leaf would have hidden every ACME renewal — so Homelabus keeps the id of the leaf it gave and takes it back once ACME's is there; and left without names over HTTP-01, Stalwart asks for `autoconfig.`, `mta-sts.`… too, which the house does not route | **passed**: nothing new is asked of a person — the ACME address and directory, the route and the provider's `DnsServer` are the exposure's already |
| 7 | ✅ **Through, on the lab** — 2026-10-20 | an internet beside the lab — a public DNS, `mx.internet.test` and `relay.internet.test`, each a Stalwart on the pinned image, the lab's container as the house's router: a message from it delivered to a house mailbox; one from the house received there with `dkim=pass` (both keys), `spf=pass` and `dmarc=pass` under `p=reject`; the same through `hlb mail relay set`, its SPF term passing. Phases 5 and 6 on the lab's installation first: `hlb upgrade stalwart --apply`, `hlb role sync --apply` (its public name's certificate from the lab's authority over HTTP-01, on 25, 465 and 993), `hlb mail queue`. **Found**: the relay's trial verified against public roots only, refusing a relay under the private ACME root Stalwart is handed — it trusts what Stalwart trusts now. And Stalwart's traces went nowhere: a tracer to standard output, at install and every night | — |

**Left from the plan**: nothing — taken up on 2026-10-20. Accepted,
not changeable: until its ACME certificate is there, and always under an internal
exposure, port 25 presents a certificate no sender trusts — one that verifies, as
Stalwart's defaults do, retries minutes later without verifying; `hlb mail dns` says
so under an internal exposure.

### 0″. The catalog, made trustworthy — the plan (decided 2026-10-18)

Asked on 2026-10-18: is everything generic — a new app is a manifest and nothing else —,
is every app configured the way its own documentation says, and can Seafile's storage be
set per role and per person. **Measured**: production Rust names a catalog app three times
outside the demonstration and the tests (`vaultwarden-local` in `hlb-api/src/breakglass.rs`,
the Immich PostgreSQL image in an `hlb-engine` error, Roundcube in a CLI hint). The code is
generic; what is missing is what the schema cannot say, and what manifests declare that
nothing reads.

**Found**, each against the upstream documentation or source of the version pinned:

| | Where | Finding |
|---|---|---|
| ✅ | every `kind: smtp` | **fixed 2026-10-18, phase 1.** The resolver generated `<app>-smtp-password` and nothing else — no Stalwart principal held it — and the engine handed out port 587, which Stalwart's defaults do not open. No app could send mail; each of the six has now sent a real one |
| ✅ | vaultwarden | **fixed 2026-10-18, phase 2.** Sign-up closed from the install, people in through PocketID (whose sign-up `SIGNUPS_ALLOWED` does not govern) — the `/#/register` step is gone; `/api/config` read nightly, which sees the whitelist and `config.json` the environment does not |
| ✅ | seafile | **fixed 2026-10-18, phase 2**: the administrator from the vault, native OIDC (the sync clients could not pass the portal), the default `me@example.com` read nightly from `ccnet_db`. ⚠️ `ENABLE_GO_FILESERVER` IS read — by `seafile.sh` and `seaserv`, not the image's `/scripts`, where this row had looked. `gc.sh` weekly since phase 6 |
| ✅ | vikunja | **fixed 2026-10-18, phase 2**: sign-up closed, a fixed `service.JWTSecret`, a guide. Local sign-in left on — PocketID never joins a local account, so turning it off would lock its owner out — and local accounts read nightly instead |
| ✅ | ntfy | **fixed 2026-10-18, phase 2**: `deny-all`, three declared accounts (`homelabus`, `watchdog`, `reader`). 🔴 And it had never run: its entrypoint is `ntfy` alone, and without `serve` it printed its help and exited |
| ✅ | termix | **fixed 2026-10-18, phases 2 and 5**: the four variables and Termix's own `/users/*-allowed` read nightly; 2.9.2; every node given to it — an account with no right beyond a shell, a key Homelabus generates, authorized `from=` Termix's node only, a host per node shared with the role `OIDC_ROLE_MAP` gives |
| ✅ | gitea | **phases 2 and 3, 2026-10-18**: `preferred_username`, `ACCOUNT_LINKING=auto`, sign-in to read, private by default, OpenID off; its administrators and who may enter from `hlb_gitea` (admin group, required claim). **2026-10-19**: the sign-in secret off the command line — written by the guide's `sql` step, bound, into `login_source.cfg`, where 1.27.3 stores it as is —; the household's logo from Homelabus. The team map is ruled out (below) |
| ✅ | grafana | **phases 2 and 3, 2026-10-18**: VictoriaMetrics provisioned, no reporting or update checks, sign-up and anonymous read nightly; from the `viewer` level only, as `Viewer`, `Editor` or `GrafanaAdmin` by the role's level, strict |
| ✅ | n8n | fixed 2026-10-18: no `N8N_SMTP_SENDER`; `N8N_SMTP_SSL` defaults to true against STARTTLS on 587 |
| ✅ | stalwart, pocket-id | **2026-10-19**: `postmaster@` and `abuse@` one shared mailbox per domain, read by the administrators; PocketID sends as itself and mails a new-device sign-in, its settings from its manifest. 🔴 Stalwart banned the platform network's addresses FOR EVER after 100 failures a day — one person guessing through Roundcube shut everyone out: never banned now, and a ban lasts a day |
| ✅ | immich | **phase 3, 2026-10-18**: `immich_role` is read at every sign-in, but `immich_quota` only when the account is created (`auth.service.js`, v3.1.0 — this row said "every sign-in"): the claim covers the creation, an `UPDATE` on its own table every quota after. ⚠️ `0` blocks uploads: no quota is no claim, and `NULL` |

**Versions**, moved on 2026-10-19 by `hlb catalog images --apply` — the newest build of
each image's own tag shape within its major, a week old (two for Vaultwarden and
PostgreSQL), every image by its digest: Anubis 1.28.1, Bulwark 1.14.2, CrowdSec 1.8.1,
Garage 2.4.1, Gitea 1.27, Grafana 11.6.16, Immich 3.3.1 (both), LibreSpeed 6.3.0, n8n
1.123.84, oauth2-proxy 7.15.5, Seafile 13.0.28, Vaultwarden 1.37.3, VictoriaMetrics
1.154.0; pinned where they were — Jellyfin 10.11.11, PocketID `v2` (2.18.0's build),
PostgreSQL, Roundcube 1.7.3, Termix 2.9.2, Valkey `8-alpine`, Vikunja `0.24`, Seafile's
notification server. By hand, a moving tag's build being days old: Stalwart `v0.16.26`
(the build the lab runs), MariaDB `11.8.8`. Moved by the pass of 2026-10-19, evening,
each started from its manifest on its new image: Grafana 13.2.4 and ntfy v2.30.0 (every
assertion held, their sign-in's failure code still a 401), Roundcube 1.7.4 (its schema
made on PostgreSQL, its sign-in page served — no sign-in through Stalwart tried).
**Held by maturation**, to be moved by the next pass: Vaultwarden 1.37.4 (10-19, 23:35
UTC), Immich 3.3.3 and n8n 2.44.1 (10-21), Bulwark 1.15.0 (10-22), MariaDB 11.8.9
(10-24), Gitea 28.2, Stalwart v0.16.27 and Termix 26.10.2 (10-25). **The majors**,
each rehearsed on its predecessor's data and written by hand on 2026-10-19: Gitea 28.1
(Gitea's own renumbering of 1.28), Grafana 13.2.3, n8n 2.43.4, Termix 26.10.1, Valkey 9,
Vikunja 2.7 — the newest build of each a week old. Seafile 14.0.9 and its notification
server 14.0.8, rehearsed then and written on 2026-10-27 once mature, after a second start
from an empty volume. MariaDB stays on its 11.8 LTS.
Jellyfin publishes 12.x only as `12.2` and `12.2.<date>-<time>`, no shape of its
10.11.11, so nothing is proposed. `hlb-caddy` is built here (`builtHere`): what pins it
is its `Dockerfile`'s bases, each by digest.

**Decided on 2026-10-18:**

- **Profiles merge into roles.** A role becomes data: a name, a permission level — the four
  of `hlb_types::Role`, so authorization keeps four levels and `Authorized<…>` does not
  change —, mail limits, and a quota per app. "Admin with my mailbox" and "admin with more"
  are two roles. A person can be given their own quota on their account page, which says
  who set the value. Migration: one role per (role, profile) pair present, counted at
  migration time; the stored names keep stable ids; `audit_log` is never rewritten.
- **Seafile is the only file app.** Its share links get no forced expiry and no forced
  password.
- **Vaultwarden's organisation follows the roles** — invited and removed through its
  Directory Connector import route — and **confirming a member stays a click of an
  existing admin**: confirming encrypts the organisation key for the member, which only an
  owner's client can do, and a machine owner whose master password sat in the vault would
  let a compromised controller read the organisation.
- **Termix reaches the nodes as a dedicated Unix account on each, never root.**
- **"Seafile's speed" means Seafile's own settings**, measured first — not disk classes.

**Taken from a sibling installation's operations tooling** — one VPS running Vaultwarden,
Termix, Gitea and a file app behind an OIDC provider, through twenty-four security reviews.
Each is a trap they paid for:

- **A 2FA required by the SSO does not guard the local door.** With `SSO_ONLY=false`,
  Vaultwarden takes an address and a master password, and an account born from the SSO has
  no second factor of its own. Hence the organisation policy "require two-step login" —
  Vaultwarden removes whoever has none — and a nightly read of accounts without one.
- **Judge a setting by its effect, every night**, never by the line that sets it: their
  production had `SIGNUPS_ALLOWED=true` and an open Termix registration while the files
  said otherwise. Read the running container's environment and the apps' own public
  endpoints (`/users/registration-allowed`); `SIGNUPS_DOMAINS_WHITELIST` reopens what
  `false` closed; Vaultwarden's `data/config.json` beats the environment.
- **A secret never reaches a command line** — `docker run -e NAME` without a value, stdin
  for psql; never Gitea's `--secret`.
- **Bitwarden's CLI**: the official standalone binary, its sha256 pinned, never npm; its
  version pinned and tried against the server first (2026.9.x does not unlock 1.37.3).
  SSH-key items need `EXPERIMENTAL_CLIENT_FEATURE_FLAGS=ssh-key-vault-item`, and one without
  its public key and fingerprint makes the whole vault unreadable in the clients.
- **Termix, set up for its admins**: a key generated in memory, authorized `from=` the
  machine Termix runs on only, the host created through its API and shared with a role in
  "connect" mode with its authentication shared (`shareSshAuth`), the group-to-role map
  (`OIDC_ROLE_MAP`), a copy of the key in the vault, a rotation command.
- **Updates**: a digest on every image, tooling included; seven days of maturation,
  fourteen for Vaultwarden and PostgreSQL; never a major alone — in code, not in a
  config the bot can edit —; never downward; the same tag shape (`18-alpine` is not
  `18.0-alpine`); the digest must be what the tag names at the registry; an active probe
  after; and a notice on success too — automation that stays silent cannot be told from
  automation that does nothing.
- **Backups**: free space checked first; every piece fatal; the dump read back; the
  off-site credential cannot delete (a versioned bucket, a policy without
  `DeleteObjectVersion`, proven on a witness object); a restore refuses an archive dated
  in the future or rewritten; what a restore brings back is filtered — Vaultwarden's
  `config.json`, Gitea's `app.ini`, hooks and `custom/` — since after an intrusion the
  archive is the intruder's.
- **The host**: journald capped (a full disk took their site down for 2.5 days and their
  backups failed silently); sysctl hardened; a memory limit on every service.
- **The ingress**: `read_header` against slowloris; probes (`/.env`, `/wp-login.php`) cut;
  cross-site forced writes refused; logs without headers or query strings; a rate limit
  on **every route that checks a secret**, matched on the decoded path (`%74oken`,
  `//user/login`) and on each app's own failure code (Vaultwarden answers 400, Gitea 200)
  — and a test that it fires: none of theirs did, because of directive order.

#### Phases

Each phase ends on a green gate and its own commit.

| # | Phase | Ends when | Kill gate |
|---|---|---|---|
| 0 | ✅ **Commit the tree in progress** — 2026-10-18 | the 42 files of 2026-10-18 committed | — |
| 1 | ✅ **Outgoing mail** — 2026-10-18 | `kind: smtp` creates the app's own sending account in Stalwart, tried before it is written; 587 is open; `{{ smtp.from }}`; an app sends only as itself; `catalog validate` refuses a capability no token reads; then Vaultwarden, n8n, Vikunja, Seafile (`local_settings.py`), Gitea (`smtp` added), Roundcube | a real message sent by each app; one not sent is not done |
| 2 | ✅ **Doors closed, and checked by their effect** — 2026-10-18 | per app: Termix's four variables; Vaultwarden's set (`ORG_CREATION_USERS=all`: only PocketID's people and invitees come in); Gitea; Seafile's admin from the vault and native OIDC; Vikunja; Grafana; ntfy `deny-all`; n8n's owner and Jellyfin's admin made at install by the guide's `api` step — no app left where the first visitor becomes admin. **Generic**: manifest `assertions` (HTTP, the running task's environment, one read-only `SELECT`) read every night into the inbox and each app's page, `hlb assert` now; `api` guide steps with a probe; `{{ secret.x:bcrypt }}`; `hlb secret-get`. Each app's assertions held on its real image, and failed on the door opened | — |
| 3 | ✅ **Roles as data, and synced** — 2026-10-18 | the decision above; one PocketID group per role; `allowedRoles` per app, closed by default — an unknown role closes the app —, with a manifest floor (Termix: admin); giving an admin-level role lists what it opens, computed from the manifests; groups read by Gitea (claim required, admin group, team map), Termix (`OIDC_ROLE_MAP`), Grafana, Immich, Vikunja; quotas by claim (Immich) or by `exec` (Seafile, `seafile_api.set_user_quota`: role quotas are a Pro feature); Vaultwarden membership by role | **passed**: `seafile_api.set_user_quota` works in 13.0.25 Community, through its RPC socket in the container |
| 4 | ✅ **The emergency vault** — 2026-10-18 | the organisation, its "Server" collection and the account's membership made by an owner once — `hlb emergency vault` prints the steps —, then the account given its own second factor and an API key by Homelabus, and VERIFIED every run: a confirmed `User`, `Server` editable and no other collection, the two-step policy on; nothing written otherwise, and the break-glass safeguard withdrawn at once. Every recovery sign-in a manifest declares (`recovery:`, held by `catalog validate`: generated somewhere, and every `hlb secret-get` a guide sends a person to) deposited, a rotated one updated with the former password in the item's history; nightly in the controller. Two SQL assertions on Vaultwarden: every organisation requires two-step login, and every account has a second factor — owners and admins included, whom the policy exempts. `hlb emergency kit`: the master key, the repository's password and each destination's credentials on a sheet, with the restic commands that bring the state back; a safeguard counted while its fingerprint is today's. The pinned CLI REPLACED by Bitwarden's client cryptography in `hlb-bitwarden`: the live test needs it anyway to be an owner, and the official CLI 2026.8.0 crashes on Vaultwarden 1.37.1's policies | **passed**: the official CLI (2026.4.2) decrypts every field Homelabus deposited — history and marker included — and Homelabus reads an item the CLI made |
| 5 | ✅ **Termix, complete** — 2026-10-18 | 2.9.2; `access.nodes: termix`. An administrator hands over an API key once (`hlb termix connect`, on standard input) — making one takes a session — and it becomes Homelabus's own Termix account and key, theirs deleted. On every node, by a job through `chroot /host`: an account `hlb-termix`, no right beyond a shell, and a key drawn in memory (`hlb-termix`'s own OpenSSH writer, read back by `ssh-keygen`), authorized `from=` Termix's node — its address, and on that node `docker_gwbridge`'s subnet. In Termix: the credential, the roles `OIDC_ROLE_MAP` gives, a host per node removed when the node leaves, each shared to `connect` with its sign-in. The key in the emergency vault; `hlb termix rotate`, the next key beside the current one everywhere before Termix moves; nightly in the controller. `hlb-termix`, a client like `hlb-identity`, said Termix-specific | — |
| 6 | ✅ **Seafile, complete** — 2026-10-18 | **measured on the lab** (Caddy on one node, Seafile on the other, the overlay over WireGuard): a 1 GiB web upload's body goes in 1.5 s from Seafile's own node, 2.7 s across the overlay and 2.7 s through Caddy — ~400 MB/s, Caddy and the MTU adding nothing measurable —, then 4–5 s "stuck at 100 %", the server cutting the file into blocks, in iowait; 10,000 small files through the sync client (8.0.10) in 9.9 s, the server's CPU under 60 % of two cores. Then: `ENABLE_RESUMABLE_FILEUPLOAD` (a two-piece upload resumed through Caddy, the file read back whole); the notification server, a companion behind the route's `/notification` (websocket 101 through Caddy); `seaf-gc` weekly — online in the community edition since 12.0 — with `[history] keep_days = 90`; `ENABLE_SETTINGS_VIA_WEB=False`; `ALLOWED_HOSTS`, read by an assertion sending another `Host` (400); `TIME_ZONE` from `{{ timezone }}`, asked before the install; encrypted libraries v4 with argon2id; `[database] max_connections = 40`, two pools of it plus 16 under MariaDB's 151, held by a test. `seafile.conf` stays the volume's: the start script runs the image's own first-start creation first, then sets the keys Homelabus owns | **fired, on half**: Seafile's speed setting, `max_indexing_threads = 4`, was no faster (29–48 s against 27 s, the same disk) — Seafile's manual gives it to S3 and Ceph — and is not set. Fast on the LAN and through Caddy, so slowness from outside is the uplink, which the lab cannot reproduce |
| 7 | ✅ **The whole catalog up to date** — 2026-10-19 | every image of the catalog by its digest, held by `catalog validate` (`builtHere` excepted: a release builds it, from the `Dockerfile`'s bases, each by digest), and every image Homelabus runs itself — restic 0.19.1 (`latest` four times, each node its own), the two dump clients, the Docker CLI, the relay `alpine/socat:1.8.0.3`, the `Dockerfile`'s six bases — found by its shape in every source, never listed. `hlb catalog images [--apply]` moves them: the newest build of the tag's own shape (its `v` included) within its major, dated by the build at the digest written, `maturationDays` (7, never fewer; 14 on Vaultwarden and PostgreSQL); a major is said, never written. `hlb update`: every candidate dated and refused before maturity (`--before-maturity`, audited); a catalog move carries the catalog's digest, never downward — by version, and by build date across a moving tag; the companions it moved switched with their app and before it (neither `update` nor `upgrade` had ever moved one); scanned at the digest that will run; every outcome a row of `update_runs`, notified by the controller, success included. **Found on the way**: tag lists are paged (ghcr.io, 100 a page — Immich's `v3` was never seen); a deployment without a digest fell back to the tag (the lab's PostgreSQL, for days); `hlb dr exercise` restored into a musl image | **fired, for the majors**: none was rehearsed on a restored copy, so all eight stay on their major, said by every pass |
| 8 | ✅ **Operations and hardening** — 2026-10-19 | journald capped and sysctl (✅ 2026-10-19: `cluster init`, `node add`, `node upgrade`), a `memory` field read by Swarm and the capacity budget (✅ `reserve` and `limit`, all 26 services of the catalog, required by `catalog validate`), image pruning on the nodes (✅ nightly and `hlb node prune` — 4.3 GB of 14.5 on the lab's deb1); Caddy as above, the rate limits fed by **auth routes declared in the manifest** (path and failure code) (✅ 2026-10-19: tried on the real `hlb-caddy` — the eleventh try a 429, `%74oken`, `//` and capitals counted — and the CrowdSec scenario on the lab's CrowdSec; nine apps declare theirs, each code read in its source); backup destinations that cannot be erased, proven (✅ `hlb backup dest prove`: a witness written with the destination's credential, then deleted with it — against rest-server 0.13.0 with and without `--append-only`, Garage 2.4.1 and MinIO, eight cases each as it is. **Found**: Garage gives every object a version id and keeps none of them, so the cluster's own destination is never out of reach; on MinIO a policy that leaves `s3:DeleteObjectVersion` out still deletes versions through `s3:DeleteObject` — only a `Deny` stops it, which reading the policy would never have shown); restores pinned and filtered (✅ only a snapshot Homelabus recorded taking, every one of them now (`snapshots_taken`), one written by anyone else set aside and named, its full id — the hash of its content — restoring it anyway, tried on a real restic with a forged latest; filtered at the START rather than at the restore, so every way back in is covered: Gitea rebuilds `app.ini` from its environment, removes `custom/`, `.gitconfig` and `authorized_keys`, keeps each repository's hooks and config to its own and writes them again — a forged hook ran at the first push under the old start, and nothing under the new —, and Vaultwarden reads `config.json` from outside its volume — a forged one opened its admin page and sign-ups. **Found**: Gitea ran with an EMPTY `SECRET_KEY`, so 1.27.3 encrypted second factors and Actions secrets with a constant written in its source (not the sign-in's secret, stored as is — checked 2026-10-19); its four keys come from the vault now); drills with no side effects (✅ the restored server has no network, archives nothing — its own `archive_command` would have pushed into the real archive — and runs no replication worker; no drill starts an application, so a restored n8n runs no workflow); this repository's CI pinned by SHA, read-only token, `cargo audit` and `bun audit` (✅ 2026-10-19, held by `hlb-types/tests/workflows.rs`; the first `cargo audit` found 10 vulnerabilities — quinn-proto and rustls, moved; `rsa`'s Marvin has no fix and is ignored with its reason in `.cargo/audit.toml`) | — |

**Left from phase 3**, each said where it shows: Vaultwarden's members are kept, but its organisation and API key are an owner's to make
— by hand still, after phase 4 — and until then the sync says "not configured"; a role per Vaultwarden
group (`ORG_GROUPS_ENABLED`) is written since 2026-10-19, a removed role's group emptied — an owner gives each its collections. The portal's five-minute refresh of a
session's groups rests on PocketID's source (refresh tokens issued with no
`offline_access`), not on a sign-in run through oauth2-proxy. On the lab since
2026-10-19: the controller's role pass runs, Stalwart and PocketID took theirs; no person
there has a mailbox or a PocketID sign-in, so groups reaching an app at a real sign-in
is still a person's to watch.

**Left from phase 4**: Vaultwarden is installed on the lab (2026-10-19), and `hlb
emergency vault` waits there for its organisation, which an owner makes in a Bitwarden
client after signing in through PocketID by passkey — what no command does for them.
Every step held against the pinned image on PostgreSQL, and the official CLI read the
result. The account's address
must be a mailbox a person reads: with mail on, Vaultwarden's invitation is a link sent
there, and registering needs it. A password generated by an install reaches the vault at
the controller's next nightly pass or `hlb emergency vault --apply`, not at the install.
An item Homelabus made whose app is gone is kept — the data it opens may be restored.
The kit safeguard proves a kit was GENERATED with today's material; that it was printed
and put away is a person's to know.

**Left from phase 5**: none of it has run on the lab, which runs no Termix: its first
API key takes an administrator's session, through PocketID. Termix's API held against its
2.9.2 image and, on 2026-10-19, 26.10.1, the node script against Debian's and Alpine's `sshd` in containers standing
for nodes, the `chroot` with its four capabilities against a Debian root; Swarm's own
job path and a real `docker_gwbridge` were not. That a container reaching its own host
arrives from its bridge's subnet is the kernel's local delivery — no `POSTROUTING`, so
no masquerade — and was not observed: on the development machine `ufw` dropped the
packet first, and a node firewalled that way would shut Termix out of its own node.
Termix asks a person to accept each node's host key at their first connection — no
API sets it — so `hlb termix sync` prints each one to compare. A node joins Termix at
the next nightly pass or `hlb termix sync --apply`, not at `hlb node add`. The account
stays on a node when Termix is removed. The key went into the emergency vault through
`access.nodes`, not a `recovery:` line: nothing in the manifest generates it.

**Left from phase 6**: the uplink — "slow from outside" — was not measured: the lab has
none, and a person's real one is the next measurement. The lab's disk (ZFS on qcow2 on
an encrypted btrfs) slowed by five times over the runs, so the indexing figures hold for
that stack only. The notification server ran on a database Seafile had
already filled. 🔴 A fresh install of Seafile failed until 2026-10-19 — the start skipped
two directories the image's own makes first —; found by a rehearsal that began empty,
tried since on a fresh volume, the notification server included.

**Left from phase 7**: an
installation moving across a major runs `hlb upgrade <app>` then `hlb update <app>`, and
between the two its new configuration meets its old image — Vikunja's OIDC sign-in is
off for those minutes. A first pin of a moving tag whose build is days old is a person's
choice: the bot keeps a pinned digest until the next build matures, but has none to keep
the first time. The project's own images carry no digest in the catalog, and ghcr.io
refuses `hlb-caddy` anonymously — an installation needs its `registry-ghcr.io`
credentials. On the lab since 2026-10-19: the controller (`hlb-controller:lab10`) runs,
PostgreSQL is pinned by digest, Vikunja runs 2.7. 🔴 PostgreSQL's update lost its probe
there — every read-modify-write did, bollard reading `HealthCheck` where Docker writes
`Healthcheck` —, fixed in `SwarmOrchestrator::inspect_whole`. deb1 was stopped with `vm.sh
down` once, which kills qemu: its databases recover from a power cut on the next boot.

**Left from phase 8**: `hlb-caddy` must be released with `caddy-ratelimit` before
an installation publishes an `authRoutes` (the lab runs a local build of it since
2026-10-19): on the 0.2.0 image, the ingress job's `caddy
validate` refuses the new Caddyfile and keeps the routes as they were. Apps with no
`authRoutes`, each for a reason: Roundcube reads `_task=login` from the body as well as
the query, so no matcher Caddy has names its sign-in — it locks an account after three
failures a minute itself (1.7.3), and Stalwart no longer bans its address; Stalwart checks Basic authentication on every path and bans by itself;
PocketID signs in by passkey; Termix's password sign-in is closed; Bulwark signs in
through Stalwart; Gitea's API takes a password by header. The User-Agent and the query
arguments are gone from the access log, and with them CrowdSec's bad-agent, SQL-injection
and XSS scenarios. Deb2 hung at boot on 2026-10-19 under the host's load (sshd never
came, ACPI ignored); cut with `vm.sh down` the same day, with the maintainer's leave, it
came back in four minutes. Backups: every destination is proved again each week by the controller (since
2026-10-19), and kept to the retention policy where the proof says it can be erased
anyway — one out of reach is its owner's to prune. A lifecycle rule expiring old
versions is not tried, since trying writes one. The snapshots taken before 0039 are
known by the last of each run only: an app's other volumes need their full id until the
next pass. Gitea's repositories are cleaned at every start, which costs a pass over
each; its `custom/` does not survive one — the logo comes from Homelabus. Gitea's four
keys change on an installation that had them empty: its second factors and Actions
secrets (none on the lab, which runs no Gitea) are lost; its PocketID sign-in, stored
as is, is not.

**Generic mechanisms this adds** — after them an app is still a manifest: the SMTP account;
`assertions`; `verify: sql` for guides; routes by path to a companion (✅ phase 6,
Seafile's `/notification`) and paths open to anyone (✅ `openPaths`, n8n's webhooks);
a guide's `sql` write with its values bound (✅ Gitea's secret); scheduled
`jobs:` (✅ phase 6); roles as data with PocketID groups and
`allowedRoles` (✅ phase 3); quota by claim, `exec` or one `UPDATE` (✅); the vault-deposit flag (`recovery:`, ✅ phase 4); declared auth routes (✅ phase 8);
`memory` (✅ phase 8); a `{{ timezone }}` token (✅ phase 6, Bulwark's too); digests in the
catalog (✅ phase 7), and `maturationDays`.

### 0. ✅ The interface, made usable — the plan (done 2026-10-07)

Decided 2026-10-07, on the maintainer's verdict after using it: not ergonomic, hard to
understand, space badly used, "it looks AI-made". The Svelte plan below organised the
interface around the server's `attention`; it never asked what a screen costs to READ.
Measured on the demonstration, French, Light, 1280 × 800:

| | Measured | Why it matters |
|---|---|---|
| **The home** | 2,111 px — **2.6 screens**; 3,795 px at 360 px | a dashboard is read at a glance or not at all — one screen, no scrolling (Few) |
| **The inbox** | 31 lines in six cards, and **7 are one cause**: six applications never backed up, plus the `backup-absent` alert saying so | one problem read seven times, and the other 24 lost under it |
| **Repetition** | `garage` "JAMAIS sauvegardée" is on the home **three times** — inbox, Applications widget, Backups widget | the pinned widgets restate the inbox |
| **Language** | **11 of 23** detail lines on the French home are English — the server's sentences | "on ne comprend pas grand chose" is partly literal |
| **Lists** | **1 `<table>` in 32 pages, 2 pages that filter**; an account is a ~320 px card, two per row, no search | 1,000 accounts ≈ **160,000 px** of scrolling; at 40 px a row with a search field, one keystroke |
| **Status** | the same "action requise" pill **16 times** on the home, on 8 of 12 application rows | a badge that is everywhere says nothing — the REASON is what a person needs |
| **Details** | 2 detail pages (application, machine); none for an account, an alert, an invitation | the inbox line about `dominique` leads to the whole list |

**What the others do** — looked at 2026-10-07, chosen for the features this project
shares with them, not for resembling it:

| Pattern | Who | Here |
|---|---|---|
| One-screen overview, the detail one click away | Proxmox's datacenter summary, Cockpit's Health card, TrueNAS 24.10 | the home becomes a status strip and the top problems |
| A problem grouped by CAUSE, its fix offered in place | Home Assistant's Repairs (count on the sidebar, "Fix" flow), Sentry issues (one issue, N events), Alertmanager grouping | issues computed on the server, each with the action that fixes it |
| An inbox beside its detail; snooze; `j`/`k` | Linear | `/inbox`, two columns; "set aside until…", server-side |
| Filters as chips stored in the URL; export of what is filtered; bulk actions on a selection | Tailscale's machines, Google Workspace's users, Carbon's data table (rows 24–64 px, 40 by default; the batch bar replaces the toolbar) | one `Table` component |
| Chrome sparse, content dense; two or three colours; cards only for unlike items | Linear, Vercel, GitHub Primer, Nielsen Norman on cards vs tables | rows everywhere a list is compared; cards for the launcher and the widgets |
| A bar of recent history per service | Uptime Kuma's heartbeat bar, Gatus | `ServiceStatus.uptime` is already served, one sample a day |
| Last run AND when the next one is due | Healthchecks.io | each backup row shows its deadline |
| `Ctrl+K` that runs actions, not only finds pages | Umbrel 1.0, Linear | the palette learns "back up gitea now" |

#### Phases

Each phase ends on a green gate, its own commit, and a contact sheet looked at.

| # | Phase | Ends when | Kill gate |
|---|---|---|---|
| 0 | ✅ **Close the previous plan** — 2026-10-07 | phase 7 committed; a 404 says "not found" with a way back, never Retry; `StatusVerdict` gains a variant for nothing exposed | — |
| 1 | ✅ **A demonstration at scale** — 2026-10-07 | `--demo-scale large`: 1,000 accounts (48 of them half-created), 300 invitations, 5,000 audit entries, 12 machines; `shots` photographs it beside the other two and ends by naming the tallest screens. **Measured**: the accounts are **174 screens** tall at 1280 px and 399 on a phone; `/api/accounts` answers in **1.2 s** in release (3.1 s debug, 293 KB), polled every 15 s — four queries per account, one of which reads EVERY user, so the cost is quadratic; invitations and the audit are **cut at 100 without saying so** (300 and 5,000 stored) | **fired**: 1.2 s is six times the gate, so the accounts are searched and paged ON THE SERVER in phase 3, the quadratic read first. Not 60 applications: an installation runs what the catalogue holds, 22 manifests |
| 2 | ✅ **Foundations** — 2026-10-07 | `Table` (`ui/Table.svelte`) over `listing.ts`, which is pure and tested: a search that ignores accents, filters, sort with the unknown last either way, 50 rows a page — all held in the query string, so a filtered view reloads, shares and comes back with Back; `j`/`k` walk the rows; "nothing yet" and "nothing matches — clear" are two states. A row's state is a dot and a word (`Status`), not a pill. `Density` (comfortable 40 px, compact 32 px) stored beside the theme, `PUT /api/preferences/density`. The applications are its first table. **Moved**: `PageHeader` to phase 6, where its first page is; the 4,000 px crawl of the large demonstration to phase 3, which it would fail until then | — |
| 3 | ✅ **Lists become tables** — 2026-10-07 | accounts (and `/accounts/[name]`, where the explanation, the remedy, the mailboxes, Bitwarden and the role went), invitations, the audit, the timeline, backup runs, secrets, exposure. **The 1.2 s was not the thousand rows**: `State::account` read the whole user table to find one row; `State::accounts` reads everyone in three queries, held equal to the single read by a test — **23 ms** in debug, so the accounts stay narrowed in the browser. The audit, which only grows, is searched and paged ON THE SERVER (`/api/audit?q&outcome&page` → `AuditPage` with its counts); invitations are no longer cut at 100; both exports are whole (they stopped at 5,000); the timeline and the runs say they are the latest 200. A role given to a selection is one plan (`POST /api/accounts/role/{role}`), refused if the selection holds every administrator — and the single route now refuses an account nobody has, which it "applied" into a foreign-key failure. `e2e/scale.spec.ts` refuses a page over 4,000 px in the large demonstration; on the old accounts page it reports 139,222 px | machines kept as cards: 1.5 screens at 12 machines, and the gauges read |
| 4 | ✅ **Problems, grouped by cause, on the server** — 2026-10-07 | ✅ 2026-10-07: `/api/issues` gathers the twelve sources the inbox read one by one, through their own builders, for the role asking; `hlb_api::issues::Cause` (38 causes, counted at ~55 sentences before — under the gate) and `group()`; health and exposure decide their cause where they write their sentence; an alert restating a cause folds into it. The household's 31 lines are 21, the thousand accounts' 80 are 21, all in the person's language. Set aside per person for a day or a week (`/api/issues/aside`, `issue_asides`): the line stays listed among what is set aside, stops counting in the navigation, and comes back early when it covers more or its attention rises — Sentry's archive-until-escalating | **counted**: ~55 distinct sentences, under 120 — all converted |
| 5 | ✅ **The home on one screen** — 2026-10-07 | a strip of one tile per module — its causes counted, or "nothing to report" — each a link; the eight worst lines, then "show the others"; what is set aside below, folded. `HomeWidget::DEFAULT` is empty: the four default cards restated the inbox as lists. `e2e/home.spec.ts`: the populated home at 1280 × 800 does not scroll (with thirty lines shown it measures 1,249 px and fails), and on a phone the strip and the first three problems are above the fold | — |
| 6 | ✅ **Detail pages that act** — 2026-10-07 | `PageHeader`: the name, what is wrong with it — the inbox's own causes naming it ("never backed up", not "action required") — and its actions, in the header: an application's Open, Back up now and Remove; a machine's drain; an account's Bitwarden. The replica count is changed on its own row; the copies are shown per destination. **Found on the way**: a reload or a shared link of any machine (`/nodes/10.0.0.2:8421`) or any `firstname.lastname` account answered 404 — the fallback took a dot for a file. A file is now an extension `mime_of` knows, and the crawl requests every page it reached directly, as a reload would | not the uptime bar on an application: `/api/status` serves EXPOSED services only, and an empty bar on the rest would read as an outage |
| 7 | ✅ **The remaining server sentences** — 2026-10-07 | counted, then: an account's explanation from its `AccountState` (4), an alert's from its rule name (8, held to `default_rules` by a test), an exposure gap from `ExposureSummary.cause` (5) — each a value the server sends and the interface words | **stopped**: the health findings (~12, built with figures and durations, and their good states have no cause yet — worded after the plan, the same day, as `HealthFinding`), timeline lines (mostly data), and every action's summary, steps and blockers (several hundred) stay English — the last is the plan's own text |
| 8 | ✅ **Look at it** — 2026-10-07 | the pill is gone — `Mark` is a dot and a word, everywhere at once (24 sites), and `Status` merged into it; a detail title is the shell's size; applications carry their catalogue icon; invitations are a full-width table with the form folded above it; a machine's card no longer says "action required" above the problem it names. `shots` keeps the previous run in `target/shots-before` and lays it beside the new one, and photographs the home with every card pinned — no card had ever been on the sheet, none being pinned by default. Then, decided by the maintainer's delegation: **the cards are figures** (`Figure`: how many, out of how many, a bar split by state, each state named) — a card that listed problems restated the inbox; the catalogue is a `Table` (search and category in the URL, the manual steps counted in the row and listed when installing) — 22 like items as cards of uneven height; **red only where it is meant**: the navigation's counts and the home's tiles are a coloured dot beside a number in the text's colour, and a tile says nothing until the inbox is read — it said "nothing to report" over no information; the shipped accents are **blue**, not the indigo that read as a template — light enough in the dark theme (#86B4F9) and deep enough in the light one (#1A52B4) to stay 60 apart from "ok" under tritanopia, which a mid blue is not (18 and 42). **Measured after**: accounts 174 → 3 screens, invitations 7.5 → 2.9, audit 7.5 → 2.9, home 2.6 → 1, catalogue ~2.5 → 1.4 | the maintainer's eye: the sheet before and after, narrow French first |

**Two decisions this plan reverses or needs.** The server's sentences were kept English
on 2026-10-05, "revisited if it reads badly in use" — it does, so phases 4 and 7 revisit
it. And a bulk action needs a route taking several targets, previewed as ONE plan: one
preview per account would make selecting fifty accounts fifty confirmations.

**Ruled out of this plan.** A snapshot browser like Backrest's: there is no restore
route, and the CLI's point-in-time restore stops at preparing one on purpose — it ends
on a human decision. A free-form widget
grid (Umbrel, TrueNAS): the pinned, ordered list exists; a drag-and-drop editor is a lot
of interface for a household's home page.

### 0′. ✅ The interface moves to SvelteKit — the plan

Decided 2026-10-05. The egui interface (`hlb-ui`, 26,467 lines, 24 screens, 299 tests)
is retired; its successor is a **SvelteKit** single-page app in `web/`, built with
**Bun**, served by the controller itself. Nothing of the egui era is kept because it was
chosen: each piece below was re-decided on its merits, and the measurement that decided
it is next to it.

**What does not change.** The controller is already an HTTP API: 68 routes, the 25 that
change something walked by the invariant tests, cookie sessions, the `x-hlb-ui` CSRF header, `?apply=true` for anything that acts. The resolver,
engine, state, orchestrator, CLI and domain crates are untouched. The interface is one
more client.

**What does.** Three things, and the second is the real architectural change:

1. **The type contract** is the controller's **OpenAPI document**, generated from the
   Rust by `utoipa` 6 + `utoipa-axum`; `openapi-typescript` turns it into types and
   `openapi-fetch` into a client where path, verb, parameters and bodies are all
   checked by TypeScript. Chosen over `ts-rs` (types only — the paths would stay
   strings, and a renamed route a runtime 404) and over `aide` (the better design,
   inferring from signatures, but its schemars-1 line has been alpha since 2025-11).
2. **The business rules stay in Rust.** The egui client called about **30 distinct
   methods** on `hlb-api` types in-process — `attention()` alone on 15 types, plus
   `verdict()`, `coverage()`, `problem()`, `mute()`… A browser cannot run them and a
   TypeScript copy would drift. They reach the interface as **serialised values** the
   controller computed: a structure, never a sentence.
3. **Translations** move from Fluent to **Paraglide JS 2**: every message compiles to a
   typed function, so a missing key or a wrong parameter is a type error. Measured: the
   `.ftl` files used 38 plural selectors and **zero** terms, attributes or functions —
   nothing Fluent-specific — and `route.ftl` had already drifted between `en` and `fr`
   by five keys, the failure a compiled catalogue makes impossible.

**Tooling, set up 2026-10-05 before any phase.** The official Svelte plugin for Claude
Code (`svelte@svelte`, from `sveltejs/ai-tools`, enabled in `.claude/settings.json`):
the Svelte MCP server — current Svelte 5 and SvelteKit documentation, and
`svelte-autofixer` to check what gets written — two skills, a `svelte-file-editor`
agent, and the Svelte language server (`svelteserver`, installed separately). The
Playwright MCP server (`.mcp.json`) is what `egui-mcp` was: driving the running
interface — accessibility tree, clicks, screenshots.

#### Phases

Each phase ends on a green gate and its own commit.

| # | Phase | Done when | Kill gate |
|---|---|---|---|
| 0 | ✅ **Retire egui** — 2026-10-05 | `hlb-ui` deleted; the half-finished batch archived on `archive/egui-wip` (79cf747) so nothing is lost; `.mcp.json`, `egui-mcp`, `/shots`, the wasm CI job and the native-UI system packages gone; `.claude/rules/interface.md` sorted — **54 of 77** entries kept (product rules), 23 egui-only dropped; `no_read_route_is_dead` `#[ignore]`d until phase 5; the advertised-command test no longer reads nine named egui screens | — |
| 1 | ✅ **Untangle what egui imposed on the rest** — 2026-10-05 | every site found by grep is gone or says why without naming egui; the palette validator and the three shipped palettes, which had left with `hlb-ui`, are back in `hlb_api::palette` and now run on the SERVER — a declared theme or a brand accent that merges two states is refused by the loader, the controller and the CLI; faces may be `woff2`/`woff`; `rust-version` measured down to 1.88 | — |
| 2 | ✅ **Typed handlers, and rules as values** — 2026-10-05 | 35 of the 70 routes returned an untyped `Response`; every JSON one now returns `ApiResult<T>` or `ActionReply` (the action protocol keeps its 422 carrying the plan, typed as `ActionError::Unplannable`); `ApiError` is one `thiserror` enum answering `hlb_api::ErrorBody` — the extractor's 401/403, once bare text, included; a test refuses a new untyped handler or a `json!` body, the 10 non-JSON ones named with their reason; 22 types serialise their rule VALUES beside their fields through `judged!` (computed by the method at serialisation, never stored), borrowed verdict enums became owned and `#[serde(tag = "kind")]`; what egui computed in-process with no endpoint is served — the outage simulator inside `/api/topology`, the break-glass verdict in `/api/recovery`, and every palette, brand accent applied, in `/api/themes`; the French wire values renamed — none was persisted as JSON, and the one stored value went through migration 0025 | — |
| 3 | ✅ **OpenAPI** — 2026-10-05 | `ToSchema` on the 105 schemas that cross the wire, `judged!` types with their rules (the macro wraps the struct and derives the schema from a mirror of the same tokens); the 68 handlers carry `#[utoipa::path]` and the router is one `routes!()` each, three bare routes named by a test; served at `/api/openapi.json`, committed as `web/openapi.json` and refused when stale; **every GET of the demo installation is checked against its declaration** — status, content type, and the body against its schema closed with `unevaluatedProperties` — which caught a typeface route declaring two of its four types; axum's rejections answer `ErrorBody` through `crate::extract` | **the list went**: role, public and preview are the extensions `x-hlb-requires`, `x-hlb-public` and `x-hlb-preview`, and every invariant test walks the document — the anonymous and role tests now cover the 43 reads too, not only the 25 writes |
| 4 | ✅ **The SvelteKit skeleton** — 2026-10-05 | `web/`: SvelteKit 3, Svelte 5, TypeScript strict, `adapter-static` with `index.html` as the SPA fallback; Bun runs everything, `bun --bun vite build` included; `openapi-fetch` behind one `connect()` that sends `x-hlb-ui` and same-origin credentials, and a test refusing a bare `fetch` anywhere else; Paraglide with **542 messages in each language**, converted by script from the archive's `.ftl` — 9,756 renders compared against Fluent's, zero differences — the five drifted `route.ftl` keys resolved by giving both languages the same eight short labels; the inlang plugin pinned through `node_modules` rather than fetched from a CDN at build; the controller answers `index.html` for a path neither a file nor under one of its own prefixes, read from the document; `bun run check`, `test` and `build` in `/check`, `stop-gate.sh` (only when `web/` moved, ~7 s) and a CI job; `web/**` in `interface.md`'s `paths:`; Tailwind 4 with Tailwind's own colours removed and the twelve roles as `@theme` variables — CSS system colours until `/api/themes` answers, a test holding them to the `Colours` schema, and one refusing a hex value, a colour function or a stock palette utility in `web/src` (the stock names read from the installed Tailwind) | **measured**: `bun test` 1.4.2 hands a `.svelte` import over as its file path, not a component — Vitest kept |
| 5 | ✅ **Build the modular interface — not a port** — 2026-10-06 | the shell (navigation, command palette, shortcuts, the attention inbox, the action panel) is DERIVED from the modules under `web/src/lib/modules/`, walked, never listed; the 24 egui screens are regrouped into seven modules and "Me" (decision below), with sign-up, kiosk and the status page outside the shell; the home is pinnable, the layout a server-side preference; **`no_read_route_is_dead` is re-enabled and green** — it walks `web/src`, and `openapi-fetch` spells paths exactly as the router does, so its matcher needs no change; the advertised-command test WALKS `web/src` instead of naming files; `/api/export/{what}` gets its client — blocked under egui because the native window authenticated with a bearer token no download carries, a plain link under cookie auth; the wording shared by the loading, empty and error states is decided once (parked by the maintainer on 2026-08-25) | a page whose data source no endpoint serves is not written — same rule as egui's phase 6 |
| 6 | ✅ **The tests the interface owes** — 2026-10-06 | `web/e2e/`, Playwright 1.63 against REAL controllers started by `cargo run` — a populated one (`--demo`) and an empty one — never stubbed answers; `bun run test:browser`, in `/check` and a CI job, ~35 s. **Staleness**: a controller killed under an open page makes the page and the shell say so while keeping the last known data, a restart clears it, and signed out the page says how to sign in. **A crawl** follows every link from the home — 85 pages populated, 38 empty — and on each refuses a thrown error, a console error, a refused request, a non-GET request, a link no page answers, an axe WCAG 2.1 AA violation and a page wider than 360 px; the Tab walk runs once per kind of page and refuses a target never reached or focused without a visible ring; its floor is every `+page.svelte`, walked. **The wall**: nothing focusable, fewer cards than `HomeWidget` has, no read of accounts, secrets, audit or invitations. The service worker check is behavioural — no `/api/`, `/auth/` or `/metrics` entry in any cache after the crawl — and holds trivially today, since there is no worker. Every check was shown to fail on an injected fault first | the axe and keyboard halves would have been dropped had they drowned in noise: they found **six** real defects, all fixed (below) |
| 7 | ✅ **Look at it, and close** — 2026-10-06 | `bun run shots` (`web/e2e/shots.ts`) photographs every screen — a route folder, its `[[tab]]` kept — in the four themes, both languages, at 1280 and 360 px, against the browser suite's two controllers: **1,216 images in ~50 s**, laid out with filters in `target/shots/index.html`; it fails on a hole (a route folder no link reached), a thrown error or a 429, never on a picture; `/shots` is back and says what to look for. Looked at: **thirteen defects** every test had passed, fixed (journal) — among them 17 elements squeezed by a zero flex-basis, now refused by `src/rows.test.ts`; two left, below | the read budget: one person spends it in one theme and language, so each combination is a different `X-Forwarded-For` behind a `--trusted-proxy` — the controller as deployed, nothing added to it |

**Decided 2026-10-05: a response field is always present, and required in the document.**
`utoipa` left every `Option` and `serde(default)` field out of `required`, so the
generated types read `domain?: string | null` for a key the server always sends — 110
fields. The document now requires every field a response reaches (`openapi::Present`);
the five `skip_serializing_if` the wire types carried (`Registered.enrolment_link`
among them) send `null` instead, and a test refuses one in any crate deriving
`ToSchema`. A schema only requests reach keeps its optional fields: there, a default
really does mean the client may leave one out. The demo's every GET is validated
against the stricter document.

**Decided 2026-10-05: phase 5 builds an interface, it does not copy one.** The move to
SvelteKit was made for this; re-drawing the 24 egui screens one for one would keep the
layout egui's limits chose. Measured first: **23 response types already carry an
`attention`** (`ok` / `notice` / `critical`) the server computed, so every domain can
already say "fine" or "look at me" — the interface is organised around that.

- **Seven modules and "Me", grouped by the question they answer**, not by endpoint:
  Applications (installed, catalog, plans), Infrastructure (nodes, topology and the
  outage simulator, drift, storage), Data (coverage, runs, restorability), Security
  (exposure, secrets, rotation), Activity (timeline, audit, tasks, alerts), People
  (accounts, invitations, announcements, break-glass), Settings (appearance, exports).
  "Me" is the portal — my apps, mailbox, aliases, account — and the whole interface for
  a role with `read-self` alone. Sign-up, kiosk and the status page live outside the
  shell; the status page is at `/uptime`, since `/status` is the server's JSON.
- **A module is a folder that declares itself**: its pages, the right each needs, the
  inbox items its data yields, the widgets it offers the home, its palette commands.
  Navigation, tab bars, the inbox and `Ctrl+K` are built from those declarations, and a
  test crosses the declared pages with the route folders both ways — a page absent
  from navigation and an entry leading nowhere both fail it.
- **The home is an inbox, then widgets.** The inbox merges every item whose
  `attention` is not `ok`, from every module the person may read, critical first, each
  a link. Below it, widgets the person pins and orders. The widget names are an enum in
  `hlb-api` (`HomeWidget`): the server refuses an unknown one, the layout is stored per
  account beside the theme — the same on every device — and the interface maps the
  enum with an exhaustive `Record`, so a widget added in Rust without its component, or
  the reverse, does not compile.

**Decided 2026-10-05: the text the server builds stays English, for now.** Phase 2 turned
the rules into structures; it did not touch the sentences the server writes — an
action's `summary`, `blockers` and `warnings`, `AccountSummary.explanation`,
`RestorabilitySummary.verdict` and `remedies`, every diagnostic `finding`, the
`HealthCheck` and timeline sentences, the Bitwarden steps, every `ErrorBody.error`. A
French session shows them in English, and that is accepted: everything the INTERFACE
says is a Paraglide message, in both languages. Revisited if it reads badly in use —
the way out is the `NodeProblem` treatment, type by type (a structure the interface
words in its catalogue), and the first step then is counting them.

**Left over from phase 1, on purpose.** `0016_appearance.up.sql` still says "wasm
constant": `sqlx` checksums applied migrations, and editing one refuses to start every
existing installation. The logo is still rasterised to PNG at upload — no longer for want
of an SVG decoder, but because the logo is served unauthenticated from the controller's
origin and an SVG can carry script; serving SVG instead needs a CSP `sandbox` on that
response, and is a choice to make, not a cleanup.

**Decided 2026-10-05: Tailwind** (v4, through `@tailwindcss/vite`), on top of CSS custom
properties. Themes are runtime data — `GET /api/themes` serves every one, shipped and
declared, brand accent laid over — so the palette cannot be build-time constants: the
twelve roles are declared once in `@theme` as `--color-<role>` (`--color-ok`,
`--color-critical`, `--color-surface`…), and the shell overwrites those variables from
the chosen theme at run time. Utilities then read `bg-surface`, `text-critical`; a hex
value or a stock palette colour (`text-red-500`) in a `.svelte` file is a colour no theme
controls, and phase 4 adds the test that refuses one.

### 1. Language: the French that is frozen on purpose

Everything is English except what a rename would break SILENTLY. Rechecked on
2026-10-05, two remained; a third was named on 2026-10-26:

- **`/donnees/{name}`**, the container mount path `hlb backup` hands to restic, recorded
  inside every snapshot ever taken. Renaming it needs a restore path accepting both
  prefixes, or a decision that older snapshots are read with the old layout — otherwise
  the disagreement is discovered on the day of a restore.
- **The audit log's entries written before 2026-10-05.** Six values the code wrote were
  French (`read-soi`, `agir-sur-soi`, `gerer-accounts`, `plan-enregistrer`,
  `announcement-retrait`, the actor `anonyme`); the code writes English since, but the
  rows already there keep their words. Each entry's hash covers its actor, action and
  target, so rewriting them would make `hlb audit --verify` report tampering on every
  installation — and rehashing to hide it is what tampering looks like. Nothing matches
  on these values; people read them.
- **The `sens="rx|tx"` label of `hlb_net_bytes_total`** (`hlb-controller/src/metrics.rs`),
  stored with every sample in VictoriaMetrics. Renamed, the series splits in two: the
  home's network curves and any query by `sens` would read the old one as gone and the
  new one as starting today. Renaming it needs a recording rule or a relabel bridging
  both names over the retention window.

The wire values this section listed (`prevue`, `operationnel`, `inconnu`, `?unite=`…) and
the alert rule names (`disque-plein`…) were renamed in phase 2: the reasons given for
freezing them — persisted JSON, mutes stored by name — turned out false when checked.
The language scan (`crates/hlb-types/tests/english_only.rs`, 398 words, nothing exempt)
guards identifiers; `.claude/rules/rust.md` says why green means "the list found
nothing", not "there is nothing". Accented **test fixtures** (`"léna"`, `"Été 2026"`)
are the test, not a relic.

### 2. Storage and the OS install: run on VMs, not yet on hardware

Run on 2026-10-17 on KVM machines (QEMU inside a container, no root on the host): a
Debian 13 netinst installed from `hlb node preseed`'s file onto the disk it names by id,
the other disk untouched, then joined by `node add`; ZFS storage nodes on Debian 12 and
Alpine 3.24, through reboots; NFS from another node, written by a root container; a
cluster of Debian 12, Debian 13, Arch, openSUSE Leap 15.6 and Alpine, overlay traffic
of 300 KB across the first four. Twelve defects, each silent or blocking, fixed. Still open:

- **Real disks.** VMs prove the commands, not a SATA controller, a disk failing under
  a scrub, or a pool imported after an OS reinstall. Creating a pool and writing
  `/etc/exports` stay printed, never automated: `.claude/rules/storage.md` says why.
- **A volume's tier changed in the catalog is refused by `hlb upgrade`**: the volume
  keeps its first backing, and moving the data is by hand.
- **A service's data node, chosen once.** The first available node of its tier, by
  hostname — the storage node (`hlb.storage`) when a volume is bound on the pool. A
  label set before 2026-10-17 does not exist: an installation deployed earlier is
  pinned on its next deployment, by the same rule.
- **The images are built by `.github/workflows/images.yml`** and ran for `v0.1.0`
  (2026-10-14) and `v0.2.0` (2026-10-17) — this line said "never run yet" until
  2026-10-27. No `hlb` binary is released beside them: plan G, goal 1.
- **Unattended updates on Arch, Alpine and openSUSE** are not automated, by design for
  Arch; `node upgrade` covers them.
- **ZFS on Rocky, Arch and openSUSE** is refused at preview: none ships it, and adding
  a third-party kernel-module repository is the machine owner's call.

### 2′. Putting apps online: run on the lab, not yet under Let's Encrypt

`hlb config exposure`, the `caddy` ingress, CrowdSec, Anubis, invitations and the
interface's sign-in ran on the lab's VMs on 2026-10-17 (journal): routes reloaded with
no dropped request, certificates from Homelabus's own root and over ACME from a step-ca,
the ingress moved from one machine to another, a ban applied and lifted. On 2026-10-18:
PocketID 2.18 with its API key set at install, the private root trusted by the apps that
sign in through PocketID, CrowdSec following a move of Caddy, and each volume backed up
on the node holding it. Still open:

- **Let's Encrypt itself.** It needs a domain the house owns: the ACME path ran against
  a step-ca, and the seven DNS modules are checked by `caddy validate` on the built
  image, never against a provider. The first attempt goes through `--staging`.
- **Sign-in through PocketID in Gitea, Immich and Termix, on the lab.** Wired on
  2026-10-18 — Gitea before it starts, Immich by its config file, Termix by its
  variables — and each mechanism checked against the catalog's own image, never with a
  real sign-in: that the first person through PocketID becomes Gitea's administrator is
  Gitea's documented behaviour, not observed here. Immich's file makes its whole
  settings screen read-only: a setting changes in the manifest, then `hlb upgrade`.
- **A volume on another node needs a destination every node reaches** — S3, or a restic
  REST server (`rest:`). A destination given as a path is that machine's disk: the
  volumes of other nodes are refused there, with the reason, and an update whose prior
  backup is refused does not run. A SQLite snapshot of another node's volume is still
  taken on that node only (`hlb backup run` there).
- **A SQLite database restored with its volume** is put back from the consistent
  snapshot the same pass took of it — for snapshots taken since 2026-10-19; an older
  one stays as restic copied it, live.
- **Sending** the invitation is left to the person who creates it, by decision.

### 3. Mail: verified against a real Stalwart, not yet against real mail

`hlb-mail` ran against Stalwart 0.16.26 on 2026-10-14 — domain, account, aliases, blob,
Sieve — and three of those failed until fixed. `hlb install stalwart`
deploys it configured: SMTP, SMTPS, IMAPS and ManageSieve on the node, its administrator
from the vault, and submission on 587 (opened by Homelabus since phase 1 of the catalog
plan). What is left — a name, the DNS records, DKIM, a relay, certificates for people's
clients — is plan 0‴ above. **MariaDB dumps** now run against a real server
(`tests/maria_roundtrip.rs`): every one had failed until then.

### 4. The rest, in decreasing order of interest

- **`hlb replication failover`** ran on a real pair on 2026-10-17: status, the
  decision, and the printed procedure — whose fencing was undone by the reconciliation
  it recommended, and whose apps never reached the new primary; both rewritten and run
  again. The standby itself stays a service you create by hand: nothing in the catalog
  deploys one, and the failover is still printed, never executed — fencing happens on
  a machine the command cannot reach. The procedure is PRINTED rather
  than executed — fencing the old primary happens on a machine the command cannot reach,
  and a half-automated failover does the easy part while leaving the dangerous one to
  someone who now believes it is handled.
- IMAP ACLs (which Stalwart implements) would allow seeing several mailboxes under ONE
  connection instead of configuring three.
- **The catalog**: 11 apps and 13 platform services today.

### Ruled out, and not coming back

- **Gitea's team map** (ruled out 2026-10-19): it maps a group onto organisations and
  teams that must exist, and making them needs a Gitea administrator's token Homelabus
  does not hold — the first person through PocketID is the administrator. A household's
  organisations are its own structure; the roles already say who enters and who
  administers.
- **The reconciliation recreating a deleted service** (ruled out 2026-10-19): it did
  once, with no volume, and reported a gap corrected. Doing it whole from the loop
  would resurrect a service someone removed on purpose — the over-correction the
  invariants refuse. The drift is reported; `hlb install <app> --apply` redeploys it.
- **`/donnees` renamed** (kept frozen 2026-10-19): it is in every snapshot ever taken,
  and since 2026-10-19 in every SQLite snapshot's path too. A rename gains a word and
  splits the history a restore reads.

- **Storage speed classes** (ruled out 2026-10-18): the "speed" asked for was Seafile's
  own tuning (plan 0″, phase 6), not SSD/HDD tiers.
- **A second file app beside Seafile** (ruled out 2026-10-18), and **forced expiry or
  password on Seafile's share links** — decided by the maintainer.
- **Confirming Vaultwarden members automatically** (ruled out 2026-10-18): it needs an
  owner whose master password Homelabus holds, and the controller would then read the
  organisation it is meant to rescue.

- **Configuring Caddy through its admin API** (ruled out 2026-10-17): it has no
  authentication, and listening where `hlb` could reach it, it listens where every app
  on the overlay can — any of them could reroute the others' traffic. The Caddyfile is
  delivered as a file; the admin API listens inside the container, for the probe.

- **Stretching the Swarm, or Garage, to a VPS** (ruled out 2026-10-27): two sites
  cannot keep Raft's quorum through losing the bigger one, so the VPS would be headless
  exactly when the house is down; a manager reads every secret, and the VPS is not
  trusted; Garage turns read-only with a node missing. One control plane per site.
- **Promoting the VPS automatically** (ruled out 2026-10-27): with two sites nothing
  tells "the house fell" from "the link broke", and an automatic promotion leaves two
  copies writing apart — the reason the PostgreSQL failover is printed, not executed.
- **An immutable OS** (Flatcar, bootc; ruled out 2026-10-27): the best answer to
  updating without breaking, but a migration off Debian redoing the preseed, ZFS and
  the partitioning. The nodes stay on Debian.
- **Grants** (NLnet; declined 2026-10-27).
- **mailcow** and the `compose` runtime. Stalwart replaces it entirely.
- **`docker-compose.yml` import**: ruled out from the start, greenfield context.
