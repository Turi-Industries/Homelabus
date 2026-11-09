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
| 3. never stolen — **widened**: trust no provider (registrar, DNS host, VPS, storage), encrypt everything | CI actions pinned by commit (0 unpinned), images by digest (enforced), one `cargo audit` exception; no release is signed. **No real node's disk is encrypted yet** (`node preseed --encrypt` installs one LUKS under a one-time passphrase that `node bind-disk` replaces with the TPM AND a Tang, measured on the lab; `hlb storage encrypt` puts a storage node's datasets under a key of its own, unlocked before Docker, measured on the lab 2026-10-30); the vault's key is sealed to the machine's TPM by `hlb secrets-seal` (2026-10-28), a `0600` file until then; no catalog variable carries a secret through the environment — `catalog validate` refuses one (2026-10-28); no DNSSEC, nothing watches the registrar. Backups are already encrypted before they leave |
| 4. no Rust | **0 of 12** apps went in without Rust in the same commit; of the last 12 commits completing an app, 8 touched Rust. No production code branches on an app's name |
| 5. always available — the vital apps reachable while the house is down, or moving | no notion of a site, of an app's criticality, of a relay: the way in is a port forward on the house's router. Every service runs `replicas: 1` |
| 6. always up to date without breaking — OS, CVEs, apps | `hlb-updater` chains registry watch, channel, maturity, window, backup, deploy, health check and rollback — and **the controller never calls it**: nothing updates without `hlb update apply`. CVEs are looked at by Grype (a Swarm job, since 2026-11-08) at update time only |
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

#### Decided by the owner, 2026-10-29

- **A node's LUKS recovery key is made when its disk is about to be encrypted**, by
  that verb's preview, which refuses until the kit printed carries it.
- **A TPM that answers and seals nothing is a refusal**, never the host key alone in
  silence; `--host-only` seals without it, said by the preview.
- **An existing node is encrypted by a drained reinstall**, never re-encrypted in
  place; it lands on Debian 13 in the same pass, and a node holding data has it
  restored from its backup or moved first.
- **No real node is encrypted before it can restart alone**: the preseed's encryption
  reached the CLI (`--encrypt`) with step 4's TPM and Tang binding, not before.
- **Until the VPS, the Tangs live on the house's other nodes**: encryption from two
  nodes, a one-node house refused until the VPS's Tang. After a whole-house power cut
  the recovery key is typed on ONE node and the others open in cascade, as each Tang
  comes back.
- **The recovery key is typed over SSH into the initrd** (`dropbear-initramfs`, the
  house's network only), so a node without a screen can be opened; the console works
  too. Its host key lies in clear on `/boot`, which the preview says.

#### Decided by the owner, 2026-10-31

- **Phase 2 is closed**, its leftovers kept under each item; phase 3 is next.
- **The family's sealed kit is mailed to each relative every time it is sealed
  again**, so each holds the latest in a mailbox of their own, the house up or not.
- **No third-party DNS service** for the signed zone: the secondaries are the house's
  own machines. The registry and the registrar stay — no domain exists without them,
  which is what the drift check and the registry lock are for. **The house serves the
  zone and the VPS keeps a copy**, built with phase 4: the house down, the VPS answers
  alone; its host cannot forge the zone (DNSSEC, the key never leaves the house), only
  stop it. A machine at a relative's, a third site, may join later.
- **Every TLD alike**: the owner's domain is a `.eu`, which has no RDAP — a feature
  that works only where RDAP exists does not count as done.
- **Phase 3's proving ground: calendars and contacts from Stalwart** (CalDAV/CardDAV,
  a capability and a phone guide). Mealie, in since 2026-10-30, stays; no other app of
  the list proposed while planning is added.
- **`homelabus-catalog` lives on GitHub, under Turi-Industries**, beside Homelabus: its
  pull requests and CI are what the gate needs, and the signed index leaves the host
  able to withhold it, never to forge, replay or freeze it.
- **The official index is signed by the owner's key, outside CI**: CI builds and tests
  the index, the owner signs it after each merge with a key only they hold, on the kit;
  neither GitHub nor Sigstore can publish an app.

#### Decided by the owner, 2026-11-01

- **Two apps keep Rust of their own through phase 3: Vaultwarden and Termix** —
  measured under gap 4, no declared step replaces either crate. Of the other eleven
  apps, none is named by production code (only `demo.rs` and tests). **On one
  condition: each stays replaceable by an alternative.** So the variant names a
  protocol, never an app, and nothing finds the app by its name: the emergency vault
  looks for `members: bitwarden-directory` (`hlb_engine::emergency`), which Bitwarden's
  own server speaks as Vaultwarden does — swapping one for the other is a manifest.
  An alternative speaking another protocol (another password manager, another web SSH
  console than `nodes: termix`) enters as a new variant, and the emergency vault's
  dependence on the Bitwarden protocol is said where it is offered.
- **Jellyfin signs in through PocketID, by MaxRink's SSO plugin** (owner, 2026-11-01,
  over Jellyfin keeping accounts of its own). Jellyfin will not take OIDC into its
  core (jellyfin/jellyfin#17271 closed 2026-10-02, "not ready"); 9p4's plugin was
  archived 2026-05-12. Of its forks, MaxRink's: K0lin's still starts an account link
  unauthenticated and has no way to refuse adopting a same-named account — a PocketID
  person called `admin` would take Jellyfin's administrator. TVs sign in by Quick
  Connect, approved from a signed-in browser or phone. **Measured** on 12.4 against
  PocketID 2.19.1, plugin 6.1.0.0: the plugin makes the account at a first sign-in;
  a person taken out of the group cannot sign in again, 🔴 but their TV's and phone's
  tokens keep working until the account is disabled (then 401 at once); the plugin
  never enables a disabled account again; a disabled account's SSO sign-in answers
  200 with a token Jellyfin refuses; the admin flag follows the role claim at each
  sign-in only. 🔴 `POST /sso/OID/Add` REPLACES the provider, its `CanonicalLinks`
  (PocketID id → Jellyfin account) with it: written again, everyone is refused (409)
  — configured once, or read-modify-written. 🔴 `POST /Users/{id}/Policy` resets
  every field it is not sent. `OidSecretFile` is in the fork's code, not in 6.1.0.0.
  The plugin loads from `/config/plugins/<any dir>/`, its settings kept apart in
  `plugins/configurations/`. Four parts, in order: (1) Jellyfin 12.4 ✅; (2)
  `spec.downloads`, a file fetched by URL and sha256 into a volume before the app
  starts, by a job on its data's node, the service restarted when it changes ✅
  2026-11-01 — `hlb_engine::download`, the job's script run in the pinned
  `docker:cli` image against the real release (fetched, a second run fetching
  nothing, a wrong hash refused with the old version left, a user's volume keeping its
  owner); its Swarm placement is the lab's to prove, with part 4; (3) an
  `api` guide step signing in with a recovery login, its token in its calls' headers,
  to set the provider once ✅ 2026-11-01 — `signIn` names a `recovery` entry, made by
  its proof before the probe, the vault read by the engine only for such a step; its
  string at the proof's `pointer` is `{{ token }}` in `headers` and nowhere else
  (`validate_guide`); a capability read by a guide's call counts as read
  (`validate_with_guide`). Jellyfin declares `sso: native`, both callbacks the plugin
  answers on (`/sso/OID/redirect/`, `/sso/OID/r/`), `hlb_jellyfin` by level and
  `AdminRoles: [admin]`; the plugin always asks `openid profile`, which carries the
  claim. Then (owner,
  2026-11-01) `EnforceSsoOnly`, `admin` exempt: a linked account's password stops
  working, so whoever leaves PocketID cannot come back by an old one. A setting of the
  plugin's one configuration document, which holds the provider and the links too: an
  `api` call's `merge` writes it over a GET (RFC 7386). Quick Connect checks no
  password (`AuthenticateDirect`): a TV approved by a person signed in through
  PocketID gets its own token under `EnforceSsoOnly` (the lab); (4)
  each linked account disabled while its person holds no role let in, enabled again
  once they do ✅ 2026-11-01 — `access.accounts` (`type: http`), run by the role sync:
  the plugin's `CanonicalLinks` walked, each account's policy read and sent back WHOLE
  with `IsDisabled` set; an account linked to nobody (`admin`) never read. 🔴 It signs
  in every hour and at every role change, so a refused recovery password is recorded
  as the nightly proof records it (`recovery:<secret>` broken) and never tried again
  by either before `hlb assert` — five refusals and Jellyfin disables its
  administrator. **The lab, 2026-11-01** (10.11.11 volume → 12.4, plugin 6.1.0.0,
  PocketID v2): the download job ran on Jellyfin's data node; the guide wrote the
  provider and `EnforceSsoOnly`; a person signed in through PocketID, their account
  made and linked (`CanonicalLinks` an object, PocketID id → id without dashes); a
  role taken away disabled it, its policy otherwise untouched, and both the browser's
  and a Quick Connect TV's tokens answered 401 at once. 🔴 Disabling DELETES the
  account's devices: enabled again, the person signs in anew and each TV redoes its
  Quick Connect.
- **Calendars and contacts: one password per device**, made by the person in Me,
  opening mail, calendars and contacts, each revoked alone. **No `calendar` capability
  yet**: no app of the catalog consumes CalDAV, and a declaration nobody reads is worse
  than none — it comes with the first app that does.

#### Decided by the owner, 2026-11-02

- **Phase 3's order**: the guide frozen at install, then the `hlb` range per app, then
  sources and a signed index, then the split into `homelabus-catalog` — creating that
  repository is asked for before it is done.
- **The index is signed by `hlb catalog sign`**: Ed25519, the private key a file
  encrypted under a passphrase, on the owner's machine. The command refuses an index
  whose counter does not rise above the published one or whose expiry is not ahead —
  over `minisign`, which signs whatever bytes it is given, and a FIDO key, whose
  verification nothing in the workspace offers yet.
- **An index is valid 30 days**: the owner signs at least monthly, merge or not, and a
  mirror can hide a fix for a month at most.
- **An expired index blocks what is new, never what runs**: installed apps keep running
  and redeploy from their frozen manifest; an install or an update from that source is
  refused, naming the expiry and the command that fetches a fresh index.
- **One `foo` installed at a time**: `community/foo` installs as `foo` — service,
  volumes and databases keep the bare name — and is refused at preview while `foo` from
  another source is installed, and the other way round. They never sit side by side.
- **The rest of phase 3, decided the same afternoon**: `Turi-Industries/homelabus-catalog`
  is created **public** — pull requests from anyone are the gate. The official index is
  served by **GitHub Pages** from it: CI builds it on merge, the owner signs it on their
  own machine, a script publishes the signed result. **Revocation lives inside the
  signed index** — a `revoked` list, so it needs no second key and a mirror cannot hide
  it past the index's 30 days. **Quality levels run on GitHub's hosted runners**, a
  single-node Swarm each — no runner of the owner's exposed to a stranger's pull request.
- **The catalog's CI gets `hlb` from a mirror** (2026-11-02): Homelabus and its releases
  are private, and a fork's pull request gets no token. `scripts/mirror-hlb.sh` in the
  catalog copies a release, verified by its own `install.sh`, into the catalog's
  releases; CI pins `install.sh` by the sum written in `hlb.env`, which checks the
  binary's signature by Homelabus's release workflow.

#### Decided by the owner, 2026-11-08

- **Phase 5 before phase 4**: it needs no hardware, phase 4 a VPS and a router. Proven
  on the lab; SMART, firmware and the UPS again on real hardware when there is some.
- **Syft and Grype for the CVEs**, run as images pinned by digest in a job: Grype's
  database carries KEV and EPSS, so no feed of our own to fetch and trust. Trivy goes —
  it knows neither, and its own release chain was compromised in March 2026.
- **No UPS yet**: the ordered shutdown is built and proven against NUT's `dummy-ups`.
- **One pull request per step, merged by Claude** once CI is green.
- **A reboot that stops apps is each house's choice**, off by default: the only node, a
  manager the others are no majority without, one keeping data — the lab's deb1 — waits
  for a person unless the house accepts that downtime in its window (`hlb config reboots
  --accept-downtime`). "Ça dépend des personnes, chacun choisit."

#### Decided by the owner, 2026-11-09

- **Phase 4 starts with the VPS, a VM of the lab**: 4 GB on the lab's `hlb-internet`
  network plays the rented server, for building and for the gate — the house can be cut
  at will there. A rented VPS comes after the gate.
- **The VPS before the router**: site, front door, lifeboat, promote and return, Gatus,
  downtime, then the gate; the signed zone's Knot and OPNsense after it, in the same
  phase.
- **One pull request per step, merged by Claude** once CI is green, as in phase 5.
- **Promoting the lifeboat** (step 4): the site's own Caddy asks for its certificates
  over HTTP-01 at promotion, for the lifeboat's names only — no key waits on the VPS
  beforehand, none leaves the house. The promotion is a script the nightly lifeboat
  leaves on the VPS, run there by SSH when the house is down; `hlb site promote` runs
  the same script from the house when it answers. A private app (Vaultwarden) is open
  to the internet while the site is promoted, behind its own second factor and the
  rate limits, said by the promotion, closed by the return. What was written on the
  VPS comes home whole — its database and volumes replacing the house's — for an app
  whose manifest declares it (`lifeboat: returns: whole`); a vital app declaring
  nothing is refused by the lifeboat.
- **Nothing of a third party watches the house** (2026-11-09): no hosted service —
  not healthchecks.io, ntfy.sh, an outside SMTP, Telegram or Discord. Healthchecks is
  self-hosted on the VPS beside Gatus; the alerts leave the VPS by a webhook to a
  destination the owner holds.
- **Step 5's shape** (2026-11-09): the alerts go to an ntfy of the VPS's own, which the
  owner's Android phone subscribes to — never ntfy.sh, which an iPhone would need to be
  woken through. The status page is public, on a name the VPS serves with a
  certificate of its own: the VPS's name, no house app's. Healthchecks' interface is
  reached by an SSH tunnel only, never published. Three pull requests: 5a Gatus, the
  probes and the alerts; 5b the heartbeats; 5c the announcement on acknowledgement.

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
✅ Passed at level B, 2026-10-29, by the verbs alone on a fresh VM (enc2, Debian 13.7):
`node preseed --encrypt` rendered the file, the netinst installed from it unattended in
208 s, `node add` joined it, `node bind-disk` bound it to its TPM AND deb1's or deb2's
Tang and took the install passphrase out of the disk and of the vault — the one in the
preseed file opens nothing since. Then: rebooted at home, it opens alone; both Tangs out
of reach, two minutes later nothing is mounted and only the initrd's SSH answers, and
it opens 16 s after ONE Tang comes back; its disk on another TPM with both Tangs up
stays closed, and the kit's key typed over `ssh -p 2222` (the fingerprint the verb
printed) opens it.
✅ Passed at level A the same night, by the verbs alone on a UEFI VM (enc3, Debian
13.7, OVMF with Secure Boot enforced, swtpm): `node bind-disk` at B, then `node
verify-boot` four times — the node's key handed to shim and enrolled in MokManager with
the one-time password it printed, the UKI installed and booted once (opened by the kit's
key over `ssh -p 2222`), then the disk sealed to it and the UKI put first. Rebooted, it
opens alone in 38 s; after `update-initramfs -u` the hook reseals and it opens alone in
35 s; both Tangs stopped it waits, and opens 18 s after one comes back; GRUB chosen in
the firmware's boot manager, both Tangs up, it waits — two minutes, nothing mounted —
and the kit's key opens it; `bind-disk` run again at A, from that GRUB boot, reseals to
three Tangs, and the third alone opens it.
✅ Closed by the owner 2026-10-31. Left, each under its item below: ~~the domain's screen~~ (✅ 2026-11-01),
~~WHOIS for the TLDs without RDAP~~ (✅ 2026-11-01, `.eu` shows no lock), DANE/TLSA, the hidden
Knot primary with secondaries of the house's own, ~~the sealed kit mailed at each seal~~
(✅ 2026-11-01), ~~the nodes screen showing each level~~ (✅ 2026-11-01), ~~the SLSA provenance of three images~~ (✅ 2026-11-01), ~~`validationmethods`~~ (✅ 2026-11-01),
and what needs real hardware or a public domain to be measured.
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
  Left: sealing by default at `cluster init`, once the installer prints the kit.
- ✅ Swarm's unlock key sealed — 2026-10-29: `hlb cluster autolock` puts the key in
  the vault and on the emergency kit (its fingerprint covers it only when there is
  one, so a kit printed without autolock stays current), then, run again once the kit
  is printed, seals it to the manager it runs on; `hlb-swarm-unlock.service` hands it
  to `docker swarm unlock` after every start of Docker and keeps it in memory for that
  one command. Every manager is sealed in one run — this one directly, the others over
  the SSH address the mesh recorded, with the cluster's key —, each refused when the
  vault's key is not its Swarm's live one, one out of reach leaving the others to seal.
  Proven on the lab (deb1, TPM, PCR 7): Docker restarted, killed and the machine
  rebooted — each time locked, then active within two seconds, the controller back on
  its own; the unit disabled, the Swarm stayed locked and the kit's key opened it. deb2
  promoted, sealed over SSH with its host key alone, and BOTH managers rebooted at once:
  each unlocked itself, quorum back, controller, PostgreSQL and Caddy 1/1. `node add
  --role manager` into a locked cluster seals the key right after the join, and is
  refused at preview when it could not (the kit stale, the key not in the vault): a
  manager joined unsealed runs until its first restart, then stays locked. A worker
  still holding the key — demoted by `docker node demote`, which tells nobody — has it
  removed by the same `cluster autolock`. Proven on the lab: a bare VM added as a
  manager, sealed, rebooted and back alone; demoted, its copy found and removed.
- **Each machine its protection level — detected, never declared** (owner's request,
  2026-10-28: every kind of machine will be met, and the best protected should carry
  what matters). What can be reached depends on the firmware, the TPM and the systemd
  version, not on the distribution's name. Measured the same day: Debian 12 (systemd
  252) has no `ukify` — not even in backports, which stop at 254 — and its cryptsetup
  knows no `tpm2-measure-pcr`; Debian 13 (257) has both, a signed `systemd-boot` and
  `pcrlock`; Clevis, Tang and `dropbear-initramfs` are in both; `sbctl` in neither;
  DKMS (3.0.10, 3.2.2) signs modules with a MOK key of its own, which a person enrols
  once at the console. Then, `hlb` detected none of this; a manager is still chosen by
  count alone.
  - ✅ **Detection** — 2026-10-29 (`hlb_bootstrap::protection`): UEFI
    (`/sys/firmware/efi`), the TPM (`has-tpm2`'s `+driver`, then the sealed round trip
    `hlb secrets-seal` already ran — a TPM can answer every probe and still not seal;
    run as anyone but root it is "not tried", never "absent"), Secure Boot (the
    `SecureBoot` variable itself, which `mokutil` reads — no package needed),
    `systemd-detect-virt`, the systemd version, the DKMS modules (warned under Secure
    Boot), and whether the root sits on a `crypt` device. Not the tools: systemd 257
    carries everything A needs, and a tool not installed yet is the step's to install.
    A signal not read counts as absent — a machine that cannot say it is not virtual is
    D. Shown by `node check`, `cluster init` and `node add` (both label the node
    `hlb.protection`), `hlb node protection <node>` reads it again over the mesh's SSH
    address and relabels it, and `cluster status` has a column, a node never read
    named under it. The level is a ceiling, said as "can reach": the line under it
    says whether the root is encrypted. Proven on the lab: deb1 (SeaBIOS, a TPM that
    seals, systemd 252) and deb2 (no TPM, DKMS `zfs`) both D, kvm, roots not
    encrypted — the same as the signals read by hand. Not read by the agent: the trial
    seals as root on the host, which the agent's container is not; the label is what
    the controller reads. ✅ The interface's nodes screen — 2026-11-01: each machine's
    card says the level it can reach (or "never read"), its page says what that level
    gives up when stolen, that it is a ceiling, and the `hlb node protection` line that
    reads it again (`NodeSummary.protection`, from the label, by hostname); on the lab
    deb1 and deb2 read D, as their labels say. Left: a VM naming a node of the
    house as its host (the lower of the two — the VM's own signals are read and not
    shown yet). ✅ `tpm2-tools` installed at provisioning where `+driver` says a TPM
    2.0 is there, and the level read again after it — without them Debian's TPM read
    C (2026-10-29). A TPM that answers and seals nothing is refused by `secrets-seal`
    and `cluster autolock`, never quietly the host key alone: `--host-only` says so.
  - **Four levels**, each one sentence and never above what was detected:
    **A — verified boot, disk bound to the network**: UEFI, Secure Boot, TPM 2.0,
    systemd ≥ 257 — a UKI signed by the node's own MOK, rebuilt after every initrd;
    Clevis bound to PCR 7 and the PCR 11 predicted for that UKI, AND a Tang, resealed
    before the next boot; PCR 11 extended on leaving the initrd and `panic=10`, so a
    root swapped in after it (the class of CVE-2026-32606) unseals nothing. **B — disk bound to the network, boot not
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
    ✅ Measured 2026-10-29 on enc3 (Debian 13.7, systemd 257, OVMF with Secure Boot
    enforced, swtpm): shim, then a UKI signed by a MOK enrolled in MokManager, named
    `grubx64.efi` in its own ESP directory — shim ignored a second stage given as a load
    option and started GRUB. The base: `systemd-measure` predicts the booted PCR 11
    exactly, replayed from the event log — but initramfs-tools runs no systemd and
    extends no phase, so its initrd sees the value of NO phase, and the booted system
    adds `sysinit` and `ready`. 🔴 PCR 7 records which certificate verified the second
    stage: `75677d…` booted by GRUB, `f7095b…` by the UKI — a policy enrolled from a GRUB
    boot refused the UKI ("Operation not permitted"). Moving a node from B to A costs one
    boot opened by the kit's key, unless PCR 7 is predicted.
    **(a)** Clevis, PCR 7 read and PCR 11 predicted, nested with a Tang as B: binds in
    8 s; opens alone, reachable 16–21 s after the reboot; a UKI changed and not resealed
    stays closed with the Tang answering, GRUB too. 🔴 The reseal cannot go through the
    binding it replaces — the booted system's PCR 11 is past the initrd's — nor through
    the volume key, a `logon` key in the kernel's keyring root cannot read: it needs a
    third slot, a keyfile on the encrypted root. Every initrd rebuild (any package's
    trigger), kernel or command line reseals before the next reboot, or that reboot waits
    for the kit's key over `ssh -p 2222`.
    **(b)** `systemd-cryptenroll`, PCR 7 and the signed PCR 11 policy and a PIN: needs
    systemd in the initrd — dracut (initramfs-tools' `cryptroot` hook copies no token
    plugin), which replaces initramfs-tools and with it `dropbear-initramfs`: no SSH at
    boot. A PIN at every boot, on the console; a wrong one refused (swtpm locks after 3,
    for 1000 s), reachable 15 s after the right one. No reboot without a person: goal 5's
    patch applied with nobody there is out.
    **(c)** The same policy without a PIN, and Tang one level up: the disk opens alone in
    0.4 s in the initrd (16 s to SSH), the volume measured into PCR 15; a new initrd and
    command line signed by the same key open with NO reseal; GRUB, a MOK-signed UKI whose
    policy another key signed, and the booted system itself (`--token-only`: the
    signature covers `enter-initrd` only) do not. A key encrypted to the TPM (PCR 7 and
    15, stable across boots) AND a Tang, opened by a unit restarted every 5 s: the Tang
    down, the disk opened and the key did not, 7 tries in 45 s; the Tang back, it opened
    5 s later. A machine stolen whole runs decrypted to a login prompt, its apps never
    started — what it gives up is the running system's surface (step 7) and its memory.
    No SSH at boot either, needed only after a PCR 7 change or a broken UKI.
    **Decided 2026-10-29: (a).** It alone meets the gate as written — a machine taken
    away boots to nothing readable —, keeps initramfs-tools and the SSH at boot, and
    its failure is loud: a missed reseal waits for the kit's key, it opens nothing more.
    Its costs are Homelabus's to carry: the reseal hook on every initrd, kernel and
    command line, and the keyfile slot, known to `bind-disk` beside the binding and the
    recovery key. 🔴 And two holes initramfs-tools leaves, the class of CVE-2026-32606 (a
    root swapped in by whoever holds the machine, run while the PCRs still read the
    initrd's): nothing extends PCR 11 on leaving the initrd, and its `panic` drops to a
    root shell AFTER the disk is open — a signed command line forbids `break=`, not that.
    Both closed and measured on enc3 the same night: an `init-bottom` script extends PCR
    11 with `leave-initrd` (digests written in — the initrd has no `sha384sum`, and the
    first try failed on it) or panics, and `panic=10` on the UKI's command line makes a
    panic reboot. Booted, PCR 11 is exactly `leave-initrd:sysinit:ready`'s prediction and
    the system can no longer unseal its own binding, Tang answering; the barrier failing,
    the disk open, it rebooted — under GRUB's command line, the same failure gave
    `(initramfs)`. The reseal reads PCR 7 only from a UKI boot (`StubInfo` set): from
    GRUB's it would bind the value the UKI never sees.
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
    ✅ The manager's role, 2026-10-30 (`protection::advise_role`, `manager_warning`):
    `node add` reads the managers' `hlb.protection` labels; a C or D machine is never
    proposed, and where the count asks for a third manager on one, no role is derived
    and both costs are said; a manager below the best manager's level, or a weak one
    imposed, is warned. Left: `cluster init` cannot compare (no other machine yet),
    `cluster join-command` sees no machine; `cluster status` says a manager a better
    node could replace (`weak_managers`); `hlb controller move` and the vital apps' constraint wait
    for phase 3's criticality. Not run on the lab.
  - **Debian 12 caps a node at B; nodes move to Debian 13** (decided 2026-10-28). The
    preseed and the lab install Debian 12 alone today (`vm.sh`'s only Debian image):
    the preseed, Docker's and ZFS's sources for trixie, the lab's image, and an
    in-place `bookworm → trixie` upgrade drained one node at a time. A node still on
    Debian 12 reaches B and says why.
  - **The order, each step proven on the lab** — QEMU with OVMF (Debian's `ovmf`
    carries variables with Microsoft's keys enrolled) and swtpm, so Secure Boot, the
    TPM and the PCRs are real; `vm.sh` boots SeaBIOS today:
    1. ✅ Detection and the level shown, nothing changed; a scorecard row: nodes per
       level (2026-10-29).
    2. Each node's LUKS recovery key generated and on the emergency kit — its
       fingerprint covering it — BEFORE any disk is touched: no step below runs while
       the kit is not current, as `secrets-seal` already refuses. Generated by the
       preview of the verb that encrypts a node's disk, never earlier (decided
       2026-10-29): no key for a node never encrypted, and the kit goes stale only
       when one is — a key made at `node add` would stale it at every node, and a
       stale kit refuses the next manager of a locked cluster. ✅ The kit's side,
       2026-10-29: `kit::recovery_key` makes a node's key once (systemd's modhex form,
       256 bits) into `luks-recovery-<node>`, the sheet prints each under its node,
       and the fingerprint covers them only once one exists — every kit printed before
       stays current. Its caller is step 4's verb, which replaces the install
       passphrase with it.
    3. LUKS at install (the preseed partitions `crypto`); an existing node is drained
       and reinstalled (decided 2026-10-29). Measured on the lab, Debian 13.7: the
       netinst with `crypto` asks nothing and installs in 200 s — `/boot` apart in
       clear, LUKS2 argon2id, LVM, swap encrypted — erasing the disk first at no
       visible cost on 20 GB (a sequential write of the disk: it is on), and the
       installed system keeps no copy of the passphrase, `/var/log/installer`
       included. Re-encrypting in place works (`cryptsetup reencrypt --encrypt`, 48 s
       for 30 GB, file system intact) but cannot boot: the nodes have no `/boot` apart,
       and Debian 13's GRUB opens neither argon2 nor a TPM — swap turned into `/boot`
       and a chroot repair from a rescue system, which `hlb` cannot drive. ✅
       2026-10-29: `preseed::PreseedConfig::install_passphrase` renders it — a
       one-time passphrase, never the recovery key, since the preseed is left on a
       USB stick or a web server. ⚠️ **Debian 13's initramfs ignores `tpm2-device`**
       ("ignoring unknown option", measured): an encrypted node asks at its console
       at every boot until step 4, so the CLI flag waited for it (decided
       2026-10-29; `hlb node preseed --encrypt` since, its passphrase in the vault as
       `luks-install-<node>`, the same on a second render). Step 4's verb takes the install passphrase out: it enrols the
       recovery key (`kit::recovery_key`, refused until the kit is current) and the
       binding, then wipes the install slot.
    4. B: Clevis, the TPM AND one Tang of two — nested, `sss` `t=2` over the TPM and an
       inner `sss` `t=1` over the Tangs. ⚠️ Not the flat "two shares of three" this
       plan first said: the two Tangs alone would open a disk taken out of its machine
       and plugged in at home. One Tang on another node of the house, one on the VPS
       answering the house's tunnel only, so a Tang down never stops a restart and no
       node needs a Tang that needs it back; after a theft, deleting the Tangs' keys
       makes the disk unreadable for good. Measured on the lab, enc1 (Debian 13.7,
       Clevis 20 with `clevis-initramfs`, `clevis-tpm2`; two Tangs on the lab bridge):
       Debian's own initramfs-tools does it, no dracut — the hook brings DHCP up in
       the initrd and the disk opens alone in ~5 s of kernel time. Both Tangs down: it
       waits at the prompt, and opens 14 s after ONE comes back, nobody typing — Clevis
       retries in a loop. Same disk on another TPM, both Tangs up: refused, the
       recovery key opens it. The recovery key added by `luksAddKey`, the install slot
       killed, `update-initramfs -u`, reboot: opens alone; `clevis luks regen` rebinds
       unattended in 1 s. Binding on PCR 7 only — the TPM itself is the point at B, and
       a firmware update moving PCR 0/2 would otherwise lock the node. ⚠️ **The initrd
       has plain IP, no WireGuard**: the VPS's Tang answers the public internet,
       filtered to the house's address (the VPS reads it from the tunnel's endpoint) —
       a WireGuard key in the initrd sits in clear on `/boot`, so a stolen machine
       would carry its own way in. ⚠️ **Tangs only on encrypted nodes deadlock a cold
       start**: after a power cut each waits for the other's Tang, which runs only
       once it is open. ⚠️ `clevis luks bind -y` trusts any advertisement: `hlb` makes
       the Tangs' keys, so it pins their thumbprints (`thp`). ✅ 2026-10-29: `hlb node
       bind-disk` (`hlb_bootstrap::disk`) makes the house's other nodes Tangs (port
       7500 — Debian's package starts one on 80 as it installs, Caddy's port, so the
       drop-in goes first), pins their signing keys, enrols the kit's recovery key,
       binds, rebuilds the initrd, opens the disk through the binding, then removes the
       install passphrase; refused while the kit lacks the key, on a one-node house, on
       a slot or a Clevis binding it does not know. On the lab, enc1 (Debian 13) joined
       by `node add`, bound by the verb with deb1 and deb2 as Tangs: reboots open alone
       in ~15 s, both Tangs stopped it waits, deb2's alone opens it, the kit's key opens
       it, a second `--apply` changes nothing. ⚠️ `clevis luks list` shows no `thp`: a
       binding is read from its LUKS token, which keeps each Tang's advertisement, so a
       Tang whose keys were remade at the same address is bound again — and read with
       Clevis absent. ⚠️ Once, the proof refused: `clevis luks pass` gave 135 bytes that
       opened nothing, while the disk kept opening alone at boot; after a reboot it gave
       54 that open, run after run. Not reproduced since (five boots, fifteen proofs,
       the same session's sequence replayed); the verb stopped before removing
       anything, which is why the proof comes first — and it now opens the disk through
       the binding's OWN slot (`--key-slot`), where a token decrypting to another slot's
       key passed. ✅ 2026-10-29 evening, the leftovers: `node preseed --encrypt` (the
       passphrase into the vault, forgotten once bind-disk has taken it out);
       `dropbear-initramfs` on port 2222 (`-s -j -k`), root's keys forced to
       `cryptroot-unlock` — those with a `from=` or `command=` left out — measured on
       enc1: the kit's key piped into `ssh -p 2222` opened the disk while Clevis's loop
       kept asking the stopped Tangs, a Tang up it opens alone as before, port 2222 is
       gone once booted, and the verb prints the initrd's host key fingerprint (in clear
       on `/boot`, its preview says so). Bound nodes are labelled `hlb.disk.tangs`;
       `node add` names each bound disk a new node could hold a Tang for, `mesh remove`
       each disk the departed node's Tang opened — red, exit 1, for one left with none
       (measured with a dummy peer). The lab's Caddy "internal error" was `lab.hlb.test`
       bare, a name no site has; every app's name answers.
    5. ✅ A, option (a) — 2026-10-29 (`hlb_bootstrap::boot`, `hlb node verify-boot`):
       a MOK made on the node and imported under a one-time password in letters an
       AZERTY and a QWERTY keyboard type alike; the UKI built by `ukify`, signed by
       it, named `grubx64.efi` beside a copy of shim in `EFI/hlb`; Clevis bound to
       PCR 7, read from a UKI boot, and the PCR 11 `systemd-measure` predicts, AND a
       Tang; `hlb-uki` run by an initramfs `post-update.d` hook that never fails dpkg
       but leaves a mark `verify-boot` reads; the barrier and `panic=10`. The stage is
       read from the node at each run (shim's MokList, `StubInfo`). Secure Boot keys:
       the distribution's shim and Microsoft's certificates kept — `sbctl` is not
       packaged, and a firmware whose option ROMs are signed by Microsoft does not
       start its graphics without them. 🔴 Two Clevis bindings do not fit side by side:
       each token carries its Tangs' advertisements, 2.3 KiB a Tang, in the 12 KiB of
       metadata a default LUKS2 header holds — the reseal's `clevis luks bind` beside
       the old binding failed "Error saving metadata to LUKS2 header", as `bind-disk`
       moving two Tangs at B would have. The new binding takes the old token's place in
       ONE header write (`token import --token-replace`), the old slot killed after:
       before it the old binding opens the disk, after it the new one. And three Tangs
       at most (11 139 of 12 288 bytes; four do not fit), those the binding names
       first. DKMS's modules signed by the MOK: done with step 6.
    6. ✅ What breaks an unlock, handled before it happens — 2026-10-30, measured on
       enc3 before anything was written. **PCR 7 is predicted, never read**: the
       firmware's event log replays to it exactly (OVMF), so `hlb-uki` keeps the PCR 7
       events of a UKI boot and recomputes the Secure Boot variables (PK, KEK, db, dbx)
       from efivarfs as they are NOW. fwupd offered Microsoft's 2023 `db` update on
       enc3 — the CA of 2026 — and applied it at once (no capsule): PCR 7 moved from
       226cd8… to 672be2…, which the replay predicted and the next boot read exactly;
       sealed to it, the disk opened alone in 20 s. A systemd path unit watching the
       four variables (inotify fires on efivarfs, measured on fwupd's write) reseals
       within seconds; replayed by the verbs alone — kit's key, `verify-boot --apply`,
       `fwupdmgr update`, reboot: opened alone in 18 s. `verify-boot` at A says when
       the next boot's PCR 7 is not the sealed one, when the node's `hlb-uki` predates
       this hlb (never run with a word it does not know: any other word reseals), and
       any fwupd update waiting for the reboot that is not a Secure Boot variable — a
       capsule, SBAT — whose measurements nothing predicts: the kit's key at hand. **A
       firmware that loses its keys** (PK deleted from enc3's variables, offline):
       SecureBoot 0, SetupMode 1, the boot waited for the kit's key — and, 🔴 once
       opened, it was still a UKI boot, so the `hlb-uki` of step 5 would have sealed
       the disk to a boot WITHOUT Secure Boot at the next initrd. It now refuses while
       `SecureBoot` is not 1 or `SetupMode` not 0 (the initrd hook and the path unit
       leave `reseal-failed`), and `verify-boot` names Setup Mode, not just "Secure
       Boot off". **ZFS under Secure Boot**: `zfs-dkms` signed by the key DKMS makes
       itself — "Key was rejected by service", no pool. DKMS now signs with the node's
       MOK (`framework.conf.d/hlb.conf`, from the key's stage), and the modules built
       before are built again (`dkms install --force` alone reinstalls the old
       signature — measured); the MOK, with no code-signing EKU, loads them, and ZFS
       loads at boot. Left, unmeasured: a real capsule update (OVMF has none) and a
       real board's event log — the replay is checked against the TPM at every UKI
       boot, and a log that does not replay falls back to that boot's own PCR 7, said;
       shim's copy in `EFI/hlb` is never updated, and a newer SbatLevel (written by a
       newer shim, or fwupd's SBAT update) would refuse it — copying it automatically
       may move PCR 7 (SbatLevel is measured there): measure a shim update on enc3
       first. The path unit is proven on a `db` write by fwupd and by hand in Setup
       Mode, never on a `dbx` (fwupd offers none on OVMF: same code path, unproven);
       a variable written WHILE its reseal runs may not start another (systemd's path
       semantics, unmeasured) — `verify-boot` then reports the drift.
    7. ✅ The running system — 2026-10-30, measured on enc3 (`-device intel-iommu`)
       before anything was written. **Lockdown**: Debian's Secure Boot already gives
       `integrity`, which disables hibernation (`/sys/power/disk` reads `[disabled]`)
       and unsigned kexec, so "where neither is needed" decided nothing.
       `confidentiality` adds only the kernel's memory kept from root — perf, kprobes,
       tracefs, `/proc/kcore`, BPF reading it — which nothing in `crates/` or
       `catalog/` uses; Docker runs under it, its BPF device cgroup included (`docker
       run --device`). **IOMMU**: Debian 6.12 already translates DMA by default
       (`INTEL_IOMMU_DEFAULT_ON_INTGPU_OFF`, five groups `DMA-FQ` on enc3 without any
       word), and 🔴 `/sys/class/iommu` lists `dmar0` whether it translates or not:
       the groups' type is read instead. Both go on the UKI's SIGNED command line,
       `lockdown=confidentiality intel_iommu=on`, GRUB's `lockdown=`, `intel_iommu=`,
       `amd_iommu=`, `iommu=` (`pt` is no protection) dropped; a node sealed before
       gets them at its next `verify-boot --apply`, which reseals the new PCR 11 —
       on enc3: preview says so, `--apply`, reboot opened alone in 14.5 s, lockdown
       `[confidentiality]`, Swarm active. At B or C GRUB's line is editable at the
       console, so neither is written there. `verify-boot` at A reads lockdown, the
       IOMMU groups and each Thunderbolt domain's `iommu_dma_protection`, and says
       what is missing and whether a reboot or `--apply` brings it; then what no
       software sets nor reads back — a setup password, USB and PXE boot off,
       Thunderbolt off where unused, VT-d / AMD-Vi on. Left, unmeasured: a VM has no
       Thunderbolt (the report is read-only, nothing is blacklisted unmeasured), and
       a real board's DMAR tables — some firmware ships broken ones, which this line
       would meet at the first UKI boot.
  - ✅ **What no level protects**, said in `docs/security-model.md`: a flaw exploited in
    a running service or in Homelabus; firmware implants (only Boot Guard or AMD PSB,
    set at the factory, help); a VPS's provider; a compromised hypervisor. And once
    booted the disk is open: the controller holds Docker's socket, which is root —
    splitting it into a minimal privileged daemon behind a narrow API, the interface
    unprivileged, is its own item. Backups are already encrypted before they leave.
- ✅ **The controller split** — decided 2026-10-30 (owner), stages 1-3 done the same
  day: a privileged executor. Today
  the controller holds Docker's socket, the vault's key, `/var/lib/docker/volumes`
  read-write and `DAC_OVERRIDE`: a flaw in any of its routes is root on its node and
  every secret. **Measured** the same day, route by route (92 operations, 20 loops):
  38 need nothing but reading the state, 7 read Docker (`nodes`, `tasks`), 16 write
  only web data (sessions, preferences, mutes, announcements), 9 write desired state a
  loop then applies (roles, quotas, destinations), 11 decrypt a secret per request, 17
  drive Docker, 11 call an admin client (PocketID, Stalwart, Vaultwarden, the database
  provisioners). A narrow API relaying `ServiceSpec`s would protect nothing — a spec
  binds any host path —, so the boundary is INTENTS: the web side asks "install gitea
  at this domain", "back up now", "give lena this role"; the daemon re-derives
  everything from the catalog and its own state, and refuses what it cannot derive.
  - **The state cannot stay one writable file.** Whoever writes `hlb.db` forges any
    secret (the vault is age X25519: encrypting needs only its PUBLIC key), mints a
    token or a session (unkeyed SHA-256 fingerprints), rewrites the audit chain
    (unkeyed), sets `users.role`, and edits `apps.manifest` — read back with a YAML
    parse only, then deployed, its jobs `exec`ed, by root. So the daemon alone writes
    `hlb.db`; the web side reads it. **Measured:** a container under another uid, the
    directory mounted `:ro`, reads it live while the daemon writes, and its writes are
    refused by the kernel; it can open it only while the daemon holds it open (the
    `-wal` and `-shm` files go with the last connection). The web side's own data —
    sessions, preferences, mutes, announcements — stays in it, written by intent: the
    CLI reads sessions too, and one file keeps the backup and the restore one.
  - **What it still gives an intruder in the web side**: whatever a signed-in person's
    intents can do — the web side vouches for who asks. No secret read, no host path,
    no image outside the catalog, no `exec`. Destructions now need a fresh passkey the
    daemon checks itself — a code it exchanges, not an `id_token` handed over (✅ below).
  - **Stages**, each gated: (1) the intents, in process — a crate the handlers call
    instead of the orchestrator, the vault and the admin clients, and a test refusing
    those types in the web modules; the suite unchanged. (2) Two processes — the
    daemon (socket, vault, volumes, the loops, `hlb.db`), the web service with none of
    them, a Unix socket between them whose peer is checked (`SO_PEERCRED`); gate on the
    lab: `docker inspect` of the web service shows no socket, no key, no capability, a
    shell in it reads no secret and writes nothing in `hlb.db`, every screen and
    assertion as before. (3) Intents re-derived and bounded: a local destination's
    path, the guide's automations, a passkey per destruction.
  - Found by the same reading, fixed at once (2026-10-30): a destination could name
    ANY secret of the vault as its credentials, signed with to a location the caller
    chose (`operate`); the Bitwarden assistant replaced a token of the name it was
    given — the deadman's included. Found, not fixed: the plans screen says a plan
    "replays its preview", and nothing replays it — `/api/plans` drops the body; a
    local destination's path is any host path, bound read-write by the backup pass;
    three read routes decrypt the whole emergency kit to show its fingerprint; the
    `drifts` screen reads the reconcile loop's memory, which stage 2 must persist.
  - ✅ Stage 1 — 2026-10-30: every handler asks `hlb_privd::Privd` an intent
    (`hlb_api::intent`, twenty of them, answers round-tripped through JSON);
    `AppState` holds the `Privd` and no client; the loops that hold one live in
    `hlb_privd::daemon`; `web_holds_no_capability` refuses, in every module but
    `main.rs`, each type `Privd` and `InstallContext` hold, read from their source.
    Left for stage 2: the web side still WRITES `hlb.db` (accounts, invitations,
    roles, the audit, the git mirror); the agents' poller holds the controller's mTLS
    key (read-only reports — nothing it opens acts); the `hlb-engine` helpers it calls
    read the state only (`roles::opened_by`, `pki::ending`, `access::pocketid_public`…)
    and stay; `main.rs`'s Termix, emergency-vault, upkeep, prune and PKI loops still
    run in the binary beside the web side.
  - ✅ Stage 2 — 2026-10-30: two processes, one image. `hlb-privd` — `hlb.db`
    read-write, the vault, Docker, the volumes, every loop, the agents' mTLS leaf —
    answers on `<state directory>/privd.sock`, to uid 8420 alone; `hlb-controller` is
    the web side: uid 8420, root read-only, every capability dropped, the state's
    directory mounted read-only at `/state`, nothing else. Its writes are intents
    (`intent/record.rs`); drifts, alerts and the fleet stay in the daemon's memory,
    asked by intent rather than persisted; the one secret it receives is its own sign-in
    client's (`SignInClient`). The one-process mode stays, for the demonstration and the
    browser suite's empty controller. Mounted whole, the state's directory must be its
    own: `/root` is closed to uid 8420 and holds the key, so `fleet controller` refuses
    it and says how to move it; the socket sits there, not in `/run`, a tmpfs a reboot
    empties under a bind. **Proven on the lab** (deb1): the state moved to
    `/var/lib/homelabus`, deployed; `docker inspect` of the web side shows one bind,
    read-only, `CapDrop ALL`; a shell in it has no capability (`CapEff` 0), cannot write
    `hlb.db` nor anything else, finds no key, Docker socket, volume, certificate or
    secret in its environment; every parameterless read route answers as before (36
    succeed, the five others with their expected refusal), the 20 assertions read with
    none broken, an announcement is written through the daemon and audited under the
    token's name; the agents deployed after, the daemon polls them over mTLS with the
    leaf now issued to `hlb-privd`, and the web side shows both nodes. Left for stage 3: the intents re-derived and bounded (a local destination's
    path, the guide's automations, a passkey per destruction).
  - Stage 3, 2026-10-30. **Measured**: of 58 intents, one carried a host path and a
    secret's name the daemon took on trust — `SetDestination`, which recorded any
    location (proven: `/` and `/etc`) and moved a declared destination, credentials
    and all; the others carry names the daemon looks up, data it stores, or an
    account the web side vouches for (accepted above). ✅ `SetDestinationClasses`
    now: the web side changes a declared destination's classes; its location and
    secret are `hlb backup dest add`'s, as root, and the route refuses another at
    preview. Read and found bounded already: the guide's automations come from
    the catalog the daemon reads, and the one value the web side chooses, the
    domain, is parsed by the daemon (`install::basis`) — nothing that would open a
    Caddyfile block passes. The kit's fingerprint is decrypted in the daemon since
    stage 2; the web side receives sixteen hex digits. ✅ Plans replay: `/api/plans`
    gives the body and the route, and the plans screen's "Preview again" opens the
    action panel on a new preview of the request as filed; a plan may name only a
    route with a preview, not a public one, and no segment that sends a fetch
    elsewhere — a replay of the Bitwarden assistant's route would have minted a
    token. **Proven on the lab** (deb1, `hlb-controller:lab16`): over the API a move of
    `nas` to `/etc` and a new destination at `/` are refused with the CLI named; on the
    daemon's socket as uid 8420, the old intent, a `location` slipped into the new one
    and an unknown name are refused; the destinations read as before; a plan of
    `/api/bitwarden` is refused and `/api/plans` gives the body and the route. ✅ Found
    deploying it, fixed the same day: Swarm replaced `hlb-privd` START-FIRST, so two
    daemons ran every loop at once for a while, and the old one, shutting down cleanly,
    removed the socket the new one had just bound — the web side waited on "the
    daemon's socket" for ever. `hlb fleet controller` deploys the daemon `alone()`
    (stop-first, kept when an update reads the service back), and the daemon removes
    the socket only while its inode is the one it bound. On the lab (`lab17`): the verb
    turned a start-first `hlb-privd` stop-first, and an overlap forced by hand
    (`--update-order start-first --force`) left the new daemon's socket in place and
    answering after the old one's clean shutdown.
  - ✅ **A passkey per destruction** — decided 2026-10-30 (owner): re-authenticated
    within five minutes, checked by the daemon; built 2026-10-30. A destroy-level
    intent applied (removing an app, draining or pausing a node, deleting a role,
    changing a person's role) is acted on only inside a `Confirmed` carrying the
    authorization CODE of a PocketID round trip the daemon began, with `prompt=login`
    and a `nonce` that is the SHA-256 of the intents begun; the daemon exchanges the
    code itself, with its own PKCE check and its own copy of the client's secret (as
    sign-in does: no signature to verify), and acts only if the `nonce` is the
    intents', `auth_time` is under five minutes old, and the `sub` is an account whose
    own role allows the intent — read from its state, not vouched for. Each intent
    begun is acted on once; a bulk change of roles is one passkey for the whole
    selection. The route answers 428 with PocketID's address in `x-hlb-passkey-url`;
    the panel opens it from a click of its own (a window opened after the request
    came back is one the browser may block) and sends the action again with the
    state and code `/auth/confirmed` hands back over a `BroadcastChannel` — not
    `window.opener`, which a `Cross-Origin-Opener-Policy` would sever. ⚠️ What it
    bounds is HOW OFTEN, not WHAT: an intruder in the web side destroys only while
    someone confirms, one destruction per passkey presented — but PocketID shows
    nothing of the intent, and the web side chooses what is begun, so the one
    destroyed need not be the one the person read. API tokens no longer destroy where
    PocketID signs people in; the CLI, as root, still does. Without PocketID (the
    demonstration, a fresh installation), nothing signs in by passkey and the intents
    stay as they are. **Proven on the lab** (deb1, `hlb-controller:lab18`): with a
    passkey registered by Playwright's virtual authenticator, the roles screen's
    "Delete" previewed, answered 428, opened PocketID asking for the passkey again, and
    the action sent back with the proof deleted the role — the daemon logging whose
    passkey; the raw `remove` intent applied on the socket is refused, its preview
    answered.
- ✅ ZFS native encryption — 2026-10-30: `hlb storage encrypt <node>`, from a manager,
  puts the node's dataset key in the vault and on the emergency kit (`zfs-key-<node>`,
  covered by its fingerprint; refused until the kit is printed with it), writes it to
  `/etc/hlb/zfs.key` (0400), and installs `hlb-zfs-load-key.service`: Debian masks
  ZFS's own unit, and `zfs mount -a` leaves an encrypted dataset locked over an EMPTY
  directory of its plain parent (measured on Debian 12 and 13) — a bind mount there
  writes in clear. The unit loads and mounts every dataset under the key after
  `zfs-mount`, fails unless all are mounted, and Docker and the NFS server `Require`
  it. ZFS cannot encrypt in place: each volume is copied (`send | recv`, its own
  encryption root), its file list compared, swapped in by two renames and the original
  destroyed, every app owning one stopped meanwhile — a rename passes under a
  container's bind mount, and the app would keep writing into the original. Each shape
  in between is named, so a run resumes. `storage init` creates new ones encrypted and
  refuses clear without `--unencrypted`. Proven on the lab (deb2, Debian 12, ZFS 2.1):
  27 volumes of 20 apps moved, every assertion green; rebooted, unlocked 0.5 s after
  `zfs-mount` and before NFS and Docker, everything back alone; booted with the key
  moved away, the unit fails naming the kit, Docker and NFS stay down, nothing is
  mounted; the key put back, all returns. Left: the plain blocks a copy freed stay on
  the disks until overwritten, and on a root disk in clear the key lies beside the pool
  — a data disk taken alone gives nothing, the whole machine everything; and `zfs send
  -w`, which would let a remote site keep a copy it cannot read.
- The domain, the weakest point (every domain theft of 2024-2026 went through a
  registrar's support): Knot at home signs the zone and serves it, the VPS a secondary
  of the house's own (decided 2026-10-31: no third-party DNS service; built with phase
  4) — the signing key never leaves the house; the simple level stays
  a provider driven by its API (deSEC). CAA with `accounturi` (RFC 8657), certspotter,
  and a nightly drift check of NS, DS, CAA and the WHOIS statuses. DANE/TLSA beside
  MTA-STS.
  - The drift check first: it needs no provider chosen and watches the theft itself —
    a registrar's support moving the NS. **Measured** 2026-10-30: the two DoH resolvers
    `public_dns` already asks give NS, DS and CAA in the same JSON (`type` 2, 43, 257),
    with `AD` set when the chain validated; Google writes a DS digest in capitals and
    either may reorder, so a reading is lowercased and sorted before it is compared.
    The registry's side is RDAP (IANA's `dns.json`, 592 TLDs): `.com`'s gives the six
    EPP locks, the registrar and the expiry, `.fr`'s the status and the DS it holds —
    but `.eu`, `.de`, `.io`, `.be` and `.ch` have NO RDAP, and `.eu`'s port-43 WHOIS
    shows no status at all (registrar, NS, keys), `.de`'s one word (`connect`). So the
    registry is read where RDAP exists and said "not read, no RDAP for .eu" elsewhere,
    the DNS half covering every TLD alike. Designed: the zone is found by walking up
    from the exposure's domain to the first name holding NS; the first reading is
    shown and accepted by `hlb domain accept --apply` (preview by default) as the
    baseline; each night the daemon reads again and a change of NS, DS, validation,
    CAA, registrar or locks is a critical notification keyed by what moved; a reading
    that could not be made is not a change. Said beside it, not alerted: no transfer
    lock where the statuses are known, a zone not signed, no CAA, an expiry within 30
    days. ✅ Built 2026-10-30 (`hlb_api::domain`, `hlb_engine::domain`, `hlb domain
    watch` / `accept`, the daemon's nightly pass beside the mail records). 🔴 Found on
    its first real run: `www.desec.io` is a CNAME, and the resolver's NS answer carries
    the TARGET's records — the walk took `www` for a zone. `PublicDns::query` keeps
    the records the name itself owns; `lookup`, for mail, still follows the CNAME.
    Read against the internet: `desec.io` (signed, CAA with `accounturi`, `.io` said
    not read), `google.com` (MarkMonitor, the six locks, not signed), `afnic.fr`
    (signed, `active` only: no transfer lock and no CAA, both advised); a baseline
    accepted, one name server forged in it, `watch` named the name servers and the
    delegation and exited 1. ✅ The inbox, 2026-10-31 (`hlb_controller::domain`):
    `domain_moved`, `caa_refuses_account` and `certificate_foreign` critical,
    `domain_unwatched` (no baseline, of the zone or of the logs) and `domain_unknown`
    (not read for two days, or no resolver answered) notices — judged from what the
    night recorded, by the rules `hlb domain watch` prints with; filed under security.
    ✅ The screen, 2026-11-01 (`/domain`, `GET /api/domain`): one pure judgment
    (`DomainPublic::judge`) of the reading, the baseline and the logs' watch, which the
    inbox's lines are now derived from too — the screen and the inbox cannot disagree;
    the moves, the baseline with `hlb domain accept --apply` to copy, the foreign
    certificates, the advice with a pin's records, each account's CAA verdict, both
    halves of the reading. A drift's sides are values (`Side`), worded by the
    interface. The demonstration judges a fabricated night by the same rules.
    ✅ WHOIS for the TLDs without RDAP, 2026-11-01: the host IANA's WHOIS names, asked
    on port 43 for the zone then each parent; two shapes parsed — `key: value` (ICANN's,
    `.io`; DENIC's, asked `-T dn,ace`) and EURid's and DNS Belgium's indented blocks —
    statuses spelled as RDAP spells them. **Measured**: `.eu` registrar and delegation,
    NO status — unknown now (`statuses: None`), never advised as a missing lock nor
    compared; `.de` `connect` and the delegation, no registrar; `.be` its `Flags` as
    statuses; `.ch` refuses anyone but a registrar, said not read in its own words.
    The real answers are kept (`hlb-api/tests/whois/`); `live_whois` reads them again.
    Left: the nightly pass not run on the lab, whose exposure is internal —
    nothing to watch.
  - CAA with `accounturi`. **Measured** 2026-10-30 (`hlb-caddy:dev`, Pebble 2.8.0,
    offline where no CA was to be reached): Caddy keeps its account in
    `/data/caddy/acme/<directory, ':' and '/' as '-'>/users/<email>/<local part>.json`,
    the URI its `location` (`acme-v02.api.letsencrypt.org-directory` for Let's
    Encrypt). 🔴 With an `email` and no issuer named — Homelabus's Caddyfile in
    production — Caddy tries Let's Encrypt THEN ZeroSSL for every name outside the
    wildcard (the wildcard's own `tls` has Let's Encrypt only): a CAA naming one account
    would cut the fallback silently, and ZeroSSL's account does not exist until first
    used, so it cannot be pinned. ✅ `cert_issuer acme` in the global block: one
    authority, `acme_ca` still honoured (adapted). Stalwart opens its own account for
    `mail.<domain>`: 0.16.27 and 1.0.0 both carry an `accountUri` property (read from
    the binaries; to prove through `x:AcmeProvider/get` in `live_mail`'s certificate
    test, which runs Caddy, Stalwart and Pebble together). Designed: the reading takes
    the house's accounts — Caddy's by `exec_in_service` reading that file, Stalwart's
    by JMAP — on Let's Encrypt's production only; the CAA judged is the one governing
    the exposure's names (climbing from its domain to the zone, the first set found);
    one that refuses an account is critical (renewals fail 30 days before expiry),
    none pinned is advised with the exact lines, `0 issue "letsencrypt.org;
    accounturi=<uri>"` per account, `issuewild` judged for a wildcard. ✅ Built
    2026-10-31 (`hlb_api::domain::judge`, `hlb_engine::domain::accounts`, `hlb domain
    watch`, the nightly pass: `caa:<who>`). Stalwart's `accountUri` proven on 0.16.27
    and 1.0.0 in `live_mail` beside Caddy's file, two accounts; the file's path is
    certmagic 0.25's `storageKeyUserReg`, read from its source (`Safe` keeps `/` out by
    `issuerKey`, not by itself). Judged on desec.io's real set: its account pinned, any
    other refused. ✅ `validationmethods` (RFC 8657) judged 2026-11-01: each account
    says the challenges its certificates take (`Account::validations`) — Caddy's,
    read from certmagic 0.25.3 and acmez 3.1.6, DNS-01 alone for its wildcard (a DNS
    solver disables the other two) and HTTP-01 or TLS-ALPN-01 for a published name
    beyond its reach, without a provider for every name; Stalwart's its provider's
    `challengeType`. A kind of certificate with no challenge left is refused; one of
    two is enough (acmez retries the other on the next attempt). A pin keeps the
    methods its owner restricted. Left: the accounts were not read through a real
    Swarm (the lab's exposure is internal), and no authority was asked under a
    `validationmethods` — that needs a public domain.
  - Certificate Transparency — what CAA and the drift check cannot see: a domain
    moved for an hour and moved back between two nights (DNS-01 and the CAA both the
    thief's meanwhile), or an authority ignoring the CAA. **Measured** 2026-10-31:
    Cert Spotter's API (`api.certspotter.com/v1/issuances`, `include_subdomains`)
    answers without a key, 10 requests per window (`x-ratelimit-limit`), the unexpired
    certificates oldest first, a precertificate and its certificate as ONE issuance
    (by `tbs_sha256`), paged by `after=<id>` — the `Link` says `next` even on the last
    page, whose follower is `[]`. desec.io: 10 issuances, all Let's Encrypt; afnic.fr:
    24, Let's Encrypt, Sectigo and Amazon. Its `pubkey_sha256` is the SHA-256 of the
    SPKI's DER: desec.io's served certificate matches its issuance of 2026-10-12, and
    the one of 2026-08-14 matches nothing the site still holds. Stalwart's
    `x:Certificate/get` answers each certificate's PEM, its key masked (`****`), on
    0.16.27 and 1.0.0. Designed: an issuance is the house's when its key is one the
    house holds — Caddy's certificates (`/data/caddy/certificates/**.crt`, by
    `exec_in_service`) and Stalwart's, read AFTER Cert Spotter, so one issued between
    the two is held by then. The account cannot decide it: no log says which account
    asked. Watched: the exposure's domain and its subdomains, not the zone — an
    owner's site hosted elsewhere at the apex would ring every renewal. An issuance
    with another key is critical (`ct:<id>`) when one of its names is the house's —
    one its certificates carry or an app is routed at, a wildcard matching either
    way —, said beside otherwise. Each night reads after the last id judged and
    advances; those it found foreign stay listed and alerted until `hlb domain
    accept --apply`, whose preview shows them, and which on a first reading takes
    every unexpired issuance as the baseline (the house's own previous certificate
    among them, its key gone with the renewal). A reading that could not be made —
    the API, Caddy or Stalwart not read — judges nothing and does not advance.
    ✅ Built 2026-10-31 (`hlb_api::domain::{Issuance, Transparency, judge_issuances}`,
    `hlb_engine::domain::{issuances, held, transparency}`, `hlb domain watch` /
    `accept`, the nightly pass: `ct:<id>`). The SPKI is read by `trust.rs`'s DER walker,
    held to desec.io's real certificate (RSA, Cert Spotter's own `pubkey_sha256`) and
    to a P-256 one (OpenSSL's). Proven in `live_mail` on 0.16.27 and 1.0.0: the key
    Stalwart serves on 993 is among those its ACME certificate's PEM gives over JMAP,
    and Caddy's on 443 among those `find … -exec cat` reads in its container
    (BusyBox's `find` exits 1 on a missing directory: not read, never "no key"). Read
    against the internet: `hlb domain watch` for desec.io read the logs and judged
    nothing, Caddy unreadable without a Swarm — the cursor unmoved. Left: never judged
    end to end on a real Swarm (the lab's exposure is internal); a Cert Spotter key
    for more than ten requests a window; a screen, as for the drift.
- ✅ An append-only destination (rest-server), pruned with another credential from
  another machine, never automatically: restic handles no S3 object lock, and Garage has
  none. Done 2026-10-30: the upkeep already left a destination proven out of reach
  unpruned ("its owner prunes it") and nothing helped the owner do it — every
  append-only repository only grew. `hlb backup dest prune-script <name>` prints the
  upkeep's own passes (`hlb_backup::restic::forget_passes`, which `forget` now runs
  too, so the two cannot drift) as a `sh` script holding no secret: the owner sets
  `RESTIC_REPOSITORY` to a credential that may delete and `RESTIC_PASSWORD` from the
  kit. Refused for a destination proven erasable — the upkeep prunes it. Proven against
  real rest-servers (`hlb-backup-run/tests/upkeep.rs`): the script, run as printed
  through a second server over the append-only one's files, leaves what the upkeep
  leaves on an erasable one. Found doing it: a proof's witness snapshot is restic's
  `/etc/hostname`, grouped by host and paths with anything else backed up from there —
  only the test's own snapshots were.
- Upstream images' cosign signatures checked against a pinned signer before deploying;
  Secure Boot's dbx checked (PKfail). **Measured** 2026-10-30, asking each registry for
  the `sha256-<hex>.sig` tag, the OCI referrers and ghcr.io's referrers tag, for the 50
  images pinned in the catalog and the crates: 7 carry a cosign signature
  (`curlimages/curl`, Chainguard's two MinIO images — tests only —, Meilisearch,
  Stalwart and its migrator, Vikunja), 3 more only a signed SLSA provenance
  (Vaultwarden, Bulwark, Anubis); the other 40 — PostgreSQL, MariaDB, PocketID, Garage,
  Immich, Gitea, Fluxer's twelve — nothing. Every image is already pinned by digest, so
  a signature guards only the moment a new digest is chosen, which is the update; and
  there one `HLB_COSIGN_IDENTITY` serves every image, so setting it would refuse every
  image but one signer's — it is never set, and nothing is verified. Worth doing as: a
  signer per image in the manifest, for the handful that sign.
  - ✅ The signer per image — 2026-10-30: `signedBy: { github, workflow }` on an image
    (`hlb_types::ImageSigner`), the identity derived anchored and on a tag only — cosign
    matches an expression anywhere. `hlb update apply` verifies each image that will
    start against the CATALOG's signer (a frozen manifest predates it), and with one
    declared, "no signatures found" is refused as a substitution rather than reported
    as unchecked; `HLB_COSIGN_IDENTITY` is gone from it (`update scan` keeps its flags).
    The bot's rewrite keeps the signer on the line. Declared for Vikunja, Stalwart and
    Fluxer's Meilisearch, read from each signature's certificate (all GitHub Actions,
    Sigstore bundles in the OCI referrers, no `.sig` tag) and proven with cosign 3.1.4
    (`hlb-catalog/tests/signatures.rs`, ignored: cosign and the network); a wrong
    workflow fails it. ✅ Vaultwarden, Bulwark and Anubis — 2026-11-01: each publishes
    a signed SLSA v1 provenance alone (`gh attestation verify` read its signer: a
    workflow at the release's tag), and cosign 3.1.4's `verify` takes that bundle from
    the OCI referrers as it takes a signature — `signedBy` declared, the same check,
    six of six clean and a wrong workflow refused. Left: the migrator, a constant in `stalwart_migrate.rs` no update moves;
    cosign missing on the machine still reads as "not checked", as Trivy did — Grype and
    Syft run as pinned Swarm jobs since 2026-11-08, cosign could too.
  - ✅ PKfail — 2026-10-30: the platform key's certificate is read from efivarfs
    (`od` of `PK`, readable by anyone) and a subject or issuer saying "DO NOT TRUST" or
    "DO NOT SHIP" — Binarly's markers for the test keys ~900 boards shipped — is
    warned by `node check`, `cluster init` and `node add`, the subject quoted. A
    warning, not a lower level: PCR 7 measures PK, KEK and db, so keys rewritten from
    the running system leave the TPM opening nothing; the attack is the kit's key typed
    at the prompt that follows. Proven on a fixture made like AMI's key (an
    EFI_SIGNATURE_LIST in efivarfs's layout, the subject read by its DER length — the
    next element follows at once) and on this desktop's real Gigabyte PK, which carries
    no marker. Not measured on enc3, nor on a board that has the test key.
  - Secure Boot's dbx — whether it holds today's revocations (BlackLotus, the 2023
    boot managers). **Measured** 2026-10-30 on this desktop (fwupd 2.1.9): `fwupdmgr
    get-devices --json` reads the `UEFI dbx` device (plugin `uefi_dbx`) as `20250902`,
    as any user; LVFS's metadata, fetched apart, publishes `20260402` for its GUID
    `f8ba2887…` and `20260707` for its other, `d07ff664…` (the KEK 2023's) — two
    behind. 🔴 And `fwupdmgr get-updates --json` answered `{"Devices": []}`, exit 0:
    its `lvfs` remote reads `"Mtime": -1`, metadata never downloaded, so "nothing to
    update" and "nothing known" are the same answer. Designed: a signal beside PKfail's
    in `observe.rs` — the device's version, the `lvfs` remote's `Mtime` (`get-remotes
    --json`), and `get-updates`'s releases for that device — read as not checked (no
    fwupd, no device), unknown (metadata never fetched or older than a month: `fwupdmgr
    refresh`), behind (`fwupdmgr update`) or current. A WARNING under Secure Boot, not a
    lower level, as PKfail: PCR 7 records which db entry verified each image, so a
    revoked boot manager booting does not open a level-A disk; and a dbx written is
    resealed at once (`hlb-uki-efivars.path`). ✅ Coded 2026-10-30
    (`protection::parse_dbx`, `Signals::dbx`), held to this desktop's real outputs:
    read here it says unknown, "never downloaded" — and without that check, current,
    proven by removing it. `get-updates` runs with `--no-metadata-check
    --no-remote-check --no-unreported-check`, so observing downloads nothing. Its
    releases fixture is built in its shape from the LVFS versions measured, since this
    desktop's metadata was not ours to refresh; and not measured on a Secure Boot node
    (this desktop's is off: no warning, rightly), nor on Debian 12's fwupd 1.8.
- The family without the owner: the emergency kit's key split among relatives (3 of 5),
  and a restore they rehearse once a year.
  - ✅ The split — 2026-10-30. What is split is not the kit: it changes with every
    destination and key, and five sheets to hand out again each time would be stale in
    a drawer within a year. `hlb emergency split` draws a fresh age identity, cuts its
    32 bytes by Shamir over GF(256) (`blahaj`, Distrust's fork of `sharks`, whose
    coefficients skip zero — RUSTSEC-2024-0398, never fixed there) and forgets it:
    only its PUBLIC half is kept (the vault's `kit-split`), so the kit can be sealed
    to it again after any change — `hlb emergency kit --sealed`, a file safe to email
    to every relative — without anyone's share moving; kept nowhere, the key needs no
    protection of its own. Each share is printed with its index, the
    threshold, the split's id (from the public half) and a checksum, in modhex — the
    letters an AZERTY and a QWERTY keyboard place alike, as the disk recovery keys. `hlb
    emergency combine` needs no state and no vault: it refuses a mistyped share by
    name, shares of two splits, one given twice and fewer than the threshold, and
    checks that what it rebuilt IS the split's key (its public half's id) before
    decrypting `--kit`; without `--kit` it only says the shares open the split — the
    yearly rehearsal's gesture. A new split leaves the old shares opening the sealed
    kits already handed out: there is no revoking paper, and `--replace` says so. The
    checksum is a CRC-16: every single mistyped letter and every swap of two is
    refused (tested at every position), and a share ends with the line that completes
    it, so one typed on the two lines it is printed on is one share. Held end to end
    through the binary (`hlb-cli/tests/family_split.rs`): split where the state is,
    three sheets typed back where there is none, two refused with nothing shown, the
    kit sealed again opening with the same shares. A sealed kit is counted as the kit
    (same fingerprint), from the day it is written, not the day each relative got it.
  - ✅ The rehearsal — 2026-10-30. Proved, not attested (`family-rehearsal`,
    `Proof::Rehearsal`): the sealed kit ends with a rehearsal code — 64 bits of modhex,
    kept in the vault so a kit sealed again carries the same one — that only its opened
    text shows. The owner types it back (`hlb emergency rehearsed <code>`), which
    checks it, burns it and attests the safeguard; a wrong code is audited as failed.
    Burned because a code read once would otherwise prove every year to come; the next
    kit sealed carries a new one, so the yearly gesture is: seal, send, the family
    opens, the code comes back. A new split draws a new code and withdraws the
    rehearsal. It ages as every attestation does (180 days, then a notice), not after
    a year: one expiry serves every safeguard, and twice a year is no harm.
    And it counts only while the family's copy is today's: the last kit sealed for them
    keeps its own fingerprint (`family-kit-sealed`), since a plain kit printed after a
    change makes `emergency-kit` current again while theirs restores the old house.
  - ✅ The sealed kit mailed to each relative at every seal — 2026-11-01:
    `hlb emergency relatives add|remove|list` (an address of the house's own domain
    refused: that copy would go down with it); `kit --sealed` and `split` send kit.age
    to each, one message apiece, from `noreply@` with answers to `postmaster@`, no copy
    left in the house. A relative's server refusing it reaches `postmaster@` too — the
    queue forgets a bounce at once, and `noreply@` is read by nobody. Proven on the lab:
    `split` and `kit --sealed` delivered to a mailbox on the lab's internet, the file
    byte-identical; a relative behind a null MX bounced, and the refusal landed in the
    administrators' box. Live test on Stalwart 1.0.0 and 0.16.26.

**3. An app without Rust, then the catalog on its own.** Gate: an app enters through a
pull request to the catalog, with no `hlb` release.
✅ Passed 2026-11-03 on `v0.4.2`: catalog PR #2 changed Termix's volume from a SQLite
snapshot to a copy made stopped. Merged, proven by Quality on main, built into index 2
(Termix `26.10.5~hlb2`), signed by the owner and served by Pages. The lab installed
Termix from index 1. An unchanged official 0.4.2 binary fetched index 2, and `hlb upgrade
termix` previewed exactly that change (`copy: stopped`, `sqlite: false`), then applied
it: the service healthy, `hlb assert termix` four of four, the upgrade preview empty. The
next `hlb backup run --app termix` scaled Termix to 0, copied it to nas and rest, and
started it again four seconds later (Swarm's events).
- The five schema gaps below come first: while no app enters without Rust, a separate
  repository receives pull requests nobody can merge without a release.
- ✅ The guide frozen beside the manifest — 2026-11-02, the first step of the order
  agreed that day (guide, then the `hlb` range, then sources and a signed index, then
  the split). Six readers took today's catalog's guide for an installed app: `hlb ack`
  and `todo --verify`, the interface's acknowledgement, the nightly re-check, the
  post-restore steps, `plan_as_installed`. They read `apps.guide` now — the catalog's
  only for an app installed before it — and a guide changed alone is an upgrade. The
  source an app came from is NOT recorded yet: with one source there is nothing to
  read it, so it comes with the sources.
- ✅ The `hlb` range per app — 2026-11-02 (step 2). `metadata.hlb: ">=0.4.0"`, required
  by the catalog, optional on read; the workspace carries the next release as
  `0.4.0-dev` (owner's choice that day, over a schema level). An app outside the range
  is set aside instead of refusing the whole catalog, and `catalog validate` holds a
  range to the schema its floor's release committed (`crates/hlb-types/schemas/`).
  Every app starts at 0.4.0: the field itself is unknown to 0.3.0.
- ✅ Sources, unsigned — 2026-11-02 (step 3, first half). `hlb catalog source
  add|list|remove`: a directory read beside the official catalog, its apps
  `<source>/<app>`, installed under the bare name and refused while another source's
  app of that name is installed (`install::basis`). A platform service in a source, or
  an app named after one of the official catalog's, is set aside: the graph finds a
  provider by its bare name. The source is frozen in `apps.source` (migration 0052);
  `upgrade` and `update check` follow it (`Catalog::followed`). The controller and
  privd read the sources once at startup. Left for the second half: the signed index
  and its fetch, so a source can be a URL.
- ✅ The signed index, built and checked offline — 2026-11-02 (step 3b). `hlb catalog
  key generate` (Ed25519, the seed under an age passphrase, 0600, never overwritten);
  `hlb catalog index build|sign|verify` (`hlb_catalog::index`, the format
  `hlb_types::index`). Every file of an app's directory is walked and hashed, each
  version kept under `apps/<app>/<version>/` so an older `hlb` finds the last one its
  range accepts; a changed file under an unchanged image tag is `<tag>~hlbN`. `sign`
  refuses a counter not above `--published`'s (or `--first`), an expiry behind or past
  30 days, a file not the one named; `verify` a path climbing out of its directory.
  Left: fetching an index into a source (3c), the official key compiled in.
- ✅ Signed sources read and fetched — 2026-11-02 (step 3c). A source with a URL and a
  key (migration 0053) is read from its cache by `Catalog::add_signed_source`: held to
  its key again at every read, each app the newest version this `hlb`'s range accepts,
  every app set aside once the index expires. `index::accept` refuses a counter below
  the highest seen, `State::raise_catalog_source_counter` only ever rises, `swap_in`
  replaces the cache only by an index that verifies whole; an install freezes the
  index counter it came in (`apps.source_index`, `install::Origin`). `hlb catalog
  source add <name> <url> --key` downloads and reads it even in preview; `fetch [name]`
  checks the signature and the counter before any file, copies what the cache holds by
  digest (a `~hlbN` fix downloads only what moved), refuses over 8 MiB a response, and
  leaves no staging behind a failure. HTTPS only, plain HTTP from loopback. The cache
  sits in `catalog-sources/<name>` beside the state, deleted with the source. Tried by
  hand: a changed file, an edited index, a replayed one, another signer, a damaged
  cache (repaired by the next fetch) — each refused, the cache untouched.
  ✅ Fetched every night, read again — 2026-11-02: the fetch moved to
  `hlb_engine::sources` (the CLI and the daemon call one), the daemon fetches every
  signed source nightly and notifies a revoked install; privd and the controller hold
  the catalog in a `catalog::Shared` read again every 10 minutes and after a fetch, an
  official catalog unreadable now keeping the one read before.
  ✅ The official source — 2026-11-02: `hlb_catalog::OFFICIAL` (reserved),
  `OFFICIAL_URL`, `OFFICIAL_KEY` (`None` until the owner generates it);
  `Catalog::add_official` lays the official index over the carried catalog — its apps
  under bare names, the platform kept, an app with no version for this `hlb` kept as
  carried, an expired index changing nothing but keeping its revocations. Once a key is
  compiled in, `hlb_engine::sources::ensure_official` writes the `official` row
  (`State::set_carried_source`: address and key from the binary, the counter kept) before
  every fetch — the daemon's first tick at start, `hlb catalog source fetch` — and a
  revoked official install (no source recorded) is named. `hlb catalog source
  add|remove official` refused. The owner's key generated 2026-11-02 and compiled into
  0.4.0 (`official.pub` in the catalog).
- `homelabus-catalog`, one repository, a directory per app; platform services and
  `hlb-types` stay here, where the resolver points. The catalog leaves the controller's
  image (`/usr/share/hlb/catalog`), so a new app version stops requiring a release.
  ✅ The split — 2026-11-02: `Turi-Industries/homelabus-catalog` created public, ONE
  commit (the history starts over, as Homelabus's will), mounted here at `catalog/apps`
  as a submodule; `_platform` stays. Its CI validates a pull request with `hlb catalog
  validate --apps .` (its apps over the platform that `hlb` carries, a platform service
  among them refused) and builds the next index on merge and twice a month;
  `scripts/publish.sh` signs it on the owner's machine and pushes it to GitHub Pages,
  `scripts/github-settings.sh` sets the repository (squash only, read-only token, the
  rules on main, immutable releases). Rehearsed locally with a throwaway key: built,
  signed `--first`, verified, built again over it and signed as index 2. The carried
  catalog stays in `hlb` and the image as the fallback the official index lays over.
  An icon is read beside its entry's manifest, wherever the catalog read it from.
  0.4.0 released with the key and mirrored (`hlb-v0.4.0` in the catalog's releases):
  its Validate and Index runs pass. Index 1 signed by the owner and served by Pages the
  same day; a 0.4.0 `hlb catalog source fetch` takes it, 13 apps, held to the key.
- Three levels of source — official (its key built into `hlb`), community (any URL,
  trusted explicitly per app or per source), local (a directory). An app carries its
  source's name, so `community/foo` never shadows `foo`; a third-party source may
  REQUIRE a capability and never PROVIDE one. A revocation list `hlb` reads.
  ✅ Revocation — 2026-11-02: `index.revoked` (signed with the index), fed by the
  catalog's `revoked.yaml`, carried by every later build and never dropped, a version
  no index holds refused; a revoked version is never offered, an app whose every
  version is revoked set aside with the reason. An install freezes the version it took
  (`apps.source_version`), an upgrade moves it with the manifest and a reverted one
  puts it back; a house running a revoked version has a critical `version_revoked`
  line in its inbox, and `hlb catalog source fetch` prints why.
- A signed `index.json` — each manifest's and image's digest, a counter that only
  rises, an expiry, so a mirror can neither replay nor freeze it — one key per source;
  the frozen install keeps its source and index number. Each app version declares the
  `hlb` range it accepts, the index keeps several versions per app, and `3.3.1~hlb2`
  counts a packaging fix as an update.
- Quality levels computed by CI, never declared: install, update from the published
  version, back up, restore, prove, uninstall — on each pull request and weekly; shown
  as *installs, updates, restores, maintained for N months*.
  ✅ The results — 2026-11-02: `quality-v1.json` beside the index (`hlb_types::quality`,
  its format frozen with the index's, which 0.4.0 reads `deny_unknown_fields`), built by
  `hlb catalog index build --quality <runs>` over the previous file (the day each app
  entered is carried, the newer run kept), signed with the index and held to its
  counter, so a mirror cannot pair today's index with older results. A fetch keeps it
  only verified and says why one was left out; the catalog screen has a Proven column
  and the install window the run, step by step. The catalog's `scripts/quality.sh`
  rehearsed whole on a fresh Debian 12 VM with Mealie (published version, a guide
  change as the update, volume and database restored: every step passed), with the
  `Quality` workflow and the Index's gathering. On hosted runners with 0.4.2, catalog
  PR #2: all 13 apps pass every step that applies — install, back up, restore,
  uninstall; the update from the published version for Fluxer and Termix, the two the
  PR changed (the other eleven had no newer version to update to: `notRun`); LibreSpeed
  keeps nothing, so no restore. Immich and Jellyfin keep their volumes on a local NFS
  export. Fluxer's restore reached green once its search rebuild worked on a house with
  no community (Fluxer's full refresh fails until a threads refresh readies its index).
- ✅ Before installing, the preview shows what the app receives — 2026-11-02.
  `Manifest::grants` names what the manifest opened past the closed defaults: exposure
  to the internet (now or after its guide), paths open to anyone, ports published on
  the node, capabilities kept or given back, setuid, a writable root, a webmail's use
  of each person's mailbox password, a compose runtime — the app's and each
  companion's, `SecuritySpec` destructured whole so a new field must be answered.
  `hlb install` prints it above the plan; privd puts it in the preview's warnings, which
  the interface shows. The host network, Docker's socket, `privileged`, devices and a
  mail administrator's token have no field: no manifest can ask for them.
- ✅ An app's criticality — 2026-11-02. `metadata.criticality: vital | important |
  normal`, required of an app by the catalog, refused on a platform service, optional
  on read (`normal`). Read today by the backup pass, which serves vital apps first
  (`Pass::most_critical_first`); the lifeboat's input in phase 4. Set by Claude, to
  confirm: Vaultwarden vital; Immich, Seafile, Gitea, Fluxer, Termix important; the
  rest normal.
- Proving ground for goal 4: **which apps is the owner's decision, taken when this phase
  starts** (2026-10-30) — the list below was proposed while planning, never decided, and
  no app is added from it meanwhile. Decided 2026-10-31: calendars and contacts from
  Stalwart (a capability and a phone guide); the rest of the list proposed —
  Paperless-ngx, Actual, Audiobookshelf, Navidrome, FreshRSS — was not chosen.
  - ✅ Mealie — 2026-10-30, a manifest and a guide, no Rust beyond the form-encoded
    recovery proof it showed missing. **Proven on the lab** by `hlb install mealie
    --apply` alone: the guide's `sql` step run by the executor (all four assertions
    hold, the recovery proof signs in), its session keys mounted inside the volume's
    path (a backup of the volume holds empty files there), camille and dominique
    signed in through PocketID — an administrator from `hlb_mealie` and a member —, a
    message sent over STARTTLS and delivered DKIM-signed, the volume and its database
    backed up. The first app of the catalog under a read-only root: `TMPDIR` on its
    volume, without which an upload past 1 MB is refused (400, measured).
  - ✅ Calendars and contacts from Stalwart — 2026-11-01. A device's password is
    Stalwart's own `x:AppPassword` (1.0), and Stalwart the only list of them: Me →
    Devices and `hlb user device add|list|revoke`, making one takes the person's own
    passkey, the password shown once beside a setup panel — server, user, an Apple
    profile built in the browser (CalDAV, CardDAV, IMAP and SMTP), DAVx⁵ and mail-app
    lines. **Proven on the lab**: from the CLI and from the page with a real passkey,
    the password answered PROPFIND through Caddy (207, CalDAV and CardDAV) and IMAP,
    and after revocation 401 and refused. The lab found one defect: `revoke` refused
    the address `device list` prints.

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
- The VPS as the signed zone's secondary (decided 2026-10-31): Knot at home signs and
  serves, the VPS's Knot transfers the zone over WireGuard and answers alone while the
  house is down. Both are the zone's NS; no third-party DNS service.
- The lifeboat: vital apps restored nightly onto the VPS, stopped, started once by a
  health check — goal 2's rehearsal, nightly, on a real machine. `hlb site promote` and
  `hlb site return`, by hand: with two sites nothing tells "the house fell" from "the
  link broke". An app is writable on the VPS only if its manifest declares how its data
  comes home, read-only otherwise; the preview refuses a selection beyond the VPS's
  declared memory or disk, figures measured with `docker stats` on the lab first.
- Gatus on the VPS, generated from the catalog: two probes per app (through the front
  door, and straight home over WireGuard) to say where it breaks; heartbeats pushed from
  home (backup done, lifeboat verified); alerts never through the house's own Stalwart
  or ntfy; the house probes the VPS, and the VPS's own Healthchecks — self-hosted
  there, never healthchecks.io — receives the pings. Names the family
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
- **The steps** (2026-11-09), in this order; the gate's row is `5 available` already.
  1. **A site.** `hlb site add` prepares the VPS over SSH as the bootstrap prepares a
     node — Docker, hardening, unattended updates — with a Swarm of its OWN, one node,
     never joined to the house's. The link is not the mesh: an interface of its own
     (`hlb-site`, `10.43.0.0/24`), each house node opening its tunnel to the VPS — the
     house is behind NAT or a CGNAT — and the house's firewall letting the VPS reach
     80 and Caddy's relay port only. Swarm's ports on that link would hand the VPS every secret. The
     site's memory and disk read off the machine and recorded; each tunnel's last
     handshake read by `hlb site status` — the controller watches it with step 5.
     Built 2026-11-09: `hlb_mesh::site`, `hlb site add | status | sync`; the house's
     rules sit at prerouting, before Docker's DNAT, which `input` never sees. Found on
     the way: the bootstrap wrote one tunnel's unit files under fixed names, so the
     link would have rewritten Docker's wait for the mesh (`mesh::Tunnel`). Run on the
     lab 2026-11-09: `vps1`, a 4 GB Debian 12 VM on `hlb-internet` (10.99.0.40, the
     house reaching it through NAT only, it reaching no 10.77.0.x), deb1 and deb2
     handshaking, enc1–3 off and said so.
  2. **The front door.** HAProxy on the VPS in TCP mode, never decrypting, every house
     node a backend on its site address, its health check finding the one Caddy runs
     on; the PROXY protocol to Caddy, accepted from the site network only, so the
     client's address survives. Certificates stay at home.
     Built 2026-11-09: `hlb_ingress::front_door`, deployed by `hlb site add | sync`
     (`hlb-front-door`, host-mode 80 and 443, read-only, no capability; its file
     checked by the image before the rename, `SIGUSR2` for a new node). 443 is relayed
     to Caddy's port 10443 with the header, never to 443: a hostile VPS can forge any
     source — measured, Caddy read a header claiming `192.168.1.5` — so the PORT, not
     the header, tells relayed traffic apart, and a private route refuses it there;
     `10.43.0.0/24` is cut out of the private ranges. 80 is relayed as is. Measured:
     `haproxy -c` on the rendered file, the image read-only binding 80 and 443 and
     reloading on `SIGUSR2`, the real Caddy on the relay listener. Run on the lab
     2026-11-09, and it found two holes: a Caddy frozen before the relay publishes no
     10443, so the door led nowhere for HTTPS (`site add | sync` say so now, `hlb
     upgrade caddy` named); and 🔴 a PRIVATE route answered through the door — behind
     `proxy_protocol`, `{http.request.local.port}` is the header's destination, 443 as
     HAProxy writes it. Every site block is rendered once per listener now, nobody at
     home on 10443 (`tests/relay_is_a_stranger.rs`, real HAProxy and Caddy, fails on the
     old rendering). After: Vaultwarden 403 through the VPS and 200 at home, the public
     controller 200 through it with the visitor's address.
  3. **The lifeboat.** Vital apps — Vaultwarden, PocketID — restored nightly from their
     backups onto the VPS, stopped, started once by a health check, recorded as a
     rehearsal; refused at preview beyond the site's memory or disk, figures measured
     with `docker stats` on the lab first.
     Built 2026-11-09: `hlb site lifeboat [--apply]`
     (`hlb_engine::lifeboat` chooses and renders, `hlb_backup_run::lifeboat` sends). The
     house reads the backups and pushes to the site's Docker over SSH (`docker system
     dial-stdio`: the house's key may not forward a socket): each volume's archive with its root put back in front (`restic dump` leaves the
     directory out), its SQLite from the same pass's copy, each PostgreSQL dump into a
     server of the site's own whose administrator is the site's (`site-lifeboat-postgres-
     admin`), the app's role created with the password its app is given. The SMTP
     password is withheld. Memory is the manifests' limits against the site's; each
     archive is refused past a tenth of the site's disk left free. Recorded as a drill
     (`lifeboat`), audited; what it left is named in the vault and removed by the next
     run. Run on the lab 2026-11-09: PocketID (its SQLite from the pass's copy, 5
     accounts, integrity ok), Vaultwarden (its database's witness row, its RSA key) and
     the site's PostgreSQL, started healthy and stopped in 124 s; Vaultwarden starts
     with its SMTP token literal. Found there: the house's key is `no-port-forwarding`,
     so sshd refused the socket forward — `docker system dial-stdio` instead, a command
     per connection; and the archive's scratch file was opened write-only (`EBADF`,
     reported as "SendRequest"), then a database's path named a directory that did not
     exist — `tests/lifeboat.rs` now sends a volume and its SQLite too. **Measured**
     (`docker stats`, idle on the site): PostgreSQL 60 MiB, PocketID 15, Vaultwarden 9,
     HAProxy 16; at home, in use, 157, 54 and 27. The limits say 2 560 MB, PostgreSQL's
     2 GiB the bulk: a 2 GB VPS is refused at preview though 100 MiB is what the
     lifeboat uses — the site's PostgreSQL could be given a limit of its own. A
     Vaultwarden installed before `criticality` was read as not vital until `hlb
     upgrade`. Left: the nightly run from the controller.
  4. **Promote and return**, by hand: `hlb site promote` points the front door at the
     lifeboat; `hlb site return` brings writes home where the manifest says how,
     read-only on the VPS otherwise. A promoted site's lifeboat is serving: `hlb site
     lifeboat` must refuse it, or the night's run removes what people are writing to.
     Two pull requests: 4a promotes, 4b returns.
     4a built 2026-11-09: each night the lifeboat also leaves, stopped, the site's own
     Caddy (`hlb-site-caddy`, its file checked by its binary; site mode of the
     Caddyfile: HTTP-01 against the house's ACME directory, never the internal root
     nor a DNS token — `Internal` exposure is refused; its volumes are carried, so
     removed each night and no key waits there), the door's promoted file
     (`haproxy.promoted.cfg`, the lifeboat's names to that Caddy, every other name
     home, kept by `hlb site sync`) and `/usr/local/sbin/hlb-site-promote`: it marks the
     site (`/etc/hlb/site/promoted`) before starting anything, starts PostgreSQL, the
     sign-in, the apps and the Caddy each until healthy, then checks and swaps the
     door. `hlb site promote [--apply]` runs that script from the house, audited;
     `hlb site status` says since when; a marked site's lifeboat is refused. The
     memory budget counts the site Caddy's 512 MB. A carried app declares how it
     returns (`spec.lifeboat.returns: whole`), one declaring nothing is refused. Found:
     Caddy's automatic redirect named `:10443` and beat a catch-all `http://`, so the
     site mode disables redirects (`tests/promoted_door.rs`, real HAProxy and Caddy).
     Left: Vaultwarden's catalog manifest can declare `lifeboat` only once a release
     reads it (the catalog is validated by the released `hlb`) — until then the lab's
     Vaultwarden is refused; and the house coming back mid-promotion still serves its
     own copies to the LAN, which 4b must hold.
     4b built 2026-11-09: `hlb site return [--apply]`. What the site wrote comes home
     THROUGH the backups: each database dumped on the site's PostgreSQL by its own
     administrator, each backed-up volume read off the site's daemon
     (`SwarmOrchestrator::get_archive`) and unpacked here, both archived to the app's
     destinations as `kind:from-site` and recorded, then put back by the restores
     `hlb backup restore` runs — placement and NFS as they know them, what the house
     held backed up first (`kind:pre-restore`), `--delete`. The site's copy outlives the
     site. Order: the house's copies held stopped (`promote --apply` holds them from the
     start, a year), the site's stopped, everything read, everything restored, the house
     started until healthy — never fewer replicas than the plan declares — then the mark
     removed and the door sent home, the site's Caddy and its certificates removed. A
     failure before the door gives the site its apps back and keeps the house held: a
     rerun reads the site again. Measured on a real Docker (`tests/lifeboat.rs`): a
     volume and a PostgreSQL database come home whole, owned as on the site. Found: a
     restore in place keeps the volume's ROOT as it was (restic 0.19.1). Left: a house
     back after a promotion made over SSH alone still starts its own copies for the LAN
     — nothing reads the site's mark when the house starts; what they write is replaced
     at the return, kept in the copy taken first. Not yet run on the lab.
  5. **Gatus on the VPS**, generated from the catalog, two probes per app, heartbeats
     from home, alerts that never go through the house.
     5a built 2026-11-09: `hlb site add` and `sync` put the site's watch in place after
     the door, on an overlay of its own (`hlb-site-watch`, never the lifeboat's): an
     ntfy of the VPS's (`deny-all`, the phone's account read-only, Gatus's token
     write-only, no `upstream-base-url`), Gatus, and the edge — a Caddy of the site's
     own serving `status.` and `alerts.` of the house's domain, its certificates over
     HTTP-01 like the lifeboat's and kept, since nothing of the house's is in them. The
     door sends those two names to the edge, promoted or not. Gatus probes every name
     the house's Caddy last PUBLISHED, through the door — each resolved to the door's
     address on the overlay, whatever the public DNS says — a public app by its answer
     (`< 500`), a private one by its 403: a private app answering strangers is down.
     One probe of the house's Caddy over the link, not one per app: an app cannot be
     reached that way — 10443 wants the PROXY header, 443 is closed to the VPS — and
     which node's link is down is the house's to say, in 5b. The page shows no host,
     address, condition or error. Its file is checked by Gatus itself before it is put
     in place, and two wait beside it: the promotion swaps the page after the door
     (private apps served on purpose then), the return swaps it back. Measured on the
     real Gatus and Caddy (`tests/status_page.rs`). Gatus has no `NET_RAW`, so no ping.
     Not yet run on the lab.
  6. **Downtime**: stop-first with Caddy's maintenance page, two replicas of stateless
     services, the disruption budget, the migration undone in one command.
  7. **The gate on the lab**, timed both ways.
  8. Then Knot (the house signing, the VPS secondary) and OPNsense.

**5. Always up to date.** Gate: a patch applied with nobody there; an exploited CVE
reported within 24 hours.
- The controller calls `hlb-updater`. A policy per kind of version instead of one
  channel, overridable by the manifest and by the house — patch automatic, minor one
  click from the inbox with its notes, major manual with the catalog's migration guide,
  KEV-exploited at the next window. Guards: notes saying *breaking* or *migration* stop
  the automatic path; the catalog can hold a version back for everyone; `hlb` records
  when it first saw a tag (GHCR and Quay date nothing).
- CVEs: an SBOM (Syft) at each deploy, compared daily without pulling again; each
  machine's own packages by the same two — not `debsecan`, Debian's alone and blind to
  KEV and EPSS (2026-11-08). An alert only when a fix exists, the flaw is exploited (KEV)
  or likely to be (EPSS), and the component is exposed; the rest in a weekly digest; no
  fix, never an alert.
- Planned reboots under a lock, one node at a time: drained, rebooted, waited healthy,
  in the window, never while the house is degraded or the VPS is relaying. Built
  2026-11-08 (`hlb_updater::reboot`, `hlb-privd`'s `daemon::reboots`): the nodes are
  asked hourly in the window (`daily 03:00-05:00` in the house's zone by default) through
  a job entering the host's namespaces — no SSH; one waiting is drained, rebooted, and
  put back once Swarm sees it ready AND its uptime says it booted since. Degraded means
  another node not ready or not active (`maintenance` refuses). The lock is a row of the
  state, which outlives the daemon rebooted with its node; a reboot that does not drain
  in 10 min or come back in 30 stops every other until `hlb node upgrade` succeeds
  (`node_reboot_stopped`). ⚠️ "Never while the VPS is relaying" waits for phase 4: there
  is no VPS to ask yet. Still to prove on the lab.
  `needrestart` without Docker — written by bootstrap since before phase 5
  (`/etc/needrestart/conf.d/hlb.conf`, where it is installed); `fwupd` reports firmware
  and never applies it — read daily since 2026-11-08 (`hlb_updater::firmware`) into the
  inbox (`firmware_update`, `firmware_unknown`), never measured on a real board's
  capsule yet.
- `cargo deny` beside `cargo audit` — done 2026-11-08: licences, bans and sources in CI's
  "Dependencies" job, the advisories left to `cargo audit`'s one list. Disks: SMART read
  daily since 2026-11-08 (`hlb_updater::disks`): a disk failing, or an error counter that
  GREW, said at once and in the inbox (`disk_failing`), one unread `disk_unknown`; each
  pool's health and last scrub too (`pool_unhealthy`, `pool_not_scrubbed` past six
  weeks). The scrub stays the distribution's (Debian's monthly timer), read and never
  scheduled; never measured on a spinning disk nor a real pool yet. The
  UPS — done 2026-11-08, held to a real `upsd` 2.8 with `dummy-ups`: NUT read every 15 s
  (`GET VAR` only), five minutes on battery or under ten of runtime or at low battery stop
  the apps in waves from the capability graph — those nothing uses first, the databases
  last — and the mains steady two minutes start them in reverse (`hlb config ups`,
  `power_stopped`, `ups_unknown`). Each machine is shut down by NUT's own `upsmon`, a
  secondary Homelabus writes on every node (`--shutdown-user`, decided by the owner
  2026-11-08), held to a real `nut-client` 2.8.0. Not yet run on the lab.
- ✅ **The gate, on the lab** — 2026-11-08 and 09, Debian 12 deb1 + deb2 with enc1–3
  off. **A patch applied with nobody there**: the hourly pass took crowdsec v1.8.1 →
  v1.8.2 in its window, copied its two volumes first, switched by digest, saw it running
  and froze it (`update-applied` by `controller`, notified; 3 days from first sighting).
  **An exploited CVE in the inbox**: KEV CVE-2026-111497 (brotli) alerted for five apps at
  the first daily pass. The UPS on `dummy-ups`: waves in order (apps, the databases once
  the apps had EXITED, Stalwart), started in reverse, `hlb-privd` killed mid-wave
  finishing from its row, no pass that changes things beginning mid-stop; upsmon on each
  ready node, a real `OB LB` powering deb2 off after its last task container, deb1
  waiting its 60 s cap. Disks and the pool `tank`, firmware and each host's packages read.
  **Found**: reconciliation took an update back mid-switch — crowdsec, then Caddy 0.4.8,
  both "inconclusive" 180 s later — since the manifest is frozen only once the new image
  is proved (#114: the switch is on the state's record, `Drift::Switching`); 0.2 → 0.4
  read as a minor, so a KEV took Caddy across a breaking release (#113: below 1.0 the
  second number is the major).
- **Left from phase 5**: a real planned reboot — refused all evening because enc1–3 were
  down (degraded), which is the rule; it needs them up or out of the Swarm. SMART on a
  spinning disk, a real pool's scrub and a real board's fwupd capsule wait for hardware.

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

**Goal 2 — never lose.** Every app's backups are read back weekly: volumes counted, dumps
restored into a disposable server, SQLite checked, buckets read to their end. What is
left: a read-back proves a copy returns, not that the app runs on it. A store copied live
passes (`.claude/rules/backups.md`), so `scripts/drills/recovery.sh` starts every app of the
lab on a bare VM from the kit and one destination alone, its assertions held: 14 of 14 on
2026-11-05, by hand. The catalog's CI does it for packaging, the lifeboat (phase 4) will for
the vital apps nightly. ⚠️ The lab holds little (Vaultwarden no account, Vikunja no task), so
on those an assertion says the app runs, not that a person's data came back. A verification
reads the newest
destination it can, so an off-site copy is rarely the one read. Proposed beside it:
reciprocal backups between two houses, each keeping the other's encrypted copy append-only
— an off-site copy with no provider at all.

**Goal 4 — no Rust: the schema gaps**, each a closed list a new app has had to extend,
ranked by how many apps they would have spared (audit of 2026-10-27):
1. **Deploy knobs** — tmpfs, `sharedEnv`, host-port update order, a probe-derived wait,
   keepalives: each was a Rust change. A bounded pass-through of Swarm service and mount
   options, refused at preview when it weakens isolation.
   **Measured** 2026-10-31: those five are all Fluxer's, and all in the schema now — the
   question is the NEXT app's knob. Read from two public stores' compose files (Umbrel
   396 apps, CasaOS 181: 577), each service key counted once per app, against what a
   manifest says. Not sayable today, isolation intact: arguments after the image's own
   entrypoint (`command`, **109** — a manifest can only replace the entrypoint, so
   PostgreSQL's restates Immich's to add three settings, and an image changing its
   entrypoint would be overridden in silence), a stop grace period (**188**, 184 of
   them Umbrel's blanket `1m`; ~30 chosen, up to `15m30s` — Swarm's default is 10 s,
   then `SIGKILL`), `init` (**45**), a sized `/dev/shm` (**14**, `shm_size`; a tmpfs
   has no size here), `hostname` (15), `ulimits` (7, `nofile`), `working_dir` (3),
   `sysctls` (3, `net.*`), `stop_signal` (2), `group_add` (1). Weakening isolation:
   `network_mode: host` (45), `privileged: true` (22), `devices` (16, `/dev/dri`),
   `extra_hosts` to the host (13), `pid`/`ipc: host` (4) — Swarm has no field for
   privileged nor devices. Everything else is compose bookkeeping Homelabus does
   itself (`restart`, `depends_on`, `container_name`, `labels`, `logging`). Swarm's
   `ContainerSpec` carries every one of the ten (bollard 0.21: `args`,
   `stop_grace_period`, `init`, `hostname`, `ulimits`, `dir`, `sysctls`,
   `stop_signal`, `groups`; `size_bytes` on a tmpfs). **So: typed, not a
   pass-through.** The tail ends at ten keys, each a field `deny_unknown_fields`
   checks; untyped options merged over the spec could undo `read_only` or `cap_drop`
   where nothing reads them. The number that would have killed it: a tail of keys
   used by one app each, never ending — measured, there is none outside the ones that
   weaken isolation, which stay refused (the third-party sources' confirmation, later
   in this phase, is where host network may come in). Designed: `args` beside
   `command` on the app and a companion; `process: { init, stopGracePeriod,
   stopSignal, workingDir, hostname, ulimits, sysctls, groups }` on both, one type;
   a tmpfs written `{ path, size }` as well as a path; `sysctls` only `net.*`, which
   the container's own namespace holds; all optional on read. Each reaches Swarm's
   spec through a destructuring with no `..`, so an eleventh field fails to compile
   until it is mapped. ✅ Built 2026-10-31 (`hlb_types::{Process, Ulimit, Tmpfs}`, `args`, the
   orchestrator's `to_bollard`): each field held from the manifest to Swarm's spec by a
   test per layer — validation, the plan (arguments and `sysctls` shown in the
   preview), the executor (proven to fail with the wiring removed), the spec. Five
   manifests moved from a restated entrypoint to `args`, each against its image's
   `Entrypoint` and `Cmd` read from the registry: PostgreSQL, MariaDB, ntfy, and
   Fluxer's NATS and Valkey — 🔴 whose `command` had dropped the image's `tini`.
   **Proven on the lab** the same day by `hlb upgrade --apply` (PostgreSQL, MariaDB,
   Fluxer; the lab's older MariaDB 11.8, NATS 2.14 and Valkey checked the same shape):
   Swarm's spec now `Command: null` and the `Args`; Valkey's PID 1 `valkey-server`
   before, `tini -- docker-entrypoint.sh valkey-server …` after; the others' processes
   unchanged, PostgreSQL's keepalives still from the `command line` and `vchord.so`
   still preloaded; every service 1/1, `hlb assert` 24 green. ntfy is not installed
   there.
2. **Tokens and secret forms** (`binding.rs`) — timezone, logo, VAPID, RSA. A secret
   generated by a declared template or command; install facts as generic tokens.
   **Measured** 2026-10-31 on the same 577 apps — **neither design is needed; nothing
   built.** The number that would have called for a template or a command: a tail of
   secret forms, one per app, never ending. Umbrel generates every app's secrets itself
   (`APP_SEED` fed raw to 61 apps, 25 secrets derived in 16 `exports.sh`): all are a
   SHA-256 in hex, cut to 16, 32 or 64 characters, or 32 bytes in base64 — what
   `{{ secret.x }}` (32 alphanumerics: Laravel's `APP_KEY` wants exactly 32), `:hex`
   and `:base64` already give. What none of the forms gives is the tail, and it ends at three:
   exactly 16 bytes of hex (Activepieces' `AP_ENCRYPTION_KEY`, LibreChat's
   `CREDS_IV`, 2 apps), an RSA key as PKCS#1 DER (wger, 1) and as a JWKS (Lobe Chat,
   1), the last two made by a `pre-start` hook. VAPID: 2 apps, already a form. Each
   is a `SecretForm` variant when an app the owner names needs it — exhaustive, where
   a command run at install time would execute code for no app measured. Install facts:
   the time zone (95 apps, 31 of them hard-coding one) and the domain (78) are the
   only ones that recur, and both are tokens. User ids (112 apps) are constants a
   manifest writes literally, as Mealie's does; the 8 first-admin e-mails are
   placeholders (`admin@example.com`), and Seafile's manifest already gives its own
   `{{ smtp.from }}`, while people come in through PocketID; a language, 3 apps.
3. **Engines** — `DbEngine` is PostgreSQL or MariaDB, the cache is Valkey: Fluxer runs
   Valkey, NATS and Meilisearch as companions, without provisioning or dump backups.
   **Measured** 2026-10-31 on the 577 apps, by image: 112 run a backing engine, and
   **85 of them only engines Homelabus provisions** — PostgreSQL (64, pgvector
   included), MariaDB or MySQL (25), a Redis-compatible cache (38), S3 (Garage). The
   other 27 spread thin: MongoDB 10 (two of them MongoDB itself, three Bitcoin wallets),
   Meilisearch 6, PostGIS 2, Elasticsearch/OpenSearch 2, a vector database 2, then
   TimescaleDB, DocumentDB, ClickHouse, RabbitMQ and Memcached, one app each. No third
   engine approaches the two: a generic engine declaration would serve a tail, and
   MongoDB enters as a `DbEngine` variant when an app the owner names runs it. 🔴 What
   the tail shares is the real gap: each runs as a companion, and the nightly pass
   copies a companion's volume **while it runs** — only a restore stops services — so
   a database's files can be caught mid-write. That is gap 5's step before a backup (a
   declared dump, or the companion stopped for its copy), not an engine.
4. **Syncing people and nodes into an app** — `Members` and `Nodes` have one variant
   each, and each needed a crate. Per-person and per-node `exec`/HTTP steps, as
   `AdminsApply` and `QuotaApply` already are.
   **Measured** 2026-10-31 on the catalog — the two stores keep no accounts to compare
   with. Of the 13 apps holding people, 7 take them through OIDC claims at each sign-in
   and need nothing kept in step; 3 keep an existing account in step by declared
   per-person steps, with no Rust (Fluxer's administrators by `exec`, Immich's quota by
   `sql`, Seafile's by `exec`). The two crates would not have been spared by a declared
   step: Vaultwarden's members are ONE import call for the whole set, declarable — but
   confirming a member encrypts the organisation's key, which only an owner's client
   can, and `hlb-bitwarden` is the emergency vault's client cryptography far more than
   the sync (171 of its 1,630 lines). Termix's hosts are a diff against Termix's own
   list, declarable — but each node's key is authorized ON the node, a machine's
   action, not an app's. Then Jellyfin, named 2026-11-01: its accounts made by its SSO
   plugin at a first sign-in, kept enabled by role ✅ 2026-11-01 — `access.accounts`,
   an `http` variant signing in as a recovery sign-in, walking the APP's links
   (PocketID id → account), not Homelabus's people, so a person deleted from Homelabus
   is disabled too (below, "Jellyfin signs in through PocketID", part 4).
5. **Lifecycle** — jobs run daily or weekly only; no pre-upgrade step (none needed,
   measured); post-restore steps and connection budgets built 2026-11-01.
   **Measured** 2026-10-31, the step before a backup first. The nightly pass copies
   every `backup: true` volume with restic while its service runs — only a restore
   stops one — and the catalog declares 24. By what they hold (the lab's `nas`
   repository and volumes read the same day):
   - SQLite snapshotted by `VACUUM INTO`, flagged `sqlite: true`: PocketID, Jellyfin,
     Termix. 🔴 **SQLite copied live, unflagged: CrowdSec's `crowdsec.db`** (5 MB, on
     the lab), **ntfy's `cache.db` and `auth.db`** (its accounts and tokens, by its
     manifest's own variables), **Grafana's `grafana.db`** (its manifest's comment
     says "SQLite"). Three of six carry the flag — a hand-maintained list, drifted.
     `sqlite::discover` already finds a database by its header; the flag only says
     which volumes to look in.
   - An engine's store, copied live: **Stalwart's RocksDB** (all the mail), Garage's
     LMDB `meta` (whose manifest says "stopping the service before copying stays the
     only way to be consistent" — nothing stops it), Fluxer's NATS JetStream, and
     PostgreSQL's and MariaDB's own data directories (MariaDB's, 201 MB every night on
     the lab) beside the dumps that actually restore them.
   - Files written whole, safe live: Caddy's certificates, CrowdSec's configuration,
     Immich's and Vikunja's files, Vaultwarden's, Mealie's and n8n's data (their
     databases are PostgreSQL), Bulwark's two. Not read file by file: Seafile's
     blocks, Gitea's `/data` (its queues are LevelDB by default).

   **The drill**, on deb1, from snapshot `d4e79ce7` (2026-10-30 20:37): Stalwart 1.0,
   `--network none`, opened the live copy with no RocksDB error — the live server's
   accounts bar the one made since, the same e-mail count in each, four messages
   byte-identical. One idle sample says nothing of the race, so the race was played on
   the restored copy: restic 0.19.1 reads a directory in name order, two files at a
   time — the `000*.sst` first, `MANIFEST-*` last (checked) —, and a flush between the two (forced by a restart) left
   a copy whose MANIFEST names `000465.sst`, written after the SSTs were read —
   **`Corruption: … 000465.sst: No such file or directory`, and Stalwart does not
   start.** restic reports nothing: a file created after its listing is no error,
   only one that vanished (exit 3, which the pass does fail on). Nothing reads a
   volume snapshot back as its app would — `backup verify` compares the snapshot with
   itself — so it shows the day of the restore. Stalwart's own `--export` opens the
   store, so it too needs the service stopped; a ZFS snapshot would not (it is what a
   power cut leaves, and RocksDB recovers from that), but `data-v1` is a Docker volume
   on deb1, not a dataset.

   **So**, three steps, by what a volume holds. (1) SQLite: discovered in every
   backed-up volume, flag or not, and paired at restore the same way — the scan
   replaces the list. (2) A declared step before a volume's copy, an exhaustive enum:
   the service **stopped** for its copy and started again whatever happened
   (Stalwart, NATS), or a command **writing a consistent copy** into the volume while
   it runs (Garage's `garage meta snapshot`). (3) PostgreSQL's and MariaDB's data
   directories: read what restores them today (dumps, PITR's base backups) before
   taking them out of the volume pass. The kill number for (2)'s stop: a mail server
   down long enough for a sender to give up — measured in days, against a stop that
   lasts restic's incremental pass over immutable SSTs.
   ✅ (1) built 2026-10-31: the pass looks in every backed-up volume on its machine
   (`Pass::holds_sqlite`, by header), snapshots what it finds and marks the volume
   `sqlite` in the state — owed a snapshot from then on, its databases put back at a
   restore, which now asks for them whatever the flag (`tests/pass.rs`, proven to fail
   first). CrowdSec, ntfy and Grafana flagged in the catalog too: a volume on another
   node is not looked in, and only a flag makes its live copy fail out loud there.
   ✅ (2) built 2026-10-31, the stop only: `copy: stopped` on a volume (an app's or a
   companion's; refused on one not backed up or another app's), read from the frozen
   manifest by the nightly pass AND the copy taken before an update. The services
   writing such a volume are held, stopped once for every due destination and started
   again whatever happened (`restore::stop`/`start`); with no orchestrator, or a service
   whose state cannot be read, the copy FAILS — never taken live instead
   (`tests/pass.rs`, proven to fail first). Stalwart's `data-v1` declares it. No `exec`
   variant: Garage's `meta snapshot`, its one candidate, copies metadata whose blocks
   are not backed up — whether `garage-meta` is backed up at all is the owner's call.
   NATS is not declared, unmeasured. **Measured** on deb1 the same day (`hlb backup run
   --app stalwart --force`, two destinations, `nas` and `rest`): SMTP on port 25 stopped
   answering for **5.0 s** (probed every 0.5 s), the pass took 8.3 s — against senders
   that retry for days, so the stop stays. Released after: reconciliation sees no gap.
   ✅ `garage-meta` decided 2026-11-01 (owner, on the drill): **no longer backed up.**
   Its blocks are not, so a restored `meta` names objects whose bytes are gone. Drilled
   on deb1 first: Garage's service and both volumes deleted, then `hlb install garage`,
   `hlb garage init`, `hlb redeploy fluxer` (its four buckets and a new key, the vault
   updated — 71 actions) and `hlb backup restore fluxer fluxer`: 4 objects of 4, md5
   identical, the attachment served through Caddy by Fluxer's media proxy. 🔴 Found on
   the way: **nothing notices a Garage that lost an app's buckets or key** — Fluxer ran
   1/1 against `No such key` until the redeploy, reconciliation saw no gap, and
   `hlb upgrade` says "nothing to apply". ✅ Both built 2026-11-01: reconciliation
   reads Garage's buckets and keys every pass (`Drift::StorageLost`, refused, its fix
   the redeploy and one restore per bucket backed up; `StorageUnread` when Garage is
   silent) — in `hlb reconcile`, `hlb-privd`'s loop and the drift screen — and the
   runbook's "If Garage lost its data" lists the four commands and every app's
   buckets from the state. **On the lab** the same day: Fluxer's key renamed in
   Garage, then one bucket's global alias taken off (its objects untouched), each
   named by `hlb reconcile` with its fix and by the controller's `/api/drift` — and
   put back, no gap. 🔴 Found on the way: the drift came out GREEN, a refusal being a
   decision, so the issues list dropped it and the dashboard stayed calm. A drift now
   says what it does to the app (`DriftHarm`): lost storage and a missing service are
   red, an unread Garage amber.
   ✅ (3), PostgreSQL, built 2026-11-01 (`hlb_backup_run::engine_copy`, the owner's
   "physical copy, hot" of 2026-10-31): `copy: pg-basebackup` on the catalog's
   `postgres-data`. The pass and the copy before an update run `pg_basebackup`
   (`--wal-method=stream`) in the SERVER's image where the volume lives — `docker run`
   here, a Swarm job on another node, the password a file — into `hlb-copy-<volume>`,
   back that up at the real volume's path, and empty it; no administrator known, the
   copy fails, never taken live. The server reads `hlb_hba.conf` (the data directory's
   own file included first, then `host replication postgres`). Proven
   (`tests/pass.rs`) on the catalog's image with a writer inserting throughout: the
   restored directory starts, `pg_amcheck --all --heapallindexed` clean, every row
   from before; with the live copy, no `backup_label` — fails first. **On the lab**:
   `hlb upgrade postgres --apply`, then the pass in 7.8 s through a job on deb2 —
   🔴 after a fix: a job run's file secret overflowed Swarm's 64 characters, latent
   since the restic jobs' names were short. Snapshot `29b86bf1` restored into a
   throwaway volume and started with no network: backup recovery, consistent, its
   six databases, `pg_amcheck` 0 — 220 MB where the live volume copy took 381 (the WAL
   the lab's stale slot holds stays out). MariaDB the same way, `copy: mariadb-backup`
   on `mariadb-data`: `mariadb-backup --backup` reads the LIVE volume mounted read-only
   at its own path (`ServiceSpec::mount_read_only` on a job), the password in
   `MYSQL_PWD`, then `--prepare`; the entrypoint's `.my-healthcheck.cnf`, which the
   tool does not copy, taken beside it — or the restored server's probe has no user
   until the entrypoint's upgrade path recreates one. Proven on
   the catalog's image the same way: healthy under the catalog's probe,
   `mariadb-check --all-databases --extended` clean, every row; live, no prepared
   `mariadb_backup_checkpoints` — fails first. **On the lab**: `hlb upgrade mariadb
   --apply` (still 11.8: the copy runs in the server's own image), the pass in 7.7 s
   to both destinations; snapshot `88c1fb67` restored into a throwaway volume and
   started with no network: `log-applied`, the probe healthy with no upgrade run,
   Seafile's three databases with every table (13, 46, 127, as live),
   `mariadb-check --extended` 0.

   **The rest of gap 5, measured 2026-11-01** (upstream sources at the pinned tags; the
   577 compose files of Umbrel and CasaOS; the lab):
   - **Job cadence — nothing to build.** The catalog declares one job (Seafile's
     weekly gc). Of the 577 apps, 2 schedule anything more often than daily from their
     compose (Nextcloud every 5 min, FreshRSS every 30), both a cron inside the app's
     own container — a companion, not a job Homelabus runs.
   - **A step before an upgrade — nothing to build.** None of the 13 apps' upgrade
     notes asks for one within its major that its start does not do (Gitea 28.2's
     migrations, Roundcube's `initdb.sh --update` in its entrypoint, Seafile 14.0.x
     "change the image"); the copy before an update is already taken.
   - **A step after a restore — two apps.** Fluxer's message search, rebuilt by one
     call — written today as a `post-install` tip a person must remember and paste;
     Seafile's `seaf-fsck` (its binary install's doc; the Docker doc omits it, the
     start does not run it). Gitea's `regenerate hooks`/`keys` run at every start
     already; Immich's dump needs its `search_path` line handled by the restore
     itself; n8n, Termix and Vaultwarden need only their keys restored with the data.
   - **NATS copied live — safe, nothing to build.** Fluxer's `fluxer-nats-data`
     snapshot `9ea218a5` restored on deb1 (`/root/natsdrill.sh`): the live copy's
     `index.db` disagreed with its blocks ("Recovering stream state from index
     errored"), NATS 2.15 rebuilt it from the blocks — healthy, `JOBS_DLQ`'s 3
     messages there. With `index.db` gone, the last block cut mid-record, or the
     consumers' `o.dat` gone: healthy each time (an empty stream's sequence restarts
     at 0). JetStream's file store recovers from a crash's shape; a block removed
     during the copy fails the pass out loud (restic exit 3), one written after its
     listing is a copy taken earlier.
   - 🔴 **Connection budgets — any one of three apps exhausts the shared
     PostgreSQL.** 97 connections (100 − 3 reserved); 9 consumers, 2 capped by the
     catalog (Fluxer 4 × ≤ 25 by a test, Seafile on MariaDB by another). Upstream
     defaults: **Gitea unlimited** (`MAX_OPEN_CONNS` 0, `modules/setting/database.go:83`),
     **Vikunja 100** (`config.go:433`), **Roundcube one per Apache worker, 150**
     (prefork default, non-persistent); then Immich 20 fixed (2 processes × 10, no
     setting), Mealie 15 (SQLAlchemy 5 + 10, no setting), Vaultwarden 10, n8n 2. On
     the lab at rest: 16 in use. The two tests each hold ONE app to a share; nothing
     sums them, and the next app's pool is whatever its author left.
     ✅ Built 2026-11-01 (owner: "raise to 200"): `connections` on every database
     requirement, summed by `catalog validate` per server (the largest twice, for its
     update), PostgreSQL `max_connections=200`, MariaDB `--max-connections=250`; the
     role's server-side limit is twice the app's sum (`role_connection_limit`), proven
     on a real PostgreSQL to refuse the third connection of a role limited to 2. Pools
     capped in the manifests: Gitea, Vikunja, Vaultwarden 10, n8n 2, Roundcube 16
     Apache workers, Mealie one Uvicorn worker. On the lab the same day: `SHOW
     max_connections` 200 and MariaDB's 250 after `hlb upgrade postgres|mariadb`; each
     app's `hlb upgrade` re-ran its database step (its description names the limit, so
     the journal's done row did not carry over) — roles fluxer 44, immich 42, mealie
     30, vaultwarden 20, vikunja 20, MariaDB's seafile 232, all twice their sum.
   - ✅ **A `post-restore` guide phase** (owner, 2026-11-01). Never planned by an
     install; `hlb backup restore` runs its `exec` and `api` steps, in order, once each
     one's service is healthy again, says what each did, and exits non-zero when one
     did not. `validate_guide` refuses there what a restore would not read: `env`,
     `sql`, a probe, a `verify`, `after`, `blocking`. An `exec` names a companion's
     container by `service` (Fluxer's api). Seafile's `seaf-fsck` (check only) — it
     exits 0 whatever it found, so its lines are judged: on the lab, a database
     restore ran it ✓, and again with one block set aside, 🔴 "block … is missing",
     exit 1. Fluxer's search refresh moved there, judged by the job's END (the api's
     200 only says it was queued) — 🔴 and on the lab it FAILS: Fluxer 2026.1026 and
     2026.1027 initialise six Meilisearch indexes and not the threads', which the
     `all` refresh empties first ("Meilisearch adapter not initialised"), so the
     messages' index was never rebuilt — the tip a person pasted before never worked
     either, and said 200.
   - ✅ **Fluxer's message search after a restore** (owner, 2026-11-01: work around
     it AND report it). Read in the api image's source: the threads' index is made
     ready lazily, by whatever asks it first, and `all` empties it without asking. A
     `threads` refresh of one community (its id from `GET /admin/guilds?limit=1`)
     asks first, in the same worker; `all` then runs whole. On the lab: the worker
     restarted and the messages' index emptied, `all` alone fails again, the guide's
     script exits 0 and the index is back to 18. Without a community it still fails
     — nothing else readies the index in the worker. Upstream: the report is the
     owner's to post at feedback.fluxer.com; the first refresh goes once Fluxer
     readies the index before emptying it.

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
10.11.11, so nothing was proposed: 12.4 written by hand on 2026-11-01, rehearsed on a
10.11.11 volume — the SSO plugin it now carries targets 12 only. `hlb-caddy` is built here (`builtHere`): what pins it
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

- ✅ **What the first timed deployment found** — 2026-11-04, `scripts/drills/deploy.sh` on 0.4.4;
  the figures are in `docs/measures.tsv`. Answered 2026-11-05: `hlb ack` attests a step before
  the first `--apply` (`attested_ahead`), a machine reporting 7168 MB is `heavy`
  (`HEAVY_TIER_MIN_MB`), and `hlb ps` says a global service is global.
- ✅ **A node's reboot can leave a pinned service down** — seen on the lab 2026-11-05, answered the
  same day. deb2 off, its free services landed on deb1 and stayed, Swarm rebalancing nothing,
  and Stalwart, pinned to deb1 by its data, stayed Pending on "insufficient resources" until
  `docker service update --force` moved Fluxer's two largest back. Reconciliation reads it now
  (`Drift::NoRoom`, harm broken) and, applied, moves the largest free services a node can take.
  Run on the lab's Swarm 2026-11-06 with Stalwart starved on a crowded deb1: it named
  `fluxer-gateway`, Swarm put it on deb2, and Stalwart ran 30 s after the apply.
- **A bound disk waits for its TPM after power cuts, and says nothing** — measured 2026-11-06
  on enc3, which held 16 minutes in its initrd on 2026-11-05 and again on demand. Each power
  cut counts one failure in the TPM's dictionary lockout, in the initrd as on a running system;
  a clean stop or reboot counts none. The object Clevis seals is `noda`, the primary it loads
  it under is not: locked, the load answers `0x921` and Clevis loops, the Tangs answering 200
  every 6 s, nothing on the console. swtpm allows 3 failures and forgives one per 1000 s: the
  disk opened 16 min 34 s after the first Tang request. The kit's key still opens it, and
  `tpm2_dictionarylockout --clear-lockout` from the opened system resets the count with no
  authorization. The binding has no PIN, so the lockout guards no guess here, and whoever holds
  the machine can clear it from another OS. Proposed, not built: clear it after each boot of a
  bound node. A real TPM's numbers are not measured: read `tpm2_getcap properties-variable` on
  the owner's laptop first. `stolen.sh` clears enc3's count once it opens at home.
- ✅ **A task whose pull failed stays down after the failure ended** — seen on the lab
  2026-11-06 as "a Docker with no DNS", which it was not: reproduced and answered the same day on
  Docker 29.9.3. dockerd's resolver recovers within seconds, and a `docker pull` beside it works.
  A SWARM task whose pull fails on a name or a timeout stays `Preparing`, and Swarm repeats that
  one error each second without asking anything again: 333 failures, one source port. A refused
  connection or a missing tag ends the task, and its replacement recovers alone. A node booted
  before its network does it, as does any registry silent while a task starts. Restarting Docker
  cured it; so does a new task. `Drift::PullStuck` reads it, as broken, once the task has been
  there 5 minutes, and `reconcile --apply` starts a new one: run on the lab's Swarm with a real
  DNS cut, Caddy back in 20 s. Not tried on bare metal.
- ✅ **A restore stopped halfway could not be retried on NFS** — met on the lab and fixed
  2026-11-05. It left the app at 0 replicas with no data pin, so a second was refused, "runs
  nowhere". The hold records the volume's node before anything stops.
- ✅ **A catalog source's cache does not come back with the state** — seen in the same drill and
  answered 2026-11-05: the kit's step 4 fetches it, and the warning names the verb.
- ✅ **An update's prior copy held no database** — read in the code and fixed 2026-11-05.
  An app with a volume and a database was updated with its database as old as the last
  pass, across whatever migration the image runs, and one holding only a database
  (Roundcube) was refused for ever, "no known volume". The copy dumps each database now.
- ✅ **An update's prior copy took a SQLite database live and no bucket** — read in the code
  and fixed 2026-11-05. A rollback of PocketID, Jellyfin, Grafana, ntfy or CrowdSec got what
  restic read of the live files, and Fluxer's objects were as old as the last pass. The copy
  stops what writes SQLite and reads every bucket, or refuses the update.
- ✅ **Two mesh peers recorded at one address overwrote each other's tunnel** — found
  and fixed 2026-10-29: the lab's mesh still recorded `arch1`, a VM long gone, at
  10.77.0.13, and `node add` of a fresh VM there pushed arch1's WireGuard configuration
  over its own. `node add` now refuses an address another peer holds, by endpoint or
  SSH address, before touching anything, and `hlb mesh remove` takes a peer out —
  refused while it is still a Swarm node — and tells every other node. Proven on the
  lab: refused at arch1's address; the four dead peers removed, `mesh sync` succeeding
  there for the first time; the same `node add` then passing.
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
- **Bots and crawlers, done properly — later, and carefully** (owner, 2026-11-03).
  **Anubis is removed** (owner, the same day): it protected nothing — no chain of the
  catalog named it — and where it went was the catalog's choice, never the house's. The
  catalog refuses a chain naming it; a manifest frozen by an older `hlb` keeps that
  route withheld until `hlb upgrade`, and a house that installed it takes it out with
  `hlb remove anubis`. Swapping the challenger for a logo (go-away, Cerberus, a fork,
  Caddy serving other images over Anubis's) was judged too dangerous by the owner — it
  works around the problem instead of solving it. What a return must answer, read in
  Anubis v1.28.2's source the same day:
  - 🔴 Our `DIFFICULTY: "4"` was read by nobody: the built-in policy's thresholds set
    their own (a browser gets 2), and `DIFFICULTY` only fills a `CHALLENGE` rule
    without a `challenge:` block (TecharoHQ/anubis#1431).
  - The built-in policy challenges only a User-Agent matching `Mozilla|Opera`; any
    other passes, an empty one is denied. So most of the apps' proof-of-work comments
    ("No Anubis" until the removal) are a guess: git, DAVx⁵, Immich's and Jellyfin's native clients would pass; the Bitwarden
    extension, Electron apps and webview TV apps would be challenged. Measure each
    before deciding, and declare what must never be challenged by path, not by app.
  - `ANUBIS_ALWAYS_BYPASS` was a hand-maintained list of some apps' paths; they
    belong in their manifests, generated into a `POLICY_FNAME` file.
  - The store is in memory, so one replica; subrequest mode answers DENY with 200
    under the built-in policy (a pass for `forward_auth`) and reads a client-sent
    `X-Original-Uri` (the shape of GHSA-6wcg-mqvh-fcvg).
  - Phase 4: with the VPS relaying TCP, `{remote_host}` becomes the relay — the pass
    is bound to `X-Real-IP`, so PROXY protocol first.
  - A scraper's native solver outruns a browser's proof-of-work by an order of
    magnitude (`eternal-flame-AD/pow-buster`): a challenge raises the cost, it is not
    a wall. What else belongs beside it — rate limits, CrowdSec's scenarios, tarpits —
    is part of the question.
  - Left by the removal: `ingress[].chain` is gone from the apps (catalog #3) and from
    the plan, but the schema still reads it, because a frozen manifest carries it and
    `deny_unknown_fields` would refuse that manifest. It leaves the schema once no
    house can hold one, and until then a link nothing serves stays refused.

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
