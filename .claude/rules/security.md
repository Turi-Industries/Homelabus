---
paths:
  - "crates/hlb-secrets/**/*.rs"
  - "crates/hlb-ingress/**/*.rs"
  - "crates/hlb-objstore/**/*.rs"
  - "crates/hlb-bootstrap/**/*.rs"
  - "crates/hlb-users/**/*.rs"
  - "crates/hlb-identity/**/*.rs"
  - "crates/hlb-engine/src/roles.rs"
  - "crates/hlb-controller/src/{roles,accounts}.rs"
  - "crates/hlb-controller/src/{auth,signin,promql,portal,exposure}.rs"
  - "crates/hlb-bitwarden/**/*.rs"
  - "crates/hlb-engine/src/emergency.rs"
  - "crates/hlb-backup-run/src/kit.rs"
  - "crates/hlb-controller/src/recovery.rs"
  - "crates/hlb-termix/**/*.rs"
  - "crates/hlb-engine/src/termix.rs"
---

# Security and authorization

Tokens, roles, sessions, the vault and forward-auth. A mistake here is not visible from
the outside, which is the whole problem.

- **An API token carries a ROLE, not an identity.** Enough to read state, wrong as soon
  as a request acts FOR someone: without a binding, a stolen token would create aliases
  on anyone's mailbox. An unbound `admin` token is therefore refused where a bound
  `operator` passes.
- **An authenticated role is not an authorized role.** `Role::allows` existed with no
  production caller: every handler took `_auth: Authenticated` and ignored the role.
  Authorization now lives in the TYPE of the argument (`Authorized<CanOperate>`) — the
  compiler demands it in the signature, so it cannot be forgotten.
- **A bare `403` makes you doubt everything.** It does not say whether you are on the
  wrong screen, the system is broken, or a right is missing. The refusal names the
  action, the required role, the held role and **who can grant it** — and returns `None`
  when allowed, so a refusal cannot be shown by mistake.
- **A person's role is re-read on EVERY request**, never frozen into the session. Frozen,
  removing someone's admin rights would have no effect for twelve hours — and you remove
  them precisely when you are in a hurry.
- **`SameSite=Lax` is not enough against CSRF.** Any mutating request carried by a cookie
  requires the `X-HLB-UI` header. Token calls are exempt: with no cookie there is no
  ambient authority to hijack.
- **A `Secure` cookie is NOT set at all over `http://`.** The attribute follows the
  public URL and is never hard-coded, or local development loops on the sign-in screen
  **with no error message at all**.
- **The web token goes through the URL FRAGMENT**, never the query string: a `?token=`
  ends up in access logs, `Referer` headers and every proxy.
- **An API token is never stored in clear**, not even in the vault: a SHA-256
  fingerprint is kept. A leak reveals that a token exists, not its value.
- **An `id_token` signature is not verified** — and that is correct: it is fetched by the
  controller itself over TLS, never received from the browser. ⚠️ This reasoning would
  NOT hold for an implicit flow.
- **Trusting `X-Forwarded-For` without a trusted proxy defeats rate limiting**: each
  attacker gets a fresh counter on every request, and the protection looks like it
  works. Hence `--trusted-proxy`, explicit.
- **Forward-auth must erase incoming identity headers.** Otherwise
  `curl -H "X-Auth-Request-User: admin"` is enough to impersonate an account. 🔴 And
  BEFORE the portal, which the written order does not give: Caddy sorts
  `request_header` after `forward_auth`, so the scrubbing erased the portal's headers
  too. The global `order request_header before forward_auth` does — not a `route { }`,
  which runs after every `handle` and would serve a companion's path unasked.
- **An open PromQL relay is exfiltration.** `{__name__=~".+"}` returns the whole
  database: hostnames, paths, app names — the map of the installation, to anyone holding
  a `viewer` token. Hence an **allowlist** of prefixes: you cannot enumerate what is
  dangerous, you can enumerate what is useful.
- **A missing scanner is not a green light.** `NotChecked` is distinct from `Clean`:
  treating "trivy absent" as "nothing found" disables the check while looking like it ran.
- **`sshd` SILENTLY ignores `authorized_keys`** if it is group-readable, or if `~/.ssh`
  is. The key looks installed and nothing works.
- **CrowdSec only goes where the client's own address is seen.** Behind another proxy
  it sees that proxy, and bans it on the first attacker. One Caddy is the ingress, its
  ports published in host mode so the address survives.
- **🔴 Docker's userland proxy hands Caddy a private address for every IPv6 client.**
  Its ports are host-mode on `docker_gwbridge`, IPv4 only: `docker-proxy` carried an
  IPv6 connection in and Caddy saw the bridge's gateway (`172.18.0.1`) — inside
  `172.16.0.0/12`, so a private route answered the internet, and CrowdSec (which
  whitelists private addresses) judged no IPv6 client. Decided 2026-10-26: the cause
  goes, not the symptom — the `daemon.json` Homelabus writes says `"userland-proxy":
  false` (the kernel's DNAT keeps the client's address; IPv6 then reaches no IPv4-only
  container at all, which is closed, not open), and an existing Docker that leaves it
  on is warned at `node add`. Taking the gateway out of the private ranges was not
  chosen: its subnet differs per node, and a CIDR list with a hole punched per node is
  one more thing to read from every machine.
- **Caddy's admin API has no authentication.** On `0.0.0.0:2019` it listened on the
  overlay, where any app could load a Caddyfile routing every other app's traffic —
  sign-ins included — through itself. The Caddyfile is delivered as a file (a Swarm
  secret named after its content, `Orchestrator::reconfigure`); the admin API listens
  on `localhost`, for the probe. A test refuses `0.0.0.0:2019` in the output.
- **The internal authority's root is Homelabus's, ECDSA**, in the vault
  (`ingress-root`), under an authority named `homelabus` — never Caddy's `local`, whose
  certificates kept the root it had generated. Not the cluster CA: ed25519 is refused
  by browsers in a TLS chain, and `pathlen:0` forbids the intermediate Caddy signs.
- **🔴 A short certificate nobody renews is an outage with a date.** The fleet's mTLS
  leaves live 90 days and nothing renewed them: day 91, every agent refuses the
  controller. `hlb_engine::pki::Renewal` (the controller nightly, `hlb pki renew`)
  reissues 30 days ahead through `reconfigure`. A Swarm secret cannot be read back, so
  each leaf's end is the state's (`pki-leaf:<service>`, written at issue); the
  controller's own is read from its file — after a rollback the state would lie. The
  controller's image needs `openssl` for it.
- **A sign-in route is limited where Caddy reads the path the app routes.** `path`
  matches the decoded, cleaned path, without case: `%74oken`, `//`, `TOKEN` are all
  counted (`hlb-ingress/tests/rate_limit_fires.rs`, on the real image — `caddy
  validate` accepts a limit that never fires). The global `order rate_limit before
  basic_auth`; a sibling installation's `before reverse_proxy` fell behind the `handle`
  around its proxy, and none of its limits ever ran.
- **A refusal CrowdSec counts can ban the victim.** Its generic brute-force scenarios
  ban five POSTs answered 401 or 403 in ten seconds: a cross-site write refused in 403
  would have banned the visitor whose browser another page made send it. The refusal
  is `log_skip`ped; a probe a browser was made to ask for (`Sec-Fetch-Site:
  cross-site`) too. Cross-SITE only: apps on one domain may write to each other.
- **What an app answers a wrong secret is its own.** Vaultwarden 400, Vikunja 412,
  most 401, Gitea and Seafile's web form a 200 — which only the limit bounds. Caddy
  marks the line (`hlb_auth`, `hlb_auth_fails`) and `homelabus/auth-failures` compares;
  a scenario keyed on 401 never saw a Vaultwarden guess. Both names are held on both
  sides by a test. ⚠️ CrowdSec whitelists private addresses: `cscli explain` with a
  lab's line says "whitelisted", not "no match".
- **The access log keeps what CrowdSec reads and nothing that opens a door.** Every
  request header (tokens, cookies), the query string (an OIDC `code`, a reset link),
  a response's `Set-Cookie` are filtered out; `client_ip`, method, path and status
  stay. CrowdSec reads a missing header as absent — the cost is the User-Agent and the
  arguments its SQL-injection and XSS scenarios read.
- **A preview never prints a credential.** The Caddyfile carries the DNS provider's
  token and the bouncer's key: `hlb ingress` prints `Config::redacted()`.
- **A secret must never enter a plan.** The plan passes through `hlb plan` (display), the
  SQLite state (recording) and the Git mirror (export with history). Secret token
  substitution therefore happens in the executor, at deploy time. `{{ db.url }}` counts
  as a secret despite looking like an address: it contains the password.
- **An unresolved token stays literal, never empty.** An empty variable looks like
  missing configuration: the app complains about a bad password and you go looking at the
  password. `{{ db.password }}` in the logs points at the real problem.
- **The vault is NOT the source of truth for a password.** Rotating it there alone
  changes nothing: PostgreSQL keeps the old one, the container keeps the old one in its
  environment, and everything keeps working — until the next redeploy, where the app
  fails on "incorrect password" with nobody connecting it to a rotation three weeks
  earlier. A rotation is an ORDERED PROCEDURE.
- **An app never owns its S3 bucket.** `read` + `write`, never `owner`: as owner, a
  compromised app could delete its own bucket — erasing what the backups protected.
  ⚠️ Not owning it does not keep it from EXPIRING it: Garage 2.4.1 takes a lifecycle
  rule from a read-write key (measured, `hlb-objstore/tests/live_garage.rs`) — no more
  than deleting each object, which writing allows, but a bucket's backup is what
  answers either, never the grant.
- **Garage NEVER returns a secret key twice.** `CreateKey` gives it once; `GetKeyInfo`
  returns null afterwards. Idempotency therefore cannot rest on "does the key exist?" —
  the vault is authoritative, or a resumed run starts without a secret and the app fails
  on an "invalid signature" that points nowhere.
- **🔴 A recovery sign-in is proven by signing in, every night.** Seafile's lab ran on
  the image's own `me@example.com` / `asecret`: it began before `INIT_SEAFILE_ADMIN_*`,
  which the image reads at its FIRST start only, so the vault's password — deposited in
  the emergency vault — opened an account that did not exist, and the admin anyone could
  guess stayed. Grafana reads its administrator's password the same way. Each
  `recovery:` carries a `proof` (one POST on the overlay, JSON or HTTP Basic, a pointer
  the answer holds once signed in), required by the catalog and checked against the six
  real images; it is an assertion like the others (`recovery:<secret>`). A refusal is
  NEVER tried again by the nightly pass — Jellyfin disables an administrator after five,
  Stalwart bans the address — only by a person's `hlb assert`. Optional when read: a
  manifest frozen before proofs reads as "not read", `hlb upgrade` named.
- **Homelabus can verify few of the access safeguards** — the recovery drill, the
  emergency vault's verified deposit, a kit printed with today's material
  (`hlb_api::breakglass::proof`): it does not know how many passkeys exist or whether
  the codes are printed. So it asks for a dated attestation and expires it — and a point
  it *can* prove is not attestable by hand, or you would paint the most important
  safeguard green with no drill having happened. `verifiable` and a proof go together,
  by test.
- **A package named `docker` is not Docker.** On Debian and Ubuntu it is a tray applet,
  and the distribution's `docker.io` is 20.10 on Debian 12, below the floor. Docker
  comes from Docker's repository where it publishes one, with its signing keys COMPILED
  IN (`hlb-bootstrap/keys/`, fingerprints in `docker.rs`): a key downloaded at install
  time trusts whatever answered that day. `get.docker.com` is never used. An existing
  Docker below the floor is REFUSED, not replaced — it was not ours.
- **Rootless Docker cannot run Swarm**: no overlay networks. Containers run unprivileged
  through the manifest defaults instead.
- **The engine stays out of unattended upgrades.** Upgrading it restarts every task on
  the node, and the timer fires at the same hour on every node — the whole cluster,
  managers included, restarts at once. Same for Ubuntu's `needrestart`. No unattended
  reboot either: a reboot drains nothing. `hlb node upgrade` does both, one node at a
  time.
- **Probe what a package installs, not its name.** `wireguard-tools` installs `wg`,
  `ca-certificates` no binary at all, and `restic` refuses `--version`: probed by name,
  each read as missing on every run. `dpkg-query` succeeds on a REMOVED package whose
  configuration remains — read the status. And the clock needs ONE client: chrony next
  to a running systemd-timesyncd is two daemons fighting over it.
- **The vault's default path is relative to where `hlb` runs.** From another directory
  it was created anew, empty, and the next command worked on it without a word. Only
  `cluster init` creates it at the default; a path given explicitly may be created;
  a new key beside an existing state is refused always (`open_vault`, held by
  `hlb-cli/tests/vault_guard.rs`).
- **A preseeded machine is reached as root, by key.** `node add` connects as root and
  `homelab` has no password to sudo with: with the key on `homelab` alone, the machine
  could join nothing. And a preseed fetched over the network arrives after `netcfg`: the
  hostname is written in `late_command`, or every machine is called `debian`.
- **A new node's host key is accepted once, never a changed one.** BatchMode alone
  refused every fresh machine; `StrictHostKeyChecking=accept-new`, never `no`.
- **One portal, one OIDC client.** oauth2-proxy signs in for every `proxy-only` app
  with its own client; each app adds `https://<app>/oauth2/callback` to it
  (`AddPortalCallback`). A client per app was never used and its callback never
  accepted. And `{{ oidc.client_id }}` is PocketID's generated id, read from the vault —
  the app's name was there and is not one.
- **The host's hardening never touches what the cluster routes with.** Forwarding,
  bridges and `rp_filter` are Docker's, Swarm's and the mesh's: a strict `rp_filter`
  drops VXLAN replies arriving through WireGuard. `hlb_bootstrap::host` writes its own
  `90-homelabus.conf`, applied with `sysctl -e` — a key the kernel lacks (Yama) is
  skipped, where both procps and BusyBox would stop on it — and a test reads every key.
- **Name `iptables-nft` on the RPM side.** With EPEL enabled, dnf satisfied Docker's
  `iptables` with `iptables-legacy`, and the daemon failed on the `nat` table (Rocky 9).
  And read a hostname from `/proc/sys/kernel/hostname`: the `hostname` binary is
  absent from a minimal Rocky.
- **`pacman -Sy` then install is a partial upgrade**, which Arch does not support. `-Syu`.
- **Swarm's ports are closed outside the mesh by nftables, not by advertising.**
  `--advertise-addr` tells nodes where to talk; the kernel still accepts VXLAN (4789,
  no authentication) on every interface. The rules load with the interface (`PostUp`),
  `policy accept` and four ports only, so a mistake cannot cut SSH. And
  `--listen-addr` on init and join, or 2377 listens on `0.0.0.0`.
- **A sealed vault key's path is a LINK into memory** (`hlb secrets-seal`,
  `hlb_bootstrap::seal`): `/run/credentials/hlb-vault.service/`, a `ramfs` that exists
  while the unit is active. `Path::exists` follows the link, so a key not yet unsealed
  read as no key and a new one would have been made: `hlb_secrets::key_present`. And a
  rekey's `mv key key.old` would move the link — `.old` pointing at memory that the
  reseal empties — so a sealed key is COPIED out first.
- **🔴 Measure the TPM binding, never assume it.** systemd 252 (Debian 12) seals with
  `--tpm2-pcrs=` (no PCR) and then refuses to unseal it ("PCR bank invalid"); Debian
  ships no TSS libraries, so `has-tpm2` says `+driver` and every seal fails "TPM2
  support not installed" (`tpm2-tools` pulls them in); SeaBIOS answers `-firmware` over
  a TPM that seals fine. `hlb secrets-seal` seals and unseals a throwaway value per
  binding and keeps the first that comes back. Sealing is refused until the emergency
  kit is current: sealed, the key dies with the board.
- **Swarm's unlock unit must NOT remain active** (`hlb_bootstrap::unlock`). Docker's
  next start pulls it in through `WantedBy=docker.service`, and a start job on an
  active unit runs nothing: a restarted daemon would stay locked behind a green unit.
  As a plain `oneshot` it reruns on every start — a restart, a crash, a boot (measured
  on deb1) — and its credential directory is gone once the unlock returns. Its key is
  sealed per manager: Swarm's key is the cluster's, a TPM is the machine's. A manager
  `node add` joins into a locked cluster is sealed in the same run, or refused at
  preview: unsealed, it runs until its first restart and then stays locked. And
  `docker node demote` tells nobody: `cluster autolock` visits the workers too, and
  takes back a copy left on one.
- **`COPY . .` sends the master key to the daemon.** `web/hlb-master.key` exists; the
  `.dockerignore` refuses `**/*.key` first.

- **A generated password has a lower-case letter, an upper-case one and a digit.**
  n8n refuses an owner's password without a digit, and one 32-character draw in three
  hundred has none: an install failing once in a while, on a reason nobody reproduces.
  `generate_password` draws again until it qualifies.
- **`hlb secret-get` writes the audit entry BEFORE it prints.** A reading that leaves no
  trace is the one an intruder with a shell makes; the value never enters the log.
- **The catalog's ntfy is `deny-all`, its accounts declared.** Its default was
  read-write for anyone on a guessable topic: anyone read the alerts, or forged one. The
  passwords are generated and handed to ntfy as bcrypt (`{{ secret.x:bcrypt }}`, its
  salt derived from the password so the hash — and the service — does not change at
  every deployment). The controller publishes as `homelabus`, the deadman's script as
  `watchdog`, its account given to curl on stdin (`-K -`), never as `-u`.

- **A role is data, and its id is a PocketID group's name** (`hlb-<id>`), written into
  every app's restriction: it never changes once created. The four LEVELS stay
  `hlb_types::Role`, and a role's level is what `Authorized<…>` reads — re-read on every
  request through `users.role`. A role id naming no role reads as no role at all.
- **🔴 A PocketID client NOT restricted lets everyone in, whatever groups it lists**;
  turning the restriction off CLEARS its groups, and restricted with no group it lets
  nobody in (2.18, `oidc_service.go`). `restrict_client` writes the groups first, then
  the flag — the other way round shuts out whoever is signed in between the two calls.
- **🔴 oauth2-proxy's `allowed_groups` left EMPTY is everyone signed in**
  (`checkAllowedGroups`, v7.15.3). A route behind the portal whose app lets no role in
  answers 403 in Caddy and never asks the portal. The portal asks PocketID for the
  `groups` scope, without which no session has a group; and refreshes every five
  minutes, or a role taken away kept the door open for the cookie's week.
- **An app no role is allowed into is CLOSED, and a role named that does not exist
  closes it too** (`hlb_users::access`): "the others still get in" is not what whoever
  typed the role decided. An app's `access.floor` keeps lower roles out whatever is
  asked — Termix, every machine's SSH access, is `admin`.
- **PocketID gives custom claims with the `profile` scope only, to EVERY app the person
  signs in to**, a person's own beating their group's. Two manifests may not write one
  claim (`catalog validate`). An app is told only through the groups of the roles it
  lets in, so a claim it requires (Gitea's `hlb_gitea`) refuses the others even were the
  restriction lifted by hand.
- **🔴 Never a `null` claim.** PocketID 2.18 answered 500 building an ID token with one
  (its own preview: "field is <nil>") — and a person's claims reach every app: one quota
  "none" written as `null` could shut them out of all of them. "None" is the app's own
  write (`apply`).
- **Giving a role says what it opens**: the ADMIN level, and each installed app it
  administers (`access.admins` in the manifest, `hlb_users::access::opens`) — before it
  is given, in the CLI, the route and the invitation form.

- **The emergency vault's account sees one collection, as a `User`** — what it reads, a
  compromised controller reads; Homelabus already holds what it deposits, so that is
  nothing new. An Owner, an Admin, a Manager or one more collection is REFUSED before
  anything is written (`hlb_bitwarden::emergency::check`), and the safeguard withdrawn
  that night. Homelabus never holds an owner's master password.
- **🔴 Vaultwarden's two-step policy exempts owners and admins** (`two_factor/mod.rs`,
  1.37.1): the accounts that matter most are the ones it never removes. Hence the
  SQL assertion over EVERY account, not the policy alone.
- **🔴 A confirmed member signing in by password WITHOUT a second factor is revoked**
  where the organisation requires one (`twofactor_auth` → `enforce_2fa_policy`), and an
  owner cannot confirm one while the policy is on. Homelabus therefore gives its
  account a TOTP factor — its secret kept in the vault BEFORE it is turned on — at its
  first sign-in, before an owner confirms it; afterwards it signs in by API key, which
  asks no second factor.
- **The server decrypts nothing, and checks nothing it is handed.** A malformed key is
  stored and fails in the next client. Bitwarden's client cryptography lives in
  `hlb_bitwarden::crypto`, its derivation held to vectors computed apart (Python's
  hashlib), and what it writes read back by the official CLI. The official CLI is not
  used: 2026.8.0 crashes on Vaultwarden 1.37.1 as soon as an organisation has a policy
  (`Policy.toSdkPolicyView`: no `revisionDate`) — a nightly deposit through it would
  have stopped on the night the two-step policy was turned on.
- **🔴 Vaultwarden 1.37.4 refuses an item without `encryptedFor`** — the writing
  account's id, checked against the token — on create AND on rewrite, with a bare 422
  (a parse failure: no message). The pin moved and every deposit failed; only
  `live_emergency` said so. `Session::create`/`update` add it to whatever they write.
- **An item Homelabus did not make is never touched**: only one carrying its
  `homelabus` field is. One it cannot decrypt is set aside and said, never a failure
  of the whole deposit — a newer client's format must not stop every night's.
- **The emergency kit prints what restores the vault, and stops counting when that
  changes.** Its fingerprint covers the master key by its PUBLIC half, the repository's
  password and each destination's credentials; the safeguard counts a kit only while the
  fingerprint printed is today's. Written with `create_new` and mode 0600, never over a
  file, audited before it is shown, and counted only once written — attested first, a
  full disk left the safeguard green over a kit nobody held.
- **`hlb secrets-rekey` never races the controller.** It holds the old key in memory and
  writes secrets under it: refused while its Swarm service runs, `--apply` requires
  `--controller-stopped` for one run by hand, and the rewrite is a compare-and-swap
  under `BEGIN IMMEDIATE` — a secret stored or rotated since the reading refuses the
  whole rekey (`Error::VaultChanged`) rather than staying under the old key.

- **🔴 Termix hands a shared host's key to every member who asks.** Shared to
  `connect` with the owner's sign-in (`shareSshAuth`) — the only way a member opens
  the host at all — and `/host/db/host/{id}/local-connection-auth` answers the private
  key (2.9.2, for the desktop app's own connections). What keeps it useless is each
  node's `from=`: Termix's node's address — and on that node's line ONLY, the subnet of
  `docker_gwbridge`, which a container's connection to its own host comes from. Every
  node's bridge has the same default subnet: on every line, it let a container of any
  node open its own host with the key, and the end-to-end test said nothing until it
  tried from there.
- **Termix's first API key takes an administrator's session**, and with sign-up and
  password sign-in closed nothing else makes one. A person hands one over once
  (`hlb termix connect`, on standard input); it makes Homelabus's own account
  (`homelabus`, local, its password drawn and kept nowhere) and its own key, then is
  deleted.
- **The account Termix reaches a node as has no right beyond a shell** — no `sudo`, no
  `docker` group, both root by other names. Homelabus never writes `sudoers`.
- **A locked account refuses every key where sshd reads the lock itself.** Alpine's
  sshd has no PAM; `adduser -D` writes `!`, and the key in place is answered "account
  is locked". `*` opens nothing by password and leaves keys alone. And `AllowUsers`
  or `AllowGroups` shut a new account out without a word: the node job reads
  `sshd -T` and says so.
- **Termix gives a key back without its final newline**, and `ssh` refuses such a file
  saying only "error in libcrypto". The emergency vault's item says to add it.

- **What a volume holds is data, never what the app runs.** A restore writes back the
  backup, and after an intrusion the backup is the intruder's. Filtering the restore
  guards one way in; reading nothing executable from the volume guards all of them —
  restic by hand during an outage included. Gitea's start rebuilds `app.ini` from its
  environment, removes `custom/`, `.gitconfig` and `authorized_keys`, empties every
  repository's `hooks/` and keeps its config to an allowlist (`core.hooksPath`,
  `commondir` and `include.path` point git elsewhere); Vaultwarden's `CONFIG_FILE` and
  `TEMPLATES_FOLDER` are outside `/data`. `hlb-catalog/tests/volume_decides_nothing.rs`
  forges both volumes on the pinned images.
- **🔴 Gitea's image leaves `SECRET_KEY` empty, and 1.27.3 then encrypts with a constant
  in its source** (`!#@FDEWREWR&*(`, `modules/setting/security.go`): second factors,
  Actions secrets. Its four keys come from the vault (`JWT_SECRET` and `LFS_JWT_SECRET`
  as `{{ secret.x:base64url }}`, 43 characters, which Gitea refuses to start without).
  ⚠️ NOT the sign-in source's client secret: `login_source.cfg` holds it as is (read
  back on 1.27.3, 2026-10-19).
- **A secret never reaches a command line — Gitea's `--secret` included.** Its CLI takes
  a sign-in's secret no other way, and an argument is readable in `ps` by every account
  of the node (`hlb-termix`'s among them). The start writes the source without it
  (`update-oauth` without `--secret` keeps what is there), and the guide's `sql`
  automation writes it: one `UPDATE`, its values BOUND (`$1`), a probe read in the same
  transaction and the write rolled back unless it holds, the app restarted. A token in
  the statement itself is refused by `validate_guide`: a statement may be logged.
  🔴 `docker run -e K=V` is a command line too: restic's password, S3 secrets and the
  dump passwords went that way beside comments saying "never on the command line".
  `-e K` with the value in the client's environment (`hlb_backup::docker_env`), and a
  Swarm job gets files, never variables; `hlb-types/tests/argv.rs` refuses another `-e`.
- **A path opened to anyone is the manifest's, said there** (`ingress[].openPaths`):
  past the portal, the private ranges and Anubis — never the bouncer. `forward_auth`
  takes a matcher excluding those paths, since Caddy orders it before every `handle`;
  the private ranges' 403 excludes them too. Only n8n's production webhooks
  (`/webhook/*`); the editor's `/webhook-test/*` stays behind the portal. ⚠️ `path`
  matches the CLEANED path and the app gets the raw one: `/rest/x/..%2F..%2Fwebhook/a`
  matched. An open path is open only as written (`caddyfile::UNCLEAN_PATH`, read on
  `{http.request.uri}`: an encoded `/`, `\` or `.`, or a dot segment, is gated).

- **🔴 A first-run token can outlive the first run.** Fluxer writes a setup token in its
  log until an administrator is BOOTSTRAPPED, and the registration presenting it
  becomes one, past closed sign-ups. `FLUXER_INSTANCE_SETUP_CONFIGURED` hides the setup
  screen and closes nothing: the token was still "unused" after the role sync had made
  an administrator (the lab). The api's configuration sets `app_public.setup.configured`,
  which claims the bootstrap and burns the token, and its own token is the vault's
  (`FLUXER_SETUP_TOKEN_FILE`), so none is ever written to a log Homelabus shows.

- **A secret reaches a container as a file, never through its environment** —
  `docker inspect` shows a service's environment to anyone who reads the Swarm
  (`catalog validate` refuses one, by `hlb_types::binding::carries_secret`). A `files:`
  entry `content: "{{ token }}"` on ONE quoted line: Swarm mounts it 0444, as written.
  🔴 PocketID's `ENCRYPTION_KEY_FILE` and oauth2-proxy's two `_FILE`s keep a final
  newline — one more byte decrypts nothing / a 33-byte cookie secret. 🔴 Garage refuses
  a 0444 secret file without `allow_world_readable_secrets`. Vaultwarden, Vikunja, n8n
  and Fluxer stop or misread when a variable AND its `_FILE` are both set. An image
  reading its environment only (Stalwart, Termix, Bulwark's admin, Seafile) is started
  by `sh -c 'X=$(cat /run/secrets/x) exec <its Entrypoint and Cmd>'`. ⚠️ A `docker
  exec` — a job, `access.quota.apply` — gets the SERVICE's environment, not the
  process's: it reads the file itself (Seafile's gc and quota). 🔴 Fluxer's push and
  media proxy resolve EVERY `FLUXER_*_FILE` they are given, so each companion names
  only the files it mounts — and `catalog validate` refuses a `/run/secrets` path named
  in an environment that the container does not mount.
  LiveKit takes its whole configuration as a file (`--config`), never `key_file`,
  refused when readable by all; Meilisearch a TOML holding `master_key` alone
  (`MEILI_CONFIG_FILE_PATH`), its variables winning over the rest.

## Invariants, encoded in tests

- **Secure by default.** `read_only_rootfs`, `cap_drop: [ALL]`, `no_new_privileges`, no
  published ports, `private` exposure. Defaults go the safe way.
