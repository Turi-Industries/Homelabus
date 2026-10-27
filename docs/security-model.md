# The security model

What Homelabus defends against, what it has to trust, and what it does not protect yet.
The last part matters as much as the first: a protection you believe in and do not have
is worse than one you know is missing.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## What it defends against

### Someone on the internet

- **One way in.** Every app is `private` until you publish it. Published apps go through
  a single Caddy on the ingress node. No other container publishes a port, and Swarm's
  own ports are closed outside the WireGuard mesh by nftables.
- **A sign-in in front of apps that have none.** A portal (oauth2-proxy and PocketID)
  stands in front of every `proxy-only` app. Incoming identity headers are erased before
  the portal runs, so a forged `X-Auth-Request-User` gets nobody in. An app that no role
  is allowed into stays closed, even to people who are signed in.
- **Guessing is limited and banned.** Sign-in routes are rate-limited on the path the
  app actually routes, so `%74oken` or `//token` are counted too. CrowdSec reads each
  app's own answer to a wrong secret and bans the address that keeps trying.
- **Paths opened to anyone are written in the manifest** (n8n's production webhooks) and
  are open exactly as written: an encoded or dot-segment path is sent through the
  portal.

### A compromised app

- **It holds only its own credentials.** Each app gets its own database role, and an
  integration test proves it cannot read another app's data. On Garage it gets `read` +
  `write` on its own bucket, never `owner`, so it cannot delete the bucket its backups
  protect.
- **It runs with as little as possible.** The defaults are a read-only root filesystem,
  every Linux capability dropped, `no-new-privileges` and no published port. A manifest
  has to ask for more, and asking shows up in review.
- **What it writes to its volume is data, never code that runs.** A restore puts back
  whatever was backed up, and after an intrusion that is the intruder's copy. Gitea and
  Vaultwarden therefore read nothing executable from their volumes, and a test plants
  hostile files to check it.
- ⚠️ **All apps share one overlay network** (`hlb_platform`). One app can reach another
  app's port. Credentials keep it out, the network does not.

### A stolen API token, or a curious account

- **Every route says which role it needs, in the type of its argument.** The code does
  not compile without it, and a test walks the API to find a route that declares none.
- **Roles are read again on every request.** Taking someone's admin role away takes
  effect immediately, not when their session expires.
- **A token is stored as a SHA-256 fingerprint.** A stolen database shows that a token
  exists, not what it is.
- **Cookie-borne writes need the `X-HLB-UI` header.** `SameSite=Lax` alone does not stop
  cross-site requests. Visiting a screen never changes anything: writing needs
  `?apply=true`.
- **The metrics relay answers an allowlist of prefixes**, not arbitrary PromQL. An open
  relay would give the map of the installation to anyone with a `viewer` token.

### Whoever holds your backups

- **Backups are encrypted by restic before they leave the house.** A storage provider
  holds ciphertext.
- **Homelabus checks that an intruder could not erase the off-site copy.** With the
  credentials the cluster holds, it writes a witness to the destination, tries to delete
  that exact version, then reads it back. A destination where the delete succeeds is
  reported as not protecting anything.

### A tampered release or image

- **`hlb` is signed.** Each release's `SHA256SUMS` is signed keylessly with Sigstore by
  the release workflow. `install.sh` checks a pinned cosign against its checksum, then
  the signature against that workflow's identity on a `v` tag, then the binary against
  `SHA256SUMS`. The release workflow runs the installer on both architectures and checks
  that it refuses a `SHA256SUMS` with one line added.
- **The agent, controller and Caddy images are signed** the same way. They carry an SBOM
  and their build provenance.
- **Every app image is pinned by digest.** A deployment never falls back to a tag. An
  update waits until the new build is at least a week old, is scanned by Trivy and backed up
  before it switches, and is rolled back if the app does not come up.
- **The build itself**: GitHub Actions are pinned by commit, every workflow's token is
  read-only unless a job needs to write, the job that can push never checks the code
  out, and every run is checked by `cargo audit`, CodeQL and Scorecard.

### Someone who already has a shell

- **Reading a secret is recorded before it is shown** (`hlb secret-get`, and the
  watchdog script that carries ntfy's password). The audit log is a hash chain:
  `hlb audit --verify` detects an entry changed after the fact.
- **A secret never appears on a command line**, where every account on the node could
  read it in `ps`. A test refuses `docker run -e KEY=value` anywhere in the code.
- **A secret never enters a plan.** Plans are displayed, stored in the state and
  mirrored to Git, so secret tokens are only replaced by their values in the executor,
  at deploy time.

## What it has to trust

- **Root on any node, and the Docker socket**, which amounts to the same thing. A Swarm
  manager can run anything anywhere. No app in the catalog is given the socket.
- **The vault's master key.** It decrypts every secret and opens every backup
  repository. Whoever holds the file holds the installation, and losing it loses
  everything. `hlb emergency kit` prints what restores it.
- **The controller.** It holds the platform's administrator credentials (PostgreSQL,
  MariaDB, Garage, Stalwart, PocketID's API) so that it can provision apps.
- **The upstream projects.** Pinning a digest proves that you run the image that was
  reviewed. It does not prove that the image is honest.
- **GitHub and Sigstore** for the provenance of `hlb` and its images.

## Not protected yet

These are measured in the [roadmap](../ROADMAP.md) and closed in this order. Until then,
plan around them.

- **Disks are not encrypted.** A machine carried away from the house can be read. LUKS,
  unlocked by the node's TPM together with a Tang server on another node, is the next
  phase.
- **The vault's key is a `0600` file next to the state.** Root on the controller node
  can read it. It will be sealed to the TPM and kept in memory only.
- **Most app secrets reach their container as environment variables** (51 of them, 9
  through a `_FILE`). Anyone allowed to run `docker inspect` can read them. They are
  moving to files, and a test will then refuse a secret in `env`.
- **Your domain is not watched.** There is no DNSSEC and no alert if the registrar
  record changes. A registrar with a registry lock is recommended.
- **One maintainer.** No change is reviewed by a second person before it is merged.
