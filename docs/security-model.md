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

### Someone who carries a machine away

- **Its disk opens only at home.** A node installed with `hlb node preseed --encrypt`
  and bound by `hlb node bind-disk` opens its disk with its TPM AND one of the house's
  Tangs, on up to three other nodes. Out of every Tang's reach it waits for the
  emergency kit's recovery key; in another machine its disk opens with nothing.
- **Where the firmware allows it, nobody inside the house alters its boot either.**
  With Secure Boot, a TPM and systemd 257, `hlb node verify-boot` boots a kernel image
  signed by the node's own key and seals the disk to the measurements that image
  produces. GRUB, a changed initrd or command line, or a root swapped in after the
  initrd opens nothing. Every new initrd is resealed before the next reboot, and so
  is every Secure Boot variable a db or dbx update writes; a missed reseal makes that
  boot wait for the kit's key, it never opens more. A firmware that lost its keys
  boots without Secure Boot and waits for that key too — and nothing is sealed to such
  a boot until the keys are restored. Once booted, the kernel's memory is kept from
  root (lockdown in `confidentiality`) and devices reach memory only through the IOMMU,
  both on the signed command line. The firmware's own password, and USB and network
  boot turned off, are yours to set: `verify-boot` lists them, it cannot read them.
  A board shipped with a test platform key (PKfail: "DO NOT TRUST - AMI Test PK",
  its private half public) is said by `node check`: anyone with a root shell can
  rewrite its boot's keys. The seal holds — the disk then waits for the kit's key —
  but that prompt, after a reboot nobody explained, is the attack. A revocation list
  (dbx) behind LVFS's is said beside it: a revoked boot manager still boots, though
  the TPM, which records the entry that verified it, opens nothing to it.
- **A storage node's pool opens with its own key.** `hlb storage encrypt` encrypts its
  datasets under a key kept in the vault and on the emergency kit; at boot they are
  unlocked before Docker and the NFS server start, and without the key neither starts —
  nothing is written beside a locked volume. The pool's disks taken alone, in this
  machine or another, give nothing without that key.

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
  update waits until the new build is at least a week old, is scanned by Grype and backed up
  before it switches — refused when it brings a critical or exploited flaw the running
  image did not carry — and is rolled back if the app does not come up.
- **An image whose publisher signs it is held to that signer.** The catalog names the
  GitHub workflow that signs Vikunja, Stalwart and Meilisearch (`signedBy`); an update
  to a digest it did not sign — unsigned, or signed by anyone else — is refused. Most
  publishers sign nothing (40 of the 50 images measured on 2026-10-30): for those, the
  digest pinned in the catalog is the only guarantee.
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
- **The daemon, `hlb-privd`.** It holds the platform's administrator credentials
  (PostgreSQL, MariaDB, Garage, Stalwart, PocketID's API) so that it can provision
  apps, and Docker's socket.
- **The upstream projects.** Pinning a digest proves that you run the image that was
  reviewed. It does not prove that the image is honest.
- **GitHub and Sigstore** for the provenance of `hlb` and its images.

## What no protection level covers

A node's level (`hlb node protection`: A, a verified boot; B, the disk bound to the TPM
and the house; C, no TPM that seals; D, a virtual machine) says what a machine carried
away, or a boot altered, gives up. It says nothing about a machine that is running:

- **A flaw exploited in a running service, or in Homelabus.** Once booted the disk is
  open, and an intruder in an app holds what that app holds. The daemon holds
  Docker's socket, which is root on its node: a flaw in the daemon is root. What the
  network reaches is the web side, `hlb-controller`: its own uid, no capability, the
  state read-only, no key and no socket but the daemon's, which answers that uid only
  and only with intents. A flaw there reaches what a signed-in person's intents can
  do, not the node.
- **The firmware itself.** Secure Boot starts after it; a firmware rewritten underneath
  measures what it likes. Only Intel Boot Guard or AMD Platform Secure Boot, fused at
  the factory, verify it — Homelabus can neither set nor read either.
- **Whoever runs the hypervisor**, a VPS's provider included. It reads the machine's
  memory and its virtual TPM, which is why every virtual machine reads D.

What leaves the house is covered whatever the level: backups are encrypted before they
leave.

## Not protected yet

These are measured in the [roadmap](../ROADMAP.md) and closed in this order. Until then,
plan around them.

- **A disk is encrypted only where the node was installed so.** An existing node is
  drained and reinstalled to get there. A bound node without Secure Boot, or on
  Debian 12, verifies no boot: whoever has it inside the house, a Tang answering, gets
  a root shell at boot. A virtual machine's host reads its memory whatever is bound.
- **A storage node's dataset key is a file on its root disk.** Where that disk is not
  encrypted, the whole machine carried away opens its pool. And a volume encrypted
  after the fact leaves its plain blocks on the disks until ZFS writes over them.
- **The vault's key is a `0600` file next to the state until you seal it.** `hlb
  secrets-seal` seals it to the node's TPM and keeps it in memory only; root on that
  node can still read it there, and a node carried away whole unseals it at boot until
  its disks are encrypted.
- **Swarm keeps its Raft keys in clear on every manager** unless autolock is on. `hlb
  cluster autolock` then seals the unlock key to each manager, over the SSH address the
  mesh recorded, and each unlocks itself after every start of Docker; a manager
  joined by hand, with no address recorded, waits for a person and the kit's key.
- **Your domain is watched, not protected.** `hlb domain` reads its name servers, DS,
  DNSSEC validation and CAA from a public resolver, and its registrar, locks and
  delegation over RDAP; once a reading is accepted, a change is a critical alert the
  next night. It tells you of a theft, it does not prevent one, and many ccTLDs
  (`.eu`, `.de`, `.io`, `.ch`) publish no RDAP — there only the DNS half is read.
  Homelabus signs no zone yet. A registrar with a registry lock is recommended.
- **A CAA naming the house's accounts is yours to publish.** Homelabus reads Caddy's
  and Stalwart's Let's Encrypt accounts and says the exact `accounturi` lines; a CAA
  refusing one of them is a critical alert, since its certificate would stop renewing.
  Pinned, a certificate for your names needs one of those accounts' keys — not just
  control of a name for a minute. Caddy asks Let's Encrypt alone, with no fallback to
  ZeroSSL, whose account could not be pinned before it exists.
- **One maintainer.** No change is reviewed by a second person before it is merged.
