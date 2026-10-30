# The `hlb` command tour

Every verb, with a runnable example. This file is reference: it is read when you need a
command, not carried into every session. `hlb <verb> --help` is always authoritative —
what this file adds is which verbs exist and what each one is *for*.

⚠️ **Most of these need state and a vault**, and fail confusingly without them. To try
things without touching a real install:

```sh
export HLB_STATE=/tmp/try.db HLB_MASTER_KEY=/tmp/try.key
```

🔴 **Preview is the default, everywhere.** A command changes nothing until `--apply`.
The two exceptions are declared and locked by a test — see "Configuration routes have no
preview" in [`.claude/rules/interface-api.md`](../.claude/rules/interface-api.md).

## The catalog and a plan

```sh
./target/debug/hlb catalog validate
./target/debug/hlb order
./target/debug/hlb plan gitea --domain git.example.org
```

## Installing and running an app

```sh
./target/debug/hlb install valkey            # preview
./target/debug/hlb install valkey --apply    # real execution

./target/debug/hlb scale gitea 3             # --apply; zero is refused
./target/debug/hlb stop gitea                # 0 replicas, everything else kept
./target/debug/hlb remove gitea --confirm gitea --apply
```

`scale ... 0` is refused on purpose: scaling to zero is a shutdown, not a resize, and
`stop` is the verb that says so.

An installation runs the manifest frozen when it was installed. When the catalog
changes, `upgrade` brings it along — images excepted, which `hlb update` moves after its
backup:

```sh
./target/debug/hlb upgrade                   # which installed apps the catalog changed
./target/debug/hlb upgrade vikunja           # the differences, and the plan
./target/debug/hlb upgrade vikunja --apply   # services updated in place
```

A change that would strand data — a volume changing tier or disappearing, a database or
a bucket renamed, a companion dropped — is refused, with what to do instead.

An image moves with `hlb update`: a newer build of its tag, a later version its channel
allows (never a major), or the image the catalog moved to. Each is dated by its build and
held until it is a week old — two for Vaultwarden and PostgreSQL (`maturationDays`) —,
scanned at the digest that will run, deployed after its backup, and its outcome notified
by the controller, success included:

```sh
./target/debug/hlb update check              # what each installed app could move to, and when
./target/debug/hlb update apply gitea        # backup, then the switch Swarm rolls back on failure
./target/debug/hlb update apply gitea --before-maturity   # an urgent fix; audited
```

A companion the catalog moved — Immich's machine learning — moves with its app and
before it, in the same `update apply`; one that does not come up leaves the app as it
was.

The catalog's own images are pinned by digest, and moved by the same rules — the newest
mature build of each image's tag shape within its major, the digest the tag names when
it is written. A major is only said: a person rehearses it on a restored copy first.

```sh
./target/debug/hlb catalog images            # what each image could move to; reads the registries
./target/debug/hlb catalog images --apply    # writes tag and digest into the manifests
```

⚠️ Docker Hub answers an anonymous address 100 manifest reads an hour, then refuses
everything until the hour has passed: a pass over the whole catalog spends about 15.

What a deployment computes rather than the manifest declares — the root an app signing
in through PocketID trusts, a secret's value — reaches a running app when it is deployed
again, its manifest unchanged. `hlb config exposure` does it for the apps a new root
concerns:

```sh
./target/debug/hlb redeploy gitea            # the plan, from the frozen manifest
./target/debug/hlb redeploy gitea --apply    # services updated in place
```

What a manifest says must stay true — sign-up closed, a default administrator absent —
is read from the running app every night, into the inbox: its own public endpoint, the
environment its task was started with, a read-only query on its own database. Each
recovery sign-in the emergency vault holds is signed in with too, and one that does not
hold says what to do. A refused sign-in is tried again only from here — some apps lock an
account after a few refusals, so the nightly pass keeps the refusal. Read it now, and
record it:

```sh
./target/debug/hlb assert                    # every installed app; exits 1 on a door open
./target/debug/hlb assert vaultwarden
```

What an app needs done on a schedule — Seafile's weekly garbage collection — is declared
in its manifest and run in its own container by the controller when it is due; a failed
run is in the inbox. List the jobs and their last run, or run one now:

```sh
./target/debug/hlb job                       # every installed app's jobs, and their last run
./target/debug/hlb job seafile gc --apply    # now, wherever Seafile runs
```

An administrator's password Homelabus generated — for when an app's SSO cannot sign
anyone in — is printed by one verb, and the reading goes to the audit log:

```sh
./target/debug/hlb secret-get seafile-admin-password
```

The same passwords, where an owner finds them when PocketID is down: Vaultwarden's
"Server" collection, written as a member an owner invites once — the command lists their
steps, gives the account its own second factor, and verifies what it was given before
depositing anything. The controller runs it every night.

```sh
./target/debug/hlb emergency vault --address homelabus@example.org   # preview; --apply
./target/debug/hlb emergency vault --apply   # after each owner step: verifies, then deposits
```

What restores the vault itself cannot live in it: the master key, the backup
repository's password and each destination's credentials go on a sheet to print, with
the restic commands that bring the state back. Recorded in the audit log; a rekey or a
new destination makes the printed one stale, and the recovery screen says so.

```sh
./target/debug/hlb emergency kit --out /tmp/kit.txt   # print it, then delete the file
```

Termix gets every node: on each, an account `hlb-termix` with no right beyond a shell,
and a key Homelabus generates, accepted from Termix's own node only; in Termix, a host
per node shared with the administrators. Termix lets no program make its first API key,
so an administrator hands one over once — read on standard input. The controller syncs
every night: a node that joined appears, one that left is removed.

```sh
./target/debug/hlb termix connect --apply   # paste an administrator's API key
./target/debug/hlb termix sync              # preview: reads every node, writes nothing
./target/debug/hlb termix rotate --apply    # a new key, Termix never shut out
```

## Backups and monitoring

```sh
./target/debug/hlb backup dest list
./target/debug/hlb backup status             # freshness PER destination
./target/debug/hlb metrics rules
./target/debug/hlb metrics deadman --ntfy https://ntfy.sh/watchdog
./target/debug/hlb replication config nas-01
./target/debug/hlb replication failover nas-01   # --force if it would lose data
```

Freshness is per destination and the summary shows the worst case; a single fresh
destination must never make a three-week-old off-site look current.

A restore is rehearsed for real in a disposable container, on the image the installed
PostgreSQL runs — a base backup does not open on another libc:

```sh
./target/debug/hlb dr exercise --disposable            # preview
./target/debug/hlb dr exercise --disposable --apply    # restore, open, count, destroy
```

## People

```sh
./target/debug/hlb user list
./target/debug/hlb user add lena --email lena@example.org   # --apply; PocketID identity, then the mailbox in Stalwart
./target/debug/hlb user mailbox add lena contact     # --apply; an existing Stalwart account is said, never silent
./target/debug/hlb user mailbox remove lena contact  # --apply; its Stalwart account and mail stay
./target/debug/hlb user alias sieve lena     # --apply to install in Stalwart
./target/debug/hlb user role lena admin      # --apply; lists what it opens, refuses to demote the last one
./target/debug/hlb user quota lena immich --gib 200   # --apply; --none, or --role for their role's again
./target/debug/hlb role list                 # roles, holders, apps each enters, what it administers
./target/debug/hlb role set family --name Family --level user   # --apply; --mailboxes, --mail-gib…
./target/debug/hlb role allow family gitea   # --apply; an app no role is let into lets nobody in
./target/debug/hlb role deny family gitea    # --apply
./target/debug/hlb role quota family immich --gib 50   # --apply; --none
./target/debug/hlb role sync                 # what PocketID and the apps would be made to hold; --apply
./target/debug/hlb user sessions lena        # --close <ref>|all
./target/debug/hlb user names lena --first Léna --display "Léna M."   # --apply; needs PocketID
./target/debug/hlb user mailbox default lena contact   # --apply; PocketID's address follows
./target/debug/hlb audit --verify            # chain integrity
```

## The installation itself

```sh
./target/debug/hlb announcement list
./target/debug/hlb alert mute disk-full --for 4h --reason "purge under way"   # max 7d
./target/debug/hlb alert mutes                  # still listed, one notch lower
./target/debug/hlb alert unmute disk-full
./target/debug/hlb config appearance --name "Turi Industries" --apply
./target/debug/hlb config timezone Europe/Paris --apply   # before Seafile: read at its first start
./target/debug/hlb secrets-rekey --new-key /tmp/new.key   # --controller-stopped --apply; a running one is refused
sudo ./target/debug/hlb secrets-seal  # sealed to this machine's TPM; refused until `hlb emergency kit` is current
sudo ./target/debug/hlb secrets-seal --host-only --apply  # a TPM that seals nothing: refused without this
```

## A new fleet, from bare machines

In order. Every line previews without `--apply`.

```sh
./target/debug/hlb node deps                 # what this machine lacks, and what would run
sudo ./target/debug/hlb cluster init --endpoint 192.168.1.10 --apply
./target/debug/hlb cluster autolock --apply  # then `hlb emergency kit`, and again: sealed on each manager
./target/debug/hlb node add 192.168.1.11 --identity ~/.ssh/id_ed25519 \
    --failure-domain rack-a --apply
./target/debug/hlb mesh sync --apply         # a node that missed a peer
./target/debug/hlb mesh remove old-node      # a machine gone; refused while it is in the Swarm
printf '%s' '<user>:<token>' | ./target/debug/hlb secret-set registry-ghcr.io --purpose registry
./target/debug/hlb fleet agent --image ghcr.io/turi-industries/hlb-agent:0.2.1 --apply
./target/debug/hlb fleet controller --image ghcr.io/turi-industries/hlb-controller:0.2.1 --apply
```

The agents and the controller talk over mTLS, with certificates that live 90 days.
The controller issues them again a month before they end and rolls them out; one it
could not renew is in the inbox and notified every day. By hand, the same pass:

```sh
./target/debug/hlb pki status                # each leaf's end date
./target/debug/hlb pki renew                 # what is due — preview
./target/debug/hlb pki renew --apply
```

`cluster init` and `node add` install Docker from Docker's own repository (its signing
key is compiled in), switch on unattended SECURITY updates with the engine kept out of
them, bring up the WireGuard mesh with a firewall closing Swarm's ports outside it, and
set the node's tier. The images are published to GHCR by the `Images` workflow when a
`v*` tag is pushed (amd64 and arm64), or built locally from the `Dockerfile`
(`docker build --target agent .`, `--target controller`).

Keeping the machines current — one node at a time, drained first, rebooted only if its
kernel asks for it:

```sh
./target/debug/hlb node upgrade worker-1             # preview
./target/debug/hlb node upgrade worker-1 --apply
./target/debug/hlb node upgrade solo --accept-downtime --apply   # the only node
./target/debug/hlb node prune                        # the images no container uses
```

Each machine's protection level — what a stolen one would give up — is read from its
firmware, TPM and systemd, never declared: `node check`, `cluster init` and `node add`
show it, the last two label the node, and `cluster status` lists it. A, a verified boot
and the disk bound to the network; B, the disk bound to the TPM and the network, boot
not verified (every Debian 12); C, no TPM that seals; D, a virtual machine. It is what
the machine can reach: the line under it says whether its disk is encrypted yet.

```sh
./target/debug/hlb node check 192.168.1.11           # the level, nothing changed
./target/debug/hlb node protection worker-1          # read again — preview
./target/debug/hlb node protection worker-1 --apply  # and labelled
```

A disk the installer encrypted asks for its passphrase at every boot until it is bound:
`node bind-disk` makes the house's other nodes Tangs (port 7500, their keys pinned),
binds the disk to its TPM AND one of them (three at most: the disk's header holds no
more), enrols the node's recovery key and takes the
install passphrase out. Refused while the printed kit lacks that key, and on a one-node
house — the disk would open for whoever carries the machine away. When no Tang answers,
the kit's key is typed at the console or over SSH at boot (`ssh -p 2222`, root's keys,
the fingerprint it printed). `node add` and `mesh remove` name the disks to bind again.

```sh
./target/debug/hlb node bind-disk worker-1           # what would change — the key made
./target/debug/hlb emergency kit                     # printed with it
./target/debug/hlb node bind-disk worker-1 --apply
```

Bound, a node whose firmware has Secure Boot, a TPM and systemd 257 (Debian 13) reaches
level A with `node verify-boot`: a kernel image (UKI) signed by a key of the node's own,
booted by shim, and the binding resealed to the PCRs that image produces — `hlb-uki`,
run after every `update-initramfs`, before the next reboot. Run once per stage, each
read from the node: the key made and handed to shim (a one-time password to type at the
console, in MokManager), the UKI installed and booted once — that boot opened by the
kit's key over `ssh -p 2222`, since only a boot through it reads its PCR 7 —, then the
disk sealed to it and the UKI first. GRUB opens nothing afterwards; `bind-disk` reseals.
At level A, a db or dbx update (`fwupdmgr update`) is resealed as soon as it is written —
the next boot's PCR 7 is predicted from the firmware's event log — and DKMS modules (ZFS)
are signed by the same key. Run again, the verb says what would make the next boot wait
for the kit's key: a PCR 7 nothing resealed, a firmware update fwupd holds for the
reboot, a firmware in Setup Mode.

```sh
./target/debug/hlb node verify-boot worker-1           # which stage, and what it does
./target/debug/hlb node verify-boot worker-1 --apply   # then reboot, as it says; again
```

`cluster init`, `node add` and `node upgrade` also cap the system journal (500 MB, a
month) and harden the kernel (`/etc/sysctl.d/90-homelabus.conf`: no redirects, eBPF
and kernel addresses for root only) — neither touches forwarding or `rp_filter`, which
Swarm and the mesh need. The controller prunes unused images every night; volumes are
never touched.

The platform's own secrets — PostgreSQL's and MariaDB's administrators, Garage's RPC
secret and token, Grafana's admin, Pocket ID's key — are generated at install into the
vault (`{{ secret.<name> }}` in their manifests), and `hlb` and the controller read the
admin URLs from there. Backups to the cluster's Garage, then off-site:

```sh
./target/debug/hlb install garage --apply
./target/debug/hlb garage init --apply                # each node: 9/10 of its free disk
./target/debug/hlb backup dest garage --apply        # bucket, key, credentials, destination
./target/debug/hlb backup dest add offsite --location s3:https://s3.example.org/hlb \
    --classes critical --access-key AKIA…              # secret key on standard input
./target/debug/hlb backup run                        # what the controller runs on its own
./target/debug/hlb backup run --app hlb --force      # one app now; `hlb` is the state itself
./target/debug/hlb backup dest prove                 # which ones the credential can erase
```

`dest prove` writes a witness with each destination's credential and tries to delete
it with that same credential; `dest list` shows the last verdict. The cluster's Garage
always comes out erasable — it keeps no versions —, so the copy an intruder cannot
reach is an append-only REST server or a versioned bucket whose credential is denied
`s3:DeleteObjectVersion`.

A volume put back as a snapshot holds it, on the node holding it — the app stopped
meanwhile, and what the volume holds backed up first, so the restore itself can be
undone:

```sh
./target/debug/hlb backup restore pocket-id          # which snapshot, from where, on which node
./target/debug/hlb backup restore pocket-id pocket-id-data --snapshot 74c465b8 --from nas --apply
```

Only a snapshot Homelabus took is restored: one written into the repository by anyone
else is set aside, and the preview names it. Its full id — the hash of its content —
restores it anyway.

A bucket an app declares `backup: true` (the default) is read by the pass through the
app's own key and streamed into restic as one archive — no copy on any disk, and an
unchanged bucket adds nothing. It is put back the same way, every object with the
headers it had, and the ones written since deleted:

```sh
./target/debug/hlb backup restore fluxer fluxer         # Fluxer's attachments, avatars, emoji
./target/debug/hlb backup restore fluxer fluxer --snapshot 9c1d2e44 --from nas --apply
```

A database comes back from its dump: dropped and recreated as installing it made it —
the app's, shut to every other, its extensions enabled —, the dump restored into it,
and what it held dumped first. PostgreSQL's in one transaction; MariaDB's table by table,
the app left stopped if it stops halfway:

```sh
./target/debug/hlb backup restore fluxer --database        # its one database; --database <name> among several
./target/debug/hlb backup restore fluxer --database --snapshot 91f7dad8 --from rest --apply
```

## Putting apps online, and inviting people

Once: the domain, where certificates come from, the machine the router forwards 80 and
443 to. The DNS provider's credentials go in the vault first — `hlb config exposure`
names each one it misses, and refuses until they are there:

```sh
printf '%s' '<token>' | ./target/debug/hlb secret-set dns-cloudflare-api-token --purpose dns
./target/debug/hlb config exposure --domain example.org --email you@example.org \
    --dns cloudflare --staging --node deb1          # preview: what DNS and the router need
./target/debug/hlb config exposure --domain example.org --email you@example.org \
    --dns cloudflare --staging --node deb1 --apply
./target/debug/hlb install caddy --apply              # the ingress, on that node
./target/debug/hlb config exposure --production --apply   # once staging served
```

Providers built into the ingress: cloudflare, desec, duckdns, gandi, hetzner, ovh,
porkbun — each credential is `dns-<provider>-<field>` (`dns-ovh-application-key`…).
Without `--dns`, one certificate per name over HTTP-01: a DNS record per app, before
it is installed. Two other sources, for a house no public name reaches:

```sh
./target/debug/hlb config exposure --domain home.lan --internal --node deb1 --apply
./target/debug/hlb config exposure --root > homelabus-root.crt   # install it on devices
./target/debug/hlb config exposure --acme-ca https://ca.home.lan:9000/acme/acme/directory \
    --acme-ca-root root_ca.crt --dns none --apply             # a step-ca of your own
```

`--internal` signs under a root Homelabus generates and keeps in the vault; the
controller trusts it, and so does any device it is installed on. A private ACME
authority's root is trusted the same way.

From then on an install publishes itself, at `<app>.<domain>` unless `--domain` says
otherwise, and every install, upgrade and removal republishes the whole Caddyfile. It is
written into Caddy's own volume by a one-off job that has it checked by `caddy validate`
first; Caddy reloads it without dropping a connection, and a file it would refuse
never reaches it:

```sh
./target/debug/hlb install vikunja --apply           # https://vikunja.example.org
./target/debug/hlb ingress                           # the Caddyfile, credentials hidden
./target/debug/hlb ingress --apply                   # republish, after a secret changed
./target/debug/hlb config exposure --node deb2 --apply   # Caddy moves, CrowdSec with it
```

Two platform services sit in front of the apps when installed after Caddy: CrowdSec
reads Caddy's access log and bans through its bouncer, whose key is generated at
install; Anubis puts a proof-of-work in front of an app whose manifest names it in its
`chain`:

```sh
./target/debug/hlb install crowdsec --apply
./target/debug/hlb install anubis --apply
```

The interface is published at `hlb.<domain>` (`--interface` for another) once `hlb
fleet controller` runs it; that command also registers its sign-in client in PocketID,
through the API key generated at PocketID's install (`pocket-id-api-key` in the vault):

```sh
./target/debug/hlb user invite --role standard --note "Camille" --apply   # the link, once
./target/debug/hlb user invitations
./target/debug/hlb user revoke-invitation <reference> --apply
./target/debug/hlb user link camille         # a new passkey link, valid 12 h
```

Sending the invitation is yours: Homelabus shows the link once and keeps its
fingerprint only.

Stalwart answers as its route's name — `mail.<domain>` — from its install, and computes
every DNS record each mail domain needs, its DKIM keys included. They are read from a
public resolver every night, a missing one in the inbox; read them now, with the lines
to add:

```sh
./target/debug/hlb mail dns                  # every domain Stalwart hosts; exits 1 while one is missing
./target/debug/hlb mail dns example.org
```

Most residential lines close port 25 outward: mail to other domains then waits for days
and bounces. `hlb mail relay` says whether Stalwart's node reaches it, and sends every
remote domain through a provider's submission service instead — TLS required, its
certificate verified, the account tried before anything is written:

```sh
./target/debug/hlb mail relay                # through what, and whether port 25 leaves the house
printf '%s' '<password>' | ./target/debug/hlb mail relay set --host smtp.provider.net \
    --user house@example.org --spf include:spf.provider.net --apply
./target/debug/hlb mail relay remove --apply # by each domain's MX again
```

A message that cannot leave waits in Stalwart's queue — retried for three days, its
sender told after one — so the controller reads the queue every quarter of an hour, and
a recipient waiting over an hour is in the inbox by its domain:

```sh
./target/debug/hlb mail queue                # what waits, what the last attempt was told; exits 1 past an hour
```

A Stalwart installed on 0.16 stays there: 1.0 refuses to open its store, so `hlb update`
holds the move and `hlb upgrade` refuses it. `hlb mail migrate` copies the store into a
new volume with `stalwart-migrate` while 0.16 serves, stops it for the last changes,
compares every account and starts 1.0 on the copy. The 0.16 volume is never written:
until 1.0 has served anyone, rolling back is starting 0.16 on it.

```sh
./target/debug/hlb update apply stalwart     # first, onto 0.16.27 by digest: the only 0.16 it migrates
./target/debug/hlb mail migrate              # what it would do, and any question it cannot answer
./target/debug/hlb mail migrate --apply
```

People's own clients meet Stalwart on 465 and 993 under its public name: a certificate
under Homelabus's root for an internal exposure, one Stalwart requests from the
exposure's ACME directory otherwise. The install and the nightly role pass see to it;
`hlb role sync --apply` does it now.

## Storage and nodes

```sh
./target/debug/hlb storage status            # ZFS pools, and what would be done
./target/debug/hlb storage init --apply      # import, then the datasets
./target/debug/hlb storage export --network 10.0.0.0/24
./target/debug/hlb node add <host> --storage-node --apply
./target/debug/hlb garage status
```

Preparing a new machine ahead of time — printed, never written to disk:

```sh
./target/debug/hlb node preseed nas-02 --domain example.org \
    --disk /dev/disk/by-id/ata-Samsung_SSD_1TB_S1234 \
    --ssh-key "$(cat ~/.ssh/id_ed25519.pub)"
./target/debug/hlb node preseed nas-02 --disk /dev/disk/by-id/ata-Samsung_SSD_1TB_S1234 \
    --ssh-key "$(cat ~/.ssh/id_ed25519.pub)" --encrypt   # LUKS, until bind-disk
```

The environment variables that decide where volumes land, and the traps that go with
them, are in [`.claude/rules/storage.md`](../.claude/rules/storage.md).

## The interface, with no cluster and no Docker

The fastest way to see it:

```sh
./target/debug/hlb-controller --demo --listen 127.0.0.1:8420 &
curl -s http://127.0.0.1:8420/api/apps
```

The web interface (SvelteKit, in `web/`) runs against demo mode — every module, the
inbox, the action panel, painted in the installation's theme:

```sh
(cd web && bun install && bun run build)
./target/debug/hlb-controller --demo --insecure-no-auth --ui-dir web/build \
    --listen 127.0.0.1:8420
```

Then open <http://127.0.0.1:8420/>. `/uptime` is the status page, `/kiosk` the wall
display. For working on the interface, `bun run dev` in `web/` serves it on
<http://localhost:5173> and hands the API to the controller beside it.
