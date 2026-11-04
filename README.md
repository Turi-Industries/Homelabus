# Homelabus

[![CI](https://github.com/Turi-Industries/Homelabus/actions/workflows/ci.yml/badge.svg)](https://github.com/Turi-Industries/Homelabus/actions/workflows/ci.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](LICENSE)

**Your own cloud, at home, on a few ordinary machines.**

Photos, passwords, files, mail, chat, films, a git server. Everything a family, an
association or a small team usually rents from big platforms can run on machines you
own. Homelabus installs these apps, connects them to each other and looks after them:
the backups, the sign-in, the updates, the addresses. It also tells you, in plain words,
when something is not protected. It never shows you a green light it cannot prove.

## What it does for you

📦 **An app in one command.** Ask for Immich, Vaultwarden or Seafile, and Homelabus
works out what the app needs: a database, a sign-in, an address, a mailbox, a place on
disk. It prepares all of it and starts everything in the right order. You never type a
database password or an internal address.

💾 **Backups you can count on.** Every app is copied on a schedule to several places,
and the copies are read back to check they are whole. Restores are rehearsed, and
Homelabus checks whether someone who broke in could erase the copy kept elsewhere.

🔑 **One account for the whole house.** Everyone signs in once, with a passkey, and is
let into the apps their role allows. Each person also gets a mailbox and disposable
addresses to give to websites.

🌍 **Online, when you decide.** Each app gets its own `https://` address with its own
certificate. A sign-in page can stand in front of an app that has none of its own.

🔄 **Updates without bad surprises.** Versions are pinned and watched. A backup is
taken before each update, and an update that breaks the app is rolled back by itself.

🖥️ **One screen for everything.** A web dashboard shows what is running, what is
backed up, and what needs you, in plain words. When it loses contact, it says so
instead of showing yesterday's state.

✋ **Nothing happens behind your back.** Every command first shows what it would do,
and changes nothing until you add `--apply`. The interface works the same way.

## Where it is going

Homelabus already runs a real cluster at home. The finished version aims further, and
each goal below is measured, not just promised:

- **From a bare machine to your first app in minutes.** You download one signed file,
  then a guided installer asks a few questions and does the rest.
- **Nothing lost, ever.** The restore of every app is rehearsed regularly and proven,
  not assumed.
- **Nothing stolen.** Disks are encrypted and unlock only at home, so a machine carried
  away shows nothing. Secrets never sit in plain sight, and no single provider (domain
  registrar, DNS host, server, storage) can take your installation away.
- **Always reachable.** A small rented server acts as the front door and as a
  lifeboat: passwords and sign-in stay available even when the house is offline or
  moving, and a status page says what is down.
- **Always up to date.** Security fixes are applied by themselves after a short wait,
  with a backup first. Big upgrades stay your decision.
- **New apps without code.** Adding an app to the catalog means writing a short
  description of what it needs, not programming.
- **Simple to live with.** A clear dashboard and documentation written for the person
  running it, not for its author.

It is built for households first, and also for associations, schools and small
alternative hosters who want the same thing for their members. You start small: one
machine, your apps, backups. A second machine, a router or a rented server can be added
later without reinstalling anything.

## The apps

Thirteen applications today: **Immich** (photos), **Vaultwarden** (passwords),
**Seafile** (files), **Jellyfin** (films and music), **Gitea** (code), **Vikunja**
(tasks), **Mealie** (recipes), **n8n** (automations), **Fluxer** (chat and calls),
**Bulwark** and **Roundcube** (webmail), **Termix** (a terminal for your machines)
and **LibreSpeed** (a speed test).

Beneath them, Homelabus runs the services they share and installs each one only when
an app needs it: PostgreSQL, MariaDB, Valkey, PocketID (sign-in), Stalwart (mail),
Caddy (addresses and certificates), Garage (storage), CrowdSec, ntfy (notifications),
VictoriaMetrics and Grafana (monitoring), and oauth2-proxy.

## Try it

```sh
# Download hlb: the installer checks its signature before installing anything
curl -fsSL https://github.com/Turi-Industries/Homelabus/releases/latest/download/install.sh | sh
# a fresh Debian has wget and no curl:
#   wget -qO- https://github.com/Turi-Industries/Homelabus/releases/latest/download/install.sh | sh

# As root, from one directory: the state and the vault's key are made here
hlb cluster init --endpoint 192.168.1.10 --apply         # Docker, Swarm, the state, the vault
hlb config exposure --domain home.lan --internal --node "$(hostname)" --apply
hlb install caddy --apply                                # addresses and certificates

# What Vikunja needs: its preview refuses until they run, and names each one
hlb install postgres --apply
hlb install stalwart --apply
hlb install pocket-id --apply

hlb install vikunja                                      # shows what it would do, changes nothing
hlb install vikunja --apply                              # stops: the app's DNS record comes first
hlb ack vikunja/dns-record                               # checks it; --force attests one it cannot see
hlb install vikunja --apply                              # does it
```

PostgreSQL, Stalwart and PocketID ask for a node reporting 8192 MB or more, which a
machine sold as 8 GB does not, and refuse a smaller one: `hlb node tier <node> --set
heavy --apply` overrides that, and the machine can then run out of memory.
`scripts/drills/deploy.sh` runs this path on a bare VM, and
[docs/measures.tsv](docs/measures.tsv) keeps what it took.

From a checkout, `cargo build --release -p hlb-cli` builds the same binary. Putting
apps online and inviting people takes a few more commands, all in
[the command tour](docs/cli-tour.md#putting-apps-online-and-inviting-people).

🔴 **Keep the vault's master key safe.** `cluster init` creates it, and losing it makes
every secret and every backup unrecoverable. Keep two copies offline: `hlb emergency
kit` prints one. Then `hlb secrets-seal` seals it to the machine's TPM, in memory only.

## How it compares

**YunoHost** is the closest in spirit. It is free software (AGPL) built for people
rather than developers, with one account for every app and a mail server included. It
runs on one server, and its community has packaged hundreds of apps. Homelabus spreads
a dozen apps over several machines, and proves its backups and restores instead of
assuming they work.

**Cloudron** is polished, and also runs on one server. Its platform is not free
software, and it is paid beyond two apps.

**Coolify** is a self-hosted Heroku. It deploys your own code and one-click services to
several servers, and leaves sign-in, mail and the links between apps to you.

Choose Homelabus if you want several ordinary machines to act as one, backups whose
restores are proven, and a tool that tells you what is not protected. Choose another
one if you need a large catalog today, or a project with more than one maintainer.

## Security

What Homelabus defends against, what it has to trust and what it does not protect yet
is in [the security model](docs/security-model.md). A node installed encrypted opens its
disk only at home; one installed before must be reinstalled to get there.

## Status

Homelabus is young. It is before version 1.0, has one maintainer, runs on a real
cluster and is checked by more than two thousand tests. What is missing or not yet
proven is listed openly in [the known limitations](docs/limitations.md).

## Documentation

| | |
|---|---|
| [docs/cli-tour.md](docs/cli-tour.md) | every `hlb` command, with an example |
| [docs/operating.md](docs/operating.md) | the dashboard, backups, storage, accounts, the daemon |
| [docs/how-it-works.md](docs/how-it-works.md) | the design: how an app's needs become a plan |
| [docs/limitations.md](docs/limitations.md) | what is missing or not yet proven |
| [docs/security-model.md](docs/security-model.md) | what it defends against, what it trusts, what is not protected yet |
| [CHANGELOG.md](CHANGELOG.md) | what changed in each release |

## Contributing

Questions are welcome in
[Discussions](https://github.com/Turi-Industries/Homelabus/discussions) (see
[SUPPORT.md](SUPPORT.md)). Code is welcome under [CONTRIBUTING.md](CONTRIBUTING.md), and
[GOVERNANCE.md](GOVERNANCE.md) lists what will not be merged. Report a vulnerability
privately, as [SECURITY.md](SECURITY.md) explains.

## License

Copyright © 2026 Turi Industries. [GNU Affero General Public License](LICENSE), version 3
or any later version. If you run a modified Homelabus for other people over a network,
you owe them its source, so no one can turn it into a closed service.
