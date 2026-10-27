# Governance

## One maintainer

Homelabus has a single maintainer, who decides what is merged, what is released and
what the project is for. There is no committee, foundation or company behind it, and no
funding: the project declined grants on purpose. Decisions and their reasons are
recorded in [ROADMAP.md](ROADMAP.md), so a refusal can be read rather than guessed.

Contributions are welcome under [CONTRIBUTING.md](CONTRIBUTING.md) and the
[code of conduct](CODE_OF_CONDUCT.md). A vulnerability goes through
[SECURITY.md](SECURITY.md). Anything else reaches the maintainer at
contact@turi-industries.eu.

## What Homelabus will not do

A pull request towards one of these will be closed, however well written — each was
weighed and refused, and [ROADMAP.md](ROADMAP.md) says why:

- **Act on your behalf where a mistake cannot be undone**: no automatic database
  failover, no automatic major update, no `hlb` updating itself unattended, no backup
  site promoted automatically.
- **Stretch one cluster across sites**: a VPS is a separate site, never a Swarm member.
- **Run anything but Debian** on the nodes: no immutable OS.
- **Import `docker-compose.yml`**, or run apps through Compose: an app is a manifest
  declaring what it needs, never a topology.
- **Configure Caddy through its admin API**, which has no authentication.
- **Bill anyone**: a hoster's usage is measured and exported, never invoiced.

## If the maintainer disappears

There is no successor. If the repository sees no commit and no reply from the
maintainer for **twelve months**, consider the project ended: it will be archived as it
stands. Releases are signed by this repository's workflow, so no one else can publish
one that `scripts/install.sh` accepts.

What keeps running does not need the maintainer. An installation holds its own state,
vault and backups, and `hlb` carries its catalog, so nothing stops working when the
repository goes quiet. The code is AGPL-3.0-or-later: anyone may fork it and carry it
on under another name, as long as their users get its source too.
