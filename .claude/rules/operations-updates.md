---
paths:
  - "crates/hlb-updater/**/*.rs"
  - "crates/hlb-selfupdate/**/*.rs"
  - "crates/hlb-registry/**/*.rs"
  - "crates/hlb-gitops/**/*.rs"
  - "crates/hlb-engine/src/{upgrade,prune}.rs"
  - "crates/hlb-{types,catalog}/src/index.rs"
  - "crates/hlb-engine/src/sources.rs"
---

# Operations: images, updates and upgrades

Registries, tags, digests, `hlb update` (an image moves) and `hlb upgrade` (the catalog's
manifest is re-frozen). A wrong answer here reads as "up to date".

## Registries and tags

- **A tag that validates may not exist.** `catalog validate` checks shapes;
  `hlb-catalog/tests/images_exist.rs` (ignored, network) resolves every image and
  requires a Linux build of it — Bulwark's resolved for months, FreeBSD only.
- **A tag list is paged.** ghcr.io answers 100 tags (1,000 asked) in no useful order,
  the rest behind `Link: rel="next"`: read as the whole list, Immich's first page held
  no `v3` and every `hlb update check` said "up to date". `list_tags` follows every page
  (immich-machine-learning: 214 of them), and a cut list is an error, never a short one.
- **Docker Hub allows an anonymous address 100 manifest reads an hour**, and once they
  are spent it refuses even the `HEAD` it does not count. A 429 read as "registry down"
  hid it; `Error::RateLimited` names it. Measured on 2026-10-19: a pass over the whole
  catalog spent 13, dating each image only as far as its first mature build.
- **The `v` is part of a tag's shape.** Bulwark publishes `1.15.0` and `v1.15.0` side by
  side; `Version::same_flavor` keeps a tag written the way it was.
- **Versions cannot say "downward" across a moving tag.** An installation on `v2` runs
  whatever `v2` named when it was installed; a catalog pinning `v2.29.0` reads as later
  than `2` and would take it back three releases. A catalog move older BY BUILD DATE
  than what runs is no move (`hlb_updater::check`), and the same build under another
  name is none either.

- **A release moves four files, not one, and the next commit moves the version on.**
  The workspace's `version` in `Cargo.toml` (`0.4.0-dev` → `0.4.0`), the catalog's
  `hlb-caddy` tag (`the_ingress_runs_the_image_this_release_builds`),
  `web/openapi.json` (`HLB_UPDATE_OPENAPI=1 cargo test -p hlb-controller --lib
  the_committed_document_is_the_generated_one`) and the schema it reads
  (`HLB_UPDATE_SCHEMA=1 cargo test -p hlb-types --test release_schema`, into
  `crates/hlb-types/schemas/`). Run the WHOLE suite before tagging: releases are
  immutable, and 0.2.1 took two red CI runs to find the last two. Then `0.5.0-dev`
  (and the OpenAPI document again) at once: a manifest using what was added since says
  `hlb: ">=0.5.0"`, and a workspace still saying `0.4.0` would set it aside itself.
- **An app's `metadata.hlb` is held to its floor's schema** (2026-11-02). An `hlb`
  outside the range sets the app aside (`Catalog::get` says which `hlb` it needs) —
  before, one manifest using a field it did not know refused the whole catalog. A
  floor below the running release is checked against that release's committed schema,
  manifest and guide: `metadata.hlb` itself is unknown to 0.3.0, so no app starts
  there.

## Digests

- **An image is dated by its BUILD, at the digest that would run** (the configuration's
  `created`, `RegistryClient::created`) — never by its tag, which may name another build
  since. No date, or the epoch of a reproducible build, is `Maturity::Undated`: not
  mature, or every undated image would be fifty years old. ⚠️ Docker's official images
  are REBUILT every week or two for their base, so a moving tag's build is often days
  old: the bot keeps the digest already pinned until the next one matures.
- **🔴 A deployment never falls back to the tag.** Without a digest in the state the
  executor deployed `repo:tag` without a word — the lab's PostgreSQL ran so for days
  beside sixteen pinned services. `Error::Unpinned` refuses it, and a resolved digest
  that matches no image of the app is not a step done.
- **An app's images are not one image.** A resolved digest was frozen on the app's own
  image whatever it was resolved for, and every service of the app deployed from it:
  Immich's machine-learning companion ran as `immich-server@` a digest that existed for
  neither. Each image is matched by repository and tag, the companions' included
  (`State::set_image_digest`).
- **A security scan reads the digest that will run.** A rebuild was scanned as the
  installed image's own `reference()` — the OLD digest — and a version by its tag alone,
  which may name another build by the switch.

## Moving an app

- **🔴 A companion moves with its app, before it.** `hlb update` moved the app's image
  alone and `hlb upgrade` keeps every image as installed, so no companion had ever moved:
  a catalog taking Immich to 3.3.1 would have run its server beside a machine-learning
  service left in 3.1.0. The catalog's companion moves ride in the app's candidate
  (`CompanionMove`), switched first — the install's order — each frozen into the state
  once it runs; one that does not come up stops the update before the app. A companion
  follows the CATALOG only: no registry watch of its own.
- **A major is rehearsed on its predecessor's data, through the manifest's own start**,
  and from an EMPTY volume too: Seafile's start skipped two directories its image's
  `start.py` makes first, and only a fresh volume showed it. Rehearsed and immature is
  not written: an install would take it at once.
- **A frozen manifest does not follow the catalog, and rerunning an install did not
  either.** Every deployment already done was skipped, so a catalog fix — Vikunja's
  replicas — never reached the running service. `hlb upgrade` re-freezes the catalog's
  manifest (its images excepted: `hlb update` moves those, after a backup) and runs the
  plan again; `deploy` updates an existing service in place. What would strand data is
  refused (`hlb_engine::upgrade::refusals`).
- **The guide is frozen beside the manifest** (`apps.guide`, 2026-11-02). Read from
  today's catalog, `hlb ack`, the nightly re-check and a restore's post-restore steps
  followed a guide the running manifest was never deployed with — and none once the
  app left the catalog. Every reader goes through `install::installed_guide`; NULL
  (installed before) falls back to the catalog's. A guide changed alone is an upgrade
  (`upgrade::guide_changes`), or the frozen one would never move; a reverted upgrade
  puts the previous guide back with the manifest.
- **🔴 A frozen manifest moves only with a plan run to its end.** `hlb upgrade` froze the
  catalog's manifest, then the plan failed (no Docker socket): the next upgrade found
  nothing to apply, and the change never reached the service. The CLI and the controller
  put the previous manifest back when `State::plan_finished` is false.
- **"Nothing before" is not "nothing changed".** In manifest history, the first known
  version does not have an empty diff because nothing moved: it has nothing before it.
  And a commit not touching the app still carries its file — without deduplication,
  twenty identical versions drown the one real change.
- **Every update leaves its previous image on every node that ran it.** Nothing removed
  one until 2026-10-19: on the lab's deb1, three days of work left 4.3 GB of 14.5 to
  give back, on the root disk the journal and Docker's state share. `hlb_engine::prune`
  runs `docker image prune --all` nightly through a job on each node's own daemon —
  what a container uses, a STOPPED one included, stays, so Swarm's task history keeps
  the image a rollback needs. Never `system prune`: it reaches volumes. ⚠️ An image no
  container uses goes, whatever its origin: the lab's `hlb-runner:bookworm`, built on
  deb1 and run only with `--rm`, was gone the next day — one that cannot be pulled again
  is kept by a container, or rebuilt.

## The catalog's signed index

- **🔴 The index's format is frozen for every release already out.** `index.json` is
  read `deny_unknown_fields`: one field added makes every house running 0.4.0 refuse
  the whole official catalog, at its next fetch. Something new a source publishes goes
  in a file of its own beside the index (`quality-v1.json`), which an older `hlb` never
  asks for; changing the index itself is a new file name, served beside the old one
  while releases reading it run. `hlb-types/tests/index_format.rs` holds the format
  0.4.0 reads.
