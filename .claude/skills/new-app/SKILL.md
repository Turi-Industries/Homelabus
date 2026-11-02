---
name: new-app
description: Add an application to the catalog as a manifest and a guide, with no Rust — and when the schema cannot say something, record the gap instead of special-casing the app. Use when asked to add, package or port an app into catalog/.
---

The goal this serves: **an app is a folder under `catalog/`, never a Rust change.** Of the
twelve commits that last added or completed an app, eight touched Rust (measured
2026-10-27) — each time because a closed list (a deploy knob, a token, a secret form, a
database engine) lacked an entry. This skill is how the ninth stays out of `crates/`.

`CONTRIBUTING.md`, *Adding an app to the catalog*, holds the rules a manifest keeps.
Read it first; this is the order of work around it.

## 1. Read the image, not its documentation

For the version you will pin: the Dockerfile, the entrypoint, and the code that reads
the environment. List every variable the image actually reads, the port, the user it
runs as, what it writes and where, how it reaches its database, and every door it
leaves open at first start (sign-up, a default administrator, a setup wizard, a token
printed in the logs). A variable from the documentation that the image never reads is a
declaration nobody reads: the app runs on its default and looks healthy.

From the publisher's compose file: its `command` is the manifest's `args` (after the
image's entrypoint, which stays), its `entrypoint` the manifest's `command`;
`init`, `stop_grace_period`, `stop_signal`, `working_dir`, `hostname`, `ulimits`,
`sysctls` (`net.*`) and `group_add` go under `process`; `shm_size` is a tmpfs `{ path:
/dev/shm, size }`. `network_mode: host`, `privileged`, `devices` and `extra_hosts`
reaching the host have no field: they are a decision (§4).

## 2. Start from the closest manifest

| Shape | Start from |
|---|---|
| one container, PostgreSQL, native OIDC, mail | `vikunja`, `gitea` |
| one container, no database | `librespeed`, `termix`, `bulwark` |
| media on NFS, a cache, companions | `immich` |
| MariaDB, several databases, companions | `seafile` |
| object storage, many companions | `fluxer` |
| behind the proxy only (no OIDC of its own) | `n8n` |

Write `catalog/<name>/manifest.yaml` (the folder name IS `metadata.name`) and, when
the app needs steps after it starts, `guide.yaml`. Needs, never addresses: `requires`
plus tokens (`{{ db.url }}`, `{{ oidc.client_id }}`, `{{ secret.<name> }}`).
`metadata` says `hlb: ">=<the release that first reads it>"` and `criticality:` —
`vital` (getting back in: passwords), `important` (missed within the day: files,
photos, chat) or `normal`; the backup pass serves the vital apps first. Which an app
is, is the owner's call: ask when unsure.

## 3. Prove it, cheapest first

```sh
export HLB_STATE=/tmp/<name>.db HLB_MASTER_KEY=/tmp/<name>.key
cargo run -q -p hlb-cli -- catalog validate          # a typo refused with its line
cargo run -q -p hlb-cli -- install <name>            # the preview: every action, nothing done
cargo run -q -p hlb-cli -- catalog images            # the newest mature tag of each, by digest
```

If the publisher signs its images with cosign, declare who: `signedBy: { github:
owner/repository, workflow: release.yml }` in the image, read from the signature's
certificate, then `cargo test -p hlb-catalog --test signatures -- --ignored` with
`cosign` on the `PATH`.

Then every closed door gets an `assertion` read back from the running app, proven on
the pinned image (`crates/hlb-guide/tests/live_assertions.rs` says how) — and proven to
FAIL once you open the door by hand, or it reads nothing. Then the lab, which `lease.sh`
gives to one session at a time.

## 4. When the manifest cannot say it — stop

🔴 Do not write `if app == "<name>"`, a match arm on the app, or a constant naming it.
Stop and decide which of these it is:

- **A generic field is missing.** Name the need in words any app could have ("a tmpfs
  at a path", "a secret in the form X", "a wait until a probe answers"). Ask whether a
  second app in the catalog, or a well-known one outside it, has the same need. If yes,
  it is a schema change: a field in `hlb-types`, read by the resolver or the engine,
  with a test whose fixture is a made-up app, never this one. Make it its own commit,
  before the app's, and say in the message which apps it serves.
- **Only this app will ever need it.** Then it does not belong in Homelabus. Say so to
  the user, with what the app would lose without it.
- **It is a decision** (exposing a port, weakening isolation, trusting an image's
  defaults): ask the user.

Either way, add the need to `ROADMAP.md`, plan G, goal 4 (the schema gaps), if it is
not built in this session. A gap written down is a gap the next app
does not rediscover.

## 5. Record

The commit message says what was proven, on which version, and what was not; update
the catalog count in `ROADMAP.md` if it states one.
