# hlb-cli

One `main.rs` of about 8 000 lines, and roughly forty verbs. It assembles every domain
and owns none of them: the logic lives in the crate the verb calls into, and so do the
traps.

**That is why this file exists.** The rules in `.claude/rules/` are scoped by `paths:`
to the crates that own each domain, so none of them fires on `main.rs`. Reading a verb's
implementation here gives you the CLI plumbing and none of the reasons behind it.

**The rule: open the domain rule for the crate the verb calls into, before changing what
the verb does.** The table below is a shortcut for the ones where that crate is not
obvious from the verb — it is deliberately not a list of every verb, because a
hand-maintained list of verbs here would drift the way three others in this repository
already have.

| Verb | Not obviously |
|---|---|
| `dr`, `pitr`, `snapshot` | `hlb-backup` — `backups.md` *and* `databases.md` |
| `todo`, `ack` | `hlb-guide`, the blocking manual actions — `operations.md` |
| `history` | `hlb-gitops`, the git mirror of desired state — `operations-updates.md` |
| `selfy` | `hlb-selfupdate`, not `hlb-updater` — `operations-updates.md` |
| `access`, `crowdsec`, `pki`, `token` | `security.md` |
| `emergency` | `hlb-engine::emergency` over `hlb-bitwarden` (the vault), `hlb-backup-run::kit` (the kit), `hlb-secrets::split` (its split among relatives) — `security.md` |
| `termix` | `hlb-engine::termix` over `hlb-termix`, its jobs through `hlb-orchestrator` — `security.md` |
| `ingress` | `hlb-ingress`, Caddy and forward-auth — `security.md` |
| `init`, `deps` | `hlb-bootstrap` — `security.md` and `storage.md` |
| `garage` | `hlb-objstore` for keys, `operations-swarm.md` for the layout |

⚠️ **Every command line advertised elsewhere must exist here.** `cli_command` in the API
is shown to people as "here is the equivalent command", and five of them once named
commands nobody had written. A test crosses every `hlb <verb>` in the API against the
clap enum — if you rename a verb, that test is what catches the call sites you forgot.
The interface's hints, the engine's refusals and the command tour are read too, and a
line with a flag or a placeholder is parsed by clap as pasted.

⚠️ **Every verb that changes something writes an audit entry.** `tests/audited.rs` reads
every `Subcommand` leaf from the source: one taking `--apply`, or calling a `State`
method that writes SQL, must reach `.audit(` — or sit in its `EXEMPT` list with a reason.

```sh
cargo test -p hlb-cli
```
