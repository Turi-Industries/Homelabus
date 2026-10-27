---
paths:
  - "crates/hlb-api/**/*.rs"
  - "web/openapi.json"
  - "web/scripts/*.ts"
  - "web/src/lib/causes.ts"
  - "web/src/lib/fields.ts"
---

# Interface — the API it is generated from

The wire contract between the controller and `web/`: `hlb-api`'s types, the OpenAPI
document, and what the demonstration serves through them.

## Decided for the web interface

- **A response field is always there; `null` says "none".** The document marks every
  field a response reaches as required (`openapi::Present`), so the generated type is
  `domain: string | null`, never `domain?:` — one kind of nothing to test for. That is
  only true while no wire type carries `skip_serializing_if`, and a controller test
  refuses one in every crate deriving `ToSchema`. A request body keeps its optional
  fields: there, `serde(default)` really means the client may leave one out.
- **🔴 Two wire types of one name are ONE schema in the document**, the second
  silently replacing the first: an assertion's `Verdict` took the restorability's place
  on 2026-10-18, and only `svelte-check` happened to notice. `#[schema(as = …)]`
  renames one; `no_two_wire_types_share_a_name` reads every crate for what derives
  `ToSchema` (or `judged!` wraps, or implements it by hand) and holds the document's
  schemas as its floor.
- **The controller answers `index.html` for a path that is neither a file nor under one
  of its own prefixes** — those are read from the document, so a reload on
  `/apps/gitea` lands in the interface and `/api/typo` stays a 404. ⚠️ `/status` is a
  SERVER route (the public status page's JSON): the screen is at `/uptime`, which reads
  `/api/status` signed in and `/status` otherwise.
- **What a field accepts is the controller's, declared once** (`hlb-controller`
  `limits.rs`): `BOUNDS` is written into the document and the body extractor refuses
  outside it before any handler runs — refused, never cut to fit: ninety days of
  invitation used to become thirty without a word. `scripts/limits.ts` generates
  `#lib/api/limits.ts` from the document, and `src/fields.test.ts` refuses a text field
  without `maxlength` or a number without `min` and `max`. A field the page alone reads
  (a search, the storage wizard) takes `TYPED` from `#lib/fields.ts`.
- **The inbox is the CONTROLLER's, grouped by cause** (`/api/issues`, `hlb_api::issues`).
  Each source is read through the function its own route answers with, and decides its
  `Cause` in the branch that writes its sentence (`health::findings`,
  `exposure::findings`) — never a second copy of the rule. One cause is one line, naming
  what it covers: 48 half-created accounts are two lines, not 48, and the home went from
  80 lines to 21 at a thousand accounts. An alert restating a cause folds into it
  (`issues::restated`, decided for every rule by a test). The interface words each cause
  in `causes.ts` — a `switch` ending on `never` — and files it under the module that
  declares it (`causes:` in `module.ts`; `modules.test.ts` walks the document's `Cause`
  and holds each to exactly one module). The navigation counts causes, not subjects.
  An inbox that could not be read says so — never "nothing needs you".
- **`--demo` freezes the catalog's own manifests** when it has the app, its stubs only
  otherwise. The stubs made every demonstration application "changed by the catalog" —
  a line no installation shows, since an install freezes the catalog's manifest.
  Vikunja is frozen with the two replicas the catalog has dropped, so the
  `catalog_changed` line and the upgrade button are on the screens the browser suite
  crawls.
- **`--demo` acts for its administrator** (`demo::ADMIN`, through a token named
  `demonstration`): what only an account is offered — arranging the home, "later", one's
  mailbox — is on the demonstration and in the browser suite. `--insecure-no-auth` on
  a real installation stays `anonymous`.

## Learned on the first interface

- **A dead route is invisible.** `/api/apps/{name}` existed with no caller. A test
  crosses the routes of the OpenAPI document with what the interface actually requests;
  a route served to other clients carries an `x-hlb-client` extension on its handler,
  naming who calls it — a decision, not an oversight.
- **Configuration routes have no preview, and that is a declared choice.** Writing a
  brand name is idempotent and reversible; forcing a round trip would train people to
  click twice, which drains the protection where it matters. `x-hlb-preview: false` is
  declared on the handler and a test locks the short exemption list.
- **A preview is logged as `preview`, not `ok`.** Knowing someone looked at what a purge
  would do is information; confusing it with an execution would make the log useless.
- **🔴 An endpoint existing is not the same as the interface being able to address it.**
  `POST /api/nodes/{id}/availability` is addressed by SWARM's identifier; the node detail
  is keyed by the AGENT ADDRESS (`10.0.0.1:8421`), which is not one, and `NodeDetail`
  carried no availability either, so a drain button could not know whether it had
  anything to do. `NodeDetail.swarm` joins the two on the HOSTNAME — the only name both
  sides share — and stays `None` when Swarm does not know the machine: the card then
  says so and offers no action. Guessing an identifier drains something else, and
  nothing says it did.
- **🔴 Docker addresses a node by id OR hostname, and a guard that compares only one is
  not a guard.** The refusal that stops the last active node being drained matched on
  `n.id == id`, so a call made by hostname answered "the target is not active", skipped
  itself, and emptied the cluster. Every test spelled the id and the hostname the same,
  so none of them could tell which was compared.
- **Every advertised command line exists — and runs as pasted.** `cli_command` is shown
  as "here is the equivalent command"; five of them named commands nobody had written.
  A test in `hlb-cli` walks each line down clap's own tree — a subcommand at every
  level, no stray word after a leaf, every flag — over the controller, `hlb-engine`'s
  refusals, `hlb-api`'s comments, `web/src`, the message catalogues and
  `docs/cli-tour.md`. It read one word until 2026-10-17, and `hlb user guest`, `hlb user
  link` and `hlb ingress apply` had passed. 🔴 Real words are not enough: `hlb remove
  {app} --apply` and `hlb dr exercise --apply` named only real flags and were refused
  when pasted (`--confirm`, `--disposable`). A line with a flag or a placeholder is
  handed to clap itself, placeholders filled — so a requirement the verb enforces
  belongs in clap (`requires`, `required`), where the test can see it.
- **A demo that invents its own names teaches a false convention.** That is what let a
  secret-naming defect go unnoticed. 🔴 It happened again, found on 2026-08-28 by reading
  the running window: `demo::alerts` showed `disk-plein`, and the rule `hlb-metrics`
  emits was **`disque-plein`** (`disk-full` since 2026-10-05). A rename is
  compiler-verified for identifiers and for nothing inside a string, and no test
  compared the two sides. The one that drifted was the **muted** alert, in the set
  precisely to prove that muting does not hide it — mute `disk-plein` and the real rule
  keeps firing under a name no screen shows. `every_demo_alert_names_a_rule_that_exists`
  crosses `alerts()` against `default_rules()`, derived from the function rather than
  from a second list of names: two lists is the shape that let this one drift.
- **Secret name suffixes are read from the resolver, not from memory.** Two kinds were
  inferred from guessed conventions (`-s3-key` instead of `-s3-secret`): the rule never
  fired, and the screen stayed silent about exactly the secrets that matter.
- **An age in days is not displayed in seconds.** "Verified 0 s ago" for a drill counted
  in whole days reads as "just now" when it may date from last night. The type carries
  its resolution, or the display invents a precision that does not exist.
