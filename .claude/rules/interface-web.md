---
paths:
  - "web/**"
---

# Interface — the whole web app

What holds for anything under `web/` (SvelteKit). The screens, the themes, the API
contract, the portal's screens and the browser tests each have their own
`interface-*.md`.

## Decided for the web interface

- **Generated, never edited:** `src/lib/api/schema.d.ts` (from `openapi.json`) and
  `src/lib/paraglide/` (from `messages/*.json`), rebuilt before every check, test and
  build and ignored by git. ⚠️ SvelteKit 3 imports `#lib/…` (declared in
  `package.json`'s `imports`); `$lib` is gone, and an older version's documentation
  will suggest it.
- **No hand-written API type.** Types and client are generated from the controller's
  OpenAPI document (`openapi-typescript`, `openapi-fetch`). A TypeScript interface
  describing a response is the second definition `hlb-api` exists to prevent.
- **No business rule in TypeScript.** `attention()`, `verdict()`, `coverage()` run in
  Rust; the interface receives their result as a value and only chooses how to say it.
  A threshold written in a `.svelte` file has already drifted from the server's. The
  value travels through `judged!` in `hlb-api`: computed AT SERIALISATION, beside the
  fields, never stored — a stored copy is one more struct literal that can fill it in
  wrong. A rule that reads the clock is decided by the controller per response
  (`ActiveAlert::at(now)` → `AlertAt`).
- **Every displayed string is a Paraglide message**, in `en` and `fr`. A missing key is
  a type error; that is the point of choosing it. ⚠️ What the SERVER writes as a
  sentence is shown as received. Since 2026-10-07 the server sends a VALUE (`Cause`,
  `AccountState`, an alert's rule name, `ExposureSummary.cause`, `Need`,
  `HealthFinding`) and the interface words it — never by matching the server's words,
  a second copy of its sentences that the first reword breaks in silence. Still
  English, counted and left: timeline lines, an action's summary, steps and blockers,
  `ErrorBody.error`.
- **🔴 Paraglide shows the ENGLISH for a message missing in French, without a word.**
  Measured on 2.25: it compiles, renders, and nothing fails — "a missing key is a type
  error" holds only for a key missing in every language. `messages.test.ts` holds the
  catalogues to the same keys and the same inputs.
- **⚠️ Paraglide puts a number into a message as it is; Fluent formatted it.** "12 345
  comptes" under Fluent is "12345 comptes" now. Under 1,000 the two agree, which is why
  the conversion check (9,756 renders, zero differences) could not see it. **Decided
  2026-10-06:** a figure that can reach four digits — a size, a duration, a byte count
  — goes through `format.ts` (`number`, `megabytes`, `duration`) and enters its message
  as a STRING; a plural takes the raw number to choose its form, and is kept for counts
  of things a homelab has dozens of (applications, machines, accounts).
- **Every cookie-authenticated mutating call sends `x-hlb-ui`**, through the one client
  — never a bare `fetch`. And nothing mutates without `?apply=true`: loading a route
  issues reads only.
- **The inlang plugin is loaded from `node_modules`, pinned by `bun.lock`** — the
  scaffold had the build fetch it from a CDN at a floating major: code nobody locked,
  executed on every build, and a build that fails offline.
- **The shell is DERIVED from `src/lib/modules/*/module.ts`, walked by
  `import.meta.glob`.** A module declares its pages, the GET routes each reads, its
  inbox feeds and what `Ctrl+K` can find; navigation, tab bars, the inbox and the
  palette are built from that. Whether a page or a button is offered comes from
  `requires.ts`, generated from the document's `x-hlb-requires` — never a right written
  in TypeScript. `modules.test.ts` crosses the declared pages with the route folders
  under `(shell)` both ways; the three pages outside it (`/signup`, `/uptime`,
  `/kiosk`) are named there on purpose.
- **Every page reads through `read(path)`** (`resource.svelte.ts`): one shared
  `Resource` per route and parameters, numbered requests, a 10 s timeout, polling while
  something on screen watches it, and `Loaded.svelte` as the ONE place the loading,
  failed and stale states are worded. A page that fetched on its own would have its own
  idea of freshness.
- **Every action goes through `proposal()`** (`action.svelte.ts`): the request is built
  once from the route and its values, and the preview, the execution and the saved plan
  are three calls of that same value — which is what "rebuilt from the preview"
  protects, without parsing the command line back.
- **🔴 `$state` proxies what it holds, and identity stops matching.** The action panel
  dropped every preview — stuck on "asking the controller" — because `stage.proposal !==
  proposal` compared a proxy with the object it wraps. State compared by identity, and
  API data that is replaced rather than mutated, is `$state.raw`.
- **The controller allows 600 reads a minute per address**, and a household behind one
  NAT shares it. A steady shell costs ~60; 33 full reloads in a row spent it (measured
  2026-10-06). So polling stops in a hidden tab, and the start-up retries rather than
  leaving a dead page after one refused request. 🔴 The compiled files
  (`/_app/immutable/…`) are NOT counted (`throughput::exempt`): a first load asks for
  ~50, and counted, eight loads a minute spent the budget — every 429 the browser suite
  met on 2026-10-10 and 11 was that, not the API.
- **Stale data must never look fresh.** Every resource carries when it was last
  received; the controller being unreachable is shown, never papered over by the last
  known state — and the service worker never caches `/api/`.
- **Every page has a `<title>`, derived from the modules** by the shell, like the
  navigation; the pages outside it set their own. axe refuses a page without one.

## Learned on the first interface

Carried over from the egui interface, retired 2026-10-05: what the product owes the
people using it. Where an entry names a screen or a test, that is where it was learned.

- **Shared text must depend on NONE of its consumers.** Coherence messages carried a 🔴:
  fine in a terminal, a substitution box in egui. Severity travels through content and
  the caller's colour, never through a glyph.
- **A stale response must be DISCARDED, not adopted.** A request abandoned on timeout can
  arrive afterwards: without a turn number it is consumed as fresh, and the screen dates
  minutes-old data as now.
- **🔴 The service worker NEVER caches the API.** A data cache resurrects exactly the lie
  freshness exists to prevent: green apps served from cache while the cluster burns.
  There is no worker today; `e2e/crawl.spec.ts` reads every cache after visiting every
  page and refuses an entry under `/api/`, `/auth/` or `/metrics`, so it stays true when
  one arrives.
- **A written screen absent from navigation is wasted work.** The secrets screen was
  reachable only by typing the URL. A test crosses implemented screens with navigation
  entries.
- **Never offer a screen that does not exist.** An entry leading to "coming soon"
  promises, you click, you get nothing, and you doubt the rest.
- **A written screen deliberately out of navigation deserves its own test.** Otherwise
  the "every written screen is reachable" rule eventually adds an entry for it.
- **The action panel lives in the shell, not in a screen.** In the app detail, a preview
  triggered from the accounts screen fired with nothing displayed, and the click looked
  inert.
- **The request to apply is rebuilt from the PREVIEW**, never from state kept alongside:
  two sources diverge, and you apply something other than what you just read. An
  unrecognised action falls back to nothing — it returns 404, which shows.
- **⚠️ `replay()` has one non-`hlb` arm, and it is deliberate.** There is no `hlb node
  drain`, so the controller advertises `docker node update --availability <state> <id>`.
  Without an arm for it, the panel's Apply rebuilds `/api/unknown-action` and the action
  silently does nothing.
- **Confirmation comes from the PREVIEW, never fabricated by the interface.** The server
  says which target must be confirmed; the interface repeats it after the user has read
  what it destroys. Two states to keep in sync would eventually diverge.
- **Three beats, not two.** A button followed by a generic "Confirm?" says nothing about
  what is going to happen: you click by reflex and the protection stops protecting. The
  confirmation is about **the plan**.
- **A warning is NOT a blocker.** "This link will let five people in" filed under
  blockers made the action impossible — while it is a legitimate choice you simply want
  to see first. Two distinct fields, two shapes on screen.
