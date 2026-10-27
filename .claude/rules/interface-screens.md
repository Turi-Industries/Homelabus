---
paths:
  - "web/src/routes/**"
  - "web/src/lib/ui/**"
  - "web/src/lib/home/**"
  - "web/src/lib/listing*"
  - "web/src/app.css"
---

# Interface — screens, layout and the home

How a screen is laid out: lists, rows, modals, tabs, gauges and the home's tiles. The
palettes themselves are in `interface-themes.md`; the portal's screens in
`interface-portal.md`.

## Decided for the web interface

- **Tailwind 4, over the palette's CSS variables.** The twelve roles are `@theme`
  variables (`--color-ok`, `--color-critical`, `--color-surface`…) that the shell
  overwrites from `/api/themes` at run time; components use `bg-surface`,
  `text-critical`. A hex value or a stock colour (`text-red-500`) is a colour no theme —
  and no palette check — controls: the colour-blind separation the server validates
  stops applying the moment one is written.
- **🔴 In a wrapping row, what yields is `grow basis-48`, never `flex-1`.** `flex-1` is
  a basis of 0, and a `flex-wrap` line breaks on the basis: zero always fits, so the row
  NEVER wraps and the text is squeezed to a word per line beside its badge and buttons.
  Nothing overflows, so the crawl's 360 px check cannot see it — the contact sheet found
  it; `src/rows.test.ts` then found 17 sites with Svelte's parser, `Row` itself through
  the snippet it renders, and refuses the next. Commands wrap with `wrap-anywhere`, not
  `break-all`, which cut `--root apps` into `app s`.
- **A list people compare is a `Table`, narrowed by `listing.ts`.** Cards are for
  things unlike each other — the launcher, the home's widgets; a list of like rows as
  cards is ~320 px a row, and 1,000 accounts were 174 screens. The search, filters,
  sort and page live in the query string (`parse`/`write`), never in component state:
  a filtered view must survive a reload and Back. A figure that can pass 999 enters a
  message through `number()`, the count included.
- **A list that only grows is narrowed by the SERVER** (`/api/audit?q&outcome&page`
  answers `AuditPage` with `matched` and `total`), and `Table` takes `paged` for it.
  ⚠️ Such a page reads a different resource for every search: it HOLDS the last page
  received and draws it until the next arrives, or `Loaded` falls back to "loading…"
  and takes the search field being typed in with it.
- **A list cut by a `LIMIT` says so, or is not cut.** Invitations stopped at 100 and
  both CSV exports at 5,000, with nothing on screen to say it: a page that reads "100
  invitations" is believed. A window is stated ("the latest 200 runs — the whole
  history is in the CSV"), and an export is whole.
- **What a button opens is a `Modal`, never unfolded into the page.** Unfolded, a form
  pushed down the list it belongs to, or appeared above a list scrolled past it, out of
  sight of its button. `Modal` does not close on a click beside it, like the action
  panel: a stray click would take a key shown once with it. `src/disclosures.test.ts`
  refuses an `{#if}` on a clicked `$state` holding a control outside a dialog, and a
  `<details>` holding one. ⚠️ It does not scope names: an `{@const}` derived from a
  clicked state taints a snippet parameter of the same name — rename the const.
- **The home is one screen of tiles** (`e2e/home.spec.ts`, at four sizes from a tablet
  to a wide screen). Every card is a `HomeWidget` tile with a size a person picks
  (`hlb_api::HomeTile`, 1–4 columns × 1–3 rows, bounds served through `limits.ts`); the
  inbox is one of them (`problems`), and `HomeTile::DEFAULT` is the four by three of a
  wide screen exactly: figures, problems, applications, processors, memory, disks.
  `home/layout.ts` packs them in order, grows neighbours into any gap, and falls back to
  bands that cannot leave one — 20,000 random layouts hold no hole (`layout.test.ts`).
  The grid takes a HEIGHT, the screen's: under a min-height, rows grew to hold
  twenty-one problems and the home was three screens. A long list scrolls inside its
  tile, and 🔴 every scrolling tile is `relative`: a `sr-only` word is absolutely
  placed, escapes an unpositioned scroller and lengthens the page by the list it was
  clipped from. ⚠️ The columns follow the GRID's width, not the window's: beside the
  navigation, a 1280 px screen leaves 960. A line set aside (`/api/issues/aside`) stays
  LISTED, folded, and comes back by itself when it covers more or gets more serious.
- **A state is a dot and a word** (`Mark`), never a pill: a column of pills is a column
  of borders, and "action required" repeated sixteen times said nothing. Where the
  inbox knows WHY, say why (`causes.ts::reason`, `PageHeader`).
- **Colour is the dot's, the figure is the text's.** A count in the navigation or on a
  home tile is a coloured dot beside a number in the text's colour: seven red pills down
  the side said "alarm" seven times and nothing about which. 🔴 A tile, a count or a
  card says NOTHING until its source is read — the strip said "nothing to report" while
  the inbox was still loading, the all-clear over no information.
- **🔴 ONE card is about problems: `problems`, the inbox.** Every other card says what
  the installation IS — figures (`summary`), the applications and whether they run,
  each machine's processor, memory and disks (the nodes page's `Gauge` and `Disk`, the
  disk's colour the server's pressure step), availability by day, the latest backups,
  public addresses, Swarm's services, the cluster's shape, the people. A card that
  counted what is wrong — a module strip of counts, a bar split by `attention` with
  "needs action: 8" under it — restated the inbox, and was taken out on 2026-10-10 at
  the user's request (`Figure` with it). A figure on a card is a link to its page,
  which is also what makes a tile that scrolls reachable by keyboard (axe
  `scrollable-region-focusable`).
- **The home's curves are the controller's own day of measurements** (`history.rs`,
  table `history`, one a minute, kept a day): nothing installed beside it, and the
  demonstration seeds its day from what its machines report now. ONE request answers
  every metric (`/api/history?window=`), read once a minute (`SLOWER` in
  `resource.svelte.ts`) — six separate reads every 15 s spent the empty controller's
  budget in the browser suite, and a household's shared one. ONE period for every
  curve, in the address (`?window=`), above the tiles. A curve per machine, one ink
  (`Sparkline`): the accent, and the muted ink for a second line (swap, sent) — never
  a status colour. 🔴 A silence longer than the line's own rhythm is a GAP, never
  joined: the threshold is the step or the line's usual spacing, whichever is longer —
  on the step alone, a demonstration measured every five minutes drew six hours of
  dots. A counter (network bytes) is a rate when read, and a restart gives no point
  rather than a negative one. A curve inside a link is `quiet`: no focus of its own.

## Learned on the first interface

- **Each quantity has its own colour thresholds.** Seen on screen: with the CPU scale, a
  swap at 71 % showed GREEN — a machine already swapping 70 % is crawling. Sharing one
  hue function across CPU, memory and swap is an economy that lies.
- **An unreachable node must show NO gauge.** It does not have bad numbers, it has none:
  bars at zero would read as "idle machine". Show the reason and stop there.
- **🔴 A right-margin item that does not fit must wrap, not widen the page.** Seen at
  380 pt: one label-and-value row that could not share its line pushed its card past the
  viewport, the scroll area grew with it, and **every other card on the screen was
  clipped by that one row**. In CSS the same shape is a flex child at its default
  `min-width: auto`. Stack the two halves when they do not fit — triggered by the text,
  never by a "narrow" breakpoint — and give a badge, a wrapping label and a button
  separate lines rather than a reserved width a longer translation breaks. ⚠️ Invisible
  at desktop width: look at the narrow column.
- **A figure on the dashboard is a link, and the TYPE says so.** In egui, `Tile` and
  `Row` carried a `to: Route` that was not an `Option`, so a figure with no destination
  could not be built, and one `rows()` helper was the only way a row reached the screen.
  The corollary decides the layout: **a section that cannot be made clickable does not
  go on the dashboard.** Storage is the case that fired — no endpoint serves it, so a
  disk figure would lead nowhere, and it stays off until one does. ⚠️ A destination is
  checked against the URL parser, not just the compiler: a route that renders to a path
  the parser refuses is a link to a screen that is not there.
- **A row carrying a button is not also a click target.** The button and the row compete
  for the same press and the winner is whatever was laid out on top. The dashboard's
  manual actions are the case: the rows carry Attest, and the figure that links is the
  tile above them.
- **Every tab offered is written, and the TYPE CHECKER is what says so.** The app
  detail declared seven tabs and offered four, filtered through a hand-maintained
  `implemented()` list — a catch-all with extra steps, already drifted: it named six of
  the seven. 🔴 A tab nobody offers is not invisible, it is URL-reachable:
  `/apps/gitea/logs` rendered a header, a tab bar and "not written yet". In TypeScript:
  a union of the tabs that exist, a `switch` ending on `const _: never = tab`, no
  `default:`, no `.filter()` on the bar — and a test that reads the labels back from
  the rendered page in the EMPTY state, which also guards "chrome does not depend on
  data".
- **A tab is decided by its DATA SOURCE, not by how much work it looks like.** The three
  removed above each failed that question differently: `Logs` had no endpoint and no
  producer to build one on, `Updates` would have rendered the dataset `History` already
  renders, and `Metrics`' two per-app series were both already on screen in a better
  form. ⚠️ `promql.rs` allowlists `container_*` and `hlb-agent`'s doc comment calls
  cadvisor "deployed as a catalog app" — **it is not in the catalog**. An allowlist
  entry is not evidence the metric exists.
- **Chrome does not depend on data.** Two screens drew their tab bar after the early
  return on missing data, so the tabs vanished exactly when the controller was slow — on
  the screen you are looking at *because* it is slow. The strip is one call, made before
  the guard.
- **One value is asked ONCE.** The invitation form put `[7 days]` beside a field reading
  `168 h`, with a separator between them saying they were two controls. Presets and
  their exact field are one control, labelled by one formatter — so they cannot
  disagree, and a preset the field would re-express in another unit is changed rather
  than kept.
- **An inline error must have something TRUE to say.** Four forms took text input, and
  three had no rule beyond the controller's own "not empty" — an error there either
  repeats the disabled button or invents a refusal the server will not make. The storage
  wizard earns one: it ASSEMBLES a command line you copy, so a space in a value is
  `--pool my pool` rejected by clap after the paste, and nothing else catches it because
  the server never sees that form.
- **Scaling to zero replicas is not a resize, it is a shutdown.** Refused from a numeric
  field, where it never happens on purpose.
- **A wizard not tried end to end ships something false.** The Bitwarden wizard bound
  the MAILBOX and not the ACCOUNT: its token was refused by the alias API, with six
  reassuring steps sending you to look at Bitwarden. Found by actually calling
  `/api/v1/aliases` with the token it produced.
- **A QR code is painted, not written.** No font is involved, therefore no tofu. The
  module must be a WHOLE number of pixels — fractional, the renderer smooths the edges,
  squares blend and the code becomes unreadable to a scanner while looking crisp to the
  eye (in a browser: an SVG with `shape-rendering: crispEdges`, or integer scaling).
  The 4-module quiet zone is mandatory: it is the most frequent cause of a QR that
  "only works on some phones".
