---
paths:
  - "web/e2e/**"
  - "web/playwright*.ts"
---

# Interface — the browser tests and the contact sheet

`web/e2e/`: the Playwright suite against real controllers, and `bun run shots`.

## Decided for the web interface

- **The browser tests run against REAL controllers** (`web/e2e/`, `bun run
  test:browser`): `--demo` for the populated case and a fresh state for the empty one,
  started by `cargo run` so the binary is never older than the source. A stubbed answer
  is a second definition of the API. 🔴 The household demonstration has FOUR accounts,
  and a screen of cards reads fine at four: only `--demo-scale large` (1,000 accounts,
  300 invitations, 5,000 audit entries, 12 machines) shows what a list costs — 174
  screens of accounts, measured 2026-10-07. The crawl follows links from the home and
  its floor is every `+page.svelte`, walked: a page no link reaches fails it, and the
  three outside the shell are visited by address because that is what they are for.
- **🔴 SvelteKit draws AFTER the `load` event `goto` waits for.** "Nothing is
  `aria-busy`" is true of an empty document, and a test waiting on it alone checks a
  blank page and passes. `e2e/settle.ts` also requires a `<main>` — every page, the
  error page included, has one — and the start-up's "connecting…" is `aria-busy`.
- **The crawl moves through the router, not by reloading.** A reload per page restarts
  the shell and its feeds, and 85 of them spend the 600-reads-a-minute budget that a
  test then reads as a 429.
- **The contact sheet is `bun run shots`** (`e2e/shots.ts`, `/shots`): every screen ×
  theme × language × width, against the same controllers plus `--demo-scale large`,
  under three minutes. It fails on a hole, never on a picture, and ends by naming the
  tallest screens in screens of their width. It plays a `--trusted-proxy` and shows each
  combination to a different `X-Forwarded-For`: one person spends the read budget in
  about one theme and language. ⚠️ It photographs on a viewport as tall as the page, not
  with `fullPage`, which stitches under an 800 px `dvh` and cuts the sticky navigation
  short. 🔴 None of the home's cards is pinned by default, so the sheet adds
  `home+cards`, the home with every card pinned: until it did, no card had ever been
  photographed.

## Learned on the first interface

- **A screen can compile and PANIC AT RENDER.** An out-of-bounds index in a display loop
  only shows when you open the screen — and out of twenty screens, the broken one is
  rarely the one you look at; egui's suite rendered them all offscreen, empty and
  narrow. Purely VISUAL defects, on the other hand, were all found by looking at a
  screenshot, never by comparing two images.
