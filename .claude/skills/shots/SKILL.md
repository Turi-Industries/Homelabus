---
name: shots
description: Photograph every screen of the interface and lay them out on one page.
---

```sh
cd web && bun run shots
xdg-open ../target/shots/index.html
```

Builds the interface, starts the browser suite's three controllers (the `--demo` one,
an empty one and `--demo-scale large` — a thousand accounts — ports 8431, 8432 and
8435, so not while `bun run test:browser` runs) and photographs every screen in every
theme, both languages, at 1280 px and 360 px: **1,824 images in under three minutes**,
in `target/shots/`. The run ends by naming the tallest screens, in screens of their
width — a page read without scrolling is 1; the accounts at a thousand were 174. The page groups them one
section per screen, with filters for data, theme, language and width. A screen is a
route folder, its `[[tab]]` kept; which application a detail names is not.

🔴 **Nothing is compared, and a picture can never fail this.** It exists so that
LOOKING is cheap — every purely visual defect this project has had was found by looking
at a screenshot. What does fail it: a route folder no link reached (the floor), a thrown
error, or a 429 — that last one means the picture would be of the refusal.

When asked to review the result, open the images rather than report that the command
succeeded. `target/` cannot be read directly: tile the images into the scratchpad first
(`magick … +append`). Look at the **narrow French** column first — it is where the
longest words meet the least room, and where each of the first review's worst defects
was. Look for:

- text squeezed to a word per line beside a badge or a button (a `flex-1` in a
  wrapping row: its basis is 0, so the row never wraps)
- a verdict or a button pushed off to the right, or into a sideways scroller
- a command broken inside a word
- a badge stretched to the width of its container
- English on a French screen beyond what the server writes, which stays English
- a state that reads wrong — "fine" over nothing, a count that disagrees with its page
- an empty state that looks like a broken screen rather than a deliberate one
