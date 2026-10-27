---
paths:
  - "themes/*.yaml"
  - "crates/hlb-api/src/palette.rs"
  - "web/src/lib/theme.ts"
---

# Interface — palettes and themes

The palettes, the validator that judges them, and the theme a person chooses. How a
component uses the palette is in `interface-screens.md`.

## Decided for the web interface

- **⚠️ The accent is blue only within a band.** A mid blue merges with the cyan-leaning
  "ok" under tritanopia (#6AA6FF: 18, 60 needed); the dark theme's is light (#86B4F9)
  and the light theme's deep (#1A52B4). `Palette::validate` refuses the rest — try a
  colour against it before arguing for it.

## Learned on the first interface

- **A palette may not make states indistinguishable.** Traffic-light green and red
  converge under deuteranopia (distance 35, 60 needed): the two most important
  indicators were indistinguishable for 8 % of men. Green is shifted toward cyan and the
  accent is **cool** — the initial copper read as "critical". Not taste, a constraint,
  and the palette validator enforces it.
- **The theme is a NAME, not a palette.** A palette stored per person would survive the
  removal of the theme it came from, and you could no longer evolve it.
- **"The installation's own" is a distinct option**, not the absence of a choice: whoever
  picks it says "follow the brand", and their theme changes if the administrator changes
  the default.
- **An unknown theme is REFUSED, not silently accepted.** Accepted, it would be stored,
  fall back to the default on display, and you would think the choice was lost to a bug.
- **The theme list is declared ONCE**, in `hlb_api::THEMES`. Three places need it — the
  controller serves it, the CLI validates against it, the interface renders it — and
  none may depend on the others. It lived in the controller with a copy in the UI test,
  which is exactly what let them drift: a theme removed in one would keep being offered
  by another, and choosing it would silently give the default. ⚠️ These are stored
  VALUES (`user_prefs.theme`): renaming one orphans everyone who chose it.
