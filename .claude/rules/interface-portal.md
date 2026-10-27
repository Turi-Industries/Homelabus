---
paths:
  - "web/src/routes/*/{invitations,signup,roles,announcements,uptime,kiosk,me}/**"
  - "web/src/lib/modules/{people,me}/**"
  - "web/src/lib/ui/StatusBoard.svelte"
---

# Interface — the screens for the people, not the operators

Invitations and sign-up, announcements, the status page, the kiosk and the portal: the
screens read by someone who does not run the installation.

## Learned on the first interface

- **An invitation is NOT kept in local storage**, unlike the access token: it is used
  once, and a shared browser would offer it to the next person — whose account would
  then carry the role meant for someone else.
- **An invitation for N uses that leaks lets N people in.** The default stays 1, the
  remaining count is displayed, and a widely open link stands out visually — that is the
  one you forget to close.
- **Revoking an invitation EXHAUSTS it, does not delete it.** Deleting it would lose the
  trace of who created it and who already came in, at the exact moment you need it.
- **An invitation refused for a typo must NOT be consumed.** The name is validated
  first, or a single-use link is wasted on a capital letter.
- **The role is fixed at INVITATION time**, never chosen by the invitee: otherwise anyone
  would sign up as an administrator. Roles are data (`/api/access`): a form offering
  them reads that, and a page reading it outside `Loaded` must `watch()` it, or it is
  never asked for — the invitation's role list stayed empty until it did.
- **The sign-up screen has NEITHER navigation NOR a session header.** It addresses
  someone with no account: offering "Dashboard" would send them to a refusal, and
  showing the identity of whoever opened the link would be confusing at best.
- **An incident is FOLLOWED, not rewritten.** It is the chronology you re-read
  afterwards. And it stays open until someone closes it: silence must not pass for a
  resolution.
- **An announced maintenance is not an outage.** It was planned, and showing it as an
  outage sends people looking for what is wrong.
- **An announcement that does not concern its reader is noise.** Flooding a portal user
  with operational messages makes them stop reading — exactly when one will matter.
  Hence audience by role.
- **The status page is PRIVATE by default.** Published, it reveals the list of what runs
  at your place and the calendar of your outages. Open, it shows only **exposed**
  services — never nodes, backups or accounts.
- **The status page requires ReadSelf, not Read.** It is made for the people suffering
  the outage, not those operating it: requiring a console right would remove it from
  the portal, which is where people look for it.
- **🔴 `StatusPage.incidents` is the announcements, filtered.** `portal.rs::build_status`
  fills it from the same rows `/api/announcements` serves, keeping incident and
  maintenance level. Reading both on one screen lists every open incident twice. The
  duplicate exists so the status page has something to show a reader who cannot see
  `/api/announcements` at all — it is not a second source.
- **Homelabus ANNOUNCES applications, it does not grant access.** That comes from
  PocketID and forward-auth. And a link to a stopped app leads to an error page people
  read as a permissions problem.
- **Kiosk mode is an ALLOWLIST of screens, never a denylist.** A wall is visible to
  anyone in the room; you cannot enumerate what will be sensitive tomorrow, you can
  enumerate what is harmless today. A screen added later is excluded by default.
  🔴 And the wall is `inert`, not `pointer-events-none`: that stopped the pointer and
  left Tab and Enter to follow a card's link into the console, with the wall's session
  (found 2026-10-06 by `e2e/bare.spec.ts`).
