---
paths:
  - "crates/hlb-engine/src/ingress.rs"
  - "crates/hlb-ingress/**/*.rs"
  - "crates/hlb-controller/src/exposure.rs"
---

# Operations: routes and Caddy

Publishing routes, certificates, and checking what is actually exposed. Caddy refuses
some mistakes loudly; the others are a 502, or a door left open.

## Caddy

- **`*.example.org` does not cover `example.org`.** Both names must be requested.
- **🔴 Caddy runs `forward_auth` before every `handle`.** The portal's `handle /oauth2/*`
  was never reached: its sign-in page asked the portal, which sent it to the sign-in
  page — every sign-in looped, found at the lab's first one (2026-11-10), while
  `open_paths.rs` (a fake portal, a status read) and `live_portal_replicas.rs` (no
  Caddy) passed. `forward_auth` takes a matcher leaving out `PORTAL_PATHS` — the same
  `path` as the `handle`, so what skips the portal that way is answered by it.
- **Caddy's `status` matcher only exists inside a `forward_auth` block.** At site level,
  Caddy refuses to start with "module not registered".
- **A route beside a wildcard gets a certificate of its own.** A site block per host,
  next to a `*.example.org` block, made Caddy request one certificate per name over
  HTTP-01: the quota a wildcard spares, and the names in public CT logs. Every host the
  wildcard covers is a `handle @host` INSIDE its block — one label deep only.
- **A path a companion answers is the APP's route** (`ingress[].paths`), never a field of
  the companion. 🔴 Caddy runs `handle` before `respond`: the private ranges' 403 at
  the top of a route did not reach the path — tried, an outside client reached the
  companion of a private route — so it is said again inside the path's block. A named
  matcher (`/x` and `/x/*`), not `handle_path /x*`, which also takes `/xyz`.
- **A public name resolves where the router may not loop back.** An app reaching
  PocketID's issuer at its public address from inside the house depends on hairpin NAT,
  which many routers drop. The ingress answers to PocketID's name as a network alias,
  so on the overlay that name is Caddy — that one only: an alias is part of the task,
  and one per route restarted Caddy at every install.
- **🔴 A DNS provider's API can retire under a module that still builds.** `caddy-dns/
  hetzner` v1 spoke to `dns.hetzner.com`, which answers every call with a 301 to the
  console's home since Hetzner moved DNS into its Cloud: `caddy validate` passed, and no
  certificate could be renewed. v2 speaks to `api.hetzner.cloud`, with a Cloud token —
  a DNS console token is refused there. Stalwart's `dns-update` 0.5.9 speaks the same.
- **🔴 Relayed HTTPS reaches Caddy on 10443, never on 443.** The VPS's HAProxy sends
  the visitor's address in a PROXY header, and a hostile VPS forges any source in it —
  measured, a header claiming `192.168.1.5` was read as the client. Only the LISTENER
  tells relayed traffic apart: every site block is rendered twice, and on 10443 a
  private route refuses everyone. 🔴 Never `{http.request.local.port}`: behind
  `proxy_protocol` the local address is the header's destination — 443 as HAProxy
  writes it — and the lab's Vaultwarden, private, answered 200 through the VPS
  (`tests/relay_is_a_stranger.rs`, real HAProxy and Caddy). And `fallback_policy
  reject` did NOT refuse a LAN client sending no header on 10443 — the listener's own
  blocks are what close it. Without the header at all,
  every visitor would be `10.43.0.1`, which is why the site network is cut out of the
  private ranges.

- **🔴 An error is a NEW answer.** `handle_errors` starts from nothing: the route's
  `header` block (HSTS, `nosniff`, `-Server`) is gone and `Server: Caddy` is back, so
  the maintenance page says them again. It sees Caddy's own failures only — an app's
  own 502 passes through — and `{http.error.message}` is never shown: it holds the
  overlay's names and resolver (`tests/maintenance.rs`, real image).

## Publishing

- **A route change restarts nothing.** The Caddyfile lives in Caddy's `config` volume;
  a one-off job on its node runs `caddy validate` on the new one with the same binary
  and renames it into place, and Caddy (`--watch`) reloads it. Delivered as a Swarm
  secret, every change was a new task, and every site went down for a few seconds.
- **Every publication republishes everything, removal included.** A removed app's route
  stayed in the Caddyfile, answering 502 at its name; the controller published without
  the bouncer the CLI had set. One path, `hlb_engine::ingress::publish`, and it takes no
  CrowdSec address: a role change passed none and took the bouncer off every route. The
  address is the state's (`hlb crowdsec enroll --url`).
- **A route frozen before a rule changed still deploys.** Vikunja's chain named an
  Anubis the catalog never deployed: its route was a 502. Anubis is gone since: the
  catalog refuses a chain naming it, and a frozen manifest's route through it is
  withheld — published, it would lack the challenge it asks for — with `hlb upgrade`
  named.

## Checking the exposure

- **Comparing two computations from the SAME function can never fail.** The exposure
  screen compared manifests to `routes_from_manifest` applied to those same manifests:
  it would have shown "compliant" whatever happened. Compare what was ACTUALLY
  published with what the manifests ask for today.
- **An orphan route appears in no walk over installed apps.** A removed app whose route
  still answers is in no manifest, therefore in no loop: look for it from the PUBLISHED
  routes, not from the apps.
