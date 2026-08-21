# Security policy

Homelabus provisions databases, issues OIDC clients, holds an encrypted secret vault
and drives backups. A bug in the wrong place does not crash a service — it silently
stops protecting one. Reports are welcome.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private reporting instead:
[Security → Report a vulnerability](https://github.com/Turi-Industries/Homelabus/security/advisories/new).

Please include the version or commit, what an attacker can reach, and a way to
reproduce it. A proof of concept helps but is not required — a clear description of
the reasoning is enough to get started.

This is a personal project, not a funded one. Expect a first reply within a week and
no bug bounty.

## Scope

The parts worth attacking first, and what is meant to hold:

| Area | The property that must hold |
|---|---|
| Secret vault (`hlb-secrets`) | Secrets are encrypted at rest with an `age` key that never enters a plan, the state database, or the Git mirror |
| API authorization (`hlb-types::rbac`) | Every mutating route carries its required role in the *type* of its argument, so it cannot be forgotten |
| API tokens | Only a SHA-256 fingerprint is stored; a leak of the database reveals that a token exists, never its value |
| Session cookies | `Secure` follows the public URL, and every cookie-borne mutation requires the `X-HLB-UI` header — `SameSite=Lax` alone does not stop CSRF |
| Forward-auth (`hlb-ingress`) | Incoming identity headers are erased before proxying, so `curl -H "X-Auth-Request-User: admin"` cannot impersonate anyone |
| Database provisioning (`hlb-platform`) | Each application gets an isolated role; a compromised app cannot read another app's data. This is proven by an integration test, not assumed |
| Object storage (`hlb-objstore`) | An app gets `read` + `write` on its bucket, never `owner` — an owner could delete the bucket its backups protect |
| PromQL relay | An allowlist of metric prefixes. An open relay would return the whole installation's topology to anyone holding a `viewer` token |

## Out of scope

- Anything requiring physical access to a node, or an existing root shell on one.
- Denial of service through resource exhaustion on a self-hosted cluster you own.
- Missing hardening on the *upstream* images in `catalog/` — report those upstream.
- The known gaps already documented in the README under "Known limitations".
  `Unimplemented` is never reported as `Done`, and that is deliberate.

## Handling of secrets in this repository

The repository must never contain a real key. `.gitignore` covers `hlb-master.key` and
`*.key`, and the only private-key strings in the history are test fixtures in
`crates/hlb-agent/`.

If you ever find a real credential committed here, treat it as compromised and report
it privately — rotating it matters more than removing it from history, because history
can be cloned before it is purged.
