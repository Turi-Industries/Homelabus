---
paths:
  - "crates/hlb-engine/**/*.rs"
  - "crates/hlb-state/**/*.rs"
  - "crates/hlb-guide/**/*.rs"
  - "crates/hlb-controller/src/*.rs"
---

# Operations: deploying and reconciling

The executor, the journal, guides, reconciliation, plans and runbooks. The Swarm,
monitoring, updates and routes have their own `operations-*.md`.

## Deploying an app

- **Provisioning is not connecting.** The resolver created the database, the isolated
  role and the password, then deployed the app without telling it anything: it fell back
  to its internal SQLite. Healthy service, green probe, green dashboard — and the data in
  a file nobody backed up, while an empty database was faithfully dumped every night.
  Hence `spec.env` and binding tokens.
- **A declared field nobody reads is found by deploying.** `publishedPorts` was validated
  and never reached Swarm (host mode now: ingress would hide the client's address);
  `runtime: compose` was ignored and Stalwart went to the Swarm with its setup page
  open — the resolver refuses it.
- **`{{ … }}` in a service's environment is Swarm's own template.** A guide variable
  nothing filled (`{{ base_domain }}`) reached Swarm, which refused the service:
  "function not defined". A test holds every guide template to `GUIDE_VARS`.
- **A missing companion is invisible.** Immich without its machine-learning service
  imports and displays photos perfectly, and never recognises anyone. Hence deploying the
  companion BEFORE the app, waiting for it to become healthy, and a guide step that makes
  you check it really works.
- **An app whose services are not there is refused at preview.** On a bare machine
  Vikunja's preview listed a database, a client and an account, three ended unimplemented,
  and Docker refused a `{{ smtp.from }}` nothing filled (2026-11-04, the first timed
  deployment). `ingress::app_blockers` asks Swarm for each `platform_service()`; a service
  gone from Swarm and recorded `running` counts, since a failover removes the old
  primary's and the standby answers to its name.
- **Secrets before companions.** The resolver deployed companions first and generated
  the secrets after: Seafile's notification server would have started with
  `{{ secret.jwt-key }}` as its key. Generated secrets are scanned from the app's
  variables, its files and its companions', and planned before either.
- **Removing an app removes its companions.** Both removals took the app's own service
  alone, and Immich's machine-learning service stayed running, managed by nobody; an
  install that failed before its app's service existed could not be removed at all
  ("service not found"). `hlb_engine::remove_services` serves the CLI and the controller.
  🔴 And the Swarm secrets its files rode on: the preview said "nothing will be left"
  while Anubis's signing key stayed in the Swarm and in the vault (2026-11-04).
  `SwarmOrchestrator::remove` takes every version of them. The vault's are kept, and the
  preview says so — a volume or a backup kept was written with them; `hlb secrets-forget`
  deletes them, for an app the audit log shows removed and not installed again. 🔴 So do
  its database and role, its OIDC client or portal callback, its bucket and key, its mail
  accounts: no removal touches them, and until 2026-11-04 no preview named them
  (`removal::kept_elsewhere`, an exhaustive match). A reinstall finds them again. After
  `secrets-forget`, a role takes the newly drawn password at `provision`, where it kept
  the old one and the app was refused. 🔴 A secret forgotten alone leaves an OIDC client,
  a Garage key or an SMTP account a reinstall stops on: `secrets-forget` deletes those and
  the portal's callback first (`removal::Leftover`), each secret only once its other half
  is gone, so a refusal resumes. Data stays: the database, the bucket, and an SMTP account
  that is also the mail account. Each is proved the app's before it goes — the client's and
  the key's id against the vault's, the account by its password and no owner, since an
  address is handed out again. `forget_app` keeps the domain of an app behind the portal
  (`removed-domains:<app>`): nothing else remembers the callback's URL. 🔴 The portal's
  last callback stays: PocketID 2.0 saves the first callback asked of a client with none,
  2.18 refuses (read from the sources), and a pinned one stays older. A service no longer
  installed is not asked: the vault keeps its access, so a client was built, timed out,
  and the secret stayed for ever. Reconciliation reports a callback no installed app has
  (`Drift::OrphanCallback`, an app removed before its domain was kept, or moved) and
  leaves it: one added by hand reads the same. `hlb portal drop-callback` takes it off.
- **A scheduled job runs in its app's own container** (`spec.jobs`, `hlb_engine::jobs`),
  looked at hourly and run when due; a failed run is tried again a day later, kept as
  failed until one succeeds, in the inbox (`job_failed`) and notified. An app whose plan
  failed has its jobs wait.

## The journal

- **The journal's progress follows the ACTION, not its seq.** Matched by position, an
  action inserted mid-plan sat on a done row and was skipped (`record_plan`,
  `completed_actions`); and a preview records nothing at all — no app, no journal, no
  guide.
- **🔴 A run resuming after a failure is installing, not failed.** The routes leave a
  failed app out, so its own route step republished everything but itself — taking away
  the route it had — and the run ended "running" with the app unreachable (found on the
  lab, 2026-10-18). The executor marks it `installing` before it starts.
- **`record_verification` inferred failure from the presence of a detail.** A successful
  verification described in detail was recorded as a failure, and the app stayed "never
  verified" forever. `succeeded: bool` is a first-class argument.
- **A dependency cycle reveals where code should live.** `hlb-state` cannot implement a
  trait from `hlb-backup` (which depends on `hlb-updater`, which depends on `hlb-state`).
  The adapter goes in `hlb-backup-run`, which depends on both and serves the CLI and the
  controller alike — and the logic stays in `hlb-backup`, testable in memory.

## Reconciliation

- **🔴 A decision kept in Swarm alone is drift to the next pass.** `hlb stop` scaled to
  zero and recorded nothing: reconciliation read the zero against the manifest and
  started the app again within a minute. Stop and scale write `apps.replicas`, which
  reconciliation and every deployment of the app's own service read over the manifest.
- **Reconciliation's non-actions were invisible.** Nothing distinguished "there is
  nothing to do" from "there is something and I deliberately chose not to touch it". The
  refusal names the reason, and a test requires correctable and refused to be exactly
  complementary. A refusal is painted GREEN: it is a decision, not a failure — 🔴
  unless what it refuses to touch is broken (`Drift::harm`, an exhaustive match). Read
  from the refusal alone, the lab's Fluxer without its Garage key was green on `/drift`,
  and the issues list drops green: nothing else said a word. A missing service is
  `Broken` too, `StorageUnread` `Unknown` (amber).
- **🔴 A service stopped for a while is HELD, or reconciliation starts it.** A restore
  scaled the app to zero and recorded nothing: with `--reconcile-apply` (60 s) it came
  back onto a volume half written. `restore::stop` holds what it stops
  (`State::hold_services`, `Drift::Held`), `restore::start` releases it whatever
  happened; a hold lapses after a day, for a process that died holding it.
- **Reconciliation does not recreate a deleted service.** It did, from the image and the
  tier alone — no volume, no environment, no probe — and reported "1 gap corrected". The
  drift is reported with its refusal; `hlb install <app> --apply` redeploys a service
  marked done and gone since, whole.
- **🔴 A Garage that lost an app's buckets or key is no service's gap.** Wiped and
  rebuilt, it left Fluxer 1/1 against `No such key` while reconciliation saw every
  service in place. Each pass reads Garage's buckets and keys once (`StoreInventory`)
  against each running app's (`app_buckets`) and the key id it signs with:
  `StorageLost`, refused, its `fix` the redeploy then one restore per BUCKET backed up
  — never `<app> <app>`, a bucket has its own name. Garage silent is `StorageUnread`,
  never "all there". The runbook prints the same recovery from the installed apps.

## Guides and what an app holds open

- **A prerequisite handled once is read again** (a guide step's `recheck`, pre-install
  only, never sooner than 24 h): the controller's nightly pass re-runs the step's check
  and puts it back in the inbox when it fails twice in a row
  (`hlb_engine::recheck_guides`). An attestation forced against a failing check (`hlb ack
  --force`, the interface's `force`) is recorded so (`pending_guides.forced`) and left as
  said, until the first night its check agrees: established from then on.
- **A setting is judged by its effect, every night** (`spec.assertions`,
  `hlb_guide::assertions`). A sibling installation ran with sign-up open while its files
  said closed; Vaultwarden's `SIGNUPS_DOMAINS_WHITELIST` reopens what
  `SIGNUPS_ALLOWED=false` closed, and its `config.json` beats both — `/api/config` says
  which won. An assertion reads the app's own endpoint on the overlay (never through
  Caddy, whose portal would answer for it), the running TASK's environment, or one
  `SELECT` in a read-only transaction. 🔴 Never read, or not for two days, is `unknown`
  — a door nobody looked at is not a closed one — and a 500 where a body was to be read
  is `unknown` too, never "broken" nor "fine". An assertion's `fix` is said beside it
  while it does not hold: Seafile's default administrator was reported for nine days
  with no way given to close it. And an installation that began before a catalog fix
  keeps the door until `hlb upgrade` — the lab's Jellyfin still had its first-run
  wizard open to the first visitor on 2026-10-27.
- **What follows a restore is the restore's, never an install's** (`phase:
  post-restore`). Fluxer's message search is rebuilt from the database and Seafile's
  libraries checked against their blocks only after `hlb backup restore` started the
  app again: run at install, the first rebuilds nothing. The resolver leaves the phase
  out of every plan; the restore waits for each step's service (an `exec` names a
  companion by `service`) and fails when a step does. 🔴 Both upstream commands exit 0
  whatever they found — Fluxer's relay on a `relay_error`, `seaf-fsck.sh` on damaged
  blocks — so each step judges its output in `sh -c`, the damage sent to stderr where
  the refusal reads its first line (from another node both streams come back as one).
  And a 200 that QUEUES work is not the work: Fluxer's refresh is followed to its
  job's end, which on the lab is a failure its api never mentioned.
- **A first-run wizard belongs to whoever reaches it first.** n8n's `/rest/owner/setup`
  and Jellyfin's `/Startup/User` take no authentication until done: the guide's `api`
  step runs them after `WaitHealthy` and before any route, with a generated password —
  and a `probe` first, because a second call is refused (n8n: 400) or, worse, accepted.
  An answer's body is never echoed in a refusal: it can carry the password sent.
- **Healthy is not ready.** n8n 1.123 says 200 on `/healthz` and `/healthz/readiness`,
  then answers every route with its starting page (`200 text/html`), then 404s them —
  for minutes: n8n 2's first start ran 300 migrations. A guide `api` step with a probe
  waits until the probe reads as JSON, and is done only when the probe then says so; a
  2xx page is never an API's answer.
- **A claim read at an account's creation changes nothing after it.** Immich v3.1.0
  reads `immich_role` at every sign-in and `immich_quota` only when it creates the
  account: a quota is kept in step by `access.quota.apply` — one `UPDATE` on its own
  table, or a command in its container (Seafile's per-role quotas are Pro;
  `seafile_api.set_user_quota` through its RPC socket is the Community edition's).
  Someone who never signed in has no account to set: retried, never failed.
- **Gitea, Termix and Grafana take ONE admin group, exact** — a claim of each app's own
  (`hlb_gitea`, `hlb_termix`, `hlb_grafana`), valued by the role's level, never the
  roles' groups. Gitea's team map needs organisations and teams that already exist, and
  skips the rest with a log warning.

## Plans, runbooks and exports

- **A named plan is replayed AS PREVIEWED**, never recomputed: two computations at two
  moments can diverge, and you would execute something other than what you read.
  Replaying reruns the preview, not the execution. A plan targeting an unknown route is
  refused AT SAVE TIME — accepted, it would fail weeks later on a 404 pointing nowhere.
  🔴 A plan names only a route WITH a preview, and not a public one (`plannable`):
  replayed with `apply=false`, a route declaring none acts anyway — the Bitwarden
  assistant would mint a token — and a public route's body carries what opens it
  (a sign-up's invitation), on a list every viewer reads. A segment a fetch resolves
  or cuts (`..`, `?`, `#`, `//`) is refused too: it would address another route.
- **A path template is compared segment by segment.** A prefix comparison would let
  `/api/apps/gitea/install/really` through, which does not exist.
- **A runbook written by hand is wrong the day you need it.** This one is generated from
  real state, carries its date, and contains NO secret — it is meant to be printed and
  stored elsewhere. When the restart order cannot be computed, the REASON is printed:
  "garage is missing" can be fixed, "the order could not be computed" cannot.
- **A CSV field that is not quoted shifts every following column.** The audit log holds
  details written by humans: commas and quotes are the norm. And the line ending is
  CRLF, or Excel merges rows.

## The power

- **NUT is READ, never driven** (`hlb_engine::power`, `hlb-privd`'s `daemon::power`,
  `HLB_UPS_SECS`): `GET VAR`, which `upsd` answers without an account. The machines are
  shut down by NUT's own `upsmon` at low battery; what Homelabus adds is that nothing
  writes by then. 🔴 A UPS NUT lost (`DRIVER-NOT-CONNECTED`, `DATA-STALE`) is an error,
  never "on the mains", and an unreadable UPS decides nothing — no app stops on a server
  that does not answer, none starts again (`ups_unknown` after five minutes).
- **The waves come from the capability graph, consumers first**
  (`DependencyGraph::shutdown_waves`): every app nothing uses in wave one — ntfy among
  them, so the stop is said BEFORE the first wave — the databases once their last
  consumer is gone. A service at 0 replicas (a person's stop) is left out: started after
  the power, it would undo that person's decision. Started again in reverse, each wave
  given 180 s to run before the next. 🔴 Nothing that changes the house BEGINS while a
  stop is under way (`power::under_way`): the hourly update pass ran mid-stop on the lab
  (2026-11-08) and dumped Mealie towards a stopped PostgreSQL; a planned reboot waits too.
- **🔴 The stop is written BEFORE anything stops** (`power_stop`: waves and replicas):
  the battery may run out mid-wave, and Swarm says 0 by the time the daemon is back. A
  stop begun is always finished, from the row; a wave that does not stop whole is said
  and passed — waiting on it spends the battery the next ones need. Each service is
  HELD (`restore::stop_held`, 30 days, `power: …`), and while stopped every pass puts
  down again what something else started: a backup's copy or a restore ending starts its
  services and releases their hold. `hlb config ups --off` mid-stop starts the apps.
- **Each node's `upsmon` is a secondary Homelabus writes** (`hlb_bootstrap::nut`, `hlb
  config ups --shutdown-user`), never over a NUT a person set up: the machine serving
  the UPS runs the primary, which cuts the power after the secondaries are down —
  rewritten, the UPS would have nobody to cut it. Measured on `nut-client` 2.8.0: a
  secondary at `OB LB` waits HOSTSYNC (15 s) for the primary's FSD, then runs its
  `SHUTDOWNCMD`. 🔴 upsd takes a quoted password with a space, and `upsmon` sends it
  BARE (`ERR INVALID-ARGUMENT`): proved quoted, the account would fail on every node in
  silence. `check_login` signs in exactly as upsmon does, and `unusable` refuses a space,
  a quote, a backslash or `#` first. NUT's `LIST CLIENT` is the proof each node signed in.
- **NUT 2.8's `dummy-ups` reads its `.dev` file ONCE** (`mode dummy-once`): a status
  changes with `upsrw -s ups.status=…` (`tests/live_nut.rs`, its Dockerfile beside it).

## Invariants, encoded in tests

If one of these tests fails, the code is usually wrong, not the test.

- **Reconciliation never deletes an orphan, never resurrects a failed install, and
  never forces a convergence in flight.** A system that over-corrects is more dangerous
  than one that corrects nothing. Key distinction: the Swarm *instruction*
  (`desired_replicas`) comes from a decision and gets corrected; *progress*
  (`running_replicas`) is transient and gets left alone.
- **A prerequisite stops the install; a post-install step holds back the route.**
  `phase: pre-install` + `blocking` (a DNS record, an account at a provider) stops
  before any modification — after its `verify:` is tried, so a wildcard record
  satisfies "create the DNS record" by itself. A blocking step of any other phase
  ("print the recovery codes", "close sign-ups") cannot be done before the app runs:
  counted before, it made PocketID and every `after-guide` app impossible to install
  until someone attested undone work. It keeps an `after-guide` route private instead.
