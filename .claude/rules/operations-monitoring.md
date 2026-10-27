---
paths:
  - "crates/hlb-agent/**/*.rs"
  - "crates/hlb-metrics/**/*.rs"
  - "crates/hlb-notify/**/*.rs"
  - "crates/hlb-controller/src/{agents,capacity,loops,metrics,mutes,notify,promql,timeline}.rs"
---

# Operations: watching the system

The agent, metrics, alerts, notifications and the screens read mid-outage. This is
where silence is cheapest: an unknown reads as calm unless the type forbids it.

## The watchdog

- **A periodic heartbeat proves nothing.** It attests that a thread is alive, not that
  the system works: the controller can have an unreadable database and a dead Docker and
  keep beating. The watchdog then stays green over an unusable system — **worse than no
  deadman, since you trust it**. The beat is conditional on a successful check, and
  silence is the signal.
- **The watchdog does not run on what it watches**, and does not alert through it. A
  deadman hosted by the controller dies with it; an alert relayed by the controller does
  not leave when the controller is what died. And a failing `curl` is swallowed by
  `>/dev/null 2>&1`: hence the fallback to stderr, which cron mails out.

## The agent and its readings

- **The agent protocol goes up, compatibility stays both ways.** Every added field is
  `Option` + `serde(default)`, and nothing is `deny_unknown_fields`: the controller can
  be updated before the agents or the reverse. Otherwise the first update makes the whole
  fleet "unreachable" — precisely when you need to see it.
- **The controller polls agents by IP; their certificates name hosts.** Verifying the IP
  failed every agent the day mTLS was on — the test that "proved" mTLS polled
  `localhost`. Each poll connects to the task's IP and verifies `tasks.<service>`.
- **A containerised agent measures itself** unless given the host: `--host-root /host`
  for the hostname, `df`, os-release, and `proc/1/net/dev` for the host's interfaces.
- **The CPU rate needs TWO readings.** `/proc/stat` is cumulative since boot: on the
  first pass the value is `None`, never `0.0` — "0 %" reads as "idle machine", the exact
  opposite of "I do not know". Same after a reboot, where counters go backwards: the
  subtraction is checked, not wrapped.
- **Load is only comparable divided by cores.** 4 is dramatic on one core and
  comfortable on sixteen; a homelab is made of heterogeneous machines.
- **Memory is measured on AVAILABLE, not free.** Linux caches everything it can: "free"
  is near zero on a healthy machine, and trusting it would cry out-of-memory permanently.
- **Swap starting to be used is a signal BEFORE the failure.** The machine slows without
  having fallen over yet. The threshold is low (5 %) for that reason.
- **The capacity budget does not add up.** A service is not split across two machines:
  two nodes with 400 MB free make 400 MB usable, not 800. A manifest's `memory.reserve`
  is compared with the largest node (catalog: required since 2026-10-19); one without it
  gets what is left on the tier, never a margin you do not have. "Left" is
  `MemAvailable`, what the kernel kills by — not Swarm's unreserved.
- **A node of unknown tier belongs to no tier.** Assuming otherwise announces space
  where there is none; a tier with no node makes `wait_healthy` expire without ever
  saying why.

## Metrics and alerts

- **Prometheus values are STRINGS, not numbers.** Read with `as_f64()` they are all
  `None`, and the curve is empty with no error at all.
- **An empty series is not a zero series.** A flat line reads as "all calm";
  `Series::Unavailable` is a distinct variant the type forces you to handle.
- **A non-evaluable rule is not a satisfied rule.** If collection fails, the unknown
  state surfaces at `Important` level — not at the rule's level, which would suggest the
  threshold is breached when you do not know whether it is.
- **`hlb_backup_copies` existed nowhere** while the `single-copy` rule queried it: the
  rule guarding 3-2-1 never fired once.
- **A muted alert stays DISPLAYED.** Muting silences the notification, not the screen:
  hiding it gives a green dashboard over a known, unresolved problem. A mute carries a
  deadline (a week at most, `hlb_api::MUTE_MAX_S`) and a reason, and the alert comes back
  whole afterwards.
- **A mute lives in `alert_mutes`, and NOWHERE else.** Until 2026-10-06 the evaluation
  loop kept the previous pass's mutes in memory: a restart lifted them all, and the
  first pass notified what had been silenced. The loop reads the table on every pass and
  `/api/alerts` at answer time, both through `ActiveAlert::apply_mutes`. ⚠️ It stores the
  RULE NAME: renaming a rule in `hlb-metrics` orphans every mute on it, and the renamed
  rule notifies again. An unknown name is refused by the route and the CLI, checked
  against `default_rules()`.

## Notifications

- **Quiet hours hold a notification, never drop it.** `send` answered a `bool`, and held
  read as said: an Important alert raised at night was never raised again, an update
  applied at 3 a.m. was marked notified. Held goes to `held_notifications` (one per
  subject) and `notify::Notifier::flush` sends it in the installation's morning — its
  `hlb config timezone`, never UTC. And a rule read as ONE number (`min(hlb_app_up)`)
  never said a second app was failing: the rules keep a series per subject, and the loop
  says a subject, or a level, it has not said yet.
- **An update said nowhere is silence.** Every outcome of `hlb update apply`, success
  included, is a row of `update_runs` the controller notifies once
  (`loops::notify_update_runs`); a notice ntfy refused stays unsent for the next pass.

## Read mid-outage

- **A causal chain you cannot follow stops.** On "unknown cause", never on a guess: a
  plausible but wrong diagnosis makes you repair the wrong thing, then doubt the screen.
  An alert is only attached if the node's own reading corroborates it.
- **A timeline source you cannot read must APPEAR.** Hiding it suggests "no human action
  preceded the outage" when you know nothing — and this screen is read mid-outage.
- **SQLite writes timestamps without a timezone or a "T".** Parsed strictly as RFC 3339,
  every row is `None` and the timeline is empty on healthy data.
