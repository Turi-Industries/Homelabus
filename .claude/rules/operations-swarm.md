---
paths:
  - "crates/hlb-orchestrator/**/*.rs"
  - "crates/hlb-mesh/**/*.rs"
---

# Operations: the Swarm

Placement, failure domains, the overlay, and what a service needs to run under Swarm.
Most of these fail behind a healthy task.

## Tasks, nodes and placement

- **A Swarm task names its service and its node by ID.** The service's name label is on
  the container, never on the task; a node's hostname is on the node. Passed through,
  every screen listed `mky0…` and the node screens and the causal chain attributed
  nothing to any machine — only the demo's fabricated tasks named hostnames.
  `read_tasks` translates the service, `api::task_summaries` the node.
- **Counting Swarm tasks**: filter on `desired-state` **and** the actual state. Swarm
  keeps the history of dead tasks, which you would otherwise count as alive.
- **A dead Swarm task is not a stopped task.** `desired_state` AND `state` decide whether
  it lives; but a deliberately stopped task (update, scale-down) is not a failure —
  counted as one, the dashboard blinks on every normal deploy and you stop looking at it.
- **🔴 A task told to stop is not stopped.** A scale to zero turns each task's desired
  state to `remove` at once, while its container runs its stop for seconds more ("Remove
  / Running", lab 2026-11-08): `running_replicas` reads 0 at once. Every wait for a stop
  trusted it — the power's waves stopped PostgreSQL in the same second as its apps, and
  a restore or a stopped copy began beside a process still writing.
  `hlb_orchestrator::wait_stopped` reads the tasks' own state (`TaskInfo::still_runs`);
  `hlb-types/tests/stop_wait.rs` refuses the field compared with zero.
- **Anti-affinity is about HARDWARE, never `node.id`.** Two VMs on one server are two
  Swarm nodes and **one** point of failure: two replicas "across two nodes" protect
  nothing. The domain is declared at `hlb node add` (label `hlb.failureDomain`) —
  neither Swarm nor the agent can guess it. Swarm spreads by node alone: several
  replicas carry a placement preference spreading them over that label first. A
  one-node house is never flagged — its replicas have nowhere else to go.
- **An undeclared domain is not an isolated domain.** Assuming isolation is exactly the
  optimistic assumption that creates the illusion. Nodes without a domain form a
  "we do not know" group, displayed as such.
- **Simulate the loss of a DOMAIN, never of a machine.** On two VMs of one server,
  per-node says "the service survives" where per-domain says "it goes down entirely".
  Quorum requires a STRICT majority of managers: two survivors of four are not enough —
  a naive `>=` would conclude the cluster holds.
- **Draining the last active node would empty the cluster.** Swarm accepts it without
  complaint — it is on us to refuse.
- **Maintenance is one node at a time** (`cluster::maintenance`): a second node down
  while another is drained leaves the moved services nowhere to go, and two managers of
  three down is a lost quorum.
- **A tier keeps heavy services off small machines, never light ones off big ones.**
  Matched exactly, a cluster of 16 GB nodes (all `heavy`) could place none of the nine
  `light` apps. `light` asks for no constraint, and the capacity budget counts heavy
  nodes toward it (`hlb_types::manifest::tier_admits`).
- **Replicas share no local volume.** Vikunja ran two over its `files`: on two nodes, two
  diverging copies behind one routing mesh; on one, two processes racing their
  migrations. Validation refuses more than one replica over a `tier: local` volume.
- **🔴 A task's pull error can be a recording.** A Swarm task whose pull fails on a name or a
  timeout stays `Preparing`, and Swarm repeats that error each second without trying again:
  `lookup … on [::1]:53` went on long after the resolver worked, and read as "Docker has no
  DNS" (Docker 29.9.3, 2026-11-06: 333 failures, one source port, no packet). A refusal or a
  missing tag ends the task instead, and an image already on the node starts anyway. Only a
  new task pulls again: `Drift::PullStuck`. ⚠️ A pull in progress is `Preparing` with no error.
- **Nothing that installs Docker may connect to it first.** `cluster init` connected at
  the top of its command and could never start on a bare machine.
- **Upgrading a kernel on Arch or Alpine deletes the running one's modules.** Docker then
  fails on `nf_tables`, WireGuard on its module, until a reboot. `node add` reboots the
  machine it is adding before starting anything; elsewhere the command says so.

## The overlay

- **A service on no network cannot resolve `postgres`.** `ServiceSpec.networks` was never
  translated to Swarm and nothing set it, until 2026-10-11: every service ran on no
  overlay. The executor defaults to `hlb_platform` rather than to nothing, and creates it
  first.
- **Overlays are created at MTU 1370.** VXLAN over WireGuard (1420) does not fit 1500:
  small requests work, large responses stall, nothing logs. An overlay's MTU cannot
  change once services are attached, so it is set everywhere from the start. The ingress
  network is recreated at `swarm init`, before anything publishes through it — and both
  edges are asynchronous: wait for it to exist, then for it to be gone.
- **🔴 Swarm's virtual IP forgets a connection idle for 900 s, and tells neither end.**
  IPVS expires every established entry at 899 s (measured on the lab, in the `lb_`
  namespace's `/proc/net/ip_vs_conn`): a pooled PostgreSQL connection quiet for a quarter
  of an hour failed its next query, and Fluxer answered its first channel opening 503.
  The SERVER's keepalives cross the VIP for every client, whatever its pool does:
  PostgreSQL runs `tcp_keepalives_idle=300` (a session idle 17 minutes answered; one
  `SET` back to the system's 7200 lost its connection), MariaDB
  `--tcp-keepalive-time=300` (lost at 17 minutes before it). Valkey's own
  `tcp-keepalive` is 300 by default; NATS pings every two minutes.
- **A service with host-mode ports answers from the interface it was reached on — or
  does not.** LiveKit offered a candidate per interface and answered a call's checks from
  its overlay address (10.0.1.x), which leaves the node untranslated: no client took
  them. Its `rtc.ips` excludes Swarm's pool (10.0.0.0/8, which `cluster init` keeps), so
  only `docker_gwbridge`'s address — the host-mode ports' own — is left. Host-mode UDP
  itself works (`-p udp --dport 7882 -j DNAT`, measured with a real call).
- **A host resolves none of the platform's names.** `postgres`, `mariadb`, `garage` exist
  on the overlay only: run from a manager, `hlb install` recorded every database as
  unimplemented. `relay::reach` opens a relay container on the platform network,
  published on 127.0.0.1, for the command's lifetime — only for connections `hlb` makes
  itself: a URL handed to a container on the overlay keeps the service's name.

## Talking to Swarm

- **🔴 A service read back from Swarm has no probe.** bollard's `ContainerSpec` names it
  `HealthCheck`; Docker writes `Healthcheck`. Go reads JSON without case, so a CREATED
  service always had it; serde does not, so every read-modify-write (an image moved, a
  scale, a restart) wrote the service back without one and the image's own probe ran —
  the lab's PostgreSQL, its `healthcheck.sh` signing in as `root`, stayed "starting" and
  down. `inspect_whole` reads it again through the CLI; `swarm_spike.rs` holds it.
- **A Swarm secret is immutable.** Configuration files ride on secrets (bollard 0.19 has
  no configs), named after a hash of their content, so a new version is a new secret.
  🔴 Each stayed: 26 under the lab's `fluxer-api`, a key in every one that held one.
  `prune_file_secrets` deletes them at each deployment and reconfiguration, but for the
  spec's and the `PreviousSpec`'s: Swarm refuses to delete what a spec mounts and deletes
  what a `PreviousSpec` mounts without a word (measured 2026-11-04), which is what the
  update policy rolls back to.
- **🔴 A job's secret outlives a run nobody finished.** A job carries credentials as
  files and deletes them at its end. A process killed mid-run never gets there; the next
  run cleared the service and left the secrets, and nothing said so: sixteen on the lab,
  a week old, dated from the hours its Docker was being restarted (found 2026-11-04).
  `clear_ended_runs` reads them from the spec of the run it clears, and a run Swarm
  refuses deletes its own.
- **A private image needs its credentials sent WITH the service.** The Swarm daemon never
  reads a node's `docker login`: every node fails on "pull access denied" with a good
  login in place. `SwarmOrchestrator::with_registry_auth`, fed from the vault's
  `registry-<host>` (`user:token`), is what `--with-registry-auth` does.
- **A timeout without Swarm's reason is a guess.** `wait_healthy` waited 120 s and said
  "0/1 tasks running" over a "no suitable node", or a mount error, Swarm had stated at
  once. `HealthTimeout` carries the last task's own words.
- **`exec` reached the daemon `hlb` talks to, and its node only.** A task on another node
  answered "no such container", read as the command failing — the guides' `exec`
  automations had the same blind spot. There, a job on that node runs `docker exec`
  against its own daemon (`DOCKER_CLI_IMAGE`), its exit code printed last and read back.
- **🔴 The `docker` CLI reaches the LOCAL daemon unless told otherwise.** An
  orchestrator of the site's daemon (`connect_unix`, bridged over SSH) read the house's
  previous spec, probe and logs for the site's services — the lifeboat's `postgres` and
  `vaultwarden` exist on both. Every CLI call goes through `SwarmOrchestrator::cli`,
  which sets `DOCKER_HOST` (`tests/cli_follows_the_daemon.rs`).
- **`docker service logs` is the BINARY's** (bollard has no service logs): a process
  without `docker` read every job's log as empty, and a remote exec "did not say how it
  ended" with nothing naming the missing binary. The controller's image carries it; a
  log that cannot be read is said as such.

## What runs inside the container

- **A probe runs inside the image, not on the host.** Distroless and bare-binary images
  have no `sh` and no `wget` (Garage, oauth2-proxy): a `CMD-SHELL` probe never passes.
  `localhost` may resolve to `::1` first where only IPv4 listens — probe `127.0.0.1`.
  Next.js binds to `$HOSTNAME`, which Docker sets to the container's name.
- **A probe the image cannot run never passes.** Garage's image is the bare binary: no
  `sh`, no `wget`. Its probe is `/garage status`; `/health` stays 503 until a layout.
- **An image whose entrypoint is a bare CLI runs nothing.** ntfy's is `ntfy`: with no
  `serve` it printed its help and exited, Swarm restarted it, and the catalog's ntfy
  never received one alert. Read `Config.Entrypoint` and `Cmd` before trusting that a
  manifest without `args` starts anything.
- **`command` replaces the image's ENTRYPOINT; `args` its `Cmd`.** Restating an
  entrypoint to add arguments drops whatever it had and the manifest never sees:
  Valkey's is `tini -- docker-entrypoint.sh`, and Fluxer's `command` began at the
  script, without `tini` (2026-10-31). Arguments go in `args`; `command` is for a
  start the image does not have (a `sh -c` reading a secret file, Gitea's script).
- **An image that runs as a user and ships no directory for its volume cannot write it.**
  Docker initialises a new named volume from the image's directory at that path, owner
  included — with none, the volume is root's, 755. Vikunja runs as 1000: no attachment
  was ever stored (0.24 said nothing; 2.7 refuses to start). It runs as `0:0` with no
  capability; check `docker inspect --format '{{.Config.User}}'` against the volume.
- **An entrypoint that chowns as root cannot cross a directory its user made 0700.**
  Valkey's runs `find . \! -user valkey -exec chown` before dropping privileges; with
  every capability dropped, root could not enter `appendonlydir`: the companion started
  on an empty volume only, and exited on every restart after. Started as the image's own
  user (`security.user`), it skips the chown and needs no capability.
- **🔴 A read-only root is proven by USE, never by a healthy task.** Turned read-only one
  by one, Fluxer's services all came back healthy — and Meilisearch refused every
  document batch ("Read-only file system", os error 30; each is written to a temporary
  file first) behind a green probe: the search was silently empty. And a task "1/1"
  after an update may be the OLD one: Swarm rolled the api back on its own, and only
  `Spec…ReadOnly` (or `UpdateStatus` `rollback_completed`) said so. Read the spec, then
  use the app — a message, an upload, a search, a call — and read every log for `EROFS`.
  What an image writes outside its volumes goes to `security.tmpfs`, mode 1777 (root's
  0755 shut Fluxer's api, run as 65532, out of its socket's directory).

## Invariants, encoded in tests

If one of these tests fails, the code is usually wrong, not the test.

- **The update policy is not negotiable.** `failure_action: rollback` + `monitor` are
  hard-coded in `hlb-orchestrator`, not configurable per app; an app that cannot cope
  belongs on `channel: pin`. The ORDER follows from where the data is, never from a
  manifest: `start-first` everywhere, except a service keeping data on its node, which
  stops first — restarting PostgreSQL ran two postmasters on one directory, the new one
  lost its lock file and shut down hard, and the next replayed its WAL. So does one
  holding a port of its node (host mode): Fluxer's LiveKit, on the one ingress node,
  waited "host-mode port already in use" for its own old task, and the update never
  ended (`a_service_holding_a_port_of_its_node_stops_before_its_next_task`). And
  Homelabus's daemon, `alone()`: two `hlb-privd` ran every loop at once, and the old
  one's shutdown removed the socket the new one had bound. A service read back that
  already stops first keeps it — `alone()` leaves no other trace in Swarm.

## Running the Swarm integration tests

They are `#[ignore]`d so `cargo test` stays fast and usable without Docker.

```sh
docker swarm init
export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
cargo test -p hlb-orchestrator -- --ignored --test-threads=1 --nocapture
```

⚠️ **On macOS (colima / Docker Desktop), `DOCKER_HOST` is mandatory.** `bollard` looks
for `/var/run/docker.sock`, which does not exist there. Without it, every integration
test and `hlb ps` / `hlb install` fails with `SocketNotFoundError`.

⚠️ **Node tiers are real Swarm placement constraints.** `hlb node add` sets them; on a
manually joined node you must do it yourself, or nothing schedules and `wait_healthy`
times out:

```sh
docker node update --label-add tier=heavy $(docker node ls -q)
```

## Garage

- **Garage answers a staged layout with the CURRENT version.** The one to commit is the
  next (`ClusterLayout::next_version`).
- **A fresh Garage stores nothing, and its first app's install stopped on it.** No
  layout, every bucket refused "Layout not ready" — Garage installed by the same plan
  as Fluxer always is. The bucket step gives an EMPTY layout the one `hlb garage init`
  would (`Garage::ensure_layout`, a node measuring no disk refused); a layout that
  exists is never touched, since placing a node moves data.

Garage goes multi-node through the layout, never through `replicas` — additional nodes
join the cluster as their own services sharing the RPC secret:

```sh
hlb garage status                              # known nodes, current layout
hlb garage assign <node-id> --zone home --capacity 500000000000 --apply
hlb garage commit --version <n> --apply        # n from the assign above
```
