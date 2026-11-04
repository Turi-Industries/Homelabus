//! The `bollard` spike - the project's first risk.
//!
//! The goal: prove **before** writing the rest of the product that `bollard` really
//! covers the Swarm surface Homelabus depends on. If there is a gap, better to find it
//! now than in four months.
//!
//! These tests need an active Swarm. They are `#[ignore]`d so `cargo test` stays fast
//! and usable without Docker:
//!
//! ```sh
//! docker swarm init
//! cargo test -p hlb-orchestrator -- --ignored --test-threads=1 --nocapture
//! ```

// In a test, `expect` IS the assertion: the message carries the diagnosis.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_orchestrator::{Orchestrator, ServiceSpec, SwarmOrchestrator, UpdateState, VolumeSpec};

const IMAGE: &str = "alpine:3";
/// A non-existent image: the pull fails and the task never starts. This is the
/// realistic scenario of a wrong digest or a withdrawn image.
const BROKEN: &str = "alpine:this-version-does-not-exist";

async fn orch() -> SwarmOrchestrator {
    SwarmOrchestrator::connect()
        .await
        .expect("daemon docker reachable")
}

/// A unique name per test: tests can run in parallel against one daemon.
fn name(suffix: &str) -> String {
    format!("hlb-spike-{suffix}")
}

async fn cleanup(o: &SwarmOrchestrator, n: &str) {
    let _ = o.remove(n).await;
}

/// The constraint keeping a service on the node these tests talk to.
async fn local_node(o: &SwarmOrchestrator) -> String {
    let id = o.local_node().await.expect("node").expect("in a swarm");
    format!("node.id=={id}")
}

fn sleeper(n: &str) -> ServiceSpec {
    ServiceSpec::new(n, IMAGE).command(["sleep", "3600"])
}

#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn q1_daemon_and_swarm_reachable() {
    let version = orch().await.ping().await.expect("ping");
    println!("✓ daemon docker {version}");
}

/// Q2 - service creation, convergence, and reading state back.
#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn q2_deploy_and_convergence() {
    let o = orch().await;
    let n = name("deploy");
    cleanup(&o, &n).await;

    let id = o.deploy(&sleeper(&n).replicas(2)).await.expect("deploy");
    assert!(!id.is_empty());

    let st = o.wait_healthy(&n, 120).await.expect("convergence");
    assert_eq!(st.desired_replicas, 2);
    assert_eq!(st.running_replicas, 2);
    assert!(st.is_converged());
    println!("✓ 2/2 tasks running, image={}", st.image);

    cleanup(&o, &n).await;
}

/// Q3 - placement constraints. Without them, node tiers and pinning databases are
/// impossible.
#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn q3_placement_constraints() {
    let o = orch().await;
    let n = name("placement");
    cleanup(&o, &n).await;

    // A satisfiable constraint: a manager necessarily exists.
    o.deploy(&sleeper(&n).constraint("node.role==manager"))
        .await
        .expect("deploy with a constraint");
    let st = o.wait_healthy(&n, 120).await.expect("convergence");
    assert_eq!(st.running_replicas, 1);
    println!("✓ node.role==manager constraint honoured");
    cleanup(&o, &n).await;

    // An impossible constraint: the task must stay unscheduled, not crash.
    let n2 = name("placement-impossible");
    cleanup(&o, &n2).await;
    o.deploy(&sleeper(&n2).constraint("node.labels.tier==does-not-exist"))
        .await
        .expect("deploy accepted even when unschedulable");
    let err = o.wait_healthy(&n2, 15).await.unwrap_err();
    println!("✓ impossible constraint → did not converge, clear error: {err}");
    cleanup(&o, &n2).await;
}

/// Q4 - image update with version-based concurrency control.
#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn q4_update_image() {
    let o = orch().await;
    let n = name("update");
    cleanup(&o, &n).await;

    o.deploy(&sleeper(&n)).await.expect("deploy");
    o.wait_healthy(&n, 120).await.expect("initial convergence");

    o.update_image(&n, "alpine:3.21").await.expect("update");
    let st = o
        .wait_healthy(&n, 120)
        .await
        .expect("convergence after update");
    assert!(st.image.contains("3.21"), "image effective : {}", st.image);
    println!("✓ update applied → {}", st.image);

    cleanup(&o, &n).await;
}

/// 🔴 Q5 - THE test that matters: does Swarm roll back a failed update on its own?
///
/// This is the foundation of the whole update pipeline. Rollback logic never exercises
/// itself in real conditions before the day you desperately need it, so it has to be
/// tested deliberately.
#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn q5_automatic_rollback_on_a_failed_update() {
    let o = orch().await;
    let n = name("rollback");
    cleanup(&o, &n).await;

    o.deploy(&sleeper(&n)).await.expect("deploy");
    let before = o.wait_healthy(&n, 120).await.expect("initial convergence");
    println!(
        "  initial state: {} ({} task)",
        before.image, before.running_replicas
    );

    // A broken image is pushed deliberately.
    o.update_image(&n, BROKEN).await.expect("update accepted");

    // Swarm must detect the failure and roll back, with no intervention from us.
    let mut observed = None;
    for _ in 0..60 {
        let st = o.status(&n).await.expect("status");
        if let Some(s) = st.update_state {
            if s.is_failure() {
                observed = Some((s, st));
                break;
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    let (state, st) = observed.expect(
        "Swarm reported no update failure: \
         failure_action=rollback does not work as expected",
    );

    println!("✓ Swarm reacted: {state:?}");
    assert!(
        matches!(
            state,
            UpdateState::RollbackStarted | UpdateState::RollbackCompleted | UpdateState::Paused
        ),
        "unexpected state: {state:?}"
    );

    // And the service must have survived: that is the whole point of start-first.
    assert_eq!(
        st.running_replicas, 1,
        "the service must never go down during a rollback"
    );
    println!("✓ service still up during the rollback ({})", st.image);

    cleanup(&o, &n).await;
}

/// Q6 - label filtering: Homelabus must never touch services it did not create.
#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn q6_list_only_sees_what_it_manages() {
    let o = orch().await;
    let n = name("list");
    cleanup(&o, &n).await;

    o.deploy(&sleeper(&n)).await.expect("deploy");
    let services = o.list().await.expect("list");
    assert!(
        services.iter().any(|s| s.name == n),
        "the managed service must appear"
    );
    println!(
        "✓ {} managed {} listed",
        services.len(),
        if services.len() == 1 {
            "service"
        } else {
            "services"
        }
    );

    cleanup(&o, &n).await;
}

/// Q7 — an unknown service gives a usable error, not a panic.
#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn q7_unknown_service() {
    let err = orch()
        .await
        .status("hlb-spike-does-not-exist")
        .await
        .unwrap_err();
    assert!(
        matches!(err, hlb_orchestrator::Error::NotFound(_)),
        "{err:?}"
    );
    println!("✓ typed error: {err}");
}

// ── Hardening must be APPLIED, not merely declared ───────────────────────────

/// Reads a service's effective spec, as Swarm stores it.
async fn effective_spec(name: &str) -> serde_json::Value {
    let out = std::process::Command::new("docker")
        .args([
            "service",
            "inspect",
            name,
            "--format",
            "{{json .Spec.TaskTemplate.ContainerSpec}}",
        ])
        .output()
        .expect("docker inspect");
    serde_json::from_slice(&out.stdout).expect("json")
}

#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn hardening_reaches_swarm() {
    // 🔴 The test that was missing: the security spec was declared in manifests,
    // validated, and never passed on. A container deployed with Docker's default
    // privileges while "secure by default" was supposed to be an invariant.
    let o = orch().await;
    let n = name("durcissement");
    cleanup(&o, &n).await;

    o.deploy(&sleeper(&n)).await.expect("deploy");
    o.wait_healthy(&n, 120).await.expect("convergence");

    let cs = effective_spec(&n).await;

    assert_eq!(cs["ReadOnly"], true, "rootfs should be read-only");
    assert_eq!(
        cs["CapabilityDrop"],
        serde_json::json!(["ALL"]),
        "every capability should be dropped"
    );
    assert_eq!(
        cs["Privileges"]["NoNewPrivileges"], true,
        "no-new-privileges should be set"
    );
    println!("✓ rootfs ro, cap_drop ALL, no-new-privileges applied by Swarm");

    cleanup(&o, &n).await;
}

#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn a_relaxed_manifest_is_honoured_too() {
    // An app that needs more must be able to ask - otherwise the default hardening
    // would be worked around by disabling Homelabus.
    let o = orch().await;
    let n = name("assoupli");
    cleanup(&o, &n).await;

    let released = hlb_types::SecuritySpec {
        read_only_rootfs: false,
        cap_add: vec!["NET_BIND_SERVICE".to_string()],
        ..Default::default()
    };

    o.deploy(&sleeper(&n).hardening(released))
        .await
        .expect("deploy");
    o.wait_healthy(&n, 120).await.expect("convergence");

    let cs = effective_spec(&n).await;
    // Docker omits false values: absent is equivalent to `false`.
    assert!(
        cs["ReadOnly"].is_null() || cs["ReadOnly"] == false,
        "rootfs should be writable: {}",
        cs["ReadOnly"]
    );
    assert_eq!(cs["CapabilityAdd"], serde_json::json!(["NET_BIND_SERVICE"]));
    println!("✓ explicit relaxation honoured");

    cleanup(&o, &n).await;
}

#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn healthchecks_reach_swarm() {
    let o = orch().await;
    let n = name("sonde");
    cleanup(&o, &n).await;

    let hc = hlb_types::Healthcheck {
        test: vec!["CMD-SHELL".into(), "true".into()],
        interval_secs: 5,
        timeout_secs: 2,
        retries: 3,
        start_period_secs: 1,
    };
    o.deploy(&sleeper(&n).healthcheck(hc))
        .await
        .expect("deploy");
    o.wait_healthy(&n, 120).await.expect("convergence");

    let cs = effective_spec(&n).await;
    // ⚠️ The field is spelled "Healthcheck", not "HealthCheck".
    assert_eq!(
        cs["Healthcheck"]["Test"],
        serde_json::json!(["CMD-SHELL", "true"])
    );
    // Swarm stores durations in nanoseconds.
    assert_eq!(cs["Healthcheck"]["Interval"], 5_000_000_000i64);
    assert_eq!(cs["Healthcheck"]["Retries"], 3);
    println!("✓ sonde transmise, intervalles convertis en nanosecondes");

    cleanup(&o, &n).await;
}

/// 🔴 Every read-modify-write wrote the service back with no probe: bollard reads
/// `HealthCheck` where Docker writes `Healthcheck`. The lab's PostgreSQL lost its own at
/// an image update, and the image's ran, signing in as a role that does not exist.
#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn an_image_moved_or_a_scale_keeps_the_probe() {
    let o = orch().await;
    let n = name("probe-kept");
    cleanup(&o, &n).await;
    let hc = hlb_types::Healthcheck {
        test: vec!["CMD-SHELL".into(), "true".into()],
        interval_secs: 5,
        timeout_secs: 2,
        retries: 3,
        start_period_secs: 1,
    };
    o.deploy(&sleeper(&n).healthcheck(hc))
        .await
        .expect("deploy");
    o.wait_healthy(&n, 120).await.expect("convergence");

    o.update_image(&n, "alpine:3.20")
        .await
        .expect("image moved");
    assert_eq!(
        effective_spec(&n).await["Healthcheck"]["Test"],
        serde_json::json!(["CMD-SHELL", "true"]),
        "the image moved, the probe kept"
    );
    o.scale(&n, 0).await.expect("scaled down");
    o.scale(&n, 1).await.expect("scaled up");
    assert_eq!(
        effective_spec(&n).await["Healthcheck"]["Test"],
        serde_json::json!(["CMD-SHELL", "true"]),
        "scaled, the probe kept"
    );
    println!("✓ the probe survives an image moved and a scale");
    cleanup(&o, &n).await;
}

#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn declared_volumes_are_actually_mounted() {
    // 🔴 A serious regression found in production: volumes were created by the
    // executor and then NEVER attached to the service. Data went into the container's
    // ephemeral layer and disappeared on the first redeploy - while being declared
    // "backed up".
    let o = orch().await;
    let n = name("montage");
    let vol = format!("{n}-data");
    cleanup(&o, &n).await;
    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", &vol])
        .output();

    o.create_volume(&VolumeSpec::docker(&vol))
        .await
        .expect("volume");
    o.deploy(&sleeper(&n).mount(&vol, "/data"))
        .await
        .expect("deploy");
    o.wait_healthy(&n, 120).await.expect("convergence");

    let cs = effective_spec(&n).await;
    let mounts = cs["Mounts"].as_array().expect("mounts present");
    assert_eq!(mounts.len(), 1, "exactly one mount expected: {cs}");
    assert_eq!(mounts[0]["Source"], vol.as_str());
    assert_eq!(mounts[0]["Target"], "/data");
    assert_eq!(mounts[0]["Type"], "volume");
    println!("✓ volume {vol} mounted at /data");

    cleanup(&o, &n).await;
    let _ = std::process::Command::new("docker")
        .args(["volume", "rm", "-f", &vol])
        .output();
}

/// 🔴 A FRESH Swarm, so it runs against a throwaway daemon rather than yours:
///
/// ```sh
/// docker run -d --privileged --name hlb-dind -p 127.0.0.1:23750:2375 \
///     -e DOCKER_TLS_CERTDIR= docker:dind
/// DOCKER_HOST=tcp://127.0.0.1:23750 cargo test -p hlb-orchestrator --test swarm_spike \
///     a_fresh_swarm -- --ignored --nocapture
/// ```
///
/// The ingress network is created by `swarm init` at MTU 1500, which stalls large
/// responses once the overlay rides the WireGuard mesh — and it can only be replaced
/// before anything publishes through it.
#[tokio::test]
#[ignore = "needs a throwaway Docker daemon with no Swarm"]
async fn a_fresh_swarm_gets_overlays_at_the_mesh_mtu_and_services_join_them() {
    use bollard::query_parameters::InspectNetworkOptions;

    let docker = bollard::Docker::connect_with_defaults().expect("daemon");
    let o = SwarmOrchestrator::from_docker(docker.clone());
    // One node on a throwaway daemon: nothing else will ever join it.
    o.cluster_init("127.0.0.1").await.expect("swarm init");

    let mtu_of = |n: bollard::models::NetworkInspect| {
        n.options
            .and_then(|o| o.get("com.docker.network.driver.mtu").cloned())
    };
    let ingress = docker
        .inspect_network("ingress", None::<InspectNetworkOptions>)
        .await
        .expect("ingress");
    assert_eq!(
        mtu_of(ingress),
        Some(hlb_orchestrator::OVERLAY_MTU.to_string())
    );

    o.ensure_network("hlb_platform").await.expect("created");
    assert!(!o.ensure_network("hlb_platform").await.expect("kept"));
    let net = docker
        .inspect_network("hlb_platform", None::<InspectNetworkOptions>)
        .await
        .expect("platform network");
    assert_eq!(net.driver.as_deref(), Some("overlay"));
    assert_eq!(net.attachable, Some(true));
    let net_id = net.id.clone().expect("id");
    assert_eq!(mtu_of(net), Some(hlb_orchestrator::OVERLAY_MTU.to_string()));

    let n = name("network");
    cleanup(&o, &n).await;
    o.deploy(&sleeper(&n).network("hlb_platform"))
        .await
        .expect("deploy");
    let svc = docker
        .inspect_service(&n, None::<bollard::query_parameters::InspectServiceOptions>)
        .await
        .expect("service");
    let attached: Vec<String> = svc
        .spec
        .and_then(|s| s.task_template)
        .and_then(|t| t.networks)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|a| a.target)
        .collect();
    assert!(
        attached.iter().any(|t| t == &net_id || t == "hlb_platform"),
        "service attached to {attached:?}"
    );
    cleanup(&o, &n).await;
    println!(
        "✓ ingress and hlb_platform at MTU {}, service attached",
        hlb_orchestrator::OVERLAY_MTU
    );
}

/// A configuration file reaches the container at its path, and a changed content is a
/// new secret rather than an update Swarm refuses.
#[tokio::test]
#[ignore = "needs an active Swarm"]
async fn files_reach_the_container_at_their_path() {
    let o = orch().await;
    let n = name("files");
    cleanup(&o, &n).await;
    let content = "metadata_dir = \"/var/lib/garage/meta\"\nreplication_factor = 1\n";
    // On this node: read through a job on another one, the output comes back line by
    // line from its log, and the last newline with it.
    let here = local_node(&o).await;
    o.deploy(
        &sleeper(&n)
            .file("/etc/garage.toml", content)
            .constraint(here),
    )
    .await
    .expect("deploy");
    o.wait_healthy(&n, 60).await.expect("running");

    let out = o
        .exec_in_service(&n, &["cat".into(), "/etc/garage.toml".into()])
        .await
        .expect("exec");
    assert_eq!(out.stdout, content);
    cleanup(&o, &n).await;

    // Same service name, other content: a second secret, no conflict.
    o.deploy(&sleeper(&n).file("/etc/garage.toml", "replication_factor = 3\n"))
        .await
        .expect("redeploy with another content");
    cleanup(&o, &n).await;
    println!("✓ file delivered at its path");
}

/// Removing a service takes the secrets its files rode on, every version of them, and a
/// second removal finds nothing left to do. Left behind, a signing key outlived its app
/// (Anubis, on the lab) while the preview promised nothing would be left.
#[tokio::test]
#[ignore = "needs an active Swarm"]
async fn removing_a_service_takes_its_file_secrets() {
    let o = orch().await;
    let n = name("gone");
    let neighbour = name("gone-neighbour");
    cleanup(&o, &n).await;
    cleanup(&o, &neighbour).await;

    let secrets = |prefix: String| async move {
        let out = tokio::process::Command::new("docker")
            .args(["secret", "ls", "--format", "{{.Name}}"])
            .output()
            .await
            .expect("docker secret ls");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| l.starts_with(&prefix))
            .map(str::to_string)
            .collect::<Vec<_>>()
    };

    o.deploy(&sleeper(&n).file("/etc/one.toml", "one"))
        .await
        .expect("deploy");
    o.wait_healthy(&n, 60).await.expect("running");
    o.deploy(&sleeper(&n).file("/etc/one.toml", "two"))
        .await
        .expect("a new version of the file");
    o.deploy(&sleeper(&neighbour).file("/etc/one.toml", "one"))
        .await
        .expect("a neighbour sharing the name's start");
    let mine = format!("{n}-file-");
    assert_eq!(secrets(mine.clone()).await.len(), 2, "two versions");

    o.remove(&n).await.expect("removed");
    assert_eq!(secrets(mine.clone()).await, Vec::<String>::new());
    assert_eq!(
        secrets(format!("{neighbour}-file-")).await.len(),
        1,
        "the neighbour keeps its own"
    );

    assert!(
        matches!(
            o.remove(&n).await,
            Err(hlb_orchestrator::Error::NotFound(_))
        ),
        "already gone reads as it always did"
    );
    cleanup(&o, &neighbour).await;
    assert_eq!(
        secrets(format!("{neighbour}-file-")).await,
        Vec::<String>::new()
    );
}

/// `publishedPorts` reaches Swarm, in host mode: declared and ignored until 2026-10-14.
/// By its protocol: LiveKit's media is UDP, which Swarm was always handed as TCP.
#[tokio::test]
#[ignore = "needs an active Swarm"]
async fn declared_ports_are_published_on_the_node_itself() {
    use hlb_types::manifest::{Protocol, PublishedPort};
    let o = orch().await;
    let n = name("ports");
    cleanup(&o, &n).await;
    let mut spec = sleeper(&n);
    spec.hardening.published_ports = vec![
        PublishedPort::tcp(18025),
        PublishedPort {
            port: 18026,
            protocol: Protocol::Udp,
        },
    ];
    o.deploy(&spec).await.expect("deploy");
    o.wait_healthy(&n, 60)
        .await
        .expect("a host-mode UDP port is placed");

    let docker = bollard::Docker::connect_with_defaults().expect("daemon");
    let svc = docker
        .inspect_service(&n, None::<bollard::query_parameters::InspectServiceOptions>)
        .await
        .expect("service");
    let ports = svc
        .spec
        .and_then(|s| s.endpoint_spec)
        .and_then(|e| e.ports)
        .unwrap_or_default();
    assert_eq!(ports.len(), 2, "{ports:?}");
    assert_eq!(ports[0].published_port, Some(18025));
    assert_eq!(
        ports[0].protocol,
        Some(bollard::models::EndpointPortConfigProtocolEnum::TCP)
    );
    assert_eq!(ports[1].published_port, Some(18026));
    assert_eq!(
        ports[1].protocol,
        Some(bollard::models::EndpointPortConfigProtocolEnum::UDP)
    );
    for p in &ports {
        assert_eq!(
            p.publish_mode,
            Some(bollard::models::EndpointPortConfigPublishModeEnum::HOST)
        );
    }
    cleanup(&o, &n).await;
}

/// A private image is pulled with the credentials the orchestrator was given — the
/// daemon never reads a `docker login`. Needs, on the Swarm's daemon:
///
/// ```sh
/// docker run --rm --entrypoint htpasswd httpd:2.4-alpine -Bbn hlbuser hlbpass > htpasswd
/// docker create --name reg -p 5000:5000 -e REGISTRY_AUTH=htpasswd \
///     -e REGISTRY_AUTH_HTPASSWD_REALM=r -e REGISTRY_AUTH_HTPASSWD_PATH=/htpasswd registry:2
/// docker cp htpasswd reg:/htpasswd && docker start reg
/// docker tag alpine:3 127.0.0.1:5000/private/alpine:3   # then login, push, logout, rmi
/// ```
#[tokio::test]
#[ignore = "needs a Swarm and a password-protected registry at 127.0.0.1:5000"]
async fn a_private_image_is_pulled_with_the_credentials_given() {
    let image = "127.0.0.1:5000/private/alpine:3";

    // Without credentials: the task is rejected on the pull.
    let anon = orch().await;
    let n = name("private-anon");
    cleanup(&anon, &n).await;
    anon.deploy(&ServiceSpec::new(&n, image).command(["sleep", "3600"]))
        .await
        .expect("deploy");
    let mut refused = false;
    for _ in 0..30 {
        let t = anon.tasks(Some(&n)).await.expect("tasks");
        if t.iter().any(|t| t.state == "rejected" || t.err.is_some()) {
            refused = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    assert!(refused, "a private image pulled with no credentials");
    cleanup(&anon, &n).await;

    // With them: it runs.
    let auth =
        SwarmOrchestrator::from_docker(bollard::Docker::connect_with_defaults().expect("daemon"))
            .with_registry_auth("127.0.0.1:5000", "hlbuser", "hlbpass");
    let n = name("private-auth");
    cleanup(&auth, &n).await;
    auth.deploy(&ServiceSpec::new(&n, image).command(["sleep", "3600"]))
        .await
        .expect("deploy");
    auth.wait_healthy(&n, 60)
        .await
        .expect("running with the credentials");
    cleanup(&auth, &n).await;
}

#[tokio::test]
#[ignore = "needs an active Docker Swarm"]
async fn a_command_reaches_a_container_through_a_job_on_its_node() {
    // The path a task on ANOTHER node takes: the daemon `hlb` talks to has none of
    // that node's containers. One node here, so the path is taken by hand.
    let o = orch().await;
    let n = name("exec-remote");
    cleanup(&o, &n).await;
    // Its container is looked for on this node's daemon: placed elsewhere, none is.
    o.deploy(&sleeper(&n).constraint(local_node(&o).await))
        .await
        .expect("deploy");
    o.wait_healthy(&n, 60).await.expect("running");
    let node = o.local_node().await.expect("node").expect("in a swarm");
    let ps = std::process::Command::new("docker")
        .args([
            "ps",
            "-q",
            "--filter",
            &format!("label=com.docker.swarm.service.name={n}"),
        ])
        .output()
        .expect("docker ps");
    let container = String::from_utf8_lossy(&ps.stdout).trim().to_string();
    assert!(!container.is_empty(), "its container");
    let out = o
        .exec_on_node(
            &n,
            &node,
            &container,
            &[
                "sh".into(),
                "-c".into(),
                "echo seen from the node; exit 3".into(),
            ],
        )
        .await
        .expect("exec");
    assert_eq!(out.exit_code, 3, "the command's own code: {out:?}");
    assert!(out.stdout.contains("seen from the node"), "{out:?}");
    cleanup(&o, &n).await;
}
