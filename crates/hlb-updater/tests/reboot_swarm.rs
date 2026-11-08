//! The reboot probe as it runs: a Swarm job on the node, entering the host's namespaces.
//!
//! Ignored: it needs a Swarm. `docker swarm init`, then
//! `cargo test -p hlb-updater --test reboot_swarm -- --ignored --nocapture`.
//! The reboot itself is proven on the lab, never on the machine running the suite.

use hlb_orchestrator::swarm::SwarmOrchestrator;
use hlb_orchestrator::Orchestrator;
use hlb_updater::reboot;

#[tokio::test]
#[ignore]
async fn a_node_says_its_kernel_and_its_uptime_from_a_job() {
    let orch = SwarmOrchestrator::connect().await.expect("a Swarm");
    let nodes = orch.nodes().await.expect("nodes");
    let node = nodes.iter().find(|n| n.is_ready()).expect("a ready node");
    let out = orch
        .run_job(&reboot::probe_job(node), reboot::JOB_TIMEOUT_S)
        .await
        .expect("the job ran");
    eprintln!("{out:?}");
    let probe = reboot::read_probe(&out).expect("read");

    // The HOST's uptime, not the container's, which is seconds.
    let host: f64 = std::fs::read_to_string("/proc/uptime")
        .expect("this machine's uptime")
        .split(' ')
        .next()
        .and_then(|s| s.parse().ok())
        .expect("a number");
    let up = probe.uptime_s.expect("an uptime") as f64;
    assert!((host - up).abs() < 120.0, "host {host}, read {up}");
    // And its kernel: whether one waits is this machine's business, but it is known.
    assert!(probe.required.is_some(), "{out:?}");
}
