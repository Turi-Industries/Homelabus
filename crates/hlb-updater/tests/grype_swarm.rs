//! The scan as it runs: Syft and Grype as Swarm jobs, against a real registry.
//!
//! Ignored: it needs a Swarm and the network, and its first run downloads Grype's
//! database (3.2 GB unpacked). `docker swarm init`, then
//! `cargo test -p hlb-updater --test grype_swarm -- --ignored --nocapture`.

use hlb_orchestrator::swarm::SwarmOrchestrator;
use hlb_orchestrator::Orchestrator;
use hlb_updater::grype::Grype;

/// Alpine 3.21.0 (December 2024): OpenSSL, musl and BusyBox flaws fixed since, in the
/// same branch. ⚠️ Not 3.18 → 3.20: 3.18 is past its end of life, its advisories stopped,
/// and 3.20 read as bringing three OpenSSL flaws 3.18 carries too (`grype::compare`).
const OLD: &str =
    "alpine:3.21.0@sha256:21dc6063fd678b478f57c0e13f47560d0ea4eeba26dfc947b2a4f81f686b9f45";
const NEWER: &str =
    "alpine:3.21.9@sha256:ee16d92f96db08d9d2d07da48555a27f3a69d8f0759021dbc601195ed0d2b5bd";

#[tokio::test]
#[ignore]
async fn an_image_is_listed_then_read_as_swarm_jobs() {
    let orch = SwarmOrchestrator::connect().await.expect("a Swarm");
    orch.ensure_network("hlb_platform").await.expect("network");
    let grype = Grype {
        orchestrator: &orch,
        network: "hlb_platform",
    };
    let found = grype.findings(OLD).await.expect("a reading");
    eprintln!("{} matches in {OLD}", found.len());
    assert!(
        found.iter().any(|f| f.package == "musl"),
        "musl's flaws, fixed since in the branch"
    );
    // Read again from the package list kept: no Syft this time, the same answer.
    assert_eq!(grype.findings(OLD).await.expect("again"), found);

    let moved = grype.vulnerabilities(NEWER, Some(OLD)).await;
    eprintln!("{}", moved.describe());
    assert!(moved.was_checked(), "{moved:?}");
    assert!(
        !moved.blocks(),
        "a later build of one branch brings nothing: {moved:?}"
    );

    let unpinned = grype.vulnerabilities("alpine:3.21.0", None).await;
    assert!(!unpinned.was_checked(), "{unpinned:?}");
}
