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

/// This machine, read as the daily pass reads every node: a system Grype holds
/// advisories for is read, any other is said NOT READ — never clean.
#[tokio::test]
#[ignore]
async fn a_machine_is_read_or_said_unread_never_clean() {
    let orch = SwarmOrchestrator::connect().await.expect("a Swarm");
    orch.ensure_network("hlb_platform").await.expect("network");
    let grype = Grype {
        orchestrator: &orch,
        network: "hlb_platform",
    };
    let local = orch.local_node().await.expect("asked").expect("a node");
    let nodes = orch.nodes().await.expect("nodes");
    let node = nodes.iter().find(|n| n.id == local).expect("this node");
    let reading = grype.host_findings(node).await;
    eprintln!(
        "{}: {:?}",
        reading.system,
        reading.found.as_ref().map(Vec::len)
    );

    let os = std::fs::read_to_string("/etc/os-release").expect("os-release");
    let distro = hlb_bootstrap::Distro::parse(&os).expect("a known system");
    assert_eq!(
        reading.system, distro.pretty_name,
        "read on the node itself"
    );
    match hlb_updater::host::database(&distro) {
        Ok(_) => {
            reading.found.expect("a reading");
        }
        Err(_) => {
            let why = reading.found.expect_err("never clean");
            assert!(why.contains("would read clean"), "{why}");
        }
    }
}

/// The two other jobs on their own, whatever this machine runs: Syft lists its package
/// database through the binds, Grype reads a Debian list handed as a file.
#[tokio::test]
#[ignore]
async fn a_package_database_is_listed_and_a_list_is_read_as_swarm_jobs() {
    let orch = SwarmOrchestrator::connect().await.expect("a Swarm");
    orch.ensure_network("hlb_platform").await.expect("network");
    let local = orch.local_node().await.expect("asked").expect("a node");
    let nodes = orch.nodes().await.expect("nodes");
    let node = nodes.iter().find(|n| n.id == local).expect("this node");

    let db = [
        "/var/lib/dpkg",
        "/var/lib/rpm",
        "/lib/apk/db",
        "/var/lib/pacman/local",
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).is_dir())
    .expect("a package database");
    let listed = orch
        .run_job(&hlb_updater::host::syft_job(node, db), 1_200)
        .await
        .expect("ran");
    assert!(listed.succeeded, "{:?}", listed.output);
    // A system Grype does not read has packages Syft cannot name either: refused, after
    // the whole list came through the log.
    match hlb_updater::host::parse(&listed.output) {
        Ok(p) => eprintln!("{}: {} packages", p.distro, p.purls.len()),
        Err(why) => {
            eprintln!("{why}");
            assert!(why.contains("have no package URL"), "{why}");
        }
    }

    // GnuTLS as Debian 12.8 shipped it: fixed since by Debian's own updates.
    let purls = [
        "pkg:deb/debian/libgnutls30@3.7.9-2%2Bdeb12u3?arch=amd64&distro=debian-12&upstream=gnutls28"
            .to_string(),
    ];
    let read = orch
        .run_job(
            &hlb_updater::host::grype_job(node, &purls, "hlb_platform", Some(&local)),
            1_200,
        )
        .await
        .expect("ran");
    assert!(read.succeeded, "{:?}", read.output);
    let found = hlb_updater::grype::parse(&read.output).expect("a reading");
    eprintln!("{} flaws in GnuTLS 3.7.9-2+deb12u3", found.len());
    assert!(
        found
            .iter()
            .any(|f| f.package == "libgnutls30" && f.fixed_in.contains("deb12u")),
        "{found:?}"
    );
}
