//! An archive unpacked into a volume through Docker's API, read back from a container.
//!
//! Needs a Docker daemon (no Swarm): `#[ignore]`d, run with
//! `cargo test -p hlb-orchestrator --test put_archive -- --ignored`.

use hlb_orchestrator::tar::{self, Kind};
use hlb_orchestrator::{Orchestrator as _, SwarmOrchestrator, VolumeSpec};

/// An image with `sh`, pinned; any would do, since the container never starts.
const IMAGE: &str =
    "restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510";

fn archive() -> Vec<u8> {
    let mut out = Vec::new();
    // The root first, as `restic dump` never writes it.
    out.extend(tar::header("donnees/vol", Kind::Dir, 1000, 1001, 0o700).expect("root"));
    let content = b"hello\n";
    out.extend(
        tar::header(
            "donnees/vol/a.txt",
            Kind::File(content.len() as u64),
            1000,
            1001,
            0o640,
        )
        .expect("file"),
    );
    out.extend(tar::padded(content));
    out.extend(tar::end());
    out
}

#[tokio::test]
#[ignore = "needs a Docker daemon"]
async fn an_archive_lands_in_the_volume_with_its_owners_and_modes() {
    let o = SwarmOrchestrator::connect().await.expect("docker");
    let volume = format!("hlb-put-test-{}", std::process::id());
    o.create_volume(&VolumeSpec::docker(&volume))
        .await
        .expect("volume");
    let bytes = bytes::Bytes::from(archive());
    o.put_archive(
        IMAGE,
        &volume,
        "/donnees/vol",
        futures::stream::iter([Ok::<_, std::io::Error>(bytes)]),
    )
    .await
    .expect("put");

    let read = std::process::Command::new("docker")
        .args(["run", "--rm", "--entrypoint", "sh", "-v"])
        .arg(format!("{volume}:/v"))
        .arg(IMAGE)
        .args(["-c", "stat -c '%u:%g %a' /v /v/a.txt && cat /v/a.txt"])
        .output()
        .expect("docker run");
    let _ = o.remove_volume(&volume).await;
    let out = String::from_utf8_lossy(&read.stdout);
    assert_eq!(out, "1000:1001 700\n1000:1001 640\nhello\n", "{read:?}");
}
