//! A bucket's archive streamed into restic, and back out — on the catalog's restic image.
//!
//! What a pipe cannot say by itself: a writer that failed halfway and one that
//! finished both end the stream. These tests break one halfway and look for what restic
//! kept of it.
//!
//! ```sh
//! cargo test -p hlb-backup --test restic_stream -- --ignored --test-threads=1 --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_backup::tarball::{self, Entry, Writer};
use hlb_backup::{ContainerRunner, Repository};

const VOLUME: &str = "hlb-test-restic-stream";

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable (DOCKER_HOST?)")
}

fn repo() -> Repository<ContainerRunner> {
    Repository::new(
        ContainerRunner::default().mount(VOLUME, "/repo"),
        "/repo",
        "stream-test-password",
    )
}

fn entry(path: &str, size: usize) -> Entry {
    Entry {
        path: path.into(),
        size: size as u64,
        mtime: 1_793_000_000,
        headers: vec![("content-type".into(), "text/plain".into())],
    }
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_stream_that_breaks_saves_nothing_and_a_whole_one_reads_back() {
    docker(&["volume", "rm", "-f", VOLUME]);
    docker(&["volume", "create", VOLUME]);
    let r = repo();
    r.init().await.expect("init");

    // Broken: the object said 4 MiB, the read stops at 1 MiB and the writer is dropped.
    let (sink, mut source) = tarball::pipe();
    let writing = async move {
        let mut w = Writer::new(sink);
        w.start(&entry("big", 4 << 20)).await.expect("start");
        w.write(&vec![b'x'; 1 << 20]).await.expect("a part");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    let (_, broken) = tokio::join!(writing, r.backup_stdin("bucket.tar", &["t"], &mut source));
    let e = broken.expect_err("a broken stream is refused");
    println!("✓ refused: {e}");
    let after = r.snapshots(None).await.expect("list");
    assert!(
        after.is_empty(),
        "restic saved what a broken stream gave it: {after:?}"
    );

    // Whole: two objects and the trailer.
    let (sink, mut source) = tarball::pipe();
    let writing = async move {
        let mut w = Writer::new(sink);
        for (k, body) in [
            ("a.txt", b"alpha".to_vec()),
            ("b/c.txt", vec![b'y'; 70_000]),
        ] {
            w.start(&entry(k, body.len())).await.expect("start");
            w.write(&body).await.expect("body");
            w.end_entry().await.expect("end");
        }
        w.finish().await.expect("finish")
    };
    let (count, id) = tokio::join!(writing, r.backup_stdin("bucket.tar", &["t"], &mut source));
    assert_eq!(count, 2);
    let id = id.expect("snapshot");

    let mut back = Vec::new();
    r.dump(&id, "/bucket.tar", &mut back).await.expect("dump");
    let mut reader = tarball::Reader::new(back.as_slice());
    let mut keys = Vec::new();
    while let Some(e) = reader.next().await.expect("whole") {
        keys.push(e.path);
    }
    assert_eq!(keys, ["a.txt", "b/c.txt"]);
    println!("✓ {} restored whole", &id[..8]);
    docker(&["volume", "rm", "-f", VOLUME]);
}
