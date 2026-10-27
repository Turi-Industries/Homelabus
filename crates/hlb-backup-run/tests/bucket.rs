//! A bucket through the pass and back, against a real Garage and the catalog's restic:
//! its objects and their headers come back, what was written since goes, and the copy
//! the restore took first undoes it.
//!
//! ```sh
//! # a single-node Garage, laid out, its admin API and S3 API on 127.0.0.1
//! export HLB_TEST_GARAGE_ADMIN=http://127.0.0.1:13903 HLB_TEST_GARAGE_TOKEN=…
//! export HLB_TEST_GARAGE_S3=http://127.0.0.1:13900
//! cargo test -p hlb-backup-run --test bucket -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use hlb_backup_run::restore::Restore;
use hlb_backup_run::{Event, Pass};
use hlb_objstore::{reqwest, s3, Garage};

fn var(n: &str) -> String {
    std::env::var(n).unwrap_or_else(|_| panic!("{n} is not set"))
}

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable")
}

/// Every object: key → (content, content-type).
async fn contents(b: &s3::Bucket) -> BTreeMap<String, (Vec<u8>, Option<String>)> {
    let mut out = BTreeMap::new();
    for o in b.list().await.expect("list") {
        let mut d = b.open(&o.key).await.expect("open");
        let kind = d
            .headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .map(|(_, v)| v.clone());
        let mut body = Vec::new();
        while let Some(c) = d.chunk().await.expect("read") {
            body.extend(c);
        }
        out.insert(o.key, (body, kind));
    }
    out
}

async fn put(b: &s3::Bucket, key: &str, body: &[u8], kind: &str) {
    b.put_stream(
        key,
        body.len() as u64,
        &[("content-type".to_string(), kind.to_string())],
        reqwest::Body::from(body.to_vec()),
    )
    .await
    .expect("put");
}

#[tokio::test]
#[ignore = "needs Docker and a Garage: see the module's header"]
async fn a_bucket_backed_up_comes_back_whole_and_the_copy_taken_first_undoes_it() {
    let dir = tempfile::tempdir().expect("tmp");
    let state_path = dir.path().join("hlb.db");
    let state = hlb_state::State::open(&state_path).await.expect("state");
    let vault = hlb_secrets::Vault::open_or_init(dir.path().join("k.key")).expect("vault");
    let repo = "hlb-bucket-repo";
    let _ = docker(&["volume", "rm", "-f", repo]);
    docker(&["volume", "create", repo]);

    // The bucket and the app's key, as `ProvisionBucket` leaves them.
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let bucket = format!("hlb-test-cdn-{n}");
    let g = Garage::new(var("HLB_TEST_GARAGE_ADMIN"), var("HLB_TEST_GARAGE_TOKEN"));
    let id = g.ensure_bucket(&bucket).await.expect("bucket");
    let key = g.ensure_key(&format!("chat-{n}"), None).await.expect("key");
    g.allow(&id, &key.access_key_id).await.expect("grant");
    let (id_name, secret_name) = hlb_types::capability::s3_key_secrets("chat");
    for (name, value) in [
        (id_name, &key.access_key_id),
        (secret_name, &key.secret_access_key),
    ] {
        state
            .store_secret_if_absent(&name, &vault.encrypt(value).unwrap(), "test")
            .await
            .expect("vault");
    }
    let manifest: hlb_types::Manifest = serde_yaml_ng::from_str(&format!(
        "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: chat }}\n\
         spec:\n  image: {{ repo: a/b, tag: \"1\" }}\n  requires:\n    \
         - {{ kind: object-storage, bucket: {bucket} }}\n  env: {{ S3: \"{{{{ s3.endpoint }}}}\" }}\n"
    ))
    .expect("manifest");
    state
        .upsert_app("chat", &manifest, None)
        .await
        .expect("app");
    state
        .upsert_destination("nas", repo, "critical,bulky", None)
        .await
        .expect("destination");

    let s3_url = var("HLB_TEST_GARAGE_S3");
    let at = s3::Location {
        endpoint: s3_url.clone(),
        bucket: bucket.clone(),
        prefix: String::new(),
    };
    let b = s3::Bucket::connect(at, &key.access_key_id, &key.secret_access_key)
        .await
        .expect("connect");
    put(&b, "avatars/1.png", b"\x89PNG one", "image/png").await;
    put(
        &b,
        "attachments/é tête.txt",
        &vec![b'a'; 300_000],
        "text/plain",
    )
    .await;
    put(&b, "emoji/blob.webp", b"webp", "image/webp").await;
    let taken = contents(&b).await;

    let pass = Pass {
        state: &state,
        vault: &vault,
        state_path: &state_path,
        fallback_repo: None,
        network: "bridge",
        postgres_admin: None,
        mariadb_admin: None,
        schedule: hlb_backup::Schedule::default(),
        force: true,
        only: Some("chat"),
        orchestrator: None,
        s3_endpoint: Some(&s3_url),
    };
    let mut events = Vec::new();
    let sum = pass.run(&mut |e| events.push(e)).await.expect("pass");
    assert_eq!(sum.failed, 0, "{events:?}");
    assert!(
        events.iter().any(
            |e| matches!(e, Event::Done { what, destination, .. } if what == "chat buckets" && destination == "nas")
        ),
        "{events:?}"
    );

    // What happens to a bucket: one object gone, one replaced, one added.
    b.delete("emoji/blob.webp", None).await.expect("delete");
    put(
        &b,
        "avatars/1.png",
        b"overwritten",
        "application/octet-stream",
    )
    .await;
    put(&b, "attachments/later.txt", b"written since", "text/plain").await;
    let since = contents(&b).await;

    let restore = Restore {
        state: &state,
        vault: &vault,
        fallback_repo: None,
        network: "bridge",
        orchestrator: None,
    };
    let source = restore
        .find_bucket("chat", &bucket, None, None)
        .await
        .expect("a snapshot");
    let (before, restored) = restore
        .bucket_in_place("chat", &bucket, &s3_url, &source)
        .await
        .expect("restored");
    assert_eq!(restored.written, 3);
    assert_eq!(restored.deleted, 1, "what was written since goes");
    assert_eq!(contents(&b).await, taken, "the bucket as the pass took it");

    // The copy taken first undoes the restore.
    let undo = restore
        .find_bucket("chat", &bucket, None, Some(&before))
        .await
        .expect("the copy taken before");
    restore
        .bucket_in_place("chat", &bucket, &s3_url, &undo)
        .await
        .expect("undone");
    assert_eq!(
        contents(&b).await,
        since,
        "the bucket as it was before the restore"
    );
    println!("✓ {bucket}: backed up, restored whole, and the restore undone");
    let _ = docker(&["volume", "rm", "-f", repo]);
}
