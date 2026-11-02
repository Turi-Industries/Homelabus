//! Against a real Garage — what its admin API and its S3 API accept, measured rather
//! than read in its documentation.
//!
//! ```sh
//! # a single-node Garage, laid out (`garage layout assign` then `apply`), with
//! # `admin_token` set and its two APIs published on 127.0.0.1
//! export HLB_TEST_GARAGE_ADMIN=http://127.0.0.1:13903 HLB_TEST_GARAGE_TOKEN=…
//! export HLB_TEST_GARAGE_S3=http://127.0.0.1:13900
//! cargo test -p hlb-objstore --test live_garage -- --ignored --nocapture
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_objstore::{s3, Garage};

fn garage() -> Garage {
    let var = |n: &str| std::env::var(n).unwrap_or_else(|_| panic!("{n} is not set"));
    Garage::new(var("HLB_TEST_GARAGE_ADMIN"), var("HLB_TEST_GARAGE_TOKEN"))
        .with_s3(var("HLB_TEST_GARAGE_S3"))
}

fn unique(what: &str) -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("hlb-test-{what}-{n}")
}

/// Fluxer's `uploads` is a staging bucket: Garage deletes what a day leaves there.
/// The app's own key owns nothing, and Garage 2.5.0 refuses it the lifecycle — so
/// Homelabus writes it with a key of its own, which does not outlive the call.
#[tokio::test]
#[ignore = "needs a Garage: see the module's header"]
async fn a_buckets_expiry_is_written_by_a_key_that_does_not_outlive_it() {
    let g = garage();
    let bucket = unique("expiry");
    let id = g.ensure_bucket(&bucket).await.expect("bucket");
    let app = g.ensure_key(&unique("app"), None).await.expect("key");
    g.allow(&id, &app.access_key_id)
        .await
        .expect("read and write, no owner");

    let at = s3::Location {
        endpoint: g.s3_endpoint().expect("s3").to_string(),
        bucket: bucket.clone(),
        prefix: String::new(),
    };
    let own = s3::Bucket::connect(at, &app.access_key_id, &app.secret_access_key)
        .await
        .expect("connect");
    match own.expire_after(1).await {
        Err(hlb_objstore::Error::Rejected { status: 403, .. }) => {
            println!("✓ the app's own key may not set its bucket's lifecycle");
        }
        Ok(()) => println!("⚠️ this Garage takes a lifecycle from a read-write key (2.4.1 did)"),
        Err(e) => panic!("neither taken nor refused: {e}"),
    }

    g.expire_after(&id, &bucket, 1)
        .await
        .expect("the rule holds");
    // Written again with another span: the bucket's one rule is replaced, not added to.
    g.expire_after(&id, &bucket, 7)
        .await
        .expect("the rule is replaced");
    let keys = g.inventory().await.expect("inventory").keys;
    assert!(
        !keys.contains_key("homelabus-lifecycle"),
        "the key owning the bucket outlived the call: {keys:?}"
    );
    println!("✓ {bucket}: objects and unfinished uploads expire after 7 days");
}

/// A Garage installed in the same plan as its first app has no layout, and refuses
/// every bucket "Layout not ready": the install gives it one. Laid out already —
/// whoever came first —, it is left as it is: placing a node moves data.
#[tokio::test]
#[ignore = "needs a Garage: see the module's header"]
async fn a_garage_gets_a_layout_once_and_then_takes_a_bucket() {
    let g = garage();
    let before = g.layout().await.expect("layout");
    let given = g
        .ensure_layout(hlb_objstore::DEFAULT_ZONE)
        .await
        .expect("laid out");
    if before.roles.is_empty() {
        assert_eq!(given, Some(before.next_version()));
        println!("✓ layout {} given to a fresh Garage", before.next_version());
    } else {
        assert_eq!(given, None);
        assert_eq!(g.layout().await.expect("layout"), before, "moved");
        println!("✓ layout {} left as it was", before.version);
    }
    g.ensure_bucket(&unique("laid")).await.expect("a bucket");
    assert_eq!(g.ensure_layout("elsewhere").await.expect("read"), None);
}

/// A bucket read out whole and written back: past a page of the listing, its keys as
/// written — spaces, accents —, its headers kept.
#[tokio::test]
#[ignore = "needs a Garage: see the module's header"]
async fn a_bucket_lists_past_a_page_and_its_objects_go_back_with_their_headers() {
    let g = garage();
    let bucket = unique("roundtrip");
    let id = g.ensure_bucket(&bucket).await.expect("bucket");
    let key = g.ensure_key(&unique("app"), None).await.expect("key");
    g.allow(&id, &key.access_key_id).await.expect("grant");
    let at = s3::Location {
        endpoint: g.s3_endpoint().expect("s3").to_string(),
        bucket: bucket.clone(),
        prefix: String::new(),
    };
    let b = s3::Bucket::connect(at, &key.access_key_id, &key.secret_access_key)
        .await
        .expect("connect");

    let png = vec![("content-type".to_string(), "image/png".to_string())];
    let odd = "avatars/é tête & co/1.png";
    b.put_stream(odd, 3, &png, reqwest::Body::from(b"png".to_vec()))
        .await
        .expect("put");
    for i in 0..1003 {
        let k = format!("emoji/{i:04}");
        b.put_stream(&k, 1, &[], reqwest::Body::from(b"e".to_vec()))
            .await
            .expect("put");
    }
    let all = b.list().await.expect("list");
    assert_eq!(all.len(), 1004, "a page of the listing lost");
    assert!(all
        .iter()
        .any(|o| o.key == odd && o.size == 3 && o.modified > 0));

    let mut d = b.open(odd).await.expect("open");
    assert_eq!(d.size, 3);
    assert!(d.headers.contains(&png[0]), "{:?}", d.headers);
    let mut body = Vec::new();
    while let Some(c) = d.chunk().await.expect("read") {
        body.extend(c);
    }
    assert_eq!(body, b"png");
    println!("✓ {bucket}: 1004 objects listed, one read back with its type");
}
