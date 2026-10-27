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

/// Fluxer's `uploads` is a staging bucket: Garage deletes what a day leaves there,
/// written with the app's own key — which owns nothing.
#[tokio::test]
#[ignore = "needs a Garage: see the module's header"]
async fn an_apps_own_key_sets_its_buckets_expiry_and_it_reads_back() {
    let g = garage();
    let bucket = unique("expiry");
    let id = g.ensure_bucket(&bucket).await.expect("bucket");
    let key = g.ensure_key(&unique("app"), None).await.expect("key");
    g.allow(&id, &key.access_key_id)
        .await
        .expect("read and write, no owner");

    let at = s3::Location {
        endpoint: g.s3_endpoint().expect("s3").to_string(),
        bucket: bucket.clone(),
        prefix: String::new(),
    };
    let b = s3::Bucket::connect(at, &key.access_key_id, &key.secret_access_key)
        .await
        .expect("connect");
    b.expire_after(1).await.expect("the rule holds");
    // Written again with another span: the bucket's one rule is replaced, not added to.
    b.expire_after(7).await.expect("the rule is replaced");
    println!("✓ {bucket}: objects and unfinished uploads expire after 7 days");
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
