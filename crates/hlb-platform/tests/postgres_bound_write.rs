//! A guide's `sql` write: its values bound, never written into the statement, and kept
//! only when its probe then holds.
//!
//! ```sh
//! docker run -d --name hlb-test-pg -e POSTGRES_PASSWORD=test \
//!     -p 55432:5432 postgres:17-alpine
//! export HLB_TEST_PG=postgres://postgres:test@localhost:55432/postgres
//! cargo test -p hlb-platform --test postgres_bound_write -- --ignored --nocapture
//! docker rm -f hlb-test-pg
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_platform::PostgresProvisioner;

#[tokio::test]
#[ignore = "needs a PostgreSQL (see the header)"]
async fn a_bound_write_is_kept_only_when_its_probe_holds() {
    let url = std::env::var("HLB_TEST_PG").expect("HLB_TEST_PG");
    let pg = PostgresProvisioner::connect(&url).await.expect("admin");
    pg.provision("hlb_bound", "hlb_bound", "a-password-0123456789")
        .await
        .expect("database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!(
            "{}/hlb_bound",
            url.rsplit_once('/').expect("a database").0
        ))
        .await
        .expect("connect");
    sqlx::query("DROP TABLE IF EXISTS source")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE source (name text, cfg text)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(r#"INSERT INTO source VALUES ('PocketID', '{"ClientSecret":""}')"#)
        .execute(&pool)
        .await
        .unwrap();

    let write = "UPDATE source SET cfg = jsonb_set(cfg::jsonb, '{ClientSecret}', \
                 to_jsonb($1::text))::text WHERE name = $2";
    let probe = "SELECT cfg::jsonb->>'ClientSecret' = $1 FROM source WHERE name = 'PocketID'";
    // A quote and a brace are values, whatever the statement looks like.
    let secret = r#"it's {"a"} secret'); DROP TABLE source; --"#.to_string();
    let params = [secret.clone(), "PocketID".to_string()];

    assert!(!pg
        .probe_bound("hlb_bound", probe, &params)
        .await
        .expect("probe"));
    let (rows, held) = pg
        .write_bound("hlb_bound", write, probe, &params)
        .await
        .expect("write");
    assert_eq!((rows, held), (1, true));
    assert!(pg
        .probe_bound("hlb_bound", probe, &params)
        .await
        .expect("probe"));

    // A write that leaves its probe false is rolled back, not half done.
    let other = ["another".to_string(), "nobody".to_string()];
    let (rows, held) = pg
        .write_bound("hlb_bound", write, probe, &other)
        .await
        .expect("write");
    assert_eq!((rows, held), (0, false));
    assert!(pg
        .probe_bound("hlb_bound", probe, &params)
        .await
        .expect("kept"));
    println!("✓ bound, kept when its probe holds, rolled back otherwise");
}
