//! Dump → destruction → restore, against a real MariaDB.
//!
//! Every MariaDB trap in `mariadump` is one where the dump succeeds and restores without
//! an error: these tests restore and then look for what would be missing.
//!
//! ```sh
//! cargo test -p hlb-backup --test maria_roundtrip -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! The server is the client's image unless `HLB_TEST_MARIADB_SERVER` names another: an
//! install keeps its major when the catalog's moves, and the new client dumps it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hlb_backup::images::MARIADB_CLIENT;
use hlb_backup::mariadump::{self, Consistency, MariaDumper, MariaTarget};
use hlb_backup::pgrunner::MariaContainerRunner;

const CONTAINER: &str = "hlb-test-mariadump";
const NETWORK: &str = "hlb-test-maria-net";
const PASSWORD: &str = "test-password";

fn docker(args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("docker reachable (DOCKER_HOST?)")
}

/// Runs SQL as root in the server's container, and returns the output.
fn sql(db: &str, statement: &str) -> String {
    let out = docker(&[
        "exec",
        "-e",
        &format!("MYSQL_PWD={PASSWORD}"),
        CONTAINER,
        "mariadb",
        "-uroot",
        "-N",
        "-B",
        db,
        "-e",
        statement,
    ]);
    assert!(
        out.status.success(),
        "mariadb failed on \"{statement}\":\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn server_image() -> String {
    std::env::var("HLB_TEST_MARIADB_SERVER").unwrap_or_else(|_| MARIADB_CLIENT.to_string())
}

fn start() {
    let _ = docker(&["rm", "-f", CONTAINER]);
    let _ = docker(&["network", "create", NETWORK]);
    let out = docker(&[
        "run",
        "-d",
        "--name",
        CONTAINER,
        "--network",
        NETWORK,
        "-e",
        &format!("MARIADB_ROOT_PASSWORD={PASSWORD}"),
        &server_image(),
        "--event-scheduler=ON",
    ]);
    assert!(
        out.status.success(),
        "starting mariadb: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The image restarts the server once after initialising: wait for a query, twice.
    for _ in 0..90 {
        let r = docker(&[
            "exec",
            CONTAINER,
            "healthcheck.sh",
            "--connect",
            "--innodb_initialized",
        ]);
        if r.status.success() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    panic!("mariadb did not start in time");
}

fn stop() {
    let _ = docker(&["rm", "-f", CONTAINER]);
    let _ = docker(&["network", "rm", NETWORK]);
}

fn target() -> MariaTarget {
    MariaTarget {
        host: CONTAINER.to_string(),
        port: 3306,
        database: "app".to_string(),
        user: "root".to_string(),
        password: PASSWORD.to_string(),
    }
}

fn dumper() -> MariaDumper<MariaContainerRunner> {
    MariaDumper::new(MariaContainerRunner::new(MARIADB_CLIENT).network(NETWORK))
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn routines_triggers_events_and_myisam_tables_come_back_from_a_dump() {
    start();

    sql("", "CREATE DATABASE app");
    sql(
        "app",
        "CREATE TABLE orders (id INT AUTO_INCREMENT PRIMARY KEY, total INT) ENGINE=InnoDB;
         CREATE TABLE audit (n INT) ENGINE=MyISAM;
         CREATE TRIGGER count_orders AFTER INSERT ON orders FOR EACH ROW
             INSERT INTO audit VALUES (NEW.id);
         CREATE PROCEDURE double_total(IN x INT) SELECT x * 2;
         CREATE EVENT nightly ON SCHEDULE EVERY 1 DAY DO DELETE FROM audit WHERE n < 0;
         INSERT INTO orders (total) VALUES (10), (20), (30);",
    );
    assert_eq!(sql("app", "SELECT COUNT(*) FROM audit"), "3");

    // What the scheduled pass reads before choosing the options.
    let engines: Vec<String> = sql(
        "",
        &mariadump::engines_query("app").replace("'app'", "'app' ORDER BY ENGINE"),
    )
    .lines()
    .map(str::to_string)
    .collect();
    let consistency = mariadump::consistency_for(&engines);
    assert_eq!(consistency, Consistency::LockRequired, "{engines:?}");

    let dump = dumper().dump(&target(), consistency).await.expect("dump");
    let text = String::from_utf8_lossy(&dump);
    for needle in [
        "TRIGGER",
        "count_orders",
        "PROCEDURE",
        "double_total",
        "EVENT",
        "nightly",
    ] {
        assert!(text.contains(needle), "the dump lacks {needle}");
    }
    println!("✓ dump: {} bytes, guard line present", dump.len());

    sql("", "DROP DATABASE app");
    dumper().restore(&target(), &dump).await.expect("restore");

    assert_eq!(sql("app", "SELECT SUM(total) FROM orders"), "60");
    assert_eq!(sql("app", "SELECT COUNT(*) FROM audit"), "3");
    assert_eq!(sql("app", "CALL double_total(21)"), "42");
    assert_eq!(
        sql(
            "",
            "SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA = 'app'"
        ),
        "1"
    );
    // The trigger came back AND fires: a restored app that writes must keep counting.
    sql("app", "INSERT INTO orders (total) VALUES (40)");
    assert_eq!(sql("app", "SELECT COUNT(*) FROM audit"), "4");
    println!("✓ restored: rows, trigger, procedure and event all back");

    stop();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_dump_cut_short_is_refused_on_restore() {
    start();
    sql("", "CREATE DATABASE app");
    sql(
        "app",
        "CREATE TABLE t (i INT) ENGINE=InnoDB; INSERT INTO t VALUES (1), (2);",
    );
    let dump = dumper()
        .dump(&target(), Consistency::Transactional)
        .await
        .expect("dump");

    // Everything but the end: still valid SQL, which is the whole danger.
    let cut = &dump[..dump.len() - 200];
    let refused = dumper().restore(&target(), cut).await;
    assert!(refused.is_err(), "a truncated dump was restored");
    stop();
}
