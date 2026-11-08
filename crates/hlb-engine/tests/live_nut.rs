//! The UPS read from a real NUT server — `upsd` with its dummy driver, built from
//! `tests/data/nut/Dockerfile` — and decided on: on the mains nothing stops, at low
//! battery everything does.
//!
//! ```sh
//! docker build -t hlb-nut-dummy:test crates/hlb-engine/tests/data/nut
//! docker run -d --name hlb-nut -p 127.0.0.1:13493:3493 hlb-nut-dummy:test
//! cargo test -p hlb-engine --test live_nut -- --ignored --nocapture
//! ```
//!
//! `HLB_NUT` names another server (`host:port`), `HLB_NUT_CONTAINER` the container whose
//! `upsrw` sets the status.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

use hlb_engine::power::{decide, read, Decision};
use hlb_state::{State, UpsPolicy};

fn server() -> String {
    std::env::var("HLB_NUT").unwrap_or_else(|_| "127.0.0.1:13493".into())
}

/// Sets the dummy UPS's status, as a UPS would change it, and waits until upsd says so.
async fn set_status(status: &str) {
    let container = std::env::var("HLB_NUT_CONTAINER").unwrap_or_else(|_| "hlb-nut".into());
    let out = std::process::Command::new("docker")
        .args(["exec", &container, "upsrw", "-s"])
        .arg(format!("ups.status={status}"))
        .args(["-u", "admin", "-p", "adminpw", "house"])
        .output()
        .expect("docker exec");
    assert!(
        out.status.success(),
        "upsrw: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for _ in 0..20 {
        if read(&server(), "house")
            .await
            .is_ok_and(|r| r.status == status)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("upsd never said {status}");
}

/// Reads the UPS into the state, as the daemon's pass does, and decides.
async fn read_and_decide(state: &State, now: i64) -> Decision {
    let policy = UpsPolicy {
        server: Some(server()),
        ups: "house".into(),
        ..UpsPolicy::default()
    };
    let reading = read(&server(), "house").await;
    let ups = state
        .record_ups(now, reading.as_ref().map_err(String::as_str))
        .await
        .expect("record");
    let stop = state.power_stop().await.expect("stop");
    decide(&policy, &ups, stop.as_ref(), now)
}

#[tokio::test]
#[ignore = "needs the dummy NUT server running (see the module's comment)"]
async fn the_mains_wait_and_a_low_battery_stops() {
    let state = State::in_memory().await.expect("state");

    set_status("OL").await;
    assert_eq!(read_and_decide(&state, 1000).await, Decision::Wait);

    // On battery, a runtime of half an hour: ridden out, then stopped after five minutes.
    set_status("OB").await;
    assert_eq!(read_and_decide(&state, 1010).await, Decision::Wait);
    assert!(matches!(
        read_and_decide(&state, 1010 + 300).await,
        Decision::Stop(_)
    ));

    // Low battery: at once, whatever the time.
    let fresh = State::in_memory().await.expect("state");
    set_status("OB LB").await;
    let Decision::Stop(why) = read_and_decide(&fresh, 2000).await else {
        panic!("low battery stops");
    };
    assert!(why.contains("low"), "{why}");

    // A UPS the server does not know is an error, never the mains.
    let lost = read(&server(), "nope").await.expect_err("unknown UPS");
    assert!(lost.contains("knows no UPS"), "{lost}");

    set_status("OL").await;
}

#[tokio::test]
#[ignore = "needs the dummy NUT server running (see the module's comment)"]
async fn the_account_a_node_signs_in_with_is_proved_as_upsmon_sends_it() {
    use hlb_engine::power::{check_login, clients};
    check_login(&server(), "house", "monitor", "mon-pass.2")
        .await
        .expect("the account signs in");
    let wrong = check_login(&server(), "house", "monitor", "nope")
        .await
        .expect_err("a wrong password");
    assert!(wrong.contains("refused"), "{wrong}");
    // upsd takes it quoted, upsmon 2.8.0 sends it bare: refused before it is sent.
    let spaced = check_login(&server(), "house", "monitor", "mon pass")
        .await
        .expect_err("a space");
    assert!(spaced.contains("unquoted"), "{spaced}");
    // Nobody signed in once the check left.
    assert!(clients(&server(), "house")
        .await
        .expect("listed")
        .is_empty());
}
