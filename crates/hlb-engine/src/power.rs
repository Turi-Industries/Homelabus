//! The house on its battery: NUT read, and the decision to stop the apps in waves or start
//! them again. The waves themselves are the privileged side's to run.
//!
//! NUT is only READ — `GET VAR`, which `upsd` answers without an account. The machines are
//! shut down by NUT's own `upsmon` at low battery, as everywhere NUT runs: what Homelabus
//! adds is that by then nothing writes — the apps stopped first, then the databases they
//! wrote to, in the order the capability graph gives.

use std::time::Duration;

use hlb_orchestrator::Orchestrator;
use hlb_resolver::graph::DependencyGraph;
use hlb_state::{PowerPhase, PowerStop, State, UpsPolicy, UpsReading, UpsState};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// NUT's port, when the server is named without one.
pub const NUT_PORT: u16 = 3493;

/// How long the server is given to answer, connection included.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// What to do about the power now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Nothing: on the mains, or not on battery for long enough yet.
    Wait,
    /// Stop the apps, or go on stopping them, for this reason.
    Stop(String),
    /// The mains are back and steady: start the waves again.
    Start,
}

/// Reads the UPS `ups` on the NUT server `server` (`host` or `host:port`).
pub async fn read(server: &str, ups: &str) -> Result<UpsReading, String> {
    let address = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:{NUT_PORT}")
    };
    let talk = async {
        let mut stream = tokio::net::TcpStream::connect(&address)
            .await
            .map_err(|e| format!("NUT's server at {address} does not answer: {e}"))?;
        let ask = format!(
            "GET VAR {ups} ups.status\nGET VAR {ups} battery.runtime\n\
             GET VAR {ups} battery.charge\nLOGOUT\n"
        );
        stream
            .write_all(ask.as_bytes())
            .await
            .map_err(|e| format!("writing to NUT's server: {e}"))?;
        let mut lines = BufReader::new(stream).lines();
        let mut answers = Vec::new();
        while let Some(l) = lines
            .next_line()
            .await
            .map_err(|e| format!("reading NUT's answer: {e}"))?
        {
            if l.starts_with("OK Goodbye") {
                break;
            }
            answers.push(l);
        }
        Ok::<_, String>(answers)
    };
    let answers = tokio::time::timeout(READ_TIMEOUT, talk)
        .await
        .map_err(|_| format!("NUT's server at {address} did not answer in 5 s"))??;
    parse(ups, &answers)
}

/// The three answers, in the order asked.
///
/// 🔴 A UPS NUT cannot reach is an ERROR, never "on the mains": `DRIVER-NOT-CONNECTED`
/// and `DATA-STALE` say the driver lost it, and a house reading that as `OL` would run
/// its battery flat with every app writing.
pub fn parse(ups: &str, answers: &[String]) -> Result<UpsReading, String> {
    let value = |var: &str| -> Option<Result<String, String>> {
        let prefix = format!("VAR {ups} {var} ");
        answers
            .iter()
            .find_map(|l| l.strip_prefix(&prefix).map(|v| Ok(unquote(v))))
    };
    let status = match value("ups.status") {
        Some(Ok(s)) if !s.trim().is_empty() => s,
        _ => {
            let err = answers
                .iter()
                .find_map(|l| l.strip_prefix("ERR "))
                .unwrap_or("no answer");
            return Err(match err.split_whitespace().next() {
                Some("UNKNOWN-UPS") => {
                    format!("NUT's server knows no UPS named {ups} (`upsc -l` lists them)")
                }
                Some("DRIVER-NOT-CONNECTED") | Some("DATA-STALE") => {
                    format!("NUT's driver has lost the UPS {ups} ({err})")
                }
                _ => format!("NUT did not say the status of {ups}: {err}"),
            });
        }
    };
    let number = |var: &str| {
        value(var)
            .and_then(Result::ok)
            .and_then(|v| v.trim().parse::<f64>().ok())
            .map(|v| v.round() as i64)
    };
    Ok(UpsReading {
        status: status.trim().to_string(),
        runtime_s: number("battery.runtime"),
        charge: number("battery.charge"),
    })
}

/// `"OB LB"` → `OB LB`, NUT's two escapes undone.
fn unquote(v: &str) -> String {
    let v = v.trim();
    let inner = v
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(v);
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Why the apps must stop now, if they must.
fn stop_reason(
    p: &UpsPolicy,
    r: &UpsReading,
    on_battery_since: Option<i64>,
    now: i64,
) -> Option<String> {
    if r.exhausted() {
        return Some(format!("the UPS says its battery is low ({})", r.status));
    }
    if !r.on_battery() {
        return None;
    }
    if let Some(left) = r.runtime_s.filter(|left| *left <= p.runtime_s) {
        return Some(format!("on battery, {} min of runtime left", left / 60));
    }
    let since = on_battery_since?;
    (now - since >= p.after_s).then(|| format!("on battery for {} min", (now - since) / 60))
}

/// What to do, from the last reading and the stop under way.
///
/// 🔴 A UPS that could not be read decides nothing: no app stops on a server that does
/// not answer, and none starts again — the inbox says it. A stop already begun is
/// finished whatever: half the waves stopped is the worst state to wait in.
pub fn decide(p: &UpsPolicy, ups: &UpsState, stop: Option<&PowerStop>, now: i64) -> Decision {
    // `record_ups` clears the failure on a good reading: a failure set is the last word.
    let fresh = ups.reading.as_ref().filter(|_| ups.failed_at.is_none());
    let reason = fresh.and_then(|r| stop_reason(p, r, ups.on_battery_since, now));
    let back = fresh
        .is_some_and(|r| r.online() && ups.online_since.is_some_and(|t| now - t >= p.steady_s));
    match stop.map(|s| (s.phase, s)) {
        None => reason.map_or(Decision::Wait, Decision::Stop),
        Some((PowerPhase::Stopping, s)) if !back => Decision::Stop(s.reason.clone()),
        Some((PowerPhase::Stopping | PowerPhase::Stopped, _)) if back => Decision::Start,
        Some((PowerPhase::Stopped, _)) => Decision::Wait,
        Some((PowerPhase::Starting, _)) => reason.map_or(Decision::Start, Decision::Stop),
        Some((PowerPhase::Stopping, _)) => Decision::Start,
    }
}

/// The installed apps' services in the waves they stop in, each with the replicas it
/// runs. A service running none — an app a person stopped — is left out: started again
/// after the power, it would be undoing that person's decision.
///
/// ⚠️ A graph with a cycle cannot pass `catalog validate`; one met anyway stops every
/// service in one wave rather than none.
pub async fn waves(
    state: &State,
    orchestrator: &dyn Orchestrator,
) -> hlb_state::Result<Vec<Vec<(String, u64)>>> {
    let mut manifests = Vec::new();
    for (app, _) in state.installed_apps().await? {
        if let Ok(m) = state.app_manifest(&app).await {
            manifests.push(m);
        }
    }
    let graph = DependencyGraph::from_manifests(&manifests);
    let apps = graph.shutdown_waves().unwrap_or_else(|e| {
        tracing::warn!("the shutdown order could not be computed ({e}): one wave");
        vec![manifests.iter().map(|m| m.metadata.name.clone()).collect()]
    });
    let mut out = Vec::new();
    for wave in apps {
        let mut services = Vec::new();
        for app in wave {
            let Some(m) = manifests.iter().find(|m| m.metadata.name == app) else {
                continue;
            };
            for s in crate::services_of(&app, m) {
                if let Ok(st) = orchestrator.status(&s).await {
                    if st.desired_replicas > 0 {
                        services.push((s, st.desired_replicas));
                    }
                }
            }
        }
        if !services.is_empty() {
            out.push(services);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(String::from).collect()
    }

    /// `upsd` 2.8.0 with `dummy-ups`, asked the three variables (measured 2026-11-08).
    const ON_BATTERY: &str = "VAR house ups.status \"OB LB\"\n\
                              VAR house battery.runtime \"240\"\n\
                              VAR house battery.charge \"100\"";

    #[test]
    fn upsd_s_answer_is_read() {
        let r = parse("house", &lines(ON_BATTERY)).expect("read");
        assert_eq!(
            r,
            UpsReading {
                status: "OB LB".into(),
                runtime_s: Some(240),
                charge: Some(100),
            }
        );
        // A UPS giving no runtime is read without one.
        let bare = "VAR house ups.status \"OL\"\nERR VAR-NOT-SUPPORTED\nERR VAR-NOT-SUPPORTED";
        let r = parse("house", &lines(bare)).expect("read");
        assert_eq!((r.status.as_str(), r.runtime_s), ("OL", None));
        assert_eq!(
            unquote(r#""a \"quoted\" \\ value""#),
            r#"a "quoted" \ value"#
        );
    }

    #[test]
    fn a_ups_nut_lost_is_an_error_never_on_the_mains() {
        for (err, says) in [
            ("ERR UNKNOWN-UPS", "knows no UPS named house"),
            ("ERR DRIVER-NOT-CONNECTED", "lost the UPS"),
            ("ERR DATA-STALE", "lost the UPS"),
        ] {
            let why = parse("house", &lines(err)).expect_err(err);
            assert!(why.contains(says), "{why}");
        }
        assert!(parse("house", &[]).is_err());
    }

    fn ups(status: &str, runtime: i64, since: i64) -> UpsState {
        let r = UpsReading {
            status: status.into(),
            runtime_s: Some(runtime),
            charge: Some(90),
        };
        UpsState {
            read_at: Some(since),
            on_battery_since: r.on_battery().then_some(since),
            online_since: r.online().then_some(since),
            reading: Some(r),
            ..UpsState::default()
        }
    }

    fn stop(phase: PowerPhase) -> PowerStop {
        PowerStop {
            phase,
            reason: "on battery for 5 min".into(),
            started_at: 0,
            phase_at: 0,
            waves: Vec::new(),
        }
    }

    #[test]
    fn the_apps_stop_after_a_while_on_battery_or_when_time_runs_short() {
        let p = UpsPolicy::default();
        // A short outage is ridden out.
        assert_eq!(
            decide(&p, &ups("OB", 1800, 1000), None, 1000 + 60),
            Decision::Wait
        );
        let Decision::Stop(why) = decide(&p, &ups("OB", 1800, 1000), None, 1000 + 300) else {
            panic!("stops after five minutes");
        };
        assert!(why.contains("5 min"), "{why}");
        // Less runtime left than the waves take: at once.
        let Decision::Stop(why) = decide(&p, &ups("OB", 540, 1000), None, 1000) else {
            panic!("stops when time runs short");
        };
        assert!(why.contains("9 min of runtime"), "{why}");
        assert!(matches!(
            decide(&p, &ups("OB LB", 1800, 1000), None, 1000),
            Decision::Stop(_)
        ));
        assert_eq!(decide(&p, &ups("OL", 1800, 0), None, 1000), Decision::Wait);
    }

    #[test]
    fn an_unreadable_ups_stops_nothing_and_starts_nothing() {
        let p = UpsPolicy::default();
        let mut lost = ups("OB LB", 60, 0);
        lost.failed_at = Some(10);
        assert_eq!(decide(&p, &lost, None, 1000), Decision::Wait);
        assert_eq!(
            decide(&p, &lost, Some(&stop(PowerPhase::Stopped)), 1000),
            Decision::Wait
        );
        // A stop begun is finished.
        assert_eq!(
            decide(&p, &lost, Some(&stop(PowerPhase::Stopping)), 1000),
            Decision::Stop("on battery for 5 min".into())
        );
    }

    #[test]
    fn the_apps_start_again_once_the_mains_are_steady() {
        let p = UpsPolicy::default();
        let stopped = stop(PowerPhase::Stopped);
        assert_eq!(
            decide(&p, &ups("OL", 1800, 1000), Some(&stopped), 1060),
            Decision::Wait
        );
        assert_eq!(
            decide(&p, &ups("OL", 1800, 1000), Some(&stopped), 1120),
            Decision::Start
        );
        // Back before the stop ended: the waves stopped are started again.
        assert_eq!(
            decide(
                &p,
                &ups("OL", 1800, 1000),
                Some(&stop(PowerPhase::Stopping)),
                1120
            ),
            Decision::Start
        );
        // On battery again while starting: stopped again.
        assert!(matches!(
            decide(
                &p,
                &ups("OB LB", 60, 1000),
                Some(&stop(PowerPhase::Starting)),
                1000
            ),
            Decision::Stop(_)
        ));
        assert_eq!(
            decide(
                &p,
                &ups("OB", 1800, 1000),
                Some(&stop(PowerPhase::Starting)),
                1000
            ),
            Decision::Start
        );
    }

    #[tokio::test]
    async fn a_server_that_does_not_answer_is_an_error() {
        // A port nothing listens on: refused at once.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let why = read(&format!("127.0.0.1:{port}"), "house")
            .await
            .expect_err("refused");
        assert!(why.contains("does not answer"), "{why}");
    }

    #[tokio::test]
    async fn the_three_variables_are_asked_and_the_answer_read() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let server = tokio::spawn(async move {
            let (s, _) = listener.accept().await.expect("accept");
            let (r, mut w) = s.into_split();
            let mut asked = Vec::new();
            let mut lines = BufReader::new(r).lines();
            while let Some(l) = lines.next_line().await.expect("line") {
                let done = l == "LOGOUT";
                asked.push(l);
                if done {
                    break;
                }
            }
            w.write_all(format!("{ON_BATTERY}\nOK Goodbye\n").as_bytes())
                .await
                .expect("write");
            asked
        });
        let r = read(&addr, "house").await.expect("read");
        assert!(r.exhausted());
        let asked = server.await.expect("server");
        assert_eq!(asked[0], "GET VAR house ups.status");
        assert_eq!(asked.last().map(String::as_str), Some("LOGOUT"));
        // Read only: nothing that signs in or sets.
        assert!(asked
            .iter()
            .all(|l| l.starts_with("GET VAR") || l == "LOGOUT"));
    }
}
