//! A day of measurements, kept by the controller itself for the home's curves.
//!
//! Every minute [`record`] reads what the agents last reported — the same
//! [`crate::api::nodes_summary`] the machines page shows — and how many applications
//! run, and stores it; [`history`] answers a curve per machine or disk. Nothing needs to
//! be installed beside the controller for the home to draw its curves: a longer
//! history is VictoriaMetrics' (`/api/v1/metrics/series`).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State as AxumState;
use hlb_api::{History, HistoryLine, Metric, Window};
use hlb_state::Sample;

use crate::api::AppState;
use crate::auth::{Authorized, CanRead};
use crate::error::ApiError;
use crate::extract::{Json, Query};

/// How long a measurement is kept: the longest window, and an hour to spare so the
/// day's first point is never pruned while being drawn.
pub const KEPT_S: i64 = 86_400 + 3_600;

/// What the installation measures now, dated on the minute.
pub async fn sample(s: &AppState, now: i64) -> Vec<Sample> {
    let at = now - now.rem_euclid(60);
    let mut out = Vec::new();
    let mut push = |metric: String, subject: &str, value: Option<f64>| {
        // 🔴 Nothing measured, nothing stored: a zero would draw an idle machine where
        // there is one that did not answer.
        if let Some(value) = value.filter(|v| v.is_finite()) {
            out.push(Sample {
                at,
                subject: subject.to_string(),
                metric,
                value,
            });
        }
    };

    for n in crate::api::nodes_summary(s).await {
        if !n.reachable {
            continue;
        }
        push(Metric::Cpu.key().into(), &n.address, n.cpu_busy);
        push(Metric::Memory.key().into(), &n.address, n.memory_used);
        push(Metric::Swap.key().into(), &n.address, n.swap_used);
        push(Metric::Load.key().into(), &n.address, n.load_per_core);
        for d in &n.disks {
            push(
                format!("{}{}", Metric::Disk.key(), d.path),
                &n.address,
                Some(d.used),
            );
        }
    }
    for (address, status) in crate::api::fleet_now(s).await.iter() {
        if let Some(r) = status.report() {
            if !r.interfaces.is_empty() {
                let rx = r.interfaces.iter().map(|i| i.rx_bytes as f64).sum();
                let tx = r.interfaces.iter().map(|i| i.tx_bytes as f64).sum();
                push(Metric::NetIn.key().into(), address, Some(rx));
                push(Metric::NetOut.key().into(), address, Some(tx));
            }
        }
    }
    if let Ok(apps) = s.state.installed_apps().await {
        let running = apps
            .iter()
            .filter(|(_, status)| status == "running")
            .count();
        push(Metric::AppsRunning.key().into(), "", Some(running as f64));
    }
    out
}

/// Stores what is measured now, and forgets what is older than a day.
pub async fn record(s: &AppState, now: i64) -> Result<(), String> {
    let asked = hlb_api::intent::RecordHistory {
        samples: sample(s, now).await,
        forget_before: now - KEPT_S,
    };
    s.record(asked).await
}

#[derive(serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HistoryQuery {
    /// A day when left out.
    window: Option<Window>,
}

/// Every measurement over a day — or an hour, or six: a curve per machine, or per disk.
///
/// All of them in one answer: the home draws several from the same period, and one
/// request a minute costs a household's shared read budget less than eight.
#[utoipa::path(
    get,
    path = "/api/history",
    params(HistoryQuery),
    responses(
        (status = 200, body = Vec<hlb_api::History>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
pub async fn history(
    _auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Vec<History>>, ApiError> {
    let now = crate::auth::now();
    let window = q.window.unwrap_or_default();
    let names: BTreeMap<String, String> = crate::api::fleet_now(&s)
        .await
        .iter()
        .filter_map(|(a, st)| st.report().map(|r| (a.clone(), r.hostname.clone())))
        .collect();
    let mut out = Vec::new();
    for metric in Metric::ALL {
        let samples = s
            .state
            .history(metric.key(), now - window.seconds())
            .await?;
        out.push(History {
            metric,
            unit: metric.unit(),
            window,
            step_s: window.step(),
            from: now - window.seconds(),
            now,
            lines: lines(metric, window, &samples, &names),
        });
    }
    Ok(Json(out))
}

/// The samples of one metric as curves: one per subject and disk, a counter turned into
/// a rate, averaged over each step.
pub fn lines(
    metric: Metric,
    window: Window,
    samples: &[Sample],
    names: &BTreeMap<String, String>,
) -> Vec<HistoryLine> {
    let mut grouped: BTreeMap<(String, String), Vec<(i64, f64)>> = BTreeMap::new();
    for x in samples {
        grouped
            .entry((x.subject.clone(), x.metric.clone()))
            .or_default()
            .push((x.at, x.value));
    }
    let step = window.step();
    grouped
        .into_iter()
        .map(|((subject, key), points)| {
            let points = if metric.is_counter() {
                rates(&points)
            } else {
                points
            };
            HistoryLine {
                name: names
                    .get(&subject)
                    .cloned()
                    .unwrap_or_else(|| subject.clone()),
                disk: key
                    .strip_prefix(Metric::Disk.key())
                    .filter(|_| metric == Metric::Disk)
                    .map(str::to_string),
                subject,
                points: buckets(&points, step),
            }
        })
        .collect()
}

/// The longest silence a rate is taken across: a few missed minutes, never an outage.
const RATE_GAP_S: i64 = 15 * 60;

/// A counter's growth per second between two readings. A reading lower than the one
/// before is a restart — the counter began again — and gives no rate rather than a
/// negative one; so does a gap, which would spread an outage's traffic over its length.
fn rates(points: &[(i64, f64)]) -> Vec<(i64, f64)> {
    points
        .windows(2)
        .filter_map(|w| {
            let ((t0, v0), (t1, v1)) = (w[0], w[1]);
            let dt = t1 - t0;
            (dt > 0 && dt <= RATE_GAP_S && v1 >= v0).then(|| (t1, (v1 - v0) / dt as f64))
        })
        .collect()
}

/// The mean of each `step`, dated at its start. A step with no reading has no point:
/// the gap stays a gap.
fn buckets(points: &[(i64, f64)], step: i64) -> Vec<(i64, f64)> {
    let mut out: Vec<(i64, f64, u32)> = Vec::new();
    for &(t, v) in points {
        let start = t - t.rem_euclid(step);
        match out.last_mut() {
            Some(last) if last.0 == start => {
                last.1 += v;
                last.2 += 1;
            }
            _ => out.push((start, v, 1)),
        }
    }
    out.into_iter()
        .map(|(t, sum, n)| (t, sum / f64::from(n)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(metric: &str, subject: &str, at: i64, value: f64) -> Sample {
        Sample {
            metric: metric.into(),
            subject: subject.into(),
            at,
            value,
        }
    }

    #[test]
    fn a_counter_is_read_as_a_rate_and_a_restart_gives_no_point() {
        let samples = [
            at("net_rx", "a", 0, 1_000.0),
            at("net_rx", "a", 60, 7_000.0),
            at("net_rx", "a", 120, 13_000.0),
            // The machine rebooted: its counter began again.
            at("net_rx", "a", 180, 500.0),
            at("net_rx", "a", 240, 6_500.0),
        ];
        let l = lines(Metric::NetIn, Window::Hour, &samples, &BTreeMap::new());
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].points, vec![(60, 100.0), (120, 100.0), (240, 100.0)]);
    }

    #[test]
    fn a_gap_in_measurement_stays_a_gap() {
        // 🔴 An hour without an answer is not an hour at the average of its two ends.
        let samples = [at("cpu", "a", 0, 0.2), at("cpu", "a", 7_200, 0.8)];
        let l = lines(Metric::Cpu, Window::Day, &samples, &BTreeMap::new());
        assert_eq!(l[0].points.len(), 2);
        let net = [at("net_rx", "a", 0, 0.0), at("net_rx", "a", 7_200, 7_200.0)];
        assert_eq!(
            lines(Metric::NetIn, Window::Day, &net, &BTreeMap::new())[0].points,
            vec![]
        );
    }

    #[test]
    fn each_disk_is_its_own_line_named_after_its_machine() {
        let samples = [
            at("disk:/", "10.0.0.1:8421", 0, 0.3),
            at("disk:/var", "10.0.0.1:8421", 0, 0.9),
        ];
        let names = BTreeMap::from([("10.0.0.1:8421".to_string(), "small-01".to_string())]);
        let l = lines(Metric::Disk, Window::Day, &samples, &names);
        assert_eq!(
            l.iter()
                .map(|x| (x.name.as_str(), x.disk.as_deref()))
                .collect::<Vec<_>>(),
            vec![("small-01", Some("/")), ("small-01", Some("/var"))]
        );
    }

    #[test]
    fn a_day_is_averaged_into_steps_of_twelve_minutes() {
        let samples: Vec<Sample> = (0..24)
            .map(|m| at("cpu", "a", m * 60, if m < 12 { 0.2 } else { 0.4 }))
            .collect();
        let l = lines(Metric::Cpu, Window::Day, &samples, &BTreeMap::new());
        let rounded: Vec<(i64, f64)> = l[0]
            .points
            .iter()
            .map(|&(t, v)| (t, (v * 100.0).round() / 100.0))
            .collect();
        assert_eq!(rounded, vec![(0, 0.2), (720, 0.4)]);
    }
}
