//! The unified timeline (batch 9.5).
//!
//! ## 🔴 What only a timeline makes possible
//!
//! "The app went down at 03:12" and "update applied at 03:10" are two facts filed in two
//! different tables. Bringing them together means opening two screens and comparing
//! times by hand — and that is exactly what you do, badly, at the moment you are in a
//! hurry.
//!
//! ## ⚠️ A mute source is not an empty source
//!
//! If the audit log cannot be re-read, the timeline does not display "nothing happened":
//! it loses a source without saying so, and you would conclude that no human action
//! preceded the outage. Read errors are therefore carried in the timeline itself, as
//! events.

use hlb_api::{Attention, Event, EventKind};
use hlb_state::State;

/// Converts a SQLite timestamp (`YYYY-MM-DD HH:MM:SS`, UTC) into seconds.
///
/// ⚠️ SQLite writes with no timezone and no `T`. `chrono` would refuse that format as RFC
/// 3339: we read it by hand rather than return `None` on every row, which would give an
/// empty timeline on perfectly healthy data.
fn parse_timestamp(s: &str) -> Option<i64> {
    let (date, time_part) = s.split_once(['T', ' '])?;
    let mut d = date.split('-');
    let (year, month, day): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let mut h = time_part.trim_end_matches('Z').split(':');
    let (hh, mm, ss): (i64, i64, f64) = (
        h.next()?.parse().ok()?,
        h.next()?.parse().ok()?,
        h.next().unwrap_or("0").parse().ok()?,
    );

    // Days since the epoch, the civil-days algorithm (Howard Hinnant).
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    Some(days * 86_400 + hh * 3_600 + mm * 60 + ss as i64)
}

/// The recent events, across every source, newest first.
pub async fn events(state: &State, limit: usize) -> Vec<Event> {
    let mut out = Vec::new();

    // --- The backups ----------------------------------------------------------
    match state.backup_history_all(limit).await {
        Ok(runs) => {
            for r in runs {
                let failure = r.status != "ok";
                out.push(Event {
                    when: parse_timestamp(&r.finished_at).unwrap_or(0),
                    kind_of: EventKind::Backup,
                    target: r.app.clone(),
                    what: match (&r.destination, &r.error) {
                        (Some(d), Some(e)) => format!("{} to {d}: {e}", r.kind),
                        (Some(d), None) => format!("{} to {d}", r.kind),
                        (None, Some(e)) => format!("{}: {e}", r.kind),
                        (None, None) => r.kind.clone(),
                    },
                    attention: if failure {
                        Attention::Critical
                    } else {
                        Attention::Ok
                    },
                });
            }
        }
        Err(e) => out.push(silent_source("backups", &e.to_string())),
    }

    // --- The audit log ----------------------------------------------------------
    match state.audit_trail(limit).await {
        Ok(entries) => {
            for a in entries {
                out.push(Event {
                    when: parse_timestamp(&a.at).unwrap_or(0),
                    kind_of: EventKind::Action,
                    target: a.target.clone(),
                    what: format!("{} by {} ({})", a.action, a.actor, a.outcome),
                    attention: match a.outcome.as_str() {
                        "failed" => Attention::Critical,
                        // 🔴 A refusal is NOT a failure: it is the system that
                        // protected. Painting them the same would send you looking for
                        // an outage where a guard worked.
                        "refused" => Attention::Notice,
                        _ => Attention::Ok,
                    },
                });
            }
        }
        Err(e) => out.push(silent_source("audit log", &e.to_string())),
    }

    // Newest first: what just happened is what you are looking for.
    out.sort_by_key(|e| std::cmp::Reverse(e.when));
    out.truncate(limit);
    out
}

/// A source that could not be read, carried IN the timeline.
///
/// 🔴 Staying quiet about it would have you conclude "nothing happened" when you know
/// nothing — and this screen is read in the middle of an outage.
fn silent_source(what: &str, detail: &str) -> Event {
    Event {
        when: crate::auth::now(),
        kind_of: EventKind::Alert,
        target: what.to_string(),
        what: format!("this source could not be read: {detail}"),
        attention: Attention::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sqlite_timestamp_is_read_without_a_timezone() {
        // ⚠️ SQLite writes "2026-08-19 07:12:00": no "T", no "Z". Refusing it as RFC
        // 3339 would return `None` on EVERY row, and the timeline would be empty on
        // perfectly healthy data.
        assert_eq!(parse_timestamp("1970-01-01 00:00:00"), Some(0));
        assert_eq!(parse_timestamp("2000-01-01 00:00:00"), Some(946_684_800));
        assert_eq!(parse_timestamp("2026-08-19 07:12:00"), Some(1_787_123_520));
        // And the RFC 3339 form passes too: both coexist in the database.
        assert_eq!(parse_timestamp("2000-01-01T00:00:00Z"), Some(946_684_800));
    }

    #[test]
    fn an_unreadable_source_appears_instead_of_vanishing() {
        // 🔴 The heart of it: losing a source in silence would have you conclude "no
        // human action preceded the outage".
        let e = silent_source("audit log", "database locked");
        assert_eq!(e.attention, Attention::Critical);
        assert!(e.what.contains("could not be read"));
    }

    #[tokio::test]
    async fn the_river_is_sorted_newest_first_across_sources() {
        let s = State::in_memory().await.expect("state");
        s.record_backup_to("gitea", "volume", "nas", Some("a"), None)
            .await
            .expect("backup");
        s.audit(
            "lena",
            hlb_types::Role::Admin,
            "install",
            "gitea",
            "ok",
            None,
        )
        .await
        .expect("audit");

        let f = events(&s, 50).await;
        assert!(f.len() >= 2, "{f:#?}");
        // Both sources are present in the SAME list: that is the whole point.
        assert!(f.iter().any(|e| e.kind_of == EventKind::Backup));
        assert!(f.iter().any(|e| e.kind_of == EventKind::Action));
        // And the order is descending.
        for w in f.windows(2) {
            assert!(w[0].when >= w[1].when, "{f:#?}");
        }
    }

    #[tokio::test]
    async fn a_refusal_is_never_painted_like_a_failure() {
        // A refusal is a guard that worked; a failure is an outage. Painting them the
        // same would send you looking for a problem where there is none.
        let s = State::in_memory().await.expect("state");
        s.audit(
            "viewer",
            hlb_types::Role::Viewer,
            "remove",
            "gitea",
            "refused",
            None,
        )
        .await
        .expect("audit");
        s.audit(
            "lena",
            hlb_types::Role::Admin,
            "backup",
            "immich",
            "failed",
            None,
        )
        .await
        .expect("audit");

        let f = events(&s, 50).await;
        let refusal = f
            .iter()
            .find(|e| e.what.contains("refused"))
            .expect("refusal");
        let failure = f
            .iter()
            .find(|e| e.what.contains("failed"))
            .expect("failure");
        assert_eq!(refusal.attention, Attention::Notice);
        assert_eq!(failure.attention, Attention::Critical);
    }
}
