//! The installation checklist.
//!
//! ## 🔴 What this is NOT
//!
//! It is **not** a setup wizard, deliberately. A web interface cannot
//! be the first step of an installation — you already need a cluster, a controller and a
//! token to reach it.
//!
//! It is an **after-the-fact** checklist: the things you believe are done and have never
//! verified. Each one points at the screen or the command that fixes it.
//!
//! ## What each line says about itself
//!
//! A line cannot be "green" for lack of information. Not knowing is a third state —
//! `Unknown` — because a green obtained through ignorance attests to a verification that
//! never happened, which is worse than having no checklist at all.

use hlb_api::issues::Cause;
use hlb_api::HealthFinding as Finding;
use hlb_state::State;

/// A check's result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Good,
    /// To be done, without urgency.
    Todo,
    /// 🔴 Missing, and it matters.
    Missing,
    /// Cannot be known from here.
    Unknown,
}

impl Verdict {
    fn attention(self) -> hlb_api::Attention {
        match self {
            Self::Good => hlb_api::Attention::Ok,
            Self::Todo | Self::Unknown => hlb_api::Attention::Notice,
            Self::Missing => hlb_api::Attention::Critical,
        }
    }
}

fn line(verdict: Verdict, finding: Finding, remedy: Option<&str>) -> hlb_api::HealthCheck {
    hlb_api::HealthCheck {
        attention: verdict.attention(),
        finding,
        remedy: remedy.map(str::to_string),
    }
}

/// The list, computed from the real state.
///
/// `beat`: the deadman's heartbeat file, when one is configured.
/// A check, filed under a cause or under none.
trait Filed: Sized {
    fn with(self, cause: Cause) -> (Self, Option<Cause>);
    fn fine(self) -> (Self, Option<Cause>);
}

impl Filed for hlb_api::HealthCheck {
    fn with(self, cause: Cause) -> (Self, Option<Cause>) {
        (self, Some(cause))
    }
    fn fine(self) -> (Self, Option<Cause>) {
        (self, None)
    }
}

pub async fn checks(
    state: &State,
    beat: Option<&std::path::Path>,
    now: i64,
) -> Vec<hlb_api::HealthCheck> {
    findings(state, beat, now)
        .await
        .into_iter()
        .map(|(check, _)| check)
        .collect()
}

/// Each check, and the cause the inbox files it under when it is not fine — decided in
/// the same branch, so the line on the health page and the line in the inbox cannot say
/// two different things.
pub async fn findings(
    state: &State,
    beat: Option<&std::path::Path>,
    now: i64,
) -> Vec<(hlb_api::HealthCheck, Option<Cause>)> {
    let mut out = Vec::new();

    // --- The off-site ---------------------------------------------------------
    let destinations = state.destinations().await.unwrap_or_default();
    out.push(match destinations.len() {
        0 => line(
            Verdict::Missing,
            Finding::NoDestination,
            Some("hlb backup dest add nas --location /mnt/nas/restic"),
        )
        .with(Cause::NoBackupDestination),
        // One copy disappears with the machine carrying it, and a power failure takes
        // both.
        1 => line(
            Verdict::Missing,
            Finding::SingleDestination,
            Some("hlb backup dest add offsite --location s3:…"),
        )
        .with(Cause::SingleDestination),
        n => line(
            Verdict::Good,
            Finding::Destinations { count: n as u64 },
            None,
        )
        .fine(),
    });

    // --- The recovery drill --------------------------------------------
    //
    // 🔴 The only reliable indicator that the backups work. A backup never restored is a
    // hypothesis.
    use hlb_backup::drill::{Readiness, INTERVAL_DAYS, LATE_DAYS};
    let days = state.days_since_successful_drill().await.unwrap_or(None);
    out.push(match Readiness::from_days(days) {
        Readiness::Never => line(
            Verdict::Missing,
            Finding::DrillNever,
            Some("hlb dr exercise --disposable --apply"),
        )
        .with(Cause::DrillNever),
        Readiness::Due { days } => line(
            Verdict::Todo,
            Finding::DrillDue {
                days,
                every_days: INTERVAL_DAYS,
            },
            Some("hlb dr exercise --disposable --apply"),
        )
        .with(Cause::DrillStale),
        Readiness::Overdue { days } => line(
            Verdict::Todo,
            Finding::DrillOverdue {
                days,
                late_days: LATE_DAYS,
            },
            Some("hlb dr exercise --disposable --apply"),
        )
        .with(Cause::DrillStale),
        Readiness::Ready { days } => {
            line(Verdict::Good, Finding::DrillRecent { days }, None).fine()
        }
    });

    // --- The watchdog --------------------------------------------------
    //
    // ⚠️ What this screen can NOT attest: the watchdog does not run on what it watches. A
    // green light shown BY THE CONTROLLER about the watchdog attests to one thing only —
    // that the controller is alive. The wording says so in the observation itself, or
    // the line reassures about exactly what it does not prove.
    let last = beat.and_then(|p| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
    });
    out.push(match last {
        None => line(
            Verdict::Missing,
            Finding::HeartbeatAbsent,
            Some("hlb metrics deadman --ntfy https://ntfy.sh/<topic>"),
        )
        .with(Cause::DeadmanAbsent),
        Some(t) => {
            let age = now.saturating_sub(t);
            let silent = age > 3 * 3_600;
            let check = line(
                if silent {
                    Verdict::Missing
                } else {
                    Verdict::Good
                },
                Finding::Heartbeat { age_seconds: age },
                None,
            );
            (check, silent.then_some(Cause::DeadmanSilent))
        }
    });

    // --- The admin token -------------------------------------------------------
    let tokens = state.list_tokens().await.unwrap_or_default();
    let admins = tokens.iter().filter(|(_, role, _)| role == "admin").count();
    out.push(match admins {
        0 => line(Verdict::Unknown, Finding::AdminUnknown, None).with(Cause::AdminUnknown),
        1 => line(Verdict::Good, Finding::AdminSingle, None).fine(),
        // 🔴 Each extra token is a copy of total power lying around somewhere. It is
        // not an outage, it is a surface.
        n => line(
            Verdict::Todo,
            Finding::AdminTokens { count: n as u64 },
            Some("hlb token list"),
        )
        .with(Cause::AdminTokens),
    });

    // --- The audit log ----------------------------------------------------------
    out.push(
        match state.verify_audit_chain().await.map(|i| i.is_intact()) {
            Ok(true) => line(Verdict::Good, Finding::AuditIntact, None).fine(),
            Ok(false) => line(
                Verdict::Missing,
                Finding::AuditBroken,
                Some("hlb audit --verify"),
            )
            .with(Cause::AuditBroken),
            Err(_) => line(
                Verdict::Unknown,
                Finding::AuditUnreadable,
                Some("hlb audit --verify"),
            )
            .with(Cause::AuditUnreadable),
        },
    );

    out
}
