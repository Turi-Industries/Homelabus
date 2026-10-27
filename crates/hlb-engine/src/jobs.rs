//! The manifests' scheduled jobs (`spec.jobs`): run in the app's running container when
//! they are due, by the controller, and on demand by `hlb job`.
//!
//! 🔴 A job that stays silent cannot be told from a job that does nothing: every run is
//! recorded, the failed ones are in the inbox, and one never run is due at once.

use hlb_orchestrator::Orchestrator;
use hlb_state::{JobRun, State};
use hlb_types::{Job, Manifest};

/// How much of what a run printed is kept: the end, where the error is.
pub const OUTPUT_KEPT: usize = 2_000;

/// A failed run is tried again a day later rather than a period later: a weekly job
/// failing once would otherwise leave its work undone for two weeks.
const RETRY_AFTER_S: i64 = 86_400;

/// When a job runs next, given its last run: at once when it never ran.
pub fn next_run(j: &Job, last: Option<&JobRun>) -> Option<i64> {
    let r = last?;
    Some(
        r.ran_at
            + if r.succeeded {
                j.every.seconds()
            } else {
                j.every.seconds().min(RETRY_AFTER_S)
            },
    )
}

/// The jobs of `m` due at `now`, given every job's last run.
pub fn due<'a>(m: &'a Manifest, runs: &[JobRun], now: i64) -> Vec<&'a Job> {
    m.spec
        .jobs
        .iter()
        .filter(|j| {
            let last = runs
                .iter()
                .find(|r| r.app == m.metadata.name && r.job == j.id);
            next_run(j, last).is_none_or(|at| now >= at)
        })
        .collect()
}

/// Runs one job now, and records it.
pub async fn run<O: Orchestrator + ?Sized>(
    orch: &O,
    state: &State,
    app: &str,
    job: &Job,
    now: i64,
) -> crate::Result<JobRun> {
    let (succeeded, output) = match orch.exec_in_service(app, &job.command).await {
        Ok(o) => {
            let printed = format!("{}{}", o.stdout, o.stderr);
            let said = if o.ok() {
                printed
            } else {
                format!("{printed}\nexit {}", o.exit_code)
            };
            (o.ok(), said)
        }
        Err(e) => (false, format!("not run: {e}")),
    };
    let run = JobRun {
        app: app.to_string(),
        job: job.id.clone(),
        ran_at: now,
        succeeded,
        output: tail(output.trim(), OUTPUT_KEPT),
    };
    state.record_job_run(&run).await?;
    Ok(run)
}

/// What one pass over every installed app did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pass {
    pub ran: usize,
    /// `app/job: the end of what it said`.
    pub failed: Vec<String>,
}

/// Runs every job due, app by app. A failed app's jobs wait: its container may not be
/// the one its manifest describes.
pub async fn run_due<O: Orchestrator + ?Sized>(orch: &O, state: &State, now: i64) -> Pass {
    let mut pass = Pass::default();
    let runs = state.job_runs().await.unwrap_or_default();
    for (app, status) in state.installed_apps().await.unwrap_or_default() {
        if status == "failed" {
            continue;
        }
        let Ok(m) = state.app_manifest(&app).await else {
            continue;
        };
        for job in due(&m, &runs, now) {
            pass.ran += 1;
            match run(orch, state, &app, job, now).await {
                Ok(r) if r.succeeded => {}
                Ok(r) => pass
                    .failed
                    .push(format!("{app}/{}: {}", job.id, tail(&r.output, 300))),
                Err(e) => pass
                    .failed
                    .push(format!("{app}/{}: not recorded: {e}", job.id)),
            }
        }
    }
    pass
}

/// The last `max` characters of `s`, cut on a character.
fn tail(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    format!("…{}", s.chars().skip(n - max).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        serde_yaml_ng::from_str(
            r#"
apiVersion: hlb/v1
kind: App
metadata: { name: files }
spec:
  image: { repo: a/b, tag: "1" }
  jobs:
    - { id: gc, does: frees blocks, every: week, command: [/gc.sh] }
    - { id: tidy, does: tidies, every: day, command: [/tidy.sh] }
"#,
        )
        .expect("manifest")
    }

    fn ran(job: &str, ago: i64, succeeded: bool) -> JobRun {
        JobRun {
            app: "files".into(),
            job: job.into(),
            ran_at: 1_000_000 - ago,
            succeeded,
            output: String::new(),
        }
    }

    #[test]
    fn the_next_run_is_a_period_after_a_success_and_a_day_after_a_failure() {
        let m = manifest();
        let gc = &m.spec.jobs[0];
        assert_eq!(next_run(gc, None), None, "never run: due at once");
        let ok = ran("gc", 0, true);
        assert_eq!(next_run(gc, Some(&ok)), Some(ok.ran_at + 7 * 86_400));
        let failed = ran("gc", 0, false);
        assert_eq!(next_run(gc, Some(&failed)), Some(failed.ran_at + 86_400));
    }

    fn ids(jobs: Vec<&Job>) -> Vec<&str> {
        jobs.iter().map(|j| j.id.as_str()).collect()
    }

    #[test]
    fn a_job_never_run_is_due_at_once() {
        assert_eq!(ids(due(&manifest(), &[], 1_000_000)), ["gc", "tidy"]);
    }

    #[test]
    fn a_job_is_due_again_a_period_after_a_success_and_a_day_after_a_failure() {
        let m = manifest();
        let now = 1_000_000;
        let ok_two_days = [ran("gc", 2 * 86_400, true), ran("tidy", 2 * 86_400, true)];
        assert_eq!(ids(due(&m, &ok_two_days, now)), ["tidy"]);
        let failed_two_days = [ran("gc", 2 * 86_400, false), ran("tidy", 3_600, true)];
        assert_eq!(ids(due(&m, &failed_two_days, now)), ["gc"]);
        let failed_an_hour = [ran("gc", 3_600, false), ran("tidy", 3_600, true)];
        assert!(due(&m, &failed_an_hour, now).is_empty());
    }

    #[test]
    fn what_a_run_printed_is_kept_by_its_end() {
        let long = format!("{}error: disk full", "x".repeat(5_000));
        let kept = tail(&long, 40);
        assert!(kept.ends_with("error: disk full") && kept.chars().count() == 41);
        assert_eq!(tail("é short", 40), "é short");
    }
}
