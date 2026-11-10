//! One update, from the scan to the recorded run.
//!
//! `hlb update apply` and the controller go through this one function, so a path with
//! nobody watching cannot skip a guard the command line keeps: the scan before the
//! switch, the window, maturity, the copy first, and the run recorded whatever it gave.

use hlb_orchestrator::Orchestrator;
use hlb_state::{State, UpdateRun, UpdateRunOutcome, UpdateUndo};
use hlb_types::{Image, ImageSigner, Role};

use crate::scan::Report;
use crate::{
    apply, authorize, BackupProvider, Candidate, Error, Result, UpdateKind, UpdateOutcome,
};

/// How long Swarm's switch is watched before the outcome is `Inconclusive`.
const SWITCH_TIMEOUT_SECS: u64 = 180;

/// What a person chose to override. Each is a decision recorded in the audit log, never a
/// default — the controller passes none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Overrides {
    pub force_window: bool,
    pub force_vulnerable: bool,
    pub before_maturity: bool,
}

/// Who the audit log names.
#[derive(Debug, Clone, Copy)]
pub struct Actor<'a> {
    pub name: &'a str,
    pub role: Role,
}

/// Checks an image before it runs, against the one it `replacing`, when one runs. A
/// trait so a test stands in; `crate::grype::Grype` is the one that runs.
#[async_trait::async_trait]
pub trait Scanner: Send + Sync {
    async fn audit(
        &self,
        image: &str,
        signer: Option<&ImageSigner>,
        replacing: Option<&str>,
    ) -> Result<Report>;
}

/// What happened so far, said as it happens: the switch alone can take minutes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// Every image that will start, checked: each report described.
    Scanned {
        described: String,
    },
    /// Critical findings let through by `force_vulnerable`.
    VulnerableForced,
    /// Applied before its maturity, by `before_maturity`.
    BeforeMaturity {
        why: String,
    },
    /// The app holds nothing to copy, or asks for no copy.
    NoCopyOwed,
    CopyStarted,
    /// The copy taken: every snapshot of it, kept with the run for an undo.
    Copied {
        snapshots: Vec<String>,
    },
    /// The switch starts.
    Switching {
        describe: String,
    },
}

/// Why an update did not start. Nothing ran and nothing changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A check blocks: critical vulnerabilities, or a signature that is not the publisher's.
    Vulnerable {
        described: String,
    },
    OutsideWindow,
    Immature {
        why: String,
    },
    /// The copy owed before the switch failed: no copy, no switch.
    CopyFailed {
        error: String,
    },
}

/// What one update came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ran {
    Refused(Refusal),
    /// The switch ran; its outcome is recorded as an update run.
    Switched(UpdateOutcome),
}

/// What an update needs besides the candidate.
pub struct Update<'a, O: Orchestrator + ?Sized> {
    pub orchestrator: &'a O,
    pub state: &'a State,
    /// The catalog's image for the app, whose signer a frozen manifest may predate.
    pub in_catalog: Option<&'a Image>,
    /// `None` when no destination is declared: an app owing a copy is then refused.
    pub backup: Option<&'a dyn BackupProvider>,
    pub scanner: &'a dyn Scanner,
    pub overrides: Overrides,
    pub actor: Actor<'a>,
    /// Seconds since the epoch, for maturity.
    pub now: i64,
}

impl<O: Orchestrator + ?Sized> Update<'_, O> {
    /// Runs one update to its end, or refuses it before anything changed.
    pub async fn run(
        &self,
        c: &Candidate,
        progress: &mut (dyn FnMut(Progress) + Send),
    ) -> Result<Ran> {
        let app = c.app.as_str();
        let installed = self.state.app_manifest(app).await?.spec;

        // 🔴 Scan BEFORE deploying, not after. A critical image deployed and then flagged
        // has already run. And the digest that will run: a rebuild was scanned as the
        // installed image's own reference, its OLD digest, and a tag alone may name another
        // build by now. Each image against its own publisher's signer.
        // Against what runs now: what the move brings, not what both carry.
        let mut reports = Vec::new();
        let replaced = c.replaced(&installed);
        for (i, (image, signer)) in c
            .to_verify(&installed.image, self.in_catalog)
            .into_iter()
            .enumerate()
        {
            let before = replaced.get(i).cloned().flatten();
            reports.push(
                self.scanner
                    .audit(&image, signer.as_ref(), before.as_deref())
                    .await?,
            );
        }
        let blocks = reports.iter().any(Report::blocks);
        let described = reports
            .iter()
            .map(Report::describe)
            .collect::<Vec<_>>()
            .join("\n");
        progress(Progress::Scanned {
            described: described.clone(),
        });

        if blocks && !self.overrides.force_vulnerable {
            self.audit("update-refused", app, "refused", Some(&described))
                .await?;
            return Ok(Ran::Refused(Refusal::Vulnerable { described }));
        }
        if blocks {
            progress(Progress::VulnerableForced);
            self.audit("update-forced", app, "ok", Some(&described))
                .await?;
        }

        if !c.in_window && !self.overrides.force_window {
            return Ok(Ran::Refused(Refusal::OutsideWindow));
        }

        // 🔴 No copy available, no update.
        match authorize(
            c,
            self.backup,
            self.overrides.force_window,
            self.overrides.before_maturity,
            self.now,
        ) {
            Err(Error::Immature { why, .. }) => {
                return Ok(Ran::Refused(Refusal::Immature { why }));
            }
            other => other?,
        }
        if let Some(why) = c.maturity.refusal(self.now) {
            progress(Progress::BeforeMaturity { why: why.clone() });
            self.audit("update-before-maturity", app, "ok", Some(&why))
                .await?;
        }

        let copies = match (c.needs_backup, self.backup) {
            (false, _) => {
                progress(Progress::NoCopyOwed);
                Vec::new()
            }
            (true, Some(p)) => {
                progress(Progress::CopyStarted);
                match p.snapshot(app).await {
                    Ok(snapshots) => {
                        progress(Progress::Copied {
                            snapshots: snapshots.clone(),
                        });
                        snapshots
                    }
                    Err(error) => return Ok(Ran::Refused(Refusal::CopyFailed { error })),
                }
            }
            // `authorize` refused it above.
            (true, None) => {
                return Err(Error::BackupRequired {
                    app: app.to_string(),
                })
            }
        };

        progress(Progress::Switching {
            describe: c.describe(),
        });
        let from = installed.image.reference();
        // Read before the switch: `apply` freezes the companions' new images.
        let companions_from = c
            .companions
            .iter()
            .filter_map(|m| {
                let before = installed.companions.iter().find(|x| x.name == m.name)?;
                Some((m.name.clone(), before.image.reference()))
            })
            .collect();
        let outcome = apply(self.orchestrator, self.state, c, SWITCH_TIMEOUT_SECS).await?;

        // Every outcome is recorded, success included: the controller notifies each, and an
        // update said nowhere is silence.
        let (recorded, detail) = match &outcome {
            UpdateOutcome::Applied { .. } => (UpdateRunOutcome::Applied, String::new()),
            UpdateOutcome::RolledBack { reason } => (UpdateRunOutcome::RolledBack, reason.clone()),
            UpdateOutcome::Paused => (UpdateRunOutcome::Paused, String::new()),
            UpdateOutcome::Inconclusive => (UpdateRunOutcome::Inconclusive, String::new()),
        };
        let to = target(c, &installed.image);
        let with: Vec<String> = c
            .companions
            .iter()
            .map(|m| format!("{} → {}", m.name, m.to.reference()))
            .collect();
        let detail = match (with.is_empty(), detail.is_empty()) {
            (true, _) => detail,
            (false, true) => format!("with {}", with.join(", ")),
            (false, false) => format!("with {}; {detail}", with.join(", ")),
        };
        self.state
            .record_update_run(&UpdateRun {
                id: 0,
                app: app.to_string(),
                ran_at: chrono::Utc::now().timestamp(),
                from_image: from,
                to_image: to.clone(),
                outcome: recorded,
                detail,
                undo: Some(UpdateUndo {
                    copies,
                    companions: companions_from,
                }),
            })
            .await?;
        self.audit(
            &format!("update-{}", recorded.as_str()),
            app,
            if outcome.is_success() { "ok" } else { "failed" },
            Some(&to),
        )
        .await?;
        Ok(Ran::Switched(outcome))
    }

    async fn audit(
        &self,
        action: &str,
        app: &str,
        outcome: &str,
        detail: Option<&str>,
    ) -> Result<()> {
        Ok(self
            .state
            .audit(
                self.actor.name,
                self.actor.role,
                action,
                app,
                outcome,
                detail,
            )
            .await?)
    }
}

/// `repo:tag@digest` the app moves to.
fn target(c: &Candidate, installed: &Image) -> String {
    let named = match &c.kind {
        UpdateKind::NewVersion { to_tag } => format!("{}:{to_tag}", installed.repo),
        UpdateKind::Catalog { repo, tag } => format!("{repo}:{tag}"),
        UpdateKind::DigestOnly | UpdateKind::Companions => {
            format!("{}:{}", installed.repo, installed.tag)
        }
    };
    format!("{named}@{}", c.to_digest)
}
