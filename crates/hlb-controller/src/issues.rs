//! `/api/issues`: what needs a person, from every source they may read, grouped by
//! cause.
//!
//! ## 🔴 The sources' own builders, never a second copy of their rules
//!
//! Each source is read through the function its own route answers with — the health
//! checks and the exposure decide their cause in the branch that writes their
//! sentence. A rule restated here would say "fine" the day the original moves.
//!
//! ## And only what the person may read
//!
//! The accounts, the break-glass safeguards and the secrets need `manage-accounts`. An
//! operator's inbox is built without them — never with them and then filtered, which
//! would read data the role does not reach.

use std::sync::Arc;

use axum::extract::State as AxumState;
use hlb_api::issues::{group, Cause, Finding, Issue};
use hlb_api::{AccountState, Attention, Coverage, NodeProblem};
use hlb_types::rbac::Action;

use crate::api::AppState;
use crate::auth::{Authorized, CanRead};
use crate::error::ApiResult;
use crate::extract::Json;

/// What needs a person, one line per cause, the worst first.
#[utoipa::path(
    get,
    path = "/api/issues",
    responses(
        (status = 200, body = Vec<hlb_api::issues::Issue>)
    ),
    extensions(
        ("x-hlb-requires" = json!("read"))
    )
)]
pub async fn issues(
    auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
) -> ApiResult<Vec<Issue>> {
    let people = auth.identity().can(Action::ManageAccounts);
    let mut issues = group(findings(&s, people).await?);
    // What THIS person set aside: a service token belongs to nobody, and sets nothing.
    if let Some(account) = auth.actor().for_account() {
        let now = crate::auth::now();
        let asides = s.state.asides_of(account, now).await.unwrap_or_default();
        hlb_api::issues::apply_asides(&mut issues, &asides, now);
    }
    Ok(Json(issues))
}

/// Sets a line of the signed-in person's inbox aside, for a while.
///
/// ⚠️ No preview: it changes what one person sees, is undone in one click, and touches
/// nothing on the installation. The line stays listed — among what is set aside — and
/// comes back early if it gets worse.
#[utoipa::path(
    put,
    path = "/api/issues/aside",
    request_body = hlb_api::issues::AsideRequest,
    responses(
        (status = 204, description = "Set aside")
    ),
    extensions(
        ("x-hlb-requires" = json!("read")),
        ("x-hlb-preview" = json!(false))
    )
)]
pub async fn set_aside(
    auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
    Json(d): Json<hlb_api::issues::AsideRequest>,
) -> Result<axum::http::StatusCode, crate::error::ApiError> {
    let Some(account) = auth.actor().for_account() else {
        return Err(crate::error::ApiError::Forbidden(
            "a service token has no inbox of its own: it belongs to nobody".into(),
        ));
    };
    if d.for_s <= 0 || d.for_s > hlb_api::issues::ASIDE_MAX_S {
        return Err(crate::error::ApiError::Unprocessable(format!(
            "a line is set aside between 1 second and {} days: one with no end is a \
             problem deleted, not deferred",
            hlb_api::issues::ASIDE_MAX_S / 86_400
        )));
    }
    // Remembered as it is NOW — what it covers and how bad it is — so a worse line is
    // recognised as one. A cause no longer in the inbox has nothing to set aside.
    let people = auth.identity().can(Action::ManageAccounts);
    let current = group(findings(&s, people).await?);
    let Some(issue) = current.iter().find(|i| i.cause == d.cause) else {
        return Err(crate::error::ApiError::NotFound(
            "this line is no longer in the inbox".into(),
        ));
    };
    s.record(hlb_api::intent::SetAside {
        user: account.to_string(),
        aside: hlb_api::issues::Aside {
            cause: d.cause,
            until: crate::auth::now() + d.for_s,
            attention: issue.attention,
            subjects: issue.subjects.len(),
        },
    })
    .await
    .map_err(crate::error::ApiError::Internal)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Brings a line set aside back into view.
#[utoipa::path(
    delete,
    path = "/api/issues/aside",
    request_body = hlb_api::issues::BackRequest,
    responses(
        (status = 204, description = "Back in view")
    ),
    extensions(
        ("x-hlb-requires" = json!("read")),
        ("x-hlb-preview" = json!(false))
    )
)]
pub async fn bring_back(
    auth: Authorized<CanRead>,
    AxumState(s): AxumState<Arc<AppState>>,
    Json(d): Json<hlb_api::issues::BackRequest>,
) -> Result<axum::http::StatusCode, crate::error::ApiError> {
    let Some(account) = auth.actor().for_account() else {
        return Err(crate::error::ApiError::Forbidden(
            "a service token has no inbox of its own: it belongs to nobody".into(),
        ));
    };
    let asked = hlb_api::intent::BringBack {
        user: account.to_string(),
        cause: d.cause,
    };
    if !s
        .record(asked)
        .await
        .map_err(crate::error::ApiError::Internal)?
    {
        return Err(crate::error::ApiError::NotFound(
            "this line was not set aside".into(),
        ));
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Every finding, source by source.
pub async fn findings(s: &AppState, people: bool) -> Result<Vec<Finding>, crate::error::ApiError> {
    let mut out: Vec<Finding> = Vec::new();

    // --- Applications --------------------------------------------------------
    for (name, status) in s.state.installed_apps().await? {
        let app = crate::api::summarise(s, &name, status).await?;
        // The backup reasons are the coverage's, below: said twice they were two lines.
        let cause = match app.status.as_str() {
            "failed" => Some((Cause::AppFailed, Attention::Critical)),
            "partial" => Some((Cause::AppPartial, Attention::Notice)),
            _ => None,
        };
        if let Some((cause, attention)) = cause {
            out.push((cause, attention, Some(app.name)));
        }
    }
    for (app, _) in s.state.installed_apps().await? {
        if !crate::actions::catalog_changes(s, &app).await.is_empty() {
            out.push((Cause::CatalogChanged, Attention::Notice, Some(app)));
        }
    }
    // Read against the catalog loaded, the sources' last fetched indexes: a source
    // that revokes a version is heard by the next fetch.
    if let Some(catalog) = s.catalog.get() {
        for (app, _) in s.state.installed_apps().await? {
            let source = s.state.app_source(&app).await?;
            let Some(version) = s.state.app_release(&app).await?.version else {
                continue;
            };
            if catalog
                .revocation(&app, source.as_deref(), &version)
                .is_some()
            {
                out.push((Cause::VersionRevoked, Attention::Critical, Some(app)));
            }
        }
    }
    // Still declared: a job the manifest has dropped since is not left reporting work
    // nobody asks for any more.
    for run in s.state.job_runs().await? {
        let declared = s
            .state
            .app_manifest(&run.app)
            .await
            .is_ok_and(|m| m.spec.jobs.iter().any(|j| j.id == run.job));
        if !run.succeeded && declared {
            out.push((Cause::JobFailed, Attention::Notice, Some(run.app)));
        }
    }
    out.extend(crate::updates::findings(&s.state).await);
    let now = crate::auth::now();
    out.extend(crate::mail_queue::findings(&s.state, now).await);
    for (app, _, _, blocking) in s.state.pending_guides().await? {
        out.push(if blocking {
            (Cause::GuideBlocking, Attention::Critical, Some(app))
        } else {
            (Cause::GuidePending, Attention::Notice, Some(app))
        });
    }

    // --- Data -------------------------------------------------------------------
    for c in crate::api::coverage_now(s).await {
        let cause = match c.coverage() {
            Coverage::NoDestination => Some(Cause::NoBackupDestination),
            Coverage::NeverBackedUp => Some(Cause::NeverBackedUp),
            Coverage::NoFreshCopy { .. } => Some(Cause::NoFreshCopy),
            Coverage::OneFreshCopy { .. } => Some(Cause::OneFreshCopy),
            Coverage::FreshCopies { .. } => None,
        };
        if let Some(cause) = cause {
            out.push((cause, c.attention(), Some(c.app)));
        }
    }

    // --- Infrastructure ---------------------------------------------------------
    for n in crate::api::nodes_summary(s).await {
        let cause = match &n.problem() {
            Some(NodeProblem::Unreachable) => Some(Cause::NodeUnreachable),
            Some(NodeProblem::DiskFull { .. }) => Some(Cause::NodeDiskFull),
            Some(NodeProblem::DiskFilling { .. }) => Some(Cause::NodeDiskFilling),
            Some(NodeProblem::Swapping) => Some(Cause::NodeSwapping),
            Some(NodeProblem::Load { .. }) => Some(Cause::NodeLoad),
            Some(NodeProblem::RebootPending) => Some(Cause::NodeRebootPending),
            None => None,
        };
        if let Some(cause) = cause {
            out.push((
                cause,
                n.attention(),
                Some(n.hostname.clone().unwrap_or(n.address)),
            ));
        }
    }
    out.extend(reboot_stopped(&s.state).await?);
    let topology = crate::api::topology_now(s).await;
    out.push((
        Cause::Topology {
            verdict: topology.verdict(),
        },
        topology.attention(),
        None,
    ));
    for d in crate::api::drifts_now(s).await? {
        out.push((Cause::Drift, d.attention(), Some(d.target.clone())));
    }
    for (check, cause) in crate::health::findings(&s.state, s.beat.as_deref(), now).await {
        if let Some(cause) = cause {
            out.push((cause, check.attention, None));
        }
    }

    // --- Security -----------------------------------------------------------------
    out.extend(certificates(&s.state, now).await);
    out.extend(crate::assertions::findings(&s.state, now).await);
    out.extend(crate::flaws::findings(&s.state, now).await);
    out.extend(crate::mail_dns::findings(&s.state, now).await);
    out.extend(crate::domain::findings(&s.state, now).await);
    for (route, cause) in crate::exposure::findings(&s.state).await {
        if let Some(cause) = cause {
            out.push((cause, route.attention(), Some(route.host)));
        }
    }

    // --- Activity -----------------------------------------------------------------
    for a in crate::api::alerts_now(s).await? {
        let evaluable = a.alert.level != hlb_api::AlertLevel::Unknown;
        // An alert saying what a line already says is that line: `backup-absent` beside
        // "6 applications never backed up" was the same problem read twice. A rule that
        // cannot be evaluated restates nothing — the watch is blind, which is news.
        let cause = match restated(&a.alert.rule) {
            Some(Some(cause)) if evaluable => cause,
            _ => Cause::Alert {
                rule: a.alert.rule.clone(),
                evaluable,
            },
        };
        out.push((cause, a.attention, None));
    }

    // --- People: only for a role that may read them ---------------------------------
    if people {
        for a in crate::accounts::resumes(s).await {
            let cause = match a.coherence {
                AccountState::Complete => None,
                AccountState::WithoutMailbox => Some(Cause::AccountWithoutMailbox),
                AccountState::WithoutIdentity => Some(Cause::AccountWithoutIdentity),
                AccountState::Empty => Some(Cause::AccountEmpty),
            };
            if let Some(cause) = cause {
                out.push((cause, a.coherence.attention(), Some(a.name.clone())));
            }
            // 🔴 An address its owner believes closed still receives: a broken promise.
            if a.broken_promises > 0 {
                out.push((
                    Cause::AliasStillReceiving,
                    Attention::Critical,
                    Some(a.name),
                ));
            }
        }
        let kit = crate::recovery::kit_now(s).await;
        for g in crate::recovery::state(&s.state, kit.as_deref()).await {
            out.push((Cause::Safeguard, g.attention(), Some(g.id.clone())));
        }
        for secret in crate::api::rotation_now(s).await {
            let cause = if secret.never_rotated {
                Cause::SecretNeverRotated
            } else {
                Cause::SecretRotationDue
            };
            out.push((cause, secret.attention(), Some(secret.name)));
        }
    }

    Ok(out)
}

/// The fleet's mTLS leaves ending without having been renewed: critical in the last
/// week, when the agents are days from refusing the controller.
async fn certificates(state: &hlb_state::State, now: i64) -> Vec<Finding> {
    let known = state.leaf_expiries().await.unwrap_or_default();
    hlb_engine::pki::ending(&known, now)
        .into_iter()
        .map(|(service, t)| {
            let attention = if hlb_engine::pki::days_left(t, now) < 7 {
                Attention::Critical
            } else {
                Attention::Notice
            };
            (Cause::CertificateExpiring, attention, Some(service))
        })
        .collect()
}

/// A node the house's own reboot gave up on. Draining and rebooting are not a line: the
/// reboot is under way, and the node's reading says it waits for one.
async fn reboot_stopped(state: &hlb_state::State) -> Result<Vec<Finding>, hlb_state::Error> {
    Ok(state
        .node_reboot()
        .await?
        .filter(|r| r.phase == hlb_state::RebootPhase::Stopped)
        .map(|r| {
            (
                Cause::NodeRebootStopped,
                Attention::Critical,
                Some(r.hostname),
            )
        })
        .into_iter()
        .collect())
}

/// The cause an alert rule says again, if it says one: `Some(None)` for a rule that is
/// its own line, `None` for a name this function was never told about.
///
/// ⚠️ Not a catch-all: a rule added to `hlb_metrics::default_rules` and not here is
/// `None`, and `every_rule_is_decided` fails until someone decides.
fn restated(rule: &str) -> Option<Option<Cause>> {
    Some(match rule {
        "backup-absent" => Some(Cause::NeverBackedUp),
        "backup-late" => Some(Cause::NoFreshCopy),
        "single-copy" => Some(Cause::OneFreshCopy),
        "app-failed" => Some(Cause::AppFailed),
        "node-unreachable" => Some(Cause::NodeUnreachable),
        "disk-full" => Some(Cause::NodeDiskFull),
        "blocking-guides" => Some(Cause::GuideBlocking),
        // No source below the alerts sees a verification's age.
        "verification-stale" => None,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_reboot_given_up_is_a_line_and_one_under_way_is_not() {
        use hlb_state::RebootPhase;
        let st = hlb_state::State::in_memory().await.expect("state");
        assert!(reboot_stopped(&st).await.expect("read").is_empty());
        st.begin_node_reboot("n1", "deb2", RebootPhase::Draining, true, 10)
            .await
            .expect("begin");
        assert!(reboot_stopped(&st).await.expect("read").is_empty());
        st.set_node_reboot_phase("n1", RebootPhase::Stopped, 20, Some("did not move"))
            .await
            .expect("stop");
        assert_eq!(
            reboot_stopped(&st).await.expect("read"),
            vec![(
                Cause::NodeRebootStopped,
                Attention::Critical,
                Some("deb2".to_string())
            )]
        );
    }

    #[test]
    fn every_rule_is_decided() {
        let undecided: Vec<&str> = hlb_metrics::rules::default_rules()
            .iter()
            .map(|r| r.name)
            .filter(|name| restated(name).is_none())
            .collect();
        assert_eq!(undecided, Vec::<&str>::new());
    }

    #[tokio::test]
    async fn the_demonstration_is_one_line_a_cause() {
        let st = hlb_state::State::in_memory().await.expect("state");
        hlb_privd::demo::seed_at(&st, crate::demo::Scale::Large, None)
            .await
            .expect("seed");
        let s = crate::api::tests::demo_state(st).await;
        let issues = group(findings(&s, true).await.expect("findings"));

        // Forty-eight half-created accounts are two lines, not forty-eight.
        let halves: usize = issues
            .iter()
            .filter(|i| {
                matches!(
                    i.cause,
                    Cause::AccountWithoutMailbox | Cause::AccountWithoutIdentity
                )
            })
            .map(|i| i.subjects.len())
            .sum();
        assert_eq!(halves, 48);
        assert_eq!(
            issues
                .iter()
                .filter(|i| i.cause == Cause::AccountWithoutMailbox)
                .count(),
            1
        );
        // `backup-absent` is the never-backed-up line, not a second one.
        assert!(!issues
            .iter()
            .any(|i| matches!(&i.cause, Cause::Alert { rule, .. } if rule == "backup-absent")));
        // One line a cause, whatever the count of causes the demonstration grows to: a
        // ceiling on lines was raised by each new cause and said nothing more.
        let mut causes: Vec<String> = issues.iter().map(|i| format!("{:?}", i.cause)).collect();
        let lines = causes.len();
        causes.sort();
        causes.dedup();
        assert_eq!(causes.len(), lines, "a cause on two lines: {causes:?}");
    }

    #[tokio::test]
    async fn a_version_its_source_revoked_is_critical_until_it_moves() {
        use hlb_catalog::index;
        let seed = [7u8; 32];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64;
        let official = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog");
        let theirs = tempfile::tempdir().expect("source");
        let copied = std::process::Command::new("cp")
            .arg("-r")
            .arg(official.join("apps/librespeed"))
            .arg(theirs.path())
            .status()
            .expect("cp")
            .success();
        assert!(copied);
        let one = tempfile::tempdir().expect("one");
        let first = index::build(theirs.path(), "community", None, one.path(), now).expect("built");
        let version = first.apps["librespeed"][0].version.clone();
        std::fs::write(
            theirs.path().join(index::REVOKED_FILE),
            format!("librespeed: [ {{ version: \"{version}\", why: \"leaks\" }} ]\n"),
        )
        .expect("revoked");
        let two = tempfile::tempdir().expect("two");
        index::build(
            theirs.path(),
            "community",
            Some(one.path()),
            two.path(),
            now,
        )
        .expect("built");
        index::sign(two.path(), &seed, None, now).expect("signed");
        let mut catalog = hlb_catalog::Catalog::default();
        catalog
            .add_signed_source("community", two.path(), &index::public_key(&seed), now)
            .expect("added");

        let st = hlb_state::State::in_memory().await.expect("state");
        let m = hlb_catalog::Catalog::load(theirs.path())
            .expect("catalog")
            .get("librespeed")
            .expect("librespeed")
            .manifest
            .clone();
        st.upsert_app("librespeed", &m, None).await.expect("app");
        let installed = |v: &str| hlb_state::Release {
            index: Some(1),
            version: Some(v.into()),
        };
        st.set_app_source("librespeed", Some("community"), &installed(&version))
            .await
            .expect("source");
        let mut s = crate::api::tests::base_state(std::sync::Arc::new(st), true);
        s.catalog = hlb_privd::catalog::SharedCatalog::new(Some(std::sync::Arc::new(catalog)));
        let revoked = |found: &[Finding]| {
            found
                .iter()
                .find(|(c, _, a)| *c == Cause::VersionRevoked && a.as_deref() == Some("librespeed"))
                .map(|(_, at, _)| *at)
        };
        let found = findings(&s, false).await.expect("findings");
        assert_eq!(revoked(&found), Some(Attention::Critical));

        // Moved to a version still offered, it is no longer said.
        s.state
            .set_app_release("librespeed", &installed("7.0.0"))
            .await
            .expect("moved");
        let found = findings(&s, false).await.expect("findings");
        assert_eq!(revoked(&found), None);
        // Nor of the official app of that name, which the revocation is not about.
        s.state
            .set_app_source("librespeed", None, &installed(&version))
            .await
            .expect("official");
        let found = findings(&s, false).await.expect("findings");
        assert_eq!(revoked(&found), None);
    }

    #[tokio::test]
    async fn a_certificate_left_to_end_is_in_the_inbox_and_critical_in_its_last_week() {
        let st = hlb_state::State::in_memory().await.expect("state");
        let now = 1_800_000_000;
        st.set_leaf_expiry("hlb-agent", Some(now + 3 * 86_400))
            .await
            .expect("record");
        st.set_leaf_expiry("hlb-controller", Some(now + 20 * 86_400))
            .await
            .expect("record");
        st.set_leaf_expiry("hlb-other", Some(now + 80 * 86_400))
            .await
            .expect("record");
        let found = certificates(&st, now).await;
        assert_eq!(
            found,
            [
                (
                    Cause::CertificateExpiring,
                    Attention::Critical,
                    Some("hlb-agent".to_string())
                ),
                (
                    Cause::CertificateExpiring,
                    Attention::Notice,
                    Some("hlb-controller".to_string())
                ),
            ]
        );
    }

    #[tokio::test]
    async fn an_operator_inbox_never_reads_the_accounts() {
        let st = hlb_state::State::in_memory().await.expect("state");
        hlb_privd::demo::seed(&st).await.expect("seed");
        let s = crate::api::tests::demo_state(st).await;
        let issues = group(findings(&s, false).await.expect("findings"));
        assert!(!issues.iter().any(|i| matches!(
            i.cause,
            Cause::AccountWithoutMailbox | Cause::Safeguard | Cause::SecretNeverRotated
        )));
    }
}
