//! What needs a person, grouped by CAUSE.
//!
//! ## 🔴 One problem is one line
//!
//! Six applications never backed up, and the alert saying so, were seven lines of the
//! home's inbox — the person read one problem seven times and lost the other twenty-four
//! under it. A thousand accounts made it worse: forty-eight half-created ones were
//! forty-eight lines. Grouped by cause, they are one line each, naming what they cover.
//!
//! The grouping is a rule, so it lives here and not in the interface: two clients
//! grouping separately would disagree about how many things are wrong.
//!
//! ## And the cause is a value, never a sentence
//!
//! The interface words each [`Cause`] in the person's language. The sentences the
//! sources wrote were English on a French screen — half the home's lines.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{Attention, TopologyVerdict};

/// Why something needs a person. Exhaustive: a cause added here does not compile in an
/// interface that has no words for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Cause {
    // --- Applications ---------------------------------------------------------
    /// The deployment failed.
    AppFailed,
    /// Running with fewer replicas than wanted.
    AppPartial,
    /// A manual step blocks the deployment.
    GuideBlocking,
    /// A manual step is waiting, without blocking anything.
    GuidePending,
    /// The catalog has changed it since it was installed: `hlb upgrade` applies it.
    CatalogChanged,
    /// 🔴 It runs a version its catalog source has revoked — a flaw the source found,
    /// whose reason `hlb catalog source fetch` prints. The subjects are the apps;
    /// `hlb upgrade` takes each to the newest version still offered.
    VersionRevoked,
    /// A scheduled job of its manifest failed its last run — Seafile's garbage
    /// collection. The subjects are the apps; `hlb job` says what it printed.
    JobFailed,
    /// 🔴 A message has waited over an hour in Stalwart's queue: the sender believes it
    /// sent, and learns otherwise from a bounce days later. The subjects are the
    /// recipients' domains; `hlb mail queue` says what the last attempt was told.
    MailWaiting,

    // --- Data -----------------------------------------------------------------
    /// 🔴 Running, and nothing protects its data.
    NeverBackedUp,
    /// No destination is declared: nothing is backed up anywhere.
    NoBackupDestination,
    /// Every copy is too old.
    NoFreshCopy,
    /// One up-to-date copy left: it disappears with the machine carrying it.
    OneFreshCopy,
    /// A single destination is declared.
    SingleDestination,
    /// No restore was ever rehearsed.
    DrillNever,
    /// The last rehearsal is getting old.
    DrillStale,

    // --- Infrastructure ---------------------------------------------------------
    NodeUnreachable,
    NodeDiskFull,
    NodeDiskFilling,
    NodeSwapping,
    NodeLoad,
    /// Security fixes installed and waiting for a reboot.
    NodeRebootPending,
    /// What the topology says about surviving the loss of a failure domain.
    Topology {
        verdict: TopologyVerdict,
    },
    /// What runs differs from what was declared.
    Drift,
    /// No heartbeat: if everything stops, nothing will warn anyone.
    DeadmanAbsent,
    /// The heartbeat stopped.
    DeadmanSilent,

    // --- Security ---------------------------------------------------------------
    /// The ingress configuration was never applied: what is reachable is unknown.
    ExposureUnknown,
    /// 🔴 Published on the internet while its manifest does not want it.
    ExposedAgainstManifest,
    /// Should be published and is not.
    NotPublished,
    /// The ingress was not applied again since the install.
    RouteNotApplied,
    /// A route still answers for an application no longer installed.
    OrphanRoute,
    SecretNeverRotated,
    SecretRotationDue,
    /// 🔴 An mTLS certificate of the fleet ends within 30 days and was not renewed: the
    /// day it ends every agent refuses the controller, and every node reads
    /// unreachable. The subjects are the services; `hlb pki renew --apply` renews them.
    CertificateExpiring,
    /// Several `admin` tokens: each opens everything.
    AdminTokens,
    /// No `admin` token is recorded, which cannot be checked from here.
    AdminUnknown,
    /// 🔴 An audit entry was removed or modified.
    AuditBroken,
    /// The audit log could not be re-read.
    AuditUnreadable,
    /// 🔴 A running app says something its manifest promises it does not — a sign-up
    /// open, a variable gone. The subjects are the apps.
    AssertionBroken,
    /// An app's assertions could not be read, or not lately: a door nobody looked at.
    AssertionUnknown,
    /// 🔴 A DNS record the house's mail needs is not what the internet resolves — a
    /// DKIM key nobody published, no SPF, an MX elsewhere: mail is refused or filed as
    /// spam. The subjects are the records' names; `hlb mail dns` prints the lines.
    MailRecordWrong,
    /// The mail records could not be read from a public resolver, or not lately.
    MailRecordUnknown,
    /// The spam filter's blocklists refuse the resolver Stalwart asks through — a
    /// public one, or one asking them too often —, so they check nothing and every
    /// spammer's message passes them. The subjects are the refusing lists' tags;
    /// `hlb mail dns` says what to change.
    MailBlocklistsRefused,
    /// 🔴 The house's domain moved since the baseline `hlb domain accept` recorded —
    /// its name servers, DS, CAA, registrar or locks —, the way a registrar's support
    /// hands a domain to a thief. The subject is the zone; `hlb domain watch` says
    /// what moved.
    DomainMoved,
    /// 🔴 The CAA governing the house's names refuses one of its ACME accounts: its
    /// certificates stop renewing. The subjects are who holds the account (`Caddy`,
    /// `Stalwart`); `hlb domain watch` prints the line to add.
    CaaRefusesAccount,
    /// 🔴 A Certificate Transparency log holds a certificate for the house's names under
    /// a key neither Caddy nor Stalwart holds: someone else can answer for them. The
    /// subjects are its names; `hlb domain watch` says which authority, and when.
    CertificateForeign,
    /// The domain, or the certificates issued for it, have no baseline: nothing is
    /// compared, so no change can be told. The subject is the zone; `hlb domain accept
    /// --apply` sets one.
    DomainUnwatched,
    /// The domain was not read from the internet lately, or no resolver answered: a
    /// change made meanwhile is not known.
    DomainUnknown,

    // --- People -------------------------------------------------------------
    /// An identity and no mailbox: signs in everywhere, receives nothing.
    AccountWithoutMailbox,
    /// A mailbox and no identity: receives mail nobody can read.
    AccountWithoutIdentity,
    AccountEmpty,
    /// 🔴 An expired alias still receives: the purge has not run.
    AliasStillReceiving,
    /// Break-glass safeguards not attested, or to attest again. The subjects are their
    /// ids, the stored values `hlb_api::breakglass` names them by.
    Safeguard,

    // --- Activity ---------------------------------------------------------------
    /// An alert rule fires — or cannot be evaluated, which is not "fine".
    Alert {
        rule: String,
        evaluable: bool,
    },
}

/// One cause, and everything it covers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Issue {
    pub cause: Cause,
    /// The worst attention any of its subjects carries.
    pub attention: Attention,
    /// What the cause is about — applications, machines, accounts, routes — sorted.
    /// Empty when it is about the installation itself.
    pub subjects: Vec<String>,
    /// Set aside by the person reading, until then — seconds since the epoch. `null`
    /// for a line in view, and for one set aside that has got worse since.
    pub aside_until: Option<i64>,
}

/// The longest a line is set aside: a week, like a mute — one with no end is a
/// problem deleted, not deferred.
pub const ASIDE_MAX_S: i64 = 7 * 86_400;

/// A line a person set aside, as it was then.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Aside {
    pub cause: Cause,
    pub until: i64,
    /// Its attention and how many things it covered when it was set aside: worse than
    /// that, and it is back.
    pub attention: Attention,
    pub subjects: usize,
}

/// Marks the lines set aside that are still within their time — and NOT worse than
/// they were. 🔴 A line set aside at "one application" that now covers four, or that
/// went from notice to critical, is not the problem that was deferred: it comes back,
/// as Sentry's "archive until escalating" does.
pub fn apply_asides(issues: &mut [Issue], asides: &[Aside], now: i64) {
    for issue in issues {
        issue.aside_until = asides
            .iter()
            .find(|a| a.cause == issue.cause)
            .filter(|a| {
                a.until > now
                    && issue.attention <= a.attention
                    && issue.subjects.len() <= a.subjects
            })
            .map(|a| a.until);
    }
}

/// A request to set a line aside.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AsideRequest {
    pub cause: Cause,
    /// How long, in seconds: at most [`ASIDE_MAX_S`].
    pub for_s: i64,
}

/// A request to bring a line back.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BackRequest {
    pub cause: Cause,
}

/// What a source found: a cause, how much it matters, and what it is about.
pub type Finding = (Cause, Attention, Option<String>);

/// Groups findings by cause: one [`Issue`] each, at the worst attention, with every
/// subject once. Critical first; within an attention, the order of the causes above,
/// so the list does not reshuffle between two reads.
pub fn group(findings: impl IntoIterator<Item = Finding>) -> Vec<Issue> {
    let mut out: Vec<Issue> = Vec::new();
    for (cause, attention, subject) in findings {
        if attention == Attention::Ok {
            continue;
        }
        let at = match out.iter().position(|i| i.cause == cause) {
            Some(at) => at,
            None => {
                out.push(Issue {
                    cause,
                    attention,
                    subjects: Vec::new(),
                    aside_until: None,
                });
                out.len() - 1
            }
        };
        let issue = &mut out[at];
        issue.attention = issue.attention.max(attention);
        if let Some(s) = subject {
            if !issue.subjects.contains(&s) {
                issue.subjects.push(s);
            }
        }
    }
    for issue in &mut out {
        issue.subjects.sort();
    }
    // Stable: equal attentions keep the order the sources were read in.
    out.sort_by_key(|i| std::cmp::Reverse(i.attention));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_cause_is_one_line_naming_what_it_covers() {
        let issues = group([
            (
                Cause::NeverBackedUp,
                Attention::Critical,
                Some("seafile".into()),
            ),
            (
                Cause::AppPartial,
                Attention::Notice,
                Some("jellyfin".into()),
            ),
            (
                Cause::NeverBackedUp,
                Attention::Critical,
                Some("garage".into()),
            ),
            // The same subject twice — two sources noticing it — is named once.
            (
                Cause::NeverBackedUp,
                Attention::Critical,
                Some("garage".into()),
            ),
        ]);
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].cause, Cause::NeverBackedUp);
        assert_eq!(issues[0].subjects, vec!["garage", "seafile"]);
    }

    #[test]
    fn a_line_is_as_bad_as_its_worst_subject_and_the_worst_come_first() {
        let issues = group([
            (Cause::NodeDiskFilling, Attention::Notice, Some("a".into())),
            (Cause::Drift, Attention::Notice, Some("gitea".into())),
            (Cause::Drift, Attention::Critical, Some("n8n".into())),
        ]);
        assert_eq!(issues[0].cause, Cause::Drift);
        assert_eq!(issues[0].attention, Attention::Critical);
    }

    #[test]
    fn what_is_fine_is_not_a_line() {
        assert!(group([(Cause::DrillStale, Attention::Ok, None)]).is_empty());
    }

    #[test]
    fn an_alert_rule_is_its_own_cause() {
        let alert = |rule: &str| Cause::Alert {
            rule: rule.into(),
            evaluable: true,
        };
        let issues = group([
            (alert("disk-full"), Attention::Notice, None),
            (alert("backup-absent"), Attention::Critical, None),
        ]);
        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn a_line_set_aside_comes_back_when_it_gets_worse_or_its_time_is_up() {
        let mut issues = group([
            (
                Cause::NeverBackedUp,
                Attention::Critical,
                Some("garage".into()),
            ),
            (Cause::DrillStale, Attention::Notice, None),
        ]);
        let aside = |cause, attention, subjects| Aside {
            cause,
            until: 100,
            attention,
            subjects,
        };
        apply_asides(
            &mut issues,
            &[
                aside(Cause::NeverBackedUp, Attention::Critical, 1),
                aside(Cause::DrillStale, Attention::Notice, 0),
            ],
            50,
        );
        assert_eq!(issues[0].aside_until, Some(100));
        assert_eq!(issues[1].aside_until, Some(100));

        // A second application never backed up: not the problem that was deferred.
        let mut worse = group([
            (
                Cause::NeverBackedUp,
                Attention::Critical,
                Some("garage".into()),
            ),
            (
                Cause::NeverBackedUp,
                Attention::Critical,
                Some("seafile".into()),
            ),
        ]);
        apply_asides(
            &mut worse,
            &[aside(Cause::NeverBackedUp, Attention::Critical, 1)],
            50,
        );
        assert_eq!(worse[0].aside_until, None);

        // From notice to critical: back too.
        let mut sharper = group([(Cause::DrillStale, Attention::Critical, None)]);
        apply_asides(
            &mut sharper,
            &[aside(Cause::DrillStale, Attention::Notice, 0)],
            50,
        );
        assert_eq!(sharper[0].aside_until, None);

        // Its time up: back.
        apply_asides(
            &mut issues,
            &[aside(Cause::DrillStale, Attention::Notice, 0)],
            100,
        );
        assert_eq!(issues[1].aside_until, None);
    }
}
