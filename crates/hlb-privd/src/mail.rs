//! What reaches Stalwart with its admin credentials on someone's behalf.

use hlb_api::intent::PurgeAlias;
use hlb_api::{ActionResult, ActionStep, StepState};

use crate::Privd;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Purges one of the account's own expired-but-still-active aliases.
///
/// 🔴 The state is marked ONLY AFTER the removal succeeds on Stalwart — the reverse
/// would claim the address closed while it still receives.
pub(crate) async fn purge_alias(p: &Privd, i: PurgeAlias) -> ActionResult {
    let PurgeAlias {
        account,
        local,
        apply,
    } = i;
    let mut blockers = Vec::new();
    // (mailbox local part, its domain), once we know the alias is eligible.
    let mut target: Option<(String, String)> = None;

    match &account {
        None => blockers.push("this request acts on nobody's behalf — sign in first".into()),
        Some(acct) => {
            let rows = p.state.aliases(acct).await.unwrap_or_default();
            match rows.into_iter().find(|(_, l, ..)| l == &local) {
                None => blockers.push(format!("no such alias: {local}")),
                // 🔴 Purge is for the expired-but-still-active bug case, not a general
                // "delete this alias" button: a permanent or still-valid alias is not
                // what it exists to fix, and the button must not become a second,
                // unlabelled way to delete one.
                Some((mailbox, _, expires_at, active, ..)) => {
                    let eligible = active && matches!(expires_at, Some(e) if now() >= e);
                    // The alias lives at its MAILBOX's domain, which is not always the
                    // installation's: removed at the other one, nothing was removed.
                    let domain = p
                        .state
                        .mailboxes(acct)
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .find(|(l, ..)| l == &mailbox)
                        .map(|(_, d, _)| d);
                    if !eligible {
                        blockers.push("not expired-and-still-active: nothing to purge".into());
                    } else if let Some(domain) = domain {
                        target = Some((mailbox, domain));
                    } else {
                        blockers.push(format!(
                            "its mailbox \"{mailbox}\" is no longer yours — the alias \
                             cannot be found on the mail server from here"
                        ));
                    }
                }
            }
        }
    }

    if p.mail.is_none() {
        // 🔴 Refuse rather than record a purge that removed nothing: it would claim
        // the address is closed while it still receives, and nothing would say so.
        blockers.push(
            "Stalwart is not configured on this controller — refusing rather than \
             recording a removal that never happened"
                .into(),
        );
    }

    let applied = apply && blockers.is_empty();
    let domain = target
        .as_ref()
        .map_or(p.mail_domain.as_str(), |(_, d)| d.as_str());
    let address = format!("{local}@{domain}");
    let mut steps = vec![ActionStep {
        description: format!("remove {address} from Stalwart"),
        state: StepState::Planned,
        error: None,
    }];

    if applied {
        // Both present whenever `blockers` is empty: `target` only stays `None` when a
        // blocker was pushed alongside it.
        if let (Some(account), Some((mailbox, domain)), Some(mail)) = (&account, &target, &p.mail) {
            let mailbox_address = format!("{mailbox}@{domain}");
            match mail.remove_alias(&mailbox_address, &local).await {
                // Removed but not recorded is said: the screen would go on showing an
                // open door that is closed, and the next purge would try it again.
                Ok(_) => match p.state.deactivate_alias(account, &local).await {
                    Ok(_) => steps[0].state = StepState::Done,
                    Err(e) => {
                        steps[0].state = StepState::Failed;
                        steps[0].error = Some(format!(
                            "removed from Stalwart, but not recorded as removed: {e}"
                        ));
                    }
                },
                Err(e) => {
                    steps[0].state = StepState::Failed;
                    steps[0].error = Some(e.to_string());
                }
            }
        }
    }

    ActionResult {
        applied,
        summary: format!("purge {address}: remove it from Stalwart for good, it stops receiving"),
        steps,
        cli_command: format!("hlb user alias purged --alias {local} --apply"),
        blockers,
        warnings: Vec::new(),
        confirmation_required: None,
    }
}
