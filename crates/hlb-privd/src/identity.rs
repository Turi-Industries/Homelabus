//! What reaches PocketID with its admin key on a person's own behalf.
//!
//! 🔴 The account is the one the web side vouches is signed in — never one named in
//! a URL or a body, or one person could rename another.

use std::sync::Arc;

use hlb_api::intent::{Acted, DefaultMailbox, MyIdentity, Rename};
use hlb_api::{ActionResult, ActionStep, IdentityLink, StepState};

use crate::Privd;

const NOBODY: &str = "this request acts on nobody's behalf — sign in first";

fn planned(description: String) -> ActionStep {
    ActionStep {
        description,
        state: StepState::Planned,
        error: None,
    }
}

/// An argument as a shell reads it: a name with a space or a quote in it is a person's
/// name, and a command line you copy must not split it.
fn quoted(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// The PocketID client and the account's id there, or why there are none.
async fn linked(
    p: &Privd,
    account: &str,
) -> Result<(Arc<hlb_identity::PocketId>, String), IdentityLink> {
    let Some(pid) = &p.identity else {
        return Err(IdentityLink::NotConfigured);
    };
    match p.state.account(account).await {
        Ok(a) => match a.pocket_id {
            Some(id) => Ok((pid.clone(), id)),
            None => Err(IdentityLink::NotLinked),
        },
        Err(_) => Err(IdentityLink::NotLinked),
    }
}

fn unlinked(link: IdentityLink, account: &str) -> String {
    match link {
        IdentityLink::NotConfigured => {
            "PocketID is not configured on this controller (--pocketid-url, --pocketid-key)".into()
        }
        IdentityLink::NotLinked => format!(
            "this account has no PocketID identity yet — an administrator finishes it \
             with \"hlb user add {account} --apply\""
        ),
        IdentityLink::Linked | IdentityLink::Unreachable => "PocketID did not answer".into(),
    }
}

/// The person's names and address, as PocketID holds them; `passkeys_url` is the web
/// side's to fill.
pub(crate) async fn my_identity(p: &Privd, i: MyIdentity) -> hlb_api::MyIdentity {
    let account = i.account.as_str();
    let mut out = hlb_api::MyIdentity {
        link: IdentityLink::NotLinked,
        first_name: None,
        last_name: None,
        display_name: None,
        email: None,
        passkeys_url: None,
    };
    match linked(p, account).await {
        Err(link) => out.link = link,
        Ok((pid, id)) => match pid.user(&id).await {
            Ok(u) => {
                out.link = IdentityLink::Linked;
                out.first_name = Some(u.first_name);
                out.last_name = Some(u.last_name.unwrap_or_default());
                out.display_name = Some(u.display_name);
                out.email = u.email;
            }
            Err(e) => {
                tracing::warn!(account, error = %e, "PocketID identity unreadable");
                out.link = IdentityLink::Unreachable;
            }
        },
    }
    out
}

/// Writes the person's names to PocketID — what every application shows.
pub(crate) async fn rename(p: &Privd, i: Rename) -> ActionResult {
    let Rename {
        account,
        first_name,
        last_name,
        display_name,
        apply,
    } = i;
    let (first, last, display) = (
        first_name.trim().to_string(),
        last_name.trim().to_string(),
        display_name.trim().to_string(),
    );
    let mut blockers = Vec::new();
    let mut target = None;

    match &account {
        None => blockers.push(NOBODY.into()),
        Some(a) => match linked(p, a).await {
            Ok(t) => target = Some(t),
            Err(link) => blockers.push(unlinked(link, a)),
        },
    }
    // The name everything shows: PocketID would store an empty one, and every
    // application would greet the person with nothing.
    if display.is_empty() {
        blockers.push("the display name cannot be empty".into());
    }

    let applied = apply && blockers.is_empty();
    let mut steps = vec![planned(format!(
        "write to PocketID: first name \"{first}\", last name \"{last}\", shown as \"{display}\""
    ))];

    if applied {
        if let Some((pid, id)) = &target {
            let change = hlb_identity::UserChange::Names {
                first: first.clone(),
                last: last.clone(),
                display: display.clone(),
            };
            match pid.update_user(id, &change).await {
                Ok(_) => steps[0].state = StepState::Done,
                Err(e) => {
                    steps[0].state = StepState::Failed;
                    steps[0].error = Some(e.to_string());
                }
            }
        }
    }

    let who = account.as_deref().unwrap_or("<account>");
    ActionResult {
        applied,
        summary: format!("call {who} \"{display}\""),
        steps,
        cli_command: format!(
            "hlb user names {who} --first {} --last {} --display {} --apply",
            quoted(&first),
            quoted(&last),
            quoted(&display)
        ),
        blockers,
        // Read at sign-in, by PocketID's own clients as by this one.
        warnings: vec![
            "applications already signed in keep the old name until their next sign-in".into(),
        ],
        confirmation_required: None,
    }
}

/// Makes one of the person's mailboxes their default, then the address PocketID hands
/// applications. Resumable: choosing the default again writes PocketID again.
pub(crate) async fn default_mailbox(p: &Privd, i: DefaultMailbox) -> Acted {
    let DefaultMailbox {
        account,
        local,
        apply,
    } = i;
    let local = local.trim().to_string();
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let mut address = format!("{local}@{}", p.mail_domain);
    let mut identity = None;

    match &account {
        None => blockers.push(NOBODY.into()),
        Some(a) => {
            let boxes = match p.state.mailboxes(a).await {
                Ok(b) => b,
                Err(e) => return Acted::Unplannable(e.to_string()),
            };
            match boxes.iter().find(|(l, ..)| l == &local) {
                Some((l, domain, _)) => address = format!("{l}@{domain}"),
                None => blockers.push(format!("this account has no mailbox \"{local}\"")),
            }
            match linked(p, a).await {
                Ok(t) => identity = Some(t),
                // Not a blocker: the default is Homelabus's own, and still worth
                // changing. But PocketID keeps handing out the old address, and that
                // must be read before applying, not discovered in an application.
                Err(link) => warnings.push(format!(
                    "{} — applications keep receiving the old address",
                    unlinked(link, a)
                )),
            }
        }
    }

    let applied = apply && blockers.is_empty();
    let mut steps = vec![planned(format!("make {address} the default mailbox"))];
    if identity.is_some() {
        steps.push(planned(format!(
            "give applications {address} as the address, in PocketID"
        )));
    }

    if applied {
        if let Some(a) = &account {
            match p.state.set_default_mailbox(a, &local).await {
                Ok(true) => steps[0].state = StepState::Done,
                Ok(false) => {
                    steps[0].state = StepState::Failed;
                    steps[0].error = Some(format!("no mailbox \"{local}\" any more"));
                }
                Err(e) => {
                    steps[0].state = StepState::Failed;
                    steps[0].error = Some(e.to_string());
                }
            }
        }
        // Only once the first step holds: PocketID announcing an address Homelabus
        // does not consider the default would be the two systems disagreeing.
        if let (Some((pid, id)), StepState::Done) = (&identity, steps[0].state) {
            let change = hlb_identity::UserChange::Email(address.clone());
            match pid.update_user(id, &change).await {
                Ok(_) => steps[1].state = StepState::Done,
                Err(e) => {
                    steps[1].state = StepState::Failed;
                    steps[1].error = Some(format!("{e} — choose the same mailbox again to finish"));
                }
            }
        }
    }

    let who = account.as_deref().unwrap_or("<account>");
    Acted::Planned(ActionResult {
        applied,
        summary: format!("make {address} the default mailbox of {who}"),
        steps,
        cli_command: format!("hlb user mailbox default {who} {local} --apply"),
        blockers,
        warnings,
        confirmation_required: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_with_a_space_or_a_quote_survives_the_copied_command() {
        assert_eq!(quoted("Léna"), "'Léna'");
        assert_eq!(quoted("Le Gall"), "'Le Gall'");
        assert_eq!(quoted("O'Neill"), r"'O'\''Neill'");
        // An empty last name is still an argument, or `--last --display x` shifts.
        assert_eq!(quoted(""), "''");
        assert_eq!(quoted("lena"), "lena");
    }
}
