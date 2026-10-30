//! What reaches Stalwart with its admin credentials on someone's behalf.

use hlb_api::intent::{Acted, CreateAlias, CreateMailbox, PurgeAlias, Refusal};
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

/// Creates an alias on the account's mailbox for the addy.io API: on Stalwart FIRST,
/// in the state afterwards, within the role's quota. Answers the address created.
pub(crate) async fn create_alias(p: &Privd, i: CreateAlias) -> Result<String, Refusal> {
    let CreateAlias {
        account: user,
        mailbox: targeted_mailbox,
        domain,
        description,
    } = i;
    let internal = |e: hlb_state::Error| Refusal::Internal(e.to_string());
    // The account's default mailbox receives the alias. It is the only choice that makes
    // sense here: the client does not know the mailboxes, and asking it to choose would
    // step outside the protocol Bitwarden knows how to speak.
    let mailboxes = p.state.mailboxes(&user).await.map_err(internal)?;
    // 🔴 The mailbox targeted by the TOKEN wins: it is the only way to choose, the
    // addy.io protocol having no field for it. Failing that, the default mailbox.
    let chosen = match &targeted_mailbox {
        Some(name) => mailboxes.iter().find(|(l, ..)| l == name).cloned(),
        None => mailboxes.iter().find(|(.., d)| *d).cloned(),
    };

    let Some((mailbox, mailbox_domain, _)) = chosen else {
        // ⚠️ A token targeting a deleted mailbox must FAIL, not silently fall back on
        // the default mailbox: the user would believe their aliases filed where they are
        // not, and the sorting rules would no longer apply.
        let detail = match &targeted_mailbox {
            Some(name) => format!(
                "the mailbox \"{name}\" targeted by this token no longer exists for {user}. \
                 Recreate it, or make a new token without --mailbox"
            ),
            None => {
                format!("{user} has no default mailbox: the alias would have nowhere to go")
            }
        };
        return Err(Refusal::Conflict(detail));
    };

    // ⚠️ The domain the client asks for is only honoured if it matches the mailbox's.
    // Accepting any domain would create an address on a domain we do not serve: it would
    // never receive anything, and the user would believe it active because the client
    // displayed it.
    let domain = match domain.as_deref() {
        Some(d) if d != mailbox_domain => {
            return Err(Refusal::Unprocessable(format!(
                "domain \"{d}\" not served for this account; expected \"{mailbox_domain}\""
            )));
        }
        _ => mailbox_domain,
    };

    let description = description.unwrap_or_default();
    let hint = hlb_users::forwarder::hint_from_description(&description);

    let mut entropy = [0u8; hlb_users::generation::SUFFIX_LEN];
    hlb_secrets::fill_random(&mut entropy);
    let generated = hlb_users::Generated::for_site(hint.as_deref().unwrap_or(""), &entropy);

    // 🔴 The quota applies HERE too. A comment already claimed it and it was FALSE:
    // `add_alias` was called directly, so that a `guest` profile limited to zero
    // permanent aliases created as many as it liked over HTTP. A limit an API bypasses
    // limits nothing, and makes the roles' limits decorative.
    let account = p.state.account(&user).await.map_err(internal)?;
    let role = p.state.role_of(&user).await.map_err(internal)?;
    let usage = account.usage(now());
    if let Err(refusal) = role.authorized(&usage, hlb_users::Request::AliasPermanent) {
        return Err(Refusal::TooMany(refusal.reason));
    }

    // 🔴 On Stalwart FIRST, in the state AFTERWARDS — as `hlb user alias add`. Recorded
    // alone, the alias was handed to a merchant and every mail to it bounced, back to
    // the sender: nobody on this side would know the address does not work.
    let Some(mail) = &p.mail else {
        return Err(Refusal::Conflict(
            "mail is not configured on this controller — refusing rather than handing \
             out an address that would receive nothing"
                .into(),
        ));
    };
    mail.add_alias(&format!("{mailbox}@{domain}"), &generated.local)
        .await
        .map_err(|e| Refusal::Internal(format!("the mail server refused the alias: {e}")))?;

    // ⚠️ Permanent by default — Bitwarden has no notion of duration, and fabricating an
    // expiry the user did not ask for would kill their addresses without warning.
    p.state
        .add_alias(
            &user,
            &mailbox,
            &generated.local,
            None,
            hint.as_deref(),
            Some(&description),
        )
        .await
        .map_err(internal)?;

    // The proposed sorting folder, which the user will be able to change.
    if let Some(d) = hlb_users::sieve::Rule::default_folder(hint.as_deref()) {
        let _ = p
            .state
            .set_alias_folder(&user, &generated.local, Some(&d))
            .await;
    }

    tracing::info!(user, alias = %generated.local, "alias created by the addy.io API");
    Ok(generated.address(&domain))
}

/// Creates the account's own mailbox: quota, then Stalwart, then the state — never
/// reversed, or a half-created account looks functional until the first lost email.
pub(crate) async fn create_mailbox(p: &Privd, i: CreateMailbox) -> Acted {
    let CreateMailbox { account, local } = i;
    let local = local.trim().to_string();
    let mut blockers = Vec::new();

    match &account {
        None => blockers.push("this request acts on nobody's behalf — sign in first".into()),
        Some(user) => match p.state.account(user).await {
            Ok(a) => {
                let role = p
                    .state
                    .role_of(user)
                    .await
                    .unwrap_or_else(|_| hlb_users::RoleDef::nothing());
                let usage = a.usage(now());
                if let Err(refusal) = role.authorized(&usage, hlb_users::Request::Mailbox) {
                    // Same shape as `create_alias`'s own quota check: a quantity
                    // refusal, not a rights problem.
                    blockers.push(refusal.reason);
                }
            }
            Err(e) => return Acted::Unplannable(e.to_string()),
        },
    }

    if p.mail.is_none() {
        // 🔴 Refuse rather than record a mailbox that does not exist on the server: a
        // half-created account looks functional and only shows on the first lost
        // email.
        blockers.push(
            "mail is not configured on this controller — refusing rather than \
             recording a mailbox that would receive nothing"
                .into(),
        );
    }

    // A reserved name, an app's own account, another person's mailbox: refused before
    // anything is asked of Stalwart.
    if let Some(user) = &account {
        match hlb_engine::mailbox::refusal(&p.state, user, &local, &p.mail_domain).await {
            Ok(Some(refusal)) => blockers.push(refusal),
            Ok(None) => {}
            Err(e) => return Acted::Unplannable(e.to_string()),
        }
    }

    let mut applied = blockers.is_empty();
    let address = format!("{local}@{}", p.mail_domain);
    let mut steps = vec![ActionStep {
        description: format!("create {address} in Stalwart"),
        state: StepState::Planned,
        error: None,
    }];

    if applied {
        // Both present whenever `blockers` is empty.
        if let (Some(user), Some(mail)) = (&account, &p.mail) {
            // 🔴 An account Stalwart holds already is REFUSED, never adopted: it is an
            // app's or one made by hand, and its mail would become this person's.
            match hlb_engine::mailbox::create(
                &p.state,
                mail,
                user,
                &local,
                &p.mail_domain,
                false,
                hlb_engine::mailbox::Existing::Refuse,
            )
            .await
            {
                Ok(Ok(_)) => {
                    steps[0].state = StepState::Done;
                    tracing::info!(user, mailbox = %address, "mailbox created via self-service");
                }
                Ok(Err(refusal)) => {
                    applied = false;
                    blockers.push(refusal);
                }
                Err(e) => {
                    steps[0].state = StepState::Failed;
                    steps[0].error = Some(e.to_string());
                }
            }
        }
    }

    Acted::Planned(ActionResult {
        applied,
        summary: format!("create {address}"),
        steps,
        cli_command: format!(
            "hlb user mailbox add {} {local} --apply",
            account.as_deref().unwrap_or("<account>")
        ),
        blockers,
        warnings: Vec::new(),
        confirmation_required: None,
    })
}
