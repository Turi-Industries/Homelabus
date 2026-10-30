//! An account made from an invitation: the one privileged act nobody signed in asks for.
//!
//! The order of its steps, and why, is `/api/signup`'s documentation: the
//! invitation, the account in the state, then the identity before the mailbox.

use hlb_api::intent::{SignUp, SignedUp};
use hlb_api::{ActionResult, ActionStep, StepState};

use crate::Privd;

fn step(what: &str) -> ActionStep {
    ActionStep {
        description: what.to_string(),
        state: StepState::Planned,
        error: None,
    }
}

fn result(name: &str, applied: bool, steps: Vec<ActionStep>, blockers: Vec<String>) -> SignedUp {
    SignedUp {
        result: ActionResult {
            applied,
            summary: if applied {
                format!("account \"{name}\" created")
            } else {
                format!("create the account \"{name}\"")
            },
            steps,
            cli_command: format!("hlb user add {name} --apply"),
            blockers,
            warnings: Vec::new(),
            confirmation_required: None,
        },
        enrolment_link: None,
    }
}

pub(crate) async fn sign_up(p: &Privd, i: SignUp) -> SignedUp {
    let SignUp {
        invitation,
        name,
        display_name,
        apply,
    } = i;
    let now = crate::now();
    let mut blockers = Vec::new();

    // The name becomes both the address's local part AND the PocketID identifier.
    if let Err(e) = hlb_users::validate_name(&name) {
        blockers.push(e.to_string());
    }

    // What is taken is said only to whoever holds a link that opens: to anyone else
    // the preview was a directory of the household's names. An unreadable state reads
    // as no link — it opens nothing either.
    let invited = p
        .state
        .invitation_open(&invitation, now)
        .await
        .unwrap_or(false);
    if invited && blockers.is_empty() {
        blockers.extend(name_taken(p, &name).await);
    }

    // ⚠️ The invitation is not CONSUMED in preview: you must be able to check your
    // name without burning the link.
    if !apply {
        let steps = vec![
            step("create the PocketID identity"),
            step("open the mailbox"),
            step("record the account"),
        ];
        return result(&name, false, steps, blockers);
    }
    if !blockers.is_empty() {
        return result(&name, false, Vec::new(), blockers);
    }

    // 1. The invitation, consumed BEFORE anything: single use guaranteed by the transaction.
    let Ok(Some(role)) = p.state.consume_invitation(&invitation, &name, now).await else {
        // Unknown, expired or already used: indistinguishable on purpose.
        let refused = "invalid, expired or already used invitation — ask for a new link";
        return result(&name, false, Vec::new(), vec![refused.to_string()]);
    };

    let mut steps = Vec::new();

    // 2. The account in the database, straight away.
    // Created, never upserted: a sign-up racing another for the same name since the
    // check above stops here, rather than rewriting the role of the account it lost to.
    let mut e = step("record the account");
    match p.state.create_user(&name, &role).await {
        Ok(true) => e.state = StepState::Done,
        Ok(false) => {
            e.state = StepState::Failed;
            e.error = Some(format!("the name \"{name}\" is already taken"));
            steps.push(e);
            return result(&name, true, steps, Vec::new());
        }
        Err(err) => {
            e.state = StepState::Failed;
            e.error = Some(err.to_string());
            steps.push(e);
            return result(&name, true, steps, Vec::new());
        }
    }
    steps.push(e);
    // Who granted it: the invitation, whose creator the audit log names.
    let _ = p
        .state
        .set_user_role(&name, &role, Some("invitation"))
        .await;

    // 3. The PocketID identity.
    //
    // ⚠️ It comes BEFORE the mailbox: an identity with no mailbox lets the person sign
    // in and receive nothing; a mailbox with no identity leaves mail nobody can read.
    // The first state is the less bad of the two — you can at least reach the person
    // some other way.
    let mut e = step("create the PocketID identity");
    let mut enrolment_link = None;

    match &p.identity {
        Some(pid) => {
            let display_name = display_name.unwrap_or_else(|| name.clone());
            let address = format!("{name}@{}", p.mail_domain);
            match pid
                .create_user(&name, Some(&address), &display_name, &[])
                .await
            {
                Ok(u) => {
                    e.state = StepState::Done;
                    let _ = p.state.upsert_user_pocket_id(&name, &u.id).await;

                    // 🔴 PocketID has NO password: passkey authentication. So we do not
                    // hand over an initial secret but a single-use token, shown once
                    // and never recorded.
                    match pid.one_time_token(&u.id, "12h").await {
                        Ok(token) => {
                            let public = hlb_engine::access::pocketid_public(&p.state)
                                .await
                                .unwrap_or_else(|| pid.issuer().to_string());
                            enrolment_link =
                                Some(hlb_engine::access::enrolment_link(&public, &token));
                        }
                        Err(err) => {
                            // The account exists but nobody can sign in to it: that is
                            // not a creation failure, it is a link to redo. We say so
                            // without marking the step as failed.
                            e.error = Some(format!(
                                "identity created, but the enrolment link failed \
                                 ({err}) — make another with \"hlb user link {name}\""
                            ));
                        }
                    }
                }
                Err(err) => {
                    e.state = StepState::Failed;
                    e.error = Some(err.to_string());
                }
            }
        }
        None => {
            e.state = StepState::Unimplemented;
            e.error = Some(
                "PocketID not configured on this controller — finish with \"hlb user add \
                 <name> --apply\", which picks up where this stopped"
                    .into(),
            );
        }
    }
    steps.push(e);

    // 4. The mailbox.
    let mut e = step("open the mailbox");
    match &p.mail {
        // 🔴 An account Stalwart holds already is refused, never adopted: an app's own
        // (`vikunja@`) would have become this person's, its mail with it.
        Some(mail) => match hlb_engine::mailbox::create(
            &p.state,
            mail,
            &name,
            &name,
            &p.mail_domain,
            true,
            hlb_engine::mailbox::Existing::Refuse,
        )
        .await
        {
            Ok(Ok(_)) => e.state = StepState::Done,
            Ok(Err(refusal)) => {
                e.state = StepState::Failed;
                e.error = Some(refusal);
            }
            Err(err) => {
                e.state = StepState::Failed;
                e.error = Some(err.to_string());
            }
        },
        None => {
            e.state = StepState::Unimplemented;
            e.error = Some(
                "Stalwart not configured on this controller — the mailbox does not \
                 exist, and the address will receive nothing"
                    .into(),
            );
        }
    }
    steps.push(e);

    let mut done = result(&name, true, steps, Vec::new());
    done.enrolment_link = enrolment_link;
    done
}

/// Why `name` cannot be signed up: an account has it, or the address it would take is
/// reserved, an app's or another person's. 🔴 A state that cannot be read is a refusal,
/// never a free name.
async fn name_taken(p: &Privd, name: &str) -> Vec<String> {
    let mut blockers = Vec::new();
    match p.state.users().await {
        Ok(u) if u.iter().any(|(n, _, _)| n == name) => {
            blockers.push(format!("the name \"{name}\" is already taken"));
        }
        Ok(_) => {}
        Err(e) => blockers.push(format!("the accounts cannot be read: {e}")),
    }
    match hlb_engine::mailbox::refusal(&p.state, name, name, &p.mail_domain).await {
        Ok(Some(r)) => blockers.push(r),
        Ok(None) => {}
        Err(e) => blockers.push(format!("the mailboxes cannot be read: {e}")),
    }
    // Asked before the invitation is used: found only at the mailbox step, the person
    // would be left with an account and no address.
    if let Some(mail) = &p.mail {
        let found = match mail.domain_id(&p.mail_domain).await {
            Ok(id) => mail.find_account(name, &id).await.map(|a| a.is_some()),
            Err(hlb_mail::Error::UnknownDomain(_)) => Ok(false),
            Err(e) => Err(e),
        };
        match found {
            Ok(false) => {}
            Ok(true) => blockers.push(format!(
                "{name}@{} exists already in the mail server — choose another name",
                p.mail_domain
            )),
            Err(e) => blockers.push(format!("the mail server cannot be read: {e}")),
        }
    }
    blockers
}
