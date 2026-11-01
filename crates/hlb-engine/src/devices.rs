//! A person's devices: one password each for their mailbox — mail, calendars and
//! contacts on a phone, which cannot sign in through PocketID.
//!
//! Stalwart holds them and is the only list: a device revoked in its own screens is
//! gone here too. The privileged daemon and the CLI both answer through these.

use hlb_api::intent::{Acted, AddDevice, DeviceAdded, Devices, RevokeDevice};
use hlb_api::DEVICE_NAME_MAX as NAME_MAX;
use hlb_api::{ActionResult, ActionStep, Device, DeviceSetup, StepState};
use hlb_mail::Stalwart;
use hlb_state::State;

const NOBODY: &str = "this request acts on nobody's behalf — sign in first";
const NO_MAIL: &str = "mail is not configured on this controller";

/// Every device of every mailbox of `account`, oldest first within each.
pub async fn devices(
    state: &State,
    mail: Option<&Stalwart>,
    i: Devices,
) -> Result<Vec<Device>, String> {
    let Some(mail) = mail else {
        return Err(NO_MAIL.into());
    };
    let mut out = Vec::new();
    for (local, domain, _) in state
        .mailboxes(&i.account)
        .await
        .map_err(|e| e.to_string())?
    {
        let address = format!("{local}@{domain}");
        // A mailbox Stalwart lost has no device to list; the mailbox screen says the rest.
        let Some(id) = mail.account_of(&address).await.map_err(|e| e.to_string())? else {
            continue;
        };
        for a in mail.app_passwords(&id).await.map_err(|e| e.to_string())? {
            out.push(Device {
                id: a.id,
                name: a.description,
                mailbox: address.clone(),
                created_at: a.created_at,
            });
        }
    }
    Ok(out)
}

/// Why `name` cannot name a device, if it cannot.
fn name_refusal(name: &str) -> Option<String> {
    if name.is_empty() {
        return Some("name the device — it is how you will tell it from the others".into());
    }
    if name.chars().count() > NAME_MAX {
        return Some(format!("a device's name is {NAME_MAX} characters at most"));
    }
    if name.chars().any(char::is_control) {
        return Some("a device's name is one line of text".into());
    }
    None
}

/// The mailbox `wanted` names among `account`'s — their default one when `None` — as
/// `(local, address)`. Named by its local part or its whole address: the device list
/// shows the address, and a revocation refusing what the list shows was met on the lab.
async fn mailbox_of(
    state: &State,
    account: &str,
    wanted: Option<&str>,
) -> Result<Result<(String, String), String>, String> {
    let boxes = state.mailboxes(account).await.map_err(|e| e.to_string())?;
    let found = match wanted {
        Some(w) => boxes
            .iter()
            .find(|(l, d, _)| l == w || w.split_once('@') == Some((l.as_str(), d.as_str()))),
        None => boxes.iter().find(|(.., d)| *d),
    };
    Ok(match (found, wanted) {
        (Some((l, d, _)), _) => Ok((l.clone(), format!("{l}@{d}"))),
        (None, Some(w)) => Err(format!("\"{w}\" is not one of {account}'s mailboxes")),
        (None, None) => Err("you have no default mailbox for the device to sign in to".into()),
    })
}

/// Single quotes around `s` for a shell, its own quotes kept.
fn quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

pub async fn add_device(state: &State, mail: Option<&Stalwart>, i: AddDevice) -> DeviceAdded {
    let AddDevice {
        account,
        name,
        mailbox,
        apply,
    } = i;
    let name = name.trim().to_string();
    let mut blockers = Vec::new();
    blockers.extend(name_refusal(&name));
    let mut target = None;
    match &account {
        None => blockers.push(NOBODY.into()),
        Some(a) => match mailbox_of(state, a, mailbox.as_deref()).await {
            Ok(Ok(t)) => target = Some(t),
            Ok(Err(why)) => blockers.push(why),
            Err(e) => blockers.push(e),
        },
    }
    // Where the phone finds CalDAV, CardDAV and IMAP: without a public name, a
    // password made now opens nothing a phone can reach.
    let server = match state.app_domain("stalwart").await {
        Ok(Some(d)) => Some(d),
        Ok(None) => {
            blockers.push(
                "Stalwart has no public name: a phone could not reach it — expose it first".into(),
            );
            None
        }
        Err(e) => {
            blockers.push(e.to_string());
            None
        }
    };
    let mut stalwart_id = None;
    match (mail, &target) {
        (None, _) => blockers.push(NO_MAIL.into()),
        (Some(mail), Some((_, address))) => match mail.account_of(address).await {
            Ok(Some(id)) => {
                // Two devices of one name could not be told apart when revoking one.
                match mail.app_passwords(&id).await {
                    Ok(list) if list.iter().any(|d| d.description == name) => blockers.push(
                        format!("a device of {address} is called \"{name}\" already"),
                    ),
                    Ok(_) => {}
                    Err(e) => blockers.push(e.to_string()),
                }
                stalwart_id = Some(id);
            }
            Ok(None) => blockers.push(format!("Stalwart has no account {address}")),
            Err(e) => blockers.push(e.to_string()),
        },
        (Some(_), None) => {}
    }

    let address = target.as_ref().map(|(_, a)| a.clone()).unwrap_or_default();
    let mut step = ActionStep {
        description: format!(
            "make a password for \"{name}\" to sign in to {address}: mail, calendars, contacts"
        ),
        state: StepState::Planned,
        error: None,
    };
    let applied = apply && blockers.is_empty();
    let mut setup = None;
    if applied {
        if let (Some(mail), Some(id), Some(server)) = (mail, &stalwart_id, &server) {
            match mail.create_app_password(id, &name).await {
                Ok(made) => {
                    step.state = StepState::Done;
                    tracing::info!(device = %name, mailbox = %address, "device password made");
                    setup = Some(DeviceSetup {
                        device: name.clone(),
                        user: address.clone(),
                        password: made.secret,
                        server: server.clone(),
                    });
                }
                Err(e) => {
                    step.state = StepState::Failed;
                    step.error = Some(e.to_string());
                }
            }
        }
    }
    DeviceAdded {
        result: ActionResult {
            applied,
            summary: format!("give \"{name}\" a password for {address}"),
            steps: vec![step],
            cli_command: format!(
                "hlb user device add {} {}{} --apply",
                account.as_deref().unwrap_or("<account>"),
                quoted(&name),
                mailbox
                    .as_deref()
                    .map(|m| format!(" --mailbox {m}"))
                    .unwrap_or_default()
            ),
            blockers,
            warnings: vec![
                "the password is shown once, and opens your mail as well as your calendars \
                 and contacts: put it in the device, nowhere else"
                    .into(),
            ],
            confirmation_required: None,
        },
        setup,
    }
}

pub async fn revoke_device(state: &State, mail: Option<&Stalwart>, i: RevokeDevice) -> Acted {
    let RevokeDevice {
        account,
        mailbox,
        id,
        apply,
    } = i;
    let mut blockers = Vec::new();
    let mut target = None;
    match &account {
        None => blockers.push(NOBODY.into()),
        Some(a) => match mailbox_of(state, a, Some(&mailbox)).await {
            Ok(Ok(t)) => target = Some(t),
            Ok(Err(why)) => blockers.push(why),
            Err(e) => return Acted::Unplannable(e),
        },
    }
    let mut found = None;
    match (mail, &target) {
        (None, _) => blockers.push(NO_MAIL.into()),
        (Some(mail), Some((_, address))) => match mail.account_of(address).await {
            Ok(Some(sid)) => match mail.app_passwords(&sid).await {
                Ok(list) => match list.into_iter().find(|d| d.id == id) {
                    Some(d) => found = Some((sid, d.description)),
                    None => blockers.push(format!("{address} has no device \"{id}\"")),
                },
                Err(e) => return Acted::Unplannable(e.to_string()),
            },
            Ok(None) => blockers.push(format!("Stalwart has no account {address}")),
            Err(e) => return Acted::Unplannable(e.to_string()),
        },
        (Some(_), None) => {}
    }
    let address = target.map_or_else(|| mailbox.clone(), |(_, a)| a);
    let name = found.as_ref().map(|(_, n)| n.clone()).unwrap_or(id.clone());
    let mut step = ActionStep {
        description: format!("revoke \"{name}\"'s password for {address}"),
        state: StepState::Planned,
        error: None,
    };
    let applied = apply && blockers.is_empty();
    if applied {
        if let (Some(mail), Some((sid, _))) = (mail, &found) {
            match mail.revoke_app_password(sid, &id).await {
                Ok(_) => step.state = StepState::Done,
                Err(e) => {
                    step.state = StepState::Failed;
                    step.error = Some(e.to_string());
                }
            }
        }
    }
    Acted::Planned(ActionResult {
        applied,
        summary: format!("revoke \"{name}\""),
        steps: vec![step],
        cli_command: format!(
            "hlb user device revoke {} {mailbox} {id} --apply",
            account.as_deref().unwrap_or("<account>")
        ),
        blockers,
        warnings: Vec::new(),
        confirmation_required: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_is_named_on_one_short_line() {
        assert!(name_refusal("").is_some());
        assert!(name_refusal(&"x".repeat(NAME_MAX + 1)).is_some());
        assert!(name_refusal("phone\nrm -rf").is_some());
        assert_eq!(name_refusal("Camille's phone"), None);
    }

    #[test]
    fn a_name_reaches_the_command_as_one_word() {
        assert_eq!(quoted("Camille's phone"), r"'Camille'\''s phone'");
    }

    #[tokio::test]
    async fn a_mailbox_is_named_by_its_address_as_the_list_shows_it() {
        let state = State::in_memory().await.expect("state");
        state
            .upsert_user("lena", "standard", None)
            .await
            .expect("account");
        state
            .add_mailbox("lena", "lena", "home.example", true)
            .await
            .expect("mailbox");
        let wanted = "lena".to_string();
        for asked in ["lena", "lena@home.example"] {
            let found = mailbox_of(&state, &wanted, Some(asked))
                .await
                .expect("read");
            assert_eq!(
                found,
                Ok(("lena".into(), "lena@home.example".into())),
                "{asked}"
            );
        }
        let elsewhere = mailbox_of(&state, &wanted, Some("lena@other.example"))
            .await
            .expect("read");
        assert!(elsewhere.is_err(), "{elsewhere:?}");
    }

    #[tokio::test]
    async fn nobody_and_a_house_without_mail_get_no_password() {
        let state = State::in_memory().await.expect("state");
        let asked = |account: Option<&str>| AddDevice {
            account: account.map(str::to_string),
            name: "phone".into(),
            mailbox: None,
            apply: true,
        };
        let nobody = add_device(&state, None, asked(None)).await;
        assert!(!nobody.result.applied);
        assert!(nobody.setup.is_none());
        assert!(
            nobody.result.blockers.iter().any(|b| b == NOBODY),
            "{:?}",
            nobody.result.blockers
        );
        let unmailed = add_device(&state, None, asked(Some("lena"))).await;
        assert!(!unmailed.result.applied);
        assert!(unmailed.setup.is_none());
        assert!(
            unmailed.result.blockers.iter().any(|b| b == NO_MAIL),
            "{:?}",
            unmailed.result.blockers
        );
    }
}
