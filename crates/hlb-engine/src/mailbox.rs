//! Giving a person a mailbox: in Stalwart first, then in the state.
//!
//! One path for the self-service route, sign-up, `hlb user add` and `hlb user mailbox
//! add`, so none of them is the one that hands out an address it should not.

use hlb_mail::Stalwart;
use hlb_state::State;

/// What to do with an account Stalwart has already and the state gives nobody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    /// Refused. A person asking for an address for themselves never gets one that
    /// exists already: it is an app's, or one made by hand, and its mail is not theirs.
    Refuse,
    /// Taken as the person's, its password unchanged — an administrator naming an
    /// account they made by hand.
    Adopt,
}

/// What [`create`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Created {
    pub address: String,
    /// The account existed in Stalwart already and was adopted.
    pub adopted: bool,
}

/// Gives `user` the mailbox `local@domain`: created in Stalwart, then recorded.
///
/// `Ok(Err(refusal))` when it may not be theirs: a reserved or malformed name, an
/// installed app's own account, another person's mailbox, or — with
/// [`Existing::Refuse`] — an account Stalwart holds that the state gives nobody.
pub async fn create(
    state: &State,
    mail: &Stalwart,
    user: &str,
    local: &str,
    domain: &str,
    is_default: bool,
    existing: Existing,
) -> crate::Result<std::result::Result<Created, String>> {
    let address = format!("{local}@{domain}");
    if let Some(refusal) = refusal(state, user, local, domain).await? {
        return Ok(Err(refusal));
    }
    let ours = state.mailbox_owner(local, domain).await?.as_deref() == Some(user);
    let domain_id = mail.ensure_domain(domain).await?;
    let found = mail.find_account(local, &domain_id).await?.is_some();
    if found && !ours && existing == Existing::Refuse {
        return Ok(Err(format!(
            "{address} exists already in the mail server, and is not yours — choose \
             another name"
        )));
    }
    if !found {
        // The IMAP/SMTP password is generated and discarded: sign-in goes through the
        // webmail's SSO, and a displayed password would be one more secret to hand out
        // for a use almost nobody has.
        let password = hlb_secrets::generate_password(hlb_secrets::DEFAULT_PASSWORD_LEN);
        mail.ensure_account(&address, &password, &[]).await?;
    }
    match state.add_mailbox(user, local, domain, is_default).await {
        Ok(()) => {}
        Err(hlb_state::Error::MailboxTaken { address }) => {
            return Ok(Err(format!("{address} is another account's mailbox")))
        }
        Err(e) => return Err(e.into()),
    }
    Ok(Ok(Created {
        address,
        adopted: found && !ours,
    }))
}

/// Why `local@domain` may not be `user`'s, before anything is asked of Stalwart.
pub async fn refusal(
    state: &State,
    user: &str,
    local: &str,
    domain: &str,
) -> crate::Result<Option<String>> {
    if let Err(e) = hlb_users::validate_name(local) {
        return Ok(Some(e.to_string()));
    }
    // An app sending mail has its own account, named after it (`ProvisionSmtpAccount`).
    if state
        .installed_apps()
        .await?
        .iter()
        .any(|(a, _)| a == local)
    {
        return Ok(Some(format!(
            "{local}@{domain} is the app \"{local}\"'s own account — choose another name"
        )));
    }
    if let Some(owner) = state.mailbox_owner(local, domain).await? {
        if owner != user {
            return Ok(Some(format!(
                "{local}@{domain} is another account's mailbox"
            )));
        }
    }
    Ok(None)
}
