//! The Bitwarden assistant.
//!
//! ## 🔴 What this screen replaces
//!
//! Today, wiring Bitwarden up is done from memory: create an `operator` token, remember
//! to bind it to the right mailbox, find the server URL again, and guess what the
//! "domain" field expects. The `0013_token_mailbox` migration exists ONLY for this, and
//! nothing explained it anywhere.
//!
//! ## ⚠️ Two traps the wizard must name
//!
//! - **An unbound `admin` token is refused** where a bound `operator` passes: a token
//!   carries a ROLE, not an identity, and without a binding it would create aliases on
//!   anyone's mailbox.
//! - **The destination lives on the TOKEN**, because the addy.io protocol has no field
//!   for choosing it: Bitwarden only sends `domain` and `description`. One token per
//!   mailbox, and changing destination means changing token.

use serde::Deserialize;

/// What the wizard asks for.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct Request {
    /// The account owning the mailbox.
    pub account: String,
    /// The destination mailbox. `None` = the account's default mailbox.
    #[serde(default)]
    pub mailbox: Option<String>,
    /// A name for the token, so you know which one to revoke later.
    #[serde(default)]
    pub name: Option<String>,
}

/// What has to be pasted into Bitwarden.
///
/// 🔴 The token's value appears ONLY in this response, once: the state keeps only a
/// fingerprint of it. It is neither logged nor re-readable.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct Settings {
    /// The name of the token created, to revoke it later.
    pub token_name: String,
    /// 🔴 Shown once only.
    pub token: String,
    /// The address to paste into "Self-host server URL".
    #[serde(rename = "server_url")]
    pub server_url: String,
    /// The domain to paste into "Domain".
    pub domain: String,
    /// The mailbox that will receive the aliases.
    pub mailbox: String,
    /// What to do, in order, in Bitwarden's interface.
    pub steps: Vec<String>,
}

/// The steps, as they appear in Bitwarden.
///
/// ⚠️ The field names are those of Bitwarden's English interface — translating them
/// would send you looking for a field that is not on screen.
pub fn steps(url: &str, domain: &str) -> Vec<String> {
    vec![
        "In Bitwarden: Settings, then Options, then Username Generator.".to_string(),
        "Choose \"Forwarded email alias\", then the \"addy.io\" service.".to_string(),
        "Paste the token above into \"API access token\".".to_string(),
        format!("Put \"{url}\" into \"Self-host server URL\"."),
        format!("Put \"{domain}\" into \"Domain\"."),
        "Generate an alias to check: it must appear in \"My mailbox\" right here.".to_string(),
    ]
}

/// The token's name, derived when none is given.
///
/// ⚠️ The name carries the mailbox: with one token per mailbox, a plain "bitwarden"
/// would become ambiguous from the second one on, and you would revoke the wrong one.
pub fn token_name(account: &str, mailbox: Option<&str>) -> String {
    match mailbox {
        Some(b) => format!("bitwarden-{account}-{b}"),
        None => format!("bitwarden-{account}"),
    }
}

/// Creates the token bound to the mailbox, and returns what has to be pasted.
///
/// ⚠️ A configuration route: it CREATES a token, which is neither destructive nor
/// irreversible (you revoke it in one click), and there is nothing to preview — the
/// value only exists at the moment of creation.
#[utoipa::path(
    post,
    path = "/api/bitwarden",
    request_body = Request,
    responses(
        (status = 200, body = Settings)
    ),
    extensions(
        ("x-hlb-requires" = json!("manage-accounts")),
        ("x-hlb-preview" = json!(false))
    )
)]
pub async fn assistant(
    auth: crate::auth::Authorized<crate::auth::CanManageAccounts>,
    axum::extract::State(s): axum::extract::State<std::sync::Arc<crate::api::AppState>>,
    crate::extract::Json(d): crate::extract::Json<Request>,
) -> crate::error::ApiResult<Settings> {
    use crate::error::ApiError;

    // 🔴 The mailbox must EXIST. A token bound to a missing mailbox would fail on every
    // alias generation, weeks later, on a message Bitwarden does not even display — it
    // simply does not fill the field.
    let mailboxes = s.state.mailboxes(&d.account).await.unwrap_or_default();
    if mailboxes.is_empty() {
        return Err(ApiError::NotFound(format!(
            "\"{}\" has no mailbox: nothing would receive the aliases.",
            d.account
        )));
    }

    let mailbox = match &d.mailbox {
        Some(b) => {
            if !mailboxes.iter().any(|(local, ..)| local == b) {
                return Err(ApiError::NotFound(format!(
                    "\"{b}\" is not a mailbox of \"{}\".",
                    d.account
                )));
            }
            b.clone()
        }
        // The account's default mailbox: the common case, and it asks for nothing.
        None => mailboxes
            .iter()
            .find(|(_, _, default)| *default)
            .map(|(local, ..)| local.clone())
            .unwrap_or_else(|| mailboxes[0].0.clone()),
    };

    let domain = mailboxes
        .iter()
        .find(|(local, ..)| local == &mailbox)
        .map(|(_, dom, _)| dom.clone())
        .unwrap_or_default();

    // ⚠️ The public URL, never the listen address: Bitwarden calls from a phone, where
    // "127.0.0.1" means the phone.
    let Some(url) = s.public_url.clone() else {
        return Err(ApiError::Conflict(
            "the controller's public URL is unknown (--public-url): Bitwarden calls from \
             outside, and a local address does not mean this machine"
                .into(),
        ));
    };

    let name = d
        .name
        .clone()
        .unwrap_or_else(|| token_name(&d.account, d.mailbox.as_deref()));

    let mut entropy = [0u8; hlb_types::token::TOKEN_BYTES];
    hlb_secrets::fill_random(&mut entropy);
    // 🔴 `user`, the least there is: creating an alias is acting on oneself. The token
    // lives in a password manager on a phone — stolen as `operator`, it installed,
    // removed and drained.
    let (value, stored) = hlb_types::token::generate(&name, hlb_types::Role::User, entropy);

    if let Err(e) = s.state.store_token(&stored).await {
        return Err(ApiError::Conflict(e.to_string()));
    }
    // 🔴 TWO bindings, and the second was forgotten in a first attempt: the token
    // carried its mailbox but no ACCOUNT, and the alias API refused it — "this request
    // does not act on anyone's behalf". The wizard would have delivered, with its six
    // reassuring steps, a token Bitwarden could not use.
    //
    // A token carries a ROLE, not an identity: without a binding it would create
    // aliases on anyone's mailbox, so it creates nothing at all.
    s.state.set_token_user(&name, Some(&d.account)).await?;
    s.state.set_token_mailbox(&name, Some(&mailbox)).await?;

    // 🔴 The log records the CREATION, never the value.
    let _ = s
        .state
        .audit(
            auth.identity().actor.name(),
            auth.identity().role,
            "bitwarden-assistant",
            &name,
            "ok",
            Some(&format!("user token bound to \"{mailbox}\"")),
        )
        .await;

    Ok(crate::extract::Json(Settings {
        steps: steps(&url, &domain),
        token_name: name,
        token: value,
        server_url: url,
        domain,
        mailbox,
    }))
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn the_token_is_bound_to_the_account_not_only_to_the_mailbox() {
        // 🔴 The defect exactly as it showed up, and that no unit test would have
        // caught: the first attempt bound the MAILBOX and not the ACCOUNT. The wizard
        // then delivered, with its six reassuring steps, a token the alias API refuses
        // — "this request does not act on anyone's behalf" — and you would have gone
        // looking at Bitwarden.
        //
        // Found by actually calling `/api/v1/aliases` with the token produced.
        let s = hlb_state::State::in_memory().await.expect("state");
        s.upsert_user("lena", "standard", None)
            .await
            .expect("account");
        s.add_mailbox("lena", "lena", "home.example", true)
            .await
            .expect("mailbox");

        let mut entropy = [0u8; hlb_types::token::TOKEN_BYTES];
        hlb_secrets::fill_random(&mut entropy);
        let (_, stored) =
            hlb_types::token::generate("bitwarden-lena", hlb_types::Role::Operator, entropy);
        s.store_token(&stored).await.expect("token");
        s.set_token_user("bitwarden-lena", Some("lena"))
            .await
            .expect("account");
        s.set_token_mailbox("bitwarden-lena", Some("lena"))
            .await
            .expect("mailbox");

        // BOTH bindings, or one of the two is missing in silence.
        let (account, mailbox) = s.token_target("bitwarden-lena").await.expect("read");
        assert_eq!(
            account,
            Some("lena".to_string()),
            "without an account, the alias API refuses the request"
        );
        assert_eq!(
            mailbox,
            Some("lena".to_string()),
            "without a mailbox, the aliases would go to the default mailbox"
        );
    }

    use super::*;

    #[test]
    fn the_token_name_carries_the_mailbox_so_two_never_collide() {
        // ⚠️ One token per mailbox: a plain "bitwarden" would become ambiguous from the
        // second mailbox on, and you would revoke the wrong one believing you closed
        // the other.
        assert_eq!(token_name("lena", None), "bitwarden-lena");
        assert_eq!(token_name("lena", Some("achats")), "bitwarden-lena-achats");
        assert_ne!(
            token_name("lena", Some("achats")),
            token_name("lena", Some("banque"))
        );
    }

    #[test]
    fn the_steps_name_the_fields_as_bitwarden_shows_them() {
        // 🔴 Translating "Self-host server URL" would send you looking for a field that
        // is not on screen: Bitwarden's interface is in English.
        let e = steps("https://hlb.home.example", "home.example");
        let everything = e.join(" ");
        assert!(everything.contains("Self-host server URL"), "{everything}");
        assert!(everything.contains("API access token"), "{everything}");
        assert!(everything.contains("addy.io"), "{everything}");
        // And the URL and the domain appear there just as they must be pasted.
        assert!(everything.contains("https://hlb.home.example"));
        assert!(everything.contains("home.example"));
    }

    #[test]
    fn the_last_step_is_a_verification() {
        // A wizard that stops at pasting lets you believe it is wired. The only way to
        // know is to generate an alias and see it arrive.
        let e = steps("https://x", "y");
        assert!(e.last().is_some_and(|d| d.contains("check")), "{e:?}");
    }
}
