//! The family's sealed kit, mailed to each relative every time it is sealed again
//! (decided 2026-10-31): each then holds the latest in a mailbox of their own, which
//! the house being down, stolen or burnt does not take with it.
//!
//! The kit is sealed to the split's key, which only their shares rebuild: the message
//! carries nothing an intercepted copy opens. It leaves from `noreply@`, one message a
//! relative — none learns the others' addresses — with no copy kept in the house.

use hlb_mail::{Attachment, Outgoing, Stalwart};
use hlb_state::State;

/// The account the house sends as. Reserved (`hlb_users::RESERVED_LOCALS`): no person
/// is given it, so whoever opens it reads nothing of theirs.
pub const SENDER: &str = "noreply";

/// What the message says of the kit it carries.
pub struct Sealed<'a> {
    pub installation: &'a str,
    pub split_id: &'a str,
    pub threshold: u8,
    pub count: u8,
    pub fingerprint: &'a str,
    pub printed: &'a str,
    /// The sealed kit itself.
    pub kit: &'a str,
}

/// How one relative's message went: the submission's id, or why it was not made.
pub struct Sent {
    pub to: String,
    pub outcome: Result<String, String>,
}

/// Why `address` cannot be a relative's, if it cannot.
pub fn address_refusal(address: &str, house: Option<&str>) -> Option<String> {
    let Some((local, domain)) = address.split_once('@') else {
        return Some(format!("\"{address}\" is not an address: no @"));
    };
    let bad = |c: char| c.is_whitespace() || c.is_control() || ",;<>\"()[]\\@".contains(c);
    if local.is_empty() || local.chars().any(bad) || domain.chars().any(bad) {
        return Some(format!("\"{address}\" is not an address"));
    }
    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return Some(format!("\"{address}\": its domain has no dot"));
    }
    // 🔴 The point is a copy the house does not hold: a mailbox in it goes down, or is
    // carried off, with everything else.
    if house.is_some_and(|h| domain.eq_ignore_ascii_case(h)) {
        return Some(format!(
            "\"{address}\" is a mailbox of this house — a relative's copy must outlive \
             it: give an address they hold elsewhere"
        ));
    }
    None
}

/// The message's text: what the file is, and how it opens without the owner.
pub fn text(k: &Sealed<'_>) -> String {
    let (i, t, n) = (k.installation, k.threshold, k.count);
    format!(
        "This is the emergency kit of {i}, sealed {printed}, attached as kit.age.\n\
         \n\
         Keep this message: it replaces any kit.age you received before. Nobody can \
         read the file alone — {t} of the {n} paper shares handed out for split {id} \
         open it, and nothing less does. It holds what brings the house back from \
         its backups if the house itself is lost.\n\
         \n\
         To open it, gather {t} shares and, on any computer with hlb \
         (https://github.com/Turi-Industries/Homelabus):\n\
         \n\
         \x20  hlb emergency combine --kit kit.age --out kit.txt\n\
         \n\
         typing one share per line. The kit's fingerprint is {fp}.\n\
         \n\
         This message was sent by the house itself, not by a person: an answer reaches \
         its administrators.\n",
        printed = k.printed,
        id = k.split_id,
        fp = k.fingerprint,
    )
}

/// Mails the sealed kit to every relative, each on their own. Fails as a whole only
/// when nothing could be tried; each relative's outcome is said otherwise.
pub async fn mail_kit(
    state: &State,
    mail: Option<&Stalwart>,
    domain: Option<&str>,
    k: &Sealed<'_>,
) -> Result<Vec<Sent>, String> {
    let relatives = state.relatives().await.map_err(|e| e.to_string())?;
    if relatives.is_empty() {
        return Ok(Vec::new());
    }
    let Some(mail) = mail else {
        return Err("mail is not configured here: the kit was mailed to nobody".into());
    };
    let Some(domain) = domain else {
        return Err("the house has no domain to send from: the kit was mailed to nobody".into());
    };
    let from = format!("{SENDER}@{domain}");
    // Nobody signs in as it: its password is drawn and forgotten.
    mail.ensure_account(&from, &hlb_secrets::generate_password(40), &[])
        .await
        .map_err(|e| format!("{from} could not be made to send from: {e}"))?;
    let reply_to = format!("{}@{domain}", hlb_mail::POSTMASTER);
    // A refusal comes back to `noreply@`: the administrators must read it, as they read
    // an answer, or a relative left without the kit goes unsaid.
    mail.forward_everything(&from, &reply_to)
        .await
        .map_err(|e| format!("{from} could not hand its refusals to {reply_to}: {e}"))?;
    let subject = format!("The emergency kit of {}", k.installation);
    let body = text(k);
    let mut out = Vec::new();
    for to in relatives {
        let outcome = mail
            .send(&Outgoing {
                from: &from,
                from_name: k.installation,
                reply_to: Some(&reply_to),
                to: &to,
                subject: &subject,
                text: &body,
                attachment: Some(Attachment {
                    name: "kit.age",
                    mime: "application/octet-stream",
                    bytes: k.kit.as_bytes(),
                }),
            })
            .await
            .map_err(|e| e.to_string());
        out.push(Sent { to, outcome });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_is_an_address_held_outside_the_house() {
        assert_eq!(
            address_refusal("lena@example.net", Some("home.example")),
            None
        );
        for bad in [
            "lena",
            "@example.net",
            "lena@",
            "le na@example.net",
            "a,b@x.net",
            "lena@localhost",
        ] {
            assert!(address_refusal(bad, None).is_some(), "{bad}");
        }
        let inside = address_refusal("lena@HOME.example", Some("home.example"));
        assert!(inside.is_some_and(|w| w.contains("outlive")));
    }

    #[test]
    fn the_message_says_how_to_open_the_kit_and_nothing_of_it() {
        let kit =
            "-----BEGIN AGE ENCRYPTED FILE-----\nSECRETBYTES\n-----END AGE ENCRYPTED FILE-----\n";
        let k = Sealed {
            installation: "Turi Industries",
            split_id: "abcd1234",
            threshold: 3,
            count: 5,
            fingerprint: "75a8513e09e1cb39",
            printed: "2026-11-01 16:00 UTC",
            kit,
        };
        let t = text(&k);
        assert!(t.contains("3 of the 5"), "{t}");
        assert!(t.contains("hlb emergency combine --kit kit.age"), "{t}");
        assert!(
            t.contains("abcd1234") && t.contains("75a8513e09e1cb39"),
            "{t}"
        );
        assert!(
            !t.contains("SECRETBYTES"),
            "the kit travels attached, never inline"
        );
        // The command is indented on purpose; a gap inside a sentence is a forgotten `\`.
        assert!(
            t.lines().all(|l| !l.trim_start().contains("  ")),
            "a gap from a line continuation: {t:?}"
        );
    }

    #[tokio::test]
    async fn nobody_to_mail_tries_nothing_and_somebody_without_mail_is_said() {
        let state = State::in_memory().await.expect("state");
        let k = Sealed {
            installation: "x",
            split_id: "s",
            threshold: 2,
            count: 3,
            fingerprint: "f",
            printed: "p",
            kit: "k",
        };
        let none = mail_kit(&state, None, Some("home.example"), &k).await;
        assert!(none.is_ok_and(|v| v.is_empty()));
        assert!(state.add_relative("lena@example.net").await.expect("add"));
        assert!(!state.add_relative("lena@example.net").await.expect("again"));
        let unmailed = mail_kit(&state, None, Some("home.example"), &k).await;
        assert!(unmailed.is_err_and(|e| e.contains("mailed to nobody")));
        assert!(state.remove_relative("lena@example.net").await.expect("rm"));
        assert!(state.relatives().await.expect("list").is_empty());
    }
}
