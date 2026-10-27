//! Human accounts: identity, mailboxes, aliases and quotas.
//!
//! ## What this crate adds
//!
//! Until now Homelabus only knew about **applications**. `hlb-identity` created OIDC
//! clients, `hlb-mail` created the mailbox of an app that declared the need - and no
//! code knew what a *person* was. Creating an account meant doing it by hand in
//! PocketID, its mailbox by hand in Stalwart, and nothing linked the two: deleting one
//! left the other in place.
//!
//! This crate carries the model that was missing, and above all its **rules**. The
//! network clients stay where they are: everything here is testable without a server.
//!
//! ## The three pieces
//!
//! - [`role`] - what a person may do, and how many mailboxes and aliases they may open.
//! - [`alias`] - permanent or temporary, and above all what happens when the purge does
//!   not run.
//! - [`generation`] - the disposable per-recipient aliases, addy.io style.
//!
//! ## 🔴 A half-created account is worse than a missing one
//!
//! Creating a user touches **two** systems: PocketID for the identity, Stalwart for the
//! mailbox. If the second fails, you get someone who can sign in to every app and whose
//! address receives nothing - a state that looks functional until the first lost email,
//! often a password reset.
//!
//! [`Account::coherence`] makes that state **visible and named** rather than leaving it
//! to be discovered. And creation is resumable: rerunning finishes what is missing,
//! without ever recreating what exists.

pub mod access;
pub mod alias;
pub mod forwarder;
pub mod generation;
pub mod role;
pub mod sieve;

pub use alias::{Alias, Duration, State as AliasState};
pub use forwarder::{AliasCreated, CreationRequest};
pub use generation::Generated;
pub use role::{MailLimits, Refusal, Request, RoleDef, Usage};
pub use sieve::Rule as SieveRule;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Quota(String),

    #[error("\"{0}\": unusable identifier — lowercase, digits, dot, hyphen")]
    InvalidName(String),

    #[error(
        "\"{0}\" is reserved: other servers and people write there to reach the \
         installation's administrators, never one person's mailbox"
    )]
    ReservedName(String),

    #[error(
        "the default mailbox \"{0}\" cannot be deleted: it is the account's \
             identity. Change it first, or delete the whole user"
    )]
    DefaultMailbox(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A mailbox belonging to someone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailbox {
    /// Partie locale : `lena`, `contact`, `photo`.
    pub local: String,
    pub domain: String,
    /// 🔴 The one serving as the account's identity. Exactly one per user.
    pub default: bool,
    pub aliases: Vec<Alias>,
}

impl Mailbox {
    pub fn address(&self) -> String {
        format!("{}@{}", self.local, self.domain)
    }

    /// The aliases whose expiry was not honoured.
    ///
    /// 🔴 These are addresses the user believes closed and that still receive.
    pub fn broken_promises(&self, now: i64) -> Vec<&Alias> {
        self.aliases
            .iter()
            .filter(|a| a.state(now).breaks_the_promise())
            .collect()
    }
}

/// Un account humain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Identifiant de signin.
    pub name: String,
    /// The role's id; `None` for an account given none — it gets the lowest level,
    /// creates nothing and enters no app.
    pub role: Option<String>,
    /// The PocketID id, once the identity is created.
    pub pocket_id: Option<String>,
    pub mailboxes: Vec<Mailbox>,
}

/// An account's state across the two systems it spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coherence {
    /// Identity and default mailbox both in place.
    Complete,
    /// 🔴 They can sign in, their address receives nothing.
    ///
    /// The state that looks functional until the first lost email - often a password
    /// reset, which is to say at the worst possible moment.
    WithoutMailbox,
    /// 🔴 Their mailbox receives, they can sign in to nothing.
    WithoutIdentity,
    /// Nothing succeeded.
    Empty,
}

impl Coherence {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::Complete => "complete",
            // ⚠️ No emoji in these messages: they are DISPLAYED by the CLI *and* by
            // the interface. Severity travels through the content and the caller's
            // colour, which each consumer can restyle; a glyph is a channel none can.
            Self::WithoutMailbox => {
                "identity created, NO mailbox - this person can sign in everywhere \
                 and their address receives nothing. The first lost email will \
                 probably be a password reset. Rerun `hlb user add` with the same \
                 arguments: creation resumes where it stopped"
            }
            Self::WithoutIdentity => {
                "mailbox created, NO identity - mail arrives and nobody can \
                 read it. Run \"hlb user add\" again to finish"
            }
            Self::Empty => "no identity, no mailbox",
        }
    }
}

impl Account {
    pub fn new(name: impl Into<String>, role: Option<&str>) -> Self {
        Self {
            name: name.into(),
            role: role.map(str::to_string),
            pocket_id: None,
            mailboxes: Vec::new(),
        }
    }

    /// The mailbox serving as the identity.
    pub fn default_mailbox(&self) -> Option<&Mailbox> {
        self.mailboxes.iter().find(|b| b.default)
    }

    /// 🔴 Is the account usable, or half created?
    pub fn coherence(&self) -> Coherence {
        match (self.pocket_id.is_some(), self.default_mailbox().is_some()) {
            (true, true) => Coherence::Complete,
            (true, false) => Coherence::WithoutMailbox,
            (false, true) => Coherence::WithoutIdentity,
            (false, false) => Coherence::Empty,
        }
    }

    /// What this account consumes of its role's limits.
    ///
    /// ⚠️ Temporary aliases **already purged** no longer count: they cost the server
    /// nothing any more, and counting them would prevent creating new ones after a year
    /// of normal use.
    pub fn usage(&self, now: i64) -> Usage {
        let mut u = Usage {
            mailboxes: self.mailboxes.len() as u32,
            ..Default::default()
        };

        for b in &self.mailboxes {
            for a in &b.aliases {
                match a.duration {
                    Duration::Permanent => u.permanent_aliases += 1,
                    Duration::Temporary { .. } => {
                        if !matches!(a.state(now), alias::State::Expired) {
                            u.temporary_aliases += 1;
                        }
                    }
                }
            }
        }
        u
    }

    /// Every broken expiry promise, across all mailboxes.
    pub fn broken_promises(&self, now: i64) -> Vec<(&Mailbox, &Alias)> {
        self.mailboxes
            .iter()
            .flat_map(|b| b.broken_promises(now).into_iter().map(move |a| (b, a)))
            .collect()
    }

    /// Can this mailbox be deleted?
    ///
    /// 🔴 The default mailbox is the account's identity: deleting it would leave
    /// someone able to sign in whose address leads nowhere.
    pub fn can_delete_mailbox(&self, local: &str) -> Result<()> {
        match self.mailboxes.iter().find(|b| b.local == local) {
            Some(b) if b.default => Err(Error::DefaultMailbox(b.address())),
            _ => Ok(()),
        }
    }
}

/// Local parts that reach the installation's administrators (RFC 2142) or the machine
/// itself. Given to one person, `postmaster@` would hand them every delivery report
/// and `hostmaster@` the certificate authorities' mail for the domain.
pub const RESERVED_LOCALS: &[&str] = &[
    "postmaster",
    "abuse",
    "hostmaster",
    "webmaster",
    "noc",
    "security",
    "admin",
    "administrator",
    "root",
    "mailer-daemon",
    "nobody",
    "noreply",
    "no-reply",
];

/// An acceptable username — or mailbox local part?
///
/// ⚠️ It becomes an address's local part AND a PocketID identifier. Deliberately
/// strict: a name accepted here and refused further along would leave a half-created
/// account.
pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 50
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
        && !name.starts_with(['.', '-'])
        && !name.ends_with(['.', '-'])
        && !name.contains("..");

    if !ok {
        Err(Error::InvalidName(name.to_string()))
    } else if RESERVED_LOCALS.contains(&name) {
        Err(Error::ReservedName(name.to_string()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A glyph that carries meaning on its own: emoji, dingbats, warning signs.
    ///
    /// Same predicate as `hlb-api`'s, duplicated because this crate does not depend on
    /// it and must not start to for a test.
    fn is_pictograph(c: char) -> bool {
        matches!(c as u32, 0x2600..=0x27BF | 0x2B00..=0x2BFF | 0xFE0F | 0x1F000..=0x1FAFF)
    }

    #[test]
    fn shared_messages_carry_no_pictograph() {
        // ⚠️ These messages are displayed by the CLI AND by the interface. A glyph in
        // them once rendered as a substitution box ("¤ identity created, NO mailbox");
        // the lasting reason is that severity belongs to the words and the caller's
        // colour, and shared text must not depend on any one of its consumers.
        for c in [
            Coherence::Complete,
            Coherence::WithoutMailbox,
            Coherence::WithoutIdentity,
            Coherence::Empty,
        ] {
            for ch in c.describe().chars() {
                assert!(
                    !is_pictograph(ch),
                    "{c:?} contains U+{:04X}, a pictograph",
                    ch as u32
                );
            }
        }
    }

    const T: i64 = 1_700_000_000;

    fn mailbox(local: &str, default: bool) -> Mailbox {
        Mailbox {
            local: local.into(),
            domain: "example.fr".into(),
            default,
            aliases: Vec::new(),
        }
    }

    #[test]
    fn a_half_created_account_is_named_not_hidden() {
        // 🔴 Creating a user touches TWO systems. If the second fails, you get someone
        // who signs in everywhere and whose address receives nothing - a state that
        // looks functional until the first lost email, often a password reset, which is
        // to say at the worst possible moment.
        let mut c = Account::new("lena", Some("standard"));
        assert_eq!(c.coherence(), Coherence::Empty);

        c.pocket_id = Some("uuid".into());
        assert_eq!(c.coherence(), Coherence::WithoutMailbox);
        assert!(!c.coherence().is_complete());

        let d = c.coherence().describe();
        assert!(d.contains("receives nothing"), "{d}");
        assert!(
            d.contains("password reset"),
            "the concrete consequence: {d}"
        );
        assert!(d.contains("hlb user add"), "la reprise : {d}");

        c.mailboxes.push(mailbox("lena", true));
        assert_eq!(c.coherence(), Coherence::Complete);
    }

    #[test]
    fn a_mailbox_without_an_identity_is_its_own_problem() {
        // Mail arrives and nobody can read it — distinct from the opposite case.
        let mut c = Account::new("lena", Some("standard"));
        c.mailboxes.push(mailbox("lena", true));
        assert_eq!(c.coherence(), Coherence::WithoutIdentity);
    }

    #[test]
    fn the_default_mailbox_cannot_be_deleted() {
        // 🔴 It is the account's identity: deleting it would leave someone able to
        // sign in whose address leads nowhere.
        let mut c = Account::new("lena", Some("standard"));
        c.mailboxes.push(mailbox("lena", true));
        c.mailboxes.push(mailbox("photo", false));

        let e = c.can_delete_mailbox("lena").unwrap_err().to_string();
        assert!(e.contains("lena@example.fr"), "{e}");
        assert!(e.contains("Change it first"), "the way out: {e}");

        c.can_delete_mailbox("photo")
            .expect("an ordinary mailbox can be deleted");
    }

    #[test]
    fn purged_temporary_aliases_stop_counting() {
        // ⚠️ They cost the server nothing any more. Counting them would prevent
        // creating new ones after a year of normal use, for no technical reason.
        let mut b = mailbox("lena", true);
        let mut old = Alias::temporary("old", T - 1000);
        old.active = false; // purged
        b.aliases.push(old);
        b.aliases.push(Alias::temporary("actuel", T + 1000));
        b.aliases.push(Alias::permanent("contact"));

        let mut c = Account::new("lena", Some("standard"));
        c.mailboxes.push(b);

        let u = c.usage(T);
        assert_eq!(u.mailboxes, 1);
        assert_eq!(u.permanent_aliases, 1);
        assert_eq!(u.temporary_aliases, 1, "the purged one no longer counts");
    }

    #[test]
    fn an_expired_but_still_active_alias_counts_and_is_reported() {
        // 🔴 It still consumes quota - since it still exists in Stalwart - AND it
        // betrays the promise made to the user. Both at once.
        let mut b = mailbox("lena", true);
        b.aliases.push(Alias::temporary("oublie", T - 86_400));

        let mut c = Account::new("lena", Some("standard"));
        c.mailboxes.push(b);

        assert_eq!(c.usage(T).temporary_aliases, 1, "it still exists");

        let broken = c.broken_promises(T);
        assert_eq!(broken.len(), 1);
        assert_eq!(broken[0].1.local, "oublie");
    }

    #[test]
    fn a_username_that_would_fail_downstream_is_refused_here() {
        // ⚠️ It becomes an address's local part AND a PocketID identifier. A name
        // accepted here and refused further along would leave a half-created account.
        validate_name("lena").expect("simple");
        validate_name("lena.durand").expect("point");
        validate_name("lena-2").expect("hyphen and digit");

        for bad in [
            "",
            "Lena",
            "lena@example.fr",
            ".lena",
            "lena-",
            "léna", // accented: rejected on purpose
            "a b",
            "lena..durand",
        ] {
            assert!(
                validate_name(bad).is_err(),
                "\"{bad}\" should have been refused"
            );
        }
    }

    #[test]
    fn an_address_that_reaches_the_administrators_is_nobodys_name() {
        for reserved in ["postmaster", "abuse", "hostmaster", "webmaster", "admin"] {
            assert!(
                matches!(validate_name(reserved), Err(Error::ReservedName(_))),
                "{reserved} was accepted"
            );
        }
    }

    #[test]
    fn quotas_and_the_account_model_agree() {
        // The account counts, the role decides: both must speak of the same figure.
        let mut c = Account::new("guest", Some("guest"));
        c.mailboxes.push(mailbox("guest", true));

        let p = RoleDef::new("guest", hlb_types::Role::User, MailLimits::guest());
        let e = p
            .authorized(&c.usage(T), Request::Mailbox)
            .unwrap_err()
            .reason;
        assert!(e.contains("1/1"), "{e}");
    }
}
