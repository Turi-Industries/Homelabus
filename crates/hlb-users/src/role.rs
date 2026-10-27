//! Roles: what a person may do, and how much they may hold.
//!
//! ## A role is data
//!
//! It was two axes: `hlb_types::Role` (four levels, what may be done to the cluster)
//! and a quota *profile* (how many mailboxes). The two were always chosen as a pair —
//! "an admin with my mailbox", "an admin with more" — and a person given one and not
//! the other was a gap nobody saw. A role is now a row — a name, one of
//! the four levels, mail limits, a quota per app — and "admin with more" is another
//! role. Authorization keeps its four levels: a role's [`RoleDef::level`] is what
//! `Authorized<…>` checks, unchanged.
//!
//! ⚠️ A role's `id` is stored in PocketID (its group, `hlb-<id>`), in every app's
//! restriction and in `users.role`: it never changes. Its `name` is for people.
//!
//! ## 🔴 A limit reached must say WHO set it
//!
//! "Quota exceeded" sends people looking at the disk or the mail server. The real
//! information is: which limit, from which role, and who can change it. Without
//! that, the message costs its reader half an hour.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// What a role allows of mail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailLimits {
    /// Maximum number of mailboxes, the default address **included**.
    ///
    /// ⚠️ Included, not "on top": otherwise `max_mailboxes: 0` would still give one
    /// mailbox, and the limit would mean nothing.
    pub max_mailboxes: u32,
    /// Permanent aliases per mailbox.
    pub max_permanent_aliases: u32,
    /// Temporary aliases per mailbox.
    ///
    /// Separate from the permanent ones: disposables get created as you go, often by
    /// the dozen, and counting them together would hit the permanent limit with nobody
    /// understanding why.
    pub max_temporary_aliases: u32,
    /// Maximum lifetime of a temporary alias, in seconds.
    ///
    /// 🔴 Without a cap, "temporary" can mean ten years, and the notion empties itself
    /// of meaning with nothing forbidding it.
    pub max_duration_s: i64,
    /// Space quota per mailbox, in bytes. `None` means the server's own.
    pub quota_bytes: Option<u64>,
}

impl MailLimits {
    /// An ordinary account's — the `standard` profile's, before roles.
    pub fn standard() -> Self {
        Self {
            max_mailboxes: 3,
            max_permanent_aliases: 10,
            // Generous: this is the usage to encourage, one disposable alias per
            // merchant rather than a single address given everywhere.
            max_temporary_aliases: 50,
            max_duration_s: 365 * 86_400,
            quota_bytes: Some(5 * 1024 * 1024 * 1024),
        }
    }

    /// A guest's: one mailbox, no permanent alias.
    pub fn guest() -> Self {
        Self {
            max_mailboxes: 1,
            max_permanent_aliases: 0,
            max_temporary_aliases: 5,
            max_duration_s: 30 * 86_400,
            quota_bytes: Some(1024 * 1024 * 1024),
        }
    }

    /// No practical limit.
    ///
    /// ⚠️ "No limit" is still a number: limits that were truly infinite could not be
    /// displayed, compared or tested.
    pub fn unlimited() -> Self {
        Self {
            max_mailboxes: u32::MAX,
            max_permanent_aliases: u32::MAX,
            max_temporary_aliases: u32::MAX,
            max_duration_s: i64::MAX,
            quota_bytes: None,
        }
    }

    /// Nothing: what someone holding no role may create.
    pub fn none() -> Self {
        Self {
            max_mailboxes: 0,
            max_permanent_aliases: 0,
            max_temporary_aliases: 0,
            max_duration_s: 0,
            quota_bytes: Some(0),
        }
    }
}

/// A role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleDef {
    /// 🔴 Stable: PocketID's group and every restriction name it.
    pub id: String,
    pub name: String,
    /// What it may do to Homelabus itself — what authorization reads.
    pub level: hlb_types::Role,
    pub mail: MailLimits,
    /// Per app, a storage quota in bytes. An app absent has none.
    pub quotas: BTreeMap<String, u64>,
}

impl RoleDef {
    pub fn new(id: &str, level: hlb_types::Role, mail: MailLimits) -> Self {
        Self {
            id: id.to_string(),
            name: id.to_string(),
            level,
            mail,
            quotas: BTreeMap::new(),
        }
    }

    /// What someone holding no role gets: the lowest level, nothing to create, no app.
    pub fn nothing() -> Self {
        Self::new("", hlb_types::Role::User, MailLimits::none())
    }

    /// The name a refusal or a screen shows: "no role" for [`Self::nothing`].
    pub fn label(&self) -> &str {
        if self.id.is_empty() {
            "no role"
        } else {
            &self.name
        }
    }
}

/// What is being created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    Mailbox,
    AliasPermanent,
    AliasTemporary { duration_s: i64 },
}

/// What is already held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub mailboxes: u32,
    pub permanent_aliases: u32,
    pub temporary_aliases: u32,
}

/// Why it is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub reason: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl RoleDef {
    /// Does this request pass?
    ///
    /// 🔴 The refusal names the limit, the role that sets it, and the command that
    /// changes it. "Quota exceeded" would send people looking at the disk or the mail
    /// server - which is to say nowhere.
    pub fn authorized(&self, usage: &Usage, request: Request) -> Result<(), Refusal> {
        match request {
            Request::Mailbox => {
                if usage.mailboxes >= self.mail.max_mailboxes {
                    return Err(Refusal {
                        reason: format!(
                            "mailbox limit reached: {}/{} for the \"{}\" role. \
                             Give another role with `hlb user role <name> <role>`, \
                             raise this one's with `hlb role set`, or delete a mailbox",
                            usage.mailboxes,
                            self.mail.max_mailboxes,
                            self.label()
                        ),
                    });
                }
            }

            Request::AliasPermanent => {
                if usage.permanent_aliases >= self.mail.max_permanent_aliases {
                    return Err(Refusal {
                        reason: format!(
                            "permanent alias limit reached: {}/{} for the \"{}\" \
                             role. A TEMPORARY alias is still possible ({} at most), \
                             and that is often what is wanted",
                            usage.permanent_aliases,
                            self.mail.max_permanent_aliases,
                            self.label(),
                            self.mail.max_temporary_aliases
                        ),
                    });
                }
            }

            Request::AliasTemporary { duration_s } => {
                if usage.temporary_aliases >= self.mail.max_temporary_aliases {
                    return Err(Refusal {
                        reason: format!(
                            "temporary alias limit reached: {}/{} for the \"{}\" \
                             role. Already-purged expired ones no longer count - \
                             `hlb user alias purge` removes them",
                            usage.temporary_aliases,
                            self.mail.max_temporary_aliases,
                            self.label()
                        ),
                    });
                }

                if duration_s > self.mail.max_duration_s {
                    return Err(Refusal {
                        reason: format!(
                            "requested duration too long: {} d, maximum {} d for the \
                             \"{}\" role. Beyond that, \"temporary\" stops meaning \
                             much - take a permanent alias if that is the intent",
                            duration_s / 86_400,
                            self.mail.max_duration_s / 86_400,
                            self.label()
                        ),
                    });
                }

                if duration_s <= 0 {
                    return Err(Refusal {
                        reason: "zero or negative duration: the alias would be expired \
                                 before existing, and the purge would remove it on its \
                                 first pass"
                            .into(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_mailbox_counts_against_the_limit() {
        // ⚠️ Included, not "on top": otherwise `max_mailboxes: 0` would still give one
        // mailbox, and the limit would mean nothing.
        let p = RoleDef::new("guest", hlb_types::Role::User, MailLimits::guest());
        assert_eq!(p.mail.max_mailboxes, 1);

        let usage = Usage {
            mailboxes: 1,
            ..Default::default()
        };
        assert!(
            p.authorized(&usage, Request::Mailbox).is_err(),
            "the guest already has its default mailbox: the second is refused"
        );
    }

    #[test]
    fn a_refusal_names_the_limit_the_role_and_the_way_out() {
        // 🔴 "Quota exceeded" would send people looking at the disk or the mail
        // server, which is to say nowhere.
        let p = RoleDef::new("guest", hlb_types::Role::User, MailLimits::guest());
        let usage = Usage {
            mailboxes: 1,
            ..Default::default()
        };
        let e = p.authorized(&usage, Request::Mailbox).unwrap_err().reason;

        assert!(e.contains("1/1"), "the limit as a figure: {e}");
        assert!(e.contains("guest"), "the role that sets it: {e}");
        assert!(e.contains("hlb user role"), "the way out: {e}");
    }

    #[test]
    fn permanent_and_temporary_aliases_are_counted_apart() {
        // Disposables get created by the dozen. Counting them with the permanent ones
        // would hit the permanent limit with nobody understanding why.
        let p = RoleDef::new("standard", hlb_types::Role::User, MailLimits::standard());
        let usage = Usage {
            mailboxes: 1,
            permanent_aliases: 0,
            temporary_aliases: 49,
        };
        assert!(p.authorized(&usage, Request::AliasPermanent).is_ok());
        assert!(p
            .authorized(&usage, Request::AliasTemporary { duration_s: 86_400 })
            .is_ok());

        let full = Usage {
            temporary_aliases: 50,
            ..usage
        };
        assert!(full.temporary_aliases.eq(&p.mail.max_temporary_aliases));
        assert!(p
            .authorized(&full, Request::AliasTemporary { duration_s: 86_400 })
            .is_err());
        assert!(
            p.authorized(&full, Request::AliasPermanent).is_ok(),
            "permanent aliases are untouched by the temporary cap"
        );
    }

    #[test]
    fn a_permanent_refusal_suggests_the_temporary_route() {
        // Refusing without offering the available alternative pushes people to ask for
        // a role change for a need that did not call for one.
        let p = RoleDef::new("guest", hlb_types::Role::User, MailLimits::guest());
        let usage = Usage {
            permanent_aliases: 0,
            ..Default::default()
        };
        let e = p
            .authorized(&usage, Request::AliasPermanent)
            .unwrap_err()
            .reason;
        assert!(e.contains("TEMPORARY"), "{e}");
    }

    #[test]
    fn a_temporary_alias_cannot_outlive_the_notion() {
        // 🔴 With no cap, "temporary" can mean ten years, and the word empties itself
        // of meaning with nothing forbidding it.
        let p = RoleDef::new("guest", hlb_types::Role::User, MailLimits::guest());
        let usage = Usage::default();

        assert!(p
            .authorized(
                &usage,
                Request::AliasTemporary {
                    duration_s: 30 * 86_400
                }
            )
            .is_ok());

        let e = p
            .authorized(
                &usage,
                Request::AliasTemporary {
                    duration_s: 3650 * 86_400,
                },
            )
            .unwrap_err()
            .reason;
        assert!(e.contains("30 d"), "the limit must be stated: {e}");
        assert!(e.contains("permanent"), "the honest alternative: {e}");
    }

    #[test]
    fn a_zero_duration_alias_is_refused_rather_than_created_dead() {
        // Created then removed on the purge's first pass: the user would believe they
        // had it, and the address would never work.
        let e = RoleDef::new("standard", hlb_types::Role::User, MailLimits::standard())
            .authorized(&Usage::default(), Request::AliasTemporary { duration_s: 0 })
            .unwrap_err()
            .reason;
        assert!(e.contains("expired before existing"), "{e}");
    }

    #[test]
    fn the_unlimited_role_still_refuses_nonsense() {
        // "No limit" does not mean "accepts anything": a negative duration is still a
        // typing mistake.
        let p = RoleDef::new("unlimited", hlb_types::Role::User, MailLimits::unlimited());
        assert!(p
            .authorized(
                &Usage::default(),
                Request::AliasTemporary { duration_s: -1 }
            )
            .is_err());
        assert!(p
            .authorized(
                &Usage {
                    mailboxes: 9999,
                    ..Default::default()
                },
                Request::Mailbox
            )
            .is_ok());
    }

    #[test]
    fn someone_holding_no_role_creates_nothing_and_is_told_so() {
        let e = RoleDef::nothing()
            .authorized(&Usage::default(), Request::Mailbox)
            .unwrap_err()
            .reason;
        assert!(e.contains("0/0") && e.contains("no role"), "{e}");
    }
}
