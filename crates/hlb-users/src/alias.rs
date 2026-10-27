//! Mail aliases, permanent or temporary.
//!
//! ## 🔴 The central trap: Stalwart cannot expire an alias
//!
//! A mail server has no notion of a lifetime on an alias. An account's `aliases`
//! property is a plain list: what is written there stays.
//!
//! So a "temporary" alias is only temporary **if something actually removes it**. And
//! that is exactly the kind of promise that breaks silently: you give
//! `purchase-3f2a@example.org` to a merchant thinking it will expire in thirty days,
//! the purge task does not run - because the controller went down, because Stalwart was
//! unreachable that day - and the address stays alive forever. You believe you closed a
//! door that stayed open.
//!
//! Hence [`Alias::state`], which distinguishes **three** situations and not two: still
//! valid, expired-and-removed, and 🔴 **expired-but-still-active**. The third is the one
//! that matters, and it would not exist if we merely compared a date to the current
//! time.
//!
//! ## Why temporary aliases exist
//!
//! Giving your real address to every merchant hands them a shared identifier linking
//! them to each other, and a permanent target in case of a leak. A disposable alias per
//! use cuts both: it is removed without touching the account, and the leak reveals only
//! a dead address.

use serde::{Deserialize, Serialize};

/// An alias's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Duration {
    /// Disappears only when removed.
    Permanent,
    /// Must be removed at this date (Unix timestamp).
    ///
    /// ⚠️ "Must", not "will be": it is an intent the purge has to honour.
    Temporary { expires_at: i64 },
}

/// An alias as we know it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alias {
    /// The local part only: `purchase-3f2a`, never the full address.
    pub local: String,
    pub duration: Duration,
    /// Is it actually still present in Stalwart?
    ///
    /// 🔴 This field is what makes the distinction possible. Without it, an expired
    /// alias and an expired-but-never-removed one would be indistinguishable.
    pub active: bool,
    /// What it is for, so it still makes sense six months later.
    pub note: Option<String>,
}

/// An alias's real state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Permanent and active.
    Permanent,
    /// Temporary, still valid.
    Valid { remaining_s: i64 },
    /// Temporary, expired, and **actually removed**. The nominal case.
    Expired,
    /// 🔴 Temporary, expired, and **STILL ACTIVE**.
    ///
    /// The purge did not do its job. The address believed closed keeps receiving - the
    /// exact opposite of what was asked for.
    ExpiredButActive { since_s: i64 },
}

impl Alias {
    pub fn permanent(local: impl Into<String>) -> Self {
        Self {
            local: local.into(),
            duration: Duration::Permanent,
            active: true,
            note: None,
        }
    }

    pub fn temporary(local: impl Into<String>, expires_at: i64) -> Self {
        Self {
            local: local.into(),
            duration: Duration::Temporary { expires_at },
            active: true,
            note: None,
        }
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// The real state, at instant `now`.
    pub fn state(&self, now: i64) -> State {
        match self.duration {
            Duration::Permanent => State::Permanent,
            Duration::Temporary { expires_at } => {
                let passed = now >= expires_at;
                match (passed, self.active) {
                    (false, _) => State::Valid {
                        remaining_s: expires_at - now,
                    },
                    // 🔴 The case that justifies this whole module.
                    (true, true) => State::ExpiredButActive {
                        since_s: now - expires_at,
                    },
                    (true, false) => State::Expired,
                }
            }
        }
    }

    /// Must it be removed now?
    pub fn is_due_for_purge(&self, now: i64) -> bool {
        matches!(self.state(now), State::ExpiredButActive { .. })
    }
}

impl State {
    /// Is an address believed closed still receiving?
    pub fn breaks_the_promise(&self) -> bool {
        matches!(self, Self::ExpiredButActive { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Permanent => "permanent".into(),
            Self::Valid { remaining_s } => {
                format!("expires in {}", readable_duration(*remaining_s))
            }
            Self::Expired => "expired, removed".into(),
            Self::ExpiredButActive { since_s } => format!(
                "🔴 EXPIRED {} ago and STILL ACTIVE - the purge did not run, this \
                 address is still receiving",
                readable_duration(*since_s)
            ),
        }
    }
}

fn readable_duration(s: i64) -> String {
    let s = s.max(0);
    if s < 3600 {
        format!("{} min", s / 60)
    } else if s < 172_800 {
        format!("{} h", s / 3600)
    } else {
        format!("{} d", s / 86400)
    }
}

/// The aliases to purge, in the order they will be handled.
///
/// ⚠️ Longest-expired first: if the purge is interrupted halfway, the promises broken
/// longest ago are the ones that will have been kept first.
pub fn due_for_purge(aliases: &[Alias], now: i64) -> Vec<&Alias> {
    let mut v: Vec<&Alias> = aliases.iter().filter(|a| a.is_due_for_purge(now)).collect();
    v.sort_by_key(|a| match a.duration {
        Duration::Temporary { expires_at } => expires_at,
        Duration::Permanent => i64::MAX,
    });
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_700_000_000;

    #[test]
    fn an_expired_alias_that_still_works_is_its_own_state() {
        // 🔴 THE point of this module. A temporary alias is only temporary if
        // something actually removes it. If the purge did not run, the address believed
        // closed is still receiving - the opposite of what was asked for. Comparing a
        // date to the current time is NOT enough to see it.
        let mut a = Alias::temporary("achat-3f2a", T);
        a.active = true;

        let e = a.state(T + 86_400);
        assert_eq!(e, State::ExpiredButActive { since_s: 86_400 });
        assert!(e.breaks_the_promise());

        // The same alias, actually removed: the nominal case, with no alert.
        a.active = false;
        assert_eq!(a.state(T + 86_400), State::Expired);
        assert!(!a.state(T + 86_400).breaks_the_promise());
    }

    #[test]
    fn the_message_says_the_address_still_receives() {
        // Saying "expired" would wrongly reassure. It must say it RECEIVES.
        let a = Alias::temporary("x", T);
        let m = a.state(T + 172_800).describe();
        assert!(m.contains("STILL ACTIVE"), "{m}");
        assert!(m.contains("still receiving"), "{m}");
        assert!(m.contains("purge"), "the cause must be named: {m}");
    }

    #[test]
    fn a_valid_alias_says_how_long_is_left() {
        let a = Alias::temporary("x", T + 86_400);
        assert_eq!(
            a.state(T),
            State::Valid {
                remaining_s: 86_400
            }
        );
        assert!(!a.is_due_for_purge(T));
    }

    #[test]
    fn a_permanent_alias_is_never_purged() {
        let a = Alias::permanent("contact");
        assert_eq!(a.state(T), State::Permanent);
        assert!(!a.is_due_for_purge(T + 10_000_000_000));
    }

    #[test]
    fn expiry_is_inclusive_of_its_own_instant() {
        // Exactly at the stated time the alias is expired. Leaving it one second
        // longer would be arbitrary, and "expires at 14:00" must mean 14:00.
        let a = Alias::temporary("x", T);
        assert!(a.is_due_for_purge(T));
        assert!(!a.is_due_for_purge(T - 1));
    }

    #[test]
    fn the_oldest_broken_promise_is_purged_first() {
        // ⚠️ If the purge is interrupted halfway, the addresses open longest are the
        // ones that will have been closed first.
        let aliases = vec![
            Alias::temporary("recent", T - 100),
            Alias::permanent("contact"),
            Alias::temporary("old", T - 100_000),
            Alias::temporary("futur", T + 100_000),
        ];

        let p = due_for_purge(&aliases, T);
        assert_eq!(
            p.iter().map(|a| a.local.as_str()).collect::<Vec<_>>(),
            vec!["old", "recent"]
        );
    }

    #[test]
    fn an_already_purged_alias_is_not_purged_twice() {
        let mut a = Alias::temporary("x", T - 1000);
        a.active = false;
        assert!(!a.is_due_for_purge(T), "already removed in Stalwart");
    }
}
