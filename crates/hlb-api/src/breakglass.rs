//! The break-glass plan, kept alive.
//!
//! ## 🔴 A centralised SSO is a single point of failure ON ACCESS
//!
//! If PocketID goes down, you can no longer sign in to Homelabus — therefore no longer
//! drive PocketID's restore. The safeguards below stand against that.
//!
//! ## What Homelabus can, and cannot, do
//!
//! It does **not** know how many passkeys are registered, nor whether the one-time
//! codes are printed and stored in a drawer. Ticking those boxes on your behalf would
//! be the worst possible display: a green screen over guarantees that do not exist,
//! consulted precisely on the day you are locked out.
//!
//! So it asks for a **dated attestation**, and lets it expire. A break-glass never
//! exercised is not a break-glass — the same reasoning as the restore drills.
//!
//! Four it proves itself, and no hand attests: the restore drill, the emergency vault's
//! verified deposit, an emergency kit printed since what it holds last changed, and the
//! family having opened it without the owner ([`proof`]).

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

judged! {
    /// One emergency-access safeguard.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Safeguard {
        /// Stable identifier, used to attest.
        pub id: String,
        pub title: String,
        /// Why this safeguard exists.
        pub why: String,
        /// How to set it up or verify it.
        pub comment: String,
        /// Age of the last attestation, in seconds. `None` = never attested.
        #[serde(default)]
        pub attested_ago_s: Option<i64>,
        #[serde(default)]
        pub attested_by: Option<String>,
        /// 🔴 True when Homelabus can verify it itself — only one is.
        pub verifiable: bool,
        /// ⚠️ True when the age only has DAY resolution.
        ///
        /// The recovery drill is counted in whole days: showing "0 s ago" for a drill from
        /// last night would suggest it just happened. The type carries the resolution, or
        /// the display invents a precision that does not exist.
        #[serde(default)]
        pub resolution_day: bool,
    }

    rules {
        attention: crate::Attention = Safeguard::attention,
        attestation: Attestation = Safeguard::attestation,
    }
}

/// Whether a safeguard was ever verified: see [`Safeguard::attestation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Attestation {
    /// 🔴 Not "maybe in place": "we know nothing about it".
    Never,
    Verified {
        when: When,
        #[serde(default)]
        by: Option<String>,
    },
}

/// When an attestation was made, at the resolution the record has.
///
/// ⚠️ A drill counted in whole days is `Today`, `Yesterday` or `DaysAgo` — never a
/// number of seconds, which would show "0 s ago" for last night's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum When {
    Today,
    Yesterday,
    DaysAgo {
        days: i64,
    },
    /// This many seconds ago, at full resolution.
    Ago {
        seconds: i64,
    },
}

/// Beyond that, an attestation stops being reassuring: devices change, people leave,
/// and "we did it" becomes "we think we did it".
pub const ATTESTATION_STALE_S: i64 = 180 * 86_400;

impl Safeguard {
    pub fn attention(&self) -> crate::Attention {
        match self.attested_ago_s {
            // 🔴 Never attested: not "maybe in place", but "we know nothing about it" —
            // and that is the situation you discover while locked out.
            None => crate::Attention::Critical,
            Some(age) if age > ATTESTATION_STALE_S => crate::Attention::Notice,
            Some(_) => crate::Attention::Ok,
        }
    }

    /// When it was last verified, and by whom — the decision, resolution included;
    /// the interface has the words.
    pub fn attestation(&self) -> Attestation {
        let Some(age) = self.attested_ago_s else {
            return Attestation::Never;
        };
        let when = if self.resolution_day {
            match age / 86_400 {
                0 => When::Today,
                1 => When::Yesterday,
                days => When::DaysAgo { days },
            }
        } else {
            When::Ago { seconds: age }
        };
        Attestation::Verified {
            when,
            by: self.attested_by.clone(),
        }
    }
}

/// The PocketID restore drill's id.
pub const DRILL: &str = "pocketid-restored";
/// The emergency vault's: every recovery sign-in deposited, its account verified.
pub const EMERGENCY_VAULT: &str = "emergency-vault";
/// The emergency kit's: printed since what it holds last changed.
pub const EMERGENCY_KIT: &str = "emergency-kit";
/// The family's: the holders of the kit's shares opened it together, without the owner.
pub const FAMILY_REHEARSAL: &str = "family-rehearsal";
/// Not a safeguard: the fingerprint of the last kit sealed for the family, which the
/// rehearsal's proof reads. Its own row, since a plain kit printed after a change makes
/// [`EMERGENCY_KIT`] current again while the family's copy stays the old one.
pub const FAMILY_KIT: &str = "family-kit-sealed";

/// What proves a safeguard Homelabus verifies itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    /// A successful restore drill.
    Drill,
    /// A deposit made after every check of the account held — withdrawn the night one
    /// does not.
    Deposit,
    /// A kit printed with what is current: its fingerprint is kept with the attestation.
    Kit,
    /// The rehearsal code read off the sealed kit, which only its shares open, given
    /// back — and burned; counted while the last kit sealed for them is current.
    Rehearsal,
}

/// The proof of a safeguard Homelabus verifies itself; `None` for one a person attests.
/// `verifiable` says the same, and a test holds the two together.
pub fn proof(id: &str) -> Option<Proof> {
    match id {
        DRILL => Some(Proof::Drill),
        EMERGENCY_VAULT => Some(Proof::Deposit),
        EMERGENCY_KIT => Some(Proof::Kit),
        FAMILY_REHEARSAL => Some(Proof::Rehearsal),
        _ => None,
    }
}

/// The safeguards, in the order you want to read them.
pub fn safeguards() -> Vec<Safeguard> {
    vec![
        Safeguard {
            id: "printed-codes".into(),
            title: "One-time sign-in codes, printed".into(),
            why: "The first net when the device holding the passkey is not there \
                       — lost, broken, or left somewhere else."
                .into(),
            comment: "Generate them in PocketID, PRINT them, and store them outside the \
                      cluster. A file on the machine that went down is no use."
                .into(),
            attested_ago_s: None,
            attested_by: None,
            verifiable: false,
            resolution_day: false,
        },
        Safeguard {
            id: "two-passkeys".into(),
            title: "At least two passkeys, on distinct devices".into(),
            why: "A single passkey is a single point of loss: the phone falls in \
                       the water and access goes with it."
                .into(),
            comment: "Register a second passkey on a different kind of device — a \
                      hardware key rather than a second phone."
                .into(),
            attested_ago_s: None,
            attested_by: None,
            verifiable: false,
            resolution_day: false,
        },
        Safeguard {
            id: "vaultwarden-local".into(),
            title: "Local sign-in still enabled on Vaultwarden".into(),
            why: "The one way in that depends on NO other service: it gives access \
                       to the passwords when the SSO is down."
                .into(),
            comment: "Check that SSO_ONLY is false, and actually sign in with the master \
                      password — not just read the setting."
                .into(),
            attested_ago_s: None,
            attested_by: None,
            verifiable: false,
            resolution_day: false,
        },
        Safeguard {
            id: DRILL.into(),
            title: "PocketID restore actually exercised".into(),
            why: "PocketID is the most critical service in the cluster: without it \
                       you sign in nowhere, not even here to drive its own restore."
                .into(),
            comment: "hlb dr exercise, then hlb dr promote pocketid at least once — on \
                      a sandbox, but for real."
                .into(),
            attested_ago_s: None,
            attested_by: None,
            verifiable: true,
            // The drill is counted in whole days.
            resolution_day: true,
        },
        Safeguard {
            id: EMERGENCY_VAULT.into(),
            title: "Every recovery sign-in in the emergency vault".into(),
            why: "The day PocketID signs nobody in, each app's own administrator is the \
                  way in — and a password nobody can find opens nothing."
                .into(),
            comment: "hlb emergency vault --apply, with an owner once: then every night it \
                      verifies its account and deposits. It stops counting the night the \
                      account no longer verifies."
                .into(),
            attested_ago_s: None,
            attested_by: None,
            verifiable: true,
            resolution_day: false,
        },
        Safeguard {
            id: EMERGENCY_KIT.into(),
            title: "The emergency kit, printed and current".into(),
            why: "The master key and the backup repository's password restore the vault \
                  itself: they cannot be kept inside it."
                .into(),
            comment: "hlb emergency kit, printed and kept away from the cluster. A kit \
                      printed before the master key, the repository's password or a \
                      destination changed no longer counts."
                .into(),
            attested_ago_s: None,
            attested_by: None,
            verifiable: true,
            resolution_day: false,
        },
        Safeguard {
            id: FAMILY_REHEARSAL.into(),
            title: "The family can open today's kit without the owner".into(),
            why: "The day the owner is gone, a kit nobody else can open is no kit, and \
                  one they open from before a change restores nothing."
                .into(),
            comment: "Each relative holds a share of hlb emergency split. After any change, \
                      and once a year, send them hlb emergency kit --sealed; having opened \
                      it together, they give you the rehearsal code it ends with, for hlb \
                      emergency rehearsed <code>. It stops counting when what the kit holds \
                      changes, until the family has the new one."
                .into(),
            attested_ago_s: None,
            attested_by: None,
            verifiable: true,
            resolution_day: false,
        },
    ]
}

/// The overall verdict.
///
/// ⚠️ The WORST case decides, not the average: four safeguards out of five do not make
/// 80 % of an emergency access. The missing one is the one that will be missing.
pub fn verdict(safeguards: &[Safeguard]) -> Verdict {
    let never = safeguards
        .iter()
        .filter(|g| g.attested_ago_s.is_none())
        .count();

    if never == safeguards.len() {
        return Verdict::NoneEverVerified;
    }
    if never > 0 {
        return Verdict::NeverVerified { safeguards: never };
    }

    let stale = safeguards
        .iter()
        .filter(|g| g.attested_ago_s.is_some_and(|a| a > ATTESTATION_STALE_S))
        .count();
    if stale > 0 {
        return Verdict::ToReverify { safeguards: stale };
    }
    Verdict::AllRecent
}

/// What the safeguards add up to: see [`verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Verdict {
    /// 🔴 If PocketID goes down, nothing says you will still be able to get in.
    NoneEverVerified,
    /// This many never verified — the one that will be missing.
    NeverVerified {
        safeguards: usize,
    },
    /// This many past the stale age: "we did it" has become "we think we did it".
    ToReverify {
        safeguards: usize,
    },
    AllRecent,
}

judged! {
    /// The safeguards, and what they add up to — what `/api/recovery` answers.
    ///
    /// A struct rather than the bare list: the verdict is the worst case across them all,
    /// and a client handed only the list would have to re-derive it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct BreakGlass {
        pub safeguards: Vec<Safeguard>,
    }

    rules {
        verdict: Verdict = |b: &BreakGlass| verdict(&b.safeguards),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_never_attested_guardrail_is_critical_not_merely_unknown() {
        // 🔴 "We know nothing about it" is exactly the situation you discover while
        // locked out. Painting it yellow would get it postponed.
        let g = &safeguards()[0];
        assert_eq!(g.attested_ago_s, None);
        assert_eq!(g.attention(), crate::Attention::Critical);
        assert_eq!(g.attestation(), Attestation::Never);
    }

    #[test]
    fn an_old_attestation_stops_reassuring() {
        // A break-glass never exercised is not a break-glass: the same reasoning as the
        // restore drills.
        let mut g = safeguards()[1].clone();
        g.attested_ago_s = Some(ATTESTATION_STALE_S + 86_400);
        g.attested_by = Some("lena".into());
        assert_eq!(g.attention(), crate::Attention::Notice);

        g.attested_ago_s = Some(86_400);
        assert_eq!(g.attention(), crate::Attention::Ok);
        assert!(
            matches!(
                g.attestation(),
                Attestation::Verified { by: Some(ref b), .. } if b == "lena"
            ),
            "{:?}",
            g.attestation()
        );
    }

    #[test]
    fn a_day_resolution_age_never_pretends_to_be_precise() {
        // 🔴 Seen on screen: "verified 0 s ago" for a drill counted in whole days. It
        // reads as "just now", when the drill may date from last night.
        let mut g = safeguards()
            .into_iter()
            .find(|g| g.verifiable)
            .expect("the verifiable safeguard");
        assert!(g.resolution_day);

        let when = |g: &Safeguard| match g.attestation() {
            Attestation::Verified { when, .. } => when,
            Attestation::Never => panic!("attested"),
        };
        g.attested_ago_s = Some(0);
        assert_eq!(when(&g), When::Today);
        g.attested_ago_s = Some(86_400);
        assert_eq!(when(&g), When::Yesterday);
        g.attested_ago_s = Some(5 * 86_400);
        assert_eq!(when(&g), When::DaysAgo { days: 5 });
        // And the same age at full resolution is seconds, which the interface words.
        g.resolution_day = false;
        assert_eq!(
            when(&g),
            When::Ago {
                seconds: 5 * 86_400
            }
        );
    }

    #[test]
    fn a_safeguard_claims_to_be_verifiable_only_with_a_proof() {
        // ⚠️ Homelabus does not know how many passkeys exist, nor whether codes are
        // printed. Claiming otherwise would give a green screen over guarantees that do
        // not exist — and one it proves must not be attestable by a hand.
        for g in safeguards() {
            assert_eq!(g.verifiable, proof(&g.id).is_some(), "{}", g.id);
        }
        let human: Vec<String> = safeguards()
            .into_iter()
            .filter(|g| !g.verifiable)
            .map(|g| g.id)
            .collect();
        assert_eq!(
            human,
            ["printed-codes", "two-passkeys", "vaultwarden-local"]
        );
    }

    #[test]
    fn the_worst_case_decides_never_the_average() {
        // Four out of five do not make 80 % of an emergency access.
        let mut g = safeguards();
        for x in g.iter_mut() {
            x.attested_ago_s = Some(86_400);
        }
        assert_eq!(verdict(&g), Verdict::AllRecent);

        g[2].attested_ago_s = None;
        assert_eq!(verdict(&g), Verdict::NeverVerified { safeguards: 1 });

        g[2].attested_ago_s = Some(ATTESTATION_STALE_S + 1);
        assert_eq!(verdict(&g), Verdict::ToReverify { safeguards: 1 });
    }

    #[test]
    fn nothing_attested_at_all_says_so_plainly() {
        assert_eq!(verdict(&safeguards()), Verdict::NoneEverVerified);
    }
}
