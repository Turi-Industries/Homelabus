//! The updates waiting, as the inbox and the updates page show them: who applies each,
//! why a person is needed, the notes to read first, and what the automatic path refused.
//!
//! Decided by the privileged side's hourly pass and stored; the web side reads that,
//! and never asks a registry or GitHub itself — a page polled every few seconds would
//! spend their rate limits in minutes.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Who applies an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpdateWho {
    /// The privileged side, in its window, with nobody there.
    Automatic,
    /// A person's approval; the pass then applies it in its window.
    OneClick,
    /// A person, by hand, with the migration guide: never from a click.
    Manual,
}

impl UpdateWho {
    /// As the state stores it.
    pub fn as_stored(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::OneClick => "one-click",
            Self::Manual => "manual",
        }
    }

    pub fn from_stored(s: &str) -> Option<Self> {
        [Self::Automatic, Self::OneClick, Self::Manual]
            .into_iter()
            .find(|w| w.as_stored() == s)
    }
}

/// What moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpdateMove {
    /// The same tag, rebuilt by its publisher.
    Rebuild,
    /// A newer version its channel allows.
    Version,
    /// The catalog names another image.
    Catalog,
    /// Its companions alone.
    Companions,
}

impl UpdateMove {
    pub fn as_stored(self) -> &'static str {
        match self {
            Self::Rebuild => "rebuild",
            Self::Version => "version",
            Self::Catalog => "catalog",
            Self::Companions => "companions",
        }
    }

    pub fn from_stored(s: &str) -> Option<Self> {
        [
            Self::Rebuild,
            Self::Version,
            Self::Catalog,
            Self::Companions,
        ]
        .into_iter()
        .find(|m| m.as_stored() == s)
    }
}

/// How far an update moves what runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpdateJump {
    Patch,
    Minor,
    Major,
}

/// How far updates go alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpdateReach {
    None,
    Patch,
    Minor,
}

/// Why an update waits for a person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UpdateWhy {
    /// A new major, another image, or a tag no version reads.
    Major,
    /// Further than the house — or the manifest, when the house says nothing — lets an
    /// update go alone.
    BeyondReach {
        jump: UpdateJump,
        reach: UpdateReach,
        by_house: bool,
    },
    /// A release on the way says it breaks something or migrates data; `word` is the
    /// one found, as the notes wrote it.
    NotesSay { tag: String, word: String },
    /// The target's notes are not among the releases.
    NotesMissing { tag: String },
    /// The notes could not be read; `error` as the server was told.
    NotesUnreadable { error: String },
}

/// One release's notes, to read before approving.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ReleaseNote {
    pub tag: String,
    pub url: String,
}

/// What stopped the automatic path, or an approved update, from applying. The text a
/// value carries is the tool's own (the scan, the backup, Swarm), shown as received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UpdateRefusal {
    /// Critical vulnerabilities, or a signature that is not the publisher's.
    Vulnerable { described: String },
    /// The copy owed before the switch failed: nothing switched.
    CopyFailed { error: String },
    /// It could not even start.
    Failed { error: String },
    /// Swarm rolled the switch back: the previous version runs.
    RolledBack { reason: String },
    /// The switch paused: a person looks.
    Paused,
    /// No outcome within the time allotted.
    Inconclusive,
}

judged! {
    /// One update waiting.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct WaitingUpdate {
        pub app: String,
        pub from_tag: String,
        pub moves: UpdateMove,
        /// The tag it moves to; `null` for a rebuild or companions alone.
        pub to_tag: Option<String>,
        pub who: UpdateWho,
        /// `null` when it applies itself.
        pub why: Option<UpdateWhy>,
        /// The releases between what runs and the target; `null` when the manifest names
        /// no source for them, or they could not be read.
        pub notes: Option<Vec<ReleaseNote>>,
        /// Seconds since the epoch: when the pass last decided.
        pub decided_at: i64,
        pub refused: Option<UpdateRefusal>,
        pub refused_at: Option<i64>,
        pub approved_by: Option<String>,
        pub approved_at: Option<i64>,
    }

    rules {
        /// Approved since its last refusal: the pass applies it in its window.
        approved: bool = WaitingUpdate::approved,
        /// Who must act on it: the automatic path's refusal is a person's again.
        needs: Option<UpdateNeed> = WaitingUpdate::needs,
    }
}

/// What a waiting update needs from a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UpdateNeed {
    /// A click, after reading its notes.
    Approval,
    /// A person, by hand, with the migration guide.
    Hands,
    /// Refused while nobody was there: look at why, then approve it again or apply it
    /// by hand.
    Look,
}

impl WaitingUpdate {
    pub fn approved(&self) -> bool {
        match (self.approved_at, self.refused_at) {
            (Some(a), Some(r)) => a > r,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// `None` when it goes on alone: automatic, or approved and not refused since.
    pub fn needs(&self) -> Option<UpdateNeed> {
        if self.who == UpdateWho::Manual {
            return Some(UpdateNeed::Hands);
        }
        if self.refused_at.is_some() && !self.approved() {
            return Some(UpdateNeed::Look);
        }
        match self.who {
            UpdateWho::OneClick if !self.approved() => Some(UpdateNeed::Approval),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waiting(who: UpdateWho) -> WaitingUpdate {
        WaitingUpdate {
            app: "gitea".into(),
            from_tag: "1.24.3".into(),
            moves: UpdateMove::Version,
            to_tag: Some("1.25.0".into()),
            who,
            why: None,
            notes: None,
            decided_at: 0,
            refused: None,
            refused_at: None,
            approved_by: None,
            approved_at: None,
        }
    }

    #[test]
    fn a_click_is_needed_until_given_and_again_after_a_refusal() {
        let mut u = waiting(UpdateWho::OneClick);
        assert_eq!(u.needs(), Some(UpdateNeed::Approval));
        u.approved_at = Some(10);
        assert_eq!(u.needs(), None);
        u.refused_at = Some(20);
        assert_eq!(u.needs(), Some(UpdateNeed::Look));
        u.approved_at = Some(30);
        assert_eq!(u.needs(), None);
    }

    #[test]
    fn an_automatic_update_needs_nobody_until_refused() {
        let mut u = waiting(UpdateWho::Automatic);
        assert_eq!(u.needs(), None);
        u.refused_at = Some(5);
        assert_eq!(u.needs(), Some(UpdateNeed::Look));
    }

    #[test]
    fn a_major_is_always_by_hand() {
        let mut u = waiting(UpdateWho::Manual);
        u.approved_at = Some(1);
        assert_eq!(u.needs(), Some(UpdateNeed::Hands));
    }

    #[test]
    fn what_is_stored_reads_back() {
        for w in [UpdateWho::Automatic, UpdateWho::OneClick, UpdateWho::Manual] {
            assert_eq!(UpdateWho::from_stored(w.as_stored()), Some(w));
        }
        for m in [
            UpdateMove::Rebuild,
            UpdateMove::Version,
            UpdateMove::Catalog,
            UpdateMove::Companions,
        ] {
            assert_eq!(UpdateMove::from_stored(m.as_stored()), Some(m));
        }
    }
}
