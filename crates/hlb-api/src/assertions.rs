//! The last reading of an app's assertions: what its manifest says must stay true,
//! read from the running app.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// What a reading found.
///
/// ⚠️ `AssertionVerdict` in the document: the restorability's `Verdict` has the name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = AssertionVerdict)]
pub enum Verdict {
    Holds,
    /// 🔴 The app answered, and what it said is not what the manifest promises.
    Broken,
    /// It could not be read — the app down, its database unreachable. Not "fine": a
    /// door nobody looked at is not known to be closed.
    Unknown,
}

impl Verdict {
    /// The value stored in `assertion_results.verdict`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Holds => "holds",
            Self::Broken => "broken",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::Holds, Self::Broken, Self::Unknown]
            .into_iter()
            .find(|v| v.as_str() == s)
    }
}

judged! {
    /// One assertion, as last read.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AssertionResult {
        pub id: String,
        /// The manifest's sentence for it, as it was when read.
        pub holds: String,
        pub verdict: Verdict,
        /// What the app answered — never a secret's value.
        pub observed: String,
        /// Seconds since the epoch; `0` for one never read.
        pub checked_at: i64,
        /// What a person does about it, while it does not hold.
        pub fix: Option<String>,
    }

    rules {
        attention: crate::Attention = AssertionResult::attention,
    }
}

impl AssertionResult {
    /// A door open needs an action; one not looked at, a look.
    pub fn attention(&self) -> crate::Attention {
        match self.verdict {
            Verdict::Holds => crate::Attention::Ok,
            Verdict::Broken => crate::Attention::Critical,
            Verdict::Unknown => crate::Attention::Notice,
        }
    }
}

/// A reading older than this is reported unknown: the nightly pass stopped, and the
/// last "holds" says nothing about tonight.
pub const STALE_AFTER_S: i64 = 2 * 86_400;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_verdict_reads_back_what_it_stores() {
        for v in [Verdict::Holds, Verdict::Broken, Verdict::Unknown] {
            assert_eq!(Verdict::parse(v.as_str()), Some(v));
            assert_eq!(
                serde_json::to_value(v).expect("serialises"),
                serde_json::Value::String(v.as_str().into())
            );
        }
    }
}
