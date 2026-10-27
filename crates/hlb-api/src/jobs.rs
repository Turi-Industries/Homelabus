//! A manifest's scheduled jobs, as an app's page shows them: what each does, when it
//! last ran and how, and when it runs next.

judged! {
    /// One job of an app, and its last run.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct JobState {
        pub id: String,
        /// The manifest's sentence for it.
        pub does: String,
        /// `day` or `week`.
        pub every: String,
        /// Seconds since the epoch; `null` for one never run.
        pub last_run_at: Option<i64>,
        pub succeeded: Option<bool>,
        /// The end of what it printed last.
        pub output: String,
        /// Seconds since the epoch: when the controller runs it next — at once for one
        /// never run, a day after a failure.
        pub next_run_at: Option<i64>,
    }

    rules {
        attention: crate::Attention = JobState::attention,
    }
}

impl JobState {
    /// A failed run is work not done, as the inbox's `job_failed` says it; one never
    /// run is not yet a problem — it is due at once, and the inbox speaks if it fails.
    pub fn attention(&self) -> crate::Attention {
        match self.succeeded {
            Some(false) => crate::Attention::Notice,
            Some(true) | None => crate::Attention::Ok,
        }
    }
}
