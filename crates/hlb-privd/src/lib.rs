//! The privileged executor.
//!
//! Everything that is root on a node or reads a secret sits behind [`Privd`]: Docker's
//! socket, the vault, the admin clients. The web side holds a `Privd` and can do one
//! thing with it — ask an [`Intent`] — because every field is private to this crate: a
//! handler that wants the orchestrator does not compile, rather than relying on a
//! reviewer to notice.
//!
//! For now both sides run in one process. The answers already go through JSON, so the
//! day they become two processes joined by a socket, only the transport changes.

use std::sync::Arc;

use hlb_api::intent::{Ask, Intent};
use hlb_orchestrator::Orchestrator;
use hlb_state::State;

mod swarm;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An answer that does not survive its own wire format: a bug on this side, found
    /// in process before a socket ever carries it.
    #[error("the privileged side's answer does not read back: {0}")]
    Wire(#[from] serde_json::Error),
}

/// What the privileged side holds, and the only door to it.
pub struct Privd {
    state: Arc<State>,
    /// `None` = Docker unreachable, or the demonstration: each intent says so in its
    /// answer rather than fail.
    orchestrator: Option<Arc<dyn Orchestrator>>,
}

impl Privd {
    pub fn new(state: Arc<State>) -> Self {
        Self {
            state,
            orchestrator: None,
        }
    }

    pub fn with_orchestrator(mut self, o: Option<Arc<dyn Orchestrator>>) -> Self {
        self.orchestrator = o;
        self
    }

    /// Asks one intent, and reads its answer back as its own type.
    pub async fn ask<A: Ask>(&self, intent: A) -> Result<A::Answer, Error> {
        let wire = self.answer(intent.into()).await?;
        Ok(serde_json::from_value(wire)?)
    }

    /// Answers an intent with its answer as it travels.
    ///
    /// 🔴 No `_ =>` arm: an intent added to the enum does not compile until it is
    /// answered here.
    pub async fn answer(&self, intent: Intent) -> Result<serde_json::Value, Error> {
        Ok(match intent {
            Intent::Scale(i) => serde_json::to_value(swarm::scale(self, i).await)?,
            Intent::NodeAvailability(i) => {
                serde_json::to_value(swarm::node_availability(self, i).await)?
            }
        })
    }
}
