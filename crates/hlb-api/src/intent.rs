//! What the web side may ASK the privileged side to do.
//!
//! ## Why intents, and not a narrow Docker API
//!
//! A route that relays a service specification protects nothing: a spec binds any host
//! path, and whoever writes one is root on the node. So the web side never says HOW —
//! it says "scale gitea to three", "drain this node", and the privileged side
//! re-derives everything else from the catalog and its own state, refusing what it
//! cannot derive. An intruder in the web side can then do what a signed-in person's
//! intents can, and no more: no secret read, no host path, no `exec`.
//!
//! ## 🔴 One enum, matched exhaustively
//!
//! [`Intent`] is every privileged thing a handler can ask, and the privileged side
//! dispatches it with one `match` that has no `_ =>` arm: an intent added here breaks
//! that match until it is answered. Each intent is also its own struct implementing
//! [`Ask`], which names the type of its answer — so a caller gets the answer typed,
//! while the wire carries one enum.
//!
//! Every type here is serialisable both ways, and the privileged side round-trips each
//! answer through JSON even in process: the day the two sides become two processes,
//! the wire is the one already tested.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::ActionResult;

/// An intent, with the type of its answer.
pub trait Ask: Into<Intent> {
    type Answer: Serialize + DeserializeOwned;
}

/// Every privileged thing the web side may ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "intent", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Intent {
    Scale(Scale),
    NodeAvailability(NodeAvailability),
}

macro_rules! asks {
    ($($variant:ident => $answer:ty),* $(,)?) => {
        $(
            impl From<$variant> for Intent {
                fn from(i: $variant) -> Self {
                    Intent::$variant(i)
                }
            }

            impl Ask for $variant {
                type Answer = $answer;
            }
        )*
    };
}

asks! {
    Scale => ActionResult,
    NodeAvailability => ActionResult,
}

/// Run an application's service with this many replicas, and keep that decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scale {
    pub app: String,
    /// `None` = the caller sent none: refused, never defaulted.
    pub replicas: Option<u64>,
    pub apply: bool,
}

/// Set a Swarm node's availability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAvailability {
    /// Swarm's id for the node, or its hostname: Docker takes either.
    pub node: String,
    /// `active`, `pause` or `drain`; anything else is refused.
    pub availability: String,
    /// The node's name repeated, accepting the downtime a drain announces.
    pub confirmed: Option<String>,
    pub apply: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_intent_travels_as_one_tagged_object() {
        let i: Intent = Scale {
            app: "gitea".into(),
            replicas: Some(3),
            apply: false,
        }
        .into();
        let wire = serde_json::to_value(&i).expect("serialise");
        assert_eq!(wire["intent"], "scale");
        assert_eq!(
            serde_json::from_value::<Intent>(wire).expect("deserialise"),
            i
        );
    }

    #[test]
    fn an_intent_with_a_field_the_daemon_does_not_know_is_refused() {
        let wire = serde_json::json!({
            "intent": "scale", "app": "gitea", "replicas": 3, "apply": true,
            "image": "evil/latest"
        });
        assert!(serde_json::from_value::<Intent>(wire).is_err());
    }
}
