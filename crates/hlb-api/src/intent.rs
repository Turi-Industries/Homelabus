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
    Nodes(Nodes),
    Install(Install),
    Upgrade(Upgrade),
    CatalogChanges(CatalogChanges),
    AttestGuide(AttestGuide),
    Remove(Remove),
    BackUp(BackUp),
    PurgeAlias(PurgeAlias),
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
    Nodes => Option<Result<Vec<hlb_types::swarm::NodeInfo>, String>>,
    Install => Acted,
    Upgrade => Acted,
    CatalogChanges => Vec<String>,
    AttestGuide => ActionResult,
    Remove => ActionResult,
    BackUp => ActionResult,
    PurgeAlias => ActionResult,
}

/// The answer of an action that may not even be planned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Acted {
    /// The plan, previewed or applied.
    Planned(ActionResult),
    /// Nothing could be planned — no catalog, an unknown app, a run that stopped —
    /// and this says why.
    Unplannable(String),
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

/// The cluster's nodes as Swarm lists them; `None` when no orchestrator is reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nodes {}

/// Install an application from the catalog, or resume its interrupted install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Install {
    pub app: String,
    /// The domain a person chose; `None` takes the installation's default.
    pub domain: Option<String>,
    pub mail_domain: Option<String>,
    pub apply: bool,
}

/// Bring an installed application to its catalog manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upgrade {
    pub app: String,
    pub apply: bool,
}

/// What the catalog has changed in an installed application, field by field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogChanges {
    pub app: String,
}

/// Attest that a manual step was done — checked first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestGuide {
    pub app: String,
    pub id: String,
    /// Attest even against the step's own check.
    pub force: bool,
    pub apply: bool,
}

/// Remove an application; its volumes are kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remove {
    pub app: String,
    /// The app's name repeated: checked by the privileged side, never on trust.
    pub confirmed: Option<String>,
    pub apply: bool,
}

/// Back one application up now, whether due or not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackUp {
    pub app: String,
    pub apply: bool,
}

/// Purge one of an account's own expired-but-still-active aliases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeAlias {
    /// The account the web side vouches is asking; `None` = nobody signed in.
    pub account: Option<String>,
    pub local: String,
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
