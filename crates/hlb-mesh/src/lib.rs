//! Mesh WireGuard entre nœuds (§2ter, §6.3, §9).
//!
//! 🔴 **Les ports de Swarm ne doivent JAMAIS être exposés publiquement.**
//!
//! Swarm a besoin de 2377 (API cluster), 7946 (découverte) et 4789 (overlay VXLAN).
//! Les ouvrir sur Internet expose l'API de contrôle du cluster ; le port 4789 en
//! particulier n'a **aucune authentification** — quiconque peut y envoyer des paquets
//! peut injecter du trafic dans les réseaux overlay.
//!
//! Le mesh résout ça : Swarm n'écoute que sur l'interface WireGuard, et le trafic
//! entre nœuds est chiffré indépendamment de l'overlay.
//!
//! ## Ce que ce crate fait, et ne fait pas
//!
//! Il **génère** les clés et les configurations. Il ne les **applique** pas : poser
//! une interface réseau demande les droits root sur chaque machine, ce qui est le
//! rôle du bootstrap. Cette séparation permet de tester toute la logique
//! d'attribution d'adresses et de génération de configuration sans toucher au réseau.

pub mod config;
pub mod keys;

pub use config::{provision_node, MeshConfig, Peer};
pub use keys::KeyPair;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("adresse mesh épuisée : {0} nœuds au maximum dans {1}")]
    AddressPoolExhausted(usize, String),

    #[error("nœud « {0} » déjà présent dans le mesh")]
    DuplicateNode(String),

    #[error("clé invalide : {0}")]
    InvalidKey(String),
}

pub type Result<T> = std::result::Result<T, Error>;
