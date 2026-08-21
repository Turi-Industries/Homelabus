//! Le système de design : couleurs, thèmes, typographie, composants.
//!
//! ## La règle
//!
//! **Aucun écran ne pose de couleur, de taille ni de marge à la main.** Tout vient
//! d'ici. C'est ce qui rend un changement de thème complet et instantané — un seul
//! `Color32::from_rgb(…)` oublié dans un écran, et l'interface a l'air cassée dans le
//! thème clair, sans que personne ne sache pourquoi.

pub mod composants;
pub mod glyphes;
pub mod palette;
pub mod qr;
pub mod theme;

pub use palette::Palette;
pub use theme::{mesures, Theme};
