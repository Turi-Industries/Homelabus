//! Rôles et permissions (§9ter).
//!
//! **Trois rôles suffisent, n'en invente pas plus.** Un modèle de permissions fin est
//! une source de bugs de sécurité : chaque combinaison non testée est un trou
//! potentiel, et personne ne relit une matrice de trente droits.
//!
//! Les rôles sont rattachés aux **groupes PocketID** (§5.9), pas gérés ici : une
//! seule source de vérité pour les identités.
//!
//! Si tu es seul utilisateur, tu es `admin` et ce module ne te coûte rien. Le poser
//! dès maintenant évite une refonte le jour où tu ouvres un accès à quelqu'un.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Tout voir, ne rien modifier.
    #[default]
    Viewer,
    /// Le travail courant : installer, mettre à jour, sauvegarder.
    Operator,
    /// Tout, y compris ce qui détruit.
    Admin,
}

/// Ce qu'on cherche à faire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Lire l'état, les journaux, les métriques.
    Read,
    /// Installer, mettre à jour, redémarrer, sauvegarder.
    Operate,
    /// 🔴 Détruire ou exposer : `--purge`, restauration en production, suppression
    /// d'un nœud, gestion des accès.
    Destroy,
}

impl Role {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "viewer" | "lecteur" => Some(Self::Viewer),
            "operator" | "operateur" | "opérateur" => Some(Self::Operator),
            "admin" | "administrateur" => Some(Self::Admin),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }

    /// Ce rôle autorise-t-il cette action ?
    ///
    /// L'ordre des rôles est croissant, donc une simple comparaison suffit — et un
    /// rôle ajouté au milieu ne créerait pas de trou silencieux.
    pub fn allows(&self, action: Action) -> bool {
        match action {
            Action::Read => true,
            Action::Operate => *self >= Self::Operator,
            Action::Destroy => *self == Self::Admin,
        }
    }

    /// Le rôle déduit des groupes PocketID (§5.9).
    ///
    /// Le plus élevé gagne : appartenir à `homelab-admins` et `homelab-users` donne
    /// `admin`, pas l'inverse.
    pub fn from_groups(groups: &[String], mapping: &[(String, Role)]) -> Self {
        groups
            .iter()
            .filter_map(|g| {
                mapping
                    .iter()
                    .find(|(nom, _)| nom == g)
                    .map(|(_, r)| *r)
            })
            .max()
            .unwrap_or_default()
    }
}

/// 🔴 Les opérations qui exigent une confirmation nommant explicitement la cible.
///
/// Le rôle ne suffit pas : un admin fatigué à 2 h du matin reste un admin. La
/// confirmation doit **répéter le nom** de ce qu'on détruit, pour qu'un `--purge`
/// tapé sur la mauvaise app ne passe pas.
pub fn needs_confirmation(action: &str) -> bool {
    matches!(
        action,
        "purge" | "restore-production" | "node-remove" | "secrets-rekey" | "cluster-destroy"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_viewer_can_only_read() {
        let r = Role::Viewer;
        assert!(r.allows(Action::Read));
        assert!(!r.allows(Action::Operate));
        assert!(!r.allows(Action::Destroy));
    }

    #[test]
    fn an_operator_works_but_never_destroys() {
        // 🔴 La distinction qui compte : installer n'est pas détruire.
        let r = Role::Operator;
        assert!(r.allows(Action::Read));
        assert!(r.allows(Action::Operate));
        assert!(!r.allows(Action::Destroy), "un opérateur ne détruit pas");
    }

    #[test]
    fn an_admin_may_do_everything() {
        let r = Role::Admin;
        assert!(r.allows(Action::Read));
        assert!(r.allows(Action::Operate));
        assert!(r.allows(Action::Destroy));
    }

    #[test]
    fn the_default_is_the_least_privileged() {
        // Un rôle absent ou illisible ne doit jamais donner plus de droits.
        assert_eq!(Role::default(), Role::Viewer);
    }

    #[test]
    fn roles_are_ordered_by_privilege() {
        assert!(Role::Viewer < Role::Operator);
        assert!(Role::Operator < Role::Admin);
    }

    #[test]
    fn the_highest_group_wins() {
        let mapping = vec![
            ("homelab-admins".to_string(), Role::Admin),
            ("homelab-users".to_string(), Role::Operator),
        ];
        let groupes = vec!["homelab-users".to_string(), "homelab-admins".to_string()];
        assert_eq!(Role::from_groups(&groupes, &mapping), Role::Admin);
    }

    #[test]
    fn an_unmapped_group_gives_the_lowest_role() {
        let mapping = vec![("homelab-admins".to_string(), Role::Admin)];
        let groupes = vec!["quelque-autre-groupe".to_string()];
        assert_eq!(Role::from_groups(&groupes, &mapping), Role::Viewer);
    }

    #[test]
    fn no_group_at_all_gives_viewer() {
        assert_eq!(Role::from_groups(&[], &[]), Role::Viewer);
    }

    #[test]
    fn destructive_operations_are_listed() {
        assert!(needs_confirmation("purge"));
        assert!(needs_confirmation("node-remove"));
        assert!(!needs_confirmation("install"));
        assert!(!needs_confirmation("backup"));
    }

    #[test]
    fn roles_parse_from_both_languages() {
        assert_eq!(Role::parse("admin"), Some(Role::Admin));
        assert_eq!(Role::parse("Opérateur"), Some(Role::Operator));
        assert_eq!(Role::parse("lecteur"), Some(Role::Viewer));
        assert_eq!(Role::parse("root"), None);
    }
}
