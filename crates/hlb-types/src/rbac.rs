//! Rôles et permissions (§9ter).
//!
//! **Quatre rôles, et pas un de plus.** Un modèle de permissions fin est une source de
//! bugs de sécurité : chaque combinaison non testée est un trou potentiel, et personne
//! ne relit une matrice de trente droits.
//!
//! Le §9ter en prévoyait trois — `viewer`, `operator`, `admin` — tous des rôles
//! d'**exploitation**. Il manquait celui de la personne qui a simplement un compte :
//! une boîte, des aliases, un portail. Lui donner `viewer` lui ouvrirait l'état du
//! cluster, les noms de secrets et le journal d'audit. D'où [`Role::Utilisateur`], en
//! dessous de tout le reste.
//!
//! ## Ce qui a changé par rapport au §9ter
//!
//! Le plan disait « rattachés aux **groupes PocketID**, pas gérés dans Homelabus ».
//! **Décision amendée** : les *identités* restent dans PocketID — une seule source de
//! vérité pour « qui est cette personne » — mais les *rôles* sont attribués ici. Gérer
//! les droits d'accès à Homelabus depuis l'interface de PocketID, en éditant des
//! groupes dont seul Homelabus connaît le sens, revenait à cacher la moitié du modèle
//! dans un autre produit. [`Role::from_groups`] reste disponible pour qui préfère
//! l'ancien schéma.
//!
//! ## Pourquoi [`Action`] est un enum exhaustif
//!
//! Même raison que `Capability` : ajouter une variante doit **faire échouer la
//! compilation** partout où une décision doit être prise. Un modèle à chaînes libres
//! (`"backup.restore"`) accepterait silencieusement une permission mal orthographiée,
//! qui ne serait jamais accordée — ou pire, jamais exigée.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Une personne qui a un compte, et rien d'autre : sa boîte, ses aliases, le
    /// portail. Ce n'est **pas** un rôle d'exploitation.
    ///
    /// C'est le défaut, donc ce qu'obtient un jeton dont le rôle est illisible et une
    /// identité PocketID inconnue de Homelabus. Le défaut doit toujours être le moins
    /// privilégié.
    #[default]
    Utilisateur,
    /// Tout voir de l'exploitation, ne rien modifier.
    Viewer,
    /// Le travail courant : installer, mettre à jour, sauvegarder, publier.
    Operator,
    /// Tout, y compris ce qui détruit et ce qui accorde des droits.
    Admin,
}

/// Ce qu'on cherche à faire.
///
/// 🔴 Exhaustif par construction : voir l'en-tête du module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Lire ses propres données : son compte, ses boîtes, ses aliases, les annonces
    /// qui lui sont destinées.
    LireSoi,
    /// Agir sur ses propres données : créer un alias, régler son tri Sieve, choisir
    /// son thème, révoquer ses sessions.
    AgirSurSoi,
    /// Lire l'exploitation : état du cluster, nœuds, journaux, métriques, inventaire
    /// des secrets (leurs noms), journal d'audit.
    Lire,
    /// Publier une annonce, ouvrir ou clore un incident, déclarer une maintenance.
    Publier,
    /// Installer, mettre à jour, redémarrer, sauvegarder, drainer un nœud.
    Operer,
    /// Créer un compte, inviter, changer le rôle de quelqu'un.
    ///
    /// Séparé de [`Self::Detruire`] parce que ce n'est pas la même faute : détruire
    /// perd des données, accorder un rôle perd le contrôle.
    GererComptes,
    /// 🔴 Détruire : `--purge`, restauration en production, suppression d'un nœud,
    /// re-chiffrement, destruction du cluster.
    Detruire,
}

impl Action {
    /// Le rôle minimal qui autorise cette action.
    ///
    /// 🔴 C'est **le seul endroit** où la matrice est écrite. Un `match` exhaustif,
    /// donc une variante ajoutée à [`Action`] ne compile pas tant qu'on n'a pas décidé
    /// qui a le droit de la faire — jamais un défaut permissif hérité par accident.
    pub fn role_minimum(&self) -> Role {
        match self {
            Self::LireSoi | Self::AgirSurSoi => Role::Utilisateur,
            Self::Lire => Role::Viewer,
            Self::Operer | Self::Publier => Role::Operator,
            Self::GererComptes | Self::Detruire => Role::Admin,
        }
    }

    /// Le nom de l'action, en français, tel qu'il apparaît dans un refus.
    ///
    /// Une phrase, pas un identifiant : le message doit se lire tel quel dans une
    /// interface (« l'action *publier une annonce* demande… »).
    /// L'identifiant court et stable, pour le journal d'audit.
    ///
    /// ⚠️ Distinct de `describe`, qui est une phrase destinée à être lue. Un journal se
    /// filtre : il lui faut un jeton stable, pas une tournure qu'on pourrait reformuler.
    pub fn nom(&self) -> &'static str {
        match self {
            Self::LireSoi => "lire-soi",
            Self::AgirSurSoi => "agir-sur-soi",
            Self::Lire => "lire",
            Self::Publier => "publier",
            Self::Operer => "operer",
            Self::GererComptes => "gerer-comptes",
            Self::Detruire => "detruire",
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::LireSoi => "consulter son propre compte",
            Self::AgirSurSoi => "modifier son propre compte",
            Self::Lire => "consulter l'état du système",
            Self::Publier => "publier une annonce",
            Self::Operer => "agir sur le système",
            Self::GererComptes => "gérer les comptes et les droits",
            Self::Detruire => "détruire ou restaurer en production",
        }
    }
}

impl Role {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "utilisateur" | "user" => Some(Self::Utilisateur),
            "viewer" | "lecteur" => Some(Self::Viewer),
            "operator" | "operateur" | "opérateur" => Some(Self::Operator),
            "admin" | "administrateur" => Some(Self::Admin),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Utilisateur => "utilisateur",
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }

    /// Ce que ce rôle permet, en une ligne, pour un écran de gestion des droits.
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Utilisateur => "son compte, sa boîte, ses aliases",
            Self::Viewer => "tout voir, ne rien modifier",
            Self::Operator => "installer, mettre à jour, sauvegarder, publier",
            Self::Admin => "tout, y compris détruire et accorder des droits",
        }
    }

    /// Ce rôle autorise-t-il cette action ?
    ///
    /// L'ordre des rôles est croissant, donc la comparaison suffit une fois la matrice
    /// posée par [`Action::role_minimum`] — et un rôle ajouté au milieu ne créerait pas
    /// de trou silencieux.
    pub fn allows(&self, action: Action) -> bool {
        *self >= action.role_minimum()
    }

    /// 🔴 Le message d'un refus : **jamais un simple « interdit »**.
    ///
    /// Un bouton grisé sans explication, ou un `403` nu, laisse la personne deviner si
    /// elle s'est trompée d'écran, si le système est cassé, ou s'il lui manque un
    /// droit. Le refus nomme donc l'action, le rôle requis, le rôle détenu, et **qui
    /// peut y remédier** — c'est la seule forme actionnable.
    ///
    /// Rend `None` quand l'action est autorisée : le type porte l'information, on ne
    /// peut pas afficher un refus par erreur.
    pub fn refus(&self, action: Action) -> Option<String> {
        if self.allows(action) {
            return None;
        }
        let requis = action.role_minimum();
        Some(format!(
            "{} demande le rôle « {} » ; le vôtre est « {} ». Un administrateur peut vous l'accorder.",
            action.describe(),
            requis.as_str(),
            self.as_str(),
        ))
    }

    /// Le rôle déduit des groupes PocketID (§5.9).
    ///
    /// Conservé pour qui préfère piloter les droits depuis PocketID plutôt que depuis
    /// Homelabus (cf. l'en-tête du module). Le plus élevé gagne : appartenir à
    /// `homelab-admins` et `homelab-users` donne `admin`, pas l'inverse.
    pub fn from_groups(groups: &[String], mapping: &[(String, Role)]) -> Self {
        groups
            .iter()
            .filter_map(|g| mapping.iter().find(|(nom, _)| nom == g).map(|(_, r)| *r))
            .max()
            .unwrap_or_default()
    }

    /// Tous les rôles, du moins au plus privilégié.
    ///
    /// Pour peupler un menu de sélection sans qu'un rôle ajouté soit oublié.
    pub fn tous() -> [Role; 4] {
        [Self::Utilisateur, Self::Viewer, Self::Operator, Self::Admin]
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
    fn a_plain_user_never_sees_the_cluster() {
        // 🔴 Le rôle ajouté au §9ter : une personne qui a un compte n'est pas un
        // opérateur en lecture seule. Lui donner `viewer` lui ouvrirait l'état du
        // cluster, les noms de secrets et le journal d'audit.
        let r = Role::Utilisateur;
        assert!(r.allows(Action::LireSoi));
        assert!(r.allows(Action::AgirSurSoi));
        assert!(!r.allows(Action::Lire), "le portail n'est pas la console");
        assert!(!r.allows(Action::Operer));
        assert!(!r.allows(Action::Publier));
        assert!(!r.allows(Action::Detruire));
    }

    #[test]
    fn a_viewer_can_only_read() {
        let r = Role::Viewer;
        assert!(r.allows(Action::Lire));
        assert!(r.allows(Action::LireSoi), "voir le cluster implique se voir soi");
        assert!(!r.allows(Action::Operer));
        assert!(!r.allows(Action::Publier));
        assert!(!r.allows(Action::Detruire));
    }

    #[test]
    fn an_operator_works_but_never_destroys() {
        // 🔴 La distinction qui compte : installer n'est pas détruire.
        let r = Role::Operator;
        assert!(r.allows(Action::Lire));
        assert!(r.allows(Action::Operer));
        assert!(r.allows(Action::Publier), "annoncer une maintenance est du travail courant");
        assert!(!r.allows(Action::Detruire), "un opérateur ne détruit pas");
        assert!(!r.allows(Action::GererComptes), "ni n'accorde de droits");
    }

    #[test]
    fn granting_rights_is_separate_from_destroying() {
        // Détruire perd des données ; accorder un rôle perd le contrôle. Les deux sont
        // réservés à l'admin, mais ce sont deux fautes différentes — et les nommer
        // séparément permet de les journaliser séparément.
        assert_eq!(Action::GererComptes.role_minimum(), Role::Admin);
        assert_eq!(Action::Detruire.role_minimum(), Role::Admin);
        assert_ne!(Action::GererComptes, Action::Detruire);
    }

    #[test]
    fn an_admin_may_do_everything() {
        let r = Role::Admin;
        for a in [
            Action::LireSoi,
            Action::AgirSurSoi,
            Action::Lire,
            Action::Publier,
            Action::Operer,
            Action::GererComptes,
            Action::Detruire,
        ] {
            assert!(r.allows(a), "admin devrait pouvoir {}", a.describe());
        }
    }

    #[test]
    fn the_default_is_the_least_privileged() {
        // Un rôle absent ou illisible ne doit jamais donner plus de droits. C'est ce
        // que rend `State::find_token` quand la colonne `role` est corrompue.
        assert_eq!(Role::default(), Role::Utilisateur);
        for r in Role::tous() {
            assert!(Role::default() <= r);
        }
    }

    #[test]
    fn roles_are_ordered_by_privilege() {
        assert!(Role::Utilisateur < Role::Viewer);
        assert!(Role::Viewer < Role::Operator);
        assert!(Role::Operator < Role::Admin);
    }

    #[test]
    fn a_refusal_says_what_is_missing_and_who_can_fix_it() {
        // 🔴 Un « interdit » nu laisse deviner si on s'est trompé d'écran, si le
        // système est cassé, ou s'il manque un droit.
        let m = Role::Viewer
            .refus(Action::Detruire)
            .expect("un viewer ne peut pas détruire");
        assert!(m.contains("admin"), "le rôle requis doit être nommé : {m}");
        assert!(m.contains("viewer"), "le rôle détenu doit être nommé : {m}");
        assert!(m.contains("administrateur"), "le remède doit être nommé : {m}");
    }

    #[test]
    fn an_allowed_action_has_no_refusal_to_display() {
        // La garantie est structurelle : on ne peut pas afficher un refus pour une
        // action autorisée, `refus` ne rend rien.
        assert_eq!(Role::Admin.refus(Action::Detruire), None);
        assert_eq!(Role::Utilisateur.refus(Action::AgirSurSoi), None);
    }

    #[test]
    fn every_action_names_itself_readably() {
        // Le message de refus se lit tel quel dans une interface : pas d'identifiant
        // technique, et jamais une chaîne vide.
        for a in [
            Action::LireSoi,
            Action::AgirSurSoi,
            Action::Lire,
            Action::Publier,
            Action::Operer,
            Action::GererComptes,
            Action::Detruire,
        ] {
            assert!(!a.describe().is_empty());
            assert!(!a.describe().contains('_'), "{} n'est pas une phrase", a.describe());
        }
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
        assert_eq!(Role::from_groups(&groupes, &mapping), Role::Utilisateur);
    }

    #[test]
    fn no_group_at_all_gives_the_least_privileged() {
        assert_eq!(Role::from_groups(&[], &[]), Role::Utilisateur);
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
        assert_eq!(Role::parse("utilisateur"), Some(Role::Utilisateur));
        assert_eq!(Role::parse("root"), None);
    }

    #[test]
    fn a_role_survives_a_round_trip_through_its_name() {
        // `as_str` alimente la colonne `api_tokens.role` et `Role::parse` la relit :
        // une divergence rendrait tous les jetons au rôle par défaut, silencieusement.
        for r in Role::tous() {
            assert_eq!(Role::parse(r.as_str()), Some(r), "{}", r.as_str());
        }
    }

    #[test]
    fn every_role_is_listed_in_tous() {
        // Si un rôle est ajouté sans être mis dans `tous()`, il manquera dans tous les
        // menus de sélection — et personne ne pourra l'attribuer.
        assert_eq!(Role::tous().len(), 4);
        let mut vus = Role::tous().to_vec();
        vus.sort();
        vus.dedup();
        assert_eq!(vus.len(), 4, "des doublons dans Role::tous()");
    }
}
