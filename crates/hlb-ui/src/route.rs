//! Où l'on est dans l'interface.
//!
//! ## Pourquoi une route et pas un onglet
//!
//! L'interface avait quatre onglets et un champ `Onglet` dans la structure. Ça ne monte
//! pas : avec le détail d'une app et ses sept sous-onglets, il faut savoir *quelle* app
//! et *quel* sous-onglet. Et surtout, il faut pouvoir **envoyer un lien** — « regarde
//! les sauvegardes de gitea » doit se coller dans une conversation.
//!
//! ## 🔴 Le fragment porte déjà le jeton
//!
//! `#token=…` est lu au démarrage puis **effacé de la barre d'adresse** pour qu'un lien
//! copié ne l'emporte pas (voir `lib.rs`). L'ordre est donc : consommer le jeton, puis
//! seulement lire la route. Un fragment qui contiendrait les deux ferait fuiter le
//! jeton dans le premier lien partagé.

use std::fmt;
use std::str::FromStr;

/// Les sous-onglets du détail d'une app (§11bis, écran 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OngletApp {
    #[default]
    Apercu,
    Journaux,
    Config,
    Sauvegardes,
    MisesAJour,
    Metriques,
    Historique,
}

impl OngletApp {
    pub fn slug(&self) -> &'static str {
        match self {
            Self::Apercu => "apercu",
            Self::Journaux => "journaux",
            Self::Config => "config",
            Self::Sauvegardes => "sauvegardes",
            Self::MisesAJour => "maj",
            Self::Metriques => "metriques",
            Self::Historique => "historique",
        }
    }

    pub fn libelle(&self) -> &'static str {
        match self {
            Self::Apercu => "Vue d'ensemble",
            Self::Journaux => "Journaux",
            Self::Config => "Configuration",
            Self::Sauvegardes => "Sauvegardes",
            Self::MisesAJour => "Mises à jour",
            Self::Metriques => "Métriques",
            Self::Historique => "Historique",
        }
    }

    pub fn tous() -> [OngletApp; 7] {
        [
            Self::Apercu,
            Self::Journaux,
            Self::Config,
            Self::Sauvegardes,
            Self::MisesAJour,
            Self::Metriques,
            Self::Historique,
        ]
    }

    fn depuis(s: &str) -> Option<Self> {
        Self::tous().into_iter().find(|o| o.slug() == s)
    }
}

/// Un écran.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Route {
    #[default]
    TableauDeBord,
    Apps,
    App {
        nom: String,
        onglet: OngletApp,
    },
    Noeuds,
    Topologie,
    /// Les écarts entre ce qui devrait tourner et ce qui tourne — refus délibérés
    /// compris (lot 9.8).
    Derive,
    /// La rivière datée de tout ce qui s'est passé (lot 9.5).
    Chronologie,
    /// Les plans préparés à froid (§10.4).
    Plans,
    Alertes,
    Sauvegardes,
    Securite,
    Catalogue,
    Journal,
    Secrets,
    AFaire,
    Comptes,
    Annonces,
    Reglages,
    /// Le portail : ce que voit quelqu'un qui a un compte et rien d'autre.
    Portail,
    /// La page de statut : ce qui marche, ce qui ne marche pas.
    Statut,
    MaBoite,
    MonCompte,
    /// L'écran d'inscription, atteint par un lien d'invitation.
    Inscription,
}

impl Route {
    /// Le libellé de l'entrée de navigation.
    pub fn libelle(&self) -> &'static str {
        match self {
            Self::TableauDeBord => "Tableau de bord",
            Self::Apps => "Applications",
            Self::App { .. } => "Application",
            Self::Noeuds => "Nœuds",
            Self::Topologie => "Topologie",
            Self::Derive => "Dérive",
            Self::Chronologie => "Chronologie",
            Self::Plans => "Plans",
            Self::Alertes => "Alertes",
            Self::Sauvegardes => "Sauvegardes",
            Self::Securite => "Sécurité",
            Self::Catalogue => "Catalogue",
            Self::Journal => "Journal",
            Self::Secrets => "Secrets",
            Self::AFaire => "À faire",
            Self::Comptes => "Comptes",
            Self::Annonces => "Annonces",
            Self::Reglages => "Réglages",
            Self::Portail => "Accueil",
            Self::Statut => "Statut",
            Self::MaBoite => "Ma boîte",
            Self::MonCompte => "Mon compte",
            Self::Inscription => "Inscription",
        }
    }

    /// Un libellé court, pour la barre basse d'un téléphone.
    ///
    /// ⚠️ Les libellés longs poussaient les dernières entrées hors de l'écran, et on ne
    /// pouvait plus les atteindre du tout.
    pub fn libelle_court(&self) -> &'static str {
        match self {
            Self::TableauDeBord => "Bord",
            Self::Apps => "Apps",
            Self::Sauvegardes => "Sauveg.",
            Self::Alertes => "Alertes",
            Self::AFaire => "À faire",
            Self::Comptes => "Comptes",
            Self::Chronologie => "Chrono.",
            autre => autre.libelle(),
        }
    }

    /// 🔴 Le droit minimal pour voir cet écran.
    ///
    /// Ce n'est **pas** le contrôle d'accès — il a lieu à chaque requête, côté
    /// controller. C'est de quoi ne pas afficher une entrée de navigation qui mènerait
    /// à un écran vide et à un 403.
    pub fn exige(&self) -> hlb_types::rbac::Action {
        use hlb_types::rbac::Action;
        match self {
            // ⚠️ La page de statut demande `LireSoi`, pas `Lire` : elle est faite pour
            // les gens qui subissent la panne, pas pour ceux qui l'exploitent. Exiger
            // un droit de console la ferait disparaître du portail — c'est-à-dire de
            // l'endroit où on la cherche quand quelque chose ne marche pas.
            Self::Portail | Self::Statut | Self::Inscription => Action::LireSoi,
            Self::MaBoite | Self::MonCompte => Action::AgirSurSoi,
            Self::Comptes => Action::GererComptes,
            Self::Annonces => Action::Publier,
            Self::Reglages => Action::Operer,
            _ => Action::Lire,
        }
    }
}

impl fmt::Display for Route {
    /// La forme qui va dans le fragment d'URL.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TableauDeBord => write!(f, "/"),
            Self::Apps => write!(f, "/apps"),
            Self::App { nom, onglet } => write!(f, "/apps/{nom}/{}", onglet.slug()),
            Self::Noeuds => write!(f, "/noeuds"),
            Self::Topologie => write!(f, "/topologie"),
            Self::Derive => write!(f, "/derive"),
            Self::Chronologie => write!(f, "/chronologie"),
            Self::Plans => write!(f, "/plans"),
            Self::Alertes => write!(f, "/alertes"),
            Self::Sauvegardes => write!(f, "/sauvegardes"),
            Self::Securite => write!(f, "/securite"),
            Self::Catalogue => write!(f, "/catalogue"),
            Self::Journal => write!(f, "/journal"),
            Self::Secrets => write!(f, "/secrets"),
            Self::AFaire => write!(f, "/a-faire"),
            Self::Comptes => write!(f, "/comptes"),
            Self::Annonces => write!(f, "/annonces"),
            Self::Reglages => write!(f, "/reglages"),
            Self::Portail => write!(f, "/portail"),
            Self::Statut => write!(f, "/statut"),
            Self::MaBoite => write!(f, "/portail/boite"),
            Self::MonCompte => write!(f, "/portail/compte"),
            Self::Inscription => write!(f, "/inscription"),
        }
    }
}

/// Ce qui ne va pas dans une route écrite à la main.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteInconnue(pub String);

impl fmt::Display for RouteInconnue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RouteInconnue {}

impl FromStr for Route {
    type Err = RouteInconnue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().trim_start_matches('#');
        let s = s.trim_start_matches('/');
        let morceaux: Vec<&str> = s.split('/').filter(|m| !m.is_empty()).collect();

        match morceaux.as_slice() {
            [] => Ok(Self::TableauDeBord),
            ["apps"] => Ok(Self::Apps),
            // ⚠️ Un onglet inconnu retombe sur la vue d'ensemble plutôt que d'échouer :
            // un lien vers un onglet renommé doit continuer d'ouvrir la bonne app.
            ["apps", nom] => Ok(Self::App {
                nom: (*nom).to_string(),
                onglet: OngletApp::default(),
            }),
            ["apps", nom, onglet] => Ok(Self::App {
                nom: (*nom).to_string(),
                onglet: OngletApp::depuis(onglet).unwrap_or_default(),
            }),
            ["noeuds"] => Ok(Self::Noeuds),
            ["topologie"] => Ok(Self::Topologie),
            ["derive"] => Ok(Self::Derive),
            ["chronologie"] => Ok(Self::Chronologie),
            ["plans"] => Ok(Self::Plans),
            ["alertes"] => Ok(Self::Alertes),
            ["sauvegardes"] | ["backup"] => Ok(Self::Sauvegardes),
            ["securite"] => Ok(Self::Securite),
            ["catalogue"] => Ok(Self::Catalogue),
            ["journal"] | ["audit"] => Ok(Self::Journal),
            ["secrets"] => Ok(Self::Secrets),
            ["a-faire"] | ["todo"] => Ok(Self::AFaire),
            ["comptes"] | ["users"] => Ok(Self::Comptes),
            ["annonces"] => Ok(Self::Annonces),
            ["reglages"] => Ok(Self::Reglages),
            ["portail"] => Ok(Self::Portail),
            ["statut"] => Ok(Self::Statut),
            ["portail", "boite"] => Ok(Self::MaBoite),
            ["portail", "compte"] => Ok(Self::MonCompte),
            ["inscription"] => Ok(Self::Inscription),
            // ⚠️ On ne suggère que les écrans ÉCRITS. Lister le plan complet
            // proposerait des routes qui s'ouvrent sur « pas encore écrit » : on
            // suivrait la suggestion, on n'aurait rien, et on douterait du message.
            _ => Err(RouteInconnue(format!(
                "route « /{s} » inconnue. Écrans disponibles : {}",
                Route::navigation_admin()
                    .iter()
                    .map(|r| r.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }
}

impl Route {
    /// Cet écran est-il écrit ?
    ///
    /// 🔴 La navigation ne montre QUE les écrans existants. Une entrée qui mènerait à
    /// « à venir » est pire qu'une entrée absente : elle promet, on clique, on n'a rien,
    /// et on doute de tout le reste. Les routes non implémentées restent dans l'énuméré
    /// parce qu'elles sont le plan (§11bis) — elles ne sont simplement pas offertes.
    pub fn implemente(&self) -> bool {
        matches!(
            self,
            Self::TableauDeBord
                | Self::Apps
                | Self::App { .. }
                | Self::Noeuds
                | Self::Topologie
                | Self::Derive
                | Self::Chronologie
                | Self::Plans
                | Self::Securite
                | Self::Alertes
                | Self::Sauvegardes
                | Self::Comptes
                | Self::Portail
                | Self::Annonces
                | Self::Statut
                | Self::Inscription
                | Self::AFaire
                | Self::Journal
                | Self::Secrets
                | Self::Reglages
        )
    }

    /// Les entrées de la navigation d'administration, dans l'ordre d'affichage.
    ///
    /// Le tableau de bord d'abord : c'est l'écran qui répond à « est-ce que quelque
    /// chose ne va pas ? », et il doit être atteignable sans réfléchir.
    pub fn navigation_admin() -> Vec<Route> {
        Self::plan_admin().into_iter().filter(Route::implemente).collect()
    }

    /// Tout ce que le §11bis prévoit, implémenté ou non.
    pub fn plan_admin() -> Vec<Route> {
        vec![
            Self::TableauDeBord,
            Self::Apps,
            Self::Alertes,
            Self::Noeuds,
            Self::Topologie,
            Self::Derive,
            Self::Chronologie,
            Self::Plans,
            Self::Sauvegardes,
            Self::AFaire,
            Self::Securite,
            Self::Secrets,
            Self::Catalogue,
            Self::Journal,
            Self::Comptes,
            Self::Annonces,
            Self::Reglages,
        ]
    }

    /// Les entrées du portail.
    pub fn navigation_portail() -> Vec<Route> {
        Self::plan_portail().into_iter().filter(Route::implemente).collect()
    }

    pub fn plan_portail() -> Vec<Route> {
        vec![Self::Portail, Self::Statut, Self::MaBoite, Self::MonCompte]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_route_survives_a_round_trip_through_its_url() {
        // 🔴 Si écrire et relire une route divergeaient, un lien collé dans une
        // conversation ouvrirait un autre écran que celui qu'on voulait partager — et
        // c'est justement pour ça que le routage existe.
        let toutes = [
            Route::TableauDeBord,
            Route::Apps,
            Route::App { nom: "gitea".into(), onglet: OngletApp::Sauvegardes },
            Route::App { nom: "gitea".into(), onglet: OngletApp::Apercu },
            Route::Noeuds,
            Route::Topologie,
            Route::Derive,
            Route::Chronologie,
            Route::Plans,
            Route::Alertes,
            Route::Sauvegardes,
            Route::Securite,
            Route::Catalogue,
            Route::Journal,
            Route::Secrets,
            Route::AFaire,
            Route::Comptes,
            Route::Annonces,
            Route::Reglages,
            Route::Portail,
            Route::Statut,
            Route::MaBoite,
            Route::MonCompte,
            Route::Inscription,
        ];
        for r in toutes {
            let s = r.to_string();
            assert_eq!(Route::from_str(&s).expect(&s), r, "aller-retour cassé pour {s}");
        }
    }

    #[test]
    fn a_renamed_tab_still_opens_the_right_app() {
        // ⚠️ Un lien vers `/apps/gitea/logs` (renommé depuis en `journaux`) doit
        // continuer d'ouvrir gitea, pas afficher une erreur de route.
        let r = Route::from_str("/apps/gitea/un-onglet-supprime").expect("route");
        assert_eq!(
            r,
            Route::App { nom: "gitea".into(), onglet: OngletApp::Apercu }
        );
    }

    #[test]
    fn an_app_without_a_tab_opens_its_overview() {
        assert_eq!(
            Route::from_str("/apps/gitea").expect("route"),
            Route::App { nom: "gitea".into(), onglet: OngletApp::Apercu }
        );
    }

    #[test]
    fn the_leading_hash_and_slash_are_optional() {
        // Le fragment arrive tantôt avec `#`, tantôt sans, selon le navigateur et selon
        // qu'on vient d'un `set_hash`. Les trois formes doivent marcher.
        for s in ["#/apps", "/apps", "apps"] {
            assert_eq!(Route::from_str(s).expect(s), Route::Apps, "{s}");
        }
        for s in ["#/", "/", "", "#"] {
            assert_eq!(Route::from_str(s).expect(s), Route::TableauDeBord, "{s}");
        }
    }

    #[test]
    fn english_aliases_are_accepted() {
        // Le projet est en français, mais `/backup` et `/todo` sont ce qu'on tape par
        // réflexe — et les refuser n'apprend rien à personne.
        assert_eq!(Route::from_str("/backup").expect("r"), Route::Sauvegardes);
        assert_eq!(Route::from_str("/todo").expect("r"), Route::AFaire);
        assert_eq!(Route::from_str("/audit").expect("r"), Route::Journal);
        assert_eq!(Route::from_str("/users").expect("r"), Route::Comptes);
    }

    #[test]
    fn an_unknown_route_only_suggests_screens_that_exist() {
        // Un « route inconnue » nu oblige à lire le code source pour savoir quoi taper.
        // Et suggérer un écran non écrit serait pire : on suivrait la suggestion, on
        // n'aurait rien, et on douterait du message.
        let e = Route::from_str("/nimportequoi").expect_err("devrait échouer");
        let m = e.to_string();
        assert!(m.contains("/apps"), "{m}");
        for r in Route::plan_admin() {
            if !r.implemente() {
                assert!(
                    !m.contains(&r.to_string()),
                    "« {r} » est suggéré sans exister : {m}"
                );
            }
        }
    }

    #[test]
    fn signup_is_reachable_only_by_link() {
        // 🔴 L'inscription est écrite, et pourtant ABSENTE de toute navigation — c'est
        // voulu, et ça mérite d'être verrouillé. Une entrée « Inscription » dans la
        // barre latérale s'afficherait à des gens qui ont déjà un compte, et mènerait à
        // un écran qui leur dit qu'il leur manque une invitation.
        //
        // Elle s'atteint par `#invitation=…`, et seulement comme ça.
        assert!(Route::Inscription.implemente());
        assert!(!Route::plan_admin().contains(&Route::Inscription));
        assert!(!Route::plan_portail().contains(&Route::Inscription));
    }

    #[test]
    fn every_written_screen_is_reachable_by_clicking() {
        // 🔴 L'écran des secrets existait et n'était dans aucune navigation : on ne
        // pouvait l'atteindre qu'en tapant l'URL à la main. Un écran écrit et
        // inatteignable est du travail perdu que personne ne remarque.
        let offerts: Vec<Route> = Route::plan_admin()
            .into_iter()
            .chain(Route::plan_portail())
            .collect();
        for r in [
            Route::TableauDeBord,
            Route::Apps,
            Route::Noeuds,
            Route::Alertes,
            Route::Sauvegardes,
            Route::AFaire,
            Route::Journal,
            Route::Secrets,
            Route::Reglages,
            Route::Statut,
        ] {
            assert!(r.implemente(), "{:?}", r);
            assert!(
                offerts.contains(&r),
                "« {} » est écrit mais n'apparaît dans aucune navigation",
                r.libelle()
            );
        }
    }

    #[test]
    fn navigation_only_offers_screens_that_exist() {
        // 🔴 Une entrée qui mènerait à « à venir » promet, on clique, on n'a rien, et on
        // doute de tout le reste.
        for r in Route::navigation_admin().into_iter().chain(Route::navigation_portail()) {
            assert!(r.implemente(), "« {} » est proposé sans exister", r.libelle());
        }
        assert!(!Route::navigation_admin().is_empty());
    }

    #[test]
    fn the_portal_never_demands_console_rights() {
        // 🔴 Une entrée de portail qui exigerait `Lire` disparaîtrait pour ceux à qui
        // elle est destinée : les comptes sans rôle d'exploitation.
        use hlb_types::rbac::Action;
        for r in Route::plan_portail() {
            let a = r.exige();
            assert!(
                matches!(a, Action::LireSoi | Action::AgirSurSoi),
                "{} exige {a:?}, que n'a pas un simple utilisateur",
                r.libelle()
            );
            assert!(hlb_types::Role::Utilisateur.allows(a));
        }
    }

    #[test]
    fn admin_navigation_is_hidden_from_a_plain_user() {
        // Et réciproquement : aucune entrée de la console ne doit apparaître pour
        // quelqu'un qui n'a qu'un compte, sinon chaque clic mène à un 403.
        for r in Route::plan_admin() {
            assert!(
                !hlb_types::Role::Utilisateur.allows(r.exige()),
                "« {} » serait visible depuis le portail",
                r.libelle()
            );
        }
    }

    #[test]
    fn every_navigation_entry_has_a_label_that_fits_a_phone() {
        // Les libellés longs poussaient les dernières entrées hors de l'écran, et on ne
        // pouvait plus les atteindre du tout.
        for r in Route::plan_admin().into_iter().chain(Route::plan_portail()) {
            let c = r.libelle_court();
            assert!(!c.is_empty(), "{r:?}");
            assert!(c.chars().count() <= 10, "« {c} » est trop long pour une barre basse");
        }
    }

    #[test]
    fn no_route_label_needs_a_glyph_egui_might_not_have() {
        // Même invariant que partout ailleurs : un « ● » dans un libellé de navigation
        // s'afficherait en carré vide.
        for r in Route::plan_admin().into_iter().chain(Route::plan_portail()) {
            for s in [r.libelle(), r.libelle_court()] {
                for c in s.chars() {
                    assert!(
                        crate::design::glyphes::sur(c),
                        "U+{:04X} dans « {s} »",
                        c as u32
                    );
                }
            }
        }
    }
}
