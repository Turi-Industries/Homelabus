//! Le mode kiosque (lot 11.4).
//!
//! ## À quoi ça sert
//!
//! Un écran mural qui tourne en boucle sur l'état du cluster. Pas d'interaction, pas de
//! navigation : on le regarde en passant, et on voit tout de suite si quelque chose ne
//! va pas.
//!
//! ## 🔴 Un écran mural est visible par TOUT LE MONDE
//!
//! Quiconque passe dans la pièce le voit — un invité, un livreur, quelqu'un qui filme.
//! Les écrans qui portent des secrets, des comptes, des jetons ou le journal d'audit en
//! sont donc **exclus par construction**, et pas seulement absents de la rotation :
//! `Route::convient_au_kiosque` décide, et un test croise cette fonction avec la liste
//! complète des écrans pour qu'un écran ajouté demain ne s'y invite pas par défaut.

use crate::route::Route;

/// Combien de temps chaque écran reste affiché, en secondes.
///
/// ⚠️ Assez long pour qu'on ait le temps de LIRE en passant : un défilement rapide
/// donne l'impression que ça bouge et n'informe de rien.
pub const DUREE_ECRAN_S: f64 = 20.0;

/// La rotation, dans l'ordre d'affichage.
///
/// Le tableau de bord d'abord et le plus souvent : c'est lui qui répond à « est-ce que
/// quelque chose ne va pas ? ».
pub fn rotation() -> Vec<Route> {
    Route::plan_admin()
        .into_iter()
        .filter(Route::implemente)
        .filter(convient_au_kiosque)
        .collect()
}

/// Cet écran peut-il s'afficher sur un mur ?
///
/// 🔴 Liste BLANCHE de ce qui est sûr, jamais liste noire de ce qui ne l'est pas : on
/// ne peut pas énumérer tout ce qui sera sensible demain, on peut énumérer ce qui est
/// anodin aujourd'hui. Un écran ajouté plus tard est donc exclu par défaut.
pub fn convient_au_kiosque(r: &Route) -> bool {
    matches!(
        r,
        Route::TableauDeBord
            | Route::Apps
            | Route::Alertes
            | Route::Noeuds
            | Route::Topologie
            | Route::Sauvegardes
            | Route::Derive
    )
}

/// L'écran à afficher, d'après le temps écoulé.
///
/// ⚠️ Rend `None` quand la rotation est vide plutôt que de retomber sur un écran
/// arbitraire : mieux vaut un message que le mauvais écran affiché en boucle.
pub fn ecran_courant(secondes: f64) -> Option<Route> {
    let r = rotation();
    if r.is_empty() {
        return None;
    }
    let index = ((secondes / DUREE_ECRAN_S) as usize) % r.len();
    r.get(index).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_screen_carrying_secrets_ever_reaches_the_wall() {
        // 🔴 Un écran mural est visible par quiconque passe dans la pièce. Les secrets,
        // les comptes, les jetons et le journal d'audit n'y ont rien à faire — même
        // sans valeur affichée, la liste des noms de secrets est une carte de
        // l'installation.
        for interdit in [
            Route::Secrets,
            Route::Comptes,
            Route::Journal,
            Route::Securite,
            Route::Reglages,
            Route::Plans,
        ] {
            assert!(
                !convient_au_kiosque(&interdit),
                "« {} » ne doit jamais s'afficher sur un mur",
                interdit.libelle()
            );
            assert!(!rotation().contains(&interdit));
        }
    }

    #[test]
    fn a_screen_added_tomorrow_is_excluded_by_default() {
        // 🔴 Liste BLANCHE : on ne peut pas énumérer ce qui sera sensible demain, on
        // peut énumérer ce qui est anodin aujourd'hui. Ce test échouera si quelqu'un
        // transforme la règle en liste noire — auquel cas un écran nouveau passerait.
        let admis: Vec<Route> = Route::plan_admin()
            .into_iter()
            .filter(convient_au_kiosque)
            .collect();
        let tous = Route::plan_admin().len();
        assert!(
            admis.len() < tous,
            "tous les écrans sont admis : la règle n'est plus une liste blanche"
        );
    }

    #[test]
    fn the_rotation_only_offers_screens_that_exist() {
        // Un écran non implémenté afficherait un vide en boucle sur un mur, et l'on
        // croirait le système en panne.
        for r in rotation() {
            assert!(r.implemente(), "« {} » n'est pas écrit", r.libelle());
        }
        assert!(!rotation().is_empty());
    }

    #[test]
    fn the_rotation_cycles_without_ever_landing_nowhere() {
        // ⚠️ Un index qui déborde ferait disparaître l'affichage au bout de quelques
        // minutes, ce que personne ne verrait tout de suite sur un mur.
        let n = rotation().len();
        for tour in 0..(n * 3) {
            let t = tour as f64 * DUREE_ECRAN_S + 0.5;
            assert!(ecran_courant(t).is_some(), "trou à {t} s");
        }
        // Et le cycle revient bien au début.
        assert_eq!(ecran_courant(0.0), ecran_courant(n as f64 * DUREE_ECRAN_S));
    }

    #[test]
    fn a_full_cycle_stays_short_enough_to_be_worth_waiting_for() {
        // Deux contraintes opposées : assez lent pour qu'on LISE en passant, assez
        // rapide pour qu'un tour complet ne dure pas dix minutes — au-delà, l'écran
        // qu'on cherche n'est jamais celui qui est affiché.
        let tour = rotation().len() as f64 * DUREE_ECRAN_S;
        assert!(tour <= 180.0, "un tour complet dure {tour} s");
        assert!(tour >= 60.0, "un tour complet ne dure que {tour} s");
    }
}
