//! Chaque écran se rend-il vraiment ? (lot 12.1)
//!
//! ## 🔴 Ce que ces tests attrapent, et que rien d'autre ne voit
//!
//! Un écran peut compiler parfaitement et **paniquer au rendu** : un index hors bornes
//! dans une boucle d'affichage, une division par zéro dans un calcul de jauge, un
//! `expect` sur une donnée absente. Rien ne le signale avant qu'on ouvre l'écran — et
//! sur vingt écrans, celui qui casse est rarement celui qu'on regarde en développant.
//!
//! ## ⚠️ Ce ne sont PAS des instantanés d'images
//!
//! Le plan (§12.1) prévoyait `egui_kittest`. Essayé : la variante qui compare des
//! images exige un rendu GPU (`wgpu`), et la variante légère active la fonction
//! `accesskit` d'egui, ce qui casse la compilation d'`egui-winit` 0.33.3 — un décalage
//! de version en amont, pas un défaut d'ici.
//!
//! Le contexte egui tourne de toute façon sans fenêtre : `Context::run` suffit, sans
//! aucune dépendance de plus. On y perd la comparaison pixel à pixel, on y gagne de ne
//! pas avoir d'images de référence à tenir à jour — et les défauts purement visuels de
//! ce chantier (un swap peint en vert, des cartes en escalier, un trou dans une phrase)
//! se sont **tous** trouvés en regardant l'écran, jamais en comparant deux images.

use hlb_ui::route::Route;

/// Rend un écran une fois, hors écran, et rend `true` s'il n'a pas paniqué.
fn rendre(route: &Route, largeur: f32) {
    let ctx = egui::Context::default();

    let entree = egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(
            egui::Pos2::ZERO,
            egui::vec2(largeur, 900.0),
        )),
        ..Default::default()
    };

    // La sortie ne nous intéresse pas : ce test vérifie que le rendu ABOUTIT, pas ce
    // qu'il produit — c'est en regardant l'écran qu'on juge le reste.
    let _ = ctx.run(entree, |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            // 🔴 On passe par le dispatcher RÉEL, pas par une fonction d'écran choisie
            // à la main : un écran atteignable mais oublié dans la liste du test ne
            // serait pas couvert, et c'est exactement l'oubli qu'on cherche.
            hlb_ui::ecrans::rendu_a_vide(ui, route);
        });
    });
}

#[test]
fn every_reachable_screen_renders_without_data() {
    // ⚠️ Sans données, chaque écran doit afficher son état vide — pas paniquer. C'est
    // l'état réel au premier affichage, et celui qu'on voit quand le controller tombe.
    // C'est aussi celui que personne ne regarde en développant, parce qu'on a toujours
    // le mode démonstration sous la main.
    let ecrans: Vec<Route> = Route::plan_admin()
        .into_iter()
        .chain(Route::plan_portail())
        .chain(std::iter::once(Route::Inscription))
        .filter(Route::implemente)
        .collect();

    assert!(
        ecrans.len() > 10,
        "la liste des écrans a fondu : {ecrans:?}"
    );

    for route in ecrans {
        rendre(&route, 1200.0);
    }
}

#[test]
fn the_narrow_layout_renders_too() {
    // La disposition étroite a ses propres cartes et sa propre barre : elle casse
    // indépendamment, et personne ne la regarde en développant sur un écran large.
    for route in Route::plan_admin().into_iter().filter(Route::implemente) {
        rendre(&route, 360.0);
    }
}

#[test]
fn an_app_detail_renders_for_every_tab() {
    // Les onglets d'une app sont atteignables par URL : chacun doit tenir debout seul,
    // y compris sur une app dont on n'a encore rien reçu.
    for onglet in hlb_ui::route::OngletApp::tous() {
        rendre(
            &Route::App {
                nom: "gitea".into(),
                onglet,
            },
            1200.0,
        );
    }
}
