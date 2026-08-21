//! La frise chronologique unifiée (lot 9.5).
//!
//! ## 🔴 Ce que seule une frise permet
//!
//! « L'app est tombée à 3 h 12 » vit dans un tableau, « mise à jour appliquée à 3 h 10 »
//! dans un autre. Les rapprocher demande d'ouvrir deux écrans et de comparer des heures
//! à la main — au moment précis où l'on est pressé. Une seule rivière datée les met
//! côte à côte, et la corrélation saute aux yeux au lieu de se chercher.

use egui::{Align, Layout};
use hlb_api::{Attention, Evenement};

use crate::client::Freshness;
use crate::design::{composants as c, mesures};

pub fn afficher(
    ui: &mut egui::Ui,
    evenements: Option<&Vec<Evenement>>,
    maintenant: i64,
    fraicheur: &Freshness,
) {
    c::titre(ui, "Chronologie");
    ui.add_space(mesures::ESPACE_SERRE);

    let Some(liste) = evenements else {
        c::etat_vide(ui, &fraicheur.describe(), None);
        return;
    };

    if liste.is_empty() {
        c::etat_vide(
            ui,
            "Rien d'enregistré pour l'instant : ni sauvegarde, ni action.",
            None,
        );
        return;
    }

    c::legende(
        ui,
        "Sauvegardes et actions dans une seule rivière datée. C'est ici qu'une panne se \
         rapproche de ce qui l'a précédée.",
    );
    ui.add_space(mesures::ESPACE);

    // Un séparateur par jour : sans lui, une frise de deux cents lignes devient un mur
    // d'heures sans repère.
    let mut jour_courant: Option<i64> = None;

    for e in liste {
        let jour = e.quand.div_euclid(86_400);
        if jour_courant != Some(jour) {
            jour_courant = Some(jour);
            ui.add_space(mesures::ESPACE_SERRE);
            c::legende(ui, &libelle_jour(maintenant, e.quand));
            ui.add_space(mesures::ESPACE_SERRE);
        }

        c::carte_attention(ui, e.attention, |ui| {
            ui.horizontal(|ui| {
                c::pastille(ui, e.attention);
                ui.add_space(mesures::ESPACE_SERRE);
                c::mono(ui, &heure(e.quand));
                ui.add_space(mesures::ESPACE_SERRE);
                c::texte_libre(ui, &e.cible);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    c::legende(ui, e.genre.libelle());
                });
            });
            if e.attention != Attention::Ok || !e.quoi.is_empty() {
                ui.add_space(mesures::ESPACE_SERRE);
                c::legende(ui, &e.quoi);
            }
        });
        ui.add_space(mesures::ESPACE_SERRE);
    }
}

/// « aujourd'hui », « hier », ou l'âge en jours.
///
/// ⚠️ Pas de date absolue : le fuseau de l'utilisateur n'est pas connu ici, et afficher
/// une date UTC comme si elle était locale décalerait les événements du soir d'un jour.
fn libelle_jour(maintenant: i64, quand: i64) -> String {
    let jours = maintenant.div_euclid(86_400) - quand.div_euclid(86_400);
    match jours {
        j if j <= 0 => "aujourd'hui".into(),
        1 => "hier".into(),
        j => format!("il y a {j} jours"),
    }
}

/// L'heure du jour, en UTC — la même que celle des journaux du serveur.
fn heure(quand: i64) -> String {
    let s = quand.rem_euclid(86_400);
    format!("{:02}:{:02}", s / 3_600, (s % 3_600) / 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_day_label_never_shows_a_date_in_the_wrong_timezone() {
        // Un fuseau inconnu rendrait « 19 août » faux d'un jour pour les événements du
        // soir. Un âge relatif est juste partout.
        let minuit = 1_787_097_600; // 2026-08-19 00:00 UTC
        assert_eq!(libelle_jour(minuit, minuit), "aujourd'hui");
        assert_eq!(libelle_jour(minuit, minuit - 86_400), "hier");
        assert_eq!(libelle_jour(minuit, minuit - 5 * 86_400), "il y a 5 jours");
    }

    #[test]
    fn the_hour_is_read_from_the_timestamp_alone() {
        assert_eq!(heure(1_787_097_600), "00:00");
        assert_eq!(heure(1_787_097_600 + 3 * 3_600 + 12 * 60), "03:12");
    }

    #[test]
    fn no_timeline_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("frise.rs");
        for (n, ligne) in src.lines().enumerate() {
            for ch in ligne.split("//").next().unwrap_or("").chars() {
                assert!(
                    crate::design::glyphes::sur(ch),
                    "ligne {} : U+{:04X}",
                    n + 1,
                    ch as u32
                );
            }
        }
    }
}
