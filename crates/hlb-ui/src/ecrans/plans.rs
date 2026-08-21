//! Les plans préparés à froid (lot 10.4, §9quater).
//!
//! ## 🔴 Pourquoi ranger un plan plutôt que le refaire
//!
//! Une opération se prépare quand on a le temps de lire, et s'exécute à l'heure creuse.
//! Tout décider et tout exécuter dans la même minute est exactement la façon dont on se
//! trompe de cible.
//!
//! ## Ce qui est rejoué
//!
//! La requête telle qu'elle a été **prévisualisée**, jamais recalculée. Deux calculs à
//! deux instants différents peuvent diverger — une app installée entre-temps, un
//! domaine changé — et l'on exécuterait alors autre chose que ce qu'on a relu.
//!
//! ⚠️ Rejouer relance l'**aperçu**, pas l'exécution : le plan rangé décrit peut-être un
//! cluster qui a changé, et c'est le nouvel aperçu qui le dira.

use hlb_api::PlanNomme;

use crate::client::Freshness;
use crate::design::{composants as c, mesures};

/// Ce que l'écran demande.
pub enum Demande {
    /// Rejouer un plan : relance son aperçu.
    Rejouer(PlanNomme),
}

pub fn afficher(
    ui: &mut egui::Ui,
    plans: Option<&Vec<PlanNomme>>,
    fraicheur: &Freshness,
) -> Option<Demande> {
    let mut demande = None;

    c::titre(ui, "Plans préparés");
    ui.add_space(mesures::ESPACE_SERRE);

    let Some(liste) = plans else {
        c::etat_vide(ui, &fraicheur.describe(), None);
        return None;
    };

    if liste.is_empty() {
        c::etat_vide(
            ui,
            "Aucun plan préparé. Prévisualise une action, puis range-la sous un nom \
             pour l'exécuter plus tard.",
            None,
        );
        return None;
    }

    c::legende(
        ui,
        "Chaque plan est rangé tel qu'il a été prévisualisé. Le rejouer relance son \
         aperçu — pas l'exécution : ce qu'il décrit a pu changer depuis.",
    );
    ui.add_space(mesures::ESPACE);

    for p in liste {
        c::carte_attention(ui, p.attention(), |ui| {
            ui.horizontal(|ui| {
                c::pastille(ui, p.attention());
                ui.add_space(mesures::ESPACE_SERRE);
                c::texte_libre(ui, &p.nom);
                ui.with_layout(
                    egui::Layout::right_to_left(egui::Align::Center),
                    |ui| {
                        c::legende(
                            ui,
                            &format!(
                                "par {} il y a {}",
                                p.cree_par,
                                hlb_api::humanise(p.age_s)
                            ),
                        );
                    },
                );
            });

            ui.add_space(mesures::ESPACE_SERRE);
            // Le résumé lu au moment de l'enregistrement : c'est CE texte qui a été
            // approuvé, et pas une reformulation d'aujourd'hui.
            c::texte_libre(ui, &p.resume);
            ui.add_space(mesures::ESPACE_SERRE);
            c::mono(ui, &format!("{} {}", p.methode, p.chemin));

            if let Some(garde) = p.mise_en_garde() {
                ui.add_space(mesures::ESPACE_SERRE);
                c::legende(ui, &garde);
            }

            ui.add_space(mesures::ESPACE_SERRE);
            if ui.button("Revoir l'aperçu").clicked() {
                demande = Some(Demande::Rejouer(p.clone()));
            }
        });
        ui.add_space(mesures::ESPACE_SERRE);
    }

    demande
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_plan_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("plans.rs");
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
