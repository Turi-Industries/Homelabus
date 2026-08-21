//! La dérive : ce que la réconciliation a vu, et ce qu'elle a refusé de toucher.
//!
//! ## 🔴 Pourquoi cet écran existe
//!
//! La réconciliation ne supprime jamais un orphelin, ne ressuscite jamais une
//! installation en échec, et ne force jamais une convergence en cours. Ces refus
//! n'apparaissaient nulle part : ils partaient dans les journaux, et rien ne
//! distinguait « rien à faire » de « il y a quelque chose et j'ai délibérément choisi
//! de ne pas y toucher ».
//!
//! Les deux se ressemblent. La seconde, non expliquée, fait douter du système — on
//! finit par corriger à la main ce qu'il protégeait, ou par croire qu'il n'a rien vu.
//!
//! ## Deux sections, jamais mélangées
//!
//! Les écarts **corrigibles** seront repris au prochain tour : ils informent. Les
//! **refus délibérés** sont des décisions : les peindre en rouge ferait chercher un
//! problème là où le système a fait exactement ce qu'il fallait.

use hlb_api::{Attention, EcartSummary};

use crate::client::Freshness;
use crate::design::{composants as c, mesures};

pub fn afficher(ui: &mut egui::Ui, ecarts: Option<&Vec<EcartSummary>>, fraicheur: &Freshness) {
    c::titre(ui, "Dérive");
    ui.add_space(mesures::ESPACE_SERRE);

    let Some(liste) = ecarts else {
        c::etat_vide(ui, &fraicheur.describe(), None);
        return;
    };

    if liste.is_empty() {
        // ⚠️ Une liste vide veut dire « l'état réel correspond à l'état voulu », ce qui
        // est une bonne nouvelle — pas un écran cassé. On le dit.
        c::etat_vide(
            ui,
            "Aucun écart : ce qui tourne correspond à ce qui a été décidé.",
            Some("hlb reconcile"),
        );
        return;
    }

    let (corrigibles, refus): (Vec<_>, Vec<_>) = liste.iter().partition(|e| e.corrigible);

    if !corrigibles.is_empty() {
        c::sous_titre(ui, "Sera corrigé au prochain tour");
        ui.add_space(mesures::ESPACE_SERRE);
        c::legende(
            ui,
            "La consigne Swarm vient d'une décision : elle se corrige. Ces écarts \
             n'appellent aucun geste.",
        );
        ui.add_space(mesures::ESPACE_SERRE);

        for e in &corrigibles {
            c::carte_attention(ui, Attention::Notice, |ui| {
                ui.horizontal_top(|ui| {
                    c::pastille(ui, Attention::Notice);
                    ui.add_space(mesures::ESPACE_SERRE);
                    c::texte_libre(ui, &e.description);
                });
            });
            ui.add_space(mesures::ESPACE_SERRE);
        }
        ui.add_space(mesures::ESPACE);
    }

    if !refus.is_empty() {
        c::sous_titre(ui, "Laissé tel quel, délibérément");
        ui.add_space(mesures::ESPACE_SERRE);
        c::legende(
            ui,
            "Un système qui corrige trop est plus dangereux qu'un système qui ne \
             corrige rien. Voici ce que Homelabus a vu et n'a pas touché, et pourquoi.",
        );
        ui.add_space(mesures::ESPACE_SERRE);

        for e in &refus {
            // 🔴 Peint en « Ok » : c'est une décision, pas une panne. Le rouge ferait
            // chercher un problème là où le système a fait ce qu'il fallait.
            c::carte_attention(ui, Attention::Ok, |ui| {
                ui.horizontal_top(|ui| {
                    c::pastille(ui, Attention::Ok);
                    ui.add_space(mesures::ESPACE_SERRE);
                    c::texte_libre(ui, &e.description);
                });
                if let Some(r) = &e.refus {
                    ui.add_space(mesures::ESPACE_SERRE);
                    c::legende(ui, r);
                }
            });
            ui.add_space(mesures::ESPACE_SERRE);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_drift_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("derive.rs");
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
