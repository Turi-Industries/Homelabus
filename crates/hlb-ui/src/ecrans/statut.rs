//! La page de statut : ce qui marche, ce qui ne marche pas.
//!
//! ## Ce qu'elle apporte qu'aucune sonde ne voit
//!
//! Un service peut répondre parfaitement et mal fonctionner — Immich qui met huit
//! secondes à afficher une photo répond `200`. C'est un **incident déclaré** qui le dit,
//! et c'est pourquoi cette page mêle l'état mesuré et ce que les humains ont constaté.
//!
//! ## 🔴 Privée par défaut
//!
//! Publiée, elle révèle la liste de ce qui tourne chez vous et le calendrier de vos
//! pannes. L'écran le rappelle quand elle est ouverte : ce n'est pas une case à cocher
//! anodine.

use egui::{Align, Layout};
use hlb_api::{Attention, EtatService, PageStatut};

use crate::client::Freshness;
use crate::design::{composants as c, mesures};

pub fn afficher(ui: &mut egui::Ui, statut: Option<&PageStatut>, fraicheur: &Freshness) {
    let p = c::palette(ui);

    c::titre(ui, "Statut des services");
    ui.add_space(mesures::ESPACE_SERRE);

    let Some(v) = statut else {
        c::etat_vide(ui, &fraicheur.describe(), None);
        return;
    };

    let att = v.attention();
    c::bandeau(ui, p.attention_de(att), &v.verdict(), None);
    ui.add_space(mesures::ESPACE);

    if v.publique {
        // ⚠️ Le rappel n'est pas décoratif : on oublie qu'une page est ouverte, et
        // c'est en général en la regardant qu'on s'en souvient.
        c::legende(
            ui,
            "Cette page est PUBLIQUE : elle montre vos services exposés et vos incidents \
             en cours à qui connaît l'adresse.",
        );
        ui.add_space(mesures::ESPACE);
    }

    // Les incidents d'abord : c'est ce qu'on vient lire quand quelque chose cloche.
    if !v.incidents.is_empty() {
        c::sous_titre(ui, "Incidents en cours");
        ui.add_space(mesures::ESPACE_SERRE);
        for i in &v.incidents {
            c::carte_attention(ui, Attention::Critical, |ui| {
                c::sous_titre(ui, &i.titre);
                ui.add_space(mesures::ESPACE_SERRE);
                c::texte_libre(ui, &i.corps);
                for m in &i.suivi {
                    ui.add_space(mesures::ESPACE_SERRE);
                    ui.horizontal(|ui| {
                        ui.add_space(mesures::ESPACE);
                        ui.vertical(|ui| {
                            c::legende(ui, &m.at);
                            c::texte_libre(ui, &m.corps);
                        });
                    });
                }
            });
            ui.add_space(mesures::ESPACE_SERRE);
        }
        ui.add_space(mesures::ESPACE);
    }

    c::sous_titre(ui, "Services");
    ui.add_space(mesures::ESPACE_SERRE);

    if v.services.is_empty() {
        c::etat_vide(ui, "Aucun service exposé.", None);
        return;
    }

    c::carte(ui, |ui| {
        for s in &v.services {
            let a = s.etat.attention();
            ui.horizontal(|ui| {
                c::pastille(ui, a);
                ui.add_space(mesures::ESPACE_SERRE);
                ui.vertical(|ui| {
                    c::texte_libre(ui, &s.nom);
                    if let Some(d) = &s.domaine {
                        c::mono(ui, d);
                    }
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    // 🔴 Le mot, pas seulement la couleur — et « maintenance prévue »
                    // se distingue d'une panne : c'était annoncé, et le dire évite
                    // qu'on cherche ce qui ne va pas.
                    ui.label(
                        egui::RichText::new(s.etat.libelle())
                            .size(c::taille::LEGENDE)
                            .color(p.attention_de(a)),
                    );
                });
            });
            ui.add_space(mesures::ESPACE_SERRE);
        }
    });

    let _ = EtatService::Operationnel;
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_status_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("statut.rs");
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
