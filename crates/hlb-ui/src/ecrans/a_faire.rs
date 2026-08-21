//! Les actions manuelles en attente (§4.6).
//!
//! ## Les bloquantes d'abord
//!
//! Un guide bloquant arrête un déploiement : tant qu'il n'est pas fait, l'app ne part
//! pas. Le mettre après trois conseils facultatifs ferait chercher pourquoi rien ne se
//! passe.
//!
//! ## 🔴 Un guide vérifié est une ATTESTATION, pas une case cochée
//!
//! Cocher « fait » sans l'avoir fait débloque un déploiement qui échouera plus loin,
//! avec un message sans rapport. L'écran le dit ; c'est le seul garde-fou possible,
//! Homelabus ne pouvant pas vérifier qu'un enregistrement DNS existe vraiment.

use hlb_api::GuideItem;

use crate::design::{composants as c, mesures};

pub const ACK_EST_UNE_ATTESTATION: &str =
    "Marquer une action « faite » est une attestation, pas une case à cocher. \
     La cocher sans l'avoir faite débloque un déploiement qui échouera plus loin, \
     avec un message sans rapport avec la cause.";

pub fn afficher(
    ui: &mut egui::Ui,
    items: &[GuideItem],
    sante: Option<&Vec<hlb_api::ControleSante>>,
    etroit: bool,
) {
    let p = c::palette(ui);

    let mut v = items.to_vec();
    // Les bloquantes d'abord, puis par app pour rester stable d'une image à l'autre.
    v.sort_by_key(|g| (!g.blocking, g.app.clone(), g.id.clone()));

    let bloquants = v.iter().filter(|g| g.blocking).count();

    c::titre(ui, "À faire");
    ui.add_space(mesures::ESPACE_SERRE);

    if v.is_empty() {
        c::etat_vide(
            ui,
            "Aucune action manuelle en attente.",
            Some("hlb guide list"),
        );
        return;
    }

    if bloquants > 0 {
        c::bandeau(
            ui,
            p.attention,
            &format!(
                "{} bloque{} un déploiement.",
                hlb_api::plural(bloquants as u64, "action", "actions"),
                if bloquants > 1 { "nt" } else { "" }
            ),
            Some(ACK_EST_UNE_ATTESTATION),
        );
    } else {
        c::legende(ui, ACK_EST_UNE_ATTESTATION);
    }
    ui.add_space(mesures::ESPACE);

    for g in &v {
        let teinte = if g.blocking {
            p.attention
        } else {
            p.texte_faible
        };
        c::carte(ui, |ui| {
            ui.horizontal(|ui| {
                c::badge(ui, &g.app, teinte);
                ui.add_space(mesures::ESPACE_SERRE);
                ui.vertical(|ui| {
                    c::texte_libre(ui, &g.title);
                    if !etroit {
                        c::mono(ui, &format!("hlb guide verify {} {}", g.app, g.id));
                    }
                });
            });
            if g.blocking {
                ui.add_space(mesures::ESPACE_SERRE);
                c::badge(ui, "bloquante", p.attention);
            }
        });
        ui.add_space(mesures::ESPACE_SERRE);
    }
    if let Some(controles) = sante {
        if !controles.is_empty() {
            ui.add_space(mesures::ESPACE_LARGE);
            c::sous_titre(ui, "Santé de l'installation");
            ui.add_space(mesures::ESPACE_SERRE);
            c::legende(
                ui,
                "Les choses qu'on croit faites et qu'on n'a jamais vérifiées. Aucune \
                 ne bloque quoi que ce soit — elles se découvrent au pire moment.",
            );
            ui.add_space(mesures::ESPACE_SERRE);

            for ctl in controles {
                c::carte_attention(ui, ctl.attention, |ui| {
                    ui.horizontal(|ui| {
                        c::pastille(ui, ctl.attention);
                        ui.add_space(mesures::ESPACE_SERRE);
                        c::texte_libre(ui, &ctl.titre);
                    });
                    ui.add_space(mesures::ESPACE_SERRE);
                    c::legende(ui, &ctl.constat);
                    if let Some(r) = &ctl.remede {
                        ui.add_space(mesures::ESPACE_SERRE);
                        c::mono(ui, r);
                    }
                });
                ui.add_space(mesures::ESPACE_SERRE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(app: &str, id: &str, bloquant: bool) -> GuideItem {
        GuideItem {
            app: app.into(),
            id: id.into(),
            title: "Faire quelque chose".into(),
            blocking: bloquant,
        }
    }

    #[test]
    fn blocking_guides_come_before_the_others() {
        // Un guide bloquant arrête un déploiement. Le mettre après trois conseils
        // facultatifs ferait chercher pourquoi rien ne se passe.
        let mut v = [
            g("aaa", "conseil", false),
            g("zzz", "dns", true),
            g("bbb", "autre", false),
        ];
        v.sort_by_key(|x| (!x.blocking, x.app.clone(), x.id.clone()));
        assert_eq!(v[0].app, "zzz");
        assert!(v[0].blocking);
    }

    #[test]
    fn the_attestation_wording_says_what_goes_wrong() {
        // « Confirmez-vous ? » n'apprend rien. Le message doit nommer la conséquence.
        assert!(ACK_EST_UNE_ATTESTATION.contains("attestation"));
        assert!(ACK_EST_UNE_ATTESTATION.contains("échouera"));
    }

    #[test]
    fn no_todo_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("a_faire.rs");
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
