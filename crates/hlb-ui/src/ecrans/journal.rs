//! Le journal d'audit (§9ter).
//!
//! ## 🔴 Un refus n'est PAS un échec
//!
//! « refused » veut dire que le système a protégé l'utilisateur : un rôle insuffisant,
//! une confirmation manquante, un garde-fou qui a joué. « failed » veut dire que
//! l'opération a été tentée et a cassé. Les afficher pareil rendrait le journal
//! inexploitable — on chercherait des pannes là où le système a bien travaillé.

use hlb_api::AuditItem;

use crate::design::{composants as c, mesures};

pub fn afficher(ui: &mut egui::Ui, items: &[AuditItem], etroit: bool) {
    let p = c::palette(ui);

    c::titre(ui, "Journal");
    c::legende(
        ui,
        "Append-only et chaîné : chaque entrée porte l'empreinte de la précédente. \
         Vérifier l'intégrité : hlb audit --verify",
    );
    ui.add_space(mesures::ESPACE);

    if items.is_empty() {
        c::etat_vide(ui, "Aucune action enregistrée.", Some("hlb audit"));
        return;
    }

    for e in items {
        let (mot, teinte) = verdict(e, &p);
        c::carte(ui, |ui| {
            ui.horizontal(|ui| {
                c::badge(ui, mot, teinte);
                ui.add_space(mesures::ESPACE_SERRE);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        c::texte_libre(ui, &format!("{} sur {}", e.action, e.target));
                    });
                    let qui = if e.role.is_empty() {
                        e.actor.clone()
                    } else {
                        format!("{} ({})", e.actor, e.role)
                    };
                    c::legende(ui, &format!("{} · {}", e.at, qui));
                    // Le diff : c'est ce que demandait le §9ter et qui manquait.
                    // Sans lui, « config modifiée » ne dit pas ce qui a changé.
                    if let Some(d) = &e.detail {
                        if !etroit {
                            c::mono(ui, d);
                        }
                    }
                });
            });
        });
        ui.add_space(mesures::ESPACE_SERRE);
    }
}

/// Le mot et la couleur d'une issue.
pub fn verdict(e: &AuditItem, p: &crate::design::Palette) -> (&'static str, egui::Color32) {
    if e.is_refusal() {
        // 🔴 Orange et non rouge, et le mot dit POURQUOI : c'est une protection qui a
        // joué, pas une panne à réparer.
        return ("refusé (protection)", p.attention);
    }
    if e.is_failure() {
        return ("échec", p.critique);
    }
    ("ok", p.ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(issue: &str) -> AuditItem {
        AuditItem {
            id: 1,
            at: "2026-08-18 10:00:00".into(),
            actor: "remy".into(),
            role: "admin".into(),
            action: "purge".into(),
            target: "gitea".into(),
            outcome: issue.into(),
            detail: None,
        }
    }

    #[test]
    fn a_refusal_is_never_shown_as_a_failure() {
        // 🔴 Les confondre ferait chercher des pannes là où le système a bien travaillé.
        let p = crate::design::Theme::turi_sombre().palette;
        let (mr, cr) = verdict(&e("refused"), &p);
        let (mf, cf) = verdict(&e("failed"), &p);
        let (mo, co) = verdict(&e("ok"), &p);

        assert_ne!(mr, mf);
        assert_ne!(cr, cf);
        assert!(mr.contains("protection"), "{mr}");
        assert_ne!(mo, mr);
        assert_ne!(co, cr);
    }

    #[test]
    fn no_journal_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("journal.rs");
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
