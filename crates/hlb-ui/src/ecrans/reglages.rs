//! Les réglages : marque, thème.
//!
//! ## Pourquoi l'aperçu est à côté de l'édition
//!
//! Changer une couleur et devoir naviguer ailleurs pour voir l'effet oblige à faire
//! l'aller-retour dix fois. Les trois voyants d'état sont donc peints juste sous
//! l'éditeur — et c'est aussi là qu'on voit immédiatement si un accent entre en
//! concurrence avec eux.

use hlb_api::Attention;

use crate::design::{composants as c, mesures, Theme};

/// Ce que l'écran demande.
pub enum Demande {
    /// Choisir un thème. `None` = revenir à celui de l'installation.
    Theme(Option<String>),
}

pub fn afficher(ui: &mut egui::Ui, preferences: Option<&hlb_api::Preferences>) -> Option<Demande> {
    let p = c::palette(ui);
    let mut demande = None;

    c::titre(ui, "Réglages");
    ui.add_space(mesures::ESPACE);

    c::carte(ui, |ui| {
        c::sous_titre(ui, "Votre thème");
        ui.add_space(mesures::ESPACE_SERRE);
        c::legende(
            ui,
            "Ce choix vous suit sur tous vos appareils : il est enregistré côté \
             serveur, pas dans ce navigateur.",
        );
        ui.add_space(mesures::ESPACE);

        let Some(prefs) = preferences else {
            c::legende(ui, "chargement…");
            return;
        };

        ui.horizontal_wrapped(|ui| {
            // 🔴 « Celui de l'installation » est une option À PART, pas l'absence de
            // choix : la personne qui la sélectionne dit « suivez la marque », et son
            // thème changera si l'administrateur change le défaut. C'est différent
            // d'avoir figé la même valeur.
            let suit_defaut = prefs.theme.is_none();
            let libelle = match &prefs.defaut {
                Some(d) => format!("celui de l'installation ({d})"),
                None => "celui de l'installation".to_string(),
            };
            if ui.selectable_label(suit_defaut, libelle).clicked() && !suit_defaut {
                demande = Some(Demande::Theme(None));
            }

            for t in &prefs.disponibles {
                let actif = prefs.theme.as_deref() == Some(t.as_str());
                if ui.selectable_label(actif, t).clicked() && !actif {
                    demande = Some(Demande::Theme(Some(t.clone())));
                }
            }
        });
    });

    ui.add_space(mesures::ESPACE);

    c::carte(ui, |ui| {
        c::sous_titre(ui, "Apparence");
        ui.add_space(mesures::ESPACE_SERRE);
        c::legende(
            ui,
            "La marque et le thème vivent côté serveur : les changer ne demande pas de \
             recompiler l'interface, et ils suivent sur tous les appareils.",
        );
        ui.add_space(mesures::ESPACE);

        // ⚠️ L'édition passe par PUT /api/apparence et exige le rôle `operator`. Tant
        // que l'écran de formulaire n'est pas écrit, on dit la commande plutôt que
        // d'afficher des champs qui ne serviraient à rien.
        c::mono(ui, "hlb config apparence --nom \"Turi Industries\"");
    });

    ui.add_space(mesures::ESPACE);

    c::carte(ui, |ui| {
        c::sous_titre(ui, "Thèmes livrés");
        ui.add_space(mesures::ESPACE_SERRE);
        for t in Theme::livres() {
            ui.horizontal(|ui| {
                // Un aperçu peint : les trois pastilles telles qu'elles seraient dans
                // ce thème. Voir vaut mieux que lire un nom de couleur.
                for (a, teinte) in [
                    (Attention::Ok, t.palette.ok),
                    (Attention::Notice, t.palette.attention),
                    (Attention::Critical, t.palette.critique),
                ] {
                    let _ = a;
                    pastille_de(ui, teinte);
                }
                ui.add_space(mesures::ESPACE_SERRE);
                pastille_de(ui, t.palette.accent);
                ui.add_space(mesures::ESPACE);
                c::texte_libre(ui, &t.nom);
            });
        }
    });

    ui.add_space(mesures::ESPACE);

    c::carte(ui, |ui| {
        c::sous_titre(ui, "Lisibilité");
        ui.add_space(mesures::ESPACE_SERRE);
        c::legende(
            ui,
            "Un thème n'a pas le droit de rendre les états indistincts. Chaque palette \
             est validée : contraste du texte, et distinction des trois voyants en \
             vision deutéranope, qui concerne environ 8 % des hommes.",
        );
        ui.add_space(mesures::ESPACE_SERRE);

        // Le résultat de la validation, ici même : un thème refusé doit se voir dans
        // l'écran qui le propose, pas seulement dans les tests.
        for t in Theme::livres() {
            let pbs = t.palette.valider();
            ui.horizontal(|ui| {
                c::pastille(
                    ui,
                    if pbs.is_empty() {
                        Attention::Ok
                    } else {
                        Attention::Critical
                    },
                );
                ui.add_space(mesures::ESPACE_SERRE);
                c::texte_libre(
                    ui,
                    &if pbs.is_empty() {
                        format!("{} : lisible", t.nom)
                    } else {
                        format!(
                            "{} : {}",
                            t.nom,
                            hlb_api::plural(pbs.len() as u64, "problème", "problèmes")
                        )
                    },
                );
            });
            for pb in &pbs {
                c::legende(ui, &format!("   {}", pb.describe()));
            }
        }
        let _ = p;
    });

    demande
}

/// Un rond de couleur, peint : sert d'échantillon.
fn pastille_de(ui: &mut egui::Ui, teinte: egui::Color32) {
    let taille = 12.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(taille, taille), egui::Sense::hover());
    ui.painter()
        .circle_filled(rect.center(), taille * 0.4, teinte);
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_settings_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("reglages.rs");
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
