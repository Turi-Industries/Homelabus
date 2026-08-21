//! Le panneau d'action : aperçu, décision, résultat.
//!
//! ## 🔴 Pourquoi trois temps et pas deux
//!
//! Un bouton « installer » suivi d'une boîte de dialogue générique — « Confirmer ? » —
//! ne dit rien de ce qui va se passer. On clique par réflexe, et la protection ne
//! protège plus.
//!
//! Ici, la confirmation porte sur **le plan lui-même** : les onze actions que
//! l'installation va exécuter, les guides qui la bloquent, le volume qui sera conservé.
//! C'est ce que le §11bis appelle « un assistant guidé, avec aperçu de l'effet avant de
//! confirmer ».
//!
//! ## Et la commande équivalente, toujours affichée
//!
//! Le CLI reste la source de vérité. L'interface l'enseigne au lieu de s'y substituer,
//! l'action reste reproductible et scriptable — et l'on peut vérifier que l'interface
//! fait bien ce qu'on croit.

use egui::{Align, Layout, RichText};
use hlb_api::{Attention, EtatEtape, ResultatAction};

use crate::client::ActionEnCours;
use crate::design::{composants as c, mesures};

/// Ce que l'utilisateur a décidé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Appliquer pour de vrai.
    Appliquer,
    /// Ranger le plan sous un nom, pour l'exécuter plus tard (§10.4).
    Enregistrer(String),
    /// Fermer sans rien faire.
    Fermer,
}

/// Affiche le panneau, et rend la décision s'il y en a une.
pub fn panneau(ui: &mut egui::Ui, etat: &ActionEnCours) -> Option<Decision> {
    let p = c::palette(ui);
    let mut decision = None;

    if let Some(e) = etat.lire_erreur() {
        c::carte_attention(ui, Attention::Critical, |ui| {
            c::sous_titre(ui, "L'action n'a pas pu être lancée");
            c::texte_libre(ui, &e);
            if ui.button("Fermer").clicked() {
                decision = Some(Decision::Fermer);
            }
        });
        return decision;
    }

    // Le résultat l'emporte sur l'aperçu : une fois appliquée, c'est ce qui s'est passé
    // qui compte.
    let lien = etat.lire_lien();
    if let Some(r) = etat.lire_resultat() {
        return resultat(ui, &r, lien.as_deref(), p);
    }

    let a = etat.lire_apercu()?;
    apercu(ui, &a, etat.occupee(), p, &mut decision);
    decision
}

fn apercu(
    ui: &mut egui::Ui,
    a: &ResultatAction,
    occupee: bool,
    p: crate::design::Palette,
    decision: &mut Option<Decision>,
) {
    let att = if a.applicable() {
        Attention::Notice
    } else {
        Attention::Critical
    };

    c::carte_attention(ui, att, |ui| {
        c::sous_titre(ui, "Aperçu — rien n'a encore été modifié");
        ui.add_space(mesures::ESPACE_SERRE);
        c::texte_libre(ui, &a.resume);
        ui.add_space(mesures::ESPACE);

        if !a.etapes.is_empty() {
            c::legende(ui, "Ce qui sera fait, dans cet ordre :");
            ui.add_space(mesures::ESPACE_SERRE);
            for (i, e) in a.etapes.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("{:>2}.", i + 1))
                            .monospace()
                            .size(c::taille::LEGENDE)
                            .color(p.texte_faible),
                    );
                    c::texte_libre(ui, &e.description);
                });
            }
            ui.add_space(mesures::ESPACE);
        }

        // 🔴 Les blocages en évidence : ils disent pourquoi le bouton est inactif.
        // Un bouton grisé sans explication fait chercher un défaut d'interface.
        for b in &a.blocages {
            ui.horizontal(|ui| {
                c::pastille(ui, Attention::Critical);
                ui.add_space(mesures::ESPACE_SERRE);
                c::texte_libre(ui, b);
            });
        }

        // ⚠️ Les avertissements se distinguent des blocages, forme comprise : ce sont
        // des choses à savoir, pas des refus. Les peindre pareil ferait croire que
        // l'action est impossible — et on chercherait comment la débloquer.
        for a in &a.avertissements {
            ui.horizontal(|ui| {
                c::pastille(ui, Attention::Notice);
                ui.add_space(mesures::ESPACE_SERRE);
                c::texte_libre(ui, a);
            });
        }

        if let Some(cible) = &a.confirmation_requise {
            ui.add_space(mesures::ESPACE_SERRE);
            c::bandeau(
                ui,
                p.critique,
                "Opération destructive",
                Some(&format!(
                    "Appliquer confirmera explicitement « {cible} ». Le rôle ne suffit \
                     pas : répéter le nom est ce qui empêche de détruire la mauvaise cible.",
                )),
            );
        }

        // ⚠️ Vide quand l'action n'a même pas pu être planifiée. Afficher le libellé
        // au-dessus d'un blanc laisserait croire à un défaut d'affichage — et un
        // « équivalent en ligne de commande » qui n'équivaut à rien est pire que rien.
        if !a.commande_cli.is_empty() {
            ui.add_space(mesures::ESPACE);
            ui.horizontal(|ui| {
                c::legende(ui, "Équivalent en ligne de commande :");
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    // Le CLI reste la source de vérité : l'interface l'enseigne au lieu
                    // de s'y substituer, et l'action devient reproductible et
                    // scriptable.
                    if ui.small_button("Copier").clicked() {
                        ui.ctx().copy_text(a.commande_cli.clone());
                    }
                });
            });
            c::mono(ui, &a.commande_cli);
        }

        // 🔴 Préparer à froid, exécuter à l'heure creuse (§10.4). Tout décider et tout
        // exécuter dans la même minute est exactement la façon dont on se trompe de
        // cible.
        //
        // ⚠️ Uniquement pour ce qui est applicable : ranger un plan bloqué produirait un
        // brouillon qui échouera, et on ne le découvrirait qu'en le rejouant.
        if a.applicable() && !occupee {
            ui.add_space(mesures::ESPACE);
            // ⚠️ Le nom saisi vit dans la mémoire d'egui, pas dans les ressources : il
            // ne concerne que ce panneau, et le faire remonter obligerait chaque écran
            // à porter un champ de texte qui ne le regarde pas.
            let id = egui::Id::new("nom-du-plan");
            let mut nom_plan: String = ui.data_mut(|d| d.get_temp(id).unwrap_or_default());
            ui.horizontal(|ui| {
                c::legende(ui, "Préparer pour plus tard :");
                let champ = ui.add(
                    egui::TextEdit::singleline(&mut nom_plan)
                        .hint_text("nom du plan")
                        .desired_width(160.0),
                );
                let valide = !nom_plan.trim().is_empty();
                let entree = champ.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if (ui.add_enabled(valide, egui::Button::new("Enregistrer")).clicked()
                    || (entree && valide))
                    && valide
                {
                    *decision = Some(Decision::Enregistrer(nom_plan.trim().to_string()));
                }
            });
            ui.data_mut(|d| d.insert_temp(id, nom_plan));
        }

        ui.add_space(mesures::ESPACE);
        ui.horizontal(|ui| {
            let peut = a.applicable() && !occupee;
            let libelle = if occupee {
                "Application en cours…"
            } else if a.confirmation_requise.is_some() {
                "Appliquer — irréversible"
            } else {
                "Appliquer"
            };

            if ui
                .add_enabled(peut, egui::Button::new(libelle))
                .on_disabled_hover_text(if occupee {
                    "une action est déjà en cours".to_string()
                } else {
                    // Le motif exact, plutôt qu'un bouton muet.
                    a.blocages.join(" · ")
                })
                .clicked()
            {
                *decision = Some(Decision::Appliquer);
            }

            if ui.button("Annuler").clicked() {
                *decision = Some(Decision::Fermer);
            }
        });
    });
}

fn resultat(
    ui: &mut egui::Ui,
    r: &ResultatAction,
    lien: Option<&str>,
    p: crate::design::Palette,
) -> Option<Decision> {
    let mut decision = None;

    // 🔴 Le verdict distingue trois cas que rien ne sépare autrement : réussi, échoué,
    // et « appliqué sans erreur mais INCOMPLET » — ce dernier étant celui qui ferait
    // croire que l'app est prête.
    let att = if r.reussie() {
        Attention::Ok
    } else if r.etapes.iter().any(|e| e.etat == EtatEtape::Echouee) {
        Attention::Critical
    } else {
        Attention::Notice
    };

    c::carte_attention(ui, att, |ui| {
        ui.horizontal(|ui| {
            c::pastille(ui, att);
            ui.add_space(mesures::ESPACE_SERRE);
            c::sous_titre(ui, "Résultat");
        });
        ui.add_space(mesures::ESPACE_SERRE);
        c::texte_libre(ui, &r.verdict());
        ui.add_space(mesures::ESPACE);

        for e in &r.etapes {
            ui.horizontal(|ui| {
                let (mot, teinte) = etiquette(e.etat, p);
                c::badge(ui, mot, teinte);
                ui.add_space(mesures::ESPACE_SERRE);
                c::texte_libre(ui, &e.description);
            });
            if let Some(err) = &e.erreur {
                ui.horizontal(|ui| {
                    ui.add_space(mesures::ESPACE_LARGE);
                    ui.label(
                        RichText::new(crate::design::glyphes::sans_tofu(err))
                            .size(c::taille::LEGENDE)
                            .color(p.texte_faible),
                    );
                });
            }
        }

        // 🔴 Le lien à usage unique, affiché UNE fois : il n'est ni stocké ni
        // réaffichable. Le QR existe parce qu'on le crée sur un ordinateur et qu'on
        // l'ouvre sur un téléphone — recopier cinquante caractères à la main est
        // exactement le moment où l'on renonce.
        if let Some(l) = lien {
            ui.add_space(mesures::ESPACE);
            c::mono(ui, l);
            ui.add_space(mesures::ESPACE_SERRE);
            c::legende(
                ui,
                "Affiché une seule fois : il n'est enregistré nulle part. Le QR se \
                 photographie aussi par-dessus l'épaule — ne l'affiche pas devant \
                 quelqu'un à qui il n'est pas destiné.",
            );
            ui.add_space(mesures::ESPACE_SERRE);
            crate::design::qr::peindre(ui, l, 180.0);
        }

        ui.add_space(mesures::ESPACE);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.button("Fermer").clicked() {
                decision = Some(Decision::Fermer);
            }
        });
    });

    decision
}

/// Le mot et la couleur d'un état d'étape.
///
/// 🔴 « non implémentée » a son PROPRE mot et sa propre couleur : la confondre avec
/// « faite » ferait croire qu'une base a été provisionnée alors que personne ne l'a
/// fait. C'est l'invariant « Unimplemented n'est jamais Done », rendu visible.
fn etiquette(e: EtatEtape, p: crate::design::Palette) -> (&'static str, egui::Color32) {
    match e {
        EtatEtape::Prevue => ("prévue", p.texte_faible),
        EtatEtape::Faite => ("faite", p.ok),
        EtatEtape::Echouee => ("ÉCHEC", p.critique),
        EtatEtape::NonImplementee => ("PAS FAITE", p.attention),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unimplemented_step_never_reads_as_done() {
        // 🔴 L'invariant le plus important du projet, rendu visible : quatre états,
        // quatre mots, quatre couleurs. Les confondre ferait croire qu'une base a été
        // provisionnée alors que personne ne l'a fait.
        let p = crate::design::Theme::turi_sombre().palette;
        let (mot_faite, c_faite) = etiquette(EtatEtape::Faite, p);
        let (mot_non, c_non) = etiquette(EtatEtape::NonImplementee, p);

        assert_ne!(mot_faite, mot_non);
        assert_ne!(c_faite, c_non);
        assert!(mot_non.contains("PAS"), "{mot_non}");
    }

    #[test]
    fn every_step_state_has_its_own_wording() {
        let p = crate::design::Theme::turi_sombre().palette;
        let mots: Vec<&str> = [
            EtatEtape::Prevue,
            EtatEtape::Faite,
            EtatEtape::Echouee,
            EtatEtape::NonImplementee,
        ]
        .into_iter()
        .map(|e| etiquette(e, p).0)
        .collect();

        let mut uniques = mots.clone();
        uniques.sort_unstable();
        uniques.dedup();
        assert_eq!(uniques.len(), 4, "deux états portent le même mot : {mots:?}");
    }

    #[test]
    fn no_action_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("action.rs");
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
