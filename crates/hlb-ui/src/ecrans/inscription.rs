//! L'inscription : créer son compte depuis un lien d'invitation.
//!
//! ## 🔴 Le seul écran qu'on voit sans avoir de compte
//!
//! Il n'a donc ni barre latérale ni navigation : proposer « Tableau de bord » à
//! quelqu'un qui n'a pas encore de compte l'enverrait sur un refus.
//!
//! ## Ce que l'aperçu sert à vérifier
//!
//! Le nom choisi devient à la fois la partie locale de l'adresse mail **et**
//! l'identifiant PocketID. Il ne se change pas ensuite. L'aperçu permet donc de
//! vérifier qu'il est libre et valide **sans consommer le lien** — sinon une majuscule
//! de trop gâcherait une invitation à usage unique.

use egui::{Align, Layout, RichText};
use hlb_api::{Attention, ResultatAction};

use crate::design::{composants as c, mesures};

/// Ce que l'écran demande.
pub enum Demande {
    /// Vérifier le nom, sans consommer le lien.
    Verifier { nom: String },
    /// Créer le compte pour de bon.
    Creer { nom: String },
}

pub fn afficher(
    ui: &mut egui::Ui,
    invitation: Option<&str>,
    apercu: Option<&ResultatAction>,
    resultat: Option<&ResultatAction>,
    lien_enrolement: Option<&str>,
    occupee: bool,
) -> Option<Demande> {
    let p = c::palette(ui);
    let mut demande = None;

    ui.add_space(mesures::ESPACE_LARGE);
    c::titre(ui, "Créer votre compte");
    ui.add_space(mesures::ESPACE_SERRE);

    let Some(_) = invitation else {
        // ⚠️ Sans invitation, on ne montre PAS de formulaire : le remplir mènerait à un
        // refus, et l'on croirait avoir mal choisi son nom.
        c::bandeau(
            ui,
            p.attention,
            "Aucune invitation dans ce lien.",
            Some(
                "L'inscription se fait par un lien reçu d'un administrateur. Si vous en \
                 avez un, ouvrez-le tel quel — sans recopier une partie de l'adresse.",
            ),
        );
        return None;
    };

    // Le compte créé : c'est fini, on affiche ce qu'il faut faire ensuite.
    if let Some(r) = resultat {
        return fin(ui, r, lien_enrolement, p);
    }

    let id = egui::Id::new("form-inscription");
    let mut nom: String = ui
        .ctx()
        .data(|d| d.get_temp::<String>(id))
        .unwrap_or_default();

    c::carte(ui, |ui| {
        c::legende(
            ui,
            "Ce nom sera votre identifiant de connexion ET la partie locale de votre \
             adresse mail. Il ne pourra pas être changé ensuite.",
        );
        ui.add_space(mesures::ESPACE);

        ui.horizontal(|ui| {
            c::legende(ui, "nom");
            ui.add(
                egui::TextEdit::singleline(&mut nom)
                    .hint_text("prenom")
                    .desired_width(220.0),
            );
        });
        c::legende(
            ui,
            "Minuscules, chiffres, point et tiret. Ni espace, ni majuscule, ni accent.",
        );

        // 🔴 L'aperçu d'abord, toujours : il vérifie que le nom est libre SANS
        // consommer le lien. Une invitation à usage unique gâchée sur une faute de
        // frappe serait à redemander à un administrateur.
        if let Some(a) = apercu {
            ui.add_space(mesures::ESPACE);
            if a.applicable() {
                ui.horizontal(|ui| {
                    c::pastille(ui, Attention::Ok);
                    ui.add_space(mesures::ESPACE_SERRE);
                    c::texte_libre(ui, "Ce nom est disponible.");
                });
            } else {
                for b in &a.blocages {
                    ui.horizontal(|ui| {
                        c::pastille(ui, Attention::Critical);
                        ui.add_space(mesures::ESPACE_SERRE);
                        c::texte_libre(ui, b);
                    });
                }
            }
        }

        ui.add_space(mesures::ESPACE);
        ui.horizontal(|ui| {
            let vide = nom.trim().is_empty();

            if ui
                .add_enabled(!vide && !occupee, egui::Button::new("Vérifier ce nom"))
                .clicked()
            {
                demande = Some(Demande::Verifier {
                    nom: nom.trim().to_string(),
                });
            }

            // Le bouton de création n'apparaît qu'APRÈS un aperçu favorable : c'est ce
            // qui garantit qu'on ne consomme pas le lien à l'aveugle.
            let pret = apercu.is_some_and(|a| a.applicable());
            if ui
                .add_enabled(pret && !occupee, egui::Button::new("Créer mon compte"))
                .on_disabled_hover_text(if pret {
                    "création en cours…"
                } else {
                    "vérifiez d'abord que le nom est disponible"
                })
                .clicked()
            {
                demande = Some(Demande::Creer {
                    nom: nom.trim().to_string(),
                });
            }
        });
    });

    ui.ctx().data_mut(|d| d.insert_temp(id, nom));
    demande
}

/// L'écran de fin : ce qu'il reste à faire.
fn fin(
    ui: &mut egui::Ui,
    r: &ResultatAction,
    lien: Option<&str>,
    p: crate::design::Palette,
) -> Option<Demande> {
    let complet = r.reussie();

    c::carte_attention(
        ui,
        if complet {
            Attention::Ok
        } else {
            Attention::Notice
        },
        |ui| {
            ui.horizontal(|ui| {
                c::pastille(
                    ui,
                    if complet {
                        Attention::Ok
                    } else {
                        Attention::Notice
                    },
                );
                ui.add_space(mesures::ESPACE_SERRE);
                c::sous_titre(ui, &r.resume);
            });

            ui.add_space(mesures::ESPACE);

            // 🔴 Le lien d'enrôlement, affiché UNE fois. PocketID n'a pas de mot de
            // passe : ce jeton sert à enregistrer une clé d'accès, et il n'est ni
            // stocké ni réaffichable.
            if let Some(l) = lien {
                c::bandeau(
                    ui,
                    p.accent,
                    "Terminez maintenant : enregistrez votre clé d'accès",
                    Some(
                        "Ce lien ne s'affichera qu'une fois et expire dans 12 heures. \
                         Il n'y a pas de mot de passe : votre appareil devient la clé.",
                    ),
                );
                ui.add_space(mesures::ESPACE_SERRE);
                ui.hyperlink_to(RichText::new(l).size(c::taille::CORPS).color(p.accent), l);
                ui.add_space(mesures::ESPACE);
            }

            // ⚠️ Les étapes qui n'ont PAS abouti sont dites, pas tues : un compte à
            // moitié créé paraît fonctionnel, et la personne le découvrirait au premier
            // courriel perdu.
            for e in &r.etapes {
                if e.etat == hlb_api::EtatEtape::Faite {
                    continue;
                }
                ui.horizontal(|ui| {
                    c::badge(ui, "à terminer", p.attention);
                    ui.add_space(mesures::ESPACE_SERRE);
                    ui.vertical(|ui| {
                        c::texte_libre(ui, &e.description);
                        if let Some(err) = &e.erreur {
                            c::legende(ui, err);
                        }
                    });
                });
                ui.add_space(mesures::ESPACE_SERRE);
            }

            if !complet {
                ui.add_space(mesures::ESPACE_SERRE);
                c::legende(
                    ui,
                    "Votre compte existe, mais tout n'est pas en place. Signalez-le à \
                     la personne qui vous a invité : une relance de sa part terminera \
                     ce qui manque.",
                );
            }

            ui.add_space(mesures::ESPACE);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Aller à l'accueil").clicked() {
                    // Rien à demander : la coquille change de route.
                }
            });
        },
    );

    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_signup_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("inscription.rs");
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
