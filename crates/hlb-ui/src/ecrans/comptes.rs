//! Les comptes humains, et les invitations.
//!
//! ## 🔴 Un compte à moitié créé paraît fonctionnel
//!
//! C'est ce que cet écran existe pour montrer. Créer un compte, c'est trois opérations
//! sur trois systèmes ; si l'une échoue, on obtient une personne qui se connecte partout
//! sans rien recevoir, ou une boîte que personne ne peut lire. Rien ne le signale — ça
//! se découvre au premier courriel perdu, souvent une réinitialisation de mot de passe.
//!
//! Les moitiés sont donc **en tête de liste**, en rouge, avec le geste qui répare.
//!
//! ## Et un alias expiré qui reçoit encore
//!
//! Un serveur de messagerie ne sait pas expirer un alias : ce qui est écrit y reste. Un
//! alias « temporaire » ne l'est que si la purge est passée. L'écran compte donc les
//! **promesses rompues** — les adresses qu'on croit fermées et qui reçoivent.

use egui::{Align, Layout};
use hlb_api::{Attention, CompteSummary, InvitationSummary};

use crate::client::Freshness;
use crate::design::{composants as c, mesures};

/// Ce que l'écran demande.
pub enum Demande {
    /// Créer une invitation : `(durée en secondes, nombre d'usages, rôle)`.
    Inviter {
        duree_s: i64,
        usages: i64,
        role: String,
    },
    /// Révoquer une invitation par sa référence.
    Revoquer(String),
    /// Changer un rôle : `(compte, rôle)`.
    Role(String, String),
}

pub fn afficher(
    ui: &mut egui::Ui,
    comptes: Option<&Vec<CompteSummary>>,
    invitations: Option<&Vec<InvitationSummary>>,
    fraicheur: &Freshness,
    etroit: bool,
) -> Option<Demande> {
    let p = c::palette(ui);
    let mut demande = None;

    c::titre(ui, "Comptes");
    ui.add_space(mesures::ESPACE_SERRE);

    let Some(comptes) = comptes else {
        c::etat_vide(ui, &fraicheur.describe(), None);
        return None;
    };

    let casses = comptes
        .iter()
        .filter(|x| x.coherence != hlb_api::EtatCompte::Complet)
        .count();
    let rompues: usize = comptes.iter().map(|x| x.promesses_rompues).sum();

    if casses > 0 {
        c::bandeau(
            ui,
            p.critique,
            &format!(
                "{} incomplet{}.",
                hlb_api::pluriel(casses as u64, "compte", "comptes"),
                if casses > 1 { "s" } else { "" }
            ),
            Some(
                "Un compte à moitié créé paraît fonctionnel : la personne se connecte \
                 et ne reçoit rien, ou reçoit sans pouvoir se connecter. La création \
                 est reprenable.",
            ),
        );
        ui.add_space(mesures::ESPACE);
    }

    if rompues > 0 {
        c::bandeau(
            ui,
            p.critique,
            &format!(
                "{} reçoi{} ENCORE.",
                hlb_api::pluriel(rompues as u64, "alias expiré", "aliases expirés"),
                if rompues > 1 { "vent" } else { "t" }
            ),
            Some(
                "Un serveur de messagerie ne sait pas expirer un alias : la purge n'est \
                 pas passée, et ces adresses qu'on croit fermées restent ouvertes.",
            ),
        );
        ui.add_space(mesures::ESPACE);
    }

    if let Some(d) = formulaire_invitation(ui, p) {
        demande = Some(d);
    }
    ui.add_space(mesures::ESPACE);

    ui.horizontal(|ui| {
        c::sous_titre(ui, "Comptes");
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            c::legende(
                ui,
                &hlb_api::pluriel(comptes.len() as u64, "compte", "comptes"),
            );
        });
    });
    ui.add_space(mesures::ESPACE_SERRE);

    for compte in comptes {
        if let Some(d) = carte_compte(ui, compte, etroit, p) {
            demande = Some(d);
        }
        ui.add_space(mesures::ESPACE_SERRE);
    }

    if let Some(inv) = invitations.filter(|i| !i.is_empty()) {
        ui.add_space(mesures::ESPACE_LARGE);
        c::sous_titre(ui, "Invitations");
        ui.add_space(mesures::ESPACE_SERRE);
        for i in inv {
            if let Some(d) = carte_invitation(ui, i, p) {
                demande = Some(d);
            }
            ui.add_space(mesures::ESPACE_SERRE);
        }
    }

    demande
}

/// Le formulaire d'invitation : durée et nombre d'usages.
///
/// ## Pourquoi des choix PRÉDÉFINIS et non des champs libres
///
/// Un champ « durée en secondes » se remplit de travers — 3600 pour une heure, ou 3600
/// pour une journée si l'on se trompe d'unité. Les valeurs proposées couvrent les cas
/// réels, et le bouton dit ce qu'il fait en toutes lettres.
///
/// 🔴 Le nombre d'usages est affiché avec sa conséquence : un lien à N entrées qui
/// fuite fait entrer N personnes.
fn formulaire_invitation(ui: &mut egui::Ui, p: crate::design::Palette) -> Option<Demande> {
    let mut demande = None;
    let id = egui::Id::new("form-invitation");

    // L'état du formulaire vit dans la mémoire d'egui : le porter dans la structure de
    // l'écran obligerait à le faire remonter à travers toute la coquille pour trois
    // valeurs qui ne concernent que ce panneau.
    let (mut duree, mut usages, mut role) = ui.ctx().data(|d| {
        d.get_temp::<(i64, i64, String)>(id)
            .unwrap_or((7 * 86_400, 1, "utilisateur".to_string()))
    });

    c::carte(ui, |ui| {
        c::sous_titre(ui, "Inviter");
        ui.add_space(mesures::ESPACE_SERRE);

        ui.horizontal_wrapped(|ui| {
            c::legende(ui, "valable");
            for (libelle, secondes) in [
                ("1 h", 3_600_i64),
                ("24 h", 86_400),
                ("7 jours", 7 * 86_400),
                ("30 jours", 30 * 86_400),
            ] {
                if ui.selectable_label(duree == secondes, libelle).clicked() {
                    duree = secondes;
                }
            }
        });

        ui.add_space(mesures::ESPACE_SERRE);
        ui.horizontal_wrapped(|ui| {
            c::legende(ui, "pour");
            for n in [1_i64, 3, 5, 10, 25] {
                let libelle = hlb_api::pluriel(n as u64, "personne", "personnes");
                if ui.selectable_label(usages == n, libelle).clicked() {
                    usages = n;
                }
            }
        });

        ui.add_space(mesures::ESPACE_SERRE);
        ui.horizontal_wrapped(|ui| {
            c::legende(ui, "rôle");
            for r in hlb_types::Role::tous() {
                if ui
                    .selectable_label(role == r.as_str(), r.as_str())
                    .on_hover_text(r.describe())
                    .clicked()
                {
                    role = r.as_str().to_string();
                }
            }
        });

        // 🔴 La conséquence, dite AVANT de créer le lien — pas après l'avoir partagé.
        if usages > 3 {
            ui.add_space(mesures::ESPACE_SERRE);
            c::bandeau(
                ui,
                p.attention,
                &format!(
                    "Ce lien laissera entrer {}.",
                    hlb_api::pluriel(usages as u64, "personne", "personnes")
                ),
                Some("S'il fuite, ce sont autant de comptes créés. Un lien par personne coûte plus cher à transmettre, et beaucoup moins cher à révoquer."),
            );
        }
        if role == "admin" {
            ui.add_space(mesures::ESPACE_SERRE);
            c::bandeau(
                ui,
                p.critique,
                "Rôle ADMIN",
                Some("La personne pourra accorder des rôles et détruire des données."),
            );
        }

        ui.add_space(mesures::ESPACE);
        if ui.button("Créer le lien…").clicked() {
            demande = Some(Demande::Inviter {
                duree_s: duree,
                usages,
                role: role.clone(),
            });
        }
    });

    ui.ctx()
        .data_mut(|d| d.insert_temp(id, (duree, usages, role)));
    demande
}

fn carte_compte(
    ui: &mut egui::Ui,
    x: &CompteSummary,
    etroit: bool,
    p: crate::design::Palette,
) -> Option<Demande> {
    let att = x.coherence.attention();
    let mut demande = None;

    c::carte_attention(ui, att, |ui| {
        ui.horizontal(|ui| {
            c::monogramme(ui, &x.nom, p.attention_de(att), 26.0);
            ui.add_space(mesures::ESPACE_SERRE);
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    c::sous_titre(ui, &x.nom);
                    c::badge(ui, &x.role, p.info);
                    c::badge(ui, &x.profil, p.texte_faible);
                });
                for b in &x.boites {
                    c::mono(
                        ui,
                        &format!(
                            "{}{}",
                            b.adresse,
                            if b.par_defaut { " (défaut)" } else { "" }
                        ),
                    );
                }
            });

            if !etroit {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if x.sessions > 0 {
                        c::legende(
                            ui,
                            &hlb_api::pluriel(x.sessions as u64, "session", "sessions"),
                        );
                    }
                });
            }
        });

        // 🔴 L'état de cohérence, avec sa conséquence concrète — pas un simple libellé.
        if att != Attention::Ok {
            ui.add_space(mesures::ESPACE_SERRE);
            c::texte_libre(ui, &x.explication);
            if let Some(remede) = x.coherence.remede(&x.nom) {
                c::mono(ui, &remede);
            }
        }

        if x.promesses_rompues > 0 {
            ui.add_space(mesures::ESPACE_SERRE);
            c::badge(
                ui,
                &format!(
                    "{} qui reçoi{} encore",
                    hlb_api::pluriel(
                        x.promesses_rompues as u64,
                        "alias expiré",
                        "aliases expirés"
                    ),
                    if x.promesses_rompues > 1 { "vent" } else { "t" }
                ),
                p.critique,
            );
        }

        // Le changement de rôle : un bouton par rôle, plutôt qu'un menu déroulant —
        // sur quatre valeurs, le menu coûte un clic de plus pour rien.
        ui.add_space(mesures::ESPACE_SERRE);
        ui.horizontal_wrapped(|ui| {
            c::legende(ui, "rôle :");
            for r in hlb_types::Role::tous() {
                let actif = r.as_str() == x.role;
                if ui
                    .add_enabled(!actif, egui::Button::new(r.as_str()).small())
                    .on_hover_text(r.describe())
                    .clicked()
                {
                    demande = Some(Demande::Role(x.nom.clone(), r.as_str().to_string()));
                }
            }
        });
    });

    demande
}

fn carte_invitation(
    ui: &mut egui::Ui,
    i: &InvitationSummary,
    p: crate::design::Palette,
) -> Option<Demande> {
    let mut demande = None;

    c::carte(ui, |ui| {
        ui.horizontal(|ui| {
            // 🔴 Un lien largement ouvert se distingue d'un lien normal : c'est celui
            // qu'on oublie de fermer, et celui dont la fuite coûte le plus cher.
            let teinte = if i.largement_ouverte() {
                p.attention
            } else if i.utilisable() {
                p.ok
            } else {
                p.texte_faible
            };
            c::badge(ui, i.etat(), teinte);
            ui.add_space(mesures::ESPACE_SERRE);
            ui.vertical(|ui| {
                c::mono(ui, &i.reference);
                c::legende(
                    ui,
                    &format!(
                        "{} / {} · invitée par {}{}",
                        i.profil,
                        i.role,
                        i.cree_par,
                        match &i.note {
                            Some(n) => format!(" · {n}"),
                            None => String::new(),
                        }
                    ),
                );
            });

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if i.utilisable() {
                    if ui.button("Révoquer").clicked() {
                        demande = Some(Demande::Revoquer(i.reference.clone()));
                    }
                    c::legende(
                        ui,
                        &format!(
                            "{} restante{} · expire dans {}",
                            hlb_api::pluriel(i.restants() as u64, "entrée", "entrées"),
                            if i.restants() > 1 { "s" } else { "" },
                            hlb_api::humanise(i.expire_dans_s)
                        ),
                    );
                } else {
                    // ⚠️ Pas de bouton : une invitation épuisée reste au registre,
                    // c'est l'historique de qui a créé quel compte.
                    c::legende(ui, "conservée comme trace");
                }
            });
        });
    });

    demande
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_accounts_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("comptes.rs");
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
