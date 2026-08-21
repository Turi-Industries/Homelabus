//! Publier une annonce, suivre un incident.
//!
//! ## 🔴 Un incident se SUIT, il ne se réécrit pas
//!
//! Le bouton dit « ajouter une nouvelle », jamais « modifier ». C'est la chronologie
//! qu'on relit après coup — à quelle heure on a su, compris, réglé — et réécrire le
//! message d'origine l'effacerait.
//!
//! ## Et l'audience se choisit avant de publier
//!
//! Inonder l'utilisateur du portail de messages d'exploitation lui fait cesser de les
//! lire, au moment précis où l'un d'eux comptera. Le formulaire montre donc qui verra
//! l'annonce **pendant** qu'on l'écrit.

use egui::{Align, Layout};
use hlb_api::{Annonce, Attention};

use crate::client::Freshness;
use crate::design::{composants as c, mesures};

/// Ce que l'écran demande.
pub enum Demande {
    Publier {
        titre: String,
        corps: String,
        niveau: String,
        audience: Option<String>,
        epinglee: bool,
    },
    /// Ajouter une nouvelle au fil d'une annonce.
    Suivre {
        id: i64,
        corps: String,
    },
    Retirer(i64),
}

pub fn afficher(
    ui: &mut egui::Ui,
    annonces: Option<&Vec<Annonce>>,
    fraicheur: &Freshness,
) -> Option<Demande> {
    let p = c::palette(ui);
    let mut demande = None;

    c::titre(ui, "Annonces");
    ui.add_space(mesures::ESPACE_SERRE);

    if let Some(d) = formulaire(ui, p) {
        demande = Some(d);
    }
    ui.add_space(mesures::ESPACE_LARGE);

    let Some(v) = annonces else {
        c::etat_vide(ui, &fraicheur.describe(), None);
        return demande;
    };

    if v.is_empty() {
        c::etat_vide(ui, "Aucune annonce publiée.", None);
        return demande;
    }

    // Les incidents ouverts d'abord : ce sont eux qui demandent une nouvelle.
    let (ouverts, autres): (Vec<&Annonce>, Vec<&Annonce>) =
        v.iter().partition(|a| a.incident_ouvert());

    if !ouverts.is_empty() {
        c::sous_titre(ui, "Incidents en cours");
        ui.add_space(mesures::ESPACE_SERRE);
        for a in &ouverts {
            if let Some(d) = carte(ui, a, true, p) {
                demande = Some(d);
            }
            ui.add_space(mesures::ESPACE_SERRE);
        }
        ui.add_space(mesures::ESPACE);
    }

    c::sous_titre(ui, "Publiées");
    ui.add_space(mesures::ESPACE_SERRE);
    for a in &autres {
        if let Some(d) = carte(ui, a, false, p) {
            demande = Some(d);
        }
        ui.add_space(mesures::ESPACE_SERRE);
    }

    demande
}

fn formulaire(ui: &mut egui::Ui, p: crate::design::Palette) -> Option<Demande> {
    let mut demande = None;
    let id = egui::Id::new("form-annonce");

    let (mut titre, mut corps, mut niveau, mut audience, mut epinglee) = ui.ctx().data(|d| {
        d.get_temp::<(String, String, String, String, bool)>(id)
            .unwrap_or_default()
    });
    if niveau.is_empty() {
        niveau = "info".to_string();
    }

    c::carte(ui, |ui| {
        c::sous_titre(ui, "Publier");
        ui.add_space(mesures::ESPACE_SERRE);

        ui.add(
            egui::TextEdit::singleline(&mut titre)
                .hint_text("Titre")
                .desired_width(f32::INFINITY),
        );
        ui.add_space(mesures::ESPACE_SERRE);
        ui.add(
            egui::TextEdit::multiline(&mut corps)
                .hint_text("Ce qu'il faut savoir, en quelques lignes.")
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );

        ui.add_space(mesures::ESPACE_SERRE);
        ui.horizontal_wrapped(|ui| {
            c::legende(ui, "niveau");
            for (v, libelle) in [
                ("info", "information"),
                ("maintenance", "maintenance"),
                ("avertissement", "avertissement"),
                ("incident", "incident"),
            ] {
                if ui.selectable_label(niveau == v, libelle).clicked() {
                    niveau = v.to_string();
                }
            }
        });

        ui.add_space(mesures::ESPACE_SERRE);
        ui.horizontal_wrapped(|ui| {
            c::legende(ui, "qui verra");
            // ⚠️ L'audience se choisit AVANT de publier, et son effet est dit en toutes
            // lettres : « tout le monde » inclut les gens qui n'ont qu'une boîte mail.
            for (v, libelle) in [
                ("", "tout le monde"),
                ("viewer", "à partir de viewer"),
                ("operator", "l'exploitation"),
                ("admin", "les admins"),
            ] {
                if ui.selectable_label(audience == v, libelle).clicked() {
                    audience = v.to_string();
                }
            }
            ui.checkbox(&mut epinglee, "épingler");
        });

        // 🔴 Un incident sans audience va jusqu'au portail — c'est en général ce qu'on
        // veut, mais il faut le savoir avant de l'écrire.
        if niveau == "incident" && audience.is_empty() {
            ui.add_space(mesures::ESPACE_SERRE);
            c::bandeau(
                ui,
                p.info,
                "Cet incident sera visible de tous.",
                Some(
                    "Il restera affiché jusqu'à ce que vous le clôturiez : une panne qui \
                     disparaît toute seule de l'écran laisse croire qu'elle est réglée.",
                ),
            );
        }
        if niveau == "maintenance" && audience.is_empty() {
            ui.add_space(mesures::ESPACE_SERRE);
            c::bandeau(
                ui,
                p.attention,
                "Cette maintenance ira jusqu'au portail.",
                Some(
                    "Les personnes qui n'ont qu'une boîte mail la verront aussi. Trop de \
                     messages d'exploitation leur font cesser de lire les annonces.",
                ),
            );
        }

        ui.add_space(mesures::ESPACE);
        let pret = !titre.trim().is_empty() && !corps.trim().is_empty();
        if ui
            .add_enabled(pret, egui::Button::new("Publier…"))
            .on_disabled_hover_text("il faut un titre et un texte")
            .clicked()
        {
            demande = Some(Demande::Publier {
                titre: titre.trim().to_string(),
                corps: corps.trim().to_string(),
                niveau: niveau.clone(),
                audience: (!audience.is_empty()).then(|| audience.clone()),
                epinglee,
            });
        }
    });

    ui.ctx()
        .data_mut(|d| d.insert_temp(id, (titre, corps, niveau, audience, epinglee)));
    demande
}

fn carte(
    ui: &mut egui::Ui,
    a: &Annonce,
    suivable: bool,
    p: crate::design::Palette,
) -> Option<Demande> {
    let mut demande = None;
    let att = a.niveau.attention();

    c::carte_attention(ui, att, |ui| {
        ui.horizontal(|ui| {
            c::badge(ui, a.niveau.libelle(), p.attention_de(att));
            if a.epinglee {
                c::badge(ui, "épinglée", p.info);
            }
            ui.add_space(mesures::ESPACE_SERRE);
            c::sous_titre(ui, &a.titre);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Retirer").clicked() {
                    demande = Some(Demande::Retirer(a.id));
                }
                c::legende(ui, &format!("{} · {}", a.publiee_le, a.auteur));
            });
        });

        ui.add_space(mesures::ESPACE_SERRE);
        c::texte_libre(ui, &a.corps);

        for m in &a.suivi {
            ui.add_space(mesures::ESPACE_SERRE);
            ui.horizontal(|ui| {
                ui.add_space(mesures::ESPACE);
                ui.vertical(|ui| {
                    c::legende(ui, &format!("{} · {}", m.at, m.auteur));
                    c::texte_libre(ui, &m.corps);
                });
            });
        }

        if suivable {
            ui.add_space(mesures::ESPACE);
            let id = egui::Id::new(("suivi", a.id));
            let mut texte: String = ui
                .ctx()
                .data(|d| d.get_temp::<String>(id))
                .unwrap_or_default();

            ui.add(
                egui::TextEdit::multiline(&mut texte)
                    .hint_text(
                        "Où en est-on ? Cette nouvelle s'ajoute au fil, elle ne remplace rien.",
                    )
                    .desired_rows(2)
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(mesures::ESPACE_SERRE);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !texte.trim().is_empty(),
                        // ⚠️ « ajouter », jamais « modifier » : c'est la chronologie
                        // qu'on relit, et la réécrire l'effacerait.
                        egui::Button::new("Ajouter une nouvelle"),
                    )
                    .clicked()
                {
                    demande = Some(Demande::Suivre {
                        id: a.id,
                        corps: texte.trim().to_string(),
                    });
                }
                c::legende(
                    ui,
                    "Pour clore l'incident, publiez la dernière nouvelle puis retirez-le.",
                );
            });
            ui.ctx().data_mut(|d| d.insert_temp(id, texte));
        }

        let _ = Attention::Ok;
    });

    demande
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_announcement_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("annonces.rs");
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
