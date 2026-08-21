//! Le portail : ce que voit quelqu'un qui a un compte et rien d'autre.
//!
//! ## 🔴 Homelabus ANNONCE, il n'accorde pas
//!
//! Le portail liste les applications exposées. Il ne donne pas l'accès — celui-ci vient
//! de PocketID et du forward-auth. La distinction n'est pas théorique : afficher une
//! app comme « disponible » ne la rend pas accessible, et laisser croire l'inverse
//! ferait chercher une panne là où il manque une autorisation.
//!
//! ## Et un lien vers une app arrêtée est pire qu'un lien absent
//!
//! Il envoie sur une page d'erreur, et l'on croit que c'est son propre accès qui est
//! cassé. L'état est donc affiché, et le lien d'une app arrêtée est grisé.

use egui::{Align, Layout, RichText};
use hlb_api::{Annonce, Attention, NiveauAnnonce};

use crate::client::Freshness;
use crate::design::{composants as c, mesures};

/// Ce que le portail reçoit du controller.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct Portail {
    #[serde(default)]
    pub apps: Vec<AppPortail>,
    #[serde(default)]
    pub annonces: Vec<Annonce>,
    #[serde(default)]
    pub compte: Option<String>,
    #[serde(default)]
    pub boites: Vec<hlb_api::BoiteBreve>,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct AppPortail {
    pub nom: String,
    pub nom_affiche: String,
    #[serde(default)]
    pub domaine: Option<String>,
    #[serde(default)]
    pub categorie: Option<String>,
    pub disponible: bool,
}

pub fn afficher(
    ui: &mut egui::Ui,
    portail: Option<&Portail>,
    fraicheur: &Freshness,
    etroit: bool,
) {
    let p = c::palette(ui);

    let Some(v) = portail else {
        c::titre(ui, "Accueil");
        c::etat_vide(ui, &fraicheur.describe(), None);
        return;
    };

    ui.horizontal(|ui| {
        c::titre(ui, "Accueil");
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if let Some(compte) = &v.compte {
                c::legende(ui, compte);
            }
        });
    });
    ui.add_space(mesures::ESPACE);

    // Les incidents ouverts d'abord : c'est ce qu'on vient vérifier quand quelque
    // chose ne marche pas.
    let ouverts: Vec<&Annonce> = v.annonces.iter().filter(|a| a.incident_ouvert()).collect();
    for a in &ouverts {
        carte_annonce(ui, a, p);
        ui.add_space(mesures::ESPACE_SERRE);
    }
    if !ouverts.is_empty() {
        ui.add_space(mesures::ESPACE);
    }

    // Les applications.
    c::sous_titre(ui, "Vos applications");
    c::legende(
        ui,
        "Ces applications existent et sont exposées. Homelabus ne décide pas de vos \
         droits d'accès : c'est votre identité qui les porte.",
    );
    ui.add_space(mesures::ESPACE_SERRE);

    if v.apps.is_empty() {
        c::etat_vide(ui, "Aucune application exposée pour l'instant.", None);
    } else if etroit {
        for a in &v.apps {
            carte_app(ui, a, p);
            ui.add_space(mesures::ESPACE_SERRE);
        }
    } else {
        // Trois par ligne : au-delà, les cartes deviennent trop étroites pour porter
        // un nom d'application complet.
        for rangee in v.apps.chunks(3) {
            ui.columns(3, |col| {
                for (i, a) in rangee.iter().enumerate() {
                    carte_app(&mut col[i], a, p);
                }
            });
            ui.add_space(mesures::ESPACE_SERRE);
        }
    }

    // Le reste des annonces.
    let autres: Vec<&Annonce> = v.annonces.iter().filter(|a| !a.incident_ouvert()).collect();
    if !autres.is_empty() {
        ui.add_space(mesures::ESPACE_LARGE);
        c::sous_titre(ui, "Annonces");
        ui.add_space(mesures::ESPACE_SERRE);
        for a in autres {
            carte_annonce(ui, a, p);
            ui.add_space(mesures::ESPACE_SERRE);
        }
    }

    if !v.boites.is_empty() {
        ui.add_space(mesures::ESPACE_LARGE);
        c::carte(ui, |ui| {
            c::sous_titre(ui, "Vos adresses");
            ui.add_space(mesures::ESPACE_SERRE);
            for b in &v.boites {
                c::mono(
                    ui,
                    &format!("{}{}", b.adresse, if b.par_defaut { " (principale)" } else { "" }),
                );
            }
        });
    }
}

fn carte_app(ui: &mut egui::Ui, a: &AppPortail, p: crate::design::Palette) {
    c::carte(ui, |ui| {
        ui.horizontal(|ui| {
            c::monogramme(
                ui,
                &a.nom_affiche,
                if a.disponible { p.accent } else { p.texte_faible },
                28.0,
            );
            ui.add_space(mesures::ESPACE_SERRE);
            ui.vertical(|ui| {
                c::texte_libre(ui, &a.nom_affiche);
                match (&a.domaine, a.disponible) {
                    // 🔴 Un lien vers une app ARRÊTÉE envoie sur une page d'erreur, et
                    // l'on croit que c'est son propre accès qui est cassé. On le dit.
                    (Some(d), true) => {
                        ui.hyperlink_to(
                            RichText::new(d.clone())
                                .size(c::taille::LEGENDE)
                                .color(p.accent),
                            format!("https://{d}"),
                        );
                    }
                    (Some(d), false) => {
                        ui.label(
                            RichText::new(format!("{d} — arrêtée"))
                                .size(c::taille::LEGENDE)
                                .color(p.texte_faible),
                        );
                    }
                    (None, _) => {}
                }
            });
        });
    });
}

fn carte_annonce(ui: &mut egui::Ui, a: &Annonce, p: crate::design::Palette) {
    let att = a.niveau.attention();
    c::carte_attention(ui, att, |ui| {
        ui.horizontal(|ui| {
            c::badge(ui, a.niveau.libelle(), p.attention_de(att));
            ui.add_space(mesures::ESPACE_SERRE);
            c::sous_titre(ui, &a.titre);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                c::legende(ui, &a.publiee_le);
            });
        });
        ui.add_space(mesures::ESPACE_SERRE);
        c::texte_libre(ui, &a.corps);

        // 🔴 Le fil, dans l'ordre : c'est la chronologie qu'on relit. La masquer
        // derrière un repli ferait qu'on lirait le premier message — « on cherche » —
        // en croyant que c'est l'état actuel.
        if !a.suivi.is_empty() {
            ui.add_space(mesures::ESPACE_SERRE);
            for m in &a.suivi {
                ui.horizontal(|ui| {
                    ui.add_space(mesures::ESPACE);
                    ui.vertical(|ui| {
                        c::legende(ui, &format!("{} · {}", m.at, m.auteur));
                        c::texte_libre(ui, &m.corps);
                    });
                });
                ui.add_space(mesures::ESPACE_SERRE);
            }
        }

        if a.niveau == NiveauAnnonce::Incident && a.suivi.is_empty() {
            // ⚠️ Un incident sans nouvelle depuis sa publication : on ne sait pas où en
            // est la situation, et il vaut mieux le dire que laisser supposer.
            ui.add_space(mesures::ESPACE_SERRE);
            c::legende(ui, "Aucune nouvelle depuis la publication.");
        }
        let _ = Attention::Ok;
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_portal_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("portail.rs");
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
