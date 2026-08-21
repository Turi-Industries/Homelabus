//! Les sauvegardes : couverture réelle et frise des exécutions.
//!
//! ## 🔴 La fraîcheur se mesure PAR destination
//!
//! C'est le piège du §8.1, et il est structurant pour cet écran. Une seule destination
//! fraîche masque toutes les autres si l'on agrège : un hors-site mort depuis trois
//! semaines passe pour une sauvegarde de deux heures, parce que le NAS, lui, tourne. On
//! croit le 3-2-1 tenu alors qu'il ne reste qu'une copie, sur les mêmes machines.
//!
//! Le résumé affiche donc le **pire** cas, jamais le meilleur — sinon il contredirait
//! le détail juste en dessous, et c'est le résumé qu'on lit.
//!
//! ## Et « configuré » n'est pas « protégé »
//!
//! Le nombre de destinations déclarées ne dit rien du nombre de copies : une
//! destination en échec est une destination qui ne protège de rien. C'est
//! `copies_a_jour` qui compte.

use egui::{Align, Layout};
use hlb_api::{Attention, CouvertureSummary, SauvegardeRun};

use crate::client::Freshness;
use crate::design::{composants as c, mesures};

pub fn afficher(
    ui: &mut egui::Ui,
    couverture: Option<&Vec<CouvertureSummary>>,
    historique: Option<&Vec<SauvegardeRun>>,
    fraicheur: &Freshness,
    etroit: bool,
) {
    let p = c::palette(ui);

    c::titre(ui, "Sauvegardes");
    ui.add_space(mesures::ESPACE_SERRE);

    let Some(couverture) = couverture else {
        c::etat_vide(ui, &fraicheur.describe(), None);
        return;
    };

    if couverture.is_empty() {
        c::etat_vide(
            ui,
            "Aucune application installée.",
            Some("hlb backup dest add <nom> --location <chemin> --apply"),
        );
        return;
    }

    // Le verdict global d'abord : combien d'apps ne sont pas protégées.
    let sans = couverture.iter().filter(|c| c.copies_a_jour == 0).count();
    let une = couverture.iter().filter(|c| c.copies_a_jour == 1).count();

    let (teinte, verdict) = if sans > 0 {
        (
            p.critique,
            format!(
                "{} n'{} AUCUNE copie à jour.",
                hlb_api::pluriel(sans as u64, "application", "applications"),
                if sans > 1 { "ont" } else { "a" }
            ),
        )
    } else if une > 0 {
        (
            p.attention,
            format!(
                "{} n'{} plus qu'une seule copie.",
                hlb_api::pluriel(une as u64, "application", "applications"),
                if une > 1 { "ont" } else { "a" }
            ),
        )
    } else {
        (p.ok, "Toutes les applications ont au moins deux copies.".to_string())
    };
    c::bandeau(
        ui,
        teinte,
        &verdict,
        (sans > 0 || une > 0).then_some(
            "Le nombre de destinations déclarées ne dit rien du nombre de copies : une \
             destination en échec ne protège de rien.",
        ),
    );
    ui.add_space(mesures::ESPACE_LARGE);

    c::sous_titre(ui, "Couverture par application");
    ui.add_space(mesures::ESPACE_SERRE);

    for cv in couverture {
        carte_couverture(ui, cv, p);
        ui.add_space(mesures::ESPACE_SERRE);
    }

    if let Some(h) = historique.filter(|h| !h.is_empty()) {
        ui.add_space(mesures::ESPACE_LARGE);
        c::sous_titre(ui, "Dernières exécutions");
        ui.add_space(mesures::ESPACE_SERRE);
        historique_recent(ui, h, etroit, p);
    }
}

fn carte_couverture(ui: &mut egui::Ui, cv: &CouvertureSummary, p: crate::design::Palette) {
    let att = cv.attention();
    c::carte_attention(ui, att, |ui| {
        ui.horizontal(|ui| {
            c::pastille(ui, att);
            ui.add_space(mesures::ESPACE_SERRE);
            c::sous_titre(ui, &cv.app);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                c::legende(ui, &cv.resume());
            });
        });

        ui.add_space(mesures::ESPACE_SERRE);
        for (dest, age) in &cv.par_destination {
            ui.horizontal(|ui| {
                c::mono(ui, dest);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    // 🔴 « JAMAIS » et un âge ne sont pas la même chose : le second dit
                    // qu'une copie existe quelque part, le premier qu'il n'y en a
                    // aucune. Les afficher pareil est exactement l'erreur qu'on évite.
                    let (texte, teinte) = match age {
                        None => ("JAMAIS".to_string(), p.critique),
                        Some(s) if *s > SEUIL_PEREMPTION_S => {
                            (hlb_api::humanise(*s), p.critique)
                        }
                        Some(s) => (hlb_api::humanise(*s), p.texte_faible),
                    };
                    ui.label(
                        egui::RichText::new(texte)
                            .size(c::taille::LEGENDE)
                            .color(teinte),
                    );
                });
            });
        }
    });
}

/// Au-delà, une sauvegarde ne compte plus comme une copie à jour.
const SEUIL_PEREMPTION_S: i64 = 12 * 3_600;

fn historique_recent(
    ui: &mut egui::Ui,
    h: &[SauvegardeRun],
    etroit: bool,
    p: crate::design::Palette,
) {
    c::carte(ui, |ui| {
        // ⚠️ Les vingt dernières seulement. L'historique complet fait des milliers de
        // lignes ; les afficher toutes rendrait l'écran illisible et lent, pour une
        // information qu'on ne lit jamais au-delà des derniers jours.
        for r in h.iter().take(20) {
            ui.horizontal(|ui| {
                // 🔴 Les échecs sont là, et c'est le but : une frise où rien ne s'est
                // jamais mal passé ferait ressembler une destination en panne à une
                // destination inutilisée.
                c::pastille(
                    ui,
                    if r.reussie {
                        Attention::Ok
                    } else {
                        Attention::Critical
                    },
                );
                ui.add_space(mesures::ESPACE_SERRE);
                c::texte_libre(
                    ui,
                    &format!(
                        "{} · {}{}",
                        r.app,
                        r.kind,
                        match &r.destination {
                            Some(d) => format!(" vers {d}"),
                            None => String::new(),
                        }
                    ),
                );
                if !etroit {
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        c::legende(ui, &r.quand);
                    });
                }
            });
            if let Some(e) = &r.erreur {
                ui.horizontal(|ui| {
                    ui.add_space(mesures::ESPACE_LARGE);
                    ui.label(
                        egui::RichText::new(crate::design::glyphes::sans_tofu(e))
                            .size(c::taille::LEGENDE)
                            .color(p.critique),
                    );
                });
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_never_served_destination_is_not_an_old_one() {
        // 🔴 Un âge dit qu'une copie existe quelque part ; « JAMAIS » dit qu'il n'y en
        // a aucune. Les afficher pareil est l'erreur que tout ce projet évite.
        let jamais = CouvertureSummary {
            app: "immich".into(),
            par_destination: vec![("nas".into(), Some(7200)), ("offsite".into(), None)],
            copies_a_jour: 1,
        };
        assert_eq!(jamais.attention(), Attention::Notice);
        assert!(jamais.resume().contains("3-2-1"));
    }

    #[test]
    fn zero_copies_outweighs_a_fresh_destination() {
        let rien = CouvertureSummary {
            app: "seafile".into(),
            par_destination: vec![("nas".into(), None)],
            copies_a_jour: 0,
        };
        assert_eq!(rien.attention(), Attention::Critical);
    }

    #[test]
    fn no_backup_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("sauvegardes.rs");
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
