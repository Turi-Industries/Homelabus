//! La liste des applications.
//!
//! ## La règle de tri
//!
//! 🔴 **Ce qui demande une action d'abord.** Trier par nom mettrait l'app en échec au
//! milieu de la liste, entre deux apps saines — et sur vingt apps, on ne la verrait pas.
//! Le tri est donc par urgence décroissante, puis par nom pour rester stable d'une
//! image à l'autre.

use egui::{Align, Layout, RichText};
use hlb_api::AppSummary;

use crate::client::Snapshot;
use crate::design::{composants as c, mesures};

/// Rend l'app sur laquelle on a cliqué, s'il y en a une.
pub fn afficher(ui: &mut egui::Ui, data: &Snapshot, etroit: bool) -> Option<String> {
    let p = c::palette(ui);
    let mut ouvrir = None;

    let mut apps = data.apps.clone();
    apps.sort_by(|a, b| {
        b.attention()
            .cmp(&a.attention())
            .then_with(|| a.name.cmp(&b.name))
    });

    ui.horizontal(|ui| {
        c::titre(ui, "Applications");
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            c::legende(
                ui,
                &hlb_api::pluriel(apps.len() as u64, "installée", "installées"),
            );
        });
    });
    ui.add_space(mesures::ESPACE);

    if apps.is_empty() {
        c::etat_vide(
            ui,
            "Aucune application installée.",
            Some("hlb install <app> --domain <domaine> --apply"),
        );
        return None;
    }

    for a in &apps {
        if carte_app(ui, a, etroit, p) {
            ouvrir = Some(a.name.clone());
        }
        ui.add_space(mesures::ESPACE);
    }
    ouvrir
}

/// Rend `true` si la carte a été cliquée.
fn carte_app(ui: &mut egui::Ui, a: &AppSummary, etroit: bool, p: crate::design::Palette) -> bool {
    let att = a.attention();
    let reponse = c::carte_attention(ui, att, |ui| {
        ui.horizontal(|ui| {
            c::monogramme(ui, &a.name, p.attention_de(att), 28.0);
            ui.add_space(mesures::ESPACE_SERRE);

            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&a.name)
                            .size(c::taille::SOUS_TITRE)
                            .strong()
                            .color(p.texte),
                    );
                    c::etat(ui, att);
                });
                if let Some(d) = &a.domain {
                    c::mono(ui, d);
                }
            });

            if !etroit {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    // 🔴 « JAMAIS » et « 0 s » ne sont pas la même chose : la seconde
                    // veut dire « sauvegardée à l'instant », soit l'exact contraire. La
                    // distinction vient du type (`Option`), et l'affichage la conserve.
                    let teinte = match a.last_backup_secs {
                        None => p.critique,
                        Some(s) if s > 86_400 => p.critique,
                        _ => p.texte_faible,
                    };
                    ui.label(
                        RichText::new(a.backup_label())
                            .size(c::taille::LEGENDE)
                            .color(teinte),
                    );
                    ui.label(
                        RichText::new("sauvegarde")
                            .size(c::taille::LEGENDE)
                            .color(p.texte_faible),
                    );
                });
            }
        });

        if etroit {
            ui.add_space(mesures::ESPACE_SERRE);
            c::ligne(ui, "sauvegarde", &a.backup_label());
        }

        if a.blocking_guides > 0 {
            ui.add_space(mesures::ESPACE_SERRE);
            c::badge(
                ui,
                &format!(
                    "{} bloquante{}",
                    hlb_api::pluriel(
                        a.blocking_guides.max(0) as u64,
                        "action manuelle",
                        "actions manuelles"
                    ),
                    if a.blocking_guides > 1 { "s" } else { "" }
                ),
                p.attention,
            );
        }
    });

    // ⚠️ La carte ENTIÈRE est cliquable, pas seulement le titre : une cible de la
    // taille d'un mot est pénible à la souris et impossible au doigt.
    reponse
        .interact(egui::Sense::click())
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_api::Attention;

    fn app(nom: &str, statut: &str, backup: Option<i64>) -> AppSummary {
        AppSummary {
            name: nom.into(),
            status: statut.into(),
            image: "x/y:1".into(),
            domain: None,
            last_backup_secs: backup,
            last_verification_secs: None,
            blocking_guides: 0,
        }
    }

    #[test]
    fn the_worst_app_comes_first() {
        // 🔴 Sur vingt apps, une app en échec triée par nom se perdrait au milieu.
        let mut v = [
            app("aaa", "running", Some(60)),
            app("zzz", "failed", Some(60)),
            app("mmm", "running", None),
        ];
        v.sort_by(|a, b| {
            b.attention()
                .cmp(&a.attention())
                .then_with(|| a.name.cmp(&b.name))
        });
        assert_eq!(v[2].name, "aaa", "la seule app saine doit finir dernière");
        assert_eq!(v[0].attention(), Attention::Critical);
    }

    #[test]
    fn the_order_is_stable_between_two_frames() {
        // Un tri qui varierait ferait sauter les cartes sous le curseur.
        let mut v = [
            app("b", "running", Some(60)),
            app("a", "running", Some(60)),
            app("c", "running", Some(60)),
        ];
        v.sort_by(|x, y| {
            y.attention()
                .cmp(&x.attention())
                .then_with(|| x.name.cmp(&y.name))
        });
        assert_eq!(
            v.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
    }

    #[test]
    fn never_backed_up_is_shown_differently_from_just_backed_up() {
        assert_eq!(app("x", "running", None).backup_label(), "JAMAIS");
        assert_eq!(app("x", "running", Some(0)).backup_label(), "0 s");
    }
}
