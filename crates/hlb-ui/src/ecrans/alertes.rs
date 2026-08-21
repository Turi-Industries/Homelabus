//! Les alertes actives.
//!
//! ## 🔴 Une alerte en sourdine reste affichée
//!
//! La sourdine coupe la **notification**, pas l'écran. La faire disparaître donnerait un
//! tableau de bord vert pour un problème connu et non résolu — la même famille d'erreur
//! que d'afficher des données périmées comme fraîches.
//!
//! Elle est donc visible, marquée, avec l'échéance de sa sourdine et le nom de qui l'a
//! posée.
//!
//! ## Et « non évaluable » n'est pas « tout va bien »
//!
//! Si la collecte tombe, une règle cesse de pouvoir être jugée. Ce n'est pas un seuil
//! respecté : c'est une surveillance aveugle, et ça mérite qu'on regarde.

use egui::{Align, Layout};
use hlb_api::{AlerteActive, Attention, NiveauAlerte};

use crate::client::Freshness;
use crate::design::{composants as c, mesures};

pub fn afficher(
    ui: &mut egui::Ui,
    alertes: Option<&Vec<AlerteActive>>,
    fraicheur: &Freshness,
    maintenant: i64,
) {
    let p = c::palette(ui);

    let Some(alertes) = alertes else {
        c::titre(ui, "Alertes");
        c::etat_vide(ui, &fraicheur.describe(), None);
        return;
    };

    let silencees = alertes
        .iter()
        .filter(|a| a.est_silencee(maintenant))
        .count();
    let aveugles = alertes
        .iter()
        .filter(|a| a.niveau == NiveauAlerte::Inconnu)
        .count();

    ui.horizontal(|ui| {
        c::titre(ui, "Alertes");
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if silencees > 0 {
                c::legende(
                    ui,
                    &format!(
                        "{}, dont {silencees} en sourdine",
                        hlb_api::pluriel(alertes.len() as u64, "active", "actives")
                    ),
                );
            } else {
                c::legende(
                    ui,
                    &hlb_api::pluriel(alertes.len() as u64, "active", "actives"),
                );
            }
        });
    });
    ui.add_space(mesures::ESPACE);

    if alertes.is_empty() {
        c::etat_vide(ui, "Aucune alerte active.", None);
        return;
    }

    if aveugles > 0 {
        c::bandeau(
            ui,
            p.attention,
            &format!(
                "{} ne peu{} plus être évaluée{}.",
                hlb_api::pluriel(aveugles as u64, "règle", "règles"),
                if aveugles > 1 { "vent" } else { "t" },
                if aveugles > 1 { "s" } else { "" }
            ),
            Some(
                "Ce n'est PAS « tout va bien » : la collecte est probablement tombée, et \
                 cette surveillance est aveugle depuis.",
            ),
        );
        ui.add_space(mesures::ESPACE);
    }

    for a in alertes {
        carte_alerte(ui, a, maintenant, p);
        ui.add_space(mesures::ESPACE_SERRE);
    }
}

fn carte_alerte(ui: &mut egui::Ui, a: &AlerteActive, maintenant: i64, p: crate::design::Palette) {
    let att = a.attention(maintenant);
    c::carte_attention(ui, att, |ui| {
        ui.horizontal(|ui| {
            c::pastille(ui, att);
            ui.add_space(mesures::ESPACE_SERRE);
            ui.vertical(|ui| {
                c::sous_titre(ui, &a.regle);
                c::texte_libre(ui, &a.libelle(maintenant));
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                // 🔴 Depuis quand : une alerte qui dure depuis trois jours a été
                // ignorée, ou son remède ne marche pas. Ça ne se traite pas comme une
                // alerte qui vient d'apparaître.
                if a.depuis_s > 0 {
                    c::legende(ui, &format!("depuis {}", hlb_api::humanise(a.depuis_s)));
                }
            });
        });

        ui.add_space(mesures::ESPACE_SERRE);
        match a.valeur {
            Some(v) => c::ligne(ui, "mesuré", &format!("{v:.2} (seuil {:.2})", a.seuil)),
            // 🔴 Pas de valeur : on ne sait pas. Afficher « 0 » dirait « seuil
            // respecté », soit exactement le contraire.
            None => c::ligne(ui, "mesuré", "aucune donnée"),
        }
        let _ = p;
    });
}

/// Le niveau d'attention le plus élevé parmi les alertes — pour le tableau de bord.
pub fn pire(alertes: &[AlerteActive], maintenant: i64) -> Attention {
    alertes
        .iter()
        .map(|a| a.attention(maintenant))
        .max()
        .unwrap_or(Attention::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alerte(niveau: NiveauAlerte, silencee: Option<i64>) -> AlerteActive {
        AlerteActive {
            regle: "disque-plein".into(),
            niveau,
            explication: "un disque dépasse 85 %".into(),
            valeur: Some(0.96),
            seuil: 0.85,
            depuis_s: 3600,
            silencee_jusqu_a: silencee,
            silencee_par: silencee.map(|_| "remy".into()),
        }
    }

    #[test]
    fn a_silenced_alert_is_still_in_the_list() {
        // 🔴 La faire disparaître donnerait un tableau de bord vert pour un problème
        // connu et non résolu.
        let a = alerte(NiveauAlerte::Critique, Some(10_000));
        let l = a.libelle(5_000);
        assert!(l.contains("SOURDINE"), "{l}");
        assert_ne!(
            a.attention(5_000),
            Attention::Ok,
            "silencée n'est pas résolue"
        );
    }

    #[test]
    fn the_worst_alert_drives_the_dashboard() {
        let v = vec![
            alerte(NiveauAlerte::Info, None),
            alerte(NiveauAlerte::Critique, None),
        ];
        assert_eq!(pire(&v, 0), Attention::Critical);
        assert_eq!(pire(&[], 0), Attention::Ok, "aucune alerte = calme");
    }

    #[test]
    fn a_silenced_critical_does_not_drive_the_dashboard_red() {
        // Rétrogradée, pas éteinte : la sourdine dit « je sais », et le tableau de bord
        // ne doit plus crier — mais l'alerte reste visible sur son écran.
        let v = vec![alerte(NiveauAlerte::Critique, Some(10_000))];
        assert_eq!(pire(&v, 5_000), Attention::Notice);
    }

    #[test]
    fn no_alert_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("alertes.rs");
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
