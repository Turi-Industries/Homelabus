//! Le tableau de bord.
//!
//! ## L'objectif, unique et non négociable (§11bis)
//!
//! Répondre à « **est-ce que quelque chose ne va pas ?** » en deux secondes.
//!
//! D'où la règle de composition : **rien de vert n'a besoin d'être grand.** L'écran est
//! majoritairement calme, et l'anomalie est la seule chose qui attire l'œil. Un tableau
//! de bord où tout crie ne se lit plus — et c'est le jour où quelque chose crie
//! vraiment qu'on ne le voit pas.

use egui::{Align, Layout};
use hlb_api::Attention;

use crate::client::Snapshot;
use crate::design::{composants as c, mesures};

pub fn afficher(ui: &mut egui::Ui, data: &Snapshot, etroit: bool) {
    let p = c::palette(ui);

    let critiques = data
        .apps
        .iter()
        .filter(|a| a.attention() == Attention::Critical)
        .count();
    let a_voir = data
        .apps
        .iter()
        .filter(|a| a.attention() == Attention::Notice)
        .count();
    let bloquants: i64 = data.todo.iter().filter(|g| g.blocking).count() as i64;
    let jamais = data
        .apps
        .iter()
        .filter(|a| a.last_backup_secs.is_none())
        .count();

    ui.horizontal(|ui| {
        c::titre(ui, "Tableau de bord");
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if let Some(h) = &data.health {
                c::legende(ui, &format!("controller {} · {}", h.version, h.status));
            }
        });
    });
    ui.add_space(mesures::ESPACE);

    // 🔴 Le verdict d'abord, en une phrase. Un tableau de chiffres oblige à faire la
    // synthèse soi-même, et c'est exactement le travail qu'on veut éviter à 3 h du
    // matin.
    let (teinte, verdict) = if critiques > 0 {
        (
            p.critique,
            format!(
                "{} demande{} une action.",
                hlb_api::plural(critiques as u64, "application", "applications"),
                if critiques > 1 { "nt" } else { "" }
            ),
        )
    } else if a_voir > 0 || bloquants > 0 {
        (
            p.attention,
            format!(
                "{a_voir} à surveiller, {} en attente.",
                hlb_api::plural(
                    bloquants.max(0) as u64,
                    "action manuelle",
                    "actions manuelles"
                )
            ),
        )
    } else {
        (p.ok, "Rien à signaler.".to_string())
    };
    c::bandeau(
        ui,
        teinte,
        &verdict,
        (jamais > 0).then_some(
            "Dont des applications qui n'ont JAMAIS été sauvegardées : elles tournent \
             parfaitement et leurs données ne sont protégées par rien.",
        ),
    );
    ui.add_space(mesures::ESPACE_LARGE);

    // Les chiffres, en tuiles.
    let tuiles: Vec<(&str, String, Option<String>, egui::Color32)> = vec![
        (
            "Applications",
            data.apps.len().to_string(),
            Some(format!("{critiques} en alerte")),
            if critiques > 0 { p.critique } else { p.texte },
        ),
        (
            "Jamais sauvegardées",
            jamais.to_string(),
            (jamais > 0).then(|| "aucune copie".to_string()),
            if jamais > 0 { p.critique } else { p.ok },
        ),
        (
            "Actions manuelles",
            data.todo.len().to_string(),
            Some(format!(
                "dont {}",
                hlb_api::plural(bloquants.max(0) as u64, "bloquante", "bloquantes")
            )),
            if bloquants > 0 { p.attention } else { p.texte },
        ),
        (
            "Secrets",
            data.secrets.len().to_string(),
            Some("valeurs jamais exposées".to_string()),
            p.texte,
        ),
    ];

    if etroit {
        for (l, v, s, t) in &tuiles {
            c::carte(ui, |ui| c::tuile_stat(ui, l, v, s.as_deref(), *t));
            ui.add_space(mesures::ESPACE_SERRE);
        }
    } else {
        ui.columns(tuiles.len(), |col| {
            for (i, (l, v, s, t)) in tuiles.iter().enumerate() {
                c::carte(&mut col[i], |ui| c::tuile_stat(ui, l, v, s.as_deref(), *t));
            }
        });
    }

    ui.add_space(mesures::ESPACE_LARGE);

    // Ce qui ne va pas, et rien d'autre.
    let mut ennuis: Vec<_> = data
        .apps
        .iter()
        .filter(|a| a.attention() != Attention::Ok)
        .collect();
    ennuis.sort_by(|a, b| {
        b.attention()
            .cmp(&a.attention())
            .then_with(|| a.name.cmp(&b.name))
    });

    c::sous_titre(ui, "Ce qui demande de l'attention");
    ui.add_space(mesures::ESPACE_SERRE);

    if ennuis.is_empty() {
        // ⚠️ Pas de liste des apps saines ici : « rien de vert n'a besoin d'être
        // grand », et les lister ferait défiler l'écran pour rien.
        c::etat_vide(ui, "Toutes les applications vont bien.", None);
        return;
    }

    for a in ennuis {
        let att = a.attention();
        c::carte_attention(ui, att, |ui| {
            ui.horizontal(|ui| {
                c::pastille(ui, att);
                ui.add_space(mesures::ESPACE_SERRE);
                ui.vertical(|ui| {
                    c::sous_titre(ui, &a.name);
                    c::legende(ui, &raison(a, &p));
                });
            });
        });
        ui.add_space(mesures::ESPACE_SERRE);
    }
}

/// **Pourquoi** cette app demande de l'attention.
///
/// 🔴 Un voyant rouge sans motif oblige à ouvrir l'app pour comprendre. Or les trois
/// causes se réparent différemment : jamais sauvegardée, sauvegarde périmée, service en
/// échec.
fn raison(a: &hlb_api::AppSummary, _p: &crate::design::Palette) -> String {
    if a.last_backup_secs.is_none() {
        return "jamais sauvegardée — elle tourne, et ses données ne sont protégées par rien"
            .to_string();
    }
    if a.status == "failed" {
        return "le service est en échec".to_string();
    }
    if a.last_backup_secs.is_some_and(|s| s > 86_400) {
        return format!(
            "dernière sauvegarde il y a {} — plus rien ne part depuis",
            a.backup_label()
        );
    }
    if a.blocking_guides > 0 {
        return format!(
            "{} bloque{} le déploiement",
            hlb_api::plural(
                a.blocking_guides.max(0) as u64,
                "action manuelle",
                "actions manuelles"
            ),
            if a.blocking_guides > 1 { "nt" } else { "" }
        );
    }
    if a.status == "partial" {
        return "déploiement partiel : tous les réplicas ne tournent pas".to_string();
    }
    "à surveiller".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_api::AppSummary;

    fn app(nom: &str, statut: &str, backup: Option<i64>, guides: i64) -> AppSummary {
        AppSummary {
            name: nom.into(),
            status: statut.into(),
            image: "x/y:1".into(),
            domain: None,
            last_backup_secs: backup,
            last_verification_secs: None,
            blocking_guides: guides,
        }
    }

    #[test]
    fn each_cause_gets_its_own_wording() {
        // 🔴 Les trois causes de « critique » se réparent différemment. Un message
        // unique obligerait à ouvrir l'app pour savoir laquelle c'est.
        let p = crate::design::Theme::turi_sombre().palette;
        let jamais = raison(&app("a", "running", None, 0), &p);
        let perimee = raison(&app("a", "running", Some(90_000), 0), &p);
        let echec = raison(&app("a", "failed", Some(60), 0), &p);
        let guides = raison(&app("a", "running", Some(60), 2), &p);

        for (n, m) in [
            ("jamais", &jamais),
            ("périmée", &perimee),
            ("échec", &echec),
            ("guides", &guides),
        ] {
            assert!(!m.is_empty(), "{n}");
        }
        let tous = [&jamais, &perimee, &echec, &guides];
        for i in 0..tous.len() {
            for j in (i + 1)..tous.len() {
                assert_ne!(tous[i], tous[j], "deux causes portent le même message");
            }
        }
    }

    #[test]
    fn never_backed_up_wins_over_every_other_cause() {
        // Une app en échec ET jamais sauvegardée : c'est l'absence de sauvegarde qu'il
        // faut dire, parce que c'est elle qui est irréversible.
        let p = crate::design::Theme::turi_sombre().palette;
        let m = raison(&app("a", "failed", None, 3), &p);
        assert!(m.contains("jamais"), "{m}");
    }

    #[test]
    fn no_dashboard_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("tableau_bord.rs");
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
