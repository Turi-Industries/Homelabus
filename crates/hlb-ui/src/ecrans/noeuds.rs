//! Les nœuds du cluster.
//!
//! ## 🔴 Un nœud injoignable n'est pas un nœud sain
//!
//! C'est le piège central de cet écran. Une machine qui ne répond pas n'a pas de
//! mauvais chiffres à montrer : elle n'en a **aucun**. Si on la range avec les autres,
//! ses jauges vides se lisent « rien à signaler » — alors que ses données ne sont plus
//! sauvegardées et qu'on ignore l'état de son disque.
//!
//! Elle est donc marquée, expliquée, et remontée en tête.
//!
//! ## Et un agent qui parle un vieux protocole n'est pas un agent muet
//!
//! Pendant une mise à jour, une partie du parc reste en protocole 1 : ses mesures
//! système sont absentes. « Inconnu » et « 0 % » ne s'affichent pas pareil.

use egui::{Align, Layout};
use hlb_api::NoeudSummary;

use crate::client::Freshness;
use crate::design::{composants as c, mesures};

/// La version de dialogue que le controller courant attend.
///
/// Un agent en dessous fonctionne — c'est tout l'intérêt de la compatibilité N/N+1 —
/// mais ses mesures système manquent, et il faut savoir pourquoi.
const PROTOCOLE_COURANT: u32 = 2;

pub fn afficher(
    ui: &mut egui::Ui,
    noeuds: Option<&Vec<NoeudSummary>>,
    fraicheur: &Freshness,
    etroit: bool,
) {
    let p = c::palette(ui);

    ui.horizontal(|ui| {
        c::titre(ui, "Nœuds");
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if let Some(n) = noeuds {
                let muets = n.iter().filter(|x| !x.joignable).count();
                c::legende(
                    ui,
                    &match muets {
                        0 => hlb_api::pluriel(n.len() as u64, "nœud", "nœuds"),
                        m => format!(
                            "{}, dont {} injoignable{}",
                            hlb_api::pluriel(n.len() as u64, "nœud", "nœuds"),
                            m,
                            if m > 1 { "s" } else { "" }
                        ),
                    },
                );
            }
        });
    });
    ui.add_space(mesures::ESPACE);

    let Some(noeuds) = noeuds else {
        // ⚠️ On distingue « pas encore chargé » de « aucun nœud ». Le second serait un
        // cluster vide, ce qui n'arrive pas — et l'afficher ferait chercher une panne
        // là où il n'y a qu'une requête en cours.
        c::etat_vide(ui, &fraicheur.describe(), None);
        return;
    };

    if noeuds.is_empty() {
        c::etat_vide(
            ui,
            "Aucun agent ne rapporte. Le service d'agent est-il déployé ?",
            Some("hlb node add <hôte> --apply"),
        );
        return;
    }

    for n in noeuds {
        carte_noeud(ui, n, etroit, p);
        ui.add_space(mesures::ESPACE);
    }
}

fn carte_noeud(ui: &mut egui::Ui, n: &NoeudSummary, etroit: bool, p: crate::design::Palette) {
    let att = n.attention();
    c::carte_attention(ui, att, |ui| {
        ui.horizontal(|ui| {
            c::pastille(ui, att);
            ui.add_space(mesures::ESPACE_SERRE);
            ui.vertical(|ui| {
                // Le nom d'hôte s'il est connu, l'adresse sinon — et jamais l'inverse :
                // c'est l'adresse qui est l'identité stable.
                c::sous_titre(ui, n.hostname.as_deref().unwrap_or(&n.adresse));
                c::mono(ui, &n.adresse);
            });

            if !etroit {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if let Some(v) = &n.agent_version {
                        // ⚠️ Un parc dépareillé est un piège (§7bis) : un agent resté
                        // en protocole 1 est signalé, parce que ses mesures manquantes
                        // ne sont PAS une panne — c'est une mise à jour inachevée.
                        let teinte = match n.protocole {
                            Some(pr) if pr < PROTOCOLE_COURANT => p.attention,
                            _ => p.texte_faible,
                        };
                        c::badge(ui, &format!("agent {v}"), teinte);
                    }
                });
            }
        });

        if let Some(r) = n.raison() {
            ui.add_space(mesures::ESPACE_SERRE);
            c::texte_libre(ui, &r);
        }

        // 🔴 Un nœud injoignable s'arrête ici : il n'a AUCUNE mesure. Peindre des
        // jauges vides donnerait l'apparence d'une machine au repos.
        if !n.joignable {
            return;
        }

        ui.add_space(mesures::ESPACE);
        mesure(ui, "CPU", n.cpu_occupation, teinte_taux, p);
        mesure(ui, "Mémoire", n.memoire_utilisee, teinte_taux, p);
        if let Some(s) = n.swap_utilise.filter(|s| *s > 0.0) {
            // 🔴 Le swap a ses PROPRES seuils, bien plus bas. Constaté à l'écran : avec
            // l'échelle du CPU, un swap à 71 % s'affichait en vert — or une machine qui
            // échange déjà 70 % de son swap est en train de ramer, pas « dans le
            // vert ». Un swap qui sert du tout est un signal.
            mesure(ui, "Swap", Some(s), teinte_swap, p);
        }
        if let Some(ch) = n.charge_par_coeur {
            // La charge par cœur n'est pas bornée à 1 : on l'écrit plutôt que de la
            // peindre en jauge, sinon 2.5 remplirait la barre comme 1.0.
            c::ligne(ui, "Charge par cœur", &format!("{ch:.2}"));
        }

        for d in &n.disques {
            ui.add_space(mesures::ESPACE_SERRE);
            ui.horizontal(|ui| {
                c::mono(ui, &d.chemin);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    c::legende(
                        ui,
                        &format!(
                            "{} libres",
                            hlb_api::octets(d.libre_mb as f64 * 1_048_576.0)
                        ),
                    );
                });
            });
            c::jauge(
                ui,
                d.utilise as f32,
                teinte_pression(d.pression, p),
                ui.available_width(),
            );
        }

        if !n.taches.is_empty() && !etroit {
            ui.add_space(mesures::ESPACE_SERRE);
            c::legende(ui, &format!("héberge : {}", n.taches.join(", ")));
        }

        if let Some(u) = n.uptime_s {
            // Un redémarrage récent explique beaucoup de choses, et on n'y pense pas.
            let libelle = hlb_api::humanise(u as i64);
            c::ligne(ui, "En route depuis", &libelle);
        }
    });
}

/// Une mesure en jauge, ou « inconnu » — jamais zéro.
///
/// `teinte` est un paramètre : chaque grandeur a ses seuils. Les partager ferait
/// afficher en vert un swap à 70 %, qui est un problème, parce qu'un CPU à 70 % n'en
/// est pas un.
fn mesure(
    ui: &mut egui::Ui,
    nom: &str,
    v: Option<f64>,
    teinte: fn(f64, crate::design::Palette) -> egui::Color32,
    p: crate::design::Palette,
) {
    ui.horizontal(|ui| {
        c::legende(ui, nom);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| match v {
            Some(v) => c::legende(ui, &format!("{:.0} %", v * 100.0)),
            // 🔴 « inconnu » et non « 0 % » : le second se lit « au repos », soit
            // exactement le contraire.
            None => c::legende(ui, "inconnu"),
        });
    });
    if let Some(v) = v {
        c::jauge(ui, v as f32, teinte(v, p), ui.available_width());
    }
}

fn teinte_taux(v: f64, p: crate::design::Palette) -> egui::Color32 {
    if v >= 0.90 {
        p.critique
    } else if v >= 0.75 {
        p.attention
    } else {
        p.ok
    }
}

/// Les seuils du SWAP, distincts de ceux du CPU.
///
/// 🔴 Beaucoup plus bas, et c'est voulu : un swap qui commence à servir signale une
/// machine qui ralentit avant de tomber (§9bis). Attendre 90 % comme pour le CPU, ce
/// serait attendre que la machine soit inutilisable.
fn teinte_swap(v: f64, p: crate::design::Palette) -> egui::Color32 {
    if v >= 0.50 {
        p.critique
    } else if v >= 0.05 {
        p.attention
    } else {
        p.ok
    }
}

fn teinte_pression(palier: u8, p: crate::design::Palette) -> egui::Color32 {
    match palier {
        0 => p.ok,
        1 | 2 => p.attention,
        _ => p.critique,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_api::Attention;

    fn noeud(joignable: bool) -> NoeudSummary {
        NoeudSummary {
            adresse: "10.0.0.1:8421".into(),
            hostname: Some("n1".into()),
            joignable,
            detail: None,
            rapport_age_s: Some(30),
            cpu_occupation: None,
            charge_par_coeur: None,
            memoire_utilisee: None,
            swap_utilise: None,
            disques: Vec::new(),
            uptime_s: None,
            distro: None,
            noyau: None,
            agent_version: None,
            protocole: None,
            taches: Vec::new(),
        }
    }

    #[test]
    fn an_unreachable_node_never_shows_empty_gauges() {
        // 🔴 Le piège : une machine qui ne répond pas n'a pas de mauvais chiffres, elle
        // n'en a AUCUN. Des jauges à zéro se liraient « au repos ».
        let n = noeud(false);
        assert_eq!(n.attention(), Attention::Critical);
        assert!(n.raison().is_some(), "l'absence doit être expliquée");
    }

    #[test]
    fn a_gauge_colour_escalates_with_the_value() {
        let p = crate::design::Theme::turi_sombre().palette;
        assert_eq!(teinte_taux(0.10, p), p.ok);
        assert_eq!(teinte_taux(0.80, p), p.attention);
        assert_eq!(teinte_taux(0.95, p), p.critique);
    }

    #[test]
    fn swap_has_its_own_thresholds() {
        // 🔴 Constaté à l'écran : avec l'échelle du CPU, un swap à 71 % s'affichait en
        // VERT. Une machine qui échange déjà 70 % de son swap rame — elle n'est pas
        // « dans le vert ».
        let p = crate::design::Theme::turi_sombre().palette;
        assert_eq!(
            teinte_swap(0.71, p),
            p.critique,
            "un swap à 71 % est critique"
        );
        assert_eq!(teinte_taux(0.71, p), p.ok, "un CPU à 71 % ne l'est pas");

        assert_eq!(teinte_swap(0.03, p), p.ok, "quelques pages, c'est normal");
        assert_eq!(teinte_swap(0.10, p), p.attention, "ça commence à servir");
    }

    #[test]
    fn disk_pressure_maps_to_three_colours_not_five() {
        // Cinq paliers, trois couleurs : au-delà, l'œil ne distingue plus, et « avis »
        // contre « récupération » est une nuance qui n'aide pas à décider.
        let p = crate::design::Theme::turi_sombre().palette;
        assert_eq!(teinte_pression(0, p), p.ok);
        assert_eq!(teinte_pression(1, p), p.attention);
        assert_eq!(teinte_pression(2, p), p.attention);
        assert_eq!(teinte_pression(3, p), p.critique);
        assert_eq!(teinte_pression(4, p), p.critique);
    }

    #[test]
    fn no_node_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("noeuds.rs");
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
