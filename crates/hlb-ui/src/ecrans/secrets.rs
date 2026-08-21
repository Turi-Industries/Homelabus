//! L'inventaire des secrets : leurs **noms** et leurs **usages**.
//!
//! ## 🔴 Jamais les valeurs, et la garantie est structurelle
//!
//! `hlb_api::SecretItem` n'a **aucun champ** pour porter une valeur. Ce n'est pas une
//! discipline d'affichage qu'on pourrait oublier : on ne peut pas fuiter ce qu'on ne
//! peut pas représenter. Un test de `hlb-api` sérialise le type et vérifie l'absence.

use hlb_api::{rotation::SecretARouler, SecretItem};

use crate::design::{composants as c, mesures};

pub const SECRETS_SANS_VALEUR: &str =
    "Les valeurs ne sortent jamais du coffre, pas même vers cette page : le type de \
     l'API n'a aucun champ pour les porter. Pour en lire une, il faut la clé maîtresse \
     et la ligne de commande.";

pub fn afficher(
    ui: &mut egui::Ui,
    items: &[SecretItem],
    rotation: Option<&Vec<SecretARouler>>,
) {
    c::titre(ui, "Secrets");
    c::legende(ui, SECRETS_SANS_VALEUR);
    ui.add_space(mesures::ESPACE);

    if items.is_empty() {
        c::etat_vide(
            ui,
            "Aucun secret enregistré.",
            Some("hlb install <app> --apply"),
        );
        return;
    }

    c::carte(ui, |ui| {
        egui::Grid::new("secrets")
            .num_columns(2)
            .striped(true)
            .spacing([mesures::ESPACE_LARGE, mesures::ESPACE_SERRE])
            .show(ui, |ui| {
                for s in items {
                    c::mono(ui, &s.name);
                    c::texte_libre(ui, &s.purpose);
                    ui.end_row();
                }
            });
    });

    rotation_assistee(ui, rotation);
}

/// L'assistant de rotation (§9quater, lot 10.1).
///
/// 🔴 Ce qu'il apporte n'est pas « ce secret est vieux » — c'est **ce que le tourner
/// impliquerait**. Le coffre n'est pas la source de vérité d'un mot de passe de base :
/// le tourner ici seul ne change rien, jusqu'au prochain redéploiement où l'app se met
/// à échouer sur « mot de passe incorrect », trois semaines plus tard.
fn rotation_assistee(ui: &mut egui::Ui, rotation: Option<&Vec<SecretARouler>>) {
    let Some(liste) = rotation.filter(|l| !l.is_empty()) else {
        return;
    };

    ui.add_space(mesures::ESPACE_LARGE);
    c::sous_titre(ui, "Rotation");
    ui.add_space(mesures::ESPACE_SERRE);
    c::legende(
        ui,
        "Tourner un secret n'est pas une écriture, c'est une procédure ordonnée. Le \
         coffre ne fait pas autorité : le mot de passe vit AUSSI dans PostgreSQL, chez \
         PocketID ou chez Garage.",
    );
    ui.add_space(mesures::ESPACE_SERRE);

    for s in liste {
        c::carte_attention(ui, s.attention(), |ui| {
            ui.horizontal(|ui| {
                c::pastille(ui, s.attention());
                ui.add_space(mesures::ESPACE_SERRE);
                c::mono(ui, &s.nom);
                ui.with_layout(
                    egui::Layout::right_to_left(egui::Align::Center),
                    |ui| {
                        // ⚠️ « jamais tourné » n'est pas « tourné il y a longtemps » :
                        // l'un est l'état normal d'un secret récent, l'autre un oubli.
                        c::legende(
                            ui,
                            &if s.jamais_tourne {
                                format!("créé il y a {}", hlb_api::humanise(s.age_s))
                            } else {
                                format!("tourné il y a {}", hlb_api::humanise(s.age_s))
                            },
                        );
                    },
                );
            });

            ui.add_space(mesures::ESPACE_SERRE);
            c::legende(ui, s.nature.libelle());
            c::texte_libre(ui, &s.consequence());

            let procedure = s.nature.procedure();
            if procedure.is_empty() {
                // 🔴 On ne devine pas : exécuter les mauvais gestes dans le mauvais
                // ordre, sur le mauvais système, coûte plus cher que ne rien proposer.
                c::legende(
                    ui,
                    "Nature non reconnue : aucune procédure n'est proposée, elle serait \
                     inventée.",
                );
            } else {
                ui.add_space(mesures::ESPACE_SERRE);
                for (i, etape) in procedure.iter().enumerate() {
                    ui.horizontal_top(|ui| {
                        c::mono(ui, &format!("{}.", i + 1));
                        ui.add_space(mesures::ESPACE_SERRE);
                        c::texte_libre(ui, etape);
                    });
                }
            }
        });
        ui.add_space(mesures::ESPACE_SERRE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wording_explains_why_there_is_nothing_to_click() {
        // Sans explication, l'absence de valeur passe pour un écran incomplet, et
        // quelqu'un finit par « corriger » en exposant les secrets.
        assert!(SECRETS_SANS_VALEUR.contains("aucun champ"));
        assert!(SECRETS_SANS_VALEUR.contains("clé maîtresse"));
    }

    #[test]
    fn the_type_cannot_carry_a_value() {
        // La garantie est dans le type, pas dans cet écran.
        let s = SecretItem {
            name: "gitea-db-password".into(),
            purpose: "mot de passe PostgreSQL".into(),
        };
        let j = serde_json::to_string(&s).expect("sérialisable");
        assert!(!j.contains("value"), "{j}");
    }

    #[test]
    fn no_secrets_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("secrets.rs");
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
