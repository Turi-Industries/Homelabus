//! Sécurité : ce qui est réellement joignable depuis l'internet.
//!
//! ## 🔴 Pourquoi cet écran existe (§11bis, lot 9.10)
//!
//! Le manifest déclare `expose` ; la configuration Caddy décide. Les deux informations
//! existent et personne ne les met côte à côte — une app publiée par erreur est donc
//! totalement invisible. Le plan dit que « c'est facile de se tromper » ; c'est
//! précisément ce qu'on ne pouvait pas voir.
//!
//! ## Ce que l'écran refuse de faire
//!
//! Il ne conclut jamais « conforme » faute d'information. Si la configuration d'entrée
//! n'a jamais été appliquée, on ne sait pas ce qui répond — et un écran vert obtenu par
//! ignorance serait pire qu'un écran absent : il attesterait d'une vérification qui n'a
//! pas eu lieu.

use hlb_api::{breakglass::GardeFou, ExpositionSummary};

use crate::client::Freshness;
use crate::design::{composants as c, mesures};

/// Ce que l'écran demande.
pub enum Demande {
    /// Attester un garde-fou d'accès de secours.
    Attester(String),
}

pub fn afficher(
    ui: &mut egui::Ui,
    exposition: Option<&Vec<ExpositionSummary>>,
    secours: Option<&Vec<GardeFou>>,
    fraicheur: &Freshness,
) -> Option<Demande> {
    c::titre(ui, "Sécurité");
    ui.add_space(mesures::ESPACE_SERRE);

    let demande = acces_de_secours(ui, secours);
    ui.add_space(mesures::ESPACE_LARGE);

    runbook(ui);
    ui.add_space(mesures::ESPACE_LARGE);

    let Some(liste) = exposition else {
        c::etat_vide(ui, &fraicheur.describe(), None);
        return demande;
    };

    c::sous_titre(ui, "Exposition");
    ui.add_space(mesures::ESPACE_SERRE);
    c::legende(
        ui,
        "Ce que chaque application demande, face à ce qui a été réellement posé à la \
         dernière application de la configuration d'entrée.",
    );
    ui.add_space(mesures::ESPACE_SERRE);

    if liste.is_empty() {
        c::etat_vide(
            ui,
            "Aucune application n'expose de route.",
            Some("hlb ingress apply"),
        );
        return demande;
    }

    let divergentes = liste.iter().filter(|e| e.divergence.is_some()).count();
    if divergentes > 0 {
        c::bandeau(
            ui,
            c::palette(ui).critique,
            &format!(
                "{} entre ce qui est déclaré et ce qui répond.",
                hlb_api::plural(divergentes as u64, "divergence", "divergences")
            ),
            Some(
                "Une app publiée par erreur ne se voit nulle part ailleurs : ni dans \
                 le manifest, qui dit le contraire, ni dans la liste des apps.",
            ),
        );
        ui.add_space(mesures::ESPACE);
    }

    for e in liste {
        c::carte_attention(ui, e.attention(), |ui| {
            ui.horizontal(|ui| {
                c::pastille(ui, e.attention());
                ui.add_space(mesures::ESPACE_SERRE);
                c::mono(ui, &e.hote);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Ce que le manifest DEMANDE, à droite : c'est la référence
                    // contre laquelle on lit la ligne.
                    c::legende(ui, &e.declaree);
                });
            });
            ui.add_space(mesures::ESPACE_SERRE);
            c::texte_libre(ui, &e.describe());
        });
        ui.add_space(mesures::ESPACE_SERRE);
    }

    demande
}

/// Le runbook imprimable (§9quater, lot 10.3).
///
/// ⚠️ Pas de bouton « télécharger » : dans un artefact wasm servi sous CSP, un
/// téléchargement lancé par la page est inerte. On donne l'adresse et la commande, qui
/// marchent depuis n'importe où — y compris depuis une autre machine, ce qui est
/// justement le cas d'usage d'un runbook.
fn runbook(ui: &mut egui::Ui) {
    c::sous_titre(ui, "Runbook");
    ui.add_space(mesures::ESPACE_SERRE);
    c::legende(
        ui,
        "Engendré depuis l'état réel à l'instant où tu le demandes : inventaire des \
         nœuds, destinations, ordre de redémarrage et procédure de reprise. Écrit à la \
         main, un runbook est faux le jour où l'on en a besoin.",
    );
    ui.add_space(mesures::ESPACE_SERRE);
    c::mono(
        ui,
        "curl -H \"Authorization: Bearer <jeton>\" <controller>/api/runbook",
    );
    ui.add_space(mesures::ESPACE_SERRE);
    c::legende(
        ui,
        "À imprimer et à ranger HORS du cluster : un runbook qui ne survit pas à la \
         panne qu'il documente ne documente rien.",
    );
}

/// Les quatre garde-fous du §5.7bis.
///
/// 🔴 En TÊTE de l'écran de sécurité : un SSO centralisé est un point de défaillance
/// unique sur l'accès. Si PocketID tombe, on ne peut plus se connecter ici — donc plus
/// piloter sa restauration. C'est la seule panne dont on ne se sort pas depuis
/// l'interface.
fn acces_de_secours(ui: &mut egui::Ui, secours: Option<&Vec<GardeFou>>) -> Option<Demande> {
    let mut demande = None;
    let liste = secours.filter(|l| !l.is_empty())?;

    c::sous_titre(ui, "Accès de secours");
    ui.add_space(mesures::ESPACE_SERRE);
    c::texte_libre(ui, &hlb_api::breakglass::verdict(liste));
    ui.add_space(mesures::ESPACE_SERRE);
    c::legende(
        ui,
        "Homelabus ne peut vérifier lui-même que le dernier point. Les trois autres \
         sont des déclarations : il en garde la date, et redemande quand elle vieillit.",
    );
    ui.add_space(mesures::ESPACE_SERRE);

    for g in liste {
        c::carte_attention(ui, g.attention(), |ui| {
            ui.horizontal(|ui| {
                c::pastille(ui, g.attention());
                ui.add_space(mesures::ESPACE_SERRE);
                c::texte_libre(ui, &g.titre);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    c::legende(ui, &g.etat());
                });
            });

            ui.add_space(mesures::ESPACE_SERRE);
            c::legende(ui, &g.pourquoi);
            ui.add_space(mesures::ESPACE_SERRE);
            c::mono(ui, &g.comment);

            ui.add_space(mesures::ESPACE_SERRE);
            if g.verifiable {
                // ⚠️ Pas de bouton : ce garde-fou se PROUVE, il ne se déclare pas.
                // Offrir de le cocher permettrait de peindre en vert le point le plus
                // important sans qu'aucun exercice n'ait eu lieu.
                c::legende(
                    ui,
                    "Vérifié par Homelabus : la trace d'un exercice réussi fait foi, \
                     et rien d'autre.",
                );
            } else if ui.button("J'ai vérifié ce point").clicked() {
                demande = Some(Demande::Attester(g.id.clone()));
            }
        });
        ui.add_space(mesures::ESPACE_SERRE);
    }

    demande
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_security_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("securite.rs");
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
