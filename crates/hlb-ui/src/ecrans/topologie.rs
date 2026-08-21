//! La topologie : où les choses tournent VRAIMENT.
//!
//! ## 🔴 L'écran qui justifie à lui seul l'existence de l'interface (§11bis)
//!
//! En ligne de commande, `docker node ls` montre trois nœuds et l'on se croit protégé.
//! Deux d'entre eux sont deux machines virtuelles sur le même serveur : le fer tombe,
//! deux tiers du cluster partent avec.
//!
//! L'information existe — elle est dans les étiquettes Swarm — mais elle n'est lisible
//! nulle part. Cet écran la rend visible, et c'est tout son propos.
//!
//! ## Trois choses, dans cet ordre
//!
//! 1. **Le verdict**, en une phrase : ce qu'il faut retenir sans lire le reste.
//! 2. **Les violations d'anti-affinité** : les services qui paraissent redondants et
//!    ne le sont pas.
//! 3. **« Et si ça tombait ? »** — la simulation, domaine par domaine.
//! 4. **Les domaines** et ce qu'ils portent.
//!
//! La simulation est ce qui transforme le dessin en réponse : la carte montre que deux
//! réplicas partagent un fer, elle ne dit pas ce qui s'arrête quand ce fer tombe.
//!
//! Un domaine **non déclaré** n'est jamais présenté comme isolé : on ne sait pas, et
//! supposer l'isolement serait exactement l'hypothèse optimiste qui crée l'illusion.

use egui::{Align, Layout};
use hlb_api::{Attention, Topologie};

use crate::client::Freshness;
use crate::design::{composants as c, mesures};

pub fn afficher(
    ui: &mut egui::Ui,
    topo: Option<&Topologie>,
    fraicheur: &Freshness,
    etroit: bool,
) {
    let p = c::palette(ui);

    c::titre(ui, "Topologie");
    ui.add_space(mesures::ESPACE_SERRE);

    let Some(t) = topo else {
        c::etat_vide(ui, &fraicheur.describe(), None);
        return;
    };

    if t.noeuds_total == 0 {
        // ⚠️ Distinct d'un cluster vide : sans orchestrateur joignable, on ne SAIT pas
        // ce qui tourne. L'afficher comme « aucun nœud » ferait croire à un cluster
        // détruit.
        c::etat_vide(
            ui,
            "Docker est injoignable : la topologie réelle est inconnue.",
            Some("export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')"),
        );
        return;
    }

    let att = t.attention();
    c::bandeau(
        ui,
        p.attention_de(att),
        &t.verdict(),
        (att != Attention::Ok).then_some(
            "L'anti-affinité doit porter sur le FER, pas sur le nœud : deux machines \
             virtuelles du même serveur sont deux nœuds Swarm et un seul point de panne.",
        ),
    );
    ui.add_space(mesures::ESPACE_LARGE);

    if !t.violations.is_empty() {
        c::sous_titre(ui, "Redondance surévaluée");
        ui.add_space(mesures::ESPACE_SERRE);
        for v in &t.violations {
            c::carte_attention(
                ui,
                if v.totale {
                    Attention::Critical
                } else {
                    Attention::Notice
                },
                |ui| {
                    ui.horizontal(|ui| {
                        c::pastille(
                            ui,
                            if v.totale {
                                Attention::Critical
                            } else {
                                Attention::Notice
                            },
                        );
                        ui.add_space(mesures::ESPACE_SERRE);
                        c::texte_libre(ui, &v.explication);
                    });
                },
            );
            ui.add_space(mesures::ESPACE_SERRE);
        }
        ui.add_space(mesures::ESPACE);
    }

    // --- « Et si ça tombait ? » (lot 9.3) --------------------------------------
    //
    // 🔴 On simule un DOMAINE, pas une machine. Simuler nœud par nœud sur une
    // installation où deux VM partagent un serveur conclurait « l'app survit » — ce que
    // l'anti-affinité existe précisément pour empêcher.
    let simulations = hlb_api::panne::simuler_tout(t, &t.managers);
    if !simulations.is_empty() {
        c::sous_titre(ui, "Et si ça tombait ?");
        ui.add_space(mesures::ESPACE_SERRE);
        c::legende(
            ui,
            "Chaque ligne fait tomber un domaine entier. Le pire cas est en tête.",
        );
        ui.add_space(mesures::ESPACE_SERRE);

        for sim in &simulations {
            c::carte_attention(ui, sim.attention(), |ui| {
                ui.horizontal(|ui| {
                    c::pastille(ui, sim.attention());
                    ui.add_space(mesures::ESPACE_SERRE);
                    c::mono(ui, sim.cible.nom());
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        c::legende(
                            ui,
                            &hlb_api::pluriel(
                                sim.noeuds_perdus.len() as u64,
                                "nœud",
                                "nœuds",
                            ),
                        );
                    });
                });
                ui.add_space(mesures::ESPACE_SERRE);
                c::texte_libre(ui, &sim.verdict());

                // Le détail de ce qui survit diminué : un service qui passe de 3 à 1
                // réplica n'est pas intact, et le dire « debout » ferait manquer la
                // panne suivante.
                for d in &sim.services_diminues {
                    c::legende(
                        ui,
                        &format!("   {} : {} réplicas, puis {}", d.service, d.avant, d.apres),
                    );
                }
            });
            ui.add_space(mesures::ESPACE_SERRE);
        }
        ui.add_space(mesures::ESPACE);
    }

    c::sous_titre(ui, "Domaines de panne");
    ui.add_space(mesures::ESPACE_SERRE);

    for d in &t.domaines {
        let att_d = if d.concentre {
            Attention::Notice
        } else {
            Attention::Ok
        };
        c::carte_attention(ui, att_d, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    match &d.nom {
                        Some(n) => c::sous_titre(ui, n),
                        // 🔴 « Non déclaré » et non « isolé » : on ne sait pas.
                        None => c::sous_titre(ui, "Domaine non déclaré"),
                    }
                    if d.nom.is_none() {
                        c::legende(
                            ui,
                            "Ces nœuds partagent peut-être un fer — rien ne permet de le \
                             savoir. Déclare-le : hlb node add --failure-domain <nom>",
                        );
                    } else if d.concentre {
                        c::legende(
                            ui,
                            "Ce fer porte plus de la moitié du cluster : sa perte \
                             emporterait le quorum.",
                        );
                    }
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    c::legende(
                        ui,
                        &hlb_api::pluriel(d.noeuds.len() as u64, "nœud", "nœuds"),
                    );
                });
            });

            ui.add_space(mesures::ESPACE_SERRE);
            for n in &d.noeuds {
                ui.horizontal(|ui| {
                    // Un nœud injoignable dans un domaine sain reste injoignable : la
                    // couleur du domaine ne doit pas masquer l'état du nœud.
                    c::pastille(
                        ui,
                        if n.joignable {
                            Attention::Ok
                        } else {
                            Attention::Critical
                        },
                    );
                    ui.add_space(mesures::ESPACE_SERRE);
                    c::texte_libre(ui, &n.hostname);
                    if let Some(tier) = &n.tier {
                        c::badge(ui, tier, p.info);
                    }
                    if !etroit {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if n.services.is_empty() {
                                c::legende(ui, "aucun service");
                            } else {
                                c::legende(ui, &n.services.join(", "));
                            }
                        });
                    }
                });
                if etroit && !n.services.is_empty() {
                    ui.horizontal(|ui| {
                        ui.add_space(mesures::ESPACE_LARGE);
                        c::legende(ui, &n.services.join(", "));
                    });
                }
            }
        });
        ui.add_space(mesures::ESPACE);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_topology_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("topologie.rs");
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
