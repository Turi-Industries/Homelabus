//! Le détail d'une application — l'écran où l'on passe le plus de temps (§11bis).
//!
//! ## Les onglets, et pourquoi ils sont séparés
//!
//! Tout mettre sur une page ferait défiler pendant vingt secondes avant d'atteindre les
//! sauvegardes. Chaque onglet répond à une question différente : « ça tourne ? »,
//! « avec quoi c'est câblé ? », « c'est protégé ? », « qui y a touché ? ».
//!
//! ## 🔴 Les jetons de secret restent LITTÉRAUX
//!
//! L'onglet Configuration affiche `{{ db.password }}` tel quel, jamais une valeur ni
//! des astérisques. Deux raisons : la valeur ne traverse pas l'API — le type ne la
//! porte même pas — et un jeton visible dit **à quoi l'app est câblée**, ce que des
//! astérisques ne disent pas. Un jeton irrésolu au déploiement reste d'ailleurs
//! littéral lui aussi, pour la même raison : une variable vide ressemble à une
//! configuration absente.

use egui::{Align, Layout, RichText};
use hlb_api::{AppDetail, Attention};

use crate::client::Freshness;
use crate::design::{composants as c, mesures};
use crate::route::OngletApp;

/// Ce que l'écran demande à la coquille de faire.
pub enum Demande {
    /// Changer d'onglet.
    Onglet(OngletApp),
    /// Lancer une action : `(méthode, chemin, corps, applique)`.
    Action {
        methode: &'static str,
        chemin: String,
        corps: String,
        applique: bool,
    },
    /// Fermer le panneau d'action.
    Fermer,
}

/// Ce que le dispatcher fournit à l'écran de détail.
///
/// ⚠️ Un enregistrement plutôt que huit arguments : la liste s'allongeait à chaque
/// onglet, et deux paramètres du même type côte à côte finissent par s'intervertir sans
/// que le compilateur s'en aperçoive.
pub struct Vue<'a> {
    pub detail: Option<&'a AppDetail>,
    pub fraicheur: &'a Freshness,
    pub action: &'a crate::client::ActionEnCours,
    /// L'historique des manifests (§9.11). `None` = pas encore chargé.
    pub versions: Option<&'a Vec<hlb_api::VersionManifest>>,
    pub etroit: bool,
}

pub fn afficher(ui: &mut egui::Ui, nom: &str, onglet: OngletApp, vue: Vue<'_>) -> Option<Demande> {
    let Vue {
        detail,
        fraicheur,
        action,
        versions,
        etroit,
    } = vue;
    let p = c::palette(ui);
    let mut demande = None;

    let Some(d) = detail else {
        c::titre(ui, nom);
        c::etat_vide(ui, &fraicheur.describe(), None);
        return None;
    };

    let att = d.resume.attention();

    ui.horizontal(|ui| {
        c::monogramme(ui, nom, p.attention_de(att), 30.0);
        ui.add_space(mesures::ESPACE_SERRE);
        ui.vertical(|ui| {
            c::titre(ui, nom);
            if let Some(dom) = &d.domaine {
                c::mono(ui, dom);
            }
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            c::etat(ui, att);
        });
    });
    ui.add_space(mesures::ESPACE);

    // Les onglets. En étroit, ils défilent horizontalement : au-delà de quatre, les
    // derniers sortiraient de l'écran et deviendraient inatteignables.
    egui::ScrollArea::horizontal()
        .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
        .id_salt("onglets-app")
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                for o in OngletApp::tous() {
                    if !implemente(o) {
                        // 🔴 On ne propose que ce qui existe : un onglet qui mène à
                        // « à venir » promet, on clique, on n'a rien, et on doute du
                        // reste de l'écran.
                        continue;
                    }
                    let actif = o == onglet;
                    let libelle = if etroit { court(o) } else { o.libelle() };
                    let texte = RichText::new(libelle)
                        .size(c::taille::CORPS)
                        .color(if actif { p.accent } else { p.texte_faible });
                    if ui.selectable_label(actif, texte).clicked() {
                        demande = Some(Demande::Onglet(o));
                    }
                }
            });
        });
    ui.add_space(mesures::ESPACE);

    // ⚠️ Le panneau d'action est affiché par le dispatcher, pour TOUS les écrans :
    // une action déclenchée d'ici ou d'ailleurs se montre au même endroit.
    let _ = action;

    match onglet {
        OngletApp::Apercu => {
            if let Some(dd) = actions_app(ui, nom, d, etroit) {
                return Some(dd);
            }
            apercu(ui, d, p)
        }
        OngletApp::Config => config(ui, d, etroit),
        OngletApp::Sauvegardes => sauvegardes(ui, d, p),
        OngletApp::Historique => historique(ui, d, versions),
        autre => {
            c::etat_vide(
                ui,
                &format!("L'onglet « {} » n'est pas encore écrit.", autre.libelle()),
                None,
            );
        }
    }

    demande
}

/// Les boutons d'action de l'app.
///
/// ⚠️ Chacun lance un **aperçu**, jamais l'action : c'est le panneau qui, ensuite,
/// propose d'appliquer. Un bouton qui agirait directement transformerait un clic
/// distrait en installation.
fn actions_app(ui: &mut egui::Ui, nom: &str, d: &AppDetail, etroit: bool) -> Option<Demande> {
    let mut demande = None;
    let _ = etroit;

    c::carte(ui, |ui| {
        c::sous_titre(ui, "Actions");
        ui.add_space(mesures::ESPACE_SERRE);
        ui.horizontal_wrapped(|ui| {
            if ui.button("Sauvegarder maintenant").clicked() {
                demande = Some(Demande::Action {
                    methode: "POST",
                    chemin: format!("/api/apps/{nom}/backup"),
                    corps: "{}".into(),
                    applique: false,
                });
            }

            let (_, voulus) = d.replicas();
            let cible = voulus as u64 + 1;
            if ui
                .button(format!(
                    "Passer à {}",
                    hlb_api::plural(cible, "réplica", "réplicas")
                ))
                .clicked()
            {
                demande = Some(Demande::Action {
                    methode: "POST",
                    chemin: format!("/api/apps/{nom}/scale"),
                    corps: format!(r#"{{"replicas":{cible}}}"#),
                    applique: false,
                });
            }

            // 🔴 La suppression est visuellement distincte, et son aperçu montre ce
            // qu'elle emporte AVANT toute confirmation.
            let p = c::palette(ui);
            if ui
                .button(RichText::new("Supprimer…").color(p.critique))
                .clicked()
            {
                demande = Some(Demande::Action {
                    methode: "DELETE",
                    chemin: format!("/api/apps/{nom}"),
                    corps: "{}".into(),
                    applique: false,
                });
            }
        });
    });
    ui.add_space(mesures::ESPACE);
    demande
}

/// Cet onglet est-il écrit ?
fn implemente(o: OngletApp) -> bool {
    matches!(
        o,
        OngletApp::Apercu | OngletApp::Config | OngletApp::Sauvegardes | OngletApp::Historique
    )
}

fn court(o: OngletApp) -> &'static str {
    match o {
        OngletApp::Apercu => "Vue",
        OngletApp::Journaux => "Logs",
        OngletApp::Config => "Config",
        OngletApp::Sauvegardes => "Sauveg.",
        OngletApp::MisesAJour => "MAJ",
        OngletApp::Metriques => "Mesures",
        OngletApp::Historique => "Histo.",
    }
}

fn apercu(ui: &mut egui::Ui, d: &AppDetail, p: crate::design::Palette) {
    let (vivants, voulus) = d.replicas();

    // 🔴 La chaîne causale AVANT l'état : quand on ouvre une app rouge, c'est la seule
    // question qu'on a. L'état, on le connaît déjà — c'est lui qui a fait cliquer.
    if let Some(ch) = &d.diagnostic {
        if ch.a_quelque_chose_a_dire() {
            c::carte_attention(ui, Attention::Critical, |ui| {
                c::sous_titre(ui, "Pourquoi");
                ui.add_space(mesures::ESPACE_SERRE);

                for (i, m) in ch.maillons.iter().enumerate() {
                    ui.horizontal_top(|ui| {
                        // Un numéro plutôt qu'une flèche : « → » est un glyphe qu'egui
                        // n'affiche pas, et un carré vide ressemble assez à une icône
                        // pour passer inaperçu.
                        c::mono(ui, &format!("{}.", i + 1));
                        ui.add_space(mesures::ESPACE_SERRE);
                        c::texte_libre(ui, &m.constat);
                    });
                }

                if ch.cause_inconnue {
                    ui.add_space(mesures::ESPACE_SERRE);
                    // ⚠️ Le dire franchement : une chaîne qui s'arrête en silence se lit
                    // comme une chaîne complète, et sa dernière ligne passe pour la
                    // cause.
                    c::legende(ui, &ch.conclusion());
                }

                if let Some(r) = &ch.remede {
                    ui.add_space(mesures::ESPACE_SERRE);
                    c::mono(ui, r);
                }
            });
            ui.add_space(mesures::ESPACE);
        }
    }

    c::carte(ui, |ui| {
        c::sous_titre(ui, "État");
        ui.add_space(mesures::ESPACE_SERRE);
        c::ligne(ui, "Statut", &d.resume.status);
        c::ligne(ui, "Réplicas", &format!("{vivants} / {voulus}"));
        if let Some(i) = &d.image {
            c::ligne(ui, "Image", i);
        }
        c::ligne(ui, "Dernière sauvegarde", &d.resume.backup_label());
        c::ligne(ui, "Dernière vérification", &d.resume.verification_label());
    });

    // 🔴 Les échecs en premier après l'état : c'est ce qui répond à « pourquoi cette
    // app est-elle rouge ». Les enterrer sous le placement obligerait à défiler pour
    // trouver la seule information qu'on cherche.
    let echecs = d.echecs();
    if !echecs.is_empty() {
        ui.add_space(mesures::ESPACE);
        c::carte_attention(ui, Attention::Critical, |ui| {
            c::sous_titre(ui, "Tâches en échec");
            ui.add_space(mesures::ESPACE_SERRE);
            for t in &echecs {
                ui.horizontal(|ui| {
                    c::pastille(ui, Attention::Critical);
                    ui.add_space(mesures::ESPACE_SERRE);
                    ui.vertical(|ui| {
                        c::texte_libre(
                            ui,
                            &format!(
                                "réplica {} sur {} — {}",
                                t.slot.map(|s| s.to_string()).unwrap_or_else(|| "?".into()),
                                t.noeud.as_deref().unwrap_or("nœud inconnu"),
                                t.etat
                            ),
                        );
                        match &t.explication {
                            Some(e) => {
                                c::texte_libre(ui, e);
                            }
                            // ⚠️ Swarm ne dit pas toujours pourquoi. Le taire ferait
                            // croire à un affichage incomplet ; le dire oriente vers
                            // les journaux.
                            None => c::legende(
                                ui,
                                "Swarm n'a donné aucune raison — voir les journaux du service",
                            ),
                        }
                    });
                });
            }
        });
    }

    if !d.taches.is_empty() {
        ui.add_space(mesures::ESPACE);
        c::carte(ui, |ui| {
            c::sous_titre(ui, "Placement");
            ui.add_space(mesures::ESPACE_SERRE);
            for t in d.taches.iter().filter(|t| t.vivante) {
                c::ligne(
                    ui,
                    &format!(
                        "réplica {}",
                        t.slot.map(|s| s.to_string()).unwrap_or_else(|| "?".into())
                    ),
                    t.noeud.as_deref().unwrap_or("nœud inconnu"),
                );
            }
        });
    }

    if !d.guides.is_empty() {
        ui.add_space(mesures::ESPACE);
        let bloquants = d.guides.iter().any(|g| g.blocking);
        c::carte_attention(
            ui,
            if bloquants {
                Attention::Notice
            } else {
                Attention::Ok
            },
            |ui| {
                c::sous_titre(ui, "Actions manuelles");
                ui.add_space(mesures::ESPACE_SERRE);
                for g in &d.guides {
                    ui.horizontal(|ui| {
                        if g.blocking {
                            c::badge(ui, "bloquante", p.attention);
                            ui.add_space(mesures::ESPACE_SERRE);
                        }
                        c::texte_libre(ui, &g.title);
                    });
                }
            },
        );
    }
}

fn config(ui: &mut egui::Ui, d: &AppDetail, etroit: bool) {
    if !d.capacites.is_empty() {
        c::carte(ui, |ui| {
            c::sous_titre(ui, "Ce qui a été provisionné");
            ui.add_space(mesures::ESPACE_SERRE);
            for cap in &d.capacites {
                c::texte_libre(ui, cap);
            }
        });
        ui.add_space(mesures::ESPACE);
    }

    if !d.volumes.is_empty() {
        c::carte(ui, |ui| {
            c::sous_titre(ui, "Volumes");
            ui.add_space(mesures::ESPACE_SERRE);
            let p = c::palette(ui);
            for v in &d.volumes {
                ui.horizontal(|ui| {
                    // ⚠️ Deux-points et non une flèche : U+2192 est hors des glyphes que les
                    // polices d'egui portent, et le test l'a attrapé.
                    c::mono(ui, &format!("{} : {}", v.nom, v.chemin));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if v.sqlite {
                            // ⚠️ Une base SQLite ne se copie pas à chaud : il faut que
                            // ça se voie, parce que la corruption ne se découvre qu'à
                            // la restauration.
                            c::badge(ui, "SQLite", p.info);
                        }
                        c::badge(
                            ui,
                            if v.sauvegarde {
                                "sauvegardé"
                            } else {
                                "NON sauvegardé"
                            },
                            if v.sauvegarde { p.ok } else { p.critique },
                        );
                    });
                });
            }
        });
        ui.add_space(mesures::ESPACE);
    }

    if !d.env.is_empty() {
        c::carte(ui, |ui| {
            c::sous_titre(ui, "Variables d'environnement");
            c::legende(
                ui,
                "Les jetons sont affichés tels quels : leur valeur ne sort jamais du \
                 coffre, et un jeton visible dit à quoi l'app est câblée — ce que des \
                 astérisques ne diraient pas.",
            );
            ui.add_space(mesures::ESPACE_SERRE);
            egui::Grid::new("env")
                .num_columns(2)
                .striped(true)
                .spacing([mesures::ESPACE_LARGE, mesures::ESPACE_SERRE])
                .show(ui, |ui| {
                    for (k, v) in &d.env {
                        c::mono(ui, k);
                        c::mono(ui, v);
                        ui.end_row();
                    }
                });
        });
        ui.add_space(mesures::ESPACE);
    }

    if let Some(m) = &d.manifest {
        if !etroit {
            c::carte(ui, |ui| {
                c::sous_titre(ui, "Manifest figé au déploiement");
                c::legende(
                    ui,
                    "Celui de l'installation, pas celui du catalogue courant : c'est ce \
                     qui tourne.",
                );
                ui.add_space(mesures::ESPACE_SERRE);
                egui::ScrollArea::vertical()
                    .max_height(320.0)
                    .id_salt("manifest")
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(crate::design::glyphes::sans_tofu(m))
                                .monospace()
                                .size(c::taille::LEGENDE),
                        );
                    });
            });
        }
    }
}

fn sauvegardes(ui: &mut egui::Ui, d: &AppDetail, p: crate::design::Palette) {
    // 🔴 En tête, avant le détail : c'est la seule question qui compte le jour venu, et
    // la réponse se fabriquait jusqu'ici de tête en croisant quatre écrans.
    if let Some(r) = &d.restaurabilite {
        c::carte_attention(ui, r.attention(), |ui| {
            c::sous_titre(ui, "Si je perds tout maintenant");
            ui.add_space(mesures::ESPACE_SERRE);
            c::texte_libre(ui, &r.verdict);
            ui.add_space(mesures::ESPACE_SERRE);
            // ⚠️ La confiance est un second chiffre, distinct du RPO. Une copie fraîche
            // jamais restaurée est une hypothèse : le dire est tout l'objet du §8.3.
            c::legende(ui, &format!("Confiance {}", r.confiance_explication));

            if !r.remedes.is_empty() {
                ui.add_space(mesures::ESPACE_SERRE);
                for remede in &r.remedes {
                    ui.horizontal_top(|ui| {
                        c::pastille(ui, hlb_api::Attention::Notice);
                        ui.add_space(mesures::ESPACE_SERRE);
                        c::texte_libre(ui, remede);
                    });
                }
            }
        });
        ui.add_space(mesures::ESPACE);
    }

    if let Some(cv) = &d.couverture {
        c::carte_attention(ui, cv.attention(), |ui| {
            c::sous_titre(ui, "Couverture");
            ui.add_space(mesures::ESPACE_SERRE);
            c::texte_libre(ui, &cv.resume());
            ui.add_space(mesures::ESPACE_SERRE);
            for (dest, age) in &cv.par_destination {
                ui.horizontal(|ui| {
                    c::mono(ui, dest);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let (t, teinte) = match age {
                            None => ("JAMAIS".to_string(), p.critique),
                            Some(s) if *s > 12 * 3_600 => (hlb_api::humanise(*s), p.critique),
                            Some(s) => (hlb_api::humanise(*s), p.texte_faible),
                        };
                        ui.label(RichText::new(t).size(c::taille::LEGENDE).color(teinte));
                    });
                });
            }
        });
        ui.add_space(mesures::ESPACE);
    }

    if d.sauvegardes.is_empty() {
        c::etat_vide(
            ui,
            "Aucune sauvegarde enregistrée pour cette application.",
            Some("hlb backup run --app <nom> --apply"),
        );
        return;
    }

    c::carte(ui, |ui| {
        c::sous_titre(ui, "Exécutions récentes");
        ui.add_space(mesures::ESPACE_SERRE);
        for r in d.sauvegardes.iter().take(15) {
            ui.horizontal(|ui| {
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
                        "{}{}",
                        r.kind,
                        match &r.destination {
                            Some(dst) => format!(" vers {dst}"),
                            None => String::new(),
                        }
                    ),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    c::legende(ui, &r.quand);
                });
            });
            if let Some(e) = &r.erreur {
                ui.horizontal(|ui| {
                    ui.add_space(mesures::ESPACE_LARGE);
                    ui.label(
                        RichText::new(crate::design::glyphes::sans_tofu(e))
                            .size(c::taille::LEGENDE)
                            .color(p.critique),
                    );
                });
            }
        }
    });
}

fn historique(ui: &mut egui::Ui, d: &AppDetail, versions: Option<&Vec<hlb_api::VersionManifest>>) {
    if d.journal.is_empty() {
        c::etat_vide(ui, "Aucune action enregistrée sur cette application.", None);
    } else {
        super::journal::afficher(ui, &d.journal, false);
    }

    ui.add_space(mesures::ESPACE_LARGE);
    c::sous_titre(ui, "Ce qui a changé dans le manifest");
    ui.add_space(mesures::ESPACE_SERRE);

    // ⚠️ Sans miroir Git, il n'y a PAS d'historique : `apps.manifest` est écrasé à
    // chaque mise à jour. On le dit et on donne le drapeau, plutôt que d'afficher un
    // vide qui se lirait « rien n'a jamais changé ».
    let Some(v) = versions.filter(|v| !v.is_empty()) else {
        c::etat_vide(
            ui,
            "Aucun historique de manifest : le miroir Git n'est pas activé, et l'état \
             ne garde que la version courante.",
            Some("hlb-controller --git-mirror /var/lib/hlb/miroir"),
        );
        return;
    };

    for ver in v {
        c::carte(ui, |ui| {
            ui.horizontal(|ui| {
                c::mono(ui, &ver.reference);
                ui.add_space(mesures::ESPACE_SERRE);
                c::texte_libre(ui, &ver.sujet);
            });

            ui.add_space(mesures::ESPACE_SERRE);
            if ver.origine {
                // 🔴 « Rien avant » n'est pas « rien n'a changé » : le premier se lit
                // comme une installation, le second comme une mise à jour sans effet.
                c::legende(ui, "Première version connue : il n'y a rien avant elle.");
            } else if ver.diff.is_empty() {
                c::legende(ui, "Aucun changement de manifest.");
            } else {
                for ligne in &ver.diff {
                    c::mono(ui, ligne);
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
    fn only_written_tabs_are_offered() {
        // 🔴 Un onglet qui mène à « à venir » promet, on clique, on n'a rien, et on
        // doute du reste de l'écran.
        assert!(implemente(OngletApp::Apercu));
        assert!(implemente(OngletApp::Config));
        assert!(implemente(OngletApp::Sauvegardes));
        assert!(implemente(OngletApp::Historique));
        assert!(!implemente(OngletApp::Journaux), "pas encore écrit");
        assert!(!implemente(OngletApp::Metriques), "pas encore écrit");
    }

    #[test]
    fn every_tab_has_a_short_label_that_fits_a_phone() {
        for o in OngletApp::tous() {
            let s = court(o);
            assert!(!s.is_empty(), "{o:?}");
            assert!(s.chars().count() <= 8, "« {s} » est trop long en étroit");
        }
    }

    #[test]
    fn no_app_detail_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("app_detail.rs");
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
