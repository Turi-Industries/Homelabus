//! Le tableau de bord.
//!
//! ## Le principe de mise en page
//!
//! Un tableau de bord d'administration n'est pas un rapport : on le regarde deux
//! secondes en passant. La question à laquelle il doit répondre est **« est-ce que je
//! dois faire quelque chose maintenant ? »**, pas « quel est l'état exhaustif du
//! système ».
//!
//! D'où l'ordre : ce qui va mal d'abord, en haut, en couleur ; le reste ensuite. Une
//! liste alphabétique où l'app en panne est en septième position rate son objectif,
//! même si toute l'information y est.

use std::sync::Arc;

use hlb_api::{Attention, AuditItem, GuideItem};

use crate::client::{Shared, Snapshot};

/// Les textes affichés à l'écran.
///
/// 🔴 Regroupés ici pour être **testables**. Deux glyphes ont déjà traversé la revue
/// de code et n'ont été vus qu'à la capture d'écran : « ● » s'affichait en carré vide,
/// et le sélecteur de variante de « ⚠️ » ajoutait un carré parasite. Les polices
/// embarquées par egui ne couvrent pas tout, et un « tofu » ressemble assez à une
/// icône pour passer inaperçu en relecture.
mod texte {
    pub const ACK_EST_UNE_ATTESTATION: &str =
        "« hlb ack » est une ATTESTATION, pas une vérification : le système te croit \
         sur parole. « hlb todo --verify » constate pour de vrai.";

    pub const SECRETS_SANS_VALEUR: &str =
        "Les VALEURS ne sont jamais transmises par l'API : le type qui les transporte \
         n'a pas de champ pour ça.";

    pub const DERNIER_ETAT_CONNU: &str =
        "Ce qui suit est le DERNIER ÉTAT CONNU, pas l'état actuel.";

    pub const AUCUNE_APP: &str = "Aucune app installée.";
    pub const RIEN_EN_ATTENTE: &str = "Rien en attente.";
    pub const JOURNAL_VIDE: &str = "Journal vide.";
    pub const AUCUN_SECRET: &str = "Aucun secret au coffre.";

    /// Tous les textes, pour la vérification de police.
    #[cfg(test)]
    pub const TOUS: &[&str] = &[
        ACK_EST_UNE_ATTESTATION,
        SECRETS_SANS_VALEUR,
        DERNIER_ETAT_CONNU,
        AUCUNE_APP,
        RIEN_EN_ATTENTE,
        JOURNAL_VIDE,
        AUCUN_SECRET,
    ];
}

/// Les couleurs des trois niveaux d'attention.
///
/// ⚠️ La couleur ne porte **jamais** l'information seule : environ 8 % des hommes
/// distinguent mal le rouge du vert. Chaque état porte donc aussi un symbole et un
/// mot — la couleur ne fait que rendre le balayage plus rapide.
fn couleur(a: Attention) -> egui::Color32 {
    match a {
        Attention::Ok => egui::Color32::from_rgb(0x4c, 0xaf, 0x50),
        Attention::Notice => egui::Color32::from_rgb(0xff, 0xa7, 0x26),
        Attention::Critical => egui::Color32::from_rgb(0xe5, 0x39, 0x35),
    }
}

/// Dessine la pastille d'état.
///
/// 🔴 **Une forme peinte, pas un caractère.** La première version utilisait « ● ▲ ■ » :
/// à l'écran, le rond s'affichait en carré vide — le glyphe manque aux polices
/// embarquées par egui, et le « tofu » ressemble assez à une icône pour passer pour
/// un choix délibéré. Une capture d'écran l'a montré ; aucun test de chaîne ne
/// l'aurait fait.
///
/// Les trois formes restent distinctes **sans la couleur** : environ 8 % des hommes
/// distinguent mal le rouge du vert.
fn pastille(ui: &mut egui::Ui, a: Attention) {
    let taille = 11.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(taille, taille), egui::Sense::hover());
    let p = ui.painter();
    let c = couleur(a);
    let centre = rect.center();

    match a {
        // Rond plein : rien à signaler.
        Attention::Ok => {
            p.circle_filled(centre, taille * 0.38, c);
        }
        // Triangle : à regarder.
        Attention::Notice => {
            let r = taille * 0.46;
            let _ = p.add(egui::Shape::convex_polygon(
                [
                    egui::pos2(centre.x, centre.y - r),
                    egui::pos2(centre.x - r, centre.y + r * 0.8),
                    egui::pos2(centre.x + r, centre.y + r * 0.8),
                ]
                .to_vec(),
                c,
                egui::Stroke::NONE,
            ));
        }
        // Carré plein : action requise.
        Attention::Critical => {
            let r = taille * 0.36;
            p.rect_filled(egui::Rect::from_center_size(centre, egui::vec2(r * 2.0, r * 2.0)), 1.0, c);
        }
    }
}

fn mot(a: Attention) -> &'static str {
    match a {
        Attention::Ok => "ok",
        Attention::Notice => "à voir",
        Attention::Critical => "ACTION",
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum Onglet {
    #[default]
    Apps,
    Todo,
    Audit,
    Secrets,
}

impl std::str::FromStr for Onglet {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "apps" | "applications" => Ok(Self::Apps),
            "todo" | "a-faire" | "à-faire" => Ok(Self::Todo),
            "audit" | "journal" => Ok(Self::Audit),
            "secrets" => Ok(Self::Secrets),
            autre => Err(format!(
                "onglet « {autre} » inconnu — attendu : apps, todo, journal, secrets"
            )),
        }
    }
}

pub struct Dashboard {
    shared: Arc<Shared>,
    url: String,
    onglet: Onglet,
}

impl Dashboard {
    pub fn new(shared: Arc<Shared>, url: String, onglet: Onglet) -> Self {
        Self { shared, url, onglet }
    }
}

impl eframe::App for Dashboard {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let (data, fraicheur) = self.shared.read();

        // 🔴 La bannière de péremption avant TOUT le reste, et en occupant de la
        // place. Un tableau de bord qui affiche son dernier état connu comme s'il
        // était actuel est exactement l'écran d'un système en bonne santé — au moment
        // précis où il ment.
        if !fraicheur.is_trustworthy() {
            egui::TopBottomPanel::top("peremption").show(ctx, |ui| {
                let rouge = fraicheur.describe().contains("INJOIGNABLE");
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(fraicheur.describe())
                            .size(15.0)
                            .strong()
                            .color(if rouge {
                                couleur(Attention::Critical)
                            } else {
                                egui::Color32::GRAY
                            }),
                    );
                });
                if rouge {
                    ui.horizontal(|ui| {
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(texte::DERNIER_ETAT_CONNU).italics(),
                        );
                    });
                }
                ui.add_space(6.0);
            });
        }

        egui::TopBottomPanel::top("entete").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.heading("HomelabUS");
                ui.separator();

                let n = data.apps.len();
                let critiques = data
                    .apps
                    .iter()
                    .filter(|a| a.attention() == Attention::Critical)
                    .count();

                if critiques > 0 {
                    ui.label(
                        egui::RichText::new(format!("{critiques}/{n} demandent une action"))
                            .color(couleur(Attention::Critical))
                            .strong(),
                    );
                } else if n > 0 {
                    ui.label(format!("{n} app(s), rien à signaler"));
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(&self.url).weak().small());
                    if fraicheur.is_trustworthy() {
                        ui.label(egui::RichText::new(fraicheur.describe()).weak().small());
                    }
                });
            });

            ui.horizontal(|ui| {
                let mut onglet = |o: Onglet, libelle: String| {
                    if ui.selectable_label(self.onglet == o, libelle).clicked() {
                        self.onglet = o;
                    }
                };
                onglet(Onglet::Apps, format!("Applications ({})", data.apps.len()));

                let bloquants = data.todo.iter().filter(|g| g.blocking).count();
                onglet(
                    Onglet::Todo,
                    if bloquants > 0 {
                        format!("À faire ({} dont {bloquants} bloquantes)", data.todo.len())
                    } else {
                        format!("À faire ({})", data.todo.len())
                    },
                );
                onglet(Onglet::Audit, "Journal".to_string());
                onglet(Onglet::Secrets, format!("Secrets ({})", data.secrets.len()));
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.onglet {
            Onglet::Apps => apps(ui, &data),
            Onglet::Todo => todo(ui, &data.todo),
            Onglet::Audit => audit(ui, &data.audit),
            Onglet::Secrets => secrets(ui, &data),
        });
    }
}

fn apps(ui: &mut egui::Ui, data: &Snapshot) {
    if data.apps.is_empty() {
        vide(ui, texte::AUCUNE_APP, "hlb install <app> --apply");
        return;
    }

    // 🔴 Le tri par urgence, pas alphabétique. Une app en panne en septième position
    // rate l'objectif du tableau de bord, même si l'information y est.
    let mut apps: Vec<_> = data.apps.iter().collect();
    apps.sort_by(|a, b| {
        b.attention()
            .cmp(&a.attention())
            .then_with(|| a.name.cmp(&b.name))
    });

    egui::ScrollArea::vertical().show(ui, |ui| {
        for a in apps {
            let att = a.attention();
            egui::Frame::group(ui.style())
                .stroke(egui::Stroke::new(1.0_f32, couleur(att)))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        // Forme + mot + couleur : l'information passe trois fois, et
                        // aucune ne dépend d'une police.
                        pastille(ui, att);
                        ui.label(egui::RichText::new(&a.name).strong().size(15.0));
                        ui.label(
                            egui::RichText::new(mot(att))
                                .color(couleur(att))
                                .small()
                                .strong(),
                        );
                        ui.separator();
                        ui.label(egui::RichText::new(&a.status).weak());

                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                ui.label(egui::RichText::new(&a.image).weak().small());
                            },
                        );
                    });

                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing.x = 14.0;

                        // 🔴 « JAMAIS » en rouge, jamais confondu avec un âge : une
                        // app sans aucune sauvegarde est le pire état du système, et
                        // le plus discret si on l'affiche comme les autres.
                        let jamais = a.last_backup_secs.is_none();
                        ui.label("sauvegarde :");
                        ui.label(
                            egui::RichText::new(a.backup_label())
                                .strong()
                                .color(if jamais {
                                    couleur(Attention::Critical)
                                } else {
                                    ui.visuals().text_color()
                                }),
                        );

                        ui.label("· vérifiée :");
                        ui.label(
                            egui::RichText::new(a.verification_label())
                                .color(if a.last_verification_secs.is_none() {
                                    couleur(Attention::Notice)
                                } else {
                                    ui.visuals().text_color()
                                }),
                        );

                        if a.blocking_guides > 0 {
                            ui.label(
                                egui::RichText::new(format!(
                                    "· {} action(s) bloquante(s)",
                                    a.blocking_guides
                                ))
                                .color(couleur(Attention::Notice)),
                            );
                        }

                        if let Some(d) = &a.domain {
                            ui.label(egui::RichText::new(format!("· {d}")).weak());
                        }
                    });
                });
            ui.add_space(4.0);
        }
    });
}

fn todo(ui: &mut egui::Ui, items: &[GuideItem]) {
    if items.is_empty() {
        vide(ui, texte::RIEN_EN_ATTENTE, "");
        return;
    }

    // Les bloquantes d'abord : elles arrêtent des déploiements.
    let mut items: Vec<_> = items.iter().collect();
    items.sort_by_key(|g| (!g.blocking, g.app.clone()));

    egui::ScrollArea::vertical().show(ui, |ui| {
        for g in items {
            ui.horizontal(|ui| {
                if g.blocking {
                    pastille(ui, Attention::Critical);
                    ui.label(
                        egui::RichText::new("BLOQUANTE")
                            .color(couleur(Attention::Critical))
                            .strong()
                            .small(),
                    );
                } else {
                    pastille(ui, Attention::Notice);
                    ui.label(egui::RichText::new("à faire").weak().small());
                }
                ui.label(egui::RichText::new(&g.app).strong());
                ui.label(&g.title);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // La commande exacte, copiable : un tableau de bord en lecture
                    // seule doit dire QUOI TAPER, sinon il oblige à chercher.
                    ui.label(
                        egui::RichText::new(format!("hlb ack {}/{}", g.app, g.id))
                            .monospace()
                            .weak()
                            .small(),
                    );
                });
            });
            ui.separator();
        }
    });

    ui.add_space(8.0);
    ui.label(
        egui::RichText::new(texte::ACK_EST_UNE_ATTESTATION)
            .italics()
            .weak(),
    );
}

fn audit(ui: &mut egui::Ui, items: &[AuditItem]) {
    if items.is_empty() {
        vide(ui, texte::JOURNAL_VIDE, "");
        return;
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("audit")
            .num_columns(5)
            .striped(true)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                for e in items {
                    ui.label(egui::RichText::new(&e.at).monospace().small());
                    ui.label(&e.actor);
                    ui.label(egui::RichText::new(&e.action).strong());
                    ui.label(&e.target);

                    // 🔴 Un refus n'est PAS un échec : c'est le système qui a protégé
                    // l'utilisateur. Les afficher pareil rendrait le journal
                    // inexploitable — on ne saurait plus distinguer « ça a planté »
                    // de « on t'a empêché de faire une bêtise ».
                    let (texte, c) = if e.is_refusal() {
                        ("refusé (protection)", couleur(Attention::Notice))
                    } else if e.is_failure() {
                        ("échec", couleur(Attention::Critical))
                    } else {
                        ("ok", couleur(Attention::Ok))
                    };
                    ui.label(egui::RichText::new(texte).color(c).small());
                    ui.end_row();
                }
            });
    });
}

fn secrets(ui: &mut egui::Ui, data: &Snapshot) {
    ui.label(
        egui::RichText::new(texte::SECRETS_SANS_VALEUR).italics().weak(),
    );
    ui.add_space(8.0);

    if data.secrets.is_empty() {
        vide(ui, texte::AUCUN_SECRET, "");
        return;
    }

    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("secrets")
            .num_columns(2)
            .striped(true)
            .spacing([24.0, 4.0])
            .show(ui, |ui| {
                for s in &data.secrets {
                    ui.label(egui::RichText::new(&s.name).monospace());
                    ui.label(egui::RichText::new(&s.purpose).weak());
                    ui.end_row();
                }
            });
    });
}

/// Un état vide qui dit quoi faire, plutôt qu'un écran blanc.
fn vide(ui: &mut egui::Ui, message: &str, commande: &str) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        ui.label(egui::RichText::new(message).size(15.0).weak());
        if !commande.is_empty() {
            ui.add_space(6.0);
            ui.label(egui::RichText::new(commande).monospace());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_api::AppSummary;

    fn app(nom: &str, statut: &str, backup: Option<i64>) -> AppSummary {
        AppSummary {
            name: nom.into(),
            status: statut.into(),
            image: "a/b:1".into(),
            domain: None,
            last_backup_secs: backup,
            last_verification_secs: None,
            blocking_guides: 0,
        }
    }

    #[test]
    fn every_level_has_a_word_not_just_a_colour() {
        // ⚠️ Environ 8 % des hommes distinguent mal le rouge du vert. La couleur ne
        // doit jamais porter l'information seule. La forme est peinte (cf. `pastille`)
        // et le mot est ici — deux canaux indépendants de la couleur.
        for a in [Attention::Ok, Attention::Notice, Attention::Critical] {
            assert!(!mot(a).is_empty());
        }
        assert_ne!(mot(Attention::Ok), mot(Attention::Critical));
        assert_ne!(mot(Attention::Notice), mot(Attention::Critical));
    }

    #[test]
    fn no_displayed_text_needs_a_glyph_egui_might_not_have() {
        // 🔴 Deux glyphes ont déjà traversé la revue de code et n'ont été vus qu'à la
        // capture d'écran. Les polices embarquées par egui couvrent le latin et un
        // jeu d'émojis restreint ; tout le reste s'affiche en carré vide, et un tofu
        // ressemble assez à une icône pour passer pour un choix délibéré.
        for s in texte::TOUS {
            for c in s.chars() {
                let o = c as u32;
                assert!(
                    o < 0x2C0 || (0x2000..=0x206F).contains(&o),
                    "{c:?} (U+{o:04X}) dans « {s} » : risque de carré vide"
                );
            }
        }
    }

    #[test]
    fn no_status_glyph_depends_on_a_font() {
        // 🔴 La leçon d'une capture d'écran : « ● » s'affichait en carré vide, et le
        // tofu ressemblait assez à une icône pour passer pour un choix délibéré.
        // Aucun caractère décoratif ne doit rester dans le code d'état.
        let src = include_str!("app.rs");
        for glyphe in ['\u{25CF}', '\u{25B2}', '\u{25A0}'] {
            assert!(
                !src.contains(&format!("new(\"{glyphe}")),
                "le glyphe {glyphe:?} est de retour dans un libellé"
            );
        }
    }

    #[test]
    fn the_worst_app_comes_first() {
        // 🔴 Un tri alphabétique mettrait « zabbix en panne » en dernier. Le tableau
        // de bord doit répondre à « dois-je agir maintenant ? » en deux secondes.
        let mut apps = [
            app("alpha", "running", Some(60)),
            app("beta", "failed", Some(60)),
            app("gamma", "running", None),
        ];
        apps.sort_by(|a, b| {
            b.attention()
                .cmp(&a.attention())
                .then_with(|| a.name.cmp(&b.name))
        });

        // beta (failed) et gamma (jamais sauvegardée) sont tous deux critiques,
        // départagés par le nom ; alpha, sain, passe en dernier.
        assert_eq!(apps[2].name, "alpha");
        assert!(apps[..2].iter().all(|a| a.attention() == Attention::Critical));
    }

    #[test]
    fn blocking_guides_come_before_the_others() {
        let mut items = [
            GuideItem { app: "z".into(), id: "a".into(), title: "t".into(), blocking: false },
            GuideItem { app: "a".into(), id: "b".into(), title: "t".into(), blocking: true },
        ];
        items.sort_by_key(|g| (!g.blocking, g.app.clone()));
        assert!(items[0].blocking, "la bloquante arrête un déploiement");
    }

    #[test]
    fn tabs_are_addressable_by_name() {
        use std::str::FromStr;
        assert_eq!(Onglet::from_str("todo").expect("todo"), Onglet::Todo);
        assert_eq!(Onglet::from_str("Journal").expect("journal"), Onglet::Audit);
        assert_eq!(Onglet::from_str("apps").expect("apps"), Onglet::Apps);
        // Un nom inconnu doit DIRE lesquels existent, pas juste échouer.
        let e = Onglet::from_str("nimportequoi").unwrap_err();
        assert!(e.contains("apps"), "{e}");
    }

    #[test]
    fn colours_are_distinct_enough_to_scan() {
        assert_ne!(couleur(Attention::Ok), couleur(Attention::Critical));
        assert_ne!(couleur(Attention::Notice), couleur(Attention::Critical));
    }
}
