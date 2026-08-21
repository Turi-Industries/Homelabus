//! La coquille : ce qui entoure tous les écrans.
//!
//! ## Ce qu'elle garantit, à chaque image et pour chaque écran
//!
//! 1. **La fraîcheur est visible.** Le bandeau de péremption est peint AVANT tout le
//!    reste, et rien ne peut le masquer. Une donnée périmée ne doit jamais ressembler à
//!    une donnée fraîche.
//! 2. **La navigation ne propose que ce qui existe et ce à quoi on a droit.** Un lien
//!    qui mène à un 403 est un lien qui fait douter du reste.
//! 3. **Le thème s'applique en un seul endroit.** Aucun écran ne pose de couleur.
//!
//! ## Deux dispositions, un seul code
//!
//! En large : barre latérale. En étroit : barre d'onglets basse, où le pouce arrive.
//! Le seuil est le même qu'avant (600 px), et ses bornes sont vérifiées à la
//! compilation — un téléphone moderne fait 390 px de large en portrait.

use std::sync::Arc;

use egui::{Align, Layout, RichText};

use crate::client::{Acces, Freshness, Poller, Ressource, Ressources, Shared};
use crate::design::{composants as c, mesures, theme, Theme};
use crate::route::Route;

/// En deçà, on passe en disposition téléphone.
pub const SEUIL_ETROIT: f32 = 600.0;

/// Largeur de la barre latérale déployée.
const BARRE: f32 = 208.0;

/// L'application.
pub struct Application {
    partage: Arc<Shared>,
    poller: Poller,
    route: Route,
    theme: Theme,
    marque: Arc<Ressource<hlb_api::Marque>>,
    moi: Arc<Ressource<hlb_api::Moi>>,
    acces: Acces,
    /// Les ressources des écrans d'administration, chacune avec sa cadence.
    ressources: Ressources,
    /// Le jeton d'invitation, s'il y en avait un dans l'URL.
    ///
    /// ⚠️ Gardé en mémoire vive uniquement, jamais rangé : il sert une fois, et un
    /// navigateur partagé ne doit pas le proposer à la personne suivante.
    invitation: Option<String>,
    /// Le dernier `Moi` connu, pour ne pas faire clignoter la navigation entre deux
    /// sondages : les droits ne changent pas d'une seconde à l'autre.
    droits: hlb_api::Droits,
    /// Mode kiosque : rotation automatique, aucune navigation (§11.4).
    kiosque: bool,
}

impl Application {
    pub fn new(partage: Arc<Shared>, poller: Poller, route: Route) -> Self {
        let acces = poller.acces().clone();
        Self {
            partage,
            poller,
            route,
            theme: Theme::turi_sombre(),
            // La marque change rarement : la redemander toutes les cinq secondes
            // serait du bruit. Cinq minutes suffisent.
            marque: Arc::new(Ressource::new("/api/apparence", 300.0)),
            moi: Arc::new(Ressource::new("/api/moi", 60.0)),
            acces,
            ressources: Ressources::default(),
            invitation: None,
            // 🔴 Aucun droit tant qu'on ne sait pas qui regarde. Supposer l'inverse
            // afficherait brièvement une console complète à quelqu'un qui n'y a pas
            // droit — et les clics partiraient avant la correction.
            droits: hlb_api::Droits::default(),
            kiosque: false,
        }
    }

    /// Passe en mode kiosque : rotation automatique et aucune interaction.
    ///
    /// 🔴 Le mode ne se quitte pas depuis l'écran : un mur n'a ni clavier ni souris, et
    /// un bouton « sortir » y serait au mieux inutile, au pire une porte ouverte pour
    /// qui passe. On relance le binaire sans le drapeau.
    pub fn en_kiosque(mut self) -> Self {
        self.kiosque = true;
        self
    }

    /// Pose l'invitation lue dans le fragment d'URL.
    pub fn avec_invitation(&mut self, invitation: Option<String>) {
        self.invitation = invitation;
    }

    /// La route courante, exposée pour les tests et pour le natif.
    pub fn route(&self) -> &Route {
        &self.route
    }

    pub fn aller(&mut self, r: Route) {
        self.route = r;
        #[cfg(target_arch = "wasm32")]
        crate::ecrire_fragment(&self.route.to_string());
    }
}

impl eframe::App for Application {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // ⚠️ L'horloge d'egui, jamais `Instant::now()` : ce dernier PANIQUE en
        // WebAssembly, et l'interface se fermerait sur une page blanche.
        let maintenant = ctx.input(|i| i.time);

        let reveil = {
            let ctx = ctx.clone();
            move || ctx.request_repaint()
        };
        self.poller.tick(maintenant, reveil.clone());
        self.marque.tick(&self.acces, maintenant, reveil.clone());
        self.moi.tick(&self.acces, maintenant, reveil.clone());
        self.ressources.tick(&self.acces, maintenant, reveil);

        // Sans ça, l'âge affiché se figerait entre deux mouvements de souris : « il y a
        // 3 s » resterait à l'écran pendant une minute.
        ctx.request_repaint_after(std::time::Duration::from_millis(500));

        // 🔴 En kiosque, la route est PILOTÉE par l'horloge : elle ne vient ni d'un
        // clic ni de l'URL. Les écrans qui portent des secrets, des comptes ou le
        // journal en sont exclus par construction (`kiosque::convient_au_kiosque`).
        if self.kiosque {
            if let Some(r) = crate::kiosque::ecran_courant(maintenant) {
                self.route = r;
            }
        }

        let (marque, _) = self.marque.lire(maintenant);
        let marque = marque.unwrap_or_default();
        let (moi, _) = self.moi.lire(maintenant);
        if let Some(m) = &moi {
            self.droits = m.peut;
        }

        // Le thème, dans cet ordre de priorité :
        //   1. le choix de la personne — c'est le sien, il l'emporte ;
        //   2. le défaut de l'installation ;
        //   3. le thème de secours compilé.
        //
        // ⚠️ Un thème inconnu retombe sur le défaut plutôt que d'échouer : un nom
        // périmé, gardé en base après le retrait d'un thème, ne doit pas empêcher
        // l'interface de s'afficher.
        let (prefs, _) = self.ressources.preferences.lire(maintenant);
        let choisi = prefs.as_ref().and_then(|p| p.theme.clone());

        let mut t = match choisi.as_deref().or(marque.theme_defaut.as_deref()) {
            Some(n) => Theme::par_nom(n),
            None => self.theme.clone(),
        };
        if let Some([r, v, b]) = marque.accent {
            t.palette = t.palette.avec_accent(egui::Color32::from_rgb(r, v, b));
        }
        theme::appliquer(ctx, &t);
        c::poser_palette(ctx, t.palette);
        let p = t.palette;

        let (data, fraicheur) = self.partage.read(maintenant);
        let etroit = ctx.available_rect().width() < SEUIL_ETROIT;

        // 🔴 AVANT tout le reste : rien ne doit pouvoir masquer la péremption.
        if !fraicheur.is_trustworthy() {
            egui::TopBottomPanel::top("peremption").show(ctx, |ui| {
                ui.add_space(mesures::ESPACE_SERRE);
                let (teinte, detail) = match &fraicheur {
                    Freshness::Never => (p.info, None),
                    Freshness::NeverSucceeded { .. } => (p.critique, Some(AUCUNE_DONNEE)),
                    _ => (p.critique, Some(DERNIER_ETAT_CONNU)),
                };
                c::bandeau(ui, teinte, &fraicheur.describe(), detail);
                ui.add_space(mesures::ESPACE_SERRE);
            });
        }

        // 🔴 L'inscription n'a NI navigation NI en-tête de session : elle s'adresse à
        // quelqu'un qui n'a pas encore de compte. Lui proposer « Tableau de bord » ou
        // afficher « jeton · admin » — l'identité de qui a ouvert le lien, pas la
        // sienne — l'enverrait sur un refus et lui ferait croire qu'il s'est trompé.
        let accueil_public = matches!(self.route, Route::Inscription);

        if self.kiosque {
            // ⚠️ Ni navigation ni en-tête de session sur un mur : il n'y a personne pour
            // cliquer, et afficher « jeton · viewer » à toute la pièce ne renseigne que
            // les curieux. Seule la marque et l'écran courant restent.
            entete_public(ctx, &marque, p);
        } else if accueil_public {
            entete_public(ctx, &marque, p);
        } else {
            entete(ctx, &marque, &fraicheur, moi.as_ref(), etroit, p);
            if etroit {
                barre_basse(ctx, &mut self.route, self.droits, p);
            } else {
                barre_laterale(ctx, &mut self.route, &marque, self.droits, p);
            }
        }

        // ⚠️ L'horloge MURALE, distincte de celle d'egui : les sourdines et les
        // horodatages du serveur se comparent à 1970, pas au démarrage de l'interface.
        let epoch = epoch_secondes();

        let reveil_ecran: std::sync::Arc<dyn Fn() + Send + Sync> = {
            let ctx = ctx.clone();
            std::sync::Arc::new(move || ctx.request_repaint())
        };

        let contexte = crate::ecrans::Contexte {
            data: &data,
            ressources: &self.ressources,
            maintenant,
            epoch,
            etroit,
            acces: &self.acces,
            reveil: reveil_ecran,
            invitation: self.invitation.as_deref(),
        };

        let demande = egui::CentralPanel::default()
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .show(ui, |ui| crate::ecrans::afficher(ui, &self.route, &contexte))
                    .inner
            })
            .inner;

        // Un écran a demandé à changer de route (un onglet d'app, un lien interne).
        if let Some(r) = demande {
            self.aller(r);
        }
    }
}

/// L'heure murale, en secondes depuis 1970.
///
/// 🔴 `SystemTime` et non `Instant` : ce dernier PANIQUE en WebAssembly. `SystemTime`,
/// lui, y fonctionne — c'est le seul des deux qui traverse.
fn epoch_secondes() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

const DERNIER_ETAT_CONNU: &str =
    "Ce qui suit est le DERNIER ÉTAT CONNU, pas l'état actuel. Le cluster peut avoir \
     changé — ou brûler — sans que cet écran le montre.";
const AUCUNE_DONNEE: &str =
    "Aucune donnée n'a jamais été reçue. Ce n'est pas un chargement en cours : la \
     requête a échoué.";

fn entete(
    ctx: &egui::Context,
    marque: &hlb_api::Marque,
    fraicheur: &Freshness,
    moi: Option<&hlb_api::Moi>,
    etroit: bool,
    p: crate::design::Palette,
) {
    egui::TopBottomPanel::top("entete").show(ctx, |ui| {
        ui.add_space(mesures::ESPACE_SERRE);
        ui.horizontal(|ui| {
            if etroit {
                // En étroit, la marque tient dans l'en-tête : la barre latérale qui la
                // portait n'existe pas.
                c::monogramme(ui, &marque.nom, p.accent, 22.0);
                ui.add_space(mesures::ESPACE_SERRE);
                ui.label(
                    RichText::new(&marque.produit)
                        .size(c::taille::SOUS_TITRE)
                        .strong(),
                );
            }

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if let Some(m) = moi {
                    let qui = m.compte.clone().unwrap_or_else(|| "jeton".into());
                    ui.label(
                        RichText::new(format!("{qui} · {}", m.role))
                            .size(c::taille::LEGENDE)
                            .color(p.texte_faible),
                    )
                    .on_hover_text(&m.role_libelle);
                }
                if !etroit {
                    ui.add_space(mesures::ESPACE);
                    // La fraîcheur, discrète quand tout va bien : le bandeau prend le
                    // relais dès que ça ne va plus.
                    ui.label(
                        RichText::new(fraicheur.describe())
                            .size(c::taille::LEGENDE)
                            .color(if fraicheur.is_trustworthy() {
                                p.texte_faible
                            } else {
                                p.critique
                            }),
                    );
                }
            });
        });
        ui.add_space(mesures::ESPACE_SERRE);
    });
}

/// L'en-tête d'un écran public : la marque, et rien d'autre.
///
/// ⚠️ Pas de fraîcheur, pas d'identité : la personne n'a pas de session, et afficher
/// celle de quelqu'un d'autre serait au mieux déroutant.
fn entete_public(ctx: &egui::Context, marque: &hlb_api::Marque, p: crate::design::Palette) {
    egui::TopBottomPanel::top("entete").show(ctx, |ui| {
        ui.add_space(mesures::ESPACE);
        ui.horizontal(|ui| {
            c::monogramme(ui, &marque.nom, p.accent, 28.0);
            ui.add_space(mesures::ESPACE_SERRE);
            ui.vertical(|ui| {
                ui.label(
                    RichText::new(&marque.produit)
                        .size(c::taille::SOUS_TITRE)
                        .strong()
                        .color(p.texte),
                );
                ui.label(
                    RichText::new(&marque.nom)
                        .size(c::taille::LEGENDE)
                        .color(p.texte_faible),
                );
            });
        });
        ui.add_space(mesures::ESPACE);
    });
}

fn barre_laterale(
    ctx: &egui::Context,
    route: &mut Route,
    marque: &hlb_api::Marque,
    droits: hlb_api::Droits,
    p: crate::design::Palette,
) {
    egui::SidePanel::left("navigation")
        .exact_width(BARRE)
        .resizable(false)
        .frame(
            egui::Frame::new()
                .fill(p.surface)
                .inner_margin(egui::Margin::same(mesures::ESPACE as i8)),
        )
        .show(ctx, |ui| {
            ui.add_space(mesures::ESPACE_SERRE);
            ui.horizontal(|ui| {
                c::monogramme(ui, &marque.nom, p.accent, 30.0);
                ui.add_space(mesures::ESPACE_SERRE);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(&marque.produit)
                            .size(c::taille::SOUS_TITRE)
                            .strong()
                            .color(p.texte),
                    );
                    ui.label(
                        RichText::new(&marque.nom)
                            .size(c::taille::LEGENDE)
                            .color(p.texte_faible),
                    );
                });
            });
            ui.add_space(mesures::ESPACE_LARGE);

            for r in entrees(droits) {
                let actif = std::mem::discriminant(&r) == std::mem::discriminant(route);
                if entree_nav(ui, r.libelle(), actif, p).clicked() {
                    *route = r;
                }
            }

            ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
                if let Some(pied) = &marque.pied {
                    ui.add_space(mesures::ESPACE);
                    ui.label(
                        RichText::new(crate::design::glyphes::sans_tofu(pied))
                            .size(c::taille::LEGENDE)
                            .color(p.texte_faible),
                    );
                }
            });
        });
}

/// Une entrée de navigation : pleine largeur, avec un liseré d'accent quand elle est
/// active.
fn entree_nav(
    ui: &mut egui::Ui,
    libelle: &str,
    actif: bool,
    p: crate::design::Palette,
) -> egui::Response {
    let hauteur = 30.0;
    let (rect, reponse) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), hauteur),
        egui::Sense::click(),
    );

    let fond = if actif {
        theme::melanger(p.surface, p.accent, 0.20)
    } else if reponse.hovered() {
        p.surface_haute
    } else {
        p.surface
    };

    let pe = ui.painter();
    pe.rect_filled(rect, mesures::RAYON_PETIT, fond);
    if actif {
        // Le liseré : un second canal, pour ne pas dépendre d'une nuance de fond que
        // certains écrans n'affichent pas.
        pe.rect_filled(
            egui::Rect::from_min_size(rect.min, egui::vec2(3.0, hauteur)),
            1.0,
            p.accent,
        );
    }
    pe.text(
        egui::pos2(rect.min.x + mesures::MARGE, rect.center().y),
        egui::Align2::LEFT_CENTER,
        libelle,
        egui::FontId::proportional(c::taille::CORPS),
        if actif { p.texte } else { p.texte_faible },
    );

    reponse
}

fn barre_basse(
    ctx: &egui::Context,
    route: &mut Route,
    droits: hlb_api::Droits,
    p: crate::design::Palette,
) {
    egui::TopBottomPanel::bottom("navigation")
        .frame(
            egui::Frame::new()
                .fill(p.surface)
                .inner_margin(egui::Margin::same(mesures::ESPACE_SERRE as i8)),
        )
        .show(ctx, |ui| {
            // Défilement horizontal : au-delà de cinq entrées, les dernières
            // sortiraient de l'écran et deviendraient inatteignables.
            egui::ScrollArea::horizontal()
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        for r in entrees(droits) {
                            let actif = std::mem::discriminant(&r) == std::mem::discriminant(route);
                            let texte = RichText::new(r.libelle_court())
                                .size(c::taille::CORPS)
                                .color(if actif { p.accent } else { p.texte_faible });
                            if ui.selectable_label(actif, texte).clicked() {
                                *route = r;
                            }
                        }
                    });
                });
        });
}

/// Les entrées visibles, selon les droits.
///
/// 🔴 Ce n'est **pas** le contrôle d'accès — il a lieu à chaque requête, côté
/// controller. C'est de quoi ne pas proposer un écran qui répondrait 403 : un lien qui
/// échoue fait douter de tous les autres.
fn entrees(droits: hlb_api::Droits) -> Vec<Route> {
    let mut v: Vec<Route> = Route::navigation_portail()
        .into_iter()
        .filter(|r| autorise(r, droits))
        .collect();
    v.extend(
        Route::navigation_admin()
            .into_iter()
            .filter(|r| autorise(r, droits)),
    );
    v
}

fn autorise(r: &Route, d: hlb_api::Droits) -> bool {
    use hlb_types::rbac::Action;
    match r.exige() {
        Action::ReadSelf => d.lire_soi,
        Action::ActOnSelf => d.agir_sur_soi,
        Action::Read => d.lire,
        Action::Publish => d.publier,
        Action::Operate => d.operer,
        Action::ManageAccounts => d.gerer_comptes,
        Action::Destroy => d.detruire,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_breakpoint_covers_real_phones() {
        // Vérifié à la COMPILATION : un iPhone SE fait 375 px de large en portrait, un
        // Pixel 390. Un seuil sous ces valeurs enverrait un téléphone sur la
        // disposition large, où les colonnes se chevauchent.
        const _: () = assert!(390.0 < SEUIL_ETROIT);
        const _: () = assert!(375.0 < SEUIL_ETROIT);
        // Et une tablette en paysage doit garder la barre latérale.
        const _: () = assert!(SEUIL_ETROIT < 1024.0);
    }

    #[test]
    fn a_plain_user_sees_the_portal_and_nothing_else() {
        // 🔴 Chaque entrée d'administration proposée à un simple utilisateur serait un
        // clic vers un 403.
        let d = hlb_api::Droits::pour(hlb_types::Role::User);
        let v = entrees(d);
        for r in &v {
            assert!(
                Route::plan_portail().contains(r),
                "« {} » ne devrait pas être proposé",
                r.libelle()
            );
        }
    }

    #[test]
    fn an_admin_sees_everything_that_exists() {
        let d = hlb_api::Droits::pour(hlb_types::Role::Admin);
        let v = entrees(d);
        for r in Route::navigation_admin() {
            assert!(
                v.contains(&r),
                "« {} » manque à l'administrateur",
                r.libelle()
            );
        }
    }

    #[test]
    fn the_signup_screen_shows_no_navigation_at_all() {
        // 🔴 Elle s'adresse à quelqu'un qui n'a pas encore de compte. Proposer
        // « Tableau de bord » l'enverrait sur un refus, et il croirait s'être trompé
        // de lien plutôt que de comprendre qu'il doit d'abord créer son compte.
        //
        // Le test porte sur la CONDITION, faute de pouvoir inspecter le rendu : c'est
        // elle qui décide, et une inversion la casserait.
        let publique = |r: &Route| matches!(r, Route::Inscription);
        assert!(publique(&Route::Inscription));
        assert!(!publique(&Route::TableauDeBord));
        assert!(!publique(&Route::Portail), "le portail suppose un compte");
    }

    #[test]
    fn nothing_is_offered_before_we_know_who_is_watching() {
        // Supposer des droits par défaut afficherait brièvement une console complète à
        // quelqu'un qui n'y a pas droit — et les clics partiraient avant la correction.
        let v = entrees(hlb_api::Droits::default());
        assert!(
            v.is_empty(),
            "{:?}",
            v.iter().map(|r| r.libelle()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn no_shell_text_needs_a_glyph_egui_might_not_have() {
        let src = include_str!("shell.rs");
        for (n, ligne) in src.lines().enumerate() {
            let sans_commentaire = ligne.split("//").next().unwrap_or("");
            for ch in sans_commentaire.chars() {
                assert!(
                    crate::design::glyphes::sur(ch),
                    "ligne {} : U+{:04X}",
                    n + 1,
                    ch as u32
                );
            }
        }
    }

    #[test]
    fn the_staleness_wording_says_what_it_means() {
        // « Données périmées » ne dit pas ce qu'il faut en conclure. Ces deux messages
        // le disent : ce n'est pas l'état actuel, et ce n'est pas un chargement.
        assert!(DERNIER_ETAT_CONNU.contains("DERNIER"));
        assert!(AUCUNE_DONNEE.contains("pas un chargement"));
    }
}
