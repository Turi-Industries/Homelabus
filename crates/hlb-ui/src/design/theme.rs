//! Les thèmes livrés, et leur application à egui.
//!
//! Un thème est une [`Palette`] plus un jeu de mesures (rayons, épaisseurs,
//! espacements). Rien d'autre : la mise en page ne dépend pas du thème, sinon changer
//! de thème changerait ce qui tient à l'écran.
//!
//! ## Les quatre thèmes
//!
//! | Nom | Pour |
//! |---|---|
//! | **Turi sombre** | le défaut — on regarde un tableau de bord la nuit plus souvent qu'au soleil |
//! | **Turi clair** | plein jour, projection, impression d'écran |
//! | **Contraste élevé** | ce qui rend payant le choix « forme + mot + couleur » |
//! | **Système** | suit le réglage du navigateur ou de l'OS |

use egui::{Color32, CornerRadius, Stroke};

use super::palette::Palette;

/// La base d'un thème : décide du sens du dégradé de surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    Clair,
    Sombre,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Theme {
    pub nom: String,
    pub base: Base,
    pub palette: Palette,
}

/// Les mesures, communes à tous les thèmes.
///
/// Volontairement peu nombreuses : une échelle à douze valeurs se choisit au hasard, et
/// l'interface finit sans rythme. Quatre suffisent.
pub mod mesures {
    /// Rayon des cartes et des panneaux.
    pub const RAYON: f32 = 8.0;
    /// Rayon des éléments petits : badges, champs, boutons.
    pub const RAYON_PETIT: f32 = 5.0;
    pub const ESPACE_SERRE: f32 = 4.0;
    pub const ESPACE: f32 = 8.0;
    pub const ESPACE_LARGE: f32 = 16.0;
    /// Marge intérieure d'une carte.
    pub const MARGE: f32 = 12.0;
}

impl Theme {
    /// Le thème par défaut.
    ///
    /// Sombre, parce qu'un tableau de bord d'infrastructure se regarde plus souvent la
    /// nuit qu'au soleil, et qu'un écran blanc à 3 h du matin est une agression.
    pub fn turi_sombre() -> Self {
        Self {
            nom: "Turi sombre".into(),
            base: Base::Sombre,
            palette: Palette {
                fond: Color32::from_rgb(0x0F, 0x12, 0x16),
                surface: Color32::from_rgb(0x17, 0x1B, 0x21),
                surface_haute: Color32::from_rgb(0x1E, 0x24, 0x2B),
                bordure: Color32::from_rgb(0x2A, 0x32, 0x3B),
                texte: Color32::from_rgb(0xE6, 0xEA, 0xEF),
                texte_faible: Color32::from_rgb(0x96, 0xA1, 0xAD),
                // 🔴 Violet, et non le cuivre industriel qu'on aurait spontanément
                // choisi. Le test l'a refusé : en vision deutéranope, un accent chaud
                // se confond avec le rouge de « critique » (distance 27, il en faut
                // 40). Chaque bouton principal aurait alors ressemblé à une alerte.
                //
                // Un accent FROID est le seul choix compatible avec une triade d'état
                // qui va du vert au rouge — c'est une contrainte, pas un goût.
                accent: Color32::from_rgb(0x7B, 0x8C, 0xFF),
                sur_accent: Color32::from_rgb(0x0F, 0x12, 0x16),
                // 🔴 Un vert TIRANT SUR LE BLEU, pas le vert « feu tricolore ».
                // Le vert franc et le rouge se rejoignent en vision deutéranope
                // (distance 35) : les deux voyants les plus importants du tableau de
                // bord auraient été indiscernables pour 8 % des hommes.
                // Décalé vers le cyan, l'écart passe à 94.
                ok: Color32::from_rgb(0x38, 0xC7, 0xB4),
                attention: Color32::from_rgb(0xFF, 0xC9, 0x4D),
                critique: Color32::from_rgb(0xF0, 0x5C, 0x5C),
                info: Color32::from_rgb(0x6E, 0xA8, 0xFE),
            },
        }
    }

    pub fn turi_clair() -> Self {
        Self {
            nom: "Turi clair".into(),
            base: Base::Clair,
            palette: Palette {
                fond: Color32::from_rgb(0xF4, 0xF6, 0xF9),
                surface: Color32::from_rgb(0xFF, 0xFF, 0xFF),
                surface_haute: Color32::from_rgb(0xEB, 0xEF, 0xF4),
                bordure: Color32::from_rgb(0xD3, 0xDA, 0xE3),
                texte: Color32::from_rgb(0x14, 0x18, 0x1D),
                texte_faible: Color32::from_rgb(0x56, 0x61, 0x6E),
                accent: Color32::from_rgb(0x4A, 0x46, 0xC7),
                sur_accent: Color32::from_rgb(0xFF, 0xFF, 0xFF),
                // Mêmes contraintes qu'en sombre, résolues avec des valeurs plus
                // sombres : sur fond blanc, il faut assombrir pour atteindre le
                // contraste, ce qui rapproche les teintes — la triade est donc plus
                // difficile à trouver ici qu'en thème sombre.
                ok: Color32::from_rgb(0x0F, 0x8F, 0x7E),
                attention: Color32::from_rgb(0x7A, 0x52, 0x06),
                critique: Color32::from_rgb(0xC0, 0x2A, 0x46),
                info: Color32::from_rgb(0x1C, 0x5C, 0xA8),
            },
        }
    }

    /// 🔴 Le thème qui justifie la règle « la couleur n'est jamais le seul canal ».
    ///
    /// Noir et blanc francs, états poussés aux extrêmes de teinte. Il ne cherche pas à
    /// être joli : il cherche à rester lisible sur un écran fatigué, en plein soleil, ou
    /// pour quelqu'un qui distingue mal les couleurs.
    pub fn contraste_eleve() -> Self {
        Self {
            nom: "Contraste élevé".into(),
            base: Base::Sombre,
            palette: Palette {
                fond: Color32::BLACK,
                surface: Color32::from_rgb(0x0A, 0x0A, 0x0A),
                surface_haute: Color32::from_rgb(0x1A, 0x1A, 0x1A),
                bordure: Color32::from_rgb(0x8A, 0x8A, 0x8A),
                texte: Color32::WHITE,
                texte_faible: Color32::from_rgb(0xC8, 0xC8, 0xC8),
                accent: Color32::from_rgb(0xA8, 0xB4, 0xFF),
                sur_accent: Color32::BLACK,
                ok: Color32::from_rgb(0x3A, 0xE0, 0xC8),
                attention: Color32::from_rgb(0xFF, 0xD8, 0x40),
                critique: Color32::from_rgb(0xFF, 0x7A, 0x7A),
                info: Color32::from_rgb(0x8C, 0xCC, 0xFF),
            },
        }
    }

    /// Tous les thèmes livrés.
    ///
    /// Une fonction plutôt qu'une constante : les palettes ne sont pas `const`, et une
    /// liste tenue à la main finirait par oublier un thème — qu'on ne pourrait alors
    /// plus choisir.
    pub fn livres() -> Vec<Theme> {
        vec![
            Self::turi_sombre(),
            Self::turi_clair(),
            Self::contraste_eleve(),
        ]
    }

    /// Le thème nommé, ou le défaut.
    ///
    /// ⚠️ Retombe sur le défaut plutôt que d'échouer : un nom de thème périmé, gardé
    /// dans le `localStorage` d'un navigateur, ne doit pas empêcher l'interface de
    /// s'ouvrir.
    pub fn par_nom(nom: &str) -> Theme {
        Self::livres()
            .into_iter()
            .find(|t| t.nom.eq_ignore_ascii_case(nom))
            .unwrap_or_else(Self::turi_sombre)
    }

    /// Le thème qui suit le réglage du système.
    pub fn systeme(sombre: bool) -> Theme {
        if sombre {
            Self::turi_sombre()
        } else {
            Self::turi_clair()
        }
    }
}

/// Applique le thème au contexte egui.
///
/// Tout passe par ici : aucune couleur n'est posée à la main dans un écran. C'est ce qui
/// rend un changement de thème instantané et complet — un seul `Color32` oublié quelque
/// part et l'interface a l'air cassée dans le thème clair.
pub fn appliquer(ctx: &egui::Context, t: &Theme) {
    let p = &t.palette;
    let mut v = match t.base {
        Base::Sombre => egui::Visuals::dark(),
        Base::Clair => egui::Visuals::light(),
    };

    v.override_text_color = Some(p.texte);
    v.panel_fill = p.fond;
    v.window_fill = p.surface;
    v.extreme_bg_color = p.surface_haute;
    v.faint_bg_color = p.surface_haute;
    v.hyperlink_color = p.accent;
    v.error_fg_color = p.critique;
    v.warn_fg_color = p.attention;
    v.selection.bg_fill = p.accent.linear_multiply(0.35);
    v.selection.stroke = Stroke::new(1.0_f32, p.accent);

    // Les cinq états d'un widget. Les régler séparément est ce qui donne à egui une
    // apparence tenue plutôt que « thème sombre par défaut ».
    let arrondi = CornerRadius::same(mesures::RAYON_PETIT as u8);

    v.widgets.noninteractive.bg_fill = p.surface;
    v.widgets.noninteractive.weak_bg_fill = p.surface;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, p.bordure);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, p.texte_faible);
    v.widgets.noninteractive.corner_radius = arrondi;

    v.widgets.inactive.bg_fill = p.surface_haute;
    v.widgets.inactive.weak_bg_fill = p.surface_haute;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, p.bordure);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, p.texte);
    v.widgets.inactive.corner_radius = arrondi;

    v.widgets.hovered.bg_fill = melanger(p.surface_haute, p.accent, 0.18);
    v.widgets.hovered.weak_bg_fill = melanger(p.surface_haute, p.accent, 0.18);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, p.accent);
    v.widgets.hovered.fg_stroke = Stroke::new(1.5_f32, p.texte);
    v.widgets.hovered.corner_radius = arrondi;

    v.widgets.active.bg_fill = p.accent;
    v.widgets.active.weak_bg_fill = p.accent;
    v.widgets.active.bg_stroke = Stroke::new(1.0_f32, p.accent);
    v.widgets.active.fg_stroke = Stroke::new(1.5_f32, p.sur_accent);
    v.widgets.active.corner_radius = arrondi;

    v.widgets.open.bg_fill = p.surface_haute;
    v.widgets.open.weak_bg_fill = p.surface_haute;
    v.widgets.open.bg_stroke = Stroke::new(1.0_f32, p.accent);
    v.widgets.open.fg_stroke = Stroke::new(1.0_f32, p.texte);
    v.widgets.open.corner_radius = arrondi;

    // 🔴 L'anneau de focus. Sans lui, la navigation au clavier est possible mais
    // invisible : on tabule sans savoir où on est, ce qui revient à ne pas l'avoir.
    v.widgets.hovered.expansion = 1.0;

    ctx.set_visuals(v);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(mesures::ESPACE, mesures::ESPACE_SERRE + 2.0);
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    style.spacing.menu_margin = egui::Margin::same(mesures::ESPACE as i8);
    style.spacing.indent = mesures::ESPACE_LARGE;
    style.spacing.scroll.bar_width = 8.0;
    // Une interaction plus tolérante au doigt : le seuil par défaut d'egui est pensé
    // pour la souris, et les cibles tombent à côté sur téléphone.
    style.interaction.resize_grab_radius_side = 8.0;
    ctx.set_style(style);
}

/// Mélange deux couleurs. `t = 0` rend `a`, `t = 1` rend `b`.
pub fn melanger(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let m = |x: u8, y: u8| (x as f32 * (1.0 - t) + y as f32 * t).round() as u8;
    Color32::from_rgb(m(a.r(), b.r()), m(a.g(), b.g()), m(a.b(), b.b()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::design::palette::Probleme;

    #[test]
    fn every_shipped_theme_is_legible() {
        // 🔴 C'est le test qui fait de la validation autre chose qu'une décoration :
        // il s'applique aux thèmes qu'on livre, pas seulement à ceux qu'un utilisateur
        // fabriquerait.
        for t in Theme::livres() {
            let pbs = t.palette.valider();
            assert!(
                pbs.is_empty(),
                "le thème « {} » est illisible :\n{}",
                t.nom,
                pbs.iter()
                    .map(|p| format!("  - {}", p.describe()))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }

    #[test]
    fn the_accent_never_competes_with_a_state_colour() {
        // Un accent vert ferait ressembler chaque bouton principal à un voyant « tout
        // va bien », et un accent rouge à une alerte. La marque doit rester distincte
        // des trois couleurs qui portent l'état du système.
        for t in Theme::livres() {
            let p = &t.palette;
            for (nom, c) in [
                ("ok", p.ok),
                ("attention", p.attention),
                ("critique", p.critique),
            ] {
                let d = crate::design::palette::distance_deuteranope(p.accent, c);
                assert!(
                    d > 40.0,
                    "dans « {} », l'accent se confond avec « {nom} » (distance {d:.0})",
                    t.nom
                );
            }
        }
    }

    #[test]
    fn the_server_and_the_interface_agree_on_the_theme_list() {
        // 🔴 Le controller sert la liste des thèmes (`portail::THEMES`) pour que
        // l'écran de réglages n'ait pas à la deviner. Mais il ne peut pas dépendre de
        // l'interface — ce serait le sens inverse de la flèche — donc les deux listes
        // existent séparément.
        //
        // Ce test les tient alignées. Sans lui, un thème ajouté ici resterait
        // introuvable dans les réglages, et un thème retiré resterait proposé jusqu'au
        // prochain déploiement du wasm — où le choisir donnerait le défaut sans
        // explication.
        const CONTROLLER: &[&str] = &["Turi sombre", "Turi clair", "Contraste élevé"];

        let ici: Vec<String> = Theme::livres().into_iter().map(|t| t.nom).collect();
        assert_eq!(
            ici, CONTROLLER,
            "les listes de thèmes du controller et de l'interface ont divergé"
        );
    }

    #[test]
    fn an_unknown_theme_name_does_not_lock_anyone_out() {
        // ⚠️ Un nom gardé dans le localStorage d'un navigateur peut survivre à la
        // suppression du thème. Échouer laisserait l'interface refuser de s'ouvrir.
        assert_eq!(
            Theme::par_nom("un-theme-supprime").nom,
            Theme::turi_sombre().nom
        );
        assert_eq!(Theme::par_nom("turi clair").nom, "Turi clair");
        assert_eq!(Theme::par_nom("TURI SOMBRE").nom, "Turi sombre");
    }

    #[test]
    fn the_high_contrast_theme_earns_its_name() {
        let p = Theme::contraste_eleve().palette;
        let c = crate::design::palette::contraste(p.texte, p.fond);
        assert!(
            c > 15.0,
            "contraste seulement {c:.1}:1 pour un thème dit « élevé »"
        );
    }

    #[test]
    fn mixing_stays_within_the_two_colours() {
        let a = Color32::from_rgb(0, 0, 0);
        let b = Color32::from_rgb(100, 200, 255);
        assert_eq!(melanger(a, b, 0.0), a);
        assert_eq!(melanger(a, b, 1.0), b);
        // Hors bornes : on borne plutôt que d'extrapoler vers une couleur inexistante.
        assert_eq!(melanger(a, b, 5.0), b);
        assert_eq!(melanger(a, b, -1.0), a);
    }

    #[test]
    fn validation_reports_every_problem_not_just_the_first() {
        // Corriger une palette une erreur à la fois est décourageant : on veut la liste.
        let p = Palette {
            fond: Color32::from_rgb(0x30, 0x30, 0x30),
            surface: Color32::from_rgb(0x30, 0x30, 0x30),
            surface_haute: Color32::from_rgb(0x30, 0x30, 0x30),
            bordure: Color32::from_rgb(0x30, 0x30, 0x30),
            texte: Color32::from_rgb(0x38, 0x38, 0x38),
            texte_faible: Color32::from_rgb(0x34, 0x34, 0x34),
            accent: Color32::from_rgb(0x33, 0x33, 0x33),
            sur_accent: Color32::from_rgb(0x35, 0x35, 0x35),
            ok: Color32::from_rgb(0x31, 0x31, 0x31),
            attention: Color32::from_rgb(0x32, 0x32, 0x32),
            critique: Color32::from_rgb(0x33, 0x33, 0x33),
            info: Color32::from_rgb(0x34, 0x34, 0x34),
        };
        let pbs = p.valider();
        assert!(pbs.len() > 3, "une seule erreur remontée : {pbs:?}");
        assert!(pbs.iter().any(|x| matches!(x, Probleme::Contraste { .. })));
        assert!(pbs
            .iter()
            .any(|x| matches!(x, Probleme::EtatsConfondus { .. })));
    }
}
