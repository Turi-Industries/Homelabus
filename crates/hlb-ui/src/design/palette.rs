//! Les couleurs, nommées par leur RÔLE et non par leur teinte.
//!
//! ## Pourquoi des jetons plutôt que des couleurs
//!
//! `Color32::from_rgb(0x4c, 0xaf, 0x50)` écrit en dur dans un écran est une couleur
//! qu'aucun thème ne pourra changer. Nommer le rôle — `ok`, `critique`, `surface` —
//! permet à un thème d'être une simple substitution, et à un test de vérifier que la
//! substitution reste lisible.
//!
//! ## 🔴 Une palette n'a pas le droit de casser la lisibilité des états
//!
//! Un thème est un réglage d'apparence, sauf sur un point : si `ok`, `attention` et
//! `critique` cessent d'être distinguables, l'interface ment sur l'état du système. Un
//! thème « pastel » où le vert et l'orange se ressemblent transforme une alerte en
//! décoration.
//!
//! [`Palette::valider`] refuse donc une palette dont :
//!
//! - le texte n'a pas un contraste suffisant sur son fond (WCAG AA) ;
//! - les trois couleurs d'état ne se distinguent pas **en vision deutéranope**, qui
//!   concerne environ 8 % des hommes — et pour qui le rouge et le vert sont proches.
//!
//! C'est aussi pourquoi la couleur n'est jamais le seul canal : forme peinte + mot +
//! couleur. La validation est une ceinture, pas la bretelle.

use egui::Color32;

/// Les couleurs d'un thème, par rôle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    /// Le fond de la page.
    pub fond: Color32,
    /// Le fond d'une carte, d'un panneau.
    pub surface: Color32,
    /// Un niveau au-dessus : en-tête de tableau, ligne survolée, champ de saisie.
    pub surface_haute: Color32,
    pub bordure: Color32,
    pub texte: Color32,
    /// Métadonnées, libellés secondaires. Doit rester lisible, pas décoratif.
    pub texte_faible: Color32,
    /// La couleur de la marque. Sert aux actions principales et à l'élément actif.
    pub accent: Color32,
    /// Ce qui se pose SUR l'accent (texte d'un bouton principal).
    pub sur_accent: Color32,
    pub ok: Color32,
    pub attention: Color32,
    pub critique: Color32,
    pub info: Color32,
}

/// Ce qui cloche dans une palette.
#[derive(Debug, Clone, PartialEq)]
pub enum Probleme {
    /// Un texte illisible sur son fond.
    Contraste {
        quoi: &'static str,
        mesure: f32,
        exige: f32,
    },
    /// 🔴 Deux couleurs d'état confondues par une vision deutéranope.
    EtatsConfondus {
        a: &'static str,
        b: &'static str,
        distance: f32,
    },
}

impl Probleme {
    pub fn describe(&self) -> String {
        match self {
            Self::Contraste { quoi, mesure, exige } => format!(
                "{quoi} : contraste {mesure:.2}:1, il en faut {exige:.1}:1 — \
                 illisible pour beaucoup de monde, et pas seulement au soleil"
            ),
            Self::EtatsConfondus { a, b, distance } => format!(
                "🔴 « {a} » et « {b} » se confondent en vision deutéranope \
                 (distance {distance:.0}). Environ 8 % des hommes ne verraient pas la \
                 différence entre une alerte et un état normal"
            ),
        }
    }
}

/// Contraste minimal pour du texte courant (WCAG 2.1, niveau AA).
pub const CONTRASTE_TEXTE: f32 = 4.5;
/// Pour du texte secondaire et des grands caractères (AA large).
pub const CONTRASTE_FAIBLE: f32 = 3.0;
/// En deçà, deux couleurs d'état sont trop proches une fois simulée la deutéranopie.
pub const DISTANCE_ETATS: f32 = 60.0;

impl Palette {
    /// Les problèmes de cette palette. Vide = utilisable.
    pub fn valider(&self) -> Vec<Probleme> {
        let mut p = Vec::new();

        for (quoi, avant, arriere, exige) in [
            ("texte sur le fond", self.texte, self.fond, CONTRASTE_TEXTE),
            ("texte sur une surface", self.texte, self.surface, CONTRASTE_TEXTE),
            ("texte secondaire", self.texte_faible, self.surface, CONTRASTE_FAIBLE),
            ("texte sur l'accent", self.sur_accent, self.accent, CONTRASTE_FAIBLE),
            ("état ok", self.ok, self.surface, CONTRASTE_FAIBLE),
            ("état attention", self.attention, self.surface, CONTRASTE_FAIBLE),
            ("état critique", self.critique, self.surface, CONTRASTE_FAIBLE),
        ] {
            let m = contraste(avant, arriere);
            if m < exige {
                p.push(Probleme::Contraste { quoi, mesure: m, exige });
            }
        }

        for (na, a, nb, b) in [
            ("ok", self.ok, "attention", self.attention),
            ("attention", self.attention, "critique", self.critique),
            ("ok", self.ok, "critique", self.critique),
        ] {
            let d = distance_deuteranope(a, b);
            if d < DISTANCE_ETATS {
                p.push(Probleme::EtatsConfondus { a: na, b: nb, distance: d });
            }
        }

        p
    }

    /// La couleur d'un niveau d'attention.
    pub fn attention_de(&self, a: hlb_api::Attention) -> Color32 {
        match a {
            hlb_api::Attention::Ok => self.ok,
            hlb_api::Attention::Notice => self.attention,
            hlb_api::Attention::Critical => self.critique,
        }
    }

    /// La même palette, avec un autre accent.
    ///
    /// C'est ainsi que la marque colore l'interface sans qu'un thème complet soit
    /// nécessaire : `Marque::accent` remplace le seul jeton qui porte l'identité.
    pub fn avec_accent(mut self, accent: Color32) -> Self {
        self.accent = accent;
        // ⚠️ Le texte posé SUR l'accent doit suivre : un accent clair avec un texte
        // blanc devient invisible, et c'est le bouton principal qui disparaît.
        self.sur_accent = if luminance(accent) > 0.4 {
            Color32::from_rgb(0x14, 0x18, 0x1D)
        } else {
            Color32::from_rgb(0xFF, 0xFF, 0xFF)
        };
        self
    }
}

/// Le rapport de contraste WCAG entre deux couleurs opaques.
///
/// `(L1 + 0.05) / (L2 + 0.05)`, le plus clair au numérateur. Rend une valeur entre 1
/// (identiques) et 21 (noir sur blanc).
pub fn contraste(a: Color32, b: Color32) -> f32 {
    let (la, lb) = (luminance(a), luminance(b));
    let (haut, bas) = if la > lb { (la, lb) } else { (lb, la) };
    (haut + 0.05) / (bas + 0.05)
}

/// La luminance relative (WCAG 2.1).
pub fn luminance(c: Color32) -> f32 {
    fn canal(v: u8) -> f32 {
        let s = v as f32 / 255.0;
        if s <= 0.040_45 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    }
    0.2126 * canal(c.r()) + 0.7152 * canal(c.g()) + 0.0722 * canal(c.b())
}

/// La distance entre deux couleurs **telles que les verrait une vision deutéranope**.
///
/// Simulation par la matrice de Machado et al. (2009) à sévérité 1, appliquée en RGB
/// linéaire, puis distance euclidienne en sRGB. Ce n'est pas une métrique perceptuelle
/// rigoureuse — ce serait CIEDE2000 — mais elle suffit largement pour la question
/// posée : « ces deux voyants sont-ils distinguables ? »
pub fn distance_deuteranope(a: Color32, b: Color32) -> f32 {
    let sa = simuler_deuteranopie(a);
    let sb = simuler_deuteranopie(b);
    let d = |x: u8, y: u8| (x as f32 - y as f32).powi(2);
    (d(sa.r(), sb.r()) + d(sa.g(), sb.g()) + d(sa.b(), sb.b())).sqrt()
}

fn simuler_deuteranopie(c: Color32) -> Color32 {
    let lin = |v: u8| {
        let s = v as f32 / 255.0;
        if s <= 0.040_45 {
            s / 12.92
        } else {
            ((s + 0.055) / 1.055).powf(2.4)
        }
    };
    let srgb = |v: f32| {
        let v = v.clamp(0.0, 1.0);
        let s = if v <= 0.003_130_8 {
            v * 12.92
        } else {
            1.055 * v.powf(1.0 / 2.4) - 0.055
        };
        (s * 255.0).round().clamp(0.0, 255.0) as u8
    };

    let (r, g, b) = (lin(c.r()), lin(c.g()), lin(c.b()));
    Color32::from_rgb(
        srgb(0.367_322 * r + 0.860_646 * g - 0.227_968 * b),
        srgb(0.280_085 * r + 0.672_501 * g + 0.047_413 * b),
        srgb(-0.011_820 * r + 0.042_940 * g + 0.968_881 * b),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contrast_matches_the_reference_extremes() {
        // Noir sur blanc : 21:1, la borne haute de WCAG. Une couleur sur elle-même : 1.
        let n = Color32::BLACK;
        let b = Color32::WHITE;
        assert!((contraste(n, b) - 21.0).abs() < 0.01, "{}", contraste(n, b));
        assert!((contraste(b, b) - 1.0).abs() < 0.001);
        // Symétrique : l'ordre des arguments ne doit pas changer le verdict.
        assert!((contraste(n, b) - contraste(b, n)).abs() < 0.001);
    }

    #[test]
    fn a_palette_where_green_and_orange_merge_is_refused() {
        // 🔴 Le cas qui compte : un thème « pastel » où l'alerte devient décorative.
        let p = Palette {
            fond: Color32::WHITE,
            surface: Color32::WHITE,
            surface_haute: Color32::WHITE,
            bordure: Color32::GRAY,
            texte: Color32::BLACK,
            texte_faible: Color32::from_rgb(0x55, 0x55, 0x55),
            accent: Color32::from_rgb(0x00, 0x40, 0x80),
            sur_accent: Color32::WHITE,
            // Trois verts-jaunes très proches : en vision deutéranope, ils fusionnent.
            ok: Color32::from_rgb(0x6A, 0x9C, 0x3D),
            attention: Color32::from_rgb(0x7E, 0x99, 0x35),
            critique: Color32::from_rgb(0x8B, 0x96, 0x30),
            info: Color32::from_rgb(0x30, 0x60, 0xA0),
        };
        let pbs = p.valider();
        assert!(
            pbs.iter().any(|x| matches!(x, Probleme::EtatsConfondus { .. })),
            "une palette où les états fusionnent doit être refusée : {pbs:?}"
        );
    }

    #[test]
    fn illegible_text_is_refused() {
        let p = Palette {
            fond: Color32::from_rgb(0x20, 0x20, 0x20),
            surface: Color32::from_rgb(0x20, 0x20, 0x20),
            surface_haute: Color32::from_rgb(0x28, 0x28, 0x28),
            bordure: Color32::from_rgb(0x30, 0x30, 0x30),
            // Gris sombre sur fond sombre : le cas « ça rend bien sur ma capture ».
            texte: Color32::from_rgb(0x3A, 0x3A, 0x3A),
            texte_faible: Color32::from_rgb(0x30, 0x30, 0x30),
            accent: Color32::from_rgb(0xE0, 0x7A, 0x3F),
            sur_accent: Color32::WHITE,
            ok: Color32::from_rgb(0x4F, 0xB4, 0x77),
            attention: Color32::from_rgb(0xE0, 0xA3, 0x3F),
            critique: Color32::from_rgb(0xE0, 0x52, 0x52),
            info: Color32::from_rgb(0x4F, 0x8F, 0xD6),
        };
        let pbs = p.valider();
        assert!(pbs.iter().any(|x| matches!(x, Probleme::Contraste { .. })), "{pbs:?}");
    }

    #[test]
    fn a_problem_says_what_is_wrong_and_for_whom() {
        // Un message de validation qui dit « contraste insuffisant » n'aide personne à
        // choisir une autre couleur.
        let p = Probleme::EtatsConfondus { a: "ok", b: "critique", distance: 12.0 };
        let m = p.describe();
        assert!(m.contains("ok") && m.contains("critique"), "{m}");
        assert!(m.contains("8 %"), "le message doit dire qui est concerné : {m}");
    }

    #[test]
    fn deuteranopia_keeps_blue_and_yellow_apart() {
        // Contrôle de la simulation : c'est le ROUGE et le VERT qui se rapprochent,
        // pas le bleu et le jaune. Une simulation qui écraserait tout ferait refuser
        // toutes les palettes, et on la désactiverait — donc elle ne protégerait plus.
        let bleu = Color32::from_rgb(0x20, 0x60, 0xE0);
        let jaune = Color32::from_rgb(0xE0, 0xC0, 0x20);
        assert!(
            distance_deuteranope(bleu, jaune) > DISTANCE_ETATS,
            "bleu et jaune restent distincts : {}",
            distance_deuteranope(bleu, jaune)
        );

        let rouge = Color32::from_rgb(0xC0, 0x30, 0x30);
        let vert = Color32::from_rgb(0x30, 0xA0, 0x30);
        assert!(
            distance_deuteranope(rouge, vert) < distance_deuteranope(bleu, jaune),
            "le rouge et le vert doivent se rapprocher plus que le bleu et le jaune"
        );
    }

    #[test]
    fn an_accent_change_carries_its_foreground_with_it() {
        // 🔴 Un accent clair avec un texte blanc rend le bouton principal invisible.
        let base = crate::design::theme::Theme::turi_sombre().palette;

        let clair = base.avec_accent(Color32::from_rgb(0xFF, 0xE0, 0x60));
        assert!(
            contraste(clair.sur_accent, clair.accent) >= CONTRASTE_FAIBLE,
            "texte illisible sur un accent clair : {}",
            contraste(clair.sur_accent, clair.accent)
        );

        let sombre = base.avec_accent(Color32::from_rgb(0x20, 0x30, 0x60));
        assert!(contraste(sombre.sur_accent, sombre.accent) >= CONTRASTE_FAIBLE);
    }
}
