//! The colours, named by their ROLE and not by their hue — and the check that a set of
//! them still tells the states apart.
//!
//! ## 🔴 A palette is not allowed to break the legibility of the states
//!
//! A theme is an appearance setting, except on one point: if `ok`, `attention` and
//! `critical` stop being distinguishable, the interface lies about the system's state. A
//! "pastel" theme where green and orange look alike turns an alert into decoration.
//!
//! [`Palette::validate`] therefore refuses a palette where:
//!
//! - the text does not have sufficient contrast on its background (WCAG AA);
//! - a state, the accent or "info" merges with another state — under **any** of the
//!   three colour-vision deficiencies (protanopia, deuteranopia, tritanopia), checked
//!   independently. Clearing one does not clear the others: this project shipped three
//!   themes for a while where the accent or "info" merged with a state under
//!   tritanopia specifically, invisible to a check that only simulated deuteranopia.
//!
//! It is also why colour is never the only channel: shape + word + colour. The
//! validation is a belt, not the braces.
//!
//! ## Why here
//!
//! It is a rule, and rules run in Rust: the controller refuses a declared theme or a
//! brand accent that fails it, BEFORE anyone's screen is painted with it. Checked only
//! by the interface, a refused theme would still be offered, stored, and served.

/// A colour, as the three sRGB bytes.
pub type Rgb = [u8; 3];

/// Whether a theme draws light text on dark surfaces, or the reverse.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Base {
    Dark,
    Light,
}

impl Base {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "dark" => Some(Self::Dark),
            "light" => Some(Self::Light),
            _ => None,
        }
    }
}

/// `#RRGGBB`, the form a stylesheet reads.
pub fn hex([r, g, b]: Rgb) -> String {
    format!("#{r:02X}{g:02X}{b:02X}")
}

/// A theme's colours, by role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    /// The page background.
    pub background: Rgb,
    /// The background of a card or a panel.
    pub surface: Rgb,
    /// One level above: table header, hovered row, input field.
    pub raised_surface: Rgb,
    pub border: Rgb,
    pub text: Rgb,
    /// Metadata, secondary labels. Must stay readable, not decorative.
    pub muted_text: Rgb,
    /// The brand's colour. Used for primary actions and the active element.
    pub accent: Rgb,
    /// What sits ON the accent (a primary button's text).
    pub on_accent: Rgb,
    pub ok: Rgb,
    pub attention: Rgb,
    pub critical: Rgb,
    pub info: Rgb,
}

/// What is wrong with a palette.
#[derive(Debug, Clone, PartialEq)]
pub enum PaletteProblem {
    /// Illegible text on its background.
    Contrast {
        what: &'static str,
        measure: f32,
        requires: f32,
    },
    /// 🔴 Two colours confused under a simulated colour-vision deficiency.
    MergedStates {
        a: &'static str,
        b: &'static str,
        /// Reported by name: a fix that clears deuteranopia can still leave two colours
        /// merged under tritanopia, and one undifferentiated "merged" problem would send
        /// someone fixing the wrong colour.
        deficiency: &'static str,
        distance: f32,
    },
}

impl PaletteProblem {
    pub fn describe(&self) -> String {
        match self {
            Self::Contrast {
                what,
                measure,
                requires,
            } => format!(
                "{what}: contrast {measure:.2}:1, {requires:.1}:1 is required - \
                 unreadable for a lot of people, and not only in sunlight"
            ),
            Self::MergedStates {
                a,
                b,
                deficiency,
                distance,
            } => format!(
                // Truncated, not rounded: 59.6 printed as "60, 60 needed" reads as a
                // refusal of a colour that passes.
                "\"{a}\" and \"{b}\" merge under {deficiency} (distance {:.0}, \
                 {STATE_DISTANCE:.0} needed). Someone with this colour vision would not \
                 see the difference between an alert and a normal state",
                distance.floor()
            ),
        }
    }

    /// Does this problem concern the accent? Used to blame a brand accent only for what
    /// it caused, not for a theme's own defects.
    fn involves_accent(&self) -> bool {
        match self {
            Self::Contrast {
                what,
                measure: _,
                requires: _,
            } => *what == ON_ACCENT,
            Self::MergedStates {
                a,
                b,
                deficiency: _,
                distance: _,
            } => *a == "accent" || *b == "accent",
        }
    }
}

/// Minimum contrast for body text (WCAG 2.1, level AA).
pub const TEXT_CONTRAST: f32 = 4.5;
/// For secondary text and large characters (AA large).
pub const WEAK_CONTRAST: f32 = 3.0;
/// Below this, two state colours are too close once a deficiency is simulated.
///
/// ⚠️ "info" against "ok" in the high-contrast theme once measured 58: this close is
/// how a check with no margin passes review and fails in the field.
pub const STATE_DISTANCE: f32 = 60.0;

const ON_ACCENT: &str = "text on the accent";

impl Palette {
    /// This palette's problems. Empty = usable.
    pub fn validate(&self) -> Vec<PaletteProblem> {
        let mut p = Vec::new();

        for (what, fg, bg, requires) in [
            (
                "text on the background",
                self.text,
                self.background,
                TEXT_CONTRAST,
            ),
            ("text on a surface", self.text, self.surface, TEXT_CONTRAST),
            (
                "secondary text",
                self.muted_text,
                self.surface,
                WEAK_CONTRAST,
            ),
            (ON_ACCENT, self.on_accent, self.accent, WEAK_CONTRAST),
            ("ok state", self.ok, self.surface, WEAK_CONTRAST),
            (
                "attention state",
                self.attention,
                self.surface,
                WEAK_CONTRAST,
            ),
            ("critical state", self.critical, self.surface, WEAK_CONTRAST),
        ] {
            let m = contrast(fg, bg);
            if m < requires {
                p.push(PaletteProblem::Contrast {
                    what,
                    measure: m,
                    requires,
                });
            }
        }

        // 🔴 Not just the three state lights against each other: an accent or the
        // "info" colour that merges with a state is exactly as misleading — a primary
        // button that reads as an alert, or an informational banner nobody notices is
        // actually the critical one.
        for (na, a, nb, b) in [
            ("ok", self.ok, "attention", self.attention),
            ("attention", self.attention, "critical", self.critical),
            ("ok", self.ok, "critical", self.critical),
            ("accent", self.accent, "ok", self.ok),
            ("accent", self.accent, "attention", self.attention),
            ("accent", self.accent, "critical", self.critical),
            ("info", self.info, "ok", self.ok),
            ("info", self.info, "attention", self.attention),
            ("info", self.info, "critical", self.critical),
        ] {
            for (deficiency, m) in [
                ("protanopia", PROTANOPIA),
                ("deuteranopia", DEUTERANOPIA),
                ("tritanopia", TRITANOPIA),
            ] {
                let d = distance_under(a, b, m);
                if d < STATE_DISTANCE {
                    p.push(PaletteProblem::MergedStates {
                        a: na,
                        b: nb,
                        deficiency,
                        distance: d,
                    });
                }
            }
        }

        p
    }

    /// What the accent alone breaks in this palette.
    ///
    /// For a brand accent, laid over a theme that already passed [`Self::validate`]: a
    /// theme's own defect is the theme's to answer for, not the accent's.
    pub fn accent_problems(&self, accent: Rgb) -> Vec<PaletteProblem> {
        self.with_accent(accent)
            .validate()
            .into_iter()
            .filter(PaletteProblem::involves_accent)
            .collect()
    }

    /// The same palette, with another accent.
    ///
    /// This is how the brand colours the interface without a full theme being
    /// necessary: `Brand::accent` replaces the single token that carries the identity.
    pub fn with_accent(mut self, accent: Rgb) -> Self {
        self.accent = accent;
        // ⚠️ The text placed ON the accent must follow: a light accent with white text
        // becomes invisible, and it is the primary button that disappears. Whichever of
        // the two contrasts MORE, not a luminance cut-off: `luminance > 0.4` handed
        // Dark's own violet white text, at 2.98:1 against the 3:1 required.
        let (dark, white) = ([0x14, 0x18, 0x1D], [0xFF, 0xFF, 0xFF]);
        self.on_accent = if contrast(dark, accent) >= contrast(white, accent) {
            dark
        } else {
            white
        };
        self
    }

    /// The palette of a shipped theme, by its name in [`crate::THEMES`].
    ///
    /// ⚠️ A test walks `THEMES` and requires a palette for each: a name added there
    /// without its colours here would be offered and then painted with nothing.
    pub fn shipped(name: &str) -> Option<Palette> {
        Self::shipped_with_base(name).map(|(_, p)| p)
    }

    /// The same, with whether it is drawn on dark or on light — in the same `match`,
    /// so a shipped theme cannot have colours without a base.
    pub fn shipped_with_base(name: &str) -> Option<(Base, Palette)> {
        match name {
            // Dark, the default: an infrastructure dashboard is looked at more often at
            // night than in the sun, and a white screen at 3 a.m. is an assault.
            "Dark" => Some((
                Base::Dark,
                Palette {
                    background: [0x0F, 0x12, 0x16],
                    surface: [0x17, 0x1B, 0x21],
                    raised_surface: [0x1E, 0x24, 0x2B],
                    border: [0x2A, 0x32, 0x3B],
                    text: [0xE6, 0xEA, 0xEF],
                    muted_text: [0x96, 0xA1, 0xAD],
                    // 🔴 Cool, not the industrial copper you would spontaneously choose:
                    // under deuteranopia a warm accent merges with "critical", and every
                    // primary button reads as an alert. With a state triad running from
                    // green to red, a COOL accent is a constraint, not a taste. Blue
                    // rather than the indigo it was, which read as a template; and LIGHT,
                    // because a mid blue (#6AA6FF) merges with "ok" under tritanopia (18).
                    accent: [0x86, 0xB4, 0xF9],
                    on_accent: [0x0F, 0x12, 0x16],
                    // 🔴 A green leaning towards blue, not the traffic-light green: plain
                    // green and red converge under deuteranopia (distance 35). Shifted
                    // towards cyan, the gap goes to 94.
                    ok: [0x38, 0xC7, 0xB4],
                    attention: [0xFF, 0xC9, 0x4D],
                    critical: [0xF0, 0x5C, 0x5C],
                    // Merged with "ok" under tritanopia (17) until nudged less cyan.
                    info: [0x7E, 0xA4, 0xF8],
                },
            )),
            "Light" => Some((
                Base::Light,
                Palette {
                    background: [0xF4, 0xF6, 0xF9],
                    surface: [0xFF, 0xFF, 0xFF],
                    raised_surface: [0xEB, 0xEF, 0xF4],
                    border: [0xD3, 0xDA, 0xE3],
                    text: [0x14, 0x18, 0x1D],
                    muted_text: [0x56, 0x61, 0x6E],
                    // Blue, for the dark theme's reason; deep, because a brighter one (#1D5FD6)
                    // merges with "ok" under tritanopia (42).
                    accent: [0x1A, 0x52, 0xB4],
                    on_accent: [0xFF, 0xFF, 0xFF],
                    // On white you darken to reach the contrast, which brings the hues
                    // closer: the triad is harder to find here than in the dark theme. This
                    // "ok" merged with BOTH the accent and "info" under tritanopia (44 and
                    // 39) until its green channel was lightened.
                    ok: [0x0F, 0xA4, 0x84],
                    attention: [0x7A, 0x52, 0x06],
                    critical: [0xC0, 0x2A, 0x46],
                    info: [0x1C, 0x5C, 0xA8],
                },
            )),
            // 🔴 The theme that justifies "colour is never the only channel": plain
            // black and white, states pushed to the extremes of hue. Not pretty;
            // readable on a tired screen, in full sunlight, or for someone who
            // distinguishes colours poorly.
            "High contrast" => Some((
                Base::Dark,
                Palette {
                    background: [0x00, 0x00, 0x00],
                    surface: [0x0A, 0x0A, 0x0A],
                    raised_surface: [0x1A, 0x1A, 0x1A],
                    border: [0x8A, 0x8A, 0x8A],
                    text: [0xFF, 0xFF, 0xFF],
                    muted_text: [0xC8, 0xC8, 0xC8],
                    accent: [0xA8, 0xB4, 0xFF],
                    on_accent: [0x00, 0x00, 0x00],
                    ok: [0x3A, 0xE0, 0xC8],
                    attention: [0xFF, 0xD8, 0x40],
                    critical: [0xFF, 0x7A, 0x7A],
                    info: [0x87, 0xBC, 0xFF],
                },
            )),
            _ => None,
        }
    }
}

/// The WCAG contrast ratio between two opaque colours.
///
/// `(L1 + 0.05) / (L2 + 0.05)`, the lighter one on top: between 1 (identical) and 21
/// (black on white).
pub fn contrast(a: Rgb, b: Rgb) -> f32 {
    let (la, lb) = (luminance(a), luminance(b));
    let (lighter, darker) = if la > lb { (la, lb) } else { (lb, la) };
    (lighter + 0.05) / (darker + 0.05)
}

/// The relative luminance (WCAG 2.1).
pub fn luminance([r, g, b]: Rgb) -> f32 {
    0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
}

fn linear(v: u8) -> f32 {
    let s = v as f32 / 255.0;
    if s <= 0.040_45 {
        s / 12.92
    } else {
        ((s + 0.055) / 1.055).powf(2.4)
    }
}

/// A colour-vision-deficiency simulation matrix (Machado et al. 2009, severity 1.0),
/// applied in linear RGB. Row-major: `[[Rr,Rg,Rb], [Gr,Gg,Gb], [Br,Bg,Bb]]`.
type Matrix = [[f32; 3]; 3];

const PROTANOPIA: Matrix = [
    [0.152_286, 1.052_583, -0.204_868],
    [0.114_503, 0.786_281, 0.099_216],
    [-0.003_882, -0.048_116, 1.051_998],
];
const DEUTERANOPIA: Matrix = [
    [0.367_322, 0.860_646, -0.227_968],
    [0.280_085, 0.672_501, 0.047_413],
    [-0.011_820, 0.042_940, 0.968_881],
];
const TRITANOPIA: Matrix = [
    [1.255_528, -0.076_749, -0.178_779],
    [-0.078_411, 0.930_809, 0.147_602],
    [0.004_733, 0.691_367, 0.303_900],
];

/// The distance between two colours **as this deficiency would see them**.
///
/// Euclidean in sRGB after simulation. Not a rigorous perceptual metric — that would be
/// CIEDE2000 — but enough for the question asked: "are these two lights
/// distinguishable?"
fn distance_under(a: Rgb, b: Rgb, m: Matrix) -> f32 {
    let (sa, sb) = (simulate(a, m), simulate(b, m));
    sa.iter()
        .zip(sb.iter())
        .map(|(&x, &y)| (x as f32 - y as f32).powi(2))
        .sum::<f32>()
        .sqrt()
}

fn simulate([r, g, b]: Rgb, m: Matrix) -> Rgb {
    let srgb = |v: f32| {
        let v = v.clamp(0.0, 1.0);
        let s = if v <= 0.003_130_8 {
            v * 12.92
        } else {
            1.055 * v.powf(1.0 / 2.4) - 0.055
        };
        (s * 255.0).round().clamp(0.0, 255.0) as u8
    };
    let (r, g, b) = (linear(r), linear(g), linear(b));
    [
        srgb(m[0][0] * r + m[0][1] * g + m[0][2] * b),
        srgb(m[1][0] * r + m[1][1] * g + m[1][2] * b),
        srgb(m[2][0] * r + m[2][1] * g + m[2][2] * b),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shipped_theme_has_a_palette_and_passes_its_own_check() {
        // 🔴 Walks `THEMES`, the list the controller offers: a name there with no
        // palette here would be selectable and paint nothing. And the validator caught
        // four real merges in these palettes once — they are not exempt from it.
        for name in crate::THEMES {
            let p = Palette::shipped(name)
                .unwrap_or_else(|| panic!("\"{name}\" is offered and has no palette"));
            let problems: Vec<String> = p.validate().iter().map(|x| x.describe()).collect();
            assert!(problems.is_empty(), "{name}: {problems:#?}");
        }
    }

    #[test]
    fn contrast_matches_the_reference_extremes() {
        // Black on white: 21:1, WCAG's upper bound. A colour on itself: 1.
        let (black, white) = ([0, 0, 0], [0xFF, 0xFF, 0xFF]);
        assert!((contrast(black, white) - 21.0).abs() < 0.01);
        assert!((contrast(white, white) - 1.0).abs() < 0.001);
        assert!((contrast(black, white) - contrast(white, black)).abs() < 0.001);
    }

    fn shipped_dark() -> Palette {
        Palette::shipped("Dark").expect("shipped")
    }

    #[test]
    fn a_palette_where_green_and_orange_merge_is_refused() {
        // 🔴 The case that counts: a "pastel" theme where the alert becomes decorative.
        // Three very close yellow-greens.
        let p = Palette {
            ok: [0x6A, 0x9C, 0x3D],
            attention: [0x7E, 0x99, 0x35],
            critical: [0x8B, 0x96, 0x30],
            ..shipped_dark()
        };
        let pbs = p.validate();
        assert!(
            pbs.iter()
                .any(|x| matches!(x, PaletteProblem::MergedStates { .. })),
            "{pbs:?}"
        );
    }

    #[test]
    fn illegible_text_is_refused() {
        // Dark grey on a dark background: the "it looks fine on my screenshot" case.
        let p = Palette {
            text: [0x3A, 0x3A, 0x3A],
            ..shipped_dark()
        };
        let pbs = p.validate();
        assert!(
            pbs.iter()
                .any(|x| matches!(x, PaletteProblem::Contrast { .. })),
            "{pbs:?}"
        );
    }

    #[test]
    fn a_problem_says_what_is_wrong_and_for_whom() {
        // "Insufficient contrast" helps nobody choose another colour.
        let m = PaletteProblem::MergedStates {
            a: "ok",
            b: "critical",
            deficiency: "deuteranopia",
            distance: 12.0,
        }
        .describe();
        assert!(m.contains("ok") && m.contains("critical"), "{m}");
        assert!(m.contains("deuteranopia"), "which deficiency: {m}");
    }

    #[test]
    fn deuteranopia_keeps_blue_and_yellow_apart() {
        // A control on the simulation: it is RED and GREEN that come closer, not blue
        // and yellow. A simulation that flattened everything would refuse every palette,
        // and you would disable it — so it would no longer protect.
        let (blue, yellow) = ([0x20, 0x60, 0xE0], [0xE0, 0xC0, 0x20]);
        let (red, green) = ([0xC0, 0x30, 0x30], [0x30, 0xA0, 0x30]);
        let by = distance_under(blue, yellow, DEUTERANOPIA);
        assert!(by > STATE_DISTANCE, "blue and yellow stay apart: {by}");
        assert!(distance_under(red, green, DEUTERANOPIA) < by);
    }

    #[test]
    fn an_accent_change_carries_its_foreground_with_it() {
        // 🔴 A light accent with white text makes the primary button invisible.
        for accent in [[0xFF, 0xE0, 0x60], [0x20, 0x30, 0x60]] {
            let p = shipped_dark().with_accent(accent);
            assert!(
                contrast(p.on_accent, p.accent) >= WEAK_CONTRAST,
                "{accent:?}"
            );
        }
    }

    #[test]
    fn a_warm_accent_is_blamed_and_a_cool_one_is_not() {
        // 🔴 The copper this project first chose: under deuteranopia it merges with
        // "critical", and every primary button reads as an alert.
        let copper = [0xE0, 0x7A, 0x3F];
        let pbs = shipped_dark().accent_problems(copper);
        assert!(
            pbs.iter().any(|p| matches!(
                p,
                PaletteProblem::MergedStates {
                    a: "accent",
                    b: "critical",
                    ..
                }
            )),
            "{pbs:?}"
        );
        assert_eq!(shipped_dark().accent_problems([0x7B, 0x8C, 0xFF]), vec![]);
    }

    #[test]
    fn an_accent_is_not_blamed_for_the_theme_it_lands_on() {
        // A theme whose own text is illegible is the theme's problem: refusing the
        // brand accent for it would send someone changing the wrong setting.
        let broken = Palette {
            text: [0x3A, 0x3A, 0x3A],
            ..shipped_dark()
        };
        assert_eq!(broken.accent_problems([0x7B, 0x8C, 0xFF]), vec![]);
    }
}
