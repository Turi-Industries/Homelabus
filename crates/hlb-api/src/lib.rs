//! The controller API types, **defined exactly once**.
//!
//! ## Why this crate exists
//!
//! The server serialises these types, the CLI deserialises them, and the web interface
//! receives TypeScript GENERATED from them through the controller's OpenAPI document —
//! never written by hand. A field renamed here must break the interface's type check,
//! instead of producing an `undefined` at runtime, three weeks later, on a screen
//! nobody was looking at.
//!
//! ## 🔴 The rules stay on this side
//!
//! `attention()`, `verdict()`, `coverage()` and their neighbours are business rules. The
//! browser cannot run them, and a TypeScript copy of one would drift from this one. What
//! the interface needs from a rule reaches it as a serialised VALUE the controller
//! computed — a structure, never a sentence, so the interface says it in its own
//! language.
//!
//! ## What does NOT go here
//!
//! No secret value, ever. The types carry **names** and **purposes** (see
//! [`SecretItem`]), and the absence of any field for the value is the guarantee: you
//! cannot leak what you cannot represent.

/// Declares a wire type whose rules travel beside its fields: the struct's own fields,
/// then the VALUE of each rule, computed by the method when the type is serialised.
///
/// 🔴 Computed at serialisation, by the method, never stored in the struct. A stored copy
/// is a second spelling of the rule, and every struct literal — a handler, the demo, a
/// test — is a chance to fill it in wrong; the field and the method would then disagree
/// on the wire with nothing to notice. Here the method stays the one place the rule
/// lives, and the browser receives what it decided.
///
/// The struct gets `#[serde(remote = "Self")]`, which turns its derived `Serialize` and
/// `Deserialize` into inherent functions: the macro wraps the first and forwards the
/// second, which ignores the computed fields it is sent back.
///
/// It wraps the whole struct because the OpenAPI schema must list the rules too, and a
/// derived `ToSchema` sees only fields: the schema is derived from a mirror holding the
/// fields and then the rules, written out by the macro from the same tokens — so it
/// cannot drift from the struct, and a rule named like a field is a compile error
/// rather than a key the JSON carries twice.
macro_rules! judged {
    (
        $(#[doc = $doc:expr])*
        #[derive($($derive:path),* $(,)?)]
        $vis:vis struct $ty:ident {
            $( $(#[$fattr:meta])* $fvis:vis $field:ident : $fty:ty ),* $(,)?
        }

        rules {
            $( $(#[$rattr:meta])* $rule:ident : $rty:ty = $expr:expr ),+ $(,)?
        }
    ) => {
        $(#[doc = $doc])*
        #[derive($($derive),*)]
        #[derive(serde::Serialize, serde::Deserialize)]
        #[serde(remote = "Self")]
        $vis struct $ty {
            $( $(#[$fattr])* $fvis $field: $fty, )*
        }

        impl serde::Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                fn fields<S: serde::Serializer>(v: &&$ty, s: S) -> Result<S::Ok, S::Error> {
                    $ty::serialize(*v, s)
                }
                #[derive(serde::Serialize)]
                struct Judged<'a> {
                    #[serde(flatten, serialize_with = "fields")]
                    fields: &'a $ty,
                    $($rule: $rty,)+
                }
                Judged {
                    fields: self,
                    $($rule: ($expr)(self),)+
                }
                .serialize(s)
            }
        }

        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                $ty::deserialize(d)
            }
        }

        const _: () = {
            $(#[doc = $doc])*
            #[derive(serde::Serialize, utoipa::ToSchema)]
            #[schema(as = $ty)]
            #[allow(dead_code)]
            struct Wire {
                $( $(#[$fattr])* $field: $fty, )*
                $( $(#[$rattr])* $rule: $rty, )+
            }

            impl utoipa::PartialSchema for $ty {
                fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
                    <Wire as utoipa::PartialSchema>::schema()
                }
            }

            impl utoipa::ToSchema for $ty {
                fn name() -> std::borrow::Cow<'static, str> {
                    <Wire as utoipa::ToSchema>::name()
                }

                fn schemas(
                    schemas: &mut Vec<(
                        String,
                        utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
                    )>,
                ) {
                    <Wire as utoipa::ToSchema>::schemas(schemas)
                }
            }
        };
    };
}

pub mod assertions;
pub mod breakglass;
pub mod diagnostic;
pub mod domain;
pub mod intent;
pub mod invitation;
pub mod issues;
pub mod jobs;
pub mod mail_dns;
pub mod mail_queue;
pub mod outage;
pub mod palette;
pub mod roles;
pub mod rotation;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The controller's health.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Health {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
    /// Where this build's source can be read. The AGPL (§13) has whoever runs a
    /// modified copy for others offer them its source, so the interface links here.
    pub source: String,
}

/// The body of every refusal the API answers, whatever its status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ErrorBody {
    /// A sentence for a person, in English: the status code is what a program branches
    /// on.
    pub error: String,
}

judged! {
    /// An installed app, as the dashboard sees it.
    #[derive(Debug, Clone, PartialEq)]
    pub struct AppSummary {
        pub name: String,
        /// `running`, `partial`, `failed`, `installing`…
        pub status: String,
        pub image: String,
        pub domain: Option<String>,
        /// Age of the last successful backup, in seconds.
        ///
        /// 🔴 `None` = **never backed up**, which is not the same as "backed up 0 seconds
        /// ago". The type enforces the distinction; the UI must display them differently,
        /// or the most at-risk app is the one that looks healthiest.
        pub last_backup_secs: Option<i64>,
        /// It holds something a backup takes — a volume, a database, a SQLite file.
        /// `false`: no copy is owed, and `last_backup_secs` at `None` is not "never
        /// backed up" but "nothing to back up".
        pub holds_data: bool,
        /// Same for the last restore verification.
        pub last_verification_secs: Option<i64>,
        /// Blocking manual actions pending.
        pub blocking_guides: i64,
    }

    rules {
        attention: Attention = AppSummary::attention,
        backup_attention: Attention = AppSummary::backup_attention,
    }
}

/// How much attention an app deserves.
///
/// Computed here rather than in the UI: it is a business rule, and two clients
/// computing it separately would eventually diverge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Attention {
    /// Nothing to report.
    Ok,
    /// Worth a look when there is time.
    Notice,
    /// 🔴 Needs an action.
    Critical,
}

impl AppSummary {
    /// A backup older than 24 h is late (the target interval is 4 h).
    ///
    /// ⚠️ Was `RETARD_SECS` until 2026-08-28 — French, a private const inside an `impl`,
    /// and absent from `english_only.rs`'s word list, which is why four passes walked past
    /// it. Added to the list with this rename.
    const LATE_SECS: i64 = 86_400;

    /// How much attention the BACKUP alone deserves.
    ///
    /// 🔴 Split out of [`Self::attention`] so the rule is written once. The applications
    /// screen tints its backup figure by it, and a screen re-deriving "older than a day
    /// is late" would be a second copy of a business rule — which is the reason
    /// `attention` lives in this crate in the first place.
    pub fn backup_attention(&self) -> Attention {
        // 🔴 Valkey and LibreSpeed hold nothing: read as never backed up, they were
        // Critical on the dashboard forever, an alarm nobody could clear.
        if !self.holds_data {
            return Attention::Ok;
        }
        match self.last_backup_secs {
            // Never backed up is not "backed up a long time ago": it is the worst state
            // of the system, and the one that looks healthiest on a dashboard.
            None => Attention::Critical,
            Some(s) if s > Self::LATE_SECS => Attention::Critical,
            _ => Attention::Ok,
        }
    }

    pub fn attention(&self) -> Attention {
        // 🔴 The backup comes BEFORE the status: an app running perfectly with no backup
        // at all is the worst state of the system.
        if self.backup_attention() == Attention::Critical {
            return Attention::Critical;
        }
        if self.status == "failed" {
            return Attention::Critical;
        }
        if self.blocking_guides > 0 || self.status == "partial" {
            return Attention::Notice;
        }
        Attention::Ok
    }
}

/// A pending manual step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct GuideItem {
    pub app: String,
    pub id: String,
    pub title: String,
    /// Blocks the deployment until it is done.
    pub blocking: bool,
}

/// One page of the audit log, and what it is a page of.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AuditPage {
    pub entries: Vec<AuditItem>,
    /// Entries the search and the outcome keep — the pages are counted from it.
    pub matched: u64,
    /// Entries in the whole log.
    pub total: u64,
    /// Entries a page holds: sent, so the interface does not hold a second copy of it.
    pub page_size: u64,
}

/// An audit log entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AuditItem {
    pub id: i64,
    pub at: String,
    pub actor: String,
    /// The role **at the time of the action**, not today's. Someone demoted since
    /// does not erase what they did while they could.
    ///
    /// ⚠️ A string, not a [`hlb_types::Role`]: a role removed in a future version
    /// would make the whole log undeserialisable, and a log you can no longer read
    /// proves nothing.
    pub role: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
    /// The diff, or whatever explains the outcome. Without it, "config changed" does
    /// not say what changed.
    #[serde(default)]
    pub detail: Option<String>,
}

impl AuditItem {
    /// A refused action is not a failure: it is the system protecting the user.
    /// Confusing the two would make the log useless.
    pub fn is_refusal(&self) -> bool {
        self.outcome == "refused"
    }

    pub fn is_failure(&self) -> bool {
        self.outcome == "failed"
    }
}

/// A secret: its name and its purpose. **Never its value.**
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SecretItem {
    pub name: String,
    pub purpose: String,
}

/// Who the person (or machine) behind the current request is.
///
/// This is the **first** thing the interface asks for: it decides which screens to
/// show. A console greyed out entirely for want of knowing who is looking is worse
/// than a sign-in screen.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Me {
    /// The Homelabus account. `None` for a service token, which acts on nobody's
    /// behalf — and the interface must then hide everything that is "my …".
    pub account: Option<String>,
    pub role: String,
    /// What the role allows, in one sentence, ready to display as is.
    pub role_label: String,
    /// `true` = authenticated by API token rather than by session.
    ///
    /// The interface uses it to avoid offering "sign out" to a token holder: there is
    /// no session to close, and the button would do nothing.
    pub by_token: bool,
    pub can: Rights,
    #[serde(default)]
    pub mailboxes: Vec<MailboxBrief>,
}

/// The themes this installation offers.
///
/// 🔴 Declared ONCE, here, because three places need it and none of them may depend on
/// the others: the controller serves it, the CLI validates against it, and the
/// interface renders it. With a copy on each side, a theme removed in one would keep
/// being offered by another — and choosing it would silently give the default, which
/// reads as a bug rather than as a removal.
///
/// ⚠️ These are stored VALUES: `user_prefs.theme` holds one of these strings. Renaming
/// one orphans every person who chose it.
pub const THEMES: &[&str] = &["Dark", "Light", "High contrast"];

/// A theme an INSTALLATION declares, in a file, without touching Rust.
///
/// 🔴 [`THEMES`] above stays the list of SHIPPED themes and keeps its rule: three places
/// need it and none may depend on the others. Custom themes widen that set at run time —
/// the controller serves shipped ∪ custom, refuses a name in neither, and the interface
/// renders the union. They do not replace it: a file that disappears must not orphan
/// somebody's stored choice any more quietly than a removed shipped theme would.
///
/// ⚠️ Colours are hex strings, because a human writes this file. Twelve of them, one per
/// [`palette::Palette`] field, and none optional:
/// a theme missing its `critical` colour would fall back to a default nobody chose, and
/// the one place you must not guess is the colour that says something is wrong.
///
/// ⚠️ `deny_unknown_fields`: a typo'd key is rejected with its file named, never
/// silently ignored — the same rule every manifest in this project follows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CustomTheme {
    /// Shown in Settings, and stored in `user_prefs.theme` when someone picks it.
    pub name: String,
    /// `dark` or `light` — decides the direction of the surface gradient.
    pub base: String,
    pub background: String,
    pub surface: String,
    pub raised_surface: String,
    pub border: String,
    pub text: String,
    pub muted_text: String,
    pub accent: String,
    pub on_accent: String,
    pub ok: String,
    pub attention: String,
    pub critical: String,
    pub info: String,

    /// The proportional face this installation wants, as a file name beside the theme's
    /// own YAML — `Inter-Regular.ttf`. `None` keeps the project's `Noto Sans`.
    ///
    /// 🔴 Optional where the colours are not, and the difference is not laziness. A
    /// theme with no `critical` colour would be painted with a default nobody chose; a
    /// theme with no typeface is drawn in the one the project chose on purpose, which is
    /// a decision and not a gap.
    ///
    /// ⚠️ A file NAME, never a path or a URL: the controller serves it out of the themes
    /// directory, so `../` or an absolute path would be a way of reading the disk
    /// through the appearance API. [`Self::problems`] refuses anything with a separator
    /// in it, and any extension [`Self::face_mime`] does not know.
    #[serde(default)]
    pub typeface: Option<String>,
    /// The monospace face, same rules. `None` keeps `JetBrains Mono`.
    #[serde(default)]
    pub typeface_mono: Option<String>,
    /// How big the interface is, before the person's own text-size control multiplies
    /// it. `None` is `1.0`.
    ///
    /// ⚠️ Bounded to the same `0.8..=1.6` the Settings slider offers, and for a harder
    /// reason: the two MULTIPLY, and a theme that shipped `4.0` would leave an
    /// installation with an interface too large to reach the control that would undo it.
    #[serde(default)]
    pub scale: Option<f32>,
}

/// Which family a themed face leads.
///
/// Two variants and an exhaustive `match` rather than a string on the wire: the URL the
/// interface builds and the file the controller reads must name the same thing, and a
/// typo in either would be a 404 nobody sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FontFamilyKind {
    Proportional,
    Monospace,
}

impl FontFamilyKind {
    /// The path segment. Parsed back by [`Self::parse`], so there is one spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proportional => "proportional",
            Self::Monospace => "monospace",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "proportional" => Some(Self::Proportional),
            "monospace" => Some(Self::Monospace),
            _ => None,
        }
    }

    pub fn all() -> [Self; 2] {
        [Self::Proportional, Self::Monospace]
    }
}

/// The bounds a theme's [`CustomTheme::scale`] must sit in — the Settings slider's own.
pub const THEME_SCALE: std::ops::RangeInclusive<f32> = 0.8..=1.6;

impl CustomTheme {
    /// The face this theme names for `family`, if it names one.
    pub fn face(&self, family: FontFamilyKind) -> Option<&str> {
        match family {
            FontFamilyKind::Proportional => self.typeface.as_deref(),
            FontFamilyKind::Monospace => self.typeface_mono.as_deref(),
        }
    }

    /// Why a face file name cannot be served, or `None` if it can.
    ///
    /// 🔴 Public, and called TWICE on purpose: once by the loader, which refuses the
    /// theme, and once by the controller as it serves the bytes. The second call is not
    /// redundant — it is what stops a name that reached the state some other way from
    /// becoming a path traversal.
    pub fn face_problem(file: &str) -> Option<String> {
        if file.trim().is_empty() {
            return Some("the typeface is an empty name".into());
        }
        if file.contains('/') || file.contains('\\') || file.contains("..") {
            return Some(format!(
                "typeface \"{file}\" is a path — give the name of a file sitting beside \
                 the theme, nothing else"
            ));
        }
        if Self::face_mime(file).is_none() {
            return Some(format!(
                "typeface \"{file}\" is not .woff2, .woff, .ttf or .otf — a browser \
                 given anything else draws the fallback face, and says nothing"
            ));
        }
        None
    }

    /// The content type a face file is served with, from its extension; `None` for a
    /// file that is not a font this project serves.
    ///
    /// ⚠️ One table for both questions — "may this be a typeface?" and "what is it
    /// served as?" — so a format cannot be accepted by the loader and then sent as
    /// something the browser refuses.
    pub fn face_mime(file: &str) -> Option<&'static str> {
        let (_, ext) = file.rsplit_once('.')?;
        match ext.to_ascii_lowercase().as_str() {
            "woff2" => Some("font/woff2"),
            "woff" => Some("font/woff"),
            "ttf" => Some("font/ttf"),
            "otf" => Some("font/otf"),
            _ => None,
        }
    }

    /// The twelve colours, paired with the field each one is for.
    ///
    /// Returned as a slice rather than read field by field at each call site: a consumer
    /// that forgets one would silently paint it with a default, and there is no compiler
    /// error for a field nobody read.
    pub fn colours(&self) -> [(&'static str, &str); 12] {
        [
            ("background", &self.background),
            ("surface", &self.surface),
            ("raised_surface", &self.raised_surface),
            ("border", &self.border),
            ("text", &self.text),
            ("muted_text", &self.muted_text),
            ("accent", &self.accent),
            ("on_accent", &self.on_accent),
            ("ok", &self.ok),
            ("attention", &self.attention),
            ("critical", &self.critical),
            ("info", &self.info),
        ]
    }

    /// The twelve colours as a palette, or `None` while one of them does not parse —
    /// [`Self::problems`] names which.
    pub fn palette(&self) -> Option<palette::Palette> {
        let c = |hex: &str| Self::parse_rgb(hex);
        Some(palette::Palette {
            background: c(&self.background)?,
            surface: c(&self.surface)?,
            raised_surface: c(&self.raised_surface)?,
            border: c(&self.border)?,
            text: c(&self.text)?,
            muted_text: c(&self.muted_text)?,
            accent: c(&self.accent)?,
            on_accent: c(&self.on_accent)?,
            ok: c(&self.ok)?,
            attention: c(&self.attention)?,
            critical: c(&self.critical)?,
            info: c(&self.info)?,
        })
    }

    /// Is this name one of the shipped ones? Such a file would shadow a theme the
    /// interface guarantees, which is refused rather than resolved by precedence.
    pub fn shadows_a_shipped_theme(&self) -> bool {
        THEMES.iter().any(|t| t.eq_ignore_ascii_case(&self.name))
    }

    /// `#RRGGBB` to three bytes. `None` for anything else.
    ///
    /// One implementation for the loader and for [`Self::palette`], so a form one accepts
    /// can never be a form the other rejects.
    pub fn parse_rgb(hex: &str) -> Option<[u8; 3]> {
        let h = hex.strip_prefix('#')?;
        if h.len() != 6 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let byte = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).ok();
        Some([byte(0)?, byte(2)?, byte(4)?])
    }

    /// Everything wrong with this theme. Empty means it can be used.
    ///
    /// 🔴 Every problem, not the first one. A file rejected one mistake at a time makes
    /// you edit, reload, and be told about the next — and this file is edited by hand.
    ///
    /// 🔴 Well formed AND legible: once the twelve colours parse, the palette goes
    /// through [`palette::Palette::validate`]. An installation writing its own palette
    /// by hand is far likelier to merge two states than the shipped themes were, and
    /// they merged four times before the check existed.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.name.trim().is_empty() {
            out.push("the name is empty".into());
        }
        if self.shadows_a_shipped_theme() {
            out.push(format!(
                "\"{}\" is the name of a shipped theme — pick another, rather than \
                 shadowing one the interface guarantees",
                self.name
            ));
        }
        if palette::Base::parse(&self.base).is_none() {
            out.push(format!(
                "base is \"{}\", expected \"dark\" or \"light\"",
                self.base
            ));
        }
        for (field, value) in self.colours() {
            if Self::parse_rgb(value).is_none() {
                out.push(format!("{field}: \"{value}\" is not a #RRGGBB colour"));
            }
        }
        if let Some(p) = self.palette() {
            out.extend(p.validate().iter().map(palette::PaletteProblem::describe));
        }
        for family in FontFamilyKind::all() {
            if let Some(file) = self.face(family) {
                if let Some(problem) = Self::face_problem(file) {
                    out.push(format!("{}: {problem}", family.as_str()));
                }
            }
        }
        if let Some(scale) = self.scale {
            if !scale.is_finite() || !THEME_SCALE.contains(&scale) {
                out.push(format!(
                    "scale is {scale}, expected between {} and {} — the person's own \
                     text-size control multiplies this one, and a theme too large to \
                     read is also too large to change",
                    THEME_SCALE.start(),
                    THEME_SCALE.end()
                ));
            }
        }
        out
    }
}

/// A theme as the interface paints it: every one a person may pick, shipped or declared,
/// with the installation's brand accent already laid over.
///
/// 🔴 Resolved here, not in the browser. Laying an accent over a palette also picks the
/// text that sits ON it — whichever of two candidates contrasts more — and that choice
/// is the palette rule `with_accent` holds; a stylesheet re-deriving it would be a
/// second copy, and the first one already shipped a button at 2.98:1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Theme {
    /// Shown in Settings, and stored in `user_prefs.theme` when someone picks it.
    pub name: String,
    /// One of [`THEMES`], rather than declared by this installation in a file.
    pub shipped: bool,
    pub base: palette::Base,
    pub colours: Colours,
    /// `None` is `1.0`.
    #[serde(default)]
    pub scale: Option<f32>,
    /// Where to fetch the proportional face, when the theme names one.
    #[serde(default)]
    pub typeface_url: Option<String>,
    #[serde(default)]
    pub typeface_mono_url: Option<String>,
}

/// A palette's twelve colours, as `#RRGGBB`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Colours {
    pub background: String,
    pub surface: String,
    pub raised_surface: String,
    pub border: String,
    pub text: String,
    pub muted_text: String,
    pub accent: String,
    pub on_accent: String,
    pub ok: String,
    pub attention: String,
    pub critical: String,
    pub info: String,
}

impl From<palette::Palette> for Colours {
    fn from(p: palette::Palette) -> Self {
        // Destructured whole, so a role added to the palette does not compile until it
        // reaches the wire.
        let palette::Palette {
            background,
            surface,
            raised_surface,
            border,
            text,
            muted_text,
            accent,
            on_accent,
            ok,
            attention,
            critical,
            info,
        } = p;
        let h = palette::hex;
        Self {
            background: h(background),
            surface: h(surface),
            raised_surface: h(raised_surface),
            border: h(border),
            text: h(text),
            muted_text: h(muted_text),
            accent: h(accent),
            on_accent: h(on_accent),
            ok: h(ok),
            attention: h(attention),
            critical: h(critical),
            info: h(info),
        }
    }
}

impl Theme {
    /// A shipped theme, under the brand's accent if there is one.
    pub fn shipped(name: &str, accent: Option<palette::Rgb>) -> Option<Self> {
        let (base, p) = palette::Palette::shipped_with_base(name)?;
        Some(Self {
            name: name.to_string(),
            shipped: true,
            base,
            colours: accent.map_or(p, |a| p.with_accent(a)).into(),
            scale: None,
            typeface_url: None,
            typeface_mono_url: None,
        })
    }

    /// A declared theme, under the brand's accent. `None` for one whose colours or base
    /// do not parse — which the loader refuses before it is ever served.
    pub fn declared(t: &CustomTheme, accent: Option<palette::Rgb>) -> Option<Self> {
        let p = t.palette()?;
        let url = |family: FontFamilyKind| {
            t.face(family).map(|_| {
                format!(
                    "/api/themes/{}/font/{}",
                    path_segment(&t.name),
                    family.as_str()
                )
            })
        };
        Some(Self {
            name: t.name.clone(),
            shipped: false,
            base: palette::Base::parse(&t.base)?,
            colours: accent.map_or(p, |a| p.with_accent(a)).into(),
            scale: t.scale,
            typeface_url: url(FontFamilyKind::Proportional),
            typeface_mono_url: url(FontFamilyKind::Monospace),
        })
    }
}

/// `s`, percent-encoded to sit in one segment of a URL path: a theme's name has spaces.
fn path_segment(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// One of the person's addresses, just enough to display it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MailboxBrief {
    pub address: String,
    pub default: bool,
}

/// One of a person's devices: the password it signs in to their mailbox with — mail,
/// calendars and contacts.
///
/// Read from Stalwart, never copied here: a copy would list a device revoked in
/// Stalwart's own screens as still open.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Device {
    /// Stalwart's id, unique within its mailbox.
    pub id: String,
    /// What the person called it.
    pub name: String,
    /// The mailbox it signs in to, which is also its user name.
    pub mailbox: String,
    /// RFC 3339, UTC.
    pub created_at: Option<String>,
}

/// What a device is set up with: the one moment its password is known.
///
/// 🔴 Never stored, never logged: Stalwart answers the password once, and nothing
/// reads it back.
#[derive(Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct DeviceSetup {
    /// The user name: the mailbox's address.
    pub user: String,
    pub password: String,
    /// Stalwart's public name, where a phone finds CalDAV and CardDAV
    /// (`/.well-known/caldav`), JMAP and IMAP.
    pub server: String,
}

// By hand: a derived `Debug` would print the password into whatever logs an answer.
impl std::fmt::Debug for DeviceSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceSetup")
            .field("user", &self.user)
            .field("password", &"…")
            .field("server", &self.server)
            .finish()
    }
}

/// The signed-in person as PocketID knows them: the part of an account they edit
/// themselves.
///
/// Read from PocketID on every request and never copied here — a copy would be a second
/// name, stale the day someone renames themselves in PocketID's own screens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MyIdentity {
    pub link: IdentityLink,
    /// `None` unless `link` is [`IdentityLink::Linked`].
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    /// The address PocketID gives applications. It follows the default mailbox.
    pub email: Option<String>,
    /// PocketID's own account page, where passkeys are added and removed — they are
    /// PocketID's alone, and Homelabus cannot even count them. `None` when sign-in
    /// through PocketID is not configured.
    pub passkeys_url: Option<String>,
}

/// Why a person's identity can or cannot be read — a VALUE the interface words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityLink {
    Linked,
    /// The controller was started without a PocketID API key.
    NotConfigured,
    /// The account has no PocketID identity yet: half-created, or never signed in.
    NotLinked,
    /// PocketID did not answer, or not in a way that could be read.
    Unreachable,
}

/// One of the signed-in person's own browser sessions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct MySession {
    /// Names the session without naming its secret: what closing it is asked with.
    pub reference: String,
    /// As the browser described itself at sign-in. `None` when it said nothing.
    pub user_agent: Option<String>,
    /// Seconds since it was last used, at the time of the answer.
    pub seen_s: i64,
    /// Seconds before it expires unless used again.
    pub expires_in_s: i64,
    /// The session this very request came with: closing it is signing out.
    pub current: bool,
}

judged! {
    /// What the current role is allowed to do.
    ///
    /// 🔴 Computed **server side** and transmitted, rather than re-derived from the role
    /// name by the interface. Two implementations of the same matrix would eventually
    /// diverge, and the divergence would go the permissive way: a visible button that
    /// triggers a 403 is a bug; a visible button that *works* when it should not is a
    /// vulnerability.
    ///
    /// ⚠️ This is **not** access control: that happens on every request, in the
    /// controller. It is only enough not to display what will be refused.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Rights {
        pub read_self: bool,
        pub act_on_self: bool,
        pub read: bool,
        pub publish: bool,
        pub operate: bool,
        pub manage_accounts: bool,
        pub destroy: bool,
    }

    rules {
        sees_the_console: bool = Rights::sees_the_console,
    }
}

impl Rights {
    /// The rights of a role.
    ///
    /// The `match` on each action goes through `Role::allows`, so the matrix stays
    /// defined in a single place (`hlb_types::rbac`).
    pub fn for_role(role: hlb_types::Role) -> Self {
        use hlb_types::rbac::Action;
        Self {
            read_self: role.allows(Action::ReadSelf),
            act_on_self: role.allows(Action::ActOnSelf),
            read: role.allows(Action::Read),
            publish: role.allows(Action::Publish),
            operate: role.allows(Action::Operate),
            manage_accounts: role.allows(Action::ManageAccounts),
            destroy: role.allows(Action::Destroy),
        }
    }

    /// Is there anything at all to show from the administration console?
    ///
    /// Used to choose between the portal and the console on opening, rather than
    /// imposing an empty screen on someone who only has an account.
    pub fn sees_the_console(&self) -> bool {
        self.read
    }
}

/// The installation's visual identity.
///
/// ## Why it comes from the server
///
/// It could be compiled into the interface. But changing it would then mean rebuilding
/// and redeploying it, which puts the brand name on the same footing as an architecture
/// decision. So it lives in the database, is edited from the interface, and the build
/// stays the same whichever house uses it.
///
/// 🔴 The accent is **validated** before being accepted: [`Brand::accent_problems`]
/// refuses a colour that would be confused with "ok", "attention" or "critical" under
/// any of three colour-vision deficiencies, on any theme it can land on. A brand is not
/// allowed to make alerts indistinguishable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Brand {
    /// The house. Appears at the top of the sidebar and in the page footer.
    pub name: String,
    /// The product. Distinct from the house: "Turi Industries" runs "Homelabus", and
    /// confusing the two would make the page unreadable to a visitor.
    pub product: String,
    /// RGB components. `None` = the theme's accent.
    #[serde(default)]
    pub accent: Option<[u8; 3]>,
    /// Has a logo been uploaded? The bytes are fetched from `/api/appearance/logo`.
    ///
    /// ⚠️ A boolean and not the bytes: a 256 KB image base64-encoded into every API
    /// response would be paid for on every poll, by every screen.
    #[serde(default)]
    pub logo: bool,
    /// A footer line: legal notice, support contact, on-call number.
    #[serde(default)]
    pub footer: Option<String>,
    /// The theme offered by default to people who have not chosen one.
    #[serde(default)]
    pub default_theme: Option<String>,
}

impl Default for Brand {
    fn default() -> Self {
        Self {
            name: "Turi Industries".into(),
            product: "Homelabus".into(),
            accent: None,
            logo: false,
            footer: None,
            default_theme: None,
        }
    }
}

impl Brand {
    /// Why this brand's accent cannot be laid over these themes; empty when it can, or
    /// when there is no accent.
    ///
    /// ⚠️ Every theme the accent can land on, not the default one: the brand colours the
    /// interface for everybody, whatever theme each person picked — so the caller passes
    /// the shipped palettes AND the installation's declared ones.
    pub fn accent_problems<'a>(
        &self,
        themes: impl IntoIterator<Item = (&'a str, palette::Palette)>,
    ) -> Vec<String> {
        let Some(accent) = self.accent else {
            return Vec::new();
        };
        themes
            .into_iter()
            .flat_map(|(name, p)| {
                p.accent_problems(accent)
                    .into_iter()
                    .map(move |pb| format!("on \"{name}\": {}", pb.describe()))
            })
            .collect()
    }

    /// The window title and the browser tab title.
    pub fn title(&self) -> String {
        format!("{} · {}", self.product, self.name)
    }

    /// The initials, for the painted monogram when no logo has been set.
    pub fn initials(&self) -> String {
        let i: String = self
            .name
            .split([' ', '-', '_'])
            .filter(|m| !m.is_empty())
            .take(2)
            .filter_map(|m| m.chars().next())
            .collect::<String>()
            .to_uppercase();
        if i.is_empty() {
            "?".into()
        } else {
            i
        }
    }
}

judged! {
    /// The detail of an application — the screen you spend the most time on.
    #[derive(Debug, Clone, PartialEq)]
    pub struct AppDetail {
        pub summary: AppSummary,
        /// The replicas and where they actually run.
        #[serde(default)]
        pub tasks: Vec<TaskSummary>,
        /// What was provisioned for it.
        #[serde(default)]
        pub capabilities: Vec<Need>,
        /// The volumes, and which are backed up.
        #[serde(default)]
        pub volumes: Vec<VolumeSummary>,
        /// The manifest's environment variables.
        ///
        /// 🔴 Secret tokens are rendered **literally** (`{{ db.password }}`), never
        /// substituted. Two reasons: the value must not cross the API, and a visible token
        /// says what the app is wired to — which a value masked with asterisks does not.
        #[serde(default)]
        pub env: Vec<(String, String)>,
        /// The manual actions concerning it.
        #[serde(default)]
        pub guides: Vec<GuideItem>,
        /// Its backup coverage.
        #[serde(default)]
        pub coverage: Option<CoverageSummary>,
        /// Its latest backups, failures included.
        #[serde(default)]
        pub backups: Vec<BackupRun>,
        /// 🔴 The answer to "if I lose everything now, what do I get back?".
        #[serde(default)]
        pub restorability: Option<RestorabilitySummary>,
        /// 🔴 "Why is this app red?", traced link by link.
        ///
        /// Computed by the server: only it sees tasks, nodes and alerts at once. The
        /// interface shows them on three different screens and cannot connect them.
        #[serde(default)]
        pub diagnostic: Option<diagnostic::Chain>,
        /// The audit log filtered on it.
        #[serde(default)]
        pub journal: Vec<AuditItem>,
        /// The image actually deployed.
        #[serde(default)]
        pub image: Option<String>,
        #[serde(default)]
        pub domain: Option<String>,
        /// The manifest frozen at deploy time, rendered as YAML.
        ///
        /// ⚠️ The installation's, NOT the current catalog's: what you want to read is what
        /// is running, not what you would install today.
        #[serde(default)]
        pub manifest: Option<String>,
        /// What the catalog has changed since, field by field — empty when it matches,
        /// or when no catalog is loaded. `POST /api/apps/{name}/upgrade` applies it; the
        /// images are not in it, `hlb update` moves those.
        #[serde(default)]
        pub catalog_changes: Vec<String>,
        /// What its manifest says must stay true, as last read from the running app —
        /// one never read, or not lately, is `unknown`.
        #[serde(default)]
        pub assertions: Vec<assertions::AssertionResult>,
        /// Its manifest's scheduled jobs, each with its last run.
        #[serde(default)]
        pub jobs: Vec<jobs::JobState>,
    }

    rules {
        replicas: Replicas = |d: &AppDetail| {
            let (live, wanted) = d.replicas();
            Replicas { live, wanted }
        },
    }
}

// ⚠️ No `deny_unknown_fields`, unlike a manifest: the wire carries `attention` beside
// these fields, and a client reading it back must not refuse its own server's answer.
judged! {
    /// "If I lose everything now, what do I get back, and from when?"
    ///
    /// ## Why this type lives on the server
    ///
    /// The five pieces of the answer — age per destination, up-to-date copies, age of the
    /// last verification, drill freshness, PITR window — are scattered across four
    /// screens. Nobody adds them up in their head, and it is the only question that
    /// matters on the day.
    ///
    /// 🔴 The computation is a **business rule**: it lives in `hlb-backup`, not in the
    /// interface. Two clients redoing it separately would end up showing two different
    /// verdicts on the same backup.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RestorabilitySummary {
        pub app: String,
        /// Seconds of data that would be lost. `None` = **nothing to restore**.
        ///
        /// ⚠️ Distinct from a very large RPO: `None` means no copy exists at all.
        #[serde(default)]
        pub rpo_s: Option<i64>,
        /// The answer in one sentence, computed by the server.
        pub verdict: String,
        /// What is known about this backup, from weakest to strongest.
        pub confidence: ConfidenceLevel,
        /// What that confidence means, spelled out.
        pub confidence_explanation: String,
        /// What should be done, in order of urgency. Empty when all is well.
        #[serde(default)]
        pub remedies: Vec<String>,
    }

    rules {
        attention: Attention = RestorabilitySummary::attention,
    }
}

/// How much credit a restore deserves.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    /// 🔴 Nothing to restore.
    Nothing,
    /// Copies exist, none has ever been read back.
    Assumed,
    /// A restore succeeded, but long ago — or there is only one copy.
    Previous,
    /// Verified recently, on several copies.
    Verified,
}

impl RestorabilitySummary {
    pub fn attention(&self) -> Attention {
        match self.confidence {
            ConfidenceLevel::Nothing => Attention::Critical,
            // ⚠️ "Assumed" is NOT "good". A backup never read back and shown green is
            // exactly the lie the verification exists to prevent.
            ConfidenceLevel::Assumed | ConfidenceLevel::Previous => Attention::Notice,
            ConfidenceLevel::Verified => Attention::Ok,
        }
    }
}

/// One of an application's volumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct VolumeSummary {
    pub name: String,
    pub path: String,
    pub backup: bool,
    /// 🔴 Holds a SQLite database: it must NEVER be copied hot. The main file and its
    /// WAL would be captured at different instants, and the restored database would be
    /// corrupt — with nothing signalling it at backup time.
    pub sqlite: bool,
}

/// Live replicas over the wanted total: see [`AppDetail::replicas`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Replicas {
    pub live: usize,
    pub wanted: usize,
}

impl AppDetail {
    /// Live replicas over the wanted total.
    pub fn replicas(&self) -> (usize, usize) {
        let live = self.tasks.iter().filter(|t| t.alive).count();
        // The wanted total is derived from non-shutdown tasks: Swarm keeps the
        // history, and counting EVERY task would give a denominator that grows on
        // each redeploy.
        let wanted = self
            .tasks
            .iter()
            .filter(|t| t.desired_state == "running")
            .count();
        (live, wanted.max(live))
    }

    /// The tasks that failed, most recent first.
    ///
    /// 🔴 This is what answers "why is this app red". Hiding them would leave a
    /// "partial" service with no explanation at all.
    pub fn failures(&self) -> Vec<&TaskSummary> {
        self.tasks.iter().filter(|t| t.failed).collect()
    }
}

judged! {
    /// A cluster node, as the dashboard shows it.
    #[derive(Debug, Clone, PartialEq)]
    pub struct NodeSummary {
        /// The agent's address: **the stable identity**.
        ///
        /// 🔴 Not the hostname: an unreachable node has none to give. Changing identifier
        /// depending on whether it answers would produce two entries for one machine, and
        /// "this node is silent" would never be visible.
        pub address: String,
        /// `None` when the node has never answered.
        #[serde(default)]
        pub hostname: Option<String>,
        /// 🔴 `false` = unreachable. That is **not** "no problem reported": its data is
        /// no longer being backed up, and nothing is known about its disk.
        pub reachable: bool,
        /// Why it does not answer.
        #[serde(default)]
        pub detail: Option<String>,
        /// Age of the last report, in seconds. `None` = never received.
        #[serde(default)]
        pub report_age_s: Option<i64>,
        #[serde(default)]
        pub cpu_busy: Option<f64>,
        #[serde(default)]
        pub load_per_core: Option<f64>,
        #[serde(default)]
        pub memory_used: Option<f64>,
        #[serde(default)]
        pub swap_used: Option<f64>,
        #[serde(default)]
        pub disks: Vec<DiskSummary>,
        #[serde(default)]
        pub uptime_s: Option<u64>,
        #[serde(default)]
        pub distro: Option<String>,
        #[serde(default)]
        pub kernel: Option<String>,
        #[serde(default)]
        pub agent_version: Option<String>,
        /// Protocol version. A mismatched fleet is a trap.
        #[serde(default)]
        pub protocol: Option<u32>,
        /// The hosted tasks, by service name.
        #[serde(default)]
        pub tasks: Vec<String>,
        /// Waiting for a reboot to run its newest kernel — `hlb node upgrade` does it,
        /// drained. `None`: the agent does not say.
        #[serde(default)]
        pub reboot_pending: Option<bool>,
    }

    rules {
        attention: Attention = NodeSummary::attention,
        problem: Option<NodeProblem> = NodeSummary::problem,
    }
}

/// A filesystem on a node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct DiskSummary {
    pub path: String,
    pub used: f64,
    pub total_mb: u64,
    pub free_mb: u64,
    /// Disk pressure step: 0 healthy … 4 critical.
    pub pressure: u8,
}

/// The worst thing wrong with a node: see [`NodeSummary::problem`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NodeProblem {
    /// 🔴 Its data is no longer backed up, and nothing is known about its disk. The
    /// node's `detail` says why, when it is known.
    Unreachable,
    /// No deployment is accepted there any more. `used` is a fraction.
    DiskFull { path: String, used: f64 },
    /// Filling up. `used` is a fraction.
    DiskFilling { path: String, used: f64 },
    /// Swapping to disk: the machine slows before it falls over.
    Swapping,
    /// Load above one per core.
    Load { per_core: f64 },
    /// A newer kernel is installed than the one running: security fixes wait for a
    /// reboot. The least of the problems — nothing is wrong yet.
    RebootPending,
}

impl NodeSummary {
    /// How much attention this node deserves.
    pub fn attention(&self) -> Attention {
        // 🔴 Unreachable comes BEFORE everything else: we know nothing about it, which
        // is worse than a bad number we know.
        if !self.reachable {
            return Attention::Critical;
        }
        if self.disks.iter().any(|d| d.pressure >= 3) {
            return Attention::Critical;
        }
        if self.disks.iter().any(|d| d.pressure >= 1)
            || self.swap_used.is_some_and(|s| s > 0.05)
            || self.load_per_core.is_some_and(|c| c > 1.0)
            || self.reboot_pending == Some(true)
        {
            return Attention::Notice;
        }
        Attention::Ok
    }

    /// What is wrong — the worst thing, or nothing. The interface has the sentence.
    pub fn problem(&self) -> Option<NodeProblem> {
        if !self.reachable {
            return Some(NodeProblem::Unreachable);
        }
        if let Some(d) = self.disks.iter().max_by_key(|d| d.pressure) {
            if d.pressure >= 3 {
                return Some(NodeProblem::DiskFull {
                    path: d.path.clone(),
                    used: d.used,
                });
            }
            if d.pressure >= 1 {
                return Some(NodeProblem::DiskFilling {
                    path: d.path.clone(),
                    used: d.used,
                });
            }
        }
        if self.swap_used.is_some_and(|s| s > 0.05) {
            return Some(NodeProblem::Swapping);
        }
        if let Some(c) = self.load_per_core.filter(|c| *c > 1.0) {
            return Some(NodeProblem::Load { per_core: c });
        }
        if self.reboot_pending == Some(true) {
            return Some(NodeProblem::RebootPending);
        }
        None
    }
}

/// A node's detail — the screen you open by clicking a card. Wraps [`NodeSummary`]
/// exactly like [`AppDetail`] wraps [`AppSummary`]: the summary carries everything
/// the compact card and the Overview tab need, and this type adds only what is
/// genuinely detail-only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct NodeDetail {
    pub summary: NodeSummary,
    /// Full per-task detail (image, state, replica slot) — unlike
    /// `NodeSummary::tasks`, which is only service names.
    #[serde(default)]
    pub tasks: Vec<TaskSummary>,
    /// Collected by the agent (`NodeReport.interfaces`) since the first release, but
    /// never surfaced anywhere until this type: `NodeSummary` never carried them.
    #[serde(default)]
    pub interfaces: Vec<InterfaceSummary>,
    /// What Swarm knows about the same machine, when the two can be matched.
    ///
    /// 🔴 `None` is the normal case for a node the orchestrator does not know, and the
    /// interface must offer NO availability action then: `POST
    /// /api/nodes/{id}/availability` is addressed by Swarm's own identifier, and the
    /// agent address this detail is keyed by (`10.0.0.1:8421`) is not one.
    #[serde(default)]
    pub swarm: Option<SwarmNode>,
}

/// The Swarm side of a node: what it takes to act on it, and what state it is in.
///
/// ⚠️ Deliberately thin. Everything a screen displays about a machine comes from the
/// agent's own report ([`NodeSummary`]); this exists so the interface can address the
/// availability endpoint and say which of the three states the node is already in —
/// without which "drain" is a button that cannot know whether it has anything to do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SwarmNode {
    /// Swarm's own node identifier, which is what the endpoint's `{id}` means.
    pub id: String,
    /// `active`, `pause`, `drain` — or `unknown` when Swarm did not say.
    pub availability: String,
}

impl SwarmNode {
    /// Is this node taking work?
    pub fn active(&self) -> bool {
        self.availability == "active"
    }

    /// Is it being emptied?
    pub fn draining(&self) -> bool {
        self.availability == "drain"
    }
}

/// A network interface, as the agent reports it.
///
/// ⚠️ Mirrors `hlb_agent::system::Interface` exactly: `name`/`rx_bytes`/`tx_bytes`,
/// nothing more. The agent does not collect an address or an up/down state — adding
/// those fields here would mean fabricating them server-side, which is worse than not
/// showing them at all.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct InterfaceSummary {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// A person's display preferences.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Preferences {
    /// The chosen theme. `None` = the installation's.
    ///
    /// ⚠️ A NAME, not a palette: a palette stored per person would survive the removal
    /// of the theme it came from, and could no longer be evolved.
    #[serde(default)]
    pub theme: Option<String>,
    /// The available themes, as the interface knows them.
    ///
    /// 🔴 Served by the API so the settings screen does not have to guess: with one
    /// list on each side, a removed theme would keep being offered until the next
    /// interface deploy.
    #[serde(default)]
    pub available: Vec<String>,
    /// The installation's own, when the person has chosen nothing.
    #[serde(default)]
    pub default: Option<String>,
    /// The tiles the person laid out on the home, in order. `None` = never arranged,
    /// and [`HomeTile::DEFAULT`] applies — kept distinct from an empty list, which is a
    /// person who removed everything on purpose.
    #[serde(default)]
    pub home: Option<Vec<HomeTile>>,
    /// What the home shows to someone who never arranged it.
    #[serde(default)]
    pub home_default: Vec<HomeTile>,
    /// Every card there is, at the size it is added at.
    #[serde(default)]
    pub home_offered: Vec<HomeTile>,
    /// How tightly lists are set.
    #[serde(default)]
    pub density: Density,
}

/// How tightly a person's lists are set: the same rows, more of them on a screen.
///
/// ⚠️ A stored VALUE, in `user_prefs.density`; `NULL` there is [`Density::Comfortable`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Density {
    #[default]
    Comfortable,
    /// For whoever reads the console all day: a row of 32 px rather than 40.
    Compact,
}

impl Density {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Comfortable => "comfortable",
            Self::Compact => "compact",
        }
    }
}

/// A card the home can show, each fed by one endpoint.
///
/// 🔴 Declared here, not in the interface, for the reason [`THEMES`] is: the controller
/// must refuse a name it does not know rather than store it, and the interface maps
/// every variant to a component with an exhaustive `Record` — a variant added on one side
/// only does not compile on the other.
///
/// ⚠️ Stored VALUES, in `user_prefs.home`. A removed variant is dropped from a stored
/// layout when read, so it costs one card and not the person's whole arrangement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HomeWidget {
    /// Every line of the inbox, the worst first, with "later" and the lines set aside.
    /// 🔴 The ONE card about problems: the others say what the installation is, and a
    /// home where each card restated the inbox put `garage` on it three times.
    Problems,
    /// The installation in a line of figures: machines, applications, processor,
    /// memory, storage, what is public.
    Summary,
    /// Every application, running or not, with where it is reached.
    Apps,
    /// Each machine's processor and its load.
    Cpu,
    /// Each machine's memory and swap.
    Memory,
    /// Every disk of every machine: how full, how much is left.
    Disks,
    /// What each machine receives and sends.
    Network,
    /// The machines: system, kernel, how long they have been up, what they host.
    Nodes,
    /// What the loss of one machine, or one failure domain, would take down.
    Resilience,
    /// The latest backups: what, when, where, and whether it worked.
    Backups,
    /// The addresses reachable from the internet.
    Exposure,
    /// The latest events.
    Activity,
    /// Swarm's services, and their replicas running.
    Tasks,
    /// The announcements in force.
    Announcements,
    /// The services' availability over the last days.
    Uptime,
    /// The people: accounts, mailboxes, aliases, sessions.
    Accounts,
}

/// The widest a tile may be, in columns of the home's grid: as many as a wide screen has.
pub const TILE_W_MAX: u8 = 4;
/// The tallest a tile may be, in rows: past three, the home stops fitting one screen.
pub const TILE_H_MAX: u8 = 3;

/// A card on the home and the room it takes: `w` columns and `h` rows of its grid.
///
/// The size is what a person asked for, not where the tile lands: the interface packs
/// the tiles in order and grows some to close the gaps, so the grid is always full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HomeTile {
    pub widget: HomeWidget,
    /// Columns, from 1 to [`TILE_W_MAX`].
    pub w: u8,
    /// Rows, from 1 to [`TILE_H_MAX`].
    pub h: u8,
}

impl HomeTile {
    /// The home of someone who never arranged it: the installation at a glance — its
    /// figures, its applications, its processors, memory and disks — and every problem
    /// in one tile beside them. Exactly the four by three of a wide screen, so nothing
    /// grows to fill it.
    pub const DEFAULT: &[HomeTile] = &[
        HomeTile {
            widget: HomeWidget::Summary,
            w: 4,
            h: 1,
        },
        HomeTile {
            widget: HomeWidget::Problems,
            w: 2,
            h: 2,
        },
        HomeTile {
            widget: HomeWidget::Apps,
            w: 1,
            h: 1,
        },
        HomeTile {
            widget: HomeWidget::Cpu,
            w: 1,
            h: 1,
        },
        HomeTile {
            widget: HomeWidget::Memory,
            w: 1,
            h: 1,
        },
        HomeTile {
            widget: HomeWidget::Disks,
            w: 1,
            h: 1,
        },
    ];

    /// Within the grid's bounds: at least one cell, and no more than it has.
    pub fn fits(&self) -> bool {
        (1..=TILE_W_MAX).contains(&self.w) && (1..=TILE_H_MAX).contains(&self.h)
    }
}

impl HomeWidget {
    /// Every card, in the order the interface offers them.
    pub const ALL: [HomeWidget; 16] = [
        Self::Problems,
        Self::Summary,
        Self::Apps,
        Self::Cpu,
        Self::Memory,
        Self::Disks,
        Self::Network,
        Self::Nodes,
        Self::Uptime,
        Self::Backups,
        Self::Exposure,
        Self::Tasks,
        Self::Activity,
        Self::Announcements,
        Self::Resilience,
        Self::Accounts,
    ];

    /// The room a card takes when it is added, or read from a layout stored before
    /// tiles had a size: a figure fits one cell, a list wants more.
    pub fn tile(self) -> HomeTile {
        let (w, h) = match self {
            Self::Summary => (4, 1),
            Self::Problems => (2, 2),
            Self::Apps => (1, 2),
            Self::Disks
            | Self::Network
            | Self::Nodes
            | Self::Uptime
            | Self::Backups
            | Self::Activity
            | Self::Tasks
            | Self::Announcements => (2, 1),
            Self::Cpu | Self::Memory | Self::Exposure | Self::Resilience | Self::Accounts => (1, 1),
        };
        HomeTile { widget: self, w, h }
    }
}

judged! {
    /// The status page: what works, what does not.
    ///
    /// ## 🔴 Private by default, and that is a decision
    ///
    /// A public status page reveals **the list of what runs at your place** and the
    /// calendar of your outages. For a commercial service that is a transparency
    /// commitment; for a homelab it is reconnaissance handed to whoever reads it.
    ///
    /// Opening it is an explicit choice (`status.public = true`), and the settings screen
    /// says what that publishes — not an innocuous checkbox.
    #[derive(Debug, Clone, PartialEq)]
    pub struct StatusPage {
        /// The state of each exposed application.
        pub services: Vec<ServiceStatus>,
        /// Incident- and maintenance-level announcements, open AND past.
        ///
        /// `Announcement` already IS the incident history — never deleted, `expires_at`
        /// marks it closed. Historical / realtime / scheduled is derived by the READER
        /// from `level` and `active()`, not a separate field: `Incident` + `!active()` →
        /// historical, `Incident` + `active()` → realtime, `Maintenance` → scheduled. No
        /// new storage, no new type.
        #[serde(default)]
        pub incidents: Vec<Announcement>,
        /// Is this page reachable without authentication?
        pub public: bool,
    }

    rules {
        verdict: StatusVerdict = StatusPage::verdict,
        attention: Attention = StatusPage::attention,
    }
}

judged! {
    #[derive(Debug, Clone, PartialEq)]
    pub struct ServiceStatus {
        pub name: String,
        #[serde(default)]
        pub domain: Option<String>,
        pub state: ServiceState,
        /// One entry per day of the retained window, oldest first.
        #[serde(default)]
        pub uptime: Vec<UptimeSample>,
    }

    rules {
        attention: Attention = |s: &ServiceStatus| s.state.attention(),
    }
}

judged! {
    /// One day's WORST recorded state for a service — `state: None` means no sample was
    /// ever taken that day, distinct from `Operational`: "an empty series is not a zero
    /// series."
    #[derive(Debug, Clone, PartialEq)]
    pub struct UptimeSample {
        /// `YYYY-MM-DD`.
        pub day: String,
        #[serde(default)]
        pub state: Option<ServiceState>,
    }

    rules {
        attention: Option<Attention> = |u: &UptimeSample| u.state.map(|s| s.attention()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceState {
    /// All is well.
    Operational,
    /// Partially deployed: it works, but with no margin.
    Degraded,
    /// En outage.
    Unavailable,
    /// 🔴 An ANNOUNCED maintenance. Distinct from an outage: it was planned, and
    /// saying so stops people looking for what is wrong.
    Maintenance,
}

impl ServiceState {
    /// What an app's recorded status shows on the status page.
    ///
    /// One definition for the live page and the daemon's uptime sampling: two would let
    /// the history disagree with what the page showed that day.
    pub fn of(status: &str, announced: bool) -> Self {
        match status {
            _ if announced => Self::Maintenance,
            "running" => Self::Operational,
            "partial" => Self::Degraded,
            _ => Self::Unavailable,
        }
    }

    pub fn attention(&self) -> Attention {
        match self {
            Self::Operational => Attention::Ok,
            Self::Degraded | Self::Maintenance => Attention::Notice,
            Self::Unavailable => Attention::Critical,
        }
    }
}

/// The one line at the top of the status page. The worst thing decides, in this order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StatusVerdict {
    /// This many services are down.
    Down {
        services: usize,
    },
    /// Nothing is down, but this many incidents are open.
    Incidents {
        open: usize,
    },
    /// This many services are degraded.
    Degraded {
        services: usize,
    },
    /// No service is exposed, so none can be said to work: "all operational" would hold
    /// by vacuity over an empty list, read as a reassurance about nothing.
    NothingExposed,
    AllOperational,
}

impl StatusPage {
    /// The overall verdict — the decision; the interface has the sentence.
    pub fn verdict(&self) -> StatusVerdict {
        let down = self
            .services
            .iter()
            .filter(|s| s.state == ServiceState::Unavailable)
            .count();
        let degraded = self
            .services
            .iter()
            .filter(|s| s.state == ServiceState::Degraded)
            .count();

        if down > 0 {
            StatusVerdict::Down { services: down }
        } else if !self.incidents.is_empty() {
            StatusVerdict::Incidents {
                open: self.incidents.len(),
            }
        } else if self.services.is_empty() {
            StatusVerdict::NothingExposed
        } else if degraded > 0 {
            StatusVerdict::Degraded { services: degraded }
        } else {
            StatusVerdict::AllOperational
        }
    }

    pub fn attention(&self) -> Attention {
        self.services
            .iter()
            .map(|s| s.state.attention())
            .chain(self.incidents.iter().map(|i| i.level.attention()))
            .max()
            .unwrap_or(Attention::Ok)
    }
}

judged! {
    /// An announcement, as the portal shows it.
    #[derive(Debug, Clone, PartialEq)]
    pub struct Announcement {
        pub id: i64,
        pub title: String,
        pub body: String,
        pub level: AnnouncementLevel,
        pub pinned: bool,
        pub author: String,
        pub published_at: String,
        /// Seconds before it disappears. `None` = permanent.
        #[serde(default)]
        pub expires_in_s: Option<i64>,
        /// The update thread, oldest first.
        ///
        /// 🔴 An incident is FOLLOWED, not rewritten: the chronology is what you re-read
        /// afterwards — when you knew, when you understood, when it was fixed.
        #[serde(default)]
        pub follow_ups: Vec<AnnouncementUpdate>,
    }

    rules {
        attention: Attention = |a: &Announcement| a.level.attention(),
        active: bool = Announcement::active,
        open_incident: bool = Announcement::open_incident,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AnnouncementUpdate {
    pub body: String,
    pub author: String,
    pub at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AnnouncementLevel {
    Info,
    /// Planned, therefore announced ahead of time.
    Maintenance,
    Warning,
    /// Ongoing, and followed.
    Incident,
}

impl AnnouncementLevel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Info => "information",
            Self::Maintenance => "maintenance",
            Self::Warning => "warning",
            Self::Incident => "incident",
        }
    }

    pub fn attention(&self) -> Attention {
        match self {
            Self::Info => Attention::Ok,
            Self::Maintenance | Self::Warning => Attention::Notice,
            Self::Incident => Attention::Critical,
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "maintenance" => Self::Maintenance,
            "warning" => Self::Warning,
            "incident" => Self::Incident,
            // ⚠️ The default is the LOWEST level: an unreadable level in the database
            // must not turn an information into an incident on every screen.
            _ => Self::Info,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Maintenance => "maintenance",
            Self::Warning => "warning",
            Self::Incident => "incident",
        }
    }
}

impl Announcement {
    /// Is it still visible?
    pub fn active(&self) -> bool {
        self.expires_in_s.is_none_or(|s| s > 0)
    }

    /// An ongoing, unresolved incident.
    ///
    /// 🔴 What makes an incident "resolved" is not its age but an update saying so. An
    /// incident you forget to close stays open, deliberately: silence must not pass for
    /// a resolution.
    pub fn open_incident(&self) -> bool {
        self.level == AnnouncementLevel::Incident && self.active()
    }

    /// The latest news, or the original body.
    pub fn last_update(&self) -> &str {
        self.follow_ups
            .last()
            .map(|m| m.body.as_str())
            .unwrap_or(&self.body)
    }
}

judged! {
    /// A human account, as the management screen sees it.
    #[derive(Debug, Clone, PartialEq)]
    pub struct AccountSummary {
        pub name: String,
        /// The role's id; `None` for an account given none.
        #[serde(default)]
        pub role: Option<String>,
        #[serde(default)]
        pub role_name: Option<String>,
        /// What the role may do to Homelabus — what authorization reads.
        pub level: String,
        /// Who gave the role.
        #[serde(default)]
        pub granted_by: Option<String>,
        /// Per app taking one, the quota that applies to them, and whose it is.
        #[serde(default)]
        pub quotas: Vec<crate::roles::AccountQuota>,
        /// 🔴 The COHERENCE state, not a plain "active / inactive".
        ///
        /// A half-created account looks functional: identity without a mailbox, the person
        /// signs in everywhere and their address receives nothing. It only shows on the
        /// first lost email — often a password reset, that is, at the worst moment.
        pub coherence: AccountState,
        /// What the state implies, and how to repair it.
        pub explanation: String,
        #[serde(default)]
        pub pocket_id: Option<String>,
        #[serde(default)]
        pub mailboxes: Vec<MailboxBrief>,
        pub active_aliases: usize,
        /// 🔴 Expired aliases that STILL receive: the purge has not run, and the address
        /// you believe is closed stays open.
        pub broken_promises: usize,
        /// Sessions ouvertes.
        pub sessions: usize,
    }

    rules {
        attention: Attention = |a: &AccountSummary| a.coherence.attention(),
        remedy: Option<String> = |a: &AccountSummary| a.coherence.remedy(&a.name),
    }
}

judged! {
    /// One alias, as its owner sees it.
    ///
    /// 🔴 Four states, not two. "Expired" and "expired but still receiving" are the same
    /// date and opposite realities: the second means the purge did not run and the address
    /// you believe closed is still open. Merging them would hide the only case worth acting
    /// on.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AliasSummary {
        /// The full address.
        pub address: String,
        /// The mailbox it delivers to.
        pub mailbox: String,
        /// The readable hint it was created from, when there was one.
        #[serde(default)]
        pub hint: Option<String>,
        #[serde(default)]
        pub note: Option<String>,
        /// `permanent`, `valid`, `expired`, `expired-but-active`.
        pub state: String,
        /// Seconds left before expiry, or elapsed since it. `None` when permanent.
        #[serde(default)]
        pub seconds: Option<i64>,
        /// Does it still receive?
        pub active: bool,
    }

    rules {
        lifecycle: AliasLifecycle = AliasSummary::lifecycle,
        attention: Attention = AliasSummary::attention,
    }
}

/// Where an alias is in its life — the four states of [`AliasSummary`], typed.
///
/// 🔴 The STRUCTURE and never the sentence. The sentence used to be built here, in
/// English, by `describe()`, and the interface displayed it in a French session — this
/// crate has no locale and cannot have one, since the controller and the CLI read it
/// too. The decision (which state, how long) stays here so the interface never
/// re-derives it; the words are the interface's, in its catalogue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AliasLifecycle {
    Permanent,
    /// Still receiving, for this long.
    Valid {
        expires_in_s: i64,
    },
    /// Expired and removed: it no longer receives.
    Expired,
    /// 🔴 Expired this long ago and STILL RECEIVING: the purge has not run.
    ExpiredButActive {
        since_s: i64,
    },
    /// A state this version does not know, from a newer controller.
    Unknown,
}

impl AliasSummary {
    /// Where this alias is in its life.
    pub fn lifecycle(&self) -> AliasLifecycle {
        match (self.state.as_str(), self.seconds) {
            ("permanent", _) => AliasLifecycle::Permanent,
            ("valid", Some(s)) => AliasLifecycle::Valid { expires_in_s: s },
            ("expired", _) => AliasLifecycle::Expired,
            ("expired-but-active", Some(s)) => AliasLifecycle::ExpiredButActive { since_s: s },
            _ => AliasLifecycle::Unknown,
        }
    }

    /// How much attention this alias deserves.
    pub fn attention(&self) -> Attention {
        match self.lifecycle() {
            // 🔴 The promise made to the person is broken: they asked for thirty days
            // and the address is still open. Nothing else here is critical.
            AliasLifecycle::ExpiredButActive { .. } => Attention::Critical,
            AliasLifecycle::Expired => Attention::Notice,
            AliasLifecycle::Permanent | AliasLifecycle::Valid { .. } | AliasLifecycle::Unknown => {
                Attention::Ok
            }
        }
    }
}

/// The coherence state of an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AccountState {
    Complete,
    /// Identity created, no mailbox.
    WithoutMailbox,
    /// Mailbox created, no identity.
    WithoutIdentity,
    Empty,
}

impl AccountState {
    pub fn attention(&self) -> Attention {
        match self {
            Self::Complete => Attention::Ok,
            // 🔴 Both halves are critical, not "keep an eye on it": in one case the
            // person receives nothing, in the other they cannot sign in. Both are
            // discovered at the worst moment.
            Self::WithoutMailbox | Self::WithoutIdentity | Self::Empty => Attention::Critical,
        }
    }

    /// The gesture that repairs it.
    pub fn remedy(&self, account: &str) -> Option<String> {
        match self {
            Self::Complete => None,
            // Resumable: `upsert_user` does a COALESCE on `pocket_id`, so a rerun
            // does not destroy what already exists.
            _ => Some(format!("hlb user add {account} --apply")),
        }
    }
}

judged! {
    /// An invitation to create an account.
    ///
    /// 🔴 The token VALUE is never here — only its fingerprint is stored, and the value is
    /// shown once, at creation. The type cannot represent it, so it cannot be leaked by
    /// accident.
    #[derive(Debug, Clone, PartialEq)]
    pub struct InvitationSummary {
        /// The first characters of the fingerprint, to name it without naming its value.
        pub reference: String,
        pub created_by: String,
        /// The role the account will hold — its id, fixed when the link was made.
        pub role: String,
        /// Seconds before expiry. Negative = already expired.
        pub expires_in_s: i64,
        /// `Some(date)` = the last time it was used.
        #[serde(default)]
        pub used_at: Option<String>,
        /// How many times it has been used.
        #[serde(default)]
        pub uses: usize,
        /// How many times it CAN be used.
        ///
        /// 🔴 A link with N uses that leaks lets N people in, not one. The number is
        /// therefore displayed: a widely open link must not go unnoticed.
        #[serde(default = "un")]
        pub max_uses: usize,
        #[serde(default)]
        pub note: Option<String>,
    }

    rules {
        state: InvitationState = InvitationSummary::state,
        usable: bool = InvitationSummary::usable,
        remaining: usize = InvitationSummary::remaining,
        widely_open: bool = InvitationSummary::widely_open,
    }
}

/// The default for `max_uses`: the safe case.
fn un() -> usize {
    1
}

/// What an invitation link can still do — typed, so the interface can say it in its
/// own language; see [`AliasLifecycle`] for why the words are not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum InvitationState {
    /// Every use is spent.
    Exhausted,
    Expired,
    /// Used at least once and still open: the one people forget to close.
    PartlyUsed,
    /// Never used, still open.
    Pending,
}

impl InvitationSummary {
    /// Can this invitation still be used?
    pub fn usable(&self) -> bool {
        self.uses < self.max_uses && self.expires_in_s > 0
    }

    /// How many people can still use it.
    pub fn remaining(&self) -> usize {
        self.max_uses.saturating_sub(self.uses)
    }

    pub fn state(&self) -> InvitationState {
        if self.uses >= self.max_uses {
            InvitationState::Exhausted
        } else if self.expires_in_s <= 0 {
            InvitationState::Expired
        } else if self.uses > 0 {
            // ⚠️ Distinct from "pending": a link that has already been used AND stays
            // open is the case worth seeing, because it is the one people forget to
            // close.
            InvitationState::PartlyUsed
        } else {
            InvitationState::Pending
        }
    }

    /// Does this link deserve suspicion?
    ///
    /// 🔴 A widely open link left lying around is a way in: the more uses remain, the
    /// more a leak costs.
    pub fn widely_open(&self) -> bool {
        self.usable() && self.remaining() > 3
    }
}

/// What an application asks the platform for: a [`hlb_types::Capability`] as the
/// interface words it, with the defaults it would leave to the reader resolved.
///
/// A value rather than a sentence, so it is read in the person's language — and a
/// mirror rather than the capability itself, which the document cannot describe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Need {
    Database {
        /// The engine's own name (`postgres`), which is not translated.
        engine: String,
        name: String,
        /// They must be in the server's image, so they are worth reading before.
        extensions: Vec<String>,
        /// The most it opens to the shared server, which every app's budget shares.
        connections: Option<u32>,
    },
    Cache {
        engine: String,
        dedicated: bool,
    },
    Sso {
        mode: SsoNeed,
        redirects: usize,
    },
    Smtp {
        /// Sent as the person signed in, with their own mailbox — a webmail: no
        /// account of the app's.
        as_person: bool,
    },
    MailAccount {
        aliases: bool,
        /// ⚠️ Declared, never enforced: Stalwart does not expose quotas over JMAP, and
        /// a quota shown without saying so suggests a limit that does not exist.
        declared_quota_bytes: Option<u64>,
    },
    Volume {
        name: String,
        path: String,
        nfs: bool,
        backed_up: bool,
        sqlite: bool,
    },
    Bucket {
        name: String,
        backed_up: bool,
    },
}

/// How an application signs people in — [`hlb_types::SsoMode`], for the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SsoNeed {
    Native,
    ProxyHeader,
    ProxyOnly,
    Excluded,
}

impl Need {
    /// 🔴 Exhaustive, and with no `..`: a field skipped here is a declaration the
    /// catalogue stops showing — how `mode` was once swallowed on `Sso`.
    pub fn of(capability: &hlb_types::Capability, app: &str) -> Self {
        use hlb_types::{Capability as C, SsoMode, StorageTier};
        match capability {
            C::Database {
                engine,
                name,
                extensions,
                connections,
            } => Self::Database {
                engine: engine.service_name().into(),
                name: name.clone().unwrap_or_else(|| app.into()),
                extensions: extensions.clone(),
                connections: *connections,
            },
            C::Cache { engine, dedicated } => Self::Cache {
                engine: engine.service_name().into(),
                dedicated: *dedicated,
            },
            C::Sso {
                mode,
                redirect_paths,
            } => Self::Sso {
                mode: match mode {
                    SsoMode::Native => SsoNeed::Native,
                    SsoMode::ProxyHeader => SsoNeed::ProxyHeader,
                    SsoMode::ProxyOnly => SsoNeed::ProxyOnly,
                    SsoMode::None => SsoNeed::Excluded,
                },
                redirects: redirect_paths.len(),
            },
            C::Smtp { sender } => Self::Smtp {
                as_person: match sender {
                    hlb_types::SmtpSender::App => false,
                    hlb_types::SmtpSender::Person => true,
                },
            },
            C::MailAccount {
                quota_bytes,
                aliases,
            } => Self::MailAccount {
                aliases: *aliases,
                declared_quota_bytes: *quota_bytes,
            },
            // Another app's volume reads as a volume of this one, not backed up by it —
            // which is what it is from here.
            C::Storage {
                name,
                path,
                tier,
                backup,
                sqlite,
                copy: _,
                owner: _,
            } => Self::Volume {
                name: name.clone(),
                path: path.clone(),
                nfs: match tier {
                    StorageTier::Local => false,
                    StorageTier::Nfs => true,
                },
                backed_up: *backup,
                sqlite: *sqlite,
            },
            // 🔴 No backup pass reads a bucket: shown as backed up because the manifest
            // said so, it was a copy nobody makes. Validation refuses `backup: true`;
            // a manifest frozen before still says it.
            C::ObjectStorage {
                bucket,
                backup: _,
                expire_after_days: _,
            } => Self::Bucket {
                name: hlb_types::capability::bucket_name(bucket.as_deref(), app).into(),
                backed_up: false,
            },
        }
    }
}

/// A catalog entry, as browsed before installing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct CatalogItem {
    pub name: String,
    pub display_name: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    pub image: String,
    /// What it requires: databases, SSO, volumes, object storage.
    #[serde(default)]
    pub capabilities: Vec<Need>,
    /// Does it need a domain?
    ///
    /// Decided here rather than guessed by the interface: an app with no ingress has
    /// nothing to expose, and asking for a domain would collect an unused value.
    pub requests_domain: bool,
    /// 🔴 The MANUAL prerequisites, before the install even starts.
    ///
    /// Listing them up front lets you prepare everything in one sitting, instead of
    /// discovering on the sixth screen that a DNS record was needed.
    #[serde(default)]
    pub prerequisites: Vec<String>,
    /// Already installed?
    pub installed: bool,
    /// Whether `/api/catalog/{name}/icon` has an image to serve. Most apps do; the
    /// rest get a monogram rather than a request answered 404.
    pub icon: bool,
}

judged! {
    /// The outcome of an action: what it WOULD do, or what it did.
    ///
    /// ## 🔴 Preview by default, over HTTP as on the command line
    ///
    /// An action route returns this plan **without doing anything**. It acts only with
    /// `?apply=true`. This is the exact transposition of `Executor::apply(true)`, and the
    /// most important invariant of this project: the default mode changes nothing.
    ///
    /// The type carries `applied` so the interface cannot confuse "here is what would
    /// happen" with "here is what happened" — the most expensive confusion possible on a
    /// screen that triggers actions.
    #[derive(Debug, Clone, PartialEq)]
    pub struct ActionResult {
        /// `false` = preview, nothing was done.
        pub applied: bool,
        /// What the action does, in one sentence.
        pub summary: String,
        /// The detail, step by step.
        #[serde(default)]
        pub steps: Vec<ActionStep>,
        /// 🔴 The equivalent command.
        ///
        /// The CLI stays the source of truth; the interface teaches it rather than
        /// replacing it, and the action becomes reproducible and scriptable. It is also
        /// what lets you check that the interface does what you think it does.
        pub cli_command: String,
        /// What **prevents** applying.
        #[serde(default)]
        pub blockers: Vec<String>,
        /// What you should know before applying, without it standing in the way.
        ///
        /// 🔴 Distinct from blockers, and the distinction matters. Filing a warning among
        /// the blockers makes the action impossible: "this link will let five people in"
        /// becomes a refusal, when it is a legitimate choice you simply want to see before
        /// making it.
        ///
        /// The reverse is worse still: treating a blocker as a warning would let an action
        /// be applied that cannot succeed.
        #[serde(default)]
        pub warnings: Vec<String>,
        /// The confirmation expected for a destructive operation.
        ///
        /// `Some(target)` = exactly this name must be sent back in the body. A role is not
        /// enough: a tired administrator at 2 a.m. is still an administrator.
        #[serde(default)]
        pub confirmation_required: Option<String>,
    }

    rules {
        applicable: bool = ActionResult::applicable,
        succeeded: bool = ActionResult::succeeded,
        outcome: Outcome = ActionResult::outcome,
    }
}

/// One step of an action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ActionStep {
    pub description: String,
    pub state: StepState,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum StepState {
    /// In preview: what would be done.
    Planned,
    Done,
    Failed,
    /// 🔴 Recognised but not yet implemented by the executor.
    ///
    /// **Never confused with `Done`**: we never claim to have provisioned a database.
    /// This is the invariant that stops a dashboard going green on an action nobody
    /// performed.
    Unimplemented,
}

/// How an action ended: see [`ActionResult::outcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    /// Nothing was changed; the summary is what would be done.
    Preview,
    /// This many steps failed, and the action stopped at the first.
    Failed { steps: usize },
    /// 🔴 No error, and this many steps the executor cannot perform yet: the action is
    /// INCOMPLETE, and must never read as finished.
    Incomplete { steps: usize },
    /// Every step done; the summary is what was approved.
    Done,
}

impl ActionResult {
    /// Can this be applied?
    pub fn applicable(&self) -> bool {
        self.blockers.is_empty()
    }

    /// Did the action really succeed?
    ///
    /// ⚠️ An unimplemented step fails this verdict: "the plan ran without error" and
    /// "the app is installed" are not the same thing.
    pub fn succeeded(&self) -> bool {
        self.applied && self.steps.iter().all(|e| e.state == StepState::Done)
    }

    /// What happened, as a decision the interface can word in its own language.
    pub fn outcome(&self) -> Outcome {
        if !self.applied {
            return Outcome::Preview;
        }
        let failures = self
            .steps
            .iter()
            .filter(|e| e.state == StepState::Failed)
            .count();
        let unimplemented = self
            .steps
            .iter()
            .filter(|e| e.state == StepState::Unimplemented)
            .count();

        if failures > 0 {
            Outcome::Failed { steps: failures }
        } else if unimplemented > 0 {
            // 🔴 Say it explicitly: "finished" on a half-implemented plan would
            // suggest the app is ready.
            Outcome::Incomplete {
                steps: unimplemented,
            }
        } else {
            Outcome::Done
        }
    }

    /// What happened, in English — for the audit log the controller writes, which has
    /// no locale. The interface reads [`Self::outcome`] instead and says it in its own.
    pub fn verdict(&self) -> String {
        match self.outcome() {
            Outcome::Preview => format!("Preview — nothing was changed. {}", self.summary),
            Outcome::Failed { steps: n } => {
                format!(
                    "{} failed — the action stopped there.",
                    plural(n as u64, "step", "steps")
                )
            }
            Outcome::Incomplete { steps: n } => format!(
                "{} {} not implemented yet — the action is INCOMPLETE, despite the \
                 absence of any error.",
                plural(n as u64, "step", "steps"),
                if n > 1 { "are" } else { "is" }
            ),
            Outcome::Done => self.summary.clone(),
        }
    }
}

/// What the topology says about the installation: see [`Topology::verdict`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TopologyVerdict {
    /// 🔴 This many services have ALL their replicas on one piece of hardware.
    RedundancyIllusion { services: usize },
    /// `nodes` of the `total` are on one domain — losing it would take the quorum.
    /// `domain` is `None` when that domain is undeclared.
    Concentrated {
        nodes: usize,
        total: usize,
        domain: Option<String>,
    },
    /// Some nodes have no declared failure domain: the real spread is unknown.
    SpreadUnknown,
    /// The load is spread across several failure domains.
    Spread,
    /// No machine is known: there is nothing to judge, which is not a spread.
    NoMachine,
}

judged! {
    /// The cluster topology, grouped by **failure domain**.
    ///
    /// ## 🔴 What this screen exists to dispel
    ///
    /// On the command line you see three nodes and believe yourself protected. Two of them
    /// are two VMs on the same server: the hardware dies and two thirds of the cluster go
    /// with it. This screen justifies the interface on its own, for that precise reason —
    /// the information exists, it is simply not readable anywhere else.
    #[derive(Debug, Clone, PartialEq)]
    pub struct Topology {
        pub domains: Vec<DomainSummary>,
        /// The services whose replicas share a piece of hardware.
        #[serde(default)]
        pub violations: Vec<ViolationSummary>,
        /// The manager nodes, when they are known.
        ///
        /// ⚠️ An EMPTY list means "we do not know", never "no manager" — a cluster with no
        /// manager does not exist. The simulator then returns `Quorum::Unknown` rather
        /// than claiming quorum holds.
        #[serde(default)]
        pub managers: Vec<String>,
        /// Total number of reachable nodes.
        pub total_nodes: usize,
    }

    rules {
        attention: Attention = Topology::attention,
        verdict: TopologyVerdict = Topology::verdict,
        // What losing each failure domain would cost. The drawing shows WHERE things run;
        // this says what goes with each domain, which nobody adds up from a drawing.
        simulations: Vec<outage::Simulation> = |t: &Topology| outage::simulate_all(t, &t.managers),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct DomainSummary {
    /// `None` = undeclared domain. That is **not** "isolated": it is "we do not
    /// know", and the display must say so.
    #[serde(default)]
    pub name: Option<String>,
    pub nodes: Vec<NodeInDomain>,
    /// Does this domain carry more than half the cluster?
    pub concentrated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct NodeInDomain {
    pub id: String,
    pub hostname: String,
    #[serde(default)]
    pub tier: Option<String>,
    pub reachable: bool,
    /// The services running on it.
    #[serde(default)]
    pub services: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ViolationSummary {
    pub service: String,
    #[serde(default)]
    pub domain: Option<String>,
    pub replicas: usize,
    pub total: usize,
    /// 🔴 Every replica in the same place: the redundancy is an illusion.
    pub total_violation: bool,
    pub explanation: String,
}

impl Topology {
    /// The overall attention level.
    pub fn attention(&self) -> Attention {
        if self.total_nodes == 0 {
            return Attention::Notice;
        }
        if self.violations.iter().any(|v| v.total_violation) {
            return Attention::Critical;
        }
        if !self.violations.is_empty() || self.domains.iter().any(|d| d.concentrated) {
            return Attention::Notice;
        }
        Attention::Ok
    }

    /// The verdict — the decision, worst first; the interface has the sentence.
    pub fn verdict(&self) -> TopologyVerdict {
        // 🔴 Before the rest: with no domain, "none concentrated, none undeclared" holds
        // by vacuity, and an installation with no machine would read as well spread.
        if self.total_nodes == 0 {
            return TopologyVerdict::NoMachine;
        }
        let total = self.violations.iter().filter(|v| v.total_violation).count();
        if total > 0 {
            return TopologyVerdict::RedundancyIllusion { services: total };
        }
        if let Some(d) = self.domains.iter().find(|d| d.concentrated) {
            return TopologyVerdict::Concentrated {
                nodes: d.nodes.len(),
                total: self.total_nodes,
                domain: d.name.clone(),
            };
        }
        if self.domains.iter().any(|d| d.name.is_none()) {
            // ⚠️ Neither good nor bad: we do not know. Staying quiet would suggest a
            // verified spread that has not been verified.
            return TopologyVerdict::SpreadUnknown;
        }
        TopologyVerdict::Spread
    }
}

/// A Swarm task, as the topology view places it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct TaskSummary {
    pub id: String,
    pub service: String,
    #[serde(default)]
    pub slot: Option<u64>,
    #[serde(default)]
    pub node: Option<String>,
    pub state: String,
    pub desired_state: String,
    pub alive: bool,
    pub failed: bool,
    /// 🔴 What explains a failure. This is the field the old counter threw away.
    #[serde(default)]
    pub explanation: Option<String>,
    #[serde(default)]
    pub image: Option<String>,
}

/// A backup run, for the timeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct BackupRun {
    /// The run's row: two runs can share everything else, down to the second — four
    /// retries refused by the same dead destination do.
    pub id: i64,
    pub app: String,
    pub kind: String,
    #[serde(default)]
    pub destination: Option<String>,
    pub succeeded: bool,
    #[serde(default)]
    pub error: Option<String>,
    pub when: String,
}

judged! {
    /// The state of a destination for one app.
    #[derive(Debug, Clone, PartialEq)]
    pub struct CoverageSummary {
        pub app: String,
        /// `(destination, age in seconds or `None` if never used)`.
        pub per_destination: Vec<(String, Option<i64>)>,
        /// 🔴 The 3-2-1 number: how many copies REALLY protect.
        ///
        /// Distinct from the number of declared destinations — a failing destination
        /// protects nothing.
        pub up_to_date_copies: usize,
    }

    rules {
        attention: Attention = CoverageSummary::attention,
        coverage: Coverage = CoverageSummary::coverage,
    }
}

/// Where an app stands against 3-2-1: see [`CoverageSummary::coverage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Coverage {
    NoDestination,
    /// Nothing exists anywhere.
    NeverBackedUp,
    /// Copies exist, and every one of the `destinations` is too old.
    NoFreshCopy {
        destinations: usize,
    },
    /// One up-to-date copy out of `destinations`: 3-2-1 is not met.
    OneFreshCopy {
        destinations: usize,
    },
    /// This many up-to-date copies.
    FreshCopies {
        copies: usize,
    },
}

impl CoverageSummary {
    pub fn attention(&self) -> Attention {
        match self.up_to_date_copies {
            0 => Attention::Critical,
            1 => Attention::Notice,
            _ => Attention::Ok,
        }
    }

    /// Are there backups, but all of them stale?
    ///
    /// 🔴 Two very different situations hide behind "no up-to-date copy": **never
    /// backed up** (nothing exists, anywhere) and **stale backups** (copies exist, they
    /// are old). The first calls for configuring a backup, the second for understanding
    /// why it stopped running.
    ///
    /// Seen on screen: "NO up-to-date copy" next to two destinations showing "1 d"
    /// reads as a contradiction, and you then doubt the whole screen.
    pub fn all_stale(&self) -> bool {
        self.up_to_date_copies == 0
            && !self.per_destination.is_empty()
            && self.per_destination.iter().all(|(_, age)| age.is_some())
    }

    /// Nothing exists anywhere.
    pub fn never_backed_up(&self) -> bool {
        self.per_destination.iter().all(|(_, age)| age.is_none())
    }

    /// Where this app stands against 3-2-1 — the decision; the interface has the
    /// sentence.
    pub fn coverage(&self) -> Coverage {
        let destinations = self.per_destination.len();
        match self.up_to_date_copies {
            0 if destinations == 0 => Coverage::NoDestination,
            0 if self.never_backed_up() => Coverage::NeverBackedUp,
            0 => Coverage::NoFreshCopy { destinations },
            1 => Coverage::OneFreshCopy { destinations },
            copies => Coverage::FreshCopies { copies },
        }
    }
}

judged! {
    /// A gap between what should be running and what is.
    ///
    /// ## Why the reason for a refusal is a field, not a comment
    ///
    /// Reconciliation never deletes an orphan, never resurrects a failed install, and
    /// never forces a convergence in flight. Those refusals were **invisible**: nothing
    /// distinguished "nothing to do" from "there is something and I deliberately chose not
    /// to touch it".
    ///
    /// The two look alike on screen. The second, unexplained, makes you doubt the system:
    /// you fix by hand what it was protecting, or you believe it saw nothing.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DriftSummary {
        /// The app or service concerned.
        pub target: String,
        /// The finding, in one sentence.
        pub description: String,
        /// Can reconciliation correct this gap?
        pub corrigible: bool,
        /// 🔴 Why it does **not** correct it. Present exactly when `corrigible` is false.
        #[serde(default)]
        pub refusal: Option<String>,
        /// The command that repairs what it leaves alone, when one does.
        #[serde(default)]
        pub fix: Option<String>,
        /// What the gap does to the app while it stands — apart from whether
        /// reconciliation touches it.
        #[serde(default)]
        pub harm: DriftHarm,
    }

    rules {
        attention: Attention = DriftSummary::attention,
    }
}

/// What a gap does to the app while it stands.
///
/// 🔴 Separate from `corrigible`: refusing to act is a decision, but what was refused
/// can still be an outage. Read from the refusal alone, a Garage that lost Fluxer's key
/// was painted green, and the issues list drops green — Fluxer ran 1/1 against
/// `No such key` with the dashboard calm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DriftHarm {
    /// Nothing is broken: a decision, or progress under way.
    #[default]
    Harmless,
    /// Whether anything is broken could not be read — never "it is fine".
    Unknown,
    /// The app does not work as it should until a person acts.
    Broken,
}

impl DriftSummary {
    pub fn attention(&self) -> Attention {
        if self.corrigible {
            // A correctable gap is not a failure: the next round will pick it up.
            return Attention::Notice;
        }
        match self.harm {
            // ⚠️ A deliberate refusal over nothing broken is not an alert — it is a
            // decision. Painting it red would send you looking for a problem where the
            // system did exactly the right thing.
            DriftHarm::Harmless => Attention::Ok,
            DriftHarm::Unknown => Attention::Notice,
            DriftHarm::Broken => Attention::Critical,
        }
    }
}

judged! {
    /// What an app declares, and what is actually published.
    ///
    /// ## Why the comparison is a screen
    ///
    /// The manifest declares `expose`, and `hlb-ingress` renders the Caddy configuration.
    /// Both exist; nobody puts them side by side. An app published by mistake is therefore
    /// **completely invisible** — and that is exactly the kind of mistake that is easy to
    /// make.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ExposureSummary {
        pub app: String,
        /// Whether `app` is installed. ⚠️ A route can outlive its app — Caddy keeps
        /// serving it — and there is then no application page to lead to.
        pub installed: bool,
        pub host: String,
        /// What the manifest asks for: `private`, `after-guide`, `public`.
        pub declared: String,
        /// 🔴 What is REALLY reachable from the internet, right now.
        pub public: bool,
        /// The explanation of the gap between the two, when there is one.
        #[serde(default)]
        pub divergence: Option<String>,
        /// The gap as a value — what the inbox files it under, and what the interface
        /// words in the reader's language. `divergence` is the CLI's sentence.
        #[serde(default)]
        pub cause: Option<crate::issues::Cause>,
    }

    rules {
        attention: Attention = ExposureSummary::attention,
        reach: Reach = ExposureSummary::reach,
    }
}

/// What one exposure row says: see [`ExposureSummary::reach`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Reach {
    /// The controller found the exposure differs from what the manifest declares —
    /// its own words, already a sentence, are the row's `divergence`.
    Diverged,
    /// Reachable from the internet.
    Internet,
    /// Reachable from the VPN only.
    VpnOnly,
}

impl ExposureSummary {
    pub fn attention(&self) -> Attention {
        if self.divergence.is_some() {
            Attention::Critical
        } else if self.public {
            // ⚠️ A compliant public app is not a problem — but it is not "nothing to
            // report" either. What sits on the internet deserves to be seen, or the
            // list stops being read.
            Attention::Notice
        } else {
            Attention::Ok
        }
    }

    /// What the row says: a divergence the controller found, or where the host can be
    /// reached from. The interface has the sentence for the last two.
    pub fn reach(&self) -> Reach {
        match (&self.divergence, self.public) {
            (Some(_), _) => Reach::Diverged,
            (None, true) => Reach::Internet,
            (None, false) => Reach::VpnOnly,
        }
    }
}

/// One row of the installation checklist.
///
/// 🔴 This is not a setup wizard — a web interface cannot be the first step. It is an
/// AFTER-THE-FACT check, on the things you believe are done and never verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HealthCheck {
    pub attention: Attention,
    /// What was found — its title included, since the interface words both.
    pub finding: HealthFinding,
    /// The command or screen that fixes it. Absent when there is nothing to do.
    #[serde(default)]
    pub remedy: Option<String>,
}

/// What a [`HealthCheck`] found, the good states included: a line that is fine still
/// says what was checked, and in the reader's language.
///
/// Its `attention` beside it says how much it matters; a variant never decides that
/// twice — `Heartbeat` is silent or not according to the check's attention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HealthFinding {
    NoDestination,
    SingleDestination,
    Destinations {
        count: u64,
    },
    DrillNever,
    DrillRecent {
        days: i64,
    },
    /// Past the interval the drills aim for.
    DrillDue {
        days: i64,
        every_days: i64,
    },
    /// 🔴 Past the age at which the procedure has had time to diverge.
    DrillOverdue {
        days: i64,
        late_days: i64,
    },
    HeartbeatAbsent,
    /// ⚠️ It attests to the heartbeat only: the watchdog does not run on what it
    /// watches, and the wording must say so whatever the age.
    Heartbeat {
        age_seconds: i64,
    },
    /// No `admin` token: access may go through an OIDC session, invisible from here.
    AdminUnknown,
    AdminSingle,
    AdminTokens {
        count: u64,
    },
    AuditIntact,
    AuditBroken,
    AuditUnreadable,
}

/// One event of the unified timeline.
///
/// ## Why a single river
///
/// Deployments, backups, alerts and audit entries each live on their own screen and in
/// their own table. Correlating "the app went down at 03:12" with "update applied at
/// 03:10" then means opening four screens and comparing timestamps by hand — precisely
/// what the command line cannot do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Event {
    /// Seconds since the epoch. The sort key, and the only thing the four sources have
    /// in common.
    pub when: i64,
    pub kind_of: EventKind,
    /// The app, node or person concerned.
    pub target: String,
    /// What happened, in one sentence.
    pub what: String,
    pub attention: Attention,
}

/// Where the event comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Backup,
    Verification,
    /// A human or machine action, taken from the audit log.
    Action,
    Alert,
}

/// One manifest version, with what changed since the previous one.
///
/// ## Why the Git mirror rather than one more table
///
/// `apps.manifest` is overwritten on every update: the state only keeps the current
/// version. Answering "what changed when the app stopped working?" would therefore
/// mean storing a history — while `hlb-gitops` already keeps one, complete and dated.
/// We read from it, we add nothing to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct VersionManifest {
    /// The mirror's short commit.
    pub reference: String,
    /// The commit summary: what Homelabus was doing at that moment.
    pub subject: String,
    /// The lines changed since the previous version, prefixed `+` or `-`.
    ///
    /// ⚠️ Empty for the oldest known version: there is nothing before it. That is
    /// **not** "nothing changed".
    #[serde(default)]
    pub diff: Vec<String>,
    /// True for the oldest known version, the one with no predecessor.
    pub origin: bool,
}

judged! {
    /// A plan prepared cold, saved under a name.
    ///
    /// ## Why save a plan rather than redo it
    ///
    /// An operation is prepared when you have time, and executed during a quiet hour.
    /// Deciding and executing everything within the same minute is exactly how you aim at
    /// the wrong target.
    ///
    /// 🔴 The plan is replayed **as it was previewed**, never recomputed: two computations
    /// at two different moments can diverge — an app installed meanwhile, a changed
    /// domain — and you would then execute something other than what you read.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct NamedPlan {
        pub name: String,
        /// The summary read at save time: THIS is the text that was approved.
        pub summary: String,
        pub method: String,
        pub path: String,
        /// The request's JSON body as previewed; empty when it had none.
        pub body: String,
        /// The route template the request is replayed through; `None` when no route
        /// takes it any more, or none that previews — then it is kept, never replayed.
        pub route: Option<String>,
        pub created_by: String,
        /// The plan's age, in seconds.
        pub age_s: i64,
    }

    rules {
        attention: Attention = NamedPlan::attention,
    }
}

/// Beyond that, a prepared plan may describe a cluster that no longer exists.
pub const PLAN_STALE_S: i64 = 30 * 86_400;

impl NamedPlan {
    pub fn attention(&self) -> Attention {
        if self.age_s > PLAN_STALE_S {
            // ⚠️ Not a blocker: a warning. A six-week-old plan can be perfectly valid —
            // but it was written for a cluster you may no longer have.
            Attention::Notice
        } else {
            Attention::Ok
        }
    }

    /// How old the plan is, when that is old enough to re-read the preview before
    /// applying it — the installation may have changed since. `None` while it is
    /// recent enough not to say so.
    pub fn stale_for(&self) -> Option<i64> {
        (self.age_s > PLAN_STALE_S).then_some(self.age_s)
    }
}

/// An alert, as the interface shows it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ActiveAlert {
    /// The rule's short, stable identifier.
    pub rule: String,
    pub level: AlertLevel,
    /// What the person needs to understand, in one sentence.
    pub explanation: String,
    /// The observed value. `None` when the rule could not be evaluated.
    #[serde(default)]
    pub value: Option<f64>,
    pub threshold: f64,
    /// How long it has been active, in seconds.
    ///
    /// 🔴 An alert that just appeared and one that has lasted three days are not
    /// handled the same way: the second was ignored, or its remedy does not work.
    pub since_s: i64,
    /// 🔴 Muted — **never resolved**. See [`Self::is_muted`].
    #[serde(default)]
    pub muted_until: Option<i64>,
    /// Who muted it.
    #[serde(default)]
    pub muted_by: Option<String>,
    /// Why. Required when muting: a mute nobody can explain afterwards is the one
    /// nobody dares lift.
    #[serde(default)]
    pub mute_reason: Option<String>,
}

/// A mute as it is stored, in `alert_mutes`.
///
/// 🔴 The ONE source of a mute. The evaluation loop used to carry the previous pass's
/// copy forward in memory, so a restart lifted every mute — and the alert it silenced
/// notified again, on the night nobody was watching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertMute {
    pub rule: String,
    /// When it ends, in seconds since the epoch.
    pub until: i64,
    pub by: String,
    pub reason: String,
}

/// The longest a mute may run. A mute with no end is a deleted alert that still looks
/// like it is being watched.
pub const MUTE_MAX_S: i64 = 7 * 86_400;

/// The severity of an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AlertLevel {
    /// 🔴 The rule can no longer be evaluated. **This is not "all is well"**:
    /// collection may have died, and this watch has been blind since.
    Unknown,
    Info,
    Important,
    Critical,
}

impl AlertLevel {
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Unknown => "not evaluable",
            Self::Info => "information",
            Self::Important => "important",
            Self::Critical => "critical",
        }
    }

    /// The matching attention level, for display.
    pub fn attention(&self) -> Attention {
        match self {
            Self::Info => Attention::Ok,
            // ⚠️ "Not evaluable" maps to `Notice` and not `Ok`: not knowing deserves a
            // look, even if it is not yet a failure.
            Self::Unknown | Self::Important => Attention::Notice,
            Self::Critical => Attention::Critical,
        }
    }
}

/// A mute in force: see [`ActiveAlert::mute`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Mute {
    /// How long it still has to run.
    pub remaining_s: i64,
    /// Who set it, when the controller recorded it.
    #[serde(default)]
    pub by: Option<String>,
    /// Why it was set.
    #[serde(default)]
    pub reason: Option<String>,
}

/// An alert as it stands at one instant, with the rules that read the clock decided.
///
/// ⚠️ Not `judged!`: a mute runs out, so whether one is in force depends on WHEN the
/// answer is produced, and serialisation has no clock to ask. The controller builds
/// this with its own `now`, once per response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AlertAt {
    #[serde(flatten)]
    pub alert: ActiveAlert,
    pub attention: Attention,
    #[serde(default)]
    pub mute: Option<Mute>,
}

impl ActiveAlert {
    /// Is this alert muted at this instant?
    pub fn is_muted(&self, now: i64) -> bool {
        self.muted_until.is_some_and(|f| f > now)
    }

    /// The mute in force at this instant, if any: how long it still has to run, and
    /// who set it.
    ///
    /// 🔴 A muted alert **never** looks like a resolved one: it stays visible, marked,
    /// with the deadline of its mute. Making it disappear would be the same family of
    /// error as `Freshness` — absent information disguised as reassuring information.
    /// The interface says so beside the explanation, in its own words.
    pub fn mute(&self, now: i64) -> Option<Mute> {
        match self.muted_until {
            Some(f) if f > now => Some(Mute {
                remaining_s: f - now,
                by: self.muted_by.clone(),
                reason: self.mute_reason.clone(),
            }),
            _ => None,
        }
    }

    /// Takes its mute from the stored ones — and drops any it carried: a mute lifted
    /// in the table must stop applying here, not linger until the next restart.
    pub fn apply_mutes(&mut self, mutes: &[AlertMute]) {
        let m = mutes.iter().find(|m| m.rule == self.rule);
        self.muted_until = m.map(|m| m.until);
        self.muted_by = m.map(|m| m.by.clone());
        self.mute_reason = m.map(|m| m.reason.clone());
    }

    /// This alert at `now`, ready to be sent.
    pub fn at(&self, now: i64) -> AlertAt {
        AlertAt {
            attention: self.attention(now),
            mute: self.mute(now),
            alert: self.clone(),
        }
    }

    /// The level accounts for the mute — to sort, not to hide.
    pub fn attention(&self, now: i64) -> Attention {
        if self.is_muted(now) {
            // Downgraded one notch, never as far as `Ok`: a mute says "I know", not
            // "it is fixed".
            return match self.level.attention() {
                Attention::Critical => Attention::Notice,
                other => other,
            };
        }
        self.level.attention()
    }
}

/// A time series, as the interface draws it.
///
/// 🔴 **`Unavailable` is a variant, not an empty series.**
///
/// An empty series draws as a flat line at zero, which reads as "all is calm" — the
/// exact opposite of "I have no data". Same family of error as `Freshness` in the
/// interface and as "an absent metric beats a zero" on the server: in all three,
/// absent information disguises itself as reassuring information.
///
/// The type therefore forces the case to be handled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Series {
    Points {
        name: String,
        /// `(Unix timestamp, value)`, in order.
        points: Vec<(i64, f64)>,
        unit: Unit,
    },
    /// VictoriaMetrics is absent, silent, or the query returned nothing.
    Unavailable { reason: String },
}

/// How to read a series' values.
///
/// Used for display: a ratio shows as a percentage, bytes show in GiB, a duration is
/// humanised. Without this, the interface would have to guess from the metric name —
/// and would get it wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    /// A fraction in `[0, 1]`, displayed as a percentage.
    Ratio,
    Bytes,
    /// Bytes per second.
    BytesPerSecond,
    Seconds,
    /// A unitless count.
    Count,
}

/// A measurement the controller keeps a day of, for the home's curves.
///
/// Kept by the controller itself, one a minute, so that a curve needs nothing installed
/// beside it. A longer history is VictoriaMetrics' (`/api/v1/metrics/series`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    /// A machine's processor in use, `[0, 1]`.
    Cpu,
    /// A machine's memory in use, `[0, 1]`.
    Memory,
    /// A machine's swap in use, `[0, 1]`.
    Swap,
    /// A machine's load average over a minute, per core.
    Load,
    /// How full each disk of each machine is, `[0, 1]`.
    Disk,
    /// What a machine receives, every interface together.
    NetIn,
    /// What a machine sends, every interface together.
    NetOut,
    /// How many applications run, across the installation.
    AppsRunning,
}

impl Metric {
    /// Every measurement, as the recorder keeps them.
    pub const ALL: [Metric; 8] = [
        Self::Cpu,
        Self::Memory,
        Self::Swap,
        Self::Load,
        Self::Disk,
        Self::NetIn,
        Self::NetOut,
        Self::AppsRunning,
    ];

    /// The key it is stored under; a disk's is followed by its mount point.
    pub fn key(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Swap => "swap",
            Self::Load => "load",
            Self::Disk => "disk:",
            Self::NetIn => "net_rx",
            Self::NetOut => "net_tx",
            Self::AppsRunning => "apps_running",
        }
    }

    pub fn unit(self) -> Unit {
        match self {
            Self::Cpu | Self::Memory | Self::Swap | Self::Disk => Unit::Ratio,
            Self::NetIn | Self::NetOut => Unit::BytesPerSecond,
            Self::Load | Self::AppsRunning => Unit::Count,
        }
    }

    /// Stored as a counter that only grows, and read as a rate: a byte count since boot
    /// draws a ramp that says nothing about now.
    pub fn is_counter(self) -> bool {
        matches!(self, Self::NetIn | Self::NetOut)
    }
}

/// How far back a curve goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Window {
    Hour,
    SixHours,
    #[default]
    Day,
}

impl Window {
    pub fn seconds(self) -> i64 {
        match self {
            Self::Hour => 3_600,
            Self::SixHours => 6 * 3_600,
            Self::Day => 86_400,
        }
    }

    /// One point per this many seconds: about a hundred and twenty points, never finer
    /// than the minute the recorder keeps.
    pub fn step(self) -> i64 {
        (self.seconds() / 120).max(60)
    }
}

/// A day — or less — of one measurement, a line per machine or disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct History {
    pub metric: Metric,
    pub unit: Unit,
    pub window: Window,
    /// Seconds between two points.
    pub step_s: i64,
    /// Where the period begins and ends, in Unix seconds: the curve's horizontal scale,
    /// so a machine that answered only lately is drawn at the right end, not stretched.
    pub from: i64,
    pub now: i64,
    pub lines: Vec<HistoryLine>,
}

/// One machine's — or one disk's — curve.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct HistoryLine {
    /// The node's agent address; `""` for the installation as a whole.
    pub subject: String,
    /// What to call it: the machine's hostname as last reported, else its address.
    pub name: String,
    /// The mount point, for a disk.
    pub disk: Option<String>,
    /// `(Unix timestamp, value)`, oldest first. A gap in time is a gap in measurement —
    /// the machine did not answer — and is drawn as one, never joined across.
    pub points: Vec<(i64, f64)>,
}

impl Unit {
    /// Renders a value readable.
    pub fn show(&self, v: f64) -> String {
        match self {
            Self::Ratio => format!("{:.0} %", v * 100.0),
            Self::Bytes => bytes(v),
            Self::BytesPerSecond => format!("{}/s", bytes(v)),
            Self::Seconds => humanise(v as i64),
            // ⚠️ No decimal on a count: "3.0 applications" reads as an approximate
            // measurement when it is an exact integer.
            Self::Count => format!("{v:.0}"),
        }
    }
}

impl Series {
    /// The points, or nothing.
    ///
    /// There is **no** accessor returning an empty `Vec` when the series is
    /// unavailable: that is precisely the confusion being avoided.
    pub fn points(&self) -> Option<&[(i64, f64)]> {
        match self {
            Self::Points { points, .. } => Some(points),
            Self::Unavailable { .. } => None,
        }
    }

    /// The last known value.
    pub fn last(&self) -> Option<f64> {
        self.points()?.last().map(|(_, v)| *v)
    }

    /// What to display instead of a chart.
    pub fn unavailable(&self) -> Option<&str> {
        match self {
            Self::Unavailable { reason } => Some(reason),
            // A series of fewer than two points does not make a curve: drawing it
            // would give a misleading flat line.
            Self::Points { points, .. } if points.len() < 2 => Some("not enough samples"),
            Self::Points { .. } => None,
        }
    }
}

/// A byte count, readable.
pub fn bytes(v: f64) -> String {
    const THRESHOLD: f64 = 1024.0;
    let mut v = v;
    for u in ["B", "KiB", "MiB", "GiB", "TiB"] {
        if v.abs() < THRESHOLD {
            return if u == "B" {
                format!("{v:.0} {u}")
            } else {
                format!("{v:.1} {u}")
            };
        }
        v /= THRESHOLD;
    }
    format!("{v:.1} PiB")
}

/// Agrees a word with a count.
///
/// ⚠️ Text gets read: "1 replicas" jumps out and makes a page look accidentally
/// generated. Writing "replica(s)" everywhere would be the opposite of the care put
/// into the rest.
///
/// 🔴 This function was written for French, where **zero takes the singular**. English
/// inverts that rule: only one is singular. The translation was therefore a rewrite,
/// not a rename — a mechanical port would have produced "0 replica" everywhere.
pub fn plural(n: u64, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("{n} {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// The unit [`humanise`] picked, so a caller that has a locale can say it in its own
/// words.
///
/// 🔴 The point of splitting this out is that there is exactly ONE bucket table. A
/// second duration formatter written beside this one — which is what "the interface
/// needs French units" asks for — would carry its own thresholds, and two of them drift:
/// the day this one grows a "weeks" bucket, a copy in the interface keeps saying "13 d".
/// Here the interface chooses the WORD and never the number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurationUnit {
    /// A negative age. Not a duration at all: something is wrong with a clock.
    Future,
    Seconds,
    Minutes,
    Hours,
    Days,
    Months,
}

/// A duration in seconds, as a number and the unit it is counted in.
///
/// Deliberately coarse: on a dashboard, "3 h ago" informs as much as "3 h 12 min 04 s
/// ago" and reads at a glance.
///
/// ⚠️ [`DurationUnit::Future`] comes with a meaningless `0`: there is no number to show, and the
/// caller must render it as a sentence rather than as "0 something".
pub fn humanise_parts(secs: i64) -> (i64, DurationUnit) {
    match secs {
        s if s < 0 => (0, DurationUnit::Future),
        s if s < 60 => (s, DurationUnit::Seconds),
        s if s < 3600 => (s / 60, DurationUnit::Minutes),
        s if s < 86_400 => (s / 3600, DurationUnit::Hours),
        s if s < 2_592_000 => (s / 86_400, DurationUnit::Days),
        s => (s / 2_592_000, DurationUnit::Months),
    }
}

/// The same duration in English, for the controller, the CLI and anything else with no
/// locale to consult.
///
/// ⚠️ The interface must NOT show this: it says the unit in its locale's own words,
/// over the same [`humanise_parts`]. Four of these six units read the same in French,
/// and the two that do not are exactly the ones nobody notices.
pub fn humanise(secs: i64) -> String {
    let (n, unit) = humanise_parts(secs);
    match unit {
        DurationUnit::Future => "in the future?".to_string(),
        DurationUnit::Seconds => format!("{n} s"),
        DurationUnit::Minutes => format!("{n} min"),
        DurationUnit::Hours => format!("{n} h"),
        DurationUnit::Days => format!("{n} d"),
        DurationUnit::Months => format!("{n} mo"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_shared_string_uses_the_parenthesised_plural() {
        // 🔴 Seen on screen: "1 service(s) whose replicas ALL share...". The test that
        // banned this tic only covered the interface — yet `verdict()` is computed
        // HERE, precisely so both clients say the same thing. A writing rule enforced
        // on one side of the contract only protects nothing.
        //
        // ⚠️ The pattern is ASSEMBLED: writing it literally would make this test fail
        // on its own source.
        let tic = format!("({})", "s");
        // Walked: this test named `lib.rs` and `outage.rs` until 2026-10-05, and the
        // four other modules build sentences too.
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut walked = Vec::new();
        for entry in std::fs::read_dir(&src).expect("src/") {
            let path = entry.expect("entry").path();
            if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("read");
                let code = text
                    .split("\n#[cfg(test)]")
                    .next()
                    .unwrap_or("")
                    .to_string();
                walked.push((path.display().to_string(), code));
            }
        }
        assert!(walked.len() >= 6, "only {} sources walked", walked.len());
        for (file, source) in &walked {
            // ⚠️ The scan reads STRINGS, not code: `Some(s) => f(s)` is a perfectly
            // legitimate Rust pattern, and a line-by-line scan flagged it — a guard
            // that shouts at correct code ends up disabled.
            for text in displayed_strings(source) {
                assert!(
                    !text.contains(&tic),
                    "{file}: \"{text}\" — hlb_api::plural exists for this"
                );
            }
        }
    }

    /// The string literals of a source, comments excluded.
    ///
    /// ⚠️ A state machine, not a split on `//`, which cuts `"https://"` in half and reads
    /// every later quote of the file the wrong way round.
    fn displayed_strings(source: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut current = String::new();
        let mut inside = false;
        let mut chars = source.chars().peekable();

        while let Some(c) = chars.next() {
            if inside {
                match c {
                    '\\' => {
                        chars.next();
                    }
                    '"' => {
                        out.push(std::mem::take(&mut current));
                        inside = false;
                    }
                    _ => current.push(c),
                }
                continue;
            }
            match c {
                '/' if chars.peek() == Some(&'/') => {
                    for c in chars.by_ref() {
                        if c == '\n' {
                            break;
                        }
                    }
                }
                // `'"'` is a character, not the start of a string; `'a` is a lifetime.
                '\'' => {
                    let mut look = chars.clone();
                    match (look.next(), look.next()) {
                        (Some('\\'), _) => {
                            chars.next();
                            chars.next();
                            chars.next();
                        }
                        (Some(_), Some('\'')) => {
                            chars.next();
                            chars.next();
                        }
                        _ => {}
                    }
                }
                '"' => inside = true,
                _ => {}
            }
        }
        out
    }

    /// A glyph that carries meaning on its own: emoji, dingbats (`✓`, `✗`), warning
    /// signs. Arrows, dashes and accented letters are text, and pass.
    ///
    /// ⚠️ The same predicate sits in `hlb-backup` and `hlb-users`, which do not depend on
    /// this crate and must not start to for a test.
    fn is_pictograph(c: char) -> bool {
        matches!(c as u32, 0x2600..=0x27BF | 0x2B00..=0x2BFF | 0xFE0F | 0x1F000..=0x1FAFF)
    }

    #[test]
    fn no_shared_string_carries_a_pictograph() {
        // 🔴 These texts are shown by the CLI and by the interface, and severity travels
        // through their WORDS and the caller's colour — never a glyph. A 🔴 inside the
        // sentence is a second severity channel no caller can restyle, a screen reader
        // reads it out as "red circle", and it once rendered as a substitution box in an
        // interface whose fonts lacked it. Shared text must depend on NONE of its
        // consumers.
        //
        // Every source of the crate, walked rather than named: a module added tomorrow
        // is covered without anyone remembering to list it. Comments are skipped — the
        // 🔴 above is for the reader of the code, not for a screen.
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut walked = 0;
        for entry in std::fs::read_dir(&src).expect("src/") {
            let path = entry.expect("entry").path();
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            walked += 1;
            let source = std::fs::read_to_string(&path).expect("read");
            for (n, line) in source.lines().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if let Some(c) = code.chars().find(|&c| is_pictograph(c)) {
                    panic!(
                        "{} line {}: U+{:04X} in shared text",
                        path.display(),
                        n + 1,
                        c as u32
                    );
                }
            }
        }
        // lib.rs, breakglass, diagnostic, outage, palette, rotation on 2026-10-05.
        assert!(walked >= 6, "only {walked} sources walked");
    }

    use super::*;

    /// Every source of this crate, its tests cut off and its comments blanked.
    fn crate_code() -> Vec<(String, String)> {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&src).expect("src/") {
            let path = entry.expect("entry").path();
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read");
            let code = text
                .split("\n#[cfg(test)]")
                .next()
                .unwrap_or("")
                .lines()
                .map(|l| l.split("//").next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\n");
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            out.push((name.unwrap_or_default(), code));
        }
        // lib.rs, breakglass, diagnostic, outage, palette, rotation on 2026-10-05.
        assert!(out.len() >= 6, "only {} sources walked", out.len());
        out
    }

    /// The names a `judged!` block adds to the wire, by type.
    fn judged_fields(code: &str) -> Vec<(String, Vec<String>)> {
        let mut out = Vec::new();
        for block in code.split("judged! {").skip(1) {
            let Some((_, after)) = block.split_once("pub struct ") else {
                continue;
            };
            let ty: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let Some((_, rules)) = block.split_once("rules {") else {
                continue;
            };
            let fields = rules
                .split("\n    }\n}")
                .next()
                .unwrap_or("")
                .lines()
                .filter_map(|l| {
                    let l = l.trim();
                    let (name, _) = l.split_once(':')?;
                    // A rule line starts the line; a closure's body does not.
                    name.chars()
                        .all(|c| c.is_ascii_lowercase() || c == '_')
                        .then(|| name.to_string())
                })
                .collect();
            out.push((ty, fields));
        }
        out
    }

    #[test]
    fn every_attention_reaches_the_wire() {
        // `attention()` is THE rule every screen tints by. A struct that has one and does
        // not send it leaves the browser to re-derive it — the copy this crate exists to
        // prevent. (An enum's reaches the wire through the struct that holds it.)
        let sources = crate_code();
        let judged: Vec<(String, Vec<String>)> =
            sources.iter().flat_map(|(_, c)| judged_fields(c)).collect();
        // Twenty-two types on 2026-10-05; a parser that stopped finding them would pass.
        assert!(
            judged.len() >= 20,
            "only {} judged types found",
            judged.len()
        );
        let mut found = 0;
        for (file, code) in &sources {
            let mut owner: Option<String> = None;
            for line in code.lines() {
                if let Some(rest) = line.strip_prefix("impl ") {
                    owner = rest.split([' ', '<', '{']).next().map(str::to_string);
                }
                if !line.contains("pub fn attention(&self)") {
                    continue;
                }
                let Some(ty) = owner.clone() else { continue };
                let is_struct = sources
                    .iter()
                    .any(|(_, c)| c.contains(&format!("pub struct {ty} ")));
                if !is_struct {
                    continue;
                }
                found += 1;
                assert!(
                    judged
                        .iter()
                        .any(|(t, rules)| *t == ty && rules.iter().any(|r| r == "attention")),
                    "{file}: `{ty}::attention` is computed and never sent — add it to its \
                     `judged!`"
                );
            }
        }
        assert!(found >= 12, "only {found} structs with an attention found");
    }

    #[test]
    fn a_rule_reaches_the_wire_as_a_value_beside_the_fields() {
        // Never backed up, and running: the worst state there is, and the one a client
        // re-deriving the rule from `status` alone would paint green.
        let a = app("running", None, 0);
        let v = serde_json::to_value(&a).expect("serialise");
        assert_eq!(v["name"], "gitea", "{v}");
        assert_eq!(v["attention"], "critical", "{v}");
        assert_eq!(v["backup_attention"], "critical", "{v}");

        // And reading it back ignores what the rules added: they are recomputed, never
        // trusted from the wire.
        let back: AppSummary = serde_json::from_value(v).expect("read back");
        assert_eq!(back, a);
    }

    fn app(status: &str, backup: Option<i64>, guides: i64) -> AppSummary {
        AppSummary {
            name: "gitea".into(),
            status: status.into(),
            image: "gitea/gitea:1.24".into(),
            domain: Some("git.example.fr".into()),
            last_backup_secs: backup,
            holds_data: true,
            last_verification_secs: None,
            blocking_guides: guides,
        }
    }

    #[test]
    fn an_app_holding_nothing_is_owed_no_backup_on_the_dashboard() {
        let stateless = AppSummary {
            holds_data: false,
            ..app("running", None, 0)
        };
        assert_eq!(stateless.backup_attention(), Attention::Ok);
        assert_eq!(stateless.attention(), Attention::Ok);
        // Holding data, the same "never" stays the worst state.
        assert_eq!(app("running", None, 0).attention(), Attention::Critical);
    }

    #[test]
    fn a_never_backed_up_app_is_critical_even_when_healthy() {
        // 🔴 The dashboard trap: an app running perfectly with NO backup at all is the
        // worst state of the system — and the one that looks healthiest if you only
        // read the status.
        let a = app("running", None, 0);
        assert_eq!(a.attention(), Attention::Critical);
        assert_eq!(
            a.last_backup_secs, None,
            "never backed up, not backed up at 0 s"
        );
    }

    #[test]
    fn never_and_zero_seconds_are_not_the_same() {
        // Same distinction as for the metrics: a "0" would mean "backed up just now",
        // which is exactly the opposite.
        // ⚠️ The WORDS belong to the interface's locale, not to this crate. What is
        // asserted here is the distinction the type carries, which is this crate's half.
        assert_eq!(app("running", None, 0).last_backup_secs, None);
        assert_eq!(app("running", Some(0), 0).last_backup_secs, Some(0));
        assert_ne!(
            app("running", None, 0).attention(),
            app("running", Some(0), 0).attention()
        );
    }

    #[test]
    fn a_stale_backup_is_critical() {
        // The target interval is 4 h; beyond 24 h something is broken and nobody has
        // noticed.
        assert_eq!(app("running", Some(3600), 0).attention(), Attention::Ok);
        assert_eq!(
            app("running", Some(90_000), 0).attention(),
            Attention::Critical
        );
    }

    #[test]
    fn a_failed_app_is_critical() {
        assert_eq!(app("failed", Some(60), 0).attention(), Attention::Critical);
    }

    #[test]
    fn blocking_guides_are_a_notice_not_a_failure() {
        // A blocking guide is the system protecting the user, not a failure.
        assert_eq!(app("running", Some(60), 2).attention(), Attention::Notice);
        assert_eq!(app("partial", Some(60), 0).attention(), Attention::Notice);
    }

    #[test]
    fn a_healthy_app_is_ok() {
        assert_eq!(app("running", Some(600), 0).attention(), Attention::Ok);
    }

    #[test]
    fn attention_levels_are_ordered() {
        // Lets the dashboard sort by urgency with no ad hoc rule.
        assert!(Attention::Ok < Attention::Notice);
        assert!(Attention::Notice < Attention::Critical);
    }

    #[test]
    fn only_one_is_singular() {
        // 🔴 This inverts the French rule the function was first written for, where
        // zero takes the singular. In English "0 replica" reads as a bug.
        assert_eq!(plural(0, "replica", "replicas"), "0 replicas");
        assert_eq!(plural(1, "replica", "replicas"), "1 replica");
        assert_eq!(plural(2, "replica", "replicas"), "2 replicas");
        assert_eq!(plural(12, "copy", "copies"), "12 copies");
    }

    #[test]
    fn durations_read_at_a_glance() {
        assert_eq!(humanise(30), "30 s");
        assert_eq!(humanise(120), "2 min");
        assert_eq!(humanise(7200), "2 h");
        assert_eq!(humanise(172_800), "2 d");
        assert_eq!(humanise(5_184_000), "2 mo");
    }

    #[test]
    fn a_negative_age_does_not_lie() {
        // A clock skewed between nodes can give a negative age. Showing "0 s" would
        // suggest a backup taken just now.
        assert_eq!(humanise(-10), "in the future?");
    }

    #[test]
    fn a_refusal_is_not_a_failure() {
        let refusal = AuditItem {
            id: 1,
            at: "2026-08-16".into(),
            actor: "cli".into(),
            role: "operator".into(),
            action: "update".into(),
            target: "gitea".into(),
            outcome: "refused".into(),
            detail: None,
        };
        assert!(refusal.is_refusal());
        assert!(!refusal.is_failure());
    }

    #[test]
    fn rights_are_computed_from_the_single_matrix() {
        // 🔴 Re-deriving rights from the role name in the interface would make two
        // implementations of the same matrix diverge — and the divergence would go the
        // permissive way, which is a vulnerability, not a display defect.
        let u = Rights::for_role(hlb_types::Role::User);
        assert!(u.act_on_self);
        assert!(!u.read, "an ordinary user does not see the console");
        assert!(!u.sees_the_console());

        let v = Rights::for_role(hlb_types::Role::Viewer);
        assert!(v.read && v.sees_the_console());
        assert!(!v.operate);

        let o = Rights::for_role(hlb_types::Role::Operator);
        assert!(o.operate && o.publish);
        assert!(!o.destroy && !o.manage_accounts);

        let a = Rights::for_role(hlb_types::Role::Admin);
        assert!(a.destroy && a.manage_accounts);
    }

    #[test]
    fn a_service_token_is_shown_as_acting_for_nobody() {
        // The interface must hide "my mailbox", "my aliases": there is nobody behind a
        // service token, and offering those screens would lead to a 403.
        let m = Me {
            account: None,
            role: "admin".into(),
            role_label: "tout".into(),
            by_token: true,
            can: Rights::for_role(hlb_types::Role::Admin),
            mailboxes: Vec::new(),
        };
        assert!(m.account.is_none());
        assert!(m.by_token);
        assert!(m.mailboxes.is_empty());
    }

    #[test]
    fn the_default_brand_is_the_one_this_installation_was_made_for() {
        let m = Brand::default();
        assert_eq!(m.name, "Turi Industries");
        assert_eq!(m.product, "Homelabus");
        assert_eq!(m.initials(), "TI");
    }

    #[test]
    fn the_house_and_the_product_are_never_merged() {
        // "Turi Industries" runs "Homelabus". Confusing the two would make the page
        // unreadable to someone discovering the tool.
        let m = Brand::default();
        assert!(m.title().contains(&m.name));
        assert!(m.title().contains(&m.product));
        assert_ne!(m.name, m.product);
    }

    #[test]
    fn a_brand_never_carries_its_logo_in_every_response() {
        // A 256 KB image encoded into every response would be paid for on every poll,
        // by every screen. The type cannot represent it.
        let j = serde_json::to_string(&Brand::default()).expect("serialisable");
        assert!(!j.contains("base64"), "{j}");
        assert!(j.contains("\"logo\":false"), "{j}");
    }

    #[test]
    fn initials_survive_an_empty_or_odd_name() {
        let initials_of = |name: &str| {
            Brand {
                name: name.into(),
                ..Default::default()
            }
            .initials()
        };
        assert_eq!(initials_of(""), "?");
        assert_eq!(initials_of("---"), "?");
        assert_eq!(initials_of("ACME"), "A");
        assert_eq!(initials_of("Turi Industries"), "TI");
    }

    fn status(services: Vec<(ServiceState, &str)>) -> StatusPage {
        StatusPage {
            services: services
                .into_iter()
                .map(|(state, name)| ServiceStatus {
                    name: name.into(),
                    domain: None,
                    state,
                    uptime: Vec::new(),
                })
                .collect(),
            incidents: Vec::new(),
            public: false,
        }
    }

    #[test]
    fn a_planned_maintenance_is_not_an_outage() {
        // 🔴 It was planned, and saying so stops people looking for what is wrong.
        let p = status(vec![(ServiceState::Maintenance, "postgres")]);
        assert_eq!(p.attention(), Attention::Notice);
        assert_eq!(p.verdict(), StatusVerdict::AllOperational);

        let outage = status(vec![(ServiceState::Unavailable, "postgres")]);
        assert_eq!(outage.attention(), Attention::Critical);
        assert_eq!(outage.verdict(), StatusVerdict::Down { services: 1 });
    }

    #[test]
    fn an_open_incident_shows_even_when_every_service_answers() {
        // A service can answer and still misbehave: that is exactly what a declared
        // incident says, and what no probe would see.
        let mut p = status(vec![(ServiceState::Operational, "immich")]);
        assert_eq!(p.verdict(), StatusVerdict::AllOperational);

        p.incidents.push(Announcement {
            id: 1,
            title: "Lenteurs".into(),
            body: "x".into(),
            level: AnnouncementLevel::Incident,
            pinned: true,
            author: "lena".into(),
            published_at: "…".into(),
            expires_in_s: None,
            follow_ups: Vec::new(),
        });
        assert_eq!(p.attention(), Attention::Critical);
        assert_eq!(p.verdict(), StatusVerdict::Incidents { open: 1 });
    }

    #[test]
    fn nothing_exposed_is_never_all_operational() {
        assert_eq!(status(Vec::new()).verdict(), StatusVerdict::NothingExposed);
        // An open incident still comes first: it is news even with nothing exposed.
        let mut p = status(Vec::new());
        p.incidents.push(Announcement {
            id: 1,
            title: "Panne".into(),
            body: "x".into(),
            level: AnnouncementLevel::Incident,
            pinned: true,
            author: "lena".into(),
            published_at: "…".into(),
            expires_in_s: None,
            follow_ups: Vec::new(),
        });
        assert_eq!(p.verdict(), StatusVerdict::Incidents { open: 1 });
    }

    #[test]
    fn a_status_page_is_private_until_someone_decides_otherwise() {
        // 🔴 A public page reveals the list of what runs at your place and the calendar
        // of your outages. A choice, not a default.
        assert!(!status(Vec::new()).public);
    }

    fn announcement(level: AnnouncementLevel, expire: Option<i64>) -> Announcement {
        Announcement {
            id: 1,
            title: "Database maintenance".into(),
            body: "PostgreSQL restarts at 3 a.m.".into(),
            level,
            pinned: false,
            author: "lena".into(),
            published_at: "2026-08-18 10:00:00".into(),
            expires_in_s: expire,
            follow_ups: Vec::new(),
        }
    }

    #[test]
    fn an_incident_stays_open_until_someone_closes_it() {
        // 🔴 What makes an incident resolved is not its age, it is an update saying so.
        // Silence must not pass for a resolution.
        let open = announcement(AnnouncementLevel::Incident, None);
        assert!(open.open_incident());
        assert_eq!(open.level.attention(), Attention::Critical);

        let closed = announcement(AnnouncementLevel::Incident, Some(-60));
        assert!(!closed.open_incident(), "expired, therefore no longer open");
    }

    #[test]
    fn the_latest_update_is_what_people_read() {
        // An incident is FOLLOWED: the latest news is what counts, not the original
        // message — which often says "we are looking into it".
        let mut a = announcement(AnnouncementLevel::Incident, None);
        assert_eq!(a.last_update(), "PostgreSQL restarts at 3 a.m.");

        a.follow_ups.push(AnnouncementUpdate {
            body: "Cause found: disk full.".into(),
            author: "lena".into(),
            at: "11:00".into(),
        });
        a.follow_ups.push(AnnouncementUpdate {
            body: "Resolved.".into(),
            author: "lena".into(),
            at: "11:30".into(),
        });
        assert_eq!(a.last_update(), "Resolved.");
        // And the full chronology stays readable.
        assert_eq!(a.follow_ups.len(), 2);
    }

    #[test]
    fn an_unreadable_level_never_becomes_an_incident() {
        // ⚠️ The default is the LOWEST level: a corrupt column must not shout
        // "incident" on every screen.
        assert_eq!(
            AnnouncementLevel::parse("n'importe what"),
            AnnouncementLevel::Info
        );
        assert_eq!(
            AnnouncementLevel::parse("incident"),
            AnnouncementLevel::Incident
        );
    }

    #[test]
    fn a_permanent_announcement_never_expires() {
        assert!(announcement(AnnouncementLevel::Info, None).active());
        assert!(announcement(AnnouncementLevel::Info, Some(3600)).active());
        assert!(!announcement(AnnouncementLevel::Info, Some(-1)).active());
    }

    #[test]
    fn a_half_created_account_is_critical_not_a_notice() {
        // 🔴 Identity without a mailbox: the person signs in everywhere and their
        // address receives nothing. It only shows on the first lost email, often a
        // password reset — that is, at the worst moment.
        assert_eq!(
            AccountState::WithoutMailbox.attention(),
            Attention::Critical
        );
        assert_eq!(
            AccountState::WithoutIdentity.attention(),
            Attention::Critical
        );
        assert_eq!(AccountState::Complete.attention(), Attention::Ok);
    }

    #[test]
    fn a_broken_account_says_how_to_repair_it() {
        // Creation is resumable: rerunning finishes what is missing without destroying
        // what exists.
        assert!(AccountState::WithoutMailbox
            .remedy("lena")
            .is_some_and(|r| r.contains("hlb user add lena")));
        assert_eq!(AccountState::Complete.remedy("lena"), None);
    }

    #[test]
    fn a_multi_use_invitation_counts_down() {
        // Inviting a team meant one link per person. A five-use link does the same work
        // in one go — at the price of a leak five times as expensive.
        let mut i = InvitationSummary {
            reference: "a1".into(),
            created_by: "lena".into(),
            role: "standard".into(),
            expires_in_s: 3600,
            used_at: None,
            uses: 0,
            max_uses: 5,
            note: None,
        };
        assert_eq!(i.remaining(), 5);
        assert!(i.widely_open(), "five ways in, that must be visible");

        i.uses = 2;
        assert_eq!(i.state(), InvitationState::PartlyUsed);
        assert!(i.usable());

        i.uses = 5;
        assert!(!i.usable());
        assert_eq!(i.state(), InvitationState::Exhausted);
        assert_eq!(i.remaining(), 0);
        assert!(!i.widely_open());
    }

    #[test]
    fn a_partially_used_link_is_distinguishable_from_an_untouched_one() {
        // 🔴 A link already used AND still open is the one you forget to close.
        let mut i = InvitationSummary {
            reference: "a1".into(),
            created_by: "lena".into(),
            role: "standard".into(),
            expires_in_s: 3600,
            used_at: None,
            uses: 0,
            max_uses: 3,
            note: None,
        };
        assert_eq!(i.state(), InvitationState::Pending);
        i.uses = 1;
        assert_ne!(i.state(), InvitationState::Pending);
    }

    #[test]
    fn an_old_invitation_without_the_field_stays_single_use() {
        // ⚠️ Compatibility: an invitation serialised before the field was added must
        // not become unlimited. The default is the SAFE case.
        let j = r#"{"reference":"a1","created_by":"lena",
                    "role":"standard","expires_in_s":3600}"#;
        let i: InvitationSummary = serde_json::from_str(j).expect("relisible");
        assert_eq!(i.max_uses, 1);
        assert!(i.usable());
    }

    #[test]
    fn an_invitation_never_carries_its_value() {
        // 🔴 The guarantee is structural: the type has no field for the value, so it
        // cannot be leaked by accident.
        let i = InvitationSummary {
            reference: "a1b2c3d4".into(),
            created_by: "lena".into(),
            role: "standard".into(),
            expires_in_s: 3600,
            used_at: None,
            uses: 0,
            max_uses: 1,
            note: None,
        };
        let j = serde_json::to_string(&i).expect("serialisable");
        assert!(!j.contains("token"), "{j}");
        assert!(!j.contains("token"), "{j}");
        assert!(!j.contains("value"), "{j}");
    }

    #[test]
    fn a_used_invitation_can_never_serve_again() {
        // Single use: reusing it would create a second account with the same rights, in
        // the name of someone who asked for nothing.
        let mut i = InvitationSummary {
            reference: "a1".into(),
            created_by: "lena".into(),
            role: "standard".into(),
            expires_in_s: 3600,
            used_at: None,
            uses: 0,
            max_uses: 1,
            note: None,
        };
        assert!(i.usable());
        assert_eq!(i.state(), InvitationState::Pending);

        i.uses = 1;
        i.used_at = Some("2026-08-18".into());
        assert!(!i.usable());
        assert_eq!(i.state(), InvitationState::Exhausted);
    }

    #[test]
    fn an_expired_invitation_is_distinguishable_from_a_used_one() {
        // Both are unusable, but not for the same reason: one can be renewed, the other
        // has already been used.
        let i = InvitationSummary {
            reference: "a1".into(),
            created_by: "lena".into(),
            role: "standard".into(),
            expires_in_s: -60,
            used_at: None,
            uses: 0,
            max_uses: 1,
            note: None,
        };
        assert!(!i.usable());
        assert_eq!(i.state(), InvitationState::Expired);
    }

    fn action(applied: bool, steps: Vec<StepState>) -> ActionResult {
        ActionResult {
            applied,
            summary: "installer gitea".into(),
            steps: steps
                .into_iter()
                .map(|state| ActionStep {
                    description: "faire quelque chose".into(),
                    state,
                    error: None,
                })
                .collect(),
            cli_command: "hlb install gitea --apply".into(),
            blockers: Vec::new(),
            warnings: Vec::new(),
            confirmation_required: None,
        }
    }

    #[test]
    fn a_warning_never_blocks_a_legitimate_action() {
        // 🔴 "This link will let five people in" is a legitimate choice you want to see
        // before making it — not a refusal. Filing a warning among the blockers would
        // make the action impossible.
        let mut a = action(false, vec![StepState::Planned]);
        a.warnings.push("cinq personnes pourront entrer".into());
        assert!(a.applicable(), "a warning blocked the action");

        a.blockers.push("the DNS record does not exist".into());
        assert!(!a.applicable(), "a real blocker must prevent it");
    }

    #[test]
    fn a_preview_never_looks_like_a_completed_action() {
        // 🔴 The most expensive confusion possible on a screen that triggers actions:
        // believing it is done when it is a preview.
        let a = action(false, vec![StepState::Planned, StepState::Planned]);
        assert!(!a.succeeded());
        assert!(
            a.verdict().contains("nothing was changed"),
            "{}",
            a.verdict()
        );
    }

    #[test]
    fn an_unimplemented_step_is_never_a_success() {
        // 🔴 "The plan ran without error" and "the app is installed" are not the same
        // thing. We never claim to have provisioned a database.
        let a = action(true, vec![StepState::Done, StepState::Unimplemented]);
        assert!(!a.succeeded(), "an unimplemented step is not a success");
        assert!(a.verdict().contains("INCOMPLETE"), "{}", a.verdict());
        // And above all: no error, so nothing would signal it without this message.
        assert!(!a.verdict().contains("failed"));
    }

    #[test]
    fn a_fully_applied_action_says_what_it_did() {
        let a = action(true, vec![StepState::Done, StepState::Done]);
        assert!(a.succeeded());
        assert_eq!(a.verdict(), "installer gitea");
    }

    #[test]
    fn a_failure_stops_the_verdict_from_being_positive() {
        let a = action(true, vec![StepState::Done, StepState::Failed]);
        assert!(!a.succeeded());
        assert!(a.verdict().contains("failed"), "{}", a.verdict());
    }

    #[test]
    fn blockers_prevent_application() {
        let mut a = action(false, vec![StepState::Planned]);
        assert!(a.applicable());
        a.blockers
            .push("the DNS record for git.example.fr does not exist".into());
        assert!(!a.applicable(), "a blocking guide must prevent applying");
    }

    #[test]
    fn every_action_carries_its_cli_equivalent() {
        // The CLI stays the source of truth: the interface teaches it rather than
        // replacing it, and the action stays reproducible.
        let a = action(false, Vec::new());
        assert!(a.cli_command.starts_with("hlb "), "{}", a.cli_command);
        assert!(a.cli_command.contains("--apply"));
    }

    fn topo(violations: Vec<ViolationSummary>, domains: Vec<DomainSummary>) -> Topology {
        let total_nodes = domains.iter().map(|d| d.nodes.len()).sum();
        Topology {
            managers: Vec::new(),
            domains,
            violations,
            total_nodes,
        }
    }

    fn domain(name: Option<&str>, n: usize, concentrated: bool) -> DomainSummary {
        DomainSummary {
            name: name.map(str::to_string),
            nodes: (0..n)
                .map(|i| NodeInDomain {
                    id: format!("n{i}"),
                    hostname: format!("h{i}"),
                    tier: None,
                    reachable: true,
                    services: Vec::new(),
                })
                .collect(),
            concentrated,
        }
    }

    #[test]
    fn an_illusory_redundancy_is_the_worst_verdict() {
        // 🔴 Every replica on the same hardware: the service LOOKS redundant. That is
        // exactly what the command line does not show.
        let t = topo(
            vec![ViolationSummary {
                service: "gitea".into(),
                domain: Some("big-01".into()),
                replicas: 2,
                total: 2,
                total_violation: true,
                explanation: "…".into(),
            }],
            vec![domain(Some("big-01"), 2, false)],
        );
        assert_eq!(t.attention(), Attention::Critical);
        assert_eq!(
            t.verdict(),
            TopologyVerdict::RedundancyIllusion { services: 1 }
        );
    }

    #[test]
    fn a_concentrated_domain_is_flagged_even_without_violations() {
        // No badly spread service, and yet: two nodes out of three on one machine,
        // losing it takes the quorum.
        let t = topo(
            Vec::new(),
            vec![
                domain(Some("big-01"), 2, true),
                domain(Some("small"), 1, false),
            ],
        );
        assert_eq!(t.attention(), Attention::Notice);
        assert_eq!(
            t.verdict(),
            TopologyVerdict::Concentrated {
                nodes: 2,
                total: 3,
                domain: Some("big-01".into()),
            }
        );
    }

    #[test]
    fn undeclared_domains_are_said_to_be_unknown_not_fine() {
        // ⚠️ Staying quiet would suggest a verified spread that has not been verified.
        let t = topo(Vec::new(), vec![domain(None, 2, false)]);
        assert_eq!(t.verdict(), TopologyVerdict::SpreadUnknown);
    }

    #[test]
    fn no_machine_known_is_not_a_spread_cluster() {
        // 🔴 With no domain at all, "every domain is declared and none is concentrated"
        // holds by vacuity: an installation with no machine answered "spread across
        // several failure domains — fine".
        let t = topo(Vec::new(), Vec::new());
        assert_eq!(t.verdict(), TopologyVerdict::NoMachine);
        assert_eq!(t.attention(), Attention::Notice);
    }

    #[test]
    fn a_properly_spread_cluster_says_so_plainly() {
        let t = topo(
            Vec::new(),
            vec![domain(Some("a"), 1, false), domain(Some("b"), 1, false)],
        );
        assert_eq!(t.attention(), Attention::Ok);
        assert_eq!(t.verdict(), TopologyVerdict::Spread);
    }

    fn task(state: &str, desired: &str) -> TaskSummary {
        TaskSummary {
            id: "t".into(),
            service: "gitea".into(),
            slot: Some(1),
            node: Some("n1".into()),
            state: state.into(),
            desired_state: desired.into(),
            alive: state == "running" && desired == "running",
            failed: matches!(state, "failed" | "rejected" | "orphaned"),
            explanation: None,
            image: None,
        }
    }

    fn detail(tasks: Vec<TaskSummary>) -> AppDetail {
        AppDetail {
            catalog_changes: Vec::new(),
            assertions: Vec::new(),
            jobs: Vec::new(),
            diagnostic: None,
            restorability: None,
            summary: AppSummary {
                name: "gitea".into(),
                status: "running".into(),
                image: "gitea/gitea:1.24".into(),
                domain: None,
                last_backup_secs: Some(60),
                holds_data: true,
                last_verification_secs: None,
                blocking_guides: 0,
            },
            tasks,
            capabilities: Vec::new(),
            volumes: Vec::new(),
            env: Vec::new(),
            guides: Vec::new(),
            coverage: None,
            backups: Vec::new(),
            journal: Vec::new(),
            image: None,
            domain: None,
            manifest: None,
        }
    }

    #[test]
    fn dead_task_history_never_inflates_the_replica_count() {
        // 🔴 Swarm keeps the history of dead tasks. Counting every task would give
        // "2/9 replicas" after a few redeploys, and you would go looking for seven
        // replicas nobody ever asked for.
        let d = detail(vec![
            task("running", "running"),
            task("running", "running"),
            task("shutdown", "shutdown"),
            task("shutdown", "shutdown"),
            task("failed", "shutdown"),
        ]);
        assert_eq!(d.replicas(), (2, 2));
    }

    #[test]
    fn a_partially_deployed_app_shows_the_gap() {
        // Two replicas wanted, one standing: this is the "partial" case, and the
        // number must show it.
        let d = detail(vec![task("running", "running"), task("pending", "running")]);
        assert_eq!(d.replicas(), (1, 2));
    }

    #[test]
    fn failures_are_reachable_because_they_explain_the_colour() {
        // Hiding them would leave a "partial" service with no explanation at all.
        let mut failed = task("failed", "running");
        failed.explanation = Some("no suitable node (insufficient memory)".into());
        let d = detail(vec![task("running", "running"), failed]);

        let e = d.failures();
        assert_eq!(e.len(), 1);
        assert!(e[0].explanation.as_deref().unwrap_or("").contains("memory"));
    }

    fn node(reachable: bool) -> NodeSummary {
        NodeSummary {
            address: "10.0.0.1:8421".into(),
            hostname: Some("n1".into()),
            reachable,
            detail: None,
            report_age_s: Some(30),
            cpu_busy: Some(0.4),
            load_per_core: Some(0.5),
            memory_used: Some(0.6),
            swap_used: Some(0.0),
            disks: Vec::new(),
            uptime_s: Some(3600),
            distro: None,
            kernel: None,
            agent_version: Some("0.2.0".into()),
            protocol: Some(2),
            tasks: Vec::new(),
            reboot_pending: None,
        }
    }

    #[test]
    fn an_unreachable_node_is_never_a_healthy_one() {
        // 🔴 "No problem reported" is the worst possible display for a node you know
        // nothing about: its data is no longer being backed up.
        let mut n = node(false);
        n.detail = Some("connection refused".into());
        assert_eq!(n.attention(), Attention::Critical);
        assert_eq!(n.problem(), Some(NodeProblem::Unreachable));
        // What failed must reach the interface, which states the consequence: the
        // node's own `detail`, beside the decision.
        let v = serde_json::to_value(&n).expect("serialise");
        assert_eq!(v["problem"]["kind"], "unreachable", "{v}");
        assert_eq!(v["detail"], "connection refused", "{v}");
    }

    #[test]
    fn a_saturated_disk_outweighs_everything_else() {
        let mut n = node(true);
        n.disks = vec![
            DiskSummary {
                path: "/".into(),
                used: 0.30,
                total_mb: 100_000,
                free_mb: 70_000,
                pressure: 0,
            },
            DiskSummary {
                path: "/var/lib/docker".into(),
                used: 0.96,
                total_mb: 50_000,
                free_mb: 2_000,
                pressure: 4,
            },
        ];
        assert_eq!(n.attention(), Attention::Critical);
        assert_eq!(
            n.problem(),
            Some(NodeProblem::DiskFull {
                path: "/var/lib/docker".into(),
                used: 0.96,
            }),
            "the WORST disk decides"
        );
    }

    #[test]
    fn swapping_and_load_are_notices_not_failures() {
        // The machine slows without having fallen over: it must be visible, without shouting.
        let mut n = node(true);
        n.swap_used = Some(0.7);
        assert_eq!(n.attention(), Attention::Notice);
        assert_eq!(n.problem(), Some(NodeProblem::Swapping));

        let mut n = node(true);
        n.load_per_core = Some(1.5);
        assert_eq!(n.attention(), Attention::Notice);
    }

    #[test]
    fn a_healthy_node_says_nothing() {
        // "Nothing green needs to be loud": a healthy node has no sentence.
        assert_eq!(node(true).attention(), Attention::Ok);
        assert_eq!(node(true).problem(), None);
    }

    #[test]
    fn never_backed_up_reads_differently_from_stale() {
        // 🔴 Seen on screen: "NO up-to-date copy" next to two destinations showing
        // "1 d" reads as a contradiction, and you doubt the whole screen. Yet these are
        // two different situations, repaired differently.
        let never = CoverageSummary {
            app: "seafile".into(),
            per_destination: vec![("nas".into(), None), ("offsite".into(), None)],
            up_to_date_copies: 0,
        };
        let stale = CoverageSummary {
            app: "vikunja".into(),
            per_destination: vec![
                ("nas".into(), Some(108_000)),
                ("offsite".into(), Some(111_600)),
            ],
            up_to_date_copies: 0,
        };

        assert!(never.never_backed_up());
        assert!(!never.all_stale());
        assert_eq!(never.coverage(), Coverage::NeverBackedUp);

        assert!(stale.all_stale());
        assert!(!stale.never_backed_up());
        assert_eq!(
            stale.coverage(),
            Coverage::NoFreshCopy { destinations: 2 },
            "copies exist and are too old — the apparent contradiction, explained"
        );
    }

    #[test]
    fn no_destination_at_all_says_so() {
        // "No copy" with no destination configured sends you looking for a failure
        // where there is only a configuration to do.
        let nothing = CoverageSummary {
            app: "neuve".into(),
            per_destination: Vec::new(),
            up_to_date_copies: 0,
        };
        assert_eq!(nothing.coverage(), Coverage::NoDestination);
    }

    #[test]
    fn one_copy_is_not_three_two_one() {
        // 🔴 The number of DECLARED destinations says nothing about the number of copies.
        let c = CoverageSummary {
            app: "immich".into(),
            per_destination: vec![("nas".into(), Some(7200)), ("offsite".into(), None)],
            up_to_date_copies: 1,
        };
        assert_eq!(c.attention(), Attention::Notice);
        assert_eq!(c.coverage(), Coverage::OneFreshCopy { destinations: 2 });

        let zero = CoverageSummary {
            app: "seafile".into(),
            per_destination: vec![("nas".into(), None)],
            up_to_date_copies: 0,
        };
        assert_eq!(zero.attention(), Attention::Critical);
        // The verdict names the exact situation: here nothing has ever been backed up.
        assert_eq!(zero.coverage(), Coverage::NeverBackedUp);
    }

    fn alert(level: AlertLevel) -> ActiveAlert {
        ActiveAlert {
            rule: "backup-absent".into(),
            level,
            explanation: "an app has never been backed up".into(),
            value: Some(1.0),
            threshold: 0.0,
            since_s: 3_600,
            muted_until: None,
            muted_by: None,
            mute_reason: None,
        }
    }

    #[test]
    fn a_silenced_alert_never_looks_resolved() {
        // 🔴 Making it disappear would be the same error as showing stale data as
        // fresh: absent information disguised as reassuring information.
        let mut a = alert(AlertLevel::Critical);
        a.muted_until = Some(10_000);
        a.muted_by = Some("lena".into());
        a.mute_reason = Some("purge under way".into());

        assert_eq!(
            a.mute(5_000),
            Some(Mute {
                remaining_s: 5_000,
                by: Some("lena".into()),
                reason: Some("purge under way".into()),
            }),
            "who muted it, and for how long, must reach the interface"
        );

        // Downgraded, never switched off: a mute says "I know", not "it is fixed".
        assert_eq!(a.attention(5_000), Attention::Notice);
        assert_ne!(a.attention(5_000), Attention::Ok);
    }

    #[test]
    fn a_silence_expires_and_the_alert_comes_back() {
        // A mute with no deadline would be a disguised deletion.
        let mut a = alert(AlertLevel::Critical);
        a.muted_until = Some(10_000);

        assert!(a.is_muted(9_999));
        assert!(!a.is_muted(10_001));
        assert_eq!(
            a.attention(10_001),
            Attention::Critical,
            "it comes back whole"
        );
    }

    #[test]
    fn not_being_able_to_evaluate_is_not_fine() {
        // 🔴 "No data" is not "all is well": collection may have died, and this watch
        // has been blind since.
        assert_eq!(AlertLevel::Unknown.attention(), Attention::Notice);
        assert_ne!(AlertLevel::Unknown.attention(), Attention::Ok);
    }

    #[test]
    fn alert_levels_are_ordered_for_sorting() {
        assert!(AlertLevel::Info < AlertLevel::Important);
        assert!(AlertLevel::Important < AlertLevel::Critical);
    }

    #[test]
    fn an_unavailable_series_is_never_an_empty_one() {
        // 🔴 An empty series draws as a flat line at zero, which reads as "all is
        // calm" — the exact opposite of "I have no data".
        let absent = Series::Unavailable {
            reason: "VictoriaMetrics unreachable".into(),
        };
        assert_eq!(absent.points(), None);
        assert_eq!(absent.last(), None);
        assert!(absent.unavailable().is_some());

        let empty = Series::Points {
            name: "x".into(),
            points: Vec::new(),
            unit: Unit::Ratio,
        };
        // Even a series of zero or one point must refuse to be drawn.
        assert!(empty.unavailable().is_some());
    }

    #[test]
    fn a_real_series_is_drawable() {
        let s = Series::Points {
            name: "hlb_cpu_used_ratio".into(),
            points: vec![(100, 0.4), (160, 0.6)],
            unit: Unit::Ratio,
        };
        assert_eq!(s.unavailable(), None);
        assert_eq!(s.last(), Some(0.6));
        assert_eq!(s.points().map(|p| p.len()), Some(2));
    }

    #[test]
    fn units_read_the_way_a_human_expects() {
        assert_eq!(Unit::Ratio.show(0.415), "42 %");
        assert_eq!(Unit::Count.show(3.0), "3", "not \"3.0 applications\"");
        assert_eq!(Unit::Bytes.show(512.0), "512 B");
        assert_eq!(Unit::Bytes.show(1536.0), "1.5 KiB");
        assert_eq!(Unit::Bytes.show(5.0 * 1024.0 * 1024.0 * 1024.0), "5.0 GiB");
        assert_eq!(Unit::BytesPerSecond.show(2048.0), "2.0 KiB/s");
        assert_eq!(Unit::Seconds.show(7200.0), "2 h");
    }

    #[test]
    fn a_series_survives_a_json_roundtrip() {
        // The server-to-interface contract: a mislabelled variant would silently break
        // chart rendering.
        for s in [
            Series::Points {
                name: "x".into(),
                points: vec![(1, 2.0)],
                unit: Unit::Bytes,
            },
            Series::Unavailable {
                reason: "absent".into(),
            },
        ] {
            let j = serde_json::to_string(&s).expect("serialisable");
            let reread: Series = serde_json::from_str(&j).expect("relisible");
            assert_eq!(reread, s, "{j}");
        }
    }

    #[test]
    fn a_secret_has_no_field_for_its_value() {
        // 🔴 The guarantee is structural: you cannot leak what you cannot represent.
        let s = SecretItem {
            name: "restic-repo-password".into(),
            purpose: "repository encryption".into(),
        };
        let j = serde_json::to_string(&s).expect("serialisable");
        assert!(!j.contains("value"), "{j}");
        assert!(!j.to_lowercase().contains("secret\":"), "{j}");
    }

    fn volume(backup: bool, sqlite: bool, tier: hlb_types::StorageTier) -> hlb_types::Capability {
        hlb_types::Capability::Storage {
            name: "data".into(),
            path: "/data".into(),
            tier,
            backup,
            sqlite,
            copy: hlb_types::VolumeCopy::Live,
            owner: None,
        }
    }

    #[test]
    fn a_need_names_what_the_manifest_left_to_the_app_name() {
        // "<app name>" was what the catalogue showed: the reader had to know the rule.
        let db = hlb_types::Capability::Database {
            engine: hlb_types::DbEngine::Postgres,
            name: None,
            extensions: vec!["vector".into()],
            connections: Some(21),
        };
        let bucket = hlb_types::Capability::ObjectStorage {
            bucket: None,
            backup: true,
            expire_after_days: None,
        };
        assert_eq!(
            Need::of(&db, "immich"),
            Need::Database {
                engine: "postgres".into(),
                name: "immich".into(),
                extensions: vec!["vector".into()],
                connections: Some(21),
            }
        );
        assert_eq!(
            Need::of(&bucket, "immich"),
            Need::Bucket {
                name: "immich".into(),
                backed_up: false,
            }
        );
    }

    #[test]
    fn every_field_that_carries_meaning_reaches_the_need() {
        use hlb_types::{Capability as C, SsoMode, StorageTier};
        // 🔴 `mode: none` is a deliberate exclusion: read as another mode, it once gave
        // an app an OIDC client with empty URIs.
        let sso = |mode| C::Sso {
            mode,
            redirect_paths: vec!["/cb".into()],
        };
        let modes = [
            SsoMode::Native,
            SsoMode::ProxyHeader,
            SsoMode::ProxyOnly,
            SsoMode::None,
        ]
        .map(|m| Need::of(&sso(m), "a"));
        for (i, a) in modes.iter().enumerate() {
            for b in &modes[i + 1..] {
                assert_ne!(a, b);
            }
        }

        let base = Need::of(&volume(true, false, StorageTier::Local), "a");
        for changed in [
            volume(false, false, StorageTier::Local),
            volume(true, true, StorageTier::Local),
            volume(true, false, StorageTier::Nfs),
        ] {
            assert_ne!(Need::of(&changed, "a"), base, "{changed:?}");
        }

        let mailbox = |quota_bytes, aliases| C::MailAccount {
            quota_bytes,
            aliases,
        };
        let plain = Need::of(&mailbox(None, false), "a");
        assert_ne!(Need::of(&mailbox(Some(5), false), "a"), plain);
        assert_ne!(Need::of(&mailbox(None, true), "a"), plain);

        let cache = |dedicated| C::Cache {
            engine: hlb_types::CacheEngine::Valkey,
            dedicated,
        };
        assert_ne!(Need::of(&cache(true), "a"), Need::of(&cache(false), "a"));
    }

    /// Every `HomeWidget`, read from its schema rather than listed.
    fn every_widget() -> Vec<HomeWidget> {
        let schema =
            serde_json::to_value(<HomeWidget as utoipa::PartialSchema>::schema()).expect("schema");
        let names = schema["enum"].as_array().expect("an enum").clone();
        assert!(names.len() >= 15, "the walk found {} widgets", names.len());
        names
            .into_iter()
            .map(|n| serde_json::from_value(n).expect("a widget"))
            .collect()
    }

    #[test]
    fn every_widget_is_offered() {
        // `ALL` is written out: the schema, walked, says whether it is whole.
        let mut all = HomeWidget::ALL.to_vec();
        let mut walked = every_widget();
        let key = |w: &HomeWidget| format!("{w:?}");
        all.sort_by_key(key);
        walked.sort_by_key(key);
        assert_eq!(all, walked);
    }

    #[test]
    fn every_widget_is_added_at_a_size_the_grid_holds() {
        for w in every_widget() {
            assert!(w.tile().fits(), "{w:?} is added at {:?}", w.tile());
        }
    }

    #[test]
    fn the_default_home_fills_a_wide_screen_exactly() {
        let tiles = HomeTile::DEFAULT;
        assert!(tiles.iter().all(HomeTile::fits));
        for (i, t) in tiles.iter().enumerate() {
            assert!(
                !tiles[..i].iter().any(|u| u.widget == t.widget),
                "{:?} twice",
                t.widget
            );
        }
        // Four columns by three rows: nothing has to grow to close a gap.
        let area: u32 = tiles.iter().map(|t| u32::from(t.w) * u32::from(t.h)).sum();
        assert_eq!(area, u32::from(TILE_W_MAX) * 3);
        assert!(
            tiles.iter().any(|t| t.widget == HomeWidget::Problems),
            "every problem is on it"
        );
    }

    #[test]
    fn every_metric_is_recorded() {
        // `ALL` is written out: the schema, walked, says whether it is whole.
        let schema =
            serde_json::to_value(<Metric as utoipa::PartialSchema>::schema()).expect("schema");
        let mut walked: Vec<Metric> = schema["enum"]
            .as_array()
            .expect("an enum")
            .iter()
            .map(|n| serde_json::from_value(n.clone()).expect("a metric"))
            .collect();
        assert!(walked.len() >= 8, "the walk found {}", walked.len());
        let mut all = Metric::ALL.to_vec();
        let key = |m: &Metric| format!("{m:?}");
        all.sort_by_key(key);
        walked.sort_by_key(key);
        assert_eq!(all, walked);
        // Two metrics under one key would read each other's points.
        let mut keys: Vec<&str> = Metric::ALL.iter().map(|m| m.key()).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), Metric::ALL.len());
    }
}
