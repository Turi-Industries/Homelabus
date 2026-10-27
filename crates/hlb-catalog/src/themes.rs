//! Themes an installation declares in files, rather than in Rust.
//!
//! One YAML file per theme in a directory beside the catalog. The controller loads them
//! at startup and serves them; the interface offers them next to the three shipped ones.
//!
//! ## Why files, and why here
//!
//! The same reasoning that moved application icons into `catalog/<app>/`: data belongs
//! with data. A theme in a file is versionable, diffable, editable by someone who does
//! not write Rust, and it needs no migration, no write endpoint and no authentication
//! path to exist.
//!
//! It lives in this crate rather than in `hlb-api` because `hlb-api` does no I/O: it is
//! the wire types and the rules computed on them, checkable in a test with no disk. The
//! TYPE and every rule about its content are there; reading files is here, beside the
//! catalog loader that already does the same for manifests.
//!
//! ## One bad file never costs you the others
//!
//! A theme that will not parse is refused BY NAME and the rest still load — the same
//! rule the catalog itself follows, and the same reason: an installation should not lose
//! its whole appearance to one typo.

use std::path::{Path, PathBuf};

use hlb_api::CustomTheme;

/// A file that could not become a theme, and why.
#[derive(Debug, Clone, PartialEq)]
pub struct Refused {
    pub file: PathBuf,
    pub reason: String,
}

/// What a directory yielded.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Loaded {
    pub themes: Vec<CustomTheme>,
    /// 🔴 Reported, never swallowed. A theme silently missing from Settings is
    /// indistinguishable from one nobody wrote, and you go looking for the wrong thing.
    pub refused: Vec<Refused>,
}

/// Reads every `*.yaml` in `dir`.
///
/// An absent directory is not an error: most installations declare no theme at all, and
/// saying "no such directory" at every startup would train people to ignore the log.
pub fn load(dir: &Path) -> Loaded {
    let mut out = Loaded::default();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };

    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml" || e == "yml"))
        .collect();
    // Sorted, so the "a name is already taken" refusal below always names the same file
    // of a colliding pair, whatever order the filesystem happened to hand them over in.
    files.sort();

    for file in files {
        let text = match std::fs::read_to_string(&file) {
            Ok(t) => t,
            Err(e) => {
                out.refused.push(Refused {
                    file,
                    reason: e.to_string(),
                });
                continue;
            }
        };
        let theme: CustomTheme = match serde_yaml_ng::from_str(&text) {
            Ok(t) => t,
            Err(e) => {
                out.refused.push(Refused {
                    file,
                    reason: e.to_string(),
                });
                continue;
            }
        };
        let mut problems = theme.problems();
        // 🔴 The one check `hlb_api` cannot make, having no filesystem. A theme naming a
        // face that is not there would load, be offered in Settings, and then draw in
        // the project's font with nothing anywhere saying why — the silent failure this
        // loader exists to turn into a named refusal.
        for family in hlb_api::FontFamilyKind::all() {
            let Some(face) = theme.face(family) else {
                continue;
            };
            if hlb_api::CustomTheme::face_problem(face).is_some() {
                // Already reported by `problems()`, with the reason. Looking for the
                // file of a name that is not a file name would only add noise.
                continue;
            }
            let beside = dir.join(face);
            if !beside.is_file() {
                problems.push(format!(
                    "{}: \"{face}\" is not a file in {} — a face that is not there \
                     draws as the project's own, silently",
                    family.as_str(),
                    dir.display()
                ));
            }
        }
        if !problems.is_empty() {
            out.refused.push(Refused {
                file,
                reason: problems.join("; "),
            });
            continue;
        }
        if out
            .themes
            .iter()
            .any(|t| t.name.eq_ignore_ascii_case(&theme.name))
        {
            out.refused.push(Refused {
                file,
                reason: format!(
                    "the name \"{}\" is already taken by another file — two themes with \
                     one name means whichever loaded first wins, silently",
                    theme.name
                ),
            });
            continue;
        }
        out.themes.push(theme);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).expect("write");
    }

    /// A complete, valid theme — the shape the documentation promises.
    fn valid(name: &str) -> String {
        format!(
            "name: {name}\nbase: dark\nbackground: \"#0F1216\"\nsurface: \"#171B21\"\n\
             raised_surface: \"#1E242B\"\nborder: \"#2A323B\"\ntext: \"#E6EAEF\"\n\
             muted_text: \"#96A1AD\"\naccent: \"#7B8CFF\"\non_accent: \"#0F1216\"\n\
             ok: \"#38C7B4\"\nattention: \"#FFC94D\"\ncritical: \"#F05C5C\"\n\
             info: \"#7EA4F8\"\n"
        )
    }

    #[test]
    fn an_absent_directory_yields_nothing_and_complains_about_nothing() {
        let got = load(Path::new("/nonexistent/themes"));
        assert_eq!(got, Loaded::default());
    }

    #[test]
    fn a_valid_theme_loads() {
        let d = tempfile::tempdir().expect("tmp");
        write(d.path(), "maison.yaml", &valid("Maison"));
        let got = load(d.path());
        assert_eq!(got.refused, vec![]);
        assert_eq!(got.themes.len(), 1);
        assert_eq!(got.themes[0].name, "Maison");
    }

    #[test]
    fn the_example_theme_in_the_repository_loads() {
        // 🔴 The example IS the documentation of the format. One the loader refuses
        // teaches the format and then fails on the first copy someone makes of it.
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes");
        let got = load(&dir);
        assert_eq!(got.refused, vec![]);
        assert!(
            got.themes.iter().any(|t| t.name == "Ardoise"),
            "{:?}",
            got.themes
        );
    }

    #[test]
    fn an_illegible_theme_is_refused_by_name() {
        // Well formed, and "ok" and "attention" are the same yellow-green: every alert on
        // the dashboard would read as fine. Refused here, before anyone's screen.
        let d = tempfile::tempdir().expect("tmp");
        let body = valid("Pastel")
            .replace("ok: \"#38C7B4\"", "ok: \"#7E9935\"")
            .replace("attention: \"#FFC94D\"", "attention: \"#7E9935\"");
        write(d.path(), "pastel.yaml", &body);
        let got = load(d.path());
        assert_eq!(got.themes, vec![]);
        let reason = &got.refused[0].reason;
        assert!(
            reason.contains("\"ok\" and \"attention\" merge"),
            "{reason}"
        );
    }

    /// 🔴 The whole point of refusing per file rather than per directory.
    #[test]
    fn one_broken_file_never_costs_the_others() {
        let d = tempfile::tempdir().expect("tmp");
        write(d.path(), "good.yaml", &valid("Maison"));
        write(d.path(), "broken.yaml", "name: Cassé\nbase: dark\n");
        let got = load(d.path());
        assert_eq!(got.themes.len(), 1, "the valid one must still load");
        assert_eq!(got.refused.len(), 1);
        assert!(got.refused[0].file.ends_with("broken.yaml"));
    }

    #[test]
    fn a_typo_in_a_key_is_refused_with_the_key_named() {
        let d = tempfile::tempdir().expect("tmp");
        // `accant` for `accent` — `deny_unknown_fields` is what catches it.
        write(
            d.path(),
            "typo.yaml",
            &valid("Maison").replace("accent:", "accant:"),
        );
        let got = load(d.path());
        assert!(got.themes.is_empty());
        assert!(
            got.refused[0].reason.contains("accant"),
            "the message must name the offending key: {}",
            got.refused[0].reason
        );
    }

    #[test]
    fn a_colour_that_is_not_a_colour_is_refused_by_field() {
        let d = tempfile::tempdir().expect("tmp");
        write(
            d.path(),
            "bad.yaml",
            &valid("Maison").replace("\"#F05C5C\"", "red"),
        );
        let got = load(d.path());
        assert!(got.themes.is_empty());
        assert!(
            got.refused[0].reason.contains("critical"),
            "{}",
            got.refused[0].reason
        );
    }

    /// 🔴 Every problem at once: this file is edited by hand, and being told about one
    /// mistake per reload is how people give up.
    #[test]
    fn every_problem_is_reported_together() {
        let d = tempfile::tempdir().expect("tmp");
        write(
            d.path(),
            "bad.yaml",
            &valid("Maison")
                .replace("base: dark", "base: sombre")
                .replace("\"#F05C5C\"", "red")
                .replace("\"#38C7B4\"", "green"),
        );
        let got = load(d.path());
        let r = &got.refused[0].reason;
        for expected in ["base", "critical", "ok"] {
            assert!(r.contains(expected), "{expected} missing from: {r}");
        }
    }

    #[test]
    fn a_file_may_not_shadow_a_shipped_theme() {
        let d = tempfile::tempdir().expect("tmp");
        write(d.path(), "x.yaml", &valid("Dark"));
        let got = load(d.path());
        assert!(got.themes.is_empty());
        assert!(got.refused[0].reason.contains("shipped"));
    }

    #[test]
    fn a_theme_may_name_a_face_that_is_there() {
        let d = tempfile::tempdir().expect("tmp");
        std::fs::write(d.path().join("Inter-Regular.ttf"), b"not really a font").expect("write");
        write(
            d.path(),
            "maison.yaml",
            &format!(
                "{}typeface: Inter-Regular.ttf\nscale: 1.1\n",
                valid("Maison")
            ),
        );
        let got = load(d.path());
        assert_eq!(got.refused, vec![]);
        assert_eq!(got.themes[0].typeface.as_deref(), Some("Inter-Regular.ttf"));
        assert_eq!(got.themes[0].scale, Some(1.1));
        // ⚠️ The BYTES are not checked here, deliberately: parsing a font would put a
        // font parser in the controller for a check the interface already survives —
        // `typeface::install` is arranged so a face that never arrives changes how text
        // looks and nothing about what it says.
    }

    #[test]
    fn a_face_that_is_not_beside_the_theme_is_refused_by_name() {
        // 🔴 The failure this catches is silence: the theme would load, be offered, and
        // draw in the project's font with nothing saying the file was missing.
        let d = tempfile::tempdir().expect("tmp");
        write(
            d.path(),
            "maison.yaml",
            &format!("{}typeface: Absent.ttf\n", valid("Maison")),
        );
        let got = load(d.path());
        assert!(got.themes.is_empty());
        assert!(
            got.refused[0].reason.contains("Absent.ttf"),
            "{}",
            got.refused[0].reason
        );
    }

    #[test]
    fn a_face_that_is_a_path_is_refused_before_anything_looks_for_it() {
        // The appearance API serves these files. A name with a separator in it would be
        // a way of reading the disk through it.
        let d = tempfile::tempdir().expect("tmp");
        write(
            d.path(),
            "maison.yaml",
            &format!("{}typeface_mono: ../../etc/passwd.ttf\n", valid("Maison")),
        );
        let got = load(d.path());
        assert!(got.themes.is_empty());
        assert!(
            got.refused[0].reason.contains("is a path"),
            "{}",
            got.refused[0].reason
        );
    }

    #[test]
    fn a_scale_outside_the_slider_is_refused() {
        // A theme at 4.0 leaves an interface too large to reach the control that would
        // undo it — the two factors multiply.
        let d = tempfile::tempdir().expect("tmp");
        write(
            d.path(),
            "maison.yaml",
            &format!("{}scale: 4.0\n", valid("Maison")),
        );
        let got = load(d.path());
        assert!(got.themes.is_empty());
        assert!(
            got.refused[0].reason.contains("scale is 4"),
            "{}",
            got.refused[0].reason
        );
    }

    /// Two files, one name: whichever loaded first would win and nothing would say so.
    #[test]
    fn two_files_may_not_claim_one_name() {
        let d = tempfile::tempdir().expect("tmp");
        write(d.path(), "a.yaml", &valid("Maison"));
        write(d.path(), "b.yaml", &valid("maison"));
        let got = load(d.path());
        assert_eq!(got.themes.len(), 1);
        assert_eq!(got.refused.len(), 1);
        assert!(got.refused[0].reason.contains("already taken"));
    }
}
