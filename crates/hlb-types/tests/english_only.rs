//! The project is written in English — its names, its stored values, its comments —
//! and this is what keeps it so. It also holds the source scans that are not about
//! language: lost line continuations, code after a test module, the walk's own floor.
//!
//! ## Why this exists
//!
//! The code was first written in French and translated. Each sweep was declared
//! finished and was not: the second found ~250 identifiers the first had missed, and
//! fifteen comments survived every pass over the names, because nothing read comments.
//! The suite was green before and after each time — nothing was watching.
//!
//! ## What it can and cannot do
//!
//! ⚠️ **A list only catches what it names.** This is not a language detector: the words
//! it refuses are in `data/non-english-words.txt`, and a word that is not there passes.
//! When one gets past, add it to the file — that is how the list earns its keep, and
//! why it is not presented as complete. Words shared with English (`role`, `source`,
//! `message`, `service`…) are left out: a test that cries wolf gets deleted rather than
//! its cause fixed.
//!
//! ## Scanning
//!
//! Identifiers with string literals and comments blanked — the accented fixtures ARE the
//! test they sit in —, then the literals shaped like a value, then whole-line comments.
//! The directory is walked, never listed by hand: a hand-maintained list of files to
//! scan is a thing this repository has already watched go stale while still passing.

mod scan;

use std::sync::LazyLock;

use scan::{code_only, crates_root, rust_files, short, split};

// Read once: the comment scan asks for them on each of twenty thousand lines.
static PROSE: LazyLock<Vec<&str>> = LazyLock::new(|| words("prose"));
static SHORT: LazyLock<Vec<&str>> = LazyLock::new(|| words("short"));

/// One section of `data/non-english-words.txt`.
fn words(section: &str) -> Vec<&'static str> {
    let header = format!("[{section}]");
    let list: Vec<&'static str> = include_str!("data/non-english-words.txt")
        .lines()
        .map(str::trim)
        .skip_while(|l| *l != header)
        .skip(1)
        .take_while(|l| !l.starts_with('['))
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    // A section misspelt, or the file cut short, would refuse nothing.
    assert!(list.len() >= 15, "only {} words in [{section}]", list.len());
    list
}

/// Names and values that are French and stay French, each with the reason it costs more
/// to change than to keep.
///
/// It held twelve identifiers, on the belief that `rename_all` enums (`StepState`,
/// `ConfidenceLevel`, `ServiceState`, `AlertLevel`) had their values written into the
/// audit log, saved plan bodies and alert history. Checked against the code, none of the
/// three holds them: the audit log stores a sentence, a saved plan stores the REQUEST,
/// and alerts live in memory. The one value that was stored — `ServiceState`, in the
/// uptime samples — goes through a hand-written mapping, and migration 0025 moved its
/// rows. They were renamed before the OpenAPI document could copy them into TypeScript
/// as literal types.
///
/// What remains are values French on purpose, read from outside:
const EXEMPT: &[&str] = &[
    // `Role::parse` reads rows written before the roles were translated: dropping the
    // aliases would make every token and person stored with one fail to load.
    "utilisateur",
    "lecteur",
    "operateur",
    // A drill refuses to restore into a database that looks like production, and a
    // French-speaking owner names it `primaire` as readily as `primary`.
    "primaire",
];

#[test]
fn every_identifier_is_english() {
    let foreign = words("identifier");
    let mut offenders: Vec<String> = Vec::new();

    for file in rust_files(&crates_root()) {
        let source = std::fs::read_to_string(&file).unwrap_or_default();
        let code = code_only(&source);
        for ident in identifiers(&code) {
            if EXEMPT.contains(&ident.as_str()) {
                continue;
            }
            if words_of(&ident)
                .iter()
                .any(|w| foreign.contains(&w.as_str()))
            {
                offenders.push(format!("{}: {ident}", short(&file)));
            }
        }
    }
    offenders.sort();
    offenders.dedup();

    assert!(
        offenders.is_empty(),
        "Identifiers not in English, {} of them:\n  {}\n\n\
         Rename them. If one genuinely must stay — a serde value that is already \
         persisted, or a name that is also on the wire — add it to EXEMPT with the \
         reason, so the next reader knows it is a decision.",
        offenders.len(),
        offenders.join("\n  ")
    );
}

/// Is this literal a value a program reads — `announcement-remove`, `anonymous` — rather
/// than a sentence, a path or a format string?
fn is_machine_value(s: &str) -> bool {
    s.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.".contains(c))
}

#[test]
fn every_value_a_program_reads_is_english() {
    // 🔴 The scan above blanks string literals, and the values that outlive a rename
    // live in exactly those: audit-log actions, actor names, safeguard ids, wire
    // values. Twelve were French on 2026-10-05 after five passes over the identifiers, nine of
    // them stored —
    // `read-soi`, `gerer-accounts`, `announcement-retrait`, `anonyme`, `deux-passkeys`
    // among them — while `retrait` and `deux` sat in the list below. A sentence is skipped (a space is not in a value), and so
    // are the tests, whose French fixtures ARE the test.
    let mut offenders: Vec<String> = Vec::new();
    let foreign = words("identifier");
    let mut read = 0;
    for file in rust_files(&crates_root()) {
        if file.components().any(|c| c.as_os_str() == "tests") {
            continue;
        }
        let source = std::fs::read_to_string(&file).unwrap_or_default();
        let production = source.split("\n#[cfg(test)]").next().unwrap_or("");
        for value in split(production).1 {
            if !is_machine_value(&value) {
                continue;
            }
            read += 1;
            if value
                .split(['-', '_', '.'])
                .any(|w| foreign.contains(&w) && !EXEMPT.contains(&value.as_str()))
            {
                offenders.push(format!("{}: \"{value}\"", short(&file)));
            }
        }
    }
    // A stripper that stopped yielding strings would pass on nothing.
    assert!(read > 1_000, "only {read} machine values read");
    offenders.sort();
    offenders.dedup();
    assert!(
        offenders.is_empty(),
        "Values not in English, {} of them:\n  {}\n\nA value written to the database needs a \
         migration to be renamed (see 0025); one on the wire changes the API document.",
        offenders.len(),
        offenders.join("\n  ")
    );
}

/// Does this line of a string literal carry a lost line continuation — a sentence with
/// the source's indentation in the middle of it?
///
/// A run of eight spaces or more inside a LONG line. Column alignment in a short line
/// (`--binary                  restore the previous binary`) is left alone: a lost
/// continuation is always in a sentence, since a sentence is what gets wrapped.
fn lost_continuation(line: &str) -> bool {
    let line = line.trim();
    if line.chars().count() < 80 {
        return false;
    }
    let chars: Vec<char> = line.chars().collect();
    let mut run = 0;
    for (i, c) in chars.iter().enumerate() {
        if *c == ' ' {
            run += 1;
        } else {
            if run >= 8 && i > run {
                return true;
            }
            run = 0;
        }
    }
    false
}

#[test]
fn the_lost_continuation_check_tells_a_sentence_from_a_column() {
    // The message that shipped on 2026-10-11, and the alignments that must not trip it.
    assert!(lost_continuation(
        "{} is one of {managers} managers and the others are not a majority                  \
         without it: the running services keep running, but nothing is"
    ));
    assert!(!lost_continuation(
        "--binary                  restore the previous binary"
    ));
    assert!(!lost_continuation(
        "key         {name}-backups, read + write, never owner"
    ));
}

#[test]
fn no_message_carries_a_lost_line_continuation() {
    // 🔴 A wrapped string whose trailing `\` went missing keeps the next line's
    // indentation: "not a majority                  without it". Invisible in the
    // source, which looks wrapped; obvious on screen. Four shipped in one day, in
    // crates the screen-text tests never read — so this one reads every production
    // source.
    let mut offenders = Vec::new();
    let mut read = 0;
    for file in rust_files(&crates_root()) {
        if file.components().any(|c| c.as_os_str() == "tests") {
            continue;
        }
        let source = std::fs::read_to_string(&file).unwrap_or_default();
        let production = source.split("\n#[cfg(test)]").next().unwrap_or("");
        for literal in split(production).1 {
            for line in literal.lines() {
                read += 1;
                if lost_continuation(line) {
                    offenders.push(format!("{}: {}", short(&file), line.trim()));
                }
            }
        }
    }
    assert!(read > 5_000, "only {read} literal lines read");
    assert!(
        offenders.is_empty(),
        "strings with a source indentation in the middle — a `\\` at the end of the \
         previous line is missing:\n  {}",
        offenders.join("\n  ")
    );
}

/// Every scan here reads a file up to its first `#[cfg(test)]`, so code written after a
/// test module is read by none of them: `restic/restic:latest` sat in `pgdump.rs`'s
/// scheduled dumps, below its tests, out of reach of the test pinning every image.
#[test]
fn no_code_follows_a_test_module() {
    const ITEMS: &[&str] = &[
        "fn ",
        "async fn ",
        "mod ",
        "struct ",
        "enum ",
        "impl",
        "const ",
        "static ",
        "trait ",
        "use ",
        "type ",
        "macro_rules!",
    ];
    let mut offenders = Vec::new();
    for file in rust_files(&crates_root()) {
        if file.components().any(|c| c.as_os_str() == "tests") {
            continue;
        }
        let source = std::fs::read_to_string(&file).unwrap_or_default();
        let Some((_, after)) = source.split_once("\n#[cfg(test)]") else {
            continue;
        };
        let mut previous = "#[cfg(test)]";
        for line in after.lines() {
            let item = line
                .strip_prefix("pub ")
                .or_else(|| line.strip_prefix("pub(crate) "))
                .unwrap_or(line);
            if ITEMS.iter().any(|i| item.starts_with(i)) && previous != "#[cfg(test)]" {
                offenders.push(format!("{}: {line}", short(&file)));
                break;
            }
            if !line.is_empty() {
                previous = line;
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "code after a test module, which every scan cutting at `#[cfg(test)]` misses — \
         move the test module last:\n  {}",
        offenders.join("\n  ")
    );
}

/// Is this comment written in another language than English?
///
/// What sits between backticks or quotes is code or a quotation (`Noto Sans`,
/// `docker-ce`), not the comment's own language; and a word counts once.
fn foreign_prose(comment: &str) -> bool {
    let mut prose = String::new();
    let mut quoted: Option<char> = None;
    for c in comment.chars() {
        match quoted {
            Some(q) if c == q => quoted = None,
            Some(_) => {}
            None if c == '`' || c == '"' => quoted = Some(c),
            None => prose.push(c),
        }
    }
    let mut seen: Vec<String> = prose
        .split(|c: char| !c.is_alphabetic())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect();
    seen.sort();
    seen.dedup();
    let has = |list: &[&str]| seen.iter().filter(|w| list.contains(&w.as_str())).count();
    has(&PROSE) > 0 || has(&SHORT) >= 2
}

#[test]
fn foreign_prose_is_told_from_english() {
    for french in [
        "/// Pourquoi ce garde-fou existe.",
        "/// Âge du plan, en secondes.",
        "/// Analyse la output JSON de Trivy.",
        "// Sans confirmation.",
    ] {
        assert!(foreign_prose(french), "{french}");
    }
    for english in [
        "/// The `le` label of a histogram bucket.",
        "// Read the dump's list, then en-dash the range.",
        "/// Bytes per second, on par with the agent's.",
        "/// `None` keeps the project's `Noto Sans`; `docker-ce-cli` and `docker-ce` too.",
    ] {
        assert!(!foreign_prose(english), "{english}");
    }
}

#[test]
fn every_comment_is_english() {
    // 🔴 The scans above blank comments, so French ones outlived every pass over the
    // identifiers: "Pourquoi ce garde-fou existe." documented a field of the API
    // document until 2026-10-27, beside a dozen others. Whole-line comments only — a
    // comment after code is rare here, and a string holding `//` would be misread.
    let mut offenders = Vec::new();
    let mut read = 0;
    for file in rust_files(&crates_root()) {
        let source = std::fs::read_to_string(&file).unwrap_or_default();
        for (n, line) in source.lines().enumerate() {
            let Some(comment) = line.trim_start().strip_prefix("//") else {
                continue;
            };
            read += 1;
            if foreign_prose(comment) {
                offenders.push(format!("{}:{}: {}", short(&file), n + 1, line.trim()));
            }
        }
    }
    // A walk that read no comment would pass on nothing.
    assert!(read > 20_000, "only {read} comment lines read");
    assert!(
        offenders.is_empty(),
        "Comments not in English, {} of them:\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
}

/// The test would be worthless if its own list silently stopped being applied.
#[test]
fn the_scan_actually_reaches_the_whole_workspace() {
    let files = rust_files(&crates_root());
    // 150 until 2026-10-05, when the egui interface left and took its sources with it:
    // 143 remained. The floor follows a shrinking workspace DOWN, never a broken walk.
    assert!(
        files.len() > 130,
        "only {} sources walked — the scan is not reaching the workspace, and an empty \
         walk passes every assertion above it",
        files.len()
    );
    // Blanking must not blank everything: a stripper with an unterminated state eats the
    // rest of the file and reports a clean bill of health for code it never read.
    let total: usize = files
        .iter()
        .map(|f| code_only(&std::fs::read_to_string(f).unwrap_or_default()).len())
        .sum();
    assert!(
        total > 500_000,
        "only {total} bytes of code survived stripping"
    );
}

/// `ident` split on `_` and on camelCase humps.
/// The words inside an identifier: `snake_case`, `camelCase` and `SCREAMING_CASE`.
///
/// 🔴 A run of capitals is ONE word, and getting that wrong cost this test four passes.
/// The first version broke at every capital, so `RETARD_SECS` came out as
/// `r e t a r d s e c s` — ten single letters, none of them a French word — and sailed
/// through while `retard` sat in the list below. Every `const` in the workspace was
/// invisible to this scan for as long as it existed: `BARRE`, `FONCTIONS` and
/// `LIGNE_DE_GARDE` were all found by somebody READING, and written up in `ROADMAP.md`
/// as words missing from the list. Three of the four were in the list.
///
/// ⚠️ The boundary is a capital that either follows a lower-case letter (`aJour`) or
/// precedes one (`HTTPServer` → `http` + `server`). That second half is what keeps
/// `AJour` — the name this test caught on its very first run — still splitting into
/// `a` + `jour`.
fn words_of(ident: &str) -> Vec<String> {
    let mut out = Vec::new();
    for chunk in ident.split('_') {
        let chars: Vec<char> = chunk.chars().collect();
        let mut start = 0;
        for i in 1..chars.len() {
            let opens_a_word = chars[i].is_uppercase()
                && (!chars[i - 1].is_uppercase()
                    || chars.get(i + 1).is_some_and(|c| c.is_lowercase()));
            if opens_a_word {
                out.push(chars[start..i].iter().collect::<String>().to_lowercase());
                start = i;
            }
        }
        if start < chars.len() {
            out.push(chars[start..].iter().collect::<String>().to_lowercase());
        }
    }
    out
}

fn identifiers(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for c in code.chars() {
        if c.is_alphanumeric() || c == '_' {
            current.push(c);
        } else if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}
