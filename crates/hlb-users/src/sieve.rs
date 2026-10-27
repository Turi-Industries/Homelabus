//! Generating Sieve sorting rules.
//!
//! ## What this solves
//!
//! One alias per recipient is useless if everything lands unsorted in the inbox: you
//! know you have fifty addresses, you cannot see which receives what. Automatic sorting
//! is what makes **attribution** visible - the only real benefit. Opening the `fnac`
//! folder and finding mattress advertising says immediately who sold the address.
//!
//! ## 🔴 The folder name belongs to the user, not to the generator
//!
//! It would be tempting to derive the folder from the hint without asking. That would
//! be a mistake: people file their mail according to **their** logic, not ours. Someone
//! who wants everything in `Purchases/2026` rather than a folder per merchant is right,
//! and a system deciding for them produces a tree they then have to undo by hand.
//!
//! So [`Rule::folder`] is **supplied**, with a default only when nothing is said. And
//! the generated rule stays readable and editable in Roundcube - a rule you cannot
//! inspect is a rule you do not trust.
//!
//! ## 🔴 NEVER overwrite what the user wrote
//!
//! A Sieve script is a single file per account. Rewriting it wholesale would erase
//! hand-written rules - hours of tuning, lost without a warning, for a simple alias
//! creation.
//!
//! Hence the **delimited** block: Homelabus writes only between its two markers and
//! copies the rest across untouched. See [`merge`].

use serde::{Deserialize, Serialize};

/// Start of the managed block. Everything **outside** it belongs to the user.
pub const START: &str = "# >>> Homelabus - start of the managed block. Do not edit by hand.";
/// End of the managed block.
pub const END: &str = "# <<< Homelabus - end of the managed block.";

/// A sorting rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// The local part of the alias in question.
    pub alias: String,
    /// The destination folder, as the user wants it.
    ///
    /// ⚠️ Separators are `/`: Stalwart translates them into the IMAP hierarchy.
    pub folder: String,
    /// Should processing of the following rules also stop?
    ///
    /// True by default: without `stop`, a message matching two rules would be filed
    /// twice - and appear twice in the client.
    pub stop: bool,
}

impl Rule {
    /// A rule filing the alias into the requested folder.
    pub fn new(alias: impl Into<String>, folder: impl Into<String>) -> Self {
        Self {
            alias: alias.into(),
            folder: folder.into(),
            stop: true,
        }
    }

    /// The default folder, when the user gives none.
    ///
    /// ⚠️ This is a DEFAULT, not a rule: the site hint is the best starting point, and
    /// it stays editable. With no hint, nothing is guessed - the inbox beats an
    /// `unnamed` folder nobody will ever look at.
    pub fn default_folder(hint: Option<&str>) -> Option<String> {
        hint.map(str::trim)
            .filter(|i| !i.is_empty())
            .map(|i| format!("Alias/{i}"))
    }
}

/// Escapes a string for a Sieve string literal.
///
/// 🔴 A folder name comes from the user. An unescaped quote would break the script's
/// syntax - and Stalwart would REFUSE the whole script, hand-written rules included. A
/// single misplaced quote would therefore lose the sorting of every address at once.
pub fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// The managed block, to be inserted into the account's script.
pub fn block(rules: &[Rule]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();

    let _ = writeln!(s, "{START}");
    let _ = writeln!(
        s,
        "# These rules file each alias's mail. Change the folder instead"
    );
    let _ = writeln!(
        s,
        "# through `hlb user alias folder`, or the next generation will overwrite it."
    );

    if rules.is_empty() {
        let _ = writeln!(s, "# (no alias sorted yet)");
    }

    for r in rules {
        let _ = writeln!(s);
        // ⚠️ The local part, not the full address: a message shows the alias as "Name
        // <alias@dom>". And the ENVELOPE as well as `to` and `cc`: a copy in Bcc names
        // the alias in no header at all, and on `to` alone it landed unsorted.
        let alias = escape(&r.alias);
        let _ = writeln!(
            s,
            "if anyof (envelope :localpart :is \"to\" \"{alias}\",\n          \
             address :localpart :is [\"to\", \"cc\"] \"{alias}\") {{"
        );
        let _ = writeln!(s, "    fileinto :create \"{}\";", escape(&r.folder));
        if r.stop {
            // Without `stop`, a message matching two rules would be filed twice and
            // appear twice in the client.
            let _ = writeln!(s, "    stop;");
        }
        let _ = writeln!(s, "}}");
    }

    let _ = writeln!(s, "{END}");
    s
}

/// The extensions the managed block uses: `fileinto`, `:create` (`mailbox`), and
/// `envelope`.
const EXTENSIONS: [&str; 3] = ["fileinto", "mailbox", "envelope"];

/// The extensions a script's `require` statements already name.
fn required(script: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = script;
    while let Some(at) = rest.find("require") {
        let tail = &rest[at + "require".len()..];
        // A statement starts its line; the word in a comment requires nothing.
        let line_start = rest[..at].rfind('\n').map_or(0, |n| n + 1);
        if !rest[line_start..at].trim().is_empty() {
            rest = tail;
            continue;
        }
        let statement = tail.split(';').next().unwrap_or("");
        found.extend(statement.split('"').skip(1).step_by(2).map(str::to_string));
        rest = tail;
    }
    found
}

/// `script` with a `require` for each extension the block uses that it lacks.
///
/// ⚠️ Without one, Stalwart refuses the WHOLE script — the user's rules included,
/// which worked until then. Several `require` at the top are valid Sieve, so the
/// missing ones go first and the user's own stays as written.
fn with_requires(script: String) -> String {
    let have = required(&script);
    let missing: Vec<String> = EXTENSIONS
        .iter()
        .filter(|e| !have.iter().any(|h| h == *e))
        .map(|e| format!("\"{e}\""))
        .collect();
    if missing.is_empty() {
        script
    } else {
        format!("require [{}];\n{script}", missing.join(", "))
    }
}

/// Inserts or replaces the managed block in an existing script.
///
/// 🔴 **Never touches anything outside the block.** A Sieve script is a single file per
/// account: rewriting it wholesale would erase hand-written rules, without a warning,
/// for a simple alias creation.
pub fn merge(existing_script: &str, rules: &[Rule]) -> String {
    let new_one = block(rules);

    match (existing_script.find(START), existing_script.find(END)) {
        (Some(d), Some(f)) if f > d => {
            let before = &existing_script[..d];
            let after = &existing_script[f + END.len()..];
            // The newline that followed the old end marker is removed, or blank lines
            // pile up on every generation.
            let after = after.strip_prefix('\n').unwrap_or(after);
            with_requires(format!("{before}{new_one}{after}"))
        }
        _ => {
            // No block: it is appended at the END. At the top it would catch messages
            // before the user's own rules, changing their script's behaviour without
            // them asking.
            let base = existing_script.trim_end();
            if base.is_empty() {
                with_requires(format!("\n{new_one}"))
            } else {
                with_requires(format!("{base}\n\n{new_one}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_written_rules_are_never_lost() {
        // 🔴 THE point of this module. A Sieve script is a single file per account:
        // rewriting it wholesale would erase hours of tuning, without a warning, for a
        // simple alias creation.
        let existing = "require [\"fileinto\"];\n\
                        # my own rule\n\
                        if header :contains \"subject\" \"facture\" {\n\
                        \x20   fileinto \"Compta\";\n\
                        }\n";

        let merged = merge(existing, &[Rule::new("fnac-a1b2", "Alias/fnac")]);

        assert!(merged.contains("# my own rule"), "{merged}");
        assert!(merged.contains("\"Compta\""), "{merged}");
        assert!(merged.contains("fnac-a1b2"), "{merged}");
    }

    #[test]
    fn regenerating_replaces_only_the_managed_block() {
        // Two generations in a row must not stack blocks, nor grow the script with
        // every alias created.
        let base = "# perso\nif true { keep; }\n";
        let un = merge(base, &[Rule::new("a", "A")]);
        let two = merge(&un, &[Rule::new("b", "B")]);

        assert_eq!(two.matches(START).count(), 1, "{two}");
        assert_eq!(two.matches(END).count(), 1, "{two}");
        assert!(
            two.contains("# perso"),
            "the out-of-block content survives: {two}"
        );
        assert!(two.contains("\"b\""), "{two}");
        assert!(!two.contains("\"a\""), "the old block is REPLACED: {two}");
    }

    #[test]
    fn the_managed_block_goes_last_not_first() {
        // At the top it would catch messages BEFORE the user's own rules, changing
        // their script's behaviour without them asking.
        let base = "require [\"fileinto\"];\nif true { fileinto \"Tout\"; stop; }\n";
        let f = merge(base, &[Rule::new("x", "X")]);

        let pos_user = f.find("\"Tout\"").expect("user rule");
        let block_pos = f.find(START).expect("managed block");
        assert!(
            pos_user < block_pos,
            "the managed block must come AFTER: {f}"
        );
    }

    #[test]
    fn a_quote_in_a_folder_name_cannot_break_the_whole_script() {
        // 🔴 A folder name comes from the user. An unescaped quote would break the
        // syntax, and Stalwart would refuse the WHOLE script - including hand-written
        // rules, which worked until then.
        let r = Rule::new("x", "Dossier \"spécial\"");
        let b = block(&[r]);

        assert!(b.contains(r#"\"spécial\""#), "{b}");
        // The count of unescaped quotes must stay even, or the string is not closed.
        let unescaped = b.matches('"').count() - b.matches(r#"\""#).count() * 2;
        assert_eq!(unescaped % 2, 0, "unbalanced quotes: {b}");
    }

    #[test]
    fn a_backslash_is_escaped_too() {
        assert_eq!(escape(r"a\b"), r"a\\b");
        assert_eq!(escape(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn the_require_is_added_when_missing() {
        // ⚠️ `fileinto` and `:create` need their extensions. Without the `require`,
        // Stalwart refuses the WHOLE script - including the user's rules.
        let f = merge("# nothing\n", &[Rule::new("x", "X")]);
        assert!(f.starts_with("require ["), "{f}");
        assert!(f.contains("fileinto"), "{f}");

        // And it is not added twice when already present.
        let all = "require [\"fileinto\", \"mailbox\", \"envelope\"];\n";
        let already = merge(all, &[Rule::new("x", "X")]);
        assert_eq!(already.matches("require [").count(), 1, "{already}");
    }

    #[test]
    fn every_extension_the_block_uses_is_required_whatever_the_script_had() {
        // `require ["fileinto"]` alone counted as "required": `:create` (mailbox) was
        // missing, and Stalwart refused the whole script, the person's rules with it.
        for existing in [
            "require [\"fileinto\"];\nif true { keep; }\n",
            "require \"fileinto\";\n",
            "# I require \"mailbox\" one day;\nrequire \"fileinto\";\n",
        ] {
            let once = merge(existing, &[Rule::new("x", "X")]);
            let again = merge(&once, &[Rule::new("y", "Y")]);
            for f in [&once, &again] {
                let have = required(f);
                for e in EXTENSIONS {
                    assert_eq!(have.iter().filter(|h| *h == e).count(), 1, "{e}: {f}");
                }
            }
        }
    }

    #[test]
    fn an_alias_is_sorted_whether_it_is_in_to_in_cc_or_only_in_the_envelope() {
        let b = block(&[Rule::new("shop-x1", "Shops")]);
        assert!(
            b.contains("envelope :localpart :is \"to\" \"shop-x1\""),
            "{b}"
        );
        assert!(
            b.contains("address :localpart :is [\"to\", \"cc\"] \"shop-x1\""),
            "{b}"
        );
        assert!(b.contains("anyof ("), "{b}");
    }

    #[test]
    fn an_empty_script_still_gets_its_require() {
        let f = merge("", &[Rule::new("x", "X")]);
        assert!(f.starts_with("require ["), "{f}");
        assert!(f.contains(START));
    }

    #[test]
    fn rules_match_the_local_part_not_the_whole_address() {
        // ⚠️ A message can arrive with the alias in COPY, or as "Name <alias@domain>".
        // Comparing the whole address would miss those cases, and the rule would never
        // fire - with no error anywhere.
        let b = block(&[Rule::new("fnac-a1b2", "Alias/fnac")]);
        assert!(b.contains(":localpart"), "{b}");
        assert!(
            !b.contains("@"),
            "the full address has no business here: {b}"
        );
    }

    #[test]
    fn a_stopless_rule_can_be_asked_for() {
        // `stop` is the default - otherwise a message matching two rules would be
        // filed twice and appear twice in the client.
        assert!(block(&[Rule::new("x", "X")]).contains("stop;"));

        let mut r = Rule::new("x", "X");
        r.stop = false;
        assert!(!block(&[r]).contains("stop;"));
    }

    #[test]
    fn the_default_folder_is_only_a_suggestion() {
        // 🔴 People file their mail according to THEIR logic. The default starts from
        // the site hint, and stays editable.
        assert_eq!(
            Rule::default_folder(Some("fnac")),
            Some("Alias/fnac".into())
        );
        // With no hint, nothing is guessed: the inbox beats an "unnamed" folder nobody
        // will ever look at.
        assert_eq!(Rule::default_folder(None), None);
        assert_eq!(Rule::default_folder(Some("  ")), None);
    }

    #[test]
    fn an_empty_rule_set_still_produces_a_valid_block() {
        // Deleting the last alias must not leave a malformed block, nor break the
        // whole script.
        let b = block(&[]);
        assert!(b.contains(START) && b.contains(END), "{b}");
        assert!(b.contains("no alias sorted"), "{b}");
    }
}
