//! The instruction files that steer Claude Code, and what keeps them true.
//!
//! ## Why this test exists
//!
//! `CLAUDE.md` reached 1310 lines before anyone measured it, and every one of them was
//! reloaded into every session. The fix was to split the domain traps into
//! `.claude/rules/`, where each file carries a `paths:` glob and only enters context
//! when a file it covers is read.
//!
//! That fix introduced a mapping from globs to crates, maintained by hand. This
//! repository has watched three hand-maintained lists go stale while still passing —
//! the `include_str!` scanner list, `Resources::tick`, and the files-to-scan list in
//! `english_only.rs` — so writing a fourth one without a test would repeat the exact
//! mistake the split was meant to record.
//!
//! ## The failure being guarded
//!
//! 🔴 **It is silent, in the worst way.** A rule whose glob matches nothing is not an
//! error anywhere: Claude Code loads the file, finds no match, and says nothing. The
//! rule simply never fires, and the traps it holds stop reaching anybody — while the
//! file sits in the repository looking maintained. Rename a crate and that is what you
//! get, with no signal at all.
//!
//! ## What it can and cannot do
//!
//! ⚠️ This does not evaluate globs. It checks that the **literal prefix** of each
//! pattern — everything before the first wildcard — exists on disk, which is what
//! catches a renamed or deleted crate. A pattern that is wildcard from the start, like
//! `**/Cargo.toml`, cannot drift and is not checked.

use std::path::{Path, PathBuf};

/// Crates with no domain rule, each with the reason. Keep this short: an entry here is
/// a crate whose traps reach nobody through `paths:`.
///
/// Both are still covered by `rust.md`, which fires on any `.rs`.
const NO_DOMAIN_RULE: &[(&str, &str)] = &[
    (
        "hlb-catalog",
        "loading and validating the catalog — the rules that matter for it (the folder \
         name matching metadata.name, deny_unknown_fields, a capability pointing at an \
         absent service) are core, and live in the root CLAUDE.md",
    ),
    (
        "hlb-cli",
        "one main.rs assembling every domain and owning none; it has its own nested \
         crates/hlb-cli/CLAUDE.md pointing at the right domain rule per verb, which is \
         what a paths: glob cannot do for a single file that touches everything",
    ),
];

/// The size that made the split necessary in the first place.
const CLAUDE_MD_MAX_LINES: usize = 200;

#[derive(serde::Deserialize)]
struct Frontmatter {
    paths: Vec<String>,
}

#[test]
fn every_rule_is_scoped_by_paths() {
    let mut unscoped = Vec::new();
    for rule in rule_files() {
        let source = std::fs::read_to_string(&rule).unwrap_or_default();
        if frontmatter(&source).is_none() {
            unscoped.push(name_of(&rule));
        }
    }
    unscoped.sort();

    assert!(
        unscoped.is_empty(),
        "rules with no `paths:` frontmatter: {}\n\n\
         A rule without `paths:` loads at launch, in every session, which is the cost \
         the split into .claude/rules/ exists to avoid. Give it a glob, or move it into \
         CLAUDE.md deliberately.",
        unscoped.join(", ")
    );
}

#[test]
fn every_rule_path_points_at_something_that_exists() {
    let root = repo_root();
    let mut dead = Vec::new();

    for rule in rule_files() {
        let source = std::fs::read_to_string(&rule).unwrap_or_default();
        let Some(front) = frontmatter(&source) else {
            continue; // reported by every_rule_is_scoped_by_paths
        };
        for pattern in &front.paths {
            for expanded in brace_expand(pattern) {
                let Some(prefix) = literal_prefix(&expanded) else {
                    continue; // wildcard from the start; cannot drift
                };
                if !root.join(&prefix).exists() {
                    dead.push(format!("{}: {pattern} -> {prefix}", name_of(&rule)));
                }
            }
        }
    }
    dead.sort();
    dead.dedup();

    assert!(
        dead.is_empty(),
        "rule paths matching nothing, {} of them:\n  {}\n\n\
         A glob that matches nothing makes its rule silently stop firing — no error, no \
         warning, the traps just stop reaching anybody. Fix the glob, or delete the rule \
         if the domain is gone.",
        dead.len(),
        dead.join("\n  ")
    );
}

#[test]
fn every_crate_has_a_domain_rule_or_a_recorded_reason() {
    let root = repo_root();
    let mut covered: Vec<String> = Vec::new();

    for rule in rule_files() {
        let source = std::fs::read_to_string(&rule).unwrap_or_default();
        let Some(front) = frontmatter(&source) else {
            continue;
        };
        for pattern in &front.paths {
            if let Some(rest) = pattern.strip_prefix("crates/") {
                if let Some((krate, _)) = rest.split_once('/') {
                    if !krate.contains('*') {
                        covered.push(krate.to_string());
                    }
                }
            }
        }
    }

    // `rust.md` fires on any `.rs`, so it covers everything and would hide the gap this
    // test looks for. Only domain rules count.
    covered.retain(|c| !c.is_empty());

    let mut uncovered: Vec<String> = crate_names(&root)
        .into_iter()
        .filter(|c| !covered.contains(c))
        .filter(|c| !NO_DOMAIN_RULE.iter().any(|(name, _)| name == c))
        .collect();
    uncovered.sort();

    assert!(
        uncovered.is_empty(),
        "crates no domain rule covers, {} of them:\n  {}\n\n\
         Add the crate to the `paths:` of the rule that owns its domain, or add it to \
         NO_DOMAIN_RULE with the reason so the next reader knows it is a decision and \
         not an oversight.",
        uncovered.len(),
        uncovered.join("\n  ")
    );

    // The exemption for hlb-cli is only true while that file is there to make it true.
    for (name, _) in NO_DOMAIN_RULE {
        if *name == "hlb-cli" {
            assert!(
                root.join("crates/hlb-cli/CLAUDE.md").exists(),
                "hlb-cli is exempt from the domain rules because it carries its own \
                 nested CLAUDE.md, and that file is gone — so nothing points a reader \
                 of main.rs at the domain traps any more"
            );
        }
    }
}

#[test]
fn claude_md_stays_short_enough_to_be_read() {
    let root = repo_root();
    let mut over = Vec::new();

    for path in ["CLAUDE.md", "crates/hlb-cli/CLAUDE.md"] {
        let source = std::fs::read_to_string(root.join(path)).unwrap_or_default();
        let lines = source.lines().count();
        assert!(lines > 0, "{path} is missing or empty");
        if lines > CLAUDE_MD_MAX_LINES {
            over.push(format!("{path}: {lines} lines"));
        }
    }

    assert!(
        over.is_empty(),
        "CLAUDE.md files over {CLAUDE_MD_MAX_LINES} lines:\n  {}\n\n\
         This file is reloaded in full at the start of every session, and adherence \
         drops as it grows — it was 1310 lines once. A domain trap belongs in \
         .claude/rules/, what changed in a commit message, remaining work in \
         ROADMAP.md, and a command tour in docs/cli-tour.md.",
        over.join("\n  ")
    );
}

/// What Claude Code reads of a file it loads on demand — a path-scoped rule — in a session
/// with a 200K window: the first 40,000 characters, and nothing past them. Subagents and
/// smaller models run in such windows. A rule over it does not fail: it loses its END,
/// silently, and the newest traps are appended at the end.
const RULE_MAX_CHARS: usize = 40_000;

/// Measured 2026-10-27: `operations.md` at 36,521 characters and `interface.md` at
/// 36,187, both growing — the rules went from 62 KB to 157 KB in five weeks.
#[test]
fn every_rule_fits_in_what_claude_code_loads() {
    let mut over = Vec::new();
    for rule in rule_files() {
        let chars = std::fs::read_to_string(&rule)
            .unwrap_or_default()
            .chars()
            .count();
        if chars > RULE_MAX_CHARS {
            over.push(format!("{}: {chars} characters", name_of(&rule)));
        }
    }

    assert!(
        over.is_empty(),
        "rules over the {RULE_MAX_CHARS} characters Claude Code loads of them:\n  {}\n\n\
         Past that the end of the file is cut without a word. Do not raise the limit: \
         split the rule by the files it covers, with narrower `paths:`, or cut what is \
         history rather than a trap — a trap states what to do and \
         why in a few lines.",
        over.join("\n  ")
    );
}

#[derive(serde::Deserialize)]
struct SkillFrontmatter {
    name: String,
    description: String,
}

/// A skill is found by its directory and chosen by its description: a `SKILL.md` whose
/// frontmatter does not parse, or names another skill, is never offered — and nothing
/// says so.
#[test]
fn every_skill_is_named_after_its_directory_and_says_what_it_is_for() {
    let mut walked = 0;
    let mut broken = Vec::new();
    let Ok(entries) = std::fs::read_dir(repo_root().join(".claude/skills")) else {
        panic!(".claude/skills is missing");
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        walked += 1;
        let directory = name_of(&dir);
        let source = std::fs::read_to_string(dir.join("SKILL.md")).unwrap_or_default();
        let parsed = source
            .strip_prefix("---\n")
            .and_then(|rest| rest.find("\n---").map(|end| &rest[..end]))
            .and_then(|yaml| serde_yaml_ng::from_str::<SkillFrontmatter>(yaml).ok());
        match parsed {
            None => broken.push(format!(
                "{directory}: no SKILL.md frontmatter with name and description"
            )),
            Some(front) if front.name != directory => {
                broken.push(format!("{directory}: named `{}`", front.name))
            }
            Some(front) if front.description.trim().len() < 40 => {
                broken.push(format!("{directory}: a description too short to choose by"))
            }
            Some(_) => {}
        }
    }

    assert!(
        broken.is_empty(),
        "skills Claude Code cannot offer:\n  {}",
        broken.join("\n  ")
    );
    assert!(
        walked >= 5,
        "only {walked} skills walked — an empty walk passes the assertion above"
    );
}

/// A hook is the one instruction that runs whatever the model decides — but only if the
/// script is still there. A `settings.json` pointing at a missing or non-executable file
/// fails quietly: the hook simply does not run, and the guarantee it was written to be
/// silently becomes advice again.
#[test]
fn every_hook_command_exists_and_can_run() {
    let root = repo_root();
    let settings = std::fs::read_to_string(root.join(".claude/settings.json"))
        .expect(".claude/settings.json is missing");
    let parsed: serde_json::Value =
        serde_json::from_str(&settings).expect(".claude/settings.json is not valid JSON");

    let mut broken = Vec::new();
    let mut seen = 0;
    for command in hook_commands(&parsed) {
        seen += 1;
        let relative = command.replace("${CLAUDE_PROJECT_DIR}/", "");
        let path = root.join(&relative);
        if !path.is_file() {
            broken.push(format!("{command} -> no such file"));
            continue;
        }
        if !is_executable(&path) {
            broken.push(format!("{command} -> not executable"));
        }
    }

    assert!(
        broken.is_empty(),
        "hooks pointing at nothing, {} of them:\n  {}",
        broken.len(),
        broken.join("\n  ")
    );
    assert!(
        seen > 0,
        "no hook command found in .claude/settings.json — either the hooks were removed \
         (then remove this test with them) or the shape of the file changed and this \
         check is now walking past everything it was written to inspect"
    );
}

/// Cargo names a workspace crate's artifacts by its path relative to the workspace, so a
/// `target/` symlinked into a worktree is written by both checkouts under the same names,
/// and mtimes decide whose crate the next build links: on 2026-10-27 a worktree compiled
/// against the main checkout's `hlb-api`. Nothing fails when it happens — a suite simply
/// tests the other checkout's code.
#[test]
fn no_worktree_shares_the_build_directory() {
    let settings = std::fs::read_to_string(repo_root().join(".claude/settings.json"))
        .expect(".claude/settings.json is missing");
    let parsed: serde_json::Value =
        serde_json::from_str(&settings).expect(".claude/settings.json is not valid JSON");

    let shared: Vec<&str> = parsed
        .pointer("/worktree/symlinkDirectories")
        .and_then(|d| d.as_array())
        .into_iter()
        .flatten()
        .filter_map(|d| d.as_str())
        .filter(|d| {
            let d = d.trim_start_matches("./").trim_end_matches('/');
            d == "target" || d.starts_with("target/") || d.ends_with("/target")
        })
        .collect();

    assert!(
        shared.is_empty(),
        "worktree.symlinkDirectories shares a cargo build directory: {shared:?}\n\n\
         Each checkout would build against the other's crates without a word. A worktree \
         gets its own target/, reflinked from the main checkout's by \
         scripts/worktree-target.sh."
    );
}

/// The two tables that say which crate owns what. The README's — in
/// `docs/how-it-works.md` since 2026-10-27 — had lost three crates: `hlb-backup-run`,
/// `hlb-bitwarden`, `hlb-termix`, and nothing said so: a search that starts from it
/// does not find them.
#[test]
fn every_crate_is_named_where_the_crates_are_listed() {
    let root = repo_root();
    let crates = crate_names(&root);
    assert!(
        crates.len() >= 30,
        "only {} crates walked — an empty walk names nothing missing",
        crates.len()
    );
    for doc in ["docs/how-it-works.md", "CLAUDE.md"] {
        let text = std::fs::read_to_string(root.join(doc)).unwrap_or_default();
        let mut missing: Vec<&String> = crates
            .iter()
            .filter(|c| !text.contains(&format!("`{c}`")))
            .collect();
        missing.sort();
        assert!(
            missing.is_empty(),
            "{doc} does not name {} crate(s): {missing:?} — add each to its table of \
             crates, with what it owns",
            missing.len()
        );
    }
}

/// The scan would pass every assertion above if it walked nothing.
#[test]
fn the_scan_actually_reaches_the_rules() {
    let rules = rule_files();
    assert!(
        rules.len() >= 8,
        "only {} rules walked, expected at least the eight domain files — an empty walk \
         passes every assertion above it",
        rules.len()
    );

    let with_paths = rules
        .iter()
        .filter(|r| frontmatter(&std::fs::read_to_string(r).unwrap_or_default()).is_some())
        .count();
    assert!(
        with_paths >= 8,
        "only {with_paths} frontmatters parsed — the parser is failing open, which \
         makes every check above it vacuous"
    );
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .unwrap_or_default()
}

fn rule_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_markdown(&repo_root().join(".claude/rules"), &mut out);
    out.sort();
    out
}

/// Walked, never listed by hand — rules are discovered recursively by Claude Code too.
fn collect_markdown(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_markdown(&path, out);
        } else if path.extension().is_some_and(|x| x == "md") {
            out.push(path);
        }
    }
}

fn crate_names(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root.join("crates")) else {
        return out;
    };
    for entry in entries.flatten() {
        if entry.path().join("Cargo.toml").exists() {
            out.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    out
}

/// Every `command` string under `hooks.<Event>[].hooks[]`, whatever the events are.
///
/// Walked rather than reading a known event name: a hook moved to another event would
/// otherwise stop being checked without anything saying so.
fn hook_commands(settings: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(events) = settings.get("hooks").and_then(|h| h.as_object()) else {
        return out;
    };
    for matchers in events.values() {
        for matcher in matchers.as_array().into_iter().flatten() {
            for hook in matcher
                .get("hooks")
                .and_then(|h| h.as_array())
                .into_iter()
                .flatten()
            {
                if let Some(command) = hook.get("command").and_then(|c| c.as_str()) {
                    out.push(command.to_string());
                }
            }
        }
    }
    out
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

fn name_of(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The YAML block between the opening `---` and the next one.
fn frontmatter(source: &str) -> Option<Frontmatter> {
    let rest = source.strip_prefix("---\n")?;
    let end = rest.find("\n---")?;
    serde_yaml_ng::from_str(&rest[..end]).ok()
}

/// `a/{b,c}/d` becomes `a/b/d` and `a/c/d`. Nested groups expand too.
fn brace_expand(pattern: &str) -> Vec<String> {
    let Some(open) = pattern.find('{') else {
        return vec![pattern.to_string()];
    };
    let Some(close) = pattern[open..].find('}').map(|i| open + i) else {
        return vec![pattern.to_string()];
    };
    let mut out = Vec::new();
    for option in pattern[open + 1..close].split(',') {
        let rebuilt = format!("{}{option}{}", &pattern[..open], &pattern[close + 1..]);
        out.extend(brace_expand(&rebuilt));
    }
    out
}

/// Everything before the first wildcard, cut back to a directory boundary.
///
/// `crates/hlb-api/**/*.rs` gives `crates/hlb-api`, `clippy.toml` gives itself, and
/// `**/Cargo.toml` gives nothing — it is wildcard from the start and cannot drift.
fn literal_prefix(pattern: &str) -> Option<String> {
    let head = match pattern.find(['*', '?', '[']) {
        Some(i) => pattern[..i].rsplit_once('/').map(|(d, _)| d)?,
        None => pattern,
    };
    (!head.is_empty()).then(|| head.to_string())
}
