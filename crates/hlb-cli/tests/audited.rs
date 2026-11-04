//! Every verb that changes something leaves an audit entry.
//!
//! 🔴 Found by review: `remove`, `stop`, `scale`, `ack --force`, `backup dest add`,
//! `secrets-rekey` and a dozen more changed the installation and wrote nothing, while
//! the controller audited the same actions. A list of the verbs that must audit would
//! drift like the thirteen before it, so the verbs are read from the source: every
//! leaf of a `Subcommand` enum, the code its match arm runs — the crate's own functions
//! it calls, followed — and the code after the `match` in the function holding the arm,
//! where a module audits once for all its verbs. A verb that takes `--apply`, or calls
//! a `State` method writing SQL, must reach `.audit(`.

#![allow(clippy::expect_used)]

#[path = "../../hlb-types/tests/scan/mod.rs"]
mod scan;

use std::collections::{BTreeMap, BTreeSet};

/// Verbs that change something without being a decision worth an entry, and why. A
/// verb here that starts auditing must leave, so the list cannot outgrow its reasons.
const EXEMPT: &[(&str, &str)] = &[
    (
        "Command::Todo",
        "records what a check observed, decided by nobody",
    ),
    ("Command::Assert", "records what a reading observed"),
    ("MailCmd::Dns", "records what the DNS lookups observed"),
    ("MailCmd::Queue", "records what Stalwart's queue holds"),
    (
        "DomainCmd::Watch",
        "records what the DNS and the registry answered",
    ),
    (
        "NodeCmd::Deps",
        "runs on a machine before it joins: there is no state on it to write to",
    ),
    (
        "StorageCmd::Init",
        "runs on the storage node, which holds no state",
    ),
    (
        "ReplCmd::Failover",
        "prints a procedure for a person to run; it changes nothing",
    ),
    (
        "CatalogCmd::Images",
        "writes the catalog's files in the repository, which git records",
    ),
];

fn ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The index just past the brace or parenthesis closing the one at `open`.
fn close(s: &[char], open: usize) -> usize {
    let (o, c) = (s[open], if s[open] == '{' { '}' } else { ')' });
    let mut depth = 0;
    for (i, ch) in s.iter().enumerate().skip(open) {
        if *ch == o {
            depth += 1;
        } else if *ch == c {
            depth -= 1;
            if depth == 0 {
                return i + 1;
            }
        }
    }
    s.len()
}

fn find(s: &[char], from: usize, needle: &str) -> Option<usize> {
    let n: Vec<char> = needle.chars().collect();
    (from..s.len().saturating_sub(n.len() - 1)).find(|&i| s[i..i + n.len()] == n[..])
}

fn text(s: &[char]) -> String {
    s.iter().collect()
}

struct Source {
    /// Each module's code, strings and comments blanked.
    code: BTreeMap<String, Vec<char>>,
    /// (module, function) → the span of its body.
    fns: BTreeMap<(String, String), (usize, usize)>,
    /// Each module's brace pairs.
    pairs: BTreeMap<String, Vec<(usize, usize)>>,
}

impl Source {
    fn read() -> Self {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut code = BTreeMap::new();
        for p in scan::rust_files(&dir) {
            let raw = std::fs::read_to_string(&p).expect("source");
            let prod = raw.split("\n#[cfg(test)]").next().unwrap_or("");
            let module = p
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            code.insert(module, scan::code_only(prod).chars().collect::<Vec<_>>());
        }
        let mut fns = BTreeMap::new();
        let mut pairs = BTreeMap::new();
        for (module, s) in &code {
            let mut stack = Vec::new();
            let mut p = Vec::new();
            for (i, c) in s.iter().enumerate() {
                match c {
                    '{' => stack.push(i),
                    '}' => {
                        if let Some(o) = stack.pop() {
                            p.push((o, i + 1));
                        }
                    }
                    _ => {}
                }
            }
            pairs.insert(module.clone(), p);
            let mut from = 0;
            while let Some(at) = find(s, from, "fn ") {
                from = at + 3;
                if at > 0 && ident(s[at - 1]) {
                    continue;
                }
                let name: String = s[at + 3..].iter().take_while(|c| ident(**c)).collect();
                let (Some(open), semi) = (find(s, at, "{"), find(s, at, ";")) else {
                    continue;
                };
                if semi.is_some_and(|semi| semi < open) || name.is_empty() {
                    continue;
                }
                let end = close(s, open);
                // The dispatcher in `main` holds every arm: followed, it would credit
                // each verb with every other verb's audit.
                if text(&s[open..end]).contains("Command::Catalog") {
                    continue;
                }
                fns.entry((module.clone(), name)).or_insert((open, end));
            }
        }
        Source { code, fns, pairs }
    }

    /// The crate's functions `code` calls: `f(`, `module::f(` — never a method.
    fn calls(&self, module: &str, code: &[char]) -> BTreeSet<(String, String)> {
        let mut out = BTreeSet::new();
        for (i, c) in code.iter().enumerate() {
            if *c != '(' {
                continue;
            }
            let mut j = i;
            while j > 0 && code[j - 1].is_whitespace() {
                j -= 1;
            }
            let end = j;
            while j > 0 && ident(code[j - 1]) {
                j -= 1;
            }
            if j == end {
                continue;
            }
            let name = text(&code[j..end]);
            let mut path = Vec::new();
            let mut k = j;
            while k >= 2 && code[k - 1] == ':' && code[k - 2] == ':' {
                let seg_end = k - 2;
                let mut seg = seg_end;
                while seg > 0 && ident(code[seg - 1]) {
                    seg -= 1;
                }
                path.push(text(&code[seg..seg_end]));
                k = seg;
            }
            if k > 0 && code[k - 1] == '.' {
                continue;
            }
            let target = path
                .iter()
                .find(|p| !matches!(p.as_str(), "crate" | "self" | "super"))
                .cloned();
            let key = (
                target.clone().unwrap_or_else(|| module.into()),
                name.clone(),
            );
            if self.fns.contains_key(&key) {
                out.insert(key);
            } else if target.is_none() && self.fns.contains_key(&("main".into(), name.clone())) {
                out.insert(("main".into(), name));
            }
        }
        out
    }

    /// `code` and the bodies of the crate functions it reaches.
    fn closure(
        &self,
        module: &str,
        code: &[char],
        depth: u8,
        seen: &mut BTreeSet<(String, String)>,
    ) -> String {
        let mut out = text(code);
        if depth == 0 {
            return out;
        }
        for key in self.calls(module, code) {
            if !seen.insert(key.clone()) {
                continue;
            }
            let (s, e) = self.fns[&key];
            let body = &self.code[&key.0][s..e];
            out.push_str(&self.closure(&key.0, body, depth - 1, seen));
        }
        out
    }

    /// Everything a verb runs, reached from each place its variant is matched.
    fn scope(&self, variant: &str) -> String {
        let mut out = String::new();
        for (module, s) in &self.code {
            let mut from = 0;
            while let Some(at) = find(s, from, variant) {
                from = at + variant.chars().count();
                let after = from;
                if (at > 0 && ident(s[at - 1])) || s.get(after).is_some_and(|c| ident(*c)) {
                    continue;
                }
                let mut k = after;
                while k < s.len() && s[k].is_whitespace() {
                    k += 1;
                }
                if k < s.len() && (s[k] == '{' || s[k] == '(') {
                    k = close(s, k);
                }
                let before = text(&s[at.saturating_sub(12)..at]);
                let mut seen = BTreeSet::new();
                if before.contains("if let") {
                    if let Some(open) = find(s, k, "{") {
                        out.push_str(&self.closure(module, &s[open..close(s, open)], 5, &mut seen));
                    }
                    continue;
                }
                let Some(arrow) = find(s, k, "=>") else {
                    continue;
                };
                let between = text(&s[k..arrow]);
                if arrow - k > 400 || between.contains(';') || between.contains('{') {
                    continue;
                }
                let mut a = arrow + 2;
                while a < s.len() && s[a].is_whitespace() {
                    a += 1;
                }
                let arm_end = if s.get(a) == Some(&'{') {
                    close(s, a)
                } else {
                    find(s, a, "\n").unwrap_or(s.len())
                };
                out.push_str(&self.closure(module, &s[a..arm_end], 5, &mut seen));
                // A module matching its verbs to values and auditing once after the
                // `match`: that tail is the verb's too.
                let enclosing = self
                    .fns
                    .iter()
                    .filter(|((m, _), (o, e))| m == module && *o <= at && at < *e)
                    .map(|(_, span)| *span)
                    .min_by_key(|(o, e)| e - o);
                if let Some((_, fn_end)) = enclosing {
                    let the_match = self.pairs[module]
                        .iter()
                        .filter(|(o, e)| *o < at && at < *e)
                        .filter(|(o, _)| {
                            let line = s[..*o].iter().rposition(|c| *c == '\n').unwrap_or(0);
                            text(&s[line..*o]).contains("match ")
                        })
                        .max_by_key(|(o, _)| *o);
                    if let Some((_, end)) = the_match {
                        if *end < fn_end {
                            out.push_str(&self.closure(module, &s[*end..fn_end], 5, &mut seen));
                        }
                    }
                }
            }
        }
        out
    }
}

/// `State`'s methods that write: their SQL inserts, updates or deletes, or they call
/// one that does — a private helper holding the SQL hid `verify_guide` from the scan.
fn state_writers() -> BTreeSet<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../hlb-state/src/lib.rs");
    let raw = std::fs::read_to_string(path).expect("hlb-state");
    // Its tests write too, and are nobody's verb.
    let raw = raw.split("\n#[cfg(test)]").next().unwrap_or_default();
    // Every method of the impl, public or not, and its body up to the next one.
    let mut methods: Vec<(String, String)> = Vec::new();
    for line in raw.lines() {
        let head = [
            "    pub async fn ",
            "    pub fn ",
            "    async fn ",
            "    fn ",
        ]
        .iter()
        .find_map(|m| line.strip_prefix(m));
        match head {
            Some(rest) => methods.push((
                rest.chars().take_while(|c| ident(*c)).collect(),
                String::new(),
            )),
            None => {
                if let Some((_, body)) = methods.last_mut() {
                    body.push_str(line);
                    body.push('\n');
                }
            }
        }
    }
    let mut out: BTreeSet<String> = methods
        .iter()
        .filter(|(_, body)| {
            ["INSERT ", "UPDATE ", "DELETE ", "REPLACE "]
                .iter()
                .any(|sql| body.contains(sql))
        })
        .map(|(name, _)| name.clone())
        .collect();
    loop {
        let before = out.len();
        for (name, body) in &methods {
            if out.iter().any(|w| body.contains(&format!("self.{w}("))) {
                out.insert(name.clone());
            }
        }
        if out.len() == before {
            return out;
        }
    }
}

/// Every leaf of every `Subcommand` enum: (`Enum::Variant`, takes `--apply`).
fn leaves(src: &Source) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for s in src.code.values() {
        let mut from = 0;
        while let Some(at) = find(s, from, "#[derive(") {
            from = at + 1;
            let attr_end = find(s, at, ")]").unwrap_or(s.len());
            if !text(&s[at..attr_end]).contains("Subcommand") {
                continue;
            }
            let Some(e) = find(s, attr_end, "enum ") else {
                continue;
            };
            let name: String = s[e + 5..].iter().take_while(|c| ident(**c)).collect();
            let Some(open) = find(s, e, "{") else {
                continue;
            };
            let end = close(s, open);
            let mut i = open + 1;
            let mut depth = 0;
            while i < end - 1 {
                let c = s[i];
                if depth == 0 && c == '#' {
                    i = find(s, i, "]").map_or(end, |j| j + 1);
                    continue;
                }
                if depth == 0 && c.is_ascii_uppercase() && !ident(s[i - 1]) {
                    let variant: String = s[i..].iter().take_while(|c| ident(**c)).collect();
                    let mut k = i + variant.len();
                    while s[k].is_whitespace() {
                        k += 1;
                    }
                    match s[k] {
                        // A group: its own enum's leaves are walked.
                        '(' => i = close(s, k),
                        '{' => {
                            let fields_end = close(s, k);
                            let fields = text(&s[k..fields_end]);
                            let apply = fields.match_indices("apply").any(|(j, _)| {
                                let prev = fields[..j].chars().last();
                                !prev.is_some_and(ident)
                                    && fields[j + 5..].trim_start().starts_with(':')
                            });
                            out.push((format!("{name}::{variant}"), apply));
                            i = fields_end;
                        }
                        _ => {
                            out.push((format!("{name}::{variant}"), false));
                            i = k;
                        }
                    }
                    continue;
                }
                match c {
                    '{' | '(' => depth += 1,
                    '}' | ')' => depth -= 1,
                    _ => {}
                }
                i += 1;
            }
        }
    }
    out
}

fn method_calls(code: &str) -> BTreeSet<String> {
    code.match_indices('.')
        .filter_map(|(i, _)| {
            let name: String = code[i + 1..].chars().take_while(|c| ident(*c)).collect();
            code[i + 1 + name.len()..]
                .trim_start()
                .starts_with('(')
                .then_some(name)
        })
        .collect()
}

#[test]
fn every_verb_that_changes_something_is_audited() {
    let src = Source::read();
    let writers = state_writers();
    let leaves = leaves(&src);
    // 🔴 The floor under the scan: a parser that stopped finding verbs would pass.
    assert!(
        writers.len() > 50,
        "only {} writing State methods",
        writers.len()
    );
    assert!(leaves.len() > 120, "only {} verbs read", leaves.len());

    let mut changing = 0;
    let mut audited = 0;
    let mut missing = Vec::new();
    let mut flagged = BTreeSet::new();
    for (variant, apply) in &leaves {
        let scope = src.scope(variant);
        assert!(!scope.is_empty(), "{variant}: no match arm found");
        let writes: Vec<String> = method_calls(&scope)
            .intersection(&writers)
            .cloned()
            .collect();
        if !*apply && writes.is_empty() {
            continue;
        }
        changing += 1;
        if scope.contains(".audit(") {
            audited += 1;
            continue;
        }
        flagged.insert(variant.clone());
        if !EXEMPT.iter().any(|(v, _)| v == variant) {
            missing.push(format!(
                "{variant}{}{}",
                if *apply { " (--apply)" } else { "" },
                if writes.is_empty() {
                    String::new()
                } else {
                    format!(" writes through {}", writes.join(", "))
                }
            ));
        }
    }
    assert!(
        changing > 80,
        "only {changing} verbs seen changing anything"
    );
    assert!(audited > 70, "only {audited} audits found");
    for known in ["Command::SecretGet", "Command::Remove", "UserCmd::Add"] {
        assert!(
            leaves.iter().any(|(v, _)| v == known),
            "{known} was not read as a verb"
        );
        assert!(
            src.scope(known).contains(".audit("),
            "{known}'s audit not seen"
        );
    }
    assert!(
        missing.is_empty(),
        "verbs changing the installation without an audit entry:\n{}",
        missing.join("\n")
    );
    let stale: Vec<&str> = EXEMPT
        .iter()
        .map(|(v, _)| *v)
        .filter(|v| !flagged.contains(*v))
        .collect();
    assert!(stale.is_empty(), "exempted, and audited or gone: {stale:?}");
}
