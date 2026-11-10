//! Every plan the house builds says where a vital app's databases go.
//!
//! `InstallParams::vital_postgres` defaults to false, so a site that builds a plan with
//! `..Default::default()` and forgets it places a vital app's databases on the shared
//! server once the vital one runs: the executor refuses it there (`DatabaseElsewhere`)
//! — every upgrade of Vaultwarden refused, from that one site. Found by walking the
//! sources, not from a list of the sites.

mod scan;

use scan::{code_only, crates_root, rust_files, short};

/// The struct literals of `InstallParams` in `code`, each up to its closing brace.
fn literals(code: &str) -> Vec<&str> {
    let head = format!("{}Params {{", "Install");
    let mut out = Vec::new();
    for (at, _) in code.match_indices(&head) {
        // The definition and its impls are not literals.
        let before = code[..at].trim_end();
        if before.ends_with("struct") || before.ends_with("for") || before.ends_with("impl") {
            continue;
        }
        let body = &code[at + head.len()..];
        let mut depth = 1;
        let end = body
            .char_indices()
            .find(|(_, c)| {
                match c {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
                depth == 0
            })
            .map_or(body.len(), |(i, _)| i);
        out.push(&body[..end]);
    }
    out
}

#[test]
fn the_matcher_sees_a_literal_and_skips_the_definition() {
    let field = format!("vital_{}", "postgres");
    let code = format!(
        "pub struct InstallParams {{ pub {field}: bool }}\n\
         impl Default for InstallParams {{ fn default() -> Self {{ todo!() }} }}\n\
         let p = hlb_resolver::InstallParams {{ domain: f(x), ..Default::default() }};\n\
         let q = InstallParams {{ {field}: g().await?, ..Default::default() }};"
    );
    let found = literals(&code);
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(!found[0].contains(&field));
    assert!(found[1].contains(&field));
}

#[test]
fn every_plan_built_outside_tests_names_the_vital_server() {
    let field = format!("vital_{}", "postgres");
    let mut read = 0;
    let mut silent = Vec::new();
    for file in rust_files(&crates_root()) {
        if file.components().any(|c| c.as_os_str() == "tests") {
            continue;
        }
        let source = std::fs::read_to_string(&file).unwrap_or_default();
        let production = code_only(source.split("\n#[cfg(test)]").next().unwrap_or(""));
        for literal in literals(&production) {
            read += 1;
            if !literal.contains(&field) {
                silent.push(short(&file));
            }
        }
    }
    // The CLI's four, privd's two, the lifeboat's: a scan finding none passes on nothing.
    assert!(read >= 7, "only {read} literals found in the sources");
    assert!(
        silent.is_empty(),
        "a plan built without saying where a vital app's databases go — \
         `hlb_engine::install::vital_postgres(state)`:\n  {}",
        silent.join("\n  ")
    );
}
