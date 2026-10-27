//! What counts as a domain name, for every way one comes in.
//!
//! A domain typed into an install — over HTTP, on the command line, in the exposure —
//! is written into the Caddyfile as is. 🔴 One carrying a newline or a brace there
//! opens a site block of its own: a `file_server` over Caddy's `/config`, which holds
//! the DNS provider's token. One validator, called by every entry point, so a new one
//! cannot be the door the others close.

/// `raw` made canonical — trimmed, lower case, without a final dot — or why it is not
/// a domain name: at least two labels of letters, digits and inner hyphens, never
/// `*.` nor a scheme.
pub fn parse(raw: &str) -> Result<String, String> {
    let d = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if is_domain(&d) {
        Ok(d)
    } else {
        Err(format!(
            "\"{}\" is not a domain name — lowercase labels separated by dots, without \
             \"*.\" or a scheme",
            raw.escape_debug()
        ))
    }
}

/// A name DNS allows, at least two labels: `example.org`, never `*.example.org`.
pub fn is_domain(d: &str) -> bool {
    d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

/// A host a site may answer at: a domain name, or a wildcard one label deep over one.
pub fn is_host(h: &str) -> bool {
    is_domain(h.strip_prefix("*.").unwrap_or(h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_domain_is_made_canonical() {
        assert_eq!(
            parse(" Git.Example.ORG. ").as_deref(),
            Ok("git.example.org")
        );
    }

    #[test]
    fn what_would_open_a_caddyfile_block_is_not_a_domain() {
        for bad in [
            "git.example.org {\n\tfile_server\n}\nx.example.org",
            "git.example.org}",
            "git example.org",
            "git.example.org/admin",
            "https://git.example.org",
            "*.example.org",
            "localhost",
            "-bad.example.org",
            "",
            "{{ domain }}",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn a_refusal_shows_a_newline_escaped() {
        let refusal = parse("a.org\nb").expect_err("refused");
        assert!(!refusal.contains('\n'), "{refusal}");
    }

    #[test]
    fn a_host_is_a_domain_or_a_wildcard_over_one() {
        assert!(is_host("git.example.org"));
        assert!(is_host("*.example.org"));
        assert!(!is_host("*.*.example.org"));
        assert!(!is_host("git.example.org {"));
        assert!(!is_host("{{ domain }}"));
    }
}
