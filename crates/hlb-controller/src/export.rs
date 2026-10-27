//! CSV export of the tabular views (batch 11.5).
//!
//! ## Why CSV and not JSON
//!
//! JSON is already there: every API route returns it. What is missing is what you open
//! in a spreadsheet to sort, filter and hand to someone — an audit log to re-read after
//! an incident, an inventory of accounts to compare.
//!
//! ## 🔴 No secret value is exportable
//!
//! The export carries the same types as the API, and those types have no field for a
//! secret value. The guarantee is not in this file: it is in the types, and it travels
//! through the export without anyone having to think about it.

/// Escapes a CSV field (RFC 4180).
///
/// 🔴 A field containing a comma, a quote or a newline SHIFTS every following column if
/// it is not quoted. The audit log holds details written by humans: commas and quotes are
/// the norm there, not the exception.
///
/// 🔴 And a field a spreadsheet would read as a FORMULA — starting with `=`, `+`, `-`,
/// `@`, a tab or a carriage return — is given a leading `'`: an account name or an
/// audit detail typed by anyone (`=HYPERLINK(…)`) ran in the administrator's
/// spreadsheet the day they opened the export. A number stays a number.
pub fn field(v: &str) -> String {
    let formula = v.starts_with(['=', '+', '-', '@', '\t', '\r']) && v.parse::<f64>().is_err();
    let v = if formula {
        std::borrow::Cow::Owned(format!("'{v}"))
    } else {
        std::borrow::Cow::Borrowed(v)
    };
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

/// One CSV row.
pub fn line(fields: &[&str]) -> String {
    let mut s = fields
        .iter()
        .map(|c| field(c))
        .collect::<Vec<_>>()
        .join(",");
    // ⚠️ CRLF, as the RFC demands: otherwise Excel on Windows merges the rows.
    s.push_str("\r\n");
    s
}

/// The audit log, as CSV.
pub fn audit(entries: &[hlb_state::AuditRecord]) -> String {
    let mut s = line(&[
        "when", "actor", "role", "action", "target", "outcome", "detail",
    ]);
    for e in entries {
        s.push_str(&line(&[
            &e.at,
            &e.actor,
            &e.role,
            &e.action,
            &e.target,
            &e.outcome,
            e.detail.as_deref().unwrap_or(""),
        ]));
    }
    s
}

/// The backups, as CSV.
pub fn backups(runs: &[hlb_state::BackupRun]) -> String {
    let mut s = line(&[
        "when",
        "app",
        "kind",
        "destination",
        "snapshot",
        "outcome",
        "error",
    ]);
    for r in runs {
        s.push_str(&line(&[
            &r.finished_at,
            &r.app,
            &r.kind,
            r.destination.as_deref().unwrap_or(""),
            r.snapshot_id.as_deref().unwrap_or(""),
            &r.status,
            r.error.as_deref().unwrap_or(""),
        ]));
    }
    s
}

/// The accounts, as CSV.
pub fn accounts(accounts: &[hlb_api::AccountSummary]) -> String {
    let mut s = line(&[
        "name",
        "role",
        "level",
        "coherence",
        "mailboxes",
        "active_aliases",
        // 🔴 The column that counts: expired aliases that STILL receive. An export
        // omitting it would have you re-read a reassuring inventory.
        "broken_promises",
        "sessions",
    ]);
    for c in accounts {
        let mailboxes: Vec<&str> = c.mailboxes.iter().map(|b| b.address.as_str()).collect();
        s.push_str(&line(&[
            &c.name,
            c.role.as_deref().unwrap_or(""),
            &c.level,
            &format!("{:?}", c.coherence),
            &mailboxes.join(" "),
            &c.active_aliases.to_string(),
            &c.broken_promises.to_string(),
            &c.sessions.to_string(),
        ]));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_a_spreadsheet_would_run_is_written_as_text() {
        assert_eq!(field("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(field("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(field("+1-2"), "'+1-2");
        assert_eq!(field("-12"), "-12", "a number stays a number");
        assert_eq!(field("lena"), "lena");
    }

    #[test]
    fn a_field_with_a_comma_never_shifts_the_columns() {
        // 🔴 The audit log holds details written by humans: commas and quotes are the
        // norm there. An unquoted field shifts EVERY following column, and the table
        // becomes wrong without looking broken.
        assert_eq!(field("simple"), "simple");
        assert_eq!(field("one, two"), "\"one, two\"");
        assert_eq!(field("they said \"no\""), "\"they said \"\"no\"\"\"");
        assert_eq!(field("two\nlines"), "\"two\nlines\"");
    }

    #[test]
    fn the_line_ending_is_crlf_as_the_standard_demands() {
        // ⚠️ Excel on Windows merges rows separated by a plain LF.
        assert!(line(&["a", "b"]).ends_with("\r\n"));
        assert_eq!(line(&["a", "b"]), "a,b\r\n");
    }

    #[test]
    fn an_empty_table_still_carries_its_header() {
        // An empty file reads as "the export failed". A file with only the header reads
        // as "there was nothing", which is information.
        let csv = audit(&[]);
        assert!(csv.starts_with("when,actor,role"));
        assert_eq!(csv.lines().count(), 1);
    }

    #[test]
    fn nothing_in_the_exported_types_can_carry_a_secret_value() {
        // 🔴 The guarantee lives in the API's TYPES, not in this exporter: they have no
        // field for a value. This test is the reminder, right where one would be tempted
        // to add a "handy" column.
        let header = audit(&[]);
        for forbidden in ["value", "secret", "password", "token"] {
            assert!(!header.contains(forbidden), "column \"{forbidden}\"");
        }
    }
}
