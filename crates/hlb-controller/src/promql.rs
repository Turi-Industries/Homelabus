//! The relay to VictoriaMetrics, and its allowlist.
//!
//! ## Why a relay rather than direct access
//!
//! The interface could query VictoriaMetrics itself. Three reasons not to:
//!
//!
//! 1. **VictoriaMetrics is private**: it is not exposed, and opening it for the
//!    interface would open it for everyone.
//! 2. **A single authentication.** The interface already carries a token or a session
//!    for the controller; making it carry a second one for the time-series database
//!    would double the surface and the chances of a leak.
//! 3. **The filtering.** See below.
//!
//! ## 🔴 An open PromQL relay is exfiltration
//!
//! PromQL is not an innocuous language. `{__name__=~".+"}` returns the **whole**
//! database, and labels carry hostnames, file paths, app names — the complete map of the
//! installation, served to anyone with a `viewer` token.
//!
//! Hence an **allowlist of metrics**, and not a denylist of dangerous patterns: you
//! cannot enumerate what is dangerous, you can enumerate what is useful. An unknown
//! metric is refused while naming the ones that exist, rather than leaving you to
//! search.

use std::time::Duration;

/// The metric prefixes the interface is allowed to query.
///
/// Three families, and nothing else:
/// - `hlb_*`: what the controller emits itself;
/// - `node_*`: node-exporter, the nodes' hardware health;
/// - `container_*`: cadvisor, the per-container statistics.
pub const PREFIXES: &[&str] = &["hlb_", "node_", "container_"];

/// The allowed PromQL functions.
///
/// ⚠️ An allowlist here too. `rate` and `irate` are indispensable for a counter; the
/// aggregations serve to reduce twenty series to one. Everything else is refused — not
/// because it is dangerous in itself, but because a query we did not plan for is a query
/// whose cost we do not know, and VictoriaMetrics runs on the same hardware as the apps.
///
pub const FUNCTIONS: &[&str] = &[
    "rate",
    "irate",
    "increase",
    "avg_over_time",
    "max_over_time",
    "min_over_time",
    "sum",
    "avg",
    "max",
    "min",
    "count",
    "topk",
    "by",
    "without",
];

/// What caused a query to be refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No recognised metric in the query.
    NoMetric,
    MetricNotAllowed(String),
    FunctionNotAllowed(String),
    /// Too long a range would make VictoriaMetrics sweep months of points, and it runs
    /// on the same hardware as the apps.
    RangeTooLong {
        requested_s: i64,
        max_s: i64,
    },
    TooManyPoints {
        request: i64,
        max: i64,
    },
    /// Something the interface never sends: a comment, a `__name__` matcher, a quoted
    /// name, a character outside PromQL's operators.
    Construct(String),
}

impl Refusal {
    pub fn describe(&self) -> String {
        match self {
            Self::NoMetric => format!(
                "no recognised metric. The names must start with {}",
                PREFIXES.join(", ")
            ),
            Self::MetricNotAllowed(m) => format!(
                "metric \"{m}\" not allowed. Only those starting with {} are — an open \
                 PromQL relay would return the whole database, labels included",
                PREFIXES.join(", ")
            ),
            Self::Construct(c) => format!(
                "{c} is not allowed here: every selector names a metric starting with \
                 {}, and nothing else is read",
                PREFIXES.join(", ")
            ),
            Self::FunctionNotAllowed(f) => format!(
                "function \"{f}\" not allowed. Available: {}",
                FUNCTIONS.join(", ")
            ),
            Self::RangeTooLong { requested_s, max_s } => format!(
                "range of {} requested, maximum {} — beyond that, go through Grafana, \
                 which is made for it",
                hlb_api::humanise(*requested_s),
                hlb_api::humanise(*max_s)
            ),
            Self::TooManyPoints { request, max } => format!(
                "{request} points requested, maximum {max} — a curve of more than {max} \
                 points does not read any better, it just costs more"
            ),
        }
    }
}

/// The longest queryable range: seven days.
///
/// Beyond that it is analysis, and Grafana is made for it: Homelabus aggregates and
/// connects, it does not replace.
pub const RANGE_MAX_S: i64 = 7 * 86_400;

/// The maximum number of points in a curve.
///
/// A sparkline of 500 points is already denser than the pixels available.
pub const POINTS_MAX: i64 = 500;

/// Checks a query is acceptable.
///
/// Deliberately coarse parsing — we do not reimplement a PromQL parser. We extract the
/// identifiers and check each is either an allowed metric, a known function, or a
/// keyword. Doubt goes to the **refusal**: a construct we do not recognise is rejected,
/// not let through.
pub fn check(q: &str, since_s: i64, step_s: i64) -> Result<(), Refusal> {
    // `since_s == 0`: an INSTANT query, not a range. It costs one point and therefore
    // has neither a range nor a point count to bound.
    if since_s == 0 {
        return check_expression(q);
    }
    if since_s > RANGE_MAX_S {
        return Err(Refusal::RangeTooLong {
            requested_s: since_s,
            max_s: RANGE_MAX_S,
        });
    }
    let points = if step_s > 0 {
        since_s / step_s
    } else {
        i64::MAX
    };
    if points > POINTS_MAX {
        return Err(Refusal::TooManyPoints {
            request: points,
            max: POINTS_MAX,
        });
    }

    check_expression(q)
}

/// Checks the expression alone, without the range bounds.
///
/// 🔴 EVERY selector names an allowed metric, and every function is one of
/// [`FUNCTIONS`]. Skipping what followed a `{` or a `,` let `{__name__=~"node_.+|.*"}`
/// through on the strength of a metric named beside it, and a MetricsQL comment
/// (`# hlb_up`) supplied the allowed name while the rest of the line selected anything.
fn check_expression(q: &str) -> Result<(), Refusal> {
    let toks = tokens(q)?;
    let mut seen_metric = false;
    let mut in_braces = false;
    let mut brackets = 0usize;
    let mut parens = 0usize;
    // The depth of the parenthesis a `by (…)`-style label list opened.
    let mut label_list: Option<usize> = None;

    for (i, t) in toks.iter().enumerate() {
        let prev = i.checked_sub(1).and_then(|p| toks.get(p));
        let next = toks.get(i + 1);
        match t {
            Tok::Ident(w) if w.starts_with("__") => {
                return Err(Refusal::Construct(format!("\"{w}\"")));
            }
            Tok::Ident(_) if in_braces || label_list.is_some() => {} // a label name
            Tok::Ident(w) if brackets > 0 => {
                return Err(Refusal::Construct(format!("\"{w}\" in a range")));
            }
            Tok::Ident(w) if LABEL_LISTS.contains(&w.as_str()) => {
                if next == Some(&Tok::Punct('(')) {
                    label_list = Some(parens + 1);
                }
            }
            Tok::Ident(w) if MODIFIERS.contains(&w.as_str()) => {}
            Tok::Ident(w) if SET_OPERATORS.contains(&w.as_str()) => {}
            Tok::Ident(w) if FUNCTIONS.contains(&w.as_str()) => {}
            Tok::Ident(w) if next == Some(&Tok::Punct('(')) => {
                return Err(Refusal::FunctionNotAllowed(w.clone()));
            }
            Tok::Ident(w) if PREFIXES.iter().any(|p| w.starts_with(p)) => seen_metric = true,
            Tok::Ident(w) => return Err(Refusal::MetricNotAllowed(w.clone())),
            Tok::Number => {}
            // A string is a matcher's value, and nothing else: `{"metric"}` names a
            // metric in Prometheus 3, and a string outside braces is a function's
            // argument no allowed function takes.
            Tok::Str => {
                if !(in_braces && matches!(prev, Some(Tok::Punct('=' | '~')))) {
                    return Err(Refusal::Construct("a quoted name".into()));
                }
            }
            Tok::Punct('{') => {
                // A selector without a metric's name selects every metric.
                let named = matches!(prev, Some(Tok::Ident(w))
                    if PREFIXES.iter().any(|p| w.starts_with(p)));
                if in_braces || !named {
                    return Err(Refusal::NoMetric);
                }
                in_braces = true;
            }
            Tok::Punct('}') => in_braces = false,
            Tok::Punct('[') => brackets += 1,
            Tok::Punct(']') => brackets = brackets.saturating_sub(1),
            Tok::Punct('(') => parens += 1,
            Tok::Punct(')') => {
                if label_list == Some(parens) {
                    label_list = None;
                }
                parens = parens.saturating_sub(1);
            }
            Tok::Punct(_) => {}
        }
    }

    if !seen_metric {
        return Err(Refusal::NoMetric);
    }
    Ok(())
}

/// Keywords followed by a list of label names.
const LABEL_LISTS: &[&str] = &[
    "by",
    "without",
    "on",
    "ignoring",
    "group_left",
    "group_right",
];

/// Keywords that modify what precedes them.
const MODIFIERS: &[&str] = &["offset", "bool"];

/// Operators joining two expressions, each held to the rules above on its own: they
/// read nothing themselves. `backup-absent` needs `unless` and `or`, and a rule the
/// relay refuses is a rule forever "unknown".
const SET_OPERATORS: &[&str] = &["and", "or", "unless"];

#[derive(Debug, PartialEq, Eq)]
enum Tok {
    Ident(String),
    /// A number or a duration: `5`, `0.5`, `5m`, `1h30m`.
    Number,
    Str,
    Punct(char),
}

/// A query's tokens, or the construct that has no place in one.
fn tokens(q: &str) -> Result<Vec<Tok>, Refusal> {
    let mut out = Vec::new();
    let mut chars = q.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {}
            '"' | '\'' | '`' => {
                let mut closed = false;
                while let Some(d) = chars.next() {
                    if d == '\\' && c != '`' {
                        chars.next();
                    } else if d == c {
                        closed = true;
                        break;
                    }
                }
                if !closed {
                    return Err(Refusal::Construct("an unterminated string".into()));
                }
                out.push(Tok::Str);
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let mut w = c.to_string();
                while let Some(&d) = chars.peek() {
                    if d.is_ascii_alphanumeric() || d == '_' || d == ':' {
                        w.push(d);
                        chars.next();
                    } else {
                        break;
                    }
                }
                out.push(Tok::Ident(w));
            }
            c if c.is_ascii_digit() || c == '.' => {
                while chars
                    .peek()
                    .is_some_and(|d| d.is_ascii_alphanumeric() || *d == '.' || *d == '_')
                {
                    chars.next();
                }
                out.push(Tok::Number);
            }
            '(' | ')' | '[' | ']' | '{' | '}' | ',' | '=' | '!' | '~' | '<' | '>' | '+' | '-'
            | '*' | '/' | '%' | '^' | ':' => out.push(Tok::Punct(c)),
            // `#` opens a comment in MetricsQL: what follows is read by nobody, and
            // anything else — `@`, `;` — is a construct the interface never sends.
            '#' => return Err(Refusal::Construct("a comment".into())),
            other => return Err(Refusal::Construct(format!("\"{other}\""))),
        }
    }
    Ok(out)
}

/// The VictoriaMetrics client.
pub struct Metrics {
    base_url: String,
    http: reqwest::Client,
}

impl Metrics {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            // Short: a graph query that drags blocks a screen. Better to say
            // "unavailable" than to make people wait.
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Queries an instant value.
    ///
    /// Used to evaluate the alert rules: we want "what is the value now", not a curve.
    ///
    ///
    /// ⚠️ Returns a `Result` and not a `Series`, unlike [`Self::range`]: here the caller
    /// MUST distinguish "the rule is 0" from "I could not evaluate it". Confusing them
    /// would give a green dashboard while collection is down — precisely what
    /// `Evaluation::Unknown` exists to prevent.
    pub async fn instant(&self, q: &str) -> Result<Vec<f64>, String> {
        // The allowlist applies to our own rules too: that is what guarantees no shipped
        // rule queries anything other than the expected metrics, including after an
        // absent-minded change.
        if let Err(r) = check(q, 0, 60) {
            return Err(r.describe());
        }

        let url = format!("{}/api/v1/query", self.base_url);
        let response = self.http.get(&url).query(&[("query", q)]).send().await;

        let text = match response {
            Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
            Ok(r) => return Err(format!("VictoriaMetrics answered {}", r.status())),
            Err(e) => return Err(format!("VictoriaMetrics unreachable ({e})")),
        };

        hlb_metrics::promql_values(&text).map_err(|e| e.to_string())
    }

    /// [`Self::instant`], each series with its labels: what names the app or node
    /// that crossed a threshold.
    pub async fn instant_samples(&self, q: &str) -> Result<Vec<hlb_metrics::Sample>, String> {
        if let Err(r) = check(q, 0, 60) {
            return Err(r.describe());
        }
        let url = format!("{}/api/v1/query", self.base_url);
        let text = match self.http.get(&url).query(&[("query", q)]).send().await {
            Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
            Ok(r) => return Err(format!("VictoriaMetrics answered {}", r.status())),
            Err(e) => return Err(format!("VictoriaMetrics unreachable ({e})")),
        };
        hlb_metrics::promql_samples(&text).map_err(|e| e.to_string())
    }

    /// Queries a time range.
    ///
    /// Always returns an [`hlb_api::Series`] — never an error. An unreachable time-series
    /// database is not a controller outage: it is information to display.
    pub async fn range(
        &self,
        q: &str,
        since_s: i64,
        step_s: i64,
        unit: hlb_api::Unit,
        now: i64,
    ) -> hlb_api::Series {
        if let Err(r) = check(q, since_s, step_s) {
            return hlb_api::Series::Unavailable {
                reason: r.describe(),
            };
        }

        let url = format!("{}/api/v1/query_range", self.base_url);
        let start = now - since_s;
        let response = self
            .http
            .get(&url)
            .query(&[
                ("query", q),
                ("start", &start.to_string()),
                ("end", &now.to_string()),
                ("step", &format!("{step_s}s")),
            ])
            .send()
            .await;

        let text = match response {
            Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
            Ok(r) => {
                return hlb_api::Series::Unavailable {
                    reason: format!("VictoriaMetrics answered {}", r.status()),
                }
            }
            Err(e) => {
                return hlb_api::Series::Unavailable {
                    // The raw message talks about network layers; what you need to know
                    // is whether the time-series database is deployed.
                    reason: format!(
                        "VictoriaMetrics unreachable ({e}). Is it installed? \
                         \"hlb install victoriametrics --apply\""
                    ),
                };
            }
        };

        match parse_range(&text) {
            Some(points) if !points.is_empty() => hlb_api::Series::Points {
                name: q.to_string(),
                points,
                unit,
            },
            // 🔴 A valid query with no result is NOT an empty series: it is "the metric
            // does not exist yet", which happens all the time before the first scrape.
            // Saying so avoids looking for an outage.
            Some(_) => hlb_api::Series::Unavailable {
                reason: "no measurement over this period — does the metric exist?".into(),
            },
            None => hlb_api::Series::Unavailable {
                reason: "unreadable response from VictoriaMetrics".into(),
            },
        }
    }
}

/// Extracts the points from an `/api/v1/query_range` response.
///
/// Minimal parsing, like `hlb_metrics::promql_values`: the shape is stable and
/// documented, and one more dependency to read three fields is not justified.
pub fn parse_range(json: &str) -> Option<Vec<(i64, f64)>> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    if v.get("status")?.as_str()? != "success" {
        return None;
    }
    let results = v.get("data")?.get("result")?.as_array()?;

    // ⚠️ We take the FIRST series. A query returning several should aggregate
    // (`sum by (…)`): stacking them here would draw a curve jumping from one series to
    // another, which looks like erratic data.
    let Some(first) = results.first() else {
        return Some(Vec::new());
    };

    let mut points = Vec::new();
    for p in first.get("values")?.as_array()? {
        let pair = p.as_array()?;
        let t = pair.first()?.as_f64()? as i64;
        // The value is a STRING in the Prometheus format, not a number.
        let val: f64 = pair.get(1)?.as_str()?.parse().ok()?;
        // `NaN` crosses JSON as "NaN": keeping it would produce a hole invisible in
        // the curve.
        if val.is_finite() {
            points.push((t, val));
        }
    }
    Some(points)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shipped_rule_passes_the_relay_s_own_allowlist() {
        // 🔴 The alert loop queries through this check: a rule it refuses is evaluated
        // never, and reads "unknown" forever. `backup-absent` was, for its `or`.
        for r in hlb_metrics::rules::default_rules() {
            assert_eq!(check(r.query, 0, 60), Ok(()), "{}: {}", r.name, r.query);
        }
    }

    #[test]
    fn a_wildcard_query_is_refused() {
        // 🔴 `{__name__=~".+"}` returns the WHOLE database: hostnames, paths, app names
        // — the complete map of the installation, to anyone with a
        // `viewer`.
        let r = check(r#"{__name__=~".+"}"#, 3600, 60).expect_err("must refuse");
        assert!(
            matches!(r, Refusal::MetricNotAllowed(_) | Refusal::NoMetric),
            "{r:?}"
        );
    }

    #[test]
    fn every_selector_must_name_an_allowed_metric() {
        // 🔴 Each of these passed: what followed `{` or `,` was never read, and one
        // allowed name anywhere satisfied the whole query.
        for q in [
            r#"hlb_up + {__name__=~".+"}"#,
            r#"hlb_up{__name__=~"secret.*"}"#,
            r#"sum(hlb_up) + count({job="x"})"#,
            r#"hlb_up + {"secret_tokens_total"}"#,
            "hlb_up # comment\n+ secret_tokens_total",
            "secret_tokens_total # hlb_up",
            r#"hlb_up or on() {__name__!=""}"#,
            "label_replace(hlb_up, \"a\", \"b\", \"c\", \"d\")",
            "hlb_up[5m:secret]",
            "hlb_up @ start()",
            "rate(hlb_up[5m]) and secret_tokens_total",
        ] {
            assert!(check(q, 3600, 60).is_err(), "let through: {q}");
        }
    }

    #[test]
    fn what_the_interface_asks_still_passes() {
        for q in [
            "sum by (node) (rate(hlb_net_bytes_total[5m]))",
            "sum(rate(hlb_net_bytes_total[5m])) by (node)",
            r#"topk(5, container_memory_usage_bytes{name!=""})"#,
            "max_over_time(hlb_cpu_used_ratio[1h:5m])",
            "hlb_cpu_used_ratio offset 1h",
            "node_load1 / on (instance) group_left node_cpu_count",
            "hlb_disk_used_ratio > bool 0.9",
            r#"hlb_disk_used_ratio{node=~"small-.*",path!="/"} * 100"#,
        ] {
            assert!(check(q, 3600, 60).is_ok(), "wrongly refused: {q}");
        }
    }

    #[test]
    fn an_allowed_metric_passes() {
        for q in [
            "hlb_cpu_used_ratio",
            r#"hlb_disk_used_ratio{node="small-01"}"#,
            "rate(hlb_net_bytes_total[5m])",
            "sum(container_memory_usage_bytes)",
            r#"avg_over_time(node_load1{instance="n1"}[1h])"#,
        ] {
            assert!(check(q, 3600, 60).is_ok(), "wrongly refused: {q}");
        }
    }

    #[test]
    fn a_foreign_metric_is_refused_by_name() {
        // A DENYLIST cannot enumerate what is dangerous. The allowlist can — and the
        // message names what is possible rather than leaving you to search.
        let r = check("secret_tokens_total", 3600, 60).expect_err("must refuse");
        assert!(r.describe().contains("hlb_"), "{}", r.describe());
        assert!(
            r.describe().contains("secret_tokens_total"),
            "{}",
            r.describe()
        );
    }

    #[test]
    fn label_values_are_not_mistaken_for_metric_names() {
        // ⚠️ `node="small-01"`: neither "node" nor "small-01" is a metric. Treating
        // them as such would refuse perfectly legitimate queries, and you would end up
        // disabling the filter.
        assert!(check(
            r#"hlb_disk_used_ratio{node="postgres_secret",path="/"}"#,
            3600,
            60
        )
        .is_ok());
    }

    #[test]
    fn an_unknown_function_is_refused() {
        let r = check(
            "label_replace(hlb_app_up, \"a\", \"b\", \"c\", \"d\")",
            3600,
            60,
        )
        .expect_err("must refuse");
        assert!(r.describe().contains("label_replace"), "{}", r.describe());
    }

    #[test]
    fn a_query_without_any_metric_is_refused() {
        // Neither `1+1` nor a constant is of any use here, and letting a query with no
        // metric through would open the door to exotic constructs.
        assert_eq!(check("1 + 1", 3600, 60), Err(Refusal::NoMetric));
    }

    #[test]
    fn a_month_long_range_is_refused_with_a_pointer_to_grafana() {
        // Beyond seven days it is analysis — and VictoriaMetrics runs on the same
        // hardware as the apps.
        let r = check("hlb_cpu_used_ratio", 30 * 86_400, 3600).expect_err("must refuse");
        assert!(r.describe().contains("Grafana"), "{}", r.describe());
    }

    #[test]
    fn too_many_points_are_refused() {
        // A one-second step over a day = 86 400 points, for a sparkline of
        // 200 pixels.
        let r = check("hlb_cpu_used_ratio", 86_400, 1).expect_err("must refuse");
        assert!(matches!(r, Refusal::TooManyPoints { .. }), "{r:?}");
    }

    #[test]
    fn a_zero_step_does_not_divide_by_zero() {
        let r = check("hlb_cpu_used_ratio", 3600, 0).expect_err("must refuse");
        assert!(matches!(r, Refusal::TooManyPoints { .. }), "{r:?}");
    }

    #[test]
    fn a_prometheus_range_response_is_parsed() {
        let json = r#"{
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [{
                    "metric": {"__name__": "hlb_cpu_used_ratio", "node": "n1"},
                    "values": [[1700000000, "0.42"], [1700000060, "0.55"]]
                }]
            }
        }"#;
        let p = parse_range(json).expect("analysable");
        assert_eq!(p, vec![(1_700_000_000, 0.42), (1_700_000_060, 0.55)]);
    }

    #[test]
    fn values_are_strings_in_the_prometheus_format() {
        // ⚠️ The format's trap: the values are STRINGS, not numbers. Reading them with
        // `as_f64()` would return `None` on all of them, and the curve would be empty
        // no error at all.
        let json = r#"{"status":"success","data":{"result":[{"values":[[1,"3.5"]]}]}}"#;
        assert_eq!(parse_range(json), Some(vec![(1, 3.5)]));
    }

    #[test]
    fn a_nan_is_dropped_rather_than_drawn() {
        // `NaN` would produce an invisible hole in the curve — or a crash in the plot.
        let json = r#"{"status":"success","data":{"result":[{"values":[[1,"1.0"],[2,"NaN"],[3,"2.0"]]}]}}"#;
        assert_eq!(parse_range(json), Some(vec![(1, 1.0), (3, 2.0)]));
    }

    #[test]
    fn an_error_response_is_not_read_as_empty_data() {
        // An error read as "no data" would show "no measurement" when the query was at
        // fault.
        assert_eq!(
            parse_range(r#"{"status":"error","errorType":"bad_data","error":"parse error"}"#),
            None
        );
        assert_eq!(parse_range("not json"), None);
    }

    #[test]
    fn an_empty_result_is_distinguishable_from_a_parse_failure() {
        // `Some(vec![])` = the query worked and found nothing.
        // `None` = we could not read it. The two are displayed differently.
        assert_eq!(
            parse_range(r#"{"status":"success","data":{"result":[]}}"#),
            Some(Vec::new())
        );
    }
}
