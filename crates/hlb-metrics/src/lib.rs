//! Observability: scraping, alert rules and the deadman switch.
//!
//! ## What this crate adds, and what already existed
//!
//! The controller had exposed `/metrics` for a long time, and `hlb-notify` knew how to
//! push four-level notifications with quiet hours. The whole middle was missing:
//! **nobody read those metrics**. `hlb_backup_age_seconds` was emitted correctly and
//! consumed by nothing, no history was kept, and no threshold was evaluated.
//!
//! Three pieces fill that gap:
//!
//! - [`scrape`] - VictoriaMetrics' scrape configuration, which stores.
//! - [`rules`] - the thresholds, evaluated by Homelabus and routed to `hlb-notify`.
//! - [`deadman`] - the external watchdog, for when Homelabus itself is dead.
//!
//! ## 🔴 Why the last two do not replace each other
//!
//! [`rules`] runs **on** the controller. If the controller dies, none of its rules is
//! evaluated any more, and the silence is indistinguishable from everything being fine.
//! [`deadman`] exists precisely for that failure, and it is the only mechanism that
//! does not share the fate of what it watches.
//!
//! Conversely, the deadman says nothing about a disk at 90 % or a missed backup on an
//! otherwise living system. The two cover disjoint halves.

pub mod deadman;
pub mod rules;
pub mod scrape;

pub use deadman::{Beat, Emission, Health, Watch};
pub use rules::{Comparison, Evaluation, Rule};
pub use scrape::Target;

/// The crate's errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("VictoriaMetrics unreachable: {0}")]
    Unreachable(String),

    #[error("unreadable response: {0}")]
    Response(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Extracts the values from a PromQL `/api/v1/query` response.
///
/// 🔴 A **valid but empty** response (`"result": []`) returns an empty vector, never an
/// error. That is a legitimate state - the metric does not exist - and it is
/// [`Rule::judge`] that decides "no data" is not "all is well". Returning an error
/// here would confuse "the query failed" with "the response is empty", two situations
/// that call for different responses.
///
/// Deliberately minimal parsing: no JSON dependency for reading an array of numbers,
/// and the shape of this response has been stable since Prometheus 2.0.
pub fn promql_values(json: &str) -> Result<Vec<f64>> {
    if !json.contains("\"status\"") {
        return Err(Error::Response("this is not a PromQL response".into()));
    }
    if json.contains("\"status\":\"error\"") || json.contains("\"status\": \"error\"") {
        return Err(Error::Response(json.chars().take(200).collect()));
    }

    let mut v = Vec::new();
    // Each sample is `"value":[<timestamp>,"<value>"]`.
    for chunk in json.split("\"value\"").skip(1) {
        let Some(after) = chunk.split(',').nth(1) else {
            continue;
        };
        let raw: String = after
            .chars()
            .skip_while(|c| !c.is_ascii_digit() && *c != '-' && *c != '.')
            .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-' || *c == 'e')
            .collect();

        if let Ok(f) = raw.parse::<f64>() {
            v.push(f);
        }
    }
    Ok(v)
}

/// One series of an instant query: its labels and its value.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub labels: std::collections::BTreeMap<String, String>,
    pub value: f64,
}

/// The series of a PromQL `/api/v1/query` response, labels kept — what names WHICH
/// app or node crossed a threshold, where [`promql_values`] keeps only how far.
///
/// Same contract: an empty result is an empty vector, an error or something that is
/// no PromQL answer is an error, never a zero.
pub fn promql_samples(json: &str) -> Result<Vec<Sample>> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| Error::Response(e.to_string()))?;
    match v["status"].as_str() {
        Some("success") => {}
        Some(_) => return Err(Error::Response(json.chars().take(200).collect())),
        None => return Err(Error::Response("this is not a PromQL response".into())),
    }
    let Some(result) = v["data"]["result"].as_array() else {
        return Err(Error::Response("a PromQL answer with no result".into()));
    };
    let mut out = Vec::new();
    for series in result {
        // Prometheus values are strings: `as_f64()` reads none of them.
        let Some(value) = series["value"][1].as_str().and_then(|s| s.parse().ok()) else {
            continue;
        };
        let labels = series["metric"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        out.push(Sample { labels, value });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_keep_the_labels_that_name_their_subject() {
        let json = r#"{"status":"success","data":{"resultType":"vector","result":[
            {"metric":{"app":"gitea","status":"failed"},"value":[1755000000,"0"]},
            {"metric":{},"value":[1755000000,"1.5e3"]}
        ]}}"#;
        let s = promql_samples(json).expect("samples");
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].labels["app"], "gitea");
        assert_eq!((s[0].value, s[1].value), (0.0, 1500.0));
        assert!(s[1].labels.is_empty());
        assert!(promql_samples(r#"{"status":"error","error":"x"}"#).is_err());
        assert!(promql_samples("<html>502</html>").is_err());
        assert_eq!(
            promql_samples(r#"{"status":"success","data":{"result":[]}}"#).expect("empty"),
            vec![]
        );
    }

    #[test]
    fn an_empty_result_is_not_an_error() {
        // 🔴 "The metric does not exist" and "the query failed" call for different
        // responses: the first is a fact to interpret, the second a scrape failure.
        // Confusing them here would deny the rules that distinction.
        let empty = r#"{"status":"success","data":{"resultType":"vector","result":[]}}"#;
        assert_eq!(
            promql_values(empty).expect("valid response"),
            Vec::<f64>::new()
        );
    }

    #[test]
    fn values_are_read_from_a_real_response() {
        let json = r#"{"status":"success","data":{"resultType":"vector","result":[
            {"metric":{"app":"gitea"},"value":[1755000000,"3600"]},
            {"metric":{"app":"vikunja"},"value":[1755000000,"0.85"]}
        ]}}"#;
        assert_eq!(promql_values(json).expect("values"), vec![3600.0, 0.85]);
    }

    #[test]
    fn an_error_response_is_an_error() {
        let json = r#"{"status":"error","errorType":"bad_data","error":"parse error"}"#;
        assert!(promql_values(json).is_err());
    }

    #[test]
    fn garbage_is_not_read_as_zero() {
        // 🔴 A proxy's HTML error page parsed as "0" would read as a valid
        // measurement - and `0` is precisely the reassuring value everywhere here.
        assert!(promql_values("<html>502 Bad Gateway</html>").is_err());
        assert!(promql_values("").is_err());
    }

    #[test]
    fn negative_and_scientific_values_survive() {
        // VictoriaMetrics readily answers in scientific notation.
        let json = r#"{"status":"success","data":{"result":[
            {"value":[1,"-5"]},{"value":[2,"1.5e3"]}
        ]}}"#;
        let v = promql_values(json).expect("values");
        assert_eq!(v, vec![-5.0, 1500.0]);
    }

    #[test]
    fn a_missing_metric_reaches_the_rules_as_unknown() {
        // The full path, from empty response to conclusion: the chain is what matters,
        // and it is the chain that breaks in other systems.
        let empty = r#"{"status":"success","data":{"result":[]}}"#;
        let values = promql_values(empty).expect("valid response");

        let rule = &rules::default_rules()[0];
        let e = rule.judge(&values);

        assert!(matches!(e, Evaluation::Unknown { .. }), "{e:?}");
        assert!(
            rule.notification(&e).is_some(),
            "not knowing must be said, not kept quiet"
        );
    }
}
