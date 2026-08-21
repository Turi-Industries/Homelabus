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

pub use deadman::{Battement, Emission, Sante, Veille};
pub use rules::{Comparaison, Evaluation, Regle};
pub use scrape::Cible;

/// Erreurs du crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("VictoriaMetrics injoignable : {0}")]
    Injoignable(String),

    #[error("unreadable response: {0}")]
    Reponse(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Extracts the values from a PromQL `/api/v1/query` response.
///
/// 🔴 A **valid but empty** response (`"result": []`) returns an empty vector, never an
/// error. That is a legitimate state - the metric does not exist - and it is
/// [`Regle::juger`] that decides "no data" is not "all is well". Returning an error
/// here would confuse "the query failed" with "the response is empty", two situations
/// that call for different responses.
///
/// Deliberately minimal parsing: no JSON dependency for reading an array of numbers,
/// and the shape of this response has been stable since Prometheus 2.0.
pub fn valeurs_promql(json: &str) -> Result<Vec<f64>> {
    if !json.contains("\"status\"") {
        return Err(Error::Reponse("this is not a PromQL response".into()));
    }
    if json.contains("\"status\":\"error\"") || json.contains("\"status\": \"error\"") {
        return Err(Error::Reponse(json.chars().take(200).collect()));
    }

    let mut v = Vec::new();
    // Each sample is `"value":[<timestamp>,"<value>"]`.
    for morceau in json.split("\"value\"").skip(1) {
        let Some(apres) = morceau.split(',').nth(1) else {
            continue;
        };
        let brut: String = apres
            .chars()
            .skip_while(|c| !c.is_ascii_digit() && *c != '-' && *c != '.')
            .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-' || *c == 'e')
            .collect();

        if let Ok(f) = brut.parse::<f64>() {
            v.push(f);
        }
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_result_is_not_an_error() {
        // 🔴 "The metric does not exist" and "the query failed" call for different
        // responses: the first is a fact to interpret, the second a scrape failure.
        // Confusing them here would deny the rules that distinction.
        let vide = r#"{"status":"success","data":{"resultType":"vector","result":[]}}"#;
        assert_eq!(
            valeurs_promql(vide).expect("valid response"),
            Vec::<f64>::new()
        );
    }

    #[test]
    fn values_are_read_from_a_real_response() {
        let json = r#"{"status":"success","data":{"resultType":"vector","result":[
            {"metric":{"app":"gitea"},"value":[1755000000,"3600"]},
            {"metric":{"app":"vikunja"},"value":[1755000000,"0.85"]}
        ]}}"#;
        assert_eq!(valeurs_promql(json).expect("valeurs"), vec![3600.0, 0.85]);
    }

    #[test]
    fn an_error_response_is_an_error() {
        let json = r#"{"status":"error","errorType":"bad_data","error":"parse error"}"#;
        assert!(valeurs_promql(json).is_err());
    }

    #[test]
    fn garbage_is_not_read_as_zero() {
        // 🔴 A proxy's HTML error page parsed as "0" would read as a valid
        // measurement - and `0` is precisely the reassuring value everywhere here.
        assert!(valeurs_promql("<html>502 Bad Gateway</html>").is_err());
        assert!(valeurs_promql("").is_err());
    }

    #[test]
    fn negative_and_scientific_values_survive() {
        // VictoriaMetrics rend volontiers de la notation scientifique.
        let json = r#"{"status":"success","data":{"result":[
            {"value":[1,"-5"]},{"value":[2,"1.5e3"]}
        ]}}"#;
        let v = valeurs_promql(json).expect("valeurs");
        assert_eq!(v, vec![-5.0, 1500.0]);
    }

    #[test]
    fn a_missing_metric_reaches_the_rules_as_unknown() {
        // The full path, from empty response to conclusion: the chain is what matters,
        // and it is the chain that breaks in other systems.
        let vide = r#"{"status":"success","data":{"result":[]}}"#;
        let valeurs = valeurs_promql(vide).expect("valid response");

        let regle = &rules::regles_par_defaut()[0];
        let e = regle.juger(&valeurs);

        assert!(matches!(e, Evaluation::Inconnu { .. }), "{e:?}");
        assert!(
            regle.notification(&e).is_some(),
            "l'ignorance doit se dire, pas se taire"
        );
    }
}
