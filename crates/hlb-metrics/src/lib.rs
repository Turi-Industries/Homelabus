//! Observabilité : collecte, règles d'alerte et deadman switch (§8bis).
//!
//! ## Ce que ce crate ajoute, et ce qui existait déjà
//!
//! Le controller exposait `/metrics` depuis longtemps, et `hlb-notify` savait pousser
//! des notifications à quatre niveaux avec des heures calmes. Il manquait tout le
//! milieu : **personne ne lisait ces métriques**. `hlb_backup_age_seconds` était émise
//! correctement et n'était consommée par rien, aucun historique n'était conservé, et
//! aucun seuil n'était évalué.
//!
//! Trois pièces comblent ce vide :
//!
//! - [`scrape`] — la configuration de collecte de VictoriaMetrics, qui stocke.
//! - [`rules`] — les seuils, évalués par Homelabus et routés vers `hlb-notify`.
//! - [`deadman`] — le veilleur externe, pour le cas où Homelabus lui-même est mort.
//!
//! ## 🔴 Pourquoi les deux derniers ne se remplacent pas
//!
//! [`rules`] tourne **sur** le controller. Si le controller meurt, aucune de ses
//! règles ne s'évalue plus, et le silence est indiscernable du bon fonctionnement.
//! [`deadman`] existe précisément pour cette panne-là, et il est le seul dispositif qui
//! ne partage pas le sort de ce qu'il surveille.
//!
//! Inversement, le deadman ne dit rien d'un disque à 90 % ou d'une sauvegarde manquée
//! sur un système par ailleurs vivant. Les deux couvrent des moitiés disjointes.

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

    #[error("réponse illisible : {0}")]
    Reponse(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Extrait les valeurs d'une réponse PromQL `/api/v1/query`.
///
/// 🔴 Une réponse **valide mais vide** (`"result": []`) rend un vecteur vide, jamais
/// une erreur. C'est un état légitime — la métrique n'existe pas — et c'est
/// [`Regle::juger`] qui décidera que « pas de donnée » n'est pas « tout va bien ».
/// Renvoyer une erreur ici confondrait « la requête a échoué » avec « la réponse est
/// vide », deux situations qui n'appellent pas la même conduite.
///
/// Analyse volontairement minimale : on ne veut pas d'une dépendance JSON pour lire un
/// tableau de nombres, et la forme de cette réponse est stable depuis Prometheus 2.0.
pub fn valeurs_promql(json: &str) -> Result<Vec<f64>> {
    if !json.contains("\"status\"") {
        return Err(Error::Reponse("ce n'est pas une réponse PromQL".into()));
    }
    if json.contains("\"status\":\"error\"") || json.contains("\"status\": \"error\"") {
        return Err(Error::Reponse(json.chars().take(200).collect()));
    }

    let mut v = Vec::new();
    // Chaque échantillon est `"value":[<horodatage>,"<valeur>"]`.
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
        // 🔴 « La métrique n'existe pas » et « la requête a échoué » n'appellent pas la
        // même conduite : la première est un fait à interpréter, la seconde une panne
        // de la collecte. Les confondre ici priverait les règles de la distinction.
        let vide = r#"{"status":"success","data":{"resultType":"vector","result":[]}}"#;
        assert_eq!(valeurs_promql(vide).expect("réponse valide"), Vec::<f64>::new());
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
        // 🔴 Une page HTML d'erreur de proxy analysée en « 0 » serait lue comme une
        // mesure valide — et `0` est justement la valeur qui rassure partout ici.
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
        // Le chemin complet, de la réponse vide à la conclusion : c'est l'enchaînement
        // qui compte, et c'est lui qui a été cassé dans d'autres systèmes.
        let vide = r#"{"status":"success","data":{"result":[]}}"#;
        let valeurs = valeurs_promql(vide).expect("réponse valide");

        let regle = &rules::regles_par_defaut()[0];
        let e = regle.juger(&valeurs);

        assert!(matches!(e, Evaluation::Inconnu { .. }), "{e:?}");
        assert!(
            regle.notification(&e).is_some(),
            "l'ignorance doit se dire, pas se taire"
        );
    }
}
