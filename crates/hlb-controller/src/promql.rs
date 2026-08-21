//! Le relais vers VictoriaMetrics, et sa liste blanche.
//!
//! ## Pourquoi un relais plutôt qu'un accès direct
//!
//! L'interface pourrait interroger VictoriaMetrics elle-même. Trois raisons de ne pas
//! le faire :
//!
//! 1. **VictoriaMetrics est privé** (§6.3) : il n'est pas exposé, et l'ouvrir pour
//!    l'interface l'ouvrirait pour tout le monde.
//! 2. **Une seule authentification.** L'interface porte déjà un jeton ou une session
//!    pour le controller ; lui en faire porter un second pour la base de séries
//!    doublerait la surface et les occasions de fuite.
//! 3. **Le filtrage.** Voir ci-dessous.
//!
//! ## 🔴 Un relais PromQL ouvert est une exfiltration
//!
//! PromQL n'est pas un langage anodin. `{__name__=~".+"}` rend **toute** la base, et
//! des étiquettes portent des noms d'hôtes, des chemins de fichiers, des noms d'apps —
//! la cartographie complète de l'installation, servie à qui a un jeton `viewer`.
//!
//! D'où une **liste blanche de métriques**, et non une liste noire de motifs
//! dangereux : on ne peut pas énumérer ce qui est dangereux, on peut énumérer ce qui
//! est utile. Une métrique inconnue est refusée en nommant celles qui existent, plutôt
//! que de laisser chercher.

use std::time::Duration;

/// Les préfixes de métriques que l'interface a le droit d'interroger.
///
/// Trois familles, et rien d'autre :
/// - `hlb_*` : ce que le controller émet lui-même ;
/// - `node_*` : node-exporter, la santé matérielle des nœuds ;
/// - `container_*` : cadvisor, les statistiques par conteneur.
pub const PREFIXES: &[&str] = &["hlb_", "node_", "container_"];

/// Les fonctions PromQL autorisées.
///
/// ⚠️ Liste blanche là aussi. `rate` et `irate` sont indispensables pour un compteur ;
/// les agrégations servent à réduire vingt séries à une. Tout le reste est refusé —
/// pas parce que c'est dangereux en soi, mais parce qu'une requête qu'on n'a pas prévue
/// est une requête dont on ne connaît pas le coût, et VictoriaMetrics tourne sur le
/// même matériel que les apps.
pub const FONCTIONS: &[&str] = &[
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

/// Ce qui a fait refuser une requête.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refus {
    /// Aucune métrique reconnue dans la requête.
    AucuneMetrique,
    MetriqueInterdite(String),
    FonctionInterdite(String),
    /// Une plage trop longue ferait balayer des mois de points à VictoriaMetrics, qui
    /// tourne sur le même matériel que les apps.
    PlageTropLongue { demande_s: i64, max_s: i64 },
    TropDePoints { demande: i64, max: i64 },
}

impl Refus {
    pub fn describe(&self) -> String {
        match self {
            Self::AucuneMetrique => format!(
                "aucune métrique reconnue. Les noms doivent commencer par {}",
                PREFIXES.join(", ")
            ),
            Self::MetriqueInterdite(m) => format!(
                "métrique « {m} » non autorisée. Seules celles commençant par {} le sont — \
                 un relais PromQL ouvert rendrait toute la base, étiquettes comprises",
                PREFIXES.join(", ")
            ),
            Self::FonctionInterdite(f) => format!(
                "fonction « {f} » non autorisée. Disponibles : {}",
                FONCTIONS.join(", ")
            ),
            Self::PlageTropLongue { demande_s, max_s } => format!(
                "plage de {} demandée, maximum {} — au-delà, passe par Grafana, qui est \
                 fait pour ça",
                hlb_api::humanise(*demande_s),
                hlb_api::humanise(*max_s)
            ),
            Self::TropDePoints { demande, max } => format!(
                "{demande} points demandés, maximum {max} — une courbe de plus de {max} \
                 points ne se lit pas mieux, elle coûte juste plus cher"
            ),
        }
    }
}

/// Plage maximale interrogeable : sept jours.
///
/// Au-delà, c'est de l'analyse, et Grafana est fait pour ça (§11bis : « HomelabUS
/// agrège et relie, il ne remplace pas »).
pub const PLAGE_MAX_S: i64 = 7 * 86_400;

/// Nombre maximal de points d'une courbe.
///
/// Une sparkline de 500 points est déjà plus dense que les pixels disponibles.
pub const POINTS_MAX: i64 = 500;

/// Vérifie qu'une requête est acceptable.
///
/// Analyse volontairement grossière — on ne réimplémente pas un analyseur PromQL. On
/// extrait les identifiants et on vérifie que chacun est soit une métrique autorisée,
/// soit une fonction connue, soit un mot-clé. Le doute profite au **refus** : une
/// construction qu'on ne reconnaît pas est rejetée, pas laissée passer.
pub fn verifier(q: &str, depuis_s: i64, pas_s: i64) -> Result<(), Refus> {
    // `depuis_s == 0` : une requête INSTANTANÉE, pas une plage. Elle ne coûte qu'un
    // point et n'a donc ni plage ni nombre de points à borner.
    if depuis_s == 0 {
        return verifier_expression(q);
    }
    if depuis_s > PLAGE_MAX_S {
        return Err(Refus::PlageTropLongue {
            demande_s: depuis_s,
            max_s: PLAGE_MAX_S,
        });
    }
    let points = if pas_s > 0 { depuis_s / pas_s } else { i64::MAX };
    if points > POINTS_MAX {
        return Err(Refus::TropDePoints {
            demande: points,
            max: POINTS_MAX,
        });
    }

    verifier_expression(q)
}

/// Vérifie la seule expression, sans les bornes de plage.
fn verifier_expression(q: &str) -> Result<(), Refus> {
    let mut vu_metrique = false;
    for mot in identifiants(q) {
        if PREFIXES.iter().any(|p| mot.starts_with(p)) {
            vu_metrique = true;
            continue;
        }
        if FONCTIONS.contains(&mot.as_str()) || MOTS_CLES.contains(&mot.as_str()) {
            continue;
        }
        // Un identifiant qui ressemble à une métrique (minuscules et soulignés) mais
        // hors préfixe : c'est une tentative d'aller voir ailleurs.
        if mot.contains('_') || mot.len() > 3 {
            return Err(Refus::MetriqueInterdite(mot));
        }
        return Err(Refus::FonctionInterdite(mot));
    }

    if !vu_metrique {
        return Err(Refus::AucuneMetrique);
    }
    Ok(())
}

/// Les mots-clés PromQL qui ne sont ni métrique ni fonction.
const MOTS_CLES: &[&str] = &["on", "ignoring", "group_left", "group_right", "offset", "bool"];

/// Extrait les identifiants d'une requête, hors chaînes entre guillemets.
///
/// ⚠️ Le contenu des chaînes est ignoré : une valeur d'étiquette (`node="small-01"`)
/// n'est pas un nom de métrique, et la traiter comme tel refuserait des requêtes
/// parfaitement légitimes.
fn identifiants(q: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut courant = String::new();
    let mut dans_chaine = false;
    let mut apres_etiquette = false;

    for c in q.chars() {
        if dans_chaine {
            if c == '"' {
                dans_chaine = false;
            }
            continue;
        }
        match c {
            '"' => {
                dans_chaine = true;
                courant.clear();
            }
            c if c.is_alphanumeric() || c == '_' || c == ':' => courant.push(c),
            _ => {
                if !courant.is_empty() {
                    // Un identifiant suivi d'un `=` est un NOM D'ÉTIQUETTE, pas une
                    // métrique. `{node="x"}` ne doit pas faire refuser la requête.
                    if !apres_etiquette && !courant.chars().next().is_some_and(|c| c.is_numeric()) {
                        out.push(courant.clone());
                    }
                    courant.clear();
                }
                apres_etiquette = matches!(c, '{' | ',');
                if c == '=' || c == '!' {
                    // Ce qui précédait était une étiquette : on l'a déjà écartée.
                    apres_etiquette = false;
                }
            }
        }
    }
    if !courant.is_empty() && !courant.chars().next().is_some_and(|c| c.is_numeric()) {
        out.push(courant);
    }
    out
}

/// Le client VictoriaMetrics.
pub struct Metriques {
    base_url: String,
    http: reqwest::Client,
}

impl Metriques {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            // Court : une requête de graphe qui traîne bloque un écran. Mieux vaut
            // dire « indisponible » que faire attendre.
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Interroge une valeur instantanée.
    ///
    /// Sert à l'évaluation des règles d'alerte : on veut « quelle est la valeur
    /// maintenant », pas une courbe.
    ///
    /// ⚠️ Rend un `Result` et non une `Serie`, contrairement à [`Self::plage`] : ici
    /// l'appelant DOIT distinguer « la règle vaut 0 » de « je n'ai pas pu évaluer ».
    /// Les confondre donnerait un tableau de bord vert pendant que la collecte est
    /// tombée — c'est précisément ce que `Evaluation::Inconnu` existe pour empêcher.
    pub async fn instant(&self, q: &str) -> Result<Vec<f64>, String> {
        // La liste blanche s'applique aussi à nos propres règles : c'est ce qui
        // garantit qu'aucune règle livrée n'interroge autre chose que les métriques
        // attendues, y compris après une modification distraite.
        if let Err(r) = verifier(q, 0, 60) {
            return Err(r.describe());
        }

        let url = format!("{}/api/v1/query", self.base_url);
        let reponse = self.http.get(&url).query(&[("query", q)]).send().await;

        let texte = match reponse {
            Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
            Ok(r) => return Err(format!("VictoriaMetrics a répondu {}", r.status())),
            Err(e) => return Err(format!("VictoriaMetrics injoignable ({e})")),
        };

        hlb_metrics::valeurs_promql(&texte).map_err(|e| e.to_string())
    }

    /// Interroge une plage de temps.
    ///
    /// Rend toujours une [`hlb_api::Serie`] — jamais une erreur. Une base de séries
    /// injoignable n'est pas une panne du controller : c'est une information à afficher.
    pub async fn plage(
        &self,
        q: &str,
        depuis_s: i64,
        pas_s: i64,
        unite: hlb_api::Unite,
        maintenant: i64,
    ) -> hlb_api::Serie {
        if let Err(r) = verifier(q, depuis_s, pas_s) {
            return hlb_api::Serie::Indisponible {
                raison: r.describe(),
            };
        }

        let url = format!("{}/api/v1/query_range", self.base_url);
        let debut = maintenant - depuis_s;
        let reponse = self
            .http
            .get(&url)
            .query(&[
                ("query", q),
                ("start", &debut.to_string()),
                ("end", &maintenant.to_string()),
                ("step", &format!("{pas_s}s")),
            ])
            .send()
            .await;

        let texte = match reponse {
            Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default(),
            Ok(r) => {
                return hlb_api::Serie::Indisponible {
                    raison: format!("VictoriaMetrics a répondu {}", r.status()),
                }
            }
            Err(e) => {
                return hlb_api::Serie::Indisponible {
                    // Le message brut parle de couches réseau ; ce qu'il faut savoir,
                    // c'est si la base de séries est déployée.
                    raison: format!(
                        "VictoriaMetrics injoignable ({e}). Est-il installé ? \
                         « hlb install victoriametrics --apply »"
                    ),
                }
            }
        };

        match parser_plage(&texte) {
            Some(points) if !points.is_empty() => hlb_api::Serie::Points {
                nom: q.to_string(),
                points,
                unite,
            },
            // 🔴 Une requête valide sans résultat n'est PAS une série vide : c'est
            // « la métrique n'existe pas encore », ce qui arrive tout le temps avant
            // le premier scrape. Le dire évite de chercher une panne.
            Some(_) => hlb_api::Serie::Indisponible {
                raison: "aucune mesure sur cette période — la métrique existe-t-elle ?".into(),
            },
            None => hlb_api::Serie::Indisponible {
                raison: "réponse de VictoriaMetrics illisible".into(),
            },
        }
    }
}

/// Extrait les points d'une réponse `/api/v1/query_range`.
///
/// Analyse minimale, comme `hlb_metrics::valeurs_promql` : la forme est stable et
/// documentée, et une dépendance de plus pour lire trois champs ne se justifie pas.
pub fn parser_plage(json: &str) -> Option<Vec<(i64, f64)>> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    if v.get("status")?.as_str()? != "success" {
        return None;
    }
    let resultats = v.get("data")?.get("result")?.as_array()?;

    // ⚠️ On prend la PREMIÈRE série. Une requête qui en rend plusieurs devrait
    // agréger (`sum by (…)`) : les empiler ici dessinerait une courbe qui saute d'une
    // série à l'autre, ce qui ressemble à des données erratiques.
    let Some(premier) = resultats.first() else {
        return Some(Vec::new());
    };

    let mut points = Vec::new();
    for p in premier.get("values")?.as_array()? {
        let paire = p.as_array()?;
        let t = paire.first()?.as_f64()? as i64;
        // La valeur est une CHAÎNE dans le format Prometheus, pas un nombre.
        let val: f64 = paire.get(1)?.as_str()?.parse().ok()?;
        // `NaN` traverse le JSON sous forme de "NaN" : le garder produirait un trou
        // invisible dans la courbe.
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
    fn a_wildcard_query_is_refused() {
        // 🔴 `{__name__=~".+"}` rend TOUTE la base : noms d'hôtes, chemins, noms
        // d'apps — la cartographie complète de l'installation, à qui a un jeton
        // `viewer`.
        let r = verifier(r#"{__name__=~".+"}"#, 3600, 60).expect_err("doit refuser");
        assert!(matches!(r, Refus::MetriqueInterdite(_) | Refus::AucuneMetrique), "{r:?}");
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
            assert!(verifier(q, 3600, 60).is_ok(), "refusée à tort : {q}");
        }
    }

    #[test]
    fn a_foreign_metric_is_refused_by_name() {
        // Une liste NOIRE ne peut pas énumérer ce qui est dangereux. La liste blanche,
        // si — et le message nomme ce qui est possible plutôt que de laisser chercher.
        let r = verifier("secret_tokens_total", 3600, 60).expect_err("doit refuser");
        assert!(r.describe().contains("hlb_"), "{}", r.describe());
        assert!(r.describe().contains("secret_tokens_total"), "{}", r.describe());
    }

    #[test]
    fn label_values_are_not_mistaken_for_metric_names() {
        // ⚠️ `node="small-01"` : ni « node » ni « small-01 » ne sont des métriques.
        // Les traiter comme tels refuserait des requêtes parfaitement légitimes, et on
        // finirait par désactiver le filtre.
        assert!(verifier(r#"hlb_disk_used_ratio{node="postgres_secret",path="/"}"#, 3600, 60).is_ok());
    }

    #[test]
    fn an_unknown_function_is_refused() {
        let r = verifier("label_replace(hlb_app_up, \"a\", \"b\", \"c\", \"d\")", 3600, 60)
            .expect_err("doit refuser");
        assert!(r.describe().contains("label_replace"), "{}", r.describe());
    }

    #[test]
    fn a_query_without_any_metric_is_refused() {
        // Ni `1+1` ni une constante ne servent à rien ici, et laisser passer une
        // requête sans métrique ouvrirait la porte aux constructions exotiques.
        assert_eq!(verifier("1 + 1", 3600, 60), Err(Refus::AucuneMetrique));
    }

    #[test]
    fn a_month_long_range_is_refused_with_a_pointer_to_grafana() {
        // Au-delà de sept jours, c'est de l'analyse — et VictoriaMetrics tourne sur le
        // même matériel que les apps.
        let r = verifier("hlb_cpu_used_ratio", 30 * 86_400, 3600).expect_err("doit refuser");
        assert!(r.describe().contains("Grafana"), "{}", r.describe());
    }

    #[test]
    fn too_many_points_are_refused() {
        // Une seconde de pas sur une journée = 86 400 points, pour une sparkline de
        // 200 pixels.
        let r = verifier("hlb_cpu_used_ratio", 86_400, 1).expect_err("doit refuser");
        assert!(matches!(r, Refus::TropDePoints { .. }), "{r:?}");
    }

    #[test]
    fn a_zero_step_does_not_divide_by_zero() {
        let r = verifier("hlb_cpu_used_ratio", 3600, 0).expect_err("doit refuser");
        assert!(matches!(r, Refus::TropDePoints { .. }), "{r:?}");
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
        let p = parser_plage(json).expect("analysable");
        assert_eq!(p, vec![(1_700_000_000, 0.42), (1_700_000_060, 0.55)]);
    }

    #[test]
    fn values_are_strings_in_the_prometheus_format() {
        // ⚠️ Le piège du format : les valeurs sont des CHAÎNES, pas des nombres. Les
        // lire en `as_f64()` rendrait `None` sur toutes, et la courbe serait vide sans
        // aucune erreur.
        let json = r#"{"status":"success","data":{"result":[{"values":[[1,"3.5"]]}]}}"#;
        assert_eq!(parser_plage(json), Some(vec![(1, 3.5)]));
    }

    #[test]
    fn a_nan_is_dropped_rather_than_drawn() {
        // `NaN` produirait un trou invisible dans la courbe — ou un plantage du tracé.
        let json = r#"{"status":"success","data":{"result":[{"values":[[1,"1.0"],[2,"NaN"],[3,"2.0"]]}]}}"#;
        assert_eq!(parser_plage(json), Some(vec![(1, 1.0), (3, 2.0)]));
    }

    #[test]
    fn an_error_response_is_not_read_as_empty_data() {
        // Une erreur lue comme « aucune donnée » afficherait « pas de mesure » alors
        // que la requête était fautive.
        assert_eq!(
            parser_plage(r#"{"status":"error","errorType":"bad_data","error":"parse error"}"#),
            None
        );
        assert_eq!(parser_plage("pas du json"), None);
    }

    #[test]
    fn an_empty_result_is_distinguishable_from_a_parse_failure() {
        // `Some(vec![])` = la requête a marché et n'a rien trouvé.
        // `None` = on n'a pas su lire. Les deux s'affichent différemment.
        assert_eq!(
            parser_plage(r#"{"status":"success","data":{"result":[]}}"#),
            Some(Vec::new())
        );
    }
}
