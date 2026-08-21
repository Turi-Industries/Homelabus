//! Exposition déclarée contre exposition réelle (lot 9.10).
//!
//! ## 🔴 Le point du §11bis : « c'est facile de se tromper »
//!
//! Le manifest déclare `expose` ; `hlb-ingress` rend la configuration Caddy. Les deux
//! informations existent, et personne ne les met côte à côte : une app publiée par
//! erreur est **invisible**.
//!
//! ## 🔴 Contre QUOI on compare
//!
//! Un premier jet comparait les manifests… à `routes_from_manifest` appliqué aux mêmes
//! manifests. Les deux côtés venaient de la même fonction : la comparaison ne pouvait
//! **jamais** échouer, et l'écran aurait affiché « conforme » quoi qu'il arrive. Pire
//! qu'absent : il aurait attesté d'une vérification qui n'avait pas lieu.
//!
//! La comparaison porte donc sur ce qui a été RÉELLEMENT publié à la dernière
//! application de la configuration d'entrée (`ingress_publie`), face à ce que les
//! manifests demandent aujourd'hui. C'est le cas dangereux et réel : une app installée
//! ou modifiée sans réappliquer l'entrée, ou une app retirée dont la route reste
//! ouverte.
//!
//! ⚠️ Aucune application enregistrée ne vaut PAS « conforme » : on ne sait rien, et
//! l'écran doit le dire.

use hlb_state::State;

/// L'exposition de chaque app installée.
pub async fn tout(state: &State) -> Vec<hlb_api::ExpositionSummary> {
    let mut out = Vec::new();

    let publie = state.ingress_publie().await.unwrap_or_default();
    // ⚠️ Jamais appliqué : distinct de « rien n'est publié ». Confondre les deux
    // annoncerait un cluster fermé alors qu'on n'en sait rien.
    let jamais_applique = publie.is_empty();

    let apps = state.installed_apps().await.unwrap_or_default();
    for (nom, _statut) in apps {
        let Ok(m) = state.app_manifest(&nom).await else {
            continue;
        };
        let domaine = state.app_domain(&nom).await.ok().flatten();

        // §4.6bis : la route ne s'ouvre qu'une fois les actions manuelles bloquantes
        // traitées. C'est exactement le calcul du CLI.
        let libere = state.unverified_blocking(&nom).await.unwrap_or(1) == 0;
        let routes = hlb_ingress::routes_from_manifest(&m, domaine.as_deref(), libere);

        for (i, r) in routes.iter().enumerate() {
            let declaree = m
                .spec
                .ingress
                .get(i)
                .map(|ing| match ing.expose {
                    hlb_types::ExposePolicy::Private => "private",
                    hlb_types::ExposePolicy::AfterGuide => "after-guide",
                    hlb_types::ExposePolicy::Public => "public",
                })
                .unwrap_or("private");

            let reel = publie.iter().find(|(h, ..)| h == &r.host);

            let (publique, divergence) = match (jamais_applique, reel) {
                (true, _) => (
                    r.public,
                    Some(format!(
                        "{} : la configuration d'entrée n'a jamais été appliquée — ce \
                         qui est réellement joignable est INCONNU.",
                        r.host
                    )),
                ),
                // 🔴 Le cas dangereux : ouvert sur l'internet alors que rien ne l'a
                // demandé.
                (false, Some((_, _, true))) if !r.public => (
                    true,
                    Some(format!(
                        "{} est publiée sur l'internet alors que le manifest la veut \
                         « {declaree} ».",
                        r.host
                    )),
                ),
                (false, Some((_, _, false))) if r.public => (
                    false,
                    Some(format!(
                        "{} devrait être publiée et ne l'est pas : la configuration \
                         d'entrée date d'avant ce changement.",
                        r.host
                    )),
                ),
                (false, None) => (
                    false,
                    Some(format!(
                        "{} n'a aucune route posée : « hlb ingress apply » n'a pas été \
                         rejoué depuis l'installation.",
                        r.host
                    )),
                ),
                (false, Some((_, _, publique))) => (*publique, None),
            };

            out.push(hlb_api::ExpositionSummary {
                app: nom.clone(),
                hote: r.host.clone(),
                declaree: declaree.to_string(),
                publique,
                divergence,
            });
        }
    }

    // Ce qui est ouvert d'abord : sur vingt lignes, celle qui pose problème se perdrait
    // au milieu d'un tri alphabétique.
    out.sort_by(|a, b| {
        b.attention()
            .cmp(&a.attention())
            .then_with(|| a.hote.cmp(&b.hote))
    });
    out
}

/// Les routes posées mais que plus aucun manifest ne demande.
///
/// 🔴 C'est la moitié qu'un parcours des apps installées ne peut PAS voir : une app
/// retirée dont la route reste ouverte n'apparaît dans aucun manifest, donc dans aucune
/// boucle sur les apps. Elle continue pourtant de répondre sur l'internet.
pub async fn orphelines(state: &State) -> Vec<hlb_api::ExpositionSummary> {
    let publie = state.ingress_publie().await.unwrap_or_default();
    let mut attendus = std::collections::BTreeSet::new();

    for (nom, _) in state.installed_apps().await.unwrap_or_default() {
        let Ok(m) = state.app_manifest(&nom).await else {
            continue;
        };
        let domaine = state.app_domain(&nom).await.ok().flatten();
        let libere = state.unverified_blocking(&nom).await.unwrap_or(1) == 0;
        for r in hlb_ingress::routes_from_manifest(&m, domaine.as_deref(), libere) {
            attendus.insert(r.host);
        }
    }

    publie
        .into_iter()
        .filter(|(host, ..)| !attendus.contains(host))
        .map(|(host, app, public)| hlb_api::ExpositionSummary {
            declaree: "aucune (l'app n'est plus installée)".into(),
            divergence: Some(format!(
                "{host} répond encore{} alors que {app} n'est plus installée.",
                if public {
                    " depuis l'internet"
                } else {
                    " depuis le VPN"
                }
            )),
            hote: host,
            app,
            publique: public,
        })
        .collect()
}
