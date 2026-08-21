//! Le runbook imprimable (lot 10.3, §9quater).
//!
//! ## 🔴 Pourquoi il est GÉNÉRÉ, et jamais écrit à la main
//!
//! Le §9quater prévoit un runbook imprimé. Écrit à la main, il est faux le jour où l'on
//! en a besoin : les nœuds changent, les destinations bougent, les apps s'ajoutent. Un
//! document rassurant et périmé est pire que pas de document — on le suit.
//!
//! Celui-ci est produit depuis l'état réel, à l'instant où on le demande. Il porte sa
//! date de génération, parce qu'une fois imprimé il commence lui aussi à vieillir.
//!
//! ## ⚠️ Il ne contient AUCUN secret
//!
//! Un runbook est fait pour être imprimé et rangé ailleurs — c'est tout son intérêt, et
//! c'est exactement pourquoi il ne doit porter aucune valeur de secret. Il dit **où
//! sont** les choses, pas ce qu'elles valent.

use hlb_state::State;

/// Le runbook, en Markdown : lisible tel quel, et imprimable depuis n'importe quoi.
pub async fn engendrer(
    state: &State,
    noeuds: &[hlb_api::NoeudSummary],
    maintenant: i64,
) -> String {
    let mut s = String::new();

    s.push_str("# Runbook Homelabus\n\n");
    s.push_str(
        "Généré automatiquement depuis l'état réel. Une fois imprimé, ce document \
         commence à vieillir : régénère-le après tout changement d'infrastructure.\n\n",
    );

    // --- Ce qu'il faut avoir sous la main -------------------------------------
    s.push_str("## Avant tout : la clé maîtresse\n\n");
    s.push_str(
        "Sans elle, les secrets du coffre sont définitivement inexploitables, et \
         AUCUNE restauration ne rendra un système fonctionnel : les bases se \
         restaureront, les apps ne pourront pas s'y connecter.\n\n\
         - Emplacement par défaut : `~/.config/hlb/master.key`\n\
         - Elle doit exister en DEHORS du cluster, sur un support qui ne dépend pas \
           de lui.\n\n",
    );
    // 🔴 On ne dit pas où elle est vraiment : le runbook est imprimé et rangé, et
    // nommer l'emplacement exact d'une clé sur un papier est un risque en soi.

    // --- L'ordre de redémarrage -----------------------------------------------
    s.push_str("## Ordre de redémarrage\n\n");
    s.push_str(
        "Docker Swarm n'a pas de `depends_on` : il démarre tout en parallèle, et une \
         app lancée avant sa base boucle en crash. Cet ordre vient du graphe des \
         capacités, pas d'une liste tenue à la main.\n\n",
    );
    match ordre_de_demarrage(state).await {
        Ok(ordre) if !ordre.is_empty() => {
            for (i, app) in ordre.iter().enumerate() {
                s.push_str(&format!("{}. `{app}`\n", i + 1));
            }
        }
        // ⚠️ Un ordre qu'on ne sait pas calculer n'est pas remplacé par un ordre
        // plausible : suivre le mauvais ordre au pire moment est exactement ce qu'on
        // veut éviter. Et la RAISON est imprimée — « il manque postgres » se corrige,
        // « l'ordre n'a pas pu être calculé » ne se corrige pas.
        Ok(_) => s.push_str("*Aucune application installée.*\n"),
        Err(raison) => s.push_str(&format!(
            "*L'ordre n'a pas pu être calculé : {raison}.*\n\n\
             *En attendant, démarre les services de plateforme (postgres, valkey, \
             garage) AVANT les applications, et vérifie chacun avant de passer au \
             suivant.*\n"
        )),
    }
    s.push('\n');

    // --- Les nœuds ------------------------------------------------------------
    s.push_str("## Nœuds\n\n");
    if noeuds.is_empty() {
        s.push_str("*Aucun nœud connu : Docker est injoignable, ou aucun agent ne \
                    répond.*\n\n");
    } else {
        s.push_str("| Nom | Adresse | Joignable |\n|---|---|---|\n");
        for n in noeuds {
            s.push_str(&format!(
                "| {} | `{}` | {} |\n",
                n.hostname.as_deref().unwrap_or("(inconnu)"),
                n.adresse,
                // ⚠️ L'état au moment de la génération, pas une propriété du nœud. Un
                // runbook imprimé le fige : c'est justement pour ça qu'il porte sa date.
                if n.joignable { "oui" } else { "NON" }
            ));
        }
        s.push('\n');
    }

    // --- Les destinations de sauvegarde ---------------------------------------
    s.push_str("## Destinations de sauvegarde\n\n");
    let dests = state.destinations().await.unwrap_or_default();
    if dests.is_empty() {
        s.push_str(
            "🔴 **AUCUNE destination déclarée.** Il n'y a rien à restaurer.\n\n",
        );
    } else {
        s.push_str("| Nom | Emplacement | Classes |\n|---|---|---|\n");
        for (nom, location, classes, _secret) in &dests {
            // ⚠️ `location` peut contenir des identifiants S3 dans une URL. On passe par
            // le masquage de `hlb-backup` plutôt que d'imprimer une clé d'accès sur un
            // papier qui traînera dans un tiroir.
            s.push_str(&format!(
                "| {nom} | `{}` | {classes} |\n",
                hlb_backup::Destination {
                    nom: nom.clone(),
                    location: location.clone(),
                    classes: Vec::new(),
                    credentials_secret: None,
                }
                .lieu_masque()
            ));
        }
        s.push('\n');
    }

    // --- La procédure ---------------------------------------------------------
    s.push_str("## Reprise après sinistre\n\n");
    s.push_str(
        "1. Vérifier que la clé maîtresse est disponible. **Sans elle, s'arrêter ici** \
         et la retrouver.\n\
         2. `hlb dr status` — dit si la bascule est possible, et ce qui manque sinon.\n\
         3. `hlb backup verify <app>` — vérifier AVANT de détruire quoi que ce soit.\n\
         4. `hlb dr promote <nœud> --apply` — la bascule assistée.\n\
         5. `hlb reconcile --apply` — remettre l'état réel en accord avec l'état voulu.\n\
         6. `hlb ingress apply` — reposer les routes : sans ça, rien n'est joignable.\n\n",
    );

    s.push_str("## Si l'on ne peut plus se connecter\n\n");
    s.push_str(
        "PocketID est le point de défaillance unique sur l'ACCÈS : s'il est tombé, on \
         ne peut plus entrer dans Homelabus, donc plus piloter sa restauration.\n\n\
         - Les codes de connexion à usage unique PocketID (imprimés séparément).\n\
         - La connexion locale de Vaultwarden, qui ne dépend d'aucun autre service.\n\
         - Un jeton d'API `admin` permet de tout piloter en ligne de commande sans \
           passer par le SSO.\n\n",
    );

    s.push_str(&format!(
        "---\n\nGénéré le {} (UTC). Les chiffres et les listes ci-dessus datent de cet \
         instant.\n",
        horodatage_lisible(maintenant)
    ));

    s
}

/// « 2026-08-19 07:12 », en UTC.
///
/// ⚠️ Pas de fuseau local : le serveur ne connaît pas celui du lecteur, et une date
/// affichée dans le mauvais fuseau se compare mal aux journaux, qui sont en UTC.
fn horodatage_lisible(t: i64) -> String {
    let jours = t.div_euclid(86_400);
    let reste = t.rem_euclid(86_400);

    // Algorithme des jours civils (Howard Hinnant), inverse de celui de la frise.
    let z = jours + 719_468;
    let ere = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - ere * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + ere * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        reste / 3_600,
        (reste % 3_600) / 60
    )
}

/// L'ordre topologique des apps installées.
///
/// L'erreur est REMONTÉE, pas avalée : `MissingDependency` nomme le service absent, et
/// c'est une information autrement plus utile qu'un ordre manquant.
async fn ordre_de_demarrage(state: &State) -> Result<Vec<String>, String> {
    let mut manifests = Vec::new();
    let apps = state
        .installed_apps()
        .await
        .map_err(|e| format!("état illisible ({e})"))?;
    for (nom, statut) in apps {
        if statut == "failed" {
            continue;
        }
        if let Ok(m) = state.app_manifest(&nom).await {
            manifests.push(m);
        }
    }
    // ⚠️ Le MÊME tri topologique que celui du déploiement : un ordre écrit à part
    // divergerait dès qu'une capacité change, et c'est le pire moment pour s'en
    // apercevoir.
    hlb_resolver::graph::DependencyGraph::from_manifests(&manifests)
        .deployment_order()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_runbook_never_carries_a_secret_value() {
        // 🔴 Un runbook est fait pour être IMPRIMÉ et rangé ailleurs. Y faire figurer
        // une valeur de secret la met sur un papier, hors de tout contrôle d'accès.
        let s = State::in_memory().await.expect("état");
        s.store_secret_if_absent("gitea-db-password", b"tres-secret", "mot de passe")
            .await
            .expect("secret");

        let r = engendrer(&s, &[], 1_787_097_600).await;
        assert!(!r.contains("tres-secret"), "une valeur de secret a fuité");
    }

    #[tokio::test]
    async fn an_installation_with_no_backup_destination_says_so_loudly() {
        // Le runbook qu'on lit au pire moment doit dire tout de suite qu'il n'y a rien
        // à restaurer, plutôt que de dérouler une procédure sans objet.
        let s = State::in_memory().await.expect("état");
        let r = engendrer(&s, &[], 1_787_097_600).await;
        assert!(r.contains("AUCUNE destination déclarée"), "{r}");
    }

    #[tokio::test]
    async fn the_generation_date_is_printed_because_paper_goes_stale() {
        let s = State::in_memory().await.expect("état");
        let r = engendrer(&s, &[], 1_787_097_600).await;
        assert!(r.contains("2026-08-19"), "{r}");
        assert!(r.contains("commence à vieillir"));
    }

    #[tokio::test]
    async fn an_uncomputable_order_prints_the_reason_not_just_the_failure() {
        // ⚠️ « L'ordre n'a pas pu être calculé » ne se corrige pas ; « gitea a besoin
        // de postgres, qui n'est pas dans le catalogue » se corrige. Et suivre un ordre
        // inventé au pire moment est exactement ce qu'on veut éviter.
        let s = State::in_memory().await.expect("état");
        let m: hlb_types::Manifest = serde_yaml_ng::from_str(
            "apiVersion: hlb/v1\nkind: App\nmetadata: { name: gitea }\n\
             spec:\n  image: { repo: a/b, tag: \"1\" }\n  requires:\n\
             \x20   - kind: database\n      engine: postgres\n",
        )
        .expect("manifest");
        s.upsert_app("gitea", &m, None).await.expect("app");

        let r = engendrer(&s, &[], 1_787_097_600).await;
        assert!(r.contains("postgres"), "la raison doit nommer le manquant : {r}");
        assert!(r.contains("AVANT les applications"));
    }

    #[tokio::test]
    async fn an_empty_installation_says_so_rather_than_blaming_a_calculation() {
        // 🔴 « L'ordre n'a pas pu être calculé » sur une installation vide ferait
        // chercher une panne là où il n'y a simplement rien.
        let s = State::in_memory().await.expect("état");
        let r = engendrer(&s, &[], 1_787_097_600).await;
        assert!(r.contains("Aucune application installée"), "{r}");
    }
}

#[cfg(test)]
mod tests_horodatage {
    use super::horodatage_lisible;

    #[test]
    fn the_civil_date_matches_known_epochs() {
        // Le calcul est fait à la main (pas de dépendance de dates dans ce crate) :
        // une erreur d'un jour daterait le runbook de la veille, et l'on croirait avoir
        // régénéré un document qu'on n'a pas régénéré.
        assert_eq!(horodatage_lisible(0), "1970-01-01 00:00");
        assert_eq!(horodatage_lisible(946_684_800), "2000-01-01 00:00");
        assert_eq!(horodatage_lisible(1_787_097_600), "2026-08-19 00:00");
        assert_eq!(horodatage_lisible(1_787_097_600 + 11_520), "2026-08-19 03:12");
    }
}
