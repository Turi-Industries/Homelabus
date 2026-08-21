//! Le diff de manifest entre installations (lot 9.11).
//!
//! ## 🔴 Ce que ça répond
//!
//! « L'app marchait la semaine dernière. Qu'est-ce qui a changé ? » — une question à
//! laquelle rien ne répondait : `apps.manifest` est écrasé à chaque mise à jour.
//!
//! ## Le diff est ligne à ligne, et c'est assez
//!
//! Un YAML de manifest fait quelques dizaines de lignes et change peu. Un algorithme de
//! plus longue sous-séquence commune donnerait un diff plus joli sur un fichier
//! réordonné ; ici, la sérialisation vient toujours du même `serde`, donc l'ordre est
//! stable. Une comparaison ensembliste suffit et ne peut pas mentir sur ce qu'elle
//! montre.

/// Les versions successives d'un manifest, chacune avec son diff.
pub fn versions(
    miroir: &hlb_gitops::GitMirror,
    app: &str,
    limite: usize,
) -> Vec<hlb_api::VersionManifest> {
    let brutes = miroir.versions(app, limite).unwrap_or_default();
    let mut out = Vec::new();

    for (i, (reference, sujet, contenu)) in brutes.iter().enumerate() {
        // La version d'après dans la liste est la PRÉCÉDENTE dans le temps : la liste
        // est du plus récent au plus ancien.
        let precedent = brutes.get(i + 1).map(|(_, _, c)| c.as_str());
        out.push(hlb_api::VersionManifest {
            reference: reference.clone(),
            sujet: sujet.clone(),
            diff: precedent.map(|p| diff(p, contenu)).unwrap_or_default(),
            // 🔴 La plus ancienne version connue n'a pas de diff vide « parce que rien
            // n'a changé » : elle n'a rien avant elle. Confondre les deux ferait lire
            // « aucun changement » sur l'installation initiale.
            origine: precedent.is_none(),
        });
    }
    out
}

/// Les lignes retirées puis ajoutées, dans l'ordre du fichier.
pub fn diff(avant: &str, apres: &str) -> Vec<String> {
    let a: Vec<&str> = avant.lines().collect();
    let b: Vec<&str> = apres.lines().collect();

    let mut out = Vec::new();
    for l in &a {
        if !b.contains(l) {
            out.push(format!("- {l}"));
        }
    }
    for l in &b {
        if !a.contains(l) {
            out.push(format!("+ {l}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changed_tag_shows_both_sides() {
        // Le cas courant : une mise à jour d'image. Ne montrer que le « + » laisserait
        // deviner d'où l'on vient, et c'est précisément ce qu'on cherche.
        let d = diff("image:\n  tag: 1.23\n", "image:\n  tag: 1.24\n");
        assert_eq!(d, vec!["-   tag: 1.23", "+   tag: 1.24"], "{d:?}");
    }

    #[test]
    fn an_identical_manifest_produces_nothing() {
        // 🔴 Un diff vide affiché comme un changement ferait chercher ce qui a bougé
        // alors que rien n'a bougé.
        assert!(diff("a\nb\n", "a\nb\n").is_empty());
    }

    #[test]
    fn the_first_known_version_is_not_reported_as_unchanged() {
        // ⚠️ « Aucun changement » et « rien avant » sont deux réponses opposées. C'est
        // le champ `origine` qui les distingue, pas la taille du diff.
        let tmp = tempfile::tempdir().expect("dossier");
        let m = hlb_gitops::GitMirror::open_or_init(tmp.path()).expect("miroir");
        let manifest = |tag: &str| -> hlb_types::Manifest {
            serde_yaml_ng::from_str(&format!(
                "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: gitea }}\n\
                 spec:\n  image: {{ repo: a/b, tag: \"{tag}\" }}\n"
            ))
            .expect("manifest")
        };

        m.export(
            &[("gitea".into(), "running".into(), manifest("1.23"))],
            "installation",
        )
        .expect("export");
        m.export(
            &[("gitea".into(), "running".into(), manifest("1.24"))],
            "mise à jour",
        )
        .expect("export");

        let v = versions(&m, "gitea", 10);
        assert_eq!(v.len(), 2);
        assert!(!v[0].origine, "la plus récente a un prédécesseur");
        assert!(!v[0].diff.is_empty(), "et un diff");
        assert!(v[1].origine, "la plus ancienne n'a rien avant elle");
        assert!(v[1].diff.is_empty());
    }
}
