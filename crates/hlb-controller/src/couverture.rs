//! Le pont entre l'état et le calcul de couverture des sauvegardes (§8.1).
//!
//! ## Pourquoi ce module existe, et pas ailleurs
//!
//! `hlb_backup::couverture_de` a besoin de lire l'état ; `hlb-state` ne peut pas
//! implémenter le trait lui-même — `hlb-backup` dépend de `hlb-updater` qui dépend de
//! `hlb-state`, et l'inverse fermerait un cycle que Cargo refuse.
//!
//! Le controller, lui, dépend déjà des deux. C'est donc ici que l'adaptateur vit : une
//! coquille de vingt lignes, sans logique métier — celle-ci reste dans `hlb-backup`,
//! testable en mémoire.
//!
//! ## Ce que ça débloque
//!
//! `Couverture` n'était construite que dans le CLI. Conséquence directe : le controller
//! n'émettait pas `hlb_backup_copies`, et la règle d'alerte `copie-unique` — celle qui
//! garde le 3-2-1 du §8.1 — **ne s'est jamais déclenchée**. Elle interrogeait une
//! métrique qui n'existait nulle part.

use hlb_backup::{Classe, Couverture, Destination, SourceCouverture};
use hlb_state::State;

/// L'heure, en secondes depuis l'époque.
fn maintenant() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Adapte l'état aux besoins du calcul de couverture.
pub struct EtatSource<'a>(pub &'a State);

impl SourceCouverture for EtatSource<'_> {
    async fn destinations(&self) -> Vec<Destination> {
        // ⚠️ Une erreur de lecture rend une liste VIDE, donc zéro copie à jour, donc
        // une alerte. C'est le sens sûr : une base illisible ne doit pas se traduire
        // par « tout va bien ».
        self.0
            .destinations()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(
                |(nom, location, classes, credentials_secret)| Destination {
                    nom,
                    location,
                    classes: classes.split(',').filter_map(Classe::parse).collect(),
                    credentials_secret,
                },
            )
            .collect()
    }

    async fn route(&self, app: &str, classe: Classe) -> Vec<String> {
        self.0.route(app, classe.nom()).await.unwrap_or_default()
    }

    async fn age_sur(&self, app: &str, destination: &str) -> Option<i64> {
        self.0
            .seconds_since_last_success_on(app, destination)
            .await
            .ok()
            .flatten()
    }
}

/// La couverture de chaque app installée.
pub async fn toutes(state: &State, seuil_s: i64) -> Vec<Couverture> {
    let source = EtatSource(state);
    let mut out = Vec::new();
    for (app, _) in state.installed_apps().await.unwrap_or_default() {
        out.push(hlb_backup::couverture_de(&source, &app, seuil_s).await);
    }
    out
}

/// La restaurabilité d'une app (§8.1 + §8.3), à partir de tout ce que l'état sait.
///
/// ⚠️ Même raison d'être que l'adaptateur ci-dessus : le calcul vit dans `hlb-backup`,
/// et seule la collecte des ingrédients est ici.
pub async fn restaurabilite(
    state: &State,
    app: &str,
    seuil_s: i64,
) -> hlb_backup::Restaurabilite {
    let source = EtatSource(state);
    let couverture = hlb_backup::couverture_de(&source, app, seuil_s).await;

    let verifiee = state
        .seconds_since_last_verification(app)
        .await
        .ok()
        .flatten();

    // Les exercices de reprise ne sont pas par app : c'est la restauration EN GÉNÉRAL
    // qu'ils éprouvent (§8.3). 🔴 `days_since_successful_drill` ne compte que les
    // exercices RÉUSSIS — un exercice échoué qui compterait comme « fait » dirait
    // « on a vérifié » à propos d'une vérification qui a raté.
    let exercices = hlb_backup::drill::Readiness::from_days(
        state.days_since_successful_drill().await.unwrap_or(None),
    );

    // La profondeur PITR n'existe que pour les apps à journalisation continue. Une app
    // sans base de sauvegarde n'a pas de fenêtre, et c'est `None` — pas zéro, qui se
    // lirait « on peut remonter jusqu'à maintenant », soit l'inverse.
    let pitr = state
        .base_backups(app)
        .await
        .unwrap_or_default()
        .iter()
        .map(|(_, at)| *at)
        .min()
        .map(|t| maintenant() - t);

    hlb_backup::Restaurabilite::calculer(&couverture, verifiee, pitr, exercices)
}

/// La traduction vers le contrat d'API.
pub fn en_resume(r: &hlb_backup::Restaurabilite) -> hlb_api::RestaurabiliteSummary {
    use hlb_backup::Confiance;
    hlb_api::RestaurabiliteSummary {
        app: r.app.clone(),
        rpo_s: r.rpo_s,
        verdict: r.verdict(),
        confiance: match r.confiance() {
            Confiance::Aucune => hlb_api::NiveauConfiance::Aucune,
            Confiance::Suppose => hlb_api::NiveauConfiance::Suppose,
            Confiance::Ancienne => hlb_api::NiveauConfiance::Ancienne,
            Confiance::Verifiee => hlb_api::NiveauConfiance::Verifiee,
        },
        confiance_explication: r.confiance().describe().to_string(),
        remedes: r.remedes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(nom: &str) -> hlb_types::Manifest {
        let y = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {nom} }}\n\
             spec:\n  image: {{ repo: a/b, tag: \"1\" }}\n"
        );
        serde_yaml_ng::from_str(&y).expect("manifest de test")
    }

    #[tokio::test]
    async fn coverage_is_computed_from_the_real_state() {
        // Le pont, exercé de bout en bout : deux destinations, l'une servie, l'autre
        // jamais. C'est ce chemin qui manquait au controller.
        let s = State::in_memory().await.expect("état");
        s.upsert_app("immich", &manifest("immich"), None)
            .await
            .expect("app");
        s.upsert_destination("nas", "/mnt/nas", "critique,volumineux", None)
            .await
            .expect("destination");
        s.upsert_destination("offsite", "s3:x/y", "critique", None)
            .await
            .expect("destination");
        s.record_backup_to("immich", "volume", "nas", Some("abc"), None)
            .await
            .expect("sauvegarde");

        let c = toutes(&s, 12 * 3_600).await;
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].app, "immich");
        assert_eq!(c[0].par_destination.len(), 2);
        // 🔴 Une seule copie protège vraiment : c'est le chiffre que la règle
        // `copie-unique` attendait et qui n'existait nulle part.
        assert_eq!(c[0].copies_a_jour(), 1);
    }

    #[tokio::test]
    async fn an_app_with_no_destination_at_all_is_not_silently_fine() {
        // Aucune destination déclarée : zéro copie. Rendre une couverture vide ferait
        // passer l'app pour couverte par défaut.
        let s = State::in_memory().await.expect("état");
        s.upsert_app("seafile", &manifest("seafile"), None)
            .await
            .expect("app");

        let c = toutes(&s, 12 * 3_600).await;
        assert_eq!(c[0].copies_a_jour(), 0);
    }
}
