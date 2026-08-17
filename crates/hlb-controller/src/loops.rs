//! Les boucles de fond du controller (§2.1).
//!
//! Ce qui transforme une collection de commandes manuelles en système autonome.
//!
//! **Chaque boucle est un `tick()` séparé de son ordonnancement.** Un test appelle
//! `tick()` directement et observe le résultat ; il n'attend jamais un intervalle
//! réel. Une boucle qu'on ne peut tester qu'en dormant n'est pas testée.
//!
//! 🔴 **Une boucle ne panique jamais.** Une erreur est journalisée et le tour suivant
//! réessaie. Un controller qui meurt sur une erreur transitoire — registre
//! momentanément injoignable, nœud qui redémarre — est pire qu'un controller qui
//! réessaie : il faut alors que quelqu'un s'aperçoive qu'il est mort.

use std::sync::Arc;
use std::time::Duration;

use hlb_engine::Reconciler;
use hlb_orchestrator::Orchestrator;
use hlb_state::State;

/// Compte rendu d'un tour de boucle. Sert aux tests et à la supervision.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TickReport {
    pub examined: usize,
    pub acted: usize,
    pub errors: Vec<String>,
}

impl TickReport {
    pub fn is_clean(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Réconciliation périodique : l'état réel doit correspondre à l'état désiré.
pub struct ReconcileLoop<O: Orchestrator> {
    orchestrator: Arc<O>,
    state: Arc<State>,
    /// Faux par défaut : on observe avant de corriger.
    apply: bool,
}

impl<O: Orchestrator> ReconcileLoop<O> {
    pub fn new(orchestrator: Arc<O>, state: Arc<State>) -> Self {
        Self {
            orchestrator,
            state,
            apply: false,
        }
    }

    pub fn apply(mut self, yes: bool) -> Self {
        self.apply = yes;
        self
    }

    pub async fn tick(&self) -> TickReport {
        let mut r = TickReport::default();

        match Reconciler::new(&*self.orchestrator, &self.state)
            .reconcile(self.apply)
            .await
        {
            Ok(report) => {
                r.examined = report.drifts.len();
                r.acted = report.corrected.len();
                for d in &report.drifts {
                    tracing::info!("écart : {d}");
                }
            }
            Err(e) => {
                // On journalise et on rendra la main : le tour suivant réessaiera.
                tracing::warn!("réconciliation impossible ce tour-ci : {e}");
                r.errors.push(e.to_string());
            }
        }
        r
    }
}

/// Sauvegarde périodique des apps dont l'échéance est passée.
pub struct BackupLoop {
    state: Arc<State>,
    schedule: hlb_backup::Schedule,
}

impl BackupLoop {
    pub fn new(state: Arc<State>, schedule: hlb_backup::Schedule) -> Self {
        Self { state, schedule }
    }

    /// Les apps dues, sans rien exécuter.
    ///
    /// Séparé de l'exécution : décider *quoi* sauvegarder est une logique qu'on veut
    /// pouvoir tester sans dépôt restic ni Docker.
    pub async fn due_apps(&self) -> Result<Vec<String>, hlb_state::Error> {
        let mut due = Vec::new();
        for (app, status) in self.state.installed_apps().await? {
            // Une app en échec a un problème plus urgent que sa sauvegarde.
            if status == "failed" {
                continue;
            }
            let age = self
                .state
                .seconds_since_last_success(&app)
                .await?
                .map(|s| Duration::from_secs(s.max(0) as u64));

            if self.schedule.is_due(age) {
                due.push(app);
            }
        }
        Ok(due)
    }

    /// Les apps dont l'absence de sauvegarde mérite une alerte (§8bis).
    pub async fn overdue_apps(&self) -> Result<Vec<String>, hlb_state::Error> {
        let mut tard = Vec::new();
        for (app, _) in self.state.installed_apps().await? {
            let age = self
                .state
                .seconds_since_last_success(&app)
                .await?
                .map(|s| Duration::from_secs(s.max(0) as u64));
            if self.schedule.is_overdue(age) {
                tard.push(app);
            }
        }
        Ok(tard)
    }
}

/// Le battement de cœur du §8bis : « qui surveille le surveillant ? ».
///
/// Le controller écrit un horodatage **hors du cluster**. Un `cron` trivial sur le NAS
/// constate qu'il n'a pas bougé et alerte — voir `hlb metrics deadman`, qui produit ce
/// script. C'est la seule chose qui préviendra si le controller meurt, puisque c'est
/// lui qui envoie toutes les autres alertes.
///
/// ## 🔴 Le battement est CONDITIONNEL, jamais périodique
///
/// La première version battait à chaque tour de minuteur, sans rien vérifier. C'est le
/// piège de ce dispositif : un tel battement prouve qu'un fil d'exécution vit encore,
/// et **rien d'autre**. Le controller peut avoir sa boucle de réconciliation bloquée,
/// son Docker injoignable et sa base illisible, et continuer à battre imperturbablement.
///
/// Le veilleur resterait alors au vert sur un système inutilisable — ce qui est pire
/// que pas de deadman du tout, parce qu'on lui fait confiance. Le battement passe donc
/// par [`hlb_metrics::Battement::emettre_si`], et **se tait** quand quelque chose ne va
/// pas : le silence est le signal.
pub struct Heartbeat {
    path: std::path::PathBuf,
}

impl Heartbeat {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Bat si — et seulement si — le système est en état de le prétendre.
    ///
    /// Renvoie `true` si le battement est parti.
    pub async fn beat_si_sain(&self, sante: &hlb_metrics::Sante) -> std::io::Result<bool> {
        match hlb_metrics::Battement::emettre_si(sante) {
            hlb_metrics::Emission::Envoyer => {
                self.beat().await?;
                Ok(true)
            }
            hlb_metrics::Emission::Taire { manquements } => {
                // 🔴 On se TAIT, et on dit pourquoi dans les journaux. Battre ici
                // laisserait le veilleur au vert sur un système en panne.
                tracing::error!(
                    manquements = manquements.join(", "),
                    "battement de cœur RETENU : le veilleur va alerter, c'est voulu"
                );
                Ok(false)
            }
        }
    }

    /// Écrit le battement, sans condition.
    ///
    /// ⚠️ Réservé aux tests et à [`Self::beat_si_sain`]. L'appeler directement depuis
    /// une boucle recrée exactement le défaut décrit en tête de type.
    pub async fn beat(&self) -> std::io::Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Écriture atomique : un lecteur ne doit jamais voir un fichier à moitié
        // écrit et conclure à tort que le controller est mort.
        let tmp = self.path.with_extension("tmp");
        tokio::fs::write(&tmp, format!("{now}\n")).await?;
        tokio::fs::rename(&tmp, &self.path).await
    }
}

/// Lance une tâche périodique jusqu'à l'arrêt.
///
/// Le premier tour a lieu immédiatement : au démarrage, on veut savoir tout de suite
/// dans quel état est le cluster, pas dans un quart d'heure.
pub async fn every<F, Fut>(interval: Duration, mut shutdown: tokio::sync::watch::Receiver<bool>, mut f: F)
where
    F: FnMut() -> Fut + Send,
    Fut: std::future::Future<Output = ()> + Send,
{
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => f().await,
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(name: &str) -> hlb_types::Manifest {
        let y = format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {name} }}\n\
             spec:\n  image: {{ repo: a/b, tag: \"1\" }}\n"
        );
        serde_yaml_ng::from_str(&y).expect("manifest de test")
    }

    async fn state_with(apps: &[(&str, &str)]) -> Arc<State> {
        let s = State::in_memory().await.expect("base");
        for (name, status) in apps {
            s.upsert_app(name, &manifest(name), None).await.expect("upsert");
            s.set_app_status(name, status).await.expect("statut");
        }
        Arc::new(s)
    }

    #[tokio::test]
    async fn a_never_backed_up_app_is_due() {
        let s = state_with(&[("gitea", "running")]).await;
        let l = BackupLoop::new(s, hlb_backup::Schedule::default());
        assert_eq!(l.due_apps().await.expect("dues"), vec!["gitea"]);
    }

    #[tokio::test]
    async fn a_failed_app_is_skipped() {
        // Elle a un problème plus urgent que sa sauvegarde.
        let s = state_with(&[("gitea", "failed")]).await;
        let l = BackupLoop::new(s, hlb_backup::Schedule::default());
        assert!(l.due_apps().await.expect("dues").is_empty());
    }

    #[tokio::test]
    async fn a_recently_backed_up_app_is_not_due() {
        let s = state_with(&[("gitea", "running")]).await;
        s.record_backup("gitea", "volume", Some("abc"), None).await.expect("sauvegarde");

        let l = BackupLoop::new(s, hlb_backup::Schedule::default());
        assert!(l.due_apps().await.expect("dues").is_empty());
    }

    #[tokio::test]
    async fn a_failed_backup_leaves_the_app_due() {
        // 🔴 Un échec ne repousse pas l'échéance (§8.1).
        let s = state_with(&[("gitea", "running")]).await;
        s.record_backup("gitea", "volume", None, Some("disque plein"))
            .await
            .expect("échec");

        let l = BackupLoop::new(s, hlb_backup::Schedule::default());
        assert_eq!(l.due_apps().await.expect("dues"), vec!["gitea"]);
    }

    #[tokio::test]
    async fn never_backed_up_is_due_but_not_overdue() {
        let s = state_with(&[("gitea", "running")]).await;
        let l = BackupLoop::new(s, hlb_backup::Schedule::default());
        assert_eq!(l.due_apps().await.expect("dues"), vec!["gitea"]);
        assert!(
            l.overdue_apps().await.expect("retards").is_empty(),
            "« jamais fait » appelle une action, pas une alerte de dérive"
        );
    }

    #[tokio::test]
    async fn the_heartbeat_is_written_atomically() {
        let dir = tempfile::tempdir().expect("dossier temporaire");
        let p = dir.path().join("heartbeat");
        let h = Heartbeat::new(&p);

        h.beat().await.expect("battement");
        let contenu = tokio::fs::read_to_string(&p).await.expect("lecture");
        assert!(contenu.trim().parse::<u64>().is_ok(), "horodatage : {contenu:?}");

        // Aucun fichier temporaire ne doit subsister.
        assert!(!p.with_extension("tmp").exists());

        // Un second battement écrase proprement.
        h.beat().await.expect("second battement");
        assert!(tokio::fs::read_to_string(&p).await.expect("lecture").trim().parse::<u64>().is_ok());
    }

    #[tokio::test]
    async fn a_sick_controller_does_not_beat() {
        // 🔴 Le défaut que ce test protège existait vraiment : le battement partait à
        // chaque tour de minuteur, sans rien vérifier. Un tel battement ne prouve que
        // la survie d'un fil d'exécution — le controller pouvait avoir sa base
        // illisible et son Docker mort, et laisser le veilleur au vert sur un système
        // inutilisable. Ce qui est PIRE que pas de deadman, puisqu'on s'y fie.
        let dir = tempfile::tempdir().expect("dossier temporaire");
        let p = dir.path().join("battement");
        let h = Heartbeat::new(&p);

        let malade = hlb_metrics::Sante {
            etat_lisible: true,
            orchestrateur_joignable: false,
            reconciliation_recente: true,
        };
        assert!(!h.beat_si_sain(&malade).await.expect("décision"), "ne doit pas battre");
        assert!(!p.exists(), "aucun fichier ne doit être écrit : le silence EST le signal");

        let saine = hlb_metrics::Sante {
            etat_lisible: true,
            orchestrateur_joignable: true,
            reconciliation_recente: true,
        };
        assert!(h.beat_si_sain(&saine).await.expect("décision"), "doit battre");
        assert!(p.exists(), "un système sain écrit bien son battement");
    }

    #[tokio::test]
    async fn a_stale_beat_is_never_refreshed_by_a_sick_controller() {
        // Cas plus vicieux : le controller a battu quand il allait bien, puis est
        // tombé. Le fichier existe déjà — il ne doit PLUS être rafraîchi, sinon le
        // veilleur ne verra jamais le silence.
        let dir = tempfile::tempdir().expect("dossier temporaire");
        let p = dir.path().join("battement");
        let h = Heartbeat::new(&p);

        h.beat().await.expect("battement initial");
        let avant = tokio::fs::read_to_string(&p).await.expect("lecture");

        // Le temps passe, et le système tombe.
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let malade = hlb_metrics::Sante {
            etat_lisible: false,
            orchestrateur_joignable: true,
            reconciliation_recente: true,
        };
        assert!(!h.beat_si_sain(&malade).await.expect("décision"));

        let apres = tokio::fs::read_to_string(&p).await.expect("lecture");
        assert_eq!(avant, apres, "l'horodatage doit VIEILLIR, pas se rafraîchir");
    }

    #[tokio::test]
    async fn a_tick_report_without_errors_is_clean() {
        assert!(TickReport::default().is_clean());
        let r = TickReport {
            errors: vec!["boum".into()],
            ..Default::default()
        };
        assert!(!r.is_clean());
    }

    #[tokio::test]
    async fn the_periodic_runner_stops_on_shutdown() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let compteur = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = compteur.clone();

        let h = tokio::spawn(every(Duration::from_millis(10), rx, move || {
            let c = c.clone();
            async move {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }));

        tokio::time::sleep(Duration::from_millis(60)).await;
        tx.send(true).expect("signal d'arrêt");
        h.await.expect("la boucle doit se terminer");

        let n = compteur.load(std::sync::atomic::Ordering::SeqCst);
        assert!(n >= 2, "la boucle a tourné {n} fois");
    }
}
