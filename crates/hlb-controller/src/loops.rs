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
    /// Là où la boucle publie ce qu'elle a vu — et ce qu'elle a refusé de toucher.
    ecarts: Option<EtatEcarts>,
}

impl<O: Orchestrator> ReconcileLoop<O> {
    pub fn new(orchestrator: Arc<O>, state: Arc<State>) -> Self {
        Self {
            orchestrator,
            state,
            apply: false,
            ecarts: None,
        }
    }

    pub fn apply(mut self, yes: bool) -> Self {
        self.apply = yes;
        self
    }

    /// Publier les écarts observés à chaque tour.
    pub fn publie_dans(mut self, ecarts: EtatEcarts) -> Self {
        self.ecarts = Some(ecarts);
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

                if let Some(partage) = &self.ecarts {
                    // 🔴 Les écarts CORRIGÉS ne sont pas republiés : ils ne sont plus
                    // des écarts. Les laisser ferait paraître le système en dérive
                    // permanente alors qu'il vient précisément de faire son travail.
                    *partage.write().await = report
                        .drifts
                        .iter()
                        .map(|d| hlb_api::EcartSummary {
                            cible: d.app().to_string(),
                            description: d.to_string(),
                            corrigible: d.is_correctable(),
                            refus: d.refus().map(str::to_string),
                        })
                        .collect();
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

/// Purge des aliases temporaires expirés (§5bis.3).
///
/// 🔴 **Sans cette boucle, « temporaire » est un mensonge.** Stalwart n'a aucune
/// notion d'expiration : la liste d'aliases d'un compte est une simple liste, et ce
/// qui y est écrit y reste. Une adresse donnée à un marchand « pour trente jours »
/// continue de recevoir indéfiniment si personne ne vient la retirer.
///
/// ## 🔴 Un échec de purge doit se VOIR
///
/// C'est la propriété qui distingue cette boucle des autres. Une réconciliation qui
/// échoue laisse le cluster tel quel — c'est ennuyeux mais honnête. Une purge qui
/// échoue laisse des portes **ouvertes que leur propriétaire croit fermées**, et le
/// silence entretient la croyance. Le compte rendu remonte donc le nombre d'adresses
/// encore ouvertes, et non seulement le nombre d'erreurs.
pub struct AliasPurgeLoop {
    state: Arc<State>,
    mail: Option<Arc<hlb_mail::Stalwart>>,
    domaine_defaut: String,
}

/// Ce qu'un passage de purge a donné.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PurgeReport {
    /// Aliases expirés trouvés encore actifs.
    pub dus: usize,
    /// Effectivement retirés du serveur.
    pub retires: usize,
    pub errors: Vec<String>,
}

impl PurgeReport {
    /// Combien d'adresses restent ouvertes alors qu'on les croit fermées.
    ///
    /// 🔴 C'est LE chiffre à surveiller — pas le nombre d'erreurs. Une purge sans
    /// erreur mais qui n'a rien retiré laisse autant de portes ouvertes qu'une purge
    /// qui a échoué bruyamment.
    pub fn encore_ouvertes(&self) -> usize {
        self.dus.saturating_sub(self.retires)
    }

    pub fn is_clean(&self) -> bool {
        self.encore_ouvertes() == 0
    }
}

impl AliasPurgeLoop {
    pub fn new(
        state: Arc<State>,
        mail: Option<Arc<hlb_mail::Stalwart>>,
        domaine_defaut: impl Into<String>,
    ) -> Self {
        Self {
            state,
            mail,
            domaine_defaut: domaine_defaut.into(),
        }
    }

    pub async fn tick(&self) -> PurgeReport {
        let mut r = PurgeReport::default();

        let maintenant = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let dus = match self.state.aliases_to_purge(maintenant).await {
            Ok(v) => v,
            Err(e) => {
                r.errors.push(e.to_string());
                return r;
            }
        };
        r.dus = dus.len();

        let Some(mail) = &self.mail else {
            if r.dus > 0 {
                // 🔴 On ne marque RIEN comme purgé. Le faire sans retirer l'alias
                // serait le pire des deux mondes : l'adresse recevrait encore, et
                // plus rien ne le signalerait.
                tracing::error!(
                    ouvertes = r.dus,
                    "purge impossible (Stalwart non configuré) : ces adresses expirées \
                     RECOIVENT encore, et leur propriétaire les croit fermées"
                );
                r.errors.push("Stalwart non configuré".into());
            }
            return r;
        };

        for (user, boite, local) in dus {
            let dom = self
                .state
                .mailboxes(&user)
                .await
                .ok()
                .and_then(|v| {
                    v.into_iter()
                        .find(|(l, ..)| l == &boite)
                        .map(|(_, d, _)| d)
                })
                .unwrap_or_else(|| self.domaine_defaut.clone());

            // L'état n'est marqué qu'APRÈS le retrait effectif.
            match mail.remove_alias(&format!("{boite}@{dom}"), &local).await {
                Ok(_) => match self.state.deactivate_alias(&user, &local).await {
                    Ok(()) => {
                        r.retires += 1;
                        tracing::info!(user, alias = %local, "alias expiré retiré");
                    }
                    Err(e) => r.errors.push(format!("{local} : {e}")),
                },
                // Un échec ne bloque pas les suivants : chaque porte refermée est un
                // gain, même si la suivante résiste.
                Err(e) => r.errors.push(format!("{local} : {e}")),
            }
        }

        if !r.is_clean() {
            tracing::error!(
                ouvertes = r.encore_ouvertes(),
                "🔴 adresses expirées TOUJOURS actives après la purge"
            );
        }
        r
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
/// L'évaluation périodique des règles d'alerte (§8bis).
///
/// ## Ce qui manquait
///
/// `hlb_metrics::regles_par_defaut()` existait, et n'était évalué **que par le CLI** —
/// donc seulement quand quelqu'un tapait `hlb metrics check`. Il n'y avait aucune
/// surveillance continue : les règles décrivaient ce qu'il fallait surveiller sans que
/// personne ne le surveille.
///
/// ## 🔴 Une alerte en sourdine reste une alerte
///
/// La sourdine empêche la **notification**, pas l'**affichage**. Faire disparaître une
/// alerte silencée de l'état donnerait un tableau de bord vert pour un problème connu
/// et non résolu — la même famille d'erreur que `Freshness`.
pub struct AlerteLoop {
    metriques: Arc<crate::promql::Metriques>,
    notif: Option<Arc<hlb_notify::NtfyClient>>,
    /// L'état courant des alertes, partagé avec l'API.
    ///
    /// Même motif que `LastPoll` : la boucle écrit, l'API lit. Un `RwLock` parce que
    /// plusieurs écrans peuvent lire pendant qu'un seul tour écrit.
    pub actives: EtatAlertes,
    regles: Vec<hlb_metrics::Regle>,
}

/// Ce qu'un tour d'évaluation a donné.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AlerteReport {
    pub evaluees: usize,
    pub declenchees: usize,
    /// 🔴 Règles qu'on n'a **pas pu** évaluer. Ce n'est pas « zéro alerte » : c'est
    /// une surveillance aveugle, et ça doit se compter séparément.
    pub inconnues: usize,
    pub notifiees: usize,
}

impl AlerteLoop {
    pub fn new(
        metriques: Arc<crate::promql::Metriques>,
        notif: Option<Arc<hlb_notify::NtfyClient>>,
    ) -> Self {
        Self {
            metriques,
            notif,
            actives: Default::default(),
            regles: hlb_metrics::rules::regles_par_defaut(),
        }
    }

    /// Un tour d'évaluation.
    pub async fn tick(&self, maintenant: i64) -> AlerteReport {
        let mut rapport = AlerteReport::default();
        let mut nouvelles = Vec::new();

        // Les sourdines et les dates d'apparition du tour précédent : une alerte qui
        // persiste garde son ancienneté, sinon « depuis 3 jours » redeviendrait
        // « à l'instant » à chaque tour, et on ne verrait jamais qu'elle dure.
        let precedentes = self.actives.read().await.clone();

        for r in &self.regles {
            rapport.evaluees += 1;

            let valeurs = self.mesurer(r.requete).await;
            let e = match valeurs {
                Ok(v) => r.juger(&v),
                Err(raison) => hlb_metrics::Evaluation::Inconnu { raison },
            };

            let (niveau, valeur) = match &e {
                hlb_metrics::Evaluation::Ok => continue,
                hlb_metrics::Evaluation::Declenchee { valeur } => {
                    rapport.declenchees += 1;
                    (niveau_de(r.niveau), Some(*valeur))
                }
                hlb_metrics::Evaluation::Inconnu { .. } => {
                    rapport.inconnues += 1;
                    if !r.absence_alarmante {
                        continue;
                    }
                    (hlb_api::NiveauAlerte::Inconnu, None)
                }
            };

            let ancienne = precedentes.iter().find(|a| a.regle == r.nom);
            let depuis_s = match ancienne {
                Some(a) => a.depuis_s + INTERVALLE_DEFAUT_S,
                None => 0,
            };

            let alerte = hlb_api::AlerteActive {
                regle: r.nom.to_string(),
                niveau,
                explication: r.explication.to_string(),
                valeur,
                seuil: r.seuil,
                depuis_s,
                silencee_jusqu_a: ancienne.and_then(|a| a.silencee_jusqu_a),
                silencee_par: ancienne.and_then(|a| a.silencee_par.clone()),
            };

            // 🔴 La notification, elle, respecte la sourdine — et pas seulement à la
            // première occurrence : sans ça, une alerte persistante notifierait à
            // chaque tour, et on couperait les notifications en bloc.
            let deja_signalee = ancienne.is_some();
            if !alerte.est_silencee(maintenant) && !deja_signalee {
                if let Some(n) = r.notification(&e) {
                    // `notify_or_log` : sans ntfy configuré, l'alerte part aux journaux
                    // plutôt que nulle part. Une alerte qui disparaît faute de canal
                    // est pire que pas d'alerte du tout.
                    hlb_notify::ntfy::notify_or_log(self.notif.as_deref(), &n).await;
                    rapport.notifiees += 1;
                }
            }

            nouvelles.push(alerte);
        }

        // Trié par gravité : ce qui compte doit être en haut sans que l'interface ait
        // à refaire ce tri.
        nouvelles.sort_by(|a, b| b.niveau.cmp(&a.niveau).then_with(|| a.regle.cmp(&b.regle)));
        *self.actives.write().await = nouvelles;
        rapport
    }

    /// Interroge la base de séries et rend les valeurs courantes.
    async fn mesurer(&self, requete: &str) -> Result<Vec<f64>, String> {
        // On réutilise le relais : sa liste blanche s'applique aussi à nos propres
        // règles, ce qui garantit qu'aucune règle livrée n'interroge autre chose que
        // les métriques attendues.
        match self
            .metriques
            .instant(requete)
            .await
        {
            Ok(v) => Ok(v),
            Err(e) => Err(e),
        }
    }
}

/// L'état des alertes, partagé entre la boucle qui écrit et l'API qui lit.
pub type EtatAlertes = Arc<tokio::sync::RwLock<Vec<hlb_api::AlerteActive>>>;

/// Les écarts du dernier tour de réconciliation, refus délibérés compris.
///
/// Même motif que les alertes : la boucle écrit, l'API lit. Sans ce partage, les
/// non-actions du système ne sortaient jamais des journaux — c'est-à-dire nulle part.
pub type EtatEcarts = Arc<tokio::sync::RwLock<Vec<hlb_api::EcartSummary>>>;

/// Intervalle par défaut entre deux évaluations.
pub const INTERVALLE_DEFAUT_S: i64 = 60;

fn niveau_de(l: hlb_notify::Level) -> hlb_api::NiveauAlerte {
    match l {
        hlb_notify::Level::Debug | hlb_notify::Level::Info => hlb_api::NiveauAlerte::Info,
        hlb_notify::Level::Important => hlb_api::NiveauAlerte::Important,
        hlb_notify::Level::Critical => hlb_api::NiveauAlerte::Critique,
    }
}

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

    // -----------------------------------------------------------------------
    // AlerteLoop (lot 3.4)
    // -----------------------------------------------------------------------

    fn boucle_alertes() -> AlerteLoop {
        // Pas de ntfy, pas de VictoriaMetrics : on exerce la logique d'état, pas le
        // réseau. C'est justement ce que le découpage permet.
        AlerteLoop::new(
            Arc::new(crate::promql::Metriques::new("http://127.0.0.1:1")),
            None,
        )
    }

    fn alerte(regle: &str, niveau: hlb_api::NiveauAlerte, depuis: i64) -> hlb_api::AlerteActive {
        hlb_api::AlerteActive {
            regle: regle.into(),
            niveau,
            explication: "quelque chose".into(),
            valeur: Some(1.0),
            seuil: 0.0,
            depuis_s: depuis,
            silencee_jusqu_a: None,
            silencee_par: None,
        }
    }

    #[tokio::test]
    async fn an_unreachable_metrics_base_produces_unknown_not_silence() {
        // 🔴 Le cas qui compte : VictoriaMetrics est injoignable. Ne rien signaler
        // donnerait un tableau de bord vert alors que TOUTE la surveillance est
        // aveugle. Les règles marquées `absence_alarmante` doivent remonter.
        let b = boucle_alertes();
        let r = b.tick(1_000).await;

        assert!(r.evaluees > 0, "aucune règle évaluée");
        assert!(r.inconnues > 0, "une base injoignable doit produire des inconnues");

        let actives = b.actives.read().await;
        assert!(
            actives.iter().any(|a| a.niveau == hlb_api::NiveauAlerte::Inconnu),
            "aucune alerte « non évaluable » : la surveillance serait aveugle en silence"
        );
    }

    #[tokio::test]
    async fn alerts_are_sorted_worst_first() {
        // L'interface ne doit pas avoir à retrier : ce qui compte est en haut.
        let b = boucle_alertes();
        b.tick(1_000).await;

        let actives = b.actives.read().await;
        for f in actives.windows(2) {
            assert!(
                f[0].niveau >= f[1].niveau,
                "tri cassé : {:?} avant {:?}",
                f[0].niveau,
                f[1].niveau
            );
        }
    }

    #[tokio::test]
    async fn a_persisting_alert_keeps_its_age() {
        // 🔴 Une alerte qui dure depuis trois jours et une qui vient d'apparaître ne se
        // traitent pas pareil : la première a été ignorée, ou son remède ne marche pas.
        // Réinitialiser l'ancienneté à chaque tour effacerait cette information.
        let b = boucle_alertes();
        b.tick(1_000).await;
        let apres_un = b.actives.read().await.clone();
        assert!(!apres_un.is_empty());

        b.tick(1_060).await;
        let apres_deux = b.actives.read().await.clone();

        let av = apres_un.first().expect("une alerte");
        let ap = apres_deux
            .iter()
            .find(|a| a.regle == av.regle)
            .expect("la même alerte");
        assert!(ap.depuis_s > av.depuis_s, "l'ancienneté doit croître");
    }

    #[tokio::test]
    async fn a_silence_survives_a_new_evaluation() {
        // Une sourdine qui sauterait au tour suivant ne servirait à rien : on la
        // reposerait toutes les minutes.
        let b = boucle_alertes();
        b.tick(1_000).await;

        {
            let mut w = b.actives.write().await;
            for a in w.iter_mut() {
                a.silencee_jusqu_a = Some(9_999);
                a.silencee_par = Some("remy".into());
            }
        }

        b.tick(1_060).await;
        let actives = b.actives.read().await;
        assert!(
            actives.iter().all(|a| a.silencee_jusqu_a == Some(9_999)),
            "la sourdine a été perdue au tour suivant"
        );
        assert!(actives.iter().all(|a| a.silencee_par.as_deref() == Some("remy")));
    }

    #[tokio::test]
    async fn a_silenced_alert_stays_in_the_list() {
        // 🔴 La sourdine empêche la NOTIFICATION, pas l'AFFICHAGE. La faire
        // disparaître donnerait un tableau de bord vert pour un problème connu et non
        // résolu.
        let b = boucle_alertes();
        b.tick(1_000).await;
        let avant = b.actives.read().await.len();

        {
            let mut w = b.actives.write().await;
            for a in w.iter_mut() {
                a.silencee_jusqu_a = Some(9_999);
            }
        }
        b.tick(1_060).await;

        assert_eq!(
            b.actives.read().await.len(),
            avant,
            "une alerte silencée a disparu de la liste"
        );
    }

    #[test]
    fn every_notify_level_maps_to_an_alert_level() {
        // Un `match` exhaustif : ajouter un niveau à `hlb_notify` doit faire échouer la
        // compilation ici plutôt que de retomber silencieusement sur « info ».
        assert_eq!(niveau_de(hlb_notify::Level::Debug), hlb_api::NiveauAlerte::Info);
        assert_eq!(niveau_de(hlb_notify::Level::Info), hlb_api::NiveauAlerte::Info);
        assert_eq!(
            niveau_de(hlb_notify::Level::Important),
            hlb_api::NiveauAlerte::Important
        );
        assert_eq!(
            niveau_de(hlb_notify::Level::Critical),
            hlb_api::NiveauAlerte::Critique
        );
    }

    #[test]
    fn an_alert_report_counts_unknowns_separately() {
        // « Zéro déclenchée » avec dix inconnues n'est pas « tout va bien ».
        let r = AlerteReport {
            evaluees: 10,
            declenchees: 0,
            inconnues: 10,
            notifiees: 0,
        };
        assert_ne!(r.inconnues, 0);
        assert_eq!(r.declenchees, 0);
    }

    #[test]
    fn an_alert_that_has_never_been_seen_starts_at_zero() {
        let a = alerte("x", hlb_api::NiveauAlerte::Critique, 0);
        assert_eq!(a.depuis_s, 0);
        assert!(!a.est_silencee(1_000));
    }

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
    async fn a_purge_without_stalwart_marks_nothing() {
        // 🔴 Marquer un alias « purgé » sans l'avoir retiré du serveur serait le pire
        // des deux mondes : l'adresse recevrait encore, ET plus rien ne le
        // signalerait. Le silence entretiendrait la croyance que la porte est fermée.
        let s = Arc::new(State::in_memory().await.expect("état"));
        s.upsert_user("remy", "standard", None).await.expect("compte");
        s.add_mailbox("remy", "remy", "example.fr", true).await.expect("boîte");
        s.add_alias("remy", "remy", "vieux", Some(1), None, None)
            .await
            .expect("alias expiré");

        let l = AliasPurgeLoop::new(s.clone(), None, "example.fr");
        let r = l.tick().await;

        assert_eq!(r.dus, 1);
        assert_eq!(r.retires, 0);
        assert_eq!(r.encore_ouvertes(), 1, "l'adresse reçoit toujours");
        assert!(!r.is_clean());

        // Et l'état n'a PAS été touché : l'alias reste signalé comme actif.
        let restants = s.aliases_to_purge(9_999_999_999).await.expect("relecture");
        assert_eq!(restants.len(), 1, "rien n'a été marqué purgé");
    }

    #[tokio::test]
    async fn a_clean_purge_has_nothing_left_open() {
        // Aucun alias expiré : rien à faire, et le compte rendu doit le dire sans
        // fabriquer une alerte.
        let s = Arc::new(State::in_memory().await.expect("état"));
        s.upsert_user("remy", "standard", None).await.expect("compte");
        s.add_mailbox("remy", "remy", "example.fr", true).await.expect("boîte");
        // Permanent : jamais dû.
        s.add_alias("remy", "remy", "contact", None, None, None)
            .await
            .expect("alias permanent");

        let r = AliasPurgeLoop::new(s, None, "example.fr").tick().await;
        assert_eq!(r.dus, 0);
        assert!(r.is_clean());
        assert!(r.errors.is_empty(), "aucune alerte pour un permanent : {:?}", r.errors);
    }

    #[test]
    fn what_matters_is_what_stays_open_not_the_error_count() {
        // 🔴 Une purge SANS erreur qui n'a rien retiré laisse autant de portes
        // ouvertes qu'une purge qui a échoué bruyamment. C'est le premier chiffre
        // qu'on regarde.
        let muette = PurgeReport { dus: 5, retires: 0, errors: vec![] };
        assert_eq!(muette.encore_ouvertes(), 5);
        assert!(!muette.is_clean(), "aucune erreur, et pourtant cinq portes ouvertes");

        let bruyante = PurgeReport {
            dus: 5,
            retires: 5,
            errors: vec!["avertissement".into()],
        };
        assert!(bruyante.is_clean(), "tout est refermé : le bruit ne change rien");
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
