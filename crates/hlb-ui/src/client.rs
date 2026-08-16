//! Interrogation du controller, en tâche de fond.
//!
//! ## 🔴 Une donnée périmée ne doit JAMAIS ressembler à une donnée fraîche
//!
//! C'est le piège central de tout tableau de bord qui interroge périodiquement.
//!
//! Le controller tombe. L'UI garde son dernier état connu et continue de l'afficher :
//! toutes les apps sont vertes, les sauvegardes datent de dix minutes, tout va bien.
//! Pendant ce temps le cluster brûle. L'écran est **exactement** celui d'un système en
//! bonne santé, et c'est précisément quand on a besoin de lui qu'il ment.
//!
//! C'est la même famille d'erreur que « une métrique absente vaut mieux qu'un zéro »
//! (§8bis) et que « un nœud injoignable n'est pas un nœud sain » (§9bis) : dans les
//! trois cas, l'absence d'information se déguise en information rassurante.
//!
//! D'où [`Freshness`], que l'interface est obligée de regarder — le type ne permet pas
//! d'accéder aux données sans savoir de quand elles datent.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hlb_api::{AppSummary, AuditItem, GuideItem, Health, SecretItem};

/// De quand datent les données affichées.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Freshness {
    /// Jamais interrogé : au démarrage.
    Never,
    /// Réponse obtenue il y a `secs` secondes.
    Fresh { secs: u64 },
    /// 🔴 Le controller ne répond plus. `secs` dit depuis quand les données datent.
    Stale { secs: u64, error: String },
}

impl Freshness {
    /// Peut-on se fier à ce qui est affiché ?
    pub fn is_trustworthy(&self) -> bool {
        matches!(self, Self::Fresh { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Never => "connexion en cours…".to_string(),
            Self::Fresh { secs } if *secs < 2 => "à l'instant".to_string(),
            Self::Fresh { secs } => format!("il y a {secs} s"),
            Self::Stale { secs, error } => format!(
                "🔴 CONTROLLER INJOIGNABLE — données vieilles de {} ({error})",
                hlb_api::humanise(*secs as i64)
            ),
        }
    }
}

/// Tout ce que l'UI affiche.
#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    pub health: Option<Health>,
    pub apps: Vec<AppSummary>,
    pub todo: Vec<GuideItem>,
    pub audit: Vec<AuditItem>,
    pub secrets: Vec<SecretItem>,
}

/// L'état partagé entre le sondeur et l'interface.
pub struct Shared {
    data: Mutex<Snapshot>,
    /// Instant de la dernière réponse RÉUSSIE. `None` = jamais.
    last_ok: Mutex<Option<Instant>>,
    last_error: Mutex<Option<String>>,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            data: Mutex::new(Snapshot::default()),
            last_ok: Mutex::new(None),
            last_error: Mutex::new(None),
        }
    }
}

impl Shared {
    /// Les données **et** leur fraîcheur, indissociables.
    ///
    /// 🔴 Il n'existe pas d'accesseur qui rende les données seules : l'interface ne
    /// peut pas afficher un tableau de bord sans savoir de quand il date.
    pub fn read(&self) -> (Snapshot, Freshness) {
        let data = self.data.lock().map(|d| d.clone()).unwrap_or_default();
        let ok = self.last_ok.lock().ok().and_then(|o| *o);
        let err = self.last_error.lock().ok().and_then(|e| e.clone());

        let fraicheur = match (ok, err) {
            (None, _) => Freshness::Never,
            (Some(t), None) => Freshness::Fresh {
                secs: t.elapsed().as_secs(),
            },
            (Some(t), Some(e)) => Freshness::Stale {
                secs: t.elapsed().as_secs(),
                error: e,
            },
        };
        (data, fraicheur)
    }
}

/// Interroge le controller.
pub struct Client {
    base_url: String,
    /// Jeton pour `/metrics` et, plus tard, les routes protégées.
    token: Option<String>,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(base_url: impl Into<String>, token: Option<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token,
            agent: ureq::Agent::new_with_config(
                ureq::Agent::config_builder()
                    // Court : un tableau de bord qui gèle dix secondes sur chaque
                    // tour donne l'impression que c'est LUI qui est cassé.
                    .timeout_global(Some(Duration::from_secs(5)))
                    .build(),
            ),
        }
    }

    fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let url = format!("{}{path}", self.base_url);
        let mut req = self.agent.get(&url);
        if let Some(t) = &self.token {
            req = req.header("Authorization", &format!("Bearer {t}"));
        }

        let mut resp = req.call().map_err(|e| lisible(&e))?;
        resp.body_mut()
            .read_json::<T>()
            .map_err(|e| format!("réponse illisible : {e}"))
    }

    /// Un tour complet.
    ///
    /// ⚠️ Tout ou rien : si une seule route échoue, on ne met **rien** à jour. Un
    /// instantané où les apps datent de maintenant et le journal d'audit d'il y a une
    /// heure serait incohérent, et l'incohérence ne se verrait pas à l'écran.
    pub fn poll(&self) -> Result<Snapshot, String> {
        Ok(Snapshot {
            health: Some(self.get("/healthz")?),
            apps: self.get("/api/apps")?,
            todo: self.get("/api/todo")?,
            audit: self.get("/api/audit")?,
            secrets: self.get("/api/secrets")?,
        })
    }
}

/// Rend une erreur `ureq` compréhensible.
///
/// Le message brut parle de couches réseau ; l'utilisateur a besoin de savoir si c'est
/// le controller qui est arrêté, l'adresse qui est fausse, ou le jeton qui manque.
fn lisible(e: &ureq::Error) -> String {
    let brut = e.to_string();
    if brut.contains("401") {
        return "jeton refusé (--token)".into();
    }
    if brut.contains("Connection refused") || brut.contains("connection refused") {
        return "controller arrêté ou mauvais port".into();
    }
    if brut.contains("dns") || brut.contains("Dns") || brut.contains("resolve") {
        return "nom d'hôte introuvable".into();
    }
    if brut.contains("timed out") || brut.contains("Timeout") {
        return "délai dépassé".into();
    }
    brut
}

/// Démarre le sondage en tâche de fond.
///
/// `repaint` réveille egui : sans lui, l'interface ne se redessine qu'au prochain
/// mouvement de souris, et les données paraissent figées alors qu'elles arrivent.
pub fn spawn_poller(
    client: Client,
    shared: Arc<Shared>,
    interval: Duration,
    repaint: impl Fn() + Send + 'static,
) {
    std::thread::spawn(move || loop {
        match client.poll() {
            Ok(s) => {
                if let Ok(mut d) = shared.data.lock() {
                    *d = s;
                }
                if let Ok(mut o) = shared.last_ok.lock() {
                    *o = Some(Instant::now());
                }
                if let Ok(mut e) = shared.last_error.lock() {
                    *e = None;
                }
            }
            Err(msg) => {
                // 🔴 On garde les DONNÉES précédentes — elles restent la meilleure
                // information disponible — mais on marque l'échec, et c'est lui que
                // l'interface affichera en gros.
                if let Ok(mut e) = shared.last_error.lock() {
                    *e = Some(msg);
                }
            }
        }
        repaint();
        std::thread::sleep(interval);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_are_never_readable_without_their_age() {
        // 🔴 La garantie est structurelle : `read()` rend un couple, et il n'existe
        // aucun accesseur qui donne les données seules.
        let s = Shared::default();
        let (_, f) = s.read();
        assert_eq!(f, Freshness::Never);
        assert!(!f.is_trustworthy());
    }

    #[test]
    fn an_unreachable_controller_is_never_trustworthy() {
        // Le piège : garder le dernier état connu et l'afficher comme s'il était
        // actuel. Toutes les apps vertes pendant que le cluster brûle.
        let f = Freshness::Stale {
            secs: 300,
            error: "controller arrêté".into(),
        };
        assert!(!f.is_trustworthy());
        assert!(f.describe().contains("INJOIGNABLE"), "{}", f.describe());
        assert!(f.describe().contains("5 min"), "l'âge doit être visible");
    }

    #[test]
    fn fresh_data_say_so_discreetly() {
        assert!(Freshness::Fresh { secs: 1 }.is_trustworthy());
        assert_eq!(Freshness::Fresh { secs: 1 }.describe(), "à l'instant");
        assert_eq!(Freshness::Fresh { secs: 12 }.describe(), "il y a 12 s");
    }

    #[test]
    fn the_base_url_is_normalised() {
        let c = Client::new("http://localhost:8420/", None);
        assert_eq!(c.base_url, "http://localhost:8420");
    }

    #[test]
    fn network_errors_say_what_to_check() {
        // Le message brut de ureq parle de couches réseau ; l'utilisateur veut
        // savoir si c'est le controller, l'adresse ou le jeton.
        let c = Client::new("http://127.0.0.1:9", None);
        let e = c.poll().unwrap_err();
        assert!(
            e.contains("arrêté") || e.contains("délai") || e.contains("refus"),
            "message peu utile : {e}"
        );
    }

    #[test]
    fn a_partial_failure_updates_nothing() {
        // ⚠️ Un instantané où les apps datent de maintenant et l'audit d'il y a une
        // heure serait incohérent — et l'incohérence ne se verrait pas à l'écran.
        // `poll` s'arrête au premier `?`.
        let c = Client::new("http://127.0.0.1:9", None);
        assert!(c.poll().is_err());
    }
}
