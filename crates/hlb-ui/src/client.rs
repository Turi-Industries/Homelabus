//! Interrogation du controller, sur les deux cibles.
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
//!
//! ## 🔴 Deux pièges propres au navigateur
//!
//! 1. **`std::time::Instant::now()` PANIQUE sur `wasm32-unknown-unknown`.** Il n'y a
//!    pas d'horloge monotone dans cette cible. Une UI qui compile parfaitement se
//!    ferme donc sur une page blanche au premier appel. On utilise l'horloge d'egui
//!    (`ctx.input(|i| i.time)`), qui existe partout et évite une dépendance de plus.
//!
//! 2. **Il n'y a ni thread ni `sleep` en WebAssembly.** Un `thread::spawn` + `sleep`
//!    gèlerait l'onglet. Le sondage est donc piloté par la boucle de rendu d'egui :
//!    à chaque image, on regarde si l'intervalle est écoulé. Ça marche à l'identique
//!    en natif, donc il n'y a **qu'un seul chemin de code** à maintenir.

use std::sync::{Arc, Mutex};

use hlb_api::{AppSummary, AuditItem, GuideItem, Health, SecretItem};

/// De quand datent les données affichées.
#[derive(Debug, Clone, PartialEq)]
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
                "CONTROLLER INJOIGNABLE — données vieilles de {} ({error})",
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

/// L'état partagé entre le sondage et l'interface.
#[derive(Default)]
pub struct Shared {
    data: Mutex<Snapshot>,
    /// Horloge d'egui à la dernière réponse RÉUSSIE. `None` = jamais.
    ///
    /// ⚠️ Volontairement un `f64` et pas un `Instant` : ce dernier panique en
    /// WebAssembly.
    last_ok: Mutex<Option<f64>>,
    last_error: Mutex<Option<String>>,
}

impl Shared {
    /// Les données **et** leur fraîcheur, indissociables.
    ///
    /// 🔴 Il n'existe pas d'accesseur qui rende les données seules : l'interface ne
    /// peut pas afficher un tableau de bord sans savoir de quand il date.
    pub fn read(&self, now: f64) -> (Snapshot, Freshness) {
        let data = self.data.lock().map(|d| d.clone()).unwrap_or_default();
        let ok = self.last_ok.lock().ok().and_then(|o| *o);
        let err = self.last_error.lock().ok().and_then(|e| e.clone());

        let fraicheur = match (ok, err) {
            (None, _) => Freshness::Never,
            (Some(t), None) => Freshness::Fresh {
                secs: (now - t).max(0.0) as u64,
            },
            (Some(t), Some(e)) => Freshness::Stale {
                secs: (now - t).max(0.0) as u64,
                error: e,
            },
        };
        (data, fraicheur)
    }

    fn succes(&self, s: Snapshot, now: f64) {
        if let Ok(mut d) = self.data.lock() {
            *d = s;
        }
        if let Ok(mut o) = self.last_ok.lock() {
            *o = Some(now);
        }
        if let Ok(mut e) = self.last_error.lock() {
            *e = None;
        }
    }

    fn echec(&self, message: String) {
        // 🔴 On garde les DONNÉES précédentes — elles restent la meilleure information
        // disponible — mais on marque l'échec, et c'est lui que l'interface affiche
        // en gros.
        if let Ok(mut e) = self.last_error.lock() {
            *e = Some(message);
        }
    }
}

/// Les routes à interroger, dans l'ordre.
const ROUTES: &[&str] = &["/healthz", "/api/apps", "/api/todo", "/api/audit", "/api/secrets"];

/// Les réponses d'un tour, remplies au fil des retours réseau.
///
/// `Option` : pas encore répondu. `Result` : répondu, avec succès ou non.
type Reponses = Arc<Mutex<Vec<Option<Result<String, String>>>>>;

/// Un tour de sondage en cours.
struct EnCours {
    /// Réponses reçues, indexées comme [`ROUTES`].
    recu: Reponses,
    /// Horloge d'egui au lancement du tour.
    lance_a: f64,
}

/// Pilote le sondage depuis la boucle de rendu.
pub struct Poller {
    base_url: String,
    token: Option<String>,
    interval_secs: f64,
    shared: Arc<Shared>,
    en_cours: Option<EnCours>,
    /// Horloge d'egui au dernier lancement, réussi ou non.
    dernier_lancement: Option<f64>,
}

impl Poller {
    pub fn new(
        base_url: impl Into<String>,
        token: Option<String>,
        interval_secs: f64,
        shared: Arc<Shared>,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token,
            // Un intervalle nul ferait tourner le sondage en boucle serrée et
            // saturerait le controller sans rien apporter.
            interval_secs: interval_secs.max(1.0),
            shared,
            en_cours: None,
            dernier_lancement: None,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// À appeler à chaque image. Lance un tour si c'est le moment, récolte sinon.
    pub fn tick(&mut self, now: f64, reveil: impl Fn() + Clone + Send + 'static) {
        if self.en_cours.is_some() {
            self.recolter(now);
            return;
        }

        let du = match self.dernier_lancement {
            None => true,
            Some(t) => now - t >= self.interval_secs,
        };
        if du {
            self.lancer(now, reveil);
        }
    }

    fn lancer(&mut self, now: f64, reveil: impl Fn() + Clone + Send + 'static) {
        let recu: Reponses = Arc::new(Mutex::new(vec![None; ROUTES.len()]));

        for (i, route) in ROUTES.iter().enumerate() {
            let mut req = ehttp::Request::get(format!("{}{route}", self.base_url));
            if let Some(t) = &self.token {
                req.headers.insert("Authorization", format!("Bearer {t}"));
            }

            let recu = recu.clone();
            let reveil = reveil.clone();
            ehttp::fetch(req, move |resultat| {
                let valeur = match resultat {
                    Err(e) => Err(lisible(&e)),
                    Ok(r) if !r.ok => Err(match r.status {
                        401 => "jeton refusé (--token)".to_string(),
                        s => format!("HTTP {s}"),
                    }),
                    Ok(r) => match r.text() {
                        Some(t) => Ok(t.to_string()),
                        None => Err("réponse illisible".to_string()),
                    },
                };
                if let Ok(mut v) = recu.lock() {
                    v[i] = Some(valeur);
                }
                reveil();
            });
        }

        self.dernier_lancement = Some(now);
        self.en_cours = Some(EnCours { recu, lance_a: now });
    }

    fn recolter(&mut self, now: f64) {
        let Some(tour) = &self.en_cours else { return };

        // Un tour qui n'aboutit jamais (réseau qui avale les paquets) doit finir par
        // être abandonné, sinon plus aucun sondage ne repart et l'écran reste figé
        // sur « connexion en cours ».
        const DELAI: f64 = 15.0;
        if now - tour.lance_a > DELAI {
            self.shared.echec("délai dépassé".into());
            self.en_cours = None;
            return;
        }

        let Ok(v) = tour.recu.lock() else { return };
        if v.iter().any(|r| r.is_none()) {
            return;
        }

        // ⚠️ Tout ou rien : si une seule route a échoué, on ne met RIEN à jour. Un
        // instantané où les apps datent de maintenant et le journal d'une heure serait
        // incohérent, et l'incohérence ne se verrait pas à l'écran.
        let mut corps = Vec::with_capacity(ROUTES.len());
        for r in v.iter() {
            match r {
                Some(Ok(t)) => corps.push(t.clone()),
                Some(Err(e)) => {
                    let msg = e.clone();
                    drop(v);
                    self.shared.echec(msg);
                    self.en_cours = None;
                    return;
                }
                None => return,
            }
        }
        drop(v);

        match assembler(&corps) {
            Ok(s) => self.shared.succes(s, now),
            Err(e) => self.shared.echec(e),
        }
        self.en_cours = None;
    }
}

/// Assemble les cinq réponses en un instantané.
fn assembler(corps: &[String]) -> Result<Snapshot, String> {
    // Une fonction générique et non une fermeture : le type d'une fermeture est figé
    // par son premier usage, et les cinq routes rendent des types différents.
    fn de<T: serde::de::DeserializeOwned>(corps: &[String], i: usize) -> Result<T, String> {
        serde_json::from_str(&corps[i]).map_err(|e| format!("{} : {e}", ROUTES[i]))
    }

    Ok(Snapshot {
        health: Some(de(corps, 0)?),
        apps: de(corps, 1)?,
        todo: de(corps, 2)?,
        audit: de(corps, 3)?,
        secrets: de(corps, 4)?,
    })
}

/// Rend une erreur réseau compréhensible.
///
/// Le message brut parle de couches réseau ; l'utilisateur a besoin de savoir si c'est
/// le controller qui est arrêté, l'adresse qui est fausse, ou le jeton qui manque.
fn lisible(brut: &str) -> String {
    let b = brut.to_lowercase();
    if b.contains("connection refused") || b.contains("connexion refus") {
        return "controller arrêté ou mauvais port".into();
    }
    if b.contains("dns") || b.contains("resolve") || b.contains("nodename") {
        return "nom d'hôte introuvable".into();
    }
    if b.contains("timed out") || b.contains("timeout") {
        return "délai dépassé".into();
    }
    // En navigateur, une politique CORS absente donne un message parfaitement
    // opaque : autant nommer la cause la plus probable.
    if b.contains("failed to fetch") || b.contains("networkerror") {
        return "injoignable depuis le navigateur (controller arrêté, ou CORS absent)".into();
    }
    brut.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_are_never_readable_without_their_age() {
        // 🔴 La garantie est structurelle : `read()` rend un couple, et il n'existe
        // aucun accesseur qui donne les données seules.
        let s = Shared::default();
        let (_, f) = s.read(0.0);
        assert_eq!(f, Freshness::Never);
        assert!(!f.is_trustworthy());
    }

    #[test]
    fn an_unreachable_controller_is_never_trustworthy() {
        // Le piège : garder le dernier état connu et l'afficher comme s'il était
        // actuel. Toutes les apps vertes pendant que le cluster brûle.
        let s = Shared::default();
        s.succes(Snapshot::default(), 100.0);
        s.echec("controller arrêté".into());

        let (_, f) = s.read(400.0);
        assert!(!f.is_trustworthy());
        assert!(f.describe().contains("INJOIGNABLE"), "{}", f.describe());
        assert!(f.describe().contains("5 min"), "l'âge doit être visible");
    }

    #[test]
    fn the_last_known_state_is_kept_but_marked() {
        // Garder les données est utile : c'est la meilleure information disponible.
        // Ce qu'il ne faut pas, c'est les présenter comme actuelles.
        let s = Shared::default();
        s.succes(
            Snapshot {
                apps: vec![],
                health: Some(Health {
                    status: "ok".into(),
                    version: "1".into(),
                    uptime_secs: 5,
                }),
                ..Default::default()
            },
            10.0,
        );
        s.echec("arrêté".into());

        let (d, f) = s.read(20.0);
        assert!(d.health.is_some(), "le dernier état connu reste disponible");
        assert!(!f.is_trustworthy(), "mais il n'est plus présenté comme fiable");
    }

    #[test]
    fn a_success_clears_a_previous_error() {
        let s = Shared::default();
        s.echec("arrêté".into());
        s.succes(Snapshot::default(), 50.0);
        assert!(s.read(50.5).1.is_trustworthy());
    }

    #[test]
    fn no_wall_clock_is_used_because_instant_panics_in_wasm() {
        // 🔴 `std::time::Instant::now()` PANIQUE sur wasm32-unknown-unknown. Une UI
        // qui compile parfaitement se ferme alors sur une page blanche. Toute la
        // fraîcheur passe donc par l'horloge d'egui, fournie en paramètre.
        // On scanne le CODE, pas les commentaires : ceux-ci nomment justement les
        // pièges, et les inclure ferait échouer le test sur sa propre documentation.
        // Les motifs sont assemblés à l'exécution pour la même raison.
        let code: String = include_str!("client.rs")
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        for motif in [format!("Instant::{}()", "now"), format!("thread::{}", "sleep")] {
            assert!(
                !code.contains(&motif),
                "« {motif} » est revenu dans le code : il paniquera ou gèlera l'onglet"
            );
        }
    }

    #[test]
    fn the_base_url_is_normalised() {
        let p = Poller::new("http://localhost:8420/", None, 5.0, Arc::default());
        assert_eq!(p.base_url(), "http://localhost:8420");
    }

    #[test]
    fn the_interval_can_never_be_zero() {
        // Un intervalle nul ferait tourner le sondage en boucle serrée et saturerait
        // le controller sans rien apporter : les données bougent à la minute.
        let p = Poller::new("http://x", None, 0.0, Arc::default());
        assert!(p.interval_secs >= 1.0);
    }

    #[test]
    fn network_errors_say_what_to_check() {
        assert!(lisible("Connection refused (os error 61)").contains("arrêté"));
        assert!(lisible("failed to lookup address: nodename nor servname").contains("hôte"));
        assert!(lisible("operation timed out").contains("délai"));
        // Le message du navigateur est opaque : il faut nommer la cause probable.
        assert!(lisible("TypeError: Failed to fetch").contains("CORS"));
    }

    #[test]
    fn a_partial_response_updates_nothing() {
        // ⚠️ Un instantané où les apps datent de maintenant et l'audit d'il y a une
        // heure serait incohérent — et ça ne se verrait pas à l'écran.
        let corps = vec![
            r#"{"status":"ok","version":"1","uptime_secs":1}"#.to_string(),
            "[]".to_string(),
            "[]".to_string(),
            "pas du json".to_string(),
            "[]".to_string(),
        ];
        let e = assembler(&corps).unwrap_err();
        assert!(e.contains("/api/audit"), "l'erreur doit nommer la route : {e}");
    }

    #[test]
    fn a_complete_response_is_assembled() {
        let corps = vec![
            r#"{"status":"ok","version":"1","uptime_secs":42}"#.to_string(),
            r#"[{"name":"gitea","status":"running","image":"a/b:1","domain":null,
                "last_backup_secs":60,"last_verification_secs":null,
                "blocking_guides":0}]"#
                .to_string(),
            "[]".to_string(),
            "[]".to_string(),
            "[]".to_string(),
        ];
        let s = assembler(&corps).expect("assemblable");
        assert_eq!(s.apps.len(), 1);
        assert_eq!(s.apps[0].name, "gitea");
        assert_eq!(s.health.expect("santé").uptime_secs, 42);
    }
}
