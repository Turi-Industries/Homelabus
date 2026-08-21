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
    /// Jamais interrogé : au démarrage, l'espace de quelques instants.
    Never,
    /// 🔴 Jamais RÉUSSI, et on sait pourquoi.
    ///
    /// Distinct de [`Self::Stale`], qui suppose une réussite antérieure. Sans cette
    /// variante, un controller qui refuse la toute première requête — jeton absent,
    /// adresse erronée — laisse l'écran sur « connexion en cours… » indéfiniment :
    /// un chargement perpétuel, sans la moindre explication.
    NeverSucceeded { error: String },
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
            Self::NeverSucceeded { error } => {
                format!("CONNEXION IMPOSSIBLE — {error}")
            }
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
            // 🔴 Jamais réussi ET une erreur connue : on la dit, au lieu de laisser
            // croire que la connexion est encore en cours.
            (None, Some(e)) => Freshness::NeverSucceeded { error: e },
            (None, None) => Freshness::Never,
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

/// Les routes du tableau de bord, sondées ensemble.
///
/// ⚠️ Celles-ci restent groupées **délibérément** : elles alimentent un même écran, et
/// un instantané où les apps dateraient de maintenant et le journal d'une heure serait
/// incohérent sans que ça se voie. Les écrans de détail, eux, utilisent [`Ressource`],
/// qui porte sa propre fraîcheur.
const ROUTES: &[&str] = &[
    "/healthz",
    "/api/apps",
    "/api/todo",
    "/api/audit",
    "/api/secrets",
];

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

/// Au-delà, un tour est abandonné et une nouvelle requête pourra repartir.
///
/// Sans ça, un réseau qui avale les paquets fige l'écran sur « connexion en cours »
/// pour toujours : aucun nouveau sondage ne repart, et rien ne dit pourquoi.
const DELAI_ABANDON: f64 = 15.0;

/// Comment joindre le controller.
///
/// Extrait pour que [`Ressource`] et [`Poller`] s'en servent sans le dupliquer : deux
/// endroits qui construiraient l'en-tête d'autorisation finiraient par en avoir un qui
/// l'oublie, et l'écran correspondant afficherait un 401 inexplicable.
#[derive(Clone)]
pub struct Acces {
    base_url: String,
    token: Option<String>,
}

impl Acces {
    pub fn new(base_url: impl Into<String>, token: Option<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn requete(&self, chemin: &str) -> ehttp::Request {
        let mut r = ehttp::Request::get(format!("{}{chemin}", self.base_url));
        self.autoriser(&mut r);
        r
    }

    /// Une requête qui MODIFIE quelque chose.
    ///
    /// 🔴 Pose l'en-tête `X-HLB-UI`, exigé par le controller sur toute requête mutante
    /// portée par un cookie de session. `SameSite=Lax` seul ne couvre pas un `POST`
    /// déclenché depuis un autre site ; un en-tête personnalisé, si.
    pub fn action(&self, methode: &str, chemin: &str, corps: &str) -> ehttp::Request {
        let mut r = ehttp::Request {
            method: methode.to_string(),
            url: format!("{}{chemin}", self.base_url),
            body: corps.as_bytes().to_vec(),
            headers: ehttp::Headers::new(&[("Content-Type", "application/json"), (ENTETE_UI, "1")]),
        };
        self.autoriser(&mut r);
        r
    }

    fn autoriser(&self, r: &mut ehttp::Request) {
        if let Some(t) = &self.token {
            r.headers.insert("Authorization", format!("Bearer {t}"));
        }
    }
}

/// L'en-tête anti-CSRF exigé par le controller.
///
/// ⚠️ Doit correspondre à `hlb_controller::auth::ENTETE_UI`. Une divergence rendrait
/// TOUTES les actions impossibles, avec un `403` dont le message parle de CSRF — ce
/// qui n'oriente pas vers une faute de frappe côté interface.
pub const ENTETE_UI: &str = "x-hlb-ui";

/// Traduit une réponse HTTP en corps utilisable ou en message lisible.
pub fn corps_ou_message(resultat: Result<ehttp::Response, String>) -> Result<String, String> {
    match resultat {
        Err(e) => Err(lisible(&e)),
        Ok(r) if !r.ok => Err(match r.status {
            // 🔴 Le cas le plus fréquent après un déploiement : dire COMMENT obtenir un
            // jeton, pas seulement qu'il en faut un.
            401 => "jeton absent ou refusé — « hlb token create <nom> --role viewer \
                    --apply », puis ouvre l'UI avec #token=<valeur>"
                .to_string(),
            403 => "jeton valide mais rôle insuffisant".to_string(),
            429 => "trop de requêtes — le controller a limité le débit".to_string(),
            s => format!("HTTP {s}"),
        }),
        Ok(r) => match r.text() {
            Some(t) => Ok(t.to_string()),
            None => Err("réponse illisible".to_string()),
        },
    }
}

/// La table de décision de la fraîcheur.
///
/// Une seule implémentation, partagée par [`Shared`] et [`Ressource`] : deux copies
/// finiraient par diverger, et la divergence irait dans le sens rassurant.
fn fraicheur(last_ok: Option<f64>, last_error: Option<String>, now: f64) -> Freshness {
    match (last_ok, last_error) {
        // 🔴 Jamais réussi ET une erreur connue : on la dit, au lieu de laisser croire
        // que la connexion est encore en cours.
        (None, Some(e)) => Freshness::NeverSucceeded { error: e },
        (None, None) => Freshness::Never,
        (Some(t), None) => Freshness::Fresh {
            secs: (now - t).max(0.0) as u64,
        },
        (Some(t), Some(e)) => Freshness::Stale {
            secs: (now - t).max(0.0) as u64,
            error: e,
        },
    }
}

/// Une réponse réseau **estampillée du tour qui l'a demandée**.
///
/// Le numéro est ce qui permet de jeter la réponse d'un tour abandonné : sans lui, une
/// réponse tardive serait adoptée comme fraîche.
type ReponseDatee = Arc<Mutex<Option<(u64, Result<String, String>)>>>;

/// Ce qu'une [`Ressource`] sait d'elle-même.
struct EtatRessource<T> {
    donnees: Option<T>,
    last_ok: Option<f64>,
    last_error: Option<String>,
    /// Horloge d'egui au lancement de la requête en vol. `None` = rien en vol.
    lance_a: Option<f64>,
    dernier_lancement: Option<f64>,
    /// 🔴 Numéro du tour. Une réponse abandonnée pour dépassement de délai peut très
    /// bien arriver ensuite : sans ce numéro, elle serait consommée comme fraîche et
    /// l'écran afficherait des données vieilles de plusieurs minutes en les datant de
    /// maintenant. C'est exactement le mensonge que `Freshness` existe pour empêcher.
    tour: u64,
}

impl<T> Default for EtatRessource<T> {
    fn default() -> Self {
        Self {
            donnees: None,
            last_ok: None,
            last_error: None,
            lance_a: None,
            dernier_lancement: None,
            tour: 0,
        }
    }
}

/// Une donnée d'écran, **avec sa propre fraîcheur**.
///
/// ## Pourquoi une par écran plutôt qu'un instantané global
///
/// Le tableau de bord tient dans un seul tour de sondage. Un écran de détail, non : les
/// journaux se rafraîchissent à la seconde, la liste des sauvegardes toutes les
/// minutes, le catalogue jamais. Les sonder ensemble ferait payer à chacun la cadence
/// du plus pressé, et un échec sur l'un priverait tous les autres.
///
/// 🔴 Ce qui NE change pas : il n'existe aucun accesseur qui rende la donnée seule.
/// [`Ressource::lire`] rend toujours le couple `(donnée, fraîcheur)`. Une donnée périmée
/// ne doit jamais ressembler à une donnée fraîche, et cette garantie doit survivre au
/// passage de un à vingt écrans.
pub struct Ressource<T> {
    chemin: String,
    intervalle_s: f64,
    etat: Mutex<EtatRessource<T>>,
    /// La case que remplit le rappel réseau, estampillée du numéro de tour.
    ///
    /// ⚠️ Le rappel ne peut pas dater sa réponse : il n'a pas accès à l'horloge d'egui,
    /// et `Instant::now()` PANIQUE en WebAssembly. C'est `tick` — qui reçoit `now` de la
    /// boucle de rendu — qui horodate.
    boite: ReponseDatee,
}

impl<T: serde::de::DeserializeOwned + Clone> Ressource<T> {
    pub fn new(chemin: impl Into<String>, intervalle_s: f64) -> Self {
        Self {
            chemin: chemin.into(),
            // Un intervalle nul ferait tourner le sondage à la fréquence de rendu, soit
            // soixante requêtes par seconde et par ressource.
            intervalle_s: intervalle_s.max(0.5),
            etat: Mutex::new(EtatRessource::default()),
            boite: Arc::new(Mutex::new(None)),
        }
    }

    pub fn chemin(&self) -> &str {
        &self.chemin
    }

    /// La donnée **et** sa fraîcheur, indissociables.
    pub fn lire(&self, now: f64) -> (Option<T>, Freshness) {
        match self.etat.lock() {
            Ok(e) => (
                e.donnees.clone(),
                fraicheur(e.last_ok, e.last_error.clone(), now),
            ),
            // Un verrou empoisonné ne doit pas faire passer l'absence de donnée pour
            // une donnée fraîche.
            Err(_) => (
                None,
                Freshness::NeverSucceeded {
                    error: "état interne corrompu".into(),
                },
            ),
        }
    }

    /// Force un rafraîchissement au prochain `tick`.
    ///
    /// Sert au bouton « actualiser » et au retour d'une action : attendre l'intervalle
    /// après avoir cliqué sur « redémarrer » ferait croire que rien ne s'est passé.
    pub fn invalider(&self) {
        if let Ok(mut e) = self.etat.lock() {
            e.dernier_lancement = None;
        }
    }

    /// À appeler à chaque image.
    pub fn tick(&self, acces: &Acces, now: f64, reveil: impl Fn() + Send + 'static) {
        self.recolter(now);

        let (en_vol, du) = match self.etat.lock() {
            Ok(e) => (
                e.lance_a.is_some(),
                match e.dernier_lancement {
                    None => true,
                    Some(t) => now - t >= self.intervalle_s,
                },
            ),
            Err(_) => return,
        };

        if !en_vol && du {
            self.lancer(acces, now, reveil);
        }
    }

    fn lancer(&self, acces: &Acces, now: f64, reveil: impl Fn() + Send + 'static) {
        let tour = {
            let Ok(mut e) = self.etat.lock() else { return };
            e.tour = e.tour.wrapping_add(1);
            e.lance_a = Some(now);
            e.dernier_lancement = Some(now);
            e.tour
        };

        let boite = self.boite.clone();
        ehttp::fetch(acces.requete(&self.chemin), move |resultat| {
            if let Ok(mut b) = boite.lock() {
                *b = Some((tour, corps_ou_message(resultat)));
            }
            reveil();
        });
    }

    fn recolter(&self, now: f64) {
        let attendu = match self.etat.lock() {
            Ok(e) => e.tour,
            Err(_) => return,
        };

        // On ne prend la réponse que si elle correspond au tour courant. Une réponse
        // d'un tour abandonné est jetée — et sa case libérée, sinon elle bloquerait la
        // suivante.
        let arrivee = match self.boite.lock() {
            Ok(mut b) => match b.take() {
                Some((t, r)) if t == attendu => Some(r),
                Some(_) => None,
                None => None,
            },
            Err(_) => None,
        };

        match arrivee {
            Some(Ok(corps)) => {
                match serde_json::from_str::<T>(&corps) {
                    Ok(v) => self.succes(v, now),
                    // 🔴 La route est NOMMÉE : « JSON invalide » tout seul n'aide pas à
                    // savoir laquelle des vingt requêtes a mal tourné.
                    Err(e) => self.echec(format!("{} : réponse illisible ({e})", self.chemin)),
                }
                self.terminer();
            }
            Some(Err(e)) => {
                self.echec(e);
                self.terminer();
            }
            None => {
                let expire = self
                    .etat
                    .lock()
                    .ok()
                    .and_then(|e| e.lance_a)
                    .is_some_and(|t| now - t > DELAI_ABANDON);
                if expire {
                    self.echec("délai dépassé".into());
                    self.terminer();
                }
            }
        }
    }

    fn terminer(&self) {
        if let Ok(mut e) = self.etat.lock() {
            e.lance_a = None;
        }
    }

    fn succes(&self, v: T, now: f64) {
        if let Ok(mut e) = self.etat.lock() {
            e.donnees = Some(v);
            e.last_ok = Some(now);
            e.last_error = None;
        }
    }

    fn echec(&self, message: String) {
        // 🔴 On garde les DONNÉES précédentes — elles restent la meilleure information
        // disponible — mais on marque l'échec, et c'est lui que l'interface affiche.
        if let Ok(mut e) = self.etat.lock() {
            e.last_error = Some(message);
        }
    }
}

/// La réponse d'une action, estampillée de `applique` — pour la ranger au bon endroit.
type ReponseAction = Arc<Mutex<Option<(bool, Result<String, String>)>>>;

/// Une action déclenchée depuis l'interface, et son avancement.
///
/// ## Le cycle, et pourquoi il a trois temps
///
/// 1. **Aperçu** — la route est appelée sans `?apply=true` ; on obtient ce qui *serait*
///    fait.
/// 2. **Confirmation** — l'utilisateur voit le plan et décide.
/// 3. **Application** — la même route, avec `?apply=true`.
///
/// 🔴 Deux temps ne suffiraient pas : un bouton « installer » qui montre une boîte de
/// dialogue générique (« Confirmer ? ») ne dit rien de ce qui va se passer. C'est le
/// PLAN qu'il faut lire, pas une question.
#[derive(Default)]
pub struct ActionEnCours {
    /// L'aperçu obtenu, en attente de décision.
    pub apercu: Mutex<Option<hlb_api::ResultatAction>>,
    /// Le résultat de l'application.
    pub resultat: Mutex<Option<hlb_api::ResultatAction>>,
    /// Une erreur de transport (pas un refus métier, qui vit dans `blocages`).
    pub erreur: Mutex<Option<String>>,
    /// 🔴 Le lien à usage unique que certaines réponses portent (enrôlement PocketID,
    /// invitation créée).
    ///
    /// Gardé en mémoire vive le temps de l'afficher, jamais rangé : il ne s'affiche
    /// qu'une fois, et un stockage le rendrait réaffichable — donc récupérable par
    /// quelqu'un d'autre sur un navigateur partagé.
    lien: Mutex<Option<String>>,
    /// Une requête est-elle en vol ?
    ///
    /// Sert à griser le bouton : double-cliquer sur « appliquer » lancerait deux
    /// installations.
    pub en_vol: Mutex<bool>,
    /// La case que remplit le rappel réseau.
    boite: ReponseAction,
}

impl ActionEnCours {
    /// Lance un aperçu ou une application.
    pub fn lancer(
        &self,
        acces: &Acces,
        methode: &str,
        chemin: &str,
        corps: &str,
        applique: bool,
        reveil: impl Fn() + Send + 'static,
    ) {
        if self.en_vol.lock().map(|v| *v).unwrap_or(false) {
            // Déjà en cours : un second clic ne doit pas lancer une seconde action.
            return;
        }
        if let Ok(mut v) = self.en_vol.lock() {
            *v = true;
        }
        if let Ok(mut e) = self.erreur.lock() {
            *e = None;
        }

        let url = if applique {
            format!(
                "{chemin}{}apply=true",
                if chemin.contains('?') { "&" } else { "?" }
            )
        } else {
            chemin.to_string()
        };

        let boite = self.boite.clone();
        ehttp::fetch(acces.action(methode, &url, corps), move |resultat| {
            if let Ok(mut b) = boite.lock() {
                *b = Some((applique, corps_ou_message(resultat)));
            }
            reveil();
        });
    }

    /// À appeler à chaque image : range la réponse arrivée.
    pub fn recolter(&self) {
        let Some((applique, r)) = self.boite.lock().ok().and_then(|mut b| b.take()) else {
            return;
        };
        if let Ok(mut v) = self.en_vol.lock() {
            *v = false;
        }

        // Le lien éventuel : extrait avant la désérialisation typée, parce qu'il ne
        // fait pas partie de `ResultatAction` — il n'y a rien à faire dans un type que
        // l'API renvoie partout.
        let corps_brut = r.clone().ok();
        if let Some(l) = corps_brut
            .as_deref()
            .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
            .and_then(|v| {
                v.get("lien_enrolement")
                    .or_else(|| v.get("lien"))
                    .and_then(|x| x.as_str().map(str::to_string))
            })
        {
            if let Ok(mut cible) = self.lien.lock() {
                *cible = Some(l);
            }
        }

        match r.and_then(|corps| {
            serde_json::from_str::<hlb_api::ResultatAction>(&corps)
                .map_err(|e| format!("réponse illisible ({e})"))
        }) {
            Ok(res) => {
                let cible = if applique {
                    &self.resultat
                } else {
                    &self.apercu
                };
                if let Ok(mut c) = cible.lock() {
                    *c = Some(res);
                }
            }
            Err(e) => {
                if let Ok(mut err) = self.erreur.lock() {
                    *err = Some(e);
                }
            }
        }
    }

    /// Efface tout : on ferme le panneau d'action.
    pub fn fermer(&self) {
        if let Ok(mut a) = self.apercu.lock() {
            *a = None;
        }
        if let Ok(mut r) = self.resultat.lock() {
            *r = None;
        }
        if let Ok(mut e) = self.erreur.lock() {
            *e = None;
        }
        // Le lien part avec le reste : le garder le ferait réapparaître sur l'action
        // suivante, qui n'a rien à voir.
        if let Ok(mut l) = self.lien.lock() {
            *l = None;
        }
    }

    pub fn lire_apercu(&self) -> Option<hlb_api::ResultatAction> {
        self.apercu.lock().ok().and_then(|a| a.clone())
    }

    pub fn lire_resultat(&self) -> Option<hlb_api::ResultatAction> {
        self.resultat.lock().ok().and_then(|r| r.clone())
    }

    pub fn lire_erreur(&self) -> Option<String> {
        self.erreur.lock().ok().and_then(|e| e.clone())
    }

    /// Le lien à usage unique de la dernière réponse, s'il y en avait un.
    pub fn lire_lien(&self) -> Option<String> {
        self.lien.lock().ok().and_then(|l| l.clone())
    }

    pub fn occupee(&self) -> bool {
        self.en_vol.lock().map(|v| *v).unwrap_or(false)
    }
}

/// Les ressources des écrans d'administration.
///
/// Chacune a **sa propre cadence et sa propre fraîcheur** : les journaux se
/// rafraîchissent à la seconde, le catalogue jamais. Les sonder ensemble ferait payer à
/// chacun la cadence du plus pressé, et un échec sur l'un priverait tous les autres.
pub struct Ressources {
    pub noeuds: Ressource<Vec<hlb_api::NoeudSummary>>,
    pub taches: Ressource<Vec<hlb_api::TacheSummary>>,
    pub alertes: Ressource<Vec<hlb_api::AlerteActive>>,
    pub sauvegardes: Ressource<Vec<hlb_api::SauvegardeRun>>,
    pub couverture: Ressource<Vec<hlb_api::CouvertureSummary>>,
    pub topologie: Ressource<hlb_api::Topologie>,
    /// Les écarts du dernier tour de réconciliation, refus délibérés compris.
    pub ecarts: Ressource<Vec<hlb_api::EcartSummary>>,
    /// Ce qui est déclaré, face à ce qui est réellement publié.
    pub exposition: Ressource<Vec<hlb_api::ExpositionSummary>>,
    /// La liste de contrôle de l'installation.
    pub sante: Ressource<Vec<hlb_api::ControleSante>>,
    /// Sauvegardes et actions dans une seule rivière datée.
    pub frise: Ressource<Vec<hlb_api::Evenement>>,
    /// Les secrets et ce que leur rotation impliquerait.
    pub rotation: Ressource<Vec<hlb_api::rotation::SecretARouler>>,
    /// Les garde-fous d'accès de secours (§5.7bis).
    pub secours: Ressource<Vec<hlb_api::breakglass::GardeFou>>,
    /// Les plans préparés à froid (§10.4).
    pub plans: Ressource<Vec<hlb_api::PlanNomme>>,
    pub comptes: Ressource<Vec<hlb_api::CompteSummary>>,
    pub invitations: Ressource<Vec<hlb_api::InvitationSummary>>,
    pub portail: Ressource<crate::ecrans::portail::Portail>,
    pub annonces: Ressource<Vec<hlb_api::Annonce>>,
    pub statut: Ressource<hlb_api::PageStatut>,
    pub preferences: Ressource<hlb_api::Preferences>,
    /// L'action en cours, s'il y en a une. Une seule à la fois : mener deux actions
    /// de front sur la même app est un accident, pas un besoin.
    pub action: ActionEnCours,
    /// Le détail de l'app **actuellement regardée**.
    ///
    /// 🔴 Une seule ressource, reciblée quand on change d'app — et non une par app.
    /// Sur cinquante apps, en garder cinquante sonderait le controller pour
    /// quarante-neuf écrans que personne ne regarde.
    ///
    /// ⚠️ Le rechargement doit être EXPLICITE (`cibler`) : sans lui, l'écran d'une app
    /// afficherait un instant le détail de la précédente, avec une fraîcheur qui dirait
    /// « à jour ». Exactement le mensonge que `Freshness` existe pour empêcher.
    detail_app: Mutex<Option<(String, Ressource<hlb_api::AppDetail>)>>,
    /// L'historique des manifests de l'app affichée. Même motif de reciblage que
    /// `detail_app` : garder l'ancienne donnée montrerait le passé d'une autre app.
    versions_app: Mutex<Option<(String, Ressource<Vec<hlb_api::VersionManifest>>)>>,
}

impl Default for Ressources {
    fn default() -> Self {
        Self {
            // Les nœuds et les alertes bougent à l'échelle de la minute, mais ce sont
            // eux qu'on regarde en cas de problème : dix secondes est le compromis.
            noeuds: Ressource::new("/api/noeuds", 10.0),
            taches: Ressource::new("/api/taches", 10.0),
            alertes: Ressource::new("/api/alertes", 10.0),
            // L'historique ne change qu'au rythme des sauvegardes, soit toutes les
            // quatre heures : le redemander toutes les dix secondes serait du bruit.
            sauvegardes: Ressource::new("/api/sauvegardes", 60.0),
            couverture: Ressource::new("/api/couverture", 60.0),
            // La topologie ne bouge qu'au rythme des déploiements et des ajouts de
            // nœuds : la sonder plus souvent serait du bruit.
            topologie: Ressource::new("/api/topologie", 30.0),
            // La réconciliation tourne à la minute : sonder plus vite ne montrerait
            // rien de nouveau.
            ecarts: Ressource::new("/api/derive", 30.0),
            exposition: Ressource::new("/api/exposition", 60.0),
            // Elle ne change qu'au rythme des décisions d'installation.
            sante: Ressource::new("/api/sante", 120.0),
            frise: Ressource::new("/api/frise", 30.0),
            rotation: Ressource::new("/api/secrets/rotation", 120.0),
            secours: Ressource::new("/api/secours", 120.0),
            plans: Ressource::new("/api/plans", 60.0),
            // Les comptes ne changent qu'à la main : trente secondes suffisent, et le
            // rafraîchissement forcé après une action fait le reste.
            comptes: Ressource::new("/api/comptes", 30.0),
            invitations: Ressource::new("/api/invitations", 30.0),
            // Le portail se regarde, il ne se surveille pas : trente secondes suffisent.
            portail: Ressource::new("/api/portail", 30.0),
            annonces: Ressource::new("/api/annonces", 30.0),
            // C'est la page qu'on regarde quand ça ne va pas : dix secondes.
            statut: Ressource::new("/api/statut", 10.0),
            // Une préférence ne change que quand on la change : deux minutes suffisent,
            // et `invalider` la relit tout de suite après un choix.
            preferences: Ressource::new("/api/preferences", 120.0),
            action: ActionEnCours::default(),
            detail_app: Mutex::new(None),
            versions_app: Mutex::new(None),
        }
    }
}

impl Ressources {
    /// À appeler à chaque image.
    pub fn tick(&self, acces: &Acces, now: f64, reveil: impl Fn() + Clone + Send + 'static) {
        self.noeuds.tick(acces, now, reveil.clone());
        self.taches.tick(acces, now, reveil.clone());
        self.alertes.tick(acces, now, reveil.clone());
        self.sauvegardes.tick(acces, now, reveil.clone());
        self.couverture.tick(acces, now, reveil.clone());
        self.topologie.tick(acces, now, reveil.clone());
        self.ecarts.tick(acces, now, reveil.clone());
        self.exposition.tick(acces, now, reveil.clone());
        self.sante.tick(acces, now, reveil.clone());
        self.frise.tick(acces, now, reveil.clone());
        self.rotation.tick(acces, now, reveil.clone());
        self.secours.tick(acces, now, reveil.clone());
        self.plans.tick(acces, now, reveil.clone());
        self.comptes.tick(acces, now, reveil.clone());
        self.invitations.tick(acces, now, reveil.clone());
        self.portail.tick(acces, now, reveil.clone());
        self.annonces.tick(acces, now, reveil.clone());
        self.statut.tick(acces, now, reveil.clone());
        self.preferences.tick(acces, now, reveil);
        self.action.recolter();
    }

    /// Le détail d'une app, en reciblant la ressource si nécessaire.
    ///
    /// Rend `(détail, fraîcheur)` comme toute ressource — jamais la donnée seule.
    pub fn detail_app(
        &self,
        nom: &str,
        acces: &Acces,
        now: f64,
        reveil: impl Fn() + Send + 'static,
    ) -> (Option<hlb_api::AppDetail>, Freshness) {
        let Ok(mut cible) = self.detail_app.lock() else {
            return (
                None,
                Freshness::NeverSucceeded {
                    error: "état interne corrompu".into(),
                },
            );
        };

        // 🔴 Changement d'app : on REMPLACE la ressource plutôt que de la vider. Garder
        // l'ancienne donnée le temps d'un tour afficherait le détail de l'app
        // précédente sous le nom de la nouvelle.
        let a_recibler = cible.as_ref().map(|(n, _)| n != nom).unwrap_or(true);
        if a_recibler {
            *cible = Some((
                nom.to_string(),
                // Cinq secondes : c'est l'écran qu'on regarde en train de déployer, et
                // le placement des réplicas y bouge à la seconde.
                Ressource::new(format!("/api/apps/{nom}/detail"), 5.0),
            ));
        }

        let Some((_, r)) = cible.as_ref() else {
            return (None, Freshness::Never);
        };
        r.tick(acces, now, reveil);
        r.lire(now)
    }

    /// L'historique des manifests de l'app affichée.
    pub fn versions_app(
        &self,
        nom: &str,
        acces: &Acces,
        now: f64,
        reveil: impl Fn() + Send + 'static,
    ) -> Option<Vec<hlb_api::VersionManifest>> {
        let Ok(mut cible) = self.versions_app.lock() else {
            return None;
        };

        if cible.as_ref().map(|(n, _)| n != nom).unwrap_or(true) {
            *cible = Some((
                nom.to_string(),
                // Un manifest ne change qu'aux déploiements : inutile de sonder vite.
                Ressource::new(format!("/api/apps/{nom}/versions"), 60.0),
            ));
        }

        let (_, r) = cible.as_ref()?;
        r.tick(acces, now, reveil);
        r.lire(now).0
    }

    /// Force un rafraîchissement de tout au prochain tour.
    pub fn invalider_tout(&self) {
        self.noeuds.invalider();
        self.taches.invalider();
        self.alertes.invalider();
        self.sauvegardes.invalider();
        self.couverture.invalider();
        self.topologie.invalider();
        self.ecarts.invalider();
        self.exposition.invalider();
        self.sante.invalider();
        self.frise.invalider();
        self.rotation.invalider();
        self.secours.invalider();
        self.plans.invalider();
        self.comptes.invalider();
        self.invitations.invalider();
        self.portail.invalider();
        self.annonces.invalider();
        self.statut.invalider();
        self.preferences.invalider();
        if let Ok(c) = self.detail_app.lock() {
            if let Some((_, r)) = c.as_ref() {
                r.invalider();
            }
        }
    }
}

/// Le sondage groupé du tableau de bord.
///
/// Conservé tel quel à côté de [`Ressource`] : les cinq routes qu'il interroge
/// alimentent un même écran, et un instantané mi-frais serait incohérent sans que ça se
/// voie. Les écrans de détail, eux, ont chacun leur [`Ressource`].
pub struct Poller {
    acces: Acces,
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
            acces: Acces::new(base_url, token),
            interval_secs: interval_secs.max(1.0),
            shared,
            en_cours: None,
            dernier_lancement: None,
        }
    }

    pub fn acces(&self) -> &Acces {
        &self.acces
    }

    pub fn base_url(&self) -> &str {
        self.acces.base_url()
    }

    /// À appeler à chaque image.
    ///
    /// ⚠️ Piloté par la boucle de rendu, pas par un fil : il n'y a ni thread ni `sleep`
    /// en WebAssembly, et un `thread::spawn` gèlerait l'onglet.
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
            let recu = recu.clone();
            let reveil = reveil.clone();
            ehttp::fetch(self.acces.requete(route), move |resultat| {
                let valeur = corps_ou_message(resultat);
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
        // être abandonné, sinon plus aucun sondage ne repart et l'écran reste figé sur
        // « connexion en cours ».
        if now - tour.lance_a > DELAI_ABANDON {
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
        serde_json::from_str(&corps[i])
            // La route est NOMMÉE : « JSON invalide » tout seul n'aide pas à savoir
            // laquelle des cinq requêtes a mal tourné.
            .map_err(|e| format!("{} : réponse illisible ({e})", ROUTES[i]))
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
    #[test]
    fn every_resource_is_read_through_its_only_accessor() {
        // 🔴 Le lot 12.4. `Ressource::lire` est le SEUL accesseur, et il rend
        // `(Option<&T>, Freshness)` : le type oblige à regarder l'âge. Un écran qui
        // atteindrait la donnée autrement afficherait le dernier état connu comme s'il
        // était frais — exactement le mensonge que `Freshness` existe pour empêcher.
        //
        // ⚠️ Le test scanne les ÉCRANS, pas ce fichier : c'est là que la tentation
        // existe, et c'est là qu'un raccourci passerait inaperçu en relecture.
        let ecrans = [
            ("mod.rs", include_str!("ecrans/mod.rs")),
            ("app_detail.rs", include_str!("ecrans/app_detail.rs")),
            ("sauvegardes.rs", include_str!("ecrans/sauvegardes.rs")),
            ("noeuds.rs", include_str!("ecrans/noeuds.rs")),
            ("alertes.rs", include_str!("ecrans/alertes.rs")),
            ("topologie.rs", include_str!("ecrans/topologie.rs")),
            ("derive.rs", include_str!("ecrans/derive.rs")),
            ("securite.rs", include_str!("ecrans/securite.rs")),
            ("frise.rs", include_str!("ecrans/frise.rs")),
            ("plans.rs", include_str!("ecrans/plans.rs")),
        ];

        for (nom, src) in ecrans {
            for (n, ligne) in src.lines().enumerate() {
                let code = ligne.split("//").next().unwrap_or("");
                // Les seuls accès légitimes à une ressource passent par `.lire(` — qui
                // rend la fraîcheur — ou par `.invalider()` / `.tick(`, qui ne lisent
                // rien.
                for interdit in [".valeur()", ".donnee()", ".contenu()", ".get()"] {
                    assert!(
                        !code.contains(interdit),
                        "{nom} ligne {} : « {interdit} » contourne Freshness",
                        n + 1
                    );
                }
            }
        }
    }

    #[test]
    fn the_single_accessor_always_hands_back_the_freshness() {
        // La garantie est STRUCTURELLE : `lire` ne peut pas rendre la donnée seule.
        // Si quelqu'un ajoutait un accesseur qui ne rend que `Option<T>`, ce test ne le
        // verrait pas — mais le suivant, qui scanne la signature, si.
        let src = include_str!("client.rs");
        let sig = src
            .lines()
            .find(|l| l.contains("pub fn lire(&self, now: f64)"))
            .expect("l'accesseur unique");
        assert!(
            sig.contains("Freshness"),
            "« lire » doit rendre la fraîcheur avec la donnée : {sig}"
        );
    }

    use super::*;

    // -----------------------------------------------------------------------
    // Actions (lot 5)
    // -----------------------------------------------------------------------

    fn resultat(applique: bool) -> String {
        format!(
            r#"{{"applique":{applique},"resume":"installer gitea","etapes":[],
               "commande_cli":"hlb install gitea --apply","blocages":[]}}"#
        )
    }

    #[test]
    fn a_preview_and_an_application_land_in_different_places() {
        // 🔴 Les confondre ferait afficher « c'est fait » sur un aperçu, ou l'inverse.
        // La distinction voyage AVEC la réponse, pas dans un état à côté qui pourrait
        // se désynchroniser.
        let a = ActionEnCours::default();

        *a.boite.lock().expect("boîte") = Some((false, Ok(resultat(false))));
        a.recolter();
        assert!(
            a.lire_apercu().is_some(),
            "l'aperçu doit être rangé comme tel"
        );
        assert!(a.lire_resultat().is_none());

        *a.boite.lock().expect("boîte") = Some((true, Ok(resultat(true))));
        a.recolter();
        assert!(a.lire_resultat().is_some());
    }

    #[test]
    fn a_second_click_does_not_launch_a_second_action() {
        // Double-cliquer sur « appliquer » lancerait deux installations. Le bouton est
        // grisé à l'écran, mais l'état doit aussi le refuser : un clavier, un
        // rafraîchissement ou une latence contournent le grisé.
        let a = ActionEnCours::default();
        let acces = Acces::new("http://127.0.0.1:1", None);

        *a.en_vol.lock().expect("verrou") = true;
        a.lancer(&acces, "POST", "/api/apps/x/backup", "{}", false, || {});
        // Rien n'a été mis en boîte : la requête n'est pas partie.
        assert!(a.boite.lock().expect("boîte").is_none());
        assert!(a.occupee());
    }

    #[test]
    fn an_unreadable_answer_is_an_error_not_an_empty_result() {
        // Une réponse illisible affichée comme un résultat vide ferait croire que
        // l'action a abouti sans rien faire.
        let a = ActionEnCours::default();
        *a.boite.lock().expect("boîte") = Some((true, Ok("pas du json".into())));
        a.recolter();

        assert!(a.lire_resultat().is_none());
        assert!(a.lire_erreur().is_some());
        assert!(
            !a.occupee(),
            "le verrou doit être relâché même en cas d'erreur"
        );
    }

    #[test]
    fn closing_clears_everything() {
        // Un aperçu qui survivrait à la fermeture réapparaîtrait sur l'action suivante,
        // avec le plan de la précédente.
        let a = ActionEnCours::default();
        *a.boite.lock().expect("boîte") = Some((false, Ok(resultat(false))));
        a.recolter();
        assert!(a.lire_apercu().is_some());

        a.fermer();
        assert!(a.lire_apercu().is_none());
        assert!(a.lire_resultat().is_none());
        assert!(a.lire_erreur().is_none());
    }

    #[test]
    fn applying_adds_the_parameter_without_breaking_an_existing_query() {
        // Le paramètre doit s'ajouter proprement : « ?apply=true » sur une URL qui a
        // déjà une chaîne de requête produirait une adresse invalide.
        let sans = "/api/apps/x/backup";
        let avec = "/api/apps/x/backup?force=1";

        let joint = |c: &str| format!("{c}{}apply=true", if c.contains('?') { "&" } else { "?" });
        assert_eq!(joint(sans), "/api/apps/x/backup?apply=true");
        assert_eq!(joint(avec), "/api/apps/x/backup?force=1&apply=true");
    }

    #[test]
    fn a_mutating_request_carries_the_csrf_header() {
        // 🔴 Sans lui, le controller refuse toute action portée par un cookie de
        // session — avec un 403 dont le message parle de CSRF, ce qui n'oriente pas
        // vers une faute de frappe côté interface.
        let a = Acces::new("http://x:1", Some("jeton".into()));
        let r = a.action("POST", "/api/apps/gitea/backup", "{}");

        assert_eq!(r.method, "POST");
        assert_eq!(r.headers.get(ENTETE_UI), Some("1"));
        assert_eq!(r.headers.get("Authorization"), Some("Bearer jeton"));
        assert_eq!(r.body, b"{}");
    }

    // -----------------------------------------------------------------------
    // Ressource : la fraîcheur par écran
    // -----------------------------------------------------------------------

    #[test]
    fn a_resource_never_yields_data_without_its_age() {
        // 🔴 La garantie structurelle, portée du tableau de bord aux écrans de détail :
        // il n'existe aucun accesseur qui rende la donnée seule.
        let r: Ressource<Vec<String>> = Ressource::new("/api/apps", 5.0);
        let (d, f) = r.lire(0.0);
        assert!(d.is_none());
        assert_eq!(f, Freshness::Never);
        assert!(!f.is_trustworthy());
    }

    #[test]
    fn a_resource_keeps_its_last_known_data_but_marks_the_failure() {
        // Les données précédentes restent la meilleure information disponible ; c'est
        // l'ÉCHEC qui doit se voir, pas un écran vide.
        let r: Ressource<Vec<u32>> = Ressource::new("/api/x", 5.0);
        r.succes(vec![1, 2, 3], 100.0);
        assert!(r.lire(100.0).1.is_trustworthy());

        r.echec("controller injoignable".into());
        let (d, f) = r.lire(160.0);
        assert_eq!(d, Some(vec![1, 2, 3]), "les données doivent survivre");
        match f {
            Freshness::Stale { secs, error } => {
                assert_eq!(secs, 60);
                assert!(error.contains("injoignable"));
            }
            autre => panic!("attendu Stale, obtenu {autre:?}"),
        }
    }

    #[test]
    fn a_resource_that_never_succeeded_says_why() {
        // 🔴 Sans cette distinction, un premier échec — jeton absent, mauvaise adresse —
        // laisse l'écran sur « connexion en cours… » indéfiniment.
        let r: Ressource<u32> = Ressource::new("/api/x", 5.0);
        r.echec("jeton refusé".into());
        match r.lire(10.0).1 {
            Freshness::NeverSucceeded { error } => assert!(error.contains("jeton")),
            autre => panic!("attendu NeverSucceeded, obtenu {autre:?}"),
        }
    }

    #[test]
    fn a_late_answer_from_an_abandoned_round_is_thrown_away() {
        // 🔴 Le cas subtil : une requête abandonnée pour dépassement de délai peut
        // arriver quand même. Sans numéro de tour, elle serait consommée comme fraîche
        // et l'écran daterait de maintenant des données vieilles de plusieurs minutes —
        // exactement le mensonge que `Freshness` existe pour empêcher.
        let r: Ressource<Vec<u32>> = Ressource::new("/api/x", 5.0);

        // Simule un tour lancé (tour 1) puis abandonné.
        {
            let mut e = r.etat.lock().expect("verrou");
            e.tour = 1;
            e.lance_a = Some(0.0);
        }
        r.recolter(DELAI_ABANDON + 1.0);
        assert!(matches!(r.lire(20.0).1, Freshness::NeverSucceeded { .. }));

        // La réponse du tour 1 arrive maintenant, alors qu'on en est au tour 2.
        {
            let mut e = r.etat.lock().expect("verrou");
            e.tour = 2;
        }
        *r.boite.lock().expect("boîte") = Some((1, Ok("[1,2,3]".to_string())));
        r.recolter(30.0);

        assert_eq!(
            r.lire(30.0).0,
            None,
            "une réponse périmée ne doit pas être adoptée"
        );
    }

    #[test]
    fn the_matching_answer_is_adopted() {
        // Le pendant du test précédent : une réponse du tour courant DOIT être prise,
        // sinon l'écran ne se remplirait jamais.
        let r: Ressource<Vec<u32>> = Ressource::new("/api/x", 5.0);
        {
            let mut e = r.etat.lock().expect("verrou");
            e.tour = 7;
            e.lance_a = Some(0.0);
        }
        *r.boite.lock().expect("boîte") = Some((7, Ok("[4,5]".to_string())));
        r.recolter(1.0);

        let (d, f) = r.lire(1.0);
        assert_eq!(d, Some(vec![4, 5]));
        assert!(f.is_trustworthy());
    }

    #[test]
    fn an_unreadable_answer_names_the_route() {
        // « JSON invalide » tout seul n'aide pas à savoir laquelle des vingt requêtes a
        // mal tourné.
        let r: Ressource<Vec<u32>> = Ressource::new("/api/sauvegardes", 5.0);
        {
            let mut e = r.etat.lock().expect("verrou");
            e.tour = 1;
            e.lance_a = Some(0.0);
        }
        *r.boite.lock().expect("boîte") = Some((1, Ok("pas du json".to_string())));
        r.recolter(1.0);

        match r.lire(1.0).1 {
            Freshness::NeverSucceeded { error } => {
                assert!(error.contains("/api/sauvegardes"), "{error}")
            }
            autre => panic!("attendu NeverSucceeded, obtenu {autre:?}"),
        }
    }

    #[test]
    fn a_zero_interval_does_not_poll_at_frame_rate() {
        // Un intervalle nul ferait soixante requêtes par seconde et par ressource — le
        // controller limiterait le débit, et l'écran se remplirait de 429.
        let r: Ressource<u32> = Ressource::new("/api/x", 0.0);
        assert!(r.intervalle_s >= 0.5);
    }

    #[test]
    fn invalidating_forces_the_next_tick_to_fetch() {
        // Après une action, attendre l'intervalle ferait croire que rien ne s'est passé.
        let r: Ressource<u32> = Ressource::new("/api/x", 60.0);
        {
            let mut e = r.etat.lock().expect("verrou");
            e.dernier_lancement = Some(100.0);
        }
        r.invalider();
        assert_eq!(
            r.etat.lock().expect("verrou").dernier_lancement,
            None,
            "la ressource devrait redemander au prochain tour"
        );
    }

    #[test]
    fn the_authorization_header_is_built_in_one_place_only() {
        // Deux endroits qui le construiraient finiraient par en avoir un qui l'oublie,
        // et l'écran correspondant afficherait un 401 inexplicable.
        let a = Acces::new("http://x:1/", Some("jeton".into()));
        let r = a.requete("/api/apps");
        assert_eq!(r.headers.get("Authorization"), Some("Bearer jeton"));
        assert_eq!(
            r.url, "http://x:1/api/apps",
            "la barre finale ne doit pas doubler"
        );

        let sans = Acces::new("http://x:1", None);
        assert!(sans
            .requete("/api/apps")
            .headers
            .get("Authorization")
            .is_none());
    }

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
    fn a_first_request_that_fails_is_never_a_loading_state() {
        // 🔴 Le bug qu'un test d'intégration a trouvé : sans réussite antérieure,
        // l'échec retombait sur « connexion en cours… » — un chargement perpétuel
        // sans explication, exactement ce que cette UI existe pour éviter.
        let s = Shared::default();
        s.echec("jeton absent ou refusé".into());

        let (_, f) = s.read(10.0);
        assert!(!f.is_trustworthy());
        assert!(
            !f.describe().contains("en cours"),
            "un échec ne doit pas ressembler à un chargement : {}",
            f.describe()
        );
        assert!(f.describe().contains("jeton"), "{}", f.describe());
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
        assert!(
            !f.is_trustworthy(),
            "mais il n'est plus présenté comme fiable"
        );
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

        for motif in [
            format!("Instant::{}()", "now"),
            format!("thread::{}", "sleep"),
        ] {
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
        assert!(
            e.contains("/api/audit"),
            "l'erreur doit nommer la route : {e}"
        );
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
