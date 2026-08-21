//! Destinations de sauvegarde multiples et leur routage (§8.1).
//!
//! ## Le problème que ça résout
//!
//! Un seul dépôt suffisait tant qu'il n'y avait qu'un NAS. Dès qu'on veut la règle
//! 3-2-1 du §8.1 — une copie rapide sur le LAN, une copie hors site contre l'incendie
//! et le ransomware — il en faut plusieurs, et **toutes les données ne peuvent pas
//! aller partout**.
//!
//! Ce n'est pas une question d'importance : tout est important. C'est une question de
//! **volume et de tuyau**. Quelques gigaoctets de dumps SQL traversent n'importe quelle
//! connexion domestique ; plusieurs centaines de gigaoctets de photos n'y passent pas,
//! et la première sauvegarde ne rattraperait jamais son retard. D'où le routage par
//! classe de données, décidé à l'installation et non au catalogue — c'est la connexion
//! et le budget de chacun qui tranchent, pas l'auteur d'un manifest.
//!
//! ## 🔴 L'invariant central : une destination fraîche n'en masque jamais une périmée
//!
//! C'est le piège qui viderait le dispositif de son sens. `seconds_since_last_success`
//! prenait le maximum **toutes destinations confondues** : avec un NAS sauvegardé
//! toutes les quatre heures et un hors-site en échec depuis trois semaines, la réponse
//! restait « sauvegardé il y a 2 h ». On croirait la règle 3-2-1 respectée alors qu'il
//! ne reste qu'une seule copie, sur les mêmes machines.
//!
//! La fraîcheur est donc mesurée **par destination**, et [`Etat::pire`] retient
//! toujours le cas le plus défavorable.
//!
//! ## 🔴 Les identifiants ne transitent jamais par un plan ni par un journal
//!
//! Une clé S3 vit au coffre et n'apparaît que dans l'environnement du conteneur
//! restic, au moment de l'exécution. Une destination affichée montre son point
//! d'entrée, jamais ses clés — voir [`Destination::describe`].

use crate::{Error, Result};

/// Une classe de données à sauvegarder.
///
/// 🔴 La distinction n'est pas « important / pas important » — tout l'est. Elle sépare
/// ce qui **tient dans une connexion domestique** de ce qui n'y tient pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Classe {
    /// Dumps SQL, état, secrets, manifests. Quelques gigaoctets au plus.
    ///
    /// C'est ce qui doit partir hors site en priorité : sans la base, les volumes ne
    /// servent à rien ; sans les secrets, les sauvegardes elles-mêmes sont illisibles.
    Critique,
    /// Volumes applicatifs : photos, fichiers, médias. Sans limite haute.
    Volumineux,
}

impl Classe {
    pub fn nom(&self) -> &'static str {
        match self {
            Self::Critique => "critique",
            Self::Volumineux => "volumineux",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critique" | "critical" | "dumps" => Some(Self::Critique),
            "volumineux" | "volumes" | "bulk" => Some(Self::Volumineux),
            _ => None,
        }
    }
}

/// Où va une sauvegarde.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// Identifiant court : `nas`, `garage`, `offsite`.
    pub nom: String,
    /// Emplacement restic. Un chemin, ou une URL `s3:…`.
    pub location: String,
    /// Ce que cette destination accepte. Vide = rien, et c'est dit.
    pub classes: Vec<Classe>,
    /// Nom du secret portant `clé_accès:clé_secrète`, pour les destinations S3.
    pub credentials_secret: Option<String>,
}

impl Destination {
    /// Est-ce un dépôt S3 ?
    ///
    /// 🔴 Décide de tout le reste : un dépôt S3 ne se **monte pas** dans le conteneur
    /// restic, il se joint par le réseau. Le monter créerait un répertoire vide et
    /// restic répondrait « repository does not exist » en désignant un chemin local
    /// qui n'a rien à voir avec la vraie destination.
    pub fn est_s3(&self) -> bool {
        let l = self.location.trim_start();
        l.starts_with("s3:") || l.starts_with("s3s:")
    }

    pub fn accepte(&self, c: Classe) -> bool {
        self.classes.contains(&c)
    }

    /// Description affichable. **Jamais** les identifiants.
    ///
    /// ⚠️ Une URL S3 peut porter des identifiants (`s3:https://clé:secret@hôte/seau`).
    /// On la tronque avant le `@` : sinon `hlb backup dest list` publierait la clé dans
    /// le terminal, puis dans l'historique du shell, puis dans une capture d'écran.
    /// L'emplacement, identifiants masqués.
    ///
    /// ⚠️ Extrait de `describe` plutôt que recopié : deux masquages divergents
    /// finiraient par en laisser un qui n'en est pas un, et c'est une clé d'accès qui
    /// partirait dans un terminal ou sur un papier imprimé.
    pub fn lieu_masque(&self) -> String {
        match self.location.split_once('@') {
            Some((avant, apres)) if avant.contains("://") => {
                let schema = avant.split_once("://").map(|(s, _)| s).unwrap_or("s3");
                format!("{schema}://••••@{apres}")
            }
            _ => self.location.clone(),
        }
    }

    pub fn describe(&self) -> String {
        let lieu = self.lieu_masque();

        let classes: Vec<&str> = self.classes.iter().map(|c| c.nom()).collect();
        if classes.is_empty() {
            // 🔴 Une destination qui n'accepte rien ne reçoit rien. Le dire, parce
            // qu'elle ressemble par ailleurs à une destination configurée.
            format!("{} → {lieu}  ⚠️ n'accepte AUCUNE classe : rien n'y sera envoyé", self.nom)
        } else {
            format!("{} → {lieu}  [{}]", self.nom, classes.join(", "))
        }
    }

    /// Les variables d'environnement à donner à restic.
    ///
    /// `identifiants` est le contenu du secret, au format `clé_accès:clé_secrète`.
    ///
    /// 🔴 Par l'environnement, jamais par la ligne de commande : celle-ci est lisible
    /// par tout utilisateur de la machine via `ps`.
    pub fn env(&self, identifiants: Option<&str>) -> Result<Vec<(String, String)>> {
        let mut v = Vec::new();

        if !self.est_s3() {
            return Ok(v);
        }

        let Some(id) = identifiants else {
            return Err(Error::Unexpected(format!(
                "destination « {} » : dépôt S3 sans identifiants. Dépose-les avec \
                 « hlb backup dest add {} --location … --access-key … »",
                self.nom, self.nom
            )));
        };

        let Some((cle, secret)) = id.split_once(':') else {
            return Err(Error::Unexpected(format!(
                "destination « {} » : identifiants illisibles, format attendu \
                 « clé_accès:clé_secrète »",
                self.nom
            )));
        };

        v.push(("AWS_ACCESS_KEY_ID".into(), cle.to_string()));
        v.push(("AWS_SECRET_ACCESS_KEY".into(), secret.to_string()));
        Ok(v)
    }
}

impl Destination {
    /// Le runner conteneur et le chemin de dépôt à donner à restic.
    ///
    /// 🔴 Toute la différence entre local et S3 tient ici, et elle est facile à rater :
    /// un dépôt local se **monte** et restic le voit en `/depot` ; un dépôt S3 se
    /// **joint par le réseau** et restic reçoit l'URL telle quelle. Monter une URL
    /// créerait un répertoire vide, et restic répondrait « repository does not exist »
    /// en désignant un chemin local sans rapport avec la vraie destination.
    ///
    /// `network` sert aux dépôts S3 servis DANS le cluster (Garage) : sans lui, le
    /// conteneur restic ne résout pas `garage`.
    pub fn runner(
        &self,
        network: Option<&str>,
    ) -> (crate::runner::ContainerRunner, String) {
        let mut r = crate::runner::ContainerRunner::default();

        if self.est_s3() {
            if let Some(n) = network {
                r = r.network(n);
            }
            (r, self.location.clone())
        } else {
            (r.mount(&self.location, "/depot"), "/depot".to_string())
        }
    }
}

/// La fraîcheur d'une destination pour une app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Etat {
    /// 🔴 Rien n'y est JAMAIS arrivé.
    ///
    /// Distinct d'« en retard », pour la même raison que `NeverSucceeded` l'est de
    /// `Stale` dans l'UI : une destination qui n'a jamais rien reçu n'a jamais rien
    /// protégé. La confondre avec un retard ferait chercher une panne récente, alors
    /// que le routage n'a peut-être jamais été branché.
    Jamais,
    Frais { age_s: i64 },
    /// En retard au-delà du seuil.
    Perime { age_s: i64 },
}

impl Etat {
    pub fn juger(age_s: Option<i64>, seuil_s: i64) -> Self {
        match age_s {
            None => Self::Jamais,
            Some(a) if a > seuil_s => Self::Perime { age_s: a },
            Some(a) => Self::Frais { age_s: a },
        }
    }

    pub fn est_alarmant(&self) -> bool {
        !matches!(self, Self::Frais { .. })
    }
}

/// L'état d'une app sur toutes ses destinations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Couverture {
    pub app: String,
    /// `(nom de destination, état)`.
    pub par_destination: Vec<(String, Etat)>,
}

impl Couverture {
    /// 🔴 Le pire cas, jamais le meilleur.
    ///
    /// C'est LA règle de ce module. Prendre le plus récent — ce que faisait
    /// `seconds_since_last_success` en agrégeant toutes les destinations — laisserait
    /// un NAS frais masquer un hors-site mort depuis trois semaines. On croirait la
    /// règle 3-2-1 tenue alors qu'il ne reste qu'une copie, sur les mêmes machines.
    pub fn pire(&self) -> Option<&Etat> {
        self.par_destination
            .iter()
            .map(|(_, e)| e)
            .max_by_key(|e| match e {
                // Jamais reçu est le pire cas, quel que soit l'âge des autres.
                Etat::Jamais => i64::MAX,
                Etat::Perime { age_s } => *age_s,
                Etat::Frais { age_s } => -*age_s,
            })
    }

    /// Les destinations qui posent problème.
    pub fn alarmantes(&self) -> Vec<&(String, Etat)> {
        self.par_destination
            .iter()
            .filter(|(_, e)| e.est_alarmant())
            .collect()
    }

    /// Combien de copies réellement à jour ?
    ///
    /// 🔴 C'est le chiffre qui compte pour le 3-2-1, et il ne se déduit PAS du nombre
    /// de destinations configurées : une destination en échec est une destination
    /// configurée qui ne protège de rien.
    pub fn copies_a_jour(&self) -> usize {
        self.par_destination
            .iter()
            .filter(|(_, e)| matches!(e, Etat::Frais { .. }))
            .count()
    }
}

/// Ce qu'il faut savoir de l'état pour calculer une couverture.
///
/// ## Pourquoi un trait plutôt qu'un `&State`
///
/// `hlb-backup` ne dépend pas de `hlb-state` et ne doit pas commencer : ce crate est
/// testable sans base ni serveur, et c'est ce qui permet d'exercer toute la logique de
/// sauvegarde en mémoire. Le trait inverse la dépendance — l'appelant fournit les
/// faits, le calcul vit ici.
///
/// C'était **le** défaut : `Couverture` n'était construite que dans le CLI. Le
/// controller ne pouvait donc pas émettre `hlb_backup_copies`, et la règle d'alerte
/// `copie-unique` — celle qui garde le 3-2-1 — ne s'est jamais déclenchée.
#[allow(async_fn_in_trait)]
pub trait SourceCouverture {
    /// Les destinations déclarées.
    async fn destinations(&self) -> Vec<Destination>;

    /// Les destinations explicitement routées pour cette app et cette classe.
    /// Vide = pas de route explicite, on retombe sur ce que chaque destination accepte.
    async fn route(&self, app: &str, classe: Classe) -> Vec<String>;

    /// Âge de la dernière réussite sur cette destination, en secondes.
    /// `None` = jamais réussi — ce qui n'est pas « il y a très longtemps ».
    async fn age_sur(&self, app: &str, destination: &str) -> Option<i64>;
}

/// Les destinations qui doivent recevoir cette classe pour cette app.
///
/// Une route explicite l'emporte ; sinon on retombe sur ce que chaque destination
/// accepte globalement. C'est ce qui permet de dire « le volumineux d'Immich part hors
/// site » sans y envoyer celui de toutes les autres apps.
pub async fn destinations_pour<S: SourceCouverture>(
    source: &S,
    app: &str,
    classe: Classe,
) -> Vec<Destination> {
    let toutes = source.destinations().await;
    let explicites = source.route(app, classe).await;

    if explicites.is_empty() {
        return toutes.into_iter().filter(|d| d.accepte(classe)).collect();
    }
    toutes
        .into_iter()
        .filter(|d| explicites.contains(&d.nom))
        .collect()
}

/// La couverture réelle d'une app : où ses données sont, et de quand.
///
/// 🔴 **Par destination, jamais agrégée.** Un `MAX(finished_at)` sur toutes les
/// destinations fait passer un hors-site mort depuis trois semaines pour une sauvegarde
/// de deux heures, parce que le NAS, lui, tourne. On croit le 3-2-1 tenu alors qu'il ne
/// reste qu'une copie, sur les mêmes machines.
pub async fn couverture_de<S: SourceCouverture>(
    source: &S,
    app: &str,
    seuil_s: i64,
) -> Couverture {
    let mut noms: Vec<String> = Vec::new();
    for c in [Classe::Critique, Classe::Volumineux] {
        for d in destinations_pour(source, app, c).await {
            if !noms.contains(&d.nom) {
                noms.push(d.nom);
            }
        }
    }
    // Trié : une couverture qui changerait d'ordre d'un appel à l'autre rendrait les
    // affichages instables et les tests d'instantané inutilisables.
    noms.sort();

    let mut par_destination = Vec::new();
    for n in noms {
        let age = source.age_sur(app, &n).await;
        par_destination.push((n, Etat::juger(age, seuil_s)));
    }

    Couverture {
        app: app.to_string(),
        par_destination,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une source en mémoire : c'est tout l'intérêt d'avoir inversé la dépendance.
    struct SourceEnMemoire {
        destinations: Vec<Destination>,
        routes: Vec<(String, Classe, Vec<String>)>,
        ages: Vec<(String, String, Option<i64>)>,
    }

    impl SourceCouverture for SourceEnMemoire {
        async fn destinations(&self) -> Vec<Destination> {
            self.destinations.clone()
        }
        async fn route(&self, app: &str, classe: Classe) -> Vec<String> {
            self.routes
                .iter()
                .find(|(a, c, _)| a == app && *c == classe)
                .map(|(_, _, d)| d.clone())
                .unwrap_or_default()
        }
        async fn age_sur(&self, app: &str, destination: &str) -> Option<i64> {
            self.ages
                .iter()
                .find(|(a, d, _)| a == app && d == destination)
                .and_then(|(_, _, age)| *age)
        }
    }

    fn dest(nom: &str, classes: Vec<Classe>) -> Destination {
        Destination {
            nom: nom.into(),
            location: format!("/mnt/{nom}"),
            classes,
            credentials_secret: None,
        }
    }

    #[tokio::test]
    async fn a_fresh_destination_never_hides_a_dead_one() {
        // 🔴 LE piège du §8.1, désormais calculable hors du CLI. Le NAS tourne, le
        // hors-site est mort depuis des semaines : un agrégat ferait passer ça pour une
        // sauvegarde de deux heures, et on croirait le 3-2-1 tenu.
        let s = SourceEnMemoire {
            destinations: vec![
                dest("nas", vec![Classe::Critique, Classe::Volumineux]),
                dest("offsite", vec![Classe::Critique]),
            ],
            routes: Vec::new(),
            ages: vec![
                ("immich".into(), "nas".into(), Some(7_200)),
                ("immich".into(), "offsite".into(), Some(21 * 86_400)),
            ],
        };

        let c = couverture_de(&s, "immich", 12 * 3_600).await;
        assert_eq!(c.par_destination.len(), 2);
        assert_eq!(c.copies_a_jour(), 1, "une seule copie protège vraiment");
        assert!(
            c.pire().is_some_and(|e| e.est_alarmant()),
            "le résumé doit montrer le PIRE cas, pas le meilleur"
        );
    }

    #[tokio::test]
    async fn an_explicit_route_overrides_what_a_destination_accepts() {
        // « Le volumineux d'Immich part hors site » sans y envoyer celui des autres.
        let s = SourceEnMemoire {
            destinations: vec![
                dest("nas", vec![Classe::Critique, Classe::Volumineux]),
                dest("offsite", vec![Classe::Critique]),
            ],
            routes: vec![(
                "immich".into(),
                Classe::Volumineux,
                vec!["offsite".into()],
            )],
            ages: Vec::new(),
        };

        let v = destinations_pour(&s, "immich", Classe::Volumineux).await;
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].nom, "offsite", "la route explicite l'emporte");

        // Une autre app garde le comportement par défaut.
        let v = destinations_pour(&s, "gitea", Classe::Volumineux).await;
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].nom, "nas");
    }

    #[tokio::test]
    async fn an_app_never_backed_up_has_zero_copies() {
        // « Configuré n'est pas protégé » : deux destinations déclarées, zéro copie.
        let s = SourceEnMemoire {
            destinations: vec![
                dest("nas", vec![Classe::Critique]),
                dest("offsite", vec![Classe::Critique]),
            ],
            routes: Vec::new(),
            ages: Vec::new(),
        };
        let c = couverture_de(&s, "seafile", 12 * 3_600).await;
        assert_eq!(c.par_destination.len(), 2, "les destinations sont bien déclarées");
        assert_eq!(c.copies_a_jour(), 0, "et ne protègent de rien");
    }

    #[tokio::test]
    async fn coverage_order_is_stable() {
        // Un ordre qui varierait rendrait les affichages instables et les tests
        // d'instantané inutilisables.
        let s = SourceEnMemoire {
            destinations: vec![
                dest("zzz", vec![Classe::Critique]),
                dest("aaa", vec![Classe::Critique]),
                dest("mmm", vec![Classe::Critique]),
            ],
            routes: Vec::new(),
            ages: Vec::new(),
        };
        let c = couverture_de(&s, "app", 3_600).await;
        let noms: Vec<&str> = c.par_destination.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(noms, vec!["aaa", "mmm", "zzz"]);
    }


    fn d(nom: &str, location: &str, classes: Vec<Classe>) -> Destination {
        Destination {
            nom: nom.into(),
            location: location.into(),
            classes,
            credentials_secret: None,
        }
    }

    #[test]
    fn a_fresh_destination_never_masks_a_stale_one() {
        // 🔴 L'invariant du module. Avec un NAS sauvegardé toutes les 4 h et un
        // hors-site en échec depuis trois semaines, l'ancienne agrégation répondait
        // « sauvegardé il y a 2 h ». On croyait le 3-2-1 tenu alors qu'il ne restait
        // qu'une copie, sur les mêmes machines.
        let c = Couverture {
            app: "immich".into(),
            par_destination: vec![
                ("nas".into(), Etat::Frais { age_s: 7_200 }),
                ("offsite".into(), Etat::Perime { age_s: 1_814_400 }),
            ],
        };

        assert_eq!(c.pire(), Some(&Etat::Perime { age_s: 1_814_400 }));
        assert_eq!(c.alarmantes().len(), 1);
        assert_eq!(c.copies_a_jour(), 1, "une seule copie protège vraiment");
    }

    #[test]
    fn never_received_outranks_any_delay() {
        // Une destination qui n'a JAMAIS rien reçu est pire qu'une très en retard :
        // elle n'a jamais rien protégé, et la cause est différente — le routage n'a
        // probablement jamais été branché.
        let c = Couverture {
            app: "immich".into(),
            par_destination: vec![
                ("offsite".into(), Etat::Perime { age_s: 10_000_000 }),
                ("garage".into(), Etat::Jamais),
            ],
        };
        assert_eq!(c.pire(), Some(&Etat::Jamais));
    }

    #[test]
    fn configured_is_not_protected() {
        // 🔴 Le nombre de destinations configurées ne dit rien du nombre de copies.
        // Trois destinations dont deux en échec, ce n'est pas du 3-2-1.
        let c = Couverture {
            app: "immich".into(),
            par_destination: vec![
                ("nas".into(), Etat::Frais { age_s: 100 }),
                ("garage".into(), Etat::Jamais),
                ("offsite".into(), Etat::Perime { age_s: 999_999 }),
            ],
        };
        assert_eq!(c.par_destination.len(), 3);
        assert_eq!(c.copies_a_jour(), 1);
    }

    #[test]
    fn an_s3_repository_is_recognised_and_never_mounted() {
        // 🔴 Un dépôt S3 monté créerait un répertoire vide, et restic répondrait
        // « repository does not exist » en désignant un chemin local sans rapport
        // avec la vraie destination.
        assert!(d("o", "s3:https://s3.example.com/depot", vec![]).est_s3());
        assert!(d("o", "s3:http://garage:3900/backups", vec![]).est_s3());
        assert!(!d("n", "/mnt/nas/restic", vec![]).est_s3());
        assert!(!d("n", "hlb-depot", vec![]).est_s3());
    }

    #[test]
    fn credentials_never_reach_the_command_line() {
        // Par l'environnement seulement : une ligne de commande est lisible par tout
        // utilisateur de la machine via `ps`.
        let dest = d("offsite", "s3:https://s3.example.com/depot", vec![Classe::Critique]);
        let env = dest.env(Some("AKIA123:secret456")).expect("identifiants");

        assert_eq!(env.len(), 2);
        assert_eq!(env[0], ("AWS_ACCESS_KEY_ID".into(), "AKIA123".into()));
        assert_eq!(env[1], ("AWS_SECRET_ACCESS_KEY".into(), "secret456".into()));
    }

    #[test]
    fn an_s3_destination_without_credentials_fails_loudly() {
        // 🔴 Sans clés, restic échouerait sur une erreur d'autorisation S3 qui ne dit
        // pas que le secret n'a jamais été déposé. Mieux vaut refuser ici, avec la
        // commande à taper.
        let dest = d("offsite", "s3:https://s3.example.com/depot", vec![Classe::Critique]);
        let e = dest.env(None).expect_err("doit refuser").to_string();
        assert!(e.contains("sans identifiants"), "{e}");
        assert!(e.contains("hlb backup dest add"), "l'erreur doit dire quoi faire : {e}");
    }

    #[test]
    fn the_secret_name_is_never_mistaken_for_its_value() {
        // 🔴 `credentials_secret` est le NOM du secret au coffre, pas sa valeur.
        // Le passer tel quel enverrait « backup-dest-offsite » comme clé d'accès, et
        // S3 répondrait « signature invalide » — une erreur qui n'oriente vers rien.
        //
        // Un nom de secret ne contient pas de « : », donc `env()` le refuse. Ce test
        // fige ce garde-fou.
        let dest = Destination {
            nom: "offsite".into(),
            location: "s3:https://s3.ext/depot".into(),
            classes: vec![Classe::Critique],
            credentials_secret: Some("backup-dest-offsite".into()),
        };

        let e = dest
            .env(Some("backup-dest-offsite"))
            .expect_err("un nom de secret n'est pas un couple clé:secret")
            .to_string();
        assert!(e.contains("clé_accès:clé_secrète"), "{e}");
    }

    #[test]
    fn a_local_destination_needs_no_credentials() {
        let dest = d("nas", "/mnt/nas/restic", vec![Classe::Volumineux]);
        assert!(dest.env(None).expect("aucun identifiant requis").is_empty());
    }

    #[test]
    fn a_url_never_shows_its_credentials() {
        // ⚠️ `hlb backup dest list` publierait sinon la clé dans le terminal, puis
        // dans l'historique du shell, puis dans une capture d'écran.
        let dest = d(
            "offsite",
            "s3:https://AKIA123:tressecret@s3.example.com/depot",
            vec![Classe::Critique],
        );
        let s = dest.describe();
        assert!(!s.contains("tressecret"), "{s}");
        assert!(!s.contains("AKIA123"), "{s}");
        assert!(s.contains("s3.example.com/depot"), "le lieu reste lisible : {s}");
    }

    #[test]
    fn a_destination_accepting_nothing_says_so() {
        // Elle ressemble par ailleurs à une destination configurée, et l'on croirait
        // les sauvegardes couvertes.
        let s = d("garage", "s3:http://garage:3900/b", vec![]).describe();
        assert!(s.contains("AUCUNE classe"), "{s}");
    }

    #[test]
    fn routing_separates_by_volume_not_by_importance() {
        // Le découpage réel d'une installation domestique : tout va sur le NAS, le
        // critique part aussi hors site, et le volumineux ne part hors site que pour
        // les apps qu'on choisit — parce qu'une connexion domestique ne l'avale pas.
        let nas = d("nas", "/mnt/nas/restic", vec![Classe::Critique, Classe::Volumineux]);
        let garage = d("garage", "s3:http://garage:3900/b", vec![Classe::Critique]);
        let offsite = d("offsite", "s3:https://s3.ext/d", vec![Classe::Critique, Classe::Volumineux]);

        assert!(nas.accepte(Classe::Volumineux));
        assert!(garage.accepte(Classe::Critique));
        assert!(
            !garage.accepte(Classe::Volumineux),
            "Garage vit sur les disques du cluster : y mettre les photos doublerait \
             leur occupation"
        );
        assert!(offsite.accepte(Classe::Volumineux));
    }

    #[test]
    fn class_names_are_read_from_several_spellings() {
        assert_eq!(Classe::parse("critique"), Some(Classe::Critique));
        assert_eq!(Classe::parse("dumps"), Some(Classe::Critique));
        assert_eq!(Classe::parse("VOLUMES"), Some(Classe::Volumineux));
        assert_eq!(Classe::parse(" volumineux "), Some(Classe::Volumineux));
        assert_eq!(Classe::parse("n'importe quoi"), None);
    }

    #[test]
    fn an_s3_repository_is_passed_as_a_url_not_a_mount() {
        // 🔴 Monter une URL créerait un répertoire vide, et restic répondrait
        // « repository does not exist » en désignant un chemin local qui n'a rien à
        // voir avec la vraie destination — le diagnostic partirait à côté.
        let s3 = d("offsite", "s3:https://s3.ext/depot", vec![Classe::Critique]);
        let (_, chemin) = s3.runner(None);
        assert_eq!(chemin, "s3:https://s3.ext/depot");

        let local = d("nas", "/mnt/nas/restic", vec![Classe::Critique]);
        let (_, chemin) = local.runner(None);
        assert_eq!(chemin, "/depot", "un dépôt local est monté et vu en /depot");
    }

    #[test]
    fn a_never_backed_up_app_is_alarming_on_every_destination() {
        let c = Couverture {
            app: "neuve".into(),
            par_destination: vec![
                ("nas".into(), Etat::Jamais),
                ("offsite".into(), Etat::Jamais),
            ],
        };
        assert_eq!(c.copies_a_jour(), 0);
        assert_eq!(c.alarmantes().len(), 2);
    }

    #[test]
    fn the_threshold_decides_stale_from_fresh() {
        assert_eq!(Etat::juger(None, 100), Etat::Jamais);
        assert_eq!(Etat::juger(Some(50), 100), Etat::Frais { age_s: 50 });
        assert_eq!(Etat::juger(Some(100), 100), Etat::Frais { age_s: 100 });
        assert_eq!(Etat::juger(Some(101), 100), Etat::Perime { age_s: 101 });
    }
}
