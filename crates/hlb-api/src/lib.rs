//! Les types de l'API du controller, **définis une seule fois**.
//!
//! ## Pourquoi ce crate existe
//!
//! Le plan prévoyait une UI SvelteKit, donc un OpenAPI (`utoipa`) puis une génération
//! de types TypeScript (`openapi-typescript`). Trois représentations de la même chose,
//! et un pipeline de génération à faire tourner à chaque changement.
//!
//! Avec une UI en Rust, il n'en reste **qu'une**. Le serveur sérialise ces types,
//! l'UI les désérialise, et le compilateur refuse tout désaccord. Un champ renommé
//! côté serveur casse la compilation de l'UI — au lieu de produire un `undefined` à
//! l'exécution, trois semaines plus tard, dans un écran que personne ne regardait.
//!
//! C'est le seul vrai bénéfice d'aller jusqu'au bout du Rust, et il justifie à lui
//! seul le choix.
//!
//! ## Ce qu'on ne met PAS ici
//!
//! Aucune valeur de secret, jamais. Les types portent les **noms** et les **usages**
//! (cf. [`SecretItem`]), et le fait qu'il n'existe pas de champ pour la valeur est la
//! garantie : on ne peut pas fuiter ce qu'on ne peut pas représenter.

pub mod breakglass;
pub mod diagnostic;
pub mod panne;
pub mod rotation;

use serde::{Deserialize, Serialize};

/// L'état de santé du controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
}

/// Une app installée, vue du tableau de bord.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppSummary {
    pub name: String,
    /// `running`, `partial`, `failed`, `installing`…
    pub status: String,
    pub image: String,
    pub domain: Option<String>,
    /// Âge de la dernière sauvegarde réussie, en secondes.
    ///
    /// 🔴 `None` = **jamais sauvegardée**, ce qui n'est pas la même chose que
    /// « sauvegardée il y a 0 seconde ». Le type l'impose ; l'UI doit les afficher
    /// différemment, sinon l'app la plus à risque est celle qui paraît la plus saine.
    pub last_backup_secs: Option<i64>,
    /// Idem pour la dernière vérification par restauration (§8.3).
    pub last_verification_secs: Option<i64>,
    /// Actions manuelles bloquantes en attente (§4.6).
    pub blocking_guides: i64,
}

/// Le niveau d'attention que mérite une app.
///
/// Calculé ici plutôt que dans l'UI : c'est une règle métier, et deux clients qui la
/// calculeraient chacun de leur côté finiraient par diverger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attention {
    /// Rien à signaler.
    Ok,
    /// À regarder quand on aura le temps.
    Notice,
    /// 🔴 Demande une action.
    Critical,
}

impl AppSummary {
    /// Une sauvegarde de plus de 24 h est en retard (§8.1 : intervalle visé de 4 h).
    const RETARD_SECS: i64 = 86_400;

    pub fn attention(&self) -> Attention {
        // 🔴 Jamais sauvegardée passe AVANT le statut : une app qui tourne
        // parfaitement et n'a aucune sauvegarde est le pire état du système, et
        // c'est précisément celui qui paraît le plus sain sur un tableau de bord.
        if self.last_backup_secs.is_none() {
            return Attention::Critical;
        }
        if self.status == "failed" {
            return Attention::Critical;
        }
        if self.last_backup_secs.is_some_and(|s| s > Self::RETARD_SECS) {
            return Attention::Critical;
        }
        if self.blocking_guides > 0 || self.status == "partial" {
            return Attention::Notice;
        }
        Attention::Ok
    }

    /// Ce qu'il faut afficher pour l'âge de sauvegarde.
    pub fn backup_label(&self) -> String {
        match self.last_backup_secs {
            None => "JAMAIS".to_string(),
            Some(s) => humanise(s),
        }
    }

    pub fn verification_label(&self) -> String {
        match self.last_verification_secs {
            None => "jamais vérifiée".to_string(),
            Some(s) => humanise(s),
        }
    }
}

/// Une action manuelle en attente (§4.6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuideItem {
    pub app: String,
    pub id: String,
    pub title: String,
    /// Bloque le déploiement tant qu'elle n'est pas faite.
    pub blocking: bool,
}

/// Une entrée du journal d'audit (§9).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditItem {
    pub id: i64,
    pub at: String,
    pub actor: String,
    /// Le rôle **au moment de l'action**, pas celui d'aujourd'hui. Une personne
    /// rétrogradée depuis n'efface pas ce qu'elle a fait quand elle pouvait le faire.
    ///
    /// ⚠️ Une chaîne et non un [`hlb_types::Role`] : un rôle retiré d'une version
    /// future rendrait tout le journal illisible à la désérialisation, et un journal
    /// qu'on ne sait plus relire ne prouve rien.
    pub role: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
    /// Le diff, ou ce qui explique l'issue. C'est ce que demande le §9ter et qui
    /// manquait : sans lui, « config modifiée » ne dit pas ce qui a changé.
    #[serde(default)]
    pub detail: Option<String>,
}

impl AuditItem {
    /// Une action refusée n'est pas un échec : c'est le système qui a protégé
    /// l'utilisateur. Les confondre rendrait le journal inexploitable.
    pub fn is_refusal(&self) -> bool {
        self.outcome == "refused"
    }

    pub fn is_failure(&self) -> bool {
        self.outcome == "failed"
    }
}

/// Un secret : son nom et son usage. **Jamais sa valeur.**
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretItem {
    pub name: String,
    pub purpose: String,
}

/// Qui est la personne (ou la machine) derrière la requête courante.
///
/// C'est la **première** chose que demande l'interface : elle détermine quels écrans
/// afficher. Une console dont tout serait grisé faute de savoir qui regarde est pire
/// qu'un écran de connexion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Moi {
    /// Le compte Homelabus. `None` pour un jeton de service, qui n'agit au nom de
    /// personne — et l'interface doit alors masquer tout ce qui est « mes … ».
    pub compte: Option<String>,
    pub role: String,
    /// Ce que le rôle permet, en une phrase, pour l'afficher tel quel.
    pub role_libelle: String,
    /// `true` = authentifié par jeton d'API plutôt que par session.
    ///
    /// L'interface s'en sert pour ne pas proposer « se déconnecter » à un porteur de
    /// jeton : il n'y a pas de session à fermer, et le bouton ne ferait rien.
    pub par_jeton: bool,
    pub peut: Droits,
    #[serde(default)]
    pub boites: Vec<BoiteBreve>,
}

/// Une adresse de la personne, juste de quoi l'afficher.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoiteBreve {
    pub adresse: String,
    pub par_defaut: bool,
}

/// Ce que le rôle courant autorise.
///
/// 🔴 Calculé **côté serveur** et transmis, plutôt que redéduit du nom du rôle par
/// l'interface. Deux implémentations de la même matrice finiraient par diverger, et la
/// divergence irait dans le sens permissif : un bouton visible qui déclenche un 403 est
/// un bug ; un bouton visible qui *fonctionne* alors qu'il ne devrait pas serait une
/// faille.
///
/// ⚠️ Ce n'est **pas** le contrôle d'accès : celui-ci a lieu à chaque requête, côté
/// controller. C'est uniquement de quoi ne pas afficher ce qui sera refusé.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct Droits {
    pub lire_soi: bool,
    pub agir_sur_soi: bool,
    pub lire: bool,
    pub publier: bool,
    pub operer: bool,
    pub gerer_comptes: bool,
    pub detruire: bool,
}

impl Droits {
    /// Les droits d'un rôle.
    ///
    /// Le `match` sur chaque action passe par `Role::allows`, donc la matrice reste
    /// définie à un seul endroit (`hlb_types::rbac`).
    pub fn pour(role: hlb_types::Role) -> Self {
        use hlb_types::rbac::Action;
        Self {
            lire_soi: role.allows(Action::ReadSelf),
            agir_sur_soi: role.allows(Action::ActOnSelf),
            lire: role.allows(Action::Read),
            publier: role.allows(Action::Publish),
            operer: role.allows(Action::Operate),
            gerer_comptes: role.allows(Action::ManageAccounts),
            detruire: role.allows(Action::Destroy),
        }
    }

    /// Y a-t-il quoi que ce soit à montrer de la console d'administration ?
    ///
    /// Sert à choisir entre le portail et la console à l'ouverture, plutôt que
    /// d'imposer un écran vide à qui n'a qu'un compte.
    pub fn voit_la_console(&self) -> bool {
        self.lire
    }
}

/// L'identité visuelle de l'installation.
///
/// ## Pourquoi elle vient du serveur
///
/// Elle pourrait être compilée dans l'interface. Mais alors la changer voudrait dire
/// recompiler le wasm, ce qui met le nom de la marque au même niveau qu'une décision
/// d'architecture. Elle vit donc en base, s'édite depuis l'interface, et le wasm reste
/// le même quelle que soit la maison qui l'utilise.
///
/// 🔴 L'accent est **validé** avant d'être accepté : `Palette::valider` refuse une
/// couleur qui se confondrait avec « ok », « attention » ou « critique » en vision
/// deutéranope. Une marque n'a pas le droit de rendre les alertes indistinctes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marque {
    /// La maison. Apparaît en tête de la barre latérale et au pied des pages.
    pub nom: String,
    /// Le produit. Distinct du précédent : « Turi Industries » exploite « Homelabus »,
    /// et confondre les deux rendrait la page incompréhensible pour un visiteur.
    pub produit: String,
    /// Composantes RVB. `None` = l'accent du thème.
    #[serde(default)]
    pub accent: Option<[u8; 3]>,
    /// Un logo a-t-il été téléversé ? Le contenu se récupère sur `/api/apparence/logo`.
    ///
    /// ⚠️ Un booléen et non les octets : une image de 256 Ko encodée en base64 dans
    /// chaque réponse d'API serait payée à chaque sondage, par chaque écran.
    #[serde(default)]
    pub logo: bool,
    /// Une ligne de pied de page : mentions, contact du support, numéro d'astreinte.
    #[serde(default)]
    pub pied: Option<String>,
    /// Le thème proposé par défaut aux personnes qui n'en ont pas choisi.
    #[serde(default)]
    pub theme_defaut: Option<String>,
}

impl Default for Marque {
    fn default() -> Self {
        Self {
            nom: "Turi Industries".into(),
            produit: "Homelabus".into(),
            accent: None,
            logo: false,
            pied: None,
            theme_defaut: None,
        }
    }
}

impl Marque {
    /// Le titre de la fenêtre et de l'onglet du navigateur.
    pub fn titre(&self) -> String {
        format!("{} · {}", self.produit, self.nom)
    }

    /// Les initiales, pour le monogramme peint quand aucun logo n'est posé.
    pub fn initiales(&self) -> String {
        let i: String = self
            .nom
            .split([' ', '-', '_'])
            .filter(|m| !m.is_empty())
            .take(2)
            .filter_map(|m| m.chars().next())
            .collect::<String>()
            .to_uppercase();
        if i.is_empty() {
            "?".into()
        } else {
            i
        }
    }
}

/// Le détail d'une application — l'écran où l'on passe le plus de temps (§11bis).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppDetail {
    pub resume: AppSummary,
    /// Les réplicas et leur placement réel.
    #[serde(default)]
    pub taches: Vec<TacheSummary>,
    /// Ce qui a été provisionné pour elle.
    #[serde(default)]
    pub capacites: Vec<String>,
    /// Les volumes, et lesquels sont sauvegardés.
    #[serde(default)]
    pub volumes: Vec<VolumeSummary>,
    /// Les variables d'environnement du manifest.
    ///
    /// 🔴 Les jetons de secret sont rendus **littéralement** (`{{ db.password }}`),
    /// jamais substitués. Deux raisons : la valeur ne doit pas traverser l'API, et un
    /// jeton visible dit à quoi l'app est câblée — ce qu'une valeur masquée par des
    /// astérisques ne dit pas.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Les actions manuelles la concernant.
    #[serde(default)]
    pub guides: Vec<GuideItem>,
    /// La couverture de ses sauvegardes.
    #[serde(default)]
    pub couverture: Option<CouvertureSummary>,
    /// Ses dernières sauvegardes, échecs compris.
    #[serde(default)]
    pub sauvegardes: Vec<SauvegardeRun>,
    /// 🔴 La réponse à « si je perds tout maintenant, je récupère quoi ? ».
    #[serde(default)]
    pub restaurabilite: Option<RestaurabiliteSummary>,
    /// 🔴 « Pourquoi cette app est-elle rouge ? », remontée maillon par maillon.
    ///
    /// Calculée par le serveur : lui seul voit à la fois les tâches, les nœuds et les
    /// alertes. L'interface les affiche sur trois écrans différents et ne peut pas
    /// faire le lien.
    #[serde(default)]
    pub diagnostic: Option<diagnostic::Chaine>,
    /// Le journal d'audit filtré sur elle.
    #[serde(default)]
    pub journal: Vec<AuditItem>,
    /// L'image effectivement déployée.
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub domaine: Option<String>,
    /// Le manifest figé au déploiement (§4.8), rendu en YAML.
    ///
    /// ⚠️ Celui de l'installation, PAS celui du catalogue courant : c'est ce qui tourne
    /// qu'on veut lire, pas ce qu'on installerait aujourd'hui.
    #[serde(default)]
    pub manifest: Option<String>,
}

/// « Si je perds tout maintenant, je récupère quoi, et de quand ? » (lot 9.2)
///
/// ## Pourquoi ce type existe côté serveur
///
/// Les cinq morceaux de la réponse — âge par destination, copies à jour, âge de la
/// dernière vérification, fraîcheur des exercices, fenêtre PITR — sont dispersés sur
/// quatre écrans. Personne ne fait la somme de tête, et c'est pourtant la seule
/// question qui compte le jour venu.
///
/// 🔴 Le calcul est une **règle métier** : il vit dans `hlb-backup`, pas dans
/// l'interface. Deux clients qui le referaient chacun de leur côté finiraient par
/// afficher deux verdicts différents sur la même sauvegarde.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RestaurabiliteSummary {
    pub app: String,
    /// Secondes de données qu'on perdrait. `None` = **rien à restaurer**.
    ///
    /// ⚠️ Distinct d'un RPO très grand : `None` veut dire qu'aucune copie n'existe.
    #[serde(default)]
    pub rpo_s: Option<i64>,
    /// La réponse en une phrase, calculée par le serveur.
    pub verdict: String,
    /// Ce qu'on sait de cette sauvegarde, du plus faible au plus fort.
    pub confiance: NiveauConfiance,
    /// Ce que la confiance veut dire, en toutes lettres.
    pub confiance_explication: String,
    /// Ce qu'il faudrait faire, par ordre d'urgence. Vide quand tout va bien.
    #[serde(default)]
    pub remedes: Vec<String>,
}

/// Le crédit qu'on peut accorder à une restauration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum NiveauConfiance {
    /// 🔴 Rien à restaurer.
    Aucune,
    /// Des copies existent, aucune n'a jamais été relue.
    Suppose,
    /// Une restauration a réussi, mais il y a longtemps — ou il n'y a qu'une copie.
    Ancienne,
    /// Vérifiée récemment, sur plusieurs copies.
    Verifiee,
}

impl RestaurabiliteSummary {
    pub fn attention(&self) -> Attention {
        match self.confiance {
            NiveauConfiance::Aucune => Attention::Critical,
            // ⚠️ « Supposé » n'est PAS « bon ». Une sauvegarde jamais relue affichée en
            // vert est exactement le mensonge que le §8.3 existe pour empêcher.
            NiveauConfiance::Suppose | NiveauConfiance::Ancienne => Attention::Notice,
            NiveauConfiance::Verifiee => Attention::Ok,
        }
    }
}

/// Un volume d'une application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeSummary {
    pub nom: String,
    pub chemin: String,
    pub sauvegarde: bool,
    /// 🔴 Contient une base SQLite : elle ne doit JAMAIS être copiée à chaud (§3.4).
    /// Le fichier principal et son WAL seraient capturés à des instants différents, et
    /// la base restaurée serait corrompue — sans que rien ne le signale au moment de
    /// la sauvegarde.
    pub sqlite: bool,
}

impl AppDetail {
    /// Les réplicas vivants sur le total voulu.
    pub fn replicas(&self) -> (usize, usize) {
        let vivants = self.taches.iter().filter(|t| t.vivante).count();
        // Le total voulu se déduit des tâches non abandonnées : Swarm garde
        // l'historique, et compter TOUTES les tâches donnerait un dénominateur qui
        // grossit à chaque redéploiement.
        let voulus = self
            .taches
            .iter()
            .filter(|t| t.etat_voulu == "running")
            .count();
        (vivants, voulus.max(vivants))
    }

    /// Les tâches qui ont échoué, la plus récente d'abord.
    ///
    /// 🔴 C'est ce qui répond à « pourquoi cette app est-elle rouge ». Les masquer
    /// laisserait un service « partiel » sans aucune explication.
    pub fn echecs(&self) -> Vec<&TacheSummary> {
        self.taches.iter().filter(|t| t.echouee).collect()
    }
}

/// Un nœud du cluster, tel que le tableau de bord le montre.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoeudSummary {
    /// L'adresse de l'agent : **l'identité stable**.
    ///
    /// 🔴 Pas le nom d'hôte : un nœud injoignable n'en a pas à donner. Changer
    /// d'identifiant selon qu'il répond ou non ferait apparaître deux entrées pour la
    /// même machine, et « ce nœud est muet » ne se verrait jamais.
    pub adresse: String,
    /// `None` quand le nœud n'a jamais répondu.
    #[serde(default)]
    pub hostname: Option<String>,
    /// 🔴 `false` = injoignable. Ce n'est **pas** « pas de problème signalé » : ses
    /// données ne sont plus sauvegardées, et on ne sait rien de son disque.
    pub joignable: bool,
    /// Pourquoi il ne répond pas.
    #[serde(default)]
    pub detail: Option<String>,
    /// Âge du dernier rapport, en secondes. `None` = jamais reçu.
    #[serde(default)]
    pub rapport_age_s: Option<i64>,
    #[serde(default)]
    pub cpu_occupation: Option<f64>,
    #[serde(default)]
    pub charge_par_coeur: Option<f64>,
    #[serde(default)]
    pub memoire_utilisee: Option<f64>,
    #[serde(default)]
    pub swap_utilise: Option<f64>,
    #[serde(default)]
    pub disques: Vec<DisqueSummary>,
    #[serde(default)]
    pub uptime_s: Option<u64>,
    #[serde(default)]
    pub distro: Option<String>,
    #[serde(default)]
    pub noyau: Option<String>,
    #[serde(default)]
    pub agent_version: Option<String>,
    /// Version du dialogue. Un parc dépareillé est un piège (§7bis).
    #[serde(default)]
    pub protocole: Option<u32>,
    /// Les tâches hébergées, par nom de service.
    #[serde(default)]
    pub taches: Vec<String>,
}

/// Un système de fichiers d'un nœud.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisqueSummary {
    pub chemin: String,
    pub utilise: f64,
    pub total_mb: u64,
    pub libre_mb: u64,
    /// Palier de pression (§9bis) : 0 sain … 4 critique.
    pub pression: u8,
}

impl NoeudSummary {
    /// Le niveau d'attention de ce nœud.
    pub fn attention(&self) -> Attention {
        // 🔴 Injoignable passe AVANT tout le reste : on ne sait rien de lui, ce qui
        // est pire qu'un mauvais chiffre connu.
        if !self.joignable {
            return Attention::Critical;
        }
        if self.disques.iter().any(|d| d.pression >= 3) {
            return Attention::Critical;
        }
        if self.disques.iter().any(|d| d.pression >= 1)
            || self.swap_utilise.is_some_and(|s| s > 0.05)
            || self.charge_par_coeur.is_some_and(|c| c > 1.0)
        {
            return Attention::Notice;
        }
        Attention::Ok
    }

    /// Ce qui ne va pas, en une phrase — ou rien.
    pub fn raison(&self) -> Option<String> {
        if !self.joignable {
            return Some(format!(
                "injoignable{} — ses données ne sont plus sauvegardées, et on ne sait \
                 rien de son disque",
                match &self.detail {
                    Some(d) => format!(" ({d})"),
                    None => String::new(),
                }
            ));
        }
        if let Some(d) = self.disques.iter().max_by_key(|d| d.pression) {
            if d.pression >= 3 {
                return Some(format!(
                    "{} est plein à {:.0} % — plus aucun déploiement n'y est accepté",
                    d.chemin,
                    d.utilise * 100.0
                ));
            }
            if d.pression >= 1 {
                return Some(format!("{} est à {:.0} %", d.chemin, d.utilise * 100.0));
            }
        }
        if self.swap_utilise.is_some_and(|s| s > 0.05) {
            return Some("échange sur le disque — la machine ralentit avant de tomber".to_string());
        }
        if let Some(c) = self.charge_par_coeur.filter(|c| *c > 1.0) {
            return Some(format!("charge de {c:.1} par cœur"));
        }
        None
    }
}

/// Les préférences d'affichage d'une personne.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Preferences {
    /// Le thème choisi. `None` = celui de l'installation.
    ///
    /// ⚠️ Un NOM, pas une palette : une palette stockée par personne survivrait à la
    /// suppression du thème dont elle vient, et l'on ne saurait plus la faire évoluer.
    #[serde(default)]
    pub theme: Option<String>,
    /// Les thèmes disponibles, tels que l'interface les connaît.
    ///
    /// 🔴 Servis par l'API pour que l'écran de réglages n'ait pas à les deviner : si
    /// l'interface et le serveur avaient chacun leur liste, un thème retiré resterait
    /// proposé jusqu'au prochain déploiement du wasm.
    #[serde(default)]
    pub disponibles: Vec<String>,
    /// Celui de l'installation, quand la personne n'a rien choisi.
    #[serde(default)]
    pub defaut: Option<String>,
}

/// La page de statut : ce qui marche, ce qui ne marche pas.
///
/// ## 🔴 Privée par défaut, et c'est une décision
///
/// Une page de statut publique révèle **la liste de ce qui tourne chez vous** et le
/// calendrier de vos pannes. Pour un service commercial c'est un engagement de
/// transparence ; pour un homelab c'est de la reconnaissance offerte à qui la lit.
///
/// L'ouvrir est un choix explicite (`statut.public = true`), et l'écran de réglages dit
/// ce que ça publie — pas une case à cocher anodine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PageStatut {
    /// L'état de chaque application exposée.
    pub services: Vec<ServiceStatut>,
    /// Les incidents ouverts, avec leur fil.
    #[serde(default)]
    pub incidents: Vec<Annonce>,
    /// Cette page est-elle accessible sans authentification ?
    pub publique: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceStatut {
    pub nom: String,
    #[serde(default)]
    pub domaine: Option<String>,
    pub etat: EtatService,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EtatService {
    /// Tout va bien.
    Operationnel,
    /// Déployé partiellement : ça marche, mais sans marge.
    Degrade,
    /// En panne.
    Indisponible,
    /// 🔴 Une maintenance ANNONCÉE. Distincte d'une panne : c'était prévu, et le dire
    /// évite qu'on cherche ce qui ne va pas.
    Maintenance,
}

impl EtatService {
    pub fn libelle(&self) -> &'static str {
        match self {
            Self::Operationnel => "opérationnel",
            Self::Degrade => "dégradé",
            Self::Indisponible => "indisponible",
            Self::Maintenance => "maintenance prévue",
        }
    }

    pub fn attention(&self) -> Attention {
        match self {
            Self::Operationnel => Attention::Ok,
            Self::Degrade | Self::Maintenance => Attention::Notice,
            Self::Indisponible => Attention::Critical,
        }
    }
}

impl PageStatut {
    /// Le verdict global, en une phrase.
    pub fn verdict(&self) -> String {
        let hs = self
            .services
            .iter()
            .filter(|s| s.etat == EtatService::Indisponible)
            .count();
        let degrades = self
            .services
            .iter()
            .filter(|s| s.etat == EtatService::Degrade)
            .count();

        if hs > 0 {
            return format!(
                "{} hors service.",
                pluriel(hs as u64, "service", "services")
            );
        }
        if !self.incidents.is_empty() {
            return format!(
                "{} en cours.",
                pluriel(self.incidents.len() as u64, "incident", "incidents")
            );
        }
        if degrades > 0 {
            return format!(
                "{} en mode dégradé.",
                pluriel(degrades as u64, "service", "services")
            );
        }
        "Tous les services sont opérationnels.".to_string()
    }

    pub fn attention(&self) -> Attention {
        self.services
            .iter()
            .map(|s| s.etat.attention())
            .chain(self.incidents.iter().map(|i| i.niveau.attention()))
            .max()
            .unwrap_or(Attention::Ok)
    }
}

/// Une annonce, telle que le portail la montre.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Annonce {
    pub id: i64,
    pub titre: String,
    pub corps: String,
    pub niveau: NiveauAnnonce,
    pub epinglee: bool,
    pub auteur: String,
    pub publiee_le: String,
    /// Secondes avant disparition. `None` = permanente.
    #[serde(default)]
    pub expire_dans_s: Option<i64>,
    /// Le fil de suivi, du plus ancien au plus récent.
    ///
    /// 🔴 Un incident se SUIT, il ne se réécrit pas : c'est la chronologie qu'on relit
    /// après coup — à quelle heure on a su, compris, réglé.
    #[serde(default)]
    pub suivi: Vec<MajAnnonce>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MajAnnonce {
    pub corps: String,
    pub auteur: String,
    pub at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NiveauAnnonce {
    Info,
    /// Prévue, donc annoncée à l'avance.
    Maintenance,
    Avertissement,
    /// En cours, et suivie.
    Incident,
}

impl NiveauAnnonce {
    pub fn libelle(&self) -> &'static str {
        match self {
            Self::Info => "information",
            Self::Maintenance => "maintenance",
            Self::Avertissement => "avertissement",
            Self::Incident => "incident",
        }
    }

    pub fn attention(&self) -> Attention {
        match self {
            Self::Info => Attention::Ok,
            Self::Maintenance | Self::Avertissement => Attention::Notice,
            Self::Incident => Attention::Critical,
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "maintenance" => Self::Maintenance,
            "avertissement" => Self::Avertissement,
            "incident" => Self::Incident,
            // ⚠️ Le défaut est le niveau le plus BAS : un niveau illisible en base ne
            // doit pas transformer une information en incident sur tous les écrans.
            _ => Self::Info,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Maintenance => "maintenance",
            Self::Avertissement => "avertissement",
            Self::Incident => "incident",
        }
    }
}

impl Annonce {
    /// Est-elle encore visible ?
    pub fn active(&self) -> bool {
        self.expire_dans_s.is_none_or(|s| s > 0)
    }

    /// Un incident en cours, non résolu.
    ///
    /// 🔴 Ce qui rend un incident « résolu » n'est pas son âge mais une mise à jour qui
    /// le dit. Un incident qu'on oublie de clore reste ouvert, et c'est voulu : le
    /// silence ne doit pas passer pour une résolution.
    pub fn incident_ouvert(&self) -> bool {
        self.niveau == NiveauAnnonce::Incident && self.active()
    }

    /// La dernière nouvelle, ou le corps d'origine.
    pub fn derniere_nouvelle(&self) -> &str {
        self.suivi
            .last()
            .map(|m| m.corps.as_str())
            .unwrap_or(&self.corps)
    }
}

/// Un compte humain, vu de l'écran de gestion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompteSummary {
    pub nom: String,
    pub profil: String,
    pub role: String,
    /// 🔴 L'état de COHÉRENCE, pas un simple « actif / inactif ».
    ///
    /// Un compte à moitié créé paraît fonctionnel : identité sans boîte, la personne
    /// se connecte partout et son adresse ne reçoit rien. Ça ne se voit qu'au premier
    /// courriel perdu — souvent une réinitialisation de mot de passe, c'est-à-dire au
    /// pire moment.
    pub coherence: EtatCompte,
    /// Ce que l'état implique, et comment le réparer.
    pub explication: String,
    #[serde(default)]
    pub pocket_id: Option<String>,
    #[serde(default)]
    pub boites: Vec<BoiteBreve>,
    pub aliases_actifs: usize,
    /// 🔴 Aliases expirés qui reçoivent ENCORE : la purge n'a pas tourné, et l'adresse
    /// qu'on croit fermée reste ouverte.
    pub promesses_rompues: usize,
    /// Sessions ouvertes.
    pub sessions: usize,
}

/// L'état de cohérence d'un compte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EtatCompte {
    Complet,
    /// Identité créée, aucune boîte.
    SansBoite,
    /// Boîte créée, aucune identité.
    SansIdentite,
    Vide,
}

impl EtatCompte {
    pub fn attention(&self) -> Attention {
        match self {
            Self::Complet => Attention::Ok,
            // 🔴 Les deux moitiés sont critiques, pas « à surveiller » : dans un cas la
            // personne ne reçoit rien, dans l'autre elle ne peut pas se connecter. Les
            // deux se découvrent au pire moment.
            Self::SansBoite | Self::SansIdentite | Self::Vide => Attention::Critical,
        }
    }

    /// Le geste qui répare.
    pub fn remede(&self, compte: &str) -> Option<String> {
        match self {
            Self::Complet => None,
            // Reprenable : `upsert_user` fait un COALESCE sur `pocket_id`, et une
            // relance ne détruit pas ce qui existe déjà.
            _ => Some(format!("hlb user add {compte} --apply")),
        }
    }
}

/// Une invitation à créer un compte.
///
/// 🔴 La VALEUR du jeton n'est jamais ici — seulement son empreinte est stockée, et la
/// valeur n'est affichée qu'une fois, à la création. Le type ne permet pas de la
/// représenter, donc on ne peut pas la fuiter par accident.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvitationSummary {
    /// Les premiers caractères de l'empreinte, pour la désigner sans la nommer.
    pub reference: String,
    pub cree_par: String,
    pub profil: String,
    pub role: String,
    /// Secondes avant expiration. Négatif = déjà expirée.
    pub expire_dans_s: i64,
    /// `Some(date)` = la dernière fois qu'elle a servi.
    #[serde(default)]
    pub utilisee_le: Option<String>,
    /// Combien de fois elle a servi.
    #[serde(default)]
    pub usages: usize,
    /// Combien de fois elle PEUT servir.
    ///
    /// 🔴 Un lien à N usages qui fuite fait entrer N personnes, pas une. Le nombre est
    /// donc affiché : un lien largement ouvert ne doit pas passer inaperçu.
    #[serde(default = "un")]
    pub usages_max: usize,
    #[serde(default)]
    pub note: Option<String>,
}

/// Le défaut de `usages_max` : le cas sûr.
fn un() -> usize {
    1
}

impl InvitationSummary {
    /// Cette invitation peut-elle encore servir ?
    pub fn utilisable(&self) -> bool {
        self.usages < self.usages_max && self.expire_dans_s > 0
    }

    /// Combien de personnes peuvent encore l'utiliser.
    pub fn restants(&self) -> usize {
        self.usages_max.saturating_sub(self.usages)
    }

    pub fn etat(&self) -> &'static str {
        if self.usages >= self.usages_max {
            "épuisée"
        } else if self.expire_dans_s <= 0 {
            "expirée"
        } else if self.usages > 0 {
            // ⚠️ Distinct de « en attente » : un lien qui a déjà servi ET reste ouvert
            // est le cas qu'on veut voir, parce que c'est celui qu'on oublie de fermer.
            "partiellement utilisée"
        } else {
            "en attente"
        }
    }

    /// Ce lien mérite-t-il qu'on s'en méfie ?
    ///
    /// 🔴 Un lien largement ouvert qui traîne est une porte d'entrée : plus il reste
    /// d'usages, plus une fuite coûte cher.
    pub fn largement_ouverte(&self) -> bool {
        self.utilisable() && self.restants() > 3
    }
}

/// Une entrée du catalogue, telle qu'on la parcourt avant d'installer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatalogueItem {
    pub nom: String,
    pub nom_affiche: String,
    #[serde(default)]
    pub categorie: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    pub image: String,
    /// Ce qu'elle réclame : bases, SSO, volumes, stockage objet.
    #[serde(default)]
    pub capacites: Vec<String>,
    /// A-t-elle besoin d'un domaine ?
    ///
    /// Décidé ici plutôt que devinné par l'interface : une app sans ingress n'a rien à
    /// exposer, et lui demander un domaine ferait saisir une valeur inutilisée.
    pub demande_domaine: bool,
    /// 🔴 Les prérequis MANUELS, avant même l'installation (§4.6).
    ///
    /// Les lister à l'avance permet de tout préparer en une session, au lieu de
    /// découvrir au sixième écran qu'il fallait un enregistrement DNS.
    #[serde(default)]
    pub prerequis: Vec<String>,
    /// Déjà installée ?
    pub installee: bool,
}

/// Le résultat d'une action : ce qu'elle FERAIT, ou ce qu'elle a fait.
///
/// ## 🔴 Aperçu par défaut, en HTTP comme en ligne de commande
///
/// Une route d'action rend ce plan **sans rien faire**. Elle n'agit qu'avec
/// `?apply=true`. C'est la transposition exacte de `Executor::apply(true)`, et
/// l'invariant le plus important de ce projet : le mode par défaut ne modifie rien.
///
/// Le type porte `applique` pour que l'interface ne puisse pas confondre « voici ce qui
/// se passerait » et « voici ce qui s'est passé » — la confusion la plus coûteuse
/// possible sur un écran qui déclenche des actions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultatAction {
    /// `false` = aperçu, rien n'a été fait.
    pub applique: bool,
    /// Ce que l'action fait, en une phrase.
    pub resume: String,
    /// Le détail, étape par étape.
    #[serde(default)]
    pub etapes: Vec<EtapeAction>,
    /// 🔴 La commande équivalente.
    ///
    /// Le CLI reste la source de vérité ; l'interface l'enseigne au lieu de s'y
    /// substituer, et l'action devient reproductible et scriptable. C'est aussi ce qui
    /// permet de vérifier que l'interface fait bien ce qu'on croit.
    pub commande_cli: String,
    /// Ce qui **empêche** d'appliquer.
    #[serde(default)]
    pub blocages: Vec<String>,
    /// Ce qu'il faut savoir avant d'appliquer, sans que ça empêche.
    ///
    /// 🔴 Distinct des blocages, et la distinction compte. Ranger un avertissement
    /// parmi les blocages rend l'action impossible : « ce lien laissera entrer cinq
    /// personnes » devient un refus, alors que c'est un choix légitime qu'on veut
    /// simplement voir avant de le faire.
    ///
    /// L'inverse est pire encore : traiter un blocage comme un avertissement laisserait
    /// appliquer une action qui ne peut pas aboutir.
    #[serde(default)]
    pub avertissements: Vec<String>,
    /// La confirmation attendue pour une opération destructive (§9ter).
    ///
    /// `Some(cible)` = il faut renvoyer exactement ce nom dans le corps. Un rôle ne
    /// suffit pas : un administrateur fatigué à 2 h du matin reste un administrateur.
    #[serde(default)]
    pub confirmation_requise: Option<String>,
}

/// Une étape d'une action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EtapeAction {
    pub description: String,
    pub etat: EtatEtape,
    #[serde(default)]
    pub erreur: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EtatEtape {
    /// En aperçu : ce qui serait fait.
    Prevue,
    Faite,
    Echouee,
    /// 🔴 Reconnue mais pas encore implémentée par l'exécuteur.
    ///
    /// **Jamais confondue avec `Faite`** : on ne prétend jamais avoir provisionné une
    /// base. C'est l'invariant qui empêche un tableau de bord de passer au vert sur
    /// une action que personne n'a faite.
    NonImplementee,
}

impl ResultatAction {
    /// Peut-on appliquer ?
    pub fn applicable(&self) -> bool {
        self.blocages.is_empty()
    }

    /// L'action a-t-elle vraiment abouti ?
    ///
    /// ⚠️ Une étape non implémentée fait échouer ce verdict : « le plan s'est déroulé
    /// sans erreur » et « l'app est installée » ne sont pas la même chose.
    pub fn reussie(&self) -> bool {
        self.applique && self.etapes.iter().all(|e| e.etat == EtatEtape::Faite)
    }

    /// Ce qu'il faut afficher après coup.
    pub fn verdict(&self) -> String {
        if !self.applique {
            return format!("Aperçu — rien n'a été modifié. {}", self.resume);
        }
        let echecs = self
            .etapes
            .iter()
            .filter(|e| e.etat == EtatEtape::Echouee)
            .count();
        let manquantes = self
            .etapes
            .iter()
            .filter(|e| e.etat == EtatEtape::NonImplementee)
            .count();

        if echecs > 0 {
            return format!(
                "{} en échec — l'action s'est arrêtée là.",
                pluriel(echecs as u64, "étape", "étapes")
            );
        }
        if manquantes > 0 {
            // 🔴 Le dire explicitement : « terminé » sur un plan à moitié implémenté
            // ferait croire que l'app est prête.
            // ⚠️ L'accord se fait à la main : « 1 étape n'EST pas implémentéE » et
            // « 5 étapes NE SONT pas implémentéES ». Le pluriel français ne se résume
            // pas à un « s » collé au nom.
            return format!(
                "{} {} pas encore implémentée{} — l'action est INCOMPLÈTE, malgré \
                 l'absence d'erreur.",
                pluriel(manquantes as u64, "étape", "étapes"),
                if manquantes > 1 { "ne sont" } else { "n'est" },
                if manquantes > 1 { "s" } else { "" }
            );
        }
        self.resume.clone()
    }
}

/// La topologie du cluster, groupée par **domaine de panne** (§2bis.2).
///
/// ## 🔴 Ce que cet écran existe pour dissiper
///
/// En ligne de commande, on voit trois nœuds et on se croit protégé. Deux d'entre eux
/// sont deux VM sur le même serveur : le fer tombe, deux tiers du cluster partent avec.
/// Le §11bis dit que cet écran justifie à lui seul l'existence de l'interface, et c'est
/// pour cette raison précise — l'information existe, elle n'est simplement lisible
/// nulle part ailleurs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Topologie {
    pub domaines: Vec<DomaineSummary>,
    /// Les services dont plusieurs réplicas partagent un fer.
    #[serde(default)]
    pub violations: Vec<ViolationSummary>,
    /// Les nœuds managers, quand on les connaît.
    ///
    /// ⚠️ Une liste VIDE veut dire « on ne sait pas », jamais « aucun manager » — un
    /// cluster sans manager n'existe pas. Le simulateur rend alors `SortQuorum::Inconnu`
    /// plutôt que d'affirmer que le quorum tient.
    #[serde(default)]
    pub managers: Vec<String>,
    /// Nombre total de nœuds joignables.
    pub noeuds_total: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomaineSummary {
    /// `None` = domaine non déclaré. Ce n'est **pas** « isolé » : c'est « on ne sait
    /// pas », et l'affichage doit le dire.
    #[serde(default)]
    pub nom: Option<String>,
    pub noeuds: Vec<NoeudDansDomaine>,
    /// Ce domaine porte-t-il plus de la moitié du cluster ?
    pub concentre: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoeudDansDomaine {
    pub id: String,
    pub hostname: String,
    #[serde(default)]
    pub tier: Option<String>,
    pub joignable: bool,
    /// Les services qui y tournent.
    #[serde(default)]
    pub services: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ViolationSummary {
    pub service: String,
    #[serde(default)]
    pub domaine: Option<String>,
    pub replicas: usize,
    pub total: usize,
    /// 🔴 Tous les réplicas au même endroit : la redondance est une illusion.
    pub totale: bool,
    pub explication: String,
}

impl Topologie {
    /// Le niveau d'attention global.
    pub fn attention(&self) -> Attention {
        if self.violations.iter().any(|v| v.totale) {
            return Attention::Critical;
        }
        if !self.violations.is_empty() || self.domaines.iter().any(|d| d.concentre) {
            return Attention::Notice;
        }
        Attention::Ok
    }

    /// Le verdict en une phrase.
    pub fn verdict(&self) -> String {
        let totales = self.violations.iter().filter(|v| v.totale).count();
        if totales > 0 {
            return format!(
                "{} dont TOUS les réplicas partagent un même fer — leur redondance est \
                 une illusion.",
                pluriel(totales as u64, "service", "services")
            );
        }
        if let Some(d) = self.domaines.iter().find(|d| d.concentre) {
            return format!(
                "{} des {} nœuds sont sur « {} » : sa perte emporterait le quorum.",
                d.noeuds.len(),
                self.noeuds_total,
                d.nom.as_deref().unwrap_or("un domaine non déclaré")
            );
        }
        if self.domaines.iter().any(|d| d.nom.is_none()) {
            // ⚠️ Ni bon ni mauvais : on ne sait pas. Le taire ferait croire à une
            // répartition vérifiée qui ne l'est pas.
            return "Des nœuds n'ont pas de domaine de panne déclaré : leur répartition \
                    réelle est inconnue."
                .to_string();
        }
        "La charge est répartie sur plusieurs domaines de panne.".to_string()
    }
}

/// Une tâche Swarm, telle que la vue topologie la place.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TacheSummary {
    pub id: String,
    pub service: String,
    #[serde(default)]
    pub slot: Option<u64>,
    #[serde(default)]
    pub noeud: Option<String>,
    pub etat: String,
    pub etat_voulu: String,
    pub vivante: bool,
    pub echouee: bool,
    /// 🔴 Ce qui explique un échec. C'est le champ que l'ancien compteur jetait.
    #[serde(default)]
    pub explication: Option<String>,
    #[serde(default)]
    pub image: Option<String>,
}

/// Une exécution de sauvegarde, pour la frise du §11bis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SauvegardeRun {
    pub app: String,
    pub kind: String,
    #[serde(default)]
    pub destination: Option<String>,
    pub reussie: bool,
    #[serde(default)]
    pub erreur: Option<String>,
    pub quand: String,
}

/// L'état d'une destination pour une app.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CouvertureSummary {
    pub app: String,
    /// `(destination, âge en secondes ou `None` si jamais servie)`.
    pub par_destination: Vec<(String, Option<i64>)>,
    /// 🔴 Le chiffre du 3-2-1 : combien de copies protègent VRAIMENT.
    ///
    /// Distinct du nombre de destinations déclarées — une destination en échec est une
    /// destination qui ne protège de rien.
    pub copies_a_jour: usize,
}

impl CouvertureSummary {
    pub fn attention(&self) -> Attention {
        match self.copies_a_jour {
            0 => Attention::Critical,
            1 => Attention::Notice,
            _ => Attention::Ok,
        }
    }

    /// Y a-t-il des sauvegardes, mais toutes périmées ?
    ///
    /// 🔴 Deux situations très différentes se cachent derrière « aucune copie à jour » :
    /// **jamais sauvegardée** (rien n'existe, nulle part) et **sauvegardes périmées**
    /// (des copies existent, elles datent). La première demande de configurer une
    /// sauvegarde, la seconde de comprendre pourquoi elle ne tourne plus.
    ///
    /// Constaté à l'écran : « AUCUNE copie à jour » à côté de deux destinations
    /// affichant « 1 j » se lit comme une contradiction, et on doute de l'écran entier.
    pub fn toutes_perimees(&self) -> bool {
        self.copies_a_jour == 0
            && !self.par_destination.is_empty()
            && self.par_destination.iter().all(|(_, age)| age.is_some())
    }

    /// Rien n'existe nulle part.
    pub fn jamais_sauvegardee(&self) -> bool {
        self.par_destination.iter().all(|(_, age)| age.is_none())
    }

    pub fn resume(&self) -> String {
        match self.copies_a_jour {
            0 if self.par_destination.is_empty() => "aucune destination configurée".to_string(),
            0 if self.jamais_sauvegardee() => "JAMAIS sauvegardée".to_string(),
            0 => format!(
                "aucune copie À JOUR — {} trop {}",
                pluriel(
                    self.par_destination.len() as u64,
                    "destination",
                    "destinations"
                ),
                if self.par_destination.len() > 1 {
                    "anciennes"
                } else {
                    "ancienne"
                }
            ),
            1 => format!(
                "1 seule copie à jour sur {} — le 3-2-1 n'est pas tenu",
                pluriel(
                    self.par_destination.len() as u64,
                    "destination",
                    "destinations"
                )
            ),
            n => format!("{n} copies à jour"),
        }
    }
}

/// Un écart entre ce qui devrait tourner et ce qui tourne (lot 9.8).
///
/// ## Pourquoi la raison du refus est un champ, et pas un commentaire
///
/// La réconciliation ne supprime jamais un orphelin, ne ressuscite jamais une
/// installation en échec, et ne force jamais une convergence en cours. Ces refus
/// étaient **invisibles** : rien ne distinguait « rien à faire » de « il y a quelque
/// chose et j'ai délibérément choisi de ne pas y toucher ».
///
/// Les deux se ressemblent à l'écran. La seconde, non expliquée, fait douter du
/// système : on corrige à la main ce qu'il protégeait, ou l'on croit qu'il n'a rien vu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcartSummary {
    /// L'app ou le service concerné.
    pub cible: String,
    /// Le constat, en une phrase.
    pub description: String,
    /// La réconciliation sait-elle corriger cet écart ?
    pub corrigible: bool,
    /// 🔴 Pourquoi elle ne le corrige **pas**. Présent exactement quand
    /// `corrigible` est faux.
    #[serde(default)]
    pub refus: Option<String>,
}

impl EcartSummary {
    pub fn attention(&self) -> Attention {
        if self.corrigible {
            // Un écart corrigible n'est pas une panne : il sera repris au tour suivant.
            Attention::Notice
        } else {
            // ⚠️ Un refus délibéré n'est pas une alerte non plus — c'est une décision.
            // Le peindre en rouge ferait chercher un problème là où le système a fait
            // exactement ce qu'il fallait.
            Attention::Ok
        }
    }
}

/// Ce qu'une app déclare, et ce qui est réellement publié (lot 9.10).
///
/// ## Pourquoi la comparaison est un écran
///
/// Le manifest déclare `expose`, et `hlb-ingress` rend la configuration Caddy. Les
/// deux existent ; personne ne les met côte à côte. Une app publiée par erreur est
/// donc **totalement invisible** — et c'est précisément ce que le §11bis désigne comme
/// « facile de se tromper ».
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpositionSummary {
    pub app: String,
    pub hote: String,
    /// Ce que le manifest demande : `private`, `after-guide`, `public`.
    pub declaree: String,
    /// 🔴 Ce qui est RÉELLEMENT joignable depuis l'internet, maintenant.
    pub publique: bool,
    /// L'explication de l'écart entre les deux, quand il y en a un.
    #[serde(default)]
    pub divergence: Option<String>,
}

impl ExpositionSummary {
    pub fn attention(&self) -> Attention {
        if self.divergence.is_some() {
            Attention::Critical
        } else if self.publique {
            // ⚠️ Une app publique conforme n'est pas un problème — mais elle n'est pas
            // « rien à signaler » non plus. Ce qui est sur l'internet mérite d'être vu,
            // sinon la liste ne se lit plus.
            Attention::Notice
        } else {
            Attention::Ok
        }
    }

    /// La phrase qui résume la ligne.
    pub fn describe(&self) -> String {
        match (&self.divergence, self.publique) {
            (Some(d), _) => d.clone(),
            (None, true) => format!("{} est joignable depuis l'internet.", self.hote),
            (None, false) => format!("{} n'est joignable que depuis le VPN.", self.hote),
        }
    }
}

/// Une ligne de la liste de contrôle de l'installation (lot 9.7).
///
/// 🔴 Ce n'est pas un assistant de démarrage — le §2ter.0 l'interdit : une interface
/// web ne peut pas être le premier pas. C'est une vérification d'APRÈS-COUP, sur les
/// choses qu'on croit faites et qu'on n'a jamais contrôlées.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControleSante {
    pub titre: String,
    pub attention: Attention,
    /// Le constat, en toutes lettres.
    pub constat: String,
    /// La commande ou l'écran qui corrige. Absent quand il n'y a rien à faire.
    #[serde(default)]
    pub remede: Option<String>,
}

/// Un événement de la frise chronologique unifiée (lot 9.5).
///
/// ## Pourquoi une seule rivière
///
/// Déploiements, sauvegardes, alertes et entrées d'audit vivent chacun sur leur écran
/// et dans leur tableau. Corréler « l'app est tombée à 3 h 12 » avec « mise à jour
/// appliquée à 3 h 10 » demande alors d'ouvrir quatre écrans et de comparer des heures
/// à la main — c'est précisément ce que la ligne de commande ne sait pas faire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evenement {
    /// Secondes depuis l'époque. C'est la clé de tri, et la seule chose que les quatre
    /// sources ont en commun.
    pub quand: i64,
    pub genre: GenreEvenement,
    /// L'app, le nœud ou la personne concernée.
    pub cible: String,
    /// Ce qui s'est passé, en une phrase.
    pub quoi: String,
    pub attention: Attention,
}

/// D'où vient l'événement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenreEvenement {
    Sauvegarde,
    Verification,
    /// Une action humaine ou machine, prise au journal d'audit.
    Action,
    Alerte,
}

impl GenreEvenement {
    pub fn libelle(&self) -> &'static str {
        match self {
            Self::Sauvegarde => "sauvegarde",
            Self::Verification => "vérification",
            Self::Action => "action",
            Self::Alerte => "alerte",
        }
    }
}

/// Une version du manifest, avec ce qui a changé depuis la précédente (lot 9.11).
///
/// ## Pourquoi le miroir Git plutôt qu'une table de plus
///
/// `apps.manifest` est écrasé à chaque mise à jour : l'état ne garde que la version
/// courante. Répondre à « qu'est-ce qui a changé quand l'app a cessé de marcher ? »
/// demanderait donc de stocker un historique — alors que `hlb-gitops` en tient déjà un,
/// complet et daté. On y lit, on n'y ajoute rien.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionManifest {
    /// Le commit court du miroir.
    pub reference: String,
    /// Le résumé du commit : ce que Homelabus faisait à ce moment-là.
    pub sujet: String,
    /// Les lignes changées depuis la version précédente, préfixées `+` ou `-`.
    ///
    /// ⚠️ Vide pour la version la plus ancienne connue : il n'y a rien avant elle. Ce
    /// n'est **pas** « rien n'a changé ».
    #[serde(default)]
    pub diff: Vec<String>,
    /// Vrai pour la plus ancienne version connue, celle qui n'a pas de prédécesseur.
    pub origine: bool,
}

/// Un plan préparé à froid, enregistré sous un nom (lot 10.4).
///
/// ## Pourquoi enregistrer un plan plutôt que le refaire
///
/// Une opération se prépare quand on a le temps, et s'exécute à l'heure creuse. Tout
/// décider et tout exécuter dans la même minute est exactement la façon dont on se
/// trompe de cible.
///
/// 🔴 Le plan est rejoué **tel qu'il a été prévisualisé**, jamais recalculé : deux
/// calculs à deux instants différents peuvent diverger — une app installée entre-temps,
/// un domaine changé — et l'on exécuterait alors autre chose que ce qu'on a relu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanNomme {
    pub nom: String,
    /// Le résumé lu au moment de l'enregistrement : c'est CE texte qu'on a approuvé.
    pub resume: String,
    pub methode: String,
    pub chemin: String,
    pub cree_par: String,
    /// Âge du plan, en secondes.
    pub age_s: i64,
}

/// Au-delà, un plan préparé décrit peut-être un cluster qui n'existe plus.
pub const PLAN_PERIME_S: i64 = 30 * 86_400;

impl PlanNomme {
    pub fn attention(&self) -> Attention {
        if self.age_s > PLAN_PERIME_S {
            // ⚠️ Pas un blocage : c'est un avertissement. Un plan d'il y a six semaines
            // peut être parfaitement valide — mais il a été écrit pour un cluster qu'on
            // n'a plus forcément.
            Attention::Notice
        } else {
            Attention::Ok
        }
    }

    pub fn mise_en_garde(&self) -> Option<String> {
        (self.age_s > PLAN_PERIME_S).then(|| {
            format!(
                "Préparé il y a {} : relis l'aperçu avant d'appliquer, l'installation a \
                 pu changer depuis.",
                humanise(self.age_s)
            )
        })
    }
}

/// Une alerte, telle que l'interface la montre.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlerteActive {
    /// L'identifiant court et stable de la règle.
    pub regle: String,
    pub niveau: NiveauAlerte,
    /// Ce que la personne doit comprendre, en une phrase.
    pub explication: String,
    /// La valeur observée. `None` quand la règle n'a pas pu être évaluée.
    #[serde(default)]
    pub valeur: Option<f64>,
    pub seuil: f64,
    /// Depuis quand elle est active, en secondes.
    ///
    /// 🔴 Une alerte qui vient d'apparaître et une qui dure depuis trois jours ne se
    /// traitent pas pareil : la seconde a été ignorée, ou son remède ne marche pas.
    pub depuis_s: i64,
    /// 🔴 Mise en sourdine — **jamais résolue**. Voir [`Self::est_silencee`].
    #[serde(default)]
    pub silencee_jusqu_a: Option<i64>,
    /// Qui l'a mise en sourdine, et pourquoi.
    #[serde(default)]
    pub silencee_par: Option<String>,
}

/// La gravité d'une alerte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NiveauAlerte {
    /// 🔴 La règle ne peut plus être évaluée. **Ce n'est pas « tout va bien »** : la
    /// collecte est peut-être tombée, et cette surveillance est aveugle depuis.
    Inconnu,
    Info,
    Important,
    Critique,
}

impl NiveauAlerte {
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Inconnu => "non évaluable",
            Self::Info => "information",
            Self::Important => "important",
            Self::Critique => "critique",
        }
    }

    /// Le niveau d'attention correspondant, pour l'affichage.
    pub fn attention(&self) -> Attention {
        match self {
            Self::Info => Attention::Ok,
            // ⚠️ « Non évaluable » vaut `Notice` et non `Ok` : ne pas savoir mérite
            // qu'on regarde, même si ce n'est pas encore une panne.
            Self::Inconnu | Self::Important => Attention::Notice,
            Self::Critique => Attention::Critical,
        }
    }
}

impl AlerteActive {
    /// Cette alerte est-elle en sourdine à cet instant ?
    pub fn est_silencee(&self, maintenant: i64) -> bool {
        self.silencee_jusqu_a.is_some_and(|f| f > maintenant)
    }

    /// Ce qu'il faut afficher.
    ///
    /// 🔴 Une alerte en sourdine ne ressemble **jamais** à une alerte résolue : elle
    /// reste visible, marquée, avec l'échéance de sa sourdine. La faire disparaître
    /// serait la même famille d'erreur que `Freshness` — l'absence d'information qui
    /// se déguise en information rassurante.
    pub fn libelle(&self, maintenant: i64) -> String {
        match self.silencee_jusqu_a {
            Some(f) if f > maintenant => format!(
                "{} — EN SOURDINE encore {}{}",
                self.explication,
                humanise(f - maintenant),
                match &self.silencee_par {
                    Some(qui) => format!(" (par {qui})"),
                    None => String::new(),
                }
            ),
            _ => self.explication.clone(),
        }
    }

    /// Le niveau tenu compte de la sourdine — pour trier, pas pour cacher.
    pub fn attention(&self, maintenant: i64) -> Attention {
        if self.est_silencee(maintenant) {
            // Rétrogradée d'un cran, jamais jusqu'à `Ok` : une sourdine dit « je sais »,
            // pas « c'est réglé ».
            return match self.niveau.attention() {
                Attention::Critical => Attention::Notice,
                autre => autre,
            };
        }
        self.niveau.attention()
    }
}

/// Une série temporelle, telle que l'interface la dessine.
///
/// 🔴 **`Indisponible` est une variante, pas une série vide.**
///
/// Une série vide se dessine comme une ligne plate à zéro, qui se lit « tout est
/// calme » — soit exactement le contraire de « je n'ai pas de données ». C'est la même
/// famille d'erreur que `Freshness` côté interface et que « une métrique absente vaut
/// mieux qu'un zéro » côté serveur : dans les trois cas, l'absence d'information se
/// déguise en information rassurante.
///
/// Le type oblige donc à traiter le cas.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "etat", rename_all = "lowercase")]
pub enum Serie {
    Points {
        nom: String,
        /// `(horodatage Unix, valeur)`, dans l'ordre.
        points: Vec<(i64, f64)>,
        unite: Unite,
    },
    /// VictoriaMetrics est absent, muet, ou la requête n'a rien rendu.
    Indisponible { raison: String },
}

/// Comment lire les valeurs d'une série.
///
/// Sert à l'affichage : un ratio se montre en pourcentage, des octets se montrent en
/// Go, une durée se humanise. Sans cette information, l'interface devrait deviner
/// d'après le nom de la métrique — et se tromperait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Unite {
    /// Une fraction dans `[0, 1]`, affichée en pourcentage.
    Ratio,
    Octets,
    /// Octets par seconde.
    OctetsParSeconde,
    Secondes,
    /// Un décompte sans unité.
    Nombre,
}

impl Unite {
    /// Rend une valeur lisible.
    pub fn afficher(&self, v: f64) -> String {
        match self {
            Self::Ratio => format!("{:.0} %", v * 100.0),
            Self::Octets => octets(v),
            Self::OctetsParSeconde => format!("{}/s", octets(v)),
            Self::Secondes => humanise(v as i64),
            // ⚠️ Pas de décimale sur un décompte : « 3,0 applications » se lit comme
            // une mesure approximative alors que c'est un entier exact.
            Self::Nombre => format!("{v:.0}"),
        }
    }
}

impl Serie {
    /// Les points, ou rien.
    ///
    /// Il n'existe **pas** d'accesseur qui rendrait un `Vec` vide en cas
    /// d'indisponibilité : c'est précisément la confusion qu'on évite.
    pub fn points(&self) -> Option<&[(i64, f64)]> {
        match self {
            Self::Points { points, .. } => Some(points),
            Self::Indisponible { .. } => None,
        }
    }

    /// La dernière valeur connue.
    pub fn derniere(&self) -> Option<f64> {
        self.points()?.last().map(|(_, v)| *v)
    }

    /// Ce qu'il faut afficher à la place d'un graphe.
    pub fn indisponible(&self) -> Option<&str> {
        match self {
            Self::Indisponible { raison } => Some(raison),
            // Une série de moins de deux points ne fait pas une courbe : la dessiner
            // donnerait un trait plat trompeur.
            Self::Points { points, .. } if points.len() < 2 => Some("pas assez de mesures"),
            Self::Points { .. } => None,
        }
    }
}

/// Un nombre d'octets, lisible.
pub fn octets(v: f64) -> String {
    const SEUIL: f64 = 1024.0;
    let mut v = v;
    for u in ["o", "Kio", "Mio", "Gio", "Tio"] {
        if v.abs() < SEUIL {
            return if u == "o" {
                format!("{v:.0} {u}")
            } else {
                format!("{v:.1} {u}")
            };
        }
        v /= SEUIL;
    }
    format!("{v:.1} Pio")
}

/// Accorde un mot au singulier ou au pluriel.
///
/// ⚠️ Le projet est en français et se lit : « 1 réplicas » saute aux yeux et donne
/// l'impression d'un texte fabriqué par accident. Écrire « réplica(s) » partout serait
/// le contraire du soin qu'on met au reste.
pub fn pluriel(n: u64, singulier: &str, pluriel: &str) -> String {
    // 🔴 Zéro prend le SINGULIER en français — « 0 réplica », pas « 0 réplicas ».
    // C'est la règle qui surprend, et celle qu'un `if n > 1` naïf rate.
    if n <= 1 {
        format!("{n} {singulier}")
    } else {
        format!("{n} {pluriel}")
    }
}

/// Une durée en secondes, rendue lisible.
///
/// Volontairement grossier : sur un tableau de bord, « il y a 3 h » informe autant que
/// « il y a 3 h 12 min 04 s » et se lit d'un coup d'œil.
pub fn humanise(secs: i64) -> String {
    match secs {
        s if s < 0 => "dans le futur ?".to_string(),
        s if s < 60 => format!("{s} s"),
        s if s < 3600 => format!("{} min", s / 60),
        s if s < 86_400 => format!("{} h", s / 3600),
        s if s < 2_592_000 => format!("{} j", s / 86_400),
        s => format!("{} mois", s / 2_592_000),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_shared_string_uses_the_parenthesised_plural() {
        // 🔴 Constaté à l'écran : « 1 service(s) dont TOUS les réplicas… ». Le test qui
        // interdisait ce tic ne couvrait que l'interface — or `verdict()` est calculé
        // ICI, précisément pour que les deux clients disent la même chose. Une règle
        // d'écriture appliquée d'un seul côté du contrat ne protège de rien.
        //
        // ⚠️ Le motif est ASSEMBLÉ : l'écrire littéralement ferait échouer ce test sur
        // son propre code.
        let tic = format!("({})", "s");
        for (fichier, source) in [
            ("lib.rs", include_str!("lib.rs")),
            ("panne.rs", include_str!("panne.rs")),
        ] {
            // ⚠️ Le scan porte sur les CHAÎNES, pas sur le code : `Some(s) => f(s)` est
            // un motif Rust parfaitement légitime, et un scan ligne à ligne le
            // signalait — un garde-fou qui crie sur du code correct finit désactivé.
            for texte in chaines_affichees(source) {
                assert!(
                    !texte.contains(&tic),
                    "{fichier} : « {texte} » — hlb_api::pluriel existe pour ça"
                );
            }
        }
    }

    /// Les littéraux de chaîne d'un source, commentaires exclus.
    ///
    /// Le même extracteur que celui de l'interface : les deux tests portent la même
    /// règle, et une règle appliquée d'un seul côté du contrat ne protège de rien.
    fn chaines_affichees(source: &str) -> Vec<String> {
        let sans_commentaires: String = source
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");

        let mut out = Vec::new();
        let mut courant = String::new();
        let mut dedans = false;
        let mut echappe = false;

        for c in sans_commentaires.chars() {
            if echappe {
                echappe = false;
                continue;
            }
            match c {
                '\\' if dedans => echappe = true,
                '"' => {
                    if dedans {
                        out.push(std::mem::take(&mut courant));
                    }
                    dedans = !dedans;
                }
                _ if dedans => courant.push(c),
                _ => {}
            }
        }
        out
    }

    #[test]
    fn no_shared_string_carries_a_glyph_the_interface_cannot_display() {
        // 🔴 Le piège déjà constaté sur `Coherence::describe()`, transposé au contrat.
        //
        // Ces textes sont rendus par le CLI **et** par egui. Le terminal affiche les
        // emoji, egui non : il les remplace par un caractère de substitution, et la
        // phrase se casse (« ¤ identité créée, AUCUNE boîte »). Un texte partagé ne
        // doit dépendre d'AUCUN de ses consommateurs.
        //
        // Le scan porte sur tout ce qui n'est pas un commentaire — les identifiants
        // Rust sont ASCII, donc seuls les littéraux affichés peuvent déclencher.
        // ⚠️ Un scan par expression régulière sur les chaînes ne suffirait pas : une
        // chaîne à continuation de ligne n'est pas close sur sa propre ligne, et le
        // caractère fautif passerait exactement là où il s'est présenté.
        for (fichier, source) in [
            ("lib.rs", include_str!("lib.rs")),
            ("panne.rs", include_str!("panne.rs")),
            ("rotation.rs", include_str!("rotation.rs")),
            ("breakglass.rs", include_str!("breakglass.rs")),
            ("diagnostic.rs", include_str!("diagnostic.rs")),
        ] {
            for (n, ligne) in source.lines().enumerate() {
                let code = ligne.split("//").next().unwrap_or("");
                for ch in code.chars() {
                    let cp = ch as u32;
                    assert!(
                        cp < 0x2C0 || (0x2000..=0x206F).contains(&cp),
                        "{fichier} ligne {} : U+{cp:04X} ne s'affiche pas dans egui",
                        n + 1
                    );
                }
            }
        }
    }

    use super::*;

    fn app(status: &str, backup: Option<i64>, guides: i64) -> AppSummary {
        AppSummary {
            name: "gitea".into(),
            status: status.into(),
            image: "gitea/gitea:1.24".into(),
            domain: Some("git.example.fr".into()),
            last_backup_secs: backup,
            last_verification_secs: None,
            blocking_guides: guides,
        }
    }

    #[test]
    fn a_never_backed_up_app_is_critical_even_when_healthy() {
        // 🔴 Le piège du tableau de bord : une app qui tourne parfaitement et n'a
        // AUCUNE sauvegarde est le pire état du système — et celui qui paraît le
        // plus sain si on ne regarde que le statut.
        let a = app("running", None, 0);
        assert_eq!(a.attention(), Attention::Critical);
        assert_eq!(a.backup_label(), "JAMAIS");
    }

    #[test]
    fn never_and_zero_seconds_are_not_the_same() {
        // Même distinction que pour les métriques : un « 0 » voudrait dire
        // « sauvegardée à l'instant », soit exactement le contraire.
        assert_eq!(app("running", None, 0).backup_label(), "JAMAIS");
        assert_eq!(app("running", Some(0), 0).backup_label(), "0 s");
        assert_ne!(
            app("running", None, 0).attention(),
            app("running", Some(0), 0).attention()
        );
    }

    #[test]
    fn a_stale_backup_is_critical() {
        // L'intervalle visé est de 4 h (§8.1) ; au-delà de 24 h, quelque chose est
        // cassé et personne ne s'en est aperçu.
        assert_eq!(app("running", Some(3600), 0).attention(), Attention::Ok);
        assert_eq!(
            app("running", Some(90_000), 0).attention(),
            Attention::Critical
        );
    }

    #[test]
    fn a_failed_app_is_critical() {
        assert_eq!(app("failed", Some(60), 0).attention(), Attention::Critical);
    }

    #[test]
    fn blocking_guides_are_a_notice_not_a_failure() {
        // Un guide bloquant est le système qui protège l'utilisateur, pas une panne.
        assert_eq!(app("running", Some(60), 2).attention(), Attention::Notice);
        assert_eq!(app("partial", Some(60), 0).attention(), Attention::Notice);
    }

    #[test]
    fn a_healthy_app_is_ok() {
        assert_eq!(app("running", Some(600), 0).attention(), Attention::Ok);
    }

    #[test]
    fn attention_levels_are_ordered() {
        // Permet de trier le tableau de bord par urgence sans règle ad hoc.
        assert!(Attention::Ok < Attention::Notice);
        assert!(Attention::Notice < Attention::Critical);
    }

    #[test]
    fn french_agreement_treats_zero_as_singular() {
        // 🔴 « 0 réplica » en français, pas « 0 réplicas ». C'est la règle qui
        // surprend, et celle qu'un `if n > 1` naïf rate.
        assert_eq!(pluriel(0, "réplica", "réplicas"), "0 réplica");
        assert_eq!(pluriel(1, "réplica", "réplicas"), "1 réplica");
        assert_eq!(pluriel(2, "réplica", "réplicas"), "2 réplicas");
        assert_eq!(pluriel(12, "copie", "copies"), "12 copies");
    }

    #[test]
    fn durations_read_at_a_glance() {
        assert_eq!(humanise(30), "30 s");
        assert_eq!(humanise(120), "2 min");
        assert_eq!(humanise(7200), "2 h");
        assert_eq!(humanise(172_800), "2 j");
        assert_eq!(humanise(5_184_000), "2 mois");
    }

    #[test]
    fn a_negative_age_does_not_lie() {
        // Une horloge décalée entre nœuds peut donner un âge négatif. Afficher
        // « 0 s » ferait croire à une sauvegarde à l'instant.
        assert_eq!(humanise(-10), "dans le futur ?");
    }

    #[test]
    fn a_refusal_is_not_a_failure() {
        let refus = AuditItem {
            id: 1,
            at: "2026-08-16".into(),
            actor: "cli".into(),
            role: "operator".into(),
            action: "update".into(),
            target: "gitea".into(),
            outcome: "refused".into(),
            detail: None,
        };
        assert!(refus.is_refusal());
        assert!(!refus.is_failure());
    }

    #[test]
    fn rights_are_computed_from_the_single_matrix() {
        // 🔴 Redéduire les droits du nom du rôle côté interface ferait diverger deux
        // implémentations de la même matrice — et la divergence irait dans le sens
        // permissif, ce qui est une faille et pas un défaut d'affichage.
        let u = Droits::pour(hlb_types::Role::User);
        assert!(u.agir_sur_soi);
        assert!(!u.lire, "un simple utilisateur ne voit pas la console");
        assert!(!u.voit_la_console());

        let v = Droits::pour(hlb_types::Role::Viewer);
        assert!(v.lire && v.voit_la_console());
        assert!(!v.operer);

        let o = Droits::pour(hlb_types::Role::Operator);
        assert!(o.operer && o.publier);
        assert!(!o.detruire && !o.gerer_comptes);

        let a = Droits::pour(hlb_types::Role::Admin);
        assert!(a.detruire && a.gerer_comptes);
    }

    #[test]
    fn a_service_token_is_shown_as_acting_for_nobody() {
        // L'interface doit masquer « ma boîte », « mes aliases » : il n'y a personne
        // derrière un jeton de service, et proposer ces écrans mènerait à un 403.
        let m = Moi {
            compte: None,
            role: "admin".into(),
            role_libelle: "tout".into(),
            par_jeton: true,
            peut: Droits::pour(hlb_types::Role::Admin),
            boites: Vec::new(),
        };
        assert!(m.compte.is_none());
        assert!(m.par_jeton);
        assert!(m.boites.is_empty());
    }

    #[test]
    fn the_default_brand_is_the_one_this_installation_was_made_for() {
        let m = Marque::default();
        assert_eq!(m.nom, "Turi Industries");
        assert_eq!(m.produit, "Homelabus");
        assert_eq!(m.initiales(), "TI");
    }

    #[test]
    fn the_house_and_the_product_are_never_merged() {
        // « Turi Industries » exploite « Homelabus ». Les confondre rendrait la page
        // incompréhensible pour quelqu'un qui découvre l'outil.
        let m = Marque::default();
        assert!(m.titre().contains(&m.nom));
        assert!(m.titre().contains(&m.produit));
        assert_ne!(m.nom, m.produit);
    }

    #[test]
    fn a_brand_never_carries_its_logo_in_every_response() {
        // Une image de 256 Ko encodée dans chaque réponse serait payée à chaque
        // sondage, par chaque écran. Le type ne permet pas de la représenter.
        let j = serde_json::to_string(&Marque::default()).expect("sérialisable");
        assert!(!j.contains("base64"), "{j}");
        assert!(j.contains("\"logo\":false"), "{j}");
    }

    #[test]
    fn initials_survive_an_empty_or_odd_name() {
        let avec = |nom: &str| {
            Marque {
                nom: nom.into(),
                ..Default::default()
            }
            .initiales()
        };
        assert_eq!(avec(""), "?");
        assert_eq!(avec("---"), "?");
        assert_eq!(avec("ACME"), "A");
        assert_eq!(avec("Turi Industries"), "TI");
    }

    fn statut(services: Vec<(EtatService, &str)>) -> PageStatut {
        PageStatut {
            services: services
                .into_iter()
                .map(|(etat, nom)| ServiceStatut {
                    nom: nom.into(),
                    domaine: None,
                    etat,
                })
                .collect(),
            incidents: Vec::new(),
            publique: false,
        }
    }

    #[test]
    fn a_planned_maintenance_is_not_an_outage() {
        // 🔴 C'était prévu, et le dire évite qu'on cherche ce qui ne va pas.
        let p = statut(vec![(EtatService::Maintenance, "postgres")]);
        assert_eq!(p.attention(), Attention::Notice);
        assert!(!p.verdict().contains("hors service"), "{}", p.verdict());

        let panne = statut(vec![(EtatService::Indisponible, "postgres")]);
        assert_eq!(panne.attention(), Attention::Critical);
        assert!(panne.verdict().contains("hors service"));
    }

    #[test]
    fn an_open_incident_shows_even_when_every_service_answers() {
        // Un service peut répondre et mal fonctionner : c'est précisément ce qu'un
        // incident déclaré dit, et qu'aucune sonde ne verrait.
        let mut p = statut(vec![(EtatService::Operationnel, "immich")]);
        assert!(p.verdict().contains("opérationnels"));

        p.incidents.push(Annonce {
            id: 1,
            titre: "Lenteurs".into(),
            corps: "x".into(),
            niveau: NiveauAnnonce::Incident,
            epinglee: true,
            auteur: "remy".into(),
            publiee_le: "…".into(),
            expire_dans_s: None,
            suivi: Vec::new(),
        });
        assert_eq!(p.attention(), Attention::Critical);
        assert!(p.verdict().contains("incident"), "{}", p.verdict());
    }

    #[test]
    fn a_status_page_is_private_until_someone_decides_otherwise() {
        // 🔴 Une page publique révèle la liste de ce qui tourne chez vous et le
        // calendrier de vos pannes. C'est un choix, pas un défaut.
        assert!(!statut(Vec::new()).publique);
    }

    fn annonce(niveau: NiveauAnnonce, expire: Option<i64>) -> Annonce {
        Annonce {
            id: 1,
            titre: "Maintenance des bases".into(),
            corps: "PostgreSQL redémarre à 3 h.".into(),
            niveau,
            epinglee: false,
            auteur: "remy".into(),
            publiee_le: "2026-08-18 10:00:00".into(),
            expire_dans_s: expire,
            suivi: Vec::new(),
        }
    }

    #[test]
    fn an_incident_stays_open_until_someone_closes_it() {
        // 🔴 Ce qui rend un incident résolu n'est pas son âge, c'est une mise à jour
        // qui le dit. Le silence ne doit pas passer pour une résolution.
        let ouvert = annonce(NiveauAnnonce::Incident, None);
        assert!(ouvert.incident_ouvert());
        assert_eq!(ouvert.niveau.attention(), Attention::Critical);

        let clos = annonce(NiveauAnnonce::Incident, Some(-60));
        assert!(!clos.incident_ouvert(), "expiré, donc plus ouvert");
    }

    #[test]
    fn the_latest_update_is_what_people_read() {
        // Un incident se SUIT : c'est la dernière nouvelle qui compte, pas le message
        // d'origine — lequel dit souvent « on cherche ».
        let mut a = annonce(NiveauAnnonce::Incident, None);
        assert_eq!(a.derniere_nouvelle(), "PostgreSQL redémarre à 3 h.");

        a.suivi.push(MajAnnonce {
            corps: "Cause trouvée : disque plein.".into(),
            auteur: "remy".into(),
            at: "11:00".into(),
        });
        a.suivi.push(MajAnnonce {
            corps: "Résolu.".into(),
            auteur: "remy".into(),
            at: "11:30".into(),
        });
        assert_eq!(a.derniere_nouvelle(), "Résolu.");
        // Et la chronologie complète reste lisible.
        assert_eq!(a.suivi.len(), 2);
    }

    #[test]
    fn an_unreadable_level_never_becomes_an_incident() {
        // ⚠️ Le défaut est le niveau le plus BAS : une colonne corrompue ne doit pas
        // faire crier « incident » sur tous les écrans.
        assert_eq!(NiveauAnnonce::parse("n'importe quoi"), NiveauAnnonce::Info);
        assert_eq!(NiveauAnnonce::parse("incident"), NiveauAnnonce::Incident);
    }

    #[test]
    fn a_permanent_announcement_never_expires() {
        assert!(annonce(NiveauAnnonce::Info, None).active());
        assert!(annonce(NiveauAnnonce::Info, Some(3600)).active());
        assert!(!annonce(NiveauAnnonce::Info, Some(-1)).active());
    }

    #[test]
    fn a_half_created_account_is_critical_not_a_notice() {
        // 🔴 Identité sans boîte : la personne se connecte partout et son adresse ne
        // reçoit rien. Ça ne se voit qu'au premier courriel perdu, souvent une
        // réinitialisation de mot de passe — c'est-à-dire au pire moment.
        assert_eq!(EtatCompte::SansBoite.attention(), Attention::Critical);
        assert_eq!(EtatCompte::SansIdentite.attention(), Attention::Critical);
        assert_eq!(EtatCompte::Complet.attention(), Attention::Ok);
    }

    #[test]
    fn a_broken_account_says_how_to_repair_it() {
        // La création est reprenable : relancer termine ce qui manque, sans détruire
        // ce qui existe.
        assert!(EtatCompte::SansBoite
            .remede("remy")
            .is_some_and(|r| r.contains("hlb user add remy")));
        assert_eq!(EtatCompte::Complet.remede("remy"), None);
    }

    #[test]
    fn a_multi_use_invitation_counts_down() {
        // Inviter une équipe demandait un lien par personne. Un lien à cinq usages fait
        // le même travail en une fois — au prix d'une fuite cinq fois plus coûteuse.
        let mut i = InvitationSummary {
            reference: "a1".into(),
            cree_par: "remy".into(),
            profil: "standard".into(),
            role: "utilisateur".into(),
            expire_dans_s: 3600,
            utilisee_le: None,
            usages: 0,
            usages_max: 5,
            note: None,
        };
        assert_eq!(i.restants(), 5);
        assert!(i.largement_ouverte(), "cinq entrées, ça doit se voir");

        i.usages = 2;
        assert_eq!(i.etat(), "partiellement utilisée");
        assert!(i.utilisable());

        i.usages = 5;
        assert!(!i.utilisable());
        assert_eq!(i.etat(), "épuisée");
        assert_eq!(i.restants(), 0);
        assert!(!i.largement_ouverte());
    }

    #[test]
    fn a_partially_used_link_is_distinguishable_from_an_untouched_one() {
        // 🔴 Un lien qui a déjà servi ET reste ouvert est celui qu'on oublie de fermer.
        let mut i = InvitationSummary {
            reference: "a1".into(),
            cree_par: "remy".into(),
            profil: "standard".into(),
            role: "utilisateur".into(),
            expire_dans_s: 3600,
            utilisee_le: None,
            usages: 0,
            usages_max: 3,
            note: None,
        };
        assert_eq!(i.etat(), "en attente");
        i.usages = 1;
        assert_ne!(i.etat(), "en attente");
    }

    #[test]
    fn an_old_invitation_without_the_field_stays_single_use() {
        // ⚠️ Compatibilité : une invitation sérialisée avant l'ajout du champ ne doit
        // pas devenir illimitée. Le défaut est le cas SÛR.
        let j = r#"{"reference":"a1","cree_par":"remy","profil":"standard",
                    "role":"utilisateur","expire_dans_s":3600}"#;
        let i: InvitationSummary = serde_json::from_str(j).expect("relisible");
        assert_eq!(i.usages_max, 1);
        assert!(i.utilisable());
    }

    #[test]
    fn an_invitation_never_carries_its_value() {
        // 🔴 La garantie est structurelle : le type n'a aucun champ pour la valeur, on
        // ne peut donc pas la fuiter par accident.
        let i = InvitationSummary {
            reference: "a1b2c3d4".into(),
            cree_par: "remy".into(),
            profil: "standard".into(),
            role: "utilisateur".into(),
            expire_dans_s: 3600,
            utilisee_le: None,
            usages: 0,
            usages_max: 1,
            note: None,
        };
        let j = serde_json::to_string(&i).expect("sérialisable");
        assert!(!j.contains("jeton"), "{j}");
        assert!(!j.contains("token"), "{j}");
        assert!(!j.contains("value"), "{j}");
    }

    #[test]
    fn a_used_invitation_can_never_serve_again() {
        // Usage unique : la réutiliser créerait un second compte avec les mêmes droits,
        // au nom de quelqu'un qui n'a rien demandé.
        let mut i = InvitationSummary {
            reference: "a1".into(),
            cree_par: "remy".into(),
            profil: "standard".into(),
            role: "utilisateur".into(),
            expire_dans_s: 3600,
            utilisee_le: None,
            usages: 0,
            usages_max: 1,
            note: None,
        };
        assert!(i.utilisable());
        assert_eq!(i.etat(), "en attente");

        i.usages = 1;
        i.utilisee_le = Some("2026-08-18".into());
        assert!(!i.utilisable());
        assert_eq!(i.etat(), "épuisée");
    }

    #[test]
    fn an_expired_invitation_is_distinguishable_from_a_used_one() {
        // Les deux sont inutilisables, mais pas pour la même raison : l'une se
        // renouvelle, l'autre a déjà servi.
        let i = InvitationSummary {
            reference: "a1".into(),
            cree_par: "remy".into(),
            profil: "standard".into(),
            role: "utilisateur".into(),
            expire_dans_s: -60,
            utilisee_le: None,
            usages: 0,
            usages_max: 1,
            note: None,
        };
        assert!(!i.utilisable());
        assert_eq!(i.etat(), "expirée");
    }

    fn action(applique: bool, etapes: Vec<EtatEtape>) -> ResultatAction {
        ResultatAction {
            applique,
            resume: "installer gitea".into(),
            etapes: etapes
                .into_iter()
                .map(|etat| EtapeAction {
                    description: "faire quelque chose".into(),
                    etat,
                    erreur: None,
                })
                .collect(),
            commande_cli: "hlb install gitea --apply".into(),
            blocages: Vec::new(),
            avertissements: Vec::new(),
            confirmation_requise: None,
        }
    }

    #[test]
    fn a_warning_never_blocks_a_legitimate_action() {
        // 🔴 « Ce lien laissera entrer cinq personnes » est un choix légitime qu'on
        // veut voir avant de le faire — pas un refus. Ranger un avertissement parmi
        // les blocages rendrait l'action impossible.
        let mut a = action(false, vec![EtatEtape::Prevue]);
        a.avertissements
            .push("cinq personnes pourront entrer".into());
        assert!(a.applicable(), "un avertissement a bloqué l'action");

        a.blocages.push("le DNS n'existe pas".into());
        assert!(!a.applicable(), "un vrai blocage doit empêcher");
    }

    #[test]
    fn a_preview_never_looks_like_a_completed_action() {
        // 🔴 La confusion la plus coûteuse possible sur un écran qui déclenche des
        // actions : croire que c'est fait alors que c'est un aperçu.
        let a = action(false, vec![EtatEtape::Prevue, EtatEtape::Prevue]);
        assert!(!a.reussie());
        assert!(
            a.verdict().contains("rien n'a été modifié"),
            "{}",
            a.verdict()
        );
    }

    #[test]
    fn an_unimplemented_step_is_never_a_success() {
        // 🔴 « Le plan s'est déroulé sans erreur » et « l'app est installée » ne sont
        // pas la même chose. On ne prétend jamais avoir provisionné une base.
        let a = action(true, vec![EtatEtape::Faite, EtatEtape::NonImplementee]);
        assert!(
            !a.reussie(),
            "une étape non implémentée n'est pas une réussite"
        );
        assert!(a.verdict().contains("INCOMPLÈTE"), "{}", a.verdict());
        // Et surtout : pas d'erreur, donc rien ne le signalerait sans ce message.
        assert!(!a.verdict().contains("échec"));
    }

    #[test]
    fn a_fully_applied_action_says_what_it_did() {
        let a = action(true, vec![EtatEtape::Faite, EtatEtape::Faite]);
        assert!(a.reussie());
        assert_eq!(a.verdict(), "installer gitea");
    }

    #[test]
    fn a_failure_stops_the_verdict_from_being_positive() {
        let a = action(true, vec![EtatEtape::Faite, EtatEtape::Echouee]);
        assert!(!a.reussie());
        assert!(a.verdict().contains("échec"), "{}", a.verdict());
    }

    #[test]
    fn blockers_prevent_application() {
        let mut a = action(false, vec![EtatEtape::Prevue]);
        assert!(a.applicable());
        a.blocages
            .push("le DNS de git.example.fr n'existe pas".into());
        assert!(
            !a.applicable(),
            "un guide bloquant doit empêcher d'appliquer"
        );
    }

    #[test]
    fn every_action_carries_its_cli_equivalent() {
        // Le CLI reste la source de vérité : l'interface l'enseigne au lieu de s'y
        // substituer, et l'action reste reproductible.
        let a = action(false, Vec::new());
        assert!(a.commande_cli.starts_with("hlb "), "{}", a.commande_cli);
        assert!(a.commande_cli.contains("--apply"));
    }

    fn topo(violations: Vec<ViolationSummary>, domaines: Vec<DomaineSummary>) -> Topologie {
        let noeuds_total = domaines.iter().map(|d| d.noeuds.len()).sum();
        Topologie {
            managers: Vec::new(),
            domaines,
            violations,
            noeuds_total,
        }
    }

    fn domaine(nom: Option<&str>, n: usize, concentre: bool) -> DomaineSummary {
        DomaineSummary {
            nom: nom.map(str::to_string),
            noeuds: (0..n)
                .map(|i| NoeudDansDomaine {
                    id: format!("n{i}"),
                    hostname: format!("h{i}"),
                    tier: None,
                    joignable: true,
                    services: Vec::new(),
                })
                .collect(),
            concentre,
        }
    }

    #[test]
    fn an_illusory_redundancy_is_the_worst_verdict() {
        // 🔴 Tous les réplicas sur le même fer : le service PARAÎT redondant. C'est
        // exactement ce que la ligne de commande ne montre pas.
        let t = topo(
            vec![ViolationSummary {
                service: "gitea".into(),
                domaine: Some("big-01".into()),
                replicas: 2,
                total: 2,
                totale: true,
                explication: "…".into(),
            }],
            vec![domaine(Some("big-01"), 2, false)],
        );
        assert_eq!(t.attention(), Attention::Critical);
        assert!(t.verdict().contains("illusion"), "{}", t.verdict());
    }

    #[test]
    fn a_concentrated_domain_is_flagged_even_without_violations() {
        // Aucun service mal réparti, et pourtant : deux nœuds sur trois sur un seul
        // fer, sa perte emporte le quorum.
        let t = topo(
            Vec::new(),
            vec![
                domaine(Some("big-01"), 2, true),
                domaine(Some("small"), 1, false),
            ],
        );
        assert_eq!(t.attention(), Attention::Notice);
        assert!(t.verdict().contains("quorum"), "{}", t.verdict());
    }

    #[test]
    fn undeclared_domains_are_said_to_be_unknown_not_fine() {
        // ⚠️ Le taire ferait croire à une répartition vérifiée qui ne l'est pas.
        let t = topo(Vec::new(), vec![domaine(None, 2, false)]);
        assert!(t.verdict().contains("inconnue"), "{}", t.verdict());
    }

    #[test]
    fn a_properly_spread_cluster_says_so_plainly() {
        let t = topo(
            Vec::new(),
            vec![domaine(Some("a"), 1, false), domaine(Some("b"), 1, false)],
        );
        assert_eq!(t.attention(), Attention::Ok);
        assert!(t.verdict().contains("répartie"), "{}", t.verdict());
    }

    fn tache(etat: &str, voulu: &str) -> TacheSummary {
        TacheSummary {
            id: "t".into(),
            service: "gitea".into(),
            slot: Some(1),
            noeud: Some("n1".into()),
            etat: etat.into(),
            etat_voulu: voulu.into(),
            vivante: etat == "running" && voulu == "running",
            echouee: matches!(etat, "failed" | "rejected" | "orphaned"),
            explication: None,
            image: None,
        }
    }

    fn detail(taches: Vec<TacheSummary>) -> AppDetail {
        AppDetail {
            diagnostic: None,
            restaurabilite: None,
            resume: AppSummary {
                name: "gitea".into(),
                status: "running".into(),
                image: "gitea/gitea:1.24".into(),
                domain: None,
                last_backup_secs: Some(60),
                last_verification_secs: None,
                blocking_guides: 0,
            },
            taches,
            capacites: Vec::new(),
            volumes: Vec::new(),
            env: Vec::new(),
            guides: Vec::new(),
            couverture: None,
            sauvegardes: Vec::new(),
            journal: Vec::new(),
            image: None,
            domaine: None,
            manifest: None,
        }
    }

    #[test]
    fn dead_task_history_never_inflates_the_replica_count() {
        // 🔴 Swarm garde l'historique des tâches mortes. Compter toutes les tâches
        // donnerait « 2/9 réplicas » après quelques redéploiements, et on chercherait
        // sept réplicas qui n'ont jamais été demandés.
        let d = detail(vec![
            tache("running", "running"),
            tache("running", "running"),
            tache("shutdown", "shutdown"),
            tache("shutdown", "shutdown"),
            tache("failed", "shutdown"),
        ]);
        assert_eq!(d.replicas(), (2, 2));
    }

    #[test]
    fn a_partially_deployed_app_shows_the_gap() {
        // Deux réplicas voulus, un seul debout : c'est le cas « partial », et le
        // chiffre doit le montrer.
        let d = detail(vec![
            tache("running", "running"),
            tache("pending", "running"),
        ]);
        assert_eq!(d.replicas(), (1, 2));
    }

    #[test]
    fn failures_are_reachable_because_they_explain_the_colour() {
        // Les masquer laisserait un service « partiel » sans la moindre explication.
        let mut echouee = tache("failed", "running");
        echouee.explication = Some("no suitable node (insufficient memory)".into());
        let d = detail(vec![tache("running", "running"), echouee]);

        let e = d.echecs();
        assert_eq!(e.len(), 1);
        assert!(e[0].explication.as_deref().unwrap_or("").contains("memory"));
    }

    fn noeud(joignable: bool) -> NoeudSummary {
        NoeudSummary {
            adresse: "10.0.0.1:8421".into(),
            hostname: Some("n1".into()),
            joignable,
            detail: None,
            rapport_age_s: Some(30),
            cpu_occupation: Some(0.4),
            charge_par_coeur: Some(0.5),
            memoire_utilisee: Some(0.6),
            swap_utilise: Some(0.0),
            disques: Vec::new(),
            uptime_s: Some(3600),
            distro: None,
            noyau: None,
            agent_version: Some("0.2.0".into()),
            protocole: Some(2),
            taches: Vec::new(),
        }
    }

    #[test]
    fn an_unreachable_node_is_never_a_healthy_one() {
        // 🔴 « Pas de problème signalé » est le pire affichage possible pour un nœud
        // dont on ne sait rien : ses données ne sont plus sauvegardées.
        let mut n = noeud(false);
        n.detail = Some("connexion refusée".into());
        assert_eq!(n.attention(), Attention::Critical);
        let r = n.raison().expect("une raison");
        assert!(r.contains("injoignable"), "{r}");
        assert!(
            r.contains("sauvegardées"),
            "la conséquence doit être dite : {r}"
        );
    }

    #[test]
    fn a_saturated_disk_outweighs_everything_else() {
        let mut n = noeud(true);
        n.disques = vec![
            DisqueSummary {
                chemin: "/".into(),
                utilise: 0.30,
                total_mb: 100_000,
                libre_mb: 70_000,
                pression: 0,
            },
            DisqueSummary {
                chemin: "/var/lib/docker".into(),
                utilise: 0.96,
                total_mb: 50_000,
                libre_mb: 2_000,
                pression: 4,
            },
        ];
        assert_eq!(n.attention(), Attention::Critical);
        let r = n.raison().expect("une raison");
        assert!(r.contains("/var/lib/docker"), "le PIRE disque décide : {r}");
    }

    #[test]
    fn swapping_and_load_are_notices_not_failures() {
        // La machine ralentit sans être tombée : il faut le voir, sans crier.
        let mut n = noeud(true);
        n.swap_utilise = Some(0.7);
        assert_eq!(n.attention(), Attention::Notice);
        assert!(n.raison().expect("raison").contains("ralentit"));

        let mut n = noeud(true);
        n.charge_par_coeur = Some(1.5);
        assert_eq!(n.attention(), Attention::Notice);
    }

    #[test]
    fn a_healthy_node_says_nothing() {
        // « Rien de vert n'a besoin d'être grand » : un nœud sain n'a pas de phrase.
        assert_eq!(noeud(true).attention(), Attention::Ok);
        assert_eq!(noeud(true).raison(), None);
    }

    #[test]
    fn never_backed_up_reads_differently_from_stale() {
        // 🔴 Constaté à l'écran : « AUCUNE copie à jour » à côté de deux destinations
        // affichant « 1 j » se lit comme une contradiction, et on doute de l'écran
        // entier. Ce sont pourtant deux situations différentes, qui se réparent
        // différemment.
        let jamais = CouvertureSummary {
            app: "seafile".into(),
            par_destination: vec![("nas".into(), None), ("offsite".into(), None)],
            copies_a_jour: 0,
        };
        let perimee = CouvertureSummary {
            app: "vikunja".into(),
            par_destination: vec![
                ("nas".into(), Some(108_000)),
                ("offsite".into(), Some(111_600)),
            ],
            copies_a_jour: 0,
        };

        assert!(jamais.jamais_sauvegardee());
        assert!(!jamais.toutes_perimees());
        assert!(jamais.resume().contains("JAMAIS"), "{}", jamais.resume());

        assert!(perimee.toutes_perimees());
        assert!(!perimee.jamais_sauvegardee());
        assert!(
            perimee.resume().contains("anciennes"),
            "le résumé doit expliquer la contradiction apparente : {}",
            perimee.resume()
        );
        assert_ne!(jamais.resume(), perimee.resume());
    }

    #[test]
    fn no_destination_at_all_says_so() {
        // « Aucune copie » sans destination configurée fait chercher une panne là où il
        // n'y a qu'une configuration à faire.
        let rien = CouvertureSummary {
            app: "neuve".into(),
            par_destination: Vec::new(),
            copies_a_jour: 0,
        };
        assert!(rien.resume().contains("destination"), "{}", rien.resume());
    }

    #[test]
    fn one_copy_is_not_three_two_one() {
        // 🔴 Le nombre de destinations DÉCLARÉES ne dit rien du nombre de copies.
        let c = CouvertureSummary {
            app: "immich".into(),
            par_destination: vec![("nas".into(), Some(7200)), ("offsite".into(), None)],
            copies_a_jour: 1,
        };
        assert_eq!(c.attention(), Attention::Notice);
        assert!(c.resume().contains("3-2-1"), "{}", c.resume());

        let zero = CouvertureSummary {
            app: "seafile".into(),
            par_destination: vec![("nas".into(), None)],
            copies_a_jour: 0,
        };
        assert_eq!(zero.attention(), Attention::Critical);
        // Le libellé nomme la situation exacte : ici rien n'a jamais été sauvegardé.
        assert!(zero.resume().contains("JAMAIS"), "{}", zero.resume());
    }

    fn alerte(niveau: NiveauAlerte) -> AlerteActive {
        AlerteActive {
            regle: "sauvegarde-absente".into(),
            niveau,
            explication: "une app n'a jamais été sauvegardée".into(),
            valeur: Some(1.0),
            seuil: 0.0,
            depuis_s: 3_600,
            silencee_jusqu_a: None,
            silencee_par: None,
        }
    }

    #[test]
    fn a_silenced_alert_never_looks_resolved() {
        // 🔴 La faire disparaître serait la même erreur que d'afficher des données
        // périmées comme fraîches : l'absence d'information déguisée en information
        // rassurante.
        let mut a = alerte(NiveauAlerte::Critique);
        a.silencee_jusqu_a = Some(10_000);
        a.silencee_par = Some("remy".into());

        let l = a.libelle(5_000);
        assert!(l.contains("SOURDINE"), "{l}");
        assert!(l.contains("remy"), "qui l'a silencée doit se voir : {l}");
        assert!(l.contains(&a.explication), "le motif reste visible : {l}");

        // Rétrogradée, jamais éteinte : une sourdine dit « je sais », pas « c'est réglé ».
        assert_eq!(a.attention(5_000), Attention::Notice);
        assert_ne!(a.attention(5_000), Attention::Ok);
    }

    #[test]
    fn a_silence_expires_and_the_alert_comes_back() {
        // Une sourdine sans échéance serait une suppression déguisée.
        let mut a = alerte(NiveauAlerte::Critique);
        a.silencee_jusqu_a = Some(10_000);

        assert!(a.est_silencee(9_999));
        assert!(!a.est_silencee(10_001));
        assert_eq!(
            a.attention(10_001),
            Attention::Critical,
            "elle revient entière"
        );
    }

    #[test]
    fn not_being_able_to_evaluate_is_not_fine() {
        // 🔴 « Aucune donnée » n'est pas « tout va bien » : la collecte est peut-être
        // tombée, et cette surveillance est aveugle depuis.
        assert_eq!(NiveauAlerte::Inconnu.attention(), Attention::Notice);
        assert_ne!(NiveauAlerte::Inconnu.attention(), Attention::Ok);
    }

    #[test]
    fn alert_levels_are_ordered_for_sorting() {
        assert!(NiveauAlerte::Info < NiveauAlerte::Important);
        assert!(NiveauAlerte::Important < NiveauAlerte::Critique);
    }

    #[test]
    fn an_unavailable_series_is_never_an_empty_one() {
        // 🔴 Une série vide se dessine comme une ligne plate à zéro, qui se lit « tout
        // est calme » — l'exact contraire de « je n'ai pas de données ».
        let absente = Serie::Indisponible {
            raison: "VictoriaMetrics injoignable".into(),
        };
        assert_eq!(absente.points(), None);
        assert_eq!(absente.derniere(), None);
        assert!(absente.indisponible().is_some());

        let vide = Serie::Points {
            nom: "x".into(),
            points: Vec::new(),
            unite: Unite::Ratio,
        };
        // Même une série de zéro ou un point doit refuser d'être dessinée.
        assert!(vide.indisponible().is_some());
    }

    #[test]
    fn a_real_series_is_drawable() {
        let s = Serie::Points {
            nom: "hlb_cpu_used_ratio".into(),
            points: vec![(100, 0.4), (160, 0.6)],
            unite: Unite::Ratio,
        };
        assert_eq!(s.indisponible(), None);
        assert_eq!(s.derniere(), Some(0.6));
        assert_eq!(s.points().map(|p| p.len()), Some(2));
    }

    #[test]
    fn units_read_the_way_a_human_expects() {
        assert_eq!(Unite::Ratio.afficher(0.415), "42 %");
        assert_eq!(Unite::Nombre.afficher(3.0), "3", "pas « 3,0 applications »");
        assert_eq!(Unite::Octets.afficher(512.0), "512 o");
        assert_eq!(Unite::Octets.afficher(1536.0), "1.5 Kio");
        assert_eq!(
            Unite::Octets.afficher(5.0 * 1024.0 * 1024.0 * 1024.0),
            "5.0 Gio"
        );
        assert_eq!(Unite::OctetsParSeconde.afficher(2048.0), "2.0 Kio/s");
        assert_eq!(Unite::Secondes.afficher(7200.0), "2 h");
    }

    #[test]
    fn a_series_survives_a_json_roundtrip() {
        // Le contrat serveur ↔ interface : une variante mal étiquetée casserait
        // silencieusement l'affichage des graphes.
        for s in [
            Serie::Points {
                nom: "x".into(),
                points: vec![(1, 2.0)],
                unite: Unite::Octets,
            },
            Serie::Indisponible {
                raison: "absent".into(),
            },
        ] {
            let j = serde_json::to_string(&s).expect("sérialisable");
            let relue: Serie = serde_json::from_str(&j).expect("relisible");
            assert_eq!(relue, s, "{j}");
        }
    }

    #[test]
    fn a_secret_has_no_field_for_its_value() {
        // 🔴 La garantie est structurelle : on ne peut pas fuiter ce qu'on ne peut
        // pas représenter.
        let s = SecretItem {
            name: "restic-repo-password".into(),
            purpose: "chiffrement du dépôt".into(),
        };
        let j = serde_json::to_string(&s).expect("sérialisable");
        assert!(!j.contains("value"), "{j}");
        assert!(!j.to_lowercase().contains("secret\":"), "{j}");
    }
}
