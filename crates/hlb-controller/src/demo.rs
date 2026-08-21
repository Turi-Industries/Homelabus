//! Un controller peuplé de données plausibles, sans Docker ni cluster (lot 2.6).
//!
//! ## Pourquoi ça existe
//!
//! L'interface a une vingtaine d'écrans à écrire. Sans mode démo, chaque itération
//! visuelle exige une installation réelle : un Swarm, des apps déployées, des
//! sauvegardes de plusieurs jours d'ancienneté, un compte en échec de création. On ne
//! reproduit pas ça pour ajuster une marge.
//!
//! Et surtout : les cas qu'il faut *voir* sont ceux qu'on n'a jamais sous la main. Une
//! app jamais sauvegardée, un hors-site périmé depuis trois semaines, un alias expiré
//! qui reçoit encore, un nœud à 96 % de disque, un compte à moitié créé. Ce sont
//! exactement ceux dont l'affichage doit être juste, et exactement ceux qu'on ne
//! rencontre pas en développant.
//!
//! ## 🔴 Ce que ce mode ne doit jamais faire
//!
//! Toucher à une base réelle. Il ouvre **`State::in_memory()`** et rien d'autre : le
//! chemin `--state` est ignoré, et le dire au démarrage évite le malentendu où l'on
//! croit avoir perdu ses données.
//!
//! Il n'écrit pas non plus dans Docker : aucun orchestrateur n'est branché, aucune
//! boucle de réconciliation ne tourne.

use std::collections::BTreeMap;

use hlb_agent::disk::DiskUsage;
use hlb_agent::report::NodeReport;
use hlb_state::State;

use crate::agents::AgentStatus;

/// Un jeu de données qui couvre les cas intéressants.
///
/// Chaque entrée est là pour un état d'affichage précis, noté en commentaire — sans
/// quoi le jeu dérive vers « trois apps qui vont bien », c'est-à-dire vers le seul cas
/// qui n'a pas besoin d'être vérifié.
pub async fn peupler(state: &State) -> Result<(), Box<dyn std::error::Error>> {
    let maintenant = crate::auth::maintenant();

    // --- Applications, une par état d'attention ------------------------------
    for (nom, statut, domaine) in [
        ("gitea", "running", Some("git.turi.fr")),
        ("vikunja", "running", Some("taches.turi.fr")),
        ("immich", "running", Some("photos.turi.fr")),
        ("vaultwarden", "running", Some("coffre.turi.fr")),
        ("jellyfin", "partial", Some("media.turi.fr")),
        ("n8n", "failed", Some("flux.turi.fr")),
        ("seafile", "running", Some("fichiers.turi.fr")),
        ("postgres", "running", None),
        // 🔴 Le runbook engendré a révélé son absence : gitea déclare du SSO, donc le
        // graphe de dépendances exige « pocket-id ». Sans lui, l'ordre de redémarrage
        // ne se calculait pas — un manque réel, pas un défaut d'affichage.
        ("pocket-id", "running", Some("id.turi.fr")),
        // Idem : Immich déclare du stockage objet, donc Garage doit exister.
        ("garage", "running", None),
        ("valkey", "running", None),
        ("stalwart", "running", Some("mail.turi.fr")),
    ] {
        state.upsert_app(nom, &manifest(nom)?, domaine).await?;
        state.set_app_status(nom, statut).await?;
    }

    // Les volumes, avec les deux cas qui portent un piège : un volume NON sauvegardé
    // et une base SQLite qu'on ne peut pas copier à chaud (§3.4).
    for (app, nom, chemin, sauvegarde, sqlite) in [
        ("gitea", "gitea-data", "/data", true, false),
        ("immich", "immich-cache", "/cache", false, false),
        ("vaultwarden", "vaultwarden-data", "/data", true, true),
    ] {
        state
            .add_volume(app, nom, chemin, sauvegarde, sqlite)
            .await?;
    }

    // --- Sauvegardes : les quatre cas qui comptent ---------------------------
    state
        .upsert_destination("nas", "/mnt/nas/restic", "critique,volumineux", None)
        .await?;
    state
        .upsert_destination(
            "offsite",
            "s3:s3.eu-central.example/hlb",
            "critique",
            Some("backup-dest-offsite"),
        )
        .await?;

    // Fraîche partout : le cas nominal.
    for dest in ["nas", "offsite"] {
        state
            .record_backup_to("gitea", "volume", dest, Some("a1b2c3d4"), None)
            .await?;
        state
            .record_backup_to("vaultwarden", "database", dest, Some("e5f6a7b8"), None)
            .await?;
    }

    // 🔴 Le cas piège du §8.1 : le NAS tourne, le hors-site est mort. Un résumé qui
    // prendrait le MAX passerait ça pour une sauvegarde de deux heures, alors qu'il ne
    // reste qu'une copie, sur les mêmes machines.
    state
        .record_backup_to("immich", "volume", "nas", Some("c9d0e1f2"), None)
        .await?;
    for _ in 0..4 {
        state
            .record_backup_to(
                "immich",
                "volume",
                "offsite",
                None,
                Some("connexion refusée"),
            )
            .await?;
    }

    // Sauvegardée et fraîche, mais partiellement déployée : c'est ce qui produit un
    // `Notice`. ⚠️ Sans cette ligne, jellyfin retombait en `Critical` — une app jamais
    // sauvegardée l'emporte sur son statut, et le jeu de démonstration ne montrait
    // alors AUCUN cas intermédiaire. Le test l'a attrapé.
    for dest in ["nas", "offsite"] {
        state
            .record_backup_to("jellyfin", "volume", dest, Some("11aa22bb"), None)
            .await?;
        state
            .record_backup_to("n8n", "database", dest, Some("33cc44dd"), None)
            .await?;
        // Sauvegardée, mais PLUS DEPUIS 30 HEURES : l'app tourne, le tableau de bord
        // affiche une coche verte à côté du statut, et pourtant plus rien ne part.
        // C'est un troisième `Critical`, de cause différente des deux autres.
        state
            .record_backup_to("vikunja", "database", dest, Some("55ee66ff"), None)
            .await?;
    }

    // 🔴 Le pire état du système : l'app tourne parfaitement et n'a AUCUNE sauvegarde.
    // C'est celui qui paraît le plus sain sur un tableau de bord.
    // (seafile n'a volontairement aucune ligne de sauvegarde.)

    // 🔴 Des âges VARIÉS, pas tous « à l'instant ». Une sauvegarde de deux heures et
    // une de trente heures ne s'affichent pas pareil — la seconde est en retard (§8.1)
    // — et c'est exactement cette différence d'affichage qu'on veut pouvoir vérifier.
    for (app, dest, age_s) in [
        ("gitea", "nas", 2 * 3_600),
        ("gitea", "offsite", 9 * 3_600),
        ("vaultwarden", "nas", 40 * 60),
        ("vaultwarden", "offsite", 5 * 3_600),
        // ⚠️ jellyfin garde une sauvegarde FRAÎCHE : c'est son statut `partial` qui
        // doit produire un `Notice`. L'antidater la ferait basculer en `Critical`, et
        // le jeu de démonstration n'aurait plus aucun cas intermédiaire — le test l'a
        // attrapé deux fois.
        ("jellyfin", "nas", 50 * 60),
        ("jellyfin", "offsite", 3 * 3_600),
        // En retard : plus de 24 h, donc `Critical` malgré une app qui tourne bien.
        ("vikunja", "nas", 30 * 3_600),
        ("vikunja", "offsite", 31 * 3_600),
        ("n8n", "nas", 3 * 3_600),
        ("n8n", "offsite", 6 * 3_600),
        ("immich", "nas", 7 * 3_600),
    ] {
        state.backdate_backup(app, dest, age_s).await?;
    }

    // 🔴 L'exposition RÉELLEMENT posée, telle qu'un « hlb ingress apply » l'aurait
    // enregistrée. Trois cas d'un coup : conforme, publiée alors qu'elle ne devrait pas
    // l'être, et une route survivante d'une app retirée.
    state
        .record_ingress(&[
            ("git.turi.fr".into(), "gitea".into(), true),
            // 🔴 Immich est déclarée PRIVÉE dans son manifest et répond pourtant depuis
            // l'internet. C'est l'app publiée par erreur, aujourd'hui invisible.
            ("photos.turi.fr".into(), "immich".into(), true),
            // Et la route d'une app qui n'existe plus : elle n'apparaît dans aucun
            // manifest, donc dans aucun parcours des apps installées.
            ("cloud.turi.fr".into(), "nextcloud".into(), true),
        ])
        .await?;

    // Gitea est l'app dont la restauration a été VÉRIFIÉE : sans elle, la démo ne
    // montrerait jamais le seul cas où l'on peut vraiment se fier à une sauvegarde.
    state
        .record_verification("gitea", "a1b2c3d4", true, Some("1 284 fichiers relus"))
        .await?;
    // Et Immich celle dont la vérification a ÉCHOUÉ : une app peut avoir des copies
    // fraîches et une relecture qui rate, ce qui est le cas le plus trompeur.
    state
        .record_verification("immich", "e5f6a7b8", false, Some("3 blocs illisibles"))
        .await?;
    state
        .record_drill(
            "postgres",
            true,
            Some(42),
            187,
            "restauration en bac à sable",
        )
        .await?;

    // --- Actions manuelles en attente ----------------------------------------
    state
        .add_guide(
            "n8n",
            "premier-admin",
            "Créer le compte administrateur",
            true,
        )
        .await?;
    state
        .add_guide(
            "jellyfin",
            "bibliotheques",
            "Déclarer les bibliothèques",
            false,
        )
        .await?;

    // --- Secrets : noms et usages, jamais de valeurs -------------------------
    for (nom, usage) in [
        ("gitea-db-password", "mot de passe PostgreSQL"),
        ("gitea-oidc-secret", "client OIDC PocketID"),
        ("restic-repo-password", "chiffrement du dépôt restic"),
        ("backup-dest-offsite", "identifiants S3 du hors-site"),
        ("immich-s3-secret", "clé Garage d'Immich"),
    ] {
        // ⚠️ Une valeur factice, jamais crédible : ce mode sert de démonstration, et un
        // secret d'allure réelle finirait copié quelque part.
        state
            .store_secret_if_absent(nom, b"(mode demonstration)", usage)
            .await?;
    }

    // --- Comptes humains ------------------------------------------------------
    state
        .upsert_user("remy", "illimite", Some("pid-remy"))
        .await?;
    state.add_mailbox("remy", "remy", "turi.fr", true).await?;
    state
        .set_user_role("remy", hlb_types::Role::Admin, Some("bootstrap"))
        .await?;

    state
        .upsert_user("camille", "standard", Some("pid-camille"))
        .await?;
    state
        .add_mailbox("camille", "camille", "turi.fr", true)
        .await?;
    state
        .set_user_role("camille", hlb_types::Role::Operator, Some("remy"))
        .await?;

    // 🔴 Un compte à MOITIÉ créé : identité posée, aucune boîte. La personne se
    // connecte partout et son adresse ne reçoit rien — ça ne se voit qu'au premier
    // courriel perdu, souvent une réinitialisation de mot de passe.
    state
        .upsert_user("dominique", "standard", Some("pid-dominique"))
        .await?;

    // 🔴 Et l'inverse : boîte créée, aucune identité.
    state.upsert_user("sacha", "invite", None).await?;
    state.add_mailbox("sacha", "sacha", "turi.fr", true).await?;

    // --- Aliases : les quatre états de `alias::Etat` --------------------------
    let jour = 86_400;
    // Permanent.
    state
        .add_alias(
            "remy",
            "remy",
            "impots-k3m9x2",
            None,
            Some("impots"),
            Some("impots.gouv.fr"),
        )
        .await?;
    // Temporaire encore valide.
    state
        .add_alias(
            "remy",
            "remy",
            "concours-p7t4nz",
            Some(maintenant + 20 * jour),
            Some("concours"),
            Some("jeu-concours"),
        )
        .await?;
    // 🔴 Expiré ET TOUJOURS ACTIF : la purge n'a pas tourné, l'adresse reçoit encore.
    // C'est le seul état qui trahit la promesse faite à l'utilisateur.
    state
        .add_alias(
            "remy",
            "remy",
            "newsletter-w2r8kd",
            Some(maintenant - 3 * jour),
            Some("newsletter"),
            Some("infolettre du fournisseur"),
        )
        .await?;
    // Expiré et retiré : l'état nominal après purge.
    state
        .add_alias(
            "remy",
            "remy",
            "essai-b6h1qc",
            Some(maintenant - 30 * jour),
            Some("essai"),
            None,
        )
        .await?;
    state.deactivate_alias("remy", "essai-b6h1qc").await?;

    // ⚠️ Trois valeurs distinctes pour le dossier de tri : `NULL` (rien décidé, on
    // propose un défaut), `""` (choix explicite de ne PAS trier) et un dossier choisi.
    // Les confondre réimposerait un dossier à chaque régénération.
    state
        .set_alias_folder("remy", "impots-k3m9x2", Some("Administratif/Impôts"))
        .await?;
    state
        .set_alias_folder("remy", "concours-p7t4nz", Some(""))
        .await?;

    state
        .add_alias(
            "camille",
            "camille",
            "amazon-r4j8mv",
            None,
            Some("amazon"),
            Some("amazon.fr"),
        )
        .await?;

    // --- Annonces : les quatre niveaux, dont un incident SUIVI ----------------
    //
    // 🔴 Un incident sans son fil ne montrerait pas ce qui fait la valeur du système :
    // la chronologie qu'on relit après coup.
    let incident = state
        .publier_annonce(
            "Lenteurs sur les photos",
            "Immich répond lentement depuis 9 h. On cherche.",
            hlb_api::NiveauAnnonce::Incident,
            true,
            None,
            "remy",
            None,
        )
        .await?;
    state
        .suivre_annonce(
            incident,
            "Cause identifiée : le disque de small-01 est plein à 96 %.",
            "remy",
        )
        .await?;
    state
        .suivre_annonce(
            incident,
            "Purge en cours. Les photos déjà importées ne sont pas affectées.",
            "camille",
        )
        .await?;

    state
        .publier_annonce(
            "Maintenance des bases mardi",
            "PostgreSQL redémarre mardi à 3 h. Coupure d'environ dix minutes.",
            hlb_api::NiveauAnnonce::Maintenance,
            false,
            // ⚠️ Réservée à l'exploitation : l'utilisateur du portail n'a rien à en
            // faire, et l'inonder lui ferait cesser de lire les annonces.
            Some(hlb_types::Role::Operator),
            "remy",
            None,
        )
        .await?;

    state
        .publier_annonce(
            "Nouveau webmail",
            "Bulwark est disponible sur mail.turi.fr. Roundcube reste accessible.",
            hlb_api::NiveauAnnonce::Info,
            false,
            None,
            "remy",
            None,
        )
        .await?;

    // Une annonce EXPIRÉE : elle a quitté le portail et reste à l'historique.
    state
        .publier_annonce(
            "Panne réseau du 12 août",
            "Résolu : câble débranché au sous-sol.",
            hlb_api::NiveauAnnonce::Incident,
            false,
            None,
            "remy",
            Some(maintenant - 86_400),
        )
        .await?;

    // --- Journal d'audit ------------------------------------------------------
    //
    // 🔴 Le dernier champ est l'ÂGE en secondes. Sans lui, tous les événements portent
    // la même minute, et la frise chronologique — dont le seul intérêt est de
    // rapprocher « l'app est tombée » de « la mise à jour a été appliquée » — ne montre
    // rien du tout. C'est l'écran qui a rendu le défaut visible.
    for (acteur, role, action, cible, issue, detail, age) in [
        (
            "remy",
            hlb_types::Role::Admin,
            "install",
            "immich",
            "ok",
            None,
            6 * 86_400,
        ),
        // La paire qui raconte quelque chose : la mise à jour, puis l'échec deux
        // minutes plus tard.
        (
            "camille",
            hlb_types::Role::Operator,
            "update",
            "gitea",
            "ok",
            Some("1.23 vers 1.24"),
            3_720,
        ),
        (
            "remy",
            hlb_types::Role::Admin,
            "backup-run",
            "immich",
            "failed",
            Some("hors-site injoignable"),
            3_600,
        ),
        (
            "camille",
            hlb_types::Role::Operator,
            "purge",
            "vikunja",
            "refused",
            Some("rôle insuffisant"),
            2 * 86_400,
        ),
        (
            "remy",
            hlb_types::Role::Admin,
            "user-role",
            "camille",
            "ok",
            Some("utilisateur vers operator"),
            26 * 3_600,
        ),
        (
            "bitwarden",
            hlb_types::Role::Operator,
            "alias-create",
            "remy",
            "ok",
            None,
            900,
        ),
    ] {
        state
            .audit(acteur, role, action, cible, issue, detail)
            .await?;
        // L'identifiant de la ligne qu'on vient d'écrire : la plus récente.
        if let Some(dernier) = state.audit_trail(1).await?.first() {
            state.backdate_audit(dernier.id, age).await?;
        }
    }

    Ok(())
}

/// La topologie, telle qu'un vrai cluster la rendrait.
///
/// 🔴 Fabriquée avec **le piège du §2bis.2 dedans** : deux VM sur le même fer, et un
/// service dont les deux réplicas y sont tous les deux. Sans ce cas, l'écran qui
/// justifie l'existence de l'interface n'aurait rien à montrer — et on ne saurait pas
/// s'il le montre bien.
pub fn topologie() -> hlb_api::Topologie {
    let noeud = |id: &str, host: &str, tier: &str, joignable: bool, services: &[&str]| {
        hlb_api::NoeudDansDomaine {
            id: id.into(),
            hostname: host.into(),
            tier: Some(tier.into()),
            joignable,
            services: services.iter().map(|s| s.to_string()).collect(),
        }
    };

    hlb_api::Topologie {
        noeuds_total: 4,
        // Deux managers sur le MÊME fer : la perte de « big-01 » emporte le quorum en
        // plus des apps. C'est le cas que le simulateur doit rendre lisible.
        managers: vec!["n-heavy".into(), "n-mail".into(), "n-small1".into()],
        domaines: vec![
            // 🔴 LE cas : deux nœuds Swarm, un seul serveur physique. La ligne de
            // commande en montre deux et laisse croire à de la redondance.
            hlb_api::DomaineSummary {
                nom: Some("big-01 (fer unique)".into()),
                concentre: true,
                noeuds: vec![
                    noeud(
                        "n-heavy",
                        "swarm-heavy",
                        "heavy",
                        true,
                        &["postgres", "valkey", "gitea", "immich"],
                    ),
                    noeud("n-mail", "mail-vm", "light", true, &["stalwart", "gitea"]),
                ],
            },
            hlb_api::DomaineSummary {
                nom: Some("small-01".into()),
                concentre: false,
                noeuds: vec![noeud("n-small1", "small-01", "light", true, &["vikunja"])],
            },
            // Un nœud sans domaine déclaré : on ne SAIT PAS s'il partage un fer.
            hlb_api::DomaineSummary {
                nom: None,
                concentre: false,
                noeuds: vec![noeud("n-small2", "small-02", "light", false, &[])],
            },
        ],
        violations: vec![hlb_api::ViolationSummary {
            service: "gitea".into(),
            domaine: Some("big-01 (fer unique)".into()),
            replicas: 2,
            total: 2,
            totale: true,
            explication: "gitea : ses 2 réplicas sont TOUS sur le domaine \
                              « big-01 (fer unique) » — la redondance est une illusion"
                .into(),
        }],
    }
}

/// Les alertes actives, telles que la boucle les produirait.
///
/// 🔴 Fabriquées, parce que le mode démonstration n'a pas de VictoriaMetrics : sans
/// elles, l'écran des alertes serait vide et on ne pourrait pas l'écrire. Or c'est
/// précisément l'écran dont l'affichage doit être juste — une alerte mal rendue est
/// une alerte qu'on ne verra pas le jour venu.
///
/// Le jeu couvre les quatre cas qui s'affichent différemment : critique, important,
/// **non évaluable** (la collecte est tombée, ce n'est pas « tout va bien »), et une
/// alerte **en sourdine** qui doit rester visible.
pub fn alertes(maintenant: i64) -> Vec<hlb_api::AlerteActive> {
    vec![
        hlb_api::AlerteActive {
            regle: "sauvegarde-absente".into(),
            niveau: hlb_api::NiveauAlerte::Critique,
            explication: "des applications n'ont JAMAIS été sauvegardées".into(),
            valeur: Some(4.0),
            seuil: 0.0,
            // Trois jours : une alerte qui dure a été ignorée, ou son remède ne marche
            // pas. Ça ne se traite pas comme une alerte qui vient d'apparaître.
            depuis_s: 3 * 86_400,
            silencee_jusqu_a: None,
            silencee_par: None,
        },
        hlb_api::AlerteActive {
            regle: "copie-unique".into(),
            niveau: hlb_api::NiveauAlerte::Critique,
            explication: "une application n'a plus qu'UNE copie à jour".into(),
            valeur: Some(1.0),
            seuil: 2.0,
            depuis_s: 9 * 3_600,
            silencee_jusqu_a: None,
            silencee_par: None,
        },
        hlb_api::AlerteActive {
            regle: "disque-plein".into(),
            niveau: hlb_api::NiveauAlerte::Important,
            explication: "un système de fichiers dépasse 85 % d'occupation".into(),
            valeur: Some(0.96),
            seuil: 0.85,
            depuis_s: 2 * 3_600,
            // 🔴 En sourdine, et qui doit RESTER visible : la faire disparaître
            // donnerait un tableau de bord vert pour un problème connu et non résolu.
            silencee_jusqu_a: Some(maintenant + 4 * 3_600),
            silencee_par: Some("remy".into()),
        },
        hlb_api::AlerteActive {
            regle: "verification-perimee".into(),
            niveau: hlb_api::NiveauAlerte::Inconnu,
            explication: "la règle ne peut plus être évaluée : plus de données".into(),
            // 🔴 Aucune valeur : on ne sait pas. Mettre 0 dirait « seuil respecté ».
            valeur: None,
            seuil: 31.0,
            depuis_s: 40 * 60,
            silencee_jusqu_a: None,
            silencee_par: None,
        },
    ]
}

/// Les nœuds tels qu'un agent les rapporterait.
///
/// Séparé de l'état parce que ces rapports ne vivent pas en base : ils sont en mémoire,
/// dans `LastPoll`, et c'est justement le partage boucle → API qu'on veut exercer.
pub fn noeuds(maintenant: u64) -> BTreeMap<String, AgentStatus> {
    let mut m = BTreeMap::new();

    m.insert(
        "10.0.0.1:8421".to_string(),
        AgentStatus::Reporting(Box::new(NodeReport {
            hostname: "swarm-heavy".into(),
            at: maintenant,
            disks: vec![
                disque("/", 500_000, 210_000),
                disque("/var/lib/docker", 200_000, 96_000),
            ],
            memory_total_mb: Some(16_384),
            memory_available_mb: Some(4_900),
            agent_version: "0.2.0".into(),
            protocol: 2,
            cpu_coeurs: Some(8),
            charge: Some(hlb_agent::systeme::Charge {
                une_min: 3.2,
                cinq_min: 2.8,
                quinze_min: 2.4,
            }),
            cpu_occupation: Some(0.41),
            swap_total_mb: Some(4_096),
            swap_utilise_mb: Some(120),
            interfaces: vec![hlb_agent::systeme::Interface {
                nom: "eth0".into(),
                rx_octets: 91_284_733_912,
                tx_octets: 42_119_884_004,
            }],
            systeme: Some(hlb_agent::systeme::Systeme {
                noyau: Some("6.1.0-18-amd64".into()),
                distro: Some("Debian GNU/Linux 12 (bookworm)".into()),
                uptime_s: Some(41 * 86_400),
            }),
        })),
    );

    // 🔴 Un nœud sous pression : /var/lib/docker à 96 %. Un `/` à moitié vide ne
    // console de rien — c'est le PIRE système de fichiers qui décide.
    m.insert(
        "10.0.0.2:8421".to_string(),
        AgentStatus::Reporting(Box::new(NodeReport {
            hostname: "small-01".into(),
            at: maintenant,
            disks: vec![
                disque("/", 100_000, 30_000),
                disque("/var/lib/docker", 50_000, 48_000),
            ],
            memory_total_mb: Some(4_096),
            memory_available_mb: Some(890),
            agent_version: "0.2.0".into(),
            protocol: 2,
            cpu_coeurs: Some(4),
            // 🔴 Charge par cœur supérieure à 1 : la machine est en surcharge.
            charge: Some(hlb_agent::systeme::Charge {
                une_min: 6.1,
                cinq_min: 5.4,
                quinze_min: 4.9,
            }),
            cpu_occupation: Some(0.93),
            swap_total_mb: Some(2_048),
            // 🔴 Le swap SERT : signal avant-coureur, la machine ralentit sans être
            // encore en panne. C'est le cas qu'il faut voir à l'écran.
            swap_utilise_mb: Some(1_450),
            interfaces: vec![hlb_agent::systeme::Interface {
                nom: "eth0".into(),
                rx_octets: 12_884_901_888,
                tx_octets: 3_221_225_472,
            }],
            systeme: Some(hlb_agent::systeme::Systeme {
                noyau: Some("6.1.0-18-arm64".into()),
                distro: Some("Debian GNU/Linux 12 (bookworm)".into()),
                // Redémarré il y a vingt minutes : ça explique souvent beaucoup, et
                // on n'y pense pas.
                uptime_s: Some(1_200),
            }),
        })),
    );

    // 🔴 Un nœud injoignable. Distinct d'un nœud sain : ses données ne sont plus
    // sauvegardées, et l'afficher comme « pas de problème signalé » serait le mensonge
    // que tout ce projet cherche à éviter.
    m.insert(
        "10.0.0.3:8421".to_string(),
        AgentStatus::Unreachable {
            detail: "connexion refusée (agent arrêté ?)".into(),
        },
    );

    // Un agent MUET depuis longtemps : il a répondu autrefois, plus depuis. Le rapport
    // existe donc, mais il est vieux — et c'est à l'interface de ne pas le faire passer
    // pour frais.
    m.insert(
        "10.0.0.4:8421".to_string(),
        AgentStatus::Reporting(Box::new(NodeReport {
            hostname: "small-02".into(),
            at: maintenant.saturating_sub(3_600),
            disks: vec![disque("/", 100_000, 19_000)],
            memory_total_mb: Some(4_096),
            memory_available_mb: Some(2_600),
            // ⚠️ Resté en protocole 1 : le parc dépareillé du §7bis. Ses mesures
            // système sont absentes — et doivent s'afficher « inconnu », pas « 0 % ».
            agent_version: "0.1.0".into(),
            protocol: 1,
            ..Default::default()
        })),
    );

    m
}

fn disque(path: &str, total_mb: u64, used_mb: u64) -> DiskUsage {
    DiskUsage {
        path: path.into(),
        total_mb,
        used_mb,
        free_mb: total_mb - used_mb,
    }
}

/// Un manifest de démonstration, aussi RICHE que ceux du catalogue.
///
/// 🔴 Un manifest minimal donnerait un écran de détail vide : ni capacités, ni volumes,
/// ni variables. On n'écrirait donc jamais l'affichage de ces sections — et ce sont
/// justement celles qui portent les pièges (un volume non sauvegardé, une base SQLite
/// qu'on ne peut pas copier à chaud, un jeton de secret qui doit rester littéral).
///
/// ⚠️ Rend un `Result` plutôt que de dépaqueter : `expect` est interdit en production
/// dans ce dépôt, et ce module en fait partie — il est compilé dans le binaire.
fn manifest(nom: &str) -> Result<hlb_types::Manifest, Box<dyn std::error::Error>> {
    let y = match nom {
        "gitea" => r#"
apiVersion: hlb/v1
kind: App
metadata: { name: gitea, displayName: Gitea, category: development }
spec:
  image: { repo: gitea/gitea, tag: "1.24" }
  requires:
    - kind: database
      engine: postgres
    - kind: sso
      mode: native
      redirectPaths: ["/user/oauth2/PocketID/callback"]
    - kind: storage
      name: data
      path: /data
      backup: true
  env:
    GITEA__database__DB_TYPE: postgres
    GITEA__database__HOST: "{{ db.host }}:{{ db.port }}"
    GITEA__database__NAME: "{{ db.name }}"
    GITEA__database__USER: "{{ db.user }}"
    GITEA__database__PASSWD: "{{ db.password }}"
    GITEA__server__ROOT_URL: "https://{{ domain }}/"
  ingress:
    - host: "{{ domain }}"
      port: 3000
      expose: after-guide
"#
        .to_string(),
        "immich" => r#"
apiVersion: hlb/v1
kind: App
metadata: { name: immich, displayName: Immich, category: media }
spec:
  image: { repo: ghcr.io/immich-app/immich-server, tag: "v1.119" }
  requires:
    - kind: database
      engine: postgres
      extensions: ["vector", "vchord"]
    - kind: object-storage
      bucket: immich
    - kind: storage
      name: cache
      path: /cache
      backup: false
  env:
    DB_HOSTNAME: "{{ db.host }}"
    DB_PASSWORD: "{{ db.password }}"
    S3_ACCESS_KEY: "{{ s3.access_key }}"
  ingress:
    - host: "{{ domain }}"
      port: 2283
      expose: private
"#
        .to_string(),
        "vaultwarden" => r#"
apiVersion: hlb/v1
kind: App
metadata: { name: vaultwarden, displayName: Vaultwarden, category: security }
spec:
  image: { repo: vaultwarden/server, tag: "1.32" }
  requires:
    - kind: storage
      name: data
      path: /data
      backup: true
      sqlite: true
    - kind: smtp
  env:
    DOMAIN: "https://{{ domain }}"
    SMTP_PASSWORD: "{{ smtp.password }}"
"#
        .to_string(),
        autre => format!(
            "apiVersion: hlb/v1\nkind: App\nmetadata: {{ name: {autre} }}\n\
             spec:\n  image: {{ repo: exemple/{autre}, tag: \"1.0\" }}\n"
        ),
    };
    Ok(serde_yaml_ng::from_str(&y)?)
}

/// Le parc réduit au tier et à la mémoire disponible, pour le budget de capacité.
///
/// 🔴 Cohérent avec `sondage()` et `topologie()` : `small-01` est la machine à 4 Go du
/// §2bis.4, dont il ne reste presque rien. C'est elle qui doit déclencher
/// l'avertissement, et pas une absence d'information.
pub fn parc_par_tier() -> Vec<(Option<String>, Option<u64>)> {
    vec![
        (Some("heavy".into()), Some(11_800)),
        (Some("light".into()), Some(890)),
        // Le nœud muet : le budget devient un minorant, et le dit.
        (Some("light".into()), None),
    ]
}

/// Les tâches Swarm d'une app, fabriquées pour la démonstration.
///
/// 🔴 Elles portent les cas qu'on n'a jamais sous la main au bon moment : l'échec dont
/// Swarm donne la raison, l'échec qu'il n'explique pas, et le service qui tourne à
/// moitié. C'est ce qui rend la chaîne causale visible sans cluster.
pub fn taches(app: &str) -> Vec<hlb_api::TacheSummary> {
    let t = |id: &str, noeud: &str, vivante: bool, err: Option<&str>| hlb_api::TacheSummary {
        id: id.into(),
        service: app.into(),
        slot: Some(1),
        noeud: Some(noeud.into()),
        etat: if vivante {
            "running".into()
        } else {
            "failed".into()
        },
        etat_voulu: "running".into(),
        vivante,
        echouee: !vivante,
        explication: err.map(str::to_string),
        image: None,
    };

    match app {
        // La chaîne complète : Swarm dit pourquoi, le nœud manque d'espace, la règle
        // l'a signalé.
        "n8n" => vec![t(
            "tk-n8n-1",
            // ⚠️ Le nœud SOUS PRESSION : c'est ce qui ferme la chaîne. Placer la tâche
            // sur une machine saine donnerait « cause inconnue », ce qui est le second
            // cas — porté par seafile juste en dessous.
            "small-01",
            false,
            Some("no space left on device"),
        )],
        // 🔴 L'échec que rien n'explique. C'est le cas que le diagnostic doit refuser
        // d'inventer : il s'arrête sur « cause inconnue » plutôt que d'accuser le
        // premier nœud venu.
        "seafile" => vec![t("tk-seafile-1", "swarm-heavy", false, Some("exit code 1"))],
        "immich" => vec![t("tk-immich-1", "swarm-heavy", true, None)],
        "gitea" => vec![
            t("tk-gitea-1", "swarm-heavy", true, None),
            t("tk-gitea-2", "mail-vm", true, None),
        ],
        _ => Vec::new(),
    }
}

/// Les écarts de réconciliation, fabriqués pour la démonstration.
///
/// 🔴 Sans orchestrateur, la boucle ne tourne pas — et l'écran qui rend les
/// non-actions lisibles serait vide, donc impossible à écrire. Les deux familles y
/// sont : ce qui sera corrigé, et ce qui a été délibérément laissé.
pub fn ecarts() -> Vec<hlb_api::EcartSummary> {
    use hlb_engine::reconcile::Drift;

    // ⚠️ On passe par les VRAIS `Drift` plutôt que d'écrire les phrases à la main : une
    // démonstration qui invente ses propres textes finit par montrer un écran que le
    // code ne produit jamais.
    [
        Drift::ReplicasDiverged {
            app: "vikunja".into(),
            desired: 2,
            actual: 1,
        },
        Drift::OrphanService {
            name: "vieux-nextcloud".into(),
        },
        Drift::Converging {
            app: "immich".into(),
            running: 1,
            desired: 2,
        },
    ]
    .iter()
    .map(|d| hlb_api::EcartSummary {
        cible: d.app().to_string(),
        description: d.to_string(),
        corrigible: d.is_correctable(),
        refus: d.refus().map(str::to_string),
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hlb_api::Attention;

    #[tokio::test]
    async fn the_demo_manifests_are_rich_enough_to_render_a_detail_screen() {
        // 🔴 Un manifest minimal donnerait un écran de détail VIDE : ni capacités, ni
        // variables. On n'écrirait donc jamais l'affichage de ces sections — et ce sont
        // celles qui portent les pièges.
        let s = State::in_memory().await.expect("état");
        peupler(&s).await.expect("peuplement");

        let m = s.app_manifest("gitea").await.expect("manifest");
        assert!(!m.spec.requires.is_empty(), "aucune capacité à afficher");
        assert!(!m.spec.env.is_empty(), "aucune variable à afficher");

        // Et les jetons de secret sont là, LITTÉRAUX : c'est ce que l'écran doit
        // montrer sans jamais les résoudre.
        assert!(
            m.spec.env.values().any(|v| v.contains("{{ db.password }}")),
            "aucun jeton de secret : l'affichage littéral ne serait pas exercé"
        );
    }

    #[tokio::test]
    async fn the_demo_has_an_unbacked_volume_and_a_sqlite_one() {
        // Les deux cas qui portent un piège : un volume qu'on croit protégé et qui ne
        // l'est pas, et une base SQLite qui ne peut pas être copiée à chaud.
        let s = State::in_memory().await.expect("état");
        peupler(&s).await.expect("peuplement");

        let immich = s.app_volumes("immich").await.expect("volumes");
        assert!(
            immich.iter().any(|(_, _, backup, _)| !backup),
            "aucun volume non sauvegardé"
        );

        let vw = s.app_volumes("vaultwarden").await.expect("volumes");
        assert!(
            vw.iter().any(|(_, _, _, sqlite)| *sqlite),
            "aucun volume SQLite"
        );
    }

    #[tokio::test]
    async fn the_demo_covers_every_attention_level() {
        // 🔴 Un jeu de données qui ne montre que des apps saines ne sert à rien : les
        // écrans qu'il faut vérifier sont ceux des cas qu'on n'a jamais sous la main.
        let s = State::in_memory().await.expect("état");
        peupler(&s).await.expect("peuplement");

        let apps = s.installed_apps().await.expect("apps");
        assert!(apps.len() >= 8);

        let mut vus = std::collections::BTreeSet::new();
        for (nom, statut) in &apps {
            let a = hlb_api::AppSummary {
                name: nom.clone(),
                status: statut.clone(),
                image: String::new(),
                domain: None,
                last_backup_secs: s.seconds_since_last_success(nom).await.expect("sauvegarde"),
                last_verification_secs: None,
                blocking_guides: s.unverified_blocking(nom).await.expect("guides") as i64,
            };
            vus.insert(a.attention());
        }

        for niveau in [Attention::Ok, Attention::Notice, Attention::Critical] {
            assert!(
                vus.contains(&niveau),
                "le jeu de démonstration n'a aucun cas {niveau:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_demo_shows_all_three_causes_of_a_critical_app() {
        // 🔴 « Critical » recouvre trois situations qui se réparent différemment :
        // jamais sauvegardée, sauvegarde périmée, service en échec. Un jeu qui n'en
        // montrerait qu'une laisserait les deux autres affichages non vérifiés.
        let s = State::in_memory().await.expect("état");
        peupler(&s).await.expect("peuplement");

        assert_eq!(
            s.seconds_since_last_success("seafile")
                .await
                .expect("jamais"),
            None,
            "aucun cas « jamais sauvegardée »"
        );
        assert!(
            s.seconds_since_last_success("vikunja")
                .await
                .expect("périmée")
                .unwrap_or(0)
                > 86_400,
            "aucun cas « sauvegarde périmée »"
        );
        assert!(
            s.installed_apps()
                .await
                .expect("apps")
                .iter()
                .any(|(_, st)| st == "failed"),
            "aucun cas « service en échec »"
        );
    }

    #[tokio::test]
    async fn the_demo_shows_a_fresh_destination_masking_a_dead_one() {
        // Le piège du §8.1 : `MAX(finished_at)` sur toutes les destinations fait passer
        // un hors-site mort depuis des semaines pour une sauvegarde de deux heures.
        let s = State::in_memory().await.expect("état");
        peupler(&s).await.expect("peuplement");

        assert!(
            s.seconds_since_last_success_on("immich", "nas")
                .await
                .expect("nas")
                .is_some(),
            "le NAS a reçu"
        );
        assert_eq!(
            s.seconds_since_last_success_on("immich", "offsite")
                .await
                .expect("offsite"),
            None,
            "le hors-site n'a JAMAIS rien reçu, et ça doit se voir"
        );
        assert!(
            s.consecutive_failures_on("immich", "offsite")
                .await
                .expect("échecs")
                >= 4,
            "les échecs répétés doivent se voir avant le seuil de péremption"
        );
    }

    #[tokio::test]
    async fn the_demo_has_an_app_that_looks_healthy_and_is_not() {
        // Le pire état du système : l'app tourne et n'a AUCUNE sauvegarde. C'est celui
        // qui paraît le plus sain, donc celui que l'affichage doit attraper.
        let s = State::in_memory().await.expect("état");
        peupler(&s).await.expect("peuplement");

        assert_eq!(
            s.seconds_since_last_success("seafile")
                .await
                .expect("sauvegarde"),
            None
        );
    }

    #[tokio::test]
    async fn the_demo_has_a_half_created_account_in_both_directions() {
        // Identité sans boîte ET boîte sans identité : les deux moitiés se voient
        // différemment et se réparent différemment.
        let s = State::in_memory().await.expect("état");
        peupler(&s).await.expect("peuplement");

        use hlb_users::Coherence;
        assert_eq!(
            s.compte("remy").await.expect("compte").coherence(),
            Coherence::Complet
        );
        assert_eq!(
            s.compte("dominique").await.expect("compte").coherence(),
            Coherence::SansBoite
        );
        assert_eq!(
            s.compte("sacha").await.expect("compte").coherence(),
            Coherence::SansIdentite
        );
    }

    #[tokio::test]
    async fn the_demo_has_an_expired_alias_that_still_receives() {
        // 🔴 Le troisième état, celui qui n'existe que parce qu'un serveur mail ne sait
        // pas expirer un alias : expiré, et TOUJOURS actif.
        let s = State::in_memory().await.expect("état");
        peupler(&s).await.expect("peuplement");

        let c = s.compte("remy").await.expect("compte");
        let rompues = c.promesses_rompues(crate::auth::maintenant());
        assert!(!rompues.is_empty(), "aucun alias ne trahit sa promesse");
        assert!(rompues
            .iter()
            .any(|(_, a)| a.local.starts_with("newsletter")));
    }

    #[tokio::test]
    async fn the_demo_distinguishes_no_folder_from_no_sorting() {
        // `NULL` = rien n'a été décidé (on propose un défaut) ; `""` = je ne VEUX pas
        // de tri. Les confondre réimpose un dossier à chaque régénération.
        let s = State::in_memory().await.expect("état");
        peupler(&s).await.expect("peuplement");

        let regles = s.alias_rules("remy", "remy").await.expect("règles");
        let dossier = |alias: &str| {
            regles
                .iter()
                .find(|(a, ..)| a.starts_with(alias))
                .map(|(_, d, _)| d.clone())
                .expect("alias présent")
        };
        assert_eq!(dossier("impots").as_deref(), Some("Administratif/Impôts"));
        assert_eq!(
            dossier("concours").as_deref(),
            Some(""),
            "refus explicite de trier"
        );
        assert_eq!(dossier("newsletter"), None, "rien décidé");
    }

    #[test]
    fn the_demo_has_a_node_still_speaking_the_old_protocol() {
        // 🔴 Le parc dépareillé du §7bis : c'est l'état NORMAL pendant une mise à jour.
        // Sans lui dans le jeu de démonstration, on n'écrirait jamais l'affichage
        // « mesure inconnue » — et un `0 %` finirait par s'y glisser.
        let n = noeuds(1_000_000);
        let ancien = n
            .values()
            .filter_map(|s| s.report())
            .find(|r| r.protocol < 2)
            .expect("aucun agent de protocole 1");
        assert_eq!(ancien.cpu_occupation, None);
        assert!(ancien.interfaces.is_empty());
        // Mais ce qu'il envoie reste exploitable.
        assert!(ancien.memoire_utilisee().is_some());
    }

    #[test]
    fn the_demo_shows_a_machine_that_has_started_swapping() {
        // Un swap qui sert est un signal AVANT la panne : la machine ralentit sans
        // être encore tombée. C'est le cas qu'on veut pouvoir regarder à l'écran.
        let n = noeuds(1_000_000);
        assert!(
            n.values()
                .filter_map(|s| s.report())
                .any(|r| r.echange_sur_disque()),
            "aucun nœud n'échange sur disque"
        );
    }

    #[test]
    fn the_demo_shows_a_machine_over_one_load_per_core() {
        // Le seul chiffre comparable entre machines hétérogènes.
        let n = noeuds(1_000_000);
        let surcharge = n
            .values()
            .filter_map(|s| s.report())
            .filter_map(|r| r.charge_par_coeur())
            .any(|c| c > 1.0);
        assert!(surcharge, "aucun nœud en surcharge");
    }

    #[test]
    fn the_demo_topology_contains_the_trap_it_exists_to_show() {
        // 🔴 Sans deux VM sur un même fer, l'écran qui justifie l'existence de
        // l'interface n'aurait rien à montrer — et on ne saurait pas s'il le montre
        // bien.
        let t = topologie();
        assert_eq!(t.attention(), hlb_api::Attention::Critical);
        assert!(t.verdict().contains("illusion"), "{}", t.verdict());

        let concentre = t
            .domaines
            .iter()
            .find(|d| d.concentre)
            .expect("aucun domaine concentré");
        assert!(
            concentre.noeuds.len() >= 2,
            "un fer doit porter plusieurs nœuds"
        );

        assert!(
            t.domaines.iter().any(|d| d.nom.is_none()),
            "aucun domaine non déclaré : le cas « on ne sait pas » ne serait pas affiché"
        );
        assert!(
            t.domaines
                .iter()
                .flat_map(|d| &d.noeuds)
                .any(|n| !n.joignable),
            "aucun nœud injoignable dans la topologie"
        );
    }

    #[tokio::test]
    async fn the_demo_has_a_followed_incident() {
        // 🔴 Un incident sans son fil ne montrerait pas ce qui fait la valeur du
        // système : la chronologie qu'on relit après coup.
        let s = State::in_memory().await.expect("état");
        peupler(&s).await.expect("peuplement");

        let v = s
            .annonces(hlb_types::Role::Admin, crate::auth::maintenant(), false)
            .await
            .expect("annonces");
        let incident = v
            .iter()
            .find(|a| a.incident_ouvert())
            .expect("aucun incident ouvert");
        assert!(incident.suivi.len() >= 2, "un incident sans fil de suivi");
        assert_ne!(
            incident.derniere_nouvelle(),
            incident.corps,
            "la dernière nouvelle doit différer du message d'origine"
        );
    }

    #[tokio::test]
    async fn the_demo_shows_the_portal_filtering_at_work() {
        // ⚠️ Sans annonce réservée à l'exploitation, on n'écrirait jamais l'affichage
        // filtré — et une annonce de maintenance finirait sur le portail.
        let s = State::in_memory().await.expect("état");
        peupler(&s).await.expect("peuplement");
        let now = crate::auth::maintenant();

        let portail = s
            .annonces(hlb_types::Role::User, now, false)
            .await
            .expect("annonces");
        let admin = s
            .annonces(hlb_types::Role::Admin, now, false)
            .await
            .expect("annonces");

        assert!(
            admin.len() > portail.len(),
            "aucune annonce réservée : le filtrage ne serait pas exercé"
        );
    }

    #[tokio::test]
    async fn the_demo_keeps_an_expired_announcement_in_the_record() {
        let s = State::in_memory().await.expect("état");
        peupler(&s).await.expect("peuplement");
        let now = crate::auth::maintenant();

        let actives = s
            .annonces(hlb_types::Role::Admin, now, false)
            .await
            .expect("a");
        let toutes = s
            .annonces(hlb_types::Role::Admin, now, true)
            .await
            .expect("a");
        assert!(
            toutes.len() > actives.len(),
            "aucune annonce expirée à l'historique"
        );
    }

    #[test]
    fn the_demo_alerts_cover_every_display_case() {
        // 🔴 Chacun s'affiche différemment, et chacun est celui qu'on ne verra pas le
        // jour venu s'il est mal rendu.
        let a = alertes(1_000_000);

        assert!(a
            .iter()
            .any(|x| x.niveau == hlb_api::NiveauAlerte::Critique));
        assert!(a
            .iter()
            .any(|x| x.niveau == hlb_api::NiveauAlerte::Important));
        assert!(
            a.iter().any(|x| x.niveau == hlb_api::NiveauAlerte::Inconnu),
            "« non évaluable » manque : c'est le cas qu'on confond avec « tout va bien »"
        );
        assert!(
            a.iter().any(|x| x.est_silencee(1_000_000)),
            "aucune alerte en sourdine : l'affichage correspondant ne serait jamais écrit"
        );
        // Une alerte non évaluable n'a PAS de valeur : mettre 0 dirait « seuil
        // respecté », soit exactement le contraire.
        let inconnue = a
            .iter()
            .find(|x| x.niveau == hlb_api::NiveauAlerte::Inconnu)
            .expect("une inconnue");
        assert_eq!(inconnue.valeur, None);
    }

    #[test]
    fn a_demo_silenced_alert_still_shows_its_reason() {
        let a = alertes(1_000_000);
        let silencee = a
            .iter()
            .find(|x| x.est_silencee(1_000_000))
            .expect("une alerte en sourdine");
        let l = silencee.libelle(1_000_000);
        assert!(l.contains("SOURDINE"), "{l}");
        assert!(l.contains("remy"), "qui l'a silencée doit se voir : {l}");
    }

    #[test]
    fn the_demo_nodes_cover_reachable_saturated_and_silent() {
        let n = noeuds(1_000_000);
        assert_eq!(n.len(), 4);

        let seuils = hlb_agent::disk::Thresholds::default();
        let sature = n
            .values()
            .filter_map(|s| s.report())
            .any(|r| !r.allows_deploy(&seuils));
        assert!(
            sature,
            "aucun nœud sous pression : le cas critique n'est pas montré"
        );

        let injoignable = n
            .values()
            .any(|s| matches!(s, AgentStatus::Unreachable { .. }));
        assert!(injoignable, "un nœud injoignable n'est pas un nœud sain");

        let muet = n
            .values()
            .filter_map(|s| s.report())
            .any(|r| r.is_stale(1_000_000, 120));
        assert!(muet, "un agent muet doit être représenté");
    }
}
