//! La rotation des secrets, assistée (lot 10.1, §9quater).
//!
//! ## 🔴 Le piège que ce module existe pour nommer
//!
//! Le coffre n'est **pas** la source de vérité d'un mot de passe de base. Le tourner
//! dans le coffre ne change rien : PostgreSQL garde l'ancien, le conteneur garde
//! l'ancien dans son environnement, et tout continue de marcher — jusqu'au prochain
//! redéploiement, où l'app se met à échouer sur « mot de passe incorrect » sans que
//! personne ne fasse le lien avec une rotation d'il y a trois semaines.
//!
//! Une rotation est donc une **procédure ordonnée**, pas une écriture. Ce module dit
//! laquelle, pour chaque nature de secret, et refuse de traiter tous les secrets pareil.
//!
//! ## Ce qui décide, c'est l'usage, pas le nom
//!
//! Un secret injecté dans l'environnement d'une app exige un redéploiement ; un secret
//! relu à chaque usage n'en demande pas. Confondre les deux fait laisser tourner une app
//! sur une valeur périmée en croyant l'avoir tournée.

use serde::{Deserialize, Serialize};

/// Ce qu'un secret est, du point de vue de sa rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Nature {
    /// Mot de passe d'un rôle de base : vit dans PostgreSQL **et** dans le coffre.
    MotDePasseBase,
    /// Secret de client OIDC : vit dans PocketID **et** dans le coffre.
    ClientOidc,
    /// Clé d'accès S3 : Garage ne redonne jamais la clé secrète.
    CleObjet,
    /// Mot de passe IMAP/SMTP : vit chez Stalwart **et** dans le coffre.
    MotDePasseMail,
    /// Passphrase d'un dépôt restic. 🔴 La perdre rend les sauvegardes illisibles.
    PassphraseDepot,
    /// Clé d'API d'un service tiers, relue à chaque usage.
    CleApi,
    /// Identifiants d'une destination de sauvegarde (`backup-dest-<nom>`).
    ///
    /// 🔴 N'appartient à aucune app : rien à redéployer. Mais une rotation ratée ne se
    /// voit qu'à la prochaine sauvegarde, sur une « signature invalide » qui n'oriente
    /// vers rien.
    IdentifiantsDestination,
    /// Mot de passe d'un cache Valkey, injecté dans l'environnement de l'app.
    MotDePasseCache,
    /// On ne sait pas : on ne devine pas de procédure.
    Inconnue,
}

impl Nature {
    /// Déduite du nom et de l'usage enregistrés.
    ///
    /// ⚠️ `Inconnue` est un résultat légitime : inventer une procédure pour un secret
    /// qu'on ne reconnaît pas ferait exécuter les mauvais gestes dans le mauvais ordre.
    pub fn deduire(nom: &str, usage: &str) -> Self {
        let n = nom.to_ascii_lowercase();
        let u = usage.to_ascii_lowercase();

        // ⚠️ Les suffixes viennent des noms que le RÉSOLVEUR produit réellement
        // (`hlb-resolver`), pas d'une convention supposée. Une nature déduite d'un nom
        // qui n'existe pas ne se déclencherait jamais, et l'écran resterait
        // silencieux sur les secrets qui comptent le plus.
        if n.ends_with("-db-password") || u.contains("mot de passe postgresql") {
            Self::MotDePasseBase
        } else if n.ends_with("-oidc-secret") || u.contains("client oidc") {
            Self::ClientOidc
        } else if n.ends_with("-s3-secret") || u.contains("clé secrète s3") {
            Self::CleObjet
        } else if n.ends_with("-mail-password")
            || n.ends_with("-smtp-password")
            || u.contains("imap")
        {
            Self::MotDePasseMail
        } else if n.ends_with("-cache-password") {
            Self::MotDePasseCache
        } else if n.starts_with("backup-dest-") || u.contains("identifiants s3") {
            Self::IdentifiantsDestination
        } else if u.contains("chiffrement du dépôt") {
            Self::PassphraseDepot
        } else if u.contains("clé d'api") || n.contains("crowdsec") {
            Self::CleApi
        } else {
            Self::Inconnue
        }
    }

    /// Tourner ce secret impose-t-il de redéployer l'app qui l'utilise ?
    ///
    /// 🔴 C'est LA question. Un mot de passe de base tourné sans redéploiement casse
    /// l'app en silence : elle se plaint d'un mot de passe incorrect, et l'on cherche du
    /// côté du mot de passe alors que le problème est qu'elle a l'ancien.
    pub fn exige_redeploiement(&self) -> bool {
        match self {
            Self::MotDePasseBase
            | Self::ClientOidc
            | Self::CleObjet
            | Self::MotDePasseMail
            | Self::MotDePasseCache => true,
            // Relue à chaque usage, ou n'appartenant à aucune app.
            Self::CleApi | Self::PassphraseDepot | Self::IdentifiantsDestination => false,
            // ⚠️ On ne SAIT pas : on répond « oui » parce que redéployer inutilement
            // coûte une interruption de quelques secondes, tandis que ne pas redéployer
            // quand il le fallait casse l'app sans le dire.
            Self::Inconnue => true,
        }
    }

    /// La procédure, dans l'ordre. Vide quand on ne sait pas.
    pub fn procedure(&self) -> Vec<&'static str> {
        match self {
            Self::MotDePasseBase => vec![
                "changer le mot de passe DANS PostgreSQL (ALTER ROLE … PASSWORD)",
                "écrire la nouvelle valeur au coffre",
                "redéployer l'app pour qu'elle reçoive la nouvelle variable",
            ],
            Self::ClientOidc => vec![
                "régénérer le secret client DANS PocketID",
                "écrire la nouvelle valeur au coffre",
                "redéployer l'app",
            ],
            Self::CleObjet => vec![
                "créer une NOUVELLE clé dans Garage (l'ancienne reste valide)",
                "écrire la nouvelle valeur au coffre — Garage ne la redonnera jamais",
                "redéployer l'app",
                "supprimer l'ancienne clé SEULEMENT après avoir vu l'app fonctionner",
            ],
            Self::MotDePasseMail => vec![
                "changer le mot de passe chez Stalwart",
                "écrire la nouvelle valeur au coffre",
                "redéployer l'app, et reconfigurer les clients de messagerie",
            ],
            Self::PassphraseDepot => vec![
                "NE PAS tourner sans avoir d'abord vérifié une restauration",
                "ajouter la nouvelle clé au dépôt restic (restic key add)",
                "écrire la nouvelle valeur au coffre",
                "retirer l'ancienne clé du dépôt seulement après un exercice réussi",
            ],
            Self::MotDePasseCache => vec![
                "changer le mot de passe DANS Valkey",
                "écrire la nouvelle valeur au coffre",
                "redéployer l'app — sinon elle garde l'ancien dans son environnement",
            ],
            Self::IdentifiantsDestination => vec![
                "créer une nouvelle clé chez le fournisseur S3",
                "écrire la nouvelle valeur au coffre",
                "lancer une sauvegarde et VÉRIFIER qu'elle réussit : une rotation ratée \
                 ne se voit qu'ici, sur une « signature invalide »",
                "révoquer l'ancienne clé une fois la sauvegarde passée",
            ],
            Self::CleApi => vec![
                "générer la nouvelle clé chez le fournisseur",
                "écrire la nouvelle valeur au coffre",
                "recharger la configuration qui la lit",
            ],
            Self::Inconnue => Vec::new(),
        }
    }

    pub fn libelle(&self) -> &'static str {
        match self {
            Self::MotDePasseBase => "mot de passe de base",
            Self::ClientOidc => "secret de client OIDC",
            Self::CleObjet => "clé de stockage objet",
            Self::MotDePasseMail => "mot de passe de messagerie",
            Self::PassphraseDepot => "passphrase de dépôt de sauvegarde",
            Self::CleApi => "clé d'API",
            Self::MotDePasseCache => "mot de passe de cache",
            Self::IdentifiantsDestination => "identifiants de destination de sauvegarde",
            Self::Inconnue => "nature inconnue",
        }
    }
}

/// Un secret et ce que sa rotation impliquerait.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretARouler {
    pub nom: String,
    pub usage: String,
    pub nature: Nature,
    /// Âge depuis la dernière rotation — ou depuis la création si jamais tourné.
    pub age_s: i64,
    /// Vrai si le secret n'a JAMAIS été tourné depuis sa création.
    pub jamais_tourne: bool,
    /// L'app à redéployer, quand on sait la déduire du nom.
    #[serde(default)]
    pub app: Option<String>,
}

/// Au-delà, on propose la rotation (§9quater : une fois par an au moins).
pub const AGE_CONSEILLE_S: i64 = 365 * 86_400;

impl SecretARouler {
    pub fn attention(&self) -> crate::Attention {
        if self.age_s > 2 * AGE_CONSEILLE_S {
            crate::Attention::Critical
        } else if self.age_s > AGE_CONSEILLE_S {
            crate::Attention::Notice
        } else {
            crate::Attention::Ok
        }
    }

    /// Ce que la rotation impliquerait, en une phrase.
    pub fn consequence(&self) -> String {
        match (self.nature.exige_redeploiement(), &self.app) {
            (true, Some(app)) => format!(
                "Tourner ce secret IMPOSE de redéployer {app} : sans redéploiement, \
                 l'app garde l'ancienne valeur et échoue sans dire pourquoi."
            ),
            (true, None) => "Tourner ce secret impose de redéployer ce qui l'utilise : \
                             sans redéploiement, l'ancienne valeur reste en place."
                .to_string(),
            (false, _) => "Ce secret est relu à chaque usage : un rechargement de configuration \
                 suffit."
                .to_string(),
        }
    }
}

/// L'app propriétaire d'un secret, déduite de son nom (`gitea-db-password`).
///
/// ⚠️ Rend `None` plutôt que de deviner : nommer la mauvaise app ferait redéployer un
/// service qui n'avait rien à voir, pendant qu'on croirait la rotation terminée.
pub fn app_de(nom: &str) -> Option<String> {
    for suffixe in [
        "-db-password",
        "-oidc-secret",
        "-oidc-client-id",
        "-s3-secret",
        "-mail-password",
        "-smtp-password",
        "-cache-password",
    ] {
        if let Some(app) = nom.strip_suffix(suffixe) {
            return (!app.is_empty()).then(|| app.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_database_password_can_never_be_rotated_in_the_vault_alone() {
        // 🔴 Le piège central : le coffre n'est pas la source de vérité. La procédure
        // commence DANS PostgreSQL, et finit par un redéploiement.
        let n = Nature::deduire("gitea-db-password", "secret généré");
        assert_eq!(n, Nature::MotDePasseBase);
        assert!(n.exige_redeploiement());

        let p = n.procedure();
        assert!(p[0].contains("DANS PostgreSQL"), "{p:?}");
        assert!(p.last().is_some_and(|d| d.contains("redéployer")), "{p:?}");
    }

    #[test]
    fn an_object_key_is_replaced_before_the_old_one_is_removed() {
        // ⚠️ Garage ne redonne JAMAIS une clé secrète. Supprimer l'ancienne avant
        // d'avoir vu la nouvelle fonctionner laisse l'app sans aucun accès, et sans
        // moyen de revenir en arrière.
        let p = Nature::CleObjet.procedure();
        let creation = p
            .iter()
            .position(|e| e.contains("NOUVELLE"))
            .expect("création");
        let suppression = p
            .iter()
            .position(|e| e.contains("supprimer l'ancienne"))
            .expect("suppression");
        assert!(creation < suppression, "{p:?}");
        assert!(p[suppression].contains("après"), "{p:?}");
    }

    #[test]
    fn a_repository_passphrase_is_the_one_that_must_not_be_lost() {
        // La tourner sans avoir vérifié une restauration peut rendre TOUTES les
        // sauvegardes illisibles. C'est le seul cas où la première étape est un refus.
        let p = Nature::PassphraseDepot.procedure();
        assert!(p[0].contains("NE PAS tourner"), "{p:?}");
        // Et elle n'appartient à aucune app : rien à redéployer.
        assert!(!Nature::PassphraseDepot.exige_redeploiement());
    }

    #[test]
    fn an_unknown_secret_gets_no_invented_procedure() {
        // 🔴 Inventer des gestes pour un secret qu'on ne reconnaît pas les ferait
        // exécuter dans le mauvais ordre, sur le mauvais système.
        let n = Nature::deduire("truc-bizarre", "");
        assert_eq!(n, Nature::Inconnue);
        assert!(n.procedure().is_empty());
        // Mais on suppose le pire : redéployer pour rien coûte quelques secondes,
        // l'oublier casse l'app en silence.
        assert!(n.exige_redeploiement());
    }

    #[test]
    fn every_name_the_resolver_produces_is_recognised() {
        // 🔴 Constaté en regardant la sortie : deux secrets tombaient en « nature
        // inconnue » parce que mes suffixes étaient devinés. Une règle qui ne
        // correspond à aucun nom réel ne se déclenche jamais, et l'écran reste muet sur
        // exactement les secrets qui comptent.
        //
        // Ces noms viennent de `hlb-resolver` et `hlb-backup`.
        for (nom, usage, attendu) in [
            ("gitea-db-password", "secret généré", Nature::MotDePasseBase),
            (
                "gitea-oidc-secret",
                "client secret OIDC",
                Nature::ClientOidc,
            ),
            ("immich-s3-secret", "clé secrète S3", Nature::CleObjet),
            (
                "remy-smtp-password",
                "mot de passe IMAP/SMTP",
                Nature::MotDePasseMail,
            ),
            (
                "seafile-cache-password",
                "secret généré",
                Nature::MotDePasseCache,
            ),
            (
                "backup-dest-offsite",
                "identifiants S3 du hors-site",
                Nature::IdentifiantsDestination,
            ),
            (
                "restic-repo-password",
                "chiffrement du dépôt",
                Nature::PassphraseDepot,
            ),
        ] {
            assert_eq!(Nature::deduire(nom, usage), attendu, "{nom}");
        }
    }

    #[test]
    fn a_destination_rotation_is_verified_before_the_old_key_dies() {
        // ⚠️ Une rotation ratée ne se voit qu'à la sauvegarde suivante, sur une
        // « signature invalide » qui n'oriente vers rien. Révoquer l'ancienne clé avant
        // d'avoir vu une sauvegarde passer laisse le hors-site muet sans le savoir.
        let p = Nature::IdentifiantsDestination.procedure();
        let verif = p
            .iter()
            .position(|e| e.contains("VÉRIFIER"))
            .expect("vérification");
        let revoc = p
            .iter()
            .position(|e| e.contains("révoquer"))
            .expect("révocation");
        assert!(verif < revoc, "{p:?}");
        // Et rien à redéployer : aucune app ne porte ces identifiants.
        assert!(!Nature::IdentifiantsDestination.exige_redeploiement());
    }

    #[test]
    fn the_owning_app_is_deduced_or_left_unknown() {
        assert_eq!(app_de("gitea-db-password").as_deref(), Some("gitea"));
        assert_eq!(app_de("immich-s3-secret").as_deref(), Some("immich"));
        // ⚠️ Aucune supposition : nommer la mauvaise app ferait redéployer un service
        // qui n'a rien à voir, en croyant la rotation terminée.
        assert_eq!(app_de("restic-repo-passphrase"), None);
        assert_eq!(app_de("-db-password"), None);
    }

    #[test]
    fn a_secret_that_needs_a_redeploy_says_which_app() {
        let s = SecretARouler {
            nom: "gitea-db-password".into(),
            usage: "secret généré".into(),
            nature: Nature::MotDePasseBase,
            age_s: 400 * 86_400,
            jamais_tourne: true,
            app: Some("gitea".into()),
        };
        assert!(
            s.consequence().contains("redéployer gitea"),
            "{}",
            s.consequence()
        );
        assert_eq!(s.attention(), crate::Attention::Notice);
    }

    #[test]
    fn a_reloadable_secret_does_not_claim_a_redeploy() {
        // Dire « il faut redéployer » quand ce n'est pas vrai fait interrompre un
        // service pour rien — et à la longue, on cesse de croire l'écran.
        let s = SecretARouler {
            nom: "crowdsec-bouncer-key".into(),
            usage: "clé d'API".into(),
            nature: Nature::CleApi,
            age_s: 10 * 86_400,
            jamais_tourne: true,
            app: None,
        };
        assert!(
            s.consequence().contains("rechargement"),
            "{}",
            s.consequence()
        );
        assert_eq!(s.attention(), crate::Attention::Ok);
    }
}
