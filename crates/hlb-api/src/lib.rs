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

use serde::{Deserialize, Serialize};

/// L'état de santé du controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
}

/// Une app installée, vue du tableau de bord.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuideItem {
    pub app: String,
    pub id: String,
    pub title: String,
    /// Bloque le déploiement tant qu'elle n'est pas faite.
    pub blocking: bool,
}

/// Une entrée du journal d'audit (§9).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditItem {
    pub at: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretItem {
    pub name: String,
    pub purpose: String,
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
        assert_eq!(app("running", Some(90_000), 0).attention(), Attention::Critical);
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
            at: "2026-08-16".into(),
            actor: "cli".into(),
            action: "update".into(),
            target: "gitea".into(),
            outcome: "refused".into(),
        };
        assert!(refus.is_refusal());
        assert!(!refus.is_failure());
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
