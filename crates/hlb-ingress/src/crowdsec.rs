//! Enrôlement du videur CrowdSec (§8bis).
//!
//! ## Pourquoi une étape à part
//!
//! Le Caddyfile a besoin d'une clé de videur (`bouncer`) que **seul CrowdSec peut
//! produire**, via `cscli bouncers add`. On ne peut ni l'inventer ni la deviner : elle
//! est générée par le moteur de décision et enregistrée dans sa base.
//!
//! Elle n'est affichée **qu'une fois**, à la création. La perdre oblige à supprimer le
//! videur et à en réenrôler un — d'où le stockage au coffre dès l'obtention, comme
//! pour les secrets OIDC (§5.2).
//!
//! ## 🔴 Un videur enrôlé ne protège rien tant que Caddy ne l'utilise pas
//!
//! Les deux moitiés sont indépendantes et leur asymétrie est piégeuse :
//!
//! - CrowdSec qui tourne sans videur **détecte** les attaques et n'en **bloque**
//!   aucune. Les journaux se remplissent d'alertes, le tableau de bord est vert, et
//!   personne n'est jamais banni.
//! - Un Caddy configuré avec une clé invalide **échoue à démarrer**, ce qui est
//!   bruyant et donc préférable.
//!
//! Le premier cas est le dangereux. `status` existe pour le rendre visible.

use crate::{Error, Result};

/// Le nom sous lequel le videur est enregistré dans CrowdSec.
///
/// Stable et unique : réenrôler sous le même nom échoue, ce qui est voulu — deux
/// videurs pour un seul Caddy rendraient impossible de savoir lequel est en service.
pub const BOUNCER_NAME: &str = "hlb-caddy-front";

/// Nom du secret au coffre.
pub const SECRET_NAME: &str = "crowdsec-bouncer-key";

/// Comment joindre `cscli`.
///
/// CrowdSec tourne dans un conteneur ; `cscli` n'existe pas sur l'hôte. On l'exécute
/// donc là où il se trouve.
#[derive(Debug, Clone)]
pub struct Cscli {
    /// Nom du service Swarm portant CrowdSec.
    pub service: String,
}

impl Default for Cscli {
    fn default() -> Self {
        Self { service: "crowdsec".into() }
    }
}

impl Cscli {
    pub fn new(service: impl Into<String>) -> Self {
        Self { service: service.into() }
    }

    /// Retrouve le conteneur CrowdSec sur cette machine.
    ///
    /// ⚠️ En Swarm, le nom du conteneur porte un suffixe aléatoire
    /// (`crowdsec.1.x7k9…`) : filtrer sur le nom exact ne trouverait rien. C'est
    /// l'étiquette posée par Swarm qui est stable.
    pub async fn container(&self) -> Result<String> {
        let par_etiquette = self
            .docker(&[
                "ps",
                "--filter",
                &format!("label=com.docker.swarm.service.name={}", self.service),
                "--format",
                "{{.ID}}",
            ])
            .await?;

        if let Some(id) = par_etiquette.lines().next().filter(|l| !l.is_empty()) {
            return Ok(id.to_string());
        }

        // Hors Swarm (docker run, compose), l'étiquette n'existe pas.
        let par_nom = self
            .docker(&["ps", "--filter", &format!("name={}", self.service), "--format", "{{.ID}}"])
            .await?;

        par_nom
            .lines()
            .next()
            .filter(|l| !l.is_empty())
            .map(|s| s.to_string())
            .ok_or_else(|| Error::CrowdSec(format!(
                "aucun conteneur CrowdSec en fonctionnement (service « {} »)",
                self.service
            )))
    }

    /// Enrôle le videur et renvoie sa clé.
    ///
    /// `-o raw` : sans lui, `cscli` encadre la clé de texte décoratif qu'il faudrait
    /// découper — et le format de ce texte change d'une version à l'autre.
    pub async fn enroll(&self) -> Result<String> {
        let c = self.container().await?;
        let out = self
            .docker(&["exec", &c, "cscli", "bouncers", "add", BOUNCER_NAME, "-o", "raw"])
            .await?;

        let cle = out.trim().lines().next_back().unwrap_or("").trim().to_string();
        if cle.is_empty() {
            return Err(Error::CrowdSec(
                "cscli n'a renvoyé aucune clé — le videur existe peut-être déjà ; \
                 supprime-le (cscli bouncers delete) ou récupère sa clé"
                    .into(),
            ));
        }
        Ok(cle)
    }

    /// Le videur est-il enregistré côté CrowdSec ?
    pub async fn is_enrolled(&self) -> Result<bool> {
        let c = self.container().await?;
        let out = self
            .docker(&["exec", &c, "cscli", "bouncers", "list", "-o", "raw"])
            .await?;
        Ok(out.lines().any(|l| l.split(',').next() == Some(BOUNCER_NAME)))
    }

    async fn docker(&self, args: &[&str]) -> Result<String> {
        let out = tokio::process::Command::new("docker")
            .args(args)
            .output()
            .await
            .map_err(|e| Error::CrowdSec(format!("docker introuvable : {e}")))?;

        if !out.status.success() {
            return Err(Error::CrowdSec(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }
}

/// Une clé de videur plausible ?
///
/// 🔴 Le vrai danger : une clé vide ou tronquée produit un Caddyfile **syntaxiquement
/// valide**. Caddy démarre, le videur s'authentifie mal, et plus rien n'est bloqué —
/// sans la moindre erreur visible. Mieux vaut refuser de générer la configuration.
pub fn looks_like_key(k: &str) -> bool {
    let k = k.trim();
    k.len() >= 16 && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plausible_key_is_accepted() {
        assert!(looks_like_key("K7xQ2mNpR4vL8wZa1bC3dE5f"));
        assert!(looks_like_key("abcdefghijklmnop"));
    }

    #[test]
    fn an_empty_or_short_key_is_refused() {
        // 🔴 Une clé vide donne un Caddyfile valide, un Caddy qui démarre, et plus
        // aucun bannissement — sans erreur nulle part.
        assert!(!looks_like_key(""));
        assert!(!looks_like_key("   "));
        assert!(!looks_like_key("trop-court"));
    }

    #[test]
    fn decorative_output_is_refused() {
        // Sans `-o raw`, cscli encadre la clé de texte. Si ça passait, la « clé »
        // serait une phrase.
        assert!(!looks_like_key("Api key for 'hlb-caddy-front': abc123"));
        assert!(!looks_like_key("K7xQ2mNpR4vL8wZa\nautre ligne"));
    }

    #[test]
    fn the_bouncer_name_is_stable() {
        // Réenrôler sous un nom différent laisserait deux videurs déclarés, sans
        // savoir lequel est réellement en service.
        assert_eq!(BOUNCER_NAME, "hlb-caddy-front");
    }
}
