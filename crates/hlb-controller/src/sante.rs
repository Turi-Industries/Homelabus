//! La liste de contrôle de l'installation (lot 9.7).
//!
//! ## 🔴 Ce que ce n'est PAS
//!
//! Ce n'est **pas** un assistant de démarrage : le §2ter.0 l'interdit explicitement.
//! Une interface web ne peut pas être le premier pas d'une installation — il faut déjà
//! un cluster, un controller et un jeton pour l'atteindre.
//!
//! C'est une liste de contrôle **d'après-coup** : les choses qu'on croit faites et
//! qu'on n'a jamais vérifiées. Chacune renvoie à l'écran ou à la commande qui la
//! corrige.
//!
//! ## Ce que chaque ligne dit d'elle-même
//!
//! Une ligne ne peut pas être « verte » faute d'information. Ne pas savoir est un
//! troisième état — `Inconnu` — parce qu'un vert obtenu par ignorance atteste d'une
//! vérification qui n'a pas eu lieu, ce qui est pire que pas de liste du tout.

use hlb_state::State;

/// Le résultat d'un contrôle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Bon,
    /// À faire, sans urgence.
    AFaire,
    /// 🔴 Manquant, et ça compte.
    Manquant,
    /// On ne peut pas savoir d'ici.
    Inconnu,
}

impl Verdict {
    fn attention(self) -> hlb_api::Attention {
        match self {
            Self::Bon => hlb_api::Attention::Ok,
            Self::AFaire | Self::Inconnu => hlb_api::Attention::Notice,
            Self::Manquant => hlb_api::Attention::Critical,
        }
    }
}

fn ligne(
    titre: &str,
    verdict: Verdict,
    constat: String,
    remede: Option<&str>,
) -> hlb_api::ControleSante {
    hlb_api::ControleSante {
        titre: titre.to_string(),
        attention: verdict.attention(),
        constat,
        remede: remede.map(str::to_string),
    }
}

/// La liste, calculée à partir de l'état réel.
///
/// `battement` : le fichier de battement du deadman, quand il est configuré.
pub async fn controles(
    state: &State,
    battement: Option<&std::path::Path>,
    maintenant: i64,
) -> Vec<hlb_api::ControleSante> {
    let mut out = Vec::new();

    // --- Le hors-site ---------------------------------------------------------
    let destinations = state.destinations().await.unwrap_or_default();
    out.push(match destinations.len() {
        0 => ligne(
            "Sauvegardes",
            Verdict::Manquant,
            "Aucune destination déclarée : rien n'est sauvegardé nulle part.".into(),
            Some("hlb backup dest add nas --location /mnt/nas/restic --apply"),
        ),
        1 => ligne(
            "Hors-site",
            Verdict::Manquant,
            "Une seule destination : une copie unique disparaît avec la machine qui la \
             porte, et une panne électrique emporte les deux."
                .into(),
            Some("hlb backup dest add offsite --location s3:… --apply"),
        ),
        n => ligne(
            "Hors-site",
            Verdict::Bon,
            format!(
                "{} déclarées.",
                hlb_api::pluriel(n as u64, "destination", "destinations")
            ),
            None,
        ),
    });

    // --- L'exercice de reprise (§8.3) ----------------------------------------
    //
    // 🔴 Le seul indicateur fiable que les sauvegardes fonctionnent. Une sauvegarde
    // jamais restaurée est une hypothèse.
    let jours = state.days_since_successful_drill().await.unwrap_or(None);
    out.push(match hlb_backup::drill::Readiness::from_days(jours) {
        hlb_backup::drill::Readiness::Never => ligne(
            "Exercice de reprise",
            Verdict::Manquant,
            "Jamais fait : personne ne sait si une restauration marche.".into(),
            Some("hlb dr exercise --apply"),
        ),
        etat if etat.needs_attention() => ligne(
            "Exercice de reprise",
            Verdict::AFaire,
            etat.describe(),
            Some("hlb dr exercise --apply"),
        ),
        etat => ligne("Exercice de reprise", Verdict::Bon, etat.describe(), None),
    });

    // --- Le veilleur (§8bis) --------------------------------------------------
    //
    // ⚠️ Ce que cet écran ne peut PAS attester : le veilleur ne tourne pas sur ce qu'il
    // surveille. Un voyant vert affiché PAR LE CONTROLLER au sujet du veilleur n'atteste
    // que d'une chose — que le controller est vivant. On le dit dans le constat même,
    // sinon la ligne rassure sur exactement ce qu'elle ne prouve pas.
    let dernier = battement.and_then(|p| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
    });
    out.push(match dernier {
        None => ligne(
            "Deadman",
            Verdict::Manquant,
            "Aucun battement : si tout s'arrête, rien ne préviendra.".into(),
            Some("hlb metrics deadman --ntfy https://ntfy.sh/<sujet>"),
        ),
        Some(t) => {
            let age = maintenant.saturating_sub(t);
            ligne(
                "Deadman",
                if age > 3 * 3_600 {
                    Verdict::Manquant
                } else {
                    Verdict::Bon
                },
                format!(
                    "Dernier battement il y a {}. Cet écran n'atteste que du battement : \
                     le veilleur, lui, ne tourne pas ici et ne peut pas se déclarer \
                     vivant tout seul.",
                    hlb_api::humanise(age)
                ),
                None,
            )
        }
    });

    // --- Le jeton d'administration -------------------------------------------
    let jetons = state.list_tokens().await.unwrap_or_default();
    let admins = jetons.iter().filter(|(_, role, _)| role == "admin").count();
    out.push(match admins {
        0 => ligne(
            "Accès d'administration",
            Verdict::Inconnu,
            "Aucun jeton `admin` enregistré : l'accès passe peut-être par une session \
             OIDC, ce qu'on ne peut pas vérifier d'ici."
                .into(),
            None,
        ),
        1 => ligne(
            "Accès d'administration",
            Verdict::Bon,
            "Un seul jeton `admin` : c'est le bon nombre.".into(),
            None,
        ),
        // 🔴 Chaque jeton supplémentaire est une copie du pouvoir total qui traîne
        // quelque part. Ce n'est pas une panne, c'est une surface.
        n => ligne(
            "Accès d'administration",
            Verdict::AFaire,
            format!(
                "{} `admin` en circulation : chacun ouvre tout, et on ne sait plus \
                 lesquels servent encore.",
                hlb_api::pluriel(n as u64, "jeton", "jetons")
            ),
            Some("hlb token list"),
        ),
    });

    // --- Le journal d'audit ---------------------------------------------------
    out.push(match state.verify_audit_chain().await.map(|i| i.est_intacte()) {
        Ok(true) => ligne(
            "Journal d'audit",
            Verdict::Bon,
            "Le chaînage est intact : aucune entrée n'a été retirée ni modifiée.".into(),
            None,
        ),
        Ok(false) => ligne(
            "Journal d'audit",
            Verdict::Manquant,
            "Le chaînage est ROMPU : une entrée a été retirée ou modifiée.".into(),
            Some("hlb audit --verify"),
        ),
        Err(_) => ligne(
            "Journal d'audit",
            Verdict::Inconnu,
            "Le journal n'a pas pu être relu.".into(),
            Some("hlb audit --verify"),
        ),
    });

    out
}
