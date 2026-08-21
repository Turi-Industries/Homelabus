//! Le plan break-glass, vivant (lot 10.2, §5.7bis).
//!
//! ## 🔴 Un SSO centralisé est un point de défaillance unique SUR L'ACCÈS
//!
//! Si PocketID tombe, on ne peut plus se connecter à Homelabus — donc plus piloter la
//! restauration de PocketID. Le §5.7bis pose quatre garde-fous contre ça.
//!
//! ## Ce que Homelabus peut, et ne peut pas
//!
//! Il ne sait **pas** combien de passkeys sont enregistrées, ni si les codes à usage
//! unique sont imprimés et rangés dans un tiroir. Cocher ces cases à sa place serait le
//! pire des affichages : un écran vert sur des garanties inexistantes, consulté
//! précisément le jour où l'on est enfermé dehors.
//!
//! Il demande donc une **attestation datée**, et la fait expirer. Un break-glass jamais
//! éprouvé n'est pas un break-glass — même raisonnement que les exercices du §8.3.

use serde::{Deserialize, Serialize};

/// Un garde-fou d'accès de secours.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GardeFou {
    /// Identifiant stable, utilisé pour attester.
    pub id: String,
    pub titre: String,
    /// Pourquoi ce garde-fou existe.
    pub pourquoi: String,
    /// Comment le mettre en place ou le vérifier.
    pub comment: String,
    /// Âge de la dernière attestation, en secondes. `None` = jamais attesté.
    #[serde(default)]
    pub atteste_il_y_a_s: Option<i64>,
    #[serde(default)]
    pub atteste_par: Option<String>,
    /// 🔴 Vrai quand Homelabus peut le vérifier lui-même — un seul l'est.
    pub verifiable: bool,
    /// ⚠️ Vrai quand l'âge n'a qu'une résolution d'un JOUR.
    ///
    /// L'exercice de reprise est compté en jours entiers : afficher « il y a 0 s » pour
    /// un exercice d'hier soir donnerait à croire qu'il vient d'avoir lieu. Le type
    /// porte la résolution, sinon l'affichage invente une précision qui n'existe pas.
    #[serde(default)]
    pub resolution_jour: bool,
}

/// Au-delà, une attestation ne rassure plus : les appareils changent, les gens
/// partent, et « on l'avait fait » devient « on croit l'avoir fait ».
pub const ATTESTATION_PERIMEE_S: i64 = 180 * 86_400;

impl GardeFou {
    pub fn attention(&self) -> crate::Attention {
        match self.atteste_il_y_a_s {
            // 🔴 Jamais attesté : ce n'est pas « peut-être en place », c'est « on n'en
            // sait rien », et c'est la situation qu'on découvre enfermé dehors.
            None => crate::Attention::Critical,
            Some(age) if age > ATTESTATION_PERIMEE_S => crate::Attention::Notice,
            Some(_) => crate::Attention::Ok,
        }
    }

    pub fn etat(&self) -> String {
        let Some(age) = self.atteste_il_y_a_s else {
            return "jamais vérifié".to_string();
        };

        let quand = if self.resolution_jour {
            match age / 86_400 {
                0 => "aujourd'hui".to_string(),
                1 => "hier".to_string(),
                j => format!("il y a {j} j"),
            }
        } else {
            format!("il y a {}", crate::humanise(age))
        };

        match &self.atteste_par {
            Some(qui) => format!("vérifié {quand} par {qui}"),
            None => format!("vérifié {quand}"),
        }
    }
}

/// Les quatre garde-fous du §5.7bis, dans l'ordre où l'on veut les lire.
pub fn garde_fous() -> Vec<GardeFou> {
    vec![
        GardeFou {
            id: "codes-imprimes".into(),
            titre: "Codes de connexion à usage unique, imprimés".into(),
            pourquoi: "C'est le premier filet quand l'appareil qui porte la passkey \
                       n'est pas là — perdu, cassé, ou resté ailleurs."
                .into(),
            comment: "Les générer dans PocketID, les IMPRIMER, et les ranger hors du \
                      cluster. Un fichier sur la machine qui est tombée ne sert à rien."
                .into(),
            atteste_il_y_a_s: None,
            atteste_par: None,
            verifiable: false,
            resolution_jour: false,
        },
        GardeFou {
            id: "deux-passkeys".into(),
            titre: "Au moins deux passkeys, sur des supports distincts".into(),
            pourquoi: "Une seule passkey est un seul point de perte : le téléphone \
                       tombe dans l'eau et l'accès part avec."
                .into(),
            comment: "Enregistrer une seconde passkey sur un support différent — clé \
                      matérielle plutôt qu'un second appareil du même type."
                .into(),
            atteste_il_y_a_s: None,
            atteste_par: None,
            verifiable: false,
            resolution_jour: false,
        },
        GardeFou {
            id: "vaultwarden-local".into(),
            titre: "Connexion locale active sur Vaultwarden".into(),
            pourquoi: "C'est le point d'entrée qui ne dépend d'AUCUN autre service : \
                       il donne accès aux mots de passe quand le SSO est tombé."
                .into(),
            comment: "Vérifier que « SSO_ONLY » est faux, et se connecter réellement \
                      avec le mot de passe maître — pas seulement lire le réglage."
                .into(),
            atteste_il_y_a_s: None,
            atteste_par: None,
            verifiable: false,
            resolution_jour: false,
        },
        GardeFou {
            id: "pocketid-restaure".into(),
            titre: "Restauration de PocketID éprouvée pour de vrai".into(),
            pourquoi: "PocketID est le service le plus critique du cluster : sans lui, \
                       on ne se connecte nulle part, pas même ici pour piloter sa \
                       propre restauration."
                .into(),
            comment: "hlb dr exercise, puis « hlb dr promote pocketid » au moins une \
                      fois — sur un bac à sable, mais en vrai."
                .into(),
            atteste_il_y_a_s: None,
            atteste_par: None,
            verifiable: true,
            // L'exercice est compté en jours entiers.
            resolution_jour: true,
        },
    ]
}

/// Le verdict d'ensemble.
///
/// ⚠️ Le PIRE cas décide, pas la moyenne : trois garde-fous sur quatre ne font pas
/// 75 % d'un accès de secours. Celui qui manque est celui qui manquera.
pub fn verdict(garde_fous: &[GardeFou]) -> String {
    let jamais = garde_fous
        .iter()
        .filter(|g| g.atteste_il_y_a_s.is_none())
        .count();

    if jamais == garde_fous.len() {
        return "Aucun garde-fou d'accès n'a jamais été vérifié : si PocketID tombe, \
                rien ne dit qu'on pourra encore entrer."
            .to_string();
    }
    if jamais > 0 {
        return format!(
            "{} jamais vérifié{} : c'est celui-là qui manquera.",
            crate::pluriel(jamais as u64, "garde-fou", "garde-fous"),
            if jamais > 1 { "s" } else { "" }
        );
    }

    let perimes = garde_fous
        .iter()
        .filter(|g| g.atteste_il_y_a_s.is_some_and(|a| a > ATTESTATION_PERIMEE_S))
        .count();
    if perimes > 0 {
        return format!(
            "{} à revérifier : les appareils changent, et « on l'avait fait » devient \
             « on croit l'avoir fait ».",
            crate::pluriel(perimes as u64, "garde-fou", "garde-fous")
        );
    }

    "Les quatre garde-fous ont été vérifiés récemment.".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_never_attested_guardrail_is_critical_not_merely_unknown() {
        // 🔴 « On n'en sait rien » est exactement la situation qu'on découvre enfermé
        // dehors. La peindre en jaune la ferait remettre à plus tard.
        let g = &garde_fous()[0];
        assert_eq!(g.atteste_il_y_a_s, None);
        assert_eq!(g.attention(), crate::Attention::Critical);
        assert_eq!(g.etat(), "jamais vérifié");
    }

    #[test]
    fn an_old_attestation_stops_reassuring() {
        // Un break-glass jamais éprouvé n'est pas un break-glass : même raisonnement
        // que les exercices de restauration du §8.3.
        let mut g = garde_fous()[1].clone();
        g.atteste_il_y_a_s = Some(ATTESTATION_PERIMEE_S + 86_400);
        g.atteste_par = Some("remy".into());
        assert_eq!(g.attention(), crate::Attention::Notice);

        g.atteste_il_y_a_s = Some(86_400);
        assert_eq!(g.attention(), crate::Attention::Ok);
        assert!(g.etat().contains("par remy"));
    }

    #[test]
    fn a_day_resolution_age_never_pretends_to_be_precise() {
        // 🔴 Constaté à l'écran : « vérifié il y a 0 s » pour un exercice compté en
        // jours entiers. Ça se lit « à l'instant », alors que l'exercice peut dater
        // d'hier soir.
        let mut g = garde_fous()
            .into_iter()
            .find(|g| g.verifiable)
            .expect("le garde-fou vérifiable");
        assert!(g.resolution_jour);

        g.atteste_il_y_a_s = Some(0);
        assert!(g.etat().contains("aujourd'hui"), "{}", g.etat());
        g.atteste_il_y_a_s = Some(86_400);
        assert!(g.etat().contains("hier"), "{}", g.etat());
        g.atteste_il_y_a_s = Some(5 * 86_400);
        assert!(g.etat().contains("il y a 5 j"), "{}", g.etat());
    }

    #[test]
    fn only_one_guardrail_claims_to_be_verifiable() {
        // ⚠️ Homelabus ne sait pas combien de passkeys existent, ni si des codes sont
        // imprimés. Prétendre le contraire donnerait un écran vert sur des garanties
        // inexistantes.
        let v: Vec<_> = garde_fous().into_iter().filter(|g| g.verifiable).collect();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].id, "pocketid-restaure");
    }

    #[test]
    fn the_worst_case_decides_never_the_average() {
        // Trois sur quatre ne font pas 75 % d'un accès de secours.
        let mut g = garde_fous();
        for x in g.iter_mut() {
            x.atteste_il_y_a_s = Some(86_400);
        }
        assert!(verdict(&g).contains("vérifiés récemment"));

        g[2].atteste_il_y_a_s = None;
        let v = verdict(&g);
        assert!(v.contains("celui-là qui manquera"), "{v}");
    }

    #[test]
    fn nothing_attested_at_all_says_so_plainly() {
        let v = verdict(&garde_fous());
        assert!(v.contains("Aucun garde-fou"), "{v}");
        assert!(v.contains("pourra encore entrer"), "{v}");
    }
}
