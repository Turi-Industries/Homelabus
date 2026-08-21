//! Génération automatique d'aliases, façon addy.io / SimpleLogin (§5bis.3).
//!
//! ## Ce que ce modèle apporte vraiment
//!
//! On croit souvent que l'intérêt d'un alias jetable est de pouvoir le jeter. C'est le
//! moindre. Le vrai gain est **l'attribution** : une adresse par destinataire, et le
//! jour où du spam arrive sur `amazon-k7m2p9@example.fr`, on sait *qui* a laissé fuiter
//! l'adresse. Avec une adresse unique donnée partout, on sait seulement qu'on a fuité,
//! ce qui n'aide personne.
//!
//! C'est pourquoi [`Genere::pour`] garde un indice lisible : sans lui, on se retrouve
//! avec cinquante adresses aléatoires dont on ne sait plus laquelle allait où, et
//! l'attribution — le seul vrai bénéfice — disparaît.
//!
//! ## 🔴 Un alias doit être INDEVINABLE
//!
//! C'est la propriété qui fait tout tenir, et la plus facile à perdre.
//!
//! Si l'alias donné à Amazon est `amazon@example.fr`, alors `paypal@example.fr`,
//! `impots@example.fr` et `banque@example.fr` existent probablement aussi — et un
//! expéditeur de masse les essaie toutes pour le prix d'une. Le compartimentage tombe
//! d'un coup : chaque alias devine les autres, et l'on a construit une passoire en
//! croyant construire des cloisons.
//!
//! L'indice n'est donc **jamais** l'adresse entière : il est toujours suivi d'un
//! suffixe aléatoire. Six caractères en base32 font environ un milliard de
//! possibilités — assez pour qu'une énumération coûte plus cher qu'elle ne rapporte,
//! tout en restant dictable au téléphone.
//!
//! ## 🔴 Désactiver plutôt que supprimer
//!
//! Un alias supprimé rejette le courrier, et l'on n'apprend plus rien. Un alias
//! **désactivé** le rejette aussi, mais on continue de compter ce qui frappe à la
//! porte — ce qui dit combien de temps un marchand a continué de vendre l'adresse
//! après qu'on l'a fermée. Voir [`crate::alias::Alias::actif`].

/// L'alphabet du suffixe.
///
/// ⚠️ Ni `0`/`O`, ni `1`/`I`/`L` : ces adresses se dictent au téléphone et se recopient
/// à la main depuis un écran. Une confusion à la lecture produit un rebond
/// « destinataire inconnu » que personne ne rattache à la police de caractères.
const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// Longueur du suffixe aléatoire.
///
/// 🔴 31^6 ≈ 887 millions. Assez pour qu'énumérer les aliases d'un domaine coûte plus
/// cher que ça ne rapporte, tout en restant court à dicter.
pub const SUFFIXE_LEN: usize = 6;

/// ⚠️ Stalwart accepte des parties locales plus longues, mais au-delà l'adresse cesse
/// d'être recopiable à la main — ce qui est justement l'usage.
pub const INDICE_MAX: usize = 24;

/// Un alias généré.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Genere {
    /// La partie locale complète : `amazon-k7m2p9`.
    pub local: String,
    /// L'indice retenu, après nettoyage.
    pub indice: String,
}

/// Nettoie un indice pour qu'il soit utilisable dans une adresse.
///
/// ⚠️ Une partie locale n'accepte pas n'importe quoi. Un indice non nettoyé produirait
/// une adresse que certains serveurs rejettent — et le rebond arrive chez
/// l'expéditeur, pas chez nous : on ne saurait même pas que l'alias ne marche pas.
pub fn nettoyer_indice(brut: &str) -> String {
    let s: String = brut
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();

    // Les tirets en tête, en queue ou en série sont laids et parfois refusés.
    let mut out = String::with_capacity(s.len());
    let mut tiret = true; // vrai au départ : supprime les tirets de tête
    for c in s.chars() {
        if c == '-' {
            if !tiret {
                out.push(c);
            }
            tiret = true;
        } else {
            out.push(c);
            tiret = false;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out.truncate(INDICE_MAX);
    while out.ends_with('-') {
        out.pop();
    }
    out
}

impl Genere {
    /// Un alias pour un destinataire donné.
    ///
    /// `alea` fournit l'entropie — passé en paramètre pour que la génération soit
    /// **testable** : un générateur qui tire son hasard lui-même ne peut pas être
    /// vérifié, et c'est précisément la partie qu'on veut vérifier.
    ///
    /// 🔴 L'indice ne fait JAMAIS l'adresse à lui seul. Voir la note d'en-tête : sans
    /// suffixe, chaque alias devine tous les autres.
    pub fn pour(indice: &str, alea: &[u8]) -> Self {
        let indice = nettoyer_indice(indice);
        let suffixe = suffixe(alea);

        let local = if indice.is_empty() {
            // Sans indice utilisable, l'alias reste anonyme — mais toujours aléatoire.
            // C'est moins pratique à retrouver, jamais moins sûr.
            suffixe
        } else {
            format!("{indice}-{suffixe}")
        };

        Self { local, indice }
    }

    /// L'adresse complète.
    pub fn adresse(&self, domaine: &str) -> String {
        format!("{}@{}", self.local, domaine)
    }
}

fn suffixe(alea: &[u8]) -> String {
    // ⚠️ Le modulo introduit un biais négligeable ici (256 mod 31), et l'enjeu est de
    // ne pas être devinable, pas d'être une source cryptographique parfaite.
    alea.iter()
        .take(SUFFIXE_LEN)
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALEA: &[u8] = &[7, 42, 200, 13, 99, 251, 3, 4];

    #[test]
    fn a_hint_never_makes_the_whole_address() {
        // 🔴 LA propriété du module. Si l'alias d'Amazon est « amazon@example.fr »,
        // alors « paypal@ », « impots@ » et « banque@ » existent probablement aussi, et
        // un expéditeur de masse les essaie toutes pour le prix d'une. Le
        // compartimentage tombe : chaque alias devine les autres.
        let g = Genere::pour("amazon", ALEA);

        assert_ne!(g.local, "amazon", "l'indice seul serait devinable");
        assert!(g.local.starts_with("amazon-"), "{}", g.local);
        assert_eq!(
            g.local.len(),
            "amazon-".len() + SUFFIXE_LEN,
            "un suffixe de longueur fixe : {}",
            g.local
        );
    }

    #[test]
    fn two_aliases_for_the_same_site_differ() {
        // Sinon redemander un alias pour un marchand rendrait le précédent, et
        // l'attribution d'une fuite deviendrait impossible.
        let a = Genere::pour("amazon", &[1, 2, 3, 4, 5, 6]);
        let b = Genere::pour("amazon", &[9, 8, 7, 6, 5, 4]);
        assert_ne!(a.local, b.local);
    }

    #[test]
    fn the_hint_survives_so_attribution_stays_possible() {
        // Sans indice, on se retrouve avec cinquante adresses aléatoires dont on ne
        // sait plus laquelle allait où — et l'attribution, seul vrai bénéfice du
        // dispositif, disparaît.
        let g = Genere::pour("Le Bon Coin", ALEA);
        assert_eq!(g.indice, "le-bon-coin");
        assert!(g.local.starts_with("le-bon-coin-"), "{}", g.local);
    }

    #[test]
    fn ambiguous_characters_are_never_produced() {
        // ⚠️ Ces adresses se dictent au téléphone et se recopient depuis un écran. Un
        // « 0 » lu « O » produit un rebond « destinataire inconnu » que personne ne
        // rattache à la police de caractères.
        for b in 0u8..=255 {
            let g = Genere::pour("x", &[b; SUFFIXE_LEN]);
            let suffixe = g.local.strip_prefix("x-").expect("préfixe");
            for c in suffixe.chars() {
                assert!(
                    !"01loi".contains(c),
                    "caractère ambigu « {c} » dans « {suffixe} »"
                );
            }
        }
    }

    #[test]
    fn a_dirty_hint_is_cleaned_rather_than_refused() {
        // Une partie locale n'accepte pas n'importe quoi, et un rebond arriverait chez
        // l'EXPÉDITEUR : on ne saurait même pas que l'alias ne marche pas.
        assert_eq!(nettoyer_indice("Amazon.fr"), "amazon-fr");
        assert_eq!(nettoyer_indice("  --Fnac--  "), "fnac");
        assert_eq!(nettoyer_indice("a@@@b"), "a-b");
        assert_eq!(nettoyer_indice("Été 2026"), "t-2026");
    }

    #[test]
    fn a_hint_is_never_long_enough_to_break_copying() {
        let long = "a".repeat(200);
        let g = Genere::pour(&long, ALEA);
        assert!(g.indice.len() <= INDICE_MAX);
        assert!(!g.local.contains("--"));
    }

    #[test]
    fn an_alias_without_a_usable_hint_is_still_random() {
        // Moins pratique à retrouver, jamais moins sûr.
        let g = Genere::pour("!!!", ALEA);
        assert!(g.indice.is_empty());
        assert_eq!(g.local.len(), SUFFIXE_LEN);
        assert!(!g.local.starts_with('-'), "{}", g.local);
    }

    #[test]
    fn the_address_is_built_once_and_correctly() {
        let g = Genere::pour("amazon", ALEA);
        let a = g.adresse("example.fr");
        assert_eq!(a.matches('@').count(), 1, "{a}");
        assert!(a.ends_with("@example.fr"));
    }

    #[test]
    fn the_search_space_is_large_enough_to_discourage_enumeration() {
        // 🔴 31^6 ≈ 887 millions. Un alphabet ou une longueur réduits par mégarde
        // rendraient l'énumération rentable, et tout le compartimentage avec.
        let espace = (ALPHABET.len() as u64).pow(SUFFIXE_LEN as u32);
        assert!(espace > 500_000_000, "espace trop petit : {espace}");
    }
}
