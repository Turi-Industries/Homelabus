//! Jetons d'accès à l'API (§9ter).
//!
//! ## Ce que ceci est, et ce que ce n'est pas
//!
//! Le §9ter prévoit que les rôles viennent des **groupes PocketID** : une seule source
//! de vérité pour les identités. C'est la bonne cible, et ce module ne la remplace
//! pas — il fournit la couche en dessous.
//!
//! Un jeton porteur reste nécessaire même avec OIDC : c'est ce qu'un flux OIDC finit
//! par délivrer, et c'est ce dont un script ou un collecteur de métriques a besoin,
//! puisqu'ils ne peuvent pas ouvrir un navigateur pour se connecter.
//!
//! ## 🔴 Le jeton n'est jamais stocké en clair
//!
//! Le coffre `age` chiffre déjà ce qu'il contient, donc stocker le jeton tel quel
//! « marcherait ». Mais alors, quiconque obtient la clé maîtresse **et** la base
//! obtient des jetons **utilisables immédiatement**.
//!
//! On stocke donc une **empreinte**. Une fuite du coffre révèle qu'un jeton existe,
//! pas sa valeur : il faut le régénérer, pas s'en inquiéter. C'est exactement le
//! raisonnement d'un fichier de mots de passe, et il vaut ici pour la même raison.
//!
//! ⚠️ Conséquence assumée : **un jeton perdu ne se retrouve pas**, il se remplace.

use serde::{Deserialize, Serialize};

use crate::rbac::Role;

/// Longueur du jeton engendré, en octets d'entropie.
///
/// 32 octets = 256 bits. Bien au-delà de ce qui se force par recherche exhaustive,
/// et le coût d'un jeton plus long est nul.
pub const TOKEN_BYTES: usize = 32;

/// Un jeton, tel qu'il est conservé.
///
/// 🔴 Il n'y a **pas de champ pour la valeur**. Comme pour [`crate::rbac::Role`], la
/// garantie est structurelle : on ne peut pas fuiter ce qu'on ne peut pas représenter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredToken {
    /// Nom lisible, pour savoir lequel révoquer.
    pub name: String,
    pub role: Role,
    /// Empreinte hexadécimale de la valeur.
    pub fingerprint: String,
}

impl StoredToken {
    /// Le jeton fourni correspond-il ?
    ///
    /// 🔴 Comparaison à **temps constant**. Un `==` sur des chaînes s'arrête au
    /// premier octet différent : le temps de réponse révèle combien de caractères
    /// sont corrects, et le jeton se devine octet par octet. Le surcoût ici est nul,
    /// l'absence de protection ne l'est pas.
    pub fn matches(&self, presented: &str) -> bool {
        constant_eq(&fingerprint(presented), &self.fingerprint)
    }
}

/// L'empreinte d'un jeton.
///
/// ## Pourquoi SHA-256 et pas un hachage de mot de passe
///
/// Un `bcrypt`/`argon2` sert à ralentir la recherche exhaustive **d'un secret que
/// l'humain a choisi**, donc à faible entropie. Ici le jeton fait 256 bits engendrés
/// aléatoirement : il n'y a rien à ralentir, l'espace est déjà hors de portée.
///
/// Et un hachage lent serait un défaut : il s'exécute à **chaque requête** de l'API,
/// y compris celles du collecteur de métriques qui passe toutes les quinze secondes.
pub fn fingerprint_of(token: &str) -> String {
    fingerprint(token)
}

fn fingerprint(token: &str) -> String {
    // SHA-256 en implémentation directe : pas de dépendance nouvelle pour trente
    // lignes, et l'algorithme est figé depuis vingt ans.
    let d = sha256(token.as_bytes());
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Un jeton neuf : la valeur (à donner UNE fois) et sa forme stockée.
pub fn generate(name: &str, role: Role, random: [u8; TOKEN_BYTES]) -> (String, StoredToken) {
    // Base32 sans padding : lisible, sélectionnable d'un double-clic, et sans
    // caractère que le shell interprète — contrairement au base64, dont le « / »
    // et le « + » cassent les copier-coller dans une URL ou un fichier d'unité.
    let valeur = base32(&random);
    let stored = StoredToken {
        name: name.to_string(),
        role,
        fingerprint: fingerprint(&valeur),
    };
    (valeur, stored)
}

/// Comparaison à temps constant.
pub fn constant_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Encodage base32 (RFC 4648, sans remplissage).
fn base32(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut tampon: u32 = 0;
    let mut bits = 0;

    for &b in data {
        tampon = (tampon << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((tampon >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((tampon << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// SHA-256.
fn sha256(message: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut m = message.to_vec();
    let bits = (message.len() as u64) * 8;
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    m.extend_from_slice(&bits.to_be_bytes());

    for bloc in m.chunks(64) {
        let mut w = [0u32; 64];
        for (i, c) in bloc.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        let (mut e, mut f, mut g, mut hh) = (h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        for (i, v) in [a, b, c, d, e, f, g, hh].iter().enumerate() {
            h[i] = h[i].wrapping_add(*v);
        }
    }

    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alea(n: u8) -> [u8; TOKEN_BYTES] {
        let mut v = [0u8; TOKEN_BYTES];
        for (i, b) in v.iter_mut().enumerate() {
            *b = n.wrapping_add(i as u8);
        }
        v
    }

    #[test]
    fn sha256_matches_the_reference_vectors() {
        // 🔴 Une implémentation cryptographique écrite à la main DOIT être vérifiée
        // contre les vecteurs officiels. Une erreur d'un bit donnerait un hachage
        // parfaitement cohérent avec lui-même, donc des jetons qui « marchent » —
        // jusqu'au jour où l'on compare avec un autre outil.
        let vide: String = sha256(b"").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            vide,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let abc: String = sha256(b"abc").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            abc,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        // Un message de plus d'un bloc, pour exercer le remplissage.
        let long: String = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            long,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn the_stored_form_has_no_field_for_the_value() {
        // 🔴 La garantie est structurelle : on ne peut pas fuiter ce qu'on ne peut
        // pas représenter.
        let (_, s) = generate("ui", Role::Viewer, alea(1));
        let j = serde_json::to_string(&s).expect("sérialisable");
        assert!(!j.contains("value"), "{j}");
        assert!(!j.contains("token\":"), "{j}");
        assert!(j.contains("fingerprint"));
    }

    #[test]
    fn a_vault_dump_does_not_yield_usable_tokens() {
        // Le point du hachage : une fuite révèle qu'un jeton EXISTE, pas sa valeur.
        let (valeur, s) = generate("ui", Role::Viewer, alea(7));
        assert!(!s.fingerprint.contains(&valeur));
        assert_ne!(s.fingerprint, valeur);
        // Et l'empreinte ne permet pas de reconstruire la valeur.
        assert!(!s.matches(&s.fingerprint));
    }

    #[test]
    fn a_token_matches_only_itself() {
        let (valeur, s) = generate("ui", Role::Viewer, alea(3));
        assert!(s.matches(&valeur));
        assert!(!s.matches(&format!("{valeur}x")));
        assert!(!s.matches(""));
        assert!(!s.matches("NIMPORTEQUOI"));
    }

    #[test]
    fn two_tokens_are_never_identical() {
        let (a, _) = generate("a", Role::Viewer, alea(1));
        let (b, _) = generate("b", Role::Viewer, alea(2));
        assert_ne!(a, b);
    }

    #[test]
    fn the_token_survives_a_copy_paste() {
        // ⚠️ Base32 : pas de « / » ni de « + » comme en base64, qui cassent les
        // copier-coller dans une URL ou un fichier d'unité systemd.
        let (v, _) = generate("x", Role::Admin, alea(9));
        assert!(v.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
        assert!(!v.contains('/') && !v.contains('+') && !v.contains('='));
        // 32 octets → au moins 51 caractères base32.
        assert!(v.len() >= 51, "{} caractères", v.len());
    }

    #[test]
    fn comparison_does_not_leak_by_timing() {
        // Un `==` s'arrête au premier octet différent : le temps de réponse dirait
        // combien de caractères sont bons, et le jeton se devinerait octet par octet.
        assert!(constant_eq("abc", "abc"));
        assert!(!constant_eq("abc", "abd"));
        assert!(!constant_eq("abc", "abcd"));
        assert!(constant_eq("", ""));
    }

    #[test]
    fn the_role_is_carried_by_the_token() {
        // C'est lui qui décidera ce que la requête a le droit de faire.
        let (_, s) = generate("ops", Role::Operator, alea(5));
        assert_eq!(s.role, Role::Operator);
        assert!(s.role.allows(crate::rbac::Action::Operate));
        assert!(!s.role.allows(crate::rbac::Action::Destroy));
    }
}
