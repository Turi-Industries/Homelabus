//! Autorité de certification interne pour le mTLS agent ↔ controller (§2).
//!
//! ## Ce que ça remplace
//!
//! L'API de l'agent était en HTTP clair, protégée seulement par le chiffrement de
//! l'overlay Swarm. Ça suppose que **tout ce qui est sur l'overlay est de confiance** —
//! or n'importe quel conteneur compromis y est aussi. Un Gitea vérolé pouvait
//! interroger tous les agents du parc et cartographier les disques du cluster.
//!
//! Le mTLS règle les deux sens à la fois :
//!
//! - l'agent n'accepte que des clients porteurs d'un certificat signé par notre CA ;
//! - le controller vérifie qu'il parle bien à un agent, pas à un imposteur qui aurait
//!   pris la place dans le DNS de l'overlay.
//!
//! ## 🔴 Pourquoi `openssl` plutôt qu'une bibliothèque Rust
//!
//! Même raisonnement que pour `ssh-keygen` (§2ter phase 0bis) : X.509 est un format
//! où une erreur d'encodage produit un certificat que les outils acceptent et que la
//! pile TLS rejette — ou pire, l'inverse. `openssl` est présent sur toute machine qui
//! fait tourner un serveur, et le déléguer évite d'ajouter une dépendance dont on
//! auditerait mal la sortie.
//!
//! ## Ce qui n'est PAS géré ici, et pourquoi c'est dit
//!
//! Il n'y a **pas de révocation** (ni CRL, ni OCSP). Sur un parc de quelques machines,
//! une CRL qu'il faut distribuer et rafraîchir ajoute un mécanisme qui échoue en
//! silence ; on préfère des certificats **courts** qu'on renouvelle. Retirer un nœud
//! du parc se fait en révoquant son accès SSH (§2ter) et en le retirant du Swarm, pas
//! en espérant qu'une liste de révocation soit arrivée partout.

use std::path::Path;

use crate::Error;

type Result<T> = std::result::Result<T, Error>;

/// Durée de vie de la CA, en jours.
///
/// Longue **délibérément** : la remplacer impose de redéployer tous les certificats du
/// parc en même temps. Une CA qui expire au bout d'un an transforme une panne
/// silencieuse en panne totale, un matin, sans que personne n'ait rien changé.
pub const CA_DAYS: u32 = 3650;

/// Durée de vie des certificats de feuille.
///
/// Courte **délibérément** : c'est ce qui remplace la révocation. Un certificat volé
/// cesse de servir tout seul, et le renouvellement automatique est exercé assez
/// souvent pour qu'on sache qu'il fonctionne — au lieu de le découvrir le jour où il
/// est cassé depuis six mois.
pub const LEAF_DAYS: u32 = 90;

/// Une paire certificat + clé privée, au format PEM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPair {
    pub cert_pem: String,
    pub key_pem: String,
}

impl CertPair {
    /// Le certificat porte-t-il bien une clé privée à part ?
    ///
    /// 🔴 Garde-fou contre l'erreur la plus coûteuse du domaine : coller la clé privée
    /// dans le fichier de certificat, qui est distribué à tout le monde.
    pub fn looks_valid(&self) -> bool {
        self.cert_pem.contains("BEGIN CERTIFICATE")
            && !self.cert_pem.contains("PRIVATE KEY")
            && self.key_pem.contains("PRIVATE KEY")
    }
}

/// Le rôle que le certificat autorise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// L'agent, qui présente son certificat aux clients.
    Server,
    /// Le controller, qui prouve son identité à l'agent.
    Client,
}

impl Purpose {
    /// L'extension d'usage étendu correspondante.
    ///
    /// ⚠️ Elle n'est pas décorative : une pile TLS refuse un certificat serveur
    /// présenté comme client, et réciproquement. Un certificat sans `extendedKeyUsage`
    /// passe chez certains clients et pas chez d'autres — donc marche en test et
    /// échoue en production.
    fn ext_key_usage(&self) -> &'static str {
        match self {
            Self::Server => "serverAuth",
            Self::Client => "clientAuth",
        }
    }
}

/// Génère l'autorité de certification du cluster.
pub async fn generate_ca(common_name: &str) -> Result<CertPair> {
    let dir = tempdir()?;
    let key = dir.path().join("ca.key");
    let crt = dir.path().join("ca.crt");

    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "ed25519",
        // Sans phrase de passe : la clé est protégée par le coffre, et une invite
        // interactive bloquerait tout automatisme.
        "-nodes",
        "-keyout",
        &key.to_string_lossy(),
        "-out",
        &crt.to_string_lossy(),
        "-days",
        &CA_DAYS.to_string(),
        "-subj",
        &format!("/CN={common_name}"),
        // `critical` : un client qui ne comprend pas cette extension doit REFUSER,
        // pas l'ignorer. Sans ça, un certificat de feuille pourrait en signer d'autres.
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    ])
    .await?;

    lire_paire(&crt, &key).await
}

/// Émet un certificat signé par la CA.
///
/// `names` liste les noms sous lesquels le porteur sera joint. Pour un agent, c'est
/// son nom d'hôte **et** l'entrée DNS de l'overlay.
pub async fn issue(
    ca: &CertPair,
    common_name: &str,
    names: &[String],
    purpose: Purpose,
) -> Result<CertPair> {
    let dir = tempdir()?;
    let ca_crt = dir.path().join("ca.crt");
    let ca_key = dir.path().join("ca.key");
    let key = dir.path().join("leaf.key");
    let csr = dir.path().join("leaf.csr");
    let crt = dir.path().join("leaf.crt");
    let ext = dir.path().join("leaf.ext");

    ecrire(&ca_crt, &ca.cert_pem).await?;
    ecrire(&ca_key, &ca.key_pem).await?;
    ecrire(&ext, &extensions(names, purpose)).await?;

    openssl(&[
        "req",
        "-new",
        "-newkey",
        "ed25519",
        "-nodes",
        "-keyout",
        &key.to_string_lossy(),
        "-out",
        &csr.to_string_lossy(),
        "-subj",
        &format!("/CN={common_name}"),
    ])
    .await?;

    openssl(&[
        "x509",
        "-req",
        "-in",
        &csr.to_string_lossy(),
        "-CA",
        &ca_crt.to_string_lossy(),
        "-CAkey",
        &ca_key.to_string_lossy(),
        "-CAcreateserial",
        "-out",
        &crt.to_string_lossy(),
        "-days",
        &LEAF_DAYS.to_string(),
        "-extfile",
        &ext.to_string_lossy(),
    ])
    .await?;

    lire_paire(&crt, &key).await
}

/// Le fichier d'extensions passé à la signature.
///
/// 🔴 **Le `subjectAltName` est obligatoire, pas le `CN`.** Toutes les piles TLS
/// modernes ignorent le Common Name depuis des années : un certificat sans SAN est
/// rejeté avec un message qui parle de nom d'hôte, ce qui envoie chercher un problème
/// de DNS pendant des heures.
pub fn extensions(names: &[String], purpose: Purpose) -> String {
    let san: Vec<String> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            // Une IP doit être déclarée en `IP:`, pas en `DNS:` : déclarée en DNS,
            // elle ne correspond jamais, et l'erreur ne dit pas pourquoi.
            if n.parse::<std::net::IpAddr>().is_ok() {
                format!("IP.{} = {n}", i + 1)
            } else {
                format!("DNS.{} = {n}", i + 1)
            }
        })
        .collect();

    format!(
        "basicConstraints = critical,CA:FALSE\n\
         keyUsage = critical,digitalSignature,keyEncipherment\n\
         extendedKeyUsage = {}\n\
         subjectAltName = @noms\n\
         \n\
         [noms]\n\
         {}\n",
        purpose.ext_key_usage(),
        san.join("\n")
    )
}

/// Les noms sous lesquels un agent doit être joignable.
///
/// ⚠️ L'entrée `tasks.<service>` est indispensable : c'est par elle que le controller
/// interroge **chaque** tâche plutôt que la VIP. Un certificat qui ne la porte pas
/// fait échouer toutes les connexions avec une erreur de nom, alors que le nom d'hôte
/// est pourtant correct.
pub fn agent_names(hostname: &str, service: &str) -> Vec<String> {
    let mut v = vec![
        hostname.to_string(),
        service.to_string(),
        format!("tasks.{service}"),
        // Le controller se connecte parfois à l'adresse résolue plutôt qu'au nom.
        "localhost".to_string(),
    ];
    v.dedup();
    v
}

async fn openssl(args: &[&str]) -> Result<String> {
    let out = tokio::process::Command::new("openssl")
        .args(args)
        .output()
        .await
        .map_err(|e| Error::Pki(format!("openssl introuvable : {e}")))?;

    if !out.status.success() {
        return Err(Error::Pki(format!(
            "openssl {} : {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn tempdir() -> Result<tempfile::TempDir> {
    tempfile::tempdir().map_err(|e| Error::Pki(format!("répertoire temporaire : {e}")))
}

async fn ecrire(p: &Path, contenu: &str) -> Result<()> {
    tokio::fs::write(p, contenu)
        .await
        .map_err(|e| Error::Pki(format!("écriture de {} : {e}", p.display())))
}

async fn lire_paire(crt: &Path, key: &Path) -> Result<CertPair> {
    let cert_pem = tokio::fs::read_to_string(crt)
        .await
        .map_err(|e| Error::Pki(format!("lecture du certificat : {e}")))?;
    let key_pem = tokio::fs::read_to_string(key)
        .await
        .map_err(|e| Error::Pki(format!("lecture de la clé : {e}")))?;

    let p = CertPair { cert_pem, key_pem };
    if !p.looks_valid() {
        return Err(Error::Pki(
            "openssl a produit une paire inattendue — clé privée dans le certificat ?".into(),
        ));
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_and_a_client_are_not_interchangeable() {
        // ⚠️ Une pile TLS refuse un certificat serveur présenté comme client. Sans
        // extendedKeyUsage, ça marche chez certains clients et pas chez d'autres —
        // donc en test et pas en production.
        let s = extensions(&["agent".into()], Purpose::Server);
        let c = extensions(&["controller".into()], Purpose::Client);

        assert!(s.contains("extendedKeyUsage = serverAuth"), "{s}");
        assert!(c.contains("extendedKeyUsage = clientAuth"), "{c}");
        assert_ne!(s, c);
    }

    #[test]
    fn a_leaf_can_never_sign_other_certificates() {
        // 🔴 `CA:FALSE` en critique : un certificat de feuille qui pourrait signer
        // transformerait la compromission d'un seul agent en compromission du parc.
        let e = extensions(&["x".into()], Purpose::Server);
        assert!(e.contains("basicConstraints = critical,CA:FALSE"), "{e}");
    }

    #[test]
    fn names_are_declared_as_subject_alt_names() {
        // 🔴 Le CN est ignoré par toutes les piles TLS modernes. Un certificat sans
        // SAN échoue sur une erreur de nom d'hôte, ce qui fait chercher un problème
        // de DNS pendant des heures.
        let e = extensions(&["node1".into(), "tasks.hlb-agent".into()], Purpose::Server);
        assert!(e.contains("subjectAltName = @noms"), "{e}");
        assert!(e.contains("DNS.1 = node1"), "{e}");
        assert!(e.contains("DNS.2 = tasks.hlb-agent"), "{e}");
    }

    #[test]
    fn an_ip_is_declared_as_an_ip_not_a_dns_name() {
        // Une IP déclarée en DNS ne correspond jamais, et le message d'erreur ne dit
        // pas pourquoi.
        let e = extensions(&["10.42.0.2".into(), "node1".into()], Purpose::Server);
        assert!(e.contains("IP.1 = 10.42.0.2"), "{e}");
        assert!(e.contains("DNS.2 = node1"), "{e}");
        assert!(!e.contains("DNS.1 = 10.42.0.2"), "{e}");
    }

    #[test]
    fn an_agent_is_reachable_by_its_overlay_name() {
        // ⚠️ `tasks.<service>` est le nom par lequel le controller atteint CHAQUE
        // tâche. Sans lui au certificat, toutes les connexions échouent.
        let n = agent_names("node1", "hlb-agent");
        assert!(n.contains(&"tasks.hlb-agent".to_string()), "{n:?}");
        assert!(n.contains(&"node1".to_string()));
        assert!(n.contains(&"hlb-agent".to_string()));
    }

    #[test]
    fn a_private_key_inside_a_certificate_is_refused() {
        // 🔴 L'erreur la plus coûteuse du domaine : le certificat est distribué à
        // tout le monde, la clé privée ne doit jamais y être.
        let mauvais = CertPair {
            cert_pem: "-----BEGIN CERTIFICATE-----\nx\n-----BEGIN PRIVATE KEY-----".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----".into(),
        };
        assert!(!mauvais.looks_valid());

        let bon = CertPair {
            cert_pem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\ny\n-----END PRIVATE KEY-----".into(),
        };
        assert!(bon.looks_valid());
    }

    #[test]
    fn leaves_expire_long_before_the_authority() {
        // La durée courte REMPLACE la révocation : un certificat volé cesse de servir
        // tout seul. La CA, elle, doit survivre — la remplacer impose de redéployer
        // tout le parc le même jour.
        // `const` : la contrainte est vérifiée à la COMPILATION, donc changer une
        // constante sans y penser ne compile même pas.
        const _: () = assert!(LEAF_DAYS * 10 < CA_DAYS);
        const _: () = assert!(
            LEAF_DAYS >= 30,
            "trop court : le renouvellement deviendrait un fardeau"
        );
    }
}
