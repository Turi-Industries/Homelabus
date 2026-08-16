//! Analyse de vulnérabilités et vérification de signature (§7, phase 4).
//!
//! ## Ce que chacun répond
//!
//! Les deux outils sont souvent confondus alors qu'ils répondent à des questions
//! opposées :
//!
//! | | Question | Ce qu'un échec veut dire |
//! |---|---|---|
//! | **Trivy** | l'image contient-elle des failles connues ? | le contenu est risqué |
//! | **cosign** | l'image vient-elle bien de qui elle prétend ? | l'image est peut-être substituée |
//!
//! Une image signée peut être criblée de CVE ; une image saine peut avoir été
//! remplacée. Il faut les deux, et un échec de signature est **toujours** plus grave
//! qu'un échec de scan.
//!
//! ## 🔴 Un outil absent n'est pas un feu vert
//!
//! Le piège central de ce module. Si `trivy` n'est pas installé et qu'on traite ça
//! comme « aucune vulnérabilité trouvée », toutes les mises à jour passent en donnant
//! l'impression d'être vérifiées. C'est pire que de ne pas scanner du tout, puisqu'on
//! croit l'être.
//!
//! Chaque résultat distingue donc explicitement **« vérifié et propre »** de
//! **« pas vérifié »**, et l'appelant doit traiter les deux différemment.

use crate::Result;

/// Le verdict d'un contrôle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Contrôle effectué, rien à signaler.
    Clean,
    /// Contrôle effectué, problèmes trouvés.
    Findings { critical: usize, high: usize, detail: String },
    /// 🔴 Contrôle **non effectué**. Ce n'est pas un succès.
    NotChecked { reason: String },
}

impl Verdict {
    /// Le contrôle a-t-il réellement eu lieu ?
    pub fn was_checked(&self) -> bool {
        !matches!(self, Self::NotChecked { .. })
    }

    /// Peut-on continuer sans décision humaine ?
    ///
    /// 🔴 `NotChecked` ne bloque pas — sinon un homelab sans `trivy` ne pourrait plus
    /// jamais se mettre à jour, et l'utilisateur désactiverait le contrôle en entier.
    /// Mais ça ne vaut pas « propre » non plus : `was_checked()` permet de le dire.
    pub fn blocks(&self) -> bool {
        matches!(self, Self::Findings { critical, .. } if *critical > 0)
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Clean => "✓ aucune vulnérabilité critique".into(),
            Self::Findings { critical, high, detail } => {
                format!("🔴 {critical} critique(s), {high} élevée(s) — {detail}")
            }
            Self::NotChecked { reason } => {
                format!("⚠️  NON VÉRIFIÉ ({reason}) — ce n'est pas la même chose que « propre »")
            }
        }
    }
}

/// Scanne une image avec Trivy.
///
/// ⚠️ `--severity CRITICAL,HIGH` : sans filtre, une image Debian ordinaire remonte des
/// centaines de vulnérabilités basses que personne ne lira. Un rapport qu'on ne lit
/// pas ne protège de rien.
///
/// `--ignore-unfixed` : une faille sans correctif disponible n'appelle aucune action.
/// La signaler à chaque mise à jour entraîne à ignorer le rapport.
pub async fn scan_image(image: &str) -> Verdict {
    let out = tokio::process::Command::new("trivy")
        .args([
            "image",
            "--quiet",
            "--format", "json",
            "--severity", "CRITICAL,HIGH",
            "--ignore-unfixed",
            // Sans ça, un registre lent fait attendre indéfiniment le pipeline.
            "--timeout", "5m",
            image,
        ])
        .output()
        .await;

    let out = match out {
        Ok(o) => o,
        Err(e) => {
            return Verdict::NotChecked {
                reason: format!("trivy indisponible : {e}"),
            }
        }
    };

    if !out.status.success() {
        return Verdict::NotChecked {
            reason: format!(
                "trivy a échoué : {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        };
    }

    parse_trivy(&String::from_utf8_lossy(&out.stdout))
}

/// Analyse la sortie JSON de Trivy.
pub fn parse_trivy(json: &str) -> Verdict {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        // 🔴 Une sortie illisible n'est PAS une image propre : le format a pu changer
        // d'une version à l'autre, et l'interpréter comme un succès désactiverait le
        // contrôle en silence.
        return Verdict::NotChecked {
            reason: "sortie de trivy illisible".into(),
        };
    };

    let mut critical = 0;
    let mut high = 0;
    let mut exemples = Vec::new();

    for r in v.get("Results").and_then(|r| r.as_array()).into_iter().flatten() {
        for vuln in r.get("Vulnerabilities").and_then(|x| x.as_array()).into_iter().flatten() {
            match vuln.get("Severity").and_then(|s| s.as_str()) {
                Some("CRITICAL") => {
                    critical += 1;
                    if exemples.len() < 3 {
                        if let Some(id) = vuln.get("VulnerabilityID").and_then(|x| x.as_str()) {
                            exemples.push(id.to_string());
                        }
                    }
                }
                Some("HIGH") => high += 1,
                _ => {}
            }
        }
    }

    if critical == 0 && high == 0 {
        return Verdict::Clean;
    }
    Verdict::Findings {
        critical,
        high,
        detail: if exemples.is_empty() {
            "voir le rapport complet".into()
        } else {
            exemples.join(", ")
        },
    }
}

/// Vérifie la signature d'une image avec cosign.
///
/// `identity` et `issuer` décrivent QUI a le droit d'avoir signé. Les omettre revient
/// à accepter n'importe quelle signature valide — y compris celle d'un attaquant qui
/// aurait signé son image avec son propre compte.
pub async fn verify_signature(
    image: &str,
    identity_regexp: Option<&str>,
    issuer: Option<&str>,
) -> Verdict {
    let (Some(identity), Some(issuer)) = (identity_regexp, issuer) else {
        // 🔴 Sans identité attendue, `cosign verify` accepte toute signature valide.
        // Un attaquant signe son image avec son propre compte GitHub et passe.
        // Refuser de vérifier est plus honnête que vérifier n'importe quoi.
        return Verdict::NotChecked {
            reason: "aucune identité de signataire déclarée — une vérification sans \
                     identité accepte n'importe quelle signature"
                .into(),
        };
    };

    let out = tokio::process::Command::new("cosign")
        .args([
            "verify",
            "--certificate-identity-regexp", identity,
            "--certificate-oidc-issuer", issuer,
            image,
        ])
        .output()
        .await;

    match out {
        Err(e) => Verdict::NotChecked {
            reason: format!("cosign indisponible : {e}"),
        },
        Ok(o) if o.status.success() => Verdict::Clean,
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            // Distinguer « pas de signature » de « signature invalide » : le premier
            // est courant (beaucoup d'images ne sont pas signées), le second est une
            // alerte de sécurité.
            if err.contains("no matching signatures") || err.contains("no signatures found") {
                Verdict::NotChecked {
                    reason: "image non signée".into(),
                }
            } else {
                Verdict::Findings {
                    critical: 1,
                    high: 0,
                    detail: format!("signature INVALIDE : {}", err.trim()),
                }
            }
        }
    }
}

/// Le résultat combiné des deux contrôles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub image: String,
    pub vulnerabilities: Verdict,
    pub signature: Verdict,
}

impl Report {
    /// La mise à jour doit-elle être refusée sans intervention ?
    pub fn blocks(&self) -> bool {
        self.vulnerabilities.blocks() || self.signature.blocks()
    }

    /// Combien de contrôles n'ont pas eu lieu.
    pub fn unchecked(&self) -> usize {
        usize::from(!self.vulnerabilities.was_checked())
            + usize::from(!self.signature.was_checked())
    }

    pub fn describe(&self) -> String {
        format!(
            "{}\n  vulnérabilités : {}\n  signature      : {}",
            self.image,
            self.vulnerabilities.describe(),
            self.signature.describe()
        )
    }
}

/// Contrôle complet d'une image.
pub async fn audit(
    image: &str,
    identity_regexp: Option<&str>,
    issuer: Option<&str>,
) -> Result<Report> {
    Ok(Report {
        image: image.to_string(),
        vulnerabilities: scan_image(image).await,
        signature: verify_signature(image, identity_regexp, issuer).await,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_tool_is_never_a_pass() {
        // 🔴 Le piège central. Traiter « trivy absent » comme « rien trouvé » ferait
        // passer toutes les mises à jour en donnant l'impression d'être vérifiées —
        // pire que de ne pas scanner du tout.
        let v = Verdict::NotChecked { reason: "trivy indisponible".into() };

        assert!(!v.was_checked());
        assert!(!v.blocks(), "mais ça ne doit pas bloquer non plus");
        assert!(v.describe().contains("NON VÉRIFIÉ"), "{}", v.describe());
        assert!(
            v.describe().contains("pas la même chose"),
            "le message doit dire que ce n'est pas « propre »"
        );
    }

    #[test]
    fn a_clean_scan_and_an_unchecked_one_are_distinguishable() {
        assert!(Verdict::Clean.was_checked());
        assert!(!Verdict::NotChecked { reason: "x".into() }.was_checked());
        assert_ne!(Verdict::Clean, Verdict::NotChecked { reason: "x".into() });
    }

    #[test]
    fn only_critical_findings_block() {
        // Les failles élevées sont signalées, pas bloquantes : bloquer dessus
        // arrêterait pratiquement toutes les mises à jour d'images Debian, et
        // l'utilisateur finirait par désactiver le contrôle.
        let haute = Verdict::Findings { critical: 0, high: 12, detail: "x".into() };
        assert!(!haute.blocks());

        let crit = Verdict::Findings { critical: 1, high: 0, detail: "CVE-2026-1".into() };
        assert!(crit.blocks());
    }

    #[test]
    fn trivy_output_is_parsed() {
        let json = r#"{"Results":[{"Target":"app","Vulnerabilities":[
            {"VulnerabilityID":"CVE-2026-1111","Severity":"CRITICAL"},
            {"VulnerabilityID":"CVE-2026-2222","Severity":"HIGH"},
            {"VulnerabilityID":"CVE-2026-3333","Severity":"HIGH"}]}]}"#;

        match parse_trivy(json) {
            Verdict::Findings { critical, high, detail } => {
                assert_eq!(critical, 1);
                assert_eq!(high, 2);
                assert!(detail.contains("CVE-2026-1111"), "{detail}");
            }
            autre => panic!("attendu des trouvailles, obtenu {autre:?}"),
        }
    }

    #[test]
    fn an_empty_result_is_clean() {
        assert_eq!(parse_trivy(r#"{"Results":[]}"#), Verdict::Clean);
        // Trivy renvoie parfois `null` plutôt qu'un tableau vide.
        assert_eq!(parse_trivy(r#"{"Results":null}"#), Verdict::Clean);
    }

    #[test]
    fn unreadable_output_is_not_clean() {
        // 🔴 Le format de trivy change d'une version majeure à l'autre. L'interpréter
        // comme un succès désactiverait le contrôle en silence.
        assert!(!parse_trivy("pas du json").was_checked());
        assert!(!parse_trivy("").was_checked());
    }

    #[tokio::test]
    async fn verification_without_a_declared_signer_is_refused() {
        // 🔴 `cosign verify` sans identité accepte TOUTE signature valide : un
        // attaquant signe son image avec son propre compte et passe le contrôle.
        let v = verify_signature("alpine:3", None, None).await;
        assert!(!v.was_checked());
        assert!(v.describe().contains("identité"), "{}", v.describe());
    }

    #[test]
    fn a_report_counts_what_it_could_not_check() {
        let r = Report {
            image: "a/b:1".into(),
            vulnerabilities: Verdict::Clean,
            signature: Verdict::NotChecked { reason: "image non signée".into() },
        };
        assert_eq!(r.unchecked(), 1);
        assert!(!r.blocks(), "une image non signée ne bloque pas, elle se signale");
    }

    #[test]
    fn an_invalid_signature_blocks() {
        // Non signée ≠ mal signée. La seconde veut dire que quelqu'un a tenté
        // quelque chose.
        let r = Report {
            image: "a/b:1".into(),
            vulnerabilities: Verdict::Clean,
            signature: Verdict::Findings {
                critical: 1,
                high: 0,
                detail: "signature INVALIDE".into(),
            },
        };
        assert!(r.blocks());
    }
}
