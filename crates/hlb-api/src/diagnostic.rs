//! « Pourquoi cette app est-elle rouge ? » — la chaîne causale (lot 9.4).
//!
//! ## Ce que ça ajoute
//!
//! Les maillons existent tous, chacun sur son écran : la tâche en échec porte son
//! erreur, le nœud porte sa pression disque, la règle `disque-plein` s'est déclenchée.
//! Personne ne les relie, et c'est ce qui sépare un tableau de bord d'un diagnostic.
//!
//! ## 🔴 Une chaîne qu'on ne sait pas remonter s'arrête
//!
//! Elle s'arrête sur « cause inconnue », jamais sur une supposition. Un diagnostic
//! plausible mais faux coûte plus cher que pas de diagnostic du tout : on répare la
//! mauvaise chose, et on cesse ensuite de croire l'écran.

use serde::{Deserialize, Serialize};

use crate::{AlerteActive, AppDetail, NoeudSummary};

/// Un maillon de la chaîne.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Maillon {
    /// Le constat, en une phrase.
    pub constat: String,
    /// Ce qui le documente : identifiant de tâche, nom de nœud, nom de règle.
    #[serde(default)]
    pub source: Option<String>,
}

/// Le résultat d'un diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chaine {
    pub app: String,
    /// Du symptôme vers la cause. Vide quand il n'y a rien à expliquer.
    pub maillons: Vec<Maillon>,
    /// 🔴 Vrai quand la remontée s'est arrêtée sans atteindre une cause.
    ///
    /// Distinct d'une chaîne vide : « rien à expliquer » et « je ne sais pas
    /// expliquer » sont deux réponses opposées.
    pub cause_inconnue: bool,
    /// Le geste qui corrige, quand il y en a un.
    #[serde(default)]
    pub remede: Option<String>,
}

impl Chaine {
    /// Y a-t-il quelque chose à lire ?
    pub fn a_quelque_chose_a_dire(&self) -> bool {
        !self.maillons.is_empty()
    }

    /// La dernière ligne, celle qui conclut.
    pub fn conclusion(&self) -> String {
        if self.maillons.is_empty() {
            return format!("{} ne présente aucun symptôme.", self.app);
        }
        if self.cause_inconnue {
            // ⚠️ Le dire franchement. Une chaîne qui s'arrête en silence se lit comme
            // une chaîne complète, et la dernière hypothèse passe pour la cause.
            return "La cause n'a pas pu être remontée plus loin. Les journaux du \
                    service sont la prochaine étape."
                .to_string();
        }
        self.maillons
            .last()
            .map(|m| m.constat.clone())
            .unwrap_or_default()
    }
}

/// Palier de pression disque à partir duquel on tient le disque pour responsable.
const PRESSION_COUPABLE: u8 = 3;

/// Remonte la chaîne, du symptôme vers la cause.
pub fn expliquer(app: &AppDetail, noeuds: &[NoeudSummary], alertes: &[AlerteActive]) -> Chaine {
    let nom = app.resume.name.clone();
    let mut maillons = Vec::new();

    // --- Maillon 1 : le symptôme ---------------------------------------------
    let echouees: Vec<_> = app.taches.iter().filter(|t| t.echouee).collect();
    let vivantes = app.taches.iter().filter(|t| t.vivante).count();

    if app.resume.status == "running" && echouees.is_empty() {
        // Rien à expliquer. Une chaîne fabriquée pour une app saine ferait chercher un
        // problème qui n'existe pas.
        return Chaine {
            app: nom,
            maillons: Vec::new(),
            cause_inconnue: false,
            remede: None,
        };
    }

    maillons.push(Maillon {
        constat: match (vivantes, echouees.len()) {
            (0, 0) => format!("{nom} n'a aucun réplica en vie."),
            (0, n) => format!(
                "{nom} n'a aucun réplica en vie, et {} en échec.",
                crate::plural(n as u64, "réplica", "réplicas")
            ),
            (v, 0) => format!(
                "{nom} tourne avec {}, mais son état est « {} ».",
                crate::plural(v as u64, "réplica", "réplicas"),
                app.resume.status
            ),
            (v, n) => format!(
                "{nom} tourne avec {}, et {} en échec.",
                crate::plural(v as u64, "réplica", "réplicas"),
                crate::plural(n as u64, "réplica", "réplicas")
            ),
        },
        source: None,
    });

    // --- Maillon 2 : ce que dit Swarm ----------------------------------------
    //
    // 🔴 C'est le champ que l'ancien compteur de tâches jetait. Sans lui, la chaîne
    // s'arrêtait au premier maillon.
    let explication = echouees.iter().find_map(|t| t.explication.as_ref());
    if let Some(e) = explication {
        maillons.push(Maillon {
            constat: format!("Swarm rapporte : {e}"),
            source: echouees.first().map(|t| t.id.clone()),
        });
    }

    // --- Maillon 3 : le nœud qui portait la tâche ----------------------------
    let noeud_id = echouees
        .iter()
        .find_map(|t| t.noeud.clone())
        .or_else(|| app.taches.iter().find_map(|t| t.noeud.clone()));

    let noeud = noeud_id.as_ref().and_then(|id| {
        noeuds
            .iter()
            .find(|n| n.adresse == *id || n.hostname.as_deref() == Some(id.as_str()))
    });

    let mut cause_trouvee = false;
    let mut remede = None;

    if let Some(n) = noeud {
        let nom_noeud = n.hostname.clone().unwrap_or_else(|| n.adresse.clone());

        if !n.joignable {
            maillons.push(Maillon {
                constat: format!(
                    "Le nœud {nom_noeud} est injoignable{}.",
                    n.detail
                        .as_ref()
                        .map(|d| format!(" : {d}"))
                        .unwrap_or_default()
                ),
                source: Some(n.adresse.clone()),
            });
            cause_trouvee = true;
            remede = Some(format!(
                "Vérifier la machine et l'agent : hlb node show {nom_noeud}"
            ));
        } else if let Some(d) = n
            .disques
            .iter()
            .filter(|d| d.pression >= PRESSION_COUPABLE)
            .max_by_key(|d| d.pression)
        {
            maillons.push(Maillon {
                constat: format!(
                    "Le nœud {nom_noeud} manque d'espace sur {} : {} % occupés, {} Mo libres.",
                    d.chemin,
                    // ⚠️ `utilise` est une FRACTION, pas un pourcentage. L'afficher tel
                    // quel donnerait « 1 % occupés » sur un disque plein à 96 %.
                    (d.utilise * 100.0).round() as i64,
                    d.libre_mb
                ),
                source: Some(n.adresse.clone()),
            });
            cause_trouvee = true;
            remede = Some(format!(
                "Libérer de l'espace sur {} du nœud {nom_noeud}, ou déplacer l'app.",
                d.chemin
            ));
        }
    }

    // --- Maillon 4 : la règle d'alerte qui l'a vu ----------------------------
    //
    // ⚠️ On ne rattache une alerte QUE si le constat du nœud la corrobore. Une règle
    // globale qui se déclenche en même temps n'est pas une cause, et l'accrocher ici
    // fabriquerait un lien qui n'existe pas.
    if cause_trouvee {
        let regle_attendue = if noeud.is_some_and(|n| !n.joignable) {
            "noeud-injoignable"
        } else {
            "disque-plein"
        };
        if let Some(a) = alertes.iter().find(|a| a.regle == regle_attendue) {
            maillons.push(Maillon {
                constat: format!("La règle « {} » l'a signalé : {}", a.regle, a.explication),
                source: Some(a.regle.clone()),
            });
        }
    }

    Chaine {
        app: nom,
        maillons,
        cause_inconnue: !cause_trouvee,
        remede,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppSummary, DisqueSummary, NiveauAlerte, TacheSummary};

    fn app(nom: &str, status: &str, taches: Vec<TacheSummary>) -> AppDetail {
        AppDetail {
            diagnostic: None,
            resume: AppSummary {
                name: nom.into(),
                status: status.into(),
                image: "a/b:1".into(),
                domain: None,
                last_backup_secs: None,
                last_verification_secs: None,
                blocking_guides: 0,
            },
            taches,
            capacites: Vec::new(),
            volumes: Vec::new(),
            env: Vec::new(),
            guides: Vec::new(),
            couverture: None,
            sauvegardes: Vec::new(),
            restaurabilite: None,
            journal: Vec::new(),
            image: None,
            domaine: None,
            manifest: None,
        }
    }

    fn tache(id: &str, noeud: Option<&str>, echouee: bool, err: Option<&str>) -> TacheSummary {
        TacheSummary {
            id: id.into(),
            service: "svc".into(),
            slot: Some(1),
            noeud: noeud.map(str::to_string),
            etat: if echouee {
                "failed".into()
            } else {
                "running".into()
            },
            etat_voulu: "running".into(),
            vivante: !echouee,
            echouee,
            explication: err.map(str::to_string),
            image: None,
        }
    }

    fn noeud(adresse: &str, joignable: bool, pression: u8) -> NoeudSummary {
        NoeudSummary {
            adresse: adresse.into(),
            hostname: Some(adresse.into()),
            joignable,
            detail: (!joignable).then(|| "agent muet depuis 4 min".to_string()),
            rapport_age_s: Some(30),
            cpu_occupation: None,
            charge_par_coeur: None,
            memoire_utilisee: None,
            swap_utilise: None,
            disques: vec![DisqueSummary {
                chemin: "/".into(),
                utilise: 0.96,
                total_mb: 100_000,
                libre_mb: 4_000,
                pression,
            }],
            uptime_s: None,
            distro: None,
            noyau: None,
            agent_version: None,
            protocole: Some(2),
            taches: Vec::new(),
        }
    }

    fn alerte(regle: &str) -> AlerteActive {
        AlerteActive {
            regle: regle.into(),
            niveau: NiveauAlerte::Critique,
            explication: format!("la règle {regle} est franchie"),
            valeur: Some(1.0),
            seuil: 0.0,
            depuis_s: 600,
            silencee_jusqu_a: None,
            silencee_par: None,
        }
    }

    #[test]
    fn a_healthy_app_gets_no_fabricated_chain() {
        // Une chaîne inventée pour une app saine ferait chercher un problème inexistant.
        let a = app(
            "gitea",
            "running",
            vec![tache("t1", Some("n1"), false, None)],
        );
        let c = expliquer(&a, &[noeud("n1", true, 0)], &[]);
        assert!(!c.a_quelque_chose_a_dire());
        assert!(!c.cause_inconnue);
        assert!(c.conclusion().contains("aucun symptôme"));
    }

    #[test]
    fn the_chain_goes_from_the_symptom_all_the_way_to_the_disk() {
        // 🔴 Le propos du lot : les quatre maillons existaient chacun sur son écran.
        let a = app(
            "immich",
            "failed",
            vec![tache(
                "t1",
                Some("n1"),
                true,
                Some("no space left on device"),
            )],
        );
        let c = expliquer(&a, &[noeud("n1", true, 4)], &[alerte("disque-plein")]);

        assert_eq!(c.maillons.len(), 4, "{:#?}", c.maillons);
        assert!(c.maillons[0].constat.contains("aucun réplica en vie"));
        assert!(c.maillons[1].constat.contains("no space left"));
        assert!(c.maillons[2].constat.contains("manque d'espace"));
        // ⚠️ Le pourcentage, pas la fraction : « 1 % occupés » sur un disque plein
        // ferait chercher ailleurs.
        assert!(
            c.maillons[2].constat.contains("96 %"),
            "{:?}",
            c.maillons[2]
        );
        assert!(c.maillons[3].constat.contains("disque-plein"));
        assert!(!c.cause_inconnue);
        assert!(c.remede.is_some());
    }

    #[test]
    fn an_unexplained_failure_stops_honestly() {
        // 🔴 Le cœur du lot : une chaîne qu'on ne sait pas remonter s'arrête sur
        // « cause inconnue », jamais sur une supposition. Réparer la mauvaise chose
        // coûte plus cher que ne pas savoir.
        let a = app(
            "n8n",
            "failed",
            vec![tache("t1", Some("n1"), true, Some("exit code 1"))],
        );
        // Le nœud va parfaitement bien : rien n'explique l'échec.
        let c = expliquer(&a, &[noeud("n1", true, 0)], &[alerte("app-en-echec")]);

        assert!(c.cause_inconnue);
        assert!(c.remede.is_none(), "aucun remède ne doit être inventé");
        assert!(c.conclusion().contains("journaux"), "{}", c.conclusion());
        // Et surtout : l'alerte présente n'est PAS accrochée comme une cause.
        assert!(
            !c.maillons.iter().any(|m| m.constat.contains("règle")),
            "{:#?}",
            c.maillons
        );
    }

    #[test]
    fn an_unreachable_node_is_named_as_the_cause() {
        let a = app("gitea", "failed", vec![tache("t1", Some("n1"), true, None)]);
        let c = expliquer(&a, &[noeud("n1", false, 0)], &[alerte("noeud-injoignable")]);

        assert!(!c.cause_inconnue);
        assert!(c.maillons.iter().any(|m| m.constat.contains("injoignable")));
        assert!(c.maillons.iter().any(|m| m.constat.contains("agent muet")));
        assert!(c
            .remede
            .as_deref()
            .is_some_and(|r| r.contains("hlb node show")));
    }

    #[test]
    fn nothing_to_explain_is_not_the_same_as_cannot_explain() {
        // Deux réponses opposées que le même « chaîne vide » confondrait.
        let saine = expliquer(
            &app(
                "gitea",
                "running",
                vec![tache("t", Some("n1"), false, None)],
            ),
            &[noeud("n1", true, 0)],
            &[],
        );
        let opaque = expliquer(
            &app("gitea", "failed", vec![tache("t", Some("n1"), true, None)]),
            &[noeud("n1", true, 0)],
            &[],
        );

        assert!(!saine.cause_inconnue && !saine.a_quelque_chose_a_dire());
        assert!(opaque.cause_inconnue && opaque.a_quelque_chose_a_dire());
        assert_ne!(saine.conclusion(), opaque.conclusion());
    }

    #[test]
    fn a_partially_running_app_is_still_explained() {
        // « partial » : des réplicas vivent, d'autres échouent. C'est le cas qu'on rate
        // en ne regardant que « l'app tourne-t-elle ? ».
        let a = app(
            "seafile",
            "partial",
            vec![
                tache("t1", Some("n1"), false, None),
                tache("t2", Some("n1"), true, Some("OOMKilled")),
            ],
        );
        let c = expliquer(&a, &[noeud("n1", true, 0)], &[]);
        assert!(c.a_quelque_chose_a_dire());
        assert!(
            c.maillons[0].constat.contains("1 réplica"),
            "{:?}",
            c.maillons[0]
        );
        assert!(c.maillons[1].constat.contains("OOMKilled"));
    }

    #[test]
    fn an_unknown_node_never_invents_a_cause() {
        // Le nœud a disparu de l'inventaire : on ne peut rien en dire, et le supposer
        // sain comme le supposer mort serait également faux.
        let a = app(
            "gitea",
            "failed",
            vec![tache("t1", Some("parti"), true, None)],
        );
        let c = expliquer(&a, &[noeud("n1", true, 0)], &[]);
        assert!(c.cause_inconnue);
        assert!(c.remede.is_none());
    }
}
