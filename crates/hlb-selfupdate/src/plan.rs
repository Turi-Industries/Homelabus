//! La séquence de mise à jour, et son retour arrière (§7bis).
//!
//! ## 🔴 La règle d'or
//!
//! > Le controller ne se met **jamais** à jour lui-même en une seule étape.
//! > Il prépare, valide, bascule, et garde la possibilité de revenir en arrière.
//!
//! ## Pourquoi l'ordre est celui-là et pas un autre
//!
//! ```text
//! 1. Sauvegarde de l'état       ← sans elle, un échec en 4 est définitif
//! 2. Compatibilité              ← avant d'avoir touché à quoi que ce soit
//! 3. Agents, un nœud à la fois  ← un agent cassé ne casse pas les autres
//! 4. Controller                 ← en dernier : c'est lui qui pilote les étapes 1-3
//! 5. Vérification post-bascule  ← sinon on ne sait pas si ça a marché
//! ```
//!
//! **Le controller en dernier**, parce que c'est lui qui exécute les étapes
//! précédentes. Se remplacer d'abord reviendrait à scier la branche : si la nouvelle
//! version ne démarre pas, il ne reste plus rien pour mettre à jour les agents ni
//! pour revenir en arrière.
//!
//! **Un agent à la fois**, parce qu'un agent injoignable n'empêche pas le cluster de
//! fonctionner (les services tournent sous Swarm, pas sous Homelabus), alors que dix
//! agents cassés simultanément aveuglent complètement la supervision.
//!
//! ## 🔴 Ce qui rend le retour arrière possible — ou impossible
//!
//! Le binaire se remplace facilement. **Le schéma de base, non.** Si la version N+1
//! migre la base et qu'on revient au binaire N, celui-ci lit un schéma qu'il ne
//! comprend pas. C'est l'état dont on ne peut plus sortir.
//!
//! D'où deux exigences non négociables, vérifiées par [`Preflight`] :
//!
//! - toute migration a son inverse (`down`), sinon la mise à jour est **refusée** ;
//! - l'état est exporté avant la migration, pas après.

use crate::version::{compatible, Compatibility, Jump, Version};

/// Un nœud du parc, avec la version de son agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentNode {
    pub node: String,
    /// `None` = agent injoignable.
    pub version: Option<Version>,
}

/// Ce qui empêche de commencer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocker {
    /// 🔴 Une migration ne sait pas revenir en arrière.
    IrreversibleMigration { name: String },
    /// Versions incompatibles.
    Incompatible { detail: String },
    /// 🔴 Des agents ne répondent pas : on ne met pas à jour à l'aveugle.
    UnreachableAgents { nodes: Vec<String> },
    /// Aucune sauvegarde de l'état : un échec serait définitif.
    NoStateBackup,
    /// Rien à faire.
    AlreadyCurrent,
}

impl Blocker {
    pub fn describe(&self) -> String {
        match self {
            Self::IrreversibleMigration { name } => format!(
                "🔴 la migration « {name} » n'a pas d'inverse. Si la nouvelle version \
                 échoue, le binaire précédent lira un schéma qu'il ne comprend pas — \
                 et il n'y aura plus de retour possible. Écris le `down` d'abord."
            ),
            Self::Incompatible { detail } => detail.clone(),
            Self::UnreachableAgents { nodes } => format!(
                "🔴 {} agent(s) injoignable(s) : {}. On ne met pas à jour un parc \
                 qu'on ne voit pas — les nœuds muets resteraient en version N sans \
                 qu'on sache s'ils fonctionnent.",
                nodes.len(),
                nodes.join(", ")
            ),
            Self::NoStateBackup => "🔴 aucune sauvegarde de l'état : un échec en \
                 cours de migration serait définitif. Lance `hlb backup run --force` \
                 d'abord."
                .to_string(),
            Self::AlreadyCurrent => "déjà à jour".to_string(),
        }
    }

    /// Est-ce un refus de sécurité, ou simplement « rien à faire » ?
    pub fn is_refusal(&self) -> bool {
        !matches!(self, Self::AlreadyCurrent)
    }
}

/// Une migration de schéma et son inverse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    pub name: String,
    /// 🔴 `false` = pas de `down`. Bloque la mise à jour.
    pub reversible: bool,
}

/// Tout ce qu'on sait avant de décider.
#[derive(Debug, Clone)]
pub struct Preflight {
    pub from: Version,
    pub to: Version,
    pub agents: Vec<AgentNode>,
    pub migrations: Vec<Migration>,
    /// L'état a-t-il été sauvegardé récemment ?
    pub state_backed_up: bool,
}

/// La séquence à exécuter.
#[derive(Debug, Clone)]
pub struct UpdatePlan {
    pub from: Version,
    pub to: Version,
    pub jump: Jump,
    /// Nœuds à mettre à jour, dans l'ordre.
    ///
    /// ⚠️ Trié par nom : une mise à jour qui prendrait les nœuds dans un ordre
    /// variable rendrait un incident irreproductible.
    pub agents: Vec<String>,
    pub migrations: Vec<Migration>,
}

impl UpdatePlan {
    pub fn describe(&self) -> String {
        let mut s = format!(
            "Mise à jour {} → {} ({})\n",
            self.from,
            self.to,
            self.jump.describe()
        );
        s.push_str(&format!(
            "  1. sauvegarde de l'état\n  2. {} agent(s), un à la fois : {}\n",
            self.agents.len(),
            if self.agents.is_empty() {
                "aucun".to_string()
            } else {
                self.agents.join(", ")
            }
        ));
        s.push_str(&format!(
            "  3. controller EN DERNIER ({} migration(s) réversible(s))\n",
            self.migrations.len()
        ));
        s.push_str("  4. réconciliation à blanc pour vérifier\n");
        s
    }
}

/// Décide si la mise à jour peut commencer, et comment.
///
/// 🔴 L'ordre des contrôles n'est pas indifférent : on vérifie ce qui rend le RETOUR
/// impossible avant ce qui rend la mise à jour inutile. Découvrir qu'une migration est
/// irréversible après avoir migré serait précisément trop tard.
pub fn plan(p: &Preflight) -> Result<UpdatePlan, Blocker> {
    // 1. Ce qui condamne le retour arrière, d'abord.
    if let Some(m) = p.migrations.iter().find(|m| !m.reversible) {
        return Err(Blocker::IrreversibleMigration {
            name: m.name.clone(),
        });
    }

    // 2. Puis ce qui rend l'opération inutile ou dangereuse.
    let jump = Jump::between(p.from, p.to);
    if jump == Jump::None {
        return Err(Blocker::AlreadyCurrent);
    }
    if jump == Jump::Downgrade {
        return Err(Blocker::Incompatible {
            detail: format!(
                "🔴 {} est ANTÉRIEURE à {} — ce n'est pas une mise à jour. Pour \
                 revenir en arrière, utilise `hlb self rollback`, qui restaure aussi \
                 le schéma.",
                p.to, p.from
            ),
        });
    }

    if !p.state_backed_up {
        return Err(Blocker::NoStateBackup);
    }

    // 3. Les agents muets : on ne met pas à jour un parc qu'on ne voit pas.
    let muets: Vec<String> = p
        .agents
        .iter()
        .filter(|a| a.version.is_none())
        .map(|a| a.node.clone())
        .collect();
    if !muets.is_empty() {
        return Err(Blocker::UnreachableAgents { nodes: muets });
    }

    // 4. Chaque agent doit pouvoir parler au controller cible.
    for a in &p.agents {
        let Some(v) = a.version else { continue };
        if let Compatibility::Incompatible { reason } = compatible(v, p.to) {
            return Err(Blocker::Incompatible {
                detail: format!("{} : {reason}", a.node),
            });
        }
    }

    let mut agents: Vec<String> = p.agents.iter().map(|a| a.node.clone()).collect();
    // Ordre stable : un incident doit être reproductible.
    agents.sort();

    Ok(UpdatePlan {
        from: p.from,
        to: p.to,
        jump,
        agents,
        migrations: p.migrations.clone(),
    })
}

/// Ce qu'on garde pour pouvoir revenir.
///
/// ⚠️ Le binaire précédent est **conservé sur disque**, pas retéléchargé : le jour où
/// l'on a besoin d'un retour arrière, c'est souvent parce que quelque chose ne va pas
/// — et le réseau peut en faire partie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rollback {
    pub previous_version: Version,
    pub previous_binary: std::path::PathBuf,
    /// Export de l'état avant migration.
    pub state_export: std::path::PathBuf,
    /// Migrations à défaire, **dans l'ordre inverse** de leur application.
    pub undo: Vec<Migration>,
}

impl Rollback {
    /// Les migrations à défaire, dans le bon ordre.
    ///
    /// 🔴 L'ordre inverse est obligatoire : une migration qui ajoute une colonne
    /// référencée par la suivante doit être défaite **après** elle. Les défaire dans
    /// l'ordre d'application échouerait sur une contrainte, à mi-chemin, laissant un
    /// schéma qui n'est ni l'ancien ni le nouveau.
    pub fn undo_order(&self) -> Vec<&Migration> {
        self.undo.iter().rev().collect()
    }

    pub fn describe(&self) -> String {
        format!(
            "Retour à {} :\n  binaire  : {}\n  état     : {}\n  {} migration(s) à défaire",
            self.previous_version,
            self.previous_binary.display(),
            self.state_export.display(),
            self.undo.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migration(nom: &str, reversible: bool) -> Migration {
        Migration {
            name: nom.into(),
            reversible,
        }
    }

    fn preflight() -> Preflight {
        Preflight {
            from: Version::new(0, 1, 0),
            to: Version::new(0, 2, 0),
            agents: vec![
                AgentNode {
                    node: "node2".into(),
                    version: Some(Version::new(0, 1, 0)),
                },
                AgentNode {
                    node: "node1".into(),
                    version: Some(Version::new(0, 1, 0)),
                },
            ],
            migrations: vec![migration("0007_truc", true)],
            state_backed_up: true,
        }
    }

    #[test]
    fn an_irreversible_migration_blocks_everything() {
        // 🔴 LE contrôle qui compte. Sans `down`, un échec de la version N+1 laisse
        // la base dans un état que le binaire N ne comprend pas — et il n'y a plus
        // de sortie.
        let mut p = preflight();
        p.migrations.push(migration("0008_sans_retour", false));

        let e = plan(&p).unwrap_err();
        assert_eq!(
            e,
            Blocker::IrreversibleMigration {
                name: "0008_sans_retour".into()
            }
        );
        assert!(e.describe().contains("plus de retour possible"), "{}", e.describe());
    }

    #[test]
    fn reversibility_is_checked_before_anything_else() {
        // Découvrir qu'une migration est irréversible APRÈS avoir migré serait trop
        // tard. Même avec une version identique et aucun agent, c'est ce contrôle
        // qui doit parler en premier.
        let p = Preflight {
            to: Version::new(0, 1, 0),
            agents: vec![],
            migrations: vec![migration("x", false)],
            state_backed_up: false,
            ..preflight()
        };
        assert!(matches!(
            plan(&p).unwrap_err(),
            Blocker::IrreversibleMigration { .. }
        ));
    }

    #[test]
    fn updating_without_a_state_backup_is_refused() {
        // Un échec en cours de migration serait définitif.
        let p = Preflight {
            state_backed_up: false,
            ..preflight()
        };
        let e = plan(&p).unwrap_err();
        assert_eq!(e, Blocker::NoStateBackup);
        assert!(e.describe().contains("backup run"), "l'erreur doit dire quoi faire");
    }

    #[test]
    fn a_mute_agent_stops_the_update() {
        // 🔴 On ne met pas à jour un parc qu'on ne voit pas : les nœuds muets
        // resteraient en version N sans qu'on sache s'ils fonctionnent.
        let mut p = preflight();
        p.agents.push(AgentNode {
            node: "node3".into(),
            version: None,
        });

        let e = plan(&p).unwrap_err();
        assert_eq!(
            e,
            Blocker::UnreachableAgents {
                nodes: vec!["node3".into()]
            }
        );
        assert!(e.describe().contains("parc qu'on ne voit pas"));
    }

    #[test]
    fn a_downgrade_is_redirected_to_rollback() {
        // 🔴 Le faire passer pour une mise à jour laisserait la base en schéma N+1
        // sous un binaire N — l'état dont on ne peut plus sortir.
        let p = Preflight {
            from: Version::new(0, 3, 0),
            to: Version::new(0, 2, 0),
            ..preflight()
        };
        let e = plan(&p).unwrap_err();
        assert!(e.describe().contains("hlb self rollback"), "{}", e.describe());
    }

    #[test]
    fn being_current_is_not_a_refusal() {
        // « Rien à faire » ne doit pas ressembler à « on t'a empêché » : un code de
        // sortie en échec ferait croire à un problème dans un script de mise à jour.
        let p = Preflight {
            to: Version::new(0, 1, 0),
            ..preflight()
        };
        let e = plan(&p).unwrap_err();
        assert_eq!(e, Blocker::AlreadyCurrent);
        assert!(!e.is_refusal());
    }

    #[test]
    fn a_major_mismatch_names_the_node() {
        // Sur un parc de dix machines, savoir LAQUELLE bloque évite de les
        // inspecter une par une.
        let mut p = preflight();
        p.to = Version::new(1, 0, 0);
        let e = plan(&p).unwrap_err();
        assert!(e.describe().contains("node"), "{}", e.describe());
    }

    #[test]
    fn agents_are_updated_in_a_stable_order() {
        // ⚠️ Un ordre variable rendrait un incident irreproductible : « ça a cassé
        // au troisième nœud » ne veut rien dire si le troisième change.
        let p = plan(&preflight()).expect("plan");
        assert_eq!(p.agents, vec!["node1", "node2"]);
    }

    #[test]
    fn the_plan_puts_the_controller_last() {
        // 🔴 Le controller exécute les étapes précédentes. Se remplacer d'abord
        // reviendrait à scier la branche : si la nouvelle version ne démarre pas, il
        // ne reste plus rien pour mettre à jour les agents ni pour revenir.
        let d = plan(&preflight()).expect("plan").describe();
        let i_agents = d.find("agent(s)").expect("agents");
        let i_ctrl = d.find("controller").expect("controller");
        assert!(i_agents < i_ctrl, "les agents doivent précéder le controller :\n{d}");
        assert!(d.contains("EN DERNIER"), "{d}");
    }

    #[test]
    fn migrations_are_undone_in_reverse_order() {
        // 🔴 Une migration qui ajoute une colonne référencée par la suivante doit
        // être défaite APRÈS elle. L'ordre d'application échouerait à mi-chemin,
        // laissant un schéma qui n'est ni l'ancien ni le nouveau.
        let r = Rollback {
            previous_version: Version::new(0, 1, 0),
            previous_binary: "/opt/hlb/hlb-0.1.0".into(),
            state_export: "/var/lib/hlb/avant-0.2.0.sql".into(),
            undo: vec![
                migration("0007_colonne", true),
                migration("0008_index_sur_colonne", true),
            ],
        };

        let ordre: Vec<&str> = r.undo_order().iter().map(|m| m.name.as_str()).collect();
        assert_eq!(ordre, vec!["0008_index_sur_colonne", "0007_colonne"]);
    }

    #[test]
    fn the_previous_binary_is_kept_on_disk() {
        // ⚠️ Le jour où l'on a besoin d'un retour arrière, c'est souvent parce que
        // quelque chose ne va pas — et le réseau peut en faire partie.
        let r = Rollback {
            previous_version: Version::new(0, 1, 0),
            previous_binary: "/opt/hlb/hlb-0.1.0".into(),
            state_export: "/var/lib/hlb/avant.sql".into(),
            undo: vec![],
        };
        assert!(r.describe().contains("/opt/hlb/hlb-0.1.0"));
        assert!(r.describe().contains("/var/lib/hlb/avant.sql"));
    }
}
