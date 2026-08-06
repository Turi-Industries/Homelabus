//! Le plan d'exécution : ce que HomelabUS **va** faire, avant de le faire.
//!
//! C'est la sortie de `--dry-run`, et le principe directeur du §2ter.4 : *tu valides un
//! plan, tu ne subis pas un script*. Rien ne doit être modifié sans être annoncé.
//!
//! Le plan est aussi un objet de test : en CI, on vérifie qu'il ne change pas de façon
//! inattendue entre deux versions (§12bis).

use std::fmt;

use hlb_types::{DbEngine, StorageTier};

/// Une action atomique. Volontairement descriptive : l'exécution est ailleurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// §3.1 — une base + un rôle par app, jamais de superuser partagé.
    ProvisionDatabase {
        engine: DbEngine,
        database: String,
        role: String,
        /// Le secret qui porte le mot de passe. Il doit être généré AVANT.
        password_secret: String,
    },

    /// Mot de passe généré aléatoirement, jamais saisi, jamais dans le Git.
    GenerateSecret { name: String, purpose: String },

    /// §5.2 — le client OIDC est créé dans PocketID, pas à la main.
    CreateOidcClient {
        app: String,
        redirect_uris: Vec<String>,
    },

    CreateVolume {
        name: String,
        path: String,
        tier: StorageTier,
        backup: bool,
    },

    ProvisionMailAccount {
        address: String,
        aliases: bool,
    },

    DeployService {
        name: String,
        image: String,
        replicas: u64,
        constraints: Vec<String>,
        /// §9 — durcissement, transporté depuis le manifest jusqu'à Swarm.
        hardening: hlb_types::SecuritySpec,
        /// Sans sonde, `wait_healthy` ne sait que compter des tâches en cours.
        healthcheck: Option<hlb_types::Healthcheck>,
    },

    /// §7 — le catalogue déclare un tag ; le digest est résolu contre le registre
    /// puis figé. Un tag est mutable, un digest ne l'est pas.
    ResolveDigest { repo: String, tag: String },

    /// Attente explicite : Swarm n'a pas de `depends_on` (§4.7).
    WaitHealthy { name: String, timeout_secs: u64 },

    ConfigureIngress {
        host: String,
        service: String,
        port: u16,
        chain: Vec<String>,
        /// §4.6bis — pas d'exposition publique avant validation du guide.
        public: bool,
    },

    /// §4.6 — une action que l'utilisateur devra faire lui-même.
    PendingGuideStep {
        id: String,
        title: String,
        blocking: bool,
    },
}

impl Action {
    /// Une action qui modifie quelque chose hors du cluster, ou qui est coûteuse à
    /// annuler. Sert à colorer le plan et à décider ce qui demande confirmation.
    pub fn is_mutating(&self) -> bool {
        !matches!(self, Self::WaitHealthy { .. } | Self::PendingGuideStep { .. })
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProvisionDatabase { engine, database, role, password_secret } => write!(
                f,
                "créer la base {database} sur {} avec le rôle {role} (isolé, mot de passe {password_secret})",
                engine.service_name()
            ),
            Self::GenerateSecret { name, purpose } => {
                write!(f, "générer le secret {name} ({purpose})")
            }
            Self::CreateOidcClient { app, redirect_uris } => write!(
                f,
                "créer le client OIDC « {app} » dans PocketID → {}",
                redirect_uris.join(", ")
            ),
            Self::CreateVolume { name, path, tier, backup } => write!(
                f,
                "créer le volume {name} sur {path} (tier {tier:?}, sauvegarde {})",
                if *backup { "activée" } else { "désactivée" }
            ),
            Self::ProvisionMailAccount { address, aliases } => write!(
                f,
                "créer la boîte {address}{}",
                if *aliases { " avec aliases" } else { "" }
            ),
            Self::DeployService { name, image, replicas, constraints, hardening, healthcheck } => {
                write!(f, "déployer {name} ×{replicas} depuis {image}")?;
                if !constraints.is_empty() {
                    write!(f, " [{}]", constraints.join(", "))?;
                }
                // Le durcissement figure dans le plan : il doit être visible avant
                // application, pas découvert après coup.
                let mut d = Vec::new();
                if hardening.read_only_rootfs { d.push("rootfs ro".to_string()); }
                if hardening.no_new_privileges { d.push("no-new-privileges".to_string()); }
                if !hardening.cap_drop.is_empty() {
                    d.push(format!("cap_drop {}", hardening.cap_drop.join("+")));
                }
                if healthcheck.is_some() { d.push("sonde".to_string()); }
                if !d.is_empty() {
                    write!(f, " ({})", d.join(", "))?;
                }
                Ok(())
            }
            Self::ResolveDigest { repo, tag } => {
                write!(f, "résoudre le digest de {repo}:{tag} contre le registre")
            }
            Self::WaitHealthy { name, timeout_secs } => {
                write!(f, "attendre que {name} soit sain (max {timeout_secs} s)")
            }
            Self::ConfigureIngress { host, service, port, chain, public } => write!(
                f,
                "router {host} → {service}:{port} via {} ({})",
                if chain.is_empty() { "direct".to_string() } else { chain.join(" → ") },
                if *public { "public" } else { "VPN uniquement" }
            ),
            Self::PendingGuideStep { id, title, blocking } => write!(
                f,
                "{} action manuelle « {title} » [{id}]",
                if *blocking { "🔴" } else { "🟠" }
            ),
        }
    }
}

/// La liste ordonnée des actions, telle qu'elle sera exécutée.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub actions: Vec<Action>,
}

impl Plan {
    pub fn push(&mut self, a: Action) {
        self.actions.push(a);
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Les actions manuelles bloquantes. Si cette liste n'est pas vide, l'installation
    /// ne doit pas démarrer (§4.6).
    pub fn blocking_steps(&self) -> Vec<&Action> {
        self.actions
            .iter()
            .filter(|a| matches!(a, Action::PendingGuideStep { blocking: true, .. }))
            .collect()
    }

    pub fn mutating_count(&self) -> usize {
        self.actions.iter().filter(|a| a.is_mutating()).count()
    }
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return writeln!(f, "Aucune action : l'état désiré est déjà atteint.");
        }
        writeln!(
            f,
            "{} action(s), dont {} modifiante(s) :\n",
            self.len(),
            self.mutating_count()
        )?;
        for (i, a) in self.actions.iter().enumerate() {
            writeln!(f, "  {:>2}. {a}", i + 1)?;
        }
        let blocking = self.blocking_steps();
        if !blocking.is_empty() {
            writeln!(
                f,
                "\n🔴 {} action(s) manuelle(s) bloquante(s) : l'installation ne démarrera pas avant.",
                blocking.len()
            )?;
        }
        Ok(())
    }
}
