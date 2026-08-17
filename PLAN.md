# HomelabUS — Plan d'architecture

> Plateforme de gestion d'un cluster Docker Swarm self-hosted : déploiement d'apps,
> bases de données mutualisées, SSO, reverse proxy, sécurité, backups et mises à jour
> automatiques.

---

## 1. Choix du langage

### ✅ Décision : **Rust** pour le cœur, **SvelteKit** pour l'UI web

#### Pourquoi Rust gagne sur ce projet précis

Le déclencheur n'est pas la performance (il n'y a aucun calcul intensif ici), c'est
que **ce système est essentiellement une machine à états sur de la config typée** —
exactement le terrain où le système de types de Rust rapporte.

**1. Le résolveur de capacités devient sûr par construction.**

```rust
enum Capability {
    Database { engine: DbEngine, name: String },
    Cache    { engine: CacheEngine, dedicated: bool },
    Sso      { kind: SsoKind, redirect: String },
    Smtp,
    Storage  { tier: StorageTier, backup: bool },
}
```
Le jour où tu ajoutes `Capability::ObjectStore`, **le compilateur t'énumère les 14
endroits à mettre à jour**. En Go, tu l'oublies dans le générateur de Caddyfile et tu
le découvres en production trois semaines plus tard.

**2. Les transitions de déploiement illégales deviennent inexprimables.**

```rust
enum DeployState {
    Planned, BackingUp, Deploying,
    Verifying { deadline: Instant },
    Rollback { reason: FailureReason },
    Done,
}
```
Sur un système qui met à jour tes services tout seul à 3h du matin avec rollback
automatique, c'est là que la sûreté paie vraiment.

**3. `#[serde(deny_unknown_fields)]` valide tes manifests au parsing.**
Une faute de frappe (`replicas:` écrit `replica:`) est rejetée immédiatement avec
la ligne exacte, au lieu d'être silencieusement ignorée. Pour un système entièrement
piloté par du YAML, c'est décisif.

**4. `sqlx` vérifie tes requêtes SQL à la compilation**, contre le vrai schéma.
Pas d'ORM, du vrai SQL, mais aucune requête cassée ne compile.

**5. `minijinja` corrige le point faible que j'avais reproché à Go.**
Templating façon Jinja2 (même auteur que Flask) pour générer compose et Caddyfile —
bien plus expressif que `text/template`.

#### Les vrais coûts, sans enrobage

| Problème | Gravité | Mitigation |
|---|---|---|
| `bollard` moins éprouvé que le SDK Go sur la partie Swarm | 🔴 le risque principal | Trait `Orchestrator` dès le jour 1 (§2). En cas de trou : l'API Docker est du JSON sur socket Unix, `hyper` la parle directement. Vérifier `ServiceUpdate` + `RollbackConfig` **en spike, avant la phase 1.** |
| Résolution de digest registry moins outillée qu'en Go | 🟠 | `oci-client` (ex-`oci-distribution`) couvre l'essentiel ; sinon `skopeo`/`crane` en sous-processus |
| Temps de compilation | 🟠 | **Ne jamais compiler sur les nœuds à 4 Go.** Cross-compilation via `cross`, ou build en CI |
| Frictions de lifetimes async sur l'état partagé | 🟠 | Modèle acteur : chaque sous-système possède son état, communication par `mpsc`. Évite `Arc<RwLock<>>` partout |
| `serde_yaml` archivé en 2024 | 🟡 | Vérifier l'alternative vivante au démarrage (`serde_yaml_ng`, `saphyr`…) |
| Vitesse de dev inférieure à Go | 🟡 | Réelle, mais compensée par le temps non passé à débugger en prod |

#### Stack de crates

| Besoin | Crate |
|---|---|
| Runtime async | `tokio` |
| Docker / Swarm | `bollard` (derrière ton propre trait) |
| API HTTP | `axum` + `tower` |
| Agent ↔ controller | `tonic` (gRPC, mTLS) |
| Base d'état | `sqlx` (SQLite → Postgres) |
| Templating | `minijinja` |
| Manifests | `serde` + `schemars` (génère le JSON Schema → autocomplétion dans l'éditeur) |
| CLI | `clap` (derive) |
| Secrets | `age` (implémentation Rust native) |
| Registry OCI | `oci-client` |
| SSH (accès aux nœuds) | `russh` |
| Logs / traces | `tracing` + `tracing-subscriber` |
| Planification | `tokio-cron-scheduler` |
| OpenAPI | `utoipa` (génère la spec depuis les handlers axum) |

#### Le pont Rust ↔ SvelteKit

`utoipa` génère l'OpenAPI depuis tes handlers `axum` → `openapi-typescript` génère
les types TS → **le typage est vérifié de bout en bout**. Si tu changes un champ dans
une struct Rust, le build TypeScript casse. Tu ne peux pas avoir ça avec un backend
non typé.

L'UI compilée (`adapter-static`) est embarquée dans le binaire via `rust-embed`
→ **un seul binaire à déployer**, comme prévu.

### ⚠️ Point clé : « modulaire » ≠ plugins compilés

En Rust il n'y a pas d'ABI stable, donc pas de plugins dynamiques réalistes.
**La modularité doit être déclarative (data-driven), pas compilée.**

→ Une app = un dossier de fichiers YAML + templates + hooks shell. Ajouter une app
= ajouter un dossier, **zéro recompilation**. C'est le cœur du design (§4).

---

## 2. Architecture générale

```
                        ┌──────────────────────────────────┐
                        │        hlb-controller            │
   CLI `hlb` ──────────►│  (1 binaire Go, sur un manager)  │
   Web UI  ──────────►  │                                  │
                        │  • API REST + gRPC               │
                        │  • Boucle de réconciliation      │
                        │  • Catalogue d'apps              │
                        │  • Résolveur de dépendances      │
                        │  • Scheduler (backups, updates)  │
                        │  • Store d'état (SQLite/Postgres)│
                        │  • Coffre de secrets (age/SOPS)  │
                        └───────────┬──────────────────────┘
                                    │ mTLS
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
  ┌───────────┐              ┌───────────┐              ┌───────────┐
  │ hlb-agent │              │ hlb-agent │              │ hlb-agent │
  │  node-1   │              │  node-2   │              │  node-3   │
  │ (manager) │              │ (manager) │              │ (worker)  │
  └───────────┘              └───────────┘              └───────────┘
        └──────────────── Docker Swarm ─────────────────────┘
                     (réseau overlay chiffré)
```

**`hlb-controller`** — le cerveau. Source de vérité = base d'état + export Git
(voir §2.3). Ne touche jamais directement aux hôtes : il parle à l'API Swarm et
aux agents.

**`hlb-agent`** — déployé comme **service Swarm `global`** (donc automatiquement
présent sur chaque nœud, y compris les nouveaux). Il gère ce que Swarm ne sait pas
faire :
- snapshots de volumes locaux (restic) sans passer par le réseau
- exécution des hooks pre/post backup dans les conteneurs
- métriques disque / SMART / température
- rotation des logs, pruning d'images
- vérification d'intégrité des volumes

**`hlb` (CLI)** — interface de première classe. **Tout ce que fait l'UI doit être
faisable en CLI**, l'UI n'est qu'un client de l'API. Ça garantit la scriptabilité
et le debug quand l'UI est cassée.

### 2.1 Modèle déclaratif + réconciliation

Le controller ne fait pas d'actions impératives « one-shot ». Il maintient une
boucle : **état désiré → diff → plan → application → vérification**.

```
état désiré (DB)  ──diff──►  plan d'exécution  ──apply──►  Swarm
       ▲                                                     │
       └──────────────── état observé ◄──────────────────────┘
```

Avantage : si un nœud tombe et revient, si quelqu'un fait un `docker service rm`
à la main, le système reconverge tout seul. C'est le modèle Kubernetes, appliqué
à Swarm.

### 2.2 Store d'état

- **SQLite** (avec Litestream → S3) pour démarrer : simple, zéro dépendance, suffisant.
- Migration possible vers le Postgres partagé plus tard si besoin de HA du controller.
- Le controller doit pouvoir **redémarrer à froid depuis zéro** en relisant Swarm +
  le repo Git. L'état ne doit jamais être irremplaçable.

### 2.3 Export Git (GitOps-lite)

Chaque changement d'état désiré est **rendu en YAML et commité dans un dépôt Git**
(ton Gitea, justement). Ça te donne gratuitement :
- historique complet et lisible de toute la configuration
- rollback (`hlb rollback <commit>`)
- diff avant application (`hlb plan`)
- une sauvegarde de la config indépendante du système lui-même

La DB reste la source de vérité (le Git est un miroir), sinon tu réimplémentes
ArgoCD et tu passes 6 mois dessus.

---

## 2bis. Topologie adaptative et matériel hétérogène

**Topologie physique réelle :**

```
┌─ big-01 ── machine 32 Go, bon CPU, OpenMediaVault + KVM ────────────────┐
│                                                                         │
│   ┌─ VM swarm-heavy ──┐   ┌─ VM mailcow ──┐   ┌─ OMV (hôte) ─────────┐  │
│   │ nœud Swarm heavy  │   │ déjà en prod  │   │ exports NFS (médias) │  │
│   │ Postgres, MariaDB │   │ hors swarm    │   │ dépôt restic local   │  │
│   │ Valkey, métriques │   │               │   │ pools de disques     │  │
│   └───────────────────┘   └───────────────┘   └──────────────────────┘  │
│                                                                         │
└─────────────────────── ⚠️ UN SEUL DOMAINE DE PANNE ─────────────────────┘

┌─ small-01 ─ 4 Go ─┐   ┌─ small-02 ─ 4 Go ─┐
│ nœud Swarm light  │   │ nœud Swarm light  │
│ Caddy, apps web   │   │ Caddy, apps web   │
└───────────────────┘   └───────────────────┘
```

| Nœud Swarm | RAM allouée | Tier | Domaine de panne | Rôle |
|---|---|---|---|---|
| `swarm-heavy` (VM) | ~16 Go | `heavy` | `big-01` | manager + **tout le stateful** |
| `small-01` | 4 Go | `light` | `small-01` | manager + stateless |
| `small-02` | 4 Go | `light` | `small-02` | manager + stateless |

Avec 4 Go, un nœud ne peut **pas** héberger PostgreSQL sérieusement. En revanche un
manager Swarm ne coûte que ~250 Mo → **les 3 nœuds sont managers**, quorum réel,
tolérance à une panne. C'est la bonne configuration.

### 2bis.0 Budget RAM de `big-01`

32 Go, mais partagés entre l'hôte NAS et deux VM. Répartition à figer **avant** de
commencer, sinon tu découvriras le problème en production :

| Consommateur | Allocation | Note |
|---|---|---|
| OMV (hôte) + services NAS | 3 Go | |
| **Cache ARC (si ZFS)** | **2-4 Go, plafonné** | ⚠️ Sans `zfs_arc_max`, ZFS mange toute la RAM libre et étouffe les VM |
| VM mailcow | 8 Go | déjà en place |
| VM `swarm-heavy` | **16 Go** | Postgres + MariaDB + Valkey + métriques + apps heavy |
| Marge | 1-2 Go | |

Si le stockage est en **mdadm/ext4** plutôt qu'en ZFS, tu récupères 2-4 Go pour la VM
Swarm. `hlb doctor host` doit vérifier ce plafonnement ARC au bootstrap — c'est une
cause classique d'instabilité de VM sur OMV.

### 2bis.0bis Disques : ne pas mettre les bases sur le pool NAS

Le NFS est maintenant trivialement disponible, ce qui rend la faute facile à commettre.
Règle absolue :

| Donnée | Support | Pourquoi |
|---|---|---|
| Postgres, MariaDB, SQLite | **Disque virtio de la VM, sur SSD** | Le verrouillage de fichiers NFS n'est pas fiable → corruption garantie à terme |
| Volumes applicatifs (config, petits fichiers) | Disque virtio de la VM | Latence |
| Médias, gros fichiers (`tier: nfs`) | **Export NFS OMV** | Lecture majoritaire, tolère la latence |
| Dépôt restic local | Pool OMV | C'est sa fonction |

Idéalement : un SSD dédié (ou une partition SSD) passé à la VM `swarm-heavy` pour les
volumes `tier: local`, distinct du pool de disques mécaniques du NAS.

### 2bis.1 Profils de cluster (auto-détectés)

HomelabUS calcule un profil au démarrage et à chaque `hlb node add/rm`, puis
**recalcule automatiquement le placement de toutes les apps**.

| Profil | Nœuds | Managers | Comportement |
|---|---|---|---|
| `solo` | 1 | 1 | Pas de réplication, tout local, anti-affinité désactivée. Procédure de restauration Raft documentée. |
| `duo` | 2 | **1** (jamais 2) | 1 manager + 1 worker. Stateful sur le plus gros, stateless réparti. 2 managers = perte de quorum au premier incident → interdit par le système. |
| `quorum` | 3-4 | 3 | HA stateless réelle, anti-affinité, `max_replicas_per_node: 1`. **← ton cas** |
| `large` | 5+ | 5 | Idem + séparation managers dédiés / workers. |

Le passage d'un profil à l'autre est un événement de première classe :

```bash
hlb node add small-03 --ssh root@10.0.0.13
# → profil quorum (3) maintenu, small-03 rejoint comme worker
# → 4 apps rééquilibrées, plan affiché avant application
hlb topology plan     # ce qui changerait si un nœud partait
hlb topology explain  # pourquoi chaque service est placé où il est
```

### 2bis.2 Tiers de nœuds et placement automatique

Les labels Swarm sont **dérivés automatiquement** des ressources détectées par l'agent
(pas saisis à la main) :

```
node.labels.hlb.tier          = heavy | standard | light   # ≥16 Go | 8-16 Go | <8 Go
node.labels.hlb.storage       = primary | replica | none   # présence de SSD + espace
node.labels.hlb.db            = true | false
node.labels.hlb.arch          = amd64 | arm64
node.labels.hlb.failureDomain = big-01 | small-01 | ...    # ← machine physique
node.labels.hlb.virtualized   = true | false
```

**Le domaine de panne est distinct du nœud.** Sur ton infra, la VM `swarm-heavy` et la
VM mailcow vivent sur le même fer : les répartir « sur deux nœuds différents » ne
protège de rien. L'anti-affinité doit donc porter sur `failureDomain`, **pas** sur
`node.id` — sinon Swarm te donne une illusion de redondance. L'agent détecte la
virtualisation et le domaine de panne est déclaré au moment du `hlb node add`.

Le manifest déclare un **besoin**, pas un nœud :

```yaml
placement:
  tier: heavy          # heavy | standard | light | any
  affinity: db         # se colle au tier des bases
  antiAffinity: self   # jamais 2 réplicas sur le même nœud
```

Tu peux forcer manuellement (`hlb app pin vikunja --node big-01`), mais le défaut
doit toujours être correct.

### 2bis.3 Réplicas adaptatifs

Le manifest ne fige pas un nombre de réplicas — il décrit une **intention** :

```yaml
swarm:
  replicas:
    mode: adaptive     # fixed | adaptive | global
    min: 1
    max: 3
    perLightNode: 1    # 1 réplica par nœud light disponible
```

- profil `solo` → 1 réplica
- profil `duo` → 2 réplicas
- profil `quorum` → 3 réplicas (1 par nœud), anti-affinité stricte

C'est exactement la partie « HA sur le stateless » de ton choix : Caddy backend en
`mode: global`, apps web en `adaptive`, load balancing IPVS natif de Swarm entre les
réplicas. Un nœud tombe → le trafic bascule sans coupure.

### 2bis.4 Protéger les nœuds à 4 Go

Sur 4 Go, une seule app qui fuit met le nœud à genoux et fait tomber un manager.
Garde-fous obligatoires :

- **`reservations.memory` obligatoire dans chaque manifest** — Swarm refuse de placer
  un service si les réservations dépassent la capacité restante. C'est le mécanisme
  qui empêche la surcharge, et il est inopérant si on ne renseigne pas les réservations.
- **`limits.memory` obligatoire** — un conteneur qui dépasse est tué, pas le nœud.
- **Réserve système de 1 Go** non allouable sur les nœuds `light` (OS + Swarm + agent).
  → budget réellement disponible : **~3 Go par petit nœud**.
- **zram** activé sur les nœuds `light` (compression mémoire, gain effectif ~1,5×),
  swap sur SSD en secours.
- `hlb node capacity` affiche l'allocation réelle et **refuse une installation** qui ne
  tiendrait pas, en proposant un nœud alternatif.
- Alerte ntfy dès 85 % d'allocation mémoire sur un nœud.

### 2bis.5 🔴 Le point critique : `big-01` porte les données **et** les backups

C'est le risque n°1 de toute l'architecture, et il mérite d'être énoncé sans détour :

> **Les bases de données, mailcow, les médias et le dépôt restic local sont sur la
> même machine physique.** Une panne de carte mère, d'alimentation, un dégât des eaux
> ou un vol, et tu perds simultanément les données de production *et* la sauvegarde
> censée les restaurer.

Le NAS n'est pas une sauvegarde tant qu'il est dans le même boîtier que les données.
Il sert à la **restauration rapide** (erreur humaine, corruption applicative,
mauvaise mise à jour) — ce qui est utile et couvre 95 % des incidents réels — mais il
ne couvre pas la perte du matériel.

**Conséquences directes sur le plan :**

1. **L'offsite Hetzner cesse d'être un supplément : c'est la seule vraie sauvegarde.**
   Sa surveillance devient critique — vérification d'intégrité (`restic check`)
   hebdomadaire et non mensuelle, alerte immédiate si une sauvegarde offsite échoue
   deux fois de suite, et blocage des mises à jour automatiques tant que l'offsite
   est en retard de plus de 24 h.
2. **Priorisation de la restauration.** Rapatrier 1 To depuis Hetzner sur une connexion
   domestique, c'est long : à 100 Mb/s descendants, compte ~24 h ; à 500 Mb/s, ~5 h.
   Les backups sont donc restaurés **par classe**, dans cet ordre :

   | Ordre | Classe | Volume typique | Temps |
   |---|---|---|---|
   | 1 | secrets, manifests, état du controller | < 100 Mo | secondes |
   | 2 | dumps SQL + WAL (toutes les apps) | 1-10 Go | minutes |
   | 3 | volumes applicatifs (config, pièces jointes) | 10-50 Go | ~1 h |
   | 4 | médias volumineux | le reste | en tâche de fond |

   `hlb restore --priority-only` remonte un service fonctionnel avec les classes 1-3,
   pendant que les médias se rapatrient en arrière-plan. **C'est ce qui fait la
   différence entre 1 heure et 24 heures d'indisponibilité.**
3. **Snapshots système côté OMV.** Si le pool est en ZFS ou btrfs, les snapshots
   donnent un retour arrière quasi instantané en local (minutes, pas heures) pour les
   incidents logiques. À combiner avec restic, pas à remplacer : `hlb snapshot create`
   avant chaque opération risquée.
4. **Une troisième copie physique est le meilleur investissement du projet**, avant
   toute amélioration logicielle : un disque USB de 2 To rotatif et débranché, ou une
   copie du dépôt restic sur un des petits nœuds s'il a du disque. Coût dérisoire,
   couverture du seul scénario réellement destructeur.

Ce qu'il faut absolument prévoir en face :

1. **Archivage WAL continu** vers le NAS *et* l'offsite → RPO ≈ 1 minute
2. **Un mode dégradé** : les petits nœuds doivent pouvoir accueillir un Postgres de
   secours. 4 Go suffisent pour un Postgres homelab avec un profil réduit
   (`shared_buffers=512MB`, `work_mem=8MB`, `max_connections=50` derrière PgBouncer).

```bash
hlb dr promote small-01 --profile minimal
# → restaure le dernier basebackup + rejoue les WAL sur small-01
# → réécrit les Caddyfile et les chaînes de connexion
# → redémarre les apps compatibles, met les autres en pause
```

Objectif : **RTO ≈ 20 min sans `big-01`**, avec un service dégradé mais fonctionnel.
Cette procédure doit être **testée automatiquement chaque mois** (§8.3), sinon elle
ne marchera pas le jour où tu en auras besoin.

3. **Un `big-02` est le meilleur investissement futur** — pas un 4e petit nœud.
   Le système doit détecter l'arrivée d'un second nœud `heavy` et proposer
   automatiquement la mise en place du standby en réplication streaming (phase 2 du §3.2).

---

## 2ter. Installation, bootstrap et support multi-distribution

### 2ter.0 ⚠️ Le piège de séquencement : l'assistant web ne peut pas être le premier

Tu veux un assistant dans l'UI. Logique — mais **l'UI est servie par le controller,
qui n'existe pas encore au moment où tu installes le premier serveur.** On ne peut pas
utiliser une interface web pour installer la chose qui sert l'interface web.

**Solution : deux assistants, pas un.**

| Étape | Assistant | Pourquoi |
|---|---|---|
| **Serveur maître** (la première fois) | **TUI** dans le terminal (`ratatui`) | Rien n'existe encore |
| **Nœuds suivants** | **Assistant web** | Le controller tourne, l'UI est disponible |
| Tout, en scripté | `hlb` non-interactif + fichier | CI, refaire à l'identique |

Les trois chemins appellent **exactement le même code** — l'assistant n'est qu'une
façade sur `hlb cluster init` et `hlb node add`. Aucune logique dupliquée.

### 2ter.1 Comment le binaire arrive sur le maître

**Un binaire statique unique, sans aucune dépendance.**

En Rust, la cible `x86_64-unknown-linux-musl` (et `aarch64-unknown-linux-musl`) produit
un exécutable **totalement statique** : aucune dépendance à la glibc, donc **le même
fichier tourne sur Debian, Rocky, Alpine, Arch ou openSUSE**. C'est ce qui rend le
« n'importe quelle distro » réel plutôt qu'aspirationnel.

```bash
# Sur le futur maître, en root :
curl -fsSLO https://…/hlb-x86_64-linux
curl -fsSLO https://…/hlb-x86_64-linux.sig
minisign -Vm hlb-x86_64-linux -P <clé publique>   # ← vérification AVANT exécution
chmod +x hlb-x86_64-linux && ./hlb-x86_64-linux init
```

🔴 **Pas de `curl | sh`.** Ce motif exécute du code non vérifié récupéré sur le réseau.
Pour un outil qui va prendre le contrôle root de toutes tes machines, c'est
inacceptable. Binaire signé, signature vérifiée, puis exécution.

`hlb init` lance le TUI, puis : détection de la distro → installation de Docker →
init Swarm → génération des identités → démarrage du controller → affichage de l'URL
de l'UI et du premier code de connexion.

### 2ter.2 Le modèle d'accès SSH — et pourquoi il est temporaire

C'est le cœur de ta demande. Le principe important :

> 🔑 **HomelabUS génère sa propre paire de clés SSH. Tu ne lui donnes jamais tes clés
> personnelles.**

```
┌─ Maître ────────────────────────────────────────────┐
│  hlb init génère une paire de clés dédiée           │
│  ~/.hlb/bootstrap_ed25519  (privée, chiffrée age)   │
│  → affiche la clé publique dans le TUI et l'UI      │
└──────────────────────┬──────────────────────────────┘
                       │  tu installes la clé publique
                       │  sur le nœud cible (ssh-copy-id)
                       ▼
┌─ Nœud cible ────────────────────────────────────────┐
│  1. HomelabUS se connecte en SSH                    │
│  2. Détecte la distro, exécute les préchecks        │
│  3. Installe Docker, rejoint le Swarm               │
│  4. Déploie l'agent (service Swarm global)          │
│  5. Établit le canal mTLS agent ↔ controller        │
│  6. ⭐ Révoque sa propre clé SSH (optionnel)        │
└─────────────────────────────────────────────────────┘
```

**Le point de conception qui compte : le SSH ne sert qu'au bootstrap.**

Une fois l'agent en place, toute l'exploitation passe par **mTLS**, pas par SSH. Le
controller n'a donc pas besoin d'un accès root SSH permanent sur tout ton parc — ce
qui réduit énormément le rayon de souffle en cas de compromission.

```bash
hlb node add 192.168.1.42 --role worker --ephemeral-access
#                                        └─ retire la clé après installation
```

Trois modes d'authentification proposés par l'assistant :

| Mode | Fonctionnement | Quand |
|---|---|---|
| **Clé dédiée** ⭐ | Tu installes la clé publique de HomelabUS toi-même | ✅ **Recommandé** |
| Agent SSH | HomelabUS emprunte ton agent le temps du bootstrap | Rapide, rien à installer |
| Identifiants ponctuels | Saisis dans l'assistant, jamais stockés | Machine neuve sans clé |

Alternative **pull** disponible, pour ne pas exposer de SSH du tout : le maître affiche
une commande à coller sur le nœud, qui rejoint le cluster avec un jeton à usage unique
et durée limitée.

```bash
hlb node invite --expires 15m
# → curl -fsSLO https://hlb.local/hlb && ./hlb join --token AbC…
```

### 2ter.3 L'abstraction multi-distribution

Ce qui diffère réellement entre distributions serveur :

| | Debian / Ubuntu | RHEL / Rocky / Alma | Alpine | Arch | openSUSE |
|---|---|---|---|---|---|
| Paquets | `apt` | `dnf` | `apk` | `pacman` | `zypper` |
| Init | systemd | systemd | **OpenRC** | systemd | systemd |
| Pare-feu | ufw / nftables | **firewalld** | iptables | nftables | firewalld |
| MAC | AppArmor | **SELinux** | — | — | AppArmor |

D'où un trait unique, avec une implémentation par famille :

```rust
trait DistroAdapter: Send + Sync {
    fn detect(os: &OsRelease) -> Option<Self> where Self: Sized;
    fn ensure_docker(&self, v: VersionSpec) -> Result<DockerVersion>;
    fn install_packages(&self, pkgs: &[Package]) -> Result<()>;
    fn service_manager(&self) -> &dyn ServiceManager;   // systemd | openrc
    fn firewall(&self) -> &dyn Firewall;                // ufw | firewalld | nftables
    fn mac_system(&self) -> MacSystem;                  // selinux | apparmor | none
    fn preflight(&self) -> Vec<Check>;
}
```

La détection se fait sur `/etc/os-release` (`ID`, `ID_LIKE`, `VERSION_ID`) — `ID_LIKE`
permet de rattraper les dérivées inconnues (Linux Mint → Debian, Nobara → Fedora…).

#### 🔴 Les pièges réels, par famille

Ce sont eux qui font échouer les installateurs « universels » :

| Piège | Impact | Traitement |
|---|---|---|
| **SELinux en `enforcing`** (RHEL) | Les montages de volumes échouent silencieusement | Détecter, appliquer les labels `:z` / `:Z`, **ne jamais désactiver SELinux** |
| **firewalld + Docker Swarm** (RHEL) | Le réseau overlay ne fonctionne pas | Ouvrir explicitement 2377/tcp, 7946/tcp+udp, 4789/udp dans la bonne zone |
| **nftables pur** (distros récentes) | Docker a besoin d'iptables | Vérifier la présence de `iptables-nft` |
| **cgroups v1** (distros anciennes) | Certaines limites de ressources sont ignorées | Détecter et avertir, proposer la bascule v2 |
| **OpenRC** (Alpine) | Pas de systemd | Implémentation `ServiceManager` dédiée |
| **Swap accounting désactivé** | Les limites mémoire ne sont pas appliquées | Avertir : nécessite un paramètre kernel **et un redémarrage** |
| **Docker fourni par la distro** | Souvent trop ancien pour Swarm | Préférer le dépôt officiel docker.com, ou refuser en dessous d'une version plancher |

#### Niveaux de support — être honnête plutôt qu'exhaustif

Ne promets jamais « toutes les distributions ». Promets des niveaux :

| Niveau | Distributions | Engagement |
|---|---|---|
| **1 — Testé en CI** | Debian 12/13, Ubuntu LTS, Rocky/Alma 9/10 | Ça marche, régressions bloquantes |
| **2 — Best effort** | Fedora, openSUSE, Arch | Devrait marcher, corrigé si signalé |
| **3 — Communauté** | Alpine, NixOS, autres | Adaptateur fourni par contribution |

### 2ter.4 L'assistant d'ajout de nœud

```
┌─ Ajouter un nœud ──────────────────────── étape 3/6 ─┐
│                                                       │
│  ✅ PRÉCHECKS                                         │
│                                                       │
│  ✓ SSH joignable, sudo disponible                    │
│  ✓ Distro : Rocky Linux 10  (famille RHEL)           │
│  ✓ Arch x86_64 · 4,0 Go RAM · 118 Go libres          │
│  ✓ Horloge synchronisée (NTP actif)                  │
│  ⚠ SELinux enforcing → labels :Z appliqués           │
│  ⚠ firewalld actif → 3 règles seront ajoutées        │
│  ⚠ 4 Go de RAM → sera classé tier « light »          │
│  ✗ Docker absent → installation 27.x (docker.com)    │
│                                                       │
│  [ Voir le plan détaillé ]      [ Retour ] [ Suivant ]│
└───────────────────────────────────────────────────────┘
```

**Les préchecks sont la fonctionnalité la plus importante de tout l'assistant.** C'est
ce qui transforme « ça devrait marcher sur ta distro » en « voici précisément ce que je
vais changer sur ta machine ». Ils sont **en lecture seule** : aucune modification tant
que tu n'as pas validé le plan.

Étapes complètes :

1. **Adresse** — hôte, port SSH, utilisateur
2. **Authentification** — les trois modes du §2ter.2
3. **Préchecks** — ci-dessus, sans rien modifier
4. **Rôle et placement** — manager/worker (suggéré par le profil de quorum), tier
   heavy/light (suggéré d'après RAM/CPU), et 🔴 **domaine de panne, demandé
   explicitement** : « cette machine partage-t-elle un hôte physique avec un nœud
   existant ? » — c'est ici qu'on attrape le piège des deux VM sur `big-01` (§2bis)
5. **Plan** — la liste exacte des actions, avant exécution
6. **Exécution** — journal en direct, étape par étape
7. **Vérification** — nœud actif, agent connecté, et proposition de révoquer la clé
   de bootstrap

### 2ter.5 Deux exigences non négociables

**Idempotence.** Relancer `hlb node add` sur un nœud déjà configuré ne doit rien
casser : chaque étape vérifie l'état avant d'agir. Tu dois pouvoir relancer sans peur.

**Reprise après échec.** Si l'étape 4 sur 7 échoue, l'exécution reprend à l'étape 4 —
elle ne recommence pas de zéro et ne laisse pas le nœud à moitié configuré. Chaque
étape est journalisée dans l'état du controller.

```bash
hlb node add 192.168.1.42 --dry-run    # préchecks + plan, aucune modification
hlb node add 192.168.1.42 --resume     # reprend une installation interrompue
hlb node remove 192.168.1.42 --drain   # sortie propre : vide le nœud d'abord
```

### 2ter.6 Installation automatique des dépendances

**Principe : tu n'installes rien à la main. Jamais.** Le seul geste manuel de tout le
projet, c'est de télécharger et vérifier le binaire `hlb`. Tout le reste est déduit et
installé par HomelabUS.

#### Ce qui est installé, et pourquoi

| Dépendance | Rôle | Installé quand |
|---|---|---|
| **Docker Engine + plugin compose** | l'orchestrateur | toujours |
| **wireguard-tools** | mesh chiffré entre nœuds | toujours |
| **restic** | moteur de sauvegarde | toujours |
| **rclone** | destinations offsite (Hetzner, B2) | si backup offsite |
| `ca-certificates`, `curl` | TLS, téléchargements | toujours |
| `chrony` ou `systemd-timesyncd` | 🔴 horloge — **Swarm et TLS cassent en cas de dérive** | si absent |
| `iptables-nft` | compatibilité Docker sur distros nftables | selon détection |
| `nfs-common` / `nfs-utils` | montages NFS depuis le NAS | si `tier: nfs` utilisé |
| `smartmontools` | santé disque remontée par l'agent | recommandé |
| `clamav` | antivirus mail | uniquement sur l'hôte mail |

Les paquets **spécifiques à une app** sont déclarés dans son manifest et installés à
l'installation de celle-ci, pas au bootstrap :

```yaml
# manifest d'une app
hostDependencies:
  - name: nfs-common
    reason: "montage du partage médias depuis le NAS"
```

#### Les trois règles qui évitent les mauvaises surprises

**1. Version plancher, pas version fixe.** Un Docker trop ancien casse Swarm. Un Docker
imposé au patch près te bloque sur les correctifs de sécurité.

```rust
DockerRequirement { min: "24.0", preferred_channel: Stable, source: DockerCom }
```

Si le paquet de la distro est trop ancien (fréquent sur Debian stable et RHEL), le
dépôt officiel docker.com est ajouté. Si l'utilisateur a déjà une version récente, on
n'y touche pas.

**2. Rien n'est installé sans être annoncé.** Les préchecks (§2ter.4) listent chaque
paquet, sa version et sa provenance **avant** toute modification. C'est le principe de
l'assistant : tu valides un plan, tu ne subis pas un script.

**3. 🔴 Ne jamais mettre à niveau ce qu'on n'a pas installé.** Si Docker est déjà
présent et suffisant, HomelabUS le laisse strictement tranquille. Écraser la
configuration Docker d'une machine existante est le meilleur moyen de casser autre
chose. La règle : **on ajoute, on ne remplace pas.**

```bash
hlb node deps 192.168.1.42          # ce qui est présent, manquant, trop ancien
hlb node deps 192.168.1.42 --fix    # installe uniquement ce qui manque
```

#### Cas particuliers à traiter

- **Docker installé via snap** (Ubuntu) : confinement incompatible avec certains
  montages → **détecter et refuser**, avec la marche à suivre pour migrer.
- **Podman présent au lieu de Docker** : l'émulation ne couvre pas Swarm → refuser
  proprement plutôt que d'échouer plus tard.
- **Redémarrage nécessaire** (cgroups v2, comptabilité swap, modules kernel) :
  HomelabUS ne redémarre **jamais** une machine tout seul. Il le signale comme action
  manuelle (§4.6) et poursuit ce qui peut l'être.

---

## 3. Couche « plateforme » (services partagés)

Ce sont les services que HomelabUS installe et gère lui-même, dont les apps
dépendent. Ils sont décrits par les mêmes manifests que les apps, mais marqués
`kind: PlatformService`.

| Service | Rôle | Notes |
|---|---|---|
| **PostgreSQL** | BDD principale mutualisée | 1 instance, 1 base + 1 rôle par app, auto-provisionnés |
| **PgBouncer** | Pool de connexions | Indispensable dès 5-6 apps |
| **MariaDB** | Pour les apps qui l'exigent | Idem : 1 base par app |
| **Valkey** (fork Redis) | Cache / queues | 1 instance, 1 numéro de DB par app + ACL |
| **PocketID** | Fournisseur OIDC (SSO) | Passkey-first, léger |
| **Caddy frontend** | TLS, entrée unique | ACME DNS-01 wildcard |
| **Anubis** | Filtrage bots / scrapers IA | Entre les deux Caddy, comme chez toi |
| **Caddy backend** | Routage vers les services | Config générée par HomelabUS |
| **CrowdSec** | Détection d'intrusion + WAF (AppSec) | Bouncer Caddy + l'UI que tu as repérée |
| **Restic / rclone** | Moteur de backup | Piloté par l'agent |
| **VictoriaMetrics + Grafana + Alloy** | Métriques / logs / alertes | Plus léger que Prometheus+Loki |
| **ntfy** | Notifications push | Alertes vers ton téléphone |

### 3.1 Provisioning automatique des bases

C'est un des points que tu demandes explicitement. Le flux :

```
Install de "vikunja"
   │
   ├─► manifest déclare: requires.database = {engine: postgres, name: vikunja}
   │
   ├─► HomelabUS génère un mot de passe aléatoire (32 octets)
   ├─► CREATE ROLE vikunja LOGIN PASSWORD '...';
   ├─► CREATE DATABASE vikunja OWNER vikunja;
   ├─► REVOKE ALL ON DATABASE vikunja FROM PUBLIC;   ← isolation entre apps
   ├─► stocke le secret dans le coffre (age) + crée un `docker secret`
   └─► injecte DATABASE_URL dans le service via /run/secrets/
```

**Règle d'isolation** : chaque app a son rôle, ne voit que sa base, jamais de
superuser. Un Gitea compromis ne peut pas lire la base de Vaultwarden.

À la désinstallation : `hlb app remove vikunja --purge` → dump final archivé, puis
DROP. Sans `--purge`, la base est conservée et marquée orpheline.

### 3.2 Réalisme sur la HA de PostgreSQL

**Sois honnête avec toi-même : la vraie HA Postgres sur Swarm, c'est douloureux.**
Patroni exige etcd/Consul, ce qui double la surface de maintenance.

Approche recommandée, par ordre croissant d'ambition :

1. **Phase 1** — Postgres épinglé sur un nœud (`node.labels.db==primary`), volume
   local sur SSD, + **archivage WAL continu vers S3** (pgBackRest ou WAL-G).
   → RPO ≈ 1 minute, RTO ≈ 10-20 min (restore PITR). **Suffisant pour 95 % des homelabs.**
2. **Phase 2** — ajout d'un standby en réplication streaming sur un 2e nœud, bascule
   assistée (`hlb db failover`), pas automatique.
3. **Phase 3** — Patroni + etcd si tu y tiens vraiment.

Ne commence pas par la phase 3. Le PITR te sauvera bien plus souvent qu'un failover
automatique.

#### État : phase 2 faite (`hlb replication config` / `status`)

**Asynchrone, par décision.** En synchrone, la primaire attend la confirmation du
standby avant de valider chaque transaction : si le standby tombe, **plus aucune
écriture n'aboutit**. Sur deux nœuds, ça transforme la panne du nœud de secours en
panne totale — l'inverse du but. Le coût est un RPO de quelques centaines de
millisecondes, et il est choisi plutôt que subi.

**Le standby ne remplace ni l'instantané ni le PITR.** Il suit la primaire, donc il
suit aussi ses erreurs : une table effacée par mégarde est répliquée immédiatement. Le
standby protège de la panne matérielle ; le PITR protège de l'erreur humaine.

**🔴 Le slot de réplication est le même piège que l'`archive_command` du §8.1.** Un
slot garantit la rétention du WAL tant que le standby n'a pas consommé — donc un
standby mort dont le slot survit fait grossir `pg_wal` jusqu'à saturer le disque de la
**primaire**. D'où `max_slot_wal_keep_size = 8GB` : au-delà, le slot est invalidé et le
standby devra être reconstruit, ce qui est très préférable à une primaire à l'arrêt
faute de place. `hlb replication status` sort en échec sur un slot orphelin et donne
la commande de remède.

Vérifié contre un vrai couple : copie initiale, rattrapage après coupure (les données
écrites pendant l'absence sont bien là), refus des écritures côté standby, et alerte
de slot orphelin. Deux pièges constatés à cette occasion sont notés dans CLAUDE.md —
`pg_basebackup -R` qui écrase `postgresql.auto.conf` en perdant l'`application_name`,
et le fait qu'un slot **neuf** ne retient rien (le danger vient du slot qui a servi).

Reste, pour un déploiement réel : un second nœud `heavy` et la bascule assistée
(`hlb db failover`), volontairement non automatique.

### 3.3 Le cas Valkey/Redis

Certaines apps supposent d'être seules sur la DB 0. Stratégie :
- par défaut : instance partagée, **1 numéro de DB + 1 utilisateur ACL par app**
- si le manifest dit `cache.dedicated: true` → instance dédiée (ça coûte ~5 Mo de RAM,
  ce n'est pas un drame)

### 3.4 Applications SQLite

Vaultwarden (par défaut), PocketID et pas mal d'autres utilisent SQLite. Il ne faut
**jamais** copier un fichier SQLite à chaud.

- soit **Litestream** (réplication continue du WAL vers S3) → RPO de quelques secondes
- soit hook de backup `sqlite3 db.sqlite ".backup /tmp/snap.db"` avant restic

Le manifest déclare `storage[].sqlite: true` et HomelabUS applique la bonne méthode
automatiquement.

### 3.5 Stockage objet — fait (`Capability::ObjectStorage`, Garage)

Certaines apps ne veulent pas un volume mais un **compartiment S3** : Outline l'exige,
Matrix y déporte ses médias, Nextcloud peut y mettre son stockage primaire. Un volume
se monte dans un chemin et impose une contrainte de placement ; un compartiment se
parle en HTTP, et l'app cesse d'avoir à tourner près de sa donnée — ce qui compte sur
un cluster hétérogène.

**Garage plutôt que MinIO** : conçu pour des nœuds inégaux reliés par un réseau
ordinaire, quelques dizaines de mégaoctets de RAM, et pas de console web à protéger —
l'administration passe par son API. ⚠️ Sa compatibilité S3 n'est pas totale : pas de
versionnement d'objets. Sans conséquence pour restic, Outline et Matrix ; à signaler à
l'ajout d'un manifest qui l'exigerait.

**🔴 Isolation par compartiment ET par clé**, comme les bases du §3.1. Une clé
d'administration partagée donnerait à chaque app la lecture des compartiments de toutes
les autres — les photos d'Immich lisibles depuis le wiki, et réciproquement.

**🔴 Garage ne redonne JAMAIS une clé secrète.** `CreateKey` la donne une fois ;
`GetKeyInfo` la rend nulle ensuite. L'idempotence ne peut donc pas reposer sur « la clé
existe-t-elle ? » : une reprise repartirait sans secret, et l'app échouerait sur une
« signature invalide » qui n'oriente vers rien. C'est le **coffre** qui fait autorité.

**🔴 Une app n'est jamais `owner` de son compartiment** — `read` + `write` seulement.
Propriétaire, une app compromise pourrait supprimer son propre compartiment, effaçant
d'un coup ce que les sauvegardes protégeaient.

⚠️ **Garage vit sur les disques du cluster.** Y sauvegarder des photos double leur
occupation chez soi : c'est une seconde copie contre la panne de disque, pas une copie
hors site. Voir le routage par classe au §8.1.

---

## 4. Le système de modules (ajouter une app)

**C'est le cœur de ton projet.** Tout le reste en découle.

### 4.1 Anatomie d'un module

```
catalog/vikunja/
├── manifest.yaml       # métadonnées + dépendances déclarées
├── stack.yaml.tmpl     # template Go du compose Swarm
├── sso.yaml            # mapping OIDC vers PocketID
├── hooks/
│   ├── pre-backup.sh
│   ├── post-restore.sh
│   └── post-install.sh
├── caddy.tmpl          # snippet de reverse proxy (optionnel)
└── README.md
```

### 4.2 Exemple de manifest

```yaml
apiVersion: hlb/v1
kind: App
metadata:
  name: vikunja
  displayName: Vikunja
  category: productivity
  homepage: https://vikunja.io

spec:
  image:
    repo: vikunja/vikunja
    tag: "0.24.6"
    digest: sha256:abc123...        # épinglage fort
    verifySignature: false          # true si cosign dispo

  requires:
    database:
      engine: postgres
      name: vikunja
    cache:
      engine: valkey
      optional: true
    sso:
      type: oidc
      redirectPath: /auth/openid/hlb
      scopes: [openid, profile, email]
    smtp: true

  ingress:
    - host: "{{ .Domain }}"
      port: 3456
      chain: [caddy-front, anubis, caddy-back]   # ta topologie
      crowdsec: true
      auth: sso                                  # ou: none | forward-auth

  storage:
    - name: files
      path: /app/vikunja/files
      tier: local            # local | nfs
      backup: true

  swarm:
    replicas: 2
    updateConfig:
      parallelism: 1
      order: start-first     # zéro downtime
      failureAction: rollback
    rollbackConfig:
      parallelism: 1
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:3456/api/v1/info"]
      interval: 30s
    resources:
      limits: {cpus: "1.0", memory: 512M}
      reservations: {memory: 128M}

  update:
    channel: minor           # pin | patch | minor | latest
    window: "sun 03:00-05:00"
    backupBefore: true       # snapshot avant toute MAJ
    autoRollback: true

  security:
    readOnlyRootfs: true
    noNewPrivileges: true
    capDrop: [ALL]
    user: "1000:1000"
    networkPolicy:
      egress: [postgres, valkey, smtp, internet]   # tout le reste bloqué
```

### 4.3 Le résolveur de capacités

Le manifest ne dit **jamais** « connecte-toi à `postgres:5432` ». Il déclare un
**besoin** (`requires.database.engine: postgres`), et le controller le résout vers
l'instance réelle, crée la base, génère le secret, et injecte les variables.

Conséquence : le même manifest fonctionne que ton Postgres soit local, sur un autre
nœud, derrière PgBouncer, ou managé ailleurs. **C'est ce qui rend le système
réellement modulaire.**

### 4.4 Expérience développeur

```bash
hlb catalog search vikunja
hlb app install vikunja --domain tasks.mondomaine.fr --sso
hlb app new mon-app --from-compose ./docker-compose.yml   # import & conversion
hlb app validate ./catalog/mon-app     # lint du manifest + dry-run
hlb app diff vikunja                   # ce qui va changer
hlb app logs vikunja -f
hlb app backup vikunja --now
hlb app restore vikunja --at "2026-08-01 14:00"
```

L'import depuis un `docker-compose.yml` existant est important : c'est ce qui rend
l'ajout de n'importe quelle app self-hosted rapide, sans écrire le manifest à la main.

### 4.5 Catalogue

- **Catalogue intégré** versionné dans le dépôt du projet (les 30-50 apps courantes)
- **Catalogues externes** : `hlb catalog add https://github.com/moi/mon-catalogue`
- Signature des manifests (cosign / minisign) pour les catalogues tiers

### 4.6 Le système de guides : actions manuelles, astuces et vérifications

Il reste toujours des choses que le déploiement seul ne couvre pas. Elles se rangent en
**deux familles bien distinctes**, qui appellent deux traitements différents :

| Famille | Exemples | Traitement |
|---|---|---|
| **A — Hors du système** | enregistrement DNS, redirection de port sur la box, rDNS chez l'hébergeur, ranger des codes de récupération | **Irréductiblement manuel** → guide vérifiable (§4.6) |
| **B — Dans les applications** | créer le premier compte, fermer les inscriptions, activer un réglage, générer un jeton, migrer après une montée de version | **Automatisable dans 80 % des cas** → §4.6bis |

La famille B est celle qu'on traite mal d'habitude : on la documente comme si elle était
manuelle, alors que la plupart de ces étapes se scriptent. **Le plan traite les deux, et
ne bascule en manuel qu'après avoir essayé d'automatiser.**

C'est le **maillon faible de tout installateur automatique** : l'app se déploie, tout
semble vert, et rien ne marche parce qu'un enregistrement DNS manque.

#### 🔴 Les trois erreurs de conception à éviter

| Erreur | Pourquoi c'est grave |
|---|---|
| **Une popup « pense à faire X »** | Elle est fermée et oubliée en trois secondes |
| **Une étape non vérifiable** | L'utilisateur clique « c'est fait » alors que ça ne l'est pas |
| **Vérifier une seule fois** | Un enregistrement DNS supprimé, une box redémarrée qui perd son NAT, et ça casse six mois plus tard |

D'où trois principes : **toute action manuelle est vérifiable automatiquement, elle
persiste jusqu'à vérification, et elle est re-vérifiée périodiquement.**

#### Le format

```yaml
# catalog/<app>/guide.yaml
guide:
  - id: dns-record
    phase: pre-install           # pre-install | post-install | first-login | maintenance
    severity: blocking           # blocking | required | recommended | tip
    title: "Créer l'enregistrement DNS"
    body: |
      Chez ton registrar, ajoute :

          {{ subdomain }}   CNAME   {{ cluster_fqdn }}

      Si tu utilises déjà un wildcard `*.{{ base_domain }}`, il n'y a rien à faire.
    verify:
      type: dns
      record: "{{ domain }}"
      expect: { resolves_to: "{{ cluster_ip }}" }
      timeout: 10m
    recheck: 24h
    docs: "https://…"
```

**Les types de vérification** — c'est ce qui rend le système réel plutôt que déclaratif :

| Type | Vérifie | Exemple |
|---|---|---|
| `dns` | résolution d'un enregistrement | le CNAME existe et pointe au bon endroit |
| `http` | code de retour / contenu | l'app répond bien derrière le proxy |
| `tcp` | port joignable | le 25 sortant n'est pas bloqué |
| `tls` | certificat valide et non expirant | ACME a bien abouti |
| `exec` | commande dans le conteneur | un fichier de config attendu existe |
| `api` | appel à l'API de l'app | le premier compte admin existe |
| `attest` | ⚠️ **aucune vérification possible** | « les codes de récupération sont rangés » |

`attest` est le dernier recours, et l'UI l'affiche explicitement comme **non vérifié
par le système** — pour ne jamais donner une fausse impression de sécurité.

#### Les quatre phases

| Phase | Quand | Bloquant ? |
|---|---|---|
| `pre-install` | avant tout déploiement | ✅ souvent — inutile de déployer si le DNS n'existe pas |
| `post-install` | juste après | selon |
| `first-login` | à la première ouverture de l'app | non, mais rappelé |
| `maintenance` | récurrent | non, mais suivi |

#### Exemple complet : Stalwart, le cas le plus riche

Un serveur mail concentre presque toutes les actions manuelles possibles.

```yaml
guide:
  - id: port-25-egress
    phase: pre-install
    severity: blocking
    title: "Vérifier que le port 25 sortant est ouvert"
    body: |
      La majorité des FAI le bloquent sur les offres résidentielles.
      Sans lui, tu peux recevoir mais pas envoyer.
    verify: { type: tcp, target: "gmail-smtp-in.l.google.com:25", direction: egress }

  - id: rdns
    phase: pre-install
    severity: blocking
    title: "Configurer le rDNS (PTR)"
    body: |
      Chez ton FAI ou ton hébergeur, fais pointer le reverse de {{ public_ip }}
      vers {{ mail_hostname }}. Sans PTR correct, tes mails partent en spam.
    verify: { type: dns, record: "{{ public_ip }}", expect: { ptr: "{{ mail_hostname }}" } }

  - id: mx-spf-dmarc
    phase: pre-install
    severity: blocking
    title: "Publier MX, SPF et DMARC"
    body: |
      {{ base_domain }}        MX     10 {{ mail_hostname }}
      {{ base_domain }}        TXT    "v=spf1 mx -all"
      _dmarc.{{ base_domain }} TXT    "v=DMARC1; p=quarantine; rua=mailto:{{ admin }}"
    verify: { type: dns, checks: [mx, spf, dmarc] }

  - id: dkim
    phase: post-install
    severity: blocking
    title: "Publier la clé DKIM"
    body: |
      Stalwart a généré cette clé. Publie-la :

          {{ dkim_selector }}._domainkey.{{ base_domain }}  TXT  "{{ dkim_value }}"
    verify: { type: dns, record: "{{ dkim_selector }}._domainkey.{{ base_domain }}" }
    recheck: 24h

  - id: router-ports
    phase: pre-install
    severity: blocking
    title: "Rediriger les ports sur ta box"
    body: "25, 465, 587, 993, 4190 → {{ node_ip }}"
    verify: { type: tcp, targets: [25, 465, 587, 993, 4190], direction: ingress }

  - id: warmup
    phase: post-install
    severity: tip
    title: "Monter en charge progressivement"
    body: |
      Une IP neuve n'a pas de réputation. Sur les deux premières semaines,
      évite les envois massifs — commence par quelques mails par jour.

  - id: deliverability-test
    phase: post-install
    severity: recommended
    title: "Tester la délivrabilité"
    body: "Envoie un message vers un testeur de délivrabilité et vise 10/10."
```

Autres exemples courts, tirés de tes apps :

```yaml
# vaultwarden
- id: first-admin
  phase: first-login
  severity: required
  title: "Crée ton compte immédiatement"
  body: "L'inscription sera fermée juste après. Ne laisse pas cette fenêtre ouverte."
  verify: { type: api, endpoint: /admin/users, expect: { count: ">= 1" } }

# pocket-id
- id: recovery-codes
  phase: post-install
  severity: blocking
  title: "Imprime tes codes de récupération"
  body: |
    PocketID fonctionne uniquement par passkey. Si tu perds ton appareil sans
    ces codes, tu perds l'accès à TOUT le cluster.
    Range-les physiquement, hors du cluster.
  verify: { type: attest }        # ⚠️ non vérifiable — affiché comme tel

- id: second-passkey
  phase: post-install
  severity: required
  title: "Enregistre une seconde passkey"
  body: "Sur un support différent — idéalement une clé matérielle."
  verify: { type: api, endpoint: /api/credentials, expect: { count: ">= 2" } }
```

#### La file d'actions en attente — le vrai mécanisme

Ce n'est **pas** une boîte de dialogue. C'est une **file persistante** en base, exposée
partout :

```
┌─ ACTIONS EN ATTENTE ─────────────────────────── 4 ─┐
│ 🔴 stalwart · rDNS non configuré        [Guide]    │
│ 🔴 stalwart · DKIM non publié           [Vérifier] │
│ 🟠 pocket-id · une seule passkey        [Guide]    │
│ ⚪ gitea · pense à activer les webhooks  [Rejeter]  │
└────────────────────────────────────────────────────┘
```

- **Tableau de bord** : compteur visible en permanence
- **Fiche de l'app** : ses actions à elle
- **ntfy** : notification si une action `blocking` apparaît
- **CLI** : `hlb todo`, `hlb todo verify <id>`, `hlb todo dismiss <id>`

🟢 **Et la re-vérification attrape la dérive** : le jour où ta box perd sa
redirection de port après une mise à jour firmware, ou qu'un enregistrement DNS est
supprimé par erreur, l'action réapparaît **avant** que tu ne t'en aperçoives par un
service cassé.

#### Génération de la checklist

```bash
hlb todo export --format md > actions-manuelles.md
```

Avant une installation, tu peux tout voir d'un coup :

```bash
hlb app install stalwart --domain mail.x.fr --show-guide
# → liste les 6 prérequis manuels AVANT de commencer,
#   pour que tu prépares ton DNS en une seule session
```

C'est ce qui évite le pire scénario : découvrir au milieu d'une installation qu'il
faut attendre 4 heures la propagation d'un enregistrement DNS.

### 4.6bis Les manipulations **dans** les applications

Les actions du §4.6 concernaient l'extérieur (DNS, box, hébergeur). Mais l'essentiel du
travail oublié se passe **à l'intérieur des apps** : créer le premier compte, fermer les
inscriptions, activer un réglage qui n'existe pas en variable d'environnement, générer
un jeton, cliquer sur « lancer la migration » après une montée de version…

#### 🔴 Le principe : automatiser d'abord, guider seulement en dernier recours

La faute serait de traiter toutes ces étapes comme manuelles. **La plupart ne le sont
pas.** Chaque étape déclare comment elle peut être exécutée, et HomelabUS descend
l'échelle jusqu'à ce que quelque chose fonctionne :

| Niveau | Moyen | Fiabilité | Exemple |
|---|---|---|---|
| **1** | **Variable d'env / fichier de config** | ✅✅ idéal, déclaratif | `GITEA__service__DISABLE_REGISTRATION=true` |
| **2** | **CLI dans le conteneur** | ✅ stable, prévu pour ça | `gitea admin user create`, `occ config:set` |
| **3** | **API de l'app** | ✅ propre, mais nécessite un jeton | `POST /api/v1/admin/users` |
| **4** | **Écriture directe en base** | ⚠️ fragile, dépend de la version | à éviter, mais parfois seule voie |
| **5** | **Manuel dans l'interface web** | ❌ dernier recours | réglage exposé uniquement en UI |

```yaml
- id: close-registration
  phase: post-install
  severity: blocking
  title: "Fermer les inscriptions"
  after: [create-admin]                  # ordre entre étapes du guide
  automate:
    - method: env                        # niveau 1 — tenté en premier
      vars: { GITEA__service__DISABLE_REGISTRATION: "true" }
    - method: exec                       # niveau 2 — repli
      command: ["gitea", "admin", "config", "set", "service.DISABLE_REGISTRATION", "true"]
  verify:
    type: http
    url: "{{ app_url }}/user/sign_up"
    expect: { status: [403, 404] }       # la page d'inscription ne répond plus
```

Si aucun niveau ne fonctionne, l'étape bascule automatiquement en action manuelle
guidée — mais elle n'y bascule qu'**après** avoir essayé.

#### Quand c'est vraiment manuel : rendre le guidage précis

Une instruction du type « va dans les paramètres et active l'option » est inutilisable
six mois plus tard. Le format impose donc :

```yaml
- id: enable-actions
  phase: post-install
  severity: recommended
  title: "Activer Gitea Actions"
  manual:
    deeplink: "{{ app_url }}/-/admin/config"     # ⭐ lien direct vers LA page
    steps:
      - "Section « Dépôts » → activer « Actions »"
      - "Copier le jeton d'enregistrement du runner"
    input:                                        # ce que HomelabUS récupère ensuite
      - { id: runner_token, label: "Jeton du runner", secret: true }
  verify: { type: api, endpoint: /api/v1/admin/runners, expect: { reachable: true } }
```

Trois éléments obligatoires :

- **`deeplink`** — un lien cliquable vers la page exacte, pas « va dans les
  paramètres ». C'est ce qui divise par dix le temps passé.
- **`steps`** — les clics précis, dans l'ordre.
- **`input`** — si l'étape produit une valeur (jeton, identifiant), HomelabUS la
  récupère, la chiffre dans le coffre et la réinjecte là où elle est attendue. C'est ce
  qui permet de **chaîner** une action manuelle vers une configuration automatique.

#### 🔴 Le motif de sécurité : « premier compte = admin »

Gitea, Vikunja, Vaultwarden et beaucoup d'autres donnent les droits admin **au premier
compte créé**. Si l'app est exposée publiquement avant que tu ne t'inscrives, **n'importe
qui peut devenir administrateur de ton instance**. C'est une fenêtre de quelques minutes,
et elle est réellement exploitée par les scanners automatiques.

HomelabUS doit rendre ce scénario impossible par construction :

```yaml
ingress:
  expose: after-guide        # ⭐ pas d'exposition publique tant que le guide n'est pas validé
```

Séquence appliquée automatiquement :

```
1. Déploiement       → joignable UNIQUEMENT depuis le VPN
2. Guide             → « crée ton compte admin maintenant »
3. Vérification      → l'API confirme qu'un admin existe
4. Fermeture         → inscriptions désactivées (automate niveau 1 ou 2)
5. Vérification      → /sign_up renvoie 403
6. ✅ Exposition publique ouverte
```

C'est le genre de protection qu'on n'a pas quand on déploie à la main, et c'est un
argument fort pour ton produit.

#### Les autres cas récurrents

| Cas | Traitement |
|---|---|
| **Assistant de première configuration** (Nextcloud, Grafana, Immich) | `automate` par CLI si dispo (`occ maintenance:install`), sinon guide avec `deeplink` |
| **Rattacher un compte local existant au SSO** | Guide `first-login` — l'app doit lier, pas dupliquer (`ACCOUNT_LINKING=auto` quand ça existe) |
| **Générer un jeton pour une autre app** | `manual.input` → coffre → injecté dans l'app consommatrice |
| **Tester l'envoi de mail depuis l'app** | `severity: recommended` + `verify: exec` sur les logs SMTP |
| **Migration après montée de version majeure** | `phase: post-upgrade` (voir ci-dessous) |

#### `phase: post-upgrade` — les étapes qui n'existent qu'une fois

Certaines montées de version imposent une action ponctuelle : lancer une réindexation,
cliquer sur « appliquer la migration », régénérer un cache.

```yaml
- id: reindex-after-1-23
  phase: post-upgrade
  when: { version_crosses: "1.23.0" }     # déclenché seulement au franchissement
  severity: required
  title: "Réindexer les dépôts"
  automate:
    - method: exec
      command: ["gitea", "admin", "reindex"]
  verify: { type: http, url: "{{ app_url }}/api/healthz" }
```

Le `when.version_crosses` est important : l'étape apparaît **uniquement** si la mise à
jour franchit cette version, et jamais sur une installation neuve qui démarre déjà
au-dessus.

#### Ce que ça change pour le catalogue

Chaque app du catalogue gagne un fichier `guide.yaml` qui devient, de fait, **la
documentation exécutable de son installation**. C'est ce qui distingue HomelabUS d'un
simple générateur de `docker-compose` : le compose te donne un conteneur qui tourne,
le guide te donne un **service réellement utilisable et correctement fermé**.

```bash
hlb app guide gitea              # toutes les étapes, leur état, ce qui reste à faire
hlb app guide gitea --run        # exécute tout ce qui est automatisable
hlb todo                         # ce qui reste vraiment manuel, toutes apps confondues
```

### 4.7 ⚠️ Ordonnancement des dépendances entre services

**Trou identifié dans la version précédente du plan.** Docker Swarm n'a **pas**
d'équivalent à `depends_on` : il démarre tous les services en parallèle. Une app qui
démarre avant que PostgreSQL soit prêt va planter, redémarrer en boucle, et selon
l'app corrompre son initialisation.

Trois niveaux de traitement, du plus simple au plus solide :

1. **Healthchecks obligatoires** sur tous les services de plateforme — sans quoi rien
   d'autre ne fonctionne.
2. **Graphe de dépendances déduit des `requires`** du manifest : le controller
   ordonne le déploiement et **attend l'état `healthy`** de chaque dépendance avant de
   déployer ce qui en dépend.
3. **`wait-for` injecté** dans les apps fragiles, en point d'entrée, pour les cas où
   l'app ne supporte pas d'être seule au monde.

```rust
// hlb-resolver — tri topologique avant déploiement
let order = dependency_graph(&apps).topological_sort()?;   // cycles = erreur de validation
for app in order {
    orchestrator.deploy(&app).await?;
    orchestrator.wait_healthy(&app, timeout).await?;
}
```

Le même graphe sert à **l'arrêt en ordre inverse** (on ne coupe pas Postgres avant les
apps qui l'utilisent) et à la **restauration** (§8.3).

### 4.7bis Conteneurs compagnons — fait (`spec.companions`)

Certaines apps ne tiennent pas dans un conteneur : Immich a besoin d'un service
d'apprentissage automatique séparé. Ce ne sont pas des services de plateforme — ils ne
sont partagés avec personne et meurent avec leur app.

Trois choses qu'un compagnon **n'a pas**, inscrites dans le type plutôt que dans une
consigne :

- **Pas d'`ingress`.** Une aide interne exposée publiquement, c'est un composant sans
  authentification face à Internet.
- **Pas de `requires`.** Un compagnon qui réclamerait sa propre base serait une app
  déguisée, et devrait en être une.
- **Pas de `replicas`.** Répartir un cache ou un modèle demande une coordination que
  rien ici ne fournit.

Il est déployé **avant** l'app et attendu sain. Sans cette attente, l'ordre du plan ne
garantirait que l'ordre des *appels* à Swarm, pas celui des démarrages — même problème
que l'absence de `depends_on` au §4.7.

🔴 **Un compagnon absent ne se voit pas.** Immich sans son service d'apprentissage
importe et affiche les photos parfaitement, et ne reconnaît jamais personne. Rien à
l'écran ne dit que la moitié de la fonctionnalité manque — d'où une étape de guide qui
fait *vérifier* que ça marche, pas seulement que le service tourne.

### 4.8 Versionnement du catalogue — trou identifié

Le catalogue évolue indépendamment des apps installées. Trois questions restaient sans
réponse : que se passe-t-il quand un manifest change pour une app **déjà installée** ?
Le catalogue se met-il à jour avec le binaire ? Peut-on revenir en arrière ?

**Règle : le manifest utilisé au déploiement est figé dans l'état, pas relu à chaud.**

```
catalog/gitea/manifest.yaml   v3    ← le catalogue évolue
        │
        ▼
état de l'app installée       v2    ← figé au déploiement, fait foi
```

Une évolution du catalogue **ne modifie jamais** une app en fonctionnement. Elle
apparaît comme une proposition :

```bash
hlb catalog diff gitea       # ce qui a changé entre v2 et v3
hlb app adopt gitea --to v3  # applique, avec plan et sauvegarde préalable
```

- Le catalogue intégré est versionné **avec** le binaire, mais sa mise à jour ne
  déclenche aucun redéploiement.
- Les manifests de catalogues externes sont **épinglés par commit**, jamais par branche.
- Un manifest cassé ne peut pas casser une app installée : la validation se fait à
  l'adoption, pas à la lecture.

---

## 5. SSO avec PocketID — automatisation complète

### 5.0 Les quatre modes d'intégration

Toute app self-hosted tombe dans un de ces quatre cas. Le manifest déclare lequel,
et HomelabUS applique la bonne mécanique.

| Mode | Quand | Mécanique | Sécurité |
|---|---|---|---|
| **`native`** | L'app parle OIDC | Client créé dans PocketID, config injectée | ✅ La meilleure |
| **`proxy-header`** | L'app lit un en-tête de confiance (`Remote-User`) | oauth2-proxy + en-têtes | ⚠️ Voir §5.4 — dangereux si mal isolé |
| **`proxy-only`** | L'app n'a aucune notion d'identité | oauth2-proxy en portail devant | ✅ Mais pas de compte dans l'app |
| **`none`** | Incompatible ou exclusion volontaire | Auth propre à l'app | Décision explicite |

### 5.1 Verdict pour tes quatre apps

| App | Mode | Détail |
|---|---|---|
| **Gitea** | `native` | OIDC natif, **configurable en CLI** → automatisation parfaite |
| **Vikunja** | `native` | OIDC natif via config/env, login local désactivable |
| **Vaultwarden** | `native` ✅ | **SSO OIDC officiel depuis la 1.35.0.** Image standard, aucun fork — voir §5.6 |
| **Mailcow** | `native` | **Generic-OIDC + provisioning JIT des mailboxes.** Voir §5.5 |

### 5.2 Le flux automatique (mode `native`)

```
hlb app install gitea --domain git.example.fr --sso
   │
   ├─1─► lecture de catalog/gitea/sso.yaml
   ├─2─► calcul des redirect URIs : https://git.example.fr + redirectPaths
   │      (⚠️ jamais en dur : dépend du domaine choisi à l'install)
   ├─3─► POST vers l'API PocketID → création du client OIDC
   ├─4─► récupération client_id + client_secret
   ├─5─► chiffrement age → coffre → `docker secret`
   ├─6─► application selon `apply.method` (env / file / exec / api)
   ├─7─► déploiement du service
   └─8─► enregistrement dans l'état → visible dans `hlb sso status`
```

Désinstallation : le client OIDC est supprimé de PocketID en même temps que l'app.
Pas de clients orphelins qui traînent — c'est une vraie source de dette de sécurité.

### 5.3 Le fichier `sso.yaml` — la partie modulaire

Chaque app décrit **comment** on la configure. Quatre méthodes couvrent
pratiquement tout l'écosystème self-hosted :

**`method: exec`** — l'app se configure par une commande (cas de Gitea) :

```yaml
# catalog/gitea/sso.yaml
mode: native
redirectPaths: ["/user/oauth2/PocketID/callback"]
scopes: [openid, profile, email]
apply:
  method: exec
  probe: ["gitea", "admin", "auth", "list"]        # idempotence : déjà configuré ?
  matchName: "PocketID"
  command:
    - gitea
    - admin
    - auth
    - add-oauth
    - --name=PocketID
    - --provider=openidConnect
    - --key={{ client_id }}
    - --secret={{ client_secret }}
    - --auto-discover-url={{ issuer }}/.well-known/openid-configuration
extraEnv:
  GITEA__service__ALLOW_ONLY_EXTERNAL_REGISTRATION: "true"
  GITEA__oauth2_client__ENABLE_AUTO_REGISTRATION: "true"
  GITEA__oauth2_client__ACCOUNT_LINKING: "auto"
```

**`method: env`** — l'app se configure par variables (cas de Vikunja) :

```yaml
# catalog/vikunja/sso.yaml
mode: native
redirectPaths: ["/auth/openid/pocketid"]
apply:
  method: env
  vars:
    VIKUNJA_AUTH_LOCAL_ENABLED: "false"      # ⚠️ après création du 1er compte
    VIKUNJA_AUTH_OPENID_ENABLED: "true"
    VIKUNJA_AUTH_OPENID_PROVIDERS_POCKETID_NAME: "PocketID"
    VIKUNJA_AUTH_OPENID_PROVIDERS_POCKETID_AUTHURL: "{{ issuer }}"
    VIKUNJA_AUTH_OPENID_PROVIDERS_POCKETID_CLIENTID: "{{ client_id }}"
    VIKUNJA_AUTH_OPENID_PROVIDERS_POCKETID_CLIENTSECRET: "{{ client_secret }}"
```

Les deux autres : **`method: file`** (rendu minijinja d'un fichier de config monté)
et **`method: api`** (appel HTTP à l'app après démarrage, pour celles qui n'exposent
que ça).

⚠️ **Ne jamais couper le login local avant d'avoir vérifié que le SSO fonctionne.**
HomelabUS applique la séquence : déployer avec login local → tester le flux OIDC de
bout en bout → seulement alors désactiver le local. Sinon tu te verrouilles dehors.

### 5.4 L'alternative : forward-auth (modes `proxy-*`)

Pour toute app sans OIDC. Choix retenu : **`oauth2-proxy` comme service de plateforme
partagé**, une instance pour toutes les apps.

**Pourquoi pas `caddy-security`** : il impose de recompiler Caddy avec `xcaddy`. Or tu
as déjà une chaîne à trois maillons (Caddy → Anubis → Caddy) ; y ajouter des builds
custom de Caddy à maintenir à chaque MAJ est un mauvais calcul. **Garder Caddy
standard a de la valeur.**

Généré automatiquement dans le Caddy backend :

```caddy
handle /oauth2/* {
    reverse_proxy oauth2-proxy:4180
}
handle {
    forward_auth oauth2-proxy:4180 {
        uri /oauth2/auth
        copy_headers X-Auth-Request-User X-Auth-Request-Email
    }
    reverse_proxy monapp:8080
}
```

#### 🔴 Le piège de `proxy-header`

Si une app fait confiance à un en-tête `Remote-User`, alors **quiconque atteint l'app
sans passer par le proxy peut se faire passer pour n'importe qui**. Un simple
`curl -H "Remote-User: admin"` = compromission totale.

C'est la faille la plus courante des setups forward-auth en homelab.

HomelabUS doit rendre ça impossible par construction :
- l'app en `proxy-header` est **seule sur son réseau overlay**, avec le proxy comme
  unique voisin autorisé
- **aucun port publié** sur l'hôte (`ports:` interdit par le validateur de manifest)
- le validateur **refuse** un manifest en `proxy-header` qui exposerait un port ou
  serait joignable depuis un autre réseau

```yaml
mode: proxy-header
headers: {user: Remote-User, email: Remote-Email}
requiresIsolation: true      # ← vérifié à la validation, pas seulement documenté
```

### 5.5 Mailcow : SSO natif, mais seulement pour le web

**Correction d'une erreur de la v1 de ce plan.** Mailcow gère bel et bien un
fournisseur d'identité externe : **Generic-OIDC**, configurable dans
*System > Configuration > Access > Identity Provider*. Mieux encore, il fait du
**provisioning JIT** : la mailbox est créée automatiquement à la première connexion
SSO, avec mapping de rôles vers des templates de mailbox.

C'est exactement le comportement automatique recherché — un compte PocketID, une
mailbox créée toute seule.

**Ce qui reste vrai malgré tout : les protocoles mail échappent au SSO.**

| Accès | SSO ? |
|---|---|
| Interface mailcow, SOGo (webmail) | ✅ OIDC |
| **IMAP / SMTP (Thunderbird, iOS Mail, K-9…)** | ❌ **mot de passe d'application obligatoire** |
| ActiveSync | ❌ idem |

Ce n'est pas un défaut de mailcow : les clients mail gèrent très mal OAuth face à un
IdP générique. **Tout le monde vit avec ça, y compris les offres commerciales.**

⚠️ Mailcow étant en mode adoption (§10.1), la bascule OIDC se fait **à la main, une
fois**, quand tu le décides. HomelabUS crée le client dans PocketID et te fournit les
trois endpoints à coller — il ne modifie pas la config mailcow tout seul.

⚠️ Le connecteur OIDC de mailcow est relativement récent et a connu des ratés
d'intégration selon les IdP. **Teste avec un compte jetable avant de basculer ton
compte principal.**

Autres cas hors SSO, à accepter :
- **Git en HTTPS, APIs, CI** : OIDC ne s'applique pas à `git clone` ni à un script
  → jetons d'accès personnels. **Le SSO couvre la connexion web, pas l'accès machine.**

### 5.6 ✅ Vaultwarden : SSO officiel upstream, aucun fork

**Deuxième correction — tu avais raison, et mes deux objections tombent.**

La PR #3899 de Timshel a été **fusionnée dans `dani-garcia/vaultwarden` le 8 août
2025**, après revue de sécurité et pentest, et livrée dans la **version 1.35.0**. Le
fork `Timshel/vaultwarden` est « quasi abandonné » précisément **parce qu'il n'est
plus nécessaire** — j'avais lu ce signal à l'envers.

→ **Image officielle standard, pipeline de MAJ automatique normal, aucune dette de
fork.** L'objection principale de la version précédente de ce plan n'existe plus.

Et ton argument sur le mot de passe maître est confirmé par la doc officielle : il
reste requis et **n'est pas contrôlé par le SSO**. C'est exactement le modèle que tu
décrivais.

**Configuration — entièrement automatisable :**

```yaml
# catalog/vaultwarden/sso.yaml
mode: native
redirectPaths: ["/identity/connect/oidc-signin"]   # dérivé de DOMAIN, automatique
apply:
  method: env
  vars:
    SSO_ENABLED: "true"
    SSO_AUTHORITY: "{{ issuer }}"          # endpoint de découverte OIDC
    SSO_CLIENT_ID: "{{ client_id }}"
    SSO_CLIENT_SECRET: "{{ client_secret }}"
    SSO_PKCE: "true"                       # défaut, à garder
    SSO_SIGNUPS_MATCH_EMAIL: "true"
    SSO_ONLY: "false"                      # 🔴 voir ci-dessous
```

Autres variables disponibles : `SSO_MASTER_PASSWORD_POLICY`,
`SSO_ALLOW_UNKNOWN_EMAIL_VERIFICATION`, `SSO_AUDIENCE_TRUSTED`,
`SSO_AUTH_ONLY_NOT_SESSION`, `SSO_DEBUG_TOKENS` (débogage uniquement).

L'URL de callback est **générée automatiquement depuis `DOMAIN`** — HomelabUS n'a
donc rien à calculer, il suffit qu'il déclare la même valeur des deux côtés.

🔴 **Garder `SSO_ONLY: false`.** C'est le seul point de vigilance restant : mettre
`true` supprime l'authentification par mot de passe maître, et si PocketID tombe tu
perds l'accès au coffre qui contient les identifiants nécessaires pour le réparer.
Avec `false`, la dépendance circulaire est neutralisée — tu gardes toujours une porte
d'entrée locale.

Le validateur de manifest de HomelabUS **refuse** `SSO_ONLY=true` sur Vaultwarden
sans un `--i-understand-the-lockout-risk` explicite.

### 5.7 Le fournisseur d'identité — PocketID et ses alternatives

#### Le vrai critère de choix : as-tu besoin d'un annuaire LDAP ?

Tous ces outils font de l'OIDC correctement. Ce qui les sépare vraiment, c'est ce
qu'ils font **en plus**. Et dans ton cas, un besoin précis a émergé avec le mail :
**Stalwart peut lire ses comptes depuis un annuaire LDAP**.

⚠️ **Point à connaître : PocketID fait de la *synchronisation* LDAP, pas du *service*
LDAP.** Il sait importer des utilisateurs **depuis** un annuaire existant ; il ne sait
pas se comporter **comme** un annuaire pour Stalwart. La nuance est structurante.

#### Comparatif

| | **PocketID** | **Kanidm** | **Authentik** | **Authelia** | **Zitadel** |
|---|---|---|---|---|---|
| Langage | Go | **Rust** | Python | Go | Go |
| **Fournisseur OIDC** | ✅ **Certifié OpenID Connect™** | ✅ | ✅ | ✅ | ✅ |
| **Serveur LDAP** | ❌ (sync seulement) | ✅ natif | ✅ via outpost | ❌ (consomme) | ❌ |
| SAML | ❌ | ❌ | ✅ | ❌ | ✅ |
| **Forward-auth intégré** | ❌ | ❌ | ✅ proxy provider | ✅ natif | ❌ |
| Passkeys / WebAuthn | ✅ **exclusivement** | ✅ | ✅ | ✅ | ✅ |
| **Attestation WebAuthn** | ❌ | ✅ **unique** | ❌ | ❌ | ❌ |
| Auth Unix / SSH / RADIUS | ❌ | ✅ **unique** | partiel | ❌ | ❌ |
| Base externe requise | SQLite/Postgres | ❌ **base intégrée** | Postgres + Redis | fichier ou LDAP | Postgres |
| RAM typique | **~50 Mo** | ~100 Mo | **~1 Go+** | ~50 Mo | ~200 Mo |
| API de gestion des clients OIDC | ✅ REST + CLI typé | ✅ CLI | ✅ REST | ⚠️ config statique | ✅ REST |
| Courbe d'apprentissage | **très faible** | moyenne | moyenne | faible | moyenne |

**Les compléments spécialisés :**
- **LLDAP** — annuaire LDAP minimaliste, **moins de 10 Mo de RAM**, SQLite. Pas d'OIDC.
  Il existe une configuration d'exemple officielle **pour Stalwart**.
- **Rauthy** — OIDC seul, en Rust, très léger. Plus jeune, moins couvert.

#### ✅ Ma recommandation : garder PocketID

**Cinq raisons, dans l'ordre d'importance :**

1. **Il est certifié OpenID Connect™.** Ce n'est pas un détail marketing : ça veut dire
   que le flux est conforme et testé contre la suite officielle. Sur la brique qui
   authentifie *tout* ton système, c'est le meilleur signal de qualité disponible.
2. **Passkey exclusif = aucun identifiant hameçonnable.** Pas de mot de passe à voler,
   à rejouer ou à réutiliser. C'est structurellement plus sûr que n'importe quelle
   politique de mot de passe. Et le repli existe : **codes de connexion à usage
   unique** quand l'appareil à passkey n'est pas disponible.
3. **API REST + CLI typé généré depuis l'OpenAPI** → l'automatisation du §5.2
   fonctionne intégralement, et tu peux générer le client Rust.
4. **~50 Mo de RAM et aucune dépendance lourde.** Sur ton cluster, ça compte.
5. **Tu l'utilises déjà et il te convient.** Migrer un fournisseur d'identité est une
   opération à risque qui ne se justifie que par un besoin réel non couvert.

#### 🔴 Le seul point qu'il faut trancher : l'annuaire mail

PocketID ne pouvant pas servir d'annuaire LDAP à Stalwart, il reste trois voies :

| Voie | Architecture | Verdict |
|---|---|---|
| **A — HomelabUS synchronise** ⭐ | PocketID = identités. Stalwart = boîtes et aliases. **HomelabUS réconcilie les deux via leurs API.** | ✅ **Retenu et fait** — c'est littéralement la raison d'être de ton produit |
| **B — LLDAP en source de vérité** | LLDAP porte les utilisateurs. PocketID synchronise depuis LLDAP. Stalwart lit LLDAP directement. | Solide et éprouvé, mais **une brique de plus** et la gestion des comptes se fait dans LLDAP |
| **C — Migrer vers Kanidm** | Un seul composant : OIDC + LDAP + passkeys + attestation | Le plus élégant sur le papier, mais **tu perds PocketID** et sa simplicité |

**La voie A est celle qui a été construite** — mais sans idmail, qui remplacerait
l'annuaire de Stalwart et ne peut donc pas coexister avec le client JMAP (voir la
décision au §5bis.3). HomelabUS parle directement aux deux :

```bash
hlb user add remy --email remy@example.fr   # identité PocketID + boîte Stalwart
hlb user list                                # qui existe où, et ce qui manque
```

🔴 **Le point dur n'était pas la synchronisation, c'était l'échec partiel.** Créer un
utilisateur touche DEUX systèmes ; si le second échoue, on obtient quelqu'un qui se
connecte partout et dont l'adresse ne reçoit rien. Cet état paraît fonctionnel jusqu'au
premier courriel perdu — souvent une réinitialisation de mot de passe, c'est-à-dire au
pire moment. Il est donc **nommé** (`Coherence::SansBoite`) et la création est
reprenable : relancer termine ce qui manque, sans recréer ce qui existe.

⚠️ `Capability::MailAccount` existe bien, mais elle sert aux **applications** qui ont
besoin de leur propre adresse. Les comptes humains passent par `hlb-users` : ce ne sont
pas les mêmes objets, et les confondre donnerait des quotas d'app à des personnes.

#### Quand reconsidérer

Change d'avis **seulement** si l'un de ces besoins apparaît :

| Besoin | Va vers |
|---|---|
| Authentification Unix / SSH / sudo centralisée | **Kanidm** |
| Imposer des modèles précis de clés matérielles (attestation) | **Kanidm** |
| Applications SAML, ou beaucoup d'apps legacy | **Authentik** |
| Supprimer oauth2-proxy en unifiant forward-auth et OIDC | **Authentik** ou **Authelia** |

Aucun de ces besoins n'est présent dans ton périmètre actuel.

### 5.7bis 🔴 Ne pas se verrouiller dehors : le plan break-glass

Un SSO centralisé crée un point de défaillance unique **sur l'accès**. Quatre
garde-fous :

1. **Codes de connexion à usage unique PocketID** — la fonction existe nativement,
   c'est ton premier filet quand l'appareil à passkey n'est pas disponible.
   **À générer et imprimer dès l'installation.**
2. **Au moins deux passkeys enregistrées** sur des supports distincts (téléphone +
   clé matérielle type YubiKey). Une seule passkey = un seul point de perte.
3. **Login local actif sur Vaultwarden** (`SSO_ONLY=false`, §5.6) → ton point d'entrée
   de secours, qui ne dépend d'aucun autre service.
4. **PocketID est le service le plus critique du cluster.** Priorité de restauration
   maximale, sauvegarde vérifiée, et `hlb dr promote pocketid` testé **pour de vrai**
   au moins une fois.

L'UI de HomelabUS doit avoir un chemin d'accès local d'urgence, utilisable si PocketID
est HS — sinon tu ne peux même pas piloter la restauration.

### 5.8 ⚠️ Anubis et les endpoints d'authentification

Un challenge proof-of-work devant un callback OAuth **casse le flux de connexion** :
la redirection depuis PocketID est une navigation automatique, pas une action
utilisateur, et certains agents ne résoudront pas le challenge.

HomelabUS exclut automatiquement d'Anubis :
`/.well-known/*`, `/oauth2/*`, `/login/oauth/*`, et les `redirectPaths` déclarés
dans le `sso.yaml` de chaque app.

### 5.9 Rôles et groupes

Là où l'app le supporte, le manifest mappe les groupes PocketID vers les rôles :

```yaml
roleMapping:
  claim: groups
  map:
    homelab-admins: admin
    homelab-users: user
```

Support inégal selon les apps (Gitea gère le mapping de groupe vers admin, d'autres
non). Quand ce n'est pas supporté, HomelabUS le signale à l'installation au lieu de
faire semblant.

### 5.10 Commandes

```bash
hlb sso status                    # quelles apps sont câblées, lesquelles non
hlb sso test gitea                # flux OIDC de bout en bout, sans toucher à la prod
hlb sso rewire gitea              # régénère le client (rotation du secret)
hlb sso breakglass list           # rappel des comptes de secours et de leur emplacement
```

### 5.11 ✅ API PocketID : vérifiée, c'est bon

**Le point de blocage identifié en v1 est levé.** PocketID expose une **API
d'administration REST** couvrant la création de clients OIDC, plus un CLI typé généré
depuis l'OpenAPI (`pocket-id-cli`), authentifié par `POCKET_ID_API_KEY`. Le
provisionnement automatisé en CI/CD est un cas d'usage explicitement supporté.

→ Le flux §5.2 est réalisable intégralement. Et l'OpenAPI signifie que tu peux
**générer le client Rust** plutôt que de l'écrire à la main.

Restent à vérifier, sans caractère bloquant :
1. 🟠 Format exact des variables OIDC de Vikunja selon la version déployée.
2. 🟠 Robustesse du connecteur Generic-OIDC de mailcow face à PocketID
   (à tester sur un compte jetable, cf. §5.5).
3. 🟠 Compatibilité web vault ↔ OIDCWarden à la version installée.

---

## 5bis. La pile mail complète — remplacer mailcow

### 5bis.0 Stalwart : ce qui est libre et ce qui est payant

Stalwart est en **double licence** : Community sous **AGPL-3.0** et Enterprise sous
licence commerciale, **même base de code**. L'AGPL ne se déclenche que si tu
redistribues une version modifiée ou l'offres comme service réseau — un usage interne
n'impose aucune obligation.

La Community Edition n'est **pas** bridée : aucune limite de boîtes, aucune limite de
domaines, aucun protocole retiré.

| Fonction | Community | Enterprise |
|---|---|---|
| SMTP, IMAP, JMAP, POP3, ManageSieve | ✅ | ✅ |
| CalDAV, CardDAV, WebDAV (+ ACL) | ✅ | ✅ |
| Filtre antispam intégré, DKIM/SPF/DMARC/ARC | ✅ | ✅ |
| Console d'administration web | ✅ | ✅ |
| Nombre de boîtes / domaines | illimité | illimité |
| Multi-tenant (isolation par locataire) | ❌ | ✅ |
| **Masked email (adresses jetables)** | ❌ | ✅ |
| **Archivage de comptes / undelete** | ❌ | ✅ |
| Télémétrie live + alertes sur métriques | ❌ | ✅ |
| Antispam assisté par LLM | ❌ | ✅ |
| Réplicas de lecture, stockage shardé | ❌ | ✅ |
| Branding par locataire | ❌ | ✅ |

Tarif : à partir d'environ **2 €/boîte/an** sur la tranche 25–499 boîtes (dégressif
jusqu'à ~0,89 € au-delà de 50 000). La licence est ancrée à un **nom d'hôte**, pas à
un serveur — une clé couvre un nombre illimité de serveurs sous ton domaine.

#### 🔴 Le point qui décide pour toi

**« Masked email » — les adresses jetables — est une fonction Enterprise.** C'est
précisément ce que tu demandais. Et « archivage / undelete » aussi, ce qui compte pour
la récupération d'un mail supprimé par erreur.

Concrètement, pour un homelab la tranche minimale (25 boîtes) revient à ~50 €/an. Ce
n'est pas délirant, mais **le catch-all de la Community te donne déjà des adresses
jetables illimitées gratuitement** (§5bis.3). Tu paierais surtout pour de la gestion
fine par alias.

→ **Verdict : Stalwart Community.** Aucune raison de payer l'Enterprise ici.

### 5bis.1 L'architecture cible

```
                    Internet (MX, ports 25/465/587/993/4190)
                                    │
                    ┌───────────────▼────────────────┐
                    │   VM mail dédiée (sur big-01)  │
                    │   IP publique + rDNS conservés │
                    │   runtime: compose             │
                    ├────────────────────────────────┤
                    │  ┌──────────────────────────┐  │
                    │  │  Stalwart                │  │
                    │  │  SMTP · IMAP · JMAP      │  │
                    │  │  POP3 · ManageSieve      │  │
                    │  │  CalDAV · CardDAV        │  │
                    │  │  WebDAV · antispam · DKIM│  │
                    │  │  console d'admin         │  │
                    │  └───┬──────────────┬───────┘  │
                    │      │ milter       │          │
                    │  ┌───▼─────┐   ┌────▼───────┐  │
                    │  │ ClamAV  │   │  RocksDB   │  │
                    │  │ (option)│   │  + blobs   │  │
                    │  └─────────┘   └────────────┘  │
                    │  ┌──────────────────────────┐  │
                    │  │  Bulwark (JMAP)          │  │
                    │  │  mail+agenda+contacts    │  │
                    │  ├──────────────────────────┤  │
                    │  │  Roundcube (IMAP)        │  │
                    │  │  filet de secours, sans  │  │
                    │  │  SSO — voir §5bis.2ter   │  │
                    │  └──────────────────────────┘  │
                    └────────────────────────────────┘
                                    │ HTTPS uniquement
                    ┌───────────────▼────────────────┐
                    │  Caddy frontend (cluster Swarm)│
                    │  mail.domaine.fr    → Bulwark  │
                    │  webmail.domaine.fr → Roundcube│
                    │  admin.domaine.fr   → Stalwart │
                    └────────────────────────────────┘
```

⚠️ Les aliases ne sont **pas** un service : ils sont portés par HomelabUS lui-même
(`hlb user alias`, API addy.io sur le controller). idmail figurait ici dans une version
antérieure du plan — il remplacerait l'annuaire de Stalwart, ce qui est incompatible
avec le client JMAP. Voir la décision au §5bis.3.

**Quatre conteneurs au lieu des ~15 de mailcow**, tous sur ta machine. Sans ClamAV,
l'ensemble tient sous 1 Go de RAM (mailcow en recommande 6).

🔴 **Bulwark seul, sans webmail de secours : garde un client IMAP configuré**
(Thunderbird sur ton poste, Mail sur ton téléphone). Bulwark vise sa v1 en 2026 ; si
une mise à jour le casse, un client IMAP te garantit l'accès à tes mails pendant que
tu répares. Ça ne coûte rien et ce n'est pas un second webmail à maintenir.

### 5bis.2 Correspondance fonction par fonction

| Composant mailcow | Remplacement | Note |
|---|---|---|
| Postfix (SMTP) | **Stalwart** | intégré |
| Dovecot (IMAP) | **Stalwart** | intégré, + JMAP en bonus |
| Rspamd (antispam) | **Stalwart** | filtre intégré, pas de service séparé |
| ClamAV (antivirus) | **ClamAV via milter** | supporté depuis Stalwart v0.3.1 |
| SOGo — webmail | **Roundcube** | ou SnappyMail (plus léger) |
| SOGo — agenda/contacts | **Stalwart CalDAV/CardDAV** | natif depuis v0.12 |
| SOGo — **ActiveSync** | ⚠️ **aucun** | voir régressions ci-dessous |
| Filtres Sieve | **Stalwart ManageSieve** | intégré |
| Signature DKIM | **Stalwart** | intégré |
| Certificats ACME | **Caddy** (ou ACME Stalwart) | déjà dans ta chaîne |
| UI d'administration | **console Stalwart** | intégrée |
| MariaDB + Redis internes | **RocksDB embarqué** | voir §5bis.4 |
| **Aliases temporaires** | ⚠️ **addy.io** | Enterprise chez Stalwart |
| Aliases permanents | **Stalwart** | natif, illimités |

#### ⚠️ La régression réelle : ActiveSync

Stalwart ne l'implémente pas. Concrètement : Outlook mobile et le profil
« Exchange » d'iOS ne fonctionneront plus. Le remplacement est IMAP + CalDAV +
CardDAV, que iOS et Android gèrent nativement — mais c'est **trois comptes à
configurer au lieu d'un**, sur chaque appareil.

*Seul contournement : garder SOGo en frontal contre l'IMAP de Stalwart. Ça préserve
ActiveSync mais réintroduit une base et un stock CalDAV concurrents — le pire des deux
mondes, je le déconseille.*

**En revanche, la « perte d'intégration webmail » que j'annonçais n'existe plus** :
voir §5bis.2ter, un client couvre désormais mail + agenda + contacts + fichiers.

### 5bis.2bis JMAP vs IMAP — pourquoi ça change quelque chose

**IMAP** date de 1988. **JMAP** (RFC 8620/8621, publié en 2019, issu de Fastmail) a été
conçu pour le web et le mobile. Ce ne sont pas deux versions du même protocole : ce
sont deux philosophies.

| | IMAP | JMAP |
|---|---|---|
| Transport | TCP, connexion permanente, commandes texte | **HTTP + JSON** |
| État | protocole à état (`SELECT` un dossier à la fois) | sans état |
| Ouvrir un message | plusieurs allers-retours (`SELECT`, `FETCH`, `FETCH`…) | **un seul appel**, requêtes chaînables |
| Synchroniser | comparer les UID, réconcilier soi-même | **« qu'est-ce qui a changé depuis l'état X ? »** → delta direct |
| Notification | `IDLE` : **une connexion TCP maintenue par dossier** | **push, une connexion pour tout** |
| Périmètre | mail seulement | **mail + contacts + agendas + fichiers** |
| Envoi | protocole séparé (SMTP) | intégré (`EmailSubmission`) |
| Batterie / mobile | mauvais (connexions maintenues) | conçu pour |
| Support client | **universel** | **rare** |

**En pratique, pour toi :**

- **Bulwark parle JMAP** → interface instantanée, push réel, et *un seul* protocole
  pour mail, agenda et contacts. C'est ce qui lui permet de remplacer SOGo.
- **Ton téléphone et Thunderbird parleront IMAP** (+ CalDAV + CardDAV), parce que le
  support JMAP côté clients reste marginal.

🟢 **Ce n'est pas un choix** : Stalwart expose IMAP **et** JMAP simultanément. Tu
utilises JMAP là où c'est possible (webmail), IMAP partout ailleurs. Aucune
configuration à arbitrer.

L'image mentale : **IMAP est un protocole de terminal**, JMAP est une **API REST**.

### 5bis.2ter Le webmail — panorama complet

C'est le point que tu voulais creuser, et c'est là que ça a le plus bougé récemment.

| Webmail | Protocole | Mail | Agenda | Contacts | Fichiers | Poids | Statut |
|---|---|---|---|---|---|---|---|
| **Bulwark** ⭐ | JMAP | ✅ | ✅ | ✅ | ✅ | léger | 🆕 AGPL-3.0, **v1 visée en 2026** |
| **Roundcube** | IMAP | ✅ | greffon | greffon | ❌ | moyen | mature, référence historique |
| **SnappyMail** | IMAP | ✅ | ❌ | ✅ basique | ❌ | **très léger** | fork sécurisé de RainLoop, très bon sur mobile |
| **SOGo** | IMAP + propre | ✅ | ✅ | ✅ | ❌ | lourd | seul à faire **ActiveSync** |
| **Cypht** | IMAP multi | ✅ | ❌ | ❌ | ❌ | léger | agrège plusieurs comptes en une boîte unifiée |
| **Nextcloud Mail** | IMAP | ✅ | ✅ NC | ✅ NC | ✅ NC | lourd | pertinent **seulement** si tu as déjà Nextcloud |
| **jmap-webmail** | JMAP | ✅ | ? | ? | ? | léger | 🆕 alternative à Bulwark, moins avancée |
| **Webmail Stalwart officiel** | JMAP | — | — | — | — | — | 🔮 annoncé (Rust + Dioxus), **pas encore sorti** |
| ~~RainLoop~~ | IMAP | — | — | — | — | — | ⛔ **à éviter** — non maintenu, failles connues. Utiliser SnappyMail |

#### ⭐ Bulwark change la donne

Client webmail **JMAP natif conçu spécifiquement pour Stalwart**, AGPL-3.0,
auto-hébergeable en deux services Docker Compose derrière ton reverse proxy.

Il couvre **mail (threads, recherche plein texte, filtres Sieve, S/MIME, modèles) +
agenda (vues mois/semaine/jour, récurrences, invitations iMIP, abonnements CalDAV) +
contacts (carnets multiples, groupes, import/export vCard) + fichiers**.

→ **C'est un remplacement fonctionnel de SOGo**, sauf ActiveSync. Et étant en JMAP
(push, un aller-retour par action) plutôt qu'en IMAP, il est nettement plus réactif
que Roundcube.

⚠️ **Réserve honnête** : le projet vise sa **v1 en 2026**, il est donc encore en
développement actif et pas déclaré production-ready. Pour ton mail principal, c'est
un vrai risque à peser.

#### Recommandation

| Profil | Choix |
|---|---|
| **Tu veux du sûr et éprouvé** | **Roundcube** — ennuyeux, mature, ça marche |
| **Tu veux léger et rapide, surtout mobile** | **SnappyMail** |
| **Tu veux remplacer SOGo (mail+agenda+contacts)** | **Bulwark**, en acceptant son statut pré-v1 |
| **Tu as déjà Nextcloud** | **Nextcloud Mail** sur Stalwart, expérience unifiée gratuite |

**Le bon compromis** : déployer **Roundcube ET Bulwark en parallèle** sur deux
sous-domaines. Ils tapent le même serveur, ne partagent aucun état. Tu utilises
Bulwark au quotidien, et Roundcube reste ton filet de sécurité si Bulwark casse à
une mise à jour. Coût : ~100 Mo de RAM. C'est exactement le genre de chose que le
catalogue HomelabUS rend trivial.

### 5bis.3 Les aliases — modèle complet en libre-service

#### D'abord, trois notions à ne pas confondre

| | Définition | Identifiants | Boîte |
|---|---|---|---|
| **Alias** | Une adresse qui **redirige** vers une boîte existante | aucun | la boîte cible |
| **Adresse secondaire** | Un alias pointant vers ta propre boîte | aucun | **la tienne** |
| **Mailbox** | Un vrai compte, boîte séparée | mot de passe propre | la sienne |

Quand tu dis « plusieurs mails pour ma boîte », tu veux des **adresses secondaires** :
`remy@`, `contact@`, `perso@` arrivent tous dans **une seule boîte**, un seul mot de
passe, un seul client à configurer. C'est le cas le plus simple, et il est natif.

#### Ce que Stalwart fait seul

Stalwart gère **aliases et catch-all**, activables, désactivables et annotables, et le
mécanisme d'alias est débrayable par compte.

```
remy@domaine.fr ─┐
contact@domaine.fr ─┼──► boîte "remy"   (aliases classiques, illimités)
perso@domaine.fr ─┘

*@jetable.domaine.fr ──► boîte "remy"   (catch-all : adresses illimitées,
                                          créées en les utilisant)
```

🔴 **Mais la limite est nette : c'est de l'administration, pas du libre-service.**
Les aliases se créent depuis la console d'admin ou l'API. Un utilisateur lambda ne
peut pas créer les siens. **C'est la vraie régression face au panneau utilisateur de
mailcow.**

#### La pièce manquante : idmail — ⛔ finalement écarté

> 🔴 **Décision du 18/08/2026 : idmail n'est PAS intégré.** Ce qui suit décrit ce qu'il
> apporte, parce que ça reste le bon inventaire du besoin — mais la voie retenue est
> que HomelabUS porte le modèle lui-même. La raison est structurelle et se trouve
> juste après le tableau.

**idmail** (MIT) est une interface de gestion de comptes et d'aliases conçue
précisément pour les serveurs mail auto-hébergés comme Stalwart.

| Fonction | idmail |
|---|---|
| **Chaque utilisateur crée ses propres aliases** | ✅ en libre-service |
| Nombre d'aliases par utilisateur | ✅ illimité |
| **Génération d'alias aléatoire** | ✅ |
| **API compatible Bitwarden, addy.io, SimpleLogin** | ✅ ⭐ |
| Plusieurs mailboxes par utilisateur | ✅ |
| Catch-all par domaine | ✅ |
| Gestion multi-domaines | ✅ |
| Statistiques envoi/réception par alias | ⚠️ nécessite des hooks MTA **non documentés** |
| **Aliases temporaires / à expiration** | ❌ **absent** |
| **SSO / OIDC** | ❌ **absent** — login séparé |

⭐ **Le détail qui compte pour toi** : l'API est compatible avec celle de Bitwarden.
Ton **extension navigateur Vaultwarden peut donc générer un alias directement** au
moment où tu crées un identifiant. C'est exactement l'expérience addy.io, sans
addy.io, sans port 25 supplémentaire, sans MariaDB ni Redis.

#### 🔴 Deux points de vigilance sérieux

**1. Maturité.** idmail est un petit projet (une centaine de commits, une trentaine
d'étoiles). Pour une brique qui détient tes comptes mail, c'est un risque réel. Il est
en MIT et adossé à une simple base SQLite, donc reprenable — mais tu dois le savoir.

**2. Conflit d'annuaire avec le SSO.** idmail s'intègre à Stalwart en **annuaire
externe** : Stalwart lit comptes, mailboxes et aliases via des requêtes SQL sur la
base SQLite d'idmail. Conséquence : **idmail devient la source de vérité des comptes**,
ce qui entre en tension avec le provisionnement JIT par PocketID décrit en §5bis.3bis.

→ ✅ **Arbitré en §5.7 (voie A)** : PocketID reste la source de vérité des identités,
idmail gère comptes mail et aliases, et **HomelabUS réconcilie les deux via leurs
API** (`hlb identity sync`). Tu évites d'ajouter un annuaire LDAP, et la
réconciliation est exactement le motif « résolveur de capacités » du §4.3.

#### Ce que HomelabUS doit apporter par-dessus

Le manque le plus visible d'idmail — **les aliases à expiration** — est aussi le plus
facile à combler, et c'est typiquement le rôle de ton projet.

idmail stocke les aliases dans SQLite avec un drapeau `active`. Il suffit d'une
colonne `expires_at` et d'une tâche planifiée :

```rust
// hlb-platform/src/mail/alias_expiry.rs — exécuté toutes les heures
UPDATE aliases SET active = false
WHERE expires_at IS NOT NULL AND expires_at < now() AND active = true;
```

```bash
hlb mail alias new --user remy --expires 7d      # jetable 7 jours
hlb mail alias new --user remy --random          # aléatoire, permanent
hlb mail alias list --user remy
hlb mail alias disable inscription-truc@…        # coupe une fuite
```

C'est ~200 lignes, et ça te redonne **exactement** la fonction « alias temporaire » de
mailcow, en mieux (durée choisie plutôt que figée).

À terme, si idmail te semble trop fragile, HomelabUS peut porter le portail d'aliases
lui-même : le modèle de données est trivial, et tu gagnes l'intégration PocketID
native. À garder en phase 7, pas au démarrage.

#### 🔴 Décision : idmail n'est PAS intégré — HomelabUS porte le modèle

Vérification faite, **idmail et `hlb-mail` ne peuvent pas coexister**, et ce n'est pas
une question de redondance.

idmail ne *parle* pas à Stalwart : il **remplace son annuaire**. On configure Stalwart
avec un `directory` externe de type `sqlite` pointant sur la base d'idmail, qui devient
alors la source de vérité des comptes et des aliases. Or `hlb-mail` écrit dans
l'annuaire **interne** de Stalwart, en JMAP.

Les deux ensemble donneraient : alias créé en JMAP → dans un annuaire que Stalwart ne
consulte plus → l'adresse ne reçoit rien, **et rien ne le signale**. C'est exactement
le mode de panne silencieux que tout ce document cherche à éliminer.

Ce qu'idmail apportait de vraiment distinctif, c'était son **API pour gestionnaires de
mots de passe**. HomelabUS la parle désormais (`POST /api/v1/aliases`, format addy.io
relevé dans le code de Bitwarden), sans le service ni le conflit d'annuaire.

#### Récapitulatif : tes trois besoins

| Ton besoin | Réponse |
|---|---|
| « Plusieurs mails pour ma boîte » | ✅ **Aliases** — `hlb user alias add` |
| « Plusieurs boîtes séparées » | ✅ `hlb user mailbox add`, quota par profil |
| « Temporaires ou permanents, au choix » | ✅ trois axes **indépendants** : durée, nom généré ou choisi, indice de site |
| « Chaque utilisateur crée les siens » | ⚠️ par l'API addy.io ; l'**écran UI reste à écrire** |
| Bonus non demandé | ⭐ génération depuis Vaultwarden, avec choix de la boîte par le jeton |

#### État : fait (`hlb-users`, `hlb user`)

Trois pièges méritent d'être retenus, parce qu'ils sont invisibles à l'usage :

**🔴 Un serveur de messagerie ne sait pas expirer un alias.** La liste `aliases` d'un
compte Stalwart n'a pas de date : ce qui y est écrit y reste. Un alias « temporaire »
ne l'est donc que si une purge vient réellement le supprimer — sinon l'adresse qu'on
croit fermée reçoit pour toujours. D'où **trois** états et non deux : valide,
expiré-et-supprimé, et 🔴 expiré-mais-**toujours actif**. Le controller purge toutes
les heures ; sans cette boucle, la promesse ne tiendrait que si quelqu'un pensait à
lancer la commande.

**🔴 Un alias devinable annule le compartimentage.** Si celui d'Amazon est
`amazon@example.fr`, alors `paypal@`, `banque@` et `impots@` existent probablement
aussi — un expéditeur de masse les essaie toutes pour le prix d'une. On aurait
construit une passoire en croyant construire des cloisons. L'indice ne fait donc jamais
l'adresse : il est suivi d'un suffixe aléatoire de six caractères.

**L'intérêt d'un alias jetable n'est pas de le jeter, c'est l'attribution.** Une adresse
par destinataire dit *qui* a laissé fuiter. C'est pourquoi l'indice lisible est
conservé — cinquante adresses purement aléatoires feraient perdre le seul vrai
bénéfice — et pourquoi les règles Sieve rangent chaque alias dans son dossier.

### 5bis.3bis Plusieurs adresses par compte SSO

- **Provisionnement JIT par OIDC** : Stalwart accepte OIDC (ainsi que LDAP, SQL ou son
  annuaire interne) → la boîte est créée à la première connexion PocketID
- **Aliases** : toutes les adresses supplémentaires pointent vers cette boîte unique

⚠️ Comme partout : **IMAP/SMTP resteront sur des mots de passe d'application.**

### 5bis.4 Stockage : une exception assumée à la doctrine « une seule BDD »

Stalwart accepte plusieurs backends : RocksDB embarqué, FoundationDB, ou SQL
(PostgreSQL / MySQL / SQLite), avec un magasin de blobs séparable (système de
fichiers ou S3).

La tentation serait de le brancher sur ton PostgreSQL partagé — cohérent avec §3, et
tu récupérerais le PITR gratuitement.

**Je le déconseille, et c'est un choix délibéré :**

| | Postgres partagé | **RocksDB local** ✅ |
|---|---|---|
| Cohérence avec la doctrine §3 | ✅ | ❌ exception |
| PITR gratuit via ton archivage WAL | ✅ | ❌ (restic + snapshots) |
| **Le mail survit à une panne du cluster** | ❌ | ✅ |
| Complexité | moyenne | faible |

Le mail est le service qui doit **le moins** dépendre du reste. Un serveur mail qui
tombe parce que ton cluster Swarm redémarre, c'est exactement ce qu'on cherche à
éviter. Le SMTP a des sémantiques de réessai qui pardonnent, mais l'IMAP non — tu
perds l'accès à ta boîte au pire moment.

→ **RocksDB local + blobs sur le disque de la VM.** Sauvegarde par restic (§8), avec
un hook `pre-backup` qui déclenche un point de cohérence Stalwart.

### 5bis.5 Alternatives à Stalwart

Puisque tu demandais à comparer :

Le paysage 2026 se divise en trois familles : les piles assemblées à la main
(Postfix + Dovecot), les **serveurs modernes réécrits de zéro** (Stalwart, Mox), et
les distributions clés en main (mailcow, Mailu).

| | Stalwart CE | **Mox** 🆕 | Mailu | docker-mailserver | mailcow |
|---|---|---|---|---|---|
| Langage / forme | Rust, 1 binaire | **Go, 1 binaire** | conteneurs | conteneurs | ~15 conteneurs |
| Licence | AGPL-3.0 | **MIT** | MIT | MIT | GPL/Syncrasy |
| Webmail intégré | ❌ (Bulwark/Roundcube) | ✅ **mais « early stages »** | ✅ Roundcube/SnappyMail | ❌ | ✅ SOGo |
| SMTP / IMAP | ✅ | ✅ | ✅ | ✅ | ✅ |
| POP3 | ✅ | ❌ **non supporté** | ✅ | ✅ | ✅ |
| JMAP | ✅ | 🔮 prévu | ❌ | ❌ | ❌ |
| **Filtres Sieve** | ✅ ManageSieve | ❌ **pas encore** (rulesets) | ✅ | ✅ | ✅ |
| **CalDAV / CardDAV** | ✅ natif | 🔮 prévu | ❌ | ❌ | ✅ SOGo |
| ActiveSync | ❌ | ❌ | ❌ | ❌ | ✅ |
| **OIDC / SSO** | ✅ (+ LDAP, SQL) | ❌ **prévu (OAUTH2)** | ✅ | ❌ | ✅ |
| Antivirus | ClamAV via milter | ❌ non documenté | ✅ ClamAV | ✅ ClamAV (option) | ✅ ClamAV |
| Antispam | intégré | **bayésien + réputation par utilisateur** | Rspamd | Rspamd/SA | Rspamd |
| DANE / MTA-STS | ✅ | ✅ **point fort** | partiel | partiel | partiel |
| Aliases / catch-all | ✅ | ✅ | ✅ | ✅ | ✅ |
| Aliases temporaires natifs | ❌ Enterprise | ❌ | ❌ | ❌ | ✅ |
| RAM typique | ~0,5–1 Go | **~0,3–0,5 Go** | ~1,5 Go | ~0,7 Go | 6 Go recommandés |
| Pilotable déclarativement | ✅ TOML | ✅ fichiers | moyen | ✅✅ fichiers plats | ⚠️ via API |

#### 🆕 Mox — le nouveau venu sérieux, mais pas pour toi

C'est la nouveauté que tu voulais que je cherche : un **binaire Go unique sous
licence MIT**, avec webmail intégré, DANE et MTA-STS de série, filtrage bayésien
**et réputation apprise par utilisateur**, ACME automatique, autoconfiguration des
clients, et rapports DMARC agrégés. Philosophie « low-maintenance », très soignée,
financé en partie par NLnet.

**Mais trois manques le disqualifient pour ton cas précis :**

1. ❌ **Pas d'OIDC/SSO** (OAUTH2 seulement *prévu*) — or tout ton projet repose sur
   PocketID
2. ❌ **Pas de CalDAV/CardDAV** (prévu) — tu perdrais agenda et contacts
3. ❌ **Pas de Sieve** (des « rulesets » à la place)

Et son webmail est décrit par ses propres auteurs comme *early stages*.

→ **À surveiller sérieusement pour dans 2 ans.** Aujourd'hui, Stalwart est devant sur
tout ce qui compte pour toi.

#### Les autres

**`docker-mailserver`** : tout se configure par fichiers plats, ce qui en fait le
candidat le plus naturel pour une plateforme déclarative comme HomelabUS. Mais ni
webmail, ni interface d'administration, ni CalDAV, ni SSO — tout à assembler.

**Mailu** : mailcow en plus léger, mais sans CalDAV/CardDAV ni alias temporaires.
Il ne t'apporte rien que mailcow n'ait déjà.

#### Verdict

**Stalwart CE + Bulwark (ou Roundcube) + ClamAV + catch-all.**
Tout auto-hébergé, aucune brique externe, aucun conflit de port, ~1 Go de RAM.

### 5bis.6 Plan de migration — sans casser ta délivrabilité

🟢 **Bonne nouvelle qui change tout** : si tu **conserves la même IP publique et le
même rDNS**, ta réputation est préservée. C'était mon principal argument contre la
migration, et il tombe si la nouvelle VM sort par la même IP. Le risque devient
gérable.

#### Phase A — Préparation (aucun risque, réversible)
1. Nouvelle VM en parallèle sur `big-01`, mailcow **intact et en production**
2. Stalwart déployé, hostname temporaire (`mail2.domaine.fr`)
3. Création des domaines et des comptes (ou provisionnement JIT par PocketID)
4. **Nouvelle clé DKIM avec un nouveau sélecteur**, publiée *à côté* de l'ancienne —
   le DNS accepte plusieurs sélecteurs simultanément, aucune coupure

#### Phase B — Synchronisation des données (répétable)
5. `imapsync` mailcow → Stalwart, incrémental, à relancer autant de fois que voulu
6. Export/import des règles Sieve, des aliases, des agendas (CalDAV) et contacts (vCard)

#### Phase C — Validation
7. Tests sur un domaine secondaire d'abord
8. Envoi vers un testeur de délivrabilité : vérifier SPF, DKIM, DMARC, rDNS, et
   l'absence de listing
9. Test complet des clients : iOS, Android, Thunderbird, webmail

#### Phase D — Bascule
10. TTL du MX abaissé à 300 s, **48 h avant**
11. Bascule du MX vers Stalwart
12. **Mailcow conservé en MX secondaire** (priorité plus haute) quelques jours →
    aucun mail perdu même en cas de problème
13. `imapsync` final pour rattraper le delta
14. TTL remis à sa valeur normale

#### Phase E — Après
15. **VM mailcow gelée 30 à 60 jours, pas supprimée** — c'est ton rollback
16. Ancien sélecteur DKIM retiré du DNS après 30 jours
17. `hlb dr-drill mail` : une restauration de test avant de considérer la migration finie

🔴 **Ne lance jamais la phase D un vendredi**, et garde le plan de retour arrière
écrit noir sur blanc avant de commencer.

### 5bis.7 Intégration dans HomelabUS

```yaml
# catalog/stalwart/manifest.yaml
spec:
  runtime: compose
  target: {host: mail-vm, via: ssh}
  requires:
    sso: {type: oidc, scope: admin-console}    # IMAP/SMTP → mots de passe d'app
  storage:
    - {name: data, path: /opt/stalwart, backup: true, tier: local}
  update:
    channel: minor
    backupBefore: true
    window: "sun 04:00-05:00"
  backup:
    preHooks: [{type: exec, command: ["stalwart-cli", "server", "checkpoint"]}]
  monitoring:
    checks: [queue-size, disk-space, cert-expiry, dnsbl-status]
```

Contrairement à mailcow (mode adoption, `deploy: false`), une pile Stalwart déployée
par HomelabUS peut être **entièrement gérée** : déploiement, sauvegarde, mise à jour
automatique, supervision. C'est un gain de cohérence réel — mais il se paie par la
migration.

---

## 6. Réseau, reverse proxy et load balancing

### 6.1 La chaîne d'entrée (ta topologie, automatisée)

```
Internet
   │
   ▼
[Caddy frontend]   TLS termination, ACME DNS-01 wildcard, HTTP/3
   │               rate-limit global, bouncer CrowdSec
   ▼
[Anubis]           challenge proof-of-work anti-scraper (sélectif par route)
   │
   ▼
[Caddy backend]    routage par host/path → services Swarm
   │               en-têtes de sécurité, compression, auth forward
   ▼
[réseau overlay chiffré]  →  services applicatifs
```

HomelabUS **génère intégralement les Caddyfile** depuis les manifests et recharge
Caddy via son API admin (`POST /load`, zéro downtime). Tu n'écris plus jamais de
config Caddy à la main.

Anubis est appliqué **sélectivement** : `chain: [...]` dans le manifest. Tu ne veux
pas de proof-of-work devant une API ou un client mobile (ex. : pas devant l'API
Vaultwarden ni devant le endpoint Git de Gitea — ça casserait `git clone`).

### 6.2 Load balancing Swarm

Swarm te donne le routing mesh + VIP par service. À exploiter :
- `endpoint_mode: vip` (par défaut) : Swarm load-balance en IPVS entre les réplicas
- `dnsrr` pour les cas où le VIP pose problème (services stateful)
- **Caddy backend en `mode: global`** → une instance par nœud, pas de SPOF sur l'entrée
- `placement.preferences: spread by node` pour répartir les réplicas
- healthchecks **obligatoires** : sans eux, Swarm route vers des conteneurs morts

### 6.3 Réseaux et isolation

- **Un réseau overlay par app** + un réseau `platform` pour l'accès aux BDD
- Tous les overlays en `--opt encrypted` (chiffrement IPsec entre nœuds)
- **Les ports Swarm (2377, 7946, 4789) ne doivent JAMAIS être exposés publiquement**
  → mesh WireGuard (ou Tailscale/Netbird) entre les nœuds, Swarm écoute uniquement
  sur l'interface du tunnel
- Politique par défaut : une app ne peut pas parler à une autre app sauf déclaration
  explicite (`security.networkPolicy`)

### 6.4 Gestion du DNS — trou identifié

Chaque app a besoin d'un enregistrement DNS, et l'ACME en DNS-01 (nécessaire pour les
certificats wildcard) exige un accès API chez ton fournisseur. Le plan précédent le
supposait résolu sans jamais le décrire.

#### Trois modes, du plus simple au plus automatique

| Mode | Fonctionnement | Quand |
|---|---|---|
| **Wildcard** ⭐ | Un seul `*.{{ base_domain }}` créé une fois. Toute nouvelle app est immédiatement joignable, **sans aucune action DNS** | ✅ **Recommandé** |
| **API fournisseur** | HomelabUS crée/supprime les enregistrements via l'API (Cloudflare, OVH, deSEC, Gandi…) | Si tu veux des enregistrements précis |
| **Manuel** | HomelabUS affiche l'enregistrement à créer, en action de guide vérifiée (§4.6) | Registrar sans API |

Le mode wildcard est de loin le meilleur compromis : **une action manuelle une seule
fois**, puis plus jamais. Et il se combine avec l'ACME DNS-01 pour obtenir un
certificat wildcard, ce qui évite en prime d'exposer tes sous-domaines dans les
journaux de Certificate Transparency (§9).

Le jeton d'API du fournisseur DNS est un secret sensible : il est stocké dans le
coffre `age` et **restreint à la zone concernée** quand le fournisseur le permet.

#### 🔴 Le piège des limites ACME

Let's Encrypt applique des quotas stricts. Une boucle de réconciliation boguée qui
redemande un certificat en continu te fait bannir pour une semaine — et **tous** tes
services passent en TLS invalide.

Protections obligatoires dans HomelabUS :
- **Toujours tester contre l'environnement de staging** avant le premier certificat réel
- Cache persistant des certificats, jamais régénérés au redémarrage
- Compteur de tentatives avec repli exponentiel, et arrêt net après N échecs
- Alerte **30 jours** avant expiration, pas 7 : ça laisse le temps de réparer
- Renouvellement à 2/3 de la durée de vie, jamais à la dernière minute

### 6.5 IPv6 — trou identifié

Jamais mentionné dans les versions précédentes, alors que c'est un sujet piégeux.

**Docker Swarm et IPv6 cohabitent mal.** Le routing mesh, les réseaux overlay et la
publication de ports en IPv6 sont historiquement fragiles et mal documentés.

**Décision : IPv6 en bordure, IPv4 à l'intérieur.**

```
Internet IPv6 ──► Caddy frontend (double pile)  ──► overlay IPv4 ──► services
Internet IPv4 ──►                                
```

Caddy accepte les deux, le cluster travaille en IPv4. Tu es joignable en IPv6 sans
subir les défauts de Swarm.

🔴 **L'exception qui compte : le mail.** Si ton serveur mail a une IPv6 mais un
enregistrement `AAAA` sans rDNS IPv6 correct, **Gmail et Outlook rejettent tes mails**.
Deux options, à choisir explicitement :

1. **Pas d'enregistrement `AAAA` sur l'hôte mail** — le plus simple, l'envoi passe en
   IPv4. Aucune perte réelle.
2. **IPv6 complet** — `AAAA` + rDNS IPv6 + SPF incluant l'IPv6. Tout ou rien.

Le guide Stalwart (§4.6) vérifie ce point avant la mise en service.

---

## 7. Mises à jour automatiques

Ne pas utiliser Watchtower (pas Swarm-aware). Shepherd fait le job basique, mais
autant l'intégrer proprement pour contrôler la politique.

### Pipeline de mise à jour

```
1. Veille        │ poll des registries → nouveau digest ?
                 │ lecture des release notes / CVE feeds
2. Politique     │ le canal du manifest autorise-t-il ce saut ?
                 │ (pin → jamais | patch → 1.2.3→1.2.4 | minor → 1.2→1.3)
3. Fenêtre       │ on est dans la maintenance window ?
4. Scan          │ Trivy/Grype sur la nouvelle image
                 │ vérification de signature cosign si dispo
5. Backup        │ snapshot restic + dump SQL AVANT toute chose
6. Déploiement   │ docker service update --image <digest>
                 │ order: start-first, parallelism: 1
7. Vérification  │ healthcheck + smoke test HTTP défini au manifest
8a. OK           │ commit, notification, purge de l'ancienne image
8b. KO           │ ROLLBACK automatique (Swarm natif) + restore si migration DB
                 │ alerte ntfy, app épinglée sur l'ancienne version
```

**Règles non négociables :**
- **Toujours épingler par digest**, jamais par tag mouvant. `:latest` = accident garanti.
- **Backup avant mise à jour, systématiquement.** Les migrations de schéma DB ne sont
  pas réversibles par un rollback d'image.
- **Mises à jour échelonnées** : une app à la fois, jamais tout le cluster d'un coup.
- Les **majeures ne sont jamais automatiques** : notification + validation manuelle
  (`hlb app upgrade gitea --to 1.24.0`), avec affichage des release notes.
- Mode **canary** possible : 1 réplica sur N mis à jour, observation, puis le reste.

## 7bis. La mise à jour de HomelabUS lui-même — trou identifié

Le plan décrivait comment mettre à jour **les apps**, jamais comment mettre à jour
**le controller et les agents**. C'est pourtant l'opération la plus délicate du
système : tu remplaces l'outil qui pilote tout, pendant qu'il pilote tout.

#### La règle d'or

> 🔴 **Le controller ne se met jamais à jour lui-même en une seule étape.**
> Il prépare, valide, bascule, et garde la possibilité de revenir en arrière.

#### Séquence

```
1. Sauvegarde de l'état          → export DB + dépôt Git (§2.3)
2. Vérification de compatibilité → la version N+1 lit-elle le schéma N ?
3. Agents d'abord, pas le controller
   └─ un nœud à la fois, vérification de la connexion mTLS après chacun
   └─ ⚠️ l'agent N doit parler au controller N+1 : compatibilité descendante obligatoire
4. Controller ensuite
   └─ migrations de schéma en transaction, réversibles
   └─ nouveau binaire démarré, ancien conservé sur disque
5. Vérification post-bascule
   └─ réconciliation à blanc : l'état observé correspond-il toujours ?
   └─ ❌ si non → retour au binaire précédent + restauration du schéma
```

#### Points de conception

- **Compatibilité N/N+1 obligatoire entre agent et controller.** Sans elle, une mise à
  jour partielle casse le cluster. À traiter par un numéro de version de protocole
  explicite dans le handshake mTLS.
- **Migrations de schéma réversibles.** Chaque migration `sqlx` a son `down`. Testé en
  CI, pas seulement écrit.
- **Les apps continuent de tourner.** Le controller peut être arrêté sans impact sur
  les services : Swarm continue à faire tourner ce qui est déployé. C'est une propriété
  précieuse — **le controller n'est pas dans le chemin critique** du trafic.
- **Jamais de mise à jour automatique du controller.** Notification, validation
  manuelle. C'est le seul composant dont la panne t'empêche de réparer les autres.

```bash
hlb self check-update           # version dispo, notes de version, compatibilité
hlb self update --dry-run       # plan de migration, sans rien changer
hlb self update
hlb self rollback               # binaire + schéma précédents
```

---

## 8. Sauvegardes et restauration

### 8.1 Stratégie 3-2-1 en trois couches

| Couche | Contenu | Outil | Fréquence | Destination |
|---|---|---|---|---|
| **L1 — Logique** | dumps SQL par app | `pg_dump`, `mysqldump` | horaire | NAS + S3 |
| **L1bis — PITR** | archivage WAL continu | pgBackRest / WAL-G | continu | S3 |
| **L2 — Volumes** | données applicatives | restic (via l'agent) | 4h | NAS + S3 |
| **L3 — Système** | manifests, secrets, état | git + age | à chaque changement | S3 + copie froide |

- **NAS** = restauration rapide (LAN, gigabit) → c'est ce que tu utiliseras à 95 %.
- **S3 offsite** = protection contre incendie/vol/ransomware.
- **Immutabilité** : activer l'Object Lock / versioning côté S3, et utiliser une clé
  applicative **append-only** (`restic --no-delete` + politique bucket). Sans ça, un
  ransomware qui compromet le controller efface aussi tes backups.
- **Chiffrement systématique** (restic chiffre nativement en AES-256) — la clé n'est
  jamais stockée uniquement sur le cluster.

### 8.2 Cohérence des sauvegardes

Un `cp` sur un volume de base de données en cours d'écriture produit une sauvegarde
inutilisable. Les hooks du manifest gèrent ça :

```yaml
backup:
  preHooks:
    - type: exec           # dans le conteneur
      command: ["/app/freeze.sh"]
    - type: scale-down     # pour les apps sans mode quiesce
      timeout: 60s
  postHooks:
    - type: scale-up
```

### 8.3 Restauration — le point que tout le monde néglige

**Un backup non testé n'est pas un backup.**

HomelabUS doit intégrer une **vérification automatique de restauration** :
- tous les mois, restauration d'une app dans un namespace isolé (`app-verify`)
- lancement des healthchecks + requêtes de validation (ex. : `SELECT count(*)`)
- comparaison avec les métriques attendues
- rapport + alerte si échec

```bash
hlb restore list vikunja                     # points de restauration disponibles
hlb restore vikunja --at "2026-08-01 14:00"  # PITR
hlb restore --dry-run --to-sandbox           # test sans risque
hlb dr-drill                                 # simulation de reprise complète
```

### 8.4 Choix du stockage offsite

Ordres de grandeur (⚠️ **tarifs à revérifier**, ils changent) :

| Fournisseur | ~Prix / To / mois | Egress | Remarques |
|---|---|---|---|
| **Hetzner Storage Box** | ~3-4 € | gratuit | SFTP/BorgBackup, pas S3 mais parfait pour restic. **Meilleur rapport qualité/prix**, EU |
| **Backblaze B2** | ~6 $ | gratuit jusqu'à 3× le stockage | vraie API S3, Object Lock |
| **Cloudflare R2** | ~15 $ | **0 $** | cher au stockage, imbattable si tu restaures souvent |
| **Scaleway Glacier** | ~2 € | payant | archivage froid, restauration lente |
| **Wasabi** | ~7 $ | gratuit | minimum 1 To facturé |

**Décision retenue** (cible 100 Go – 1 To, extensible) :

```
┌─ OMV / big-01 ────────── dépôt restic complet ─── ⚠️ MÊME MACHINE que les données
│                          → restauration rapide uniquement, PAS une sauvegarde
├─ Hetzner Storage Box ── dépôt restic complet, offsite ── BX11 1 To ≈ 4 €/mois
│                          → LA sauvegarde réelle (cf. §2bis.5)
├─ Backblaze B2 ────────── sous-ensemble critique, Object Lock ── ~5 Go ≈ 0,10 $/mois
└─ Disque USB rotatif ──── copie froide débranchée ── recommandé, ~60 € une fois
```

Le sous-ensemble critique B2 = dumps SQL, secrets chiffrés, manifests, état du
controller. Quelques Go, coût négligeable, mais **c'est la seule copie réellement
immuable** — celle qui survit à un ransomware qui aurait compromis le controller.

Notes :
- Le Storage Box **ne propose pas d'Object Lock**, mais des **snapshots côté Hetzner**
  (à activer). Complété par un sous-compte SFTP en écriture seule, ça donne une
  protection correcte.
- Passage à BX21 (5 To) sans migration si le volume grandit → le tiering du plan tient
  jusqu'à plusieurs To sans rien changer.
- Tout passe par **rclone** : les trois destinations sont déclarées en config, ajouter
  ou remplacer un backend ne touche à aucun code.

```yaml
backup:
  targets:
    - name: nas
      type: sftp
      retention: {daily: 14, weekly: 8, monthly: 6}
    - name: hetzner
      type: sftp
      retention: {daily: 7, weekly: 4, monthly: 12, yearly: 2}
    - name: b2-critical
      type: s3
      objectLock: true
      classes: [critical]        # ne reçoit que les données marquées critical
      retention: {daily: 30, monthly: 12}
```

Chaque app déclare sa classe (`backup.class: critical | standard | none`), ce qui rend
la politique de rétention modulaire app par app.

## 8bis. Observabilité et alerting

Mentionné dans la feuille de route, jamais conçu. Or **un système d'alerte mal réglé
est pire que pas d'alerte du tout** : au bout de trois semaines de faux positifs, tu
ne les lis plus, et tu rates la vraie panne.

### Le principe : alerter sur les symptômes, pas sur les causes

| ❌ Mauvaise alerte | ✅ Bonne alerte |
|---|---|
| « CPU à 85 % » | « gitea répond en plus de 5 s depuis 10 min » |
| « conteneur redémarré » | « vikunja a redémarré 5 fois en 10 min » |
| « disque à 71 % » | « au rythme actuel, disque plein dans 6 jours » |

Une alerte doit répondre à : **est-ce que quelque chose est cassé pour l'utilisateur, et
dois-je agir maintenant ?** Si la réponse est non, c'est une métrique, pas une alerte.

### Quatre niveaux, trois canaux

| Niveau | Exemple | Canal |
|---|---|---|
| 🔴 **Critique** | app injoignable, disque à 95 %, quorum perdu, sauvegarde échouée 2× | **ntfy immédiat** |
| 🟠 **Important** | certificat expire dans 30 j, MAJ de sécurité, action `blocking` en attente | ntfy groupé, 1×/jour |
| 🟡 **Info** | MAJ disponible, sauvegarde réussie | tableau de bord seulement |
| ⚪ **Debug** | traces détaillées | journaux |

**Heures calmes** : les alertes non critiques sont retenues entre 22 h et 8 h. Les
critiques passent toujours.

### La pile

```
Agents → métriques → VictoriaMetrics (léger, compatible Prometheus)
Agents → journaux  → Alloy → stockage local, rétention 14 j
                            └─ ⚠️ rétention OBLIGATOIRE (§9bis)
Controller → alertes → ntfy → ton téléphone
Grafana → tableaux de bord → intégré en iframe dans l'UI, pas réimplémenté
```

### 🔴 Qui surveille le surveillant ?

Si HomelabUS tombe, **rien ne t'alerte** — c'est lui qui envoie les alertes. Faille
classique et rarement traitée.

Solution sans service externe : un **deadman switch inversé**. Le controller écrit un
battement de cœur horodaté sur le NAS (hors cluster). Un `cron` de trois lignes sur le
NAS vérifie l'horodatage et te notifie directement s'il n'a pas bougé depuis 15 minutes.

```bash
# sur le NAS, indépendant du cluster
[ $(( $(date +%s) - $(stat -c %Y /srv/hlb/heartbeat) )) -gt 900 ] && notify "HomelabUS muet"
```

C'est trivial, et c'est la seule chose qui te préviendra si le cluster entier meurt.

#### État : fait (`hlb-metrics`, `hlb metrics …`)

Trois écarts par rapport à l'esquisse ci-dessus, chacun venant d'un défaut constaté :

**1. Le battement est CONDITIONNEL, pas périodique.** La première version écrivait
l'horodatage à chaque tour de minuteur. Un tel battement prouve qu'un fil d'exécution
vit, et **rien d'autre** : le controller peut avoir sa base illisible et son Docker
mort, et battre imperturbablement. Le veilleur reste alors au vert sur un système
inutilisable — ce qui est **pire que pas de deadman**, puisqu'on lui fait confiance. Le
battement passe désormais par une vérification (base d'état lisible, orchestrateur
joignable) et **se tait** sinon : le silence est le signal.

**2. « Jamais armé » est distinct de « silencieux ».** Même raison que `NeverSucceeded`
face à `Stale` dans l'UI : un deadman qui n'a jamais reçu de battement n'a jamais rien
protégé. Le confondre avec une panne récente ferait chercher un incident du jour, alors
que l'installation était mauvaise depuis le début.

**3. Le veilleur a un repli sur stderr.** Constaté en exécutant réellement le script :
`curl … >/dev/null 2>&1` avale son propre échec, donc une alerte perdue ne laisse
aucune trace — le veilleur ne peut pas signaler qu'il n'a pas pu signaler. Le repli
passe par stderr, que cron envoie par courriel : une seconde voie qui ne partage ni le
réseau ni le service de la première.

Trois battements manqués sont tolérés avant l'alerte : une alerte à chaque hoquet du
Wi-Fi est une alerte qu'on finit par couper, et un deadman coupé ne protège de rien.

#### Écart assumé : ni Alloy, ni Alertmanager

**VictoriaMetrics seul** collecte, stocke et répond en PromQL. Prometheus + Alloy + un
stockage distant ajouterait deux services à maintenir pour un résultat identique, et
Alloy n'apporte rien tant qu'il n'y a pas de journaux à router.

**Les règles sont évaluées par HomelabUS**, pas par `vmalert` → Alertmanager. La raison
est précise : `hlb-notify` porte déjà les quatre niveaux de ce paragraphe et les heures
calmes, testés. Confier le routage à Alertmanager obligerait à **redire** ces règles
dans sa configuration, dans une autre syntaxe et sans test — et deux définitions de
« qu'est-ce qui mérite de réveiller quelqu'un » finissent toujours par diverger.

**🔴 Une règle sans donnée n'est jamais « verte ».** Elle est *aveugle*, ce qui est un
troisième état, visible et distinct — et pour les règles qui comptent, l'absence de
donnée déclenche une alerte de son propre chef, à un niveau qui dit « je ne sais plus »
plutôt que « le seuil est franchi ». C'est le même invariant que la métrique absente
plutôt qu'à zéro, appliqué un cran plus haut.

---

## 9. Sécurité (défense en profondeur)

### Niveau hôte
- Mesh **WireGuard** entre nœuds, Swarm ne parle jamais sur l'IP publique
- **Swarm autolock** activé (les clés Raft chiffrées au repos)
- SSH par clé uniquement, pas de root, port non standard, `fail2ban`
- Mises à jour OS automatiques (`unattended-upgrades`), redémarrage planifié
- `auditd` + expédition des logs vers le controller

### Niveau Docker
- **Jamais de socket Docker brut monté dans un conteneur** → `docker-socket-proxy`
  avec permissions minimales par consommateur
- `userns-remap` activé sur le daemon
- Par conteneur : `no-new-privileges`, `cap_drop: ALL` (+ ajouts explicites),
  `read_only: true` + tmpfs, profils seccomp/AppArmor déclarés au manifest
- Limites de ressources obligatoires (évite qu'une app OOM tue un nœud)
- Overlays chiffrés, réseaux cloisonnés par app

### Niveau applicatif
- **Secrets** : chiffrés au repos avec **age/SOPS**, la clé maîtresse hors cluster
  (YubiKey ou papier dans un coffre). Injectés via `docker secret` → jamais dans les
  variables d'environnement, jamais dans le Git.
- **Rotation automatique** des mots de passe de BDD (`hlb secrets rotate`)
- Tous les mots de passe générés aléatoirement, jamais de valeur par défaut
- Scan d'images **Trivy** à l'installation et à chaque mise à jour, blocage sur
  CVE critique
- **CrowdSec** : collections Caddy + composant **AppSec (WAF)**, bouncer au niveau
  du Caddy frontend, partage de la blocklist communautaire

### Niveau HomelabUS lui-même
- L'UI est protégée par PocketID + passkey obligatoire
- **Journal d'audit immuable** : qui a fait quoi, quand, avec le diff
- API en mTLS entre agent et controller, certificats à rotation courte
- Approbation en 2 étapes pour les opérations destructives (`--purge`, restauration
  en production)
- Mode « break-glass » : accès d'urgence documenté si PocketID est HS

### Exposition
- Rien n'est exposé publiquement sans déclaration explicite dans le manifest
- Par défaut, les nouvelles apps sont en **`visibility: private`** (accès via le VPN
  uniquement) — l'exposition publique est un acte volontaire
- Wildcard TLS via DNS-01 → aucun sous-domaine n'apparaît dans les logs Certificate
  Transparency (pas d'énumération de ton infra)

## 9bis. Protection contre la saturation disque — trou identifié

**C'est la panne numéro un des homelabs**, loin devant les défaillances matérielles :
les logs remplissent le disque, et *tout* s'arrête d'un coup — y compris les bases de
données, souvent avec corruption à la clé.

Le plan n'en parlait nulle part.

#### Défense en trois niveaux

**1. Plafonner à la source** — appliqué par défaut à toute app déployée :

```yaml
logging:
  driver: json-file
  options: { max-size: "10m", max-file: "3" }    # 30 Mo max par conteneur
```

Sans ça, un conteneur bavard écrit indéfiniment. **C'est le défaut de Docker, et c'est
un piège.**

**2. Surveiller et alerter tôt** — l'agent remonte l'espace libre en continu :

| Seuil | Action |
|---|---|
| 75 % | notification |
| 85 % | alerte + purge automatique des images inutilisées (`docker image prune`) |
| 90 % | 🔴 **refus de tout nouveau déploiement** et de toute mise à jour |
| 95 % | mode dégradé : arrêt des services non essentiels pour protéger les bases |

**3. Quotas par app** — déclarés au manifest, vérifiés par l'agent :

```yaml
storage:
  - name: data
    quota: 20Gi          # alerte à 80 %, refus d'écriture au-delà si le FS le permet
```

🔴 **Cas particulier des sauvegardes** : un dépôt restic qui grossit sans politique de
rétention remplit le disque et fait tomber la machine qu'il était censé protéger.
Politique de rétention **obligatoire** dans la configuration, jamais optionnelle :

```yaml
retention: { hourly: 24, daily: 14, weekly: 8, monthly: 12, yearly: 3 }
```

---

## 9ter. Modèle d'accès à HomelabUS (RBAC) — trou identifié

Listé comme « à vérifier » depuis le début sans jamais être tranché. Décision :

**Trois rôles suffisent, n'en invente pas plus :**

| Rôle | Peut | Ne peut pas |
|---|---|---|
| `viewer` | tout voir : état, logs, métriques, historique | rien modifier |
| `operator` | installer, mettre à jour, redémarrer, sauvegarder | supprimer avec `--purge`, gérer les accès, restaurer en production |
| `admin` | tout | — |

Rattachés aux **groupes PocketID**, pas gérés dans HomelabUS (§5.9) : une seule source
de vérité pour les identités.

**Et deux garde-fous qui comptent plus que les rôles :**

- **Double validation** pour les opérations destructives : `--purge`, restauration en
  production, suppression d'un nœud. Une confirmation explicite qui nomme la cible.
- **Journal d'audit immuable** : qui, quoi, quand, avec le diff. En append-only, et
  sauvegardé hors du cluster.

Si tu es seul utilisateur, tu es `admin` et le RBAC ne te coûte rien. Mais le poser dès
le départ évite une refonte le jour où tu ouvres un accès à quelqu'un.

## 9quater. Cycle de vie des secrets et perte du controller

### Le problème du déverrouillage au démarrage — trou identifié

Le plan disait « secrets chiffrés avec `age`, clé maîtresse hors cluster ». Mais alors :
**au redémarrage du controller, où trouve-t-il la clé pour déchiffrer ?**

Non résolu jusqu'ici. Quatre options, avec leurs compromis :

| Option | Redémarrage sans toi | Sécurité au repos | Verdict |
|---|---|---|---|
| Clé en clair sur disque | ✅ automatique | ❌ nulle si la machine est volée | ❌ |
| **Clé sur disque + chiffrement du disque (LUKS)** | ✅ automatique | ✅ bonne | ✅ **recommandé** |
| Déverrouillage manuel | ❌ tu dois être là | ✅✅ excellente | Pour les paranoïaques |
| TPM | ✅ automatique | ✅ bonne | Complexe, peu de gain ici |

**Décision : LUKS sur le disque du controller + clé `age` en clair dessus.**
Le raisonnement : ta menace réaliste est le **vol de machine ou de disque**, pas un
attaquant qui a déjà root sur un système démarré (dans ce cas, il a déjà tout). LUKS
couvre la menace réelle, et le cluster redémarre seul après une coupure de courant —
ce qui compte pour un homelab sans opérateur.

🔴 **La clé maîtresse `age` doit exister en deux copies hors ligne** : une imprimée
rangée physiquement, une sur un support chiffré séparé. **Sans elle, aucune sauvegarde
n'est déchiffrable.** C'est le seul secret dont la perte est définitive.

### Rotation

```bash
hlb secrets rotate --app gitea        # nouveau mot de passe BDD, app redémarrée
hlb secrets rotate --all --dry-run    # plan complet avant exécution
hlb secrets rekey                     # change la clé maîtresse, rechiffre tout
```

Rotation automatique trimestrielle des mots de passe de base de données (générés, jamais
tapés, donc sans coût). **Pas** de rotation automatique de la clé maîtresse : opération
manuelle et vérifiée.

### Perte du controller — la procédure

Cas non couvert jusqu'ici : le nœud qui porte le controller meurt.

🟢 **Bonne nouvelle : les apps continuent de tourner.** Swarm maintient les services
déployés sans le controller — il n'est pas dans le chemin critique du trafic. Tu perds
le pilotage, pas le service.

```
1. Nouveau nœud (ou nœud réinstallé) → hlb init --restore
2. Récupération : sauvegarde de l'état + dépôt Git + clé maîtresse age
3. Reconnexion au Swarm existant (les managers restants ont le quorum)
4. Réconciliation à blanc → écart entre l'état attendu et le réel
5. Adoption des services déjà en cours, sans redéploiement
```

Le point de conception qui rend ça possible : **le controller n'est jamais la source de
vérité unique.** L'état vit en trois exemplaires — sa base, le dépôt Git (§2.3), et le
Swarm lui-même. Deux suffisent à reconstruire le troisième.

```bash
hlb dr controller-restore --from <dépôt restic>
hlb dr drill --controller-loss      # simule la perte, sans rien casser
```

### Le runbook imprimé

🔴 **Le jour où tout est éteint, tu n'as accès ni à ton wiki, ni à ton Gitea, ni à ce
document.**

HomelabUS doit générer un **document de reprise autonome**, à imprimer et ranger avec
la clé maîtresse :

```bash
hlb dr runbook --output runbook.pdf
```

Contenu : inventaire des nœuds et de leurs rôles, emplacement des sauvegardes et leurs
identifiants d'accès, ordre de restauration, procédure de reconstruction du controller,
et les codes de récupération PocketID. **Sans réseau, sans cluster, sans écran d'accès.**

À régénérer à chaque changement d'infrastructure — et l'action est suivie dans la file
du §4.6.

---

## 10. Points durs et pièges connus

### 10.1 ⚠️ Mailcow ne supporte PAS Docker Swarm

C'est officiel et documenté chez eux : mailcow-dockerized est prévu pour
`docker compose` uniquement (dépendances de nommage réseau, IPv6, ordre de
démarrage, sa propre MariaDB, son propre Redis). Le faire tourner en Swarm = casse
à chaque mise à jour.

**Solution recommandée :** HomelabUS gère deux types de cibles de déploiement.

```yaml
spec:
  runtime: compose        # au lieu de: swarm
  targetNode: mail-01     # hôte dédié
```

Mailcow tourne sur un hôte dédié (VM ou machine physique, hors du swarm), mais reste
**piloté par HomelabUS** : backups, mises à jour, monitoring, certificats, routage.
Bonus : un serveur mail veut une IP fixe avec bonne réputation, du rDNS et du
SPF/DKIM/DMARC — le mettre à part est de toute façon la bonne pratique.

> 📌 **Deux stratégies possibles** — celle décrite ci-dessous (garder mailcow en mode
> adoption) reste la recommandation par défaut. Si tu veux le remplacer par une pile
> entièrement gérée par HomelabUS, **voir §5bis** : architecture complète, comparatif
> et plan de migration.

#### Situation retenue : mailcow existe déjà et fonctionne — on n'y touche pas

Une VM mailcow dédiée tourne déjà sur `big-01` (OMV + KVM), envoi et réception
opérationnels. **C'est de loin le meilleur des cas** : le sujet le plus fragile du
homelab est déjà résolu, et il n'y a aucune raison de le rejouer.

→ Mailcow est donc le seul service en **mode adoption**, à l'inverse du reste du
projet qui est greenfield. HomelabUS le pilote **sans jamais le redéployer** :

```yaml
apiVersion: hlb/v1
kind: App
metadata: {name: mailcow}
spec:
  runtime: compose
  adopt: true               # ne recrée rien, prend le contrôle de l'existant
  target:
    host: mailcow-vm
    via: ssh
    path: /opt/mailcow-dockerized
  manage:
    backup: true            # ✅ mailcow_backup.sh + volumes + MariaDB interne
    monitoring: true        # ✅ métriques, healthchecks, alertes ntfy
    certificates: false     # ❌ mailcow gère son ACME, on n'y touche pas
    updates: notify-only    # ⚠️ update.sh manuel, jamais automatique
    deploy: false           # ❌ HomelabUS ne fait jamais de docker compose up ici
```

**Pourquoi `updates: notify-only` :** `mailcow.sh update` fait bien plus qu'un pull
d'images (migrations de schéma, changements de config, parfois interventions
manuelles documentées dans les release notes). L'automatiser, c'est se réveiller un
matin sans mail. HomelabUS **détecte** la disponibilité d'une mise à jour, la
notifie, sauvegarde à la demande — et te laisse lancer `update.sh` toi-même.

**Ce que HomelabUS apporte quand même :**
- sauvegarde unifiée dans la même politique que le reste (restic → OMV + Hetzner),
  en appelant `mailcow_backup.sh` comme hook plutôt qu'en copiant les volumes à chaud
- snapshot de la VM avant chaque mise à jour manuelle (`hlb snapshot create mailcow-vm`)
- supervision et alertes (files d'attente, espace disque, expiration des certificats,
  état des blocklists)
- routage optionnel de l'interface web via le Caddy frontend, **si** tu le souhaites
  un jour — pas nécessaire tant que la config actuelle fonctionne

**Règles à ne pas transgresser :**
- Les ports **25, 465, 587, 993, 4190 restent exposés en direct**, jamais derrière
  Caddy ni Anubis (SMTP/IMAP ne sont pas du HTTP — un proof-of-work devant du SMTP
  casserait la réception).
- **Jamais les données mailcow sur NFS** : il embarque sa propre MariaDB.
- La VM mailcow **ne rejoint pas le Swarm**, même « juste pour le monitoring ».

### 10.2 ⚠️ Le stockage, principal talon d'Achille de Swarm

Swarm reprogramme les conteneurs sur d'autres nœuds, **mais les volumes locaux ne
suivent pas**. Un service stateful qui migre repart sur un volume vide. C'est LE
piège qui détruit les données en homelab.

Stratégie par type de donnée :

| Type | Solution | Pourquoi |
|---|---|---|
| Bases de données | **Volume local + `placement.constraints`** épinglé à un nœud | Jamais de DB sur du réseau. Point. |
| Config / petits fichiers | Volume local + réplication restic | Simple, rapide à restaurer |
| Médias, gros fichiers | **NFS depuis le NAS** | Lecture majoritaire, tolère la latence |
| Objets / uploads | **Garage** ou **SeaweedFS** (S3 local) | Réplication native, apps modernes savent parler S3 |

**Ne mets jamais** une base SQLite ou Postgres sur du NFS : le verrouillage de
fichiers y est non fiable → corruption garantie à terme.

Le manifest déclare `storage[].tier` et HomelabUS applique automatiquement les
bonnes contraintes de placement.

### 10.3 Quorum Swarm

Il faut **3 managers** (ou 5) pour tolérer une panne. Avec 2 managers, la perte d'un
seul bloque tout le cluster — c'est pire qu'un seul manager. Avec 1 manager, prévoir
la procédure de restauration du Raft (`docker swarm init --force-new-cluster`), que
HomelabUS doit savoir exécuter.

### 10.4 « Pourquoi pas k3s ? »

Question légitime : k3s apporte CSI (volumes qui suivent), HA réelle, un écosystème
plus riche. Mais : complexité 5×, consommation de RAM supérieure, et **tu as déjà
choisi Swarm**. Swarm est largement suffisant pour un homelab et infiniment plus
simple à débugger à 2h du matin.

→ Prévois quand même une **abstraction `Orchestrator`** dans le code Go (interface
avec `Deploy`, `Scale`, `Rollback`, `Status`). Ça coûte 200 lignes aujourd'hui et te
laisse la porte ouverte vers Nomad/k3s plus tard sans réécrire le produit.

---

## 11. Structure du dépôt

Workspace Cargo — un crate par domaine, pour garder les temps de compilation
supportables (seul le crate touché recompile).

```
homelabus/
├── Cargo.toml                  # [workspace]
├── crates/
│   ├── hlb-cli/                # bin: clap → client de l'API
│   ├── hlb-controller/         # bin: axum + boucle de réconciliation
│   ├── hlb-agent/              # bin: service Swarm global (léger !)
│   │
│   ├── hlb-types/              # ⭐ structs partagées + serde + schemars
│   │                           #    (manifests, états, DTO d'API)
│   ├── hlb-orchestrator/       # trait Orchestrator + impl swarm / compose
│   ├── hlb-catalog/            # parsing, validation, minijinja
│   ├── hlb-resolver/           # enum Capability + résolution
│   ├── hlb-platform/           # postgres, mariadb, valkey, pocketid, caddy
│   ├── hlb-backup/             # restic, dumps, PITR, vérification
│   ├── hlb-updater/            # veille OCI, politique, rollback
│   ├── hlb-secrets/            # coffre age
│   ├── hlb-ingress/            # génération Caddyfile + reload API
│   ├── hlb-security/           # trivy, cosign, crowdsec, policies
│   └── hlb-state/              # sqlx + réconciliation
│
├── catalog/                    # manifests intégrés (aucune recompilation)
│   ├── _platform/              # postgres, caddy, crowdsec, pocketid…
│   ├── gitea/  vikunja/  vaultwarden/
│   └── mailcow/                # runtime: compose, adopt: true
├── web/                        # SvelteKit → adapter-static → rust-embed
├── deploy/                     # bootstrap cluster
└── docs/
```

**`hlb-types` est le crate central** : il porte les structs de manifest et les DTO
d'API, dérive `schemars` (JSON Schema → autocomplétion YAML dans l'éditeur) et
`utoipa` (OpenAPI → types TypeScript). Une seule définition, trois consommateurs.

---

## 11bis. L'interface web : à quoi elle sert et ce qu'il y a dessus

### Le principe directeur

**Le CLI fait tout. L'UI ne sert que là où le CLI est mauvais.** Si un écran ne fait
qu'afficher joliment ce que `hlb status` affiche déjà, il ne mérite pas d'exister.

Le CLI est mauvais à exactement trois choses :

| Besoin | Pourquoi le CLI échoue | Ce que l'UI apporte |
|---|---|---|
| **Voir un système vivant** | `watch hlb status` ne montre pas de tendance, pas de corrélation | Un tableau de bord qui se met à jour seul, où l'anomalie saute aux yeux |
| **Explorer / découvrir** | Parcourir 50 apps ou 90 jours de points de restauration en texte, c'est atroce | Recherche, filtres, navigation temporelle |
| **Faire un truc rare et dangereux** | Restaurer une base à 2h du matin, de mémoire, avec les bons flags = accident | Un assistant guidé, avec aperçu de l'effet **avant** de confirmer |

Tout le reste (installer, mettre à jour, scripter, automatiser) reste meilleur en CLI.

### ⚠️ Ce qu'il ne faut PAS reconstruire

Piège classique : réimplémenter des outils qui existent déjà, et passer 6 mois dessus.

- **Grafana** → tu l'intègres en iframe ou tu pointes dessus. Tu n'écris pas de
  moteur de graphes.
- **L'UI CrowdSec** → tu la déploies comme une app du catalogue et tu la lies.
  Tu affiches juste un résumé (nb de bans actifs, top attaquants).
- **L'admin PocketID** → PocketID a sa propre interface. Tu affiches *quelles apps
  sont câblées au SSO*, et tu renvoies vers PocketID pour gérer les utilisateurs.
- **Un terminal web / un explorateur de fichiers** → surface d'attaque énorme pour
  un bénéfice faible. Tu as SSH.

**HomelabUS agrège et relie. Il ne remplace pas.**

---

### Les écrans

#### 1. Tableau de bord (page d'accueil)

L'objectif, unique et non négociable : **répondre à « est-ce que quelque chose ne va
pas ? » en 2 secondes.**

```
┌─ CLUSTER ─────────────────────────────────────────────────────┐
│ ● quorum (3 managers)   Raft OK   dernier backup il y a 34 min │
└───────────────────────────────────────────────────────────────┘
┌─ NŒUDS ───────────────────────────────────────────────────────┐
│ swarm-heavy   [heavy]  CPU 34%  RAM 11.2/16 Go  SSD 45%   ●    │
│ small-01      [light]  CPU 12%  RAM  3.1/4 Go ⚠ Disk 22%  ●    │
│ small-02      [light]  CPU  8%  RAM  2.4/4 Go   Disk 19%  ●    │
└───────────────────────────────────────────────────────────────┘
┌─ ALERTES ─────────────────────────────────────────────────────┐
│ 🔴 gitea : backup échoué depuis 2 jours                        │
│ 🟠 3 mises à jour en attente (dont 1 corrige une CVE)          │
│ 🟠 small-01 : RAM à 78 %, marge faible                         │
└───────────────────────────────────────────────────────────────┘
┌─ APPS ─── 12 actives ─────────────────────────────────────────┐
│ [grille de cartes : nom, état, réplicas, âge du backup, MAJ]   │
└───────────────────────────────────────────────────────────────┘
```

Règle de design : **rien de vert n'a besoin d'être grand.** L'écran doit être
majoritairement calme, et l'anomalie doit être la seule chose qui attire l'œil.

#### 2. Vue topologie — *l'écran qui justifie à lui seul l'existence de l'UI*

C'est ici que ton problème de **domaines de panne** devient visible. En CLI, tu vois
3 nœuds et tu crois être protégé. En visuel, tu vois immédiatement que deux d'entre
eux sont dans la même boîte physique :

```
┌── DOMAINE DE PANNE : big-01 (fer unique) ──────────┐   ┌── small-01 ──┐
│  ┌ VM swarm-heavy ┐    ┌ VM mailcow ┐              │   │  vikunja ×1  │
│  │ postgres  ●    │    │  mailcow ● │              │   │  gitea   ×1  │
│  │ valkey    ●    │    └────────────┘              │   └──────────────┘
│  │ gitea    ×1    │                                │   ┌── small-02 ──┐
│  └────────────────┘                                │   │  vikunja ×1  │
└────────────────────────────────────────────────────┘   └──────────────┘
      ⚠️ 60 % de la charge sur un seul point de panne physique
```

Fonctions : voir la répartition des réplicas, repérer les violations d'anti-affinité,
lancer un rééquilibrage (avec **aperçu du plan avant application**), drainer un nœud,
poser des labels.

#### 3. Catalogue et installation

- Parcourir / rechercher / filtrer par catégorie
- Clic sur une app → assistant d'installation :
  domaine, SSO oui/non, moteur de BDD (pré-rempli par le manifest), tier de stockage,
  limites de ressources, tier de nœud cible
- **Aperçu du plan avant d'appliquer** : « va créer la base `vikunja`, générer 2
  secrets, ajouter une route Caddy, déployer 2 réplicas sur small-01 et small-02 »
- **Import `docker-compose.yml`** : tu colles ton fichier, l'UI génère le manifest,
  te le montre, tu corriges, tu installes. C'est la fonctionnalité qui rend l'ajout
  de n'importe quelle app self-hosted rapide.

#### 4. Détail d'une app — l'écran où tu passeras le plus de temps

Onglets :

| Onglet | Contenu |
|---|---|
| **Vue d'ensemble** | état, réplicas et leur placement, URL, santé, ressources consommées |
| **Logs** | tail en direct (SSE), filtre, sélection par réplica |
| **Config** | variables, secrets (masqués), volumes, manifest rendu |
| **Sauvegardes** | points de restauration, taille, âge, statut de vérification, bouton restaurer |
| **Mises à jour** | digest actuel, version dispo, changelog, résultat du scan CVE, boutons MAJ / rollback |
| **Métriques** | CPU / RAM / réseau dans le temps |
| **Historique** | journal d'audit filtré sur cette app |

#### 5. Sauvegardes — *la deuxième vraie justification de l'UI*

Parcourir 90 jours de points de restauration en ligne de commande est insupportable.

- **Frise temporelle** : une colonne par jour, vert/rouge par job
- **État des destinations** : local / Hetzner / B2 → espace utilisé, dernière synchro,
  santé. Avec le rappel visuel que le local **n'est pas une sauvegarde** (§2bis.5)
- **Explorateur de restauration** : app → point dans le temps → *ce qui va se passer*
  → essai en bac à sable → confirmation
- **Rapports de vérification** : historique des restaurations de test mensuelles.
  C'est ton seul indicateur fiable que tes backups fonctionnent vraiment.

#### 6. Mises à jour

- File d'attente : app, version actuelle → nouvelle, criticité, CVE corrigées
- Actions par app : approuver / reporter / épingler
- Historique avec résultat (réussie / rollback automatique)
- Configuration des fenêtres de maintenance

#### 7. Sécurité

- Synthèse CrowdSec (bans actifs, top attaquants) + lien vers son UI dédiée
- Résultats des scans d'images, agrégés sur toutes les apps
- Secrets : inventaire, âge, état de rotation — **jamais les valeurs**
- **Carte d'exposition** : ce qui est public vs VPN-only. Facile à se tromper, et une
  vue visuelle attrape immédiatement l'app exposée par erreur
- Expiration des certificats

#### 8. SSO et paramètres

- Quelles apps sont câblées à PocketID, lesquelles ne le sont pas → lien vers PocketID
- Journal d'audit global : qui, quoi, quand, avec le diff
- Notifications (ntfy), réglages du cluster

---

### 💡 Restructuration proposée : sortir l'UI en lecture seule dès la phase 2.5

L'UI est prévue en phase 6, donc dans ~5 mois. C'est trop tard : le tableau de bord et
la vue topologie ont une valeur quotidienne **immédiate**, et sont sans risque.

→ **Phase 2.5 (≈1 semaine) : UI strictement en lecture seule.** Dashboard, topologie,
détail d'app, logs. Aucune mutation, donc aucun risque de casser quoi que ce soit, et
une surface d'attaque quasi nulle.

Les écrans qui *agissent* (installation, restauration, mises à jour) restent en phase 6,
quand les APIs correspondantes seront stabilisées et éprouvées via le CLI.

---

## 12. Feuille de route

Chaque phase produit quelque chose d'**utilisable en production**. Pas de big bang.

> **Contexte retenu : greenfield.** L'import `docker-compose.yml` et l'adoption de
> stacks existantes ne sont donc pas prioritaires → repoussés en phase 6. Tu migres
> mailcow, Gitea, Vikunja et Vaultwarden à la main, service par service, au fur et à
> mesure que les phases les rendent possibles.

### Phase 0 — Fondations et bootstrap (3-4 semaines)
- Workspace Cargo, CLI `clap`, API `axum`, store `sqlx`/SQLite
- Trait `Orchestrator` + implémentation Swarm (⚠️ spike `bollard` **d'abord**)
- **Trait `DistroAdapter`** : Debian/Ubuntu + RHEL en niveau 1 (§2ter.3)
- **Moteur de préchecks en lecture seule** — c'est la brique de confiance
- Binaire **statique musl signé**, `hlb cluster init` avec **assistant TUI** (`ratatui`)
- `hlb node add` par SSH avec **clé dédiée générée par HomelabUS**, révocable
- Agent en service global, **bascule SSH → mTLS** après bootstrap
- WireGuard + Swarm join + autolock
- **Détection des ressources + tiers automatiques + profils de cluster** (§2bis)
- **Comptabilité mémoire et refus d'installation si le nœud ne peut pas tenir**
- **Idempotence et reprise après échec dès le départ**, pas rétrofitées
- ✅ **Livrable** : d'une machine nue à un cluster sécurisé debout, profil `quorum`
  détecté sur les 3 nœuds, `hlb topology explain` fonctionnel

### Phase 0bis — Gestion centralisée des accès SSH (3-4 jours)
- `hlb access grant / revoke / list / audit` — `authorized_keys` distribués par l'agent
- Réconciliation : les clés restent conformes même modifiées à la main
- ✅ **Livrable** : révocation d'un accès en un seul point, sur tout le parc

### Phase 1 — Déploiement d'apps (4-5 semaines)
- **Système de guides + file d'actions en attente + vérifications** (§4.6)
- **Échelle d'automatisation des étapes in-app** env → CLI → API → manuel (§4.6bis)
- **`expose: after-guide`** : pas d'exposition publique avant fermeture des inscriptions
- **Graphe de dépendances et ordonnancement du déploiement** (§4.7)
- **Plafonnement des logs et seuils disque dès le premier déploiement** (§9bis)
- Format de manifest + validateur + moteur de templates
- Boucle de réconciliation
- Postgres + MariaDB + Valkey partagés, provisioning automatique des bases
- Coffre de secrets (age)
- 3 apps de référence : Gitea, Vikunja, Vaultwarden
- ✅ **Livrable** : `hlb app install gitea --domain git.x.fr` fonctionne de bout en bout

### Phase 2 — Ingress & SSO (2-3 semaines)
- Génération Caddyfile (front + anubis + back), rechargement à chaud
- ACME DNS-01 wildcard
- PocketID + création automatique des clients OIDC
- Forward-auth pour les apps sans OIDC
- ✅ **Livrable** : une app installée est accessible en HTTPS avec SSO, sans intervention

### Phase 2.5 — UI en lecture seule (1 semaine)
- SvelteKit + `adapter-static`, embarqué via `rust-embed`
- Types TS générés depuis l'OpenAPI (`utoipa` → `openapi-typescript`)
- Dashboard, vue topologie (domaines de panne), détail d'app, logs en direct (SSE)
- **Aucune mutation** : surface d'attaque quasi nulle, aucun risque de casse
- ✅ **Livrable** : tu vois l'état réel de ton cluster depuis ton téléphone

### Phase 3 — Sauvegardes (3-4 semaines)
- Intégration restic (NAS + S3 via rclone)
- Dumps SQL + hooks de quiesce
- Archivage WAL / PITR Postgres, Litestream pour SQLite
- Restauration, `--to-sandbox`, vérification automatique mensuelle
- **`hlb dr promote` : bascule de Postgres sur un nœud `light` en profil réduit** (§2bis.5)
- ✅ **Livrable** : perte totale de `big-01` → service dégradé restauré en ~20 min,
  procédure testée automatiquement chaque mois

### Phase 4 — Mises à jour automatiques (2-3 semaines)
- Veille registry, épinglage par digest, canaux de version
- Fenêtres de maintenance, backup préalable, rollback automatique
- Scan Trivy, vérification cosign
- **Mise à jour de HomelabUS lui-même** : compatibilité agent N/N+1, migrations
  réversibles, `hlb self update/rollback` (§7bis)
- ✅ **Livrable** : le cluster se met à jour seul, en sécurité, la nuit

### Phase 5 — Sécurité & observabilité (3-4 semaines)
- CrowdSec + AppSec + bouncer + UI
- Politiques réseau, durcissement des conteneurs
- VictoriaMetrics + Grafana + Alloy + alertes ntfy
- Journal d'audit
- **Alerting à quatre niveaux, heures calmes, deadman switch sur le NAS** (§8bis)
- ✅ **Livrable** : tableau de bord de l'état de santé et de sécurité du cluster

### Phase 6 — UI web & catalogue (4-6 semaines)
- SvelteKit embarqué : dashboard, installateur d'apps, explorateur de backups, logs
- Catalogue étendu (30-50 apps), catalogues externes signés
- Import `docker-compose.yml` → manifest
- ✅ **Livrable** : installation d'une app en 3 clics

### Phase 7 — Cas particuliers
- HA Postgres phase 2 (standby + bascule assistée)
- Exercices de reprise après sinistre automatisés

> **État au 18/08/2026 : la feuille de route est couverte.**
>
> La réplication streaming est faite et **vérifiée contre un vrai couple
> primaire/standby** (§3.2) ; il ne manque que `hlb db failover`, la bascule assistée,
> qui demande un second nœud `heavy` réel pour être éprouvée. Les exercices de reprise
> sont faits (`hlb dr exercise`, §8.3).
>
> Ce qui a été ajouté au-delà du plan initial, parce que le besoin est apparu en
> construisant : les **destinations de sauvegarde multiples** (§8.1 rendu réel), les
> **comptes humains et aliases** (§5bis.3), le **multi-conteneur** (§4.8) et le
> **stockage objet** (§3.5).
>
> 🔴 **Le vrai reste à faire n'est pas dans cette liste** : rien de la partie mail n'a
> été exécuté contre un vrai Stalwart. Voir « Ce qui reste » dans CLAUDE.md.

> **~~Runtime `compose` pour mailcow~~ — ABANDONNÉ (décision du 17/08/2026).**
>
> Mailcow n'est pas intégré et ne le sera pas. Stalwart le remplace entièrement
> (§5.9), et il est déjà au catalogue avec son client de provisionnement
> (`hlb-mail`).
>
> Les mentions de mailcow qui subsistent dans ce document sont **historiques** :
> elles expliquent pourquoi Stalwart a été retenu, ce qui reste utile à qui
> reprendrait la décision. Elles ne décrivent aucun travail à faire.
>
> Conséquence directe : le runtime `compose` n'a plus de raison d'être. Il
> n'existait que pour mailcow, qui refuse de tourner autrement qu'en pile
> Docker Compose sur un hôte dédié. Tout le reste du catalogue est en Swarm natif.

---

## 12bis. Stratégie de test

Comment teste-t-on un logiciel dont le rôle est de piloter des clusters de machines ?
C'est la question qui décide si ce projet reste maintenable au bout de six mois.

| Niveau | Portée | Outil | Vitesse |
|---|---|---|---|
| **Unitaire** | résolveur, templates, parsing de manifests, graphe de dépendances | `cargo test` | secondes |
| **Contrat** | validation de tous les manifests du catalogue | `cargo test` + `schemars` | secondes |
| **Intégration** | vrai Docker, un seul nœud | `testcontainers` | ~1 min |
| **E2E Swarm** | cluster à 3 nœuds, vrai bootstrap | VM jetables (`vagrant` / `cloud-init` / QEMU) | ~10 min |
| **Multi-distro** | Debian, Ubuntu, Rocky, Alpine | matrice CI sur images cloud | ~20 min |
| **Restauration** | sauvegarder puis restaurer pour de vrai | E2E nocturne | ~30 min |

#### Les trois tests qui comptent vraiment

1. **Le test de bootstrap multi-distro.** Une VM nue par distribution supportée →
   `hlb init` → cluster fonctionnel. C'est ce qui rend crédible la promesse du §2ter.
   Sans lui, « ça marche sur n'importe quelle distro » est une supposition.

2. **Le test de restauration complète.** Déployer, remplir de données, tout détruire,
   restaurer, **vérifier que les données sont identiques**. C'est le seul test qui
   prouve que ton système de sauvegarde fonctionne (§8.3).

3. **Le test de mise à jour ratée.** Déployer une app, la mettre à jour vers une image
   volontairement cassée, et vérifier que le rollback automatique se déclenche et
   restaure le service. La logique de rollback ne s'exercera jamais en conditions
   réelles avant le jour où tu en auras désespérément besoin — **il faut donc la tester
   exprès.**

#### Le mode `--dry-run` comme test permanent

Chaque commande mutante doit avoir son `--dry-run` qui produit un plan. Ces plans sont
comparables : en CI, on vérifie que le plan généré pour un catalogue donné ne change
pas de façon inattendue entre deux versions (tests d'instantané). C'est peu coûteux et
ça attrape énormément de régressions.

---

## 13. Décisions

### Tranchées

| Sujet | Décision |
|---|---|
| Langage | **Rust** (controller, agent, CLI) + SvelteKit embarqué |
| Cluster | 3 nœuds Swarm, 3 managers, profil `quorum`, **topologie adaptative de 1 à N** |
| Matériel | `big-01` = OMV 32 Go + KVM (VM `swarm-heavy` 16 Go + VM mail 8 Go) ; 2× 4 Go |
| Disponibilité | HA sur le stateless (réplicas adaptatifs + IPVS), PITR sur les bases |
| Anti-affinité | Par **domaine de panne**, pas par nœud (2 VM = 1 seul fer) |
| Stateful | VM `swarm-heavy`, disque virtio SSD. **Jamais sur NFS.** |
| Migration | Greenfield, sauf mailcow en **mode adoption** (jamais redéployé) |
| Offsite | Hetzner Storage Box ≈4 €/mois = **la vraie sauvegarde** + B2 immuable |
| Mailcow | Deux voies (§5bis) : **rester** en `adopt`/`notify-only`, ou **migrer** vers Stalwart CE + Bulwark + ClamAV + idmail |
| Webmail | **Bulwark seul** (JMAP), + un client IMAP en filet de sécurité |
| SSO | Gitea, Vikunja, **Vaultwarden (1.35.0+, officiel)**, Stalwart : OIDC natif |
| Fournisseur d'identité | **PocketID conservé** (§5.7) ; identités réconciliées par HomelabUS, pas de LDAP ajouté |
| Aliases | **idmail** en libre-service + **expiration ajoutée par HomelabUS** |
| Accès OS | 🔴 **Pas d'auth Unix centralisée** — `authorized_keys` distribués par l'agent |
| Installation | Binaire **statique musl signé**, TUI pour le maître, assistant web pour les nœuds |
| Dépendances | **Installées automatiquement**, annoncées avant, jamais écrasées si déjà présentes |
| Actions manuelles | **Guides vérifiables et re-vérifiés** (§4.6) |
| Config dans les apps | **Échelle d'automatisation** env → CLI → API → manuel guidé (§4.6bis) |
| Premier compte admin | `expose: after-guide` — **pas d'exposition publique avant fermeture des inscriptions** |
| DNS | **Wildcard** + ACME DNS-01 → une seule action manuelle, une seule fois |
| RBAC | 3 rôles adossés aux groupes PocketID + double validation sur le destructif |
| Secrets au démarrage | **LUKS sur le disque du controller** + clé `age` dessus → redémarre seul |
| IPv6 | **En bordure (Caddy) seulement**, IPv4 dans le cluster. Pas d'`AAAA` sur l'hôte mail |
| Alerting | Sur les **symptômes**, pas les causes. 4 niveaux, heures calmes 22h–8h |
| Tout auto-hébergé | ✅ aucune dépendance à un service externe, nulle part |

### Trous comblés dans cette révision

| Trou | Traité en |
|---|---|
| Mise à jour de HomelabUS lui-même | §7bis |
| Ordonnancement des dépendances entre services | §4.7 |
| Gestion du DNS et limites ACME | §6.4 |
| Saturation disque (panne n°1 des homelabs) | §9bis |
| Modèle RBAC | §9ter |
| Stratégie de test du projet | §12bis |
| Versionnement du catalogue | §4.8 |
| IPv6 (et le piège du rDNS mail) | §6.5 |
| Observabilité, alerting, deadman switch | §8bis |
| Déverrouillage des secrets au démarrage | §9quater |
| Perte du controller + runbook imprimé | §9quater |
| Actions manuelles hors système (DNS, box, rDNS) | §4.6 |
| Manipulations **dans** les apps web | §4.6bis |
| Installation automatique des dépendances | §2ter.6 |

### Restant à vérifier

**Avant d'écrire du code :**
1. ✅ **Spike `bollard` — FAIT, validé le 2026-08-05.** 7 questions testées contre un
   Swarm réel : création, convergence, contraintes de placement, `ServiceUpdate` avec
   contrôle de concurrence, **rollback automatique sur mise à jour ratée**, filtrage
   par label, erreurs typées. **Aucun repli vers l'API HTTP brute n'est nécessaire.**
   Détail dans le README, tests dans `crates/hlb-orchestrator/tests/swarm_spike.rs`.
2. 🔴 **Spike API PocketID** — création de clients OIDC par programme (§5.11).
3. 🟠 **Arbitrage annuaire mail** — PocketID ↔ idmail ↔ Stalwart (§5.7, voie A).

**Sur ton infrastructure :**
4. **ZFS ou ext4 sur OMV ?** → si ZFS, plafonner `zfs_arc_max` **avant tout** (§2bis.0).
5. **SSD dédié pour la VM `swarm-heavy` ?** → sinon les bases tournent sur le pool
   mécanique : fonctionnel, mais plafonné.
6. **Débit descendant** → dimensionne le RTO offsite réel (§2bis.5).
7. **Port 25 sortant et rDNS** → bloquant **uniquement** si tu migres mailcow (§5bis.6).
8. **Troisième copie physique** (disque USB rotatif) → meilleur rapport sécurité/prix
   de tout le projet.
