# HomelabUS

Plateforme de gestion d'un cluster Docker Swarm auto-hébergé : déploiement d'apps,
bases mutualisées, SSO, reverse proxy, sauvegardes et mises à jour automatiques.

📄 **L'architecture complète est dans [PLAN.md](PLAN.md).**

---

## État d'avancement

| Composant | État |
|---|---|
| Spike `bollard`/Swarm (risque n°1) | ✅ **validé** — voir ci-dessous |
| `hlb-types` — manifests, capacités, **liaisons**, validation | ✅ 69 tests |
| `hlb-orchestrator` — trait + implémentation Swarm | ✅ 24 tests + 11 d'intégration |
| `hlb-resolver` — résolution + graphe + plan | ✅ 26 tests |
| `hlb-catalog` — chargement et validation | ✅ 9 tests |
| `hlb-state` — état persistant, reprise, secrets, **comptes** (sqlx/SQLite) | ✅ 87 tests |
| `hlb-secrets` — coffre `age`, génération de mots de passe | ✅ 11 tests |
| `hlb-platform` — provisionnement isolé **PostgreSQL + MariaDB** | ✅ 14 tests + 11 d'intégration |
| `hlb-engine` — exécuteur + **réconciliation** (§2.1) | ✅ 28 tests |
| `hlb-ingress` — Caddyfile, CrowdSec, **forward-auth**, **ACME wildcard** | ✅ 40 tests + 7 d'intégration |
| `hlb-registry` — résolution de digest, politique de version | ✅ 28 tests + 6 d'intégration |
| `hlb-updater` — veille, fenêtres, rollback, **Trivy + cosign** | ✅ 30 tests |
| `hlb-backup` — restic, PITR, SQLite, DR, réplication, MariaDB, **destinations**, **restaurabilité** | ✅ 207 tests + 17 d'intégration |
| `hlb-identity` — client PocketID : OIDC, **connexion des personnes** (PKCE) | ✅ 17 tests + 4 d'intégration |
| `hlb-mail` — client Stalwart (JMAP) : boîtes, aliases, **Sieve** | ✅ 16 tests |
| `hlb-guide` — vérification + automatisation des guides | ✅ 16 tests |
| `hlb-gitops` — miroir Git de l'état désiré | ✅ 10 tests |
| `hlb-bootstrap` — distributions, préchecks, **accès SSH gérés** | ✅ 78 tests + 4 d'intégration |
| `hlb-agent` — état du nœud, **protocole 2** (charge, CPU, swap), PKI + mTLS | ✅ 61 tests |
| `hlb-controller` — daemon : API, RBAC, audit chaîné, boucles, **mode démo** | ✅ 185 tests + 3 d'intégration |
| `hlb-mesh` — clés WireGuard, adressage, configurations | ✅ 23 tests |
| `hlb-notify` — ntfy : niveaux, heures calmes | ✅ 16 tests |
| `hlb-cli` — 28 commandes : `install`, `backup`, `user`, `metrics`, `replication`… | ✅ utilisable |
| `hlb-api` — types de l'API, **partagés serveur et UI** | ✅ 97 tests |
| `hlb-selfupdate` — compatibilité N/N+1, séquence, retour arrière | ✅ 44 tests |
| `hlb-ui` — **20 écrans egui** : natif, web, téléphone, PWA, kiosque | ✅ 146 tests + 3 d'intégration |
| `hlb-metrics` — règles d'alerte, collecte, **deadman switch** | ✅ 31 tests |
| `hlb-objstore` — client Garage : compartiments et clés isolées | ✅ 6 tests |
| `hlb-users` — comptes, boîtes, **aliases**, quotas, **Sieve**, **API addy.io** | ✅ 51 tests |

**1370 tests unitaires + 66 tests d'intégration** (ces derniers `#[ignore]` : ils exigent
Docker, un réseau, ou un vrai controller). `cargo clippy --all-targets` reste à zéro
avertissement.

### Tests d'intégration PostgreSQL

Ils prouvent la promesse d'isolation du §3.1 — *un Gitea compromis ne peut pas lire
la base de Vaultwarden*. Une revendication de sécurité se prouve, elle ne se suppose pas.

```sh
docker run -d --name hlb-test-pg -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:17-alpine
export HLB_TEST_PG=postgres://postgres:test@localhost:55432/postgres
cargo test -p hlb-platform -- --ignored --test-threads=1 --nocapture
docker rm -f hlb-test-pg
```

### Tests contre les vrais registres

La danse d'authentification OCI (401 → `WWW-Authenticate` → jeton → réessai) ne se
teste pas contre un bouchon : chaque registre a ses particularités.

```sh
cargo test -p hlb-registry -- --ignored --nocapture   # accès réseau requis
```

### Tests multi-distribution

⚠️ Ces tests **ne téléchargent jamais d'image** : une distribution dont l'image
n'est pas déjà présente localement est ignorée, et le test le dit. `docker pull`
reste à ta main.

```sh
export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
cargo test -p hlb-bootstrap -- --ignored --test-threads=1 --nocapture
```

### Tests PocketID

PocketID ne publie pas de spécification OpenAPI : la forme de son API a été
établie en la sondant. Ces tests sont la seule garantie que le client reste juste.

```sh
cargo test -p hlb-identity -- --ignored --test-threads=1 --nocapture
```

### Tests de sauvegarde et restauration

§8.3 — « un backup non testé n'est pas un backup ». Ces tests détruisent
réellement les données et vérifient qu'elles reviennent à l'identique.

```sh
export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
cargo test -p hlb-backup -- --ignored --test-threads=1 --nocapture
```

Dont le cas décisif du §8.1 : un `pg_dump` pris **pendant** des écritures
concurrentes, restauré, et dont on vérifie que l'invariant transactionnel tient.
C'est précisément ce qu'une sauvegarde de fichiers ne sait pas faire.

## Essayer

```sh
cargo build
./target/debug/hlb catalog list
./target/debug/hlb catalog validate
./target/debug/hlb order
./target/debug/hlb plan gitea --domain git.example.fr

# Installation — aperçu par défaut, rien n'est modifié
./target/debug/hlb install valkey
./target/debug/hlb install valkey --apply    # exécute réellement
./target/debug/hlb todo                      # actions manuelles en attente
./target/debug/hlb todo --verify             # les vérifie et retire ce qui est fait
./target/debug/hlb ack gitea/gitea-first-admin
./target/debug/hlb secrets                   # inventaire, jamais les valeurs

# Réconciliation : détection seule, puis correction
./target/debug/hlb reconcile
./target/debug/hlb reconcile --apply

# Configuration Caddy générée depuis les manifests figés
./target/debug/hlb ingress
./target/debug/hlb ingress --apply --front-admin http://caddy-front:2019
```

Pour le provisionnement réel des bases :

```sh
export HLB_POSTGRES_ADMIN=postgres://postgres:motdepasse@hote:5432/postgres
```

🔴 La clé maîtresse (`hlb-master.key`) est créée au premier usage. **Sa perte rend
tous les secrets et toutes les sauvegardes irrécupérables** — garde deux copies
hors ligne. Elle est dans `.gitignore` : elle ne doit jamais entrer dans un dépôt, et
sa fuite vaut la fuite de tout le coffre.

⚠️ Les tiers de nœuds sont des contraintes de placement Swarm. `hlb node add` les
pose ; sur un nœud rattaché à la main, il faut le faire soi-même — sinon rien ne se
planifie et `wait_healthy` expire :

```sh
docker node update --label-add tier=heavy $(docker node ls -q)
```

## L'interface

20 écrans en **egui** : le même code tourne en natif, dans le navigateur (wasm) et sur
un téléphone (PWA installable). `hlb-api` définit les types **une seule fois** pour le
serveur et pour l'interface — il n'y a pas d'OpenAPI, et il n'y en aura pas.

Le moyen le plus rapide de la voir, sans cluster ni Docker : le **mode démonstration**,
qui peuple une base en mémoire des cas qu'on n'a jamais sous la main — app jamais
sauvegardée, hors-site mort depuis trois semaines, alias expiré qui reçoit encore,
compte à moitié créé dans les deux sens.

```sh
./target/debug/hlb-controller --demo --listen 127.0.0.1:8420 &
./target/debug/hlb-ui --url http://127.0.0.1:8420 --route /apps
```

Pour la version web :

```sh
crates/hlb-ui/build-web.sh          # budget de taille vérifié : 6 Mo max
./target/debug/hlb-controller --demo --ui-dir crates/hlb-ui/web
```

Ce que l'interface fait et que le CLI ne fait pas — c'est ce qui justifie son
existence :

- **La topologie** : les nœuds regroupés par **domaine de panne**, et les violations
  d'anti-affinité. L'information vivait dans les étiquettes Swarm et n'était lisible
  nulle part. « Domaine non déclaré » y est distinct de « nœud isolé ».
- **La corrélation** : restaurabilité (« si je perds tout maintenant, je récupère
  quoi ? »), simulateur de panne, chaîne causale de la tâche en échec au disque plein,
  frise unifiée des sauvegardes et des actions, exposition **déclarée** contre
  **réellement posée**.
- **Les opérations rares et dangereuses** : rotation assistée d'un secret (le coffre
  n'est pas la source de vérité), break-glass avec attestations datées qui expirent,
  runbook imprimable engendré depuis l'état réel et sans aucun secret, plans nommés
  préparés à froid puis rejoués **tels qu'ils ont été prévisualisés**.

🔴 **Une donnée périmée ne ressemble jamais à une donnée fraîche.** Si le controller
tombe, l'interface garderait son dernier état connu : toutes les apps vertes pendant
que le cluster brûle. `Ressource<T>` porte sa `Freshness`, que le type oblige à
regarder — et le service worker de la PWA ne met **jamais** l'API en cache.

## Sauvegardes — le 3-2-1 du §8.1

Le routage se fait par **classe de volume**, pas par importance : tout est important,
mais tout ne passe pas dans une connexion domestique.

```sh
hlb backup dest add nas     --location /mnt/nas/restic --classes critique,volumineux
hlb backup dest add garage  --location s3:http://garage:3900/hlb --classes critique
hlb backup dest add offsite --location s3:https://s3.exemple.com/depot \
  --classes critique,volumineux --access-key <clé>   # le secret est lu sur STDIN

# Les bases partout, les photos seulement où la connexion suit
hlb backup route immich  --critique nas,garage,offsite --volumineux nas,offsite
hlb backup route seafile --critique nas,garage,offsite --volumineux nas

hlb backup status        # par destination, jamais agrégé
hlb backup run --force
```

🔴 `backup status` mesure la fraîcheur **par destination**. Une agrégation ferait
passer un hors-site mort depuis trois semaines pour une sauvegarde de 2 h, parce que le
NAS, lui, tourne — et l'on croirait le 3-2-1 tenu alors qu'il ne reste qu'une copie.

## Comptes et aliases (§5bis.3)

```sh
hlb user add remy --email remy@exemple.fr    # identité PocketID + boîte, en une fois
hlb user mailbox add remy photo              # une boîte de plus (quota par profil)

# Trois axes INDÉPENDANTS : durée, nom généré ou choisi, indice de site
hlb user alias add remy                            # aléatoire, permanent
hlb user alias add remy --pour amazon              # aléatoire lié à un site
hlb user alias add remy --pour fnac --pendant 30j  # jetable et attribuable
hlb user alias add remy --nom-alias contact        # choisi, permanent

hlb user alias list remy --problemes   # les expirés TOUJOURS actifs
hlb user alias purge --apply           # ce qui rend l'expiration vraie
hlb user alias sieve remy --apply      # pose les règles de tri chez Stalwart
```

🔴 Stalwart n'a **aucune notion d'expiration** : sa liste d'aliases n'a pas de date. Un
alias « temporaire » ne l'est que si la purge le supprime réellement — le controller la
fait tourner toutes les heures. D'où trois états et non deux : valide, expiré-et-
supprimé, et **expiré-mais-toujours-actif**.

### Génération depuis Vaultwarden

HomelabUS parle le protocole d'addy.io, celui que Bitwarden sait appeler :

```sh
hlb token create bw-perso --user remy                  # → boîte par défaut
hlb token create bw-photo --user remy --mailbox photo  # → boîte « photo »
```

Le jeton se colle dans les réglages du générateur de Bitwarden. Le protocole n'ayant
aucun champ pour choisir la boîte, c'est le **jeton** qui la porte : un jeton par boîte.

⚠️ Un jeton sans `--user` est un jeton de **service** : il ne peut pas créer d'alias au
nom de quelqu'un, même en rôle `admin`. Le privilège ne remplace pas l'identité.

## Le daemon

```sh
./target/debug/hlb-controller \
  --listen 127.0.0.1:8420 \
  --agent-service hlb-agent --agent-poll-secs 60 \
  --reconcile-secs 60 --reconcile-apply \
  --backup-repo hlb-depot --backup-check-secs 600 \
  --heartbeat /mnt/nas/hlb-heartbeat
```

Le battement de cœur va **hors du cluster** (§8bis) : c'est le controller qui
envoie les alertes, donc rien ne préviendrait s'il mourait.

🔴 **Le battement est conditionnel, pas périodique.** Il ne part que si la base
d'état répond et que Docker répond. Un battement de simple minuteur ne prouverait
que la survie d'un fil d'exécution : le controller pourrait avoir sa base illisible
et son orchestrateur mort, et laisser le veilleur au vert sur un système
inutilisable — pire que pas de deadman, puisqu'on s'y fie.

Le script du veilleur se génère, et se pose **sur le NAS** :

```sh
hlb metrics deadman --ntfy https://ntfy.sh/mon-veilleur > veilleur.sh
# puis, en cron toutes les 5 minutes, SUR LE NAS :
#   */5 * * * * /srv/hlb/veilleur.sh
```

Son sujet ntfy doit être **distinct** de celui de HomelabUS : si le controller est
mort, c'est le veilleur seul qui doit pouvoir parler.

## Observabilité

```sh
hlb metrics rules                      # les règles livrées et leurs seuils
hlb metrics scrape --token <jeton>     # config de collecte VictoriaMetrics
hlb metrics check                      # évalue tout maintenant
```

🔴 `hlb metrics check` distingue **« aveugle »** de **« vert »** : une règle sans
donnée n'est pas une règle satisfaite, et le code de sortie le reflète.

## Développement

```sh
cargo test                  # tests unitaires, sans Docker (rapide)
cargo clippy --all-targets
```

### Tests d'intégration Swarm

Ils sont `#[ignore]` par défaut pour que `cargo test` reste utilisable sans Docker.

```sh
docker swarm init

# ⚠️ Sur macOS + colima/Docker Desktop, le socket n'est pas /var/run/docker.sock :
export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')

cargo test -p hlb-orchestrator -- --ignored --test-threads=1 --nocapture
```

---

## Résultat du spike `bollard` (§13 du plan)

Le plan identifiait `bollard` comme **le risque principal** : moins éprouvé que le SDK
Go sur la partie Swarm. Sept questions devaient être tranchées avant d'écrire le reste.

| # | Question | Résultat |
|---|---|---|
| 1 | Daemon et Swarm joignables | ✅ |
| 2 | Création de service + convergence des réplicas | ✅ 2/2 tâches |
| 3 | Contraintes de placement (socle du §2bis) | ✅ satisfiable **et** non satisfiable gérées |
| 4 | Mise à jour d'image avec contrôle de concurrence | ✅ |
| 5 | 🔴 **Rollback automatique sur mise à jour ratée** | ✅ `RollbackStarted`, **service jamais tombé** |
| 6 | Filtrage par label (ne jamais toucher au non-géré) | ✅ |
| 7 | Erreurs typées plutôt que panics | ✅ `NotFound` |

**Conclusion : aucun repli vers l'API HTTP brute n'est nécessaire.** `bollard` couvre
toute la surface Swarm dont HomelabUS dépend. Le pari du §1 est validé.

Le point 5 est le plus important : il prouve que `failure_action: rollback` +
`order: start-first` fonctionnent réellement — c'est le socle du pipeline de mise à
jour automatique (§7), et la seule chose qui rend acceptable de laisser un système
mettre à jour tes services à 3 h du matin.

## Licence

AGPL-3.0-or-later.

## Limites assumées

Ces manques sont **explicites dans le code**, jamais masqués. Une absence qui
ressemblerait à un succès est traitée comme un défaut, pas comme un raccourci.

### Non vérifié contre un vrai serveur

- 🔴 **Toute la partie mail.** `hlb-mail` est écrit à partir du code source de
  Stalwart, mais **jamais exécuté contre une instance réelle** : pas d'image en local.
  Restent à éprouver le chemin `/jmap/upload/`, la forme d'`onSuccessActivateScript`,
  le format de `/jmap/download/` et `x:Account/get` sur `aliases`. C'est plus faible
  que la réplication PostgreSQL, elle vérifiée contre un vrai couple.
- **Les dumps MariaDB** passent par un runner simulé, pour la même raison.

### Actions de l'API qui ne sont pas encore branchées

L'interface sait **prévisualiser** ces quatre actions — le plan affiché est le vrai,
produit par le résolveur — mais l'exécution rend `NonImplementee` avec sa raison, et
renvoie vers la commande à taper. Jamais un faux succès.

| Action | Ce qui manque |
|---|---|
| installer une app | coffre + orchestrateur + clients de plateforme dans l'état de l'API |
| lancer une sauvegarde | le dépôt restic vit dans la boucle du controller |
| drainer un nœud | `Orchestrator` n'expose pas la disponibilité |
| supprimer une app | orchestrateur + exécuteur |

Les autres routes du lot 5 agissent réellement : attester un guide, déclarer une
destination, mettre à l'échelle, ainsi que tous les réglages et la gestion des comptes.

### Fonctionnalités absentes

- **Pas de libre-service pour les aliases.** Un utilisateur passe par la ligne de
  commande ou par l'API addy.io ; l'écran `MaBoite` reste à écrire. Deux autres écrans
  sont dans ce cas — `MonCompte` et `Catalogue`. Ils sont **absents de la navigation**
  tant qu'ils n'existent pas : proposer un écran vide serait pire que ne rien proposer.
- **`hlb user mailbox add` n'ouvre pas le compte Stalwart**, il l'enregistre seulement.
  Les ACL IMAP — plusieurs boîtes sous une seule connexion — ne sont pas câblées.
- **`hlb db failover`** n'existe pas : la réplication fonctionne et est vérifiée, mais
  la bascule reste manuelle. Elle demande un second nœud `heavy` réel.
- **Le déploiement multi-nœuds de Garage** passe par `garage layout`, pas par
  `replicas` : une seule instance tant qu'il n'y a qu'un nœud de stockage.
- **Pas d'import `docker-compose.yml`** — écarté d'entrée, contexte greenfield (§12).
- **Pas d'assistant TUI** pour `hlb cluster init` : la commande existe et est
  idempotente, sans l'accompagnement `ratatui` prévu au §12.

### Choix assumés

- **La réconciliation ne corrige pas par défaut** : `--reconcile-apply` doit être
  demandé. Un système qui corrige trop est plus dangereux qu'un système qui ne corrige
  rien.
- **`Verify::Exec`** est rapporté comme non vérifié, jamais comme réussi.
- **Sans dépôt configuré, toute mise à jour exigeant une sauvegarde est refusée.** De
  même si l'app n'a aucun volume connu : « rien à sauvegarder » ne vaut jamais
  « sauvegarde réussie ».
- **`Unimplemented` n'est jamais `Done`.** Sans coffre, sans PostgreSQL ou sans
  Stalwart, l'action est enregistrée non implémentée — jamais simulée.
- **Bulwark est en `channel: pin`** : aucune release Git, aucune licence déclarée,
  seules les images existent. Roundcube l'accompagne comme filet de sécurité.
- `age` tire `proc-macro-error2`, signalé comme incompatible avec un futur Rust.
  Dépendance transitive, sans action possible de notre côté.
