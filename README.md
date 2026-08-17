# HomelabUS

Plateforme de gestion d'un cluster Docker Swarm auto-hébergé : déploiement d'apps,
bases mutualisées, SSO, reverse proxy, sauvegardes et mises à jour automatiques.

📄 **L'architecture complète est dans [PLAN.md](PLAN.md).**

---

## État d'avancement

| Composant | État |
|---|---|
| Spike `bollard`/Swarm (risque n°1) | ✅ **validé** — voir ci-dessous |
| `hlb-types` — manifests, capacités, **liaisons**, validation | ✅ 52 tests |
| `hlb-orchestrator` — trait + implémentation Swarm | ✅ 7 tests d'intégration |
| `hlb-resolver` — résolution + graphe + plan | ✅ 25 tests |
| `hlb-catalog` — chargement et validation | ✅ 9 tests |
| `hlb-state` — état persistant, reprise, secrets (sqlx/SQLite) | ✅ 27 tests |
| `hlb-secrets` — coffre `age`, génération de mots de passe | ✅ 11 tests |
| `hlb-platform` — provisionnement isolé **PostgreSQL + MariaDB** | ✅ 14 + 11 tests |
| `hlb-engine` — exécuteur + **réconciliation** (§2.1) | ✅ 25 tests |
| `hlb-ingress` — Caddyfile, CrowdSec, **forward-auth**, **ACME wildcard** | ✅ 33 + 7 tests |
| `hlb-registry` — résolution de digest, politique de version | ✅ 28 + 6 tests |
| `hlb-updater` — veille, fenêtres, rollback, **Trivy + cosign** | ✅ 30 tests |
| `hlb-backup` — restic, PITR, SQLite, Litestream, DR, **exercices**, **réplication**, **MariaDB** | ✅ 177 + 18 tests |
| `hlb-identity` — client PocketID : provisionnement OIDC | ✅ 5 + 4 tests |
| `hlb-mail` — client Stalwart (JMAP) : boîtes et aliases | ✅ 16 tests |
| `hlb-guide` — vérification + automatisation des guides | ✅ 16 tests |
| `hlb-gitops` — miroir Git de l'état désiré | ✅ 7 tests |
| `hlb-bootstrap` — distributions, préchecks, **accès SSH gérés** | ✅ 72 + 6 tests |
| `hlb-agent` — état du nœud, seuils disque, **PKI + mTLS** | ✅ 37 + 10 tests |
| `hlb-controller` — daemon : API de lecture, `/metrics`, boucles de fond | ✅ 45 + 3 tests |
| `hlb-mesh` — clés WireGuard, adressage, configurations | ✅ 23 tests |
| `hlb-notify` — ntfy : niveaux, heures calmes | ✅ 16 tests |
| `hlb-cli` — `install`, `node add`, `access`, `backup`, `dr`, `pki`, `mesh`, `crowdsec`… | ✅ utilisable |
| `hlb-api` — types de l'API, **partagés serveur et UI** | ✅ 11 tests |
| `hlb-selfupdate` — compatibilité N/N+1, séquence, retour arrière | ✅ 22 tests |
| `hlb-ui` — tableau de bord **egui** : natif, web, téléphone | ✅ 20 + 2 tests |
| `hlb-metrics` — règles d'alerte, collecte, **deadman switch** | ✅ 31 tests |
| `hlb-objstore` — client Garage : compartiments et clés isolées | ✅ 6 tests |

**836 tests unitaires + 66 tests d'intégration** (ces derniers `#[ignore]`, ils exigent Docker).

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
hors ligne.

⚠️ Les tiers de nœuds sont des contraintes de placement Swarm. En attendant
`hlb node add`, il faut poser le label à la main :

```sh
docker node update --label-add tier=heavy $(docker node ls -q)
```

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

Ces manques sont **explicites dans le code**, jamais masqués :

- **Pas d'archivage WAL.** Le PITR du §8.1 n'existe pas : on ne peut restaurer
  qu'aux instants où un dump a été pris, pas à une seconde arbitraire.
- **Les dumps SQL ne sont pas encore chaînés** à l'ordonnanceur : `backup run`
  ne sauvegarde que les volumes.
- **`ProvisionMailAccount`** reste la seule action non implémentée : elle attend
  un client Stalwart.
- **`Verify::Exec`** (commande dans le conteneur) est rapporté comme non vérifié,
  jamais comme réussi : il demande un accès conteneur qui appartient à l'exécuteur.
- **La vérification par restauration n'est pas câblée au CLI.** Elle existe en
  bibliothèque (`hlb_backup::verify_by_restore`) et est couverte par les tests
  d'intégration, mais `hlb backup verify` le dit franchement au lieu de faire
  semblant.
- **L'API du controller est en lecture seule**, délibérément (§11bis) : aucune
  route POST/PUT/DELETE, et un test le vérifie.
- **L'agent n'est pas encore déployé automatiquement.** Le controller sait
  l'interroger (`tasks.hlb-agent` → un rapport par nœud), et le mode `global` est
  supporté par l'orchestrateur, mais la création du service reste à écrire — elle
  suppose une image de l'agent, qu'il faut construire.
- **L'API de l'agent est en HTTP clair.** Elle n'écoute que sur l'overlay,
  chiffré par IPsec avec `--opt encrypted` (§6.3), mais le mTLS du §2 n'est pas
  en place — c'est dit plutôt que sous-entendu.
- **Le rattachement d'un nœud reste manuel** : `hlb cluster join-command` produit
  la commande, mais ne l'exécute pas à distance. Le mesh WireGuard et l'agent
  n'existent pas encore.
- **Le RBAC n'est pas encore appliqué** : les rôles et leurs permissions sont
  définis et testés, mais l'API étant en lecture seule il n'y a rien à protéger
  pour l'instant. Le CLI s'exécute localement — qui le lance a déjà la clé
  maîtresse.
- **La réconciliation ne corrige pas par défaut** : `--reconcile-apply` doit
  être demandé explicitement.
- **Sans `--backup-repo`, toute mise à jour exigeant une sauvegarde est
  refusée.** De même si l'app n'a aucun volume connu : « rien à sauvegarder »
  ne vaut jamais « sauvegarde réussie ».
- **Client PocketID et création de volume** restent `Unimplemented` dans
  l'exécuteur — enregistrés comme tels, jamais comptés comme réussis.
- `age` tire `proc-macro-error2`, signalé comme incompatible avec un futur
  Rust. Dépendance transitive, sans action possible de notre côté pour l'instant.
