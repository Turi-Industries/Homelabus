# HomelabUS

Plateforme de gestion d'un cluster Docker Swarm auto-hébergé : déploiement d'apps,
bases mutualisées, SSO, reverse proxy, sauvegardes et mises à jour automatiques.

📄 **L'architecture complète est dans [PLAN.md](PLAN.md).**

---

## État d'avancement

| Composant | État |
|---|---|
| Spike `bollard`/Swarm (risque n°1) | ✅ **validé** — voir ci-dessous |
| `hlb-types` — manifests, capacités, validation | ✅ 14 tests |
| `hlb-orchestrator` — trait + implémentation Swarm | ✅ 7 tests d'intégration |
| `hlb-resolver` — résolution + graphe + plan | ✅ 17 tests |
| `hlb-catalog` — chargement et validation | ✅ 5 tests |
| `hlb-state` — état persistant, reprise, secrets (sqlx/SQLite) | ✅ 13 tests |
| `hlb-secrets` — coffre `age`, génération de mots de passe | ✅ 11 tests |
| `hlb-platform` — provisionnement PostgreSQL isolé | ✅ 7 + 5 tests |
| `hlb-engine` — exécuteur + **réconciliation** (§2.1) | ✅ 10 + 11 tests |
| `hlb-ingress` — génération Caddyfile + rechargement à chaud | ✅ 17 + 4 tests |
| `hlb-registry` — résolution de digest, politique de version | ✅ 28 + 6 tests |
| `hlb-cli` — `catalog`, `plan`, `order`, `install`, `reconcile`, `ingress`, `todo`, `ack`, `secrets`, `ps` | ✅ utilisable |
| Client PocketID, volumes, pipeline de MAJ complet | ⬜ à venir |
| Controller HTTP (axum), agent, UI | ⬜ à venir |

**136 tests unitaires + 22 tests d'intégration.**

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
