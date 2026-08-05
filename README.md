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
| `hlb-cli` — `catalog`, `plan`, `order`, `ps` | ✅ utilisable |
| Controller (axum), agent, état (sqlx) | ⬜ à venir |

**36 tests, 0 avertissement clippy.**

## Essayer

```sh
cargo build
./target/debug/hlb catalog list
./target/debug/hlb catalog validate
./target/debug/hlb order
./target/debug/hlb plan gitea --domain git.example.fr
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
