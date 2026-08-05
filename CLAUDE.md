# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Langue

**Tout ce projet est en français** : commentaires de code, messages d'erreur, sortie
CLI, noms de tests, documentation, messages de commit. Le code lui-même (identifiants,
types) est en anglais, comme il est d'usage en Rust. Garde cette convention.

## PLAN.md est la source de vérité de l'architecture

`PLAN.md` (~3200 lignes) contient l'architecture complète, les décisions et surtout
**les raisons** de chaque décision. Le code y renvoie constamment par numéro de
section (`§4.3`, `§2ter.5`…).

**Avant de modifier un comportement, lis la section citée en commentaire.** Beaucoup
de choix qui paraissent arbitraires sont des garde-fous contre un piège documenté :
`start-first` + `failure_action: rollback`, l'interdiction de SQLite sur NFS, le refus
d'exposer une app en `proxy-header`, l'exposition privée par défaut.

Si tu changes une décision, mets à jour la section correspondante de PLAN.md.

## Commandes

```sh
cargo test                      # tests unitaires, aucune dépendance externe
cargo test -p hlb-resolver      # un seul crate
cargo test -p hlb-state -- completed_actions_survive_a_replan   # un seul test
cargo clippy --all-targets      # doit rester à zéro avertissement
cargo build
```

### Tests d'intégration Swarm

Ils sont `#[ignore]` pour que `cargo test` reste rapide et utilisable sans Docker.

```sh
docker swarm init
export DOCKER_HOST=$(docker context inspect -f '{{.Endpoints.docker.Host}}')
cargo test -p hlb-orchestrator -- --ignored --test-threads=1 --nocapture
```

⚠️ **Sur macOS (colima / Docker Desktop), `DOCKER_HOST` est indispensable** : `bollard`
cherche `/var/run/docker.sock`, qui n'existe pas. Sans cette variable, tous les tests
d'intégration et `hlb ps` / `hlb install` échouent avec `SocketNotFoundError`.

### Essayer le CLI

```sh
./target/debug/hlb catalog validate
./target/debug/hlb order
./target/debug/hlb plan gitea --domain git.example.fr
./target/debug/hlb install valkey            # aperçu
./target/debug/hlb install valkey --apply    # exécution réelle
```

⚠️ Les tiers de nœuds sont de vraies contraintes de placement Swarm. Tant que
`hlb node add` n'existe pas, il faut poser le label à la main, sinon rien ne se
planifie et `wait_healthy` expire :

```sh
docker node update --label-add tier=heavy $(docker node ls -q)
```

## Architecture

### L'idée centrale : le résolveur de capacités

C'est ce qui structure tout le reste. Un manifest ne dit **jamais** « connecte-toi à
`postgres:5432` ». Il déclare un **besoin** :

```yaml
requires:
  - kind: database
    engine: postgres
  - kind: sso
    mode: native
    redirectPaths: ["/user/oauth2/PocketID/callback"]
```

`hlb-resolver` traduit ces besoins en actions concrètes (créer la base + le rôle
isolé, générer le secret, créer le client OIDC avec les URI **calculées depuis le
domaine choisi à l'installation**). Conséquence : le même manifest fonctionne quelle
que soit la topologie réelle.

`Capability` est un `enum` exhaustif. **Ajouter une variante fait échouer la
compilation partout où un `match` doit être mis à jour** — c'est la raison principale
du choix de Rust, ne la casse pas avec un bras `_ =>`.

### Le flux complet

```
catalog/*/manifest.yaml
   ↓  hlb-catalog     charge, valide, vérifie nom-de-dossier == metadata.name
Manifest (hlb-types)
   ↓  hlb-resolver    résolution des capacités + graphe de dépendances
Plan { actions: Vec<Action> }
   ↓  hlb-engine      exécution : aperçu par défaut, idempotente, reprenable
hlb-orchestrator      trait Orchestrator → bollard → Docker Swarm
   ↕  hlb-state       manifest figé + journal de progression (SQLite)
```

### Dépendances entre crates

`hlb-types` est le socle : **la seule définition du schéma**, consommée par le code
Rust, par `schemars` (JSON Schema pour l'autocomplétion YAML) et à terme par
l'OpenAPI du controller. Aucun autre crate ne redéfinit ces types.

```
hlb-types  ←  hlb-resolver  ←  hlb-engine  →  hlb-orchestrator
     ↑              ↑              ↓
hlb-catalog    hlb-state    ←──────┘
                    ↑
                 hlb-cli (assemble tout)
```

### Ordonnancement des dépendances

**Docker Swarm n'a pas de `depends_on`.** Il démarre tout en parallèle, et une app qui
démarre avant PostgreSQL boucle en crash. `hlb-resolver::graph` déduit le graphe des
`requires` (via `Capability::platform_service()`) et produit un ordre par tri
topologique. L'arrêt se fait dans l'ordre inverse.

Ajouter un service de plateforme au catalogue met le graphe à jour automatiquement —
il n'y a **aucune liste à maintenir à la main**. En revanche, une capacité qui pointe
vers un service absent du catalogue fait échouer `hlb catalog validate`.

## Invariants à ne pas casser

Ces règles sont encodées dans des tests. Si un test échoue, c'est probablement le code
qui a tort, pas le test.

- **Aperçu par défaut.** `Executor` ne modifie rien sans `.apply(true)`. Le mode par
  défaut doit rester non destructif.
- **`Unimplemented` n'est jamais `Done`.** Une action que l'exécuteur ne sait pas
  encore faire est enregistrée comme non implémentée et rapportée telle quelle. Ne
  jamais faire semblant d'avoir provisionné une base.
- **Idempotence et reprise.** `record_plan` n'écrase pas une action `done` ; l'exécuteur
  saute ce qui est déjà fait et s'arrête au premier échec plutôt que de cascader.
- **La réconciliation ne supprime jamais un orphelin, ne ressuscite jamais une
  installation en échec, et ne force jamais une convergence en cours.** Un système qui
  corrige trop est plus dangereux qu'un système qui ne corrige rien. Distinction clé :
  la *consigne* Swarm (`desired_replicas`) vient d'une décision et se corrige ;
  l'*avancement* (`running_replicas`) est transitoire et se laisse tranquille.
- **Les guides bloquants arrêtent avant toute modification.** Inutile de déployer une
  app dont le DNS n'existe pas ou dont le compte admin n'est pas créé.
- **Politique de mise à jour non négociable.** `start-first` + `failure_action:
  rollback` + `monitor` sont codés en dur dans `hlb-orchestrator`, pas configurables
  par app. Une app qui ne le supporte pas doit être en `channel: pin`.
- **Sécurité par défaut.** `read_only_rootfs`, `cap_drop: [ALL]`, `no_new_privileges`,
  aucun port publié, exposition `private`. Les défauts vont dans le sens sûr.
- **`deny_unknown_fields` partout.** Une faute de frappe dans un manifest doit être
  rejetée avec son numéro de ligne, jamais ignorée silencieusement.

## Conventions

- **`unwrap` / `expect` interdits en production** (lint `warn` dans le workspace). Ils
  sont autorisés dans les tests via `clippy.toml` — là, `expect("message")` *est*
  l'assertion, et le message porte le diagnostic.
- **Erreurs typées par crate** (`thiserror`), jamais de `String` nue. Le CLI déroule la
  chaîne de causes.
- **Les plans doivent être reproductibles.** Le tri topologique départage par ordre
  alphabétique — un plan qui varie d'une exécution à l'autre rend les futurs tests
  d'instantané inutilisables.
- **Tests en français, nommés comme des affirmations** :
  `postgres_comes_before_its_consumers`, `unimplemented_is_never_reported_as_done`.

## Pièges connus

- **Continuation de ligne Rust dans les YAML de test.** Un `\` en fin de ligne mange la
  newline *et l'indentation* de la ligne suivante, ce qui casse le YAML de façon
  déroutante. Utilise des chaînes brutes `r#"..."#` pour tout manifest de test.
- **`sqlx` en requêtes runtime**, pas les macros compile-time : celles-ci exigent
  `DATABASE_URL` au build ou un `cargo sqlx prepare`. À basculer une fois le schéma
  stabilisé. La vérification SQL à la compilation n'est donc **pas** encore en place.
- **SQLite en mémoire** : `max_connections(1)` est obligatoire, sinon chaque connexion
  voit une base différente.
- **Compter les tâches Swarm** : filtrer sur `desired-state` **et** l'état réel. Swarm
  conserve l'historique des tâches mortes, qu'on compterait sinon comme vivantes.

## État d'avancement

Fait : types + validation, orchestrateur Swarm (spike `bollard` validé, dont le
rollback automatique), résolveur + graphe + plan, catalogue, état persistant,
exécuteur, CLI.

Fait aussi : coffre de secrets `age`, provisionnement PostgreSQL isolé (avec preuve
d'isolation en test d'intégration), boucle de réconciliation.

Pas encore écrit — ces actions restent `Unimplemented` dans l'exécuteur : client
PocketID, générateur de Caddyfile, création de volume, résolution de digest. Le moteur
de vérification des guides (bloc `verify:` du §4.6) n'existe pas non plus : `hlb ack`
est une attestation, et le CLI le dit à chaque usage. Voir la feuille de route en §12
de PLAN.md.
