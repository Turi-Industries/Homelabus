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
- **Une métrique absente vaut mieux qu'un zéro.** `hlb_backup_age_seconds` n'est pas
  émise quand aucune sauvegarde n'a réussi : un `0` signifierait « sauvegardée à
  l'instant », et l'alerte ne partirait jamais pour les apps les plus à risque.
- **CrowdSec ne va que sur le Caddy frontal.** Le backend ne voit que l'IP du frontal :
  y poser le videur ferait bannir son propre frontal au premier attaquant.
- **Un `archive_command` WAL qui échoue ne perd pas les journaux, il les garde.**
  `pg_wal` grossit jusqu'à saturer le disque. Archiver vers une destination cassée est
  plus dangereux que ne pas archiver.
- **Le dossier temporaire de l'hôte n'est PAS partagé avec la VM Docker sur macOS.**
  Tout espace jetable monté dans un conteneur doit être un *volume Docker*, et son
  contenu compté depuis un conteneur. Un `tempfile::tempdir()` y apparaît vide, ce qui
  fait conclure à une sauvegarde vide sur une sauvegarde saine.
- **Stalwart n'a pas d'API REST pour les comptes.** Tout passe par JMAP (`POST /jmap/`,
  capacité `urn:stalwart:jmap`, méthodes `x:Account/set` et `x:Domain/query`), à partir
  de la **v0.16** seulement. Le discriminant est `@type`, `emailAddress` est calculé par
  le serveur, et un `/set` qui échoue renvoie quand même HTTP 200 — l'échec vit dans
  `notCreated`. **Une condition de filtre ne porte qu'UNE propriété** : chaque clé
  écrase la précédente, il faut un `AND` de conditions séparées. `accountId` n'est en
  revanche pas requis pour `Account`/`Domain` (ils n'ont pas `OBJ_FILTER_ACCOUNT`).
- **`pg_basebackup` passe par le protocole de réplication**, que `pg_hba.conf` traite
  comme une base à part. Un utilisateur qui se connecte parfaitement en `psql` est
  refusé. L'image officielle n'autorise la réplication que depuis `127.0.0.1` : il faut
  `host replication all all scram-sha-256`.
- **Comparer les tailles ne détecte pas la corruption.** Un bit retourné laisse le
  fichier à la même taille. D'où `restic check --read-data-subset` en plus du décompte.
- **`SystemTime::now()` n'a pas la résolution nanoseconde sur macOS.** Un identifiant
  unique bâti dessus seul produit des doublons entre deux appels rapprochés.
- **Un fichier SQLite ne se copie pas à chaud.** En mode WAL c'est trois fichiers que
  restic copie l'un après l'autre ; entre-temps l'app écrit. `VACUUM INTO` produit un
  instantané cohérent, et la panne ne se voit qu'à la restauration.
- **`sshd` ignore SILENCIEUSEMENT `authorized_keys`** s'il est lisible par le groupe,
  ou si `~/.ssh` l'est. La clé paraît installée et rien ne marche.
- **Un utilisateur MariaDB est `'nom'@'hôte'`.** Sans partie hôte explicite, l'app est
  refusée depuis un autre conteneur avec un message parlant de mot de passe incorrect.
  Et `_`/`%` sont des JOKERS dans un `GRANT`.
- **`*.example.fr` ne couvre pas `example.fr`.** Les deux noms doivent être demandés.
- **Le matcher `status` de Caddy n'existe que dans un bloc `forward_auth`.** Au niveau
  du site, Caddy refuse de démarrer sur « module not registered ».
- **Un outil de scan absent n'est pas un feu vert.** `NotChecked` est distinct de
  `Clean` : traiter « trivy absent » comme « rien trouvé » désactive le contrôle en
  donnant l'impression de l'avoir fait.
- **Le forward-auth doit effacer les en-têtes d'identité entrants.** Sinon
  `curl -H "X-Auth-Request-User: admin"` suffit à usurper un compte.
- **egui n'embarque pas tous les glyphes.** « ● », le sélecteur de variante de « ⚠️ »
  et « ⚑ » s'affichent en carré vide, et un « tofu » ressemble assez à une icône pour
  passer inaperçu en relecture. Les formes d'état sont **peintes**, pas écrites, et un
  test scanne tous les littéraux du fichier (commentaires exclus).
- **`std::time::Instant::now()` PANIQUE en WebAssembly**, et il n'y a ni thread ni
  `sleep`. Toute la fraîcheur passe par l'horloge d'egui, et le sondage est piloté par
  la boucle de rendu — un seul chemin de code pour le natif et le web.
- **Servir du wasm exige `Content-Type: application/wasm`.**
  `WebAssembly.instantiateStreaming` refuse un `application/octet-stream` avec un
  message qui ne dit pas ce qu'il attendait.
- **Le binaire `wasm-bindgen` doit avoir EXACTEMENT la version du crate.** Une
  divergence donne un bundle qui se charge et plante à la première fonction.
- **Une donnée périmée ne doit jamais ressembler à une donnée fraîche.** Si le
  controller tombe, l'UI garderait son dernier état connu : toutes les apps vertes
  pendant que le cluster brûle. D'où `Freshness`, que le type oblige à regarder.

## État d'avancement

Fait : types + validation, orchestrateur Swarm (spike `bollard` validé, dont le
rollback automatique), résolveur + graphe + plan, catalogue, état persistant,
exécuteur, CLI.

Fait aussi : coffre de secrets `age`, provisionnement PostgreSQL isolé (avec preuve
d'isolation en test d'intégration), boucle de réconciliation, mesh WireGuard
(`hlb-mesh`), autolock Swarm (`hlb cluster autolock`), observabilité (`hlb-notify` +
`/metrics` sur le controller + CrowdSec au frontal), PITR PostgreSQL (`hlb backup
pitr`).

Fait également : client Stalwart (`hlb-mail`) et provisionnement des boîtes,
`hlb backup verify` (restauration réelle + relecture de blocs), inventaire des
segments WAL, `hlb backup pitr base` (pg_basebackup), `hlb crowdsec enroll`,
`hlb mesh add/show/list`, `/metrics` protégé par jeton.

Fait aussi : `hlb node add` (SSH, clé dédiée révocable, dépendances, join, tier),
`hlb access grant/revoke/list`, dumps SQL dans l'ordonnanceur, mTLS agent ↔ controller
(`hlb pki`), scan Trivy + cosign avant mise à jour, MariaDB, forward-auth pour les apps
sans SSO natif, ACME DNS-01 wildcard, instantanés SQLite + Litestream, `hlb dr promote`.

Fait enfin : l'UI en **egui** (`hlb-ui`), avec `hlb-api` qui définit les types de
l'API **une seule fois** pour le serveur et l'interface. L'OpenAPI `utoipa` + la
génération TypeScript du plan §11bis sont donc sans objet.

Reste la feuille de route du §12 : phase 7 (runtime compose pour mailcow, HA
PostgreSQL en réplication streaming, exercices de reprise automatisés).
