# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Langue

**Tout ce projet est en français** : commentaires de code, messages d'erreur, sortie
CLI, noms de tests, documentation, messages de commit. Le code lui-même (identifiants,
types) est en anglais, comme il est d'usage en Rust. Garde cette convention.

## PLAN.md est la source de vérité de l'architecture

`PLAN.md` (~3500 lignes) contient l'architecture complète, les décisions et surtout
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

# Les commandes récentes, toutes en aperçu par défaut
./target/debug/hlb backup dest list
./target/debug/hlb backup status             # fraîcheur PAR destination
./target/debug/hlb metrics rules
./target/debug/hlb metrics deadman --ntfy https://ntfy.sh/veilleur
./target/debug/hlb replication config nas-01
./target/debug/hlb user list
./target/debug/hlb user alias sieve remy     # --apply pour poser chez Stalwart
./target/debug/hlb user role remy admin      # --apply ; refuse de rétrograder le dernier
./target/debug/hlb user sessions remy        # --close <réf>|toutes
./target/debug/hlb audit --verify            # intégrité du chaînage

# L'interface, sans cluster ni Docker : le moyen le plus rapide de la voir
./target/debug/hlb-controller --demo --listen 127.0.0.1:8420 &
./target/debug/hlb-ui --url http://127.0.0.1:8420 --route /apps
```

⚠️ **Beaucoup de commandes ont besoin d'un état et d'un coffre.** Pour essayer sans
toucher à une installation réelle :

```sh
export HLB_STATE=/tmp/essai.db HLB_MASTER_KEY=/tmp/essai.key
```

⚠️ Les tiers de nœuds sont de vraies contraintes de placement Swarm. `hlb node add` les
pose ; sur un nœud rattaché à la main, il faut le faire soi-même, sinon rien ne se
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
Rust et par `schemars` (JSON Schema pour l'autocomplétion YAML). Aucun autre crate ne
redéfinit ces types.

⚠️ L'OpenAPI n'existe pas et n'existera pas : depuis le choix d'egui, `hlb-api` définit
les types de l'API **une seule fois** pour le serveur et l'interface, tous deux en
Rust. Le §11bis prévoyait `utoipa` + génération TypeScript ; c'est sans objet.

```
hlb-types  ←  hlb-resolver  ←  hlb-engine  →  hlb-orchestrator
     ↑              ↑              ↓
hlb-catalog    hlb-state    ←──────┘
     ↑              ↑
hlb-users      hlb-cli (assemble tout)   hlb-api  →  hlb-ui
```

Les crates « métier » ne dépendent que de `hlb-types` et ne parlent jamais réseau :
`hlb-users` (comptes, aliases, quotas, Sieve), `hlb-metrics` (règles, deadman). Les
clients réseau sont à côté — `hlb-mail`, `hlb-identity`, `hlb-objstore` — ce qui rend
la logique testable sans serveur.

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
  Tout espace jetable monté dans un conteneur doit être un *volume Docker* (ou un
  chemin sous `/Users`), et son contenu lu depuis un conteneur. Un
  `tempfile::tempdir()` y apparaît vide, ce qui fait conclure à une sauvegarde vide sur
  une sauvegarde saine. **Ce piège s'est présenté trois fois** : vérification restic,
  dumps SQL, exercices de reprise.
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
- **`pg_basebackup -R` écrase `postgresql.auto.conf`**, qui est lu APRÈS
  `postgresql.conf` et l'emporte donc. Le `primary_conninfo` qu'il écrit n'a pas
  d'`application_name` : des réglages posés AVANT sont silencieusement perdus, et tous
  les standbys s'annoncent `walreceiver`. On voit alors qu'un nœud décroche sans savoir
  lequel — d'où l'avertissement d'ambiguïté dans `hlb replication status`.
- **Un slot de réplication neuf ne retient rien** tant qu'aucun standby ne s'y connecte
  (sauf `immediately_reserve`). Le cas dangereux n'est pas le slot jamais utilisé, c'est
  celui *qui a servi* et dont le consommateur a disparu : lui seul fait grossir `pg_wal`.
- **Un dump MariaDB n'inclut PAS les routines, déclencheurs ni événements** sans
  `--routines --triggers --events`. Le dump réussit, restaure sans erreur, et l'app est
  subtilement cassée — un déclencheur manquant ne se voit qu'à la première écriture
  concernée.
- **`--single-transaction` ne protège que les tables transactionnelles.** Sur MyISAM ou
  Aria, l'option est acceptée SANS avertissement et n'apporte aucune cohérence. D'où la
  lecture des moteurs avant chaque dump — et une liste illisible vaut `VerrouillageRequis`,
  jamais « c'est sûrement de l'InnoDB ».
- **Un dump MariaDB tronqué reste du SQL valide.** C'est du texte écrit au fil de l'eau :
  interrompu, il restaure une base à qui il manque des tables, sans une seule erreur. La
  ligne `-- Dump completed` est la seule preuve de complétude — d'où l'interdiction de
  `--skip-comments`, qui la supprimerait.
- **Un battement de cœur périodique ne prouve rien.** Il atteste qu'un fil d'exécution
  vit, pas que le système marche : le controller peut avoir sa base illisible et son
  Docker mort, et battre imperturbablement. Le veilleur reste alors au vert sur un
  système inutilisable — **pire que pas de deadman, puisqu'on s'y fie**. Le battement
  est conditionné à une vérification réussie, et le silence est le signal.
- **Le veilleur ne tourne pas sur ce qu'il surveille**, et n'alerte pas à travers lui.
  Un deadman hébergé par le controller meurt avec lui ; une alerte relayée par le
  controller ne part pas quand c'est lui qui est mort. Et si `curl` échoue, l'échec est
  avalé par `>/dev/null 2>&1` : d'où le repli sur stderr, que cron envoie par courriel.
- **Un `..` dans un motif a le même effet qu'un bras `_ =>`.** Constaté sur
  `Capability::Sso { redirect_paths, .. }` : le `mode` était ignoré, donc une app en
  `mode: none` (exclusion volontaire) recevait un client OIDC aux URI VIDES, et une app
  derrière portail un client pointant vers elle au lieu d'oauth2-proxy. Le compilateur
  ne pouvait pas le dire — c'est exactement ce que l'exhaustivité devait empêcher.
- **Provisionner n'est pas connecter.** Le résolveur créait la base, le rôle isolé et le
  mot de passe, puis déployait l'app sans rien lui dire : elle retombait sur son SQLite
  interne. Service sain, sonde verte, tableau de bord au vert — et les données dans un
  fichier que personne ne sauvegardait, pendant qu'une base vide était fidèlement dumpée
  chaque nuit. D'où `spec.env` et les jetons de liaison.
- **Un secret ne doit jamais entrer dans un plan.** Le plan traverse `hlb plan`
  (affichage), l'état SQLite (enregistrement) et le miroir Git (export avec historique).
  La substitution des jetons de secret a donc lieu dans l'exécuteur, au déploiement.
  `{{ db.url }}` compte comme un secret malgré son air d'adresse : elle contient le mot
  de passe.
- **Un jeton irrésolu reste littéral, jamais vide.** Une variable vide ressemble à une
  configuration absente : l'app se plaint d'un mot de passe incorrect et l'on cherche du
  côté du mot de passe. `{{ db.password }}` dans les journaux désigne le vrai problème.
- **Une extension PostgreSQL ne s'installe pas depuis SQL.** Elle doit être dans
  l'IMAGE du serveur, sinon `CREATE EXTENSION` échoue sur « n'est pas disponible », ce
  qui ressemble à un problème de droits. Et elle est **locale à une base** : posée sur
  `postgres`, elle réussit et l'app ne la voit jamais.
- **Changer la libc de l'image PostgreSQL casse les index texte.** musl (alpine) et
  glibc (debian) ne trient pas pareil. Les B-tree construits sous l'une deviennent
  incohérents sous l'autre : recherches incomplètes, contraintes d'unicité qui laissent
  passer des doublons. PostgreSQL ne le signale que par un avertissement de « collation
  version mismatch ». D'où `REINDEX DATABASE` + `REFRESH COLLATION VERSION`.
- **Le rôle appartient à l'APP, pas à la base.** Seafile veut trois bases et s'y
  connecte avec un seul compte. Nommer le rôle d'après la base produirait trois comptes
  pour un jeu d'identifiants, et l'app échouerait sur deux d'entre elles.
- **Garage ne redonne JAMAIS une clé secrète.** `CreateKey` la donne une fois ;
  `GetKeyInfo` la rend nulle ensuite. L'idempotence ne peut donc pas reposer sur « la
  clé existe-t-elle ? » — c'est le coffre qui fait autorité, sinon une reprise repart
  sans secret et l'app échoue sur une « signature invalide » qui n'oriente vers rien.
- **Une app n'est jamais propriétaire de son compartiment S3.** `read` + `write`, jamais
  `owner` : propriétaire, une app compromise pourrait supprimer son propre
  compartiment — effaçant ce que les sauvegardes protégeaient.
- **Un compagnon absent ne se voit pas.** Immich sans son service d'apprentissage
  importe et affiche les photos parfaitement, et ne reconnaît jamais personne. D'où le
  déploiement du compagnon AVANT l'app, avec attente de sa mise en santé, et une étape
  de guide qui fait vérifier que ça marche vraiment.
- **Une destination de sauvegarde fraîche en masque une périmée.** `MAX(finished_at)`
  sur toutes les destinations faisait passer un hors-site mort depuis trois semaines
  pour une sauvegarde de 2 h, parce que le NAS, lui, tournait. On croyait le 3-2-1 tenu
  alors qu'il ne restait qu'une copie, sur les mêmes machines. La fraîcheur se mesure
  PAR destination, et le résumé affiche le pire cas — sinon il contredit le détail
  juste en dessous, et c'est le résumé qu'on lit.
- **Configuré n'est pas protégé.** Le nombre de destinations déclarées ne dit rien du
  nombre de copies : une destination en échec est une destination qui ne protège de
  rien. D'où `copies_a_jour()` et la règle d'alerte `copie-unique`.
- **Un dépôt restic S3 ne se MONTE pas.** Le monter crée un répertoire vide, et restic
  répond « repository does not exist » en désignant un chemin local sans rapport avec la
  vraie destination. Et il faut un `--network` pour joindre un Garage interne.
- **Un échec sur une destination ne doit jamais priver les autres.** Un hors-site
  injoignable qui interromprait la boucle supprimerait aussi la sauvegarde locale : on
  perdrait les deux copies pour la panne d'une seule.
- **L'échéance se juge PAR destination.** La juger globalement fait sauter le hors-site
  dès que le NAS vient d'être servi — il ne recevrait alors jamais rien, pendant que le
  statut global paraîtrait frais.
- **Un échec RÉPÉTÉ doit se voir avant le seuil de péremption.** Une destination qui
  échoue à chaque tentative reste « fraîche » douze heures avec l'intervalle par défaut.
  D'où le compteur d'échecs consécutifs, affiché immédiatement.
- **`datetime('now')` a une résolution d'une SECONDE.** Une réussite et l'échec qui la
  suit dans la même seconde portent le même horodatage, et une comparaison stricte les
  exclut — le compteur reste à zéro alors que tout échoue. Ordonner par `id`, qui est
  monotone.
- **`credentials_secret` est le NOM du secret, pas sa valeur.** Le passer tel quel
  enverrait « backup-dest-offsite » comme clé d'accès S3, et le serveur répondrait
  « signature invalide » — une erreur qui n'oriente vers rien.
- **Un serveur de messagerie ne sait PAS expirer un alias.** La liste `aliases` d'un
  compte Stalwart n'a pas de date : ce qui y est écrit y reste. Un alias « temporaire »
  ne l'est que si une purge vient réellement le supprimer — sinon l'adresse qu'on croit
  fermée reçoit pour toujours. D'où **trois** états et non deux : valide, expiré-et-
  supprimé, et 🔴 expiré-mais-TOUJOURS-ACTIF.
- **Un alias devinable annule le compartimentage.** Si celui d'Amazon est
  `amazon@example.fr`, alors `paypal@`, `banque@` et `impots@` existent probablement
  aussi, et un expéditeur de masse les essaie toutes pour le prix d'une. L'indice ne
  fait jamais l'adresse : il est suivi d'un suffixe aléatoire.
- **L'intérêt d'un alias jetable n'est pas de le jeter, c'est l'attribution.** Une
  adresse par destinataire dit *qui* a laissé fuiter. D'où l'indice lisible conservé :
  cinquante adresses purement aléatoires font perdre le seul vrai bénéfice.
- **Désactiver vaut mieux que supprimer.** Un alias supprimé rejette le courrier et
  n'apprend rien ; désactivé, il le rejette aussi mais laisse compter ce qui frappe
  encore — donc combien de temps un marchand a continué de vendre l'adresse.
- **Un compte à moitié créé paraît fonctionnel.** Identité sans boîte : la personne se
  connecte partout et son adresse ne reçoit rien. Ça ne se voit qu'au premier courriel
  perdu, souvent une réinitialisation de mot de passe. L'état est nommé, et la création
  est reprenable.
- **PocketID n'a pas de mot de passe** : authentification par clé d'accès. On ne
  transmet donc pas un secret initial mais un **jeton à usage unique**, affiché une
  fois et jamais enregistré.
- **JMAP `update` REMPLACE la propriété entière.** Il n'y a pas d'opération « ajouter
  un alias » : écrire un seul alias effacerait tous les autres, sans lever d'erreur.
  D'où lecture-modification-écriture — et deux modifications simultanées feraient
  perdre la première.
- **Marquer un alias « purgé » sans l'avoir retiré du serveur est pire que ne rien
  faire.** L'adresse recevrait encore ET plus rien ne le signalerait : le silence
  entretiendrait la croyance que la porte est fermée. L'état n'est marqué qu'APRÈS le
  retrait effectif, et la purge sans Stalwart refuse au lieu de mentir.
- **Ce qui compte dans une purge, c'est ce qui reste OUVERT, pas le nombre d'erreurs.**
  Une purge sans erreur qui n'a rien retiré laisse autant de portes ouvertes qu'une
  purge qui a échoué bruyamment.
- **Un script Sieve est un fichier UNIQUE par compte.** Le réécrire entièrement
  effacerait les règles écrites à la main — des heures de réglages, perdues sans un
  avertissement, pour une simple création d'alias. D'où un bloc délimité par des
  marqueurs : HomelabUS n'écrit qu'entre eux, et le bloc va en FIN de script (en tête,
  il capterait les messages avant les règles de l'utilisateur).
- **Un guillemet non échappé dans un nom de dossier casse TOUT le script**, y compris
  les règles de l'utilisateur, que Stalwart refuse alors en bloc. Le nom vient de
  l'utilisateur : il s'échappe.
- **`NULL` ≠ chaîne vide pour un dossier de tri.** `NULL` = « rien n'a été décidé », on
  propose un défaut ; `""` = « je ne veux PAS de tri », et c'est un choix explicite.
  Les confondre réimpose un dossier à chaque régénération.
- **🔴 idmail et `hlb-mail` ne peuvent pas coexister.** idmail ne parle pas à Stalwart :
  il REMPLACE son annuaire (`directory` externe de type sqlite). Les deux ensemble
  donneraient un alias créé en JMAP dans un annuaire que Stalwart ne consulte plus —
  l'adresse ne recevrait rien, sans que rien ne le signale. D'où l'API compatible
  addy.io côté HomelabUS plutôt que l'intégration d'idmail.
- **Le contrat de l'API addy.io est imposé par BITWARDEN**, pas par nous. Relevé dans
  son code (`libs/tools/generator/core/src/integration/addy-io.ts`) : la réponse doit
  être `{data:{email}}` — à la racine, le client lit `undefined` et l'alias existe côté
  serveur sans que personne ne le sache.
- **Un jeton d'API porte un RÔLE, pas une identité.** Suffisant pour lire l'état, faux
  dès qu'une requête agit POUR quelqu'un : sans rattachement, un jeton volé créerait des
  aliases sur la boîte de n'importe qui. Un jeton `admin` non rattaché est donc refusé
  là où un `operator` rattaché passe.
- **Un script Sieve ne voyage pas dans l'appel JMAP.** `SieveScript` ne porte qu'un
  `blobId` : il faut téléverser le contenu, puis le référencer. Et **sans
  `onSuccessActivateScript`, le script existe et ne trie RIEN** — panne totalement
  silencieuse, les règles sont visibles dans Roundcube et sans effet.
- **Le protocole addy.io n'a aucun champ pour choisir la boîte.** Bitwarden n'envoie
  que `domain` et `description`. La destination vit donc sur le JETON — un jeton par
  boîte — et un jeton qui vise une boîte disparue ÉCHOUE au lieu de retomber sur celle
  par défaut : l'utilisateur croirait ses aliases rangés là où ils ne sont pas.
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
  pendant que le cluster brûle. D'où `Freshness`, que le type oblige à regarder — avec
  `NeverSucceeded` distinct de `Stale`, sans quoi un échec de la PREMIÈRE requête
  laisse l'écran sur « connexion en cours… » indéfiniment.
- **Un jeton d'API n'est jamais stocké en clair**, même dans le coffre : on garde une
  empreinte SHA-256. Une fuite révèle qu'un jeton existe, pas sa valeur.
- **Le jeton web passe par le FRAGMENT d'URL**, jamais la chaîne de requête : un
  `?token=` part dans les journaux d'accès, les en-têtes `Referer` et tout proxy.
- **Un rôle authentifié n'est pas un rôle autorisé.** `Role::allows` a existé sans
  aucun appelant en production : tous les gestionnaires prenaient `_auth: Authentifie`
  et ignoraient le rôle. L'autorisation vit maintenant dans le TYPE de l'argument
  (`Autorise<PeutOperer>`) — le compilateur l'exige dans la signature, donc on ne peut
  pas l'oublier.
- **Un `403` nu fait douter de tout.** Il ne dit pas si on s'est trompé d'écran, si le
  système est cassé, ou s'il manque un droit. `Role::refus` nomme l'action, le rôle
  requis, le rôle détenu et **qui peut l'accorder** — et rend `None` quand c'est permis,
  pour qu'on ne puisse pas afficher un refus par erreur.
- **Le rôle d'une personne se relit à CHAQUE requête**, jamais figé dans la session.
  Figé, retirer les droits d'admin à quelqu'un n'aurait aucun effet pendant douze
  heures — or on les retire précisément quand on est pressé.
- **`SameSite=Lax` ne suffit pas contre le CSRF.** Toute requête mutante portée par un
  cookie exige l'en-tête `X-HLB-UI`. Les appels par jeton en sont dispensés : sans
  cookie, il n'y a pas d'autorité ambiante à détourner.
- **Un cookie `Secure` n'est PAS posé du tout sur `http://`.** L'attribut suit l'URL
  publique et n'est jamais codé en dur, sinon le développement local boucle sur l'écran
  de connexion **sans le moindre message d'erreur**.
- **La signature d'un `id_token` n'est pas vérifiée** — et c'est correct : il est
  récupéré par le controller lui-même sur TLS, jamais reçu du navigateur (OIDC Core
  §3.1.3.7). ⚠️ Ce raisonnement ne tiendrait PAS pour un flux implicite.
- **Croire `X-Forwarded-For` sans proxy de confiance annule la limitation de débit** :
  chaque attaquant se donne un compteur neuf à chaque requête, et la protection donne
  l'impression de fonctionner. D'où `--trusted-proxy`, explicite.
- **Une réponse réseau tardive doit être JETÉE, pas adoptée.** Une requête abandonnée
  pour dépassement de délai peut arriver ensuite : sans numéro de tour, elle serait
  consommée comme fraîche et l'écran daterait de maintenant des données vieilles de
  plusieurs minutes. C'est exactement le mensonge que `Freshness` existe pour empêcher.
- **Une palette n'a pas le droit de rendre les états indistincts.** Le vert « feu
  tricolore » et le rouge se rejoignent en vision deutéranope (distance 35, il en faut
  60) : les deux voyants les plus importants du tableau de bord étaient indiscernables
  pour 8 % des hommes. Le vert est décalé vers le cyan, et l'accent est **froid** —
  le cuivre initial se confondait avec « critique ». Ce n'est pas un goût, c'est une
  contrainte, et `Palette::valider` la fait respecter.
- **Sans `set_width`, chaque carte egui prend la largeur de son CONTENU.** Une liste de
  cartes devient un escalier dont le bord droit suit la longueur du texte. Invisible
  dans le code, évident à l'écran — d'où un test qui scanne les conteneurs.
- **Un écran écrit et absent de la navigation est du travail perdu.** L'écran des
  secrets existait et ne s'atteignait qu'en tapant l'URL. Un test croise désormais les
  écrans implémentés et les entrées de navigation.
- **Ne jamais proposer un écran qui n'existe pas.** Une entrée qui mène à « à venir »
  promet, on clique, on n'a rien, et on doute de tout le reste. `Route::implemente()`
  filtre la navigation ET les suggestions du message d'erreur.
- **Une tâche Swarm morte n'est pas une tâche arrêtée.** `desired_state` ET `state`
  décident si elle vit ; mais une tâche volontairement arrêtée (mise à jour, réduction
  d'échelle) n'est pas une panne — la compter comme telle ferait clignoter le tableau
  de bord à chaque déploiement normal, et on cesserait de le regarder.
- **Le taux CPU exige DEUX relevés.** `/proc/stat` est cumulé depuis le démarrage : au
  premier passage, la valeur est `None` et jamais `0.0` — un « 0 % » se lit « machine
  au repos », soit l'exact contraire de « je ne sais pas ». Idem après un redémarrage,
  où les compteurs reculent : la soustraction est vérifiée, pas enveloppée.
- **La charge n'est comparable que divisée par les cœurs.** 4 est dramatique sur un
  cœur et confortable sur seize ; un homelab est fait de machines hétérogènes, et la
  valeur brute côte à côte ne veut rien dire.
- **La mémoire se mesure sur la DISPONIBLE, pas sur la libre.** Linux met en cache tout
  ce qu'il peut : « libre » est presque toujours proche de zéro sur une machine saine.
  S'y fier ferait crier au manque de mémoire en permanence.
- **Un swap qui commence à servir est un signal AVANT la panne.** La machine ralentit
  sans être encore tombée. Le seuil est bas (5 %) pour cette raison — attendre la
  saturation, c'est attendre trop tard.
- **Le protocole de l'agent monte, la compatibilité reste dans les deux sens.** Tous
  les champs ajoutés sont `Option` + `serde(default)`, et rien n'est en
  `deny_unknown_fields` : on peut mettre à jour le controller avant les agents ou
  l'inverse. Sans ça, la première mise à jour rendrait tout le parc « injoignable » —
  précisément quand on a besoin de le voir.
- **Un relais PromQL ouvert est une exfiltration.** `{__name__=~".+"}` rend toute la
  base : noms d'hôtes, chemins, noms d'apps — la cartographie de l'installation, à qui
  a un jeton `viewer`. D'où une liste **blanche** de préfixes : on ne peut pas énumérer
  ce qui est dangereux, on peut énumérer ce qui est utile.
- **Les valeurs Prometheus sont des CHAÎNES, pas des nombres.** Les lire en `as_f64()`
  rend `None` sur toutes, et la courbe est vide sans la moindre erreur.
- **Une série vide n'est pas une série à zéro.** Une ligne plate se lit « tout est
  calme » ; `Serie::Indisponible` est une variante distincte, que le type oblige à
  traiter.
- **Une alerte en sourdine reste AFFICHÉE.** La sourdine coupe la notification, pas
  l'écran : la faire disparaître donnerait un tableau de bord vert pour un problème
  connu et non résolu. Elle porte une échéance, et revient entière ensuite.
- **Une règle non évaluable n'est pas une règle satisfaite.** Si la collecte tombe,
  `Evaluation::Inconnu` remonte au niveau `Important` — pas au niveau de la règle, qui
  laisserait croire que le seuil est franchi alors qu'on ignore s'il l'est.
- **`hlb_backup_copies` n'existait nulle part** alors que la règle `copie-unique`
  l'interrogeait : la règle qui garde le 3-2-1 ne s'est donc jamais déclenchée.
  `Couverture` n'était construite que dans le CLI — un calcul que le controller ne
  pouvait pas refaire.
- **Un cycle de dépendances révèle où le code doit vivre.** `hlb-state` ne peut pas
  implémenter un trait de `hlb-backup` (qui dépend de `hlb-updater`, qui dépend de
  `hlb-state`). L'adaptateur va donc dans le controller, qui dépend déjà des deux — et
  la logique reste dans `hlb-backup`, testable en mémoire.
- **Chaque grandeur a ses propres seuils de couleur.** Constaté à l'écran : avec
  l'échelle du CPU, un swap à 71 % s'affichait en VERT — or une machine qui échange
  déjà 70 % de son swap rame. Partager une fonction de teinte entre CPU, mémoire et
  swap est une économie qui ment.
- **« Aucune copie à jour » recouvre deux situations opposées.** Jamais sauvegardée
  (rien n'existe) et sauvegardes périmées (des copies existent, elles datent) ne se
  réparent pas pareil. Constaté à l'écran : « AUCUNE copie » à côté de deux
  destinations affichant « 1 j » se lit comme une contradiction, et on doute de tout
  l'écran.
- **L'anti-affinité porte sur le FER, jamais sur `node.id`.** Deux VM du même serveur
  sont deux nœuds Swarm et **un seul** point de panne : répartir deux réplicas « sur
  deux nœuds » ne protège de rien, et Swarm rend une illusion de redondance. Le domaine
  est déclaré à `hlb node add` (étiquette `hlb.failureDomain`) — ni Swarm ni l'agent ne
  peuvent le deviner.
- **Un domaine non déclaré n'est pas un domaine isolé.** Supposer l'isolement serait
  exactement l'hypothèse optimiste qui crée l'illusion. Les nœuds sans domaine forment
  un groupe « on ne sait pas », affiché comme tel.
- **`?apply=true`, sinon aperçu.** La transposition HTTP de `Executor::apply(true)` :
  une visite d'écran ne doit jamais devenir une exécution. Un test parcourt la liste qui
  SERT à construire le routeur et vérifie qu'aucune route n'agit sans le paramètre.
- **Les routes de CONFIGURATION n'ont pas d'aperçu, et c'est un choix déclaré.**
  Écrire le nom de la marque est idempotent et réversible ; imposer un aller-retour
  ferait prendre l'habitude de cliquer deux fois, ce qui viderait la protection de son
  sens là où elle compte. Le champ `apercu: false` est explicite, et un test verrouille
  la courte liste des exemptions.
- **La confirmation vient de l'APERÇU, jamais fabriquée par l'interface.** C'est le
  serveur qui dit quelle cible doit être confirmée ; l'interface se contente de la
  répéter après que l'utilisateur a lu ce que ça détruit. Deux états à synchroniser
  finiraient par diverger, et on appliquerait une action différente de celle
  prévisualisée.
- **Trois temps, pas deux.** Un bouton suivi d'un « Confirmer ? » générique ne dit rien
  de ce qui va se passer : on clique par réflexe, et la protection ne protège plus. La
  confirmation porte sur **le plan**, pas sur une question.
- **Descendre à zéro réplica n'est pas un redimensionnement, c'est un arrêt.** Refusé
  depuis un champ numérique, où ça n'arrive jamais volontairement.
- **Une destination S3 sans identifiants échoue des heures plus tard**, sur une
  « signature invalide » qui n'oriente vers rien. Refusée à la déclaration, avec le
  message qui nomme l'erreur qu'on verrait sinon.
- **Drainer le dernier nœud actif viderait le cluster.** Swarm l'accepte sans broncher —
  c'est à nous de refuser.
- **Une continuation de ligne OUBLIÉE laisse l'indentation dans la chaîne.** Le piège
  documenté a un jumeau : sans le `\` final, le texte s'affiche avec un trou au milieu
  (« côté serveur,        pas dans ce navigateur »). Invisible en lisant le code,
  évident à l'écran — d'où un test qui refuse deux espaces consécutifs dans une chaîne
  affichée.
- **Le thème est un NOM, pas une palette.** Une palette stockée par personne survivrait
  au retrait du thème dont elle vient, et l'on ne saurait plus la faire évoluer.
- **« Celui de l'installation » est une option à part**, pas l'absence de choix : la
  personne qui la sélectionne dit « suivez la marque », et son thème changera si
  l'administrateur change le défaut.
- **Un thème inconnu est REFUSÉ, pas accepté silencieusement.** Accepté, il serait
  stocké, retomberait sur le défaut à l'affichage, et l'on croirait le choix perdu par
  un défaut de l'interface.
- **La liste des thèmes vit côté serveur.** Si l'interface et le controller avaient
  chacun la leur, un thème retiré resterait proposé jusqu'au prochain déploiement du
  wasm. Un test tient les deux alignées.
- **Comparer deux calculs issus de la MÊME fonction ne peut jamais échouer.** L'écran
  d'exposition comparait les manifests à `routes_from_manifest` appliqué aux mêmes
  manifests : il aurait affiché « conforme » quoi qu'il arrive, en attestant d'une
  vérification qui n'avait pas lieu. La comparaison porte sur ce qui a été RÉELLEMENT
  posé (`ingress_publie`, écrit après le rechargement de Caddy), face à ce que les
  manifests demandent aujourd'hui.
- **Une route orpheline n'apparaît dans aucun parcours des apps installées.** Une app
  retirée dont la route répond encore n'est dans aucun manifest, donc dans aucune
  boucle : elle se cherche depuis les routes POSÉES, pas depuis les apps.
- **Deux chiffres pour une sauvegarde, pas un.** Le RPO dit ce qu'on perdrait ; la
  confiance dit ce qu'on sait de cette copie. Une sauvegarde fraîche jamais relue est
  une hypothèse, et l'afficher en vert est le mensonge que le §8.3 existe pour empêcher.
  Le RPO se mesure sur les destinations À JOUR seulement — sinon une copie périmée
  fournit un chiffre rassurant.
- **On simule la perte d'un DOMAINE, jamais d'une machine.** Sur deux VM d'un même
  serveur, la simulation par nœud conclut « le service survit » là où la simulation par
  domaine dit « il s'éteint entièrement ». Et le quorum exige la majorité STRICTE des
  managers : sur quatre, deux survivants ne suffisent pas — un `>=` naïf conclurait que
  le cluster tient.
- **Une chaîne causale qu'on ne sait pas remonter s'arrête.** Sur « cause inconnue »,
  jamais sur une supposition : un diagnostic plausible mais faux fait réparer la
  mauvaise chose, puis douter de l'écran. Une alerte n'est rattachée que si le constat
  du nœud la corrobore — l'accrocher parce qu'elle est active fabriquerait un lien.
- **Les non-actions de la réconciliation étaient invisibles.** Rien ne distinguait « il
  n'y a rien à faire » de « il y a quelque chose et j'ai délibérément choisi de ne pas y
  toucher ». `Drift::refus()` nomme la raison, et un test exige que corrigible et refus
  soient exactement complémentaires. Un refus est peint en VERT : c'est une décision,
  pas une panne.
- **`record_verification` déduisait l'échec de la présence d'un détail.** Décrire une
  vérification réussie l'enregistrait donc comme un échec, et l'app restait
  éternellement « jamais vérifiée ». `reussie: bool` est un argument à part entière —
  le compilateur a exigé les cinq appels.
- **Le budget de capacité ne s'additionne pas.** Un service ne se répartit pas entre
  deux machines : deux nœuds à 400 Mo libres ne font pas 800 Mo utilisables, ils font
  400. Et il n'existe AUCUN champ de mémoire dans les manifests — on annonce ce qui
  reste sur le tier visé, jamais une marge qu'on n'a pas.
- **Un nœud de tier inconnu n'appartient à aucun tier.** Le supposer ferait annoncer de
  la place là où il n'y en a pas ; un tier sans nœud fait expirer `wait_healthy` sans
  jamais dire pourquoi.
- **« Rien avant » n'est pas « rien n'a changé ».** Dans l'historique des manifests, la
  première version connue n'a pas un diff vide parce que rien n'a bougé : elle n'a rien
  avant elle. Et un commit qui ne touche pas l'app porte quand même son fichier — sans
  déduplication, vingt versions identiques noieraient le seul vrai changement.
- **Une source de frise qu'on ne sait pas lire doit APPARAÎTRE.** La taire ferait
  conclure « aucune action humaine n'a précédé la panne » alors qu'on ne sait rien — et
  c'est en pleine panne qu'on lit cet écran.
- **SQLite écrit ses horodatages sans fuseau ni « T ».** Les refuser comme du RFC 3339
  rend `None` sur toutes les lignes, et la frise est vide sur des données saines.
- **La règle du pluriel ne valait que d'un seul côté du contrat.** Le test qui interdit
  « action(s) » ne couvrait que l'interface, alors que les phrases sont fabriquées dans
  `hlb-api` et le controller. Il y en avait sept. Les tests couvrent maintenant les deux
  côtés — et `pluriel` accorde le NOM, pas le verbe : « 5 services s'arrêterait » a été
  constaté à l'écran.
- **Un scan par expression régulière rate les chaînes à continuation de ligne.** Elles
  ne sont pas closes sur leur propre ligne : le caractère fautif passe exactement là où
  il s'est présenté. Les scanners lisent les CHAÎNES (extracteur à états), pas les
  lignes — et scanner le code brut crie sur `Some(s) => f(s)`, un motif Rust
  parfaitement légitime.
- **Le coffre n'est PAS la source de vérité d'un mot de passe.** Le tourner là seul ne
  change rien : PostgreSQL garde l'ancien, le conteneur garde l'ancien dans son
  environnement, et tout continue — jusqu'au prochain redéploiement, où l'app échoue sur
  « mot de passe incorrect » sans que personne ne fasse le lien avec une rotation d'il y
  a trois semaines. Une rotation est une PROCÉDURE ORDONNÉE, et `Nature` dit laquelle.
- **Les suffixes de secrets se lisent dans le résolveur, pas dans sa tête.** Deux
  natures étaient déduites de conventions devinées (`-s3-key` au lieu de `-s3-secret`) :
  la règle ne se déclenchait jamais, et l'écran restait muet sur exactement les secrets
  qui comptent. Un test énumère les noms que le code produit réellement.
- **Une démonstration qui invente ses propres noms enseigne une fausse convention.**
  C'est elle qui a fait passer le défaut ci-dessus inaperçu.
- **HomelabUS ne peut vérifier AUCUN des garde-fous d'accès**, sauf l'exercice de
  reprise : il ne sait pas combien de passkeys existent ni si les codes sont imprimés.
  Il demande donc une attestation datée, qu'il fait expirer — et le seul point dont il a
  la trace ne s'atteste PAS à la main, sinon on peindrait en vert le garde-fou le plus
  important sans qu'aucun exercice n'ait eu lieu.
- **Un âge en jours ne s'affiche pas en secondes.** « Vérifié il y a 0 s » pour un
  exercice compté en jours entiers se lit « à l'instant », alors qu'il peut dater
  d'hier soir. Le type porte sa résolution (`resolution_jour`), sinon l'affichage
  invente une précision qui n'existe pas.
- **Un runbook écrit à la main est faux le jour où l'on en a besoin.** Celui-ci est
  engendré depuis l'état réel, porte sa date, et ne contient AUCUN secret — il est fait
  pour être imprimé et rangé ailleurs. Quand l'ordre de redémarrage ne se calcule pas,
  c'est la RAISON qui est imprimée : « il manque garage » se corrige, « l'ordre n'a pas
  pu être calculé » ne se corrige pas.
- **Le runbook engendré a révélé un manque réel de la démonstration** — ni `pocket-id`
  ni `garage` n'y étaient installés, alors que gitea et immich les déclarent. Le graphe
  refusait donc de produire un ordre, à juste titre.
- **Un plan nommé se rejoue TEL QU'IL A ÉTÉ PRÉVISUALISÉ**, jamais recalculé : deux
  calculs à deux instants peuvent diverger, et l'on exécuterait autre chose que ce qu'on
  a relu. Rejouer relance l'aperçu, pas l'exécution. Et un plan visant une route inconnue
  est refusé À L'ENREGISTREMENT — accepté, il échouerait des semaines plus tard sur un
  404 qui n'oriente vers rien.
- **Un gabarit de chemin se compare segment par segment.** Une comparaison par préfixe
  laisserait passer `/api/apps/gitea/install/vraiment`, qui n'existe pas.
- **Le piège de la continuation de ligne existe aussi côté serveur.** Constaté dans le
  runbook engendré : un paragraphe partait à quinze espaces de la marge. Le test se
  scanne LIGNE PAR LIGNE comme celui de l'interface — extraire les chaînes du fichier
  entier échoue sur toutes les continuations légitimes, parce que l'extracteur mange la
  newline mais pas l'indentation, là où rustc mange les deux.
- **Un assistant qui n'est pas essayé de bout en bout livre du faux.** L'assistant
  Bitwarden rattachait la BOÎTE et pas le COMPTE : son jeton était refusé par l'API
  d'aliases (« cette requête n'agit au nom de personne »), avec six étapes rassurantes
  qui envoyaient chercher du côté de Bitwarden. Constaté en appelant réellement
  `/api/v1/aliases` avec le jeton produit.
- **🔴 Le service worker ne met JAMAIS l'API en cache.** Un cache de données
  ressusciterait exactement le mensonge que `Freshness` existe pour empêcher : des apps
  vertes servies depuis le cache pendant que le cluster brûle. Un test scanne `sw.js` et
  refuse `/api/`, `/auth/` et `/metrics` dans la liste de la coquille.
- **Un QR se peint, il ne s'écrit pas.** Aucune police n'intervient, donc aucun tofu.
  Le module doit faire un nombre ENTIER de pixels — fractionnaire, egui lisse les bords,
  les carrés se mélangent et le code devient illisible pour un lecteur alors qu'il
  paraît net à l'œil. Et la marge de 4 modules est obligatoire : c'est la cause la plus
  fréquente d'un QR qui « ne marche que sur certains téléphones ».
- **Le kiosque est une liste BLANCHE d'écrans, jamais une liste noire.** Un mur est
  visible par quiconque passe dans la pièce ; on ne peut pas énumérer ce qui sera
  sensible demain, on peut énumérer ce qui est anodin aujourd'hui. Un écran ajouté plus
  tard est donc exclu par défaut, et un test refuse que la règle devienne une liste
  noire.
- **Un champ CSV non cité décale toutes les colonnes suivantes.** Le journal d'audit
  contient des détails écrits par des humains : virgules et guillemets y sont la norme.
  Et le fin de ligne est CRLF, sinon Excel fusionne les lignes.
- **L'état de HomelabUS n'était PAS sauvegardé.** Marque, thèmes, annonces, rôles,
  invitations, attestations de secours, plans, routes réellement posées : tout vit dans
  la base d'état, et rien ne la copiait. Une restauration rendait des apps qui tournent
  dans une installation qui ne sait plus qui est administrateur.
- **Un écran peut compiler et paniquer AU RENDU.** Un index hors bornes dans une
  boucle d'affichage ne se voit qu'en ouvrant l'écran — et sur vingt écrans, celui qui
  casse est rarement celui qu'on regarde. `Context::run` les rend tous hors écran, à
  vide et en disposition étroite. En revanche, les défauts purement VISUELS de ce
  chantier se sont tous trouvés en regardant une capture, jamais en comparant deux
  images.
- **Une route morte ne se voit pas.** `/api/apps/{name}` existait sans aucun appelant.
  Un test croise les routes déclarées avec ce que l'interface demande vraiment ; les
  routes servies à d'autres clients (Bitwarden, le veilleur, le CLI) sont listées
  explicitement — c'est une décision, pas un oubli.
- **La page de statut est PRIVÉE par défaut.** Publiée, elle révèle la liste de ce qui
  tourne chez vous et le calendrier de vos pannes. Ouverte, elle ne montre que les
  services **exposés** — jamais les nœuds, les sauvegardes ou les comptes.
- **Une maintenance annoncée n'est pas une panne.** C'était prévu, et l'afficher comme
  telle évite qu'on cherche ce qui ne va pas.
- **La page de statut demande `LireSoi`, pas `Lire`.** Elle est faite pour les gens qui
  subissent la panne, pas pour ceux qui l'exploitent : exiger un droit de console la
  ferait disparaître du portail, c'est-à-dire de l'endroit où on la cherche.
- **Une invitation ne se range PAS dans le stockage local**, contrairement au jeton
  d'accès : elle sert une fois, et un navigateur partagé la proposerait à la personne
  suivante — dont le compte porterait alors le rôle prévu pour quelqu'un d'autre.
- **L'écran d'inscription n'a NI navigation NI en-tête de session.** Il s'adresse à
  quelqu'un qui n'a pas de compte : lui proposer « Tableau de bord » l'enverrait sur un
  refus, et afficher l'identité de celui qui a ouvert le lien serait au mieux
  déroutant.
- **Un écran écrit et volontairement hors navigation mérite son propre test.** Sinon la
  règle « tout écran écrit est atteignable » finit par y ajouter une entrée, qui
  s'afficherait à des gens ayant déjà un compte.
- **Un avertissement n'est PAS un blocage.** « Ce lien laissera entrer cinq personnes »
  rangé parmi les blocages rendait l'action impossible — alors que c'est un choix
  légitime qu'on veut simplement voir avant de le faire. Deux champs distincts, deux
  formes à l'écran.
- **Une invitation à N usages qui fuite fait entrer N personnes.** Le défaut reste 1, le
  nombre restant est affiché, et un lien largement ouvert se distingue visuellement —
  c'est celui qu'on oublie de fermer.
- **Révoquer une invitation l'ÉPUISE, ne la supprime pas.** L'effacer perdrait la trace
  de qui l'a créée et de qui est déjà entré, au moment précis où on en a besoin.
- **Un incident se SUIT, il ne se réécrit pas.** C'est la chronologie qu'on relit après
  coup — à quelle heure on a su, compris, réglé. Et il reste ouvert tant que personne
  ne le clôt : le silence ne doit pas passer pour une résolution.
- **Une annonce qui ne concerne pas son lecteur est du bruit.** Inonder l'utilisateur du
  portail de messages d'exploitation lui fait cesser de les lire — au moment précis où
  l'un d'eux comptera. D'où l'audience par rôle.
- **HomelabUS ANNONCE les applications, il n'accorde pas l'accès.** Celui-ci vient de
  PocketID et du forward-auth. Et un lien vers une app arrêtée envoie sur une page
  d'erreur qu'on prend pour un problème de ses propres droits.
- **Un texte partagé ne doit dépendre d'AUCUN de ses consommateurs.** Les messages de
  `Coherence::describe()` portaient un 🔴 : très bien dans un terminal, remplacé par
  « ¤ » dans egui, ce qui donnait « ¤ identité créée, AUCUNE boîte ». La gravité passe
  par le contenu et par la couleur de l'appelant, jamais par un glyphe.
- **Un test qui scanne du source doit ASSEMBLER ses motifs.** Le test qui interdit
  « action(s) » s'est déclenché sur son propre code, trois fois de suite. Même astuce
  que le test qui interdit `Instant::now()` : `format!("({})", "s")` plutôt que le
  littéral.
- **Une invitation refusée pour une faute de frappe ne doit PAS être consommée.** Le
  nom est validé avant, sinon un lien à usage unique se gâche sur une majuscule.
- **Le rôle et le profil sont fixés à l'INVITATION**, jamais choisis par l'invité :
  sinon n'importe qui s'inscrirait administrateur.
- **Le panneau d'action vit dans le dispatcher, pas dans un écran.** Il était dans le
  détail d'app : un aperçu déclenché depuis l'écran des comptes partait sans que rien
  ne s'affiche, et le clic paraissait sans effet.
- **La requête à appliquer se reconstruit depuis l'APERÇU**, jamais depuis un état
  gardé à côté : deux sources finiraient par diverger, et l'on appliquerait une action
  différente de celle qu'on vient de lire. Une action non reconnue ne retombe sur
  aucune autre — elle rend 404, ce qui se voit.
- **« 0 réplica » prend le SINGULIER en français.** C'est la règle qui surprend, et
  celle qu'un `if n > 1` naïf rate. `hlb_api::pluriel` la porte, et un test interdit
  « action(s) » dans toute chaîne affichée — le tic qui trahit un texte fabriqué.
- **Un aperçu est journalisé `preview`, pas `ok`.** Savoir que quelqu'un a regardé ce
  qu'une purge ferait est une information ; la confondre avec une exécution rendrait le
  journal inexploitable.
- **Un nœud injoignable ne doit afficher AUCUNE jauge.** Il n'a pas de mauvais chiffres,
  il n'en a aucun : des barres à zéro se liraient « machine au repos ». On affiche la
  raison et on s'arrête là.
- **Un tofu peut venir du CONTENU, pas seulement des littéraux.** Le test qui scanne le
  source ne protège pas d'un emoji dans une annonce ou un nom de dossier Sieve.
  `glyphes::sans_tofu` remplace par un caractère visible — le supprimer ferait
  disparaître du texte en silence, ce qui est pire.

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

Fait enfin : `hlb self` (compatibilité, migrations réversibles, rollback du schéma),
`hlb snapshot` (ZFS/btrfs), et l'**authentification de l'API par jetons** avec rôles
(`hlb token`). Le controller REFUSE de démarrer sans jeton, sauf `--insecure-no-auth`.

🔴 **mailcow est abandonné** (décision du 17/08/2026). Stalwart le remplace, et le
runtime `compose` qui n'existait que pour lui n'a plus de raison d'être. Les mentions
de mailcow dans PLAN.md sont historiques : elles expliquent le choix de Stalwart.

Fait aussi : `hlb dr exercise` — la restauration répétée pour de vrai dans un
conteneur jetable (§8.3), avec un compteur de péremption dans `dr status`.

Fait enfin : la **réplication streaming PostgreSQL** (`hlb replication config/status`),
vérifiée contre un vrai couple primaire/standby — copie initiale, rattrapage après une
coupure, alerte de slot orphelin avec son remède, et détection des standbys qu'on ne
sait pas distinguer. Asynchrone par décision : en synchrone, la panne du standby
bloquerait les écritures de la primaire.

Catalogue : Gitea, Vikunja, Vaultwarden, plus **n8n, Jellyfin, LibreSpeed et Termix**.
Les ajouter a révélé trois défauts du résolveur (client OIDC créé pour une exclusion
volontaire, callback de portail pointant vers l'app, `native` sans `redirectPaths`
accepté), tous corrigés — c'est bien l'ajout d'apps aux combinaisons différentes qui
fait sortir ces trous, pas le volume.

Fait : **les liaisons** (`spec.env` + `hlb-types::binding`), la moitié qui manquait au
résolveur. Une app déclare comment elle veut recevoir ce qui a été provisionné, par des
jetons (`{{ db.host }}`, `{{ db.password }}`, `{{ oidc.client_secret }}`…). 🔴 Les
jetons de secret sont résolus **dans l'exécuteur**, jamais dans le plan : celui-ci est
affiché, enregistré dans l'état et exporté vers le miroir Git.

Fait aussi : les **dumps MariaDB** (`hlb-backup::mariadump`), qui manquaient — une app
MariaDB était provisionnée mais n'avait aucune sauvegarde logique.

Fait enfin : l'**observabilité complète** (`hlb-metrics`) — VictoriaMetrics et Grafana
au catalogue, règles d'alerte évaluées par HomelabUS et routées vers `hlb-notify`
(plutôt qu'Alertmanager, qui dupliquerait les niveaux et les heures calmes), et le
**deadman switch** du §8bis avec son veilleur pour le NAS. `hlb metrics rules / scrape /
check / deadman`.

Fait : le **multi-conteneur** (`spec.companions`, §4.7bis) — un compagnon est déployé
avant l'app et attendu sain, n'a jamais d'ingress ni de capacités propres, et se joint
par `{{ companion.<nom>.host }}`. Et le **stockage objet** (`Capability::ObjectStorage`
+ `hlb-objstore` + Garage au catalogue), avec compartiment et clé isolés par app.

Catalogue : Gitea, Vikunja, Vaultwarden, n8n, Jellyfin, LibreSpeed, Termix, **Immich**
(avec son compagnon d'apprentissage automatique) et **Seafile CE** (trois bases, un
rôle). Voir `catalog/CATALOGUE.md` pour les candidats suivants.

⚠️ L'image du service `postgres` est passée à `ghcr.io/immich-app/postgres:17-…`, qui
porte `pgvector` et `vchord`. Même version majeure, mais **libc différente** : lire le
guide `reindex-collation` d'Immich avant de basculer une installation existante.

Fait : les **destinations de sauvegarde multiples** (`hlb backup dest` / `route`) — le
3-2-1 du §8.1 rendu réel. restic sait désormais écrire en S3 (identifiants par
l'environnement, jamais dans l'URL ni la ligne de commande), et le routage se fait par
**classe de volume** : `critique` (dumps, état, secrets — quelques Go, ça part hors
site) et `volumineux` (photos, fichiers — des centaines de Go, ça reste où la connexion
le permet), avec un réglage par app. `hlb backup run` sert chaque destination
séparément — un échec sur l'une n'empêche pas les autres, et chacune a sa propre
échéance.

Fait : les **comptes humains** (`hlb-users`, `hlb user`). Jusque-là HomelabUS ne
connaissait que des applications — `hlb-identity` créait des clients OIDC, jamais des
personnes. Un compte se crée maintenant en une commande : identité PocketID + boîte
mail, avec un lien d'inscription à usage unique. Les aliases couvrent **trois axes
indépendants** — permanent ou temporaire, généré ou choisi, avec ou sans indice de
site — et `hlb user alias purge` est ce qui rend l'expiration vraie, Stalwart n'en
ayant aucune notion — et le controller la fait tourner toutes les heures, sinon la
promesse ne tiendrait que si quelqu'un pensait à lancer la commande.

Fait aussi : les deux **webmails** du §5bis.2ter — **Bulwark** (JMAP natif pour
Stalwart, `channel: pin` : aucune release Git ni licence déclarée, seules les images
existent) et **Roundcube** comme filet de sécurité, délibérément SANS SSO pour rester
joignable quand PocketID tombe. Et la **génération des règles Sieve** de tri par alias,
avec dossier configurable par l'utilisateur. Et l'**API compatible addy.io /
Bitwarden** (`POST /api/v1/aliases`) : Vaultwarden génère l'alias au moment de créer un
compte sur un site, comme avec idmail — qu'on n'intègre PAS, puisqu'il remplacerait
l'annuaire de Stalwart.

Fait (18/08/2026) : le **lot 1 de la refonte UI** — RBAC réellement appliqué (quatre
rôles, `Autorise<Peut*>` dans la signature des routes), **connexion par OIDC PocketID**
(`hlb-identity::oidc`, PKCE, cookie dont seule l'empreinte est stockée), **journal
d'audit chaîné** (`hlb audit --verify`), limitation de débit, `hlb user role/sessions`.
Trois défauts réels corrigés au passage : l'API d'aliases n'appliquait **aucun quota**
malgré un commentaire affirmant le contraire, `Capability::MailAccount { .., }` avalait
`quota_bytes` par un `..`, et le CLI suggérait un rôle `metrics` inexistant.

Fait aussi : le **lot 2** — système de design (`hlb-ui::design`), marque *Turi
Industries* servie par le controller et éditable, **routage par fragment d'URL**
(`#/apps/gitea/sauvegardes`), coquille responsive (barre latérale / barre basse),
`Ressource<T>` qui porte **sa propre `Freshness`**, et le **mode démonstration**
(`hlb-controller --demo`) — base en mémoire peuplée des cas qu'on n'a jamais sous la
main : app jamais sauvegardée, hors-site mort, alias expiré qui reçoit encore, compte à
moitié créé dans les deux sens.

Fait aussi : le **lot 3** — la télémétrie. Les tâches Swarm ne sont plus un compteur
(`Orchestrator::tasks` rend le placement, l'état réel et l'ERREUR), les journaux de
service sont lisibles (`Orchestrator::logs`), l'agent passe en **protocole 2** (charge,
occupation CPU, swap, interfaces, noyau/distro, uptime — tous `Option`, compatibles dans
les deux sens), un **relais PromQL** à liste blanche alimente les graphes, et une
**boucle d'alertes** évalue enfin les règles en continu — elles n'étaient évaluées que
par le CLI, donc uniquement quand quelqu'un tapait `hlb metrics check`.

Fait aussi : le **début du lot 4** — les écrans de lecture branchés sur la télémétrie.
Nœuds (jauges, disques, tâches hébergées, agent injoignable ou en vieux protocole),
Alertes (les quatre cas d'affichage, sourdine comprise) et Sauvegardes (couverture par
destination, historique avec ses échecs). Trois défauts d'affichage trouvés **en
regardant l'écran**, pas en lisant le code : swap peint en vert à 71 %, « AUCUNE copie »
contredisant le détail juste en dessous, et cartes en escalier faute de `set_width`.

Fait aussi : la **vue topologie** (§11bis) — regroupement par domaine de panne,
détection des violations d'anti-affinité, et distinction entre « domaine non déclaré »
et « nœud isolé ». C'est l'écran que le plan désigne comme justifiant à lui seul
l'existence de l'interface : l'information existait dans les étiquettes Swarm et
n'était lisible nulle part.

Fait enfin : le **début du lot 5** — les routes qui agissent, sous les trois règles qui
remplacent l'ancienne interdiction « lecture seule » : aperçu par défaut (`?apply=true`),
autorisation dans la signature (`Autorise<PeutOperer>`), journal d'audit systématique.
Plus la **confirmation nommée** pour ce qui détruit. Les exécuteurs réels ne sont pas
encore branchés : les actions rendent `NonImplementee` plutôt qu'un faux succès.

Fait : le **lot 5 complet** — huit routes d'action (installer, sauvegarder, mettre à
l'échelle, attester un guide, déclarer une destination, drainer un nœud, supprimer), le
catalogue exposé, et le panneau d'action de l'interface avec son cycle **aperçu →
décision → résultat**. L'aperçu d'installation montre le **plan réel** produit par le
résolveur, guides bloquants compris. Un champ `apercu` sur `RouteMutante` distingue les
actions (qui doivent être prévisualisées) des réglages (qui n'ont rien à prévisualiser),
et un test verrouille la courte liste des exemptions.

⚠️ Les exécuteurs réels ne sont branchés que pour ce qui ne demande ni coffre ni Docker :
attester un guide et déclarer une destination agissent vraiment ; installer, sauvegarder
et supprimer rendent `NonImplementee` avec la raison — jamais un faux succès.

Fait : le **lot 6** — invitations à usage unique (consommation atomique en
transaction), inscription libre-service, gestion des comptes et des rôles, et l'écran
qui montre les **comptes à moitié créés** en tête de liste avec le geste qui répare.
PocketID et Stalwart sont branchés sur le controller : l'inscription crée réellement
l'identité et la boîte quand ils sont configurés, et le dit honnêtement sinon.

Un second garde-fou déclaré sur `RouteMutante` : `publique: bool`. L'inscription est la
**seule** route sans authentification — la personne n'a pas encore de compte, et
l'invitation porte sa propre autorisation. Un test verrouille cette liste d'une entrée.

Fait : les **invitations multi-usages** (durée et nombre de personnes choisis à la
création, bornés des deux côtés) et le **lot 7** — portail utilisateur, annonces avec
audience par rôle, et incidents **suivis** plutôt que réécrits.

Un troisième champ sur `ResultatAction` : `avertissements`, distinct de `blocages`. Un
avertissement informe sans empêcher ; les confondre rendait impossible une action
parfaitement légitime.

Fait aussi : l'**écran d'inscription**, atteint par `#invitation=` et seulement comme
ça. Le nom se vérifie **sans consommer le lien** — une majuscule de trop gâcherait une
invitation à usage unique — et le lien d'enrôlement PocketID s'affiche une fois, jamais
stocké.

Fait aussi : l'**écran d'annonces** (publier, suivre un incident, retirer) et la **page
de statut** — privée par défaut, ouverte par `--statut-public`, et ne montrant alors que
les services exposés.

Fait : le **lot 8** — chaque personne choisit son thème, enregistré côté serveur et non
dans le navigateur, donc il la suit sur tous ses appareils. Trois thèmes livrés, tous
validés contre la vision deutéranope.

Fait : le **lot 9** — la corrélation, ce qui distingue l'interface du CLI. Aucune
donnée nouvelle : la somme de ce qui existait, dispersé sur quatre écrans.

**Restaurabilité** (`hlb-backup::restaurabilite`) : « si je perds tout maintenant, je
récupère quoi ? », en un verdict et des remèdes ordonnés. **Simulateur de panne**
(`hlb-api::panne`) : la topologie cesse d'être un dessin et répond. **Chaîne causale**
(`hlb-api::diagnostic`) : de la tâche en échec au disque plein, en s'arrêtant honnêtement
quand elle ne sait plus. **Écran dérive** : les refus délibérés de la réconciliation,
avec leur raison. **Frise unifiée** (`hlb-controller::frise`) : sauvegardes et actions
dans une seule rivière datée. **Exposition déclarée contre réelle** : la table
`ingress_publie` enregistre ce que `hlb ingress apply` a posé, et l'écart se voit —
routes orphelines comprises. **Liste de contrôle** (`hlb-controller::sante`), **budget de
capacité** avant installation, et **diff de manifest** lu dans le miroir Git.

Trois défauts réels trouvés au passage : `record_verification` enregistrait en échec
toute vérification qu'on décrivait, sept pluriels entre parenthèses dans du texte
fabriqué côté serveur, et un `✓` illisible dans egui au milieu d'un message partagé.

Fait : le **lot 10** — les opérations rares et dangereuses, celles que le §11bis
désigne comme la troisième raison d'être de l'interface.

**Rotation assistée** (`hlb-api::rotation`) : ce que tourner un secret IMPLIQUE, par
nature, dans l'ordre — le coffre n'est pas la source de vérité. **Break-glass vivant**
(`hlb-api::breakglass` + `hlb-controller::secours`) : quatre garde-fous, trois
attestations datées qui expirent, et un seul point que HomelabUS prouve lui-même.
**Runbook imprimable** (`hlb-controller::runbook`) engendré depuis l'état réel, sans
aucun secret. **Plans nommés** (migration `0022`) : préparer à froid, exécuter à l'heure
creuse, en rejouant exactement ce qui a été prévisualisé.

Fait : les **lots 11 et 12** — la finition et les garde-fous de fabrication.

**Assistant Bitwarden** (`hlb-controller::bitwarden`) : crée le jeton `operator`
rattaché au compte ET à la boîte, et dit exactement quoi coller. **QR code peint**
(`hlb-ui::design::qr`) pour les liens à usage unique. **PWA installable** — dont le
service worker ne met JAMAIS l'API en cache. **Mode kiosque** (`hlb-ui::kiosque`), avec
liste blanche d'écrans. **Export CSV** du journal, des sauvegardes et des comptes. Et
la **sauvegarde de l'état lui-même**, qui manquait.

Côté fabrication : **tests de rendu** de tous les écrans (headless, sans dépendance
ajoutée), test de **routes mortes**, test de **discipline `Freshness`**, et **budget de
taille du wasm** dans `build-web.sh` (6 Mo ; le bundle en fait 3,4).

⚠️ `egui_kittest` du §12.1 n'est PAS utilisé : la variante à instantanés d'images exige
un rendu GPU, et la variante légère active la fonction `accesskit` d'egui, ce qui casse
la compilation d'`egui-winit` 0.33.3 — un décalage de version en amont. `Context::run`
tourne sans fenêtre et suffit à attraper ce qui compte : un écran qui panique au rendu.

## Ce qui reste

État vérifié le 21/08/2026 : `cargo test --workspace` passe (**1370 tests unitaires,
66 d'intégration `#[ignore]`**), `cargo clippy --all-targets` est à zéro avertissement.
La feuille de route du §12 est couverte.

Ce qui suit est **la liste de reprise** : par ordre d'utilité, avec l'endroit exact où
le travail attend. Elle est ici pour qu'aucun de ces points ne se redécouvre en panne.

### 1. Les exécuteurs réels des routes d'action (§11bis, lot 5)

C'est la moitié manquante du lot 5, et le premier chantier à reprendre. Quatre routes
construisent un aperçu juste, puis rendent `EtatEtape::NonImplementee` avec la raison
au lieu d'agir — c'est l'invariant « `Unimplemented` n'est jamais `Done` », tenu
honnêtement, mais ce sont les quatre gestes qu'on veut faire depuis l'interface.

| Action | Ce qui manque | Où |
|---|---|---|
| installer une app | coffre + orchestrateur + clients de plateforme dans l'état partagé | `hlb-controller/src/actions.rs:281` |
| lancer une sauvegarde | le dépôt restic vit dans la boucle du controller, pas dans l'état de l'API | `hlb-controller/src/actions.rs:407` |
| drainer un nœud | `Orchestrator` n'expose pas la disponibilité, seulement `label_node` | `hlb-controller/src/actions.rs:775` |
| supprimer une app | orchestrateur + exécuteur | `hlb-controller/src/actions.rs:863` |

**Le drainage est le plus facile** — une méthode à ajouter au trait `Orchestrator`, en
face de `docker node update --availability`. **L'installation est la plus
structurante** : elle demande de partager avec l'API le contexte que le CLI assemble
déjà (coffre, bollard, `hlb-platform`, `hlb-identity`), et le reste suit.

⚠️ Ne pas « brancher » en appelant le CLI en sous-processus : le plan serait recalculé
au lieu d'être rejoué, et l'on exécuterait autre chose que ce qui a été prévisualisé.

### 2. Trois écrans déclarés et non écrits

`Route::implemente()` les filtre de la navigation, donc rien ne ment à l'écran — c'est
la règle « ne jamais proposer un écran qui n'existe pas ». Ils manquent quand même :

- **`Route::MaBoite`** — les **aliases en libre-service**. L'API (`/api/v1/aliases`),
  les quotas et les rôles sont en place ; c'est l'interface qui manque, et c'est ce qui
  rendrait les aliases utilisables par quelqu'un d'autre que l'administrateur. Le plus
  utile des trois.
- **`Route::MonCompte`** — profil, thème, sessions, jetons Bitwarden vus par leur
  propriétaire.
- **`Route::Catalogue`** — pourtant déjà exposé par l'API depuis le lot 5.

Ajouter l'écran suffit : `Route::implemente()` le fait apparaître dans la navigation,
et le test qui croise écrans et navigation le vérifie.

### 3. 🔴 Rien de la partie mail n'est vérifié contre un vrai Stalwart

`hlb-mail` est écrit à partir du code source amont, jamais exécuté contre une
instance : pas d'image en local. À éprouver le jour où on en aura une — le chemin
`/jmap/upload/{accountId}/`, la forme d'`onSuccessActivateScript`, le format de
`/jmap/download/`, et `x:Account/get` sur `aliases`. Les **dumps MariaDB** sont dans le
même cas (runner simulé). C'est plus faible que la réplication PostgreSQL, elle
vérifiée contre un vrai couple.

Ça ne demande pas de code : ça demande une instance.

### 4. Le reste, par ordre décroissant d'intérêt

- **`hlb db failover`** : la bascule assistée du §3.2 phase 2. Aucune occurrence de
  « failover » dans le workspace aujourd'hui. La réplication marche et est vérifiée
  contre un vrai couple ; il manque la commande, et un second nœud `heavy` réel pour
  l'éprouver.
- **`hlb user mailbox add` n'ouvre pas le compte Stalwart** — il l'enregistre
  seulement. Et les **ACL IMAP** (que Stalwart implémente) permettraient de voir
  plusieurs boîtes sous UNE seule connexion, au lieu d'en configurer trois.
- **`hlb self update`** attend une URL de distribution. La vérification Ed25519 et la
  bascule du binaire sont faites et testées (`hlb-selfupdate`, 44 tests).
- **Le catalogue** : 11 apps et 12 services de plateforme aujourd'hui, ~30 candidates
  dans `catalog/CATALOGUE.md` — toutes réalisables sans nouveau mécanisme depuis le
  multi-conteneur et le stockage objet.
- **Le multi-nœuds de Garage** passe par `garage layout`, pas par `replicas` : une
  seule instance tant qu'il n'y a qu'un nœud de stockage.
- **Pas d'assistant TUI** pour `hlb cluster init` : la commande existe et est
  idempotente, sans l'accompagnement `ratatui` prévu au §12.

### Ce qui a été écarté, et ne revient pas

- **mailcow** et le runtime `compose` (décision du 17/08/2026, §5.9). Stalwart le
  remplace ; les mentions dans PLAN.md sont historiques.
- **L'OpenAPI `utoipa` + génération TypeScript** du §11bis : sans objet depuis le choix
  d'egui, `hlb-api` définit les types une seule fois pour les deux côtés.
- **L'import `docker-compose.yml`** : écarté d'entrée, contexte greenfield (§12).
- **`egui_kittest`** du §12.1 : la variante à instantanés exige un GPU, la variante
  légère casse la compilation d'`egui-winit` 0.33.3. `Context::run` suffit.

## Hygiène du dépôt

🔴 **`hlb-master.key` a été suivi par git du 16/08/2026 (commit `2d2ea0f`) jusqu'au
21/08/2026.** Le fichier porte pourtant « NE PAS COMMITER » dans son propre en-tête. Il
est maintenant dans `.gitignore` et retiré de l'index, **mais il reste dans
l'historique** : `git log -- hlb-master.key` le montre encore. Avant toute publication
du dépôt, il faut soit purger l'historique, soit tourner la clé — sa fuite expose tous
les secrets du coffre et toutes les sauvegardes.

Rien d'autre de sensible n'est suivi : les seules autres occurrences de clés dans
l'historique (`hlb-agent/src/pki.rs`, `hlb-agent/src/tls.rs`) sont des données de test.
