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

Fait : le **multi-conteneur** (`spec.companions`, §4.8) — un compagnon est déployé
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

Il ne reste rien de la feuille de route du §12. Le déploiement multi-nœuds de la
réplication attend un second nœud `heavy` réel ; `hlb self update` attend une URL de
distribution (la vérification Ed25519 et la bascule du binaire sont faites).
