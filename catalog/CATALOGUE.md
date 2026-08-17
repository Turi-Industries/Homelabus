# Ce qu'on peut mettre au catalogue

Inventaire des apps candidates, classées par **ce qu'elles demandent au système**
plutôt que par popularité. Le classement est le point : ajouter une app dont la
capacité n'existe pas n'est pas « une app de plus », c'est du travail de fond caché
derrière un fichier YAML.

## Légende

| | Signification |
|---|---|
| ✅ | Rentre dans les capacités actuelles : un conteneur, PostgreSQL / MariaDB / Valkey / SSO / SMTP / stockage |
| 🔶 | Demande le **multi-conteneur** (compagnon ML, agent, courtier de messages) |
| 🔷 | Demande le **stockage objet** (S3 : MinIO ou Garage) |
| ⛔ | Mauvais candidat pour Swarm, et il vaut mieux le savoir avant |
| 🟢 | Déjà au catalogue |

---

## Déjà là

| App | Ce que c'est |
|---|---|
| 🟢 Gitea | Forge Git : dépôts, tickets, revues de code |
| 🟢 Vikunja | Tâches et projets, dans l'esprit de Todoist |
| 🟢 Vaultwarden | Gestionnaire de mots de passe compatible Bitwarden |
| 🟢 n8n | Automatisation : relie des services entre eux par des workflows |
| 🟢 Jellyfin | Serveur multimédia — films, séries, musique |
| 🟢 LibreSpeed | Test de débit, hébergé chez soi |
| 🟢 Termix | Terminal SSH dans le navigateur |

Services de plateforme : PostgreSQL, MariaDB, Valkey, PocketID, Stalwart, Caddy,
CrowdSec, oauth2-proxy, ntfy, VictoriaMetrics, Grafana.

---

## ✅ Rentrent aujourd'hui

### Documents

| App | Ce que c'est | Demande |
|---|---|---|
| **Paperless-ngx** | Numérise et indexe les papiers administratifs, avec OCR. On photographie une facture, elle devient cherchable par son texte. | postgres + valkey + stockage |
| **Stirling-PDF** | Boîte à outils PDF : fusionner, découper, signer, compresser, OCR. Sans état. | rien |
| **Docuseal** | Signature électronique de documents, façon DocuSign. | postgres + stockage |

### Lecture et veille

| App | Ce que c'est | Demande |
|---|---|---|
| **Miniflux** | Lecteur RSS minimal, très rapide, sans fioriture. Parle OIDC nativement. | postgres + SSO natif |
| **FreshRSS** | Lecteur RSS plus riche : filtres, extensions, applications mobiles. | postgres ou mariadb |
| **Wallabag** | « Lire plus tard » : archive une page web en version lisible, hors ligne. | mariadb + valkey |
| **Linkwarden** | Marque-pages qui **archive** vraiment la page — elle survit à sa disparition. | postgres + SSO natif |

### Médias

| App | Ce que c'est | Demande |
|---|---|---|
| **Navidrome** | Serveur de musique compatible Subsonic : marche avec toutes les apps mobiles du protocole. | SQLite + NFS |
| **Audiobookshelf** | Livres audio et podcasts, avec reprise de lecture entre appareils. | SQLite + NFS |
| **Kavita** | Lecture de BD, mangas et livres numériques dans le navigateur. | SQLite + NFS |
| **Calibre-Web** | Bibliothèque d'ebooks : envoi vers liseuse, conversion de format. | SQLite + NFS |
| **PhotoPrism** | Galerie photo avec reconnaissance d'objets et de visages **embarquée** — c'est ce qui le distingue d'Immich ici : un seul conteneur. | postgres ou mariadb + NFS |
| **Piwigo** | Galerie photo classique, mûre, sans apprentissage automatique. | mariadb + NFS |

### Médiathèque automatisée

Chacun est un conteneur indépendant, tous partagent le même NFS.

| App | Ce que c'est | Demande |
|---|---|---|
| **Sonarr / Radarr** | Suivent séries et films : téléchargement, renommage, rangement. | SQLite + NFS |
| **Prowlarr** | Gère les indexeurs pour les deux précédents, en un seul point. | SQLite |
| **Bazarr** | Va chercher les sous-titres manquants. | SQLite + NFS |
| **qBittorrent** | Client BitTorrent avec interface web. | SQLite + NFS |
| **SABnzbd** | Client Usenet. | SQLite + NFS |
| **Jellyseerr** | Page de demandes : quelqu'un réclame un film, la chaîne s'en occupe. | SQLite + SSO |

### Fichiers et synchronisation

| App | Ce que c'est | Demande |
|---|---|---|
| **Nextcloud** | Le « Google Drive » auto-hébergé : fichiers, agenda, contacts, bureautique. Gros, mais central. | mariadb + valkey + stockage + SMTP |
| **Syncthing** | Synchronisation de dossiers entre machines, sans serveur central. | stockage |
| **Filebrowser** | Explorateur de fichiers web, minimal, pour un partage rapide. | stockage |

### Organisation quotidienne

| App | Ce que c'est | Demande |
|---|---|---|
| **Mealie** | Recettes de cuisine : import depuis une URL, menus de la semaine, liste de courses. | postgres + SSO natif |
| **Grocy** | Gestion des stocks de la maison : dates de péremption, courses, corvées. | SQLite |
| **Actual Budget** | Budget familial par enveloppes, avec application mobile. | SQLite |
| **Baikal** | Serveur CalDAV/CardDAV : agenda et contacts synchronisés avec le téléphone. | mariadb |

### Outils et infrastructure

| App | Ce que c'est | Demande |
|---|---|---|
| **Uptime Kuma** | Supervision de disponibilité vue de **l'extérieur** — complémentaire de `hlb-metrics`, qui regarde de l'intérieur. | SQLite |
| **Dozzle** | Journaux Docker en direct dans le navigateur, sans rien stocker. | rien |
| **Homepage** | Page d'accueil du homelab : tuiles vers les services, avec leur état. | fichiers de config |
| **IT-Tools** | Boîte à outils : encodage, hachage, UUID, JWT, conversions. Sans état. | rien |
| **Excalidraw** | Tableau blanc pour schémas à main levée. Sans état. | rien |

### Communication

| App | Ce que c'est | Demande |
|---|---|---|
| **Matrix Synapse** | Messagerie fédérée, chiffrée de bout en bout. ⚠️ L'espace média grossit vite — le S3 (🔷) le soulagerait. | postgres + stockage |

---

## 🔶 Demandent le multi-conteneur

Le format de manifest décrit **un** conteneur. Ces apps en veulent plusieurs qui
partagent leur cycle de vie.

| App | Ce que c'est | Ce qui manque |
|---|---|---|
| **Immich** | Galerie photo façon Google Photos : reconnaissance de visages, recherche par description, applications mobiles avec sauvegarde automatique. **La plus demandée du lot.** | Un conteneur d'apprentissage automatique séparé, **et** un PostgreSQL avec extension vectorielle — deux blocages, pas un |
| **Woodpecker CI** | Intégration continue branchée sur Gitea. | Serveur + agent |
| **Karakeep** | Marque-pages avec résumé automatique et recherche en texte intégral. | Meilisearch + navigateur sans tête |
| **Seafile** | Synchronisation de fichiers, plus rapide que Nextcloud sur les gros volumes. | Plusieurs services |
| **Zigbee2MQTT** | Passerelle Zigbee vers MQTT pour la domotique. | Courtier MQTT séparé |
| **Beszel** | Supervision légère de serveurs. | Hub + agents |

---

## 🔷 Demandent le stockage objet

Une capacité `object-storage` plus MinIO ou Garage en service de plateforme.

**Double usage** : ce même service ferait cible pour restic, ce qui remplacerait le S3
externe du 3-2-1 (§8.1) par un troisième site à soi.

| App | Ce que c'est |
|---|---|
| **Outline** | Wiki d'équipe soigné, façon Notion. Le S3 n'est pas optionnel chez lui. |
| **Matrix Synapse** | Y déporter les médias évite que le volume local explose. |
| **Nextcloud** | Stockage primaire objet : la donnée quitte le disque du nœud. |

---

## ⛔ Mauvais candidats pour Swarm

À dire franchement plutôt que de les ajouter et de découvrir le problème après.

| App | Pourquoi |
|---|---|
| **Home Assistant** | Veut le réseau de l'hôte et l'accès direct aux clés USB (Zigbee, Z-Wave). Swarm ne sait pas placer une app « sur le nœud où est branchée la clé ». Sa place est sur une machine dédiée. |
| **AdGuard Home / Pi-hole** | Veulent le port 53 sur l'hôte et sont l'infrastructure DNS dont dépend le cluster : les héberger dans le cluster crée une dépendance circulaire — le DNS tombe, le cluster ne redémarre plus. |
| **Plex** | Modèle d'authentification lié à un compte distant, incompatible avec le SSO local. Jellyfin fait le même travail sans cette laisse. |

---

## Ce que ça dit de l'ordre à suivre

Le catalogue « ✅ » représente une trentaine d'apps déjà atteignables — assez pour un
homelab complet. Mais l'app la plus demandée du lot (Immich) est en 🔶, et le stockage
objet (🔷) rendrait service **deux fois**, aux apps comme aux sauvegardes.

🔴 **Et rien de tout cela ne fonctionnera tant que les identifiants de base
n'atteindront pas le conteneur** — voir la section correspondante de CLAUDE.md. Une
app à base de données démarre aujourd'hui sans savoir s'y connecter.
