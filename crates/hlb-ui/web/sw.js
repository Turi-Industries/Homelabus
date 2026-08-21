// Le service worker de HomelabUS (lot 11.3).
//
// 🔴 IL NE MET JAMAIS L'API EN CACHE.
//
// C'est la seule règle de ce fichier, et elle n'est pas négociable. Un cache de
// réponses d'API ressusciterait exactement le mensonge que `Freshness` existe pour
// empêcher : des applications affichées en vert, servies depuis le cache, pendant que
// le cluster brûle. La coquille (wasm, JS, HTML) se met en cache ; les données, jamais.
//
// ⚠️ Un test de `hlb-ui` scanne ce fichier et refuse tout motif `/api/`, `/metrics` ou
// `/auth/` dans la liste des ressources mises en cache.

const VERSION = 'hlb-coquille-v1';

// Uniquement la coquille : ce qui est identique pour tout le monde et ne dit rien de
// l'état du cluster.
const COQUILLE = [
  './',
  './index.html',
  './hlb_ui.js',
  './hlb_ui_bg.wasm',
  './manifest.json',
  './icone.svg',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(COQUILLE)));
  // La nouvelle version prend la main tout de suite : garder l'ancienne coquille
  // ferait tourner un wasm périmé contre une API à jour, et les types ne
  // correspondraient plus.
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((noms) =>
      Promise.all(noms.filter((n) => n !== VERSION).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // 🔴 Tout ce qui porte des DONNÉES passe directement au réseau, sans cache et sans
  // repli. Si le controller est mort, la requête échoue — et c'est précisément ce que
  // l'interface doit voir pour afficher « données périmées » au lieu d'un faux vert.
  const donnees =
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/auth/') ||
    url.pathname.startsWith('/metrics');

  if (donnees || e.request.method !== 'GET') {
    return; // Comportement par défaut du navigateur : réseau, point.
  }

  // La coquille : cache d'abord, réseau ensuite. Elle ne périme qu'au déploiement.
  e.respondWith(
    caches.match(e.request).then((r) => r || fetch(e.request))
  );
});
