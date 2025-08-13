const CACHE_NAME = 'inventario-cache-v2';
const OFFLINE_URLS = [
  '/',
  '/static/css/styles.css',
  '/static/js/offline.js',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];
self.addEventListener('install', evt => {
  evt.waitUntil(
    caches.open(CACHE_NAME).then(c => c.addAll(OFFLINE_URLS))
  );
});
self.addEventListener('activate', evt => {
  evt.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k=>k!==CACHE_NAME).map(k=>caches.delete(k))))
  );
});
self.addEventListener('fetch', evt => {
  const req = evt.request;
  if (req.method !== 'GET') return;

  const accept = req.headers.get('accept') || '';

  // Always try the network first for navigation requests (HTML)
  // so that dynamic pages like forms include a fresh CSRF token.
  if (req.mode === 'navigate' || accept.includes('text/html')) {
    evt.respondWith(
      fetch(req).catch(() => caches.match('/'))
    );
    return;
  }

  // Cache-first strategy for static assets
  evt.respondWith(
    caches.match(req).then(cached => cached || fetch(req).then(res => {
      const copy = res.clone();
      caches.open(CACHE_NAME).then(c => c.put(req, copy));
      return res;
    }))
  );
});
