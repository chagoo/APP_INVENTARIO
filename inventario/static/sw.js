const CACHE_NAME = 'inventario-cache-v1';
const OFFLINE_URLS = [
  '/',
  '/static/css/styles.css'
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
  evt.respondWith(
    caches.match(req).then(cached => cached || fetch(req).then(res => {
      const copy = res.clone();
      caches.open(CACHE_NAME).then(c => c.put(req, copy));
      return res;
    }).catch(()=>caches.match('/')))
  );
});
