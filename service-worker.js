// Lunox — service worker для PWA.
// Кэширует статику (cache-first), не трогает запросы к Firebase/Firestore/
// Telegram/GigaChat/Gemini и Netlify Functions (network-first, без агрессивного кэша),
// чтобы не ломать реалтайм-данные и авторизацию.

const CACHE_VERSION = 'lunox-static-v34';
const PRECACHE_URLS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png',
  '/icon-512-maskable.png',
  '/apple-touch-icon.png'
];

const STATIC_EXT = ['.html', '.css', '.js', '.json', '.png', '.jpg', '.jpeg', '.svg', '.ico', '.woff', '.woff2'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION)
      .then((cache) => Promise.allSettled(
        // По одному файлу: 404/сеть на любом из них не срывает установку воркера (cache.addAll — «всё или ничего»).
        PRECACHE_URLS.map((url) => cache.add(url).catch((err) => { console.warn('[Lunox SW] precache пропущен:', url, err && err.message); }))
      ))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((key) => key !== CACHE_VERSION).map((key) => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

function isApiRequest(url) {
  return url.pathname.startsWith('/.netlify/functions/');
}

function isStaticAsset(url) {
  if (url.origin !== self.location.origin) return false;
  if (url.pathname === '/') return true;
  return STATIC_EXT.some((ext) => url.pathname.endsWith(ext));
}

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);

  // Netlify Functions (GigaChat / Gemini) — всегда свежие данные, сеть в приоритете.
  if (isApiRequest(url)) {
    event.respondWith(
      fetch(request).catch(() => caches.match(request))
    );
    return;
  }

  // HTML (страница и index.html) — network-first: всегда свежая версия, кэш только офлайн.
  if (request.mode === 'navigate' || url.pathname === '/' || url.pathname.endsWith('.html')) {
    if (url.origin === self.location.origin) {
      event.respondWith(
        fetch(request, { cache: 'no-cache' }).then((response) => {
          if (response && response.ok) {
            const clone = response.clone();
            caches.open(CACHE_VERSION).then((cache) => cache.put(request, clone));
          }
          return response;
        }).catch(() => caches.match(request).then((c) => c || caches.match('/index.html')))
      );
      return;
    }
  }

  // Собственная статика — cache-first, обновление кэша в фоне.
  if (isStaticAsset(url)) {
    event.respondWith(
      caches.match(request).then((cached) => {
        const networkFetch = fetch(request)
          .then((response) => {
            if (response && response.ok) {
              const clone = response.clone();
              caches.open(CACHE_VERSION).then((cache) => cache.put(request, clone));
            }
            return response;
          })
          .catch(() => cached);
        return cached || networkFetch;
      })
    );
    return;
  }

  // Всё остальное (Firebase, Firestore, Telegram, GigaChat, Gemini, сторонние API)
  // сервис-воркер не перехватывает — запросы идут напрямую в сеть.
});
