// Minimal service worker: cache-first for static assets, network-only for API calls.
// Keeps the app shell loadable offline; car data always comes fresh from the network.

const CACHE = 'bluewink-v1'
const APP_PREFIX = '/bil/kona'

self.addEventListener('install', (event) => {
  self.skipWaiting()
})

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  )
})

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url)

  // Never cache: API proxy, login (session/auth), non-GET
  if (url.pathname.includes('/api-proxy/') || url.pathname === '/login' || event.request.method !== 'GET') {
    return
  }

  // Only handle same-origin app assets
  if (url.origin !== self.location.origin) return

  event.respondWith(
    caches.open(CACHE).then(async (cache) => {
      const cached = await cache.match(event.request)
      const fetchPromise = fetch(event.request)
        .then((response) => {
          if (response.ok) cache.put(event.request, response.clone())
          return response
        })
        .catch(() => cached)
      return cached || fetchPromise
    })
  )
})
