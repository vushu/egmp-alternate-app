// Production CORS proxy for self-hosted web deployments.
//
// Serves the static web build (from dist/) and proxies /api-proxy/<host>/<path>
// to the manufacturer APIs, adding the CORS headers browsers require.
//
// Usage:
//   npx expo export --platform web     # builds static site into dist/
//   npx tsx scripts/serve-web.ts       # serves on PORT (default 3000)
//
// Security notes:
//   - Host allowlist: only manufacturer API hosts can be proxied.
//   - Bind to localhost behind a reverse proxy (nginx/caddy) with TLS,
//     or expose directly if you accept plain HTTP on a private network.
//   - The app stores credentials in the browser's localStorage (web
//     platform limitation) — only host this where you trust the machine
//     and network, ideally for personal use only.

import * as http from 'http'
import * as https from 'https'
import * as fs from 'fs'
import * as path from 'path'
import { URL } from 'url'

const PORT = Number(process.env.PORT || 3000)
const DIST_DIR = path.join(__dirname, '..', 'dist')

const ALLOWED_HOSTS = new Set([
  // Europe
  'prd.eu-ccapi.hyundai.com',
  'prd.eu-ccapi.hyundai.com:8080',
  'idpconnect-eu.hyundai.com',
  'prd.eu-ccapi.kia.com',
  'prd.eu-ccapi.kia.com:8080',
  'idpconnect-eu.kia.com',
  'cci-api-eu.kia.com',
  // Canada
  'mybluelink.ca',
  'kiaconnect.ca',
  'genesisconnect.ca',
  // USA
  'api.telematics.hyundaiusa.com',
  'api.owners.kia.com',
  // India
  'api.kia.com',
  // Australia
  'au.api.acms.mykia.com.au',
  'au.api.acms.apps.hyundai.com.au',
])

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.map': 'application/json',
  '.txt': 'text/plain; charset=utf-8',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
}

function corsHeaders(origin: string | undefined): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, HEAD',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Expose-Headers': '*',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  }
}

function serveStatic(req: http.IncomingMessage, res: http.ServerResponse, pathname: string) {
  let filePath = path.join(DIST_DIR, pathname === '/' ? 'index.html' : pathname)
  // Prevent path traversal
  if (!path.resolve(filePath).startsWith(path.resolve(DIST_DIR))) {
    res.writeHead(403)
    res.end('Forbidden')
    return
  }
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    // SPA fallback: serve index.html for unknown routes
    filePath = path.join(DIST_DIR, 'index.html')
    if (!fs.existsSync(filePath)) {
      res.writeHead(404, { 'Content-Type': 'text/plain' })
      res.end('dist/ not found — run: npx expo export --platform web')
      return
    }
  }
  const ext = path.extname(filePath).toLowerCase()
  const mime = MIME_TYPES[ext] || 'application/octet-stream'
  res.writeHead(200, { 'Content-Type': mime })
  fs.createReadStream(filePath).pipe(res)
}

function proxyApi(req: http.IncomingMessage, res: http.ServerResponse, origin: string | undefined, search: URL['search']) {
  const url = new URL(req.url || '/', 'http://localhost')
  const parts = url.pathname.replace(/^\/+api-proxy\/+/, '').split('/')
  const hostWithPort = parts[0]
  const rest = '/' + parts.slice(1).join('/') + (search || '')

  if (!hostWithPort || !ALLOWED_HOSTS.has(hostWithPort)) {
    res.writeHead(403, { 'Content-Type': 'application/json', ...corsHeaders(origin) })
    res.end(JSON.stringify({ error: `Host not allowed: ${hostWithPort || '(none)'}` }))
    return
  }

  const [host, portStr] = hostWithPort.split(':')
  const port = portStr ? Number(portStr) : 443

  const headers = { ...req.headers }
  delete headers.host
  delete headers.origin
  delete headers.referer
  delete headers['accept-encoding']

  const upstream = https.request(
    { host, port, path: rest, method: req.method, headers },
    (upstreamRes) => {
      const respHeaders = { ...upstreamRes.headers }
      delete respHeaders['transfer-encoding']
      res.writeHead(upstreamRes.statusCode || 502, { ...respHeaders, ...corsHeaders(origin) })
      upstreamRes.pipe(res)
    }
  )

  upstream.on('error', (err) => {
    console.error(`[serve-web] upstream error for ${host}${rest}: ${err.message}`)
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json', ...corsHeaders(origin) })
    }
    res.end(JSON.stringify({ error: `Upstream error: ${err.message}` }))
  })

  req.pipe(upstream)
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', 'http://localhost')
  const origin = req.headers.origin

  if (url.pathname.startsWith('/api-proxy/')) {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, corsHeaders(origin))
      res.end()
      return
    }
    proxyApi(req, res, origin, url.search)
    return
  }

  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders(origin))
    res.end()
    return
  }

  serveStatic(req, res, url.pathname)
})

server.listen(PORT, () => {
  console.log(`[serve-web] serving ${DIST_DIR} on http://localhost:${PORT}`)
  console.log(`[serve-web] API proxy at /api-proxy/<host>/<path> (${ALLOWED_HOSTS.size} allowed hosts)`)
})
