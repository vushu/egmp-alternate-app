// Production CORS proxy for self-hosted web deployments.
//
// Serves the static web build (from dist/) and proxies /api-proxy/<host>/<path>
// to the manufacturer APIs, adding the CORS headers browsers require.
//
// Usage:
//   npx expo export --platform web     # builds static site into dist/
//   npx tsx scripts/serve-web.ts       # serves on PORT (default 3000)
//
// To enable password protection, generate a scrypt hash and pass it:
//   node -e "const c=require('crypto');const s=c.randomBytes(16);console.log(c.scryptSync(process.argv[1],s,64).toString('hex')+':'+s.toString('hex'))" 'YOUR_PASSWORD'
//   BLUEWINK_PASSWORD_HASH=<output> npx tsx scripts/serve-web.ts
//
// Security notes:
//   - Host allowlist: only manufacturer API hosts can be proxied.
//   - Optional password protection: set BLUEWINK_PASSWORD_HASH (scrypt,
//     format "<hex>:<hex-salt>") to require login before anything is
//     served. Sessions use signed httpOnly cookies; login is rate-limited.
//   - Bind to localhost behind a reverse proxy (nginx/caddy) with TLS,
//     or expose directly if you accept plain HTTP on a private network.
//   - The app stores credentials in the browser's localStorage (web
//     platform limitation) — only host this where you trust the machine
//     and network, ideally for personal use only.

import * as http from 'http'
import * as https from 'https'
import * as fs from 'fs'
import * as path from 'path'
import * as crypto from 'crypto'
import { URL } from 'url'

const PORT = Number(process.env.PORT || 3000)
const DIST_DIR = path.join(__dirname, '..', 'dist')

// Password protection (optional). Hash format: "<scrypt-hex>:<salt-hex>"
const PASSWORD_HASH = process.env.BLUEWINK_PASSWORD_HASH
const SESSION_SECRET = process.env.BLUEWINK_SESSION_SECRET || crypto.randomBytes(32).toString('hex')
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000 // 30 days
const LOGIN_RATE_LIMIT = 5 // attempts
const LOGIN_RATE_WINDOW_MS = 15 * 60 * 1000 // per 15 min

const sessions = new Map<string, number>() // token -> expiry
const loginAttempts = new Map<string, { count: number; first: number }>()

function verifyPassword(password: string): boolean {
  if (!PASSWORD_HASH) return false
  const [hashHex, saltHex] = PASSWORD_HASH.split(':')
  if (!hashHex || !saltHex) return false
  const hash = Buffer.from(hashHex, 'hex')
  const salt = Buffer.from(saltHex, 'hex')
  const derived = crypto.scryptSync(password, salt, hash.length)
  return crypto.timingSafeEqual(hash, derived)
}

function createSession(): string {
  const token = crypto.randomBytes(32).toString('hex')
  sessions.set(token, Date.now() + SESSION_TTL_MS)
  return token
}

function isValidSession(token: string | undefined): boolean {
  if (!token) return false
  const expiry = sessions.get(token)
  if (!expiry) return false
  if (Date.now() > expiry) {
    sessions.delete(token)
    return false
  }
  return true
}

function getCookie(req: http.IncomingMessage, name: string): string | undefined {
  const cookies = req.headers.cookie
  if (!cookies) return undefined
  for (const part of cookies.split(';')) {
    const [k, ...v] = part.trim().split('=')
    if (k === name) return v.join('=')
  }
  return undefined
}

function isRateLimited(clientIp: string): boolean {
  const now = Date.now()
  const entry = loginAttempts.get(clientIp)
  if (!entry || now - entry.first > LOGIN_RATE_WINDOW_MS) {
    loginAttempts.set(clientIp, { count: 1, first: now })
    return false
  }
  entry.count++
  return entry.count > LOGIN_RATE_LIMIT
}

function parseBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = ''
    req.on('data', (chunk) => {
      body += chunk
      if (body.length > 10_000) req.destroy() // sanity cap
    })
    req.on('end', () => resolve(body))
    req.on('error', () => resolve(''))
  })
}

function serveLoginPage(res: http.ServerResponse, error = '') {
  res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' })
  res.end(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bluewink — Login</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; background: #111318; color: #E2E2E9;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  form { background: #1D2024; padding: 32px; border-radius: 20px; display: flex; flex-direction: column; gap: 16px; width: 320px; }
  h1 { font-size: 20px; margin: 0; text-align: center; }
  input { background: #272A2F; color: #E2E2E9; border: 1px solid #44474F; border-radius: 8px;
          padding: 12px; font-size: 16px; }
  button { background: #B0C6FF; color: #002E69; border: none; border-radius: 100px;
           padding: 12px; font-size: 16px; font-weight: 600; cursor: pointer; }
  .err { color: #FFB4AB; font-size: 14px; text-align: center; min-height: 18px; }
</style></head>
<body><form method="POST" action="/login">
  <h1>Bluewink</h1>
  <input type="password" name="password" placeholder="Password" autofocus>
  <div class="err">${error}</div>
  <button type="submit">Sign in</button>
</form></body></html>`)
}

function handleLogin(req: http.IncomingMessage, res: http.ServerResponse) {
  const clientIp = req.socket.remoteAddress || 'unknown'
  if (isRateLimited(clientIp)) {
    res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end('<h1>Too many attempts</h1><p>Try again in 15 minutes.</p>')
    return
  }
  parseBody(req).then((body) => {
    const params = new URLSearchParams(body)
    const password = params.get('password') || ''
    if (verifyPassword(password)) {
      const token = createSession()
      res.writeHead(303, {
        'Set-Cookie': `bluewink_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}`,
        Location: '/',
      })
      res.end()
    } else {
      serveLoginPage(res, 'Wrong password')
    }
  })
}

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

// Base path the web export was built with (BLUEWINK_BASE_PATH at export time).
// The export writes assets to dist/ root but references them under this prefix.
// Defaults to "/" (no prefix) for backward compatibility.
const BASE_PATH = (process.env.BLUEWINK_BASE_PATH?.trim().replace(/\/+$/, '') || '')

function serveStatic(req: http.IncomingMessage, res: http.ServerResponse, pathname: string) {
  // Strip the base path prefix so /<base>/_expo/... maps to dist/_expo/...
  let diskPath = pathname
  if (BASE_PATH && diskPath.startsWith(BASE_PATH)) {
    diskPath = diskPath.slice(BASE_PATH.length) || '/'
  }
  let filePath = path.join(DIST_DIR, diskPath === '/' ? 'index.html' : diskPath)
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

  // Password protection: everything (static files AND the API proxy)
  // requires a valid session when BLUEWINK_PASSWORD_HASH is set.
  if (PASSWORD_HASH) {
    if (url.pathname === '/login') {
      if (req.method === 'POST') {
        handleLogin(req, res)
        return
      }
      serveLoginPage(res)
      return
    }
    if (!isValidSession(getCookie(req, 'bluewink_session'))) {
      if (url.pathname.startsWith('/api-proxy/')) {
        // API calls get a JSON 401, not the login page
        res.writeHead(401, { 'Content-Type': 'application/json', ...corsHeaders(origin) })
        res.end(JSON.stringify({ error: 'Authentication required' }))
        return
      }
      serveLoginPage(res)
      return
    }
  }

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
  console.log(PASSWORD_HASH ? '[serve-web] password protection: ENABLED' : '[serve-web] password protection: disabled (set BLUEWINK_PASSWORD_HASH to enable)')
})
