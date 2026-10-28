// Local dev proxy for web platform — manufacturer APIs send no CORS headers,
// so browser requests are blocked. This proxy forwards requests and adds the
// missing Access-Control-Allow-* headers on responses.
//
// Usage: npx tsx scripts/dev-proxy.ts  (defaults to port 8788)
// On web, the app automatically routes API calls through http://localhost:8788.

import * as http from 'http'
import * as https from 'https'
import * as url from 'url'

const PORT = Number(process.env.PORT || 8788)

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

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url || '/', true)
  const origin = req.headers.origin

  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders(origin))
    res.end()
    return
  }

  // Expected path format: /<host>[:port]/<rest-of-path>
  const parts = parsed.pathname!.replace(/^\/+/, '').split('/')
  const hostWithPort = parts[0]
  const rest = '/' + parts.slice(1).join('/') + (parsed.search || '')

  if (!hostWithPort || !ALLOWED_HOSTS.has(hostWithPort)) {
    res.writeHead(403, { 'Content-Type': 'application/json', ...corsHeaders(origin) })
    res.end(JSON.stringify({ error: `Host not allowed: ${hostWithPort || '(none)'}` }))
    return
  }

  const [host, portStr] = hostWithPort.split(':')
  const port = portStr ? Number(portStr) : 443

  // Collect request headers, dropping hop-by-hop ones
  const headers = { ...req.headers }
  delete headers.host
  delete headers.origin
  delete headers.referer
  delete headers['accept-encoding'] // avoid gzipped responses we don't decompress

  const options: https.RequestOptions = {
    host,
    port,
    path: rest,
    method: req.method,
    headers,
  }

  const upstream = https.request(options, (upstreamRes) => {
    const respHeaders = { ...upstreamRes.headers }
    delete respHeaders['transfer-encoding'] // we re-chunk via Node
    res.writeHead(upstreamRes.statusCode || 502, { ...respHeaders, ...corsHeaders(origin) })
    upstreamRes.pipe(res)
  })

  upstream.on('error', (err) => {
    console.error(`[proxy] upstream error for ${host}${rest}: ${err.message}`)
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json', ...corsHeaders(origin) })
    }
    res.end(JSON.stringify({ error: `Upstream error: ${err.message}` }))
  })

  req.pipe(upstream)
})

server.listen(PORT, () => {
  console.log(`[dev-proxy] CORS proxy listening on http://localhost:${PORT}`)
  console.log('[dev-proxy] Allowed hosts:')
  for (const h of ALLOWED_HOSTS) console.log(`  - ${h}`)
})

export { server }
