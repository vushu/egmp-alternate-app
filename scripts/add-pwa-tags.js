#!/usr/bin/env node
// Post-export step: inject PWA tags into every generated .html file.
// The static export pipeline doesn't use app/+html.tsx, so we patch the
// output directly. Run after `npx expo export --platform web`.

const fs = require('fs')
const path = require('path')

const DIST = path.join(__dirname, '..', 'dist')
const BASE_PATH = process.env.BLUEWINK_BASE_PATH?.trim().replace(/\/+$/, '') || ''

const TAGS = `  <!-- PWA -->
  <link rel="manifest" href="/manifest.json" />
  <meta name="theme-color" content="#0c2340" />
  <meta name="apple-mobile-web-app-capable" content="yes" />
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
  <link rel="apple-touch-icon" href="/icon-192.png" />
`

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) walk(full)
    else if (entry.name.endsWith('.html')) {
      let html = fs.readFileSync(full, 'utf8')
      if (html.includes('rel="manifest"')) continue // already patched
      // iPhone notch/Dynamic Island: extend web content into safe areas
      html = html.replace(
        'name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"',
        'name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no, viewport-fit=cover"'
      )
      // iOS safe areas + themed background behind the status bar
      html = html.replace(
        '</head>',
        `  <style>
    html { padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left); }
    body { background-color: #FAF9FD; }
    @media (prefers-color-scheme: dark) { body { background-color: #111318; } }
  </style>
</head>`
      )
      html = html.replace('</head>', TAGS + '  </head>')
      fs.writeFileSync(full, html)
      console.log('patched', path.relative(DIST, full))
    }
  }
}

walk(DIST)

// Substitute the base path into the manifest (start_url/scope) and service worker
const manifestPath = path.join(DIST, 'manifest.json')
if (fs.existsSync(manifestPath)) {
  let manifest = fs.readFileSync(manifestPath, 'utf8')
  manifest = manifest.replaceAll('__BASE_PATH__', BASE_PATH || '/')
  fs.writeFileSync(manifestPath, manifest)
  console.log('manifest base path set to:', BASE_PATH || '/')
}

const swPath = path.join(DIST, 'sw.js')
if (fs.existsSync(swPath)) {
  let sw = fs.readFileSync(swPath, 'utf8')
  sw = sw.replaceAll('__BASE_PATH__', BASE_PATH || '/')
  fs.writeFileSync(swPath, sw)
  console.log('service worker base path set to:', BASE_PATH || '/')
}

console.log('PWA tags injected.')
