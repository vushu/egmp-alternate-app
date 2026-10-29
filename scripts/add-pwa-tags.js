#!/usr/bin/env node
// Post-export step: inject PWA tags into every generated .html file.
// The static export pipeline doesn't use app/+html.tsx, so we patch the
// output directly. Run after `npx expo export --platform web`.

const fs = require('fs')
const path = require('path')

const DIST = path.join(__dirname, '..', 'dist')
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
      html = html.replace('</head>', TAGS + '  </head>')
      fs.writeFileSync(full, html)
      console.log('patched', path.relative(DIST, full))
    }
  }
}

walk(DIST)
console.log('PWA tags injected.')
