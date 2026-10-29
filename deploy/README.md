# Deploying Bluewink on your own server

The app runs as a Node server (static files + manufacturer API proxy) behind
nginx with TLS. Everything lives under `/bil/kona` on your domain.

## 1. Get the code and build

```bash
git clone git@github.com:vushu/egmp-alternate-app.git /opt/egmp-alternate-app
cd /opt/egmp-alternate-app
npm install
npx expo export --platform web        # builds dist/ with /bil/kona baked in
```

## 2. Generate secrets

```bash
# Password hash (users must enter this to open the app):
node -e "const c=require('crypto');const s=c.randomBytes(16);console.log(c.scryptSync(process.argv[1],s,64).toString('hex')+':'+s.toString('hex'))" 'YOUR_PASSWORD'

# Session secret (keeps logins valid across restarts):
openssl rand -hex 32
```

## 3. Run the server in the background (systemd)

```bash
sudo cp deploy/bluewink.service /etc/systemd/system/bluewink.service
# Edit it: set WorkingDirectory, BLUEWINK_PASSWORD_HASH, BLUEWINK_SESSION_SECRET
sudo nano /etc/systemd/system/bluewink.service

sudo systemctl daemon-reload
sudo systemctl enable --now bluewink     # start now + on boot

systemctl status bluewink                # verify it's running
journalctl -u bluewink -f                # tail logs (Ctrl-C to exit)
```

The server listens on `127.0.0.1:3000` — only nginx talks to it.

## 4. nginx + TLS

```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/bluewink
sudo nano /etc/nginx/sites-available/bluewink   # set your domain (2 places)
sudo ln -s /etc/nginx/sites-available/bluewink /etc/nginx/sites-enabled/

# Get a free Let's Encrypt certificate (also sets up the HTTP→HTTPS redirect):
sudo certbot --nginx -d your-domain.dk

sudo nginx -t && sudo systemctl reload nginx
```

Open **https://your-domain.dk/bil/kona** — you should see the login page.

## 5. Updating the app later

```bash
cd /opt/egmp-alternate-app
git pull
npm install
npx expo export --platform web
sudo systemctl restart bluewink
```

## Troubleshooting

| Symptom | Check |
|---|---|
| 502 Bad Gateway | `systemctl status bluewink` — is the Node server up? |
| Login page loops | `X-Real-IP` header missing in nginx config (rate limiter miscounts) |
| Assets 404 | Did you run `npx expo export --platform web` after the last `git pull`? |
| API calls fail | `journalctl -u bluewink` — look for upstream errors |
| Wrong base path | `BLUEWINK_BASE_PATH` env var must match `experiments.baseUrl` in app.json |

## Security notes

- The password hash and session secret live only in the systemd unit file —
  never commit them
- Only `/bil/kona` and `/api-proxy/` are exposed; everything else 404s
- The API proxy only forwards to a hardcoded allowlist of manufacturer hosts
- On web, credentials are stored in the browser's localStorage — use a
  device/browser profile you control
