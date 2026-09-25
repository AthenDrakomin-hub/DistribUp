# DistribUp

Self-hosted iOS/Android app distribution with on-demand re-signing (super-signature flow).

- **Cloudflare Workers** — frontend, API, links, no server to manage
- **D1** — SQLite database
- **R2** — IPA/APK storage (free egress)
- **VPS sidecar** — zsign re-signing engine on your own Vultr box

## Architecture

```
User scans QR
  -> Cloudflare Worker: GET /api/install/:appId/online-sign?udid=xxx
  -> Worker calls VPS: POST http://vps:3001/sign
  -> VPS: register UDID via ASC API -> download IPA from R2 -> zsign -> upload signed IPA to R2
  -> Worker writes manifest.plist to R2
  -> User taps itms-services:// link, iOS installs re-signed IPA
```

## Prerequisites

1. Cloudflare account (free tier works)
2. Vultr VPS (Ubuntu 24.04) with zsign installed
3. Apple Developer account ($99/yr) with:
   - App Store Connect API key (.p8, Issuer ID, Key ID)
   - iOS signing certificate (.p12 + password)
   - mobileprovision profile
4. R2 bucket with a public custom domain (e.g. `dl.yourdomain.com`)

## Step 1 — Cloudflare Workers

```bash
git clone https://github.com/AthenDrakomin-hub/DistribUp.git
cd DistribUp
npm install
npx wrangler login

# Create D1
npx wrangler d1 create distribup-db
# Copy the database_id into wrangler.toml

# Create R2 bucket
npx wrangler r2 bucket create distribup-files
# In Cloudflare Dashboard: R2 -> bucket -> Settings -> bind public custom domain (dl.yourdomain.com)

# Run migrations
npm run db:migrate

# Set secrets
npx wrangler secret put JWT_SECRET
npx wrangler secret put SIGNSERVER_SECRET   # same value as VPS .env SHARED_SECRET

# Edit wrangler.toml: set R2_PUBLIC_BASE, BASE_URL, SIGNSERVER_URL
npm run deploy
```

## Step 2 — First admin

```bash
node scripts/hash-password.cjs YourStrongPassword
# Run the printed SQL in D1:
npx wrangler d1 execute distribup-db --remote --command "INSERT INTO teams (name) VALUES ('Default');"
npx wrangler d1 execute distribup-db --remote --command "INSERT INTO users (username,email,password_hash,role,team_id,is_active) VALUES ('admin','you@example.com','<HASH>','admin',1,1);"
```

## Step 3 — VPS sign sidecar

```bash
# Install zsign
apt update && apt install -y build-essential libssl-dev
git clone https://github.com/zhlynn/zsign.git /tmp/zsign
cd /tmp/zsign && make && cp zsign /usr/local/bin/

# Deploy service
mkdir -p /opt/sign-server
# scp vps-sign-server/{index.js,package.json} to /opt/sign-server/
cd /opt/sign-server && npm install --production
cp .env.example .env
# Edit .env: PORT, SHARED_SECRET, WORKER_URL, R2 creds

# systemd
cp distribup-sign.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now distribup-sign
curl http://localhost:3001/health
```

## Step 4 — Configure signing materials via web

1. Open `https://<your-worker>.workers.dev/login.html`, sign in as admin
2. Go to **Settings** → **iOS Signing Materials**
3. Fill in: ASC Issuer ID, ASC Key ID, R2 Public Base, p12 password
4. Upload: `.p12`, `.mobileprovision`, `.p8`
5. Click **Save**

The VPS pulls this config automatically every 10 minutes.

## Step 5 — Use it

1. **Apps** → New App (iOS)
2. Click **Upload** → pick your unsigned IPA
3. Give users the install link: `https://<worker>/api/install/<appId>/online-sign?udid=<DEVICE_UDID>`
4. User opens it in Safari → taps install → VPS re-signs on the fly → installed

For Android: upload APK, give the direct R2 link. No signing needed.

## Files

```
├── src/workers/index.ts          # Worker (all routes, JWT, D1, R2)
├── public/                       # HTML pages (inlined as base64 at build)
├── migrations/001_init.sql      # D1 schema (9 tables)
├── scripts/embed-html.cjs        # build: HTML → base64
├── scripts/hash-password.cjs     # bootstrap admin password
├── vps-sign-server/              # zsign sidecar (deploy on your VPS)
│   ├── index.js
│   ├── package.json
│   ├── distribup-sign.service
│   └── .env.example
└── wrangler.toml
```
