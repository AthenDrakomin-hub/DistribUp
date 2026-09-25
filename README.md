# DistribUp

Enterprise iOS/Android app distribution platform running on Cloudflare Workers.

- **Workers** — edge runtime, no server to manage
- **D1** — SQLite database for users, teams, apps, devices, uploads
- **R2** — object storage for IPA/APK binaries

## Project layout

```
├── src/workers/index.ts      # Worker entry (all routes, JWT, pbkdf2 hashing)
├── public/*.html             # Frontend pages (inlined as base64 at build time)
├── scripts/embed-html.cjs    # Build step: public/*.html → base64 in index.ts
├── migrations/001_init.sql   # D1 schema
└── wrangler.toml             # Workers bindings and vars
```

## Deploy

### 1. Install & login

```bash
npm install
npx wrangler login
```

### 2. Create cloud resources

```bash
npx wrangler d1 create distribup-db
# Copy the returned database_id into wrangler.toml

npx wrangler r2 bucket create distribup-files
```

### 3. Run migrations

```bash
npm run db:migrate
```

### 4. Set secrets

```bash
npx wrangler secret put JWT_SECRET
# Paste a 64-char random hex string
```

Optionally set `ASC_ISSUER_ID`, `ASC_KEY_ID`, `ASC_PRIVATE_KEY` for App Store Connect auto device registration.

### 5. Create the first admin (no public signup)

Public registration is disabled — this is a private instance. Generate a password hash:

```bash
node scripts/hash-password.cjs YourStrongPassword
```

Copy the printed SQL and run it against D1:

```bash
npx wrangler d1 execute distribup-db --remote --command "INSERT INTO teams (name) VALUES ('Default');"
npx wrangler d1 execute distribup-db --remote --command "INSERT INTO users (username, email, password_hash, role, team_id, is_active) VALUES ('admin', 'you@example.com', '<hash-from-script>', 'admin', 1, 1);"
```

### 6. Deploy

```bash
npm run deploy
```

Visit `https://<your-worker>.workers.dev/login.html` and sign in.

## Local dev

```bash
npm run build     # rebuild base64 HTML constants after editing public/*.html
npm run dev       # wrangler dev on http://localhost:8788
```

## Free tier limits

| Resource | Free quota |
|---|---|
| Workers | 100k requests/day |
| D1 | 50k reads / 1k writes per day |
| R2 | 10 GB storage, 1M reads/month |

## Notes

- iOS OTA install requires HTTPS and a valid manifest; Android uses direct download links.
- Actual IPA/APK signing (zsign, apksigner) cannot run on Workers — sign locally or via a sidecar service, then upload the signed binary.
