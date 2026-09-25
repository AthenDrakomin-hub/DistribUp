# DistribUp Sign Sidecar (VPS)

Runs on your Vultr box. This is the component that actually re-signs IPA on demand.

## What it does

When a user scans the install QR:
1. Cloudflare Worker calls this service with `{ udid, ipaUrl, bundleId }`
2. This service registers the UDID via App Store Connect API
3. Downloads the raw IPA from R2
4. Runs `zsign` with your p12 cert + mobileprovision
5. Uploads the signed IPA back to R2
6. Returns the public R2 URL

## Prerequisites on the VPS

### 1. Install zsign

```bash
# Ubuntu 24.04
apt update && apt install -y build-essential libssl-dev
git clone https://github.com/zhlynn/zsign.git /tmp/zsign
cd /tmp/zsign && make && cp zsign /usr/local/bin/
zsign --help  # verify
```

### 2. Place signing materials

```bash
mkdir -p /opt/sign
# scp these from your machine:
#   cert.p12
#   profile.mobileprovision
#   AuthKey_XXXXXXXXXX.p8   (App Store Connect API key)
chmod 600 /opt/sign/*
```

### 3. Install this service

```bash
mkdir -p /opt/sign-server
# copy index.js, package.json from this directory
cd /opt/sign-server
npm install --production
cp .env.example .env
# edit .env with your real values
```

### 4. systemd

```bash
cp distribup-sign.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now distribup-sign
systemctl status distribup-sign   # should be active
curl http://localhost:3001/health  # {"ok":true}
```

### 5. Open firewall (if needed)

The Worker needs to reach `http://45.77.31.155:3001`. Vultr default firewall should allow outbound.
For inbound, either open port 3001 or put nginx in front with HTTPS.

**Recommended**: put nginx with HTTPS in front, then set `SIGNSERVER_URL = https://sign.yourdomain.com`.

## Environment variables

See `.env.example`. Required:

- `SHARED_SECRET` — random long string; Workers must send the same value in `x-sign-secret` header
- `ASC_ISSUER_ID`, `ASC_KEY_ID`, `ASC_PRIVATE_KEY` — Apple Developer API
- `P12_PATH`, `P12_PASSWORD`, `MOBILEPROVISION_PATH` — signing materials
- `R2_*` — R2 S3 credentials for uploading signed IPA back

## Smoke test

```bash
curl -X POST http://localhost:3001/sign \
  -H "x-sign-secret: YOUR_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"udid":"TESTUDID123","ipaUrl":"https://dl.yourdomain.com/raw.ipa","bundleId":"com.example.app"}'
```

Should return `{"ok":true,"signedUrl":"https://dl.yourdomain.com/signed/..."}`.

## Full flow

```
User scans QR
  -> Cloudflare Worker: GET /api/install/:appId/online-sign?udid=xxx
  -> Worker fetches this VPS: POST /sign
  -> VPS: register UDID -> download IPA -> zsign -> upload R2
  -> Worker builds manifest.plist pointing at signed IPA
  -> Worker returns HTML page with itms-services:// link
  -> User taps link, iOS installs the re-signed IPA
```
