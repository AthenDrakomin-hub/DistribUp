// DistribUp sign sidecar — runs on your VPS.
// Pipeline: download raw IPA -> register UDID via ASC API -> zsign -> upload to R2 -> return public URL.

import express from 'express';
import { execFile } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import https from 'https';
import AWS from 'aws-sdk';

const execFileAsync = promisify(execFile);

const app = express();
app.use(express.json({ limit: '1mb' }));

// ─── Minimal env: only connection + shared secret ────────────────────────────
const PORT = process.env.PORT || 3001;
const SHARED_SECRET = process.env.SHARED_SECRET;
const WORKER_URL = process.env.WORKER_URL; // e.g. https://distribup.xxx.workers.dev
const ZSIGN_PATH = process.env.ZSIGN_PATH || '/usr/local/bin/zsign';

if (!SHARED_SECRET || !WORKER_URL) {
  console.error('ERROR: SHARED_SECRET and WORKER_URL must be set in .env');
  process.exit(1);
}

// Pulled config (populated on startup + refreshed every 10 min)
let cfg = null;
const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sign-cfg-'));

async function pullConfig() {
  const res = await fetch(`${WORKER_URL}/api/vps/signing-config`, {
    headers: { 'x-sign-secret': SHARED_SECRET }
  });
  if (!res.ok) throw new Error('Failed to pull config: HTTP ' + res.status);
  const c = await res.json();

  // Write materials to temp files
  const p8File = path.join(workDir, 'AuthKey.p8');
  const p12File = path.join(workDir, 'cert.p12');
  const provFile = path.join(workDir, 'profile.mobileprovision');

  if (c.asc_p8_path_content) fs.writeFileSync(p8File, c.asc_p8_path_content);
  if (c.p12_path_content) fs.writeFileSync(p12File, Buffer.from(c.p12_path_content, 'base64'));
  if (c.mobileprovision_path_content) fs.writeFileSync(provFile, Buffer.from(c.mobileprovision_path_content, 'base64'));

  cfg = {
    ascIssuerId: c.asc_issuer_id,
    ascKeyId: c.asc_key_id,
    ascP8Path: p8File,
    p12Path: p12File,
    p12Password: c.p12_password,
    provisionPath: provFile,
    r2PublicBase: c.r2_public_base
  };
  console.log('Config pulled: issuer=' + cfg.ascIssuerId + ' key=' + cfg.ascKeyId);
}

// Initial pull
await pullConfig();
setInterval(pullConfig, 10 * 60 * 1000);

// ─── Apple ASC JWT (ES256) ───────────────────────────────────────────────────
let cachedToken = null;
let tokenExpiry = 0;

async function getAscToken() {
  if (cachedToken && Date.now() < tokenExpiry) return cachedToken;

  const privateKey = fs.readFileSync(cfg.ascP8Path, 'utf8');

  const header = { alg: 'ES256', kid: cfg.ascKeyId, typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = { iss: cfg.ascIssuerId, iat: now, exp: now + 1199, aud: 'appstoreconnect-v1' };

  const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const data = `${b64(header)}.${b64(payload)}`;

  const key = await crypto.subtle.importKey(
    'pkcs8', Buffer.from(privateKey),
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('ECDSA', key, new TextEncoder().encode(data));
  // ASN.1 DER -> raw R||S for JWT
  const der = Buffer.from(sig);
  const r = der.slice(4, 4 + der[3]).toString('hex').padStart(64, '0');
  const s = der.slice(4 + der[3] + 2).toString('hex').padStart(64, '0');
  const rawSig = Buffer.from(r + s, 'hex').toString('base64url');

  cachedToken = `${data}.${rawSig}`;
  tokenExpiry = Date.now() + 20 * 60 * 1000;
  return cachedToken;
}

async function ascFetch(path, method = 'GET', body) {
  const token = await getAscToken();
  const res = await fetch(`https://api.appstoreconnect.apple.com${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: body ? JSON.stringify(body) : undefined
  });
  return res.json();
}

async function ensureDeviceRegistered(udid, name) {
  // Check if already registered
  const existing = await ascFetch(`/v1/devices?filter[udid]=${udid}`);
  if (existing.data && existing.data.length > 0) {
    return { already: true, id: existing.data[0].id };
  }
  // Register
  const created = await ascFetch('/v1/devices', 'POST', {
    data: {
      type: 'devices',
      attributes: { name: name || udid.slice(0, 10), udid, platform: 'IOS' }
    }
  });
  if (!created.data) throw new Error('ASC device registration failed: ' + JSON.stringify(created.errors));
  return { already: false, id: created.data.id };
}

// ─── R2 upload (S3 creds stay in .env; public base comes from web config) ─────
const s3 = new AWS.S3({
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  accessKeyId: process.env.R2_ACCESS_KEY_ID,
  secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  region: 'auto',
  signatureVersion: 'v4'
});
const R2_BUCKET = process.env.R2_BUCKET || 'distribup-files';

async function uploadToR2(localPath, objectKey) {
  const body = fs.readFileSync(localPath);
  await s3.upload({
    Bucket: R2_BUCKET,
    Key: objectKey,
    Body: body,
    ContentType: 'application/octet-stream'
  }).promise();
  return `${cfg.r2PublicBase}/${objectKey}`;
}

// ─── Download helper ─────────────────────────────────────────────────────────
async function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destPath);
    const doReq = (u) => {
      https.get(u, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          file.close();
          fs.unlinkSync(destPath);
          return doReq(res.headers.location);
        }
        if (res.statusCode !== 200) {
          file.close();
          return reject(new Error(`Download failed: HTTP ${res.statusCode}`));
        }
        res.pipe(file);
        file.on('finish', () => { file.close(); resolve(destPath); });
      }).on('error', reject);
    };
    doReq(url);
  });
}

// ─── Auth middleware ──────────────────────────────────────────────────────────
function auth(req, res, next) {
  if (req.get('x-sign-secret') !== SHARED_SECRET) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

// ─── Health ───────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// ─── Sign endpoint ───────────────────────────────────────────────────────────
app.post('/sign', auth, async (req, res) => {
  const { udid, ipaUrl, bundleId, version } = req.body;
  if (!udid || !ipaUrl) return res.status(400).json({ error: 'udid and ipaUrl required' });

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sign-'));
  const rawIpa = path.join(workDir, 'input.ipa');
  const signedIpa = path.join(workDir, 'signed.ipa');

  try {
    console.log(`[${new Date().toISOString()}] sign request: udid=${udid} ipa=${ipaUrl}`);

    // 1. Register UDID
    await ensureDeviceRegistered(udid, `device-${Date.now()}`);

    // 2. Download raw IPA
    console.log('  downloading IPA...');
    await downloadFile(ipaUrl, rawIpa);

    // 3. Run zsign
    console.log('  running zsign...');
    await execFileAsync(ZSIGN_PATH, [
      '-k', cfg.p12Password,
      '-p', cfg.p12Path,
      '-m', cfg.provisionPath,
      '-o', signedIpa,
      rawIpa
    ], { maxBuffer: 1024 * 1024 * 512 });

    // 4. Upload signed IPA to R2
    const objectKey = `signed/${bundleId || 'app'}/${version || 'v1'}/${udid}.ipa`;
    console.log('  uploading to R2 as', objectKey);
    const publicUrl = await uploadToR2(signedIpa, objectKey);

    res.json({ ok: true, signedUrl: publicUrl });
  } catch (err) {
    console.error('  sign failed:', err.message);
    res.status(500).json({ error: err.message });
  } finally {
    // Cleanup
    fs.rmSync(workDir, { recursive: true, force: true });
  }
});

app.listen(PORT, () => {
  console.log(`DistribUp sign server listening on :${PORT}`);
  console.log(`  zsign: ${ZSIGN_PATH}`);
  console.log(`  worker: ${WORKER_URL}`);
});
