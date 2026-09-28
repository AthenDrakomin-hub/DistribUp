// DistribUp sign sidecar — runs on your VPS.
// Full super-sign pipeline:
//   1. Register UDID via App Store Connect API
//   2. Look up / create App ID (bundleId)
//   3. Look up development certificate
//   4. Create a NEW provisioning profile that includes this UDID
//   5. Download the fresh .mobileprovision
//   6. zsign with p12 + fresh profile
//   7. Upload signed IPA to R2
//   8. Return public signed URL

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

// ─── Env ──────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
const SHARED_SECRET = process.env.SHARED_SECRET;
const WORKER_URL = process.env.WORKER_URL;
const ZSIGN_PATH = process.env.ZSIGN_PATH || '/usr/local/bin/zsign';

if (!SHARED_SECRET || !WORKER_URL) {
  console.error('ERROR: SHARED_SECRET and WORKER_URL must be set in .env');
  process.exit(1);
}

// ─── Pulled config from Workers (p8, p12, r2 base) ──────────────────────────
let cfg = null;
const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sign-cfg-'));

async function pullConfig() {
  const res = await fetch(`${WORKER_URL}/api/vps/signing-config`, {
    headers: { 'x-sign-secret': SHARED_SECRET }
  });
  if (!res.ok) throw new Error('Failed to pull config: HTTP ' + res.status);
  const c = await res.json();

  const p8File = path.join(workDir, 'AuthKey.p8');
  const p12File = path.join(workDir, 'cert.p12');

  if (c.asc_p8_path_content) fs.writeFileSync(p8File, Buffer.from(c.asc_p8_path_content, 'base64').toString('utf8'));
  if (c.p12_path_content) fs.writeFileSync(p12File, Buffer.from(c.p12_path_content, 'base64'));

  cfg = {
    ascIssuerId: c.asc_issuer_id,
    ascKeyId: c.asc_key_id,
    ascP8Path: p8File,
    p12Path: p12File,
    p12Password: c.p12_password,
    r2PublicBase: c.r2_public_base
  };
  console.log('Config pulled: issuer=' + cfg.ascIssuerId + ' key=' + cfg.ascKeyId);
}

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
  const der = Buffer.from(sig);
  const r = der.slice(4, 4 + der[3]).toString('hex').padStart(64, '0');
  const s = der.slice(4 + der[3] + 2).toString('hex').padStart(64, '0');
  const rawSig = Buffer.from(r + s, 'hex').toString('base64url');
  cachedToken = `${data}.${rawSig}`;
  tokenExpiry = Date.now() + 20 * 60 * 1000;
  return cachedToken;
}

async function ascFetch(p, method = 'GET', body, raw = false) {
  const token = await getAscToken();
  const opts = {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`https://api.appstoreconnect.apple.com${p}`, opts);
  if (raw) return res;
  return res.json();
}

// ─── Cached ASC lookups ───────────────────────────────────────────────────────
let cachedCertId = null;
let bundleIdCache = {}; // bundleId -> ascId

async function getDevelopmentCertificateId() {
  if (cachedCertId) return cachedCertId;
  const data = await ascFetch('/v1/certificates?filter[certificateType]=IOS_DEVELOPMENT&limit=1');
  if (!data.data || data.data.length === 0) {
    throw new Error('No iOS Development certificate found in ASC. Create one at https://developer.apple.com/account/resources/certificates/list');
  }
  cachedCertId = data.data[0].id;
  console.log('  cached development certificate:', cachedCertId);
  return cachedCertId;
}

async function getOrCreateBundleId(bundleId) {
  if (bundleIdCache[bundleId]) return bundleIdCache[bundleId];
  // Look up
  const found = await ascFetch(`/v1/bundleIds?filter[identifier]=${encodeURIComponent(bundleId)}`);
  if (found.data && found.data.length > 0) {
    bundleIdCache[bundleId] = found.data[0].id;
    return found.data[0].id;
  }
  // Create
  const created = await ascFetch('/v1/bundleIds', 'POST', {
    data: {
      type: 'bundleIds',
      attributes: { name: bundleId, identifier: bundleId, platform: 'IOS' }
    }
  });
  if (!created.data) throw new Error('Failed to create BundleId: ' + JSON.stringify(created.errors));
  bundleIdCache[bundleId] = created.data.id;
  console.log('  created BundleId:', bundleId, '->', created.data.id);
  return created.data.id;
}

async function ensureDeviceRegistered(udid, name) {
  const existing = await ascFetch(`/v1/devices?filter[udid]=${udid}`);
  if (existing.data && existing.data.length > 0) {
    return existing.data[0].id;
  }
  const created = await ascFetch('/v1/devices', 'POST', {
    data: {
      type: 'devices',
      attributes: { name: name || ('dev-' + udid.slice(0, 8)), udid, platform: 'IOS' }
    }
  });
  if (!created.data) throw new Error('ASC device registration failed: ' + JSON.stringify(created.errors));
  console.log('  registered device:', udid);
  return created.data.id;
}

async function createProfile(profileName, bundleId, certId, deviceId) {
  // Create a new development profile scoped to this single device
  const created = await ascFetch('/v1/profiles', 'POST', {
    data: {
      type: 'profiles',
      attributes: { name: profileName, profileType: 'IOS_APP_DEVELOPMENT' },
      relationships: {
        bundleId: { data: { type: 'bundleIds', id: bundleId } },
        certificates: { data: [{ type: 'certificates', id: certId }] },
        devices: { data: [{ type: 'devices', id: deviceId }] }
      }
    }
  });
  if (!created.data) throw new Error('Failed to create profile: ' + JSON.stringify(created.errors));
  const profileId = created.data.id;
  const contentUrl = created.data.attributes.contentUrl;

  // Download the .mobileprovision (binary)
  const token = await getAscToken();
  const dl = await fetch(contentUrl, { headers: { Authorization: `Bearer ${token}` } });
  if (!dl.ok) throw new Error('Failed to download profile: HTTP ' + dl.status);
  const buf = Buffer.from(await dl.arrayBuffer());
  return { profileId, content: buf };
}

// ─── R2 upload ────────────────────────────────────────────────────────────────
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

async function uploadBufferToR2(buf, objectKey, contentType) {
  await s3.upload({
    Bucket: R2_BUCKET,
    Key: objectKey,
    Body: buf,
    ContentType: contentType || 'application/octet-stream'
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

// ─── Sign endpoint (the core pipeline) ────────────────────────────────────────
app.post('/sign', auth, async (req, res) => {
  const { udid, ipaUrl, bundleId, version, appName } = req.body;
  if (!udid || !ipaUrl) return res.status(400).json({ error: 'udid and ipaUrl required' });

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sign-'));
  const rawIpa = path.join(tmpDir, 'input.ipa');
  const signedIpa = path.join(tmpDir, 'signed.ipa');
  const profilePath = path.join(tmpDir, 'profile.mobileprovision');

  try {
    console.log(`[${new Date().toISOString()}] sign: udid=${udid} bundle=${bundleId}`);

    // 1. Register UDID
    console.log('  [1/6] registering UDID...');
    const deviceId = await ensureDeviceRegistered(udid, 'dev-' + Date.now());

    // 2. Resolve App ID
    console.log('  [2/6] resolving App ID...');
    const ascAppId = await getOrCreateBundleId(bundleId);

    // 3. Get development certificate
    console.log('  [3/6] getting certificate...');
    const certId = await getDevelopmentCertificateId();

    // 4. Create a fresh profile for this UDID
    console.log('  [4/6] creating provisioning profile...');
    const profileName = `distribup-${bundleId}-${udid.slice(0, 8)}-${Date.now()}`;
    const { content: profileBuf } = await createProfile(profileName, ascAppId, certId, deviceId);
    fs.writeFileSync(profilePath, profileBuf);

    // 5. Download raw IPA + zsign
    console.log('  [5/6] downloading IPA and running zsign...');
    await downloadFile(ipaUrl, rawIpa);

    await execFileAsync(ZSIGN_PATH, [
      '-k', cfg.p12Password,
      '-p', cfg.p12Path,
      '-m', profilePath,
      '-o', signedIpa,
      rawIpa
    ], { maxBuffer: 1024 * 1024 * 512 });

    // 6. Upload signed IPA + manifest to R2
    console.log('  [6/6] uploading to R2...');
    const objectKey = `signed/${bundleId}/${version || 'v1'}/${udid}.ipa`;
    const signedUrl = await uploadToR2(signedIpa, objectKey);

    // Build manifest.plist pointing at the signed IPA
    const manifestKey = `manifests/${bundleId}-${udid}.plist`;
    const manifestPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>items</key>
  <array>
    <dict>
      <key>assets</key>
      <array>
        <dict><key>kind</key><string>software-package</string><key>url</key><string>${signedUrl}</string></dict>
      </array>
      <key>metadata</key>
      <dict>
        <key>bundle-identifier</key><string>${bundleId}</string>
        <key>bundle-version</key><string>${version || '1.0.0'}</string>
        <key>kind</key><string>software</string>
        <key>title</key><string>${appName || bundleId}</string>
      </dict>
    </dict>
  </array>
</dict>
</plist>`;
    const manifestUrl = await uploadBufferToR2(
      Buffer.from(manifestPlist, 'utf8'),
      manifestKey,
      'application/xml'
    );

    res.json({ ok: true, signedUrl, manifestUrl });
  } catch (err) {
    console.error('  sign failed:', err.message);
    res.status(500).json({ error: err.message });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

app.listen(PORT, () => {
  console.log(`DistribUp sign server listening on :${PORT}`);
  console.log(`  zsign: ${ZSIGN_PATH}`);
  console.log(`  worker: ${WORKER_URL}`);
});
