// DistribUp sign sidecar — Enterprise (In-House) mode.
// No ASC API, no UDID registration, no per-device profiles.
// Uses a fixed enterprise p12 + mobileprovision (ProvisionsAllDevices=true).
// Any iOS device can install after re-signing.
//
// Pipeline: download raw IPA -> zsign with fixed cert -> upload signed IPA + manifest to R2.

import express from 'express';
import { execFile } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import https from 'https';
import AWS from 'aws-sdk';

const execFileAsync = promisify(execFile);

const app = express();
app.use(express.json({ limit: '1mb' }));

// ─── Env ──────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
const SHARED_SECRET = process.env.SHARED_SECRET;
const ZSIGN_PATH = process.env.ZSIGN_PATH || '/usr/local/bin/zsign';

// Enterprise cert files (placed on VPS)
const P12_PATH = process.env.P12_PATH || '/opt/sign-server/cert.p12';
const P12_PASSWORD = process.env.P12_PASSWORD || 'AppleP12.com';
const PROFILE_PATH = process.env.PROFILE_PATH || '/opt/sign-server/profile.mobileprovision';
const R2_PUBLIC_BASE = process.env.R2_PUBLIC_BASE || '';

if (!SHARED_SECRET) {
  console.error('ERROR: SHARED_SECRET must be set in .env');
  process.exit(1);
}
if (!fs.existsSync(P12_PATH)) {
  console.error('ERROR: p12 not found at', P12_PATH);
  process.exit(1);
}
if (!fs.existsSync(PROFILE_PATH)) {
  console.error('ERROR: mobileprovision not found at', PROFILE_PATH);
  process.exit(1);
}

// ─── R2 upload ──────────────────────────────────────────────────────────────────
const s3 = new AWS.S3({
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  accessKeyId: process.env.R2_ACCESS_KEY_ID,
  secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  region: 'auto',
  signatureVersion: 'v4'
});
const R2_BUCKET = process.env.R2_BUCKET || 'distribup-files';

async function uploadFile(localPath, objectKey, contentType) {
  const body = fs.readFileSync(localPath);
  await s3.upload({ Bucket: R2_BUCKET, Key: objectKey, Body: body, ContentType: contentType || 'application/octet-stream' }).promise();
  return `${R2_PUBLIC_BASE}/${objectKey}`;
}

async function uploadBuffer(buf, objectKey, contentType) {
  await s3.upload({ Bucket: R2_BUCKET, Key: objectKey, Body: buf, ContentType: contentType || 'application/octet-stream' }).promise();
  return `${R2_PUBLIC_BASE}/${objectKey}`;
}

// ─── Download helper ─────────────────────────────────────────────────────────
async function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destPath);
    const doReq = (u) => {
      https.get(u, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          file.close(); fs.unlinkSync(destPath); return doReq(res.headers.location);
        }
        if (res.statusCode !== 200) { file.close(); return reject(new Error(`Download failed: HTTP ${res.statusCode}`)); }
        res.pipe(file);
        file.on('finish', () => { file.close(); resolve(destPath); });
      }).on('error', reject);
    };
    doReq(url);
  });
}

// ─── Auth middleware ──────────────────────────────────────────────────────────
function auth(req, res, next) {
  if (req.get('x-sign-secret') !== SHARED_SECRET) return res.status(401).json({ error: 'unauthorized' });
  next();
}

// ─── Health ───────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// ─── Sign endpoint ───────────────────────────────────────────────────────────
app.post('/sign', auth, async (req, res) => {
  const { ipaUrl, bundleId, version, appName } = req.body;
  if (!ipaUrl) return res.status(400).json({ error: 'ipaUrl required' });

  const workDir = fs.mkdtempSync('/tmp/sign-');
  const rawIpa = path.join(workDir, 'input.ipa');
  const signedIpa = path.join(workDir, 'signed.ipa');

  try {
    console.log(`[${new Date().toISOString()}] sign: bundle=${bundleId} v${version}`);

    console.log('  downloading IPA...');
    await downloadFile(ipaUrl, rawIpa);

    console.log('  running zsign...');
    await execFileAsync(ZSIGN_PATH, [
      '-k', P12_PASSWORD,
      '-p', P12_PATH,
      '-m', PROFILE_PATH,
      '-o', signedIpa,
      rawIpa
    ], { maxBuffer: 1024 * 1024 * 512 });

    const objectKey = `signed/${bundleId}/${version || 'v1'}/signed.ipa`;
    console.log('  uploading signed IPA to R2:', objectKey);
    const signedUrl = await uploadFile(signedIpa, objectKey, 'application/octet-stream');

    const manifestKey = `manifests/${bundleId}.plist`;
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
    const manifestUrl = await uploadBuffer(Buffer.from(manifestPlist, 'utf8'), manifestKey, 'application/xml');

    res.json({ ok: true, signedUrl, manifestUrl });
  } catch (err) {
    console.error('  sign failed:', err.message);
    res.status(500).json({ error: err.message });
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
});

app.listen(PORT, () => {
  console.log(`DistribUp sign server (enterprise mode) listening on :${PORT}`);
  console.log(`  zsign: ${ZSIGN_PATH}`);
  console.log(`  p12: ${P12_PATH}`);
  console.log(`  profile: ${PROFILE_PATH}`);
});
