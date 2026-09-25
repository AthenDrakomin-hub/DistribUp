/**
 * DistribUp - Cloudflare Workers entry (native Fetch API)
 * Replaces the original Express server/index.js.
 *
 * Usage: wrangler deploy (requires D1/R2 bindings in wrangler.toml).
 */

const JWT_EXPIRES_IN = '7d';

// ─── JWT utils (pure JS, no external lib) ────────────────────────────────────
async function signJWT(payload, secret, expiresIn) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const exp = Math.floor(Date.now() / 1000) + parseExp(expiresIn);
  const body = btoa(JSON.stringify({ ...payload, exp }));
  const sig = await hmacSign(header + '.' + body, secret);
  return header + '.' + body + '.' + sig;
}

async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sig] = parts;
  const valid = await hmacVerify(headerB64 + '.' + payloadB64, secret, sig);
  if (!valid) return null;
  const decoded = JSON.parse(atob(payloadB64));
  if (decoded.exp && decoded.exp < Math.floor(Date.now() / 1000)) return null;
  return decoded;
}

async function hmacSign(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function hmacVerify(data, secret, expectedSig) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const sigBytes = Uint8Array.from(atob(expectedSig), c => c.charCodeAt(0));
  return crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(data));
}

function parseExp(str) {
  const m = str.match(/(\d+)([smhd])/);
  if (!m) return 604800;
  const [, num, unit] = m;
  const n = parseInt(num);
  return { s: n, m: n * 60, h: n * 3600, d: n * 86400 }[unit] || 604800;
}

// ─── bcrypt replacement: Web Crypto + pbkdf2-style iterations ────────────────
async function bcryptHash(password, rounds = 10) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = Math.pow(2, rounds);
  let derivedKey = salt;
  for (let i = 0; i < iterations; i++) {
    const data = new Uint8Array([...derivedKey, ...new TextEncoder().encode(password)]);
    const hash = await crypto.subtle.digest('SHA-256', data);
    derivedKey = new Uint8Array(hash);
  }
  const hashB64 = btoa(String.fromCharCode(...derivedKey));
  const saltB64 = btoa(String.fromCharCode(...salt));
  return `$sha256$${rounds}$${saltB64}$${hashB64}`;
}

async function bcryptCompare(password, hash) {
  if (!hash.startsWith('$sha256$')) return false;
  const parts = hash.split('$');
  const rounds = parseInt(parts[2]);
  const salt = Uint8Array.from(atob(parts[3]), c => c.charCodeAt(0));
  const iterations = Math.pow(2, rounds);
  let derivedKey = salt;
  for (let i = 0; i < iterations; i++) {
    const data = new Uint8Array([...derivedKey, ...new TextEncoder().encode(password)]);
    const hash = await crypto.subtle.digest('SHA-256', data);
    derivedKey = new Uint8Array(hash);
  }
  const hashB64 = btoa(String.fromCharCode(...derivedKey));
  return hashB64 === parts[4];
}

async function computeMD5(buffer) {
  // Cloudflare Workers does not expose MD5 via Web Crypto; return placeholder.
  return '';
}

// ─── Response helpers ────────────────────────────────────────────────────────
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/xml; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
  });
}

function handleOptions(req) {
  if (req.method !== 'OPTIONS') return null;
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Max-Age': '86400'
    }
  });
}

async function getJSON(req, env) {
  try {
    return await req.json();
  } catch {
    return {};
  }
}

async function authenticate(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace(/^Bearer\s+/i, '');
  if (!token) return null;
  const decoded = await verifyJWT(token, env.JWT_SECRET);
  if (!decoded) return null;
  return decoded;
}

// ─── Static file service (base64-inlined HTML; injected by scripts/embed-html.cjs) ──
const STATIC_FILES = {
  '/': INDEX_HTML_B64,
  '/index.html': INDEX_HTML_B64,
  '/login.html': LOGIN_HTML_B64,
  '/admin.html': ADMIN_HTML_B64,
  '/upload.html': UPLOAD_HTML_B64
};

function getStaticFile(path) {
  const b64 = STATIC_FILES[path];
  if (!b64) return null;
  const page = atob(b64);
  return new Response(page, {
    status: 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Access-Control-Allow-Origin': '*' }
  });
}

// ─── Main router ─────────────────────────────────────────────────────────────
async function handleRequest(req, env, ctx) {
  // CORS preflight
  const corsResp = handleOptions(req);
  if (corsResp) return corsResp;

  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;

  // Health check
  if (path === '/health') {
    return json({ status: 'ok', timestamp: new Date().toISOString() });
  }

  // Static pages
  const staticResp = getStaticFile(path);
  if (staticResp) return staticResp;

  // Auth routes (public signup disabled - personal deployment; admin creates users)
  if (path === '/api/auth/login' && method === 'POST') return handleLogin(req, env);
  if (path === '/api/auth/me' && method === 'GET') return handleMe(req, env);
  if (path === '/api/auth/password' && method === 'PUT') return handlePassword(req, env);

  // Dashboard stats
  if (path === '/api/stats' && method === 'GET') return handleStats(req, env);
  if (path === '/api/uploads/recent' && method === 'GET') return handleRecentUploads(req, env);

  // Apps routes
  if (path === '/api/apps' && method === 'GET') return handleListApps(req, env);
  if (path === '/api/apps' && method === 'POST') return handleCreateApp(req, env);
  if (/^\/api\/apps\/\d+$/.test(path) && method === 'GET') return handleGetApp(req, env);
  if (/^\/api\/apps\/\d+$/.test(path) && method === 'PUT') return handleUpdateApp(req, env);
  if (/^\/api\/apps\/\d+$/.test(path) && method === 'DELETE') return handleDeleteApp(req, env);
  if (/^\/api\/apps\/\d+\/ota-url$/.test(path) && method === 'GET') return handleOtaUrl(req, env);

  // Upload routes
  if (/^\/api\/upload\/\d+$/.test(path) && method === 'POST') return handleUpload(req, env);
  if (/^\/api\/upload\/list\/\d+$/.test(path) && method === 'GET') return handleListUploads(req, env);
  if (/^\/api\/upload\/\d+$/.test(path) && method === 'DELETE') return handleDeleteUpload(req, env);

  // Sign routes
  if (/^\/api\/sign\/list\/\d+$/.test(path) && method === 'GET') return handleListSigned(req, env);
  if (path === '/api/sign/resign' && method === 'POST') return handleResign(req, env);
  if (path === '/api/sign/android' && method === 'POST') return handleAndroidSign(req, env);

  // Install routes
  if (/^\/api\/install\/manifest\/.+/.test(path) && method === 'GET') return handleManifest(req, env);
  if (/^\/api\/install\/ota\/.+/.test(path) && method === 'GET') return handleOta(req, env);
  if (/^\/api\/install\/android-download\/.+/.test(path) && method === 'GET') return handleAndroidDownload(req, env);
  if (/^\/api\/install\/\d+\/online-sign/.test(path) && method === 'GET') return handleOnlineSign(req, env);
  if (path === '/api/install/udid-config' && method === 'GET') return handleUdidConfig(req, env);
  if (path === '/api/install/udid-collect' && method === 'POST') return handleUdidCollect(req, env);

  // Devices routes
  if (path === '/api/devices' && method === 'GET') return handleListDevices(req, env);
  if (path === '/api/devices' && method === 'POST') return handleAddDevice(req, env);
  if (/^\/api\/devices\/\d+$/.test(path) && method === 'DELETE') return handleDeleteDevice(req, env);
  if (path === '/api/devices/collect-config' && method === 'GET') return handleCollectConfig(req, env);

  // Admin routes
  if (path === '/api/admin/users' && method === 'GET') return handleAdminUsers(req, env);
  if (path === '/api/admin/users' && method === 'POST') return handleAdminCreateUser(req, env);
  if (/^\/api\/admin\/users\/\d+$/.test(path) && method === 'PUT') return handleAdminUpdateUser(req, env);
  if (/^\/api\/admin\/users\/\d+$/.test(path) && method === 'DELETE') return handleAdminDeleteUser(req, env);

  // App Store Connect routes
  if (path === '/api/appstore/devices/register' && method === 'POST') return handleAppstoreRegister(req, env);
  if (path === '/api/appstore/devices' && method === 'GET') return handleAppstoreDevices(req, env);

  // R2 direct file proxy
  if (/^\/signed\/.+/.test(path)) {
    const filename = path.replace('/signed/', '');
    const object = await env.STORAGE.get(filename);
    if (object) {
      const headers = new Headers();
      headers.set('Content-Type', object.httpMetadata?.contentType || 'application/octet-stream');
      headers.set('Access-Control-Allow-Origin', '*');
      return new Response(object.body, { status: 200, headers });
    }
    return json({ error: 'File not found' }, 404);
  }

  return json({ error: 'Not found' }, 404);
}

// ─── Stats handlers ─────────────────────────────────────────────────────────────
async function handleStats(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const isAdmin = user.role === 'admin';
  const teamFilter = isAdmin ? '' : 'WHERE team_id = ?';
  const binds = isAdmin ? [] : [user.team_id];

  const [apps, devices, downloads, users] = await Promise.all([
    env.distribup_db.prepare(`SELECT COUNT(*) as c FROM apps ${teamFilter}`).bind(...binds).first(),
    env.distribup_db.prepare(`SELECT COUNT(*) as c FROM devices ${teamFilter}`).bind(...binds).first(),
    env.distribup_db.prepare(`SELECT COALESCE(SUM(download_count),0) as c FROM uploads u JOIN apps a ON u.app_id=a.id ${teamFilter.replace('team_id', 'a.team_id')}`).bind(...binds).first(),
    isAdmin
      ? env.distribup_db.prepare('SELECT COUNT(*) as c FROM users').first()
      : Promise.resolve({ c: 1 })
  ]);

  return json({
    totalApps: apps.c || 0,
    totalDevices: devices.c || 0,
    totalDownloads: downloads.c || 0,
    totalUsers: users.c || 0
  });
}

async function handleRecentUploads(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const isAdmin = user.role === 'admin';
  const sql = isAdmin
    ? `SELECT u.id, u.original_name, u.file_size, u.created_at, a.name as app_name, a.platform
       FROM uploads u JOIN apps a ON u.app_id = a.id ORDER BY u.created_at DESC LIMIT 10`
    : `SELECT u.id, u.original_name, u.file_size, u.created_at, a.name as app_name, a.platform
       FROM uploads u JOIN apps a ON u.app_id = a.id
       WHERE a.team_id = ? ORDER BY u.created_at DESC LIMIT 10`;
  const result = isAdmin
    ? await env.distribup_db.prepare(sql).all()
    : await env.distribup_db.prepare(sql).bind(user.team_id).all();
  return json({ uploads: result.results || [] });
}

// ─── Auth handlers ────────────────────────────────────────────────────────────

async function handleLogin(req, env) {
  const { username, password } = await getJSON(req, env);
  if (!username || !password) return json({ error: 'Username and password are required' }, 400);
  const user = await env.distribup_db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').bind(username, username).first();
  if (!user) return json({ error: 'Invalid username or password' }, 401);
  if (!user.is_active) return json({ error: 'Account is disabled' }, 403);
  const valid = await bcryptCompare(password, user.password_hash);
  if (!valid) return json({ error: 'Invalid username or password' }, 401);
  const token = await signJWT(
    { id: user.id, username: user.username, email: user.email, role: user.role, team_id: user.team_id },
    env.JWT_SECRET, JWT_EXPIRES_IN
  );
  return json({
    message: 'Logged in', token,
    user: { id: user.id, username: user.username, email: user.email, role: user.role, team_id: user.team_id }
  });
}

async function handleMe(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const result = await env.distribup_db.prepare(
    'SELECT id, username, email, role, team_id, created_at FROM users WHERE id = ?'
  ).bind(user.id).first();
  return json({ user: result });
}

async function handlePassword(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const { oldPassword, newPassword } = await getJSON(req, env);
  if (!oldPassword || !newPassword) return json({ error: 'Old and new password are required' }, 400);
  const dbUser = await env.distribup_db.prepare('SELECT password_hash FROM users WHERE id = ?').bind(user.id).first();
  if (!await bcryptCompare(oldPassword, dbUser.password_hash)) return json({ error: 'Old password is incorrect' }, 401);
  const hash = await bcryptHash(newPassword);
  await env.distribup_db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(hash, user.id).run();
  return json({ message: 'Password updated' });
}

// ─── Apps handlers ────────────────────────────────────────────────────────────
async function handleListApps(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const sql = user.role === 'admin'
    ? 'SELECT * FROM apps ORDER BY created_at DESC'
    : 'SELECT * FROM apps WHERE team_id = ? ORDER BY created_at DESC';
  const result = user.role === 'admin'
    ? await env.distribup_db.prepare(sql).all()
    : await env.distribup_db.prepare(sql).bind(user.team_id).all();
  return json({ apps: result.results || [] });
}

async function handleCreateApp(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const { name, platform, bundle_id, package_name, version, description } = await getJSON(req, env);
  if (!name || !bundle_id) return json({ error: 'App name and Bundle ID are required' }, 400);
  const existing = await env.distribup_db.prepare(
    'SELECT id FROM apps WHERE bundle_id = ? AND team_id = ?'
  ).bind(bundle_id, user.team_id).first();
  if (existing) return json({ error: 'Bundle ID already exists in this team' }, 400);
  const result = await env.distribup_db.prepare(
    'INSERT INTO apps (team_id, name, platform, bundle_id, package_name, version, description, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(user.team_id, platform || 'ios', name, bundle_id, package_name || null, version || '1.0.0', description, user.id).run();
  const app = await env.distribup_db.prepare('SELECT * FROM apps WHERE id = ?').bind(result.meta?.last_row_id ?? 0).first();
  return json({ app }, 201);
}

async function handleGetApp(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const id = req.url.match(/\/api\/apps\/(\d+)/)?.[1];
  if (!id) return json({ error: 'Invalid parameter' }, 400);
  const app = await env.distribup_db.prepare(
    'SELECT * FROM apps WHERE id = ? AND team_id IN (SELECT team_id FROM users WHERE id = ? OR role = ?)'
  ).bind(id, user.id, 'admin').first();
  if (!app) return json({ error: 'App not found' }, 404);
  const uploadCount = await env.distribup_db.prepare('SELECT COUNT(*) as count FROM uploads WHERE app_id = ?').bind(app.id).first();
  return json({ app, upload_count: uploadCount.count });
}

async function handleUpdateApp(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const id = req.url.match(/\/api\/apps\/(\d+)/)?.[1];
  const { name, platform, bundle_id, package_name, version, description } = await getJSON(req, env);
  await env.distribup_db.prepare(
    'UPDATE apps SET name=?, platform=?, bundle_id=?, package_name=?, version=?, description=? WHERE id=? AND team_id IN (SELECT team_id FROM users WHERE id=? OR role=?)'
  ).bind(name, platform, bundle_id, package_name, version, description, id, user.id, 'admin').run();
  return json({ message: 'Updated' });
}

async function handleDeleteApp(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const id = req.url.match(/\/api\/apps\/(\d+)/)?.[1];
  await env.distribup_db.prepare(
    'DELETE FROM apps WHERE id = ? AND team_id IN (SELECT team_id FROM users WHERE id = ? OR role = ?)'
  ).bind(id, user.id, 'admin').run();
  return json({ message: 'Deleted' });
}

async function handleOtaUrl(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const id = req.url.match(/\/api\/apps\/(\d+)\/ota-url/)?.[1];
  const app = await env.distribup_db.prepare('SELECT * FROM apps WHERE id = ?').bind(id).first();
  if (!app) return json({ error: 'App not found' }, 404);
  const latest = await env.distribup_db.prepare(
    'SELECT * FROM uploads WHERE app_id = ? ORDER BY created_at DESC LIMIT 1'
  ).bind(app.id).first();
  if (!latest) return json({ error: 'No uploaded version found' }, 404);
  const baseUrl = env.BASE_URL || `https://${req.headers.get('host')}`;
  const manifestUrl = `${baseUrl}/api/install/manifest/${app.bundle_id}`;
  return json({
    itmsUrl: `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`,
    manifestUrl
  });
}

// ─── Upload handlers ──────────────────────────────────────────────────────────
async function handleUpload(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const appId = req.url.match(/\/api\/upload\/(\d+)/)?.[1];
  const url = new URL(req.url);
  const platform = url.searchParams.get('platform') || 'ios';

  const app = await env.distribup_db.prepare(
    'SELECT * FROM apps WHERE id = ? AND team_id IN (SELECT team_id FROM users WHERE id = ?)'
  ).bind(appId, user.id).first();
  if (!app) return json({ error: 'App not found or not permitted' }, 404);

  const formData = await req.formData();
  const file = formData.get('file');
  if (!file) return json({ error: 'No file selected' }, 400);

  if (app.platform === 'android' && !/\.(apk|xapk|obb)$/i.test(file.name)) {
    return json({ error: 'Android apps only accept APK/XAPK/OBB files' }, 400);
  }
  if (app.platform === 'ios' && !/\.ipa$/i.test(file.name)) {
    return json({ error: 'iOS apps only accept IPA files' }, 400);
  }

  const maxSize = parseInt(env.MAX_UPLOAD_SIZE || '524288000');
  if (file.size > maxSize) {
    return json({ error: `File exceeds size limit (max ${maxSize / 1024 / 1024}MB)` }, 400);
  }

  const ext = file.name.split('.').pop()?.toLowerCase() || '';
  const timestamp = Date.now();
  const filename = `${platform}_${app.id}_${timestamp}.${ext}`;
  const buffer = Buffer.from(await file.arrayBuffer());

  await env.STORAGE.put(filename, buffer, {
    httpMetadata: { contentType: file.type || 'application/octet-stream' },
    customMetadata: { appId: String(app.id), platform }
  });

  const storageUrl = `https://${env.STORAGE.bucketName}.r2.cloudflarestorage.com/${filename}`;
  await env.distribup_db.prepare(
    `INSERT INTO uploads (app_id, user_id, filename, original_name, file_size, file_type, storage_path, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'uploaded')`
  ).bind(appId, user.id, filename, file.name, buffer.length, `.${ext}`, storageUrl).run();

  return json({ success: true, url: storageUrl, size: buffer.length, filename, platform });
}

async function handleListUploads(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const appId = req.url.match(/\/api\/upload\/list\/(\d+)/)?.[1];
  const result = await env.distribup_db.prepare(
    `SELECT u.*, a.name as app_name, a.bundle_id FROM uploads u JOIN apps a ON u.app_id = a.id WHERE u.app_id = ? ORDER BY u.created_at DESC`
  ).bind(appId).all();
  return json({ uploads: result.results || [] });
}

async function handleDeleteUpload(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const uploadId = req.url.match(/\/api\/upload\/(\d+)/)?.[1];
  const upload = await env.distribup_db.prepare(
    'SELECT * FROM uploads WHERE id = ? AND user_id = ?'
  ).bind(uploadId, user.id).first();
  if (!upload) return json({ error: 'Record not found' }, 404);
  await env.STORAGE.delete(upload.filename);
  await env.distribup_db.prepare('DELETE FROM uploads WHERE id = ?').bind(uploadId).run();
  return json({ message: 'Deleted' });
}

// ─── Sign handlers ─────────────────────────────────────────────────────────────
async function handleListSigned(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const appId = req.url.match(/\/api\/sign\/list\/(\d+)/)?.[1];
  const result = await env.distribup_db.prepare(
    `SELECT u.*, s.filename, s.created_at FROM uploads u LEFT JOIN signed_files s ON u.id = s.upload_id WHERE u.app_id = ? ORDER BY u.created_at DESC`
  ).bind(appId).all();
  return json({ files: result.results || [] });
}

async function handleResign(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const { appId, certId, udids } = await getJSON(req, env);
  if (!appId || !certId || !udids?.length) return json({ error: 'Missing required parameters' }, 400);
  const [app, cert] = await Promise.all([
    env.distribup_db.prepare('SELECT * FROM apps WHERE id = ?').bind(appId).first(),
    env.distribup_db.prepare(
      'SELECT * FROM certificates WHERE id = ? AND team_id IN (SELECT team_id FROM users WHERE id = ?)'
    ).bind(certId, user.id).first()
  ]);
  if (!app || !cert) return json({ error: 'App or certificate not found' }, 404);
  if (app.platform !== 'ios') return json({ error: 'This endpoint supports iOS apps only' }, 400);
  if (cert.expires_at && new Date(cert.expires_at) < new Date()) {
    return json({ error: 'Certificate has expired' }, 400);
  }
  return json({ message: 'iOS signing must be done via the zsign sidecar service', appId });
}

// Public endpoint: anonymous user scans QR -> this triggers on-demand re-sign on the VPS.
// GET /api/install/:appId/online-sign?udid=xxx
async function handleOnlineSign(req, env) {
  const url = new URL(req.url);
  const m = url.pathname.match(/\/api\/install\/(\d+)\/online-sign/);
  const appId = parseInt(m[1]);
  const udid = url.searchParams.get('udid');
  if (!udid) return new Response('Missing udid parameter', { status: 400 });

  const app = await env.distribup_db.prepare('SELECT * FROM apps WHERE id = ?').bind(appId).first();
  if (!app) return new Response('App not found', { status: 404 });

  const upload = await env.distribup_db.prepare(
    "SELECT * FROM uploads WHERE app_id = ? AND platform = 'ios' ORDER BY created_at DESC LIMIT 1"
  ).bind(appId).first();
  if (!upload) return new Response('No IPA uploaded for this app', { status: 404 });

  // The raw IPA must be publicly reachable by the VPS. Use R2 public URL.
  const baseUrl = url.origin;
  const rawIpaUrl = `${baseUrl}/signed/${upload.storage_path.split('/').pop()}`;

  // Call VPS sign service
  const signRes = await fetch(`${env.SIGNSERVER_URL}/sign`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-sign-secret': env.SIGNSERVER_SECRET
    },
    body: JSON.stringify({
      udid,
      ipaUrl: rawIpaUrl,
      bundleId: app.bundle_id,
      version: app.version
    }),
    // Workers CPU limit: this call can take 30-60s. Subrequest body timeout is 15s on free tier,
    // but the VPS does the heavy work; this just waits.
    signal: AbortSignal.timeout(120000)
  });

  if (!signRes.ok) {
    const err = await signRes.text();
    return new Response(`Signing failed: ${err}`, { status: 500 });
  }

  const { signedUrl } = await signRes.json();

  // Build a one-off manifest pointing at the signed IPA
  const manifestPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>items</key><array><dict>
    <key>assets</key><array><dict>
      <key>kind</key><string>software-package</string>
      <key>url</key><string>${signedUrl}</string>
    </dict></array>
    <key>metadata</key><dict>
      <key>bundle-identifier</key><string>${app.bundle_id}</string>
      <key>bundle-version</key><string>${app.version}</string>
      <key>kind</key><string>software</string>
      <key>title</key><string>${app.name}</string>
    </dict>
  </dict></array>
</dict>
</plist>`;

  // Store manifest as a short-lived R2 object, or just redirect to itms directly
  // For simplicity: return an HTML page that triggers the itms prompt
  const itmsUrl = `itms-services://?action=download-manifest&url=${encodeURIComponent(signedUrl.replace(/\.ipa$/, '.plist'))}`;

  // Persist manifest to R2 so iOS can fetch it
  await env.STORAGE.put(`manifests/${app.bundle_id}-${udid}.plist`, manifestPlist, {
    httpMetadata: { contentType: 'application/xml' }
  });

  return new Response(
    `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<title>Installing...</title></head><body style="font-family:system-ui;text-align:center;padding-top:40px">` +
    `<p>Signing complete. Tap <a href="itms-services://?action=download-manifest&url=${encodeURIComponent(`${baseUrl}/signed/manifests/${app.bundle_id}-${udid}.plist`)}">here to install</a></p>` +
    `<p style="color:#888;font-size:14px">If nothing happens, open this page in Safari.</p>` +
    `</body></html>`,
    { headers: { 'Content-Type': 'text/html' } }
  );
}

async function handleAndroidSign(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const { appId, certId } = await getJSON(req, env);
  if (!appId || !certId) return json({ error: 'Missing required parameters' }, 400);
  const [app, cert] = await Promise.all([
    env.distribup_db.prepare('SELECT * FROM apps WHERE id = ?').bind(appId).first(),
    env.distribup_db.prepare(
      'SELECT * FROM certificates WHERE id = ? AND team_id IN (SELECT team_id FROM users WHERE id = ?)'
    ).bind(certId, user.id).first()
  ]);
  if (!app || !cert) return json({ error: 'App or certificate not found' }, 404);
  if (app.platform !== 'android') return json({ error: 'This endpoint supports Android apps only' }, 400);
  return json({
    message: 'Android signing requires apksigner; download the raw APK, sign locally, then re-upload',
    appId
  });
}

// ─── Install handlers ─────────────────────────────────────────────────────────
async function handleManifest(req, env) {
  const bundleId = req.url.match(/\/api\/install\/manifest\/(.+)/)?.[1];
  const app = await env.distribup_db.prepare('SELECT * FROM apps WHERE bundle_id = ?').bind(bundleId).first();
  if (!app) return json({ error: 'App not found' }, 404);
  if (app.platform === 'android') {
    return json({ error: 'Android apps do not support OTA install; use the direct download link' }, 400);
  }
  const latest = await env.distribup_db.prepare(
    'SELECT * FROM uploads WHERE app_id = ? ORDER BY created_at DESC LIMIT 1'
  ).bind(app.id).first();
  if (!latest) return json({ error: 'No available version' }, 404);
  await env.distribup_db.prepare(
    'UPDATE uploads SET download_count = download_count + 1 WHERE id = ?'
  ).bind(latest.id).run();
  const baseUrl = env.BASE_URL || `https://${req.headers.get('host')}`;
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>items</key>
  <array>
    <dict>
      <key>assets</key>
      <array>
        <dict><key>kind</key><string>software-package</string><key>url</key><string>${latest.storage_path}</string></dict>
        <dict><key>kind</key><string>display-image</string><key>url</key><string>${app.icon_path || `${baseUrl}/assets/default-icon.png`}</string></dict>
        <dict><key>kind</key><string>full-size-image</string><key>url</key><string>${app.icon_path || `${baseUrl}/assets/default-icon.png`}</string></dict>
      </array>
      <key>metadata</key>
      <dict>
        <key>bundle-identifier</key><string>${app.bundle_id}</string>
        <key>bundle-version</key><string>${app.version}</string>
        <key>kind</key><string>software</string>
        <key>title</key><string>${app.name}</string>
      </dict>
    </dict>
  </array>
</dict>
</plist>`;
  return html(plist);
}

async function handleOta(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const bundleId = req.url.match(/\/api\/install\/ota\/(.+)/)?.[1];
  const app = await env.distribup_db.prepare('SELECT * FROM apps WHERE bundle_id = ?').bind(bundleId).first();
  if (!app) return json({ error: 'App not found' }, 404);
  if (app.platform === 'android') {
    return json({ error: 'Android apps do not support OTA install; use the direct download link' }, 400);
  }
  const baseUrl = env.BASE_URL || `https://${req.headers.get('host')}`;
  const manifestUrl = `${baseUrl}/api/install/manifest/${app.bundle_id}`;
  return json({
    itmsUrl: `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`,
    manifestUrl
  });
}

async function handleAndroidDownload(req, env) {
  const bundleId = req.url.match(/\/api\/install\/android-download\/(.+)/)?.[1];
  const app = await env.distribup_db.prepare('SELECT * FROM apps WHERE bundle_id = ?').bind(bundleId).first();
  if (!app) return json({ error: 'App not found' }, 404);
  if (app.platform !== 'android') return json({ error: 'This endpoint supports Android apps only' }, 400);
  const latest = await env.distribup_db.prepare(
    'SELECT * FROM uploads WHERE app_id = ? ORDER BY created_at DESC LIMIT 1'
  ).bind(app.id).first();
  if (!latest) return json({ error: 'No available version' }, 404);
  await env.distribup_db.prepare(
    'UPDATE uploads SET download_count = download_count + 1 WHERE id = ?'
  ).bind(latest.id).run();
  return json({
    appName: app.name, version: app.version, fileSize: latest.file_size,
    downloadUrl: latest.storage_path,
    qrCode: `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(latest.storage_path)}`
  });
}

async function handleUdidConfig(req, env) {
  const baseUrl = env.BASE_URL || `https://${req.headers.get('host')}`;
  const config = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>items</key>
  <array>
    <dict>
      <key>assets</key>
      <array>
        <dict><key>kind</key><string>software</string><key>url</key><string>${baseUrl}/api/install/udid-collect</string></dict>
      </array>
      <key>metadata</key>
      <dict><key>kind</key><string>software</string><key>title</key><string>UDID Enrollment</string></dict>
    </dict>
  </array>
</dict>
</plist>`;
  return html(config);
}

async function handleUdidCollect(req, env) {
  const { udid, name, platform = 'iOS', team_id } = await getJSON(req, env);
  if (!udid) return json({ error: 'UDID is required' }, 400);
  await env.distribup_db.prepare(
    'INSERT OR REPLACE INTO devices (udid, name, platform, team_id, registered_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(udid, name, platform, team_id, new Date().toISOString()).run();
  return json({ success: true, message: 'Device registered successfully' });
}

// ─── Devices handlers ─────────────────────────────────────────────────────────
async function handleListDevices(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const result = await env.distribup_db.prepare(
    'SELECT * FROM devices WHERE team_id = ? ORDER BY created_at DESC'
  ).bind(user.team_id).all();
  return json({ devices: result.results || [] });
}

async function handleAddDevice(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const { udid, name, platform = 'iOS' } = await getJSON(req, env);
  if (!udid) return json({ error: 'UDID is required' }, 400);
  const result = await env.distribup_db.prepare(
    'INSERT OR REPLACE INTO devices (udid, name, platform, team_id, registered_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(udid, name, platform, user.team_id, new Date().toISOString()).run();
  return json({ id: result.meta?.last_row_id ?? 0, udid, name, message: 'Device added' });
}

async function handleDeleteDevice(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const id = req.url.match(/\/api\/devices\/(\d+)/)?.[1];
  await env.distribup_db.prepare(
    'DELETE FROM devices WHERE id = ? AND team_id = ?'
  ).bind(id, user.team_id).run();
  return json({ message: 'Deleted' });
}

async function handleCollectConfig(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const baseUrl = env.BASE_URL || `https://${req.headers.get('host')}`;
  return json({ collectUrl: `${baseUrl}/api/install/udid-collect`, expiresIn: 86400 });
}

// ─── Admin handlers ────────────────────────────────────────────────────────────
async function handleAdminUsers(req, env) {
  const user = await authenticate(req, env);
  if (!user || user.role !== 'admin') return json({ error: 'Forbidden' }, 403);
  const result = await env.distribup_db.prepare(
    'SELECT id, username, email, role, team_id, is_active, created_at FROM users ORDER BY created_at DESC'
  ).all();
  return json({ success: true, data: result.results || [] });
}

async function handleAdminCreateUser(req, env) {
  const user = await authenticate(req, env);
  if (!user || user.role !== 'admin') return json({ error: 'Forbidden' }, 403);
  const { username, password, email, role, teamId } = await getJSON(req, env);
  const existing = await env.distribup_db.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existing) return json({ error: 'Username already exists' }, 400);
  const hash = await bcryptHash(password || Math.random().toString(36).slice(2, 10));
  const result = await env.distribup_db.prepare(
    'INSERT INTO users (username, email, password_hash, role, team_id, is_active) VALUES (?, ?, ?, ?, ?, 1)'
  ).bind(username, email, hash, role || 'user', teamId).run();
  const u = await env.distribup_db.prepare(
    'SELECT id, username, email, role, team_id, is_active, created_at FROM users WHERE id = ?'
  ).bind(result.meta?.last_row_id ?? 0).first();
  return json({ success: true, data: u });
}

async function handleAdminUpdateUser(req, env) {
  const authUser = await authenticate(req, env);
  if (!authUser || authUser.role !== 'admin') return json({ error: 'Forbidden' }, 403);
  const id = req.url.match(/\/api\/admin\/users\/(\d+)/)?.[1];
  const { role, isActive, teamId } = await getJSON(req, env);
  const fields = [], values = [];
  if (role) { fields.push('role=?'); values.push(role); }
  if (isActive !== undefined) { fields.push('is_active=?'); values.push(isActive); }
  if (teamId) { fields.push('team_id=?'); values.push(teamId); }
  if (!fields.length) return json({ error: 'No fields to update' }, 400);
  values.push(id);
  await env.distribup_db.prepare(`UPDATE users SET ${fields.join(',')} WHERE id = ?`).bind(...values).run();
  const u = await env.distribup_db.prepare(
    'SELECT id, username, email, role, team_id, is_active FROM users WHERE id = ?'
  ).bind(id).first();
  return json({ success: true, data: u });
}

async function handleAdminDeleteUser(req, env) {
  const authUser = await authenticate(req, env);
  if (!authUser || authUser.role !== 'admin') return json({ error: 'Forbidden' }, 403);
  const id = req.url.match(/\/api\/admin\/users\/(\d+)/)?.[1];
  await env.distribup_db.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
  return json({ success: true, message: 'Deleted' });
}

// ─── App Store Connect handlers ───────────────────────────────────────────────
async function handleAppstoreRegister(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const { udid, name, platform = 'IOS' } = await getJSON(req, env);
  if (!udid) return json({ error: 'UDID is required' }, 400);
  if (!env.ASC_ISSUER_ID || !env.ASC_KEY_ID || !env.ASC_PRIVATE_KEY) {
    return json({ error: 'App Store Connect API is not configured' }, 400);
  }
  const iss = env.ASC_ISSUER_ID, kid = env.ASC_KEY_ID;
  const headerB64 = btoa(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid }));
  const payloadObj = { iss, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 86400 * 7 };
  const payloadB64 = btoa(JSON.stringify(payloadObj));
  const encoder = new TextEncoder();
  const dataToSign = encoder.encode(`${headerB64}.${payloadB64}`);
  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8', encoder.encode(env.ASC_PRIVATE_KEY),
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  );
  const signature = await crypto.subtle.sign('ECDSA', cryptoKey, dataToSign);
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(signature)));
  const token = `${headerB64}.${payloadB64}.${sigB64}`;
  try {
    const resp = await fetch('https://api.appstoreconnect.apple.com/v1/devices', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: { type: 'devices', attributes: { name: name || udid, udid, platform } } })
    });
    const data = await resp.json();
    await env.distribup_db.prepare(
      'INSERT OR REPLACE INTO devices (udid, name, platform, registered_at, team_id) VALUES (?, ?, ?, ?, ?)'
    ).bind(udid, name, platform, new Date().toISOString(), user.team_id).run();
    return json({ success: true, deviceId: data.data?.id, udid, message: 'Device registered' });
  } catch (err) {
    return json({ error: 'Device registration failed', detail: err.message }, 500);
  }
}

async function handleAppstoreDevices(req, env) {
  const user = await authenticate(req, env);
  if (!user) return json({ error: 'Not authenticated' }, 401);
  const result = await env.distribup_db.prepare(
    'SELECT * FROM devices WHERE team_id = ? ORDER BY created_at DESC'
  ).bind(user.team_id).all();
  return json({ devices: result.results || [] });
}









const ADMIN_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI+CiAgICA8dGl0bGU+QWRtaW4gLSBEaXN0cmliVXA8L3RpdGxlPgogICAgPHN0eWxlPgogICAgICAgICogeyBtYXJnaW46IDA7IHBhZGRpbmc6IDA7IGJveC1zaXppbmc6IGJvcmRlci1ib3g7IH0KICAgICAgICBib2R5IHsgZm9udC1mYW1pbHk6IC1hcHBsZS1zeXN0ZW0sIEJsaW5rTWFjU3lzdGVtRm9udCwgJ1NlZ29lIFVJJywgUm9ib3RvLCBzYW5zLXNlcmlmOyBiYWNrZ3JvdW5kOiAjZjVmNWY3OyB9CiAgICAgICAgLnNpZGViYXIgeyBwb3NpdGlvbjogZml4ZWQ7IGxlZnQ6IDA7IHRvcDogMDsgd2lkdGg6IDIzMHB4OyBoZWlnaHQ6IDEwMHZoOyBiYWNrZ3JvdW5kOiAjMWExYTJlOyBjb2xvcjogd2hpdGU7IHBhZGRpbmc6IDIwcHg7IH0KICAgICAgICAuc2lkZWJhciBoMiB7IG1hcmdpbi1ib3R0b206IDMwcHg7IHBhZGRpbmctYm90dG9tOiAxNnB4OyBib3JkZXItYm90dG9tOiAxcHggc29saWQgIzMzMzsgZm9udC1zaXplOiAyMHB4OyB9CiAgICAgICAgLnNpZGViYXIgbmF2IGEgeyBkaXNwbGF5OiBibG9jazsgcGFkZGluZzogMTJweCAxNXB4OyBjb2xvcjogI2FhYTsgdGV4dC1kZWNvcmF0aW9uOiBub25lOyBib3JkZXItcmFkaXVzOiA4cHg7IG1hcmdpbi1ib3R0b206IDRweDsgY3Vyc29yOiBwb2ludGVyOyB9CiAgICAgICAgLnNpZGViYXIgbmF2IGE6aG92ZXIsIC5zaWRlYmFyIG5hdiBhLmFjdGl2ZSB7IGJhY2tncm91bmQ6ICM2NjdlZWE7IGNvbG9yOiB3aGl0ZTsgfQogICAgICAgIC5tYWluIHsgbWFyZ2luLWxlZnQ6IDIzMHB4OyBwYWRkaW5nOiAzMHB4OyB9CiAgICAgICAgLmhlYWRlciB7IGRpc3BsYXk6IGZsZXg7IGp1c3RpZnktY29udGVudDogc3BhY2UtYmV0d2VlbjsgYWxpZ24taXRlbXM6IGNlbnRlcjsgbWFyZ2luLWJvdHRvbTogMzBweDsgfQogICAgICAgIC5oZWFkZXIgaDEgeyBjb2xvcjogIzMzMzsgfQogICAgICAgIC5jYXJkIHsgYmFja2dyb3VuZDogd2hpdGU7IGJvcmRlci1yYWRpdXM6IDEycHg7IHBhZGRpbmc6IDI0cHg7IG1hcmdpbi1ib3R0b206IDIwcHg7IGJveC1zaGFkb3c6IDAgMnB4IDEwcHggcmdiYSgwLDAsMCwwLjA1KTsgfQogICAgICAgIC5jYXJkIGgzIHsgbWFyZ2luLWJvdHRvbTogMThweDsgY29sb3I6ICMzMzM7IH0KICAgICAgICAuc3RhdHMgeyBkaXNwbGF5OiBncmlkOyBncmlkLXRlbXBsYXRlLWNvbHVtbnM6IHJlcGVhdCg0LCAxZnIpOyBnYXA6IDE2cHg7IG1hcmdpbi1ib3R0b206IDI0cHg7IH0KICAgICAgICAuc3RhdC1jYXJkIHsgYmFja2dyb3VuZDogd2hpdGU7IHBhZGRpbmc6IDIwcHg7IGJvcmRlci1yYWRpdXM6IDEycHg7IGJveC1zaGFkb3c6IDAgMnB4IDEwcHggcmdiYSgwLDAsMCwwLjA1KTsgfQogICAgICAgIC5zdGF0LWNhcmQgLm51bWJlciB7IGZvbnQtc2l6ZTogMzJweDsgZm9udC13ZWlnaHQ6IDcwMDsgY29sb3I6ICM2NjdlZWE7IH0KICAgICAgICAuc3RhdC1jYXJkIC5sYWJlbCB7IGNvbG9yOiAjODg4OyBtYXJnaW4tdG9wOiA0cHg7IGZvbnQtc2l6ZTogMTNweDsgfQogICAgICAgIHRhYmxlIHsgd2lkdGg6IDEwMCU7IGJvcmRlci1jb2xsYXBzZTogY29sbGFwc2U7IH0KICAgICAgICB0aCwgdGQgeyBwYWRkaW5nOiAxMnB4IDEwcHg7IHRleHQtYWxpZ246IGxlZnQ7IGJvcmRlci1ib3R0b206IDFweCBzb2xpZCAjZWVlOyBmb250LXNpemU6IDE0cHg7IH0KICAgICAgICB0aCB7IGJhY2tncm91bmQ6ICNmOGY5ZmE7IGZvbnQtd2VpZ2h0OiA2MDA7IGNvbG9yOiAjNTU1OyB9CiAgICAgICAgLmJ0biB7IHBhZGRpbmc6IDdweCAxNnB4OyBib3JkZXI6IG5vbmU7IGJvcmRlci1yYWRpdXM6IDZweDsgY3Vyc29yOiBwb2ludGVyOyBmb250LXNpemU6IDEzcHg7IH0KICAgICAgICAuYnRuLXByaW1hcnkgeyBiYWNrZ3JvdW5kOiAjNjY3ZWVhOyBjb2xvcjogd2hpdGU7IH0KICAgICAgICAuYnRuLWRhbmdlciB7IGJhY2tncm91bmQ6ICNlNzRjM2M7IGNvbG9yOiB3aGl0ZTsgfQogICAgICAgIC5idG4tc20geyBwYWRkaW5nOiA0cHggMTBweDsgZm9udC1zaXplOiAxMnB4OyB9CiAgICAgICAgLmZvcm0tZ3JvdXAgeyBtYXJnaW4tYm90dG9tOiAxNnB4OyB9CiAgICAgICAgLmZvcm0tZ3JvdXAgbGFiZWwgeyBkaXNwbGF5OiBibG9jazsgbWFyZ2luLWJvdHRvbTogNnB4OyBjb2xvcjogIzU1NTsgZm9udC1zaXplOiAxM3B4OyBmb250LXdlaWdodDogNTAwOyB9CiAgICAgICAgLmZvcm0tZ3JvdXAgaW5wdXQsIC5mb3JtLWdyb3VwIHNlbGVjdCB7IHdpZHRoOiAxMDAlOyBwYWRkaW5nOiAxMHB4OyBib3JkZXI6IDFweCBzb2xpZCAjZGRkOyBib3JkZXItcmFkaXVzOiA4cHg7IGZvbnQtc2l6ZTogMTRweDsgfQogICAgICAgIC5wbGF0Zm9ybS1iYWRnZSB7IHBhZGRpbmc6IDNweCA4cHg7IGJvcmRlci1yYWRpdXM6IDRweDsgZm9udC1zaXplOiAxMXB4OyBmb250LXdlaWdodDogNjAwOyB9CiAgICAgICAgLnBsYXRmb3JtLWJhZGdlLmlvcyB7IGJhY2tncm91bmQ6ICNlM2YyZmQ7IGNvbG9yOiAjMTU2NWMwOyB9CiAgICAgICAgLnBsYXRmb3JtLWJhZGdlLmFuZHJvaWQgeyBiYWNrZ3JvdW5kOiAjZThmNWU5OyBjb2xvcjogIzJlN2QzMjsgfQogICAgICAgIC5yb2xlLWJhZGdlIHsgcGFkZGluZzogM3B4IDhweDsgYm9yZGVyLXJhZGl1czogNHB4OyBmb250LXNpemU6IDExcHg7IGZvbnQtd2VpZ2h0OiA2MDA7IH0KICAgICAgICAucm9sZS1iYWRnZS5hZG1pbiB7IGJhY2tncm91bmQ6ICNmZmYzZTA7IGNvbG9yOiAjZTY1MTAwOyB9CiAgICAgICAgLnJvbGUtYmFkZ2UudXNlciB7IGJhY2tncm91bmQ6ICNmNWY1ZjU7IGNvbG9yOiAjNjY2OyB9CiAgICAgICAgLm1vZGFsIHsgZGlzcGxheTogbm9uZTsgcG9zaXRpb246IGZpeGVkOyB0b3A6IDA7IGxlZnQ6IDA7IHdpZHRoOiAxMDAlOyBoZWlnaHQ6IDEwMCU7IGJhY2tncm91bmQ6IHJnYmEoMCwwLDAsMC41KTsgei1pbmRleDogMTAwMDsgfQogICAgICAgIC5tb2RhbC1jb250ZW50IHsgYmFja2dyb3VuZDogd2hpdGU7IHdpZHRoOiA5MCU7IG1heC13aWR0aDogNTYwcHg7IG1hcmdpbjogNTBweCBhdXRvOyBwYWRkaW5nOiAyOHB4OyBib3JkZXItcmFkaXVzOiAxMnB4OyB9CiAgICAgICAgLmNsb3NlIHsgZmxvYXQ6IHJpZ2h0OyBmb250LXNpemU6IDI0cHg7IGN1cnNvcjogcG9pbnRlcjsgY29sb3I6ICNhYWE7IH0KICAgICAgICAuY2xvc2U6aG92ZXIgeyBjb2xvcjogIzMzMzsgfQogICAgICAgIC5wYWdlIHsgZGlzcGxheTogbm9uZTsgfQogICAgICAgIC5wYWdlLmFjdGl2ZSB7IGRpc3BsYXk6IGJsb2NrOyB9CiAgICAgICAgLnRvYXN0IHsgcG9zaXRpb246IGZpeGVkOyB0b3A6IDIwcHg7IHJpZ2h0OiAyMHB4OyBwYWRkaW5nOiAxNHB4IDIwcHg7IGJvcmRlci1yYWRpdXM6IDhweDsgY29sb3I6IHdoaXRlOyBmb250LXNpemU6IDE0cHg7IHotaW5kZXg6IDIwMDA7IGRpc3BsYXk6IG5vbmU7IH0KICAgICAgICAudG9hc3Qub2sgeyBiYWNrZ3JvdW5kOiAjMjdhZTYwOyB9CiAgICAgICAgLnRvYXN0LmVyciB7IGJhY2tncm91bmQ6ICNlNzRjM2M7IH0KICAgIDwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+CiAgICA8ZGl2IGNsYXNzPSJzaWRlYmFyIj4KICAgICAgICA8aDI+8J+TpiBEaXN0cmliVXA8L2gyPgogICAgICAgIDxuYXY+CiAgICAgICAgICAgIDxhIGNsYXNzPSJuYXYtbGluayBhY3RpdmUiIGRhdGEtcGFnZT0iZGFzaGJvYXJkIj5EYXNoYm9hcmQ8L2E+CiAgICAgICAgICAgIDxhIGNsYXNzPSJuYXYtbGluayIgZGF0YS1wYWdlPSJhcHBzIj5BcHBzPC9hPgogICAgICAgICAgICA8YSBjbGFzcz0ibmF2LWxpbmsiIGRhdGEtcGFnZT0iZGV2aWNlcyI+RGV2aWNlczwvYT4KICAgICAgICAgICAgPGEgY2xhc3M9Im5hdi1saW5rIiBkYXRhLXBhZ2U9InVzZXJzIj5Vc2VyczwvYT4KICAgICAgICAgICAgPGEgY2xhc3M9Im5hdi1saW5rIiBkYXRhLXBhZ2U9InNldHRpbmdzIj5TZXR0aW5nczwvYT4KICAgICAgICA8L25hdj4KICAgIDwvZGl2PgoKICAgIDxkaXYgY2xhc3M9Im1haW4iPgogICAgICAgIDxkaXYgY2xhc3M9ImhlYWRlciI+CiAgICAgICAgICAgIDxoMSBpZD0icGFnZVRpdGxlIj5EYXNoYm9hcmQ8L2gxPgogICAgICAgICAgICA8ZGl2PgogICAgICAgICAgICAgICAgPHNwYW4gaWQ9InVzZXJJbmZvIiBzdHlsZT0ibWFyZ2luLXJpZ2h0OjE2cHg7Y29sb3I6IzY2NiI+PC9zcGFuPgogICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1kYW5nZXIiIG9uY2xpY2s9ImxvZ291dCgpIj5Mb2dvdXQ8L2J1dHRvbj4KICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CgogICAgICAgIDxkaXYgaWQ9ImRhc2hib2FyZCIgY2xhc3M9InBhZ2UgYWN0aXZlIj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0ic3RhdHMiPgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0ic3RhdC1jYXJkIj48ZGl2IGNsYXNzPSJudW1iZXIiIGlkPSJzdEFwcHMiPuKAkzwvZGl2PjxkaXYgY2xhc3M9ImxhYmVsIj5BcHBzPC9kaXY+PC9kaXY+CiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJzdGF0LWNhcmQiPjxkaXYgY2xhc3M9Im51bWJlciIgaWQ9InN0RGV2aWNlcyI+4oCTPC9kaXY+PGRpdiBjbGFzcz0ibGFiZWwiPkRldmljZXM8L2Rpdj48L2Rpdj4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InN0YXQtY2FyZCI+PGRpdiBjbGFzcz0ibnVtYmVyIiBpZD0ic3REb3dubG9hZHMiPuKAkzwvZGl2PjxkaXYgY2xhc3M9ImxhYmVsIj5Eb3dubG9hZHM8L2Rpdj48L2Rpdj4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9InN0YXQtY2FyZCI+PGRpdiBjbGFzcz0ibnVtYmVyIiBpZD0ic3RVc2VycyI+4oCTPC9kaXY+PGRpdiBjbGFzcz0ibGFiZWwiPlVzZXJzPC9kaXY+PC9kaXY+CiAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICAgICAgICAgIDxoMz5SZWNlbnQgdXBsb2FkczwvaDM+CiAgICAgICAgICAgICAgICA8dGFibGU+CiAgICAgICAgICAgICAgICAgICAgPHRoZWFkPjx0cj48dGg+QXBwPC90aD48dGg+RmlsZTwvdGg+PHRoPlNpemU8L3RoPjx0aD5UaW1lPC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgICAgICAgICAgICAgPHRib2R5IGlkPSJyZWNlbnRCb2R5Ij48L3Rib2R5PgogICAgICAgICAgICAgICAgPC90YWJsZT4KICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgPC9kaXY+CgogICAgICAgIDxkaXYgaWQ9ImFwcHMiIGNsYXNzPSJwYWdlIj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47YWxpZ24taXRlbXM6Y2VudGVyO21hcmdpbi1ib3R0b206MTZweCI+CiAgICAgICAgICAgICAgICAgICAgPGgzIHN0eWxlPSJtYXJnaW46MCI+QXBwczwvaDM+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJzaG93QXBwTW9kYWwoKSI+KyBOZXcgQXBwPC9idXR0b24+CiAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgIDx0YWJsZT4KICAgICAgICAgICAgICAgICAgICA8dGhlYWQ+PHRyPjx0aD5JRDwvdGg+PHRoPk5hbWU8L3RoPjx0aD5QbGF0Zm9ybTwvdGg+PHRoPkJ1bmRsZSBJRDwvdGg+PHRoPlZlcnNpb248L3RoPjx0aD5BY3Rpb25zPC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgICAgICAgICAgICAgPHRib2R5IGlkPSJhcHBzQm9keSI+PC90Ym9keT4KICAgICAgICAgICAgICAgIDwvdGFibGU+CiAgICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgoKICAgICAgICA8ZGl2IGlkPSJkZXZpY2VzIiBjbGFzcz0icGFnZSI+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9ImNhcmQiPgogICAgICAgICAgICAgICAgPGgzPkRldmljZXM8L2gzPgogICAgICAgICAgICAgICAgPHRhYmxlPgogICAgICAgICAgICAgICAgICAgIDx0aGVhZD48dHI+PHRoPlVESUQ8L3RoPjx0aD5OYW1lPC90aD48dGg+UGxhdGZvcm08L3RoPjx0aD5SZWdpc3RlcmVkPC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgICAgICAgICAgICAgPHRib2R5IGlkPSJkZXZpY2VzQm9keSI+PC90Ym9keT4KICAgICAgICAgICAgICAgIDwvdGFibGU+CiAgICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgoKICAgICAgICA8ZGl2IGlkPSJ1c2VycyIgY2xhc3M9InBhZ2UiPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4KICAgICAgICAgICAgICAgIDxkaXYgc3R5bGU9ImRpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjthbGlnbi1pdGVtczpjZW50ZXI7bWFyZ2luLWJvdHRvbToxNnB4Ij4KICAgICAgICAgICAgICAgICAgICA8aDMgc3R5bGU9Im1hcmdpbjowIj5Vc2VyczwvaDM+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IiBvbmNsaWNrPSJzaG93VXNlck1vZGFsKCkiPisgTmV3IFVzZXI8L2J1dHRvbj4KICAgICAgICAgICAgICAgIDwvZGl2PgogICAgICAgICAgICAgICAgPHRhYmxlPgogICAgICAgICAgICAgICAgICAgIDx0aGVhZD48dHI+PHRoPklEPC90aD48dGg+VXNlcm5hbWU8L3RoPjx0aD5FbWFpbDwvdGg+PHRoPlJvbGU8L3RoPjx0aD5BY3RpdmU8L3RoPjx0aD5BY3Rpb25zPC90aD48L3RyPjwvdGhlYWQ+CiAgICAgICAgICAgICAgICAgICAgPHRib2R5IGlkPSJ1c2Vyc0JvZHkiPjwvdGJvZHk+CiAgICAgICAgICAgICAgICA8L3RhYmxlPgogICAgICAgICAgICA8L2Rpdj4KICAgICAgICA8L2Rpdj4KCiAgICAgICAgPGRpdiBpZD0ic2V0dGluZ3MiIGNsYXNzPSJwYWdlIj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZCIgc3R5bGU9Im1heC13aWR0aDo0ODBweCI+CiAgICAgICAgICAgICAgICA8aDM+Q2hhbmdlIHBhc3N3b3JkPC9oMz4KICAgICAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAiPjxsYWJlbD5DdXJyZW50IHBhc3N3b3JkPC9sYWJlbD48aW5wdXQgdHlwZT0icGFzc3dvcmQiIGlkPSJvbGRQd2QiPjwvZGl2PgogICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+PGxhYmVsPk5ldyBwYXNzd29yZDwvbGFiZWw+PGlucHV0IHR5cGU9InBhc3N3b3JkIiBpZD0ibmV3UHdkIj48L2Rpdj4KICAgICAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0iY2hhbmdlUGFzc3dvcmQoKSI+VXBkYXRlPC9idXR0b24+CiAgICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgogICAgPC9kaXY+CgogICAgPGRpdiBpZD0iYXBwTW9kYWwiIGNsYXNzPSJtb2RhbCI+CiAgICAgICAgPGRpdiBjbGFzcz0ibW9kYWwtY29udGVudCI+CiAgICAgICAgICAgIDxzcGFuIGNsYXNzPSJjbG9zZSIgb25jbGljaz0iY2xvc2VNb2RhbCgnYXBwTW9kYWwnKSI+JnRpbWVzOzwvc3Bhbj4KICAgICAgICAgICAgPGgzIHN0eWxlPSJtYXJnaW4tYm90dG9tOjE2cHgiPk5ldyBBcHA8L2gzPgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJmb3JtLWdyb3VwIj48bGFiZWw+QXBwIG5hbWU8L2xhYmVsPjxpbnB1dCBpZD0iZk5hbWUiIHBsYWNlaG9sZGVyPSJNeSBBcHAiPjwvZGl2PgogICAgICAgICAgICA8ZGl2IGNsYXNzPSJmb3JtLWdyb3VwIj48bGFiZWw+UGxhdGZvcm08L2xhYmVsPgogICAgICAgICAgICAgICAgPHNlbGVjdCBpZD0iZlBsYXRmb3JtIj48b3B0aW9uIHZhbHVlPSJpb3MiPmlPUzwvb3B0aW9uPjxvcHRpb24gdmFsdWU9ImFuZHJvaWQiPkFuZHJvaWQ8L29wdGlvbj48L3NlbGVjdD4KICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAiPjxsYWJlbD5CdW5kbGUgSUQ8L2xhYmVsPjxpbnB1dCBpZD0iZkJ1bmRsZSIgcGxhY2Vob2xkZXI9ImNvbS5leGFtcGxlLmFwcCI+PC9kaXY+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAiPjxsYWJlbD5WZXJzaW9uPC9sYWJlbD48aW5wdXQgaWQ9ImZWZXJzaW9uIiB2YWx1ZT0iMS4wLjAiPjwvZGl2PgogICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLXByaW1hcnkiIG9uY2xpY2s9ImNyZWF0ZUFwcCgpIj5DcmVhdGU8L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgIDwvZGl2PgoKICAgIDxkaXYgaWQ9InVzZXJNb2RhbCIgY2xhc3M9Im1vZGFsIj4KICAgICAgICA8ZGl2IGNsYXNzPSJtb2RhbC1jb250ZW50Ij4KICAgICAgICAgICAgPHNwYW4gY2xhc3M9ImNsb3NlIiBvbmNsaWNrPSJjbG9zZU1vZGFsKCd1c2VyTW9kYWwnKSI+JnRpbWVzOzwvc3Bhbj4KICAgICAgICAgICAgPGgzIHN0eWxlPSJtYXJnaW4tYm90dG9tOjE2cHgiPk5ldyBVc2VyPC9oMz4KICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+PGxhYmVsPlVzZXJuYW1lPC9sYWJlbD48aW5wdXQgaWQ9InVOYW1lIj48L2Rpdj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+PGxhYmVsPkVtYWlsPC9sYWJlbD48aW5wdXQgaWQ9InVFbWFpbCI+PC9kaXY+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0tZ3JvdXAiPjxsYWJlbD5QYXNzd29yZCAobGVhdmUgYmxhbmsgdG8gYXV0by1nZW5lcmF0ZSk8L2xhYmVsPjxpbnB1dCB0eXBlPSJwYXNzd29yZCIgaWQ9InVQYXNzIj48L2Rpdj4KICAgICAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+PGxhYmVsPlJvbGU8L2xhYmVsPgogICAgICAgICAgICAgICAgPHNlbGVjdCBpZD0idVJvbGUiPjxvcHRpb24gdmFsdWU9InVzZXIiPlVzZXI8L29wdGlvbj48b3B0aW9uIHZhbHVlPSJhZG1pbiI+QWRtaW48L29wdGlvbj48L3NlbGVjdD4KICAgICAgICAgICAgPC9kaXY+CiAgICAgICAgICAgIDxidXR0b24gY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgb25jbGljaz0iY3JlYXRlVXNlcigpIj5DcmVhdGU8L2J1dHRvbj4KICAgICAgICA8L2Rpdj4KICAgIDwvZGl2PgoKICAgIDxkaXYgY2xhc3M9InRvYXN0IiBpZD0idG9hc3QiPjwvZGl2PgoKICAgIDxzY3JpcHQ+CiAgICAgICAgY29uc3QgQVBJID0gJy9hcGknOwogICAgICAgIGxldCB0b2tlbiA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCd0b2tlbicpOwogICAgICAgIGlmICghdG9rZW4pIGxvY2F0aW9uLmhyZWYgPSAnL2xvZ2luLmh0bWwnOwogICAgICAgIGxldCBtZSA9IG51bGw7CgogICAgICAgIGFzeW5jIGZ1bmN0aW9uIGFwaShwYXRoLCBvcHRzID0ge30pIHsKICAgICAgICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goQVBJICsgcGF0aCwgewogICAgICAgICAgICAgICAgLi4ub3B0cywKICAgICAgICAgICAgICAgIGhlYWRlcnM6IHsgJ0F1dGhvcml6YXRpb24nOiAnQmVhcmVyICcgKyB0b2tlbiwgLi4uKG9wdHMuaGVhZGVycyB8fCB7fSkgfQogICAgICAgICAgICB9KTsKICAgICAgICAgICAgaWYgKHJlcy5zdGF0dXMgPT09IDQwMSkgeyBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgndG9rZW4nKTsgbG9jYXRpb24uaHJlZiA9ICcvbG9naW4uaHRtbCc7IH0KICAgICAgICAgICAgcmV0dXJuIHJlcy5qc29uKCk7CiAgICAgICAgfQoKICAgICAgICBmdW5jdGlvbiB0b2FzdChtc2csIG9rID0gdHJ1ZSkgewogICAgICAgICAgICBjb25zdCB0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3RvYXN0Jyk7CiAgICAgICAgICAgIHQuY2xhc3NOYW1lID0gJ3RvYXN0ICcgKyAob2sgPyAnb2snIDogJ2VycicpOwogICAgICAgICAgICB0LnRleHRDb250ZW50ID0gbXNnOwogICAgICAgICAgICB0LnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOwogICAgICAgICAgICBzZXRUaW1lb3V0KCgpID0+IHQuc3R5bGUuZGlzcGxheSA9ICdub25lJywgMjUwMCk7CiAgICAgICAgfQoKICAgICAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcubmF2LWxpbmsnKS5mb3JFYWNoKGEgPT4gewogICAgICAgICAgICBhLm9uY2xpY2sgPSAoKSA9PiB7CiAgICAgICAgICAgICAgICBkb2N1bWVudC5xdWVyeVNlbGVjdG9yQWxsKCcubmF2LWxpbmsnKS5mb3JFYWNoKHggPT4geC5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKSk7CiAgICAgICAgICAgICAgICBhLmNsYXNzTGlzdC5hZGQoJ2FjdGl2ZScpOwogICAgICAgICAgICAgICAgY29uc3QgcCA9IGEuZGF0YXNldC5wYWdlOwogICAgICAgICAgICAgICAgZG9jdW1lbnQucXVlcnlTZWxlY3RvckFsbCgnLnBhZ2UnKS5mb3JFYWNoKHggPT4geC5jbGFzc0xpc3QucmVtb3ZlKCdhY3RpdmUnKSk7CiAgICAgICAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChwKS5jbGFzc0xpc3QuYWRkKCdhY3RpdmUnKTsKICAgICAgICAgICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwYWdlVGl0bGUnKS50ZXh0Q29udGVudCA9IGEudGV4dENvbnRlbnQudHJpbSgpOwogICAgICAgICAgICAgICAgbG9hZFBhZ2UocCk7CiAgICAgICAgICAgIH07CiAgICAgICAgfSk7CgogICAgICAgIGZ1bmN0aW9uIGxvYWRQYWdlKHApIHsKICAgICAgICAgICAgaWYgKHAgPT09ICdkYXNoYm9hcmQnKSBsb2FkRGFzaGJvYXJkKCk7CiAgICAgICAgICAgIGlmIChwID09PSAnYXBwcycpIGxvYWRBcHBzKCk7CiAgICAgICAgICAgIGlmIChwID09PSAnZGV2aWNlcycpIGxvYWREZXZpY2VzKCk7CiAgICAgICAgICAgIGlmIChwID09PSAndXNlcnMnICYmIG1lLnJvbGUgPT09ICdhZG1pbicpIGxvYWRVc2VycygpOwogICAgICAgIH0KCiAgICAgICAgYXN5bmMgZnVuY3Rpb24gbG9hZE1lKCkgewogICAgICAgICAgICBjb25zdCBkID0gYXdhaXQgYXBpKCcvYXV0aC9tZScpOwogICAgICAgICAgICBtZSA9IGQudXNlcjsKICAgICAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3VzZXJJbmZvJykudGV4dENvbnRlbnQgPSBtZS51c2VybmFtZSArIChtZS5yb2xlID09PSAnYWRtaW4nID8gJyAoYWRtaW4pJyA6ICcnKTsKICAgICAgICAgICAgaWYgKG1lLnJvbGUgIT09ICdhZG1pbicpIGRvY3VtZW50LnF1ZXJ5U2VsZWN0b3IoJ1tkYXRhLXBhZ2U9dXNlcnNdJykuc3R5bGUuZGlzcGxheSA9ICdub25lJzsKICAgICAgICB9CgogICAgICAgIGFzeW5jIGZ1bmN0aW9uIGxvYWREYXNoYm9hcmQoKSB7CiAgICAgICAgICAgIGNvbnN0IFtzLCByXSA9IGF3YWl0IFByb21pc2UuYWxsKFthcGkoJy9zdGF0cycpLCBhcGkoJy91cGxvYWRzL3JlY2VudCcpXSk7CiAgICAgICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzdEFwcHMnKS50ZXh0Q29udGVudCA9IHMudG90YWxBcHBzOwogICAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3REZXZpY2VzJykudGV4dENvbnRlbnQgPSBzLnRvdGFsRGV2aWNlczsKICAgICAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3N0RG93bmxvYWRzJykudGV4dENvbnRlbnQgPSBzLnRvdGFsRG93bmxvYWRzOwogICAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnc3RVc2VycycpLnRleHRDb250ZW50ID0gcy50b3RhbFVzZXJzOwogICAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgncmVjZW50Qm9keScpLmlubmVySFRNTCA9IChyLnVwbG9hZHMgfHwgW10pLm1hcCh1ID0+IGAKICAgICAgICAgICAgICAgIDx0cj48dGQ+JHt1LmFwcF9uYW1lfTwvdGQ+PHRkPiR7dS5vcmlnaW5hbF9uYW1lIHx8IHUuZmlsZW5hbWV9PC90ZD4KICAgICAgICAgICAgICAgIDx0ZD4keyh1LmZpbGVfc2l6ZS8xMDI0LzEwMjQpLnRvRml4ZWQoMSl9IE1CPC90ZD4KICAgICAgICAgICAgICAgIDx0ZD4ke25ldyBEYXRlKHUuY3JlYXRlZF9hdCkudG9Mb2NhbGVTdHJpbmcoKX08L3RkPjwvdHI+YCkuam9pbignJykgfHwKICAgICAgICAgICAgICAgICc8dHI+PHRkIGNvbHNwYW49IjQiIHN0eWxlPSJjb2xvcjojOTk5O3RleHQtYWxpZ246Y2VudGVyIj5ObyB1cGxvYWRzIHlldDwvdGQ+PC90cj4nOwogICAgICAgIH0KCiAgICAgICAgYXN5bmMgZnVuY3Rpb24gbG9hZEFwcHMoKSB7CiAgICAgICAgICAgIGNvbnN0IGQgPSBhd2FpdCBhcGkoJy9hcHBzJyk7CiAgICAgICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdhcHBzQm9keScpLmlubmVySFRNTCA9IChkLmFwcHMgfHwgW10pLm1hcChhID0+IGAKICAgICAgICAgICAgICAgIDx0cj48dGQ+JHthLmlkfTwvdGQ+PHRkPiR7YS5uYW1lfTwvdGQ+CiAgICAgICAgICAgICAgICA8dGQ+PHNwYW4gY2xhc3M9InBsYXRmb3JtLWJhZGdlICR7YS5wbGF0Zm9ybX0iPiR7YS5wbGF0Zm9ybX08L3NwYW4+PC90ZD4KICAgICAgICAgICAgICAgIDx0ZD4ke2EuYnVuZGxlX2lkfTwvdGQ+PHRkPiR7YS52ZXJzaW9ufTwvdGQ+CiAgICAgICAgICAgICAgICA8dGQ+CiAgICAgICAgICAgICAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1wcmltYXJ5IGJ0bi1zbSIgb25jbGljaz0ibG9jYXRpb24uaHJlZj0nL3VwbG9hZC5odG1sP2lkPSR7YS5pZH0nIj5VcGxvYWQ8L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgICA8YnV0dG9uIGNsYXNzPSJidG4gYnRuLWRhbmdlciBidG4tc20iIG9uY2xpY2s9ImRlbEFwcCgke2EuaWR9KSI+RGVsZXRlPC9idXR0b24+CiAgICAgICAgICAgICAgICA8L3RkPjwvdHI+YCkuam9pbignJykgfHwKICAgICAgICAgICAgICAgICc8dHI+PHRkIGNvbHNwYW49IjYiIHN0eWxlPSJjb2xvcjojOTk5O3RleHQtYWxpZ246Y2VudGVyIj5ObyBhcHBzIHlldDwvdGQ+PC90cj4nOwogICAgICAgIH0KCiAgICAgICAgYXN5bmMgZnVuY3Rpb24gbG9hZERldmljZXMoKSB7CiAgICAgICAgICAgIGNvbnN0IGQgPSBhd2FpdCBhcGkoJy9hcHBzdG9yZS9kZXZpY2VzJyk7CiAgICAgICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdkZXZpY2VzQm9keScpLmlubmVySFRNTCA9IChkLmRldmljZXMgfHwgW10pLm1hcCh4ID0+IGAKICAgICAgICAgICAgICAgIDx0cj48dGQ+JHt4LnVkaWR9PC90ZD48dGQ+JHt4Lm5hbWV8fCcnfTwvdGQ+PHRkPiR7eC5wbGF0Zm9ybXx8Jyd9PC90ZD4KICAgICAgICAgICAgICAgIDx0ZD4ke3gucmVnaXN0ZXJlZF9hdCA/IG5ldyBEYXRlKHgucmVnaXN0ZXJlZF9hdCkudG9Mb2NhbGVEYXRlU3RyaW5nKCkgOiAnJ308L3RkPjwvdHI+YCkuam9pbignJykgfHwKICAgICAgICAgICAgICAgICc8dHI+PHRkIGNvbHNwYW49IjQiIHN0eWxlPSJjb2xvcjojOTk5O3RleHQtYWxpZ246Y2VudGVyIj5ObyBkZXZpY2VzPC90ZD48L3RyPic7CiAgICAgICAgfQoKICAgICAgICBhc3luYyBmdW5jdGlvbiBsb2FkVXNlcnMoKSB7CiAgICAgICAgICAgIGNvbnN0IGQgPSBhd2FpdCBhcGkoJy9hZG1pbi91c2VycycpOwogICAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndXNlcnNCb2R5JykuaW5uZXJIVE1MID0gKGQuZGF0YSB8fCBbXSkubWFwKHUgPT4gYAogICAgICAgICAgICAgICAgPHRyPjx0ZD4ke3UuaWR9PC90ZD48dGQ+JHt1LnVzZXJuYW1lfTwvdGQ+PHRkPiR7dS5lbWFpbHx8Jyd9PC90ZD4KICAgICAgICAgICAgICAgIDx0ZD48c3BhbiBjbGFzcz0icm9sZS1iYWRnZSAke3Uucm9sZX0iPiR7dS5yb2xlfTwvc3Bhbj48L3RkPgogICAgICAgICAgICAgICAgPHRkPiR7dS5pc19hY3RpdmUgPyAn4pyTJyA6ICfinJcnfTwvdGQ+CiAgICAgICAgICAgICAgICA8dGQ+PGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1kYW5nZXIgYnRuLXNtIiBvbmNsaWNrPSJkZWxVc2VyKCR7dS5pZH0pIj5EZWxldGU8L2J1dHRvbj48L3RkPjwvdHI+YCkuam9pbignJyk7CiAgICAgICAgfQoKICAgICAgICBmdW5jdGlvbiBzaG93QXBwTW9kYWwoKSB7IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdhcHBNb2RhbCcpLnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOyB9CiAgICAgICAgZnVuY3Rpb24gc2hvd1VzZXJNb2RhbCgpIHsgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3VzZXJNb2RhbCcpLnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOyB9CiAgICAgICAgZnVuY3Rpb24gY2xvc2VNb2RhbChpZCkgeyBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCkuc3R5bGUuZGlzcGxheSA9ICdub25lJzsgfQoKICAgICAgICBhc3luYyBmdW5jdGlvbiBjcmVhdGVBcHAoKSB7CiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSB7CiAgICAgICAgICAgICAgICBuYW1lOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZk5hbWUnKS52YWx1ZSwKICAgICAgICAgICAgICAgIHBsYXRmb3JtOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZlBsYXRmb3JtJykudmFsdWUsCiAgICAgICAgICAgICAgICBidW5kbGVfaWQ6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdmQnVuZGxlJykudmFsdWUsCiAgICAgICAgICAgICAgICB2ZXJzaW9uOiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZlZlcnNpb24nKS52YWx1ZQogICAgICAgICAgICB9OwogICAgICAgICAgICBjb25zdCBkID0gYXdhaXQgYXBpKCcvYXBwcycsIHsgbWV0aG9kOiAnUE9TVCcsIGhlYWRlcnM6IHsgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyB9LCBib2R5OiBKU09OLnN0cmluZ2lmeShib2R5KSB9KTsKICAgICAgICAgICAgaWYgKGQuYXBwKSB7IHRvYXN0KCdBcHAgY3JlYXRlZCcpOyBjbG9zZU1vZGFsKCdhcHBNb2RhbCcpOyBsb2FkQXBwcygpOyB9CiAgICAgICAgICAgIGVsc2UgdG9hc3QoZC5lcnJvciB8fCAnRmFpbGVkJywgZmFsc2UpOwogICAgICAgIH0KCiAgICAgICAgYXN5bmMgZnVuY3Rpb24gZGVsQXBwKGlkKSB7CiAgICAgICAgICAgIGlmICghY29uZmlybSgnRGVsZXRlIHRoaXMgYXBwPycpKSByZXR1cm47CiAgICAgICAgICAgIGF3YWl0IGFwaSgnL2FwcHMvJyArIGlkLCB7IG1ldGhvZDogJ0RFTEVURScgfSk7CiAgICAgICAgICAgIGxvYWRBcHBzKCk7CiAgICAgICAgfQoKICAgICAgICBhc3luYyBmdW5jdGlvbiBjcmVhdGVVc2VyKCkgewogICAgICAgICAgICBjb25zdCBwYXNzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3VQYXNzJykudmFsdWU7CiAgICAgICAgICAgIGNvbnN0IGJvZHkgPSB7CiAgICAgICAgICAgICAgICB1c2VybmFtZTogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3VOYW1lJykudmFsdWUsCiAgICAgICAgICAgICAgICBlbWFpbDogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3VFbWFpbCcpLnZhbHVlLAogICAgICAgICAgICAgICAgcm9sZTogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3VSb2xlJykudmFsdWUKICAgICAgICAgICAgfTsKICAgICAgICAgICAgaWYgKHBhc3MpIGJvZHkucGFzc3dvcmQgPSBwYXNzOwogICAgICAgICAgICBjb25zdCBkID0gYXdhaXQgYXBpKCcvYWRtaW4vdXNlcnMnLCB7IG1ldGhvZDogJ1BPU1QnLCBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vanNvbicgfSwgYm9keTogSlNPTi5zdHJpbmdpZnkoYm9keSkgfSk7CiAgICAgICAgICAgIGlmIChkLnN1Y2Nlc3MpIHsKICAgICAgICAgICAgICAgIHRvYXN0KHBhc3MgPyAnVXNlciBjcmVhdGVkJyA6ICdVc2VyIGNyZWF0ZWQgd2l0aCByYW5kb20gcGFzc3dvcmQnKTsKICAgICAgICAgICAgICAgIGNsb3NlTW9kYWwoJ3VzZXJNb2RhbCcpOyBsb2FkVXNlcnMoKTsKICAgICAgICAgICAgfSBlbHNlIHRvYXN0KGQuZXJyb3IgfHwgJ0ZhaWxlZCcsIGZhbHNlKTsKICAgICAgICB9CgogICAgICAgIGFzeW5jIGZ1bmN0aW9uIGRlbFVzZXIoaWQpIHsKICAgICAgICAgICAgaWYgKCFjb25maXJtKCdEZWxldGUgdXNlcj8nKSkgcmV0dXJuOwogICAgICAgICAgICBhd2FpdCBhcGkoJy9hZG1pbi91c2Vycy8nICsgaWQsIHsgbWV0aG9kOiAnREVMRVRFJyB9KTsKICAgICAgICAgICAgbG9hZFVzZXJzKCk7CiAgICAgICAgfQoKICAgICAgICBhc3luYyBmdW5jdGlvbiBjaGFuZ2VQYXNzd29yZCgpIHsKICAgICAgICAgICAgY29uc3Qgb2xkUGFzc3dvcmQgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnb2xkUHdkJykudmFsdWU7CiAgICAgICAgICAgIGNvbnN0IG5ld1Bhc3N3b3JkID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ25ld1B3ZCcpLnZhbHVlOwogICAgICAgICAgICBjb25zdCBkID0gYXdhaXQgYXBpKCcvYXV0aC9wYXNzd29yZCcsIHsgbWV0aG9kOiAnUFVUJywgaGVhZGVyczogeyAnQ29udGVudC1UeXBlJzogJ2FwcGxpY2F0aW9uL2pzb24nIH0sIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgb2xkUGFzc3dvcmQsIG5ld1Bhc3N3b3JkIH0pIH0pOwogICAgICAgICAgICBpZiAoZC5tZXNzYWdlKSB7IHRvYXN0KCdQYXNzd29yZCB1cGRhdGVkJyk7IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdvbGRQd2QnKS52YWx1ZT0nJzsgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ25ld1B3ZCcpLnZhbHVlPScnOyB9CiAgICAgICAgICAgIGVsc2UgdG9hc3QoZC5lcnJvciB8fCAnRmFpbGVkJywgZmFsc2UpOwogICAgICAgIH0KCiAgICAgICAgZnVuY3Rpb24gbG9nb3V0KCkgeyBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgndG9rZW4nKTsgbG9jYXRpb24uaHJlZiA9ICcvJzsgfQoKICAgICAgICBsb2FkTWUoKS50aGVuKCgpID0+IGxvYWREYXNoYm9hcmQoKSk7CiAgICA8L3NjcmlwdD4KPC9ib2R5Pgo8L2h0bWw+Cg==";

const LOGIN_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI+CiAgICA8dGl0bGU+U2lnbiBJbiAtIERpc3RyaWJVcDwvdGl0bGU+CiAgICA8c3R5bGU+CiAgICAgICAgKiB7IG1hcmdpbjogMDsgcGFkZGluZzogMDsgYm94LXNpemluZzogYm9yZGVyLWJveDsgfQogICAgICAgIGJvZHkgeyBmb250LWZhbWlseTogLWFwcGxlLXN5c3RlbSwgQmxpbmtNYWNTeXN0ZW1Gb250LCAnU2Vnb2UgVUknLCBSb2JvdG8sIHNhbnMtc2VyaWY7IGJhY2tncm91bmQ6IGxpbmVhci1ncmFkaWVudCgxMzVkZWcsICM2NjdlZWEgMCUsICM3NjRiYTIgMTAwJSk7IGhlaWdodDogMTAwdmg7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGp1c3RpZnktY29udGVudDogY2VudGVyOyB9CiAgICAgICAgLmxvZ2luLWJveCB7IGJhY2tncm91bmQ6IHdoaXRlOyBwYWRkaW5nOiA0MHB4OyBib3JkZXItcmFkaXVzOiAxNnB4OyBib3gtc2hhZG93OiAwIDEwcHggNDBweCByZ2JhKDAsMCwwLDAuMik7IHdpZHRoOiAxMDAlOyBtYXgtd2lkdGg6IDQwMHB4OyB9CiAgICAgICAgLmxvZ2luLWJveCBoMiB7IHRleHQtYWxpZ246IGNlbnRlcjsgbWFyZ2luLWJvdHRvbTogMzBweDsgY29sb3I6ICMzMzM7IH0KICAgICAgICAuZm9ybS1ncm91cCB7IG1hcmdpbi1ib3R0b206IDIwcHg7IH0KICAgICAgICAuZm9ybS1ncm91cCBsYWJlbCB7IGRpc3BsYXk6IGJsb2NrOyBtYXJnaW4tYm90dG9tOiA4cHg7IGNvbG9yOiAjNjY2OyB9CiAgICAgICAgLmZvcm0tZ3JvdXAgaW5wdXQgeyB3aWR0aDogMTAwJTsgcGFkZGluZzogMTRweDsgYm9yZGVyOiAycHggc29saWQgI2UwZTBlMDsgYm9yZGVyLXJhZGl1czogOHB4OyBmb250LXNpemU6IDE2cHg7IHRyYW5zaXRpb246IGJvcmRlci1jb2xvciAwLjNzOyB9CiAgICAgICAgLmZvcm0tZ3JvdXAgaW5wdXQ6Zm9jdXMgeyBvdXRsaW5lOiBub25lOyBib3JkZXItY29sb3I6ICM2NjdlZWE7IH0KICAgICAgICAuYnRuIHsgd2lkdGg6IDEwMCU7IHBhZGRpbmc6IDE0cHg7IGJhY2tncm91bmQ6ICM2NjdlZWE7IGNvbG9yOiB3aGl0ZTsgYm9yZGVyOiBub25lOyBib3JkZXItcmFkaXVzOiA4cHg7IGZvbnQtc2l6ZTogMTZweDsgZm9udC13ZWlnaHQ6IDYwMDsgY3Vyc29yOiBwb2ludGVyOyB9CiAgICAgICAgLmJ0bjpob3ZlciB7IGJhY2tncm91bmQ6ICM1NTY4ZDM7IH0KICAgICAgICAuZXJyb3IgeyBjb2xvcjogI2U3NGMzYzsgZm9udC1zaXplOiAxNHB4OyBtYXJnaW4tdG9wOiAxMHB4OyB0ZXh0LWFsaWduOiBjZW50ZXI7IGRpc3BsYXk6IG5vbmU7IH0KICAgIDwvc3R5bGU+CjwvaGVhZD4KPGJvZHk+CiAgICA8ZGl2IGNsYXNzPSJsb2dpbi1ib3giPgogICAgICAgIDxoMj7wn5OmIERpc3RyaWJVcDwvaDI+CiAgICAgICAgPGRpdiBjbGFzcz0iZm9ybS1ncm91cCI+CiAgICAgICAgICAgIDxsYWJlbD5Vc2VybmFtZSAvIEVtYWlsPC9sYWJlbD4KICAgICAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJ1c2VybmFtZSIgcGxhY2Vob2xkZXI9IkVudGVyIHVzZXJuYW1lIG9yIGVtYWlsIj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8ZGl2IGNsYXNzPSJmb3JtLWdyb3VwIj4KICAgICAgICAgICAgPGxhYmVsPlBhc3N3b3JkPC9sYWJlbD4KICAgICAgICAgICAgPGlucHV0IHR5cGU9InBhc3N3b3JkIiBpZD0icGFzc3dvcmQiIHBsYWNlaG9sZGVyPSJFbnRlciBwYXNzd29yZCI+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGRpdiBpZD0iZXJyb3IiIGNsYXNzPSJlcnJvciI+PC9kaXY+CiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBvbmNsaWNrPSJsb2dpbigpIj5TaWduIEluPC9idXR0b24+CiAgICA8L2Rpdj4KCiAgICA8c2NyaXB0PgogICAgICAgIGFzeW5jIGZ1bmN0aW9uIGxvZ2luKCkgewogICAgICAgICAgICBjb25zdCB1c2VybmFtZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd1c2VybmFtZScpLnZhbHVlOwogICAgICAgICAgICBjb25zdCBwYXNzd29yZCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdwYXNzd29yZCcpLnZhbHVlOwogICAgICAgICAgICBjb25zdCBlcnJvckVsID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Vycm9yJyk7CiAgICAgICAgICAgIGlmICghdXNlcm5hbWUgfHwgIXBhc3N3b3JkKSB7CiAgICAgICAgICAgICAgICBlcnJvckVsLnRleHRDb250ZW50ID0gJ1BsZWFzZSBmaWxsIGluIGFsbCBmaWVsZHMnOwogICAgICAgICAgICAgICAgZXJyb3JFbC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsgcmV0dXJuOwogICAgICAgICAgICB9CiAgICAgICAgICAgIHRyeSB7CiAgICAgICAgICAgICAgICBjb25zdCByZXMgPSBhd2FpdCBmZXRjaCgnL2FwaS9hdXRoL2xvZ2luJywgewogICAgICAgICAgICAgICAgICAgIG1ldGhvZDogJ1BPU1QnLAogICAgICAgICAgICAgICAgICAgIGhlYWRlcnM6IHsgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi9qc29uJyB9LAogICAgICAgICAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KHsgdXNlcm5hbWUsIHBhc3N3b3JkIH0pCiAgICAgICAgICAgICAgICB9KTsKICAgICAgICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgICAgICAgICAgICAgaWYgKGRhdGEudG9rZW4pIHsKICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgndG9rZW4nLCBkYXRhLnRva2VuKTsKICAgICAgICAgICAgICAgICAgICBsb2NhbFN0b3JhZ2Uuc2V0SXRlbSgndXNlcicsIEpTT04uc3RyaW5naWZ5KGRhdGEudXNlcikpOwogICAgICAgICAgICAgICAgICAgIGxvY2F0aW9uLmhyZWYgPSAnL2FkbWluLmh0bWwnOwogICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICBlcnJvckVsLnRleHRDb250ZW50ID0gZGF0YS5lcnJvciB8fCAnTG9naW4gZmFpbGVkJzsKICAgICAgICAgICAgICAgICAgICBlcnJvckVsLnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOwogICAgICAgICAgICAgICAgfQogICAgICAgICAgICB9IGNhdGNoIHsKICAgICAgICAgICAgICAgIGVycm9yRWwudGV4dENvbnRlbnQgPSAnTmV0d29yayBlcnJvcic7CiAgICAgICAgICAgICAgICBlcnJvckVsLnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOwogICAgICAgICAgICB9CiAgICAgICAgfQogICAgICAgIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoJ2tleXByZXNzJywgZSA9PiB7IGlmIChlLmtleSA9PT0gJ0VudGVyJykgbG9naW4oKTsgfSk7CiAgICA8L3NjcmlwdD4KPC9ib2R5Pgo8L2h0bWw+Cg==";

const INDEX_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI+CiAgICA8dGl0bGU+RGlzdHJpYlVwIC0gQXBwIERpc3RyaWJ1dGlvbjwvdGl0bGU+CiAgICA8c3R5bGU+CiAgICAgICAgKiB7IG1hcmdpbjogMDsgcGFkZGluZzogMDsgYm94LXNpemluZzogYm9yZGVyLWJveDsgfQogICAgICAgIGJvZHkgeyBmb250LWZhbWlseTogLWFwcGxlLXN5c3RlbSwgQmxpbmtNYWNTeXN0ZW1Gb250LCAnU2Vnb2UgVUknLCBSb2JvdG8sIHNhbnMtc2VyaWY7IGJhY2tncm91bmQ6ICNmNWY1Zjc7IH0KICAgICAgICAuaGVhZGVyIHsgYmFja2dyb3VuZDogbGluZWFyLWdyYWRpZW50KDEzNWRlZywgIzY2N2VlYSAwJSwgIzc2NGJhMiAxMDAlKTsgY29sb3I6IHdoaXRlOyBwYWRkaW5nOiA2MHB4IDIwcHg7IHRleHQtYWxpZ246IGNlbnRlcjsgfQogICAgICAgIC5oZWFkZXIgaDEgeyBmb250LXNpemU6IDQ4cHg7IG1hcmdpbi1ib3R0b206IDEycHg7IH0KICAgICAgICAuaGVhZGVyIHAgeyBmb250LXNpemU6IDE4cHg7IG9wYWNpdHk6IDAuOTsgfQogICAgICAgIC5tYWluIHsgbWF4LXdpZHRoOiA4MDBweDsgbWFyZ2luOiA0MHB4IGF1dG87IHBhZGRpbmc6IDAgMjBweDsgdGV4dC1hbGlnbjogY2VudGVyOyB9CiAgICAgICAgLmJ0biB7IGRpc3BsYXk6IGlubGluZS1ibG9jazsgcGFkZGluZzogMTRweCA0MHB4OyBiYWNrZ3JvdW5kOiAjNjY3ZWVhOyBjb2xvcjogd2hpdGU7IGJvcmRlci1yYWRpdXM6IDhweDsgdGV4dC1kZWNvcmF0aW9uOiBub25lOyBmb250LXNpemU6IDE2cHg7IGZvbnQtd2VpZ2h0OiA2MDA7IG1hcmdpbi10b3A6IDI0cHg7IH0KICAgICAgICAuYnRuOmhvdmVyIHsgYmFja2dyb3VuZDogIzU1NjhkMzsgfQogICAgICAgIGZvb3RlciB7IGJhY2tncm91bmQ6ICMxYTFhMmU7IGNvbG9yOiAjODg4OyBwYWRkaW5nOiAyNHB4OyB0ZXh0LWFsaWduOiBjZW50ZXI7IG1hcmdpbi10b3A6IDgwcHg7IGZvbnQtc2l6ZTogMTNweDsgfQogICAgPC9zdHlsZT4KPC9oZWFkPgo8Ym9keT4KICAgIDxkaXYgY2xhc3M9ImhlYWRlciI+CiAgICAgICAgPGgxPvCfk6YgRGlzdHJpYlVwPC9oMT4KICAgICAgICA8cD5Qcml2YXRlIGlPUy9BbmRyb2lkIGFwcCBkaXN0cmlidXRpb248L3A+CiAgICAgICAgPGEgY2xhc3M9ImJ0biIgaHJlZj0iL2xvZ2luLmh0bWwiPlNpZ24gSW48L2E+CiAgICA8L2Rpdj4KICAgIDxkaXYgY2xhc3M9Im1haW4iPgogICAgICAgIDxwIHN0eWxlPSJjb2xvcjojNjY2O2xpbmUtaGVpZ2h0OjEuNyI+CiAgICAgICAgICAgIFRoaXMgaXMgYSBwcml2YXRlIGRpc3RyaWJ1dGlvbiBpbnN0YW5jZS4KICAgICAgICAgICAgQWNjZXNzIGlzIGJ5IGludml0YXRpb24gb25seSDigJQgYXNrIHRoZSBhZG1pbmlzdHJhdG9yIGZvciBhbiBhY2NvdW50LgogICAgICAgIDwvcD4KICAgIDwvZGl2PgogICAgPGZvb3Rlcj4mY29weTsgMjAyNiBEaXN0cmliVXA8L2Zvb3Rlcj4KPC9ib2R5Pgo8L2h0bWw+Cg==";

const UPLOAD_HTML_B64 = "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI+CiAgICA8dGl0bGU+VXBsb2FkIC0gRGlzdHJpYlVwPC90aXRsZT4KICAgIDxzdHlsZT4KICAgICAgICAqIHsgbWFyZ2luOiAwOyBwYWRkaW5nOiAwOyBib3gtc2l6aW5nOiBib3JkZXItYm94OyB9CiAgICAgICAgYm9keSB7IGZvbnQtZmFtaWx5OiAtYXBwbGUtc3lzdGVtLCBCbGlua01hY1N5c3RlbUZvbnQsICdTZWdvZSBVSScsIFJvYm90bywgc2Fucy1zZXJpZjsgYmFja2dyb3VuZDogI2Y1ZjVmNzsgbWluLWhlaWdodDogMTAwdmg7IGRpc3BsYXk6IGZsZXg7IGFsaWduLWl0ZW1zOiBjZW50ZXI7IGp1c3RpZnktY29udGVudDogY2VudGVyOyBwYWRkaW5nOiAyMHB4OyB9CiAgICAgICAgLmJveCB7IGJhY2tncm91bmQ6IHdoaXRlOyBib3JkZXItcmFkaXVzOiAxNnB4OyBib3gtc2hhZG93OiAwIDRweCAyMHB4IHJnYmEoMCwwLDAsMC4wOCk7IHdpZHRoOiAxMDAlOyBtYXgtd2lkdGg6IDU2MHB4OyBwYWRkaW5nOiA0MHB4OyB9CiAgICAgICAgaDEgeyBmb250LXNpemU6IDI0cHg7IGNvbG9yOiAjMzMzOyBtYXJnaW4tYm90dG9tOiA4cHg7IH0KICAgICAgICAuc3ViIHsgY29sb3I6ICM4ODg7IG1hcmdpbi1ib3R0b206IDI0cHg7IGZvbnQtc2l6ZTogMTRweDsgfQogICAgICAgIC5kcm9wem9uZSB7IGJvcmRlcjogMnB4IGRhc2hlZCAjZDBkMGUwOyBib3JkZXItcmFkaXVzOiAxMnB4OyBwYWRkaW5nOiA0MHB4IDIwcHg7IHRleHQtYWxpZ246IGNlbnRlcjsgY3Vyc29yOiBwb2ludGVyOyB0cmFuc2l0aW9uOiBib3JkZXItY29sb3IgMC4ycywgYmFja2dyb3VuZCAwLjJzOyB9CiAgICAgICAgLmRyb3B6b25lOmhvdmVyLCAuZHJvcHpvbmUuZHJhZyB7IGJvcmRlci1jb2xvcjogIzY2N2VlYTsgYmFja2dyb3VuZDogI2YwZjJmZjsgfQogICAgICAgIC5kcm9wem9uZSBwIHsgY29sb3I6ICM2NjY7IG1hcmdpbi10b3A6IDhweDsgfQogICAgICAgIC5kcm9wem9uZSAuaWNvbiB7IGZvbnQtc2l6ZTogNDBweDsgfQogICAgICAgIGlucHV0W3R5cGU9ZmlsZV0geyBkaXNwbGF5OiBub25lOyB9CiAgICAgICAgLm1ldGEgeyBtYXJnaW4tdG9wOiAxNnB4OyBwYWRkaW5nOiAxMnB4OyBiYWNrZ3JvdW5kOiAjZjhmOWZhOyBib3JkZXItcmFkaXVzOiA4cHg7IGZvbnQtc2l6ZTogMTRweDsgY29sb3I6ICM1NTU7IGRpc3BsYXk6IG5vbmU7IH0KICAgICAgICAuYmFyIHsgaGVpZ2h0OiA2cHg7IGJhY2tncm91bmQ6ICNlZWU7IGJvcmRlci1yYWRpdXM6IDNweDsgbWFyZ2luLXRvcDogMTZweDsgb3ZlcmZsb3c6IGhpZGRlbjsgZGlzcGxheTogbm9uZTsgfQogICAgICAgIC5iYXIgPiBkaXYgeyBoZWlnaHQ6IDEwMCU7IGJhY2tncm91bmQ6ICM2NjdlZWE7IHdpZHRoOiAwJTsgdHJhbnNpdGlvbjogd2lkdGggMC4yczsgfQogICAgICAgIC5idG4geyBkaXNwbGF5OiBpbmxpbmUtYmxvY2s7IG1hcmdpbi10b3A6IDIwcHg7IHBhZGRpbmc6IDEycHggMzJweDsgYmFja2dyb3VuZDogIzY2N2VlYTsgY29sb3I6IHdoaXRlOyBib3JkZXI6IG5vbmU7IGJvcmRlci1yYWRpdXM6IDhweDsgZm9udC1zaXplOiAxNXB4OyBmb250LXdlaWdodDogNjAwOyBjdXJzb3I6IHBvaW50ZXI7IHdpZHRoOiAxMDAlOyB9CiAgICAgICAgLmJ0bjpkaXNhYmxlZCB7IGJhY2tncm91bmQ6ICNiMGI4ZTg7IGN1cnNvcjogbm90LWFsbG93ZWQ7IH0KICAgICAgICAucmVzdWx0IHsgbWFyZ2luLXRvcDogMjRweDsgcGFkZGluZzogMjBweDsgYm9yZGVyLXJhZGl1czogMTJweDsgZGlzcGxheTogbm9uZTsgfQogICAgICAgIC5yZXN1bHQub2sgeyBiYWNrZ3JvdW5kOiAjZThmNWU5OyBib3JkZXI6IDFweCBzb2xpZCAjYTVkNmE3OyB9CiAgICAgICAgLnJlc3VsdC5lcnIgeyBiYWNrZ3JvdW5kOiAjZmZlYmVlOyBib3JkZXI6IDFweCBzb2xpZCAjZWY5YTlhOyB9CiAgICAgICAgLnJlc3VsdCBoMyB7IG1hcmdpbi1ib3R0b206IDEycHg7IGZvbnQtc2l6ZTogMTZweDsgfQogICAgICAgIC5yZXN1bHQgYSB7IGNvbG9yOiAjMTU2NWMwOyB3b3JkLWJyZWFrOiBicmVhay1hbGw7IH0KICAgICAgICAucXIgeyB0ZXh0LWFsaWduOiBjZW50ZXI7IG1hcmdpbi10b3A6IDE2cHg7IH0KICAgICAgICAucXIgaW1nIHsgYm9yZGVyLXJhZGl1czogOHB4OyB9CiAgICAgICAgLmJhY2sgeyB0ZXh0LWFsaWduOiBjZW50ZXI7IG1hcmdpbi10b3A6IDIwcHg7IH0KICAgICAgICAuYmFjayBhIHsgY29sb3I6ICM2NjdlZWE7IHRleHQtZGVjb3JhdGlvbjogbm9uZTsgZm9udC1zaXplOiAxNHB4OyB9CiAgICA8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5PgogICAgPGRpdiBjbGFzcz0iYm94Ij4KICAgICAgICA8aDE+8J+TpiBVcGxvYWQgQnVpbGQ8L2gxPgogICAgICAgIDxwIGNsYXNzPSJzdWIiIGlkPSJhcHBMYWJlbCI+UHJlcGFyaW5nLi4uPC9wPgoKICAgICAgICA8ZGl2IGNsYXNzPSJkcm9wem9uZSIgaWQ9ImR6Ij4KICAgICAgICAgICAgPGRpdiBjbGFzcz0iaWNvbiI+8J+TgTwvZGl2PgogICAgICAgICAgICA8cD48c3Ryb25nPkNsaWNrIHRvIHNlbGVjdDwvc3Ryb25nPiBvciBkcmFnICZhbXA7IGRyb3AgaGVyZTwvcD4KICAgICAgICAgICAgPHAgaWQ9ImhpbnQiPklQQSBmb3IgaU9TLCBBUEsvWEFQSy9PQkIgZm9yIEFuZHJvaWQ8L3A+CiAgICAgICAgPC9kaXY+CiAgICAgICAgPGlucHV0IHR5cGU9ImZpbGUiIGlkPSJmaWxlSW5wdXQiIGFjY2VwdD0iLmlwYSwuYXBrLC54YXBrLC5vYmIiPgoKICAgICAgICA8ZGl2IGNsYXNzPSJtZXRhIiBpZD0ibWV0YSI+PC9kaXY+CiAgICAgICAgPGRpdiBjbGFzcz0iYmFyIiBpZD0iYmFyIj48ZGl2IGlkPSJiYXJGaWxsIj48L2Rpdj48L2Rpdj4KCiAgICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIiBpZD0idXBsb2FkQnRuIiBkaXNhYmxlZD5VcGxvYWQ8L2J1dHRvbj4KCiAgICAgICAgPGRpdiBjbGFzcz0icmVzdWx0IiBpZD0icmVzdWx0Ij48L2Rpdj4KCiAgICAgICAgPGRpdiBjbGFzcz0iYmFjayI+PGEgaHJlZj0iL2FkbWluLmh0bWwiPuKGkCBCYWNrIHRvIGFkbWluPC9hPjwvZGl2PgogICAgPC9kaXY+CgogICAgPHNjcmlwdD4KICAgICAgICBjb25zdCBwYXJhbXMgPSBuZXcgVVJMU2VhcmNoUGFyYW1zKGxvY2F0aW9uLnNlYXJjaCk7CiAgICAgICAgY29uc3QgYXBwSWQgPSBwYXJhbXMuZ2V0KCdpZCcpOwogICAgICAgIGNvbnN0IHRva2VuID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ3Rva2VuJyk7CiAgICAgICAgaWYgKCF0b2tlbikgbG9jYXRpb24uaHJlZiA9ICcvbG9naW4uaHRtbCc7CgogICAgICAgIGxldCBzZWxlY3RlZEZpbGUgPSBudWxsOwogICAgICAgIGNvbnN0IGR6ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2R6Jyk7CiAgICAgICAgY29uc3QgZmlsZUlucHV0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2ZpbGVJbnB1dCcpOwogICAgICAgIGNvbnN0IHVwbG9hZEJ0biA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCd1cGxvYWRCdG4nKTsKICAgICAgICBjb25zdCBtZXRhID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ21ldGEnKTsKCiAgICAgICAgYXN5bmMgZnVuY3Rpb24gbG9hZEFwcCgpIHsKICAgICAgICAgICAgY29uc3QgcmVzID0gYXdhaXQgZmV0Y2goJy9hcGkvYXBwcy8nICsgYXBwSWQsIHsgaGVhZGVyczogeyAnQXV0aG9yaXphdGlvbic6ICdCZWFyZXIgJyArIHRva2VuIH0gfSk7CiAgICAgICAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCByZXMuanNvbigpOwogICAgICAgICAgICBpZiAoZGF0YS5hcHApIHsKICAgICAgICAgICAgICAgIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdhcHBMYWJlbCcpLnRleHRDb250ZW50ID0gZGF0YS5hcHAubmFtZSArICcgwrcgJyArIGRhdGEuYXBwLnBsYXRmb3JtICsgJyDCtyB2JyArIGRhdGEuYXBwLnZlcnNpb247CiAgICAgICAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnaGludCcpLnRleHRDb250ZW50ID0gZGF0YS5hcHAucGxhdGZvcm0gPT09ICdpb3MnCiAgICAgICAgICAgICAgICAgICAgPyAnU2VsZWN0IGFuIC5pcGEgZmlsZScKICAgICAgICAgICAgICAgICAgICA6ICdTZWxlY3QgLmFwayAvIC54YXBrIC8gLm9iYic7CiAgICAgICAgICAgIH0KICAgICAgICB9CiAgICAgICAgbG9hZEFwcCgpOwoKICAgICAgICBkei5vbmNsaWNrID0gKCkgPT4gZmlsZUlucHV0LmNsaWNrKCk7CiAgICAgICAgZHoub25kcmFnb3ZlciA9IChlKSA9PiB7IGUucHJldmVudERlZmF1bHQoKTsgZHouY2xhc3NMaXN0LmFkZCgnZHJhZycpOyB9OwogICAgICAgIGR6Lm9uZHJhZ2xlYXZlID0gKCkgPT4gZHouY2xhc3NMaXN0LnJlbW92ZSgnZHJhZycpOwogICAgICAgIGR6Lm9uZHJvcCA9IChlKSA9PiB7CiAgICAgICAgICAgIGUucHJldmVudERlZmF1bHQoKTsgZHouY2xhc3NMaXN0LnJlbW92ZSgnZHJhZycpOwogICAgICAgICAgICBpZiAoZS5kYXRhVHJhbnNmZXIuZmlsZXNbMF0pIHNldEZpbGUoZS5kYXRhVHJhbnNmZXIuZmlsZXNbMF0pOwogICAgICAgIH07CiAgICAgICAgZmlsZUlucHV0Lm9uY2hhbmdlID0gKCkgPT4geyBpZiAoZmlsZUlucHV0LmZpbGVzWzBdKSBzZXRGaWxlKGZpbGVJbnB1dC5maWxlc1swXSk7IH07CgogICAgICAgIGZ1bmN0aW9uIHNldEZpbGUoZikgewogICAgICAgICAgICBzZWxlY3RlZEZpbGUgPSBmOwogICAgICAgICAgICBtZXRhLnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOwogICAgICAgICAgICBtZXRhLnRleHRDb250ZW50ID0gZi5uYW1lICsgJyDCtyAnICsgKGYuc2l6ZSAvIDEwMjQgLyAxMDI0KS50b0ZpeGVkKDIpICsgJyBNQic7CiAgICAgICAgICAgIHVwbG9hZEJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgIH0KCiAgICAgICAgdXBsb2FkQnRuLm9uY2xpY2sgPSAoKSA9PiB7CiAgICAgICAgICAgIGlmICghc2VsZWN0ZWRGaWxlKSByZXR1cm47CiAgICAgICAgICAgIHVwbG9hZEJ0bi5kaXNhYmxlZCA9IHRydWU7CiAgICAgICAgICAgIHVwbG9hZEJ0bi50ZXh0Q29udGVudCA9ICdVcGxvYWRpbmcuLi4nOwogICAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYmFyJykuc3R5bGUuZGlzcGxheSA9ICdibG9jayc7CgogICAgICAgICAgICBjb25zdCBmb3JtID0gbmV3IEZvcm1EYXRhKCk7CiAgICAgICAgICAgIGZvcm0uYXBwZW5kKCdmaWxlJywgc2VsZWN0ZWRGaWxlKTsKCiAgICAgICAgICAgIGNvbnN0IHhociA9IG5ldyBYTUxIdHRwUmVxdWVzdCgpOwogICAgICAgICAgICB4aHIub3BlbignUE9TVCcsICcvYXBpL3VwbG9hZC8nICsgYXBwSWQpOwogICAgICAgICAgICB4aHIuc2V0UmVxdWVzdEhlYWRlcignQXV0aG9yaXphdGlvbicsICdCZWFyZXIgJyArIHRva2VuKTsKICAgICAgICAgICAgeGhyLnVwbG9hZC5vbnByb2dyZXNzID0gKGUpID0+IHsKICAgICAgICAgICAgICAgIGlmIChlLmxlbmd0aENvbXB1dGFibGUpIHsKICAgICAgICAgICAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYmFyRmlsbCcpLnN0eWxlLndpZHRoID0gKGUubG9hZGVkIC8gZS50b3RhbCAqIDEwMCkgKyAnJSc7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH07CiAgICAgICAgICAgIHhoci5vbmxvYWQgPSAoKSA9PiB7CiAgICAgICAgICAgICAgICBjb25zdCBkYXRhID0gSlNPTi5wYXJzZSh4aHIucmVzcG9uc2VUZXh0KTsKICAgICAgICAgICAgICAgIGNvbnN0IHJlc3VsdCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdyZXN1bHQnKTsKICAgICAgICAgICAgICAgIGlmICh4aHIuc3RhdHVzID49IDIwMCAmJiB4aHIuc3RhdHVzIDwgMzAwICYmIGRhdGEuc3VjY2VzcykgewogICAgICAgICAgICAgICAgICAgIHJlc3VsdC5jbGFzc05hbWUgPSAncmVzdWx0IG9rJzsKICAgICAgICAgICAgICAgICAgICBzaG93U3VjY2VzcyhyZXN1bHQpOwogICAgICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICAgICByZXN1bHQuY2xhc3NOYW1lID0gJ3Jlc3VsdCBlcnInOwogICAgICAgICAgICAgICAgICAgIHJlc3VsdC5pbm5lckhUTUwgPSAnPGgzPlVwbG9hZCBmYWlsZWQ8L2gzPjxwPicgKyAoZGF0YS5lcnJvciB8fCB4aHIuc3RhdHVzVGV4dCkgKyAnPC9wPic7CiAgICAgICAgICAgICAgICAgICAgcmVzdWx0LnN0eWxlLmRpc3BsYXkgPSAnYmxvY2snOwogICAgICAgICAgICAgICAgICAgIHVwbG9hZEJ0bi5kaXNhYmxlZCA9IGZhbHNlOwogICAgICAgICAgICAgICAgICAgIHVwbG9hZEJ0bi50ZXh0Q29udGVudCA9ICdSZXRyeSc7CiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgIH07CiAgICAgICAgICAgIHhoci5vbmVycm9yID0gKCkgPT4gewogICAgICAgICAgICAgICAgY29uc3QgcmVzdWx0ID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3Jlc3VsdCcpOwogICAgICAgICAgICAgICAgcmVzdWx0LmNsYXNzTmFtZSA9ICdyZXN1bHQgZXJyJzsKICAgICAgICAgICAgICAgIHJlc3VsdC5pbm5lckhUTUwgPSAnPGgzPk5ldHdvcmsgZXJyb3I8L2gzPic7CiAgICAgICAgICAgICAgICByZXN1bHQuc3R5bGUuZGlzcGxheSA9ICdibG9jayc7CiAgICAgICAgICAgICAgICB1cGxvYWRCdG4uZGlzYWJsZWQgPSBmYWxzZTsKICAgICAgICAgICAgICAgIHVwbG9hZEJ0bi50ZXh0Q29udGVudCA9ICdSZXRyeSc7CiAgICAgICAgICAgIH07CiAgICAgICAgICAgIHhoci5zZW5kKGZvcm0pOwogICAgICAgIH07CgogICAgICAgIGFzeW5jIGZ1bmN0aW9uIHNob3dTdWNjZXNzKGVsKSB7CiAgICAgICAgICAgIC8vIEZldGNoIE9UQSAvIGRvd25sb2FkIGxpbmsKICAgICAgICAgICAgY29uc3QgYXBwUmVzID0gYXdhaXQgZmV0Y2goJy9hcGkvYXBwcy8nICsgYXBwSWQsIHsgaGVhZGVyczogeyAnQXV0aG9yaXphdGlvbic6ICdCZWFyZXIgJyArIHRva2VuIH0gfSk7CiAgICAgICAgICAgIGNvbnN0IGFwcERhdGEgPSBhd2FpdCBhcHBSZXMuanNvbigpOwogICAgICAgICAgICBjb25zdCBhcHAgPSBhcHBEYXRhLmFwcDsKCiAgICAgICAgICAgIGxldCBodG1sID0gJzxoMz7inJMgVXBsb2FkIGNvbXBsZXRlPC9oMz4nOwogICAgICAgICAgICBpZiAoYXBwLnBsYXRmb3JtID09PSAnaW9zJykgewogICAgICAgICAgICAgICAgY29uc3Qgb3RhUmVzID0gYXdhaXQgZmV0Y2goJy9hcGkvYXBwcy8nICsgYXBwSWQgKyAnL290YS11cmwnLCB7IGhlYWRlcnM6IHsgJ0F1dGhvcml6YXRpb24nOiAnQmVhcmVyICcgKyB0b2tlbiB9IH0pOwogICAgICAgICAgICAgICAgY29uc3Qgb3RhID0gYXdhaXQgb3RhUmVzLmpzb24oKTsKICAgICAgICAgICAgICAgIGh0bWwgKz0gJzxwPkluc3RhbGwgb24gZGV2aWNlOjwvcD4nOwogICAgICAgICAgICAgICAgaHRtbCArPSAnPHAgc3R5bGU9Im1hcmdpbjo4cHggMCI+PGEgaHJlZj0iJyArIG90YS5pdG1zVXJsICsgJyI+8J+TsiBUYXAgdG8gaW5zdGFsbDwvYT48L3A+JzsKICAgICAgICAgICAgICAgIGh0bWwgKz0gJzxkaXYgY2xhc3M9InFyIj48aW1nIHNyYz0iaHR0cHM6Ly9hcGkucXJzZXJ2ZXIuY29tL3YxL2NyZWF0ZS1xci1jb2RlLz9zaXplPTIwMHgyMDAmZGF0YT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KG90YS5pdG1zVXJsKSArICciPjwvZGl2Pic7CiAgICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICAgICBodG1sICs9ICc8cD5EaXJlY3QgZG93bmxvYWQ6PC9wPic7CiAgICAgICAgICAgICAgICBodG1sICs9ICc8cCBzdHlsZT0ibWFyZ2luOjhweCAwO3dvcmQtYnJlYWs6YnJlYWstYWxsIj48YSBocmVmPSIvYXBpL2luc3RhbGwvYW5kcm9pZC1kb3dubG9hZC8nICsgYXBwLmJ1bmRsZV9pZCArICciPkRvd25sb2FkIEFQSzwvYT48L3A+JzsKICAgICAgICAgICAgfQogICAgICAgICAgICBlbC5pbm5lckhUTUwgPSBodG1sOwogICAgICAgICAgICBlbC5zdHlsZS5kaXNwbGF5ID0gJ2Jsb2NrJzsKICAgICAgICAgICAgdXBsb2FkQnRuLnRleHRDb250ZW50ID0gJ1VwbG9hZCBhbm90aGVyJzsKICAgICAgICAgICAgdXBsb2FkQnRuLmRpc2FibGVkID0gZmFsc2U7CiAgICAgICAgfQogICAgPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo=";

export default {
  fetch: async (req, env, ctx) => {
    try {
      return await handleRequest(req, env, ctx);
    } catch (err) {
      console.error('Worker error:', err);
      return json({ error: err.message || 'Internal server error' }, 500);
    }
  }
};
