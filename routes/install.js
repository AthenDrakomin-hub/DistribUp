const express = require('express');
const db = require('./database');
const { checkPermission } = require('../middleware/auth');
const { generateManifest } = require('../templates/manifest');
const { generateMobileConfig } = require('../templates/mobileconfig');

const router = express.Router();

// 生成 manifest.plist（仅 iOS）
router.get('/manifest/:bundleId', async (req, res) => {
  try {
    const app = await db.get('SELECT * FROM apps WHERE bundle_id = ?', [req.params.bundleId]);
    if (!app) {
      return res.status(404).json({ error: '应用不存在' });
    }

    // iOS 才支持 OTA manifest
    if (app.platform === 'android') {
      return res.status(400).json({ error: 'Android 应用不支持 OTA 安装，请使用直链下载' });
    }

    const latestUpload = await db.get(
      'SELECT * FROM uploads WHERE app_id = ? ORDER BY created_at DESC LIMIT 1',
      [app.id]
    );

    if (!latestUpload) {
      return res.status(404).json({ error: '没有可用的版本' });
    }

    const baseUrl = process.env.BASE_URL || `http://${req.headers.host}`;
    const manifest = generateManifest({
      name: app.name,
      bundleId: app.bundle_id,
      version: app.version,
      downloadUrl: `${baseUrl}/signed/${latestUpload.filename}`,
      iconUrl: app.icon_path ? `${baseUrl}${app.icon_path}` : `${baseUrl}/assets/default-icon.png`,
      fileSize: latestUpload.file_size,
      md5: ''
    });

    res.setHeader('Content-Type', 'text/xml');
    res.send(manifest);
  } catch (err) {
    res.status(500).json({ error: '生成 manifest 失败' });
  }
});

// 生成 UDID 采集配置
router.get('/udid-config', async (req, res) => {
  try {
    const config = generateMobileConfig(
      `${process.env.BASE_URL || 'http://localhost:8080'}/api/devices/collect`,
      req.query.bundleId
    );
    res.setHeader('Content-Type', 'text/xml');
    res.send(config);
  } catch (err) {
    res.status(500).json({ error: '生成配置失败' });
  }
});

// UDID 采集接口
router.post('/collect', async (req, res) => {
  try {
    const { udid, name, platform = 'iOS' } = req.body;
    
    if (!udid) {
      return res.status(400).json({ error: 'UDID 不能为空' });
    }
    
    // 获取团队 ID（从 app 或默认）
    const appId = req.query.appId;
    let teamId = req.body.team_id;
    
    if (appId) {
      const app = await db.get('SELECT team_id FROM apps WHERE id = ?', [appId]);
      if (app) teamId = app.team_id;
    }
    
    if (!teamId) {
      return res.status(400).json({ error: '缺少团队 ID' });
    }
    
    await db.run(
      'INSERT OR REPLACE INTO devices (udid, name, platform, team_id, registered_at) VALUES (?, ?, ?, ?, ?)',
      [udid, name, platform, teamId, new Date().toISOString()]
    );
    
    res.json({ success: true, message: '设备注册成功' });
  } catch (err) {
    res.status(500).json({ error: '采集失败' });
  }
});

// 生成 OTA 安装链接（iOS）
router.get('/ota/:bundleId', async (req, res) => {
  try {
    const app = await db.get('SELECT * FROM apps WHERE bundle_id = ?', [req.params.bundleId]);
    if (!app) {
      return res.status(404).json({ error: '应用不存在' });
    }

    if (app.platform === 'android') {
      return res.status(400).json({ error: 'Android 应用不支持 OTA 安装，请使用直链下载' });
    }

    const baseUrl = process.env.BASE_URL || `http://${req.headers.host}`;
    const manifestUrl = `${baseUrl}/api/install/manifest/${app.bundle_id}`;

    res.json({
      itmsUrl: `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`,
      manifestUrl
    });
  } catch (err) {
    res.status(500).json({ error: '生成链接失败' });
  }
});

// 获取 Android 下载链接
router.get('/android-download/:bundleId', async (req, res) => {
  try {
    const app = await db.get('SELECT * FROM apps WHERE bundle_id = ?', [req.params.bundleId]);
    if (!app) {
      return res.status(404).json({ error: '应用不存在' });
    }

    if (app.platform !== 'android') {
      return res.status(400).json({ error: '该接口仅支持 Android 应用' });
    }

    const latestUpload = await db.get(
      'SELECT * FROM uploads WHERE app_id = ? ORDER BY created_at DESC LIMIT 1',
      [app.id]
    );

    if (!latestUpload) {
      return res.status(404).json({ error: '没有可用的版本' });
    }

    const baseUrl = process.env.BASE_URL || `http://${req.headers.host}`;
    const downloadUrl = `${baseUrl}/signed/${latestUpload.filename}`;

    res.json({
      appName: app.name,
      version: app.version,
      fileSize: latestUpload.file_size,
      downloadUrl,
      qrCode: `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(downloadUrl)}`
    });
  } catch (err) {
    res.status(500).json({ error: '获取下载链接失败' });
  }
});

module.exports = router;
