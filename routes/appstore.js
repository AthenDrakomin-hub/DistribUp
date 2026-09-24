const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('./database');
const { checkPermission } = require('../middleware/auth');

const router = express.Router();

// 生成 App Store Connect API Token
function generateASAToken() {
  const iss = process.env.ASC_ISSUER_ID;
  const kid = process.env.ASC_KEY_ID;
  const privateKeyPath = process.env.ASC_PRIVATE_KEY_PATH;

  if (!iss || !kid || !privateKeyPath) {
    throw new Error('App Store Connect API 配置不完整');
  }

  const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
  
  const header = {
    alg: 'ES256',
    typ: 'JWT',
    kid: kid
  };

  const payload = {
    iss: iss,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (86400 * 7), // 7天有效期
    aud: 'appstoreconnect-v1'
  };

  return jwt.sign(payload, privateKey, { algorithm: 'ES256', header });
}

// 注册设备
router.post('/devices/register', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const { udid, name, platform = 'IOS' } = req.body;

    if (!udid) {
      return res.status(400).json({ error: 'UDID 不能为空' });
    }

    // 生成 API Token
    const token = generateASAToken();

    // 调用 App Store Connect API
    const response = await axios.post(
      'https://api.appstoreconnect.apple.com/v1/devices',
      {
        data: {
          type: 'devices',
          attributes: {
            name: name || udid,
            udid,
            platform
          }
        }
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      }
    );

    // 保存到数据库
    const result = await db.run(
      'INSERT OR REPLACE INTO devices (udid, name, platform, registered_at, team_id) VALUES (?, ?, ?, ?, ?)',
      [udid, name, platform, new Date().toISOString(), req.user.team_id]
    );

    res.json({
      success: true,
      deviceId: response.data.data.id,
      udid,
      message: '设备注册成功'
    });
  } catch (err) {
    console.error('设备注册失败:', err.response?.data || err.message);
    res.status(500).json({ 
      error: '设备注册失败',
      detail: err.response?.data?.errors?.[0]?.detail || err.message 
    });
  }
});

// 获取设备列表
router.get('/devices', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const devices = await db.all(
      'SELECT * FROM devices WHERE team_id = ? ORDER BY created_at DESC',
      [req.user.team_id]
    );
    res.json({ devices });
  } catch (err) {
    res.status(500).json({ error: '获取设备列表失败' });
  }
});

// 同步证书和 Profile
router.post('/sync', checkPermission(['admin']), async (req, res) => {
  try {
    const token = generateASAToken();

    // 获取证书列表
    const certsResponse = await axios.get(
      'https://api.appstoreconnect.apple.com/v1/certificates',
      { headers: { Authorization: `Bearer ${token}` } }
    );

    // 获取 Profile 列表
    const profilesResponse = await axios.get(
      'https://api.appstoreconnect.apple.com/v1/profiles',
      { headers: { Authorization: `Bearer ${token}` } }
    );

    res.json({
      success: true,
      certificates: certsResponse.data.data.length,
      profiles: profilesResponse.data.data.length,
      message: '同步完成'
    });
  } catch (err) {
    console.error('同步失败:', err.message);
    res.status(500).json({ error: '同步失败' });
  }
});

// 生成 UDID 采集配置
router.get('/udid-config', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const config = {
      udid_url: `/api/appstore/udid-collect`,
      expires_in: 86400 // 24小时
    };
    res.json(config);
  } catch (err) {
    res.status(500).json({ error: '获取配置失败' });
  }
});

module.exports = router;
