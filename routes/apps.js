const express = require('express');
const db = require('./database');
const { checkPermission, checkTeamOwnership } = require('../middleware/auth');

const router = express.Router();

// 获取应用列表
router.get('/', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const query = req.user.role === 'admin' 
      ? 'SELECT * FROM apps ORDER BY created_at DESC'
      : 'SELECT * FROM apps WHERE team_id = ? ORDER BY created_at DESC';
    
    const apps = req.user.role === 'admin'
      ? await db.all(query)
      : await db.all(query, [req.user.team_id]);
    
    res.json({ apps });
  } catch (err) {
    res.status(500).json({ error: '获取应用列表失败' });
  }
});

// 创建应用
router.post('/', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const { name, bundle_id, version, description } = req.body;
    
    if (!name || !bundle_id) {
      return res.status(400).json({ error: '应用名称和 Bundle ID 不能为空' });
    }

    // 检查 Bundle ID 是否已存在
    const existing = await db.get('SELECT id FROM apps WHERE bundle_id = ? AND team_id = ?', [bundle_id, req.user.team_id]);
    if (existing) {
      return res.status(400).json({ error: 'Bundle ID 已存在' });
    }

    const result = await db.run(
      'INSERT INTO apps (team_id, name, bundle_id, version, description, created_by) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.team_id, name, bundle_id, version || '1.0.0', description, req.user.id]
    );

    const app = await db.get('SELECT * FROM apps WHERE id = ?', [result.id]);
    res.status(201).json({ app });
  } catch (err) {
    console.error('创建应用失败:', err);
    res.status(500).json({ error: '创建应用失败' });
  }
});

// 获取应用详情
router.get('/:id', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const app = await db.get(
      'SELECT * FROM apps WHERE id = ? AND team_id IN (SELECT team_id FROM users WHERE id = ? OR role = ?)',
      [req.params.id, req.user.id, 'admin']
    );
    
    if (!app) {
      return res.status(404).json({ error: '应用不存在' });
    }
    
    // 获取上传记录数
    const uploadCount = await db.get('SELECT COUNT(*) as count FROM uploads WHERE app_id = ?', [app.id]);
    
    res.json({ app, upload_count: uploadCount.count });
  } catch (err) {
    res.status(500).json({ error: '获取应用详情失败' });
  }
});

// 更新应用
router.put('/:id', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const { name, bundle_id, version, description } = req.body;
    
    await db.run(
      'UPDATE apps SET name = ?, bundle_id = ?, version = ?, description = ? WHERE id = ? AND team_id IN (SELECT team_id FROM users WHERE id = ?)',
      [name, bundle_id, version, description, req.params.id, req.user.id]
    );
    
    res.json({ message: '更新成功' });
  } catch (err) {
    res.status(500).json({ error: '更新失败' });
  }
});

// 删除应用
router.delete('/:id', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    await db.run('DELETE FROM apps WHERE id = ? AND team_id IN (SELECT team_id FROM users WHERE id = ?)', 
      [req.params.id, req.user.id]);
    res.json({ message: '删除成功' });
  } catch (err) {
    res.status(500).json({ error: '删除失败' });
  }
});

// 生成 OTA 安装链接
router.get('/:id/ota-url', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const app = await db.get('SELECT * FROM apps WHERE id = ?', [req.params.id]);
    if (!app) {
      return res.status(404).json({ error: '应用不存在' });
    }

    // 获取最新的上传记录
    const latestUpload = await db.get('SELECT * FROM uploads WHERE app_id = ? ORDER BY created_at DESC LIMIT 1', [app.id]);
    
    if (!latestUpload) {
      return res.status(404).json({ error: '没有找到已上传的应用' });
    }

    const baseUrl = process.env.BASE_URL || `http://${req.headers.host}`;
    const manifestUrl = `${baseUrl}/manifest/${app.bundle_id}.plist`;
    
    res.json({
      itmsUrl: `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`,
      manifestUrl
    });
  } catch (err) {
    res.status(500).json({ error: '生成链接失败' });
  }
});

module.exports = router;
