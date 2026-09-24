const express = require('express');
const db = require('./database');
const { checkPermission } = require('../middleware/auth');

const router = express.Router();

// 获取设备列表
router.get('/', checkPermission(['user', 'admin']), async (req, res) => {
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

// 添加设备
router.post('/', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const { udid, name, platform = 'iOS' } = req.body;
    
    if (!udid) {
      return res.status(400).json({ error: 'UDID 不能为空' });
    }
    
    const result = await db.run(
      'INSERT OR REPLACE INTO devices (udid, name, platform, team_id, registered_at) VALUES (?, ?, ?, ?, ?)',
      [udid, name, platform, req.user.team_id, new Date().toISOString()]
    );
    
    res.json({ id: result.id, udid, name, message: '设备添加成功' });
  } catch (err) {
    res.status(500).json({ error: '添加设备失败' });
  }
});

// 删除设备
router.delete('/:id', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    await db.run('DELETE FROM devices WHERE id = ? AND team_id = ?', [req.params.id, req.user.team_id]);
    res.json({ message: '删除成功' });
  } catch (err) {
    res.status(500).json({ error: '删除失败' });
  }
});

// 获取 UDID 采集配置
router.get('/collect-config', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const config = {
      collectUrl: `${process.env.BASE_URL || 'http://localhost:8080'}/api/devices/collect`,
      expiresIn: 86400
    };
    res.json(config);
  } catch (err) {
    res.status(500).json({ error: '获取配置失败' });
  }
});

module.exports = router;
