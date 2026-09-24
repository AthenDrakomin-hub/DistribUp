const express = require('express');
const db = require('./database');
const { checkPermission } = require('../middleware/auth');

const router = express.Router();

// 获取用户列表 (admin only)
router.get('/', checkPermission('admin'), async (req, res) => {
  try {
    const users = await db.all('SELECT id, username, email, role, team_id, created_at FROM users ORDER BY created_at DESC');
    res.json({ users });
  } catch (err) {
    res.status(500).json({ error: '获取用户列表失败' });
  }
});

// 更新用户角色 (admin only)
router.put('/:id/role', checkPermission('admin'), async (req, res) => {
  try {
    const { role } = req.body;
    await db.run('UPDATE users SET role = ? WHERE id = ?', [role, req.params.id]);
    res.json({ message: '角色更新成功' });
  } catch (err) {
    res.status(500).json({ error: '更新失败' });
  }
});

module.exports = router;
