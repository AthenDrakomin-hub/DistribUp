const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('./database');
const { checkPermission } = require('../middleware/auth');

// 获取所有用户（管理员）
router.get('/users', checkPermission('admin'), async (req, res) => {
  try {
    const users = await db.all(`
      SELECT id, username, email, role, team_id, is_active, created_at
      FROM users ORDER BY created_at DESC
    `);
    res.json({ success: true, data: users });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 创建用户
router.post('/users', checkPermission('admin'), async (req, res) => {
  try {
    const { username, password, email, role, teamId } = req.body;
    
    const existing = await db.get('SELECT id FROM users WHERE username = ?', [username]);
    if (existing) return res.status(400).json({ error: '用户名已存在' });
    
    const hashedPassword = await bcrypt.hash(password || generatePwd(), 10);
    const result = await db.run(
      `INSERT INTO users (username, email, password_hash, role, team_id, is_active) 
       VALUES (?, ?, ?, ?, ?, 1)`,
      [username, email, hashedPassword, role || 'user', teamId]
    );
    
    const user = await db.get('SELECT id, username, email, role, team_id, is_active, created_at FROM users WHERE id = ?', [result.id]);
    res.json({ success: true, data: user });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 更新用户角色/状态
router.put('/users/:userId', checkPermission('admin'), async (req, res) => {
  try {
    const { role, isActive, teamId } = req.body;
    const fields = [];
    const values = [];
    
    if (role) { fields.push('role=?'); values.push(role); }
    if (isActive !== undefined) { fields.push('is_active=?'); values.push(isActive); }
    if (teamId) { fields.push('team_id=?'); values.push(teamId); }
    
    if (fields.length === 0) return res.status(400).json({ error: '无更新字段' });
    
    values.push(req.params.userId);
    await db.run(`UPDATE users SET ${fields.join(',')} WHERE id = ?`, ...values);
    
    const user = await db.get('SELECT id, username, email, role, team_id, is_active FROM users WHERE id = ?', [req.params.userId]);
    res.json({ success: true, data: user });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 删除用户
router.delete('/users/:userId', checkPermission('admin'), async (req, res) => {
  try {
    await db.run('DELETE FROM users WHERE id = ?', [req.params.userId]);
    res.json({ success: true, message: '删除成功' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function generatePwd() {
  return Math.random().toString(36).substring(2, 10);
}

module.exports = router;
