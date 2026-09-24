const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./database');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'distribup_secret_key_change_in_production';
const JWT_EXPIRES_IN = '7d';

// 用户注册
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, team_id } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: '用户名和密码不能为空' });
    }

    // 检查用户是否存在
    const existing = await db.get('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
    if (existing) {
      return res.status(400).json({ error: '用户名或邮箱已存在' });
    }

    // 哈希密码
    const password_hash = await bcrypt.hash(password, 10);

    // 创建用户
    const result = await db.run(
      'INSERT INTO users (username, email, password_hash, role, team_id) VALUES (?, ?, ?, ?, ?)',
      [username, email, password_hash, 'user', team_id || null]
    );

    // 生成 Token
    const token = jwt.sign(
      { id: result.id, username, email, role: 'user' },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.status(201).json({
      message: '注册成功',
      token,
      user: { id: result.id, username, email, role: 'user' }
    });
  } catch (err) {
    console.error('注册失败:', err);
    res.status(500).json({ error: '注册失败' });
  }
});

// 用户登录
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: '用户名和密码不能为空' });
    }

    // 查找用户
    const user = await db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, username]);
    if (!user) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    if (!user.is_active) {
      return res.status(403).json({ error: '账户已被禁用' });
    }

    // 验证密码
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    // 生成 Token
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({
      message: '登录成功',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        team_id: user.team_id
      }
    });
  } catch (err) {
    console.error('登录失败:', err);
    res.status(500).json({ error: '登录失败' });
  }
});

// 获取当前用户信息
router.get('/me', require('../middleware/auth').checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const user = await db.get(
      'SELECT id, username, email, role, team_id, created_at FROM users WHERE id = ?',
      [req.user.id]
    );
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: '获取用户信息失败' });
  }
});

// 更新密码
router.put('/password', require('../middleware/auth').checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: '请输入旧密码和新密码' });
    }

    const user = await db.get('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
    const validPassword = await bcrypt.compare(oldPassword, user.password_hash);
    
    if (!validPassword) {
      return res.status(401).json({ error: '旧密码错误' });
    }

    const password_hash = await bcrypt.hash(newPassword, 10);
    await db.run('UPDATE users SET password_hash = ? WHERE id = ?', [password_hash, req.user.id]);

    res.json({ message: '密码修改成功' });
  } catch (err) {
    res.status(500).json({ error: '密码修改失败' });
  }
});

module.exports = router;
