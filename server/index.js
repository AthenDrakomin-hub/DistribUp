const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');

// 初始化 Express 应用
const app = express();
const PORT = process.env.PORT || 8080;

// 中间件
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined'));

// 静态文件服务
app.use('/public', express.static(path.join(__dirname, '../public')));
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));
app.use('/signed', express.static(path.join(__dirname, '../signed')));

// 数据库初始化
const db = require('../routes/database');
db.init().then(() => {
  console.log('✅ 数据库初始化完成');
}).catch(err => {
  console.error('❌ 数据库初始化失败:', err);
  process.exit(1);
});

// API 路由
app.use('/api/auth', require('../routes/auth'));
app.use('/api/apps', require('../routes/apps'));
app.use('/api/upload', require('../routes/upload'));
app.use('/api/sign', require('../routes/sign'));
app.use('/api/appstore', require('../routes/appstore'));
app.use('/api/users', require('../routes/users'));
app.use('/api/devices', require('../routes/devices'));
app.use('/api/install', require('../routes/install'));
app.use('/api/admin', require('../routes/admin'));

// 健康检查
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// 前端页面
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, '../public/index.html'));
  }
});

// 错误处理
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: '服务器内部错误' });
});

// 启动服务
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 DistribUp 服务运行在 http://0.0.0.0:${PORT}`);
  console.log(`📊 环境: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
