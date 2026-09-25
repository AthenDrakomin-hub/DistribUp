const express = require('express');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const db = require('./database');
const { checkPermission } = require('../middleware/auth');
const StorageAdapter = require('../services/storage');

const router = express.Router();

// 配置存储适配器
const storageType = process.env.STORAGE_TYPE || 'local';
const storageConfig = {
  basePath: process.env.LOCAL_BASE_PATH || './uploads',
  endpoint: process.env.S3_ENDPOINT || process.env.OSS_ENDPOINT || '',
  bucket: process.env.AWS_BUCKET || process.env.OSS_BUCKET || '',
  region: process.env.AWS_REGION || process.env.OSS_REGION || 'us-east-1',
  accessKeyId: process.env.AWS_ACCESS_KEY_ID || process.env.OSS_ACCESS_KEY_ID || '',
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || process.env.OSS_SECRET_ACCESS_KEY || ''
};

const storage = StorageAdapter.create(storageType, storageConfig);

// 配置 multer
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: parseInt(process.env.MAX_UPLOAD_SIZE || '500MB')
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.ipa', '.apk', '.obb'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('仅支持 IPA 和 APK 文件'));
    }
  }
});

// 上传文件
router.post('/:appId', checkPermission(['user', 'admin']), upload.single('file'), async (req, res) => {
  try {
    const { appId } = req.params;
    const platform = req.query.platform || 'ios';

    // 验证应用存在
    const app = await db.get('SELECT * FROM apps WHERE id = ? AND team_id IN (SELECT team_id FROM users WHERE id = ?)',
      [appId, req.user.id]);

    if (!app) {
      return res.status(404).json({ error: '应用不存在或无权限' });
    }

    // 如果应用指定了平台，校验上传文件类型
    if (app.platform === 'android' && !['.apk', '.obb', '.xapk'].includes(path.extname(req.file.originalname).toLowerCase())) {
      return res.status(400).json({ error: 'Android 应用只支持 APK/XAPK/OBB 文件' });
    }
    if (app.platform === 'ios' && path.extname(req.file.originalname).toLowerCase() !== '.ipa') {
      return res.status(400).json({ error: 'iOS 应用只支持 IPA 文件' });
    }

    if (!req.file) {
      return res.status(400).json({ error: '请选择要上传的文件' });
    }

    // 生成文件名
    const timestamp = Date.now();
    const ext = path.extname(req.file.originalname);
    const filename = `${platform}_${app.id}_${timestamp}${ext}`;
    const fileBuffer = req.file.buffer;
    const md5 = crypto.createHash('md5').update(fileBuffer).digest('hex');

    // 上传到存储服务
    const result = await storage.upload(filename, fileBuffer, {
      contentType: req.file.mimetype,
      metadata: { appId: app.id, platform, md5 }
    });

    // 保存记录到数据库
    await db.run(
      `INSERT INTO uploads (app_id, user_id, filename, original_name, file_size, file_type, storage_path, status, md5)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'uploaded', ?)`,
      [appId, req.user.id, filename, req.file.originalname, fileBuffer.length, ext, result.url, md5]
    );

    res.json({
      success: true,
      url: result.url,
      md5,
      size: fileBuffer.length,
      filename,
      platform
    });
  } catch (err) {
    console.error('上传失败:', err);
    res.status(500).json({ error: err.message || '上传失败' });
  }
});

// 获取应用上传列表
router.get('/list/:appId', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const uploads = await db.all(
      `SELECT u.*, a.name as app_name, a.bundle_id 
       FROM uploads u
       JOIN apps a ON u.app_id = a.id
       WHERE u.app_id = ?
       ORDER BY u.created_at DESC`,
      [req.params.appId]
    );
    res.json({ uploads });
  } catch (err) {
    res.status(500).json({ error: '获取列表失败' });
  }
});

// 删除上传记录
router.delete('/:uploadId', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const upload = await db.get('SELECT * FROM uploads WHERE id = ? AND user_id = ?', 
      [req.params.uploadId, req.user.id]);
    
    if (!upload) {
      return res.status(404).json({ error: '记录不存在' });
    }

    // 删除云存储文件
    const filename = path.basename(upload.storage_path);
    await storage.delete(filename);

    await db.run('DELETE FROM uploads WHERE id = ?', [req.params.uploadId]);
    res.json({ message: '删除成功' });
  } catch (err) {
    res.status(500).json({ error: '删除失败' });
  }
});

module.exports = router;
