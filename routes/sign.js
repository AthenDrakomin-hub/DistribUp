const express = require('express');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const { promisify } = require('util');
const db = require('./database');
const { checkPermission } = require('../middleware/auth');

const router = express.Router();
const execAsync = promisify(exec);

// 确保目录存在
const signedDir = path.join(__dirname, '../signed');
if (!fs.existsSync(signedDir)) {
  fs.mkdirSync(signedDir, { recursive: true });
}

// 重签名接口
router.post('/resign', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const { appId, certId, udids } = req.body;

    if (!appId || !certId || !udids || udids.length === 0) {
      return res.status(400).json({ error: '缺少必要参数' });
    }

    // 获取应用和证书信息
    const [app, cert] = await Promise.all([
      db.get('SELECT * FROM apps WHERE id = ?', [appId]),
      db.get('SELECT * FROM certificates WHERE id = ? AND team_id IN (SELECT team_id FROM users WHERE id = ?)', [certId, req.user.id])
    ]);

    if (!app || !cert) {
      return res.status(404).json({ error: '应用或证书不存在' });
    }

    // 检查证书是否过期
    if (cert.expires_at && new Date(cert.expires_at) < new Date()) {
      return res.status(400).json({ error: '证书已过期' });
    }

    // 构建输出文件名
    const timestamp = Date.now();
    const outputFilename = `${app.bundle_id}_signed_${timestamp}.ipa`;
    const outputPath = path.join(signedDir, outputFilename);

    // 构建 zsign 命令
    const certPath = path.join(__dirname, '../certs', cert.certificate_p12);
    const provisionPath = path.join(__dirname, '../certs', cert.mobileprovision);
    
    // 查找原始 IPA
    const uploads = await db.all('SELECT storage_path FROM uploads WHERE app_id = ? ORDER BY created_at DESC LIMIT 1', [appId]);
    if (!uploads.length) {
      return res.status(404).json({ error: '未找到原始 IPA 文件' });
    }

    const inputPath = uploads[0].storage_path;
    
    if (!fs.existsSync(inputPath) || !fs.existsSync(certPath)) {
      return res.status(400).json({ error: '源文件不存在' });
    }

    // 生成 UDID 列表文件
    const udidFile = path.join(__dirname, '../temp_udids.txt');
    fs.writeFileSync(udidFile, udids.join('\n'));

    // 执行 zsign
    const cmd = `zsign -k "${certPath}" -p "${cert.certificate_password}" -m "${provisionPath}" -o "${outputPath}" "${inputPath}"`;
    
    try {
      const { stdout, stderr } = await execAsync(cmd, { timeout: 300000 });
      
      // 清理临时文件
      fs.unlinkSync(udidFile);
      
      // 更新上传记录
      await db.run('UPDATE uploads SET status = ?', ['signed']);
      
      res.json({
        success: true,
        downloadUrl: `/signed/${outputFilename}`,
        filename: outputFilename,
        stdout
      });
    } catch (execErr) {
      fs.unlinkSync(udidFile);
      throw new Error(execErr.stderr || execErr.message);
    }
  } catch (err) {
    console.error('签名失败:', err);
    res.status(500).json({ error: '签名失败: ' + err.message });
  }
});

// 获取签名后的文件列表
router.get('/list/:appId', checkPermission(['user', 'admin']), async (req, res) => {
  try {
    const signedFiles = await db.all(
      `SELECT u.*, s.filename, s.created_at 
       FROM uploads u 
       LEFT JOIN signed_files s ON u.id = s.upload_id 
       WHERE u.app_id = ? 
       ORDER BY u.created_at DESC`,
      [req.params.appId]
    );
    res.json({ files: signedFiles });
  } catch (err) {
    res.status(500).json({ error: '获取列表失败' });
  }
});

module.exports = router;
