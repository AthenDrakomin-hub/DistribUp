# DistribUp - Cloudflare Workers 部署指南

## 架构说明

本项目已迁移至 Cloudflare Workers 架构：
- **D1** — 服务器端 SQLite 数据库（替代本地 SQLite 文件）
- **R2** — 对象存储（替代本地 uploads/signed 目录，兼容 S3/OSS 协议）
- **Workers** — 无服务器函数运行后端 API
- **Workers Assets** — 托管前端静态页面（public/ 目录）

---

## 快速开始

### 1. 安装 Wrangler CLI
```bash
npm install -g wrangler
# 或 npx wrangler
```

### 2. 登录 Cloudflare
```bash
wrangler login
```

### 3. 创建 Cloudflare 资源

**创建 D1 数据库：**
```bash
wrangler d1 create distribup-db
```
记录输出的 `database_id`，填入 `wrangler.toml` 的 `database_id` 字段。

**创建 R2 Bucket：**
```bash
wrangler r2 bucket create distribup-files
```

### 4. 运行数据库迁移
```bash
wrangler d1 execute distribup-db --file=migrations/001_init.sql --remote
```

### 5. 配置环境变量
编辑 `wrangler.toml`：
```toml
[vars]
JWT_SECRET = "你的随机密钥"           # 生成: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
BASE_URL = "https://distribup.example.com"  # 你的实际域名
```

### 6. 本地测试
```bash
npx wrangler dev
```
访问 http://localhost:8788/admin.html

### 7. 部署到 Cloudflare
```bash
npx wrangler deploy
```

### 8. 绑定自定义域名（可选）
在 Cloudflare Dashboard → Workers & Pages → DistribUp → 添加域名。

---

## 免费额度说明

| 资源 | 免费额度 | 说明 |
|------|---------|------|
| Workers | 10 万次请求/天 | 足够小规模分发 |
| D1 | 5 万读/1 千写/天 | 数据库操作 |
| R2 | 10GB 存储 + 100 万次读/天 | 存储 IPA/APK 文件 |

---

## 文件存储说明

所有 IPA/APK 文件存储在 R2 Bucket，访问 URL 格式：
```
https://distribup-files.<account-id>.r2.cloudflarestorage.com/<filename>
```

建议在 R2 控制台启用 **Public Access** 或使用 **Signed URLs** 保护文件。

---

## 关于签名功能

**iOS 签名（zsign）和 Android 签名（apksigner）需要本地工具执行。**

Workers 无服务器环境无法直接运行这些命令行工具。推荐方案：

1. **手动签名**：下载原始 IPA/APK → 本地签名 → 重新上传
2. **独立签名服务**：在 Fly.io / Render 上部署一个签名微服务，Workers 调用它
3. **CI/CD 集成**：GitHub Actions 中完成签名，产物上传至 R2

---

## 原有 Node.js 版本保留

原 Express 版本代码保留在 `server/` 和 `routes/` 目录，可在任意 VPS 上运行：
```bash
cd server && node index.js
```

