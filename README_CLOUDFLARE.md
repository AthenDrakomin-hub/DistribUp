# DistribUp - Cloudflare Workers 部署指南

## 快速开始

### 1. 安装依赖
```bash
npm install
```

### 2. 登录 Cloudflare
```bash
npx wrangler login
```

### 3. 创建 D1 数据库
```bash
npx wrangler d1 create distribup-db
```
记录输出的 `DATABASE_ID`，填入 `wrangler.toml` 中的 `database_id`。

### 4. 创建 R2 Bucket
```bash
npx wrangler r2 bucket create distribup-files
```

### 5. 运行数据库迁移
```bash
npm run db:migrate
```

### 6. 配置环境变量
编辑 `wrangler.toml`，填入：
- `JWT_SECRET`：随机密钥
- `BASE_URL`：你的域名
- （可选）`ASC_ISSUER_ID` / `ASC_KEY_ID` / `ASC_PRIVATE_KEY`：App Store Connect API 凭证

### 7. 本地测试
```bash
npm run dev
```
访问 http://localhost:8788/admin.html

### 8. 部署到 Cloudflare
```bash
npm run deploy
```

---

## 计费说明

Cloudflare 免费额度：
- **Workers**：每天 10 万次请求，足够小规模分发使用
- **D1**：每天 5 万次读取、1 万次写入
- **R2**：每月 10GB 存储 + 1000 万次读取

超过额度后按量计费，价格透明。

---

## 文件存储说明

R2 Bucket 存储 IPA/APK 文件，下载链接格式：
```
https://distribup-files.[account-id].r2.cloudflarestorage.com/ios_1_1234567890.ipa
```

建议配置 R2 的 **Public Access** 或 **Signed URLs** 保护文件。

---

## Android 签名说明

Cloudflare Workers 无服务器环境无法直接执行 `apksigner`。

**方案一（推荐）**：APK 上传后直接提供下载链接，用户手动安装。  
签名可在本地或 CI/CD 流水线中完成，将签名后的 APK 再次上传即可。

**方案二**：部署一个独立的签名服务（如 Fly.io / Render），通过 API 调用。

---

## 原有 Node.js 版本保留

原 Express 版本代码仍保留在 `routes/` 和 `server/` 目录，可在 VPS 上运行：
```bash
cd server && node index.js
```
