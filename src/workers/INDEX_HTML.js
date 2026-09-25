export const INDEX_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DistribUp - 应用分发平台</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f7; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; }
        .header h1 { font-size: 48px; margin-bottom: 10px; }
        .header p { font-size: 18px; opacity: 0.9; }
        .nav { background: white; padding: 15px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .nav-links a { margin-left: 30px; text-decoration: none; color: #333; font-weight: 500; }
        .nav-links a:hover { color: #667eea; }
        .btn { padding: 12px 30px; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: 600; transition: all 0.3s; }
        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover { background: #5568d3; transform: translateY(-2px); }
        .btn-outline { background: transparent; color: #667eea; border: 2px solid #667eea; }
        .main { padding: 40px; }
        .feature-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 30px; margin-top: 40px; }
        .feature-card { background: white; padding: 30px; border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }
        .feature-card h3 { color: #333; margin-bottom: 15px; }
        .feature-card p { color: #666; line-height: 1.6; }
        .stats { display: flex; justify-content: center; gap: 60px; margin: 60px 0; }
        .stat-item { text-align: center; }
        .stat-number { font-size: 48px; font-weight: 700; color: #667eea; }
        .stat-label { color: #666; margin-top: 5px; }
        footer { background: #1a1a2e; color: white; padding: 40px; text-align: center; margin-top: 80px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>📦 DistribUp</h1>
        <p>企业级 iOS/Android 应用分发平台</p>
    </div>
    
    <div class="nav">
        <div class="logo">DistribUp</div>
        <div class="nav-links">
            <a href="#features">功能</a>
            <a href="#pricing">定价</a>
            <a href="#docs">文档</a>
            <a href="#" onclick="showLogin()">登录</a>
            <a href="#" onclick="showRegister()" class="btn btn-primary">注册</a>
        </div>
    </div>
    
    <div class="main">
        <div class="stats">
            <div class="stat-item">
                <div class="stat-number">10K+</div>
                <div class="stat-label">应用分发</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">500+</div>
                <div class="stat-label">企业客户</div>
            </div>
            <div class="stat-item">
                <div class="stat-number">99.9%</div>
                <div class="stat-label">可用性</div>
            </div>
        </div>
        
        <div id="features" class="feature-grid">
            <div class="feature-card">
                <h3>🔐 自动签名</h3>
                <p>集成 zsign 引擎，支持 iOS 证书自动重签名，为特定 UDID 列表生成可安装 IPA 文件。</p>
            </div>
            <div class="feature-card">
                <h3>☁️ 多端存储</h3>
                <p>支持本地、AWS S3、阿里云 OSS 等多种存储后端，灵活适配不同业务场景。</p>
            </div>
            <div class="feature-card">
                <h3>👥 多租户隔离</h3>
                <p>团队级别数据隔离，每个团队独立管理应用、证书和设备，安全可靠。</p>
            </div>
            <div class="feature-card">
                <h3>📱 OTA 安装</h3>
                <p>一键生成 itms-services 安装链接，用户扫码即可安装，无需连接电脑。</p>
            </div>
            <div class="feature-card">
                <h3>🔌 App Store API</h3>
                <p>集成 App Store Connect API，自动注册设备、同步证书和 Profile。</p>
            </div>
            <div class="feature-card">
                <h3>📊 数据统计</h3>
                <p>详细的下载统计和日志记录，实时监控应用分发情况。</p>
            </div>
        </div>
    </div>
    
    <footer>
        <p>&copy; 2026 DistribUp. All rights reserved.</p>
    </footer>
    
    <script>
        function showLogin() {
            window.location.href = '/login';
        }
        function showRegister() {
            window.location.href = '/register';
        }
    </script>
</body>
</html>
`;
