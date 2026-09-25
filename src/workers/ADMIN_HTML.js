export const ADMIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理后台 - DistribUp</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f7; }
        .sidebar { position: fixed; left: 0; top: 0; width: 250px; height: 100vh; background: #1a1a2e; color: white; padding: 20px; }
        .sidebar h2 { margin-bottom: 30px; padding-bottom: 20px; border-bottom: 1px solid #333; }
        .sidebar nav a { display: block; padding: 15px; color: #aaa; text-decoration: none; border-radius: 8px; margin-bottom: 5px; }
        .sidebar nav a:hover, .sidebar nav a.active { background: #667eea; color: white; }
        .main { margin-left: 250px; padding: 30px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .card { background: white; border-radius: 12px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        .card h3 { margin-bottom: 20px; color: #333; }
        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        .stat-card .number { font-size: 36px; font-weight: 700; color: #667eea; }
        .stat-card .label { color: #666; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 15px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; color: #333; }
        .btn { padding: 8px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; }
        .btn-primary { background: #667eea; color: white; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn-success { background: #27ae60; color: white; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: #333; font-weight: 500; }
        .form-group input, .form-group select { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; }
        .platform-badge { padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .platform-badge.ios { background: #e3f2fd; color: #1565c0; }
        .platform-badge.android { background: #e8f5e9; color: #2e7d32; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; }
        .modal-content { background: white; width: 90%; max-width: 600px; margin: 50px auto; padding: 30px; border-radius: 12px; }
        .close { float: right; font-size: 28px; cursor: pointer; color: #aaa; }
        .close:hover { color: #333; }
    </style>
</head>
<body>
    <div class="sidebar">
        <h2>📦 DistribUp</h2>
        <nav>
            <a href="#" class="active" onclick="showPage('dashboard')">控制面板</a>
            <a href="#" onclick="showPage('apps')">应用管理</a>
            <a href="#" onclick="showPage('devices')">设备管理</a>
            <a href="#" onclick="showPage('users')">用户管理</a>
            <a href="#" onclick="showPage('settings')">系统设置</a>
        </nav>
    </div>
    
    <div class="main">
        <div class="header">
            <h1>管理后台</h1>
            <div>
                <span id="userInfo"></span>
                <button class="btn btn-danger" onclick="logout()">退出</button>
            </div>
        </div>
        
        <div id="dashboard" class="page">
            <div class="stats">
                <div class="stat-card">
                    <div class="number" id="totalApps">0</div>
                    <div class="label">应用总数</div>
                </div>
                <div class="stat-card">
                    <div class="number" id="totalDevices">0</div>
                    <div class="label">注册设备</div>
                </div>
                <div class="stat-card">
                    <div class="number" id="totalDownloads">0</div>
                    <div class="label">下载次数</div>
                </div>
                <div class="stat-card">
                    <div class="number" id="totalUsers">0</div>
                    <div class="label">用户数</div>
                </div>
            </div>
            
            <div class="card">
                <h3>最近上传</h3>
                <table>
                    <thead>
                        <tr><th>应用</th><th>文件名</th><th>大小</th><th>时间</th></tr>
                    </thead>
                    <tbody id="recentUploads"></tbody>
                </table>
            </div>
        </div>
        
        <div id="apps" class="page" style="display:none">
            <div class="card">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px">
                    <h3>应用列表</h3>
                    <button class="btn btn-primary" onclick="showAddApp()">+ 新建应用</button>
                </div>
                <table>
                    <thead>
                        <tr><th>ID</th><th>名称</th><th>平台</th><th>Bundle ID</th><th>版本</th><th>操作</th></tr>
                    </thead>
                    <tbody id="appsList"></tbody>
                </table>
            </div>
        </div>
        
        <div id="devices" class="page" style="display:none">
            <div class="card">
                <h3>设备管理</h3>
                <table>
                    <thead>
                        <tr><th>UDID</th><th>名称</th><th>平台</th><th>注册时间</th></tr>
                    </thead>
                    <tbody id="devicesList"></tbody>
                </table>
            </div>
        </div>
    </div>
    
    <div id="addAppModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <h3>新建应用</h3>
            <div class="form-group">
                <label>应用名称</label>
                <input type="text" id="appName" placeholder="请输入应用名称">
            </div>
            <div class="form-group">
                <label>平台</label>
                <select id="appPlatform" onchange="updatePackageNameField()">
                    <option value="ios">iOS</option>
                    <option value="android">Android</option>
                </select>
            </div>
            <div class="form-group">
                <label>Bundle ID / 包名</label>
                <input type="text" id="bundleId" placeholder="com.example.app">
            </div>
            <div class="form-group" id="packageNameGroup" style="display:none">
                <label>Package Name（可选，与 Bundle ID 相同也可）</label>
                <input type="text" id="packageName" placeholder="com.example.app">
            </div>
            <div class="form-group">
                <label>版本号</label>
                <input type="text" id="appVersion" value="1.0.0">
            </div>
            <button class="btn btn-primary" onclick="createApp()">创建</button>
        </div>
    </div>
    
    <script>
        const API_BASE = '/api';
        let token = localStorage.getItem('token');
        
        async function api(path, options = {}) {
            const res = await fetch(API_BASE + path, {
                headers: { 'Authorization': \x60Bearer ${token}\x60 },
                ...options
            });
            return res.json();
        }
        
        async function loadDashboard() {
            const apps = await api('/apps');
            const devices = await api('/appstore/devices');
            document.getElementById('totalApps').textContent = apps.apps?.length || 0;
            document.getElementById('totalDevices').textContent = devices.devices?.length || 0;
        }
        
        async function loadApps() {
            const apps = await api('/apps');
            const tbody = document.getElementById('appsList');
            tbody.innerHTML = (apps.apps || []).map(app => \x60
                <tr>
                    <td>${app.id}</td>
                    <td>${app.name}</td>
                    <td><span class="platform-badge ${app.platform}">${app.platform === 'ios' ? '🍎 iOS' : '🤖 Android'}</span></td>
                    <td>${app.bundle_id}</td>
                    <td>${app.version}</td>
                    <td>
                        <button class="btn btn-primary" onclick="uploadApp(${app.id})">上传</button>
                        <button class="btn btn-danger" onclick="deleteApp(${app.id})">删除</button>
                    </td>
                </tr>
            \x60).join('');
        }
        
        function showPage(page) {
            document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
            document.getElementById(page).style.display = 'block';
            document.querySelectorAll('.sidebar nav a').forEach(a => a.classList.remove('active'));
            event.target.classList.add('active');
            if (page === 'dashboard') loadDashboard();
            if (page === 'apps') loadApps();
        }
        
        function showAddApp() {
            document.getElementById('addAppModal').style.display = 'block';
            updatePackageNameField();
        }

        function updatePackageNameField() {
            const platform = document.getElementById('appPlatform').value;
            document.getElementById('packageNameGroup').style.display = platform === 'android' ? 'block' : 'none';
            document.getElementById('bundleId').placeholder = platform === 'android' ? 'com.example.app' : 'com.example.app';
        }

        function closeModal() { document.getElementById('addAppModal').style.display = 'none'; }
        
        async function createApp() {
            const platform = document.getElementById('appPlatform').value;
            const packageName = platform === 'android' ? document.getElementById('packageName').value : null;
            const res = await api('/apps', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: document.getElementById('appName').value,
                    platform: platform,
                    bundle_id: document.getElementById('bundleId').value,
                    package_name: packageName,
                    version: document.getElementById('appVersion').value
                })
            });
            if (res.app) { closeModal(); loadApps(); }
        }
        
        function uploadApp(appId) {
            window.location.href = \x60/upload.html?id=${appId}\x60;
        }
        
        function logout() {
            localStorage.removeItem('token');
            window.location.href = '/';
        }
        
        // 初始化
        if (!token) window.location.href = '/login.html';
        loadDashboard();
    </script>
</body>
</html>
`;
