#!/bin/bash
set -e

echo "🚀 DistribUp 安装脚本"
echo "======================"

# 检查 Node.js
if ! command -v node &> /dev/null; then
    echo "❌ 需要 Node.js 18+"
    exit 1
fi

echo "✓ Node.js $(node -v)"

# 检查端口可用性
PORT=${PORT:-8080}
if lsof -i:$PORT &>/dev/null; then
    echo "⚠️ 端口 $PORT 已被占用"
    read -p "更改端口？[y/N] " choice
    if [[ "$choice" == [Yy]* ]]; then
        read -p "输入新端口: " PORT
    fi
fi

# 创建数据目录
mkdir -p data uploads
echo "✓ 数据目录已创建"

# 复制环境变量模板
cp .env.example .env 2>/dev/null || echo ".env 文件未找到，请手动配置"

# 启动服务
echo ""
echo "📦 启动 DistribUp..."
npm start &
SERVER_PID=$!

echo "✓ 服务正在启动 (PID: $SERVER_PID)"
echo ""
echo "访问地址: http://localhost:$PORT"
echo "管理后台: http://localhost:$PORT/admin.html"
echo ""
echo "按 Ctrl+C 停止服务"

wait $SERVER_PID
