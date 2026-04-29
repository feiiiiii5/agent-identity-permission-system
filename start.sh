#!/bin/bash
set -e

echo "=== AgentPass 启动脚本 ==="

if [ ! -d "data" ]; then
    mkdir -p data
fi

if [ ! -d "reports" ]; then
    mkdir -p reports
fi

if [ -f ".env" ]; then
    echo "加载 .env 配置..."
    export $(grep -v '^#' .env | xargs)
fi

echo "启动 AgentPass 服务..."
python3 main.py
