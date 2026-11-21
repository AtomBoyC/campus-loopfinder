#!/bin/bash
# 将 LoopFinder 打包为 macOS 独立桌面应用 (dist/LoopFinder.app)
set -e
cd "$(dirname "$0")/.."

python3 -m pip install --upgrade pyinstaller pywebview scapy pyserial

python3 -m PyInstaller \
  --noconfirm \
  --windowed \
  --name "LoopFinder" \
  --add-data "loopfinder/web/static:loopfinder/web/static" \
  --add-data "loopfinder/data/sample_ledger.csv:loopfinder/data" \
  app.py

echo ""
echo "[完成] macOS 应用已生成：dist/LoopFinder.app"
echo "提示：如需免 sudo 直接进行实时二层抓包，建议在运维笔记本安装 Wireshark 自带的 ChmodBPF。"
