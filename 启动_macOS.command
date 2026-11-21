#!/bin/bash
# 双击启动 LoopFinder 校园网环路定位仪 (macOS)
cd "$(dirname "$0")"

PY="python3"
if [ -x ".venv/bin/python3" ]; then
  PY=".venv/bin/python3"
fi

echo "============================================================"
echo "  LoopFinder 校园网环路定位仪 (macOS 启动器)"
echo "============================================================"

# 检查当前用户是否有 /dev/bpf0 读写权限（安装过 Wireshark ChmodBPF 的电脑无需 sudo）
if [ -r /dev/bpf0 ] && [ -w /dev/bpf0 ]; then
  echo "[OK] 已检测到 /dev/bpf 抓包权限，直接启动..."
  "$PY" app.py
else
  echo "[提示] macOS 实时二层抓包与主动环路探针需要读取 /dev/bpf*。"
  echo "  1) 输入本机管理员密码以完整权限启动（推荐：支持实时抓包 + 主动探针 + SNMP）"
  echo "  2) 直接按回车 / 按 N 普通模式启动（支持弱电间 SNMP 扫描 + 仿真演练）"
  read -r -p "是否提权启动以开启完整二层抓包？[Y/n]: " ans
  if [[ "$ans" =~ ^[Nn]$ ]]; then
    "$PY" app.py
  else
    sudo "$PY" app.py
  fi
fi
