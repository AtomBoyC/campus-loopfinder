#!/bin/bash
# 本地将 LoopFinder 打包为 macOS 独立桌面应用 (dist/LoopFinder.app 与 dist/LoopFinder-macOS.dmg)
set -e
cd "$(dirname "$0")/.."

python3 -m pip install --upgrade pyinstaller pywebview pyserial
python3 -m PyInstaller --noconfirm --clean LoopFinder.spec

codesign --force --deep --sign - dist/LoopFinder.app

mkdir -p dist/dmg_stage
rm -rf dist/dmg_stage/*
cp -R dist/LoopFinder.app dist/dmg_stage/
ln -sf /Applications dist/dmg_stage/Applications
cp docs/现场速查卡.md dist/dmg_stage/现场速查卡.md
hdiutil create -volname "LoopFinder" -srcfolder dist/dmg_stage -ov -format UDZO dist/LoopFinder-macOS.dmg
rm -rf dist/dmg_stage

echo ""
echo "[完成] macOS 开袋即食安装包已生成：dist/LoopFinder-macOS.dmg"
echo "       应用本体位于：dist/LoopFinder.app"
