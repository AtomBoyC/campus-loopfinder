@echo off
chcp 65001 >nul
REM 将 LoopFinder 打包为 Windows 独立桌面程序 (dist\LoopFinder\LoopFinder.exe)
cd /d "%~dp0\.."

python -m pip install --upgrade pyinstaller pywebview scapy paramiko

python -m PyInstaller ^
  --noconfirm ^
  --windowed ^
  --uac-admin ^
  --name "LoopFinder" ^
  --add-data "loopfinder\web\static;loopfinder\web\static" ^
  --add-data "loopfinder\data\sample_ledger.csv;loopfinder\data" ^
  app.py

echo.
echo [完成] Windows 独立程序已生成：dist\LoopFinder\LoopFinder.exe
echo 提示：目标运维电脑需提前安装 Npcap (https://npcap.com/) 以支持原始二层抓包。
pause
