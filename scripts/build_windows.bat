@echo off
chcp 65001 >nul
REM 本地将 LoopFinder 打包为 Windows 单文件开袋即食程序 (dist\LoopFinder.exe)
cd /d "%~dp0\.."

python -m pip install --upgrade pyinstaller pywebview scapy pyserial
python -m PyInstaller --noconfirm --clean LoopFinder.spec

echo.
echo [完成] Windows 单文件开袋即食版已生成：dist\LoopFinder.exe
echo 提示：目标电脑如需去教研室实时抓包，安装一次 Npcap (https://npcap.com/) 即可，无需安装 Python。
pause
