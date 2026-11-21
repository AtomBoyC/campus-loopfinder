@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================================
echo   LoopFinder 校园网环路定位仪 (Windows 源码一键启动器)
echo ============================================================
echo [提示] 如果不想安装 Python，请直接到 GitHub Releases 下载开袋即食版 LoopFinder.exe！
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [错误] 未检测到 Python 3。
    echo        推荐方案：直接到 GitHub Releases 下载 LoopFinder-Windows-x64.zip，解压双击 LoopFinder.exe 即可，无需安装 Python！
    echo        或从 https://www.python.org/ 安装 Python 3.9+（勾选 Add Python to PATH）。
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [首次运行] 正在自动创建独立运行环境并安装组件，请稍等 1~2 分钟...
    python -m venv .venv
    .venv\Scripts\python.exe -m pip install --upgrade pip >nul 2>nul
    .venv\Scripts\python.exe -m pip install -r requirements.txt
)

if not exist "%SystemRoot%\System32\Npcap\wpcap.dll" if not exist "%SystemRoot%\System32\wpcap.dll" (
    echo [提示] 未检测到 Npcap 驱动：机房 SNMP / Console / 演练可直接用；
    echo        如需去教研室实时抓包，请安装 https://npcap.com/ （勾选 WinPcap 兼容模式）。
    echo.
)

.venv\Scripts\python.exe app.py
pause
