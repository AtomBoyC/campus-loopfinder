@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================================
echo   LoopFinder 校园网环路定位仪 (Windows 启动器)
echo ============================================================

set "PY=python"
if exist ".venv\Scripts\python.exe" (
    set "PY=.venv\Scripts\python.exe"
)

where %PY% >nul 2>nul
if errorlevel 1 (
    echo [错误] 未检测到 Python 3，请先从 https://www.python.org/ 安装 Python 3.9+ 并勾选 Add to PATH。
    pause
    exit /b 1
)

if not exist "%SystemRoot%\System32\Npcap\wpcap.dll" if not exist "%SystemRoot%\System32\wpcap.dll" (
    echo [提示] 未检测到 Npcap 驱动。
    echo        - 弱电间 SNMP 扫描、SSH 巡检和「仿真演练模式」可直接使用；
    echo        - 如需在教研室实时抓包与发送二层探针，请先安装 Npcap: https://npcap.com/
    echo.
)

%PY% -c "import scapy" >nul 2>nul
if errorlevel 1 (
    echo [提示] 检测到尚未安装可选增强库 scapy/paramiko/pywebview。
    echo        如需在 Windows 开启实时抓包与 SSH，可运行: pip install -r requirements.txt
    echo.
)

%PY% app.py
pause
