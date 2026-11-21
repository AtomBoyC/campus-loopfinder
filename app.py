#!/usr/bin/env python3
"""LoopFinder Desktop Application Entrypoint (macOS & Windows).

Starts the local-only diagnostic backend on 127.0.0.1 and launches a clean
native desktop window (via pywebview if installed, or frameless Chrome/Edge
--app desktop window, with default browser fallback).
"""

from __future__ import annotations

import argparse
import multiprocessing
import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time
import webbrowser

from loopfinder import __app_name__, __version__
from loopfinder.core.interfaces import check_capabilities
from loopfinder.core.paths import ensure_data_dir
from loopfinder.web.server import create_server


def _ensure_safe_stdio() -> None:
    """In PyInstaller --windowed builds on Windows/macOS, sys.stdout/stderr can be None."""
    if sys.stdout is None or sys.stderr is None:
        try:
            log_path = os.path.join(ensure_data_dir(), "loopfinder.log")
            fh = open(log_path, "a", encoding="utf-8", buffering=1)
            if sys.stdout is None:
                sys.stdout = fh  # type: ignore
            if sys.stderr is None:
                sys.stderr = fh  # type: ignore
        except Exception:
            devnull = open(os.devnull, "w", encoding="utf-8")
            if sys.stdout is None:
                sys.stdout = devnull  # type: ignore
            if sys.stderr is None:
                sys.stderr = devnull  # type: ignore


def _open_desktop_window(url: str, force_browser: bool = False) -> bool:
    """Try opening a frameless desktop window using Chrome/Edge --app mode."""
    system = platform.system()
    if force_browser:
        webbrowser.open(url)
        return False

    if system == "Darwin":
        sudo_user = os.environ.get("SUDO_USER")
        chrome_bin = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        edge_bin = "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
        chosen = chrome_bin if os.path.isfile(chrome_bin) else (edge_bin if os.path.isfile(edge_bin) else None)

        if chosen:
            cmd = [chosen, f"--app={url}", "--window-size=1360,880", "--proxy-bypass-list=127.0.0.1;localhost"]
            if sudo_user and os.geteuid() == 0:
                subprocess.Popen(
                    ["sudo", "-u", sudo_user, *cmd],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True

        # Fallback: macOS `open` under original desktop user
        if sudo_user and os.geteuid() == 0:
            subprocess.Popen(
                ["sudo", "-u", sudo_user, "open", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            subprocess.Popen(["open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return False

    if system == "Windows":
        candidates = [
            os.path.join(os.environ.get("ProgramFiles(x86)", ""), r"Microsoft\Edge\Application\msedge.exe"),
            os.path.join(os.environ.get("ProgramFiles", ""), r"Microsoft\Edge\Application\msedge.exe"),
            os.path.join(os.environ.get("ProgramFiles", ""), r"Google\Chrome\Application\chrome.exe"),
            os.path.join(os.environ.get("ProgramFiles(x86)", ""), r"Google\Chrome\Application\chrome.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Google\Chrome\Application\chrome.exe"),
        ]
        for exe in candidates:
            if exe and os.path.isfile(exe):
                subprocess.Popen(
                    [exe, f"--app={url}", "--window-size=1360,880", "--proxy-bypass-list=127.0.0.1;localhost"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return True
        webbrowser.open(url)
        return False

    # Linux fallback
    for bin_name in ("google-chrome", "chromium", "chromium-browser", "microsoft-edge"):
        exe = shutil.which(bin_name)
        if exe:
            subprocess.Popen(
                [exe, f"--app={url}", "--window-size=1360,880"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
    webbrowser.open(url)
    return False


class _DesktopBridge:
    """Minimal whitelisted JS-to-Python bridge exposed to pywebview."""

    def __init__(self, base_url: str) -> None:
        self._base_url = base_url.rstrip("/")

    def open_in_browser(self, target_url: str) -> bool:
        target = (target_url or "").strip()
        if not target:
            return False
        if target.startswith("/"):
            target = f"{self._base_url}{target}"
        allowed_prefixes = (
            f"{self._base_url}/",
            "https://npcap.com/",
            "https://github.com/AtomBoyC/campus-loopfinder",
        )
        if not target.startswith(allowed_prefixes):
            return False
        try:
            webbrowser.open(target)
            return True
        except Exception:
            return False


def main() -> int:
    multiprocessing.freeze_support()
    _ensure_safe_stdio()
    parser = argparse.ArgumentParser(description=f"{__app_name__} v{__version__}")
    parser.add_argument("--port", type=int, default=18765, help="本地服务端口（默认 18765，占用时自动换端口）")
    parser.add_argument("--demo", action="store_true", help="启动时自动进入教研室环路仿真演练模式")
    parser.add_argument("--browser", action="store_true", help="强制在默认浏览器打开（不使用 pywebview）")
    parser.add_argument("--no-open", action="store_true", help="仅启动本地服务，不自动打开窗口")
    args, _unknown = parser.parse_known_args()

    try:
        server, ctx = create_server(host="127.0.0.1", port=args.port)
    except OSError:
        server, ctx = create_server(host="127.0.0.1", port=0)

    actual_port = server.server_address[1]
    url = f"http://127.0.0.1:{actual_port}"
    caps = check_capabilities()

    print("=" * 64)
    print(f"  {__app_name__} v{__version__}")
    print(f"  本地控制台地址: {url}")
    print(f"  运行平台: {caps['os']} | 实时二层抓包: {'就绪 (' + caps['preferred_backend'] + ')' if caps['can_live_capture'] else '未提权/缺少驱动（可用仿真与SNMP）'}")
    if not caps["can_live_capture"]:
        print(f"  提示: {caps['hint']}")
    print("  按 Ctrl+C 退出程序")
    print("=" * 64)

    if args.demo:
        ctx.capture.start(interface="__SIMULATION__", mode="active", backend="simulation")

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    def _shutdown(*_a) -> None:
        ctx.capture.stop()
        ctx.syslog.stop()
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Prefer native pywebview desktop window when installed and not macOS root
    use_pywebview = False
    if not args.no_open and not args.browser:
        if not (platform.system() == "Darwin" and os.geteuid() == 0):
            try:
                import webview  # type: ignore

                webview.settings["ALLOW_DOWNLOADS"] = True
                webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True
                webview.create_window(
                    f"{__app_name__} v{__version__}",
                    url,
                    width=1360,
                    height=880,
                    min_size=(980, 660),
                    js_api=_DesktopBridge(url),
                )
                use_pywebview = True
                webview.start()
                ctx.capture.stop()
                ctx.syslog.stop()
                server.shutdown()
                return 0
            except ImportError:
                use_pywebview = False
            except Exception as e:
                use_pywebview = False
                print(f"[提示] pywebview 窗口启动回退至独立桌面窗口模式: {e}")

    if not use_pywebview and not args.no_open:
        time.sleep(0.25)
        _open_desktop_window(url, force_browser=args.browser)

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        _shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
