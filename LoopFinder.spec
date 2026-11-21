# -*- mode: python ; coding: utf-8 -*-
"""Unified PyInstaller spec for LoopFinder (Windows single-file .exe & macOS .app)."""

import os
import platform
import sys

from PyInstaller.utils.hooks import collect_all, collect_submodules

IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"

datas = [
    ("loopfinder/web/static", "loopfinder/web/static"),
    ("loopfinder/data/sample_ledger.csv", "loopfinder/data"),
    ("loopfinder/data/oui_ieee.tsv.gz", "loopfinder/data"),
]
binaries = []
hiddenimports = [
    "serial",
    "serial.tools",
    "serial.tools.list_ports",
    "loopfinder.core.mac_bpf",
    "loopfinder.core.console_inspector",
]

# Collect pywebview (native desktop window on Windows WebView2 & macOS WKWebView)
for _pkg in ("webview", "clr_loader", "pythonnet") if IS_WIN else ("webview",):
    try:
        _d, _b, _h = collect_all(_pkg)
        datas += _d
        binaries += _b
        hiddenimports += _h
    except Exception:
        pass

# On Windows, bundle scapy's core L2/Npcap modules (macOS uses zero-dep native mac_bpf.py)
if IS_WIN:
    try:
        for _mod in ("scapy.arch", "scapy.layers", "scapy.modules", "scapy.asn1"):
            hiddenimports += collect_submodules(_mod)
        hiddenimports += [
            "scapy.all",
            "scapy.sendrecv",
            "scapy.config",
            "scapy.supersocket",
            "serial.tools.list_ports_windows",
            "webview.platforms.edgechromium",
        ]
    except Exception:
        pass
elif IS_MAC:
    hiddenimports += [
        "serial.tools.list_ports_osx",
        "serial.tools.list_ports_posix",
        "webview.platforms.cocoa",
    ]

block_cipher = None

a = Analysis(
    ["app.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "pandas", "scipy", "PIL", "pytest"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

if IS_WIN:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.zipfiles,
        a.datas,
        [],
        name="LoopFinder",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,
        disable_windowed_traceback=False,
        uac_admin=True,
        icon="assets/icon.ico" if os.path.isfile("assets/icon.ico") else None,
    )
elif IS_MAC:
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name="LoopFinder",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,
        argv_emulation=False,
        icon="assets/icon.icns" if os.path.isfile("assets/icon.icns") else None,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.zipfiles,
        a.datas,
        strip=False,
        upx=False,
        name="LoopFinder",
    )
    app = BUNDLE(
        coll,
        name="LoopFinder.app",
        icon="assets/icon.icns" if os.path.isfile("assets/icon.icns") else None,
        bundle_identifier="com.atomboyc.campus-loopfinder",
        info_plist={
            "CFBundleName": "LoopFinder",
            "CFBundleDisplayName": "LoopFinder 校园网环路定位仪",
            "CFBundleShortVersionString": "2.3.1",
            "CFBundleVersion": "2.3.1",
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "11.0",
            "NSLocalNetworkUsageDescription": "LoopFinder 需要访问本地局域网以检测教研室网络环路并查询弱电间交换机。",
        },
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.zipfiles,
        a.datas,
        [],
        name="LoopFinder",
        debug=False,
        console=True,
    )
