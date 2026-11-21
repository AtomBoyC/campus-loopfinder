"""Per-user writable data directory for LoopFinder (ledger, switch inventory).

Data must NOT live inside the code directory, because:
- A PyInstaller .app/.exe bundle is read-only / extracted to a temp dir (data would be lost).
- When started with `sudo` on macOS, files created in the project dir become root-owned and a
  later normal (non-sudo) launch can no longer save them.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from typing import Optional


def resource_path(*parts: str) -> str:
    """Resolve bundled static/data files cleanly both from source and PyInstaller bundles."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return os.path.join(meipass, *parts)
    # repo root is two levels above loopfinder/core/paths.py
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(root, *parts)


def _real_user_home() -> str:
    """Home dir of the real desktop user, even when running under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and platform.system() != "Windows":
        try:
            import pwd

            return pwd.getpwnam(sudo_user).pw_dir
        except Exception:
            pass
    return os.path.expanduser("~")


def user_data_dir() -> str:
    override = os.environ.get("LOOPFINDER_DATA_DIR")
    if override:
        path = override
    elif platform.system() == "Windows":
        path = os.path.join(os.environ.get("APPDATA") or _real_user_home(), "LoopFinder")
    else:
        path = os.path.join(_real_user_home(), ".loopfinder")
    return path


def fix_owner(path: str) -> None:
    """When running as root via sudo, hand the file back to the real user."""
    if platform.system() == "Windows":
        return
    try:
        if os.geteuid() == 0 and os.environ.get("SUDO_UID"):
            os.chown(path, int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", "-1")))
    except Exception:
        pass


def ensure_data_dir() -> str:
    path = user_data_dir()
    if not os.path.isdir(path):
        os.makedirs(path, exist_ok=True)
        fix_owner(path)
    return path


def default_data_file(filename: str) -> str:
    """Path for a data file in the user data dir; migrates a legacy copy from loopfinder/data/ once."""
    target = os.path.join(user_data_dir(), filename)
    legacy = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", filename)
    if not os.path.isfile(target) and os.path.isfile(legacy):
        try:
            ensure_data_dir()
            shutil.copy2(legacy, target)
            fix_owner(target)
        except Exception:
            return legacy
    return target


def atomic_write_text(path: str, text: str, base_dir: Optional[str] = None) -> None:
    os.makedirs(base_dir or os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)
    fix_owner(path)
