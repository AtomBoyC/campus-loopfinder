"""Cross-platform network interface discovery & L2 capture capability check."""

from __future__ import annotations

import ctypes
import glob
import json
import os
import platform
import re
import socket
import subprocess
from typing import Any, Dict, List, Optional


def is_admin() -> bool:
    """Return True if process runs with elevated/root privileges."""
    system = platform.system().lower()
    if system == "windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def check_capabilities() -> Dict[str, Any]:
    """Detect available L2 capture backends and privilege status."""
    system = platform.system()
    has_scapy = False
    try:
        import scapy.all  # noqa: F401
        has_scapy = True
    except Exception:
        has_scapy = False

    has_bpf_access = False
    has_npcap = False
    preferred_backend = "simulation"
    hint = ""

    if system == "Darwin":
        for dev in sorted(glob.glob("/dev/bpf*"))[:16]:
            if os.access(dev, os.R_OK | os.W_OK):
                has_bpf_access = True
                break
        if has_bpf_access:
            preferred_backend = "mac_bpf" if not has_scapy else "mac_bpf"
            hint = "macOS 原生 BPF 抓包与主动二层探针就绪（支持内核级回环防误报）"
        else:
            preferred_backend = "simulation"
            hint = (
                "当前尚未开启本机有线抓包权限：点击右侧「🔐 一键开启本机抓包权限」输入开机密码即可立刻解锁；"
                "若只做仿真演练或机房 SNMP / Console 排查，无需授权可直接用。"
            )
    elif system == "Windows":
        npcap_dll = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap", "wpcap.dll")
        winpcap_dll = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "wpcap.dll")
        has_npcap = os.path.isfile(npcap_dll) or os.path.isfile(winpcap_dll)
        if has_scapy and has_npcap:
            preferred_backend = "scapy"
            hint = "Windows Npcap + Scapy 二层引擎就绪"
            if not is_admin():
                hint += "（建议右键「以管理员身份运行」确保所有网卡均可发包）"
        elif not has_npcap:
            hint = "去教研室实时抓包需安装一次免费驱动 Npcap（安装时勾选 WinPcap 兼容模式）；机房 SNMP、Console 串口直连与仿真演练当前可直接用。"
        else:
            hint = "Windows 源码运行需安装 scapy（运行 `pip install scapy`）以启用实时二层抓包；SNMP / Console 与仿真模式已可直接运行。"
    else:
        if has_scapy and is_admin():
            preferred_backend = "scapy"
            hint = "Linux Scapy Raw Socket 引擎就绪"
        else:
            hint = "Linux 实时抓包需 root/CAP_NET_RAW 权限与 scapy；SNMP / Console 与仿真模式已就绪。"

    return {
        "os": system,
        "os_release": platform.release(),
        "is_admin": is_admin(),
        "has_scapy": has_scapy,
        "has_bpf_access": has_bpf_access,
        "has_npcap": has_npcap,
        "can_live_capture": bool(
            (system == "Darwin" and has_bpf_access)
            or (system == "Windows" and has_scapy and has_npcap)
            or (system == "Linux" and has_scapy and is_admin())
        ),
        "preferred_backend": preferred_backend,
        "hint": hint,
    }


def _run_cmd(cmd: List[str], timeout: float = 4.0) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout)
        for enc in ("utf-8", "gbk", "cp936", "latin-1"):
            try:
                return out.decode(enc)
            except UnicodeDecodeError:
                continue
        return out.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _list_macos_interfaces() -> List[Dict[str, Any]]:
    hw_map: Dict[str, str] = {}
    hw_out = _run_cmd(["networksetup", "-listallhardwareports"])
    cur_port = ""
    for line in hw_out.splitlines():
        line = line.strip()
        if line.startswith("Hardware Port:"):
            cur_port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:"):
            dev = line.split(":", 1)[1].strip()
            if cur_port:
                hw_map[dev] = cur_port

    if_out = _run_cmd(["ifconfig"])
    interfaces: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None

    for line in if_out.splitlines():
        if line and not line[0].isspace() and ":" in line:
            if current:
                interfaces.append(current)
            name = line.split(":", 1)[0].strip()
            flags_m = re.search(r"<([^>]*)>", line)
            flags = flags_m.group(1).split(",") if flags_m else []
            current = {
                "name": name,
                "display_name": hw_map.get(name, name),
                "mac": "",
                "ipv4": "",
                "is_up": "UP" in flags and "RUNNING" in flags,
                "active": False,
                "is_wired": False,
                "media": "",
            }
        elif current:
            s = line.strip()
            if s.startswith("ether "):
                current["mac"] = s.split()[1].upper()
            elif s.startswith("inet ") and not current["ipv4"]:
                parts = s.split()
                if len(parts) >= 2:
                    current["ipv4"] = parts[1]
            elif s.startswith("status:"):
                current["active"] = "active" in s.lower()
            elif s.startswith("media:"):
                current["media"] = s.split(":", 1)[1].strip()

    if current:
        interfaces.append(current)

    filtered: List[Dict[str, Any]] = []
    for iface in interfaces:
        name = iface["name"]
        if not re.match(r"^(en|bridge|vlan)\d+$", name):
            continue
        disp = iface["display_name"]
        low = (disp + " " + iface.get("media", "")).lower()
        is_bridge = name.startswith("bridge")
        is_wifi = "wi-fi" in low or "airport" in low or "802.11" in low
        is_wired = (
            not is_wifi
            and not is_bridge
            and ("ethernet" in low or "lan" in low or "usb" in low or "baset" in low or "thunderbolt" in low)
        )
        iface["is_wired"] = is_wired
        iface["is_wifi"] = is_wifi
        if not iface["mac"]:
            continue
        label_parts = [name]
        if disp != name:
            label_parts.append(disp)
        if iface["ipv4"]:
            label_parts.append(iface["ipv4"])
        elif iface["active"]:
            label_parts.append("已插线/无IP")
        else:
            label_parts.append("未插线")
        iface["label"] = " · ".join(label_parts)
        filtered.append(iface)

    # Sort: physical active wired first, then active interfaces with IPv4, demote bridge*
    filtered.sort(
        key=lambda x: (
            x["name"].startswith("bridge"),
            not x["active"],
            not x["is_wired"],
            not bool(x["ipv4"]),
            x["name"],
        )
    )
    return filtered


def _list_windows_interfaces() -> List[Dict[str, Any]]:
    interfaces: List[Dict[str, Any]] = []
    ps_script = (
        "Get-NetAdapter | ForEach-Object { "
        "$ip = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue "
        "| Select-Object -First 1 -ExpandProperty IPAddress); "
        "[PSCustomObject]@{Name=$_.Name; Desc=$_.InterfaceDescription; Mac=$_.MacAddress; "
        "Status=$_.Status.ToString(); LinkSpeed=$_.LinkSpeed; IP=$ip; Guid=$_.InterfaceGuid} "
        "} | ConvertTo-Json -Compress"
    )
    out = _run_cmd(["powershell", "-NoProfile", "-Command", ps_script], timeout=6.0)
    if out.strip():
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                name = str(item.get("Name") or "")
                desc = str(item.get("Desc") or name)
                mac = str(item.get("Mac") or "").replace("-", ":").upper()
                status = str(item.get("Status") or "")
                ip = str(item.get("IP") or "")
                active = status.lower() == "up"
                low = (name + " " + desc).lower()
                is_wifi = "wi-fi" in low or "wireless" in low or "wlan" in low
                is_wired = not is_wifi and ("ethernet" in low or "以太网" in low or "realtek" in low or "intel" in low or "usb" in low or "gigabit" in low)
                guid = str(item.get("Guid") or "")
                scapy_name = f"\\Device\\NPF_{guid}" if guid else name
                label_parts = [name]
                if desc and desc != name:
                    label_parts.append(desc[:32])
                label_parts.append(ip if ip else ("已插线/无IP" if active else "未连接"))
                interfaces.append({
                    "name": name,
                    "scapy_name": scapy_name,
                    "display_name": desc,
                    "mac": mac,
                    "ipv4": ip,
                    "is_up": active,
                    "active": active,
                    "is_wired": is_wired,
                    "is_wifi": is_wifi,
                    "media": str(item.get("LinkSpeed") or ""),
                    "label": " · ".join(label_parts),
                })
        except Exception:
            pass

    if not interfaces:
        # Fallback to basic socket hostname lookup
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = ""
        interfaces.append({
            "name": "Ethernet",
            "display_name": "默认有线网卡",
            "mac": "",
            "ipv4": ip,
            "is_up": True,
            "active": True,
            "is_wired": True,
            "is_wifi": False,
            "media": "",
            "label": f"默认网卡 · {ip or '未分配IP'}",
        })

    interfaces.sort(key=lambda x: (not x["active"], not x["is_wired"], x["name"]))
    return interfaces


def _list_linux_interfaces() -> List[Dict[str, Any]]:
    interfaces: List[Dict[str, Any]] = []
    sys_net = "/sys/class/net"
    if os.path.isdir(sys_net):
        for name in sorted(os.listdir(sys_net)):
            if name == "lo":
                continue
            mac = ""
            state = ""
            try:
                with open(f"{sys_net}/{name}/address", "r", encoding="utf-8") as fh:
                    mac = fh.read().strip().upper()
                with open(f"{sys_net}/{name}/operstate", "r", encoding="utf-8") as fh:
                    state = fh.read().strip().lower()
            except OSError:
                pass
            active = state == "up"
            is_wifi = name.startswith(("wl", "wlan"))
            interfaces.append({
                "name": name,
                "display_name": name,
                "mac": mac,
                "ipv4": "",
                "is_up": active,
                "active": active,
                "is_wired": not is_wifi,
                "is_wifi": is_wifi,
                "media": state,
                "label": f"{name} · {'已连接' if active else '未连接'}",
            })
    return interfaces


def request_macos_bpf_permission() -> Dict[str, Any]:
    """Prompt macOS graphical administrator dialog to grant /dev/bpf* rw access to current user's group.

    Uses the same group-permission model as Wireshark's official ChmodBPF helper so
    beginners using the double-click .app never need to open Terminal or type sudo.
    """
    if platform.system() != "Darwin":
        return {"ok": False, "error": "仅 macOS 支持此一键授权操作"}
    gid = os.getgid()
    script = f'do shell script "chgrp {gid} /dev/bpf* && chmod g+rw /dev/bpf*" with administrator privileges'
    try:
        proc = subprocess.run(
            ["osascript", "-e", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=90,
            check=False,
        )
        if proc.returncode != 0:
            err_txt = proc.stderr.decode("utf-8", errors="ignore").strip()
            if "canceled" in err_txt.lower() or "-128" in err_txt:
                return {"ok": False, "error": "已取消管理员授权"}
            return {"ok": False, "error": f"授权未完成：{err_txt or '请检查管理员密码'}"}
        caps = check_capabilities()
        if not caps.get("has_bpf_access"):
            return {"ok": False, "error": "权限命令已执行，但仍无法读取 /dev/bpf0，请尝试重启软件。"}
        return {"ok": True, "capabilities": caps, "message": "已成功开启本机有线抓包权限，现在可直接开始监测！"}
    except Exception as e:
        return {"ok": False, "error": f"无法弹出 macOS 授权框：{e}"}


def list_interfaces() -> List[Dict[str, Any]]:
    """Return cross-platform list of physical network interfaces."""
    system = platform.system()
    if system == "Darwin":
        ifaces = _list_macos_interfaces()
    elif system == "Windows":
        ifaces = _list_windows_interfaces()
    else:
        ifaces = _list_linux_interfaces()
    return ifaces
