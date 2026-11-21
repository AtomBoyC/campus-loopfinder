"""Cross-platform Console (Serial RS232 / USB-to-RJ45) Switch Loop Locator.

Works out-of-band over a standard 9600 8N1 Console cable even when a severe
broadcast storm has completely killed SNMP / SSH / Web management!

Transport:
- Uses `pyserial` if installed (Windows / macOS / Linux).
- Zero-dependency native POSIX `termios` driver on macOS & Linux when `pyserial`
  is absent (so macOS laptops work out-of-the-box with zero pip installs!).

Capabilities:
- Automatic vendor/prompt detection (Huawei VRP, H3C Comware, Ruijie RGOS,
  Cisco IOS/Catalyst, TP-LINK Managed)
- 2-pass Inbound Broadcast Counter Delta over Console (computes exact per-port
  inbound broadcast PPS to pinpoint the TRUE broadcast source port!)
- MAC Flapping / Loopback-Detection / RLDP alert extraction
- LLDP / CDP neighbor parsing to tell whether the hot port leads to a
  downstream floor switch or directly to a classroom wall jack
- Built-in realistic Simulation Mode for training & verification
"""

from __future__ import annotations

import glob
import os
import platform
import re
import select
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from loopfinder.core.ledger import PortLedger
from loopfinder.core.ssh_inspector import parse_switch_cli_output


# ==============================================================================
# Cross-Platform Serial Port Enumeration
# ==============================================================================

def list_serial_ports() -> List[Dict[str, str]]:
    """Return available Console / USB-to-Serial ports across macOS, Windows, and Linux."""
    ports: List[Dict[str, str]] = []

    try:
        import serial.tools.list_ports  # type: ignore

        for p in serial.tools.list_ports.comports():
            dev = p.device or ""
            desc = p.description or dev
            low = (dev + " " + desc).lower()
            is_bt = "bluetooth" in low or "debug-console" in low or "wlan" in low
            is_usb = any(k in low for k in ("usb", "ch340", "ch341", "ftdi", "pl2303", "cp210", "prolific", "serial", "uart", "com"))
            ports.append({
                "device": dev,
                "description": desc,
                "label": f"{dev} · {desc}" if desc != dev else dev,
                "is_usb": "1" if (is_usb and not is_bt) else "0",
                "is_bt": "1" if is_bt else "0",
            })
    except ImportError:
        system = platform.system()
        if system == "Darwin":
            for dev in sorted(glob.glob("/dev/cu.*")):
                low = dev.lower()
                is_bt = "bluetooth" in low or "debug-console" in low or "wlan" in low
                is_usb = any(k in low for k in ("usb", "wch", "slab", "pl2303", "ftdi", "serial", "uart"))
                desc = "USB 转串口 Console 线" if is_usb else ("蓝牙/系统串口" if is_bt else "串口设备")
                ports.append({
                    "device": dev,
                    "description": desc,
                    "label": f"{dev} · {desc}",
                    "is_usb": "1" if (is_usb and not is_bt) else "0",
                    "is_bt": "1" if is_bt else "0",
                })
        elif system == "Linux":
            for pattern in ("/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyS*"):
                for dev in sorted(glob.glob(pattern)):
                    is_usb = "ttyUSB" in dev or "ttyACM" in dev
                    ports.append({
                        "device": dev,
                        "description": "USB 串口" if is_usb else "主板串口",
                        "label": f"{dev} · {'USB 串口' if is_usb else '串口'}",
                        "is_usb": "1" if is_usb else "0",
                        "is_bt": "0",
                    })
        elif system == "Windows":
            try:
                out = subprocess.check_output(
                    ["powershell", "-NoProfile", "-Command", "[System.IO.Ports.SerialPort]::GetPortNames()"],
                    stderr=subprocess.DEVNULL,
                    timeout=3.0,
                ).decode("utf-8", errors="ignore")
                for line in out.splitlines():
                    com = line.strip()
                    if re.match(r"^COM\d+$", com, re.IGNORECASE):
                        ports.append({
                            "device": com.upper(),
                            "description": "Windows COM 串口（需 pip install pyserial）",
                            "label": f"{com.upper()} · 串口设备",
                            "is_usb": "1",
                            "is_bt": "0",
                        })
            except Exception:
                pass

    # Prioritize USB serial cables over Bluetooth/system serial ports
    ports.sort(key=lambda x: (x["is_bt"] == "1", x["is_usb"] != "1", x["device"]))
    return ports


# ==============================================================================
# Serial Connection Abstraction (pyserial + zero-dep POSIX termios fallback)
# ==============================================================================

class SerialTransport:
    """Unified serial read/write wrapper supporting pyserial and zero-dep macOS/Linux termios."""

    def __init__(self, device: str, baudrate: int = 9600) -> None:
        self.device = device
        self.baudrate = int(baudrate)
        self._ser = None
        self._fd: Optional[int] = None
        self._open()

    def _open(self) -> None:
        try:
            import serial  # type: ignore

            self._ser = serial.Serial(
                port=self.device,
                baudrate=self.baudrate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=0.2,
                xonxoff=False,
                rtscts=False,
                dsrdtr=False,
            )
            return
        except ImportError:
            if platform.system() == "Windows":
                raise RuntimeError("Windows Console 串口直连需要安装 pyserial：请运行 `pip install pyserial`")

        # Zero-dependency POSIX termios driver (macOS & Linux)
        import termios

        fd = os.open(self.device, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            attrs = termios.tcgetattr(fd)
            baud_const = getattr(termios, f"B{self.baudrate}", termios.B9600)
            # Input flags: disable software flow control & CR/NL translation
            attrs[0] &= ~(
                termios.IGNBRK | termios.BRKINT | termios.PARMRK | termios.ISTRIP
                | termios.INLCR | termios.IGNCR | termios.ICRNL | termios.IXON | termios.IXOFF
            )
            # Output flags: raw output
            attrs[1] &= ~termios.OPOST
            # Control flags: 8N1, local, enable receiver, disable hardware flow control
            attrs[2] &= ~(termios.CSIZE | termios.PARENB | termios.CSTOPB)
            if hasattr(termios, "CRTSCTS"):
                attrs[2] &= ~termios.CRTSCTS
            attrs[2] |= termios.CS8 | termios.CREAD | termios.CLOCAL
            # Local flags: non-canonical, no echo, no signals
            attrs[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)
            attrs[4] = baud_const  # ispeed
            attrs[5] = baud_const  # ospeed
            attrs[6][termios.VMIN] = 0
            attrs[6][termios.VTIME] = 2
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            termios.tcflush(fd, termios.TCIOFLUSH)
            self._fd = fd
        except Exception:
            os.close(fd)
            raise

    def write(self, data: str) -> None:
        raw = data.encode("utf-8", errors="ignore")
        if self._ser is not None:
            self._ser.write(raw)
            self._ser.flush()
        elif self._fd is not None:
            os.write(self._fd, raw)

    def read_available(self, timeout: float = 0.25) -> str:
        if self._ser is not None:
            self._ser.timeout = timeout
            chunk = self._ser.read(4096)
            return chunk.decode("utf-8", errors="ignore") if chunk else ""
        if self._fd is not None:
            rlist, _, _ = select.select([self._fd], [], [], timeout)
            if not rlist:
                return ""
            try:
                chunk = os.read(self._fd, 4096)
                return chunk.decode("utf-8", errors="ignore") if chunk else ""
            except BlockingIOError:
                return ""
        return ""

    def close(self) -> None:
        if self._ser is not None:
            try:
                self._ser.close()
            except Exception:
                pass
            self._ser = None
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None


# ==============================================================================
# Multi-Vendor Console Counter & Neighbor Parsers
# ==============================================================================

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\r")
_PROMPT_RE = re.compile(r"(?:^|\n)([<\[]?[A-Za-z0-9_.\-/]{1,48}[>\]#])\s*$")
_PORT_RE_LINE = re.compile(
    r"^\s*((?:(?:Ten-?|X)?GigabitEthernet|FastEthernet|Ethernet|GE|XGE|Gi|Fa|Te|Eth|Po)\s*\d+(?:/\d+){1,3})\s+(.+)$",
    re.IGNORECASE,
)


def _clean_cli(text: str) -> str:
    return _ANSI_RE.sub("", text)


def parse_counters_table(raw_text: str) -> Dict[str, Dict[str, Any]]:
    """Parse per-port inbound broadcast/multicast/total/utilization stats across Huawei/H3C/Ruijie/Cisco/TP-Link."""
    clean = _clean_cli(raw_text)
    lines = clean.splitlines()
    ports: Dict[str, Dict[str, Any]] = {}

    header_cols: List[str] = []
    mode = "generic"

    for line in lines:
        s = line.strip()
        if not s:
            continue
        low = s.lower()

        # Detect table header semantics
        if ("interface" in low or low.startswith("port ")) and any(
            k in low for k in ("broadcast", "inbcast", "inuti", "multicast", "total")
        ):
            header_cols = re.split(r"\s{2,}|\s+", low)
            if "inuti" in low:
                mode = "huawei_brief"
            elif "inbcastpkts" in low or "inoctets" in low:
                mode = "ruijie_counters"
            elif "total (pkts)" in low or ("total" in low and "broadcast" in low):
                mode = "h3c_inbound"
            elif "broadcast" in low and "multicast" in low:
                mode = "cisco_bcast"
            continue

        m = _PORT_RE_LINE.match(line)
        if not m:
            continue
        pname = re.sub(r"\s+", "", m.group(1))
        rest = m.group(2).strip()
        tokens = rest.split()
        if not tokens:
            continue

        if mode == "huawei_brief" or any(t.endswith("%") for t in tokens):
            # Format: PHY Protocol InUti OutUti inErrors outErrors
            pcts = [float(t.rstrip("%")) for t in tokens if re.match(r"^\d+(?:\.\d+)?%$", t)]
            nums = [int(t) for t in tokens if t.isdigit()]
            status = "up" if (tokens[0].lower() == "up" or "*up" in tokens[0].lower()) else "down"
            ports[pname] = {
                "port": pname,
                "status": status,
                "in_uti_pct": pcts[0] if len(pcts) >= 1 else 0.0,
                "out_uti_pct": pcts[1] if len(pcts) >= 2 else 0.0,
                "in_errors": nums[0] if len(nums) >= 1 else 0,
                "out_errors": nums[1] if len(nums) >= 2 else 0,
            }
            continue

        # Numeric counter rows (H3C inbound, Cisco broadcast, Ruijie counters)
        nums = [int(t.replace(",", "")) for t in tokens if re.match(r"^\d[\d,]*$", t)]
        if not nums:
            continue

        if mode == "h3c_inbound" and len(nums) >= 3:
            # Total, Broadcast, Multicast, [Err]
            ports[pname] = {
                "port": pname,
                "total": nums[0],
                "broadcast": nums[1],
                "multicast": nums[2],
                "errors": nums[3] if len(nums) >= 4 else 0,
            }
        elif mode == "cisco_bcast" and len(nums) >= 2:
            # Broadcast, Multicast (or InBroadcast first)
            ports[pname] = {
                "port": pname,
                "total": nums[0] + nums[1],
                "broadcast": nums[0],
                "multicast": nums[1],
                "errors": 0,
            }
        elif mode == "ruijie_counters" and len(nums) >= 4:
            # InOctets, InUcastPkts, InMcastPkts, InBcastPkts
            ports[pname] = {
                "port": pname,
                "total": nums[1] + nums[2] + nums[3],
                "multicast": nums[2],
                "broadcast": nums[3],
                "errors": 0,
            }
        elif len(nums) >= 2:
            ports[pname] = {
                "port": pname,
                "total": nums[0],
                "broadcast": nums[1] if len(nums) >= 3 else nums[0],
                "multicast": nums[2] if len(nums) >= 3 else nums[1],
                "errors": nums[3] if len(nums) >= 4 else 0,
            }

    return ports


def parse_single_huawei_interface_bcast(raw_text: str) -> Tuple[int, int]:
    """Extract (inbound_broadcast_pkts, outbound_broadcast_pkts) from Huawei `display interface` output."""
    clean = _clean_cli(raw_text)
    in_bcast = 0
    out_bcast = 0
    section = ""
    for line in clean.splitlines():
        low = line.lower()
        if "input:" in low or "last 300 seconds input" in low:
            section = "in"
        elif "output:" in low or "last 300 seconds output" in low:
            section = "out"
        m = re.search(r"broadcast\s*:\s*(\d+)", low)
        if m:
            val = int(m.group(1))
            if section == "out":
                out_bcast = val
            else:
                in_bcast = val
    return in_bcast, out_bcast


def parse_lldp_brief(raw_text: str) -> Dict[str, Dict[str, str]]:
    """Parse LLDP/CDP neighbor brief tables across Huawei/H3C/Ruijie/Cisco into {local_port: {remote_sys, remote_port}}."""
    clean = _clean_cli(raw_text)
    neighbors: Dict[str, Dict[str, str]] = {}
    port_tok_re = re.compile(
        r"^(?:(?:Ten-?|X)?GigabitEthernet|FastEthernet|Ethernet|GE|XGE|Gi|Fa|Te|Eth)\s*\d+(?:/\d+){1,3}$",
        re.IGNORECASE,
    )
    mac_tok_re = re.compile(
        r"^(?:[0-9a-fA-F]{4}[-.][0-9a-fA-F]{4}[-.][0-9a-fA-F]{4}|(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})$"
    )
    for line in clean.splitlines():
        s = line.strip()
        if not s or s.startswith("-") or "local" in s.lower() or "device id" in s.lower():
            continue
        parts = s.split()
        if len(parts) < 3:
            continue
        if port_tok_re.match(parts[0]):
            local_p = parts[0]
            if mac_tok_re.match(parts[1]) and len(parts) >= 4:
                # H3C Comware: LocalIntf  ChassisMAC  RemotePort  SystemName
                rem_port = parts[2]
                rem_sys = parts[3]
            elif parts[1].isdigit() and len(parts) >= 4:
                # Variant with Exptime second: LocalIntf  Exptime  SystemName  RemotePort
                rem_sys = parts[2]
                rem_port = parts[3]
            else:
                # Huawei VRP: LocalIntf  SystemName  RemotePort  [Exptime]
                rem_sys = parts[1]
                rem_port = parts[2]
            neighbors[local_p] = {"remote_sys": rem_sys, "remote_port": rem_port}
        elif port_tok_re.match(parts[1]) and len(parts) >= 4:
            # Cisco / Ruijie: DeviceID  LocalIntf  Holdt  [Cap...]  PortID
            neighbors[parts[1]] = {"remote_sys": parts[0], "remote_port": parts[-1]}
    return neighbors


def compute_counter_deltas(
    snap1: Dict[str, Dict[str, Any]],
    snap2: Dict[str, Dict[str, Any]],
    dt: float,
    lldp_map: Dict[str, Dict[str, str]],
    flap_ports: set,
    switch_ip: str,
    ledger: PortLedger,
    brief_map: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Compute per-port inbound broadcast PPS delta and rank the exact broadcast source port(s)."""
    dt = max(0.5, dt)
    all_ports = sorted(set(snap1.keys()) | set(snap2.keys()))
    rows: List[Dict[str, Any]] = []

    for pname in all_ports:
        c1 = snap1.get(pname, {})
        c2 = snap2.get(pname, {})
        b_delta = max(0, int(c2.get("broadcast", 0)) - int(c1.get("broadcast", 0)))
        m_delta = max(0, int(c2.get("multicast", 0)) - int(c1.get("multicast", 0)))
        t_delta = max(0, int(c2.get("total", 0)) - int(c1.get("total", 0)))
        e_delta = max(0, int(c2.get("errors", 0)) - int(c1.get("errors", 0)))
        in_bcast_pps = round(b_delta / dt, 1)
        in_mcast_pps = round(m_delta / dt, 1)
        in_total_pps = round(t_delta / dt, 1)

        brief = (brief_map or {}).get(pname, {})
        in_uti = float(brief.get("in_uti_pct", c2.get("in_uti_pct", 0.0)))
        out_uti = float(brief.get("out_uti_pct", c2.get("out_uti_pct", 0.0)))
        is_flapping = any(pname.lower() in fp.lower() or fp.lower() in pname.lower() for fp in flap_ports)
        lldp = lldp_map.get(pname)
        loc = ledger.format_location(switch_ip, pname) if switch_ip else ""

        score = 0
        reasons: List[str] = []
        if in_bcast_pps >= 1000:
            score += 60
            reasons.append(f"入向广播风暴 {in_bcast_pps:.0f} pps（广播源头方向！）")
        elif in_bcast_pps >= 200:
            score += 30
            reasons.append(f"入向广播偏高 {in_bcast_pps:.0f} pps")
        if is_flapping:
            score += 40
            reasons.append("日志确认存在 MAC 漂移 / 环路告警")
        if in_uti >= 50.0:
            score += 25
            reasons.append(f"入向带宽利用率飙高 ({in_uti:.1f}%)")
        if e_delta >= 5:
            score += 10
            reasons.append(f"错包增量 +{e_delta}")

        # Determine clear direction verdict
        if in_bcast_pps >= 300 or (in_uti >= 40 and in_uti >= out_uti):
            direction = "🚨 广播源头灌入口 (In主导)"
        elif out_uti >= 40 and in_uti < 10 and in_bcast_pps < 80:
            direction = "⚪ 受害转发口 (Out主导，可排除)"
        elif is_flapping:
            direction = "⚡ MAC漂移涉事口"
        else:
            direction = "🟢 正常端口"

        score = min(100, score)
        rows.append({
            "port": pname,
            "location": loc,
            "in_broadcast_pps": in_bcast_pps,
            "in_multicast_pps": in_mcast_pps,
            "in_total_pps": in_total_pps,
            "in_uti_pct": in_uti,
            "out_uti_pct": out_uti,
            "errors_delta": e_delta,
            "is_flapping": is_flapping,
            "lldp_neighbor": lldp,
            "direction": direction,
            "risk_score": score,
            "reasons": reasons,
        })

    rows.sort(key=lambda x: (-x["risk_score"], -x["in_broadcast_pps"], -x["in_uti_pct"]))
    return rows


# ==============================================================================
# Interactive Console Session Orchestrator
# ==============================================================================

def _send_and_read(
    ser: SerialTransport,
    cmd: str,
    wait_idle: float = 0.65,
    max_wait: float = 8.0,
) -> str:
    """Send one CLI command over Console, auto-paging `--More--`, and return output."""
    ser.write(cmd + "\r\n")
    buf = ""
    t_start = time.time()
    t_last = t_start
    while time.time() - t_start < max_wait:
        chunk = ser.read_available(timeout=0.2)
        if chunk:
            buf += chunk
            t_last = time.time()
            low_tail = buf[-60:].lower()
            if "more" in low_tail and ("--" in low_tail or "press" in low_tail):
                ser.write(" ")
                continue
            if _PROMPT_RE.search(_clean_cli(buf)):
                if time.time() - t_start > 0.35:
                    break
        else:
            if buf and (time.time() - t_last) >= wait_idle:
                break
    return _clean_cli(buf)


def _detect_vendor_from_console(ser: SerialTransport, initial_text: str, requested_vendor: str) -> Tuple[str, str]:
    """Return (vendor_key, sys_name_guess)."""
    prompt_m = _PROMPT_RE.search(initial_text)
    prompt = prompt_m.group(1) if prompt_m else ""
    sys_name = prompt.strip("<>[]# ") or "Console交换机"

    if requested_vendor and requested_vendor != "auto":
        return requested_vendor, sys_name

    low = (initial_text + " " + prompt).lower()
    if "huawei" in low or "vrp" in low:
        return "huawei", sys_name
    if "h3c" in low or "comware" in low:
        return "h3c", sys_name
    if "ruijie" in low or "rgos" in low:
        return "ruijie", sys_name
    if "tp-link" in low:
        return "tplink", sys_name

    if prompt.startswith("<") or prompt.startswith("["):
        ver = _send_and_read(ser, "display version", wait_idle=0.5, max_wait=3.0).lower()
        if "h3c" in ver or "comware" in ver:
            return "h3c", sys_name
        return "huawei", sys_name

    ver = _send_and_read(ser, "show version", wait_idle=0.5, max_wait=3.0).lower()
    if "ruijie" in ver or "rgos" in ver:
        return "ruijie", sys_name
    if "tp-link" in ver:
        return "tplink", sys_name
    return "cisco", sys_name


def simulate_console_inspection(switch_ip: str, ledger: PortLedger) -> Dict[str, Any]:
    """Simulate a full 2-pass H3C aggregation switch Console inspection for safe training."""
    ip = switch_ip.strip() or "10.10.1.1"
    snap1_txt = """<H3C-3F-Agg-SW01> display counters inbound interface
Interface            Total (pkts)     Broadcast (pkts) Multicast (pkts) Err (pkts)
GE1/0/1                  18294021                 4210             1820          0
GE1/0/2                   1204112                  310               95          0
GE1/0/14                 99482110             18429100           412000         32
GE1/0/15                 42100400              3210400            98400          5
GE1/0/16                  3110220                  920              210          0
"""
    snap2_txt = """<H3C-3F-Agg-SW01> display counters inbound interface
Interface            Total (pkts)     Broadcast (pkts) Multicast (pkts) Err (pkts)
GE1/0/1                  18294480                 4238             1832          0
GE1/0/2                   1204150                  314               96          0
GE1/0/14                 99506520             18451330           414520         44
GE1/0/15                 42104510              3214120            98810          7
GE1/0/16                  3110288                  926              212          0
"""
    mac_move_txt = """<H3C-3F-Agg-SW01> display mac-address mac-move
MAC Address      VLAN Current Port   Source Port    Times Last Time
d80d-176a-3b9c   20   GE1/0/14       GE1/0/15       146   2026-11-21 11:06:12
482a-e311-2201   20   GE1/0/15       GE1/0/14       92    2026-11-21 11:06:14

<H3C-3F-Agg-SW01> display loopback-detection
Loopback detection is enabled globally.
GigabitEthernet1/0/14  VLAN 20  Detected-Loop: Yes  Action: Block
"""
    lldp_txt = """<H3C-3F-Agg-SW01> display lldp neighbor-information list
Local Interface   Chassis ID       Port ID              System Name
GE1/0/1           5489-9800-0001   XGE1/0/3             CORE-Campus-S12700
GE1/0/14          5489-98aa-1234   GE0/0/24             HW-3F-East-SW02
GE1/0/16          00d0-f811-2233   Gi0/24               RJ-3F-West-SW03
"""
    s1 = parse_counters_table(snap1_txt)
    s2 = parse_counters_table(snap2_txt)
    lldp_map = parse_lldp_brief(lldp_txt)
    parsed_logs = parse_switch_cli_output(mac_move_txt, switch_ip=ip, ledger=ledger)
    flap_ports = {p["port"] for p in parsed_logs["affected_ports"]}
    ranked = compute_counter_deltas(s1, s2, dt=3.0, lldp_map=lldp_map, flap_ports=flap_ports, switch_ip=ip, ledger=ledger)

    top = ranked[0]
    raw_transcript = "\n".join([
        "=== [仿真 Console 串口会话: /dev/cu.usbserial-DEMO · 9600 8N1] ===",
        snap1_txt.strip(),
        "\n--- 等待 3.0 秒执行第 2 次采样 ---\n",
        snap2_txt.strip(),
        "\n",
        mac_move_txt.strip(),
        "\n",
        lldp_txt.strip(),
    ])
    return {
        "ok": True,
        "simulated": True,
        "port_device": "/dev/cu.usbserial-DEMO (9600 8N1)",
        "vendor": "H3C (新华三 Comware)",
        "sys_name": "H3C-3F-Agg-SW01",
        "switch_ip": ip,
        "sample_interval": 3.0,
        "ranked_ports": ranked,
        "parsed_logs": parsed_logs,
        "lldp_neighbors": lldp_map,
        "summary": (
            f"通过 Console 双采样在 H3C-3F-Agg-SW01 精准锁定广播源头口：{top['port']}"
            f"（入向广播 +{top['in_broadcast_pps']:.0f} pps"
            f"{'，📍' + top['location'] if top['location'] else ''}"
            f"{'，下联 ' + top['lldp_neighbor']['remote_sys'] if top.get('lldp_neighbor') else ''}）！"
        ),
        "raw_output": raw_transcript,
    }


def inspect_switch_console(
    device: str,
    baudrate: int = 9600,
    vendor: str = "auto",
    username: str = "",
    password: str = "",
    enable_password: str = "",
    switch_ip: str = "",
    sample_interval: float = 3.0,
    ledger: Optional[PortLedger] = None,
    simulate: bool = False,
) -> Dict[str, Any]:
    """Connect over physical Console cable, run 2-pass inbound broadcast counter diff, and locate source port."""
    active_ledger = ledger or PortLedger()
    if simulate or device == "__SIM_CONSOLE__":
        return simulate_console_inspection(switch_ip, active_ledger)

    if not device:
        return {"ok": False, "error": "请先选择 Console 串口设备（如 /dev/cu.usbserial-xxx 或 COM3）"}

    interval = max(2.0, min(8.0, float(sample_interval)))
    transcript: List[str] = []
    ser: Optional[SerialTransport] = None

    try:
        ser = SerialTransport(device=device, baudrate=baudrate)

        # 1. Wake up prompt & handle optional Console login / enable
        ser.write("\r\n\r\n")
        time.sleep(0.5)
        banner = _clean_cli(ser.read_available(timeout=0.6))
        if not banner.strip():
            ser.write("\r\n")
            time.sleep(0.5)
            banner += _clean_cli(ser.read_available(timeout=0.6))

        for _ in range(4):
            low_b = banner[-120:].lower()
            if ("username:" in low_b or "login:" in low_b) and username:
                banner += "\n" + _send_and_read(ser, username, wait_idle=0.5, max_wait=2.5)
            elif "password:" in low_b and (password or enable_password):
                banner += "\n" + _send_and_read(ser, password or enable_password, wait_idle=0.5, max_wait=2.5)
            elif "press enter" in low_b:
                banner += "\n" + _send_and_read(ser, "", wait_idle=0.4, max_wait=2.0)
            else:
                break

        # Cisco / Ruijie user-exec `>` -> enter privileged `#`
        pm = _PROMPT_RE.search(banner)
        if pm and pm.group(1).endswith(">") and not pm.group(1).startswith("<"):
            en_out = _send_and_read(ser, "enable", wait_idle=0.5, max_wait=2.0)
            banner += "\n" + en_out
            if "password:" in en_out.lower() and (enable_password or password):
                banner += "\n" + _send_and_read(ser, enable_password or password, wait_idle=0.5, max_wait=2.0)

        transcript.append(f"=== Console 握手 ===\n{banner.strip()}")

        # 2. Detect vendor & disable terminal pagination
        vkey, sys_name = _detect_vendor_from_console(ser, banner, vendor)
        vendor_labels = {
            "huawei": "华为 Huawei (VRP)",
            "h3c": "新华三 H3C (Comware)",
            "ruijie": "锐捷 Ruijie (RGOS)",
            "cisco": "思科 Cisco (IOS/Catalyst)",
            "tplink": "TP-LINK 网管交换机",
        }

        if vkey == "huawei":
            _send_and_read(ser, "screen-length 0 temporary", wait_idle=0.3, max_wait=1.8)
        elif vkey == "h3c":
            _send_and_read(ser, "screen-length disable", wait_idle=0.3, max_wait=1.8)
        elif vkey in ("ruijie", "cisco"):
            _send_and_read(ser, "terminal length 0", wait_idle=0.3, max_wait=1.8)

        # 3. Collect MAC Flapping / Loopback / LLDP diagnostics
        log_chunks: List[str] = []
        lldp_text = ""
        if vkey == "huawei":
            diag_cmds = ["display mac-address flapping record", "display loopback-detect", "display stp brief"]
            lldp_cmd = "display lldp neighbor brief"
        elif vkey == "h3c":
            diag_cmds = ["display mac-address mac-move", "display loopback-detection", "display stp brief"]
            lldp_cmd = "display lldp neighbor-information list"
        elif vkey == "ruijie":
            diag_cmds = ["show rldp", "show loopback-detection", "show logging | include LOOP|RLDP|FLAP|MAC"]
            lldp_cmd = "show lldp neighbors"
        elif vkey == "cisco":
            diag_cmds = ["show logging | include MACFLAP|LOOP|ERR_DISABLE|STORM", "show interfaces status err-disabled"]
            lldp_cmd = "show cdp neighbors"
        else:
            diag_cmds = ["show loopback-detection interface", "show logging buffer"]
            lldp_cmd = "show lldp neighbor-information list"

        for cmd in diag_cmds:
            out = _send_and_read(ser, cmd, wait_idle=0.55, max_wait=5.0)
            log_chunks.append(f">>> {cmd}\n{out}")
            transcript.append(f">>> {cmd}\n{out}")

        lldp_text = _send_and_read(ser, lldp_cmd, wait_idle=0.55, max_wait=4.0)
        transcript.append(f">>> {lldp_cmd}\n{lldp_text}")
        lldp_map = parse_lldp_brief(lldp_text)

        parsed_logs = parse_switch_cli_output("\n".join(log_chunks), switch_ip=switch_ip, ledger=active_ledger)
        flap_ports = {p["port"] for p in parsed_logs["affected_ports"]}

        # 4. Two-Pass Inbound Broadcast Counter Delta over Console!
        brief_map: Dict[str, Dict[str, Any]] = {}
        snap1: Dict[str, Dict[str, Any]] = {}
        snap2: Dict[str, Dict[str, Any]] = {}
        dt = interval

        if vkey == "huawei":
            brief_out = _send_and_read(ser, "display interface brief", wait_idle=0.6, max_wait=6.0)
            transcript.append(f">>> display interface brief\n{brief_out}")
            brief_map = parse_counters_table(brief_out)
            # Pick top 4 active ports by inbound utilization + any flapping ports for exact broadcast delta
            candidates = sorted(
                [p for p in brief_map.values() if p.get("status") == "up"],
                key=lambda x: (-x.get("in_uti_pct", 0.0), -x.get("in_errors", 0)),
            )
            hot_names = [p["port"] for p in candidates[:4]]
            for fp in flap_ports:
                if fp not in hot_names and len(hot_names) < 6:
                    hot_names.append(fp)

            t1 = time.time()
            for pname in hot_names:
                d1 = _send_and_read(ser, f"display interface {pname}", wait_idle=0.45, max_wait=3.5)
                in_b, _ = parse_single_huawei_interface_bcast(d1)
                snap1[pname] = {"port": pname, "broadcast": in_b, "multicast": 0, "total": in_b, "errors": brief_map.get(pname, {}).get("in_errors", 0)}
            # Keep non-probed up ports in table with brief utilization
            for pname, binfo in brief_map.items():
                if pname not in snap1 and binfo.get("status") == "up":
                    snap1[pname] = {"port": pname, "broadcast": 0, "multicast": 0, "total": 0, "errors": binfo.get("in_errors", 0)}

            rem = interval - (time.time() - t1)
            if rem > 0.2:
                time.sleep(rem)

            t2 = time.time()
            for pname in hot_names:
                d2 = _send_and_read(ser, f"display interface {pname}", wait_idle=0.45, max_wait=3.5)
                in_b, _ = parse_single_huawei_interface_bcast(d2)
                snap2[pname] = {"port": pname, "broadcast": in_b, "multicast": 0, "total": in_b, "errors": brief_map.get(pname, {}).get("in_errors", 0)}
            for pname, binfo in brief_map.items():
                if pname not in snap2 and binfo.get("status") == "up":
                    snap2[pname] = {"port": pname, "broadcast": 0, "multicast": 0, "total": 0, "errors": binfo.get("in_errors", 0)}
            dt = max(0.5, t2 - t1)
        else:
            counter_cmd = {
                "h3c": "display counters inbound interface",
                "cisco": "show interfaces counters broadcast",
                "ruijie": "show interfaces counters",
                "tplink": "show interface counters",
            }.get(vkey, "display counters inbound interface")

            t1 = time.time()
            c1_out = _send_and_read(ser, counter_cmd, wait_idle=0.65, max_wait=7.0)
            transcript.append(f">>> {counter_cmd} (第1次采样)\n{c1_out}")
            snap1 = parse_counters_table(c1_out)

            rem = interval - (time.time() - t1)
            if rem > 0.2:
                time.sleep(rem)

            t2 = time.time()
            c2_out = _send_and_read(ser, counter_cmd, wait_idle=0.65, max_wait=7.0)
            transcript.append(f">>> {counter_cmd} (第2次采样)\n{c2_out}")
            snap2 = parse_counters_table(c2_out)
            dt = max(0.5, t2 - t1)

        ranked = compute_counter_deltas(
            snap1=snap1,
            snap2=snap2,
            dt=dt,
            lldp_map=lldp_map,
            flap_ports=flap_ports,
            switch_ip=switch_ip,
            ledger=active_ledger,
            brief_map=brief_map,
        )

        if ranked and ranked[0]["risk_score"] > 0:
            top = ranked[0]
            summary = (
                f"通过 Console 在 {sys_name} ({vendor_labels.get(vkey, vkey)}) 锁定头号广播源头口：{top['port']}"
                f"（入向广播 {top['in_broadcast_pps']:.0f} pps"
                f"{'，入向利用率 ' + str(top['in_uti_pct']) + '%' if top['in_uti_pct'] > 0 else ''}"
                f"{'，📍' + top['location'] if top['location'] else ''}）"
            )
        else:
            summary = (
                f"已完成 {sys_name} ({vendor_labels.get(vkey, vkey)}) Console 双采样（共解析 {len(ranked)} 个口），"
                f"未检测到显著广播风暴；日志告警 {parsed_logs['finding_count']} 条。"
            )

        return {
            "ok": True,
            "simulated": False,
            "port_device": f"{device} ({baudrate} 8N1)",
            "vendor": vendor_labels.get(vkey, vkey),
            "sys_name": sys_name,
            "switch_ip": switch_ip,
            "sample_interval": round(dt, 2),
            "ranked_ports": ranked[:24],
            "parsed_logs": parsed_logs,
            "lldp_neighbors": lldp_map,
            "summary": summary,
            "raw_output": "\n\n".join(transcript),
        }
    except PermissionError as e:
        return {"ok": False, "error": f"无权访问串口 {device} ({e})，请检查驱动或是否被 SecureCRT/screen 占用。"}
    except Exception as e:
        return {"ok": False, "error": f"Console 串口诊断失败 ({device}): {e}"}
    finally:
        if ser is not None:
            ser.close()
