"""Multi-Vendor Switch SSH Read-Only Inspector & Universal CLI Log Parser.

Supports Huawei (VRP), H3C (Comware), Ruijie (RGOS), Cisco (IOS/NX-OS), and TP-Link.
Works BOTH via live SSH (paramiko if installed) AND offline via pasting CLI outputs
from Console cable / SecureCRT / MobaXterm into the UI for instant loop analysis!
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from loopfinder.core.ledger import PortLedger
from loopfinder.data.oui_vendors import lookup_mac_vendor, normalize_mac


VENDOR_COMMANDS: Dict[str, Dict[str, Any]] = {
    "huawei": {
        "label": "华为 Huawei (VRP)",
        "disable_paging": "screen-length 0 temporary",
        "commands": [
            "display mac-address flapping record",
            "display loopback-detect",
            "display stp brief",
            "display trapbuffer | include LOOP|FLAP|STORM",
        ],
    },
    "h3c": {
        "label": "新华三 H3C (Comware)",
        "disable_paging": "screen-length disable",
        "commands": [
            "display mac-address mac-move",
            "display loopback-detection",
            "display stp brief",
            "display logbuffer | include LOOP|MOVE|FLAP|STORM",
        ],
    },
    "ruijie": {
        "label": "锐捷 Ruijie (RGOS)",
        "disable_paging": "terminal length 0",
        "commands": [
            "show rldp",
            "show loopback-detection",
            "show mac-address-table notification",
            "show spanning-tree summary",
            "show logging | include LOOP|RLDP|FLAP|ERR",
        ],
    },
    "cisco": {
        "label": "思科 Cisco (IOS/Catalyst)",
        "disable_paging": "terminal length 0",
        "commands": [
            "show logging | include MACFLAP|LOOP|ERR_DISABLE|STORM",
            "show interfaces status err-disabled",
            "show spanning-tree summary",
        ],
    },
    "tplink": {
        "label": "TP-LINK 网管交换机",
        "disable_paging": "",
        "commands": [
            "show loopback-detection global",
            "show loopback-detection interface",
            "show spanning-tree active",
            "show logging buffer",
        ],
    },
}

SAMPLE_CLI_OUTPUT = """
<HW-3F-East-SW02> display mac-address flapping record
Info: The mac-address flapping record is displayed as follows:
S  : start time
E  : end time
(Q): quit vlan
(D): error down
-------------------------------------------------------------------------------
MoveTime                 VLAN MAC-Address   Original-Port  Move-Ports   MoveNum
-------------------------------------------------------------------------------
S:2026-11-21 09:20:11    20   d80d-176a-3b9c GE0/0/14      GE0/0/15     128
E:2026-11-21 09:20:42                                      GE0/0/14
S:2026-11-21 09:20:15    20   482a-e311-2201 GE0/0/15      GE0/0/14     94
E:2026-11-21 09:20:42                                      GE0/0/15
-------------------------------------------------------------------------------

<HW-3F-East-SW02> display loopback-detect
Loopback-detect is enabled globally.
Port             VLAN   Status     Action      Detected-Loop
GE0/0/14         20     Block      Shutdown    Yes
GE0/0/15         20     Normal     Shutdown    No

Nov 21 09:20:18 HW-3F-East-SW02 %LBDT/4/LOOP_DETECTED: Loopback exists on GigabitEthernet0/0/14 (VLAN 20).
""".strip()


_PORT_TOKEN = r"(?:(?:Ten-?|X)?GigabitEthernet|FastEthernet|Ethernet|GE|XGE|Gi|Fa|Te|Eth|Po)\s*\d+(?:/\d+){1,3}"
_MAC_TOKEN = r"(?:[0-9a-fA-F]{4}[-.][0-9a-fA-F]{4}[-.][0-9a-fA-F]{4}|(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})"


def parse_switch_cli_output(
    raw_text: str,
    switch_ip: str = "",
    ledger: Optional[PortLedger] = None,
) -> Dict[str, Any]:
    """Parse Huawei/H3C/Ruijie/Cisco/TP-Link CLI logs into structured loop & MAC-flap findings."""
    active_ledger = ledger or PortLedger()
    findings: List[Dict[str, Any]] = []
    affected_ports: Dict[str, Dict[str, Any]] = {}
    involved_macs: Dict[str, Dict[str, Any]] = {}

    def _touch_port(port: str, reason: str, severity: str) -> None:
        p = port.strip()
        if not p:
            return
        entry = affected_ports.setdefault(
            p,
            {
                "port": p,
                "location": active_ledger.format_location(switch_ip, p) if switch_ip else "",
                "severity": severity,
                "reasons": [],
            },
        )
        if reason not in entry["reasons"]:
            entry["reasons"].append(reason)
        if severity == "danger":
            entry["severity"] = "danger"

    def _touch_mac(mac_raw: str, port: str = "") -> Dict[str, Any]:
        norm = normalize_mac(mac_raw)
        vinfo = lookup_mac_vendor(norm)
        entry = involved_macs.setdefault(
            norm,
            {
                "mac": norm,
                "vendor": vinfo["vendor"],
                "category": vinfo["category"],
                "category_label": vinfo["category_label"],
                "ports": [],
            },
        )
        if port and port not in entry["ports"]:
            entry["ports"].append(port)
        return entry

    lines = raw_text.splitlines()
    for idx, line in enumerate(lines, start=1):
        s = line.strip()
        if not s:
            continue
        low = s.lower()

        # 1. Huawei / H3C / Cisco MAC Flapping lines
        macs = re.findall(_MAC_TOKEN, s)
        ports = re.findall(_PORT_TOKEN, s, re.IGNORECASE)

        if macs and len(ports) >= 2 and (
            "flap" in low or "move" in low or "s:" in low or "between" in low or "mac_move" in low
            or re.search(r"\b\d{1,4}\s+" + _MAC_TOKEN, s)
        ):
            mac_entry = _touch_mac(macs[0], ports[0])
            _touch_mac(macs[0], ports[1])
            _touch_port(ports[0], f"MAC 漂移 ({mac_entry['mac']} / {mac_entry['vendor']})", "danger")
            _touch_port(ports[1], f"MAC 漂移 ({mac_entry['mac']} / {mac_entry['vendor']})", "danger")
            findings.append({
                "type": "MAC_FLAP",
                "severity": "danger",
                "line": idx,
                "title": f"MAC 地址漂移：{mac_entry['mac']} ({mac_entry['vendor']})",
                "detail": f"在端口 {ports[0]} 与 {ports[1]} 之间频繁跳动",
                "ports": ports[:2],
                "raw": s,
            })
            continue

        # 2. Loopback-detection / RLDP / Loop Detected alerts
        if any(k in low for k in ("loopback exists", "loop_detected", "loop detected", "rldp", "detected-loop", "loop-detect")) or (
            ports and any(k in low for k in ("block", "err-disabled", "errdisable", "shutdown", "loop"))
            and ("yes" in low or "loop" in low or "err" in low or "block" in low)
        ):
            if "not detected" in low or "no loop" in low or "normal" in low and "yes" not in low:
                continue
            for p in ports:
                _touch_port(p, "交换机环路检测告警 / 端口阻塞", "danger")
            findings.append({
                "type": "LOOP_DETECTED",
                "severity": "danger",
                "line": idx,
                "title": f"交换机触发环路检测 ({', '.join(ports) if ports else '全局'})",
                "detail": s[:180],
                "ports": ports,
                "raw": s,
            })
            continue

        # 3. Broadcast storm / Storm control alerts
        if any(k in low for k in ("storm", "broadcast", "广播风暴")) and (
            "exceed" in low or "suppress" in low or "detect" in low or "block" in low or "告警" in low
        ):
            for p in ports:
                _touch_port(p, "触发广播风暴抑制", "warning")
            findings.append({
                "type": "STORM_CONTROL",
                "severity": "warning",
                "line": idx,
                "title": f"端口触发广播风暴告警 ({', '.join(ports) if ports else '未指定端口'})",
                "detail": s[:180],
                "ports": ports,
                "raw": s,
            })
            continue

        # 4. STP Blocking / Discarding / Alternate info
        if ports and any(k in low for k in ("discarding", "blocking", "root-inconsistent", "loop-inconsistent")):
            for p in ports:
                _touch_port(p, "STP 阻塞状态 (Discarding/Blocking)", "warning")
            findings.append({
                "type": "STP_BLOCK",
                "severity": "warning",
                "line": idx,
                "title": f"STP 阻塞端口：{', '.join(ports)}",
                "detail": s[:180],
                "ports": ports,
                "raw": s,
            })

    return {
        "finding_count": len(findings),
        "findings": findings[:50],
        "affected_ports": list(affected_ports.values()),
        "involved_macs": list(involved_macs.values()),
        "summary": (
            f"共提取 {len(findings)} 条环路/漂移异常记录，涉及 {len(affected_ports)} 个物理端口与 {len(involved_macs)} 个可疑 MAC。"
            if findings
            else "未在输出日志中发现明确的 MAC 漂移、RLDP/LBDT 环路或广播风暴告警。"
        ),
    }


def inspect_switch_ssh(
    host: str,
    username: str,
    password: str,
    vendor: str = "huawei",
    port: int = 22,
    timeout: float = 8.0,
    ledger: Optional[PortLedger] = None,
) -> Dict[str, Any]:
    """Connect to a managed switch via SSH (paramiko), run read-only diagnostics, and parse outputs."""
    try:
        import paramiko  # type: ignore
    except ImportError:
        return {
            "ok": False,
            "error": (
                "未安装 paramiko 库，无法直接发起 SSH 连接。"
                "请运行 `pip install paramiko`，或者将串口/终端里的交换机输出直接粘贴到下方「离线日志一键解析」区！"
            ),
        }

    profile = VENDOR_COMMANDS.get(vendor, VENDOR_COMMANDS["huawei"])
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    raw_chunks: List[str] = []

    try:
        client.connect(
            hostname=host.strip(),
            port=int(port),
            username=username,
            password=password,
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        shell = client.invoke_shell(width=200, height=50)
        shell.settimeout(2.5)
        time.sleep(0.8)
        if shell.recv_ready():
            raw_chunks.append(shell.recv(65535).decode("utf-8", errors="ignore"))

        cmds = []
        if profile["disable_paging"]:
            cmds.append(profile["disable_paging"])
        cmds.extend(profile["commands"])

        for cmd in cmds:
            shell.send(cmd + "\n")
            time.sleep(0.9)
            buf = ""
            deadline = time.time() + 2.5
            while time.time() < deadline:
                if shell.recv_ready():
                    chunk = shell.recv(65535).decode("utf-8", errors="ignore")
                    buf += chunk
                    if "--More--" in chunk or "---- More ----" in chunk:
                        shell.send(" ")
                        deadline = time.time() + 1.5
                else:
                    time.sleep(0.15)
            raw_chunks.append(f"\n>>> {cmd}\n{buf}")

        raw_output = "\n".join(raw_chunks)
        parsed = parse_switch_cli_output(raw_output, switch_ip=host, ledger=ledger)
        return {
            "ok": True,
            "host": host,
            "vendor": profile["label"],
            "raw_output": raw_output,
            "parsed": parsed,
        }
    except Exception as e:
        return {"ok": False, "error": f"SSH 连接或采集中断 ({host}:{port}): {e}"}
    finally:
        try:
            client.close()
        except Exception:
            pass


def generate_hardening_config(
    vendor: str,
    port_prefix: str = "GigabitEthernet0/0/",
    port_start: int = 1,
    port_end: int = 22,
    uplink_port: str = "GigabitEthernet0/0/24",
    syslog_host: str = "",
    syslog_port: int = 1514,
) -> Dict[str, str]:
    """Generate ready-to-paste anti-loop + storm-control + DHCP-snooping config scripts."""
    v = (vendor or "huawei").lower()
    ps = max(1, int(port_start))
    pe = max(ps, int(port_end))

    if v == "huawei":
        p_pref = port_prefix or "GigabitEthernet0/0/"
        uplink = uplink_port or f"{p_pref}24"
        lines = [
            "system-view",
            "# 1. 全局开启环路检测、STP 与 DHCP Snooping",
            "stp enable",
            "stp mode rstp",
            "stp bpdu-protection",
            "loopback-detect enable",
            "mac-address flapping detection",
            "dhcp enable",
            "dhcp snooping enable",
            "",
            f"# 2. 教研室下联接入端口批量防环加固 ({p_pref}{ps} ~ {pe})",
            f"port-group group-member {p_pref}{ps} to {p_pref}{pe}",
            " loopback-detect enable",
            " loopback-detect action block",
            " loopback-detect recovery-time 300",
            " stp edged-port enable",
            " broadcast-suppression 10",
            " multicast-suppression 10",
            " dhcp snooping enable",
            "quit",
            "",
            f"# 3. 上联汇聚口设为 DHCP Snooping 信任口（防止影响正常取地址！）",
            f"interface {uplink}",
            " dhcp snooping trusted",
            "quit",
        ]
        if syslog_host:
            lines += [
                "",
                "# 4. 推送实时环路/漂移 Syslog 到 LoopFinder 运维笔记本",
                "info-center enable",
                f"info-center loghost {syslog_host} port {syslog_port}",
            ]
        lines.append("save")
        return {"vendor": "华为 Huawei (VRP)", "config": "\n".join(lines)}

    if v == "h3c":
        p_pref = port_prefix or "GigabitEthernet1/0/"
        uplink = uplink_port or f"{p_pref}24"
        lines = [
            "system-view",
            "# 1. 全局开启环路检测、MAC 漂移记录与 DHCP Snooping",
            "stp global enable",
            "stp mode rstp",
            "stp bpdu-protection",
            "loopback-detection global enable vlan all",
            "mac-address notification mac-move",
            "dhcp snooping enable",
            "",
            f"# 2. 教研室下联口批量防环 ({p_pref}{ps} ~ {pe})",
            f"interface range {p_pref}{ps} to {p_pref}{pe}",
            " loopback-detection action shutdown",
            " stp edged-port",
            " broadcast-suppression pps 100",
            " multicast-suppression pps 100",
            "quit",
            "",
            f"# 3. 上联口配置为 DHCP Snooping Trust",
            f"interface {uplink}",
            " dhcp snooping trust",
            "quit",
        ]
        if syslog_host:
            lines += [
                "",
                "# 4. 推送实时告警 Syslog 到 LoopFinder",
                "info-center enable",
                f"info-center loghost {syslog_host} port {syslog_port}",
            ]
        lines.append("save force")
        return {"vendor": "新华三 H3C (Comware)", "config": "\n".join(lines)}

    if v == "ruijie":
        p_pref = port_prefix or "GigabitEthernet 0/"
        uplink = uplink_port or f"{p_pref}24"
        lines = [
            "configure terminal",
            "! 1. 全局开启锐捷 RLDP 防环与 DHCP Snooping",
            "rldp enable",
            "spanning-tree",
            "spanning-tree mode rstp",
            "ip dhcp snooping",
            "",
            f"! 2. 教研室下联口批量加固 ({p_pref}{ps}-{pe})",
            f"interface range {p_pref}{ps}-{pe}",
            " rldp port loop-detect shutdown-port",
            " spanning-tree portfast",
            " spanning-tree bpduguard enable",
            " storm-control broadcast pps 100",
            "exit",
            "",
            f"! 3. 上联口设为 DHCP Snooping 信任口",
            f"interface {uplink}",
            " ip dhcp snooping trust",
            "exit",
        ]
        if syslog_host:
            lines += [
                "",
                "! 4. 推送 Syslog 告警到 LoopFinder",
                f"logging server {syslog_host} port {syslog_port}",
            ]
        lines += ["end", "write"]
        return {"vendor": "锐捷 Ruijie (RGOS)", "config": "\n".join(lines)}

    if v == "cisco":
        p_pref = port_prefix or "GigabitEthernet1/0/"
        uplink = uplink_port or f"{p_pref}24"
        lines = [
            "configure terminal",
            "! 1. 全局开启 RSTP、Errdisable 自动恢复与 DHCP Snooping",
            "spanning-tree mode rapid-pvst",
            "errdisable recovery cause bpduguard",
            "errdisable recovery cause loopback",
            "errdisable recovery interval 300",
            "ip dhcp snooping",
            "ip dhcp snooping vlan 1-4094",
            "",
            f"! 2. 教研室接入端口批量防环 ({p_pref}{ps}-{pe})",
            f"interface range {p_pref}{ps}-{pe}",
            " spanning-tree portfast",
            " spanning-tree bpduguard enable",
            " storm-control broadcast level 5.00",
            " storm-control action trap",
            "exit",
            "",
            f"! 3. 上联汇聚口设为信任口",
            f"interface {uplink}",
            " ip dhcp snooping trust",
            "exit",
        ]
        if syslog_host:
            lines += ["", f"logging host {syslog_host} transport udp port {syslog_port}"]
        lines += ["end", "write memory"]
        return {"vendor": "思科 Cisco (IOS/Catalyst)", "config": "\n".join(lines)}

    # TP-LINK Managed
    p_pref = port_prefix or "gigabitEthernet 1/0/"
    uplink = uplink_port or f"{p_pref}24"
    lines = [
        "configure",
        "# 1. 全局开启环路检测与广播风暴抑制",
        "loopback-detection",
        "loopback-detection interval 5",
        "ip dhcp snooping",
        "",
        f"# 2. 教研室下联口批量配置 ({p_pref}{ps}-{pe})",
        f"interface range {p_pref}{ps}-{pe}",
        " loopback-detection",
        " loopback-detection process-mode port-based",
        " loopback-detection recovery-mode auto",
        " storm-control broadcast rate 100",
        "exit",
        "",
        f"# 3. 上联口配置为 DHCP Snooping Trusted",
        f"interface {uplink}",
        " ip dhcp snooping trust",
        "exit",
        "end",
        "copy running-config startup-config",
    ]
    return {"vendor": "TP-LINK 网管交换机", "config": "\n".join(lines)}

