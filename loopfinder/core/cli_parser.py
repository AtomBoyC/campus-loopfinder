"""Universal Multi-Vendor Switch CLI Log Parser.

Parses Huawei (VRP), H3C (Comware), Ruijie (RGOS), Cisco (IOS) and TP-Link outputs
(MAC flapping, loopback-detection / RLDP, storm-control, STP blocking) into structured
loop findings. Used by the Console serial locator, the Syslog radar, and the
"paste Console/terminal output" parser in the UI.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from loopfinder.core.ledger import PortLedger
from loopfinder.data.oui_vendors import lookup_mac_vendor, normalize_mac


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
