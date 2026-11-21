"""Realistic school campus simulation engine for testing & staff training.

Allows testing both:
1. Classroom/Office L2 broadcast storm, duplicate ARP bursts, active 0x88B5 probe
   echoes, Rogue TP-Link DHCP server, LLDP upstream switch discovery, and live
   bisection unplug recovery.
2. Multi-vendor weak-current room SNMP scans (H3C aggregation switch -> Huawei
   access switch) with broadcast PPS spikes, live MAC flapping, and LLDP drill-down.
"""

from __future__ import annotations

import random
import struct
import time
from typing import Any, Dict, List, Optional

from loopfinder.core.ledger import PortLedger, normalize_port_name
from loopfinder.core.packet_parser import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    ETHERTYPE_LLDP,
    build_loop_probe_frame,
    mac_str_to_bytes,
)
from loopfinder.data.oui_vendors import lookup_mac_vendor


def _build_sim_arp_frame(src_mac: str, sender_ip: str, target_ip: str) -> bytes:
    dst = b"\xff\xff\xff\xff\xff\xff"
    src = mac_str_to_bytes(src_mac)
    import socket
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1, 0x0800, 6, 4, 1,
        src, socket.inet_aton(sender_ip),
        b"\x00" * 6, socket.inet_aton(target_ip),
    )
    frame = dst + src + struct.pack("!H", ETHERTYPE_ARP) + arp
    return frame + b"\x00" * max(0, 60 - len(frame))


def _build_sim_lldp_frame(
    chassis_mac: str,
    port_id: str,
    sys_name: str,
    sys_desc: str,
    mgmt_ip: str,
    vlan_id: int = 20,
) -> bytes:
    import socket

    def tlv(t: int, val: bytes) -> bytes:
        hdr = ((t & 0x7F) << 9) | (len(val) & 0x1FF)
        return struct.pack("!H", hdr) + val

    tlvs = b"".join([
        tlv(1, b"\x04" + mac_str_to_bytes(chassis_mac)),
        tlv(2, b"\x05" + port_id.encode("ascii")),
        tlv(3, struct.pack("!H", 120)),
        tlv(5, sys_name.encode("utf-8")),
        tlv(6, sys_desc.encode("utf-8")),
        tlv(8, b"\x05\x01" + socket.inet_aton(mgmt_ip) + b"\x02\x00\x00\x00\x0e\x00"),
        tlv(127, b"\x00\x80\xc2\x01" + struct.pack("!H", vlan_id)),
        b"\x00\x00",
    ])
    dst = mac_str_to_bytes("01:80:C2:00:00:0E")
    src = mac_str_to_bytes(chassis_mac)
    return dst + src + struct.pack("!H", ETHERTYPE_LLDP) + tlvs


def _build_sim_dhcp_offer(
    server_mac: str,
    server_ip: str,
    offered_ip: str,
    router_ip: str,
    xid: int = 0x12345678,
) -> bytes:
    import socket

    bootp = bytearray(236)
    bootp[0] = 2  # BOOTREPLY
    bootp[1] = 1
    bootp[2] = 6
    struct.pack_into("!I", bootp, 4, xid)
    bootp[16:20] = socket.inet_aton(offered_ip)
    bootp[20:24] = socket.inet_aton(server_ip)
    bootp[28:34] = mac_str_to_bytes("AA:BB:CC:11:22:33")

    opts = (
        bytes([53, 1, 2])  # OFFER
        + bytes([54, 4]) + socket.inet_aton(server_ip)
        + bytes([3, 4]) + socket.inet_aton(router_ip)
        + bytes([1, 4]) + socket.inet_aton("255.255.255.0")
        + bytes([51, 4]) + struct.pack("!I", 7200)
        + bytes([255])
    )
    payload = bytes(bootp) + b"\x63\x82\x53\x63" + opts
    udp = struct.pack("!HHHH", 67, 68, 8 + len(payload), 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp) + len(payload), 1, 0, 64, 17, 0,
        socket.inet_aton(server_ip), socket.inet_aton("255.255.255.255"),
    )
    eth = b"\xff\xff\xff\xff\xff\xff" + mac_str_to_bytes(server_mac) + struct.pack("!H", ETHERTYPE_IPV4)
    return eth + ip + udp + payload


class ClassroomSimulator:
    """Generates realistic Ethernet frames for simulation mode."""

    def __init__(self) -> None:
        self.loop_active: bool = True
        self.rogue_dhcp_active: bool = True
        self._tick: int = 0
        self._normal_macs = [
            ("48:2A:E3:11:22:01", "10.10.20.41"),  # Lenovo PC
            ("8C:EC:4B:33:44:02", "10.10.20.42"),  # Dell PC
            ("A4:83:E7:55:66:03", "10.10.20.43"),  # Apple MacBook
            ("00:1E:8F:77:88:04", "10.10.20.44"),  # Canon Printer
            ("3C:D9:2B:99:AA:05", "10.10.20.45"),  # HP PC
        ]
        self._rogue_mac = "D8:0D:17:6A:3B:9C"  # TP-LINK SOHO Router
        self._storm_victim_mac = "48:2A:E3:11:22:01"
        self._loop_arp_frame = _build_sim_arp_frame(self._rogue_mac, "192.168.1.1", "192.168.1.1")
        self._loop_arp_frame2 = _build_sim_arp_frame(self._storm_victim_mac, "10.10.20.41", "10.10.20.1")
        self._lldp_frame = _build_sim_lldp_frame(
            chassis_mac="54:89:98:AA:12:34",
            port_id="GigabitEthernet0/0/14",
            sys_name="HW-3F-East-SW02",
            sys_desc="Huawei S5735-L24T4S-A VRP V200R021C00",
            mgmt_ip="10.10.2.12",
            vlan_id=20,
        )

    def generate_batch(self, session_id: int, last_probe_seq: int, probe_mac: str) -> List[bytes]:
        """Return a batch of frames representing ~200ms of wire activity."""
        self._tick += 1
        frames: List[bytes] = []

        # Emit upstream LLDP frame on startup and every ~4 seconds
        if self._tick == 1 or self._tick % 20 == 0:
            frames.append(self._lldp_frame)

        # Normal background traffic (2~5 packets per 200ms = 10~25 pps)
        for _ in range(random.randint(2, 4)):
            mac, ip = random.choice(self._normal_macs)
            target = f"10.10.20.{random.randint(1, 250)}"
            frames.append(_build_sim_arp_frame(mac, ip, target))

        # Rogue DHCP offers (school legit + rogue TP-LINK)
        if self._tick == 2 or self._tick % 25 == 0:
            frames.append(_build_sim_dhcp_offer("00:23:89:01:02:03", "10.10.1.1", "10.10.20.108", "10.10.20.1"))
            if self.rogue_dhcp_active:
                frames.append(_build_sim_dhcp_offer(self._rogue_mac, "192.168.1.1", "192.168.1.102", "192.168.1.1"))

        if self.loop_active:
            # Broadcast storm: identical ARP frames looping hundreds of times per second
            burst_a = random.randint(120, 170)
            burst_b = random.randint(60, 95)
            frames.extend([self._loop_arp_frame] * burst_a)
            frames.extend([self._loop_arp_frame2] * burst_b)

            # Echo active probe back multiple times when a probe was recently transmitted
            if last_probe_seq > 0 and self._tick % 5 == 0:
                echo_frame = build_loop_probe_frame(probe_mac, session_id, last_probe_seq)
                frames.extend([echo_frame] * random.randint(3, 6))

        return frames


DEMO_LOCATIONS: Dict[str, str] = {
    "10.10.1.1|ge1/0/1": "实验楼 · 三楼弱电间 · 上联核心",
    "10.10.1.1|ge1/0/14": "第一教学楼 · 302大教研室 · 汇聚下联->HW-3F-East-SW02",
    "10.10.1.1|ge1/0/15": "第一教学楼 · 305教研室 · 东墙1-6号面板",
    "10.10.1.1|ge1/0/16": "第一教学楼 · 308教研室 · 北墙2号面板",
    "10.10.2.12|ge0/0/1": "第一教学楼 · 302大教研室 · 北墙1号信息点",
    "10.10.2.12|ge0/0/8": "第一教学楼 · 302大教研室 · 南墙3号信息点",
    "10.10.2.12|ge0/0/14": "第一教学楼 · 302大教研室 · 东墙4号信息点",
    "10.10.2.12|ge0/0/15": "第一教学楼 · 302大教研室 · 东墙5号信息点",
    "10.10.2.12|ge0/0/24": "第一教学楼 · 三楼弱电间 · 上联汇聚口",
}


def demo_location(switch_ip: str, port_name: str, ledger: Optional[PortLedger] = None) -> str:
    """Resolve location from user ledger first, falling back to demo labels in simulation mode."""
    if ledger is not None:
        hit = ledger.format_location(switch_ip, port_name)
        if hit:
            return hit
    return DEMO_LOCATIONS.get(f"{switch_ip.strip()}|{normalize_port_name(port_name)}", "")


def simulate_snmp_switch_scan(switch_ip: str, ledger: PortLedger) -> Dict[str, Any]:
    """Generate a realistic multi-vendor weak-current room switch scan result.

    Supports a full 3-tier simulated campus tree:
    - 10.10.0.1  (CORE-Campus-S12700, Huawei) -> LLDP -> 10.10.1.1
    - 10.10.1.1  (H3C-3F-Agg-SW01, H3C)       -> LLDP -> 10.10.2.12 (fault) & 10.10.2.13 (healthy)
    - 10.10.2.12 (HW-3F-East-SW02, Huawei)    -> Edge ports GE0/0/14 & GE0/0/15 (302大教研室)
    - 10.10.2.13 (RJ-3F-West-SW03, Ruijie)    -> Healthy control switch
    """
    now = time.time()
    ip_clean = switch_ip.strip() or "10.10.1.1"
    cpu_pct = 86

    if ip_clean == "10.10.0.1":
        sys_name = "CORE-Campus-S12700"
        sys_desc = "Huawei Versatile Routing Platform Software S12700E-8"
        vendor = "Huawei (华为)"
        cpu_pct = 62
        port_count = 16
        port_prefix = "XGigabitEthernet1/0/"
        hot_ports = {
            3: {"bcast": 7180.0, "mcast": 830.0, "err": 4, "disc": 96, "macs": 185, "mbps": 420.5, "stp": "forwarding"},
        }
        lldp_map = {
            3: {"remote_sys": "H3C-3F-Agg-SW01", "remote_port": "GigabitEthernet1/0/1", "remote_ip": "10.10.1.1"},
        }
        flaps = []
        sample_macs = {
            "D8:0D:17:6A:3B:9C": "XGigabitEthernet1/0/3",
            "48:2A:E3:11:22:01": "XGigabitEthernet1/0/3",
        }
    elif ip_clean == "10.10.2.13":
        sys_name = "RJ-3F-West-SW03"
        sys_desc = "Ruijie Gigabit Ethernet Switch (RG-S2910-24GT4XS-E) RGOS 11.4"
        vendor = "Ruijie (锐捷)"
        cpu_pct = 14
        port_count = 24
        port_prefix = "GigabitEthernet0/"
        hot_ports = {
            24: {"bcast": 22.0, "mcast": 8.0, "err": 0, "disc": 0, "macs": 24, "mbps": 18.4, "stp": "forwarding", "uplink": True},
        }
        lldp_map = {
            24: {"remote_sys": "H3C-3F-Agg-SW01", "remote_port": "GigabitEthernet1/0/16", "remote_ip": "10.10.1.1"},
        }
        flaps = []
        sample_macs = {
            "A4:83:E7:55:66:03": "GigabitEthernet0/5",
        }
    elif ip_clean == "10.10.2.12":
        sys_name = "HW-3F-East-SW02"
        sys_desc = "Huawei Versatile Routing Platform Software S5735-L24T4S-A"
        vendor = "Huawei (华为)"
        cpu_pct = 96
        port_count = 24
        port_prefix = "GigabitEthernet0/0/"
        hot_ports = {
            14: {"bcast": 7420.5, "mcast": 840.2, "err": 18, "disc": 412, "macs": 16, "mbps": 91.4, "stp": "forwarding"},
            15: {"bcast": 6810.0, "mcast": 790.0, "err": 9, "disc": 280, "macs": 14, "mbps": 84.2, "stp": "forwarding"},
            24: {"bcast": 7150.3, "mcast": 815.1, "err": 0, "disc": 12, "macs": 68, "mbps": 118.6, "stp": "forwarding", "uplink": True},
        }
        lldp_map = {
            24: {"remote_sys": "H3C-3F-Agg-SW01", "remote_port": "GigabitEthernet1/0/14", "remote_ip": "10.10.1.1"},
        }
        flaps = [
            {
                "mac": "D8:0D:17:6A:3B:9C",
                "vendor": lookup_mac_vendor("D8:0D:17:6A:3B:9C")["vendor"],
                "category": "soho_router",
                "from_port": "GigabitEthernet0/0/14",
                "to_port": "GigabitEthernet0/0/15",
                "from_location": demo_location(ip_clean, "GigabitEthernet0/0/14", ledger),
                "to_location": demo_location(ip_clean, "GigabitEthernet0/0/15", ledger),
            },
            {
                "mac": "48:2A:E3:11:22:01",
                "vendor": lookup_mac_vendor("48:2A:E3:11:22:01")["vendor"],
                "category": "endpoint",
                "from_port": "GigabitEthernet0/0/15",
                "to_port": "GigabitEthernet0/0/14",
                "from_location": demo_location(ip_clean, "GigabitEthernet0/0/15", ledger),
                "to_location": demo_location(ip_clean, "GigabitEthernet0/0/14", ledger),
            },
        ]
        sample_macs = {
            "D8:0D:17:6A:3B:9C": "GigabitEthernet0/0/14",
            "48:2A:E3:11:22:01": "GigabitEthernet0/0/14",
            "8C:EC:4B:33:44:02": "GigabitEthernet0/0/15",
            "A4:83:E7:55:66:03": "GigabitEthernet0/0/8",
            "00:1E:8F:77:88:04": "GigabitEthernet0/0/1",
        }
    else:
        ip_clean = ip_clean or "10.10.1.1"
        sys_name = "H3C-3F-Agg-SW01"
        sys_desc = "H3C Comware Software, Version 7.1.070, S5560X-30C-EI"
        vendor = "H3C (新华三)"
        cpu_pct = 89
        port_count = 24
        port_prefix = "GigabitEthernet1/0/"
        hot_ports = {
            1: {"bcast": 7120.0, "mcast": 820.0, "err": 0, "disc": 5, "macs": 240, "mbps": 342.0, "stp": "forwarding", "uplink": True},
            14: {"bcast": 7380.4, "mcast": 845.6, "err": 24, "disc": 520, "macs": 42, "mbps": 146.8, "stp": "forwarding"},
            15: {"bcast": 1240.2, "mcast": 110.5, "err": 2, "disc": 18, "macs": 11, "mbps": 28.4, "stp": "forwarding"},
        }
        lldp_map = {
            1: {"remote_sys": "CORE-Campus-S12700", "remote_port": "XGigabitEthernet1/0/3", "remote_ip": "10.10.0.1"},
            14: {"remote_sys": "HW-3F-East-SW02", "remote_port": "GigabitEthernet0/0/24", "remote_ip": "10.10.2.12"},
            16: {"remote_sys": "RJ-3F-West-SW03", "remote_port": "GigabitEthernet0/24", "remote_ip": "10.10.2.13"},
        }
        flaps = [
            {
                "mac": "D8:0D:17:6A:3B:9C",
                "vendor": lookup_mac_vendor("D8:0D:17:6A:3B:9C")["vendor"],
                "category": "soho_router",
                "from_port": "GigabitEthernet1/0/14",
                "to_port": "GigabitEthernet1/0/15",
                "from_location": demo_location(ip_clean, "GigabitEthernet1/0/14", ledger),
                "to_location": demo_location(ip_clean, "GigabitEthernet1/0/15", ledger),
            },
        ]
        sample_macs = {
            "D8:0D:17:6A:3B:9C": "GigabitEthernet1/0/14",
            "48:2A:E3:11:22:01": "GigabitEthernet1/0/14",
            "8C:EC:4B:33:44:02": "GigabitEthernet1/0/14",
            "A4:83:E7:55:66:03": "GigabitEthernet1/0/15",
        }
    switch_ip = ip_clean

    ports: List[Dict[str, Any]] = []
    flapping_ports = {f["from_port"] for f in flaps} | {f["to_port"] for f in flaps}

    for idx in range(1, port_count + 1):
        pname = f"{port_prefix}{idx}"
        hot = hot_ports.get(idx)
        up = bool(hot) or idx in (1, 2, 3, 5, 6, 8, 9, 12, 16, 18, 20, 24)
        bcast = hot["bcast"] if hot else (round(random.uniform(3.0, 28.0), 1) if up else 0.0)
        mcast = hot["mcast"] if hot else (round(random.uniform(1.0, 12.0), 1) if up else 0.0)
        err = hot["err"] if hot else 0
        disc = hot["disc"] if hot else 0
        mac_cnt = hot["macs"] if hot else (random.randint(1, 3) if up else 0)
        mbps = hot["mbps"] if hot else (round(random.uniform(0.2, 8.5), 2) if up else 0.0)
        is_uplink = bool(hot and hot.get("uplink"))
        lldp = lldp_map.get(idx)
        loc = demo_location(switch_ip, pname, ledger)

        reasons: List[str] = []
        score = 0
        if bcast >= 1000:
            score += 55
            reasons.append(f"广播风暴 {bcast:.0f} pps")
        elif bcast >= 200:
            score += 25
            reasons.append(f"广播偏高 {bcast:.0f} pps")
        if pname in flapping_ports:
            score += 40
            reasons.append("检测到实时 MAC 漂移")
        if disc >= 50 or err >= 5:
            score += 15
            reasons.append(f"入向丢包/错包激增 (+{disc}/{err})")
        if (not is_uplink) and (not lldp) and mac_cnt >= 8:
            score += 15
            reasons.append(f"单口学习 {mac_cnt} 个 MAC（疑似下挂傻瓜交换机）")
        if is_uplink:
            score = min(score, 40)
            reasons.append("上联主干口（可能为下级传导风暴）")

        score = min(100, score)
        level = "danger" if score >= 65 else ("warning" if score >= 25 else ("up" if up else "down"))

        out_bcast = round(random.uniform(6200.0, 7400.0), 1) if (up and cpu_pct > 50 and bcast < 100) else round(bcast * 0.35, 1)
        if bcast >= 300:
            bcast_dir = "🚨 广播源头灌入 (In高)"
        elif out_bcast >= 300 and bcast < 80:
            bcast_dir = "⚪ 受害转发口 (仅Out高)"
        else:
            bcast_dir = "正常"

        ports.append({
            "if_index": idx,
            "name": pname,
            "short_name": f"P{idx}",
            "alias": loc or ("上联口" if is_uplink else ""),
            "location": loc,
            "oper_status": "up" if up else "down",
            "speed_mbps": 1000,
            "broadcast_pps": bcast,
            "out_broadcast_pps": out_bcast,
            "broadcast_direction": bcast_dir,
            "multicast_pps": mcast,
            "in_mbps": mbps,
            "errors_delta": err,
            "discards_delta": disc,
            "mac_count": mac_cnt,
            "stp_state": hot["stp"] if hot else ("forwarding" if up else "disabled"),
            "lldp_neighbor": lldp,
            "risk_score": score,
            "risk_level": level,
            "reasons": reasons,
            "is_uplink": is_uplink,
        })

    suspects = sorted([p for p in ports if p["risk_score"] > 0], key=lambda x: (-x["risk_score"], -x["broadcast_pps"]))
    return {
        "simulated": True,
        "scanned_at": now,
        "switch_ip": switch_ip,
        "sys_name": sys_name,
        "sys_desc": sys_desc,
        "vendor": vendor,
        "cpu_pct": cpu_pct,
        "stp_top_changes": 19 if cpu_pct > 50 else 0,
        "ports": ports,
        "suspect_ports": suspects[:10],
        "mac_flaps": flaps,
        "mac_table": sample_macs,
        "summary": (
            f"在 {sys_name} ({vendor}) 发现 {len(flaps)} 条实时 MAC 漂移记录，"
            f"头号可疑口为 {suspects[0]['name']} ({suspects[0]['location'] or '未录入台账'})，"
            f"广播速率 {suspects[0]['broadcast_pps']:.0f} pps。"
        )
        if suspects
        else f"{sys_name} 端口状态正常，未检测到明显环路风暴。",
    }
