"""Zero-dependency pure-Python L2/L3 Ethernet frame parser and active probe builder.

Parses:
- Ethernet II & 802.1Q / QinQ VLAN tags
- LoopFinder Active L2 Probe frames (EtherType 0x88B5)
- ARP (0x0806)
- STP / RSTP / MSTP BPDUs (01:80:C2:00:00:00)
- LLDP (0x88CC) neighbor TLVs (Chassis ID, Port ID, System Name, Mgmt IP, VLAN)
- CDP (01:00:0C:CC:CC:CC) neighbor TLVs (Device ID, Port ID, Platform, Mgmt IP, Native VLAN)
- DHCP (IPv4 UDP 67/68) Offer/Ack server identification
- Fast payload signature hashing for sliding-window duplicate frame burst detection
"""

from __future__ import annotations

import hashlib
import socket
import struct
import time
from typing import Any, Dict, Optional

PROBE_ETHERTYPE = 0x88B5
PROBE_MAGIC = b"LFPRB1"
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_LLDP = 0x88CC

DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"


def mac_bytes_to_str(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in b)


def mac_str_to_bytes(mac: str) -> bytes:
    cleaned = mac.replace(":", "").replace("-", "").replace(".", "")
    if len(cleaned) != 12:
        raise ValueError(f"Invalid MAC address: {mac}")
    return bytes.fromhex(cleaned)


def build_loop_probe_frame(
    src_mac: str,
    session_id: int,
    seq: int,
    dst_mac: str = "FF:FF:FF:FF:FF:FF",
) -> bytes:
    """Build a 64-byte IEEE 802.1 Local Experimental (0x88B5) L2 loop probe frame."""
    dst_b = mac_str_to_bytes(dst_mac)
    src_b = mac_str_to_bytes(src_mac)
    sent_us = int(time.time() * 1_000_000)
    payload = struct.pack("!6sIIQ", PROBE_MAGIC, session_id & 0xFFFFFFFF, seq & 0xFFFFFFFF, sent_us)
    frame = dst_b + src_b + struct.pack("!H", PROBE_ETHERTYPE) + payload
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def _ipv4_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_dhcp_discover_frame(client_mac: str, xid: int) -> bytes:
    """Build a complete raw Ethernet + IPv4 + UDP + DHCPDISCOVER broadcast frame."""
    chaddr = mac_str_to_bytes(client_mac)
    # BOOTP header (236 bytes) + magic cookie (4 bytes) + DHCP options
    bootp = bytearray(236)
    bootp[0] = 1  # BOOTREQUEST
    bootp[1] = 1  # Ethernet
    bootp[2] = 6  # HLEN
    bootp[3] = 0  # HOPS
    struct.pack_into("!I", bootp, 4, xid & 0xFFFFFFFF)
    struct.pack_into("!H", bootp, 10, 0x8000)  # Broadcast flag so offers return via L2 broadcast
    bootp[28:34] = chaddr

    options = bytes([
        53, 1, 1,              # DHCP Message Type: Discover (1)
        55, 4, 1, 3, 6, 51,    # Parameter Request List: Subnet, Router, DNS, Lease
        61, 7, 1,              # Client Identifier
    ]) + chaddr + bytes([255])  # End option

    dhcp_payload = bytes(bootp) + DHCP_MAGIC_COOKIE + options
    if len(dhcp_payload) < 300:
        dhcp_payload += b"\x00" * (300 - len(dhcp_payload))

    # UDP header (src 68 -> dst 67, checksum 0 optional for IPv4)
    udp_len = 8 + len(dhcp_payload)
    udp_hdr = struct.pack("!HHHH", 68, 67, udp_len, 0)

    # IPv4 header (0.0.0.0 -> 255.255.255.255)
    ip_total = 20 + udp_len
    ip_hdr_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, ip_total, xid & 0xFFFF, 0, 64, 17, 0,
        b"\x00\x00\x00\x00", b"\xff\xff\xff\xff",
    )
    csum = _ipv4_checksum(ip_hdr_no_csum)
    ip_hdr = ip_hdr_no_csum[:10] + struct.pack("!H", csum) + ip_hdr_no_csum[12:]

    eth_hdr = b"\xff\xff\xff\xff\xff\xff" + chaddr + struct.pack("!H", ETHERTYPE_IPV4)
    return eth_hdr + ip_hdr + udp_hdr + dhcp_payload


def _parse_lldp(payload: bytes) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    offset = 0
    n = len(payload)
    while offset + 2 <= n:
        hdr = struct.unpack_from("!H", payload, offset)[0]
        tlv_type = (hdr >> 9) & 0x7F
        tlv_len = hdr & 0x01FF
        offset += 2
        if tlv_type == 0:
            break
        if offset + tlv_len > n:
            break
        val = payload[offset : offset + tlv_len]
        offset += tlv_len

        if tlv_type == 1 and tlv_len >= 2:  # Chassis ID
            subtype = val[0]
            body = val[1:]
            if subtype == 4 and len(body) == 6:
                info["chassis_id"] = mac_bytes_to_str(body)
            else:
                info["chassis_id"] = body.decode("utf-8", errors="ignore").strip("\x00 ")
        elif tlv_type == 2 and tlv_len >= 2:  # Port ID
            subtype = val[0]
            body = val[1:]
            if subtype == 3 and len(body) == 6:
                info["port_id"] = mac_bytes_to_str(body)
            else:
                info["port_id"] = body.decode("utf-8", errors="ignore").strip("\x00 ")
        elif tlv_type == 4:  # Port Description
            info["port_desc"] = val.decode("utf-8", errors="ignore").strip("\x00 ")
        elif tlv_type == 5:  # System Name
            info["sys_name"] = val.decode("utf-8", errors="ignore").strip("\x00 ")
        elif tlv_type == 6:  # System Description
            info["sys_desc"] = val.decode("utf-8", errors="ignore").strip("\x00 ")[:160]
        elif tlv_type == 8 and tlv_len >= 6:  # Management Address
            addr_len = val[0]
            if addr_len >= 2 and 1 + addr_len <= tlv_len:
                addr_subtype = val[1]
                addr_bytes = val[2 : 1 + addr_len]
                if addr_subtype == 1 and len(addr_bytes) == 4:
                    info["mgmt_ip"] = socket.inet_ntoa(addr_bytes)
        elif tlv_type == 127 and tlv_len >= 6:  # Org-specific (IEEE 802.1 PVID)
            if val[:3] == b"\x00\x80\xc2" and val[3] == 1:
                info["vlan_id"] = struct.unpack_from("!H", val, 4)[0]
    info["protocol"] = "LLDP"
    return info


def _parse_cdp(payload: bytes) -> Dict[str, Any]:
    """Parse Cisco Discovery Protocol (after LLC/SNAP 8 bytes)."""
    info: Dict[str, Any] = {"protocol": "CDP"}
    if len(payload) < 4:
        return info
    offset = 4  # version(1) + ttl(1) + checksum(2)
    n = len(payload)
    while offset + 4 <= n:
        tlv_type, tlv_len = struct.unpack_from("!HH", payload, offset)
        if tlv_len < 4 or offset + tlv_len > n:
            break
        val = payload[offset + 4 : offset + tlv_len]
        offset += tlv_len
        if tlv_type == 0x0001:  # Device ID
            info["sys_name"] = val.decode("utf-8", errors="ignore").strip("\x00 ")
        elif tlv_type == 0x0003:  # Port ID
            info["port_id"] = val.decode("utf-8", errors="ignore").strip("\x00 ")
        elif tlv_type == 0x0006:  # Platform
            info["sys_desc"] = val.decode("utf-8", errors="ignore").strip("\x00 ")
        elif tlv_type == 0x000A and len(val) >= 2:  # Native VLAN
            info["vlan_id"] = struct.unpack_from("!H", val, 0)[0]
        elif tlv_type == 0x0002 and len(val) >= 13:  # Addresses
            num_addr = struct.unpack_from("!I", val, 0)[0]
            pos = 4
            for _ in range(min(num_addr, 4)):
                if pos + 2 > len(val):
                    break
                proto_type, proto_len = val[pos], val[pos + 1]
                pos += 2 + proto_len
                if pos + 2 > len(val):
                    break
                addr_len = struct.unpack_from("!H", val, pos)[0]
                pos += 2
                if addr_len == 4 and pos + 4 <= len(val):
                    info["mgmt_ip"] = socket.inet_ntoa(val[pos : pos + 4])
                    break
                pos += addr_len
    return info


def _parse_stp(llc_payload: bytes) -> Optional[Dict[str, Any]]:
    """Parse IEEE 802.1D / RSTP / MSTP BPDU after 3-byte LLC (42 42 03)."""
    if len(llc_payload) < 4:
        return None
    proto_id, version, bpdu_type = struct.unpack_from("!HBB", llc_payload, 0)
    if proto_id != 0:
        return None
    result: Dict[str, Any] = {
        "version": version,
        "bpdu_type": bpdu_type,
        "tc_flag": False,
        "root_mac": "",
        "root_priority": 0,
        "bridge_mac": "",
        "root_cost": 0,
    }
    if bpdu_type == 0x80:  # TCN BPDU
        result["tc_flag"] = True
        return result
    if len(llc_payload) >= 31:
        flags = llc_payload[4]
        result["tc_flag"] = bool(flags & 0x01)
        root_prio = struct.unpack_from("!H", llc_payload, 5)[0]
        root_mac = mac_bytes_to_str(llc_payload[7:13])
        root_cost = struct.unpack_from("!I", llc_payload, 13)[0]
        bridge_prio = struct.unpack_from("!H", llc_payload, 17)[0]
        bridge_mac = mac_bytes_to_str(llc_payload[19:25])
        result.update({
            "root_priority": root_prio,
            "root_mac": root_mac,
            "root_cost": root_cost,
            "bridge_priority": bridge_prio,
            "bridge_mac": bridge_mac,
        })
    return result


def _parse_dhcp(udp_payload: bytes, src_mac: str, src_ip: str) -> Optional[Dict[str, Any]]:
    if len(udp_payload) < 244:
        return None
    if udp_payload[236:240] != DHCP_MAGIC_COOKIE:
        return None
    op = udp_payload[0]
    xid = struct.unpack_from("!I", udp_payload, 4)[0]
    yiaddr = socket.inet_ntoa(udp_payload[16:20])
    siaddr = socket.inet_ntoa(udp_payload[20:24])
    chaddr = mac_bytes_to_str(udp_payload[28:34])
    sname = udp_payload[44:108].split(b"\x00", 1)[0].decode("utf-8", errors="ignore").strip()

    msg_type = 0
    server_id = ""
    router_ip = ""
    subnet_mask = ""
    dns_servers = []
    lease_time = 0
    host_name = ""
    domain_name = ""
    vendor_class = ""

    pos = 240
    n = len(udp_payload)
    while pos < n:
        opt = udp_payload[pos]
        pos += 1
        if opt == 0:
            continue
        if opt == 255:
            break
        if pos >= n:
            break
        length = udp_payload[pos]
        pos += 1
        if pos + length > n:
            break
        val = udp_payload[pos : pos + length]
        pos += length

        if opt == 53 and length >= 1:
            msg_type = val[0]
        elif opt == 54 and length == 4:
            server_id = socket.inet_ntoa(val)
        elif opt == 3 and length >= 4:
            router_ip = socket.inet_ntoa(val[:4])
        elif opt == 1 and length == 4:
            subnet_mask = socket.inet_ntoa(val)
        elif opt == 6 and length >= 4:
            for i in range(0, length - (length % 4), 4):
                dns_servers.append(socket.inet_ntoa(val[i : i + 4]))
        elif opt == 51 and length == 4:
            lease_time = struct.unpack_from("!I", val, 0)[0]
        elif opt == 12 and length > 0:
            host_name = val.decode("utf-8", errors="ignore").strip("\x00 ")
        elif opt == 15 and length > 0:
            domain_name = val.decode("utf-8", errors="ignore").strip("\x00 ")
        elif opt == 60 and length > 0:
            vendor_class = val.decode("utf-8", errors="ignore").strip("\x00 ")

    msg_names = {
        1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
        5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
    }
    return {
        "op": op,
        "xid": xid,
        "msg_type": msg_type,
        "msg_name": msg_names.get(msg_type, f"TYPE_{msg_type}"),
        "server_ip": server_id or src_ip or siaddr,
        "server_mac": src_mac,
        "router_ip": router_ip or server_id or src_ip,
        "offered_ip": yiaddr,
        "subnet_mask": subnet_mask,
        "dns": dns_servers,
        "lease_time": lease_time,
        "client_mac": chaddr,
        "sname": sname,
        "host_name": host_name,
        "domain_name": domain_name,
        "vendor_class": vendor_class,
    }


def parse_ethernet_frame(raw: bytes, timestamp: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Parse raw Ethernet frame into structured diagnostic metadata."""
    if not raw or len(raw) < 14:
        return None
    ts = timestamp if timestamp is not None else time.time()
    dst_b = raw[0:6]
    src_b = raw[6:12]
    ethertype = struct.unpack_from("!H", raw, 12)[0]
    offset = 14
    vlan_id: Optional[int] = None

    # Strip up to 2 802.1Q / QinQ tags
    for _ in range(2):
        if ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ) and len(raw) >= offset + 4:
            tci, ethertype = struct.unpack_from("!HH", raw, offset)
            vlan_id = tci & 0x0FFF
            offset += 4
        else:
            break

    dst_mac = mac_bytes_to_str(dst_b)
    src_mac = mac_bytes_to_str(src_b)
    is_broadcast = dst_b == b"\xff\xff\xff\xff\xff\xff"
    is_multicast = (not is_broadcast) and bool(dst_b[0] & 0x01)
    payload = raw[offset:]

    # Fast duplicate-frame fingerprint (ignores FCS, focuses on header + first 36 payload bytes)
    sig_input = raw[0:12] + struct.pack("!H", ethertype) + payload[:36]
    frame_sig = hashlib.blake2b(sig_input, digest_size=8).digest()

    pkt: Dict[str, Any] = {
        "ts": ts,
        "length": len(raw),
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "ethertype": ethertype,
        "vlan_id": vlan_id,
        "is_broadcast": is_broadcast,
        "is_multicast": is_multicast,
        "proto": f"0x{ethertype:04X}",
        "sig": frame_sig,
        "probe": None,
        "arp": None,
        "stp": None,
        "neighbor": None,
        "dhcp": None,
    }

    # 1. LoopFinder Active L2 Probe (0x88B5)
    if ethertype == PROBE_ETHERTYPE and len(payload) >= 22 and payload[:6] == PROBE_MAGIC:
        _, session_id, seq, sent_us = struct.unpack_from("!6sIIQ", payload, 0)
        pkt["proto"] = "LOOP_PROBE"
        pkt["probe"] = {
            "session_id": session_id,
            "seq": seq,
            "sent_us": sent_us,
            "rtt_ms": max(0.0, (ts * 1_000_000 - sent_us) / 1000.0),
        }
        return pkt

    # 2. IEEE 802.3 Length-framed protocols (STP / CDP)
    if ethertype <= 1500 and len(payload) >= 3:
        dsap, ssap, ctrl = payload[0], payload[1], payload[2]
        if dsap == 0x42 and ssap == 0x42 and ctrl == 0x03:
            pkt["proto"] = "STP"
            pkt["stp"] = _parse_stp(payload[3:])
            return pkt
        if dst_mac == "01:00:0C:CC:CC:CC" and len(payload) >= 8 and payload[:3] == b"\xaa\xaa\x03":
            snap_proto = struct.unpack_from("!H", payload, 6)[0]
            if snap_proto == 0x2000:
                pkt["proto"] = "CDP"
                pkt["neighbor"] = _parse_cdp(payload[8:])
                return pkt
        pkt["proto"] = "802.3"
        return pkt

    # 3. LLDP (0x88CC)
    if ethertype == ETHERTYPE_LLDP:
        pkt["proto"] = "LLDP"
        pkt["neighbor"] = _parse_lldp(payload)
        return pkt

    # 4. ARP (0x0806)
    if ethertype == ETHERTYPE_ARP and len(payload) >= 28:
        pkt["proto"] = "ARP"
        opcode = struct.unpack_from("!H", payload, 6)[0]
        sender_mac = mac_bytes_to_str(payload[8:14])
        sender_ip = socket.inet_ntoa(payload[14:18])
        target_ip = socket.inet_ntoa(payload[24:28])
        pkt["arp"] = {
            "opcode": opcode,  # 1=request, 2=reply
            "sender_mac": sender_mac,
            "sender_ip": sender_ip,
            "target_ip": target_ip,
            "gratuitous": sender_ip == target_ip,
        }
        return pkt

    # 5. IPv4 (0x0800) -> check UDP DHCP / mDNS / NetBIOS / SSDP
    if ethertype == ETHERTYPE_IPV4 and len(payload) >= 20:
        ihl = (payload[0] & 0x0F) * 4
        ip_proto = payload[9]
        src_ip = socket.inet_ntoa(payload[12:16])
        dst_ip = socket.inet_ntoa(payload[16:20])
        if ip_proto == 17 and len(payload) >= ihl + 8:
            sport, dport = struct.unpack_from("!HH", payload, ihl)
            udp_data = payload[ihl + 8 :]
            if (sport == 67 and dport == 68) or (sport == 68 and dport == 67):
                pkt["proto"] = "DHCP"
                pkt["dhcp"] = _parse_dhcp(udp_data, src_mac, src_ip)
            elif sport == 5353 or dport == 5353:
                pkt["proto"] = "mDNS"
            elif dport in (137, 138):
                pkt["proto"] = "NetBIOS"
            elif dport == 1900:
                pkt["proto"] = "SSDP"
            else:
                pkt["proto"] = f"UDP:{dport}"
        elif ip_proto == 1:
            pkt["proto"] = "ICMP"
        elif ip_proto == 2:
            pkt["proto"] = "IGMP"
        elif ip_proto == 6:
            pkt["proto"] = "TCP"
        else:
            pkt["proto"] = f"IPv4({ip_proto})"
        return pkt

    if ethertype == ETHERTYPE_IPV6:
        pkt["proto"] = "IPv6"
        return pkt

    return pkt
