"""Zero-dependency pure-Python SNMPv2c engine & Multi-Vendor Switch Loop Analyzer.

Because school campuses mix Huawei, H3C, Ruijie, Cisco, TP-Link, ZTE, and Aruba
switches, this module uses standard RFC MIBs supported across ALL managed switches:
- SNMPv2-MIB (sysName, sysDescr) -> Vendor & model identification
- IF-MIB (ifName, ifDescr, ifAlias, ifOperStatus, ifInBroadcastPkts/HC, ifInMulticastPkts/HC,
          ifInNUcastPkts, ifInErrors, ifInDiscards, ifInOctets/HC) -> 2-pass delta PPS
- BRIDGE-MIB / Q-BRIDGE-MIB (dot1dBasePortIfIndex, dot1dTpFdbPort, dot1qTpFdbPort)
  -> Live MAC Flapping detection + MAC-to-Port lookup + Cascade Hub detection
- LLDP-MIB -> Automatic neighbor switch discovery for hop-by-hop drill-down
- STP-MIB -> Topology change counters & per-port STP state
"""

from __future__ import annotations

import concurrent.futures
import random
import re
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from loopfinder.core.ledger import PortLedger
from loopfinder.core.simulator import simulate_snmp_switch_scan
from loopfinder.data.oui_vendors import lookup_mac_vendor, normalize_mac


# ==============================================================================
# Minimal, RFC-1905 Compliant Pure-Python ASN.1 BER & SNMPv2c Client
# ==============================================================================

TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_IPADDRESS = 0x40
TAG_COUNTER32 = 0x41
TAG_GAUGE32 = 0x42
TAG_TIMETICKS = 0x43
TAG_OPAQUE = 0x44
TAG_COUNTER64 = 0x46
TAG_NO_SUCH_OBJECT = 0x80
TAG_NO_SUCH_INSTANCE = 0x81
TAG_END_OF_MIB_VIEW = 0x82

PDU_GET = 0xA0
PDU_GETNEXT = 0xA1
PDU_RESPONSE = 0xA2
PDU_GETBULK = 0xA5


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    chunks = []
    n = length
    while n > 0:
        chunks.append(n & 0xFF)
        n >>= 8
    chunks.reverse()
    return bytes([0x80 | len(chunks)]) + bytes(chunks)


def _encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def encode_integer(val: int) -> bytes:
    if val == 0:
        return _encode_tlv(TAG_INTEGER, b"\x00")
    neg = val < 0
    num = val
    out = []
    while True:
        out.append(num & 0xFF)
        num >>= 8
        if (not neg and num == 0) or (neg and num == -1):
            break
    if not neg and (out[-1] & 0x80):
        out.append(0x00)
    elif neg and not (out[-1] & 0x80):
        out.append(0xFF)
    out.reverse()
    return _encode_tlv(TAG_INTEGER, bytes(out))


def encode_octet_string(val: bytes) -> bytes:
    return _encode_tlv(TAG_OCTET_STRING, val)


def encode_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip(".").split(".") if x]
    if len(parts) < 2:
        raise ValueError(f"Invalid OID: {oid}")
    out = bytearray([parts[0] * 40 + parts[1]])
    for arc in parts[2:]:
        if arc == 0:
            out.append(0)
            continue
        sub = []
        n = arc
        while n > 0:
            sub.append(n & 0x7F)
            n >>= 7
        sub.reverse()
        for i in range(len(sub) - 1):
            out.append(sub[i] | 0x80)
        out.append(sub[-1])
    return _encode_tlv(TAG_OID, bytes(out))


def _decode_length(data: bytes, offset: int) -> Tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    nbytes = first & 0x7F
    length = 0
    for _ in range(nbytes):
        length = (length << 8) | data[offset]
        offset += 1
    return length, offset


def _decode_oid(val: bytes) -> str:
    if not val:
        return ""
    first = val[0]
    arcs = [first // 40, first % 40]
    acc = 0
    for b in val[1:]:
        acc = (acc << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(acc)
            acc = 0
    return ".".join(str(x) for x in arcs)


def _decode_tlv(data: bytes, offset: int) -> Tuple[int, Any, int]:
    tag = data[offset]
    offset += 1
    length, offset = _decode_length(data, offset)
    val = data[offset : offset + length]
    end = offset + length

    if tag in (TAG_SEQUENCE, PDU_RESPONSE):
        items = []
        pos = offset
        while pos < end:
            t, v, pos = _decode_tlv(data, pos)
            items.append((t, v))
        return tag, items, end
    if tag == TAG_INTEGER:
        return tag, int.from_bytes(val, "big", signed=True), end
    if tag in (TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS, TAG_COUNTER64):
        return tag, int.from_bytes(val, "big", signed=False), end
    if tag == TAG_OID:
        return tag, _decode_oid(val), end
    if tag == TAG_IPADDRESS:
        return tag, socket.inet_ntoa(val) if len(val) == 4 else val.hex(), end
    if tag in (TAG_OCTET_STRING, TAG_OPAQUE):
        return tag, val, end
    if tag in (TAG_NULL, TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE, TAG_END_OF_MIB_VIEW):
        return tag, None, end
    return tag, val, end


class SnmpV2Client:
    """Lightweight UDP SNMPv1/v2c client with GET, GETBULK, and automatic GETNEXT fallback."""

    def __init__(
        self,
        host: str,
        community: str = "public",
        port: int = 161,
        timeout: float = 2.0,
        retries: int = 1,
        version: str = "2c",
    ) -> None:
        self.host = host.strip()
        self.community = community
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.version = "1" if str(version).strip() == "1" else "2c"
        self._snmp_ver_int = 0 if self.version == "1" else 1
        self._use_getnext_only = self.version == "1"
        self._req_id = random.randint(1000, 0x7FFFFFF)

    def _next_req_id(self) -> int:
        self._req_id = (self._req_id + 1) & 0x7FFFFFFF
        return self._req_id

    def _exchange(self, pdu_tag: int, oids: List[str], max_repetitions: int = 20) -> List[Tuple[str, int, Any]]:
        req_id = self._next_req_id()
        varbinds = b"".join(
            _encode_tlv(TAG_SEQUENCE, encode_oid(o) + _encode_tlv(TAG_NULL, b""))
            for o in oids
        )
        varbind_list = _encode_tlv(TAG_SEQUENCE, varbinds)
        if pdu_tag == PDU_GETBULK:
            pdu_body = encode_integer(req_id) + encode_integer(0) + encode_integer(max_repetitions) + varbind_list
        else:
            pdu_body = encode_integer(req_id) + encode_integer(0) + encode_integer(0) + varbind_list
        pdu = _encode_tlv(pdu_tag, pdu_body)
        msg = _encode_tlv(
            TAG_SEQUENCE,
            encode_integer(self._snmp_ver_int) + encode_octet_string(self.community.encode("utf-8")) + pdu,
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            last_err: Optional[Exception] = None
            for _ in range(self.retries + 1):
                try:
                    sock.sendto(msg, (self.host, self.port))
                    resp, _ = sock.recvfrom(65535)
                    _, top_items, _ = _decode_tlv(resp, 0)
                    if len(top_items) < 3:
                        continue
                    _, pdu_items = top_items[2]
                    if len(pdu_items) < 4:
                        continue
                    resp_req_id = pdu_items[0][1]
                    if resp_req_id != req_id:
                        continue
                    _, vbs = pdu_items[3]
                    results: List[Tuple[str, int, Any]] = []
                    for _, vb_pair in vbs:
                        if len(vb_pair) == 2:
                            oid_str = vb_pair[0][1]
                            val_tag, val_data = vb_pair[1]
                            results.append((oid_str, val_tag, val_data))
                    return results
                except socket.timeout as e:
                    last_err = e
                except OSError as e:
                    last_err = e
            raise TimeoutError(f"SNMP 连接 {self.host}:{self.port} 超时或无响应 ({last_err})")
        finally:
            sock.close()

    def get(self, oids: List[str]) -> Dict[str, Any]:
        res = self._exchange(PDU_GET, oids)
        out: Dict[str, Any] = {}
        for oid_str, tag, val in res:
            if tag not in (TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE, TAG_END_OF_MIB_VIEW):
                out[oid_str] = val
        return out

    def walk(self, root_oid: str, max_items: int = 600, max_rep: int = 25) -> Dict[str, Any]:
        prefix = root_oid.strip(".") + "."
        current = root_oid.strip(".")
        out: Dict[str, Any] = {}
        guard = 0
        max_guard = max_items + 10 if self._use_getnext_only else 80
        while len(out) < max_items and guard < max_guard:
            guard += 1
            try:
                if self._use_getnext_only:
                    batch = self._exchange(PDU_GETNEXT, [current])
                else:
                    batch = self._exchange(PDU_GETBULK, [current], max_repetitions=max_rep)
            except TimeoutError:
                if not out and not self._use_getnext_only:
                    # Legacy switch might reject GETBULK -> transparently fall back to GETNEXT
                    self._use_getnext_only = True
                    max_guard = max_items + 10
                    continue
                if not out:
                    raise
                break
            if not batch:
                break
            progressed = False
            for oid_str, tag, val in batch:
                if tag == TAG_END_OF_MIB_VIEW:
                    return out
                if not oid_str.startswith(prefix):
                    return out
                if oid_str in out:
                    return out
                if tag not in (TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE):
                    out[oid_str] = val
                current = oid_str
                progressed = True
                if len(out) >= max_items:
                    break
            if not progressed:
                break
        return out


# ==============================================================================
# Vendor-Agnostic Managed Switch Loop & MAC-Flapping Analyzer
# ==============================================================================

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
OID_IF_IN_NUCAST = "1.3.6.1.2.1.2.2.1.12"
OID_IF_IN_DISCARDS = "1.3.6.1.2.1.2.2.1.13"
OID_IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"

OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_IN_MCAST = "1.3.6.1.2.1.31.1.1.1.2"
OID_IF_IN_BCAST = "1.3.6.1.2.1.31.1.1.1.3"
OID_IF_HC_IN_OCTETS = "1.3.6.1.2.1.31.1.1.1.6"
OID_IF_HC_IN_MCAST = "1.3.6.1.2.1.31.1.1.1.8"
OID_IF_HC_IN_BCAST = "1.3.6.1.2.1.31.1.1.1.9"
OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
OID_IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"

OID_DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
OID_DOT1D_STP_TOP_CHANGES = "1.3.6.1.2.1.17.2.4.0"
OID_DOT1D_STP_PORT_STATE = "1.3.6.1.2.1.17.2.15.1.3"
OID_DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
OID_DOT1Q_TP_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"

OID_LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
OID_LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
OID_LLDP_REM_MAN_ADDR = "1.0.8802.1.1.2.1.4.2.1.4"

STP_STATE_MAP = {
    1: "disabled",
    2: "blocking",
    3: "listening",
    4: "learning",
    5: "forwarding",
    6: "broken",
}


def _to_str(val: Any) -> str:
    if isinstance(val, bytes):
        for enc in ("utf-8", "gbk", "latin-1"):
            try:
                return val.decode(enc).strip("\x00 ")
            except UnicodeDecodeError:
                continue
        return val.decode("utf-8", errors="ignore").strip("\x00 ")
    return str(val or "").strip()


def _detect_vendor(sys_descr: str) -> str:
    low = sys_descr.lower()
    if "huawei" in low or "vrp" in low:
        return "Huawei (华为)"
    if "h3c" in low or "comware" in low:
        return "H3C (新华三)"
    if "ruijie" in low or "rgos" in low or "reyee" in low:
        return "Ruijie (锐捷)"
    if "cisco" in low or "ios" in low or "nx-os" in low:
        return "Cisco (思科)"
    if "tp-link" in low or "jetstream" in low:
        return "TP-LINK (网管)"
    if "zte" in low or "zxr10" in low:
        return "ZTE (中兴)"
    if "aruba" in low or "procurve" in low:
        return "Aruba / HPE"
    if "d-link" in low or "dgs-" in low:
        return "D-Link"
    if "mikrotik" in low or "routeros" in low:
        return "MikroTik"
    if "maipu" in low:
        return "Maipu (迈普)"
    if "bdcom" in low:
        return "BDCOM (博达)"
    return "标准网管交换机"


def _suffix_int(oid: str, root: str) -> Optional[int]:
    part = oid[len(root) + 1 :]
    if part.isdigit():
        return int(part)
    return None


def _counter_delta(v1: Optional[int], v2: Optional[int], is_64: bool = False) -> int:
    if v1 is None or v2 is None:
        return 0
    if v2 >= v1:
        return v2 - v1
    modulus = (1 << 64) if is_64 else (1 << 32)
    return (modulus - v1) + v2


def _safe_walk(client: SnmpV2Client, oid: str, max_items: int = 500) -> Dict[str, Any]:
    try:
        return client.walk(oid, max_items=max_items)
    except Exception:
        return {}


def _extract_fdb(client: SnmpV2Client, bp_to_if: Dict[int, int]) -> Dict[str, int]:
    """Return {MAC_STR: ifIndex} combining Q-BRIDGE-MIB and BRIDGE-MIB."""
    mac_to_if: Dict[str, int] = {}

    q_fdb = _safe_walk(client, OID_DOT1Q_TP_FDB_PORT, max_items=800)
    prefix_q = OID_DOT1Q_TP_FDB_PORT + "."
    for oid, bp in q_fdb.items():
        if not isinstance(bp, int) or bp <= 0:
            continue
        parts = oid[len(prefix_q) :].split(".")
        if len(parts) >= 7:
            # format: vlanId.m1.m2.m3.m4.m5.m6
            try:
                mac = ":".join(f"{int(x):02X}" for x in parts[-6:])
                if_idx = bp_to_if.get(bp, bp)
                mac_to_if[mac] = if_idx
            except ValueError:
                continue

    if not mac_to_if:
        b_fdb = _safe_walk(client, OID_DOT1D_TP_FDB_PORT, max_items=800)
        prefix_b = OID_DOT1D_TP_FDB_PORT + "."
        for oid, bp in b_fdb.items():
            if not isinstance(bp, int) or bp <= 0:
                continue
            parts = oid[len(prefix_b) :].split(".")
            if len(parts) == 6:
                try:
                    mac = ":".join(f"{int(x):02X}" for x in parts)
                    if_idx = bp_to_if.get(bp, bp)
                    mac_to_if[mac] = if_idx
                except ValueError:
                    continue

    return mac_to_if


def _extract_lldp_neighbors(client: SnmpV2Client, bp_to_if: Dict[int, int]) -> Dict[int, Dict[str, str]]:
    """Map local ifIndex -> LLDP neighbor info."""
    neighbors: Dict[int, Dict[str, str]] = {}
    rem_sys = _safe_walk(client, OID_LLDP_REM_SYS_NAME, max_items=200)
    rem_port = _safe_walk(client, OID_LLDP_REM_PORT_ID, max_items=200)
    rem_addr = _safe_walk(client, OID_LLDP_REM_MAN_ADDR, max_items=200)

    def _parse_key(oid: str, root: str) -> Optional[Tuple[int, str]]:
        # lldpRemEntry index: timeMark.localPortNum.remIndex
        parts = oid[len(root) + 1 :].split(".")
        if len(parts) >= 3 and parts[1].isdigit():
            local_port = int(parts[1])
            return local_port, f"{parts[0]}.{parts[1]}.{parts[2]}"
        return None

    by_idx: Dict[str, Tuple[int, Dict[str, str]]] = {}
    for oid, val in rem_sys.items():
        k = _parse_key(oid, OID_LLDP_REM_SYS_NAME)
        if k:
            lp, key = k
            by_idx.setdefault(key, (lp, {"remote_sys": "", "remote_port": "", "remote_ip": ""}))
            by_idx[key][1]["remote_sys"] = _to_str(val)

    for oid, val in rem_port.items():
        k = _parse_key(oid, OID_LLDP_REM_PORT_ID)
        if k:
            lp, key = k
            by_idx.setdefault(key, (lp, {"remote_sys": "", "remote_port": "", "remote_ip": ""}))
            if isinstance(val, bytes) and len(val) == 6 and not all(32 <= b < 127 for b in val):
                by_idx[key][1]["remote_port"] = ":".join(f"{b:02X}" for b in val)
            else:
                by_idx[key][1]["remote_port"] = _to_str(val)

    for oid, _ in rem_addr.items():
        # ...timeMark.localPortNum.remIndex.addrSubtype.addrLen.a1.a2.a3.a4
        parts = oid[len(OID_LLDP_REM_MAN_ADDR) + 1 :].split(".")
        if len(parts) >= 9 and parts[3] == "1" and parts[4] == "4":
            key = f"{parts[0]}.{parts[1]}.{parts[2]}"
            ip_str = ".".join(parts[5:9])
            if key in by_idx:
                by_idx[key][1]["remote_ip"] = ip_str

    for lp, info in by_idx.values():
        if_idx = bp_to_if.get(lp, lp)
        if info["remote_sys"] or info["remote_port"]:
            neighbors[if_idx] = info

    return neighbors


def _poll_counters(client: SnmpV2Client) -> Dict[str, Dict[int, int]]:
    def _to_int_map(root: str) -> Dict[int, int]:
        raw = _safe_walk(client, root, max_items=300)
        res: Dict[int, int] = {}
        for oid, val in raw.items():
            idx = _suffix_int(oid, root)
            if idx is not None and isinstance(val, int):
                res[idx] = val
        return res

    hc_bcast = _to_int_map(OID_IF_HC_IN_BCAST)
    bcast32 = {} if hc_bcast else _to_int_map(OID_IF_IN_BCAST)
    nucast = {} if (hc_bcast or bcast32) else _to_int_map(OID_IF_IN_NUCAST)

    hc_mcast = _to_int_map(OID_IF_HC_IN_MCAST)
    mcast32 = {} if hc_mcast else _to_int_map(OID_IF_IN_MCAST)

    hc_oct = _to_int_map(OID_IF_HC_IN_OCTETS)
    oct32 = {} if hc_oct else _to_int_map(OID_IF_IN_OCTETS)

    return {
        "bcast": hc_bcast or bcast32 or nucast,
        "bcast_64": bool(hc_bcast),
        "mcast": hc_mcast or mcast32,
        "mcast_64": bool(hc_mcast),
        "octets": hc_oct or oct32,
        "octets_64": bool(hc_oct),
        "errors": _to_int_map(OID_IF_IN_ERRORS),
        "discards": _to_int_map(OID_IF_IN_DISCARDS),
    }


def _poll_vendor_cpu(client: SnmpV2Client, vendor: str) -> Optional[int]:
    """Best-effort switch CPU % lookup across Huawei/H3C/Ruijie/Cisco (high CPU corroborates storm)."""
    vlow = vendor.lower()
    roots: List[str] = []
    if "huawei" in vlow:
        roots = ["1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5"]
    elif "h3c" in vlow:
        roots = ["1.3.6.1.4.1.25506.2.6.1.1.1.1.6"]
    elif "ruijie" in vlow:
        roots = ["1.3.6.1.4.1.4881.1.1.10.2.36.1.1.2"]
    elif "cisco" in vlow:
        roots = ["1.3.6.1.4.1.9.9.109.1.1.1.1.7", "1.3.6.1.4.1.9.9.109.1.1.1.1.3"]
    for root in roots:
        vals = _safe_walk(client, root, max_items=16)
        nums = [v for v in vals.values() if isinstance(v, int) and 0 <= v <= 100]
        if nums:
            return max(nums)
    return None


def scan_switch_snmp(
    switch_ip: str,
    community: str = "public",
    port: int = 161,
    sample_interval: float = 2.5,
    ledger: Optional[PortLedger] = None,
    simulate: bool = False,
    snmp_version: str = "2c",
) -> Dict[str, Any]:
    """Perform a 2-pass delta SNMP scan on ANY managed switch to locate loops & MAC flapping."""
    active_ledger = ledger or PortLedger()
    if simulate or switch_ip.strip().lower().startswith("sim"):
        return simulate_snmp_switch_scan(switch_ip, active_ledger)

    client = SnmpV2Client(
        host=switch_ip,
        community=community,
        port=port,
        timeout=2.2,
        retries=1,
        version=snmp_version,
    )

    # 1. Basic identity
    sys_info = client.get([OID_SYS_DESCR, OID_SYS_NAME, OID_DOT1D_STP_TOP_CHANGES])
    sys_descr = _to_str(sys_info.get(OID_SYS_DESCR, ""))
    sys_name = _to_str(sys_info.get(OID_SYS_NAME, "")) or switch_ip
    stp_top_changes = sys_info.get(OID_DOT1D_STP_TOP_CHANGES, 0)
    if not isinstance(stp_top_changes, int):
        stp_top_changes = 0
    vendor = _detect_vendor(sys_descr)
    cpu_pct = _poll_vendor_cpu(client, vendor)

    # 2. Interface inventory
    if_names_raw = _safe_walk(client, OID_IF_NAME, max_items=300)
    if_descr_raw = _safe_walk(client, OID_IF_DESCR, max_items=300)
    if_type_raw = _safe_walk(client, OID_IF_TYPE, max_items=300)
    if_oper_raw = _safe_walk(client, OID_IF_OPER_STATUS, max_items=300)
    if_alias_raw = _safe_walk(client, OID_IF_ALIAS, max_items=300)
    if_hspeed_raw = _safe_walk(client, OID_IF_HIGH_SPEED, max_items=300)
    if_speed_raw = _safe_walk(client, OID_IF_SPEED, max_items=300)

    def _map_by_idx(raw: Dict[str, Any], root: str) -> Dict[int, Any]:
        out: Dict[int, Any] = {}
        for oid, val in raw.items():
            idx = _suffix_int(oid, root)
            if idx is not None:
                out[idx] = val
        return out

    if_names = _map_by_idx(if_names_raw, OID_IF_NAME)
    if_descrs = _map_by_idx(if_descr_raw, OID_IF_DESCR)
    if_types = _map_by_idx(if_type_raw, OID_IF_TYPE)
    if_opers = _map_by_idx(if_oper_raw, OID_IF_OPER_STATUS)
    if_aliases = _map_by_idx(if_alias_raw, OID_IF_ALIAS)
    if_hspeeds = _map_by_idx(if_hspeed_raw, OID_IF_HIGH_SPEED)
    if_speeds = _map_by_idx(if_speed_raw, OID_IF_SPEED)

    # Bridge port -> ifIndex mapping
    bp_raw = _safe_walk(client, OID_DOT1D_BASE_PORT_IFINDEX, max_items=300)
    bp_to_if: Dict[int, int] = {}
    for oid, val in bp_raw.items():
        bp = _suffix_int(oid, OID_DOT1D_BASE_PORT_IFINDEX)
        if bp is not None and isinstance(val, int):
            bp_to_if[bp] = val

    # STP port states
    stp_raw = _safe_walk(client, OID_DOT1D_STP_PORT_STATE, max_items=300)
    stp_by_if: Dict[int, str] = {}
    for oid, val in stp_raw.items():
        bp = _suffix_int(oid, OID_DOT1D_STP_PORT_STATE)
        if bp is not None and isinstance(val, int):
            stp_by_if[bp_to_if.get(bp, bp)] = STP_STATE_MAP.get(val, str(val))

    # 3. Sample 1: Counters + FDB
    t1 = time.time()
    c1 = _poll_counters(client)
    fdb1 = _extract_fdb(client, bp_to_if)
    lldp_map = _extract_lldp_neighbors(client, bp_to_if)

    # Wait remaining interval before Sample 2
    elapsed_so_far = time.time() - t1
    if elapsed_so_far < sample_interval:
        time.sleep(sample_interval - elapsed_so_far)

    # 4. Sample 2: Counters + FDB (catches live MAC flapping!)
    t2 = time.time()
    c2 = _poll_counters(client)
    fdb2 = _extract_fdb(client, bp_to_if)
    dt = max(0.5, t2 - t1)

    # Build physical Ethernet port list (ifType == 6 ethernetCsmacd, or looks like physical port)
    all_indices = sorted(set(if_names.keys()) | set(if_descrs.keys()))
    idx_to_name: Dict[int, str] = {}
    phys_indices: List[int] = []
    for idx in all_indices:
        name = _to_str(if_names.get(idx) or if_descrs.get(idx) or f"Port-{idx}")
        idx_to_name[idx] = name
        itype = if_types.get(idx)
        low = name.lower()
        is_logical = any(
            low.startswith(p)
            for p in ("vlan", "null", "loopback", "lo", "meth", "mgmt", "aux", "console", "inloop", "cpu", "stack")
        )
        if (itype == 6 or (itype is None and not is_logical)) and not is_logical:
            phys_indices.append(idx)

    # Live MAC Flapping detection between Snapshot 1 and Snapshot 2
    flaps: List[Dict[str, Any]] = []
    flapping_if_indices = set()
    for mac, if2 in fdb2.items():
        if1 = fdb1.get(mac)
        if if1 is not None and if1 != if2 and if1 in idx_to_name and if2 in idx_to_name:
            flapping_if_indices.add(if1)
            flapping_if_indices.add(if2)
            vinfo = lookup_mac_vendor(mac)
            p1_name = idx_to_name[if1]
            p2_name = idx_to_name[if2]
            flaps.append({
                "mac": mac,
                "vendor": vinfo["vendor"],
                "category": vinfo["category"],
                "from_port": p1_name,
                "to_port": p2_name,
                "from_location": active_ledger.format_location(switch_ip, p1_name),
                "to_location": active_ledger.format_location(switch_ip, p2_name),
            })

    # Per-port learned MAC count
    mac_count_by_if: Dict[int, int] = {}
    mac_table_out: Dict[str, str] = {}
    for mac, if_idx in fdb2.items():
        mac_count_by_if[if_idx] = mac_count_by_if.get(if_idx, 0) + 1
        if if_idx in idx_to_name:
            mac_table_out[mac] = idx_to_name[if_idx]

    # Compute per-port metrics & loop risk score
    ports: List[Dict[str, Any]] = []
    for order_i, idx in enumerate(phys_indices, start=1):
        name = idx_to_name[idx]
        oper = if_opers.get(idx) == 1
        alias = _to_str(if_aliases.get(idx, ""))
        loc = active_ledger.format_location(switch_ip, name)
        speed_mbps = if_hspeeds.get(idx) or int((if_speeds.get(idx) or 0) / 1_000_000)

        b_delta = _counter_delta(c1["bcast"].get(idx), c2["bcast"].get(idx), c1["bcast_64"])
        m_delta = _counter_delta(c1["mcast"].get(idx), c2["mcast"].get(idx), c1["mcast_64"])
        o_delta = _counter_delta(c1["octets"].get(idx), c2["octets"].get(idx), c1["octets_64"])
        e_delta = _counter_delta(c1["errors"].get(idx), c2["errors"].get(idx), False)
        d_delta = _counter_delta(c1["discards"].get(idx), c2["discards"].get(idx), False)

        bcast_pps = round(b_delta / dt, 1)
        mcast_pps = round(m_delta / dt, 1)
        in_mbps = round((o_delta * 8.0 / 1_000_000.0) / dt, 2)
        mac_cnt = mac_count_by_if.get(idx, 0)
        lldp = lldp_map.get(idx)
        stp_state = stp_by_if.get(idx, "forwarding" if oper else "disabled")

        low_alias = (alias + " " + loc).lower()
        is_uplink = any(k in low_alias for k in ("uplink", "上联", "核心", "trunk", "汇聚")) or mac_cnt >= 60

        score = 0
        reasons: List[str] = []
        if bcast_pps >= 1000:
            score += 55
            reasons.append(f"广播风暴 {bcast_pps:.0f} pps")
        elif bcast_pps >= 200:
            score += 25
            reasons.append(f"广播偏高 {bcast_pps:.0f} pps")
        if idx in flapping_if_indices:
            score += 40
            reasons.append("检测到实时 MAC 漂移")
        if d_delta >= 30 or e_delta >= 5:
            score += 15
            reasons.append(f"入向丢包/错包激增 (+{d_delta}/{e_delta})")
        if stp_state in ("blocking", "broken"):
            score += 20
            reasons.append(f"STP 状态异常 ({stp_state})")
        if (not is_uplink) and (not lldp) and mac_cnt >= 8:
            score += 15
            reasons.append(f"单口学习 {mac_cnt} 个 MAC（疑似下挂傻瓜交换机/路由器）")
        if is_uplink and score > 0:
            reasons.append("疑似主干/上联口（注意区分是否为下级传导）")

        score = min(100, score)
        level = "danger" if score >= 65 else ("warning" if score >= 25 else ("up" if oper else "down"))
        short_m = re.search(r"(\d+)$", name)
        short_name = f"P{short_m.group(1)}" if short_m else f"P{order_i}"

        ports.append({
            "if_index": idx,
            "name": name,
            "short_name": short_name,
            "alias": alias,
            "location": loc,
            "oper_status": "up" if oper else "down",
            "speed_mbps": speed_mbps,
            "broadcast_pps": bcast_pps,
            "multicast_pps": mcast_pps,
            "in_mbps": in_mbps,
            "errors_delta": e_delta,
            "discards_delta": d_delta,
            "mac_count": mac_cnt,
            "stp_state": stp_state,
            "lldp_neighbor": lldp,
            "risk_score": score,
            "risk_level": level,
            "reasons": reasons,
            "is_uplink": is_uplink,
        })

    suspects = sorted([p for p in ports if p["risk_score"] > 0], key=lambda x: (-x["risk_score"], -x["broadcast_pps"]))
    if suspects:
        top = suspects[0]
        summary = (
            f"在 {sys_name} ({vendor}) 检测到 {len(suspects)} 个异常端口、{len(flaps)} 条实时 MAC 漂移；"
            f"头号可疑端口为 {top['name']}（{top['location'] or top['alias'] or '未录入台账'}，"
            f"广播 {top['broadcast_pps']:.0f} pps）。"
        )
    else:
        summary = f"已完成 {sys_name} ({vendor}) 全部 {len(ports)} 个物理端口采样，未检测到明显环路或广播风暴。"

    return {
        "simulated": False,
        "scanned_at": time.time(),
        "switch_ip": switch_ip,
        "sys_name": sys_name,
        "sys_desc": sys_descr,
        "vendor": vendor,
        "cpu_pct": cpu_pct,
        "stp_top_changes": stp_top_changes,
        "ports": ports,
        "suspect_ports": suspects[:12],
        "mac_flaps": flaps,
        "mac_table": mac_table_out,
        "summary": summary,
    }


def lookup_mac_in_scan(scan_result: Dict[str, Any], mac_query: str) -> Dict[str, Any]:
    """Find which physical port on the scanned switch learned a given MAC address."""
    norm = normalize_mac(mac_query)
    if not norm:
        return {"found": False, "error": "请输入有效的 MAC 地址（支持冒号/横杠/点分格式）"}
    mac_table = scan_result.get("mac_table") or {}
    port_name = mac_table.get(norm)
    if not port_name:
        # Partial suffix match
        for m, p in mac_table.items():
            if norm.replace(":", "") in m.replace(":", ""):
                norm = m
                port_name = p
                break
    if not port_name:
        return {"found": False, "mac": norm, "message": f"未在 {scan_result.get('sys_name')} 的 MAC 表中查到 {norm}"}

    port_obj = next((p for p in scan_result.get("ports", []) if p["name"] == port_name), None)
    vinfo = lookup_mac_vendor(norm)
    return {
        "found": True,
        "mac": norm,
        "vendor": vinfo["vendor"],
        "category_label": vinfo["category_label"],
        "switch_ip": scan_result.get("switch_ip"),
        "sys_name": scan_result.get("sys_name"),
        "port": port_name,
        "location": port_obj.get("location", "") if port_obj else "",
        "lldp_neighbor": port_obj.get("lldp_neighbor") if port_obj else None,
        "mac_count_on_port": port_obj.get("mac_count", 0) if port_obj else 0,
    }


def batch_scan_switches(
    switches: List[Dict[str, str]],
    ledger: PortLedger,
    sample_interval: float = 2.0,
    simulate: bool = False,
) -> Dict[str, Any]:
    """Concurrently sweep multiple managed switches (e.g. an entire building) to find the hottest loop source."""
    t0 = time.time()
    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []

    def _scan_one(sw: Dict[str, str]) -> Tuple[Dict[str, str], Optional[Dict[str, Any]], Optional[str]]:
        try:
            res = scan_switch_snmp(
                switch_ip=sw["ip"],
                community=sw.get("community") or "public",
                sample_interval=sample_interval,
                ledger=ledger,
                simulate=simulate,
                snmp_version=sw.get("snmp_version") or "2c",
            )
            return sw, res, None
        except Exception as e:
            return sw, None, str(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, max(1, len(switches)))) as pool:
        for sw, res, err in pool.map(_scan_one, switches):
            if res is not None:
                top_port = res["suspect_ports"][0] if res.get("suspect_ports") else None
                results.append({
                    "switch_ip": res["switch_ip"],
                    "sys_name": res["sys_name"],
                    "building": sw.get("building", ""),
                    "role": sw.get("role", ""),
                    "vendor": res["vendor"],
                    "cpu_pct": res.get("cpu_pct"),
                    "flap_count": len(res.get("mac_flaps", [])),
                    "suspect_count": len(res.get("suspect_ports", [])),
                    "max_risk": top_port["risk_score"] if top_port else 0,
                    "max_bcast_pps": top_port["broadcast_pps"] if top_port else 0.0,
                    "top_port": top_port["name"] if top_port else "-",
                    "top_location": (top_port.get("location") or top_port.get("alias") or "") if top_port else "",
                    "full_scan": res,
                })
            else:
                errors.append({"ip": sw["ip"], "name": sw.get("name", sw["ip"]), "error": err or "扫描失败"})

    results.sort(key=lambda x: (-x["max_risk"], -x["flap_count"], -x["max_bcast_pps"]))
    return {
        "ok": True,
        "elapsed_s": round(time.time() - t0, 2),
        "scanned_count": len(results),
        "error_count": len(errors),
        "switches": results,
        "errors": errors,
    }


def trace_loop_hops(
    start_ip: str,
    ledger: PortLedger,
    inventory: Any = None,
    community: str = "public",
    snmp_version: str = "2c",
    target_mac: str = "",
    sample_interval: float = 2.0,
    max_hops: int = 5,
    simulate: bool = False,
) -> Dict[str, Any]:
    """Automatically trace hop-by-hop from core/aggregation switch down to the exact edge access port.

    - If `target_mac` is given: follows the MAC address across LLDP-linked switches until reaching an edge port.
    - Otherwise: follows the highest-risk non-uplink storm port across LLDP-linked switches down to the fault port.
    """
    visited = set()
    hops: List[Dict[str, Any]] = []
    scans_collected: List[Dict[str, Any]] = []
    current_ip = start_ip.strip()
    norm_mac = normalize_mac(target_mac) if target_mac else ""
    stop_reason = ""

    for hop_idx in range(1, max(1, min(8, max_hops)) + 1):
        if not current_ip or current_ip in visited:
            stop_reason = "已避免重复访问相同交换机，追踪结束"
            break
        visited.add(current_ip)

        # Resolve per-switch SNMP community/version from inventory if saved
        inv_item = inventory.get_by_ip(current_ip) if inventory is not None else None
        sw_comm = (inv_item.get("community") if inv_item else None) or community
        sw_ver = (inv_item.get("snmp_version") if inv_item else None) or snmp_version

        try:
            scan = scan_switch_snmp(
                switch_ip=current_ip,
                community=sw_comm,
                sample_interval=sample_interval,
                ledger=ledger,
                simulate=simulate,
                snmp_version=sw_ver,
            )
        except Exception as e:
            stop_reason = f"第 {hop_idx} 跳 ({current_ip}) SNMP 连接失败：{e}"
            break

        scans_collected.append(scan)

        chosen_port: Optional[Dict[str, Any]] = None
        hop_note = ""

        if norm_mac:
            hit = lookup_mac_in_scan(scan, norm_mac)
            if not hit.get("found"):
                hops.append({
                    "hop": hop_idx,
                    "switch_ip": scan["switch_ip"],
                    "sys_name": scan["sys_name"],
                    "vendor": scan["vendor"],
                    "cpu_pct": scan.get("cpu_pct"),
                    "port": "-",
                    "location": "",
                    "broadcast_pps": 0,
                    "risk_score": 0,
                    "note": f"未在该交换机查到 MAC {norm_mac}",
                    "next_ip": "",
                })
                stop_reason = f"在 {scan['sys_name']} 未找到目标 MAC {norm_mac}"
                break
            chosen_port = next((p for p in scan["ports"] if p["name"] == hit["port"]), None)
            hop_note = f"MAC {norm_mac} ({hit['vendor']}) 由此口学出"
        else:
            # Prefer non-uplink suspect ports first; fallback to highest suspect
            non_uplinks = [p for p in scan.get("suspect_ports", []) if not p.get("is_uplink")]
            pool = non_uplinks or scan.get("suspect_ports", [])
            if not pool:
                hops.append({
                    "hop": hop_idx,
                    "switch_ip": scan["switch_ip"],
                    "sys_name": scan["sys_name"],
                    "vendor": scan["vendor"],
                    "cpu_pct": scan.get("cpu_pct"),
                    "port": "-",
                    "location": "",
                    "broadcast_pps": 0,
                    "risk_score": 0,
                    "note": "该交换机未发现高危异常端口",
                    "next_ip": "",
                })
                stop_reason = f"追踪到 {scan['sys_name']} 时未发现异常端口"
                break
            chosen_port = pool[0]
            hop_note = "；".join(chosen_port.get("reasons") or ["高危广播端口"])

        lldp = chosen_port.get("lldp_neighbor") if chosen_port else None
        next_ip = (lldp.get("remote_ip") or "").strip() if lldp else ""
        # Avoid bouncing back upward to an already-visited upstream switch
        if next_ip in visited:
            next_ip = ""

        hops.append({
            "hop": hop_idx,
            "switch_ip": scan["switch_ip"],
            "sys_name": scan["sys_name"],
            "vendor": scan["vendor"],
            "cpu_pct": scan.get("cpu_pct"),
            "port": chosen_port["name"] if chosen_port else "-",
            "location": (chosen_port.get("location") or chosen_port.get("alias") or "") if chosen_port else "",
            "broadcast_pps": chosen_port.get("broadcast_pps", 0) if chosen_port else 0,
            "risk_score": chosen_port.get("risk_score", 0) if chosen_port else 0,
            "mac_count": chosen_port.get("mac_count", 0) if chosen_port else 0,
            "lldp_remote": f"{lldp['remote_sys']} ({lldp['remote_port']})" if lldp else "",
            "note": hop_note,
            "next_ip": next_ip,
        })

        if not next_ip:
            loc = hops[-1]["location"] or "未录入台账（边缘终端/教研室墙面信息点）"
            stop_reason = f"已定位到最末端接入端口：{scan['sys_name']} 的 {hops[-1]['port']}（📍 {loc}）！"
            break
        current_ip = next_ip

    return {
        "ok": True,
        "mode": "mac" if norm_mac else "storm",
        "target_mac": norm_mac,
        "hops": hops,
        "stop_reason": stop_reason,
        "scans": scans_collected,
    }
