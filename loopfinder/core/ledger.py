"""Campus Switch-Port <-> Building/Office/Wall-Jack Ledger Manager.

Normalizes multi-vendor port names (e.g. GigabitEthernet0/0/14, GE0/0/14, Gi0/0/14)
so SNMP, LLDP, and SSH outputs automatically map to exact school rooms & wall jacks.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from typing import Dict, List, Optional


_PORT_PREFIX_RE = re.compile(
    r"^(ten-?gigabitethernet|tengigabitethernet|xgigabitethernet|xge|te|"
    r"gigabitethernet|gigabit|ge|gi|"
    r"fastethernet|fa|fe|"
    r"ethernet|eth|"
    r"25ge|40ge|100ge|port|po|eth-trunk|bridge-aggregation)\s*",
    re.IGNORECASE,
)


def normalize_port_name(port: str) -> str:
    """Normalize port names across Huawei/H3C/Ruijie/Cisco/TP-Link for fuzzy matching."""
    if not port:
        return ""
    p = port.strip()
    m = _PORT_PREFIX_RE.match(p)
    if not m:
        return p.lower()
    prefix = m.group(1).lower()
    rest = p[m.end() :].strip()
    if prefix in ("gigabitethernet", "gigabit", "ge", "gi"):
        canon = "ge"
    elif prefix in ("ten-gigabitethernet", "tengigabitethernet", "xgigabitethernet", "xge", "te"):
        canon = "xge"
    elif prefix in ("fastethernet", "fa", "fe"):
        canon = "fe"
    elif prefix in ("ethernet", "eth"):
        canon = "eth"
    else:
        canon = prefix
    return f"{canon}{rest}".lower()


class PortLedger:
    """Persistent CSV/JSON ledger mapping (switch_ip, port) to campus physical location."""

    def __init__(self, storage_path: Optional[str] = None) -> None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.sample_csv = os.path.join(base_dir, "data", "sample_ledger.csv")
        self.storage_path = storage_path or os.path.join(base_dir, "data", "campus_ledger.json")
        self.entries: List[Dict[str, str]] = []
        self._index: Dict[str, Dict[str, str]] = {}
        self.load()

    def _rebuild_index(self) -> None:
        self._index = {}
        for item in self.entries:
            sw = (item.get("switch_ip") or "").strip()
            port = normalize_port_name(item.get("port") or "")
            if sw and port:
                self._index[f"{sw}|{port}"] = item
            # Also index by port-only numeric suffix for relaxed matching on same switch
            num_m = re.search(r"(\d+/\d+(?:/\d+)?)$", item.get("port") or "")
            if sw and num_m:
                self._index.setdefault(f"{sw}|num:{num_m.group(1)}", item)

    def load(self) -> None:
        if os.path.isfile(self.storage_path):
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    self.entries = data
                    self._rebuild_index()
                    return
            except Exception:
                pass
        # Seed from sample CSV on first launch
        if os.path.isfile(self.sample_csv):
            try:
                with open(self.sample_csv, "r", encoding="utf-8") as f:
                    self.import_csv_text(f.read(), replace=True, persist=False)
            except Exception:
                self.entries = []
                self._rebuild_index()

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump(self.entries, f, ensure_ascii=False, indent=2)

    def list_entries(self) -> List[Dict[str, str]]:
        return list(self.entries)

    def upsert(self, entry: Dict[str, str]) -> List[Dict[str, str]]:
        sw = (entry.get("switch_ip") or "").strip()
        port = (entry.get("port") or "").strip()
        if not sw or not port:
            raise ValueError("交换机 IP 和端口名不能为空")
        clean = {
            "switch_ip": sw,
            "port": port,
            "building": (entry.get("building") or "").strip(),
            "room": (entry.get("room") or "").strip(),
            "wall_jack": (entry.get("wall_jack") or "").strip(),
            "note": (entry.get("note") or "").strip(),
        }
        norm_key = f"{sw}|{normalize_port_name(port)}"
        replaced = False
        for i, existing in enumerate(self.entries):
            if f"{existing.get('switch_ip','').strip()}|{normalize_port_name(existing.get('port',''))}" == norm_key:
                self.entries[i] = clean
                replaced = True
                break
        if not replaced:
            self.entries.append(clean)
        self._rebuild_index()
        self.save()
        return self.list_entries()

    def delete(self, switch_ip: str, port: str) -> List[Dict[str, str]]:
        norm_key = f"{switch_ip.strip()}|{normalize_port_name(port)}"
        self.entries = [
            e
            for e in self.entries
            if f"{e.get('switch_ip','').strip()}|{normalize_port_name(e.get('port',''))}" != norm_key
        ]
        self._rebuild_index()
        self.save()
        return self.list_entries()

    def import_csv_text(self, csv_text: str, replace: bool = False, persist: bool = True) -> int:
        reader = csv.DictReader(io.StringIO(csv_text.lstrip("\ufeff")))
        imported: List[Dict[str, str]] = []
        for row in reader:
            sw = (row.get("switch_ip") or row.get("交换机IP") or "").strip()
            port = (row.get("port") or row.get("端口") or "").strip()
            if not sw or not port:
                continue
            imported.append({
                "switch_ip": sw,
                "port": port,
                "building": (row.get("building") or row.get("楼栋") or "").strip(),
                "room": (row.get("room") or row.get("教研室") or row.get("房间") or "").strip(),
                "wall_jack": (row.get("wall_jack") or row.get("面板编号") or "").strip(),
                "note": (row.get("note") or row.get("备注") or "").strip(),
            })
        if replace:
            self.entries = imported
        else:
            existing_map = {
                f"{e['switch_ip']}|{normalize_port_name(e['port'])}": e for e in self.entries
            }
            for item in imported:
                existing_map[f"{item['switch_ip']}|{normalize_port_name(item['port'])}"] = item
            self.entries = list(existing_map.values())
        self._rebuild_index()
        if persist:
            self.save()
        return len(imported)

    def export_csv_text(self) -> str:
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=["switch_ip", "port", "building", "room", "wall_jack", "note"],
        )
        writer.writeheader()
        for row in self.entries:
            writer.writerow(row)
        return buf.getvalue()

    def lookup(self, switch_ip: str, port_name: str) -> Optional[Dict[str, str]]:
        if not switch_ip or not port_name:
            return None
        sw = switch_ip.strip()
        norm = normalize_port_name(port_name)
        hit = self._index.get(f"{sw}|{norm}")
        if hit:
            return hit
        num_m = re.search(r"(\d+/\d+(?:/\d+)?)$", port_name)
        if num_m:
            return self._index.get(f"{sw}|num:{num_m.group(1)}")
        return None

    def format_location(self, switch_ip: str, port_name: str) -> str:
        hit = self.lookup(switch_ip, port_name)
        if not hit:
            return ""
        parts = [p for p in (hit.get("building"), hit.get("room"), hit.get("wall_jack")) if p]
        return " · ".join(parts)
