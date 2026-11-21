"""Campus Managed Switch Inventory Manager (weak-current room aggregation & access switches).

Stores per-switch IP, vendor, building, SNMP version/community, and role so
engineers can run one-click concurrent sweeps across an entire teaching building
even when switch brands and SNMP communities are mixed.
"""

from __future__ import annotations

import csv
import io
import json
import os
from typing import Dict, List, Optional

from loopfinder.core.paths import atomic_write_text, default_data_file


DEFAULT_SAMPLE_SWITCHES: List[Dict[str, str]] = [
    {
        "ip": "10.10.0.1",
        "name": "CORE-Campus-S12700",
        "building": "网络中心机房",
        "role": "核心交换机",
        "vendor": "huawei",
        "community": "public",
        "snmp_version": "2c",
        "note": "全校主核心（示例）",
    },
    {
        "ip": "10.10.1.1",
        "name": "H3C-3F-Agg-SW01",
        "building": "第一教学楼",
        "role": "弱电间汇聚",
        "vendor": "h3c",
        "community": "public",
        "snmp_version": "2c",
        "note": "第一教学楼三楼弱电间汇聚（示例）",
    },
    {
        "ip": "10.10.2.12",
        "name": "HW-3F-East-SW02",
        "building": "第一教学楼",
        "role": "楼层接入",
        "vendor": "huawei",
        "community": "public",
        "snmp_version": "2c",
        "note": "302/305大教研室接入交换机（示例）",
    },
    {
        "ip": "10.10.2.13",
        "name": "RJ-3F-West-SW03",
        "building": "第一教学楼",
        "role": "楼层接入",
        "vendor": "ruijie",
        "community": "public",
        "snmp_version": "2c",
        "note": "308/310教研室锐捷接入（示例）",
    },
]


class SwitchInventory:
    """Persistent JSON/CSV inventory of campus managed switches."""

    def __init__(self, storage_path: Optional[str] = None) -> None:
        self.storage_path = storage_path or default_data_file("campus_switches.json")
        self.switches: List[Dict[str, str]] = []
        self.load()

    def load(self) -> None:
        if os.path.isfile(self.storage_path):
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    self.switches = data
                    return
            except Exception:
                pass
        self.switches = [dict(x) for x in DEFAULT_SAMPLE_SWITCHES]

    def save(self) -> None:
        atomic_write_text(self.storage_path, json.dumps(self.switches, ensure_ascii=False, indent=2))

    def list_switches(self, building: str = "") -> List[Dict[str, str]]:
        if not building:
            return list(self.switches)
        b = building.strip()
        return [s for s in self.switches if s.get("building", "").strip() == b]

    def get_by_ip(self, ip: str) -> Optional[Dict[str, str]]:
        target = ip.strip()
        return next((s for s in self.switches if s.get("ip", "").strip() == target), None)

    def upsert(self, item: Dict[str, str]) -> List[Dict[str, str]]:
        ip = (item.get("ip") or "").strip()
        if not ip:
            raise ValueError("交换机 IP 不能为空")
        clean = {
            "ip": ip,
            "name": (item.get("name") or ip).strip(),
            "building": (item.get("building") or "未分组").strip(),
            "role": (item.get("role") or "楼层接入").strip(),
            "vendor": (item.get("vendor") or "auto").strip().lower(),
            "community": (item.get("community") or "public").strip(),
            "snmp_version": (item.get("snmp_version") or "2c").strip().lower(),
            "note": (item.get("note") or "").strip(),
        }
        replaced = False
        for i, existing in enumerate(self.switches):
            if existing.get("ip", "").strip() == ip:
                self.switches[i] = clean
                replaced = True
                break
        if not replaced:
            self.switches.append(clean)
        self.save()
        return self.list_switches()

    def delete(self, ip: str) -> List[Dict[str, str]]:
        target = ip.strip()
        self.switches = [s for s in self.switches if s.get("ip", "").strip() != target]
        self.save()
        return self.list_switches()

    def import_csv_text(self, csv_text: str, replace: bool = False) -> int:
        reader = csv.DictReader(io.StringIO(csv_text.lstrip("\ufeff")))
        imported: List[Dict[str, str]] = []
        for row in reader:
            ip = (row.get("ip") or row.get("交换机IP") or "").strip()
            if not ip:
                continue
            imported.append({
                "ip": ip,
                "name": (row.get("name") or row.get("设备名") or ip).strip(),
                "building": (row.get("building") or row.get("楼栋") or "未分组").strip(),
                "role": (row.get("role") or row.get("角色") or "楼层接入").strip(),
                "vendor": (row.get("vendor") or row.get("品牌") or "auto").strip().lower(),
                "community": (row.get("community") or row.get("团体名") or "public").strip(),
                "snmp_version": (row.get("snmp_version") or "2c").strip().lower(),
                "note": (row.get("note") or row.get("备注") or "").strip(),
            })
        if replace:
            self.switches = imported
        else:
            by_ip = {s["ip"]: s for s in self.switches}
            for item in imported:
                by_ip[item["ip"]] = item
            self.switches = list(by_ip.values())
        self.save()
        return len(imported)

    def export_csv_text(self) -> str:
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=["ip", "name", "building", "role", "vendor", "community", "snmp_version", "note"],
        )
        writer.writeheader()
        for row in self.switches:
            writer.writerow(row)
        return buf.getvalue()
