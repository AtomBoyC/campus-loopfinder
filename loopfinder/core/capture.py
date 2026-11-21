"""Unified L2 Field Diagnostics Engine: Passive Storm/Duplicate Sniffer, Active Loop Probe,
LLDP/CDP Switch Discovery, STP Monitor, and Rogue DHCP Router Detector.

Supports three backends seamlessly:
1. mac_bpf   - Native zero-dependency macOS /dev/bpf* (with BIOCSSEESENT=0)
2. scapy     - Cross-platform Windows (Npcap) / macOS / Linux via scapy
3. simulation - Built-in campus classroom loop simulator for safe testing & training
"""

from __future__ import annotations

import collections
import platform
import random
import threading
import time
from typing import Any, Deque, Dict, List, Optional, Tuple

from loopfinder.core.interfaces import check_capabilities, list_interfaces
from loopfinder.core.ledger import PortLedger
from loopfinder.core.packet_parser import (
    build_dhcp_discover_frame,
    build_loop_probe_frame,
    parse_ethernet_frame,
)
from loopfinder.core.pcap_writer import build_pcap_bytes
from loopfinder.core.rogue_router import probe_router_web
from loopfinder.core.simulator import ClassroomSimulator
from loopfinder.data.oui_vendors import lookup_mac_vendor, normalize_mac


SENSITIVITY_PRESETS: Dict[str, Dict[str, Any]] = {
    "strict": {
        "label": "高灵敏（小型办公室）",
        "bcast_high": 200,
        "bcast_warn": 60,
        "dup_high": 40,
        "dup_warn": 10,
        "arp_high": 80,
    },
    "standard": {
        "label": "标准（大教研室推荐）",
        "bcast_high": 500,
        "bcast_warn": 150,
        "dup_high": 100,
        "dup_warn": 25,
        "arp_high": 200,
    },
    "noisy_vlan": {
        "label": "抗干扰（大型机房/广播域）",
        "bcast_high": 1200,
        "bcast_warn": 400,
        "dup_high": 220,
        "dup_warn": 60,
        "arp_high": 450,
    },
}

_SOHO_GATEWAY_IPS = {
    "192.168.0.1", "192.168.1.1", "192.168.2.1", "192.168.3.1",
    "192.168.10.1", "192.168.31.1", "192.168.50.1", "192.168.100.1",
    "192.168.124.1", "192.168.199.1", "10.0.0.1",
}


class CaptureController:
    """Thread-safe controller for live L2 loop & rogue router diagnostics."""

    def __init__(self, ledger: PortLedger) -> None:
        self.ledger = ledger
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._probe_thread: Optional[threading.Thread] = None

        self.running: bool = False
        self.backend: str = "idle"
        self.interface: str = ""
        self.interface_mac: str = ""
        self.probe_mode: str = "active"  # "passive" | "active"
        self.last_error: str = ""

        # Active probe session state
        self._session_id: int = random.randint(100000, 999999999)
        self._probe_mac: str = f"02:4C:4F:4F:50:{random.randint(1, 254):02X}"
        self._probe_seq: int = 0
        self._probe_sent_times: Dict[int, float] = {}
        self._probe_echo_counts: Dict[int, int] = {}
        self._probe_echo_total: int = 0
        self._probe_echo_recent: int = 0
        self._probe_last_rtt_ms: Optional[float] = None
        self._probe_paused_by_safety: bool = False
        self._expect_tx_self_echo: bool = False

        # Trusted DHCP server whitelist (editable from UI)
        self.trusted_dhcp_ips: List[str] = ["10.10.1.1"]
        self.sensitivity: str = "standard"

        # Rolling PCAP ring buffer for one-click Wireshark export
        self._pcap_ring: Deque[Tuple[float, bytes]] = collections.deque(maxlen=3000)
        self._last_frame_ts: float = 0.0

        # Passive ARP IP/Gateway conflict tracking: ip -> {mac: last_ts}
        self._arp_ip_macs: Dict[str, Dict[str, float]] = {}
        self._arp_conflicts: Dict[str, Dict[str, Any]] = {}

        # Rolling window counters (updated every tick, aggregated per second)
        self._cur_sec_start: float = time.time()
        self._sec_total: int = 0
        self._sec_broadcast: int = 0
        self._sec_multicast: int = 0
        self._sec_arp: int = 0
        self._sec_dup: int = 0
        self._sec_bytes: int = 0
        self._sec_stp_tc: int = 0
        self._sec_probe_echo: int = 0

        # Short-window duplicate signature cache: sig -> (last_ts, repeat_count, sample_info)
        self._sig_window: Dict[bytes, Tuple[float, int, Dict[str, Any]]] = {}
        self._dup_clusters: Dict[bytes, Dict[str, Any]] = {}

        # Talker stats (reset periodically / on clear)
        self._talkers: Dict[str, Dict[str, Any]] = {}

        # 60-second history for live charts (0.5s buckets -> 120 samples)
        self._history: Deque[Dict[str, Any]] = collections.deque(maxlen=120)

        # Upstream switch (LLDP / CDP) & STP Root
        self.upstream_switch: Optional[Dict[str, Any]] = None
        self.stp_info: Optional[Dict[str, Any]] = None
        self._stp_tc_total: int = 0

        # Rogue / All DHCP servers observed
        self._dhcp_servers: Dict[str, Dict[str, Any]] = {}
        self._web_probed_ips: set = set()

        # Event timeline
        self._events: Deque[Dict[str, Any]] = collections.deque(maxlen=80)

        # Live status & bisection recovery detector
        self._status: str = "IDLE"
        self._prev_status: str = "IDLE"
        self._loop_confidence: int = 0
        self._reasons: List[str] = []
        self._recovery_flash_ts: float = 0.0
        self._peak_broadcast_pps: float = 0.0
        self._started_at: float = 0.0

        # Active raw sender callback (set by backend)
        self._send_raw_fn = None

        # Simulation state
        self._simulator = ClassroomSimulator()

    def _log_event(self, level: str, message: str) -> None:
        self._events.appendleft({
            "ts": time.time(),
            "time_str": time.strftime("%H:%M:%S"),
            "level": level,  # info | warn | danger | success
            "message": message,
        })

    def reset_metrics(self) -> None:
        with self._lock:
            self._cur_sec_start = time.time()
            self._sec_total = 0
            self._sec_broadcast = 0
            self._sec_multicast = 0
            self._sec_arp = 0
            self._sec_dup = 0
            self._sec_bytes = 0
            self._sec_stp_tc = 0
            self._sec_probe_echo = 0
            self._sig_window.clear()
            self._dup_clusters.clear()
            self._talkers.clear()
            self._history.clear()
            self._dhcp_servers.clear()
            self._web_probed_ips.clear()
            self._pcap_ring.clear()
            self._arp_ip_macs.clear()
            self._arp_conflicts.clear()
            self._last_frame_ts = 0.0
            self._probe_seq = 0
            self._probe_sent_times.clear()
            self._probe_echo_counts.clear()
            self._probe_echo_total = 0
            self._probe_echo_recent = 0
            self._probe_last_rtt_ms = None
            self._probe_paused_by_safety = False
            self._stp_tc_total = 0
            self._peak_broadcast_pps = 0.0
            self._recovery_flash_ts = 0.0
            self.upstream_switch = None
            self.stp_info = None
            self._loop_confidence = 0
            self._reasons = []

    def set_trusted_dhcp(self, ips: List[str]) -> None:
        with self._lock:
            self.trusted_dhcp_ips = [ip.strip() for ip in ips if ip.strip()]
            for srv in self._dhcp_servers.values():
                srv["is_rogue"] = srv["server_ip"] not in self.trusted_dhcp_ips

    def set_sensitivity(self, preset: str) -> str:
        with self._lock:
            if preset in SENSITIVITY_PRESETS:
                self.sensitivity = preset
                self._log_event("info", f"已切换告警灵敏度：{SENSITIVITY_PRESETS[preset]['label']}")
            return self.sensitivity

    def export_pcap_bytes(self) -> bytes:
        with self._lock:
            frames = list(self._pcap_ring)
        return build_pcap_bytes(frames)

    def start(self, interface: str, mode: str = "active", backend: str = "auto") -> Dict[str, Any]:
        self.stop()
        caps = check_capabilities()
        ifaces = list_interfaces()
        iface_obj = next((i for i in ifaces if i["name"] == interface), None)

        chosen_backend = backend
        if chosen_backend == "auto":
            if interface == "__SIMULATION__":
                chosen_backend = "simulation"
            elif caps["can_live_capture"]:
                chosen_backend = caps["preferred_backend"]
            else:
                return {
                    "ok": False,
                    "error": caps["hint"],
                    "suggest_simulation": True,
                }

        with self._lock:
            self.reset_metrics()
            self._stop_event.clear()
            self.last_error = ""
            self.interface = interface if chosen_backend != "simulation" else "模拟教研室有线网卡 (SIM-en0)"
            self.interface_mac = (
                (iface_obj["mac"] if iface_obj and iface_obj.get("mac") else "")
                or f"02:11:22:33:44:55"
            )
            self.probe_mode = mode if mode in ("passive", "active") else "active"
            self.backend = chosen_backend
            self.running = True
            self._started_at = time.time()
            self._status = "NORMAL"
            self._prev_status = "NORMAL"
            self._session_id = random.randint(100000, 999999999)
            self._expect_tx_self_echo = chosen_backend == "scapy"

        if chosen_backend == "simulation":
            self._simulator = ClassroomSimulator()
            self._log_event("info", "已启动「仿真演练模式」：模拟 302 大教研室路由器二层环路 + 私接 TP-LINK 路由器场景")
            self._worker_thread = threading.Thread(target=self._run_simulation_loop, daemon=True)
        elif chosen_backend == "mac_bpf":
            self._log_event("info", f"已启动 macOS 原生 BPF 抓包引擎（网卡: {interface}，模式: {'主动探针+被动' if mode=='active' else '纯被动只读'}）")
            self._worker_thread = threading.Thread(
                target=self._run_mac_bpf_loop, args=(interface,), daemon=True
            )
        elif chosen_backend == "scapy":
            scapy_iface = (iface_obj.get("scapy_name") if iface_obj else None) or interface
            self._log_event("info", f"已启动 Scapy 二层抓包引擎（网卡: {interface}，模式: {'主动探针+被动' if mode=='active' else '纯被动只读'}）")
            self._worker_thread = threading.Thread(
                target=self._run_scapy_loop, args=(scapy_iface,), daemon=True
            )
        else:
            self.running = False
            return {"ok": False, "error": f"不支持的后端: {chosen_backend}"}

        self._worker_thread.start()
        if self.probe_mode == "active":
            self._probe_thread = threading.Thread(target=self._run_active_probe_loop, daemon=True)
            self._probe_thread.start()

        return {"ok": True, "backend": chosen_backend, "interface": self.interface}

    def stop(self) -> None:
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.5)
        if self._probe_thread and self._probe_thread.is_alive():
            self._probe_thread.join(timeout=1.0)
        with self._lock:
            self.running = False
            self._send_raw_fn = None
            if self._status != "IDLE":
                self._status = "IDLE"
                self._log_event("info", "监测已停止")

    def set_simulation_state(self, loop_active: Optional[bool] = None, rogue_dhcp_active: Optional[bool] = None) -> Dict[str, Any]:
        with self._lock:
            if loop_active is not None:
                self._simulator.loop_active = bool(loop_active)
                if not loop_active:
                    self._log_event("success", "【仿真操作】已拔掉故障支线，观察广播风暴与探针回环消退情况...")
                else:
                    self._log_event("danger", "【仿真操作】已重新接通环路网线，广播风暴与探针回环重新爆发！")
            if rogue_dhcp_active is not None:
                self._simulator.rogue_dhcp_active = bool(rogue_dhcp_active)
                if not rogue_dhcp_active:
                    self._log_event("info", "【仿真操作】已断开私接 TP-LINK 路由器电源")
            return {
                "loop_active": self._simulator.loop_active,
                "rogue_dhcp_active": self._simulator.rogue_dhcp_active,
            }

    def trigger_dhcp_scan(self) -> Dict[str, Any]:
        """Broadcast a DHCPDISCOVER frame on the active interface to uncover rogue routers."""
        with self._lock:
            if not self.running:
                return {"ok": False, "error": "请先开始监测网卡（或启动仿真演练模式）后再发起私接路由器扫描。"}
            if self.backend == "simulation":
                self._simulator._tick = 1  # Force immediate offer batch on next tick
                self._log_event("info", "已发送 DHCPDISCOVER 探测广播，正在监听所有响应的路由器...")
                return {"ok": True, "message": "已发送模拟 DHCP 探测包"}
            send_fn = self._send_raw_fn
            mac = self.interface_mac or self._probe_mac

        if send_fn is None:
            return {"ok": False, "error": "当前抓包引擎尚未就绪，无法发送二层探测帧。"}

        try:
            xid = random.randint(1, 0xFFFFFFFF)
            frame = build_dhcp_discover_frame(mac, xid)
            send_fn(frame)
            with self._lock:
                self._log_event("info", f"已广播 DHCPDISCOVER (xid=0x{xid:08X})，正在捕获局域网内所有 DHCP 响应...")
            return {"ok": True, "message": "已发送 DHCPDISCOVER 广播探测"}
        except Exception as e:
            return {"ok": False, "error": f"发送 DHCP 探测包失败: {e}"}

    def send_single_probe(self) -> Dict[str, Any]:
        """Manually send one active L2 loop probe frame right now."""
        with self._lock:
            if not self.running:
                return {"ok": False, "error": "请先启动监测。"}
            self._probe_seq += 1
            seq = self._probe_seq
            self._probe_sent_times[seq] = time.time()
            self._probe_echo_counts[seq] = 0
            send_fn = self._send_raw_fn
            is_sim = self.backend == "simulation"
            frame = build_loop_probe_frame(self._probe_mac, self._session_id, seq)

        if is_sim:
            with self._lock:
                self._log_event("info", f"手动发送主动二层环路探针 Seq #{seq}")
            return {"ok": True, "seq": seq}
        if send_fn is None:
            return {"ok": False, "error": "当前模式不支持发包。"}
        try:
            send_fn(frame)
            with self._lock:
                self._log_event("info", f"已发送主动二层环路探针 Seq #{seq} (EtherType 0x88B5)")
            return {"ok": True, "seq": seq}
        except Exception as e:
            return {"ok": False, "error": f"发包失败: {e}"}

    def _run_active_probe_loop(self) -> None:
        while not self._stop_event.wait(1.5):
            with self._lock:
                if not self.running or self.probe_mode != "active":
                    continue
                # Safety brake: don't inject frames into an already severe broadcast storm
                last_bcast = self._history[-1]["broadcast_pps"] if self._history else 0
                if last_bcast > 400:
                    if not self._probe_paused_by_safety:
                        self._probe_paused_by_safety = True
                        self._log_event("warn", "安全保护触发：当前广播风暴已超过 400 pps，自动暂停主动发包，切为纯被动听诊避免加剧拥塞。")
                    continue
                self._probe_paused_by_safety = False
                self._probe_seq += 1
                seq = self._probe_seq
                self._probe_sent_times[seq] = time.time()
                self._probe_echo_counts[seq] = 0
                # Trim old probe records
                if len(self._probe_sent_times) > 40:
                    oldest = min(self._probe_sent_times.keys())
                    self._probe_sent_times.pop(oldest, None)
                    self._probe_echo_counts.pop(oldest, None)
                send_fn = self._send_raw_fn
                is_sim = self.backend == "simulation"
                frame = build_loop_probe_frame(self._probe_mac, self._session_id, seq)

            if not is_sim and send_fn is not None:
                try:
                    send_fn(frame)
                except Exception:
                    pass

    def _run_simulation_loop(self) -> None:
        while not self._stop_event.is_set():
            t0 = time.time()
            with self._lock:
                seq = self._probe_seq
                sid = self._session_id
                pmac = self._probe_mac
            frames = self._simulator.generate_batch(sid, seq, pmac)
            for raw in frames:
                self._ingest_raw_frame(raw, time.time())
            self._maybe_roll_second()
            elapsed = time.time() - t0
            self._stop_event.wait(max(0.05, 0.2 - elapsed))

    def _run_mac_bpf_loop(self, interface: str) -> None:
        from loopfinder.core.mac_bpf import MacBPFSocket

        bpf = None
        try:
            bpf = MacBPFSocket(interface=interface, promisc=True, see_sent=False)
            with self._lock:
                self._send_raw_fn = bpf.send_frame
            while not self._stop_event.is_set():
                for ts, raw in bpf.read_frames(timeout=0.25):
                    if self._stop_event.is_set():
                        break
                    self._ingest_raw_frame(raw, ts)
                self._maybe_roll_second()
        except Exception as e:
            with self._lock:
                self.last_error = str(e)
                self.running = False
                self._status = "IDLE"
                self._log_event("danger", f"BPF 抓包异常: {e}")
        finally:
            with self._lock:
                self._send_raw_fn = None
            if bpf is not None:
                bpf.close()

    def _run_scapy_loop(self, scapy_iface: str) -> None:
        try:
            from scapy.all import conf, sendp  # type: ignore

            l2sock = conf.L2socket(iface=scapy_iface)
            with self._lock:
                self._send_raw_fn = lambda raw: l2sock.send(raw)

            # Use non-blocking select/recv loop on L2socket so stop_event reacts fast
            sock = l2sock.ins
            sock.settimeout(0.25)
            while not self._stop_event.is_set():
                try:
                    pkt = l2sock.recv_raw()
                    if pkt and pkt[1]:
                        raw = bytes(pkt[1])
                        self._ingest_raw_frame(raw, time.time())
                except Exception:
                    pass
                self._maybe_roll_second()
        except Exception as e:
            # Fallback to scapy sniff() if L2socket differs on Windows Npcap
            try:
                from scapy.all import sendp, sniff  # type: ignore

                with self._lock:
                    self._send_raw_fn = lambda raw: sendp(raw, iface=scapy_iface, verbose=False)

                while not self._stop_event.is_set():
                    sniff(
                        iface=scapy_iface,
                        prn=lambda p: self._ingest_raw_frame(bytes(p), float(getattr(p, "time", time.time()))),
                        store=False,
                        timeout=0.4,
                        stop_filter=lambda _: self._stop_event.is_set(),
                    )
                    self._maybe_roll_second()
            except Exception as e2:
                with self._lock:
                    self.last_error = f"{e} / {e2}"
                    self.running = False
                    self._status = "IDLE"
                    self._log_event("danger", f"Scapy 抓包异常: {e2}")
        finally:
            with self._lock:
                self._send_raw_fn = None

    def _probe_rogue_http_async(self, ip: str, is_sim: bool) -> None:
        def worker() -> None:
            if is_sim and ip == "192.168.1.1":
                res = {
                    "title": "TP-LINK 无线路由器 TL-WR886N",
                    "server": "Router Webserver",
                    "model_hint": "TP-LINK (TL-WR886N)",
                    "port": "80",
                }
            else:
                res = probe_router_web(ip, timeout=1.5)
            with self._lock:
                srv = self._dhcp_servers.get(ip)
                if srv:
                    srv["web_title"] = res.get("title") or ""
                    srv["model_hint"] = res.get("model_hint") or ""
                    srv["web_port"] = res.get("port") or ""

        threading.Thread(target=worker, daemon=True).start()

    def _ingest_raw_frame(self, raw: bytes, ts: float) -> None:
        pkt = parse_ethernet_frame(raw, ts)
        if pkt is None:
            return

        with self._lock:
            self._last_frame_ts = ts
            self._pcap_ring.append((ts, raw))
            self._sec_total += 1
            self._sec_bytes += pkt["length"]
            if pkt["is_broadcast"]:
                self._sec_broadcast += 1
            elif pkt["is_multicast"]:
                self._sec_multicast += 1
            if pkt["proto"] == "ARP":
                self._sec_arp += 1
                if pkt["arp"]:
                    self._track_arp_anomalies(pkt["arp"], ts)

            # 1. Active L2 Loop Probe echo check
            if pkt["probe"] is not None:
                pinfo = pkt["probe"]
                if pinfo["session_id"] == self._session_id:
                    seq = pinfo["seq"]
                    count = self._probe_echo_counts.get(seq, 0) + 1
                    self._probe_echo_counts[seq] = count
                    # On Scapy/Npcap, count==1 might be our own TX copy; count>=2 confirms wire loop!
                    # On macOS BPF (BIOCSSEESENT=0) and Simulation, count>=1 is already a wire loop!
                    is_confirmed_echo = (count >= 2) if self._expect_tx_self_echo else (count >= 1)
                    if is_confirmed_echo:
                        self._sec_probe_echo += 1
                        self._probe_echo_total += 1
                        self._probe_last_rtt_ms = round(pinfo["rtt_ms"], 2)
                        if count == (2 if self._expect_tx_self_echo else 1):
                            self._log_event(
                                "danger",
                                f"主动二层探针 Seq #{seq} 发生物理回环！(RTT {pinfo['rtt_ms']:.1f}ms，确认存在二层环路)",
                            )
                return  # Do not count our own probe in talkers/dup stats

            # 2. Duplicate frame burst detection (250ms sliding window)
            if pkt["is_broadcast"] or pkt["is_multicast"]:
                sig = pkt["sig"]
                prev = self._sig_window.get(sig)
                if prev is not None and (ts - prev[0]) <= 0.25:
                    rep = prev[1] + 1
                    self._sig_window[sig] = (ts, rep, prev[2])
                    if rep >= 2:
                        self._sec_dup += 1
                    if rep >= 3:
                        cluster = self._dup_clusters.get(sig)
                        if cluster is None:
                            vendor_info = lookup_mac_vendor(pkt["src_mac"])
                            cluster = {
                                "src_mac": pkt["src_mac"],
                                "dst_mac": pkt["dst_mac"],
                                "proto": pkt["proto"],
                                "vendor": vendor_info["vendor"],
                                "category": vendor_info["category"],
                                "category_label": vendor_info["category_label"],
                                "count": rep,
                                "last_seen": ts,
                                "detail": (
                                    f"ARP {pkt['arp']['sender_ip']} -> {pkt['arp']['target_ip']}"
                                    if pkt["arp"]
                                    else f"{pkt['proto']} ({pkt['dst_mac']})"
                                ),
                            }
                            self._dup_clusters[sig] = cluster
                        else:
                            cluster["count"] += 1
                            cluster["last_seen"] = ts
                else:
                    self._sig_window[sig] = (ts, 1, {"src_mac": pkt["src_mac"], "proto": pkt["proto"]})
                if len(self._sig_window) > 1200:
                    cutoff = ts - 0.5
                    self._sig_window = {k: v for k, v in self._sig_window.items() if v[0] >= cutoff}

            # 3. Top Talkers aggregation
            src = pkt["src_mac"]
            t = self._talkers.get(src)
            if t is None:
                vinfo = lookup_mac_vendor(src)
                t = {
                    "mac": src,
                    "vendor": vinfo["vendor"],
                    "category": vinfo["category"],
                    "category_label": vinfo["category_label"],
                    "packets": 0,
                    "broadcast": 0,
                    "arp": 0,
                    "last_ip": "",
                    "last_seen": ts,
                }
                self._talkers[src] = t
            t["packets"] += 1
            if pkt["is_broadcast"]:
                t["broadcast"] += 1
            if pkt["proto"] == "ARP":
                t["arp"] += 1
                if pkt["arp"] and pkt["arp"]["sender_ip"] != "0.0.0.0":
                    t["last_ip"] = pkt["arp"]["sender_ip"]
            t["last_seen"] = ts
            if len(self._talkers) > 500:
                # Keep top 200 active talkers
                top_keys = sorted(self._talkers.keys(), key=lambda k: self._talkers[k]["packets"], reverse=True)[:200]
                self._talkers = {k: self._talkers[k] for k in top_keys}

            # 4. LLDP / CDP Upstream Managed Switch Auto-Discovery
            if pkt["neighbor"]:
                nb = dict(pkt["neighbor"])
                nb["src_mac"] = src
                nb["seen_at"] = ts
                mgmt_ip = nb.get("mgmt_ip", "")
                port_id = nb.get("port_id", "")
                nb["location"] = self.ledger.format_location(mgmt_ip, port_id) if (mgmt_ip and port_id) else ""
                is_new = self.upstream_switch is None or self.upstream_switch.get("port_id") != port_id
                self.upstream_switch = nb
                if is_new:
                    self._log_event(
                        "info",
                        f"通过 {nb.get('protocol', 'LLDP')} 自动识别上联交换机：{nb.get('sys_name', '未知')} "
                        f"端口 {port_id} ({mgmt_ip or '无管理IP'})",
                    )

            # 5. STP / BPDU Monitor
            if pkt["stp"]:
                stp = dict(pkt["stp"])
                stp["seen_at"] = ts
                if stp.get("tc_flag"):
                    self._sec_stp_tc += 1
                    self._stp_tc_total += 1
                if stp.get("root_mac"):
                    stp["root_vendor"] = lookup_mac_vendor(stp["root_mac"])["vendor"]
                self.stp_info = stp

            # 6. DHCP Offer/Ack -> Rogue SOHO Router Detector
            if pkt["dhcp"] and pkt["dhcp"]["msg_type"] in (2, 5):  # OFFER or ACK
                d = pkt["dhcp"]
                srv_ip = d["server_ip"]
                if srv_ip and srv_ip != "0.0.0.0":
                    is_rogue = srv_ip not in self.trusted_dhcp_ips
                    vinfo = lookup_mac_vendor(d["server_mac"])
                    existing = self._dhcp_servers.get(srv_ip)
                    if existing is None:
                        self._dhcp_servers[srv_ip] = {
                            "server_ip": srv_ip,
                            "server_mac": d["server_mac"],
                            "router_ip": d["router_ip"],
                            "offered_ip": d["offered_ip"],
                            "subnet_mask": d["subnet_mask"],
                            "vendor": vinfo["vendor"],
                            "category": vinfo["category"],
                            "category_label": vinfo["category_label"],
                            "is_rogue": is_rogue,
                            "count": 1,
                            "first_seen": ts,
                            "last_seen": ts,
                            "web_title": "",
                            "model_hint": "",
                            "web_port": "",
                        }
                        if is_rogue:
                            self._log_event(
                                "danger",
                                f"发现私接小路由器/非法 DHCP：{srv_ip} ({d['server_mac']} / {vinfo['vendor']})，"
                                f"正在分配私网地址 {d['offered_ip']}",
                            )
                            if srv_ip not in self._web_probed_ips:
                                self._web_probed_ips.add(srv_ip)
                                self._probe_rogue_http_async(srv_ip, self.backend == "simulation")
                    else:
                        existing["count"] += 1
                        existing["last_seen"] = ts
                        existing["is_rogue"] = is_rogue

    def _track_arp_anomalies(self, arp: Dict[str, Any], ts: float) -> None:
        """Detect IP/gateway ARP conflicts & passively exposed SOHO routers via ARP."""
        sip = arp.get("sender_ip") or ""
        smac = arp.get("sender_mac") or ""
        if not sip or sip == "0.0.0.0" or not smac:
            return

        # 1. Track IP -> MAC mapping for IP / Gateway Conflict Detection
        mac_map = self._arp_ip_macs.setdefault(sip, {})
        mac_map[smac] = ts
        # Expire entries older than 90s
        stale = [m for m, t0 in mac_map.items() if ts - t0 > 90.0]
        for m in stale:
            mac_map.pop(m, None)
        if len(mac_map) >= 2:
            mac_list = sorted(mac_map.keys())
            existing_c = self._arp_conflicts.get(sip)
            if existing_c is None:
                vendors = [f"{m} ({lookup_mac_vendor(m)['vendor']})" for m in mac_list[:3]]
                self._arp_conflicts[sip] = {
                    "ip": sip,
                    "macs": mac_list,
                    "vendors": vendors,
                    "is_gateway": sip.endswith(".1") or sip.endswith(".254"),
                    "count": 1,
                    "last_seen": ts,
                }
                self._log_event("danger", f"检测到 ARP IP/网关冲突：{sip} 同时被 {' 与 '.join(vendors)} 宣称！")
            else:
                existing_c["macs"] = mac_list
                existing_c["count"] += 1
                existing_c["last_seen"] = ts
        if len(self._arp_ip_macs) > 400:
            self._arp_ip_macs = {k: v for k, v in list(self._arp_ip_macs.items())[-250:]}

        # 2. Passive SOHO router LAN gateway exposure (even when router DHCP hasn't answered yet)
        if sip in _SOHO_GATEWAY_IPS and sip not in self.trusted_dhcp_ips and sip not in self._dhcp_servers:
            vinfo = lookup_mac_vendor(smac)
            if vinfo["category"] == "soho_router":
                self._dhcp_servers[sip] = {
                    "server_ip": sip,
                    "server_mac": smac,
                    "router_ip": sip,
                    "offered_ip": "(ARP被动暴露)",
                    "subnet_mask": "255.255.255.0",
                    "vendor": vinfo["vendor"],
                    "category": vinfo["category"],
                    "category_label": vinfo["category_label"],
                    "is_rogue": True,
                    "count": 1,
                    "first_seen": ts,
                    "last_seen": ts,
                    "web_title": "",
                    "model_hint": "",
                    "web_port": "",
                }
                self._log_event(
                    "warn",
                    f"通过 ARP 被动发现疑似私接小路由器：{sip} ({smac} / {vinfo['vendor']})，正在探测 Web 管理型号...",
                )
                if sip not in self._web_probed_ips:
                    self._web_probed_ips.add(sip)
                    self._probe_rogue_http_async(sip, self.backend == "simulation")

    def _maybe_roll_second(self) -> None:
        now = time.time()
        with self._lock:
            elapsed = now - self._cur_sec_start
            if elapsed < 0.5:
                return

            total_pps = round(self._sec_total / elapsed, 1)
            bcast_pps = round(self._sec_broadcast / elapsed, 1)
            mcast_pps = round(self._sec_multicast / elapsed, 1)
            arp_pps = round(self._sec_arp / elapsed, 1)
            dup_pps = round(self._sec_dup / elapsed, 1)
            kbps = round((self._sec_bytes * 8 / 1000.0) / elapsed, 1)
            probe_echo_cur = self._sec_probe_echo
            stp_tc_cur = self._sec_stp_tc

            dup_ratio = round((dup_pps / max(1.0, bcast_pps + mcast_pps)) * 100.0, 1) if dup_pps > 0 else 0.0
            if bcast_pps > self._peak_broadcast_pps:
                self._peak_broadcast_pps = bcast_pps

            self._history.append({
                "ts": now,
                "label": time.strftime("%H:%M:%S", time.localtime(now)),
                "total_pps": total_pps,
                "broadcast_pps": bcast_pps,
                "multicast_pps": mcast_pps,
                "arp_pps": arp_pps,
                "dup_pps": dup_pps,
                "dup_ratio": dup_ratio,
                "kbps": kbps,
                "probe_echo": probe_echo_cur,
            })

            # Recent 2.0 seconds active probe echoes (4 x 0.5s buckets);
            # immediately clear stale echo hold when an active storm drops cleanly to normal!
            storm_just_dropped = (
                self._peak_broadcast_pps >= 200
                and bcast_pps < 80
                and dup_pps < 5
                and probe_echo_cur == 0
            )
            recent_echoes = 0 if storm_just_dropped else sum(
                item["probe_echo"] for item in list(self._history)[-4:]
            )
            self._probe_echo_recent = recent_echoes

            # Compute Loop Confidence (0..100) using active sensitivity preset
            preset = SENSITIVITY_PRESETS.get(self.sensitivity, SENSITIVITY_PRESETS["standard"])
            score = 0
            reasons: List[str] = []

            if recent_echoes > 0:
                score += 65
                reasons.append(f"主动二层探针回环 (近2秒回环 {recent_echoes} 次)")
            if dup_pps >= preset["dup_high"] or (dup_pps >= preset["dup_warn"] and dup_ratio >= 45.0):
                score += 50
                reasons.append(f"重复广播帧爆发 ({dup_pps:.0f} pps，重复占比 {dup_ratio:.0f}%)")
            elif dup_pps >= max(5, preset["dup_warn"] // 2):
                score += 20
                reasons.append(f"出现重复广播帧 ({dup_pps:.0f} pps)")
            if bcast_pps >= preset["bcast_high"]:
                score += 45
                reasons.append(f"严重广播风暴 ({bcast_pps:.0f} pps)")
            elif bcast_pps >= preset["bcast_warn"]:
                score += 25
                reasons.append(f"广播速率异常偏高 ({bcast_pps:.0f} pps)")
            if arp_pps >= preset["arp_high"]:
                score += 20
                reasons.append(f"ARP 风暴 ({arp_pps:.0f} pps)")
            if stp_tc_cur > 0:
                score += 15
                reasons.append("检测到 STP 拓扑震荡 (TC 标志)")
            if self._arp_conflicts:
                score += 20
                reasons.append(f"检测到 {len(self._arp_conflicts)} 处 ARP IP/网关冲突")

            rogue_count = sum(1 for s in self._dhcp_servers.values() if s["is_rogue"])
            if rogue_count > 0:
                score += 15
                reasons.append(f"发现 {rogue_count} 台私接小路由器/非法 DHCP")

            score = min(100, score)
            self._loop_confidence = score
            self._reasons = reasons

            if score >= 60:
                new_status = "LOOP_DETECTED"
            elif score >= 20 or rogue_count > 0:
                new_status = "WARNING"
            else:
                new_status = "NORMAL"

            # Detect sudden bisection recovery (LOOP_DETECTED -> NORMAL/WARNING with massive drop!)
            if self._prev_status == "LOOP_DETECTED" and new_status != "LOOP_DETECTED" and bcast_pps < 80:
                self._recovery_flash_ts = now
                self._log_event(
                    "success",
                    f"风暴骤降！广播速率从峰值 {self._peak_broadcast_pps:.0f} pps 跌至 {bcast_pps:.0f} pps —— 刚刚断开的支线极可能就是环路源！",
                )
            elif self._prev_status != "LOOP_DETECTED" and new_status == "LOOP_DETECTED":
                self._log_event("danger", f"确认存在二层环路（置信度 {score}%）：{'；'.join(reasons[:2])}")

            self._prev_status = new_status
            self._status = new_status

            # Decay stale duplicate clusters older than 8s
            cutoff = now - 8.0
            self._dup_clusters = {k: v for k, v in self._dup_clusters.items() if v["last_seen"] >= cutoff}

            # Reset 1s accumulators
            self._cur_sec_start = now
            self._sec_total = 0
            self._sec_broadcast = 0
            self._sec_multicast = 0
            self._sec_arp = 0
            self._sec_dup = 0
            self._sec_bytes = 0
            self._sec_stp_tc = 0
            self._sec_probe_echo = 0

    def get_snapshot(self) -> Dict[str, Any]:
        """Return full JSON-serializable state snapshot for SSE/REST polling."""
        with self._lock:
            now = time.time()
            latest = self._history[-1] if self._history else {
                "total_pps": 0.0,
                "broadcast_pps": 0.0,
                "multicast_pps": 0.0,
                "arp_pps": 0.0,
                "dup_pps": 0.0,
                "dup_ratio": 0.0,
                "kbps": 0.0,
                "probe_echo": 0,
            }
            total_pkts = sum(t["packets"] for t in self._talkers.values()) or 1
            top_talkers = sorted(
                self._talkers.values(),
                key=lambda x: (x["broadcast"], x["packets"]),
                reverse=True,
            )[:12]
            talkers_out = [
                {
                    **t,
                    "share_pct": round(t["packets"] * 100.0 / total_pkts, 1),
                }
                for t in top_talkers
            ]
            dup_top = sorted(
                self._dup_clusters.values(),
                key=lambda x: x["count"],
                reverse=True,
            )[:8]
            dhcp_list = sorted(
                self._dhcp_servers.values(),
                key=lambda x: (not x["is_rogue"], -x["count"]),
            )
            return {
                "running": self.running,
                "backend": self.backend,
                "interface": self.interface,
                "probe_mode": self.probe_mode,
                "probe_mac": self._probe_mac,
                "probe_seq": self._probe_seq,
                "probe_echo_total": self._probe_echo_total,
                "probe_echo_recent": self._probe_echo_recent,
                "probe_last_rtt_ms": self._probe_last_rtt_ms,
                "probe_paused_by_safety": self._probe_paused_by_safety,
                "status": self._status,
                "loop_confidence": self._loop_confidence,
                "reasons": list(self._reasons),
                "just_recovered": (now - self._recovery_flash_ts) < 6.0,
                "peak_broadcast_pps": self._peak_broadcast_pps,
                "latest": latest,
                "history": list(self._history),
                "top_talkers": talkers_out,
                "dup_clusters": dup_top,
                "upstream_switch": self.upstream_switch,
                "stp_info": self.stp_info,
                "stp_tc_total": self._stp_tc_total,
                "dhcp_servers": dhcp_list,
                "arp_conflicts": list(self._arp_conflicts.values()),
                "trusted_dhcp_ips": list(self.trusted_dhcp_ips),
                "sensitivity": self.sensitivity,
                "pcap_count": len(self._pcap_ring),
                "seconds_since_frame": round(now - self._last_frame_ts, 1) if self._last_frame_ts > 0 else None,
                "events": list(self._events)[:35],
                "last_error": self.last_error,
                "simulation": {
                    "active": self.backend == "simulation",
                    "loop_active": self._simulator.loop_active,
                    "rogue_dhcp_active": self._simulator.rogue_dhcp_active,
                },
            }
