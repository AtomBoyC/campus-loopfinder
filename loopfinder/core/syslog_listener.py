"""Real-time Multi-Vendor Switch Syslog Radar (UDP 1514 / 514).

Passively listens for syslog messages from Huawei / H3C / Ruijie / Cisco / TP-Link
switches and immediately extracts MAC flapping, LBDT/RLDP loop detections, and
broadcast storm alerts enriched with Campus Port Ledger room locations.
"""

from __future__ import annotations

import collections
import re
import socket
import threading
import time
from typing import Any, Deque, Dict, List, Optional

from loopfinder.core.ledger import PortLedger
from loopfinder.core.ssh_inspector import parse_switch_cli_output


_PRI_RE = re.compile(r"^<\d+>")


class SyslogRadar:
    """Thread-safe UDP syslog listener & real-time loop alert classifier."""

    def __init__(self, ledger: PortLedger) -> None:
        self.ledger = ledger
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

        self.running: bool = False
        self.bind_host: str = "0.0.0.0"
        self.port: int = 1514
        self.last_error: str = ""
        self.total_received: int = 0
        self.alert_count: int = 0
        self._last_alert_ts: float = 0.0
        self._alerts: Deque[Dict[str, Any]] = collections.deque(maxlen=120)
        self._raw_log: Deque[Dict[str, Any]] = collections.deque(maxlen=80)

    def start(self, port: int = 1514, bind_host: str = "0.0.0.0") -> Dict[str, Any]:
        self.stop()
        self._stop_event.clear()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((bind_host, int(port)))
            sock.settimeout(0.5)
        except OSError as e:
            sock.close()
            err = f"无法监听 UDP {bind_host}:{port} ({e})。非管理员模式下请改用 1514 等高位端口。"
            with self._lock:
                self.last_error = err
                self.running = False
            return {"ok": False, "error": err}

        with self._lock:
            self._sock = sock
            self.bind_host = bind_host
            self.port = int(port)
            self.running = True
            self.last_error = ""

        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()
        return {"ok": True, "port": self.port, "bind_host": self.bind_host}

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.2)
        with self._lock:
            self.running = False

    def clear(self) -> None:
        with self._lock:
            self.total_received = 0
            self.alert_count = 0
            self._alerts.clear()
            self._raw_log.clear()

    def _listen_loop(self) -> None:
        while not self._stop_event.is_set():
            sock = self._sock
            if sock is None:
                break
            try:
                data, addr = sock.recvfrom(8192)
                text = ""
                for enc in ("utf-8", "gbk", "latin-1"):
                    try:
                        text = data.decode(enc)
                        break
                    except UnicodeDecodeError:
                        continue
                if text:
                    self.ingest_message(addr[0], text)
            except socket.timeout:
                continue
            except OSError:
                break

    def ingest_message(self, source_ip: str, raw_msg: str) -> Dict[str, Any]:
        """Parse a single incoming syslog line and record if it indicates a loop/flap/storm."""
        clean = _PRI_RE.sub("", raw_msg).strip()
        now = time.time()
        tstr = time.strftime("%H:%M:%S", time.localtime(now))
        parsed = parse_switch_cli_output(clean, switch_ip=source_ip, ledger=self.ledger)

        with self._lock:
            self.total_received += 1
            self._raw_log.appendleft({
                "ts": now,
                "time_str": tstr,
                "source_ip": source_ip,
                "message": clean[:300],
                "is_alert": parsed["finding_count"] > 0,
            })
            if parsed["finding_count"] > 0:
                self.alert_count += parsed["finding_count"]
                self._last_alert_ts = now
                for f in parsed["findings"]:
                    ports = f.get("ports") or []
                    locs = [self.ledger.format_location(source_ip, p) for p in ports]
                    loc_str = " / ".join([x for x in locs if x])
                    self._alerts.appendleft({
                        "ts": now,
                        "time_str": tstr,
                        "source_ip": source_ip,
                        "type": f["type"],
                        "severity": f["severity"],
                        "title": f["title"],
                        "detail": f["detail"],
                        "ports": ports,
                        "location": loc_str,
                        "raw": clean[:260],
                    })
        return parsed

    def inject_demo_alert(self) -> Dict[str, Any]:
        """Inject a realistic multi-vendor campus loop syslog pair for testing & training."""
        samples = [
            (
                "10.10.2.12",
                "<188>Nov 21 10:12:05 HW-3F-East-SW02 %LBDT/4/LOOP_DETECTED: "
                "Loopback exists on GigabitEthernet0/0/14 (VLAN 20).",
            ),
            (
                "10.10.1.1",
                "<188>Nov 21 10:12:06 H3C-3F-Agg-SW01 %MAC/4/MAC_MOVE: "
                "MAC address d80d-176a-3b9c in VLAN 20 moved from GigabitEthernet1/0/14 to GigabitEthernet1/0/15.",
            ),
        ]
        total = 0
        for ip, msg in samples:
            res = self.ingest_message(ip, msg)
            total += res["finding_count"]
        return {"ok": True, "injected": len(samples), "alerts": total}

    def get_state(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "running": self.running,
                "bind_host": self.bind_host,
                "port": self.port,
                "last_error": self.last_error,
                "total_received": self.total_received,
                "alert_count": self.alert_count,
                "last_alert_ts": self._last_alert_ts,
                "alerts": list(self._alerts)[:40],
                "raw_log": list(self._raw_log)[:30],
            }
