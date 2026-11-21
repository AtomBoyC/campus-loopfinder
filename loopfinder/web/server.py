"""Local-only threaded HTTP + SSE API server powering the LoopFinder desktop UI."""

from __future__ import annotations

import html
import json
import mimetypes
import os
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from loopfinder import __app_name__, __version__
from loopfinder.core.capture import SENSITIVITY_PRESETS, CaptureController
from loopfinder.core.console_inspector import inspect_switch_console, list_serial_ports
from loopfinder.core.interfaces import check_capabilities, list_interfaces
from loopfinder.core.inventory import SwitchInventory
from loopfinder.core.l3_tracer import run_l3_loop_trace
from loopfinder.core.ledger import PortLedger
from loopfinder.core.snmp import (
    batch_scan_switches,
    lookup_mac_in_scan,
    scan_switch_snmp,
    trace_loop_hops,
)
from loopfinder.core.cli_parser import SAMPLE_CLI_OUTPUT, parse_switch_cli_output
from loopfinder.core.syslog_listener import SyslogRadar


STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class AppContext:
    """Shared backend state for all HTTP/SSE request threads."""

    def __init__(self) -> None:
        self.ledger = PortLedger()
        self.inventory = SwitchInventory()
        self.capture = CaptureController(self.ledger)
        self.syslog = SyslogRadar(self.ledger)
        self._lock = threading.RLock()
        self.snmp_scans: Dict[str, Dict[str, Any]] = {}
        self.last_snmp_ip: str = ""
        self.last_hop_trace: Optional[Dict[str, Any]] = None
        self.last_l3_trace: Optional[Dict[str, Any]] = None
        self.last_console_result: Optional[Dict[str, Any]] = None

    def save_snmp_scan(self, result: Dict[str, Any]) -> None:
        with self._lock:
            ip = result.get("switch_ip", "")
            if ip:
                self.snmp_scans[ip] = result
                self.last_snmp_ip = ip

    def get_snmp_history(self) -> List[Dict[str, Any]]:
        with self._lock:
            items = []
            for ip, res in self.snmp_scans.items():
                items.append({
                    "switch_ip": ip,
                    "sys_name": res.get("sys_name", ip),
                    "vendor": res.get("vendor", ""),
                    "cpu_pct": res.get("cpu_pct"),
                    "simulated": bool(res.get("simulated")),
                    "suspect_count": len(res.get("suspect_ports", [])),
                    "flap_count": len(res.get("mac_flaps", [])),
                    "scanned_at": res.get("scanned_at", 0),
                })
            items.sort(key=lambda x: x["scanned_at"], reverse=True)
            return items

    def get_combined_snapshot(self) -> Dict[str, Any]:
        snap = self.capture.get_snapshot()
        snap["syslog"] = self.syslog.get_state()
        return snap

    def build_html_report(self) -> str:
        """Build the single self-contained printable HTML incident report (print / save as PDF)."""
        snap = self.capture.get_snapshot()
        sys_alerts = self.syslog.get_state().get("alerts", [])
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        e = html.escape
        muted = "style='color:#64748b;text-align:center;'"

        def table(headers: List[str], rows: List[List[str]], empty: str) -> str:
            head = "".join(f"<th>{h}</th>" for h in headers)
            if rows:
                body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
            else:
                body = f"<tr><td colspan='{len(headers)}' {muted}>{empty}</td></tr>"
            return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"

        status_color = {
            "LOOP_DETECTED": "#dc2626",
            "WARNING": "#d97706",
            "NORMAL": "#059669",
            "IDLE": "#475569",
        }.get(snap["status"], "#475569")

        sections: List[str] = []

        # 1. Field verdict
        sections.append(
            "<h2>现场判定依据</h2>"
            f"<p>{e('；'.join(snap['reasons'])) if snap['reasons'] else '未触发异常告警'}</p>"
        )

        # 2. Upstream switch
        up = snap.get("upstream_switch")
        if up:
            sections.append(
                "<h2>自动识别的上联交换机 (LLDP/CDP)</h2>"
                + table(
                    ["设备名", "管理 IP", "端口", "VLAN", "台账位置"],
                    [[
                        e(str(up.get("sys_name", "-"))),
                        f"<code>{e(str(up.get('mgmt_ip', '-')))}</code>",
                        f"<code>{e(str(up.get('port_id', '-')))}</code>",
                        e(str(up.get("vlan_id", "-"))),
                        e(up.get("location") or "未录入"),
                    ]],
                    "",
                )
            )

        # 3. Rogue routers & ARP conflicts
        rogues = [s for s in snap["dhcp_servers"] if s.get("is_rogue")]
        sections.append(
            "<h2>私接小路由器 / 非法 DHCP 清单</h2>"
            + table(
                ["网关 IP", "MAC 地址", "厂商", "Web 识别型号", "下发地址"],
                [[
                    f"<code>{e(r['server_ip'])}</code>",
                    f"<code>{e(r['server_mac'])}</code>",
                    e(r["vendor"]),
                    f"<strong>{e(r.get('model_hint') or r.get('web_title') or '-')}</strong>",
                    f"<code>{e(r.get('offered_ip') or '-')}</code>",
                ] for r in rogues],
                "未检测到私接小路由器 / 非法 DHCP",
            )
        )
        if snap.get("arp_conflicts"):
            sections.append(
                "<h2>ARP IP / 网关冲突</h2>"
                + table(
                    ["冲突 IP", "宣称该 IP 的 MAC"],
                    [[f"<code>{e(c['ip'])}</code>" + (" (疑似网关)" if c.get("is_gateway") else ""),
                      e(" ↔ ".join(c.get("vendors", [])))] for c in snap["arp_conflicts"]],
                    "",
                )
            )

        # 4. Top talkers
        if snap["top_talkers"]:
            sections.append(
                "<h2>广播风暴源 Top MAC</h2>"
                + table(
                    ["MAC 地址", "厂商", "分类", "广播包", "总包 (占比)"],
                    [[f"<code>{e(t['mac'])}</code>", e(t["vendor"]), e(t["category_label"]),
                      str(t["broadcast"]), f"{t['packets']} ({t['share_pct']}%)"] for t in snap["top_talkers"][:8]],
                    "",
                )
            )

        with self._lock:
            # 5. Hop trace
            if self.last_hop_trace and self.last_hop_trace.get("hops"):
                hop_items = " → ".join(
                    f"<span class='chip'>{e(h['sys_name'])} <code>{e(h['port'])}</code>"
                    f"{' (' + e(h['location']) + ')' if h.get('location') else ''}</span>"
                    for h in self.last_hop_trace["hops"]
                )
                sections.append(
                    f"<h2>汇聚 → 接入自动逐跳追踪</h2><div class='hops'>{hop_items}</div>"
                    f"<p><strong>结论：</strong>{e(self.last_hop_trace.get('stop_reason', ''))}</p>"
                )

            # 6. Console serial result
            cr = self.last_console_result
            if cr and cr.get("ranked_ports"):
                rows = [[
                    f"<code>{e(rp['port'])}</code>",
                    e(rp.get("location") or "-"),
                    e(rp["direction"]),
                    f"{rp['in_broadcast_pps']} pps",
                    e(f"{rp['lldp_neighbor']['remote_sys']} ({rp['lldp_neighbor']['remote_port']})") if rp.get("lldp_neighbor") else "-",
                ] for rp in cr["ranked_ports"][:8] if rp["risk_score"] > 0 or rp["in_broadcast_pps"] > 50]
                sections.append(
                    f"<h2>Console 串口直连定位（{e(cr.get('sys_name', ''))} · {e(cr.get('vendor', ''))}）</h2>"
                    f"<p>{e(cr.get('summary', ''))}</p>"
                    + table(["端口", "台账位置", "方向判定", "入向广播", "LLDP 下联"], rows, "未发现异常端口")
                )

            # 7. SNMP scans
            if self.snmp_scans:
                blocks = ["<h2>弱电间交换机 SNMP 排查明细</h2>"]
                for ip, res in self.snmp_scans.items():
                    cpu_txt = f" · CPU {res['cpu_pct']}%" if res.get("cpu_pct") is not None else ""
                    blocks.append(
                        f"<h3>{e(res.get('sys_name', ip))} ({e(ip)} · {e(res.get('vendor', ''))}{e(cpu_txt)})</h3>"
                        f"<p>{e(res.get('summary', ''))}</p>"
                    )
                    if res.get("mac_flaps"):
                        blocks.append(table(
                            ["漂移 MAC", "厂商", "端口 A", "端口 B"],
                            [[f"<code>{e(f['mac'])}</code>", e(f["vendor"]),
                              f"<code>{e(f['from_port'])}</code> {e(f.get('from_location') or '')}",
                              f"<code>{e(f['to_port'])}</code> {e(f.get('to_location') or '')}"] for f in res["mac_flaps"]],
                            "",
                        ))
                    blocks.append(table(
                        ["端口", "教研室台账位置", "风险分", "入向广播", "MAC 数", "异常原因"],
                        [[f"<code>{e(p['name'])}</code>", e(p.get("location") or p.get("alias") or "-"),
                          f"<strong>{p['risk_score']}</strong>", f"{p['broadcast_pps']} pps", str(p["mac_count"]),
                          e("；".join(p.get("reasons") or []))] for p in (res.get("suspect_ports") or [])[:8]],
                        "未发现高危端口",
                    ))
                sections.append("".join(blocks))

            # 8. L3 trace
            if self.last_l3_trace:
                sections.append(
                    "<h2>三层路由环路探测</h2>"
                    f"<p>目标 <code>{e(str(self.last_l3_trace.get('target')))}</code>：{e(self.last_l3_trace.get('summary', ''))}</p>"
                )

        # 9. Syslog
        if sys_alerts:
            sections.append(
                "<h2>实时 Syslog 交换机告警</h2>"
                + table(
                    ["时间", "交换机", "类型", "告警", "位置"],
                    [[f"<code>{e(a['time_str'])}</code>", f"<code>{e(a['source_ip'])}</code>", e(a["type"]),
                      e(a["title"]), e(a.get("location") or "-")] for a in sys_alerts[:15]],
                    "",
                )
            )

        # 10. Timeline
        sections.append(
            "<h2>现场诊断时间线</h2>"
            + table(
                ["时间", "级别", "事件详情"],
                [[f"<code>{e(ev['time_str'])}</code>", e(ev["level"].upper()), e(ev["message"])]
                 for ev in reversed(snap["events"][:25])],
                "暂无事件记录",
            )
        )

        body = "\n".join(f"<section>{s}</section>" for s in sections)

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<title>LoopFinder 校园网环路排查报告 - {e(now_str)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", sans-serif; color: #0f172a; background: #f8fafc; margin: 0; padding: 24px; line-height: 1.55; }}
  .sheet {{ max-width: 980px; margin: 0 auto; background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 28px 32px; box-shadow: 0 4px 20px rgba(15,23,42,.06); }}
  .head {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #e2e8f0; padding-bottom: 14px; margin-bottom: 18px; }}
  h1 {{ margin: 0; font-size: 22px; }}
  h2 {{ font-size: 16px; border-left: 4px solid #2563eb; padding-left: 10px; margin: 20px 0 10px; }}
  h3 {{ font-size: 14px; margin: 14px 0 6px; }}
  .badge {{ display: inline-block; padding: 6px 14px; border-radius: 8px; color: #fff; font-weight: 700; background: {status_color}; }}
  .kpis {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 14px 0; }}
  .kpi {{ background: #f1f5f9; border-radius: 8px; padding: 10px 12px; }}
  .kpi small {{ color: #64748b; display: block; font-size: 12px; }}
  .kpi strong {{ font-size: 18px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 6px; }}
  th, td {{ border: 1px solid #e2e8f0; padding: 7px 9px; text-align: left; }}
  th {{ background: #f8fafc; color: #475569; }}
  code {{ font-family: ui-monospace, Menlo, Consolas, monospace; background: #f1f5f9; padding: 1px 5px; border-radius: 4px; font-size: 12px; }}
  .hops {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 8px 0; }}
  .chip {{ background: #eff6ff; border: 1px solid #bfdbfe; padding: 5px 10px; border-radius: 8px; font-size: 13px; }}
  .print-btn {{ padding: 7px 14px; background: #2563eb; color: #fff; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; }}
  @media print {{ body {{ background: #fff; padding: 0; }} .sheet {{ box-shadow: none; border: none; }} .print-btn {{ display: none; }} }}
</style>
</head>
<body>
<div class="sheet">
  <div class="head">
    <div>
      <h1>{e(__app_name__)} · 故障排查工单报告</h1>
      <div style="color:#64748b;font-size:13px;margin-top:4px;">v{e(__version__)} ｜ 生成时间：{e(now_str)} ｜ 监测接口：{e(snap['interface'] or '未启动')} ({e(snap['backend'])})</div>
    </div>
    <div style="text-align:right;">
      <span class="badge">{e(snap['status'])} · 置信度 {snap['loop_confidence']}%</span>
      <div style="margin-top:8px;"><button class="print-btn" onclick="window.print()">🖨️ 打印 / 另存为 PDF</button></div>
    </div>
  </div>

  <div class="kpis">
    <div class="kpi"><small>广播速率峰值</small><strong>{snap['peak_broadcast_pps']} pps</strong></div>
    <div class="kpi"><small>当前广播 / 重复帧</small><strong>{snap['latest']['broadcast_pps']} / {snap['latest']['dup_pps']} pps</strong></div>
    <div class="kpi"><small>主动探针回环累计</small><strong>{snap['probe_echo_total']} 次</strong></div>
    <div class="kpi"><small>发现私接小路由器</small><strong>{len(rogues)} 台</strong></div>
  </div>

{body}
</div>
</body>
</html>"""


def create_server(host: str = "127.0.0.1", port: int = 0, ctx: Optional[AppContext] = None) -> tuple[ThreadingHTTPServer, AppContext]:
    app_ctx = ctx or AppContext()

    class RequestHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_json(self, payload: Any, status: int = 200) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _send_bytes(self, data: bytes, content_type: str, filename: str = "") -> None:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _read_json(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length") or "0")
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception:
                return {}

        def _serve_static(self, rel_path: str) -> None:
            safe = os.path.normpath(rel_path).lstrip(os.sep)
            full_path = os.path.join(STATIC_DIR, safe)
            if not full_path.startswith(STATIC_DIR) or not os.path.isfile(full_path):
                self.send_error(HTTPStatus.NOT_FOUND, "File not found")
                return
            ctype, _ = mimetypes.guess_type(full_path)
            if full_path.endswith(".js"):
                ctype = "application/javascript; charset=utf-8"
            elif full_path.endswith(".css"):
                ctype = "text/css; charset=utf-8"
            elif full_path.endswith(".html"):
                ctype = "text/html; charset=utf-8"
            with open(full_path, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype or "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(data)

        def _handle_sse(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                while True:
                    snap = app_ctx.get_combined_snapshot()
                    msg = f"data: {json.dumps(snap, ensure_ascii=False)}\n\n".encode("utf-8")
                    self.wfile.write(msg)
                    self.wfile.flush()
                    time.sleep(0.6)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

        def do_GET(self) -> None:
            if not self._is_trusted_request(is_post=False):
                return self._send_json({"ok": False, "error": "Forbidden: untrusted host"}, status=403)
            parsed = urlparse(self.path)
            path = parsed.path

            if path == "/" or path == "/index.html":
                return self._serve_static("index.html")
            if path.startswith("/static/"):
                return self._serve_static(path[len("/static/") :])
            if path == "/api/events":
                return self._handle_sse()
            if path == "/api/system":
                return self._send_json({
                    "app_name": __app_name__,
                    "version": __version__,
                    "capabilities": check_capabilities(),
                    "interfaces": list_interfaces(),
                    "sensitivity_presets": {k: v["label"] for k, v in SENSITIVITY_PRESETS.items()},
                    "sample_cli": SAMPLE_CLI_OUTPUT,
                })
            if path == "/api/state":
                return self._send_json(app_ctx.get_combined_snapshot())
            if path == "/api/capture/pcap":
                data = app_ctx.capture.export_pcap_bytes()
                ts_tag = time.strftime("%Y%m%d_%H%M%S")
                return self._send_bytes(data, "application/vnd.tcpdump.pcap", f"LoopFinder_Capture_{ts_tag}.pcap")
            if path == "/api/snmp/history":
                return self._send_json({"items": app_ctx.get_snmp_history()})
            if path == "/api/snmp/result":
                qs = parse_qs(parsed.query)
                ip = (qs.get("ip") or [app_ctx.last_snmp_ip])[0]
                res = app_ctx.snmp_scans.get(ip)
                if not res:
                    return self._send_json({"ok": False, "error": "未找到该交换机的扫描记录"}, status=404)
                return self._send_json({"ok": True, "result": res})
            if path == "/api/inventory":
                return self._send_json({"switches": app_ctx.inventory.list_switches()})
            if path == "/api/inventory/export_csv":
                csv_data = app_ctx.inventory.export_csv_text().encode("utf-8-sig")
                return self._send_bytes(csv_data, "text/csv; charset=utf-8", "campus_switches.csv")
            if path == "/api/syslog/state":
                return self._send_json(app_ctx.syslog.get_state())
            if path == "/api/console/ports":
                return self._send_json({"ports": list_serial_ports()})
            if path == "/api/ledger":
                return self._send_json({"entries": app_ctx.ledger.list_entries()})
            if path == "/api/ledger/export_csv":
                csv_data = app_ctx.ledger.export_csv_text().encode("utf-8-sig")
                return self._send_bytes(csv_data, "text/csv; charset=utf-8", "campus_port_ledger.csv")
            if path == "/api/report":
                html_doc = app_ctx.build_html_report().encode("utf-8")
                return self._send_bytes(html_doc, "text/html; charset=utf-8")

            self._send_json({"error": "Not found"}, status=404)

        def _is_trusted_request(self, is_post: bool) -> bool:
            """Block DNS-rebinding and cross-site requests from arbitrary web pages.

            - Host must be the loopback address we listen on (defeats DNS rebinding).
            - If the browser sends an Origin, it must be our own loopback origin.
            - POST bodies must be application/json, which forces a CORS preflight that we never
              approve, so other sites cannot fire "simple" form/text POSTs at the API.
            """
            host = (self.headers.get("Host") or "").split(":")[0].strip().lower()
            if host not in ("127.0.0.1", "localhost", "[::1]"):
                return False
            origin = (self.headers.get("Origin") or "").strip().lower()
            if origin and origin != "null":
                o_host = urlparse(origin).hostname or ""
                if o_host not in ("127.0.0.1", "localhost", "::1"):
                    return False
            if is_post:
                ctype = (self.headers.get("Content-Type") or "").lower()
                if not ctype.startswith("application/json"):
                    return False
            return True

        def do_POST(self) -> None:
            if not self._is_trusted_request(is_post=True):
                return self._send_json({"ok": False, "error": "Forbidden: untrusted origin"}, status=403)
            parsed = urlparse(self.path)
            path = parsed.path
            body = self._read_json()

            if path == "/api/capture/start":
                res = app_ctx.capture.start(
                    interface=str(body.get("interface") or ""),
                    mode=str(body.get("mode") or "active"),
                    backend=str(body.get("backend") or "auto"),
                )
                return self._send_json(res, status=200 if res.get("ok") else 400)
            if path == "/api/capture/stop":
                app_ctx.capture.stop()
                return self._send_json({"ok": True})
            if path == "/api/capture/reset":
                app_ctx.capture.reset_metrics()
                return self._send_json({"ok": True})
            if path == "/api/capture/sensitivity":
                preset = app_ctx.capture.set_sensitivity(str(body.get("preset") or "standard"))
                return self._send_json({"ok": True, "sensitivity": preset})
            if path == "/api/capture/probe":
                res = app_ctx.capture.send_single_probe()
                return self._send_json(res, status=200 if res.get("ok") else 400)
            if path == "/api/capture/dhcp_scan":
                res = app_ctx.capture.trigger_dhcp_scan()
                return self._send_json(res, status=200 if res.get("ok") else 400)
            if path == "/api/capture/trusted_dhcp":
                ips = body.get("ips") or []
                if isinstance(ips, str):
                    ips = [x.strip() for x in ips.replace("，", ",").split(",") if x.strip()]
                app_ctx.capture.set_trusted_dhcp(ips)
                return self._send_json({"ok": True, "trusted_dhcp_ips": app_ctx.capture.trusted_dhcp_ips})
            if path == "/api/sim/toggle":
                res = app_ctx.capture.set_simulation_state(
                    loop_active=body.get("loop_active"),
                    rogue_dhcp_active=body.get("rogue_dhcp_active"),
                )
                return self._send_json({"ok": True, **res})
            if path == "/api/snmp/scan":
                switch_ip = str(body.get("switch_ip") or "").strip()
                community = str(body.get("community") or "public").strip()
                snmp_port = int(body.get("port") or 161)
                snmp_ver = str(body.get("snmp_version") or "2c").strip()
                interval = max(1.0, min(8.0, float(body.get("sample_interval") or 2.5)))
                simulate = bool(body.get("simulate", False))
                if not switch_ip and not simulate:
                    return self._send_json({"ok": False, "error": "请输入交换机管理 IP"}, status=400)
                try:
                    res = scan_switch_snmp(
                        switch_ip=switch_ip or "10.10.1.1",
                        community=community,
                        port=snmp_port,
                        sample_interval=interval,
                        ledger=app_ctx.ledger,
                        simulate=simulate,
                        snmp_version=snmp_ver,
                    )
                    app_ctx.save_snmp_scan(res)
                    return self._send_json({"ok": True, "result": res, "history": app_ctx.get_snmp_history()})
                except Exception as e:
                    return self._send_json({"ok": False, "error": str(e)}, status=500)
            if path == "/api/snmp/batch_scan":
                building = str(body.get("building") or "").strip()
                simulate = bool(body.get("simulate", False))
                interval = max(1.0, min(6.0, float(body.get("sample_interval") or 2.0)))
                targets = app_ctx.inventory.list_switches(building=building)
                if not targets:
                    return self._send_json({"ok": False, "error": "资产簿中没有可扫描的交换机"}, status=400)
                res = batch_scan_switches(targets, app_ctx.ledger, sample_interval=interval, simulate=simulate)
                for sw_row in res["switches"]:
                    if sw_row.get("full_scan"):
                        app_ctx.save_snmp_scan(sw_row["full_scan"])
                        sw_row.pop("full_scan", None)
                res["history"] = app_ctx.get_snmp_history()
                return self._send_json(res)
            if path == "/api/snmp/trace_hops":
                start_ip = str(body.get("start_ip") or "").strip() or "10.10.0.1"
                community = str(body.get("community") or "public").strip()
                snmp_ver = str(body.get("snmp_version") or "2c").strip()
                target_mac = str(body.get("target_mac") or "").strip()
                simulate = bool(body.get("simulate", False))
                res = trace_loop_hops(
                    start_ip=start_ip,
                    ledger=app_ctx.ledger,
                    inventory=app_ctx.inventory,
                    community=community,
                    snmp_version=snmp_ver,
                    target_mac=target_mac,
                    sample_interval=1.8,
                    simulate=simulate,
                )
                for sc in res.pop("scans", []):
                    app_ctx.save_snmp_scan(sc)
                with app_ctx._lock:
                    app_ctx.last_hop_trace = res
                res["history"] = app_ctx.get_snmp_history()
                return self._send_json(res)
            if path == "/api/snmp/lookup_mac":
                mac = str(body.get("mac") or "").strip()
                sw_ip = str(body.get("switch_ip") or app_ctx.last_snmp_ip).strip()
                scan = app_ctx.snmp_scans.get(sw_ip)
                if not scan:
                    return self._send_json({"ok": False, "error": "请先扫描至少一台弱电间交换机后再反查 MAC"}, status=400)
                return self._send_json({"ok": True, **lookup_mac_in_scan(scan, mac)})
            if path == "/api/inventory/upsert":
                try:
                    items = app_ctx.inventory.upsert(body)
                    return self._send_json({"ok": True, "switches": items})
                except Exception as e:
                    return self._send_json({"ok": False, "error": str(e)}, status=400)
            if path == "/api/inventory/delete":
                items = app_ctx.inventory.delete(str(body.get("ip") or ""))
                return self._send_json({"ok": True, "switches": items})
            if path == "/api/inventory/import_csv":
                cnt = app_ctx.inventory.import_csv_text(str(body.get("csv_text") or ""), replace=bool(body.get("replace", False)))
                return self._send_json({"ok": True, "imported": cnt, "switches": app_ctx.inventory.list_switches()})
            if path == "/api/syslog/start":
                res = app_ctx.syslog.start(port=int(body.get("port") or 1514), bind_host=str(body.get("bind_host") or "0.0.0.0"))
                return self._send_json(res, status=200 if res.get("ok") else 400)
            if path == "/api/syslog/stop":
                app_ctx.syslog.stop()
                return self._send_json({"ok": True})
            if path == "/api/syslog/clear":
                app_ctx.syslog.clear()
                return self._send_json({"ok": True})
            if path == "/api/syslog/demo":
                res = app_ctx.syslog.inject_demo_alert()
                return self._send_json(res)
            if path == "/api/l3/trace":
                res = run_l3_loop_trace(
                    target=str(body.get("target") or "").strip(),
                    max_hops=int(body.get("max_hops") or 16),
                    simulate=bool(body.get("simulate", False)),
                )
                if res.get("ok"):
                    with app_ctx._lock:
                        app_ctx.last_l3_trace = res
                return self._send_json(res, status=200 if res.get("ok") else 400)
            if path == "/api/console/inspect":
                res = inspect_switch_console(
                    device=str(body.get("device") or "").strip(),
                    baudrate=int(body.get("baudrate") or 9600),
                    vendor=str(body.get("vendor") or "auto").strip(),
                    username=str(body.get("username") or "").strip(),
                    password=str(body.get("password") or ""),
                    enable_password=str(body.get("enable_password") or ""),
                    switch_ip=str(body.get("switch_ip") or "").strip(),
                    sample_interval=float(body.get("sample_interval") or 3.0),
                    ledger=app_ctx.ledger,
                    simulate=bool(body.get("simulate", False)),
                )
                if res.get("ok"):
                    with app_ctx._lock:
                        app_ctx.last_console_result = res
                return self._send_json(res, status=200 if res.get("ok") else 400)
            if path == "/api/cli/parse":
                raw_text = str(body.get("raw_text") or "")
                sw_ip = str(body.get("switch_ip") or "").strip()
                parsed = parse_switch_cli_output(raw_text, switch_ip=sw_ip, ledger=app_ctx.ledger)
                return self._send_json({"ok": True, "parsed": parsed})
            if path == "/api/ledger/upsert":
                try:
                    entries = app_ctx.ledger.upsert(body)
                    return self._send_json({"ok": True, "entries": entries})
                except Exception as e:
                    return self._send_json({"ok": False, "error": str(e)}, status=400)
            if path == "/api/ledger/delete":
                entries = app_ctx.ledger.delete(str(body.get("switch_ip") or ""), str(body.get("port") or ""))
                return self._send_json({"ok": True, "entries": entries})
            if path == "/api/ledger/import_csv":
                csv_text = str(body.get("csv_text") or "")
                replace = bool(body.get("replace", False))
                cnt = app_ctx.ledger.import_csv_text(csv_text, replace=replace)
                return self._send_json({"ok": True, "imported": cnt, "entries": app_ctx.ledger.list_entries()})

            self._send_json({"error": "Not found"}, status=404)

    class ReusableThreadingHTTPServer(ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    server = ReusableThreadingHTTPServer((host, port), RequestHandler)
    return server, app_ctx
