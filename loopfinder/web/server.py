"""Local-only threaded HTTP + SSE API server powering the LoopFinder v2 Desktop UI."""

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
from loopfinder.core.ssh_inspector import (
    SAMPLE_CLI_OUTPUT,
    VENDOR_COMMANDS,
    generate_hardening_config,
    inspect_switch_ssh,
    parse_switch_cli_output,
)
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
        self.last_ssh_result: Optional[Dict[str, Any]] = None

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

    def build_markdown_report(self) -> str:
        snap = self.capture.get_snapshot()
        sys_alerts = self.syslog.get_state().get("alerts", [])
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"# {__app_name__} v{__version__} 现场环路排查报告",
            f"- **生成时间**: {now_str}",
            f"- **监测网卡/模式**: `{snap['interface'] or '未启动'}` ({snap['backend']} / {snap['probe_mode']} / 灵敏度: {snap.get('sensitivity', 'standard')})",
            f"- **当前结论**: **{snap['status']}**（环路置信度 {snap['loop_confidence']}%）",
            f"- **广播速率峰值**: {snap['peak_broadcast_pps']} pps | 当前广播: {snap['latest']['broadcast_pps']} pps | 重复帧: {snap['latest']['dup_pps']} pps",
            "",
        ]
        if snap["reasons"]:
            lines.append("## 一、现场判定依据")
            for r in snap["reasons"]:
                lines.append(f"- {r}")
            lines.append("")

        if snap["upstream_switch"]:
            up = snap["upstream_switch"]
            lines.append("## 二、自动识别上联交换机 (LLDP/CDP)")
            lines.append(
                f"- 设备名: `{up.get('sys_name', '-')}` | 管理IP: `{up.get('mgmt_ip', '-')}` | "
                f"端口: `{up.get('port_id', '-')}` | VLAN: `{up.get('vlan_id', '-')}` | 台账位置: {up.get('location') or '未录入'}"
            )
            lines.append("")

        rogues = [s for s in snap["dhcp_servers"] if s.get("is_rogue")]
        if rogues:
            lines.append("## 三、私接小路由器 / 非法 DHCP 清单")
            for r in rogues:
                lines.append(
                    f"- IP `{r['server_ip']}` | MAC `{r['server_mac']}` | 厂商 `{r['vendor']}` | "
                    f"型号特征 `{r.get('model_hint') or r.get('web_title') or '未知'}` | 分配地址 `{r['offered_ip']}`"
                )
            lines.append("")

        if snap.get("arp_conflicts"):
            lines.append("## 四、ARP IP/网关冲突告警")
            for c in snap["arp_conflicts"]:
                lines.append(f"- IP `{c['ip']}` 同时被以下 MAC 宣称: {', '.join(c['vendors'])}")
            lines.append("")

        if snap["top_talkers"]:
            lines.append("## 五、异常流量 Top MAC")
            lines.append("| MAC 地址 | 厂商 | 分类 | 广播包数 | 总包数 | 占比 |")
            lines.append("|---|---|---|---|---|---|")
            for t in snap["top_talkers"][:8]:
                lines.append(
                    f"| `{t['mac']}` | {t['vendor']} | {t['category_label']} | {t['broadcast']} | {t['packets']} | {t['share_pct']}% |"
                )
            lines.append("")

        with self._lock:
            if self.last_hop_trace and self.last_hop_trace.get("hops"):
                lines.append("## 六、汇聚 → 接入自动逐跳追踪路径")
                for h in self.last_hop_trace["hops"]:
                    lines.append(
                        f"- 第 {h['hop']} 跳: **{h['sys_name']}** (`{h['switch_ip']}`) 端口 `{h['port']}` "
                        f"| 广播 {h['broadcast_pps']} pps | 位置: {h.get('location') or '-'} | {h.get('note', '')}"
                    )
                lines.append(f"- **最终结论**: {self.last_hop_trace.get('stop_reason', '')}")
                lines.append("")

            if self.snmp_scans:
                lines.append("## 七、弱电间网管交换机 SNMP 排查结果")
                for ip, res in self.snmp_scans.items():
                    cpu_str = f" · CPU {res['cpu_pct']}%" if res.get("cpu_pct") is not None else ""
                    lines.append(f"### {res.get('sys_name')} (`{ip}` · {res.get('vendor')}{cpu_str})")
                    lines.append(f"- 结论: {res.get('summary')}")
                    if res.get("mac_flaps"):
                        lines.append("- **实时 MAC 漂移**:")
                        for f in res["mac_flaps"]:
                            lines.append(
                                f"  - `{f['mac']}` ({f['vendor']}): `{f['from_port']}` ({f.get('from_location') or '-'}) "
                                f"<-> `{f['to_port']}` ({f.get('to_location') or '-'})"
                            )
                    if res.get("suspect_ports"):
                        lines.append("- **高危端口**:")
                        for p in res["suspect_ports"][:6]:
                            lines.append(
                                f"  - `{p['name']}` ({p.get('location') or p.get('alias') or '无台账'}) — "
                                f"风险分 {p['risk_score']} | 广播 {p['broadcast_pps']} pps | MAC数 {p['mac_count']} | 原因: {', '.join(p['reasons'])}"
                            )
                    lines.append("")

            if self.last_console_result and self.last_console_result.get("ranked_ports"):
                cr = self.last_console_result
                lines.append(f"## Console 串口直连双采样定位 ({cr.get('sys_name')} · {cr.get('vendor')})")
                lines.append(f"- 结论: {cr.get('summary')}")
                for rp in cr["ranked_ports"][:5]:
                    if rp["risk_score"] > 0 or rp["in_broadcast_pps"] > 50:
                        lines.append(
                            f"  - `{rp['port']}` ({rp.get('location') or '-'}) | 入向广播 {rp['in_broadcast_pps']} pps | {rp['direction']}"
                        )
                lines.append("")

            if self.last_l3_trace:
                lines.append("## 八、三层路由环路探测结果")
                lines.append(f"- 目标 `{self.last_l3_trace.get('target')}`: {self.last_l3_trace.get('summary')}")
                lines.append("")

        if sys_alerts:
            lines.append("## 九、实时 Syslog 交换机告警")
            for a in sys_alerts[:12]:
                lines.append(
                    f"- `{a['time_str']}` `{a['source_ip']}` [{a['type']}] {a['title']} "
                    f"{'(' + a['location'] + ')' if a.get('location') else ''}"
                )
            lines.append("")

        if snap["events"]:
            lines.append("## 十、排障事件时间线")
            for ev in reversed(snap["events"][:25]):
                lines.append(f"- `{ev['time_str']}` [{ev['level'].upper()}] {ev['message']}")
            lines.append("")

        return "\n".join(lines)

    def build_html_report(self) -> str:
        """Build a clean, self-contained printable HTML incident report for campus ops."""
        snap = self.capture.get_snapshot()
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")
        e = html.escape

        status_color = {
            "LOOP_DETECTED": "#dc2626",
            "WARNING": "#d97706",
            "NORMAL": "#059669",
            "IDLE": "#475569",
        }.get(snap["status"], "#475569")

        rogues = [s for s in snap["dhcp_servers"] if s.get("is_rogue")]
        rogue_rows = "".join(
            f"<tr><td><code>{e(r['server_ip'])}</code></td><td><code>{e(r['server_mac'])}</code></td>"
            f"<td>{e(r['vendor'])}</td><td><strong>{e(r.get('model_hint') or r.get('web_title') or '-')}</strong></td>"
            f"<td><code>{e(r.get('offered_ip') or '-')}</code></td></tr>"
            for r in rogues
        ) or "<tr><td colspan='5' style='color:#64748b;text-align:center;'>未检测到私接小路由器 / 非法 DHCP</td></tr>"

        with self._lock:
            snmp_blocks = []
            for ip, res in self.snmp_scans.items():
                cpu_txt = f" · CPU {res['cpu_pct']}%" if res.get("cpu_pct") is not None else ""
                p_rows = "".join(
                    f"<tr><td><code>{e(p['name'])}</code></td><td>{e(p.get('location') or p.get('alias') or '-')}</td>"
                    f"<td><strong>{p['risk_score']}</strong></td><td>{p['broadcast_pps']} pps</td>"
                    f"<td>{p['mac_count']}</td><td>{e('；'.join(p.get('reasons') or []))}</td></tr>"
                    for p in (res.get("suspect_ports") or [])[:8]
                ) or "<tr><td colspan='6' style='color:#64748b;text-align:center;'>未发现高危端口</td></tr>"
                snmp_blocks.append(
                    f"<h3>{e(res.get('sys_name', ip))} ({e(ip)} · {e(res.get('vendor', ''))}{e(cpu_txt)})</h3>"
                    f"<p>{e(res.get('summary', ''))}</p>"
                    f"<table><thead><tr><th>端口</th><th>教研室台账位置</th><th>风险分</th><th>广播速率</th><th>MAC数</th><th>异常原因</th></tr></thead>"
                    f"<tbody>{p_rows}</tbody></table>"
                )
            hop_html = ""
            if self.last_hop_trace and self.last_hop_trace.get("hops"):
                hop_items = " → ".join(
                    f"<span class='chip'>{e(h['sys_name'])} <code>{e(h['port'])}</code>"
                    f"{' (' + e(h['location']) + ')' if h.get('location') else ''}</span>"
                    for h in self.last_hop_trace["hops"]
                )
                hop_html = f"<section><h2>汇聚 → 接入自动逐跳追踪</h2><div class='hops'>{hop_items}</div><p><strong>结论：</strong>{e(self.last_hop_trace.get('stop_reason', ''))}</p></section>"

        ev_rows = "".join(
            f"<tr><td><code>{e(ev['time_str'])}</code></td><td>{e(ev['level'].upper())}</td><td>{e(ev['message'])}</td></tr>"
            for ev in reversed(snap["events"][:25])
        ) or "<tr><td colspan='3' style='color:#64748b;text-align:center;'>暂无事件记录</td></tr>"

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
      <div style="color:#64748b;font-size:13px;margin-top:4px;">生成时间：{e(now_str)} ｜ 监测接口：{e(snap['interface'] or '未启动')} ({e(snap['backend'])})</div>
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

  <section>
    <h2>一、现场判定依据</h2>
    <p>{e('；'.join(snap['reasons'])) if snap['reasons'] else '未触发异常告警'}</p>
  </section>

  <section>
    <h2>二、私接小路由器 / 非法 DHCP 清单</h2>
    <table><thead><tr><th>网关 IP</th><th>MAC 地址</th><th>厂商</th><th>Web 识别型号</th><th>下发地址</th></tr></thead><tbody>{rogue_rows}</tbody></table>
  </section>

  {hop_html}

  <section>
    <h2>三、弱电间网管交换机 SNMP 排查明细</h2>
    {''.join(snmp_blocks) if snmp_blocks else '<p style="color:#64748b;">本次尚未执行弱电间 SNMP 扫描。</p>'}
  </section>

  <section>
    <h2>四、现场诊断时间线</h2>
    <table><thead><tr><th style="width:90px;">时间</th><th style="width:85px;">级别</th><th>事件详情</th></tr></thead><tbody>{ev_rows}</tbody></table>
  </section>
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
                    "vendor_profiles": {k: v["label"] for k, v in VENDOR_COMMANDS.items()},
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
                qs = parse_qs(parsed.query)
                fmt = (qs.get("format") or ["html"])[0].lower()
                ts_tag = time.strftime("%Y%m%d_%H%M%S")
                if fmt == "md":
                    md = app_ctx.build_markdown_report().encode("utf-8")
                    return self._send_bytes(md, "text/markdown; charset=utf-8", f"LoopFinder_Report_{ts_tag}.md")
                html_doc = app_ctx.build_html_report().encode("utf-8")
                return self._send_bytes(html_doc, "text/html; charset=utf-8")

            self._send_json({"error": "Not found"}, status=404)

        def do_POST(self) -> None:
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
            if path == "/api/ssh/inspect":
                res = inspect_switch_ssh(
                    host=str(body.get("host") or "").strip(),
                    username=str(body.get("username") or "").strip(),
                    password=str(body.get("password") or ""),
                    vendor=str(body.get("vendor") or "huawei"),
                    port=int(body.get("port") or 22),
                    ledger=app_ctx.ledger,
                )
                if res.get("ok"):
                    app_ctx.last_ssh_result = res
                return self._send_json(res, status=200 if res.get("ok") else 400)
            if path == "/api/ssh/parse":
                raw_text = str(body.get("raw_text") or "")
                sw_ip = str(body.get("switch_ip") or "").strip()
                parsed = parse_switch_cli_output(raw_text, switch_ip=sw_ip, ledger=app_ctx.ledger)
                return self._send_json({"ok": True, "parsed": parsed})
            if path == "/api/ssh/hardening":
                res = generate_hardening_config(
                    vendor=str(body.get("vendor") or "huawei"),
                    port_prefix=str(body.get("port_prefix") or ""),
                    port_start=int(body.get("port_start") or 1),
                    port_end=int(body.get("port_end") or 22),
                    uplink_port=str(body.get("uplink_port") or ""),
                    syslog_host=str(body.get("syslog_host") or "").strip(),
                    syslog_port=int(body.get("syslog_port") or 1514),
                )
                return self._send_json({"ok": True, **res})
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
