"""Cross-platform Layer-3 Routing Loop Detector (TTL-exceeded hop cycle analyzer).

Covers the L3 routing loop scenario (e.g., conflicting static routes between
aggregation and core L3 switches) by running system traceroute/tracert and
automatically detecting repeated hop IP cycles.
"""

from __future__ import annotations

import platform
import re
import subprocess
import time
from typing import Any, Dict, List

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_RTT_RE = re.compile(r"(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)


def parse_traceroute_output(raw_text: str, target: str) -> Dict[str, Any]:
    """Parse macOS/Linux traceroute or Windows tracert output and detect L3 hop cycles."""
    hops: List[Dict[str, Any]] = []
    seen_ips: Dict[str, int] = {}
    loop_ips: List[str] = []
    loop_start_hop = None

    for line in raw_text.splitlines():
        s = line.strip()
        m_hop = re.match(r"^(\d{1,2})\s+(.+)$", s)
        if not m_hop:
            continue
        hop_num = int(m_hop.group(1))
        rest = m_hop.group(2)
        ips = _IP_RE.findall(rest)
        rtts = [float(x) for x in _RTT_RE.findall(rest)]
        ip = ips[0] if ips else "*"
        avg_rtt = round(sum(rtts) / len(rtts), 2) if rtts else None

        is_loop_repeat = False
        if ip != "*" and ip != target:
            if ip in seen_ips:
                is_loop_repeat = True
                if ip not in loop_ips:
                    loop_ips.append(ip)
                if loop_start_hop is None:
                    loop_start_hop = seen_ips[ip]
            else:
                seen_ips[ip] = hop_num

        hops.append({
            "hop": hop_num,
            "ip": ip,
            "rtt_ms": avg_rtt,
            "is_loop": is_loop_repeat,
            "raw": s,
        })

    # Also mark the first occurrence of looping IPs for clear UI highlighting
    loop_set = set(loop_ips)
    for h in hops:
        if h["ip"] in loop_set:
            h["in_loop_cycle"] = True
        else:
            h["in_loop_cycle"] = False

    has_loop = len(loop_ips) > 0
    if has_loop:
        summary = (
            f"检测到三层路由环路！数据包从第 {loop_start_hop} 跳开始在 "
            f"{' ↔ '.join(loop_ips)} 之间反复打转直至 TTL 耗尽。"
        )
    elif hops and hops[-1]["ip"] == target:
        summary = f"路由路径正常，共 {len(hops)} 跳到达目标 {target}，未发现三层环路。"
    else:
        summary = f"共探测 {len(hops)} 跳，未检测到重复跳路由环路（部分节点可能禁 Ping/ICMP 超时）。"

    return {
        "target": target,
        "has_loop": has_loop,
        "loop_ips": loop_ips,
        "loop_start_hop": loop_start_hop,
        "hops": hops,
        "summary": summary,
        "raw": raw_text,
    }


def run_l3_loop_trace(target: str, max_hops: int = 16, simulate: bool = False) -> Dict[str, Any]:
    """Execute cross-platform traceroute/tracert (or realistic simulation) to detect L3 routing loops."""
    target = target.strip()
    if not target:
        return {"ok": False, "error": "请输入目标 IP 或域名"}

    if simulate:
        sim_out = "\n".join([
            f"traceroute to {target} ({target}), 16 hops max",
            " 1  10.10.20.1  1.124 ms  0.985 ms  1.012 ms",
            " 2  10.10.1.1   2.310 ms  2.104 ms  2.055 ms",
            " 3  10.10.0.1   3.402 ms  3.218 ms  3.190 ms",
            " 4  10.10.1.1   4.815 ms  4.700 ms  4.912 ms",
            " 5  10.10.0.1   6.120 ms  5.980 ms  6.040 ms",
            " 6  10.10.1.1   7.550 ms  7.490 ms  7.610 ms",
            " 7  10.10.0.1   8.910 ms  8.802 ms  8.765 ms",
        ])
        res = parse_traceroute_output(sim_out, target)
        res["ok"] = True
        res["simulated"] = True
        return res

    # Validate target safety (only allow hostname/IP characters)
    if not re.match(r"^[a-zA-Z0-9.\-:]+$", target):
        return {"ok": False, "error": "目标地址格式不合法"}

    max_hops = max(4, min(30, int(max_hops)))
    system = platform.system()
    if system == "Windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "800", target]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", "-q", "1", target]

    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=25,
            check=False,
        )
        raw_bytes = proc.stdout or b""
        raw_text = ""
        for enc in ("utf-8", "gbk", "latin-1"):
            try:
                raw_text = raw_bytes.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        res = parse_traceroute_output(raw_text, target)
        res["ok"] = True
        res["simulated"] = False
        res["elapsed_s"] = round(time.time() - t0, 2)
        return res
    except FileNotFoundError:
        return {"ok": False, "error": f"系统未找到 `{cmd[0]}` 命令"}
    except subprocess.TimeoutExpired as e:
        partial = (e.stdout or b"").decode("utf-8", errors="ignore") if isinstance(e.stdout, bytes) else ""
        res = parse_traceroute_output(partial, target)
        res["ok"] = True
        res["simulated"] = False
        res["summary"] = f"探测超时（25秒），已解析前 {len(res['hops'])} 跳：" + res["summary"]
        return res
    except Exception as e:
        return {"ok": False, "error": f"三层路由环路探测失败: {e}"}
