"""Rogue SOHO router HTTP/HTTPS & DHCP model fingerprinting helper.

When a rogue DHCP server (e.g., 192.168.1.1, 192.168.3.1, 192.168.31.1) is
detected in a school office, safely probes its local admin port (80 / 443 / 8080)
with a short timeout — following same-host redirects and querying lightweight
unauthenticated router info endpoints (Huawei/Honor HiLink, Xiaomi MiWiFi) — so
ops staff can ask teachers to identify the physical device immediately.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
from typing import Dict, Optional, Tuple
from urllib.parse import urlsplit


_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_MODEL_HINTS = [
    (r"TL-[A-Z0-9\-]+|XDR\d+[A-Z0-9\-]*|WDR\d+[A-Z0-9\-]*|TP-LINK", "TP-LINK"),
    (r"MW\d+[A-Z0-9\-]*|MERCURY|水星", "MERCURY (水星)"),
    (r"FW\d+[A-Z0-9\-]*|FAST|迅捷", "FAST (迅捷)"),
    (r"MiWiFi|小米路由器|Redmi\s*Router|Redmi\s*AX\d+|Xiaomi\s*Router", "Xiaomi (小米)"),
    (r"Tenda|腾达|AC\d{1,2}\s*Pro?", "Tenda (腾达)"),
    (r"荣耀路由|HONOR\s*Router|XD\d{2,3}", "HONOR (荣耀)"),
    (r"HUAWEI\s*WiFi\s*[A-Z0-9\-]+|华为路由[A-Z0-9\-\s]*|WS\d{4}[A-Z0-9\-]*|HiLink|HUAWEI", "Huawei (华为)"),
    (r"H3C\s*Magic|NX\d{2,4}|H3C", "H3C (新华三)"),
    (r"RG-EW\d+[A-Z0-9\-]*|Reyee|Ruijie|锐捷星耀|锐捷|睿易", "Ruijie (锐捷)"),
    (r"ZXHN\s*[A-Z0-9\-]+|中兴路由|巡天|晴天", "ZTE (中兴)"),
    (r"ASUS|RT-[A-Z0-9]+|TUF-AX\d+", "ASUS (华硕)"),
    (r"NETGEAR|R\d{4}|RAX\d+", "NETGEAR"),
    (r"D-Link|DIR-\d+", "D-Link"),
    (r"OpenWrt|LuCI", "OpenWrt"),
]

_DHCP_BRAND_HINTS = [
    ("homerouter.cpe", "Huawei (华为路由)"),
    ("hilink", "Huawei (华为路由)"),
    ("huawei", "Huawei (华为路由)"),
    ("honor", "HONOR (荣耀路由)"),
    ("tplinkwifi", "TP-LINK (普联)"),
    ("tplink", "TP-LINK (普联)"),
    ("miwifi", "Xiaomi (小米路由)"),
    ("xiaomi", "Xiaomi (小米路由)"),
    ("tendawifi", "Tenda (腾达)"),
    ("tenda", "Tenda (腾达)"),
    ("melogin", "MERCURY (水星)"),
    ("mercury", "MERCURY (水星)"),
    ("falogin", "FAST (迅捷)"),
    ("routerlogin", "NETGEAR"),
    ("asusrouter", "ASUS (华硕)"),
    ("reyee", "Ruijie (锐捷睿易)"),
    ("ruijie", "Ruijie (锐捷)"),
    ("openwrt", "OpenWrt"),
]


def _decode_html(raw: bytes) -> str:
    for enc in ("utf-8", "gb18030", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="ignore")


def infer_brand_from_dhcp(
    domain_name: str = "",
    host_name: str = "",
    vendor_class: str = "",
    sname: str = "",
) -> str:
    """Infer router brand/model clue from DHCP Offer/Ack metadata (zero packets sent)."""
    combined = " ".join(x for x in (domain_name, host_name, vendor_class, sname) if x).strip()
    if not combined:
        return ""
    low = combined.lower()
    for needle, label in _DHCP_BRAND_HINTS:
        if needle in low:
            return label
    return ""


def _http_fetch(
    ip: str,
    port: int,
    path: str = "/",
    use_https: bool = False,
    timeout: float = 1.5,
) -> Optional[Tuple[int, Dict[str, str], bytes]]:
    conn = None
    try:
        if use_https:
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request(
            "GET",
            path,
            headers={
                "User-Agent": "Mozilla/5.0 LoopFinder/2.3",
                "Accept": "text/html,application/json,*/*;q=0.8",
            },
        )
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        body = resp.read(20480)
        return resp.status, headers, body
    except Exception:
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def parse_huawei_deviceinfo(body: bytes) -> str:
    """Extract Huawei/Honor router model from /api/system/deviceinfo JSON."""
    text = _decode_html(body).strip()
    if not text.startswith("{"):
        return ""
    try:
        data = json.loads(text)
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    friendly = str(data.get("FriendlyName") or data.get("DeviceName") or "").strip()
    model = str(data.get("ModelName") or data.get("HardwareVersion") or "").strip()
    vendor = str(data.get("VendorName") or "").strip()
    if friendly:
        if model and model.lower() not in friendly.lower() and len(model) <= 24:
            return f"{friendly} ({model})"
        return friendly
    if model:
        return f"{vendor} {model}".strip() if vendor else model
    return ""


def parse_xiaomi_init_info(body: bytes) -> str:
    """Extract Xiaomi/Redmi router model from /cgi-bin/luci/api/xqsystem/init_info JSON."""
    text = _decode_html(body).strip()
    if not text.startswith("{"):
        return ""
    try:
        data = json.loads(text)
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    hw = str(data.get("hardware") or data.get("model") or "").strip()
    rname = str(data.get("routername") or "").strip()
    if hw and rname:
        return f"Xiaomi ({hw} / {rname})"
    if hw:
        return f"Xiaomi ({hw})"
    if rname:
        return f"Xiaomi ({rname})"
    return ""


def _match_model_hint(text: str) -> str:
    for pattern, brand in _MODEL_HINTS:
        hm = re.search(pattern, text, re.IGNORECASE)
        if hm:
            token = re.sub(r"\s+", " ", hm.group(0)).strip()
            if not token:
                continue
            return f"{brand} ({token})" if brand.lower() not in token.lower() else token
    return ""


def probe_router_web(ip: str, timeout: float = 1.5) -> Dict[str, str]:
    """Probe HTTP/HTTPS (80, 443, 8080) on a suspected rogue router IP and return title/server/model."""
    if not ip or ip in ("0.0.0.0", "255.255.255.255"):
        return {"title": "", "server": "", "model_hint": "", "port": ""}

    for port, use_https in ((80, False), (443, True), (8080, False)):
        path = "/"
        cur_https = use_https
        cur_port = port
        location_clues = []
        result = None

        # Follow up to 2 same-host redirects (very common on Huawei/Xiaomi/TP-LINK/OpenWrt)
        for _ in range(3):
            res = _http_fetch(ip, cur_port, path=path, use_https=cur_https, timeout=timeout)
            if res is None:
                break
            result = res
            status, headers, _ = res
            loc = headers.get("location", "").strip()
            if status in (301, 302, 303, 307, 308) and loc:
                location_clues.append(loc)
                parsed = urlsplit(loc)
                if parsed.scheme in ("http", "https") and parsed.hostname and parsed.hostname != ip:
                    break  # Never follow redirects off the router IP
                if parsed.scheme == "https":
                    cur_https = True
                    cur_port = parsed.port or 443
                elif parsed.scheme == "http":
                    cur_https = False
                    cur_port = parsed.port or 80
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                continue
            break

        if result is None:
            continue

        _, headers, body = result
        server = headers.get("server", "")
        www_auth = headers.get("www-authenticate", "")
        title = ""
        m = _TITLE_RE.search(body)
        if m:
            title = re.sub(r"\s+", " ", _decode_html(m.group(1))).strip()[:80]

        realm = ""
        rm = re.search(r'realm="([^"]+)"', www_auth)
        if rm:
            realm = rm.group(1).strip()

        body_preview = _decode_html(body[:6144])
        combined = f"{title} {realm} {server} {' '.join(location_clues)} {body_preview}"
        model_hint = _match_model_hint(combined)

        # Modern Huawei/Honor & Xiaomi routers serve an empty JS shell at "/" and expose JSON device info
        if not model_hint:
            hw_res = _http_fetch(ip, cur_port, path="/api/system/deviceinfo", use_https=cur_https, timeout=min(timeout, 1.2))
            if hw_res and hw_res[0] == 200:
                hw_model = parse_huawei_deviceinfo(hw_res[2])
                if hw_model:
                    model_hint = hw_model
        if not model_hint and ("luci" in combined.lower() or "xiaomi" in combined.lower() or ip.endswith(".31.1")):
            mi_res = _http_fetch(
                ip,
                cur_port,
                path="/cgi-bin/luci/api/xqsystem/init_info",
                use_https=cur_https,
                timeout=min(timeout, 1.2),
            )
            if mi_res and mi_res[0] == 200:
                mi_model = parse_xiaomi_init_info(mi_res[2])
                if mi_model:
                    model_hint = mi_model

        display_title = title or realm or server
        if display_title or model_hint:
            return {
                "title": display_title,
                "server": server,
                "model_hint": model_hint,
                "port": str(cur_port),
            }

    return {"title": "", "server": "", "model_hint": "", "port": ""}
