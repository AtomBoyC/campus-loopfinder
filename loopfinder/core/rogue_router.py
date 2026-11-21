"""Rogue SOHO router HTTP model fingerprinting helper.

When a rogue DHCP server (e.g., 192.168.1.1 or 192.168.31.1) is detected in a
school office, safely probes its web admin port (80 / 8080) with a short timeout
to extract the router model/brand (e.g. 'TL-WR886N', 'MiWiFi', '水星无线路由器')
so ops staff can ask teachers to identify the physical device immediately.
"""

from __future__ import annotations

import http.client
import re
from typing import Dict


_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_MODEL_HINTS = [
    (r"TL-[A-Z0-9\-]+", "TP-LINK"),
    (r"MW\d+[A-Z0-9\-]*|MERCURY|水星", "MERCURY (水星)"),
    (r"FW\d+[A-Z0-9\-]*|FAST|迅捷", "FAST (迅捷)"),
    (r"MiWiFi|小米路由器|Redmi", "Xiaomi (小米)"),
    (r"Tenda|腾达|AC\d{1,2}", "Tenda (腾达)"),
    (r"HUAWEI|荣耀路由|HiLink", "Huawei (华为)"),
    (r"H3C|Magic", "H3C (新华三)"),
    (r"Ruijie|Reyee|锐捷|睿易", "Ruijie (锐捷)"),
    (r"ASUS|RT-[A-Z0-9]+", "ASUS (华硕)"),
    (r"NETGEAR|R\d{4}", "NETGEAR"),
    (r"D-Link|DIR-\d+", "D-Link"),
    (r"OpenWrt|LuCI", "OpenWrt"),
]


def _decode_html(raw: bytes) -> str:
    for enc in ("utf-8", "gb18030", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="ignore")


def probe_router_web(ip: str, timeout: float = 1.5) -> Dict[str, str]:
    """Probe HTTP 80/8080 on a suspected rogue router IP and return title/server/model."""
    if not ip or ip in ("0.0.0.0", "255.255.255.255"):
        return {"title": "", "server": "", "model_hint": "", "port": ""}

    for port in (80, 8080):
        conn = None
        try:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            conn.request(
                "GET",
                "/",
                headers={
                    "User-Agent": "Mozilla/5.0 LoopFinder/1.0",
                    "Accept": "text/html,*/*;q=0.8",
                },
            )
            resp = conn.getresponse()
            server = resp.getheader("Server") or ""
            www_auth = resp.getheader("WWW-Authenticate") or ""
            body = resp.read(16384)
            title = ""
            m = _TITLE_RE.search(body)
            if m:
                title = re.sub(r"\s+", " ", _decode_html(m.group(1))).strip()[:80]

            realm = ""
            rm = re.search(r'realm="([^"]+)"', www_auth)
            if rm:
                realm = rm.group(1).strip()

            combined = f"{title} {realm} {server} {_decode_html(body[:4096])}"
            model_hint = ""
            for pattern, brand in _MODEL_HINTS:
                hm = re.search(pattern, combined, re.IGNORECASE)
                if hm:
                    token = hm.group(0).strip()
                    model_hint = f"{brand} ({token})" if brand.lower() not in token.lower() else token
                    break

            display_title = title or realm or server
            if display_title or model_hint:
                return {
                    "title": display_title,
                    "server": server,
                    "model_hint": model_hint,
                    "port": str(port),
                }
        except Exception:
            continue
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    return {"title": "", "server": "", "model_hint": "", "port": ""}
