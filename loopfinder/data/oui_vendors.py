"""Offline MAC OUI vendor lookup tailored for Chinese campus networks.

Works 100% offline (essential during L2 broadcast storms when internet is down).
Also supports optionally loading a standard IEEE oui.txt file if present.
"""

from __future__ import annotations

import gzip
import os
import re
from typing import Dict, Tuple

from loopfinder.core.paths import resource_path

# Category codes:
# - "soho_router": 家用/小型无线路由器或桌面小交换机（教研室私接环路高发嫌疑）
# - "switch": 企业级网络设备（华为/H3C/锐捷/思科等）
# - "endpoint": 电脑/手机/打印机网卡
# - "iot": 监控/门禁/大屏/IoT
# - "local": 本地管理地址（虚拟网卡/随机MAC/探针）
# - "unknown": 未知厂商

OUI_DB: Dict[str, Tuple[str, str]] = {
    # --- TP-LINK / 普联 (教研室最常见私接路由器与桌面交换机) ---
    "00:0A:EB": ("TP-LINK (普联)", "soho_router"),
    "00:19:E0": ("TP-LINK (普联)", "soho_router"),
    "00:1D:0F": ("TP-LINK (普联)", "soho_router"),
    "00:21:27": ("TP-LINK (普联)", "soho_router"),
    "00:23:CD": ("TP-LINK (普联)", "soho_router"),
    "00:25:86": ("TP-LINK (普联)", "soho_router"),
    "00:27:19": ("TP-LINK (普联)", "soho_router"),
    "10:FE:ED": ("TP-LINK (普联)", "soho_router"),
    "14:CF:92": ("TP-LINK (普联)", "soho_router"),
    "14:E6:E4": ("TP-LINK (普联)", "soho_router"),
    "18:A6:F7": ("TP-LINK (普联)", "soho_router"),
    "1C:FA:68": ("TP-LINK (普联)", "soho_router"),
    "20:DC:E6": ("TP-LINK (普联)", "soho_router"),
    "28:2C:B2": ("TP-LINK (普联)", "soho_router"),
    "30:B5:C2": ("TP-LINK (普联)", "soho_router"),
    "38:83:45": ("TP-LINK (普联)", "soho_router"),
    "40:16:9F": ("TP-LINK (普联)", "soho_router"),
    "48:7D:2E": ("TP-LINK (普联)", "soho_router"),
    "50:3E:AA": ("TP-LINK (普联)", "soho_router"),
    "50:C7:BF": ("TP-LINK (普联)", "soho_router"),
    "54:A7:03": ("TP-LINK (普联)", "soho_router"),
    "54:E6:FC": ("TP-LINK (普联)", "soho_router"),
    "5C:63:BF": ("TP-LINK (普联)", "soho_router"),
    "60:E3:27": ("TP-LINK (普联)", "soho_router"),
    "64:56:01": ("TP-LINK (普联)", "soho_router"),
    "64:66:B3": ("TP-LINK (普联)", "soho_router"),
    "64:70:02": ("TP-LINK (普联)", "soho_router"),
    "6C:B0:CE": ("TP-LINK (普联)", "soho_router"),
    "70:4F:57": ("TP-LINK (普联)", "soho_router"),
    "74:EA:3A": ("TP-LINK (普联)", "soho_router"),
    "78:44:76": ("TP-LINK (普联)", "soho_router"),
    "7C:8B:CA": ("TP-LINK (普联)", "soho_router"),
    "80:89:17": ("TP-LINK (普联)", "soho_router"),
    "84:16:F9": ("TP-LINK (普联)", "soho_router"),
    "8C:21:0A": ("TP-LINK (普联)", "soho_router"),
    "90:F6:52": ("TP-LINK (普联)", "soho_router"),
    "94:0C:6D": ("TP-LINK (普联)", "soho_router"),
    "98:DA:C4": ("TP-LINK (普联)", "soho_router"),
    "A0:F3:C1": ("TP-LINK (普联)", "soho_router"),
    "AC:84:C6": ("TP-LINK (普联)", "soho_router"),
    "B0:4E:26": ("TP-LINK (普联)", "soho_router"),
    "B0:95:75": ("TP-LINK (普联)", "soho_router"),
    "B8:F8:83": ("TP-LINK (普联)", "soho_router"),
    "BC:46:99": ("TP-LINK (普联)", "soho_router"),
    "C0:25:E9": ("TP-LINK (普联)", "soho_router"),
    "C4:6E:1F": ("TP-LINK (普联)", "soho_router"),
    "C4:E9:84": ("TP-LINK (普联)", "soho_router"),
    "C8:3A:35": ("Tenda (腾达)", "soho_router"),
    "CC:32:E5": ("TP-LINK (普联)", "soho_router"),
    "D4:6E:0E": ("TP-LINK (普联)", "soho_router"),
    "D8:07:B6": ("TP-LINK (普联)", "soho_router"),
    "D8:0D:17": ("TP-LINK (普联)", "soho_router"),
    "DC:FE:18": ("TP-LINK (普联)", "soho_router"),
    "E4:D3:32": ("TP-LINK (普联)", "soho_router"),
    "E8:94:F6": ("TP-LINK (普联)", "soho_router"),
    "E8:DE:27": ("TP-LINK (普联)", "soho_router"),
    "EC:08:6B": ("TP-LINK (普联)", "soho_router"),
    "EC:17:2F": ("TP-LINK (普联)", "soho_router"),
    "EC:26:CA": ("TP-LINK (普联)", "soho_router"),
    "F0:F3:36": ("TP-LINK (普联)", "soho_router"),
    "F4:EC:38": ("TP-LINK (普联)", "soho_router"),
    "F8:1A:67": ("TP-LINK (普联)", "soho_router"),
    "F8:D1:11": ("TP-LINK (普联)", "soho_router"),

    # --- MERCURY (水星) & FAST (迅捷) ---
    "00:1D:0E": ("MERCURY (水星)", "soho_router"),
    "14:75:90": ("MERCURY (水星)", "soho_router"),
    "24:69:68": ("MERCURY (水星)", "soho_router"),
    "34:96:72": ("MERCURY (水星)", "soho_router"),
    "38:83:46": ("MERCURY (水星)", "soho_router"),
    "48:0E:EC": ("MERCURY (水星)", "soho_router"),
    "50:BD:5F": ("MERCURY (水星)", "soho_router"),
    "5C:DE:34": ("MERCURY (水星)", "soho_router"),
    "6C:59:40": ("MERCURY (水星)", "soho_router"),
    "78:A1:06": ("MERCURY (水星)", "soho_router"),
    "88:25:93": ("MERCURY (水星)", "soho_router"),
    "8C:AB:8E": ("MERCURY (水星)", "soho_router"),
    "A8:15:4D": ("MERCURY (水星)", "soho_router"),
    "B4:A5:AC": ("MERCURY (水星)", "soho_router"),
    "BC:D1:77": ("MERCURY (水星)", "soho_router"),
    "C0:61:18": ("MERCURY (水星)", "soho_router"),
    "CC:08:FB": ("MERCURY (水星)", "soho_router"),
    "D0:C7:C0": ("MERCURY (水星)", "soho_router"),
    "E0:05:C5": ("MERCURY (水星)", "soho_router"),
    "EC:88:8F": ("MERCURY (水星)", "soho_router"),
    "F4:83:CD": ("MERCURY (水星)", "soho_router"),
    "00:0A:EC": ("FAST (迅捷)", "soho_router"),
    "08:10:74": ("FAST (迅捷)", "soho_router"),
    "1C:60:DE": ("FAST (迅捷)", "soho_router"),
    "28:6C:07": ("Xiaomi (小米)", "soho_router"),
    "3C:46:D8": ("FAST (迅捷)", "soho_router"),
    "40:3F:8C": ("FAST (迅捷)", "soho_router"),
    "54:75:95": ("FAST (迅捷)", "soho_router"),
    "70:AF:6A": ("FAST (迅捷)", "soho_router"),
    "80:8F:1D": ("FAST (迅捷)", "soho_router"),
    "9C:21:6A": ("FAST (迅捷)", "soho_router"),
    "B8:55:10": ("FAST (迅捷)", "soho_router"),
    "D4:83:04": ("FAST (迅捷)", "soho_router"),
    "EC:6C:9F": ("FAST (迅捷)", "soho_router"),

    # --- Tenda (腾达) ---
    "00:B0:0C": ("Tenda (腾达)", "soho_router"),
    "04:95:E6": ("Tenda (腾达)", "soho_router"),
    "08:40:F3": ("Tenda (腾达)", "soho_router"),
    "50:0F:F5": ("Tenda (腾达)", "soho_router"),
    "58:D9:D5": ("Tenda (腾达)", "soho_router"),
    "B4:0F:3B": ("Tenda (腾达)", "soho_router"),
    "CC:2D:21": ("Tenda (腾达)", "soho_router"),
    "D8:32:14": ("Tenda (腾达)", "soho_router"),
    "E8:65:D4": ("Tenda (腾达)", "soho_router"),

    # --- Xiaomi (小米/红米路由器) ---
    "0C:1D:AF": ("Xiaomi (小米)", "soho_router"),
    "14:F6:5A": ("Xiaomi (小米)", "soho_router"),
    "20:82:C0": ("Xiaomi (小米)", "soho_router"),
    "34:CE:00": ("Xiaomi (小米)", "soho_router"),
    "40:31:3C": ("Xiaomi (小米)", "soho_router"),
    "50:64:2B": ("Xiaomi (小米)", "soho_router"),
    "64:09:80": ("Xiaomi (小米)", "soho_router"),
    "64:B4:73": ("Xiaomi (小米)", "soho_router"),
    "74:23:44": ("Xiaomi (小米)", "soho_router"),
    "78:11:DC": ("Xiaomi (小米)", "soho_router"),
    "88:C3:97": ("Xiaomi (小米)", "soho_router"),
    "9C:9D:7E": ("Xiaomi (小米)", "soho_router"),
    "C4:0B:CB": ("Xiaomi (小米)", "soho_router"),
    "D4:97:0B": ("Xiaomi (小米)", "soho_router"),
    "F0:B4:29": ("Xiaomi (小米)", "soho_router"),
    "F4:8B:32": ("Xiaomi (小米)", "soho_router"),
    "FC:64:BA": ("Xiaomi (小米)", "soho_router"),

    # --- Netcore (磊科) / D-Link / NETGEAR / ASUS / Linksys / Phicomm ---
    "00:0F:E2": ("H3C (新华三)", "switch"),
    "04:8D:38": ("Netcore (磊科)", "soho_router"),
    "08:10:76": ("Netcore (磊科)", "soho_router"),
    "CC:B2:55": ("D-Link", "soho_router"),
    "00:05:5D": ("D-Link", "soho_router"),
    "00:17:9A": ("D-Link", "soho_router"),
    "00:1B:11": ("D-Link", "soho_router"),
    "00:22:B0": ("D-Link", "soho_router"),
    "14:D6:4D": ("D-Link", "soho_router"),
    "1C:7E:E5": ("D-Link", "soho_router"),
    "28:10:7B": ("D-Link", "soho_router"),
    "34:08:04": ("D-Link", "soho_router"),
    "84:C9:B2": ("D-Link", "soho_router"),
    "B8:A3:86": ("D-Link", "soho_router"),
    "C8:BE:19": ("D-Link", "soho_router"),
    "00:09:5B": ("NETGEAR (网件)", "soho_router"),
    "00:14:6C": ("NETGEAR (网件)", "soho_router"),
    "00:1E:2A": ("NETGEAR (网件)", "soho_router"),
    "00:24:B2": ("NETGEAR (网件)", "soho_router"),
    "20:4E:7F": ("NETGEAR (网件)", "soho_router"),
    "28:C6:8E": ("NETGEAR (网件)", "soho_router"),
    "44:94:FC": ("NETGEAR (网件)", "soho_router"),
    "A0:21:B7": ("NETGEAR (网件)", "soho_router"),
    "C0:3F:0E": ("NETGEAR (网件)", "soho_router"),
    "E0:91:F5": ("NETGEAR (网件)", "soho_router"),
    "04:92:26": ("ASUS (华硕)", "soho_router"),
    "08:60:6E": ("ASUS (华硕)", "soho_router"),
    "10:BF:48": ("ASUS (华硕)", "soho_router"),
    "1C:87:2C": ("ASUS (华硕)", "soho_router"),
    "2C:4D:54": ("ASUS (华硕)", "soho_router"),
    "30:85:A9": ("ASUS (华硕)", "soho_router"),
    "38:D5:47": ("ASUS (华硕)", "soho_router"),
    "50:46:5D": ("ASUS (华硕)", "soho_router"),
    "60:45:CB": ("ASUS (华硕)", "soho_router"),
    "74:D0:2B": ("ASUS (华硕)", "soho_router"),
    "AC:22:0B": ("ASUS (华硕)", "soho_router"),
    "BC:EE:7B": ("ASUS (华硕)", "soho_router"),
    "F0:79:59": ("ASUS (华硕)", "soho_router"),
    "00:0C:41": ("Linksys", "soho_router"),
    "00:14:BF": ("Linksys", "soho_router"),
    "20:AA:4B": ("Linksys", "soho_router"),
    "C0:56:27": ("Linksys", "soho_router"),
    "D8:C8:E9": ("PHICOMM (斐讯)", "soho_router"),
    "FC:7C:02": ("PHICOMM (斐讯)", "soho_router"),
    "2C:B2:1A": ("PHICOMM (斐讯)", "soho_router"),
    "D4:EE:07": ("HiWiFi (极路由)", "soho_router"),
    "00:1F:A3": ("360 Router", "soho_router"),

    # --- 企业交换机：Huawei (华为) ---
    "00:18:82": ("Huawei (华为)", "switch"),
    "00:1E:10": ("Huawei (华为)", "switch"),
    "00:25:68": ("Huawei (华为)", "switch"),
    "00:25:9E": ("Huawei (华为)", "switch"),
    "00:46:4B": ("Huawei (华为)", "switch"),
    "00:E0:FC": ("Huawei (华为)", "switch"),
    "04:BD:70": ("Huawei (华为)", "switch"),
    "04:C0:6F": ("Huawei (华为)", "switch"),
    "04:F9:38": ("Huawei (华为)", "switch"),
    "08:19:A6": ("Huawei (华为)", "switch"),
    "0C:37:DC": ("Huawei (华为)", "switch"),
    "10:1B:54": ("Huawei (华为)", "switch"),
    "10:47:80": ("Huawei (华为)", "switch"),
    "14:B9:68": ("Huawei (华为)", "switch"),
    "18:C5:8A": ("Huawei (华为)", "switch"),
    "20:0B:C7": ("Huawei (华为)", "switch"),
    "20:2B:C1": ("Huawei (华为)", "switch"),
    "24:09:95": ("Huawei (华为)", "switch"),
    "28:31:52": ("Huawei (华为)", "switch"),
    "28:6E:D4": ("Huawei (华为)", "switch"),
    "34:6B:D3": ("Huawei (华为)", "switch"),
    "38:F8:89": ("Huawei (华为)", "switch"),
    "48:46:FB": ("Huawei (华为)", "switch"),
    "4C:1F:CC": ("Huawei (华为)", "switch"),
    "54:89:98": ("Huawei (华为)", "switch"),
    "58:2A:F7": ("Huawei (华为)", "switch"),
    "60:DE:44": ("Huawei (华为)", "switch"),
    "68:A0:F6": ("Huawei (华为)", "switch"),
    "70:72:3C": ("Huawei (华为)", "switch"),
    "78:1D:BA": ("Huawei (华为)", "switch"),
    "80:B6:86": ("Huawei (华为)", "switch"),
    "84:A8:E4": ("Huawei (华为)", "switch"),
    "88:28:B3": ("Huawei (华为)", "switch"),
    "8C:34:FD": ("Huawei (华为)", "switch"),
    "94:04:9C": ("Huawei (华为)", "switch"),
    "A4:99:47": ("Huawei (华为)", "switch"),
    "AC:E2:15": ("Huawei (华为)", "switch"),
    "B4:30:52": ("Huawei (华为)", "switch"),
    "C4:FF:1F": ("Huawei (华为)", "switch"),
    "CC:A2:23": ("Huawei (华为)", "switch"),
    "D4:6A:A8": ("Huawei (华为)", "switch"),
    "DC:D2:FC": ("Huawei (华为)", "switch"),
    "E0:24:7F": ("Huawei (华为)", "switch"),
    "E8:CD:2D": ("Huawei (华为)", "switch"),
    "F4:55:9C": ("Huawei (华为)", "switch"),
    "FC:48:EF": ("Huawei (华为)", "switch"),

    # --- 企业交换机：H3C (新华三) ---
    "00:23:89": ("H3C (新华三)", "switch"),
    "0C:DA:41": ("H3C (新华三)", "switch"),
    "14:3E:BF": ("H3C (新华三)", "switch"),
    "2C:23:3A": ("H3C (新华三)", "switch"),
    "38:22:D6": ("H3C (新华三)", "switch"),
    "38:91:D5": ("H3C (新华三)", "switch"),
    "3C:E5:A6": ("H3C (新华三)", "switch"),
    "44:31:92": ("H3C (新华三)", "switch"),
    "48:7A:DA": ("H3C (新华三)", "switch"),
    "58:66:BA": ("H3C (新华三)", "switch"),
    "5C:DD:70": ("H3C (新华三)", "switch"),
    "6C:0B:84": ("H3C (新华三)", "switch"),
    "70:BA:EF": ("H3C (新华三)", "switch"),
    "70:F9:6D": ("H3C (新华三)", "switch"),
    "74:25:8A": ("H3C (新华三)", "switch"),
    "80:F6:2E": ("H3C (新华三)", "switch"),
    "84:D9:31": ("H3C (新华三)", "switch"),
    "88:DF:9E": ("H3C (新华三)", "switch"),
    "94:28:2E": ("H3C (新华三)", "switch"),
    "9C:D6:43": ("H3C (新华三)", "switch"),
    "A4:FA:76": ("H3C (新华三)", "switch"),
    "B8:AF:67": ("H3C (新华三)", "switch"),
    "C4:CA:D9": ("H3C (新华三)", "switch"),
    "CC:3E:5F": ("H3C (新华三)", "switch"),
    "D0:7E:28": ("H3C (新华三)", "switch"),
    "DC:9F:DB": ("Ubiquiti (UBNT)", "switch"),
    "E0:05:13": ("H3C (新华三)", "switch"),
    "E8:F7:24": ("H3C (新华三)", "switch"),
    "F4:EA:67": ("H3C (新华三)", "switch"),

    # --- 企业交换机：Ruijie (锐捷网络 - 高校极常见) ---
    "00:1A:A9": ("Ruijie (锐捷)", "switch"),
    "00:D0:F8": ("Ruijie (锐捷)", "switch"),
    "10:82:3D": ("Ruijie (锐捷)", "switch"),
    "14:14:4B": ("Ruijie (锐捷)", "switch"),
    "30:0D:9E": ("Ruijie (锐捷)", "switch"),
    "58:69:6C": ("Ruijie (锐捷)", "switch"),
    "70:54:F5": ("Ruijie (锐捷)", "switch"),
    "80:05:88": ("Ruijie (锐捷)", "switch"),
    "8C:25:05": ("Ruijie (锐捷)", "switch"),
    "B4:09:31": ("Ruijie (锐捷)", "switch"),
    "CC:B8:A8": ("Ruijie (锐捷)", "switch"),
    "E0:67:B3": ("Ruijie (锐捷)", "switch"),
    "EC:B9:70": ("Ruijie (锐捷)", "switch"),

    # --- 企业交换机：Cisco / ZTE / Aruba / Juniper / MikroTik ---
    "00:00:0C": ("Cisco (思科)", "switch"),
    "00:01:42": ("Cisco (思科)", "switch"),
    "00:0A:41": ("Cisco (思科)", "switch"),
    "00:0C:29": ("VMware (虚拟机)", "endpoint"),
    "00:0C:85": ("Cisco (思科)", "switch"),
    "00:12:DA": ("Cisco (思科)", "switch"),
    "00:1B:D4": ("Cisco (思科)", "switch"),
    "00:1E:13": ("Cisco (思科)", "switch"),
    "00:21:D8": ("Cisco (思科)", "switch"),
    "00:26:CB": ("Cisco (思科)", "switch"),
    "00:50:56": ("VMware (虚拟机)", "endpoint"),
    "08:00:27": ("VirtualBox (虚拟机)", "endpoint"),
    "1C:DF:0F": ("Cisco (思科)", "switch"),
    "2C:3F:38": ("Cisco (思科)", "switch"),
    "3C:08:F6": ("Cisco (思科)", "switch"),
    "58:97:BD": ("Cisco (思科)", "switch"),
    "64:A0:E7": ("Cisco (思科)", "switch"),
    "70:CA:9B": ("Cisco (思科)", "switch"),
    "88:5A:92": ("Cisco (思科)", "switch"),
    "A4:6C:2A": ("Cisco (思科)", "switch"),
    "BC:16:65": ("Cisco (思科)", "switch"),
    "CC:EF:48": ("Cisco (思科)", "switch"),
    "D4:8C:B5": ("Cisco (思科)", "switch"),
    "F4:CF:E2": ("Cisco (思科)", "switch"),
    "00:19:C6": ("ZTE (中兴)", "switch"),
    "00:1E:73": ("ZTE (中兴)", "switch"),
    "2C:26:C5": ("ZTE (中兴)", "switch"),
    "68:1A:B2": ("ZTE (中兴)", "switch"),
    "74:A7:8E": ("ZTE (中兴)", "switch"),
    "D0:15:4A": ("ZTE (中兴)", "switch"),
    "00:0B:86": ("Aruba / HPE", "switch"),
    "24:DE:C6": ("Aruba / HPE", "switch"),
    "9C:1C:12": ("Aruba / HPE", "switch"),
    "D8:C7:C8": ("Aruba / HPE", "switch"),
    "00:0C:42": ("MikroTik", "switch"),
    "4C:5E:0C": ("MikroTik", "switch"),
    "64:D1:54": ("MikroTik", "switch"),
    "B8:69:F4": ("MikroTik", "switch"),
    "D4:CA:6D": ("MikroTik", "switch"),
    "E4:8D:8C": ("MikroTik", "switch"),

    # --- 常见终端网卡 / PC / 苹果 / 打印机 / 监控 ---
    "00:E0:4C": ("Realtek (瑞昱网卡)", "endpoint"),
    "52:54:00": ("QEMU/KVM (虚拟机)", "endpoint"),
    "00:15:5D": ("Hyper-V (虚拟机)", "endpoint"),
    "00:1B:21": ("Intel (英特尔网卡)", "endpoint"),
    "00:1E:67": ("Intel (英特尔网卡)", "endpoint"),
    "00:21:6A": ("Intel (英特尔网卡)", "endpoint"),
    "00:24:D7": ("Intel (英特尔网卡)", "endpoint"),
    "18:5E:0F": ("Intel (英特尔网卡)", "endpoint"),
    "3C:97:0E": ("Lenovo / Wistron", "endpoint"),
    "48:2A:E3": ("Lenovo (联想)", "endpoint"),
    "54:EE:75": ("Lenovo (联想)", "endpoint"),
    "8C:EC:4B": ("Dell (戴尔)", "endpoint"),
    "B8:2A:72": ("Dell (戴尔)", "endpoint"),
    "D4:BE:D9": ("Dell (戴尔)", "endpoint"),
    "F8:B1:56": ("Dell (戴尔)", "endpoint"),
    "00:1A:4B": ("HP (惠普)", "endpoint"),
    "10:60:4B": ("HP (惠普)", "endpoint"),
    "3C:D9:2B": ("HP (惠普)", "endpoint"),
    "94:57:A5": ("HP (惠普)", "endpoint"),
    "B4:B5:2F": ("HP (惠普)", "endpoint"),
    "00:03:93": ("Apple (苹果)", "endpoint"),
    "00:17:F2": ("Apple (苹果)", "endpoint"),
    "00:25:00": ("Apple (苹果)", "endpoint"),
    "14:10:9F": ("Apple (苹果)", "endpoint"),
    "28:CF:E9": ("Apple (苹果)", "endpoint"),
    "3C:15:C2": ("Apple (苹果)", "endpoint"),
    "40:6C:8F": ("Apple (苹果)", "endpoint"),
    "60:F8:1D": ("Apple (苹果)", "endpoint"),
    "78:31:C1": ("Apple (苹果)", "endpoint"),
    "88:66:A5": ("Apple (苹果)", "endpoint"),
    "A4:83:E7": ("Apple (苹果)", "endpoint"),
    "AC:BC:32": ("Apple (苹果)", "endpoint"),
    "BC:52:B7": ("Apple (苹果)", "endpoint"),
    "DC:A9:04": ("Apple (苹果)", "endpoint"),
    "F0:18:98": ("Apple (苹果)", "endpoint"),
    "F4:5C:89": ("Apple (苹果)", "endpoint"),
    "B8:27:EB": ("Raspberry Pi", "endpoint"),
    "DC:A6:32": ("Raspberry Pi", "endpoint"),
    "E4:5F:01": ("Raspberry Pi", "endpoint"),
    "00:11:32": ("Synology (群晖NAS)", "endpoint"),
    "00:17:C8": ("Kyocera (京瓷打印机)", "endpoint"),
    "00:26:73": ("Ricoh (理光打印机)", "endpoint"),
    "00:1E:8F": ("Canon (佳能打印机)", "endpoint"),
    "00:26:AB": ("Epson (爱普生打印机)", "endpoint"),
    "28:57:BE": ("Hikvision (海康威视)", "iot"),
    "44:19:B6": ("Hikvision (海康威视)", "iot"),
    "54:C4:15": ("Hikvision (海康威视)", "iot"),
    "A4:14:37": ("Hikvision (海康威视)", "iot"),
    "BC:AD:28": ("Hikvision (海康威视)", "iot"),
    "C0:56:E3": ("Hikvision (海康威视)", "iot"),
    "14:A7:8B": ("Dahua (大华监控)", "iot"),
    "3C:EF:8C": ("Dahua (大华监控)", "iot"),
    "4C:11:BF": ("Dahua (大华监控)", "iot"),
    "90:02:A9": ("Dahua (大华监控)", "iot"),
    "A0:BD:1D": ("Dahua (大华监控)", "iot"),
    "E0:50:8B": ("Dahua (大华监控)", "iot"),
}

CATEGORY_LABELS = {
    "soho_router": "家用路由器/小交换机",
    "switch": "企业网管交换机",
    "endpoint": "电脑/终端",
    "iot": "监控/IoT",
    "local": "本地/虚拟MAC",
    "unknown": "未知设备",
}

_EXTERNAL_LOADED = False
_IEEE_DB: Dict[str, str] = {}

# Order matters: more specific rules (e.g. "huawei device" consumer routers) come before broader ones ("huawei").
_VENDOR_RULES = (
    # Consumer / SOHO Routers & Desktop Switches (教研室高频)
    (("huawei device",), "Huawei (华为终端/路由)", "soho_router"),
    (("honor device",), "HONOR (荣耀)", "soho_router"),
    (("tp-link", "tplink"), "TP-LINK (普联)", "soho_router"),
    (("xiaomi", "mi wifi", "redmi"), "Xiaomi (小米/红米)", "soho_router"),
    (("mercury",), "MERCURY (水星)", "soho_router"),
    (("shenzhen fast", "fast technologies"), "FAST (迅捷)", "soho_router"),
    (("tenda",), "Tenda (腾达)", "soho_router"),
    (("asustek", "asus "), "ASUS (华硕)", "soho_router"),
    (("d-link",), "D-Link (友讯)", "soho_router"),
    (("netgear",), "NETGEAR (网件)", "soho_router"),
    (("totolink", "zioncom"), "TOTOLINK", "soho_router"),
    (("linksys", "belkin"), "Linksys", "soho_router"),
    (("phicomm", "feixun"), "Phicomm (斐讯)", "soho_router"),
    (("shenzhen bilian", "lb-link"), "LB-LINK (必联)", "soho_router"),
    (("netcore", "netis"), "Netcore (磊科)", "soho_router"),
    (("shenzhen gongjin", "t&w"), "共进/T&W (代工路由)", "soho_router"),
    (("hiwifi", "geewifi"), "极路由 (HiWiFi)", "soho_router"),
    (("qihoo", "360 "), "360 路由", "soho_router"),
    (("gl technologies", "gl.inet"), "GL.iNet 路由", "soho_router"),
    (("mercusys",), "Mercusys (水星海外)", "soho_router"),
    (("cudy",), "Cudy 路由", "soho_router"),
    (("edimax",), "Edimax", "soho_router"),
    (("buffalo",), "Buffalo", "soho_router"),
    (("china mobile", "cmcc"), "中国移动 (光猫/路由)", "soho_router"),
    (("china telecom", "tianyi"), "中国电信 (天翼/光猫)", "soho_router"),
    (("china unicom",), "中国联通 (光猫/路由)", "soho_router"),
    # Enterprise Managed Switches / APs (机房/弱电间常见)
    (("huawei",), "Huawei (华为)", "switch"),
    (("new h3c", "hangzhou h3c", "h3c "), "H3C (新华三)", "switch"),
    (("ruijie",), "Ruijie (锐捷)", "switch"),
    (("cisco",), "Cisco (思科)", "switch"),
    (("zte ", "zte corporation"), "ZTE (中兴)", "switch"),
    (("aruba", "hewlett packard enterprise"), "HPE / Aruba", "switch"),
    (("juniper",), "Juniper", "switch"),
    (("digital china", "dcnetworks"), "神州数码 (DCN)", "switch"),
    (("maipu",), "迈普 (Maipu)", "switch"),
    (("raisecom",), "瑞斯康达 (Raisecom)", "switch"),
    (("bdcom", "baud data"), "博达 (BDCOM)", "switch"),
    (("fiberhome",), "烽火 (FiberHome)", "switch"),
    (("sangfor",), "深信服 (Sangfor)", "switch"),
    (("ubiquiti",), "Ubiquiti (UBNT)", "switch"),
    (("mikrotik", "routerboard"), "MikroTik", "switch"),
    (("fortinet",), "Fortinet (飞塔)", "switch"),
    (("extreme networks",), "Extreme", "switch"),
    (("brocade", "ruckus"), "Ruckus / Brocade", "switch"),
    (("allied telesis",), "Allied Telesis", "switch"),
    (("sundray",), "信锐 (Sundray)", "switch"),
    # Cameras / IoT
    (("hikvision",), "Hikvision (海康威视)", "iot"),
    (("dahua",), "Dahua (大华)", "iot"),
    (("uniview",), "Uniview (宇视)", "iot"),
    (("ezviz",), "萤石 (EZVIZ)", "iot"),
    (("espressif",), "Espressif (乐鑫 IoT)", "iot"),
    (("tuya",), "Tuya (涂鸦 IoT)", "iot"),
    # Common Endpoints / Computers / Phones
    (("apple",), "Apple", "endpoint"),
    (("intel ", "intel corporate"), "Intel", "endpoint"),
    (("realtek",), "Realtek", "endpoint"),
    (("dell ", "dell inc"), "Dell (戴尔)", "endpoint"),
    (("lenovo", "lcfc(hefei)"), "Lenovo (联想)", "endpoint"),
    (("hp inc", "hewlett packard"), "HP (惠普)", "endpoint"),
    (("samsung",), "Samsung (三星)", "endpoint"),
    (("vivo mobile",), "vivo", "endpoint"),
    (("guangdong oppo", "oppo "), "OPPO", "endpoint"),
    (("oneplus",), "OnePlus (一加)", "endpoint"),
    (("microsoft",), "Microsoft", "endpoint"),
    (("vmware",), "VMware 虚拟网卡", "endpoint"),
    (("asix electronics",), "ASIX USB网卡", "endpoint"),
)


def _classify_vendor(raw_name: str) -> Tuple[str, str]:
    """Map an IEEE registry vendor string to a friendly display name and device category."""
    clean = raw_name.strip()
    low = clean.lower()
    for keywords, label, cat in _VENDOR_RULES:
        if any(k in low for k in keywords):
            return label, cat
    return clean, "endpoint"


def normalize_mac(mac: str) -> str:
    """Normalize any MAC representation (aa-bb-cc-dd-ee-ff, aabb.ccdd.eeff, etc.) to AA:BB:CC:DD:EE:FF."""
    if not mac:
        return ""
    hex_only = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(hex_only) != 12:
        return mac.strip().upper()
    return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))


def _load_external_oui() -> None:
    """Load bundled compressed IEEE MA-L/MA-M/MA-S OUI registry (+ optional external oui.txt)."""
    global _EXTERNAL_LOADED
    if _EXTERNAL_LOADED:
        return
    _EXTERNAL_LOADED = True

    # 1. Bundled 58,000+ official IEEE OUI table (works from source & inside PyInstaller bundles)
    gz_candidates = [
        resource_path("loopfinder", "data", "oui_ieee.tsv.gz"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui_ieee.tsv.gz"),
    ]
    for gz_path in gz_candidates:
        if not os.path.isfile(gz_path):
            continue
        try:
            with gzip.open(gz_path, "rt", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if "\t" not in line:
                        continue
                    key, val = line.rstrip("\r\n").split("\t", 1)
                    if key and val:
                        _IEEE_DB[key] = val
            break
        except OSError:
            pass

    # 2. Optional user-supplied plain oui.txt override
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "oui.txt"),
        os.path.join(os.path.dirname(os.path.dirname(here)), "oui.txt"),
    ]
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    m = re.match(r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$", line)
                    if not m:
                        continue
                    key = f"{m.group(1)}{m.group(2)}{m.group(3)}".upper()
                    if key not in _IEEE_DB:
                        _IEEE_DB[key] = m.group(4).strip()
        except OSError:
            pass
        break


def oui_database_size() -> int:
    """Return total number of loaded offline OUI prefixes (curated + bundled IEEE)."""
    _load_external_oui()
    return len(_IEEE_DB) + len(OUI_DB)


def lookup_mac_vendor(mac: str) -> Dict[str, str]:
    """Return {'vendor': ..., 'category': ..., 'category_label': ...} for a MAC address."""
    _load_external_oui()
    norm = normalize_mac(mac)
    if len(norm) < 8:
        return {
            "vendor": "未知厂商",
            "category": "unknown",
            "category_label": CATEGORY_LABELS["unknown"],
        }
    if norm == "FF:FF:FF:FF:FF:FF":
        return {"vendor": "以太网广播", "category": "local", "category_label": "广播地址"}

    hex_clean = norm.replace(":", "")
    prefix24 = norm[:8]

    # 1. Most specific IEEE MA-S (/36) and MA-M (/28) prefixes first
    for plen in (9, 7):
        if len(hex_clean) >= plen:
            raw_ieee = _IEEE_DB.get(hex_clean[:plen])
            if raw_ieee:
                vendor, cat = _classify_vendor(raw_ieee)
                return {
                    "vendor": vendor,
                    "category": cat,
                    "category_label": CATEGORY_LABELS.get(cat, "未知设备"),
                }

    # 2. Hand-curated Chinese campus OUI priority table (24-bit)
    if prefix24 in OUI_DB:
        vendor, cat = OUI_DB[prefix24]
        return {
            "vendor": vendor,
            "category": cat,
            "category_label": CATEGORY_LABELS.get(cat, "未知设备"),
        }

    # 3. Full bundled IEEE MA-L (/24) registry (40,000+ prefixes)
    if len(hex_clean) >= 6:
        raw_ieee = _IEEE_DB.get(hex_clean[:6])
        if raw_ieee:
            vendor, cat = _classify_vendor(raw_ieee)
            return {
                "vendor": vendor,
                "category": cat,
                "category_label": CATEGORY_LABELS.get(cat, "未知设备"),
            }

    # 4. Multicast / locally administered MAC check
    try:
        first_byte = int(norm[:2], 16)
        if first_byte & 0x01:
            return {"vendor": "组播地址", "category": "local", "category_label": "组播"}
        if first_byte & 0x02:
            if norm.startswith("02:4C:4F:4F:50"):
                return {"vendor": "LoopFinder 主动探针", "category": "local", "category_label": "本机探针"}
            return {"vendor": "随机/虚拟 MAC", "category": "local", "category_label": CATEGORY_LABELS["local"]}
    except ValueError:
        pass
    return {
        "vendor": f"未知厂商 ({prefix24})",
        "category": "unknown",
        "category_label": CATEGORY_LABELS["unknown"],
    }
