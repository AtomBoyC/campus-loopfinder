"""Pure-Python standard libpcap (.pcap) writer for Wireshark inspection.

Zero external dependencies: writes classic microsecond libpcap format
(magic 0xA1B2C3D4, LINKTYPE_ETHERNET = 1) directly openable in Wireshark/tcpdump.
"""

from __future__ import annotations

import struct
from typing import Iterable, Tuple

PCAP_GLOBAL_HDR = struct.pack(
    "<IHHiIII",
    0xA1B2C3D4,  # magic number (little-endian microsecond resolution)
    2,           # major version
    4,           # minor version
    0,           # GMT to local correction
    0,           # accuracy of timestamps
    65535,       # snaplen
    1,           # LINKTYPE_ETHERNET
)


def build_pcap_bytes(frames: Iterable[Tuple[float, bytes]]) -> bytes:
    """Serialize an iterable of (unix_timestamp_float, raw_ethernet_bytes) into .pcap bytes."""
    chunks = [PCAP_GLOBAL_HDR]
    for ts, raw in frames:
        if not raw:
            continue
        sec = int(ts)
        usec = max(0, min(999999, int((ts - sec) * 1_000_000)))
        caplen = min(len(raw), 65535)
        pkt_hdr = struct.pack("<IIII", sec, usec, caplen, len(raw))
        chunks.append(pkt_hdr)
        chunks.append(raw[:caplen])
    return b"".join(chunks)
