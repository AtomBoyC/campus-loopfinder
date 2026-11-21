"""Native macOS BPF (/dev/bpf*) zero-dependency Layer-2 raw capture and injection.

Uses exact ioctl numbers and struct layouts verified against macOS SDK <net/bpf.h>.
Crucially sets BIOCSSEESENT=0 so locally injected active loop probe frames are NEVER
echoed back by the local kernel—any probe frame received back on the BPF fd is
guaranteed to have physically looped back over the Ethernet wire.
"""

from __future__ import annotations

import errno
import fcntl
import os
import select
import struct
import time
from typing import Iterator, Optional, Tuple

# Verified against macOS 64-bit <net/bpf.h>
BIOCGBLEN = 0x40044266
BIOCSBLEN = 0xC0044266
BIOCSETIF = 0x8020426C
BIOCIMMEDIATE = 0x80044270
BIOCPROMISC = 0x20004269
BIOCSSEESENT = 0x80044277
BIOCSHDRCMPLT = 0x80044275
BIOCSRTIMEOUT = 0x8010426D
BIOCGDLT = 0x4004426A

BPF_ALIGNMENT = 4
BPF_HDR_FMT = "<IIIIH"  # tv_sec(u32), tv_usec(u32), caplen(u32), datalen(u32), hdrlen(u16)
BPF_HDR_MIN_SIZE = struct.calcsize(BPF_HDR_FMT)  # 18 bytes (padded to 20 bytes)
DLT_EN10MB = 1


def _bpf_wordalign(x: int) -> int:
    return (x + (BPF_ALIGNMENT - 1)) & ~(BPF_ALIGNMENT - 1)


class MacBPFSocket:
    """Raw Ethernet reader/writer on macOS using /dev/bpf*."""

    def __init__(
        self,
        interface: str,
        promisc: bool = True,
        see_sent: bool = False,
        buf_size: int = 131072,
        read_timeout: float = 0.25,
    ) -> None:
        self.interface = interface
        self.fd: Optional[int] = None
        self.buf_size = buf_size
        self.dlt = DLT_EN10MB
        self._open(promisc=promisc, see_sent=see_sent, buf_size=buf_size, read_timeout=read_timeout)

    def _open(self, promisc: bool, see_sent: bool, buf_size: int, read_timeout: float) -> None:
        last_err: Optional[OSError] = None
        for idx in range(64):
            path = f"/dev/bpf{idx}"
            try:
                fd = os.open(path, os.O_RDWR)
                self.fd = fd
                break
            except OSError as e:
                last_err = e
                if e.errno in (errno.EBUSY, errno.ENOENT):
                    continue
                if e.errno in (errno.EACCES, errno.EPERM):
                    raise PermissionError(
                        f"无权限打开 {path}（需要 root 或 ChmodBPF 权限）。"
                        "请双击 启动_macOS.command 或使用 `sudo python3 app.py` 启动。"
                    ) from e
        if self.fd is None:
            raise RuntimeError(f"无法打开任何 /dev/bpf 设备: {last_err}")

        try:
            # 1. Request buffer size before binding interface
            try:
                res = fcntl.ioctl(self.fd, BIOCSBLEN, struct.pack("I", buf_size))
                self.buf_size = struct.unpack("I", res)[0]
            except OSError:
                res = fcntl.ioctl(self.fd, BIOCGBLEN, struct.pack("I", 0))
                self.buf_size = struct.unpack("I", res)[0]

            # 2. Bind to Ethernet interface (struct ifreq is 32 bytes on macOS)
            if_bytes = self.interface.encode("ascii")[:15]
            ifreq = struct.pack("16s16x", if_bytes)
            fcntl.ioctl(self.fd, BIOCSETIF, ifreq)

            # 3. Verify Ethernet link type
            dlt_res = fcntl.ioctl(self.fd, BIOCGDLT, struct.pack("I", 0))
            self.dlt = struct.unpack("I", dlt_res)[0]

            # 4. Immediate mode so frames arrive without waiting for buffer fill
            fcntl.ioctl(self.fd, BIOCIMMEDIATE, struct.pack("I", 1))

            # 5. Promiscuous mode to hear all broadcast/multicast/neighbor traffic
            if promisc:
                try:
                    fcntl.ioctl(self.fd, BIOCPROMISC)
                except OSError:
                    pass

            # 6. Disable seeing locally sent frames (prevents false loop detection!)
            try:
                fcntl.ioctl(self.fd, BIOCSSEESENT, struct.pack("I", 1 if see_sent else 0))
            except OSError:
                pass

            # 7. Allow writing complete Ethernet headers (custom source MAC for probe)
            try:
                fcntl.ioctl(self.fd, BIOCSHDRCMPLT, struct.pack("I", 1))
            except OSError:
                pass

            # 8. Read timeout
            sec = int(read_timeout)
            usec = int((read_timeout - sec) * 1_000_000)
            fcntl.ioctl(self.fd, BIOCSRTIMEOUT, struct.pack("qq", sec, usec))
        except Exception:
            self.close()
            raise

    def send_frame(self, raw_frame: bytes) -> int:
        if self.fd is None:
            raise RuntimeError("BPF socket is closed")
        return os.write(self.fd, raw_frame)

    def read_frames(self, timeout: float = 0.25) -> Iterator[Tuple[float, bytes]]:
        """Read available raw Ethernet frames from the BPF buffer."""
        if self.fd is None:
            return
        rlist, _, _ = select.select([self.fd], [], [], timeout)
        if not rlist:
            return
        try:
            data = os.read(self.fd, self.buf_size)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EINTR, errno.EBADF):
                return
            raise
        pos = 0
        total = len(data)
        while pos + BPF_HDR_MIN_SIZE <= total:
            tv_sec, tv_usec, caplen, _datalen, hdrlen = struct.unpack_from(BPF_HDR_FMT, data, pos)
            if hdrlen < BPF_HDR_MIN_SIZE or pos + hdrlen + caplen > total:
                break
            ts = tv_sec + tv_usec / 1_000_000.0
            if ts <= 0:
                ts = time.time()
            frame = data[pos + hdrlen : pos + hdrlen + caplen]
            yield ts, frame
            step = _bpf_wordalign(hdrlen + caplen)
            if step <= 0:
                break
            pos += step

    def close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
