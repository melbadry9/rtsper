"""Transport implementations: TCP and UDP (sync + async wrappers)."""

from __future__ import annotations

import asyncio
import socket
import threading
from typing import Optional, Tuple

from .exceptions import RTSPTransportError
from .rtp import RTPPacket
from .utils import logger

class TransportBase:
    def connect(self) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    async def aconnect(self) -> None:
        raise NotImplementedError

    async def aclose(self) -> None:
        raise NotImplementedError

# TCPTransport - blocking + asyncio stream variants
class TCPTransport(TransportBase):
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host = host
        self.port = int(port)
        self.timeout = float(timeout)
        self._sock: Optional[socket.socket] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None

    def connect(self) -> None:
        try:
            s = socket.create_connection((self.host, self.port), timeout=self.timeout)
            s.settimeout(self.timeout)
            self._sock = s
            logger.debug("TCPTransport connected to %s:%d", self.host, self.port)
        except Exception as exc:
            raise RTSPTransportError(str(exc)) from exc

    def send(self, data: bytes) -> None:
        if not self._sock:
            raise RTSPTransportError("Not connected")
        self._sock.sendall(data)

    def recv(self, size: int = 65536) -> bytes:
        if not self._sock:
            raise RTSPTransportError("Not connected")
        return self._sock.recv(size)

    def close(self) -> None:
        try:
            if self._sock:
                self._sock.close()
        finally:
            self._sock = None

    async def aconnect(self) -> None:
        try:
            self._reader, self._writer = await asyncio.open_connection(self.host, self.port)
            logger.debug("TCPTransport async connected to %s:%d", self.host, self.port)
        except Exception as exc:
            raise RTSPTransportError(str(exc)) from exc

    async def asend(self, data: bytes) -> None:
        if not self._writer:
            raise RTSPTransportError("Not async-connected")
        self._writer.write(data)
        await self._writer.drain()

    async def arecv(self, n: int = -1) -> bytes:
        if not self._reader:
            raise RTSPTransportError("Not async-connected")
        if n == -1:
            return await self._reader.read(65536)
        else:
            return await self._reader.readexactly(n)

    async def aclose(self) -> None:
        try:
            if self._writer:
                self._writer.close()
                await self._writer.wait_closed()
        finally:
            self._reader = None
            self._writer = None

# UDPTransport - bind to ports and dispatch RTP via background thread
class UDPTransport(TransportBase):
    def __init__(self, first_arg, second_arg=None, on_rtp_callback=None):
        """Construct with either:
        - UDPTransport((rtp, rtcp))
        - UDPTransport(host, port)
        """
        self.on_rtp_callback = on_rtp_callback
        self.rtp_sock: Optional[socket.socket] = None
        self.rtcp_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        if second_arg is None and isinstance(first_arg, tuple):
            self.client_ports = first_arg
            self.host = ""
            self.port = int(self.client_ports[0])
        else:
            self.host = first_arg
            self.port = int(second_arg)
            self.client_ports = (self.port, self.port + 1)

    def connect(self) -> None:
        p1, p2 = self.client_ports
        if p2 != p1 + 1:
            raise RTSPTransportError("client_ports must be consecutive (rtp, rtcp)")
        s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s1.bind(("", p1))
        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s2.bind(("", p2))
        self.rtp_sock = s1
        self.rtcp_sock = s2
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._thread.start()
        logger.debug("UDPTransport bound ports %d,%d", p1, p2)

    def _recv_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                data, addr = self.rtp_sock.recvfrom(65536)
                parsed = None
                try:
                    parsed = RTPPacket.parse(data)
                except Exception:
                    parsed = None
                if self.on_rtp_callback:
                    try:
                        self.on_rtp_callback(parsed, data, addr)
                    except Exception:
                        logger.exception("on_rtp callback failed")
            except Exception as exc:
                if self._stop_event.is_set():
                    break
                logger.exception("UDP recv error: %s", exc)
                break

    def close(self) -> None:
        self._stop_event.set()
        if self.rtp_sock:
            try:
                self.rtp_sock.close()
            except Exception:
                pass
        if self.rtcp_sock:
            try:
                self.rtcp_sock.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=1.0)
        self.rtp_sock = None
        self.rtcp_sock = None

    async def aconnect(self) -> None:
        # reuse sync behavior for simplicity
        self.connect()

    async def aclose(self) -> None:
        self.close()
