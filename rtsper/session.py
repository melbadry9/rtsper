"""High-level RTSPSession: sync + async, transports, auth, RTP reading.

This module provides RTSPSession with a requests-like API and strict RFC-aware
parsing and behavior. It uses utils.parse_rtsp_url() for host/port parsing.
"""

from __future__ import annotations

import asyncio
import socket
import time
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, Callable, Tuple

from urllib.parse import urlparse

from .exceptions import RTSPProtocolError, RTSPTransportError, RTSPValidationError
from .utils import logger, validate_token, parse_rtsp_url
from .transport import TCPTransport, UDPTransport
from .auth import basic_auth_header, parse_www_authenticate, digest_auth_header
from .sdp import parse_sdp
from .rtp import RTPPacket

log = logging.getLogger("rtsper.session")

@dataclass
class RTSPResponse:
    status_code: int
    reason: str
    headers: Dict[str, str]
    body: str
    raw: Optional[str] = None

class RTSPSession:
    """Represents an RTSP session (client)."""

    def __init__(self,
                 url: str,
                 transport: str = 'tcp',
                 version: str = '1.0',
                 auth: Optional[Any] = None,
                 timeout: float = 5.0,
                 mode: str = 'strict',
                 user_agent: str = 'rtsper/1.0',
                 keepalive: Optional[float] = None,
                 debug: bool = False,
                 reconnect: bool = True,
                 reconnect_attempts: int = 3,
                 reconnect_backoff: float = 1.0):
        if not isinstance(url, str):
            raise RTSPValidationError("url must be a string")
        self.url = url
        self.transport_type = transport.lower()
        self.version = version
        self.auth = auth
        self.timeout = float(timeout)
        self.mode = mode
        self.user_agent = user_agent
        self.keepalive = keepalive
        self.debug = debug
        self.reconnect = reconnect
        self.reconnect_attempts = int(reconnect_attempts)
        self.reconnect_backoff = float(reconnect_backoff)
        if debug:
            logger.setLevel(logging.DEBUG)
            log.setLevel(logging.DEBUG)

        # parse url into host,user,pwd,port,path
        self.host, self.user_in_url, self.pwd_in_url, self.port, self.path = parse_rtsp_url(url, mode)
        # additional scheme info if needed
        self.scheme = (urlparse(url).scheme or 'rtsp').lower()

        self.session_id: Optional[str] = None
        self.cseq = 1
        self.transport_impl = None
        self.udp_client_ports: Optional[Tuple[int, int]] = None

        # hooks
        self.on_request: Optional[Callable[[str, Dict[str, str], str], Any]] = None
        self.on_response: Optional[Callable[[RTSPResponse], Any]] = None
        self.on_rtp: Optional[Callable[[Optional[RTPPacket], bytes, Any], Any]] = None
        self.on_error: Optional[Callable[[Exception], Any]] = None
        self.on_disconnect: Optional[Callable[[], Any]] = None

    # helpers
    def _next_cseq(self) -> str:
        v = str(self.cseq)
        self.cseq += 1
        return v

    def _make_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {'CSeq': self._next_cseq(), 'User-Agent': self.user_agent}
        if self.session_id:
            headers['Session'] = self.session_id
        if extra:
            headers.update(extra)
        return headers

    def _format_request(self, method: str, headers: Dict[str, str], body: str = '') -> bytes:
        validate_token('method', method, self.mode)
        for k in headers.keys():
            validate_token('header-name', k, self.mode)
        rtsp_uri = f"{self.scheme}://{self.host}:{self.port}{self.path}"
        req_line = f"{method} {rtsp_uri} RTSP/{self.version}\r\n"
        hdrs = ''.join(f"{k}: {v}\r\n" for k, v in headers.items())
        full = req_line + hdrs + '\r\n' + (body or '')
        if self.on_request:
            try:
                self.on_request(method, headers, body)
            except Exception as e:
                if self.on_error: self.on_error(e)
        log.debug('>>> REQUEST >>>\n%s', full)
        return full.encode()

    def _parse_response_raw(self, raw: str) -> tuple[int, str, Dict[str, str], str]:
        if not raw:
            raise RTSPProtocolError('Empty response')
        header_body = raw.split('\r\n\r\n', 1)
        header_part = header_body[0]
        body = header_body[1] if len(header_body) > 1 else ''
        lines = header_part.split('\r\n')
        status_line = lines[0]
        import re
        m = re.match(r"RTSP/1\.[01]\s+([0-9]{3})\s*(.*)$", status_line) or re.match(r"RTSP/2\.[01]\s+([0-9]{3})\s*(.*)$", status_line)
        if not m:
            if self.mode == 'strict':
                raise RTSPProtocolError(f'Invalid status line: {status_line!r}')
            else:
                log.warning('lenient: invalid status line %r - treating as 500', status_line)
                return 500, '', {}, body
        status_code = int(m.group(1))
        reason = m.group(2).strip()
        headers = {}
        for line in lines[1:]:
            if not line:
                continue
            if ':' not in line:
                if self.mode == 'strict':
                    raise RTSPProtocolError(f'Malformed header line: {line!r}')
                else:
                    log.warning('lenient: malformed header line %r - skipping', line)
                    continue
            k, v = line.split(':', 1)
            headers[k.strip()] = v.strip()
        if 'Content-Length' in headers:
            try:
                expected = int(headers['Content-Length'])
                if len(body) > expected:
                    body = body[:expected]
            except Exception:
                pass
        return status_code, reason, headers, body

    def _process_response(self, raw: str) -> RTSPResponse:
        status, reason, headers, body = self._parse_response_raw(raw)
        if 'Session' in headers and not self.session_id:
            self.session_id = headers['Session'].split(';')[0]
        resp = RTSPResponse(status, reason, headers, body, raw)
        if self.on_response:
            try:
                self.on_response(resp)
            except Exception as e:
                if self.on_error: self.on_error(e)
        log.debug('<<< RESPONSE <<<\n%s', raw if len(raw) < 2000 else raw[:2000] + '...(truncated)')
        return resp

    # reset helpers
    def _reset(self):
        try:
            if self.transport_impl:
                try:
                    getattr(self.transport_impl, 'close', lambda: None)()
                except Exception as e:
                    log.debug('Error while closing transport in _reset: %s', e)
        finally:
            self.transport_impl = None
            self.session_id = None
            self.udp_client_ports = None
            log.debug('RTSP session state reset (sync).')

    async def _areset(self):
        try:
            if self.transport_impl:
                try:
                    coro = getattr(self.transport_impl, 'aclose', None)
                    if coro:
                        await coro()
                    else:
                        getattr(self.transport_impl, 'close', lambda: None)()
                except Exception as e:
                    log.debug('Error while closing transport in _areset: %s', e)
        finally:
            self.transport_impl = None
            self.session_id = None
            self.udp_client_ports = None
            log.debug('RTSP session state reset (async).')

    # transport management
    def _ensure_transport(self) -> None:
        if self.transport_impl:
            return
        if self.transport_type == 'tcp':
            self.transport_impl = TCPTransport(self.host, self.port, timeout=self.timeout)
        elif self.transport_type == 'udp':
            if self.udp_client_ports:
                ports = self.udp_client_ports
                self.transport_impl = UDPTransport(ports, on_rtp_callback=self._on_udp_rtp)
            else:
                self.transport_impl = UDPTransport(self.host, self.port, on_rtp_callback=self._on_udp_rtp)
        else:
            raise RTSPTransportError('unknown transport type')

    def set_udp_client_ports(self, rtp_port: int) -> None:
        self.udp_client_ports = (rtp_port, rtp_port + 1)
        if isinstance(self.transport_impl, UDPTransport):
            self.transport_impl.client_ports = self.udp_client_ports

    def connect(self) -> None:
        if self.transport_impl:
            log.debug('Session transport present — performing reset before connect.')
            self._reset()
        self._ensure_transport()
        attempts_left = self.reconnect_attempts if self.reconnect else 1
        backoff = self.reconnect_backoff
        while attempts_left > 0:
            try:
                self.transport_impl.connect()
                log.info('Connected to %s:%d via %s', self.host, self.port, self.transport_type.upper())
                return
            except (OSError, RTSPTransportError, socket.gaierror) as exc:
                attempts_left -= 1
                log.warning('Connect attempt failed: %s (attempts left: %d)', exc, attempts_left)
                self._reset()
                if attempts_left <= 0 or not self.reconnect:
                    if self.mode == 'strict':
                        raise
                    if self.on_error:
                        self.on_error(exc)
                    return
                time.sleep(backoff)
                backoff *= 2

    async def aconnect(self) -> None:
        if self.transport_impl:
            log.debug('Session transport present — performing async reset before connect.')
            await self._areset()
        self._ensure_transport()
        if self.transport_impl is None:
            raise RTSPTransportError('Transport implementation missing')
        attempts_left = self.reconnect_attempts if self.reconnect else 1
        backoff = self.reconnect_backoff
        while attempts_left > 0:
            try:
                await self.transport_impl.aconnect()
                log.info('Async connected to %s:%d via %s', self.host, self.port, self.transport_type.upper())
                return
            except (OSError, RTSPTransportError, socket.gaierror) as exc:
                attempts_left -= 1
                log.warning('Async connect attempt failed: %s (attempts left: %d)', exc, attempts_left)
                await self._areset()
                if attempts_left <= 0 or not self.reconnect:
                    if self.mode == 'strict':
                        raise
                    if self.on_error:
                        self.on_error(exc)
                    return
                await asyncio.sleep(backoff)
                backoff *= 2

    def close(self) -> None:
        try:
            if self.transport_impl:
                self.transport_impl.close()
            if self.on_disconnect:
                try:
                    self.on_disconnect()
                except Exception:
                    pass
        finally:
            self._reset()

    async def aclose(self) -> None:
        try:
            if self.transport_impl:
                coro = getattr(self.transport_impl, 'aclose', None)
                if coro:
                    await coro()
                else:
                    try:
                        self.transport_impl.close()
                    except Exception:
                        pass
            if self.on_disconnect:
                try:
                    self.on_disconnect()
                except Exception:
                    pass
        finally:
            await self._areset()

    # auth helpers
    def _maybe_apply_auth(self, method: str, url: str, headers: Dict[str, str], resp_headers: Dict[str, str]) -> Dict[str, str]:
        if not self.auth:
            if self.user_in_url and self.pwd_in_url:
                headers['Authorization'] = basic_auth_header(self.user_in_url, self.pwd_in_url)
            return headers
        # support dict or tuple auth styles
        if isinstance(self.auth, dict):
            user = self.auth.get('username') or self.auth.get('user')
            pwd = self.auth.get('password') or self.auth.get('pwd')
        else:
            user, pwd = self.auth
        if 'WWW-Authenticate' not in resp_headers:
            headers['Authorization'] = basic_auth_header(user, pwd)
            return headers
        chal = resp_headers['WWW-Authenticate']
        parsed = parse_www_authenticate(chal)
        scheme = parsed.get('scheme', '').lower()
        if scheme == 'basic':
            headers['Authorization'] = basic_auth_header(user, pwd)
        elif scheme == 'digest':
            headers['Authorization'] = digest_auth_header(url, method, parsed, user, pwd)
        else:
            raise RTSPProtocolError(f'Unsupported auth scheme: {scheme}')
        return headers

    # sync request
    def _send_request(self, method: str, extra_headers: Optional[Dict[str, str]] = None, body: str = '') -> RTSPResponse:
        self._ensure_transport()
        headers = self._make_headers(extra_headers)
        raw_req = self._format_request(method, headers, body)
        try:
            if isinstance(self.transport_impl, TCPTransport):
                self.transport_impl.send(raw_req)
                data = self.transport_impl.recv(65536)
                text = data.decode(errors='ignore')
                status, reason, resp_headers, resp_body = self._parse_response_raw(text)
                if status == 401 and self.auth and 'WWW-Authenticate' in resp_headers:
                    headers2 = self._make_headers(extra_headers)
                    headers2 = self._maybe_apply_auth(method, self.url, headers2, resp_headers)
                    raw2 = self._format_request(method, headers2, body)
                    self.transport_impl.send(raw2)
                    data2 = self.transport_impl.recv(65536)
                    text2 = data2.decode(errors='ignore')
                    return self._process_response(text2)
                return self._process_response(text)
            elif isinstance(self.transport_impl, UDPTransport):
                sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                sock.sendall(raw_req)
                data = sock.recv(65536)
                sock.close()
                return self._process_response(data.decode(errors='ignore'))
            else:
                raise RTSPTransportError('Unknown transport implementation')
        except (ConnectionResetError, BrokenPipeError, socket.gaierror, OSError) as exc:
            log.warning('Transport error during request: %s', exc)
            if self.reconnect:
                try:
                    self.connect()
                except Exception as e:
                    log.debug('Reconnect failed after transport error: %s', e)
            if self.mode == 'strict':
                raise
            if self.on_error:
                self.on_error(exc)
            raise

    # async request
    async def _async_send_request(self, method: str, extra_headers: Optional[Dict[str, str]] = None, body: str = '') -> RTSPResponse:
        self._ensure_transport()
        headers = self._make_headers(extra_headers)
        raw_req = self._format_request(method, headers, body)
        try:
            if isinstance(self.transport_impl, TCPTransport):
                await self.transport_impl.asend(raw_req)
                data = await self.transport_impl.arecv()
                text = data.decode(errors='ignore')
                status, reason, resp_headers, resp_body = self._parse_response_raw(text)
                if status == 401 and self.auth and 'WWW-Authenticate' in resp_headers:
                    headers2 = self._make_headers(extra_headers)
                    headers2 = self._maybe_apply_auth(method, self.url, headers2, resp_headers)
                    raw2 = self._format_request(method, headers2, body)
                    await self.transport_impl.asend(raw2)
                    data2 = await self.transport_impl.arecv()
                    return self._process_response(data2.decode(errors='ignore'))
                return self._process_response(text)
            elif isinstance(self.transport_impl, UDPTransport):
                reader, writer = await asyncio.open_connection(self.host, self.port)
                writer.write(raw_req)
                await writer.drain()
                header_bytes = await reader.readuntil(b'\r\n\r\n')
                text = header_bytes.decode(errors='ignore')
                writer.close()
                await writer.wait_closed()
                return self._process_response(text)
            else:
                raise RTSPTransportError('Unknown transport implementation')
        except (ConnectionResetError, BrokenPipeError, socket.gaierror, OSError) as exc:
            log.warning('Async transport error during request: %s', exc)
            if self.reconnect:
                try:
                    await self.aconnect()
                except Exception as e:
                    log.debug('Async reconnect failed after transport error: %s', e)
            if self.mode == 'strict':
                raise
            if self.on_error:
                self.on_error(exc)
            raise

    # Convenience sync and async methods (OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN)
    def options(self, headers: Optional[Dict[str, str]] = None) -> RTSPResponse:
        return self._send_request('OPTIONS', headers)

    def describe(self, headers: Optional[Dict[str, str]] = None) -> RTSPResponse:
        hdrs = {'Accept': 'application/sdp'}
        if headers:
            hdrs.update(headers)
        return self._send_request('DESCRIBE', hdrs)

    def setup(self, headers: Optional[Dict[str, str]] = None, transport: Optional[str] = None) -> RTSPResponse:
        hdrs: Dict[str, str] = {}
        if transport:
            hdrs['Transport'] = transport
        if headers:
            hdrs.update(headers)
        return self._send_request('SETUP', hdrs)

    def play(self, headers: Optional[Dict[str, str]] = None) -> RTSPResponse:
        return self._send_request('PLAY', headers)

    def pause(self, headers: Optional[Dict[str, str]] = None) -> RTSPResponse:
        return self._send_request('PAUSE', headers)

    def teardown(self, headers: Optional[Dict[str, str]] = None) -> RTSPResponse:
        return self._send_request('TEARDOWN', headers)

    def get_parameter(self, headers: Optional[Dict[str, str]] = None, body: str = '') -> RTSPResponse:
        return self._send_request('GET_PARAMETER', headers, body)

    def set_parameter(self, headers: Optional[Dict[str, str]] = None, body: str = '') -> RTSPResponse:
        return self._send_request('SET_PARAMETER', headers, body)

    async def aoptions(self, headers: Optional[Dict[str, str]] = None) -> RTSPResponse:
        return await self._async_send_request('OPTIONS', headers)

    async def adescribe(self, headers: Optional[Dict[str, str]] = None) -> RTSPResponse:
        hdrs = {'Accept': 'application/sdp'}
        if headers:
            hdrs.update(headers)
        return await self._async_send_request('DESCRIBE', hdrs)

    async def asetup(self, headers: Optional[Dict[str, str]] = None, transport: Optional[str] = None) -> RTSPResponse:
        hdrs: Dict[str, str] = {}
        if transport:
            hdrs['Transport'] = transport
        if headers:
            hdrs.update(headers)
        return await self._async_send_request('SETUP', hdrs)

    async def aplay(self, headers: Optional[Dict[str, str]] = None) -> RTSPResponse:
        return await self._async_send_request('PLAY', headers)

    async def apause(self, headers: Optional[Dict[str, str]] = None) -> RTSPResponse:
        return await self._async_send_request('PAUSE', headers)

    async def ateardown(self, headers: Optional[Dict[str, str]] = None) -> RTSPResponse:
        return await self._async_send_request('TEARDOWN', headers)

    async def aget_parameter(self, headers: Optional[Dict[str, str]] = None, body: str = '') -> RTSPResponse:
        return await self._async_send_request('GET_PARAMETER', headers, body)

    async def aset_parameter(self, headers: Optional[Dict[str, str]] = None, body: str = '') -> RTSPResponse:
        return await self._async_send_request('SET_PARAMETER', headers, body)

    # RTP helpers
    def _on_udp_rtp(self, parsed: Optional[RTPPacket], raw: bytes, addr: Any) -> None:
        if self.on_rtp:
            try:
                self.on_rtp(parsed, raw, addr)
            except Exception as e:
                if self.on_error:
                    self.on_error(e)

    async def read_interleaved(self, rtp_callback: Optional[Callable] = None) -> None:
        if not isinstance(self.transport_impl, TCPTransport):
            raise RTSPTransportError('Interleaved read only valid for TCPTransport')
        reader = getattr(self.transport_impl, '_reader', None)
        if reader is None:
            raise RTSPTransportError('Not async-connected')
        handler = rtp_callback or (lambda ch, payload, parsed: self.on_rtp(parsed, payload, ch) if self.on_rtp else None)
        try:
            while True:
                hdr = await reader.readexactly(4)
                if hdr[0] != 0x24:
                    continue
                channel = hdr[1]
                length = int.from_bytes(hdr[2:4], 'big')
                payload = await reader.readexactly(length)
                parsed: Optional[RTPPacket]
                try:
                    parsed = RTPPacket.parse(payload)
                except Exception:
                    parsed = None
                try:
                    if self.on_rtp:
                        self.on_rtp(parsed, payload, channel)
                    if rtp_callback:
                        rtp_callback(channel, payload, parsed)
                except Exception as e:
                    if self.on_error:
                        self.on_error(e)
        except asyncio.IncompleteReadError:
            if self.on_disconnect:
                try:
                    self.on_disconnect()
                except Exception:
                    pass
        except Exception as e:
            if self.on_error:
                self.on_error(e)
            if self.mode == 'strict':
                raise
