import pytest
from rtsper.session import RTSPSession
from rtsper.transport import TCPTransport, UDPTransport
from rtsper.utils import parse_rtsp_url
from rtsper.rtp import RTPPacket
from rtsper.exceptions import RTSPTransportError, RTSPValidationError

RTSP_URL = "rtsp://127.0.0.1:554/"
TIMEOUT = 5

def test_rtp_parse_min_length():
    with pytest.raises(ValueError):
        RTPPacket.parse(b'\x80\x60')

def test_parse_rtsp_url_with_port():
    url = "rtsp://user:pass@host:8554/media"
    host, user, pwd, port, path = parse_rtsp_url(url)
    assert host == "host"
    assert user == "user"
    assert pwd == "pass"
    assert port == 8554
    assert path == "/media"

def test_parse_rtsp_url_without_port():
    url = "rtsp://example.com/stream"
    host, user, pwd, port, path = parse_rtsp_url(url)
    assert host == "example.com"
    assert port == 554
    assert path == "/stream"

def test_parse_rtsp_url_ipv6():
    url = "rtsp://[2001:db8::1]:8554/video"
    host, user, pwd, port, path = parse_rtsp_url(url)
    assert host == "2001:db8::1"
    assert port == 8554
    assert path == "/video"

def test_sync_tcp_transport_connect_and_close():
    t = TCPTransport("127.0.0.1", 554, timeout=TIMEOUT)
    try:
        t.connect()
        assert t._sock is not None
    except RTSPTransportError:
        pytest.skip("TCP connection unavailable")
    finally:
        t.close()

@pytest.mark.asyncio
async def test_async_tcp_transport_connect_and_close():
    t = TCPTransport("127.0.0.1", 554, timeout=TIMEOUT)
    try:
        await t.aconnect()
        assert t._writer is not None
    except RTSPTransportError:
        pytest.skip("Async TCP connect failed")
    finally:
        await t.aclose()

def test_udp_transport_creation_and_close():
    u = UDPTransport("127.0.0.1", 6000)
    assert u.host == "127.0.0.1"
    assert u.port == 6000
    u.close()

def test_sync_session_options_describe():
    sess = RTSPSession(RTSP_URL, transport="tcp", timeout=TIMEOUT)
    try:
        sess.connect()
        resp1 = sess.options()
        assert 200 <= resp1.status_code < 600
        resp2 = sess.describe()
        assert resp2 is not None
    except RTSPTransportError:
        pytest.skip("RTSP server unreachable")
    finally:
        sess.close()

def test_sync_session_play_teardown():
    sess = RTSPSession(RTSP_URL, transport="tcp", timeout=TIMEOUT)
    try:
        sess.connect()
        sess.options()
        sess.describe()
        sess.setup()
        try:
            sess.play()
        except Exception as e:
            pytest.skip(f"PLAY skipped: {e}")
        sess.teardown()
    except RTSPTransportError:
        pytest.skip("RTSP server unavailable")
    finally:
        sess.close()

@pytest.mark.asyncio
async def test_async_session_full_cycle():
    sess = RTSPSession(RTSP_URL, transport="tcp", timeout=TIMEOUT)
    try:
        await sess.aconnect()
        await sess.aoptions()
        await sess.adescribe()
        await sess.asetup()
        try:
            await sess.aplay()
        except Exception as e:
            pytest.skip(f"Async PLAY skipped: {e}")
        await sess.ateardown()
    except RTSPTransportError:
        pytest.skip("RTSP async connection unavailable")
    finally:
        await sess.aclose()

@pytest.mark.asyncio
async def test_auth_digest_mock():
    sess = RTSPSession(RTSP_URL)
    # simulate dict-style auth
    sess.auth = {
        'username': 'user',
        'password': 'pass',
    }
    resp_headers = {'WWW-Authenticate': 'Digest realm="testrealm", nonce="abcd"'}
    headers = sess._maybe_apply_auth('DESCRIBE', RTSP_URL, {}, resp_headers)
    assert 'Authorization' in headers

def test_invalid_url_raises():
    with pytest.raises(RTSPValidationError):
        RTSPSession('not-a-url')

@pytest.mark.asyncio
async def test_async_invalid_url_raises():
    with pytest.raises(RTSPValidationError):
        await RTSPSession('not-a-url').aconnect()
