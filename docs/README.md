# 🛰️ rtsper — Python RTSP Client SDK

> **rtsper** is a modern, type-safe, fully asynchronous **RTSP client library** for Python.  
> It supports both synchronous and asynchronous APIs, TCP and UDP transport, authentication, reconnection, and robust URL parsing — all wrapped in a clean, developer-friendly interface.

---

## 📦 Installation

### From PyPI
```bash
pip install rtsper
```

### From Source
```bash
git clone https://github.com/melbadry9/rtsper.git
cd rtsper
pip install .
```

---

## ⚙️ Quickstart

### Synchronous Example

```python
from rtsper import RTSPSession

url = "rtsp://127.0.0.1:554/"
sess = RTSPSession(url, transport="tcp")

sess.connect()
sess.options()
sess.describe()
sess.setup()
sess.play()

print(sess.last_response.status_code)
print(sess.last_response.headers)

sess.teardown()
sess.close()
```

---

### ⚡ Asynchronous Example

```python
import asyncio
from rtsper import RTSPSession

async def main():
    sess = RTSPSession("rtsp://127.0.0.1:554/")
    await sess.aconnect()
    await sess.aoptions()
    await sess.adescribe()
    await sess.asetup()
    await sess.aplay()
    await sess.ateardown()
    await sess.aclose()

asyncio.run(main())
```

---

## 🧠 Architecture Overview

```
rtsper/
├── auth.py
├── exceptions.py
├── rtp.py
├── sdp.py
├── session.py
├── transport.py
└── utils.py
```

---

## API Reference

### 🧠 RTSPSession
Represents an RTSP connection with full command support.

#### Constructor
```python
RTSPSession(
    url: str,
    transport: Literal["tcp", "udp"] = "tcp",
    timeout: float = 5.0,
    reconnect: bool = True,
    reconnect_attempts: int = 3,
    reconnect_backoff: float = 0.5
)
```

#### Synchronous Methods
| Method | Description |
|--------|--------------|
| connect() | Establishes a connection |
| options() | Sends OPTIONS |
| describe() | Sends DESCRIBE |
| setup() | Sends SETUP |
| play() | Sends PLAY |
| teardown() | Sends TEARDOWN |
| close() | Closes transport |

#### Asynchronous Methods
| Method | Description |
|--------|--------------|
| aconnect() | Async connect |
| aoptions() | Async OPTIONS |
| adescribe() | Async DESCRIBE |
| asetup() | Async SETUP |
| aplay() | Async PLAY |
| ateardown() | Async TEARDOWN |
| aclose() | Async close |

---

### 🌐 parse_rtsp_url(url: str)
Parses and validates RTSP/RTSPS URLs.

Returns:
```python
(host, username, password, port, path, scheme)
```

Example:
```python
from rtsper.utils import parse_rtsp_url

parse_rtsp_url("rtsp://user:pass@192.168.1.10:8554/stream")
# -> ("192.168.1.10", "user", "pass", 8554, "/stream", "rtsp")
```

---

### 🔌 TCPTransport
Handles RTSP communication via TCP sockets.

| Method | Description |
|--------|--------------|
| connect() / aconnect() | Establish TCP connection |
| send(data) / asend(data) | Send raw RTSP data |
| recv() / arecv() | Receive data |
| close() | Close socket |

---

### 📡 UDPTransport
Handles RTP/RTCP over UDP.

| Attribute | Description |
|------------|-------------|
| host | Destination IP |
| port | Destination port |
| connected | Connection state |

| Method | Description |
|--------|--------------|
| sendto(data, addr) | Send data to target |
| recvfrom(bufsize) | Receive data from target |
| close() | Close socket |

---

### ⚠️ Exceptions

| Exception | Description |
|------------|-------------|
| RTSPError | Base class for all SDK errors |
| RTSPTransportError | Transport/socket layer failure |
| RTSPValidationError | Invalid RTSP URL or protocol |
| RTSPAuthError | Authentication failure |
| RTSPTimeoutError | Operation timed out |

---

## 🔐 Authentication

Supports both Basic and Digest authentication.

Example:
```python
sess = RTSPSession("rtsp://user:pass@camera.local:554/stream")
sess.connect()
sess.describe()  # Handles WWW-Authenticate challenges automatically
```

---

## Utility Helpers

### basic_auth_header(username, password)
Returns a correctly encoded Basic Auth header.

### digest_auth_header(username, password, realm, nonce, uri, method)
Generates a Digest Auth header per RFC 2617.

---

## Testing

Run all tests:

```bash
pytest -v
```

Async Tests:
```bash
pip install pytest-asyncio
pytest -v tests/
```

---

## 🧱 Design Diagram

```
+----------------------+
|     RTSPSession      |
|----------------------|
|  - options()         |
|  - describe()        |
|  - setup()           |
|  - play()            |
+----------+-----------+
           |
           v
+----------------------+
|   TCPTransport       |
|----------------------|
|  - connect()         |
|  - send()            |
|  - recv()            |
+----------+-----------+
           |
           v
+----------------------+
|     Socket Layer     |
+----------------------+

+----------------------+
|   UDPTransport       |
|----------------------|
|  - sendto()          |
|  - recvfrom()        |
+----------------------+
```

---

## 🧾 Changelog

**v1.0.0 — 2025-10-17**
- Added full RTSP command stack
- Sync + Async transport support
- Added TCP and UDP modes
- URL parsing improvements
- Authentication: Basic & Digest
- Added reconnect + timeout logic
- PyPI packaging & documentation

---

## 🧑‍💻 Contributing

1. Fork the repo  
2. Create your feature branch (`git checkout -b feature/awesome`)
3. Commit changes (`git commit -m 'Add awesome feature'`)
4. Push to branch (`git push origin feature/awesome`)
5. Open a Pull Request
