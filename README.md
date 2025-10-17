# rtsper

rtsper is a modern RTSP client SDK for Python (sync + async).
It offers RFC-aware URL parsing, TCP/UDP transports, auth helpers, RTP/RTCP parsing,
SDP parsing, event hooks, and flexible logging/validation modes.

## Quickstart

```python
from rtsper import RTSPSession

sess = RTSPSession('rtsp://127.0.0.1:554/', transport='tcp', debug=True)
sess.connect()
resp = sess.describe()
print(resp.status_code)
sess.close()
```
