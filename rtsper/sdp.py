"""Minimal SDP parser suitable for RTSP DESCRIBE results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Any

class SDPParseError(Exception):
    pass

@dataclass
class MediaDesc:
    type: str
    port: int
    proto: str
    fmt: List[str]
    attrs: Dict[str, str]

def parse_sdp(sdp_text: str) -> Dict[str, Any]:
    session = {}
    media_list: List[MediaDesc] = []
    current_media = None
    for raw in sdp_text.splitlines():
        line = raw.strip()
        if not line or '=' not in line:
            continue
        prefix, value = line[0], line[2:]
        if prefix == 'v':
            session['version'] = value
        elif prefix == 'o':
            session['origin'] = value
        elif prefix == 's':
            session['session_name'] = value
        elif prefix == 't':
            session['timing'] = value
        elif prefix == 'a':
            if current_media is None:
                if ':' in value:
                    k, v = value.split(':',1)
                    session.setdefault('attrs', {})[k] = v
                else:
                    session.setdefault('attrs', {})[value] = ''
            else:
                if ':' in value:
                    k, v = value.split(':',1)
                    current_media.attrs[k] = v
                else:
                    current_media.attrs[value] = ''
        elif prefix == 'm':
            parts = value.split()
            if len(parts) >= 4:
                mtype = parts[0]
                port = int(parts[1])
                proto = parts[2]
                fmt = parts[3:]
                current_media = MediaDesc(type=mtype, port=port, proto=proto, fmt=fmt, attrs={})
                media_list.append(current_media)
            else:
                continue
        else:
            continue
    return {'session': session, 'media': media_list}
