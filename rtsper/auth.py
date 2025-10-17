"""Authentication helpers for Basic and Digest (MD5, qop=auth)."""

from __future__ import annotations

import base64
import hashlib
import time
import re
from typing import Dict

def basic_auth_header(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"

def parse_www_authenticate(header_value: str) -> Dict[str, str]:
    """Parse a simple WWW-Authenticate header into a dict, with 'scheme'."""
    parts = header_value.split(None, 1)
    scheme = parts[0]
    params = {}
    if len(parts) > 1:
        rest = parts[1]
        for m in re.finditer(r'([a-zA-Z0-9_\-]+)=("(?:[^"\\]|\\.)*"|[^,\s]+)', rest):
            k = m.group(1)
            v = m.group(2)
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            params[k] = v
    params['scheme'] = scheme
    return params

def digest_auth_header(uri: str, method: str, auth_params: Dict[str, str], user: str, password: str) -> str:
    """Compute Digest Authorization header (MD5 + qop=auth subset)."""
    realm = auth_params.get('realm', '')
    nonce = auth_params.get('nonce', '')
    algorithm = auth_params.get('algorithm', 'MD5').upper()
    qop = auth_params.get('qop')

    if algorithm not in ('MD5', 'MD5-SESS'):
        raise ValueError(f"Unsupported digest algorithm: {algorithm}")

    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    if algorithm == 'MD5-SESS':
        ha1 = hashlib.md5(f"{ha1}:{nonce}:".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()

    if qop:
        qop_list = [x.strip() for x in qop.split(',')]
        chosen_qop = 'auth' if 'auth' in qop_list else qop_list[0]
        nc = '00000001'
        cnonce = hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
        response = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{chosen_qop}:{ha2}".encode()).hexdigest()
        header = (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
                  f'response="{response}", qop={chosen_qop}, nc={nc}, cnonce="{cnonce}"')
        return header

    response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    header = (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{response}"')
    return header
