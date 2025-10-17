"""Utilities: logging, URL parsing, validation helpers.

parse_rtsp_url returns a 5-tuple:
    (host, username_or_None, password_or_None, port, path)

This is intentionally stable for tests and external callers.
"""

from __future__ import annotations

import logging
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from .exceptions import RTSPValidationError

logger = logging.getLogger("rtsper")
logger.addHandler(logging.NullHandler())

_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

def validate_token(name: str, value: str, mode: str = "strict") -> None:
    """Validate small token-like strings (header names or methods)."""
    if not isinstance(value, str):
        raise RTSPValidationError(f"{name} must be str")
    if not _TOKEN_RE.match(value):
        if mode == "strict":
            raise RTSPValidationError(f"Invalid {name}: {value!r}")
        else:
            logger.warning("lenient: invalid %s %r - continuing", name, value)

def parse_rtsp_url(url: str, mode: str = "strict") -> Tuple[str, Optional[str], Optional[str], int, str]:
    """Parse RTSP/RTSPS URL robustly.

    Returns:
        (host, username, password, port, path)
    Raises:
        RTSPValidationError on invalid URL in strict mode.
    """
    if not isinstance(url, str):
        raise RTSPValidationError("url must be a string")
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("rtsp", "rtsps"):
        if mode == "strict":
            raise RTSPValidationError(f"Invalid RTSP scheme: {parsed.scheme!r}")
        else:
            logger.warning("lenient: invalid scheme in URL %r", url)
            return "", None, None, 554, "/"

    username = parsed.username
    password = parsed.password

    # Prefer parsed.hostname which strips port & IPv6 brackets
    host = parsed.hostname
    if host is None:
        # defensive fallback parsing of netloc
        netloc = parsed.netloc or ""
        if "@" in netloc:
            netloc = netloc.split("@", 1)[1]
        if netloc.startswith("[") and "]" in netloc:
            # [ipv6]:port or [ipv6]
            host = netloc.split("]", 1)[0].strip("[]")
        else:
            host = netloc.split(":", 1)[0] if netloc else ""

    default_port = 322 if scheme == "rtsps" else 554
    port = parsed.port or default_port

    path = parsed.path or "/"

    return host, username, password, int(port), path
