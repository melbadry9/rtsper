"""RTSP-specific exception hierarchy."""

class RTSPError(Exception):
    """Base RTSP exception."""
    pass

class RTSPValidationError(RTSPError):
    """Raised when input validation fails."""
    pass

class RTSPProtocolError(RTSPError):
    """Raised when protocol parsing or framing fails."""
    pass

class RTSPAuthError(RTSPError):
    """Authentication-related errors."""
    pass

class RTSPTransportError(RTSPError):
    """Transport-level errors (socket/connect/send/receive)."""
    pass
