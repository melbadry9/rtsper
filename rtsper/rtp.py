"""RTP packet parsing (RFC 3550 subset)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

@dataclass
class RTPPacket:
    version: int
    padding: int
    extension: int
    csrc_count: int
    marker: int
    payload_type: int
    sequence: int
    timestamp: int
    ssrc: int
    csrcs: List[int]
    extension_profile: Optional[int]
    extension_data: Optional[bytes]
    payload: bytes

    @staticmethod
    def parse(raw: bytes) -> "RTPPacket":
        if len(raw) < 12:
            raise ValueError("RTP packet too short")
        b0 = raw[0]
        version = (b0 >> 6) & 0x03
        padding = (b0 >> 5) & 0x01
        extension = (b0 >> 4) & 0x01
        csrc_count = b0 & 0x0F
        b1 = raw[1]
        marker = (b1 >> 7) & 0x01
        payload_type = b1 & 0x7F
        sequence = int.from_bytes(raw[2:4], "big")
        timestamp = int.from_bytes(raw[4:8], "big")
        ssrc = int.from_bytes(raw[8:12], "big")
        offset = 12
        csrcs = []
        for _ in range(csrc_count):
            if offset + 4 > len(raw):
                raise ValueError('CSRC truncated')
            csrcs.append(int.from_bytes(raw[offset:offset+4], 'big'))
            offset += 4
        extension_profile = None
        extension_data = None
        if extension:
            if offset + 4 > len(raw):
                raise ValueError('extension header truncated')
            extension_profile = int.from_bytes(raw[offset:offset+2], 'big')
            ext_len = int.from_bytes(raw[offset+2:offset+4], 'big')
            offset += 4
            ext_bytes = ext_len * 4
            if offset + ext_bytes > len(raw):
                raise ValueError('extension contents truncated')
            extension_data = raw[offset:offset+ext_bytes]
            offset += ext_bytes
        payload_end = len(raw)
        if padding:
            pad_len = raw[-1]
            if pad_len == 0 or pad_len > len(raw) - offset:
                raise ValueError('Invalid RTP padding')
            payload_end = len(raw) - pad_len
        payload = raw[offset:payload_end]
        return RTPPacket(version, padding, extension, csrc_count, marker, payload_type,
                         sequence, timestamp, ssrc, csrcs, extension_profile, extension_data, payload)
