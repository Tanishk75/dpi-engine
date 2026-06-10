# dpi/sni_extractor.py
from typing import Optional


CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
EXTENSION_SNI          = 0x0000


def _u16(data: bytes, off: int) -> int:
    return (data[off] << 8) | data[off + 1]

def _u24(data: bytes, off: int) -> int:
    return (data[off] << 16) | (data[off + 1] << 8) | data[off + 2]


def is_tls_client_hello(payload: bytes) -> bool:
    if len(payload) < 9:
        return False
    if payload[0] != CONTENT_TYPE_HANDSHAKE:
        return False
    version = _u16(payload, 1)
    if not (0x0300 <= version <= 0x0304):
        return False
    record_len = _u16(payload, 3)
    if record_len > len(payload) - 5:
        return False
    return payload[5] == HANDSHAKE_CLIENT_HELLO


def extract_sni(payload: bytes) -> Optional[str]:
    if not is_tls_client_hello(payload):
        return None

    off  = 5     # skip TLS record header
    off += 4     # skip handshake type + 3-byte length
    off += 2     # client version
    off += 32    # random

    if off >= len(payload):
        return None

    # Session ID
    sid_len = payload[off]
    off += 1 + sid_len

    # Cipher suites
    if off + 2 > len(payload): return None
    cs_len = _u16(payload, off)
    off += 2 + cs_len

    # Compression methods
    if off >= len(payload): return None
    cm_len = payload[off]
    off += 1 + cm_len

    # Extensions
    if off + 2 > len(payload): return None
    ext_total = _u16(payload, off)
    off += 2
    ext_end = min(off + ext_total, len(payload))

    while off + 4 <= ext_end:
        ext_type = _u16(payload, off)
        ext_len  = _u16(payload, off + 2)
        off += 4
        if off + ext_len > ext_end:
            break

        if ext_type == EXTENSION_SNI:
            if ext_len < 5:
                return None
            name_len = _u16(payload, off + 3)
            name_off = off + 5
            if name_off + name_len > len(payload):
                return None
            return payload[name_off: name_off + name_len].decode("ascii", errors="ignore")

        off += ext_len

    return None


def extract_http_host(payload: bytes) -> Optional[str]:
    try:
        text = payload.decode("ascii", errors="ignore")
    except Exception:
        return None
    for line in text.splitlines():
        if line.lower().startswith("host:"):
            return line.split(":", 1)[1].strip().split(":")[0]
    return None