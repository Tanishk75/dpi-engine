# dpi/packet_parser.py
import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class ParsedPacket:
    ts_sec:     int   = 0
    ts_usec:    int   = 0
    src_mac:    str   = ""
    dst_mac:    str   = ""
    ether_type: int   = 0
    has_ip:     bool  = False
    src_ip:     str   = ""
    dst_ip:     str   = ""
    protocol:   int   = 0
    ttl:        int   = 0
    has_tcp:    bool  = False
    has_udp:    bool  = False
    src_port:   int   = 0
    dst_port:   int   = 0
    tcp_flags:  int   = 0
    seq:        int   = 0
    ack:        int   = 0
    payload:    bytes = b""
    _src_ip_int: int  = 0
    _dst_ip_int: int  = 0


class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20

    @staticmethod
    def to_str(flags: int) -> str:
        names = [(0x02,"SYN"),(0x10,"ACK"),(0x01,"FIN"),
                 (0x04,"RST"),(0x08,"PSH"),(0x20,"URG")]
        return " ".join(name for bit, name in names if flags & bit) or "none"


def _mac(data: bytes, off: int) -> str:
    return ":".join(f"{b:02x}" for b in data[off:off+6])

def _ip(data: bytes, off: int) -> str:
    return ".".join(str(b) for b in data[off:off+4])

def _ip_int(data: bytes, off: int) -> int:
    b = data[off:off+4]
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)


def parse(raw_data: bytes, ts_sec: int = 0, ts_usec: int = 0) -> Optional[ParsedPacket]:
    p = ParsedPacket(ts_sec=ts_sec, ts_usec=ts_usec)
    data = raw_data

    # Ethernet (14 bytes)
    if len(data) < 14:
        return None
    p.dst_mac    = _mac(data, 0)
    p.src_mac    = _mac(data, 6)
    p.ether_type = struct.unpack_from(">H", data, 12)[0]
    offset = 14

    if p.ether_type != 0x0800:
        return p

    # IPv4
    if len(data) < offset + 20:
        return p
    version_ihl = data[offset]
    if (version_ihl >> 4) != 4:
        return p
    ihl        = (version_ihl & 0x0F) * 4
    p.ttl      = data[offset + 8]
    p.protocol = data[offset + 9]
    p.src_ip   = _ip(data, offset + 12)
    p.dst_ip   = _ip(data, offset + 16)
    p._src_ip_int = _ip_int(data, offset + 12)
    p._dst_ip_int = _ip_int(data, offset + 16)
    p.has_ip   = True
    offset += ihl

    # TCP
    if p.protocol == 6:
        if len(data) < offset + 20:
            return p
        p.src_port  = struct.unpack_from(">H", data, offset)[0]
        p.dst_port  = struct.unpack_from(">H", data, offset + 2)[0]
        p.seq       = struct.unpack_from(">I", data, offset + 4)[0]
        p.ack       = struct.unpack_from(">I", data, offset + 8)[0]
        tcp_hlen    = ((data[offset + 12] >> 4) & 0xF) * 4
        p.tcp_flags = data[offset + 13]
        p.has_tcp   = True
        offset += tcp_hlen

    # UDP
    elif p.protocol == 17:
        if len(data) < offset + 8:
            return p
        p.src_port = struct.unpack_from(">H", data, offset)[0]
        p.dst_port = struct.unpack_from(">H", data, offset + 2)[0]
        p.has_udp  = True
        offset += 8

    p.payload = data[offset:]
    return p