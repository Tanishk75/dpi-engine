# dpi/pcap_reader.py
import struct
from dataclasses import dataclass
from typing import Iterator, Optional


PCAP_MAGIC_NATIVE  = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1


@dataclass
class PcapGlobalHeader:
    magic:         int
    version_major: int
    version_minor: int
    thiszone:      int
    sigfigs:       int
    snaplen:       int
    network:       int


@dataclass
class RawPacket:
    ts_sec:  int
    ts_usec: int
    data:    bytes


class PcapReader:
    def __init__(self, path: str):
        self.path = path
        self._fh = None
        self._swapped = False
        self.global_header: Optional[PcapGlobalHeader] = None

    def open(self) -> "PcapReader":
        self._fh = open(self.path, "rb")
        raw = self._fh.read(24)
        if len(raw) < 24:
            raise ValueError("File too short to be a valid PCAP")

        magic = struct.unpack_from("<I", raw)[0]
        if magic == PCAP_MAGIC_NATIVE:
            self._swapped = False
            endian = "<"
        elif magic == PCAP_MAGIC_SWAPPED:
            self._swapped = True
            endian = ">"
        else:
            raise ValueError(f"Not a PCAP file (magic=0x{magic:08X})")

        fields = struct.unpack_from(f"{endian}IHHiIII", raw)
        self.global_header = PcapGlobalHeader(*fields)

        link = self.global_header.network
        link_name = "Ethernet" if link == 1 else str(link)
        print(f"Opened: {self.path}")
        print(f"  Version : {self.global_header.version_major}.{self.global_header.version_minor}")
        print(f"  Snaplen : {self.global_header.snaplen} bytes")
        print(f"  Link    : {link} ({link_name})")
        return self

    def packets(self) -> Iterator[RawPacket]:
        endian = ">" if self._swapped else "<"
        fh = self._fh
        while True:
            hdr = fh.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", hdr)
            if incl_len > 65535:
                break
            data = fh.read(incl_len)
            if len(data) < incl_len:
                break
            yield RawPacket(ts_sec, ts_usec, data)

    def close(self):
        if self._fh:
            self._fh.close()
            self._fh = None

    def __enter__(self): return self.open()
    def __exit__(self, *_): self.close()


class PcapWriter:
    GLOBAL_HEADER = struct.pack("<IHHiIII",
        PCAP_MAGIC_NATIVE, 2, 4, 0, 0, 65535, 1)

    def __init__(self, path: str):
        self._fh = open(path, "wb")
        self._fh.write(self.GLOBAL_HEADER)

    def write(self, pkt: RawPacket):
        n = len(pkt.data)
        self._fh.write(struct.pack("<IIII", pkt.ts_sec, pkt.ts_usec, n, n))
        self._fh.write(pkt.data)

    def close(self):
        if self._fh:
            self._fh.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()