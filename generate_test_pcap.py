# generate_test_pcap.py
# Generates a test PCAP file with realistic traffic including
# YouTube, Facebook, Netflix, Google, Discord and more.
# Run: python generate_test_pcap.py

import struct
import socket


PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII",
    0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

TS = 1700000000  # base timestamp


def u16(val):
    return struct.pack(">H", val)

def u32(val):
    return struct.pack(">I", val)

def ip_to_bytes(ip):
    return socket.inet_aton(ip)

def make_eth(src_mac, dst_mac):
    return bytes.fromhex(src_mac.replace(":","")) + \
           bytes.fromhex(dst_mac.replace(":","")) + \
           b"\x08\x00"  # IPv4

def make_ip(src_ip, dst_ip, protocol, payload_len):
    total = 20 + payload_len
    return (
        b"\x45"           # version=4, ihl=5
        b"\x00"           # DSCP
        + u16(total)      # total length
        + b"\x00\x01"     # identification
        + b"\x40\x00"     # flags + fragment offset
        + b"\x40"         # TTL = 64
        + bytes([protocol])
        + b"\x00\x00"     # checksum (zero)
        + ip_to_bytes(src_ip)
        + ip_to_bytes(dst_ip)
    )

def make_tcp(src_port, dst_port, flags=0x18):
    return (
        u16(src_port)
        + u16(dst_port)
        + b"\x00\x00\x00\x01"  # seq
        + b"\x00\x00\x00\x00"  # ack
        + b"\x50"               # data offset = 5
        + bytes([flags])        # flags
        + b"\xff\xff"           # window
        + b"\x00\x00"           # checksum
        + b"\x00\x00"           # urgent
    )

def make_udp(src_port, dst_port, payload_len):
    length = 8 + payload_len
    return u16(src_port) + u16(dst_port) + u16(length) + b"\x00\x00"

def make_tls_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode()
    sni_len   = len(sni_bytes)

    # SNI extension
    sni_ext = (
        b"\x00\x00"              # extension type: SNI
        + u16(sni_len + 5)       # extension length
        + u16(sni_len + 3)       # SNI list length
        + b"\x00"                # SNI type: host_name
        + u16(sni_len)           # SNI name length
        + sni_bytes              # SNI name
    )

    extensions = sni_ext
    ext_len    = len(extensions)

    # Client Hello body
    hello_body = (
        b"\x03\x03"              # client version TLS 1.2
        + b"\x00" * 32           # random
        + b"\x00"                # session ID length
        + b"\x00\x02\xc0\x2b"   # cipher suites
        + b"\x01\x00"            # compression methods
        + u16(ext_len)           # extensions length
        + extensions
    )

    # Handshake header
    handshake = (
        b"\x01"                  # Client Hello
        + b"\x00" + u16(len(hello_body))
        + hello_body
    )

    # TLS record
    record = (
        b"\x16"                  # Content Type: Handshake
        + b"\x03\x01"            # TLS 1.0
        + u16(len(handshake))
        + handshake
    )
    return record

def make_dns_query(domain: str) -> bytes:
    parts  = domain.encode().split(b".")
    qname  = b"".join(bytes([len(p)]) + p for p in parts) + b"\x00"
    return (
        b"\x00\x01"   # transaction ID
        + b"\x01\x00" # flags: standard query
        + b"\x00\x01" # questions: 1
        + b"\x00\x00" * 3
        + qname
        + b"\x00\x01" # type A
        + b"\x00\x01" # class IN
    )

def write_packet(f, eth, ip, transport, payload, ts_offset=0):
    global TS
    data = eth + ip + transport + payload
    hdr  = struct.pack("<IIII", TS + ts_offset, 0, len(data), len(data))
    f.write(hdr + data)

# Traffic definitions: (src_ip, dst_ip, src_port, dst_port, sni, label)
HTTPS_FLOWS = [
    ("192.168.1.10", "142.250.185.100", 52001, 443, "www.youtube.com",    "YouTube"),
    ("192.168.1.10", "142.250.185.101", 52002, 443, "ytimg.com",          "YouTube"),
    ("192.168.1.11", "157.240.100.100", 52003, 443, "www.facebook.com",   "Facebook"),
    ("192.168.1.11", "157.240.100.101", 52004, 443, "fbcdn.net",          "Facebook"),
    ("192.168.1.12", "52.94.100.100",   52005, 443, "www.netflix.com",    "Netflix"),
    ("192.168.1.13", "142.250.100.100", 52006, 443, "www.google.com",     "Google"),
    ("192.168.1.14", "13.107.100.100",  52007, 443, "www.microsoft.com",  "Microsoft"),
    ("192.168.1.15", "162.159.100.100", 52008, 443, "discord.com",        "Discord"),
    ("192.168.1.16", "185.60.100.100",  52009, 443, "www.instagram.com",  "Instagram"),
    ("192.168.1.17", "17.253.100.100",  52010, 443, "www.apple.com",      "Apple"),
    ("192.168.1.18", "104.18.100.100",  52011, 443, "open.spotify.com",   "Spotify"),
    ("192.168.1.19", "3.33.100.100",    52012, 443, "zoom.us",            "Zoom"),
    ("192.168.1.20", "149.154.100.100", 52013, 443, "web.telegram.org",   "Telegram"),
    ("192.168.1.21", "140.82.100.100",  52014, 443, "github.com",         "GitHub"),
    ("192.168.1.22", "104.244.100.100", 52015, 443, "twitter.com",        "Twitter"),
    ("192.168.1.23", "185.199.100.100", 52016, 443, "tiktok.com",         "TikTok"),
    ("192.168.1.24", "13.35.100.100",   52017, 443, "www.amazon.com",     "Amazon"),
]

HTTP_FLOWS = [
    ("192.168.1.25", "93.184.100.100",  52018, 80,  "example.com",        "HTTP"),
    ("192.168.1.26", "54.235.100.100",  52019, 80,  "httpbin.org",        "HTTP"),
]

DNS_QUERIES = [
    ("192.168.1.10", "8.8.8.8", "www.youtube.com"),
    ("192.168.1.11", "8.8.8.8", "www.facebook.com"),
    ("192.168.1.12", "8.8.8.8", "www.netflix.com"),
    ("192.168.1.13", "8.8.8.8", "www.google.com"),
]

SRC_MAC = "aa:bb:cc:dd:ee:ff"
DST_MAC = "11:22:33:44:55:66"

output_file = "test_traffic.pcap"

with open(output_file, "wb") as f:
    f.write(PCAP_GLOBAL_HEADER)
    ts = 0

    # Write HTTPS flows (3 packets each: SYN + Client Hello + Data)
    for src_ip, dst_ip, src_port, dst_port, sni, label in HTTPS_FLOWS:
        eth = make_eth(SRC_MAC, DST_MAC)

        # SYN
        tcp_syn = make_tcp(src_port, dst_port, flags=0x02)
        ip      = make_ip(src_ip, dst_ip, 6, len(tcp_syn))
        write_packet(f, eth, ip, tcp_syn, b"", ts); ts += 1

        # Client Hello (TLS SNI)
        tls     = make_tls_client_hello(sni)
        tcp     = make_tcp(src_port, dst_port, flags=0x18)
        ip      = make_ip(src_ip, dst_ip, 6, len(tcp) + len(tls))
        write_packet(f, eth, ip, tcp, tls, ts); ts += 1

        # Data packet (same flow, no SNI)
        data    = b"\x17\x03\x03" + b"\x00" * 20  # TLS app data
        tcp     = make_tcp(src_port, dst_port, flags=0x18)
        ip      = make_ip(src_ip, dst_ip, 6, len(tcp) + len(data))
        write_packet(f, eth, ip, tcp, data, ts); ts += 1

    # Write HTTP flows
    for src_ip, dst_ip, src_port, dst_port, host, label in HTTP_FLOWS:
        eth     = make_eth(SRC_MAC, DST_MAC)
        payload = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
        tcp     = make_tcp(src_port, dst_port, flags=0x18)
        ip      = make_ip(src_ip, dst_ip, 6, len(tcp) + len(payload))
        write_packet(f, eth, ip, tcp, payload, ts); ts += 1

    # Write DNS queries
    for src_ip, dst_ip, domain in DNS_QUERIES:
        eth     = make_eth(SRC_MAC, DST_MAC)
        payload = make_dns_query(domain)
        udp     = make_udp(54321, 53, len(payload))
        ip      = make_ip(src_ip, dst_ip, 17, len(udp) + len(payload))
        write_packet(f, eth, ip, udp, payload, ts); ts += 1

total = len(HTTPS_FLOWS)*3 + len(HTTP_FLOWS) + len(DNS_QUERIES)
print(f"Generated {output_file} with {total} packets")
print(f"  HTTPS flows : {len(HTTPS_FLOWS)} (3 packets each)")
print(f"  HTTP flows  : {len(HTTP_FLOWS)}")
print(f"  DNS queries : {len(DNS_QUERIES)}")
print(f"\nApps included: YouTube, Facebook, Netflix, Google,")
print(f"  Microsoft, Discord, Instagram, Apple, Spotify,")
print(f"  Zoom, Telegram, GitHub, Twitter, TikTok, Amazon")