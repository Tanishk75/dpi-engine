# DPI Engine (Python)

A Deep Packet Inspection engine written in Python — port of a C++ project.  
Examines network packets to identify, classify, and block application traffic.

---

## What is DPI?

**Deep Packet Inspection (DPI)** examines the *contents* of network packets, not just headers.  
Unlike simple firewalls that only check source/destination IP, DPI looks inside the payload.

**Real-World Uses:**
- ISPs throttle or block certain apps (e.g. BitTorrent)
- Enterprises block social media on office networks
- Parental controls block inappropriate websites
- Security systems detect malware or intrusion attempts

```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                             ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## How a Packet is Structured

Every network packet is like a Russian nesting doll — headers wrapped inside headers:

```
┌──────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                       │
│ ┌──────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                         │ │
│ │ ┌──────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                    │ │ │
│ │ │ ┌──────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI      │ │ │ │
│ │ │ └──────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
```

---

## What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake.  
When you visit `https://www.youtube.com`, your browser sends a **Client Hello** that includes  
the domain name *in plaintext* before encryption starts.

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

> Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## Project Structure

```
dpi_engine/
├── dpi/
│   ├── __init__.py        # Package init
│   ├── types.py           # Data structures + app classification (20+ apps)
│   ├── pcap_reader.py     # PCAP file reader and writer (no external libs)
│   ├── packet_parser.py   # Ethernet / IPv4 / TCP / UDP parser
│   └── sni_extractor.py   # TLS SNI + HTTP Host extractor
├── main.py                # Single-threaded CLI entry point
├── main_mt.py             # Multi-threaded CLI entry point
├── requirements.txt       # No external dependencies
└── .gitignore
```

---

## The Journey of a Packet

### Step 1 — Read PCAP File

```
PCAP File Format:
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp + length
│ Packet Data  (variable)    │  ← Actual network bytes
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2 — Parse Protocol Headers

```
raw bytes:
[0-13]   Ethernet Header  → src/dst MAC, EtherType
[14-33]  IP Header        → src/dst IP, protocol, TTL
[34-53]  TCP Header       → src/dst port, flags, seq
[54+]    Payload          → TLS / HTTP / DNS data
```

### Step 3 — Build the Five-Tuple

A connection is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's app identifier |
| Destination Port | 443 | Service (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

All packets with the same five-tuple belong to the same **flow**.

### Step 4 — Extract SNI (Deep Packet Inspection)

For HTTPS traffic on port 443, we parse the TLS Client Hello:

```
Byte 0:     Content Type = 0x16 (Handshake)
Byte 5:     Handshake Type = 0x01 (Client Hello)
...
SNI Extension (type 0x0000):
└── Server Name: "www.youtube.com"  ← EXTRACTED
```

### Step 5 — Classify the Flow

```python
sni = "www.youtube.com"
# maps to → AppType.YOUTUBE
```

Supports 20+ apps: Google, YouTube, Facebook, Instagram, Netflix,
Amazon, Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify,
Zoom, Discord, GitHub, Cloudflare, Twitter/X, and more.

### Step 6 — Apply Blocking Rules

```
Packet arrives
│
▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │ No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │ No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │ No
                ▼
        FORWARD → write to output.pcap
```

### Step 7 — Generate Report

```
╔══════════════════════════════════════════════╗
║             PROCESSING REPORT               ║
╠══════════════════════════════════════════════╣
║  Total Packets  :         69                ║
║  Forwarded      :         61                ║
║  Dropped        :          8                ║
║  Active Flows   :         38                ║
╠══════════════════════════════════════════════╣
║          APPLICATION BREAKDOWN              ║
╠══════════════════════════════════════════════╣
║  HTTPS              34   49.3%  #########   ║
║  YouTube             4    5.8%  # (BLOCKED) ║
║  DNS                 4    5.8%  #           ║
╚══════════════════════════════════════════════╝
```

---

## Two Versions

| Version | File | Use Case |
|---------|------|----------|
| Single-threaded | `main.py` | Learning, small captures |
| Multi-threaded | `main_mt.py` | Large captures, high performance |

### Multi-threaded Architecture

```
            ┌─────────────────┐
            │  Reader Thread  │
            │  (reads PCAP)   │
            └────────┬────────┘
                     │ hash(5-tuple) % num_lbs
      ┌──────────────┴──────────────┐
      ▼                             ▼
┌─────────────────┐           ┌─────────────────┐
│  LB0 Thread     │           │  LB1 Thread     │
│ (Load Balancer) │           │ (Load Balancer) │
└────────┬────────┘           └────────┬────────┘
         │ hash % num_fps              │ hash % num_fps
    ┌────┴────┐                   ┌────┴────┐
    ▼         ▼                   ▼         ▼
┌───────┐ ┌───────┐           ┌───────┐ ┌───────┐
│  FP0  │ │  FP1  │           │  FP2  │ │  FP3  │
│(Fast  │ │(Fast  │           │(Fast  │ │(Fast  │
│ Path) │ │ Path) │           │ Path) │ │ Path) │
└───┬───┘ └───┬───┘           └───┬───┘ └───┬───┘
    └─────────┴───────────────────┴─────────┘
                        │
                        ▼
            ┌───────────────────────┐
            │  Output Writer Thread │
            │   (writes to PCAP)    │
            └───────────────────────┘
```

**Why consistent hashing?**  
All packets of the same connection always go to the same Fast Path thread,  
so flow state is tracked correctly without locks.

---

## Usage

```bash
# Basic
python main.py input.pcap output.pcap

# Block by app
python main.py input.pcap output.pcap --block-app YouTube

# Block by domain
python main.py input.pcap output.pcap --block-domain facebook.com

# Block by IP
python main.py input.pcap output.pcap --block-ip 192.168.1.50

# Combine rules
python main.py input.pcap output.pcap --block-app YouTube --block-domain tiktok.com --block-ip 192.168.1.50

# Multi-threaded
python main_mt.py input.pcap output.pcap --lbs 2 --fps 4
```

---

## Requirements

- Python 3.10+
- No external libraries needed — pure Python