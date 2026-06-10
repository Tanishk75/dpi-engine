# DPI Engine (Python)

A Deep Packet Inspection engine written in Python — port of a C++ project.

## Features
- Reads and writes `.pcap` files with no external dependencies
- Parses Ethernet / IPv4 / TCP / UDP packets
- Extracts TLS SNI and HTTP Host headers
- Classifies traffic into 20+ apps (YouTube, Google, Netflix, Discord, etc.)
- Blocks traffic by IP, app name, or domain

## Usage

```bash
python main.py input.pcap output.pcap
python main.py input.pcap output.pcap --block-app YouTube
python main.py input.pcap output.pcap --block-domain facebook.com
python main.py input.pcap output.pcap --block-ip 192.168.1.50
```

## Project Structure
dpi_engine/
├── dpi/
│   ├── init.py        # Package init
│   ├── types.py           # Data structures + app classification
│   ├── pcap_reader.py     # PCAP file reader and writer
│   ├── packet_parser.py   # Ethernet / IP / TCP / UDP parser
│   └── sni_extractor.py   # TLS SNI + HTTP Host extractor
├── main.py                # CLI entry point
├── requirements.txt       # No external dependencies
└── .gitignore

## Requirements
- Python 3.10+
- No external libraries needed