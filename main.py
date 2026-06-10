
# main.py
import argparse
import sys
from collections import defaultdict
from dpi.pcap_reader   import PcapReader, PcapWriter
from dpi.packet_parser import parse, TCPFlags
from dpi.sni_extractor import extract_sni, extract_http_host
from dpi.types         import FiveTuple, Flow, AppType, sni_to_app_type


class BlockingRules:
    def __init__(self):
        self.blocked_ips:     set[int]     = set()
        self.blocked_apps:    set[AppType] = set()
        self.blocked_domains: list[str]    = []

    def block_ip(self, ip: str):
        parts = list(map(int, ip.strip().split(".")))
        val = parts[0] | (parts[1]<<8) | (parts[2]<<16) | (parts[3]<<24)
        self.blocked_ips.add(val)
        print(f"[Rules] Blocked IP: {ip}")

    def block_app(self, name: str):
        for app in AppType:
            if app.value.lower() == name.lower():
                self.blocked_apps.add(app)
                print(f"[Rules] Blocked app: {name}")
                return
        print(f"[Rules] Unknown app: {name}", file=sys.stderr)

    def block_domain(self, domain: str):
        self.blocked_domains.append(domain.lower())
        print(f"[Rules] Blocked domain: {domain}")

    def is_blocked(self, src_ip_int: int, app: AppType, sni: str) -> bool:
        if src_ip_int in self.blocked_ips:
            return True
        if app in self.blocked_apps:
            return True
        sni_lower = sni.lower()
        return any(dom in sni_lower for dom in self.blocked_domains)


def run(input_path: str, output_path: str, rules: BlockingRules):
    banner = (
        "╔══════════════════════════════════════╗\n"
        "║        DPI ENGINE  (Python)          ║\n"
        "╚══════════════════════════════════════╝"
    )
    print(f"\n{banner}\n")

    flows:     dict[FiveTuple, Flow] = {}
    app_stats: dict[AppType, int]    = defaultdict(int)
    total = forwarded = dropped = 0

    with PcapReader(input_path) as reader, PcapWriter(output_path) as writer:
        print("\n[DPI] Processing packets...\n")
        for raw in reader.packets():
            total += 1
            p = parse(raw.data, raw.ts_sec, raw.ts_usec)
            if not p or not p.has_ip or (not p.has_tcp and not p.has_udp):
                continue

            key = FiveTuple(p._src_ip_int, p._dst_ip_int,
                            p.src_port, p.dst_port, p.protocol)

            if key not in flows:
                flows[key] = Flow(tuple=key)

            flow = flows[key]
            flow.packets += 1
            flow.bytes   += len(raw.data)

            # SNI extraction (HTTPS port 443)
            if (flow.app_type in (AppType.UNKNOWN, AppType.HTTPS)
                    and not flow.sni
                    and p.has_tcp and p.dst_port == 443
                    and len(p.payload) > 5):
                sni = extract_sni(p.payload)
                if sni:
                    flow.sni      = sni
                    flow.app_type = sni_to_app_type(sni)

            # HTTP Host extraction (port 80)
            if (flow.app_type in (AppType.UNKNOWN, AppType.HTTP)
                    and not flow.sni
                    and p.has_tcp and p.dst_port == 80
                    and p.payload):
                host = extract_http_host(p.payload)
                if host:
                    flow.sni      = host
                    flow.app_type = sni_to_app_type(host)

            # DNS fallback
            if flow.app_type == AppType.UNKNOWN:
                if p.src_port == 53 or p.dst_port == 53:
                    flow.app_type = AppType.DNS

            # Port-based fallback
            if flow.app_type == AppType.UNKNOWN:
                if p.dst_port == 443:
                    flow.app_type = AppType.HTTPS
                elif p.dst_port == 80:
                    flow.app_type = AppType.HTTP

            # Apply blocking rules
            if not flow.blocked:
                flow.blocked = rules.is_blocked(p._src_ip_int, flow.app_type, flow.sni)
                if flow.blocked:
                    label = flow.app_type.value
                    if flow.sni:
                        label += f": {flow.sni}"
                    print(f"[BLOCKED] {p.src_ip} -> {p.dst_ip}  ({label})")

            app_stats[flow.app_type] += 1

            if flow.blocked:
                dropped += 1
            else:
                forwarded += 1
                writer.write(raw)

    # Report
    print("\n╔══════════════════════════════════════════════╗")
    print("║             PROCESSING REPORT               ║")
    print("╠══════════════════════════════════════════════╣")
    print(f"║  Total Packets  : {total:>10}                 ║")
    print(f"║  Forwarded      : {forwarded:>10}                 ║")
    print(f"║  Dropped        : {dropped:>10}                 ║")
    print(f"║  Active Flows   : {len(flows):>10}                 ║")
    print("╠══════════════════════════════════════════════╣")
    print("║          APPLICATION BREAKDOWN              ║")
    print("╠══════════════════════════════════════════════╣")

    if total > 0:
        for app, count in sorted(app_stats.items(), key=lambda x: -x[1]):
            pct = 100.0 * count / total
            bar = "#" * int(pct / 5)
            print(f"║  {app.value:<14} {count:>7}  {pct:5.1f}%  {bar:<12}  ║")

    print("╚══════════════════════════════════════════════╝")

    unique_snis = {f.sni: f.app_type for f in flows.values() if f.sni}
    if unique_snis:
        print("\n[Detected Applications / Domains]")
        for sni, app in sorted(unique_snis.items()):
            print(f"  {sni}  ->  {app.value}")

    print(f"\nOutput written to: {output_path}\n")


def main():
    ap = argparse.ArgumentParser(description="DPI Engine - Deep Packet Inspection (Python)")
    ap.add_argument("input",  help="Input  .pcap file")
    ap.add_argument("output", help="Output .pcap file (filtered)")
    ap.add_argument("--block-ip",     metavar="IP",     action="append", default=[])
    ap.add_argument("--block-app",    metavar="APP",    action="append", default=[])
    ap.add_argument("--block-domain", metavar="DOMAIN", action="append", default=[])
    args = ap.parse_args()

    rules = BlockingRules()
    for ip  in args.block_ip:     rules.block_ip(ip)
    for app in args.block_app:    rules.block_app(app)
    for dom in args.block_domain: rules.block_domain(dom)

    run(args.input, args.output, rules)


if __name__ == "__main__":
    main()