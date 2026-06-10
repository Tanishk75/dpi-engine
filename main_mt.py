# main_mt.py
# Multi-threaded DPI Engine
# Architecture: Reader → Load Balancers → Fast Paths → Output Writer

import argparse
import sys
import threading
from collections import defaultdict
from queue import Queue, Empty

from dpi.pcap_reader   import PcapReader, PcapWriter, RawPacket
from dpi.packet_parser import parse
from dpi.sni_extractor import extract_sni, extract_http_host
from dpi.types         import FiveTuple, Flow, AppType, sni_to_app_type


# ── Blocking Rules (same as main.py) ─────────────────────────────────────────

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
        return any(d in sni.lower() for d in self.blocked_domains)


# ── Fast Path Thread ──────────────────────────────────────────────────────────
# Each FP has its own flow table — no locks needed for flow lookups

class FastPath:
    def __init__(self, fp_id: int, rules: BlockingRules,
                 output_queue: Queue, stats: dict):
        self.fp_id        = fp_id
        self.rules        = rules
        self.output_queue = output_queue
        self.stats        = stats
        self.input_queue  = Queue(maxsize=1000)
        self.flows:  dict[FiveTuple, Flow] = {}
        self.processed = 0

    def enqueue(self, item):
        self.input_queue.put(item)

    def run(self):
        while True:
            try:
                item = self.input_queue.get(timeout=0.5)
            except Empty:
                if self.stats.get("reading_done"):
                    break
                continue

            if item is None:
                break

            raw, p = item

            key = FiveTuple(p._src_ip_int, p._dst_ip_int,
                            p.src_port, p.dst_port, p.protocol)

            if key not in self.flows:
                self.flows[key] = Flow(tuple=key)

            flow = self.flows[key]
            flow.packets += 1
            flow.bytes   += len(raw.data)

            # SNI extraction
            if (flow.app_type in (AppType.UNKNOWN, AppType.HTTPS)
                    and not flow.sni
                    and p.has_tcp and p.dst_port == 443
                    and len(p.payload) > 5):
                sni = extract_sni(p.payload)
                if sni:
                    flow.sni      = sni
                    flow.app_type = sni_to_app_type(sni)

            # HTTP Host extraction
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

            # Port fallback
            if flow.app_type == AppType.UNKNOWN:
                if p.dst_port == 443:
                    flow.app_type = AppType.HTTPS
                elif p.dst_port == 80:
                    flow.app_type = AppType.HTTP

            # Blocking
            if not flow.blocked:
                flow.blocked = self.rules.is_blocked(
                    p._src_ip_int, flow.app_type, flow.sni)
                if flow.blocked:
                    label = flow.app_type.value
                    if flow.sni:
                        label += f": {flow.sni}"
                    print(f"[FP{self.fp_id}][BLOCKED] "
                          f"{p.src_ip} -> {p.dst_ip}  ({label})")

            if flow.blocked:
                with threading.Lock():
                    self.stats["dropped"] += 1
            else:
                with threading.Lock():
                    self.stats["forwarded"] += 1
                self.output_queue.put(raw)

            self.processed += 1


# ── Load Balancer Thread ──────────────────────────────────────────────────────
# Distributes parsed packets to Fast Paths using consistent hashing

class LoadBalancer:
    def __init__(self, lb_id: int, fast_paths: list[FastPath], stats: dict):
        self.lb_id       = lb_id
        self.fast_paths  = fast_paths
        self.stats       = stats
        self.input_queue = Queue(maxsize=1000)
        self.dispatched  = 0

    def enqueue(self, item):
        self.input_queue.put(item)

    def run(self):
        while True:
            try:
                item = self.input_queue.get(timeout=0.5)
            except Empty:
                if self.stats.get("reading_done"):
                    break
                continue

            if item is None:
                break

            raw, p = item

            # Consistent hashing — same 5-tuple always → same FP
            key = FiveTuple(p._src_ip_int, p._dst_ip_int,
                            p.src_port, p.dst_port, p.protocol)
            fp_idx = hash(key) % len(self.fast_paths)
            self.fast_paths[fp_idx].enqueue(item)
            self.dispatched += 1


# ── Output Writer Thread ──────────────────────────────────────────────────────

def output_writer(output_queue: Queue, writer: PcapWriter, stats: dict):
    while True:
        try:
            item = output_queue.get(timeout=0.5)
        except Empty:
            if stats.get("fps_done"):
                break
            continue
        if item is None:
            break
        writer.write(item)


# ── Main Engine ───────────────────────────────────────────────────────────────

def run(input_path: str, output_path: str,
        rules: BlockingRules, num_lbs: int, num_fps: int):

    banner = (
        "╔══════════════════════════════════════════════╗\n"
        "║      DPI ENGINE  (Python  Multi-threaded)    ║\n"
        "╚══════════════════════════════════════════════╝"
    )
    print(f"\n{banner}")
    print(f"  Load Balancers : {num_lbs}")
    print(f"  Fast Paths     : {num_fps}  (per LB)")
    print(f"  Total FPs      : {num_lbs * num_fps}\n")

    stats = {
        "total": 0, "forwarded": 0, "dropped": 0,
        "reading_done": False, "fps_done": False
    }

    output_queue: Queue = Queue(maxsize=2000)

    # Create Fast Paths
    all_fps: list[list[FastPath]] = []
    for lb_i in range(num_lbs):
        fps = [FastPath(lb_i * num_fps + fp_i, rules, output_queue, stats)
               for fp_i in range(num_fps)]
        all_fps.append(fps)

    # Create Load Balancers
    lbs = [LoadBalancer(i, all_fps[i], stats) for i in range(num_lbs)]

    # Start all threads
    threads = []

    for lb_fps in all_fps:
        for fp in lb_fps:
            t = threading.Thread(target=fp.run, daemon=True)
            t.start()
            threads.append(("fp", t, fp))

    for lb in lbs:
        t = threading.Thread(target=lb.run, daemon=True)
        t.start()
        threads.append(("lb", t, lb))

    with PcapWriter(output_path) as writer:
        # Start output writer thread
        out_thread = threading.Thread(
            target=output_writer,
            args=(output_queue, writer, stats),
            daemon=True
        )
        out_thread.start()

        # Reader (main thread)
        with PcapReader(input_path) as reader:
            print("[Reader] Processing packets...")
            for raw in reader.packets():
                stats["total"] += 1
                p = parse(raw.data, raw.ts_sec, raw.ts_usec)
                if not p or not p.has_ip or (not p.has_tcp and not p.has_udp):
                    continue

                # Hash to select Load Balancer
                key = FiveTuple(p._src_ip_int, p._dst_ip_int,
                                p.src_port, p.dst_port, p.protocol)
                lb_idx = hash(key) % num_lbs
                lbs[lb_idx].enqueue((raw, p))

            print(f"[Reader] Done — {stats['total']} packets read\n")
            stats["reading_done"] = True

        # Wait for LB threads
        for tag, t, obj in threads:
            if tag == "lb":
                t.join()

        # Wait for FP threads
        for tag, t, obj in threads:
            if tag == "fp":
                t.join()

        stats["fps_done"] = True
        out_thread.join()

    # ── Report ────────────────────────────────────────────────────────────────
    app_stats: dict[AppType, int] = defaultdict(int)
    all_flows: dict[FiveTuple, Flow] = {}
    for lb_fps in all_fps:
        for fp in lb_fps:
            for key, flow in fp.flows.items():
                all_flows[key] = flow
                app_stats[flow.app_type] += flow.packets

    total = stats["total"]

    print("╔══════════════════════════════════════════════╗")
    print("║             PROCESSING REPORT               ║")
    print("╠══════════════════════════════════════════════╣")
    print(f"║  Total Packets  : {total:>10}                 ║")
    print(f"║  Forwarded      : {stats['forwarded']:>10}                 ║")
    print(f"║  Dropped        : {stats['dropped']:>10}                 ║")
    print(f"║  Active Flows   : {len(all_flows):>10}                 ║")
    print("╠══════════════════════════════════════════════╣")
    print("║          THREAD STATISTICS                  ║")
    print("╠══════════════════════════════════════════════╣")
    for lb in lbs:
        print(f"║  LB{lb.lb_id} dispatched  : {lb.dispatched:>10}                 ║")
    for lb_fps in all_fps:
        for fp in lb_fps:
            print(f"║  FP{fp.fp_id} processed   : {fp.processed:>10}                 ║")
    print("╠══════════════════════════════════════════════╣")
    print("║          APPLICATION BREAKDOWN              ║")
    print("╠══════════════════════════════════════════════╣")

    if total > 0:
        for app, count in sorted(app_stats.items(), key=lambda x: -x[1]):
            pct = 100.0 * count / total
            bar = "#" * int(pct / 5)
            blocked = " (BLOCKED)" if app in rules.blocked_apps else ""
            print(f"║  {app.value:<14} {count:>7}  {pct:5.1f}%  {bar:<12}{blocked:<10}  ║")

    print("╚══════════════════════════════════════════════╝")

    unique_snis = {f.sni: f.app_type for f in all_flows.values() if f.sni}
    if unique_snis:
        print("\n[Detected Applications / Domains]")
        for sni, app in sorted(unique_snis.items()):
            print(f"  {sni}  ->  {app.value}")

    print(f"\nOutput written to: {output_path}\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="DPI Engine - Multi-threaded (Python)")
    ap.add_argument("input",  help="Input  .pcap file")
    ap.add_argument("output", help="Output .pcap file (filtered)")
    ap.add_argument("--block-ip",     metavar="IP",     action="append", default=[])
    ap.add_argument("--block-app",    metavar="APP",    action="append", default=[])
    ap.add_argument("--block-domain", metavar="DOMAIN", action="append", default=[])
    ap.add_argument("--lbs",  type=int, default=2, help="Number of Load Balancer threads")
    ap.add_argument("--fps",  type=int, default=2, help="Number of Fast Path threads per LB")
    args = ap.parse_args()

    rules = BlockingRules()
    for ip  in args.block_ip:     rules.block_ip(ip)
    for app in args.block_app:    rules.block_app(app)
    for dom in args.block_domain: rules.block_domain(dom)

    run(args.input, args.output, rules, args.lbs, args.fps)


if __name__ == "__main__":
    main()
    