"""CLI: pcap -> features.npz + flows.csv, using the live flow extractor.

    python -m training.build_features data/cicids2017/Monday-WorkingHours.pcap \\
        --out data/features/cicids2017-monday [--max-packets 3000000]
"""
from __future__ import annotations

import argparse
import time

from training.pcap_flows import pcap_to_feature_files


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("pcap")
    parser.add_argument("--out", required=True, help="output directory")
    parser.add_argument("--max-packets", type=int, default=None,
                        help="stop after this many packets (quick first model)")
    args = parser.parse_args(argv)

    started = time.time()

    def progress(stats, kept):
        rate = stats.packets_read / max(time.time() - started, 1e-9)
        print(f"  {stats.packets_read:>12,} packets  {kept:>9,} flows  {rate:,.0f} pkt/s", flush=True)

    n, stats = pcap_to_feature_files(args.pcap, args.out, args.max_packets, progress)
    print(f"done: {n:,} flows from {stats.packets_read:,} packets "
          f"({stats.packets_skipped:,} skipped) in {time.time() - started:.0f}s -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
