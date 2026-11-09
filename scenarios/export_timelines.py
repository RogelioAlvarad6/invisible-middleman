"""Analyze every scenario capture and write the timelines the visualizer loads.

Run after build_scenarios.py:   uv run python scenarios/export_timelines.py
Writes visualizer/public/data/<scenario>.json and prints each scenario's score.
"""

import json
from pathlib import Path

from invisible_middleman.cli import score
from invisible_middleman.engine import analyze, dump

ROOT = Path(__file__).resolve().parents[1]
CAPS = ROOT / "scenarios" / "captures"
DATA = ROOT / "visualizer" / "public" / "data"

SCENARIOS = ["S1_benign", "S2_arp_poisoning", "S3_rogue_ra", "S4_rogue_dhcpv6", "S5_dual_stack_gap", "C1_challenge"]


def main():
    DATA.mkdir(parents=True, exist_ok=True)
    hosts = json.loads((CAPS / "hosts.json").read_text(encoding="utf-8"))
    print(f"{'scenario':<20}{'frames':>7}{'attack':>8}{'detected':>10}{'rate':>7}{'FP/2h':>7}")
    for sid in SCENARIOS:
        tl = analyze(str(CAPS / f"{sid}.pcap"), hosts)
        dump(tl, str(DATA / f"{sid}.json"))
        r = score(tl, json.loads((CAPS / f"{sid}.labels.json").read_text(encoding="utf-8")))
        rate = "-" if r["detection_rate"] is None else f"{r['detection_rate']:.0%}"
        print(f"{sid:<20}{len(tl['frames']):>7}{r['attack_frames']:>8}{r['detected']:>10}{rate:>7}{r['false_positives_per_2h']:>7}")


if __name__ == "__main__":
    main()
