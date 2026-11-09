"""Command-line interface.

    invisible-middleman analyze capture.pcap -o timeline.json [--hosts hosts.json] [--trusted-mac MAC]
    invisible-middleman score timeline.json labels.json
"""

from __future__ import annotations

import argparse
import json
import sys

from .engine import analyze, dump
from .rules import SEVERITY_ORDER

COLORS = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": ""}
RESET = "\033[0m"


def score(timeline: dict, labels: dict) -> dict:
    """Detection rate = labeled attack frames with at least one detection alert / all labeled attack frames.
    False positives = detection alerts on frames that are not labeled as attack frames.

    XP-01 ("a host now trusts the attacker") is left out of both numbers. It is an
    impact alert: it fires on whatever frame finishes the damage, which can be an
    ordinary frame (for example the victim's own ARP reply after a rogue DHCP lease).
    """
    attack = set(labels.get("attack_frames", []))
    alerted = {f["i"] for f in timeline["frames"]
               if any(a["rule"] != "XP-01" for a in f["alerts"])}
    detected = attack & alerted
    fp_frames = sorted(alerted - attack)
    duration_h = max(timeline["frames"][-1]["rel_t"] / 3600, 1e-9) if timeline["frames"] else 0
    return {
        "attack_frames": len(attack),
        "detected": len(detected),
        "detection_rate": round(len(detected) / len(attack), 4) if attack else None,
        "missed": sorted(attack - alerted),
        "false_positive_frames": fp_frames,
        "false_positives_per_2h": round(len(fp_frames) / duration_h * 2, 3) if duration_h else 0,
        "duration_hours": round(duration_h, 3),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="invisible-middleman",
                                description="Detect layer-2 trust attacks (ARP, NDP, RA, DHCP, DHCPv6) in a capture.")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyze a .pcap and write a timeline JSON for the visualizer")
    a.add_argument("pcap")
    a.add_argument("-o", "--out", help="timeline JSON to write")
    a.add_argument("--hosts", help="JSON file mapping MAC -> {name, role}")
    a.add_argument("--trusted-mac", action="append", default=[], help="MAC of the real router (repeatable)")
    a.add_argument("-q", "--quiet", action="store_true", help="only print the summary")

    s = sub.add_parser("score", help="compare a timeline against a labels file")
    s.add_argument("timeline")
    s.add_argument("labels")

    args = p.parse_args(argv)

    if args.cmd == "analyze":
        meta = json.load(open(args.hosts, encoding="utf-8")) if args.hosts else None
        tl = analyze(args.pcap, meta, args.trusted_mac)
        if not args.quiet:
            for f in tl["frames"]:
                for al in f["alerts"]:
                    c = COLORS.get(al["severity"], "")
                    print(f"{c}[{al['severity'].upper():6}]{RESET} frame {al['frame']:>4}  "
                          f"{al['rule']:<7} {al['mitre']:<10} {al['title']}")
        sm = tl["summary"]
        print(f"\n{sm['frames']} frames, {sm['alerts']} alerts on {sm['frames_with_alerts']} frames")
        for rule, n in sorted(sm["by_rule"].items()):
            print(f"  {rule:<7} x{n}")
        for note in sm["notes"]:
            print(f"note: {note}")
        if args.out:
            dump(tl, args.out)
            print(f"timeline written to {args.out}")
        return 0

    if args.cmd == "score":
        tl = json.load(open(args.timeline, encoding="utf-8"))
        result = score(tl, json.load(open(args.labels, encoding="utf-8")))
        print(json.dumps(result, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
