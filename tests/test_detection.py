"""Tests for the detection rules and the host-state model.

The scenario tests measure the proposal's success metrics against ground truth:
  * detection rate >= 95% of labeled attack frames in S2-S5 (and C1)
  * no more than 1 false positive per 2 hours on the benign capture S1
The unit tests check that the host model follows the RFC update rules the
visualizer teaches (RFC 826 merge rule, RFC 4861 Override flag).
"""

import json
import sys
from pathlib import Path

import pytest
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, IPv6
from scapy.layers.l2 import ARP, Ether

from invisible_middleman.cli import score
from invisible_middleman.engine import Engine
from invisible_middleman.parse import normalize

ROOT = Path(__file__).resolve().parents[1]
CAPS = ROOT / "scenarios" / "captures"
sys.path.insert(0, str(ROOT / "scenarios"))
import build_scenarios  # noqa: E402

ATTACKS = ["S2_arp_poisoning", "S3_rogue_ra", "S4_rogue_dhcpv6", "S5_dual_stack_gap", "C1_challenge"]

ROUTER, VICTIM, ATTACKER = "08:00:27:00:00:01", "08:00:27:00:00:10", "08:00:27:00:00:66"


@pytest.fixture(scope="session", autouse=True)
def captures():
    build_scenarios.main()          # always rebuild so tests match the current generator
    return CAPS


def run(sid):
    from invisible_middleman.engine import analyze
    hosts = json.loads((CAPS / "hosts.json").read_text(encoding="utf-8"))
    tl = analyze(str(CAPS / f"{sid}.pcap"), hosts)
    labels = json.loads((CAPS / f"{sid}.labels.json").read_text(encoding="utf-8"))
    return tl, labels


def rules_fired(tl):
    return {a["rule"] for f in tl["frames"] for a in f["alerts"]}


# ------------------------------------------------------------- success metrics
@pytest.mark.parametrize("sid", ATTACKS)
def test_detection_rate_meets_target(sid):
    tl, labels = run(sid)
    result = score(tl, labels)
    assert result["detection_rate"] >= 0.95, f"missed frames {result['missed']}"


@pytest.mark.parametrize("sid", ATTACKS)
def test_no_false_positives_in_attack_scenarios(sid):
    tl, labels = run(sid)
    assert score(tl, labels)["false_positive_frames"] == []


def test_benign_capture_false_positive_rate():
    tl, labels = run("S1_benign")
    result = score(tl, labels)
    assert result["duration_hours"] >= 2.0
    assert result["false_positives_per_2h"] <= 1.0
    assert rules_fired(tl) == set()


# ------------------------------------------------------------- right rule, right attack
@pytest.mark.parametrize("sid, expected", [
    ("S2_arp_poisoning", {"ARP-01", "ARP-02", "XP-01"}),
    ("S3_rogue_ra", {"RA-01", "RA-02", "XP-01"}),
    ("S4_rogue_dhcpv6", {"D6-01", "D6-02", "XP-01"}),
    ("S5_dual_stack_gap", {"ARP-01", "ND-01", "RA-01", "D6-01"}),
    ("C1_challenge", {"DHCP-01", "DHCP-02", "XP-01"}),
])
def test_expected_rules_fire(sid, expected):
    tl, _ = run(sid)
    assert expected <= rules_fired(tl)


def test_rogue_dhcpv6_only_flags_ipv4_only_gap_when_no_router():
    # D6-02 means "DHCPv6 on a network with no IPv6 router". S5 has a real RA, S4 does not.
    assert "D6-02" in rules_fired(run("S4_rogue_dhcpv6")[0])
    assert "D6-02" not in rules_fired(run("S5_dual_stack_gap")[0])


def test_alerts_carry_mitre_mapping():
    tl, _ = run("S2_arp_poisoning")
    arp = [a for f in tl["frames"] for a in f["alerts"] if a["rule"] == "ARP-01"]
    assert arp and all(a["mitre"] == "T1557.002" for a in arp)


# ------------------------------------------------------------- defense modeling
def test_defenses_block_the_right_frames():
    tl, labels = run("S5_dual_stack_gap")
    blocked = {f["i"]: set(f["blocked_by"]) for f in tl["frames"] if f["blocked_by"]}
    kinds = {f["i"]: f["kind"] for f in tl["frames"]}
    for i, by in blocked.items():
        expected = {"arp": {"dai"}, "ra": {"ra_guard"}, "dhcp6": {"dhcpv6_guard"}}.get(kinds[i])
        assert by == expected, (i, kinds[i], by)
    # The spoofed NA is NOT stopped by any of the four defenses: that is the teaching point of S5.
    na = [f for f in tl["frames"] if f["kind"] == "na" and f["i"] in labels["attack_frames"]]
    assert na and all(f["blocked_by"] == [] for f in na)


def test_static_arp_only_protects_the_client_side():
    tl, _ = run("S2_arp_poisoning")
    poison = [e for f in tl["frames"] for e in f["effects"] if e["kind"] == "arp" and e["value"] == ATTACKER]
    to_client = [e for e in poison if e["host"] == VICTIM and e["key"] == "192.168.56.1"]   # victim's gateway entry
    to_router = [e for e in poison if e["host"] == ROUTER and e["key"] == "192.168.56.10"]  # router's entry for victim
    assert to_client and all(e["static_arp_blocks"] for e in to_client)
    assert to_router and not any(e["static_arp_blocks"] for e in to_router)


# ------------------------------------------------------------- host-state model
def test_final_trust_cards():
    tl, _ = run("S3_rogue_ra")
    win = next(h for h in tl["hosts"] if h["name"] == "win11-client")["final"]
    assert win["gw6_mac"] == ATTACKER and win["dns6"].startswith("fe80::a00:27ff:fe00:66")
    assert win["gw4_mac"] == ROUTER          # IPv4 untouched in the IPv6 attack


def _events(*pkts):
    evs = []
    for i, p in enumerate(pkts, 1):
        p.time = 1000.0 + i
        evs.append(normalize(p, i))
    return evs


def test_rfc826_unsolicited_reply_overwrites_existing_entry():
    eng = Engine({ROUTER: {"name": "router", "role": "router"}})
    req = Ether(src=VICTIM, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=VICTIM, psrc="10.0.0.10", pdst="10.0.0.1")
    rep = Ether(src=ROUTER, dst=VICTIM) / ARP(op=2, hwsrc=ROUTER, psrc="10.0.0.1", hwdst=VICTIM, pdst="10.0.0.10")
    forged = Ether(src=ATTACKER, dst=VICTIM) / ARP(op=2, hwsrc=ATTACKER, psrc="10.0.0.1", hwdst=VICTIM, pdst="10.0.0.10")
    eng.run(_events(req, rep, forged))
    assert eng.hosts[VICTIM].arp["10.0.0.1"] == ATTACKER
    assert any(a["rule"] == "ARP-01" for a in eng.alerts)


def test_rfc4861_na_without_override_does_not_replace_entry():
    ll = "fe80::1"

    def na(mac, override):
        return (Ether(src=mac, dst=VICTIM) / IPv6(src=ll, dst="fe80::10") /
                ICMPv6ND_NA(tgt=ll, S=0, O=override) / ICMPv6NDOptDstLLAddr(lladdr=mac))

    eng = Engine({ROUTER: {"name": "router", "role": "router"}})
    eng.host(VICTIM).nd[ll] = ROUTER
    eng.truth6[ll] = (ROUTER, "test setup")
    eng.run(_events(na(ATTACKER, 0)))
    assert eng.hosts[VICTIM].nd[ll] == ROUTER          # O=0: entry kept
    eng.run(_events(na(ATTACKER, 1)))
    assert eng.hosts[VICTIM].nd[ll] == ATTACKER        # O=1: entry replaced
