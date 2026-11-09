# Design document

## 1. Architecture

```
 scenarios/build_scenarios.py        src/invisible_middleman/               visualizer/
 (Scapy, writes .pcap + labels)      parse.py   -> normalized events         fold.js   -> host state per frame
              |                      engine.py  -> host model + truth +      main.js   -> stepper, cards, quiz
              v                                    rules + effects           diagram.js-> D3 network diagram
     captures/*.pcap  ------------>  cli.py     -> timeline JSON  -------->  public/data/*.json
     captures/*.labels.json -------> score (detection rate, FP/2h)           public/content/scenarios.json
```

The engine and the visualizer only share the timeline JSON (section 4), so each side can be
developed and tested on its own (proposal risk: tight core-development window).

## 2. Two views of the network

The engine keeps two separate pictures, because the attack lives in the gap between them.

**Sensor truth** (`Engine.truth4`, `Engine.truth6`): which MAC really owns each address. Learned,
in order of trust, from the trusted router's DHCP leases and server identifier, from RAs sent by
the trusted router, and otherwise from the first claim seen (trust on first use). Detection rules
compare every new claim against this table. This is the cross-protocol idea from ARProof [10]:
an ARP claim is checked against DHCP evidence, and this project extends it to IPv6 ND, RAs and
DHCPv6.

**Host beliefs** (`Host`): what each host would actually do, following the RFC rules:

| Message | Update rule implemented | Source |
|---------|------------------------|--------|
| ARP request or reply | If the receiver already has the sender's IP cached, overwrite it; if the receiver is the target, add it. Unsolicited replies still update. | RFC 826 "merge" step [2] |
| Neighbor Advertisement | Fill an entry the host was waiting on; replace an existing entry only if O=1; otherwise ignore | RFC 4861 sec. 7.2.5 [3] |
| Neighbor Solicitation with SLLAO | The target creates or updates an entry for the sender | RFC 4861 sec. 7.2.3 [3] |
| Router Advertisement | Lifetime > 0 adds the router; 0 removes it. Default router = highest preference, then first learned. SLLAO updates the neighbor cache. RDNSS sets the IPv6 DNS server. | RFC 4861 [3], RFC 4191 [12], RFC 8106 [13] |
| DHCPv4 ACK | Client sets its address, gateway (option 3) and DNS (option 6) | RFC 2131 [15], RFC 2132 [18] |
| DHCPv6 Reply | Client sets its IPv6 DNS server (option 23) and adds IA_NA addresses | RFC 8415 [14] |

Hosts are keyed by MAC, not IP, so temporary IPv6 addresses (RFC 8981 [16]) do not look like new
hosts.

## 3. Detection rules and defense modeling

Rules are listed in the README. Each alert records the frame, severity, the field that caused it,
a plain-language explanation, and the ATT&CK technique [7], [8].

Each frame also records `blocked_by`, the switch defenses that would have dropped it:

| Toggle | Frames dropped | Modeled on |
|--------|----------------|------------|
| `dai` (DHCP snooping + DAI) | ARP whose sender IP/MAC contradicts the binding table; DHCPv4 server replies from untrusted ports | [11] |
| `ra_guard` | RAs from untrusted ports | RFC 6105 [5] |
| `dhcpv6_guard` | DHCPv6 ADVERTISE/REPLY from untrusted ports | |
| `static_arp` | (not a frame filter) ARP effects that would change a client's gateway entry | [1, Sec. 5.2.4] |

None of the four toggles stops Neighbor Advertisement spoofing. That needs ND inspection on the
switch or SEND (RFC 3971 [19]), and S5 is built to show it.

## 4. Timeline JSON format (`invisible-middleman/timeline@1`)

```jsonc
{
  "schema": "invisible-middleman/timeline@1",
  "router_mac": "08:00:27:00:00:01",
  "hosts":  [{ "mac", "name", "role": "router|client", "ip4", "ip6": [], "final": { /* trust card */ } }],
  "frames": [{
    "i": 39, "t": 1793750424.7, "rel_t": 24.7,        // frame number matches Wireshark
    "kind": "arp|ns|na|ra|dhcp|dhcp6|data|other", "proto": "ARP", "summary": "...",
    "src_mac": "...", "dst_mac": "...",
    /* protocol fields: op, psrc, hwsrc, pdst, target, tlla, O, prf, lifetime, rdnss, msg, router, dns, ... */
    "alerts":     [{ "rule", "severity", "title", "explain", "field", "mitre", "frame" }],
    "effects":    [{ "host", "kind": "arp|nd|router6|router6_del|ip4|ip6|gw4|dns4|dns6", "key", "value", "prev",
                     "static_arp_blocks": false }],
    "blocked_by": ["dai"]
  }],
  "rules": { /* rule catalog from rules.py */ },
  "summary": { "frames", "alerts", "frames_with_alerts", "by_rule": {}, "notes": [] }
}
```

The visualizer rebuilds every host's state at frame *n* by applying the `effects` of frames 1..n
in order, skipping frames whose `blocked_by` contains an enabled toggle (`fold.js`). That is how
toggling a defense re-plays the scenario without re-running Python.

## 5. Scenario design

All scenarios share one lab: router `08:00:27:00:00:01` (192.168.56.1, `fe80::a00:27ff:fe00:1`),
ubuntu-client `.10`, win11-client `.20`, kali `.66`, and a phone `.30` that joins later. MACs use
the VirtualBox prefix and IPv6 uses the documentation prefix 2001:db8:56::/64 (RFC 3849).

| Scenario | Attack frames (labels) | Key frames for the guide |
|----------|------------------------|--------------------------|
| S1 | none, 2 h | 5 DHCP ACK, 7 ARP reply, 23 RA, 165 temporary address, 235 gratuitous ARP |
| S2 | 20 forged ARP replies | 39 victim poisoned, 40 router poisoned, 45-46 traffic relayed |
| S3 | 5 rogue RAs | 37 rogue RA, 38 DNS to kali, 43 real RA returns |
| S4 | 4 rogue DHCPv6 messages | 26 Solicit, 29 Reply, 32 WPAD lookup |
| S5 | 6 ARP, 1 NA, 2 RA, 2 DHCPv6 | 37 ARP blocked, 44 NA spoof, 45 RA, 49 DHCPv6 |
| C1 | 2 rogue DHCPv4 messages | 42 rogue OFFER, 44 rogue ACK |

## 6. Testing

- `tests/test_detection.py` (pytest, 23 tests): detection rate >= 95% and zero false positives on
  every scenario, at most 1 false positive per 2 hours on S1, the expected rules per attack,
  defense modeling, and unit tests for the RFC 826 and RFC 4861 update rules.
- `visualizer/tests/fold.test.js` (node:test, 7 tests): each defense toggle keeps exactly the
  trust cards it should keep correct, using the real exported timelines.
- XP-01 is excluded from the detection-rate and false-positive numbers because it is an impact
  alert that fires on whichever frame completes the damage (for example the victim's own ARP
  reply after a rogue DHCP lease).
