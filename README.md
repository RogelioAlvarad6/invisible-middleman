# The Invisible Middleman

An interactive visualizer and detector for layer-2 trust attacks on dual-stack (IPv4 + IPv6) LANs.
CprE 5300 project, Fall 2026, Rogelio Alvarado-Diaz.

Every device on a LAN decides who its router and DNS server are using protocols with no
authentication: ARP, IPv6 Neighbor Discovery, Router Advertisements, DHCP and DHCPv6. This
project shows, frame by frame, how one forged packet changes what a host trusts, and why
defenses deployed only for IPv4 leave IPv6 wide open.

It has two parts:

1. **Analysis engine** (`src/invisible_middleman/`, Python + Scapy). Replays a capture through a
   model of every host's ARP cache, neighbor cache, default routers and DNS servers, and flags
   suspicious events across ARP, NDP, RA, DHCP and DHCPv6. Alerts are mapped to MITRE ATT&CK.
2. **Visualizer** (`visualizer/`, JavaScript + D3 + Vite). Steps through a scenario with a network
   diagram, live trust cards, defense toggles, guided checkpoints, quizzes and a challenge mode.

The analysis engine only reads capture files. It never sends traffic.

## Quick start

```bash
# Python side (needs uv: https://docs.astral.sh/uv/)
uv sync
uv run python scenarios/build_scenarios.py     # writes scenarios/captures/*.pcap
uv run python scenarios/export_timelines.py    # writes visualizer/public/data/*.json and prints scores
uv run pytest -q

# Visualizer (needs Node 20+)
cd visualizer
npm install
npm test
npm run dev                                    # open the printed http://localhost:5173 link
```

## Analyze your own capture

```bash
uv run invisible-middleman analyze my_capture.pcap -o my_timeline.json --trusted-mac aa:bb:cc:dd:ee:ff
```

`--trusted-mac` is your real router's MAC. Without it, the engine trusts the first device that
sends a Router Advertisement or a DHCP server reply (trust on first use). Copy the JSON into
`visualizer/public/data/` to step through it.

Score a capture against a labels file (`{"attack_frames": [12, 13]}`):

```bash
uv run invisible-middleman score my_timeline.json my_labels.json
```

## Scenarios

| ID | Scenario | What it teaches |
|----|----------|-----------------|
| S1 | Healthy dual-stack network (2 hours) | How ARP, ND, RA and DHCP normally work; why renewals, new devices and temporary IPv6 addresses are not attacks |
| S2 | IPv4 ARP cache poisoning | The RFC 826 merge rule; poisoning both directions; why static ARP only protects one side |
| S3 | Rogue IPv6 Router Advertisement | Router Preference (RFC 4191) and RDNSS (RFC 8106); RA-Guard |
| S4 | Rogue DHCPv6 server on an "IPv4-only" network | The mitm6 technique; DHCPv6 option 23; DHCPv6 Guard |
| S5 | IPv4 defended, IPv6 open | The dual-stack gap; a spoofed Neighbor Advertisement that none of the four toggles stop |
| C1 | Challenge (unlabeled) | Investigate a rogue DHCPv4 server with names and alerts hidden |

The scenario captures are **synthetic**: `scenarios/build_scenarios.py` builds each frame with
Scapy and writes it with `wrpcap()`, so every capture has exact ground-truth labels. Lab-recorded
versions of S2 and S3 are planned for the evaluation phase.

## Detection rules

| Rule | Protocol | Fires when | ATT&CK |
|------|----------|------------|--------|
| ARP-01 | ARP | An ARP claim contradicts a trusted IPv4 binding (DHCP lease, router, or first sighting) | T1557.002 |
| ARP-02 | ARP | One non-router MAC claims more than one IPv4 address | T1557.002 |
| ND-01 | NDP | An NA or NS claims a known IPv6 address for a different MAC | T1557 |
| RA-01 | RA | A Router Advertisement comes from a device that is not the trusted router | T1557 |
| RA-02 | RA | An untrusted RA carries an RDNSS (DNS server) option | T1557 |
| DHCP-01 | DHCP | A DHCPv4 OFFER/ACK/NAK comes from an untrusted device | T1557.003 |
| DHCP-02 | DHCP | A lease hands out a gateway or DNS server different from the baseline | T1557.003 |
| D6-01 | DHCPv6 | A DHCPv6 ADVERTISE/REPLY comes from an untrusted device | T1557.003 |
| D6-02 | DHCPv6 | A DHCPv6 server answers on a network with no legitimate IPv6 router | T1557.003 |
| XP-01 | Cross-protocol | A host's gateway, router or DNS server now resolves to a non-router MAC | T1557 |

See `docs/DESIGN.md` for the architecture, the host-state model and the timeline JSON format.

## Limitations

- A passive sensor on a switch port only sees broadcast/multicast and its own traffic. Use a
  mirror (SPAN) port, a hub, or a virtual network where all frames are visible.
- Trust on first use: if the attacker answers before the real router is ever seen, the engine
  will trust the attacker. Pass `--trusted-mac` on real networks.
- The defense toggles model the documented behavior of each feature, not a specific vendor.

## License

MIT
