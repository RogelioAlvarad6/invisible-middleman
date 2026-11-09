"""Detection rule catalog: what each rule means and where it comes from.

The checks themselves live in engine.py. This file holds the metadata the
visualizer shows next to every alert, so the explanation a learner reads and
the rule the engine runs can never drift apart.

Design sources:
  * Cross-checking ARP claims against DHCP leases follows ARProof [10];
    this project extends the same idea to IPv6 ND, RAs and DHCPv6.
  * Trade-offs between detection schemes follow Abad and Bonilla [11].
  * IPv6 threats are the ones listed in RFC 3756 [4] sections 4.1-4.2.
  * ATT&CK mappings: T1557.002 ARP cache poisoning [7], T1557.003 DHCP
    spoofing [8], and the parent technique T1557 for IPv6 ND/RA attacks,
    which ATT&CK does not split into its own sub-technique.
"""

RULES: dict[str, dict] = {
    "ARP-01": {
        "title": "ARP claim contradicts a trusted IPv4 binding",
        "protocol": "ARP",
        "mitre": "T1557.002",
        "explain": (
            "Frame {i} says {ip} is at {claimed}, but the sensor already knows {ip} "
            "belongs to {expected} (learned from {source}). ARP has no authentication, "
            "and RFC 826 tells every host that already has {ip} cached to overwrite it "
            "with the sender's MAC. That is how one forged reply redirects traffic."
        ),
        "field": "ARP sender hardware address (hwsrc)",
    },
    "ARP-02": {
        "title": "One MAC address claims several IPv4 addresses",
        "protocol": "ARP",
        "mitre": "T1557.002",
        "explain": (
            "{claimed} has now claimed {count} different IPv4 addresses ({ips}). "
            "A normal client owns one address on a LAN. An attacker sitting in the "
            "middle claims the gateway and the victim at the same time."
        ),
        "field": "ARP sender protocol address (psrc)",
    },
    "ND-01": {
        "title": "Neighbor Advertisement contradicts a trusted IPv6 binding",
        "protocol": "NDP",
        "mitre": "T1557",
        "explain": (
            "Frame {i} says {ip} is at {claimed}, but the sensor learned {ip} belongs to "
            "{expected} (from {source}). The Override flag is {override}. RFC 4861 tells "
            "a host to replace its cached link-layer address when O=1, which is the IPv6 "
            "version of ARP poisoning (RFC 3756, section 4.1.1)."
        ),
        "field": "NA Target Link-Layer Address option",
    },
    "RA-01": {
        "title": "Router Advertisement from an untrusted device",
        "protocol": "RA",
        "mitre": "T1557",
        "explain": (
            "{claimed} is announcing itself as an IPv6 router (lifetime {lifetime}s, "
            "preference {pref}). Only {expected} is the real router. Any host can send an "
            "RA and every host that hears it adds the sender to its default-router list "
            "(RFC 3756, section 4.2.1). With a higher preference it wins outright."
        ),
        "field": "Ethernet source / RA Source Link-Layer Address option",
    },
    "RA-02": {
        "title": "Router Advertisement hands out an untrusted DNS server",
        "protocol": "RA",
        "mitre": "T1557",
        "explain": (
            "The RA in frame {i} carries an RDNSS option naming {dns} as the DNS server. "
            "Hosts that accept RDNSS (RFC 8106) will send name lookups there, so the "
            "attacker can answer with any address it likes."
        ),
        "field": "RA RDNSS option",
    },
    "DHCP-01": {
        "title": "DHCPv4 server reply from an untrusted device",
        "protocol": "DHCP",
        "mitre": "T1557.003",
        "explain": (
            "{claimed} sent a DHCP {msg}. Only {expected} is the trusted DHCP server. "
            "Clients take the first offer they get, so a rogue server can set the victim's "
            "gateway and DNS server."
        ),
        "field": "Ethernet source / DHCP option 54 (server identifier)",
    },
    "DHCP-02": {
        "title": "DHCPv4 lease points at an unexpected gateway or DNS server",
        "protocol": "DHCP",
        "mitre": "T1557.003",
        "explain": (
            "This lease tells {client} to use gateway {router} and DNS {dns}. "
            "Earlier leases on this network used gateway {base_router} and DNS {base_dns}."
        ),
        "field": "DHCP options 3 (router) and 6 (DNS)",
    },
    "D6-01": {
        "title": "DHCPv6 server reply from an untrusted device",
        "protocol": "DHCPv6",
        "mitre": "T1557.003",
        "explain": (
            "{claimed} sent a DHCPv6 {msg} naming {dns} as the DNS server. Only {expected} "
            "is trusted to answer. DHCPv6 replies are not authenticated, so whoever answers "
            "a Solicit first can set the client's IPv6 DNS server."
        ),
        "field": "DHCPv6 option 23 (DNS recursive name server)",
    },
    "D6-02": {
        "title": "DHCPv6 server on a network with no IPv6 router",
        "protocol": "DHCPv6",
        "mitre": "T1557.003",
        "explain": (
            "No legitimate Router Advertisement has been seen, so this network looks "
            "IPv4-only, yet a DHCPv6 server just answered. Windows asks for DHCPv6 by "
            "default and prefers IPv6 DNS, which is exactly the gap mitm6 abuses [6]."
        ),
        "field": "DHCPv6 message type (advertise/reply)",
    },
    "XP-01": {
        "title": "A host now trusts the attacker",
        "protocol": "Cross-protocol",
        "mitre": "T1557",
        "explain": (
            "After frame {i}, {host}'s {what} resolves to {actual} instead of the real "
            "router, {expected}. Its traffic for that role now goes through another machine."
        ),
        "field": "Host trust card",
    },
}

# Which defense would stop the frame before any host saw it.
# Keys match the defense toggles in the visualizer.
DEFENSES = {
    "static_arp": "Static ARP entry for the gateway on each client",
    "dai": "DHCP snooping + Dynamic ARP Inspection",
    "ra_guard": "RA-Guard (RFC 6105)",
    "dhcpv6_guard": "DHCPv6 Guard",
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
