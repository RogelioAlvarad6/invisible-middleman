"""Turn a packet capture into a list of normalized link-layer trust events.

Every frame in the capture becomes one event, numbered from 1 the same way
Wireshark numbers frames, so a learner can open the same .pcap in Wireshark
and find "frame 37" in both tools.

Only the fields the detection rules and the host-state model need are kept.
Protocol references:
  ARP         RFC 826  [2]
  IPv6 ND/RA  RFC 4861 [3], RDNSS option RFC 8106
  DHCPv4      RFC 2131 / RFC 2132 (options 3 = router, 6 = DNS)
  DHCPv6      RFC 8415 (option 23 = DNS recursive name server)
Field access follows the Scapy layer documentation [9].
"""

from __future__ import annotations

from scapy.all import rdpcap
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dhcp6 import (
    DHCP6OptDNSServers,
    DHCP6OptIAAddress,
)
from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.inet6 import (
    IPv6,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6ND_RA,
    ICMPv6NDOptDstLLAddr,
    ICMPv6NDOptRDNSS,
    ICMPv6NDOptSrcLLAddr,
)
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP, Ether

BROADCAST = "ff:ff:ff:ff:ff:ff"

DHCP4_TYPES = {1: "discover", 2: "offer", 3: "request", 4: "decline",
               5: "ack", 6: "nak", 7: "release", 8: "inform"}
DHCP6_TYPES = {1: "solicit", 2: "advertise", 3: "request", 4: "confirm",
               5: "renew", 6: "rebind", 7: "reply", 8: "release",
               9: "decline", 10: "reconfigure", 11: "information-request"}
# Messages that only a DHCP server sends. A client never sends these.
DHCP4_SERVER_MSGS = {"offer", "ack", "nak"}
DHCP6_SERVER_MSGS = {"advertise", "reply", "reconfigure"}

RA_PREF = {0: 0, 1: 1, 3: -1, 2: 0}  # RFC 4191: 01 high, 00 medium, 11 low, 10 reserved


def is_group(mac: str) -> bool:
    """True for broadcast and multicast MAC addresses (I/G bit set)."""
    return int(mac.split(":")[0], 16) & 1 == 1


def _dhcp_opt(dhcp: DHCP, name: str):
    for opt in dhcp.options:
        if isinstance(opt, tuple) and opt[0] == name:
            return opt[1] if len(opt) == 2 else list(opt[1:])
    return None


def _as_list(value) -> list[str]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _dhcp6_message(pkt):
    """Scapy decodes each DHCPv6 message type as its own class (DHCP6_Solicit,
    DHCP6_Reply, ...), so look for the UDP payload on ports 546/547 instead."""
    if UDP in pkt and IPv6 in pkt and {pkt[UDP].sport, pkt[UDP].dport} & {546, 547}:
        msg = pkt[UDP].payload
        if hasattr(msg, "msgtype"):
            return msg
    return None


def normalize(pkt, index: int) -> dict:
    """Return one event dict for a single frame."""
    ev: dict = {
        "i": index,
        "t": float(pkt.time),
        "src_mac": pkt[Ether].src.lower() if Ether in pkt else None,
        "dst_mac": pkt[Ether].dst.lower() if Ether in pkt else None,
        "kind": "other",
        "proto": "Other",
        "summary": pkt.summary(),
    }

    if ARP in pkt:
        a = pkt[ARP]
        ev.update(kind="arp", proto="ARP", op="request" if a.op == 1 else "reply",
                  hwsrc=a.hwsrc.lower(), psrc=a.psrc, hwdst=a.hwdst.lower(), pdst=a.pdst)
        if a.op == 1:
            ev["summary"] = f"Who has {a.pdst}? Tell {a.psrc}"
        else:
            ev["summary"] = f"{a.psrc} is at {a.hwsrc}"
        return ev

    if ICMPv6ND_RA in pkt:
        ra = pkt[ICMPv6ND_RA]
        sll = pkt[ICMPv6NDOptSrcLLAddr].lladdr.lower() if ICMPv6NDOptSrcLLAddr in pkt else None
        rdnss = list(pkt[ICMPv6NDOptRDNSS].dns) if ICMPv6NDOptRDNSS in pkt else []
        ev.update(kind="ra", proto="ICMPv6 RA", src_ip=pkt[IPv6].src,
                  lifetime=int(ra.routerlifetime), prf=RA_PREF.get(int(ra.prf), 0),
                  sllao=sll, rdnss=rdnss, managed=bool(ra.M), other=bool(ra.O))
        pref = {1: "high", 0: "medium", -1: "low"}[ev["prf"]]
        ev["summary"] = (f"Router Advertisement from {ev['src_ip']} "
                         f"(lifetime {ev['lifetime']}s, preference {pref}"
                         + (f", DNS {', '.join(rdnss)}" if rdnss else "") + ")")
        return ev

    if ICMPv6ND_NS in pkt:
        ns = pkt[ICMPv6ND_NS]
        sll = pkt[ICMPv6NDOptSrcLLAddr].lladdr.lower() if ICMPv6NDOptSrcLLAddr in pkt else None
        ev.update(kind="ns", proto="ICMPv6 NS", src_ip=pkt[IPv6].src, target=ns.tgt, sllao=sll)
        if ev["src_ip"] == "::":
            ev["summary"] = f"Duplicate Address Detection for {ns.tgt}"
        else:
            ev["summary"] = f"Who has {ns.tgt}? (from {ev['src_ip']})"
        return ev

    if ICMPv6ND_NA in pkt:
        na = pkt[ICMPv6ND_NA]
        tll = pkt[ICMPv6NDOptDstLLAddr].lladdr.lower() if ICMPv6NDOptDstLLAddr in pkt else ev["src_mac"]
        ev.update(kind="na", proto="ICMPv6 NA", src_ip=pkt[IPv6].src, dst_ip=pkt[IPv6].dst,
                  target=na.tgt, tlla=tll, R=bool(na.R), S=bool(na.S), O=bool(na.O))
        flags = "".join(f for f, on in (("R", na.R), ("S", na.S), ("O", na.O)) if on) or "none"
        ev["summary"] = f"{na.tgt} is at {tll} (flags {flags})"
        return ev

    if DHCP in pkt and BOOTP in pkt:
        b, d = pkt[BOOTP], pkt[DHCP]
        msg = DHCP4_TYPES.get(_dhcp_opt(d, "message-type"), "unknown")
        chaddr = ":".join(f"{x:02x}" for x in bytes(b.chaddr)[:6])
        ev.update(kind="dhcp", proto="DHCP", msg=msg, chaddr=chaddr, yiaddr=b.yiaddr,
                  src_ip=pkt[IP].src if IP in pkt else None,
                  server_id=_dhcp_opt(d, "server_id"),
                  router=_as_list(_dhcp_opt(d, "router")),
                  dns=_as_list(_dhcp_opt(d, "name_server")),
                  is_server_msg=msg in DHCP4_SERVER_MSGS)
        ev["summary"] = f"DHCP {msg.upper()}" + (
            f" {b.yiaddr} to {chaddr}, router {', '.join(ev['router']) or '-'}, DNS {', '.join(ev['dns']) or '-'}"
            if ev["is_server_msg"] else f" from {chaddr}")
        return ev

    d = _dhcp6_message(pkt)
    if d is not None:
        msg = DHCP6_TYPES.get(int(d.msgtype), "unknown")
        dns = list(pkt[DHCP6OptDNSServers].dnsservers) if DHCP6OptDNSServers in pkt else []
        addrs = []
        layer = pkt.getlayer(DHCP6OptIAAddress)
        n = 1
        while layer is not None:
            addrs.append(layer.addr)
            n += 1
            layer = pkt.getlayer(DHCP6OptIAAddress, n)
        ev.update(kind="dhcp6", proto="DHCPv6", msg=msg, src_ip=pkt[IPv6].src,
                  dst_ip=pkt[IPv6].dst, dns=dns, addrs=addrs,
                  is_server_msg=msg in DHCP6_SERVER_MSGS)
        ev["summary"] = f"DHCPv6 {msg.upper()}" + (
            f" from {ev['src_ip']}, DNS {', '.join(dns) or '-'}" if ev["is_server_msg"] else f" from {ev['src_ip']}")
        return ev

    # Ordinary traffic: used to show where a host's packets actually go.
    if IP in pkt or IPv6 in pkt:
        ip = pkt[IP] if IP in pkt else pkt[IPv6]
        app = "DNS query" if DNS in pkt and pkt[DNS].qr == 0 else (
              "DNS reply" if DNS in pkt else (
              "ICMP" if ICMP in pkt else ("UDP" if UDP in pkt else "IP")))
        ev.update(kind="data", proto="IPv4" if IP in pkt else "IPv6",
                  src_ip=ip.src, dst_ip=ip.dst, app=app)
        if DNS in pkt and pkt[DNS].qr == 0 and pkt[DNS].qd:
            ev["qname"] = pkt[DNS].qd[0].qname.decode(errors="replace").rstrip(".")
        ev["summary"] = f"{app} {ip.src} -> {ip.dst}" + (f" ({ev['qname']})" if "qname" in ev else "")
    return ev


def read_capture(path: str) -> list[dict]:
    """Read a .pcap/.pcapng file and return normalized events, frame 1 first."""
    return [normalize(pkt, i) for i, pkt in enumerate(rdpcap(path), start=1)]
