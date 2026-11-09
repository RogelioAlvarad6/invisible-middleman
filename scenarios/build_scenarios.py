"""Build the five guided scenarios (S1-S5) and the challenge capture (C1).

This script never sends a packet. It builds each Ethernet frame in memory with
Scapy [9] and writes the frames to a .pcap file with wrpcap(). Because the
script decides which frames are the attack, every capture comes with a
ground-truth labels file that the tests and the `score` command use.

Run:  uv run python scenarios/build_scenarios.py

Output (in scenarios/captures/):
  S1_benign.pcap ... C1_challenge.pcap   the captures (open them in Wireshark)
  S1_benign.labels.json ...              which frames are attack frames
  hosts.json                             MAC -> name/role for the lab
"""

from __future__ import annotations

import json
from pathlib import Path

from scapy.all import wrpcap
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dhcp6 import (
    DHCP6_Advertise,
    DHCP6_InfoRequest,
    DHCP6_Reply,
    DHCP6_Request,
    DHCP6_Solicit,
    DHCP6OptClientId,
    DHCP6OptDNSServers,
    DHCP6OptIA_NA,
    DHCP6OptIAAddress,
    DHCP6OptServerId,
    DUID_LL,
)
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.inet6 import (
    ICMPv6EchoRequest,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6ND_RA,
    ICMPv6NDOptDstLLAddr,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptRDNSS,
    ICMPv6NDOptSrcLLAddr,
    IPv6,
)
from scapy.layers.l2 import ARP, Ether
from scapy.utils import mac2str

OUT = Path(__file__).parent / "captures"
BCAST = "ff:ff:ff:ff:ff:ff"
PREFIX = "2001:db8:56::"          # documentation prefix (RFC 3849), never routable


def link_local(mac: str) -> str:
    """Modified EUI-64 link-local address, the way the lab VMs derive it."""
    b = [int(x, 16) for x in mac.split(":")]
    b[0] ^= 0x02
    eui = b[:3] + [0xFF, 0xFE] + b[3:]
    groups = [f"{(eui[i] << 8) | eui[i + 1]:x}" for i in range(0, 8, 2)]
    return "fe80::" + ":".join(groups)


def mcast_mac(ip6: str) -> str:
    """33:33 + last 32 bits of the IPv6 multicast address (RFC 2464)."""
    from ipaddress import IPv6Address
    tail = IPv6Address(ip6).packed[-4:]
    return "33:33:" + ":".join(f"{x:02x}" for x in tail)


def solicited_node(ip6: str) -> str:
    from ipaddress import IPv6Address
    tail = IPv6Address(ip6).packed[-3:]
    return f"ff02::1:ff{tail[0]:02x}:{tail[1]:02x}{tail[2]:02x}"


# --------------------------------------------------------------------- lab hosts
class H:
    def __init__(self, name, role, mac, ip4):
        self.name, self.role, self.mac, self.ip4 = name, role, mac, ip4
        self.ll = link_local(mac)


ROUTER = H("router", "router", "08:00:27:00:00:01", "192.168.56.1")
LINUX = H("ubuntu-client", "client", "08:00:27:00:00:10", "192.168.56.10")
WIN = H("win11-client", "client", "08:00:27:00:00:20", "192.168.56.20")
KALI = H("kali", "client", "08:00:27:00:00:66", "192.168.56.66")
PHONE = H("phone", "client", "08:00:27:00:00:30", "192.168.56.30")
ALL = [ROUTER, LINUX, WIN, KALI, PHONE]


class Capture:
    """Collects frames with timestamps and remembers which ones are attacks."""

    def __init__(self, start=1793750400.0):   # 2026-11-03 00:00 UTC, fixed so builds are identical
        self.frames, self.attack, self.t0, self.t = [], [], start, 0.0

    def add(self, pkt, at=None, attack=False, gap=0.05):
        self.t = at if at is not None else self.t + gap
        pkt.time = self.t0 + self.t
        self.frames.append(pkt)
        if attack:
            self.attack.append(len(self.frames))     # 1-based, like Wireshark
        return len(self.frames)

    # ---- ARP -----------------------------------------------------------------
    def arp_req(self, who: H, target_ip: str, **kw):
        return self.add(Ether(src=who.mac, dst=BCAST) /
                        ARP(op=1, hwsrc=who.mac, psrc=who.ip4, hwdst="00:00:00:00:00:00", pdst=target_ip), **kw)

    def arp_rep(self, frm_mac, claim_ip, to: H, **kw):
        return self.add(Ether(src=frm_mac, dst=to.mac) /
                        ARP(op=2, hwsrc=frm_mac, psrc=claim_ip, hwdst=to.mac, pdst=to.ip4), **kw)

    def resolve(self, who: H, target: H, **kw):
        self.arp_req(who, target.ip4, **kw)
        self.arp_rep(target.mac, target.ip4, who, gap=0.002)

    def gratuitous(self, who: H, **kw):
        return self.add(Ether(src=who.mac, dst=BCAST) /
                        ARP(op=1, hwsrc=who.mac, psrc=who.ip4, hwdst="00:00:00:00:00:00", pdst=who.ip4), **kw)

    # ---- DHCPv4 --------------------------------------------------------------
    def _bootp(self, op, client: H, yiaddr="0.0.0.0", xid=0x1000):
        return BOOTP(op=op, chaddr=mac2str(client.mac) + b"\x00" * 10, yiaddr=yiaddr, xid=xid, flags=0x8000)

    def dora(self, client: H, server: H = ROUTER, gw=None, dns=None, offer_first: H | None = None, attack_server=False, **kw):
        gw, dns = gw or ROUTER.ip4, dns or ROUTER.ip4
        xid = int(client.mac[-2:], 16) + 0x2000
        self.add(Ether(src=client.mac, dst=BCAST) / IP(src="0.0.0.0", dst="255.255.255.255") /
                 UDP(sport=68, dport=67) / self._bootp(1, client, xid=xid) /
                 DHCP(options=[("message-type", "discover"), "end"]), **kw)
        if offer_first is not None:      # a second server races the first one
            self._server_msg("offer", offer_first, client, xid, ROUTER.ip4, ROUTER.ip4, attack=False, gap=0.004)
        self._server_msg("offer", server, client, xid, gw, dns, attack=attack_server, gap=0.003)
        self.add(Ether(src=client.mac, dst=BCAST) / IP(src="0.0.0.0", dst="255.255.255.255") /
                 UDP(sport=68, dport=67) / self._bootp(1, client, xid=xid) /
                 DHCP(options=[("message-type", "request"), ("requested_addr", client.ip4),
                               ("server_id", server.ip4), "end"]), gap=0.01)
        self._server_msg("ack", server, client, xid, gw, dns, attack=attack_server, gap=0.003)

    def _server_msg(self, msg, server: H, client: H, xid, gw, dns, attack=False, gap=0.003):
        return self.add(Ether(src=server.mac, dst=BCAST) / IP(src=server.ip4, dst="255.255.255.255") /
                        UDP(sport=67, dport=68) / self._bootp(2, client, client.ip4, xid) /
                        DHCP(options=[("message-type", msg), ("server_id", server.ip4),
                                      ("lease_time", 7200), ("subnet_mask", "255.255.255.0"),
                                      ("router", gw), ("name_server", dns), "end"]),
                        gap=gap, attack=attack)

    def renew(self, client: H, **kw):
        xid = int(client.mac[-2:], 16) + 0x3000
        self.add(Ether(src=client.mac, dst=ROUTER.mac) / IP(src=client.ip4, dst=ROUTER.ip4) /
                 UDP(sport=68, dport=67) / self._bootp(1, client, xid=xid) /
                 DHCP(options=[("message-type", "request"), "end"]), **kw)
        self.add(Ether(src=ROUTER.mac, dst=client.mac) / IP(src=ROUTER.ip4, dst=client.ip4) /
                 UDP(sport=67, dport=68) / self._bootp(2, client, client.ip4, xid) /
                 DHCP(options=[("message-type", "ack"), ("server_id", ROUTER.ip4), ("lease_time", 7200),
                               ("router", ROUTER.ip4), ("name_server", ROUTER.ip4), "end"]), gap=0.003)

    # ---- IPv6 ND -------------------------------------------------------------
    def dad(self, who: H, addr: str, **kw):
        return self.add(Ether(src=who.mac, dst=mcast_mac(solicited_node(addr))) /
                        IPv6(src="::", dst=solicited_node(addr), hlim=255) / ICMPv6ND_NS(tgt=addr), **kw)

    def ra(self, frm: H, prf=0, lifetime=1800, rdnss=None, attack=False, **kw):
        prf_bits = {1: 1, 0: 0, -1: 3}[prf]
        pkt = (Ether(src=frm.mac, dst="33:33:00:00:00:01") / IPv6(src=frm.ll, dst="ff02::1", hlim=255) /
               ICMPv6ND_RA(prf=prf_bits, routerlifetime=lifetime) /
               ICMPv6NDOptSrcLLAddr(lladdr=frm.mac) /
               ICMPv6NDOptPrefixInfo(prefix=PREFIX, prefixlen=64, L=1, A=1))
        if rdnss:
            pkt = pkt / ICMPv6NDOptRDNSS(dns=rdnss, lifetime=lifetime)
        return self.add(pkt, attack=attack, **kw)

    def ns(self, who: H, target_ip: str, **kw):
        sn = solicited_node(target_ip)
        return self.add(Ether(src=who.mac, dst=mcast_mac(sn)) / IPv6(src=who.ll, dst=sn, hlim=255) /
                        ICMPv6ND_NS(tgt=target_ip) / ICMPv6NDOptSrcLLAddr(lladdr=who.mac), **kw)

    def na(self, frm_mac: str, src_ip: str, target_ip: str, to_mac: str, to_ip: str, S=1, O=1, R=0, attack=False, **kw):
        return self.add(Ether(src=frm_mac, dst=to_mac) / IPv6(src=src_ip, dst=to_ip, hlim=255) /
                        ICMPv6ND_NA(tgt=target_ip, R=R, S=S, O=O) / ICMPv6NDOptDstLLAddr(lladdr=frm_mac),
                        attack=attack, **kw)

    # ---- DHCPv6 --------------------------------------------------------------
    def dhcp6_info(self, client: H, **kw):
        self.add(Ether(src=client.mac, dst="33:33:00:01:00:02") / IPv6(src=client.ll, dst="ff02::1:2") /
                 UDP(sport=546, dport=547) / DHCP6_InfoRequest(trid=0x51) /
                 DHCP6OptClientId(duid=DUID_LL(lladdr=client.mac)), **kw)
        self.add(Ether(src=ROUTER.mac, dst=client.mac) / IPv6(src=ROUTER.ll, dst=client.ll) /
                 UDP(sport=547, dport=546) / DHCP6_Reply(trid=0x51) /
                 DHCP6OptServerId(duid=DUID_LL(lladdr=ROUTER.mac)) /
                 DHCP6OptClientId(duid=DUID_LL(lladdr=client.mac)) /
                 DHCP6OptDNSServers(dnsservers=[ROUTER.ll]), gap=0.004)

    def rogue_dhcp6(self, client: H, server: H, addr: str, trid=0x77, **kw):
        """Solicit -> Advertise -> Request -> Reply, the four-message exchange in RFC 8415."""
        cid = DHCP6OptClientId(duid=DUID_LL(lladdr=client.mac))
        sid = DHCP6OptServerId(duid=DUID_LL(lladdr=server.mac))
        ia = DHCP6OptIA_NA(iaid=1, ianaopts=[DHCP6OptIAAddress(addr=addr, preflft=240, validlft=300)])
        dns = DHCP6OptDNSServers(dnsservers=[server.ll])
        self.add(Ether(src=client.mac, dst="33:33:00:01:00:02") / IPv6(src=client.ll, dst="ff02::1:2") /
                 UDP(sport=546, dport=547) / DHCP6_Solicit(trid=trid) / cid / DHCP6OptIA_NA(iaid=1), **kw)
        self.add(Ether(src=server.mac, dst=client.mac) / IPv6(src=server.ll, dst=client.ll) /
                 UDP(sport=547, dport=546) / DHCP6_Advertise(trid=trid) / sid / cid / ia / dns,
                 gap=0.006, attack=True)
        self.add(Ether(src=client.mac, dst="33:33:00:01:00:02") / IPv6(src=client.ll, dst="ff02::1:2") /
                 UDP(sport=546, dport=547) / DHCP6_Request(trid=trid + 1) / cid / sid / ia, gap=0.01)
        self.add(Ether(src=server.mac, dst=client.mac) / IPv6(src=server.ll, dst=client.ll) /
                 UDP(sport=547, dport=546) / DHCP6_Reply(trid=trid + 1) / sid / cid / ia / dns,
                 gap=0.006, attack=True)

    # ---- ordinary traffic ----------------------------------------------------
    def dns4(self, client: H, via_mac: str, server_ip: str, name="example.com", **kw):
        return self.add(Ether(src=client.mac, dst=via_mac) / IP(src=client.ip4, dst=server_ip) /
                        UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname=name)), **kw)

    def dns6(self, client: H, via_mac: str, server_ip: str, name="example.com", src=None, **kw):
        return self.add(Ether(src=client.mac, dst=via_mac) / IPv6(src=src or client.ll, dst=server_ip) /
                        UDP(sport=53001, dport=53) / DNS(rd=1, qd=DNSQR(qname=name, qtype="AAAA")), **kw)

    def ping4(self, client: H, via_mac: str, dst="1.1.1.1", **kw):
        return self.add(Ether(src=client.mac, dst=via_mac) / IP(src=client.ip4, dst=dst) / ICMP(), **kw)

    def ping6(self, client: H, via_mac: str, dst="2606:4700:4700::1111", **kw):
        return self.add(Ether(src=client.mac, dst=via_mac) / IPv6(src=PREFIX + client.mac[-2:], dst=dst) /
                        ICMPv6EchoRequest(), **kw)

    def save(self, sid: str, meta: dict):
        OUT.mkdir(exist_ok=True)
        wrpcap(str(OUT / f"{sid}.pcap"), self.frames)
        labels = dict(meta, attack_frames=self.attack, frames=len(self.frames),
                      duration_s=round(self.t, 1))
        (OUT / f"{sid}.labels.json").write_text(json.dumps(labels, indent=2), encoding="utf-8")
        print(f"{sid}: {len(self.frames)} frames, {len(self.attack)} labeled attack frames, {self.t / 60:.1f} min")


# --------------------------------------------------------------------- baseline
def boot(c: Capture, hosts=(LINUX, WIN, KALI), ipv6_router=True):
    """Normal network start-up: DHCP leases, gateway ARP, IPv6 address setup."""
    c.gratuitous(ROUTER, at=0.0)
    for h in hosts:
        c.dora(h, gap=1.0)
        c.resolve(h, ROUTER, gap=0.05)
        c.dad(h, h.ll, gap=0.1)
    if not ipv6_router:
        return
    c.ra(ROUTER, prf=0, rdnss=[ROUTER.ll], gap=0.5)     # answer to the hosts' Router Solicitations
    for h in hosts:
        c.dad(h, PREFIX + h.mac[-2:], gap=0.05)         # SLAAC global address from the RA prefix
    for h in hosts:   # hosts learn the router from the RA; it answers their NS too
        c.ns(h, ROUTER.ll, gap=0.3)
        c.na(ROUTER.mac, ROUTER.ll, ROUTER.ll, h.mac, h.ll, R=1, S=1, O=1, gap=0.002)


def normal_traffic(c: Capture, gap=2.0, ipv6=True):
    c.dns4(LINUX, ROUTER.mac, ROUTER.ip4, "iastate.edu", gap=gap)
    c.ping4(LINUX, ROUTER.mac, gap=0.2)
    if ipv6:
        c.dns6(WIN, ROUTER.mac, ROUTER.ll, "canvas.iastate.edu", gap=0.5)
        c.ping6(WIN, ROUTER.mac, gap=0.2)
    else:
        c.dns4(WIN, ROUTER.mac, ROUTER.ip4, "canvas.iastate.edu", gap=0.5)


# --------------------------------------------------------------------- scenarios
def s1_benign():
    """Two hours of a healthy dual-stack LAN, with the events that fool naive detectors:
    periodic RAs, DHCP renewals, ARP cache refreshes, a new device joining with a
    gratuitous ARP, a router re-announcing itself, and a rotating IPv6 temporary address."""
    c = Capture()
    boot(c)
    t = c.t
    while t < 2 * 3600:
        t += 200
        c.ra(ROUTER, prf=0, rdnss=[ROUTER.ll], at=t)                      # RFC 4861 periodic RA
        normal_traffic(c)
        if int(t) % 600 < 200:                                             # caches expire, re-resolve
            c.resolve(LINUX, ROUTER, gap=1.0)
            c.resolve(ROUTER, WIN, gap=0.5)
            c.ns(WIN, ROUTER.ll, gap=0.4)
            c.na(ROUTER.mac, ROUTER.ll, ROUTER.ll, WIN.mac, WIN.ll, R=1, S=1, O=1, gap=0.002)
        if 3600 <= t < 3800:                                               # lease renewal at T1 = lease/2
            for h in (LINUX, WIN, KALI):
                c.renew(h, gap=0.7)
            c.dad(LINUX, PREFIX + "a1b2:c3d4:e5f6:1", gap=1.0)            # new temporary address (RFC 8981)
            c.dhcp6_info(WIN, gap=0.5)
        if 5400 <= t < 5600:                                               # a phone joins the network
            c.dora(PHONE, gap=2.0)
            c.gratuitous(PHONE, gap=0.1)
            c.resolve(PHONE, ROUTER, gap=0.1)
            c.dad(PHONE, PHONE.ll, gap=0.1)
            c.gratuitous(ROUTER, gap=5.0)
    c.save("S1_benign", {"id": "S1", "title": "A healthy dual-stack network", "attack_type": "none",
                         "attacker_mac": None, "affected_hosts": []})


def s2_arp():
    """IPv4 ARP cache poisoning: Kali tells the client it is the gateway and tells the
    gateway it is the client, then forwards traffic in between."""
    c = Capture()
    boot(c)
    normal_traffic(c, gap=5)
    c.resolve(KALI, LINUX, gap=4)                        # attacker looks up the victim first
    t = c.t + 10
    for n in range(10):                                  # repeat every 2 s so caches stay poisoned
        c.arp_rep(KALI.mac, ROUTER.ip4, LINUX, at=t + 2 * n, attack=True)
        c.arp_rep(KALI.mac, LINUX.ip4, ROUTER, gap=0.001, attack=True)
        if n in (2, 5, 8):                               # victim traffic now goes to Kali first
            c.ping4(LINUX, KALI.mac, gap=0.3)
            c.add(Ether(src=KALI.mac, dst=ROUTER.mac) / IP(src=LINUX.ip4, dst="1.1.1.1") / ICMP(), gap=0.001)
            c.dns4(LINUX, KALI.mac, ROUTER.ip4, "canvas.iastate.edu", gap=0.2)
    c.save("S2_arp_poisoning", {"id": "S2", "title": "IPv4 ARP cache poisoning", "attack_type": "ARP cache poisoning",
                                "attacker_mac": KALI.mac, "affected_hosts": [LINUX.mac, ROUTER.mac]})


def s3_rogue_ra():
    """Rogue IPv6 router: Kali sends Router Advertisements with high preference and an
    RDNSS option, so every client switches its IPv6 default router and DNS to Kali."""
    c = Capture()
    boot(c)
    normal_traffic(c, gap=5)
    t = c.t + 10
    for n in range(5):
        c.ra(KALI, prf=1, lifetime=1800, rdnss=[KALI.ll], at=t + 10 * n, attack=True)
        if n == 0:
            c.dns6(WIN, KALI.mac, KALI.ll, "outlook.office.com", gap=1.0)
            c.ping6(WIN, KALI.mac, gap=0.3)
            c.ping6(LINUX, KALI.mac, gap=0.3)
        if n == 2:
            c.ra(ROUTER, prf=0, rdnss=[ROUTER.ll], gap=1.0)            # the real router is still there
            c.ping6(LINUX, KALI.mac, gap=0.5)
    c.save("S3_rogue_ra", {"id": "S3", "title": "A rogue IPv6 router", "attack_type": "Rogue Router Advertisement",
                           "attacker_mac": KALI.mac, "affected_hosts": [LINUX.mac, WIN.mac]})


def s4_rogue_dhcpv6():
    """'IPv4-only' network (no IPv6 router) where Windows still asks for DHCPv6.
    Kali answers and makes itself the IPv6 DNS server (the mitm6 technique [6])."""
    c = Capture()
    boot(c, ipv6_router=False)
    normal_traffic(c, gap=5, ipv6=False)
    c.rogue_dhcp6(WIN, KALI, PREFIX + "6:20", gap=6.0)
    c.ns(WIN, KALI.ll, gap=0.4)                                         # resolve the new "DNS server"
    c.na(KALI.mac, KALI.ll, KALI.ll, WIN.mac, WIN.ll, S=1, O=1, gap=0.002)
    c.dns6(WIN, KALI.mac, KALI.ll, "wpad.corp.local", gap=0.4)
    c.dns6(WIN, KALI.mac, KALI.ll, "fileserver.corp.local", gap=2.0)
    c.rogue_dhcp6(WIN, KALI, PREFIX + "6:20", trid=0x91, gap=60.0)    # mitm6 hands out short leases
    c.dns6(WIN, KALI.mac, KALI.ll, "intranet.corp.local", gap=1.0)
    c.save("S4_rogue_dhcpv6", {"id": "S4", "title": "A rogue DHCPv6 server on an 'IPv4-only' network",
                               "attack_type": "Rogue DHCPv6 server (DNS takeover)",
                               "attacker_mac": KALI.mac, "affected_hosts": [WIN.mac]})


def s5_dual_stack_gap():
    """IPv4 is locked down (static gateway ARP entries + DAI), IPv6 is not.
    Kali's ARP poisoning fails, so it switches to RAs, a spoofed NA, and DHCPv6."""
    c = Capture()
    boot(c)
    normal_traffic(c, gap=5)
    t = c.t + 8
    for n in range(3):                                    # IPv4 attempt: stopped by DAI / static ARP
        c.arp_rep(KALI.mac, ROUTER.ip4, LINUX, at=t + 2 * n, attack=True)
        c.arp_rep(KALI.mac, ROUTER.ip4, WIN, gap=0.001, attack=True)
    c.ping4(LINUX, ROUTER.mac, gap=1.0)
    c.na(KALI.mac, ROUTER.ll, ROUTER.ll, "33:33:00:00:00:01", "ff02::1", S=0, O=1, R=1,
         gap=5.0, attack=True)                            # "the router's address is at my MAC"
    c.ra(KALI, prf=1, lifetime=1800, rdnss=[KALI.ll], gap=2.0, attack=True)
    c.rogue_dhcp6(WIN, KALI, PREFIX + "6:20", gap=3.0)
    c.ping6(LINUX, KALI.mac, gap=1.0)
    c.dns6(WIN, KALI.mac, KALI.ll, "canvas.iastate.edu", gap=0.5)
    c.ra(KALI, prf=1, lifetime=1800, rdnss=[KALI.ll], gap=10.0, attack=True)
    c.save("S5_dual_stack_gap", {"id": "S5", "title": "IPv4 defended, IPv6 wide open",
                                 "attack_type": "ARP attempt (blocked) then rogue RA, NA spoofing and rogue DHCPv6",
                                 "attacker_mac": KALI.mac, "affected_hosts": [LINUX.mac, WIN.mac],
                                 "default_defenses": ["static_arp", "dai"]})


def c1_challenge():
    """Challenge capture (unlabeled in the visualizer): a phone joins and a rogue DHCPv4
    server wins the race, handing out itself as gateway and DNS."""
    c = Capture()
    boot(c)
    normal_traffic(c, gap=5)
    normal_traffic(c, gap=20)
    c.dora(PHONE, server=KALI, gw=KALI.ip4, dns=KALI.ip4, offer_first=None, attack_server=True, gap=15)
    c._server_msg("offer", ROUTER, PHONE, int(PHONE.mac[-2:], 16) + 0x2000, ROUTER.ip4, ROUTER.ip4, gap=0.02)
    c.arp_req(PHONE, KALI.ip4, gap=0.2)
    c.arp_rep(KALI.mac, KALI.ip4, PHONE, gap=0.002)
    c.dns4(PHONE, KALI.mac, KALI.ip4, "accounts.google.com", gap=0.5)
    c.ping4(PHONE, KALI.mac, gap=0.5)
    normal_traffic(c, gap=8)
    c.save("C1_challenge", {"id": "C1", "title": "Challenge: something is wrong on this network",
                            "attack_type": "Rogue DHCPv4 server", "attacker_mac": KALI.mac,
                            "affected_hosts": [PHONE.mac]})


def main():
    OUT.mkdir(exist_ok=True)
    (OUT / "hosts.json").write_text(json.dumps(
        {h.mac: {"name": h.name, "role": h.role, "ip4": h.ip4, "ll": h.ll} for h in ALL}, indent=2), encoding="utf-8")
    for build in (s1_benign, s2_arp, s3_rogue_ra, s4_rogue_dhcpv6, s5_dual_stack_gap, c1_challenge):
        build()


if __name__ == "__main__":
    main()
