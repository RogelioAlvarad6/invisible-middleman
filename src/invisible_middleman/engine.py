"""Replay a capture through a model of every host and the sensor's own truth.

Two separate pictures of the network are kept on purpose:

* The **sensor truth** is what a careful observer knows: which MAC really
  owns each address (from DHCP leases, the trusted router, or first sighting).
  Detection rules compare every new claim against it.
* Each **host model** is what that host *believes*: its ARP cache, neighbor
  cache, default routers and DNS servers, updated the way the RFCs tell a
  real host to update them. When a belief stops matching the truth, the
  host's trust card in the visualizer turns red.

Hosts are tracked by MAC address, not IP, so a host that picks up a new
temporary IPv6 address is still the same host (proposal risk: IPv6 complexity).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .parse import BROADCAST, is_group, read_capture
from .rules import RULES

SCHEMA = "invisible-middleman/timeline@1"


@dataclass
class Host:
    mac: str
    name: str
    role: str = "client"
    ip4: str | None = None
    ip6: set[str] = field(default_factory=set)
    arp: dict[str, str] = field(default_factory=dict)       # IPv4 -> MAC
    nd: dict[str, str] = field(default_factory=dict)        # IPv6 -> MAC
    gw4: str | None = None
    routers6: dict[str, dict] = field(default_factory=dict)  # router IPv6 -> {pref, order}
    dns4: str | None = None
    dns6: str | None = None
    pending_ns: set[str] = field(default_factory=set)
    unsafe: set[str] = field(default_factory=set)

    def default_router6(self) -> str | None:
        """RFC 4191: highest preference wins; ties go to the router learned first."""
        if not self.routers6:
            return None
        return max(self.routers6, key=lambda ip: (self.routers6[ip]["pref"], -self.routers6[ip]["order"]))

    def card(self) -> dict:
        return {"ip4": self.ip4, "ip6": sorted(self.ip6), "gw4": self.gw4,
                "gw4_mac": self.arp.get(self.gw4) if self.gw4 else None,
                "gw6": self.default_router6(),
                "gw6_mac": self.nd.get(self.default_router6() or "", None),
                "dns4": self.dns4, "dns6": self.dns6}


class Engine:
    def __init__(self, hosts_meta: dict | None = None, trusted_macs: list[str] | None = None):
        self.meta = {k.lower(): v for k, v in (hosts_meta or {}).items()}
        self.trusted: set[str] = {m.lower() for m in (trusted_macs or [])}
        self.router_mac: str | None = next(iter(self.trusted), None)
        self.hosts: dict[str, Host] = {}
        self.truth4: dict[str, tuple[str, str]] = {}   # IPv4 -> (MAC, how we learned it)
        self.truth6: dict[str, tuple[str, str]] = {}
        self.mac_ips: dict[str, set[str]] = {}
        self.base_router: list[str] | None = None
        self.base_dns: list[str] | None = None
        self.seen_trusted_ra = False
        self.arp_requests: dict[tuple[str, str], float] = {}
        self.router_order = 0
        self.alerts: list[dict] = []
        for mac, m in self.meta.items():
            if m.get("role") == "router":
                self.trusted.add(mac)
                self.router_mac = self.router_mac or mac

    # ------------------------------------------------------------------ helpers
    def host(self, mac: str) -> Host:
        if mac not in self.hosts:
            m = self.meta.get(mac, {})
            role = m.get("role", "router" if mac in self.trusted else "client")
            self.hosts[mac] = Host(mac=mac, name=m.get("name", f"host-{mac[-5:].replace(':', '')}"), role=role)
        return self.hosts[mac]

    def name(self, mac: str | None) -> str:
        if not mac:
            return "unknown"
        h = self.hosts.get(mac)
        return f"{h.name} ({mac})" if h else mac

    def is_trusted(self, mac: str) -> bool:
        return mac in self.trusted

    def adopt_router(self, mac: str, why: str):
        """Trust-on-first-use for the router when none was configured."""
        if self.router_mac is None:
            self.router_mac = mac
            self.trusted.add(mac)
            self.host(mac).role = "router"
            self.notes.append(f"Trusted router set to {mac} ({why}). Use --trusted-mac to override.")

    def alert(self, ev: dict, rule: str, severity: str, **ctx):
        r = RULES[rule]
        a = {"rule": rule, "frame": ev["i"], "t": ev["t"], "severity": severity,
             "title": r["title"], "protocol": r["protocol"], "mitre": r["mitre"],
             "field": r["field"], "explain": r["explain"].format(i=ev["i"], **ctx)}
        ev["alerts"].append(a)
        self.alerts.append(a)

    def recipients(self, ev: dict) -> list[Host]:
        src, dst = ev["src_mac"], ev["dst_mac"]
        if dst is None:
            return []
        if dst == BROADCAST or is_group(dst):
            return [h for m, h in self.hosts.items() if m != src]
        return [self.hosts[dst]] if dst in self.hosts and dst != src else []

    @staticmethod
    def effect(ev: dict, host: Host, kind: str, key, value, prev=None, **extra):
        e = {"host": host.mac, "kind": kind, "key": key, "value": value, "prev": prev}
        e.update(extra)
        ev["effects"].append(e)

    # ------------------------------------------------------------------ main loop
    def run(self, events: list[dict]) -> dict:
        self.notes: list[str] = []
        for ev in events:
            ev["alerts"], ev["effects"], ev["blocked_by"] = [], [], []
            if ev["src_mac"] and not is_group(ev["src_mac"]):
                self.host(ev["src_mac"])
            handler = getattr(self, f"on_{ev['kind']}", None)
            if handler:
                handler(ev)
            self.check_impact(ev)
        return self.timeline(events)

    # ------------------------------------------------------------------ ARP
    def on_arp(self, ev: dict):
        ip, mac, t = ev["psrc"], ev["hwsrc"], ev["t"]
        if ev["op"] == "request":
            self.arp_requests[(ev["psrc"], ev["pdst"])] = t
        if ip == "0.0.0.0":           # ARP probe (RFC 5227): makes no claim
            return
        solicited = ev["op"] == "request" or (
            t - self.arp_requests.get((ev["pdst"], ip), -1e9) < 3.0)
        gratuitous = ev["psrc"] == ev["pdst"]

        forged = False
        known = self.truth4.get(ip)
        if known and known[0] != mac:
            forged = True
            is_gw = known[0] == self.router_mac
            self.alert(ev, "ARP-01", "high" if is_gw else "medium", ip=ip,
                       claimed=self.name(mac), expected=self.name(known[0]), source=known[1])
            if not solicited and not gratuitous:
                ev["alerts"][-1]["explain"] += " Nobody asked for this reply (unsolicited)."
            ev["blocked_by"].append("dai")

        if not self.is_trusted(mac):
            ips = self.mac_ips.setdefault(mac, set())
            if ip not in ips:
                ips.add(ip)
                if len(ips) > 1:
                    self.alert(ev, "ARP-02", "medium", claimed=self.name(mac),
                               count=len(ips), ips=", ".join(sorted(ips)))

        if not known:
            self.truth4[ip] = (mac, f"first sighting, frame {ev['i']}")
        if self.hosts[mac].ip4 is None and not forged:
            self.hosts[mac].ip4 = ip

        # RFC 826 merge rule: update an existing entry for the sender, and add
        # one if this host is the target. Unsolicited replies still update.
        for h in self.recipients(ev):
            if ip in h.arp or (h.ip4 and ev["pdst"] == h.ip4):
                prev = h.arp.get(ip)
                h.arp[ip] = mac
                pinned = h.role == "client" and h.gw4 == ip and mac != self.router_mac
                self.effect(ev, h, "arp", ip, mac, prev, static_arp_blocks=pinned)

    # ------------------------------------------------------------------ IPv6 ND
    def on_ns(self, ev: dict):
        src_ip, mac = ev["src_ip"], ev["src_mac"]
        sender = self.hosts.get(mac)
        if src_ip == "::":                    # Duplicate Address Detection
            if sender:
                sender.ip6.add(ev["target"])  # new (often temporary) address for a known MAC: normal
            return
        if sender:
            sender.pending_ns.add(ev["target"])
            sender.ip6.add(src_ip)
        lla = ev["sllao"] or mac
        known = self.truth6.get(src_ip)
        if known and known[0] != lla:
            self.alert(ev, "ND-01", "high" if known[0] == self.router_mac else "medium",
                       ip=src_ip, claimed=self.name(lla), expected=self.name(known[0]),
                       source=known[1], override="not used (NS source option)")
        elif not known:
            self.truth6[src_ip] = (lla, f"first sighting, frame {ev['i']}")
        # RFC 4861 7.2.3: the target creates or updates an entry for the sender.
        if ev["sllao"]:
            for h in self.recipients(ev):
                if ev["target"] in h.ip6:
                    prev = h.nd.get(src_ip)
                    h.nd[src_ip] = lla
                    self.effect(ev, h, "nd", src_ip, lla, prev)

    def on_na(self, ev: dict):
        tgt, lla = ev["target"], ev["tlla"]
        known = self.truth6.get(tgt)
        if known and known[0] != lla:
            self.alert(ev, "ND-01", "high" if known[0] == self.router_mac else "medium",
                       ip=tgt, claimed=self.name(lla), expected=self.name(known[0]),
                       source=known[1], override="set" if ev["O"] else "clear")
        elif not known:
            self.truth6[tgt] = (lla, f"first sighting, frame {ev['i']}")
            if ev["src_mac"] in self.hosts:
                self.hosts[ev["src_mac"]].ip6.add(tgt)
        # RFC 4861 7.2.5: replace an existing entry only when O=1 (or same address);
        # fill an entry the host was waiting on; otherwise ignore.
        for h in self.recipients(ev):
            if tgt in h.pending_ns:
                h.pending_ns.discard(tgt)
                prev = h.nd.get(tgt)
                h.nd[tgt] = lla
                self.effect(ev, h, "nd", tgt, lla, prev)
            elif tgt in h.nd and (ev["O"] or h.nd[tgt] == lla):
                prev = h.nd[tgt]
                h.nd[tgt] = lla
                self.effect(ev, h, "nd", tgt, lla, prev)

    def on_ra(self, ev: dict):
        mac, src_ip = ev["src_mac"], ev["src_ip"]
        if not self.trusted:
            self.adopt_router(mac, f"first Router Advertisement, frame {ev['i']}")
        pref = {1: "high", 0: "medium", -1: "low"}[ev["prf"]]
        if self.is_trusted(mac):
            self.seen_trusted_ra = True
            self.truth6.setdefault(src_ip, (mac, f"RA from the trusted router, frame {ev['i']}"))
        else:
            ev["blocked_by"].append("ra_guard")
            self.alert(ev, "RA-01", "high", claimed=self.name(mac), expected=self.name(self.router_mac),
                       lifetime=ev["lifetime"], pref=pref)
            if ev["rdnss"]:
                self.alert(ev, "RA-02", "high", dns=", ".join(ev["rdnss"]))
            self.truth6.setdefault(src_ip, (mac, f"first sighting, frame {ev['i']}"))

        lla = ev["sllao"] or mac
        for h in self.recipients(ev):
            if h.role == "router":          # routers do not take RAs from the LAN
                continue
            prev = h.nd.get(src_ip)
            h.nd[src_ip] = lla
            self.effect(ev, h, "nd", src_ip, lla, prev)
            if ev["lifetime"] > 0:
                if src_ip not in h.routers6:
                    self.router_order += 1
                    h.routers6[src_ip] = {"pref": ev["prf"], "order": self.router_order}
                else:
                    h.routers6[src_ip]["pref"] = ev["prf"]
                self.effect(ev, h, "router6", src_ip, {"pref": ev["prf"], "order": h.routers6[src_ip]["order"]})
            elif src_ip in h.routers6:
                del h.routers6[src_ip]
                self.effect(ev, h, "router6_del", src_ip, None)
            if ev["rdnss"]:
                prev = h.dns6
                h.dns6 = ev["rdnss"][0]
                self.effect(ev, h, "dns6", None, h.dns6, prev)

    # ------------------------------------------------------------------ DHCP
    def on_dhcp(self, ev: dict):
        mac = ev["src_mac"]
        if not ev["is_server_msg"]:
            return
        if not self.trusted:
            self.adopt_router(mac, f"first DHCP server reply, frame {ev['i']}")
        trusted = self.is_trusted(mac)
        client = self.hosts.get(ev["chaddr"]) or self.host(ev["chaddr"])
        if not trusted:
            ev["blocked_by"].append("dai")   # DHCP snooping drops server replies on untrusted ports
            self.alert(ev, "DHCP-01", "high", claimed=self.name(mac), expected=self.name(self.router_mac),
                       msg=ev["msg"].upper())
        if self.base_router is not None and ev["msg"] in ("offer", "ack") and (
                ev["router"] != self.base_router or ev["dns"] != self.base_dns):
            self.alert(ev, "DHCP-02", "medium", client=client.name,
                       router=", ".join(ev["router"]) or "-", dns=", ".join(ev["dns"]) or "-",
                       base_router=", ".join(self.base_router), base_dns=", ".join(self.base_dns))

        if trusted and ev["msg"] == "ack":
            if self.base_router is None:
                self.base_router, self.base_dns = ev["router"], ev["dns"]
            self.truth4[ev["yiaddr"]] = (ev["chaddr"], f"DHCP lease, frame {ev['i']}")
            if ev["server_id"]:
                self.truth4[ev["server_id"]] = (mac, f"DHCP server identifier, frame {ev['i']}")
            for r in ev["router"]:
                self.truth4.setdefault(r, (mac, f"DHCP router option, frame {ev['i']}"))

        if ev["msg"] == "ack":   # the client configures itself from the ACK it accepted
            for kind, val, attr in (("ip4", ev["yiaddr"], "ip4"),
                                    ("gw4", (ev["router"] or [None])[0], "gw4"),
                                    ("dns4", (ev["dns"] or [None])[0], "dns4")):
                prev = getattr(client, attr)
                setattr(client, attr, val)
                self.effect(ev, client, kind, None, val, prev)

    def on_dhcp6(self, ev: dict):
        mac = ev["src_mac"]
        if not ev["is_server_msg"]:
            sender = self.hosts.get(mac)
            if sender:
                sender.ip6.add(ev["src_ip"])
            return
        dns = ", ".join(ev["dns"]) or "-"
        self.truth6.setdefault(ev["src_ip"], (mac, f"DHCPv6 server address, frame {ev['i']}"))
        if not self.is_trusted(mac):
            ev["blocked_by"].append("dhcpv6_guard")
            self.alert(ev, "D6-01", "high", claimed=self.name(mac), expected=self.name(self.router_mac),
                       msg=ev["msg"].upper(), dns=dns)
            if not self.seen_trusted_ra:
                self.alert(ev, "D6-02", "medium")
        if ev["msg"] == "reply":
            for h in self.recipients(ev):
                if ev["dns"]:
                    prev = h.dns6
                    h.dns6 = ev["dns"][0]
                    self.effect(ev, h, "dns6", None, h.dns6, prev)
                for a in ev["addrs"]:
                    h.ip6.add(a)
                    self.effect(ev, h, "ip6", a, a)

    # ------------------------------------------------------------------ traffic
    def on_data(self, ev: dict):
        owner = self.hosts.get(ev["dst_mac"])
        ev["next_hop"] = ev["dst_mac"]
        ev["next_hop_role"] = owner.role if owner else None

    # ------------------------------------------------------------------ impact
    def owner4(self, ip: str | None) -> str | None:
        return self.truth4.get(ip, (None,))[0] if ip else None

    def owner6(self, ip: str | None) -> str | None:
        return self.truth6.get(ip, (None,))[0] if ip else None

    def check_impact(self, ev: dict):
        if not self.router_mac:
            return
        for h in self.hosts.values():
            if h.role != "client":
                continue
            checks = {}
            if h.gw4:
                checks["IPv4 gateway"] = h.arp.get(h.gw4)
            if h.default_router6():
                checks["IPv6 default router"] = h.nd.get(h.default_router6())
            # For DNS, check where the host's packets would really go: an on-link
            # DNS server is reached through the host's own (possibly poisoned) cache.
            if h.dns4 and (h.arp.get(h.dns4) or self.owner4(h.dns4)):
                checks["IPv4 DNS server"] = h.arp.get(h.dns4) or self.owner4(h.dns4)
            if h.dns6 and (h.nd.get(h.dns6) or self.owner6(h.dns6)):
                checks["IPv6 DNS server"] = h.nd.get(h.dns6) or self.owner6(h.dns6)
            for what, actual in checks.items():
                bad = actual is not None and actual != self.router_mac
                if bad and what not in h.unsafe:
                    h.unsafe.add(what)
                    self.alert(ev, "XP-01", "high", host=h.name, what=what,
                               actual=self.name(actual), expected=self.name(self.router_mac))
                elif not bad:
                    h.unsafe.discard(what)

    # ------------------------------------------------------------------ output
    def timeline(self, events: list[dict]) -> dict:
        by_rule: dict[str, int] = {}
        for a in self.alerts:
            by_rule[a["rule"]] = by_rule.get(a["rule"], 0) + 1
        t0 = events[0]["t"] if events else 0.0
        for ev in events:
            ev["rel_t"] = round(ev["t"] - t0, 3)
        return {
            "schema": SCHEMA,
            "router_mac": self.router_mac,
            "hosts": [{"mac": h.mac, "name": h.name, "role": h.role, "ip4": h.ip4,
                       "ip6": sorted(h.ip6), "final": h.card()} for h in self.hosts.values()],
            "frames": events,
            "rules": RULES,
            "summary": {"frames": len(events), "alerts": len(self.alerts),
                        "frames_with_alerts": len({a["frame"] for a in self.alerts}),
                        "by_rule": by_rule, "notes": self.notes},
        }


def analyze(pcap_path: str, hosts_meta: dict | None = None, trusted_macs: list[str] | None = None) -> dict:
    """Analyze one capture file and return the JSON-ready timeline."""
    return Engine(hosts_meta, trusted_macs).run(read_capture(pcap_path))


def dump(timeline: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(timeline, f, indent=1, default=str)
