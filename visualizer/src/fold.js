// Rebuild every host's beliefs up to a given frame, with defenses applied.
//
// The engine writes each frame's "effects" (what that frame changed in each
// host's ARP cache, neighbor cache, router list or DNS settings) and
// "blocked_by" (which switch defense would have dropped the frame). Folding
// the effects in order, and skipping blocked frames, gives the state of the
// network at any frame under any combination of defense toggles. This is how
// the defense toggles work without re-running the Python engine.

export function emptyHost() {
  return { arp: {}, nd: {}, ip4: null, ip6: new Set(), gw4: null, routers6: {}, dns4: null, dns6: null };
}

/** True if this frame never reaches any host with these defenses on. */
export function isBlocked(frame, defenses) {
  return frame.blocked_by.some((d) => defenses.has(d));
}

export function fold(timeline, upto, defenses) {
  const hosts = new Map(timeline.hosts.map((h) => [h.mac, emptyHost()]));
  const blocked = new Set();
  const pinned = new Set(); // frames whose ARP effect a static entry ignored
  for (const f of timeline.frames) {
    if (f.i > upto) break;
    if (isBlocked(f, defenses)) {
      blocked.add(f.i);
      continue;
    }
    for (const e of f.effects) {
      const h = hosts.get(e.host);
      if (!h) continue;
      if (e.kind === "arp" && e.static_arp_blocks && defenses.has("static_arp")) {
        pinned.add(f.i);
        continue;
      }
      apply(h, e);
    }
  }
  return { hosts, blocked, pinned };
}

function apply(h, e) {
  switch (e.kind) {
    case "arp": h.arp[e.key] = e.value; break;
    case "nd": h.nd[e.key] = e.value; break;
    case "router6": h.routers6[e.key] = e.value; break;
    case "router6_del": delete h.routers6[e.key]; break;
    case "ip4": h.ip4 = e.value; break;
    case "ip6": h.ip6.add(e.value); break;
    case "gw4": h.gw4 = e.value; break;
    case "dns4": h.dns4 = e.value; break;
    case "dns6": h.dns6 = e.value; break;
  }
}

/** RFC 4191: highest preference wins, ties go to the router learned first. */
export function defaultRouter6(h) {
  let best = null;
  for (const [ip, r] of Object.entries(h.routers6)) {
    if (!best || r.pref > best.r.pref || (r.pref === best.r.pref && r.order < best.r.order)) best = { ip, r };
  }
  return best ? best.ip : null;
}

const sameSubnet24 = (a, b) => a && b && a.split(".").slice(0, 3).join(".") === b.split(".").slice(0, 3).join(".");
const isLinkLocal = (ip) => ip && ip.toLowerCase().startsWith("fe80:");

/** MAC address a host's packet to `ip` would really be sent to. */
export function nextHop4(h, ip) {
  if (!ip) return null;
  return sameSubnet24(ip, h.ip4) ? h.arp[ip] ?? null : (h.gw4 ? h.arp[h.gw4] ?? null : null);
}
export function nextHop6(h, ip) {
  if (!ip) return null;
  if (isLinkLocal(ip)) return h.nd[ip] ?? null;
  const gw = defaultRouter6(h);
  return gw ? h.nd[gw] ?? null : null;
}

/** The four rows of a host's trust card. status: ok | bad | unknown */
export function trustCard(h, routerMac) {
  const gw6 = defaultRouter6(h);
  const rows = [
    { label: "IPv4 gateway", ip: h.gw4, mac: h.gw4 ? h.arp[h.gw4] ?? null : null },
    { label: "IPv6 router", ip: gw6, mac: gw6 ? h.nd[gw6] ?? null : null },
    { label: "IPv4 DNS", ip: h.dns4, mac: nextHop4(h, h.dns4) },
    { label: "IPv6 DNS", ip: h.dns6, mac: nextHop6(h, h.dns6) },
  ];
  for (const r of rows) r.status = !r.mac ? "unknown" : r.mac === routerMac ? "ok" : "bad";
  return rows;
}

/** Where a captured data packet would go now, given the folded state. */
export function effectiveNextHop(frame, h) {
  if (frame.kind !== "data" || !h) return null;
  const dns = frame.app === "DNS query";
  if (frame.proto === "IPv4") return nextHop4(h, dns ? h.dns4 ?? frame.dst_ip : frame.dst_ip);
  return nextHop6(h, dns ? h.dns6 ?? frame.dst_ip : frame.dst_ip);
}
