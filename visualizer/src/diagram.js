// Network diagram: router on top, the switch in the middle, hosts below.
// Each frame is drawn as an arrow from the sender to the receiver(s).
import * as d3 from "d3";

const W = 640;
const SWITCH = { x: W / 2, y: 150 };

export function layout(hosts) {
  const pos = new Map();
  const clients = hosts.filter((h) => h.role !== "router");
  hosts.filter((h) => h.role === "router").forEach((h) => pos.set(h.mac, { x: W / 2, y: 50 }));
  clients.forEach((h, k) => {
    const x = clients.length === 1 ? W / 2 : 70 + (k * (W - 140)) / (clients.length - 1);
    pos.set(h.mac, { x, y: 285 });
  });
  return pos;
}

export function drawDiagram(svgEl, { hosts, pos, frame, statusByMac, label, viaMac, blocked }) {
  const svg = d3.select(svgEl);
  svg.selectAll("*").remove();
  svg.append("defs").append("marker").attr("id", "arrow").attr("viewBox", "0 0 10 10")
    .attr("refX", 9).attr("refY", 5).attr("markerWidth", 7).attr("markerHeight", 7).attr("orient", "auto-start-reverse")
    .append("path").attr("d", "M0,0 L10,5 L0,10 z").attr("class", "arrowhead");

  // cables
  svg.append("g").selectAll("line").data(hosts).join("line")
    .attr("class", "cable").attr("x1", SWITCH.x).attr("y1", SWITCH.y)
    .attr("x2", (h) => pos.get(h.mac).x).attr("y2", (h) => pos.get(h.mac).y);

  svg.append("rect").attr("class", "switch").attr("x", SWITCH.x - 45).attr("y", SWITCH.y - 14)
    .attr("width", 90).attr("height", 28).attr("rx", 4);
  svg.append("text").attr("class", "switch-label").attr("x", SWITCH.x).attr("y", SWITCH.y + 4).text("switch");

  // the current frame
  if (frame && frame.src_mac && pos.has(frame.src_mac)) {
    const cls = blocked ? "flow blocked" : frame.alerts.length ? "flow alert" : "flow";
    const src = pos.get(frame.src_mac);
    const g = svg.append("g").attr("class", cls);
    const toSwitch = blocked ? { x: SWITCH.x, y: SWITCH.y } : null;
    const group = isGroup(frame.dst_mac);
    const targets = blocked ? [] : group
      ? hosts.filter((h) => h.mac !== frame.src_mac).map((h) => pos.get(h.mac))
      : pos.has(frame.dst_mac) ? [pos.get(frame.dst_mac)] : [];
    g.append("path").attr("d", line(src, toSwitch || SWITCH)).attr("marker-end", blocked ? "url(#arrow)" : null);
    for (const t of targets) g.append("path").attr("d", line(SWITCH, t)).attr("marker-end", "url(#arrow)");
    if (blocked) {
      svg.append("text").attr("class", "blocked-x").attr("x", SWITCH.x + 55).attr("y", SWITCH.y + 5).text("dropped by switch");
    }
    // where the packet would go now (only differs from the capture when a defense is on)
    if (viaMac && viaMac !== frame.dst_mac && pos.has(viaMac)) {
      svg.append("path").attr("class", "flow would").attr("d", line(SWITCH, pos.get(viaMac))).attr("marker-end", "url(#arrow)");
    }
  }

  // hosts
  const node = svg.append("g").selectAll("g").data(hosts).join("g")
    .attr("transform", (h) => `translate(${pos.get(h.mac).x},${pos.get(h.mac).y})`)
    .attr("class", (h) => `node ${h.role} ${statusByMac.get(h.mac) || ""}`);
  node.append("circle").attr("r", 24);
  node.append("text").attr("class", "node-name").attr("y", 42).text((h) => label(h));
  node.append("text").attr("class", "node-mac").attr("y", 56).text((h) => h.mac);
  node.append("text").attr("class", "node-icon").attr("y", 5)
    .text((h) => (h.role === "router" ? "R" : statusByMac.get(h.mac) === "bad" ? "!" : "PC"));
}

// Straight line from a to b, stopped short of b so the arrowhead is not hidden by the node circle.
function line(a, b) {
  const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1;
  const trim = b === SWITCH || (b.x === SWITCH.x && b.y === SWITCH.y) ? 16 : 28;
  return `M${a.x},${a.y} L${b.x - (dx / len) * trim},${b.y - (dy / len) * trim}`;
}
const isGroup = (mac) => mac && (parseInt(mac.slice(0, 2), 16) & 1) === 1;
