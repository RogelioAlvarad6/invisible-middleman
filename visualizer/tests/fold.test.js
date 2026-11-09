// Checks the defense-toggle logic against the real exported timelines.
// Run with:  npm test     (after scenarios/export_timelines.py)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fold, trustCard } from "../src/fold.js";

const load = (id) => JSON.parse(readFileSync(new URL(`../public/data/${id}.json`, import.meta.url)));

// Which rows of which client trust cards are wrong at the end of the capture.
function badRows(tl, defenses) {
  const { hosts } = fold(tl, tl.frames.length, new Set(defenses));
  const out = [];
  for (const h of tl.hosts.filter((x) => x.role === "client" && x.name !== "kali")) {
    for (const r of trustCard(hosts.get(h.mac), tl.router_mac)) if (r.status === "bad") out.push(`${h.name}: ${r.label}`);
  }
  return out.sort();
}

test("S1 benign: every trust card stays correct", () => {
  assert.deepEqual(badRows(load("S1_benign"), []), []);
});

test("S2: with no defenses, ubuntu-client's IPv4 gateway and DNS go to kali", () => {
  const bad = badRows(load("S2_arp_poisoning"), []);
  assert.ok(bad.includes("ubuntu-client: IPv4 gateway"));
});

test("S2: static ARP protects the client card, DAI protects everything", () => {
  assert.deepEqual(badRows(load("S2_arp_poisoning"), ["static_arp"]).filter((r) => r.startsWith("ubuntu")), []);
  assert.deepEqual(badRows(load("S2_arp_poisoning"), ["dai"]), []);
});

test("S3: RA-Guard keeps the IPv6 rows correct", () => {
  assert.ok(badRows(load("S3_rogue_ra"), []).length > 0);
  assert.deepEqual(badRows(load("S3_rogue_ra"), ["ra_guard"]), []);
});

test("S4: DHCPv6 Guard stops the mitm6-style DNS takeover", () => {
  assert.deepEqual(badRows(load("S4_rogue_dhcpv6"), []), ["win11-client: IPv6 DNS"]);
  assert.deepEqual(badRows(load("S4_rogue_dhcpv6"), ["dhcpv6_guard"]), []);
});

test("S5: IPv4 defenses leave IPv6 open; even all four toggles miss the NA spoof", () => {
  const tl = load("S5_dual_stack_gap");
  const ipv4Only = badRows(tl, ["static_arp", "dai"]);
  assert.ok(ipv4Only.every((r) => r.includes("IPv6")) && ipv4Only.length > 0);
  const all = badRows(tl, ["static_arp", "dai", "ra_guard", "dhcpv6_guard"]);
  assert.ok(all.length > 0 && all.every((r) => r.includes("IPv6")));
});

test("C1: DHCP snooping (part of the DAI toggle) stops the rogue DHCPv4 server", () => {
  assert.ok(badRows(load("C1_challenge"), []).some((r) => r.startsWith("phone")));
  assert.deepEqual(badRows(load("C1_challenge"), ["dai"]), []);
});
