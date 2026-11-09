// The Invisible Middleman visualizer.
// Loads a timeline produced by the Python engine plus the scenario guide, and lets
// the learner step through the capture frame by frame.
import { drawDiagram, layout } from "./diagram.js";
import { effectiveNextHop, fold, isBlocked, trustCard } from "./fold.js";

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

const state = {
  content: null, scenario: null, tl: null, pos: null,
  frame: 1, defenses: new Set(), answers: {}, quiz: {}, challengeStart: null,
};

// ------------------------------------------------------------------ loading
async function init() {
  state.content = await (await fetch("./content/scenarios.json")).json();
  const sel = $("#scenario");
  for (const s of state.content.scenarios) sel.add(new Option(s.title, s.id));
  sel.addEventListener("change", () => loadScenario(sel.value));
  bindControls();
  await loadScenario(new URLSearchParams(location.search).get("s") || state.content.scenarios[0].id);
}

async function loadScenario(id) {
  const sc = state.content.scenarios.find((s) => s.id === id) || state.content.scenarios[0];
  state.scenario = sc;
  state.tl = await (await fetch(`./data/${sc.file}.json`)).json();
  state.pos = layout(state.tl.hosts);
  state.frame = 1;
  state.defenses = new Set(sc.defaults || []);
  state.answers = {};
  state.quiz = {};
  state.challengeStart = sc.challenge ? Date.now() : null;
  $("#scenario").value = sc.id;
  $("#next-alert").hidden = !!sc.challenge; // would give the challenge away
  $("#slider").max = state.tl.frames.length;
  renderIntro();
  renderFrameList();
  renderDefenses();
  renderAssessment();
  render();
}

// ------------------------------------------------------------------ naming
// In challenge mode the host names would give the answer away, so hosts become "Host A", "Host B"...
function label(h) {
  if (!state.scenario.challenge) return h.name;
  if (h.role === "router") return "router";
  const clients = state.tl.hosts.filter((x) => x.role !== "router");
  return `Host ${String.fromCharCode(65 + clients.indexOf(h))}`;
}
function nameOf(mac) {
  const h = state.tl.hosts.find((x) => x.mac === mac);
  if (h) return label(h);
  if (mac === "ff:ff:ff:ff:ff:ff") return "everyone (broadcast)";
  if (mac && mac.startsWith("33:33")) return "IPv6 multicast";
  return mac || "?";
}
const showAlerts = () => !state.scenario.challenge;

// ------------------------------------------------------------------ rendering
function render() {
  const { tl, frame } = state;
  const f = tl.frames[frame - 1];
  const folded = fold(tl, frame, state.defenses);
  const cards = new Map(tl.hosts.filter((h) => h.role === "client")
    .map((h) => [h.mac, trustCard(folded.hosts.get(h.mac), tl.router_mac)]));
  const statusByMac = new Map([...cards].map(([mac, rows]) => [mac, rows.some((r) => r.status === "bad") ? "bad" : "ok"]));
  const blocked = isBlocked(f, state.defenses);
  const via = effectiveNextHop(f, folded.hosts.get(f.src_mac));

  drawDiagram($("#diagram"), { hosts: tl.hosts, pos: state.pos, frame: f, statusByMac, label, viaMac: via, blocked });
  $("#slider").value = frame;
  $("#position").textContent = `Frame ${frame} / ${tl.frames.length} · t = ${f.rel_t.toFixed(1)} s`;
  document.querySelectorAll("#frames tr.current").forEach((r) => r.classList.remove("current"));
  const row = document.querySelector(`#frames tr[data-i="${frame}"]`);
  if (row) { row.classList.add("current"); row.scrollIntoView({ block: "nearest" }); }

  renderDetail(f, blocked, folded, via);
  renderCards(cards, f);
  renderGuide();
}

function renderIntro() {
  const sc = state.scenario;
  $("#intro").innerHTML = `<h2>${esc(sc.title)}</h2>${sc.intro.map((p) => `<p>${esc(p)}</p>`).join("")}
    <p class="meta">Learning objective ${sc.objective} · about ${sc.minutes} minutes</p>`;
}

function renderFrameList() {
  const checkpoints = new Set(state.scenario.steps.map((s) => s.frame));
  $("#frames tbody").innerHTML = state.tl.frames.map((f) => {
    const cls = [showAlerts() && f.alerts.length ? "has-alert" : "", checkpoints.has(f.i) ? "checkpoint" : ""].join(" ");
    return `<tr data-i="${f.i}" class="${cls}"><td>${f.i}</td><td>${f.rel_t.toFixed(1)}</td><td>${esc(f.proto)}</td><td>${esc(f.summary)}</td></tr>`;
  }).join("");
  document.querySelectorAll("#frames tbody tr").forEach((tr) => tr.addEventListener("click", () => go(+tr.dataset.i)));
}

function renderDetail(f, blocked, folded, via) {
  const alerts = showAlerts() ? f.alerts : [];
  const effects = f.effects.filter((e) => e.prev !== e.value);
  const changed = blocked ? [] : effects.map((e) => {
    const pinned = e.kind === "arp" && e.static_arp_blocks && state.defenses.has("static_arp");
    const what = { arp: "ARP cache", nd: "neighbor cache", router6: "IPv6 router list", router6_del: "IPv6 router list",
      dns4: "IPv4 DNS server", dns6: "IPv6 DNS server", gw4: "IPv4 gateway", ip4: "IPv4 address", ip6: "IPv6 address" }[e.kind];
    const val = e.kind === "router6" ? `adds ${e.key} (preference ${["low", "medium", "high"][e.value.pref + 1]})`
      : e.kind === "router6_del" ? `removes ${e.key}`
      : e.key ? `${e.key} -> ${nameOf(e.value)}` : `${e.value}`;
    return `<li class="${pinned ? "pinned" : ""}">${esc(label(state.tl.hosts.find((h) => h.mac === e.host)))}: ${what} ${esc(val)}${pinned ? " (ignored: static ARP entry)" : ""}</li>`;
  });
  const fields = ["op", "psrc", "hwsrc", "pdst", "target", "tlla", "O", "S", "R", "prf", "lifetime", "sllao", "rdnss",
    "msg", "chaddr", "yiaddr", "server_id", "router", "dns", "addrs", "src_ip", "dst_ip", "qname"]
    .filter((k) => f[k] !== undefined && f[k] !== null && !(Array.isArray(f[k]) && !f[k].length))
    .map((k) => `<tr><th>${k}</th><td>${esc(Array.isArray(f[k]) ? f[k].join(", ") : f[k])}</td></tr>`).join("");
  const viaNote = f.kind === "data"
    ? `<p>Captured: sent to <b>${esc(nameOf(f.dst_mac))}</b>.` +
      (via && via !== f.dst_mac ? ` With the defenses you have on, this host would send it to <b>${esc(nameOf(via))}</b> instead.` : "") + "</p>"
    : "";
  $("#detail").innerHTML = `<h3>Frame ${f.i}: ${esc(f.proto)}</h3>
    <p class="summary">${esc(f.summary)}</p>
    <p>From <b>${esc(nameOf(f.src_mac))}</b> to <b>${esc(nameOf(f.dst_mac))}</b></p>
    ${blocked ? `<p class="blocked">Dropped by the switch: ${f.blocked_by.filter((d) => state.defenses.has(d)).map((d) => esc(state.content.defenses[d].label)).join(", ")}. No host ever sees this frame.</p>` : ""}
    ${viaNote}
    ${alerts.map((a) => `<div class="alert ${a.severity}"><b>${esc(a.severity.toUpperCase())} · ${esc(a.rule)} · ${esc(a.title)}</b>
      <p>${esc(a.explain)}</p><p class="meta">Field: ${esc(a.field)} · MITRE ATT&amp;CK ${esc(a.mitre)}</p></div>`).join("")}
    ${changed.length ? `<h4>What this frame changed</h4><ul>${changed.join("")}</ul>` : ""}
    <details><summary>Decoded fields</summary><table class="fields">${fields}</table></details>`;
}

function renderCards(cards, f) {
  const touched = new Set(f.effects.map((e) => e.host));
  $("#cards").innerHTML = `<h3>Trust cards</h3><p class="meta">Who each host believes its router and DNS server are, and which machine its packets for them really reach.</p>` +
    [...cards].map(([mac, rows]) => `<div class="card ${touched.has(mac) ? "touched" : ""}">
      <h4>${esc(nameOf(mac))}</h4>
      ${rows.map((r) => `<div class="row ${r.status}"><span>${r.label}</span><span>${esc(r.ip || "-")}</span>
        <span>${r.status === "ok" ? "OK: real router" : r.status === "bad" ? "WRONG: " + esc(nameOf(r.mac)) : "not set"}</span></div>`).join("")}
    </div>`).join("");
}

function renderDefenses() {
  const d = state.content.defenses;
  $("#defenses").innerHTML = `<h3>Defenses</h3>` + Object.entries(d).map(([k, v]) => `
    <label class="defense"><input type="checkbox" data-d="${k}" ${state.defenses.has(k) ? "checked" : ""}/> <b>${esc(v.label)}</b>
      <span class="meta">${esc(v.what)} <i>Limit:</i> ${esc(v.limit)}</span></label>`).join("");
  document.querySelectorAll("#defenses input").forEach((cb) => cb.addEventListener("change", () => {
    cb.checked ? state.defenses.add(cb.dataset.d) : state.defenses.delete(cb.dataset.d);
    render();
  }));
}

// ------------------------------------------------------------------ guided checkpoints
function renderGuide() {
  const steps = state.scenario.steps;
  const step = steps.find((s) => s.frame === state.frame);
  const answered = steps.filter((s) => s.question && state.answers[s.frame] !== undefined);
  const correct = answered.filter((s) => state.answers[s.frame] === s.question.answer).length;
  const total = steps.filter((s) => s.question).length;
  const score = total ? `<p class="meta">Checkpoint questions: ${correct} / ${total} correct${answered.length === total && total ? (correct / total >= 0.8 ? " (objective met)" : " (aim for 80%)") : ""}</p>` : "";
  if (!step) {
    const next = steps.find((s) => s.frame > state.frame);
    $("#guide").innerHTML = `<h3>Guide</h3>${next ? `<p>Next checkpoint at frame ${next.frame}: <i>${esc(next.title)}</i>.</p>` : steps.length ? "<p>No more checkpoints.</p>" : "<p>Step through the capture.</p>"}${score}`;
    return;
  }
  $("#guide").innerHTML = `<h3>Checkpoint: ${esc(step.title)}</h3><p>${esc(step.text)}</p>${step.question ? questionHtml(step.question, state.answers[step.frame], "step") : ""}${score}`;
  document.querySelectorAll("#guide button.opt").forEach((b) => b.addEventListener("click", () => {
    state.answers[step.frame] = +b.dataset.k;
    renderGuide();
  }));
}

function questionHtml(q, chosen, prefix) {
  return `<p class="q">${esc(q.prompt)}</p><div class="opts">${q.options.map((o, k) => {
    const cls = chosen === undefined ? "" : k === q.answer ? "right" : k === chosen ? "wrong" : "";
    return `<button class="opt ${cls}" data-k="${k}" data-p="${prefix}" ${chosen !== undefined ? "disabled" : ""}>${esc(o)}</button>`;
  }).join("")}</div>${chosen !== undefined ? `<p class="feedback ${chosen === q.answer ? "right" : "wrong"}">${esc(q.feedback[chosen])}</p>` : ""}`;
}

// ------------------------------------------------------------------ quizzes and challenge
function renderAssessment() {
  const sc = state.scenario;
  if (sc.challenge) return renderChallenge(sc);
  if (!sc.quiz) { $("#assessment").innerHTML = ""; return; }
  const qs = sc.quiz.questions;
  const done = Object.keys(state.quiz).length;
  const right = qs.filter((q, i) => state.quiz[i] === q.answer).length;
  $("#assessment").innerHTML = `<h3>${esc(sc.quiz.title)}</h3>` + qs.map((q, i) =>
    `<div class="quizq" data-i="${i}">${questionHtml(q, state.quiz[i], "quiz")}</div>`).join("") +
    (done === qs.length ? `<p class="score ${right / qs.length >= sc.quiz.pass ? "right" : "wrong"}">Score: ${right} / ${qs.length} (${Math.round((100 * right) / qs.length)}%). Target: ${sc.quiz.pass * 100}%.</p>` : "");
  document.querySelectorAll("#assessment .quizq").forEach((div) => div.querySelectorAll("button.opt").forEach((b) =>
    b.addEventListener("click", () => { state.quiz[+div.dataset.i] = +b.dataset.k; renderAssessment(); })));
}

function renderChallenge(sc) {
  const clients = state.tl.hosts.filter((h) => h.role !== "router");
  $("#assessment").innerHTML = `<h3>Your findings</h3>
    <label>Attack type <select id="c-type"><option value="">choose...</option>${sc.attack_options.map((o, k) => `<option value="${k}">${esc(o)}</option>`).join("")}</select></label>
    <label>Attacker MAC <select id="c-mac"><option value="">choose...</option>${clients.map((h) => `<option>${h.mac}</option>`).join("")}</select></label>
    <fieldset><legend>Affected host(s)</legend>${clients.map((h) => `<label><input type="checkbox" value="${h.mac}"/> ${esc(label(h))} (${h.mac})</label>`).join("")}</fieldset>
    <button id="c-submit">Check my answer</button><div id="c-result"></div>`;
  $("#c-submit").addEventListener("click", () => {
    const a = sc.answers;
    const type = $("#c-type").value === String(a.attack_type);
    const mac = $("#c-mac").value === a.attacker_mac;
    const picked = [...document.querySelectorAll("#assessment fieldset input:checked")].map((c) => c.value).sort();
    const hosts = JSON.stringify(picked) === JSON.stringify([...a.affected].sort());
    const mins = ((Date.now() - state.challengeStart) / 60000).toFixed(1);
    const all = type && mac && hosts;
    $("#c-result").innerHTML = `<ul><li class="${type ? "right" : "wrong"}">Attack type: ${type ? "correct" : "not quite"}</li>
      <li class="${mac ? "right" : "wrong"}">Attacker MAC: ${mac ? "correct" : "not quite"}</li>
      <li class="${hosts ? "right" : "wrong"}">Affected hosts: ${hosts ? "correct" : "not quite"}</li></ul>
      <p>Time: ${mins} minutes (target: ${sc.minutes}).</p>${all ? `<p class="feedback right">${esc(sc.debrief)}</p>` : "<p>Keep investigating: find the first trust card that turns red.</p>"}`;
  });
}

// ------------------------------------------------------------------ controls
function go(i) {
  state.frame = Math.max(1, Math.min(state.tl.frames.length, i));
  render();
}
function bindControls() {
  $("#first").onclick = () => go(1);
  $("#prev").onclick = () => go(state.frame - 1);
  $("#next").onclick = () => go(state.frame + 1);
  $("#last").onclick = () => go(state.tl.frames.length);
  $("#slider").oninput = (e) => go(+e.target.value);
  $("#next-step").onclick = () => {
    const s = state.scenario.steps.find((x) => x.frame > state.frame);
    if (s) go(s.frame);
  };
  $("#next-alert").onclick = () => {
    const f = state.tl.frames.find((x) => x.i > state.frame && (showAlerts() ? x.alerts.length : x.blocked_by.length));
    if (f) go(f.i);
  };
  document.addEventListener("keydown", (e) => {
    if (e.target.tagName === "INPUT" || e.target.tagName === "SELECT") return;
    if (e.key === "ArrowRight") go(state.frame + 1);
    if (e.key === "ArrowLeft") go(state.frame - 1);
  });
}

init();
