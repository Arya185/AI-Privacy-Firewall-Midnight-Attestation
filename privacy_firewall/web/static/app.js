"use strict";
// AI Privacy Firewall dashboard. Every result shown comes from the local backend;
// if a call fails the error is displayed and nothing is substituted.

const $ = (sel) => document.querySelector(sel);

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const fill = (el, ...nodes) => el.replaceChildren(...nodes.flat().filter((n) => n !== null && n !== undefined && n !== false));
const short = (s, n = 12) => (s && s.length > n ? s.slice(0, n) + "…" : s || "—");
const pill = (value, extra = "") => h("span", { class: `pill ${String(value).toLowerCase()} ${extra}` }, String(value).toUpperCase());
const fmtTime = (iso) => { try { return new Date(iso).toLocaleTimeString(); } catch { return iso; } };

async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  };
  let res;
  try {
    res = await fetch(path, opts);
  } catch {
    setConn(false);
    throw new Error("Cannot reach the local backend. Is the server running?");
  }
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON */ }
  if (!res.ok) throw new Error((data && data.error) || `Request failed (HTTP ${res.status}).`);
  setConn(true);
  return data;
}

async function busy(button, fn) {
  const label = [...button.childNodes];
  button.disabled = true;
  button.replaceChildren(h("span", { class: "spin" }), "Working…");
  try { return await fn(); } finally { button.disabled = false; button.replaceChildren(...label); }
}

function setConn(ok) {
  $("#conn").className = "conn " + (ok ? "ok" : "down");
  $("#conn-text").textContent = ok ? "Backend connected · 127.0.0.1" : "Backend unreachable";
}

function showError(el, msg) { el.textContent = msg || ""; }

// ------------------------------------------------------------------ navigation
function showView(name) {
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${name}`));
  document.querySelectorAll(".tab").forEach((t) => {
    const on = t.dataset.view === name;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", String(on));
  });
  history.replaceState(null, "", `#${name}`);
  const loaders = { overview: loadStatus, audit: loadAuditTables, attestation: loadAttestation };
  if (loaders[name]) loaders[name]().catch((e) => console.error(e));
}
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => showView(t.dataset.view)));
document.querySelectorAll("[data-goto]").forEach((b) => b.addEventListener("click", () => showView(b.dataset.goto)));

// ------------------------------------------------------------------ overview
async function loadStatus() {
  let s;
  try { s = await api("/api/status"); } catch (e) { $("#k-health").textContent = "Offline"; $("#k-health-sub").textContent = e.message; return; }
  const d = s.session.field_decisions;
  const allow = d.allow || 0, agg = d.aggregate_only || 0, deny = d.deny || 0;
  const blockedOut = s.session.inspections.BLOCK || 0, allowedOut = s.session.inspections.ALLOW || 0;

  $("#k-health").textContent = s.firewall.healthy ? "Healthy" : "Error";
  $("#k-health").className = "kpi-value " + (s.firewall.healthy ? "ok" : "bad");
  $("#k-health-sub").textContent = `${s.firewall.agents.length} policy · ${s.firewall.records} mock records`;
  // Counts are policy verdicts as recorded in the audit chain. An aggregate-only verdict never
  // releases raw values (statistics only for an aggregate request, nothing for a raw read).
  $("#k-allowed").textContent = allow;
  $("#k-allowed-sub").textContent = `+ ${agg} aggregate-only (raw values never released) · ${allowedOut} outputs passed`;
  $("#k-blocked").textContent = deny + blockedOut;
  $("#k-blocked-sub").textContent = `${deny} denied fields · ${blockedOut} outputs blocked`;
  const n = s.session.total_decisions;
  $("#k-chain").textContent = n === 0 ? "Empty" : (s.session.chain_valid ? "Valid" : "Broken");
  $("#k-chain").className = "kpi-value " + (n === 0 ? "" : s.session.chain_valid ? "ok" : "bad");
  $("#k-chain-sub").textContent = n === 0 ? "Send a firewall request to start the chain" : `${n} entries, SHA-256 linked`;

  const c = $("#o-contracts");
  fill(c, 
    ...s.contracts.map((k) => statusLine(`${k.name}.compact`, k.compiled ? `compiled · Compact ${k.compiler_version}` : "not compiled",
      k.compiled ? "pass" : "fail", k.compiled ? "COMPILED" : "MISSING")),
    s.recorded_simulation
      ? statusLine("Recorded simulation", `${s.recorded_simulation.date || ""} · docs/evidence`, s.recorded_simulation.exit_code === 0 ? "pass" : "fail",
          `${s.recorded_simulation.passed}/${s.recorded_simulation.checks.length} PASS`, "recorded")
      : statusLine("Recorded simulation", "no evidence file", "neutral", "NONE"),
    s.last_simulation
      ? statusLine("Live simulation (this session)", `${s.last_simulation.hashes} decision hashes · ${fmtTime(s.last_simulation.time)}`,
          s.last_simulation.exit_code === 0 ? "pass" : "fail", `${s.last_simulation.passed} PASS`, "live")
      : statusLine("Live simulation (this session)", "not run yet — see Attestation", "neutral", "NOT RUN", "live"),
    statusLine("Midnight Preview deployment", "no transaction submitted", "neutral", "NOT DEPLOYED"),
  );

  const sl = s.sample_log;
  $("#o-sample").replaceChildren(sl.error ? h("div", { class: "empty" }, sl.error) : h("div", { class: "stack" },
    statusLine("Records", "synthetic log from fake_audit_generator.py", "neutral", String(sl.count)),
    statusLine("Decisions", Object.entries(sl.decisions).map(([k, v]) => `${k} ${v}`).join(" · "), "neutral", "MIXED"),
    statusLine("Chain vs recorded root hash", "root_hash.txt", sl.root_matches ? "pass" : "fail", sl.root_matches ? "MATCH" : "MISMATCH"),
  ));

  const act = $("#o-activity");
  fill(act, ...(s.activity.length ? s.activity.map((a) => h("li", {},
    h("time", {}, fmtTime(a.time)), h("span", { class: "kind" }, a.kind), h("span", {}, a.summary), pill(a.outcome, outcomeClass(a.outcome))))
    : [h("li", { class: "empty" }, "No activity yet in this session. Try the Firewall tab.")]));
}

function outcomeClass(o) {
  const v = String(o).toUpperCase();
  if (["ALLOW", "PASS", "OK", "DETECTED"].includes(v)) return "pass";
  if (["DENY", "BLOCK", "FAIL", "MISSED"].includes(v)) return "fail";
  return "neutral";
}

function statusLine(label, sub, cls, value, tag) {
  return h("div", { class: "status-line" },
    h("span", { class: "lbl" }, h("span", {}, label, " ", tag ? h("span", { class: `tag ${tag}` }, tag.toUpperCase()) : null), h("small", {}, sub)),
    h("span", { class: `pill ${cls}` }, value));
}

// ------------------------------------------------------------------ firewall
let policyRules = {};

async function initFirewall() {
  const [policy, samples] = await Promise.all([api("/api/policy"), api("/api/samples")]);
  $("#policy-file").textContent = policy.file;
  const agent = policy.agents[0];
  policyRules = Object.fromEntries(agent.permissions.map((p) => [p.field.split(".").pop(), p.read]));
  $("#policy-table tbody").replaceChildren(...agent.permissions.map((p) =>
    h("tr", {}, h("td", {}, h("code", {}, p.field)), h("td", {}, pill(p.read)))));

  const fields = [...new Set([...policy.record_fields.map((f) => (f === "id" ? "id" : f)), "ssn"])];
  $("#f-fields").replaceChildren(...fields.map((f) => {
    const rule = policyRules[f === "id" ? "employee_id" : f] || "not in policy";
    const input = h("input", { type: "checkbox", value: f });
    const chip = h("label", { class: "chip", title: `policy: ${rule}` }, input, f, h("span", { class: "rule" }, rule === "aggregate_only" ? "AGG" : rule === "not in policy" ? "∅" : rule.toUpperCase()));
    input.addEventListener("change", () => chip.classList.toggle("on", input.checked));
    return chip;
  }));

  $("#req-samples").append(...samples.requests.map((s) =>
    h("button", { class: "btn sample-btn", type: "button", title: s.description, onclick: () => fillRequest(s.request) }, s.label)));
  $("#out-samples").append(...samples.outputs.map((s) =>
    h("button", { class: "btn sample-btn", type: "button", onclick: () => { $("#o-text").value = s.text; $("#o-allowed").value = s.allowed_fields.join(", "); showError($("#out-error"), ""); } }, s.label)));
  fillRequest(samples.requests[0].request);
}

function fillRequest(r) {
  $("#f-agent").value = r.agent_id;
  $("#f-op").value = r.operation;
  $("#f-query").value = r.query || "";
  document.querySelectorAll("#f-fields input").forEach((i) => { i.checked = r.fields.includes(i.value); i.closest(".chip").classList.toggle("on", i.checked); });
  showError($("#req-error"), "");
  $("#f-agent").removeAttribute("aria-invalid");
}

function readRequest() {
  const agent = $("#f-agent").value.trim();
  const fields = [...document.querySelectorAll("#f-fields input:checked")].map((i) => i.value);
  const query = $("#f-query").value;
  $("#f-agent").removeAttribute("aria-invalid");
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(agent)) { $("#f-agent").setAttribute("aria-invalid", "true"); throw new Error("Agent ID: 1–64 letters, digits, '.', '_' or '-'."); }
  if (!fields.length) throw new Error("Select at least one field.");
  if (query.length > 500) throw new Error("Query text is limited to 500 characters.");
  return { agent_id: agent, operation: $("#f-op").value, fields, query };
}

$("#req-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = $("#req-error");
  let body;
  try { body = readRequest(); } catch (e) { showError(err, e.message); return; }
  showError(err, "");
  try {
    const r = await busy($("#req-submit"), () => api("/api/firewall/request", body));
    renderRequestResult(r);
    $("#o-allowed").value = r.allowed_fields.join(", ");
    loadStatus();
  } catch (e) { showError(err, e.message); }
});

function renderRequestResult(r) {
  const box = $("#req-result");
  const rows = r.field_decisions.map((f) => h("tr", {},
    h("td", {}, h("code", {}, f.field)), h("td", {}, pill(f.decision),
      r.request.operation === "read" && f.decision === "aggregate_only" ? h("span", { class: "field-note" }, "raw read refused: statistics only via an aggregate request") : null),
    h("td", {}, f.reason), h("td", { class: "hash", title: f.entry_hash }, short(f.entry_hash, 14))));
  fill(box, 
    h("div", { class: "card-head" }, h("h2", {}, "Firewall decision"), h("span", { class: "tag live" }, "LIVE")),
    h("div", { class: "result-head" }, pill(r.decision, "big-pill"), h("span", {}, r.reason || (r.decision === "ALLOW" ? "Request allowed under policy." : ""))),
    r.denied_fields && r.denied_fields.length ? h("div", { class: "note" }, "Denied fields: ", r.denied_fields.join(", ")) : null,
    rows.length
      ? h("div", { class: "table-wrap" }, h("table", { class: "table" }, h("thead", {}, h("tr", {}, h("th", {}, "Policy field"), h("th", {}, "Decision"), h("th", {}, "Reason"), h("th", {}, "Audit entry"))), h("tbody", {}, rows)))
      : h("div", { class: "note" }, "No field was evaluated (the request was rejected before any data was read)."),
    h("div", {}, h("div", { class: "muted small" }, "Payload returned to the agent"),
      h("pre", { class: "code" }, r.payload ? JSON.stringify(r.payload, null, 2) : "null — nothing is released")),
  );
  box.hidden = false;
  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

$("#out-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const err = $("#out-error");
  const text = $("#o-text").value;
  const allowed = $("#o-allowed").value.split(",").map((s) => s.trim()).filter(Boolean);
  if (!text.trim()) { showError(err, "Enter some model output to inspect."); return; }
  if (allowed.some((f) => !/^[a-z_]{1,32}$/.test(f))) { showError(err, "Allowed fields: lowercase names separated by commas."); return; }
  showError(err, "");
  try {
    const r = await busy($("#out-submit"), () => api("/api/firewall/inspect", { text, allowed_fields: allowed }));
    const box = $("#out-result");
    fill(box, 
      h("div", { class: "result-head" }, pill(r.decision, "big-pill"), h("span", {}, r.output_released ? "Output released to the user." : "Output withheld from the user.")),
      r.violations.length ? h("ul", { class: "check-list" }, r.violations.map((v) => h("li", {}, pill(v.kind, "fail"), v.detail))) : h("div", { class: "note" }, r.reason),
    );
    box.hidden = false;
    loadStatus();
  } catch (e) { showError(err, e.message); }
});

// ------------------------------------------------------------------ audit
async function loadAuditTables() {
  const [session, sample] = await Promise.allSettled([api("/api/audit/session"), api("/api/audit/sample-log")]);
  const st = $("#session-table tbody");
  if (session.status === "fulfilled") {
    const e = session.value.entries;
    fill(st, ...(e.length ? e.map((x) => h("tr", {},
      h("td", {}, x.index), h("td", {}, h("code", {}, x.field)), h("td", {}, pill(x.decision)), h("td", {}, x.reason),
      h("td", { class: "hash", title: x.entry_hash }, short(x.entry_hash, 14)), h("td", { class: "hash", title: x.prev_hash }, short(x.prev_hash, 14))))
      : [h("tr", {}, h("td", { colspan: 6, class: "empty" }, "No entries yet. Send a request from the Firewall tab."))]));
  } else fill(st, h("tr", {}, h("td", { colspan: 6, class: "empty" }, session.reason.message)));

  const sb = $("#sample-table tbody");
  if (sample.status === "fulfilled") {
    const s = sample.value;
    $("#sample-meta").textContent = `${s.file} · ${s.count} synthetic records · request IDs truncated · root ${short(s.root_hash, 16)} ${s.root_matches ? "matches" : "does NOT match"} root_hash.txt`;
    fill(sb, ...s.entries.map((x) => h("tr", {},
      h("td", {}, x.index), h("td", { class: "hash" }, x.request_id), h("td", {}, x.agent), h("td", {}, h("code", {}, x.resource)),
      h("td", {}, pill(x.decision)), h("td", { class: "hash", title: x.hash }, short(x.hash, 16)))));
  } else { $("#sample-meta").textContent = ""; fill(sb, h("tr", {}, h("td", { colspan: 6, class: "empty" }, sample.reason.message))); }
}

$("#btn-verify").addEventListener("click", async (ev) => {
  const box = $("#verify-result");
  try {
    const r = await busy(ev.currentTarget, () => api("/api/audit/verify", {}));
    const s = r.sample;
    fill(box, 
      h("div", { class: "result inline" },
        h("div", { class: "result-head" }, h("b", {}, "Live session chain"), h("span", { class: "tag live" }, "LIVE")),
        h("div", { class: "result-head" }, r.session.entries === 0 ? pill("EMPTY", "neutral") : pill(r.session.valid ? "PASS" : "FAIL"),
          h("span", {}, r.session.entries === 0 ? "No entries yet — nothing to verify." : `${r.session.entries} entries recomputed with AuditLog.verify_chain().`))),
      h("div", { class: "result inline" },
        h("div", { class: "result-head" }, h("b", {}, "Sample audit log"), h("span", { class: "tag sample" }, "SAMPLE")),
        s.error ? h("div", { class: "form-error" }, s.error) : h("dl", { class: "kv" },
          h("dt", {}, "Hash chain"), h("dd", {}, pill(s.chain_valid ? "PASS" : "FAIL"), ` ${s.entries} records`),
          h("dt", {}, "Computed root"), h("dd", { class: "hash" }, short(s.root_hash, 24)),
          h("dt", {}, "Recorded root"), h("dd", { class: "hash" }, short(s.recorded_root_hash, 24)),
          h("dt", {}, "Ed25519 signature"), h("dd", {}, pill(s.signature.status === "unavailable" ? "N/A" : s.signature.status, s.signature.status === "unavailable" ? "neutral" : ""),
            " ", s.signature.detail || (s.signature.signature ? `sig ${s.signature.signature}` : "")))),
    );
    box.hidden = false;
    loadAuditTables();
  } catch (e) { fill(box, h("div", { class: "form-error" }, e.message)); box.hidden = false; }
});

$("#btn-tamper").addEventListener("click", async (ev) => {
  const err = $("#tamper-error");
  const index = Number($("#t-index").value);
  if (!Number.isInteger(index) || index < 0) { showError(err, "Entry index must be a whole number ≥ 0."); return; }
  showError(err, "");
  const box = $("#tamper-result");
  try {
    const r = await busy(ev.currentTarget, () => api("/api/audit/tamper-demo", { target: $("#t-target").value, index }));
    const detected = r.tampered_copy_valid === false;
    const originalOk = r.target === "session" ? r.original_still_valid : r.original_unchanged;
    fill(box, 
      h("div", { class: "result-head" }, pill(detected ? "TAMPER DETECTED" : "NOT DETECTED", detected ? "pass" : "fail"),
        h("span", {}, `Copy of ${r.target === "session" ? "live entry" : "sample record"} #${r.index}: ${r.change}`)),
      h("dl", { class: "kv" },
        h("dt", {}, "Copy verifies"), h("dd", {}, pill(r.tampered_copy_valid ? "PASS" : "FAIL")),
        r.target === "sample" ? [h("dt", {}, "Recorded root"), h("dd", { class: "hash" }, short(r.recorded_root_hash, 24)),
          h("dt", {}, "Root of tampered copy"), h("dd", { class: "hash" }, short(r.tampered_root_hash, 24)),
          h("dt", {}, "Ed25519 on copy"), h("dd", {}, pill(r.signature.status === "unavailable" ? "N/A" : r.signature.status, r.signature.status === "unavailable" ? "neutral" : ""))] : null,
        h("dt", {}, "Original data"), h("dd", {}, pill(originalOk ? "UNCHANGED" : "CHECK", originalOk ? "pass" : "fail"),
          r.target === "session" ? " live chain still verifies" : " file hash identical before and after")),
      h("div", { class: "note" }, "Changing a single decision changes that entry's hash, so it no longer matches the next link (or the recorded root hash). Verification fails, which is how tampering is detected."),
    );
    box.hidden = false;
    loadStatus();
  } catch (e) { showError(err, e.message); box.hidden = true; }
});

// ------------------------------------------------------------------ attestation
async function loadAttestation() {
  let a;
  try { a = await api("/api/attestation"); } catch (e) { $("#contracts").replaceChildren(h("div", { class: "glass card form-error" }, e.message)); return; }
  $("#contracts").replaceChildren(...a.contracts.map((c) => h("div", { class: "glass card" },
    h("div", { class: "card-head" }, h("h2", {}, `${c.name}.compact`), pill(c.compiled ? "COMPILED" : "NOT COMPILED", c.compiled ? "pass" : "fail")),
    h("dl", { class: "kv" },
      h("dt", {}, "Source"), h("dd", {}, h("code", {}, c.source_file)),
      h("dt", {}, "Circuits"), h("dd", {}, c.circuits.length ? c.circuits.join(", ") : "—"),
      h("dt", {}, "Toolchain"), h("dd", {}, c.compiled ? `Compact ${c.compiler_version} · language ${c.language_version} · runtime ${c.runtime_version}` : `run ${c.compile_cmd}`),
      h("dt", {}, "ZK keys"), h("dd", {}, c.keys.length ? `${c.keys.length} files (prover + verifier)` : "—")),
    h("pre", { class: "code" }, c.source || "source not found"))));

  const r = a.recorded_simulation;
  $("#recorded-sim").replaceChildren(r ? h("div", { class: "stack" },
    h("div", { class: "muted small" }, `${r.file} · captured ${r.date || "unknown"} · exit code ${r.exit_code}`),
    h("ul", { class: "check-list" }, r.checks.map((c) => h("li", {}, pill(c.split(/\s+/)[0]), c.replace(/^\S+\s+/, ""))))) : h("div", { class: "empty" }, "No recorded evidence found."));
  $("#btn-simulate").disabled = !a.simulation_available;
  if (!a.simulation_available) showError($("#att-error"), "Simulation unavailable: Node.js/npm or node_modules not found (see web/README.md).");
}

$("#btn-export").addEventListener("click", async (ev) => {
  const err = $("#att-error"), box = $("#att-result");
  showError(err, "");
  try {
    const r = await busy(ev.currentTarget, () => api("/api/attestation/export", {}));
    fill(box, 
      h("div", { class: "result-head" }, pill(`${r.count} HASHES`, "pass"), h("span", {}, `${r.circuit}() keys for ${r.contract}`)),
      h("div", { class: "table-wrap" }, h("table", { class: "table compact" },
        h("thead", {}, h("tr", {}, h("th", {}, "Decision"), h("th", {}, "Bytes32 decision hash"))),
        h("tbody", {}, r.decisions.map((d) => h("tr", {}, h("td", {}, pill(d.decision)), h("td", { class: "hash" }, d.decision_hash)))))),
      h("dl", { class: "kv" }, h("dt", {}, "State commitment"), h("dd", { class: "hash" }, r.state_commitment),
        h("dt", {}, "Batch signature"), h("dd", {}, `${r.signature.alg} (key id ${r.signature.key_id})`)),
      h("div", { class: "note" }, r.note),
    );
    box.hidden = false;
  } catch (e) { showError(err, e.message); box.hidden = true; }
});

$("#btn-simulate").addEventListener("click", async (ev) => {
  const err = $("#att-error"), box = $("#att-result");
  showError(err, "");
  try {
    const r = await busy(ev.currentTarget, () => api("/api/attestation/simulate", {}));
    fill(box, 
      h("div", { class: "result-head" }, pill(r.exit_code === 0 ? "PASS" : "FAIL", "big-pill"),
        h("span", {}, `${r.passed} passed · ${r.failed} failed · ${r.hashes} live decision hashes`), h("span", { class: "tag local" }, "LOCAL COMPACT RUNTIME")),
      h("ul", { class: "check-list" }, r.checks.map((c) => h("li", {}, pill(c.split(/\s+/)[0]), c.replace(/^\S+\s+/, "")))),
      r.stderr ? h("pre", { class: "code" }, r.stderr) : null,
      h("div", { class: "note" }, "Executed by the Compact runtime on this machine. No network, wallet or transaction is involved; nothing was deployed."),
    );
    box.hidden = false;
    loadStatus();
  } catch (e) { showError(err, e.message); box.hidden = true; }
});

// ------------------------------------------------------------------ misc
$("#btn-reset").addEventListener("click", async () => {
  if (!confirm("Start a new live session? This clears the in-memory audit chain and counters. Files on disk are not touched.")) return;
  try {
    await api("/api/session/reset", {});
    ["#req-result", "#out-result", "#verify-result", "#tamper-result", "#att-result"].forEach((s) => { $(s).hidden = true; });
    await loadStatus(); await loadAuditTables();
  } catch (e) { alert(e.message); }
});

(async function init() {
  try { await initFirewall(); } catch (e) { showError($("#req-error"), e.message); }
  const start = (location.hash || "#overview").slice(1);
  showView(["overview", "firewall", "audit", "attestation"].includes(start) ? start : "overview");
  setInterval(() => api("/api/status").then(() => {}).catch(() => {}), 15000);
})();
