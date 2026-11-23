"use strict";

const state = {
  info: null, servers: [], server: null, view: "grouped", filter: "", category: "",
  selectedId: null, detail: null, rules: [], selectedRule: null, settings: null,
};

// ------------------------------------------------------------------ tabs
$$("nav button").forEach((b) => b.onclick = () => {
  $$("nav button").forEach((x) => x.classList.toggle("active", x === b));
  $$(".tab").forEach((t) => t.classList.toggle("active", t.id === "tab-" + b.dataset.tab));
  if (b.dataset.tab === "rules") loadRules();
  if (b.dataset.tab === "profiles") loadProfiles();
  if (b.dataset.tab === "setup") { loadSettings(); loadAdb(); loadIos(); }
});

// ------------------------------------------------------------------ info
async function loadInfo() {
  const i = state.info = await api("GET", "/api/info");
  $("#proxy-info").textContent = `proxy ${i.proxy_host}:${i.proxy_port} · emulator ${i.emulator_proxy}`;
  $("#s-proxy").textContent = `${i.proxy_host}:${i.proxy_port}`;
  $("#s-emu").textContent = i.emulator_proxy;
  $("#s-mcp").textContent = i.mcp_url;
  $("#s-mcp-cmd").textContent = `claude mcp add --transport http mobileproxy ${i.mcp_url}`;
  $("#s-mcp-json").textContent = JSON.stringify({ mcpServers: { mobileproxy: { type: "http", url: i.mcp_url } } }, null, 2);
  $("#prof-dir").textContent = i.data_dir + "/profiles";
}

// ------------------------------------------------------------------ servers
async function loadServers() {
  state.servers = await api("GET", "/api/servers");
  renderServers();
}
function renderServers() {
  const ul = $("#server-list");
  const total = state.servers.reduce((a, s) => a + s.count, 0);
  let html = `<li data-id="" class="${state.server ? "" : "active"}"><span class="cnt">${total}</span><div class="sname">All servers</div></li>`;
  for (const s of state.servers) {
    html += `<li data-id="${esc(s.id)}" class="${s.id === state.server ? "active" : ""} ${s.rules_enabled ? "" : "off"}">
      <span class="cnt">${s.count}</span><div class="sname">${esc(s.alias || s.host)}</div><div class="sid">${esc(s.scheme)}://${esc(s.id)}</div></li>`;
  }
  ul.innerHTML = html;
  $("#servers-empty").hidden = state.servers.length > 0;
  $$("li", ul).forEach((li) => li.onclick = () => { state.server = li.dataset.id || null; renderServers(); renderServerHead(); loadList(); });
}
function renderServerHead() {
  const el = $("#server-head");
  const s = state.servers.find((x) => x.id === state.server);
  if (!s) { el.innerHTML = ""; return; }
  el.innerHTML = `<b>${esc(s.alias || s.id)}</b>
    <button class="small" id="sh-alias">Alias…</button>
    <label class="switch"><input type="checkbox" id="sh-rules" ${s.rules_enabled ? "checked" : ""}> rules active</label>
    <button class="small" id="sh-clear">Clear history</button>
    <button class="small" id="sh-ignore" title="Stop intercepting this host (adds it to ignored hosts)">Ignore</button>
    <button class="small danger" id="sh-forget">Remove</button>`;
  $("#sh-alias").onclick = async () => {
    const a = prompt("Server alias (empty = none)", s.alias || ""); if (a === null) return;
    await api("PATCH", `/api/servers/${encodeURIComponent(s.id)}`, { alias: a }); await loadServers(); renderServerHead();
  };
  $("#sh-rules").onchange = async (e) => { await api("PATCH", `/api/servers/${encodeURIComponent(s.id)}`, { rules_enabled: e.target.checked }); loadServers(); };
  $("#sh-clear").onclick = async () => { await api("DELETE", `/api/exchanges?server=${encodeURIComponent(s.id)}`); loadServers(); loadList(); };
  $("#sh-ignore").onclick = async () => {
    if (!confirm(`Ignore ${s.id}? Its traffic will pass through without interception.`)) return;
    await api("POST", `/api/servers/${encodeURIComponent(s.id)}/ignore`); state.server = null; loadServers(); renderServerHead(); loadList();
  };
  $("#sh-forget").onclick = async () => { await api("DELETE", `/api/servers/${encodeURIComponent(s.id)}`); state.server = null; loadServers(); renderServerHead(); loadList(); };
}
$("#btn-clear-all").onclick = async () => { await api("DELETE", "/api/exchanges"); loadServers(); loadList(); };

// ------------------------------------------------------------------ list
function setView(v) {
  state.view = v;
  try { localStorage.setItem("mp.view", v); } catch { /* ignore */ }
  $$("[data-view]").forEach((x) => x.classList.toggle("active", x.dataset.view === v));
}
try { const v = localStorage.getItem("mp.view"); if (v === "grouped" || v === "timeline") state.view = v; } catch { /* ignore */ }
setView(state.view);
$$("[data-view]").forEach((b) => b.onclick = () => { setView(b.dataset.view); loadList(); });
state.search = { text: "", bodies: false, headers: false, regex: false, status: "", since: "", modified: false };
state.limit = 300;
function readSearch() {
  state.search = {
    text: $("#filter").value.trim(), bodies: $("#s-bodies").checked, headers: $("#s-headers").checked,
    regex: $("#s-regex").checked, status: $("#s-status").value, since: $("#s-since").value, modified: $("#s-modified").checked,
  };
  state.filter = state.search.text;
  state.limit = 300;
}
const onSearch = debounce(() => { readSearch(); loadList(); if (state.detail) applyHighlights(); }, 250);
$("#filter").oninput = onSearch;
["#s-bodies", "#s-headers", "#s-regex", "#s-status", "#s-since", "#s-modified"].forEach((id) => $(id).onchange = onSearch);
$("#s-clear").onclick = () => {
  $("#filter").value = ""; ["#s-bodies", "#s-headers", "#s-regex", "#s-modified"].forEach((id) => ($(id).checked = false));
  $("#s-status").value = ""; $("#s-since").value = ""; onSearch();
};
function searchParams() {
  const p = new URLSearchParams();
  const s = state.search;
  if (s.text) { p.set("text", s.text); if (s.regex) p.set("regex", "true"); }
  if (s.bodies) p.set("bodies", "true");
  if (s.headers) p.set("headers", "true");
  if (s.status) p.set("status", s.status);
  if (s.since) p.set("since", s.since);
  if (s.modified) p.set("modified", "true");
  return p;
}
function searchRx(global = true) {
  const s = state.search;
  if (!s.text) return null;
  try { return new RegExp(s.regex ? s.text : s.text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), global ? "gi" : "i"); }
  catch { return null; }
}
const markHtml = (raw) => {
  const rx = searchRx();
  if (!rx) return esc(raw);
  let out = "", last = 0, m;
  while ((m = rx.exec(raw)) && m[0] !== "") { out += esc(raw.slice(last, m.index)) + `<mark>${esc(m[0])}</mark>`; last = m.index + m[0].length; }
  return out + esc(raw.slice(last));
};
const snippetsHtml = (r) => (r.matches || []).map((m) => `<div class="snip"><span class="snip-f">${esc(m.field)}:</span> ${markHtml(m.snippet)}</div>`).join("");
try { state.category = localStorage.getItem("mp.category") || ""; } catch { /* storage unavailable */ }
function setCategory(c) {
  state.category = c;
  try { localStorage.setItem("mp.category", c); } catch { /* ignore */ }
  $$("#cat-filter button").forEach((b) => b.classList.toggle("active", b.dataset.cat === c));
}
$$("#cat-filter button").forEach((b) => b.onclick = () => { setCategory(b.dataset.cat); loadList(); });
setCategory(state.category);

const statusCell = (r) => {
  const st = r.error ? "ERR" : (r.status ?? "");
  const stc = r.error ? "sterr" : `st${String(r.status || "")[0] || ""}`;
  return `<td class="${stc}">${esc(st)}</td>`;
};
const badgesOf = (r) => (r.replay_id ? '<span class="badge replay" title="Sent from the Repeater">REPLAY</span>' : "") + (r.mocked ? '<span class="badge mock">MOCK</span>' : "") + (r.modified ? '<span class="badge mod">MOD</span>' : "");
const countOf = (r) => r.count > 1 ? `<span class="cnt-x" title="${r.count} calls">×${r.count}</span>` : "";
const variantLabel = (r, common) => {
  const parts = [];
  if (r.query) {
    let q = r.query;
    if (common && common.size) {
      const rest = [...new URLSearchParams(r.query)].filter(([k, v]) => !common.has(k + "=" + v)).map(([k, v]) => `${k}=${v}`);
      q = rest.join("&");
    }
    if (q) parts.push(`<span class="q">${common && common.size ? "" : "?"}${esc(q)}</span>`);
  }
  if (r.req_preview) parts.push(`<span class="vprev">${esc(r.req_preview)}</span>`);
  return parts.join(" ") || '<span class="muted">(no parameters)</span>';
};
function exRow(r, { full = true, server = false, common = null } = {}) {
  const srv = server ? `<span class="q">${esc(r.server)}</span> ` : "";
  const endpointCell = full
    ? `${srv}${esc(r.path)}${r.query ? `<span class="q">?${esc(r.query)}</span>` : ""}${r.soap_op ? ` <span class="soap">#${esc(r.soap_op)}</span>` : ""}${r.req_preview ? `<div class="preq" title="${esc(r.req_preview)}">${esc(r.req_preview)}</div>` : ""}${snippetsHtml(r)}`
    : `<div class="vlabel" title="${esc((r.query ? "?" + r.query + " " : "") + (r.req_preview || ""))}">${variantLabel(r, common)}</div>${snippetsHtml(r)}`;
  return `<tr data-id="${r.id}" class="${full ? "" : "var"} ${r.id === state.selectedId ? "sel" : ""}" title="${esc(r.error || "")}">
    <td class="muted cat-${esc(r.category || "other")}" title="${esc(r.category || "")}">${r.id}</td><td>${full ? esc(r.method) : ""}</td>
    <td>${endpointCell}</td>${statusCell(r)}<td class="muted">${r.duration_ms} ms</td><td class="muted">${fmtSize(r.resp_size)}</td><td>${countOf(r)}${badgesOf(r)}</td></tr>`;
}
const AUTO_COLLAPSE = 8;
state.toggled = new Set();
const isCollapsed = (key, n) => (n > AUTO_COLLAPSE) !== state.toggled.has(key);

async function loadList() {
  const p = searchParams();
  if (state.server) p.set("server", state.server);
  if (state.category) p.set("category", state.category);
  const tb = $("#ex-table tbody");
  const searching = !!(state.search.text || state.search.status || state.search.since || state.search.modified);
  let html = "", info = "";
  if (state.view === "grouped") {
    let rows;
    try { rows = await api("GET", "/api/endpoints?" + p); } catch (e) { $("#s-info").textContent = e.message; $("#s-info").className = "sterr small"; return; }
    if (searching) info = `${rows.length} matching variant${rows.length === 1 ? "" : "s"} (latest responses)`;
    const groups = new Map();
    for (const r of rows) {
      const key = r.server + " " + r.endpoint;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(r);
    }
    for (const [key, vs] of groups) {
      if (vs.length === 1) { html += exRow(vs[0], { server: !state.server }); continue; }
      const r0 = vs[0], calls = vs.reduce((a, v) => a + (v.count || 1), 0);
      const collapsed = searching ? state.toggled.has(key) : isCollapsed(key, vs.length);
      const errs = vs.filter((v) => v.error || (v.status || 0) >= 400).length;
      html += `<tr class="grp" data-g="${esc(key)}"><td class="cat-${esc(r0.category || "other")}"><span class="caret">${collapsed ? "▸" : "▾"}</span></td><td>${esc(r0.method)}</td>
        <td colspan="5">${state.server ? "" : `<span class="q">${esc(r0.server)}</span> `}${esc(r0.path)}${r0.soap_op ? ` <span class="soap">#${esc(r0.soap_op)}</span>` : ""}
        <span class="gmeta">${vs.length} variants · ${calls} calls${errs ? ` · <span class="sterr">${errs} failing</span>` : ""}</span></td></tr>`;
      if (!collapsed) {
        // query parameters identical in all variants are hidden; only the distinguishing ones are shown
        const sets = vs.map((v) => new Set([...new URLSearchParams(v.query || "")].map(([k, val]) => k + "=" + val)));
        const common = new Set([...sets[0]].filter((x) => sets.every((st) => st.has(x))));
        html += vs.map((v) => exRow(v, { full: false, common })).join("");
      }
    }
  } else {
    p.set("limit", String(state.limit));
    let res;
    try { res = await api("GET", "/api/search?" + p); } catch (e) { $("#s-info").textContent = e.message; $("#s-info").className = "sterr small"; return; }
    html = res.items.map((r) => exRow(r, { server: !state.server })).join("");
    if (res.next_before_id) html += `<tr class="more"><td colspan="7"><button id="btn-more" class="small">Show more (${res.total - res.items.length} older)</button></td></tr>`;
    if (searching) info = `${res.total} matching call${res.total === 1 ? "" : "s"}`;
  }
  $("#s-info").textContent = info; $("#s-info").className = "muted small";
  // invisible first row fixes the column widths (table-layout: fixed takes them from the first row)
  const sizer = '<tr class="sizer"><td></td><td></td><td></td><td></td><td></td><td></td><td></td></tr>';
  tb.innerHTML = sizer + (html || `<tr><td colspan="7" class="hint">${state.category ? `No ${state.category} requests here.` : "Nothing here yet."}</td></tr>`);
  $$("tr[data-id]", tb).forEach((tr) => tr.onclick = () => selectExchange(+tr.dataset.id));
  if ($("#btn-more")) $("#btn-more").onclick = () => { state.limit += 300; loadList(); };
  $$("tr.grp", tb).forEach((tr) => tr.onclick = () => {
    const k = tr.dataset.g;
    state.toggled.has(k) ? state.toggled.delete(k) : state.toggled.add(k);
    loadList();
  });
}
const loadListSoon = debounce(loadList, 300);
const loadServersSoon = debounce(loadServers, 500);

// ------------------------------------------------------------------ detail
$$("[data-dtab]").forEach((b) => b.onclick = () => {
  $$("[data-dtab]").forEach((x) => x.classList.toggle("active", x === b));
  $$(".dtab").forEach((t) => t.hidden = t.id !== "dtab-" + b.dataset.dtab);
});
$$(".tree").forEach((t) => t.addEventListener("click", onTreeClick));

// ---- highlight search matches inside rendered bodies ----
let findMarks = [], findIdx = -1;
function highlightIn(container) {
  const rx = searchRx();
  if (!rx || !container) return 0;
  const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  let n = 0;
  for (const node of nodes) {
    const t = node.nodeValue;
    rx.lastIndex = 0;
    if (!rx.test(t)) continue;
    rx.lastIndex = 0;
    const frag = document.createDocumentFragment();
    let last = 0, m;
    while ((m = rx.exec(t)) && m[0] !== "") {
      frag.appendChild(document.createTextNode(t.slice(last, m.index)));
      const mk = document.createElement("mark"); mk.textContent = m[0]; frag.appendChild(mk); n++;
      last = m.index + m[0].length;
    }
    frag.appendChild(document.createTextNode(t.slice(last)));
    node.parentNode.replaceChild(frag, node);
  }
  container.querySelectorAll("mark").forEach((mk) => { let d = mk.closest("details"); while (d) { d.open = true; d = d.parentElement.closest("details"); } });
  return n;
}
function applyHighlights() {
  const s = state.search;
  findMarks = []; findIdx = -1;
  if (!state.detail) return;
  // re-render to drop old marks, then mark again
  if (respMode === "view") renderBody($("#resp-view"), $("#ed-body").value, state.detail.resp_type, state.detail.resp_note || "(empty response)");
  renderBody($("#orig-body"), state.detail.modified ? state.detail.resp_body_original : null, state.detail.resp_type, "(response was not modified)");
  renderBody($("#req-body"), state.detail.req_body, "", state.detail.req_note || "(no body)");
  const active = s.text && (s.bodies || s.headers || true);
  if (!active) { $("#find-bar").hidden = true; return; }
  highlightIn($("#orig-body")); highlightIn($("#req-body"));
  const n = respMode === "view" ? highlightIn($("#resp-view")) : 0;
  findMarks = [...$("#resp-view").querySelectorAll("mark")];
  $("#find-bar").hidden = !n;
  if (n) gotoMark(0);
}
function gotoMark(i) {
  if (!findMarks.length) return;
  findIdx = (i + findMarks.length) % findMarks.length;
  findMarks.forEach((m, j) => m.classList.toggle("cur", j === findIdx));
  findMarks[findIdx].scrollIntoView({ block: "center" });
  $("#find-info").textContent = `${findIdx + 1} / ${findMarks.length}`;
}
$("#find-next").onclick = () => gotoMark(findIdx + 1);
$("#find-prev").onclick = () => gotoMark(findIdx - 1);

let respMode = "view";
try { respMode = localStorage.getItem("mp.respMode") || "view"; } catch { /* storage unavailable */ }
function setRespMode(m) {
  respMode = m;
  try { localStorage.setItem("mp.respMode", m); } catch { /* ignore */ }
  $$("#resp-mode button").forEach((b) => b.classList.toggle("active", b.dataset.mode === m));
  $("#dtab-resp").classList.toggle("mode-view", m === "view");
  $("#dtab-resp").classList.toggle("mode-edit", m === "edit");
  $("#resp-view").hidden = m !== "view";
  $("#ed-body").hidden = m !== "edit";
  if (m === "edit" && state.detail && state.detail.resp_body != null && $("#ed-body").value === state.detail.resp_body) {
    // untouched captured body -> show it human readable
    $("#ed-body").value = pretty(state.detail.resp_body, state.detail.resp_type);
  }
  if (m === "edit" && state.detail) showValidity($("#ed-valid"), $("#ed-body").value, state.detail.resp_type);
  if (m === "view" && state.detail) renderBody($("#resp-view"), $("#ed-body").value, state.detail.resp_type, state.detail.resp_note || "(empty response)");
  if (state.detail && state.search && state.search.text) applyHighlights();
  else $("#find-bar").hidden = true;
}
$$("#resp-mode button").forEach((b) => b.onclick = () => setRespMode(b.dataset.mode));
$("#btn-expand").onclick = () => $$("#resp-view details").forEach((d) => (d.open = true));
$("#btn-collapse").onclick = () => $$("#resp-view details").forEach((d, i) => (d.open = i === 0));
setRespMode(respMode);


async function loadVariantHistory(d) {
  const el = $("#d-history");
  el.innerHTML = "";
  if (!d.variant) return;
  let hist;
  try { hist = await api("GET", `/api/exchanges?server=${encodeURIComponent(d.server)}&variant=${encodeURIComponent(d.variant)}&limit=100`); }
  catch { return; }
  if (state.detail !== d || hist.length < 2) return;
  const opts = hist.map((h) => `<option value="${h.id}" ${h.id === d.id ? "selected" : ""}>#${h.id} · ${fmtTime(h.ts)} · ${h.error ? "ERR" : h.status}${h.modified ? " · MOD" : ""}${h.mocked ? " · MOCK" : ""}${h === hist[0] ? " (latest)" : ""}</option>`).join("");
  el.innerHTML = `<label>Same request called ${hist.length}× · response <select id="d-hist-sel">${opts}</select></label>`;
  $("#d-hist-sel").onchange = (e) => selectExchange(+e.target.value);
}

async function selectExchange(id) {
  state.selectedId = id;
  $$("#ex-table tbody tr").forEach((tr) => tr.classList.toggle("sel", +tr.dataset.id === id));
  let d;
  try { d = await api("GET", `/api/exchanges/${id}`); } catch (e) { toast(e.message, true); return; }
  state.detail = d;
  $("#detail-empty").hidden = true; $("#detail").hidden = false;
  $("#d-title").textContent = `${d.method} ${d.url}`;
  $("#d-meta").textContent = `#${d.id} · ${d.category || ""} · ${fmtTime(d.ts)} · ${d.server}${d.soap_op ? " · SOAP " + d.soap_op : ""} · ${d.duration_ms} ms · ${d.resp_type || ""}${d.correlation_id ? " · corr " + d.correlation_id : ""}`;
  let b = "";
  if (d.error) b += `<span class="badge err">${esc(d.error)}</span>`;
  if (d.replay_id) b += `<span class="badge replay">REPLAY</span>`;
  if (d.mocked) b += `<span class="badge mock">MOCK</span>`;
  if (d.modified) b += `<span class="badge mod">modified (originally ${d.status_original})</span>`;
  for (const r of d.rules_applied || []) b += `<span class="badge info">rule: ${esc(r.name)}</span>`;
  for (const e of d.rule_errors || []) b += `<div class="sterr small">${esc(e)}</div>`;
  $("#d-badges").innerHTML = b;
  $("#ed-status").value = d.status ?? "";
  $("#pin-query").checked = !!d.query;
  loadVariantHistory(d);
  const hasBody = !!d.req_body && !["GET", "HEAD"].includes(d.method);
  $("#pin-body-wrap").hidden = !hasBody;
  $("#pin-body").checked = hasBody;
  $("#ed-body").value = d.resp_body ?? "";
  $("#ed-body").disabled = d.resp_body == null;
  $("#resp-note").textContent = d.resp_note || "";
  renderBody($("#orig-body"), d.modified ? d.resp_body_original : null, d.resp_type, "(response was not modified)");
  $("#req-line").textContent = `${d.method} ${d.url}`;
  renderBody($("#req-body"), d.req_body, "", d.req_note || "(no body)");
  $("#req-headers").innerHTML = kv(d.req_headers || []);
  $("#resp-headers").innerHTML = kv(d.resp_headers || []);
  setRespMode(respMode);
}
$("#btn-format").onclick = () => { if (state.detail) { $("#ed-body").value = pretty($("#ed-body").value, state.detail.resp_type); showValidity($("#ed-valid"), $("#ed-body").value, state.detail.resp_type); } };
$("#btn-revert").onclick = () => {
  if (!state.detail) return;
  $("#ed-body").value = pretty(state.detail.resp_body ?? "", state.detail.resp_type);
  $("#ed-status").value = state.detail.status ?? "";
  showValidity($("#ed-valid"), $("#ed-body").value, state.detail.resp_type);
};
$("#ed-body").addEventListener("input", debounce(() => { if (state.detail) showValidity($("#ed-valid"), $("#ed-body").value, state.detail.resp_type); }, 300));
async function pin(mock) {
  const d = state.detail; if (!d) return;
  const times = parseInt($("#pin-times").value, 10);
  const status = parseInt($("#ed-status").value, 10);
  try {
    const r = await api("POST", "/api/rules/from-exchange", {
      exchange_id: d.id, body: $("#ed-body").disabled ? null : $("#ed-body").value,
      status: (status && status !== d.status) || mock ? status || null : null,
      mock, match_query: $("#pin-query").checked, remaining: Number.isFinite(times) ? times : null,
      match_body_exact: !$("#pin-body-wrap").hidden && $("#pin-body").checked,
    });
    toast(`Rule "${r.name}" created${mock ? " (mock)" : ""}. Applies from the next request.`);
    loadRules();
  } catch (e) { toast(e.message, true); }
}
$("#btn-pin").onclick = () => pin(false);
$("#btn-repeater").onclick = () => {
  if (!state.detail) return;
  window.open(`/repeater?id=${state.detail.id}`, `repeater-${state.detail.id}`, "width=1280,height=820");
};
$("#btn-mock").onclick = () => pin(true);

// ------------------------------------------------------------------ rules
function ruleCond(r) {
  const m = r.match || {};
  const short = (x, n = 50) => { x = String(x); return x.length > n ? x.slice(0, n) + "…" : x; };
  const body = [];
  if (m.body_equals != null) body.push(`body=${short(m.body_equals)}`);
  if (m.body_contains) body.push(`body∋"${short(m.body_contains)}"`);
  if (m.body_regex) body.push(`body~/${short(m.body_regex)}/`);
  for (const [k, v] of Object.entries(m.body_json || {})) body.push(`${k}${v === null ? " exists" : "=" + short(JSON.stringify(v), 30)}`);
  for (const [k, v] of Object.entries(m.body_xpath || {})) body.push(`${short(k, 40)}${v === null ? " exists" : "=" + short(v, 30)}`);
  return [m.method, (m.server && m.server !== "*") ? m.server : "*", m.path, m.query != null ? "?" + m.query : "", m.soap_op ? "#" + m.soap_op : "", ...body].filter(Boolean).join(" ");
}
function ruleAction(r) {
  let a = r.action;
  if (r.action === "replace") a += r.body != null ? ` (${fmtSize(new Blob([r.body]).size)})` : "";
  if (r.action === "patch") a += ` ×${(r.patches || []).length}`;
  if (r.status) a += ` → ${r.status}`;
  if (r.mock) a += " · mock";
  if (r.delay_ms) a += ` · +${r.delay_ms} ms`;
  return a;
}
async function loadRules() {
  state.rules = await api("GET", "/api/rules");
  const active = state.rules.filter((r) => r.enabled).length;
  $("#rules-count").textContent = state.rules.length ? `${active}/${state.rules.length}` : "";
  const tb = $("#rules-table tbody");
  tb.innerHTML = state.rules.map((r) => `<tr data-id="${r.id}" class="${r.enabled ? "" : "disabled"} ${r.id === state.selectedRule ? "sel" : ""}">
    <td><input type="checkbox" data-act="toggle" ${r.enabled ? "checked" : ""}></td>
    <td>${esc(r.name || r.id)}</td><td class="cond">${esc(ruleCond(r))}</td><td>${esc(ruleAction(r))}</td>
    <td>${r.hits}${r.remaining != null ? ` <span class="muted">(${r.remaining} left)</span>` : ""}</td>
    <td style="white-space:nowrap"><button class="small" data-act="up">↑</button><button class="small" data-act="down">↓</button>
      <button class="small" data-act="edit">Edit</button><button class="small danger" data-act="del">✕</button></td></tr>`).join("")
    || `<tr><td colspan="6" class="hint">No rules. Create one with Pin in the response detail, from a template above, or via MCP.</td></tr>`;
  $$("tr[data-id]", tb).forEach((tr) => {
    const id = tr.dataset.id;
    tr.onclick = async (e) => {
      const act = e.target.dataset.act;
      try {
        if (act === "toggle") { await api("POST", `/api/rules/${id}/toggle`); return loadRules(); }
        if (act === "up" || act === "down") { await api("POST", `/api/rules/${id}/move?delta=${act === "up" ? -1 : 1}`); return loadRules(); }
        if (act === "del") { if (confirm("Delete this rule?")) { await api("DELETE", `/api/rules/${id}`); if (state.selectedRule === id) editRule(null); } return loadRules(); }
        editRule(state.rules.find((r) => r.id === id));
      } catch (err) { toast(err.message, true); }
    };
  });
}
const ruleCtype = (r) => Object.entries((r && r.headers) || {}).find(([k]) => k.toLowerCase() === "content-type")?.[1] || "";
function toggleRuleBody(action) {
  const show = action === "replace";
  $("#rule-body-sec").hidden = !show;
  $(".rules-right").classList.toggle("has-body", show);
}
function editRule(r) {
  state.selectedRule = r ? r.id : null;
  $("#rule-edit-id").textContent = r ? (r.id ? `#${r.id}` : "(new)") : "";
  if (!r) { $("#rule-json").value = ""; $("#rule-body").value = ""; toggleRuleBody(null); return; }
  const copy = { ...r }; delete copy.hits; delete copy.created;
  const body = copy.body; delete copy.body;
  // hide empty fields (null / empty list) – the server fills in defaults when saving
  const prune = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== null && !(Array.isArray(v) && !v.length)));
  Object.assign(copy, prune(copy));
  for (const k of Object.keys(copy)) if (copy[k] === null || (Array.isArray(copy[k]) && !copy[k].length)) delete copy[k];
  if (copy.match) copy.match = prune(copy.match);
  if (Array.isArray(copy.patches)) copy.patches = copy.patches.map(prune);
  if (!copy.note) delete copy.note;
  $("#rule-body").value = pretty(body ?? "", ruleCtype(copy));
  showValidity($("#rule-body-valid"), $("#rule-body").value, ruleCtype(copy));
  toggleRuleBody(copy.action);
  $("#rule-json").value = JSON.stringify(copy, null, 2);
  $("#rule-preview").hidden = true; $("#rule-msg").textContent = "";
  $$("#rules-table tbody tr").forEach((tr) => tr.classList.toggle("sel", tr.dataset.id === state.selectedRule));
}
$("#rule-json").addEventListener("input", debounce(() => {
  try { const r = JSON.parse($("#rule-json").value); toggleRuleBody(r.action); } catch { /* keep current layout while typing */ }
}, 300));
$("#rule-body").addEventListener("input", debounce(() => {
  let ct = ""; try { ct = ruleCtype(JSON.parse($("#rule-json").value)); } catch { /* ignore */ }
  showValidity($("#rule-body-valid"), $("#rule-body").value, ct);
}, 300));
$("#btn-rule-format").onclick = () => {
  let ct = ""; try { ct = ruleCtype(JSON.parse($("#rule-json").value)); } catch { /* ignore */ }
  $("#rule-body").value = pretty($("#rule-body").value, ct);
  showValidity($("#rule-body-valid"), $("#rule-body").value, ct);
};
const TEMPLATES = {
  "replace": { name: "replace response", match: { server: "*", method: "GET", path: "/path" }, action: "replace", status: 200, body: "{}", mock: false },
  "patch-json": { name: "patch JSON", match: { server: "*", path: "/path" }, action: "patch", patches: [{ type: "jsonpath", path: "$.items[0].name", op: "set", value: "TEST" }] },
  "patch-xml": { name: "patch SOAP", match: { server: "*", path: "/StatusService", soap_op: "operation" }, action: "patch", patches: [{ type: "xpath", path: "//*[local-name()='element']", op: "set", value: "TEST" }] },
  "post-json": { name: "mock by POST body (JSON)", match: { server: "*", method: "POST", path: "/path", body_json: { "$.id": 12 } }, action: "replace", mock: true, status: 200, headers: { "Content-Type": "application/json" }, body: "{}" },
  "post-soap": { name: "mock by SOAP request content", match: { server: "*", path: "/StatusService", soap_op: "operation", body_xpath: { "//*[local-name()='id']": "12" } }, action: "replace", mock: true, status: 200, headers: { "Content-Type": "text/xml; charset=utf-8" }, body: "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body></soap:Body></soap:Envelope>" },
  "patch-regex": { name: "patch regex", match: { server: "*", path: "*" }, action: "patch", patches: [{ type: "regex", pattern: "\"visible\":true", replacement: "\"visible\":false" }] },
  "error": { name: "error 500", match: { server: "*", path: "/path" }, action: "replace", status: 500, body: "Internal Server Error", mock: true, headers: { "Content-Type": "text/plain" } },
  "delay": { name: "delay 5 s", match: { server: "*", path: "*" }, action: "delay", delay_ms: 5000 },
  "drop": { name: "drop connection", match: { server: "*", path: "/path" }, action: "drop", mock: true },
};
$("#btn-new-rule").onclick = () => {
  const t = structuredClone(TEMPLATES[$("#rule-template").value]);
  if (state.server) t.match.server = state.server;
  editRule({ id: "", enabled: true, ...t });
};
$("#btn-save-rule").onclick = async () => {
  let r; try { r = JSON.parse($("#rule-json").value); } catch (e) { return toast("Invalid rule settings JSON: " + e.message, true); }
  if (r.action === "replace" && !$("#rule-body-sec").hidden) r.body = $("#rule-body").value;
  try {
    const saved = state.selectedRule ? await api("PUT", `/api/rules/${state.selectedRule}`, r) : await api("POST", "/api/rules?first=true", r);
    toast("Saved"); await loadRules(); editRule(saved);
  } catch (e) { toast(e.message, true); }
};
$("#btn-preview-rule").onclick = async () => {
  let r; try { r = JSON.parse($("#rule-json").value); } catch (e) { return toast("Invalid JSON", true); }
  if (!r.patches || !r.patches.length) return toast("The rule has no patches", true);
  const m = r.match || {};
  const exs = await api("GET", "/api/exchanges?limit=500");
  const pathRx = globRx(m.path || "*"), srvRx = globRx(m.server || "*");
  const hit = exs.find((e) => srvRx.test(e.server) && pathRx.test(e.path) && (!m.method || e.method === m.method.toUpperCase())
    && (!m.soap_op || globRx(m.soap_op).test(e.soap_op || "")));
  if (!hit) return toast("No captured response matches the rule", true);
  try {
    const res = await api("POST", "/api/patch-preview", { exchange_id: hit.id, patches: r.patches });
    $("#rule-preview").hidden = false;
    $("#rule-preview").textContent = `On response #${hit.id} ${hit.endpoint}${res.errors.length ? "\nERRORS:\n" + res.errors.join("\n") : ""}\n\n` + pretty(res.body);
  } catch (e) { toast(e.message, true); }
};
$("#btn-clear-rules").onclick = async () => { if (confirm("Delete all rules?")) { await api("DELETE", "/api/rules"); editRule(null); loadRules(); } };

// ------------------------------------------------------------------ profiles
async function loadProfiles() {
  const ps = await api("GET", "/api/profiles");
  $("#profiles-table tbody").innerHTML = ps.map((p) => `<tr data-name="${esc(p.name)}"><td><b>${esc(p.name)}</b></td><td>${esc(p.description)}</td><td>${p.rules}</td>
    <td style="white-space:nowrap"><button class="small primary" data-act="replace">Load</button> <button class="small" data-act="merge">Add to current</button>
    <button class="small danger" data-act="del">✕</button></td></tr>`).join("") || `<tr><td colspan="4" class="hint">No profiles.</td></tr>`;
  $$("#profiles-table tr[data-name]").forEach((tr) => tr.onclick = async (e) => {
    const act = e.target.dataset.act, name = tr.dataset.name; if (!act) return;
    try {
      if (act === "del") { if (!confirm(`Delete profile ${name}?`)) return; await api("DELETE", `/api/profiles/${encodeURIComponent(name)}`); }
      else { const r = await api("POST", `/api/profiles/${encodeURIComponent(name)}/load?mode=${act}`); toast(`Loaded ${r.rules} rules`); loadRules(); }
      loadProfiles();
    } catch (err) { toast(err.message, true); }
  });
}
$("#btn-save-profile").onclick = async () => {
  const name = $("#prof-name").value.trim(); if (!name) return toast("Enter a name", true);
  const r = await api("POST", "/api/profiles", { name, description: $("#prof-desc").value });
  toast(`Saved ${r.rules} rules to ${r.file}`); loadProfiles();
};

// ------------------------------------------------------------------ settings
async function loadSettings() {
  const s = state.settings = await api("GET", "/api/settings");
  $("#set-strip-cache").checked = s.strip_cache_headers;
  $("#set-max-ex").value = s.max_exchanges_per_server;
  $("#set-package").value = s.app_package;
  $("#set-ignore").value = s.ignore_hosts.join("\n");
  if (document.activeElement !== $("#set-categories")) $("#set-categories").value = categoriesToText(s.category_rules);
  if (document.activeElement !== $("#sp-hosts")) $("#sp-hosts").value = (s.system_proxy_hosts || []).join("\n");
  $("#sp-include-seen").checked = !!s.system_proxy_include_seen;
  $("#set-default-cat").value = s.default_category || "other";
  $("#rules-paused").checked = s.rules_paused;
}
$("#btn-save-settings").onclick = async () => {
  try {
    await api("PUT", "/api/settings", {
      strip_cache_headers: $("#set-strip-cache").checked, max_exchanges_per_server: +$("#set-max-ex").value || 300,
      app_package: $("#set-package").value.trim(), ignore_hosts: $("#set-ignore").value.split("\n").map((x) => x.trim()).filter(Boolean),
    });
    toast("Settings saved"); loadSettings();
  } catch (e) { toast(e.message, true); }
};
function categoriesToText(rules) {
  // one rule per line keeps the list readable; empty/null fields are dropped
  return "[\n" + rules.map((r) => "  " + JSON.stringify(Object.fromEntries(Object.entries(r).filter(([, v]) => v !== null && v !== "")))).join(",\n") + "\n]";
}
$("#btn-save-categories").onclick = async () => {
  let rules; try { rules = JSON.parse($("#set-categories").value); } catch (e) { return toast("Invalid JSON: " + e.message, true); }
  if (!Array.isArray(rules)) return toast("Expected a JSON array of rules", true);
  const bad = rules.find((r) => !["metadata", "data", "other"].includes(r.category));
  if (bad) return toast(`Invalid category in ${JSON.stringify(bad)} (use metadata / data / other)`, true);
  try {
    await api("PUT", "/api/settings", { category_rules: rules, default_category: $("#set-default-cat").value });
    toast("Categories saved – existing requests were re-classified"); $("#set-categories").blur(); loadSettings(); loadList();
  } catch (e) { toast(e.message, true); }
};
$("#btn-reset-categories").onclick = async () => {
  if (!confirm("Replace the category rules with the defaults?")) return;
  const defs = await api("GET", "/api/settings/default-categories");
  $("#set-categories").value = categoriesToText(defs);
  toast("Defaults loaded – press Save categories to apply");
};
$("#rules-paused").onchange = async (e) => { await api("PUT", "/api/settings", { rules_paused: e.target.checked }); toast(e.target.checked ? "Rules paused" : "Rules active"); };

async function loadAdb() {
  const tb = $("#adb-table tbody"); tb.innerHTML = `<tr><td colspan="3" class="hint">Loading…</td></tr>`;
  const d = await api("GET", "/api/adb/devices");
  $("#adb-path").textContent = d.adb ? `adb: ${d.adb}` : "adb not found";
  if (d.error) { tb.innerHTML = `<tr><td colspan="3" class="sterr">${esc(d.error)}</td></tr>`; return; }
  tb.innerHTML = d.devices.map((x) => `<tr data-serial="${esc(x.serial)}"><td><b>${esc(x.serial)}</b> ${esc(x.model)} <span class="muted">${esc(x.state)}</span></td>
    <td class="mono">${esc(["", ":0", "null", undefined].includes(x.http_proxy) ? "none" : x.http_proxy)}</td>
    <td style="white-space:nowrap"><button class="small primary" data-act="proxy-on">Proxy on</button> <button class="small" data-act="proxy-off">Proxy off</button>
    <button class="small" data-act="push-ca">Push CA</button> <button class="small" data-act="restart-app">Restart app</button>
    <button class="small danger" data-act="clear-app">Clear app data</button></td></tr>`).join("") || `<tr><td colspan="3" class="hint">No device. Start an emulator.</td></tr>`;
  $$("#adb-table tr[data-serial]").forEach((tr) => tr.onclick = async (e) => {
    const act = e.target.dataset.act; if (!act) return;
    if (act === "clear-app" && !confirm("Clear all app data (login, offline data)?")) return;
    try {
      const r = await api("POST", `/api/adb/${encodeURIComponent(tr.dataset.serial)}/${act}`);
      $("#adb-msg").hidden = false; $("#adb-msg").textContent = r.message; loadAdb(); loadEmu();
    } catch (err) { toast(err.message, true); }
  });
}
$("#btn-adb-refresh").onclick = loadAdb;

// ------------------------------------------------------------------ emulator proxy indicator (header)
let emuBusy = false;
function renderEmu(st) {
  const el = $("#emu-state");
  const emus = (st.devices || []).filter((d) => d.emulator && d.state === "device");
  if (!st.adb || st.error || !emus.length) { el.hidden = true; return; }
  const bad = emus.filter((d) => !d.ok);
  const list = emus.map((d) => `${d.serial}${d.model ? " (" + d.model + ")" : ""}: ${d.proxy || "no proxy"}${d.ok ? " ✓" : " → should be " + d.expected}`).join("\n");
  el.hidden = false;
  el.title = list;
  if (bad.length) {
    const other = bad.filter((d) => d.proxy);
    const msg = bad.length === emus.length
      ? (other.length ? `⚠ Emulator uses a different proxy (${esc(other[0].proxy)})` : "⚠ Emulator proxy is not set")
      : `⚠ ${bad.length} of ${emus.length} emulators without proxy`;
    el.className = "emu warn";
    el.innerHTML = `<span>${msg}</span><button id="emu-set">Set proxy</button>`;
    $("#emu-set").onclick = () => emuSetAll(true);
  } else {
    el.className = "emu ok";
    el.innerHTML = `<span>✓ ${emus.length > 1 ? emus.length + " emulators" : "Emulator"} using proxy</span><button id="emu-off" title="Switch emulators back to a direct connection (needed when MobileProxy is not running)">Turn off</button>`;
    $("#emu-off").onclick = () => emuSetAll(false);
  }
}
async function loadEmu() {
  if (emuBusy || document.hidden) return;
  try { renderEmu(await api("GET", "/api/adb/status")); } catch { /* adb not available */ }
}
async function emuSetAll(enable) {
  emuBusy = true;
  try {
    const r = await api("POST", `/api/adb/all/proxy?enable=${enable}`);
    renderEmu(r);
    const failed = r.results.filter((x) => x.error);
    if (failed.length) { toast(failed.map((x) => x.message).join(" | "), true); return; }
    toast(enable ?`Proxy set on ${r.results.length} emulator(s). Restart the app if needed.` : "Proxy turned off in emulators");
  } catch (e) { toast(e.message, true); }
  finally { emuBusy = false; }
}
setInterval(loadEmu, 5000);
document.addEventListener("visibilitychange", loadEmu);

// ------------------------------------------------------------------ iOS Simulator / macOS system proxy
let iosBusy = false, iosStatus = null;
function renderIos(st) {
  iosStatus = st;
  const el = $("#ios-state");
  const sp = st.system_proxy || {}, sims = (st.simulators && st.simulators.devices) || [];
  const caMissing = sims.filter((d) => d.ca_installed === false).length;
  // header chip: only when it matters (simulator running or proxy switched on)
  if (!sp.supported || (!sims.length && !sp.enabled)) { el.hidden = true; }
  else {
    el.hidden = false;
    el.title = sims.map((d) => `${d.name} (${d.runtime}) – CA ${d.ca_installed === true ? "installed" : d.ca_installed === false ? "missing" : "unknown"}`).join("\n")
      + `\nPAC hosts: ${(sp.hosts || []).join(", ") || "(none)"}`;
    const caBtn = caMissing ? '<button id="ios-chip-ca" title="Needed for HTTPS">Install CA</button>' : "";
    if (sp.enabled && sp.effective_ok) {
      el.className = "emu ok";
      el.innerHTML = `<span>✓ iOS Simulator via system proxy${sp.stale ? " (hosts changed)" : ""}</span>${sp.stale ? '<button id="ios-chip-apply">Apply</button>' : ""}${caBtn}<button id="ios-chip-off" title="Restore the original macOS proxy settings">Turn off</button>`;
    } else if (sp.enabled) {
      el.className = "emu warn";
      el.innerHTML = `<span>⚠ macOS proxy overridden (VPN?)</span><button id="ios-chip-apply">Re-apply</button><button id="ios-chip-off">Turn off</button>`;
    } else {
      el.className = "emu warn";
      el.innerHTML = `<span>⚠ iOS Simulator not using the proxy</span><button id="ios-chip-on">Set system proxy</button>${caBtn}`;
    }
    const on = $("#ios-chip-on"), off = $("#ios-chip-off"), ap = $("#ios-chip-apply"), ca = $("#ios-chip-ca");
    if (on) on.onclick = () => setSystemProxy(true);
    if (ap) ap.onclick = () => setSystemProxy(true);
    if (off) off.onclick = () => setSystemProxy(false);
    if (ca) ca.onclick = () => iosAction("install-ca");
  }
  // settings card
  $("#ios-unsupported").hidden = !!sp.supported;
  $("#ios-body").hidden = !sp.supported;
  if (!sp.supported) return;
  $("#sp-state").textContent = !sp.enabled ? "off" : sp.effective_ok ? `on (PAC, ${sp.hosts.length} host${sp.hosts.length === 1 ? "" : "s"})${sp.stale ? " – hosts changed, apply to reload" : ""}` : "set, but macOS uses a different proxy configuration (VPN client?)";
  $("#sp-state").className = sp.enabled && sp.effective_ok ? "st2" : sp.enabled ? "sterr" : "muted";
  $("#sp-enable").hidden = !!sp.enabled; $("#sp-apply").hidden = !sp.enabled; $("#sp-disable").hidden = !sp.enabled;
  $("#sp-effective-hosts").textContent = (sp.hosts || []).join(", ") || "(none – add hosts above)";
  if (document.activeElement !== $("#ios-bundle")) $("#ios-bundle").value = st.bundle_id || "";
  $("#ios-table tbody").innerHTML = sims.map((d) => `<tr><td><b>${esc(d.name)}</b> <span class="muted mono small">${esc(d.udid)}</span></td><td>${esc(d.runtime)}</td>
    <td>${d.ca_installed === true ? '<span class="st2">✓ installed</span>' : d.ca_installed === false ? '<span class="sterr">missing</span>' : '<span class="muted">unknown</span>'}</td></tr>`).join("")
    || `<tr><td colspan="3" class="hint">${st.simulators && st.simulators.error ? esc(st.simulators.error) : "No booted simulator."}</td></tr>`;
}
async function loadIos() {
  if (iosBusy || document.hidden || !(state.info && state.info.is_mac)) { if (state.info && !state.info.is_mac) renderIos({ system_proxy: { supported: false } }); return; }
  try { renderIos(await api("GET", "/api/macos/status")); } catch { /* ignore */ }
}
async function setSystemProxy(enable) {
  iosBusy = true;
  try {
    const r = await api("POST", `/api/macos/system-proxy?enable=${enable}`);
    toast(enable ? (r.status.effective_ok ? "System proxy on – the iOS Simulator now goes through MobileProxy" : "Set, but macOS reports a different proxy config (VPN?)") : "macOS proxy settings restored", enable && !r.status.effective_ok);
    if (r.notes && r.notes.length) { $("#ios-msg").hidden = false; $("#ios-msg").textContent = r.notes.join("\n"); }
  } catch (e) { toast(e.message, true); }
  finally { iosBusy = false; loadIos(); }
}
async function iosAction(action) {
  iosBusy = true;
  try {
    const r = await api("POST", `/api/macos/sim/${action}`);
    $("#ios-msg").hidden = false; $("#ios-msg").textContent = r.results.map((x) => `${x.name}: ${x.message}`).join("\n");
    toast(action === "install-ca" ? "CA installed – restart the app if it was running" : "App restarted");
  } catch (e) { toast(e.message, true); }
  finally { iosBusy = false; loadIos(); }
}
$("#sp-enable").onclick = () => setSystemProxy(true);
$("#sp-apply").onclick = () => setSystemProxy(true);
$("#sp-disable").onclick = () => setSystemProxy(false);
$("#ios-install-ca").onclick = () => iosAction("install-ca");
$("#ios-restart").onclick = async () => {
  await api("PUT", "/api/settings", { ios_bundle_id: $("#ios-bundle").value.trim() });
  iosAction("restart-app");
};
$("#sp-save").onclick = async () => {
  try {
    await api("PUT", "/api/settings", {
      system_proxy_hosts: $("#sp-hosts").value.split("\n").map((x) => x.trim()).filter(Boolean),
      system_proxy_include_seen: $("#sp-include-seen").checked,
      ios_bundle_id: $("#ios-bundle").value.trim(),
    });
    if (iosStatus && iosStatus.system_proxy && iosStatus.system_proxy.enabled) await setSystemProxy(true);
    else { toast("Hosts saved"); loadIos(); }
  } catch (e) { toast(e.message, true); }
};
setInterval(loadIos, 5000);
document.addEventListener("visibilitychange", loadIos);

// ------------------------------------------------------------------ live
function connectWs() {
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/ws`);
  ws.onopen = () => $("#ws-state").classList.add("on");
  ws.onclose = () => { $("#ws-state").classList.remove("on"); setTimeout(connectWs, 1500); };
  ws.onmessage = (m) => {
    const ev = JSON.parse(m.data);
    if (ev.type === "exchange") {
      loadServersSoon();
      if ($("#autoscroll").checked && (!state.server || ev.exchange.server === state.server)) loadListSoon();
    } else if (ev.type === "server" || ev.type === "cleared") { loadServersSoon(); if (ev.type === "cleared") loadListSoon(); }
    else if (ev.type === "rules") { loadRulesSoon(); }
    else if (ev.type === "settings") { loadSettings(); }
    else if (ev.type === "system_proxy") { loadIos(); }
    else if (ev.type === "profiles" && $("#tab-profiles").classList.contains("active")) loadProfiles();
  };
}
const loadRulesSoon = debounce(loadRules, 300);

(async function init() {
  try {
    await loadInfo(); await loadServers(); await loadList(); await loadRules(); await loadSettings();
  } catch (e) { toast(e.message, true); }
  connectWs();
  const deep = new URLSearchParams(location.search).get("ex");  // /?ex=123 opens an exchange (link from the Repeater)
  if (deep) selectExchange(+deep);
  loadEmu();
  loadIos();
})();
