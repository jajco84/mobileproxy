"use strict";
// Repeater window: edit a captured request, send it again, inspect the response.

const rp = { original: null, attempts: [], current: null };

const headersToText = (rows) => (rows || []).map(([k, v]) => `${k}: ${v}`).join("\n");
const ctypeOfHeaders = (text) => {
  const m = /^\s*content-type\s*:\s*(.+)$/im.exec(text || "");
  return m ? m[1].trim() : "";
};

function setTabs(groupSel, attr, value) {
  $$(`${groupSel} button`).forEach((b) => b.classList.toggle("active", b.dataset.t === value));
  return value;
}

// ---- request side
let reqTab = "body";
function showReqTab(t) {
  reqTab = setTabs("#rp-req-tabs", "t", t);
  $("#rp-body").hidden = t !== "body";
  $("#rp-headers").hidden = t !== "headers";
  $$(".rp-body-only").forEach((e) => (e.hidden = t !== "body"));
  $$(".rp-headers-only").forEach((e) => (e.hidden = t !== "headers"));
}
$$("#rp-req-tabs button").forEach((b) => (b.onclick = () => showReqTab(b.dataset.t)));

function updateValidity() {
  const body = $("#rp-body").value;
  if (!body.trim()) { $("#rp-valid").textContent = ""; return; }
  showValidity($("#rp-valid"), body, ctypeOfHeaders($("#rp-headers").value));
}
$("#rp-body").addEventListener("input", debounce(updateValidity, 300));
$("#rp-format").onclick = () => { $("#rp-body").value = pretty($("#rp-body").value, ctypeOfHeaders($("#rp-headers").value)); updateValidity(); };

function loadRequest(d) {
  $("#rp-method").value = d.method;
  if ($("#rp-method").value !== d.method) {  // unusual method
    const o = document.createElement("option"); o.textContent = d.method; $("#rp-method").appendChild(o); $("#rp-method").value = d.method;
  }
  $("#rp-url").value = d.url;
  $("#rp-headers").value = headersToText(d.req_headers);
  $("#rp-body").value = d.req_body ? pretty(d.req_body, ctypeOfHeaders($("#rp-headers").value)) : "";
  $("#rp-origin").textContent = `Based on #${d.id} · ${d.server} · ${fmtTime(d.ts)}${d.soap_op ? " · SOAP " + d.soap_op : ""}${d.req_note ? " · " + d.req_note : ""}`;
  document.title = `Repeater – ${d.method} ${d.path}${d.soap_op ? " #" + d.soap_op : ""}`;
  updateValidity();
}
$("#rp-reset").onclick = () => { if (rp.original) { loadRequest(rp.original); toast("Request reset to #" + rp.original.id); } };

// ---- response side
let respTab = "view";
function showRespTab(t) {
  respTab = setTabs("#rp-resp-tabs", "t", t);
  $("#rp-view").hidden = t !== "view";
  $("#rp-raw").hidden = t !== "raw";
  $("#rp-resp-headers").hidden = t !== "headers";
}
$$("#rp-resp-tabs button").forEach((b) => (b.onclick = () => showRespTab(b.dataset.t)));

function renderResponse(a) {
  rp.current = a;
  const r = a.res;
  if (r.error) {
    $("#rp-status").innerHTML = `<span class="sterr">ERROR</span>`;
    $("#rp-meta").textContent = `${r.duration_ms} ms`;
    $("#rp-view").innerHTML = `<pre class="sterr">${esc(r.error)}</pre>`;
    $("#rp-raw").textContent = r.error;
    $("#rp-resp-headers table").innerHTML = "";
  } else {
    const cls = `st${String(r.status)[0]}`;
    $("#rp-status").innerHTML = `<span class="${cls} rp-code">${r.status} ${esc(r.reason || "")}</span>`;
    $("#rp-meta").textContent = `${r.duration_ms} ms · ${fmtSize(r.size)} · ${r.content_type || "no content-type"} · ${r.via_proxy ? "via MobileProxy" : "direct"}`;
    renderBody($("#rp-view"), r.body, r.content_type, r.body_note || "(empty body)");
    $("#rp-raw").textContent = r.body ?? (r.body_note || "");
    $("#rp-resp-headers table").innerHTML = kv(r.headers || []);
  }
  let b = "";
  if (r.mocked) b += '<span class="badge mock">MOCK</span>';
  if (r.modified) b += '<span class="badge mod">MOD</span>';
  for (const x of r.rules_applied || []) b += `<span class="badge info">rule: ${esc(x.name)}</span>`;
  $("#rp-badges").innerHTML = b;
  $("#rp-link").innerHTML = r.exchange_id ? `recorded as <a href="#" id="rp-open">#${r.exchange_id}</a> in the main window` : "";
  const ol = $("#rp-open");
  if (ol) ol.onclick = (e) => {
    e.preventDefault();
    if (window.opener && !window.opener.closed && window.opener.selectExchange) { window.opener.selectExchange(r.exchange_id); window.opener.focus(); }
    else window.open(`/?ex=${r.exchange_id}`, "_blank");
  };
}

function renderAttempts() {
  const sel = $("#rp-attempts");
  sel.hidden = rp.attempts.length < 2;
  sel.innerHTML = rp.attempts.map((a, i) => `<option value="${i}" ${a === rp.current ? "selected" : ""}>#${i + 1} · ${a.time} · ${a.req.method} · ${a.res.error ? "ERR" : a.res.status} · ${a.res.duration_ms} ms</option>`).join("");
}
$("#rp-attempts").onchange = (e) => {
  const a = rp.attempts[+e.target.value];
  renderResponse(a);
  // show the request that produced this response as well
  $("#rp-method").value = a.req.method; $("#rp-url").value = a.req.url; $("#rp-headers").value = a.req.headers_text; $("#rp-body").value = a.req.body || "";
  updateValidity();
};

async function send() {
  const req = {
    method: $("#rp-method").value, url: $("#rp-url").value.trim(), headers_text: $("#rp-headers").value,
    body: $("#rp-body").value === "" ? null : $("#rp-body").value, via_proxy: $("#rp-via").checked,
  };
  if (!/^https?:\/\//i.test(req.url)) return toast("URL must start with http:// or https://", true);
  const btn = $("#rp-send");
  btn.disabled = true; btn.textContent = "Sending…";
  $("#rp-status").innerHTML = '<span class="muted">…</span>';
  try {
    const res = await api("POST", "/api/replay", req);
    const a = { req, res, time: new Date().toLocaleTimeString() };
    rp.attempts.push(a);
    renderResponse(a);
    renderAttempts();
  } catch (e) { toast(e.message, true); $("#rp-status").textContent = ""; }
  finally { btn.disabled = false; btn.textContent = "Send"; }
}
$("#rp-send").onclick = send;
document.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); send(); } });
$$(".tree").forEach((t) => t.addEventListener("click", onTreeClick));

(async function init() {
  showReqTab("body"); showRespTab("view");
  const id = new URLSearchParams(location.search).get("id");
  if (!id) { $("#rp-origin").textContent = "Empty request – fill in method, URL, headers and body."; return; }
  try {
    rp.original = await api("GET", `/api/exchanges/${id}`);
    loadRequest(rp.original);
  } catch (e) { toast(`Cannot load #${id}: ${e.message}`, true); }
})();
