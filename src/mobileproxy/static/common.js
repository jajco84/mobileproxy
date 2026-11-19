"use strict";
// Shared helpers for the main UI (app.js) and the Repeater window (repeater.js).
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function api(method, url, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch(url, opt);
  const txt = await r.text();
  let data; try { data = txt ? JSON.parse(txt) : null; } catch { data = txt; }
  if (!r.ok) throw new Error((data && data.detail) ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : r.statusText);
  return data;
}
function toast(msg, err = false) {
  const t = $("#toast"); t.textContent = msg; t.className = "show" + (err ? " err" : "");
  clearTimeout(toast._t); toast._t = setTimeout(() => (t.className = ""), err ? 5000 : 2200);
}
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
const fmtSize = (n) => n == null ? "" : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} kB` : `${(n / 1048576).toFixed(1)} MB`;
const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString();
const globRx = (g) => new RegExp("^" + g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$");

function xmlPretty(t) {
  // indent elements; elements with only text stay on one line; returns null when the text is not XML
  const doc = new DOMParser().parseFromString(t, "application/xml");
  if (doc.getElementsByTagName("parsererror").length) return null;
  const ser = new XMLSerializer();
  const attrEsc = (v) => v.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");
  const attrs = (el) => [...el.attributes].map((a) => ` ${a.name}="${attrEsc(a.value)}"`).join("");
  const node = (n, ind) => {
    if (n.nodeType === 1) {
      const kids = [...n.childNodes].filter((k) => !(k.nodeType === 3 && !k.nodeValue.trim()));
      const open = `<${n.nodeName}${attrs(n)}`;
      if (!kids.length) return `${ind}${open}/>`;
      if (kids.length === 1 && (kids[0].nodeType === 3 || kids[0].nodeType === 4)) return `${ind}${open}>${ser.serializeToString(kids[0])}</${n.nodeName}>`;
      return `${ind}${open}>\n${kids.map((k) => node(k, ind + "  ")).filter(Boolean).join("\n")}\n${ind}</${n.nodeName}>`;
    }
    if (n.nodeType === 3) return ind + ser.serializeToString(n).trim();
    if (n.nodeType === 4) return `${ind}<![CDATA[${n.nodeValue}]]>`;
    if (n.nodeType === 8) return `${ind}<!--${n.nodeValue}-->`;
    if (n.nodeType === 7) return `${ind}<?${n.nodeName} ${n.nodeValue}?>`;
    return "";
  };
  const decl = t.startsWith("<?xml") ? t.slice(0, t.indexOf("?>") + 2) + "\n" : "";
  return decl + node(doc.documentElement, "");
}
function pretty(text, ctype = "") {
  if (text == null) return "";
  const t = text.trim();
  if (/json/i.test(ctype) || t.startsWith("{") || t.startsWith("[")) {
    try { return JSON.stringify(JSON.parse(t), null, 2); } catch { /* not json */ }
  }
  if (/xml|soap/i.test(ctype) || t.startsWith("<")) {
    const out = xmlPretty(t);
    if (out !== null) return out;
  }
  return text;
}
// ---- readable tree view of JSON / XML bodies ----
const TREE_MAX = 3 * 1024 * 1024;
function parseXml(t) {
  const doc = new DOMParser().parseFromString(t, "application/xml");
  return doc.getElementsByTagName("parsererror").length ? null : doc;
}
function nestedOf(s) {
  const t = s.trim();
  if (t.length < 2) return null;
  if ((t[0] === "{" && t.endsWith("}")) || (t[0] === "[" && t.endsWith("]"))) {
    try { const v = JSON.parse(t); if (v && typeof v === "object") return { kind: "json", v }; } catch { /* no */ }
  }
  if (t[0] === "<" && t.endsWith(">")) { const d = parseXml(t); if (d) return { kind: "xml", d }; }
  return null;
}
function nestedHtml(n) {
  const inner = n.kind === "json" ? jsonNode(n.v, null, 1) : xmlNode(n.d.documentElement, null, 1);
  return `<span class="badge info">nested ${n.kind.toUpperCase()}</span><div class="nested">${inner}</div>`;
}
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const dp = (p) => p ? ` data-path="${esc(p)}" title="Click to copy ${esc(p)}"` : "";
const jChild = (path, k) => path == null ? null : (/^[A-Za-z_$][\w$]*$/.test(k) ? `${path}.${k}` : `${path}['${k.replace(/'/g, "\\'")}']`);

function jsonScalar(v) {
  if (v === null) return '<span class="j-null">null</span>';
  if (typeof v === "string") {
    const n = v.length > 1 ? nestedOf(v) : null;
    return n ? nestedHtml(n) : `<span class="j-str">"${esc(v)}"</span>`;
  }
  if (typeof v === "number") return `<span class="j-num">${v}</span>`;
  if (typeof v === "boolean") return `<span class="j-bool">${v}</span>`;
  return esc(String(v));
}
function jsonNode(v, path, depth, label = "", comma = "") {
  const isArr = Array.isArray(v);
  if (v === null || typeof v !== "object") return `<div class="row">${label}${jsonScalar(v)}${comma}</div>`;
  const keys = isArr ? v.map((_, i) => i) : Object.keys(v);
  const [o, c] = isArr ? ["[", "]"] : ["{", "}"];
  if (!keys.length) return `<div class="row">${label}<span class="j-br">${o}${c}</span>${comma}</div>`;
  const open = depth < 4 || keys.length <= 30;
  const cnt = isArr ? plural(keys.length, "item", "items") : plural(keys.length, "key", "keys");
  let kids = "";
  keys.forEach((k, i) => {
    const cp = path == null ? null : (isArr ? `${path}[${k}]` : jChild(path, String(k)));
    const lab = isArr ? `<span class="j-idx"${dp(cp)}>${k}</span>: ` : `<span class="j-key"${dp(cp)}>"${esc(k)}"</span>: `;
    kids += jsonNode(v[k], cp, depth + 1, lab, i < keys.length - 1 ? "," : "");
  });
  return `<details${open ? " open" : ""}><summary data-close="${c}${comma}">${label}<span class="j-br">${o}</span><span class="cnt">${cnt}</span></summary>`
    + `<div class="kids">${kids}</div><div class="row"><span class="j-br">${c}</span>${comma}</div></details>`;
}

function xmlNode(el, path, depth) {
  const name = esc(el.nodeName);
  const attrs = [...el.attributes].map((a) => ` <span class="x-attr">${esc(a.name)}</span>=<span class="x-val">"${esc(a.value)}"</span>`).join("");
  const kids = [...el.childNodes].filter((n) => !(n.nodeType === 3 && !n.nodeValue.trim()));
  const openTag = `<span class="x-tag"${dp(path)}>&lt;${name}</span>${attrs}<span class="x-tag">&gt;</span>`;
  const close = `<span class="x-tag">&lt;/${name}&gt;</span>`;
  if (!kids.length) return `<div class="row"><span class="x-tag"${dp(path)}>&lt;${name}</span>${attrs}<span class="x-tag">/&gt;</span></div>`;
  if (kids.length === 1 && (kids[0].nodeType === 3 || kids[0].nodeType === 4)) {
    const txt = kids[0].nodeValue;
    const n = nestedOf(txt);
    if (!n) return `<div class="row">${openTag}<span class="x-txt">${esc(txt)}</span>${close}</div>`;
    return `<details open><summary data-close="${esc("</" + el.nodeName + ">")}">${openTag}</summary><div class="kids">${nestedHtml(n)}</div><div class="row">${close}</div></details>`;
  }
  const counts = {};
  kids.forEach((k) => { if (k.nodeType === 1) counts[k.localName] = (counts[k.localName] || 0) + 1; });
  const seen = {};
  let inner = "";
  for (const k of kids) {
    if (k.nodeType === 1) {
      seen[k.localName] = (seen[k.localName] || 0) + 1;
      const cp = path == null ? null : `${path}/*[local-name()='${k.localName}']${counts[k.localName] > 1 ? `[${seen[k.localName]}]` : ""}`;
      inner += xmlNode(k, cp, depth + 1);
    } else if (k.nodeType === 3 || k.nodeType === 4) {
      const n = nestedOf(k.nodeValue);
      inner += n ? nestedHtml(n) : `<div class="row x-txt">${esc(k.nodeValue.trim())}</div>`;
    } else if (k.nodeType === 8) {
      inner += `<div class="row x-com">&lt;!--${esc(k.nodeValue)}--&gt;</div>`;
    }
  }
  const elCount = Object.values(counts).reduce((a, b) => a + b, 0);
  const open = depth < 5 || elCount <= 30;
  return `<details${open ? " open" : ""}><summary data-close="${esc("</" + el.nodeName + ">")}">${openTag}<span class="cnt">${elCount || ""}</span></summary>`
    + `<div class="kids">${inner}</div><div class="row">${close}</div></details>`;
}

function renderBody(container, text, ctype = "", emptyText = "(no body)") {
  if (text == null || text === "") { container.innerHTML = `<span class="muted">${esc(emptyText)}</span>`; return; }
  const t = text.trim();
  if (text.length <= TREE_MAX) {
    if (t[0] === "{" || t[0] === "[") {
      try { container.innerHTML = jsonNode(JSON.parse(t), "$", 0); return; } catch { /* not json */ }
    }
    if (t[0] === "<") {
      const doc = parseXml(t);
      if (doc) {
        const decl = t.startsWith("<?xml") ? `<div class="row x-decl">${esc(t.slice(0, t.indexOf("?>") + 2))}</div>` : "";
        container.innerHTML = decl + xmlNode(doc.documentElement, `/*[local-name()='${doc.documentElement.localName}']`, 0);
        return;
      }
    }
  }
  container.innerHTML = `<pre>${esc(pretty(text, ctype))}</pre>`;
}
function onTreeClick(e) {
  const el = e.target.closest("[data-path]");
  if (!el) return;
  e.preventDefault();
  const p = el.dataset.path;
  (navigator.clipboard ? navigator.clipboard.writeText(p) : Promise.reject()).then(
    () => toast(`Copied: ${p}`), () => toast(p));
}

function validateBody(text, ctype = "") {
  const t = (text || "").trim();
  if (!t) return { cls: "", msg: "empty" };
  if (t[0] === "{" || t[0] === "[" || /json/i.test(ctype)) {
    try { JSON.parse(t); return { cls: "ok", msg: "✓ valid JSON" }; }
    catch (e) { return { cls: "bad", msg: "✗ JSON: " + e.message }; }
  }
  if (t[0] === "<") {
    const doc = new DOMParser().parseFromString(t, "application/xml");
    const err = doc.getElementsByTagName("parsererror")[0];
    if (!err) return { cls: "ok", msg: "✓ valid XML" };
    const line = (err.textContent || "").split("\n").map((x) => x.trim()).filter(Boolean)[1] || "invalid";
    return { cls: "bad", msg: "✗ XML: " + line };
  }
  return { cls: "", msg: "plain text" };
}
function showValidity(el, text, ctype) {
  const v = validateBody(text, ctype);
  el.className = "valid " + v.cls; el.textContent = v.msg; el.title = v.msg;
}

function kv(rows) { return rows.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join(""); }
