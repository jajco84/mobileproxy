"""mitmproxy addon: records traffic into the Store and applies rules."""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Optional
from urllib.parse import urlsplit

from mitmproxy import http

import hashlib

from .rules import RequestBody, Rule, apply_patches, normalize_body, rule_matches
from .store import Store, endpoint_key, variant_key

log = logging.getLogger("mobileproxy")

TEXT_TYPES = ("text/", "json", "xml", "javascript", "x-www-form-urlencoded", "soap", "yaml", "csv", "html")
CONDITIONAL_HEADERS = ("If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since", "If-Range")

_SOAP_BODY_RX = re.compile(r"<(?:[\w.-]+:)?Body\b[^>]*>\s*<(?:[\w.-]+:)?([\w.-]+)", re.S)
_CT_ACTION_RX = re.compile(r'action="?([^";]+)', re.I)


def detect_soap_op(headers, body: Optional[str]) -> Optional[str]:
    sa = headers.get("SOAPAction")
    if sa:
        sa = sa.strip().strip('"').rstrip("/")
        if sa:
            return re.split(r"[/#]", sa)[-1] or None
    m = _CT_ACTION_RX.search(headers.get("content-type", ""))
    if m:
        return re.split(r"[/#]", m.group(1).rstrip("/"))[-1] or None
    if body and "Envelope" in body[:4000]:
        m = _SOAP_BODY_RX.search(body[:20000])
        if m:
            return m.group(1)
    return None


BODY_METHODS = ("POST", "PUT", "PATCH", "DELETE")
_SOAP_INNER_RX = re.compile(r"<(?:[\w.-]+:)?Body\b[^>]*>(.*)</(?:[\w.-]+:)?Body\s*>", re.S)


def body_signature(method: str, text: Optional[str]) -> str:
    """Short hash of the normalized request body; requests with different bodies are different endpoints."""
    if method.upper() not in BODY_METHODS or not text:
        return ""
    norm = normalize_body(text)
    return hashlib.sha1(norm.encode("utf-8", "replace")).hexdigest()[:8] if norm else ""


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _xml_compact(el) -> str:
    """<a x="1"><b>2</b><c/></a>  ->  a(x=1){b=2 c}"""
    name = _local(el.tag)
    attrs = ", ".join(f"{_local(k)}={v}" for k, v in el.attrib.items())
    kids = [c for c in el if isinstance(c.tag, str)]
    text = (el.text or "").strip()
    head = f"{name}({attrs})" if attrs else name
    if kids:
        return head + "{" + " ".join(_xml_compact(c) for c in kids) + "}"
    if text:
        return f"{head}={text}"
    return head


def _xml_preview(t: str) -> Optional[str]:
    try:
        from lxml import etree
        root = etree.fromstring(t.encode("utf-8"), etree.XMLParser(resolve_entities=False, no_network=True))
    except Exception:  # noqa: BLE001
        return None
    el = root
    if _local(el.tag) == "Envelope":  # SOAP: go to the content of Body
        body = next((c for c in el if _local(c.tag) == "Body"), None)
        kids = [c for c in body if isinstance(c.tag, str)] if body is not None else []
        if not kids:
            return ""
        el = kids[0]
    kids = [c for c in el if isinstance(c.tag, str)]
    # collapse the wrapping element (SOAP operation, <describeExtension>...) so parameters come first
    if kids:
        return " ".join(_xml_compact(c) for c in kids)
    return _xml_compact(el)


def body_preview(text: Optional[str], limit: int = 200) -> str:
    """One-line human readable summary of a request body.
    JSON: compact JSON. XML/SOAP: tag-less compact form of the Body content with the wrapping
    element collapsed, e.g. <describeExtension><extension id="samo-mobile"/></...> -> extension(id=samo-mobile)."""
    if not text:
        return ""
    t = text.strip()
    if t[:1] in ("{", "["):
        try:
            t = json.dumps(json.loads(t), ensure_ascii=False, separators=(",", ":"))
        except Exception:  # noqa: BLE001
            pass
    elif t.startswith("<"):
        compact = _xml_preview(t)
        if compact is not None:
            t = compact
        else:
            m = _SOAP_INNER_RX.search(t)
            if m:
                t = m.group(1)
            t = re.sub(r'\s+xmlns(?::[\w.-]+)?="[^"]*"', "", t)
            t = re.sub(r"<(/?)[\w.-]+:", r"<\1", t)
            t = re.sub(r">\s+<", "><", t).strip()
    t = re.sub(r"\s+", " ", t)
    return t if len(t) <= limit else t[: limit - 1] + "…"


def _is_textual(ctype: str) -> bool:
    c = ctype.lower()
    return any(t in c for t in TEXT_TYPES)


def body_text(msg: http.Message, max_bytes: int) -> tuple[Optional[str], int, str]:
    """Return (decoded text or None, size, note)."""
    if msg.raw_content is None:
        return None, 0, "body streamed (too large), not captured"
    try:
        content = msg.get_content(strict=False) or b""
    except Exception:  # noqa: BLE001
        content = msg.raw_content or b""
    size = len(content)
    if size == 0:
        return "", 0, ""
    ctype = msg.headers.get("content-type", "")
    if size > max_bytes:
        return None, size, f"body too large ({size} B), not stored"
    if _is_textual(ctype):
        return msg.get_text(strict=False), size, ""
    try:
        return content.decode("utf-8"), size, ""
    except UnicodeDecodeError:
        return None, size, f"binary body ({ctype or 'unknown type'}, {size} B)"


def _headers_list(h) -> list[list[str]]:
    return [[k, v] for k, v in h.items(multi=True)]


class ProxyAddon:
    def __init__(self, store: Store):
        self.store = store

    # ------------------------------------------------------------ helpers
    def _active(self, server_id: str) -> bool:
        if self.store.settings.rules_paused:
            return False
        srv = self.store.servers.get(server_id)
        return bool(srv and srv.rules_enabled)

    def _matching_rules(self, info: dict) -> list[Rule]:
        srv = self.store.servers.get(info["server"])
        alias = srv.alias if srv else ""
        body = RequestBody(info["req_body"])
        return [
            r for r in self.store.rules
            if r.enabled and rule_matches(
                r, server_id=info["server"], alias=alias, method=info["method"], path=info["path"],
                query=info["query"], soap_op=info["soap_op"], request_body=body,
            )
        ]

    def _consume(self, rule: Rule) -> None:
        rule.hits += 1
        if rule.remaining is not None:
            rule.remaining -= 1
            if rule.remaining <= 0:
                rule.remaining = 0
                rule.enabled = False
            self.store.save_rules()
        else:
            self.store.emit("rules", {})

    # ------------------------------------------------------------ hooks
    def request(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        replay_id = req.headers.get("X-MobileProxy-Replay")
        if replay_id is not None:  # sent by the Repeater - never forwarded to the server
            del req.headers["X-MobileProxy-Replay"]
            flow.metadata["mp_replay"] = replay_id
        host, port = req.host, req.port
        if self.store.is_ignored(host, port) or self.store.is_ignored(req.pretty_host, port):
            flow.metadata["mp_skip"] = True
            return
        srv = self.store.touch_server(host, port, req.scheme)
        if self.store.settings.strip_cache_headers:
            for h in CONDITIONAL_HEADERS:
                if h in req.headers:
                    del req.headers[h]
        parts = urlsplit(req.path)
        req_text, req_size, req_note = body_text(req, self.store.settings.max_body_bytes)
        soap_op = detect_soap_op(req.headers, req_text)
        info = {
            "server": srv.id,
            "method": req.method,
            "path": parts.path or "/",
            "query": parts.query,
            "soap_op": soap_op,
            "req_body": req_text,
            "req_size": req_size,
            "req_note": req_note,
            "req_sig": body_signature(req.method, req_text),
            "req_preview": body_preview(req_text),
            "t0": time.time(),
            "req_headers": _headers_list(req.headers),
        }
        flow.metadata["mp"] = info

        if not self._active(srv.id):
            return
        for rule in self._matching_rules(info):
            if not rule.mock or rule.action not in ("replace", "drop"):
                continue
            self._consume(rule)
            flow.metadata["mp_mock_rule"] = rule.id
            if rule.action == "drop":
                flow.metadata["mp_dropped"] = True
                self._record(flow, error="dropped by rule (mock, server not contacted)", rules=[rule])
                flow.kill()
                return
            headers = {"Content-Type": "application/json; charset=utf-8"}
            for k, v in (rule.headers or {}).items():
                if v != "":
                    headers[k] = v
            flow.response = http.Response.make(rule.status or 200, (rule.body or "").encode("utf-8"), headers)
            return

    async def response(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("mp_skip") or "mp" not in flow.metadata:
            return
        info = flow.metadata["mp"]
        resp = flow.response
        applied: list[Rule] = []
        errors: list[str] = []
        delay = 0
        orig_status = resp.status_code
        orig_text, _, _ = body_text(resp, self.store.settings.max_body_bytes)

        mock_id = flow.metadata.get("mp_mock_rule")
        if mock_id:
            r = self.store.get_rule(mock_id)
            if r:
                applied.append(r)
                delay += r.delay_ms
        elif self._active(info["server"]):
            for rule in self._matching_rules(info):
                if rule.mock:
                    continue
                if rule.action == "drop":
                    self._consume(rule)
                    if rule.delay_ms:
                        await asyncio.sleep(rule.delay_ms / 1000)
                    self._record(flow, error="dropped by rule", rules=applied + [rule])
                    flow.kill()
                    return
                if rule.action == "replace":
                    resp.text = rule.body or ""
                elif rule.action == "patch" and rule.patches:
                    cur, _, note = body_text(resp, self.store.settings.max_body_bytes)
                    if cur is None:
                        errors.append(f"rule {rule.name or rule.id}: cannot patch, {note}")
                    else:
                        new, errs = apply_patches(cur, rule.patches)
                        errors += [f"rule {rule.name or rule.id}: {e}" for e in errs]
                        if new != cur:
                            resp.text = new
                if rule.action in ("replace", "patch"):
                    if rule.status:
                        resp.status_code = rule.status
                    for k, v in (rule.headers or {}).items():
                        if v == "":
                            if k in resp.headers:
                                del resp.headers[k]
                        else:
                            resp.headers[k] = v
                delay += rule.delay_ms
                applied.append(rule)
                self._consume(rule)

        if delay > 0:
            await asyncio.sleep(delay / 1000)
        self._record(flow, rules=applied, rule_errors=errors,
                     orig=(orig_status, orig_text) if (applied and not mock_id) else None)

    def error(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("mp_skip") or flow.metadata.get("mp_dropped") or "mp" not in flow.metadata:
            return
        if flow.response is not None:
            return
        self._record(flow, error=str(flow.error) if flow.error else "error")

    # ------------------------------------------------------------ record
    def _record(self, flow: http.HTTPFlow, *, rules: Optional[list[Rule]] = None, error: Optional[str] = None,
                rule_errors: Optional[list[str]] = None, orig: Optional[tuple] = None) -> None:
        info = flow.metadata["mp"]
        if flow.metadata.get("mp_recorded"):
            return
        flow.metadata["mp_recorded"] = True
        resp = flow.response if error is None else None
        resp_text, resp_size, resp_note = (None, 0, "")
        if resp is not None:
            resp_text, resp_size, resp_note = body_text(resp, self.store.settings.max_body_bytes)
        ex = {
            "id": self.store.new_id(),
            "ts": info["t0"],
            "server": info["server"],
            "scheme": flow.request.scheme,
            "method": info["method"],
            "url": flow.request.pretty_url,
            "path": info["path"],
            "query": info["query"],
            "soap_op": info["soap_op"],
            "endpoint": endpoint_key(info["method"], info["path"], info["soap_op"]),
            "variant": variant_key(endpoint_key(info["method"], info["path"], info["soap_op"]), info["query"], info["req_sig"]),
            "req_sig": info["req_sig"],
            "req_preview": info["req_preview"],
            "category": self.store.classify(info["method"], info["path"], info["query"], info["soap_op"]),
            "req_headers": info["req_headers"],
            "req_body": info["req_body"],
            "req_note": info["req_note"],
            "status": resp.status_code if resp is not None else None,
            "resp_headers": _headers_list(resp.headers) if resp is not None else [],
            "resp_body": resp_text,
            "resp_note": resp_note,
            "resp_size": resp_size,
            "resp_type": resp.headers.get("content-type", "") if resp is not None else "",
            "duration_ms": int((time.time() - info["t0"]) * 1000),
            "modified": False,
            "mocked": bool(flow.metadata.get("mp_mock_rule")),
            "rules_applied": [{"id": r.id, "name": r.name or r.action} for r in (rules or [])],
            "rule_errors": rule_errors or [],
            "error": error,
            "correlation_id": flow.request.headers.get("X-Correlation-ID"),
            "replay_id": flow.metadata.get("mp_replay"),
        }
        if orig is not None:
            o_status, o_text = orig
            if o_status != ex["status"] or o_text != resp_text:
                ex["modified"] = True
                ex["status_original"] = o_status
                ex["resp_body_original"] = o_text
        self.store.add_exchange(ex)
