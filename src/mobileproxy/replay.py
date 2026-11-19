"""Repeater: send a (modified) request again and return the response."""
from __future__ import annotations

import time
import uuid
from typing import Optional, Union

import httpx

from .store import Store

REPLAY_HEADER = "X-MobileProxy-Replay"
# hop-by-hop / computed headers: httpx sets them from the URL and body
DROP_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "proxy-connection", "keep-alive",
                "te", "upgrade", "proxy-authorization"}


def normalize_headers(headers: Union[list, dict, None]) -> list[tuple[str, str]]:
    if not headers:
        return []
    items = headers.items() if isinstance(headers, dict) else headers
    out = []
    for kv in items:
        k, v = kv[0], kv[1]
        k = str(k).strip()
        if k and k.lower() not in DROP_HEADERS and k.lower() != REPLAY_HEADER.lower():
            out.append((k, str(v)))
    return out


def parse_header_text(text: str) -> list[tuple[str, str]]:
    """'Name: value' per line; empty lines and lines starting with # are ignored."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, v = line.split(":", 1)
        out.append((k.strip(), v.strip()))
    return out


def _find_replay(store: Store, rid: str) -> Optional[dict]:
    for h in store.history.values():
        for e in reversed(h):
            if e.get("replay_id") == rid:
                return e
    return None


async def replay(store: Store, *, proxy_port: int, method: str, url: str,
                 headers: Union[list, dict, None] = None, body: Optional[str] = None,
                 via_proxy: bool = True, timeout: float = 30.0, max_body_bytes: int = 8 * 1024 * 1024) -> dict:
    """Send the request. via_proxy=True goes through MobileProxy itself, so rules/mocks apply and the call is
    recorded in the history (marked as replay)."""
    method = (method or "GET").upper()
    hdrs = normalize_headers(headers)
    rid = uuid.uuid4().hex[:12]
    if via_proxy:
        hdrs.append((REPLAY_HEADER, rid))
    content = body.encode("utf-8") if body else None
    t0 = time.time()
    try:
        async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{proxy_port}" if via_proxy else None,
                                     verify=False, trust_env=False, timeout=timeout, follow_redirects=False) as client:
            resp = await client.request(method, url, headers=hdrs, content=content)
            raw = resp.content
    except httpx.HTTPError as e:
        return {"error": f"{type(e).__name__}: {e}", "duration_ms": int((time.time() - t0) * 1000), "replay_id": rid}
    duration = int((time.time() - t0) * 1000)
    ctype = resp.headers.get("content-type", "")
    text: Optional[str]
    note = ""
    if len(raw) > max_body_bytes:
        text, note = None, f"body too large ({len(raw)} B)"
    else:
        try:
            text = raw.decode(resp.encoding or "utf-8")
        except (UnicodeDecodeError, LookupError):
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text, note = None, f"binary body ({ctype or 'unknown type'}, {len(raw)} B)"
    result = {
        "status": resp.status_code,
        "reason": resp.reason_phrase,
        "http_version": resp.http_version,
        "headers": [[k, v] for k, v in resp.headers.multi_items()],
        "body": text,
        "body_note": note,
        "size": len(raw),
        "content_type": ctype,
        "duration_ms": duration,
        "replay_id": rid,
        "via_proxy": via_proxy,
        "exchange_id": None,
    }
    if via_proxy:
        ex = _find_replay(store, rid)
        if ex is None:  # recorded a moment later (should be rare)
            ex = await store.wait_for(lambda e: e.get("replay_id") == rid, 2.0)
        if ex:
            result["exchange_id"] = ex["id"]
            result["rules_applied"] = ex.get("rules_applied") or []
            result["mocked"] = ex.get("mocked")
            result["modified"] = ex.get("modified")
    return result
