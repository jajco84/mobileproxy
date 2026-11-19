"""Search / filtering of captured exchanges (shared by the web UI, REST API and MCP)."""
from __future__ import annotations

import re
import time
from typing import Optional

from pydantic import BaseModel, Field

SNIPPET_BEFORE = 16  # short lead-in so the match stays visible in narrow list columns
SNIPPET_AFTER = 90
MAX_SNIPPETS = 3


class SearchQuery(BaseModel):
    text: str = Field("", description="Text to find (case-insensitive). Searched in endpoint, query and request summary; "
                                      "with bodies=True also in request/response bodies.")
    regex: bool = Field(False, description="Treat text as a regular expression.")
    bodies: bool = Field(False, description="Also search full request and response bodies (incl. original response before rules).")
    headers: bool = Field(False, description="Also search request and response headers.")
    status: Optional[str] = Field(None, description="Status filter, comma separated: '200', '2xx', '4xx,5xx', '400-499', 'err' (no response / connection error).")
    method: Optional[str] = None
    category: Optional[str] = Field(None, description="metadata | data | other")
    since: Optional[str] = Field(None, description="Only newer exchanges: relative ('30s', '5m', '2h') or unix timestamp.")
    until: Optional[str] = Field(None, description="Only older exchanges: relative ('5m' = older than 5 minutes) or unix timestamp.")
    modified: Optional[bool] = Field(None, description="True = only responses changed by a rule (incl. mocks).")
    mocked: Optional[bool] = Field(None, description="True = only mocked responses (server not contacted).")
    rule_id: Optional[str] = Field(None, description="Only exchanges where this rule was applied.")
    correlation_id: Optional[str] = Field(None, description="X-Correlation-ID (substring).")


_REL_RX = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(s|sec|m|min|h|d)?\s*$", re.I)


def parse_time(v: Optional[str]) -> Optional[float]:
    """'5m' -> now - 300 s, '1795080000' -> absolute timestamp."""
    if v is None or str(v).strip() == "":
        return None
    s = str(v).strip()
    m = _REL_RX.match(s)
    if m:
        num = float(m.group(1))
        unit = (m.group(2) or "").lower()
        if not unit and num > 10_000_000:  # absolute unix timestamp
            return num
        mult = {"": 60, "m": 60, "min": 60, "s": 1, "sec": 1, "h": 3600, "d": 86400}[unit]
        return time.time() - num * mult
    raise ValueError(f"invalid time {v!r}; use e.g. '30s', '5m', '2h' or a unix timestamp")


def status_matches(ex: dict, spec: Optional[str]) -> bool:
    if not spec:
        return True
    st = ex.get("status")
    for part in str(spec).lower().replace(" ", "").split(","):
        if not part:
            continue
        if part in ("err", "error", "errors"):
            if ex.get("error") or st is None:
                return True
        elif st is None:
            continue
        elif part.endswith("xx") and len(part) == 3:
            if str(st)[0] == part[0]:
                return True
        elif "-" in part:
            lo, hi = part.split("-", 1)
            if lo.isdigit() and hi.isdigit() and int(lo) <= st <= int(hi):
                return True
        elif part.isdigit() and int(part) == st:
            return True
    return False


def _snippet(text: str, m: re.Match) -> str:
    a = max(0, m.start() - SNIPPET_BEFORE)
    b = min(len(text), m.end() + SNIPPET_AFTER)
    s = re.sub(r"\s+", " ", text[a:b])
    return ("…" if a > 0 else "") + s + ("…" if b < len(text) else "")


class Matcher:
    """Compiled SearchQuery. __call__(ex) -> None (no match) or list of {field, snippet} (may be empty)."""

    def __init__(self, q: SearchQuery):
        self.q = q
        self.rx: Optional[re.Pattern] = None
        if q.text:
            try:
                self.rx = re.compile(q.text if q.regex else re.escape(q.text), re.I)
            except re.error as e:
                raise ValueError(f"invalid regex: {e}") from e
        self.since = parse_time(q.since)
        self.until = parse_time(q.until)

    def _fields(self, ex: dict):
        yield "endpoint", ex.get("endpoint") or ""
        yield "query", ex.get("query") or ""
        yield "request", ex.get("req_preview") or ""
        yield "status", str(ex.get("status") if ex.get("status") is not None else ex.get("error") or "")
        if self.q.bodies:
            yield "request body", ex.get("req_body") or ""
            yield "response body", ex.get("resp_body") or ""
            yield "original response", ex.get("resp_body_original") or ""
        if self.q.headers:
            yield "request headers", "\n".join(f"{k}: {v}" for k, v in ex.get("req_headers") or [])
            yield "response headers", "\n".join(f"{k}: {v}" for k, v in ex.get("resp_headers") or [])

    def __call__(self, ex: dict) -> Optional[list[dict]]:
        q = self.q
        if q.category and ex.get("category") != q.category:
            return None
        if q.method and (ex.get("method") or "").upper() != q.method.upper():
            return None
        if not status_matches(ex, q.status):
            return None
        ts = ex.get("ts") or 0
        if self.since is not None and ts < self.since:
            return None
        if self.until is not None and ts > self.until:
            return None
        if q.modified is not None and bool(ex.get("modified") or ex.get("mocked")) != q.modified:
            return None
        if q.mocked is not None and bool(ex.get("mocked")) != q.mocked:
            return None
        if q.rule_id and not any(r.get("id") == q.rule_id for r in ex.get("rules_applied") or []):
            return None
        if q.correlation_id and q.correlation_id.lower() not in (ex.get("correlation_id") or "").lower():
            return None
        if self.rx is None:
            return []
        hits: list[dict] = []
        found = False
        for field, text in self._fields(ex):
            if not text:
                continue
            m = self.rx.search(text)
            if not m:
                continue
            found = True
            if field in ("endpoint", "status"):
                continue  # visible in the row anyway
            if len(hits) < MAX_SNIPPETS:
                hits.append({"field": field, "snippet": _snippet(text, m)})
        return hits if found else None
