"""In-memory state (servers, exchanges, rules) + persistence of config to the data dir."""
from __future__ import annotations

import asyncio
import fnmatch
import itertools
import json
import logging
import re
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable, Optional

import yaml
from pydantic import BaseModel, Field

from .rules import Rule

log = logging.getLogger("mobileproxy")

DEFAULT_IGNORE_HOSTS = [
    # Google / Android system traffic on emulators - passed through untouched (no TLS interception, no log)
    r"^(.+\.)?(google|googleapis|gstatic|googleusercontent|googlevideo|gvt1|gvt2|gvt3|android|ggpht|youtube|doubleclick|app-measurement|crashlytics|firebaseio|firebaselogging-pa\.googleapis)\.(com|net):\d+$",
    r"^(.+\.)?sentry\.io:\d+$",
    r"^(.+\.)?android\.clients\.google\.com:\d+$",
]
# Apple services seen from the iOS Simulator / macOS (added to existing settings by the v2 migration)
APPLE_IGNORE_HOSTS = [
    r"^(.+\.)?(apple|icloud|icloud-content|mzstatic|apple-cloudkit|cdn-apple|aaplimg|apple-dns|itunes|me)\.(com|net):\d+$",
]
DEFAULT_IGNORE_HOSTS += APPLE_IGNORE_HOSTS
SETTINGS_VERSION = 2


CATEGORIES = ("metadata", "data", "other")


class CategoryRule(BaseModel):
    """Classifies an exchange as metadata / data / other. First matching rule wins."""
    category: str = Field(..., description="metadata | data | other")
    path: str = Field("*", description="Glob on URL path (case-insensitive). Use a leading * to ignore the app context path.")
    method: Optional[str] = None
    soap_op: Optional[str] = Field(None, description="Glob on SOAP operation")
    query_contains: Optional[str] = Field(None, description="Substring of the query string (case-insensitive)")
    note: str = ""


# Derived from the SAMO / LIDS Mobile android-client sources (LoginActivity, *ServiceProvider, CoreController).
DEFAULT_CATEGORY_RULES: list[dict] = [
    # --- metadata: configuration and model the app caches in META / CODE_LISTS / RESOURCES
    {"category": "metadata", "path": "*/ExtensionService*", "note": "describeExtension: samo-mobile, mobile, mobile-workforce, light-forms, protocols"},
    {"category": "metadata", "path": "*/api/rest/metadata/*", "note": "featureTypes, groups, attributeRules, codelist types"},
    {"category": "metadata", "path": "*/rest/metadata/*", "note": "project-info"},
    {"category": "metadata", "path": "*/api/rest/codelists/*", "note": "codelist content, bindings, updated-since, query"},
    {"category": "metadata", "path": "*/rest/cross-section/feature-types*", "note": "cross-section feature types"},
    {"category": "metadata", "path": "*/api/rest/resources/*", "note": "icons / fonts / svg resources"},
    {"category": "metadata", "path": "*/ResourceManager*", "note": "legacy SOAP resources"},
    {"category": "metadata", "path": "*", "query_contains": "getcapabilities", "note": "WMS/WMTS/WFS capabilities"},
    # --- other: housekeeping that would otherwise flood the lists
    {"category": "other", "path": "*/StatusService*", "note": "keepAlive / clientClosed"},
    {"category": "other", "path": "*/rest/security/*", "note": "current user"},
    {"category": "other", "path": "*/rest/password*", "note": "password change"},
    {"category": "other", "path": "*/WebMapService*", "note": "map tiles (GetMap)"},
    {"category": "other", "path": "*/wmts*", "note": "map tiles"},
    # --- data
    {"category": "data", "path": "*/api/rest/features/*", "note": "features, features/query?stream=true"},
    {"category": "data", "path": "*/rest/search/*", "note": "elastic search"},
    {"category": "data", "path": "*/rest/business/*", "note": "business entities / actions"},
    {"category": "data", "path": "*/rest/telco/*"},
    {"category": "data", "path": "*/rest/cross-section/*"},
    {"category": "data", "path": "*/rest/document-folders/*", "note": "attachments"},
    {"category": "data", "path": "*/rest/documents/*", "note": "attachments"},
    {"category": "data", "path": "*/rest/settings*", "note": "user settings (folders, mobile places)"},
    {"category": "data", "path": "*/api/rest/material/*", "note": "WFMS material"},
    {"category": "data", "path": "*/WebFeatureService*", "note": "legacy WFS"},
]


class Settings(BaseModel):
    ignore_hosts: list[str] = Field(default_factory=lambda: list(DEFAULT_IGNORE_HOSTS))
    strip_cache_headers: bool = True
    max_exchanges_per_server: int = 300
    max_endpoints_per_server: int = 500
    max_body_bytes: int = 8 * 1024 * 1024
    rules_paused: bool = False
    app_package: str = "com.asseco.android.lidsmobile.samoMobile.debug"
    category_rules: list[CategoryRule] = Field(default_factory=lambda: [CategoryRule(**r) for r in DEFAULT_CATEGORY_RULES])
    default_category: str = "other"
    # macOS system proxy (PAC) for the iOS Simulator
    system_proxy_hosts: list[str] = Field(default_factory=list, description="Host globs routed to MobileProxy by the PAC")
    system_proxy_include_seen: bool = True
    ios_bundle_id: str = "com.asseco.ce.samomobile"
    settings_version: int = 0


class Server(BaseModel):
    id: str  # host:port
    host: str
    port: int
    scheme: str = "http"
    alias: str = ""
    rules_enabled: bool = True
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    count: int = 0


def endpoint_key(method: str, path: str, soap_op: Optional[str]) -> str:
    """Group key: METHOD /path [#soapOperation]."""
    k = f"{method.upper()} {path}"
    if soap_op:
        k += f" #{soap_op}"
    return k


def normalize_query(query: str) -> str:
    """Query string with parameters sorted, so parameter order does not create a new variant."""
    if not query:
        return ""
    from urllib.parse import parse_qsl, urlencode
    try:
        return urlencode(sorted(parse_qsl(query, keep_blank_values=True)))
    except Exception:  # noqa: BLE001
        return query


def variant_key(endpoint: str, query: str, body_sig: str) -> str:
    """Variant of an endpoint: same group + same (normalized) query + same request body."""
    k = endpoint
    nq = normalize_query(query)
    if nq:
        k += f" ?{nq}"
    if body_sig:
        k += f" @{body_sig}"
    return k


SUMMARY_FIELDS = (
    "id", "ts", "server", "method", "path", "query", "soap_op", "endpoint", "variant", "status", "duration_ms",
    "resp_size", "resp_type", "modified", "mocked", "rules_applied", "error", "correlation_id", "scheme",
    "req_sig", "req_preview", "category", "replay_id",
)


def summarize(ex: dict) -> dict:
    return {k: ex.get(k) for k in SUMMARY_FIELDS}


class Store:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "profiles").mkdir(exist_ok=True)
        self.settings = Settings()
        self.servers: dict[str, Server] = {}
        self.history: dict[str, deque] = {}
        self.exchanges: dict[int, dict] = {}
        self.last_by_endpoint: dict[str, dict[str, dict]] = {}  # server -> variant key -> latest exchange
        self.variant_counts: dict[str, dict[str, int]] = {}
        self.rules: list[Rule] = []
        self._ids = itertools.count(1)
        self._subscribers: set[asyncio.Queue] = set()
        self._waiters: list[tuple[Callable[[dict], bool], asyncio.Future]] = []
        self._ignore_rx: list[re.Pattern] = []
        self.on_settings_changed: Optional[Callable[[], None]] = None
        self._load()

    # ------------------------------------------------------------ persistence
    def _read_json(self, name: str, default: Any) -> Any:
        p = self.data_dir / name
        if not p.exists():
            return default
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            log.warning("cannot read %s: %s", p, e)
            return default

    def _write_json(self, name: str, data: Any) -> None:
        p = self.data_dir / name
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(p)

    def _load(self) -> None:
        raw = self._read_json("settings.json", {})
        self.settings = Settings(**raw)
        if raw and self.settings.settings_version < 2:  # migration: ignore Apple services
            for pat in APPLE_IGNORE_HOSTS:
                if pat not in self.settings.ignore_hosts:
                    self.settings.ignore_hosts.append(pat)
        self.settings.settings_version = SETTINGS_VERSION
        for s in self._read_json("servers.json", []):
            try:
                srv = Server(**s)
                srv.count = 0
                self.servers[srv.id] = srv
            except Exception:  # noqa: BLE001
                pass
        for r in self._read_json("rules.json", []):
            try:
                self.rules.append(Rule(**r))
            except Exception as e:  # noqa: BLE001
                log.warning("skipping invalid rule: %s", e)
        self._compile_ignore()

    def save_servers(self) -> None:
        self._write_json("servers.json", [s.model_dump() for s in self.servers.values()])

    def save_rules(self) -> None:
        self._write_json("rules.json", [r.model_dump() for r in self.rules])
        self.emit("rules", {})

    def save_settings(self) -> None:
        self._write_json("settings.json", self.settings.model_dump())
        self._compile_ignore()
        self.reclassify_all()
        if self.on_settings_changed:
            self.on_settings_changed()
        self.emit("settings", {})

    def _compile_ignore(self) -> None:
        out = []
        for p in self.settings.ignore_hosts:
            try:
                out.append(re.compile(p, re.IGNORECASE))
            except re.error as e:
                log.warning("invalid ignore_hosts regex %r: %s", p, e)
        self._ignore_rx = out

    def classify(self, method: str, path: str, query: str, soap_op: Optional[str]) -> str:
        pl, ql = (path or "").lower(), (query or "").lower()
        for r in self.settings.category_rules:
            if r.method and r.method.upper() != method.upper():
                continue
            if r.path not in ("", "*") and not fnmatch.fnmatchcase(pl, r.path.lower()):
                continue
            if r.soap_op and not fnmatch.fnmatchcase((soap_op or "").lower(), r.soap_op.lower()):
                continue
            if r.query_contains and r.query_contains.lower() not in ql:
                continue
            return r.category
        return self.settings.default_category

    def reclassify_all(self) -> None:
        for ex in self.exchanges.values():
            ex["category"] = self.classify(ex["method"], ex["path"], ex.get("query") or "", ex.get("soap_op"))

    def pac_hosts(self) -> list[str]:
        """Hosts routed to MobileProxy by the macOS PAC: manual list + (optionally) hosts of known servers."""
        hosts = [h.strip() for h in self.settings.system_proxy_hosts if h.strip()]
        if self.settings.system_proxy_include_seen:
            for srv in self.servers.values():
                if not self.is_ignored(srv.host, srv.port):
                    hosts.append(srv.host)
        seen, out = set(), []
        for h in hosts:
            if h.lower() not in seen:
                seen.add(h.lower())
                out.append(h)
        return out

    def valid_ignore_hosts(self) -> list[str]:
        return [r.pattern for r in self._ignore_rx]

    def is_ignored(self, host: str, port: int) -> bool:
        hp = f"{host}:{port}"
        return any(r.search(hp) for r in self._ignore_rx)

    # ------------------------------------------------------------ events
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def emit(self, kind: str, payload: dict) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait({"type": kind, **payload})
            except asyncio.QueueFull:
                pass

    # ------------------------------------------------------------ servers
    def touch_server(self, host: str, port: int, scheme: str) -> Server:
        sid = f"{host}:{port}"
        srv = self.servers.get(sid)
        new = srv is None
        if new:
            srv = Server(id=sid, host=host, port=port, scheme=scheme)
            self.servers[sid] = srv
        srv.last_seen = time.time()
        srv.scheme = scheme
        if new:
            self.save_servers()
            self.emit("server", {"server": srv.model_dump()})
        return srv

    def resolve_server(self, ref: str) -> Optional[Server]:
        if ref in self.servers:
            return self.servers[ref]
        for s in self.servers.values():
            if s.alias and s.alias == ref:
                return s
        for s in self.servers.values():
            if s.host == ref:
                return s
        return None

    def forget_server(self, sid: str) -> None:
        self.servers.pop(sid, None)
        for ex in self.history.pop(sid, []):
            self.exchanges.pop(ex["id"], None)
        self.last_by_endpoint.pop(sid, None)
        self.variant_counts.pop(sid, None)
        self.save_servers()
        self.emit("server", {"removed": sid})

    # ------------------------------------------------------------ exchanges
    def new_id(self) -> int:
        return next(self._ids)

    def add_exchange(self, ex: dict) -> None:
        sid = ex["server"]
        hist = self.history.setdefault(sid, deque())
        hist.append(ex)
        self.exchanges[ex["id"]] = ex
        last = self.last_by_endpoint.setdefault(sid, {})
        counts = self.variant_counts.setdefault(sid, {})
        counts[ex["variant"]] = counts.get(ex["variant"], 0) + 1
        prev = last.pop(ex["variant"], None)  # re-insert -> dict keeps most recently used last
        last[ex["variant"]] = ex
        if prev is not None and prev is not ex and not any(x is prev for x in hist):
            self.exchanges.pop(prev["id"], None)
        while len(hist) > max(10, self.settings.max_exchanges_per_server):
            old = hist.popleft()
            if last.get(old["variant"]) is not old:
                self.exchanges.pop(old["id"], None)
        # POST bodies with ids/timestamps can create many distinct endpoints: keep only the most recent ones
        while len(last) > max(50, self.settings.max_endpoints_per_server):
            _k, old = next(iter(last.items()))
            del last[_k]
            counts.pop(_k, None)
            if not any(x is old for x in hist):
                self.exchanges.pop(old["id"], None)
        srv = self.servers.get(sid)
        if srv:
            srv.count += 1
        self.emit("exchange", {"exchange": summarize(ex)})
        for pred, fut in list(self._waiters):
            if fut.done():
                continue
            try:
                ok = pred(ex)
            except Exception:  # noqa: BLE001
                ok = False
            if ok:
                fut.set_result(ex)

    def get_exchange(self, ex_id: int) -> Optional[dict]:
        return self.exchanges.get(ex_id)

    def _all_history(self, server: Optional[str]) -> list[dict]:
        if server:
            return list(self.history.get(server, []))
        items = [e for h in self.history.values() for e in h]
        items.sort(key=lambda e: e["id"])
        return items

    def search(self, server: Optional[str] = None, query: Optional["SearchQuery"] = None, limit: int = 200,
               before_id: Optional[int] = None, variant: Optional[str] = None) -> dict:
        """Newest first. Returns {total, items: [exchange...], matches: {id: [...]}, next_before_id}."""
        from .search import Matcher, SearchQuery
        matcher = Matcher(query or SearchQuery())
        items = self._all_history(server)
        out: list[dict] = []
        matches: dict[int, list] = {}
        total = 0
        for e in reversed(items):
            if variant and e.get("variant") != variant:
                continue
            if before_id is not None and e["id"] >= before_id:
                continue
            m = matcher(e)
            if m is None:
                continue
            total += 1
            if len(out) < limit:
                out.append(e)
                if m:
                    matches[e["id"]] = m
        next_before = out[-1]["id"] if out and total > len(out) else None
        return {"total": total, "items": out, "matches": matches, "next_before_id": next_before}

    def list_exchanges(self, server: Optional[str] = None, q: str = "", limit: int = 200,
                       category: Optional[str] = None, variant: Optional[str] = None) -> list[dict]:
        from .search import SearchQuery
        res = self.search(server, SearchQuery(text=q, category=category), limit, variant=variant)
        return res["items"]

    def list_endpoints(self, server: Optional[str] = None, category: Optional[str] = None, q: str = "",
                       query: Optional["SearchQuery"] = None) -> list[dict]:
        """Latest exchange of every variant (server = None -> all servers), with call counts.
        query (SearchQuery) is evaluated against the latest exchange of each variant."""
        from .search import Matcher, SearchQuery
        if query is None:
            query = SearchQuery(text=q, category=category)
        matcher = Matcher(query)
        sids = [server] if server else list(self.last_by_endpoint.keys())
        out = []
        for sid in sids:
            counts = self.variant_counts.get(sid, {})
            for key, e in self.last_by_endpoint.get(sid, {}).items():
                m = matcher(e)
                if m is None:
                    continue
                d = summarize(e)
                d["count"] = counts.get(key, 1)
                if m:
                    d["matches"] = m
                out.append(d)
        out.sort(key=lambda e: (e["server"], e["endpoint"], e.get("query") or "", e.get("req_preview") or ""))
        return out

    def clear_history(self, server: Optional[str] = None) -> None:
        sids = [server] if server else list(self.history.keys())
        for sid in sids:
            for ex in self.history.pop(sid, []):
                self.exchanges.pop(ex["id"], None)
            for ex in self.last_by_endpoint.pop(sid, {}).values():
                self.exchanges.pop(ex["id"], None)
            self.variant_counts.pop(sid, None)
            if sid in self.servers:
                self.servers[sid].count = 0
        self.emit("cleared", {"server": server})

    async def wait_for(self, pred: Callable[[dict], bool], timeout: float) -> Optional[dict]:
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        entry = (pred, fut)
        self._waiters.append(entry)
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            return None
        finally:
            self._waiters.remove(entry)

    # ------------------------------------------------------------ rules
    def get_rule(self, rid: str) -> Optional[Rule]:
        return next((r for r in self.rules if r.id == rid), None)

    def add_rule(self, rule: Rule, first: bool = False) -> Rule:
        if self.get_rule(rule.id):
            raise ValueError(f"rule id {rule.id} already exists")
        if first:
            self.rules.insert(0, rule)
        else:
            self.rules.append(rule)
        self.save_rules()
        return rule

    def replace_rule(self, rid: str, rule: Rule) -> Rule:
        for i, r in enumerate(self.rules):
            if r.id == rid:
                rule.id = rid
                self.rules[i] = rule
                self.save_rules()
                return rule
        raise KeyError(rid)

    def delete_rule(self, rid: str) -> None:
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.id != rid]
        if len(self.rules) == before:
            raise KeyError(rid)
        self.save_rules()

    def move_rule(self, rid: str, delta: int) -> None:
        idx = next((i for i, r in enumerate(self.rules) if r.id == rid), None)
        if idx is None:
            raise KeyError(rid)
        j = max(0, min(len(self.rules) - 1, idx + delta))
        r = self.rules.pop(idx)
        self.rules.insert(j, r)
        self.save_rules()

    # ------------------------------------------------------------ profiles
    def _profile_path(self, name: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.\- ]", "_", name).strip() or "profile"
        return self.data_dir / "profiles" / f"{safe}.yaml"

    def list_profiles(self) -> list[dict]:
        out = []
        for p in sorted((self.data_dir / "profiles").glob("*.yaml")):
            try:
                d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            except Exception as e:  # noqa: BLE001
                out.append({"name": p.stem, "description": f"(invalid: {e})", "rules": 0, "file": str(p)})
                continue
            out.append({"name": d.get("name", p.stem), "description": d.get("description", ""),
                        "rules": len(d.get("rules") or []), "file": str(p)})
        return out

    def save_profile(self, name: str, description: str = "", rule_ids: Optional[list[str]] = None) -> dict:
        rules = [r for r in self.rules if rule_ids is None or r.id in rule_ids]
        data = {
            "name": name,
            "description": description,
            "saved": time.strftime("%Y-%m-%d %H:%M:%S"),
            "rules": [r.model_dump(exclude={"hits", "created"}, exclude_none=True) for r in rules],
        }
        p = self._profile_path(name)
        p.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=200), encoding="utf-8")
        self.emit("profiles", {})
        return {"name": name, "file": str(p), "rules": len(rules)}

    def load_profile(self, name: str, mode: str = "replace") -> int:
        p = self._profile_path(name)
        if not p.exists():
            raise KeyError(name)
        d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        rules = [Rule(**r) for r in (d.get("rules") or [])]
        if mode == "replace":
            self.rules = rules
        else:
            existing = {r.id for r in self.rules}
            for r in rules:
                if r.id in existing:
                    r.id = Rule().id
                self.rules.append(r)
        self.save_rules()
        return len(rules)

    def delete_profile(self, name: str) -> None:
        p = self._profile_path(name)
        if not p.exists():
            raise KeyError(name)
        p.unlink()
        self.emit("profiles", {})


def glob_match(pattern: str, value: str) -> bool:
    return pattern in ("", "*") or fnmatch.fnmatchcase(value, pattern)
