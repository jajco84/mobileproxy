"""MCP server exposing the proxy state and rules (Streamable HTTP, mounted at /mcp)."""
from __future__ import annotations

import fnmatch
import functools
import inspect
from typing import Any, Optional

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .api import FromExchange, rule_from_exchange
from .rules import Patch, Rule, RuleMatch, apply_patches
from .search import SearchQuery
from .store import Store, summarize

INSTRUCTIONS = """\
MobileProxy is an HTTP(S) debugging proxy between an Android app (SAMO / LIDS Mobile) and its servers.
Every server the app talks to is listed automatically (id = 'host:port', optional alias).
For each server the proxy keeps request/response history and the LAST response per endpoint
(endpoint = 'METHOD /path' + '#soapOperation' for SOAP; each endpoint has VARIANTS = distinct query string and/or
request body, every variant keeps its own latest response and call count; 'req_preview' is a one-line body summary).
Each exchange has a category: 'metadata' (ExtensionService describeExtension = samo-mobile/light-forms/protocols,
api/rest/metadata, codelists, resources, capabilities), 'data' (features, search, business entities, attachments,
settings) or 'other' (StatusService keepAlive, security, map tiles, unknown).
Rules can match the request body: body_contains, body_regex, body_equals (normalized), body_json {JSONPath: value},
body_xpath {XPath: text}.

Typical workflow:
1. list_servers -> list_endpoints(server) -> get_last_response(server, path[, soap_op]) to see real data;
   search_exchanges to find past requests by content (bodies, headers), status, time, rule or correlation id;
   replay_request to send a captured request again (optionally with changed headers/body) and see the response.
2. Change what the app receives with rules:
   - override_response: replace the whole body/status (optionally mock = do not contact server),
   - patch_response: JSONPath / XPath / regex edits applied to every live response (robust to data changes),
   - add_rule for full control (delay, drop connection, header changes, N-times rules).
   Use preview_patches first to check JSONPath/XPath edits against a captured response.
3. Trigger the action in the app (or ask the user), then wait_for_request to observe the result.
4. save_profile / load_profile to store reusable scenarios.
Rules are evaluated in order; replace/patch effects stack. Disable rules you no longer need.
"""


def _guard(fn):
    """Turn expected errors into ToolError so the agent sees the message."""
    def convert(e: Exception) -> ToolError:
        if isinstance(e, KeyError):
            return ToolError(f"not found: {e.args[0] if e.args else e}")
        return ToolError(str(e))

    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def aw(*a, **kw):
            try:
                return await fn(*a, **kw)
            except (ValueError, KeyError) as e:
                raise convert(e) from e
        return aw

    @functools.wraps(fn)
    def w(*a, **kw):
        try:
            return fn(*a, **kw)
        except (ValueError, KeyError) as e:
            raise convert(e) from e
    return w


def build_mcp(store: Store, proxy_port: int = 8080) -> MCPServer:
    mcp = MCPServer("mobileproxy", instructions=INSTRUCTIONS)

    def store_proxy_port() -> int:
        return proxy_port
    _tool = mcp.tool

    def tool():
        def deco(fn):
            return _tool()(_guard(fn))
        return deco

    def _server_id(ref: str) -> str:
        srv = store.resolve_server(ref)
        if srv:
            return srv.id
        raise ValueError(f"unknown server {ref!r}; call list_servers")

    def _trim(text: Optional[str], n: int) -> Optional[str]:
        if text is None or n <= 0 or len(text) <= n:
            return text
        return text[:n] + f"\n... [truncated, {len(text)} chars total; raise max_body_chars]"

    def _detail(ex: dict, max_body_chars: int) -> dict:
        d = dict(ex)
        for k in ("resp_body", "resp_body_original", "req_body"):
            if k in d:
                d[k] = _trim(d[k], max_body_chars)
        return d

    # ------------------------------------------------------------ read
    @tool()
    def list_servers() -> list[dict]:
        """List servers seen by the proxy (id, alias, request count, whether rules apply)."""
        return [s.model_dump(include={"id", "alias", "scheme", "count", "rules_enabled", "last_seen"})
                for s in sorted(store.servers.values(), key=lambda s: -s.last_seen)]

    @tool()
    def set_server_alias(server: str, alias: str) -> dict:
        """Give a server a friendly alias (usable instead of host:port everywhere)."""
        srv = store.servers[_server_id(server)]
        srv.alias = alias
        store.save_servers()
        store.emit("server", {"server": srv.model_dump()})
        return srv.model_dump()

    @tool()
    def list_endpoints(server: Optional[str] = None, category: Optional[str] = None, filter: str = "") -> list[dict]:
        """Latest exchange of every endpoint variant (distinct query / request body) with call count.
        server = None -> all servers. category = 'metadata' | 'data' | 'other'. filter = substring."""
        return store.list_endpoints(_server_id(server) if server else None, category, filter)

    @tool()
    def list_exchanges(server: Optional[str] = None, filter: str = "", limit: int = 30,
                       category: Optional[str] = None) -> list[dict]:
        """Recent request/response summaries, newest first. filter = substring of endpoint/query/status/request body.
        category = 'metadata' | 'data' | 'other'."""
        sid = _server_id(server) if server else None
        return [summarize(e) for e in store.list_exchanges(sid, filter, limit, category)]

    @tool()
    def search_exchanges(text: str = "", bodies: bool = True, regex: bool = False, headers: bool = False,
                         server: Optional[str] = None, category: Optional[str] = None, method: Optional[str] = None,
                         status: Optional[str] = None, since: Optional[str] = None, until: Optional[str] = None,
                         modified: Optional[bool] = None, mocked: Optional[bool] = None, rule_id: Optional[str] = None,
                         correlation_id: Optional[str] = None, latest_per_variant: bool = False,
                         limit: int = 20, before_id: Optional[int] = None) -> dict:
        """Search captured request/response history, newest first.
        text: case-insensitive substring (or regex=True) searched in endpoint, query, request summary and - with
        bodies=True (default) - full request/response bodies incl. the original response before rules; headers=True
        adds headers. Each hit has 'matches' with snippets showing where the text was found.
        Filters: status ('500', '2xx', '4xx,5xx', '400-499', 'err' = connection error), method, category
        ('metadata'|'data'|'other'), since/until ('30s', '5m', '2h' or unix ts), modified/mocked (True = only
        responses changed by rules / mocks), rule_id (rule applied), correlation_id (X-Correlation-ID).
        latest_per_variant=True searches only the latest response of each distinct request instead of full history.
        Paging: pass next_before_id from the previous result as before_id. Use get_exchange(id) for full details."""
        sq = SearchQuery(text=text, regex=regex, bodies=bodies, headers=headers, status=status, method=method,
                         category=category, since=since, until=until, modified=modified, mocked=mocked,
                         rule_id=rule_id, correlation_id=correlation_id)
        sid = _server_id(server) if server else None
        if latest_per_variant:
            rows = store.list_endpoints(sid, query=sq)
            rows.sort(key=lambda r: -r["id"])
            return {"total": len(rows), "results": rows[:limit], "next_before_id": None}
        res = store.search(sid, sq, limit, before_id)
        results = []
        for e in res["items"]:
            d = summarize(e)
            if e["id"] in res["matches"]:
                d["matches"] = res["matches"][e["id"]]
            results.append(d)
        return {"total": res["total"], "results": results, "next_before_id": res["next_before_id"]}

    @tool()
    async def replay_request(exchange_id: Optional[int] = None, method: Optional[str] = None, url: Optional[str] = None,
                             set_headers: Optional[dict[str, str]] = None, remove_headers: Optional[list[str]] = None,
                             body: Optional[str] = None, via_proxy: bool = True, max_body_chars: int = 20000) -> dict:
        """Send a request again (Repeater), optionally modified, and return the response.
        Start from a captured exchange (exchange_id) and override method / url / body; set_headers adds or replaces
        headers, remove_headers deletes them (case-insensitive). Without exchange_id, method+url are required.
        via_proxy=True (default) sends it through MobileProxy: rules/mocks apply and the call is recorded in the
        history (exchange_id in the result, marked as replay). via_proxy=False talks to the server directly."""
        from .replay import replay
        base_headers: list = []
        base_body = None
        if exchange_id is not None:
            ex = store.get_exchange(exchange_id)
            if not ex:
                raise ValueError("exchange not found")
            method = method or ex["method"]
            url = url or ex["url"]
            base_headers = [list(h) for h in ex.get("req_headers") or []]
            base_body = ex.get("req_body")
        if not url or not method:
            raise ValueError("method and url are required when exchange_id is not given")
        rm = {h.lower() for h in (remove_headers or [])} | {k.lower() for k in (set_headers or {})}
        headers = [h for h in base_headers if h[0].lower() not in rm] + [[k, v] for k, v in (set_headers or {}).items()]
        res = await replay(store, proxy_port=store_proxy_port(), method=method, url=url, headers=headers,
                           body=body if body is not None else base_body, via_proxy=via_proxy,
                           max_body_bytes=store.settings.max_body_bytes)
        if res.get("body") is not None:
            res["body"] = _trim(res["body"], max_body_chars)
        return res

    @tool()
    def get_exchange(exchange_id: int, max_body_chars: int = 20000) -> dict:
        """Full exchange: request + response headers and bodies (original body too if a rule modified it)."""
        ex = store.get_exchange(exchange_id)
        if not ex:
            raise ValueError("exchange not found (evicted from history?)")
        return _detail(ex, max_body_chars)

    @tool()
    def get_last_response(server: str, path: str, method: Optional[str] = None, soap_op: Optional[str] = None,
                          request_body_contains: Optional[str] = None, query_contains: Optional[str] = None,
                          max_body_chars: int = 20000) -> dict:
        """Last captured exchange for an endpoint. path may be a glob ('/api/meta*'); newest match wins.
        request_body_contains narrows POSTs down to a specific request body."""
        sid = _server_id(server)
        cands = [e for e in store.last_by_endpoint.get(sid, {}).values()
                 if fnmatch.fnmatchcase(e["path"], path)
                 and (method is None or e["method"].upper() == method.upper())
                 and (soap_op is None or fnmatch.fnmatchcase(e.get("soap_op") or "", soap_op))
                 and (not request_body_contains or request_body_contains in (e.get("req_body") or ""))
                 and (not query_contains or query_contains in (e.get("query") or ""))]
        if not cands:
            raise ValueError("no captured exchange for that endpoint; see list_endpoints")
        ex = max(cands, key=lambda e: e["id"])
        return _detail(ex, max_body_chars)

    # ------------------------------------------------------------ rules
    @tool()
    def list_rules() -> list[dict]:
        """All rules in evaluation order (bodies truncated to 500 chars)."""
        out = []
        for r in store.rules:
            d = r.model_dump()
            d["body"] = _trim(d.get("body"), 500)
            out.append(d)
        return out

    @tool()
    def get_rule(rule_id: str) -> dict:
        """One rule including the full body."""
        r = store.get_rule(rule_id)
        if not r:
            raise ValueError("rule not found")
        return r.model_dump()

    @tool()
    def add_rule(rule: Rule, first: bool = True) -> dict:
        """Add a rule with full control (see schema). first=True puts it at the top of the list."""
        rule.hits = 0
        if store.get_rule(rule.id):
            rule.id = Rule().id
        return store.add_rule(rule, first=first).model_dump()

    @tool()
    def override_response(server: str, path: str, body: Optional[str] = None, status: Optional[int] = None,
                          method: Optional[str] = None, soap_op: Optional[str] = None,
                          mock: bool = False, times: Optional[int] = None, delay_ms: int = 0,
                          content_type: Optional[str] = None, name: str = "",
                          request_body_contains: Optional[str] = None, request_body_json: Optional[dict[str, Any]] = None,
                          request_body_xpath: Optional[dict[str, Optional[str]]] = None) -> dict:
        """Replace the response of an endpoint with `body` (and/or status).
        request_body_* restrict the rule to requests whose body matches (e.g. a POST with a given id):
        contains = substring, json = {JSONPath: value}, xpath = {XPath: text}.
        If body is None, the last captured body of that endpoint is used
        (handy together with status to simulate errors). mock=True answers without contacting the server.
        times=N applies the rule only N times."""
        sid = _server_id(server)
        headers = {"Content-Type": content_type} if content_type else None
        if body is None:
            cands = [e for e in store.last_by_endpoint.get(sid, {}).values()
                     if fnmatch.fnmatchcase(e["path"], path)
                     and (method is None or e["method"].upper() == method.upper())
                     and (soap_op is None or (e.get("soap_op") or "") == soap_op)
                     and (not request_body_contains or request_body_contains in (e.get("req_body") or ""))]
            if cands:
                ex = max(cands, key=lambda e: e["id"])
                body = ex.get("resp_body_original") if ex.get("modified") else ex.get("resp_body")
                if mock and not content_type and ex.get("resp_type"):
                    headers = {"Content-Type": ex["resp_type"]}
            body = body or ""
        r = Rule(name=name or f"override {path}",
                 match=RuleMatch(server=sid, method=method, path=path, soap_op=soap_op, body_contains=request_body_contains,
                                 body_json=request_body_json, body_xpath=request_body_xpath),
                 action="replace", body=body, status=status, headers=headers, mock=mock, remaining=times,
                 delay_ms=delay_ms, note="created via MCP")
        return store.add_rule(r, first=True).model_dump()

    @tool()
    def pin_exchange(exchange_id: int, body: Optional[str] = None, status: Optional[int] = None,
                     mock: bool = False, match_query: bool = False, match_request_body: bool = True,
                     times: Optional[int] = None, name: str = "") -> dict:
        """Create a replace rule from a captured exchange (same server/method/path/SOAP op),
        optionally with an edited body. Equivalent of 'edit last response and pin it' in the UI.
        match_request_body=True (default) makes the rule apply only to requests with the same body (POST etc.)."""
        r = rule_from_exchange(store, FromExchange(exchange_id=exchange_id, body=body, status=status, mock=mock,
                                                   match_query=match_query, match_body_exact=match_request_body,
                                                   remaining=times, name=name))
        return store.add_rule(r, first=True).model_dump()

    @tool()
    def patch_response(server: str, path: str, patches: list[Patch], method: Optional[str] = None,
                       soap_op: Optional[str] = None, times: Optional[int] = None, name: str = "",
                       request_body_contains: Optional[str] = None, request_body_json: Optional[dict[str, Any]] = None,
                       request_body_xpath: Optional[dict[str, Optional[str]]] = None) -> dict:
        """Add a rule that edits live responses with JSONPath / XPath / regex patches.
        Examples: {"type":"jsonpath","path":"$.items[0].name","op":"set","value":"X"},
        {"type":"xpath","path":"//*[local-name()='code']","op":"set","value":"42"},
        {"type":"regex","pattern":"\\"visible\\":true","replacement":"\\"visible\\":false"}."""
        sid = _server_id(server)
        r = Rule(name=name or f"patch {path}",
                 match=RuleMatch(server=sid, method=method, path=path, soap_op=soap_op, body_contains=request_body_contains,
                                 body_json=request_body_json, body_xpath=request_body_xpath),
                 action="patch", patches=patches, remaining=times, note="created via MCP")
        return store.add_rule(r, first=True).model_dump()

    @tool()
    def preview_patches(exchange_id: int, patches: list[Patch], max_body_chars: int = 20000) -> dict:
        """Dry-run patches against the (original) response body of a captured exchange."""
        ex = store.get_exchange(exchange_id)
        if not ex:
            raise ValueError("exchange not found")
        src = ex.get("resp_body_original") if ex.get("modified") else ex.get("resp_body")
        if src is None:
            raise ValueError("response body not available (binary or too large)")
        out, errors = apply_patches(src, patches)
        return {"changed": out != src, "errors": errors, "body": _trim(out, max_body_chars)}

    @tool()
    def update_rule(rule_id: str, changes: dict[str, Any]) -> dict:
        """Change fields of a rule, e.g. {"enabled": false} or {"body": "...", "status": 500}."""
        r = store.get_rule(rule_id)
        if not r:
            raise ValueError("rule not found")
        data = r.model_dump()
        if "match" in changes and isinstance(changes["match"], dict):
            data["match"] = {**data["match"], **changes.pop("match")}
        data.update(changes)
        return store.replace_rule(rule_id, Rule(**data)).model_dump()

    @tool()
    def delete_rule(rule_id: str) -> str:
        """Delete a rule."""
        store.delete_rule(rule_id)
        return "deleted"

    @tool()
    def clear_rules() -> str:
        """Delete all rules (save a profile first if you want to keep them)."""
        store.rules = []
        store.save_rules()
        return "all rules deleted"

    @tool()
    def set_rules_paused(paused: bool) -> str:
        """Globally pause/resume all rules (proxy keeps recording)."""
        store.settings.rules_paused = paused
        store.save_settings()
        return "paused" if paused else "active"

    # ------------------------------------------------------------ profiles
    @tool()
    def list_profiles() -> list[dict]:
        """Saved rule profiles (scenarios) on disk."""
        return store.list_profiles()

    @tool()
    def save_profile(name: str, description: str = "", rule_ids: Optional[list[str]] = None) -> dict:
        """Save current rules (or a subset) as a named profile (YAML file)."""
        return store.save_profile(name, description, rule_ids)

    @tool()
    def load_profile(name: str, mode: str = "replace") -> dict:
        """Load a profile. mode='replace' replaces current rules, 'merge' appends."""
        return {"rules_loaded": store.load_profile(name, mode)}

    # ------------------------------------------------------------ observe
    @tool()
    async def wait_for_request(path: str = "*", server: Optional[str] = None, method: Optional[str] = None,
                               soap_op: Optional[str] = None, request_body_contains: Optional[str] = None,
                               timeout_s: float = 60, max_body_chars: int = 5000) -> dict:
        """Wait for the NEXT exchange matching the filter (path glob, server, method, SOAP op) and return it.
        Use after triggering an action in the app. Returns {"timeout": true} if nothing arrived."""
        sid = _server_id(server) if server else None

        def pred(e: dict) -> bool:
            return ((sid is None or e["server"] == sid) and fnmatch.fnmatchcase(e["path"], path)
                    and (method is None or e["method"].upper() == method.upper())
                    and (soap_op is None or fnmatch.fnmatchcase(e.get("soap_op") or "", soap_op))
                    and (not request_body_contains or request_body_contains in (e.get("req_body") or "")))

        ex = await store.wait_for(pred, timeout_s)
        if ex is None:
            return {"timeout": True}
        return _detail(ex, max_body_chars)

    @tool()
    def clear_history(server: Optional[str] = None) -> str:
        """Forget captured exchanges (all, or for one server)."""
        store.clear_history(_server_id(server) if server else None)
        return "cleared"

    return mcp
