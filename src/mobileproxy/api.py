"""REST + WebSocket API for the web UI, and the ASGI app that also hosts MCP."""
from __future__ import annotations

import asyncio
import contextlib
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from typing import Annotated

from fastapi import Body, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ValidationError

from . import __version__, adb, macos
from .rules import Patch, Rule, RuleMatch, apply_patches, normalize_body
from .search import SearchQuery
from .store import Settings, Store

STATIC_DIR = Path(__file__).parent / "static"


@dataclass
class AppContext:
    store: Store
    proxy_host: str
    proxy_port: int
    ui_host: str
    ui_port: int
    confdir: Path
    applied_pac_hosts: Optional[list] = None

    @property
    def ca_path(self) -> Path:
        return self.confdir / "mitmproxy-ca-cert.pem"


def lan_ip() -> Optional[str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except Exception:  # noqa: BLE001
        return None
    finally:
        s.close()


class ServerPatch(BaseModel):
    alias: Optional[str] = None
    rules_enabled: Optional[bool] = None


class FromExchange(BaseModel):
    exchange_id: int
    body: Optional[str] = None
    status: Optional[int] = None
    mock: bool = False
    match_query: bool = False
    match_body: Optional[str] = None
    match_body_exact: bool = False
    remaining: Optional[int] = None
    name: str = ""
    delay_ms: int = 0


class PatchPreview(BaseModel):
    exchange_id: int
    patches: list[Patch]


class ReplayRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: Optional[list[list[str]]] = None
    headers_text: Optional[str] = None  # alternative: 'Name: value' per line
    body: Optional[str] = None
    via_proxy: bool = True
    timeout: float = 30.0


class ProfileSave(BaseModel):
    name: str
    description: str = ""
    rule_ids: Optional[list[str]] = None


def rule_from_exchange(store: Store, req: FromExchange) -> Rule:
    ex = store.get_exchange(req.exchange_id)
    if not ex:
        raise KeyError(req.exchange_id)
    body = req.body if req.body is not None else (ex.get("resp_body") or "")
    headers = {}
    if req.mock and ex.get("resp_type"):
        headers["Content-Type"] = ex["resp_type"]
    srv = store.servers.get(ex["server"])
    label = ex["path"] + (f" #{ex['soap_op']}" if ex.get("soap_op") else "")
    exact = req.match_body_exact and bool(ex.get("req_body"))
    if exact and ex.get("req_preview"):
        label += " " + (ex["req_preview"][:60] + ("…" if len(ex["req_preview"]) > 60 else ""))
    return Rule(
        name=req.name or f"{(srv.alias if srv and srv.alias else ex['server'])} {label}",
        match=RuleMatch(
            server=ex["server"], method=ex["method"], path=ex["path"],
            query=(ex.get("query") or "") if req.match_query else None,
            soap_op=ex.get("soap_op"), body_contains=req.match_body or None,
            body_equals=normalize_body(ex["req_body"]) if exact else None,
        ),
        action="replace", body=body, status=req.status if req.status else (ex.get("status") if req.mock else None),
        headers=headers or None, mock=req.mock, remaining=req.remaining, delay_ms=req.delay_ms,
        note=f"created from exchange #{ex['id']}",
    )


def _clean(sq: SearchQuery) -> SearchQuery:
    """Empty strings from HTML forms mean 'no filter'."""
    data = sq.model_dump()
    for k in ("status", "method", "category", "since", "until", "rule_id", "correlation_id"):
        if data.get(k) == "":
            data[k] = None
    return SearchQuery(**data)


def create_app(ctx: AppContext, mcp_server=None) -> FastAPI:
    store = ctx.store

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        if mcp_server is not None:
            async with mcp_server.session_manager.run():
                yield
        else:
            yield

    app = FastAPI(title="MobileProxy", version=__version__, lifespan=lifespan)

    # ------------------------------------------------------------ info
    @app.get("/api/info")
    def info() -> dict:
        return {
            "version": __version__,
            "proxy_host": ctx.proxy_host,
            "proxy_port": ctx.proxy_port,
            "ui_port": ctx.ui_port,
            "lan_ip": lan_ip(),
            "emulator_proxy": f"10.0.2.2:{ctx.proxy_port}",
            "ca_available": ctx.ca_path.exists(),
            "mcp_url": f"http://127.0.0.1:{ctx.ui_port}/mcp",
            "data_dir": str(store.data_dir),
            "is_mac": macos.IS_MAC,
        }

    @app.get("/api/ca.crt")
    def ca_cert():
        if not ctx.ca_path.exists():
            raise HTTPException(404, "CA certificate not generated yet")
        return FileResponse(ctx.ca_path, media_type="application/x-x509-ca-cert", filename="mobileproxy-ca.crt")

    # ------------------------------------------------------------ servers
    @app.get("/api/servers")
    def servers() -> list[dict]:
        out = [s.model_dump() for s in store.servers.values()]
        out.sort(key=lambda s: -s["last_seen"])
        return out

    @app.patch("/api/servers/{sid}")
    def patch_server(sid: str, p: ServerPatch) -> dict:
        srv = store.servers.get(sid)
        if not srv:
            raise HTTPException(404)
        if p.alias is not None:
            srv.alias = p.alias.strip()
        if p.rules_enabled is not None:
            srv.rules_enabled = p.rules_enabled
        store.save_servers()
        store.emit("server", {"server": srv.model_dump()})
        return srv.model_dump()

    @app.delete("/api/servers/{sid}")
    def delete_server(sid: str) -> dict:
        store.forget_server(sid)
        return {"ok": True}

    @app.post("/api/servers/{sid}/ignore")
    def ignore_server(sid: str) -> dict:
        srv = store.servers.get(sid)
        if not srv:
            raise HTTPException(404)
        rx = f"^{re.escape(srv.host)}:{srv.port}$"
        if rx not in store.settings.ignore_hosts:
            store.settings.ignore_hosts.append(rx)
            store.save_settings()
        store.forget_server(sid)
        return {"ok": True, "pattern": rx}

    @app.get("/api/endpoints")
    def all_endpoints(sq: Annotated[SearchQuery, Query()], server: Optional[str] = None) -> list[dict]:
        try:
            return store.list_endpoints(server or None, query=_clean(sq))
        except ValueError as e:
            raise HTTPException(422, str(e)) from e

    @app.get("/api/search")
    def search(sq: Annotated[SearchQuery, Query()], server: Optional[str] = None, limit: int = 300,
               before_id: Optional[int] = None) -> dict:
        from .store import summarize
        try:
            res = store.search(server or None, _clean(sq), limit, before_id)
        except ValueError as e:
            raise HTTPException(422, str(e)) from e
        items = []
        for e in res["items"]:
            d = summarize(e)
            if e["id"] in res["matches"]:
                d["matches"] = res["matches"][e["id"]]
            items.append(d)
        return {"total": res["total"], "items": items, "next_before_id": res["next_before_id"]}

    @app.get("/api/servers/{sid}/endpoints")
    def endpoints(sid: str, category: Optional[str] = None, q: str = "") -> list[dict]:
        return store.list_endpoints(sid, category or None, q)

    # ------------------------------------------------------------ exchanges
    @app.get("/api/exchanges")
    def exchanges(server: Optional[str] = None, q: str = "", limit: int = 300, category: Optional[str] = None,
                  variant: Optional[str] = None) -> list[dict]:
        from .store import summarize
        return [summarize(e) for e in store.list_exchanges(server, q, limit, category or None, variant or None)]

    @app.get("/api/exchanges/{ex_id}")
    def exchange(ex_id: int) -> dict:
        ex = store.get_exchange(ex_id)
        if not ex:
            raise HTTPException(404, "exchange not found (evicted?)")
        return ex

    @app.delete("/api/exchanges")
    def clear_exchanges(server: Optional[str] = None) -> dict:
        store.clear_history(server)
        return {"ok": True}

    # ------------------------------------------------------------ rules
    @app.get("/api/rules")
    def rules() -> list[dict]:
        return [r.model_dump() for r in store.rules]

    @app.post("/api/rules")
    def add_rule(rule: dict = Body(...), first: bool = False) -> dict:
        try:
            r = Rule(**{k: v for k, v in rule.items() if k != "id" or v})
            return store.add_rule(r, first=first).model_dump()
        except (ValidationError, ValueError) as e:
            raise HTTPException(422, str(e)) from e

    @app.put("/api/rules/{rid}")
    def put_rule(rid: str, rule: dict = Body(...)) -> dict:
        try:
            return store.replace_rule(rid, Rule(**rule)).model_dump()
        except ValidationError as e:
            raise HTTPException(422, str(e)) from e
        except KeyError as e:
            raise HTTPException(404) from e

    @app.post("/api/rules/{rid}/toggle")
    def toggle_rule(rid: str) -> dict:
        r = store.get_rule(rid)
        if not r:
            raise HTTPException(404)
        r.enabled = not r.enabled
        if r.enabled and r.remaining == 0:
            r.remaining = None
        store.save_rules()
        return r.model_dump()

    @app.post("/api/rules/{rid}/move")
    def move_rule(rid: str, delta: int = -1) -> dict:
        try:
            store.move_rule(rid, delta)
        except KeyError as e:
            raise HTTPException(404) from e
        return {"ok": True}

    @app.delete("/api/rules/{rid}")
    def delete_rule(rid: str) -> dict:
        try:
            store.delete_rule(rid)
        except KeyError as e:
            raise HTTPException(404) from e
        return {"ok": True}

    @app.delete("/api/rules")
    def clear_rules() -> dict:
        store.rules = []
        store.save_rules()
        return {"ok": True}

    @app.post("/api/rules/from-exchange")
    def from_exchange(req: FromExchange) -> dict:
        try:
            r = rule_from_exchange(store, req)
        except KeyError as e:
            raise HTTPException(404, "exchange not found") from e
        return store.add_rule(r, first=True).model_dump()

    @app.post("/api/patch-preview")
    def patch_preview(req: PatchPreview) -> dict:
        ex = store.get_exchange(req.exchange_id)
        if not ex:
            raise HTTPException(404)
        src = ex.get("resp_body_original") if ex.get("modified") else ex.get("resp_body")
        if src is None:
            raise HTTPException(422, "response body not available")
        out, errors = apply_patches(src, req.patches)
        return {"body": out, "errors": errors, "changed": out != src}

    # ------------------------------------------------------------ repeater
    @app.post("/api/replay")
    async def replay_ep(req: ReplayRequest) -> dict:
        from .replay import parse_header_text, replay
        headers = parse_header_text(req.headers_text) if req.headers_text is not None else (req.headers or [])
        if not req.url.lower().startswith(("http://", "https://")):
            raise HTTPException(422, "URL must start with http:// or https://")
        return await replay(store, proxy_port=ctx.proxy_port, method=req.method, url=req.url, headers=headers,
                            body=req.body, via_proxy=req.via_proxy, timeout=req.timeout,
                            max_body_bytes=store.settings.max_body_bytes)

    @app.get("/repeater")
    def repeater_page():
        return FileResponse(STATIC_DIR / "repeater.html")

    # ------------------------------------------------------------ profiles
    @app.get("/api/profiles")
    def profiles() -> list[dict]:
        return store.list_profiles()

    @app.post("/api/profiles")
    def save_profile(p: ProfileSave) -> dict:
        return store.save_profile(p.name, p.description, p.rule_ids)

    @app.post("/api/profiles/{name}/load")
    def load_profile(name: str, mode: str = "replace") -> dict:
        try:
            n = store.load_profile(name, mode)
        except KeyError as e:
            raise HTTPException(404) from e
        except (ValidationError, ValueError) as e:
            raise HTTPException(422, str(e)) from e
        return {"ok": True, "rules": n}

    @app.delete("/api/profiles/{name}")
    def delete_profile(name: str) -> dict:
        try:
            store.delete_profile(name)
        except KeyError as e:
            raise HTTPException(404) from e
        return {"ok": True}

    # ------------------------------------------------------------ settings
    @app.get("/api/settings/default-categories")
    def default_categories() -> list[dict]:
        from .store import DEFAULT_CATEGORY_RULES, CategoryRule
        return [CategoryRule(**r).model_dump() for r in DEFAULT_CATEGORY_RULES]

    @app.get("/api/settings")
    def get_settings() -> dict:
        return store.settings.model_dump()

    @app.put("/api/settings")
    def put_settings(s: dict = Body(...)) -> dict:
        try:
            merged = {**store.settings.model_dump(), **s}
            store.settings = Settings(**merged)
        except ValidationError as e:
            raise HTTPException(422, str(e)) from e
        store.save_settings()
        return store.settings.model_dump()

    # ------------------------------------------------------------ adb
    @app.get("/api/adb/devices")
    async def adb_devices() -> dict:
        d = await adb.devices()
        for dev in d.get("devices", []):
            if dev["state"] == "device":
                dev["http_proxy"] = await adb.get_proxy(dev["serial"])
        return d

    @app.get("/api/adb/status")
    async def adb_status() -> dict:
        return await adb.proxy_status(ctx.proxy_port)

    @app.post("/api/adb/all/proxy")
    async def adb_proxy_all(enable: bool = True, emulators_only: bool = True) -> dict:
        res = await adb.set_proxy_all(ctx.proxy_port, enable, emulators_only)
        return {"results": res, **(await adb.proxy_status(ctx.proxy_port))}

    @app.post("/api/adb/{serial}/{action}")
    async def adb_action(serial: str, action: str) -> dict:
        pkg = store.settings.app_package
        if action == "proxy-on":
            try:
                msg = await adb.set_proxy(serial, ctx.proxy_port)
            except adb.ReverseFailed as e:
                raise HTTPException(409, str(e))
        elif action == "proxy-off":
            msg = await adb.clear_proxy(serial)
        elif action == "push-ca":
            if not ctx.ca_path.exists():
                raise HTTPException(404, "CA not generated yet")
            msg = await adb.push_ca(serial, ctx.ca_path)
        elif action == "clear-app":
            msg = await adb.clear_app(serial, pkg)
        elif action == "restart-app":
            msg = await adb.restart_app(serial, pkg)
        else:
            raise HTTPException(404, "unknown action")
        return {"message": msg}

    # ------------------------------------------------------------ macOS: system proxy (PAC) + iOS Simulator
    def pac_proxy() -> str:
        return f"127.0.0.1:{ctx.proxy_port}"

    @app.get("/proxy.pac")
    def proxy_pac():
        return Response(macos.pac_script(store.pac_hosts(), pac_proxy()),
                        media_type="application/x-ns-proxy-autoconfig",
                        headers={"Cache-Control": "no-store"})

    async def system_proxy_status() -> dict:
        if not macos.IS_MAC:
            return {"supported": False}
        enabled = macos.backup_exists(store.data_dir)
        eff = await macos.effective_proxy()
        pac_url = eff.get("ProxyAutoConfigURLString", "")
        ours = f"http://127.0.0.1:{ctx.ui_port}/proxy.pac"
        effective_ok = eff.get("ProxyAutoConfigEnable") == "1" and pac_url.startswith(ours)
        hosts = store.pac_hosts()
        return {
            "supported": True,
            "enabled": enabled,
            "effective_ok": effective_ok,
            "effective": {k: v for k, v in eff.items() if k.startswith(("ProxyAutoConfig", "HTTP", "HTTPS"))},
            "hosts": hosts,
            "stale": enabled and ctx.applied_pac_hosts is not None and sorted(ctx.applied_pac_hosts) != sorted(hosts),
            "pac_url": ours,
        }

    @app.get("/api/macos/status")
    async def macos_status() -> dict:
        sp = await system_proxy_status()
        sims = await macos.sim_booted() if macos.IS_MAC else {"supported": False, "devices": []}
        for d in sims.get("devices", []):
            d["ca_installed"] = macos.sim_ca_installed(d["udid"], ctx.ca_path) if ctx.ca_path.exists() else None
        return {"system_proxy": sp, "simulators": sims, "bundle_id": store.settings.ios_bundle_id}

    @app.post("/api/macos/system-proxy")
    async def macos_system_proxy(enable: bool = True) -> dict:
        if not macos.IS_MAC:
            raise HTTPException(400, "system proxy is supported on macOS only")
        try:
            if enable:
                import time as _time
                url = f"http://127.0.0.1:{ctx.ui_port}/proxy.pac?v={int(_time.time())}"  # new URL = macOS refetches
                res = await macos.enable_pac(store.data_dir, url)
                ctx.applied_pac_hosts = store.pac_hosts()
            else:
                res = await macos.disable(store.data_dir)
                ctx.applied_pac_hosts = None
        except RuntimeError as e:
            raise HTTPException(500, str(e)) from e
        await asyncio.sleep(0.5)
        store.emit("system_proxy", {})
        return {**res, "status": await system_proxy_status()}

    @app.post("/api/macos/sim/{action}")
    async def macos_sim(action: str) -> dict:
        sims = await macos.sim_booted()
        devs = sims.get("devices", [])
        if not devs:
            raise HTTPException(404, "no booted iOS Simulator")
        results = []
        for d in devs:
            if action == "install-ca":
                if not ctx.ca_path.exists():
                    raise HTTPException(404, "CA not generated yet")
                msg = await macos.sim_install_ca(d["udid"], ctx.ca_path)
            elif action == "restart-app":
                msg = await macos.sim_restart_app(d["udid"], store.settings.ios_bundle_id)
            else:
                raise HTTPException(404, "unknown action")
            results.append({"udid": d["udid"], "name": d["name"], "message": msg})
        return {"results": results}

    # ------------------------------------------------------------ live events
    @app.websocket("/api/ws")
    async def ws(websocket: WebSocket):
        await websocket.accept()
        q = store.subscribe()
        try:
            while True:
                try:
                    ev = await asyncio.wait_for(q.get(), 25)
                except asyncio.TimeoutError:
                    ev = {"type": "ping"}
                await websocket.send_json(ev)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            store.unsubscribe(q)

    # ------------------------------------------------------------ UI
    @app.get("/")
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.exception_handler(KeyError)
    async def key_error(_req, exc):  # pragma: no cover
        return JSONResponse({"detail": f"not found: {exc}"}, status_code=404)

    @app.exception_handler(Exception)
    async def unexpected_error(req, exc):
        # show the real cause in the UI instead of a bare "Internal Server Error"; full traceback goes to the console
        import logging
        logging.getLogger("mobileproxy").exception("error in %s %s", req.method, req.url.path)
        return JSONResponse({"detail": f"{type(exc).__name__}: {exc} (see the MobileProxy console for details)"},
                            status_code=500)

    if mcp_server is not None:
        # Mounted last: FastAPI routes win, everything else (i.e. /mcp) goes to the MCP app.
        app.mount("/", mcp_server.streamable_http_app(streamable_http_path="/mcp", host=ctx.ui_host))

    return app

