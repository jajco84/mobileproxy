"""macOS helpers: system proxy (PAC) for the iOS Simulator and simctl utilities.

The iOS Simulator has no proxy setting of its own - it uses the macOS network settings. MobileProxy therefore
sets an *automatic proxy configuration (PAC) URL* on the Mac's network services. The PAC sends only selected
hosts (test servers) to MobileProxy; everything else on the Mac stays DIRECT.

The original settings are saved to <data_dir>/system_proxy_backup.json before the first change and restored
on shutdown (or with `mobileproxy --restore-system-proxy` after a crash).
"""
from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import json
import logging
import platform
import re
import shlex
import sqlite3
import ssl
from pathlib import Path
from typing import Optional

log = logging.getLogger("mobileproxy")

IS_MAC = platform.system() == "Darwin"
BACKUP_FILE = "system_proxy_backup.json"


# ---------------------------------------------------------------- process helpers
async def _run(*args: str, timeout: float = 30) -> tuple[int, str]:
    try:
        proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.STDOUT)
    except FileNotFoundError:
        return 127, f"{args[0]} not found"
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, f"{args[0]} timeout"
    return proc.returncode or 0, out.decode("utf-8", "replace").strip()


def _needs_admin(code: int, out: str) -> bool:
    o = out.lower()
    return code != 0 and ("admin" in o or "privilege" in o or "not authorized" in o or "permission" in o)


async def _run_many(cmds: list[list[str]]) -> list[str]:
    """Run networksetup commands; if macOS demands admin rights, run them all at once via one password prompt."""
    log_lines: list[str] = []
    pending: list[list[str]] = []
    for c in cmds:
        code, out = await _run(*c)
        if _needs_admin(code, out):
            pending.append(c)
        elif code != 0 or out.lower().startswith("** error"):
            log_lines.append(f"{shlex.join(c)}: {out}")
    if pending:
        script = "; ".join(shlex.join(c) for c in pending)
        apple = 'do shell script "' + script.replace("\\", "\\\\").replace('"', '\\"') + '" with administrator privileges'
        code, out = await _run("osascript", "-e", apple, timeout=120)
        if code != 0:
            raise RuntimeError(f"admin rights needed and the request failed or was cancelled: {out}")
        log_lines.append(f"{len(pending)} command(s) run with administrator privileges")
    return log_lines


# ---------------------------------------------------------------- network services
async def list_services() -> list[str]:
    code, out = await _run("networksetup", "-listallnetworkservices")
    if code != 0:
        raise RuntimeError(out)
    services = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if line and not line.startswith("*"):  # '*' = disabled service
            services.append(line)
    return services


def _parse_kv(out: str) -> dict[str, str]:
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip().lower()] = v.strip()
    return d


async def _get_autoproxy(service: str) -> dict:
    _code, out = await _run("networksetup", "-getautoproxyurl", service)
    kv = _parse_kv(out)
    url = kv.get("url", "")
    return {"url": "" if url in ("", "(null)") else url, "enabled": kv.get("enabled", "").lower() == "yes"}


def _backup_path(data_dir: Path) -> Path:
    return data_dir / BACKUP_FILE


def backup_exists(data_dir: Path) -> bool:
    return _backup_path(data_dir).exists()


async def enable_pac(data_dir: Path, pac_url: str) -> dict:
    """Point every enabled network service to our PAC URL. Saves the original state first (only once)."""
    if not IS_MAC:
        raise RuntimeError("system proxy is supported on macOS only")
    services = await list_services()
    bp = _backup_path(data_dir)
    if not bp.exists():
        backup = {s: await _get_autoproxy(s) for s in services}
        bp.write_text(json.dumps(backup, indent=2), encoding="utf-8")
    cmds = [["networksetup", "-setautoproxyurl", s, pac_url] for s in services]
    cmds += [["networksetup", "-setautoproxystate", s, "on"] for s in services]
    notes = await _run_many(cmds)
    return {"services": services, "notes": notes}


async def disable(data_dir: Path) -> dict:
    """Restore the saved state (or just switch PAC off when there is no backup)."""
    if not IS_MAC:
        return {"services": [], "notes": ["not macOS"]}
    bp = _backup_path(data_dir)
    backup = {}
    if bp.exists():
        try:
            backup = json.loads(bp.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            backup = {}
    services = list(backup.keys()) or await list_services()
    cmds: list[list[str]] = []
    for s in services:
        prev = backup.get(s) or {}
        if prev.get("url"):
            cmds.append(["networksetup", "-setautoproxyurl", s, prev["url"]])
            cmds.append(["networksetup", "-setautoproxystate", s, "on" if prev.get("enabled") else "off"])
        else:
            cmds.append(["networksetup", "-setautoproxystate", s, "off"])
    notes = await _run_many(cmds)
    if bp.exists():
        bp.unlink()
    return {"services": services, "notes": notes}


async def effective_proxy() -> dict:
    """What macOS actually uses right now (scutil --proxy) - VPN clients may override our settings."""
    code, out = await _run("scutil", "--proxy")
    if code != 0:
        return {}
    d = {}
    for line in out.splitlines():
        m = re.match(r"\s*(\w+)\s*:\s*(.*)$", line)
        if m:
            d[m.group(1)] = m.group(2).strip()
    return d


def pac_script(hosts: list[str], proxy: str) -> str:
    """PAC that proxies only the given host globs (shExpMatch syntax: * and ?)."""
    clean = sorted({h.strip().lower() for h in hosts if h and h.strip()})
    arr = json.dumps(clean)
    return (
        "// Generated by MobileProxy - only these hosts go through the proxy, everything else is DIRECT.\n"
        "function FindProxyForURL(url, host) {\n"
        f"  var hosts = {arr};\n"
        "  host = host.toLowerCase();\n"
        "  for (var i = 0; i < hosts.length; i++) {\n"
        f"    if (shExpMatch(host, hosts[i])) return \"PROXY {proxy}\";\n"
        "  }\n"
        "  return \"DIRECT\";\n"
        "}\n"
    )


def pac_matches(hosts: list[str], host: str) -> bool:
    return any(fnmatch.fnmatchcase(host.lower(), h.strip().lower()) for h in hosts if h.strip())


# ---------------------------------------------------------------- iOS Simulator (simctl)
async def sim_booted() -> dict:
    if not IS_MAC:
        return {"supported": False, "devices": []}
    code, out = await _run("xcrun", "simctl", "list", "devices", "booted", "-j")
    if code != 0:
        return {"supported": True, "error": out, "devices": []}
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {"supported": True, "error": "cannot parse simctl output", "devices": []}
    devs = []
    for runtime, items in (data.get("devices") or {}).items():
        rt = runtime.rsplit(".", 1)[-1].replace("iOS-", "iOS ").replace("-", ".")
        for d in items:
            if d.get("state") == "Booted":
                devs.append({"udid": d["udid"], "name": d.get("name", ""), "runtime": rt})
    return {"supported": True, "devices": devs}


def _cert_sha1(pem_path: Path) -> Optional[bytes]:
    try:
        der = ssl.PEM_cert_to_DER_cert(pem_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    return hashlib.sha1(der).digest()


def sim_ca_installed(udid: str, pem_path: Path) -> Optional[bool]:
    """Best effort: look into the simulator's trust store. None = unknown."""
    sha1 = _cert_sha1(pem_path)
    if sha1 is None:
        return None
    base = Path.home() / "Library/Developer/CoreSimulator/Devices" / udid / "data"
    for rel in ("private/var/protected/trustd/private/TrustStore.sqlite", "Library/Keychains/TrustStore.sqlite3"):
        db = base / rel
        if not db.exists():
            continue
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
            try:
                n = con.execute("SELECT COUNT(*) FROM tsettings WHERE sha1 = ?", (sha1,)).fetchone()[0]
            finally:
                con.close()
            return n > 0
        except Exception:  # noqa: BLE001
            return None
    return None


async def sim_install_ca(udid: str, pem_path: Path) -> str:
    code, out = await _run("xcrun", "simctl", "keychain", udid, "add-root-cert", str(pem_path))
    return "CA installed" if code == 0 else f"failed: {out}"


async def sim_restart_app(udid: str, bundle_id: str) -> str:
    await _run("xcrun", "simctl", "terminate", udid, bundle_id)
    code, out = await _run("xcrun", "simctl", "launch", udid, bundle_id)
    return "restarted" if code == 0 else f"failed: {out}"
