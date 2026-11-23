"""Small helpers around adb (emulator / device setup). Works on macOS, Windows and Linux."""
from __future__ import annotations

import asyncio
import os
import platform
import shutil
from pathlib import Path
from typing import Optional


def find_adb() -> Optional[str]:
    exe = "adb.exe" if platform.system() == "Windows" else "adb"
    p = shutil.which(exe)
    if p:
        return p
    candidates = []
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(env):
            candidates.append(Path(os.environ[env]))
    home = Path.home()
    candidates += [home / "Library/Android/sdk", home / "Android/Sdk"]
    if os.environ.get("LOCALAPPDATA"):
        candidates.append(Path(os.environ["LOCALAPPDATA"]) / "Android/Sdk")
    for c in candidates:
        f = c / "platform-tools" / exe
        if f.exists():
            return str(f)
    return None


async def _run(*args: str, timeout: float = 20) -> tuple[int, str]:
    adb = find_adb()
    if not adb:
        return 127, "adb not found (add Android SDK platform-tools to PATH or set ANDROID_HOME)"
    proc = await asyncio.create_subprocess_exec(
        adb, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "adb timeout"
    return proc.returncode or 0, out.decode("utf-8", "replace").strip()


async def devices() -> dict:
    code, out = await _run("devices", "-l")
    if code != 0:
        return {"adb": find_adb(), "error": out, "devices": []}
    devs = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            info = dict(p.split(":", 1) for p in parts[2:] if ":" in p)
            devs.append({"serial": parts[0], "state": parts[1], "emulator": parts[0].startswith("emulator-"),
                         "model": info.get("model", "")})
    return {"adb": find_adb(), "devices": devs}


def expected_proxy(serial: str, proxy_port: int) -> str:
    return f"10.0.2.2:{proxy_port}" if serial.startswith("emulator-") else f"127.0.0.1:{proxy_port}"


def _norm_proxy(value: str) -> str:
    v = (value or "").strip()
    return "" if v in ("", "null", ":0") else v


async def proxy_status(proxy_port: int) -> dict:
    """State of the proxy setting on every connected device (emulators first)."""
    d = await devices()
    out = []
    for dev in d.get("devices", []):
        if dev["state"] != "device":
            out.append({**dev, "proxy": "", "expected": expected_proxy(dev["serial"], proxy_port), "ok": False})
            continue
        cur = _norm_proxy(await get_proxy(dev["serial"]))
        exp = expected_proxy(dev["serial"], proxy_port)
        out.append({**dev, "proxy": cur, "expected": exp, "ok": cur == exp})
    out.sort(key=lambda x: (not x["emulator"], x["serial"]))
    return {"adb": d.get("adb"), "error": d.get("error"), "devices": out}


async def set_proxy_all(proxy_port: int, enable: bool, emulators_only: bool = True) -> list[dict]:
    d = await devices()
    results = []
    for dev in d.get("devices", []):
        if dev["state"] != "device" or (emulators_only and not dev["emulator"]):
            continue
        try:
            msg = await (set_proxy(dev["serial"], proxy_port) if enable else clear_proxy(dev["serial"]))
            results.append({"serial": dev["serial"], "message": msg})
        except ReverseFailed as e:
            results.append({"serial": dev["serial"], "message": str(e), "error": True})
    return results


class ReverseFailed(Exception):
    """adb reverse failed (typically the port is taken on the device); http_proxy was left unchanged."""


async def set_proxy(serial: str, proxy_port: int) -> str:
    """Emulator: 10.0.2.2 = host loopback. Physical device: adb reverse + 127.0.0.1."""
    log = []
    if serial.startswith("emulator-"):
        target = f"10.0.2.2:{proxy_port}"
    else:
        code, out = await _run("-s", serial, "reverse", f"tcp:{proxy_port}", f"tcp:{proxy_port}")
        if code != 0:
            # Setting http_proxy anyway would send the device's traffic to whatever listens on that port.
            raise ReverseFailed(
                f"adb reverse tcp:{proxy_port} failed on {serial}: {out or f'exit code {code}'}. "
                f"Proxy was NOT set. Port {proxy_port} is probably taken on the device; "
                f"restart MobileProxy with --proxy-port <other port>.")
        log.append(f"adb reverse: {out or 'ok'}")
        target = f"127.0.0.1:{proxy_port}"
    code, out = await _run("-s", serial, "shell", "settings", "put", "global", "http_proxy", target)
    log.append(f"http_proxy={target} {out or ('ok' if code == 0 else 'failed')}")
    return "; ".join(log)


async def clear_proxy(serial: str) -> str:
    code, out = await _run("-s", serial, "shell", "settings", "put", "global", "http_proxy", ":0")
    return out or ("proxy cleared" if code == 0 else "failed")


async def get_proxy(serial: str) -> str:
    _, out = await _run("-s", serial, "shell", "settings", "get", "global", "http_proxy")
    return out


async def push_ca(serial: str, cert_path: Path) -> str:
    dest = "/sdcard/Download/mobileproxy-ca.crt"
    code, out = await _run("-s", serial, "push", str(cert_path), dest)
    if code != 0:
        return f"push failed: {out}"
    await _run("-s", serial, "shell", "am", "start", "-a", "android.settings.SECURITY_SETTINGS")
    return (f"Certificate pushed to {dest}. On the device: Settings > Security > Encryption & credentials > "
            f"Install a certificate > CA certificate > Download/mobileproxy-ca.crt")


async def clear_app(serial: str, package: str) -> str:
    code, out = await _run("-s", serial, "shell", "pm", "clear", package)
    return out


async def restart_app(serial: str, package: str) -> str:
    await _run("-s", serial, "shell", "am", "force-stop", package)
    code, out = await _run("-s", serial, "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1")
    return "restarted" if code == 0 else out
