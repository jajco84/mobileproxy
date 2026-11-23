import asyncio

import pytest

from mobileproxy import adb


def fake_run(reverse_result):
    calls = []

    async def run(*args, timeout=20):
        calls.append(args)
        return reverse_result if "reverse" in args else (0, "")
    return run, calls


def test_set_proxy_device_reverse_ok(monkeypatch):
    run, calls = fake_run((0, ""))
    monkeypatch.setattr(adb, "_run", run)
    msg = asyncio.run(adb.set_proxy("R5CX123", 8080))
    assert "http_proxy=127.0.0.1:8080" in msg
    assert ("-s", "R5CX123", "shell", "settings", "put", "global", "http_proxy", "127.0.0.1:8080") in calls


def test_set_proxy_device_reverse_failed_leaves_proxy_unchanged(monkeypatch):
    run, calls = fake_run((1, "adb.exe: error: cannot bind listener: Address already in use"))
    monkeypatch.setattr(adb, "_run", run)
    with pytest.raises(adb.ReverseFailed, match="Address already in use"):
        asyncio.run(adb.set_proxy("R5CX123", 8080))
    assert not any("http_proxy" in c for c in calls)


def test_set_proxy_all_reports_reverse_failure(monkeypatch):
    run, _ = fake_run((1, "cannot bind listener"))
    monkeypatch.setattr(adb, "_run", run)

    async def devices():
        return {"devices": [{"serial": "R5CX123", "state": "device", "emulator": False}]}
    monkeypatch.setattr(adb, "devices", devices)
    res = asyncio.run(adb.set_proxy_all(8080, True, emulators_only=False))
    assert res[0]["error"] is True and "NOT set" in res[0]["message"]
