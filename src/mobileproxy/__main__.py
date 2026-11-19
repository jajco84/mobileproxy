"""Entry point: python -m mobileproxy  (or the `mobileproxy` script)."""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import webbrowser
from pathlib import Path

from . import __version__


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="mobileproxy", description="Editing HTTP(S) proxy for mobile app testing")
    p.add_argument("--proxy-host", default="127.0.0.1",
                   help="Proxy listen address. 127.0.0.1 is enough for the emulator (10.0.2.2) and adb reverse; "
                        "use 0.0.0.0 for physical devices over Wi-Fi.")
    p.add_argument("--proxy-port", type=int, default=8080)
    p.add_argument("--ui-host", default="127.0.0.1", help="Web UI / API / MCP listen address")
    p.add_argument("--ui-port", type=int, default=8081)
    p.add_argument("--data-dir", type=Path, default=Path.home() / ".mobileproxy",
                   help="Settings, rules, profiles and the CA certificate (default ~/.mobileproxy)")
    p.add_argument("--verify-upstream", action="store_true",
                   help="Verify server TLS certificates (off by default: test servers often use self-signed certs)")
    p.add_argument("--no-browser", action="store_true", help="Do not open the web UI on start")
    p.add_argument("--no-mcp", action="store_true", help="Disable the MCP endpoint")
    p.add_argument("--restore-system-proxy", action="store_true",
                   help="macOS: restore the network proxy settings changed by MobileProxy (e.g. after a crash) and exit")
    p.add_argument("--version", action="version", version=__version__)
    return p.parse_args(argv)


async def run(args: argparse.Namespace) -> None:
    import uvicorn
    from mitmproxy import options
    from mitmproxy.tools.dump import DumpMaster

    from .addon import ProxyAddon
    from .api import AppContext, create_app
    from .store import Store

    data_dir: Path = args.data_dir.expanduser()
    store = Store(data_dir)
    confdir = data_dir / "certs"
    confdir.mkdir(parents=True, exist_ok=True)

    opts = options.Options(
        listen_host=args.proxy_host,
        listen_port=args.proxy_port,
        confdir=str(confdir),
        ssl_insecure=not args.verify_upstream,
        ignore_hosts=store.valid_ignore_hosts(),
    )
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    master.options.update(
        termlog_verbosity="warn",
        stream_large_bodies="32m",
        connection_strategy="lazy",
    )
    master.addons.add(ProxyAddon(store))

    def apply_settings() -> None:
        master.options.update(ignore_hosts=store.valid_ignore_hosts())

    store.on_settings_changed = apply_settings

    mcp_server = None
    if not args.no_mcp:
        from .mcp_server import build_mcp
        mcp_server = build_mcp(store, proxy_port=args.proxy_port)

    ctx = AppContext(store=store, proxy_host=args.proxy_host, proxy_port=args.proxy_port,
                     ui_host=args.ui_host, ui_port=args.ui_port, confdir=confdir)
    app = create_app(ctx, mcp_server)
    server = uvicorn.Server(uvicorn.Config(app, host=args.ui_host, port=args.ui_port, log_level="warning",
                                           ws_ping_interval=20))

    proxy_task = asyncio.create_task(master.run())
    ui_url = f"http://{'127.0.0.1' if args.ui_host in ('0.0.0.0', '::') else args.ui_host}:{args.ui_port}"
    print(f"MobileProxy {__version__}")
    print(f"  proxy      : {args.proxy_host}:{args.proxy_port}   (Android emulator: 10.0.2.2:{args.proxy_port})")
    print(f"  web UI     : {ui_url}")
    if mcp_server:
        print(f"  MCP        : {ui_url}/mcp")
    print(f"  data dir   : {data_dir}")
    from . import macos
    if macos.backup_exists(data_dir):
        print("  macOS proxy: still pointing to MobileProxy (from a previous run) - it will be restored on exit")
    print("  Ctrl+C to stop")
    if not args.no_browser:
        asyncio.get_running_loop().call_later(1.0, lambda: webbrowser.open(ui_url))
    try:
        await server.serve()
    finally:
        master.shutdown()
        try:
            await asyncio.wait_for(proxy_task, 5)
        except Exception:  # noqa: BLE001
            pass


def main(argv=None) -> None:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    args = parse_args(argv)
    if args.restore_system_proxy:
        from . import macos
        data_dir = args.data_dir.expanduser()
        if not macos.IS_MAC:
            print("not macOS - nothing to restore")
            return
        res = asyncio.run(macos.disable(data_dir))
        print(f"macOS proxy settings restored for: {', '.join(res['services']) or '-'}")
        for n in res["notes"]:
            print("  " + n)
        return
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        _restore_system_proxy(args.data_dir.expanduser())


def _restore_system_proxy(data_dir: Path) -> None:
    """Runs after the event loop has finished (uvicorn re-raises Ctrl+C when it stops, which would interrupt
    an in-loop restore), in a fresh loop."""
    from . import macos
    if not macos.backup_exists(data_dir):
        return
    print("Restoring macOS proxy settings…")
    for attempt in range(2):  # a second Ctrl+C during the restore should not leave the Mac half-configured
        try:
            asyncio.run(macos.disable(data_dir))
            print("  done")
            return
        except KeyboardInterrupt:
            continue
        except Exception as e:  # noqa: BLE001
            print(f"  failed: {e} - run `mobileproxy --restore-system-proxy`", file=sys.stderr)
            return


if __name__ == "__main__":
    main()
