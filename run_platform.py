#!/usr/bin/env python3
"""
CyberAssess Security Platform - One-Command Master Launcher.
Launches the FastAPI backend server and opens the SOC Dark Theme Dashboard in the default browser.
"""

import os
import sys
import time
import webbrowser
from pathlib import Path
import uvicorn

root_dir = Path(__file__).resolve().parent
backend_dir = root_dir / "backend"
data_dir = root_dir / "data" / "scans"

if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

data_dir.mkdir(parents=True, exist_ok=True)


def check_prerequisites():
    """Verify required control-plane packages are installed."""
    required_pkgs = ["fastapi", "uvicorn", "pydantic", "httpx", "cryptography", "dns", "yaml", "bs4"]
    missing = []
    for pkg in required_pkgs:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"\n[ERROR] Missing required dependencies: {', '.join(missing)}")
        print("Please run: python -m pip install --require-hashes --requirement backend/requirements.lock\n")
        sys.exit(1)


def resolve_bind_host() -> str:
    """Return the explicit bind host, defaulting standalone mode to loopback."""
    host = os.environ.get("HOST", "127.0.0.1").strip()
    if not host:
        raise RuntimeError("HOST must not be empty.")
    return host


def resolve_port() -> int:
    """Return a validated TCP listen port."""
    try:
        port = int(os.environ.get("PORT", "8000"))
    except ValueError as exc:
        raise RuntimeError("PORT must be an integer between 1 and 65535.") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("PORT must be an integer between 1 and 65535.")
    return port


def main():
    check_prerequisites()

    host = resolve_bind_host()
    port = resolve_port()
    display_host = "localhost" if host in {"0.0.0.0", "::"} else host
    if ":" in display_host and not display_host.startswith("["):
        display_host = f"[{display_host}]"
    dashboard_url = f"http://{display_host}:{port}"
    reload_enabled = os.environ.get("UVICORN_RELOAD", "0").strip().lower() in {"1", "true", "yes"}

    from app.core.version import APP_NAME, APP_VERSION
    print("=" * 72)
    print(f" [{APP_NAME.upper()}] AUTOMATED SECURITY ASSESSMENT PLATFORM v{APP_VERSION}")
    print("=" * 72)
    print(f" [*] Local API Server   : {dashboard_url}")
    print(f" [*] Interactive Docs   : {dashboard_url}/docs")
    print(f" [*] Scan Storage Path  : {data_dir}")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        print(f" [!] Explicit non-loopback bind enabled via HOST={host}")
    print("=" * 72)
    print(" [*] Opening Cyber SOC HUD Dashboard in browser...")

    def open_browser():
        time.sleep(1.2)
        try:
            webbrowser.open(dashboard_url)
        except Exception:
            pass

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    try:
        uvicorn.run(
            "app.main:app",
            host=host,
            port=port,
            log_level="info",
            reload=reload_enabled,
            **({"reload_dirs": [str(backend_dir)]} if reload_enabled else {}),
        )
    except KeyboardInterrupt:
        print("\n[!] CyberAssess Security Platform shut down successfully.")
        sys.exit(0)


if __name__ == "__main__":
    main()
