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

# Ensure root directory and backend directory are in sys.path
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

# Ensure storage directory exists
data_dir.mkdir(parents=True, exist_ok=True)


def check_prerequisites():
    """
    Verifies required packages are installed.
    """
    required_pkgs = ["fastapi", "uvicorn", "pydantic", "httpx", "cryptography", "dns", "yaml", "bs4"]
    missing = []
    for pkg in required_pkgs:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"\n[ERROR] Missing required dependencies: {', '.join(missing)}")
        print("Please run: pip install -r backend/requirements.txt\n")
        sys.exit(1)


def main():
    check_prerequisites()

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    display_host = "localhost" if host == "0.0.0.0" else host
    dashboard_url = f"http://{display_host}:{port}"
    reload_enabled = os.environ.get("UVICORN_RELOAD", "0").strip().lower() in {"1", "true", "yes"}

    from app.core.version import APP_NAME, APP_VERSION
    print("=" * 72)
    print(f" [{APP_NAME.upper()}] AUTOMATED SECURITY ASSESSMENT PLATFORM v{APP_VERSION}")
    print("=" * 72)
    print(f" [*] Local API Server   : {dashboard_url}")
    print(f" [*] Interactive Docs   : {dashboard_url}/docs")
    print(f" [*] Scan Storage Path  : {data_dir}")
    print("=" * 72)
    print(" [*] Opening Cyber SOC HUD Dashboard in browser...")

    # Open browser in separate background process after brief pause
    def open_browser():
        time.sleep(1.2)
        try:
            webbrowser.open(dashboard_url)
        except Exception:
            pass

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    try:
        # Reload is a development opt-in; production uses a stable process.
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
