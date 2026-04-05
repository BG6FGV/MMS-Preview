#!/usr/bin/env python3
"""
launch.py — MMS Reader one-click launcher.

Double-click this file to:
  1. Start a local HTTP server
  2. Open the browser UI

No dependencies required beyond Python 3.6+.

Usage:
  python launch.py
  python launch.py --port 8080
  python launch.py --no-browser
"""

from __future__ import annotations

import argparse
import os
import sys
import webbrowser
import threading

# Ensure the project root is on sys.path so imports work
# regardless of cwd.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)


def main():
    parser = argparse.ArgumentParser(
        description="MMS Reader — launch local web UI",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5820, help="Port (default: 5820)")
    parser.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    args = parser.parse_args()

    from server.config import ServerConfig
    from server.app import run_server

    config = ServerConfig(host=args.host, port=args.port)

    # Start server in a thread (non-blocking)
    server = run_server(config, block=False)

    # Open browser
    if not args.no_browser:
        url = config.base_url
        print(f"Opening {url} ...")
        webbrowser.open(url)

    # Block main thread
    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
