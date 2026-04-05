"""
server/app.py — Application bootstrap.

Creates and runs the HTTP server. Called from launch.py.
"""

from __future__ import annotations

import http.server
import socketserver
from pathlib import Path
from threading import Event

from server.config import ServerConfig
from server.routes import MmsHttpHandler


def create_app(config: ServerConfig | None = None) -> MmsHttpHandler:
    """
    Create a configured HTTP handler class.

    Args:
        config: Server configuration. Uses defaults if None.

    Returns:
        A handler class with config attached.
    """
    cfg = config or ServerConfig()
    MmsHttpHandler.config = cfg
    MmsHttpHandler.directory = str(cfg.web_root)
    return MmsHttpHandler


def run_server(
    config: ServerConfig | None = None,
    block: bool = True,
) -> http.server.HTTPServer:
    """
    Start the MMS Reader HTTP server.

    Args:
        config: Server configuration.
        block: If True, blocks until interrupted. If False, returns immediately.

    Returns:
        The HTTPServer instance.
    """
    cfg = config or ServerConfig()
    handler = create_app(cfg)

    server = socketserver.TCPServer((cfg.host, cfg.port), handler)
    server.allow_reuse_address = True
    server.daemon_threads = True

    url = cfg.base_url
    print(f"MMS Reader server running at {url}")

    if block:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")
            server.server_close()
    else:
        import threading
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

    return server
