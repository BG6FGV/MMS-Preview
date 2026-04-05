"""
server/config.py — Application configuration.

All server settings centralized here. No magic numbers elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ServerConfig:
    """HTTP server configuration."""
    host: str = "127.0.0.1"
    port: int = 5820
    web_root: Path = Path(__file__).resolve().parent.parent / "web"

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"
