"""
analyzer/__init__.py — Binary analysis layer.

Provides:
  hex_view           — Hex dump generator for any binary data
  signature_scanner  — Magic-byte signature detection + element extraction
  special_parser     — Vendor-specific backup format handlers
  analyzer_facade    — Unified entry point combining all analysis modes
"""

from __future__ import annotations

__all__ = [
    "analyze_bytes",
    "generate_hex_view",
    "scan_signatures",
    "try_special_formats",
]
