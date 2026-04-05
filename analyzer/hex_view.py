"""
analyzer/hex_view.py — Hex dump generator.

Produces a hex + ASCII view of arbitrary binary data,
suitable for display in a browser or terminal.

Features:
  - Configurable bytes-per-line (16 by default)
  - Offset column
  - ASCII sidebar with unprintable character substitution
  - Pagination support for large files
  - Highlight support (mark specific byte ranges)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


# ─── Data types ──────────────────────────────────────────────

@dataclass
class HexLine:
    """One line of hex dump output."""
    offset: int          # byte offset of this line
    hex_bytes: str       # space-separated hex pairs, e.g. "8C 84 98 42"
    ascii_repr: str      # printable ASCII, dots for non-printable
    raw_bytes: bytes     # original bytes for this line


@dataclass
class HexView:
    """Complete hex dump result."""
    lines: list           # list[HexLine]
    total_bytes: int
    page: int
    page_size: int
    total_pages: int

    def to_html(self, highlights: Optional[dict] = None) -> str:
        """
        Render as an HTML hex viewer.

        Args:
            highlights: dict mapping {byte_offset: (color, label)} for annotation.
        """
        lines_html = []
        for line in self.lines:
            # Build hex cells with optional highlight
            cells = []
            for i, b in enumerate(line.raw_bytes):
                off = line.offset + i
                cell_class = ""
                title = ""
                if highlights and off in highlights:
                    color, label = highlights[off]
                    cell_class = f' style="background:{color}"'
                    title = f' title="{label}"'
                cells.append(
                    f'<span class="hex-cell"{cell_class}{title}>'
                    f'{b:02X}</span>'
                )

            lines_html.append(
                f'<div class="hex-line">'
                f'<span class="hex-offset">{line.offset:08X}</span>'
                f'<span class="hex-data">{" ".join(cells)}</span>'
                f'<span class="hex-ascii">{_escape_ascii(line.ascii_repr)}</span>'
                f'</div>'
            )

        return "\n".join(lines_html)


# ─── Generator ───────────────────────────────────────────────

def generate_hex_view(
    data: bytes,
    page: int = 0,
    page_size: int = 64,       # lines per page (64 lines * 16 bytes = 1024 bytes)
    bytes_per_line: int = 16,
    offset_start: int = 0,     # starting offset label
) -> HexView:
    """
    Generate a paginated hex view of binary data.

    Args:
        data: raw bytes to display
        page: zero-indexed page number
        page_size: number of lines per page
        bytes_per_line: bytes shown per line (default 16)
        offset_start: label for the first byte offset

    Returns:
        HexView with the rendered lines and pagination metadata.
    """
    bpl = bytes_per_line
    total_bytes = len(data)
    total_lines = (total_bytes + bpl - 1) // bpl
    total_pages = max(1, (total_lines + page_size - 1) // page_size)

    # Clamp page
    page = max(0, min(page, total_pages - 1))

    start_line = page * page_size
    end_line = min(start_line + page_size, total_lines)

    lines: list[HexLine] = []
    for i in range(start_line, end_line):
        off = i * bpl
        chunk = data[off:off + bpl]

        hex_str = " ".join(f"{b:02X}" for b in chunk)
        # Pad short last line
        if len(chunk) < bpl:
            hex_str += "   " * (bpl - len(chunk))
        ascii_str = "".join(
            chr(b) if 0x20 <= b < 0x7F else "."
            for b in chunk
        )

        lines.append(HexLine(
            offset=off + offset_start,
            hex_bytes=hex_str,
            ascii_repr=ascii_str,
            raw_bytes=chunk,
        ))

    return HexView(
        lines=lines,
        total_bytes=total_bytes,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


def _escape_ascii(s: str) -> str:
    """Escape HTML-special characters in ASCII sidebar."""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
