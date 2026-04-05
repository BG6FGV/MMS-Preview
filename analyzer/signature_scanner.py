"""
analyzer/signature_scanner.py — Magic-byte signature detection and element extraction.

Scans arbitrary binary data for known file signatures and extracts
embedded elements (images, audio, video, SMIL, text, etc.).

This is the "expert mode" — works on any binary blob regardless of
whether it's a standard MMS PDU or a vendor-specific format.

Supported signatures:
  - JPEG:    FF D8 FF .. FF D9
  - PNG:     89 50 4E 47 0D 0A 1A 0A
  - GIF:     47 49 46 38
  - BMP:     42 4D
  - TIFF:    49 49 (LE) or 4D 4D (BE)
  - WBMP:    00 00 (first two bytes, followed by width/height)
  - 3GP/MP4: 66 74 79 70 ("ftyp")
  - AMR:     23 21 41 4D 52 ("#!AMR")
  - MIDI:    4D 54 68 64 ("MThd")
  - SMIL:    starts with "<" + XML-like content
  - Text:    detectable by high printable-char ratio
  - Nokia VCARD: begins with "BEGIN:VCARD"
  - DRM:     DRMContent or DRM Rights objects
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Optional


# ─── Signature definitions ───────────────────────────────────

@dataclass(frozen=True, slots=True)
class Signature:
    """A file signature (magic bytes)."""
    name: str            # human-readable name
    mime: str            # MIME type
    extension: str       # file extension
    head: bytes = b""   # signature at the start (empty if using head_pattern)
    tail: Optional[bytes] = None   # optional end marker
    head_pattern: Optional[bytes] = None  # regex pattern for head (if head is not fixed)

    def match_head(self, data: bytes) -> int:
        """
        Check if data starts with this signature.
        Returns length of matched head bytes, or 0 if no match.
        """
        if self.head_pattern:
            m = re.match(self.head_pattern, data, re.DOTALL)
            return m.end() if m else 0
        if data.startswith(self.head):
            return len(self.head)
        return 0

    def find_embedded(self, data: bytes) -> list[tuple[int, int]]:
        """
        Find all occurrences of this signature in data.
        Returns list of (start_offset, end_offset) pairs.

        For signatures with a tail marker, finds head..tail pairs.
        For signatures with only a head, returns (start, estimated_end).
        """
        results = []
        pos = 0
        while pos < len(data):
            if self.head_pattern:
                m = re.search(self.head_pattern, data[pos:], re.DOTALL)
                if not m:
                    break
                start = pos + m.start()
                head_len = m.end() - m.start()
                pos = start + 1
            else:
                idx = data.find(self.head, pos)
                if idx < 0:
                    break
                start = idx
                head_len = len(self.head)
                pos = idx + 1

            # Find end
            end = None
            if self.tail:
                tail_idx = data.find(self.tail, start + head_len)
                if tail_idx >= 0:
                    end = tail_idx + len(self.tail)
                else:
                    end = None  # incomplete, still report it
            else:
                # Estimate end based on format-specific logic
                end = _estimate_end(data, start, head_len, self)

            results.append((start, end))

        return results


# ─── Known signatures ────────────────────────────────────────

SIGNATURES: list[Signature] = [
    # ── Images ──
    Signature(
        name="JPEG", mime="image/jpeg", extension=".jpg",
        head=b"\xFF\xD8\xFF",
        tail=b"\xFF\xD9",
    ),
    Signature(
        name="PNG", mime="image/png", extension=".png",
        head=b"\x89PNG\r\n\x1A\n",
    ),
    Signature(
        name="GIF87a", mime="image/gif", extension=".gif",
        head=b"GIF87a",
    ),
    Signature(
        name="GIF89a", mime="image/gif", extension=".gif",
        head=b"GIF89a",
    ),
    Signature(
        name="BMP", mime="image/bmp", extension=".bmp",
        head=b"BM",
    ),
    Signature(
        name="TIFF-LE", mime="image/tiff", extension=".tif",
        head=b"II\x2A\x00",
    ),
    Signature(
        name="TIFF-BE", mime="image/tiff", extension=".tif",
        head=b"MM\x00\x2A",
    ),
    # WBMP: 0x00 (type) 0x00 (fixed-header) + at least 2 bytes width/height
    # Use head_pattern to avoid false positives from bare \x00\x00
    Signature(
        name="WBMP", mime="image/vnd.wap.wbmp", extension=".wbmp",
        head_pattern=rb"\x00\x00[\x00-\x7F][\x00-\x7F]",  # type=0 + fixhdr=0 + width + height (single-octet)
    ),
    # ── Audio/Video ──
    Signature(
        name="3GP/MP4", mime="video/3gpp", extension=".3gp",
        head=b"ftyp",
    ),
    Signature(
        name="AMR", mime="audio/amr", extension=".amr",
        head=b"#!AMR",
    ),
    Signature(
        name="MIDI", mime="audio/midi", extension=".mid",
        head=b"MThd",
    ),
    Signature(
        name="WAV", mime="audio/wav", extension=".wav",
        head=b"RIFF",
    ),
    Signature(
        name="AAC", mime="audio/aac", extension=".aac",
        head=b"\xFF\xF1",
    ),
    Signature(
        name="MP3-ID3", mime="audio/mpeg", extension=".mp3",
        head=b"ID3",
    ),
    Signature(
        name="MP3-Sync", mime="audio/mpeg", extension=".mp3",
        head=b"\xFF\xFB",
    ),
    Signature(
        name="OGG", mime="audio/ogg", extension=".ogg",
        head=b"OggS",
    ),
    # ── Documents / Data ──
    Signature(
        name="SMIL", mime="application/smil", extension=".smil",
        head_pattern=rb"(?s)^\s*<\?xml.*?<smil|<\s*smil",
    ),
    Signature(
        name="VCARD", mime="text/vcard", extension=".vcf",
        head=b"BEGIN:VCARD",
        tail=b"END:VCARD",
    ),
    Signature(
        name="DRM-CF", mime="application/vnd.oma.drm.content", extension=".dcf",
        head=b"--\r\nContent-Type: application/vnd.oma.drm.content",
    ),
    # ── MMS-specific ──
    Signature(
        name="MMS-PDU", mime="application/vnd.wap.mms-message", extension=".mms",
        head=b"\x8C\x84",  # v1.2 Message-Type m_retrieve_conf
    ),
]


# ─── Scan result ─────────────────────────────────────────────

@dataclass
class ScannedElement:
    """One element found by signature scanning."""
    name: str              # signature name (e.g. "JPEG")
    mime: str              # MIME type
    extension: str         # suggested extension
    offset: int            # byte offset in the source data
    size: int              # byte size (None if unknown)
    data: bytes            # extracted bytes (or empty if size unknown)
    preview_data: bytes    # first few KB for preview
    confidence: str        # "high" | "medium" | "low"
    notes: str = ""        # extra info

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "mime": self.mime,
            "extension": self.extension,
            "offset": self.offset,
            "size": self.size,
            "confidence": self.confidence,
            "notes": self.notes,
        }


@dataclass
class ScanResult:
    """Result of scanning binary data for signatures."""
    elements: list = field(default_factory=list)  # list[ScannedElement]
    total_signatures_checked: int = 0
    notes: list = field(default_factory=list)     # general notes

    def to_dict(self) -> dict:
        return {
            "elements": [e.to_dict() for e in self.elements],
            "totalSignaturesChecked": self.total_signatures_checked,
            "notes": self.notes,
            "summary": _summarize(self.elements),
        }


# ─── Public API ──────────────────────────────────────────────

def scan_signatures(data: bytes, max_preview: int = 32768) -> ScanResult:
    """
    Scan binary data for all known file signatures.

    For each signature type, finds all embedded occurrences.
    Extracts data for preview purposes.

    Args:
        data: raw binary data
        max_preview: maximum bytes to keep for preview per element

    Returns:
        ScanResult with all found elements.
    """
    result = ScanResult(total_signatures_checked=len(SIGNATURES))
    seen_ranges: list[tuple[int, int]] = []  # track to avoid duplicates

    for sig in SIGNATURES:
        matches = sig.find_embedded(data)

        for start, end in matches:
            # Skip if this range overlaps with an already-found element
            if _overlaps(start, end or start + 1, seen_ranges):
                continue

            size = (end - start) if end else None
            extract_size = min(size or len(data) - start, max_preview) if size else min(len(data) - start, max_preview)
            extracted = data[start:start + extract_size] if size else data[start:start + extract_size]

            # For GIF without known end, try to truncate at trailer (0x3B)
            if sig.name in ("GIF87a", "GIF89a") and not end and extracted:
                # Search for GIF trailer from the end
                for ti in range(len(extracted) - 1, 0, -1):
                    if extracted[ti] == 0x3B:
                        extracted = extracted[:ti + 1]
                        size = ti + 1
                        break

            # Skip WBMP matches that are clearly false positives
            # WBMP's signature (00 00) is too short and matches everywhere.
            # Only report WBMP at the start of data or right at a known boundary.
            if sig.name == "WBMP" and start > 0:
                continue

            # Determine confidence
            if end is not None and size and size > 0:
                confidence = "high"
            elif start == 0:
                confidence = "high"
            else:
                confidence = "medium"

            element = ScannedElement(
                name=sig.name,
                mime=sig.mime,
                extension=sig.extension,
                offset=start,
                size=size,
                data=extracted,
                preview_data=extracted[:max_preview],
                confidence=confidence,
            )

            # Add format-specific notes
            _add_notes(element, data, start, end)

            result.elements.append(element)
            if end:
                seen_ranges.append((start, end))

    # Also try to detect text segments (SMIL/XML/text/plain)
    _scan_text_segments(data, result, seen_ranges)

    # Sort by offset
    result.elements.sort(key=lambda e: e.offset)

    return result


# ─── Internal helpers ────────────────────────────────────────

def _estimate_end(
    data: bytes, start: int, head_len: int, sig: Signature,
) -> Optional[int]:
    """Estimate end offset for signatures without a tail marker."""
    remaining = len(data) - start

    if sig.name == "3GP/MP4":
        # Parse ftyp box: 4 bytes size + "ftyp" + major_brand + minor_version + compatible
        if remaining >= 8:
            box_size = struct.unpack(">I", data[start:start + 4])[0]
            if box_size > 0 and box_size < remaining:
                return start + box_size
        return None

    if sig.name in ("TIFF-LE", "TIFF-BE"):
        # Parse TIFF IFD for image size estimate
        try:
            ifd_offset = struct.unpack(">I", data[start + 4:start + 8])[0]
            if 0 < ifd_offset < remaining - 2:
                num_entries = struct.unpack(">H", data[start + ifd_offset:start + ifd_offset + 2])[0]
                ifd_size = 2 + num_entries * 12 + 4  # count + entries + next IFD
                return start + ifd_offset + ifd_size
        except (struct.error, IndexError):
            pass
        return None

    if sig.name == "WAV":
        # RIFF chunk: 4 (size) + 4 (WAVE) + sub-chunks
        if remaining >= 8:
            riff_size = struct.unpack("<I", data[start + 4:start + 8])[0] + 8
            if 0 < riff_size <= remaining:
                return start + riff_size
        return None

    if sig.name == "WBMP":
        # WBMP header: type(1) + fixed-header(1) + width + height + data
        if remaining >= 4:
            try:
                w = data[start + 2]
                # Width is multi-octet, simplified: skip for now
                return None
            except IndexError:
                return None
        return None

    if sig.name in ("GIF87a", "GIF89a"):
        # Parse GIF blocks to find actual end (trailer 0x3B)
        # GIF header: 6 bytes, then Logical Screen Descriptor (7 bytes)
        try:
            pos = start + 6 + 7  # skip header + LSD
            if pos >= len(data):
                return None
            # Global Color Table
            packed = data[start + 10]
            gct_flag = (packed >> 7) & 1
            if gct_flag:
                gct_size = 3 * (2 ** ((packed & 0x07) + 1))
                pos += gct_size
            # Skip blocks until trailer (0x3B)
            max_scan = min(pos + 50_000, len(data))  # safety limit
            while pos < max_scan:
                block_type = data[pos]
                pos += 1
                if block_type == 0x3B:  # trailer
                    return pos
                if block_type == 0x21:  # extension
                    if pos >= len(data):
                        break
                    pos += 1  # skip label
                    # Skip sub-blocks
                    while pos < len(data):
                        sub_size = data[pos]
                        pos += 1
                        if sub_size == 0:
                            break
                        pos += sub_size
                elif block_type == 0x2C:  # image descriptor
                    pos += 8  # skip descriptor
                    if pos >= len(data):
                        break
                    # Local Color Table
                    packed_img = data[pos - 1]
                    lct_flag = (packed_img >> 7) & 1
                    if lct_flag:
                        lct_size = 3 * (2 ** ((packed_img & 0x07) + 1))
                        pos += lct_size
                    # LZW min code size + sub-blocks
                    if pos >= len(data):
                        break
                    pos += 1  # LZW min code size
                    while pos < len(data):
                        sub_size = data[pos]
                        pos += 1
                        if sub_size == 0:
                            break
                        pos += sub_size
                else:
                    break  # unknown block, stop
        except (IndexError, ValueError):
            pass
        return None

    if sig.name == "MP3-ID3":
        # ID3v2 header: 10 bytes header, size in bytes 6-9 (syncsafe)
        if remaining >= 10:
            size_bytes = data[start + 6:start + 10]
            size = (size_bytes[0] << 21) | (size_bytes[1] << 14) | (size_bytes[2] << 7) | size_bytes[3]
            return start + 10 + size
        return None

    # For other types, no reliable end estimate without parsing the full format
    return None


def _add_notes(
    element: ScannedElement, data: bytes, start: int, end: Optional[int],
):
    """Add format-specific notes to a scanned element."""
    try:
        if element.mime == "image/jpeg" and element.data:
            # Try to read JPEG dimensions from JFIF/EXIF
            _note_jpeg_dimensions(element, element.data)
        elif element.mime == "image/gif" and element.data:
            _note_gif_dimensions(element, element.data)
        elif element.mime == "image/png" and element.data:
            _note_png_dimensions(element, element.data)
    except Exception:
        pass


def _note_jpeg_dimensions(element: ScannedElement, data: bytes):
    """Extract JPEG image dimensions from SOF marker."""
    pos = 2  # skip FF D8
    while pos < len(data) - 1:
        if data[pos] != 0xFF:
            break
        marker = data[pos + 1]
        if marker == 0xDA:  # SOS — start of scan, no more metadata
            break
        if 0xC0 <= marker <= 0xCF and marker != 0xC4 and marker != 0xC8:
            # SOF marker — contains dimensions
            if pos + 9 < len(data):
                h = (data[pos + 5] << 8) | data[pos + 6]
                w = (data[pos + 7] << 8) | data[pos + 8]
                element.notes = f"{w} x {h} px"
            break
        if pos + 3 < len(data):
            seg_len = (data[pos + 2] << 8) | data[pos + 3]
            pos += 2 + seg_len
        else:
            break


def _note_gif_dimensions(element: ScannedElement, data: bytes):
    """Extract GIF image dimensions."""
    if len(data) >= 10:
        w = data[6] | (data[7] << 8)
        h = data[8] | (data[9] << 8)
        element.notes = f"{w} x {h} px"


def _note_png_dimensions(element: ScannedElement, data: bytes):
    """Extract PNG image dimensions from IHDR chunk."""
    if len(data) >= 24:
        w = struct.unpack(">I", data[16:20])[0]
        h = struct.unpack(">I", data[20:24])[0]
        element.notes = f"{w} x {h} px"


def _scan_text_segments(
    data: bytes, result: ScanResult, seen: list[tuple[int, int]],
):
    """
    Find embedded text segments (SMIL/XML, plain text) that might not
    have been caught by signature scanners.

    Looks for null-terminated text strings common in MMS:
      filename.txt\x00...filename.txt
    """
    # Search for SMIL-like XML content
    smil_pattern = re.compile(rb"(?s)<\s*(?:smil|par|img|text|audio|video|ref)\b")
    for m in smil_pattern.finditer(data):
        start = max(0, m.start() - 100)
        # Find a reasonable start: look back for "<" or null
        while start > 0 and data[start - 1:start] not in (b"<", b"\x00"):
            start -= 1
            if m.start() - start > 200:
                start = m.start()
                break

        # Find end: look for closing </smil> or reasonable boundary
        end_match = re.search(rb"</\s*smil\s*>", data[m.start():], re.IGNORECASE)
        end = (m.start() + end_match.end()) if end_match else min(m.start() + 8192, len(data))

        if not _overlaps(start, end, seen) and end - start > 10:
            element = ScannedElement(
                name="SMIL-Embedded",
                mime="application/smil",
                extension=".smil",
                offset=start,
                size=end - start,
                data=data[start:end],
                preview_data=data[start:end],
                confidence="medium",
                notes="Found by XML pattern search",
            )
            result.elements.append(element)
            seen.append((start, end))
            break  # usually only one SMIL


def _overlaps(
    start: int, end: int, ranges: list[tuple[int, int]],
) -> bool:
    """Check if [start, end) overlaps with any existing range."""
    for s, e in ranges:
        if start < e and end > s:
            return True
    return False


def _summarize(elements: list[ScannedElement]) -> dict:
    """Generate a summary of found elements by type."""
    summary: dict[str, int] = {}
    for e in elements:
        key = e.name
        summary[key] = summary.get(key, 0) + 1
    return summary
