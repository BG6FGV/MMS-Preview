"""
analyzer/special_parser.py — Vendor-specific MMS backup format handlers.

Many early Linux phones (Nokia, Sony Ericsson, Samsung, Motorola) used
proprietary PC suite software to back up MMS messages. These backups
often encode MMS data in custom containers that differ from the standard
OMA MMS PDU format.

This module attempts to detect and parse known vendor formats.

Known vendor formats:
  - Nokia .mms (Nokia PC Suite / Ovi Suite)
  - Sony Ericsson .semc / Backup format
  - Samsung .sme / Kies backup
  - Motorola Backup format
  - Generic: raw concatenated multipart data
  - Generic: MIME-wrapped email format (some Android backups)

Strategy:
  1. Try standard OMA PDU first (handled by parser/mms_parser.py)
  2. If that fails, try each vendor format detector
  3. If all fail, fall back to signature scanning (analyzer/signature_scanner.py)
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Optional

from domain.entities import MmsPart
from domain.value_objects import ContentType


# ─── Detection result ────────────────────────────────────────

@dataclass
class SpecialParseResult:
    """Result from a special format parser."""
    format_name: str             # e.g. "Nokia PC Suite"
    format_version: str = ""     # version if detected
    success: bool = False
    parts: list = field(default_factory=list)  # list[MmsPart]
    raw_headers: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "formatName": self.format_name,
            "formatVersion": self.format_version,
            "success": self.success,
            "partCount": len(self.parts),
            "parts": [
                {
                    "index": p.index,
                    "contentType": p.content_type.mime,
                    "size": p.size,
                    "filename": p.suggested_filename,
                    "contentId": p.content_id,
                }
                for p in self.parts
            ],
            "headers": self.raw_headers,
            "notes": self.notes,
            "error": self.error,
        }


# ─── Vendor format detectors ─────────────────────────────────

def detect_nokia_format(data: bytes) -> Optional[SpecialParseResult]:
    """
    Detect Nokia PC Suite / Ovi Suite MMS backup format.

    Nokia .mms files from PC Suite typically start with the standard
    OMA MMS PDU (0x8C 0x84), but some Nokia-specific backups wrap
    the PDU in a proprietary header:
      - 4 bytes: header length
      - N bytes: header data (often XML or binary metadata)
      - Rest: standard MMS PDU
    """
    # Check for Nokia wrapper: starts with a small length field
    if len(data) < 8:
        return None

    # Some Nokia files start with "BEGIN:VCALENDAR" or have a B64 PDU
    # Check for common Nokia markers
    head = data[:64]

    # Nokia backup XML format: <MMSMessage>...</MMSMessage>
    if b"<MMSMessage" in head or b"mms-message" in head.lower():
        return _parse_nokia_xml(data)

    # Nokia .mms with wrapper header
    # Try reading first 4 bytes as a length
    wrapper_len = struct.unpack(">I", data[:4])[0]
    if 8 < wrapper_len < len(data) and wrapper_len < 65536:
        # Check if the data after the wrapper looks like MMS PDU
        pdu_start = data[wrapper_len:wrapper_len + 4]
        if pdu_start[0] == 0x8C:
            result = SpecialParseResult(
                format_name="Nokia PC Suite",
                format_version="wrapped",
                notes=[f"Wrapper header: {wrapper_len} bytes"],
            )
            # Parse the wrapped PDU
            try:
                from parser.mms_parser import parse_mms
                msg = parse_mms(data[wrapper_len:])
                result.success = True
                result.parts = msg.parts
                result.raw_headers = {"Wrapped PDU at offset": wrapper_len}
            except Exception as e:
                result.error = str(e)
            return result

    return None


def _parse_nokia_xml(data: bytes) -> SpecialParseResult:
    """Parse Nokia XML-wrapped MMS backup."""
    result = SpecialParseResult(format_name="Nokia XML Backup", notes=[])

    try:
        text = data.decode("utf-8", errors="replace")

        # Extract base64-encoded PDU
        b64_pattern = re.compile(
            r'(?:<Content>|<Data>|<MMSData>|<PDU>)(.*?)(?:</Content>|</Data>|</MMSData>|</PDU>)',
            re.DOTALL,
        )
        m = b64_pattern.search(text)

        if m:
            import base64
            b64_data = re.sub(r'\s+', '', m.group(1))
            pdu_data = base64.b64decode(b64_data)
            result.notes.append(f"Found base64 PDU: {len(pdu_data)} bytes")

            from parser.mms_parser import parse_mms
            msg = parse_mms(pdu_data)
            result.success = True
            result.parts = msg.parts
            return result

        # Try to find SMIL and media URLs in the XML
        smil_match = re.search(r'(?:<SMIL>|<Smil>)(.*?)(?:</SMIL>|</Smil>)', text, re.DOTALL | re.IGNORECASE)
        if smil_match:
            smil_data = smil_match.group(1).encode("utf-8")
            result.parts.append(MmsPart(
                index=0,
                content_type=ContentType(type="application/smil"),
                data=smil_data,
            ))
            result.notes.append("Extracted SMIL from XML")

        # Extract attachment references
        url_pattern = re.compile(r'(?:<Attachment|<File)[^>]*(?:href|src|location)="([^"]+)"', re.IGNORECASE)
        for i, m in enumerate(url_pattern.finditer(text)):
            result.parts.append(MmsPart(
                index=len(result.parts),
                content_type=ContentType(type="application/octet-stream"),
                data=m.group(1).encode("utf-8"),
                header_extras={"_url_ref": m.group(1)},
            ))
            result.notes.append(f"Found attachment reference: {m.group(1)}")

        if result.parts:
            result.success = True

    except Exception as e:
        result.error = str(e)

    return result


def detect_mime_wrapped(data: bytes) -> Optional[SpecialParseResult]:
    """
    Detect MIME-wrapped MMS (email-like format).

    Some Android backups and some vendor tools export MMS as:
      MIME-Version: 1.0
      Content-Type: multipart/mixed; boundary=...
      ...
    """
    head = data[:512]
    try:
        text = head.decode("ascii", errors="replace")
    except Exception:
        return None

    if "Content-Type:" not in text and "content-type:" not in text:
        return None

    if "multipart/" not in text.lower():
        return None

    result = SpecialParseResult(format_name="MIME-wrapped", notes=["Detected MIME multipart format"])

    try:
        # Parse the MIME structure
        from email import policy
        from email.parser import BytesParser
        msg = BytesParser(policy=policy.compat32).parsebytes(data)

        # Walk parts
        idx = 0
        for part in msg.walk():
            ct = part.get_content_type()
            if part.is_multipart():
                continue

            payload = part.get_payload(decode=True)
            if payload is None:
                payload = b""

            content_id = part.get("Content-ID", "")
            content_loc = part.get("Content-Location", "")
            filename = part.get_filename() or ""

            result.parts.append(MmsPart(
                index=idx,
                content_type=ContentType(type=ct or "application/octet-stream"),
                content_id=content_id,
                content_location=content_loc or filename,
                data=payload,
                header_extras={"_filename": filename} if filename else {},
            ))
            idx += 1

        if result.parts:
            result.success = True
            result.notes.append(f"Extracted {idx} MIME parts")

    except Exception as e:
        result.error = str(e)

    return result


def detect_android_sqlite_dump(data: bytes) -> Optional[SpecialParseResult]:
    """
    Detect Android telephony.db partial dump.

    Some backup tools export MMS as a SQLite database dump containing
    the pdu column from the 'pdu' table.
    """
    if len(data) < 16:
        return None

    # SQLite header
    if data[:16] == b"SQLite format 3\x00":
        return SpecialParseResult(
            format_name="Android SQLite DB",
            notes=["Detected SQLite database. Use sqlite3 tool to extract pdu column."],
            error="SQLite databases require a SQLite reader, not binary parsing.",
        )

    return None


def detect_no_numparts_mms(data: bytes) -> Optional[SpecialParseResult]:
    """
    Detect MMS files that lack a num_parts byte prefix.

    Some Android MMS backups (especially from Sony Ericsson and certain
    Samsung devices) store the MMS PDU body without the standard
    uint8 num_parts prefix. The body starts directly with:
      [uintvar headers_length] [uintvar data_length] [headers] [data] ...

    Detection heuristic:
      - File starts with 0x00 0x00 followed by a known MMS message-type
        byte (0x82=notification, 0x84=retrieve_conf, 0x94=m_retrieve_conf
        in v1.1 encoding)
      - OR the file contains a SMIL Content-Location ("application/smil")
        near the start (within the first 64 bytes)
      - Standard parse returns 0 parts

    Body format (no num_parts):
      Repeated:
        uintvar  headers_length
        uintvar  data_length
        <headers_length bytes of WSP part headers>
        <data_length bytes of part data>

    Part headers contain:
      Content-Type (0x1E=JPEG, 0x33=multipart/related, etc.)
      Content-Location (0x8E): filename
      Content-ID (0x85 or raw string): reference ID
      Various params (Charset, Name, Start, etc.)
    """
    if len(data) < 32:
        return None

    # Check for the proprietary 2-byte null prefix pattern
    # followed by a known message-type byte in the third position
    msg_type_bytes = {0x82, 0x84, 0x86, 0x88, 0x94, 0x95, 0x96}
    starts_with_null_prefix = (
        data[0] == 0x00
        and data[1] == 0x00
        and data[2] in msg_type_bytes
    )

    # Also check for "application/smil" Content-Location in the first 64 bytes
    has_smil_header = b"application/smil" in data[:64]

    # Verify standard parse fails or returns 0 parts
    standard_ok = False
    try:
        from parser.mms_parser import parse_mms
        msg = parse_mms(data)
        if len(msg.parts) > 0:
            standard_ok = True
    except Exception:
        pass

    if (starts_with_null_prefix or has_smil_header) and not standard_ok:
        return _parse_no_numparts_body(data)

    return None


def _parse_no_numparts_body(data: bytes) -> SpecialParseResult:
    """
    Parse MMS body that lacks a num_parts byte prefix.

    Strategy:
    1. Determine body start by scanning for the first valid
       uintvar pair (headers_length, data_length) followed by
       recognizable WSP part header bytes.
    2. Parse parts sequentially until we run out of data.
    """
    result = SpecialParseResult(
        format_name="No-num-parts MMS",
        format_version="vendor",
        notes=[],
    )

    # Find the body start. The proprietary header is typically 16-18 bytes.
    # We scan for the first position where a uintvar pair followed by
    # a valid WSP Content-Type byte yields consistent results.
    body_offset = _find_body_start(data)
    if body_offset is None:
        result.error = "Could not locate body start"
        return result

    result.notes.append(f"Body starts at offset 0x{body_offset:X}")

    # Parse parts
    pos = body_offset
    part_idx = 0

    while pos < len(data) - 4:
        try:
            from parser.wsp_codec import ByteStream, CONTENT_TYPE_WELL_KNOWN

            buf = ByteStream(data[pos:])
            hdr_len = buf.read_uintvar()
            data_len = buf.read_uintvar()

            # Sanity checks
            if hdr_len < 1 or hdr_len > 10000:
                break
            if data_len < 0 or data_len > len(data):
                break

            hdr_start = pos + buf.pos
            hdr_end = hdr_start + hdr_len
            data_start = hdr_end
            data_end = hdr_end + data_len

            if data_end > len(data):
                result.notes.append(f"Part {part_idx}: data truncated (expected {data_len}B, got {len(data) - data_start}B)")
                data_end = len(data)

            # Parse part headers
            part_ct = "application/octet-stream"
            content_id = None
            content_location = None
            ct_params = {}

            try:
                hdr_buf = ByteStream(data[hdr_start:hdr_end])

                # Read Content-Type
                b = hdr_buf.peek(1)[0]
                if b & 0x80:
                    code = hdr_buf.read_byte() & 0x7F
                    part_ct = CONTENT_TYPE_WELL_KNOWN.get(code, f"wsp-ct-0x{code:02X}")
                elif b <= 0x1E:
                    from parser.mms_parser import _decode_content_type
                    ct_len = hdr_buf.read_byte()
                    if ct_len == 0:
                        ct_len = hdr_buf.read_byte()  # try next
                    if ct_len > 0 and ct_len < hdr_len:
                        ct_info = _decode_content_type(hdr_buf, ct_len)
                        part_ct = ct_info["type"]
                        ct_params = ct_info.get("params", {})
                elif 0x20 <= b < 0x7F:
                    part_ct = hdr_buf.read_cstring()

                # Read remaining headers (Content-Location, Content-ID, etc.)
                while hdr_buf.remaining > 0:
                    hb = hdr_buf.peek(1)[0]
                    if hb == 0x00:
                        hdr_buf.read_byte()
                        continue
                    if hb == 0x8E:
                        hdr_buf.read_byte()
                        content_id = hdr_buf.read_cstring()
                    elif hb == 0x85:
                        hdr_buf.read_byte()
                        content_location = hdr_buf.read_cstring()
                    elif hb & 0x80:
                        hdr_buf.read_byte()
                        # Try to read a cstring value
                        try:
                            val = hdr_buf.read_cstring()
                        except Exception:
                            break
                    else:
                        try:
                            hdr_buf.read_cstring()
                        except Exception:
                            break
            except Exception as e:
                result.notes.append(f"Part {part_idx} header parse warning: {e}")

            # Extract part data
            part_data = data[data_start:data_end]

            # Generate filename from Content-Location or Content-ID
            filename = content_location or content_id or f"part_{part_idx}"
            if filename.startswith("<") and filename.endswith(">"):
                # Remove angle brackets from SMIL Start attribute
                filename = filename[1:-1]

            part = MmsPart(
                index=part_idx,
                content_type=ContentType(type=part_ct, params=ct_params),
                content_id=content_id,
                content_location=content_location,
                data=part_data,
                header_extras={"_filename": filename},
            )
            result.parts.append(part)
            part_idx += 1
            pos = data_end

        except Exception as e:
            result.notes.append(f"Parse error at offset 0x{pos:X}: {e}")
            break

    if result.parts:
        result.success = True
        result.notes.append(f"Extracted {len(result.parts)} parts")

    return result


def _find_body_start(data: bytes) -> Optional[int]:
    """
    Find the start of the WSP multipart body in a no-num-parts MMS file.

    The body is a sequence of [uintvar hdr_len][uintvar data_len][headers][data].
    We look for the first position where this pattern yields a valid part
    whose data area contains recognizable content (SMIL, JPEG, etc.).

    We also use the heuristic that the first part's header usually contains
    "application/smil" as a Content-Location or Content-Type reference.
    """
    from parser.wsp_codec import ByteStream

    best_offset = None
    best_score = -1

    for offset in range(0, min(48, len(data) - 8)):
        try:
            buf = ByteStream(data[offset:])
            hdr_len = buf.read_uintvar()
            data_len = buf.read_uintvar()

            # Reasonable range checks
            if hdr_len < 5 or hdr_len > 5000:
                continue
            if data_len < 5 or data_len > len(data):
                continue

            # Check that the uintvar encoding didn't consume too many bytes
            if buf.pos > 10:
                continue

            hdr_end = offset + buf.pos + hdr_len
            data_start = hdr_end
            data_end = data_start + data_len

            if data_end > len(data):
                continue

            # Check if the first byte of the "header" area is a valid CT start
            ct_byte = data[offset + buf.pos]
            is_valid_ct = (
                (ct_byte & 0x80)
                or (0x00 <= ct_byte <= 0x1E)
                or (0x20 <= ct_byte <= 0x7E)
            )
            if not is_valid_ct:
                continue

            # Score this candidate
            score = 0

            # Check for "application/smil" in the header area
            hdr_region = data[offset + buf.pos:min(offset + buf.pos + hdr_len, len(data))]
            if b"application/smil" in hdr_region:
                score += 100  # very strong signal

            # Check for "smil" content-type (0x33 = multipart/related, common for SMIL parts)
            if ct_byte == 0x33 or ct_byte == 0x23:
                score += 20

            # Check data area for known content signatures
            first_bytes = data[data_start:data_start + 4]
            if first_bytes[:1] == b'<':
                score += 30  # likely SMIL/XML
            if first_bytes[:2] == b'\xFF\xD8':
                score += 15  # JPEG
            if first_bytes[:4] in (b'\x89PNG', b'GIF8', b'GIF8'):
                score += 15

            # Check for Content-Location field (0x8E) in header
            if b'\x8E' in hdr_region:
                score += 10

            # Penalize very early offsets (< 4) that don't have strong signals
            if offset < 4 and score < 50:
                score -= 10

            if score > best_score:
                best_score = score
                best_offset = offset

        except Exception:
            continue

    return best_offset if best_score >= 10 else None


def detect_raw_concatenated(data: bytes) -> Optional[SpecialParseResult]:
    """
    Detect concatenated media files without MMS headers.

    Some vendor backups simply concatenate the media files:
      [image_data][text_data][smil_data]
    """
    result = SpecialParseResult(format_name="Raw Concatenated", notes=[])

    # Check if the file starts with a known media signature but NOT an MMS PDU
    if data[:2] == b"\xFF\xD8":
        result.notes.append("Starts with JPEG signature (not MMS PDU)")
    elif data[:4] == b"\x89PNG":
        result.notes.append("Starts with PNG signature (not MMS PDU)")
    elif data[:4] == b"GIF8":
        result.notes.append("Starts with GIF signature (not MMS PDU)")
    else:
        return None

    # Use signature scanner to find all embedded elements
    from analyzer.signature_scanner import scan_signatures
    scan = scan_signatures(data)

    for i, elem in enumerate(scan.elements):
        result.parts.append(MmsPart(
            index=i,
            content_type=ContentType(type=elem.mime),
            data=elem.data,
        ))

    if result.parts:
        result.success = True
        result.notes.append(f"Extracted {len(result.parts)} elements via signature scanning")

    return result


# ─── Public API ──────────────────────────────────────────────

def try_special_formats(data: bytes) -> list[SpecialParseResult]:
    """
    Attempt to detect and parse data as various vendor-specific formats.

    Returns a list of parse results (one per format tried).
    The first successful result is the most likely match.
    """
    detectors = [
        ("No-num-parts MMS", detect_no_numparts_mms),
        ("Nokia", detect_nokia_format),
        ("MIME-wrapped", detect_mime_wrapped),
        ("Android SQLite", detect_android_sqlite_dump),
        ("Raw Concatenated", detect_raw_concatenated),
    ]

    results = []
    for name, detector in detectors:
        try:
            result = detector(data)
            if result is not None:
                results.append(result)
                if result.success:
                    break  # stop at first success
        except Exception as e:
            results.append(SpecialParseResult(
                format_name=name,
                error=f"Detector exception: {e}",
            ))

    return results
