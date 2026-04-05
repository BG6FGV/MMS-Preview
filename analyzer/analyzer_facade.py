"""
analyzer/analyzer_facade.py — Unified analysis entry point.

Provides a single function `analyze_bytes` that combines:
  1. Standard OMA MMS parsing (parser/mms_parser.py)
  2. Special format detection (analyzer/special_parser.py)
  3. Expert mode: hex view + signature scanning (analyzer/hex_view.py, signature_scanner.py)

The web UI calls this via /analyze?mode=<standard|special|expert>
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from analyzer.hex_view import HexView, generate_hex_view
from analyzer.signature_scanner import ScanResult, scan_signatures
from analyzer.special_parser import SpecialParseResult, try_special_formats


# ─── Analysis result ─────────────────────────────────────────

@dataclass
class AnalysisResult:
    """Unified result from any analysis mode."""
    mode: str                          # "standard" | "special" | "expert"
    standard: Optional[dict] = None    # MMS parser result (if mode=standard)
    special: Optional[dict] = None     # special format results
    hex_view: Optional[dict] = None    # hex dump data (if mode=expert)
    scan: Optional[dict] = None        # signature scan results (if mode=expert)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "standard": self.standard,
            "special": self.special,
            "hexView": self.hex_view,
            "scan": self.scan,
            "error": self.error,
        }


# ─── Public API ──────────────────────────────────────────────

def analyze_bytes(
    data: bytes,
    mode: str = "standard",
    hex_page: int = 0,
) -> AnalysisResult:
    """
    Analyze binary data using the specified mode.

    Args:
        data: raw binary data
        mode: "standard" (OMA MMS PDU), "special" (vendor formats),
              or "expert" (hex + signature scanning)
        hex_page: page number for hex view (0-indexed, expert mode only)

    Returns:
        AnalysisResult with parsed/analyzed content.
    """
    if mode == "standard":
        return _analyze_standard(data)
    elif mode == "special":
        return _analyze_special(data)
    elif mode == "expert":
        return _analyze_expert(data, hex_page)
    else:
        return AnalysisResult(mode=mode, error=f"Unknown mode: {mode}")


# ─── Mode implementations ────────────────────────────────────

def _analyze_standard(data: bytes) -> AnalysisResult:
    """Standard OMA MMS PDU parsing with auto-fallback to Special."""
    import hashlib
    result = AnalysisResult(mode="standard")
    file_hash = hashlib.md5(data).hexdigest()[:12]

    std_dict = None

    try:
        from parser.mms_parser import parse_mms
        msg = parse_mms(data)
        std_dict = _serialize_message(msg)
    except Exception as e:
        result.error = f"Standard parse failed: {e}"

    # If standard parse yielded 0 parts, try special format as fallback
    if (std_dict is None or std_dict.get("meta", {}).get("partCount", 0) == 0):
        special_results = try_special_formats(data)
        for sr in special_results:
            if sr.success and sr.parts:
                std_dict = _serialize_special_parts(sr, data)
                break

    if std_dict is not None:
        std_dict["_fileHash"] = file_hash
        result.standard = std_dict

    return result


def _analyze_special(data: bytes) -> AnalysisResult:
    """Special format detection (vendor-specific)."""
    import hashlib
    result = AnalysisResult(mode="special")
    file_hash = hashlib.md5(data).hexdigest()[:12]

    # Try special format detectors
    special_results = try_special_formats(data)
    result.special = {
        "attempts": [r.to_dict() for r in special_results],
        "success": any(r.success for r in special_results),
        "_fileHash": file_hash,
    }

    # Also try standard parsing as fallback
    try:
        from parser.mms_parser import parse_mms
        msg = parse_mms(data)
        std_dict = _serialize_message(msg)
        std_dict["_fileHash"] = file_hash
        result.standard = std_dict
    except Exception:
        pass

    return result


def _analyze_expert(data: bytes, hex_page: int) -> AnalysisResult:
    """Expert mode: hex view + signature scanning."""
    import hashlib
    result = AnalysisResult(mode="expert")

    file_hash = hashlib.md5(data).hexdigest()[:12]

    # Generate hex view
    hex_view = generate_hex_view(data, page=hex_page)
    result.hex_view = {
        "_fileHash": file_hash,
        "totalBytes": hex_view.total_bytes,
        "page": hex_view.page,
        "pageSize": hex_view.page_size,
        "totalPages": hex_view.total_pages,
        "lines": [
            {
                "offset": line.offset,
                "hex": line.hex_bytes,
                "ascii": line.ascii_repr,
            }
            for line in hex_view.lines
        ],
    }

    # Scan for signatures
    scan = scan_signatures(data)
    scan_dict = scan.to_dict()
    scan_dict["_fileHash"] = file_hash
    result.scan = scan_dict

    # Build highlight map for hex view
    highlights = {}
    for elem in scan.elements:
        if elem.offset is not None:
            # Color code by type
            if elem.mime.startswith("image/"):
                color = "#6c8cff"
            elif elem.mime.startswith("audio/"):
                color = "#a78bfa"
            elif elem.mime.startswith("video/"):
                color = "#f87171"
            elif "smil" in elem.mime:
                color = "#fbbf24"
            elif elem.mime.startswith("text/"):
                color = "#34d399"
            else:
                color = "#888"
            highlights[elem.offset] = (color, f"{elem.name} @ offset {elem.offset}")
            if elem.size and elem.size > 0:
                end = elem.offset + elem.size - 1
                if end not in highlights:
                    highlights[end] = (color, f"{elem.name} end")
    if highlights:
        result.hex_view["highlights"] = {
            str(k): v for k, v in highlights.items()
        }

    return result


# ─── Serialization ───────────────────────────────────────────

def _serialize_message(msg) -> dict:
    """Serialize MmsMessage to a JSON-compatible dict."""
    h = msg.header
    ct = h.content_type

    parts_list = []
    for p in msg.parts:
        part_info = _serialize_part(p)
        parts_list.append(part_info)

    smil_data = None
    if msg.smil:
        s = msg.smil
        smil_data = {
            "rootWidth": s.root_width,
            "rootHeight": s.root_height,
            "regions": [
                {"id": r.id, "left": r.left, "top": r.top,
                 "width": r.width, "height": r.height, "fit": r.fit}
                for r in s.regions
            ],
            "pars": [
                {"duration": p.duration, "media": [
                    {"tag": m.tag, "src": m.src, "region": m.region, "alt": m.alt}
                    for m in p.media
                ]}
                for p in s.pars
            ],
        }

    return {
        "meta": {
            "fileSize": msg.total_size,
            "partCount": len(msg.parts),
            "version": h.mms_version.label if h.mms_version else "unknown",
            "type": h.message_type.name if h.message_type else "unknown",
        },
        "header": {
            "transactionId": h.transaction_id,
            "messageId": h.message_id,
            "date": h.date.iso8601 if h.date else None,
            "dateDisplay": h.date.display if h.date else None,
            "from": h.from_addr.value if h.from_addr else None,
            "fromType": h.from_addr.address_type if h.from_addr else None,
            "to": h.to_addr.value if h.to_addr else None,
            "subject": h.subject,
            "contentType": ct.mime if ct else None,
            "messageClass": h.message_class.name if h.message_class else None,
            "priority": h.priority.name if h.priority else None,
            "deliveryReport": h.delivery_report,
            "readReply": h.read_reply,
        },
        "parts": parts_list,
        "smil": smil_data,
    }


def _serialize_part(p) -> dict:
    """Serialize a single MmsPart to JSON-compatible dict with text preview."""
    part_info = {
        "index": p.index,
        "contentType": p.content_type.mime,
        "size": p.size,
        "filename": p.suggested_filename,
        "contentId": p.content_id,
        "contentLocation": p.content_location,
    }
    text = p.text_content()
    if text is not None:
        part_info["text"] = text[:8192]
    return part_info


def _serialize_special_parts(special_result, raw_data: bytes) -> dict:
    """
    Serialize a successful SpecialParseResult into the same format as
    _serialize_message, so the frontend can render it identically.

    Includes text content extraction and SMIL parsing.
    """
    import hashlib

    parts_list = []
    for p in special_result.parts:
        part_info = _serialize_part(p)
        parts_list.append(part_info)

    # Try to parse SMIL from the first smil part
    smil_data = None
    smil_part = None
    for p in special_result.parts:
        if p.content_type.is_smil and p.data:
            smil_part = p
            break

    if smil_part:
        try:
            smil_data = _parse_smil_xml(smil_part.data)
        except Exception:
            pass

    # Build header from raw PDU if possible
    header_info = {}
    try:
        from parser.mms_parser import parse_mms
        msg = parse_mms(raw_data)
        h = msg.header
        header_info = {
            "transactionId": h.transaction_id,
            "date": h.date.iso8601 if h.date else None,
            "dateDisplay": h.date.display if h.date else None,
            "from": h.from_addr.value if h.from_addr else None,
            "fromType": h.from_addr.address_type if h.from_addr else None,
            "to": h.to_addr.value if h.to_addr else None,
            "subject": h.subject,
        }
    except Exception:
        pass

    return {
        "meta": {
            "fileSize": len(raw_data),
            "partCount": len(parts_list),
            "version": "unknown",
            "type": special_result.format_name,
        },
        "header": header_info,
        "parts": parts_list,
        "smil": smil_data,
        "_specialFormat": special_result.format_name,
        "_specialNotes": special_result.notes,
    }


def _parse_smil_xml(smil_data: bytes) -> dict:
    """Parse SMIL XML and extract layout + timeline info."""
    import xml.etree.ElementTree as ET

    # Handle various SMIL namespaces
    root = ET.fromstring(smil_data)
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    def _tag(local):
        return ns + local

    smil_result = {
        "rootWidth": "",
        "rootHeight": "",
        "regions": [],
        "pars": [],
    }

    # Root layout
    layout = root.find(_tag("head"))
    if layout is None:
        layout = root
    layout_el = layout.find(_tag("layout"))
    if layout_el is not None:
        root_layout = layout_el.find(_tag("root-layout"))
        if root_layout is not None:
            smil_result["rootWidth"] = root_layout.get("width", "")
            smil_result["rootHeight"] = root_layout.get("height", "")

        for region_el in layout_el.findall(_tag("region")):
            smil_result["regions"].append({
                "id": region_el.get("id", ""),
                "left": region_el.get("left", "0"),
                "top": region_el.get("top", "0"),
                "width": region_el.get("width", "100%"),
                "height": region_el.get("height", "100%"),
                "fit": region_el.get("fit", ""),
            })

    # Timeline: <par> elements in <body>
    body = root.find(_tag("body"))
    if body is not None:
        for par in body.findall(_tag("par")):
            media_items = []
            for tag_name in ("img", "text", "audio", "video", "ref"):
                for elem in par.findall(_tag(tag_name)):
                    media_items.append({
                        "tag": tag_name,
                        "src": elem.get("src", ""),
                        "region": elem.get("region", ""),
                        "alt": elem.get("alt", ""),
                    })
            smil_result["pars"].append({
                "duration": par.get("dur", ""),
                "media": media_items,
            })

    return smil_result
