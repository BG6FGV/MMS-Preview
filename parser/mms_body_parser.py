"""
parser/mms_body_parser.py — MMS multipart body and SMIL parser.

Parses the WAP multipart/related body of an MMS message and extracts
the SMIL presentation layout.

References:
  WAP-230-WSP  §8.5  Multipart data
  OMA-MMS-ENC  §7.2  Content of m_retrieve_conf
  3GPP TS 26.140  §6  SMIL presentation
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Optional
from io import BytesIO

from domain.entities import MmsPart, SmilPresentation, SmilRegion, SmilPar, SmilMediaRef
from domain.value_objects import ContentType
from .wsp_codec import ByteStream, decode_content_type_full


def parse_multipart_body(buf: ByteStream, expected_type: str = "") -> list[MmsPart]:
    """
    Parse a WAP multipart/related body.

    Per WAP-230-WSP §8.5:
      - First byte: number of parts (uint8)
      - Each part: headers-length (uintvar), data-length (uintvar),
        part-headers (bytes), data (bytes)

    Returns list[MmsPart].
    """
    parts: list[MmsPart] = []
    num_parts = buf.read_byte()

    for i in range(num_parts):
        if buf.remaining == 0:
            break

        headers_len = buf.read_uintvar()
        data_len = buf.read_uintvar()
        header_end = buf.pos + headers_len

        # Parse part Content-Type
        content_type, ct_params = _parse_part_content_type(buf)

        # Parse remaining part headers (Content-ID, Content-Location, etc.)
        content_id: Optional[str] = None
        content_location: Optional[str] = None
        extras: dict = {}

        while buf.pos < header_end:
            if buf.remaining == 0:
                break
            hb = buf.peek(1)[0]
            if hb == 0x8E:
                # Content-ID (WSP part header code)
                buf.read_byte()
                content_id = buf.read_cstring()
            elif hb == 0x85:
                # Content-Location
                buf.read_byte()
                content_location = buf.read_cstring()
            elif hb == 0x80:
                buf.read_byte()
                extras["_quoted"] = True
            elif hb & 0x80:
                code = buf.read_byte()
                try:
                    extras[f"hdr-0x{code:02X}"] = buf.read_cstring()
                except (ValueError, EOFError):
                    break
            else:
                try:
                    extras["hdr-str"] = buf.read_cstring()
                except (ValueError, EOFError):
                    break

        # Align to data boundary
        buf.pos = header_end
        data = buf.read(data_len)

        parts.append(MmsPart(
            index=i,
            content_type=ContentType(type=content_type, params=ct_params),
            content_id=content_id,
            content_location=content_location,
            data=data,
            header_extras=extras,
        ))

    return parts


def _parse_part_content_type(buf: ByteStream) -> tuple[str, dict]:
    """Parse the Content-Type from the start of a part header."""
    b = buf.peek(1)[0]

    if b & 0x80:
        # Well-known media type
        code = buf.read_byte() & 0x7F
        from .wsp_codec import CONTENT_TYPE_WELL_KNOWN
        media = CONTENT_TYPE_WELL_KNOWN.get(code, f"wsp-ct-0x{code:02X}")
        return media, {}
    elif b <= 0x1F:
        # Length-encoded Content-Type
        return decode_content_type_full(buf)
    else:
        # Text-string Content-Type
        return buf.read_cstring(), {}


# ─── SMIL parser ──────────────────────────────────────────

def parse_smil(xml_text: str) -> SmilPresentation:
    """
    Parse a SMIL XML document and extract layout metadata.

    Returns a SmilPresentation with regions, root layout, and media references.
    """
    pres = SmilPresentation(raw_xml=xml_text)

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        # Malformed XML — try basic regex fallback
        return _parse_smil_fallback(xml_text)

    ns = ""  # SMIL typically uses no namespace

    # Parse <root-layout>
    for rl in root.iter(f"{ns}root-layout"):
        pres.root_width = rl.get("width", "")
        pres.root_height = rl.get("height", "")

    # Parse <region> elements
    for region_el in root.iter(f"{ns}region"):
        pres.regions.append(SmilRegion(
            id=region_el.get("id", ""),
            left=region_el.get("left", "0"),
            top=region_el.get("top", "0"),
            width=region_el.get("width", ""),
            height=region_el.get("height", ""),
            fit=region_el.get("fit", ""),
        ))

    # Parse <par> groups
    for par_el in root.iter(f"{ns}par"):
        dur = par_el.get("dur", "")
        media_refs: list[SmilMediaRef] = []

        # Media elements: img, text, audio, video, ref
        for tag in ("img", "text", "audio", "video", "ref"):
            for el in par_el.iter(f"{ns}{tag}"):
                src = el.get("src", "")
                region = el.get("region", "")
                alt = el.get("alt", "")
                media_refs.append(SmilMediaRef(
                    tag=tag,
                    src=src.strip("<>").rstrip(),
                    region=region,
                    alt=alt,
                ))

        if media_refs:
            pres.pars.append(SmilPar(duration=dur, media=media_refs))

    return pres


def _parse_smil_fallback(xml_text: str) -> SmilPresentation:
    """
    Basic regex-based SMIL parser for malformed XML.

    Extracts what it can without relying on ET parser.
    """
    pres = SmilPresentation(raw_xml=xml_text)

    # Root layout
    m = re.search(r'root-layout[^/]*/>', xml_text)
    if m:
        tag = m.group()
        for attr in ("width", "height"):
            val = re.search(rf'{attr}="([^"]*)"', tag)
            if val:
                setattr(pres, f"root_{attr}", val.group(1))

    # Regions
    for m in re.finditer(r'<region\s+([^>]+)/>', xml_text):
        attrs = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
        pres.regions.append(SmilRegion(
            id=attrs.get("id", ""),
            left=attrs.get("left", "0"),
            top=attrs.get("top", "0"),
            width=attrs.get("width", ""),
            height=attrs.get("height", ""),
            fit=attrs.get("fit", ""),
        ))

    # Par groups
    for m in re.finditer(r'<par([^>]*)>(.*?)</par>', xml_text, re.DOTALL):
        par_attrs = m.group(1)
        par_body = m.group(2)
        dur = re.search(r'dur="([^"]*)"', par_attrs)
        dur = dur.group(1) if dur else ""

        media_refs = []
        for tag in ("img", "text", "audio", "video", "ref"):
            for el in re.finditer(rf'<{tag}\s+([^>]+)/>', par_body):
                attrs = dict(re.findall(r'(\w+)="([^"]*)"', el.group(1)))
                src = attrs.get("src", "").strip("<>").rstrip()
                media_refs.append(SmilMediaRef(
                    tag=tag,
                    src=src,
                    region=attrs.get("region", ""),
                    alt=attrs.get("alt", ""),
                ))

        if media_refs:
            pres.pars.append(SmilPar(duration=dur, media=media_refs))

    return pres
