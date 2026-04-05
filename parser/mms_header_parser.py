"""
parser/mms_header_parser.py — MMS PDU header field parser.

Supports both OMA-MMS-ENC v1.2 and v1.3 field code assignments.

Key difference: v1.2 and v1.3 use different code assignments for
the same semantic fields (e.g. 0x8C = Message-Type in v1.2 but
Bcc in v1.3). The parser auto-detects version from the PDU structure.

References:
  OMA-MMS-ENC-V1_2-20050301-A     §7  PDU header fields (MMS Compiler uses this)
  OMA-TS-MMS-ENC-V1_3-20080128-C  §7  PDU header fields
"""

from __future__ import annotations

from typing import Optional

from domain.entities import (
    MmsHeader, MmsMessageType, MmsVersion, MessageClass, Priority,
)
from domain.value_objects import Address, ContentType, MmsTimestamp
from .wsp_codec import ByteStream, decode_content_type_full


# ─── v1.2 field codes (used by MMS Compiler) ─────────────

V12_FIELDS = {
    0x8C: "Message-Type",
    0x8D: "MMS-Version",
    0x84: "Content-Type",        # always the last header
    0x85: "Date",
    0x86: "Delivery-Report",
    0x87: "Expiry",
    0x88: "Message-Class",
    0x89: "From",
    0x8A: "Message-ID",
    0x8B: "Message-Size",
    0x96: "Subject",
    0x97: "To",
    0x98: "Transaction-ID",
}

# ─── v1.3 field codes ────────────────────────────────────

V13_FIELDS = {
    0x80: "Bcc",
    0x81: "Cc",
    0x82: "Content-Location",
    0x83: "Content-Type",
    0x84: "Date",
    0x85: "Delivery-Report",
    0x86: "Expiry",
    0x87: "From",
    0x89: "Message-Class",
    0x8A: "Message-ID",
    0x8B: "Message-Size",
    0x8C: "MMS-Version",
    0x8D: "Priority",
    0x8E: "Read-Reply",
    0x8F: "Report-Allowed",
    0x90: "Response-Status",
    0x91: "Response-Text",
    0x92: "Sender-Visibility",
    0x93: "Status",
    0x94: "Subject",
    0x95: "To",
    0x96: "Transaction-ID",
    0x97: "Retrieve-Status",
    0x98: "Retrieve-Text",
    0x99: "Content-Type",        # last header in v1.3
}


def _detect_version(buf: ByteStream) -> str:
    """
    Auto-detect whether this PDU uses v1.2 or v1.3 field codes.

    Strategy: peek at the first few bytes.
    - v1.2 always starts with 0x8C (Message-Type) followed by 0x84 (m_retrieve_conf)
    - v1.3 starts with 0x8C (Bcc in v1.3), but 0x8C is followed by a Bcc address,
      which typically starts with a length byte < 0x80 or 0x80 (insert-token).
      A m_retrieve_conf value (0x84) after 0x8C indicates v1.2.

    Heuristic: if byte[0]=0x8C and byte[1] is in 0x80-0x88 (known m_send_req / m_retrieve_conf etc),
    it's v1.2. Otherwise v1.3.
    """
    if buf.remaining < 2:
        return "v1.2"  # default
    b0, b1 = buf.data[0], buf.data[1]
    # In v1.2: 0x8C = Message-Type, next byte = message type value (0x80-0x8A)
    if b0 == 0x8C and 0x80 <= b1 <= 0x95:
        return "v1.2"
    # In v1.3: 0x8C = Bcc, next byte = length or address token
    return "v1.3"


# ─── Field value readers (semantic) ─────────────────────

def _read_message_type(buf: ByteStream, header: MmsHeader):
    val = buf.read_byte()
    header.message_type = MmsMessageType.from_code(val)


def _read_mms_version(buf: ByteStream, header: MmsHeader):
    val = buf.read_byte()
    header.mms_version = MmsVersion.from_code(val & 0x7F)


def _read_transaction_id(buf: ByteStream, header: MmsHeader):
    header.transaction_id = buf.read_cstring()


def _read_message_id(buf: ByteStream, header: MmsHeader):
    header.message_id = buf.read_cstring()


def _read_date(buf: ByteStream, header: MmsHeader):
    """Date: length-byte + long-integer (big-endian, seconds since epoch)."""
    length = buf.read_byte()
    if length == 0:
        return
    raw = buf.read(length)
    epoch = int.from_bytes(raw, "big")
    header.date = MmsTimestamp(raw_value=epoch)


def _read_from(buf: ByteStream, header: MmsHeader):
    """From: Value-length(Short-length) + Encoded-string-value."""
    # The From value starts with a value-length (WSP Short-length):
    #   0x00-0x1E = direct length
    #   0x1F      = uintvar follows
    length_byte = buf.read_byte()
    if length_byte == 0x1F:
        total_len = buf.read_uintvar()
    elif length_byte <= 0x1E:
        total_len = length_byte
    else:
        # Unexpected: treat as short direct value
        total_len = length_byte & 0x7F

    if total_len == 0:
        header.from_addr = Address.anonymous()
        return

    end = buf.pos + total_len
    token = buf.read_byte()

    if token == 0x80:
        # Insert-address-token: remaining = null-terminated display string
        try:
            addr = buf.read_cstring()
        except (ValueError, EOFError):
            addr = ""
        buf.pos = end
        header.from_addr = Address(address_type="PLMN", value=addr)
    elif token == 0x81:
        header.from_addr = Address.anonymous()
        buf.pos = end
    elif token == 0x82:
        try:
            addr = buf.read_cstring()
        except (ValueError, EOFError):
            addr = ""
        buf.pos = end
        header.from_addr = Address(address_type="email", value=addr)
    else:
        buf.pos -= 1
        try:
            addr = buf.read_cstring()
        except (ValueError, EOFError):
            addr = ""
        buf.pos = end
        header.from_addr = Address(address_type="PLMN", value=addr)


def _read_to(buf: ByteStream, header: MmsHeader):
    try:
        addr = buf.read_cstring()
        header.to_addr = Address(address_type="PLMN", value=addr)
    except (ValueError, EOFError):
        header.to_addr = Address(address_type="unknown", value="")


def _read_subject(buf: ByteStream, header: MmsHeader):
    header.subject = buf.read_cstring()


def _read_content_type(buf: ByteStream, header: MmsHeader):
    """Content-Type — last header field. Read value-length first, then CT body."""
    # In v1.2: after 0x84, read short-length to get total CT value length
    # In v1.3: after 0x99, same
    from .wsp_codec import ByteStream as BS

    # The next byte(s) encode the value-length of the Content-Type value
    start_pos = buf.pos
    vl_byte = buf.peek(1)[0]

    if vl_byte <= 0x1E:
        # Direct short-length
        ct_total_len = buf.read_byte()
    elif vl_byte == 0x1F:
        # Length-quote: uintvar follows
        buf.read_byte()
        ct_total_len = buf.read_uintvar()
    else:
        # High-bit value: might be the CT media type directly
        # This can happen with simple Content-Types
        # Fallback: try to decode what we can
        ct_total_len = buf.remaining  # consume rest

    # Now read exactly ct_total_len bytes of CT value
    ct_start = buf.pos
    media, params = decode_content_type_full(buf, total_len=ct_total_len)
    # Ensure we consumed exactly ct_total_len (important for body alignment)
    expected_end = ct_start + ct_total_len
    buf.pos = expected_end  # force align regardless

    header.content_type = ContentType(type=media, params=params)


def _read_message_class(buf: ByteStream, header: MmsHeader):
    b = buf.peek(1)[0]
    if b & 0x80:
        header.message_class = MessageClass(buf.read_byte())
    else:
        header.extras["Message-Class"] = buf.read_cstring()


def _read_priority(buf: ByteStream, header: MmsHeader):
    b = buf.peek(1)[0]
    if b & 0x80:
        header.priority = Priority(buf.read_byte())
    else:
        header.extras["Priority"] = buf.read_cstring()


def _read_delivery_report(buf: ByteStream, header: MmsHeader):
    header.delivery_report = buf.read_byte() != 0


def _read_read_reply(buf: ByteStream, header: MmsHeader):
    header.read_reply = buf.read_byte() != 0


def _read_report_allowed(buf: ByteStream, header: MmsHeader):
    header.report_allowed = buf.read_byte() != 0


def _read_message_size(buf: ByteStream, header: MmsHeader):
    # Long-integer
    length = buf.read_byte()
    if length > 0:
        raw = buf.read(length)
        header.message_size = int.from_bytes(raw, "big")


def _read_sender_visibility(buf: ByteStream, header: MmsHeader):
    header.sender_visibility = buf.read_byte() != 0


def _read_expiry(buf: ByteStream, header: MmsHeader):
    length = buf.read_byte()
    if length > 0:
        raw = buf.read(length)
        epoch = int.from_bytes(raw, "big")
        header.expiry = MmsTimestamp(raw_value=epoch)


def _read_status(buf: ByteStream, header: MmsHeader, label: str = "Status"):
    code = buf.read_byte()
    STATUS_CODES = {
        0x80: "Expired", 0x81: "Rejected", 0x82: "Unrecognised",
        0x83: "Indeterminate", 0x84: "Retrieved",
        0x85: "Error-transient-failure", 0x86: "Error-transient-network",
        0x87: "Error-permanent-failure", 0x88: "Error-permanent-service-denied",
    }
    header.extras[label] = STATUS_CODES.get(code, f"0x{code:02X}")


# Semantic field dispatch table
FIELD_READERS = {
    "Message-Type":      _read_message_type,
    "MMS-Version":       _read_mms_version,
    "Transaction-ID":    _read_transaction_id,
    "Message-ID":        _read_message_id,
    "Date":              _read_date,
    "From":              _read_from,
    "To":                _read_to,
    "Subject":           _read_subject,
    "Content-Type":      _read_content_type,
    "Message-Class":     _read_message_class,
    "Priority":          _read_priority,
    "Delivery-Report":   _read_delivery_report,
    "Read-Reply":        _read_read_reply,
    "Report-Allowed":    _read_report_allowed,
    "Message-Size":      _read_message_size,
    "Sender-Visibility": _read_sender_visibility,
    "Expiry":            _read_expiry,
    "Status":            lambda b, h: _read_status(b, h, "Status"),
    "Retrieve-Status":   lambda b, h: _read_status(b, h, "Retrieve-Status"),
    "Response-Status":   lambda b, h: _read_status(b, h, "Response-Status"),
    "Response-Text":     lambda b, h: _read_status(b, h, "Response-Text"),
}


# ─── Main entry ──────────────────────────────────────────

def parse_mms_headers(buf: ByteStream) -> MmsHeader:
    """
    Parse MMS PDU header fields.

    Auto-detects v1.2 vs v1.3 encoding. Stops at Content-Type
    (the boundary between headers and body).

    Returns a populated MmsHeader. buf.pos is at the start of body.
    """
    version = _detect_version(buf)
    field_table = V12_FIELDS if version == "v1.2" else V13_FIELDS

    header = MmsHeader()
    header.extras["_version"] = version

    while buf.remaining > 0:
        b = buf.peek(1)[0]

        # All MMS field codes have high bit set
        if not (b & 0x80):
            break

        field_code = buf.read_byte()
        field_name = field_table.get(field_code, f"field-0x{field_code:02X}")

        # Content-Type is always the last header field
        if field_name == "Content-Type":
            reader = FIELD_READERS.get("Content-Type")
            if reader:
                reader(buf, header)
            break

        # Dispatch to semantic reader
        reader = FIELD_READERS.get(field_name)
        if reader:
            try:
                reader(buf, header)
            except (EOFError, ValueError, IndexError) as exc:
                header.extras[f"_error_{field_name}"] = str(exc)
                break
        else:
            # Unknown field — try null-terminated string
            try:
                val = buf.read_cstring()
                header.extras[field_name] = val
            except (ValueError, EOFError):
                header.extras[field_name] = f"<binary at {buf.pos}>"
                break

    return header
