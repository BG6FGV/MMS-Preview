"""
parser/wsp_codec.py — WSP binary encoding primitives.

Low-level byte-level readers and WSP value decoders.
No domain knowledge — purely mechanical.

References:
  WAP-230-WSP-20010705-a  §8  Binary encoding of values
"""

from __future__ import annotations

from typing import Optional


# ─── Buffer ───────────────────────────────────────────────

class ByteStream:
    """Cursor-based byte stream reader."""

    __slots__ = ("data", "pos", "length")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.length = len(data)

    @property
    def remaining(self) -> int:
        return self.length - self.pos

    def peek(self, n: int = 1) -> bytes:
        return self.data[self.pos:self.pos + n]

    def read(self, n: int) -> bytes:
        if self.pos + n > self.length:
            raise EOFError(f"read({n}) at pos {self.pos}, buffer length {self.length}")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def read_byte(self) -> int:
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_cstring(self) -> str:
        """Read null-terminated string (WSP Text-string)."""
        end = self.data.index(0, self.pos)
        raw = self.data[self.pos:end]
        self.pos = end + 1
        return raw.decode("utf-8", errors="replace")

    def read_uintvar(self) -> int:
        """WAP uintvar: variable-length unsigned integer (§8.1.2).
        
        MSB-first: each byte's 7 low bits contribute in descending
        bit-significance (first byte = most significant 7 bits).
        """
        value = 0
        while True:
            b = self.read_byte()
            value = (value << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        return value

    def read_long_int(self) -> int:
        """
        WSP Long-integer (§8.1.3).
        First byte = length (0-30), followed by that many bytes as big-endian unsigned.
        """
        length = self.read_byte()
        if length == 0:
            return 0
        raw = self.read(length)
        return int.from_bytes(raw, "big")

    def read_short_length(self) -> int:
        """
        WSP Short-length (§8.4.2.1).
        0x00..0x1E = direct value, 0x1F = followed by uintvar.
        """
        b = self.read_byte()
        if b <= 0x1E:
            return b
        if b == 0x1F:
            return self.read_uintvar()
        # > 0x1F (but < 0x80) — treated as direct in some contexts
        return b

    def read_value_length(self) -> int:
        """
        WSP Value-length (§8.4.2.2).
        Same encoding as Short-length but high-bit values are length-quote.
        """
        b = self.read_byte()
        if b <= 0x1E:
            return b
        if b == 0x1F:
            return self.read_uintvar()
        # 0x80..0xFF: single-byte length-quote (strip high bit?)
        # Per spec: if > 0x1E it's a length-quote value, meaning length = b & 0x7F
        return b & 0x7F

    def skip(self, n: int):
        self.pos += n

    def __repr__(self):
        return f"<ByteStream pos={self.pos}/{self.length}>"


# ─── Content-Type table (WAP-230-WSP Appendix A) ─────────

CONTENT_TYPE_WELL_KNOWN: dict[int, str] = {
    0x00: "*/*",
    0x01: "text/*",
    0x02: "text/html",
    0x03: "text/plain",
    0x04: "text/x-hdml",
    0x05: "text/x-ttml",
    0x06: "text/x-vCalendar",
    0x07: "text/x-vCard",
    0x08: "text/vnd.wap.wml",
    0x09: "text/vnd.wap.wmlscript",
    0x0A: "text/vnd.wap.wta-event",
    0x0B: "multipart/*",
    0x0C: "multipart/mixed",
    0x0D: "multipart/form-data",
    0x0E: "multipart/byteranges",
    0x0F: "multipart/alternative",
    0x10: "application/*",
    0x11: "application/java-vm",
    0x12: "application/x-www-form-urlencoded",
    0x13: "application/x-hdmlc",
    0x14: "application/vnd.wap.wmlc",
    0x15: "application/vnd.wap.wmlscriptc",
    0x16: "application/vnd.wap.xhtml+xml",
    0x17: "application/vnd.wap.uaprof",
    0x1A: "application/x-x509-ca-cert",
    0x1B: "application/x-x509-user-cert",
    0x1C: "image/*",
    0x1D: "image/gif",
    0x1E: "image/jpeg",
    0x1F: "image/tiff",
    0x20: "image/png",
    0x21: "image/vnd.wap.wbmp",
    0x22: "application/vnd.wap.multipart.*",
    0x23: "application/vnd.wap.multipart.mixed",
    0x24: "application/vnd.wap.multipart.form-data",
    0x25: "application/vnd.wap.multipart.byteranges",
    0x26: "application/vnd.wap.multipart.alternative",
    0x27: "application/xml",
    0x28: "text/xml",
    0x29: "application/vnd.wap.wbxml",
    0x33: "application/vnd.wap.multipart.related",
    0x3B: "text/css",
    0x3C: "application/vnd.wap.mms-message",
}


# ─── Charset MIBenum (IANA) ──────────────────────────────

CHARSET_TABLE: dict[int, str] = {
    0x03: "us-ascii",
    0x04: "iso-8859-1",
    0x05: "iso-8859-2",
    0x06: "iso-8859-3",
    0x07: "iso-8859-4",
    0x08: "iso-8859-5",
    0x09: "iso-8859-6",
    0x0A: "iso-8859-7",
    0x0B: "iso-8859-8",
    0x0C: "iso-8859-9",
    0x6A: "utf-8",
    0x6B: "utf-16",
    0x6C: "utf-16be",
    0x6D: "utf-16le",
    0xEA: "utf-8",        # MMS Compiler uses this
    0x03E8: "utf-8",      # long form
}


# ─── WSP parameter field codes ───────────────────────────

PARAM_FIELD_CODES: dict[int, str] = {
    0x00: "Q",
    0x01: "Charset",
    0x02: "Language",
    0x03: "Encoding",
    0x05: "Name",
    0x06: "Filename",
    0x07: "Differences",
    0x08: "Padding",
    0x0B: "Type",
    0x09: "Type",          # duplicate in some specs
    # Short-form parameter codes (0x80+)
    0x80: "Q",
    0x81: "Charset",
    0x82: "Language",
    0x83: "Encoding",
    0x85: "Name",
    0x86: "Filename",
    0x87: "Differences",
    0x88: "Padding",
    0x89: "Type",
    0x8A: "Start",
    0x8B: "Start-info",
    0x8C: "Comment",
    0x8D: "Domain",
    0x8E: "Max-Age",
    0x8F: "Path",
    0x90: "Secure",
    0x91: "SEC",
    0x92: "MAC",
    0x93: "Creation-date",
    0x94: "Modification-date",
    0x95: "Read-date",
    0x96: "Size",
    0x97: "Name",
    0x98: "Filename",
    0x99: "Start",
    0x9A: "Start-info",
}


# ─── Decoder functions ────────────────────────────────────

def decode_content_type_value(buf: ByteStream) -> str:
    """
    Decode a WSP Content-Type value (§8.4.2.6).

    Returns the media type string. Parameters are read and discarded;
    use decode_content_type_full() to get params too.
    """
    b = buf.peek(1)[0]
    if b & 0x80:
        code = buf.read_byte() & 0x7F
        return CONTENT_TYPE_WELL_KNOWN.get(code, f"unknown/{code}")
    elif b <= 0x1F:
        # Constrained-media: value-length then the actual CT
        length = buf.read_short_length()
        # The CT starts here, read just the type
        return _decode_media_type(buf)
    else:
        return buf.read_cstring()


def decode_content_type_full(buf: ByteStream, total_len: int = 0) -> tuple[str, dict]:
    """
    Decode a WSP Content-Type with parameters.

    Args:
        buf: byte stream positioned at the start of CT value
        total_len: total byte length of the CT value (including media type and params).
                   If > 0, params will not be read beyond this boundary.

    Returns (media_type_str, params_dict).
    """
    start = buf.pos
    end_pos = start + total_len if total_len > 0 else start + 4096  # safety cap
    b = buf.peek(1)[0]

    if b & 0x80:
        code = buf.read_byte() & 0x7F
        media = CONTENT_TYPE_WELL_KNOWN.get(code, f"unknown/{code}")
    elif b <= 0x1F:
        length = buf.read_short_length()
        sub_end = buf.pos + length
        media = _decode_media_type(buf)
        # Read params within this sub-scope
        params = _read_params(buf, min(sub_end, end_pos))
        buf.pos = sub_end
        return media, params
    else:
        media = buf.read_cstring()

    # Read trailing params (bounded by total_len if provided)
    params = _read_params(buf, end_pos)
    return media, params


def _decode_media_type(buf: ByteStream) -> str:
    """Decode just the media type token."""
    b = buf.peek(1)[0]
    if b & 0x80:
        code = buf.read_byte() & 0x7F
        return CONTENT_TYPE_WELL_KNOWN.get(code, f"unknown/{code}")
    else:
        return buf.read_cstring()


def _read_params(buf: ByteStream, end_pos: int) -> dict:
    """Read WSP parameters until end_pos or non-param byte."""
    params: dict = {}
    while buf.pos < end_pos and buf.remaining > 0:
        b = buf.peek(1)[0]
        # Parameter: 0x00-0x7F short-int key, or 0x80+ well-known
        # Value follows
        key_code = buf.read_byte()
        param_name = PARAM_FIELD_CODES.get(key_code, f"param-{key_code:02X}")

        if buf.remaining == 0:
            params[param_name] = None
            break

        # Decode parameter value (§8.4.2.4)
        v = buf.peek(1)[0]
        if v == 0x00 or (v & 0x80 and v != 0x80):
            # No-value or well-known integer value
            if v == 0x00:
                buf.read_byte()
                params[param_name] = None
            elif v & 0x80:
                intval = buf.read_byte()
                if key_code in (0x01, 0x81, 0x83):
                    params[param_name] = CHARSET_TABLE.get(intval & 0x7F, f"charset-{intval:02X}")
                else:
                    params[param_name] = intval
        elif v <= 0x1F:
            # Typed-value: integer form
            buf.read_byte()  # length/0x1F
            raw_val = buf.read_byte()
            if key_code in (0x01, 0x81, 0x83):
                params[param_name] = CHARSET_TABLE.get(raw_val, f"charset-{raw_val:02X}")
            else:
                params[param_name] = raw_val
        elif v == 0x1F:
            buf.read_byte()
            uval = buf.read_uintvar()
            if key_code in (0x01, 0x81, 0x83):
                params[param_name] = CHARSET_TABLE.get(uval, f"charset-{uval}")
            else:
                params[param_name] = uval
        else:
            # Text-string value
            params[param_name] = buf.read_cstring()
    return params


def decode_address(buf: ByteStream) -> tuple[int, str]:
    """
    Decode an MMS address value (§7.1.10).

    Returns (address_type_token, address_string).
    """
    addr_type = buf.read_byte()

    if addr_type == 0x81:
        # Insert-address-token (anonymous sender)
        return addr_type, ""

    if addr_type == 0x80:
        # PLMN / insert from device
        try:
            addr = buf.read_cstring()
        except ValueError:
            addr = ""
        return addr_type, addr

    # Other address types: read as string
    try:
        addr = buf.read_cstring()
    except (ValueError, EOFError):
        addr = ""
    return addr_type, addr
