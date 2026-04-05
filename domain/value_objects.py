"""
domain/value_objects.py — Value objects for MMS protocol.

Immutable, self-validating data classes representing protocol primitives:
  Address, ContentType, MmsTimestamp, WspCharset

References:
  OMA-TS-MMS-ENC-V1_3   — MMS Encapsulation Protocol
  3GPP TS 23.140         — MMS Architecture
  WAP-230-WSP            — Wireless Session Protocol
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# ─── MMS Address ──────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class Address:
    """
    MMS address value (From / To / Cc / Bcc).

    Encoding per OMA-MMS-ENC §7.1.10:
      - First byte = address type token:
          0x01 = PLMN (phone number, e.g. +1234567890)
          0x02 = IPv4
          0x03 = IPv6
          0x80 = Insert-address-token (from device)
          0x81 = Anonymous
      - Remaining bytes = address string (null-terminated if present)
    """
    address_type: str          # "PLMN" | "IPv4" | "IPv6" | "anonymous" | "insert"
    value: str                 # the actual address string
    raw: bytes = b""           # original encoded bytes (for round-trip fidelity)

    # ── class methods ──

    @classmethod
    def anonymous(cls) -> "Address":
        return cls(address_type="anonymous", value="")

    @classmethod
    def insert_token(cls, display_name: str = "") -> "Address":
        return cls(address_type="insert", value=display_name)


# ─── Content Type ─────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class ContentType:
    """
    A parsed WSP Content-Type value with parameters.

    Per WAP-230-WSP §8.4.2.6:
      - type:   the media type string  (e.g. "image/jpeg")
      - params: ordered dict of param name → value
    """
    type: str
    params: dict = field(default_factory=dict)

    @property
    def mime(self) -> str:
        """Return the plain MIME type without parameters."""
        return self.type

    @property
    def is_image(self) -> bool:
        return self.type.startswith("image/")

    @property
    def is_audio(self) -> bool:
        return self.type.startswith("audio/")

    @property
    def is_video(self) -> bool:
        return self.type.startswith("video/")

    @property
    def is_text(self) -> bool:
        return self.type.startswith("text/")

    @property
    def is_smil(self) -> bool:
        return self.type == "application/smil"

    @property
    def is_multipart(self) -> bool:
        return "multipart" in self.type

    @property
    def charset(self) -> Optional[str]:
        """Return the charset parameter if present."""
        return self.params.get("Charset")


# ─── MMS Timestamp ────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class MmsTimestamp:
    """
    MMS Date value.

    Per OMA-MMS-ENC: a long-integer representing seconds since
    1970-01-01 00:00:00 UTC (note: WSP uses *seconds*, not millis).
    """
    raw_value: int           # the integer read from PDU

    @property
    def epoch_seconds(self) -> int:
        return self.raw_value

    @property
    def iso8601(self) -> str:
        try:
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(self.raw_value, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OSError, OverflowError, ValueError):
            return f"epoch:{self.raw_value}"

    @property
    def display(self) -> str:
        try:
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(self.raw_value, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OSError, OverflowError, ValueError):
            return f"epoch:{self.raw_value}"
