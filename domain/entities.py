"""
domain/entities.py — Domain entities for an MMS message.

Higher-level structures that compose value objects:
  MmsHeader   — parsed header fields of an MMS PDU
  MmsPart     — one entry in a multipart/related body
  SmilRegion  — a layout region from SMIL presentation
  SmilPar     — a timed group of media references
  MmsMessage  — the top-level parsed MMS message

References:
  OMA-TS-MMS-ENC-V1_3   §7  PDU header fields
  3GPP TS 23.140         §5  MMS content model
  WAP-230-WSP            §8  Content encoding
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .value_objects import Address, ContentType, MmsTimestamp


# ─── Enums ────────────────────────────────────────────────

class MmsMessageType(Enum):
    """MMS PDU type codes (OMA-MMS-ENC Table 5)."""
    M_SEND_REQ = 0x80
    M_SEND_CONF = 0x81
    M_NOTIFICATION_IND = 0x82
    M_NOTIFYRESP_IND = 0x83
    M_RETRIEVE_CONF = 0x84
    M_ACKNOWLEDGE_IND = 0x85
    M_DELIVERY_IND = 0x86
    M_READ_REC_IND = 0x87
    M_READ_ORIG_IND = 0x88
    FORWARD_REQ = 0x89
    FORWARD_CONF = 0x8A
    MBOX_STORE_REQ = 0x8B
    MBOX_STORE_CONF = 0x8C
    MBOX_VIEW_REQ = 0x8D
    MBOX_VIEW_CONF = 0x8E
    MBOX_UPLOAD_REQ = 0x8F
    MBOX_UPLOAD_CONF = 0x90
    MBOX_DELETE_REQ = 0x91
    MBOX_DELETE_CONF = 0x92
    M_RETRIEVE_IND = 0x93
    M_TRANSACTION_ID = 0x94
    M_REJECT = 0x95
    M_CANCEL = 0x96
    # alias
    @classmethod
    def from_code(cls, code: int) -> "MmsMessageType":
        try:
            return cls(code)
        except ValueError:
            return None


class MmsVersion(Enum):
    """MMS protocol version (OMA-MMS-ENC §7.1.1)."""
    V1_0 = 0x90
    V1_1 = 0x91
    V1_2 = 0x92
    V1_3 = 0x93

    @classmethod
    def from_code(cls, code: int) -> "MmsVersion":
        try:
            return cls(code | 0x90)   # normalize: 0x00..0x03 → 0x90..0x93
        except ValueError:
            return None

    @property
    def label(self) -> str:
        return f"1.{self.value - 0x90}"


class MessageClass(Enum):
    """Message class values (OMA-MMS-ENC Table 8)."""
    PERSONAL = 0x80
    ADVERTISEMENT = 0x81
    INFORMATIONAL = 0x82
    AUTO = 0x83


class Priority(Enum):
    """Priority values (OMA-MMS-ENC Table 10)."""
    LOW = 0x80
    NORMAL = 0x81
    HIGH = 0x82


# ─── MmsHeader ────────────────────────────────────────────

@dataclass
class MmsHeader:
    """
    Parsed MMS PDU header fields.

    Not all fields are present in every PDU type.
    Per OMA-MMS-ENC §7, the following fields appear in m_retrieve_conf:
      Bcc, Cc, Content-Type, Content-Location, Date, Delivery-Report,
      Expiry, From, Message-Class, Message-ID, Message-Size,
      MMS-Version, Priority, Read-Reply, Report-Allowed, Response-Status,
      Response-Text, Retrieve-Status, Retrieve-Text, Sender-Visibility,
      Status, Subject, To, Transaction-ID, X-Mms-Message-Type
    """
    message_type: Optional[MmsMessageType] = None
    mms_version: Optional[MmsVersion] = None
    transaction_id: Optional[str] = None
    message_id: Optional[str] = None
    date: Optional[MmsTimestamp] = None
    from_addr: Optional[Address] = None
    to_addr: Optional[Address] = None
    cc: list = field(default_factory=list)
    bcc: list = field(default_factory=list)
    subject: Optional[str] = None
    content_type: Optional[ContentType] = None
    message_class: Optional[MessageClass] = None
    priority: Optional[Priority] = None
    delivery_report: Optional[bool] = None
    read_reply: Optional[bool] = None
    report_allowed: Optional[bool] = None
    message_size: Optional[int] = None
    sender_visibility: Optional[bool] = None
    expiry: Optional[MmsTimestamp] = None
    # raw extras for fields we don't model yet
    extras: dict = field(default_factory=dict)


# ─── MmsPart ──────────────────────────────────────────────

@dataclass
class MmsPart:
    """
    One part inside a WAP multipart/related body.

    Each part has its own Content-Type, optional Content-ID and
    Content-Location headers, and a raw data payload.
    """
    index: int
    content_type: ContentType
    content_id: Optional[str] = None
    content_location: Optional[str] = None
    data: bytes = b""
    header_extras: dict = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def suggested_filename(self) -> str:
        """Infer a filename from Content-ID, Content-Location, or MIME type."""
        from .value_objects import ContentType as CT  # avoid circular
        name = (self.content_location or self.content_id or f"part_{self.index}")
        name = name.replace("<", "").replace(">", "")
        # Already has extension?
        if "." in name.split("/")[-1]:
            return name
        # Infer from MIME
        ext_map = {
            "text/plain": ".txt", "text/html": ".html", "text/xml": ".xml",
            "image/gif": ".gif", "image/jpeg": ".jpg", "image/png": ".png",
            "image/tiff": ".tif", "image/vnd.wap.wbmp": ".wbmp",
            "audio/midi": ".mid", "audio/x-midi": ".mid", "audio/*": ".mid",
            "video/3gpp": ".3gp", "video/*": ".3gp",
            "application/smil": ".smil",
        }
        mime = self.content_type.mime
        ext = ext_map.get(mime, "")
        if not ext:
            for k, v in ext_map.items():
                if mime.startswith(k.rstrip("*")):
                    ext = v
                    break
        return f"{name}{ext}"

    def text_content(self) -> Optional[str]:
        """Decode text parts to string."""
        if not self.content_type.is_text and not self.content_type.is_smil:
            return None
        charset = self.content_type.charset or "utf-8"
        try:
            return self.data.decode(charset, errors="replace")
        except (LookupError, Exception):
            return self.data.decode("utf-8", errors="replace")


# ─── SMIL entities ────────────────────────────────────────

@dataclass
class SmilRegion:
    """A layout region in SMIL <layout>."""
    id: str
    left: str = "0"
    top: str = "0"
    width: str = "100%"
    height: str = "100%"
    fit: str = ""          # meet | slice | fill | scroll | hidden


@dataclass
class SmilMediaRef:
    """A <img>, <text>, <audio>, <video>, or <ref> element inside <par>."""
    tag: str               # "img", "text", "audio", "video", "ref"
    src: str               # the Content-ID or Content-Location
    region: str = ""       # target region id
    alt: str = ""


@dataclass
class SmilPar:
    """A <par> (parallel) group — all children play simultaneously."""
    duration: str = ""
    media: list = field(default_factory=list)   # list[SmilMediaRef]


@dataclass
class SmilPresentation:
    """Parsed SMIL presentation metadata."""
    raw_xml: str = ""
    root_width: str = ""
    root_height: str = ""
    regions: list = field(default_factory=list)  # list[SmilRegion]
    pars: list = field(default_factory=list)     # list[SmilPar]


# ─── MmsMessage ───────────────────────────────────────────

@dataclass
class MmsMessage:
    """
    Top-level parsed MMS message.

    Composes header + body parts + optional SMIL presentation.
    """
    header: MmsHeader
    parts: list = field(default_factory=list)    # list[MmsPart]
    smil: Optional[SmilPresentation] = None
    raw: bytes = b""                             # original PDU bytes

    # ── convenience accessors ──

    @property
    def subject(self) -> str:
        return self.header.subject or ""

    @property
    def from_display(self) -> str:
        if self.header.from_addr:
            return self.header.from_addr.value or self.header.from_addr.address_type
        return ""

    @property
    def date_display(self) -> str:
        return self.header.date.display if self.header.date else ""

    @property
    def media_parts(self) -> list:
        """Return all non-SMIL parts (text, image, audio, video)."""
        return [p for p in self.parts if not p.content_type.is_smil]

    @property
    def smil_part(self) -> Optional[MmsPart]:
        """Return the SMIL presentation part, if any."""
        for p in self.parts:
            if p.content_type.is_smil:
                return p
        return None

    @property
    def total_size(self) -> int:
        return len(self.raw)

    def part_by_id(self, cid: str) -> Optional[MmsPart]:
        """Look up a part by Content-ID (accepts both <id> and id forms)."""
        clean = cid.strip("<>").lower()
        for p in self.parts:
            pid = (p.content_id or "").strip("<>").lower()
            if pid == clean:
                return p
            loc = (p.content_location or "").strip("<>").lower()
            if loc == clean:
                return p
        return None
