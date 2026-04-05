"""
server/routes.py — HTTP route handlers.

Separate route handlers from the server bootstrap.
Each handler receives (request, response) and returns nothing —
it writes to response directly.

Routes:
  GET  /                      → serve web/index.html
  POST /parse                 → parse uploaded .mms file (standard mode)
  POST /analyze               → analyze uploaded file with mode selection
  GET  /hex                   → get hex view page
  GET  /scan-element/<id>     → serve a scanned element for preview
  GET  /part/<session>/<idx>  → serve extracted part data (standard mode)
"""

from __future__ import annotations

import json
import hashlib
import mimetypes
from pathlib import Path
from urllib.parse import unquote, urlparse, parse_qs
from http.server import SimpleHTTPRequestHandler

from server.config import ServerConfig
from parser.mms_parser import parse_mms
from domain.entities import MmsMessage
from analyzer.analyzer_facade import analyze_bytes


class MmsHttpHandler(SimpleHTTPRequestHandler):
    """
    Request handler with MMS parsing and analysis endpoints.
    """

    config: ServerConfig

    # ── Routing ──

    def do_GET(self):
        path = unquote(self.path).split("?")[0]

        if path == "/" or path == "/index.html":
            self._serve_index()
        elif path == "/hex":
            self._handle_hex_view()
        elif path.startswith("/scan-element-download/"):
            self._serve_scan_element_download()
        elif path.startswith("/scan-element/"):
            self._serve_scan_element()
        elif path.startswith("/part/"):
            self._serve_part()
        else:
            super().do_GET()

    def do_POST(self):
        path = unquote(self.path).split("?")[0]

        if path == "/parse":
            self._handle_parse_upload()
        elif path == "/analyze":
            self._handle_analyze_upload()
        else:
            self._respond(404, {"error": "Not found"})

    def do_OPTIONS(self):
        """CORS preflight."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ── Route handlers ──

    def _serve_index(self):
        """Serve the main SPA page."""
        index_path = self.config.web_root / "index.html"
        if index_path.exists():
            self._respond_file(index_path)
        else:
            self._respond(500, {"error": "index.html not found"})

    def _handle_parse_upload(self):
        """POST /parse — standard MMS parsing (backward compatible)."""
        data = self._read_upload_body()
        if data is None:
            return

        try:
            msg: MmsMessage = parse_mms(data)
        except Exception as e:
            self._respond(422, {"error": f"Parse error: {e}"})
            return

        response = self._serialize_message(msg)
        self._respond(200, response)

    def _handle_analyze_upload(self):
        """POST /analyze?mode=<standard|special|expert> — multi-mode analysis."""
        qs = parse_qs(urlparse(self.path).query)
        mode = qs.get("mode", ["standard"])[0]
        hex_page = int(qs.get("page", ["0"])[0])

        data = self._read_upload_body()
        if data is None:
            return

        result = analyze_bytes(data, mode=mode, hex_page=hex_page)

        # For standard/special mode, cache parts for preview
        if result.standard:
            file_hash = hashlib.md5(data).hexdigest()[:12]
            PartCache.clear(file_hash)
            PartCache.put_raw(file_hash, data)  # keep raw for re-parsing
            # Cache each part's data for preview/download
            std = result.standard
            parts_list = std.get("parts", [])
            is_special_fallback = bool(std.get("_specialFormat"))
            if is_special_fallback:
                # Parts came from special parser — re-run to get raw data
                from analyzer.special_parser import try_special_formats
                special_results = try_special_formats(data)
                for sr in special_results:
                    if sr.success and sr.parts:
                        for p in sr.parts:
                            PartCache.put(file_hash, p.index, p.content_type.mime, p.data)
                        break
            else:
                # Standard parse — get part data from parsed message
                try:
                    from parser.mms_parser import parse_mms
                    msg = parse_mms(data)
                    for p_info in parts_list:
                        idx = p_info.get("index")
                        ct = p_info.get("contentType", "application/octet-stream")
                        if idx < len(msg.parts):
                            PartCache.put(file_hash, idx, ct, msg.parts[idx].data)
                except Exception:
                    pass

        # For special mode with successful vendor parse, also cache those parts
        if result.special and result.special.get("success"):
            file_hash = hashlib.md5(data).hexdigest()[:12]
            # Special results might contain parts in the successful attempt
            attempts = result.special.get("attempts", [])
            for attempt in attempts:
                if attempt.get("success") and attempt.get("parts"):
                    # Try to re-parse with special parser to get raw data
                    from analyzer.special_parser import try_special_formats
                    special_results = try_special_formats(data)
                    for sr in special_results:
                        if sr.success and sr.parts:
                            for p in sr.parts:
                                ct = p.content_type.mime
                                fn = p.header_extras.get("_filename", p.suggested_filename or "")
                                PartCache.put(file_hash, p.index, ct, p.data)
                            break
                    break

        # For expert mode, cache scan elements for preview
        if result.scan:
            file_hash = hashlib.md5(data).hexdigest()[:12]
            ScanElementCache.clear(file_hash)
            from analyzer.signature_scanner import scan_signatures
            scan_result = scan_signatures(data)
            for i, elem in enumerate(scan_result.elements):
                if elem.data:
                    ScanElementCache.put(
                        file_hash, i, elem.mime, elem.data,
                    )

        self._respond(200, result.to_dict())

    def _handle_hex_view(self):
        """GET /hex?file=<path>&page=<n> — hex view of a file on disk."""
        qs = parse_qs(urlparse(self.path).query)
        file_path = qs.get("file", [None])[0]
        page = int(qs.get("page", ["0"])[0])

        if not file_path:
            self._respond(400, {"error": "Missing 'file' parameter"})
            return

        try:
            data = Path(file_path).read_bytes()
        except Exception as e:
            self._respond(500, {"error": str(e)})
            return

        from analyzer.hex_view import generate_hex_view
        hex_view = generate_hex_view(data, page=page)
        self._respond(200, {
            "totalBytes": hex_view.total_bytes,
            "page": hex_view.page,
            "totalPages": hex_view.total_pages,
            "lines": [
                {
                    "offset": line.offset,
                    "hex": line.hex_bytes,
                    "ascii": line.ascii_repr,
                }
                for line in hex_view.lines
            ],
        })

    def _serve_scan_element(self):
        """GET /scan-element/<hash>/<index> — serve a scanned element."""
        parts = self.path.lstrip("/scan-element/").split("/", 1)
        if len(parts) != 2:
            self._respond(400, {"error": "Invalid element URL"})
            return

        file_hash, index_str = parts
        try:
            index = int(index_str)
        except ValueError:
            self._respond(400, {"error": "Invalid index"})
            return

        element_data = ScanElementCache.get(file_hash, index)
        if element_data is None:
            self._respond(404, {"error": "Element not found or expired"})
            return

        ct, raw_bytes = element_data
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(raw_bytes)))
        self.send_header("Cache-Control", "private, max-age=60")
        self.end_headers()
        self.wfile.write(raw_bytes)

    def _serve_scan_element_download(self):
        """GET /scan-element-download/<hash>/<index>?name=<filename> — download a scanned element."""
        path_part = self.path.lstrip("/scan-element-download/")
        # Strip query string from path_part
        if "?" in path_part:
            path_part = path_part.split("?")[0]
        parts = path_part.split("/", 1)
        if len(parts) != 2:
            self._respond(400, {"error": "Invalid download URL"})
            return

        file_hash, index_str = parts
        try:
            index = int(index_str)
        except ValueError:
            self._respond(400, {"error": "Invalid index"})
            return

        # Parse filename from query
        qs = parse_qs(urlparse(self.path).query)
        filename = qs.get("name", [f"element_{index}.bin"])[0]

        element_data = ScanElementCache.get(file_hash, index)
        if element_data is None:
            self._respond(404, {"error": "Element not found or expired"})
            return

        ct, raw_bytes = element_data
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(raw_bytes)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "private, max-age=60")
        self.end_headers()
        self.wfile.write(raw_bytes)

    def _serve_part(self):
        """GET /part/<hash>/<index> — serve extracted part (standard mode)."""
        parts = self.path.lstrip("/part/").split("/", 1)
        if len(parts) != 2:
            self._respond(400, {"error": "Invalid part URL"})
            return

        file_hash, index_str = parts
        try:
            index = int(index_str)
        except ValueError:
            self._respond(400, {"error": "Invalid part index"})
            return

        # Parse download query params
        qs = parse_qs(urlparse(self.path).query)
        is_download = qs.get("download", ["0"])[0] == "1"
        dl_name = qs.get("name", [None])[0]

        part_data = PartCache.get(file_hash, index)
        if part_data is None:
            self._respond(404, {"error": "Part not found or expired"})
            return

        part_type, part_bytes = part_data
        self.send_response(200)
        self.send_header("Content-Type", part_type)
        self.send_header("Content-Length", str(len(part_bytes)))
        self.send_header("Cache-Control", "private, max-age=60")
        if is_download and dl_name:
            self.send_header("Content-Disposition", f'attachment; filename="{dl_name}"')
        self.end_headers()
        self.wfile.write(part_bytes)

    # ── Serialization ──

    def _serialize_message(self, msg: MmsMessage) -> dict:
        """Convert MmsMessage to JSON-serializable dict."""
        h = msg.header

        result = {
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
                "contentType": h.content_type.mime if h.content_type else None,
                "messageClass": h.message_class.name if h.message_class else None,
                "priority": h.priority.name if h.priority else None,
                "deliveryReport": h.delivery_report,
                "readReply": h.read_reply,
            },
            "parts": [],
        }

        # Cache parts for image serving
        file_hash = hashlib.md5(msg.raw).hexdigest()[:12]
        PartCache.clear(file_hash)

        for part in msg.parts:
            ct = part.content_type
            part_info = {
                "index": part.index,
                "contentType": ct.mime,
                "size": part.size,
                "filename": part.suggested_filename,
                "contentId": part.content_id,
                "contentLocation": part.content_location,
            }

            text = part.text_content()
            if text is not None:
                part_info["text"] = text[:8192]

            if not ct.is_smil:
                PartCache.put(file_hash, part.index, ct.mime, part.data)
                part_info["previewUrl"] = f"/part/{file_hash}/{part.index}"

            result["parts"].append(part_info)

        # SMIL
        if msg.smil:
            smil = msg.smil
            result["smil"] = {
                "rootWidth": smil.root_width,
                "rootHeight": smil.root_height,
                "regions": [
                    {
                        "id": r.id, "left": r.left, "top": r.top,
                        "width": r.width, "height": r.height, "fit": r.fit,
                    }
                    for r in smil.regions
                ],
                "pars": [
                    {
                        "duration": p.duration,
                        "media": [
                            {"tag": m.tag, "src": m.src, "region": m.region, "alt": m.alt}
                            for m in p.media
                        ],
                    }
                    for p in smil.pars
                ],
            }

        result["_fileHash"] = file_hash
        return result

    # ── Helpers ──

    def _read_upload_body(self) -> bytes | None:
        """Read uploaded file from POST body. Returns bytes or None (on error)."""
        content_type = self.headers.get("Content-Type", "")

        if "multipart/form-data" in content_type:
            boundary = content_type.split("boundary=")[-1].strip()
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            data = self._extract_multipart_file(body, boundary.encode())
            if data is None:
                self._respond(400, {"error": "No file found in upload"})
                return None
        else:
            content_length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(content_length)

        if len(data) < 4:
            self._respond(400, {"error": "File too small"})
            return None

        return data

    def _respond(self, status: int, body: dict | str):
        """Send a JSON response."""
        payload = json.dumps(body, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def _respond_file(self, path: Path):
        """Serve a static file."""
        ct = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _extract_multipart_file(self, body: bytes, boundary: bytes) -> bytes | None:
        """Extract the first file from a multipart/form-data body."""
        marker = b"\r\n\r\n"
        idx = body.find(marker)
        if idx < 0:
            return None
        start = idx + len(marker)
        end = body.find(boundary, start)
        if end < 0:
            return body[start:]
        return body[start:end - 2]

    def log_message(self, format, *args):
        """Quiet logging — only errors."""
        if "200" not in str(args):
            super().log_message(format, *args)


# ─── In-memory caches ─────────────────────────────────────────

class PartCache:
    """Transient cache for extracted MMS parts (standard mode)."""
    _store: dict[str, dict[int, tuple[str, bytes]]] = {}

    @classmethod
    def put(cls, file_hash: str, index: int, content_type: str, data: bytes):
        if file_hash not in cls._store:
            cls._store[file_hash] = {}
        cls._store[file_hash][index] = (content_type, data)

    @classmethod
    def put_raw(cls, file_hash: str, data: bytes):
        """Store raw data for re-parsing."""
        if file_hash not in cls._store:
            cls._store[file_hash] = {}
        cls._store[file_hash]["__raw__"] = ("application/octet-stream", data)

    @classmethod
    def get(cls, file_hash: str, index: int) -> tuple[str, bytes] | None:
        bucket = cls._store.get(file_hash)
        if bucket:
            return bucket.get(index)
        return None

    @classmethod
    def clear(cls, file_hash: str):
        if file_hash in cls._store:
            del cls._store[file_hash]


class ScanElementCache:
    """Transient cache for signature-scanned elements (expert mode)."""
    _store: dict[str, dict[int, tuple[str, bytes]]] = {}

    @classmethod
    def put(cls, file_hash: str, index: int, content_type: str, data: bytes):
        if file_hash not in cls._store:
            cls._store[file_hash] = {}
        cls._store[file_hash][index] = (content_type, data)

    @classmethod
    def get(cls, file_hash: str, index: int) -> tuple[str, bytes] | None:
        bucket = cls._store.get(file_hash)
        if bucket:
            return bucket.get(index)
        return None

    @classmethod
    def clear(cls, file_hash: str):
        if file_hash in cls._store:
            del cls._store[file_hash]
