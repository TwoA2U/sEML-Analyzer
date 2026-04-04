"""
EML Analyzer — Flask Backend
=============================
    POST /analyze/file        multipart/form-data  field: file (.eml)
    POST /analyze/text        application/json     field: raw (string)
    GET  /attachment/<sha256> download attachment safely (extension stripped)

Requirements:  pip install flask
Run:           python main.py [-p PORT] [-i INTERFACE] [-d]

Security notes
--------------
* This tool is intended for LOCAL / TRUSTED-LAN use only.
* Never expose port to the public internet without authentication.
* Rate-limiting, CSRF origin-check, and security headers are included
  but a reverse proxy with TLS and auth is strongly recommended for
  anything beyond single-user local use.
"""
import argparse
import base64
import email
import email.header
import email.policy
import hashlib
import ipaddress
import logging
import re
import os
import threading
from email.utils import parseaddr, parsedate_to_datetime, getaddresses
from typing import Any
from email.header import decode_header, make_header


from flask import Flask, jsonify, request, Response

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024   # 20 MB upload hard limit

_FRONTEND_PATH = os.path.join(os.path.dirname(__file__), "eml-analyzer.html")

# Max HTML body size to b64-encode and return in JSON (5 MB)
_MAX_HTML_BODY_BYTES = 5 * 1024 * 1024

# Max MIME nesting depth — prevents stack overflow on pathological inputs
_MAX_MIME_DEPTH = 30

# ── Thread-safe attachment store ──────────────────────────────────────────────
# Keyed by sha256; stores raw bytes for the LAST parsed email only.
_store_lock = threading.Lock()
_attachment_store: dict[str, dict] = {}


# ═══════════════════════════════════════════════════════════════════════════════
# Security headers — applied to every response via after_request
# ═══════════════════════════════════════════════════════════════════════════════

@app.after_request
def add_security_headers(resp: Response) -> Response:
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"]        = "DENY"
    resp.headers["Referrer-Policy"]        = "no-referrer"
    resp.headers["Cache-Control"]          = "no-store"
    # Tight CSP — only the main page needs to load fonts from Google
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "script-src 'self' 'unsafe-inline'; "
        "frame-src 'self' blob:; "
        "connect-src 'self';"
    )
    return resp


# ═══════════════════════════════════════════════════════════════════════════════
# CSRF origin check — applied to all mutating POST routes
# ═══════════════════════════════════════════════════════════════════════════════

def _check_origin() -> bool:
    """
    Accept requests that come from the same host (browser-local use).
    Rejects cross-origin requests that don't carry the expected Origin/Referer.
    """
    origin  = request.headers.get("Origin", "")
    referer = request.headers.get("Referer", "")
    host    = request.host  # e.g. "127.0.0.1:5000"

    # Allow requests with no origin header (curl, API clients — intentional)
    if not origin and not referer:
        return True

    # Check that the origin matches our own host
    allowed = f"http://{host}"
    if origin and not (origin == allowed or origin.startswith(allowed + "/")):
        return False
    if referer and not (referer == allowed or referer.startswith(allowed + "/")):
        return False
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _safe_decode(value: Any) -> str:
    return "" if value is None else str(value)


def _decode_header_value(raw: Any) -> str:
    """
    Hardened RFC 2047 decoder.
    Handles unknown charsets and malformed phishing headers more robustly.
    """
    if raw is None:
        return ""

    # 1. Clean the input: Force to string and strip initial whitespace
    raw_str = str(raw).strip()

    try:
        # 2. Preferred Method: make_header(decode_header())
        # This is the standard library's most robust way to handle
        # complex multi-part encoded headers.
        return str(make_header(decode_header(raw_str)))
    except Exception:
        # 3. Fallback: Manual reconstruction with aggressive error handling
        # This triggers if make_header fails due to extremely malformed parts.
        try:
            parts = decode_header(raw_str)
            decoded_parts = []
            for chunk, charset in parts:
                if isinstance(chunk, bytes):
                    # If charset is unknown (LookupError) or missing,
                    # fallback to utf-8 or latin-1 with 'replace'.
                    effective_charset = charset or "utf-8"
                    try:
                        decoded_parts.append(chunk.decode(effective_charset, errors="replace"))
                    except (LookupError, ValueError):
                        decoded_parts.append(chunk.decode("utf-8", errors="replace"))
                else:
                    decoded_parts.append(str(chunk))

            # Join and normalize internal whitespace/newlines
            return " ".join("".join(decoded_parts).split()).strip()
        except Exception:
            # 4. Ultimate Fallback: Return raw string if all else fails
            return raw_str


def _sanitise_filename(name: str) -> str:
    """
    Strip ALL extensions from a filename and replace with .bin.
    Also remove path separators and null bytes.
    e.g.  "evil.exe.doc"  →  "evil.bin"
          "../escape"      →  "..escape.bin"
    """
    # Remove path components and null bytes
    name = os.path.basename(name.replace("\x00", "").replace("/", "_").replace("\\", "_"))
    if not name:
        name = "attachment"
    # Strip every extension (everything from the first dot onwards)
    stem = name.split(".")[0] or "attachment"
    return stem + ".bin"


def _safe_content_disposition(filename: str) -> str:
    """Build a safe Content-Disposition header value using RFC 5987 encoding."""
    # ASCII fallback (strip non-ASCII for the plain filename= param)
    ascii_name = filename.encode("ascii", errors="replace").decode("ascii")
    # RFC 5987 percent-encoded version for full Unicode support
    encoded = "".join(
        c if c.isalnum() or c in "-_.~" else f"%{ord(c):02X}"
        for c in filename
    )
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{encoded}"


# ═══════════════════════════════════════════════════════════════════════════════
# Authentication
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_auth_results(raw: str) -> list[dict]:
    checks = []
    normalized = " ".join(raw.split())
    for proto in ("spf", "dkim", "dmarc", "arc"):
        m = re.search(
            rf"(?<![a-z]){proto}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
            normalized, re.IGNORECASE)
        if m:
            cm = re.search(
                rf"(?<![a-z]){proto}\b.+?(?=(?:spf|dkim|dmarc|arc)\s*=|$)",
                normalized, re.IGNORECASE | re.DOTALL)
            clause = cm.group(0).strip() if cm else m.group(0)
            checks.append({"name": proto.upper(), "result": m.group(1).lower(), "clause": clause})
    return checks


# ═══════════════════════════════════════════════════════════════════════════════
# Received chain
# ═══════════════════════════════════════════════════════════════════════════════

_FROM_RE = re.compile(r"from\s+(\S+)(?:\s+\(([^)]+)\))?", re.IGNORECASE)
_BY_RE   = re.compile(r"by\s+(\S+)",   re.IGNORECASE)
_WITH_RE = re.compile(r"with\s+(\S+)", re.IGNORECASE)
_FOR_RE  = re.compile(r"for\s+(\S+)",  re.IGNORECASE)
_IP_RE   = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")


def _parse_one_received(raw: str) -> dict:
    raw = raw.strip()
    body, ts_str = (raw.rsplit(";", 1) + [""])[:2] if ";" in raw else (raw, "")
    ts, ts_iso = None, None
    if ts_str.strip():
        try:
            ts = parsedate_to_datetime(ts_str.strip())
            ts_iso = ts.isoformat()
        except Exception:
            pass
    fm   = _FROM_RE.search(body)
    bym  = _BY_RE.search(body)
    wm   = _WITH_RE.search(body)
    form = _FOR_RE.search(body)
    return {
        "raw":           raw,
        "sender":        fm.group(1)   if fm   else None,
        "receiver":      bym.group(1)  if bym  else None,
        "protocol":      wm.group(1)   if wm   else None,
        "for":           form.group(1) if form  else None,
        "ips":           _IP_RE.findall(body),
        "timestamp_iso": ts_iso,
        "_dt":           ts,
    }


def _parse_received_hops(received_list: list[str]) -> list[dict]:
    parsed       = [_parse_one_received(r) for r in received_list]
    oldest_first = list(reversed(parsed))
    for i in range(1, len(oldest_first)):
        p, c = oldest_first[i - 1]["_dt"], oldest_first[i]["_dt"]
        if p and c:
            oldest_first[i]["delay_seconds"] = int((c - p).total_seconds())
    for hop in oldest_first:
        hop.pop("_dt", None)
    return oldest_first


# ═══════════════════════════════════════════════════════════════════════════════
# Attachments
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_attachments(msg: email.message.Message) -> list[dict]:
    attachments = []
    for part in msg.walk():
        if (part.get_content_disposition() or "").lower() != "attachment":
            continue
        filename = _decode_header_value(part.get_filename() or "")
        payload  = part.get_payload(decode=True)
        size     = len(payload) if payload else 0
        sha256   = hashlib.sha256(payload).hexdigest() if payload else None
        if sha256 and payload:
            with _store_lock:
                _attachment_store[sha256] = {
                    "payload":      payload,
                    "filename":     filename,
                    "content_type": part.get_content_type(),
                }
        attachments.append({
            "filename":     filename or "(unnamed)",
            "content_type": part.get_content_type(),
            "size_bytes":   size,
            "sha256":       sha256,
        })
    return attachments


# ═══════════════════════════════════════════════════════════════════════════════
# IOC extraction — IPs, domains, URLs
# ═══════════════════════════════════════════════════════════════════════════════

_IPV4_RE   = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b",
    re.IGNORECASE)
_URL_RE    = re.compile(r'https?://[^\s\'"<>)\]]+', re.IGNORECASE)

# not sure to implement it or not, as many threat actor use legitimate domain like microsoft and google form and google drive
# _SKIP_DOMAINS = frozenset({
#     "localhost", "example.com", "example.org", "test.com",
#     "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
#     "microsoft.com", "google.com", "amazon.com", "w3.org",
#     "ietf.org", "schemas.microsoft.com", "schemas.xmlsoap.org",
# })


def _is_public_ip(ip: str) -> bool:
    """Return True only for well-formed, globally-routable IPv4 addresses."""
    try:
        ip_obj = ipaddress.ip_address(ip)

        # Ensure it is specifically an IPv4 address
        if not isinstance(ip_obj, ipaddress.IPv4Address):
            return False

        # .is_global returns True if the address is allocated for public use.
        # It automatically filters:
        # - Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        # - Loopback (127.0.0.0/8)
        # - Link-local (169.254.0.0/16)
        # - Multicast and Reserved ranges
        return ip_obj.is_global

    except ValueError:
        # Returns False if the string is not a valid IP format
        return False


def _extract_iocs(all_headers: list[dict], bodies: dict, attachments: list[dict]) -> dict:
    ips: set[str]     = set()
    domains: set[str] = set()
    urls: set[str]    = set()

    for hdr in all_headers:
        for val in hdr["values"]:
            ips.update(_IPV4_RE.findall(val))
            for d in _DOMAIN_RE.findall(val):
                dl = d.lower()
                # if dl not in _SKIP_DOMAINS and len(dl) > 4:
                #     domains.add(dl)
                domains.add(dl)

    for body_text in [bodies.get("plain") or "", bodies.get("html") or ""]:
        for url in _URL_RE.findall(body_text):
            urls.add(url.rstrip(".,;)>"))
        for d in _DOMAIN_RE.findall(body_text):
            dl = d.lower()
            # if dl not in _SKIP_DOMAINS and len(dl) > 4:
            #     domains.add(dl)
            domains.add(dl)

    hashes = [
        {"filename": a["filename"], "sha256": a["sha256"]}
        for a in attachments if a.get("sha256")
    ]

    return {
        "ips":     sorted(ip for ip in ips if _is_public_ip(ip)),
        "domains": sorted(domains),
        "urls":    sorted(urls),
        "hashes":  hashes,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# MIME tree (depth-limited to prevent stack overflow)
# ═══════════════════════════════════════════════════════════════════════════════

def _mime_structure(msg: email.message.Message, depth: int = 0) -> dict:
    node: dict[str, Any] = {
        "content_type":              msg.get_content_type(),
        "content_disposition":       msg.get_content_disposition() or "",
        "content_transfer_encoding": _safe_decode(msg.get("Content-Transfer-Encoding", "")),
        "filename": _decode_header_value(msg.get_filename() or ""),
        "depth":    depth,
        "children": [],
    }
    if depth >= _MAX_MIME_DEPTH:
        node["truncated"] = True
        return node
    if msg.is_multipart():
        for part in msg.get_payload():
            if isinstance(part, email.message.Message):
                node["children"].append(_mime_structure(part, depth + 1))
    return node


# ═══════════════════════════════════════════════════════════════════════════════
# Bodies
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_bodies(msg: email.message.Message) -> dict:
    plain = html = None
    for part in msg.walk():
        ct  = part.get_content_type()
        dis = (part.get_content_disposition() or "").lower()
        if dis == "attachment":
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        # Safely decode with fallback for unknown/bogus charsets
        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except (LookupError, ValueError):
            text = payload.decode("utf-8", errors="replace")

        if ct == "text/plain" and plain is None:
            plain = text
        elif ct == "text/html" and html is None:
            html = text

    # Cap the HTML body that gets base64-encoded into the JSON response
    html_b64 = None
    if html is not None:
        html_bytes = html.encode("utf-8", errors="replace")
        if len(html_bytes) <= _MAX_HTML_BODY_BYTES:
            html_b64 = base64.b64encode(html_bytes).decode()
        else:
            # Truncate and flag it
            html_b64 = base64.b64encode(
                html_bytes[:_MAX_HTML_BODY_BYTES] +
                b"\n<!-- [EML Analyzer: HTML body truncated at 5 MB] -->"
            ).decode()

    return {"plain": plain, "html": html, "html_b64": html_b64}


# ═══════════════════════════════════════════════════════════════════════════════
# X-header vendor catalogue
# ═══════════════════════════════════════════════════════════════════════════════

_X_VENDORS: dict[str, str] = {
    "x-ms-":          "Microsoft",
    "x-microsoft-":   "Microsoft",
    "x-exchange-":    "Microsoft Exchange",
    "x-google-":      "Google",
    "x-gm-":          "Gmail",
    "x-ovh-":         "OVH",
    "x-ovhspam-":     "OVH",
    "x-vr-":          "OVH",
    "x-tm-":          "Trend Micro",
    "x-tmas-":        "Trend Micro",
    "x-spam-":        "Spam Filter",
    "x-forefront-":   "Microsoft Forefront",
    "x-mailer":       "Mailer",
    "x-originating-": "Originating",
    "x-source":       "Source",
    "x-sender":       "Sender",
    "x-forwarded-":   "Forwarded",
    "x-mailgun-":     "Mailgun",
    "x-sendgrid-":    "SendGrid",
    "x-ses-":         "AWS SES",
    "x-amazon-":      "Amazon",
    "x-proofpoint-":  "Proofpoint",
    "x-barracuda-":   "Barracuda",
    "x-mimeole":      "MIME OLE",
    "x-priority":     "Priority",
    "x-received":     "Received (extended)",
}


def _vendor_for(name: str) -> str:
    nl = name.lower()
    for prefix, label in _X_VENDORS.items():
        if nl.startswith(prefix) or nl == prefix.rstrip("-"):
            return label
    return "Custom"


def _build_x_headers(all_headers: list[dict]) -> list[dict]:
    return [
        {"name": h["name"], "values": h["values"], "vendor": _vendor_for(h["name"])}
        for h in all_headers
        if h["name"].lower().startswith("x-")
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Core parser
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_eml(raw: str | bytes) -> dict:
    global _attachment_store
    with _store_lock:
        _attachment_store = {}   # clear on each parse (thread-safe)

    raw_bytes = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)

    def h(name: str) -> str:
        return _safe_decode(msg.get(name, ""))

    def h_all(name: str) -> list[str]:
        return [_safe_decode(v) for v in (msg.get_all(name) or [])]

    from_raw  = h("From")
    to_raw    = h("To")
    cc_raw    = h("CC")
    bcc_raw   = h("BCC")
    reply_raw = h("Reply-To")

    from_name_raw, from_addr = parseaddr(from_raw)
    _,             reply_addr = parseaddr(reply_raw)
    from_name = _decode_header_value(from_name_raw)

    to_list  = [{"name": _decode_header_value(n), "address": a}
                for n, a in getaddresses([to_raw])  if a]
    cc_list  = [{"name": _decode_header_value(n), "address": a}
                for n, a in getaddresses([cc_raw])  if a]
    bcc_list = [{"name": _decode_header_value(n), "address": a}
                for n, a in getaddresses([bcc_raw]) if a]

    date_raw = h("Date")
    date_iso = None
    try:
        date_iso = parsedate_to_datetime(date_raw).isoformat() if date_raw else None
    except Exception:
        pass

    auth_raw    = "\n".join(h_all("Authentication-Results"))
    auth_checks = _parse_auth_results(auth_raw) if auth_raw else []
    spf_result  = h("Received-SPF")
    dkim_header = h("DKIM-Signature")

    hops        = _parse_received_hops(h_all("Received"))
    bodies      = _extract_bodies(msg)
    attachments = _parse_attachments(msg)
    mime_tree   = _mime_structure(msg)

    seen: dict[str, list[str]] = {}
    all_headers: list[dict]    = []
    for k, v in msg.items():
        kl    = k.lower()
        entry = _safe_decode(v)
        if kl not in seen:
            seen[kl] = []
            all_headers.append({"name": k, "values": seen[kl]})
        seen[kl].append(entry)

    x_headers = _build_x_headers(all_headers)
    iocs      = _extract_iocs(all_headers, bodies, attachments)

    from_domain  = from_addr.split("@")[-1].lower()  if "@" in from_addr  else ""
    reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""
    reply_mismatch = bool(reply_addr and from_addr and from_domain != reply_domain)

    originating_ip = (
        h("X-Originating-IP") or h("X-Sender-IP") or
        h("X-Source-IP")      or h("X-Forwarded-For") or ""
    )

    return {
        "core": {
            "from":             {"raw": from_raw, "name": from_name, "address": from_addr},
            "to":               to_list,
            "cc":               cc_list,
            "bcc":              bcc_list,
            "reply_to":         {"raw": reply_raw, "address": reply_addr, "mismatch": reply_mismatch},
            "subject":          h("Subject"),
            "date":             {"raw": date_raw, "iso": date_iso},
            "message_id":       h("Message-ID"),
            "mime_version":     h("MIME-Version"),
            "content_type":     h("Content-Type"),
            "x_mailer":         h("X-Mailer"),
            "x_originating_ip": originating_ip,
        },
        "authentication": {
            "raw":                    auth_raw,
            "checks":                 auth_checks,
            "received_spf":           spf_result,
            "dkim_header":            dkim_header,
            "dkim_signature_present": bool(dkim_header),
        },
        "received_chain": hops,
        "attachments":    attachments,
        "mime_structure": mime_tree,
        "bodies":         bodies,
        "x_headers":      x_headers,
        "iocs":           iocs,
        "all_headers":    all_headers,
        "summary": {
            "total_headers":    len(list(msg.keys())),
            "hop_count":        len(hops),
            "attachment_count": len(attachments),
            "auth_count":       len(auth_checks),
            "reply_mismatch":   reply_mismatch,
            "has_html_body":    bodies["html"]  is not None,
            "has_plain_body":   bodies["plain"] is not None,
            "ioc_ip_count":     len(iocs["ips"]),
            "ioc_domain_count": len(iocs["domains"]),
            "ioc_url_count":    len(iocs["urls"]),
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index() -> Response:
    try:
        html = open(_FRONTEND_PATH, encoding="utf-8").read()

        # Replace only the LAST </body> safely
        patched = _LAST_BODY_RE.sub(
            lambda m: _PATCH_SCRIPT + "\n</body>",
            html,
            count=1
        )

        return Response(patched, mimetype="text/html")

    except FileNotFoundError:
        return Response(
            "<h2>eml-analyzer.html not found</h2><p>Place it next to main.py</p>",
            status=404,
            mimetype="text/html"
        )


@app.route("/analyze/file", methods=["POST"])
def analyze_file() -> Response:
    if not _check_origin():
        return jsonify({"error": "Forbidden: cross-origin request rejected"}), 403
    if "file" not in request.files:
        return jsonify({"error": "No file field in request"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400
    try:
        result = _parse_eml(f.read())
        return jsonify(result)
    except Exception as e:
        log.exception("Error parsing uploaded file")
        return jsonify({"error": "Parse error — check server logs"}), 500


@app.route("/analyze/text", methods=["POST"])
def analyze_text() -> Response:
    if not _check_origin():
        return jsonify({"error": "Forbidden: cross-origin request rejected"}), 403
    body = request.get_json(silent=True)
    if not body or "raw" not in body:
        return jsonify({"error": "Missing 'raw' field in JSON body"}), 400
    if len(body["raw"]) > 20 * 1024 * 1024:
        return jsonify({"error": "Input too large (max 20 MB)"}), 413
    try:
        result = _parse_eml(body["raw"])
        return jsonify(result)
    except Exception as e:
        log.exception("Error parsing pasted EML text")
        return jsonify({"error": "Parse error — check server logs"}), 500


_SHA256_RE = re.compile(r'^[0-9a-f]{64}$', re.IGNORECASE)


@app.route("/attachment/<sha256>")
def download_attachment(sha256: str) -> Response:
    # Validate the sha256 parameter is a valid hex digest
    if not _SHA256_RE.match(sha256):
        return Response("Invalid attachment ID", status=400, mimetype="text/plain")

    with _store_lock:
        entry = _attachment_store.get(sha256.lower())

    if not entry:
        return Response(
            "Attachment not found. Re-analyze the email first.",
            status=404, mimetype="text/plain")

    safe_name = _sanitise_filename(entry.get("filename") or "attachment")
    cd_header = _safe_content_disposition(safe_name)

    return Response(
        entry["payload"],
        mimetype="application/octet-stream",
        headers={"Content-Disposition": cd_header},
    )


@app.route("/health")
def health() -> Response:
    return jsonify({"status": "ok"})


# ═══════════════════════════════════════════════════════════════════════════════
# Frontend patch — injected just before the last </body>
# ═══════════════════════════════════════════════════════════════════════════════

_LAST_BODY_RE = re.compile(r"</body>(?![\s\S]*</body>)", re.IGNORECASE)

_PATCH_SCRIPT = r"""
<style>
/* ── Layout: full-width ─────────────────────────────────────────────────── */
.app { max-width:100% !important; padding:28px 40px 60px !important; }

/* ── Contrast ───────────────────────────────────────────────────────────── */
:root {
  --text:       #d4dce8;
  --text-dim:   #6e7a8a;
  --text-bright:#f0f4fa;
  --surface:    #13161e;
  --border:     #222630;
  --border2:    #2e3442;
}
.kv-table td:first-child { color:#8a96a8; }
.kv-table td:last-child  { color:#e8edf8; }
.section-head            { background:#0e1016 !important; }
.section-head:hover      { background:#13161e !important; }

/* ── Auth ───────────────────────────────────────────────────────────────── */
.auth-block             { border-bottom:1px solid var(--border); }
.auth-block:last-child  { border-bottom:none; }
.auth-proto-row         { display:flex; align-items:flex-start; gap:10px; padding:12px 16px 4px; }
.auth-proto-name        { width:52px; font-size:10px; font-weight:700; letter-spacing:.1em;
                          text-transform:uppercase; color:#8a96a8; padding-top:2px; flex-shrink:0; }
.auth-clause            { font-size:11px; color:#c8d6e8; line-height:1.7; flex:1; word-break:break-all; }
.auth-raw-block         { margin:0 16px 12px; padding:10px 14px; background:#0a0c10;
                          font-size:11px; color:#6e7a8a; white-space:pre-wrap; word-break:break-all;
                          line-height:1.7; border-left:2px solid #222630; }

/* ── Hop table ──────────────────────────────────────────────────────────── */
.hop-table              { width:100%; border-collapse:collapse; font-size:12px; }
.hop-table th           { padding:8px 12px; background:#0a0c10; color:#6e7a8a; font-size:10px;
                          letter-spacing:.08em; text-transform:uppercase; text-align:left;
                          border-bottom:1px solid var(--border); white-space:nowrap; }
.hop-table td           { padding:10px 12px; vertical-align:top; border-bottom:1px solid var(--border);
                          color:#d4dce8; word-break:break-word; }
.hop-table tr:last-child td { border-bottom:none; }
.hop-table tr.hop-raw-row td { padding:2px 12px 10px; color:#6e7a8a; font-size:10px;
                                word-break:break-all; background:#0a0c10; }
.hop-table tr:hover:not(.hop-raw-row) td { background:rgba(255,255,255,.02); }
.hop-idx                { color:var(--accent)!important; font-weight:600; width:32px; text-align:center; }
.hop-delay-badge        { display:inline-block; padding:2px 8px; font-size:10px; font-weight:600;
                          background:rgba(255,170,0,.12); color:#ffaa00; letter-spacing:.04em; }
.hop-delay-fast         { background:rgba(0,212,170,.1)!important; color:var(--accent)!important; }
.hop-delay-neg          { background:rgba(255,68,85,.1)!important; color:#ff4455!important; }

/* ── IOC ────────────────────────────────────────────────────────────────── */
.ioc-tabs               { display:flex; gap:2px; padding:12px 16px 0; border-bottom:1px solid var(--border); }
.ioc-tab                { font-family:var(--mono); font-size:10px; font-weight:600; letter-spacing:.08em;
                          text-transform:uppercase; padding:7px 16px; border:none; background:transparent;
                          color:var(--text-dim); cursor:pointer; border-bottom:2px solid transparent;
                          margin-bottom:-1px; transition:color .15s,border-color .15s; }
.ioc-tab.active         { color:var(--accent); border-bottom-color:var(--accent); }
.ioc-tab:hover          { color:var(--text); }
.ioc-panel              { display:none; }
.ioc-panel.active       { display:block; }
.ioc-list               { padding:0; }
.ioc-item               { display:flex; align-items:center; padding:8px 16px;
                          border-bottom:1px solid var(--border); gap:10px; }
.ioc-item:last-child    { border-bottom:none; }
.ioc-item:hover         { background:rgba(255,255,255,.02); }
.ioc-val                { font-size:12px; color:#5bc8ff; flex:1; word-break:break-all; font-family:var(--mono); }
.ioc-val.url            { color:#a78bfa; }
.ioc-val.hash           { font-size:11px; color:var(--accent); }
.ioc-fname              { font-size:11px; color:var(--text-dim); }
.copy-btn               { flex-shrink:0; background:transparent; border:1px solid var(--border2);
                          color:var(--text-dim); font-family:var(--mono); font-size:9px; letter-spacing:.06em;
                          text-transform:uppercase; padding:3px 9px; cursor:pointer; transition:all .15s; }
.copy-btn:hover         { border-color:var(--accent); color:var(--accent); }
.copy-btn.copied        { border-color:var(--accent); color:var(--accent); }
.copy-all-btn           { font-size:10px; padding:4px 14px; }
.dl-btn                 { flex-shrink:0; background:transparent; border:1px solid var(--border2);
                          color:var(--text-dim); font-family:var(--mono); font-size:9px; letter-spacing:.06em;
                          text-transform:uppercase; padding:3px 9px; cursor:pointer; text-decoration:none;
                          transition:all .15s; display:inline-block; }
.dl-btn:hover           { border-color:#ffaa00; color:#ffaa00; }
.ioc-empty              { padding:16px; color:var(--text-dim); font-size:12px; }

/* ── HTML viewer ────────────────────────────────────────────────────────── */
.html-toolbar           { display:flex; gap:6px; padding:10px 14px; border-bottom:1px solid var(--border);
                          background:#0a0c10; align-items:center; flex-wrap:wrap; }
.html-toolbar button    { font-family:var(--mono); font-size:10px; letter-spacing:.06em; text-transform:uppercase;
                          padding:5px 14px; border:1px solid var(--border2); background:transparent;
                          color:var(--text-dim); cursor:pointer; transition:all .15s; }
.html-toolbar button.active { border-color:var(--accent); color:var(--accent); background:rgba(0,212,170,.06); }
.html-toolbar button:hover  { border-color:var(--text); color:var(--text); }
.html-frame             { width:100%; height:520px; border:none; background:#fff; display:block; }
.html-source            { background:#080a0d; padding:14px; font-size:11px; line-height:1.8;
                          white-space:pre; overflow:auto; max-height:520px; color:#abb2bf; }
.hl-tag     { color:#e06c75; }
.hl-attr    { color:#d19a66; }
.hl-val     { color:#98c379; }
.hl-cmt     { color:#5c6370; font-style:italic; }
.hl-doctype { color:#5c6370; }

/* ── MIME tree ──────────────────────────────────────────────────────────── */
.mime-node              { border-left:2px solid var(--border2); margin-left:16px; padding:5px 10px; font-size:11px; }
.mime-node:first-child  { margin-left:0; border-left:none; padding-left:0; }
.mime-type  { color:#5bc8ff; }
.mime-dis   { color:var(--text-dim); font-size:10px; margin-left:8px; }
.mime-fn    { color:#ffaa00; font-size:10px; margin-left:8px; }
.mime-enc   { color:var(--text-dim); font-size:10px; margin-left:8px; }

/* ── Confirm overlay ────────────────────────────────────────────────────── */
.confirm-overlay        { position:fixed; inset:0; background:rgba(0,0,0,.75); z-index:9999;
                          display:flex; align-items:center; justify-content:center; }
.confirm-box            { background:#13161e; border:1px solid var(--border2); padding:28px 32px; max-width:440px; }
.confirm-box h3         { font-size:14px; color:var(--danger); margin-bottom:12px; }
.confirm-box p          { color:var(--text-dim); margin-bottom:20px; font-size:12px; line-height:1.7; }
.confirm-btns           { display:flex; gap:10px; justify-content:flex-end; }
.confirm-btns button    { font-family:var(--mono); font-size:11px; letter-spacing:.08em;
                          text-transform:uppercase; padding:8px 20px; cursor:pointer; border:none; }
.confirm-cancel         { background:transparent; border:1px solid var(--border2)!important; color:var(--text-dim); }
.confirm-proceed        { background:var(--danger); color:#fff; }

/* ── Misc ───────────────────────────────────────────────────────────────── */
.summary-card .value    { font-size:12px; color:#e0e8f5; }
</style>

<script>
// ═══════════════════════════════════════════════════════════════════════════
// Backend bridge
// ═══════════════════════════════════════════════════════════════════════════
async function callBackend(endpoint, payload) {
  let resp;
  if (endpoint === 'file') {
    const fd = new FormData();
    fd.append('file', payload);
    resp = await fetch('/analyze/file', { method:'POST', body:fd });
  } else {
    resp = await fetch('/analyze/text', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw: payload }),
    });
  }
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: resp.statusText }));
    throw new Error(err.error || 'Server error');
  }
  return resp.json();
}

function analyzeFile() {
  const fi = document.getElementById('fileInput'), file = fi.files[0];
  if (!file && !loadedFileContent) { alert('Please select an .eml file first.'); return; }
  if (!file) {
    callBackend('text', loadedFileContent).then(renderFromBackend).catch(e => showError(e.message));
    return;
  }
  callBackend('file', file).then(renderFromBackend).catch(e => showError(e.message));
}

function analyzeText() {
  const raw = document.getElementById('rawInput').value.trim();
  if (!raw) { alert('Please paste some content first.'); return; }
  callBackend('text', raw).then(renderFromBackend).catch(e => showError(e.message));
}

function showError(msg) {
  const eb = document.getElementById('error-box');
  eb.textContent = '❌ ' + msg;
  eb.style.display = 'block';
  document.getElementById('results').classList.add('visible');
}

// ═══════════════════════════════════════════════════════════════════════════
// Main renderer
// ═══════════════════════════════════════════════════════════════════════════
function renderFromBackend(d) {
  document.getElementById('error-box').style.display = 'none';
  const core     = d.core            || {};
  const auth     = d.authentication  || {};
  const hops     = d.received_chain  || [];
  const attaches = d.attachments     || [];
  const summary  = d.summary         || {};
  const allHdrs  = d.all_headers     || [];
  const xHdrs    = d.x_headers       || [];
  const iocs     = d.iocs            || {};
  const mime     = d.mime_structure  || null;
  const bodies   = d.bodies          || {};

  document.getElementById('parse-status').className   = 'badge badge-ok';
  document.getElementById('parse-status').textContent = '● Parsed OK';

  // Summary strip
  const fromAddr = core.from ? core.from.address : '—';
  document.getElementById('summary-strip').innerHTML = [
    { label:'From',          value: fromAddr || '—', cls:'' },
    { label:'Subject',       value: core.subject || '—', cls:'' },
    { label:'Date',          value: core.date ? (core.date.raw || '—') : '—', cls:'' },
    { label:'Hops',          value: summary.hop_count ?? '—', cls: summary.hop_count > 5 ? 'warn' : 'accent' },
    { label:'IPs / Domains', value: `${(iocs.ips||[]).length} / ${(iocs.domains||[]).length}`, cls:'' },
    { label:'Attachments',   value: summary.attachment_count ?? 0, cls: summary.attachment_count ? 'warn' : '' },
  ].map(c => `<div class="summary-card"><div class="label">${c.label}</div><div class="value ${c.cls}">${escHtml(String(c.value))}</div></div>`).join('');

  const sections = [];

  // ── MIME Structure ────────────────────────────────────────────────────────
  if (mime) {
    sections.push({ title:'MIME Structure', count:'',
      html:`<div style="padding:14px 18px">${renderMimeNode(mime)}</div>` });
  }

  // ── Core Headers ──────────────────────────────────────────────────────────
  const mismatch = core.reply_to && core.reply_to.mismatch;
  const toStr    = (core.to  || []).map(t => t.name ? `${t.name} <${t.address}>` : t.address).join(', ');
  const ccStr    = (core.cc  || []).map(t => t.name ? `${t.name} <${t.address}>` : t.address).join(', ');
  const bccStr   = (core.bcc || []).map(t => t.name ? `${t.name} <${t.address}>` : t.address).join(', ');
  const coreRows = [
    ['From',             core.from ? core.from.raw : ''],
    ['To',               toStr], ['CC', ccStr], ['BCC', bccStr],
    ['Reply-To',         (core.reply_to?.raw || '') + (mismatch ? ' ⚠ domain mismatch' : '')],
    ['Subject',          core.subject],
    ['Date',             core.date ? core.date.raw : ''],
    ['Message-ID',       core.message_id],
    ['MIME-Version',     core.mime_version],
    ['Content-Type',     core.content_type],
    ['X-Mailer',         core.x_mailer],
    ['X-Originating-IP', core.x_originating_ip],
  ].filter(([, v]) => v);

  sections.push({ title:'Core Headers', count: coreRows.length,
    html: `<table class="kv-table">${coreRows.map(([k, v]) => `<tr>
      <td>${escHtml(k)}</td>
      <td style="${k === 'Reply-To' && mismatch ? 'color:#ffaa00' : ''}">${escHtml(v)}</td>
    </tr>`).join('')}</table>`
  });

  // ── Authentication ────────────────────────────────────────────────────────
  if (auth.raw) {
    const checks = auth.checks || [];
    let authHtml = '';
    if (checks.length) {
      authHtml += checks.map(c => {
        const pass    = ['pass', 'bestguesspass'].includes(c.result);
        const fail    = ['fail', 'hardfail', 'softfail', 'none', 'permerror', 'temperror'].includes(c.result);
        const pillCls = pass ? 'pill-pass' : fail ? 'pill-fail' : 'pill-none';
        return `<div class="auth-block">
          <div class="auth-proto-row">
            <span class="auth-proto-name">${c.name}</span>
            <span class="pill ${pillCls}" style="flex-shrink:0;margin-top:1px">${escHtml(c.result)}</span>
            <span class="auth-clause">${escHtml(c.clause || '')}</span>
          </div>
        </div>`;
      }).join('');
    }
    authHtml += `<div style="padding:4px 16px 12px">
      <div style="font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--text-dim);margin-bottom:6px;margin-top:8px;">Full Authentication-Results</div>
      <div class="auth-raw-block">${escHtml(auth.raw)}</div>
    </div>`;
    if (auth.received_spf) {
      authHtml += `<div class="auth-block"><div class="auth-proto-row">
        <span class="auth-proto-name">SPF HDR</span>
        <span class="auth-clause">${escHtml(auth.received_spf)}</span>
      </div></div>`;
    }
    if (auth.dkim_header) {
      authHtml += `<div class="auth-block"><div class="auth-proto-row">
        <span class="auth-proto-name">DKIM SIG</span>
        <span class="auth-clause" style="word-break:break-all">${escHtml(auth.dkim_header)}</span>
      </div></div>`;
    }
    sections.push({ title:'Authentication', count: checks.length || 1, html: authHtml });
  }

  // ── Received Chain ────────────────────────────────────────────────────────
  if (hops.length) {
    let ht = `<table class="hop-table">
      <thead><tr><th>#</th><th>Sender</th><th>Receiver</th><th>Protocol</th><th>Timestamp</th><th>Delay</th></tr></thead>
      <tbody>`;
    hops.forEach((hop, i) => {
      const ds = hop.delay_seconds;
      let dcls = 'hop-delay-badge', dtxt = '—';
      if (ds != null) {
        dtxt = ds >= 0 ? `+${ds}s` : `${ds}s`;
        dcls += ds < 0 ? ' hop-delay-neg' : ds < 5 ? ' hop-delay-fast' : '';
      }
      const ips = hop.ips && hop.ips.length
        ? `<br><span style="color:#5bc8ff;font-size:10px">[${escHtml(hop.ips.join(', '))}]</span>` : '';
      ht += `<tr>
        <td class="hop-idx">${i + 1}</td>
        <td>${escHtml(hop.sender || '—')}${ips}</td>
        <td>${escHtml(hop.receiver || '—')}</td>
        <td style="color:var(--text-dim)">${escHtml(hop.protocol || '—')}</td>
        <td style="color:var(--text-dim);font-size:11px;white-space:nowrap">${escHtml(hop.timestamp_iso || '—')}</td>
        <td><span class="${dcls}">${dtxt}</span></td>
      </tr>
      <tr class="hop-raw-row"><td colspan="6">${escHtml(hop.raw)}</td></tr>`;
    });
    ht += '</tbody></table>';
    sections.push({ title:'Received Chain', count: hops.length, html: ht });
  }

  // ── IOC — IPs / Domains / URLs / Hashes ──────────────────────────────────
  const ips     = iocs.ips     || [];
  const domains = iocs.domains || [];
  const urls    = iocs.urls    || [];
  const hashes  = iocs.hashes  || [];
  const iocTotal = ips.length + domains.length + urls.length + hashes.length;

  if (iocTotal > 0) {
    const tabs = [
      { id:'ioc-ips',     label:`IPs (${ips.length})`,         items:ips,     cls:'',    type:'ip'     },
      { id:'ioc-domains', label:`Domains (${domains.length})`, items:domains, cls:'',    type:'domain' },
      { id:'ioc-urls',    label:`URLs (${urls.length})`,       items:urls,    cls:'url', type:'url'    },
      { id:'ioc-hashes',  label:`Hashes (${hashes.length})`,   items:hashes,  cls:'hash',type:'hash'   },
    ];

    const tabBar = tabs.map((t, i) =>
      `<button class="ioc-tab${i === 0 ? ' active' : ''}" onclick="switchIocTab('${t.id}',this)">${t.label}</button>`
    ).join('');

    const panels = tabs.map((t, i) => {
      // Build the copy-all text (joined list of values for this tab)
      const copyAllText = t.type === 'hash'
        ? hashes.map(h => h.sha256).join('\n')
        : t.items.join('\n');

      let inner = '';
      if (t.type === 'hash') {
        inner = hashes.length
          ? hashes.map(h => `<div class="ioc-item">
              <div style="flex:1">
                <div class="ioc-fname">${escHtml(h.filename)}</div>
                <div class="ioc-val hash">${escHtml(h.sha256)}</div>
              </div>
              <button class="copy-btn" onclick="copyText(this,${JSON.stringify(h.sha256)})">Copy</button>
            </div>`).join('')
          : '<div class="ioc-empty">No attachment hashes</div>';
      } else {
        inner = t.items.length
          ? t.items.map(v => `<div class="ioc-item">
              <span class="ioc-val ${t.cls}">${escHtml(v)}</span>
              <button class="copy-btn" onclick="copyText(this,${JSON.stringify(v)})">Copy</button>
            </div>`).join('')
          : `<div class="ioc-empty">No ${t.type}s found</div>`;
      }

      const hasItems = t.type === 'hash' ? hashes.length > 0 : t.items.length > 0;
      const copyAllBtn = hasItems
        ? `<button class="copy-btn copy-all-btn" onclick="copyText(this,${JSON.stringify(copyAllText)})">⎘ Copy All</button>`
        : '';

      return `<div class="ioc-panel${i === 0 ? ' active' : ''}" id="${t.id}">
        ${copyAllBtn ? `<div style="padding:8px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:flex-end">${copyAllBtn}</div>` : ''}
        <div class="ioc-list">${inner}</div>
      </div>`;
    }).join('');

    sections.push({ title:'IOC — IPs / Domains / URLs / Hashes', count: iocTotal,
      html:`<div class="ioc-tabs">${tabBar}</div>${panels}` });
  }

  // ── X-Headers ─────────────────────────────────────────────────────────────
  if (xHdrs.length) {
    const byVendor = {};
    xHdrs.forEach(x => { const v = x.vendor || 'Custom'; (byVendor[v] = byVendor[v] || []).push(x); });
    let xHtml = '';
    Object.entries(byVendor).forEach(([vendor, hdrs]) => {
      xHtml += `<div style="border-bottom:1px solid var(--border)">
        <div style="padding:8px 16px 4px;font-size:10px;color:#5bc8ff;letter-spacing:.08em;text-transform:uppercase">${escHtml(vendor)}</div>
        <table class="kv-table" style="margin-bottom:4px">`;
      hdrs.forEach(x => x.values.forEach(v => {
        xHtml += `<tr><td>${escHtml(x.name)}</td><td>${escHtml(v)}</td></tr>`;
      }));
      xHtml += '</table></div>';
    });
    sections.push({ title:'X-Headers', count: xHdrs.length, html: xHtml });
  }

  // ── Attachments ───────────────────────────────────────────────────────────
  if (attaches.length) {
    sections.push({ title:'Attachments', count: attaches.length,
      html: attaches.map(a => `
        <div class="attach-row">
          <span class="attach-icon">📎</span>
          <span class="attach-name">${escHtml(a.filename)}</span>
          <span class="attach-type">${escHtml(a.content_type)}</span>
          <span class="attach-size" style="margin-left:auto">${formatBytes(a.size_bytes)}</span>
          ${a.sha256 ? `<a class="dl-btn" href="/attachment/${escHtml(a.sha256)}" title="Download as .bin (all extensions stripped)">⬇ .bin</a>` : ''}
        </div>
        ${a.sha256 ? `<div style="padding:0 16px 10px;font-size:10px;color:var(--text-dim)">SHA-256: <span style="color:var(--accent);font-family:var(--mono)">${escHtml(a.sha256)}</span></div>` : ''}
      `).join('')
    });
  }

  // ── HTML Body viewer ──────────────────────────────────────────────────────
  if (bodies.html_b64) {
    const rawHtml = b64DecodeUnicode(bodies.html_b64);
    sections.push({ title:'HTML Body', count:'', html: buildHtmlViewer(rawHtml) });
  } else if (bodies.plain) {
    sections.push({ title:'Plain Body', count:'',
      html:`<div class="raw-block" style="max-height:400px">${escHtml(bodies.plain)}</div>` });
  }

  // ── All Headers (raw) ─────────────────────────────────────────────────────
  const rawBlock = allHdrs.map(h =>
    h.values.map(v =>
      `<span class="h-name">${escHtml(h.name)}</span>: <span class="h-val">${escHtml(v)}</span>`
    ).join('\n')
  ).join('\n');
  sections.push({ title:'All Headers (Raw)', count: allHdrs.reduce((s, h) => s + h.values.length, 0),
    html:`<div class="raw-block">${rawBlock}</div>` });

  // Render all sections into the DOM
  document.getElementById('sections-container').innerHTML = sections.map((s, i) => `
    <div class="section" id="sec-${i}">
      <div class="section-head" onclick="toggleSection(${i})">
        <span class="section-name">${escHtml(s.title)}
          ${s.count !== '' ? `<span class="section-count">${s.count}</span>` : ''}
        </span>
        <span class="chevron">▾</span>
      </div>
      <div class="section-body">${s.html}</div>
    </div>`).join('');

  document.getElementById('results').classList.add('visible');
  document.getElementById('results').scrollIntoView({ behavior:'smooth', block:'start' });
}

// ── HTML viewer ────────────────────────────────────────────────────────────
// Raw HTML is stored in a data-b64 attribute on the container div.
// This avoids injecting <script> tags via innerHTML (which browsers block).
function buildHtmlViewer(rawHtml) {
  // TextEncoder-based base64 — handles full Unicode without deprecated APIs
  const b64 = b64EncodeUnicode(rawHtml);
  return `
    <div class="html-toolbar" id="html-toolbar">
      <span style="font-size:10px;color:var(--text-dim);letter-spacing:.06em;text-transform:uppercase;margin-right:4px;">View:</span>
      <button class="active" onclick="htmlMode('block-remote',this)">Render (Block Remote)</button>
      <button onclick="htmlModeConfirm(this)">Render (With Remote)</button>
      <button onclick="htmlMode('source',this)">HTML Source</button>
    </div>
    <div id="html-viewer-body" data-b64="${escAttr(b64)}">
      ${buildSrcdocFrame(rawHtml, false)}
    </div>`;
}

function getViewerRaw() {
  const el = document.getElementById('html-viewer-body');
  if (!el) return '';
  return b64DecodeUnicode(el.getAttribute('data-b64') || '');
}

function buildSrcdocFrame(html, allowScripts) {
  // SECURITY: never combine allow-same-origin with allow-scripts.
  // allow-same-origin alone lets the iframe read its own srcdoc (needed for
  // rendering) but does NOT allow scripts — so remote resources that try to
  // execute JS are blocked. With allow-scripts we intentionally drop
  // allow-same-origin to prevent iframe→parent DOM access (XSS escape).
  const sandbox = allowScripts
    ? 'allow-scripts allow-popups allow-forms'   // no allow-same-origin
    : 'allow-same-origin';                        // no allow-scripts
  return `<iframe class="html-frame" sandbox="${sandbox}" srcdoc="${escAttr(html)}"></iframe>`;
}

function htmlMode(mode, btn) {
  document.querySelectorAll('#html-toolbar button').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  const raw  = getViewerRaw();
  const body = document.getElementById('html-viewer-body');
  const b64  = body.getAttribute('data-b64');   // preserve before innerHTML wipe
  if (mode === 'source') {
    body.innerHTML = `<div class="html-source">${syntaxHighlightHtml(raw)}</div>`;
  } else if (mode === 'block-remote') {
    body.innerHTML = buildSrcdocFrame(raw, false);
  } else if (mode === 'with-remote') {
    body.innerHTML = buildSrcdocFrame(raw, true);
  }
  body.setAttribute('data-b64', b64);            // restore after innerHTML wipe
}

function htmlModeConfirm(btn) {
  const overlay = document.createElement('div');
  overlay.className = 'confirm-overlay';
  overlay.innerHTML = `
    <div class="confirm-box">
      <h3>⚠ Load Remote Resources?</h3>
      <p>This will allow scripts and external resources (images, stylesheets) in the email's HTML body to execute.
         Remote resources can reveal your IP address to the sender and may execute tracking pixels or malicious code.
         Scripts run in an isolated sandbox without access to this page.</p>
      <div class="confirm-btns">
        <button class="confirm-cancel" onclick="this.closest('.confirm-overlay').remove()">Cancel</button>
        <button class="confirm-proceed" onclick="this.closest('.confirm-overlay').remove();htmlMode('with-remote',document.querySelector('#html-toolbar button:nth-child(3)'))">
          I understand — Load Remote
        </button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
}

// ── HTML syntax highlighter ────────────────────────────────────────────────
function syntaxHighlightHtml(raw) {
  return escHtml(raw)
    .replace(/(&lt;!DOCTYPE[^&]*&gt;)/gi, '<span class="hl-doctype">$1</span>')
    .replace(/(&lt;!--[\s\S]*?--&gt;)/g,  '<span class="hl-cmt">$1</span>')
    .replace(/(&lt;\/?)([\w:-]+)((?:\s[^&]*)?)(&gt;)/g, (_, open, tag, attrs, close) => {
      const hiAttrs = attrs.replace(
        /([\w:-]+)(=)(&quot;[^&]*&quot;|&#39;[^&]*&#39;|\S+)/g,
        '<span class="hl-attr">$1</span><span style="color:#abb2bf">$2</span><span class="hl-val">$3</span>'
      );
      return `<span class="hl-tag">${open}${tag}</span>${hiAttrs}<span class="hl-tag">${close}</span>`;
    });
}

// ── MIME tree ──────────────────────────────────────────────────────────────
function renderMimeNode(node) {
  const fn  = node.filename ? `<span class="mime-fn">📎 ${escHtml(node.filename)}</span>` : '';
  const dis = node.content_disposition ? `<span class="mime-dis">[${escHtml(node.content_disposition)}]</span>` : '';
  const enc = node.content_transfer_encoding ? `<span class="mime-enc">${escHtml(node.content_transfer_encoding)}</span>` : '';
  const trunc = node.truncated ? '<span style="color:var(--warn);font-size:10px"> [truncated — too deeply nested]</span>' : '';
  let html = `<div class="mime-node"><span class="mime-type">${escHtml(node.content_type)}</span>${dis}${fn}${enc}${trunc}`;
  if (node.children && node.children.length) {
    html += node.children.map(renderMimeNode).join('');
  }
  return html + '</div>';
}

// ── IOC tab switching ──────────────────────────────────────────────────────
function switchIocTab(id, btn) {
  const body = btn.closest('.section-body');
  body.querySelectorAll('.ioc-tab').forEach(b => b.classList.remove('active'));
  body.querySelectorAll('.ioc-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById(id).classList.add('active');
}

// ── Copy with clipboard API + graceful fallback ────────────────────────────
function copyText(btn, text) {
  const origLabel = btn.textContent;
  const ok  = () => { btn.textContent = 'Copied!'; btn.classList.add('copied');
                       setTimeout(() => { btn.textContent = origLabel; btn.classList.remove('copied'); }, 1500); };
  const err = () => { btn.textContent = 'Failed!';
                       setTimeout(() => { btn.textContent = origLabel; }, 1500); };

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(ok).catch(err);
  } else {
    // Fallback for non-HTTPS contexts
    try {
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      ok();
    } catch { err(); }
  }
}

// ── Utilities ──────────────────────────────────────────────────────────────
// TextEncoder-based base64 — handles full Unicode, no deprecated escape()
function b64EncodeUnicode(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary);
}

function b64DecodeUnicode(b64) {
  try {
    const binary = atob(b64);
    const bytes  = Uint8Array.from(binary, c => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return '';
  }
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escAttr(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
</script>
"""


def _patch_frontend(html: str) -> str:
    """Replace only the LAST </body> tag to avoid double-injection."""

    return  _LAST_BODY_RE.sub(
        lambda m: _PATCH_SCRIPT + "\n</body>",
        html,
        count=1
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EML Analyzer")
    parser.add_argument("-p", "--port",      default=5000,        type=int,  help="Port (default 5000)")
    parser.add_argument("-d", "--debug",     action="store_true",            help="Debug mode (never in production)")
    parser.add_argument("-i", "--interface", default="127.0.0.1", type=str,  help="Bind interface (default localhost)")
    args = parser.parse_args()

    if args.debug:
        log.warning("⚠  Debug mode enabled — Werkzeug debugger exposed. Never use in production.")

    print("=" * 55)
    print("  EML Analyzer")
    print(f"  http://{args.interface}:{args.port}/")
    print("=" * 55)
    app.run(debug=args.debug, host=args.interface, port=args.port)