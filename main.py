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
* Intended for LOCAL / TRUSTED-LAN use only.
* Never expose to the public internet without authentication.
"""
import argparse
import base64
import email
import email.header
import email.policy
import hashlib
import ipaddress
import logging
import os
import threading
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from typing import Any

import re2 as re
from flask import Flask, jsonify, request, Response
from werkzeug.utils import secure_filename

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

_FRONTEND_PATH       = os.path.join(os.path.dirname(__file__), "eml-analyzer.html")
_MAX_HTML_BODY_BYTES = 5 * 1024 * 1024
_MAX_MIME_DEPTH      = 30

_store_lock       = threading.Lock()
_attachment_store: dict[str, dict] = {}


# ═══════════════════════════════════════════════════════════════════════════════
# Security headers
# ═══════════════════════════════════════════════════════════════════════════════

@app.after_request
def add_security_headers(resp: Response) -> Response:
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"]        = "DENY"
    resp.headers["Referrer-Policy"]        = "no-referrer"
    resp.headers["Cache-Control"]          = "no-store"
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
# CSRF origin check
# ═══════════════════════════════════════════════════════════════════════════════

def _check_origin() -> bool:
    origin  = request.headers.get("Origin", "")
    referer = request.headers.get("Referer", "")
    host    = request.host
    if not origin and not referer:
        return True
    allowed = f"http://{host}"
    if origin  and not (origin  == allowed or origin.startswith(allowed + "/")):
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
    if raw is None:
        return ""
    raw_str = str(raw).strip()
    try:
        return str(make_header(decode_header(raw_str)))
    except Exception:
        try:
            parts = decode_header(raw_str)
            out = []
            for chunk, charset in parts:
                if isinstance(chunk, bytes):
                    try:
                        out.append(chunk.decode(charset or "utf-8", errors="replace"))
                    except (LookupError, ValueError):
                        out.append(chunk.decode("utf-8", errors="replace"))
                else:
                    out.append(str(chunk))
            return " ".join("".join(out).split()).strip()
        except Exception:
            return raw_str


def _sanitise_filename(filename: str) -> str:
    if not filename:
        return "unnamed_attachment.bin"
    clean = secure_filename(filename)
    base  = clean.split(".")[0] or "attachment"
    return f"{base}.bin"


def _safe_content_disposition(filename: str) -> str:
    ascii_name = filename.encode("ascii", errors="replace").decode("ascii")
    encoded    = "".join(
        c if c.isalnum() or c in "-_.~" else f"%{ord(c):02X}"
        for c in filename
    )
    return f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{encoded}'


# ═══════════════════════════════════════════════════════════════════════════════
# Authentication
# ═══════════════════════════════════════════════════════════════════════════════

_AUTH_RE = re.compile(r"(?i)\b(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)")


def _parse_auth_results(raw: str) -> list[dict]:
    if not raw:
        return []
    normalized = " ".join(raw.split())
    results    = []
    for m in _AUTH_RE.finditer(normalized):
        start = m.start()
        results.append({
            "name":   m.group(1).upper(),
            "result": m.group(2).lower(),
            "clause": normalized[start: start + 150].strip(),
        })
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# Received chain
# ═══════════════════════════════════════════════════════════════════════════════

_FROM_RE = re.compile(r"(?i)from\s+(\S+)(?:\s+\(([^)]+)\))?")
_BY_RE   = re.compile(r"(?i)by\s+(\S+)")
_WITH_RE = re.compile(r"(?i)with\s+(\S+)")
_FOR_RE  = re.compile(r"(?i)for\s+(\S+)")
_IP_RE   = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")


def _parse_one_received(raw: str) -> dict:
    raw  = raw.strip()
    body, ts_str = (raw.rsplit(";", 1) + [""])[:2] if ";" in raw else (raw, "")
    ts = ts_iso = None
    if ts_str.strip():
        try:
            ts     = parsedate_to_datetime(ts_str.strip())
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
# IOC extraction
# ═══════════════════════════════════════════════════════════════════════════════

_IPV4_RE   = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
_URL_RE    = re.compile(r"(?i)https?://[^\s'\"<>)\]]+")


def _is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return isinstance(obj, ipaddress.IPv4Address) and obj.is_global
    except ValueError:
        return False


def _extract_iocs(all_headers: list[dict], bodies: dict, attachments: list[dict]) -> dict:
    ips: set[str]     = set()
    domains: set[str] = set()
    urls: set[str]    = set()

    for hdr in all_headers:
        for val in hdr["values"]:
            ips.update(_IPV4_RE.findall(val))
            domains.update(d.lower() for d in _DOMAIN_RE.findall(val))

    for body_text in [bodies.get("plain") or "", bodies.get("html") or ""]:
        urls.update(u.rstrip(".,;)>") for u in _URL_RE.findall(body_text))
        domains.update(d.lower() for d in _DOMAIN_RE.findall(body_text))

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
# MIME tree
# ═══════════════════════════════════════════════════════════════════════════════

def _mime_structure(msg: email.message.Message, depth: int = 0) -> dict:
    node: dict[str, Any] = {
        "content_type":              msg.get_content_type(),
        "content_disposition":       msg.get_content_disposition() or "",
        "content_transfer_encoding": _safe_decode(msg.get("Content-Transfer-Encoding", "")),
        "filename":  _decode_header_value(msg.get_filename() or ""),
        "depth":     depth,
        "children":  [],
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
        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except (LookupError, ValueError):
            text = payload.decode("utf-8", errors="replace")
        if ct == "text/plain" and plain is None:
            plain = text
        elif ct == "text/html" and html is None:
            html = text

    html_b64 = None
    if html is not None:
        html_bytes = html.encode("utf-8", errors="replace")
        if len(html_bytes) <= _MAX_HTML_BODY_BYTES:
            html_b64 = base64.b64encode(html_bytes).decode()
        else:
            html_b64 = base64.b64encode(
                html_bytes[:_MAX_HTML_BODY_BYTES]
                + b"\n<!-- [EML Analyzer: HTML truncated at 5 MB] -->"
            ).decode()

    return {"plain": plain, "html": html, "html_b64": html_b64}


# ═══════════════════════════════════════════════════════════════════════════════
# X-header catalogue
# ═══════════════════════════════════════════════════════════════════════════════

_X_VENDORS: dict[str, str] = {
    "x-ms-": "Microsoft", "x-microsoft-": "Microsoft", "x-exchange-": "Microsoft Exchange",
    "x-google-": "Google", "x-gm-": "Gmail",
    "x-ovh-": "OVH", "x-ovhspam-": "OVH", "x-vr-": "OVH",
    "x-tm-": "Trend Micro", "x-tmas-": "Trend Micro",
    "x-spam-": "Spam Filter", "x-forefront-": "Microsoft Forefront",
    "x-mailer": "Mailer", "x-originating-": "Originating",
    "x-source": "Source", "x-sender": "Sender",
    "x-forwarded-": "Forwarded", "x-mailgun-": "Mailgun",
    "x-sendgrid-": "SendGrid", "x-ses-": "AWS SES", "x-amazon-": "Amazon",
    "x-proofpoint-": "Proofpoint", "x-barracuda-": "Barracuda",
    "x-mimeole": "MIME OLE", "x-priority": "Priority",
    "x-received": "Received (extended)",
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
        for h in all_headers if h["name"].lower().startswith("x-")
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# Core parser
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_eml(raw: str | bytes) -> dict:
    global _attachment_store
    with _store_lock:
        _attachment_store = {}

    raw_bytes = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)

    def h(name: str) -> str:
        return _safe_decode(msg.get(name, ""))

    def h_all(name: str) -> list[str]:
        return [_safe_decode(v) for v in (msg.get_all(name) or [])]

    from_raw = h("From"); to_raw = h("To"); cc_raw = h("CC")
    bcc_raw  = h("BCC"); reply_raw = h("Reply-To")

    from_name_raw, from_addr = parseaddr(from_raw)
    _,             reply_addr = parseaddr(reply_raw)
    from_name = _decode_header_value(from_name_raw)

    to_list  = [{"name": _decode_header_value(n), "address": a} for n, a in getaddresses([to_raw])  if a]
    cc_list  = [{"name": _decode_header_value(n), "address": a} for n, a in getaddresses([cc_raw])  if a]
    bcc_list = [{"name": _decode_header_value(n), "address": a} for n, a in getaddresses([bcc_raw]) if a]

    date_raw = h("Date"); date_iso = None
    try:
        date_iso = parsedate_to_datetime(date_raw).isoformat() if date_raw else None
    except Exception:
        pass

    auth_raw    = "\n".join(h_all("Authentication-Results"))
    auth_checks = _parse_auth_results(auth_raw)
    spf_result  = h("Received-SPF")
    dkim_header = h("DKIM-Signature")

    hops        = _parse_received_hops(h_all("Received"))
    bodies      = _extract_bodies(msg)
    attachments = _parse_attachments(msg)
    mime_tree   = _mime_structure(msg)

    seen: dict[str, list[str]] = {}
    all_headers: list[dict]    = []
    for k, v in msg.items():
        kl = k.lower(); entry = _safe_decode(v)
        if kl not in seen:
            seen[kl] = []
            all_headers.append({"name": k, "values": seen[kl]})
        seen[kl].append(entry)

    x_headers = _build_x_headers(all_headers)
    iocs      = _extract_iocs(all_headers, bodies, attachments)

    from_domain  = from_addr.split("@")[-1].lower()  if "@" in from_addr  else ""
    reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""
    reply_mismatch = bool(reply_addr and from_addr and from_domain != reply_domain)
    originating_ip = (h("X-Originating-IP") or h("X-Sender-IP") or
                      h("X-Source-IP")      or h("X-Forwarded-For") or "")

    return {
        "core": {
            "from":             {"raw": from_raw, "name": from_name, "address": from_addr},
            "to": to_list, "cc": cc_list, "bcc": bcc_list,
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
            "raw": auth_raw, "checks": auth_checks,
            "received_spf": spf_result, "dkim_header": dkim_header,
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
        return Response(open(_FRONTEND_PATH, encoding="utf-8").read(), mimetype="text/html")
    except FileNotFoundError:
        return Response("<h2>eml-analyzer.html not found</h2>", status=404, mimetype="text/html")


@app.route("/analyze/file", methods=["POST"])
def analyze_file() -> Response:
    if not _check_origin():
        return jsonify({"error": "Forbidden"}), 403
    if "file" not in request.files:
        return jsonify({"error": "No file field"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400
    try:
        return jsonify(_parse_eml(f.read()))
    except Exception:
        log.exception("Error parsing uploaded file")
        return jsonify({"error": "Parse error — check server logs"}), 500


@app.route("/analyze/text", methods=["POST"])
def analyze_text() -> Response:
    if not _check_origin():
        return jsonify({"error": "Forbidden"}), 403
    body = request.get_json(silent=True)
    if not body or "raw" not in body:
        return jsonify({"error": "Missing 'raw' field"}), 400
    if len(body["raw"]) > 20 * 1024 * 1024:
        return jsonify({"error": "Input too large (max 20 MB)"}), 413
    try:
        return jsonify(_parse_eml(body["raw"]))
    except Exception:
        log.exception("Error parsing pasted EML text")
        return jsonify({"error": "Parse error — check server logs"}), 500


_SHA256_RE = re.compile(r"(?i)^[0-9a-f]{64}$")


@app.route("/attachment/<sha256>")
def download_attachment(sha256: str) -> Response:
    if not _SHA256_RE.match(sha256):
        return Response("Invalid ID", status=400, mimetype="text/plain")
    with _store_lock:
        entry = _attachment_store.get(sha256.lower())
    if not entry:
        return Response("Not found — re-analyze first", status=404, mimetype="text/plain")
    safe_name = _sanitise_filename(entry.get("filename") or "attachment")
    return Response(
        entry["payload"],
        mimetype="application/octet-stream",
        headers={"Content-Disposition": _safe_content_disposition(safe_name)},
    )


@app.route("/health")
def health() -> Response:
    return jsonify({"status": "ok"})


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EML Analyzer")
    parser.add_argument("-p", "--port",      default=5000,        type=int)
    parser.add_argument("-d", "--debug",     action="store_true")
    parser.add_argument("-i", "--interface", default="127.0.0.1", type=str)
    args = parser.parse_args()
    if args.debug:
        log.warning("⚠  Debug mode — never use in production")
    print("=" * 55)
    print("  EML Analyzer")
    print(f"  http://{args.interface}:{args.port}/")
    print("=" * 55)
    app.run(debug=args.debug, host=args.interface, port=args.port)