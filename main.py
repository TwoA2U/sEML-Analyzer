"""
EML Analyzer — Flask Backend
=============================
Serves the frontend and exposes two API endpoints:

    POST /analyze/file    multipart/form-data  field: file (.eml)
    POST /analyze/text    application/json     field: raw (string)

Both return the same JSON structure consumed by the frontend.

Requirements:
    pip install flask

Run:
    python main.py
    python main.py -p 8080 -i 0.0.0.0 -d
"""
import argparse
import base64
import email
import email.policy
import email.header
import hashlib
import re
from email.utils import parseaddr, parsedate_to_datetime, getaddresses
import sys
from typing import Any

from flask import Flask, jsonify, request, Response

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB upload limit

import os
_FRONTEND_PATH = os.path.join(os.path.dirname(__file__), "eml-analyzer.html")


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _safe_decode(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _decode_header_value(raw: str) -> str:
    """Decode RFC 2047 encoded header value (e.g. =?UTF-8?B?...?=)."""
    parts = email.header.decode_header(raw)
    result = ""
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            result += chunk.decode(charset or "utf-8", errors="replace")
        else:
            result += str(chunk)
    return result.strip()


# ═══════════════════════════════════════════════════════════════════════════════
# Authentication parser
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_auth_results(raw: str) -> list[dict]:
    """
    Parse Authentication-Results header.
    Returns checks WITH the full relevant clause for each protocol
    so the UI can show the complete text, not a truncated version.
    """
    checks = []
    normalized = " ".join(raw.split())

    for proto in ("spf", "dkim", "dmarc", "arc"):
        pattern = rf"(?<![a-z]){proto}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)"
        m = re.search(pattern, normalized, re.IGNORECASE)
        if m:
            # Extract the full clause for this protocol (everything from the
            # keyword until the next protocol or end of string)
            clause_pattern = rf"(?<![a-z]){proto}\b.+?(?=(?:spf|dkim|dmarc|arc)\s*=|$)"
            cm = re.search(clause_pattern, normalized, re.IGNORECASE | re.DOTALL)
            clause = cm.group(0).strip() if cm else m.group(0)
            checks.append({
                "name":   proto.upper(),
                "result": m.group(1).lower(),
                "clause": clause,           # full clause for display
            })
    return checks


# ═══════════════════════════════════════════════════════════════════════════════
# Received chain parser  (oldest-first / hop 1 = origin)
# ═══════════════════════════════════════════════════════════════════════════════

_FROM_RE = re.compile(
    r"from\s+(\S+)"                     # from hostname
    r"(?:\s+\(([^)]+)\))?",            # optional (FQDN [IP])
    re.IGNORECASE,
)
_BY_RE   = re.compile(r"by\s+(\S+)", re.IGNORECASE)
_WITH_RE = re.compile(r"with\s+(\S+)", re.IGNORECASE)
_FOR_RE  = re.compile(r"for\s+(\S+)",  re.IGNORECASE)
_IP_RE   = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")


def _parse_one_received(raw: str) -> dict:
    """Break a single Received header into structured fields."""
    raw = raw.strip()
    # Split at the semicolon — everything after is the timestamp
    if ";" in raw:
        body, ts_str = raw.rsplit(";", 1)
        ts_str = ts_str.strip()
    else:
        body, ts_str = raw, ""

    ts    = None
    ts_iso = None
    if ts_str:
        try:
            ts     = parsedate_to_datetime(ts_str)
            ts_iso = ts.isoformat()
        except Exception:
            pass

    # from / by / with / for
    fm   = _FROM_RE.search(body)
    bym  = _BY_RE.search(body)
    wm   = _WITH_RE.search(body)
    form = _FOR_RE.search(body)

    sender   = fm.group(1)  if fm   else None
    receiver = bym.group(1) if bym  else None
    protocol = wm.group(1)  if wm   else None
    rcpt     = form.group(1) if form else None

    # IPs in parens e.g. (mail.example.com [1.2.3.4])
    ips = _IP_RE.findall(body)

    return {
        "raw":          raw,
        "sender":       sender,
        "receiver":     receiver,
        "protocol":     protocol,
        "for":          rcpt,
        "ips":          ips,
        "timestamp_iso": ts_iso,
        "_dt":          ts,
    }


def _parse_received_hops(received_list: list[str]) -> list[dict]:
    """
    Parse all Received headers.
    Email headers are stored newest-first; we reverse so hop 1 = origin server.
    Delay = time between consecutive hops (positive = normal, negative = clock skew).
    """
    # Parse each hop
    parsed = [_parse_one_received(r) for r in received_list]

    # Reverse to oldest-first for delay calculation
    oldest_first = list(reversed(parsed))

    for i in range(1, len(oldest_first)):
        prev_dt = oldest_first[i - 1]["_dt"]
        curr_dt = oldest_first[i]["_dt"]
        if prev_dt and curr_dt:
            oldest_first[i]["delay_seconds"] = int(
                (curr_dt - prev_dt).total_seconds()
            )

    # Strip internal _dt
    for h in oldest_first:
        h.pop("_dt", None)

    # Return oldest-first (hop 1 = origin) — UI will label them 1, 2, 3 …
    return oldest_first


# ═══════════════════════════════════════════════════════════════════════════════
# Attachment parser (with SHA-256 hash)
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_attachments(msg: email.message.Message) -> list[dict]:
    attachments = []
    for part in msg.walk():
        disposition = part.get_content_disposition()
        if disposition and disposition.lower() == "attachment":
            filename = part.get_filename() or ""
            filename = _decode_header_value(filename)

            payload = part.get_payload(decode=True)
            size    = len(payload) if payload else 0
            sha256  = hashlib.sha256(payload).hexdigest() if payload else None

            attachments.append({
                "filename":     filename or "(unnamed)",
                "content_type": part.get_content_type(),
                "size_bytes":   size,
                "sha256":       sha256,
            })
    return attachments


# ═══════════════════════════════════════════════════════════════════════════════
# IOC extraction  (IPs + domains from headers)
# ═══════════════════════════════════════════════════════════════════════════════

_IPV4_RE     = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_DOMAIN_RE   = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b",
    re.IGNORECASE,
)
# Skip very common / boring domains to reduce noise
_SKIP_DOMAINS = {
    "localhost", "example.com", "example.org", "test.com",
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "microsoft.com", "google.com", "amazon.com",
}


def _extract_iocs(all_headers: list[dict], attachments: list[dict]) -> dict:
    """
    Walk every header value and collect unique IPs and domains.
    Also collect attachment hashes.
    """
    ips: set[str]     = set()
    domains: set[str] = set()

    for hdr in all_headers:
        for val in hdr["values"]:
            ips.update(_IPV4_RE.findall(val))
            for d in _DOMAIN_RE.findall(val):
                dl = d.lower()
                if dl not in _SKIP_DOMAINS and len(dl) > 4:
                    domains.add(dl)

    # Remove IPs that look like localhost / private ranges
    def _is_interesting_ip(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            o = [int(p) for p in parts]
        except ValueError:
            return False
        if o[0] == 127:                       return False  # loopback
        if o[0] == 10:                        return False  # RFC1918
        if o[0] == 172 and 16 <= o[1] <= 31: return False  # RFC1918
        if o[0] == 192 and o[1] == 168:      return False  # RFC1918
        return True

    hashes = [
        {"filename": a["filename"], "sha256": a["sha256"]}
        for a in attachments if a.get("sha256")
    ]

    return {
        "ips":     sorted(filter(_is_interesting_ip, ips)),
        "domains": sorted(domains),
        "hashes":  hashes,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# MIME structure walker
# ═══════════════════════════════════════════════════════════════════════════════

def _mime_structure(msg: email.message.Message, depth: int = 0) -> dict:
    """Recursively describe the MIME tree."""
    node: dict[str, Any] = {
        "content_type":        msg.get_content_type(),
        "content_disposition": msg.get_content_disposition() or "",
        "content_transfer_encoding": _safe_decode(
            msg.get("Content-Transfer-Encoding", "")
        ),
        "filename": _decode_header_value(msg.get_filename() or ""),
        "depth":    depth,
        "children": [],
    }
    if msg.is_multipart():
        for part in msg.get_payload():
            if isinstance(part, email.message.Message):
                node["children"].append(_mime_structure(part, depth + 1))
    return node


# ═══════════════════════════════════════════════════════════════════════════════
# HTML body extraction
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_bodies(msg: email.message.Message) -> dict:
    """
    Extract plain-text and HTML bodies.
    Returns {"plain": str|None, "html": str|None, "html_b64": str|None}
    html_b64 is base64-encoded so it can be safely embedded in JSON
    and loaded into a sandboxed iframe by the frontend.
    """
    plain = None
    html  = None

    for part in msg.walk():
        ct  = part.get_content_type()
        dis = part.get_content_disposition() or ""
        if dis.lower() == "attachment":
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        text = payload.decode(charset, errors="replace")

        if ct == "text/plain"  and plain is None:
            plain = text
        elif ct == "text/html" and html  is None:
            html = text

    return {
        "plain":    plain,
        "html":     html,
        "html_b64": base64.b64encode(html.encode()).decode() if html else None,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# X-header catalogue
# ═══════════════════════════════════════════════════════════════════════════════

# Known vendor prefixes → friendly label
_X_VENDORS = {
    "x-ms-":          "Microsoft",
    "x-microsoft-":   "Microsoft",
    "x-exchange-":    "Microsoft Exchange",
    "x-google-":      "Google",
    "x-gm-":          "Gmail",
    "x-ovh-":         "OVH",
    "x-ovhspam-":     "OVH Spam",
    "x-tm-":          "Trend Micro",
    "x-tmas-":        "Trend Micro Anti-Spam",
    "x-spam-":        "Spam Filter",
    "x-forefront-":   "Microsoft Forefront",
    "x-mailer":       "Mailer",
    "x-originating-": "Originating",
    "x-source":       "Source",
    "x-sender":       "Sender",
    "x-received":     "Received (extended)",
    "x-forwarded-":   "Forwarded",
    "x-mailgun-":     "Mailgun",
    "x-sendgrid-":    "SendGrid",
    "x-ses-":         "AWS SES",
    "x-amazon-":      "Amazon",
    "x-proofpoint-":  "Proofpoint",
    "x-barracuda-":   "Barracuda",
    "x-mimeole":      "MIME OLE",
    "x-priority":     "Priority",
}


def _vendor_for(name: str) -> str:
    """Return a vendor label for an X- header name, or 'Custom'."""
    nl = name.lower()
    for prefix, label in _X_VENDORS.items():
        if nl.startswith(prefix) or nl == prefix.rstrip("-"):
            return label
    return "Custom"


def _build_x_headers(all_headers: list[dict]) -> list[dict]:
    """Return X- headers enriched with vendor guesses."""
    result = []
    for hdr in all_headers:
        if not hdr["name"].lower().startswith("x-"):
            continue
        result.append({
            "name":   hdr["name"],
            "values": hdr["values"],
            "vendor": _vendor_for(hdr["name"]),
        })
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Core parser
# ═══════════════════════════════════════════════════════════════════════════════

def _parse_eml(raw: str | bytes) -> dict:
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8", errors="replace")
    else:
        raw_bytes = raw

    policy = email.policy.compat32
    msg    = email.message_from_bytes(raw_bytes, policy=policy)

    def h(name: str) -> str:
        return _safe_decode(msg.get(name, ""))

    def h_all(name: str) -> list[str]:
        return [_safe_decode(v) for v in (msg.get_all(name) or [])]

    # ── Core fields ───────────────────────────────────────────────────────────
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

    # ── Authentication ────────────────────────────────────────────────────────
    auth_raw_list = h_all("Authentication-Results")   # may appear multiple times
    auth_raw      = "\n".join(auth_raw_list)
    auth_checks   = _parse_auth_results(auth_raw) if auth_raw else []
    spf_result    = h("Received-SPF")
    dkim_header   = h("DKIM-Signature")

    # ── Received chain (oldest-first) ─────────────────────────────────────────
    received_list = h_all("Received")
    hops          = _parse_received_hops(received_list)

    # ── Attachments ───────────────────────────────────────────────────────────
    attachments = _parse_attachments(msg)

    # ── MIME structure ────────────────────────────────────────────────────────
    mime_tree = _mime_structure(msg)

    # ── Bodies ────────────────────────────────────────────────────────────────
    bodies = _extract_bodies(msg)

    # ── All headers (original order) ──────────────────────────────────────────
    seen: dict[str, list[str]] = {}
    all_headers: list[dict]    = []
    for k, v in msg.items():
        kl    = k.lower()
        entry = _safe_decode(v)
        if kl not in seen:
            seen[kl] = []
            all_headers.append({"name": k, "values": seen[kl]})
        seen[kl].append(entry)

    # ── X-headers with vendor labels ──────────────────────────────────────────
    x_headers = _build_x_headers(all_headers)

    # ── IOC extraction ────────────────────────────────────────────────────────
    iocs = _extract_iocs(all_headers, attachments)

    # ── Mismatch checks ───────────────────────────────────────────────────────
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
            "raw":                     auth_raw,
            "checks":                  auth_checks,
            "received_spf":            spf_result,
            "dkim_signature_present":  bool(dkim_header),
            "dkim_header":             dkim_header,
        },
        "received_chain": hops,          # oldest-first; hop[0] = origin
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
            "has_html_body":    bodies["html"] is not None,
            "has_plain_body":   bodies["plain"] is not None,
            "ioc_ip_count":     len(iocs["ips"]),
            "ioc_domain_count": len(iocs["domains"]),
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    try:
        with open(_FRONTEND_PATH, "r", encoding="utf-8") as f:
            html = f.read()
        html = _patch_frontend(html)
        return Response(html, mimetype="text/html")
    except FileNotFoundError:
        return (
            "<h2>eml-analyzer.html not found</h2>"
            "<p>Place <code>eml-analyzer.html</code> next to <code>main.py</code>.</p>",
            404,
        )


@app.route("/analyze/file", methods=["POST"])
def analyze_file():
    if "file" not in request.files:
        return jsonify({"error": "No file field in request"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400
    try:
        result = _parse_eml(f.read())
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/analyze/text", methods=["POST"])
def analyze_text():
    body = request.get_json(silent=True)
    if not body or "raw" not in body:
        return jsonify({"error": "Missing 'raw' field in JSON body"}), 400
    if len(body["raw"]) > 20 * 1024 * 1024:
        return jsonify({"error": "Input too large (max 20 MB)"}), 413
    try:
        result = _parse_eml(body["raw"])
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ═══════════════════════════════════════════════════════════════════════════════
# Frontend patch script
# ═══════════════════════════════════════════════════════════════════════════════

_PATCH_SCRIPT = r"""
<script>
// ═══════════════════════════════════════════════════════════════════════════════
// Backend bridge + full renderer  (injected by main.py)
// ═══════════════════════════════════════════════════════════════════════════════

// ── API calls ─────────────────────────────────────────────────────────────────
async function callBackend(endpoint, payload) {
  let resp;
  if (endpoint === 'file') {
    const fd = new FormData();
    fd.append('file', payload);
    resp = await fetch('/analyze/file', { method: 'POST', body: fd });
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

// ── Entry points (override the HTML's built-in JS versions) ──────────────────
function analyzeFile() {
  const fi   = document.getElementById('fileInput');
  const file = fi.files[0];
  if (!file && !loadedFileContent) { alert('Please select an .eml file first.'); return; }
  if (!file && loadedFileContent) {
    callBackend('text', loadedFileContent).then(renderFromBackend).catch(e => showError(e.message));
    return;
  }
  callBackend('file', file).then(renderFromBackend).catch(e => showError(e.message));
}

function analyzeText() {
  const raw = document.getElementById('rawInput').value.trim();
  if (!raw) { alert('Please paste some header or EML content first.'); return; }
  callBackend('text', raw).then(renderFromBackend).catch(e => showError(e.message));
}

function showError(msg) {
  const eb = document.getElementById('error-box');
  eb.textContent = '❌ ' + msg;
  eb.style.display = 'block';
  document.getElementById('results').classList.add('visible');
}

// ── CSS injected once ─────────────────────────────────────────────────────────
(function injectStyles() {
  const s = document.createElement('style');
  s.textContent = `
    /* Hop table */
    .hop-table { width:100%; border-collapse:collapse; font-size:11px; }
    .hop-table th { padding:7px 12px; background:var(--bg); color:var(--text-dim);
                    font-size:10px; letter-spacing:.08em; text-transform:uppercase;
                    text-align:left; border-bottom:1px solid var(--border); }
    .hop-table td { padding:9px 12px; vertical-align:top; border-bottom:1px solid var(--border);
                    color:var(--text-bright); word-break:break-all; }
    .hop-table tr:last-child td { border-bottom:none; }
    .hop-table tr:hover td { background:rgba(255,255,255,.015); }
    .hop-table td.dim { color:var(--text-dim); }
    .hop-table td.idx { color:var(--accent); font-size:10px; width:30px; text-align:center; }
    .hop-delay-badge { display:inline-block; padding:1px 7px; font-size:10px;
                       background:rgba(255,170,0,.1); color:var(--warn); }
    .hop-delay-fast  { background:rgba(0,212,170,.08); color:var(--accent); }
    /* Auth full text */
    .auth-full { font-size:11px; color:var(--text-dim); padding:6px 12px 10px;
                 word-break:break-all; line-height:1.7; white-space:pre-wrap; }
    /* IOC section */
    .ioc-grid { display:grid; grid-template-columns:1fr 1fr; gap:1px; background:var(--border); }
    .ioc-col  { background:var(--surface); padding:0; }
    .ioc-head { padding:8px 14px; font-size:10px; letter-spacing:.1em; text-transform:uppercase;
                color:var(--text-dim); border-bottom:1px solid var(--border); }
    .ioc-item { padding:7px 14px; font-size:11px; color:var(--accent2); word-break:break-all;
                border-bottom:1px solid var(--border); }
    .ioc-item:last-child { border-bottom:none; }
    .ioc-hash { font-size:10px; color:var(--text-dim); padding:7px 14px;
                border-bottom:1px solid var(--border); word-break:break-all; }
    .ioc-hash:last-child { border-bottom:none; }
    .ioc-hash .fn { color:var(--text-bright); margin-bottom:2px; }
    .ioc-hash .hv { color:var(--accent); font-family:monospace; }
    /* MIME tree */
    .mime-node { border-left:2px solid var(--border2); margin-left:14px; padding:6px 10px;
                 font-size:11px; position:relative; }
    .mime-node:first-child { margin-left:0; border-left:none; }
    .mime-type { color:var(--accent2); }
    .mime-dis  { color:var(--text-dim); font-size:10px; margin-left:8px; }
    .mime-fn   { color:var(--warn); font-size:10px; margin-left:8px; }
    .mime-enc  { color:var(--text-dim); font-size:10px; margin-left:8px; }
    /* HTML body viewer */
    .html-toolbar { display:flex; gap:8px; padding:10px 14px; border-bottom:1px solid var(--border);
                    background:var(--surface); align-items:center; flex-wrap:wrap; }
    .html-toolbar button { font-family:var(--mono); font-size:10px; letter-spacing:.06em;
                           text-transform:uppercase; padding:5px 14px; border:1px solid var(--border2);
                           background:transparent; color:var(--text-dim); cursor:pointer; }
    .html-toolbar button.active { border-color:var(--accent); color:var(--accent); }
    .html-toolbar button:hover  { border-color:var(--text); color:var(--text); }
    .html-frame { width:100%; height:500px; border:none; background:#fff; display:block; }
    .html-source { background:var(--bg); padding:14px; font-size:11px; color:var(--text);
                   white-space:pre-wrap; word-break:break-all; max-height:500px; overflow-y:auto; }
    /* X-header vendor badge */
    .vendor-badge { display:inline-block; padding:1px 8px; font-size:9px; letter-spacing:.06em;
                    text-transform:uppercase; background:rgba(0,153,255,.1); color:var(--accent2);
                    margin-left:8px; vertical-align:middle; }
  `;
  document.head.appendChild(s);
})();

// ═══════════════════════════════════════════════════════════════════════════════
// Main renderer
// ═══════════════════════════════════════════════════════════════════════════════
function renderFromBackend(d) {
  document.getElementById('error-box').style.display = 'none';

  const core     = d.core            || {};
  const auth     = d.authentication  || {};
  const hops     = d.received_chain  || [];   // oldest-first
  const attaches = d.attachments     || [];
  const summary  = d.summary         || {};
  const allHdrs  = d.all_headers     || [];
  const xHdrs    = d.x_headers       || [];
  const iocs     = d.iocs            || {};
  const mime     = d.mime_structure  || null;
  const bodies   = d.bodies          || {};

  // Status badge
  document.getElementById('parse-status').className = 'badge badge-ok';
  document.getElementById('parse-status').textContent = '● Parsed OK';

  // ── Summary strip ──────────────────────────────────────────────────────────
  const fromAddr = core.from ? core.from.address : '—';
  document.getElementById('summary-strip').innerHTML = [
    { label: 'From',        value: fromAddr || '—',               cls: '' },
    { label: 'Subject',     value: core.subject || '—',           cls: '' },
    { label: 'Date',        value: core.date ? (core.date.raw||'—') : '—', cls: '' },
    { label: 'Hops',        value: summary.hop_count ?? '—',      cls: summary.hop_count > 5 ? 'warn' : 'accent' },
    { label: 'IPs / Domains', value: `${(iocs.ips||[]).length} / ${(iocs.domains||[]).length}`, cls: '' },
    { label: 'Attachments', value: summary.attachment_count ?? 0, cls: summary.attachment_count ? 'warn' : '' },
  ].map(c => `<div class="summary-card"><div class="label">${c.label}</div><div class="value ${c.cls}">${escHtml(String(c.value))}</div></div>`).join('');

  const sections = [];

  // ── 0. MIME Structure ─────────────────────────────────────────────────────
  if (mime) {
    sections.push({
      title: 'MIME Structure', count: '',
      html: `<div style="padding:12px 16px">${renderMimeNode(mime)}</div>`
    });
  }

  // ── 1. Core Headers ───────────────────────────────────────────────────────
  const replyRaw = core.reply_to ? core.reply_to.raw : '';
  const mismatch = core.reply_to && core.reply_to.mismatch;
  const toStr    = (core.to  ||[]).map(t => t.name ? `${t.name} <${t.address}>` : t.address).join(', ');
  const ccStr    = (core.cc  ||[]).map(t => t.name ? `${t.name} <${t.address}>` : t.address).join(', ');
  const bccStr   = (core.bcc ||[]).map(t => t.name ? `${t.name} <${t.address}>` : t.address).join(', ');

  const coreRows = [
    ['From',             core.from ? core.from.raw : ''],
    ['To',               toStr],
    ['CC',               ccStr],
    ['BCC',              bccStr],
    ['Reply-To',         replyRaw + (mismatch ? '  ⚠ domain mismatch' : '')],
    ['Subject',          core.subject],
    ['Date',             core.date ? core.date.raw : ''],
    ['Message-ID',       core.message_id],
    ['MIME-Version',     core.mime_version],
    ['Content-Type',     core.content_type],
    ['X-Mailer',         core.x_mailer],
    ['X-Originating-IP', core.x_originating_ip],
  ].filter(([,v]) => v);

  sections.push({
    title: 'Core Headers', count: coreRows.length,
    html: `<table class="kv-table">${coreRows.map(([k,v]) =>
      `<tr><td>${escHtml(k)}</td><td style="${k==='Reply-To'&&mismatch?'color:var(--warn)':''}">${escHtml(v)}</td></tr>`
    ).join('')}</table>`
  });

  // ── 2. Authentication ─────────────────────────────────────────────────────
  if (auth.raw) {
    const checks = auth.checks || [];
    let authHtml = '';

    if (checks.length) {
      authHtml += checks.map(c => {
        const pass = ['pass','bestguesspass'].includes(c.result);
        const fail = ['fail','hardfail','softfail','none','permerror','temperror'].includes(c.result);
        const pillCls = pass ? 'pill-pass' : fail ? 'pill-fail' : 'pill-none';
        return `<div class="auth-row">
          <span class="auth-name">${c.name}</span>
          <span class="pill ${pillCls}">${escHtml(c.result)}</span>
          <span class="auth-detail">${escHtml(c.clause || '')}</span>
        </div>`;
      }).join('');
    }

    // Always show the full raw Authentication-Results text underneath
    authHtml += `<div class="auth-full">${escHtml(auth.raw)}</div>`;

    if (auth.received_spf) {
      authHtml += `<div class="auth-row"><span class="auth-name">SPF HDR</span>
        <span class="auth-detail">${escHtml(auth.received_spf)}</span></div>`;
    }
    if (auth.dkim_signature_present) {
      authHtml += `<div class="auth-row"><span class="auth-name">DKIM SIG</span>
        <span class="auth-detail">${escHtml(auth.dkim_header || 'present')}</span></div>`;
    }

    sections.push({ title: 'Authentication', count: checks.length || 1, html: authHtml });
  }

  // ── 3. Received Chain (oldest = hop 1 at top) ─────────────────────────────
  if (hops.length) {
    let hopHtml = `<table class="hop-table">
      <thead><tr>
        <th>#</th><th>From (Sender)</th><th>By (Receiver)</th>
        <th>Protocol</th><th>Timestamp</th><th>Delay</th>
      </tr></thead><tbody>`;

    hops.forEach((hop, idx) => {
      const num   = idx + 1;
      const delay = hop.delay_seconds;
      let delayCls = 'hop-delay-badge';
      let delayTxt = '—';
      if (delay != null) {
        delayTxt = delay >= 0 ? `+${delay}s` : `${delay}s`;
        if (Math.abs(delay) < 5) delayCls += ' hop-delay-fast';
      }
      hopHtml += `<tr>
        <td class="idx">${num}</td>
        <td>${escHtml(hop.sender||'—')}${hop.ips&&hop.ips.length?`<br><span style="color:var(--accent2);font-size:10px;">[${hop.ips.join(', ')}]</span>`:''}</td>
        <td>${escHtml(hop.receiver||'—')}</td>
        <td class="dim">${escHtml(hop.protocol||'—')}</td>
        <td class="dim" style="white-space:nowrap;font-size:10px;">${escHtml(hop.timestamp_iso||'—')}</td>
        <td><span class="${delayCls}">${delayTxt}</span></td>
      </tr>
      <tr><td colspan="6" style="padding:0 12px 10px;color:var(--text-dim);font-size:10px;">${escHtml(hop.raw)}</td></tr>`;
    });

    hopHtml += '</tbody></table>';
    sections.push({ title: 'Received Chain', count: hops.length, html: hopHtml });
  }

  // ── 4. IOC — IPs, Domains, Hashes ────────────────────────────────────────
  const ips     = iocs.ips     || [];
  const domains = iocs.domains || [];
  const hashes  = iocs.hashes  || [];

  if (ips.length || domains.length || hashes.length) {
    let iocHtml = `<div class="ioc-grid">
      <div class="ioc-col">
        <div class="ioc-head">IP Addresses (${ips.length})</div>
        ${ips.length ? ips.map(ip => `<div class="ioc-item">${escHtml(ip)}</div>`).join('') : '<div class="ioc-hash" style="color:var(--text-dim);">None found</div>'}
      </div>
      <div class="ioc-col">
        <div class="ioc-head">Domains (${domains.length})</div>
        ${domains.length ? domains.map(d => `<div class="ioc-item">${escHtml(d)}</div>`).join('') : '<div class="ioc-hash" style="color:var(--text-dim);">None found</div>'}
      </div>
    </div>`;

    if (hashes.length) {
      iocHtml += `<div style="border-top:1px solid var(--border)">
        <div class="ioc-head" style="padding:8px 14px;">Attachment Hashes (SHA-256)</div>
        ${hashes.map(h => `<div class="ioc-hash"><div class="fn">${escHtml(h.filename)}</div><div class="hv">${escHtml(h.sha256)}</div></div>`).join('')}
      </div>`;
    }

    sections.push({ title: 'IOC — IPs / Domains / Hashes', count: ips.length + domains.length + hashes.length, html: iocHtml });
  }

  // ── 5. X-Headers ─────────────────────────────────────────────────────────
  if (xHdrs.length) {
    // Group by vendor
    const byVendor = {};
    xHdrs.forEach(x => {
      const v = x.vendor || 'Custom';
      if (!byVendor[v]) byVendor[v] = [];
      byVendor[v].push(x);
    });

    let xHtml = '';
    Object.entries(byVendor).forEach(([vendor, hdrs]) => {
      xHtml += `<div style="border-bottom:1px solid var(--border);padding:8px 16px 4px;">
        <div style="font-size:10px;color:var(--accent2);letter-spacing:.08em;text-transform:uppercase;margin-bottom:6px;">${escHtml(vendor)}</div>`;
      xHtml += `<table class="kv-table" style="margin-bottom:4px;">`;
      hdrs.forEach(x => {
        x.values.forEach(v => {
          xHtml += `<tr><td>${escHtml(x.name)}</td><td>${escHtml(v)}</td></tr>`;
        });
      });
      xHtml += `</table></div>`;
    });

    sections.push({ title: 'X-Headers', count: xHdrs.length, html: xHtml });
  }

  // ── 6. Attachments ────────────────────────────────────────────────────────
  if (attaches.length) {
    sections.push({
      title: 'Attachments', count: attaches.length,
      html: attaches.map(a => `
        <div class="attach-row">
          <span class="attach-icon">📎</span>
          <span class="attach-name">${escHtml(a.filename)}</span>
          <span class="attach-type">${escHtml(a.content_type)}</span>
          <span class="attach-size" style="margin-left:auto">${formatBytes(a.size_bytes)}</span>
        </div>
        ${a.sha256 ? `<div style="padding:0 16px 10px;font-size:10px;color:var(--text-dim);">SHA-256: <span style="color:var(--accent)">${escHtml(a.sha256)}</span></div>` : ''}
      `).join('')
    });
  }

  // ── 7. HTML Body Viewer ───────────────────────────────────────────────────
  if (bodies.html_b64) {
    const sectionId = 'html-body-viewer';
    const html = `
      <div class="html-toolbar" id="${sectionId}-toolbar">
        <span style="font-size:10px;color:var(--text-dim);letter-spacing:.06em;text-transform:uppercase;margin-right:4px;">View:</span>
        <button class="active" onclick="htmlViewMode('${sectionId}','render-remote')">Render (with remote)</button>
        <button onclick="htmlViewMode('${sectionId}','render-safe')">Render (block remote)</button>
        <button onclick="htmlViewMode('${sectionId}','source')">HTML Source</button>
      </div>
      <div id="${sectionId}-content">
        <iframe id="${sectionId}-frame" class="html-frame"
          sandbox="allow-same-origin allow-popups"
          srcdoc="${escAttr(atob_safe(bodies.html_b64))}"></iframe>
      </div>`;
    sections.push({ title: 'HTML Body', count: '', html });
  } else if (bodies.plain) {
    sections.push({
      title: 'Plain Body', count: '',
      html: `<div class="raw-block" style="max-height:400px;">${escHtml(bodies.plain)}</div>`
    });
  }

  // ── 8. All Headers (raw) ─────────────────────────────────────────────────
  const rawHtml = allHdrs.map(h =>
    h.values.map(v =>
      `<span class="h-name">${escHtml(h.name)}</span>: <span class="h-val">${escHtml(v)}</span>`
    ).join('\n')
  ).join('\n');

  sections.push({
    title: 'All Headers (Raw)', count: allHdrs.reduce((s,h) => s + h.values.length, 0),
    html: `<div class="raw-block">${rawHtml}</div>`
  });

  // ── Render sections ───────────────────────────────────────────────────────
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
  document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── MIME tree renderer ────────────────────────────────────────────────────────
function renderMimeNode(node) {
  const fn  = node.filename ? `<span class="mime-fn">📎 ${escHtml(node.filename)}</span>` : '';
  const dis = node.content_disposition ? `<span class="mime-dis">[${escHtml(node.content_disposition)}]</span>` : '';
  const enc = node.content_transfer_encoding ? `<span class="mime-enc">${escHtml(node.content_transfer_encoding)}</span>` : '';
  let html = `<div class="mime-node">
    <span class="mime-type">${escHtml(node.content_type)}</span>${dis}${fn}${enc}`;
  if (node.children && node.children.length) {
    html += node.children.map(renderMimeNode).join('');
  }
  html += '</div>';
  return html;
}

// ── HTML body viewer controls ─────────────────────────────────────────────────
function htmlViewMode(id, mode) {
  const toolbar = document.getElementById(id + '-toolbar');
  toolbar.querySelectorAll('button').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');

  const content  = document.getElementById(id + '-content');
  const b64      = content.querySelector('iframe') ?
    content.querySelector('iframe').getAttribute('data-b64') ||
    content.querySelector('iframe').getAttribute('srcdoc') : null;

  if (mode === 'source') {
    const frame = content.querySelector('iframe');
    const src   = frame ? frame.getAttribute('data-raw') || atob_safe(frame.getAttribute('data-b64') || '') || frame.srcdoc : '';
    content.innerHTML = `<div class="html-source">${escHtml(src)}</div>`;
  } else if (mode === 'render-safe') {
    const frame = content.querySelector('iframe');
    const src   = frame ? (frame.getAttribute('data-raw') || frame.srcdoc) : '';
    content.innerHTML = `<iframe class="html-frame"
      sandbox="allow-same-origin"
      srcdoc="${escAttr(src)}"></iframe>`;
    content.querySelector('iframe').setAttribute('data-raw', src);
  } else {
    const frame = content.querySelector('iframe');
    const src   = frame ? (frame.getAttribute('data-raw') || frame.srcdoc) : '';
    content.innerHTML = `<iframe class="html-frame"
      sandbox="allow-same-origin allow-scripts allow-popups"
      srcdoc="${escAttr(src)}"></iframe>`;
    content.querySelector('iframe').setAttribute('data-raw', src);
  }
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function atob_safe(b64) {
  try { return atob(b64); } catch { return b64; }
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
    return html.replace("</body>", _PATCH_SCRIPT + "\n</body>")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port",      default=5000,        type=int, help="Port (default 5000)")
    parser.add_argument("-d", "--debug",     action="store_true",            help="Debug mode")
    parser.add_argument("-i", "--interface", default="127.0.0.1", type=str, help="Bind interface")
    args = parser.parse_args()

    print("=" * 55)
    print("  EML Analyzer")
    print(f"  http://{args.interface}:{args.port}/")
    print("=" * 55)
    app.run(debug=args.debug, host=args.interface, port=args.port)