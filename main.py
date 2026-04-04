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
    python app.py
    open http://localhost:5000
"""
import argparse
import email
import email.policy
import email.header
import re
from email.utils import parseaddr, parsedate_to_datetime, getaddresses
import sys
from typing import Any

from flask import Flask, jsonify, request, Response

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB upload limit

# ── Load the frontend HTML once at startup ────────────────────────────────────
import os
_FRONTEND_PATH = os.path.join(os.path.dirname(__file__), "eml-analyzer.html")


# ═══════════════════════════════════════════════════════════════════════════════
# EML parsing
# ═══════════════════════════════════════════════════════════════════════════════

def _safe_decode(value: Any) -> str:
    """Coerce any header value to a plain string."""
    if value is None:
        return ""
    return str(value)


def _parse_auth_results(raw: str) -> list[dict]:
    checks = []

    # normalize whitespace (important for folded headers)
    raw = " ".join(raw.split())

    for proto in ("spf", "dkim", "dmarc", "arc"):
        pattern = rf"(?<![a-z]){proto}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)"
        m = re.search(pattern, raw, re.IGNORECASE)

        if m:
            checks.append({
                "name": proto.upper(),
                "result": m.group(1).lower()
            })

    return checks


def _parse_received_hops(received_list: list[str]) -> list[dict]:
    """
    Parse each Received header into {raw, timestamp_iso, delay_seconds}.
    Hops are returned newest-first (same order as the headers).
    Delay is the gap between consecutive hops, oldest-to-newest.
    """
    hops = []
    for raw in received_list:
        m = re.search(r";\s*(.+)$", raw.strip())
        ts = None
        ts_iso = None
        if m:
            try:
                ts = parsedate_to_datetime(m.group(1).strip())
                ts_iso = ts.isoformat()
            except Exception:
                pass
        hops.append({"raw": raw.strip(), "timestamp_iso": ts_iso, "_dt": ts})

    # Compute delays (work oldest→newest)
    ordered = list(reversed(hops))
    for i in range(1, len(ordered)):
        prev_dt = ordered[i - 1]["_dt"]
        curr_dt = ordered[i]["_dt"]
        if prev_dt and curr_dt:
            ordered[i]["delay_seconds"] = int((curr_dt - prev_dt).total_seconds())

    # Strip internal _dt before returning, restore newest-first
    for h in hops:
        h.pop("_dt", None)

    return hops


def _parse_attachments(msg: email.message.Message) -> list[dict]:
    """Walk MIME parts and collect attachment metadata."""
    attachments = []
    for part in msg.walk():
        disposition = part.get_content_disposition()
        if disposition and disposition.lower() == "attachment":
            filename = part.get_filename() or ""
            # Decode RFC 2047 encoded filenames
            decoded_parts = email.header.decode_header(filename)
            decoded_filename = ""
            for chunk, charset in decoded_parts:
                if isinstance(chunk, bytes):
                    decoded_filename += chunk.decode(charset or "utf-8", errors="replace")
                else:
                    decoded_filename += chunk
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0
            attachments.append({
                "filename":     decoded_filename or "(unnamed)",
                "content_type": part.get_content_type(),
                "size_bytes":   size,
            })
    return attachments


def _parse_eml(raw: str | bytes) -> dict:
    """
    Core parser. Accepts raw EML bytes or string.
    Returns a structured dict ready to be JSON-serialised.
    """
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8", errors="replace")
    else:
        raw_bytes = raw

    # Use the modern email policy for proper decoding
    policy = email.policy.compat32
    msg = email.message_from_bytes(raw_bytes, policy=policy)

    # ── Helpers ───────────────────────────────────────────────────────────────
    def h(name: str) -> str:
        return _safe_decode(msg.get(name, ""))

    def h_all(name: str) -> list[str]:
        return [_safe_decode(v) for v in (msg.get_all(name) or [])]

    # ── Core fields ───────────────────────────────────────────────────────────
    from_raw   = h("From")
    to_raw     = h("To")
    cc_raw     = h("CC")
    reply_raw  = h("Reply-To")

    from_name_raw, from_addr = parseaddr(from_raw)
    _, reply_addr             = parseaddr(reply_raw)

    # Decode RFC 2047 encoded display names (e.g. =?UTF-8?B?...?=)
    def _decode_name(raw_name: str) -> str:
        parts = email.header.decode_header(raw_name)
        result = ""
        for chunk, charset in parts:
            if isinstance(chunk, bytes):
                result += chunk.decode(charset or "utf-8", errors="replace")
            else:
                result += chunk
        return result.strip()

    from_name = _decode_name(from_name_raw)

    to_list  = [{"name": n, "address": a} for n, a in getaddresses([to_raw])  if a]
    cc_list  = [{"name": n, "address": a} for n, a in getaddresses([cc_raw])  if a]

    # Parse date
    date_raw = h("Date")
    date_iso = None
    try:
        date_iso = parsedate_to_datetime(date_raw).isoformat() if date_raw else None
    except Exception:
        pass

    # ── Authentication ────────────────────────────────────────────────────────
    auth_raw    = h("Authentication-Results")
    auth_checks = _parse_auth_results(auth_raw) if auth_raw else []

    # Also grab individual result headers (some servers set these separately)
    spf_result  = h("Received-SPF")
    dkim_result = h("DKIM-Signature")

    # ── Received chain ────────────────────────────────────────────────────────
    received_list = h_all("Received")
    hops = _parse_received_hops(received_list)

    # ── Attachments ───────────────────────────────────────────────────────────
    attachments = _parse_attachments(msg)

    # ── Reply-To mismatch check ───────────────────────────────────────────────
    from_domain  = from_addr.split("@")[-1].lower()  if "@" in from_addr  else ""
    reply_domain = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""
    reply_mismatch = bool(reply_addr and from_addr and from_domain != reply_domain)

    # ── All headers (preserve order, group multiples) ─────────────────────────
    seen: dict[str, list[str]] = {}
    all_headers: list[dict] = []
    for k, v in msg.items():
        key_lower = k.lower()
        entry = _safe_decode(v)
        if key_lower not in seen:
            seen[key_lower] = []
            all_headers.append({"name": k, "values": seen[key_lower]})
        seen[key_lower].append(entry)

    # ── X-headers ─────────────────────────────────────────────────────────────
    # Filter inside the comprehension — h_ goes out of scope after .items()
    x_headers = {entry["name"]: entry["values"]
                 for entry in all_headers
                 if entry["name"].lower().startswith("x-")}

    originating_ip = (
        h("X-Originating-IP") or
        h("X-Sender-IP") or
        h("X-Source-IP") or
        h("X-Forwarded-For") or ""
    )

    return {
        "core": {
            "from":        {"raw": from_raw, "name": from_name, "address": from_addr},
            "to":          to_list,
            "cc":          cc_list,
            "reply_to":    {"raw": reply_raw, "address": reply_addr, "mismatch": reply_mismatch},
            "subject":     h("Subject"),
            "date":        {"raw": date_raw, "iso": date_iso},
            "message_id":  h("Message-ID"),
            "mime_version": h("MIME-Version"),
            "content_type": h("Content-Type"),
            "x_mailer":    h("X-Mailer"),
            "x_originating_ip": originating_ip,
        },
        "authentication": {
            "raw":          auth_raw,
            "checks":       auth_checks,
            "received_spf": spf_result,
            "dkim_signature_present": bool(dkim_result),
        },
        "received_chain": hops,
        "attachments":    attachments,
        "x_headers":      x_headers,
        "all_headers":    all_headers,
        "summary": {
            "total_headers":    len(list(msg.keys())),
            "hop_count":        len(hops),
            "attachment_count": len(attachments),
            "auth_count":       len(auth_checks),
            "reply_mismatch":   reply_mismatch,
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    """Serve the frontend HTML."""
    try:
        with open(_FRONTEND_PATH, "r", encoding="utf-8") as f:
            html = f.read()
        # Patch the frontend to use the Python backend instead of its built-in JS parser
        html = _patch_frontend(html)
        return Response(html, mimetype="text/html")
    except FileNotFoundError:
        return (
            "<h2>eml-analyzer.html not found</h2>"
            "<p>Place <code>eml-analyzer.html</code> in the same directory as <code>app.py</code>.</p>",
            404,
        )


@app.route("/analyze/file", methods=["POST"])
def analyze_file():
    """
    Accept a multipart file upload.
    Field name: 'file'
    """
    if "file" not in request.files:
        return jsonify({"error": "No file field in request"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    try:
        raw = f.read()
        result = _parse_eml(raw)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/analyze/text", methods=["POST"])
def analyze_text():
    """
    Accept raw EML text as JSON.
    Body: {"raw": "<eml string>"}
    """
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
# Frontend patching — rewire the JS to call the Python API
# ═══════════════════════════════════════════════════════════════════════════════

_PATCH_SCRIPT = """
<script>
// ── Backend bridge — replaces the in-browser JS parser ───────────────────────
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

function analyzeFile() {
  const fi = document.getElementById('fileInput');
  const file = fi.files[0];
  if (!file && !loadedFileContent) { alert('Please select an .eml file first.'); return; }
  if (!file && loadedFileContent) {
    // File was drag-dropped (content in memory) — send as text to /analyze/text
    callBackend('text', loadedFileContent)
      .then(data => renderFromBackend(data))
      .catch(e  => showError(e.message));
    return;
  }
  callBackend('file', file)
    .then(data => renderFromBackend(data))
    .catch(e  => showError(e.message));
}

function analyzeText() {
  const raw = document.getElementById('rawInput').value.trim();
  if (!raw) { alert('Please paste some header or EML content first.'); return; }
  callBackend('text', raw)
    .then(data => renderFromBackend(data))
    .catch(e  => showError(e.message));
}

function showError(msg) {
  const eb = document.getElementById('error-box');
  eb.textContent = '❌ ' + msg;
  eb.style.display = 'block';
  document.getElementById('results').classList.add('visible');
}

function renderFromBackend(d) {
  document.getElementById('error-box').style.display = 'none';

  const core    = d.core    || {};
  const auth    = d.authentication || {};
  const hops    = d.received_chain || [];
  const attaches = d.attachments  || [];
  const summary  = d.summary      || {};
  const allHdrs  = d.all_headers  || [];

  // Status badge
  const statusEl = document.getElementById('parse-status');
  statusEl.className = 'badge badge-ok';
  statusEl.textContent = '● Parsed OK';

  // Summary strip
  const fromAddr = core.from ? core.from.address : '—';
  document.getElementById('summary-strip').innerHTML = [
    { label: 'From',        value: fromAddr || '—',             cls: '' },
    { label: 'Subject',     value: core.subject || '—',         cls: '' },
    { label: 'Date',        value: core.date ? (core.date.raw || '—') : '—', cls: '' },
    { label: 'Hops',        value: summary.hop_count ?? '—',    cls: summary.hop_count > 5 ? 'warn' : 'accent' },
    { label: 'Auth',        value: auth.checks && auth.checks.length ? auth.checks.map(c=>c.name).join(' · ') : '—', cls: '' },
    { label: 'Attachments', value: summary.attachment_count ?? 0, cls: summary.attachment_count ? 'warn' : '' },
  ].map(d => `<div class="summary-card"><div class="label">${d.label}</div><div class="value ${d.cls}">${escHtml(String(d.value))}</div></div>`).join('');

  // Sections
  const sections = [];

  // Core headers
  const replyRaw = core.reply_to ? core.reply_to.raw : '';
  const mismatch = core.reply_to && core.reply_to.mismatch;
  const coreRows = [
    ['From',             core.from ? core.from.raw : ''],
    ['To',               (core.to||[]).map(t=>t.address).join(', ')],
    ['CC',               (core.cc||[]).map(c=>c.address).join(', ')],
    ['Reply-To',         replyRaw + (mismatch ? ' ⚠ domain mismatch' : '')],
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
    html: `<table class="kv-table">${coreRows.map(([k,v]) => `<tr><td>${escHtml(k)}</td><td>${escHtml(v)}</td></tr>`).join('')}</table>`
  });

  // Authentication
  if (auth.checks && auth.checks.length) {
    sections.push({
      title: 'Authentication', count: auth.checks.length,
      html: auth.checks.map(c => {
        const pass = ['pass','bestguesspass'].includes(c.result);
        const fail = ['fail','hardfail','softfail','none','permerror','temperror'].includes(c.result);
        return `<div class="auth-row">
          <span class="auth-name">${c.name}</span>
          <span class="pill ${pass?'pill-pass':fail?'pill-fail':'pill-none'}">${escHtml(c.result)}</span>
          <span class="auth-detail">${escHtml((auth.raw||'').substring(0,120))}${(auth.raw||'').length>120?'…':''}</span>
        </div>`;
      }).join('')
    });
  }

  // Received chain
  if (hops.length) {
    sections.push({
      title: 'Received Chain', count: hops.length,
      html: hops.map((h,idx) => `
        <div class="hop">
          <div class="hop-num">${hops.length - idx}</div>
          <div class="hop-content">
            <div class="hop-raw">${escHtml(h.raw)}</div>
            ${h.timestamp_iso ? `<div style="color:var(--text-dim);font-size:10px;">${h.timestamp_iso}</div>` : ''}
            ${h.delay_seconds != null ? `<div class="hop-delay">+${h.delay_seconds}s from previous hop</div>` : ''}
          </div>
        </div>`).join('')
    });
  }

  // Attachments
  if (attaches.length) {
    sections.push({
      title: 'Attachments', count: attaches.length,
      html: attaches.map(a => `
        <div class="attach-row">
          <span class="attach-icon">📎</span>
          <span class="attach-name">${escHtml(a.filename)}</span>
          <span class="attach-size">${escHtml(a.content_type)}</span>
          <span class="attach-size" style="margin-left:auto">${formatBytes(a.size_bytes)}</span>
        </div>`).join('')
    });
  }

  // All headers raw
  const allHtml = allHdrs.map(h =>
    h.values.map(v => `<span class="h-name">${escHtml(h.name)}</span>: <span class="h-val">${escHtml(v)}</span>`).join('\n')
  ).join('\n');
  sections.push({
    title: 'All Headers (Raw)', count: allHdrs.reduce((s,h)=>s+h.values.length,0),
    html: `<div class="raw-block">${allHtml}</div>`
  });

  document.getElementById('sections-container').innerHTML = sections.map((s,i) => `
    <div class="section" id="sec-${i}">
      <div class="section-head" onclick="toggleSection(${i})">
        <span class="section-name">${escHtml(s.title)}<span class="section-count">${s.count}</span></span>
        <span class="chevron">▾</span>
      </div>
      <div class="section-body">${s.html}</div>
    </div>`).join('');

  document.getElementById('results').classList.add('visible');
  document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}
</script>
"""


def _patch_frontend(html: str) -> str:
    """
    Inject the backend bridge script just before </body>.
    The bridge overrides analyzeFile() and analyzeText() so all
    parsing is done by the Python backend instead of in-browser JS.
    """
    return html.replace("</body>", _PATCH_SCRIPT + "\n</body>")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", default=5000, type=int, help="Port number, defaults to 5000.")
    parser.add_argument("-d", "--debug", action="store_true", help="Run in debug mode, default false")
    parser.add_argument("-i", "--interface", default="127.0.0.1", help="interface OR IP, default localhost", type=str)
    args = parser.parse_args()

    print("=" * 55)
    print("  EML Analyzer")
    print(f"  http://{args.interface}:{args.port}/")
    print("=" * 55)
    app.run(debug=args.debug, host=args.interface, port=args.port)