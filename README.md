# EML Analyzer

Local Flask app for inspecting `.eml` email files. It extracts core headers, authentication results, Received hops, MIME structure, bodies, attachments, X-headers, and IOCs.

## Features

- Upload `.eml`, `.msg`, `message/rfc822`, or plain text email files.
- Paste raw headers or full EML content.
- Parse SPF, DKIM, DMARC, and ARC results from `Authentication-Results`.
- Build oldest-first `Received` hop timeline with delay values.
- Extract public IPv4 addresses, domains, URLs, and attachment SHA-256 hashes.
- Display MIME tree, raw headers, HTML/plain body, attachments, and X-header vendor groups.
- Render HTML email body in a sandboxed iframe.
- Disable rendered email links while preserving visual link hints.
- Right-click disabled rendered links to copy their original URL.
- Download attachments as `.bin` by SHA-256 ID after analysis.

## Files

| File | Purpose |
|---|---|
| `main.py` | Flask backend, parser, routes, attachment download store |
| `eml-analyzer.html` | Frontend HTML and JavaScript |
| `static/eml-analyzer.css` | Frontend styling |
| `requirements.txt` | Python dependencies |
| `documentation.md` | Function-level code documentation |

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`google-re2` is declared for safer regex behavior. If unavailable, `main.py` falls back to Python stdlib `re`.

## Run

```bash
python main.py
```

Default URL:

```text
http://127.0.0.1:5000/
```

Options:

```bash
python main.py -p 8080
python main.py -i 0.0.0.0 -p 5000
python main.py -d
```

## API

### `GET /`

Serves `eml-analyzer.html`.

### `POST /analyze/file`

Multipart upload endpoint.

Field:

```text
file=<email file>
```

Returns parsed JSON.

### `POST /analyze/text`

JSON endpoint for pasted raw email.

```json
{
  "raw": "From: sender@example.com\n..."
}
```

Returns parsed JSON.

### `GET /attachment/<sha256>`

Downloads an attachment from the in-memory store. The store is refreshed on each parse, so re-analyze first if a file is no longer available.

### `GET /health`

Returns:

```json
{"status": "ok"}
```

## Security Notes

This app is intended for local or trusted-LAN use. Do not expose it publicly without authentication and additional hardening.

Current safeguards:

- 20 MB Flask request limit.
- CSRF origin/referer check for analysis endpoints.
- Security headers and `no-store` cache header.
- MIME traversal depth cap.
- HTML body size cap before base64 response.
- Rendered email links have `href` removed in the iframe.
- Attachment downloads force `.bin` filenames.

## Development Checks

Syntax-check frontend JavaScript:

```bash
node -e "const fs=require('fs'); const html=fs.readFileSync('eml-analyzer.html','utf8'); const m=html.match(/<script>([\\s\\S]*)<\\/script>/); new Function(m[1]); console.log('frontend ok')"
```

Python syntax check:

```bash
python -B -m py_compile main.py
```
