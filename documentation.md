# Code Documentation

Function list for `main.py` and `eml-analyzer.html`. "Called by" shows normal call path.

## Backend: `main.py`

| Function / Class | Summary | Called By |
|---|---|---|
| `add_security_headers(resp)` | Adds security/cache/CSP headers to every response. | Flask `@app.after_request` hook |
| `_check_origin()` | Validates `Origin` / `Referer` against current host, scheme, and loopback equivalents. | `analyze_file()`, `analyze_text()` |
| `_safe_decode(value)` | Converts header value to string, strips CR/LF artifacts. | Header helpers in `_parse_eml()`, `_mime_structure()`, `all_headers` build |
| `_decode_header_value(raw)` | Decodes MIME-encoded header values and names. | `_parse_eml()`, `_parse_attachments()`, `_mime_structure()` |
| `_sanitise_filename(filename)` | Strips original extension and returns safe `.bin` filename. | `download_attachment()` |
| `_safe_content_disposition(filename)` | Builds RFC-compatible attachment `Content-Disposition`. | `download_attachment()` |
| `_parse_auth_results(raw)` | Extracts SPF/DKIM/DMARC/ARC auth checks from `Authentication-Results`. | `_parse_eml()` |
| `_parse_one_received(raw)` | Parses one `Received` header into sender, receiver, protocol, IPs, timestamp. | `_parse_received_hops()` |
| `_parse_received_hops(received_list)` | Reverses Received headers to oldest-first and calculates hop delays. | `_parse_eml()` |
| `_walk_mime_parts(msg, depth=0)` | Depth-limited MIME tree generator. | `_parse_attachments()`, `_extract_bodies()` |
| `_parse_attachments(msg)` | Extracts attachment metadata, hashes payloads, stores payloads in memory. | `_parse_eml()` |
| `_HtmlIocTextExtractor` | HTML parser that collects visible text and selected link attributes for IOC extraction. | `_html_ioc_text()` |
| `_HtmlIocTextExtractor._append(value)` | Adds capped text to parser buffer. | `handle_data()` |
| `_HtmlIocTextExtractor.length` | Returns current collected text length. | `_append()` |
| `_HtmlIocTextExtractor.handle_data(data)` | Receives visible HTML text from `HTMLParser`. | `HTMLParser.feed()` |
| `_HtmlIocTextExtractor.handle_starttag(tag, attrs)` | Captures `href`, `src`, and `action` values. | `HTMLParser.feed()` |
| `_HtmlIocTextExtractor.text()` | Returns normalized collected visible text. | `_html_ioc_text()` |
| `_html_ioc_text(html)` | Strips/caps HTML for IOC scanning while preserving HTTP(S) links. | `_extract_iocs()` |
| `_is_public_ip(ip)` | Returns true only for public IPv4 addresses. | `_extract_iocs()` |
| `_extract_iocs(all_headers, bodies, attachments)` | Extracts IPs, domains, URLs, and attachment hashes. | `_parse_eml()` |
| `_mime_structure(msg, depth=0)` | Builds recursive MIME structure tree with depth truncation. | `_parse_eml()`, itself recursively |
| `_extract_bodies(msg)` | Extracts first plain and HTML body, base64-encodes capped HTML. | `_parse_eml()` |
| `_vendor_for(name)` | Maps X-header names to known vendor/category labels. | `_build_x_headers()` |
| `_build_x_headers(all_headers)` | Builds vendor-labeled X-header list. | `_parse_eml()` |
| `_parse_eml(raw)` | Main parser. Produces API response object. | `analyze_file()`, `analyze_text()` |
| `index()` | Serves main frontend HTML. | `GET /` |
| `analyze_file()` | Accepts multipart uploaded file and returns parsed JSON. | `POST /analyze/file` |
| `analyze_text()` | Accepts JSON raw email text and returns parsed JSON. | `POST /analyze/text` |
| `download_attachment(sha256)` | Downloads stored attachment payload by SHA-256 as `.bin`. | `GET /attachment/<sha256>` |
| `health()` | Health probe endpoint. | `GET /health` |

### Backend Call Flow

```text
POST /analyze/file
  -> analyze_file()
  -> _check_origin()
  -> _parse_eml(file bytes)
     -> _parse_auth_results()
     -> _parse_received_hops()
        -> _parse_one_received()
     -> _extract_bodies()
        -> _walk_mime_parts()
     -> _parse_attachments()
        -> _walk_mime_parts()
     -> _mime_structure()
     -> _build_x_headers()
        -> _vendor_for()
     -> _extract_iocs()
        -> _html_ioc_text()
           -> _HtmlIocTextExtractor
        -> _is_public_ip()
```

```text
POST /analyze/text
  -> analyze_text()
  -> _check_origin()
  -> _parse_eml(raw string)
```

```text
GET /attachment/<sha256>
  -> download_attachment()
  -> _sanitise_filename()
  -> _safe_content_disposition()
```

## Frontend: `eml-analyzer.html`

| Function | Summary | Called By |
|---|---|---|
| `switchTab(id, btn)` | Switches upload/paste input panels and updates active hint. | Mode tab `onclick` |
| `toggleSection(i)` | Collapses or expands a rendered result section. | Section header `onclick` |
| `loadFile(f)` | Reads selected/dropped file for display and stores original `File`. | File input `change`, drop handler |
| `clearAll()` | Resets inputs, result panels, errors, status, and loading state. | Clear button `onclick` |
| `formatBytes(b)` | Formats byte counts for file/attachment sizes. | `loadFile()`, `renderFromBackend()` |
| `analyzeActive()` | Dispatches to file or text analysis based on active tab. | Analyze button `onclick` |
| `callBackend(endpoint, payload)` | Sends fetch request to `/analyze/file` or `/analyze/text`. | `runAnalyze()` |
| `runAnalyze(endpoint, payload)` | Sets loading UI, calls backend, renders result or error. | `analyzeFile()`, `analyzeText()` |
| `analyzeFile()` | Validates selected/dropped file, sends multipart if possible. | `analyzeActive()` |
| `analyzeText()` | Validates pasted text and sends JSON request. | `analyzeActive()` |
| `showError(msg)` | Displays error box and failed parse status. | `runAnalyze()` |
| `setAnalyzeState(loading)` | Enables/disables Analyze button and updates action hint. | `runAnalyze()`, `clearAll()` |
| `setStatus(kind, label)` | Updates parse status badge style/text. | `renderFromBackend()`, `showError()`, `runAnalyze()`, `clearAll()` |
| `renderFromBackend(d)` | Main renderer. Builds summary cards and result sections from API JSON. | `runAnalyze()` |
| `buildHtmlViewer(html_b64, renderId)` | Builds HTML body viewer toolbar and render/source container. | `renderFromBackend()` |
| `buildSrcdoc(html)` | Builds iframe `srcdoc`, disables links, injects link styling. | `buildHtmlViewer()`, `htmlMode()` |
| `wireRenderedLinkCopy(frame)` | Hooks right-click copy behavior for disabled links inside render iframe. | Iframe `onload` |
| `copyUrlToClipboard(url)` | Copies disabled rendered link URL and shows toast. | `wireRenderedLinkCopy()` |
| `showCopyToast(message)` | Creates/reuses toast notification. | `copyUrlToClipboard()`, `wireRenderedLinkCopy()` |
| `disableRenderedLinks(html)` | Parses rendered email HTML, moves `href` to `data-disabled-href`, removes `href`. | `buildSrcdoc()` |
| `htmlMode(mode, btn, renderId)` | Switches HTML body between rendered iframe and source view. | HTML viewer buttons `onclick` |
| `syntaxHighlightHtml(raw)` | Escapes and highlights simple HTML source tokens. | `htmlMode("source")` |
| `renderMimeNode(node)` | Recursively renders MIME tree nodes. | `renderFromBackend()`, itself recursively |
| `switchIocTab(id, btn)` | Switches IOC panels in current IOC section. | IOC tab `onclick` |
| `copyText(btn)` | Copies IOC/hash text from `data-copy` with button feedback. | Copy buttons `onclick` |
| `b64DecodeUnicode(b64)` | Decodes backend HTML base64 to Unicode string. | `buildHtmlViewer()` |
| `escHtml(s)` | Escapes text for HTML content. | Render helpers throughout |
| `escAttr(s)` | Escapes text for HTML attributes. | Render helpers, iframe `srcdoc`, copy buttons |

### Frontend Call Flow

```text
User chooses file
  -> loadFile()
  -> Analyze button
  -> analyzeActive()
  -> analyzeFile()
  -> runAnalyze("file", file)
  -> callBackend("file", file)
  -> renderFromBackend(response)
```

```text
User pastes raw email
  -> Analyze button
  -> analyzeActive()
  -> analyzeText()
  -> runAnalyze("text", raw)
  -> callBackend("text", raw)
  -> renderFromBackend(response)
```

```text
Render HTML body
  -> renderFromBackend()
  -> buildHtmlViewer()
  -> b64DecodeUnicode()
  -> buildSrcdoc()
     -> disableRenderedLinks()
  -> iframe onload
  -> wireRenderedLinkCopy()
```

```text
Right-click rendered link
  -> wireRenderedLinkCopy() contextmenu handler
  -> copyUrlToClipboard()
  -> showCopyToast("Link copied")
```

## Styling: `static/eml-analyzer.css`

CSS has no JavaScript functions. It defines:

- Theme variables in `:root`.
- Layout: header, input card, result sections.
- Upload/dropzone visuals.
- Summary cards and section headers.
- Tables for headers and hops.
- IOC tabs/panels.
- Attachment rows and download button.
- HTML body iframe/source view.
- Error box and copy toast.
