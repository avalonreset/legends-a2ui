# Security, Validation, and EDR Guardrails

A2UI payloads are agent-generated JSON rendered into operator interfaces. `legends-a2ui` enforces fail-closed validation, URL protocol allowlists, DoS bounds, secret-leak refusal, static HTML XSS/CSP hardening, and endpoint safety rules across every subcommand.

## 1. Media URL and `openUrl` Protocol Allowlists

Derived from `vendor/a2ui-spec/catalogs/basic/v1/basic_catalog_implementation_guide.md` and enforced in `legends_a2ui/spec_registry.py`, `validator.py`, `preview_html.py`, and scaffolded `a2uiSecurity.ts`:

### Media URLs (`Image.url`, `Video.url`, `Video.posterUrl`, `AudioPlayer.url`)

1. **Control-character and whitespace smuggling block:** Rejects any character with code point `< 0x20` or `0x7F` (blocking `\t`, `\r`, `\n` smuggling such as `ht\ttps://` or `/\t/host`).
2. **Scheme-relative and UNC refusal:** Normalizes `\` to `/` and rejects `//host` and `\\host`.
3. **Strict scheme allowlist:** Permits ONLY:
   - `https://` and `http://` with `//` and a non-empty host containing no whitespace (rejects `https:host`).
   - `data:image/`, `data:audio/`, and `data:video/` (rejects `data:text/html`).
   - Single-slash relative paths (`/assets/img.png`, excluding `/\`).
4. **Denied schemes:** `javascript:`, `vbscript:`, `file:`, `content:`, `blob:`, `ftp:`, and any other unapproved scheme fail with `UNSAFE_MEDIA_URL`.

### Interactive Links (`openUrl` action function)

1. Same control-character and scheme-relative refusal.
2. Permits ONLY `https://` (with host), `http://` (with host), and `mailto:` (containing `@`).
3. Rejects `javascript:`, `data:`, `vbscript:`, `file:`, and relative paths with `UNSAFE_OPEN_URL`.

Validator checks inspect both literal strings and `dataModel`-resolved `@path` pointers for media and `openUrl` arguments.

## 2. CWE-400 Resource, Graph, and Regex Bounds

Every `validate` and `normalize` call bounds untrusted input before deep processing:
- **`--max-bytes`** (default `1048576` = 1 MiB): Enforced before JSON parsing (`MAX_BYTES_EXCEEDED`).
- **`--max-depth`** (default `64`): Checked with a linear bracket/brace pre-scan prior to `json.loads` plus an iterative object depth walk (`MAX_DEPTH_EXCEEDED`), preventing stack exhaustion.
- **`--max-components`** (default `500`): Caps components per surface (`MAX_COMPONENTS_EXCEEDED`).
- **Iterative cycle detection:** Uses an iterative 3-color DFS over the component reference graph (`COMPONENT_CYCLE`), avoiding Python recursion limits and blocking infinite UI render loops.
- **Graph integrity:** Enforces `id: "root"`, unique component IDs, valid UAX #31 IDs, non-dangling child/tab/modal refs (`DANGLING_COMPONENT_REF`), orphan warnings (`ORPHAN_COMPONENT`), reserved `Surface` rejection (`RESERVED_COMPONENT_SURFACE`), and `weight` placement only under `Row`/`Column` (`INVALID_WEIGHT_PARENT`).
- **ReDoS-safe `regex` check rules:** Rejects patterns over 256 characters (`REGEX_TOO_LONG`) or containing nested quantifiers, alternation quantifiers, lookbehinds, or non-portable Unicode property escapes (`UNSAFE_REGEX`).

## 3. Fail-Closed Secret-Token Leak Scan

`validate`, `normalize`, `compose`, and `project` scan all strings and keys iteratively before emitting output (`SECRET_LEAK`). Detected credential shapes are refused without echoing the secret value:
- Stripe live and restricted keys (`sk_live_*`, `rk_live_*`, `whsec_*`)
- GitHub personal/OAuth/app tokens (`ghp_*`, `gho_*`, `ghu_*`, `ghs_*`, `ghr_*`)
- PEM private key headers (`BEGIN ... PRIVATE KEY`)
- AWS access key IDs (`AKIA*`) and `AWS_SECRET_ACCESS_KEY` assignments
- Bearer JWT headers and raw three-segment JWT strings

## 4. Static HTML Preview Hardening (CWE-79 & CSP)

`legends-a2ui preview` produces a single self-contained HTML5 file with:
- **Strict Content Security Policy:** `default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src https: http: data:; media-src https: http: data:;` (zero external scripts, fonts, CDNs, or XHR/fetch destinations).
- **Safe JSON embedding:** Serializes with `ensure_ascii=True` and escapes `</` as `<\/` and `<!--` as `<\!--` inside `<script type="application/json" id="a2ui-payload">`, blocking script-tag breakout.
- **Safe Markdown subset:** HTML-escapes all raw tags in `Text` before applying heading, list, code, bold, italic, and `isSafeOpenUrl`-filtered link formatting.

## 5. Filesystem, Network, and EDR Laws 1-6

1. **Law 1 (Zero hidden shell wrappers):** Never spawn hidden consoles, execution-policy bypass wrappers, or obfuscated shell launchers.
2. **Law 2 (Zero browser profile or OS credential reads):** Never inspect browser profile databases, cookies, saved login files, or OS credential stores. `doctor --project` skips all `.env*` files.
3. **Law 3 (Zero secret echo):** Never print raw tokens, API keys, or private keys to stdout, stderr, previews, or receipts.
4. **Law 4 (Preview-first disk mutations & CWE-22/CWE-59/CFA):** Every file-writing command computes `planSha256` and requires `--apply --confirm-plan <planSha256>` (plus `--overwrite` for existing files). `net_safety.py` enforces symlink/reparse chain refusal via `os.lstat`, base-directory containment, Windows Controlled Folder Access folder refusal, and atomic `O_CREAT|O_EXCL` writes.
5. **Law 5 (Zero localhost preview daemons):** `legends-a2ui preview` writes a static `file://` HTML document and NEVER binds a local HTTP server or launches a browser process.
6. **Law 6 (100% Doc-to-CLI parity & CWE-918 SSRF guard):** Documentation matches `legends_a2ui/cli.py` 1:1. Optional `doctor --live` uses HTTPS-only TLS 1.2+ connections pinned to verified public IPs against the strict 4-host allowlist (`registry.npmjs.org`, `pypi.org`, `api.github.com`, `a2ui.org`).
