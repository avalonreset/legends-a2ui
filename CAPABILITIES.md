# Capabilities (`legends-a2ui v0.1.0`)

`legends-a2ui` is an offline-first Python 3.11+ standard-library CLI (`dependencies = []`) for A2UI v1.0, v0.9.1, v0.9, and v0.8 engineering.

## Core Capabilities

1. **Offline Environment, Spec, and Project Diagnostics (`doctor`):**
   - Verifies Python 3.11+, optional Node.js 18+ and Playwright availability, SHA-256 integrity of all 28 vendored `a2ui-project/a2ui` files (`vendor/a2ui-spec/manifest.json`), and `knowledge/a2ui/pack.json`.
   - Static, read-only `--project <dir>` inspection (skips `.env*`, never executes configs) detecting `@a2ui/*` `<0.16.0` package drift, references to the broken HTTP 404 `v0_9/basic_catalog.json` URI, and legacy v0.8 envelope keys.
   - Optional `--live` HTTPS probe (TLS 1.2+, DNS IP pinning, strict 4-host allowlist) checking latest `@a2ui/react` on npm, `a2ui-core` on PyPI, and `a2ui-project/a2ui` `main` HEAD.
2. **Strict Multi-Format Validation (`validate`):**
   - Parses single JSON objects, JSON arrays, `{"messages": [...]}` wrappers, streaming JSONL, and Markdown fenced ```` ```a2ui ```` / `a2ui-json` / `a2ui-jsonl` blocks (`--extract-markdown`).
   - Validates protocol envelopes across v1.0, v0.9.1, v0.9, and v0.8; `createSurface` lifecycle; `id: "root"` requirement; Unicode UAX #31 component IDs via stdlib `unicodedata`; reserved `Surface` rejection; dangling component references; orphan warnings; iterative 3-color DFS cycle detection; `weight` parent placement under `Row`/`Column`; all 18 Basic Catalog components and 14 built-in functions; `Checkable` `@checks` rules; `@path`/`@call` and single-`@` / `@@` escape compliance; media URL and `openUrl` protocol allowlists; ReDoS regex checks; CWE-400 byte/depth/component bounds; and fail-closed secret-token leak refusal.
3. **Deterministic Legacy-to-v1.0 Normalization (`normalize`):**
   - Upgrades `v0.8`, `v0.9`, `v0.9.1`, and transitional draft `v1.0` payloads to canonical strict `v1.0`.
   - Context-aware `@path` / `@call` rewriting that keeps `ChildList.path` and `updateDataModel.path` unprefixed (and repairs mistakenly prefixed `ChildList.@path`).
   - Upgrades `Text.variant: h1..h5` to Markdown headings, synthesizes missing `TextField.value`, sanitizes non-UAX #31 IDs with collision-safe ref remapping, replaces broken/alias `catalogId` values with the canonical v1.0 URI, strips removed `createSurface.theme`, and verifies output with `validate --strict`.
4. **Curated Operator Surface Composition (`compose`):**
   - Ships 8 strict-validated operator templates: `ship-call`, `choice-picker`, `intake-form`, `tabbed-briefing`, `status-dashboard`, `confirm-action`, `media-review`, and `wizard-step`.
   - Accepts `--vars` or `--vars-file`, runs fail-closed secret scanning, and emits `markdown-fence`, `json`, or `jsonl` to stdout or preview-first `--output`.
5. **Zero-Coupling JSON-to-A2UI Surface Projection (`project`):**
   - Compiles arbitrary structured JSON (`--input <path|->`) into strict A2UI v1.0 surfaces via `--preset auto|plan-approval|health-deck|data-briefing`.
   - Lets any `cto-legends` module's `--json` output render as an interactive approval card, health deck, or tabbed briefing with zero cross-module coupling.
6. **Zero-Daemon Offline Static Preview (`preview`):**
   - Emits a single self-contained, zero-CDN HTML5 `file://` preview under a strict `default-src 'none'` CSP with `<\/` JSON escaping (CWE-79).
   - Implements all 18 Basic Catalog components, reactive `dataModel` bindings, `@checks` feedback, safe Markdown rendering, Precision Noir dark and Light theme switching, JSON source toggle, and a live `[A2UI Action: <name>] {...}` Action Event Inspector.
7. **Preview-First Host Integration Scaffolder (`scaffold`):**
   - Generates TypeScript + Light DOM CSS integration kits for `--target react|web-core|lit` (`precision-noir` or `neutral` theme), including `a2uiParser.ts`, `a2uiSecurity.ts`, `a2uiTheme.css`, `a2uiParser.test.ts`, action bridge/context, and host wrapper (`A2uiBlock.tsx`, `A2uiSurfaceHost.ts`, or `A2uiLitSurface.ts`).
8. **Offline Spec Catalog and Documentation Search (`catalog`, `docs-lookup`):**
   - Queries all 18 Basic Catalog components and 14 built-in functions across `1.0`, `0.9.1`, `0.9`, and `0.8` offline.
   - Searches all 28 SHA-256-pinned upstream spec files and local `wiki/` runbooks offline, with optional `--live-locations` URLs.
9. **Attachable Empire Knowledge Pack & Packaged Resource Resolution (`knowledge-pack`, `resources`):**
   - Ships `knowledge/a2ui/pack.json` (`legends.knowledge-pack/v1`) mirroring 7 wiki runbooks, `references/sources.md`, and `templates/surface-receipt.md` with SHA-256 verification and native Windows/Linux/macOS `legends-empire` attachment support.
