# legends-a2ui Engineering Wiki

Offline, source-cited operational runbooks for A2UI v1.0, v0.9.1, v0.9, and v0.8 engineering with `legends-a2ui`.

Every protocol rule, component schema, and catalog URI in this wiki is verified against the 28 upstream files pinned under `vendor/a2ui-spec/` from `a2ui-project/a2ui` commit `92c0ed6eccb499fe22fba49cb8185b058442c56a` (Apache-2.0).

## Runbooks

1. [Wire Format and Version Drift](wire-format-and-drift.md): Exact `v0.8` vs `v0.9` / `v0.9.1` vs `v1.0` drift matrix, `@path`/`@call` vs unprefixed `ChildList.path` and `updateDataModel.path`, `Text.variant` heading migration, required `TextField.value`, the 404 `v0_9/basic_catalog.json` trap, and UAX #31 identifiers.
2. [Basic Catalog Reference](basic-catalog-reference.md): All 18 Basic Catalog components, required and optional properties, variants, `Checkable` `@checks` rules, and all 14 built-in functions verified against `vendor/a2ui-spec/catalogs/basic/v1/catalog.json`.
3. [React, WebCore, and Lit Integration](react-and-lit-integration.md): Preview-first `scaffold` for `react`, `web-core`, and `lit`; Precision Noir Light DOM CSS overriding `@a2ui/web_core` `adoptedStyleSheets`; `ErrorBoundary` and `setMarkdownRenderer`; and `@a2ui/*` version parity checks via `doctor --project --live`.
4. [Security and Validation](security-and-validation.md): Media URL and `openUrl` protocol allowlists, control-character and whitespace smuggling blocks, CWE-400 cycle/depth/size bounds, secret-token leak refusal, static HTML preview CSP plus `<\/` escaping, and EDR Laws 1-6.
5. [Streaming and Actions](streaming-and-actions.md): Single JSON object, array, `{"messages": [...]}` wrapper, JSONL streaming, fenced Markdown extraction, `[A2UI Action: <name>] {...}` dispatch format, `action.event` vs `action.functionCall`, and `userMessage`.
6. [Ecosystem Projection and Offline Preview](ecosystem-projection-and-preview.md): Zero-coupling JSON-to-A2UI projection (`plan-approval`, `health-deck`, `data-briefing`, `auto`) across `cto-legends` modules and zero-daemon `file://` interactive HTML preview decks for terminal-only agents.

## Supporting Ledgers

- [Pinned Upstream Sources](../references/sources.md): Pinned commit SHA, `a2ui.org` endpoint verification, npm and PyPI package baselines, and router provenance.
- [Surface Receipt Template](../templates/surface-receipt.md): Reusable receipt template for recording validated surfaces and approval outcomes.
- [Agent Recipe](../docs/AGENT-RECIPE.md): On-demand operational workflow returned by `cto-legends handoff legends-a2ui`.

## CLI Quick Reference

All 11 subcommands run offline by default with zero third-party Python pip dependencies (`Python 3.11+` stdlib only):

| Subcommand | Purpose | Key Flags |
| :--- | :--- | :--- |
| `doctor` | Verify Python, optional Node, vendor SHA-256, knowledge pack, and optional project/live drift | `--project <dir>`, `--live`, `--json` |
| `validate` | Validate JSON, JSONL, or fenced Markdown A2UI payloads offline | `--input <path\|->`, `--extract-markdown`, `--version auto\|1.0\|0.9.1\|0.9\|0.8`, `--strict`, `--allow-warnings`, `--max-bytes`, `--max-components`, `--max-depth`, `--json` |
| `normalize` | Deterministically upgrade v0.8/v0.9/v0.9.1/draft v1.0 to strict v1.0 | `--input <path\|->`, `--extract-markdown`, `--target 1.0`, `--format json\|jsonl\|markdown-fence`, `--surface-id <id>`, `--output <path>`, `--apply`, `--confirm-plan <sha>`, `--overwrite`, `--json` |
| `compose` | Generate strict-validated v1.0 surfaces from 8 curated operator templates | `--list`, `--template <name>`, `--vars <json>`, `--vars-file <path>`, `--surface-id <id>`, `--format json\|jsonl\|markdown-fence`, `--output <path>`, `--apply`, `--confirm-plan <sha>`, `--overwrite`, `--json` |
| `project` | Project arbitrary structured JSON into a strict v1.0 surface | `--input <path\|->`, `--preset auto\|plan-approval\|health-deck\|data-briefing`, `--title <str>`, `--surface-id <id>`, `--format json\|jsonl\|markdown-fence`, `--output <path>`, `--apply`, `--confirm-plan <sha>`, `--overwrite`, `--json` |
| `preview` | Render a zero-daemon, zero-CDN static HTML5 `file://` preview | `--input <path\|->`, `--extract-markdown`, `--output <path.html>`, `--theme precision-noir\|light\|auto`, `--title <str>`, `--apply`, `--confirm-plan <sha>`, `--overwrite`, `--json` |
| `scaffold` | Generate a preview-first React, WebCore, or Lit integration kit | `--target react\|web-core\|lit`, `--output <dir>`, `--theme precision-noir\|neutral`, `--apply`, `--confirm-plan <sha>`, `--overwrite`, `--json` |
| `catalog` | Query vendored Basic/Standard Catalog schemas offline | `--component <name>`, `--function <name>`, `--version 1.0\|0.9.1\|0.9\|0.8`, `--list`, `--json` |
| `docs-lookup` | Search vendored A2UI spec docs and local wiki runbooks offline | `<query>`, `--version all\|1.0\|0.9.1\|0.9\|0.8`, `--live-locations`, `--limit <int>`, `--json` |
| `knowledge-pack` | Verify `knowledge/a2ui/pack.json` SHA-256 digests and print attachment command | `--check`, `--json` |
| `resources` | Print resolved `package_data` or checkout resource paths as JSON | `--json` |

## Boundaries and Empire Ownership

- `legends-a2ui` is strictly offline by default. Only `legends-a2ui doctor --live` makes outbound HTTPS requests, restricted to the pinned allowlist (`registry.npmjs.org`, `pypi.org`, `api.github.com`, `a2ui.org`) with DNS IP pinning and TLS 1.2+.
- Every file-writing command (`normalize --output`, `compose --output`, `project --output`, `preview --output`, `scaffold --output`) previews by default and requires `--apply --confirm-plan <planSha256>` (plus `--overwrite` if replacing existing files).
- **Empire vault ownership:** When attached into a `legends-empire` vault via `knowledge/a2ui/pack.json`, reference files land under `wiki/library/legends-a2ui/a2ui/reference/` and are managed by the pack. Your vault's shelf `index.md` and private notes remain owner-controlled and are preserved across pack upgrades.
