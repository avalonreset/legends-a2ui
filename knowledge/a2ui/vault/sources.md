# Pinned Upstream Sources and Verification Ledger

Every protocol rule, schema check, and catalog lookup in `legends-a2ui` is anchored to pinned upstream sources audited on `2026-11-25`.

## 1. Upstream A2UI Repository Pin

- **Canonical Repository:** `https://github.com/a2ui-project/a2ui` (canonical redirect from `https://github.com/google/A2UI`)
- **Default Branch:** `main`
- **Pinned Commit SHA:** `92c0ed6eccb499fe22fba49cb8185b058442c56a` (`2026-11-25T16:50:38Z`)
- **Upstream License:** Apache-2.0 (`vendor/a2ui-spec/LICENSE`, `vendor/a2ui-spec/NOTICE`, `THIRD_PARTY_NOTICES.md`)
- **Vendored File Manifest:** `vendor/a2ui-spec/manifest.json` (28 SHA-256-pinned files across `v1.0`, `v0.9.1`, `v0.9`, `v0.8`, `versions.json`, and `LICENSE`)
- **Offline Verification Command:** `legends-a2ui doctor --json`

## 2. Verified Live `a2ui.org` Endpoints (2026-11-25)

| Endpoint | Status | Role |
| :--- | :--- | :--- |
| `https://a2ui.org/llms.txt` | HTTP 200 | Official machine-readable documentation index |
| `https://a2ui.org/specification/versions.json` | HTTP 200 | Authoritative protocol version lifecycle (`v1.0` current, `v0.9.1`/`v0.9` previous, `v0.8` deprecated; no `v0.10`) |
| `https://a2ui.org/specification/v1_0/catalogs/basic/catalog.json` | HTTP 200 | Canonical v1.0 Basic Catalog URI and schema (`18` components, `14` functions) |
| `https://a2ui.org/specification/v1_0/json/agent_to_renderer.json` | HTTP 200 | v1.0 Agent-to-Renderer envelope schema |
| `https://a2ui.org/specification/v1_0/json/renderer_to_agent.json` | HTTP 200 | v1.0 Renderer-to-Agent envelope schema |
| `https://a2ui.org/specification/v1_0/json/common_types.json` | HTTP 200 | v1.0 shared primitives (`DataBinding`, `FunctionCall`, `Action`, `ChildList`) |
| `https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json` | HTTP 200 | Canonical v0.9 / v0.9.1 Basic Catalog URI |
| `https://a2ui.org/specification/v0_8/standard_catalog_definition.json` | HTTP 200 | Canonical v0.8 Standard Catalog URI |
| `https://a2ui.org/specification/v0_9/basic_catalog.json` | **HTTP 404** | **Deprecated draft URI trap; flagged by `validate` and `doctor --project`** |

## 3. Official Package Baselines (2026-11-25)

### npm (`registry.npmjs.org`)

| Package | Audited Latest | License | Notes |
| :--- | :--- | :--- | :--- |
| `@a2ui/react` | `0.16.1` | Apache-2.0 | React 17/18/19, Node `>=18.0.0` |
| `@a2ui/web_core` | `0.16.1` | Apache-2.0 | Core `MessageProcessor`, `basicCatalog`, styles |
| `@a2ui/lit` | `0.16.0` | Apache-2.0 | Lit Web Components renderer |
| `@a2ui/angular` | `0.16.0` | Apache-2.0 | Angular renderer |
| `@a2ui/markdown-it` | `0.2.4` | Apache-2.0 | Markdown renderer plugin for `Text` |
| `@a2ui/agent` | `0.2.1` | Apache-2.0 | TypeScript Agent SDK |
| `@a2ui/catalog-mcp` | `0.1.1` | Apache-2.0 | MCP catalog package |

### PyPI (`pypi.org`)

| Package | Audited Latest | License | Notes |
| :--- | :--- | :--- | :--- |
| `a2ui-core` | `0.7.1` | Apache-2.0 | Python `>=3.10` |
| `a2ui-agent-sdk` | `0.12.1` | Apache-2.0 | Python `>=3.10` |
| `a2ui-adk` | `0.3.0` | Apache-2.0 | Python `>=3.10` |
| `a2ui-a2a` | `0.4.0` | Apache-2.0 | Python `>=3.10` |

Note: `legends-a2ui` itself has **zero third-party pip dependencies** (`dependencies = []`, Python 3.11+ standard library only). The package versions above are tracked for host project drift detection (`legends-a2ui doctor --project <dir> --live`).

## 4. `cto-legends` Router Provenance

- **Router Repository:** `avalonreset/cto-legends`
- **Pinned Commit:** `cdedca282585c6ade824e4bbcb0910e57eb36851` (`.legends-router-pin`, `docs/router-provenance.json`)
- **Vendored Router Copy:** `skills/cto-legends/SKILL.md` (SHA-256 `843ecc65238478541ff0a965814c772e1073d8e7631858bd4146dce67a9a81a1`, 10,225 bytes)
