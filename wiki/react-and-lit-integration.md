# React, WebCore, and Lit Host Integration

This runbook covers integrating official `@a2ui/*` renderers into a web host application using `legends-a2ui scaffold` and keeping renderer packages aligned with upstream `a2ui-project/a2ui` using `legends-a2ui doctor`.

## 1. Preview-First Integration Kit Scaffolding

`legends-a2ui scaffold` supports three targets (`react`, `web-core`, `lit`) and two themes (`precision-noir`, `neutral`). Every run previews planned files and `planSha256` without touching disk until `--apply --confirm-plan <planSha256>` is passed:

```sh
# Preview a React + Precision Noir integration kit
legends-a2ui scaffold --target react --output ./src/a2ui --theme precision-noir --json

# Apply after reviewing plannedFiles
legends-a2ui scaffold --target react --output ./src/a2ui --theme precision-noir \
  --apply --confirm-plan <planSha256> --json

# Alternative targets:
legends-a2ui scaffold --target web-core --output ./src/a2ui --theme precision-noir --json
legends-a2ui scaffold --target lit --output ./src/a2ui --theme neutral --json
```

### Files Emitted per Target

| Target | Emitted Files |
| :--- | :--- |
| Common (all targets) | `a2uiParser.ts`, `a2uiSecurity.ts`, `a2uiTheme.css`, `a2uiParser.test.ts`, `README-INTEGRATION.md` |
| `react` | `A2uiActionContext.tsx`, `A2uiBlock.tsx` |
| `web-core` | `a2uiActionBridge.ts`, `A2uiSurfaceHost.ts` |
| `lit` | `a2uiActionBridge.ts`, `A2uiLitSurface.ts` |

## 2. Recommended Official npm Packages

Verified live against `https://registry.npmjs.org` (2026-11-25):

- `@a2ui/web_core@^0.16.1` (core `MessageProcessor`, `basicCatalog`, `injectBasicCatalogStyles`, `setMarkdownRenderer`)
- `@a2ui/markdown-it@^0.2.4` (Markdown renderer plugin for `Text`)
- `@a2ui/react@^0.16.1` (for `--target react`; supports React 17, 18, 19; requires Node `>=18.0.0`)
- `@a2ui/lit@^0.16.0` (for `--target lit`)

## 3. Critical Host Runtime Patterns

### Dual-Catalog `MessageProcessor` + Root Filter

Initialize `MessageProcessor` with both v1.0 and v0.9 Basic Catalogs so transitional payloads degrade gracefully, and filter surfaces to those containing an `"id": "root"` component before mounting:

```ts
const processor = new MessageProcessor(
  [basicCatalogV1, basicCatalogV09],
  handleAction,
  { version: "1.0", validationConfig: RELAXED_VALIDATION, reportErrorsOnly: true },
);
processor.processMessages(parsed.messages as never[]);
const readySurfaces = Array.from(processor.getSurfaces().values()).filter(
  (s) => s.componentsModel.get("root") !== undefined,
);
```

### SSR / JSDOM-Safe Runtime Init + React Error Boundary

Guard `setMarkdownRenderer(renderMarkdown)` and `injectBasicCatalogStyles()` inside a one-time `try/catch` initializer so server-side rendering and JSDOM unit tests never crash when `document.adoptedStyleSheets` is unavailable. Always wrap `<A2uiSurface />` inside an `ErrorBoundary` (`A2uiSurfaceErrorBoundary`) so malformed dynamic payloads render a contained alert instead of unmounting the host chat transcript.

### Precision Noir Light DOM CSS Overriding `adoptedStyleSheets`

`@a2ui/web_core` and `@a2ui/lit` inject default Light DOM styles via `document.adoptedStyleSheets` targeting custom elements (`a2ui-card`, `a2ui-basic-column`, `a2ui-basic-row`, `a2ui-basic-button`, `a2ui-tabs`, `a2ui-basic-text`, `a2ui-basic-textfield`, `a2ui-choicepicker`, `a2ui-checkbox`, `a2ui-slider`, `a2ui-datetimeinput`).

In `a2uiTheme.css`:
- Scope overrides under `.legends-a2ui-surface.a2ui-dark` and `.legends-a2ui-surface.a2ui-light` so author-sheet specificity beats `adoptedStyleSheets`.
- Flatten double-boxed root cards with `:has(> a2ui-card)` and `:has(> div > a2ui-card)` (`padding: 0; gap: 0;`).
- Enforce Precision Noir discipline: `#07090b` / `#0c0c0f` dark surfaces, 1px translucent hairlines, tight `2px`/`4px`/`6px` radii, and anodized crimson (`#9e0b1a`, hover `#b30f20`, edge `#c9202f`) reserved for at most one primary button per section.

## 4. Auditing Existing Projects for Drift (`doctor --project --live`)

Run static, read-only project inspection (never executes `package.json` scripts, never imports project code, and skips `.env*` files):

```sh
# Offline static drift check on a host web app
legends-a2ui doctor --project /path/to/web-app --json

# Include live HTTPS check against npm, PyPI, and a2ui-project/a2ui main
legends-a2ui doctor --project /path/to/web-app --live --json
```

What `doctor --project` flags automatically:
1. Any `@a2ui/react`, `@a2ui/web_core`, `@a2ui/lit`, or `@a2ui/angular` version below `0.16.0` (for example `0.15.0` drift).
2. Any `.ts`, `.tsx`, `.js`, `.jsx`, or `.md` file referencing the broken 404 URI `https://a2ui.org/specification/v0_9/basic_catalog.json`.
3. Any residual v0.8 envelope keys (`beginRendering`, `surfaceUpdate`, `dataModelUpdate`) still present in source files.
