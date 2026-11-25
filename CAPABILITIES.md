# Capabilities (`legends-a2ui v0.1.0`)

- **Offline Validation (`validate`):** Validates JSON objects, arrays, `{"messages": [...]}` wrappers, JSONL, and Markdown fenced ```` ```a2ui ```` blocks against vendored `a2ui-project/a2ui` schemas (v1.0, v0.9.1, v0.9, v0.8), UAX #31 IDs, component graph cycles/orphans/dangling refs, Basic Catalog 18 components, `@path`/`@call`/`@checks`, media URL & `openUrl` safety, and secret-token leak refusal.
- **Deterministic Normalization (`normalize`):** Upgrades v0.8, v0.9, v0.9.1, and draft v1.0 surfaces into strict canonical A2UI v1.0 while keeping `ChildList.path` and `updateDataModel.path` unprefixed.
- **Operator Surface Composition (`compose`):** 8 curated strict-validated v1.0 templates (`ship-call`, `choice-picker`, `intake-form`, `tabbed-briefing`, `status-dashboard`, `confirm-action`, `media-review`, `wizard-step`).
- **Zero-Coupling Surface Projection (`project`):** Compiles arbitrary structured JSON into strict A2UI v1.0 surfaces (`plan-approval`, `health-deck`, `data-briefing`, or `auto`).
- **Zero-Daemon Static Preview (`preview`):** Emits a single offline HTML5 file with strict CSP, XSS-safe JSON embedding, Precision Noir dark/light themes, all 18 Basic Catalog components, reactive `dataModel`, and an Action Event Inspector.
- **Host Integration Scaffolder (`scaffold`):** Preview-first TypeScript + CSS integration kits for `react`, `web-core`, and `lit`.
- **Offline Spec Lookup (`catalog`, `docs-lookup`):** Queries all 28 SHA-256-pinned `a2ui-project/a2ui` files and local wiki runbooks offline.
- **Diagnostics & Empire Pack (`doctor`, `knowledge-pack`, `resources`):** Environment readiness, static project `@a2ui/*` drift inspection, optional HTTPS allowlist `--live` checks, and Empire vault attachment.
