# Changelog

## 0.1.0 - 2026-11-25

- Initial Stage 2a core release of `legends-a2ui` (`v0.1.0`) with zero third-party pip dependencies.
- Vendored and SHA-256 pinned all 28 upstream `a2ui-project/a2ui` specification schemas and docs at commit `92c0ed6eccb499fe22fba49cb8185b058442c56a`.
- Implemented all 11 CLI subcommands: `doctor`, `validate`, `normalize`, `compose`, `project`, `preview`, `scaffold`, `catalog`, `docs-lookup`, `knowledge-pack`, and `resources`.
- Added hermetic `unittest` suite, preview-first write safety (`planSha256`), CWE-22/59/79/400/918 guardrails, and offline release checks.
