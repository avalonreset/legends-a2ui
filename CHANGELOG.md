# Changelog

All notable changes to `legends-a2ui` are documented in this file.

## 0.1.0 - 2026-11-25

- Initial release of `legends-a2ui` (`0.1.0`) built strictly on Python 3.11+ standard library (`dependencies = []`).
- Vendored and SHA-256 pinned all 28 upstream `a2ui-project/a2ui` (`google/A2UI`) specification schemas, catalogs, `versions.json`, `LICENSE`, and protocol docs at commit `92c0ed6eccb499fe22fba49cb8185b058442c56a` (Apache-2.0).
- Implemented all 11 CLI subcommands: `doctor`, `validate`, `normalize`, `compose`, `project`, `preview`, `scaffold`, `catalog`, `docs-lookup`, `knowledge-pack`, and `resources`, plus `--version`.
- Added preview-first (`planSha256` -> `--apply --confirm-plan <sha256>`) write safety, CWE-22/59/79/400/918 protections, Windows Controlled Folder Access path refusal, and EDR Laws 1-6 guardrails.
- Authored 7 operational engineering runbooks under `wiki/` and mirrored them with `references/sources.md` and `templates/surface-receipt.md` into the attachable `legends.knowledge-pack/v1` Empire pack at `knowledge/a2ui/pack.json` (9 files verified against `legends-empire`).
- Added evergreen `README.md`, `AGENTS.md`, `docs/AGENT-RECIPE.md`, `CAPABILITIES.md`, `docs/EMPIRE.md`, `docs/RELEASE-READINESS.md`, `docs/catalog-entry.candidate.json`, house typography banner (`assets/banner.png`, `banner.webp`, `preview.png`), `1280x640` social preview (`assets/social-preview.png`), 7 outlined `r1` SVG cards (`scripts/render_cards.py`), and `assets/manifest.json`.
- Added hermetic `unittest` suite, cross-OS CI matrix (`.github/workflows/checks.yml`), packaged wheel resource smoke check, and offline release gate (`scripts/check_release.py`).
