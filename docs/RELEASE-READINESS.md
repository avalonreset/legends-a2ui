# Release Readiness (`legends-a2ui v0.1.0`)

## Runtime & Packaging Compatibility

- **Python:** `>=3.11` (tested on Python 3.11 and 3.12 across Windows, Linux, and macOS).
- **Mandatory Python Dependencies:** Zero (`dependencies = []` in `pyproject.toml`, standard library only).
- **Optional Runtime Companions:** Node.js `>=18.0.0` (only when installing `@a2ui/*` JS/TS renderer packages in host apps); Playwright (optional, non-blocking).
- **Wheel Packaging:** `setup.py` (`BuildPyWithData`) mirrors `docs/`, `knowledge/`, `skills/`, `wiki/`, `references/`, `templates/`, `assets/`, `vendor/`, and `scripts/` into `legends_a2ui/_data/` for clean operation outside a source checkout.

## Provenance & Integrity Pins

- **Vendored Upstream Specs:** 28 files from `a2ui-project/a2ui` (`google/A2UI`) commit `92c0ed6eccb499fe22fba49cb8185b058442c56a` (Apache-2.0), SHA-256 verified in `vendor/a2ui-spec/manifest.json`.
- **Router Skill Provenance:** Byte-exact copy of `skills/cto-legends/SKILL.md` pinned to `avalonreset/cto-legends` commit `cdedca282585c6ade824e4bbcb0910e57eb36851` (`.legends-router-pin`, `docs/router-provenance.json`).
- **Empire Knowledge Pack:** 9 files verified in `knowledge/a2ui/pack.json` (`legends.knowledge-pack/v1`, `version: "0.1.0"`).
- **Presentation Assets:** Banner (`banner.png`, `banner.webp`, `preview.png`), `1280x640` social preview (`social-preview.png`), and 7 outlined `r1` SVG cards verified in `assets/manifest.json` with zero PNG/WebP metadata chunks and `font_redistributed: false`.

## Required Verification Gates

Run all gates locally before tagging or publishing:

```sh
python -m unittest discover -s tests -v
python -m legends_a2ui doctor --json
python -m legends_a2ui knowledge-pack --check --json
python scripts/verify_knowledge_attachment.py --empire-source /path/to/legends-empire
python scripts/check_release.py --root .
git diff --check -- ":!vendor/"
```

CI (`.github/workflows/checks.yml`) additionally builds wheel and sdist artifacts, installs the wheel outside the source checkout, runs `scripts/smoke_installed_resources.py`, and verifies native OS Empire knowledge attachment against pinned `avalonreset/legends-empire`.
