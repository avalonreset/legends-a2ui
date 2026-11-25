# Release Readiness (`legends-a2ui v0.1.0`)

- Core package: Python 3.11+ standard library only (`dependencies = []`).
- Vendored upstream specs: 28 files from `a2ui-project/a2ui` commit `92c0ed6eccb499fe22fba49cb8185b058442c56a`, SHA-256 verified offline.
- Router provenance: `skills/cto-legends/SKILL.md` pinned to `cdedca282585c6ade824e4bbcb0910e57eb36851`.
- Verification gates:
  - `python -m unittest discover -s tests -v`
  - `python scripts/check_release.py --root .`
  - `python -m legends_a2ui doctor --json`
