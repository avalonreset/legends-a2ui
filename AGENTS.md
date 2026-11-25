# AGENTS.md

Operating rules for agents working in `legends-a2ui`:

1. Read [docs/AGENT-RECIPE.md](docs/AGENT-RECIPE.md) and [references/sources.md](references/sources.md) before modifying protocol logic.
2. Keep Python 3.11+ standard library only (`dependencies = []` in `pyproject.toml`).
3. Keep `skills/` strictly limited to the byte-exact router copy `skills/cto-legends/SKILL.md`.
4. All file-writing commands must remain preview-first (`planSha256` -> `--apply --confirm-plan <sha256>`).
5. Run `python -m unittest discover -s tests -v` and `python scripts/check_release.py --root .` before committing.
6. Never include em-dashes, en-dashes, Windows user paths, hidden-shell flags, or secrets anywhere in the repository.
