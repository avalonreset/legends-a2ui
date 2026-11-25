# Contributing

Read `AGENTS.md`, `docs/AGENT-RECIPE.md`, and `references/sources.md`. Keep one registered router skill (`skills/cto-legends/SKILL.md`), zero mandatory third-party pip dependencies, private evidence outside the repository, and A2UI protocol claims tied to pinned `a2ui-project/a2ui` schemas and docs.

## Development setup

Python 3.11 or newer is required.

```sh
git clone https://github.com/avalonreset/legends-a2ui.git
cd legends-a2ui
python -m pip install -e .
```

## Validation checks

Run the verification suite before opening a pull request:

```sh
python -m unittest discover -s tests -v
python scripts/check_release.py --root .
```

Add hermetic unit tests for new validation rules, normalizer migrations, templates, projector presets, and security guards. Tests must use synthetic fixtures and require no network access.

Use plain language without em dashes or en dashes, and keep LF line endings everywhere.
