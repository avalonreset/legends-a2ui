# Agent Instructions (`legends-a2ui`)

Read [docs/AGENT-RECIPE.md](docs/AGENT-RECIPE.md), then [wiki/index.md](wiki/index.md) and [references/sources.md](references/sources.md) before modifying protocol logic or operating `legends-a2ui`.

## Operating Contract

1. **Offline-first readiness:** Run `legends-a2ui doctor --json` before modifying payloads or scaffolding host code. `legends-a2ui resources --json` and `legends-a2ui knowledge-pack --check --json` also run fully offline. Pass `doctor --project <dir> --live --json` only when inspecting a host project against live upstream registries.
2. **Zero third-party Python dependencies:** Keep `legends_a2ui/` strictly on Python 3.11+ standard library (`dependencies = []` in `pyproject.toml`).
3. **One-skill router rule:** Keep `skills/` strictly limited to the byte-exact copy of `skills/cto-legends/SKILL.md`. Load module guidance on demand from `docs/AGENT-RECIPE.md` and `wiki/`.
4. **Preview-first file mutations:** Every file-writing invocation (`normalize --output`, `compose --output`, `project --output`, `preview --output`, `scaffold --output`) previews by default and returns `planSha256`. Pass `--apply --confirm-plan <planSha256>` (plus `--overwrite` only when replacing existing files is authorized).
5. **Context-aware A2UI v1.0 protocol rules:** Keep `ChildList.path` and `updateDataModel.path` unprefixed while using `@path`, `@call`, `@checks`, `@accessibility`, `@catalogId`, and `@metadata` in component and dynamic value positions. Always emit canonical catalog URIs (`https://a2ui.org/specification/v1_0/catalogs/basic/catalog.json` for v1.0; `https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json` for v0.9).
6. **Keep user outputs outside managed checkouts:** Write previews, scaffolds, and receipts into the user workspace, not inside this module checkout.
7. **Verification before commit:** Run `python -m unittest discover -s tests -v`, `python -m legends_a2ui doctor --json`, `python -m legends_a2ui knowledge-pack --check --json`, and `python scripts/check_release.py --root .`. Never include em-dashes, en-dashes, Windows user paths, private hostnames, or secrets anywhere in the repository.

## EDR and Security Guardrails (Laws 1-6)

- **Law 1 (Zero hidden shells):** Never spawn hidden console windows, execution-policy bypass shell wrappers, or obfuscated command launchers.
- **Law 2 (Zero browser/credential reads):** Never read local browser profile databases, cookie stores, saved login files, or OS credential stores. Static project scans must skip `.env*` files.
- **Law 3 (Zero secret echo):** Never print raw API keys, tokens, JWTs, or private keys to stdout, stderr, HTML previews, or Markdown receipts.
- **Law 4 (Preview-first `planSha256` mutations):** Never silently overwrite user files; enforce symlink/reparse chain refusal, base-directory containment, Controlled Folder Access folder refusal, and `planSha256` confirmation.
- **Law 5 (Zero localhost preview daemons):** Never spawn detached background HTTP servers or auto-launch browsers for A2UI previews; emit self-contained offline `file://` HTML via `legends-a2ui preview`.
- **Law 6 (100% Doc-to-CLI parity):** Every documented subcommand and flag in `README.md`, `AGENTS.md`, `docs/AGENT-RECIPE.md`, and `wiki/*.md` must match `legends_a2ui/cli.py` 1:1.
