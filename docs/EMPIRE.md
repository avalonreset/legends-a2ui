# Empire Knowledge Pack Integration (`knowledge/a2ui/pack.json`)

`legends-a2ui` ships a versioned, SHA-256-verified `legends.knowledge-pack/v1` manifest at `knowledge/a2ui/pack.json` designed for clean attachment into a [`legends-empire`](https://github.com/avalonreset/legends-empire) Markdown knowledge vault.

## Pack Contents (`knowledge/a2ui/vault/`)

The pack mirrors 9 source-cited files into `knowledge/a2ui/vault/`:
- `index.md` (pack entrypoint and CLI quick reference)
- `wire-format-and-drift.md` (`v0.8` vs `v0.9` / `v0.9.1` vs `v1.0` matrix and migration traps)
- `basic-catalog-reference.md` (all 18 Basic Catalog components, `@checks`, and 14 built-in functions)
- `react-and-lit-integration.md` (`scaffold` targets, Light DOM CSS overrides, `doctor --project --live`)
- `security-and-validation.md` (URL allowlists, CWE-400 bounds, secret scan, static preview CSP, EDR Laws 1-6)
- `streaming-and-actions.md` (wire envelopes, `--extract-markdown`, `action.event` vs `action.functionCall`, `[A2UI Action: <name>]`)
- `ecosystem-projection-and-preview.md` (`project` zero-coupling JSON projection and `preview` static HTML decks)
- `sources.md` (pinned `a2ui-project/a2ui` commit, live endpoint audit, npm/PyPI baselines)
- `templates/surface-receipt.md` (surface validation and approval receipt template)

## Offline Integrity Verification

```sh
legends-a2ui knowledge-pack --check --json
```

## Attachment Workflow

Suggested vault home: `wiki/library/legends-a2ui/a2ui`

```sh
# Preview and attach into an Empire vault
cto-legends run legends-empire -- knowledge attach /path/to/legends-a2ui/knowledge/a2ui/pack.json --vault /path/to/vault
```

## Vault Ownership Guarantees

Verified end-to-end by `scripts/verify_knowledge_attachment.py`:
1. Preview mode performs zero vault writes.
2. Fresh attachment installs pack files under `wiki/library/legends-a2ui/a2ui/reference/`.
3. Repeat attachment with the same pack version is a clean no-op.
4. Upstream pack updates preserve your owner-edited shelf `index.md` and private vault notes.
5. Local manual edits inside `reference/` cause attachment to refuse before mutating the vault.
