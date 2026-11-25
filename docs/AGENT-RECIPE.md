# Operate `legends-a2ui`

On-demand agent recipe returned by `cto-legends handoff legends-a2ui`. Do not install a standalone module skill; the central `cto-legends` router loads this recipe on demand.

## 1. Readiness and Resource Resolution

1. Resolve installed resource locations and verify the Empire knowledge pack offline:
   ```sh
   legends-a2ui resources --json
   legends-a2ui knowledge-pack --check --json
   ```
2. Run offline diagnostics (and `--project <dir>` when auditing an existing JS/TS/Python app):
   ```sh
   legends-a2ui doctor --json
   legends-a2ui doctor --project /path/to/web-app --json
   legends-a2ui doctor --project /path/to/web-app --live --json
   ```
   `doctor` verifies Python 3.11+, optional Node 18+ and Playwright, SHA-256 hashes of all 28 vendored `a2ui-project/a2ui` spec files, and `knowledge/a2ui/pack.json`. `--project` performs read-only static inspection (never executes configs, skips `.env*`) and flags `@a2ui/*` `<0.16.0` drift, the broken `v0_9/basic_catalog.json` 404 URI, and residual v0.8 keys.
3. Never write user surfaces, HTML previews, scaffolds, or receipts inside the managed `legends-a2ui` module directory.

## 2. Choose the Matching Workflow (All 11 Subcommands)

### Validate Existing Payloads or Markdown Replies (`validate`)

```sh
# Validate a JSON object, JSON array, {"messages":[...]}, or JSONL file
legends-a2ui validate --input surface.json --version auto --strict --json

# Extract and validate every ```a2ui / ```a2ui-json / ```a2ui-jsonl block in Markdown
legends-a2ui validate --input reply.md --extract-markdown --version 1.0 --strict --json

# Custom CWE-400 bounds or warning tolerance
legends-a2ui validate --input surface.json --strict --allow-warnings \
  --max-bytes 1048576 --max-components 500 --max-depth 64 --json
```

### Upgrade Legacy `v0.8` / `v0.9` / `v0.9.1` / Draft `v1.0` Payloads (`normalize`)

```sh
# Emit canonical strict v1.0 to stdout (json, jsonl, or markdown-fence)
legends-a2ui normalize --input legacy.json --target 1.0 --format json
legends-a2ui normalize --input reply.md --extract-markdown --surface-id main --format markdown-fence

# Preview-first file write (two steps)
legends-a2ui normalize --input legacy.json --output upgraded.json --json
legends-a2ui normalize --input legacy.json --output upgraded.json --apply --confirm-plan <planSha256> --json
```

`normalize` preserves unprefixed `ChildList.path` and `updateDataModel.path`, upgrades `Text.variant: h1..h5` to Markdown headings, synthesizes missing `TextField.value`, repairs UAX #31 IDs and refs, replaces the 404 `v0_9/basic_catalog.json` URI, strips removed `createSurface.theme`, and refuses secrets or unsafe URLs.

### Compose Curated Operator Surfaces (`compose`)

```sh
# List all 8 curated templates
legends-a2ui compose --list --json

# Emit a strict-validated surface directly to stdout as a ```a2ui Markdown fence
legends-a2ui compose --template ship-call \
  --vars '{"title":"Ship release","target":"main"}' \
  --surface-id release_gate --format markdown-fence

# Or pass variables via --vars-file and write preview-first with --output
legends-a2ui compose --template intake-form --vars-file vars.json --output intake.md --json
```

Available templates: `ship-call`, `choice-picker`, `intake-form`, `tabbed-briefing`, `status-dashboard`, `confirm-action`, `media-review`, `wizard-step`.

### Project Structured CLI JSON into Interactive Surfaces (`project`)

Pipe `--json` output from any `cto-legends` module into `legends-a2ui project` without adding A2UI dependencies to that module:

```sh
# Auto-detect preset (plan-approval, health-deck, or data-briefing)
legends-a2ui doctor --json | legends-a2ui project --input - --preset auto --format markdown-fence

# Explicit preset + heading override
legends-a2ui project --input plan.json --preset plan-approval \
  --title "Confirm Scaffold Plan" --surface-id scaffold_gate --format markdown-fence

# Optional preview-first file write
legends-a2ui project --input report.json --preset data-briefing --output briefing.md --json
```

### Offline Zero-Daemon Interactive HTML Preview (`preview`)

For terminal-only coding agents without a native A2UI chat renderer, compile any payload into a single offline `file://` HTML5 app (never spawns a localhost server):

```sh
# 1. Preview write plan
legends-a2ui preview --input surface.json --output ./preview-surface.html \
  --theme precision-noir --title "Interactive Preview" --json

# 2. Apply with planSha256 confirmation (add --overwrite only if replacing an existing file)
legends-a2ui preview --input surface.json --output ./preview-surface.html \
  --theme precision-noir --title "Interactive Preview" \
  --apply --confirm-plan <planSha256> --json
```

Supports `--extract-markdown` and `--theme precision-noir|light|auto`.

### Scaffold Host Renderer Integration Kits (`scaffold`)

```sh
# 1. Preview target files and planSha256 (targets: react, web-core, lit; themes: precision-noir, neutral)
legends-a2ui scaffold --target react --output ./src/a2ui --theme precision-noir --json

# 2. Apply after reviewing plannedFiles
legends-a2ui scaffold --target react --output ./src/a2ui --theme precision-noir \
  --apply --confirm-plan <planSha256> --json
```

### Offline Basic Catalog and Spec Lookup (`catalog`, `docs-lookup`)

```sh
legends-a2ui catalog --list --version 1.0 --json
legends-a2ui catalog --component ChoicePicker --version 1.0 --json
legends-a2ui catalog --function openUrl --version 1.0 --json

legends-a2ui docs-lookup "Checkable @checks" --version 1.0 --limit 8 --live-locations --json
```

### Version Check

```sh
legends-a2ui --version
```

## 3. Preview-First Mutation Law

Every file-writing option (`normalize --output`, `compose --output`, `project --output`, `preview --output`, `scaffold --output`) executes in read-only preview mode by default and returns `{ "mode": "preview", "applied": false, "planSha256": "...", "plannedFiles": [...] }`. Never pass `--apply --confirm-plan <planSha256>` until the planned files are reviewed and authorized; pass `--overwrite` only when replacing existing files is explicitly intended.

## 4. Receipts and Knowledge Base

- Read detailed runbooks starting at `wiki/index.md` (mirrored into `knowledge/a2ui/vault/` for `legends-empire`).
- Record receipts using `templates/surface-receipt.md` only inside an authorized user workspace or Empire vault.

## 5. EDR and Security Guardrails (Laws 1-6)

- Never spawn hidden consoles, execution-policy bypass shell wrappers, or detached background localhost servers.
- Never read local browser profile databases, cookie stores, saved login files, or OS credential stores.
- Never print raw API keys, tokens, JWTs, or private keys to stdout, stderr, previews, or receipts.
- Never write through symlinks/reparse points or into Windows Controlled Folder Access protected folders.
- Always keep CLI flags and examples 1:1 with `legends_a2ui/cli.py`.
