# Ecosystem Projection (`project`) and Zero-Daemon Offline Preview (`preview`)

`legends-a2ui` serves two operational environments cleanly:
1. **Interactive A2UI chat hosts** that render fenced ```` ```a2ui ```` blocks natively.
2. **Terminal-only coding agents** that have no built-in graphical renderer and need an offline, zero-daemon interactive review deck.

## 1. Zero-Coupling JSON-to-A2UI Projection (`legends-a2ui project`)

Other `cto-legends` modules emit structured JSON (`--json`) for previews, diagnostics, and reports. Rather than coupling other modules to A2UI schemas, pipe any structured JSON directly into `legends-a2ui project` to compile a strict-validated A2UI v1.0 surface.

### Three Generic Presets (`--preset auto|plan-approval|health-deck|data-briefing`)

| Preset | Auto-Detection Signal (`--preset auto`) | Compiled Surface |
| :--- | :--- | :--- |
| **`plan-approval`** | Object contains `planSha256`, `plannedFiles`, or `"mode": "preview"` | Card listing planned create/overwrite files and byte sizes, `planSha256` prefix, cost/warning callouts, optional notes `TextField`, and `approve_plan` / `hold_plan` buttons carrying `planSha256` in action context. |
| **`health-deck`** | Object has boolean `ok` plus one of `checks`, `errors`, `warnings`, `modules`, `python`, `vendorSpec` | PASS/ATTENTION status card summarizing diagnostic fields, `[ERROR]`/`[WARN]` callouts, and `rerun_check` / `export_report` buttons. |
| **`data-briefing`** | Any other valid JSON object, array, or scalar | Scalar summary plus `Tabs` (when 2 to 5 nested sections exist) or stacked section `Card`s, plus an `acknowledge_briefing` action button. |

### Cross-Module Pipeline Examples

```sh
# Project any module's preview-first JSON plan into an interactive approval card
legends-a2ui scaffold --target react --output ./src/a2ui --json \
  | legends-a2ui project --input - --preset auto --format markdown-fence

# Project a doctor health report into a status deck
legends-a2ui doctor --json \
  | legends-a2ui project --input - --preset health-deck --title "A2UI Readiness"

# Project an arbitrary JSON report into a tabbed briefing and preview file write
legends-a2ui project --input report.json --preset data-briefing --output briefing.md --json
```

Projection safeguards:
- Runs `scan_for_secrets` before compiling; refuses any input containing live tokens or private keys (`SECRET_LEAK`).
- Validates the compiled surface with `validate_payload(..., version="1.0", strict=True)` before emitting output.
- Caps displayed entries (`12` items per list/table section, `5` tabbed sections) so large JSON outputs stay compact and readable.

## 2. Curated Operator Templates (`legends-a2ui compose`)

When you want a bespoke operator workflow rather than projecting existing JSON, use `legends-a2ui compose --list` to inspect the 8 strict-validated templates:
- `ship-call`: Release or deployment approval card with optional operator notes and `approve_ship` / `hold_ship`.
- `choice-picker`: 2 to 4 option `ChoicePicker` (`mutuallyExclusive` or `multipleSelection`, `chips` or `checkbox`) with confirm/cancel.
- `intake-form`: Multi-field form with `@checks` (`required`, `email`), `DateTimeInput`, `CheckBox`, and submit.
- `tabbed-briefing`: Multi-section `Tabs` briefing with acknowledgement button.
- `status-dashboard`: Metric cards `Row` + dynamic `List` template + refresh/inspect actions.
- `confirm-action`: Destructive/irreversible gate with explicit acknowledgement `CheckBox`.
- `media-review`: `Image` or `Video` review card with media URL safety validation and approve/revision actions.
- `wizard-step`: Multi-step card with `Slider`, `ChoicePicker`, and back/next navigation.

## 3. Zero-Daemon Offline Static Preview (`legends-a2ui preview`)

Terminal-only coding agents should NEVER spawn background `localhost` servers or launch browsers automatically (EDR Law 5). Instead, compile any A2UI payload (or Markdown file with `--extract-markdown`) into a single self-contained HTML5 file that opens directly via `file://`:

```sh
# 1. Preview the write plan (no disk writes yet)
legends-a2ui preview --input surface.json --output ./preview-surface.html \
  --theme precision-noir --title "Ship Call Preview" --json

# 2. Apply with planSha256 confirmation
legends-a2ui preview --input surface.json --output ./preview-surface.html \
  --theme precision-noir --title "Ship Call Preview" \
  --apply --confirm-plan <planSha256> --json
```

### What the Static Preview Includes

- **Zero CDN / Zero Network:** All CSS and JavaScript live inline under a strict `default-src 'none'` CSP.
- **Full 18-Component Runtime:** Renders `Card`, `Column`, `Row`, `List` (static and dynamic `{componentId, path}`), `Divider`, `Text` (safe Markdown), `Icon`, `Image`, `Video`, `AudioPlayer`, `Tabs`, `Modal`, `Button`, `TextField`, `CheckBox`, `ChoicePicker` (`checkbox`/`chips` + `filterable`), `Slider`, and `DateTimeInput`.
- **Reactive `dataModel` + `@checks`:** Editing inputs updates bound `@path` values live and re-evaluates `@checks` validation messages.
- **Live Action Event Inspector:** Clicking any button logs the exact `[A2UI Action: <name>] {...}` line in the inspector drawer (and blocks unsafe `openUrl` targets).
- **Theme and Source Toggles:** Switch between Precision Noir dark mode and Light mode, or toggle between the rendered UI and canonical v1.0 JSON source.
