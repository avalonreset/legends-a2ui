# Streaming Formats, Markdown Extraction, and Action Dispatch

A2UI payloads move between coding agents and host renderers across five wire/document shapes and return operator decisions through structured action events.

## 1. Supported Input Envelope Formats

Both `legends-a2ui` (`legends_a2ui/parser.py`) and the scaffolded TypeScript host parser (`a2uiParser.ts`) accept all five formats:

1. **Single JSON object:** One envelope object (for example a standalone `createSurface` with inline `components` and `dataModel`).
2. **JSON array:** Ordered list of envelope messages (`[createSurface, updateComponents, updateDataModel]`).
3. **`{"messages": [...]}` wrapper:** Object wrapping an array of envelope messages.
4. **Streaming JSONL:** Newline-delimited JSON objects, one envelope message per line. During live streaming in a host UI (`isStreaming = true`), `a2uiParser.ts` tolerates an incomplete trailing line while rendering already-received messages.
5. **Fenced Markdown blocks (`--extract-markdown`):** Extracts all ```` ```a2ui ````, ```` ```a2ui-json ````, and ```` ```a2ui-jsonl ```` code fences from a Markdown reply or document, tracking `blockIndex`, `fenceLang`, `startLine`, and `endLine`, and flagging unclosed fences (`UNCLOSED_FENCE`).

```sh
# Validate every ```a2ui block inside an agent Markdown reply
legends-a2ui validate --input reply.md --extract-markdown --strict --json

# Pipe an agent reply over stdin and normalize to JSONL
cat reply.md | legends-a2ui normalize --input - --extract-markdown --format jsonl
```

## 2. Output Formatting Options

`normalize`, `compose`, and `project` support `--format`:
- `json`: Pretty-printed JSON array of v1.0 messages (default for `normalize`).
- `jsonl`: Compact newline-delimited JSON messages, one per line, ready for streaming transports.
- `markdown-fence`: Wrapped in a ```` ```a2ui ... ``` ```` Markdown code fence (default for `compose` and `project`), ready to paste directly into hosts that render fenced A2UI blocks natively.

## 3. Button Actions: `action.event` vs `action.functionCall`

In A2UI v1.0, `Button.action` MUST contain **exact XOR** of either `event` or `functionCall` (providing both or neither fails with `INVALID_ACTION`):

### Server/Agent Round-Trip (`action.event`)

Dispatches an event back to the agent with resolved `context` values and optional `userMessage`:

```json
{
  "id": "approve_btn",
  "component": "Button",
  "child": "approve_lbl",
  "variant": "primary",
  "action": {
    "event": {
      "name": "approve_ship",
      "userMessage": "Approved release for main.",
      "context": {
        "target": "main",
        "notes": { "@path": "/notes" }
      }
    }
  }
}
```

- `name` (required non-empty string): Event identifier.
- `context` (optional object): Keys map to literals or `DynamicValue` (`@path` / `@call`), resolved against the surface's live `dataModel` at click time.
- `userMessage` (optional `DynamicString`, v1.0 addition): Human-readable summary resolved and attached to the outbound `action` message.

### Client-Side Function Execution (`action.functionCall`)

Executes a renderer-side catalog function directly (most commonly `openUrl`):

```json
{
  "id": "docs_btn",
  "component": "Button",
  "child": "docs_lbl",
  "variant": "borderless",
  "action": {
    "functionCall": {
      "@call": "openUrl",
      "args": { "url": "https://a2ui.org" }
    }
  }
}
```

`openUrl` requires user activation and is strictly restricted to `https:`, `http:`, and `mailto:` targets.

## 4. Standard Host Dispatch Format (`[A2UI Action: <name>]`)

Both `legends-a2ui preview` (in its live Action Inspector) and `legends-a2ui scaffold` (`A2uiActionContext.tsx` / `a2uiActionBridge.ts`) format clicked button events into a deterministic single-line message that coding-agent chat hosts can parse reliably:

```text
[A2UI Action: approve_ship] {"surfaceId":"ship_call","action":"approve_ship","sourceComponentId":"approve_btn","context":{"target":"main","notes":"Verified release checks"}}
```

When handling an incoming `[A2UI Action: <name>] {...}` turn:
1. Parse the JSON object after the closing `]`.
2. Match `action` and `surfaceId` against the pending decision or plan.
3. Never treat action context alone as bypass authority for destructive or unconfirmed mutations; confirm `planSha256` explicitly when applying write plans.
