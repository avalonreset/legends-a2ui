# Security

Do not include credentials, live tokens, private host inventories, or proprietary payloads in public issues. Report suspected vulnerabilities privately through the repository's GitHub security reporting feature when available; otherwise contact the maintainer through a private channel.

## Supported versions

| Version | Supported |
|---|---|
| `0.1.0` | Yes |
| `< 0.1.0` | No |

## Response timeline

- Initial acknowledgment target: within 72 hours of a private report.
- Triage and remediation plan target: within 7 days for confirmed security issues in the supported `0.1.x` release line.

## Execution boundaries

`legends-a2ui` is an offline-first A2UI validation, normalization, composition, projection, static HTML preview, and renderer scaffolding toolkit using Python 3.11+ standard library modules only.

- Default commands (`doctor`, `validate`, `normalize`, `compose`, `project`, `preview`, `scaffold`, `catalog`, `docs-lookup`, `knowledge-pack`, `resources`) make zero network requests and spawn zero background servers or browsers.
- Optional live freshness checks (`doctor --live`) query only pinned HTTPS allowlist hosts (`registry.npmjs.org`, `pypi.org`, `api.github.com`, `a2ui.org`) with private/loopback/link-local IP refusal.
- All file-writing commands (`--output`) run in preview mode first and require explicit `--apply --confirm-plan <sha256>` (and `--overwrite` when updating existing targets).
- `validate`, `normalize`, and `project` enforce media URL and `openUrl` protocol allowlists and fail closed on detected secret tokens.
