# legends-a2ui (`v0.1.0`)

Offline-first A2UI v1.0, v0.9.1, v0.9, and v0.8 toolkit for coding agents and CTO Legends operators. Zero mandatory third-party Python pip dependencies (Python 3.11+ standard library only).

## Subcommands

- `legends-a2ui doctor [--project <dir>] [--live] [--json]`
- `legends-a2ui validate --input <path|-> [--extract-markdown] [--version auto|1.0|0.9.1|0.9|0.8] [--strict] [--json]`
- `legends-a2ui normalize --input <path|-> [--format json|jsonl|markdown-fence] [--output <path> --apply --confirm-plan <sha>] [--json]`
- `legends-a2ui compose --list | --template <name> [--vars <json>] [--format json|jsonl|markdown-fence] [--json]`
- `legends-a2ui project --input <path|-> [--preset auto|plan-approval|health-deck|data-briefing] [--format json|jsonl|markdown-fence] [--json]`
- `legends-a2ui preview --input <path|-> --output <file.html> [--theme precision-noir|light|auto] [--apply --confirm-plan <sha>] [--json]`
- `legends-a2ui scaffold --target react|web-core|lit --output <dir> [--theme precision-noir|neutral] [--apply --confirm-plan <sha>] [--json]`
- `legends-a2ui catalog [--component <name> | --function <name> | --list] [--version 1.0|0.9.1|0.9|0.8] [--json]`
- `legends-a2ui docs-lookup <query> [--version all|1.0|0.9.1|0.9|0.8] [--live-locations] [--json]`
- `legends-a2ui knowledge-pack [--check] [--json]`
- `legends-a2ui resources [--json]`

## Documentation

- [Agent Recipe](docs/AGENT-RECIPE.md)
- [Capabilities](CAPABILITIES.md)
- [Wiki Index](wiki/index.md)
- [Pinned Upstream Sources](references/sources.md)
- [Empire Knowledge Pack](docs/EMPIRE.md)
- [Release Readiness](docs/RELEASE-READINESS.md)
- [Third-Party Notices](THIRD_PARTY_NOTICES.md)
