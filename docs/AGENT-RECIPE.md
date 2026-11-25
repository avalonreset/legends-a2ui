# Agent Recipe: `legends-a2ui`

Use `legends-a2ui` to validate, normalize, compose, project, preview, and scaffold A2UI v1.0 interactive surfaces offline.

## Quick Commands

1. Verify environment and vendored spec integrity:
   `legends-a2ui doctor --json`
2. Validate A2UI payloads or Markdown fenced blocks:
   `legends-a2ui validate --input surface.json --strict --json`
   `legends-a2ui validate --input reply.md --extract-markdown --strict --json`
3. Upgrade legacy v0.8 / v0.9 payloads to canonical v1.0:
   `legends-a2ui normalize --input legacy.json --format json`
4. Compose a validated operator surface:
   `legends-a2ui compose --template ship-call --vars '{"title":"Ship v0.1.0","target":"main"}' --format markdown-fence`
5. Project structured CLI JSON into an interactive A2UI v1.0 surface:
   `legends-a2ui project --input report.json --preset auto --format markdown-fence`
6. Preview offline as a static HTML5 file (two-step preview -> apply):
   `legends-a2ui preview --input surface.json --output preview.html --json`
   `legends-a2ui preview --input surface.json --output preview.html --apply --confirm-plan <planSha256> --json`
7. Scaffold a React, WebCore, or Lit integration kit (two-step preview -> apply):
   `legends-a2ui scaffold --target react --output ./src/a2ui --json`
8. Inspect Basic Catalog components and vendored docs offline:
   `legends-a2ui catalog --component TextField --version 1.0 --json`
   `legends-a2ui docs-lookup "Checkable @checks" --version 1.0 --live-locations --json`
