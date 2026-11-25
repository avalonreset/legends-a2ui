# A2UI Surface Receipt Template

Use this receipt template to record validated A2UI surfaces, static HTML previews, or host scaffold plans inside an authorized workspace or Empire vault.

- **Date (UTC):** `YYYY-MM-DDTHH:MM:SSZ`
- **Surface ID:** `<surfaceId>`
- **Protocol Version:** `1.0`
- **Catalog URI:** `https://a2ui.org/specification/v1_0/catalogs/basic/catalog.json`
- **Source Command:** `compose | project | normalize | validate | preview | scaffold`
- **Template / Preset / Target:** `<name>`
- **Strict Validation (`legends-a2ui validate --strict`):** `PASS` (`0 errors`, `0 warnings`)
- **Write Plan SHA-256 (`planSha256`, if applied):** `<sha256 or stdout-only>`
- **Operator Action Received (if applicable):** `[A2UI Action: <name>] {...}`
- **Security Checks:** Media URLs allowlisted, `openUrl` allowlisted, UAX #31 IDs verified, zero secrets detected
- **Notes:**
