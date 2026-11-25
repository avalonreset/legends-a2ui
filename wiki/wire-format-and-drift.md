# Wire Format and Version Drift (`v0.8` vs `v0.9` / `v0.9.1` vs `v1.0`)

Verified against vendored `a2ui-project/a2ui` schemas at commit `92c0ed6eccb499fe22fba49cb8185b058442c56a` (`vendor/a2ui-spec/versions.json`, `v1_0/json/*.json`, `v0_9_1/json/*.json`, `v0_9/json/*.json`, `v0_8/json/*.json`).

Upstream lifecycle (`versions.json`): `v1.0` is **current**, `v0.9.1` and `v0.9` are **previous**, and `v0.8` is **deprecated**. There is **no `v0.10`** release upstream; the specification moved directly from `v0.9.1` to `v1.0`.

## 1. Protocol Envelope and Surface Lifecycle Matrix

| Dimension | `v0.8` (Deprecated) | `v0.9` / `v0.9.1` (Previous) | `v1.0` (Current) |
| :--- | :--- | :--- | :--- |
| **`version` field** | Omitted on wire (detected by envelope keys) | `v0.9`: `"v0.9"`; `v0.9.1`: `"v0.9"` or `"v0.9.1"` | `"1.0"` (no `v` prefix) |
| **MIME type** | `application/json+a2ui` | `v0.9`: `application/json+a2ui`; `v0.9.1`: `application/a2ui+json` | `application/a2ui+json` |
| **Schema filenames** | `server_to_client.json` / `client_to_server.json` | `server_to_client.json` / `client_to_server.json` | `agent_to_renderer.json` / `renderer_to_agent.json` |
| **Agent -> Renderer messages** | `beginRendering`, `surfaceUpdate`, `dataModelUpdate`, `deleteSurface` | `createSurface`, `updateComponents`, `updateDataModel`, `deleteSurface` | `createSurface`, `updateComponents`, `updateDataModel`, `deleteSurface`, `callRendererFunction`, `agentFunctionResponse` |
| **Renderer -> Agent messages** | `userAction`, `error` | `action`, `error` | `action` (`+userMessage`, `+metadata`), `callAgentFunction`, `rendererFunctionResponse`, `error` (`+functionCallId`) |
| **Canonical Basic `catalogId`** | `https://a2ui.org/specification/v0_8/standard_catalog_definition.json` | `https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json` | `https://a2ui.org/specification/v1_0/catalogs/basic/catalog.json` |
| **Inline surface creation** | Separate `beginRendering` + `surfaceUpdate` + `dataModelUpdate` | Separate `createSurface` + `updateComponents` + `updateDataModel` | Single `createSurface` can inline `components`, `dataModel`, `metadata`, `sendDataModel` |
| **`theme` / `styles` on surface create** | `beginRendering.styles` | `createSurface.theme` | **Removed** (strict schema rejects `theme`) |
| **`updateDataModel` payload** | `contents` typed adjacency array (`valueString`, `valueNumber`, `valueBoolean`, `valueMap`, `valueArray`) | `value` optional JSON value | `value` **required**; set `"value": null` to delete a key |
| **Root component rule** | `beginRendering.root` names any component ID | Exactly one component with `id: "root"` | Implicit `Surface` owns `"child": "root"`; `"Surface"` is reserved and cannot appear in `components` |

## 2. Component Shape, Mixins, Bindings, and Functions Matrix

| Dimension | `v0.8` | `v0.9` / `v0.9.1` | `v1.0` (Strict Canonical) |
| :--- | :--- | :--- | :--- |
| **Component shape** | Nested object: `{"id":"t1","component":{"Text":{"text":{"literalString":"Hi"}}}}` | Flat discriminator: `{"id":"t1","component":"Text","text":"Hi"}` | Flat discriminator plus `@`-prefixed mixins |
| **Component envelope mixins** | None | Bare `accessibility`, `checks` | Reserved `@catalogId`, `@accessibility`, `@metadata`, `@checks` (`id`, `component`, `weight` stay unprefixed) |
| **Data binding (`DataBinding`)** | `{"path":"/x"}` or `{"literalString":"..."}` / `literalNumber` / `literalBoolean` / `literalArray` | `{"path":"/x"}` or native JSON literal | `{"@path":"/x"}` (`additionalProperties: false`) or native JSON literal |
| **Function calls (`FunctionCall`)** | Not supported | `{"call":"formatString","args":{...}}` | `{"@call":"formatString","catalogId":"...","args":{...}}` (plus system `@index`) |
| **Single-`@` escape rule** | N/A | N/A | Unrecognized single-`@` key in dynamic objects is rejected (`INVALID_RESERVED_KEY`); literal `@` keys must escape as `"@@key"` |
| **Dynamic `ChildList` template** | `children: {"template":{"dataBinding":"/items","componentId":"tpl"}}` | `children: {"componentId":"tpl","path":"/items"}` | `children: ["id1","id2"]` OR `{"componentId":"tpl","path":"/items"}` (**`path` stays unprefixed!**) |
| **`updateDataModel.path`** | `dataModelUpdate.path` (unprefixed) | `updateDataModel.path` (unprefixed) | `updateDataModel.path` (**stays unprefixed!**) |
| **Action (`Button.action`)** | `{name, context: [{key, value}]}` | `{event: {name, context}}` or `{functionCall}` | `{event: {name, userMessage?, context?}}` or `{functionCall: {"@call": ...}}` |
| **Component IDs** | Free string | Free string | **UAX #31** (`^[\p{XID_Start}_][\p{XID_Continue}]*$`) |

## 3. High-Frequency Migration Traps

### Trap A: Blindly replacing `"path"` with `"@path"` everywhere

In v1.0, `@path` applies **only** inside `DynamicValue` positions (`Text.text`, `TextField.value`, `CheckRule.condition`, `action.event.context`, function `args`, etc.). Two protocol locations MUST keep `path` unprefixed:

1. `ChildList` dynamic templates:
   ```json
   {
     "id": "items_list",
     "component": "List",
     "children": { "componentId": "item_row", "path": "/items" }
   }
   ```
2. `updateDataModel` envelope target pointers:
   ```json
   {
     "version": "1.0",
     "updateDataModel": {
       "surfaceId": "main",
       "path": "/form/name",
       "value": "Ada"
     }
   }
   ```

`legends-a2ui normalize` is context-aware: it upgrades `DataBinding` `{"path": ...}` -> `{"@path": ...}` only in dynamic value slots and actively repairs mistakenly prefixed `ChildList.@path` back to `ChildList.path`.

### Trap B: `Text.variant` Heading Removal (`h1`..`h5`)

`v0.8` used `Text.usageHint` (`h1`..`h5`, `caption`, `body`) and `v0.9` allowed `Text.variant` values `h1`..`h5`. In **v1.0**, `Text.variant` allows ONLY `"body"` or `"caption"`.

Headings MUST use Markdown syntax in `Text.text` with `"variant": "body"`:
- Literal string `"text": "Release Check", "variant": "h2"` -> `"text": "## Release Check", "variant": "body"`.
- Data-bound string `"text": {"@path": "/heading"}, "variant": "h2"` -> `"text": {"@call": "formatString", "args": {"value": "## ${/heading}"}}, "variant": "body"`.

### Trap C: `TextField.value` Required in `v1.0`

In `v0.9`, `TextField` required only `component` and `label`. In `v1.0`, `TextField` requires **`component`, `label`, AND `value`** (`DynamicString`). Omitting `value` fails strict v1.0 validation; `legends-a2ui normalize` synthesizes `{"@path": "/<sanitized_id>"}` when absent.

### Trap D: Broken `v0_9/basic_catalog.json` 404 URI

Older draft snippets and integrations reference:
- **BROKEN (HTTP 404):** `https://a2ui.org/specification/v0_9/basic_catalog.json`

Always use the canonical live URIs verified against `a2ui.org`:
- **v1.0:** `https://a2ui.org/specification/v1_0/catalogs/basic/catalog.json`
- **v0.9 / v0.9.1:** `https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json`
- **v0.8:** `https://a2ui.org/specification/v0_8/standard_catalog_definition.json`

`legends-a2ui validate` emits `BROKEN_CATALOG_URI` on the 404 URL, `legends-a2ui doctor --project <dir>` scans source files for it, and `legends-a2ui normalize` replaces it with the canonical v1.0 URI.

### Trap E: Non-UAX #31 Component IDs

Strict v1.0 requires every component ID to conform to Unicode UAX #31 (`XID_Start` or `_`, followed by zero or more `XID_Continue` characters). Hyphens (`submit-btn`), spaces, dots, and leading digits (`1st_card`) fail strict validation (`INVALID_UAX31_ID`). `legends-a2ui normalize` deterministically rewrites invalid IDs (for example `submit-btn` -> `submit_btn`, `1st-card` -> `c_1st_card`, with `_2`, `_3` collision suffixes) and updates every `child`, `children`, `children.componentId`, `trigger`, `content`, and `tabs[].child` reference.

## 4. Automated Upgrade Workflow

```sh
# 1. Inspect legacy payload warnings/errors offline
legends-a2ui validate --input legacy.json --version auto --json

# 2. Deterministically upgrade to strict v1.0 (stdout)
legends-a2ui normalize --input legacy.json --target 1.0 --format json

# 3. Preview write to disk, then apply with planSha256 confirmation
legends-a2ui normalize --input legacy.json --output upgraded.json --json
legends-a2ui normalize --input legacy.json --output upgraded.json --apply --confirm-plan <planSha256> --json
```
