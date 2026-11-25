# A2UI v1.0 Basic Catalog Reference

Canonical Catalog URI: `https://a2ui.org/specification/v1_0/catalogs/basic/catalog.json`

All 18 components and 14 built-in functions below are verified directly against `vendor/a2ui-spec/catalogs/basic/v1/catalog.json` (`a2ui-project/a2ui` commit `92c0ed6eccb499fe22fba49cb8185b058442c56a`). Query any component or function offline at any time:

```sh
legends-a2ui catalog --list --version 1.0
legends-a2ui catalog --component TextField --version 1.0 --json
legends-a2ui catalog --function formatCurrency --version 1.0 --json
```

## 1. Universal Component Envelope Properties

Every v1.0 component object carries:
- `id` (required string, UAX #31 identifier; surface root must be `"root"`).
- `component` (required string discriminator; `"Surface"` is reserved and forbidden in `components`).
- `weight` (optional number; valid ONLY when the component is a direct child of `Row` or `Column`).
- `@catalogId` (optional string URI overriding the surface default catalog for a single component).
- `@accessibility` (optional object with `DynamicString` `label`, `description`, or `DynamicBoolean` `hidden`).
- `@metadata` (optional JSON object for non-visual hints).
- `@checks` (optional list of `CheckRule` objects; valid ONLY on the 6 `Checkable` components).

## 2. All 18 Basic Catalog Components

### Display and Media (5)

| Component | Required Props | Optional Props and Variants | Notes |
| :--- | :--- | :--- | :--- |
| **`Text`** | `component`, `text` (`DynamicString`) | `variant`: `"body"` (default), `"caption"`; `weight` | Supports Markdown in `text`. Use `#`..`#####` with `"variant": "body"` for headings (`h1`..`h5` removed in v1.0). |
| **`Image`** | `component`, `url` (`DynamicString`) | `description` (`DynamicString`), `fit`: `"fill"` (default), `"contain"`, `"cover"`, `"none"`, `"scaleDown"`; `variant`: `"mediumFeature"` (default), `"icon"`, `"avatar"`, `"smallFeature"`, `"largeFeature"`, `"header"`; `weight` | `url` must pass media URL allowlist (`http:`, `https:`, `data:image/*`, or single-slash `/...`). |
| **`Icon`** | `component`, `name` | `weight` | `name` accepts any of the 60 standard Material-style icon names (`accountCircle`, `add`, `arrowBack`, `check`, `close`, `error`, `info`, `lock`, `refresh`, `search`, `settings`, `warning`, etc.) or custom SVG path object. |
| **`Video`** | `component`, `url` (`DynamicString`) | `posterUrl` (`DynamicString`, added in v1.0); `weight` | Both `url` and `posterUrl` must pass the media URL protocol allowlist. |
| **`AudioPlayer`** | `component`, `url` (`DynamicString`) | `description` (`DynamicString`); `weight` | `url` must pass the media URL protocol allowlist. |

### Layout and Containers (7)

| Component | Required Props | Optional Props and Variants | Notes |
| :--- | :--- | :--- | :--- |
| **`Row`** | `component`, `children` (`ChildList`) | `justify`: `"start"` (default), `"center"`, `"end"`, `"spaceAround"`, `"spaceBetween"`, `"spaceEvenly"`, `"stretch"`; `align`: `"stretch"` (default), `"start"`, `"center"`, `"end"`; `weight` | Direct children may declare numeric `weight`. |
| **`Column`** | `component`, `children` (`ChildList`) | `justify`: `"start"` (default), `"center"`, `"end"`, `"spaceBetween"`, `"spaceAround"`, `"spaceEvenly"`, `"stretch"`; `align`: `"stretch"` (default), `"start"`, `"center"`, `"end"`; `weight` | Direct children may declare numeric `weight`. |
| **`List`** | `component`, `children` (`ChildList`) | `direction`: `"vertical"` (default), `"horizontal"`; `align`: `"stretch"` (default), `"start"`, `"center"`, `"end"`; `weight` | Ideal for dynamic templates `{"componentId": "row_tpl", "path": "/items"}`. |
| **`Card`** | `component`, `child` (`Child`) | `weight` | Wraps a single child component ID. Common `id: "root"` container. |
| **`Tabs`** | `component`, `tabs` (`[{title, child}]`) | `weight` | Each tab item requires `title` (`DynamicString`) and `child` (component ID string). |
| **`Modal`** | `component`, `trigger` (`Child`), `content` (`Child`) | `weight` | `trigger` opens the overlay; `content` renders inside the dialog. |
| **`Divider`** | `component` | `axis`: `"horizontal"` (default), `"vertical"`; `weight` | Visual separator line. |

### Interactive and `Checkable` Controls (6)

All 6 components below implement the `Checkable` mixin and may declare `@checks`:

| Component | Required Props | Optional Props and Variants | Notes |
| :--- | :--- | :--- | :--- |
| **`Button`** | `component`, `child` (`Child`), `action` (`Action`) | `variant`: `"default"` (default), `"primary"`, `"borderless"`; `@checks`; `weight` | `child` is typically a `Text` or `Row` component ID. `action` has exactly one of `event` or `functionCall`. |
| **`TextField`** | `component`, `label` (`DynamicString`), `value` (`DynamicString`) | `placeholder` (`DynamicString`, added in v1.0); `variant`: `"shortText"` (default), `"longText"`, `"number"`, `"obscured"`; `@checks`; `weight` | **`value` is required in v1.0.** Bind to dataModel via `{"@path": "/field"}`. |
| **`CheckBox`** | `component`, `label` (`DynamicString`), `value` (`DynamicBoolean`) | `@checks`; `weight` | Two-way boolean binding via `{"@path": "/confirmed"}`. |
| **`ChoicePicker`** | `component`, `options` (`[{label, value}]`), `value` (`DynamicStringList`) | `label` (`DynamicString`); `variant`: `"mutuallyExclusive"` (default), `"multipleSelection"`; `displayStyle`: `"checkbox"` (default), `"chips"`; `filterable` (`boolean`, default `false`); `@checks`; `weight` | Replaces v0.8 `MultipleChoice`. `value` binds to a string array (`["canary"]`). |
| **`Slider`** | `component`, `value` (`DynamicNumber`), `max` (`number`) | `label` (`DynamicString`); `min` (`number`, default `0`); `steps` (`integer`, added in v1.0); `@checks`; `weight` | Replaces v0.8 `minValue` / `maxValue`. |
| **`DateTimeInput`** | `component`, `value` (`DynamicString`) | `enableDate` (`boolean`, default `false`); `enableTime` (`boolean`, default `false`); `min`; `max`; `label` (`DynamicString`); `@checks`; `weight` | Uses ISO 8601 date/time strings in `value`. |

## 3. `Checkable` `@checks` Rules

Each entry in `@checks` is a `CheckRule` object:

```json
{
  "id": "email_field",
  "component": "TextField",
  "label": "Contact Email",
  "value": { "@path": "/form/email" },
  "variant": "shortText",
  "@checks": [
    {
      "condition": {
        "@call": "email",
        "args": { "value": { "@path": "/form/email" } }
      },
      "message": "Provide a valid email address."
    }
  ]
}
```

Rules enforced by `legends-a2ui validate`:
- Declaring `@checks` on any non-`Checkable` component (such as `Text`, `Card`, `Column`) fails with `NON_CHECKABLE_COMPONENT`.
- Every `CheckRule` must include `condition` as a `DataBinding` (`@path`) or `FunctionCall` (`@call`).
- Bare `checks` (without `@`) fails under `--strict` (`TRANSITIONAL_BARE_MIXIN`).

## 4. All 14 Built-In Basic Catalog Functions

| Function | Return Type | Required Args | Optional Args | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `required` | `validationResult` | `value` | none | Non-empty validation check |
| `regex` | `validationResult` | `value`, `pattern` | none | Portable regex dialect; max 256 chars; ReDoS-checked |
| `length` | `validationResult` | `value` | `min`, `max` | String or array length bounds |
| `numeric` | `validationResult` | `value` | `min`, `max` | Numeric range validation |
| `email` | `validationResult` | `value` | none | Email syntax validation |
| `formatString` | `string` | `value` | none | Interpolates `${/pointer}` expressions inside `value` |
| `formatNumber` | `string` | `value` | `decimals`, `grouping` | Locale-formatted number output |
| `formatCurrency` | `string` | `value`, `currency` | `decimals`, `grouping` | ISO currency formatting |
| `formatDate` | `string` | `value`, `format` | none | Date/time formatting |
| `pluralize` | `string` | `value`, `other` | `zero`, `one`, `two`, `few`, `many` | CLDR pluralization |
| `openUrl` | `void` | `url` | none | `requiresUserActivation: true`; allowlists `https:`, `http:`, `mailto:` only |
| `and` | `boolean` | `values` | none | Logical conjunction |
| `or` | `boolean` | `values` | none | Logical disjunction |
| `not` | `boolean` | `value` | none | Logical negation |

System function: `{"@call": "@index", "args": {"offset": 0}}` is also recognized inside dynamic `ChildList` templates.
