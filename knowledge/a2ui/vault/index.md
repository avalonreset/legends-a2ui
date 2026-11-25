# A2UI v1.0 Knowledge Pack

Offline reference pack for `legends-a2ui` (`v0.1.0`), pinned to `a2ui-project/a2ui` commit `92c0ed6eccb499fe22fba49cb8185b058442c56a`.

## Core Rules

- Canonical v1.0 messages use `"version": "1.0"`, `@path` for DataBinding, `@call` for FunctionCall, and `@accessibility` / `@checks` / `@catalogId` / `@metadata` mixins.
- `ChildList.path` and `updateDataModel.path` stay unprefixed (`path`, not `@path`).
- Component IDs must follow Unicode UAX #31 syntax (no hyphens or leading digits).
- `Text.variant` supports only `body` and `caption` in v1.0; headings use Markdown `#`..`#####` in `Text.text`.
- `TextField.value` is required in v1.0.
