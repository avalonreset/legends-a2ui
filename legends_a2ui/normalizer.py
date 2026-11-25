"""Deterministic v0.8 / v0.9 / v0.9.1 / draft v1.0 -> canonical A2UI v1.0 normalizer."""
from __future__ import annotations

import copy
import json
from typing import Any

from legends_a2ui.parser import DEFAULT_MAX_BYTES, DEFAULT_MAX_DEPTH, parse_payload
from legends_a2ui.spec_registry import (
    BROKEN_V09_CATALOG_ID,
    CANONICAL_V08_CATALOG_ID,
    CANONICAL_V09_CATALOG_ID,
    CANONICAL_V1_CATALOG_ID,
    is_valid_uax31_id,
    sanitize_uax31_id,
    scan_for_secrets,
)
from legends_a2ui.validator import validate_payload

HEADING_PREFIX = {
    "h1": "# ",
    "h2": "## ",
    "h3": "### ",
    "h4": "#### ",
    "h5": "##### ",
}

_LEGACY_CATALOG_ALIASES = frozenset(
    {
        "",
        "basic",
        "standard",
        BROKEN_V09_CATALOG_ID,
        CANONICAL_V09_CATALOG_ID,
        CANONICAL_V08_CATALOG_ID,
    }
)

_V08_LITERAL_KEYS = ("literalString", "literalNumber", "literalBoolean", "literalArray")


def format_a2ui_messages(messages: list[dict[str, Any]], fmt: str = "json") -> str:
    """Format A2UI v1.0 messages as json, jsonl, or markdown-fence."""
    if fmt == "json":
        return json.dumps(messages, indent=2, allow_nan=False) + "\n"
    if fmt == "jsonl":
        return "\n".join(json.dumps(m, separators=(",", ":"), allow_nan=False) for m in messages) + "\n"
    if fmt == "markdown-fence":
        return "```a2ui\n" + json.dumps(messages, indent=2, allow_nan=False) + "\n```\n"
    raise ValueError(f"Unsupported output format: {fmt}")


def _convert_v08_typed_value(entry: dict[str, Any]) -> Any:
    if "valueString" in entry:
        return entry["valueString"]
    if "valueNumber" in entry:
        return entry["valueNumber"]
    if "valueBoolean" in entry:
        return entry["valueBoolean"]
    if "valueMap" in entry and isinstance(entry["valueMap"], list):
        return _convert_v08_contents(entry["valueMap"])
    if "valueArray" in entry and isinstance(entry["valueArray"], list):
        return [
            _convert_v08_typed_value(item) if isinstance(item, dict) else item
            for item in entry["valueArray"]
        ]
    return None


def _convert_v08_contents(contents: list[Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in contents:
        if isinstance(item, dict) and isinstance(item.get("key"), str):
            out[item["key"]] = _convert_v08_typed_value(item)
    return out


def _upgrade_dynamic_value(val: Any, changes: list[str]) -> Any:
    """Upgrade DynamicValue / DataBinding / FunctionCall strictly in dynamic positions."""
    if not isinstance(val, dict):
        if isinstance(val, list):
            return [_upgrade_dynamic_value(x, changes) for x in val]
        return val

    # v0.8 bound value wrappers
    for lit_key in _V08_LITERAL_KEYS:
        if lit_key in val:
            if "path" in val and isinstance(val["path"], str):
                changes.append(f"converted v0.8 bound {lit_key}+path to @path")
                return {"@path": val["path"]}
            changes.append(f"unwrapped v0.8 {lit_key}")
            return val[lit_key]

    if "@path" in val:
        return {"@path": val["@path"]}

    if set(val.keys()) == {"path"} and isinstance(val.get("path"), str):
        changes.append("upgraded DataBinding path -> @path")
        return {"@path": val["path"]}

    if "@call" in val or ("call" in val and isinstance(val.get("call"), str)):
        upgraded: dict[str, Any] = {}
        if "@call" in val:
            upgraded["@call"] = val["@call"]
        else:
            upgraded["@call"] = val["call"]
            changes.append("upgraded FunctionCall call -> @call")
        if "catalogId" in val:
            upgraded["catalogId"] = val["catalogId"]
        if isinstance(val.get("args"), dict):
            upgraded["args"] = {
                k: _upgrade_dynamic_value(v, changes) for k, v in val["args"].items()
            }
        return upgraded

    out_dict: dict[str, Any] = {}
    for k, v in val.items():
        new_k = k
        if isinstance(k, str) and k.startswith("@") and not k.startswith("@@"):
            new_k = f"@{k}"
            changes.append(f"escaped literal dynamic key '{k}' -> '{new_k}'")
        out_dict[new_k] = _upgrade_dynamic_value(v, changes)
    return out_dict


def _upgrade_action(action: Any, changes: list[str]) -> Any:
    if not isinstance(action, dict):
        return action
    # v0.8 action shape: {name, context?: [{key, value}]}
    if "name" in action and "event" not in action and "functionCall" not in action:
        event: dict[str, Any] = {"name": action["name"]}
        raw_ctx = action.get("context")
        if isinstance(raw_ctx, list):
            ctx_map: dict[str, Any] = {}
            for item in raw_ctx:
                if isinstance(item, dict) and isinstance(item.get("key"), str):
                    ctx_map[item["key"]] = _upgrade_dynamic_value(item.get("value"), changes)
            if ctx_map:
                event["context"] = ctx_map
        elif isinstance(raw_ctx, dict):
            event["context"] = {
                k: _upgrade_dynamic_value(v, changes) for k, v in raw_ctx.items()
            }
        changes.append("upgraded v0.8 action -> action.event")
        return {"event": event}

    if "event" in action and isinstance(action["event"], dict):
        ev = dict(action["event"])
        if "userMessage" in ev:
            ev["userMessage"] = _upgrade_dynamic_value(ev["userMessage"], changes)
        if isinstance(ev.get("context"), dict):
            ev["context"] = {
                k: _upgrade_dynamic_value(v, changes) for k, v in ev["context"].items()
            }
        return {"event": ev}

    if "functionCall" in action and isinstance(action["functionCall"], dict):
        return {"functionCall": _upgrade_dynamic_value(action["functionCall"], changes)}

    return action


def _upgrade_checks(raw_checks: Any, changes: list[str]) -> list[dict[str, Any]]:
    if not isinstance(raw_checks, list):
        return []
    upgraded: list[dict[str, Any]] = []
    for item in raw_checks:
        if not isinstance(item, dict):
            continue
        rule: dict[str, Any] = {}
        if "condition" in item:
            rule["condition"] = _upgrade_dynamic_value(item["condition"], changes)
        elif "call" in item or "@call" in item:
            # v0.9 CheckRule could embed call/args directly
            fn_obj = {k: v for k, v in item.items() if k != "message"}
            rule["condition"] = _upgrade_dynamic_value(fn_obj, changes)
            changes.append("wrapped v0.9 check rule into condition")
        if isinstance(item.get("message"), str):
            rule["message"] = item["message"]
        if "condition" in rule:
            upgraded.append(rule)
    return upgraded


def _normalize_component(raw_comp: dict[str, Any], changes: list[str]) -> dict[str, Any]:
    comp = copy.deepcopy(raw_comp)

    # Flatten v0.8 nested {"id": ..., "component": {"Text": {...}}}
    if isinstance(comp.get("component"), dict) and len(comp["component"]) == 1:
        comp_type, inner = next(iter(comp["component"].items()))
        flattened: dict[str, Any] = {"id": comp.get("id"), "component": comp_type}
        if "weight" in comp:
            flattened["weight"] = comp["weight"]
        if isinstance(inner, dict):
            flattened.update(inner)
        comp = flattened
        changes.append(f"flattened v0.8 component '{comp_type}'")

    ctype = comp.get("component")
    if ctype == "MultipleChoice":
        comp["component"] = "ChoicePicker"
        ctype = "ChoicePicker"
        changes.append("renamed v0.8 MultipleChoice -> ChoicePicker")

    # Bare mixin upgrades
    for bare, prefixed in (
        ("accessibility", "@accessibility"),
        ("checks", "@checks"),
        ("catalogId", "@catalogId"),
        ("metadata", "@metadata"),
    ):
        if bare in comp and prefixed not in comp:
            comp[prefixed] = comp.pop(bare)
            changes.append(f"upgraded component mixin {bare} -> {prefixed}")

    if "@accessibility" in comp and isinstance(comp["@accessibility"], dict):
        acc = dict(comp["@accessibility"])
        for k in ("label", "description", "hidden"):
            if k in acc:
                acc[k] = _upgrade_dynamic_value(acc[k], changes)
        comp["@accessibility"] = acc

    if "@checks" in comp:
        comp["@checks"] = _upgrade_checks(comp["@checks"], changes)

    # Property renames from v0.8
    if "usageHint" in comp and "variant" not in comp:
        comp["variant"] = comp.pop("usageHint")
        changes.append("renamed usageHint -> variant")
    if "distribution" in comp and "justify" not in comp:
        comp["justify"] = comp.pop("distribution")
        changes.append("renamed distribution -> justify")
    if "alignment" in comp and "align" not in comp:
        comp["align"] = comp.pop("alignment")
        changes.append("renamed alignment -> align")
    if "entryPointChild" in comp and "trigger" not in comp:
        comp["trigger"] = comp.pop("entryPointChild")
        changes.append("renamed entryPointChild -> trigger")
    if "contentChild" in comp and "content" not in comp:
        comp["content"] = comp.pop("contentChild")
        changes.append("renamed contentChild -> content")
    if "tabItems" in comp and "tabs" not in comp:
        comp["tabs"] = comp.pop("tabItems")
        changes.append("renamed tabItems -> tabs")
    if ctype == "Image" and "altText" in comp and "description" not in comp:
        comp["description"] = comp.pop("altText")
        changes.append("renamed Image.altText -> description")
    if ctype == "Image" and comp.get("fit") == "scale-down":
        comp["fit"] = "scaleDown"
        changes.append("renamed Image.fit scale-down -> scaleDown")
    if ctype == "List" and "listStyle" in comp:
        comp.pop("listStyle", None)
        changes.append("stripped removed v0.9 List.listStyle")
    if ctype == "ChoicePicker":
        if "selections" in comp and "value" not in comp:
            comp["value"] = comp.pop("selections")
            changes.append("renamed ChoicePicker.selections -> value")
        if comp.get("variant") in {"checkbox", "chips"}:
            legacy_display = comp.pop("variant")
            if "displayStyle" not in comp:
                comp["displayStyle"] = legacy_display
            changes.append(f"moved legacy ChoicePicker.variant '{legacy_display}' -> displayStyle")
        if "maxAllowedSelections" in comp:
            max_sel = comp.pop("maxAllowedSelections")
            if "variant" not in comp:
                comp["variant"] = "mutuallyExclusive" if max_sel == 1 else "multipleSelection"
            changes.append("converted maxAllowedSelections -> variant")
    if ctype == "Slider":
        if "minValue" in comp and "min" not in comp:
            comp["min"] = comp.pop("minValue")
            changes.append("renamed Slider.minValue -> min")
        if "maxValue" in comp and "max" not in comp:
            comp["max"] = comp.pop("maxValue")
            changes.append("renamed Slider.maxValue -> max")
    if ctype == "Button" and "primary" in comp:
        is_primary = bool(comp.pop("primary"))
        if "variant" not in comp:
            comp["variant"] = "primary" if is_primary else "default"
        changes.append("converted Button.primary -> variant")
    if ctype == "TextField":
        if "text" in comp and "value" not in comp:
            comp["value"] = comp.pop("text")
            changes.append("renamed TextField.text -> value")
        if "textFieldType" in comp and "variant" not in comp:
            tmap = {
                "shortText": "shortText",
                "longText": "longText",
                "number": "number",
                "obscured": "obscured",
                "date": "shortText",
            }
            comp["variant"] = tmap.get(str(comp.pop("textFieldType")), "shortText")
            changes.append("renamed TextField.textFieldType -> variant")
        if "validationRegexp" in comp:
            pattern = comp.pop("validationRegexp")
            if isinstance(pattern, str) and pattern:
                comp["_pendingValidationRegexp"] = pattern

    # Children upgrades (v0.8 explicitList/template -> v1.0 ChildList; keep ChildList.path UNPREFIXED!)
    if "children" in comp and isinstance(comp["children"], dict):
        ch = comp["children"]
        if isinstance(ch.get("explicitList"), list):
            comp["children"] = list(ch["explicitList"])
            changes.append("unwrapped v0.8 children.explicitList")
        elif isinstance(ch.get("template"), dict):
            tpl = ch["template"]
            comp["children"] = {
                "componentId": tpl.get("componentId", ""),
                "path": tpl.get("dataBinding") or tpl.get("path") or "/",
            }
            changes.append("converted v0.8 children.template -> ChildList template")
        elif "dataBinding" in ch and "componentId" in ch:
            comp["children"] = {
                "componentId": ch["componentId"],
                "path": ch["dataBinding"],
            }
            changes.append("renamed ChildList.dataBinding -> path")
        elif "@path" in ch and "componentId" in ch:
            # Repair mistakenly prefixed ChildList.@path back to unprefixed path
            comp["children"] = {
                "componentId": ch["componentId"],
                "path": ch["@path"],
            }
            changes.append("repaired ChildList.@path -> unprefixed path")

    # Upgrade dynamic properties
    for dprop in ("text", "url", "posterUrl", "description", "label", "value", "placeholder", "min", "max"):
        if dprop in comp:
            comp[dprop] = _upgrade_dynamic_value(comp[dprop], changes)

    if ctype == "Icon" and "name" in comp:
        if isinstance(comp["name"], dict) and "svgPath" in comp["name"]:
            comp["name"] = {"svgPath": _upgrade_dynamic_value(comp["name"]["svgPath"], changes)}
        else:
            comp["name"] = _upgrade_dynamic_value(comp["name"], changes)

    if ctype == "Tabs" and isinstance(comp.get("tabs"), list):
        new_tabs = []
        for tab in comp["tabs"]:
            if isinstance(tab, dict):
                tcopy = dict(tab)
                if "title" in tcopy:
                    tcopy["title"] = _upgrade_dynamic_value(tcopy["title"], changes)
                new_tabs.append(tcopy)
        comp["tabs"] = new_tabs

    if ctype == "ChoicePicker" and isinstance(comp.get("options"), list):
        new_opts = []
        for opt in comp["options"]:
            if isinstance(opt, dict):
                ocopy = dict(opt)
                if "label" in ocopy:
                    ocopy["label"] = _upgrade_dynamic_value(ocopy["label"], changes)
                new_opts.append(ocopy)
        comp["options"] = new_opts

    if ctype == "Button":
        if "action" in comp:
            comp["action"] = _upgrade_action(comp["action"], changes)
        if "variant" in comp and isinstance(comp["variant"], str):
            low = comp["variant"].lower()
            if low not in {"default", "primary", "borderless"}:
                comp["variant"] = "default"
                changes.append("coerced unknown Button.variant -> default")

    if ctype == "Text" and isinstance(comp.get("variant"), str):
        low = comp["variant"].lower()
        if low in HEADING_PREFIX:
            prefix = HEADING_PREFIX[low]
            comp["variant"] = "body"
            tval = comp.get("text")
            if isinstance(tval, str):
                if not tval.lstrip().startswith("#"):
                    comp["text"] = f"{prefix}{tval}"
            elif isinstance(tval, dict) and "@path" in tval:
                comp["text"] = {
                    "@call": "formatString",
                    "args": {"value": f"{prefix}${{{tval['@path']}}}"},
                }
            changes.append(f"upgraded Text.variant '{low}' -> Markdown heading + body")
        elif low not in {"body", "caption"}:
            comp["variant"] = "body"
            changes.append("coerced unknown Text.variant -> body")

    return comp


def _remap_component_ids(comp: dict[str, Any], id_map: dict[str, str]) -> dict[str, Any]:
    if not id_map:
        return comp
    out = copy.deepcopy(comp)
    if isinstance(out.get("id"), str) and out["id"] in id_map:
        out["id"] = id_map[out["id"]]
    for ref_key in ("child", "trigger", "content"):
        if isinstance(out.get(ref_key), str) and out[ref_key] in id_map:
            out[ref_key] = id_map[out[ref_key]]
    ch = out.get("children")
    if isinstance(ch, list):
        out["children"] = [id_map.get(c, c) if isinstance(c, str) else c for c in ch]
    elif isinstance(ch, dict) and isinstance(ch.get("componentId"), str):
        ch["componentId"] = id_map.get(ch["componentId"], ch["componentId"])
    if isinstance(out.get("tabs"), list):
        for tab in out["tabs"]:
            if isinstance(tab, dict) and isinstance(tab.get("child"), str):
                tab["child"] = id_map.get(tab["child"], tab["child"])
    return out


def normalize_payload(
    raw_text: str,
    *,
    extract_markdown: bool = False,
    target_version: str = "1.0",
    fmt: str = "json",
    default_surface_id: str = "main",
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> dict[str, Any]:
    """Upgrade v0.8/v0.9/v0.9.1/draft v1.0 payloads into strict canonical A2UI v1.0."""
    if target_version not in {"1.0", "v1.0"}:
        return {
            "ok": False,
            "changesApplied": [],
            "payload": None,
            "formatted": "",
            "validation": {
                "ok": False,
                "errors": [
                    {
                        "code": "UNSUPPORTED_TARGET_VERSION",
                        "blockIndex": 0,
                        "path": "$",
                        "message": f"Only target version '1.0' is supported (got {target_version!r}).",
                    }
                ],
                "warnings": [],
            },
        }

    parsed = parse_payload(
        raw_text,
        extract_markdown=extract_markdown,
        max_bytes=max_bytes,
        max_depth=max_depth,
    )
    if not parsed["ok"]:
        return {
            "ok": False,
            "changesApplied": [],
            "payload": None,
            "formatted": "",
            "validation": {"ok": False, "errors": parsed["errors"], "warnings": []},
        }

    all_messages: list[dict[str, Any]] = []
    for blk in parsed["blocks"]:
        all_messages.extend(blk["messages"])

    secret_findings = scan_for_secrets(all_messages)
    if secret_findings:
        return {
            "ok": False,
            "changesApplied": [],
            "payload": None,
            "formatted": "",
            "validation": {
                "ok": False,
                "errors": [
                    {
                        "code": "SECRET_LEAK",
                        "blockIndex": 0,
                        "path": f["path"],
                        "message": f["message"],
                    }
                    for f in secret_findings
                ],
                "warnings": [],
            },
        }

    changes: list[str] = []
    upgraded_msgs: list[dict[str, Any]] = []
    v08_roots: dict[str, str] = {}

    for msg in all_messages:
        if not isinstance(msg, dict):
            continue
        mcopy = copy.deepcopy(msg)

        if "beginRendering" in mcopy and isinstance(mcopy["beginRendering"], dict):
            br = mcopy["beginRendering"]
            sid = str(br.get("surfaceId") or default_surface_id)
            if isinstance(br.get("root"), str) and br["root"]:
                v08_roots[sid] = br["root"]
            cs: dict[str, Any] = {
                "surfaceId": sid,
                "catalogId": CANONICAL_V1_CATALOG_ID,
            }
            if "styles" in br:
                changes.append("stripped v0.8 beginRendering.styles")
            changes.append("upgraded v0.8 beginRendering -> createSurface")
            upgraded_msgs.append({"version": "1.0", "createSurface": cs})
            continue

        if "surfaceUpdate" in mcopy and isinstance(mcopy["surfaceUpdate"], dict):
            su = mcopy["surfaceUpdate"]
            sid = str(su.get("surfaceId") or default_surface_id)
            comps = [
                _normalize_component(c, changes)
                for c in su.get("components", [])
                if isinstance(c, dict)
            ]
            changes.append("upgraded v0.8 surfaceUpdate -> updateComponents")
            upgraded_msgs.append(
                {"version": "1.0", "updateComponents": {"surfaceId": sid, "components": comps}}
            )
            continue

        if "dataModelUpdate" in mcopy and isinstance(mcopy["dataModelUpdate"], dict):
            dmu = mcopy["dataModelUpdate"]
            sid = str(dmu.get("surfaceId") or default_surface_id)
            udm: dict[str, Any] = {"surfaceId": sid}
            if isinstance(dmu.get("path"), str) and dmu["path"]:
                udm["path"] = dmu["path"]
            contents = dmu.get("contents")
            if isinstance(contents, list):
                udm["value"] = _convert_v08_contents(contents)
            else:
                udm["value"] = dmu.get("value")
            changes.append("upgraded v0.8 dataModelUpdate -> updateDataModel")
            upgraded_msgs.append({"version": "1.0", "updateDataModel": udm})
            continue

        if "userAction" in mcopy and isinstance(mcopy["userAction"], dict):
            ua = mcopy["userAction"]
            act: dict[str, Any] = {
                "surfaceId": str(ua.get("surfaceId") or default_surface_id),
                "name": str(ua.get("name") or "action"),
                "sourceComponentId": str(ua.get("sourceComponentId") or "root"),
                "timestamp": str(ua.get("timestamp") or "2026-01-01T00:00:00Z"),
                "context": ua.get("context") if isinstance(ua.get("context"), dict) else {},
            }
            changes.append("upgraded v0.8 userAction -> action")
            upgraded_msgs.append({"version": "1.0", "action": act})
            continue

        if mcopy.get("version") != "1.0":
            changes.append(f"upgraded version {mcopy.get('version')!r} -> '1.0'")
        mcopy["version"] = "1.0"

        if "createSurface" in mcopy and isinstance(mcopy["createSurface"], dict):
            cs = dict(mcopy["createSurface"])
            cs.setdefault("surfaceId", default_surface_id)
            cat_id = cs.get("catalogId")
            if not isinstance(cat_id, str) or cat_id.strip() in _LEGACY_CATALOG_ALIASES:
                cs["catalogId"] = CANONICAL_V1_CATALOG_ID
                changes.append("set canonical v1.0 Basic Catalog catalogId")
            if "theme" in cs:
                cs.pop("theme", None)
                changes.append("stripped removed v1.0 createSurface.theme")
            if isinstance(cs.get("components"), list):
                cs["components"] = [
                    _normalize_component(c, changes)
                    for c in cs["components"]
                    if isinstance(c, dict)
                ]
            mcopy["createSurface"] = cs

        if "updateComponents" in mcopy and isinstance(mcopy["updateComponents"], dict):
            uc = dict(mcopy["updateComponents"])
            uc.setdefault("surfaceId", default_surface_id)
            if isinstance(uc.get("components"), list):
                uc["components"] = [
                    _normalize_component(c, changes)
                    for c in uc["components"]
                    if isinstance(c, dict)
                ]
            mcopy["updateComponents"] = uc

        if "updateDataModel" in mcopy and isinstance(mcopy["updateDataModel"], dict):
            udm = dict(mcopy["updateDataModel"])
            udm.setdefault("surfaceId", default_surface_id)
            if "value" not in udm:
                udm["value"] = None
                changes.append("added explicit null value to updateDataModel")
            mcopy["updateDataModel"] = udm

        upgraded_msgs.append(mcopy)

    # Ensure every surface has a leading createSurface
    created: set[str] = set()
    ensured_msgs: list[dict[str, Any]] = []
    for msg in upgraded_msgs:
        if "createSurface" in msg and isinstance(msg["createSurface"], dict):
            sid = msg["createSurface"]["surfaceId"]
            created.add(sid)
            ensured_msgs.append(msg)
            continue
        target_sid = None
        for key in ("updateComponents", "updateDataModel"):
            if key in msg and isinstance(msg[key], dict):
                target_sid = msg[key].get("surfaceId")
                break
        if isinstance(target_sid, str) and target_sid not in created:
            created.add(target_sid)
            ensured_msgs.append(
                {
                    "version": "1.0",
                    "createSurface": {
                        "surfaceId": target_sid,
                        "catalogId": CANONICAL_V1_CATALOG_ID,
                    },
                }
            )
            changes.append(f"synthesized createSurface for '{target_sid}'")
        ensured_msgs.append(msg)

    # Per-surface UAX #31 ID sanitization and v0.8 root -> "root" remapping
    surface_comp_lists: dict[str, list[list[dict[str, Any]]]] = {}
    for msg in ensured_msgs:
        if "createSurface" in msg and isinstance(msg["createSurface"].get("components"), list):
            sid = msg["createSurface"]["surfaceId"]
            surface_comp_lists.setdefault(sid, []).append(msg["createSurface"]["components"])
        if "updateComponents" in msg and isinstance(msg["updateComponents"].get("components"), list):
            sid = msg["updateComponents"]["surfaceId"]
            surface_comp_lists.setdefault(sid, []).append(msg["updateComponents"]["components"])

    for sid, comp_lists in surface_comp_lists.items():
        raw_ids: list[str] = []
        for clist in comp_lists:
            for c in clist:
                if isinstance(c.get("id"), str):
                    raw_ids.append(c["id"])
        # Deduplicate per surface so incremental updateComponents replacements
        # map deterministically to the same UAX #31 identifier.
        all_ids = list(dict.fromkeys(raw_ids))
        all_ids_set = set(all_ids)

        id_map: dict[str, str] = {}
        used: set[str] = set()

        # Remap v0.8 custom root ID -> "root" if "root" is not already present
        v08_root = v08_roots.get(sid)
        if v08_root and v08_root != "root" and "root" not in all_ids_set and v08_root in all_ids_set:
            id_map[v08_root] = "root"
            used.add("root")
            changes.append(f"remapped v0.8 root '{v08_root}' -> 'root'")

        for raw_id in all_ids:
            if raw_id in id_map:
                continue
            if is_valid_uax31_id(raw_id) and raw_id not in used:
                used.add(raw_id)
                continue
            cand = sanitize_uax31_id(raw_id)
            unique = cand
            suffix = 2
            while unique in used or (unique in all_ids_set and unique != raw_id):
                unique = f"{cand}_{suffix}"
                suffix += 1
            used.add(unique)
            if unique != raw_id:
                id_map[raw_id] = unique
                changes.append(f"sanitized UAX #31 id '{raw_id}' -> '{unique}'")

        if id_map:
            for clist in comp_lists:
                for idx, comp in enumerate(clist):
                    clist[idx] = _remap_component_ids(comp, id_map)
            for msg in ensured_msgs:
                act = msg.get("action")
                if (
                    isinstance(act, dict)
                    and act.get("surfaceId") == sid
                    and isinstance(act.get("sourceComponentId"), str)
                    and act["sourceComponentId"] in id_map
                ):
                    old_src = act["sourceComponentId"]
                    act["sourceComponentId"] = id_map[old_src]
                    changes.append(f"remapped action.sourceComponentId '{old_src}' -> '{act['sourceComponentId']}'")

        # Synthesize missing TextField.value and deferred validationRegexp checks after final UAX #31 ID remapping
        for clist in comp_lists:
            for comp in clist:
                if comp.get("component") == "TextField":
                    if "value" not in comp:
                        final_id = str(comp.get("id") or "field")
                        comp["value"] = {"@path": f"/{final_id}"}
                        changes.append(f"synthesized TextField.value binding '/{final_id}'")
                    pending_pat = comp.pop("_pendingValidationRegexp", None)
                    if isinstance(pending_pat, str) and pending_pat:
                        checks_list = comp.setdefault("@checks", [])
                        checks_list.append(
                            {
                                "condition": {
                                    "@call": "regex",
                                    "args": {
                                        "value": copy.deepcopy(comp["value"]),
                                        "pattern": pending_pat,
                                    },
                                },
                                "message": "Invalid format.",
                            }
                        )
                        changes.append("converted TextField.validationRegexp -> @checks regex")

    formatted = format_a2ui_messages(ensured_msgs, fmt)
    strict_check = validate_payload(
        json.dumps(ensured_msgs, allow_nan=False),
        extract_markdown=False,
        version="1.0",
        strict=True,
    )

    dedup_changes = list(dict.fromkeys(changes))
    return {
        "ok": bool(strict_check["ok"]),
        "changesApplied": dedup_changes,
        "payload": ensured_msgs if strict_check["ok"] else None,
        "formatted": formatted if strict_check["ok"] else "",
        "validation": strict_check,
    }
