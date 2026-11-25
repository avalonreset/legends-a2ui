"""Offline A2UI protocol, Basic Catalog, graph, URL safety, and secret validator."""
from __future__ import annotations

import re
from typing import Any

from legends_a2ui.parser import DEFAULT_MAX_BYTES, DEFAULT_MAX_DEPTH, parse_payload
from legends_a2ui.spec_registry import (
    BROKEN_V09_CATALOG_ID,
    is_valid_uax31_id,
    load_catalog_spec,
    scan_for_secrets,
    validate_media_url,
    validate_open_url,
)

DEFAULT_MAX_COMPONENTS = 500

V1_ENVELOPE_KEYS = frozenset(
    {
        "createSurface",
        "updateComponents",
        "updateDataModel",
        "deleteSurface",
        "callRendererFunction",
        "agentFunctionResponse",
        "action",
        "callAgentFunction",
        "rendererFunctionResponse",
        "error",
    }
)

V09_ENVELOPE_KEYS = frozenset(
    {
        "createSurface",
        "updateComponents",
        "updateDataModel",
        "deleteSurface",
        "action",
        "error",
    }
)

V08_ENVELOPE_KEYS = frozenset(
    {
        "beginRendering",
        "surfaceUpdate",
        "dataModelUpdate",
        "deleteSurface",
        "userAction",
        "error",
    }
)

V1_CREATE_SURFACE_KEYS = frozenset(
    {"surfaceId", "catalogId", "sendDataModel", "components", "dataModel", "metadata"}
)
V09_CREATE_SURFACE_KEYS = frozenset(
    {"surfaceId", "catalogId", "theme", "sendDataModel"}
)

V1_COMPONENT_ENVELOPE_KEYS = frozenset(
    {"id", "component", "@catalogId", "@accessibility", "@metadata", "@checks", "weight"}
)
TRANSITIONAL_MIXIN_KEYS = frozenset({"accessibility", "checks", "catalogId", "metadata"})

_SINGLE_AT_KEY_RE = re.compile(r"^@([^@]|$)")
_REDOS_NESTED_QUANTIFIER_RE = re.compile(
    r"\([^)]*[+*][^)]*\)[+*]|\([^)]*\|[^)]*\)[+*]{1,}|\(\?[<=!]"
)
_MEDIA_URL_PROPS: dict[str, tuple[str, ...]] = {
    "Image": ("url",),
    "Video": ("url", "posterUrl"),
    "AudioPlayer": ("url",),
}
_DYNAMIC_VALUE_PROPS = frozenset(
    {
        "text",
        "url",
        "posterUrl",
        "description",
        "label",
        "value",
        "placeholder",
        "min",
        "max",
        "title",
        "userMessage",
    }
)


def _detect_message_version(msg: dict[str, Any]) -> str:
    raw_ver = msg.get("version")
    if isinstance(raw_ver, str):
        cleaned = raw_ver.strip().lower()
        if cleaned in {"1.0", "v1.0", "1"}:
            return "1.0"
        if cleaned in {"0.9.1", "v0.9.1"}:
            return "0.9.1"
        if cleaned in {"0.9", "v0.9"}:
            return "0.9"
        if cleaned in {"0.8", "v0.8"}:
            return "0.8"
    if any(k in msg for k in ("beginRendering", "surfaceUpdate", "dataModelUpdate", "userAction")):
        return "0.8"
    return "1.0"


def _resolve_json_pointer(data: Any, pointer: str) -> tuple[bool, Any]:
    """Resolve an RFC 6901 JSON Pointer inside a surface dataModel."""
    if not isinstance(pointer, str):
        return False, None
    if pointer in {"", "/"}:
        return True, data
    if not pointer.startswith("/"):
        return False, None
    cur = data
    for raw_seg in pointer.lstrip("/").split("/"):
        seg = raw_seg.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        elif isinstance(cur, list):
            try:
                idx = int(seg)
                cur = cur[idx]
            except (ValueError, IndexError):
                return False, None
        else:
            return False, None
    return True, cur


def _resolve_pointer_with_context(
    data_model: dict[str, Any], pointer: str, item_ctx: Any = None
) -> tuple[bool, Any]:
    """Resolve absolute pointers against data_model or relative pointers against item_ctx."""
    if not isinstance(pointer, str) or not pointer:
        return False, None
    if pointer.startswith("/"):
        return _resolve_json_pointer(data_model, pointer)
    if item_ctx is None:
        return False, None
    cur = item_ctx
    for raw_seg in pointer.split("/"):
        seg = raw_seg.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        elif isinstance(cur, list):
            try:
                idx = int(seg)
                cur = cur[idx]
            except (ValueError, IndexError):
                return False, None
        else:
            return False, None
    return True, cur


_FORMAT_EXPR_RE = re.compile(r"\$\{([^}]+)\}")


def _validate_url_function_call(
    fn_obj: dict[str, Any],
    *,
    kind: str,
    strict: bool,
    block_index: int,
    path: str,
    errors: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
    data_model: dict[str, Any],
    item_ctx: Any = None,
) -> None:
    fn_name = fn_obj.get("@call") if "@call" in fn_obj else fn_obj.get("call")
    args = fn_obj.get("args") if isinstance(fn_obj.get("args"), dict) else {}
    code = "UNSAFE_MEDIA_URL" if kind == "media" else "UNSAFE_OPEN_URL"
    validator_fn = validate_media_url if kind == "media" else validate_open_url

    if fn_name == "formatString":
        tpl = args.get("value")
        if not isinstance(tpl, str):
            _add_issue(
                errors,
                code,
                block_index,
                path,
                f"formatString in {kind} URL requires a static string 'value' template.",
            )
            return
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in tpl):
            _add_issue(
                errors,
                code,
                block_index,
                path,
                f"formatString {kind} URL template contains disallowed control characters.",
            )
            return
        if "${" not in tpl:
            ok, reason = validator_fn(tpl)
            if not ok:
                _add_issue(errors, code, block_index, path, reason or f"Unsafe {kind} URL in formatString.")
            return

        # Interpolate resolvable placeholders and validate both static prefix and substituted URL.
        all_resolved = True

        def _subst_resolved(match: re.Match[str]) -> str:
            nonlocal all_resolved
            expr = match.group(1).strip()
            found, val = _resolve_pointer_with_context(data_model, expr, item_ctx)
            if found and val is not None:
                return str(val)
            all_resolved = False
            return "placeholder"

        resolved_str = _FORMAT_EXPR_RE.sub(_subst_resolved, tpl)
        prefix = tpl.split("${", 1)[0].strip()
        if not prefix:
            if all_resolved:
                ok, reason = validator_fn(resolved_str)
                if not ok:
                    _add_issue(errors, code, block_index, path, reason or f"Unsafe resolved {kind} URL.")
            else:
                _add_issue(
                    errors,
                    code,
                    block_index,
                    path,
                    f"formatString in {kind} URL must start with a static allowed scheme/prefix.",
                )
            return

        # Validate the static-prefix + placeholder form as well as the resolved form
        placeholder_str = _FORMAT_EXPR_RE.sub("placeholder", tpl)
        ok_tpl, reason_tpl = validator_fn(placeholder_str)
        if not ok_tpl:
            _add_issue(errors, code, block_index, path, reason_tpl or f"Unsafe {kind} URL template in formatString.")
            return
        if all_resolved:
            ok_res, reason_res = validator_fn(resolved_str)
            if not ok_res:
                _add_issue(errors, code, block_index, path, reason_res or f"Unsafe resolved {kind} URL.")
        return

    _add_issue(
        errors if strict else warnings,
        code,
        block_index,
        path,
        f"FunctionCall '{fn_name}' is not statically verifiable in {kind} URL slot.",
    )


def _add_issue(
    bucket: list[dict[str, Any]],
    code: str,
    block_index: int,
    path: str,
    message: str,
) -> None:
    bucket.append(
        {
            "code": code,
            "blockIndex": block_index,
            "path": path,
            "message": message,
        }
    )


def _check_regex_safety(pattern: Any, path: str, block_index: int, errors: list[dict[str, Any]]) -> None:
    if not isinstance(pattern, str):
        _add_issue(errors, "INVALID_REGEX", block_index, path, "regex pattern must be a string.")
        return
    if len(pattern) > 256:
        _add_issue(
            errors,
            "REGEX_TOO_LONG",
            block_index,
            path,
            f"regex pattern exceeds 256 code points ({len(pattern)}).",
        )
        return
    if _REDOS_NESTED_QUANTIFIER_RE.search(pattern) or "\\p{" in pattern:
        _add_issue(
            errors,
            "UNSAFE_REGEX",
            block_index,
            path,
            "regex pattern violates A2UI portable/ReDoS safety dialect.",
        )
        return
    try:
        re.compile(pattern)
    except re.error as exc:
        _add_issue(errors, "INVALID_REGEX", block_index, path, f"Invalid regex pattern: {exc}")


def _validate_dynamic_value(
    val: Any,
    *,
    version: str,
    strict: bool,
    block_index: int,
    path: str,
    errors: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
    catalog_functions: set[str],
    data_model: dict[str, Any],
    catalog_function_specs: dict[str, dict[str, Any]] | None = None,
    catalog_id: str | None = None,
    allow_user_activation: bool = False,
    item_ctx: Any = None,
) -> None:
    """Validate DynamicValue, DataBinding (@path), FunctionCall (@call), arrays, and single-@ escape."""
    if isinstance(val, list):
        for idx, item in enumerate(val):
            _validate_dynamic_value(
                item,
                version=version,
                strict=strict,
                block_index=block_index,
                path=f"{path}[{idx}]",
                errors=errors,
                warnings=warnings,
                catalog_functions=catalog_functions,
                data_model=data_model,
                catalog_function_specs=catalog_function_specs,
                catalog_id=catalog_id,
                allow_user_activation=False,
                item_ctx=item_ctx,
            )
        return

    if not isinstance(val, dict):
        return

    keys = set(val.keys())

    # v1.0 canonical DataBinding
    if "@path" in keys:
        if version != "1.0":
            _add_issue(
                warnings if not strict else errors,
                "VERSION_BINDING_MISMATCH",
                block_index,
                path,
                "@path binding used in pre-1.0 payload.",
            )
        if keys != {"@path"}:
            _add_issue(
                errors,
                "INVALID_DATA_BINDING",
                block_index,
                path,
                "DataBinding with '@path' must not contain extra properties.",
            )
        if not isinstance(val.get("@path"), str) or not val["@path"]:
            _add_issue(
                errors,
                "INVALID_DATA_BINDING",
                block_index,
                path,
                "'@path' must be a non-empty string.",
            )
        return

    def _validate_fn_call_body(fn_name: Any, call_val: dict[str, Any]) -> None:
        if not isinstance(fn_name, str) or not fn_name:
            _add_issue(
                errors, "INVALID_FUNCTION_CALL", block_index, path, "FunctionCall name must be a non-empty string."
            )
            return
        is_custom_fn_cat = (
            isinstance(call_val.get("catalogId"), str)
            and catalog_id is not None
            and call_val["catalogId"] != catalog_id
        )
        fn_spec = None if is_custom_fn_cat else (catalog_function_specs or {}).get(fn_name)
        if fn_name != "@index" and catalog_functions and fn_name not in catalog_functions:
            if not is_custom_fn_cat and "catalogId" not in call_val:
                _add_issue(
                    warnings if not strict else errors,
                    "UNKNOWN_FUNCTION",
                    block_index,
                    path,
                    f"Function '{fn_name}' is not in the Basic Catalog.",
                )
        if fn_spec and fn_spec.get("requiresUserActivation") and not allow_user_activation:
            _add_issue(
                errors,
                "INVALID_FUNCTION_CALL_SITE",
                block_index,
                path,
                f"Function '{fn_name}' requires user activation and is only permitted in Button.action.functionCall.",
            )
        args = call_val.get("args")
        req_args = list(fn_spec.get("requiredArgs", [])) if fn_spec else []
        allowed_args = set((fn_spec.get("args") or {}).keys()) if fn_spec else set()

        if args is None:
            if req_args:
                _add_issue(
                    errors,
                    "MISSING_REQUIRED_FUNCTION_ARG",
                    block_index,
                    f"{path}.args",
                    f"Function '{fn_name}' requires arguments: {req_args}.",
                )
        elif not isinstance(args, dict):
            _add_issue(errors, "INVALID_FUNCTION_ARGS", block_index, f"{path}.args", "'args' must be an object.")
        else:
            for req_arg in req_args:
                if req_arg not in args:
                    _add_issue(
                        errors,
                        "MISSING_REQUIRED_FUNCTION_ARG",
                        block_index,
                        f"{path}.args.{req_arg}",
                        f"Function '{fn_name}' requires argument '{req_arg}'.",
                    )
            if allowed_args:
                extra_args = set(args.keys()) - allowed_args
                if extra_args:
                    _add_issue(
                        errors if strict else warnings,
                        "UNKNOWN_FUNCTION_ARG",
                        block_index,
                        f"{path}.args",
                        f"Unexpected arguments for function '{fn_name}': {sorted(extra_args)}.",
                    )
            if fn_name == "regex" and "pattern" in args:
                _check_regex_safety(args["pattern"], f"{path}.args.pattern", block_index, errors)
            if fn_name == "openUrl" and "url" in args:
                _validate_open_url_arg(
                    args.get("url"),
                    block_index,
                    f"{path}.args.url",
                    errors,
                    data_model,
                    strict=strict,
                    warnings=warnings,
                    item_ctx=item_ctx,
                )
            for ak, av in args.items():
                _validate_dynamic_value(
                    av,
                    version=version,
                    strict=strict,
                    block_index=block_index,
                    path=f"{path}.args.{ak}",
                    errors=errors,
                    warnings=warnings,
                    catalog_functions=catalog_functions,
                    data_model=data_model,
                    catalog_function_specs=catalog_function_specs,
                    catalog_id=catalog_id,
                    allow_user_activation=False,
                    item_ctx=item_ctx,
                )

    # v1.0 canonical FunctionCall
    if "@call" in keys:
        extra = keys - {"@call", "args", "catalogId"}
        if extra:
            _add_issue(
                errors,
                "INVALID_FUNCTION_CALL",
                block_index,
                path,
                f"Unexpected properties on FunctionCall: {sorted(extra)}.",
            )
        _validate_fn_call_body(val.get("@call"), val)
        return

    # Transitional v0.9 bindings in v1.0 payloads
    if version == "1.0":
        if keys == {"path"} and isinstance(val.get("path"), str):
            target = errors if strict else warnings
            _add_issue(
                target,
                "TRANSITIONAL_PATH_BINDING",
                block_index,
                path,
                "Transitional {'path': ...} used in v1.0 DynamicValue; use {'@path': ...}.",
            )
            return
        if "call" in keys and isinstance(val.get("call"), str):
            target = errors if strict else warnings
            _add_issue(
                target,
                "TRANSITIONAL_FUNCTION_CALL",
                block_index,
                path,
                "Transitional {'call': ...} used in v1.0 FunctionCall; use {'@call': ...}.",
            )
            _validate_fn_call_body(val.get("call"), val)
            return
        # Single-@ reserved key check in literal dynamic objects
        for key in keys:
            if _SINGLE_AT_KEY_RE.match(key):
                _add_issue(
                    errors,
                    "INVALID_RESERVED_KEY",
                    block_index,
                    f"{path}.{key}",
                    f"Unrecognized single-'@' key '{key}' in dynamic object; escape literal '@' keys with '@@'.",
                )
    else:
        if "call" in keys and isinstance(val.get("call"), str):
            _validate_fn_call_body(val.get("call"), val)
            return

    # Recurse into literal dict values
    for k, v in val.items():
        _validate_dynamic_value(
            v,
            version=version,
            strict=strict,
            block_index=block_index,
            path=f"{path}.{k}",
            errors=errors,
            warnings=warnings,
            catalog_functions=catalog_functions,
            data_model=data_model,
            catalog_function_specs=catalog_function_specs,
            catalog_id=catalog_id,
            allow_user_activation=False,
            item_ctx=item_ctx,
        )


def _validate_open_url_arg(
    raw_url_val: Any,
    block_index: int,
    path: str,
    errors: list[dict[str, Any]],
    data_model: dict[str, Any],
    *,
    strict: bool = True,
    warnings: list[dict[str, Any]] | None = None,
    item_ctx: Any = None,
) -> None:
    warn_bucket = warnings if warnings is not None else errors
    candidate: Any = raw_url_val
    if isinstance(raw_url_val, dict):
        if "@call" in raw_url_val or "call" in raw_url_val:
            _validate_url_function_call(
                raw_url_val,
                kind="openUrl",
                strict=strict,
                block_index=block_index,
                path=path,
                errors=errors,
                warnings=warn_bucket,
                data_model=data_model,
                item_ctx=item_ctx,
            )
            return
        ptr = raw_url_val.get("@path") if "@path" in raw_url_val else raw_url_val.get("path")
        if isinstance(ptr, str):
            found, resolved = _resolve_pointer_with_context(data_model, ptr, item_ctx)
            if found:
                candidate = resolved
            else:
                return
        else:
            _add_issue(errors, "UNSAFE_OPEN_URL", block_index, path, "openUrl target must be a URL string, DataBinding, or safe formatString call.")
            return
    ok, reason = validate_open_url(candidate)
    if not ok:
        _add_issue(errors, "UNSAFE_OPEN_URL", block_index, path, reason or "Unsafe openUrl target.")


def _validate_media_prop(
    val: Any,
    block_index: int,
    path: str,
    errors: list[dict[str, Any]],
    data_model: dict[str, Any],
    *,
    strict: bool = True,
    warnings: list[dict[str, Any]] | None = None,
    item_ctx: Any = None,
) -> None:
    warn_bucket = warnings if warnings is not None else errors
    candidate: Any = val
    if isinstance(val, dict):
        if "literalString" in val:
            candidate = val["literalString"]
        elif "@call" in val or "call" in val:
            _validate_url_function_call(
                val,
                kind="media",
                strict=strict,
                block_index=block_index,
                path=path,
                errors=errors,
                warnings=warn_bucket,
                data_model=data_model,
                item_ctx=item_ctx,
            )
            return
        else:
            ptr = val.get("@path") if "@path" in val else val.get("path")
            if isinstance(ptr, str):
                found, resolved = _resolve_pointer_with_context(data_model, ptr, item_ctx)
                if found:
                    candidate = resolved
                else:
                    return
            else:
                _add_issue(errors, "UNSAFE_MEDIA_URL", block_index, path, "Media URL must be a string, DataBinding, or safe formatString call.")
                return
    ok, reason = validate_media_url(candidate)
    if not ok:
        _add_issue(errors, "UNSAFE_MEDIA_URL", block_index, path, reason or "Unsafe media URL.")


def _validate_action(
    action: Any,
    *,
    version: str,
    strict: bool,
    block_index: int,
    path: str,
    errors: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
    catalog_functions: set[str],
    data_model: dict[str, Any],
    catalog_function_specs: dict[str, dict[str, Any]] | None = None,
    catalog_id: str | None = None,
    item_ctx: Any = None,
) -> None:
    if not isinstance(action, dict):
        _add_issue(errors, "INVALID_ACTION", block_index, path, "Button action must be an object.")
        return
    if version == "0.8":
        if not isinstance(action.get("name"), str) or not action["name"]:
            _add_issue(errors, "INVALID_ACTION", block_index, path, "v0.8 action requires string 'name'.")
        return

    has_event = "event" in action
    has_fn = "functionCall" in action
    if has_event == has_fn:
        _add_issue(
            errors,
            "INVALID_ACTION",
            block_index,
            path,
            "Action must specify exactly one of 'event' or 'functionCall'.",
        )
        return

    if has_event:
        ev = action["event"]
        if not isinstance(ev, dict) or not isinstance(ev.get("name"), str) or not ev["name"]:
            _add_issue(errors, "INVALID_ACTION", block_index, f"{path}.event", "action.event requires non-empty string 'name'.")
            return
        allowed_ev = {"name", "context", "userMessage"} if version == "1.0" else {"name", "context"}
        extra = set(ev.keys()) - allowed_ev
        if extra:
            _add_issue(
                errors if strict else warnings,
                "UNKNOWN_ACTION_PROPERTY",
                block_index,
                f"{path}.event",
                f"Unexpected action.event properties: {sorted(extra)}.",
            )
        if "userMessage" in ev:
            _validate_dynamic_value(
                ev["userMessage"],
                version=version,
                strict=strict,
                block_index=block_index,
                path=f"{path}.event.userMessage",
                errors=errors,
                warnings=warnings,
                catalog_functions=catalog_functions,
                data_model=data_model,
                catalog_function_specs=catalog_function_specs,
                catalog_id=catalog_id,
                allow_user_activation=False,
                item_ctx=item_ctx,
            )
        if "context" in ev:
            if not isinstance(ev["context"], dict):
                _add_issue(errors, "INVALID_ACTION_CONTEXT", block_index, f"{path}.event.context", "action.event.context must be an object.")
            else:
                for ck, cv in ev["context"].items():
                    _validate_dynamic_value(
                        cv,
                        version=version,
                        strict=strict,
                        block_index=block_index,
                        path=f"{path}.event.context.{ck}",
                        errors=errors,
                        warnings=warnings,
                        catalog_functions=catalog_functions,
                        data_model=data_model,
                        catalog_function_specs=catalog_function_specs,
                        catalog_id=catalog_id,
                        allow_user_activation=False,
                        item_ctx=item_ctx,
                    )
    else:
        fn_call = action["functionCall"]
        if not isinstance(fn_call, dict):
            _add_issue(errors, "INVALID_ACTION", block_index, f"{path}.functionCall", "action.functionCall must be an object.")
            return
        if version == "1.0" and "@call" not in fn_call and "call" not in fn_call:
            _add_issue(errors, "INVALID_FUNCTION_CALL", block_index, f"{path}.functionCall", "action.functionCall requires '@call'.")
            return
        _validate_dynamic_value(
            fn_call,
            version=version,
            strict=strict,
            block_index=block_index,
            path=f"{path}.functionCall",
            errors=errors,
            warnings=warnings,
            catalog_functions=catalog_functions,
            data_model=data_model,
            catalog_function_specs=catalog_function_specs,
            catalog_id=catalog_id,
            allow_user_activation=True,
            item_ctx=item_ctx,
        )


def _extract_v08_component(raw: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    comp_field = raw.get("component")
    if isinstance(comp_field, dict) and len(comp_field) == 1:
        comp_type, props = next(iter(comp_field.items()))
        if isinstance(props, dict):
            return comp_type, props
    return None, {}


def _extract_child_refs(comp_type: str, props: dict[str, Any], version: str) -> list[tuple[str, str]]:
    """Return list of (prop_label, referenced_component_id) from a component."""
    refs: list[tuple[str, str]] = []
    if version == "0.8":
        if isinstance(props.get("child"), str):
            refs.append(("child", props["child"]))
        if isinstance(props.get("entryPointChild"), str):
            refs.append(("entryPointChild", props["entryPointChild"]))
        if isinstance(props.get("contentChild"), str):
            refs.append(("contentChild", props["contentChild"]))
        ch = props.get("children")
        if isinstance(ch, dict):
            if isinstance(ch.get("explicitList"), list):
                for cid in ch["explicitList"]:
                    if isinstance(cid, str):
                        refs.append(("children.explicitList", cid))
            if isinstance(ch.get("template"), dict) and isinstance(ch["template"].get("componentId"), str):
                refs.append(("children.template.componentId", ch["template"]["componentId"]))
        tab_items = props.get("tabItems")
        if isinstance(tab_items, list):
            for idx, item in enumerate(tab_items):
                if isinstance(item, dict) and isinstance(item.get("child"), str):
                    refs.append((f"tabItems[{idx}].child", item["child"]))
        return refs

    if isinstance(props.get("child"), str):
        refs.append(("child", props["child"]))
    if isinstance(props.get("trigger"), str):
        refs.append(("trigger", props["trigger"]))
    if isinstance(props.get("content"), str):
        refs.append(("content", props["content"]))
    ch = props.get("children")
    if isinstance(ch, list):
        for idx, cid in enumerate(ch):
            if isinstance(cid, str):
                refs.append((f"children[{idx}]", cid))
    elif isinstance(ch, dict) and isinstance(ch.get("componentId"), str):
        refs.append(("children.componentId", ch["componentId"]))
    tabs = props.get("tabs")
    if isinstance(tabs, list):
        for idx, tab in enumerate(tabs):
            if isinstance(tab, dict) and isinstance(tab.get("child"), str):
                refs.append((f"tabs[{idx}].child", tab["child"]))
    return refs


def _detect_cycles_iterative(adj: dict[str, list[str]]) -> list[list[str]]:
    """Iterative 3-color DFS cycle detection (CWE-400 safe, no recursion limit)."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {node: WHITE for node in adj}
    cycles: list[list[str]] = []

    for start in adj:
        if color[start] != WHITE:
            continue
        stack: list[tuple[str, int]] = [(start, 0)]
        path_nodes: list[str] = [start]
        color[start] = GRAY
        while stack:
            node, idx = stack[-1]
            neighbors = adj.get(node, [])
            if idx < len(neighbors):
                stack[-1] = (node, idx + 1)
                nxt = neighbors[idx]
                if nxt not in color:
                    continue
                if color[nxt] == GRAY:
                    cycle_start = path_nodes.index(nxt) if nxt in path_nodes else 0
                    cycles.append(path_nodes[cycle_start:] + [nxt])
                elif color[nxt] == WHITE:
                    color[nxt] = GRAY
                    path_nodes.append(nxt)
                    stack.append((nxt, 0))
            else:
                color[node] = BLACK
                stack.pop()
                if path_nodes:
                    path_nodes.pop()
    return cycles


def _validate_surface_components(
    *,
    surface_id: str,
    component_batches: list[list[dict[str, Any]]],
    version: str,
    root_id: str,
    strict: bool,
    max_components: int,
    block_index: int,
    errors: list[dict[str, Any]],
    warnings: list[dict[str, Any]],
    data_model: dict[str, Any],
) -> int:
    catalog = load_catalog_spec(version)
    catalog_components = catalog["components"]
    catalog_function_specs = catalog["functions"]
    catalog_functions = set(catalog_function_specs.keys())
    canonical_catalog_id = catalog["catalogId"]

    total_entries = sum(len(batch) for batch in component_batches)
    if total_entries > max_components:
        _add_issue(
            errors,
            "MAX_COMPONENTS_EXCEEDED",
            block_index,
            f"surface:{surface_id}",
            f"Surface '{surface_id}' has {total_entries} components, exceeding max_components ({max_components}).",
        )
        return total_entries

    comp_map: dict[str, tuple[str, dict[str, Any], str]] = {}
    adj: dict[str, list[str]] = {}
    parents_by_child: dict[str, list[str]] = {}
    historical_adj: dict[str, list[str]] = {}
    historical_parents: dict[str, list[str]] = {}

    multi_batch = len(component_batches) > 1
    for b_idx, batch in enumerate(component_batches):
        batch_seen_ids: set[str] = set()
        for idx, comp in enumerate(batch):
            cpath = (
                f"surface:{surface_id}.batch[{b_idx}].components[{idx}]"
                if multi_batch
                else f"surface:{surface_id}.components[{idx}]"
            )
            if not isinstance(comp, dict):
                _add_issue(errors, "INVALID_COMPONENT", block_index, cpath, "Component must be an object.")
                continue

            cid = comp.get("id")
            if not isinstance(cid, str) or not cid:
                _add_issue(errors, "MISSING_COMPONENT_ID", block_index, cpath, "Component requires non-empty string 'id'.")
                continue

            if cid in batch_seen_ids:
                _add_issue(errors, "DUPLICATE_COMPONENT_ID", block_index, cpath, f"Duplicate component id '{cid}'.")
                continue
            batch_seen_ids.add(cid)

            if version == "1.0" and not is_valid_uax31_id(cid):
                _add_issue(
                    errors,
                    "INVALID_UAX31_ID",
                    block_index,
                    f"{cpath}.id",
                    f"Component id '{cid}' violates UAX #31 identifier syntax (no hyphens, spaces, or leading digits).",
                )

            if version == "0.8":
                comp_type, props = _extract_v08_component(comp)
                if not comp_type:
                    _add_issue(
                        errors,
                        "INVALID_COMPONENT_SHAPE",
                        block_index,
                        cpath,
                        "v0.8 component must have nested 'component': {'TypeName': {...}}.",
                    )
                    continue
            else:
                comp_type = comp.get("component")
                props = comp
                if not isinstance(comp_type, str) or not comp_type:
                    _add_issue(
                        errors,
                        "MISSING_COMPONENT_TYPE",
                        block_index,
                        cpath,
                        "Component requires string 'component' type discriminator.",
                    )
                    continue

            if comp_type == "Surface":
                _add_issue(
                    errors,
                    "RESERVED_COMPONENT_SURFACE",
                    block_index,
                    cpath,
                    "'Surface' is a reserved canonical container and cannot appear in components list.",
                )
                continue

            # Last-write-wins replacement across incremental updateComponents batches
            comp_map[cid] = (comp_type, props, cpath)
            adj.setdefault(cid, [])
            hist_edges = historical_adj.setdefault(cid, [])
            for _ref_prop, ref_id in _extract_child_refs(comp_type, props, version):
                if ref_id not in hist_edges:
                    hist_edges.append(ref_id)
                historical_parents.setdefault(ref_id, []).append(comp_type)

            # Transitional bare mixins in v1.0
            if version == "1.0":
                for bare in TRANSITIONAL_MIXIN_KEYS:
                    if bare in comp and comp_type in catalog_components:
                        target = errors if strict else warnings
                        _add_issue(
                            target,
                            "TRANSITIONAL_BARE_MIXIN",
                            block_index,
                            f"{cpath}.{bare}",
                            f"Component mixin '{bare}' must be '@{bare}' in canonical A2UI v1.0.",
                        )

            # Basic Catalog schema validation when using default catalog (exact canonical URI match)
            is_custom_catalog = (
                isinstance(comp.get("@catalogId"), str)
                and comp["@catalogId"] != canonical_catalog_id
            )
            if not is_custom_catalog and comp_type in catalog_components:
                spec = catalog_components[comp_type]
                for req in spec["required"]:
                    if version == "0.8" and req == "component":
                        continue
                    if req not in props:
                        _add_issue(
                            errors,
                            "MISSING_REQUIRED_PROPERTY",
                            block_index,
                            f"{cpath}.{req}",
                            f"{comp_type} (v{version}) requires property '{req}'.",
                        )

                if version == "0.8":
                    allowed_props = set(spec["properties"].keys())
                elif version == "1.0":
                    allowed_props = set(spec["properties"].keys()) | V1_COMPONENT_ENVELOPE_KEYS
                else:
                    allowed_props = (
                        set(spec["properties"].keys())
                        | {"id", "component", "weight"}
                        | TRANSITIONAL_MIXIN_KEYS
                    )
                unknown_props = set(props.keys()) - allowed_props - (
                    TRANSITIONAL_MIXIN_KEYS if version == "1.0" else set()
                )
                if unknown_props:
                    _add_issue(
                        errors if strict else warnings,
                        "UNKNOWN_COMPONENT_PROPERTY",
                        block_index,
                        cpath,
                        f"Unknown properties on {comp_type} (v{version}): {sorted(unknown_props)}.",
                    )

                for prop_name, prop_spec in spec["properties"].items():
                    if prop_name not in props:
                        continue
                    pval = props[prop_name]
                    allowed_enum = prop_spec.get("enum")
                    if allowed_enum and isinstance(pval, str) and pval not in allowed_enum:
                        _add_issue(
                            errors,
                            "INVALID_ENUM_VALUE",
                            block_index,
                            f"{cpath}.{prop_name}",
                            f"{comp_type}.{prop_name}='{pval}' is invalid for v{version}; allowed: {allowed_enum}.",
                        )

                # Validate ChildList structure (path stays unprefixed in ChildList!)
                if "children" in props and version != "0.8":
                    ch_val = props["children"]
                    if isinstance(ch_val, list):
                        if not all(isinstance(x, str) for x in ch_val):
                            _add_issue(
                                errors,
                                "INVALID_CHILD_LIST",
                                block_index,
                                f"{cpath}.children",
                                "Static children array must contain component ID strings.",
                            )
                    elif isinstance(ch_val, dict):
                        if set(ch_val.keys()) != {"componentId", "path"} or not isinstance(
                            ch_val.get("componentId"), str
                        ) or not isinstance(ch_val.get("path"), str):
                            _add_issue(
                                errors,
                                "INVALID_CHILD_TEMPLATE",
                                block_index,
                                f"{cpath}.children",
                                "Dynamic children template must have exact string keys 'componentId' and 'path' (unprefixed).",
                            )
                    else:
                        _add_issue(
                            errors,
                            "INVALID_CHILD_LIST",
                            block_index,
                            f"{cpath}.children",
                            "children must be an array of IDs or a {componentId, path} template.",
                        )

                # Validate Tabs items
                if comp_type == "Tabs" and isinstance(props.get("tabs"), list):
                    if len(props["tabs"]) == 0:
                        _add_issue(errors, "EMPTY_TABS", block_index, f"{cpath}.tabs", "Tabs.tabs must have at least 1 item.")
                    for tidx, tab in enumerate(props["tabs"]):
                        if not isinstance(tab, dict) or "title" not in tab or "child" not in tab:
                            _add_issue(
                                errors,
                                "INVALID_TAB_ITEM",
                                block_index,
                                f"{cpath}.tabs[{tidx}]",
                                "Each tab item must contain 'title' and 'child'.",
                            )
                        else:
                            _validate_dynamic_value(
                                tab["title"],
                                version=version,
                                strict=strict,
                                block_index=block_index,
                                path=f"{cpath}.tabs[{tidx}].title",
                                errors=errors,
                                warnings=warnings,
                                catalog_functions=catalog_functions,
                                data_model=data_model,
                                catalog_function_specs=catalog_function_specs,
                                catalog_id=canonical_catalog_id,
                            )

                # Validate ChoicePicker options
                if comp_type == "ChoicePicker" and isinstance(props.get("options"), list):
                    for oidx, opt in enumerate(props["options"]):
                        if not isinstance(opt, dict) or "label" not in opt or not isinstance(opt.get("value"), str):
                            _add_issue(
                                errors,
                                "INVALID_CHOICE_OPTION",
                                block_index,
                                f"{cpath}.options[{oidx}]",
                                "Each ChoicePicker option requires 'label' and string 'value'.",
                            )
            elif not is_custom_catalog and comp_type not in catalog_components:
                _add_issue(
                    warnings if not strict else errors,
                    "UNKNOWN_COMPONENT_TYPE",
                    block_index,
                    cpath,
                    f"Component type '{comp_type}' is not in the Basic Catalog v{version}.",
                )

            # Unconditional security & dynamic checks (even when @catalogId overrides catalog)
            checks_val = props.get("@checks") if "@checks" in props else props.get("checks")
            if checks_val is not None:
                if not is_custom_catalog and comp_type in catalog_components and not catalog_components[comp_type]["checkable"]:
                    _add_issue(
                        errors,
                        "NON_CHECKABLE_COMPONENT",
                        block_index,
                        f"{cpath}.@checks",
                        f"Component '{comp_type}' is not Checkable and cannot declare @checks.",
                    )
                elif not isinstance(checks_val, list):
                    _add_issue(
                        errors, "INVALID_CHECKS", block_index, f"{cpath}.@checks", "@checks must be a list."
                    )
                else:
                    for ch_idx, rule in enumerate(checks_val):
                        rpath = f"{cpath}.@checks[{ch_idx}]"
                        if not isinstance(rule, dict) or "condition" not in rule:
                            _add_issue(
                                errors,
                                "INVALID_CHECK_RULE",
                                block_index,
                                rpath,
                                "CheckRule must be an object containing 'condition'.",
                            )
                            continue
                        cond = rule["condition"]
                        if not isinstance(cond, dict) or not (
                            "@path" in cond or "@call" in cond or "path" in cond or "call" in cond
                        ):
                            _add_issue(
                                errors,
                                "INVALID_CHECK_CONDITION",
                                block_index,
                                f"{rpath}.condition",
                                "CheckRule.condition must be a DataBinding or FunctionCall.",
                            )
                        else:
                            _validate_dynamic_value(
                                cond,
                                version=version,
                                strict=strict,
                                block_index=block_index,
                                path=f"{rpath}.condition",
                                errors=errors,
                                warnings=warnings,
                                catalog_functions=catalog_functions,
                                data_model=data_model,
                                catalog_function_specs=catalog_function_specs,
                                catalog_id=canonical_catalog_id,
                            )

            for prop_name, pval in props.items():
                if prop_name in _DYNAMIC_VALUE_PROPS:
                    _validate_dynamic_value(
                        pval,
                        version=version,
                        strict=strict,
                        block_index=block_index,
                        path=f"{cpath}.{prop_name}",
                        errors=errors,
                        warnings=warnings,
                        catalog_functions=catalog_functions,
                        data_model=data_model,
                        catalog_function_specs=catalog_function_specs,
                        catalog_id=canonical_catalog_id,
                    )

            if "action" in props and (comp_type == "Button" or isinstance(props["action"], dict)):
                _validate_action(
                    props["action"],
                    version=version,
                    strict=strict,
                    block_index=block_index,
                    path=f"{cpath}.action",
                    errors=errors,
                    warnings=warnings,
                    catalog_functions=catalog_functions,
                    data_model=data_model,
                    catalog_function_specs=catalog_function_specs,
                    catalog_id=canonical_catalog_id,
                )

            if comp_type in _MEDIA_URL_PROPS:
                for media_prop in _MEDIA_URL_PROPS[comp_type]:
                    if media_prop in props:
                        _validate_media_prop(
                            props[media_prop],
                            block_index,
                            f"{cpath}.{media_prop}",
                            errors,
                            data_model,
                            strict=strict,
                            warnings=warnings,
                        )
            elif is_custom_catalog:
                for media_prop in ("url", "posterUrl"):
                    if media_prop in props:
                        _validate_media_prop(
                            props[media_prop],
                            block_index,
                            f"{cpath}.{media_prop}",
                            errors,
                            data_model,
                            strict=strict,
                            warnings=warnings,
                        )

    # Check root presence
    if root_id not in comp_map:
        _add_issue(
            errors,
            "MISSING_ROOT_COMPONENT",
            block_index,
            f"surface:{surface_id}",
            f"Surface '{surface_id}' is missing required root component id '{root_id}'.",
        )

    # Build final active reference graph & check dangling refs
    for cid, (comp_type, props, cpath) in comp_map.items():
        for ref_prop, ref_id in _extract_child_refs(comp_type, props, version):
            if ref_id not in comp_map:
                _add_issue(
                    errors,
                    "DANGLING_COMPONENT_REF",
                    block_index,
                    f"{cpath}.{ref_prop}",
                    f"Component '{cid}' references non-existent component '{ref_id}'.",
                )
            else:
                adj[cid].append(ref_id)
                parents_by_child.setdefault(ref_id, []).append(comp_type)

    # Compute reachability on both final graph and historical union graph (for replaced placeholders)
    final_visited: set[str] = set()
    ever_visited: set[str] = set()
    if root_id in comp_map:
        queue = [root_id]
        while queue:
            cur = queue.pop()
            if cur in final_visited:
                continue
            final_visited.add(cur)
            queue.extend(adj.get(cur, []))

        hist_queue = [root_id]
        while hist_queue:
            cur = hist_queue.pop()
            if cur in ever_visited:
                continue
            ever_visited.add(cur)
            hist_queue.extend(historical_adj.get(cur, []))

    # Check weight only under Row or Column
    for cid, (_comp_type, props, cpath) in comp_map.items():
        if "weight" in props:
            parent_types = (
                parents_by_child.get(cid, [])
                if cid in final_visited
                else (historical_parents.get(cid, []) if cid in ever_visited else parents_by_child.get(cid, []))
            )
            if not parent_types or any(pt not in {"Row", "Column"} for pt in parent_types):
                _add_issue(
                    errors if strict else warnings,
                    "INVALID_WEIGHT_PARENT",
                    block_index,
                    f"{cpath}.weight",
                    f"Component '{cid}' declares 'weight' but is not a direct child of Row or Column.",
                )

    # Cycle detection on active component graph (CWE-400)
    for cycle in _detect_cycles_iterative(adj):
        _add_issue(
            errors,
            "COMPONENT_CYCLE",
            block_index,
            f"surface:{surface_id}",
            f"Cyclic component reference detected: {' -> '.join(cycle)}.",
        )

    # Validate ChildList dynamic template bindings against inline dataModel array items
    template_bindings: list[tuple[str, str]] = []
    for _cid, (_ctype, props, _cpath) in comp_map.items():
        ch = props.get("children")
        if isinstance(ch, dict):
            if version == "0.8" and isinstance(ch.get("template"), dict):
                tpl = ch["template"]
                if isinstance(tpl.get("componentId"), str) and isinstance(tpl.get("dataBinding"), str):
                    template_bindings.append((tpl["componentId"], tpl["dataBinding"]))
            elif isinstance(ch.get("componentId"), str) and isinstance(ch.get("path"), str):
                template_bindings.append((ch["componentId"], ch["path"]))

    for tpl_root_id, list_ptr in template_bindings:
        found_list, items_val = _resolve_json_pointer(data_model, list_ptr)
        if not found_list or not isinstance(items_val, list):
            continue
        if tpl_root_id not in comp_map:
            continue
        tpl_nodes: list[str] = []
        seen_tpl: set[str] = set()
        t_queue = [tpl_root_id]
        while t_queue:
            cur_id = t_queue.pop()
            if cur_id in seen_tpl or cur_id not in comp_map:
                continue
            seen_tpl.add(cur_id)
            tpl_nodes.append(cur_id)
            t_queue.extend(adj.get(cur_id, []))
        for item_idx, item in enumerate(items_val):
            for tcid in tpl_nodes:
                t_type, t_props, t_cpath = comp_map[tcid]
                t_is_custom = (
                    isinstance(t_props.get("@catalogId"), str)
                    and t_props["@catalogId"] != canonical_catalog_id
                )
                media_props = _MEDIA_URL_PROPS.get(t_type, ("url", "posterUrl") if t_is_custom else ())
                for media_prop in media_props:
                    if media_prop in t_props and isinstance(t_props[media_prop], dict):
                        val_obj = t_props[media_prop]
                        ptr = val_obj.get("@path") if "@path" in val_obj else val_obj.get("path")
                        has_call = "@call" in val_obj or "call" in val_obj
                        if (isinstance(ptr, str) and not ptr.startswith("/")) or has_call:
                            _validate_media_prop(
                                val_obj,
                                block_index,
                                f"{t_cpath}[item:{item_idx}].{media_prop}",
                                errors,
                                data_model,
                                strict=strict,
                                warnings=warnings,
                                item_ctx=item,
                            )
                if "action" in t_props and isinstance(t_props["action"], dict):
                    fn_call = t_props["action"].get("functionCall")
                    if isinstance(fn_call, dict):
                        fn_name = fn_call.get("@call") or fn_call.get("call")
                        fn_args = fn_call.get("args")
                        if fn_name == "openUrl" and isinstance(fn_args, dict) and isinstance(fn_args.get("url"), dict):
                            url_obj = fn_args["url"]
                            ptr = url_obj.get("@path") if "@path" in url_obj else url_obj.get("path")
                            has_call = "@call" in url_obj or "call" in url_obj
                            if (isinstance(ptr, str) and not ptr.startswith("/")) or has_call:
                                _validate_open_url_arg(
                                    url_obj,
                                    block_index,
                                    f"{t_cpath}[item:{item_idx}].action.functionCall.args.url",
                                    errors,
                                    data_model,
                                    strict=strict,
                                    warnings=warnings,
                                    item_ctx=item,
                                )

    # Reachability / orphan detection (ignore placeholders superseded by incremental updates)
    if root_id in comp_map:
        for cid, (_ctype, _props, cpath) in comp_map.items():
            if cid not in ever_visited:
                _add_issue(
                    warnings,
                    "ORPHAN_COMPONENT",
                    block_index,
                    cpath,
                    f"Component '{cid}' is not reachable from '{root_id}'.",
                )

    return len(comp_map)


def validate_payload(
    raw_text: str,
    *,
    extract_markdown: bool = False,
    version: str = "auto",
    strict: bool = False,
    allow_warnings: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_components: int = DEFAULT_MAX_COMPONENTS,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> dict[str, Any]:
    """Validate raw A2UI payload (JSON, JSONL, or Markdown fences) completely offline."""
    parsed = parse_payload(
        raw_text,
        extract_markdown=extract_markdown,
        max_bytes=max_bytes,
        max_depth=max_depth,
    )
    errors: list[dict[str, Any]] = list(parsed["errors"])
    warnings: list[dict[str, Any]] = []
    detected_versions: list[str] = []
    surface_ids: list[str] = []
    total_components = 0
    total_messages = 0

    req_ver = version.strip().lower().lstrip("v") if version != "auto" else "auto"

    for block in parsed["blocks"]:
        bidx = block["blockIndex"]
        messages = block["messages"]
        total_messages += len(messages)

        # Secret scan across entire parsed block first (fails closed)
        for finding in scan_for_secrets(messages):
            _add_issue(errors, "SECRET_LEAK", bidx, finding["path"], finding["message"])

        active_surfaces: set[str] = set()
        deleted_surfaces: set[str] = set()
        ever_created_surfaces: set[str] = set()
        surface_versions: dict[str, str] = {}
        surface_component_batches: dict[str, list[list[dict[str, Any]]]] = {}
        surface_data_models: dict[str, dict[str, Any]] = {}
        surface_roots: dict[str, str] = {}

        def _flush_surface(sid_to_flush: str) -> None:
            nonlocal total_components
            batches = surface_component_batches.pop(sid_to_flush, None)
            dm = surface_data_models.pop(sid_to_flush, {})
            if batches is None:
                return
            sver = surface_versions.get(sid_to_flush, "1.0")
            sroot = surface_roots.get(sid_to_flush, "root")
            total_components += _validate_surface_components(
                surface_id=sid_to_flush,
                component_batches=batches,
                version=sver,
                root_id=sroot,
                strict=strict,
                max_components=max_components,
                block_index=bidx,
                errors=errors,
                warnings=warnings,
                data_model=dm,
            )

        for midx, msg in enumerate(messages):
            mpath = f"$[{midx}]"
            if not isinstance(msg, dict):
                _add_issue(errors, "INVALID_MESSAGE", bidx, mpath, "A2UI message must be a JSON object.")
                continue

            msg_ver = req_ver if req_ver != "auto" else _detect_message_version(msg)
            if msg_ver not in detected_versions:
                detected_versions.append(msg_ver)

            if msg_ver == "1.0":
                valid_env = V1_ENVELOPE_KEYS
                if msg.get("version") != "1.0":
                    _add_issue(
                        errors if strict else warnings,
                        "INVALID_VERSION_FIELD",
                        bidx,
                        f"{mpath}.version",
                        f"v1.0 messages require version='1.0' (got {msg.get('version')!r}).",
                    )
            elif msg_ver in {"0.9", "0.9.1"}:
                valid_env = V09_ENVELOPE_KEYS
            else:
                valid_env = V08_ENVELOPE_KEYS

            present_env = [k for k in msg.keys() if k in valid_env]
            if len(present_env) != 1:
                _add_issue(
                    errors,
                    "INVALID_MESSAGE_ENVELOPE",
                    bidx,
                    mpath,
                    f"Message must contain exactly one v{msg_ver} envelope key (found {present_env}).",
                )
                continue

            env_key = present_env[0]
            extra_top = set(msg.keys()) - {env_key, "version"}
            if extra_top:
                _add_issue(
                    errors if strict else warnings,
                    "UNEXPECTED_TOP_LEVEL_KEY",
                    bidx,
                    mpath,
                    f"Unexpected top-level message keys: {sorted(extra_top)}.",
                )

            body = msg.get(env_key)
            if not isinstance(body, dict):
                _add_issue(errors, "INVALID_ENVELOPE_BODY", bidx, f"{mpath}.{env_key}", f"'{env_key}' must be an object.")
                continue

            # Handle createSurface / beginRendering
            if env_key == "createSurface":
                sid = body.get("surfaceId")
                if not isinstance(sid, str) or not sid:
                    _add_issue(errors, "MISSING_SURFACE_ID", bidx, f"{mpath}.createSurface.surfaceId", "createSurface requires string 'surfaceId'.")
                    continue
                if sid in active_surfaces:
                    _add_issue(
                        errors,
                        "DUPLICATE_SURFACE_ID",
                        bidx,
                        f"{mpath}.createSurface.surfaceId",
                        f"Duplicate createSurface for active surfaceId '{sid}'.",
                    )
                if sid in deleted_surfaces:
                    deleted_surfaces.discard(sid)
                    surface_component_batches.pop(sid, None)
                    surface_data_models.pop(sid, None)
                    surface_roots[sid] = "root"
                active_surfaces.add(sid)
                ever_created_surfaces.add(sid)
                surface_versions[sid] = msg_ver
                surface_roots.setdefault(sid, "root")
                surface_component_batches.setdefault(sid, [])
                if sid not in surface_ids:
                    surface_ids.append(sid)

                cat_id = body.get("catalogId")
                if cat_id == BROKEN_V09_CATALOG_ID:
                    _add_issue(
                        warnings,
                        "BROKEN_CATALOG_URI",
                        bidx,
                        f"{mpath}.createSurface.catalogId",
                        f"Catalog URI '{BROKEN_V09_CATALOG_ID}' returns HTTP 404 on a2ui.org; use canonical catalogs/basic/catalog.json.",
                    )
                if msg_ver in {"0.9", "0.9.1"} and not cat_id:
                    _add_issue(
                        errors,
                        "MISSING_CATALOG_ID",
                        bidx,
                        f"{mpath}.createSurface.catalogId",
                        "v0.9/v0.9.1 createSurface requires 'catalogId'.",
                    )

                if msg_ver == "1.0":
                    if "theme" in body:
                        _add_issue(
                            errors if strict else warnings,
                            "DEPRECATED_THEME_PROPERTY",
                            bidx,
                            f"{mpath}.createSurface.theme",
                            "createSurface.theme was removed in A2UI v1.0.",
                        )
                    unknown_cs = set(body.keys()) - V1_CREATE_SURFACE_KEYS - {"theme"}
                    if unknown_cs:
                        _add_issue(
                            errors if strict else warnings,
                            "UNEXPECTED_CREATE_SURFACE_KEY",
                            bidx,
                            f"{mpath}.createSurface",
                            f"Unexpected createSurface keys: {sorted(unknown_cs)}.",
                        )
                    if "dataModel" in body:
                        if isinstance(body["dataModel"], dict):
                            surface_data_models[sid] = dict(body["dataModel"])
                        else:
                            _add_issue(
                                errors,
                                "INVALID_DATA_MODEL",
                                bidx,
                                f"{mpath}.createSurface.dataModel",
                                "createSurface.dataModel must be a JSON object when provided.",
                            )
                    if "components" in body:
                        if isinstance(body["components"], list) and len(body["components"]) > 0:
                            surface_component_batches.setdefault(sid, []).append(body["components"])
                        else:
                            _add_issue(
                                errors,
                                "INVALID_COMPONENTS",
                                bidx,
                                f"{mpath}.createSurface.components",
                                "createSurface.components must be a non-empty list when provided.",
                            )

            elif env_key == "beginRendering":
                sid = body.get("surfaceId")
                root_name = body.get("root")
                if not isinstance(sid, str) or not sid:
                    _add_issue(errors, "MISSING_SURFACE_ID", bidx, f"{mpath}.beginRendering.surfaceId", "beginRendering requires 'surfaceId'.")
                    continue
                if not isinstance(root_name, str) or not root_name:
                    _add_issue(errors, "MISSING_ROOT_ID", bidx, f"{mpath}.beginRendering.root", "beginRendering requires 'root'.")
                else:
                    surface_roots[sid] = root_name
                deleted_surfaces.discard(sid)
                active_surfaces.add(sid)
                ever_created_surfaces.add(sid)
                surface_versions[sid] = "0.8"
                surface_component_batches.setdefault(sid, [])
                if sid not in surface_ids:
                    surface_ids.append(sid)

            elif env_key in {"updateComponents", "surfaceUpdate"}:
                sid = body.get("surfaceId")
                if not isinstance(sid, str) or not sid:
                    _add_issue(errors, "MISSING_SURFACE_ID", bidx, f"{mpath}.{env_key}.surfaceId", f"{env_key} requires 'surfaceId'.")
                    continue
                if sid in deleted_surfaces:
                    _add_issue(
                        errors,
                        "INACTIVE_SURFACE",
                        bidx,
                        f"{mpath}.{env_key}",
                        f"{env_key} targets deleted or inactive surface '{sid}'.",
                    )
                    continue
                if sid not in active_surfaces and env_key == "updateComponents":
                    _add_issue(
                        errors if strict else warnings,
                        "MISSING_CREATE_SURFACE",
                        bidx,
                        f"{mpath}.{env_key}",
                        f"updateComponents for '{sid}' appeared without a preceding createSurface.",
                    )
                if sid not in surface_ids:
                    surface_ids.append(sid)
                surface_versions.setdefault(sid, msg_ver)
                surface_roots.setdefault(sid, "root")
                comps = body.get("components")
                if not isinstance(comps, list) or not comps:
                    _add_issue(errors, "EMPTY_COMPONENTS", bidx, f"{mpath}.{env_key}.components", "components must be a non-empty list.")
                else:
                    surface_component_batches.setdefault(sid, []).append(comps)

            elif env_key == "updateDataModel":
                sid = body.get("surfaceId")
                if not isinstance(sid, str) or not sid:
                    _add_issue(errors, "MISSING_SURFACE_ID", bidx, f"{mpath}.updateDataModel.surfaceId", "updateDataModel requires 'surfaceId'.")
                    continue
                if sid in deleted_surfaces:
                    _add_issue(
                        errors,
                        "INACTIVE_SURFACE",
                        bidx,
                        f"{mpath}.updateDataModel",
                        f"updateDataModel targets deleted or inactive surface '{sid}'.",
                    )
                    continue
                if sid not in active_surfaces:
                    _add_issue(
                        errors if strict else warnings,
                        "INACTIVE_SURFACE",
                        bidx,
                        f"{mpath}.updateDataModel",
                        f"updateDataModel targets inactive or uncreated surface '{sid}'.",
                    )
                if msg_ver == "1.0" and "value" not in body:
                    _add_issue(
                        errors if strict else warnings,
                        "MISSING_DATA_MODEL_VALUE",
                        bidx,
                        f"{mpath}.updateDataModel",
                        "A2UI v1.0 updateDataModel requires explicit 'value' (use null to delete).",
                    )
                ptr = body.get("path", "/")
                if ptr in {"", "/"}:
                    if body.get("value") is None:
                        surface_data_models[sid] = {}
                    elif isinstance(body.get("value"), dict):
                        surface_data_models[sid] = dict(body["value"])
                elif isinstance(ptr, str) and ptr.startswith("/") and "value" in body:
                    dm = surface_data_models.setdefault(sid, {})
                    parts = [p.replace("~1", "/").replace("~0", "~") for p in ptr.lstrip("/").split("/")]
                    cur: Any = dm
                    for seg in parts[:-1]:
                        if isinstance(cur, dict):
                            nxt = cur.get(seg)
                            if not isinstance(nxt, dict):
                                if body["value"] is None:
                                    cur = None
                                    break
                                nxt = {}
                                cur[seg] = nxt
                            cur = nxt
                        else:
                            cur = None
                            break
                    if isinstance(cur, dict):
                        if body["value"] is None:
                            cur.pop(parts[-1], None)
                        else:
                            cur[parts[-1]] = body["value"]

            elif env_key == "dataModelUpdate":
                sid = body.get("surfaceId")
                if not isinstance(sid, str) or not sid:
                    _add_issue(errors, "MISSING_SURFACE_ID", bidx, f"{mpath}.dataModelUpdate.surfaceId", "dataModelUpdate requires 'surfaceId'.")

            elif env_key == "deleteSurface":
                sid = body.get("surfaceId")
                if not isinstance(sid, str) or not sid:
                    _add_issue(errors, "MISSING_SURFACE_ID", bidx, f"{mpath}.deleteSurface.surfaceId", "deleteSurface requires 'surfaceId'.")
                elif sid not in active_surfaces:
                    _add_issue(
                        errors,
                        "INACTIVE_SURFACE",
                        bidx,
                        f"{mpath}.deleteSurface",
                        f"deleteSurface targets inactive or non-existent surface '{sid}'.",
                    )
                else:
                    _flush_surface(sid)
                    active_surfaces.discard(sid)
                    deleted_surfaces.add(sid)

            elif env_key == "error":
                if msg_ver == "1.0" and "surfaceId" in body and "functionCallId" in body:
                    _add_issue(
                        errors,
                        "EXCLUSIVE_ERROR_TARGET",
                        bidx,
                        f"{mpath}.error",
                        "error.surfaceId and error.functionCallId are mutually exclusive in v1.0.",
                    )

        # Validate collected component graphs per remaining surface
        for sid in list(surface_component_batches.keys()):
            _flush_surface(sid)

    if strict and warnings and not allow_warnings:
        ok = False
    else:
        ok = len(errors) == 0

    return {
        "ok": ok,
        "strict": strict,
        "detectedVersions": detected_versions,
        "blockCount": parsed["blockCount"],
        "surfaceIds": surface_ids,
        "componentCount": total_components,
        "errors": errors,
        "warnings": warnings,
        "stats": {
            "byteLength": parsed["byteLength"],
            "messageCount": total_messages,
            "surfaceCount": len(surface_ids),
            "componentCount": total_components,
            "errorCount": len(errors),
            "warningCount": len(warnings),
        },
    }
