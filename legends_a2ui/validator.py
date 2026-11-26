"""Offline A2UI protocol, Basic Catalog, graph, URL safety, and secret validator."""
from __future__ import annotations

from functools import lru_cache
import re
from typing import Any

from legends_a2ui.parser import DEFAULT_MAX_BYTES, DEFAULT_MAX_DEPTH, parse_payload
from legends_a2ui.spec_registry import (
    BROKEN_V09_CATALOG_ID,
    CANONICAL_V08_CATALOG_ID,
    CANONICAL_V09_CATALOG_ID,
    CANONICAL_V1_CATALOG_ID,
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


_NON_CUSTOM_CATALOG_IDS = frozenset(
    {
        "",
        "basic",
        "standard",
        BROKEN_V09_CATALOG_ID,
        CANONICAL_V1_CATALOG_ID,
        CANONICAL_V09_CATALOG_ID,
        CANONICAL_V08_CATALOG_ID,
    }
)

_CANONICAL_CATALOG_ID_BY_VER: dict[str, str] = {
    "1.0": CANONICAL_V1_CATALOG_ID,
    "0.9.1": CANONICAL_V09_CATALOG_ID,
    "0.9": CANONICAL_V09_CATALOG_ID,
    "0.8": CANONICAL_V08_CATALOG_ID,
}


def _is_custom_catalog_id(cat_id: Any, canonical_catalog_id: str) -> bool:
    """Return True when cat_id names a non-Basic custom catalog URI/identifier."""
    if not isinstance(cat_id, str):
        return False
    cleaned = cat_id.strip()
    if not cleaned:
        return False
    if cleaned == canonical_catalog_id or cleaned in _NON_CUSTOM_CATALOG_IDS:
        return False
    return True


_RFC6901_INDEX_RE = re.compile(r"^(?:0|[1-9][0-9]{0,6})$")
_SIMPLE_FORMAT_PTR_RE = re.compile(r"^[^${}()\s]+$")


def _parse_rfc6901_array_index(seg: str) -> int | None:
    """Parse a bounded RFC 6901 ASCII array index ('0' or [1-9][0-9]{0,6})."""
    if not isinstance(seg, str) or not _RFC6901_INDEX_RE.fullmatch(seg):
        return None
    return int(seg)


def _canonicalize_json_pointer(ptr: str, max_segments: int = DEFAULT_MAX_DEPTH + 4) -> str:
    """Canonicalize an RFC 6901 JSON Pointer (absolute or relative) so '~' and '~0' map identically."""
    if not isinstance(ptr, str) or ptr in {"", "/"} or "~" not in ptr:
        return ptr
    if len(ptr) > max_segments and ptr.count("/") > max_segments:
        return ptr
    if ptr.startswith("/"):
        return "/" + "/".join(
            s.replace("~1", "/").replace("~0", "~").replace("~", "~0").replace("/", "~1")
            for s in ptr[1:].split("/")
        )
    return "/".join(
        s.replace("~1", "/").replace("~0", "~").replace("~", "~0").replace("/", "~1")
        for s in ptr.split("/")
    )


def _child_index_under(
    parent_ptr: str, target_ptr: str, max_segments: int = DEFAULT_MAX_DEPTH + 4
) -> int | None:
    """Extract the immediate child array index of target_ptr under parent_ptr, if valid."""
    if not isinstance(target_ptr, str) or not target_ptr.startswith("/"):
        return None
    parent_ptr = _canonicalize_json_pointer(parent_ptr, max_segments=max_segments)
    target_ptr = _canonicalize_json_pointer(target_ptr, max_segments=max_segments)
    if parent_ptr in {"", "/"}:
        rest = target_ptr[1:]
    else:
        plen = len(parent_ptr)
        if len(target_ptr) <= plen or not target_ptr.startswith(parent_ptr) or target_ptr[plen] != "/":
            return None
        rest = target_ptr[plen + 1 :]
    if not rest:
        return None
    return _parse_rfc6901_array_index(rest.split("/", 1)[0])


def _mutate_json_pointer(
    root: dict[str, Any],
    pointer: str,
    value: Any,
    max_segments: int = DEFAULT_MAX_DEPTH + 4,
) -> tuple[str, int | None]:
    """Apply an RFC 6901 JSON Pointer mutation across nested dicts and lists (None deletes).

    Returns (effective_pointer, popped_idx) where trailing '/-' appends resolve to their
    concrete numeric index and list element deletions map to the parent list pointer with
    the integer index that was popped.
    """
    if not isinstance(pointer, str) or not pointer.startswith("/") or pointer == "/":
        return (pointer if isinstance(pointer, str) else "/", None)
    if pointer.count("/") > max_segments:
        return (pointer, None)
    canon_pointer = _canonicalize_json_pointer(pointer, max_segments=max_segments)
    raw_parts = canon_pointer[1:].split("/")
    parts = [p.replace("~1", "/").replace("~0", "~") for p in raw_parts]
    if not parts:
        return (canon_pointer, None)
    cur: Any = root
    for seg in parts[:-1]:
        if isinstance(cur, dict):
            nxt = cur.get(seg)
            if not isinstance(nxt, (dict, list)):
                if value is None:
                    return (canon_pointer, None)
                nxt = {}
                cur[seg] = nxt
            cur = nxt
        elif isinstance(cur, list):
            idx = _parse_rfc6901_array_index(seg)
            if idx is None or idx >= len(cur):
                return (canon_pointer, None)
            nxt = cur[idx]
            if not isinstance(nxt, (dict, list)):
                if value is None:
                    return (canon_pointer, None)
                nxt = {}
                cur[idx] = nxt
            cur = nxt
        else:
            return (canon_pointer, None)
    last = parts[-1]
    parent_ptr = "" if len(raw_parts) == 1 else "/" + "/".join(raw_parts[:-1])
    if isinstance(cur, dict):
        if value is None:
            cur.pop(last, None)
        else:
            cur[last] = value
        return (canon_pointer, None)
    if isinstance(cur, list):
        idx = _parse_rfc6901_array_index(last)
        if idx is not None:
            if value is None:
                if idx < len(cur):
                    cur.pop(idx)
                    return (parent_ptr or "/", idx)
            else:
                if idx < len(cur):
                    cur[idx] = value
                elif idx == len(cur):
                    cur.append(value)
            return (canon_pointer, None)
        if last == "-" and value is not None:
            new_idx = len(cur)
            cur.append(value)
            return (f"{parent_ptr}/{new_idx}", None)
    return (canon_pointer, None)


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


def _pointer_ancestors(pointer: str, max_segments: int = DEFAULT_MAX_DEPTH + 4) -> list[str]:
    """Return up to max_segments non-root ancestor prefixes of an RFC 6901 pointer, including itself."""
    if not isinstance(pointer, str) or not pointer.startswith("/") or pointer == "/":
        return []
    if pointer.count("/") <= max_segments:
        pointer = _canonicalize_json_pointer(pointer, max_segments=max_segments)
        ancestors: list[str] = []
        pos = 1
        n = len(pointer)
        while pos <= n:
            slash = pointer.find("/", pos)
            if slash == -1:
                if pointer != "/":
                    ancestors.append(pointer)
                break
            prefix = pointer[:slash]
            if prefix != "/":
                ancestors.append(prefix)
            pos = slash + 1
        return ancestors
    ancestors = []
    pos = 1
    cur = ""
    n = len(pointer)
    for _ in range(max_segments):
        if pos > n:
            break
        slash = pointer.find("/", pos)
        seg = pointer[pos:] if slash == -1 else pointer[pos:slash]
        if "~" in seg:
            seg = seg.replace("~1", "/").replace("~0", "~").replace("~", "~0").replace("/", "~1")
        cur = f"{cur}/{seg}"
        if cur != "/":
            ancestors.append(cur)
        if slash == -1:
            break
        pos = slash + 1
    return ancestors


def _pointers_overlap(p1: str, p2: str, max_segments: int = DEFAULT_MAX_DEPTH + 4) -> bool:
    """Return True when two RFC 6901 JSON Pointers are identical or ancestor/descendant."""
    p1 = _canonicalize_json_pointer(p1, max_segments=max_segments)
    p2 = _canonicalize_json_pointer(p2, max_segments=max_segments)
    if p1 in {"", "/"} or p2 in {"", "/"}:
        return True
    if p1 == p2:
        return True
    l1, l2 = len(p1), len(p2)
    if l1 > l2:
        return p1.startswith(p2) and p1[l2] == "/"
    if l2 > l1:
        return p2.startswith(p1) and p2[l1] == "/"
    return False


def _pointer_affected_by_update(
    target_ptr: str,
    update_ptr: str,
    popped_idx: int | None,
    max_segments: int = DEFAULT_MAX_DEPTH + 4,
) -> bool:
    """Return True when target_ptr overlaps update_ptr and is not an unshifted sibling before popped_idx."""
    if not _pointers_overlap(target_ptr, update_ptr, max_segments=max_segments):
        return False
    if popped_idx is not None:
        cidx = _child_index_under(update_ptr, target_ptr, max_segments=max_segments)
        if cidx is not None and cidx < popped_idx:
            return False
    return True


def _extract_url_slot_pointers(
    val: Any, max_segments: int = DEFAULT_MAX_DEPTH + 4
) -> tuple[frozenset[str], frozenset[str]]:
    """Extract (absolute_pointers, relative_pointers) referenced by a URL slot value."""
    if not isinstance(val, dict):
        return frozenset(), frozenset()
    abs_ptrs: set[str] = set()
    rel_ptrs: set[str] = set()
    if "@call" in val or "call" in val:
        fn_name = val.get("@call") if "@call" in val else val.get("call")
        args = val.get("args")
        if fn_name == "formatString" and isinstance(args, dict) and isinstance(args.get("value"), str):
            status, _parts, exprs, _pfx_ne, _ph, _cost, _emp = _parse_format_string_template(args["value"])
            if status == "ok":
                for raw_expr in exprs:
                    expr = _canonicalize_json_pointer(raw_expr, max_segments=max_segments)
                    if expr.startswith("/"):
                        abs_ptrs.add(expr)
                    elif expr:
                        rel_ptrs.add(expr)
    else:
        ptr = val.get("@path") if "@path" in val else val.get("path")
        if isinstance(ptr, str) and ptr:
            canon = _canonicalize_json_pointer(ptr, max_segments=max_segments)
            if canon.startswith("/"):
                abs_ptrs.add(canon)
            else:
                rel_ptrs.add(canon)
    return frozenset(abs_ptrs), frozenset(rel_ptrs)


def _is_prefixless_format_string_url(val: Any) -> bool:
    """Return True when val is a formatString URL call starting immediately with '${'."""
    if not isinstance(val, dict):
        return False
    fn_name = val.get("@call") if "@call" in val else val.get("call")
    if fn_name != "formatString":
        return False
    args = val.get("args")
    if not isinstance(args, dict):
        return False
    tpl = args.get("value")
    if not isinstance(tpl, str) or "${" not in tpl:
        return False
    return not tpl.split("${", 1)[0].strip()


_MAX_TEMPLATE_ABS_RESCAN_EVALS = 10_000
_MAX_TEMPLATE_RESCAN_EVALS = 50_000


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


def _resolve_json_pointer(
    data: Any, pointer: str, max_segments: int = DEFAULT_MAX_DEPTH + 4
) -> tuple[bool, Any]:
    """Resolve an RFC 6901 JSON Pointer inside a surface dataModel."""
    if not isinstance(pointer, str):
        return False, None
    if pointer in {"", "/"}:
        return True, data
    if not pointer.startswith("/"):
        return False, None
    if pointer.find("/", 1) == -1 and "~" not in pointer:
        seg = pointer[1:]
        if isinstance(data, dict):
            if seg in data:
                return True, data[seg]
            return False, None
        if isinstance(data, list):
            idx = _parse_rfc6901_array_index(seg)
            if idx is None or idx >= len(data):
                return False, None
            return True, data[idx]
        return False, None
    if len(pointer) > max_segments and pointer.count("/") > max_segments:
        return False, None
    cur = data
    for raw_seg in pointer[1:].split("/"):
        seg = raw_seg.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        elif isinstance(cur, list):
            idx = _parse_rfc6901_array_index(seg)
            if idx is None or idx >= len(cur):
                return False, None
            cur = cur[idx]
        else:
            return False, None
    return True, cur


def _resolve_pointer_with_context(
    data_model: dict[str, Any],
    pointer: str,
    item_ctx: Any = None,
    max_segments: int = DEFAULT_MAX_DEPTH + 4,
) -> tuple[bool, Any]:
    """Resolve absolute pointers against data_model or relative pointers against item_ctx."""
    if not isinstance(pointer, str) or not pointer:
        return False, None
    if pointer.startswith("/"):
        return _resolve_json_pointer(data_model, pointer, max_segments)
    if item_ctx is None:
        return False, None
    if "/" not in pointer and "~" not in pointer:
        if isinstance(item_ctx, dict):
            if pointer in item_ctx:
                return True, item_ctx[pointer]
            return False, None
        if isinstance(item_ctx, list):
            idx = _parse_rfc6901_array_index(pointer)
            if idx is None or idx >= len(item_ctx):
                return False, None
            return True, item_ctx[idx]
        return False, None
    if len(pointer) >= max_segments and pointer.count("/") >= max_segments:
        return False, None
    cur = item_ctx
    for raw_seg in pointer.split("/"):
        seg = raw_seg.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        elif isinstance(cur, list):
            idx = _parse_rfc6901_array_index(seg)
            if idx is None or idx >= len(cur):
                return False, None
            cur = cur[idx]
        else:
            return False, None
    return True, cur


_FORMAT_EXPR_RE = re.compile(r"\$\{([^}]+)\}")
_MAX_FORMAT_URL_PLACEHOLDERS = 64
_MAX_FORMAT_URL_NON_DATA_LEN = 16_384
_SAFE_URL_CACHE_MAX = 4096


@lru_cache(maxsize=4096)
def _parse_format_string_template(
    tpl: str,
) -> tuple[str, tuple[str, ...], tuple[str, ...], bool, str, int, str]:
    """Parse and validate a formatString URL template once into literal segments and pointer expressions."""
    if len(tpl) > _MAX_FORMAT_URL_NON_DATA_LEN and not tpl[:16].lstrip().lower().startswith("data:"):
        return ("err_too_long", (), (), False, "", 1, "")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in tpl):
        return ("err_ctrl", (), (), False, "", 1, "")
    if "${" not in tpl:
        return ("static", (tpl,), (), bool(tpl.strip()), tpl, 1, tpl)
    if r"\${" in tpl:
        return ("err_esc", (), (), False, "", 1, "")
    parts: list[str] = []
    exprs: list[str] = []
    pos = 0
    while True:
        start = tpl.find("${", pos)
        if start == -1:
            parts.append(tpl[pos:])
            break
        if len(exprs) >= _MAX_FORMAT_URL_PLACEHOLDERS:
            return ("err_too_many_exprs", (), (), False, "", 1, "")
        end = tpl.find("}", start + 2)
        if end == -1:
            return ("err_unclosed", (), (), False, "", 1, "")
        inner = tpl[start + 2 : end]
        if not _SIMPLE_FORMAT_PTR_RE.fullmatch(inner):
            return ("err_expr", (inner,), (), False, "", 1, "")
        parts.append(tpl[pos:start])
        exprs.append(inner)
        pos = end + 1
    parts_t = tuple(parts)
    exprs_t = tuple(exprs)
    eval_cost = max(1, len(exprs_t)) + (len(tpl) // 1024)
    empty_single = f"{parts_t[0]}{parts_t[1]}" if len(exprs_t) == 1 else ""
    return ("ok", parts_t, exprs_t, bool(parts_t[0].strip()), "placeholder".join(parts_t), eval_cost, empty_single)


def _check_url_with_cache(
    candidate_url: str,
    validator_fn: Any,
    safe_url_cache: set[str] | None,
    uncached_counter: list[int] | None,
) -> tuple[bool, str | None]:
    """Validate candidate_url using validator_fn with optional bounded non-freezing safe-URL memoization."""
    if safe_url_cache is not None and candidate_url in safe_url_cache:
        return True, None
    if uncached_counter is not None:
        uncached_counter[0] += 1
    ok_u, reason_u = validator_fn(candidate_url)
    if ok_u and safe_url_cache is not None:
        if len(safe_url_cache) >= _SAFE_URL_CACHE_MAX:
            safe_url_cache.clear()
        safe_url_cache.add(candidate_url)
    return ok_u, reason_u


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
    is_historical_snapshot: bool = False,
    is_superseded: bool = False,
    safe_url_cache: set[str] | None = None,
    uncached_counter: list[int] | None = None,
    max_segments: int = DEFAULT_MAX_DEPTH + 4,
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

        status, parts, exprs, prefix_nonempty, placeholder_str, _cost, _emp = _parse_format_string_template(tpl)
        if status == "err_too_long":
            _add_issue(
                errors,
                code,
                block_index,
                path,
                f"formatString {kind} URL template exceeds maximum length ({_MAX_FORMAT_URL_NON_DATA_LEN} characters).",
            )
            return
        if status == "err_too_many_exprs":
            _add_issue(
                errors,
                code,
                block_index,
                path,
                f"formatString {kind} URL template exceeds maximum placeholder count ({_MAX_FORMAT_URL_PLACEHOLDERS}).",
            )
            return
        if status == "err_ctrl":
            _add_issue(
                errors,
                code,
                block_index,
                path,
                f"formatString {kind} URL template contains disallowed control characters.",
            )
            return
        if status == "static":
            ok, reason = _check_url_with_cache(tpl, validator_fn, safe_url_cache, uncached_counter)
            if not ok:
                _add_issue(errors, code, block_index, path, reason or f"Unsafe {kind} URL in formatString.")
            return
        if status == "err_esc":
            _add_issue(
                errors,
                code,
                block_index,
                path,
                f"formatString {kind} URL template must not contain escaped '\\${{' sequences.",
            )
            return
        if status == "err_unclosed":
            _add_issue(
                errors,
                code,
                block_index,
                path,
                f"formatString {kind} URL template contains an unclosed '${{' expression.",
            )
            return
        if status == "err_expr":
            inner = parts[0]
            _add_issue(
                errors,
                code,
                block_index,
                path,
                f"formatString {kind} URL placeholder '${{{inner}}}' must be a simple JSON Pointer path.",
            )
            return

        # Interpolate resolvable placeholders in a single pass and validate placeholder, resolved, and empty-unresolved forms.
        if len(exprs) == 1:
            found, val = _resolve_pointer_with_context(
                data_model, exprs[0], item_ctx, max_segments=max_segments
            )
            if found:
                all_resolved = True
                any_resolved = True
                s_val = "" if val is None else str(val)
                resolved_str = f"{parts[0]}{s_val}{parts[1]}"
                empty_unresolved_str = resolved_str
            else:
                all_resolved = False
                any_resolved = False
                resolved_str = placeholder_str
                empty_unresolved_str = f"{parts[0]}{parts[1]}"
        else:
            all_resolved = True
            any_resolved = False
            res_chunks: list[str] = [parts[0]]
            emp_chunks: list[str] = [parts[0]]
            for idx_e, expr in enumerate(exprs):
                found, val = _resolve_pointer_with_context(
                    data_model, expr, item_ctx, max_segments=max_segments
                )
                if found:
                    any_resolved = True
                    s_val = "" if val is None else str(val)
                    res_chunks.append(s_val)
                    emp_chunks.append(s_val)
                else:
                    all_resolved = False
                    res_chunks.append("placeholder")
                res_chunks.append(parts[idx_e + 1])
                emp_chunks.append(parts[idx_e + 1])
            resolved_str = "".join(res_chunks)
            empty_unresolved_str = resolved_str if all_resolved else "".join(emp_chunks)

        if not prefix_nonempty:
            if all_resolved:
                ok, reason = _check_url_with_cache(resolved_str, validator_fn, safe_url_cache, uncached_counter)
                if not ok:
                    _add_issue(errors, code, block_index, path, reason or f"Unsafe resolved {kind} URL.")
            elif is_historical_snapshot:
                if any_resolved:
                    ok, reason = _check_url_with_cache(resolved_str, validator_fn, safe_url_cache, uncached_counter)
                    if not ok:
                        _add_issue(errors, code, block_index, path, reason or f"Unsafe resolved {kind} URL.")
                    elif empty_unresolved_str != resolved_str:
                        ok_emp, reason_emp = _check_url_with_cache(
                            empty_unresolved_str, validator_fn, safe_url_cache, uncached_counter
                        )
                        if not ok_emp:
                            _add_issue(
                                errors,
                                code,
                                block_index,
                                path,
                                reason_emp or f"Unsafe {kind} URL when unresolved placeholders evaluate empty.",
                            )
            else:
                _add_issue(
                    errors,
                    code,
                    block_index,
                    path,
                    f"formatString in {kind} URL must start with a static allowed scheme/prefix.",
                )
            return

        # Validate placeholder, resolved, and empty-unresolved candidate strings unconditionally
        ok_tpl, reason_tpl = _check_url_with_cache(placeholder_str, validator_fn, safe_url_cache, uncached_counter)
        if not ok_tpl:
            _add_issue(errors, code, block_index, path, reason_tpl or f"Unsafe {kind} URL template in formatString.")
            return
        if is_superseded:
            return
        ok_res, reason_res = _check_url_with_cache(resolved_str, validator_fn, safe_url_cache, uncached_counter)
        if not ok_res:
            _add_issue(errors, code, block_index, path, reason_res or f"Unsafe resolved {kind} URL.")
            return
        if empty_unresolved_str != resolved_str:
            ok_emp, reason_emp = _check_url_with_cache(
                empty_unresolved_str, validator_fn, safe_url_cache, uncached_counter
            )
            if not ok_emp:
                _add_issue(
                    errors,
                    code,
                    block_index,
                    path,
                    reason_emp or f"Unsafe {kind} URL when unresolved placeholders evaluate empty.",
                )
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
    effective_catalog_id: str | None = None,
    allow_user_activation: bool = False,
    item_ctx: Any = None,
    is_historical_snapshot: bool = False,
    is_superseded: bool = False,
    template_validated_url_paths: frozenset[str] | None = None,
    max_segments: int = DEFAULT_MAX_DEPTH + 4,
    safe_open_urls: set[str] | None = None,
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
                effective_catalog_id=effective_catalog_id,
                allow_user_activation=False,
                item_ctx=item_ctx,
                is_historical_snapshot=is_historical_snapshot,
                is_superseded=is_superseded,
                template_validated_url_paths=template_validated_url_paths,
                max_segments=max_segments,
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
        raw_fn_cat: Any = None
        if "catalogId" in call_val:
            raw_fn_cat = call_val.get("catalogId")
            if not isinstance(raw_fn_cat, str) or not raw_fn_cat.strip():
                _add_issue(
                    errors,
                    "INVALID_CATALOG_ID",
                    block_index,
                    f"{path}.catalogId",
                    "FunctionCall.catalogId must be a non-empty string when provided.",
                )
            elif raw_fn_cat == BROKEN_V09_CATALOG_ID:
                _add_issue(
                    warnings,
                    "BROKEN_CATALOG_URI",
                    block_index,
                    f"{path}.catalogId",
                    f"Catalog URI '{BROKEN_V09_CATALOG_ID}' returns HTTP 404 on a2ui.org; use canonical catalogs/basic/catalog.json.",
                )
        effective_fn_cat = (
            raw_fn_cat
            if isinstance(raw_fn_cat, str) and raw_fn_cat.strip()
            else effective_catalog_id
        )
        is_custom_fn_cat = _is_custom_catalog_id(effective_fn_cat, catalog_id or "")
        fn_spec = None if is_custom_fn_cat else (catalog_function_specs or {}).get(fn_name)
        if fn_name != "@index" and catalog_functions and fn_name not in catalog_functions:
            if not is_custom_fn_cat:
                _add_issue(
                    warnings if not strict else errors,
                    "UNKNOWN_FUNCTION",
                    block_index,
                    path,
                    f"Function '{fn_name}' is not in the Basic Catalog.",
                )
        requires_activation = bool(fn_spec and fn_spec.get("requiresUserActivation")) or fn_name == "openUrl"
        if requires_activation and not allow_user_activation:
            _add_issue(
                errors,
                "INVALID_FUNCTION_CALL_SITE",
                block_index,
                path,
                f"Function '{fn_name}' requires user activation and is only permitted in Button.action.functionCall.",
            )
        args = call_val.get("args")
        req_args = list(fn_spec.get("requiredArgs", [])) if fn_spec else []
        if fn_name == "openUrl" and "url" not in req_args:
            req_args.append("url")
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
                open_url_path = f"{path}.args.url"
                _validate_open_url_arg(
                    args.get("url"),
                    block_index,
                    open_url_path,
                    errors,
                    data_model,
                    strict=strict,
                    warnings=warnings,
                    item_ctx=item_ctx,
                    is_historical_snapshot=is_historical_snapshot
                    or (
                        template_validated_url_paths is not None
                        and open_url_path in template_validated_url_paths
                    ),
                    is_superseded=is_superseded,
                    safe_url_cache=safe_open_urls,
                    max_segments=max_segments,
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
                    effective_catalog_id=effective_catalog_id,
                    allow_user_activation=False,
                    item_ctx=item_ctx,
                    is_historical_snapshot=is_historical_snapshot,
                    is_superseded=is_superseded,
                    template_validated_url_paths=template_validated_url_paths,
                    max_segments=max_segments,
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
            effective_catalog_id=effective_catalog_id,
            allow_user_activation=False,
            item_ctx=item_ctx,
            is_historical_snapshot=is_historical_snapshot,
            is_superseded=is_superseded,
            max_segments=max_segments,
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
    is_historical_snapshot: bool = False,
    is_superseded: bool = False,
    safe_url_cache: set[str] | None = None,
    uncached_counter: list[int] | None = None,
    max_segments: int = DEFAULT_MAX_DEPTH + 4,
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
                is_historical_snapshot=is_historical_snapshot,
                is_superseded=is_superseded,
                safe_url_cache=safe_url_cache,
                uncached_counter=uncached_counter,
                max_segments=max_segments,
            )
            return
        keys = set(raw_url_val.keys())
        if keys in ({"@path"}, {"path"}):
            ptr = raw_url_val.get("@path") if "@path" in raw_url_val else raw_url_val.get("path")
            if isinstance(ptr, str) and ptr:
                found, resolved = _resolve_pointer_with_context(
                    data_model, ptr, item_ctx, max_segments=max_segments
                )
                if found:
                    candidate = resolved
                else:
                    return
            else:
                _add_issue(errors, "UNSAFE_OPEN_URL", block_index, path, "openUrl DataBinding path must be a non-empty string.")
                return
        else:
            _add_issue(errors, "UNSAFE_OPEN_URL", block_index, path, "openUrl target must be a URL string, DataBinding, or safe formatString call.")
            return
    if safe_url_cache is not None and type(candidate) is str and candidate in safe_url_cache:
        return
    if uncached_counter is not None:
        uncached_counter[0] += 1
    ok, reason = validate_open_url(candidate)
    if ok:
        if safe_url_cache is not None and type(candidate) is str:
            if len(safe_url_cache) >= _SAFE_URL_CACHE_MAX:
                safe_url_cache.clear()
            safe_url_cache.add(candidate)
        return
    _add_issue(errors, "UNSAFE_OPEN_URL", block_index, path, reason or "Unsafe openUrl target.")


def _validate_media_prop(
    val: Any,
    block_index: int,
    path: str,
    errors: list[dict[str, Any]],
    data_model: dict[str, Any],
    *,
    version: str = "1.0",
    strict: bool = True,
    warnings: list[dict[str, Any]] | None = None,
    item_ctx: Any = None,
    is_historical_snapshot: bool = False,
    is_superseded: bool = False,
    safe_url_cache: set[str] | None = None,
    uncached_counter: list[int] | None = None,
    max_segments: int = DEFAULT_MAX_DEPTH + 4,
) -> None:
    warn_bucket = warnings if warnings is not None else errors
    candidate: Any = val
    if isinstance(val, dict):
        if version == "0.8":
            keys = set(val.keys())
            if not keys or not keys.issubset({"literalString", "path"}):
                _add_issue(
                    errors,
                    "UNSAFE_MEDIA_URL",
                    block_index,
                    path,
                    "v0.8 media URL object must contain only 'literalString' and/or 'path'.",
                )
                return
            if "literalString" in val:
                lit_val = val["literalString"]
                lit_ok = False
                if safe_url_cache is not None and type(lit_val) is str and lit_val in safe_url_cache:
                    lit_ok = True
                else:
                    if uncached_counter is not None:
                        uncached_counter[0] += 1
                    ok_lit, reason_lit = validate_media_url(lit_val)
                    if ok_lit:
                        lit_ok = True
                        if safe_url_cache is not None and type(lit_val) is str:
                            if len(safe_url_cache) >= _SAFE_URL_CACHE_MAX:
                                safe_url_cache.clear()
                            safe_url_cache.add(lit_val)
                    else:
                        _add_issue(errors, "UNSAFE_MEDIA_URL", block_index, path, reason_lit or "Unsafe media URL.")
                if not lit_ok:
                    return
                if "path" not in val:
                    return
            ptr = val.get("path")
            if not isinstance(ptr, str) or not ptr:
                _add_issue(errors, "UNSAFE_MEDIA_URL", block_index, path, "v0.8 media URL 'path' must be a non-empty string.")
                return
            found, resolved = _resolve_pointer_with_context(
                data_model, ptr, item_ctx, max_segments=max_segments
            )
            if not found:
                return
            candidate = resolved
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
                is_historical_snapshot=is_historical_snapshot,
                is_superseded=is_superseded,
                safe_url_cache=safe_url_cache,
                uncached_counter=uncached_counter,
                max_segments=max_segments,
            )
            return
        elif "literalString" in val:
            _add_issue(
                errors,
                "UNSAFE_MEDIA_URL",
                block_index,
                path,
                f"Legacy 'literalString' wrapper is not valid for media URLs in A2UI v{version}.",
            )
            return
        else:
            keys = set(val.keys())
            if keys in ({"@path"}, {"path"}):
                ptr = val.get("@path") if "@path" in val else val.get("path")
                if isinstance(ptr, str) and ptr:
                    found, resolved = _resolve_pointer_with_context(
                        data_model, ptr, item_ctx, max_segments=max_segments
                    )
                    if found:
                        candidate = resolved
                    else:
                        return
                else:
                    _add_issue(errors, "UNSAFE_MEDIA_URL", block_index, path, "Media URL DataBinding path must be a non-empty string.")
                    return
            else:
                _add_issue(errors, "UNSAFE_MEDIA_URL", block_index, path, "Media URL must be a string, DataBinding, or safe formatString call.")
                return
    if safe_url_cache is not None and type(candidate) is str and candidate in safe_url_cache:
        return
    if uncached_counter is not None:
        uncached_counter[0] += 1
    ok, reason = validate_media_url(candidate)
    if ok:
        if safe_url_cache is not None and type(candidate) is str:
            if len(safe_url_cache) >= _SAFE_URL_CACHE_MAX:
                safe_url_cache.clear()
            safe_url_cache.add(candidate)
        return
    _add_issue(errors, "UNSAFE_MEDIA_URL", block_index, path, reason or "Unsafe media URL.")


def _iter_open_url_slots(obj: Any, base_path: str) -> list[tuple[str, Any]]:
    """Collect (path, url_arg) pairs for every openUrl FunctionCall inside a component."""
    found: list[tuple[str, Any]] = []
    stack: list[tuple[Any, str]] = [(obj, base_path)]
    while stack:
        cur, cur_path = stack.pop()
        if isinstance(cur, dict):
            fn_name = cur.get("@call") if "@call" in cur else cur.get("call")
            if fn_name == "openUrl" and isinstance(cur.get("args"), dict) and "url" in cur["args"]:
                found.append((f"{cur_path}.args.url", cur["args"]["url"]))
            for k, v in cur.items():
                if isinstance(v, (dict, list)):
                    stack.append((v, f"{cur_path}.{k}"))
        elif isinstance(cur, list):
            for idx, item in enumerate(cur):
                if isinstance(item, (dict, list)):
                    stack.append((item, f"{cur_path}[{idx}]"))
    return found


def _append_unique_issues(
    target: list[dict[str, Any]],
    new_issues: list[dict[str, Any]],
    seen: set[tuple[str, int, str, str]],
) -> None:
    for issue in new_issues:
        key = (issue["code"], issue["blockIndex"], issue["path"], issue["message"])
        if key not in seen:
            seen.add(key)
            target.append(issue)


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
    effective_catalog_id: str | None = None,
    item_ctx: Any = None,
    is_historical_snapshot: bool = False,
    is_superseded: bool = False,
    template_validated_url_paths: frozenset[str] | None = None,
    max_segments: int = DEFAULT_MAX_DEPTH + 4,
    safe_open_urls: set[str] | None = None,
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
                effective_catalog_id=effective_catalog_id,
                allow_user_activation=False,
                item_ctx=item_ctx,
                is_historical_snapshot=is_historical_snapshot,
                is_superseded=is_superseded,
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
                        effective_catalog_id=effective_catalog_id,
                        allow_user_activation=False,
                        item_ctx=item_ctx,
                        is_historical_snapshot=is_historical_snapshot,
                        is_superseded=is_superseded,
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
            effective_catalog_id=effective_catalog_id,
            allow_user_activation=True,
            item_ctx=item_ctx,
            is_historical_snapshot=is_historical_snapshot,
            is_superseded=is_superseded,
            template_validated_url_paths=template_validated_url_paths,
            max_segments=max_segments,
            safe_open_urls=safe_open_urls,
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
    surface_catalog_id: str | None = None,
    template_validated_url_paths: frozenset[str] | None = None,
    max_segments: int = DEFAULT_MAX_DEPTH + 4,
    safe_media_urls: set[str] | None = None,
    safe_open_urls: set[str] | None = None,
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

    # Pre-compute the winning (b_idx, idx) per cid across component_batches (last-write-wins)
    winning_loc: dict[str, tuple[int, int]] = {}
    for wb_idx, wbatch in enumerate(component_batches):
        wbatch_seen: set[str] = set()
        for widx, wcomp in enumerate(wbatch):
            if not isinstance(wcomp, dict):
                continue
            wcid = wcomp.get("id")
            if not isinstance(wcid, str) or not wcid or wcid in wbatch_seen:
                continue
            wbatch_seen.add(wcid)
            if version == "0.8":
                wctype, _wprops = _extract_v08_component(wcomp)
                if not wctype:
                    continue
            else:
                wctype = wcomp.get("component")
                if not isinstance(wctype, str) or not wctype:
                    continue
            if wctype == "Surface":
                continue
            winning_loc[wcid] = (wb_idx, widx)

    for b_idx, batch in enumerate(component_batches):
        batch_seen_ids: set[str] = set()
        for idx, comp in enumerate(batch):
            cpath = (
                f"surface:{surface_id}.components[{idx}]"
                if b_idx == 0
                else f"surface:{surface_id}.batch[{b_idx}].components[{idx}]"
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
            is_superseded = winning_loc.get(cid) != (b_idx, idx)
            comp_dm = {} if is_superseded else data_model
            comp_hist = is_superseded
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

            # Basic Catalog schema validation when using default catalog (inherits createSurface.catalogId)
            raw_comp_cat = comp.get("@catalogId")
            if "@catalogId" in comp:
                if not isinstance(raw_comp_cat, str) or not raw_comp_cat.strip():
                    _add_issue(
                        errors,
                        "INVALID_CATALOG_ID",
                        block_index,
                        f"{cpath}.@catalogId",
                        "Component '@catalogId' must be a non-empty string when provided.",
                    )
                elif raw_comp_cat == BROKEN_V09_CATALOG_ID:
                    _add_issue(
                        warnings,
                        "BROKEN_CATALOG_URI",
                        block_index,
                        f"{cpath}.@catalogId",
                        f"Catalog URI '{BROKEN_V09_CATALOG_ID}' returns HTTP 404 on a2ui.org; use canonical catalogs/basic/catalog.json.",
                    )
            if "catalogId" in comp:
                raw_bare_cat = comp.get("catalogId")
                if not isinstance(raw_bare_cat, str) or not raw_bare_cat.strip():
                    _add_issue(
                        errors,
                        "INVALID_CATALOG_ID",
                        block_index,
                        f"{cpath}.catalogId",
                        "Component 'catalogId' must be a non-empty string when provided.",
                    )
                elif raw_bare_cat == BROKEN_V09_CATALOG_ID:
                    _add_issue(
                        warnings,
                        "BROKEN_CATALOG_URI",
                        block_index,
                        f"{cpath}.catalogId",
                        f"Catalog URI '{BROKEN_V09_CATALOG_ID}' returns HTTP 404 on a2ui.org; use canonical catalogs/basic/catalog.json.",
                    )
            effective_comp_catalog = (
                raw_comp_cat
                if isinstance(raw_comp_cat, str) and raw_comp_cat.strip()
                else surface_catalog_id
            )
            is_custom_catalog = _is_custom_catalog_id(effective_comp_catalog, canonical_catalog_id)
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
                            extra_tab = set(tab.keys()) - {"title", "child"}
                            if extra_tab:
                                _add_issue(
                                    errors if strict else warnings,
                                    "UNKNOWN_TAB_ITEM_PROPERTY",
                                    block_index,
                                    f"{cpath}.tabs[{tidx}]",
                                    f"Unexpected properties on Tabs.tabs[{tidx}]: {sorted(extra_tab)}.",
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
                        else:
                            extra_opt = set(opt.keys()) - {"label", "value"}
                            if extra_opt:
                                _add_issue(
                                    errors if strict else warnings,
                                    "UNKNOWN_CHOICE_OPTION_PROPERTY",
                                    block_index,
                                    f"{cpath}.options[{oidx}]",
                                    f"Unexpected properties on ChoicePicker.options[{oidx}]: {sorted(extra_opt)}.",
                                )

                # Validate Icon.name shape (enum string, DataBinding, or {"svgPath": DynamicString})
                if comp_type == "Icon" and "name" in props and version != "0.8":
                    iname = props["name"]
                    if isinstance(iname, dict):
                        if "svgPath" in iname:
                            extra_icon = set(iname.keys()) - {"svgPath"}
                            if extra_icon:
                                _add_issue(
                                    errors,
                                    "INVALID_ICON_NAME",
                                    block_index,
                                    f"{cpath}.name",
                                    f"Icon.name with 'svgPath' must not contain extra properties: {sorted(extra_icon)}.",
                                )
                            svg_val = iname["svgPath"]
                            is_valid_svg_dyn = isinstance(svg_val, str) or (
                                isinstance(svg_val, dict)
                                and (
                                    set(svg_val.keys()) == {"@path"}
                                    or (
                                        set(svg_val.keys()) == {"path"}
                                        and isinstance(svg_val.get("path"), str)
                                    )
                                    or "@call" in svg_val
                                    or (
                                        "call" in svg_val
                                        and isinstance(svg_val.get("call"), str)
                                    )
                                )
                            )
                            if not is_valid_svg_dyn:
                                _add_issue(
                                    errors,
                                    "INVALID_ICON_NAME",
                                    block_index,
                                    f"{cpath}.name.svgPath",
                                    "Icon.name.svgPath must be a string, DataBinding, or FunctionCall.",
                                )
                        elif not (
                            set(iname.keys()) == {"@path"}
                            or (set(iname.keys()) == {"path"} and isinstance(iname.get("path"), str))
                        ):
                            _add_issue(
                                errors,
                                "INVALID_ICON_NAME",
                                block_index,
                                f"{cpath}.name",
                                "Icon.name object must be a DataBinding or {'svgPath': DynamicString}.",
                            )
                    elif not isinstance(iname, str):
                        _add_issue(
                            errors,
                            "INVALID_ICON_NAME",
                            block_index,
                            f"{cpath}.name",
                            "Icon.name must be an icon name string, DataBinding, or {'svgPath': DynamicString}.",
                        )
            elif not is_custom_catalog and comp_type not in catalog_components:
                _add_issue(
                    warnings if not strict else errors,
                    "UNKNOWN_COMPONENT_TYPE",
                    block_index,
                    cpath,
                    f"Component type '{comp_type}' is not in the Basic Catalog v{version}.",
                )

            # Unconditional security & dynamic checks (even when @catalogId or createSurface.catalogId overrides catalog)
            acc_key = "@accessibility" if "@accessibility" in props else ("accessibility" if "accessibility" in props else None)
            if acc_key is not None:
                acc_val = props[acc_key]
                apath = f"{cpath}.{acc_key}"
                if not isinstance(acc_val, dict):
                    _add_issue(
                        errors,
                        "INVALID_ACCESSIBILITY",
                        block_index,
                        apath,
                        f"{acc_key} must be an object.",
                    )
                else:
                    extra_acc = set(acc_val.keys()) - {"label", "description", "hidden", "live"}
                    if extra_acc:
                        _add_issue(
                            errors,
                            "INVALID_ACCESSIBILITY",
                            block_index,
                            apath,
                            f"Unexpected properties on {acc_key}: {sorted(extra_acc)}.",
                        )
                    for ak in ("label", "description", "hidden"):
                        if ak in acc_val:
                            _validate_dynamic_value(
                                acc_val[ak],
                                version=version,
                                strict=strict,
                                block_index=block_index,
                                path=f"{apath}.{ak}",
                                errors=errors,
                                warnings=warnings,
                                catalog_functions=catalog_functions,
                                data_model=comp_dm,
                                catalog_function_specs=catalog_function_specs,
                                catalog_id=canonical_catalog_id,
                                effective_catalog_id=effective_comp_catalog,
                                allow_user_activation=False,
                                is_historical_snapshot=comp_hist,
                                is_superseded=is_superseded,
                            )
                    if "live" in acc_val:
                        live_val = acc_val["live"]
                        if not isinstance(live_val, str) or live_val not in {"off", "polite", "assertive"}:
                            _add_issue(
                                errors,
                                "INVALID_ACCESSIBILITY",
                                block_index,
                                f"{apath}.live",
                                f"{acc_key}.live must be one of ['off', 'polite', 'assertive'].",
                            )

            if comp_type == "Tabs" and isinstance(props.get("tabs"), list):
                for tidx, tab in enumerate(props["tabs"]):
                    if isinstance(tab, dict) and "title" in tab:
                        _validate_dynamic_value(
                            tab["title"],
                            version=version,
                            strict=strict,
                            block_index=block_index,
                            path=f"{cpath}.tabs[{tidx}].title",
                            errors=errors,
                            warnings=warnings,
                            catalog_functions=catalog_functions,
                            data_model=comp_dm,
                            catalog_function_specs=catalog_function_specs,
                            catalog_id=canonical_catalog_id,
                            effective_catalog_id=effective_comp_catalog,
                            allow_user_activation=False,
                            is_historical_snapshot=comp_hist,
                            is_superseded=is_superseded,
                        )

            if comp_type == "ChoicePicker" and isinstance(props.get("options"), list):
                for oidx, opt in enumerate(props["options"]):
                    if isinstance(opt, dict) and "label" in opt:
                        _validate_dynamic_value(
                            opt["label"],
                            version=version,
                            strict=strict,
                            block_index=block_index,
                            path=f"{cpath}.options[{oidx}].label",
                            errors=errors,
                            warnings=warnings,
                            catalog_functions=catalog_functions,
                            data_model=comp_dm,
                            catalog_function_specs=catalog_function_specs,
                            catalog_id=canonical_catalog_id,
                            effective_catalog_id=effective_comp_catalog,
                            allow_user_activation=False,
                            is_historical_snapshot=comp_hist,
                            is_superseded=is_superseded,
                        )

            if comp_type == "Icon" and "name" in props:
                iname = props["name"]
                if isinstance(iname, dict) and "svgPath" in iname:
                    _validate_dynamic_value(
                        iname["svgPath"],
                        version=version,
                        strict=strict,
                        block_index=block_index,
                        path=f"{cpath}.name.svgPath",
                        errors=errors,
                        warnings=warnings,
                        catalog_functions=catalog_functions,
                        data_model=comp_dm,
                        catalog_function_specs=catalog_function_specs,
                        catalog_id=canonical_catalog_id,
                        effective_catalog_id=effective_comp_catalog,
                        allow_user_activation=False,
                        is_historical_snapshot=comp_hist,
                        is_superseded=is_superseded,
                    )
                elif isinstance(iname, dict):
                    _validate_dynamic_value(
                        iname,
                        version=version,
                        strict=strict,
                        block_index=block_index,
                        path=f"{cpath}.name",
                        errors=errors,
                        warnings=warnings,
                        catalog_functions=catalog_functions,
                        data_model=comp_dm,
                        catalog_function_specs=catalog_function_specs,
                        catalog_id=canonical_catalog_id,
                        effective_catalog_id=effective_comp_catalog,
                        allow_user_activation=False,
                        is_historical_snapshot=comp_hist,
                        is_superseded=is_superseded,
                    )

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
                                data_model=comp_dm,
                                catalog_function_specs=catalog_function_specs,
                                catalog_id=canonical_catalog_id,
                                effective_catalog_id=effective_comp_catalog,
                                is_historical_snapshot=comp_hist,
                                is_superseded=is_superseded,
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
                        data_model=comp_dm,
                        catalog_function_specs=catalog_function_specs,
                        catalog_id=canonical_catalog_id,
                        effective_catalog_id=effective_comp_catalog,
                        is_historical_snapshot=comp_hist,
                        is_superseded=is_superseded,
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
                    data_model=comp_dm,
                    catalog_function_specs=catalog_function_specs,
                    catalog_id=canonical_catalog_id,
                    effective_catalog_id=effective_comp_catalog,
                    is_historical_snapshot=comp_hist,
                    is_superseded=is_superseded,
                    template_validated_url_paths=template_validated_url_paths,
                    max_segments=max_segments,
                    safe_open_urls=safe_open_urls,
                )

            if comp_type in _MEDIA_URL_PROPS:
                for media_prop in _MEDIA_URL_PROPS[comp_type]:
                    if media_prop in props:
                        media_path = f"{cpath}.{media_prop}"
                        _validate_media_prop(
                            props[media_prop],
                            block_index,
                            media_path,
                            errors,
                            comp_dm,
                            version=version,
                            strict=strict,
                            warnings=warnings,
                            is_historical_snapshot=comp_hist
                            or (
                                template_validated_url_paths is not None
                                and media_path in template_validated_url_paths
                            ),
                            is_superseded=is_superseded,
                            safe_url_cache=safe_media_urls,
                            max_segments=max_segments,
                        )
            elif is_custom_catalog:
                for media_prop in ("url", "posterUrl"):
                    if media_prop in props:
                        media_path = f"{cpath}.{media_prop}"
                        _validate_media_prop(
                            props[media_prop],
                            block_index,
                            media_path,
                            errors,
                            comp_dm,
                            version=version,
                            strict=strict,
                            warnings=warnings,
                            is_historical_snapshot=comp_hist
                            or (
                                template_validated_url_paths is not None
                                and media_path in template_validated_url_paths
                            ),
                            is_superseded=is_superseded,
                            safe_url_cache=safe_media_urls,
                            max_segments=max_segments,
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
    max_ptr_segments = max_depth + 4
    max_surface_url_evals = max(100_000, max_bytes // 8)
    max_surface_uncached_url_checks = max(30_000, max_bytes // 35)
    payload_url_slot_evals = 0
    payload_uncached_url_checks: list[int] = [0]
    payload_tpl_rescan_evals: list[int] = [0]
    payload_tpl_abs_eval_count: list[int] = [0]
    payload_budget_exceeded = False
    safe_media_urls: set[str] = set()
    safe_open_urls: set[str] = set()

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
        surface_catalog_ids: dict[str, str | None] = {}
        surface_component_batches: dict[str, list[list[dict[str, Any]]]] = {}
        surface_data_models: dict[str, dict[str, Any]] = {}
        surface_roots: dict[str, str] = {}
        surface_active_comp_map: dict[str, dict[str, tuple[str, dict[str, Any], str]]] = {}
        surface_active_adj: dict[str, dict[str, list[str]]] = {}
        # slot tuple: (kind, slot_path, raw_val, abs_ptrs, rel_ptrs, comp_cpath, slot_suffix)
        surface_url_slots: dict[
            str,
            dict[str, list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]]],
        ] = {}
        surface_childlist_templates: dict[str, dict[str, tuple[str, str]]] = {}
        surface_ptr_index: dict[
            str,
            tuple[
                dict[str, list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]]],
                dict[str, list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]]],
                list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]],
            ],
        ] = {}
        surface_ptr_index_dirty: set[str] = set()
        surface_seen_errors: dict[str, set[tuple[str, int, str, str]]] = {}
        surface_seen_warnings: dict[str, set[tuple[str, int, str, str]]] = {}
        surface_total_comp_entries: dict[str, int] = {}
        surface_tpl_summary_cache: dict[
            str,
            dict[
                str,
                tuple[
                    set[str],
                    list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]],
                    bool,
                ],
            ],
        ] = {}

        def _clear_surface_stream_state(sid_clear: str) -> None:
            surface_active_comp_map.pop(sid_clear, None)
            surface_active_adj.pop(sid_clear, None)
            surface_url_slots.pop(sid_clear, None)
            surface_childlist_templates.pop(sid_clear, None)
            surface_ptr_index.pop(sid_clear, None)
            surface_ptr_index_dirty.discard(sid_clear)
            surface_seen_errors.pop(sid_clear, None)
            surface_seen_warnings.pop(sid_clear, None)
            surface_total_comp_entries.pop(sid_clear, None)
            surface_tpl_summary_cache.pop(sid_clear, None)

        def _emit_surface_issues(
            sid_emit: str,
            tmp_errors: list[dict[str, Any]],
            tmp_warnings: list[dict[str, Any]],
        ) -> None:
            if tmp_errors:
                s_err = surface_seen_errors.setdefault(sid_emit, set())
                _append_unique_issues(errors, tmp_errors, s_err)
            if tmp_warnings:
                s_warn = surface_seen_warnings.setdefault(sid_emit, set())
                _append_unique_issues(warnings, tmp_warnings, s_warn)

        def _validate_single_url_slot(
            sid_slot: str,
            slot: tuple[str, str, Any, frozenset[str], frozenset[str], str, str],
            dm: dict[str, Any],
            tmp_errors: list[dict[str, Any]],
            tmp_warnings: list[dict[str, Any]],
            *,
            item_ctx: Any = None,
            item_idx: int | None = None,
            is_historical_snapshot: bool = True,
        ) -> bool:
            nonlocal payload_url_slot_evals, payload_budget_exceeded
            if (
                payload_budget_exceeded
                or payload_url_slot_evals >= max_surface_url_evals
                or payload_uncached_url_checks[0] >= max_surface_uncached_url_checks
            ):
                if not payload_budget_exceeded:
                    payload_budget_exceeded = True
                    _add_issue(
                        tmp_errors,
                        "MAX_TEMPLATE_EVALS_EXCEEDED",
                        bidx,
                        f"surface:{sid_slot}",
                        f"Payload URL slot evaluations exceeded limit ({max_surface_url_evals}).",
                    )
                return False

            kind, slot_path, raw_val, _abs_p, _rel_p, comp_cpath, slot_suffix = slot
            cache = safe_media_urls if kind == "media" else safe_open_urls
            eval_cost = 1
            parsed_fmt: tuple[str, tuple[str, ...], tuple[str, ...], bool, str, int, str] | None = None
            if isinstance(raw_val, dict) and ("@call" in raw_val or "call" in raw_val):
                fn_name = raw_val.get("@call") if "@call" in raw_val else raw_val.get("call")
                if fn_name == "formatString":
                    args_d = raw_val.get("args")
                    if isinstance(args_d, dict):
                        tpl_s = args_d.get("value")
                        if isinstance(tpl_s, str):
                            parsed_fmt = _parse_format_string_template(tpl_s)
                            eval_cost = parsed_fmt[5]

            if payload_url_slot_evals + eval_cost > max_surface_url_evals:
                if not payload_budget_exceeded:
                    payload_budget_exceeded = True
                    _add_issue(
                        tmp_errors,
                        "MAX_TEMPLATE_EVALS_EXCEEDED",
                        bidx,
                        f"surface:{sid_slot}",
                        f"Payload URL slot evaluations exceeded limit ({max_surface_url_evals}).",
                    )
                return False
            payload_url_slot_evals += eval_cost

            if parsed_fmt is not None:
                st, pts, exs, pfx_ne, ph_s, _cost, emp_s = parsed_fmt
                if st == "ok" and pfx_ne and len(exs) == 1 and ph_s in cache:
                    f_ex, v_ex = _resolve_pointer_with_context(dm, exs[0], item_ctx, max_ptr_segments)
                    if f_ex:
                        r_str = f"{pts[0]}{'' if v_ex is None else v_ex}{pts[1]}"
                        if r_str in cache:
                            return True
                    elif emp_s in cache:
                        return True
            elif isinstance(raw_val, dict) and not ("@call" in raw_val or "call" in raw_val):
                sver = surface_versions.get(sid_slot, "1.0")
                is_simple_binding = len(raw_val) == 1 and (
                    ("path" in raw_val)
                    if (kind == "media" and sver == "0.8")
                    else ("@path" in raw_val or "path" in raw_val)
                )
                if is_simple_binding:
                    ptr = raw_val.get("@path") if "@path" in raw_val else raw_val.get("path")
                    if isinstance(ptr, str) and ptr:
                        found, resolved = _resolve_pointer_with_context(dm, ptr, item_ctx, max_ptr_segments)
                        if not found:
                            return True
                        if type(resolved) is str:
                            if resolved in cache:
                                return True
                            payload_uncached_url_checks[0] += 1
                            ok_u, _reason_u = (
                                validate_media_url(resolved)
                                if kind == "media"
                                else validate_open_url(resolved)
                            )
                            if ok_u:
                                if len(cache) >= _SAFE_URL_CACHE_MAX:
                                    cache.clear()
                                cache.add(resolved)
                                return True
            target_path = f"{comp_cpath}[item:{item_idx}]{slot_suffix}" if item_idx is not None else slot_path
            if kind == "media":
                _validate_media_prop(
                    raw_val,
                    bidx,
                    target_path,
                    tmp_errors,
                    dm,
                    version=surface_versions.get(sid_slot, "1.0"),
                    strict=strict,
                    warnings=tmp_warnings,
                    item_ctx=item_ctx,
                    is_historical_snapshot=is_historical_snapshot,
                    safe_url_cache=cache,
                    uncached_counter=payload_uncached_url_checks,
                    max_segments=max_ptr_segments,
                )
            else:
                _validate_open_url_arg(
                    raw_val,
                    bidx,
                    target_path,
                    tmp_errors,
                    dm,
                    strict=strict,
                    warnings=tmp_warnings,
                    item_ctx=item_ctx,
                    is_historical_snapshot=is_historical_snapshot,
                    safe_url_cache=cache,
                    uncached_counter=payload_uncached_url_checks,
                    max_segments=max_ptr_segments,
                )
            return True

        def _get_surface_ptr_index(
            sid_idx: str,
        ) -> tuple[
            dict[str, list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]]],
            dict[str, list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]]],
            list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]],
        ]:
            if sid_idx not in surface_ptr_index_dirty and sid_idx in surface_ptr_index:
                return surface_ptr_index[sid_idx]
            exact_map: dict[str, list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]]] = {}
            prefix_map: dict[str, list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]]] = {}
            all_dyn: list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]] = []
            for comp_slots in surface_url_slots.get(sid_idx, {}).values():
                for slot in comp_slots:
                    abs_ptrs = slot[3]
                    if not abs_ptrs:
                        continue
                    all_dyn.append(slot)
                    seen_anc: set[str] = set()
                    for ap in abs_ptrs:
                        if ap in {"", "/"}:
                            exact_map.setdefault("/", []).append(slot)
                        else:
                            exact_map.setdefault(ap, []).append(slot)
                            for anc in _pointer_ancestors(ap, max_segments=max_ptr_segments):
                                if anc not in seen_anc:
                                    seen_anc.add(anc)
                                    prefix_map.setdefault(anc, []).append(slot)
            res_idx = (exact_map, prefix_map, all_dyn)
            surface_ptr_index[sid_idx] = res_idx
            surface_ptr_index_dirty.discard(sid_idx)
            return res_idx

        def _collect_template_scope(
            sid_tpl: str, tpl_root_id: str
        ) -> tuple[
            list[str],
            list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]],
            list[tuple[str, str]],
        ]:
            """Collect nodes, relative URL slots, and nested relative ChildLists sharing tpl_root_id's item_ctx."""
            comp_map = surface_active_comp_map.get(sid_tpl, {})
            if tpl_root_id not in comp_map:
                return [], [], []
            adj_map = surface_active_adj.get(sid_tpl, {})
            slots_by_cid = surface_url_slots.get(sid_tpl, {})
            tpl_map = surface_childlist_templates.get(sid_tpl, {})
            direct_nodes: list[str] = []
            seen_tpl: set[str] = set()
            t_queue = [tpl_root_id]
            while t_queue:
                cur_id = t_queue.pop()
                if cur_id in seen_tpl or cur_id not in comp_map:
                    continue
                seen_tpl.add(cur_id)
                direct_nodes.append(cur_id)
                t_queue.extend(adj_map.get(cur_id, []))
            direct_rel_slots: list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]] = []
            nested_rel_children: list[tuple[str, str]] = []
            seen_nested_rel: set[tuple[str, str]] = set()
            for tcid in direct_nodes:
                for slot in slots_by_cid.get(tcid, ()):
                    if slot[4]:  # has relative pointers that depend on item_ctx
                        direct_rel_slots.append(slot)
                child_tpl = tpl_map.get(tcid)
                if child_tpl is not None:
                    inner_tpl_id, inner_list_ptr = child_tpl
                    if isinstance(inner_list_ptr, str) and inner_list_ptr and not inner_list_ptr.startswith("/"):
                        nested_pair = (inner_tpl_id, inner_list_ptr)
                        if nested_pair not in seen_nested_rel:
                            seen_nested_rel.add(nested_pair)
                            nested_rel_children.append(nested_pair)
            return direct_nodes, direct_rel_slots, nested_rel_children

        def _collect_template_binding_chains(
            g_comp_map: dict[str, tuple[str, dict[str, Any], str]],
            g_adj_map: dict[str, list[str]],
            g_tpl_map: dict[str, tuple[str, str]],
        ) -> tuple[set[tuple[str, tuple[str, ...]]], bool]:
            """Compute all active (cid, chain_tuple) bindings reachable from absolute ChildList templates."""
            active_chains: set[tuple[str, tuple[str, ...]]] = set()
            seen_states: set[tuple[str, tuple[str, ...]]] = set()
            work: list[tuple[str, tuple[str, ...], frozenset[str]]] = []
            max_states = max(4096, max_components * 8)
            for _owner_cid, (tpl_root_id, list_ptr) in g_tpl_map.items():
                if not isinstance(list_ptr, str) or not list_ptr.startswith("/"):
                    continue
                if tpl_root_id not in g_comp_map:
                    continue
                init_chain = (list_ptr,)
                root_key = (tpl_root_id, init_chain)
                if root_key in seen_states:
                    continue
                seen_states.add(root_key)
                work.append((tpl_root_id, init_chain, frozenset({tpl_root_id})))

            while work:
                cur_root, chain, visited_tpls = work.pop()
                seen_nodes: set[str] = set()
                n_stack = [cur_root]
                while n_stack:
                    nid = n_stack.pop()
                    if nid in seen_nodes or nid not in g_comp_map:
                        continue
                    seen_nodes.add(nid)
                    active_chains.add((nid, chain))
                    for nxt in g_adj_map.get(nid, ()):
                        if nxt not in seen_nodes:
                            n_stack.append(nxt)
                    child_tpl = g_tpl_map.get(nid)
                    if child_tpl is not None:
                        inner_tpl_id, inner_list_ptr = child_tpl
                        if (
                            isinstance(inner_list_ptr, str)
                            and inner_list_ptr
                            and not inner_list_ptr.startswith("/")
                            and inner_tpl_id in g_comp_map
                            and inner_tpl_id not in visited_tpls
                        ):
                            next_chain = chain + (inner_list_ptr,)
                            next_key = (inner_tpl_id, next_chain)
                            if next_key not in seen_states:
                                if len(seen_states) >= max_states:
                                    return active_chains, True
                                seen_states.add(next_key)
                                work.append((inner_tpl_id, next_chain, visited_tpls | {inner_tpl_id}))
            return active_chains, False

        def _collect_template_tree_summary(
            sid_tpl: str, tpl_root_id: str
        ) -> tuple[
            set[str],
            list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]],
            bool,
        ]:
            """Collect all reachable nodes and relative URL slots across tpl_root_id and nested relative ChildLists."""
            surf_cache = surface_tpl_summary_cache.setdefault(sid_tpl, {})
            cached = surf_cache.get(tpl_root_id)
            if cached is not None:
                return cached
            all_nodes: set[str] = set()
            all_rel_slots: list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]] = []
            seen_roots: set[str] = set()
            has_nested_rel = False
            stack = [tpl_root_id]
            while stack:
                cur_root = stack.pop()
                if cur_root in seen_roots:
                    continue
                seen_roots.add(cur_root)
                d_nodes, d_rel_slots, nested_rel = _collect_template_scope(sid_tpl, cur_root)
                all_nodes.update(d_nodes)
                all_rel_slots.extend(d_rel_slots)
                if nested_rel:
                    has_nested_rel = True
                    for inner_tpl_id, _inner_ptr in nested_rel:
                        if inner_tpl_id not in seen_roots:
                            stack.append(inner_tpl_id)
            res = (all_nodes, all_rel_slots, has_nested_rel)
            surf_cache[tpl_root_id] = res
            return res

        def _validate_template_item_urls(
            sid_tpl: str,
            tpl_root_id: str,
            dm: dict[str, Any],
            item_ctx: Any,
            item_idx: int,
            tmp_errors: list[dict[str, Any]],
            tmp_warnings: list[dict[str, Any]],
            *,
            is_historical_snapshot: bool = True,
            only_prefixless: bool = False,
            abs_overlap_ptr: str | None = None,
            abs_overlap_popped_idx: int | None = None,
            target_slot_ids: set[int] | None = None,
            evaluated_slot_ids: set[int] | None = None,
            visited_tpls: frozenset[str] = frozenset(),
            eval_budget: list[int] | None = None,
            eval_limit: int = _MAX_TEMPLATE_ABS_RESCAN_EVALS,
            scope_cache: dict[
                str,
                tuple[
                    list[str],
                    list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]],
                    list[tuple[str, str]],
                ],
            ]
            | None = None,
            tree_has_slots_cache: dict[str, bool] | None = None,
        ) -> bool:
            """Validate one ChildList template item and any nested relative ChildList templates.

            Returns True if eval_limit was exceeded (fail-closed).
            """
            if tpl_root_id in visited_tpls:
                return False
            next_visited = visited_tpls | {tpl_root_id}
            if scope_cache is None:
                scope_cache = {}
            if tree_has_slots_cache is None:
                tree_has_slots_cache = {}
            scope = scope_cache.get(tpl_root_id)
            if scope is None:
                scope = _collect_template_scope(sid_tpl, tpl_root_id)
                scope_cache[tpl_root_id] = scope
            _direct_nodes, direct_rel_slots, nested_rel_children = scope

            for slot in direct_rel_slots:
                if target_slot_ids is not None and id(slot) not in target_slot_ids:
                    continue
                if only_prefixless and not _is_prefixless_format_string_url(slot[2]):
                    continue
                if abs_overlap_ptr is not None and not any(
                    _pointer_affected_by_update(
                        ap, abs_overlap_ptr, abs_overlap_popped_idx, max_segments=max_ptr_segments
                    )
                    for ap in slot[3]
                ):
                    continue
                if eval_budget is not None:
                    if eval_budget[0] >= eval_limit:
                        _add_issue(
                            tmp_errors,
                            "MAX_TEMPLATE_EVALS_EXCEEDED",
                            bidx,
                            f"surface:{sid_tpl}",
                            f"Template URL re-evaluation exceeded limit ({eval_limit}).",
                        )
                        return True
                    eval_budget[0] += 1
                if evaluated_slot_ids is not None:
                    evaluated_slot_ids.add(id(slot))
                if not _validate_single_url_slot(
                    sid_tpl,
                    slot,
                    dm,
                    tmp_errors,
                    tmp_warnings,
                    item_ctx=item_ctx,
                    item_idx=item_idx,
                    is_historical_snapshot=is_historical_snapshot,
                ):
                    return True

            if nested_rel_children:
                local_budget = eval_budget
                local_limit = eval_limit
                if local_budget is None:
                    local_budget = payload_tpl_abs_eval_count
                    local_limit = _MAX_TEMPLATE_ABS_RESCAN_EVALS
                for inner_tpl_id, inner_list_ptr in nested_rel_children:
                    if inner_tpl_id in next_visited:
                        continue
                    has_inner_slots = tree_has_slots_cache.get(inner_tpl_id)
                    if has_inner_slots is None:
                        _inodes, irel, _inest = _collect_template_tree_summary(sid_tpl, inner_tpl_id)
                        if target_slot_ids is not None:
                            irel = [s for s in irel if id(s) in target_slot_ids]
                        if only_prefixless:
                            has_inner_slots = any(_is_prefixless_format_string_url(s[2]) for s in irel)
                        elif abs_overlap_ptr is not None:
                            has_inner_slots = any(
                                any(
                                    _pointer_affected_by_update(
                                        ap, abs_overlap_ptr, abs_overlap_popped_idx, max_segments=max_ptr_segments
                                    )
                                    for ap in s[3]
                                )
                                for s in irel
                            )
                        else:
                            has_inner_slots = bool(irel)
                        tree_has_slots_cache[inner_tpl_id] = has_inner_slots
                    if not has_inner_slots:
                        continue
                    found_inner, inner_items = _resolve_pointer_with_context(
                        dm, inner_list_ptr, item_ctx, max_segments=max_ptr_segments
                    )
                    if not found_inner or not isinstance(inner_items, list):
                        continue
                    for inner_idx, inner_item in enumerate(inner_items):
                        if local_budget[0] >= local_limit:
                            _add_issue(
                                tmp_errors,
                                "MAX_TEMPLATE_EVALS_EXCEEDED",
                                bidx,
                                f"surface:{sid_tpl}",
                                f"Template URL re-evaluation exceeded limit ({local_limit}).",
                            )
                            return True
                        before = local_budget[0]
                        if _validate_template_item_urls(
                            sid_tpl,
                            inner_tpl_id,
                            dm,
                            inner_item,
                            inner_idx,
                            tmp_errors,
                            tmp_warnings,
                            is_historical_snapshot=is_historical_snapshot,
                            only_prefixless=only_prefixless,
                            abs_overlap_ptr=abs_overlap_ptr,
                            abs_overlap_popped_idx=abs_overlap_popped_idx,
                            target_slot_ids=target_slot_ids,
                            evaluated_slot_ids=evaluated_slot_ids,
                            visited_tpls=next_visited,
                            eval_budget=local_budget,
                            eval_limit=local_limit,
                            scope_cache=scope_cache,
                            tree_has_slots_cache=tree_has_slots_cache,
                        ):
                            return True
                        if local_budget[0] == before:
                            local_budget[0] += 1
            return False

        def _ingest_component_batch(sid_ing: str, b_idx: int, comps: list[dict[str, Any]]) -> None:
            total_seen = surface_total_comp_entries.get(sid_ing, 0) + len(comps)
            surface_total_comp_entries[sid_ing] = total_seen
            if total_seen > max_components:
                return
            sver = surface_versions.get(sid_ing, "1.0")
            canonical_cat_id = _CANONICAL_CATALOG_ID_BY_VER.get(sver, CANONICAL_V1_CATALOG_ID)
            surf_cat = surface_catalog_ids.get(sid_ing)
            comp_map = surface_active_comp_map.setdefault(sid_ing, {})
            adj_map = surface_active_adj.setdefault(sid_ing, {})
            slots_by_cid = surface_url_slots.setdefault(sid_ing, {})
            tpl_map = surface_childlist_templates.setdefault(sid_ing, {})
            dm = surface_data_models.get(sid_ing, {})
            tmp_errors: list[dict[str, Any]] = []
            tmp_warnings: list[dict[str, Any]] = []

            # Pre-parse incoming components before mutating any surface graph state
            parsed_incoming: list[
                tuple[str, str, dict[str, Any], str, list[str], tuple[str, str] | None]
            ] = []
            batch_seen_ids: set[str] = set()
            for idx, comp in enumerate(comps):
                if not isinstance(comp, dict):
                    continue
                cid = comp.get("id")
                if not isinstance(cid, str) or not cid or cid in batch_seen_ids:
                    continue
                batch_seen_ids.add(cid)
                cpath = (
                    f"surface:{sid_ing}.components[{idx}]"
                    if b_idx == 0
                    else f"surface:{sid_ing}.batch[{b_idx}].components[{idx}]"
                )
                if sver == "0.8":
                    c_type, c_props = _extract_v08_component(comp)
                    if not c_type:
                        continue
                else:
                    c_type = comp.get("component")
                    c_props = comp
                    if not isinstance(c_type, str) or not c_type:
                        continue
                if c_type == "Surface":
                    continue
                new_adj = [
                    ref_id
                    for rp, ref_id in _extract_child_refs(c_type, c_props, sver)
                    if rp not in {"children.componentId", "children.template.componentId"}
                ]
                ch = c_props.get("children")
                tpl_binding: tuple[str, str] | None = None
                if isinstance(ch, dict):
                    if sver == "0.8" and isinstance(ch.get("template"), dict):
                        tpl = ch["template"]
                        if isinstance(tpl.get("componentId"), str) and isinstance(tpl.get("dataBinding"), str):
                            tpl_binding = (
                                tpl["componentId"],
                                _canonicalize_json_pointer(tpl["dataBinding"], max_segments=max_ptr_segments),
                            )
                    elif isinstance(ch.get("componentId"), str) and isinstance(ch.get("path"), str):
                        tpl_binding = (
                            ch["componentId"],
                            _canonicalize_json_pointer(ch["path"], max_segments=max_ptr_segments),
                        )
                parsed_incoming.append((cid, c_type, c_props, cpath, new_adj, tpl_binding))

            # Snapshot lightweight pre-batch graph state only when replacing existing components
            replaced_entries = [entry for entry in parsed_incoming if entry[0] in comp_map]
            replaced_cids: set[str] = set()
            old_comp_map: dict[str, tuple[str, dict[str, Any], str]] | None = None
            old_adj_map: dict[str, list[str]] | None = None
            old_slots_by_cid: dict[
                str, list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]]
            ] | None = None
            old_tpl_map: dict[str, tuple[str, str]] | None = None
            if replaced_entries:
                replaced_cids = {entry[0] for entry in replaced_entries}
                old_comp_map = dict(comp_map)
                old_adj_map = {k: list(v) for k, v in adj_map.items()}
                old_slots_by_cid = dict(slots_by_cid)
                old_tpl_map = dict(tpl_map)

            updated_cids: set[str] = set()
            for cid, c_type, c_props, cpath, new_adj, tpl_binding in parsed_incoming:
                comp_map[cid] = (c_type, c_props, cpath)
                adj_map[cid] = new_adj
                updated_cids.add(cid)

                raw_c_cat = c_props.get("@catalogId")
                c_effective_cat = (
                    raw_c_cat if isinstance(raw_c_cat, str) and raw_c_cat.strip() else surf_cat
                )
                c_is_custom = _is_custom_catalog_id(c_effective_cat, canonical_cat_id)
                media_props = _MEDIA_URL_PROPS.get(c_type, ("url", "posterUrl") if c_is_custom else ())

                comp_slots: list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]] = []
                for media_prop in media_props:
                    if media_prop in c_props:
                        val_obj = c_props[media_prop]
                        abs_p, rel_p = _extract_url_slot_pointers(val_obj, max_segments=max_ptr_segments)
                        comp_slots.append(
                            ("media", f"{cpath}.{media_prop}", val_obj, abs_p, rel_p, cpath, f".{media_prop}")
                        )
                for url_path, url_val in _iter_open_url_slots(c_props, cpath):
                    abs_p, rel_p = _extract_url_slot_pointers(url_val, max_segments=max_ptr_segments)
                    suffix = url_path[len(cpath) :] if url_path.startswith(cpath) else url_path
                    comp_slots.append(("openUrl", url_path, url_val, abs_p, rel_p, cpath, suffix))

                if comp_slots:
                    slots_by_cid[cid] = comp_slots
                else:
                    slots_by_cid.pop(cid, None)

                if tpl_binding is not None:
                    tpl_map[cid] = tpl_binding
                else:
                    tpl_map.pop(cid, None)

            surface_ptr_index_dirty.add(sid_ing)
            surface_tpl_summary_cache.pop(sid_ing, None)
            if not updated_cids:
                _emit_surface_issues(sid_ing, tmp_errors, tmp_warnings)
                return

            if payload_budget_exceeded:
                _emit_surface_issues(sid_ing, tmp_errors, tmp_warnings)
                return

            # Validate genuinely outgoing prefix-less formatString URL slots by exact pre-vs-post batch diff
            if replaced_cids and old_comp_map is not None and old_adj_map is not None and old_slots_by_cid is not None and old_tpl_map is not None:
                # 1. Direct prefix-less formatString slots: validate only slots on replaced components
                direct_out_cap = False
                for rcid in replaced_cids:
                    for slot in old_slots_by_cid.get(rcid, ()):
                        if not slot[4] and _is_prefixless_format_string_url(slot[2]):
                            if not _validate_single_url_slot(
                                sid_ing, slot, dm, tmp_errors, tmp_warnings, is_historical_snapshot=False
                            ):
                                direct_out_cap = True
                                break
                    if direct_out_cap:
                        break

                # 2. Relative prefix-less formatString slots: exact pre-batch vs post-batch template chain diff
                if not direct_out_cap:
                    old_pfx_rel_by_cid: dict[
                        str, list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]]
                    ] = {}
                    for ocid, oslots in old_slots_by_cid.items():
                        pfx_rel = [s for s in oslots if s[4] and _is_prefixless_format_string_url(s[2])]
                        if pfx_rel:
                            old_pfx_rel_by_cid[ocid] = pfx_rel

                    if old_pfx_rel_by_cid:
                        old_chains, old_chain_cap = _collect_template_binding_chains(
                            old_comp_map, old_adj_map, old_tpl_map
                        )
                        new_chains, new_chain_cap = _collect_template_binding_chains(
                            comp_map, adj_map, tpl_map
                        )
                        if old_chain_cap or new_chain_cap:
                            _add_issue(
                                tmp_errors,
                                "MAX_TEMPLATE_EVALS_EXCEEDED",
                                bidx,
                                f"surface:{sid_ing}",
                                f"Template binding chain traversal exceeded limit ({max(4096, max_components * 8)}).",
                            )
                        else:
                            outgoing_by_chain: dict[
                                tuple[str, ...],
                                list[tuple[str, str, Any, frozenset[str], frozenset[str], str, str]],
                            ] = {}
                            seen_chain_slot_ids: dict[tuple[str, ...], set[int]] = {}
                            for ocid, chain in old_chains:
                                pfx_slots = old_pfx_rel_by_cid.get(ocid)
                                if not pfx_slots:
                                    continue
                                if ocid in replaced_cids or (ocid, chain) not in new_chains:
                                    c_bucket = outgoing_by_chain.setdefault(chain, [])
                                    c_seen = seen_chain_slot_ids.setdefault(chain, set())
                                    for slot in pfx_slots:
                                        if id(slot) not in c_seen:
                                            c_seen.add(id(slot))
                                            c_bucket.append(slot)

                            replaced_rel_slots: list[
                                tuple[str, str, Any, frozenset[str], frozenset[str], str, str]
                            ] = []
                            for rcid in replaced_cids:
                                replaced_rel_slots.extend(old_pfx_rel_by_cid.get(rcid, ()))

                            evaluated_slot_ids: set[int] = set()
                            pre_rescan_budget = payload_tpl_rescan_evals
                            pre_cap_hit = False

                            def _validate_chain_items(
                                chain_ptrs: tuple[str, ...],
                                depth: int,
                                cur_ctx: Any,
                                chain_slots: list[
                                    tuple[str, str, Any, frozenset[str], frozenset[str], str, str]
                                ],
                            ) -> bool:
                                if depth == 0:
                                    found_l, items_l = _resolve_json_pointer(
                                        dm, chain_ptrs[0], max_segments=max_ptr_segments
                                    )
                                else:
                                    found_l, items_l = _resolve_pointer_with_context(
                                        dm, chain_ptrs[depth], cur_ctx, max_segments=max_ptr_segments
                                    )
                                if not found_l or not isinstance(items_l, list) or not items_l:
                                    return False
                                if depth == len(chain_ptrs) - 1:
                                    for li_idx, li_item in enumerate(items_l):
                                        for slot in chain_slots:
                                            if pre_rescan_budget[0] >= _MAX_TEMPLATE_RESCAN_EVALS:
                                                _add_issue(
                                                    tmp_errors,
                                                    "MAX_TEMPLATE_EVALS_EXCEEDED",
                                                    bidx,
                                                    f"surface:{sid_ing}",
                                                    f"Template URL re-evaluation exceeded limit ({_MAX_TEMPLATE_RESCAN_EVALS}).",
                                                )
                                                return True
                                            evaluated_slot_ids.add(id(slot))
                                            if not _validate_single_url_slot(
                                                sid_ing,
                                                slot,
                                                dm,
                                                tmp_errors,
                                                tmp_warnings,
                                                item_ctx=li_item,
                                                item_idx=li_idx,
                                                is_historical_snapshot=False,
                                            ):
                                                return True
                                            pre_rescan_budget[0] += 1
                                    return False
                                for li_item in items_l:
                                    if pre_rescan_budget[0] >= _MAX_TEMPLATE_RESCAN_EVALS:
                                        _add_issue(
                                            tmp_errors,
                                            "MAX_TEMPLATE_EVALS_EXCEEDED",
                                            bidx,
                                            f"surface:{sid_ing}",
                                            f"Template URL re-evaluation exceeded limit ({_MAX_TEMPLATE_RESCAN_EVALS}).",
                                        )
                                        return True
                                    before = pre_rescan_budget[0]
                                    if _validate_chain_items(chain_ptrs, depth + 1, li_item, chain_slots):
                                        return True
                                    if pre_rescan_budget[0] == before:
                                        pre_rescan_budget[0] += 1
                                return False

                            for chain_ptrs, chain_slots in outgoing_by_chain.items():
                                if _validate_chain_items(chain_ptrs, 0, None, chain_slots):
                                    pre_cap_hit = True
                                    break
                            if not pre_cap_hit:
                                for out_slot in replaced_rel_slots:
                                    if id(out_slot) not in evaluated_slot_ids:
                                        if not _validate_single_url_slot(
                                            sid_ing,
                                            out_slot,
                                            dm,
                                            tmp_errors,
                                            tmp_warnings,
                                            is_historical_snapshot=False,
                                        ):
                                            break

            if payload_budget_exceeded:
                _emit_surface_issues(sid_ing, tmp_errors, tmp_warnings)
                return

            # Eagerly validate newly added/updated direct component URL slots against current dataModel
            direct_eager_cap = False
            for cid in updated_cids:
                for slot in slots_by_cid.get(cid, ()):
                    if not _validate_single_url_slot(
                        sid_ing, slot, dm, tmp_errors, tmp_warnings, is_historical_snapshot=True
                    ):
                        direct_eager_cap = True
                        break
                if direct_eager_cap:
                    break

            if direct_eager_cap or payload_budget_exceeded:
                _emit_surface_issues(sid_ing, tmp_errors, tmp_warnings)
                return

            # Eagerly validate any affected absolute ChildList template (including nested relative ChildLists)
            rescan_budget = payload_tpl_rescan_evals if b_idx > 0 else None
            seen_tpl_pairs_ing: set[tuple[str, str]] = set()
            ing_tpl_cap = False
            for owner_cid, (tpl_root_id, list_ptr) in tpl_map.items():
                if not isinstance(list_ptr, str) or not list_ptr.startswith("/"):
                    continue
                tpl_nodes, rel_slots, has_nested_rel = _collect_template_tree_summary(sid_ing, tpl_root_id)
                if not rel_slots:
                    continue
                if owner_cid not in updated_cids and not any(n in updated_cids for n in tpl_nodes):
                    continue
                tpl_pair = (tpl_root_id, list_ptr)
                if tpl_pair in seen_tpl_pairs_ing:
                    continue
                seen_tpl_pairs_ing.add(tpl_pair)
                found_list, items_val = _resolve_json_pointer(dm, list_ptr, max_segments=max_ptr_segments)
                if not found_list or not isinstance(items_val, list):
                    continue
                if not has_nested_rel:
                    if rescan_budget is not None:
                        cap_hit = False
                        for item_idx, item in enumerate(items_val):
                            for slot in rel_slots:
                                if rescan_budget[0] >= _MAX_TEMPLATE_RESCAN_EVALS:
                                    cap_hit = True
                                    break
                                if not _validate_single_url_slot(
                                    sid_ing,
                                    slot,
                                    dm,
                                    tmp_errors,
                                    tmp_warnings,
                                    item_ctx=item,
                                    item_idx=item_idx,
                                    is_historical_snapshot=True,
                                ):
                                    ing_tpl_cap = True
                                    break
                                rescan_budget[0] += 1
                            if cap_hit or ing_tpl_cap:
                                break
                        if cap_hit:
                            _add_issue(
                                tmp_errors,
                                "MAX_TEMPLATE_EVALS_EXCEEDED",
                                bidx,
                                f"surface:{sid_ing}",
                                f"Template URL re-evaluation exceeded limit ({_MAX_TEMPLATE_RESCAN_EVALS}).",
                            )
                            ing_tpl_cap = True
                    else:
                        for item_idx, item in enumerate(items_val):
                            for slot in rel_slots:
                                if not _validate_single_url_slot(
                                    sid_ing,
                                    slot,
                                    dm,
                                    tmp_errors,
                                    tmp_warnings,
                                    item_ctx=item,
                                    item_idx=item_idx,
                                    is_historical_snapshot=True,
                                ):
                                    ing_tpl_cap = True
                                    break
                            if ing_tpl_cap:
                                break
                else:
                    sc_ing: dict[str, Any] = {}
                    tc_ing: dict[str, bool] = {}
                    for item_idx, item in enumerate(items_val):
                        if rescan_budget is not None:
                            if rescan_budget[0] >= _MAX_TEMPLATE_RESCAN_EVALS:
                                _add_issue(
                                    tmp_errors,
                                    "MAX_TEMPLATE_EVALS_EXCEEDED",
                                    bidx,
                                    f"surface:{sid_ing}",
                                    f"Template URL re-evaluation exceeded limit ({_MAX_TEMPLATE_RESCAN_EVALS}).",
                                )
                                ing_tpl_cap = True
                                break
                            before = rescan_budget[0]
                            if _validate_template_item_urls(
                                sid_ing,
                                tpl_root_id,
                                dm,
                                item,
                                item_idx,
                                tmp_errors,
                                tmp_warnings,
                                is_historical_snapshot=True,
                                eval_budget=rescan_budget,
                                eval_limit=_MAX_TEMPLATE_RESCAN_EVALS,
                                scope_cache=sc_ing,
                                tree_has_slots_cache=tc_ing,
                            ):
                                ing_tpl_cap = True
                                break
                            if rescan_budget[0] == before:
                                rescan_budget[0] += 1
                        else:
                            if _validate_template_item_urls(
                                sid_ing,
                                tpl_root_id,
                                dm,
                                item,
                                item_idx,
                                tmp_errors,
                                tmp_warnings,
                                is_historical_snapshot=True,
                                scope_cache=sc_ing,
                                tree_has_slots_cache=tc_ing,
                            ):
                                if payload_budget_exceeded:
                                    ing_tpl_cap = True
                                break
                if ing_tpl_cap or payload_budget_exceeded:
                    break

            _emit_surface_issues(sid_ing, tmp_errors, tmp_warnings)

        def _validate_streaming_data_update(
            sid_upd: str, ptr: str, *, popped_idx: int | None = None
        ) -> None:
            comp_map = surface_active_comp_map.get(sid_upd)
            if not comp_map or payload_budget_exceeded:
                return
            if isinstance(ptr, str):
                ptr = _canonicalize_json_pointer(ptr, max_segments=max_ptr_segments)
            dm = surface_data_models.get(sid_upd, {})
            tmp_errors: list[dict[str, Any]] = []
            tmp_warnings: list[dict[str, Any]] = []

            # 1. Re-validate only direct URL slots whose bound pointer(s) overlap ptr (skipping unshifted pop siblings)
            exact_map, prefix_map, all_dyn = _get_surface_ptr_index(sid_upd)
            if all_dyn:
                if ptr in {"", "/"}:
                    if popped_idx is None:
                        affected_slots = all_dyn
                    else:
                        affected_slots = [
                            slot
                            for slot in all_dyn
                            if any(
                                _pointer_affected_by_update(
                                    ap, ptr, popped_idx, max_segments=max_ptr_segments
                                )
                                for ap in slot[3]
                            )
                        ]
                else:
                    affected_slots = []
                    seen_slot_ids: set[int] = set()
                    prefix_bucket = prefix_map.get(ptr, ())
                    if popped_idx is not None and prefix_bucket:
                        plen = len(ptr)
                        prefix_bucket = [
                            slot
                            for slot in prefix_bucket
                            if any(
                                _pointer_affected_by_update(
                                    ap, ptr, popped_idx, max_segments=max_ptr_segments
                                )
                                for ap in slot[3]
                                if len(ap) > plen and ap.startswith(ptr) and ap[plen] == "/"
                            )
                        ]
                    for bucket in (exact_map.get("/", ()), exact_map.get(ptr, ()), prefix_bucket):
                        for slot in bucket:
                            sid_obj = id(slot)
                            if sid_obj not in seen_slot_ids:
                                seen_slot_ids.add(sid_obj)
                                affected_slots.append(slot)
                    for anc in _pointer_ancestors(ptr, max_segments=max_ptr_segments):
                        if anc == ptr:
                            continue
                        for slot in exact_map.get(anc, ()):
                            sid_obj = id(slot)
                            if sid_obj not in seen_slot_ids:
                                seen_slot_ids.add(sid_obj)
                                affected_slots.append(slot)
                for slot in affected_slots:
                    if not _validate_single_url_slot(
                        sid_upd, slot, dm, tmp_errors, tmp_warnings, is_historical_snapshot=True
                    ):
                        break

            if payload_budget_exceeded:
                _emit_surface_issues(sid_upd, tmp_errors, tmp_warnings)
                return

            # 2. Re-validate affected absolute ChildList templates (and nested relative ChildLists)
            tpl_map = surface_childlist_templates.get(sid_upd)
            if tpl_map:
                seen_tpl_pairs_upd: set[tuple[str, str]] = set()
                for _owner_cid, (tpl_root_id, list_ptr) in tpl_map.items():
                    if not isinstance(list_ptr, str) or not list_ptr.startswith("/"):
                        continue
                    tpl_pair = (tpl_root_id, list_ptr)
                    if tpl_pair in seen_tpl_pairs_upd:
                        continue
                    seen_tpl_pairs_upd.add(tpl_pair)
                    _tpl_nodes, rel_slots, has_nested_rel = _collect_template_tree_summary(sid_upd, tpl_root_id)
                    if not rel_slots:
                        continue
                    list_prefix = "/" if list_ptr in {"", "/"} else f"{list_ptr}/"
                    is_single_item_target = (
                        list_ptr not in {"", "/"}
                        and isinstance(ptr, str)
                        and ptr.startswith(list_prefix)
                    )
                    found_list = False
                    items_val: Any = None
                    list_resolved = False
                    checked_target_idx: int | None = None
                    is_full_list_target = False
                    surf_cap_hit = False

                    if is_single_item_target:
                        found_list, items_val = _resolve_json_pointer(
                            dm, list_ptr, max_segments=max_ptr_segments
                        )
                        list_resolved = True
                        if found_list and isinstance(items_val, list):
                            rest = ptr[len(list_prefix) :]
                            seg = rest.split("/", 1)[0]
                            if seg == "-":
                                target_idx = len(items_val) - 1 if items_val else None
                            else:
                                idx_parsed = _parse_rfc6901_array_index(seg)
                                target_idx = (
                                    idx_parsed
                                    if idx_parsed is not None and idx_parsed < len(items_val)
                                    else None
                                )
                            if target_idx is not None:
                                checked_target_idx = target_idx
                                item = items_val[target_idx]
                                if not has_nested_rel:
                                    for slot in rel_slots:
                                        if not _validate_single_url_slot(
                                            sid_upd,
                                            slot,
                                            dm,
                                            tmp_errors,
                                            tmp_warnings,
                                            item_ctx=item,
                                            item_idx=target_idx,
                                            is_historical_snapshot=True,
                                        ):
                                            surf_cap_hit = True
                                            break
                                else:
                                    if _validate_template_item_urls(
                                        sid_upd,
                                        tpl_root_id,
                                        dm,
                                        item,
                                        target_idx,
                                        tmp_errors,
                                        tmp_warnings,
                                        is_historical_snapshot=True,
                                    ):
                                        if payload_budget_exceeded:
                                            surf_cap_hit = True
                    else:
                        is_shifted_descendant = (
                            isinstance(ptr, str)
                            and ptr not in {"", "/"}
                            and len(list_ptr) > len(ptr)
                            and list_ptr.startswith(ptr)
                            and list_ptr[len(ptr)] == "/"
                            and (
                                popped_idx is None
                                or (
                                    (child_idx := _child_index_under(ptr, list_ptr, max_segments=max_ptr_segments))
                                    is None
                                    or child_idx >= popped_idx
                                )
                            )
                        )
                        is_full_list_target = (
                            ptr in {"", "/"}
                            or (popped_idx is None and list_ptr == ptr)
                            or is_shifted_descendant
                        )
                        if is_full_list_target:
                            found_list, items_val = _resolve_json_pointer(
                                dm, list_ptr, max_segments=max_ptr_segments
                            )
                            list_resolved = True
                            if found_list and isinstance(items_val, list):
                                if popped_idx is not None:
                                    rescan_budget = payload_tpl_rescan_evals
                                    if not has_nested_rel:
                                        cap_hit = False
                                        for item_idx, item in enumerate(items_val):
                                            for slot in rel_slots:
                                                if rescan_budget[0] >= _MAX_TEMPLATE_RESCAN_EVALS:
                                                    cap_hit = True
                                                    break
                                                if not _validate_single_url_slot(
                                                    sid_upd,
                                                    slot,
                                                    dm,
                                                    tmp_errors,
                                                    tmp_warnings,
                                                    item_ctx=item,
                                                    item_idx=item_idx,
                                                    is_historical_snapshot=True,
                                                ):
                                                    surf_cap_hit = True
                                                    break
                                                rescan_budget[0] += 1
                                            if cap_hit or surf_cap_hit:
                                                break
                                        if cap_hit:
                                            _add_issue(
                                                tmp_errors,
                                                "MAX_TEMPLATE_EVALS_EXCEEDED",
                                                bidx,
                                                f"surface:{sid_upd}",
                                                f"Template URL re-evaluation exceeded limit ({_MAX_TEMPLATE_RESCAN_EVALS}).",
                                            )
                                    else:
                                        sc_pop: dict[str, Any] = {}
                                        tc_pop: dict[str, bool] = {}
                                        for item_idx, item in enumerate(items_val):
                                            if rescan_budget[0] >= _MAX_TEMPLATE_RESCAN_EVALS:
                                                _add_issue(
                                                    tmp_errors,
                                                    "MAX_TEMPLATE_EVALS_EXCEEDED",
                                                    bidx,
                                                    f"surface:{sid_upd}",
                                                    f"Template URL re-evaluation exceeded limit ({_MAX_TEMPLATE_RESCAN_EVALS}).",
                                                )
                                                break
                                            before = rescan_budget[0]
                                            if _validate_template_item_urls(
                                                sid_upd,
                                                tpl_root_id,
                                                dm,
                                                item,
                                                item_idx,
                                                tmp_errors,
                                                tmp_warnings,
                                                is_historical_snapshot=True,
                                                eval_budget=rescan_budget,
                                                eval_limit=_MAX_TEMPLATE_RESCAN_EVALS,
                                                scope_cache=sc_pop,
                                                tree_has_slots_cache=tc_pop,
                                            ):
                                                if payload_budget_exceeded:
                                                    surf_cap_hit = True
                                                break
                                            if rescan_budget[0] == before:
                                                rescan_budget[0] += 1
                                elif not has_nested_rel:
                                    for item_idx, item in enumerate(items_val):
                                        for slot in rel_slots:
                                            if not _validate_single_url_slot(
                                                sid_upd,
                                                slot,
                                                dm,
                                                tmp_errors,
                                                tmp_warnings,
                                                item_ctx=item,
                                                item_idx=item_idx,
                                                is_historical_snapshot=True,
                                            ):
                                                surf_cap_hit = True
                                                break
                                        if surf_cap_hit:
                                            break
                                else:
                                    sc_full: dict[str, Any] = {}
                                    tc_full: dict[str, bool] = {}
                                    for item_idx, item in enumerate(items_val):
                                        if _validate_template_item_urls(
                                            sid_upd,
                                            tpl_root_id,
                                            dm,
                                            item,
                                            item_idx,
                                            tmp_errors,
                                            tmp_warnings,
                                            is_historical_snapshot=True,
                                            scope_cache=sc_full,
                                            tree_has_slots_cache=tc_full,
                                        ):
                                            if payload_budget_exceeded:
                                                surf_cap_hit = True
                                            break

                    if surf_cap_hit or payload_budget_exceeded:
                        break

                    # Check cross-item absolute pointer overlaps independently of is_single_item_target
                    if not is_full_list_target:
                        abs_overlap_slots = [
                            slot
                            for slot in rel_slots
                            if any(
                                _pointer_affected_by_update(
                                    ap, ptr, popped_idx, max_segments=max_ptr_segments
                                )
                                for ap in slot[3]
                            )
                        ]
                        if abs_overlap_slots:
                            if not list_resolved:
                                found_list, items_val = _resolve_json_pointer(
                                    dm, list_ptr, max_segments=max_ptr_segments
                                )
                            if not found_list or not isinstance(items_val, list):
                                continue
                            # Always run O(1) absolute check with item_ctx=None first
                            for slot in abs_overlap_slots:
                                if not _validate_single_url_slot(
                                    sid_upd,
                                    slot,
                                    dm,
                                    tmp_errors,
                                    tmp_warnings,
                                    item_ctx=None,
                                    is_historical_snapshot=True,
                                ):
                                    surf_cap_hit = True
                                    break
                            if surf_cap_hit or payload_budget_exceeded:
                                break
                            budget = payload_tpl_abs_eval_count
                            if not has_nested_rel:
                                cap_hit = False
                                for item_idx, item in enumerate(items_val):
                                    if checked_target_idx is not None and item_idx == checked_target_idx:
                                        continue
                                    for slot in abs_overlap_slots:
                                        if budget[0] >= _MAX_TEMPLATE_ABS_RESCAN_EVALS:
                                            cap_hit = True
                                            break
                                        if not _validate_single_url_slot(
                                            sid_upd,
                                            slot,
                                            dm,
                                            tmp_errors,
                                            tmp_warnings,
                                            item_ctx=item,
                                            item_idx=item_idx,
                                            is_historical_snapshot=True,
                                        ):
                                            surf_cap_hit = True
                                            break
                                        budget[0] += 1
                                    if cap_hit or surf_cap_hit:
                                        break
                                if cap_hit:
                                    _add_issue(
                                        tmp_errors,
                                        "MAX_TEMPLATE_EVALS_EXCEEDED",
                                        bidx,
                                        f"surface:{sid_upd}",
                                        f"Template URL re-evaluation exceeded limit ({_MAX_TEMPLATE_ABS_RESCAN_EVALS}).",
                                    )
                            else:
                                sc_abs: dict[str, Any] = {}
                                tc_abs: dict[str, bool] = {}
                                for item_idx, item in enumerate(items_val):
                                    if checked_target_idx is not None and item_idx == checked_target_idx:
                                        continue
                                    if budget[0] >= _MAX_TEMPLATE_ABS_RESCAN_EVALS:
                                        _add_issue(
                                            tmp_errors,
                                            "MAX_TEMPLATE_EVALS_EXCEEDED",
                                            bidx,
                                            f"surface:{sid_upd}",
                                            f"Template URL re-evaluation exceeded limit ({_MAX_TEMPLATE_ABS_RESCAN_EVALS}).",
                                        )
                                        break
                                    before = budget[0]
                                    if _validate_template_item_urls(
                                        sid_upd,
                                        tpl_root_id,
                                        dm,
                                        item,
                                        item_idx,
                                        tmp_errors,
                                        tmp_warnings,
                                        is_historical_snapshot=True,
                                        abs_overlap_ptr=ptr,
                                        abs_overlap_popped_idx=popped_idx,
                                        eval_budget=budget,
                                        eval_limit=_MAX_TEMPLATE_ABS_RESCAN_EVALS,
                                        scope_cache=sc_abs,
                                        tree_has_slots_cache=tc_abs,
                                    ):
                                        if payload_budget_exceeded:
                                            surf_cap_hit = True
                                        break
                                    if budget[0] == before:
                                        budget[0] += 1
                            if surf_cap_hit or payload_budget_exceeded:
                                break

            _emit_surface_issues(sid_upd, tmp_errors, tmp_warnings)

        def _flush_surface(sid_to_flush: str) -> None:
            nonlocal total_components
            batches = surface_component_batches.pop(sid_to_flush, None)
            dm = surface_data_models.pop(sid_to_flush, {})
            scat = surface_catalog_ids.pop(sid_to_flush, None)
            tpl_map = surface_childlist_templates.get(sid_to_flush, {})
            if batches is None:
                _clear_surface_stream_state(sid_to_flush)
                return

            # Final non-historical check for rare prefix-less formatString URL slots inside ChildList templates
            final_tpl_errors: list[dict[str, Any]] = []
            final_tpl_warnings: list[dict[str, Any]] = []
            flushed_tpl_slot_ids: set[int] = set()
            if not payload_budget_exceeded:
                seen_tpl_pairs_fl: set[tuple[str, str]] = set()
                fl_cap_hit = False
                for _owner_cid, (tpl_root_id, list_ptr) in tpl_map.items():
                    if not isinstance(list_ptr, str) or not list_ptr.startswith("/"):
                        continue
                    tpl_pair = (tpl_root_id, list_ptr)
                    if tpl_pair in seen_tpl_pairs_fl:
                        continue
                    seen_tpl_pairs_fl.add(tpl_pair)
                    _tpl_nodes, rel_slots, has_nested_rel = _collect_template_tree_summary(sid_to_flush, tpl_root_id)
                    prefixless_slots = [s for s in rel_slots if _is_prefixless_format_string_url(s[2])]
                    if not prefixless_slots:
                        continue
                    found_list, items_val = _resolve_json_pointer(
                        dm, list_ptr, max_segments=max_ptr_segments
                    )
                    if not found_list or not isinstance(items_val, list):
                        continue
                    if not has_nested_rel:
                        for item_idx, item in enumerate(items_val):
                            for slot in prefixless_slots:
                                flushed_tpl_slot_ids.add(id(slot))
                                if not _validate_single_url_slot(
                                    sid_to_flush,
                                    slot,
                                    dm,
                                    final_tpl_errors,
                                    final_tpl_warnings,
                                    item_ctx=item,
                                    item_idx=item_idx,
                                    is_historical_snapshot=False,
                                ):
                                    fl_cap_hit = True
                                    break
                            if fl_cap_hit:
                                break
                    else:
                        sc_fl: dict[str, Any] = {}
                        tc_fl: dict[str, bool] = {}
                        for item_idx, item in enumerate(items_val):
                            if _validate_template_item_urls(
                                sid_to_flush,
                                tpl_root_id,
                                dm,
                                item,
                                item_idx,
                                final_tpl_errors,
                                final_tpl_warnings,
                                is_historical_snapshot=False,
                                only_prefixless=True,
                                evaluated_slot_ids=flushed_tpl_slot_ids,
                                scope_cache=sc_fl,
                                tree_has_slots_cache=tc_fl,
                            ):
                                if payload_budget_exceeded:
                                    fl_cap_hit = True
                                break
                    if fl_cap_hit or payload_budget_exceeded:
                        break
            _emit_surface_issues(sid_to_flush, final_tpl_errors, final_tpl_warnings)

            sver = surface_versions.get(sid_to_flush, "1.0")
            sroot = surface_roots.get(sid_to_flush, "root")

            # Compute slot paths already validated against concrete ChildList items on template-only components
            template_only_validated_paths: frozenset[str] = frozenset()
            if flushed_tpl_slot_ids:
                fl_comp_map = surface_active_comp_map.get(sid_to_flush, {})
                fl_adj_map = surface_active_adj.get(sid_to_flush, {})
                direct_reachable: set[str] = set()
                if sroot in fl_comp_map:
                    d_stack = [sroot]
                    while d_stack:
                        dcid = d_stack.pop()
                        if dcid in direct_reachable:
                            continue
                        direct_reachable.add(dcid)
                        d_stack.extend(fl_adj_map.get(dcid, ()))
                tpl_validated: set[str] = set()
                for scid, cslots in surface_url_slots.get(sid_to_flush, {}).items():
                    if scid in direct_reachable:
                        continue
                    for slot in cslots:
                        if id(slot) in flushed_tpl_slot_ids:
                            tpl_validated.add(slot[1])
                template_only_validated_paths = frozenset(tpl_validated)

            flush_errors: list[dict[str, Any]] = []
            flush_warnings: list[dict[str, Any]] = []
            total_components += _validate_surface_components(
                surface_id=sid_to_flush,
                component_batches=batches,
                version=sver,
                root_id=sroot,
                strict=strict,
                max_components=max_components,
                block_index=bidx,
                errors=flush_errors,
                warnings=flush_warnings,
                data_model=dm,
                surface_catalog_id=scat,
                template_validated_url_paths=template_only_validated_paths,
                max_segments=max_ptr_segments,
                safe_media_urls=safe_media_urls,
                safe_open_urls=safe_open_urls,
            )
            _emit_surface_issues(sid_to_flush, flush_errors, flush_warnings)
            _clear_surface_stream_state(sid_to_flush)

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
                    surface_catalog_ids.pop(sid, None)
                    _clear_surface_stream_state(sid)
                    surface_roots[sid] = "root"
                active_surfaces.add(sid)
                ever_created_surfaces.add(sid)
                surface_versions[sid] = msg_ver
                surface_roots.setdefault(sid, "root")
                surface_component_batches.setdefault(sid, [])
                if sid not in surface_ids:
                    surface_ids.append(sid)

                cat_id = body.get("catalogId")
                if "catalogId" in body:
                    if not isinstance(cat_id, str) or not cat_id.strip():
                        _add_issue(
                            errors,
                            "INVALID_CATALOG_ID",
                            bidx,
                            f"{mpath}.createSurface.catalogId",
                            "createSurface.catalogId must be a non-empty string when provided.",
                        )
                        surface_catalog_ids[sid] = None
                    else:
                        surface_catalog_ids[sid] = cat_id
                        if cat_id == BROKEN_V09_CATALOG_ID:
                            _add_issue(
                                warnings,
                                "BROKEN_CATALOG_URI",
                                bidx,
                                f"{mpath}.createSurface.catalogId",
                                f"Catalog URI '{BROKEN_V09_CATALOG_ID}' returns HTTP 404 on a2ui.org; use canonical catalogs/basic/catalog.json.",
                            )
                else:
                    surface_catalog_ids[sid] = None
                    if msg_ver in {"0.9", "0.9.1"}:
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
                    dm_updated_in_cs = False
                    if "dataModel" in body:
                        if isinstance(body["dataModel"], dict):
                            surface_data_models[sid] = body["dataModel"]
                            dm_updated_in_cs = True
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
                            batches = surface_component_batches.setdefault(sid, [])
                            b_idx = len(batches)
                            batches.append(body["components"])
                            _ingest_component_batch(sid, b_idx, body["components"])
                        else:
                            _add_issue(
                                errors,
                                "INVALID_COMPONENTS",
                                bidx,
                                f"{mpath}.createSurface.components",
                                "createSurface.components must be a non-empty list when provided.",
                            )
                    elif dm_updated_in_cs:
                        _validate_streaming_data_update(sid, "/")

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
                    batches = surface_component_batches.setdefault(sid, [])
                    b_idx = len(batches)
                    batches.append(comps)
                    _ingest_component_batch(sid, b_idx, comps)

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
                effective_ptr = ptr if isinstance(ptr, str) else "/"
                popped_idx: int | None = None
                mutated = False
                if ptr in {"", "/"}:
                    if body.get("value") is None:
                        surface_data_models[sid] = {}
                        mutated = True
                    elif isinstance(body.get("value"), dict):
                        surface_data_models[sid] = body["value"]
                        mutated = True
                elif isinstance(ptr, str) and ptr.startswith("/") and "value" in body:
                    dm = surface_data_models.setdefault(sid, {})
                    effective_ptr, popped_idx = _mutate_json_pointer(
                        dm, ptr, body["value"], max_segments=max_ptr_segments
                    )
                    mutated = True
                if mutated and isinstance(effective_ptr, str):
                    _validate_streaming_data_update(sid, effective_ptr, popped_idx=popped_idx)

            elif env_key in {"callRendererFunction", "callAgentFunction"}:
                extra_fn_keys = set(body.keys()) - {"surfaceId", "functionCallId", "callFunction"}
                if extra_fn_keys:
                    _add_issue(
                        errors if strict else warnings,
                        "UNEXPECTED_FUNCTION_ENVELOPE_KEY",
                        bidx,
                        f"{mpath}.{env_key}",
                        f"Unexpected {env_key} keys: {sorted(extra_fn_keys)}.",
                    )
                fn_call_id = body.get("functionCallId")
                if not isinstance(fn_call_id, str) or not fn_call_id.strip():
                    _add_issue(
                        errors,
                        "MISSING_FUNCTION_CALL_ID",
                        bidx,
                        f"{mpath}.{env_key}.functionCallId",
                        f"{env_key} requires non-empty string 'functionCallId'.",
                    )
                sid_opt = body.get("surfaceId")
                if env_key == "callAgentFunction":
                    if not isinstance(sid_opt, str) or not sid_opt.strip():
                        _add_issue(
                            errors,
                            "MISSING_SURFACE_ID",
                            bidx,
                            f"{mpath}.{env_key}.surfaceId",
                            "callAgentFunction requires non-empty string 'surfaceId'.",
                        )
                elif "surfaceId" in body and (not isinstance(sid_opt, str) or not sid_opt.strip()):
                    _add_issue(
                        errors,
                        "INVALID_SURFACE_ID",
                        bidx,
                        f"{mpath}.{env_key}.surfaceId",
                        f"{env_key}.surfaceId must be a non-empty string when provided.",
                    )
                call_fn = body.get("callFunction")
                if not isinstance(call_fn, dict):
                    _add_issue(
                        errors,
                        "INVALID_FUNCTION_CALL",
                        bidx,
                        f"{mpath}.{env_key}.callFunction",
                        f"{env_key}.callFunction must be a FunctionCall object.",
                    )
                else:
                    if "@call" not in call_fn and "call" not in call_fn:
                        _add_issue(
                            errors,
                            "INVALID_FUNCTION_CALL",
                            bidx,
                            f"{mpath}.{env_key}.callFunction",
                            f"{env_key}.callFunction requires '@call'.",
                        )
                    fn_cat = call_fn.get("catalogId")
                    if env_key == "callRendererFunction":
                        if not isinstance(fn_cat, str) or not fn_cat.strip():
                            _add_issue(
                                errors,
                                "MISSING_CATALOG_ID",
                                bidx,
                                f"{mpath}.{env_key}.callFunction.catalogId",
                                "callRendererFunction.callFunction requires non-empty string 'catalogId'.",
                            )
                    elif (
                        "@call" not in call_fn
                        and "call" not in call_fn
                        and "catalogId" in call_fn
                        and (not isinstance(fn_cat, str) or not fn_cat.strip())
                    ):
                        _add_issue(
                            errors,
                            "INVALID_CATALOG_ID",
                            bidx,
                            f"{mpath}.{env_key}.callFunction.catalogId",
                            "callAgentFunction.callFunction.catalogId must be a non-empty string when provided.",
                        )
                    cat_spec = load_catalog_spec(msg_ver)
                    fn_dm = surface_data_models.get(sid_opt, {}) if isinstance(sid_opt, str) else {}
                    fn_surf_cat = surface_catalog_ids.get(sid_opt) if isinstance(sid_opt, str) else None
                    _validate_dynamic_value(
                        call_fn,
                        version=msg_ver,
                        strict=strict,
                        block_index=bidx,
                        path=f"{mpath}.{env_key}.callFunction",
                        errors=errors,
                        warnings=warnings,
                        catalog_functions=set(cat_spec["functions"].keys()),
                        data_model=fn_dm,
                        catalog_function_specs=cat_spec["functions"],
                        catalog_id=cat_spec["catalogId"],
                        effective_catalog_id=fn_surf_cat,
                        allow_user_activation=False,
                        max_segments=max_ptr_segments,
                    )

            elif env_key in {"agentFunctionResponse", "rendererFunctionResponse"}:
                extra_resp_keys = set(body.keys()) - {"functionCallId", "value", "error"}
                if extra_resp_keys:
                    _add_issue(
                        errors,
                        "UNKNOWN_ENVELOPE_FIELD",
                        bidx,
                        f"{mpath}.{env_key}",
                        f"Unexpected {env_key} keys: {sorted(extra_resp_keys)}.",
                    )
                fn_call_id = body.get("functionCallId")
                if not isinstance(fn_call_id, str) or not fn_call_id.strip():
                    _add_issue(
                        errors,
                        "MISSING_FUNCTION_CALL_ID",
                        bidx,
                        f"{mpath}.{env_key}.functionCallId",
                        f"{env_key} requires non-empty string 'functionCallId'.",
                    )
                has_value = "value" in body
                has_error = "error" in body
                if has_value == has_error:
                    _add_issue(
                        errors,
                        "INVALID_FUNCTION_RESPONSE",
                        bidx,
                        f"{mpath}.{env_key}",
                        f"{env_key} must specify exactly one of 'value' or 'error'.",
                    )
                if has_error:
                    err_obj = body.get("error")
                    if not isinstance(err_obj, dict):
                        _add_issue(
                            errors,
                            "INVALID_FUNCTION_RESPONSE_ERROR",
                            bidx,
                            f"{mpath}.{env_key}.error",
                            f"{env_key}.error must be an object with 'code' and 'message'.",
                        )
                    else:
                        extra_err_keys = set(err_obj.keys()) - {"code", "message"}
                        if extra_err_keys:
                            _add_issue(
                                errors,
                                "UNKNOWN_ENVELOPE_FIELD",
                                bidx,
                                f"{mpath}.{env_key}.error",
                                f"Unexpected {env_key}.error keys: {sorted(extra_err_keys)}.",
                            )
                        err_code = err_obj.get("code")
                        if not isinstance(err_code, str) or not err_code.strip():
                            _add_issue(
                                errors,
                                "INVALID_FUNCTION_RESPONSE_ERROR",
                                bidx,
                                f"{mpath}.{env_key}.error.code",
                                f"{env_key}.error.code must be a non-empty string.",
                            )
                        err_msg = err_obj.get("message")
                        if not isinstance(err_msg, str) or not err_msg.strip():
                            _add_issue(
                                errors,
                                "INVALID_FUNCTION_RESPONSE_ERROR",
                                bidx,
                                f"{mpath}.{env_key}.error.message",
                                f"{env_key}.error.message must be a non-empty string.",
                            )

            elif env_key == "dataModelUpdate":
                sid = body.get("surfaceId")
                if not isinstance(sid, str) or not sid:
                    _add_issue(errors, "MISSING_SURFACE_ID", bidx, f"{mpath}.dataModelUpdate.surfaceId", "dataModelUpdate requires 'surfaceId'.")
                else:
                    ptr = body.get("path", "/")
                    effective_ptr = ptr if isinstance(ptr, str) else "/"
                    popped_idx: int | None = None
                    contents = body.get("contents")
                    mutated = False
                    v08_merged_keys: list[str] | None = None
                    if isinstance(contents, list):
                        conv_val = _convert_v08_contents(contents)
                        if ptr in {"", "/"}:
                            dm = surface_data_models.setdefault(sid, {})
                            dm.update(conv_val)
                            v08_merged_keys = list(conv_val.keys())
                        elif isinstance(ptr, str) and ptr.startswith("/"):
                            dm = surface_data_models.setdefault(sid, {})
                            effective_ptr, popped_idx = _mutate_json_pointer(
                                dm, ptr, conv_val, max_segments=max_ptr_segments
                            )
                            mutated = True
                    elif "value" in body:
                        if ptr in {"", "/"}:
                            if body.get("value") is None:
                                surface_data_models[sid] = {}
                                mutated = True
                            elif isinstance(body.get("value"), dict):
                                surface_data_models[sid] = body["value"]
                                mutated = True
                        elif isinstance(ptr, str) and ptr.startswith("/"):
                            dm = surface_data_models.setdefault(sid, {})
                            effective_ptr, popped_idx = _mutate_json_pointer(
                                dm, ptr, body["value"], max_segments=max_ptr_segments
                            )
                            mutated = True
                    if v08_merged_keys is not None:
                        for merged_k in v08_merged_keys:
                            if payload_budget_exceeded:
                                break
                            key_ptr = "/" + merged_k.replace("~", "~0").replace("/", "~1")
                            _validate_streaming_data_update(sid, key_ptr, popped_idx=None)
                    elif mutated and isinstance(effective_ptr, str):
                        _validate_streaming_data_update(sid, effective_ptr, popped_idx=popped_idx)

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
