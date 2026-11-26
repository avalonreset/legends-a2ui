"""Multi-format A2UI parser (JSON object, array, wrapper, JSONL, Markdown fences) with CWE-400 bounds."""
from __future__ import annotations

import io
import json
import re
from typing import Any

DEFAULT_MAX_BYTES = 1_048_576
DEFAULT_MAX_DEPTH = 64
_MAX_PARSE_ERRORS_PER_BLOCK = 64
_MAX_PARSE_ERRORS_TOTAL = 256
_MAX_MARKDOWN_BLOCKS = 1024
_PRIORITY_PARSE_ERROR_CODES = frozenset(
    {
        "MAX_DEPTH_EXCEEDED",
        "MAX_MESSAGES_EXCEEDED",
        "MAX_BLOCKS_EXCEEDED",
        "MAX_BYTES_EXCEEDED",
    }
)

A2UI_FENCE_LANGS = frozenset({"a2ui", "a2ui-json", "a2ui-jsonl"})
_FENCE_OPEN_RE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})[ \t]*([^\s`~]*)(.*)$")


def _reject_nonstandard_json_constant(token: str) -> Any:
    raise ValueError(f"Non-standard JSON constant '{token}' is disallowed.")


_STRICT_JSON_DECODER = json.JSONDecoder(parse_constant=_reject_nonstandard_json_constant)


def loads_strict_json(
    raw_text: str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> Any:
    """Parse strict RFC 8259 JSON with byte/depth bounds and NaN/Infinity refusal."""
    encoded_len = len(raw_text.encode("utf-8"))
    if encoded_len > max_bytes:
        raise ValueError(f"Input size ({encoded_len} bytes) exceeds max_bytes ({max_bytes}).")
    if _check_raw_nesting_depth(raw_text, max_depth) > max_depth:
        raise ValueError(f"JSON nesting depth exceeded max_depth ({max_depth}).")
    parsed = _STRICT_JSON_DECODER.decode(raw_text)
    if _measure_object_depth(parsed, max_depth) > max_depth:
        raise ValueError(f"JSON nesting depth exceeded max_depth ({max_depth}).")
    return parsed


def _check_raw_nesting_depth(raw_text: str, max_depth: int) -> int:
    """Fast linear bracket/brace depth pre-scan before json.loads (prevents RecursionError)."""
    depth = 0
    peak = 0
    in_string = False
    escaped = False
    for ch in raw_text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
            if depth > peak:
                peak = depth
            if depth > max_depth:
                return depth
        elif ch in "}]":
            if depth > 0:
                depth -= 1
    return peak


def _measure_object_depth(obj: Any, max_depth: int) -> int:
    """Iterative depth check on parsed Python objects with O(depth) memory."""
    obj_t = type(obj)
    if obj_t is not dict and obj_t is not list:
        if not isinstance(obj, (dict, list)):
            return 0
    peak = 1
    if 1 > max_depth:
        return 1
    if not obj:
        return 1
    # Stack frames: [is_list, iterator]
    stack: list[Any] = [iter(obj) if isinstance(obj, list) else iter(obj.values())]
    while stack:
        it = stack[-1]
        child_depth = len(stack) + 1
        pushed = False
        for child in it:
            ct = type(child)
            if ct is dict:
                if child_depth > peak:
                    peak = child_depth
                if child_depth > max_depth:
                    return child_depth
                if child:
                    has_non_empty = False
                    for v in child.values():
                        vt = type(v)
                        if vt is dict or vt is list:
                            if child_depth + 1 > peak:
                                peak = child_depth + 1
                            if child_depth + 1 > max_depth:
                                return child_depth + 1
                            if v:
                                has_non_empty = True
                                break
                    if has_non_empty:
                        stack.append(iter(child.values()))
                        pushed = True
                        break
            elif ct is list:
                if child_depth > peak:
                    peak = child_depth
                if child_depth > max_depth:
                    return child_depth
                if child:
                    stack.append(iter(child))
                    pushed = True
                    break
        if not pushed:
            stack.pop()
    return peak


def _add_parse_error(
    bucket: list[dict[str, Any]],
    err: dict[str, Any],
    *,
    limit: int,
    seen_priority_codes: set[str],
) -> None:
    code = err["code"]
    if code in _PRIORITY_PARSE_ERROR_CODES:
        if len(bucket) < limit:
            bucket.append(err)
            seen_priority_codes.add(code)
        elif code not in seen_priority_codes:
            for idx in range(len(bucket) - 1, -1, -1):
                if bucket[idx]["code"] not in _PRIORITY_PARSE_ERROR_CODES:
                    bucket[idx] = err
                    seen_priority_codes.add(code)
                    return
            bucket.append(err)
            seen_priority_codes.add(code)
        return
    if len(bucket) < limit:
        bucket.append(err)


def _extract_markdown_a2ui_blocks(
    markdown_text: str,
    *,
    max_blocks: int | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    """Stream Markdown lines and extract fenced ```a2ui / ```a2ui-json / ```a2ui-jsonl blocks."""
    blocks: list[dict[str, Any]] = []
    truncated = False
    in_fence = False
    fence_char = ""
    fence_len = 0
    fence_lang = ""
    start_line = 0
    buf: list[str] = []
    line_no = 0

    for raw_line in io.StringIO(markdown_text, newline=None):
        line_no += 1
        line = raw_line.rstrip("\r\n")
        if not in_fence:
            match = _FENCE_OPEN_RE.match(line)
            if match:
                marker = match.group(1)
                lang = match.group(2).strip().lower()
                if lang in A2UI_FENCE_LANGS and max_blocks is not None and len(blocks) >= max_blocks:
                    truncated = True
                    break
                in_fence = True
                fence_char = marker[0]
                fence_len = len(marker)
                fence_lang = lang
                start_line = line_no
                buf = []
        else:
            stripped = line.strip()
            if (
                stripped
                and all(ch == fence_char for ch in stripped)
                and len(stripped) >= fence_len
            ):
                if fence_lang in A2UI_FENCE_LANGS:
                    blocks.append(
                        {
                            "blockIndex": len(blocks),
                            "fenceLang": fence_lang,
                            "startLine": start_line,
                            "endLine": line_no,
                            "content": "\n".join(buf),
                        }
                    )
                in_fence = False
                fence_char = ""
                fence_len = 0
                fence_lang = ""
                buf = []
            elif fence_lang in A2UI_FENCE_LANGS:
                buf.append(line)

    if in_fence and fence_lang in A2UI_FENCE_LANGS:
        if max_blocks is not None and len(blocks) >= max_blocks:
            truncated = True
        else:
            blocks.append(
                {
                    "blockIndex": len(blocks),
                    "fenceLang": fence_lang,
                    "startLine": start_line,
                    "endLine": line_no,
                    "content": "\n".join(buf),
                    "unclosed": True,
                }
            )
    return blocks, truncated


def extract_markdown_a2ui_blocks(
    markdown_text: str,
    *,
    max_blocks: int | None = None,
) -> list[dict[str, Any]]:
    """Extract all fenced ```a2ui, ```a2ui-json, and ```a2ui-jsonl blocks with line numbers."""
    blocks, _ = _extract_markdown_a2ui_blocks(markdown_text, max_blocks=max_blocks)
    return blocks


def _extract_messages_from_parsed(parsed: Any) -> tuple[list[dict[str, Any]], str]:
    if isinstance(parsed, list):
        for item in parsed:
            if not isinstance(item, dict):
                raise ValueError("JSON array contains non-object elements.")
        return parsed, "json-array"
    if isinstance(parsed, dict):
        if "messages" in parsed and isinstance(parsed["messages"], list):
            raw_list = parsed["messages"]
            for item in raw_list:
                if not isinstance(item, dict):
                    raise ValueError("'messages' wrapper contains non-object elements.")
            return raw_list, "messages-wrapper"
        return [parsed], "json-object"
    raise ValueError("Top-level A2UI payload must be a JSON object or array.")


def _parse_single_block(
    content: str,
    *,
    block_index: int,
    start_line: int,
    end_line: int,
    max_depth: int,
    max_messages: int = 32_768,
    fence_lang: str | None = None,
) -> dict[str, Any]:
    trimmed = content.strip()
    if not trimmed:
        return {
            "blockIndex": block_index,
            "startLine": start_line,
            "endLine": end_line,
            "fenceLang": fence_lang,
            "format": "empty",
            "messages": [],
            "errors": [
                {
                    "code": "EMPTY_PAYLOAD",
                    "blockIndex": block_index,
                    "path": "$",
                    "message": "A2UI payload block is empty.",
                }
            ],
        }

    pre_depth = _check_raw_nesting_depth(trimmed, max_depth)
    if pre_depth > max_depth:
        return {
            "blockIndex": block_index,
            "startLine": start_line,
            "endLine": end_line,
            "fenceLang": fence_lang,
            "format": "unknown",
            "messages": [],
            "errors": [
                {
                    "code": "MAX_DEPTH_EXCEEDED",
                    "blockIndex": block_index,
                    "path": "$",
                    "message": f"Payload nesting depth exceeded max_depth ({max_depth}).",
                }
            ],
        }

    # Try full JSON parse first.
    # _check_raw_nesting_depth already verified exact RFC 8259 nesting depth <= max_depth.
    try:
        parsed = _STRICT_JSON_DECODER.decode(trimmed)
        messages_truncated = False
        if isinstance(parsed, list) and len(parsed) > max_messages:
            parsed = parsed[:max_messages]
            messages_truncated = True
        elif (
            isinstance(parsed, dict)
            and isinstance(parsed.get("messages"), list)
            and len(parsed["messages"]) > max_messages
        ):
            parsed = dict(parsed)
            parsed["messages"] = parsed["messages"][:max_messages]
            messages_truncated = True
        messages, fmt = _extract_messages_from_parsed(parsed)
        if len(messages) > max_messages:
            messages = messages[:max_messages]
            messages_truncated = True
        block_errors: list[dict[str, Any]] = []
        if messages_truncated:
            block_errors.append(
                {
                    "code": "MAX_MESSAGES_EXCEEDED",
                    "blockIndex": block_index,
                    "path": "$",
                    "message": f"Payload message count exceeded maximum ({max_messages}).",
                }
            )
        return {
            "blockIndex": block_index,
            "startLine": start_line,
            "endLine": end_line,
            "fenceLang": fence_lang,
            "format": fmt,
            "messages": messages,
            "errors": block_errors,
        }
    except ValueError as exc:
        if not isinstance(exc, json.JSONDecodeError):
            return {
                "blockIndex": block_index,
                "startLine": start_line,
                "endLine": end_line,
                "fenceLang": fence_lang,
                "format": "json",
                "messages": [],
                "errors": [
                    {
                        "code": "INVALID_STRUCTURE",
                        "blockIndex": block_index,
                        "path": "$",
                        "message": str(exc),
                    }
                ],
            }
    except Exception:
        pass

    # Fall back to streaming JSONL line-by-line parsing with bounded errors and messages.
    messages: list[dict[str, Any]] = []
    line_errors: list[dict[str, Any]] = []
    seen_priority_codes: set[str] = set()
    non_empty_count = 0
    for offset, raw_line in enumerate(io.StringIO(trimmed, newline=None), start=1):
        line_str = raw_line.strip()
        if not line_str:
            continue
        non_empty_count += 1
        if non_empty_count > max_messages:
            line_errors.append(
                {
                    "code": "MAX_MESSAGES_EXCEEDED",
                    "blockIndex": block_index,
                    "path": f"line:{offset}",
                    "message": f"JSONL non-empty line count exceeded maximum ({max_messages}).",
                }
            )
            break
        first_ch = line_str[0]
        if first_ch not in "{[":
            if len(line_errors) < _MAX_PARSE_ERRORS_PER_BLOCK:
                line_errors.append(
                    {
                        "code": "JSON_PARSE_ERROR",
                        "blockIndex": block_index,
                        "path": f"line:{offset}",
                        "message": f"Invalid JSON on line {offset}: Top-level A2UI payload must be a JSON object or array.",
                    }
                )
            continue
        if _check_raw_nesting_depth(line_str, max_depth) > max_depth:
            if (
                len(line_errors) < _MAX_PARSE_ERRORS_PER_BLOCK
                or "MAX_DEPTH_EXCEEDED" not in seen_priority_codes
            ):
                line_errors.append(
                    {
                        "code": "MAX_DEPTH_EXCEEDED",
                        "blockIndex": block_index,
                        "path": f"line:{offset}",
                        "message": f"JSONL line {offset} exceeded max_depth ({max_depth}).",
                    }
                )
                seen_priority_codes.add("MAX_DEPTH_EXCEEDED")
            continue
        try:
            item = _STRICT_JSON_DECODER.decode(line_str)
            remaining = max_messages - len(messages)
            line_truncated = False
            if isinstance(item, list) and len(item) > remaining:
                item = item[:remaining]
                line_truncated = True
            elif (
                isinstance(item, dict)
                and isinstance(item.get("messages"), list)
                and len(item["messages"]) > remaining
            ):
                item = dict(item)
                item["messages"] = item["messages"][:remaining]
                line_truncated = True
            if _measure_object_depth(item, max_depth) > max_depth:
                if (
                    len(line_errors) < _MAX_PARSE_ERRORS_PER_BLOCK
                    or "MAX_DEPTH_EXCEEDED" not in seen_priority_codes
                ):
                    line_errors.append(
                        {
                            "code": "MAX_DEPTH_EXCEEDED",
                            "blockIndex": block_index,
                            "path": f"line:{offset}",
                            "message": f"JSONL line {offset} exceeded max_depth ({max_depth}).",
                        }
                    )
                    seen_priority_codes.add("MAX_DEPTH_EXCEEDED")
                continue
            extracted, _ = _extract_messages_from_parsed(item)
            if len(extracted) > remaining:
                if remaining > 0:
                    messages.extend(extracted[:remaining])
                line_truncated = True
            else:
                messages.extend(extracted)
            if line_truncated:
                line_errors.append(
                    {
                        "code": "MAX_MESSAGES_EXCEEDED",
                        "blockIndex": block_index,
                        "path": f"line:{offset}",
                        "message": f"Payload message count exceeded maximum ({max_messages}).",
                    }
                )
                break
        except Exception as exc:
            if len(line_errors) < _MAX_PARSE_ERRORS_PER_BLOCK:
                line_errors.append(
                    {
                        "code": "JSON_PARSE_ERROR",
                        "blockIndex": block_index,
                        "path": f"line:{offset}",
                        "message": f"Invalid JSON on line {offset}: {exc}",
                    }
                )

    return {
        "blockIndex": block_index,
        "startLine": start_line,
        "endLine": end_line,
        "fenceLang": fence_lang,
        "format": "jsonl" if messages else "invalid",
        "messages": messages,
        "errors": line_errors,
    }


def parse_payload(
    raw_text: str,
    *,
    extract_markdown: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> dict[str, Any]:
    """Parse raw JSON/JSONL or Markdown-fenced A2UI payloads with strict DoS bounds."""
    encoded_len = len(raw_text.encode("utf-8"))
    if encoded_len > max_bytes:
        return {
            "ok": False,
            "byteLength": encoded_len,
            "blockCount": 0,
            "blocks": [],
            "errors": [
                {
                    "code": "MAX_BYTES_EXCEEDED",
                    "blockIndex": 0,
                    "path": "$",
                    "message": f"Input size ({encoded_len} bytes) exceeds max_bytes ({max_bytes}).",
                }
            ],
        }

    max_messages = max(16_384, max_bytes // 32)

    if extract_markdown:
        extracted, blocks_truncated = _extract_markdown_a2ui_blocks(
            raw_text, max_blocks=_MAX_MARKDOWN_BLOCKS
        )
        if not extracted:
            return {
                "ok": False,
                "byteLength": encoded_len,
                "blockCount": 0,
                "blocks": [],
                "errors": [
                    {
                        "code": "NO_A2UI_BLOCKS",
                        "blockIndex": 0,
                        "path": "$",
                        "message": "No fenced ```a2ui, ```a2ui-json, or ```a2ui-jsonl blocks found in Markdown.",
                    }
                ],
            }
        parsed_blocks: list[dict[str, Any]] = []
        top_errors: list[dict[str, Any]] = []
        seen_priority_codes: set[str] = set()
        total_messages = 0
        messages_limit_hit = False
        for blk in extracted:
            if messages_limit_hit:
                break
            parsed = _parse_single_block(
                blk["content"],
                block_index=blk["blockIndex"],
                start_line=blk["startLine"],
                end_line=blk["endLine"],
                max_depth=max_depth,
                max_messages=max(0, max_messages - total_messages),
                fence_lang=blk["fenceLang"],
            )
            if blk.get("unclosed"):
                parsed["errors"].append(
                    {
                        "code": "UNCLOSED_FENCE",
                        "blockIndex": blk["blockIndex"],
                        "path": "$",
                        "message": f"Fenced ```{blk['fenceLang']} block starting at line {blk['startLine']} is unclosed.",
                    }
                )
            total_messages += len(parsed["messages"])
            parsed_blocks.append(parsed)
            for err in parsed["errors"]:
                _add_parse_error(
                    top_errors,
                    err,
                    limit=_MAX_PARSE_ERRORS_TOTAL,
                    seen_priority_codes=seen_priority_codes,
                )
                if err["code"] == "MAX_MESSAGES_EXCEEDED":
                    messages_limit_hit = True
        if blocks_truncated:
            _add_parse_error(
                top_errors,
                {
                    "code": "MAX_BLOCKS_EXCEEDED",
                    "blockIndex": len(parsed_blocks),
                    "path": "$",
                    "message": f"Markdown fenced A2UI block count exceeded maximum ({_MAX_MARKDOWN_BLOCKS}).",
                },
                limit=_MAX_PARSE_ERRORS_TOTAL,
                seen_priority_codes=seen_priority_codes,
            )
        return {
            "ok": len(top_errors) == 0,
            "byteLength": encoded_len,
            "blockCount": len(parsed_blocks),
            "blocks": parsed_blocks,
            "errors": top_errors,
        }

    line_count = (raw_text.count("\n") + (0 if raw_text.endswith("\n") else 1)) if raw_text else 1
    single = _parse_single_block(
        raw_text,
        block_index=0,
        start_line=1,
        end_line=line_count,
        max_depth=max_depth,
        max_messages=max_messages,
    )
    return {
        "ok": len(single["errors"]) == 0,
        "byteLength": encoded_len,
        "blockCount": 1,
        "blocks": [single],
        "errors": list(single["errors"]),
    }
