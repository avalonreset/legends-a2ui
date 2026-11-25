"""Multi-format A2UI parser (JSON object, array, wrapper, JSONL, Markdown fences) with CWE-400 bounds."""
from __future__ import annotations

import json
import re
from typing import Any

DEFAULT_MAX_BYTES = 1_048_576
DEFAULT_MAX_DEPTH = 64

A2UI_FENCE_LANGS = frozenset({"a2ui", "a2ui-json", "a2ui-jsonl"})
_FENCE_OPEN_RE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})[ \t]*([^\s`~]*)(.*)$")


def _reject_nonstandard_json_constant(token: str) -> Any:
    raise ValueError(f"Non-standard JSON constant '{token}' is disallowed.")


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
    parsed = json.loads(raw_text, parse_constant=_reject_nonstandard_json_constant)
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
    """Iterative depth check on parsed Python objects."""
    peak = 0
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        cur, depth = stack.pop()
        if isinstance(cur, dict):
            if depth > peak:
                peak = depth
            if depth > max_depth:
                return depth
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
        elif isinstance(cur, list):
            if depth > peak:
                peak = depth
            if depth > max_depth:
                return depth
            for item in cur:
                if isinstance(item, (dict, list)):
                    stack.append((item, depth + 1))
    return peak


def extract_markdown_a2ui_blocks(markdown_text: str) -> list[dict[str, Any]]:
    """Extract all fenced ```a2ui, ```a2ui-json, and ```a2ui-jsonl blocks with line numbers."""
    lines = markdown_text.splitlines()
    blocks: list[dict[str, Any]] = []
    in_fence = False
    fence_char = ""
    fence_len = 0
    fence_lang = ""
    start_line = 0
    buf: list[str] = []

    for idx, line in enumerate(lines, start=1):
        if not in_fence:
            match = _FENCE_OPEN_RE.match(line)
            if match:
                marker = match.group(1)
                lang = match.group(2).strip().lower()
                in_fence = True
                fence_char = marker[0]
                fence_len = len(marker)
                fence_lang = lang
                start_line = idx
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
                            "endLine": idx,
                            "content": "\n".join(buf),
                        }
                    )
                in_fence = False
                fence_char = ""
                fence_len = 0
                fence_lang = ""
                buf = []
            else:
                buf.append(line)

    if in_fence and fence_lang in A2UI_FENCE_LANGS:
        blocks.append(
            {
                "blockIndex": len(blocks),
                "fenceLang": fence_lang,
                "startLine": start_line,
                "endLine": len(lines),
                "content": "\n".join(buf),
                "unclosed": True,
            }
        )
    return blocks


def _extract_messages_from_parsed(parsed: Any) -> tuple[list[dict[str, Any]], str]:
    if isinstance(parsed, list):
        msgs = [item for item in parsed if isinstance(item, dict)]
        if len(msgs) != len(parsed):
            raise ValueError("JSON array contains non-object elements.")
        return msgs, "json-array"
    if isinstance(parsed, dict):
        if "messages" in parsed and isinstance(parsed["messages"], list):
            raw_list = parsed["messages"]
            msgs = [item for item in raw_list if isinstance(item, dict)]
            if len(msgs) != len(raw_list):
                raise ValueError("'messages' wrapper contains non-object elements.")
            return msgs, "messages-wrapper"
        return [parsed], "json-object"
    raise ValueError("Top-level A2UI payload must be a JSON object or array.")


def _parse_single_block(
    content: str,
    *,
    block_index: int,
    start_line: int,
    end_line: int,
    max_depth: int,
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
    try:
        parsed = json.loads(trimmed, parse_constant=_reject_nonstandard_json_constant)
        if _measure_object_depth(parsed, max_depth) > max_depth:
            return {
                "blockIndex": block_index,
                "startLine": start_line,
                "endLine": end_line,
                "fenceLang": fence_lang,
                "format": "json",
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
        messages, fmt = _extract_messages_from_parsed(parsed)
        return {
            "blockIndex": block_index,
            "startLine": start_line,
            "endLine": end_line,
            "fenceLang": fence_lang,
            "format": fmt,
            "messages": messages,
            "errors": [],
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

    # Fall back to JSONL line-by-line parsing.
    messages: list[dict[str, Any]] = []
    line_errors: list[dict[str, Any]] = []
    non_empty_lines = [
        (offset, line.strip())
        for offset, line in enumerate(trimmed.splitlines(), start=1)
        if line.strip()
    ]
    for offset, line_str in non_empty_lines:
        try:
            item = json.loads(line_str, parse_constant=_reject_nonstandard_json_constant)
            if _measure_object_depth(item, max_depth) > max_depth:
                line_errors.append(
                    {
                        "code": "MAX_DEPTH_EXCEEDED",
                        "blockIndex": block_index,
                        "path": f"line:{offset}",
                        "message": f"JSONL line {offset} exceeded max_depth ({max_depth}).",
                    }
                )
                continue
            extracted, _ = _extract_messages_from_parsed(item)
            messages.extend(extracted)
        except Exception as exc:
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

    if extract_markdown:
        extracted = extract_markdown_a2ui_blocks(raw_text)
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
        parsed_blocks = []
        top_errors = []
        for blk in extracted:
            parsed = _parse_single_block(
                blk["content"],
                block_index=blk["blockIndex"],
                start_line=blk["startLine"],
                end_line=blk["endLine"],
                max_depth=max_depth,
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
            parsed_blocks.append(parsed)
            top_errors.extend(parsed["errors"])
        return {
            "ok": len(top_errors) == 0,
            "byteLength": encoded_len,
            "blockCount": len(parsed_blocks),
            "blocks": parsed_blocks,
            "errors": top_errors,
        }

    line_count = max(1, len(raw_text.splitlines()))
    single = _parse_single_block(
        raw_text,
        block_index=0,
        start_line=1,
        end_line=line_count,
        max_depth=max_depth,
    )
    return {
        "ok": len(single["errors"]) == 0,
        "byteLength": encoded_len,
        "blockCount": 1,
        "blocks": [single],
        "errors": list(single["errors"]),
    }
