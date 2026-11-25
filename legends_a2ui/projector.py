"""Zero-coupling generic JSON-to-A2UI v1.0 surface projector (legends-a2ui project)."""
from __future__ import annotations

import json
import re
from typing import Any

from legends_a2ui.normalizer import format_a2ui_messages
from legends_a2ui.parser import DEFAULT_MAX_BYTES, DEFAULT_MAX_DEPTH, loads_strict_json
from legends_a2ui.spec_registry import (
    CANONICAL_V1_CATALOG_ID,
    sanitize_uax31_id,
    scan_for_secrets,
)
from legends_a2ui.validator import validate_payload

_CONTROL_WS_RE = re.compile(r"[\r\n\t\x00-\x1f\x7f]+")


def _sanitize_md_text(val: Any, *, max_len: int | None = None) -> str:
    """Flatten newlines/control chars and escape backticks and Markdown link brackets."""
    text = _CONTROL_WS_RE.sub(" ", str(val)).strip()
    if max_len is not None and len(text) > max_len:
        text = text[: max_len - 3] + "..."
    text = text.replace("`", "'").replace("[", "\\[").replace("]", "\\]")
    return text


def _sanitize_md_code(val: Any, *, max_len: int = 240) -> str:
    """Sanitize a string for safe embedding inside single-backtick Markdown inline code."""
    text = _CONTROL_WS_RE.sub(" ", str(val)).strip()
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text.replace("`", "'").replace("[", "\\[").replace("]", "\\]")

VALID_PRESETS = ("auto", "plan-approval", "health-deck", "data-briefing")
MAX_DISPLAY_ITEMS = 12
_HEALTH_DECK_MARKERS = (
    "checks",
    "errors",
    "warnings",
    "modules",
    "python",
    "vendorSpec",
    "runtime",
    "knowledgePack",
    "health",
    "diagnostics",
    "pathCollisionCheck",
    "status",
)


def detect_preset(data: Any) -> str:
    """Detect the best generic A2UI surface compiler for arbitrary structured JSON."""
    if isinstance(data, dict):
        if "planSha256" in data or "plannedFiles" in data or data.get("mode") == "preview":
            return "plan-approval"
        if isinstance(data.get("ok"), bool) and any(k in data for k in _HEALTH_DECK_MARKERS):
            return "health-deck"
    return "data-briefing"


def _summarize_scalar(val: Any) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if val is None:
        return "null"
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, str):
        return _sanitize_md_text(val, max_len=180)
    if isinstance(val, list):
        return f"({len(val)} items)"
    if isinstance(val, dict):
        return f"{{{len(val)} fields}}"
    return _sanitize_md_text(val, max_len=180)


def _format_section_markdown(val: Any) -> str:
    lines: list[str] = []
    if isinstance(val, dict):
        items = list(val.items())
        for k, v in items[:MAX_DISPLAY_ITEMS]:
            lines.append(f"- **{_sanitize_md_text(k, max_len=80)}**: {_summarize_scalar(v)}")
        if len(items) > MAX_DISPLAY_ITEMS:
            lines.append(f"- +{len(items) - MAX_DISPLAY_ITEMS} more fields")
    elif isinstance(val, list):
        for idx, item in enumerate(val[:MAX_DISPLAY_ITEMS], start=1):
            if isinstance(item, dict):
                summary = ", ".join(
                    f"{_sanitize_md_text(k, max_len=60)}={_summarize_scalar(v)}" for k, v in list(item.items())[:4]
                )
                lines.append(f"- {idx}. {summary}")
            else:
                lines.append(f"- {_summarize_scalar(item)}")
        if len(val) > MAX_DISPLAY_ITEMS:
            lines.append(f"- +{len(val) - MAX_DISPLAY_ITEMS} more items")
    else:
        lines.append(_summarize_scalar(val))
    return "\n".join(lines) if lines else "No entries."


def _compile_plan_approval(
    data: dict[str, Any], *, title: str | None, surface_id: str
) -> list[dict[str, Any]]:
    heading = _sanitize_md_text(title or str(data.get("title") or "Mutation Plan Approval"), max_len=160)
    plan_sha = _sanitize_md_code(data.get("planSha256") or "", max_len=64)
    target = _sanitize_md_code(data.get("target") or data.get("output") or data.get("mode") or "preview", max_len=120)
    raw_files = data.get("plannedFiles")
    if not isinstance(raw_files, list):
        raw_files = []

    file_lines: list[str] = []
    for entry in raw_files[:MAX_DISPLAY_ITEMS]:
        if isinstance(entry, dict):
            path_str = _sanitize_md_code(entry.get("path") or entry.get("absolutePath") or "file")
            bcount = entry.get("bytes")
            exists = entry.get("exists")
            tag = "overwrite" if exists else "create"
            size_part = f" ({bcount} bytes)" if isinstance(bcount, int) else ""
            file_lines.append(f"- `{path_str}` ({tag}){size_part}")
        else:
            file_lines.append(f"- `{_sanitize_md_code(entry)}`")
    if len(raw_files) > MAX_DISPLAY_ITEMS:
        file_lines.append(f"- +{len(raw_files) - MAX_DISPLAY_ITEMS} more files")
    if not file_lines:
        file_lines.append("- No planned file writes listed.")

    warnings_list = data.get("warnings") if isinstance(data.get("warnings"), list) else []
    cost_note = data.get("estimatedCost") or data.get("cost")
    callout_parts: list[str] = []
    if cost_note is not None:
        callout_parts.append(f"Estimated cost: {_summarize_scalar(cost_note)}")
    for w in warnings_list[:5]:
        callout_parts.append(f"Warning: {_summarize_scalar(w)}")

    children = ["plan_heading", "plan_meta", "plan_files_md"]
    components: list[dict[str, Any]] = [
        {"id": "root", "component": "Card", "child": "plan_col"},
        {"id": "plan_heading", "component": "Text", "text": f"## {heading}", "variant": "body"},
        {
            "id": "plan_meta",
            "component": "Text",
            "text": f"Mode: `{target}` | Planned files: `{len(raw_files)}` | planSha256: `{plan_sha[:16] or 'none'}`",
            "variant": "caption",
        },
        {
            "id": "plan_files_md",
            "component": "Text",
            "text": "\n".join(file_lines),
            "variant": "body",
        },
    ]

    if callout_parts:
        children.append("plan_callout")
        components.append(
            {
                "id": "plan_callout",
                "component": "Text",
                "text": "\n".join(callout_parts),
                "variant": "caption",
            }
        )

    children.extend(["plan_divider", "notes_input", "plan_actions"])
    components.extend(
        [
            {"id": "plan_divider", "component": "Divider", "axis": "horizontal"},
            {
                "id": "notes_input",
                "component": "TextField",
                "label": "Approval notes (optional)",
                "value": {"@path": "/notes"},
                "placeholder": "Add release or approval notes",
                "variant": "shortText",
            },
            {
                "id": "plan_actions",
                "component": "Row",
                "justify": "start",
                "children": ["approve_plan_btn", "hold_plan_btn"],
            },
            {
                "id": "approve_plan_btn",
                "component": "Button",
                "child": "approve_plan_lbl",
                "variant": "primary",
                "action": {
                    "event": {
                        "name": "approve_plan",
                        "context": {
                            "planSha256": plan_sha,
                            "notes": {"@path": "/notes"},
                        },
                    }
                },
            },
            {"id": "approve_plan_lbl", "component": "Text", "text": "Approve plan", "variant": "body"},
            {
                "id": "hold_plan_btn",
                "component": "Button",
                "child": "hold_plan_lbl",
                "variant": "default",
                "action": {
                    "event": {
                        "name": "hold_plan",
                        "context": {
                            "planSha256": plan_sha,
                            "notes": {"@path": "/notes"},
                        },
                    }
                },
            },
            {"id": "hold_plan_lbl", "component": "Text", "text": "Hold plan", "variant": "body"},
        ]
    )
    components.insert(1, {"id": "plan_col", "component": "Column", "children": children})

    return [
        {
            "version": "1.0",
            "createSurface": {
                "surfaceId": surface_id,
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": components,
                "dataModel": {"notes": ""},
            },
        }
    ]


def _format_health_issue(item: Any, section: str | None = None) -> str:
    prefix = f"{section}: " if section else ""
    if isinstance(item, dict):
        code = item.get("code")
        msg = item.get("message")
        if isinstance(code, str) and isinstance(msg, str):
            return _summarize_scalar(f"{prefix}[{code}] {msg}")
        if isinstance(msg, str):
            return _summarize_scalar(f"{prefix}{msg}")
    return _summarize_scalar(f"{prefix}{_summarize_scalar(item)}")


def _compile_health_deck(
    data: dict[str, Any], *, title: str | None, surface_id: str
) -> list[dict[str, Any]]:
    ok_flag = bool(data.get("ok"))
    heading = _sanitize_md_text(
        title or ("Health Check: PASS" if ok_flag else "Health Check: ATTENTION"),
        max_len=160,
    )
    has_top_errors = isinstance(data.get("errors"), list)
    has_top_warnings = isinstance(data.get("warnings"), list)
    errors_list: list[Any] = list(data["errors"]) if has_top_errors else []
    warnings_list: list[Any] = list(data["warnings"]) if has_top_warnings else []

    nested_issue_sections = ("runtime", "knowledgePack", "diagnostics", "health", "vendorSpec", "pathCollisionCheck")
    for sec in nested_issue_sections:
        sub = data.get(sec)
        if not isinstance(sub, dict):
            continue
        if not has_top_errors:
            sub_errs = sub.get("errors")
            if isinstance(sub_errs, list):
                for item in sub_errs:
                    errors_list.append(_format_health_issue(item, sec))
            elif isinstance(sub.get("error"), str) and sub["error"].strip():
                errors_list.append(_format_health_issue(sub["error"], sec))
        if not has_top_warnings:
            sub_warns = sub.get("warnings")
            if isinstance(sub_warns, list):
                for item in sub_warns:
                    warnings_list.append(_format_health_issue(item, sec))
            elif isinstance(sub.get("warning"), str) and sub["warning"].strip():
                warnings_list.append(_format_health_issue(sub["warning"], sec))

    diag_lines: list[str] = []
    for k, v in data.items():
        if k in {"ok", "errors", "warnings"}:
            continue
        safe_k = _sanitize_md_text(k, max_len=80)
        if isinstance(v, dict):
            compact = ", ".join(
                f"{_sanitize_md_text(sk, max_len=60)}={_summarize_scalar(sv)}" for sk, sv in list(v.items())[:5]
            )
            diag_lines.append(f"- **{safe_k}**: {compact}")
            if k == "runtime":
                node_sub = v.get("node")
                if isinstance(node_sub, dict):
                    node_bits = [
                        f"{nk}={_summarize_scalar(node_sub[nk])}"
                        for nk in ("version", "status", "enginesRequired")
                        if nk in node_sub
                    ]
                    if node_bits:
                        diag_lines.append(f"- **runtime.node**: {', '.join(node_bits)}")
                snap_sub = v.get("snapshot")
                if isinstance(snap_sub, dict):
                    snap_bits = [
                        f"{sk}={_summarize_scalar(snap_sub[sk])}"
                        for sk in ("ok", "files", "schema")
                        if sk in snap_sub
                    ]
                    if snap_bits:
                        diag_lines.append(f"- **runtime.snapshot**: {', '.join(snap_bits)}")
        else:
            diag_lines.append(f"- **{safe_k}**: {_summarize_scalar(v)}")
    if not diag_lines:
        diag_lines.append("- No diagnostic entries reported.")

    issues_lines: list[str] = []
    for err in errors_list[:8]:
        issues_lines.append(f"- [ERROR] {_format_health_issue(err)}")
    for warn in warnings_list[:8]:
        issues_lines.append(f"- [WARN] {_format_health_issue(warn)}")
    if not issues_lines:
        issues_lines.append("- Zero errors and zero warnings.")

    return [
        {
            "version": "1.0",
            "createSurface": {
                "surfaceId": surface_id,
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Card", "child": "health_col"},
                    {
                        "id": "health_col",
                        "component": "Column",
                        "children": [
                            "health_heading",
                            "health_summary",
                            "health_divider",
                            "health_diag",
                            "health_issues",
                            "health_actions",
                        ],
                    },
                    {"id": "health_heading", "component": "Text", "text": f"## {heading}", "variant": "body"},
                    {
                        "id": "health_summary",
                        "component": "Text",
                        "text": f"Status: `{'PASS' if ok_flag else 'FAIL'}` | Errors: `{len(errors_list)}` | Warnings: `{len(warnings_list)}`",
                        "variant": "caption",
                    },
                    {"id": "health_divider", "component": "Divider", "axis": "horizontal"},
                    {"id": "health_diag", "component": "Text", "text": "\n".join(diag_lines[:16]), "variant": "body"},
                    {"id": "health_issues", "component": "Text", "text": "\n".join(issues_lines), "variant": "caption"},
                    {
                        "id": "health_actions",
                        "component": "Row",
                        "justify": "start",
                        "children": ["rerun_btn", "export_btn"],
                    },
                    {
                        "id": "rerun_btn",
                        "component": "Button",
                        "child": "rerun_lbl",
                        "variant": "primary",
                        "action": {"event": {"name": "rerun_check", "context": {"ok": ok_flag}}},
                    },
                    {"id": "rerun_lbl", "component": "Text", "text": "Rerun check", "variant": "body"},
                    {
                        "id": "export_btn",
                        "component": "Button",
                        "child": "export_lbl",
                        "variant": "default",
                        "action": {"event": {"name": "export_report", "context": {"ok": ok_flag}}},
                    },
                    {"id": "export_lbl", "component": "Text", "text": "Export report", "variant": "body"},
                ],
                "dataModel": {},
            },
        }
    ]


def _compile_data_briefing(
    data: Any, *, title: str | None, surface_id: str
) -> list[dict[str, Any]]:
    raw_heading = title or (str(data.get("title")) if isinstance(data, dict) and data.get("title") else "Structured Data Briefing")
    heading = _sanitize_md_text(raw_heading, max_len=160)
    components: list[dict[str, Any]] = [
        {"id": "root", "component": "Card", "child": "brief_col"},
    ]
    col_children = ["brief_heading"]
    components.append({"id": "brief_heading", "component": "Text", "text": f"## {heading}", "variant": "body"})

    if isinstance(data, dict):
        scalars = [(k, v) for k, v in data.items() if not isinstance(v, (dict, list))]
        sections = [(k, v) for k, v in data.items() if isinstance(v, (dict, list))]

        if scalars:
            scalar_lines = [f"- **{_sanitize_md_text(k, max_len=80)}**: {_summarize_scalar(v)}" for k, v in scalars[:MAX_DISPLAY_ITEMS]]
            col_children.append("scalar_summary")
            components.append(
                {"id": "scalar_summary", "component": "Text", "text": "\n".join(scalar_lines), "variant": "body"}
            )

        if 2 <= len(sections) <= 5:
            tab_items: list[dict[str, Any]] = []
            for idx, (sec_key, sec_val) in enumerate(sections):
                tid = f"sec_tab_{idx + 1}"
                tab_items.append({"title": _sanitize_md_text(sec_key, max_len=80), "child": tid})
                components.append(
                    {
                        "id": tid,
                        "component": "Text",
                        "text": _format_section_markdown(sec_val),
                        "variant": "body",
                    }
                )
            col_children.append("sections_tabs")
            components.append({"id": "sections_tabs", "component": "Tabs", "tabs": tab_items})
        else:
            for idx, (sec_key, sec_val) in enumerate(sections[:6]):
                card_id = f"sec_card_{idx + 1}"
                inner_id = f"sec_col_{idx + 1}"
                h_id = f"sec_hdr_{idx + 1}"
                b_id = f"sec_body_{idx + 1}"
                col_children.append(card_id)
                components.extend(
                    [
                        {"id": card_id, "component": "Card", "child": inner_id},
                        {"id": inner_id, "component": "Column", "children": [h_id, b_id]},
                        {"id": h_id, "component": "Text", "text": f"### {_sanitize_md_text(sec_key, max_len=80)}", "variant": "body"},
                        {"id": b_id, "component": "Text", "text": _format_section_markdown(sec_val), "variant": "body"},
                    ]
                )
    else:
        col_children.append("body_text")
        components.append(
            {"id": "body_text", "component": "Text", "text": _format_section_markdown(data), "variant": "body"}
        )

    col_children.append("brief_actions")
    components.extend(
        [
            {
                "id": "brief_actions",
                "component": "Row",
                "justify": "start",
                "children": ["ack_brief_btn"],
            },
            {
                "id": "ack_brief_btn",
                "component": "Button",
                "child": "ack_brief_lbl",
                "variant": "primary",
                "action": {"event": {"name": "acknowledge_briefing", "context": {"title": heading}}},
            },
            {"id": "ack_brief_lbl", "component": "Text", "text": "Acknowledge", "variant": "body"},
        ]
    )
    components.insert(1, {"id": "brief_col", "component": "Column", "children": col_children})

    return [
        {
            "version": "1.0",
            "createSurface": {
                "surfaceId": surface_id,
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": components,
                "dataModel": {},
            },
        }
    ]


def project_json_to_surface(
    raw_text: str,
    *,
    preset: str = "auto",
    title: str | None = None,
    surface_id: str | None = None,
    fmt: str = "markdown-fence",
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> dict[str, Any]:
    """Compile arbitrary structured JSON into a strict-validated A2UI v1.0 surface."""
    if preset not in VALID_PRESETS:
        return {
            "ok": False,
            "preset": preset,
            "error": f"Unknown preset '{preset}'. Choose from: {', '.join(VALID_PRESETS)}",
            "payload": None,
            "formatted": "",
            "validation": {"ok": False, "errors": [], "warnings": []},
        }

    try:
        data = loads_strict_json(raw_text, max_bytes=max_bytes, max_depth=max_depth)
    except Exception as exc:
        return {
            "ok": False,
            "preset": preset,
            "error": f"Input is not valid JSON: {exc}",
            "payload": None,
            "formatted": "",
            "validation": {"ok": False, "errors": [], "warnings": []},
        }

    secret_findings = scan_for_secrets(data)
    if secret_findings:
        return {
            "ok": False,
            "preset": preset,
            "error": "Secret token detected in input JSON; refused before surface projection.",
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

    resolved_preset = detect_preset(data) if preset == "auto" else preset
    sid = surface_id or sanitize_uax31_id(f"projected_{resolved_preset}")

    if resolved_preset == "plan-approval":
        messages = _compile_plan_approval(
            data if isinstance(data, dict) else {"items": data},
            title=title,
            surface_id=sid,
        )
    elif resolved_preset == "health-deck":
        messages = _compile_health_deck(
            data if isinstance(data, dict) else {"ok": False, "value": data},
            title=title,
            surface_id=sid,
        )
    else:
        messages = _compile_data_briefing(data, title=title, surface_id=sid)

    validation = validate_payload(json.dumps(messages, allow_nan=False), version="1.0", strict=True)
    formatted = format_a2ui_messages(messages, fmt) if validation["ok"] else ""
    return {
        "ok": bool(validation["ok"]),
        "preset": resolved_preset,
        "surfaceId": sid,
        "payload": messages if validation["ok"] else None,
        "formatted": formatted,
        "validation": validation,
    }
