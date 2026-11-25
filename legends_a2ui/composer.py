"""Curated A2UI v1.0 operator surface template composer with automatic strict validation."""
from __future__ import annotations

import json
import math
from typing import Any

from legends_a2ui.normalizer import format_a2ui_messages
from legends_a2ui.spec_registry import (
    CANONICAL_V1_CATALOG_ID,
    sanitize_uax31_id,
    scan_for_secrets,
)
from legends_a2ui.validator import validate_payload


def _ship_call(v: dict[str, Any], surface_id: str) -> list[dict[str, Any]]:
    title = str(v.get("title", "Release Ship Call"))
    summary = str(
        v.get("summary", "All verification gates passed. Confirm deployment approval or hold.")
    )
    target = str(v.get("target", "production"))
    approve_label = str(v.get("approve_label", "Approve and ship"))
    hold_label = str(v.get("hold_label", "Hold release"))
    notes_placeholder = str(v.get("notes_placeholder", "Optional release notes or conditions"))
    return [
        {
            "version": "1.0",
            "createSurface": {
                "surfaceId": surface_id,
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Card", "child": "main_col"},
                    {
                        "id": "main_col",
                        "component": "Column",
                        "children": [
                            "heading_text",
                            "target_caption",
                            "summary_text",
                            "top_divider",
                            "notes_field",
                            "actions_row",
                        ],
                    },
                    {"id": "heading_text", "component": "Text", "text": f"## {title}", "variant": "body"},
                    {"id": "target_caption", "component": "Text", "text": f"Target: `{target}`", "variant": "caption"},
                    {"id": "summary_text", "component": "Text", "text": summary, "variant": "body"},
                    {"id": "top_divider", "component": "Divider", "axis": "horizontal"},
                    {
                        "id": "notes_field",
                        "component": "TextField",
                        "label": "Operator notes",
                        "value": {"@path": "/notes"},
                        "placeholder": notes_placeholder,
                        "variant": "shortText",
                    },
                    {
                        "id": "actions_row",
                        "component": "Row",
                        "justify": "start",
                        "children": ["approve_btn", "hold_btn"],
                    },
                    {
                        "id": "approve_btn",
                        "component": "Button",
                        "child": "approve_label",
                        "variant": "primary",
                        "action": {
                            "event": {
                                "name": "approve_ship",
                                "context": {
                                    "target": target,
                                    "notes": {"@path": "/notes"},
                                },
                            }
                        },
                    },
                    {"id": "approve_label", "component": "Text", "text": approve_label, "variant": "body"},
                    {
                        "id": "hold_btn",
                        "component": "Button",
                        "child": "hold_label",
                        "variant": "default",
                        "action": {
                            "event": {
                                "name": "hold_ship",
                                "context": {
                                    "target": target,
                                    "notes": {"@path": "/notes"},
                                },
                            }
                        },
                    },
                    {"id": "hold_label", "component": "Text", "text": hold_label, "variant": "body"},
                ],
                "dataModel": {"notes": str(v.get("notes", ""))},
            },
        }
    ]


def _choice_picker(v: dict[str, Any], surface_id: str) -> list[dict[str, Any]]:
    title = str(v.get("title", "Select Execution Path"))
    prompt = str(v.get("prompt", "Choose the preferred option below and confirm."))
    variant = str(v.get("variant", "mutuallyExclusive"))
    if variant not in {"mutuallyExclusive", "multipleSelection"}:
        variant = "mutuallyExclusive"
    display_style = str(v.get("display_style", "chips"))
    if display_style not in {"checkbox", "chips"}:
        display_style = "chips"
    raw_options = v.get(
        "options",
        [
            {"label": "Option A: Canary Rollout", "value": "canary"},
            {"label": "Option B: Full Rollout", "value": "full"},
            {"label": "Option C: Dry Run Only", "value": "dry_run"},
        ],
    )
    options = [
        {"label": str(o.get("label", o.get("value", "Option"))), "value": str(o.get("value", "opt"))}
        for o in raw_options
        if isinstance(o, dict)
    ]
    default_sel = v.get("selected", [options[0]["value"]] if options else [])
    if not isinstance(default_sel, list):
        default_sel = [str(default_sel)]
    return [
        {
            "version": "1.0",
            "createSurface": {
                "surfaceId": surface_id,
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Card", "child": "main_col"},
                    {
                        "id": "main_col",
                        "component": "Column",
                        "children": ["heading_text", "prompt_text", "option_picker", "confirm_row"],
                    },
                    {"id": "heading_text", "component": "Text", "text": f"## {title}", "variant": "body"},
                    {"id": "prompt_text", "component": "Text", "text": prompt, "variant": "caption"},
                    {
                        "id": "option_picker",
                        "component": "ChoicePicker",
                        "label": "Available options",
                        "variant": variant,
                        "displayStyle": display_style,
                        "options": options,
                        "value": {"@path": "/selected"},
                    },
                    {
                        "id": "confirm_row",
                        "component": "Row",
                        "justify": "start",
                        "children": ["confirm_btn", "cancel_btn"],
                    },
                    {
                        "id": "confirm_btn",
                        "component": "Button",
                        "child": "confirm_lbl",
                        "variant": "primary",
                        "action": {
                            "event": {
                                "name": "confirm_choice",
                                "context": {"selected": {"@path": "/selected"}},
                            }
                        },
                    },
                    {"id": "confirm_lbl", "component": "Text", "text": "Confirm selection", "variant": "body"},
                    {
                        "id": "cancel_btn",
                        "component": "Button",
                        "child": "cancel_lbl",
                        "variant": "default",
                        "action": {"event": {"name": "cancel_choice", "context": {}}},
                    },
                    {"id": "cancel_lbl", "component": "Text", "text": "Cancel", "variant": "body"},
                ],
                "dataModel": {"selected": default_sel},
            },
        }
    ]


def _intake_form(v: dict[str, Any], surface_id: str) -> list[dict[str, Any]]:
    title = str(v.get("title", "Operator Intake Form"))
    subtitle = str(v.get("subtitle", "Provide project details and target schedule."))
    return [
        {
            "version": "1.0",
            "createSurface": {
                "surfaceId": surface_id,
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Card", "child": "form_col"},
                    {
                        "id": "form_col",
                        "component": "Column",
                        "children": [
                            "form_title",
                            "form_subtitle",
                            "name_field",
                            "email_field",
                            "date_field",
                            "consent_check",
                            "submit_row",
                        ],
                    },
                    {"id": "form_title", "component": "Text", "text": f"## {title}", "variant": "body"},
                    {"id": "form_subtitle", "component": "Text", "text": subtitle, "variant": "caption"},
                    {
                        "id": "name_field",
                        "component": "TextField",
                        "label": "Project or Owner Name",
                        "value": {"@path": "/form/name"},
                        "placeholder": "Enter name",
                        "variant": "shortText",
                        "@checks": [
                            {
                                "condition": {
                                    "@call": "required",
                                    "args": {"value": {"@path": "/form/name"}},
                                },
                                "message": "Name is required.",
                            }
                        ],
                    },
                    {
                        "id": "email_field",
                        "component": "TextField",
                        "label": "Contact Email",
                        "value": {"@path": "/form/email"},
                        "placeholder": "operator@example.com",
                        "variant": "shortText",
                        "@checks": [
                            {
                                "condition": {
                                    "@call": "email",
                                    "args": {"value": {"@path": "/form/email"}},
                                },
                                "message": "Provide a valid email address.",
                            }
                        ],
                    },
                    {
                        "id": "date_field",
                        "component": "DateTimeInput",
                        "label": "Target Date",
                        "value": {"@path": "/form/targetDate"},
                        "enableDate": True,
                        "enableTime": False,
                    },
                    {
                        "id": "consent_check",
                        "component": "CheckBox",
                        "label": "Confirm inputs are verified for execution",
                        "value": {"@path": "/form/confirmed"},
                    },
                    {
                        "id": "submit_row",
                        "component": "Row",
                        "justify": "start",
                        "children": ["submit_btn"],
                    },
                    {
                        "id": "submit_btn",
                        "component": "Button",
                        "child": "submit_lbl",
                        "variant": "primary",
                        "action": {
                            "event": {
                                "name": "submit_intake",
                                "context": {
                                    "name": {"@path": "/form/name"},
                                    "email": {"@path": "/form/email"},
                                    "targetDate": {"@path": "/form/targetDate"},
                                    "confirmed": {"@path": "/form/confirmed"},
                                },
                            }
                        },
                    },
                    {"id": "submit_lbl", "component": "Text", "text": "Submit intake", "variant": "body"},
                ],
                "dataModel": {
                    "form": {
                        "name": str(v.get("name", "")),
                        "email": str(v.get("email", "")),
                        "targetDate": str(v.get("target_date", "2026-12-01")),
                        "confirmed": bool(v.get("confirmed", False)),
                    }
                },
            },
        }
    ]


def _tabbed_briefing(v: dict[str, Any], surface_id: str) -> list[dict[str, Any]]:
    title = str(v.get("title", "Operator Briefing"))
    raw_tabs = v.get(
        "tabs",
        [
            {"title": "Summary", "body": "All primary checks passed with zero blocking regressions."},
            {"title": "Risks", "body": "- Monitor latency after rollout.\n- Verify cache hit rate."},
            {"title": "Next Steps", "body": "1. Run smoke suite.\n2. Confirm release tag."},
        ],
    )
    components: list[dict[str, Any]] = [
        {"id": "root", "component": "Card", "child": "brief_col"},
        {
            "id": "brief_col",
            "component": "Column",
            "children": ["brief_heading", "brief_tabs", "brief_actions"],
        },
        {"id": "brief_heading", "component": "Text", "text": f"## {title}", "variant": "body"},
    ]
    tab_defs: list[dict[str, Any]] = []
    for idx, tab in enumerate(raw_tabs[:6]):
        if not isinstance(tab, dict):
            continue
        t_id = f"tab_body_{idx + 1}"
        tab_defs.append({"title": str(tab.get("title", f"Tab {idx + 1}")), "child": t_id})
        components.append(
            {
                "id": t_id,
                "component": "Text",
                "text": str(tab.get("body", "")),
                "variant": "body",
            }
        )
    if not tab_defs:
        tab_defs.append({"title": "Overview", "child": "tab_body_1"})
        components.append({"id": "tab_body_1", "component": "Text", "text": "No details provided.", "variant": "body"})
    components.append({"id": "brief_tabs", "component": "Tabs", "tabs": tab_defs})
    components.append(
        {
            "id": "brief_actions",
            "component": "Row",
            "justify": "start",
            "children": ["ack_btn"],
        }
    )
    components.append(
        {
            "id": "ack_btn",
            "component": "Button",
            "child": "ack_lbl",
            "variant": "primary",
            "action": {"event": {"name": "acknowledge_briefing", "context": {"title": title}}},
        }
    )
    components.append({"id": "ack_lbl", "component": "Text", "text": "Acknowledge briefing", "variant": "body"})
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


def _status_dashboard(v: dict[str, Any], surface_id: str) -> list[dict[str, Any]]:
    title = str(v.get("title", "System Status Dashboard"))
    metrics = v.get(
        "metrics",
        [
            {"label": "Uptime", "value": "99.98%"},
            {"label": "Active Checks", "value": "28 / 28"},
            {"label": "Open Alerts", "value": "0"},
        ],
    )
    items = v.get(
        "items",
        [
            {"name": "Validator Engine", "status": "PASS"},
            {"name": "Vendor Spec Pin", "status": "VERIFIED"},
            {"name": "Preview Renderer", "status": "READY"},
        ],
    )
    components: list[dict[str, Any]] = [
        {"id": "root", "component": "Card", "child": "dash_col"},
        {
            "id": "dash_col",
            "component": "Column",
            "children": [
                "dash_title",
                "metrics_row",
                "dash_divider",
                "items_list",
                "dash_actions",
            ],
        },
        {"id": "dash_title", "component": "Text", "text": f"## {title}", "variant": "body"},
    ]
    metric_ids: list[str] = []
    for idx, m in enumerate(metrics[:4]):
        if not isinstance(m, dict):
            continue
        card_id = f"metric_card_{idx + 1}"
        col_id = f"metric_col_{idx + 1}"
        lbl_id = f"metric_lbl_{idx + 1}"
        val_id = f"metric_val_{idx + 1}"
        metric_ids.append(card_id)
        components.extend(
            [
                {"id": card_id, "component": "Card", "child": col_id, "weight": 1},
                {"id": col_id, "component": "Column", "children": [lbl_id, val_id]},
                {"id": lbl_id, "component": "Text", "text": str(m.get("label", "Metric")), "variant": "caption"},
                {"id": val_id, "component": "Text", "text": f"**{m.get('value', 'n/a')}**", "variant": "body"},
            ]
        )
    components.append({"id": "metrics_row", "component": "Row", "justify": "stretch", "children": metric_ids})
    components.append({"id": "dash_divider", "component": "Divider", "axis": "horizontal"})
    components.append(
        {
            "id": "items_list",
            "component": "List",
            "direction": "vertical",
            "children": {"componentId": "item_row_tpl", "path": "/items"},
        }
    )
    components.append(
        {
            "id": "item_row_tpl",
            "component": "Row",
            "justify": "spaceBetween",
            "children": ["item_name_txt", "item_status_txt"],
        }
    )
    components.append({"id": "item_name_txt", "component": "Text", "text": {"@path": "name"}, "variant": "body"})
    components.append({"id": "item_status_txt", "component": "Text", "text": {"@path": "status"}, "variant": "caption"})
    components.append(
        {
            "id": "dash_actions",
            "component": "Row",
            "justify": "start",
            "children": ["refresh_btn", "inspect_btn"],
        }
    )
    components.extend(
        [
            {
                "id": "refresh_btn",
                "component": "Button",
                "child": "refresh_lbl",
                "variant": "primary",
                "action": {"event": {"name": "refresh_status", "context": {"surface": surface_id}}},
            },
            {"id": "refresh_lbl", "component": "Text", "text": "Refresh", "variant": "body"},
            {
                "id": "inspect_btn",
                "component": "Button",
                "child": "inspect_lbl",
                "variant": "default",
                "action": {"event": {"name": "inspect_details", "context": {"surface": surface_id}}},
            },
            {"id": "inspect_lbl", "component": "Text", "text": "Inspect details", "variant": "body"},
        ]
    )
    return [
        {
            "version": "1.0",
            "createSurface": {
                "surfaceId": surface_id,
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": components,
                "dataModel": {"items": items},
            },
        }
    ]


def _confirm_action(v: dict[str, Any], surface_id: str) -> list[dict[str, Any]]:
    title = str(v.get("title", "Confirm Irreversible Action"))
    warning = str(
        v.get("warning", "This operation mutates state. Review the target before confirming.")
    )
    action_name = sanitize_uax31_id(str(v.get("action_name", "execute_action")))
    target = str(v.get("target", "target-resource"))
    return [
        {
            "version": "1.0",
            "createSurface": {
                "surfaceId": surface_id,
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Card", "child": "confirm_col"},
                    {
                        "id": "confirm_col",
                        "component": "Column",
                        "children": [
                            "confirm_title",
                            "confirm_warning",
                            "ack_checkbox",
                            "confirm_actions",
                        ],
                    },
                    {"id": "confirm_title", "component": "Text", "text": f"## {title}", "variant": "body"},
                    {"id": "confirm_warning", "component": "Text", "text": warning, "variant": "body"},
                    {
                        "id": "ack_checkbox",
                        "component": "CheckBox",
                        "label": f"I confirm execution against {target}",
                        "value": {"@path": "/acknowledged"},
                    },
                    {
                        "id": "confirm_actions",
                        "component": "Row",
                        "justify": "start",
                        "children": ["proceed_btn", "abort_btn"],
                    },
                    {
                        "id": "proceed_btn",
                        "component": "Button",
                        "child": "proceed_lbl",
                        "variant": "primary",
                        "action": {
                            "event": {
                                "name": action_name,
                                "context": {
                                    "target": target,
                                    "acknowledged": {"@path": "/acknowledged"},
                                },
                            }
                        },
                    },
                    {"id": "proceed_lbl", "component": "Text", "text": "Confirm and execute", "variant": "body"},
                    {
                        "id": "abort_btn",
                        "component": "Button",
                        "child": "abort_lbl",
                        "variant": "default",
                        "action": {"event": {"name": "abort_action", "context": {"target": target}}},
                    },
                    {"id": "abort_lbl", "component": "Text", "text": "Cancel", "variant": "body"},
                ],
                "dataModel": {"acknowledged": False},
            },
        }
    ]


def _media_review(v: dict[str, Any], surface_id: str) -> list[dict[str, Any]]:
    title = str(v.get("title", "Media Asset Review"))
    media_type = str(v.get("media_type", "image")).lower()
    url = str(v.get("url", "https://example.com/preview-asset.png"))
    description = str(v.get("description", "Candidate visual asset for review."))
    media_comp: dict[str, Any]
    if media_type == "video":
        media_comp = {"id": "media_item", "component": "Video", "url": url}
        if isinstance(v.get("poster_url"), str) and v["poster_url"]:
            media_comp["posterUrl"] = v["poster_url"]
    else:
        media_comp = {
            "id": "media_item",
            "component": "Image",
            "url": url,
            "description": description,
            "fit": "contain",
            "variant": "largeFeature",
        }
    return [
        {
            "version": "1.0",
            "createSurface": {
                "surfaceId": surface_id,
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Card", "child": "review_col"},
                    {
                        "id": "review_col",
                        "component": "Column",
                        "children": [
                            "review_title",
                            "media_item",
                            "review_caption",
                            "review_actions",
                        ],
                    },
                    {"id": "review_title", "component": "Text", "text": f"## {title}", "variant": "body"},
                    media_comp,
                    {"id": "review_caption", "component": "Text", "text": description, "variant": "caption"},
                    {
                        "id": "review_actions",
                        "component": "Row",
                        "justify": "start",
                        "children": ["approve_media_btn", "reject_media_btn"],
                    },
                    {
                        "id": "approve_media_btn",
                        "component": "Button",
                        "child": "approve_media_lbl",
                        "variant": "primary",
                        "action": {"event": {"name": "approve_media", "context": {"url": url}}},
                    },
                    {"id": "approve_media_lbl", "component": "Text", "text": "Approve asset", "variant": "body"},
                    {
                        "id": "reject_media_btn",
                        "component": "Button",
                        "child": "reject_media_lbl",
                        "variant": "default",
                        "action": {"event": {"name": "reject_media", "context": {"url": url}}},
                    },
                    {"id": "reject_media_lbl", "component": "Text", "text": "Request revision", "variant": "body"},
                ],
                "dataModel": {},
            },
        }
    ]


def _parse_finite_int(raw: Any, default: int, name: str) -> int:
    if raw is None:
        return default
    if isinstance(raw, bool):
        raise ValueError(f"Variable '{name}' must be an integer (got boolean).")
    try:
        if isinstance(raw, float) and not math.isfinite(raw):
            raise ValueError(f"Variable '{name}' must be a finite integer.")
        val = int(raw)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Variable '{name}' must be a valid integer (got {raw!r}).") from exc
    return val


def _parse_finite_float(raw: Any, default: float, name: str) -> float:
    if raw is None:
        return default
    if isinstance(raw, bool):
        raise ValueError(f"Variable '{name}' must be a finite number (got boolean).")
    try:
        val = float(raw)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Variable '{name}' must be a valid number (got {raw!r}).") from exc
    if not math.isfinite(val):
        raise ValueError(f"Variable '{name}' must be a finite number (got {raw!r}).")
    return val


def _wizard_step(v: dict[str, Any], surface_id: str) -> list[dict[str, Any]]:
    step_num = _parse_finite_int(v.get("step"), 1, "step")
    total_steps = _parse_finite_int(v.get("total_steps"), 3, "total_steps")
    title = str(v.get("title", "Configure Deployment Parameters"))
    slider_label = str(v.get("slider_label", "Rollout percentage"))
    slider_min = _parse_finite_float(v.get("min"), 0.0, "min")
    slider_max = _parse_finite_float(v.get("max"), 100.0, "max")
    slider_val = _parse_finite_float(v.get("value"), 25.0, "value")
    return [
        {
            "version": "1.0",
            "createSurface": {
                "surfaceId": surface_id,
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Card", "child": "wiz_col"},
                    {
                        "id": "wiz_col",
                        "component": "Column",
                        "children": [
                            "wiz_step_caption",
                            "wiz_title",
                            "wiz_slider",
                            "wiz_picker",
                            "wiz_nav_row",
                        ],
                    },
                    {
                        "id": "wiz_step_caption",
                        "component": "Text",
                        "text": f"Step {step_num} of {total_steps}",
                        "variant": "caption",
                    },
                    {"id": "wiz_title", "component": "Text", "text": f"## {title}", "variant": "body"},
                    {
                        "id": "wiz_slider",
                        "component": "Slider",
                        "label": slider_label,
                        "min": slider_min,
                        "max": slider_max,
                        "steps": 10,
                        "value": {"@path": "/wizard/rolloutPct"},
                    },
                    {
                        "id": "wiz_picker",
                        "component": "ChoicePicker",
                        "label": "Region profile",
                        "variant": "mutuallyExclusive",
                        "displayStyle": "chips",
                        "options": [
                            {"label": "Primary Region", "value": "primary"},
                            {"label": "Multi-Region", "value": "multi"},
                        ],
                        "value": {"@path": "/wizard/region"},
                    },
                    {
                        "id": "wiz_nav_row",
                        "component": "Row",
                        "justify": "spaceBetween",
                        "children": ["back_btn", "next_btn"],
                    },
                    {
                        "id": "back_btn",
                        "component": "Button",
                        "child": "back_lbl",
                        "variant": "default",
                        "action": {
                            "event": {
                                "name": "wizard_back",
                                "context": {"step": step_num},
                            }
                        },
                    },
                    {"id": "back_lbl", "component": "Text", "text": "Back", "variant": "body"},
                    {
                        "id": "next_btn",
                        "component": "Button",
                        "child": "next_lbl",
                        "variant": "primary",
                        "action": {
                            "event": {
                                "name": "wizard_next",
                                "context": {
                                    "step": step_num,
                                    "rolloutPct": {"@path": "/wizard/rolloutPct"},
                                    "region": {"@path": "/wizard/region"},
                                },
                            }
                        },
                    },
                    {"id": "next_lbl", "component": "Text", "text": "Next step", "variant": "body"},
                ],
                "dataModel": {
                    "wizard": {
                        "rolloutPct": slider_val,
                        "region": [str(v.get("region", "primary"))],
                    }
                },
            },
        }
    ]


TEMPLATES: dict[str, dict[str, Any]] = {
    "ship-call": {
        "name": "ship-call",
        "description": "Owner deployment or release approval card with optional notes and approve/hold actions.",
        "builder": _ship_call,
    },
    "choice-picker": {
        "name": "choice-picker",
        "description": "2-4 option ChoicePicker (mutuallyExclusive or multipleSelection) with confirm/cancel.",
        "builder": _choice_picker,
    },
    "intake-form": {
        "name": "intake-form",
        "description": "Multi-field intake form with @checks (required, email), DateTimeInput, CheckBox, and submit.",
        "builder": _intake_form,
    },
    "tabbed-briefing": {
        "name": "tabbed-briefing",
        "description": "Compact multi-section Tabs briefing with acknowledgement action.",
        "builder": _tabbed_briefing,
    },
    "status-dashboard": {
        "name": "status-dashboard",
        "description": "Metric cards row plus dynamic List template and refresh/inspect actions.",
        "builder": _status_dashboard,
    },
    "confirm-action": {
        "name": "confirm-action",
        "description": "Irreversible action gate with explicit acknowledgement CheckBox and execute/cancel buttons.",
        "builder": _confirm_action,
    },
    "media-review": {
        "name": "media-review",
        "description": "Image or Video asset preview card with URL safety validation and approve/revision actions.",
        "builder": _media_review,
    },
    "wizard-step": {
        "name": "wizard-step",
        "description": "Step-numbered multi-control wizard step using Slider, ChoicePicker, and back/next navigation.",
        "builder": _wizard_step,
    },
}


def list_templates() -> list[dict[str, str]]:
    return [
        {"name": meta["name"], "description": meta["description"]}
        for meta in TEMPLATES.values()
    ]


def compose_surface(
    template_name: str,
    *,
    variables: dict[str, Any] | None = None,
    surface_id: str | None = None,
    fmt: str = "markdown-fence",
) -> dict[str, Any]:
    """Compose a curated A2UI v1.0 surface and verify it passes strict validation."""
    if template_name not in TEMPLATES:
        return {
            "ok": False,
            "template": template_name,
            "error": f"Unknown template '{template_name}'. Available: {sorted(TEMPLATES.keys())}",
            "payload": None,
            "formatted": "",
            "validation": {"ok": False, "errors": [], "warnings": []},
        }

    vars_dict = variables or {}
    if not isinstance(vars_dict, dict):
        return {
            "ok": False,
            "template": template_name,
            "error": "Template variables must be a JSON object.",
            "payload": None,
            "formatted": "",
            "validation": {"ok": False, "errors": [], "warnings": []},
        }

    secret_findings = scan_for_secrets(vars_dict)
    if secret_findings:
        return {
            "ok": False,
            "template": template_name,
            "error": "Refused secret token inside template variables.",
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

    sid = surface_id or sanitize_uax31_id(f"surface_{template_name}")
    try:
        messages = TEMPLATES[template_name]["builder"](vars_dict, sid)
        serialized = json.dumps(messages, allow_nan=False)
    except (ValueError, TypeError) as exc:
        return {
            "ok": False,
            "template": template_name,
            "error": str(exc),
            "payload": None,
            "formatted": "",
            "validation": {
                "ok": False,
                "errors": [
                    {
                        "code": "INVALID_TEMPLATE_VARIABLE",
                        "blockIndex": 0,
                        "path": "$",
                        "message": str(exc),
                    }
                ],
                "warnings": [],
            },
        }
    validation = validate_payload(serialized, version="1.0", strict=True)
    formatted = format_a2ui_messages(messages, fmt) if validation["ok"] else ""
    return {
        "ok": bool(validation["ok"]),
        "template": template_name,
        "surfaceId": sid,
        "payload": messages if validation["ok"] else None,
        "formatted": formatted,
        "validation": validation,
    }
