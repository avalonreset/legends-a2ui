"""Tests for A2UI multi-format parser, strict/relaxed validator, and v0.8/v0.9->v1.0 normalizer."""
from __future__ import annotations

import json
import unittest

from legends_a2ui.normalizer import normalize_payload
from legends_a2ui.spec_registry import BROKEN_V09_CATALOG_ID, CANONICAL_V1_CATALOG_ID
from legends_a2ui.validator import validate_payload


def _valid_v1_surface() -> dict:
    return {
        "version": "1.0",
        "createSurface": {
            "surfaceId": "demo_surface",
            "catalogId": CANONICAL_V1_CATALOG_ID,
            "components": [
                {"id": "root", "component": "Card", "child": "body_col"},
                {"id": "body_col", "component": "Column", "children": ["title_txt", "go_btn"]},
                {"id": "title_txt", "component": "Text", "text": "## Ready", "variant": "body"},
                {
                    "id": "go_btn",
                    "component": "Button",
                    "child": "go_lbl",
                    "variant": "primary",
                    "action": {"event": {"name": "confirm", "context": {"ok": True}}},
                },
                {"id": "go_lbl", "component": "Text", "text": "Proceed", "variant": "body"},
            ],
            "dataModel": {"ok": True},
        },
    }


class TestValidateAndNormalize(unittest.TestCase):
    def test_validate_all_input_envelopes(self) -> None:
        msg = _valid_v1_surface()
        # 1. Single JSON object
        self.assertTrue(validate_payload(json.dumps(msg), strict=True)["ok"])
        # 2. JSON array
        self.assertTrue(validate_payload(json.dumps([msg]), strict=True)["ok"])
        # 3. {"messages": [...]} wrapper
        self.assertTrue(validate_payload(json.dumps({"messages": [msg]}), strict=True)["ok"])
        # 4. JSONL
        jsonl = json.dumps(msg) + "\n" + json.dumps({"version": "1.0", "updateDataModel": {"surfaceId": "demo_surface", "path": "/ok", "value": False}})
        self.assertTrue(validate_payload(jsonl, strict=True)["ok"])
        # 5. Markdown fenced blocks
        md = "# Reply\n\n```a2ui\n" + json.dumps([msg], indent=2) + "\n```\n\n```a2ui-jsonl\n" + json.dumps(msg) + "\n```\n"
        md_res = validate_payload(md, extract_markdown=True, strict=True)
        self.assertTrue(md_res["ok"], md_res["errors"])
        self.assertEqual(md_res["blockCount"], 2)

    def test_validate_uax31_missing_root_dangling_orphan_and_cycle(self) -> None:
        # Non-UAX #31 IDs (hyphen & leading digit)
        bad_id = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "s1",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Card", "child": "bad-child"},
                    {"id": "bad-child", "component": "Text", "text": "hi"},
                    {"id": "1leading", "component": "Text", "text": "orphan"},
                ],
            },
        }
        res = validate_payload(json.dumps(bad_id))
        codes = {e["code"] for e in res["errors"]}
        self.assertIn("INVALID_UAX31_ID", codes)
        wcodes = {w["code"] for w in res["warnings"]}
        self.assertIn("ORPHAN_COMPONENT", wcodes)

        # Missing root & dangling ref
        dangling = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "s2",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "not_root", "component": "Card", "child": "missing_node"},
                ],
            },
        }
        res2 = validate_payload(json.dumps(dangling))
        codes2 = {e["code"] for e in res2["errors"]}
        self.assertIn("MISSING_ROOT_COMPONENT", codes2)
        self.assertIn("DANGLING_COMPONENT_REF", codes2)

        # Cyclic component graph (CWE-400)
        cyclic = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "s3",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Card", "child": "node_a"},
                    {"id": "node_a", "component": "Card", "child": "node_b"},
                    {"id": "node_b", "component": "Card", "child": "node_a"},
                ],
            },
        }
        res3 = validate_payload(json.dumps(cyclic))
        self.assertFalse(res3["ok"])
        self.assertIn("COMPONENT_CYCLE", {e["code"] for e in res3["errors"]})

    def test_validate_v1_strict_vs_relaxed_and_catalog_warning(self) -> None:
        # TextField missing value & Text.variant h1 rejected in v1.0
        bad_v1 = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "s4",
                "catalogId": BROKEN_V09_CATALOG_ID,
                "theme": {"primaryColor": "#9e0b1a"},
                "components": [
                    {"id": "root", "component": "Column", "children": ["h", "f"]},
                    {"id": "h", "component": "Text", "text": "Title", "variant": "h1"},
                    {"id": "f", "component": "TextField", "label": "Name"},
                ],
            },
        }
        relaxed = validate_payload(json.dumps(bad_v1), strict=False)
        self.assertFalse(relaxed["ok"])
        ecodes = {e["code"] for e in relaxed["errors"]}
        wcodes = {w["code"] for w in relaxed["warnings"]}
        self.assertIn("INVALID_ENUM_VALUE", ecodes)
        self.assertIn("MISSING_REQUIRED_PROPERTY", ecodes)
        self.assertIn("BROKEN_CATALOG_URI", wcodes)
        self.assertIn("DEPRECATED_THEME_PROPERTY", wcodes)

        # Transitional {"path": ...} accepted with warning in relaxed, rejected in strict
        transitional = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "s5",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Text", "text": {"path": "/msg"}, "variant": "body"},
                ],
            },
        }
        rel_t = validate_payload(json.dumps(transitional), strict=False)
        self.assertTrue(rel_t["ok"])
        self.assertIn("TRANSITIONAL_PATH_BINDING", {w["code"] for w in rel_t["warnings"]})
        str_t = validate_payload(json.dumps(transitional), strict=True)
        self.assertFalse(str_t["ok"])
        self.assertIn("TRANSITIONAL_PATH_BINDING", {e["code"] for e in str_t["errors"]})

    def test_validate_media_openurl_and_secret_refusal(self) -> None:
        smuggle = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "sec1",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": ["img1", "img2", "img3", "img4", "btn1"]},
                    {"id": "img1", "component": "Image", "url": "ht\ttps://evil.com/a.png"},
                    {"id": "img2", "component": "Image", "url": "//evil.com/a.png"},
                    {"id": "img3", "component": "Image", "url": "javascript:alert(1)"},
                    {"id": "img4", "component": "Image", "url": "file:///etc/passwd"},
                    {
                        "id": "btn1",
                        "component": "Button",
                        "child": "lbl1",
                        "action": {
                            "functionCall": {
                                "@call": "openUrl",
                                "args": {"url": "javascript:alert(1)"},
                            }
                        },
                    },
                    {"id": "lbl1", "component": "Text", "text": "Click"},
                ],
            },
        }
        res = validate_payload(json.dumps(smuggle))
        self.assertFalse(res["ok"])
        media_errs = [e for e in res["errors"] if e["code"] == "UNSAFE_MEDIA_URL"]
        open_errs = [e for e in res["errors"] if e["code"] == "UNSAFE_OPEN_URL"]
        self.assertEqual(len(media_errs), 4)
        self.assertEqual(len(open_errs), 1)

        # Secret token refusal (dynamically constructed to avoid literal secrets in tests)
        fake_stripe = "sk_" + "live_" + "1234567890abcdef"
        fake_gh = "gh" + "p_" + ("A" * 24)
        fake_pem = "-----BEGIN " + "RSA PRIVATE KEY-----"
        for tok in (fake_stripe, fake_gh, fake_pem):
            payload = _valid_v1_surface()
            payload["createSurface"]["dataModel"]["secret"] = tok
            sres = validate_payload(json.dumps(payload))
            self.assertFalse(sres["ok"])
            self.assertIn("SECRET_LEAK", {e["code"] for e in sres["errors"]})
            # Ensure secret value is never echoed in error message
            for err in sres["errors"]:
                self.assertNotIn(tok, err["message"])

    def test_normalize_v08_full_upgrade(self) -> None:
        v08_payload = [
            {"beginRendering": {"surfaceId": "legacy", "root": "main-card", "styles": {"primaryColor": "#000"}}},
            {
                "surfaceUpdate": {
                    "surfaceId": "legacy",
                    "components": [
                        {"id": "main-card", "component": {"Card": {"child": "main-col"}}},
                        {
                            "id": "main-col",
                            "component": {
                                "Column": {
                                    "distribution": "start",
                                    "alignment": "stretch",
                                    "children": {"explicitList": ["hdr-1", "choice-1", "go-btn"]},
                                }
                            },
                        },
                        {
                            "id": "hdr-1",
                            "component": {
                                "Text": {
                                    "text": {"literalString": "Legacy Heading"},
                                    "usageHint": "h2",
                                }
                            },
                        },
                        {
                            "id": "choice-1",
                            "component": {
                                "MultipleChoice": {
                                    "selections": {"path": "/selected"},
                                    "maxAllowedSelections": 1,
                                    "options": [
                                        {"label": {"literalString": "Alpha"}, "value": "alpha"},
                                        {"label": {"literalString": "Beta"}, "value": "beta"},
                                    ],
                                }
                            },
                        },
                        {
                            "id": "go-btn",
                            "component": {
                                "Button": {
                                    "child": "go-lbl",
                                    "primary": True,
                                    "action": {
                                        "name": "submit_legacy",
                                        "context": [
                                            {"key": "selected", "value": {"path": "/selected"}},
                                            {"key": "tag", "value": {"literalString": "v08"}},
                                        ],
                                    },
                                }
                            },
                        },
                        {"id": "go-lbl", "component": {"Text": {"text": {"literalString": "Run"}}}},
                    ],
                }
            },
            {
                "dataModelUpdate": {
                    "surfaceId": "legacy",
                    "contents": [
                        {"key": "selected", "valueArray": [{"valueString": "alpha"}]},
                    ],
                }
            },
        ]
        norm = normalize_payload(json.dumps(v08_payload), fmt="json")
        self.assertTrue(norm["ok"], norm["validation"]["errors"])
        self.assertTrue(validate_payload(norm["formatted"], version="1.0", strict=True)["ok"])
        # Verify v0.8 root was mapped to "root" and MultipleChoice -> ChoicePicker
        uc_comps = norm["payload"][1]["updateComponents"]["components"]
        by_id = {c["id"]: c for c in uc_comps}
        self.assertIn("root", by_id)
        self.assertEqual(by_id["choice_1"]["component"], "ChoicePicker")
        self.assertEqual(by_id["hdr_1"]["text"], "## Legacy Heading")
        self.assertEqual(by_id["hdr_1"]["variant"], "body")
        self.assertEqual(by_id["go_btn"]["variant"], "primary")
        self.assertEqual(norm["payload"][2]["updateDataModel"]["value"], {"selected": ["alpha"]})

    def test_normalize_v09_and_broken_v1_preserves_childlist_path(self) -> None:
        broken = [
            {
                "version": "v1.0",
                "updateComponents": {
                    "surfaceId": "list_surface",
                    "components": [
                        {"id": "root", "component": "Column", "children": ["1-title", "item-list", "email-input"]},
                        {
                            "id": "1-title",
                            "component": "Text",
                            "text": "Items",
                            "variant": "h1",
                            "accessibility": {"label": "Heading"},
                        },
                        {
                            "id": "item-list",
                            "component": "List",
                            "children": {"componentId": "row-tpl", "path": "/items"},
                        },
                        {"id": "row-tpl", "component": "Text", "text": {"path": "name"}},
                        {
                            "id": "email-input",
                            "component": "TextField",
                            "label": "Email",
                            "checks": [
                                {"condition": {"call": "required", "args": {"value": {"path": "/email_input"}}}, "message": "Required"}
                            ],
                        },
                    ],
                },
            }
        ]
        norm = normalize_payload(json.dumps(broken), fmt="json")
        self.assertTrue(norm["ok"], norm["validation"]["errors"])
        # Must synthesize createSurface first
        self.assertIn("createSurface", norm["payload"][0])
        comps = {c["id"]: c for c in norm["payload"][1]["updateComponents"]["components"]}
        # ChildList.path MUST remain unprefixed "path"
        self.assertEqual(comps["item_list"]["children"], {"componentId": "row_tpl", "path": "/items"})
        # DynamicValue path inside row_tpl MUST become "@path"
        self.assertEqual(comps["row_tpl"]["text"], {"@path": "name"})
        # Bare mixins upgraded
        self.assertIn("@accessibility", comps["c_1_title"])
        self.assertIn("@checks", comps["email_input"])
        self.assertIn("value", comps["email_input"])
        self.assertTrue(validate_payload(norm["formatted"], version="1.0", strict=True)["ok"])


if __name__ == "__main__":
    unittest.main()
