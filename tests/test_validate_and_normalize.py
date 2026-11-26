"""Tests for A2UI multi-format parser, strict/relaxed validator, and v0.8/v0.9->v1.0 normalizer."""
from __future__ import annotations

import json
import time
import unittest

from legends_a2ui.normalizer import normalize_payload
from legends_a2ui.spec_registry import (
    BROKEN_V09_CATALOG_ID,
    CANONICAL_V08_CATALOG_ID,
    CANONICAL_V09_CATALOG_ID,
    CANONICAL_V1_CATALOG_ID,
)
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

    def test_incremental_update_components_replacement_and_same_batch_duplicate(self) -> None:
        """Incremental replacements pass across batches; same-batch duplicates still fail."""
        incremental = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "inc_dash",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "inc_dash",
                    "components": [
                        {"id": "root", "component": "Column", "children": ["left_panel"]},
                        {"id": "left_panel", "component": "Column", "children": ["loading_txt"], "weight": 1},
                        {"id": "loading_txt", "component": "Text", "text": "Loading...", "variant": "caption"},
                    ],
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "inc_dash",
                    "components": [
                        {"id": "left_panel", "component": "Column", "children": ["ready_card"], "weight": 1},
                        {"id": "ready_card", "component": "Card", "child": "ready_txt"},
                        {"id": "ready_txt", "component": "Text", "text": "Ready.", "variant": "body"},
                    ],
                },
            },
        ]
        vres = validate_payload(json.dumps(incremental), version="1.0", strict=True)
        self.assertTrue(vres["ok"], f"Errors: {vres['errors']}, Warnings: {vres['warnings']}")
        self.assertEqual(vres["errors"], [])
        self.assertEqual(vres["warnings"], [])

        nres = normalize_payload(json.dumps(incremental), fmt="json")
        self.assertTrue(nres["ok"], f"Normalize failed: {nres['validation']}")
        self.assertEqual(nres["validation"]["warnings"], [])
        # Replaced ID must NOT get suffixed with _2 across batches
        b1_ids = [c["id"] for c in nres["payload"][1]["updateComponents"]["components"]]
        b2_ids = [c["id"] for c in nres["payload"][2]["updateComponents"]["components"]]
        self.assertIn("left_panel", b1_ids)
        self.assertIn("left_panel", b2_ids)
        self.assertNotIn("left_panel_2", b2_ids)

        # Non-UAX31 ID replaced across two batches must remap to the exact same sanitized ID
        hyphen_inc = [
            {
                "version": "1.0",
                "createSurface": {"surfaceId": "inc_h", "catalogId": CANONICAL_V1_CATALOG_ID},
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "inc_h",
                    "components": [
                        {"id": "root", "component": "Column", "children": ["left-panel"]},
                        {"id": "left-panel", "component": "Text", "text": "Step 1"},
                    ],
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "inc_h",
                    "components": [
                        {"id": "left-panel", "component": "Text", "text": "Step 2"},
                    ],
                },
            },
        ]
        hnorm = normalize_payload(json.dumps(hyphen_inc), fmt="json")
        self.assertTrue(hnorm["ok"], hnorm["validation"])
        self.assertEqual(hnorm["payload"][1]["updateComponents"]["components"][1]["id"], "left_panel")
        self.assertEqual(hnorm["payload"][2]["updateComponents"]["components"][0]["id"], "left_panel")

        # Duplicate ID within the SAME batch MUST still be rejected
        same_batch_dup = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "dup_surface",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": ["dup_node"]},
                    {"id": "dup_node", "component": "Text", "text": "First"},
                    {"id": "dup_node", "component": "Text", "text": "Second"},
                ],
            },
        }
        dup_res = validate_payload(json.dumps(same_batch_dup), version="1.0", strict=True)
        self.assertFalse(dup_res["ok"])
        self.assertIn("DUPLICATE_COMPONENT_ID", {e["code"] for e in dup_res["errors"]})

        # Truly never-referenced orphan in an incremental update MUST still be flagged
        inc_orphan = json.loads(json.dumps(incremental))
        inc_orphan[2]["updateComponents"]["components"].append(
            {"id": "stray_orphan", "component": "Text", "text": "Never attached"}
        )
        orph_res = validate_payload(json.dumps(inc_orphan), version="1.0", strict=False)
        self.assertIn("ORPHAN_COMPONENT", {w["code"] for w in orph_res["warnings"]})
        self.assertTrue(any("stray_orphan" in w["message"] for w in orph_res["warnings"]))

    def test_custom_catalog_id_cannot_bypass_security_gates(self) -> None:
        """Custom @catalogId overrides never bypass media URL, action, or @checks ReDoS gates."""
        payload = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "custom_sec",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": ["img_c", "btn_c", "fld_c"]},
                    {
                        "id": "img_c",
                        "component": "Image",
                        "@catalogId": "custom:cat",
                        "url": "javascript:alert(1)",
                    },
                    {
                        "id": "btn_c",
                        "component": "Button",
                        "@catalogId": "https://evil.example/catalogs/basic",
                        "child": "btn_lbl",
                        "action": {
                            "functionCall": {
                                "@call": "openUrl",
                                "args": {"url": "javascript:alert(1)"},
                            }
                        },
                    },
                    {"id": "btn_lbl", "component": "Text", "text": "Open"},
                    {
                        "id": "fld_c",
                        "component": "TextField",
                        "@catalogId": "custom:cat",
                        "label": "Input",
                        "value": {"@path": "/in"},
                        "@checks": [
                            {
                                "condition": {
                                    "@call": "regex",
                                    "args": {"value": {"@path": "/in"}, "pattern": "(a+)+$"},
                                },
                                "message": "Bad",
                            }
                        ],
                    },
                ],
            },
        }
        res = validate_payload(json.dumps(payload), version="1.0", strict=True)
        self.assertFalse(res["ok"])
        codes = {e["code"] for e in res["errors"]}
        self.assertIn("UNSAFE_MEDIA_URL", codes)
        self.assertIn("UNSAFE_OPEN_URL", codes)
        self.assertIn("UNSAFE_REGEX", codes)

    def test_function_call_urls_template_relative_paths_and_array_dynamic_values(self) -> None:
        """FunctionCall URLs, ChildList relative bindings, nested arrays, and openUrl call-sites fail closed."""
        # 1. formatString with unsafe scheme in Image.url and openUrl
        fn_url = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "fn_url",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": ["img1", "img2", "btn1", "btn2", "txt_bad"]},
                    {
                        "id": "img1",
                        "component": "Image",
                        "url": {"@call": "formatString", "args": {"value": "javascript:alert(1)"}},
                    },
                    {
                        "id": "img2",
                        "component": "Image",
                        "url": {"@call": "formatNumber", "args": {"value": 42}},
                    },
                    {
                        "id": "btn1",
                        "component": "Button",
                        "child": "lbl1",
                        "action": {
                            "functionCall": {
                                "@call": "openUrl",
                                "args": {"url": {"@call": "formatString", "args": {"value": "javascript:alert(1)"}}},
                            }
                        },
                    },
                    {"id": "lbl1", "component": "Text", "text": "Go"},
                    {
                        "id": "btn2",
                        "component": "Button",
                        "child": "lbl2",
                        "action": {"functionCall": {"@call": "openUrl"}},
                    },
                    {"id": "lbl2", "component": "Text", "text": "NoArgs"},
                    {
                        "id": "txt_bad",
                        "component": "Text",
                        "text": {"@call": "openUrl", "args": {"url": "https://a2ui.org"}},
                    },
                ],
            },
        }
        res1 = validate_payload(json.dumps(fn_url), version="1.0", strict=True)
        self.assertFalse(res1["ok"])
        codes1 = {e["code"] for e in res1["errors"]}
        self.assertIn("UNSAFE_MEDIA_URL", codes1)
        self.assertIn("UNSAFE_OPEN_URL", codes1)
        self.assertIn("MISSING_REQUIRED_FUNCTION_ARG", codes1)
        self.assertIn("INVALID_FUNCTION_CALL_SITE", codes1)

        # 2. ChildList dynamic template relative @path resolved against inline dataModel array items
        tpl_payload = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "tpl_sec",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "List", "children": {"componentId": "row_tpl", "path": "/items"}},
                    {"id": "row_tpl", "component": "Row", "children": ["tpl_img", "tpl_btn"]},
                    {"id": "tpl_img", "component": "Image", "url": {"@path": "url"}},
                    {
                        "id": "tpl_btn",
                        "component": "Button",
                        "child": "tpl_lbl",
                        "action": {"functionCall": {"@call": "openUrl", "args": {"url": {"@path": "href"}}}},
                    },
                    {"id": "tpl_lbl", "component": "Text", "text": "Visit"},
                ],
                "dataModel": {
                    "items": [
                        {"url": "https://example.com/ok.png", "href": "https://a2ui.org"},
                        {"url": "javascript:alert(1)", "href": "javascript:alert(2)"},
                    ]
                },
            },
        }
        res2 = validate_payload(json.dumps(tpl_payload), version="1.0", strict=True)
        self.assertFalse(res2["ok"])
        codes2 = {e["code"] for e in res2["errors"]}
        self.assertIn("UNSAFE_MEDIA_URL", codes2)
        self.assertIn("UNSAFE_OPEN_URL", codes2)

        # 3. Array DynamicValue recursion (transitional path, bad single-@ key, unsafe regex inside and.values)
        arr_payload = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "arr_sec",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": ["f1", "b1"]},
                    {
                        "id": "f1",
                        "component": "TextField",
                        "label": "Field",
                        "value": {"@path": "/f"},
                        "@checks": [
                            {
                                "condition": {
                                    "@call": "and",
                                    "args": {
                                        "values": [
                                            {"path": "/f"},
                                            {"@call": "regex", "args": {"value": {"@path": "/f"}, "pattern": "(a+)+$"}},
                                        ]
                                    },
                                },
                                "message": "Invalid",
                            }
                        ],
                    },
                    {
                        "id": "b1",
                        "component": "Button",
                        "child": "b1_lbl",
                        "action": {
                            "event": {
                                "name": "send",
                                "context": {"items": [{"@bad": 1}]},
                            }
                        },
                    },
                    {"id": "b1_lbl", "component": "Text", "text": "Send"},
                ],
            },
        }
        res3 = validate_payload(json.dumps(arr_payload), version="1.0", strict=True)
        self.assertFalse(res3["ok"])
        codes3 = {e["code"] for e in res3["errors"]}
        self.assertIn("TRANSITIONAL_PATH_BINDING", codes3)
        self.assertIn("UNSAFE_REGEX", codes3)
        self.assertIn("INVALID_RESERVED_KEY", codes3)

    def test_surface_lifecycle_unknown_props_nan_json_and_normalizer_edge_cases(self) -> None:
        """Empty createSurface, post-delete mutations, unknown component props, NaN JSON, and normalizer details."""
        # 1. createSurface without components fails with MISSING_ROOT_COMPONENT
        empty_cs = {"version": "1.0", "createSurface": {"surfaceId": "empty_s", "catalogId": CANONICAL_V1_CATALOG_ID}}
        res_empty = validate_payload(json.dumps(empty_cs), version="1.0", strict=True)
        self.assertFalse(res_empty["ok"])
        self.assertIn("MISSING_ROOT_COMPONENT", {e["code"] for e in res_empty["errors"]})

        # 2. Invalid components/dataModel types on createSurface
        bad_types = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "bad_t",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": "not_a_list",
                "dataModel": [1, 2],
            },
        }
        res_bt = validate_payload(json.dumps(bad_types), version="1.0", strict=True)
        self.assertFalse(res_bt["ok"])
        bt_codes = {e["code"] for e in res_bt["errors"]}
        self.assertIn("INVALID_COMPONENTS", bt_codes)
        self.assertIn("INVALID_DATA_MODEL", bt_codes)

        # 3. Post-delete mutation fails; re-creation resets cleanly
        post_del = [
            _valid_v1_surface(),
            {"version": "1.0", "deleteSurface": {"surfaceId": "demo_surface"}},
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "demo_surface", "path": "/ok", "value": False},
            },
        ]
        res_pd = validate_payload(json.dumps(post_del), version="1.0", strict=True)
        self.assertFalse(res_pd["ok"])
        self.assertIn("INACTIVE_SURFACE", {e["code"] for e in res_pd["errors"]})

        recreate = [
            _valid_v1_surface(),
            {"version": "1.0", "deleteSurface": {"surfaceId": "demo_surface"}},
            _valid_v1_surface(),
        ]
        res_rc = validate_payload(json.dumps(recreate), version="1.0", strict=True)
        self.assertTrue(res_rc["ok"], res_rc["errors"])

        # 4. Unknown Basic Catalog component properties flagged
        unk_prop = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "unk_s",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Text", "text": "Hi", "onclick": "alert(1)"},
                ],
            },
        }
        res_unk_strict = validate_payload(json.dumps(unk_prop), version="1.0", strict=True)
        self.assertFalse(res_unk_strict["ok"])
        self.assertIn("UNKNOWN_COMPONENT_PROPERTY", {e["code"] for e in res_unk_strict["errors"]})
        res_unk_relaxed = validate_payload(json.dumps(unk_prop), version="1.0", strict=False)
        self.assertTrue(res_unk_relaxed["ok"])
        self.assertIn("UNKNOWN_COMPONENT_PROPERTY", {w["code"] for w in res_unk_relaxed["warnings"]})

        # 5. Non-standard NaN/Infinity JSON rejected
        nan_json = '{"version":"1.0","createSurface":{"surfaceId":"s","catalogId":"https://a2ui.org/specification/v1_0/catalogs/basic/catalog.json","components":[{"id":"root","component":"Text","text":"Hi"}],"dataModel":{"x":NaN}}}'
        res_nan = validate_payload(nan_json, version="1.0", strict=True)
        self.assertFalse(res_nan["ok"])

        # 6. Normalizer escapes single-@ keys, remaps action.sourceComponentId, and synthesizes TextField.value after collision suffixing
        edge_norm = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "edge_s",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "Column", "children": ["field_1", "field-1", "go-btn"]},
                        {"id": "field_1", "component": "TextField", "label": "First"},
                        {"id": "field-1", "component": "TextField", "label": "Second"},
                        {
                            "id": "go-btn",
                            "component": "Button",
                            "child": "go_lbl",
                            "action": {"event": {"name": "go", "context": {"meta": {"@type": "demo"}}}},
                        },
                        {"id": "go_lbl", "component": "Text", "text": "Go"},
                    ],
                },
            },
            {
                "version": "1.0",
                "action": {
                    "surfaceId": "edge_s",
                    "name": "go",
                    "sourceComponentId": "go-btn",
                    "timestamp": "2026-11-25T00:00:00Z",
                    "context": {},
                },
            },
        ]
        nres = normalize_payload(json.dumps(edge_norm), fmt="json")
        self.assertTrue(nres["ok"], nres["validation"])
        comps = {c["id"]: c for c in nres["payload"][0]["createSurface"]["components"]}
        self.assertIn("field_1_2", comps)
        self.assertEqual(comps["field_1_2"]["value"], {"@path": "/field_1_2"})
        self.assertIn("@@type", comps["go_btn"]["action"]["event"]["context"]["meta"])
        self.assertEqual(nres["payload"][1]["action"]["sourceComponentId"], "go_btn")

    def test_mixed_formatstring_array_data_model_rpc_envelopes_and_dynamic_slots(self) -> None:
        """Mixed formatString URLs, array updateDataModel, RPC envelopes, catalogId openUrl, and dynamic slots fail closed."""
        # 1. Mixed resolved + unresolved formatString URLs fail closed
        mixed_fmt = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "mixed_fmt",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": ["img_m", "btn_m"]},
                    {
                        "id": "img_m",
                        "component": "Image",
                        "url": {"@call": "formatString", "args": {"value": "/${/evil}${/missing}"}},
                    },
                    {
                        "id": "btn_m",
                        "component": "Button",
                        "child": "btn_lbl",
                        "action": {
                            "functionCall": {
                                "@call": "openUrl",
                                "args": {
                                    "url": {
                                        "@call": "formatString",
                                        "args": {"value": "https://${/creds}evil.example/${/missing}"},
                                    }
                                },
                            }
                        },
                    },
                    {"id": "btn_lbl", "component": "Text", "text": "Open"},
                ],
                "dataModel": {
                    "evil": "/attacker.example/x.png?",
                    "creds": "a2ui.org@",
                },
            },
        }
        res_m = validate_payload(json.dumps(mixed_fmt), version="1.0", strict=True)
        self.assertFalse(res_m["ok"])
        codes_m = {e["code"] for e in res_m["errors"]}
        self.assertIn("UNSAFE_MEDIA_URL", codes_m)
        self.assertIn("UNSAFE_OPEN_URL", codes_m)

        # 2. updateDataModel array-index mutations propagate to ChildList templates and absolute @path checks
        arr_mut = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "arr_mut",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "Column", "children": ["list_a", "abs_img"]},
                        {"id": "list_a", "component": "List", "children": {"componentId": "row_img", "path": "/items"}},
                        {"id": "row_img", "component": "Image", "url": {"@path": "url"}},
                        {"id": "abs_img", "component": "Image", "url": {"@path": "/items/0/url"}},
                    ],
                    "dataModel": {"items": [{"url": "https://example.com/safe.png"}]},
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "arr_mut",
                    "path": "/items/0/url",
                    "value": "javascript:alert(1)",
                },
            },
        ]
        res_arr = validate_payload(json.dumps(arr_mut), version="1.0", strict=True)
        self.assertFalse(res_arr["ok"])
        media_errs = [e for e in res_arr["errors"] if e["code"] == "UNSAFE_MEDIA_URL"]
        self.assertGreaterEqual(len(media_errs), 2)

        # 3. callRendererFunction and callAgentFunction envelopes validate required fields and reject openUrl/ReDoS
        rpc_bad = [
            {
                "version": "1.0",
                "callRendererFunction": {
                    "functionCallId": "call_1",
                    "callFunction": {
                        "@call": "openUrl",
                        "args": {"url": "javascript:alert(1)"},
                    },
                },
            },
            {
                "version": "1.0",
                "callAgentFunction": {
                    "functionCallId": "",
                    "callFunction": {
                        "@call": "regex",
                        "args": {"value": "abc", "pattern": "(a+)+$"},
                    },
                },
            },
        ]
        res_rpc = validate_payload(json.dumps(rpc_bad), version="1.0", strict=True)
        self.assertFalse(res_rpc["ok"])
        codes_rpc = {e["code"] for e in res_rpc["errors"]}
        self.assertIn("INVALID_FUNCTION_CALL_SITE", codes_rpc)
        self.assertIn("UNSAFE_OPEN_URL", codes_rpc)
        self.assertIn("MISSING_FUNCTION_CALL_ID", codes_rpc)
        self.assertIn("MISSING_CATALOG_ID", codes_rpc)
        self.assertIn("MISSING_SURFACE_ID", codes_rpc)
        self.assertIn("UNSAFE_REGEX", codes_rpc)

        # Valid callRendererFunction passes strict validation
        rpc_ok = {
            "version": "1.0",
            "callRendererFunction": {
                "functionCallId": "call_ok",
                "callFunction": {
                    "@call": "formatNumber",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "args": {"value": 42},
                },
            },
        }
        self.assertTrue(validate_payload(json.dumps(rpc_ok), version="1.0", strict=True)["ok"])

        # 4. Unconditional openUrl & regex safety regardless of FunctionCall.catalogId
        custom_fn_bypass = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "fn_cat_bypass",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": ["t_open", "b_missing", "f_redos"]},
                    {
                        "id": "t_open",
                        "component": "Text",
                        "text": {
                            "@call": "openUrl",
                            "catalogId": "custom:cat",
                            "args": {"url": "https://a2ui.org"},
                        },
                    },
                    {
                        "id": "b_missing",
                        "component": "Button",
                        "child": "b_lbl",
                        "action": {"functionCall": {"@call": "openUrl", "catalogId": "custom:cat"}},
                    },
                    {"id": "b_lbl", "component": "Text", "text": "Go"},
                    {
                        "id": "f_redos",
                        "component": "TextField",
                        "label": "Code",
                        "value": {"@path": "/code"},
                        "@checks": [
                            {
                                "condition": {
                                    "@call": "regex",
                                    "catalogId": "custom:cat",
                                    "args": {"value": {"@path": "/code"}, "pattern": "(a+)+$"},
                                },
                                "message": "Bad",
                            }
                        ],
                    },
                ],
            },
        }
        res_cf = validate_payload(json.dumps(custom_fn_bypass), version="1.0", strict=True)
        self.assertFalse(res_cf["ok"])
        codes_cf = {e["code"] for e in res_cf["errors"]}
        self.assertIn("INVALID_FUNCTION_CALL_SITE", codes_cf)
        self.assertIn("MISSING_REQUIRED_FUNCTION_ARG", codes_cf)
        self.assertIn("UNSAFE_REGEX", codes_cf)

        # 5. Unchecked DynamicValue slots: ChoicePicker.options[].label, Tabs.tabs[], Icon.name, @accessibility
        slots_bad = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "slots_bad",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": ["cp", "tabs", "ico", "acc_txt"]},
                    {
                        "id": "cp",
                        "component": "ChoicePicker",
                        "value": {"@path": "/choice"},
                        "options": [
                            {
                                "label": {"@call": "openUrl", "args": {"url": "javascript:alert(1)"}},
                                "value": "a",
                                "extra": True,
                            }
                        ],
                    },
                    {
                        "id": "tabs",
                        "component": "Tabs",
                        "tabs": [{"title": "One", "child": "tab_body", "extra": 1}],
                    },
                    {"id": "tab_body", "component": "Text", "text": "Tab 1"},
                    {
                        "id": "ico",
                        "component": "Icon",
                        "name": {
                            "svgPath": {"@call": "openUrl", "args": {"url": "https://a2ui.org"}},
                            "bogus": 1,
                        },
                    },
                    {
                        "id": "acc_txt",
                        "component": "Text",
                        "text": "Status",
                        "@accessibility": {
                            "label": {"path": "/lbl"},
                            "live": "invalid_mode",
                            "extraProp": 1,
                        },
                    },
                ],
            },
        }
        res_sl = validate_payload(json.dumps(slots_bad), version="1.0", strict=True)
        self.assertFalse(res_sl["ok"])
        codes_sl = {e["code"] for e in res_sl["errors"]}
        self.assertIn("UNKNOWN_CHOICE_OPTION_PROPERTY", codes_sl)
        self.assertIn("UNKNOWN_TAB_ITEM_PROPERTY", codes_sl)
        self.assertIn("INVALID_ICON_NAME", codes_sl)
        self.assertIn("INVALID_ACCESSIBILITY", codes_sl)
        self.assertIn("UNSAFE_OPEN_URL", codes_sl)
        self.assertIn("INVALID_FUNCTION_CALL_SITE", codes_sl)
        self.assertIn("TRANSITIONAL_PATH_BINDING", codes_sl)

    def test_custom_surface_catalog_and_legacy_normalization_edge_cases(self) -> None:
        """Custom surface catalogId inherits cleanly; v0.9 List.listStyle, v0.8 MultipleChoice.variant, and collision validationRegexp normalize cleanly."""
        # 1. Valid custom-catalog surface passes strict validation while still checking URLs
        custom_surface = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "chart_surface",
                "catalogId": "https://acme.example/catalogs/charts/v1/catalog.json",
                "components": [
                    {
                        "id": "root",
                        "component": "BarChart",
                        "series": [1, 2, 3],
                        "title": {"@call": "formatChartTitle", "args": {"prefix": "Q4"}},
                    }
                ],
            },
        }
        res_custom = validate_payload(json.dumps(custom_surface), version="1.0", strict=True)
        self.assertTrue(res_custom["ok"], res_custom["errors"])

        # Custom surface still blocks unsafe URLs
        custom_unsafe = json.loads(json.dumps(custom_surface))
        custom_unsafe["createSurface"]["components"][0]["url"] = "javascript:alert(1)"
        res_cu = validate_payload(json.dumps(custom_unsafe), version="1.0", strict=True)
        self.assertFalse(res_cu["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_cu["errors"]})

        # 2. v0.9 List.listStyle stripped cleanly
        v09_list = {
            "version": "0.9",
            "createSurface": {
                "surfaceId": "s_list",
                "catalogId": "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json",
            },
        }
        v09_comps = {
            "version": "0.9",
            "updateComponents": {
                "surfaceId": "s_list",
                "components": [
                    {"id": "root", "component": "List", "listStyle": "bulleted", "children": ["item_a"]},
                    {"id": "item_a", "component": "Text", "text": "Item A"},
                ],
            },
        }
        n_list = normalize_payload(json.dumps([v09_list, v09_comps]), fmt="json")
        self.assertTrue(n_list["ok"], n_list["validation"])
        root_list = n_list["payload"][1]["updateComponents"]["components"][0]
        self.assertNotIn("listStyle", root_list)

        # 3. v0.8 MultipleChoice.variant ("chips"/"checkbox") -> displayStyle + variant from maxAllowedSelections
        v08_mc = [
            {"beginRendering": {"surfaceId": "mc_s", "root": "root"}},
            {
                "surfaceUpdate": {
                    "surfaceId": "mc_s",
                    "components": [
                        {
                            "id": "root",
                            "component": {
                                "MultipleChoice": {
                                    "variant": "chips",
                                    "selections": {"path": "/tags"},
                                    "maxAllowedSelections": 1,
                                    "options": [
                                        {"label": {"literalString": "One"}, "value": "one"},
                                    ],
                                }
                            },
                        }
                    ],
                }
            },
        ]
        n_mc = normalize_payload(json.dumps(v08_mc), fmt="json")
        self.assertTrue(n_mc["ok"], n_mc["validation"])
        cp = n_mc["payload"][1]["updateComponents"]["components"][0]
        self.assertEqual(cp["component"], "ChoicePicker")
        self.assertEqual(cp["displayStyle"], "chips")
        self.assertEqual(cp["variant"], "mutuallyExclusive")

        # 4. Collision-suffixed TextField.validationRegexp binds to final suffixed @path
        coll_re = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "coll_re",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": ["code_1", "code-1"]},
                    {"id": "code_1", "component": "TextField", "label": "Primary Code"},
                    {
                        "id": "code-1",
                        "component": "TextField",
                        "label": "Secondary Code",
                        "validationRegexp": "^[A-Z]{3}$",
                    },
                ],
            },
        }
        n_re = normalize_payload(json.dumps(coll_re), fmt="json")
        self.assertTrue(n_re["ok"], n_re["validation"])
        re_comps = {c["id"]: c for c in n_re["payload"][0]["createSurface"]["components"]}
        self.assertIn("code_1_2", re_comps)
        self.assertEqual(re_comps["code_1_2"]["value"], {"@path": "/code_1_2"})
        self.assertEqual(
            re_comps["code_1_2"]["@checks"][0]["condition"]["args"]["value"],
            {"@path": "/code_1_2"},
        )

    def test_rfc6901_pointers_historical_url_snapshots_nested_format_and_schema_edges(self) -> None:
        """RFC 6901 array indices, empty-key pointers, historical URL snapshots, nested formatString, callAgentFunction, broken catalog URI, and Icon.name."""
        # 1. Non-RFC-6901 array indices (\u00b2, 4500-digit string, \u0660, "00") do not crash or desync
        non_rfc_indices = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "idx_guard",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "Image", "url": {"@path": "/items/0/url"}},
                    ],
                    "dataModel": {"items": [{"url": "javascript:alert(1)"}]},
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "idx_guard",
                    "path": "/items/\u00b2/url",
                    "value": "https://example.com/safe.png",
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "idx_guard",
                    "path": "/items/" + ("9" * 4500) + "/url",
                    "value": "https://example.com/safe.png",
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "idx_guard",
                    "path": "/items/\u0660/url",
                    "value": "https://example.com/safe.png",
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "idx_guard",
                    "path": "/items/00/url",
                    "value": "https://example.com/safe.png",
                },
            },
        ]
        res_idx = validate_payload(json.dumps(non_rfc_indices), version="1.0", strict=True)
        self.assertFalse(res_idx["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_idx["errors"]})

        # 2. Empty-key RFC 6901 JSON Pointer ("//url") resolves dataModel[""]["url"] identically to runtimes
        empty_key_ptr = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "empty_key_s",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": ["img", "btn"]},
                    {"id": "img", "component": "Image", "url": {"@path": "//url"}},
                    {
                        "id": "btn",
                        "component": "Button",
                        "child": "btn_lbl",
                        "action": {"functionCall": {"@call": "openUrl", "args": {"url": {"@path": "//url"}}}},
                    },
                    {"id": "btn_lbl", "component": "Text", "text": "Open"},
                ],
                "dataModel": {"": {"url": "javascript:alert(1)"}},
            },
        }
        res_ek = validate_payload(json.dumps(empty_key_ptr), version="1.0", strict=True)
        self.assertFalse(res_ek["ok"])
        codes_ek = {e["code"] for e in res_ek["errors"]}
        self.assertIn("UNSAFE_MEDIA_URL", codes_ek)
        self.assertIn("UNSAFE_OPEN_URL", codes_ek)

        # 3. Post-render updateDataModel overwrite cannot mask earlier unsafe URLs (direct + ChildList + formatString)
        overwrite_mask = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "hist_s",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "Column", "children": ["hero", "go_btn", "cards"]},
                        {"id": "hero", "component": "Image", "url": {"@path": "/url"}},
                        {
                            "id": "go_btn",
                            "component": "Button",
                            "child": "go_lbl",
                            "action": {
                                "functionCall": {
                                    "@call": "openUrl",
                                    "args": {
                                        "url": {
                                            "@call": "formatString",
                                            "args": {"value": "https://${/creds}example.com/"},
                                        }
                                    },
                                }
                            },
                        },
                        {"id": "go_lbl", "component": "Text", "text": "Go"},
                        {"id": "cards", "component": "List", "children": {"componentId": "card_img", "path": "/items"}},
                        {"id": "card_img", "component": "Image", "url": {"@path": "pic"}},
                    ],
                    "dataModel": {
                        "url": "javascript:alert(1)",
                        "creds": "a2ui.org@",
                        "items": [{"pic": "javascript:alert(2)"}],
                    },
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "hist_s",
                    "path": "/url",
                    "value": "https://example.com/safe.png",
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "hist_s",
                    "path": "/creds",
                    "value": "docs.",
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "hist_s",
                    "path": "/items/0/pic",
                    "value": "https://example.com/item.png",
                },
            },
        ]
        res_hist = validate_payload(json.dumps(overwrite_mask), version="1.0", strict=True)
        self.assertFalse(res_hist["ok"])
        media_hist = [e for e in res_hist["errors"] if e["code"] == "UNSAFE_MEDIA_URL"]
        open_hist = [e for e in res_hist["errors"] if e["code"] == "UNSAFE_OPEN_URL"]
        self.assertEqual(len(media_hist), 2)
        self.assertEqual(len(open_hist), 1)

        # 4. Nested ${formatString(...)}, function calls, escaped \${, and unclosed ${ in URL formatString fail closed
        for bad_tpl in (
            "https://${formatString(value:${/creds})}evil.example/",
            "/${formatString(value:${/evil})}",
            "https://example.com/${foo(bar)}",
            r"https://example.com/\${/safe}",
            "https://example.com/${/unclosed",
            "https://example.com/${}",
        ):
            bad_fmt = {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "fmt_s",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {
                            "id": "root",
                            "component": "Button",
                            "child": "lbl",
                            "action": {
                                "functionCall": {
                                    "@call": "openUrl",
                                    "args": {"url": {"@call": "formatString", "args": {"value": bad_tpl}}},
                                }
                            },
                        },
                        {"id": "lbl", "component": "Text", "text": "Open"},
                    ],
                    "dataModel": {"creds": "a2ui.org@", "evil": "/attacker.example/x.png", "safe": "ok"},
                },
            }
            res_fmt = validate_payload(json.dumps(bad_fmt), version="1.0", strict=True)
            self.assertFalse(res_fmt["ok"], f"Expected rejection for URL formatString template: {bad_tpl!r}")
            self.assertIn("UNSAFE_OPEN_URL", {e["code"] for e in res_fmt["errors"]})

        # 5. callAgentFunction requires surfaceId and treats callFunction.catalogId as optional (inheriting surface catalogId)
        agent_fn_basic_ok = {
            "version": "1.0",
            "callAgentFunction": {
                "surfaceId": "main",
                "functionCallId": "fc_basic",
                "callFunction": {"@call": "formatString", "args": {"value": "ok"}},
            },
        }
        self.assertTrue(validate_payload(json.dumps(agent_fn_basic_ok), version="1.0", strict=True)["ok"])

        agent_fn_custom_inherit = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "ops",
                    "catalogId": "https://acme.example/catalogs/ops/v1/catalog.json",
                    "components": [{"id": "root", "component": "OpsPanel"}],
                },
            },
            {
                "version": "1.0",
                "callAgentFunction": {
                    "surfaceId": "ops",
                    "functionCallId": "fc_ops_1",
                    "callFunction": {"@call": "fetchMetrics", "args": {"window": "5m"}},
                },
            },
        ]
        res_agent_inherit = validate_payload(json.dumps(agent_fn_custom_inherit), version="1.0", strict=True)
        self.assertTrue(res_agent_inherit["ok"], res_agent_inherit["errors"])

        agent_fn_missing_sid = {
            "version": "1.0",
            "callAgentFunction": {
                "functionCallId": "fc_no_sid",
                "callFunction": {
                    "@call": "formatString",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "args": {"value": "hi"},
                },
            },
        }
        res_no_sid = validate_payload(json.dumps(agent_fn_missing_sid), version="1.0", strict=True)
        self.assertFalse(res_no_sid["ok"])
        self.assertIn("MISSING_SURFACE_ID", {e["code"] for e in res_no_sid["errors"]})

        # 6. BROKEN_CATALOG_URI warning emitted on component @catalogId and FunctionCall.catalogId
        broken_cat_payload = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "broken_cat",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {
                        "id": "root",
                        "component": "Text",
                        "@catalogId": "https://a2ui.org/specification/v0_9/basic_catalog.json",
                        "text": {
                            "@call": "formatString",
                            "catalogId": "https://a2ui.org/specification/v0_9/basic_catalog.json",
                            "args": {"value": "hello"},
                        },
                    }
                ],
            },
        }
        res_bcat = validate_payload(json.dumps(broken_cat_payload), version="1.0", strict=False)
        broken_warns = [w for w in res_bcat["warnings"] if w["code"] == "BROKEN_CATALOG_URI"]
        self.assertEqual(len(broken_warns), 2)

        # 7. Icon.name rejects direct FunctionCall (@call / call) while allowing DataBinding and svgPath DynamicString
        icon_call_bad = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "icon_bad",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {
                        "id": "root",
                        "component": "Icon",
                        "name": {"@call": "formatString", "args": {"value": "check"}},
                    }
                ],
            },
        }
        res_icon_bad = validate_payload(json.dumps(icon_call_bad), version="1.0", strict=True)
        self.assertFalse(res_icon_bad["ok"])
        self.assertIn("INVALID_ICON_NAME", {e["code"] for e in res_icon_bad["errors"]})

        icon_ok = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "icon_ok",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Row", "children": ["ico_path", "ico_svg"]},
                    {"id": "ico_path", "component": "Icon", "name": {"@path": "/iconName"}},
                    {
                        "id": "ico_svg",
                        "component": "Icon",
                        "name": {"svgPath": {"@call": "formatString", "args": {"value": "M0 0 L10 10"}}},
                    },
                ],
                "dataModel": {"iconName": "check"},
            },
        }
        res_icon_ok = validate_payload(json.dumps(icon_ok), version="1.0", strict=True)
        self.assertTrue(res_icon_ok["ok"], res_icon_ok["errors"])

    def test_streaming_url_validation_performance_and_childlist_single_item(self) -> None:
        """Streaming in-place URL checks avoid snapshot blowup and catch single-item ChildList mutations."""
        # 1. Large dataModel (50k ints) + 1,000 unrelated updateDataModel lines stays well under 1s
        head = json.dumps(
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "perf_s",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [{"id": "root", "component": "Image", "url": {"@path": "/u"}}],
                    "dataModel": {"u": "https://example.com/ok.png", "arr": [1] * 50000, "c": 0},
                },
            },
            separators=(",", ":"),
        )
        updates = [
            json.dumps(
                {"version": "1.0", "updateDataModel": {"surfaceId": "perf_s", "path": "/c", "value": i % 2}},
                separators=(",", ":"),
            )
            for i in range(1000)
        ]
        t0 = time.perf_counter()
        res_perf = validate_payload("\n".join([head] + updates), version="1.0", strict=True)
        elapsed = time.perf_counter() - t0
        self.assertTrue(res_perf["ok"], res_perf["errors"])
        self.assertLess(elapsed, 1.5, f"Streaming validation took too long: {elapsed:.3f}s")

        # 2. Single-item ChildList mutation (/items/1/u and /items/-) catches unsafe URL even if later overwritten
        single_item = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "cl_single",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "row_img", "path": "/items"}},
                        {"id": "row_img", "component": "Image", "url": {"@path": "u"}},
                    ],
                    "dataModel": {"items": [{"u": "/a.png"}, {"u": "/b.png"}]},
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "cl_single",
                    "path": "/items/1/u",
                    "value": "javascript:alert(1)",
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "cl_single",
                    "path": "/items/1/u",
                    "value": "/b_safe.png",
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "cl_single",
                    "path": "/items/-",
                    "value": {"u": "javascript:alert(2)"},
                },
            },
        ]
        res_single = validate_payload(json.dumps(single_item), version="1.0", strict=True)
        self.assertFalse(res_single["ok"])
        media_errs = [e for e in res_single["errors"] if e["code"] == "UNSAFE_MEDIA_URL"]
        self.assertEqual(len(media_errs), 2)

        # 3. Deferred ChildList template component arriving in updateComponents catches existing unsafe dataModel item
        deferred_tpl = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "cl_defer",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "row_img", "path": "/items"}},
                    ],
                    "dataModel": {"items": [{"u": "javascript:alert(1)"}]},
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "cl_defer",
                    "components": [
                        {"id": "row_img", "component": "Image", "url": {"@path": "u"}},
                    ],
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "cl_defer",
                    "path": "/items/0/u",
                    "value": "https://example.com/ok.png",
                },
            },
        ]
        res_defer = validate_payload(json.dumps(deferred_tpl), version="1.0", strict=True)
        self.assertFalse(res_defer["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_defer["errors"]})

    def test_formatstring_null_and_unresolved_empty_string_smuggling(self) -> None:
        """Null or missing formatString placeholders evaluate to empty string and cannot smuggle //host or https:///."""
        for dm in ({"seg": None}, {}):
            smuggle_media = {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "emp_media",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {
                            "id": "root",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "/${/seg}/evil.example/x.png"}},
                        }
                    ],
                    "dataModel": dm,
                },
            }
            res_m = validate_payload(json.dumps(smuggle_media), version="1.0", strict=True)
            self.assertFalse(res_m["ok"], f"Expected UNSAFE_MEDIA_URL for dataModel={dm}")
            self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_m["errors"]})

            smuggle_open = {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "emp_open",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {
                            "id": "root",
                            "component": "Button",
                            "child": "lbl",
                            "action": {
                                "functionCall": {
                                    "@call": "openUrl",
                                    "args": {
                                        "url": {
                                            "@call": "formatString",
                                            "args": {"value": "https://${/seg}/evil.example"},
                                        }
                                    },
                                }
                            },
                        },
                        {"id": "lbl", "component": "Text", "text": "Open"},
                    ],
                    "dataModel": dm,
                },
            }
            res_o = validate_payload(json.dumps(smuggle_open), version="1.0", strict=True)
            self.assertFalse(res_o["ok"], f"Expected UNSAFE_OPEN_URL for dataModel={dm}")
            self.assertIn("UNSAFE_OPEN_URL", {e["code"] for e in res_o["errors"]})

        # Safe path/query templates with unresolved placeholders and resolved host templates still pass
        safe_templates = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "safe_tpl",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": ["img_rel", "img_host", "btn_path"]},
                    {
                        "id": "img_rel",
                        "component": "Image",
                        "url": {"@call": "formatString", "args": {"value": "/assets/${/img}.png"}},
                    },
                    {
                        "id": "img_host",
                        "component": "Image",
                        "url": {"@call": "formatString", "args": {"value": "https://${/host}/logo.png"}},
                    },
                    {
                        "id": "btn_path",
                        "component": "Button",
                        "child": "btn_lbl",
                        "action": {
                            "functionCall": {
                                "@call": "openUrl",
                                "args": {
                                    "url": {
                                        "@call": "formatString",
                                        "args": {"value": "https://example.com/users/${/id}"},
                                    }
                                },
                            }
                        },
                    },
                    {"id": "btn_lbl", "component": "Text", "text": "Profile"},
                ],
                "dataModel": {"host": "cdn.example.com"},
            },
        }
        res_safe = validate_payload(json.dumps(safe_templates), version="1.0", strict=True)
        self.assertTrue(res_safe["ok"], res_safe["errors"])

    def test_normalize_upgrades_legacy_component_and_function_catalog_ids(self) -> None:
        """Normalizer upgrades legacy Basic Catalog URIs on components, FunctionCalls, and RPC envelopes."""
        legacy_payload = [
            {
                "version": "0.9",
                "createSurface": {
                    "surfaceId": "leg_cat",
                    "catalogId": BROKEN_V09_CATALOG_ID,
                },
            },
            {
                "version": "0.9",
                "updateComponents": {
                    "surfaceId": "leg_cat",
                    "components": [
                        {"id": "root", "component": "Column", "children": ["t_broken", "t_v09", "t_custom"]},
                        {
                            "id": "t_broken",
                            "component": "Text",
                            "catalogId": BROKEN_V09_CATALOG_ID,
                            "text": {
                                "call": "formatString",
                                "catalogId": BROKEN_V09_CATALOG_ID,
                                "args": {"value": "Hello"},
                            },
                        },
                        {
                            "id": "t_v09",
                            "component": "Text",
                            "catalogId": CANONICAL_V09_CATALOG_ID,
                            "text": {
                                "call": "formatString",
                                "catalogId": CANONICAL_V08_CATALOG_ID,
                                "args": {"value": "World"},
                            },
                        },
                        {
                            "id": "t_custom",
                            "component": "CustomBadge",
                            "catalogId": "https://acme.example/catalogs/ui/v1/catalog.json",
                            "badgeText": "OK",
                        },
                    ],
                },
            },
            {
                "version": "0.9",
                "callRendererFunction": {
                    "functionCallId": "fc_r1",
                    "callFunction": {
                        "call": "formatNumber",
                        "catalogId": BROKEN_V09_CATALOG_ID,
                        "args": {"value": {"path": "/n"}},
                    },
                },
            },
            {
                "version": "0.9",
                "callAgentFunction": {
                    "surfaceId": "leg_cat",
                    "functionCallId": "fc_a1",
                    "callFunction": {
                        "call": "formatString",
                        "catalogId": "basic",
                        "args": {"value": "Done"},
                    },
                },
            },
        ]
        norm = normalize_payload(json.dumps(legacy_payload), fmt="json")
        self.assertTrue(norm["ok"], norm["validation"])
        self.assertTrue(validate_payload(norm["formatted"], version="1.0", strict=True)["ok"])

        comps = {c["id"]: c for c in norm["payload"][1]["updateComponents"]["components"]}
        self.assertEqual(comps["t_broken"]["@catalogId"], CANONICAL_V1_CATALOG_ID)
        self.assertEqual(comps["t_broken"]["text"]["@call"], "formatString")
        self.assertEqual(comps["t_broken"]["text"]["catalogId"], CANONICAL_V1_CATALOG_ID)
        self.assertEqual(comps["t_v09"]["@catalogId"], CANONICAL_V1_CATALOG_ID)
        self.assertEqual(comps["t_v09"]["text"]["catalogId"], CANONICAL_V1_CATALOG_ID)
        self.assertEqual(comps["t_custom"]["@catalogId"], "https://acme.example/catalogs/ui/v1/catalog.json")

        rpc_r = norm["payload"][2]["callRendererFunction"]["callFunction"]
        self.assertEqual(rpc_r["@call"], "formatNumber")
        self.assertEqual(rpc_r["catalogId"], CANONICAL_V1_CATALOG_ID)
        self.assertEqual(rpc_r["args"]["value"], {"@path": "/n"})

        rpc_a = norm["payload"][3]["callAgentFunction"]["callFunction"]
        self.assertEqual(rpc_a["@call"], "formatString")
        self.assertEqual(rpc_a["catalogId"], CANONICAL_V1_CATALOG_ID)

    def test_v1_icon_svgpath_catalog_id_types_and_function_response_envelopes(self) -> None:
        """Icon.name.svgPath types, component/FunctionCall catalogId types, and FunctionResponse envelopes are strictly validated."""
        # 1. Invalid Icon.name.svgPath values (int, null, arbitrary dict)
        for bad_svg in (123, None, {"foo": "bar"}, []):
            svg_payload = {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "bad_svg",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [{"id": "root", "component": "Icon", "name": {"svgPath": bad_svg}}],
                },
            }
            res_svg = validate_payload(json.dumps(svg_payload), version="1.0", strict=True)
            self.assertFalse(res_svg["ok"], f"Expected INVALID_ICON_NAME for svgPath={bad_svg!r}")
            self.assertIn("INVALID_ICON_NAME", {e["code"] for e in res_svg["errors"]})

        # 2. Invalid component @catalogId and FunctionCall.catalogId types (int, empty string, null, list, dict)
        for bad_cat in (123, "", None, [], {}):
            bad_cat_payload = {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "bad_cat_t",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {
                            "id": "root",
                            "component": "Text",
                            "@catalogId": bad_cat,
                            "text": {"@call": "formatString", "catalogId": bad_cat, "args": {"value": "hi"}},
                        }
                    ],
                },
            }
            res_cat = validate_payload(json.dumps(bad_cat_payload), version="1.0", strict=True)
            self.assertFalse(res_cat["ok"], f"Expected INVALID_CATALOG_ID for catalogId={bad_cat!r}")
            cat_errs = [e for e in res_cat["errors"] if e["code"] == "INVALID_CATALOG_ID"]
            self.assertEqual(len(cat_errs), 2)

        # 3. Valid agentFunctionResponse and rendererFunctionResponse envelopes
        valid_resps = [
            {"version": "1.0", "agentFunctionResponse": {"functionCallId": "fc_1", "value": None}},
            {"version": "1.0", "rendererFunctionResponse": {"functionCallId": "fc_2", "value": {"ok": True}}},
            {
                "version": "1.0",
                "agentFunctionResponse": {
                    "functionCallId": "fc_3",
                    "error": {"code": "TIMEOUT", "message": "Function timed out."},
                },
            },
        ]
        res_ok_resp = validate_payload(json.dumps(valid_resps), version="1.0", strict=True)
        self.assertTrue(res_ok_resp["ok"], res_ok_resp["errors"])

        # 4. Invalid FunctionResponse envelopes (empty, both value+error, extra key, invalid error object)
        bad_resps = [
            {"version": "1.0", "agentFunctionResponse": {}},
            {
                "version": "1.0",
                "rendererFunctionResponse": {
                    "functionCallId": "fc_both",
                    "value": 1,
                    "error": {"code": "ERR", "message": "msg"},
                },
            },
            {
                "version": "1.0",
                "agentFunctionResponse": {
                    "functionCallId": "fc_extra",
                    "value": "ok",
                    "unexpected": True,
                },
            },
            {
                "version": "1.0",
                "rendererFunctionResponse": {
                    "functionCallId": "fc_bad_err",
                    "error": {"code": "", "message": 123, "extra": 1},
                },
            },
        ]
        res_bad_resp = validate_payload(json.dumps(bad_resps), version="1.0", strict=True)
        self.assertFalse(res_bad_resp["ok"])
        resp_codes = {e["code"] for e in res_bad_resp["errors"]}
        self.assertIn("MISSING_FUNCTION_CALL_ID", resp_codes)
        self.assertIn("INVALID_FUNCTION_RESPONSE", resp_codes)
        self.assertIn("UNKNOWN_ENVELOPE_FIELD", resp_codes)
        self.assertIn("INVALID_FUNCTION_RESPONSE_ERROR", resp_codes)

    def test_streaming_array_append_splice_eval_cap_and_nested_relative_childlists(self) -> None:
        """Array /- appends, null splices, template eval-cap fail-closed, and nested relative ChildLists are enforced."""
        # 1a. Array append (/-) into a direct URL slot followed by safe overwrite fails closed
        append_direct = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "app_direct",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "Image", "url": {"@path": "/arr/0"}},
                    ],
                    "dataModel": {"arr": []},
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "app_direct",
                    "path": "/arr/-",
                    "value": "javascript:alert(1)",
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "app_direct",
                    "path": "/arr/0",
                    "value": "https://example.com/safe.png",
                },
            },
        ]
        res_ad = validate_payload(json.dumps(append_direct), version="1.0", strict=True)
        self.assertFalse(res_ad["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_ad["errors"]})

        # 1b. Array append (/-) into an ancestor of a ChildList followed by safe overwrite fails closed
        append_ancestor = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "app_anc",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "row_img", "path": "/outer/0/items"}},
                        {"id": "row_img", "component": "Image", "url": {"@path": "u"}},
                    ],
                    "dataModel": {"outer": []},
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "app_anc",
                    "path": "/outer/-",
                    "value": {"items": [{"u": "javascript:alert(1)"}]},
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "app_anc",
                    "path": "/outer",
                    "value": [],
                },
            },
        ]
        res_aa = validate_payload(json.dumps(append_ancestor), version="1.0", strict=True)
        self.assertFalse(res_aa["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_aa["errors"]})

        # 2a. Array element splice (value: null) shifting sibling into direct URL slot fails closed
        splice_direct = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "spl_direct",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "Image", "url": {"@path": "/arr/1"}},
                    ],
                    "dataModel": {"arr": ["/a.png", "/b.png", "javascript:alert(1)"]},
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "spl_direct", "path": "/arr/0", "value": None},
            },
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "spl_direct", "path": "/arr/1", "value": "/safe.png"},
            },
        ]
        res_sd = validate_payload(json.dumps(splice_direct), version="1.0", strict=True)
        self.assertFalse(res_sd["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_sd["errors"]})

        # 2b. Array element splice (value: null) shifting descendant ChildList fails closed
        splice_anc = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "spl_anc",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "row_img", "path": "/outer/1/items"}},
                        {"id": "row_img", "component": "Image", "url": {"@path": "u"}},
                    ],
                    "dataModel": {
                        "outer": [
                            {"items": [{"u": "/a.png"}]},
                            {"items": [{"u": "/b.png"}]},
                            {"items": [{"u": "javascript:alert(1)"}]},
                        ]
                    },
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "spl_anc", "path": "/outer/0", "value": None},
            },
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "spl_anc", "path": "/outer", "value": []},
            },
        ]
        res_sa = validate_payload(json.dumps(splice_anc), version="1.0", strict=True)
        self.assertFalse(res_sa["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_sa["errors"]})

        # 3. Exceeding _MAX_TEMPLATE_ABS_RESCAN_EVALS fails closed with MAX_TEMPLATE_EVALS_EXCEEDED
        items_1001 = [{"rel": "/ok.png"} for _ in range(1000)] + [{"rel": "/evil.example/x.png"}]
        cap_msgs: list[dict] = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "cap_s",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "row_img", "path": "/items"}},
                        {
                            "id": "row_img",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "/${/a}${rel}"}},
                        },
                    ],
                    "dataModel": {"a": "assets", "items": items_1001},
                },
            }
        ]
        for idx in range(10):
            cap_msgs.append(
                {
                    "version": "1.0",
                    "updateDataModel": {"surfaceId": "cap_s", "path": "/a", "value": f"p{idx}"},
                }
            )
        cap_msgs.append({"version": "1.0", "updateDataModel": {"surfaceId": "cap_s", "path": "/a", "value": ""}})
        cap_msgs.append({"version": "1.0", "updateDataModel": {"surfaceId": "cap_s", "path": "/a", "value": "assets"}})
        res_cap = validate_payload(json.dumps(cap_msgs), version="1.0", strict=True)
        self.assertFalse(res_cap["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_cap["errors"]})

        # 4a. Nested relative ChildList.path in static createSurface catches unsafe URL
        nested_static = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "nest_s",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "List", "children": {"componentId": "grp", "path": "/groups"}},
                    {"id": "grp", "component": "List", "children": {"componentId": "row_img", "path": "items"}},
                    {"id": "row_img", "component": "Image", "url": {"@path": "u"}},
                ],
                "dataModel": {"groups": [{"items": [{"u": "javascript:alert(1)"}]}]},
            },
        }
        res_ns = validate_payload(json.dumps(nested_static), version="1.0", strict=True)
        self.assertFalse(res_ns["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_ns["errors"]})

        # 4b. Nested relative ChildList.path updated via streaming updateDataModel (/- and item mutation) fails closed
        nested_stream = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "nest_stream",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "grp_col", "path": "/groups"}},
                        {"id": "grp_col", "component": "Column", "children": ["inner_list"]},
                        {"id": "inner_list", "component": "List", "children": {"componentId": "row_btn", "path": "items"}},
                        {
                            "id": "row_btn",
                            "component": "Button",
                            "child": "row_lbl",
                            "action": {"functionCall": {"@call": "openUrl", "args": {"url": {"@path": "href"}}}},
                        },
                        {"id": "row_lbl", "component": "Text", "text": "Open"},
                    ],
                    "dataModel": {"groups": [{"items": [{"href": "https://example.com/ok"}]}]},
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "nest_stream",
                    "path": "/groups/0/items/0/href",
                    "value": "javascript:alert(1)",
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "nest_stream",
                    "path": "/groups/0/items/0/href",
                    "value": "https://example.com/safe",
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "nest_stream",
                    "path": "/groups/-",
                    "value": {"items": [{"href": "https://user@evil.example/"}]},
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "nest_stream", "path": "/groups", "value": []},
            },
        ]
        res_nst = validate_payload(json.dumps(nested_stream), version="1.0", strict=True)
        self.assertFalse(res_nst["ok"])
        open_errs = [e for e in res_nst["errors"] if e["code"] == "UNSAFE_OPEN_URL"]
        self.assertEqual(len(open_errs), 2)

        # 4c. Valid nested relative ChildList.path passes strict validation cleanly
        nested_ok = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "nest_ok",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "List", "children": {"componentId": "grp", "path": "/groups"}},
                    {"id": "grp", "component": "List", "children": {"componentId": "row_img", "path": "items"}},
                    {"id": "row_img", "component": "Image", "url": {"@path": "u"}},
                ],
                "dataModel": {"groups": [{"items": [{"u": "https://example.com/a.png"}]}]},
            },
        }
        res_nok = validate_payload(json.dumps(nested_ok), version="1.0", strict=True)
        self.assertTrue(res_nok["ok"], res_nok["errors"])

    def test_component_replacement_data_slot_reuse_and_outgoing_url_checks(self) -> None:
        """Replaced URL components do not falsely fail when their old data pointer is reused for text."""
        # 1. Image -> Text replacement reusing /slot for plain text passes strict validation
        img_to_txt = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "rep_img",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [{"id": "root", "component": "Image", "url": {"@path": "/slot"}}],
                    "dataModel": {"slot": "https://example.com/ok.png"},
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "rep_img",
                    "components": [{"id": "root", "component": "Text", "text": {"@path": "/slot"}}],
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "rep_img", "path": "/slot", "value": "Plain text heading"},
            },
        ]
        res_it = validate_payload(json.dumps(img_to_txt), version="1.0", strict=True)
        self.assertTrue(res_it["ok"], res_it["errors"])

        # 2. Button(openUrl) -> Button(event) replacement reusing /slot passes strict validation
        btn_to_ev = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "rep_btn",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {
                            "id": "root",
                            "component": "Button",
                            "child": "lbl",
                            "action": {"functionCall": {"@call": "openUrl", "args": {"url": {"@path": "/slot"}}}},
                        },
                        {"id": "lbl", "component": "Text", "text": "Go"},
                    ],
                    "dataModel": {"slot": "https://example.com/docs"},
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "rep_btn",
                    "components": [
                        {
                            "id": "root",
                            "component": "Button",
                            "child": "lbl",
                            "action": {"event": {"name": "submit", "context": {"tag": {"@path": "/slot"}}}},
                        }
                    ],
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "rep_btn", "path": "/slot", "value": "not_a_url"},
            },
        ]
        res_be = validate_payload(json.dumps(btn_to_ev), version="1.0", strict=True)
        self.assertTrue(res_be["ok"], res_be["errors"])

        # 3. Outgoing unresolved prefix-less formatString URL on a replaced component still fails closed
        rep_prefixless = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "rep_pfx",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {
                            "id": "root",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "${/never_set}"}},
                        }
                    ],
                    "dataModel": {},
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "rep_pfx",
                    "components": [{"id": "root", "component": "Text", "text": "Replaced"}],
                },
            },
        ]
        res_rp = validate_payload(json.dumps(rep_prefixless), version="1.0", strict=True)
        self.assertFalse(res_rp["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_rp["errors"]})

        # 4. Superseded component with static javascript: literal still fails closed
        rep_static_bad = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "rep_static",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [{"id": "root", "component": "Image", "url": "javascript:alert(1)"}],
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "rep_static",
                    "components": [{"id": "root", "component": "Text", "text": "Clean"}],
                },
            },
        ]
        res_rs = validate_payload(json.dumps(rep_static_bad), version="1.0", strict=True)
        self.assertFalse(res_rs["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_rs["errors"]})

    def test_icon_svgpath_malformed_dicts_and_create_surface_catalog_id_types(self) -> None:
        """Malformed Icon.name.svgPath dicts and non-string/empty createSurface.catalogId fail closed."""
        # 1. Malformed Icon.name.svgPath dicts emit INVALID_ICON_NAME
        for bad_svg in (
            {"path": 123},
            {"call": 123},
            {"path": "/p", "extra": 1},
            {"@path": "/p", "extra": 1},
        ):
            payload = {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "svg_m",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [{"id": "root", "component": "Icon", "name": {"svgPath": bad_svg}}],
                },
            }
            res = validate_payload(json.dumps(payload), version="1.0", strict=True)
            self.assertFalse(res["ok"], f"Expected INVALID_ICON_NAME for svgPath={bad_svg!r}")
            self.assertIn("INVALID_ICON_NAME", {e["code"] for e in res["errors"]})

        # Direct Icon.name with non-string path also emits INVALID_ICON_NAME
        bad_direct_icon = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "ico_m",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [{"id": "root", "component": "Icon", "name": {"path": 123}}],
            },
        }
        res_di = validate_payload(json.dumps(bad_direct_icon), version="1.0", strict=True)
        self.assertFalse(res_di["ok"])
        self.assertIn("INVALID_ICON_NAME", {e["code"] for e in res_di["errors"]})

        # 2. Invalid createSurface.catalogId types emit INVALID_CATALOG_ID at $[0].createSurface.catalogId
        for bad_cat in (123, "", "   ", None, [], {}):
            cs_bad = {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "cs_cat_bad",
                    "catalogId": bad_cat,
                    "components": [{"id": "root", "component": "Text", "text": "Hi"}],
                },
            }
            res_cs = validate_payload(json.dumps(cs_bad), version="1.0", strict=True)
            self.assertFalse(res_cs["ok"], f"Expected INVALID_CATALOG_ID for catalogId={bad_cat!r}")
            cat_errs = [e for e in res_cs["errors"] if e["code"] == "INVALID_CATALOG_ID"]
            self.assertEqual(len(cat_errs), 1)
            self.assertEqual(cat_errs[0]["path"], "$[0].createSurface.catalogId")

        # Omitting catalogId on v1.0 createSurface remains valid
        cs_omit = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "cs_cat_omit",
                "components": [{"id": "root", "component": "Text", "text": "Hi"}],
            },
        }
        res_omit = validate_payload(json.dumps(cs_omit), version="1.0", strict=True)
        self.assertTrue(res_omit["ok"], res_omit["errors"])

    def test_cross_message_template_rescan_budgets_and_unshifted_pop_skips(self) -> None:
        """Unshifted ancestor array pops skip unchanged subtrees; shifted pops and repeated batch updates enforce eval caps."""
        # 1. Unshifted pop sibling skip: 25,000 items at /outer/0/items + 6,000 pops at /outer/1 = null
        unshifted_msgs: list[dict] = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "spop_unshifted",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {
                            "id": "root",
                            "component": "List",
                            "children": {"componentId": "r", "path": "/outer/0/items"},
                        },
                        {"id": "r", "component": "Image", "url": {"@path": "u"}},
                    ],
                    "dataModel": {
                        "outer": [{"items": [{"u": "/a"} for _ in range(25_000)]}] + [0] * 6_000,
                    },
                },
            }
        ]
        for _ in range(6_000):
            unshifted_msgs.append(
                {
                    "version": "1.0",
                    "updateDataModel": {"surfaceId": "spop_unshifted", "path": "/outer/1", "value": None},
                }
            )
        raw_unshifted = json.dumps(unshifted_msgs, separators=(",", ":"))
        t0 = time.perf_counter()
        res_unshifted = validate_payload(raw_unshifted, version="1.0", strict=True)
        dt_unshifted = time.perf_counter() - t0
        self.assertTrue(res_unshifted["ok"], res_unshifted["errors"])
        self.assertLess(dt_unshifted, 1.5)

        # 2. Shifted pop storm at /outer/0 = null across lists fails closed with MAX_TEMPLATE_EVALS_EXCEEDED
        pop_storm_msgs: list[dict] = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "spop_storm",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {
                            "id": "root",
                            "component": "List",
                            "children": {"componentId": "r", "path": "/outer/0/items"},
                        },
                        {"id": "r", "component": "Image", "url": {"@path": "u"}},
                    ],
                    "dataModel": {
                        "outer": [
                            {"items": [{"u": "/a"} for _ in range(18_000)]},
                            {"items": [{"u": "/a"} for _ in range(18_000)]},
                            {"items": [{"u": "/a"} for _ in range(18_000)]},
                            {"items": [{"u": "/a"} for _ in range(18_000)]},
                        ]
                    },
                },
            },
            {"version": "1.0", "updateDataModel": {"surfaceId": "spop_storm", "path": "/outer/0", "value": None}},
            {"version": "1.0", "updateDataModel": {"surfaceId": "spop_storm", "path": "/outer/0", "value": None}},
            {"version": "1.0", "updateDataModel": {"surfaceId": "spop_storm", "path": "/outer/0", "value": None}},
        ]
        raw_pop_storm = json.dumps(pop_storm_msgs, separators=(",", ":"))
        t1 = time.perf_counter()
        res_pop_storm = validate_payload(raw_pop_storm, version="1.0", strict=True)
        dt_pop_storm = time.perf_counter() - t1
        self.assertFalse(res_pop_storm["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_pop_storm["errors"]})
        self.assertLess(dt_pop_storm, 1.5)

        # 3. Repeated updateComponents batch storm over 50,000 items fails closed with MAX_TEMPLATE_EVALS_EXCEEDED
        batch_storm_msgs: list[dict] = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "sbatch_storm",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "r", "path": "/items"}},
                        {"id": "r", "component": "Image", "url": {"@path": "u"}},
                    ],
                    "dataModel": {"items": [{"u": "/a"} for _ in range(50_000)]},
                },
            }
        ]
        for _ in range(498):
            batch_storm_msgs.append(
                {
                    "version": "1.0",
                    "updateComponents": {
                        "surfaceId": "sbatch_storm",
                        "components": [{"id": "r", "component": "Image", "url": {"@path": "u"}}],
                    },
                }
            )
        raw_batch_storm = json.dumps(batch_storm_msgs, separators=(",", ":"))
        t2 = time.perf_counter()
        res_batch_storm = validate_payload(raw_batch_storm, version="1.0", strict=True)
        dt_batch_storm = time.perf_counter() - t2
        self.assertFalse(res_batch_storm["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_batch_storm["errors"]})
        self.assertLess(dt_batch_storm, 1.5)

    def test_single_item_childlist_update_checks_cross_item_absolute_overlaps(self) -> None:
        """Updating an item pointer inside a ChildList still re-validates other items referencing it absolutely."""
        # 1. openUrl authority-spoof bypass via /items/0/p overlap in items[1]
        open_url_payload = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "cross_open",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "row_btn", "path": "/items"}},
                        {
                            "id": "row_btn",
                            "component": "Button",
                            "child": "row_lbl",
                            "action": {
                                "functionCall": {
                                    "@call": "openUrl",
                                    "args": {
                                        "url": {
                                            "@call": "formatString",
                                            "args": {"value": "https://example.com${/items/0/p}${rel}"},
                                        }
                                    },
                                }
                            },
                        },
                        {"id": "row_lbl", "component": "Text", "text": "Open"},
                    ],
                    "dataModel": {
                        "items": [
                            {"p": "/dir", "rel": "/ok"},
                            {"p": "/dir", "rel": "@evil.example/phish"},
                        ]
                    },
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "cross_open", "path": "/items/0/p", "value": ""},
            },
        ]
        res_open = validate_payload(json.dumps(open_url_payload), version="1.0", strict=True)
        self.assertFalse(res_open["ok"])
        self.assertIn("UNSAFE_OPEN_URL", {e["code"] for e in res_open["errors"]})

        # 2. Image.url scheme-relative bypass via /items/0/p overlap in items[1]
        media_url_payload = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "cross_media",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "row_img", "path": "/items"}},
                        {
                            "id": "row_img",
                            "component": "Image",
                            "url": {
                                "@call": "formatString",
                                "args": {"value": "/${/items/0/p}${rel}"},
                            },
                        },
                    ],
                    "dataModel": {
                        "items": [
                            {"p": "safe", "rel": "ok.png"},
                            {"p": "safe", "rel": "/evil.example/x.png"},
                        ]
                    },
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "cross_media", "path": "/items/0/p", "value": ""},
            },
        ]
        res_media = validate_payload(json.dumps(media_url_payload), version="1.0", strict=True)
        self.assertFalse(res_media["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_media["errors"]})

    def test_pre_mutation_replaced_subtree_and_nested_childlist_prefixless_checks(self) -> None:
        """Replacing containers before leaves or detaching nested ChildLists still catches unresolved prefix-less formatStrings."""
        # 1. Same-batch container-before-leaf replacement [mid -> Text, row_img -> Text, root -> Column]
        same_batch = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "pre_mut_same",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "mid", "path": "/items"}},
                        {"id": "mid", "component": "Column", "children": ["row_img"]},
                        {
                            "id": "row_img",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "${never_set}"}},
                        },
                    ],
                    "dataModel": {"items": [{}]},
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "pre_mut_same",
                    "components": [
                        {"id": "mid", "component": "Text", "text": "m"},
                        {"id": "row_img", "component": "Text", "text": "r"},
                        {"id": "root", "component": "Column", "children": ["mid", "row_img"]},
                    ],
                },
            },
        ]
        res_same = validate_payload(json.dumps(same_batch), version="1.0", strict=True)
        self.assertFalse(res_same["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_same["errors"]})

        # 2. Two-batch nested relative ChildList replacement (inner -> Text, then row_img + root)
        two_batch_nested = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "pre_mut_nested",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "inner", "path": "/groups"}},
                        {"id": "inner", "component": "List", "children": {"componentId": "row_img", "path": "items"}},
                        {
                            "id": "row_img",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "${never_set}"}},
                        },
                    ],
                    "dataModel": {"groups": [{"items": [{}]}]},
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "pre_mut_nested",
                    "components": [{"id": "inner", "component": "Text", "text": "replaced"}],
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "pre_mut_nested",
                    "components": [
                        {"id": "row_img", "component": "Text", "text": "clean"},
                        {"id": "root", "component": "Column", "children": ["inner", "row_img"]},
                    ],
                },
            },
        ]
        res_nested = validate_payload(json.dumps(two_batch_nested), version="1.0", strict=True)
        self.assertFalse(res_nested["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_nested["errors"]})

        # 3. Additive container update keeping an active child with deferred data does not falsely fail
        additive_ok = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "pre_mut_add_ok",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "Column", "children": ["img_a"]},
                        {
                            "id": "img_a",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "${/late_url}"}},
                        },
                    ],
                    "dataModel": {},
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "pre_mut_add_ok",
                    "components": [
                        {"id": "root", "component": "Column", "children": ["img_a", "footer"]},
                        {"id": "footer", "component": "Text", "text": "Footer"},
                    ],
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "pre_mut_add_ok",
                    "path": "/late_url",
                    "value": "https://example.com/ok.png",
                },
            },
        ]
        res_add = validate_payload(json.dumps(additive_ok), version="1.0", strict=True)
        self.assertTrue(res_add["ok"], res_add["errors"])

    def test_surface_url_eval_cap_shared_template_dedup_and_v08_root_merge_timing(self) -> None:
        """Shared-template dedup, unified surface URL eval cap, and v0.8 per-key root merge keep fan-out storms bounded."""
        shared_comps = (
            [{"id": "root", "component": "Column", "children": [f"l{k}" for k in range(249)]}]
            + [
                {"id": f"l{k}", "component": "List", "children": {"componentId": "tpl", "path": "/items"}}
                for k in range(249)
            ]
            + [{"id": "tpl", "component": "Column", "children": [f"v{k}" for k in range(249)]}]
            + [
                {
                    "id": f"v{k}",
                    "component": "Video",
                    "url": {"@call": "formatString", "args": {"value": "https://example.com/${u}"}},
                    "posterUrl": {"@call": "formatString", "args": {"value": "https://example.com/${u}"}},
                }
                for k in range(249)
            ]
        )

        # 1. Shared-template single-item streaming fan-out (deduped)
        shared_stream = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "fan_shared_stream",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": shared_comps,
                    "dataModel": {"items": [{"u": "a"}]},
                },
            }
        ] + [
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "fan_shared_stream", "path": "/items/0/u", "value": f"b{k}"},
            }
            for k in range(10)
        ]
        raw_ss = json.dumps(shared_stream)
        t0 = time.perf_counter()
        res_ss = validate_payload(raw_ss, version="1.0", strict=True)
        self.assertTrue(res_ss["ok"], res_ss["errors"])
        self.assertLess(time.perf_counter() - t0, 0.5)

        # 2. Shared-template createSurface fan-out (deduped)
        shared_cs = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "fan_shared_cs",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": shared_comps,
                    "dataModel": {"items": [{"u": "a"} for _ in range(20)]},
                },
            }
        ]
        raw_sc = json.dumps(shared_cs)
        t1 = time.perf_counter()
        res_sc = validate_payload(raw_sc, version="1.0", strict=True)
        self.assertTrue(res_sc["ok"], res_sc["errors"])
        self.assertLess(time.perf_counter() - t1, 0.5)

        # 3a. Single-List 498-Video fan-out (valid small list + large list hitting surface URL eval cap)
        single_list_comps = (
            [
                {"id": "root", "component": "List", "children": {"componentId": "tpl", "path": "/items"}},
                {"id": "tpl", "component": "Column", "children": [f"v{k}" for k in range(498)]},
            ]
            + [
                {
                    "id": f"v{k}",
                    "component": "Video",
                    "url": {"@call": "formatString", "args": {"value": "https://example.com/${u}"}},
                    "posterUrl": {"@call": "formatString", "args": {"value": "https://example.com/${u}"}},
                }
                for k in range(498)
            ]
        )
        single_50 = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "fan_single_50",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": single_list_comps,
                    "dataModel": {"items": [{"u": "a"} for _ in range(50)]},
                },
            }
        ]
        raw_s50 = json.dumps(single_50)
        t2 = time.perf_counter()
        res_s50 = validate_payload(raw_s50, version="1.0", strict=True)
        self.assertTrue(res_s50["ok"], res_s50["errors"])
        self.assertLess(time.perf_counter() - t2, 0.5)

        single_cap = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "fan_single_cap",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": single_list_comps,
                    "dataModel": {"items": [{"u": f"a{k}"} for k in range(300)]},
                },
            }
        ]
        raw_scap = json.dumps(single_cap, separators=(",", ":"))
        t3 = time.perf_counter()
        res_scap = validate_payload(raw_scap, version="1.0", strict=True)
        self.assertFalse(res_scap["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_scap["errors"]})
        self.assertLess(time.perf_counter() - t3, 0.5)

        # 3b. Direct 499-Video fan-out (50 updates pass fast; 200 updates trip surface URL eval cap)
        direct_comps = (
            [{"id": "root", "component": "Column", "children": [f"v{k}" for k in range(499)]}]
            + [
                {
                    "id": f"v{k}",
                    "component": "Video",
                    "url": {"@call": "formatString", "args": {"value": "https://example.com/${/u}"}},
                    "posterUrl": {"@call": "formatString", "args": {"value": "https://example.com/${/u}"}},
                }
                for k in range(499)
            ]
        )
        direct_50 = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "fan_direct_50",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": direct_comps,
                    "dataModel": {"u": "a"},
                },
            }
        ] + [
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "fan_direct_50", "path": "/u", "value": f"v{k}"},
            }
            for k in range(50)
        ]
        raw_d50 = json.dumps(direct_50)
        t4 = time.perf_counter()
        res_d50 = validate_payload(raw_d50, version="1.0", strict=True)
        self.assertTrue(res_d50["ok"], res_d50["errors"])
        self.assertLess(time.perf_counter() - t4, 0.5)

        direct_cap = direct_50[:1] + [
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "fan_direct_50", "path": "/u", "value": f"v{k}"},
            }
            for k in range(200)
        ]
        raw_dcap = json.dumps(direct_cap, separators=(",", ":"))
        t5 = time.perf_counter()
        res_dcap = validate_payload(raw_dcap, version="1.0", strict=True)
        self.assertFalse(res_dcap["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_dcap["errors"]})
        self.assertLess(time.perf_counter() - t5, 0.5)

        # 4. v0.8 root-merge dataModelUpdate.contents scoped per key (unrelated key avoids full list rescan)
        v08_storm = [
            {"beginRendering": {"surfaceId": "v8_merge", "root": "root"}},
            {
                "surfaceUpdate": {
                    "surfaceId": "v8_merge",
                    "components": [
                        {
                            "id": "root",
                            "component": {
                                "List": {"children": {"template": {"componentId": "r", "dataBinding": "/items"}}}
                            },
                        },
                        {"id": "r", "component": {"Image": {"url": {"path": "u"}}}},
                    ],
                }
            },
            {
                "dataModelUpdate": {
                    "surfaceId": "v8_merge",
                    "path": "/",
                    "value": {"items": [{"u": f"https://example.com/{k}"} for k in range(10_000)]},
                }
            },
        ] + [
            {
                "dataModelUpdate": {
                    "surfaceId": "v8_merge",
                    "path": "/",
                    "contents": [{"key": "c", "valueString": f"y{k}"}],
                }
            }
            for k in range(50)
        ]
        raw_v08 = json.dumps(v08_storm, separators=(",", ":"))
        t6 = time.perf_counter()
        res_v08 = validate_payload(raw_v08, version="0.8", strict=False)
        self.assertTrue(res_v08["ok"], res_v08["errors"])
        self.assertLess(time.perf_counter() - t6, 0.5)

        # v0.8 root-merge updating the actual list key still catches unsafe URLs
        v08_bad_merge = [
            {"beginRendering": {"surfaceId": "v8_bad", "root": "root"}},
            {
                "surfaceUpdate": {
                    "surfaceId": "v8_bad",
                    "components": [
                        {
                            "id": "root",
                            "component": {
                                "List": {"children": {"template": {"componentId": "r", "dataBinding": "/items"}}}
                            },
                        },
                        {"id": "r", "component": {"Image": {"url": {"path": "u"}}}},
                    ],
                }
            },
            {
                "dataModelUpdate": {
                    "surfaceId": "v8_bad",
                    "path": "/",
                    "contents": [
                        {
                            "key": "items",
                            "valueArray": [{"valueMap": [{"key": "u", "valueString": "javascript:alert(1)"}]}],
                        }
                    ],
                }
            },
        ]
        res_v08_bad = validate_payload(json.dumps(v08_bad_merge), version="0.8", strict=False)
        self.assertFalse(res_v08_bad["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_v08_bad["errors"]})

    def test_rfc6901_tilde_pointer_aliasing_fails_closed(self) -> None:
        """Unescaped '~' and canonical '~0' JSON Pointers normalize identically across ChildLists and direct slots."""
        # 1. ChildList bound to /~0 mutated via /~/0/u fails closed
        childlist_tilde = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "tilde_list",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "row_img", "path": "/~0"}},
                        {"id": "row_img", "component": "Image", "url": {"@path": "u"}},
                    ],
                    "dataModel": {"~": [{"u": "https://example.com/ok.png"}]},
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "tilde_list",
                    "path": "/~/0/u",
                    "value": "javascript:alert(1)",
                },
            },
        ]
        res_cl = validate_payload(json.dumps(childlist_tilde), version="1.0", strict=True)
        self.assertFalse(res_cl["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_cl["errors"]})

        # 2. Direct slot bound to /~0 mutated via /~ then overwritten via /~0 fails closed
        direct_tilde = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "tilde_direct",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [{"id": "root", "component": "Image", "url": {"@path": "/~0"}}],
                    "dataModel": {"~": "https://example.com/ok.png"},
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "tilde_direct", "path": "/~", "value": "javascript:alert(1)"},
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "tilde_direct",
                    "path": "/~0",
                    "value": "https://example.com/clean.png",
                },
            },
        ]
        res_dir = validate_payload(json.dumps(direct_tilde), version="1.0", strict=True)
        self.assertFalse(res_dir["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_dir["errors"]})

        # 3. openUrl bound to /~0 inside ChildList mutated via /~/0/href fails closed with UNSAFE_OPEN_URL
        openurl_tilde = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "tilde_open",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "row_btn", "path": "/~0"}},
                        {
                            "id": "row_btn",
                            "component": "Button",
                            "child": "row_lbl",
                            "action": {
                                "functionCall": {"@call": "openUrl", "args": {"url": {"@path": "href"}}}
                            },
                        },
                        {"id": "row_lbl", "component": "Text", "text": "Go"},
                    ],
                    "dataModel": {"~": [{"href": "https://example.com/ok"}]},
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "tilde_open",
                    "path": "/~/0/href",
                    "value": "https://example.com@evil.example/phish",
                },
            },
        ]
        res_open = validate_payload(json.dumps(openurl_tilde), version="1.0", strict=True)
        self.assertFalse(res_open["ok"])
        self.assertIn("UNSAFE_OPEN_URL", {e["code"] for e in res_open["errors"]})

    def test_reparented_components_with_deferred_data_pass_while_detached_fail_closed(self) -> None:
        """Re-parenting active components with deferred data passes while detached/changed template bindings fail closed."""
        # 1. Direct component wrapped under a new Card with deferred /hero_url passes strict validation
        direct_reparent = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "rep_direct_ok",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "Column", "children": ["img_a"]},
                        {
                            "id": "img_a",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "${/hero_url}"}},
                        },
                    ],
                    "dataModel": {},
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "rep_direct_ok",
                    "components": [
                        {"id": "root", "component": "Column", "children": ["card_wrap"]},
                        {"id": "card_wrap", "component": "Card", "child": "img_a"},
                    ],
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "rep_direct_ok",
                    "path": "/hero_url",
                    "value": "https://example.com/hero.png",
                },
            },
        ]
        res_dr = validate_payload(json.dumps(direct_reparent), version="1.0", strict=True)
        self.assertTrue(res_dr["ok"], res_dr["errors"])

        # 2. Template component wrapped under a new Card with deferred /items/0/u passes strict validation
        tpl_reparent = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "rep_tpl_ok",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "mid", "path": "/items"}},
                        {"id": "mid", "component": "Column", "children": ["row_img"]},
                        {
                            "id": "row_img",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "${u}"}},
                        },
                    ],
                    "dataModel": {"items": [{}]},
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "rep_tpl_ok",
                    "components": [
                        {"id": "mid", "component": "Column", "children": ["card_wrap"]},
                        {"id": "card_wrap", "component": "Card", "child": "row_img"},
                    ],
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "rep_tpl_ok",
                    "path": "/items/0/u",
                    "value": "https://example.com/item.png",
                },
            },
        ]
        res_tr = validate_payload(json.dumps(tpl_reparent), version="1.0", strict=True)
        self.assertTrue(res_tr["ok"], res_tr["errors"])

        # 3. Rebinding ChildList to a different path while pre-batch list item was unresolved still fails closed
        rebind_lost_chain = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "rep_lost_chain",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "mid", "path": "/items_a"}},
                        {"id": "mid", "component": "Column", "children": ["row_img"]},
                        {
                            "id": "row_img",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "${u}"}},
                        },
                    ],
                    "dataModel": {"items_a": [{}], "items_b": [{"u": "https://example.com/ok.png"}]},
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "rep_lost_chain",
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "mid", "path": "/items_b"}},
                    ],
                },
            },
        ]
        res_lost = validate_payload(json.dumps(rebind_lost_chain), version="1.0", strict=True)
        self.assertFalse(res_lost["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_lost["errors"]})

    def test_payload_wide_url_budget_formatstring_complexity_and_pointer_depth_bounds(self) -> None:
        """Payload-wide URL budgets, formatString complexity/cost caps, and bounded pointer depth prevent DoS."""
        # 1a. Multi-surface warmup + fan-out shares one payload-wide budget and non-freezing cache
        surf_comps = (
            [
                {"id": "root", "component": "List", "children": {"componentId": "tpl", "path": "/items"}},
                {"id": "tpl", "component": "Column", "children": [f"v{k}" for k in range(12)]},
            ]
            + [
                {
                    "id": f"v{k}",
                    "component": "Video",
                    "url": {"@call": "formatString", "args": {"value": "https://z.co/${u}"}},
                    "posterUrl": {"@call": "formatString", "args": {"value": "https://z.co/${u}"}},
                }
                for k in range(12)
            ]
        )
        warmup_msg = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "warm",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "List", "children": {"componentId": "img", "path": "/items"}},
                    {"id": "img", "component": "Image", "url": {"@path": "u"}},
                ],
                "dataModel": {"items": [{"u": f"https://w.co/{k}"} for k in range(2050)]},
            },
        }
        multi_surf = [warmup_msg] + [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": f"s{i}",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": surf_comps,
                    "dataModel": {"items": [0] * 624},
                },
            }
            for i in range(30)
        ]
        raw_multi = json.dumps(multi_surf, separators=(",", ":"))
        t0 = time.perf_counter()
        res_multi = validate_payload(raw_multi, version="1.0", strict=True)
        dt_multi = time.perf_counter() - t0
        self.assertFalse(res_multi["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_multi["errors"]})
        self.assertLess(dt_multi, 2.5)

        # 1b. Repeated createSurface + deleteSurface cycles on the same surfaceId never reset the budget
        cycle_msgs: list[dict] = [warmup_msg]
        for _ in range(30):
            cycle_msgs.append(
                {
                    "version": "1.0",
                    "createSurface": {
                        "surfaceId": "s",
                        "catalogId": CANONICAL_V1_CATALOG_ID,
                        "components": surf_comps,
                        "dataModel": {"items": [0] * 624},
                    },
                }
            )
            cycle_msgs.append({"version": "1.0", "deleteSurface": {"surfaceId": "s"}})
        raw_cycle = json.dumps(cycle_msgs, separators=(",", ":"))
        t1 = time.perf_counter()
        res_cycle = validate_payload(raw_cycle, version="1.0", strict=True)
        dt_cycle = time.perf_counter() - t1
        self.assertFalse(res_cycle["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_cycle["errors"]})
        self.assertLess(dt_cycle, 2.5)

        # 1c. Multiple Markdown fences share the same payload-wide budget
        md_blocks = [f"```a2ui\n{json.dumps(warmup_msg, separators=(',', ':'))}\n```"] + [
            "```a2ui\n"
            + json.dumps(
                {
                    "version": "1.0",
                    "createSurface": {
                        "surfaceId": f"mb{i}",
                        "catalogId": CANONICAL_V1_CATALOG_ID,
                        "components": surf_comps,
                        "dataModel": {"items": [0] * 624},
                    },
                },
                separators=(",", ":"),
            )
            + "\n```"
            for i in range(15)
        ]
        res_md = validate_payload("\n".join(md_blocks), extract_markdown=True, version="1.0", strict=True)
        self.assertFalse(res_md["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_md["errors"]})

        # 2a. Multi-placeholder formatString exceeding 64 placeholders fails closed immediately
        many_ph = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "fmt_many",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "img", "path": "/items"}},
                        {
                            "id": "img",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "https://z.co/" + "${u}" * 4000}},
                        },
                    ],
                    "dataModel": {"items": [0] * 3000},
                },
            }
        ]
        t2 = time.perf_counter()
        res_many = validate_payload(json.dumps(many_ph, separators=(",", ":")), version="1.0", strict=True)
        dt_many = time.perf_counter() - t2
        self.assertFalse(res_many["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_many["errors"]})
        self.assertLess(dt_many, 2.5)

        # 2b. Non-data formatString exceeding 16384 chars fails closed immediately
        long_fmt = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "fmt_long",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {
                        "id": "root",
                        "component": "Image",
                        "url": {"@call": "formatString", "args": {"value": "https://z.co/" + ("a" * 16_500) + "${/u}"}},
                    }
                ],
                "dataModel": {"u": "ok"},
            },
        }
        res_long = validate_payload(json.dumps(long_fmt), version="1.0", strict=True)
        self.assertFalse(res_long["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_long["errors"]})

        # 2c. 64-placeholder formatString charges proportional cost per item and trips payload budget fast
        boundary_ph = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "fmt_64",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "img", "path": "/items"}},
                        {
                            "id": "img",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "https://z.co/" + "${u}" * 64}},
                        },
                    ],
                    "dataModel": {"items": [0] * 5000},
                },
            }
        ]
        t3 = time.perf_counter()
        res_b64 = validate_payload(json.dumps(boundary_ph, separators=(",", ":")), version="1.0", strict=True)
        dt_b64 = time.perf_counter() - t3
        self.assertFalse(res_b64["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_b64["errors"]})
        self.assertLess(dt_b64, 2.5)

        # 3. Deep JSON Pointer (25k and 500k segments) stays bounded in time and memory
        deep_ptr = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "deep_ptr",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [{"id": "root", "component": "Image", "url": {"@path": "/x"}}],
                    "dataModel": {"x": "https://example.com/ok.png"},
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "deep_ptr", "path": "/a" * 25_000, "value": None},
            },
        ]
        t4 = time.perf_counter()
        res_deep = validate_payload(json.dumps(deep_ptr, separators=(",", ":")), version="1.0", strict=True)
        dt_deep = time.perf_counter() - t4
        self.assertTrue(res_deep["ok"], res_deep["errors"])
        self.assertLess(dt_deep, 2.5)

    def test_v08_vs_v10_literalstring_media_url_validation_and_normalization(self) -> None:
        """v0.8 literalString+path validates both seed and bound path; v1.0 rejects legacy literalString wrappers."""
        # 1. v0.8 Image.url with safe literalString and unsafe bound /evil fails closed in non-strict and strict modes
        v08_evil_path = json.dumps(
            [
                {"beginRendering": {"surfaceId": "s8_evil", "root": "root"}},
                {
                    "surfaceUpdate": {
                        "surfaceId": "s8_evil",
                        "components": [
                            {
                                "id": "root",
                                "component": {
                                    "Image": {
                                        "url": {
                                            "literalString": "https://example.com/placeholder.png",
                                            "path": "/evil",
                                        }
                                    }
                                },
                            }
                        ],
                    }
                },
                {
                    "dataModelUpdate": {
                        "surfaceId": "s8_evil",
                        "path": "/",
                        "contents": [{"key": "evil", "valueString": "javascript:alert(1)"}],
                    }
                },
            ]
        )
        for strict_mode in (False, True):
            res_v8 = validate_payload(v08_evil_path, version="0.8", strict=strict_mode)
            self.assertFalse(res_v8["ok"])
            self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_v8["errors"]})

        # 2. v0.8 template child with literalString + relative path catches unsafe item URL via streaming update
        v08_tpl_evil = json.dumps(
            [
                {"beginRendering": {"surfaceId": "s8_tpl", "root": "root"}},
                {
                    "surfaceUpdate": {
                        "surfaceId": "s8_tpl",
                        "components": [
                            {
                                "id": "root",
                                "component": {
                                    "List": {"children": {"template": {"componentId": "row", "dataBinding": "/items"}}}
                                },
                            },
                            {
                                "id": "row",
                                "component": {
                                    "Image": {
                                        "url": {
                                            "literalString": "https://example.com/placeholder.png",
                                            "path": "u",
                                        }
                                    }
                                },
                            },
                        ],
                    }
                },
                {
                    "dataModelUpdate": {
                        "surfaceId": "s8_tpl",
                        "path": "/",
                        "contents": [
                            {
                                "key": "items",
                                "valueArray": [{"valueMap": [{"key": "u", "valueString": "javascript:alert(1)"}]}],
                            }
                        ],
                    }
                },
            ]
        )
        res_v8_tpl = validate_payload(v08_tpl_evil, version="0.8", strict=False)
        self.assertFalse(res_v8_tpl["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_v8_tpl["errors"]})

        # 3. v0.8 valid literalString + safe bound path passes validate and normalize
        v08_both_safe = json.dumps(
            [
                {"beginRendering": {"surfaceId": "s8_ok", "root": "root"}},
                {
                    "surfaceUpdate": {
                        "surfaceId": "s8_ok",
                        "components": [
                            {
                                "id": "root",
                                "component": {
                                    "Image": {
                                        "url": {
                                            "literalString": "https://example.com/placeholder.png",
                                            "path": "/live",
                                        }
                                    }
                                },
                            }
                        ],
                    }
                },
                {
                    "dataModelUpdate": {
                        "surfaceId": "s8_ok",
                        "path": "/",
                        "contents": [{"key": "live", "valueString": "https://example.com/live.png"}],
                    }
                },
            ]
        )
        self.assertTrue(validate_payload(v08_both_safe, version="0.8", strict=False)["ok"])
        self.assertTrue(normalize_payload(v08_both_safe)["ok"])

        # 4. v0.8 empty dict or unknown keys on media URL fail closed
        for bad_url in ({}, {"literalString": "https://example.com/ok.png", "extra": 1}, {"literalString": "https://example.com/ok.png", "path": ""}):
            v08_bad_shape = json.dumps(
                [
                    {"beginRendering": {"surfaceId": "s8_bad", "root": "root"}},
                    {
                        "surfaceUpdate": {
                            "surfaceId": "s8_bad",
                            "components": [{"id": "root", "component": {"Image": {"url": bad_url}}}],
                        }
                    },
                ]
            )
            res_bs = validate_payload(v08_bad_shape, version="0.8", strict=False)
            self.assertFalse(res_bs["ok"])
            self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_bs["errors"]})

        # 5. v1.0 refuses legacy literalString wrapper (with or without path) in strict and non-strict modes
        for legacy_url in (
            {"literalString": "https://example.com/ok.png", "path": "/evil"},
            {"literalString": "https://example.com/ok.png"},
        ):
            v10_legacy = json.dumps(
                {
                    "version": "1.0",
                    "createSurface": {
                        "surfaceId": "s10_leg",
                        "catalogId": CANONICAL_V1_CATALOG_ID,
                        "components": [{"id": "root", "component": "Image", "url": legacy_url}],
                        "dataModel": {"evil": "javascript:alert(1)"},
                    },
                }
            )
            res_v10 = validate_payload(v10_legacy, version="1.0", strict=True)
            self.assertFalse(res_v10["ok"])
            self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_v10["errors"]})

        # 6. normalize_payload and render_preview_html fail closed on unsafe v0.8 literalString seed even with safe path
        from legends_a2ui.preview_html import render_preview_html

        v08_unsafe_seed = json.dumps(
            [
                {"beginRendering": {"surfaceId": "s8_seed", "root": "root"}},
                {
                    "surfaceUpdate": {
                        "surfaceId": "s8_seed",
                        "components": [
                            {
                                "id": "root",
                                "component": {
                                    "Image": {
                                        "url": {
                                            "literalString": "javascript:alert(1)",
                                            "path": "/safe",
                                        }
                                    }
                                },
                            }
                        ],
                    }
                },
                {
                    "dataModelUpdate": {
                        "surfaceId": "s8_seed",
                        "path": "/",
                        "contents": [{"key": "safe", "valueString": "https://example.com/ok.png"}],
                    }
                },
            ]
        )
        res_norm = normalize_payload(v08_unsafe_seed)
        self.assertFalse(res_norm["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_norm["validation"]["errors"]})

        res_prev = render_preview_html(v08_unsafe_seed)
        self.assertFalse(res_prev["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_prev["validation"]["errors"]})

    def test_interpolated_url_length_cap_container_rejection_and_cache_bounds(self) -> None:
        import time
        from legends_a2ui.spec_registry import _MAX_DATA_MEDIA_URL_LEN
        from legends_a2ui.validator import (
            _SAFE_URL_CACHE_MAX_CHARS,
            _SAFE_URL_CACHE_MAX_ITEM_LEN,
            _BoundedUrlCache,
            _cache_safe_url,
        )

        # 1. Bounded URL cache enforces cumulative character budget and max item length
        cache = _BoundedUrlCache()
        short_url = "https://example.com/" + ("a" * 100)
        medium_data_url = "data:image/png;base64," + ("A" * (_SAFE_URL_CACHE_MAX_ITEM_LEN + 100))
        oversize_url = "data:image/png;base64," + ("A" * (_MAX_DATA_MEDIA_URL_LEN + 10))
        _cache_safe_url(cache, short_url)
        _cache_safe_url(cache, medium_data_url)
        _cache_safe_url(cache, oversize_url)
        self.assertIn(short_url, cache)
        self.assertIn(medium_data_url, cache)
        self.assertNotIn(oversize_url, cache)
        self.assertLessEqual(cache.chars, _SAFE_URL_CACHE_MAX_CHARS)

        # 2. Multi-placeholder formatString referencing a large string fails closed before join
        multi_amp = json.dumps(
            [
                {
                    "version": "1.0",
                    "createSurface": {
                        "surfaceId": "s_amp_multi",
                        "catalogId": CANONICAL_V1_CATALOG_ID,
                        "components": [
                            {"id": "root", "component": "List", "children": {"componentId": "img", "path": "/items"}},
                            {
                                "id": "img",
                                "component": "Image",
                                "url": {
                                    "@call": "formatString",
                                    "args": {"value": "https://example.com/" + ("${/b}" * 63) + "/${u}"},
                                },
                            },
                        ],
                        "dataModel": {"b": "a" * 500_000, "items": [{"u": k} for k in range(5)]},
                    },
                }
            ],
            separators=(",", ":"),
        )
        t0 = time.perf_counter()
        res_amp = validate_payload(multi_amp, version="1.0", strict=True)
        elapsed_amp = time.perf_counter() - t0
        self.assertFalse(res_amp["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_amp["errors"]})
        self.assertLess(elapsed_amp, 2.5)

        # 3. 2-placeholder formatString exceeding 16,384 chars fails closed quickly
        two_ph_amp = json.dumps(
            [
                {
                    "version": "1.0",
                    "createSurface": {
                        "surfaceId": "s_amp_two",
                        "catalogId": CANONICAL_V1_CATALOG_ID,
                        "components": [
                            {"id": "root", "component": "List", "children": {"componentId": "img", "path": "/items"}},
                            {
                                "id": "img",
                                "component": "Image",
                                "url": {
                                    "@call": "formatString",
                                    "args": {"value": "https://example.com/${/b}/${u}"},
                                },
                            },
                        ],
                        "dataModel": {"b": "a" * 500_000, "items": [{"u": k} for k in range(50)]},
                    },
                }
            ],
            separators=(",", ":"),
        )
        t0 = time.perf_counter()
        res_two = validate_payload(two_ph_amp, version="1.0", strict=True)
        elapsed_two = time.perf_counter() - t0
        self.assertFalse(res_two["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_two["errors"]})
        self.assertLess(elapsed_two, 2.5)

        # 4. Non-scalar dict/list container placeholders fail closed without str(container) serialization
        dict_msgs: list[dict[str, Any]] = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_dict_ph",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "Column", "children": ["img", "btn"]},
                        {
                            "id": "img",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "https://example.com/${/b}"}},
                        },
                        {
                            "id": "btn",
                            "component": "Button",
                            "child": "lbl",
                            "action": {
                                "functionCall": {
                                    "@call": "openUrl",
                                    "args": {
                                        "url": {
                                            "@call": "formatString",
                                            "args": {"value": "https://example.com/${/arr}"},
                                        }
                                    },
                                }
                            },
                        },
                        {"id": "lbl", "component": "Text", "text": "Open"},
                    ],
                    "dataModel": {"b": {"pad": "a" * 500_000, "flag": 0}, "arr": ["x", "y"]},
                },
            }
        ]
        for idx in range(1, 11):
            dict_msgs.append(
                {
                    "version": "1.0",
                    "updateDataModel": {"surfaceId": "s_dict_ph", "path": "/b/flag", "value": idx},
                }
            )
        t0 = time.perf_counter()
        res_dict = validate_payload(json.dumps(dict_msgs, separators=(",", ":")), version="1.0", strict=True)
        elapsed_dict = time.perf_counter() - t0
        self.assertFalse(res_dict["ok"])
        err_codes = {e["code"] for e in res_dict["errors"]}
        self.assertIn("UNSAFE_MEDIA_URL", err_codes)
        self.assertIn("UNSAFE_OPEN_URL", err_codes)
        self.assertLess(elapsed_dict, 2.5)

        # 5. data: formatString media template allows up to 262,144 chars and refuses > 262,144 chars
        data_ok = json.dumps(
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_data_ok",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {
                            "id": "root",
                            "component": "Image",
                            "url": {
                                "@call": "formatString",
                                "args": {"value": "data:image/png;base64,${/chunk}"},
                            },
                        }
                    ],
                    "dataModel": {"chunk": "A" * 20_000},
                },
            }
        )
        self.assertTrue(validate_payload(data_ok, version="1.0", strict=True)["ok"])

        data_too_big = json.dumps(
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_data_big",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {
                            "id": "root",
                            "component": "Image",
                            "url": {
                                "@call": "formatString",
                                "args": {"value": "data:image/png;base64,${/chunk}"},
                            },
                        }
                    ],
                    "dataModel": {"chunk": "A" * 270_000},
                },
            }
        )
        res_data_big = validate_payload(data_too_big, version="1.0", strict=True)
        self.assertFalse(res_data_big["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_data_big["errors"]})

        # 6. openUrl formatString rejects interpolated URL > 16,384 chars
        open_too_big = json.dumps(
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_open_big",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {
                            "id": "root",
                            "component": "Button",
                            "child": "lbl",
                            "action": {
                                "functionCall": {
                                    "@call": "openUrl",
                                    "args": {
                                        "url": {
                                            "@call": "formatString",
                                            "args": {"value": "https://example.com/${/seg}"},
                                        }
                                    },
                                }
                            },
                        },
                        {"id": "lbl", "component": "Text", "text": "Go"},
                    ],
                    "dataModel": {"seg": "a" * 16_400},
                },
            }
        )
        res_open_big = validate_payload(open_too_big, version="1.0", strict=True)
        self.assertFalse(res_open_big["ok"])
        self.assertIn("UNSAFE_OPEN_URL", {e["code"] for e in res_open_big["errors"]})

    def test_data_model_mutation_depth_limits_and_overdeep_url_pointers(self) -> None:
        from legends_a2ui.preview_html import render_preview_html

        # 1. Deep updateDataModel graft (ptr_depth + val_depth > max_depth) + over-deep URL pointers fail closed
        deep_graft = json.dumps(
            [
                {
                    "version": "1.0",
                    "createSurface": {
                        "surfaceId": "s_deep_graft",
                        "catalogId": CANONICAL_V1_CATALOG_ID,
                        "components": [
                            {"id": "root", "component": "Column", "children": ["img1", "btn1", "img2"]},
                            {"id": "img1", "component": "Image", "url": {"@path": ("/a" * 68) + "/x"}},
                            {
                                "id": "btn1",
                                "component": "Button",
                                "child": "lbl1",
                                "action": {
                                    "functionCall": {
                                        "@call": "openUrl",
                                        "args": {"url": {"@path": ("/a" * 68) + "/x"}},
                                    }
                                },
                            },
                            {
                                "id": "img2",
                                "component": "Image",
                                "url": {
                                    "@call": "formatString",
                                    "args": {"value": "https://example.com${" + ("/a" * 68) + "/spoof}"},
                                },
                            },
                            {"id": "lbl1", "component": "Text", "text": "Go"},
                        ],
                    },
                },
                {
                    "version": "1.0",
                    "updateDataModel": {
                        "surfaceId": "s_deep_graft",
                        "path": "/a" * 68,
                        "value": {"x": "javascript:alert(1)", "spoof": "@evil.example/x.png"},
                    },
                },
            ],
            separators=(",", ":"),
        )
        res_val = validate_payload(deep_graft, version="1.0", strict=True)
        self.assertFalse(res_val["ok"])
        val_codes = {e["code"] for e in res_val["errors"]}
        self.assertIn("MAX_DEPTH_EXCEEDED", val_codes)
        self.assertIn("UNSAFE_MEDIA_URL", val_codes)
        self.assertIn("UNSAFE_OPEN_URL", val_codes)

        res_norm = normalize_payload(deep_graft)
        self.assertFalse(res_norm["ok"])
        self.assertIn("MAX_DEPTH_EXCEEDED", {e["code"] for e in res_norm["validation"]["errors"]})

        res_prev = render_preview_html(deep_graft)
        self.assertFalse(res_prev["ok"])
        self.assertIn("MAX_DEPTH_EXCEEDED", {e["code"] for e in res_prev["validation"]["errors"]})

        # 2. Boundary: ptr_depth 64 + dict val_depth 1 = 65 > 64 fails; ptr_depth 63 + dict val_depth 1 = 64 resolves & validates
        at_65 = json.dumps(
            [
                {
                    "version": "1.0",
                    "createSurface": {
                        "surfaceId": "s_b65",
                        "catalogId": CANONICAL_V1_CATALOG_ID,
                        "components": [{"id": "root", "component": "Text", "text": "ok"}],
                    },
                },
                {
                    "version": "1.0",
                    "updateDataModel": {
                        "surfaceId": "s_b65",
                        "path": "/a" * 64,
                        "value": {"x": "https://example.com/ok.png"},
                    },
                },
            ]
        )
        res_65 = validate_payload(at_65, version="1.0", strict=True)
        self.assertFalse(res_65["ok"])
        self.assertIn("MAX_DEPTH_EXCEEDED", {e["code"] for e in res_65["errors"]})

        at_64_evil = json.dumps(
            [
                {
                    "version": "1.0",
                    "createSurface": {
                        "surfaceId": "s_b64",
                        "catalogId": CANONICAL_V1_CATALOG_ID,
                        "components": [
                            {"id": "root", "component": "Image", "url": {"@path": ("/a" * 63) + "/x"}},
                        ],
                    },
                },
                {
                    "version": "1.0",
                    "updateDataModel": {
                        "surfaceId": "s_b64",
                        "path": "/a" * 63,
                        "value": {"x": "javascript:alert(1)"},
                    },
                },
            ]
        )
        res_64_evil = validate_payload(at_64_evil, version="1.0", strict=True)
        self.assertFalse(res_64_evil["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_64_evil["errors"]})

        # 3. v0.8 dataModelUpdate deep contents graft also fails closed with MAX_DEPTH_EXCEEDED
        v08_deep = json.dumps(
            [
                {"beginRendering": {"surfaceId": "s8_deep", "root": "root"}},
                {
                    "surfaceUpdate": {
                        "surfaceId": "s8_deep",
                        "components": [{"id": "root", "component": {"Text": {"text": {"literalString": "hi"}}}}],
                    }
                },
                {
                    "dataModelUpdate": {
                        "surfaceId": "s8_deep",
                        "path": "/a" * 64,
                        "contents": [{"key": "x", "valueString": "javascript:alert(1)"}],
                    }
                },
            ]
        )
        res_v08_deep = validate_payload(v08_deep, version="0.8", strict=False)
        self.assertFalse(res_v08_deep["ok"])
        self.assertIn("MAX_DEPTH_EXCEEDED", {e["code"] for e in res_v08_deep["errors"]})

        # 4. Deep null deletion remains a fast ok: True no-op
        deep_del = json.dumps(
            [
                {
                    "version": "1.0",
                    "createSurface": {
                        "surfaceId": "s_deep_del",
                        "catalogId": CANONICAL_V1_CATALOG_ID,
                        "components": [{"id": "root", "component": "Text", "text": "ok"}],
                    },
                },
                {
                    "version": "1.0",
                    "updateDataModel": {
                        "surfaceId": "s_deep_del",
                        "path": "/a" * 25_000,
                        "value": None,
                    },
                },
            ]
        )
        res_del = validate_payload(deep_del, version="1.0", strict=True)
        self.assertTrue(res_del["ok"], res_del["errors"])

        # 5. Over-deep relative pointer inside ChildList template fails closed with UNSAFE_MEDIA_URL
        rel_deep = json.dumps(
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_rel_deep",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "img", "path": "/items"}},
                        {"id": "img", "component": "Image", "url": {"@path": ("a/" * 68) + "u"}},
                    ],
                    "dataModel": {"items": [{"u": "https://example.com/a.png"}]},
                },
            }
        )
        res_rel = validate_payload(rel_deep, version="1.0", strict=True)
        self.assertFalse(res_rel["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_rel["errors"]})

    def test_bounded_url_cache_kilobyte_budget_and_streaming_rescan_skips(self) -> None:
        import time
        from legends_a2ui.spec_registry import _MAX_DATA_MEDIA_URL_LEN
        from legends_a2ui.validator import (
            _SAFE_URL_CACHE_MAX_CHARS,
            _BoundedUrlCache,
            _mutate_json_pointer,
        )

        # 1. _BoundedUrlCache enforces cumulative 4 MiB char budget and resets cleanly on overflow
        cache = _BoundedUrlCache()
        urls_800k = [f"data:image/png;base64,{idx}" + ("A" * 800_000) for idx in range(6)]
        for u in urls_800k[:5]:
            cache.add(u)
        self.assertEqual(len(cache), 5)
        self.assertLessEqual(cache.chars, _SAFE_URL_CACHE_MAX_CHARS)
        # 6th 800 KB entry exceeds 4 MiB cumulative cap and resets the cache cleanly
        cache.add(urls_800k[5])
        self.assertEqual(len(cache), 1)
        self.assertIn(urls_800k[5], cache)
        self.assertNotIn(urls_800k[0], cache)
        self.assertEqual(cache.chars, len(urls_800k[5]))
        # Entries above _MAX_DATA_MEDIA_URL_LEN are never inserted
        cache.add("data:image/png;base64," + ("A" * (_MAX_DATA_MEDIA_URL_LEN + 1)))
        self.assertEqual(len(cache), 1)

        # 2. _mutate_json_pointer reports changed=False on genuine no-ops and True on real mutations
        dm_mut: dict[str, Any] = {"img": "data:image/png;base64,AA", "arr": ["x"]}
        _, _, ch_scalar_del = _mutate_json_pointer(dm_mut, "/img/a", None)
        self.assertFalse(ch_scalar_del)
        _, _, ch_missing_del = _mutate_json_pointer(dm_mut, "/missing", None)
        self.assertFalse(ch_missing_del)
        _, _, ch_oob_del = _mutate_json_pointer(dm_mut, "/arr/5", None)
        self.assertFalse(ch_oob_del)
        _, _, ch_oob_set = _mutate_json_pointer(dm_mut, "/arr/5", "y")
        self.assertFalse(ch_oob_set)
        _, _, ch_deep_del = _mutate_json_pointer(dm_mut, "/a" * 100, None)
        self.assertFalse(ch_deep_del)
        _, _, ch_real_set = _mutate_json_pointer(dm_mut, "/arr/1", "y")
        self.assertTrue(ch_real_set)
        _, popped, ch_real_del = _mutate_json_pointer(dm_mut, "/arr/0", None)
        self.assertTrue(ch_real_del)
        self.assertEqual(popped, 0)

        # 3. Valid 800 KB data: media URL with ChildList relative @path and sibling updates passes fast
        valid_data_url = "data:image/png;base64," + ("A" * 800_000)
        comps_rel = [
            {"id": "root", "component": "List", "children": {"componentId": "row", "path": "/items"}},
            {"id": "row", "component": "Column", "children": [f"i{k}" for k in range(498)]},
        ] + [{"id": f"i{k}", "component": "Image", "url": {"@path": "u"}} for k in range(498)]
        msgs_rel = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_rel_data",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_rel,
                    "dataModel": {"items": [{"u": valid_data_url, "n": 0}]},
                },
            }
        ] + [
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_rel_data", "path": "/items/0/n", "value": i}}
            for i in range(1, 60)
        ]
        raw_rel = json.dumps(msgs_rel, separators=(",", ":"))
        t0 = time.perf_counter()
        res_rel_ok = validate_payload(raw_rel, version="1.0", strict=True)
        dt_rel = time.perf_counter() - t0
        self.assertTrue(res_rel_ok["ok"], res_rel_ok["errors"])
        self.assertLess(dt_rel, 2.5)

        # 4. Self-item absolute+relative overlap inside ChildList is still caught when sibling field mutates
        self_overlap = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_self_ov",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "row_img", "path": "/items"}},
                        {
                            "id": "row_img",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "/${/items/0/n}${u}"}},
                        },
                    ],
                    "dataModel": {"items": [{"n": "safe", "u": "/evil.example/x.png"}]},
                },
            },
            {
                "version": "1.0",
                "updateDataModel": {"surfaceId": "s_self_ov", "path": "/items/0/n", "value": ""},
            },
        ]
        res_self_ov = validate_payload(json.dumps(self_overlap), version="1.0", strict=True)
        self.assertFalse(res_self_ov["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_self_ov["errors"]})

        # 5. Valid 800 KB data: media URL with direct @path and 2,500 no-op descendant deletes passes fast
        comps_dir = [{"id": "root", "component": "Column", "children": [f"i{k}" for k in range(499)]}] + [
            {"id": f"i{k}", "component": "Image", "url": {"@path": "/img"}} for k in range(499)
        ]
        msgs_dir = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_dir,
                    "dataModel": {"img": valid_data_url},
                },
            }
        ] + [
            {"version": "1.0", "updateDataModel": {"surfaceId": "s", "path": "/img/a", "value": None}}
            for _ in range(2500)
        ]
        raw_dir = json.dumps(msgs_dir, separators=(",", ":"))
        t1 = time.perf_counter()
        res_dir_ok = validate_payload(raw_dir, version="1.0", strict=True)
        dt_dir = time.perf_counter() - t1
        self.assertTrue(res_dir_ok["ok"], res_dir_ok["errors"])
        self.assertLess(dt_dir, 2.5)

        # 6. Unsafe 800 KB data: media URL with trailing NUL fails closed fast under KB budget
        unsafe_data_url = valid_data_url + "\x00"
        msgs_unsafe_rel = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_unsafe_rel",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_rel,
                    "dataModel": {"items": [{"u": unsafe_data_url, "n": 0}]},
                },
            }
        ] + [
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_unsafe_rel", "path": "/items/0/n", "value": i}}
            for i in range(1, 60)
        ]
        t2 = time.perf_counter()
        res_unsafe_rel = validate_payload(json.dumps(msgs_unsafe_rel, separators=(",", ":")), version="1.0", strict=True)
        dt_unsafe_rel = time.perf_counter() - t2
        self.assertFalse(res_unsafe_rel["ok"])
        unsafe_codes = {e["code"] for e in res_unsafe_rel["errors"]}
        self.assertIn("UNSAFE_MEDIA_URL", unsafe_codes)
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", unsafe_codes)
        self.assertLess(dt_unsafe_rel, 2.5)

        # 7. Distinct unsafe data: URLs mutated directly across 499 Images fail closed fast under KB budget
        msgs_unsafe_dir = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_unsafe_dir",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_dir,
                    "dataModel": {"img": "data:image/png;base64," + ("A" * 60_000) + "\x00"},
                },
            }
        ] + [
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "s_unsafe_dir",
                    "path": "/img",
                    "value": f"data:image/png;base64,{idx}" + ("B" * 60_000) + "\x00",
                },
            }
            for idx in range(10)
        ]
        t3 = time.perf_counter()
        res_unsafe_dir = validate_payload(json.dumps(msgs_unsafe_dir, separators=(",", ":")), version="1.0", strict=True)
        dt_unsafe_dir = time.perf_counter() - t3
        self.assertFalse(res_unsafe_dir["ok"])
        dir_codes = {e["code"] for e in res_unsafe_dir["errors"]}
        self.assertIn("UNSAFE_MEDIA_URL", dir_codes)
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", dir_codes)
        self.assertLess(dt_unsafe_dir, 2.5)

        # 8. Static formatString media URL charges KB budget on cache miss
        static_fmt_comps = [{"id": "root", "component": "Column", "children": [f"i{k}" for k in range(250)]}] + [
            {
                "id": f"i{k}",
                "component": "Image",
                "url": {
                    "@call": "formatString",
                    "args": {"value": f"data:image/svg+xml,{k}," + ("A" * 2_000)},
                },
            }
            for k in range(250)
        ]
        static_fmt_payload = json.dumps(
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_static_fmt",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": static_fmt_comps,
                },
            },
            separators=(",", ":"),
        )
        t4 = time.perf_counter()
        res_sfmt = validate_payload(static_fmt_payload, version="1.0", strict=True)
        dt_sfmt = time.perf_counter() - t4
        self.assertFalse(res_sfmt["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_sfmt["errors"]})
        self.assertLess(dt_sfmt, 2.5)

    def test_indexed_childlist_prefix_buckets_tilde_fastpath_and_template_lru_cap(self) -> None:
        """Indexed ChildList/prefix lookups, bisect pop filtering, tilde canonicalization, and LRU length cap."""
        from legends_a2ui.validator import (
            _PrefixBucket,
            _canonicalize_json_pointer,
            _parse_format_string_template,
            _parse_format_string_template_cached,
        )

        # 1. _canonicalize_json_pointer fast-path preserves canonical escapes and normalizes raw tildes
        for canon in ("", "/", "/a/b", "/~0a/~1b", "/~01/~10/~0~1"):
            self.assertEqual(_canonicalize_json_pointer(canon), canon)
        self.assertEqual(_canonicalize_json_pointer("/~a"), "/~0a")
        self.assertEqual(_canonicalize_json_pointer("/~~1"), "/~0~1")
        self.assertEqual(_canonicalize_json_pointer("/trail~"), "/trail~0")
        self.assertEqual(_canonicalize_json_pointer("~rel"), "~0rel")

        # 2. _PrefixBucket tracks max numeric child index per item and promotes non-indexed items
        bucket = _PrefixBucket()
        bucket.add("a", "slot_a", 0)
        bucket.add("a", "slot_a", 5)  # max index becomes 5
        bucket.add("b", "slot_b", 2)
        bucket.add("c", "slot_c", 3)
        bucket.add("c", "slot_c", None)  # promoted to non-indexed
        self.assertEqual(set(bucket.query(None)), {"slot_a", "slot_b", "slot_c"})
        self.assertEqual(set(bucket.query(0)), {"slot_a", "slot_b", "slot_c"})
        self.assertEqual(set(bucket.query(3)), {"slot_a", "slot_c"})
        self.assertEqual(set(bucket.query(5)), {"slot_a", "slot_c"})
        self.assertEqual(set(bucket.query(6)), {"slot_c"})

        # 3. Single-item sibling updates with tilde-escaped absolute pointers on 498 Videos stay fast
        tpl_tilde = "https://a.co/" + "".join(f"${{/~0{j}}}" for j in range(63)) + "${u}"
        comps_a = [
            {"id": "root", "component": "List", "children": {"componentId": "row", "path": "/items"}},
            {"id": "row", "component": "Column", "children": [f"v{k}" for k in range(498)]},
        ] + [
            {
                "id": f"v{k}",
                "component": "Video",
                "url": {"@call": "formatString", "args": {"value": tpl_tilde}},
                "posterUrl": {"@call": "formatString", "args": {"value": tpl_tilde}},
            }
            for k in range(498)
        ]
        msgs_a = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_idx_a",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_a,
                    "dataModel": {"items": [{"u": "x"}]},
                },
            }
        ] + [
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_idx_a", "path": "/items/0/~0n", "value": i}}
            for i in range(1000)
        ]
        t0 = time.perf_counter()
        res_a = validate_payload(json.dumps(msgs_a, separators=(",", ":")), version="1.0", strict=True)
        dt_a = time.perf_counter() - t0
        self.assertTrue(res_a["ok"], res_a["errors"])
        self.assertLess(dt_a, 2.5)

        # 4. Multi-List templates with unrelated tilde updates and v0.8 root merges stay fast
        comps_b = (
            [{"id": "root", "component": "Column", "children": [f"l{k}" for k in range(166)]}]
            + [{"id": f"l{k}", "component": "List", "children": {"componentId": "row", "path": f"/a{k}"}} for k in range(166)]
            + [{"id": "row", "component": "Column", "children": [f"v{k}" for k in range(332)]}]
            + [
                {
                    "id": f"v{k}",
                    "component": "Video",
                    "url": {"@call": "formatString", "args": {"value": tpl_tilde}},
                    "posterUrl": {"@call": "formatString", "args": {"value": tpl_tilde}},
                }
                for k in range(332)
            ]
        )
        msgs_b = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_idx_b",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_b,
                    "dataModel": {},
                },
            }
        ] + [
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_idx_b", "path": "/~0z", "value": i}}
            for i in range(2000)
        ]
        t1 = time.perf_counter()
        res_b = validate_payload(json.dumps(msgs_b, separators=(",", ":")), version="1.0", strict=True)
        dt_b = time.perf_counter() - t1
        self.assertTrue(res_b["ok"], res_b["errors"])
        self.assertLess(dt_b, 2.5)

        # 5. Direct prefix_map bisect skips unshifted array tail pops on 250 Videos fast
        tpl_arr = "https://a.co/" + "".join(f"${{/arr/0/~0{j}}}" for j in range(64))
        comps_c = [{"id": "root", "component": "Column", "children": [f"v{k}" for k in range(250)]}] + [
            {
                "id": f"v{k}",
                "component": "Video",
                "url": {"@call": "formatString", "args": {"value": tpl_arr}},
                "posterUrl": {"@call": "formatString", "args": {"value": tpl_arr}},
            }
            for k in range(250)
        ]
        msgs_c = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_idx_c",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_c,
                    "dataModel": {"arr": [0] * 2005},
                },
            }
        ] + [
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_idx_c", "path": f"/arr/{2004 - i}", "value": None}}
            for i in range(2000)
        ]
        t2 = time.perf_counter()
        res_c = validate_payload(json.dumps(msgs_c, separators=(",", ":")), version="1.0", strict=True)
        dt_c = time.perf_counter() - t2
        self.assertTrue(res_c["ok"], res_c["errors"])
        self.assertLess(dt_c, 2.5)

        # 6. Shifted pop hitting higher index of a multi-pointer direct slot STILL fails closed
        shifted_multi = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_shift_multi",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {
                            "id": "root",
                            "component": "Image",
                            "url": {
                                "@call": "formatString",
                                "args": {"value": "https://example.com${/arr/0/a}${/arr/2/b}"},
                            },
                        }
                    ],
                    "dataModel": {
                        "arr": [
                            {"a": ""},
                            {"b": "/safe.png"},
                            {"b": "/good.png"},
                            {"b": "@evil.example/x"},
                        ]
                    },
                },
            },
            # Popping /arr/1 shifts /arr/3 into /arr/2; max_cidx=2 >= 1 must trigger re-validation
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_shift_multi", "path": "/arr/1", "value": None}},
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_shift_multi", "path": "/arr/2/b", "value": "/clean.png"}},
        ]
        res_sm = validate_payload(json.dumps(shifted_multi), version="1.0", strict=True)
        self.assertFalse(res_sm["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_sm["errors"]})

        # 7. Cross-item absolute overlap inside nested relative ChildList and raw tilde updates STILL fail closed
        nested_abs_tilde = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_nest_abs",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "grp", "path": "/groups"}},
                        {"id": "grp", "component": "List", "children": {"componentId": "row_img", "path": "items"}},
                        {
                            "id": "row_img",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "/${/~0pfx}${u}"}},
                        },
                    ],
                    "dataModel": {
                        "~pfx": "safe",
                        "groups": [
                            {"items": [{"u": "ok.png"}]},
                            {"items": [{"u": "/evil.example/p.png"}]},
                        ],
                    },
                },
            },
            # Update via raw unescaped tilde '/~pfx' must canonicalize to '/~0pfx' and catch the overlap
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_nest_abs", "path": "/~pfx", "value": ""}},
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_nest_abs", "path": "/~0pfx", "value": "safe"}},
        ]
        res_nat = validate_payload(json.dumps(nested_abs_tilde), version="1.0", strict=True)
        self.assertFalse(res_nat["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_nat["errors"]})

        # 8. Item-internal array pop shifting a relative ChildList slot STILL fails closed
        item_arr_pop = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_item_pop",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "r", "path": "/items"}},
                        {"id": "r", "component": "Image", "url": {"@path": "tags/1"}},
                    ],
                    "dataModel": {"items": [{"tags": ["/a.png", "/b.png", "javascript:alert(1)"]}]},
                },
            },
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_item_pop", "path": "/items/0/tags/0", "value": None}},
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_item_pop", "path": "/items/0/tags/1", "value": "/safe.png"}},
        ]
        res_iap = validate_payload(json.dumps(item_arr_pop), version="1.0", strict=True)
        self.assertFalse(res_iap["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_iap["errors"]})

        # 9. _parse_format_string_template memoizes short templates and never pins >2048-char templates
        _parse_format_string_template_cached.cache_clear()
        short_tpl = "https://example.com/${/id}.png"
        _parse_format_string_template(short_tpl)
        _parse_format_string_template(short_tpl)
        info_short = _parse_format_string_template_cached.cache_info()
        self.assertEqual(info_short.currsize, 1)
        self.assertGreaterEqual(info_short.hits, 1)

        for idx in range(20):
            big_tpl = f"data:image/png;base64,{idx:04d}" + ("A" * 250_000) + "${u}"
            big_payload = json.dumps(
                {
                    "version": "1.0",
                    "createSurface": {
                        "surfaceId": f"s_lru_{idx}",
                        "catalogId": CANONICAL_V1_CATALOG_ID,
                        "components": [
                            {
                                "id": "root",
                                "component": "Image",
                                "url": {"@call": "formatString", "args": {"value": big_tpl}},
                            }
                        ],
                        "dataModel": {},
                    },
                },
                separators=(",", ":"),
            )
            validate_payload(big_payload, version="1.0", strict=True)
        info_after = _parse_format_string_template_cached.cache_info()
        self.assertEqual(info_after.currsize, 1)

    def test_empty_root_key_pops_deep_template_budget_and_nested_relative_index(self) -> None:
        """Empty-key array pops, deep template pointer budgeting, and nested relative indexing stay fast and fail closed."""
        # 1a. Unshifted empty-key "//<idx>" array tail pops skip unrelated direct slots in O(log K)
        tpl_ek = "https://a.co/" + "".join(f"${{/0/~0{j}}}" for j in range(64))
        comps_ek = [{"id": "root", "component": "Column", "children": [f"v{k}" for k in range(270)]}] + [
            {
                "id": f"v{k}",
                "component": "Video",
                "url": {"@call": "formatString", "args": {"value": tpl_ek}},
                "posterUrl": {"@call": "formatString", "args": {"value": tpl_ek}},
            }
            for k in range(270)
        ]
        msgs_ek = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_ek_fast",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_ek,
                    "dataModel": {"": [0] * 1005},
                },
            }
        ] + [
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_ek_fast", "path": f"//{1004 - i}", "value": None}}
            for i in range(1000)
        ]
        t0 = time.perf_counter()
        res_ek_fast = validate_payload(json.dumps(msgs_ek, separators=(",", ":")), version="1.0", strict=True)
        self.assertTrue(res_ek_fast["ok"], res_ek_fast["errors"])
        self.assertLess(time.perf_counter() - t0, 0.5)

        # 1b. Shifted empty-key "//1" pop and ChildList "//0/items" pop STILL fail closed
        shifted_ek_direct = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_ek_shift_dir",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [{"id": "root", "component": "Image", "url": {"@path": "//1"}}],
                    "dataModel": {"": ["https://example.com/a.png", "https://example.com/b.png", "javascript:alert(1)"]},
                },
            },
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_ek_shift_dir", "path": "//0", "value": None}},
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_ek_shift_dir", "path": "//1", "value": "https://example.com/ok.png"}},
        ]
        res_ek_dir = validate_payload(json.dumps(shifted_ek_direct), version="1.0", strict=True)
        self.assertFalse(res_ek_dir["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_ek_dir["errors"]})

        shifted_ek_list = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_ek_shift_list",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "row_img", "path": "//0/items"}},
                        {"id": "row_img", "component": "Image", "url": {"@path": "u"}},
                    ],
                    "dataModel": {
                        "": [
                            {"items": [{"u": "https://example.com/a.png"}]},
                            {"items": [{"u": "javascript:alert(1)"}]},
                        ]
                    },
                },
            },
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_ek_shift_list", "path": "//0", "value": None}},
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_ek_shift_list", "path": "//0/items/0/u", "value": "https://example.com/ok.png"}},
        ]
        res_ek_list = validate_payload(json.dumps(shifted_ek_list), version="1.0", strict=True)
        self.assertFalse(res_ek_list["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_ek_list["errors"]})

        # 2. Deep template list_ptr resolution storm in absolute-overlap step fails closed under eval budget
        deep_pfx = "/" + "~0/" * 56
        dm_deep: dict[str, object] = {}
        cur_d: dict[str, object] = dm_deep
        for _ in range(56):
            nxt_d: dict[str, object] = {}
            cur_d["~"] = nxt_d
            cur_d = nxt_d
        comps_deep = (
            [{"id": "root", "component": "Column", "children": [f"l{k}" for k in range(498)]}]
            + [{"id": f"l{k}", "component": "List", "children": {"componentId": "row", "path": f"{deep_pfx}a{k}"}} for k in range(498)]
            + [{"id": "row", "component": "Image", "url": {"@call": "formatString", "args": {"value": "https://a.co/${/p}${u}"}}}]
        )
        msgs_deep = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_deep_tpl",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_deep,
                    "dataModel": dm_deep,
                },
            }
        ] + [
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_deep_tpl", "path": "/p", "value": i}}
            for i in range(500)
        ]
        t1 = time.perf_counter()
        res_deep = validate_payload(json.dumps(msgs_deep, separators=(",", ":")), version="1.0", strict=True)
        self.assertFalse(res_deep["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_deep["errors"]})
        self.assertLess(time.perf_counter() - t1, 0.5)

        # 3a. Empty/scalar items across 249 nested ChildLists charge eval budget and fail closed fast
        comps_nested = (
            [{"id": "root", "component": "Column", "children": [f"l{k}" for k in range(249)]}]
            + [{"id": f"l{k}", "component": "List", "children": {"componentId": f"g{k}", "path": "/g"}} for k in range(249)]
            + [{"id": f"g{k}", "component": "List", "children": {"componentId": "leaf", "path": "s"}} for k in range(249)]
            + [{"id": "leaf", "component": "Image", "url": {"@path": "u"}}]
        )
        nested_scalar_payload = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "s_nest_scalar",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": comps_nested,
                "dataModel": {"g": [0] * 20_000},
            },
        }
        t2 = time.perf_counter()
        res_nsc = validate_payload(json.dumps(nested_scalar_payload, separators=(",", ":")), version="1.0", strict=True)
        self.assertFalse(res_nsc["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_nsc["errors"]})
        self.assertLess(time.perf_counter() - t2, 0.5)

        # 3b. Unrelated sibling updates (/g/0/z) across 249 nested ChildLists skip via outer relative index
        nested_sibling_msgs = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_nest_sib",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_nested,
                    "dataModel": {"g": [{"s": [], "z": 0}]},
                },
            }
        ] + [
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_nest_sib", "path": "/g/0/z", "value": i}}
            for i in range(4_000)
        ]
        t3 = time.perf_counter()
        res_nsib = validate_payload(json.dumps(nested_sibling_msgs, separators=(",", ":")), version="1.0", strict=True)
        self.assertTrue(res_nsib["ok"], res_nsib["errors"])
        self.assertLess(time.perf_counter() - t3, 0.5)

        # 3c. Nested relative update (/g/0/s/0/u), nested pop (/g/0/s/0), and inner absolute overlap (/g/0/z) STILL fail closed
        nested_leaf_upd = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_nest_leaf",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "grp", "path": "/g"}},
                        {"id": "grp", "component": "List", "children": {"componentId": "leaf", "path": "s"}},
                        {"id": "leaf", "component": "Image", "url": {"@path": "u"}},
                    ],
                    "dataModel": {"g": [{"s": [{"u": "https://example.com/ok.png"}]}]},
                },
            },
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_nest_leaf", "path": "/g/0/s/0/u", "value": "javascript:alert(1)"}},
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_nest_leaf", "path": "/g/0/s/0/u", "value": "https://example.com/clean.png"}},
        ]
        res_nlu = validate_payload(json.dumps(nested_leaf_upd), version="1.0", strict=True)
        self.assertFalse(res_nlu["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_nlu["errors"]})

        nested_abs_sib = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_nest_abs_sib",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "grp", "path": "/g"}},
                        {"id": "grp", "component": "List", "children": {"componentId": "leaf", "path": "s"}},
                        {
                            "id": "leaf",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "/${/g/0/z}${u}"}},
                        },
                    ],
                    "dataModel": {"g": [{"z": "safe", "s": [{"u": "/evil.example/x.png"}]}]},
                },
            },
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_nest_abs_sib", "path": "/g/0/z", "value": ""}},
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_nest_abs_sib", "path": "/g/0/z", "value": "safe"}},
        ]
        res_nas = validate_payload(json.dumps(nested_abs_sib), version="1.0", strict=True)
        self.assertFalse(res_nas["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_nas["errors"]})

    def test_long_pointer_lazy_resolution_and_per_kb_eval_budgeting(self) -> None:
        """Long (>2048-char) pointers resolve lazily, preserve RFC 6901 edges, and charge per-KB eval cost."""
        from legends_a2ui.validator import _resolve_json_pointer, _resolve_pointer_with_context

        # 1. Lazy >2048-char pointer resolution edge cases (trailing slash, empty-key, tilde, empty container, valid hit)
        long_key = "k" * 2500
        long_tilde_seg = "~0" * 1500
        decoded_tilde_key = "~" * 1500
        dm_lazy = {
            long_key: {"": "trailing_hit", "sub": ["arr_hit"]},
            "": {long_key: "empty_root_hit"},
            "~": {"/": {decoded_tilde_key: "tilde_hit"}},
            "empty_d": {},
            "empty_l": [],
        }
        self.assertEqual(_resolve_json_pointer(dm_lazy, f"/{long_key}/"), (True, "trailing_hit"))
        self.assertEqual(_resolve_json_pointer(dm_lazy, f"/{long_key}/sub/0"), (True, "arr_hit"))
        self.assertEqual(_resolve_json_pointer(dm_lazy, f"//{long_key}"), (True, "empty_root_hit"))
        self.assertEqual(_resolve_json_pointer(dm_lazy, f"/~0/~1/{long_tilde_seg}"), (True, "tilde_hit"))
        self.assertEqual(_resolve_json_pointer(dm_lazy, f"/empty_d/{long_tilde_seg}"), (False, None))
        self.assertEqual(_resolve_json_pointer(dm_lazy, f"/empty_l/{long_tilde_seg}"), (False, None))
        self.assertEqual(_resolve_json_pointer({}, f"/{long_key}"), (False, None))
        self.assertEqual(_resolve_json_pointer([], f"/{long_key}"), (False, None))
        self.assertEqual(_resolve_pointer_with_context({}, f"{long_key}/", dm_lazy), (True, "trailing_hit"))
        self.assertEqual(_resolve_pointer_with_context({}, f"~0/~1/{long_tilde_seg}", dm_lazy), (True, "tilde_hit"))
        self.assertEqual(_resolve_pointer_with_context({}, f"empty_d/{long_tilde_seg}", dm_lazy), (False, None))
        self.assertEqual(_resolve_pointer_with_context({}, long_key, {}), (False, None))
        self.assertEqual(_resolve_pointer_with_context({}, long_key, []), (False, None))

        # 2. Long inner_list_ptr (tilde and tilde-free single-segment) trips eval budget fast
        for inner_ptr in ("a/" + ("~0" * 120_000), "x" * 240_000):
            comps_inner = (
                [{"id": "root", "component": "Column", "children": [f"l{k}" for k in range(20)]}]
                + [{"id": f"l{k}", "component": "List", "children": {"componentId": f"g{k}", "path": "/g"}} for k in range(20)]
                + [{"id": "g0", "component": "List", "children": {"componentId": "leaf", "path": inner_ptr}}]
                + [{"id": f"g{k}", "component": "Card", "child": "g0"} for k in range(1, 20)]
                + [{"id": "leaf", "component": "Image", "url": {"@path": "u"}}]
            )
            payload_inner = {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_long_inner",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_inner,
                    "dataModel": {"g": [{"a": {"z": 1}} for _ in range(100)]},
                },
            }
            t0 = time.perf_counter()
            res_inner = validate_payload(json.dumps(payload_inner, separators=(",", ":")), version="1.0", strict=True)
            self.assertFalse(res_inner["ok"])
            self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_inner["errors"]})
            self.assertLess(time.perf_counter() - t0, 0.5)

        # 3. Long @path binding and v0.8 dual literalString+path binding charge per-KB cost
        long_path_tilde = "~0/" + ("~0" * 120_000)
        payload_path = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "s_long_path",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "List", "children": {"componentId": "row", "path": "/g"}},
                    {"id": "row", "component": "Image", "url": {"@path": long_path_tilde}},
                ],
                "dataModel": {"g": [{"~": {"z": 1}} for _ in range(700)]},
            },
        }
        t1 = time.perf_counter()
        res_path = validate_payload(json.dumps(payload_path, separators=(",", ":")), version="1.0", strict=True)
        self.assertFalse(res_path["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_path["errors"]})
        self.assertLess(time.perf_counter() - t1, 0.5)

        v08_long_dual = [
            {"beginRendering": {"surfaceId": "s_v08_long", "root": "root"}},
            {
                "surfaceUpdate": {
                    "surfaceId": "s_v08_long",
                    "components": [
                        {
                            "id": "root",
                            "component": {"List": {"children": {"template": {"componentId": "row", "dataBinding": "/g"}}}},
                        },
                        {
                            "id": "row",
                            "component": {
                                "Image": {
                                    "url": {
                                        "literalString": "https://example.com/ok.png",
                                        "path": long_path_tilde,
                                    }
                                }
                            },
                        },
                    ],
                }
            },
            {
                "dataModelUpdate": {
                    "surfaceId": "s_v08_long",
                    "path": "/g",
                    "value": [{"~": {"z": 1}} for _ in range(700)],
                }
            },
        ]
        t2 = time.perf_counter()
        res_v08_dual = validate_payload(json.dumps(v08_long_dual, separators=(",", ":")), version="0.8", strict=False)
        self.assertFalse(res_v08_dual["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_v08_dual["errors"]})
        self.assertLess(time.perf_counter() - t2, 0.5)

        # 4. Outgoing template chain with long chain_ptrs charges per-KB cost in updateComponents
        long_chain_ptr = "a/" + ("~0" * 120_000)
        chain_msgs = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_long_chain",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "mid", "path": "/g"}},
                        {"id": "mid", "component": "List", "children": {"componentId": "leaf", "path": long_chain_ptr}},
                        {
                            "id": "leaf",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "${u}"}},
                        },
                    ],
                    "dataModel": {"g": [{"a": {"z": 1}} for _ in range(700)]},
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "s_long_chain",
                    "components": [
                        {"id": "mid", "component": "Text", "text": "replaced"},
                    ],
                },
            },
        ]
        t3 = time.perf_counter()
        res_chain = validate_payload(json.dumps(chain_msgs, separators=(",", ":")), version="1.0", strict=True)
        self.assertFalse(res_chain["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_chain["errors"]})
        self.assertLess(time.perf_counter() - t3, 0.5)

        # 5. Malformed >2048-char formatString templates charge per-KB cost across all error branches
        from legends_a2ui.validator import _parse_format_string_template

        for expected_status, bad_tpl in (
            ("err_too_long", (" " * 280_000) + "data:image/png;base64,${u}"),
            ("err_ctrl", "data:image/png;base64," + ("A" * 200_000) + "\x07${u}"),
            ("err_esc", "data:image/png;base64," + ("A" * 200_000) + r"\${u}"),
            ("err_too_many_exprs", "data:image/png;base64," + ("A" * 10_000) + ("${u}" * 65)),
            ("err_unclosed", "data:image/png;base64," + ("A" * 200_000) + "${u"),
            ("err_expr", "data:image/png;base64," + ("A" * 200_000) + "${bad expr}"),
        ):
            parsed_bad = _parse_format_string_template(bad_tpl)
            self.assertEqual(parsed_bad[0], expected_status)
            self.assertEqual(parsed_bad[5], 1 + (len(bad_tpl) // 1024))

        bad_fmt_payload = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "s_bad_fmt",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": ["i0", "i1", "i2"]},
                    {
                        "id": "i0",
                        "component": "Image",
                        "url": {"@call": "formatString", "args": {"value": "data:image/png;base64," + ("A" * 200_000) + "\x07${u}"}},
                    },
                    {
                        "id": "i1",
                        "component": "Image",
                        "url": {"@call": "formatString", "args": {"value": "data:image/png;base64," + ("A" * 200_000) + r"\${u}"}},
                    },
                    {
                        "id": "i2",
                        "component": "Image",
                        "url": {"@call": "formatString", "args": {"value": (" " * 280_000) + "data:image/png;base64,${u}"}},
                    },
                ],
                "dataModel": {},
            },
        }
        t4 = time.perf_counter()
        res_bf = validate_payload(json.dumps(bad_fmt_payload, separators=(",", ":")), version="1.0", strict=True)
        self.assertFalse(res_bf["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_bf["errors"]})
        self.assertLess(time.perf_counter() - t4, 0.5)

        # 6. Long list_ptr in Step 2a, 2b, and 2c charges per-KB cost and stays fast
        long_list_ptr = "/" + ("~0" * 100_000)
        long_lp_msgs = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_long_lp",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "row", "path": long_list_ptr}},
                        {
                            "id": "row",
                            "component": "Image",
                            "url": {"@call": "formatString", "args": {"value": "https://a.co/${/p}${u}"}},
                        },
                    ],
                    "dataModel": {"p": "a"},
                },
            }
        ] + [
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_long_lp", "path": "/p", "value": i}}
            for i in range(800)
        ]
        t5 = time.perf_counter()
        res_llp = validate_payload(json.dumps(long_lp_msgs, separators=(",", ":")), version="1.0", strict=True)
        self.assertFalse(res_llp["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_llp["errors"]})
        self.assertLess(time.perf_counter() - t5, 0.5)

    def test_step2a_full_list_budget_and_v08_empty_key_root_merge_scoping(self) -> None:
        """Repeated ancestor updates budget full_list_pairs, and v0.8 empty-key merges avoid unrelated broadcasts."""
        # 1. Step 2a full_list_pairs budgeting over deep missing/empty List templates
        deep58 = "/~0" * 58
        dm_deep: dict[str, object] = {}
        cur_d: dict[str, object] = dm_deep
        for _ in range(58):
            nxt_d: dict[str, object] = {}
            cur_d["~"] = nxt_d
            cur_d = nxt_d
        comps_deep = (
            [{"id": "root", "component": "Column", "children": [f"l{k}" for k in range(498)]}]
            + [{"id": f"l{k}", "component": "List", "children": {"componentId": "row", "path": f"{deep58}/z{k}"}} for k in range(498)]
            + [{"id": "row", "component": "Image", "url": {"@path": "u"}}]
        )
        msgs_step2a = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_step2a",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_deep,
                    "dataModel": dm_deep,
                },
            }
        ] + [
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_step2a", "path": deep58, "value": {}}}
            for _ in range(400)
        ]
        t0 = time.perf_counter()
        res_2a = validate_payload(json.dumps(msgs_step2a, separators=(",", ":")), version="1.0", strict=True)
        self.assertFalse(res_2a["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_2a["errors"]})
        self.assertLess(time.perf_counter() - t0, 0.5)

        # 2. v0.8 empty-key ("") root merge does NOT broadcast to unrelated /~0/... List templates
        v08_comps_unrelated = (
            [{"id": "root", "component": {"Column": {"children": {"explicitList": [f"l{k}" for k in range(498)]}}}}]
            + [
                {
                    "id": f"l{k}",
                    "component": {"List": {"children": {"template": {"componentId": "row", "dataBinding": f"{deep58}/z{k}"}}}},
                }
                for k in range(498)
            ]
            + [{"id": "row", "component": {"Image": {"url": {"path": "u"}}}}]
        )
        v08_empty_key_msgs = [
            {"beginRendering": {"surfaceId": "s_v08_ek", "root": "root"}},
            {"surfaceUpdate": {"surfaceId": "s_v08_ek", "components": v08_comps_unrelated}},
        ] + [
            {
                "dataModelUpdate": {
                    "surfaceId": "s_v08_ek",
                    "path": "/",
                    "contents": [{"key": "", "valueNumber": i}],
                }
            }
            for i in range(4000)
        ]
        t1 = time.perf_counter()
        res_v08_ek = validate_payload(json.dumps(v08_empty_key_msgs, separators=(",", ":")), version="0.8", strict=False)
        self.assertTrue(res_v08_ek["ok"], res_v08_ek["errors"])
        self.assertLess(time.perf_counter() - t1, 0.5)

        # 3. v0.8 empty-key ("") root merge STILL catches UNSAFE_MEDIA_URL on direct "//u" and ChildList "//items"
        v08_ek_direct = [
            {"beginRendering": {"surfaceId": "s_v08_dir", "root": "root"}},
            {
                "surfaceUpdate": {
                    "surfaceId": "s_v08_dir",
                    "components": [{"id": "root", "component": {"Image": {"url": {"path": "//u"}}}}],
                }
            },
            {
                "dataModelUpdate": {
                    "surfaceId": "s_v08_dir",
                    "path": "/",
                    "contents": [{"key": "", "valueMap": [{"key": "u", "valueString": "javascript:alert(1)"}]}],
                }
            },
            {
                "dataModelUpdate": {
                    "surfaceId": "s_v08_dir",
                    "path": "/",
                    "contents": [{"key": "", "valueMap": [{"key": "u", "valueString": "https://example.com/ok.png"}]}],
                }
            },
        ]
        res_ek_d = validate_payload(json.dumps(v08_ek_direct), version="0.8", strict=False)
        self.assertFalse(res_ek_d["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_ek_d["errors"]})

        v08_ek_list = [
            {"beginRendering": {"surfaceId": "s_v08_lst", "root": "root"}},
            {
                "surfaceUpdate": {
                    "surfaceId": "s_v08_lst",
                    "components": [
                        {
                            "id": "root",
                            "component": {"List": {"children": {"template": {"componentId": "row", "dataBinding": "//items"}}}},
                        },
                        {"id": "row", "component": {"Image": {"url": {"path": "u"}}}},
                    ],
                }
            },
            {
                "dataModelUpdate": {
                    "surfaceId": "s_v08_lst",
                    "path": "/",
                    "contents": [
                        {
                            "key": "",
                            "valueMap": [
                                {
                                    "key": "items",
                                    "valueArray": [{"valueMap": [{"key": "u", "valueString": "javascript:alert(1)"}]}],
                                }
                            ],
                        }
                    ],
                }
            },
            {
                "dataModelUpdate": {
                    "surfaceId": "s_v08_lst",
                    "path": "/",
                    "contents": [
                        {
                            "key": "",
                            "valueMap": [
                                {
                                    "key": "items",
                                    "valueArray": [{"valueMap": [{"key": "u", "valueString": "https://example.com/ok.png"}]}],
                                }
                            ],
                        }
                    ],
                }
            },
        ]
        res_ek_l = validate_payload(json.dumps(v08_ek_list), version="0.8", strict=False)
        self.assertFalse(res_ek_l["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_ek_l["errors"]})

    def test_incremental_template_chain_pruning_index_rebuild_budgets_and_tilde_cache(self) -> None:
        """Incremental updateComponents chain pruning, budgeted index rebuilds, tilde LRU cap, and cycle cap."""
        from legends_a2ui.validator import _detect_cycles_iterative, _split_tilde_pointer_cached

        # 1a. Unrelated Divider updates on a deep multi-level ChildList DAG with a relative prefix-less
        # formatString leaf skip snapshot cloning and chain traversal cleanly
        comps_dag = [
            {"id": "root", "component": "Column", "children": ["top", "d"]},
            {"id": "d", "component": "Divider"},
            {"id": "top", "component": "List", "children": {"componentId": "c0", "path": "/g"}},
            {"id": "c0", "component": "Column", "children": [f"a{i}" for i in range(63)]},
        ]
        for i in range(63):
            comps_dag.append({"id": f"a{i}", "component": "List", "children": {"componentId": "c1", "path": f"p{i}"}})
        comps_dag.append({"id": "c1", "component": "Column", "children": [f"b{j}" for j in range(63)]})
        for j in range(63):
            comps_dag.append({"id": f"b{j}", "component": "List", "children": {"componentId": "c2", "path": f"q{j}"}})
        comps_dag.append({"id": "c2", "component": "Column", "children": ["leaf"] + [f"s{k}" for k in range(177)]})
        comps_dag.append({"id": "leaf", "component": "Image", "url": {"@call": "formatString", "args": {"value": "${u}"}}})
        for k in range(177):
            comps_dag.append({"id": f"s{k}", "component": "Divider"})
        dm_dag = {"g": [{"p0": [{"q0": [{"u": "https://example.com/1.png"}]}]}]}
        msgs_dag_unrelated = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_dag_u",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_dag,
                    "dataModel": dm_dag,
                },
            }
        ] + [
            {"version": "1.0", "updateComponents": {"surfaceId": "s_dag_u", "components": [{"id": "d", "component": "Divider"}]}}
            for _ in range(25)
        ]
        t0 = time.perf_counter()
        res_dag_u = validate_payload(json.dumps(msgs_dag_unrelated, separators=(",", ":")), version="1.0", strict=True)
        self.assertTrue(res_dag_u["ok"], res_dag_u["errors"])
        self.assertLess(time.perf_counter() - t0, 0.5)

        # 1b. Genuine ChildList binding mutation with a large slotless subgraph prunes dead branches
        comps_slotless = [
            {"id": "root", "component": "List", "children": {"componentId": "c0", "path": "/g0"}},
            {"id": "c0", "component": "Column", "children": ["leaf"] + [f"a{i}" for i in range(63)]},
            {"id": "leaf", "component": "Image", "url": {"@call": "formatString", "args": {"value": "${u}"}}},
        ]
        for i in range(63):
            comps_slotless.append({"id": f"a{i}", "component": "List", "children": {"componentId": "c1", "path": f"p{i}"}})
        comps_slotless.append({"id": "c1", "component": "Column", "children": [f"b{j}" for j in range(63)]})
        for j in range(63):
            comps_slotless.append({"id": f"b{j}", "component": "List", "children": {"componentId": "c2", "path": f"q{j}"}})
        comps_slotless.append({"id": "c2", "component": "Column", "children": [f"s{k}" for k in range(177)]})
        for k in range(177):
            comps_slotless.append({"id": f"s{k}", "component": "Divider"})
        dm_slotless = {"g0": [{"u": "https://example.com/1.png"}], "g1": [{"u": "https://example.com/2.png"}]}
        msgs_slotless = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_dag_m",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_slotless,
                    "dataModel": dm_slotless,
                },
            }
        ] + [
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "s_dag_m",
                    "components": [{"id": "root", "component": "List", "children": {"componentId": "c0", "path": f"/g{(u + 1) % 2}"}}],
                },
            }
            for u in range(10)
        ]
        t1 = time.perf_counter()
        res_slotless = validate_payload(json.dumps(msgs_slotless, separators=(",", ":")), version="1.0", strict=True)
        self.assertTrue(res_slotless["ok"], res_slotless["errors"])
        self.assertLess(time.perf_counter() - t1, 0.5)

        # 1c. Unlinking a prefix-less formatString template that resolved an unsafe URL still fails closed
        msgs_unlink_unsafe = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_dag_bad",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "List", "children": {"componentId": "c0", "path": "/g0"}},
                        {"id": "c0", "component": "Column", "children": ["leaf", "sub"]},
                        {"id": "leaf", "component": "Image", "url": {"@call": "formatString", "args": {"value": "${u}"}}},
                        {"id": "sub", "component": "Divider"},
                    ],
                    "dataModel": {
                        "g0": [{"u": "javascript:alert(1)"}],
                        "g1": [{"u": "https://example.com/ok.png"}],
                    },
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "s_dag_bad",
                    "components": [{"id": "root", "component": "List", "children": {"componentId": "c0", "path": "/g1"}}],
                },
            },
        ]
        res_unlink_bad = validate_payload(json.dumps(msgs_unlink_unsafe), version="1.0", strict=True)
        self.assertFalse(res_unlink_bad["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_unlink_bad["errors"]})

        # 2a. Alternating updateComponents + updateDataModel direct abs_ptrs index rebuilds stay budgeted
        deep55 = "/a" * 55
        dm55: dict[str, Any] = {}
        cur55 = dm55
        for _ in range(55):
            nxt55: dict[str, Any] = {}
            cur55["a"] = nxt55
            cur55 = nxt55
        comps_idx_dir = (
            [{"id": "root", "component": "Column", "children": ["d"] + [f"m{k}" for k in range(120)]},
             {"id": "d", "component": "Image", "url": {"@path": "/u0"}}]
            + [
                {
                    "id": f"m{k}",
                    "component": "Image",
                    "url": {
                        "@call": "formatString",
                        "args": {"value": "https://a.co/" + "".join(f"${{{deep55}/k{k}_{p}}}" for p in range(16))},
                    },
                }
                for k in range(120)
            ]
        )
        msgs_idx_dir = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_idx_dir",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_idx_dir,
                    "dataModel": dm55,
                },
            }
        ]
        for i in range(150):
            msgs_idx_dir.append(
                {"version": "1.0", "updateComponents": {"surfaceId": "s_idx_dir", "components": [{"id": "d", "component": "Image", "url": {"@path": f"/u{i % 2}"}}]}}
            )
            msgs_idx_dir.append(
                {"version": "1.0", "updateDataModel": {"surfaceId": "s_idx_dir", "path": "/x", "value": i % 9}}
            )
        t2 = time.perf_counter()
        res_idx_dir = validate_payload(json.dumps(msgs_idx_dir, separators=(",", ":")), version="1.0", strict=True)
        self.assertFalse(res_idx_dir["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_idx_dir["errors"]})
        self.assertLess(time.perf_counter() - t2, 0.5)

        # 2b. Alternating updateComponents + updateDataModel ChildList index rebuilds stay budgeted
        comps_idx_cl = (
            [
                {"id": "root", "component": "Column", "children": ["d"] + [f"l{k}" for k in range(250)]},
                {"id": "d", "component": "List", "children": {"componentId": "row", "path": "/u0"}},
                {"id": "row", "component": "Image", "url": {"@path": "u"}},
            ]
            + [{"id": f"l{k}", "component": "List", "children": {"componentId": "row", "path": f"{deep55}/l{k}"}} for k in range(250)]
        )
        msgs_idx_cl = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_idx_cl",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_idx_cl,
                    "dataModel": dm55,
                },
            }
        ]
        for i in range(120):
            msgs_idx_cl.append(
                {"version": "1.0", "updateComponents": {"surfaceId": "s_idx_cl", "components": [{"id": "d", "component": "List", "children": {"componentId": "row", "path": f"/u{i % 2}"}}]}}
            )
            msgs_idx_cl.append(
                {"version": "1.0", "updateDataModel": {"surfaceId": "s_idx_cl", "path": "/x", "value": i % 9}}
            )
        t3 = time.perf_counter()
        res_idx_cl = validate_payload(json.dumps(msgs_idx_cl, separators=(",", ":")), version="1.0", strict=True)
        self.assertFalse(res_idx_cl["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_idx_cl["errors"]})
        self.assertLess(time.perf_counter() - t3, 0.5)

        # 2c. Selective cache invalidation still catches UNSAFE_MEDIA_URL on genuinely updated direct and template slots
        msgs_selective_unsafe = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_sel_bad",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "Column", "children": ["img", "lst", "div"]},
                        {"id": "img", "component": "Image", "url": {"@path": "/safe"}},
                        {"id": "lst", "component": "List", "children": {"componentId": "row", "path": "/items"}},
                        {"id": "row", "component": "Image", "url": {"@path": "safe_u"}},
                        {"id": "div", "component": "Divider"},
                    ],
                    "dataModel": {"safe": "https://example.com/a.png", "items": [{"safe_u": "https://example.com/b.png"}]},
                },
            },
            {"version": "1.0", "updateComponents": {"surfaceId": "s_sel_bad", "components": [{"id": "div", "component": "Divider"}]}},
            {"version": "1.0", "updateComponents": {"surfaceId": "s_sel_bad", "components": [{"id": "img", "component": "Image", "url": {"@path": "/bad"}}]}},
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_sel_bad", "path": "/bad", "value": "javascript:alert(1)"}},
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_sel_bad", "path": "/bad", "value": "https://example.com/ok.png"}},
        ]
        res_sel_bad = validate_payload(json.dumps(msgs_selective_unsafe), version="1.0", strict=True)
        self.assertFalse(res_sel_bad["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_sel_bad["errors"]})

        msgs_sel_tpl_bad = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_sel_tpl",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {"id": "root", "component": "Column", "children": ["lst", "div"]},
                        {"id": "lst", "component": "List", "children": {"componentId": "row", "path": "/items"}},
                        {"id": "row", "component": "Image", "url": {"@path": "safe_u"}},
                        {"id": "div", "component": "Divider"},
                    ],
                    "dataModel": {"items": [{"safe_u": "https://example.com/b.png"}]},
                },
            },
            {"version": "1.0", "updateComponents": {"surfaceId": "s_sel_tpl", "components": [{"id": "row", "component": "Image", "url": {"@path": "bad_u"}}]}},
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_sel_tpl", "path": "/items/0/bad_u", "value": "javascript:alert(1)"}},
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_sel_tpl", "path": "/items/0/bad_u", "value": "https://example.com/ok.png"}},
        ]
        res_sel_tpl = validate_payload(json.dumps(msgs_sel_tpl_bad), version="1.0", strict=True)
        self.assertFalse(res_sel_tpl["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_sel_tpl["errors"]})

        # 3. 2,112 distinct 458-byte tilde pointers fit in _split_tilde_pointer_cached(maxsize=4096) and stay fast
        _split_tilde_pointer_cached.cache_clear()
        ptrs_2112 = ["/" + ("~0" * 224) + f"/k{i:04d}" for i in range(2112)]
        comps_tilde = [{"id": "root", "component": "Column", "children": [f"m{i}" for i in range(132)]}]
        for i in range(132):
            grp = ptrs_2112[i * 16 : (i + 1) * 16]
            comps_tilde.append(
                {
                    "id": f"m{i}",
                    "component": "Image",
                    "url": {"@call": "formatString", "args": {"value": "https://a.co/" + "".join(f"${{{p}}}" for p in grp)}},
                }
            )
        msgs_tilde = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_tilde_lru",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_tilde,
                    "dataModel": {"z": 1},
                },
            }
        ] + [{"version": "1.0", "updateDataModel": {"surfaceId": "s_tilde_lru", "path": "/", "value": {"z": r}}} for r in range(85)]
        t4 = time.perf_counter()
        res_tilde = validate_payload(json.dumps(msgs_tilde, separators=(",", ":")), version="1.0", strict=True)
        self.assertFalse(res_tilde["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_tilde["errors"]})
        self.assertLess(time.perf_counter() - t4, 0.5)
        self.assertEqual(_split_tilde_pointer_cached.cache_info().maxsize, 4096)
        self.assertEqual(_split_tilde_pointer_cached.cache_info().misses, 2112)

        # 4. _detect_cycles_iterative caps dense cyclic graphs at 64 cycles
        dense_adj = {f"n{i}": [f"n{j}" for j in range(20)] for i in range(20)}
        found_cycles = _detect_cycles_iterative(dense_adj)
        self.assertEqual(len(found_cycles), 64)

    def test_template_scope_cache_child_ref_dedup_and_issue_caps(self) -> None:
        """Template scope caching, child-ref deduplication, and priority-preserving issue caps stay linear and fail closed."""
        # 1a. Dense unique-edge DAG with nested ChildList under repeated updateDataModel stays fast via surface scope cache
        n_lists, n_mid, n_leaf = 40, 120, 120
        s_ids = [f"s{j}" for j in range(n_leaf)]
        d_ids = [f"d{i}" for i in range(n_mid)]
        comps_dense_dag = (
            [{"id": "root", "component": "Column", "children": [f"l{k}" for k in range(n_lists)]}]
            + [{"id": f"l{k}", "component": "List", "children": {"componentId": f"r{k}", "path": "/g"}} for k in range(n_lists)]
            + [{"id": f"r{k}", "component": "Column", "children": d_ids + ["sub_lst"]} for k in range(n_lists)]
            + [{"id": f"d{i}", "component": "Column", "children": s_ids} for i in range(n_mid)]
            + [{"id": f"s{j}", "component": "Divider"} for j in range(n_leaf)]
            + [
                {"id": "sub_lst", "component": "List", "children": {"componentId": "leaf", "path": "sub"}},
                {"id": "leaf", "component": "Image", "url": {"@path": "u"}},
            ]
        )
        msgs_dense_ok = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_scope_dag",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_dense_dag,
                    "dataModel": {"g": [1]},
                },
            }
        ] + [
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_scope_dag", "path": "/g", "value": [1]}}
            for _ in range(300)
        ]
        raw_dense_ok = json.dumps(msgs_dense_ok, separators=(",", ":"))
        t0 = time.perf_counter()
        res_dense_ok = validate_payload(raw_dense_ok, version="1.0", strict=True)
        self.assertTrue(res_dense_ok["ok"], res_dense_ok["errors"])
        self.assertLess(time.perf_counter() - t0, 0.35)

        # Nested unsafe URL on the same dense DAG is still caught fail-closed
        msgs_dense_bad = list(msgs_dense_ok[:10]) + [
            {
                "version": "1.0",
                "updateDataModel": {
                    "surfaceId": "s_scope_dag",
                    "path": "/g",
                    "value": [{"sub": [{"u": "javascript:alert(1)"}]}],
                },
            },
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_scope_dag", "path": "/g", "value": [1]}},
        ]
        res_dense_bad = validate_payload(json.dumps(msgs_dense_bad, separators=(",", ":")), version="1.0", strict=True)
        self.assertFalse(res_dense_bad["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_dense_bad["errors"]})

        # 1b. Repeated valid child IDs ["d"] * 50_000 under nested ChildList updates stay fast and still catch unsafe nested URLs
        comps_rep_child = (
            [{"id": "root", "component": "Column", "children": [f"l{k}" for k in range(120)]}]
            + [{"id": f"l{k}", "component": "List", "children": {"componentId": f"r{k}", "path": "/g"}} for k in range(120)]
            + [{"id": f"r{k}", "component": "Column", "children": ["c0"]} for k in range(120)]
            + [
                {"id": "c0", "component": "Column", "children": ["sub_lst"] + ["d"] * 50_000},
                {"id": "d", "component": "Divider"},
                {"id": "sub_lst", "component": "List", "children": {"componentId": "leaf", "path": "sub"}},
                {"id": "leaf", "component": "Image", "url": {"@path": "u"}},
            ]
        )
        msgs_rep_ok = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_rep_child",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_rep_child,
                    "dataModel": {"g": [1]},
                },
            }
        ] + [
            {"version": "1.0", "updateDataModel": {"surfaceId": "s_rep_child", "path": "/g", "value": [1]}}
            for _ in range(100)
        ]
        raw_rep_ok = json.dumps(msgs_rep_ok, separators=(",", ":"))
        t1 = time.perf_counter()
        res_rep_ok = validate_payload(raw_rep_ok, version="1.0", strict=True)
        self.assertTrue(res_rep_ok["ok"], res_rep_ok["errors"])
        self.assertLess(time.perf_counter() - t1, 0.35)

        msgs_rep_bad = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_rep_bad",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_rep_child,
                    "dataModel": {"g": [{"sub": [{"u": "javascript:alert(1)"}]}]},
                },
            }
        ]
        res_rep_bad = validate_payload(json.dumps(msgs_rep_bad, separators=(",", ":")), version="1.0", strict=True)
        self.assertFalse(res_rep_bad["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_rep_bad["errors"]})

        # 2. 32,000+ distinct dangling IDs complete in linear time with capped errors while preserving UNSAFE_MEDIA_URL
        dangling_ids = [f"m{i:05d}" for i in range(35_000)]
        msg_dangling = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "s_dang",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": dangling_ids + ["bad_img"]},
                    {"id": "bad_img", "component": "Image", "url": "javascript:alert(1)"},
                ],
            },
        }
        raw_dangling = json.dumps(msg_dangling, separators=(",", ":"))
        t2 = time.perf_counter()
        res_dangling = validate_payload(raw_dangling, version="1.0", strict=True)
        self.assertFalse(res_dangling["ok"])
        self.assertLess(time.perf_counter() - t2, 0.25)
        dang_errs = [e for e in res_dangling["errors"] if e["code"] == "DANGLING_COMPONENT_REF"]
        self.assertEqual(len(dang_errs), 64)
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_dangling["errors"]})
        # bad_img after the 35,000 dangling refs must still be linked into adj (not falsely flagged as orphan)
        self.assertNotIn("ORPHAN_COMPONENT", {w["code"] for w in res_dangling["warnings"]})

        # Priority-preserving cap: 5 surfaces of 64 dangling refs saturate generic cap (256), yet UNSAFE_MEDIA_URL on surface 6 still reports
        multi_surf_msgs: list[dict[str, Any]] = []
        for sidx in range(5):
            multi_surf_msgs.append(
                {
                    "version": "1.0",
                    "createSurface": {
                        "surfaceId": f"s_cap_{sidx}",
                        "catalogId": CANONICAL_V1_CATALOG_ID,
                        "components": [
                            {"id": "root", "component": "Column", "children": [f"x{sidx}_{j}" for j in range(70)]}
                        ],
                    },
                }
            )
        multi_surf_msgs.append(
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_cap_sec",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [{"id": "root", "component": "Image", "url": "javascript:alert(1)"}],
                },
            }
        )
        res_priority = validate_payload(json.dumps(multi_surf_msgs, separators=(",", ":")), version="1.0", strict=True)
        self.assertFalse(res_priority["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_priority["errors"]})
        self.assertLessEqual(len(res_priority["errors"]), 512)

        # 3a. Dense unique-edge DAG in template binding chain diff stays budgeted and fast
        n_a, n_b, n_u, n_v = 31, 31, 200, 150
        v_ids = [f"v{j}" for j in range(n_v)]
        u_ids = [f"u{i}" for i in range(n_u)]
        comps_chain_dense = (
            [
                {"id": "root", "component": "List", "children": {"componentId": "c0", "path": "/g0"}},
                {"id": "c0", "component": "Column", "children": [f"a{i}" for i in range(n_a)]},
            ]
            + [{"id": f"a{i}", "component": "List", "children": {"componentId": "c1", "path": f"p{i}"}} for i in range(n_a)]
            + [{"id": "c1", "component": "Column", "children": [f"b{j}" for j in range(n_b)]}]
            + [{"id": f"b{j}", "component": "List", "children": {"componentId": "c2", "path": f"q{j}"}} for j in range(n_b)]
            + [{"id": "c2", "component": "Column", "children": u_ids}]
            + [{"id": f"u{i}", "component": "Column", "children": v_ids} for i in range(n_u)]
            + [{"id": f"v{j}", "component": "Column", "children": ["leaf"]} for j in range(n_v)]
            + [{"id": "leaf", "component": "Image", "url": {"@call": "formatString", "args": {"value": "${u}"}}}]
        )
        msgs_chain_dense = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_chain_dense",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_chain_dense,
                    "dataModel": {"g0": [], "g1": []},
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "s_chain_dense",
                    "components": [{"id": "root", "component": "List", "children": {"componentId": "c0", "path": "/g1"}}],
                },
            },
        ]
        raw_chain_dense = json.dumps(msgs_chain_dense, separators=(",", ":"))
        t3 = time.perf_counter()
        res_chain_dense = validate_payload(raw_chain_dense, version="1.0", strict=True)
        self.assertFalse(res_chain_dense["ok"])
        self.assertIn("MAX_TEMPLATE_EVALS_EXCEEDED", {e["code"] for e in res_chain_dense["errors"]})
        self.assertLess(time.perf_counter() - t3, 0.35)

        # 3b. Repeated-child DAG in template binding chain diff deduplicates edges and still catches unlinked prefix-less unsafe URL
        comps_chain_rep = (
            [
                {"id": "root", "component": "List", "children": {"componentId": "c0", "path": "/g0"}},
                {"id": "c0", "component": "Column", "children": [f"a{i}" for i in range(n_a)]},
            ]
            + [{"id": f"a{i}", "component": "List", "children": {"componentId": "c1", "path": f"p{i}"}} for i in range(n_a)]
            + [{"id": "c1", "component": "Column", "children": [f"b{j}" for j in range(n_b)]}]
            + [{"id": f"b{j}", "component": "List", "children": {"componentId": "c2", "path": f"q{j}"}} for j in range(n_b)]
            + [
                {"id": "c2", "component": "Column", "children": ["s0"] * 60_000},
                {"id": "s0", "component": "Column", "children": ["leaf"]},
                {"id": "leaf", "component": "Image", "url": {"@call": "formatString", "args": {"value": "${u}"}}},
            ]
        )
        msgs_chain_rep = [
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "s_chain_rep",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": comps_chain_rep,
                    "dataModel": {"g0": [{"p0": [{"q0": [{}]}]}], "g1": []},
                },
            },
            {
                "version": "1.0",
                "updateComponents": {
                    "surfaceId": "s_chain_rep",
                    "components": [{"id": "root", "component": "List", "children": {"componentId": "c0", "path": "/g1"}}],
                },
            },
        ]
        raw_chain_rep = json.dumps(msgs_chain_rep, separators=(",", ":"))
        t4 = time.perf_counter()
        res_chain_rep = validate_payload(raw_chain_rep, version="1.0", strict=True)
        self.assertFalse(res_chain_rep["ok"])
        self.assertIn("UNSAFE_MEDIA_URL", {e["code"] for e in res_chain_rep["errors"]})
        self.assertLess(time.perf_counter() - t4, 0.35)

        # 4. Tabs.tabs and ChoicePicker.options with 50,000 invalid items complete fast with capped issues
        msg_tabs_inv = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "s_tabs_inv",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [{"id": "root", "component": "Tabs", "tabs": [0] * 50_000}],
            },
        }
        raw_tabs_inv = json.dumps(msg_tabs_inv, separators=(",", ":"))
        t5 = time.perf_counter()
        res_tabs_inv = validate_payload(raw_tabs_inv, version="1.0", strict=True)
        self.assertFalse(res_tabs_inv["ok"])
        self.assertLess(time.perf_counter() - t5, 0.25)
        self.assertEqual(len([e for e in res_tabs_inv["errors"] if e["code"] == "INVALID_TAB_ITEM"]), 64)

        msg_choice_inv = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "s_choice_inv",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {
                        "id": "root",
                        "component": "ChoicePicker",
                        "value": {"@path": "/sel"},
                        "options": [0] * 50_000,
                    }
                ],
            },
        }
        raw_choice_inv = json.dumps(msg_choice_inv, separators=(",", ":"))
        t6 = time.perf_counter()
        res_choice_inv = validate_payload(raw_choice_inv, version="1.0", strict=True)
        self.assertFalse(res_choice_inv["ok"])
        self.assertLess(time.perf_counter() - t6, 0.25)
        self.assertEqual(len([e for e in res_choice_inv["errors"] if e["code"] == "INVALID_CHOICE_OPTION"]), 64)

    def test_parser_bounds_unmaskable_priority_issues_and_dynamic_array_fast_paths(self) -> None:
        """Bounded parsing, unmaskable priority security codes, and dynamic-value fast paths stay fast and fail closed."""
        from legends_a2ui.parser import parse_payload

        fake_secret = "sk_" + "live_" + ("0" * 20)
        evil_msg = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "sec_s",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": ["img1", "btn1", "tf1", "cyc1"]},
                    {"id": "img1", "component": "Image", "url": "javascript:alert(1)"},
                    {
                        "id": "btn1",
                        "component": "Button",
                        "child": "cyc1",
                        "action": {"functionCall": {"@call": "openUrl", "args": {"url": "javascript:evil()"}}},
                    },
                    {
                        "id": "tf1",
                        "component": "TextField",
                        "label": "Input",
                        "value": {"@path": "/v"},
                        "@checks": [{"condition": {"@call": "regex", "args": {"value": "a", "pattern": "(a+)+"}}}],
                    },
                    {"id": "cyc1", "component": "Column", "children": ["cyc2"]},
                    {"id": "cyc2", "component": "Column", "children": ["cyc1"]},
                ],
                "dataModel": {"apiKey": fake_secret},
            },
        }
        evil_json = json.dumps(evil_msg, separators=(",", ":"))

        # 1a. 512 malformed JSONL lines preceding an unsafe surface cannot mask any priority security code
        raw_jsonl_mask = ("x\n" * 512) + evil_json + "\n"
        res_jsonl_mask = validate_payload(raw_jsonl_mask, version="1.0", strict=True)
        self.assertFalse(res_jsonl_mask["ok"])
        jsonl_codes = {e["code"] for e in res_jsonl_mask["errors"]}
        for expected in (
            "JSON_PARSE_ERROR",
            "SECRET_LEAK",
            "UNSAFE_MEDIA_URL",
            "UNSAFE_OPEN_URL",
            "UNSAFE_REGEX",
            "COMPONENT_CYCLE",
        ):
            self.assertIn(expected, jsonl_codes)
        self.assertLessEqual(len([e for e in res_jsonl_mask["errors"] if e["code"] == "JSON_PARSE_ERROR"]), 64)

        # 1b. 512 empty Markdown fenced blocks preceding an unsafe surface cannot mask any priority security code
        raw_md_mask = ("```a2ui\n```\n" * 512) + "```a2ui\n" + evil_json + "\n```\n"
        res_md_mask = validate_payload(raw_md_mask, version="1.0", strict=True, extract_markdown=True)
        self.assertFalse(res_md_mask["ok"])
        md_codes = {e["code"] for e in res_md_mask["errors"]}
        for expected in (
            "EMPTY_PAYLOAD",
            "SECRET_LEAK",
            "UNSAFE_MEDIA_URL",
            "UNSAFE_OPEN_URL",
            "UNSAFE_REGEX",
            "COMPONENT_CYCLE",
        ):
            self.assertIn(expected, md_codes)
        self.assertLessEqual(len([e for e in res_md_mask["errors"] if e["code"] == "EMPTY_PAYLOAD"]), 64)

        # 1c. Pure-JSON intra-priority flood (512 INVALID_REGEX on s0) cannot mask distinct priority codes on s1
        s0_regex_flood = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "s0",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {
                        "id": "root",
                        "component": "TextField",
                        "label": "Field",
                        "value": {"@path": "/v"},
                        "@checks": [
                            {"condition": {"@call": "regex", "args": {"value": "a", "pattern": "["}}}
                            for _ in range(512)
                        ],
                    }
                ],
            },
        }
        s1_unsafe = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "s1",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Column", "children": ["img1", "btn1", "cyc1"]},
                    {"id": "img1", "component": "Image", "url": "javascript:alert(1)"},
                    {
                        "id": "btn1",
                        "component": "Button",
                        "child": "cyc1",
                        "action": {"functionCall": {"@call": "openUrl", "args": {"url": "javascript:evil()"}}},
                    },
                    {"id": "cyc1", "component": "Column", "children": ["cyc2"]},
                    {"id": "cyc2", "component": "Column", "children": ["cyc1"]},
                ],
            },
        }
        raw_intra = json.dumps(
            [s0_regex_flood, {"version": "1.0", "deleteSurface": {"surfaceId": "s0"}}, s1_unsafe],
            separators=(",", ":"),
        )
        res_intra = validate_payload(raw_intra, version="1.0", strict=True)
        self.assertFalse(res_intra["ok"])
        intra_codes = {e["code"] for e in res_intra["errors"]}
        for expected in ("INVALID_REGEX", "UNSAFE_MEDIA_URL", "UNSAFE_OPEN_URL", "COMPONENT_CYCLE"):
            self.assertIn(expected, intra_codes)
        self.assertEqual(len([e for e in res_intra["errors"] if e["code"] == "INVALID_REGEX"]), 64)

        # 1d. Unclosed quote on JSONL line 1 followed by excessive nesting still reports MAX_DEPTH_EXCEEDED
        raw_quote_depth = '"\n' + ("[" * 200) + ("]" * 200) + "\n"
        res_quote_depth = validate_payload(raw_quote_depth, version="1.0", strict=True)
        self.assertFalse(res_quote_depth["ok"])
        self.assertIn("MAX_DEPTH_EXCEEDED", {e["code"] for e in res_quote_depth["errors"]})

        # 2. Bounded parse_payload and validate_payload on high-fan-out JSONL, JSON array, and Markdown inputs
        bounded_cases = [
            ("0\n" * 524_288, False, "MAX_MESSAGES_EXCEEDED"),
            ("x\n" * 524_288, False, "MAX_MESSAGES_EXCEEDED"),
            ("{}\n" * 349_525, False, "MAX_MESSAGES_EXCEEDED"),
            ("[" + "{}," * 100_000 + "{}]", False, "MAX_MESSAGES_EXCEEDED"),
            ("```a2ui\n```\n" * 87_381, True, "MAX_BLOCKS_EXCEEDED"),
        ]
        for raw_case, ext_md, expected_limit_code in bounded_cases:
            t_p = time.perf_counter()
            pres = parse_payload(raw_case, extract_markdown=ext_md)
            self.assertLess(time.perf_counter() - t_p, 0.35)
            self.assertFalse(pres["ok"])
            self.assertLessEqual(len(pres["errors"]), 256)
            self.assertIn(expected_limit_code, {e["code"] for e in pres["errors"]})

            t_v = time.perf_counter()
            vres = validate_payload(raw_case, version="1.0", strict=True, extract_markdown=ext_md)
            self.assertLess(time.perf_counter() - t_v, 0.35)
            self.assertFalse(vres["ok"])
            self.assertLessEqual(len(vres["errors"]), 256)
            self.assertIn(expected_limit_code, {e["code"] for e in vres["errors"]})
            serialized = json.dumps(vres, indent=2)
            self.assertLess(len(serialized), 50_000)

        # 3a. DynamicValue fast paths on large scalar, empty-dict, and flat-dict arrays stay fast
        for sid, text_val in (
            ("dyn_ints", [0] * 524_000),
            ("dyn_empty", [{}] * 349_400),
            ("dyn_flat", [{"a": 1}] * 130_000),
        ):
            raw_dyn = json.dumps(
                {
                    "version": "1.0",
                    "createSurface": {
                        "surfaceId": sid,
                        "catalogId": CANONICAL_V1_CATALOG_ID,
                        "components": [{"id": "root", "component": "Text", "text": text_val}],
                    },
                },
                separators=(",", ":"),
            )
            t_d = time.perf_counter()
            res_dyn = validate_payload(raw_dyn, version="1.0", strict=True)
            self.assertLess(time.perf_counter() - t_d, 0.35)
            self.assertTrue(res_dyn["ok"], res_dyn["errors"])

        # 3b. Nested unsafe openUrl calls and single-@ reserved keys inside arrays/dicts are still caught
        raw_nested_bad = json.dumps(
            {
                "version": "1.0",
                "createSurface": {
                    "surfaceId": "dyn_nested_bad",
                    "catalogId": CANONICAL_V1_CATALOG_ID,
                    "components": [
                        {
                            "id": "root",
                            "component": "Text",
                            "text": [
                                0,
                                {},
                                {"a": 1},
                                {"@call": "openUrl", "args": {"url": "javascript:x"}},
                                {"nested": [{"@bad": 1}]},
                            ],
                        }
                    ],
                },
            },
            separators=(",", ":"),
        )
        res_nested_bad = validate_payload(raw_nested_bad, version="1.0", strict=True)
        self.assertFalse(res_nested_bad["ok"])
        nested_codes = {e["code"] for e in res_nested_bad["errors"]}
        self.assertIn("INVALID_FUNCTION_CALL_SITE", nested_codes)
        self.assertIn("UNSAFE_OPEN_URL", nested_codes)
        self.assertIn("INVALID_RESERVED_KEY", nested_codes)


if __name__ == "__main__":
    unittest.main()
