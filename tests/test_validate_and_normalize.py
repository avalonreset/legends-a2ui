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


if __name__ == "__main__":
    unittest.main()
