"""Tests for compose (8 templates), project (3 presets), preview HTML, and scaffold kits."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from legends_a2ui.composer import TEMPLATES, compose_surface, list_templates
from legends_a2ui.doctor import run_doctor
from legends_a2ui.net_safety import SafetyError, execute_write_plan
from legends_a2ui.preview_html import STRICT_CSP, render_preview_html
from legends_a2ui.projector import project_json_to_surface
from legends_a2ui.scaffolder import VALID_TARGETS, VALID_THEMES, build_scaffold_files
from legends_a2ui.validator import validate_payload


class TestComposeProjectPreviewScaffold(unittest.TestCase):
    def test_compose_all_8_templates_pass_strict_validation(self) -> None:
        listed = list_templates()
        self.assertEqual(len(listed), 8)
        for name in TEMPLATES:
            for fmt in ("json", "jsonl", "markdown-fence"):
                res = compose_surface(
                    name,
                    variables={"title": f"Test {name}"},
                    fmt=fmt,
                )
                self.assertTrue(res["ok"], f"{name} ({fmt}) failed: {res['validation']}")
                extract_md = fmt == "markdown-fence"
                v = validate_payload(res["formatted"], extract_markdown=extract_md, version="1.0", strict=True)
                self.assertTrue(v["ok"], f"Strict re-validate failed for {name}/{fmt}: {v['errors']}")

    def test_project_all_3_presets_and_auto_detection_and_secret_refusal(self) -> None:
        # 1. plan-approval auto-detected from preview JSON
        plan_json = {
            "mode": "preview",
            "applied": False,
            "planSha256": "a" * 64,
            "plannedFiles": [
                {"path": "a2uiParser.ts", "bytes": 4200, "exists": False},
                {"path": "a2uiTheme.css", "bytes": 1800, "exists": True},
            ],
            "warnings": ["Existing CSS will require --overwrite"],
        }
        p1 = project_json_to_surface(json.dumps(plan_json), preset="auto", fmt="json")
        self.assertTrue(p1["ok"], p1["validation"])
        self.assertEqual(p1["preset"], "plan-approval")
        self.assertTrue(validate_payload(p1["formatted"], version="1.0", strict=True)["ok"])

        # 2. health-deck auto-detected from doctor --json output
        doc_report, _code = run_doctor()
        p2 = project_json_to_surface(json.dumps(doc_report), preset="auto", fmt="json")
        self.assertTrue(p2["ok"], p2["validation"])
        self.assertEqual(p2["preset"], "health-deck")
        self.assertTrue(validate_payload(p2["formatted"], version="1.0", strict=True)["ok"])

        # 3. data-briefing auto-detected from nested report JSON (2..5 sections -> Tabs)
        nested = {
            "title": "Q4 Readiness",
            "status": "green",
            "metrics": {"passRate": "100%", "latencyMs": 12},
            "components": {"total": 18, "checkable": 6},
            "actions": ["verify", "deploy"],
        }
        p3 = project_json_to_surface(json.dumps(nested), preset="auto", fmt="json")
        self.assertTrue(p3["ok"], p3["validation"])
        self.assertEqual(p3["preset"], "data-briefing")
        comps = p3["payload"][0]["createSurface"]["components"]
        self.assertTrue(any(c.get("component") == "Tabs" for c in comps))

        # 4. Secret leak refused fail-closed
        leaked = {"title": "Bad", "token": "sk_" + "live_" + "9876543210fedcba"}
        p4 = project_json_to_surface(json.dumps(leaked), preset="auto", fmt="json")
        self.assertFalse(p4["ok"])
        self.assertIn("SECRET_LEAK", {e["code"] for e in p4["validation"]["errors"]})

    def test_preview_html_security_csp_xss_themes_and_18_components(self) -> None:
        composed = compose_surface(
            "ship-call",
            variables={"title": "Ship </script><script>alert(1)</script>"},
            fmt="json",
        )
        self.assertTrue(composed["ok"])

        dark = render_preview_html(composed["formatted"], theme="precision-noir")
        self.assertTrue(dark["ok"])
        doc = dark["html"]
        self.assertIn(STRICT_CSP, doc)
        self.assertIn("<\\/script>", doc)
        self.assertNotIn("https://cdn.", doc)
        self.assertNotIn("unpkg.com", doc)
        self.assertIn('body class="a2ui-dark"', doc)
        self.assertIn("#9e0b1a", doc)
        # All 18 Basic Catalog component handlers exist in runtime JS
        for comp_name in (
            "Text", "Image", "Icon", "Video", "AudioPlayer", "Row", "Column", "List",
            "Card", "Tabs", "Modal", "Divider", "Button", "TextField", "CheckBox",
            "ChoicePicker", "Slider", "DateTimeInput",
        ):
            self.assertIn(f'"{comp_name}"', doc)

        light = render_preview_html(composed["formatted"], theme="light")
        self.assertTrue(light["ok"])
        self.assertIn('body class="a2ui-light"', light["html"])

        # Preview-first planSha256 gate on disk write
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "preview.html"
            preview_plan = execute_write_plan([(out_file, doc.encode("utf-8"))], apply=False)
            self.assertEqual(preview_plan["mode"], "preview")
            self.assertFalse(out_file.exists())
            with self.assertRaises(SafetyError):
                execute_write_plan([(out_file, doc.encode("utf-8"))], apply=True, confirm_plan="wrong")
            applied = execute_write_plan(
                [(out_file, doc.encode("utf-8"))],
                apply=True,
                confirm_plan=preview_plan["planSha256"],
            )
            self.assertTrue(applied["applied"])
            self.assertTrue(out_file.is_file())

    def test_scaffold_all_targets_and_themes_preview_first(self) -> None:
        for target in VALID_TARGETS:
            for theme in VALID_THEMES:
                with tempfile.TemporaryDirectory() as tmp:
                    out_dir = Path(tmp) / f"{target}_{theme}"
                    planned = build_scaffold_files(out_dir, target=target, theme=theme)
                    prev = execute_write_plan(planned, apply=False, base_dir=out_dir)
                    self.assertEqual(prev["mode"], "preview")
                    self.assertFalse(out_dir.exists())
                    applied = execute_write_plan(
                        planned,
                        apply=True,
                        confirm_plan=prev["planSha256"],
                        base_dir=out_dir,
                    )
                    self.assertTrue(applied["applied"])
                    self.assertTrue((out_dir / "a2uiParser.ts").is_file())
                    self.assertTrue((out_dir / "a2uiSecurity.ts").is_file())
                    self.assertTrue((out_dir / "a2uiTheme.css").is_file())
                    self.assertTrue((out_dir / "a2uiParser.test.ts").is_file())
                    self.assertTrue((out_dir / "README-INTEGRATION.md").is_file())
                    parser_src = (out_dir / "a2uiParser.ts").read_text(encoding="utf-8")
                    self.assertIn("https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json", parser_src)
                    self.assertIn("https://a2ui.org/specification/v1_0/catalogs/basic/catalog.json", parser_src)


if __name__ == "__main__":
    unittest.main()
