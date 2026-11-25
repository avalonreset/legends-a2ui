"""Tests for net_safety guards (CWE-22, CWE-59, CFA, no-clobber), doctor, and CLI exit codes."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from legends_a2ui import __version__
from legends_a2ui.cli import main
from legends_a2ui.doctor import inspect_project
from legends_a2ui.net_safety import (
    SafetyError,
    ensure_within_base,
    execute_write_plan,
    is_public_ip,
    reject_cfa_protected_path,
    reject_symlink_chain,
)
from legends_a2ui.spec_registry import BROKEN_V09_CATALOG_ID


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
        try:
            code = main(argv)
        except SystemExit as exc:
            code = int(exc.code) if isinstance(exc.code, int) else 0
    return code, stdout_buf.getvalue(), stderr_buf.getvalue()


class TestSafetyAndCli(unittest.TestCase):
    def test_cwe22_path_traversal_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "sandbox"
            base.mkdir()
            escaped = base / ".." / "outside.txt"
            with self.assertRaises(SafetyError):
                ensure_within_base(escaped, base)

    def test_cwe59_symlink_refused(self) -> None:
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_dir = root / "real"
            real_dir.mkdir()
            link_dir = root / "link"
            created_real = False
            try:
                os.symlink(real_dir, link_dir, target_is_directory=True)
                created_real = True
            except (OSError, NotImplementedError):
                link_dir.mkdir()

            if created_real:
                with self.assertRaises(SafetyError):
                    reject_symlink_chain(link_dir / "file.txt")
            else:
                target_link = link_dir.resolve()
                with mock.patch(
                    "legends_a2ui.net_safety._is_reparse_point",
                    side_effect=lambda p: p.resolve() == target_link,
                ):
                    with self.assertRaises(SafetyError):
                        reject_symlink_chain(link_dir / "file.txt")

    def test_cwe400_bounds_and_reserved_surface_and_weight_rule(self) -> None:
        from legends_a2ui.spec_registry import CANONICAL_V1_CATALOG_ID
        from legends_a2ui.validator import validate_payload

        # max_bytes exceeded
        res_bytes = validate_payload("{" + (" " * 200) + "}", max_bytes=64)
        self.assertFalse(res_bytes["ok"])
        self.assertIn("MAX_BYTES_EXCEEDED", {e["code"] for e in res_bytes["errors"]})

        # max_depth exceeded
        deep = "[" * 70 + "]" * 70
        res_depth = validate_payload(deep, max_depth=32)
        self.assertFalse(res_depth["ok"])
        self.assertIn("MAX_DEPTH_EXCEEDED", {e["code"] for e in res_depth["errors"]})

        # Reserved "Surface" component & weight under Card (non-Row/Column)
        payload = {
            "version": "1.0",
            "createSurface": {
                "surfaceId": "rules_test",
                "catalogId": CANONICAL_V1_CATALOG_ID,
                "components": [
                    {"id": "root", "component": "Card", "child": "inner_txt"},
                    {"id": "inner_txt", "component": "Text", "text": "Hi", "weight": 1},
                    {"id": "bad_surface", "component": "Surface", "child": "root"},
                ],
            },
        }
        res_rules = validate_payload(json.dumps(payload), strict=True)
        self.assertFalse(res_rules["ok"])
        codes = {e["code"] for e in res_rules["errors"]}
        self.assertIn("RESERVED_COMPONENT_SURFACE", codes)
        self.assertIn("INVALID_WEIGHT_PARENT", codes)

    def test_cfa_protected_folder_refused(self) -> None:
        docs_target = Path.home() / "Documents" / "should_never_write.html"
        with self.assertRaises(SafetyError):
            reject_cfa_protected_path(docs_target)
        desktop_target = Path.home() / "Desktop" / "should_never_write.html"
        with self.assertRaises(SafetyError):
            reject_cfa_protected_path(desktop_target)

    def test_no_clobber_and_overwrite_enforcement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "out.json"
            target.write_text("existing", encoding="utf-8")
            plan = execute_write_plan([(target, b"updated")], apply=False)
            with self.assertRaises(SafetyError):
                execute_write_plan(
                    [(target, b"updated")],
                    apply=True,
                    confirm_plan=plan["planSha256"],
                    overwrite=False,
                )
            self.assertEqual(target.read_text(encoding="utf-8"), "existing")
            applied = execute_write_plan(
                [(target, b"updated")],
                apply=True,
                confirm_plan=plan["planSha256"],
                overwrite=True,
            )
            self.assertTrue(applied["applied"])
            self.assertEqual(target.read_text(encoding="utf-8"), "updated")

    def test_cwe918_ip_classifier(self) -> None:
        self.assertFalse(is_public_ip("127.0.0.1"))
        self.assertFalse(is_public_ip("10.0.0.1"))
        self.assertFalse(is_public_ip("192.168.1.5"))
        self.assertFalse(is_public_ip("169.254.169.254"))
        self.assertFalse(is_public_ip("100.64.0.1"))
        self.assertFalse(is_public_ip("::1"))
        self.assertTrue(is_public_ip("1.1.1.1"))

    def test_doctor_project_static_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proj = Path(tmp)
            (proj / "package.json").write_text(
                json.dumps({"dependencies": {"@a2ui/react": "0.15.0", "@a2ui/web_core": "0.15.0"}}),
                encoding="utf-8",
            )
            (proj / "parser.ts").write_text(
                f'const CAT = "{BROKEN_V09_CATALOG_ID}";\nconst LEG = "beginRendering";\n',
                encoding="utf-8",
            )
            info = inspect_project(proj)
            self.assertIn("@a2ui/react", info["npmPackages"])
            self.assertEqual(info["brokenCatalogUriFiles"], ["parser.ts"])
            self.assertEqual(info["legacyV08Files"], ["parser.ts"])
            self.assertGreaterEqual(len(info["warnings"]), 3)

    def test_cli_all_subcommands_and_exit_codes(self) -> None:
        # --version
        code, out, _err = _run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn(__version__, out)

        # doctor --json
        code, out, _err = _run_cli(["doctor", "--json"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertTrue(doc["ok"])
        self.assertTrue(doc["vendorSpec"]["verified"])
        self.assertEqual(doc["vendorSpec"]["fileCount"], 28)
        self.assertTrue(doc["knowledgePack"]["verified"])

        # resources
        code, out, _err = _run_cli(["resources"])
        self.assertEqual(code, 0)
        res = json.loads(out)
        self.assertIn(res["source"], ("checkout", "package_data"))
        self.assertTrue(Path(res["vendor_manifest"]).is_file())

        # knowledge-pack --check --json
        code, out, _err = _run_cli(["knowledge-pack", "--check", "--json"])
        self.assertEqual(code, 0)
        kp = json.loads(out)
        self.assertTrue(kp["verified"])

        # catalog --list --json
        code, out, _err = _run_cli(["catalog", "--list", "--version", "1.0", "--json"])
        self.assertEqual(code, 0)
        cat = json.loads(out)
        self.assertEqual(cat["componentCount"], 18)

        # docs-lookup
        code, out, _err = _run_cli(["docs-lookup", "DataBinding", "--version", "1.0", "--json"])
        self.assertEqual(code, 0)
        dl = json.loads(out)
        self.assertTrue(dl["ok"])
        self.assertGreater(len(dl["results"]), 0)

        # compose -> validate -> preview -> scaffold roundtrip
        with tempfile.TemporaryDirectory() as tmp:
            surface_path = Path(tmp) / "surface.json"
            code, out, _err = _run_cli(["compose", "--template", "ship-call", "--format", "json"])
            self.assertEqual(code, 0)
            surface_path.write_text(out, encoding="utf-8")

            code, out, _err = _run_cli(["validate", "--input", str(surface_path), "--strict", "--json"])
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(out)["ok"])

            # project doctor JSON -> surface
            doc_path = Path(tmp) / "doctor.json"
            doc_path.write_text(json.dumps(doc), encoding="utf-8")
            code, out, _err = _run_cli(["project", "--input", str(doc_path), "--preset", "auto", "--json"])
            self.assertEqual(code, 0)
            proj_res = json.loads(out)
            self.assertTrue(proj_res["ok"])
            self.assertEqual(proj_res["preset"], "health-deck")

            # preview (preview-first then apply)
            html_path = Path(tmp) / "out.html"
            code, out, _err = _run_cli(["preview", "--input", str(surface_path), "--output", str(html_path), "--json"])
            self.assertEqual(code, 0)
            prev_res = json.loads(out)
            self.assertEqual(prev_res["mode"], "preview")
            self.assertFalse(html_path.exists())

            code, out, _err = _run_cli([
                "preview", "--input", str(surface_path), "--output", str(html_path),
                "--apply", "--confirm-plan", prev_res["planSha256"], "--json",
            ])
            self.assertEqual(code, 0)
            self.assertTrue(html_path.is_file())

            # scaffold (preview-first then apply)
            kit_dir = Path(tmp) / "kit"
            code, out, _err = _run_cli(["scaffold", "--target", "react", "--output", str(kit_dir), "--json"])
            self.assertEqual(code, 0)
            scaf_prev = json.loads(out)
            self.assertFalse(kit_dir.exists())
            code, out, _err = _run_cli([
                "scaffold", "--target", "react", "--output", str(kit_dir),
                "--apply", "--confirm-plan", scaf_prev["planSha256"], "--json",
            ])
            self.assertEqual(code, 0)
            self.assertTrue((kit_dir / "A2uiBlock.tsx").is_file())

        # Missing input file -> exit code 2
        code, _out, _err = _run_cli(["validate", "--input", "nonexistent_a2ui_file_12345.json", "--json"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
