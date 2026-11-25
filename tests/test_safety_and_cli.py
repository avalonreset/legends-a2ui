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
    create_tls_context,
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

    def test_tls_context_helper_enforces_strict_tls_and_optional_certifi(self) -> None:
        """TLS helper enforces TLS 1.2+, check_hostname, and loads certifi when available."""
        import ssl
        from unittest import mock

        ctx = create_tls_context()
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

        # Verify opportunistic certifi loading when certifi is present
        fake_ctx = mock.MagicMock(spec=ssl.SSLContext)
        fake_certifi = mock.MagicMock()
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            ca_path = tf.name
        try:
            fake_certifi.where.return_value = ca_path
            with (
                mock.patch("legends_a2ui.net_safety.ssl.create_default_context", return_value=fake_ctx),
                mock.patch.dict("sys.modules", {"certifi": fake_certifi}),
            ):
                out_ctx = create_tls_context()
            self.assertIs(out_ctx, fake_ctx)
            self.assertEqual(fake_ctx.minimum_version, ssl.TLSVersion.TLSv1_2)
            self.assertTrue(fake_ctx.check_hostname)
            self.assertEqual(fake_ctx.verify_mode, ssl.CERT_REQUIRED)
            fake_ctx.load_verify_locations.assert_called_once_with(cafile=ca_path)
        finally:
            Path(ca_path).unlink(missing_ok=True)

        # Verify graceful stdlib-only fallback when certifi is absent
        fake_ctx2 = mock.MagicMock(spec=ssl.SSLContext)
        with (
            mock.patch("legends_a2ui.net_safety.ssl.create_default_context", return_value=fake_ctx2),
            mock.patch.dict("sys.modules", {"certifi": None}),
        ):
            out_ctx2 = create_tls_context()
        self.assertIs(out_ctx2, fake_ctx2)
        fake_ctx2.load_verify_locations.assert_not_called()

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
            # Test files and __tests__/ should be skipped during host drift inspection
            (proj / "parser.test.ts").write_text(
                f'const CAT = "{BROKEN_V09_CATALOG_ID}";\nconst LEG = "beginRendering";\n',
                encoding="utf-8",
            )
            (proj / "parser.spec.tsx").write_text(
                f'const CAT = "{BROKEN_V09_CATALOG_ID}";\n',
                encoding="utf-8",
            )
            tests_dir = proj / "__tests__"
            tests_dir.mkdir()
            (tests_dir / "compat.ts").write_text(
                f'const CAT = "{BROKEN_V09_CATALOG_ID}";\n',
                encoding="utf-8",
            )
            info = inspect_project(proj)
            self.assertIn("@a2ui/react", info["npmPackages"])
            self.assertEqual(info["brokenCatalogUriFiles"], ["parser.ts"])
            self.assertEqual(info["legacyV08Files"], ["parser.ts"])
            self.assertGreaterEqual(len(info["warnings"]), 3)

    def test_doctor_project_clean_on_scaffolds_but_flags_active_broken_v09_constant(self) -> None:
        """Freshly scaffolded kits produce zero warnings while active broken URI still flags."""
        from legends_a2ui.scaffolder import VALID_TARGETS, build_scaffold_files

        for target in VALID_TARGETS:
            with tempfile.TemporaryDirectory() as tmp:
                out_dir = Path(tmp) / target
                planned = build_scaffold_files(out_dir, target=target, theme="precision-noir")
                prev = execute_write_plan(planned, apply=False, base_dir=out_dir)
                execute_write_plan(
                    planned,
                    apply=True,
                    confirm_plan=prev["planSha256"],
                    base_dir=out_dir,
                )
                info = inspect_project(out_dir)
                self.assertEqual(info["brokenCatalogUriFiles"], [], f"{target}: {info}")
                self.assertEqual(info["legacyV08Files"], [], f"{target}: {info}")
                self.assertEqual(info["warnings"], [], f"{target}: {info}")

        # Active broken v0.9 constant (missing canonical v0.9 URI) MUST still be flagged
        with tempfile.TemporaryDirectory() as tmp:
            proj = Path(tmp)
            (proj / "a2uiParser.ts").write_text(
                'export const A2UI_V1_BASIC_CATALOG_ID = "https://a2ui.org/specification/v1_0/catalogs/basic/catalog.json";\n'
                f'export const A2UI_V09_BASIC_CATALOG_ID = "{BROKEN_V09_CATALOG_ID}";\n',
                encoding="utf-8",
            )
            info = inspect_project(proj)
            self.assertEqual(info["brokenCatalogUriFiles"], ["a2uiParser.ts"])
            self.assertEqual(len(info["warnings"]), 1)

    def test_slot_3_render_script_uses_valid_precision_noir_theme_flag(self) -> None:
        """Slot-3 card generator advertises the canonical --theme precision-noir flag."""
        root = Path(__file__).resolve().parents[1]
        render_src = (root / "scripts" / "render_cards.py").read_text(encoding="utf-8")
        self.assertIn("preview --theme precision-noir", render_src)
        self.assertNotIn("preview --theme noir", render_src)

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

    def test_plan_sha256_commits_target_and_state_and_refuses_directory_overwrite(self) -> None:
        from legends_a2ui.scaffolder import build_scaffold_files

        with tempfile.TemporaryDirectory() as tmp:
            dir_a = Path(tmp) / "dir_a"
            dir_b = Path(tmp) / "dir_b"
            plan_a = execute_write_plan(build_scaffold_files(dir_a, target="react"), apply=False, base_dir=dir_a)
            plan_b = execute_write_plan(build_scaffold_files(dir_b, target="react"), apply=False, base_dir=dir_b)
            self.assertNotEqual(plan_a["planSha256"], plan_b["planSha256"])

            # TOCTOU: existing file content change invalidates prior planSha256
            target = Path(tmp) / "state.json"
            target.write_text("v1", encoding="utf-8")
            prev = execute_write_plan([(target, b"v2")], apply=False)
            target.write_text("tampered", encoding="utf-8")
            with self.assertRaises(SafetyError):
                execute_write_plan(
                    [(target, b"v2")],
                    apply=True,
                    confirm_plan=prev["planSha256"],
                    overwrite=True,
                )

            # Directory target refused cleanly with SafetyError (and clean CLI JSON error)
            existing_dir = Path(tmp) / "already_dir"
            existing_dir.mkdir()
            with self.assertRaises(SafetyError):
                execute_write_plan([(existing_dir, b"data")], apply=False)

            code, out, _err = _run_cli(
                [
                    "compose",
                    "--template",
                    "ship-call",
                    "--output",
                    str(existing_dir),
                    "--overwrite",
                    "--json",
                ]
            )
            self.assertEqual(code, 1)
            self.assertFalse(json.loads(out)["ok"])

    def test_unc_device_paths_and_containment_guards(self) -> None:
        from legends_a2ui.doctor import check_knowledge_pack
        from legends_a2ui.net_safety import reject_unsafe_local_path

        for bad_path in (
            r"\\attacker.example\share\payload.json",
            "//attacker.example/share/out.html",
            r"\\.\PhysicalDrive0",
            r"\\?\C:\temp\a.json",
            "CON",
            "sub/NUL.txt",
            "dir/COM1",
            "LPT9.log",
        ):
            with self.assertRaises(SafetyError, msg=f"Should refuse unsafe path: {bad_path!r}"):
                reject_unsafe_local_path(bad_path)
            with self.assertRaises(SafetyError, msg=f"reject_symlink_chain should refuse: {bad_path!r}"):
                reject_symlink_chain(Path(bad_path))

        # pack.json absolute path containment refusal
        with tempfile.TemporaryDirectory() as tmp:
            troot = Path(tmp)
            outside = troot / "outside.md"
            outside.write_text("secret", encoding="utf-8")
            pack_dir = troot / "pack"
            (pack_dir / "vault").mkdir(parents=True)
            pack_file = pack_dir / "pack.json"
            import hashlib

            pack_file.write_text(
                json.dumps(
                    {
                        "schema": "legends.knowledge-pack/v1",
                        "id": "test",
                        "version": "0.1.0",
                        "files": [
                            {
                                "path": str(outside.resolve()),
                                "sha256": hashlib.sha256(outside.read_bytes()).hexdigest(),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            kp_res = check_knowledge_pack(pack_file)
            self.assertFalse(kp_res["verified"])
            self.assertTrue(any("Unsafe pack file path" in e for e in kp_res["errors"]))

    def test_ssrf_ipv6_transition_and_tls_socket_cleanup(self) -> None:
        import ssl
        from unittest import mock
        from legends_a2ui.net_safety import _PinnedHTTPSConnection

        for blocked_ip in (
            "2002:7f00:0001::",
            "2002:a9fe:a9fe::",
            "2002:6440:0001::",
            "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
            "64:ff9b::127.0.0.1",
            "64:ff9b:1::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "fe80::1%eth0",
            "2606:4700:4700::1111%1",
        ):
            self.assertFalse(is_public_ip(blocked_ip), f"Should reject non-public/transition IP: {blocked_ip}")

        self.assertTrue(is_public_ip("2606:4700:4700::1111"))
        self.assertTrue(is_public_ip("::ffff:1.1.1.1"))

        fake_sock = mock.MagicMock()
        fake_ctx = mock.MagicMock(spec=ssl.SSLContext)
        fake_ctx.wrap_socket.side_effect = ssl.SSLError("handshake failed")
        conn = _PinnedHTTPSConnection("a2ui.org", "1.1.1.1", context=fake_ctx)
        with mock.patch("legends_a2ui.net_safety.socket.create_connection", return_value=fake_sock):
            with self.assertRaises(ssl.SSLError):
                conn.connect()
        fake_sock.close.assert_called_once()

    def test_cli_bounded_stdin_positive_flags_compose_json_and_resources_wiki(self) -> None:
        from unittest import mock
        from legends_a2ui.cli import _read_input_text
        from legends_a2ui.net_safety import is_cfa_protected_path
        from legends_a2ui.resources import resolve_resources

        # Bounded stdin read fails before decoding oversized input
        fake_stdin = io.TextIOWrapper(io.BytesIO(b"x" * 200), encoding="utf-8")
        with mock.patch("sys.stdin", fake_stdin):
            with self.assertRaises(ValueError):
                _read_input_text("-", max_bytes=32)

        # Non-positive validate limits return exit code 2 with JSON error
        for flag in ("--max-bytes", "--max-components", "--max-depth"):
            code, out, _err = _run_cli(["validate", "--input", "-", flag, "0", "--json"])
            self.assertEqual(code, 2)
            self.assertFalse(json.loads(out)["ok"])

        # compose --json emits JSON error on missing template or bad vars
        code, out, _err = _run_cli(["compose", "--json"])
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(out)["ok"])

        code, out, _err = _run_cli(["compose", "--template", "ship-call", "--vars", "{bad", "--json"])
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(out)["ok"])

        # resources includes wiki directory
        info = resolve_resources()
        self.assertIn("wiki", info)
        self.assertTrue(Path(info["wiki"]).is_dir())

        # CFA fallback when SystemRoot="" on Windows
        if os.name == "nt":
            with mock.patch.dict(os.environ, {"SystemRoot": "", "OneDrive": r"D:\MockOneDrive"}, clear=False):
                self.assertTrue(is_cfa_protected_path(Path(r"C:\Windows\System32\test.txt")))
                self.assertTrue(is_cfa_protected_path(Path(r"D:\MockOneDrive\out.html")))
                self.assertTrue(is_cfa_protected_path(Path(r"C:\ProgramData\out.html")))


if __name__ == "__main__":
    unittest.main()
