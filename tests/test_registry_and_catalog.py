"""Tests for vendored spec SHA-256 verification, UAX #31 IDs, URL safety, and catalog queries."""
from __future__ import annotations

import unittest

from legends_a2ui.docs_lookup import query_catalog, search_docs
from legends_a2ui.spec_registry import (
    PINNED_UPSTREAM_COMMIT,
    is_valid_uax31_id,
    load_catalog_spec,
    sanitize_uax31_id,
    validate_media_url,
    validate_open_url,
    verify_vendor_manifest,
)

ALL_18_V1_COMPONENTS = [
    "Text",
    "Image",
    "Icon",
    "Video",
    "AudioPlayer",
    "Row",
    "Column",
    "List",
    "Card",
    "Tabs",
    "Modal",
    "Divider",
    "Button",
    "TextField",
    "CheckBox",
    "ChoicePicker",
    "Slider",
    "DateTimeInput",
]


class TestRegistryAndCatalog(unittest.TestCase):
    def test_vendor_manifest_sha256_all_28_files(self) -> None:
        res = verify_vendor_manifest()
        self.assertTrue(res["verified"], res["errors"])
        self.assertEqual(res["fileCount"], 28)
        self.assertEqual(res["commit"], PINNED_UPSTREAM_COMMIT)
        self.assertEqual(res["repo"], "a2ui-project/a2ui")

    def test_catalog_all_18_components_v1_v09_v08(self) -> None:
        v1 = load_catalog_spec("1.0")
        self.assertEqual(v1["componentCount"], 18)
        for name in ALL_18_V1_COMPONENTS:
            res = query_catalog(version="1.0", component=name)
            self.assertTrue(res["ok"], f"Missing {name} in v1.0")
            self.assertEqual(res["component"]["name"], name)

        # Verify v1.0 TextField requires value and Text only allows body/caption
        tf_v1 = query_catalog(version="1.0", component="TextField")["component"]
        self.assertIn("value", tf_v1["required"])
        self.assertTrue(tf_v1["checkable"])
        txt_v1 = query_catalog(version="1.0", component="Text")["component"]
        self.assertEqual(set(txt_v1["properties"]["variant"]["enum"]), {"body", "caption"})

        # Verify v0.9 allows h1..h5 on Text
        txt_v09 = query_catalog(version="0.9", component="Text")["component"]
        self.assertIn("h1", txt_v09["properties"]["variant"]["enum"])
        self.assertEqual(load_catalog_spec("0.9")["componentCount"], 18)
        self.assertEqual(load_catalog_spec("0.9.1")["componentCount"], 18)

        # Verify v0.8 has MultipleChoice instead of ChoicePicker
        v08 = load_catalog_spec("0.8")
        self.assertEqual(v08["componentCount"], 18)
        self.assertIn("MultipleChoice", v08["components"])

    def test_catalog_builtin_functions(self) -> None:
        for fn in ("openUrl", "required", "regex", "length", "numeric", "email", "formatString"):
            res = query_catalog(version="1.0", function=fn)
            self.assertTrue(res["ok"], f"Missing function {fn}")
            self.assertEqual(res["function"]["name"], fn)
        open_url = query_catalog(version="1.0", function="openUrl")["function"]
        self.assertIn("url", open_url["requiredArgs"])

    def test_uax31_id_validation_and_sanitization(self) -> None:
        self.assertTrue(is_valid_uax31_id("root"))
        self.assertTrue(is_valid_uax31_id("_valid_123"))
        self.assertTrue(is_valid_uax31_id("caf\u00e9_btn"))
        self.assertTrue(is_valid_uax31_id("a\u00b7b"))
        self.assertFalse(is_valid_uax31_id("\u2e2f"))
        self.assertFalse(is_valid_uax31_id("\u037a"))
        self.assertFalse(is_valid_uax31_id("\u0e33"))
        self.assertFalse(is_valid_uax31_id("submit-btn"))
        self.assertFalse(is_valid_uax31_id("1st_item"))
        self.assertFalse(is_valid_uax31_id("has space"))
        self.assertFalse(is_valid_uax31_id(""))
        self.assertEqual(sanitize_uax31_id("submit-btn"), "submit_btn")
        self.assertEqual(sanitize_uax31_id("1st-item"), "c_1st_item")
        self.assertTrue(is_valid_uax31_id(sanitize_uax31_id("---")))

    def test_url_safety_validators(self) -> None:
        # Media URLs
        self.assertTrue(validate_media_url("https://example.com/img.png")[0])
        self.assertTrue(validate_media_url("http://example.com/a.mp4")[0])
        self.assertTrue(validate_media_url("data:image/png;base64,iVBOR")[0])
        self.assertTrue(validate_media_url("data:image/webp;base64,UklGR")[0])
        self.assertTrue(validate_media_url("data:audio/mpeg;base64,AA==")[0])
        self.assertTrue(validate_media_url("data:video/mp4;base64,AA==")[0])
        self.assertTrue(validate_media_url("/assets/banner.png")[0])

        for bad in (
            "ht\ttps://example.com/a.png",
            "https://example.com/a\n.png",
            "//evil.com/x.png",
            "\\\\evil.com\\x.png",
            "https:example.com/a.png",
            "javascript:alert(1)",
            "vbscript:msgbox(1)",
            "file:///etc/passwd",
            "blob:https://example.com/id",
            "ftp://example.com/a.png",
            "data:text/html,<script>alert(1)</script>",
            "data:image/svg+xml,<svg onload=alert(1)>",
            "data:image/svg+xml;base64,PHN2Zz4=",
            "https://user:pass@example.com/a.png",
            "https://a2ui.org@evil.example/a.png",
        ):
            self.assertFalse(validate_media_url(bad)[0], f"Should reject media URL: {bad!r}")

        # openUrl targets
        self.assertTrue(validate_open_url("https://a2ui.org")[0])
        self.assertTrue(validate_open_url("http://example.com/docs")[0])
        self.assertTrue(validate_open_url("mailto:ops@example.com")[0])
        for bad in (
            "javascript:alert(1)",
            "data:text/html,hi",
            "file:///etc/hosts",
            "vbscript:foo",
            "//evil.com/phish",
            "/relative/path",
            "https://a2ui.org@evil.example/phish",
            "https://user:secret@example.com/docs",
        ):
            self.assertFalse(validate_open_url(bad)[0], f"Should reject openUrl: {bad!r}")

    def test_expanded_secret_scanner_patterns(self) -> None:
        from legends_a2ui.spec_registry import scan_for_secrets

        tokens = [
            "github_" + "pat_" + ("A" * 24),
            "sk-" + "proj-" + ("B" * 24),
            "sk-" + "svcacct-" + ("C" * 24),
            "sk-" + "ant-" + ("D" * 24),
            "AS" + "IA" + ("1234567890ABCDEF"),
            "xo" + "xb-" + ("1234567890-abcdef"),
            "AI" + "za" + ("E" * 35),
            "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN " + "PGP PRIVATE KEY-----",
        ]
        for tok in tokens:
            hits = scan_for_secrets({"val": tok})
            self.assertGreaterEqual(len(hits), 1, f"Failed to detect secret format: {tok[:8]}...")
            for hit in hits:
                self.assertNotIn(tok, hit["message"])

        # Unicode casefold equivalence for case-insensitive secret patterns (e.g. U+017F long s)
        long_s_hits = scan_for_secrets({"val": "AWS_\u017fecret_access_key=0123456789abcdef"})
        self.assertIn("aws_secret_assignment", {h["rule"] for h in long_s_hits})
        kelvin_hits = scan_for_secrets({"val": "AWS_SECRET_ACCESS_\u212aEY=0123456789abcdef"})
        self.assertIn("aws_secret_assignment", {h["rule"] for h in kelvin_hits})

    def test_url_length_bounds(self) -> None:
        self.assertTrue(validate_open_url("https://example.com/" + ("a" * 16_300))[0])
        ok_open, reason_open = validate_open_url("https://example.com/" + ("a" * 16_400))
        self.assertFalse(ok_open)
        self.assertIn("16384", reason_open or "")

        self.assertTrue(validate_media_url("https://example.com/" + ("a" * 16_300))[0])
        ok_media, reason_media = validate_media_url("https://example.com/" + ("a" * 16_400))
        self.assertFalse(ok_media)
        self.assertIn("16384", reason_media or "")

        self.assertTrue(validate_media_url("data:image/png;base64," + ("A" * 20_000))[0])
        ok_data, reason_data = validate_media_url("data:image/png;base64," + ("A" * 1_050_000))
        self.assertFalse(ok_data)
        self.assertIn("1048576", reason_data or "")
        self.assertFalse(validate_media_url("  data:image/png;base64," + ("A" * 1_050_000))[0])

    def test_docs_lookup_offline_and_live_locations(self) -> None:
        res = search_docs("Checkable", version="1.0", live_locations=True, limit=5)
        self.assertTrue(res["ok"])
        self.assertGreater(len(res["results"]), 0)
        first = res["results"][0]
        self.assertIn("path", first)
        self.assertIn("liveLocations", first)
        self.assertIn(PINNED_UPSTREAM_COMMIT, first["liveLocations"]["rawUrl"])


if __name__ == "__main__":
    unittest.main()
