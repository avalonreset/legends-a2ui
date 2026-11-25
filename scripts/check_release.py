"""Offline release checks for links, private residue, EDR hygiene, hashes, and required artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", ".venv", "dist", "build", "__pycache__", ".pytest_cache", ".integration", "node_modules"}
REQUIRED = [
    ".legends-module",
    ".legends-router-pin",
    "VERSION",
    "README.md",
    "CAPABILITIES.md",
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES.md",
    "CITATION.cff",
    "AGENTS.md",
    "SECURITY.md",
    "SUPPORT.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "MANIFEST.in",
    "pyproject.toml",
    "setup.py",
    "wiki/index.md",
    "wiki/wire-format-and-drift.md",
    "wiki/basic-catalog-reference.md",
    "wiki/react-and-lit-integration.md",
    "wiki/security-and-validation.md",
    "wiki/streaming-and-actions.md",
    "wiki/ecosystem-projection-and-preview.md",
    "references/sources.md",
    "templates/surface-receipt.md",
    "docs/AGENT-RECIPE.md",
    "docs/EMPIRE.md",
    "docs/RELEASE-READINESS.md",
    "docs/router-provenance.json",
    "docs/catalog-entry.candidate.json",
    "skills/cto-legends/SKILL.md",
    "knowledge/a2ui/pack.json",
    "vendor/a2ui-spec/manifest.json",
    "assets/manifest.json",
    "assets/banner.png",
    "assets/banner.webp",
    "assets/preview.png",
    "assets/social-preview.png",
    "assets/cards/r1/slot-1-agent-handoff.svg",
    "assets/cards/r1/slot-2-three-pillars.svg",
    "assets/cards/r1/slot-3-plain-english-chains.svg",
    "assets/cards/r1/slot-4-a2ui-architecture.svg",
    "assets/cards/r1/slot-5-unverified-vs-a2ui.svg",
    "assets/cards/r1/slot-7-message-avalon-reset.svg",
    "assets/cards/r1/slot-collection-star-shrine.svg",
    "scripts/render_cards.py",
    "scripts/smoke_installed_resources.py",
    "scripts/verify_knowledge_attachment.py",
    ".github/workflows/checks.yml",
]
TEXT_SUFFIXES = {".md", ".py", ".json", ".toml", ".yml", ".in", ".txt", ".cfg", ".ini", ".cff", ".svg"}
FORBIDDEN = [
    r"(?i)[a-z]:\\users\\",
    r"(?i)\.tail[a-z0-9]+\.ts\.net",
    r"(?i)sk_live_[a-z0-9]{12,}",
    r"(?i)rk_live_[a-z0-9]{12,}",
    r"gh[pousr]_[A-Za-z0-9]{20,}",
    r"github_pat_[A-Za-z0-9_]{22,}",
    r"sk-proj-[A-Za-z0-9_-]{20,}",
    r"sk-svcacct-[A-Za-z0-9_-]{20,}",
    r"sk-ant-[A-Za-z0-9_-]{20,}",
    r"\bASIA[0-9A-Z]{16}\b",
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    r"\bAIza[0-9A-Za-z_-]{35}\b",
    r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED |PGP )?PRIVATE KEY-----",
    r"CREATE_NO_WINDOW",
    r"0x08000000",
    r"(?i)windowsHide\s*:\s*true",
    r"(?i)-WindowStyle\s+Hidden",
    r"(?i)-ExecutionPolicy\s+Bypass",
    r"ctypes\.windll",
    r"(?i)CryptUnprotectData",
    r"(?i)GetAsyncKeyState",
    r"(?i)IndexedDB",
    r"(?i)ctolegends\.com",
    r"(?i)rccol",
]
INTERNAL_MARKERS = [
    r"(?i)\bStage\s+[0-9][a-z]?\b",
    r"\bBT-[0-9]{2,}\b",
    r"\bC[1-9]-[0-9]{2,}\b",
    r"(?i)\bCarbon\s+Pass\b",
    r"(?i)\bbattle-test\b",
]
FORBIDDEN_FILES = {".pem", ".key", ".p12", ".pfx", ".ps1", ".bat", ".cmd", ".vbs", ".ahk"}
PNG_METADATA_CHUNKS = {"tEXt", "iTXt", "zTXt", "eXIf"}
WEBP_METADATA_CHUNKS = {b"EXIF", b"XMP "}
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def image_metadata_issues(path: Path) -> list[str]:
    """Flag raster metadata chunks that can carry authoring residue."""
    try:
        raw = path.read_bytes()
    except OSError:
        return [f"Cannot read image: {path}"]
    issues: list[str] = []
    suffix = path.suffix.lower()
    if suffix == ".png":
        if raw[:8] != b"\x89PNG\r\n\x1a\n":
            return [f"Not a PNG file: {path}"]
        offset = 8
        while offset + 8 <= len(raw):
            length = struct.unpack(">I", raw[offset : offset + 4])[0]
            chunk = raw[offset + 4 : offset + 8]
            try:
                name = chunk.decode("latin1")
            except UnicodeError:
                break
            if name in PNG_METADATA_CHUNKS:
                issues.append(f"Image metadata chunk {name} in {path.name}; strip authoring residue.")
            if name == "IEND":
                break
            offset += 12 + length
    elif suffix == ".webp":
        if raw[:4] != b"RIFF" or raw[8:12] != b"WEBP":
            return [f"Not a WebP file: {path}"]
        offset = 12
        while offset + 8 <= len(raw):
            tag = raw[offset : offset + 4]
            length = struct.unpack("<I", raw[offset + 4 : offset + 8])[0]
            if tag in WEBP_METADATA_CHUNKS:
                issues.append(f"Image metadata chunk {tag!r} in {path.name}; strip authoring residue.")
                break
            offset += 8 + length + (length % 2)
    return issues


def check_links(md_path: Path, root: Path) -> list[str]:
    errors: list[str] = []
    text = md_path.read_text(encoding="utf-8-sig")
    stripped = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    stripped = re.sub(r"`[^`\n]+`", "", stripped)
    rel = md_path.relative_to(root)
    for target_link in MARKDOWN_LINK_RE.findall(stripped):
        if target_link.startswith(("https://", "http://", "mailto:", "#")):
            continue
        cleaned = unquote(target_link.split("#", 1)[0].split("?", 1)[0]).strip()
        if not cleaned or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", cleaned):
            continue
        resolved = (md_path.parent / cleaned).resolve()
        if not resolved.is_relative_to(root.resolve()) or not resolved.exists():
            errors.append(f"Broken or external local link: {rel}: {target_link}")
    return errors


def check(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    for name in REQUIRED:
        if not (root / name).is_file():
            errors.append(f"Missing required file: {name}")

    version_file = root / "VERSION"
    if version_file.is_file():
        expected_ver = version_file.read_text(encoding="utf-8-sig").strip()
        for rel_path, pattern in [
            ("pyproject.toml", rf'version\s*=\s*"{re.escape(expected_ver)}"'),
            ("legends_a2ui/__init__.py", rf'__version__\s*=\s*"{re.escape(expected_ver)}"'),
            ("CHANGELOG.md", rf"^##\s+{re.escape(expected_ver)}\s+-"),
            ("CITATION.cff", rf"^version:\s*{re.escape(expected_ver)}\s*$"),
            ("knowledge/a2ui/pack.json", rf'"version"\s*:\s*"{re.escape(expected_ver)}"'),
            ("docs/catalog-entry.candidate.json", rf'"version"\s*:\s*"{re.escape(expected_ver)}"'),
        ]:
            p = root / rel_path
            if p.is_file() and not re.search(pattern, p.read_text(encoding="utf-8-sig"), flags=re.MULTILINE):
                errors.append(f"Version mismatch (expected {expected_ver}) in {rel_path}")

    skills_dir = root / "skills"
    if skills_dir.is_dir():
        skill_files = [
            p.relative_to(skills_dir).as_posix()
            for p in skills_dir.rglob("*")
            if p.is_file()
        ]
        if skill_files != ["cto-legends/SKILL.md"]:
            errors.append(f"One-skill rule violation under skills/: {skill_files}")

    manifest = root / "assets" / "manifest.json"
    if manifest.is_file():
        try:
            mdata = json.loads(manifest.read_text(encoding="utf-8-sig"))
            entries = mdata["files"]
            if mdata.get("font_redistributed") is not False:
                errors.append("assets/manifest.json must set font_redistributed: false.")
        except (ValueError, KeyError):
            errors.append("assets/manifest.json is not a manifest with files.")
            entries = []
        manifest_names: set[str] = set()
        for entry in entries:
            ename = entry.get("name", "")
            manifest_names.add(ename)
            target = root / "assets" / ename
            try:
                raw = target.read_bytes()
            except OSError:
                errors.append(f"Manifest asset missing: {ename}")
                continue
            if len(raw) != entry.get("bytes"):
                errors.append(f"Manifest byte mismatch: {ename}")
            if hashlib.sha256(raw).hexdigest() != entry.get("sha256"):
                errors.append(f"Manifest hash mismatch: {ename}")
        expected_assets = {
            "banner.png",
            "banner.webp",
            "preview.png",
            "social-preview.png",
            "cards/r1/slot-1-agent-handoff.svg",
            "cards/r1/slot-2-three-pillars.svg",
            "cards/r1/slot-3-plain-english-chains.svg",
            "cards/r1/slot-4-a2ui-architecture.svg",
            "cards/r1/slot-5-unverified-vs-a2ui.svg",
            "cards/r1/slot-7-message-avalon-reset.svg",
            "cards/r1/slot-collection-star-shrine.svg",
        }
        missing_in_manifest = sorted(expected_assets - manifest_names)
        if missing_in_manifest:
            errors.append(f"assets/manifest.json missing expected assets: {missing_in_manifest}")

    prov_path = root / "docs" / "router-provenance.json"
    skill_path = root / "skills" / "cto-legends" / "SKILL.md"
    if prov_path.is_file() and skill_path.is_file():
        prov = json.loads(prov_path.read_text(encoding="utf-8-sig"))
        if hashlib.sha256(skill_path.read_bytes()).hexdigest() != prov.get("sha256"):
            errors.append("skills/cto-legends/SKILL.md hash does not match router-provenance.json")

    pack_path = root / "knowledge" / "a2ui" / "pack.json"
    if pack_path.is_file():
        try:
            pack = json.loads(pack_path.read_text(encoding="utf-8-sig"))
            vault_dir = (pack_path.parent / "vault").resolve()
            for f_entry in pack.get("files", []):
                rel_p = f_entry.get("path", "")
                rp = Path(rel_p) if isinstance(rel_p, str) else None
                if not isinstance(rel_p, str) or not rel_p or rp is None or rp.is_absolute() or bool(rp.drive) or ".." in rp.parts:
                    errors.append(f"Unsafe pack file path: {rel_p!r}")
                    continue
                v_target = vault_dir / rel_p
                if v_target.is_symlink():
                    errors.append(f"Symlink refused in pack vault: {rel_p}")
                    continue
                v_resolved = v_target.resolve()
                if not v_resolved.is_relative_to(vault_dir):
                    errors.append(f"Pack file escapes vault containment: {rel_p}")
                    continue
                if not v_resolved.is_file():
                    errors.append(f"Pack file missing: {rel_p}")
                elif hashlib.sha256(v_resolved.read_bytes()).hexdigest() != f_entry.get("sha256"):
                    errors.append(f"Pack file hash mismatch: {rel_p}")
        except Exception as exc:
            errors.append(f"Invalid knowledge/a2ui/pack.json: {exc}")

    vendor_manifest = root / "vendor" / "a2ui-spec" / "manifest.json"
    if vendor_manifest.is_file():
        try:
            v_data = json.loads(vendor_manifest.read_text(encoding="utf-8-sig"))
            v_base = vendor_manifest.parent.resolve()
            for item in v_data.get("files", []):
                rel_p = item.get("localPath", "")
                rp = Path(rel_p) if isinstance(rel_p, str) else None
                if not isinstance(rel_p, str) or not rel_p or rp is None or rp.is_absolute() or bool(rp.drive) or ".." in rp.parts:
                    errors.append(f"Unsafe vendor spec path: {rel_p!r}")
                    continue
                vf = v_base / rel_p
                if vf.is_symlink() or not vf.resolve().is_relative_to(v_base):
                    errors.append(f"Vendor spec escapes containment: {rel_p}")
                    continue
                if not vf.is_file():
                    errors.append(f"Missing vendor spec file: {rel_p}")
                elif hashlib.sha256(vf.read_bytes()).hexdigest() != item.get("sha256"):
                    errors.append(f"Vendor spec hash mismatch: {rel_p}")
        except Exception as exc:
            errors.append(f"Invalid vendor/a2ui-spec/manifest.json: {exc}")

    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if not path.is_file() or any(p in SKIP or p.endswith(".egg-info") for p in rel.parts):
            continue
        if path.suffix.lower() in FORBIDDEN_FILES:
            errors.append(f"Forbidden file extension must not ship: {rel}")
            continue
        if path.suffix.lower() in {".png", ".webp"}:
            errors.extend(f"{rel}: {issue}" for issue in image_metadata_issues(path))
            continue
        if path.suffix not in TEXT_SUFFIXES and path.name not in {"LICENSE", "NOTICE", ".legends-module", ".legends-router-pin"}:
            continue
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffd]", text):
            errors.append(f"Control character or replacement character in text file: {rel}")
        if path.name != "check_release.py" and not rel.as_posix().startswith("tests/"):
            for pattern in FORBIDDEN:
                if re.search(pattern, text):
                    errors.append(f"Possible private or EDR-sensitive residue ({pattern}): {rel}")
        if rel.as_posix().startswith("vendor/"):
            continue
        if path.name != "check_release.py":
            for marker in INTERNAL_MARKERS:
                if re.search(marker, text):
                    errors.append(f"Internal pipeline marker ({marker}) must not ship: {rel}")
        if "\u2014" in text or "\u2013" in text:
            errors.append(f"Disallowed em/en-dash in non-vendor file: {rel}")
        if path.suffix == ".md":
            errors.extend(check_links(path, root))

    if (root / ".git").exists():
        try:
            proc = subprocess.run(
                ["git", "-C", str(root), "log", "--format=%H%x20%B"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    for marker in INTERNAL_MARKERS:
                        if re.search(marker, line):
                            errors.append(f"Internal pipeline marker ({marker}) in git log: {line}")
        except OSError:
            pass
    return errors


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Offline release checks.")
    parser.add_argument("--root", type=Path, default=ROOT)
    options = parser.parse_args()
    failures = check(options.root)
    for failure in failures:
        print(failure)
    print(f"Release checks: {'FAIL' if failures else 'PASS'} ({len(failures)} issues)")
    sys.exit(bool(failures))
