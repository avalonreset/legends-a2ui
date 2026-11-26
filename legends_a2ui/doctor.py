"""Offline and optional --live environment, vendor spec, knowledge pack, and project doctor."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path, PureWindowsPath
import re
import shutil
import subprocess
import sys
from typing import Any

from legends_a2ui import __version__
from legends_a2ui.net_safety import (
    SafetyError,
    ensure_within_base,
    reject_symlink_chain,
    safe_https_get_json,
)
from legends_a2ui.resources import get_knowledge_pack_path, get_vendor_dir
from legends_a2ui.spec_registry import (
    BROKEN_V09_CATALOG_ID,
    CANONICAL_V09_CATALOG_ID,
    CANONICAL_V1_CATALOG_ID,
    PINNED_UPSTREAM_COMMIT,
    verify_vendor_manifest,
)

MIN_A2UI_NPM_VERSION = (0, 16, 0)
_SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".venv",
        "venv",
        "dist",
        "build",
        "__pycache__",
        ".next",
        ".astro",
        "__tests__",
    }
)
_TEST_FILE_RE = re.compile(r"\.(?:test|spec)\.[^.]+$", re.IGNORECASE)
_V08_KEYS_RE = re.compile(r"\b(?:beginRendering|surfaceUpdate|dataModelUpdate)\b")
_DEFENSIVE_CONST_RE = re.compile(r"\b(?:BROKEN_V09_CATALOG_ID|LEGACY_[A-Z0-9_]*)\b")
_DEFENSIVE_PARSER_RE = re.compile(
    r"\b(?:normalizeVersion|normalizeMessage|parseA2uiPayload|upgradeLegacy)\b"
)


def _parse_semver_prefix(raw: str) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", raw)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def check_knowledge_pack(pack_path: Path | None = None) -> dict[str, Any]:
    """Verify knowledge/a2ui/pack.json schema and SHA-256 digests."""
    p = (pack_path or get_knowledge_pack_path()).resolve()
    if not p.is_file():
        return {
            "verified": False,
            "path": str(p),
            "fileCount": 0,
            "errors": [f"Knowledge pack manifest not found: {p}"],
        }
    try:
        pack = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "verified": False,
            "path": str(p),
            "fileCount": 0,
            "errors": [f"Invalid pack.json: {exc}"],
        }

    errors: list[str] = []
    if pack.get("schema") != "legends.knowledge-pack/v1":
        errors.append(f"Unexpected pack schema: {pack.get('schema')!r}")
    vault_dir = p.parent / "vault"
    files = pack.get("files", [])
    if not isinstance(files, list) or not files:
        errors.append("Knowledge pack has no files listed.")
    for item in files:
        rel = item.get("path", "")
        rel_path = Path(rel) if isinstance(rel, str) else None
        win_rel_path = PureWindowsPath(rel) if isinstance(rel, str) else None
        if (
            not isinstance(rel, str)
            or not rel
            or rel_path is None
            or win_rel_path is None
            or rel_path.is_absolute()
            or bool(rel_path.drive)
            or win_rel_path.is_absolute()
            or bool(win_rel_path.drive)
            or ".." in rel_path.parts
            or ".." in win_rel_path.parts
        ):
            errors.append(f"Unsafe pack file path: {rel!r}")
            continue
        target = vault_dir / rel
        if target.is_symlink():
            errors.append(f"Symlink refused in pack vault: {rel}")
            continue
        try:
            resolved = ensure_within_base(target, vault_dir)
        except Exception as exc:
            errors.append(str(exc))
            continue
        if not resolved.is_file():
            errors.append(f"Missing pack vault file: {rel}")
            continue
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if digest != item.get("sha256"):
            errors.append(f"SHA-256 mismatch for pack file: {rel}")

    return {
        "verified": len(errors) == 0,
        "path": str(p),
        "id": pack.get("id"),
        "module": pack.get("module"),
        "version": pack.get("version"),
        "suggestedHome": pack.get("ontology", {}).get("suggested_home"),
        "fileCount": len(files),
        "errors": errors,
        "attachCommand": f"cto-legends run legends-empire -- knowledge attach \"{p}\" --vault <vault-path>",
    }


def _probe_node() -> dict[str, Any]:
    node_bin = shutil.which("node")
    if not node_bin:
        return {"available": False, "version": None, "meetsMinimum": False}
    try:
        proc = subprocess.run(
            [node_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        ver_str = (proc.stdout or "").strip()
        parsed = _parse_semver_prefix(ver_str)
        meets = bool(parsed and parsed >= (18, 0, 0))
        return {
            "available": proc.returncode == 0,
            "version": ver_str or None,
            "meetsMinimum": meets,
        }
    except Exception:
        return {"available": False, "version": None, "meetsMinimum": False}


def _probe_playwright() -> dict[str, Any]:
    has_py = importlib.util.find_spec("playwright") is not None
    has_bin = shutil.which("playwright") is not None
    return {"available": bool(has_py or has_bin), "pythonPackage": has_py, "cli": has_bin}


def _has_active_broken_catalog_uri(text: str, *, has_canonical_both: bool) -> bool:
    """Return True if BROKEN_V09_CATALOG_ID appears outside defensive rewrite constants."""
    if BROKEN_V09_CATALOG_ID not in text:
        return False
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if BROKEN_V09_CATALOG_ID not in line:
            continue
        prev_line = lines[idx - 1] if idx > 0 else ""
        context = f"{prev_line} {line}"
        if has_canonical_both and _DEFENSIVE_CONST_RE.search(context):
            continue
        return True
    return False


def _has_active_v08_keys(text: str, *, has_canonical_both: bool) -> bool:
    """Return True if legacy v0.8 keys appear outside canonical v1.0/v0.9 upgrade parsers."""
    if not _V08_KEYS_RE.search(text):
        return False
    if (
        has_canonical_both
        and "createSurface" in text
        and "updateComponents" in text
        and _DEFENSIVE_PARSER_RE.search(text)
    ):
        return False
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if not _V08_KEYS_RE.search(line):
            continue
        prev_line = lines[idx - 1] if idx > 0 else ""
        if has_canonical_both and _DEFENSIVE_CONST_RE.search(f"{prev_line} {line}"):
            continue
        return True
    return False


def inspect_project(project_dir: Path) -> dict[str, Any]:
    """Read-only static inspection of a JS/TS/Python project for @a2ui/* drift and 404 URIs."""
    reject_symlink_chain(project_dir)
    root = project_dir.resolve()
    if not root.is_dir():
        raise SafetyError(f"Project directory does not exist: {project_dir}")

    npm_packages: dict[str, str] = {}
    py_packages: list[str] = []
    drift_warnings: list[str] = []
    broken_uri_hits: list[str] = []
    v08_key_hits: list[str] = []

    pkg_json = root / "package.json"
    if pkg_json.is_file() and not pkg_json.is_symlink():
        try:
            pdata = json.loads(pkg_json.read_text(encoding="utf-8"))
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                deps = pdata.get(section)
                if isinstance(deps, dict):
                    for name, spec in deps.items():
                        if isinstance(name, str) and name.startswith("@a2ui/") and isinstance(spec, str):
                            npm_packages[name] = spec
                            parsed = _parse_semver_prefix(spec)
                            if (
                                name in {"@a2ui/react", "@a2ui/web_core", "@a2ui/lit", "@a2ui/angular"}
                                and parsed
                                and parsed < MIN_A2UI_NPM_VERSION
                            ):
                                drift_warnings.append(
                                    f"Package {name}@{spec} is behind 0.16.0+ (upgrade recommended)."
                                )
        except Exception as exc:
            drift_warnings.append(f"Could not parse package.json: {exc}")

    pyproject = root / "pyproject.toml"
    if pyproject.is_file() and not pyproject.is_symlink():
        try:
            ptext = pyproject.read_text(encoding="utf-8", errors="replace")
            for found in re.findall(r"\ba2ui-[a-z0-9_-]+", ptext):
                if found not in py_packages:
                    py_packages.append(found)
        except Exception:
            pass

    scanned = 0
    for path in sorted(root.rglob("*")):
        if scanned >= 400:
            break
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if not path.is_file() or path.is_symlink():
            continue
        if path.name.startswith(".env"):
            continue
        if _TEST_FILE_RE.search(path.name):
            continue
        if path.suffix.lower() not in {".ts", ".tsx", ".js", ".jsx", ".md"}:
            continue
        try:
            ensure_within_base(path, root)
            if path.stat().st_size > 524_288:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        scanned += 1
        rel = path.relative_to(root).as_posix()
        has_canonical_both = (
            CANONICAL_V1_CATALOG_ID in text and CANONICAL_V09_CATALOG_ID in text
        )
        if _has_active_broken_catalog_uri(text, has_canonical_both=has_canonical_both):
            broken_uri_hits.append(rel)
        if _has_active_v08_keys(text, has_canonical_both=has_canonical_both):
            v08_key_hits.append(rel)

    if broken_uri_hits:
        drift_warnings.append(
            f"Broken 404 catalog URI ({BROKEN_V09_CATALOG_ID}) referenced in: {', '.join(broken_uri_hits[:5])}"
        )
    if v08_key_hits:
        drift_warnings.append(
            f"Legacy A2UI v0.8 envelope keys referenced in: {', '.join(v08_key_hits[:5])}"
        )

    return {
        "root": str(root),
        "filesScanned": scanned,
        "npmPackages": npm_packages,
        "pythonPackages": py_packages,
        "brokenCatalogUriFiles": broken_uri_hits,
        "legacyV08Files": v08_key_hits,
        "warnings": drift_warnings,
    }


def probe_live_upstream() -> dict[str, Any]:
    """Query pinned HTTPS allowlist registries for live A2UI ecosystem freshness."""
    npm_react = safe_https_get_json("https://registry.npmjs.org/@a2ui/react")
    pypi_core = safe_https_get_json("https://pypi.org/pypi/a2ui-core/json")
    gh_head = safe_https_get_json(
        "https://api.github.com/repos/a2ui-project/a2ui/commits/main"
    )

    latest_react = (npm_react.get("dist-tags") or {}).get("latest")
    latest_pypi = (pypi_core.get("info") or {}).get("version")
    latest_commit = gh_head.get("sha")
    return {
        "npmA2uiReactLatest": latest_react,
        "pypiA2uiCoreLatest": latest_pypi,
        "upstreamMainCommit": latest_commit,
        "pinnedCommit": PINNED_UPSTREAM_COMMIT,
        "specCommitMatchesHead": latest_commit == PINNED_UPSTREAM_COMMIT,
    }


def run_doctor(
    *,
    project_dir: Path | None = None,
    live: bool = False,
    vendor_dir: Path | None = None,
    pack_path: Path | None = None,
) -> tuple[dict[str, Any], int]:
    """Run offline (and optional --live) diagnostics. Returns (report, exit_code)."""
    errors: list[str] = []
    warnings: list[str] = []

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 11)
    if not py_ok:
        errors.append(f"Python 3.11+ is required (running {py_ver}).")

    node_info = _probe_node()
    if not node_info["available"]:
        warnings.append("Node.js not detected (optional; only needed for JS/TS renderer projects).")
    elif not node_info["meetsMinimum"]:
        warnings.append(f"Node.js {node_info['version']} is below recommended 18.0.0.")

    vendor_info = verify_vendor_manifest(vendor_dir or get_vendor_dir())
    if not vendor_info["verified"]:
        errors.extend(vendor_info["errors"])

    pack_info = check_knowledge_pack(pack_path or get_knowledge_pack_path())
    if not pack_info["verified"]:
        errors.extend(pack_info["errors"])

    playwright_info = _probe_playwright()

    project_info = None
    if project_dir is not None:
        try:
            project_info = inspect_project(project_dir)
            warnings.extend(project_info["warnings"])
        except Exception as exc:
            errors.append(str(exc))

    live_info = None
    live_error = False
    if live:
        try:
            live_info = probe_live_upstream()
            if live_info.get("upstreamMainCommit") and not live_info.get("specCommitMatchesHead"):
                warnings.append(
                    f"Upstream a2ui-project/a2ui main ({live_info['upstreamMainCommit'][:12]}) "
                    f"is ahead of vendored pin ({PINNED_UPSTREAM_COMMIT[:12]})."
                )
        except Exception as exc:
            live_error = True
            errors.append(f"Live upstream probe failed: {exc}")

    ok = len(errors) == 0
    report = {
        "ok": ok,
        "moduleVersion": __version__,
        "python": {
            "version": py_ver,
            "meetsMinimum": py_ok,
            "executable": sys.executable,
        },
        "node": node_info,
        "vendorSpec": {
            "verified": vendor_info["verified"],
            "repo": vendor_info.get("repo"),
            "commit": vendor_info.get("commit"),
            "fileCount": vendor_info.get("fileCount", 0),
        },
        "knowledgePack": {
            "verified": pack_info["verified"],
            "version": pack_info.get("version"),
            "fileCount": pack_info.get("fileCount", 0),
        },
        "playwright": playwright_info,
        "project": project_info,
        "live": live_info,
        "warnings": warnings,
        "errors": errors,
    }

    if live_error:
        return report, 3
    return report, 0 if ok else 1
