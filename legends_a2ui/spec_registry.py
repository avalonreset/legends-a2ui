"""Offline A2UI vendored specification registry, UAX #31 IDs, URL safety, and secret scan."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from legends_a2ui.net_safety import ensure_within_base
from legends_a2ui.resources import get_vendor_dir

CANONICAL_V1_CATALOG_ID = "https://a2ui.org/specification/v1_0/catalogs/basic/catalog.json"
CANONICAL_V09_CATALOG_ID = "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json"
CANONICAL_V08_CATALOG_ID = "https://a2ui.org/specification/v0_8/standard_catalog_definition.json"
BROKEN_V09_CATALOG_ID = "https://a2ui.org/specification/v0_9/basic_catalog.json"
PINNED_UPSTREAM_REPO = "a2ui-project/a2ui"
PINNED_UPSTREAM_COMMIT = "92c0ed6eccb499fe22fba49cb8185b058442c56a"

CATALOG_RELATIVE_PATHS = {
    "1.0": "catalogs/basic/v1/catalog.json",
    "0.9.1": "catalogs/basic/v0_9_1/catalog.json",
    "0.9": "catalogs/basic/v0_9/catalog.json",
    "0.8": "v0_8/json/standard_catalog_definition.json",
}

_SAFE_DATA_MEDIA_RE = re.compile(
    r"^data:(?:image/(?:png|jpeg|jpg|gif|webp|avif|bmp)|(?:audio|video)/[a-z0-9.+-]+)[;,]",
    re.IGNORECASE,
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("stripe_live_secret", re.compile(r"\bsk_live_[A-Za-z0-9]{12,}\b")),
    ("stripe_restricted_key", re.compile(r"\brk_live_[A-Za-z0-9]{12,}\b")),
    ("stripe_webhook_secret", re.compile(r"\bwhsec_[A-Za-z0-9]{12,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("github_fine_grained_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("openai_project_key", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b")),
    ("openai_service_account_key", re.compile(r"\bsk-svcacct-[A-Za-z0-9_-]{20,}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    (
        "private_key_pem",
        re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED |PGP )?PRIVATE KEY-----"),
    ),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_temp_access_key_id", re.compile(r"\bASIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    (
        "aws_secret_assignment",
        re.compile(r"(?i)\bAWS_SECRET_ACCESS_KEY\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{16,}"),
    ),
    (
        "bearer_jwt",
        re.compile(
            r"(?i)\bBearer\s+eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]*)?"
        ),
    ),
    (
        "raw_jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\b"
        ),
    ),
)

_CATALOG_CACHE: dict[tuple[str, str], dict[str, Any]] = {}


def is_uax31_start(ch: str) -> bool:
    return isinstance(ch, str) and len(ch) == 1 and ch.isidentifier()


def is_uax31_continue(ch: str) -> bool:
    return isinstance(ch, str) and len(ch) == 1 and f"a{ch}".isidentifier()


def is_valid_uax31_id(value: str) -> bool:
    """Validate Unicode UAX #31 identifier syntax via Python's str.isidentifier()."""
    return isinstance(value, str) and bool(value) and value.isidentifier()


def sanitize_uax31_id(raw: str) -> str:
    """Sanitize an arbitrary string into a valid UAX #31 identifier deterministically."""
    if is_valid_uax31_id(raw):
        return raw
    chars: list[str] = []
    prev_underscore = False
    for ch in str(raw):
        if is_uax31_continue(ch):
            chars.append(ch)
            prev_underscore = ch == "_"
        else:
            if not prev_underscore:
                chars.append("_")
                prev_underscore = True
    cleaned = "".join(chars).strip("_")
    if not cleaned:
        return "c_id"
    if not is_uax31_start(cleaned[0]):
        cleaned = f"c_{cleaned}"
    return cleaned


def validate_media_url(raw_url: str) -> tuple[bool, str | None]:
    """Validate media URLs per official A2UI Basic Catalog implementation guide."""
    if not isinstance(raw_url, str):
        return False, "Media URL must be a string."
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw_url):
        return False, "Media URL contains disallowed control or whitespace-smuggling characters."
    trimmed = raw_url.strip()
    if not trimmed:
        return False, "Media URL must not be empty."

    normalized_slashes = trimmed.replace("\\", "/")
    if normalized_slashes.startswith("//"):
        return False, "Scheme-relative or UNC media URLs (//host or \\\\host) are disallowed."
    if trimmed.startswith("/") and not trimmed.startswith("/\\"):
        return True, None

    scheme_match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):(.*)$", trimmed)
    if not scheme_match:
        return (
            False,
            "Media URL must use http:, https:, data:, or a single-slash relative path (/...).",
        )

    scheme = scheme_match.group(1).lower()
    rest = scheme_match.group(2)

    if scheme in {"http", "https"}:
        if not rest.startswith("//"):
            return False, f"{scheme}: media URL must include // and a host."
        parsed = urlsplit(trimmed)
        if not parsed.netloc or not parsed.hostname or any(ch.isspace() for ch in parsed.netloc):
            return False, f"{scheme}: media URL must include a valid non-empty host."
        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            return False, f"{scheme}: media URL must not contain userinfo credentials."
        return True, None

    if scheme == "data":
        if _SAFE_DATA_MEDIA_RE.match(trimmed):
            return True, None
        return (
            False,
            "data: media URLs must declare a safe raster image/ (png, jpeg, jpg, gif, webp, avif, bmp), audio/, or video/ media type.",
        )

    return False, f"Disallowed media URL scheme: {scheme}:"


def validate_open_url(raw_url: str) -> tuple[bool, str | None]:
    """Validate interactive openUrl action targets strictly (https:, http:, mailto: only)."""
    if not isinstance(raw_url, str):
        return False, "openUrl target must be a string."
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw_url):
        return False, "openUrl target contains disallowed control characters."
    trimmed = raw_url.strip()
    if not trimmed:
        return False, "openUrl target must not be empty."

    normalized_slashes = trimmed.replace("\\", "/")
    if normalized_slashes.startswith("//"):
        return False, "Scheme-relative URLs are not allowed in openUrl."

    scheme_match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):(.*)$", trimmed)
    if not scheme_match:
        return False, "openUrl target must specify https:, http:, or mailto: scheme."

    scheme = scheme_match.group(1).lower()
    rest = scheme_match.group(2)
    if scheme in {"https", "http"}:
        if not rest.startswith("//"):
            return False, f"{scheme}: openUrl target must include // and a host."
        parsed = urlsplit(trimmed)
        if not parsed.netloc or not parsed.hostname or any(ch.isspace() for ch in parsed.netloc):
            return False, f"{scheme}: openUrl target must include a valid host."
        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            return False, f"{scheme}: openUrl target must not contain userinfo credentials."
        return True, None
    if scheme == "mailto":
        if not rest.strip() or "@" not in rest:
            return False, "mailto: openUrl target must include an email address."
        return True, None
    return False, f"Disallowed openUrl scheme '{scheme}:' (only https:, http:, mailto: allowed)."


def _scan_str_for_secrets(
    text: str,
    cur_path: str,
    msg_template: str,
    findings: list[dict[str, str]],
) -> None:
    if len(text) < 15:
        return
    has_underscore = "_" in text
    has_dot = "." in text
    low: str | None = None
    for rule_name, pattern in _SECRET_PATTERNS:
        if rule_name == "stripe_live_secret":
            if "sk_live_" not in text:
                continue
        elif rule_name == "stripe_restricted_key":
            if "rk_live_" not in text:
                continue
        elif rule_name == "stripe_webhook_secret":
            if "whsec_" not in text:
                continue
        elif rule_name == "github_token":
            if not has_underscore or "gh" not in text:
                continue
        elif rule_name == "github_fine_grained_pat":
            if "github_pat_" not in text:
                continue
        elif rule_name == "openai_project_key":
            if "sk-proj-" not in text:
                continue
        elif rule_name == "openai_service_account_key":
            if "sk-svcacct-" not in text:
                continue
        elif rule_name == "anthropic_api_key":
            if "sk-ant-" not in text:
                continue
        elif rule_name == "private_key_pem":
            if "PRIVATE KEY-----" not in text:
                continue
        elif rule_name == "aws_access_key_id":
            if "AKIA" not in text:
                continue
        elif rule_name == "aws_temp_access_key_id":
            if "ASIA" not in text:
                continue
        elif rule_name == "slack_token":
            if "xox" not in text:
                continue
        elif rule_name == "google_api_key":
            if "AIza" not in text:
                continue
        elif rule_name == "aws_secret_assignment":
            if not has_underscore:
                continue
            if low is None:
                low = text.lower()
            if "aws_secret_access_key" not in low:
                continue
        elif rule_name == "bearer_jwt":
            if not has_dot:
                continue
            if low is None:
                low = text.lower()
            if "eyj" not in low or "bearer" not in low:
                continue
        elif rule_name == "raw_jwt":
            if not has_dot or "eyJ" not in text:
                continue
        if pattern.search(text):
            findings.append(
                {
                    "path": cur_path,
                    "rule": rule_name,
                    "message": msg_template.format(rule_name=rule_name),
                }
            )


def scan_for_secrets(obj: Any, path: str = "$") -> list[dict[str, str]]:
    """Iteratively scan JSON-compatible objects for leaked API keys, tokens, or private keys."""
    findings: list[dict[str, str]] = []
    stack: list[tuple[Any, str]] = [(obj, path)]
    while stack:
        current, cur_path = stack.pop()
        if isinstance(current, str):
            _scan_str_for_secrets(
                current,
                cur_path,
                "Potential secret detected ({rule_name}); redacted and refused.",
                findings,
            )
        elif isinstance(current, dict):
            for key, val in current.items():
                if isinstance(val, (str, dict, list)):
                    stack.append((val, f"{cur_path}.{key}"))
                if isinstance(key, str) and len(key) >= 15:
                    _scan_str_for_secrets(
                        key,
                        f"{cur_path}.{key}",
                        "Potential secret in key ({rule_name}); redacted and refused.",
                        findings,
                    )
        elif isinstance(current, list):
            for idx in range(len(current) - 1, -1, -1):
                item = current[idx]
                if isinstance(item, (str, dict, list)):
                    stack.append((item, f"{cur_path}[{idx}]"))
    return findings


def verify_vendor_manifest(vendor_dir: Path | None = None) -> dict[str, Any]:
    """Verify SHA-256 digests and containment for every file in vendor/a2ui-spec/manifest.json."""
    vdir = (vendor_dir or get_vendor_dir()).resolve()
    manifest_path = vdir / "manifest.json"
    if not manifest_path.is_file():
        return {
            "verified": False,
            "commit": None,
            "repo": None,
            "fileCount": 0,
            "errors": [f"Missing vendor manifest: {manifest_path}"],
        }
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {
            "verified": False,
            "commit": None,
            "repo": None,
            "fileCount": 0,
            "errors": [f"Invalid vendor manifest JSON: {exc}"],
        }

    errors: list[str] = []
    files = manifest.get("files", [])
    if not isinstance(files, list) or not files:
        errors.append("Vendor manifest contains no file entries.")

    for item in files:
        local_path = item.get("localPath", "")
        if not isinstance(local_path, str) or not local_path or ".." in Path(local_path).parts:
            errors.append(f"Unsafe localPath in vendor manifest: {local_path!r}")
            continue
        if Path(local_path).is_absolute() or bool(Path(local_path).drive):
            errors.append(f"Absolute or drive-prefixed localPath refused in vendor manifest: {local_path!r}")
            continue
        target = vdir / local_path
        try:
            resolved = ensure_within_base(target, vdir)
        except Exception as exc:
            errors.append(str(exc))
            continue
        if not resolved.is_file():
            errors.append(f"Missing vendored spec file: {local_path}")
            continue
        raw = resolved.read_bytes()
        expected_bytes = item.get("bytes")
        if expected_bytes is not None and len(raw) != expected_bytes:
            errors.append(
                f"Byte size mismatch for {local_path}: expected {expected_bytes}, got {len(raw)}"
            )
        digest = hashlib.sha256(raw).hexdigest()
        if digest != item.get("sha256"):
            errors.append(f"SHA-256 mismatch for {local_path}")

    return {
        "verified": len(errors) == 0,
        "repo": manifest.get("repo"),
        "commit": manifest.get("commit"),
        "license": manifest.get("license"),
        "fileCount": len(files),
        "errors": errors,
    }


def _extract_component_entry(name: str, raw_schema: dict[str, Any]) -> dict[str, Any]:
    """Flatten direct and allOf component schema blocks from official A2UI catalog JSON."""
    properties: dict[str, Any] = {}
    required: list[str] = []
    checkable = False
    description = raw_schema.get("description", "")

    def merge_block(block: dict[str, Any]) -> None:
        nonlocal checkable
        ref = block.get("$ref", "")
        if isinstance(ref, str) and ref.endswith("/Checkable"):
            checkable = True
        if isinstance(block.get("properties"), dict):
            for prop_name, prop_def in block["properties"].items():
                if not isinstance(prop_def, dict):
                    continue
                summary: dict[str, Any] = {}
                if "type" in prop_def:
                    summary["type"] = prop_def["type"]
                if "const" in prop_def:
                    summary["const"] = prop_def["const"]
                if "enum" in prop_def:
                    summary["enum"] = list(prop_def["enum"])
                if "default" in prop_def:
                    summary["default"] = prop_def["default"]
                if "$ref" in prop_def:
                    summary["ref"] = prop_def["$ref"]
                if "description" in prop_def:
                    summary["description"] = prop_def["description"]
                if "oneOf" in prop_def:
                    for sub in prop_def["oneOf"]:
                        if isinstance(sub, dict) and "enum" in sub:
                            summary["enum"] = list(sub["enum"])
                properties[prop_name] = summary
        if isinstance(block.get("required"), list):
            for req in block["required"]:
                if isinstance(req, str) and req not in required:
                    required.append(req)

    merge_block(raw_schema)
    for sub in raw_schema.get("allOf", []):
        if isinstance(sub, dict):
            merge_block(sub)

    return {
        "name": name,
        "description": description,
        "checkable": checkable,
        "required": required,
        "properties": properties,
    }


def _extract_function_entry(name: str, raw_schema: dict[str, Any]) -> dict[str, Any]:
    args_schema = raw_schema.get("properties", {}).get("args", {})
    args_props: dict[str, Any] = {}
    if isinstance(args_schema.get("properties"), dict):
        for arg_name, arg_def in args_schema["properties"].items():
            if isinstance(arg_def, dict):
                args_props[arg_name] = {
                    k: v
                    for k, v in arg_def.items()
                    if k in {"type", "description", "default", "enum", "$ref", "minimum", "maximum"}
                }
    return {
        "name": name,
        "description": raw_schema.get("description", ""),
        "returnType": raw_schema.get("returnType"),
        "requiresUserActivation": bool(raw_schema.get("requiresUserActivation", False)),
        "allowedCallers": raw_schema.get("allowedCallers"),
        "requiredArgs": list(args_schema.get("required", [])),
        "args": args_props,
    }


def normalize_version_arg(version: str) -> str:
    cleaned = version.strip().lower().lstrip("v")
    if cleaned in {"1", "1.0"}:
        return "1.0"
    if cleaned in {"0.9.1", "0.9", "0.8"}:
        return cleaned
    raise ValueError(f"Unsupported A2UI protocol version: {version}")


def load_catalog_spec(version: str = "1.0", vendor_dir: Path | None = None) -> dict[str, Any]:
    """Load and parse the vendored official Basic/Standard Catalog schema for a version."""
    norm_ver = normalize_version_arg(version)
    if vendor_dir is None:
        default_key = ("", norm_ver)
        cached = _CATALOG_CACHE.get(default_key)
        if cached is not None:
            return cached
        vdir = get_vendor_dir().resolve()
        cache_key = (str(vdir), norm_ver)
        cached = _CATALOG_CACHE.get(cache_key)
        if cached is not None:
            _CATALOG_CACHE[default_key] = cached
            return cached
    else:
        default_key = None
        vdir = vendor_dir.resolve()
        cache_key = (str(vdir), norm_ver)
        cached = _CATALOG_CACHE.get(cache_key)
        if cached is not None:
            return cached

    rel_path = CATALOG_RELATIVE_PATHS[norm_ver]
    schema_path = ensure_within_base(vdir / rel_path, vdir)
    raw = json.loads(schema_path.read_text(encoding="utf-8"))

    components: dict[str, dict[str, Any]] = {}
    for comp_name, comp_schema in raw.get("components", {}).items():
        if isinstance(comp_schema, dict):
            components[comp_name] = _extract_component_entry(comp_name, comp_schema)

    functions: dict[str, dict[str, Any]] = {}
    raw_funcs = raw.get("functions", {})
    if isinstance(raw_funcs, dict):
        for fn_name, fn_schema in raw_funcs.items():
            if isinstance(fn_schema, dict):
                functions[fn_name] = _extract_function_entry(fn_name, fn_schema)
    elif isinstance(raw_funcs, list):
        for fn_schema in raw_funcs:
            if isinstance(fn_schema, dict) and isinstance(fn_schema.get("name"), str):
                functions[fn_schema["name"]] = _extract_function_entry(
                    fn_schema["name"], fn_schema
                )

    result = {
        "version": norm_ver,
        "catalogId": raw.get("catalogId")
        or (
            CANONICAL_V08_CATALOG_ID
            if norm_ver == "0.8"
            else CANONICAL_V1_CATALOG_ID
            if norm_ver == "1.0"
            else CANONICAL_V09_CATALOG_ID
        ),
        "schemaPath": str(schema_path),
        "relativePath": rel_path,
        "componentCount": len(components),
        "functionCount": len(functions),
        "components": components,
        "functions": functions,
    }
    _CATALOG_CACHE[cache_key] = result
    if default_key is not None:
        _CATALOG_CACHE[default_key] = result
    return result
