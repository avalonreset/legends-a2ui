"""Resolve packaged _data resources or repository checkout paths cleanly."""
from __future__ import annotations

from pathlib import Path
from typing import Any


def resolve_resources() -> dict[str, Any]:
    """Return resolved resource locations from installed wheel _data or repo checkout."""
    pkg_dir = Path(__file__).resolve().parent
    data_dir = pkg_dir / "_data"
    if (data_dir / "docs" / "AGENT-RECIPE.md").is_file() and (
        data_dir / "vendor" / "a2ui-spec" / "manifest.json"
    ).is_file():
        root = data_dir.resolve()
        source = "package_data"
    else:
        root = pkg_dir.parent.resolve()
        source = "checkout"

    return {
        "source": source,
        "root": str(root),
        "recipe": str((root / "docs" / "AGENT-RECIPE.md").resolve()),
        "pack_manifest": str((root / "knowledge" / "a2ui" / "pack.json").resolve()),
        "vendor_manifest": str((root / "vendor" / "a2ui-spec" / "manifest.json").resolve()),
        "wiki": str((root / "wiki").resolve()),
    }


def get_resource_root() -> Path:
    return Path(resolve_resources()["root"])


def get_vendor_dir() -> Path:
    return Path(resolve_resources()["vendor_manifest"]).parent


def get_knowledge_pack_path() -> Path:
    return Path(resolve_resources()["pack_manifest"])


def get_wiki_dir() -> Path:
    return get_resource_root() / "wiki"
