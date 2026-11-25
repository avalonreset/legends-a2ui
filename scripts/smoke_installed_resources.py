"""Smoke-verify installed legends-a2ui resources outside the source checkout."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) > 1 and Path(sys.argv[1]).is_file():
        info = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    else:
        from legends_a2ui.resources import resolve_resources

        info = resolve_resources()
    assert info["source"] == "package_data", info["source"]
    root = Path(info["root"])
    assert root.is_absolute(), info["root"]
    assert (root / "THIRD_PARTY_NOTICES.md").is_file(), "Missing THIRD_PARTY_NOTICES.md in packaged _data"
    wiki_dir = Path(info["wiki"])
    assert wiki_dir.is_dir(), str(wiki_dir)
    recipe = Path(info["recipe"])
    if not recipe.is_absolute():
        recipe = root / recipe
    assert recipe.is_file(), str(recipe)
    assert recipe.name == "AGENT-RECIPE.md", recipe.name
    pack_manifest = Path(info["pack_manifest"])
    assert pack_manifest.is_file(), str(pack_manifest)
    pack = json.loads(pack_manifest.read_text(encoding="utf-8"))
    assert pack["schema"] == "legends.knowledge-pack/v1", pack.get("schema")
    vault_dir = (pack_manifest.parent / "vault").resolve()
    for item in pack["files"]:
        rel = item["path"]
        rel_path = Path(rel)
        assert not rel_path.is_absolute() and not rel_path.drive and ".." not in rel_path.parts, rel
        target = vault_dir / rel
        assert not target.is_symlink(), rel
        resolved = target.resolve()
        assert resolved.is_relative_to(vault_dir), rel
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        assert digest == item["sha256"], item["path"]
    vendor_manifest = Path(info["vendor_manifest"])
    assert vendor_manifest.is_file(), str(vendor_manifest)
    vdata = json.loads(vendor_manifest.read_text(encoding="utf-8"))
    assert vdata["fileCount"] == 28, vdata.get("fileCount")
    print("resource smoke OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
