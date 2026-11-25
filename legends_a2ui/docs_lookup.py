"""Offline Basic Catalog inspector and vendored spec + wiki docs search."""
from __future__ import annotations

import json
import math
from pathlib import Path
import re
from typing import Any

from legends_a2ui.resources import get_vendor_dir, get_wiki_dir
from legends_a2ui.spec_registry import (
    PINNED_UPSTREAM_COMMIT,
    PINNED_UPSTREAM_REPO,
    load_catalog_spec,
)

_TOKEN_RE = re.compile(r"[a-z0-9_@.-]+")


def query_catalog(
    *,
    version: str = "1.0",
    component: str | None = None,
    function: str | None = None,
    list_all: bool = False,
) -> dict[str, Any]:
    """Query vendored official A2UI Basic/Standard Catalog offline."""
    spec = load_catalog_spec(version)
    if component:
        comp_map = spec["components"]
        exact = comp_map.get(component)
        if exact is None:
            for k, v in comp_map.items():
                if k.lower() == component.lower():
                    exact = v
                    break
        if exact is None:
            return {
                "ok": False,
                "version": spec["version"],
                "catalogId": spec["catalogId"],
                "error": f"Component '{component}' not found in Basic Catalog v{spec['version']}.",
                "availableComponents": sorted(comp_map.keys()),
            }
        return {
            "ok": True,
            "version": spec["version"],
            "catalogId": spec["catalogId"],
            "component": exact,
        }

    if function:
        fn_map = spec["functions"]
        exact_fn = fn_map.get(function)
        if exact_fn is None:
            for k, v in fn_map.items():
                if k.lower() == function.lower():
                    exact_fn = v
                    break
        if exact_fn is None:
            return {
                "ok": False,
                "version": spec["version"],
                "catalogId": spec["catalogId"],
                "error": f"Function '{function}' not found in Basic Catalog v{spec['version']}.",
                "availableFunctions": sorted(fn_map.keys()),
            }
        return {
            "ok": True,
            "version": spec["version"],
            "catalogId": spec["catalogId"],
            "function": exact_fn,
        }

    # Default or --list
    return {
        "ok": True,
        "version": spec["version"],
        "catalogId": spec["catalogId"],
        "componentCount": spec["componentCount"],
        "functionCount": spec["functionCount"],
        "components": [
            {
                "name": c["name"],
                "checkable": c["checkable"],
                "required": c["required"],
            }
            for c in spec["components"].values()
        ],
        "functions": [
            {
                "name": f["name"],
                "returnType": f["returnType"],
                "requiredArgs": f["requiredArgs"],
            }
            for f in spec["functions"].values()
        ],
    }


def _file_matches_version(rel_posix: str, version: str) -> bool:
    if version == "all":
        return True
    v = version.lstrip("v")
    if rel_posix.startswith("wiki/"):
        return True
    if v == "1.0":
        return "v1_0/" in rel_posix or "basic/v1/" in rel_posix or rel_posix.endswith("versions.json")
    if v == "0.9.1":
        return "v0_9_1/" in rel_posix or rel_posix.endswith("versions.json")
    if v == "0.9":
        return "v0_9/" in rel_posix or rel_posix.endswith("versions.json")
    if v == "0.8":
        return "v0_8/" in rel_posix or rel_posix.endswith("versions.json")
    return True


def _live_locations_for_vendor_file(upstream_path: str) -> dict[str, str]:
    raw_url = f"https://raw.githubusercontent.com/{PINNED_UPSTREAM_REPO}/{PINNED_UPSTREAM_COMMIT}/{upstream_path}"
    github_url = f"https://github.com/{PINNED_UPSTREAM_REPO}/blob/{PINNED_UPSTREAM_COMMIT}/{upstream_path}"
    site_url = "https://a2ui.org/llms.txt"
    if upstream_path.startswith("specification/"):
        site_url = f"https://a2ui.org/{upstream_path}"
    elif upstream_path == "catalogs/basic/v1/catalog.json":
        site_url = "https://a2ui.org/specification/v1_0/catalogs/basic/catalog.json"
    elif upstream_path == "catalogs/basic/v0_9/catalog.json":
        site_url = "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json"
    elif upstream_path == "catalogs/basic/v0_9_1/catalog.json":
        site_url = "https://a2ui.org/specification/v0_9_1/catalogs/basic/catalog.json"
    return {
        "siteUrl": site_url,
        "rawUrl": raw_url,
        "githubUrl": github_url,
    }


def search_docs(
    query: str,
    *,
    version: str = "all",
    live_locations: bool = False,
    limit: int = 8,
    vendor_dir: Path | None = None,
    wiki_dir: Path | None = None,
) -> dict[str, Any]:
    """Deterministic offline keyword/BM25-style search over vendored A2UI specs and wiki."""
    tokens = _TOKEN_RE.findall(query.lower())
    if not tokens:
        return {
            "ok": False,
            "query": query,
            "version": version,
            "results": [],
            "error": "Query must contain at least one search term.",
        }

    vdir = (vendor_dir or get_vendor_dir()).resolve()
    wdir = (wiki_dir or get_wiki_dir()).resolve()

    upstream_map: dict[str, str] = {}
    manifest_path = vdir / "manifest.json"
    if manifest_path.is_file():
        try:
            mdata = json.loads(manifest_path.read_text(encoding="utf-8"))
            for item in mdata.get("files", []):
                if isinstance(item.get("localPath"), str) and isinstance(item.get("upstreamPath"), str):
                    upstream_map[item["localPath"]] = item["upstreamPath"]
        except Exception:
            pass

    docs: list[dict[str, Any]] = []
    if vdir.is_dir():
        for path in sorted(vdir.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".md", ".json"}:
                continue
            if path.name == "manifest.json":
                continue
            rel = path.relative_to(vdir).as_posix()
            display_rel = f"vendor/a2ui-spec/{rel}"
            if not _file_matches_version(display_rel, version):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            docs.append(
                {
                    "source": "vendor",
                    "localPath": display_rel,
                    "absolutePath": str(path),
                    "upstreamPath": upstream_map.get(rel),
                    "lines": text.splitlines(),
                    "lower": text.lower(),
                }
            )

    if wdir.is_dir():
        for path in sorted(wdir.rglob("*.md")):
            if not path.is_file():
                continue
            rel = f"wiki/{path.relative_to(wdir).as_posix()}"
            text = path.read_text(encoding="utf-8", errors="replace")
            docs.append(
                {
                    "source": "wiki",
                    "localPath": rel,
                    "absolutePath": str(path),
                    "upstreamPath": None,
                    "lines": text.splitlines(),
                    "lower": text.lower(),
                }
            )

    doc_count = max(1, len(docs))
    df: dict[str, int] = {tok: 0 for tok in set(tokens)}
    for doc in docs:
        for tok in df:
            if tok in doc["lower"]:
                df[tok] += 1

    scored: list[dict[str, Any]] = []
    phrase = query.strip().lower()

    for doc in docs:
        score = 0.0
        lower_text = doc["lower"]
        for tok in tokens:
            tf = lower_text.count(tok)
            if tf > 0:
                idf = math.log((doc_count + 1) / (df[tok] + 1)) + 1.0
                score += (1.0 + math.log(tf)) * idf
        if phrase and phrase in lower_text:
            score += 4.0
        if any(tok in doc["localPath"].lower() for tok in tokens):
            score += 1.5
        if score <= 0.0:
            continue

        # Locate best matching line window
        best_line = 1
        best_hits = -1
        lines = doc["lines"]
        for lno, line in enumerate(lines, start=1):
            ll = line.lower()
            hits = sum(1 for tok in set(tokens) if tok in ll)
            if phrase and phrase in ll:
                hits += 3
            if hits > best_hits:
                best_hits = hits
                best_line = lno

        start_l = max(1, best_line - 1)
        end_l = min(len(lines), best_line + 3)
        snippet = "\n".join(lines[start_l - 1 : end_l]).strip()
        if len(snippet) > 360:
            snippet = snippet[:357] + "..."

        entry: dict[str, Any] = {
            "source": doc["source"],
            "path": doc["localPath"],
            "startLine": start_l,
            "endLine": end_l,
            "score": round(score, 3),
            "snippet": snippet,
        }
        if live_locations and doc["upstreamPath"]:
            entry["liveLocations"] = _live_locations_for_vendor_file(doc["upstreamPath"])
        scored.append(entry)

    scored.sort(key=lambda item: (-item["score"], item["path"]))
    return {
        "ok": True,
        "query": query,
        "version": version,
        "totalMatches": len(scored),
        "results": scored[: max(1, limit)],
        "pinnedUpstream": {
            "repo": PINNED_UPSTREAM_REPO,
            "commit": PINNED_UPSTREAM_COMMIT,
            "llmsTxt": "https://a2ui.org/llms.txt",
        },
    }
