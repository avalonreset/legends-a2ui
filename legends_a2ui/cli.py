"""Command-line interface for legends-a2ui (all 11 subcommands)."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from legends_a2ui import __version__
from legends_a2ui.composer import compose_surface, list_templates
from legends_a2ui.docs_lookup import query_catalog, search_docs
from legends_a2ui.doctor import check_knowledge_pack, run_doctor
from legends_a2ui.net_safety import SafetyError, execute_write_plan, reject_symlink_chain
from legends_a2ui.normalizer import normalize_payload
from legends_a2ui.parser import DEFAULT_MAX_BYTES, DEFAULT_MAX_DEPTH, loads_strict_json
from legends_a2ui.preview_html import render_preview_html
from legends_a2ui.projector import VALID_PRESETS, project_json_to_surface
from legends_a2ui.resources import resolve_resources
from legends_a2ui.scaffolder import VALID_TARGETS, VALID_THEMES, build_scaffold_files
from legends_a2ui.validator import DEFAULT_MAX_COMPONENTS, validate_payload


def _read_input_text(input_arg: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    byte_limit = max(1, int(max_bytes)) * 4
    if input_arg == "-":
        buf = getattr(sys.stdin, "buffer", None)
        if buf is not None:
            raw_bytes = buf.read(byte_limit + 1)
            if len(raw_bytes) > byte_limit:
                raise ValueError(
                    f"Stdin input exceeds maximum read limit ({byte_limit} bytes)."
                )
            return raw_bytes.decode("utf-8-sig")
        raw_text = sys.stdin.read(byte_limit + 1)
        if len(raw_text.encode("utf-8")) > byte_limit:
            raise ValueError(
                f"Stdin input exceeds maximum read limit ({byte_limit} bytes)."
            )
        return raw_text
    path = Path(input_arg)
    reject_symlink_chain(path)
    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_arg}")
    size = path.stat().st_size
    if size > byte_limit:
        raise ValueError(f"Input file size ({size} bytes) far exceeds max_bytes ({max_bytes}).")
    return path.read_text(encoding="utf-8-sig")


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2))


def _cmd_doctor(args: argparse.Namespace) -> int:
    report, code = run_doctor(
        project_dir=Path(args.project) if args.project else None,
        live=bool(args.live),
    )
    if args.json:
        _print_json(report)
    else:
        status = "PASS" if report["ok"] else "FAIL"
        print(f"legends-a2ui v{report['moduleVersion']} doctor: {status}")
        print(f"  python: {report['python']['version']} (ok={report['python']['meetsMinimum']})")
        print(f"  node: {report['node'].get('version') or 'not found'}")
        vs = report["vendorSpec"]
        print(f"  vendorSpec: verified={vs['verified']} files={vs['fileCount']} commit={vs['commit']}")
        kp = report["knowledgePack"]
        print(f"  knowledgePack: verified={kp['verified']} files={kp['fileCount']}")
        for w in report["warnings"]:
            print(f"  [WARN] {w}")
        for e in report["errors"]:
            print(f"  [ERROR] {e}")
    return code


def _cmd_validate(args: argparse.Namespace) -> int:
    for flag_name, val in (
        ("--max-bytes", args.max_bytes),
        ("--max-components", args.max_components),
        ("--max-depth", args.max_depth),
    ):
        if val < 1:
            msg = f"{flag_name} must be >= 1 (got {val})."
            if args.json:
                _print_json({"ok": False, "error": msg})
            else:
                print(f"error: {msg}", file=sys.stderr)
            return 2

    try:
        raw = _read_input_text(args.input, max_bytes=args.max_bytes)
    except FileNotFoundError as exc:
        if args.json:
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    except (SafetyError, ValueError) as exc:
        if args.json:
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1

    res = validate_payload(
        raw,
        extract_markdown=bool(args.extract_markdown),
        version=args.version,
        strict=bool(args.strict),
        allow_warnings=bool(args.allow_warnings),
        max_bytes=args.max_bytes,
        max_components=args.max_components,
        max_depth=args.max_depth,
    )
    if args.json:
        _print_json(res)
    else:
        status = "PASS" if res["ok"] else "FAIL"
        print(
            f"validate: {status} | blocks={res['blockCount']} surfaces={len(res['surfaceIds'])} "
            f"components={res['componentCount']} errors={len(res['errors'])} warnings={len(res['warnings'])}"
        )
        for err in res["errors"]:
            print(f"  [ERROR] ({err['code']}) {err['path']}: {err['message']}")
        for warn in res["warnings"]:
            print(f"  [WARN] ({warn['code']}) {warn['path']}: {warn['message']}")
    return 0 if res["ok"] else 1


def _cmd_normalize(args: argparse.Namespace) -> int:
    try:
        raw = _read_input_text(args.input)
    except FileNotFoundError as exc:
        if args.json:
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    except (SafetyError, ValueError) as exc:
        if args.json:
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1

    res = normalize_payload(
        raw,
        extract_markdown=bool(args.extract_markdown),
        target_version=args.target,
        fmt=args.format,
        default_surface_id=args.surface_id,
    )
    if not res["ok"]:
        if args.json:
            _print_json(res)
        else:
            for err in res["validation"].get("errors", []):
                print(f"[ERROR] ({err['code']}) {err['path']}: {err['message']}", file=sys.stderr)
        return 1

    if args.output:
        try:
            plan = execute_write_plan(
                [(Path(args.output), res["formatted"].encode("utf-8"))],
                apply=bool(args.apply),
                confirm_plan=args.confirm_plan,
                overwrite=bool(args.overwrite),
            )
        except SafetyError as exc:
            if args.json:
                _print_json({"ok": False, "error": str(exc)})
            else:
                print(f"error: {exc}", file=sys.stderr)
            return 1
        out_obj = {**res, **plan}
        if args.json:
            _print_json(out_obj)
        else:
            print(
                f"normalize ({plan['mode']}): planSha256={plan['planSha256']} "
                f"applied={plan['applied']} changes={len(res['changesApplied'])}"
            )
        return 0

    if args.json:
        _print_json(res)
    else:
        sys.stdout.write(res["formatted"])
    return 0


def _cmd_compose(args: argparse.Namespace) -> int:
    if args.list:
        templates = list_templates()
        if args.json:
            _print_json({"ok": True, "templates": templates})
        else:
            for item in templates:
                print(f"{item['name']}: {item['description']}")
        return 0

    if not args.template:
        msg = "specify --template <name> or --list"
        if args.json:
            _print_json({"ok": False, "error": msg})
        else:
            print(f"error: {msg}", file=sys.stderr)
        return 2

    variables: dict[str, Any] = {}
    if args.vars_file:
        try:
            vtext = _read_input_text(args.vars_file)
            loaded = loads_strict_json(
                vtext, max_bytes=DEFAULT_MAX_BYTES, max_depth=DEFAULT_MAX_DEPTH
            )
            if not isinstance(loaded, dict):
                raise ValueError("--vars-file must contain a JSON object.")
            variables.update(loaded)
        except FileNotFoundError as exc:
            if args.json:
                _print_json({"ok": False, "error": str(exc)})
            else:
                print(f"error: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:
            if args.json:
                _print_json({"ok": False, "error": str(exc)})
            else:
                print(f"error: {exc}", file=sys.stderr)
            return 1
    if args.vars:
        try:
            loaded = loads_strict_json(
                args.vars, max_bytes=DEFAULT_MAX_BYTES, max_depth=DEFAULT_MAX_DEPTH
            )
            if not isinstance(loaded, dict):
                raise ValueError("--vars must be a JSON object.")
            variables.update(loaded)
        except Exception as exc:
            if args.json:
                _print_json({"ok": False, "error": str(exc)})
            else:
                print(f"error: {exc}", file=sys.stderr)
            return 2

    res = compose_surface(
        args.template,
        variables=variables,
        surface_id=args.surface_id,
        fmt=args.format,
    )
    if not res["ok"]:
        if args.json:
            _print_json(res)
        else:
            print(f"error: {res.get('error') or 'Validation failed'}", file=sys.stderr)
        return 1

    if args.output:
        try:
            plan = execute_write_plan(
                [(Path(args.output), res["formatted"].encode("utf-8"))],
                apply=bool(args.apply),
                confirm_plan=args.confirm_plan,
                overwrite=bool(args.overwrite),
            )
        except SafetyError as exc:
            if args.json:
                _print_json({"ok": False, "error": str(exc)})
            else:
                print(f"error: {exc}", file=sys.stderr)
            return 1
        out_obj = {**res, **plan}
        if args.json:
            _print_json(out_obj)
        else:
            print(f"compose ({plan['mode']}): planSha256={plan['planSha256']} applied={plan['applied']}")
        return 0

    if args.json:
        _print_json(res)
    else:
        sys.stdout.write(res["formatted"])
    return 0


def _cmd_project(args: argparse.Namespace) -> int:
    try:
        raw = _read_input_text(args.input)
    except FileNotFoundError as exc:
        if args.json:
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    except (SafetyError, ValueError) as exc:
        if args.json:
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1

    res = project_json_to_surface(
        raw,
        preset=args.preset,
        title=args.title,
        surface_id=args.surface_id,
        fmt=args.format,
    )
    if not res["ok"]:
        if args.json:
            _print_json(res)
        else:
            print(f"error: {res.get('error') or 'Projection failed'}", file=sys.stderr)
        return 1

    if args.output:
        try:
            plan = execute_write_plan(
                [(Path(args.output), res["formatted"].encode("utf-8"))],
                apply=bool(args.apply),
                confirm_plan=args.confirm_plan,
                overwrite=bool(args.overwrite),
            )
        except SafetyError as exc:
            if args.json:
                _print_json({"ok": False, "error": str(exc)})
            else:
                print(f"error: {exc}", file=sys.stderr)
            return 1
        out_obj = {**res, **plan}
        if args.json:
            _print_json(out_obj)
        else:
            print(
                f"project ({plan['mode']}, preset={res['preset']}): "
                f"planSha256={plan['planSha256']} applied={plan['applied']}"
            )
        return 0

    if args.json:
        _print_json(res)
    else:
        sys.stdout.write(res["formatted"])
    return 0


def _cmd_preview(args: argparse.Namespace) -> int:
    try:
        raw = _read_input_text(args.input)
    except FileNotFoundError as exc:
        if args.json:
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    except (SafetyError, ValueError) as exc:
        if args.json:
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1

    rendered = render_preview_html(
        raw,
        extract_markdown=bool(args.extract_markdown),
        theme=args.theme,
        title=args.title,
    )
    if not rendered["ok"]:
        if args.json:
            _print_json({"ok": False, "validation": rendered["validation"]})
        else:
            for err in rendered["validation"].get("errors", []):
                print(f"[ERROR] ({err['code']}) {err['path']}: {err['message']}", file=sys.stderr)
        return 1

    try:
        plan = execute_write_plan(
            [(Path(args.output), rendered["html"].encode("utf-8"))],
            apply=bool(args.apply),
            confirm_plan=args.confirm_plan,
            overwrite=bool(args.overwrite),
        )
    except SafetyError as exc:
        if args.json:
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1

    out_obj = {
        "ok": True,
        "theme": args.theme,
        "changesApplied": rendered["changesApplied"],
        **plan,
    }
    if args.json:
        _print_json(out_obj)
    else:
        print(
            f"preview ({plan['mode']}): planSha256={plan['planSha256']} "
            f"applied={plan['applied']} target={args.output}"
        )
    return 0


def _cmd_scaffold(args: argparse.Namespace) -> int:
    out_dir = Path(args.output)
    try:
        planned = build_scaffold_files(out_dir, target=args.target, theme=args.theme)
        plan = execute_write_plan(
            planned,
            apply=bool(args.apply),
            confirm_plan=args.confirm_plan,
            overwrite=bool(args.overwrite),
            base_dir=out_dir,
        )
    except (SafetyError, ValueError) as exc:
        if args.json:
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1

    out_obj = {
        "ok": True,
        "target": args.target,
        "theme": args.theme,
        **plan,
    }
    if args.json:
        _print_json(out_obj)
    else:
        print(
            f"scaffold ({plan['mode']}, target={args.target}, theme={args.theme}): "
            f"planSha256={plan['planSha256']} files={len(plan['plannedFiles'])} applied={plan['applied']}"
        )
    return 0


def _cmd_catalog(args: argparse.Namespace) -> int:
    try:
        res = query_catalog(
            version=args.version,
            component=args.component,
            function=args.function,
            list_all=bool(args.list),
        )
    except ValueError as exc:
        if args.json:
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        _print_json(res)
    else:
        if not res["ok"]:
            print(f"error: {res['error']}", file=sys.stderr)
            return 1
        if "component" in res:
            c = res["component"]
            print(f"{c['name']} (A2UI v{res['version']}, checkable={c['checkable']})")
            print(f"  required: {', '.join(c['required'])}")
            print(f"  properties: {', '.join(sorted(c['properties'].keys()))}")
        elif "function" in res:
            f = res["function"]
            print(f"{f['name']} (A2UI v{res['version']}, returnType={f['returnType']})")
            print(f"  requiredArgs: {', '.join(f['requiredArgs'])}")
        else:
            print(f"A2UI Basic Catalog v{res['version']} ({res['catalogId']})")
            print(f"  components ({res['componentCount']}): " + ", ".join(c["name"] for c in res["components"]))
            print(f"  functions ({res['functionCount']}): " + ", ".join(f["name"] for f in res["functions"]))
    return 0 if res["ok"] else 1


def _cmd_docs_lookup(args: argparse.Namespace) -> int:
    res = search_docs(
        args.query,
        version=args.version,
        live_locations=bool(args.live_locations),
        limit=args.limit,
    )
    if args.json:
        _print_json(res)
    else:
        if not res["ok"]:
            print(f"error: {res.get('error')}", file=sys.stderr)
            return 2
        print(f"docs-lookup '{res['query']}' (version={res['version']}): {res['totalMatches']} matches")
        for item in res["results"]:
            print(f"- {item['path']}:{item['startLine']}-{item['endLine']} (score={item['score']})")
            if "liveLocations" in item:
                print(f"  live: {item['liveLocations']['siteUrl']}")
    return 0 if res["ok"] else 1


def _cmd_knowledge_pack(args: argparse.Namespace) -> int:
    res = check_knowledge_pack()
    if args.json:
        _print_json(res)
    else:
        status = "VERIFIED" if res["verified"] else "INVALID"
        print(f"knowledge-pack: {status} ({res['fileCount']} files) -> {res['path']}")
        print(f"  attach: {res['attachCommand']}")
        for e in res["errors"]:
            print(f"  [ERROR] {e}")
    return 0 if res["verified"] else 1


def _cmd_resources(args: argparse.Namespace) -> int:
    info = resolve_resources()
    _print_json(info)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="legends-a2ui",
        description="Offline-first A2UI v1.0/v0.9/v0.8 validation, normalization, composition, projection, preview, and scaffolding CLI.",
    )
    parser.add_argument("--version", action="version", version=f"legends-a2ui {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # 1. doctor
    p_doc = sub.add_parser("doctor", help="Check runtime, vendor spec SHA-256, knowledge pack, and optional project/live drift.")
    p_doc.add_argument("--project", help="Optional JS/TS/Python project directory for static read-only inspection.")
    p_doc.add_argument("--live", action="store_true", help="Optional HTTPS probe to npm, PyPI, and GitHub allowlist.")
    p_doc.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    p_doc.set_defaults(func=_cmd_doctor)

    # 2. validate
    p_val = sub.add_parser("validate", help="Validate A2UI JSON, JSONL, or Markdown fences offline.")
    p_val.add_argument("--input", required=True, help="Input file path or '-' for stdin.")
    p_val.add_argument("--extract-markdown", action="store_true", help="Extract fenced ```a2ui blocks from Markdown.")
    p_val.add_argument("--version", default="auto", choices=("auto", "1.0", "0.9.1", "0.9", "0.8"))
    p_val.add_argument("--strict", action="store_true", help="Zero transitional tolerance; treat warnings as errors.")
    p_val.add_argument("--allow-warnings", action="store_true", help="Allow warnings even with --strict.")
    p_val.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    p_val.add_argument("--max-components", type=int, default=DEFAULT_MAX_COMPONENTS)
    p_val.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    p_val.add_argument("--json", action="store_true")
    p_val.set_defaults(func=_cmd_validate)

    # 3. normalize
    p_norm = sub.add_parser("normalize", help="Deterministically upgrade v0.8/v0.9/v0.9.1/draft v1.0 to strict v1.0.")
    p_norm.add_argument("--input", required=True, help="Input file path or '-' for stdin.")
    p_norm.add_argument("--extract-markdown", action="store_true")
    p_norm.add_argument("--target", default="1.0")
    p_norm.add_argument("--format", default="json", choices=("json", "jsonl", "markdown-fence"))
    p_norm.add_argument("--surface-id", default="main")
    p_norm.add_argument("--output", help="Optional file output path (preview-first unless --apply --confirm-plan).")
    p_norm.add_argument("--apply", action="store_true")
    p_norm.add_argument("--confirm-plan")
    p_norm.add_argument("--overwrite", action="store_true")
    p_norm.add_argument("--json", action="store_true")
    p_norm.set_defaults(func=_cmd_normalize)

    # 4. compose
    p_comp = sub.add_parser("compose", help="Generate validated A2UI v1.0 surfaces from 8 curated operator templates.")
    p_comp.add_argument("--list", action="store_true", help="List available templates.")
    p_comp.add_argument("--template", help="Template name.")
    p_comp.add_argument("--vars", help="JSON object string of template variables.")
    p_comp.add_argument("--vars-file", help="Path to JSON file containing template variables.")
    p_comp.add_argument("--surface-id", help="Optional custom surfaceId.")
    p_comp.add_argument("--format", default="markdown-fence", choices=("json", "jsonl", "markdown-fence"))
    p_comp.add_argument("--output", help="Optional file output path (preview-first).")
    p_comp.add_argument("--apply", action="store_true")
    p_comp.add_argument("--confirm-plan")
    p_comp.add_argument("--overwrite", action="store_true")
    p_comp.add_argument("--json", action="store_true")
    p_comp.set_defaults(func=_cmd_compose)

    # 5. project
    p_proj = sub.add_parser("project", help="Project arbitrary structured JSON into a strict A2UI v1.0 surface.")
    p_proj.add_argument("--input", required=True, help="JSON file path or '-' for stdin.")
    p_proj.add_argument("--preset", default="auto", choices=VALID_PRESETS)
    p_proj.add_argument("--title", help="Optional surface heading override.")
    p_proj.add_argument("--surface-id", help="Optional surfaceId override.")
    p_proj.add_argument("--format", default="markdown-fence", choices=("json", "jsonl", "markdown-fence"))
    p_proj.add_argument("--output", help="Optional file output path (preview-first).")
    p_proj.add_argument("--apply", action="store_true")
    p_proj.add_argument("--confirm-plan")
    p_proj.add_argument("--overwrite", action="store_true")
    p_proj.add_argument("--json", action="store_true")
    p_proj.set_defaults(func=_cmd_project)

    # 6. preview
    p_prev = sub.add_parser("preview", help="Render an offline, zero-daemon static HTML5 preview (preview-first).")
    p_prev.add_argument("--input", required=True, help="A2UI payload file path or '-' for stdin.")
    p_prev.add_argument("--extract-markdown", action="store_true")
    p_prev.add_argument("--output", required=True, help="Target .html file path.")
    p_prev.add_argument("--theme", default="precision-noir", choices=("precision-noir", "light", "auto"))
    p_prev.add_argument("--title", default="legends-a2ui Static Preview")
    p_prev.add_argument("--apply", action="store_true")
    p_prev.add_argument("--confirm-plan")
    p_prev.add_argument("--overwrite", action="store_true")
    p_prev.add_argument("--json", action="store_true")
    p_prev.set_defaults(func=_cmd_preview)

    # 7. scaffold
    p_scaf = sub.add_parser("scaffold", help="Generate a preview-first React, WebCore, or Lit integration kit.")
    p_scaf.add_argument("--target", default="react", choices=VALID_TARGETS)
    p_scaf.add_argument("--output", required=True, help="Target output directory.")
    p_scaf.add_argument("--theme", default="precision-noir", choices=VALID_THEMES)
    p_scaf.add_argument("--apply", action="store_true")
    p_scaf.add_argument("--confirm-plan")
    p_scaf.add_argument("--overwrite", action="store_true")
    p_scaf.add_argument("--json", action="store_true")
    p_scaf.set_defaults(func=_cmd_scaffold)

    # 8. catalog
    p_cat = sub.add_parser("catalog", help="Query vendored official A2UI Basic Catalog schemas offline.")
    p_cat.add_argument("--component", help="Inspect a specific component by name.")
    p_cat.add_argument("--function", help="Inspect a specific built-in function by name.")
    p_cat.add_argument("--version", default="1.0", choices=("1.0", "0.9.1", "0.9", "0.8"))
    p_cat.add_argument("--list", action="store_true", help="List all components and functions.")
    p_cat.add_argument("--json", action="store_true")
    p_cat.set_defaults(func=_cmd_catalog)

    # 9. docs-lookup
    p_dl = sub.add_parser("docs-lookup", help="Search vendored A2UI specification docs and local wiki offline.")
    p_dl.add_argument("query", help="Search query string.")
    p_dl.add_argument("--version", default="all", choices=("all", "1.0", "0.9.1", "0.9", "0.8"))
    p_dl.add_argument("--live-locations", action="store_true", help="Include upstream a2ui.org and GitHub URLs.")
    p_dl.add_argument("--limit", type=int, default=8)
    p_dl.add_argument("--json", action="store_true")
    p_dl.set_defaults(func=_cmd_docs_lookup)

    # 10. knowledge-pack
    p_kp = sub.add_parser("knowledge-pack", help="Verify knowledge/a2ui/pack.json SHA-256 and print Empire attachment info.")
    p_kp.add_argument("--check", action="store_true", help="Verify pack SHA-256 digests.")
    p_kp.add_argument("--json", action="store_true")
    p_kp.set_defaults(func=_cmd_knowledge_pack)

    # 11. resources
    p_res = sub.add_parser("resources", help="Print resolved package_data or checkout resource paths as JSON.")
    p_res.add_argument("--json", action="store_true")
    p_res.set_defaults(func=_cmd_resources)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))
