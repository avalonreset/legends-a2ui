"""Preview-first A2UI host integration kit scaffolder (react, web-core, lit)."""
from __future__ import annotations

from pathlib import Path

VALID_TARGETS = ("react", "web-core", "lit")
VALID_THEMES = ("precision-noir", "neutral")

_A2UI_PARSER_TS = """export const A2UI_V1_BASIC_CATALOG_ID =
  "https://a2ui.org/specification/v1_0/catalogs/basic/catalog.json";
export const A2UI_V09_BASIC_CATALOG_ID =
  "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json";
const BROKEN_V09_CATALOG_ID =
  "https://a2ui.org/specification/v0_9/basic_catalog.json";

export interface A2uiParseResult {
  status: "empty" | "streaming" | "ready" | "error";
  messages: Record<string, unknown>[];
  error?: string;
}

const KNOWN_KEYS = new Set([
  "createSurface",
  "updateComponents",
  "updateDataModel",
  "deleteSurface",
  "callRendererFunction",
  "agentFunctionResponse",
  "beginRendering",
  "surfaceUpdate",
  "dataModelUpdate",
]);

const HEADING_PREFIX: Record<string, string> = {
  h1: "# ",
  h2: "## ",
  h3: "### ",
  h4: "#### ",
  h5: "##### ",
};

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function sanitizeUax31Id(rawId: string): string {
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(rawId)) return rawId;
  const cleaned = rawId.replace(/[^A-Za-z0-9_]+/g, "_").replace(/^_+|_+$/g, "");
  if (!cleaned) return "c_id";
  return /^[A-Za-z_]/.test(cleaned) ? cleaned : `c_${cleaned}`;
}

function normalizeVersion(rawVersion: unknown, msg: Record<string, unknown>): string {
  if (typeof rawVersion === "string") {
    const t = rawVersion.trim().toLowerCase();
    if (t === "1.0" || t === "v1.0" || t === "1") return "1.0";
    if (t === "0.9.1" || t === "v0.9.1") return "v0.9.1";
    if (t === "0.9" || t === "v0.9") return "v0.9";
    if (t === "0.8" || t === "v0.8") return "v0.8";
  }
  if ("beginRendering" in msg || "surfaceUpdate" in msg || "dataModelUpdate" in msg) {
    return "v0.8";
  }
  return "1.0";
}

function normalizeComponent(raw: unknown): unknown {
  if (!isObj(raw)) return raw;
  const comp: Record<string, unknown> = { ...raw };
  if (comp.component === "Text" && typeof comp.variant === "string") {
    const low = comp.variant.toLowerCase();
    if (low in HEADING_PREFIX) {
      comp.variant = "body";
      if (typeof comp.text === "string" && !comp.text.trimStart().startsWith("#")) {
        comp.text = `${HEADING_PREFIX[low]}${comp.text}`;
      }
    } else if (low !== "body" && low !== "caption") {
      comp.variant = "body";
    }
  }
  if (comp.component === "Button" && typeof comp.variant === "string") {
    const low = comp.variant.toLowerCase();
    if (low !== "default" && low !== "primary" && low !== "borderless") {
      comp.variant = "default";
    }
  }
  return comp;
}

function normalizeMessage(raw: unknown): Record<string, unknown> | null {
  if (!isObj(raw)) return null;
  if (!Object.keys(raw).some((k) => KNOWN_KEYS.has(k))) return null;
  const msg: Record<string, unknown> = { ...raw };
  const ver = normalizeVersion(msg.version, msg);
  if (ver !== "v0.8") msg.version = ver;

  if (isObj(msg.createSurface)) {
    const cs: Record<string, unknown> = { ...msg.createSurface };
    const defaultCat = ver === "1.0" ? A2UI_V1_BASIC_CATALOG_ID : A2UI_V09_BASIC_CATALOG_ID;
    if (
      typeof cs.catalogId !== "string" ||
      !cs.catalogId.trim() ||
      cs.catalogId === "basic" ||
      cs.catalogId === "standard" ||
      cs.catalogId === BROKEN_V09_CATALOG_ID
    ) {
      cs.catalogId = defaultCat;
    }
    if (ver === "1.0") {
      delete cs.theme;
      if (Array.isArray(cs.components)) {
        cs.components = cs.components.map(normalizeComponent);
      }
    }
    msg.createSurface = cs;
  }
  if (isObj(msg.updateComponents) && ver === "1.0" && Array.isArray(msg.updateComponents.components)) {
    msg.updateComponents = {
      ...msg.updateComponents,
      components: msg.updateComponents.components.map(normalizeComponent),
    };
  }
  return msg;
}

export function parseA2uiPayload(raw: string, isStreaming = false): A2uiParseResult {
  const trimmed = raw.trim();
  if (!trimmed) {
    return isStreaming ? { status: "streaming", messages: [] } : { status: "empty", messages: [] };
  }
  try {
    const parsed: unknown = JSON.parse(trimmed);
    const items = Array.isArray(parsed)
      ? parsed
      : isObj(parsed) && Array.isArray(parsed.messages)
        ? parsed.messages
        : [parsed];
    const msgs = items.map(normalizeMessage).filter((m): m is Record<string, unknown> => m !== null);
    if (msgs.length > 0) return { status: "ready", messages: msgs };
    return { status: "error", messages: [], error: "No recognized A2UI messages found." };
  } catch {
    // Fall through to JSONL parsing
  }

  const lines = trimmed.split(/\\r?\\n/).map((l) => l.trim()).filter(Boolean);
  const msgs: Record<string, unknown>[] = [];
  let bad = 0;
  for (let i = 0; i < lines.length; i += 1) {
    try {
      const m = normalizeMessage(JSON.parse(lines[i]!));
      if (m) msgs.push(m);
    } catch {
      if (!(isStreaming && i === lines.length - 1)) bad += 1;
    }
  }
  if (msgs.length > 0 && (bad === 0 || isStreaming)) {
    return { status: isStreaming ? "streaming" : "ready", messages: msgs };
  }
  return isStreaming
    ? { status: "streaming", messages: [] }
    : { status: "error", messages: [], error: "Invalid A2UI JSON/JSONL payload." };
}
"""

_A2UI_SECURITY_TS = """export function isSafeMediaUrl(rawUrl: string): boolean {
  if (typeof rawUrl !== "string") return false;
  if (/[\\x00-\\x1f\\x7f]/.test(rawUrl)) return false;
  const trimmed = rawUrl.trim();
  if (!trimmed) return false;
  const normalized = trimmed.replace(/\\\\/g, "/");
  if (normalized.startsWith("//")) return false;
  if (trimmed.startsWith("/")) return true;
  const match = /^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$/.exec(trimmed);
  if (!match) return false;
  const scheme = match[1]!.toLowerCase();
  const rest = match[2]!;
  if (scheme === "http" || scheme === "https") return rest.startsWith("//");
  if (scheme === "data") return /^data:(image|audio|video)\\//i.test(trimmed);
  return false;
}

export function isSafeOpenUrl(rawUrl: string): boolean {
  if (typeof rawUrl !== "string") return false;
  if (/[\\x00-\\x1f\\x7f]/.test(rawUrl)) return false;
  const trimmed = rawUrl.trim();
  const match = /^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$/.exec(trimmed);
  if (!match) return false;
  const scheme = match[1]!.toLowerCase();
  const rest = match[2]!;
  if (scheme === "http" || scheme === "https") return rest.startsWith("//");
  if (scheme === "mailto") return rest.includes("@");
  return false;
}
"""

_ACTION_CONTEXT_TSX = """import { createContext, useCallback, useContext, useMemo, type ReactNode } from "react";

export interface A2uiActionEvent {
  surfaceId: string;
  actionName: string;
  sourceComponentId?: string;
  context: Record<string, unknown>;
  timestamp: string;
}

export interface A2uiActionContextValue {
  onAction: (event: A2uiActionEvent) => void;
  disabled: boolean;
}

const A2uiActionContext = createContext<A2uiActionContextValue | null>(null);

export function formatA2uiActionMessage(event: A2uiActionEvent): string {
  const payload = {
    surfaceId: event.surfaceId,
    action: event.actionName,
    ...(event.sourceComponentId ? { sourceComponentId: event.sourceComponentId } : {}),
    context: event.context,
  };
  return `[A2UI Action: ${event.actionName}] ${JSON.stringify(payload)}`;
}

export function A2uiActionProvider({
  onSend,
  disabled = false,
  children,
}: {
  onSend: (text: string) => void;
  disabled?: boolean;
  children: ReactNode;
}) {
  const onAction = useCallback(
    (event: A2uiActionEvent) => {
      if (!disabled) onSend(formatA2uiActionMessage(event));
    },
    [disabled, onSend],
  );
  const value = useMemo(() => ({ onAction, disabled }), [onAction, disabled]);
  return <A2uiActionContext.Provider value={value}>{children}</A2uiActionContext.Provider>;
}

export function useA2uiActionContext(): A2uiActionContextValue | null {
  return useContext(A2uiActionContext);
}
"""

_ACTION_BRIDGE_TS = """export interface A2uiActionEvent {
  surfaceId: string;
  actionName: string;
  sourceComponentId?: string;
  context: Record<string, unknown>;
  timestamp: string;
}

export function formatA2uiActionMessage(event: A2uiActionEvent): string {
  const payload = {
    surfaceId: event.surfaceId,
    action: event.actionName,
    ...(event.sourceComponentId ? { sourceComponentId: event.sourceComponentId } : {}),
    context: event.context,
  };
  return `[A2UI Action: ${event.actionName}] ${JSON.stringify(payload)}`;
}
"""

_REACT_BLOCK_TSX = """import { A2uiSurface } from "@a2ui/react";
import { renderMarkdown } from "@a2ui/markdown-it";
import {
  type ActionPayload,
  MessageProcessor,
  RELAXED_VALIDATION,
  basicCatalog as basicCatalogV1,
  injectBasicCatalogStyles,
  setMarkdownRenderer,
} from "@a2ui/web_core/v1_0";
import { basicCatalog as basicCatalogV09 } from "@a2ui/web_core/v0_9/basic_catalog";
import { Component, useCallback, useMemo, useState, type ErrorInfo, type ReactNode } from "react";

import { useA2uiActionContext } from "./A2uiActionContext";
import { parseA2uiPayload } from "./a2uiParser";
import "./a2uiTheme.css";

let initialized = false;
function initA2uiRuntime(): void {
  if (initialized) return;
  initialized = true;
  try { setMarkdownRenderer(renderMarkdown); } catch { /* SSR/JSDOM safe */ }
  try { injectBasicCatalogStyles(); } catch { /* SSR/JSDOM safe */ }
}

class A2uiSurfaceErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null }
> {
  override state: { error: Error | null } = { error: null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  override componentDidCatch(_error: Error, _info: ErrorInfo) {}
  override render() {
    if (this.state.error) {
      return <div role="alert" className="a2ui-host-error">{this.state.error.message}</div>;
    }
    return this.props.children;
  }
}

export interface A2uiBlockProps {
  code: string;
  themeMode?: "dark" | "light";
  isStreaming?: boolean;
}

export function A2uiBlock({ code, themeMode = "dark", isStreaming = false }: A2uiBlockProps) {
  initA2uiRuntime();
  const actionCtx = useA2uiActionContext();
  const [showSource, setShowSource] = useState(false);

  const parsed = useMemo(() => parseA2uiPayload(code, isStreaming), [code, isStreaming]);

  const handleAction = useCallback(
    (payload: ActionPayload) => {
      if (actionCtx && !actionCtx.disabled) {
        actionCtx.onAction({
          surfaceId: payload.surfaceId,
          actionName: payload.name || "action",
          sourceComponentId: payload.sourceComponentId,
          context: payload.context ?? {},
          timestamp: payload.timestamp || new Date().toISOString(),
        });
      }
    },
    [actionCtx],
  );

  const surfaces = useMemo(() => {
    if (parsed.messages.length === 0) return [];
    const processor = new MessageProcessor(
      [basicCatalogV1, basicCatalogV09],
      handleAction,
      { version: "1.0", validationConfig: RELAXED_VALIDATION, reportErrorsOnly: true },
    );
    processor.processMessages(parsed.messages as never[]);
    return Array.from(processor.getSurfaces().values()).filter(
      (s) => s.componentsModel.get("root") !== undefined,
    );
  }, [parsed.messages, handleAction]);

  const themeClass = themeMode === "dark" ? "a2ui-dark" : "a2ui-light";
  return (
    <div className={`legends-a2ui-block ${themeClass}`}>
      <div className="legends-a2ui-header">
        <span className="legends-a2ui-eyebrow">Interactive Surface</span>
        <button type="button" className="legends-a2ui-chrome-btn" onClick={() => setShowSource((v) => !v)}>
          {showSource ? "UI" : "JSON"}
        </button>
      </div>
      {showSource ? (
        <pre className="legends-a2ui-source"><code>{code}</code></pre>
      ) : (
        <A2uiSurfaceErrorBoundary>
          <div className={`legends-a2ui-surface ${themeClass}`}>
            {surfaces.map((surface) => (
              <A2uiSurface key={surface.id} surface={surface as never} />
            ))}
          </div>
        </A2uiSurfaceErrorBoundary>
      )}
    </div>
  );
}
"""

_WEB_CORE_HOST_TS = """import {
  type ActionPayload,
  MessageProcessor,
  RELAXED_VALIDATION,
  basicCatalog as basicCatalogV1,
  injectBasicCatalogStyles,
} from "@a2ui/web_core/v1_0";
import { basicCatalog as basicCatalogV09 } from "@a2ui/web_core/v0_9/basic_catalog";

import { formatA2uiActionMessage } from "./a2uiActionBridge";
import { parseA2uiPayload } from "./a2uiParser";
import "./a2uiTheme.css";

export function createA2uiProcessor(onDispatch: (formattedAction: string) => void): MessageProcessor {
  try { injectBasicCatalogStyles(); } catch { /* SSR safe */ }
  return new MessageProcessor(
    [basicCatalogV1, basicCatalogV09],
    (payload: ActionPayload) => {
      onDispatch(
        formatA2uiActionMessage({
          surfaceId: payload.surfaceId,
          actionName: payload.name || "action",
          sourceComponentId: payload.sourceComponentId,
          context: payload.context ?? {},
          timestamp: payload.timestamp || new Date().toISOString(),
        }),
      );
    },
    { version: "1.0", validationConfig: RELAXED_VALIDATION, reportErrorsOnly: true },
  );
}

export function processA2uiText(processor: MessageProcessor, raw: string) {
  const parsed = parseA2uiPayload(raw, false);
  if (parsed.messages.length > 0) {
    processor.processMessages(parsed.messages as never[]);
  }
  return Array.from(processor.getSurfaces().values()).filter(
    (s) => s.componentsModel.get("root") !== undefined,
  );
}
"""

_LIT_HOST_TS = """import "@a2ui/lit";
import {
  type ActionPayload,
  MessageProcessor,
  RELAXED_VALIDATION,
  basicCatalog as basicCatalogV1,
  injectBasicCatalogStyles,
} from "@a2ui/web_core/v1_0";
import { basicCatalog as basicCatalogV09 } from "@a2ui/web_core/v0_9/basic_catalog";

import { formatA2uiActionMessage } from "./a2uiActionBridge";
import { parseA2uiPayload } from "./a2uiParser";
import "./a2uiTheme.css";

export function mountA2uiLitSurface(
  container: HTMLElement,
  rawPayload: string,
  onDispatch: (formattedAction: string) => void,
  themeMode: "dark" | "light" = "dark",
): void {
  try { injectBasicCatalogStyles(); } catch { /* SSR safe */ }
  const parsed = parseA2uiPayload(rawPayload, false);
  const processor = new MessageProcessor(
    [basicCatalogV1, basicCatalogV09],
    (payload: ActionPayload) => {
      onDispatch(
        formatA2uiActionMessage({
          surfaceId: payload.surfaceId,
          actionName: payload.name || "action",
          sourceComponentId: payload.sourceComponentId,
          context: payload.context ?? {},
          timestamp: payload.timestamp || new Date().toISOString(),
        }),
      );
    },
    { version: "1.0", validationConfig: RELAXED_VALIDATION, reportErrorsOnly: true },
  );
  processor.processMessages(parsed.messages as never[]);
  container.className = `legends-a2ui-surface ${themeMode === "dark" ? "a2ui-dark" : "a2ui-light"}`;
  container.innerHTML = "";
  for (const surface of processor.getSurfaces().values()) {
    if (surface.componentsModel.get("root") === undefined) continue;
    const el = document.createElement("a2ui-surface") as HTMLElement & { surface?: unknown };
    el.surface = surface;
    container.appendChild(el);
  }
}
"""


def _theme_css(theme: str) -> str:
    primary_dark = "#9e0b1a" if theme == "precision-noir" else "#2563eb"
    primary_hover = "#b30f20" if theme == "precision-noir" else "#1d4ed8"
    primary_edge = "#c9202f" if theme == "precision-noir" else "#3b82f6"
    bg_dark = "#07090b" if theme == "precision-noir" else "#0f172a"
    surface_dark = "#0c0c0f" if theme == "precision-noir" else "#111827"
    return f"""/* A2UI v1.0 Host Theme ({theme}) overriding Light DOM adoptedStyleSheets. */
.legends-a2ui-block {{
  display: flex;
  flex-direction: column;
  width: 100%;
  border-radius: 6px;
  overflow: hidden;
}}
.legends-a2ui-block.a2ui-dark {{
  background: {bg_dark};
  border: 1px solid rgba(255, 255, 255, 0.10);
  color: #d4d4d8;
}}
.legends-a2ui-block.a2ui-light {{
  background: #ffffff;
  border: 1px solid rgba(24, 24, 27, 0.12);
  color: #27272a;
}}
.legends-a2ui-header {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 6px 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}}
.legends-a2ui-surface {{
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 18px 20px;
}}
.legends-a2ui-surface:has(> a2ui-card),
.legends-a2ui-surface:has(> div > a2ui-card) {{
  padding: 0;
  gap: 0;
}}
.legends-a2ui-surface.a2ui-dark {{
  color-scheme: dark;
  background: {surface_dark};
  --a2ui-color-primary: {primary_dark};
  --a2ui-color-primary-hover: {primary_hover};
  --a2ui-color-on-primary: #ffffff;
  --a2ui-border-radius: 4px;
}}
.legends-a2ui-surface.a2ui-dark a2ui-basic-button .a2ui-button.a2ui-button-primary {{
  background: {primary_dark};
  border: 1px solid {primary_edge};
  color: #ffffff;
}}
.legends-a2ui-surface.a2ui-dark a2ui-basic-button .a2ui-button.a2ui-button-primary:hover:not(:disabled) {{
  background: {primary_hover};
}}
.legends-a2ui-surface.a2ui-light {{
  color-scheme: light;
  background: #ffffff;
  --a2ui-color-primary: {primary_dark};
  --a2ui-color-primary-hover: {primary_hover};
  --a2ui-color-on-primary: #ffffff;
  --a2ui-border-radius: 4px;
}}
"""


_PARSER_TEST_TS = """import { A2UI_V09_BASIC_CATALOG_ID, A2UI_V1_BASIC_CATALOG_ID, parseA2uiPayload, sanitizeUax31Id } from "./a2uiParser";
import { isSafeMediaUrl, isSafeOpenUrl } from "./a2uiSecurity";

export function runSelfCheck(): void {
  const res = parseA2uiPayload(JSON.stringify({
    version: "v1.0",
    createSurface: {
      surfaceId: "demo",
      catalogId: "https://a2ui.org/specification/v0_9/basic_catalog.json",
      components: [{ id: "root", component: "Text", text: "Hello", variant: "h2" }],
    },
  }));
  if (res.status !== "ready" || res.messages.length !== 1) {
    throw new Error("Expected ready parse result");
  }
  const cs = res.messages[0]!.createSurface as Record<string, unknown>;
  if (cs.catalogId !== A2UI_V1_BASIC_CATALOG_ID) {
    throw new Error("Expected canonical v1.0 catalogId");
  }
  if (!A2UI_V09_BASIC_CATALOG_ID.endsWith("/catalogs/basic/catalog.json")) {
    throw new Error("Expected canonical v0.9 catalogId");
  }
  if (sanitizeUax31Id("1-bad-id") !== "c_1_bad_id") {
    throw new Error("Expected UAX #31 sanitized ID");
  }
  if (isSafeMediaUrl("javascript:alert(1)") || !isSafeMediaUrl("https://example.com/a.png")) {
    throw new Error("Media URL safety check failed");
  }
  if (isSafeOpenUrl("data:text/html,hi") || !isSafeOpenUrl("https://a2ui.org")) {
    throw new Error("openUrl safety check failed");
  }
}
"""


def build_scaffold_files(
    output_dir: Path, *, target: str = "react", theme: str = "precision-noir"
) -> list[tuple[Path, bytes]]:
    """Build planned file list for a target host integration kit."""
    if target not in VALID_TARGETS:
        raise ValueError(f"Unknown scaffold target '{target}'. Choose from: {', '.join(VALID_TARGETS)}")
    if theme not in VALID_THEMES:
        raise ValueError(f"Unknown scaffold theme '{theme}'. Choose from: {', '.join(VALID_THEMES)}")

    readme = (
        f"# A2UI v1.0 Integration Kit ({target} / {theme})\n\n"
        "Generated offline by `legends-a2ui scaffold`.\n\n"
        "## Recommended npm packages\n\n"
        "- `@a2ui/web_core@^0.16.1`\n"
        "- `@a2ui/markdown-it@^0.2.4`\n"
        + ("- `@a2ui/react@^0.16.1`\n" if target == "react" else "")
        + ("- `@a2ui/lit@^0.16.0`\n" if target == "lit" else "")
        + "\n## Notes\n\n"
        "- Canonical v1.0 Basic Catalog URI: `https://a2ui.org/specification/v1_0/catalogs/basic/catalog.json`\n"
        "- Canonical v0.9 Basic Catalog URI: `https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json`\n"
        "- High-specificity Light DOM selectors in `a2uiTheme.css` override `@a2ui/web_core` `adoptedStyleSheets`.\n"
    )

    files: list[tuple[str, str]] = [
        ("a2uiParser.ts", _A2UI_PARSER_TS),
        ("a2uiSecurity.ts", _A2UI_SECURITY_TS),
        ("a2uiTheme.css", _theme_css(theme)),
        ("a2uiParser.test.ts", _PARSER_TEST_TS),
        ("README-INTEGRATION.md", readme),
    ]

    if target == "react":
        files.append(("A2uiActionContext.tsx", _ACTION_CONTEXT_TSX))
        files.append(("A2uiBlock.tsx", _REACT_BLOCK_TSX))
    elif target == "web-core":
        files.append(("a2uiActionBridge.ts", _ACTION_BRIDGE_TS))
        files.append(("A2uiSurfaceHost.ts", _WEB_CORE_HOST_TS))
    else:
        files.append(("a2uiActionBridge.ts", _ACTION_BRIDGE_TS))
        files.append(("A2uiLitSurface.ts", _LIT_HOST_TS))

    return [(output_dir / rel, content.encode("utf-8")) for rel, content in files]
