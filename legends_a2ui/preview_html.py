"""Self-contained, zero-daemon, offline static HTML5 A2UI v1.0 preview generator."""
from __future__ import annotations

import html
import json
from typing import Any

from legends_a2ui.normalizer import normalize_payload

STRICT_CSP = (
    "default-src 'none'; "
    "style-src 'unsafe-inline'; "
    "script-src 'unsafe-inline'; "
    "img-src https: http: data:; "
    "media-src https: http: data:;"
)


def _safe_embed_json(obj: Any) -> str:
    """Serialize JSON safely for <script type='application/json'> (prevents CWE-79 breakout)."""
    raw = json.dumps(obj, indent=2, ensure_ascii=True, allow_nan=False)
    return raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


_PREVIEW_CSS = """
:root {
  color-scheme: dark;
  accent-color: #9e0b1a;
  --pn-font: 'legends', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  --pn-sans: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
  --pn-r-1: 2px;
  --pn-r-2: 4px;
  --pn-r-3: 6px;
}
html[data-theme="precision-noir"] {
  color-scheme: dark;
}
html[data-theme="light"] {
  color-scheme: light;
}
* { box-sizing: border-box; }
input, textarea, select {
  accent-color: #9e0b1a;
}
html, body {
  margin: 0;
  padding: 0;
  min-height: 100vh;
  font-family: var(--pn-sans);
  font-size: 13.5px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}
body.a2ui-dark {
  color-scheme: dark;
  background: #000000;
  color: #d4d4d8;
  --bg-shell: #07090b;
  --bg-card: #0c0c0f;
  --bg-inset: #09090c;
  --bg-input: #050507;
  --hairline: rgba(255, 255, 255, 0.10);
  --hairline-strong: rgba(255, 255, 255, 0.22);
  --text-primary: #f4f4f5;
  --text-body: #d4d4d8;
  --text-muted: #8e8e9a;
  --btn-bg: #121216;
  --btn-hover: #1a1a20;
  --btn-primary: #9e0b1a;
  --btn-primary-hover: #b30f20;
  --btn-primary-edge: #c9202f;
  --signal: #ff0000;
  --danger-text: #f2555f;
}
body.a2ui-light {
  color-scheme: light;
  background: #f4f4f6;
  color: #27272a;
  --bg-shell: #ffffff;
  --bg-card: #ffffff;
  --bg-inset: #fafafa;
  --bg-input: #ffffff;
  --hairline: rgba(24, 24, 27, 0.12);
  --hairline-strong: rgba(24, 24, 27, 0.26);
  --text-primary: #18181b;
  --text-body: #27272a;
  --text-muted: #71717a;
  --btn-bg: #f4f4f5;
  --btn-hover: #e4e4e7;
  --btn-primary: #9e0b1a;
  --btn-primary-hover: #b30f20;
  --btn-primary-edge: #7f1d1d;
  --signal: #ff0000;
  --danger-text: #dc2626;
}
.shell {
  max-width: 960px;
  margin: 24px auto;
  padding: 0 16px 40px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.frame {
  background: var(--bg-shell);
  border: 1px solid var(--hairline);
  border-radius: var(--pn-r-3);
  overflow: hidden;
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--hairline);
  font-family: var(--pn-font);
  font-size: 11px;
}
.topbar-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}
.signal-pip {
  width: 5px;
  height: 5px;
  background: var(--signal);
  display: inline-block;
  flex: none;
}
.eyebrow {
  color: var(--text-muted);
  letter-spacing: 0.08em;
}
.chrome-actions {
  display: flex;
  align-items: center;
  gap: 6px;
}
.chrome-btn {
  height: 26px;
  padding: 0 10px;
  border-radius: var(--pn-r-1);
  border: 1px solid var(--hairline);
  background: var(--btn-bg);
  color: var(--text-body);
  font-family: var(--pn-font);
  font-size: 11px;
  cursor: pointer;
}
.chrome-btn:hover {
  border-color: var(--hairline-strong);
  background: var(--btn-hover);
}
.surface-body {
  padding: 18px 20px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.source-view {
  margin: 0;
  padding: 16px;
  overflow: auto;
  max-height: 480px;
  background: var(--bg-input);
  color: var(--text-body);
  font-family: var(--pn-font);
  font-size: 12px;
  line-height: 1.5;
  white-space: pre-wrap;
}
.a2ui-card {
  background: var(--bg-card);
  border: 1px solid var(--hairline);
  border-radius: var(--pn-r-2);
  padding: 16px 18px;
}
.a2ui-column {
  display: flex;
  flex-direction: column;
  gap: 12px;
  width: 100%;
}
.a2ui-row {
  display: flex;
  flex-direction: row;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
}
.a2ui-list {
  display: flex;
  gap: 8px;
}
.a2ui-list.vertical { flex-direction: column; }
.a2ui-list.horizontal { flex-direction: row; flex-wrap: wrap; }
.a2ui-divider-h {
  border: 0;
  border-top: 1px solid var(--hairline);
  margin: 4px 0;
  width: 100%;
}
.a2ui-divider-v {
  border: 0;
  border-left: 1px solid var(--hairline);
  margin: 0 4px;
  min-height: 20px;
}
.a2ui-text { color: var(--text-body); }
.a2ui-text.caption { color: var(--text-muted); font-size: 12px; }
.a2ui-text h1, .a2ui-text h2, .a2ui-text h3, .a2ui-text h4, .a2ui-text h5 {
  margin: 0 0 4px;
  color: var(--text-primary);
  font-weight: 600;
  line-height: 1.28;
}
.a2ui-text h1 { font-size: 20px; }
.a2ui-text h2 { font-size: 17px; }
.a2ui-text h3 { font-size: 15px; }
.a2ui-text p { margin: 0 0 6px; }
.a2ui-text p:last-child { margin-bottom: 0; }
.a2ui-text code {
  font-family: var(--pn-font);
  font-size: 12px;
  padding: 1px 4px;
  border-radius: var(--pn-r-1);
  background: var(--bg-input);
  border: 1px solid var(--hairline);
}
.a2ui-text ul { margin: 4px 0; padding-left: 18px; }
.a2ui-text a { color: #f87171; }
.a2ui-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  min-height: 34px;
  padding: 7px 14px;
  border-radius: var(--pn-r-1);
  border: 1px solid var(--hairline);
  background: var(--btn-bg);
  color: var(--text-primary);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
}
.a2ui-btn:hover { background: var(--btn-hover); border-color: var(--hairline-strong); }
.a2ui-btn.primary {
  background: var(--btn-primary);
  border-color: var(--btn-primary-edge);
  color: #ffffff;
}
.a2ui-btn.primary:hover { background: var(--btn-primary-hover); }
.a2ui-btn.borderless {
  background: transparent;
  border-color: transparent;
  color: var(--text-muted);
}
.a2ui-btn .a2ui-text { color: inherit; }
.a2ui-field {
  display: flex;
  flex-direction: column;
  gap: 5px;
  width: 100%;
}
.a2ui-field label {
  font-size: 12px;
  color: var(--text-muted);
  font-weight: 500;
}
.a2ui-input, .a2ui-textarea {
  width: 100%;
  padding: 8px 10px;
  border-radius: var(--pn-r-1);
  border: 1px solid var(--hairline);
  background: var(--bg-input);
  color: var(--text-primary);
  font-family: inherit;
  font-size: 13px;
}
.a2ui-input:focus, .a2ui-textarea:focus {
  outline: none;
  border-color: var(--btn-primary-edge);
}
.a2ui-check-error {
  font-size: 11.5px;
  color: var(--danger-text);
  font-family: var(--pn-font);
}
.a2ui-checkbox {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}
.a2ui-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.a2ui-chip {
  padding: 5px 10px;
  border-radius: var(--pn-r-1);
  border: 1px solid var(--hairline);
  background: var(--btn-bg);
  color: var(--text-body);
  cursor: pointer;
  font-size: 12.5px;
}
.a2ui-chip.selected {
  background: var(--btn-primary);
  border-color: var(--btn-primary-edge);
  color: #ffffff;
}
.a2ui-tabs-bar {
  display: flex;
  gap: 4px;
  border-bottom: 1px solid var(--hairline);
  margin-bottom: 12px;
}
.a2ui-tab-btn {
  padding: 7px 12px;
  background: transparent;
  border: 0;
  border-bottom: 2px solid transparent;
  color: var(--text-muted);
  cursor: pointer;
  font-size: 13px;
}
.a2ui-tab-btn.active {
  color: var(--text-primary);
  border-bottom-color: var(--btn-primary-edge);
}
.a2ui-modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.72);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 50;
  padding: 16px;
}
.a2ui-modal-dialog {
  max-width: 560px;
  width: 100%;
  background: var(--bg-card);
  border: 1px solid var(--hairline-strong);
  border-radius: var(--pn-r-3);
  padding: 18px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.a2ui-media {
  max-width: 100%;
  border-radius: var(--pn-r-2);
  border: 1px solid var(--hairline);
}
.a2ui-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-family: var(--pn-font);
  font-size: 11px;
  padding: 2px 6px;
  border: 1px solid var(--hairline);
  border-radius: var(--pn-r-1);
  color: var(--text-muted);
}
.inspector {
  background: var(--bg-shell);
  border: 1px solid var(--hairline);
  border-radius: var(--pn-r-2);
  overflow: hidden;
}
.inspector-log {
  margin: 0;
  padding: 12px 14px;
  font-family: var(--pn-font);
  font-size: 11.5px;
  color: var(--text-body);
  background: var(--bg-input);
  max-height: 220px;
  overflow: auto;
  white-space: pre-wrap;
}
"""

_PREVIEW_JS = r"""
(function () {
  "use strict";

  const payloadEl = document.getElementById("a2ui-payload");
  const messages = JSON.parse(payloadEl ? payloadEl.textContent : "[]");
  const surfaceMount = document.getElementById("surface-mount");
  const sourceView = document.getElementById("source-view");
  const inspectorLog = document.getElementById("inspector-log");
  const surfaceLabel = document.getElementById("surface-id-label");
  const toggleSourceBtn = document.getElementById("toggle-source-btn");
  const toggleThemeBtn = document.getElementById("toggle-theme-btn");
  const clearLogBtn = document.getElementById("clear-log-btn");

  const surfaces = new Map();
  let showingSource = false;
  const actionLogs = [];
  let reactiveUpdaters = [];
  let pickerSeq = 0;
  const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

  function hasOwn(obj, key) {
    return obj !== null && typeof obj === "object" && Object.prototype.hasOwnProperty.call(obj, key);
  }

  function sanitizePlainValue(v) {
    if (v === null || typeof v !== "object") return v;
    if (Array.isArray(v)) return v.map(sanitizePlainValue);
    const out = Object.create(null);
    for (const k of Object.keys(v)) {
      if (FORBIDDEN_KEYS.has(k)) continue;
      out[k] = sanitizePlainValue(v[k]);
    }
    return out;
  }

  function toDisplayString(v) {
    if (v === null || v === undefined) return "";
    if (typeof v === "string") return v;
    if (typeof v === "number" || typeof v === "boolean") return String(v);
    if (typeof v === "object") {
      try {
        return JSON.stringify(v);
      } catch (_err) {
        return "";
      }
    }
    return "";
  }

  function toFiniteNumber(v) {
    if (typeof v === "number") return Number.isFinite(v) ? v : NaN;
    if (typeof v === "string" && v.trim() !== "") {
      const n = Number(v);
      return Number.isFinite(n) ? n : NaN;
    }
    return NaN;
  }

  function refreshReactiveBindings() {
    for (const fn of reactiveUpdaters) {
      try { fn(); } catch (_err) {}
    }
  }

  function escapeHtml(str) {
    return toDisplayString(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function hasValidAuthority(rest) {
    if (!rest.startsWith("//")) return false;
    const afterSlashes = rest.slice(2);
    const cut = afterSlashes.search(/[/?#]/);
    const authority = cut === -1 ? afterSlashes : afterSlashes.slice(0, cut);
    if (!authority || /\s/.test(authority) || authority.includes("@")) return false;
    return true;
  }

  function isSafeMediaUrl(url) {
    if (typeof url !== "string") return false;
    if (/[\x00-\x1f\x7f]/.test(url)) return false;
    const t = url.trim();
    if (!t) return false;
    const norm = t.replace(/\\/g, "/");
    if (norm.startsWith("//")) return false;
    if (t.startsWith("/") && !t.startsWith("/\\")) return true;
    const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$/.exec(t);
    if (!m) return false;
    const scheme = m[1].toLowerCase();
    if (scheme === "http" || scheme === "https") return hasValidAuthority(m[2]);
    if (scheme === "data") {
      return /^data:(?:image\/(?:png|jpeg|jpg|gif|webp|avif|bmp)|(?:audio|video)\/[a-z0-9.+-]+)[;,]/i.test(t);
    }
    return false;
  }

  function isSafeOpenUrl(url) {
    if (typeof url !== "string") return false;
    if (/[\x00-\x1f\x7f]/.test(url)) return false;
    const t = url.trim();
    const norm = t.replace(/\\/g, "/");
    if (norm.startsWith("//")) return false;
    const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$/.exec(t);
    if (!m) return false;
    const scheme = m[1].toLowerCase();
    if (scheme === "http" || scheme === "https") return hasValidAuthority(m[2]);
    if (scheme === "mailto") return m[2].trim().length > 0 && m[2].includes("@");
    return false;
  }

  function renderSafeMarkdown(rawText) {
    const escaped = escapeHtml(rawText === null || rawText === undefined ? "" : rawText);
    const lines = escaped.split(/\r?\n/);
    const out = [];
    let inList = false;

    function inlineFmt(line) {
      const tokens = [];
      function stash(frag) {
        const key = "\uE000" + tokens.length + "\uE001";
        tokens.push(frag);
        return key;
      }
      let s = line.replace(/[\uE000\uE001]/g, "");
      s = s.replace(/`([^`]+)`/g, function (_m, code) {
        return stash("<code>" + code + "</code>");
      });
      s = s.replace(/(^|[^\\])\[([^\[\]]+)\]\(((?:[^()\s]|\([^()\s]*\))+)\)/g, function (_m, lead, label, href) {
        if (isSafeOpenUrl(href)) {
          return lead + stash('<a href="' + href + '" target="_blank" rel="noopener noreferrer">' + label + "</a>");
        }
        return lead + label;
      });
      s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
      s = s.replace(/\*([^*]+)\*/g, "<em>$1</em>");
      for (let pass = 0; pass < 8 && /\uE000\d+\uE001/.test(s); pass += 1) {
        s = s.replace(/\uE000(\d+)\uE001/g, function (_m, idx) {
          return tokens[Number(idx)] || "";
        });
      }
      return s;
    }

    for (const line of lines) {
      const h = /^(#{1,5})\s+(.*)$/.exec(line);
      if (h) {
        if (inList) { out.push("</ul>"); inList = false; }
        const lvl = h[1].length;
        out.push("<h" + lvl + ">" + inlineFmt(h[2]) + "</h" + lvl + ">");
        continue;
      }
      const li = /^[-*]\s+(.*)$/.exec(line);
      if (li) {
        if (!inList) { out.push("<ul>"); inList = true; }
        out.push("<li>" + inlineFmt(li[1]) + "</li>");
        continue;
      }
      if (inList) { out.push("</ul>"); inList = false; }
      if (line.trim() === "") continue;
      out.push("<p>" + inlineFmt(line) + "</p>");
    }
    if (inList) out.push("</ul>");
    return out.join("");
  }

  const RFC6901_ARRAY_INDEX_RE = /^(?:0|[1-9]\d{0,6})$/;

  function getByPointer(root, pointer, itemCtx) {
    if (typeof pointer !== "string" || !pointer) return undefined;
    if (!pointer.startsWith("/")) {
      if (!itemCtx || typeof itemCtx !== "object") return undefined;
      const relParts = pointer.split("/").map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
      let cur = itemCtx;
      for (const part of relParts) {
        if (FORBIDDEN_KEYS.has(part)) return undefined;
        if (Array.isArray(cur)) {
          if (!RFC6901_ARRAY_INDEX_RE.test(part)) return undefined;
          const idx = Number(part);
          if (idx >= cur.length) return undefined;
          cur = cur[idx];
        } else if (cur && typeof cur === "object" && hasOwn(cur, part)) {
          cur = cur[part];
        } else {
          return undefined;
        }
      }
      return cur;
    }
    if (pointer === "/") return root;
    const parts = pointer.slice(1).split("/").map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
    let cur = root;
    for (const part of parts) {
      if (FORBIDDEN_KEYS.has(part)) return undefined;
      if (Array.isArray(cur)) {
        if (!RFC6901_ARRAY_INDEX_RE.test(part)) return undefined;
        const idx = Number(part);
        if (idx >= cur.length) return undefined;
        cur = cur[idx];
      } else if (cur && typeof cur === "object" && hasOwn(cur, part)) {
        cur = cur[part];
      } else {
        return undefined;
      }
    }
    return cur;
  }

  function setByPointer(root, pointer, value, itemCtx) {
    if (typeof pointer !== "string" || !pointer) return;
    let cur;
    let parts;
    if (pointer.startsWith("/")) {
      if (pointer === "/") return;
      cur = root;
      parts = pointer.slice(1).split("/").map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
    } else {
      if (!itemCtx || typeof itemCtx !== "object") return;
      cur = itemCtx;
      parts = pointer.split("/").map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
    }
    if (parts.some((p) => FORBIDDEN_KEYS.has(p))) return;
    for (let i = 0; i < parts.length - 1; i += 1) {
      const key = parts[i];
      if (Array.isArray(cur)) {
        if (!RFC6901_ARRAY_INDEX_RE.test(key)) return;
        const idx = Number(key);
        if (!Number.isInteger(idx) || idx < 0 || idx >= cur.length) return;
        if (!cur[idx] || typeof cur[idx] !== "object") {
          if (value === null) return;
          cur[idx] = Object.create(null);
        }
        cur = cur[idx];
      } else {
        if (!hasOwn(cur, key) || !cur[key] || typeof cur[key] !== "object") {
          if (value === null) return;
          cur[key] = Object.create(null);
        }
        cur = cur[key];
      }
    }
    const lastKey = parts[parts.length - 1];
    if (Array.isArray(cur)) {
      if (lastKey === "-") {
        if (value !== null) cur.push(sanitizePlainValue(value));
        return;
      }
      if (!RFC6901_ARRAY_INDEX_RE.test(lastKey)) return;
      const idx = Number(lastKey);
      if (!Number.isInteger(idx) || idx < 0) return;
      if (value === null) {
        if (idx < cur.length) cur.splice(idx, 1);
      } else if (idx < cur.length) {
        cur[idx] = sanitizePlainValue(value);
      } else if (idx === cur.length) {
        cur.push(sanitizePlainValue(value));
      }
    } else if (cur && typeof cur === "object") {
      if (value === null) {
        if (hasOwn(cur, lastKey)) delete cur[lastKey];
      } else {
        cur[lastKey] = sanitizePlainValue(value);
      }
    }
  }

  function resolveDynamic(val, dataModel, itemCtx) {
    if (val && typeof val === "object" && !Array.isArray(val)) {
      if (typeof val["@path"] === "string") {
        return getByPointer(dataModel, val["@path"], itemCtx);
      }
      if (typeof val["@call"] === "string") {
        const fn = val["@call"];
        const args = val.args || {};
        if (fn === "formatString" && typeof args.value === "string") {
          return args.value.replace(/\$\{([^}]+)\}/g, (_m, expr) => {
            const resolved = getByPointer(dataModel, expr.trim(), itemCtx);
            return toDisplayString(resolved);
          });
        }
        if (fn === "required") {
          const v = resolveDynamic(args.value, dataModel, itemCtx);
          if (v === undefined || v === null) return false;
          if (Array.isArray(v)) return v.length > 0;
          if (typeof v === "object") return Object.keys(v).length > 0;
          return toDisplayString(v).trim() !== "";
        }
        if (fn === "email") {
          const v = toDisplayString(resolveDynamic(args.value, dataModel, itemCtx));
          return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
        }
        if (fn === "length") {
          const rawVal = resolveDynamic(args.value, dataModel, itemCtx);
          const len = Array.isArray(rawVal) ? rawVal.length : toDisplayString(rawVal).length;
          if (typeof args.min === "number" && len < args.min) return false;
          if (typeof args.max === "number" && len > args.max) return false;
          return true;
        }
        if (fn === "numeric") {
          const v = toFiniteNumber(resolveDynamic(args.value, dataModel, itemCtx));
          if (Number.isNaN(v)) return false;
          if (typeof args.min === "number" && v < args.min) return false;
          if (typeof args.max === "number" && v > args.max) return false;
          return true;
        }
        if (fn === "regex" && typeof args.pattern === "string") {
          try {
            const v = toDisplayString(resolveDynamic(args.value, dataModel, itemCtx));
            return new RegExp(args.pattern, "u").test(v);
          } catch (_err) {
            return false;
          }
        }
        if (fn === "and" && Array.isArray(args.values)) {
          return args.values.every((x) => Boolean(resolveDynamic(x, dataModel, itemCtx)));
        }
        if (fn === "or" && Array.isArray(args.values)) {
          return args.values.some((x) => Boolean(resolveDynamic(x, dataModel, itemCtx)));
        }
        if (fn === "not") {
          return !Boolean(resolveDynamic(args.value, dataModel, itemCtx));
        }
        return true;
      }
    }
    return val;
  }

  function logAction(surfaceId, actionName, sourceComponentId, context) {
    const payload = {
      surfaceId: surfaceId,
      action: actionName,
      sourceComponentId: sourceComponentId,
      context: context,
    };
    const line = "[A2UI Action: " + actionName + "] " + JSON.stringify(payload);
    actionLogs.unshift(line);
    inspectorLog.textContent = actionLogs.join("\n");
  }

  // Hydrate surfaces from v1.0 messages
  for (const msg of messages) {
    if (msg.createSurface) {
      const cs = msg.createSurface;
      const comps = new Map();
      for (const c of cs.components || []) comps.set(c.id, c);
      surfaces.set(cs.surfaceId, {
        id: cs.surfaceId,
        components: comps,
        dataModel:
          cs.dataModel && typeof cs.dataModel === "object" && !Array.isArray(cs.dataModel)
            ? sanitizePlainValue(cs.dataModel)
            : Object.create(null),
        tabState: Object.create(null),
        modalState: Object.create(null),
      });
    } else if (msg.updateComponents) {
      const uc = msg.updateComponents;
      const s = surfaces.get(uc.surfaceId);
      if (s) {
        for (const c of uc.components || []) s.components.set(c.id, c);
      }
    } else if (msg.updateDataModel) {
      const udm = msg.updateDataModel;
      const s = surfaces.get(udm.surfaceId);
      if (s) {
        if (!udm.path || udm.path === "/") {
          if (udm.value === null) {
            s.dataModel = Object.create(null);
          } else if (udm.value && typeof udm.value === "object" && !Array.isArray(udm.value)) {
            s.dataModel = sanitizePlainValue(udm.value);
          }
        } else {
          setByPointer(s.dataModel, udm.path, udm.value);
        }
      }
    } else if (msg.deleteSurface) {
      surfaces.delete(msg.deleteSurface.surfaceId);
    }
  }

  function renderComponent(surface, compId, itemCtx, visited) {
    if (!compId || visited.has(compId)) return document.createTextNode("");
    const comp = surface.components.get(compId);
    if (!comp) return document.createTextNode("");
    const nextVisited = new Set(visited);
    nextVisited.add(compId);

    const type = comp.component;
    const dm = surface.dataModel;

    function applyWeight(el) {
      if (typeof comp.weight === "number") el.style.flex = String(comp.weight);
      return el;
    }

    function appendChecks(container) {
      if (!Array.isArray(comp["@checks"]) || comp["@checks"].length === 0) return;
      const slot = document.createElement("div");
      slot.className = "a2ui-checks-slot";
      function updateChecks() {
        slot.innerHTML = "";
        for (const rule of comp["@checks"]) {
          const res = resolveDynamic(rule.condition, surface.dataModel, itemCtx);
          const passed =
            typeof res === "object" && res !== null && hasOwn(res, "valid")
              ? Boolean(res.valid)
              : Boolean(res);
          if (!passed) {
            const err = document.createElement("div");
            err.className = "a2ui-check-error";
            err.textContent = rule.message || "Validation check failed.";
            slot.appendChild(err);
          }
        }
      }
      updateChecks();
      reactiveUpdaters.push(updateChecks);
      container.appendChild(slot);
    }

    function renderChildList(childrenSpec, parentEl) {
      if (Array.isArray(childrenSpec)) {
        for (const cid of childrenSpec) {
          parentEl.appendChild(renderComponent(surface, cid, itemCtx, nextVisited));
        }
      } else if (childrenSpec && typeof childrenSpec === "object") {
        const listData = getByPointer(dm, childrenSpec.path, itemCtx);
        if (Array.isArray(listData)) {
          for (const item of listData) {
            parentEl.appendChild(renderComponent(surface, childrenSpec.componentId, item, nextVisited));
          }
        }
      }
    }

    if (type === "Card") {
      const el = document.createElement("div");
      el.className = "a2ui-card";
      if (comp.child) el.appendChild(renderComponent(surface, comp.child, itemCtx, nextVisited));
      return applyWeight(el);
    }

    if (type === "Column" || type === "Row") {
      const el = document.createElement("div");
      el.className = type === "Column" ? "a2ui-column" : "a2ui-row";
      const jMap = {
        start: "flex-start", center: "center", end: "flex-end",
        spaceBetween: "space-between", spaceAround: "space-around",
        spaceEvenly: "space-evenly", stretch: "stretch",
      };
      if (comp.justify && jMap[comp.justify]) el.style.justifyContent = jMap[comp.justify];
      if (comp.align && jMap[comp.align]) el.style.alignItems = jMap[comp.align];
      renderChildList(comp.children, el);
      return applyWeight(el);
    }

    if (type === "List") {
      const el = document.createElement("div");
      el.className = "a2ui-list " + (comp.direction === "horizontal" ? "horizontal" : "vertical");
      renderChildList(comp.children, el);
      return applyWeight(el);
    }

    if (type === "Divider") {
      const el = document.createElement("hr");
      el.className = comp.axis === "vertical" ? "a2ui-divider-v" : "a2ui-divider-h";
      return applyWeight(el);
    }

    if (type === "Text") {
      const el = document.createElement("div");
      el.className = "a2ui-text " + (comp.variant === "caption" ? "caption" : "body");
      function updateText() {
        const val = resolveDynamic(comp.text, surface.dataModel, itemCtx);
        el.innerHTML = renderSafeMarkdown(toDisplayString(val));
      }
      updateText();
      if (comp.text && typeof comp.text === "object") {
        reactiveUpdaters.push(updateText);
      }
      return applyWeight(el);
    }

    if (type === "Icon") {
      const el = document.createElement("span");
      el.className = "a2ui-icon";
      const nameVal = resolveDynamic(comp.name, dm, itemCtx);
      el.textContent = typeof nameVal === "string" ? "[" + nameVal + "]" : "[icon]";
      return applyWeight(el);
    }

    if (type === "Image") {
      const url = resolveDynamic(comp.url, dm, itemCtx);
      if (!isSafeMediaUrl(url)) {
        const warn = document.createElement("div");
        warn.className = "a2ui-check-error";
        warn.textContent = "Blocked unsafe Image URL.";
        return applyWeight(warn);
      }
      const img = document.createElement("img");
      img.className = "a2ui-media";
      img.src = url;
      img.alt = toDisplayString(resolveDynamic(comp.description, dm, itemCtx));
      if (comp.fit) img.style.objectFit = comp.fit === "scaleDown" ? "scale-down" : comp.fit;
      return applyWeight(img);
    }

    if (type === "Video") {
      const url = resolveDynamic(comp.url, dm, itemCtx);
      if (!isSafeMediaUrl(url)) {
        const warn = document.createElement("div");
        warn.className = "a2ui-check-error";
        warn.textContent = "Blocked unsafe Video URL.";
        return applyWeight(warn);
      }
      const vid = document.createElement("video");
      vid.className = "a2ui-media";
      vid.controls = true;
      vid.src = url;
      if (comp.posterUrl) {
        const poster = resolveDynamic(comp.posterUrl, dm, itemCtx);
        if (isSafeMediaUrl(poster)) vid.poster = poster;
      }
      return applyWeight(vid);
    }

    if (type === "AudioPlayer") {
      const wrap = document.createElement("div");
      wrap.className = "a2ui-field";
      const url = resolveDynamic(comp.url, dm, itemCtx);
      if (!isSafeMediaUrl(url)) {
        const warn = document.createElement("div");
        warn.className = "a2ui-check-error";
        warn.textContent = "Blocked unsafe AudioPlayer URL.";
        wrap.appendChild(warn);
        return applyWeight(wrap);
      }
      if (comp.description) {
        const lbl = document.createElement("label");
        lbl.textContent = toDisplayString(resolveDynamic(comp.description, dm, itemCtx));
        wrap.appendChild(lbl);
      }
      const aud = document.createElement("audio");
      aud.controls = true;
      aud.src = url;
      wrap.appendChild(aud);
      return applyWeight(wrap);
    }

    if (type === "Tabs") {
      const wrap = document.createElement("div");
      const tabs = Array.isArray(comp.tabs) ? comp.tabs : [];
      const activeIdx = surface.tabState[compId] || 0;
      const bar = document.createElement("div");
      bar.className = "a2ui-tabs-bar";
      tabs.forEach((tab, idx) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "a2ui-tab-btn" + (idx === activeIdx ? " active" : "");
        btn.textContent = toDisplayString(resolveDynamic(tab.title, dm, itemCtx)) || "Tab";
        btn.addEventListener("click", () => {
          surface.tabState[compId] = idx;
          renderAll();
        });
        bar.appendChild(btn);
      });
      wrap.appendChild(bar);
      if (tabs[activeIdx]) {
        wrap.appendChild(renderComponent(surface, tabs[activeIdx].child, itemCtx, nextVisited));
      }
      return applyWeight(wrap);
    }

    if (type === "Modal") {
      const wrap = document.createElement("div");
      const trigWrap = document.createElement("div");
      trigWrap.addEventListener("click", () => {
        surface.modalState[compId] = true;
        renderAll();
      });
      trigWrap.appendChild(renderComponent(surface, comp.trigger, itemCtx, nextVisited));
      wrap.appendChild(trigWrap);
      if (surface.modalState[compId]) {
        const backdrop = document.createElement("div");
        backdrop.className = "a2ui-modal-backdrop";
        const dlg = document.createElement("div");
        dlg.className = "a2ui-modal-dialog";
        dlg.appendChild(renderComponent(surface, comp.content, itemCtx, nextVisited));
        const closeBtn = document.createElement("button");
        closeBtn.type = "button";
        closeBtn.className = "a2ui-btn";
        closeBtn.textContent = "Close";
        closeBtn.addEventListener("click", () => {
          surface.modalState[compId] = false;
          renderAll();
        });
        dlg.appendChild(closeBtn);
        backdrop.appendChild(dlg);
        wrap.appendChild(backdrop);
      }
      return applyWeight(wrap);
    }

    if (type === "Button") {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "a2ui-btn " + (comp.variant || "default");
      if (comp.child) btn.appendChild(renderComponent(surface, comp.child, itemCtx, nextVisited));
      btn.addEventListener("click", () => {
        const act = comp.action || {};
        if (act.event) {
          const resolvedCtx = {};
          const rawCtx = act.event.context || {};
          for (const k of Object.keys(rawCtx)) {
            resolvedCtx[k] = resolveDynamic(rawCtx[k], surface.dataModel, itemCtx);
          }
          logAction(surface.id, act.event.name || "action", comp.id, resolvedCtx);
        } else if (act.functionCall) {
          const fn = act.functionCall["@call"];
          const args = act.functionCall.args || {};
          if (fn === "openUrl") {
            const targetUrl = toDisplayString(resolveDynamic(args.url, surface.dataModel, itemCtx));
            if (isSafeOpenUrl(targetUrl)) {
              logAction(surface.id, "openUrl", comp.id, { url: targetUrl });
            } else {
              logAction(surface.id, "blocked_openUrl", comp.id, { reason: "unsafe scheme" });
            }
          } else {
            logAction(surface.id, fn || "functionCall", comp.id, args);
          }
        }
      });
      return applyWeight(btn);
    }

    if (type === "TextField") {
      const wrap = document.createElement("div");
      wrap.className = "a2ui-field";
      const lbl = document.createElement("label");
      lbl.textContent = toDisplayString(resolveDynamic(comp.label, dm, itemCtx));
      wrap.appendChild(lbl);
      const isLong = comp.variant === "longText";
      const input = document.createElement(isLong ? "textarea" : "input");
      input.className = isLong ? "a2ui-textarea" : "a2ui-input";
      if (!isLong) {
        input.type = comp.variant === "obscured" ? "password" : comp.variant === "number" ? "number" : "text";
      }
      if (comp.placeholder) {
        input.placeholder = toDisplayString(resolveDynamic(comp.placeholder, dm, itemCtx));
      }
      const curVal = resolveDynamic(comp.value, dm, itemCtx);
      input.value = toDisplayString(curVal);
      input.addEventListener("input", (e) => {
        if (comp.value && typeof comp.value["@path"] === "string") {
          setByPointer(surface.dataModel, comp.value["@path"], e.target.value, itemCtx);
          refreshReactiveBindings();
        }
      });
      wrap.appendChild(input);
      appendChecks(wrap);
      return applyWeight(wrap);
    }

    if (type === "CheckBox") {
      const wrap = document.createElement("div");
      wrap.className = "a2ui-field";
      const lbl = document.createElement("label");
      lbl.className = "a2ui-checkbox";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = Boolean(resolveDynamic(comp.value, dm, itemCtx));
      cb.addEventListener("change", (e) => {
        if (comp.value && typeof comp.value["@path"] === "string") {
          setByPointer(surface.dataModel, comp.value["@path"], e.target.checked, itemCtx);
          refreshReactiveBindings();
        }
      });
      const txt = document.createElement("span");
      txt.textContent = toDisplayString(resolveDynamic(comp.label, dm, itemCtx));
      lbl.appendChild(cb);
      lbl.appendChild(txt);
      wrap.appendChild(lbl);
      appendChecks(wrap);
      return applyWeight(wrap);
    }

    if (type === "ChoicePicker") {
      const wrap = document.createElement("div");
      wrap.className = "a2ui-field";
      if (comp.label) {
        const lbl = document.createElement("label");
        lbl.textContent = toDisplayString(resolveDynamic(comp.label, dm, itemCtx));
        wrap.appendChild(lbl);
      }
      let filterText = "";
      const optionsBox = document.createElement("div");
      optionsBox.className = comp.displayStyle === "chips" ? "a2ui-chips" : "a2ui-column";
      const multi = comp.variant === "multipleSelection";
      const pickerGroupName = "cp_" + compId + "_" + (++pickerSeq);

      function drawOptions() {
        optionsBox.innerHTML = "";
        const rawSel = resolveDynamic(comp.value, surface.dataModel, itemCtx);
        const selected = Array.isArray(rawSel) ? rawSel : [];
        for (const opt of comp.options || []) {
          const optLabel = toDisplayString(resolveDynamic(opt.label, surface.dataModel, itemCtx)) || toDisplayString(opt.value);
          if (filterText && !optLabel.toLowerCase().includes(filterText)) continue;
          const isSel = selected.includes(opt.value);
          if (comp.displayStyle === "chips") {
            const chip = document.createElement("button");
            chip.type = "button";
            chip.className = "a2ui-chip" + (isSel ? " selected" : "");
            chip.textContent = optLabel;
            chip.addEventListener("click", () => {
              const next = multi
                ? (isSel ? selected.filter((x) => x !== opt.value) : [...selected, opt.value])
                : [opt.value];
              if (comp.value && typeof comp.value["@path"] === "string") {
                setByPointer(surface.dataModel, comp.value["@path"], next, itemCtx);
              }
              drawOptions();
              refreshReactiveBindings();
            });
            optionsBox.appendChild(chip);
          } else {
            const rowLbl = document.createElement("label");
            rowLbl.className = "a2ui-checkbox";
            const inp = document.createElement("input");
            inp.type = multi ? "checkbox" : "radio";
            inp.name = pickerGroupName;
            inp.checked = isSel;
            inp.addEventListener("change", () => {
              const next = multi
                ? (inp.checked ? [...selected, opt.value] : selected.filter((x) => x !== opt.value))
                : [opt.value];
              if (comp.value && typeof comp.value["@path"] === "string") {
                setByPointer(surface.dataModel, comp.value["@path"], next, itemCtx);
              }
              drawOptions();
              refreshReactiveBindings();
            });
            const sp = document.createElement("span");
            sp.textContent = optLabel;
            rowLbl.appendChild(inp);
            rowLbl.appendChild(sp);
            optionsBox.appendChild(rowLbl);
          }
        }
      }

      if (comp.filterable) {
        const search = document.createElement("input");
        search.type = "text";
        search.className = "a2ui-input";
        search.placeholder = "Filter options...";
        search.addEventListener("input", (e) => {
          filterText = e.target.value.trim().toLowerCase();
          drawOptions();
        });
        wrap.appendChild(search);
      }
      drawOptions();
      wrap.appendChild(optionsBox);
      appendChecks(wrap);
      return applyWeight(wrap);
    }

    if (type === "Slider") {
      const wrap = document.createElement("div");
      wrap.className = "a2ui-field";
      const min = typeof comp.min === "number" ? comp.min : 0;
      const max = typeof comp.max === "number" ? comp.max : 100;
      const rawCur = toFiniteNumber(resolveDynamic(comp.value, dm, itemCtx));
      const cur = Number.isNaN(rawCur) ? min : rawCur;
      const lbl = document.createElement("label");
      const baseText = toDisplayString(resolveDynamic(comp.label, dm, itemCtx)) || "Value";
      lbl.textContent = baseText + ": " + cur;
      const range = document.createElement("input");
      range.type = "range";
      range.min = String(min);
      range.max = String(max);
      if (typeof comp.steps === "number" && comp.steps > 0) {
        range.step = String((max - min) / comp.steps);
      }
      range.value = String(cur);
      range.addEventListener("input", (e) => {
        const num = toFiniteNumber(e.target.value);
        if (Number.isNaN(num)) return;
        lbl.textContent = baseText + ": " + num;
        if (comp.value && typeof comp.value["@path"] === "string") {
          setByPointer(surface.dataModel, comp.value["@path"], num, itemCtx);
          refreshReactiveBindings();
        }
      });
      wrap.appendChild(lbl);
      wrap.appendChild(range);
      appendChecks(wrap);
      return applyWeight(wrap);
    }

    if (type === "DateTimeInput") {
      const wrap = document.createElement("div");
      wrap.className = "a2ui-field";
      if (comp.label) {
        const lbl = document.createElement("label");
        lbl.textContent = toDisplayString(resolveDynamic(comp.label, dm, itemCtx));
        wrap.appendChild(lbl);
      }
      const inp = document.createElement("input");
      inp.className = "a2ui-input";
      if (comp.enableDate && comp.enableTime) inp.type = "datetime-local";
      else if (comp.enableTime) inp.type = "time";
      else inp.type = "date";
      const cur = resolveDynamic(comp.value, dm, itemCtx);
      inp.value = toDisplayString(cur);
      inp.addEventListener("change", (e) => {
        if (comp.value && typeof comp.value["@path"] === "string") {
          setByPointer(surface.dataModel, comp.value["@path"], e.target.value, itemCtx);
          refreshReactiveBindings();
        }
      });
      wrap.appendChild(inp);
      appendChecks(wrap);
      return applyWeight(wrap);
    }

    return document.createTextNode("");
  }

  function renderAll() {
    reactiveUpdaters = [];
    surfaceMount.innerHTML = "";
    const ids = Array.from(surfaces.keys());
    surfaceLabel.textContent = ids.length ? ids.join(", ") : "none";
    for (const s of surfaces.values()) {
      if (s.components.has("root")) {
        surfaceMount.appendChild(renderComponent(s, "root", null, new Set()));
      }
    }
  }

  const initialThemeMode = document.documentElement.getAttribute("data-theme-mode") || "precision-noir";
  let manualThemeOverride = false;
  function applyTheme(mode) {
    const isLight = mode === "light";
    document.body.classList.toggle("a2ui-dark", !isLight);
    document.body.classList.toggle("a2ui-light", isLight);
    document.documentElement.setAttribute("data-theme", isLight ? "light" : "precision-noir");
    if (toggleThemeBtn) toggleThemeBtn.textContent = isLight ? "Dark" : "Light";
  }
  if (initialThemeMode === "auto" && typeof window !== "undefined" && typeof window.matchMedia === "function") {
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    applyTheme(mq.matches ? "light" : "precision-noir");
    const onSchemeChange = (e) => {
      if (!manualThemeOverride) applyTheme(e.matches ? "light" : "precision-noir");
    };
    if (typeof mq.addEventListener === "function") mq.addEventListener("change", onSchemeChange);
    else if (typeof mq.addListener === "function") mq.addListener(onSchemeChange);
  }

  sourceView.textContent = JSON.stringify(messages, null, 2);
  toggleSourceBtn.addEventListener("click", () => {
    showingSource = !showingSource;
    surfaceMount.style.display = showingSource ? "none" : "flex";
    sourceView.style.display = showingSource ? "block" : "none";
    toggleSourceBtn.textContent = showingSource ? "UI" : "JSON";
  });
  toggleThemeBtn.addEventListener("click", () => {
    manualThemeOverride = true;
    const isDark = document.body.classList.contains("a2ui-dark");
    applyTheme(isDark ? "light" : "precision-noir");
  });
  clearLogBtn.addEventListener("click", () => {
    actionLogs.length = 0;
    inspectorLog.textContent = "Click any A2UI button above to inspect the dispatched action JSON.";
  });

  renderAll();
})();
"""


def render_preview_html(
    raw_text: str,
    *,
    extract_markdown: bool = False,
    theme: str = "precision-noir",
    title: str = "legends-a2ui Static Preview",
) -> dict[str, Any]:
    """Normalize input to strict A2UI v1.0 and generate an offline static HTML5 preview."""
    norm = normalize_payload(raw_text, extract_markdown=extract_markdown, fmt="json")
    if not norm["ok"]:
        return {
            "ok": False,
            "html": "",
            "validation": norm["validation"],
            "changesApplied": norm["changesApplied"],
        }

    theme_mode = theme if theme in {"precision-noir", "light", "auto"} else "precision-noir"
    body_class = "a2ui-light" if theme_mode == "light" else "a2ui-dark"
    data_theme = "light" if theme_mode == "light" else "precision-noir"
    toggle_label = "Dark" if theme_mode == "light" else "Light"
    safe_title = html.escape(title)
    embedded_json = _safe_embed_json(norm["payload"])

    document = f"""<!DOCTYPE html>
<html lang="en" data-theme="{data_theme}" data-theme-mode="{html.escape(theme_mode)}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="{STRICT_CSP}">
  <title>{safe_title}</title>
  <style>{_PREVIEW_CSS}</style>
</head>
<body class="{body_class}">
  <div class="shell">
    <div class="frame">
      <div class="topbar">
        <div class="topbar-meta">
          <span class="signal-pip" aria-hidden="true"></span>
          <span class="eyebrow">A2UI v1.0 STATIC PREVIEW</span>
          <span class="eyebrow">/</span>
          <span id="surface-id-label">loading</span>
        </div>
        <div class="chrome-actions">
          <button id="toggle-source-btn" class="chrome-btn" type="button">JSON</button>
          <button id="toggle-theme-btn" class="chrome-btn" type="button">{toggle_label}</button>
        </div>
      </div>
      <div id="surface-mount" class="surface-body"></div>
      <pre id="source-view" class="source-view" style="display:none;"></pre>
    </div>
    <div class="inspector">
      <div class="topbar">
        <div class="topbar-meta">
          <span class="signal-pip" aria-hidden="true"></span>
          <span class="eyebrow">ACTION EVENT INSPECTOR</span>
        </div>
        <div class="chrome-actions">
          <button id="clear-log-btn" class="chrome-btn" type="button">Clear</button>
        </div>
      </div>
      <pre id="inspector-log" class="inspector-log">Click any A2UI button above to inspect the dispatched action JSON.</pre>
    </div>
  </div>
  <script type="application/json" id="a2ui-payload">{embedded_json}</script>
  <script>{_PREVIEW_JS}</script>
</body>
</html>
"""
    return {
        "ok": True,
        "html": document,
        "validation": norm["validation"],
        "changesApplied": norm["changesApplied"],
    }
