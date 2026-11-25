"""Security and filesystem safety guards (CWE-22, CWE-59, CWE-918, Windows CFA)."""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import sys
import tempfile
from typing import Any
from urllib.parse import urljoin, urlsplit

from legends_a2ui import __version__


class SafetyError(RuntimeError):
    """Raised when a path, symlink, CFA, overwrite, plan, or network guard fails."""


LIVE_ALLOWED_HOSTS = frozenset(
    {
        "registry.npmjs.org",
        "pypi.org",
        "api.github.com",
        "a2ui.org",
    }
)

_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
_DARWIN_SYSTEM_SYMLINKS = frozenset({Path("/var"), Path("/tmp"), Path("/etc")})
_WINDOWS_RESERVED_DEVICES = frozenset(
    {
        "CON",
        "CONIN$",
        "CONOUT$",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
        "COM\u00b9",
        "COM\u00b2",
        "COM\u00b3",
        "LPT\u00b9",
        "LPT\u00b2",
        "LPT\u00b3",
    }
)
_CFA_USER_FOLDERS = (
    "Desktop",
    "Documents",
    "Pictures",
    "Videos",
    "Music",
    "OneDrive",
)


def reject_unsafe_local_path(path: Path | str) -> None:
    """Refuse UNC paths, extended/NT device prefixes, NTFS ADS, and reserved Windows DOS device names."""
    raw = str(path)
    if "\x00" in raw:
        raise SafetyError("Refusing path containing NUL byte.")
    if raw.startswith(("\\\\", "//", "/\\", "\\/")):
        raise SafetyError(f"Refusing UNC or Windows device path: {raw}")
    if raw.startswith(("\\.\\", "\\?\\", "\\??\\", "/??/")):
        raise SafetyError(f"Refusing Windows device namespace path: {raw}")
    try:
        drive = Path(raw).drive
    except Exception:
        drive = ""
    if drive.startswith(("\\\\", "//")):
        raise SafetyError(f"Refusing UNC drive path: {raw}")

    for idx, seg in enumerate(raw.replace("\\", "/").split("/")):
        if not seg:
            continue
        if idx == 0 and len(seg) == 2 and seg[1] == ":" and seg[0].isalpha():
            continue
        if ":" in seg:
            raise SafetyError(
                f"Refusing colon, drive-relative path, or NTFS alternate data stream '{seg}' in path: {raw}"
            )
        seg_head = seg.split(":", 1)[0]
        base = seg_head.split(".", 1)[0].rstrip(" ").upper()
        if base in _WINDOWS_RESERVED_DEVICES:
            raise SafetyError(f"Refusing reserved Windows device name '{seg}' in path: {raw}")


def _is_reparse_point(path: Path) -> bool:
    """Detect symlinks and Windows reparse points using stdlib os.lstat only."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    file_attrs = getattr(st, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
    return bool(file_attrs & reparse_flag)


def reject_symlink_chain(path: Path) -> None:
    """Refuse unsafe local paths and any symlink or Windows reparse point along a path chain (CWE-59)."""
    reject_unsafe_local_path(path)
    candidate = Path(os.path.abspath(str(path)))
    parts = candidate.parts
    if not parts:
        return
    current = Path(parts[0])
    for part in parts[1:]:
        current = current / part
        if sys.platform == "darwin" and current in _DARWIN_SYSTEM_SYMLINKS:
            continue
        if _is_reparse_point(current):
            raise SafetyError(
                f"Refusing symlink or reparse point in path chain: {current}"
            )


def ensure_within_base(target: Path, base: Path) -> Path:
    """Ensure target resolves inside base directory without traversal (CWE-22)."""
    reject_symlink_chain(base)
    reject_symlink_chain(target)
    resolved_base = base.resolve()
    resolved_target = target.resolve()
    if not resolved_target.is_relative_to(resolved_base):
        raise SafetyError(
            f"Path escapes base directory ({resolved_base}): {target}"
        )
    return resolved_target


def _normalized_cmp(path: Path) -> str:
    text = os.path.normcase(os.path.abspath(str(path)))
    return text.rstrip("\\/")


def is_cfa_protected_path(path: Path) -> bool:
    """Return True if path falls inside Windows Controlled Folder Access or OS roots."""
    norm = _normalized_cmp(path)
    home = Path.home()
    protected: list[Path] = [home / folder for folder in _CFA_USER_FOLDERS]
    protected.append(home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu")

    if os.name == "nt":
        for env_key, fallback in (
            ("SystemRoot", "C:\\Windows"),
            ("ProgramFiles", "C:\\Program Files"),
            ("ProgramFiles(x86)", "C:\\Program Files (x86)"),
            ("ProgramData", "C:\\ProgramData"),
        ):
            val = os.environ.get(env_key) or fallback
            if val and len(Path(val).parts) >= 2:
                protected.append(Path(val))
        for od_key in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
            val = os.environ.get(od_key)
            if val and len(Path(val).parts) >= 2:
                protected.append(Path(val))

    for root in protected:
        root_norm = _normalized_cmp(root)
        if norm == root_norm or norm.startswith(root_norm + os.sep):
            return True
    return False


def reject_cfa_protected_path(path: Path) -> None:
    """Refuse writing into Controlled Folder Access or protected OS directories."""
    if is_cfa_protected_path(path):
        raise SafetyError(
            f"Refusing write into protected OS or Controlled Folder Access path: {path}"
        )


def compute_plan_sha256(
    planned_entries: list[dict[str, Any]],
    *,
    base_dir: Path | str | None = None,
) -> str:
    """Compute deterministic SHA-256 over normalized target paths, content, and pre-mutation state."""
    canonical = sorted(
        (
            {
                "path": str(item["path"]),
                "absolutePath": _normalized_cmp(Path(str(item.get("absolutePath") or item["path"]))),
                "bytes": int(item["bytes"]),
                "sha256": str(item["sha256"]),
                "exists": bool(item.get("exists", False)),
                "existingSha256": item.get("existingSha256"),
            }
            for item in planned_entries
        ),
        key=lambda row: (row["absolutePath"], row["path"]),
    )
    payload = {
        "baseDir": _normalized_cmp(Path(str(base_dir))) if base_dir is not None else None,
        "entries": canonical,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _atomic_write_bytes(target: Path, data: bytes, *, overwrite: bool) -> None:
    """Write bytes atomically with O_CREAT|O_EXCL no-clobber default."""
    reject_symlink_chain(target)
    if target.exists() and target.is_dir():
        raise SafetyError(f"Refusing to overwrite directory target: {target}")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SafetyError(f"Cannot create parent directory for {target}: {exc}") from exc
    reject_symlink_chain(target.parent)
    if target.exists() and target.is_dir():
        raise SafetyError(f"Refusing to overwrite directory target: {target}")
    if target.exists() and not overwrite:
        raise SafetyError(f"Target file already exists (pass --overwrite to replace): {target}")
    if _is_reparse_point(target):
        raise SafetyError(f"Refusing to write through symlink/reparse target: {target}")

    if not overwrite:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        try:
            fd = os.open(str(target), flags, 0o644)
        except FileExistsError as exc:
            raise SafetyError(
                f"Target file already exists (pass --overwrite to replace): {target}"
            ) from exc
        except OSError as exc:
            raise SafetyError(f"Failed to create target file {target}: {exc}") from exc
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
        except OSError as exc:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass
            raise SafetyError(f"Failed writing target file {target}: {exc}") from exc
        return

    try:
        tmp_fd, tmp_name = tempfile.mkstemp(
            prefix=".legends-a2ui-", suffix=".tmp", dir=str(target.parent)
        )
    except OSError as exc:
        raise SafetyError(f"Failed creating temporary file next to {target}: {exc}") from exc
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(tmp_fd, "wb") as handle:
            handle.write(data)
        if target.exists() and target.is_dir():
            raise SafetyError(f"Refusing to overwrite directory target: {target}")
        if _is_reparse_point(target):
            raise SafetyError(f"Refusing to write through symlink/reparse target: {target}")
        os.replace(str(tmp_path), str(target))
    except SafetyError:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    except OSError as exc:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise SafetyError(f"Atomic replace failed for {target}: {exc}") from exc


def execute_write_plan(
    planned: list[tuple[Path, bytes]],
    *,
    apply: bool = False,
    confirm_plan: str | None = None,
    overwrite: bool = False,
    base_dir: Path | None = None,
) -> dict[str, Any]:
    """Preview or apply a multi-file write plan with SHA-256 confirmation and safety checks."""
    entries: list[dict[str, Any]] = []
    validated_pairs: list[tuple[Path, bytes]] = []
    resolved_base: Path | None = None
    if base_dir is not None:
        reject_symlink_chain(base_dir)
        resolved_base = base_dir.resolve()

    for raw_target, content in planned:
        target = Path(raw_target)
        reject_symlink_chain(target)
        if base_dir is not None:
            target = ensure_within_base(target, base_dir)
        else:
            target = Path(os.path.abspath(str(target)))
        reject_cfa_protected_path(target)
        if target.exists() and target.is_dir():
            raise SafetyError(f"Refusing directory as file write target: {target}")
        exists = target.exists()
        existing_sha256: str | None = None
        if target.is_file():
            try:
                existing_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
            except OSError as exc:
                raise SafetyError(f"Cannot hash existing file {target}: {exc}") from exc
        digest = hashlib.sha256(content).hexdigest()
        rel_display = (
            target.relative_to(resolved_base).as_posix()
            if resolved_base is not None
            else str(target)
        )
        entries.append(
            {
                "path": rel_display,
                "absolutePath": str(target),
                "bytes": len(content),
                "sha256": digest,
                "exists": exists,
                "existingSha256": existing_sha256,
            }
        )
        validated_pairs.append((target, content))

    plan_sha = compute_plan_sha256(entries, base_dir=resolved_base)

    if not apply:
        return {
            "mode": "preview",
            "applied": False,
            "planSha256": plan_sha,
            "plannedFiles": entries,
        }

    if not confirm_plan or confirm_plan.strip().lower() != plan_sha:
        raise SafetyError(
            f"Plan confirmation mismatch. Re-run with --apply --confirm-plan {plan_sha}"
        )

    existing_conflicts = [e["absolutePath"] for e in entries if e["exists"]]
    if existing_conflicts and not overwrite:
        raise SafetyError(
            "Refusing to clobber existing file(s) without --overwrite: "
            + ", ".join(existing_conflicts[:5])
        )

    written: list[str] = []
    for target, content in validated_pairs:
        _atomic_write_bytes(target, content, overwrite=overwrite)
        written.append(str(target))

    return {
        "mode": "apply",
        "applied": True,
        "planSha256": plan_sha,
        "plannedFiles": entries,
        "writtenFiles": written,
    }


def is_public_ip(ip_str: str) -> bool:
    """Return True only if IP is globally routable (rejects private/loopback/CGNAT/link-local/transition)."""
    if not isinstance(ip_str, str) or "%" in ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NET:
        return False
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return is_public_ip(str(addr.ipv4_mapped))
        if addr.sixtofour is not None:
            return False
        if addr.teredo is not None:
            return False
        if addr in _NAT64_WELL_KNOWN or addr in _NAT64_LOCAL:
            return False
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return False
    return bool(addr.is_global)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection pinned to a pre-validated IP address with SNI verification."""

    def __init__(
        self,
        host: str,
        pinned_ip: str,
        port: int = 443,
        *,
        timeout: float = 10.0,
        context: ssl.SSLContext | None = None,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        raw_sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)
        except BaseException:
            raw_sock.close()
            raise


def _resolve_pinned_public_ip(hostname: str, port: int) -> str:
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise SafetyError(f"DNS lookup failed for {hostname}: {exc}") from exc
    if not infos:
        raise SafetyError(f"No DNS records returned for {hostname}")
    ips = []
    for _family, _socktype, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if not is_public_ip(ip):
            raise SafetyError(f"Refusing non-public resolved IP {ip} for {hostname}")
        if ip not in ips:
            ips.append(ip)
    return ips[0]


def create_tls_context() -> ssl.SSLContext:
    """Create a strict TLS 1.2+ SSLContext, opportunistically loading certifi if installed."""
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_ctx.check_hostname = True
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        import certifi  # type: ignore[import-not-found]

        cafile = certifi.where()
        if cafile and os.path.isfile(cafile):
            ssl_ctx.load_verify_locations(cafile=cafile)
    except Exception:
        pass
    return ssl_ctx


def safe_https_get_json(
    url: str,
    *,
    timeout: float = 10.0,
    max_redirects: int = 5,
    max_bytes: int = 2_097_152,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Fetch JSON over HTTPS with host allowlist, DNS IP pinning, and safe redirects (CWE-918)."""
    current_url = url
    req_headers = {
        "User-Agent": f"legends-a2ui/{__version__}",
        "Accept": "application/json",
    }
    if headers:
        req_headers.update(headers)

    ssl_ctx = create_tls_context()

    for _hop in range(max_redirects + 1):
        parsed = urlsplit(current_url)
        if parsed.scheme.lower() != "https":
            raise SafetyError(f"Only HTTPS URLs are allowed: {current_url}")
        hostname = (parsed.hostname or "").lower()
        if hostname not in LIVE_ALLOWED_HOSTS:
            raise SafetyError(f"Host not in HTTPS allowlist: {hostname}")
        port = parsed.port or 443
        if port != 443:
            raise SafetyError(f"Non-standard HTTPS port refused: {port}")

        pinned_ip = _resolve_pinned_public_ip(hostname, port)
        target_path = parsed.path or "/"
        if parsed.query:
            target_path = f"{target_path}?{parsed.query}"

        conn = _PinnedHTTPSConnection(
            hostname, pinned_ip, port=port, timeout=timeout, context=ssl_ctx
        )
        try:
            conn.request("GET", target_path, headers=req_headers)
            resp = conn.getresponse()
            status = resp.status
            if status in (301, 302, 303, 307, 308):
                location = resp.getheader("Location")
                resp.read(1024)
                if not location:
                    raise SafetyError(f"Redirect without Location header from {current_url}")
                current_url = urljoin(current_url, location)
                continue
            if status != 200:
                raise SafetyError(f"HTTP {status} from {hostname}{target_path}")
            body = resp.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise SafetyError(f"Response exceeded {max_bytes} bytes from {hostname}")
            data = json.loads(body.decode("utf-8"))
            if not isinstance(data, dict):
                return {"data": data}
            return data
        except SafetyError:
            raise
        except Exception as exc:
            raise SafetyError(f"HTTPS request failed for {hostname}: {exc}") from exc
        finally:
            conn.close()

    raise SafetyError(f"Exceeded max redirects ({max_redirects}) for {url}")
