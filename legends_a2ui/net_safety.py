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
_DARWIN_SYSTEM_SYMLINKS = frozenset({Path("/var"), Path("/tmp"), Path("/etc")})
_CFA_USER_FOLDERS = (
    "Desktop",
    "Documents",
    "Pictures",
    "Videos",
    "Music",
    "OneDrive",
)


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
    """Refuse any symlink or Windows reparse point along a path chain (CWE-59)."""
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
        ):
            val = os.environ.get(env_key, fallback)
            if val:
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


def compute_plan_sha256(planned_entries: list[dict[str, Any]]) -> str:
    """Compute deterministic SHA-256 over planned file paths, sizes, and content digests."""
    canonical = sorted(
        (
            {
                "path": str(item["path"]),
                "bytes": int(item["bytes"]),
                "sha256": str(item["sha256"]),
            }
            for item in planned_entries
        ),
        key=lambda row: row["path"],
    )
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _atomic_write_bytes(target: Path, data: bytes, *, overwrite: bool) -> None:
    """Write bytes atomically with O_CREAT|O_EXCL no-clobber default."""
    target.parent.mkdir(parents=True, exist_ok=True)
    reject_symlink_chain(target.parent)
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
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
        except Exception:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        return

    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=".legends-a2ui-", suffix=".tmp", dir=str(target.parent)
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(tmp_fd, "wb") as handle:
            handle.write(data)
        os.replace(str(tmp_path), str(target))
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


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

    for raw_target, content in planned:
        target = Path(raw_target)
        reject_symlink_chain(target)
        if base_dir is not None:
            target = ensure_within_base(target, base_dir)
        else:
            target = Path(os.path.abspath(str(target)))
        reject_cfa_protected_path(target)
        digest = hashlib.sha256(content).hexdigest()
        rel_display = (
            target.relative_to(base_dir.resolve()).as_posix()
            if base_dir is not None
            else str(target)
        )
        entries.append(
            {
                "path": rel_display,
                "absolutePath": str(target),
                "bytes": len(content),
                "sha256": digest,
                "exists": target.exists(),
            }
        )
        validated_pairs.append((target, content))

    plan_sha = compute_plan_sha256(entries)

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
    """Return True only if IP is globally routable (rejects private/loopback/CGNAT/link-local)."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if addr.version == 4 and addr in _CGNAT_NET:
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
        self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)


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
        "User-Agent": "legends-a2ui/0.1.0",
        "Accept": "application/json",
    }
    if headers:
        req_headers.update(headers)

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

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
