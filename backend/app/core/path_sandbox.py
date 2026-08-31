"""
Contract 01 §6 & Contract 08 §12.3:
Filesystem Workspace Containment & Target Path Sandboxing.
Prevents arbitrary host filesystem scanning, directory traversal, and sensitive credential exposure.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import List, Optional, Tuple


# Sensitive system root directory denylists (normalized lower-case prefixes)
FORBIDDEN_POSIX_DIRECTORIES = [
    "/etc",
    "/root",
    "/var/run",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/private/etc",
    "/private/var",
]

FORBIDDEN_WINDOWS_DIRECTORIES = [
    "c:\\windows",
    "c:\\winnt",
    "c:\\program files",
    "c:\\program files (x86)",
    "c:\\programdata",
    "c:\\recovery",
    "c:\\system volume information",
]

FORBIDDEN_FILE_PATTERNS = [
    "id_rsa",
    "id_ed25519",
    "id_dsa",
    "credentials",
    ".aws/credentials",
    ".ssh/authorized_keys",
    ".kube/config",
    "shadow",
    "passwd",
    "sam",
    "system",
    "security",
]


class PathSandboxViolation(ValueError):
    """Raised when a requested scan target path is outside allowed workspace boundaries or targets protected files."""
    pass


def get_default_workspace_dir() -> Path:
    """Returns the default allowed workspace base path."""
    base = Path(__file__).resolve().parent.parent.parent.parent / "data" / "workspaces"
    base.mkdir(parents=True, exist_ok=True)
    return base


def is_path_safe(path_str: str, allowed_roots: Optional[List[Path]] = None) -> Tuple[bool, Optional[str]]:
    """
    Validates whether a filesystem path is permitted for automated security inspection.
    """
    if not path_str or not isinstance(path_str, str):
        return False, "Target path cannot be empty."

    raw_val = path_str.strip()
    
    # Check for direct sensitive file targeting
    lower_val = raw_val.lower().replace("\\", "/")
    for pattern in FORBIDDEN_FILE_PATTERNS:
        if lower_val == pattern or lower_val.endswith("/" + pattern) or lower_val.endswith("\\" + pattern):
            return False, f"Direct access to sensitive credential/system target '{pattern}' is prohibited."

    try:
        resolved = Path(raw_val).expanduser().resolve()
    except Exception as exc:
        return False, f"Failed to resolve path '{raw_val}': {str(exc)}"

    if not resolved.exists():
        return False, f"Target path does not exist on filesystem: '{raw_val}'."

    resolved_str = str(resolved).lower()

    # POSIX system checks
    for forbidden in FORBIDDEN_POSIX_DIRECTORIES:
        if resolved_str == forbidden or resolved_str.startswith(forbidden + "/"):
            return False, f"Target path '{raw_val}' resides within protected system directory '{forbidden}'."

    # Windows system checks
    for forbidden in FORBIDDEN_WINDOWS_DIRECTORIES:
        if resolved_str == forbidden or resolved_str.startswith(forbidden + "\\") or resolved_str.startswith(forbidden + "/"):
            return False, f"Target path '{raw_val}' resides within protected system directory '{forbidden}'."

    # Sensitive user directories
    user_home = str(Path.home()).lower()
    for sensitive_sub in (".ssh", ".aws", ".kube", ".gnupg"):
        sensitive_path = os.path.join(user_home, sensitive_sub).lower()
        if resolved_str == sensitive_path or resolved_str.startswith(sensitive_path + os.sep):
            return False, f"Target path '{raw_val}' attempts to access sensitive user directory '{sensitive_sub}'."

    # If explicit allowed_roots are configured, ensure resolved path is contained within one of them
    if allowed_roots:
        resolved_allowed = [r.resolve() for r in allowed_roots if r.exists()]
        if resolved_allowed:
            is_contained = any(
                resolved == root or root in resolved.parents
                for root in resolved_allowed
            )
            if not is_contained:
                return False, f"Target path '{raw_val}' is outside permitted workspace roots."

    return True, None


def assert_safe_path(path_str: str, allowed_roots: Optional[List[Path]] = None) -> Path:
    """
    Validates that a path is safe and returns the resolved Path object.
    Raises PathSandboxViolation if disallowed.
    """
    safe, reason = is_path_safe(path_str, allowed_roots=allowed_roots)
    if not safe:
        raise PathSandboxViolation(reason or "Path sandbox violation.")
    return Path(path_str).expanduser().resolve()
