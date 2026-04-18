# constraints.py — architectural guardrails for sift-mcp
# Enforced at the MCP layer — not prompt-based

import os
from pathlib import Path

# Paths the server is allowed to read from
# Forensic tools need broad read access — write access remains tightly restricted
ALLOWED_READ_PATHS = [
    "/cases",
    "/opt",
    "/tmp",
    "/home",
    "/usr",
    "/bin",
    "/sbin",
    "/etc",
    "/var",
    "/lib",
    "/mnt",
    "/media",
    "/srv",
]

# Paths the server is allowed to write to
ALLOWED_WRITE_PATHS = [
    "/cases",
    "/home/sansforensics/sift-mcp/logs",
]


class ConstraintError(Exception):
    """Raised when an operation violates a guardrail."""
    pass


def check_path(path: str, write: bool = False) -> Path:
    """Verify path is within the allowed allowlist. Raises ConstraintError if not."""
    resolved = Path(path).resolve()
    allowed = ALLOWED_WRITE_PATHS if write else ALLOWED_READ_PATHS
    for allowed_path in allowed:
        if str(resolved).startswith(str(Path(allowed_path).resolve())):
            return resolved
    action = "write to" if write else "read from"
    raise ConstraintError(
        f"Blocked: attempt to {action} path outside allowlist: {resolved}"
    )


def require_case(case_id: str) -> None:
    """Verify a case directory exists before allowing forensic operations."""
    case_dir = Path(f"/cases/{case_id}")
    if not case_dir.exists():
        raise ConstraintError(
            f"Blocked: case '{case_id}' does not exist. Call case_create first."
        )


def no_arbitrary_exec(command: str) -> None:
    """Placeholder guard — MCP tools must never pass raw shell commands."""
    raise ConstraintError(
        "Blocked: arbitrary shell execution is not permitted. Use a registered tool."
    )
