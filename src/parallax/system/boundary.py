"""Linux security boundaries, DAC auditing, and helper orchestration for PARALLAX.

Defines the ground-truth system specification and verification functions:
- User identities and privilege tiers (analyst, rhea, svc-pulse, root).
- Discretionary Access Control (DAC) permissions and setuid boundary.
- Systemd service definition and process isolation parsing.
- Linux auditd syscall monitoring rules.
- Helper compilation and execution harness for reproducible verification.
"""

from __future__ import annotations

import configparser
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
from typing import Any

# Ground Truth Identity Definitions
ANALYST_USER = "analyst"
ANALYST_UID = 1000
ANALYST_GID = 1000

RHEA_USER = "rhea"
RHEA_UID = 1001
RHEA_GID = 1001

SVC_PULSE_USER = "svc-pulse"
SVC_PULSE_UID = 1002
SVC_PULSE_GID = 1002

ROOT_USER = "root"
ROOT_UID = 0
ROOT_GID = 0

# Security Boundary Specification
BOUNDARY_SPEC: dict[str, dict[str, Any]] = {
    "/usr/local/bin/pulse-helper": {
        "description": "Privileged maintenance helper (setuid root for svc-pulse)",
        "expected_mode": 0o4750,  # -rwsr-x---
        "expected_owner": ROOT_USER,
        "expected_group": SVC_PULSE_USER,
        "is_setuid": True,
        "required_for_playthrough": True,
    },
    "/var/archive/meridian": {
        "description": "Restricted archive directory containing encrypted vaults",
        "expected_mode": 0o0700,  # drwx------
        "expected_owner": ROOT_USER,
        "expected_group": ROOT_USER,
        "is_setuid": False,
        "required_for_playthrough": True,
    },
    "/etc/pulse/pulse.conf": {
        "description": "PULSE/1 daemon configuration file",
        "expected_mode": 0o0644,  # -rw-r--r--
        "expected_owner": ROOT_USER,
        "expected_group": ROOT_USER,
        "is_setuid": False,
        "required_for_playthrough": True,
    },
    "/var/log/pulse": {
        "description": "PULSE/1 application log directory",
        "expected_mode": 0o0750,  # drwxr-x---
        "expected_owner": SVC_PULSE_USER,
        "expected_group": SVC_PULSE_USER,
        "is_setuid": False,
        "required_for_playthrough": True,
    },
    "/var/log/audit/audit.log": {
        "description": "Linux auditd log (read-only for analyst via POSIX ACL)",
        "expected_mode": 0o0640,  # -rw-r-----
        "expected_owner": ROOT_USER,
        "expected_group": ROOT_USER,
        "is_setuid": False,
        "required_for_playthrough": True,
    },
}

DEFAULT_C_SOURCE = Path(__file__).resolve().parent.parent.parent / "helper" / "pulse-helper.c"


def compile_helper(
    source_file: str | Path | None = None,
    output_binary: str | Path | None = None,
    fixed_mode: bool = False,
    cc: str = "cc",
) -> Path:
    """Compile pulse-helper from C source.

    Args:
        source_file: Path to pulse-helper.c. Defaults to src/helper/pulse-helper.c.
        output_binary: Path to destination binary. Defaults to adjacent binary name.
        fixed_mode: If True, compiles with -DFIXED_MODE (hardened).
        cc: C compiler command (default: cc).

    Returns:
        Path to compiled binary.

    Raises:
        FileNotFoundError: If source file or compiler cannot be found.
        RuntimeError: If compilation fails.
    """
    src = Path(source_file) if source_file else DEFAULT_C_SOURCE
    if not src.is_file():
        raise FileNotFoundError(f"C source file not found at: {src}")

    if not shutil.which(cc):
        raise FileNotFoundError(f"C compiler '{cc}' not found in PATH")

    if output_binary:
        out = Path(output_binary)
    else:
        out_name = "pulse-helper-fixed" if fixed_mode else "pulse-helper"
        out = src.parent / out_name

    out.parent.mkdir(parents=True, exist_ok=True)

    cmd = [cc, "-Wall", "-Wextra", "-O2", "-std=c99", "-o", str(out), str(src)]
    if fixed_mode:
        cmd.insert(5, "-DFIXED_MODE")

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Compilation failed (code {proc.returncode}):\n{proc.stderr}\n{proc.stdout}"
        )

    out.chmod(0o0755)
    return out


def run_helper(
    helper_binary: str | Path,
    archive_path: str,
    archive_dir: str | None = None,
    extra_args: list[str] | None = None,
    timeout: float = 5.0,
) -> subprocess.CompletedProcess[str]:
    """Execute pulse-helper --archive-check <archive_path>.

    Args:
        helper_binary: Path to compiled pulse-helper executable.
        archive_path: Argument passed to --archive-check.
        archive_dir: Optional PARALLAX_ARCHIVE_DIR environment override.
        extra_args: Optional additional arguments.
        timeout: Execution timeout in seconds.

    Returns:
        subprocess.CompletedProcess containing returncode, stdout, and stderr.
    """
    binary = Path(helper_binary).resolve()
    if not binary.is_file():
        raise FileNotFoundError(f"Helper binary not found: {binary}")

    cmd = [str(binary), "--archive-check", archive_path]
    if extra_args:
        cmd.extend(extra_args)

    env = dict(os.environ)
    if archive_dir:
        env["PARALLAX_ARCHIVE_DIR"] = archive_dir

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def parse_systemd_unit(content_or_path: str | Path) -> dict[str, dict[str, str]]:
    """Parse a systemd service unit file into sections and key-value pairs."""
    text: str
    if isinstance(content_or_path, Path) or (
        isinstance(content_or_path, str) and "\n" not in content_or_path and Path(content_or_path).is_file()
    ):
        text = Path(content_or_path).read_text(encoding="utf-8")
    else:
        text = str(content_or_path)

    config = configparser.ConfigParser(interpolation=None, strict=False)
    # preserve option case
    config.optionxform = lambda option: option  # type: ignore[assignment]
    config.read_string(text)

    return {section: dict(config.items(section)) for section in config.sections()}


def validate_systemd_unit(unit_dict: dict[str, dict[str, str]]) -> tuple[bool, list[str]]:
    """Validate systemd unit directives against security requirements.

    Requirements:
    - User is 'svc-pulse'
    - Group is 'svc-pulse'
    - ExecStart binds strictly to loopback (127.0.0.1) and port 7741
    - Slice is 'system.slice'
    - Logging redirects to /var/log/pulse/pulse.log
    """
    errors: list[str] = []

    service = unit_dict.get("Service", {})
    if not service:
        return False, ["Missing [Service] section in unit definition"]

    if service.get("User") != SVC_PULSE_USER:
        errors.append(f"Expected User={SVC_PULSE_USER}, got {service.get('User')}")

    if service.get("Group") != SVC_PULSE_USER:
        errors.append(f"Expected Group={SVC_PULSE_USER}, got {service.get('Group')}")

    exec_start = service.get("ExecStart", "")
    if "127.0.0.1" not in exec_start:
        errors.append("ExecStart must strictly bind to loopback (127.0.0.1)")
    if "7741" not in exec_start:
        errors.append("ExecStart must specify port 7741")

    if service.get("Slice") != "system.slice":
        errors.append(f"Expected Slice=system.slice, got {service.get('Slice')}")

    stdout_dest = service.get("StandardOutput", "")
    if "pulse.log" not in stdout_dest:
        errors.append("StandardOutput should direct to pulse.log")

    return (len(errors) == 0, errors)


def parse_audit_rules(content_or_path: str | Path) -> list[str]:
    """Parse auditd rules file into active rule lines."""
    text: str
    if isinstance(content_or_path, Path) or (
        isinstance(content_or_path, str) and "\n" not in content_or_path and Path(content_or_path).is_file()
    ):
        text = Path(content_or_path).read_text(encoding="utf-8")
    else:
        text = str(content_or_path)

    lines: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def validate_audit_rules(rules: list[str]) -> tuple[bool, list[str]]:
    """Validate that audit rules contain tracking for pulse-helper execve."""
    errors: list[str] = []
    found_helper_rule = False

    for rule in rules:
        if (
            "pulse-helper" in rule
            and "execve" in rule
            and "always,exit" in rule
            and "b64" in rule
        ):
            found_helper_rule = True
            break

    if not found_helper_rule:
        errors.append(
            "Missing required kernel execve audit rule for /usr/local/bin/pulse-helper"
        )

    return (len(errors) == 0, errors)


def audit_host_boundaries(target_root: str | Path = "/") -> dict[str, Any]:
    """Inspect host filesystem permissions against the ground-truth boundary spec.

    Args:
        target_root: Filesystem root path to inspect (defaults to /).

    Returns:
        Dictionary with per-path audit results, platform info, and overall status.
    """
    root = Path(target_root)
    results: dict[str, Any] = {
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
            "is_linux": platform.system() == "Linux",
        },
        "paths": {},
        "overall_compliant": True,
        "missing_paths": 0,
        "mismatched_paths": 0,
    }

    for path_str, spec in BOUNDARY_SPEC.items():
        rel = path_str.lstrip("/")
        actual_path = root / rel

        item_result: dict[str, Any] = {
            "description": spec["description"],
            "expected_mode": oct(spec["expected_mode"]),
            "expected_owner": spec["expected_owner"],
            "expected_group": spec["expected_group"],
            "exists": actual_path.exists(),
        }

        if not actual_path.exists():
            item_result["status"] = "MISSING"
            results["missing_paths"] += 1
            if spec["required_for_playthrough"]:
                results["overall_compliant"] = False
        else:
            file_stat = actual_path.stat()
            actual_mode = stat.S_IMODE(file_stat.st_mode)
            item_result["actual_mode"] = oct(actual_mode)
            item_result["is_setuid"] = bool(file_stat.st_mode & stat.S_ISUID)

            mode_match = (actual_mode == spec["expected_mode"])
            setuid_match = (item_result["is_setuid"] == spec["is_setuid"])

            if mode_match and setuid_match:
                item_result["status"] = "COMPLIANT"
            else:
                item_result["status"] = "MISMATCH"
                results["mismatched_paths"] += 1
                results["overall_compliant"] = False

        results["paths"][path_str] = item_result

    return results
