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


def find_c_compiler(preferred: str | None = None) -> str | None:
    """Find an available C compiler in PATH."""
    candidates = [preferred] if preferred else ["cc", "gcc", "clang"]
    for cand in candidates:
        if cand and shutil.which(cand):
            return cand
    return None


def compile_helper(
    source_file: str | Path | None = None,
    output_binary: str | Path | None = None,
    fixed_mode: bool = False,
    cc: str | None = None,
) -> Path:
    """Compile pulse-helper from C source.

    Args:
        source_file: Path to pulse-helper.c. Defaults to src/helper/pulse-helper.c.
        output_binary: Path to destination binary. Defaults to adjacent binary name.
        fixed_mode: If True, compiles with -DFIXED_MODE (hardened).
        cc: Optional C compiler command (default: checks cc, gcc, clang in order).

    Returns:
        Path to compiled binary.

    Raises:
        FileNotFoundError: If source file or compiler cannot be found.
        RuntimeError: If compilation fails.
    """
    src = Path(source_file) if source_file else DEFAULT_C_SOURCE
    if not src.is_file():
        raise FileNotFoundError(f"C source file not found at: {src}")

    compiler = find_c_compiler(cc)
    if not compiler:
        raise FileNotFoundError(f"C compiler '{cc or 'cc'}' not found in PATH")

    if output_binary:
        out = Path(output_binary)
    else:
        out_name = "pulse-helper-fixed" if fixed_mode else "pulse-helper"
        out = src.parent / out_name

    out.parent.mkdir(parents=True, exist_ok=True)

    cmd = [compiler, "-Wall", "-Wextra", "-O2", "-std=c99"]
    if fixed_mode:
        cmd.extend(["-DFIXED_MODE", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2"])
    cmd.extend(["-o", str(out), str(src)])

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Compilation failed (code {proc.returncode}):\n{proc.stderr}\n{proc.stdout}"
        )

    out.chmod(0o0755)
    return out


def validate_identities() -> tuple[bool, list[str]]:
    """Statically validate ground-truth user and group identity definitions."""
    errors: list[str] = []
    identities = [
        ("analyst", ANALYST_UID, ANALYST_GID),
        ("rhea", RHEA_UID, RHEA_GID),
        ("svc-pulse", SVC_PULSE_UID, SVC_PULSE_GID),
        ("root", ROOT_UID, ROOT_GID),
    ]
    uids = [uid for _, uid, _ in identities]
    gids = [gid for _, _, gid in identities]
    if len(set(uids)) != len(uids):
        errors.append("Duplicate UID detected among ground-truth identities")
    if len(set(gids)) != len(gids):
        errors.append("Duplicate GID detected among ground-truth identities")
    return (len(errors) == 0, errors)


def validate_boundary_spec() -> tuple[bool, list[str]]:
    """Statically validate the security boundary specification for consistency."""
    errors: list[str] = []
    for path, spec in BOUNDARY_SPEC.items():
        if not path.startswith("/"):
            errors.append(f"Path '{path}' must be absolute")
        mode = spec.get("expected_mode")
        if mode is None or not isinstance(mode, int):
            errors.append(f"Path '{path}' has invalid or missing expected_mode")
        if not spec.get("expected_owner"):
            errors.append(f"Path '{path}' missing expected_owner")
        if not spec.get("expected_group"):
            errors.append(f"Path '{path}' missing expected_group")

    # Verify helper permissions match service identity requirements
    helper_spec = BOUNDARY_SPEC.get("/usr/local/bin/pulse-helper")
    if helper_spec:
        if helper_spec["expected_group"] != SVC_PULSE_USER:
            errors.append(
                f"Helper expected group must be '{SVC_PULSE_USER}', got '{helper_spec['expected_group']}'"
            )
        mode = helper_spec["expected_mode"]
        if not (mode & 0o4000):
            errors.append("Helper mode must have setuid bit (0o4000)")
        if not (mode & 0o0010):
            errors.append("Helper mode must allow group execution for svc-pulse")
        if (mode & 0o0007) != 0:
            errors.append("Helper mode must deny all permissions to other users (world)")

    # Verify archive directory is restricted
    archive_spec = BOUNDARY_SPEC.get("/var/archive/meridian")
    if archive_spec:
        if archive_spec["expected_mode"] != 0o0700:
            errors.append("Archive directory must be restricted to mode 0700")

    # Verify audit log is root-restricted
    audit_spec = BOUNDARY_SPEC.get("/var/log/audit/audit.log")
    if audit_spec:
        if audit_spec["expected_mode"] != 0o0640:
            errors.append("Audit log must have mode 0640")

    return (len(errors) == 0, errors)


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


def check_host_identities(
    admin_user: str = "parallaxadmin",
    passwd_path: str | Path | None = None,
    group_path: str | Path | None = None,
) -> dict[str, Any]:
    """Inspect user and group definitions to verify safe challenge provisioning.

    Verifies:
    - Administrator account (e.g. parallaxadmin) is preserved intact if present.
    - Challenge accounts (analyst, rhea, svc-pulse) have unique, non-conflicting IDs.
    - No challenge account collides with the administrator account's UID or GID.

    Args:
        admin_user: Name of administrator account to verify (default: 'parallaxadmin').
        passwd_path: Optional path to custom/mock passwd file.
        group_path: Optional path to custom/mock group file.

    Returns:
        Dictionary detailing identity status, collisions, and compliance.
    """
    users: dict[str, dict[str, Any]] = {}
    groups: dict[str, int] = {}

    if passwd_path:
        p_path = Path(passwd_path)
        if p_path.is_file():
            for line in p_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(":")
                    if len(parts) >= 7:
                        try:
                            users[parts[0]] = {
                                "uid": int(parts[2]),
                                "gid": int(parts[3]),
                                "gecos": parts[4],
                                "home": parts[5],
                                "shell": parts[6],
                            }
                        except ValueError:
                            pass
    else:
        try:
            import pwd
            for entry in pwd.getpwall():
                users[entry.pw_name] = {
                    "uid": entry.pw_uid,
                    "gid": entry.pw_gid,
                    "gecos": entry.pw_gecos,
                    "home": entry.pw_dir,
                    "shell": entry.pw_shell,
                }
        except (ImportError, AttributeError):
            pass

    if group_path:
        g_path = Path(group_path)
        if g_path.is_file():
            for line in g_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(":")
                    if len(parts) >= 3:
                        try:
                            groups[parts[0]] = int(parts[2])
                        except ValueError:
                            pass
    else:
        try:
            import grp
            for entry in grp.getgrall():
                groups[entry.gr_name] = entry.gr_gid
        except (ImportError, AttributeError):
            pass

    errors: list[str] = []
    admin_info = users.get(admin_user)

    challenge_users = [ANALYST_USER, RHEA_USER, SVC_PULSE_USER]
    present_challenge_uids: list[int] = []
    present_challenge_gids: list[int] = []

    for cuser in challenge_users:
        if cuser in users:
            cuid = users[cuser]["uid"]
            cgid = users[cuser]["gid"]
            if admin_info:
                if cuid == admin_info["uid"]:
                    errors.append(f"Collision: challenge user '{cuser}' shares UID {cuid} with '{admin_user}'")
                if cgid == admin_info["gid"]:
                    errors.append(f"Collision: challenge user '{cuser}' shares GID {cgid} with '{admin_user}'")
            present_challenge_uids.append(cuid)
            present_challenge_gids.append(cgid)

    if len(set(present_challenge_uids)) != len(present_challenge_uids):
        errors.append("Duplicate UID detected among active challenge accounts")
    if len(set(present_challenge_gids)) != len(present_challenge_gids):
        errors.append("Duplicate GID detected among active challenge accounts")

    return {
        "admin_present": admin_info is not None,
        "admin_user": admin_user,
        "admin_uid": admin_info["uid"] if admin_info else None,
        "admin_gid": admin_info["gid"] if admin_info else None,
        "admin_preserved": admin_info is not None and len(errors) == 0,
        "challenge_accounts": {
            u: users[u] for u in challenge_users if u in users
        },
        "compliant": len(errors) == 0,
        "errors": errors,
    }

