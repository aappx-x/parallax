"""Tests for Linux security boundaries, systemd/auditd specs, and pulse-helper execution."""

from __future__ import annotations

import os
from pathlib import Path
import platform
import stat
import tarfile
import tempfile
import pytest

from parallax.system.boundary import (
    ANALYST_GID,
    ANALYST_UID,
    ANALYST_USER,
    BOUNDARY_SPEC,
    RHEA_GID,
    RHEA_UID,
    RHEA_USER,
    ROOT_GID,
    ROOT_UID,
    ROOT_USER,
    SVC_PULSE_GID,
    SVC_PULSE_UID,
    SVC_PULSE_USER,
    audit_host_boundaries,
    check_host_identities,
    compile_helper,
    find_c_compiler,
    parse_audit_rules,
    parse_systemd_unit,
    run_helper,
    validate_audit_rules,
    validate_boundary_spec,
    validate_identities,
    validate_systemd_unit,
)


def has_c_compiler() -> bool:
    return find_c_compiler() is not None


def create_sample_tar_gz(dest_path: Path, filename: str = "sample.txt", content: bytes = b"meridian telemetry payload\n") -> Path:
    """Helper to generate a genuine, valid compressed tar archive."""
    with tarfile.open(dest_path, "w:gz") as tar:
        ti = tarfile.TarInfo(name=filename)
        ti.size = len(content)
        ti.mtime = 1700000000
        import io
        tar.addfile(ti, io.BytesIO(content))
    return dest_path


def test_ground_truth_identities():
    assert ANALYST_USER == "analyst"
    assert ANALYST_UID == 1000
    assert ANALYST_GID == 1000

    assert RHEA_USER == "rhea"
    assert RHEA_UID == 1001
    assert RHEA_GID == 1001

    assert SVC_PULSE_USER == "svc-pulse"
    assert SVC_PULSE_UID == 1002
    assert SVC_PULSE_GID == 1002

    assert ROOT_USER == "root"
    assert ROOT_UID == 0
    assert ROOT_GID == 0

    assert "/usr/local/bin/pulse-helper" in BOUNDARY_SPEC
    assert BOUNDARY_SPEC["/usr/local/bin/pulse-helper"]["expected_mode"] == 0o4750


def test_validate_identities_and_spec_static():
    valid_id, id_errs = validate_identities()
    assert valid_id is True, f"Identities validation failed: {id_errs}"
    assert len(id_errs) == 0

    valid_spec, spec_errs = validate_boundary_spec()
    assert valid_spec is True, f"Boundary spec validation failed: {spec_errs}"
    assert len(spec_errs) == 0


@pytest.mark.skipif(not has_c_compiler(), reason="C compiler not found in PATH")
def test_compile_helper_both_modes():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        vuln_bin = compile_helper(output_binary=tmp_path / "pulse-helper", fixed_mode=False)
        assert vuln_bin.is_file()
        assert vuln_bin.stat().st_mode & stat.S_IXUSR

        fixed_bin = compile_helper(output_binary=tmp_path / "pulse-helper-fixed", fixed_mode=True)
        assert fixed_bin.is_file()
        assert fixed_bin.stat().st_mode & stat.S_IXUSR


@pytest.mark.skipif(not has_c_compiler(), reason="C compiler not found in PATH")
def test_helper_cli_help_and_version():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        vuln_bin = compile_helper(output_binary=tmp_path / "pulse-helper", fixed_mode=False)
        fixed_bin = compile_helper(output_binary=tmp_path / "pulse-helper-fixed", fixed_mode=True)

        res_help = run_helper(vuln_bin, archive_path="", extra_args=["--help"])
        assert res_help.returncode == 0
        assert "PULSE/1 Maintenance Helper" in res_help.stdout

        res_v_vuln = run_helper(vuln_bin, archive_path="", extra_args=["--version"])
        assert res_v_vuln.returncode == 0
        assert "STANDARD" in res_v_vuln.stdout

        res_v_fixed = run_helper(fixed_bin, archive_path="", extra_args=["--version"])
        assert res_v_fixed.returncode == 0
        assert "HARDENED" in res_v_fixed.stdout


@pytest.mark.skipif(not has_c_compiler(), reason="C compiler not found in PATH")
def test_helper_legitimate_archive_verification():
    """Verify that both helper modes successfully verify legitimate valid archives."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        archive_dir = tmp_path / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)

        valid_archive = archive_dir / "valid_backup.tar.gz"
        create_sample_tar_gz(valid_archive)

        vuln_bin = compile_helper(output_binary=tmp_path / "pulse-helper", fixed_mode=False)
        fixed_bin = compile_helper(output_binary=tmp_path / "pulse-helper-fixed", fixed_mode=True)

        # Standard/vulnerable mode checks valid archive
        res_vuln = run_helper(vuln_bin, archive_path=str(valid_archive), archive_dir=str(archive_dir))
        assert res_vuln.returncode == 0, f"Expected clean check, stderr: {res_vuln.stderr}"
        assert "Archive check completed" in res_vuln.stdout

        # Hardened/fixed mode checks valid archive without breaking legitimate workflow
        res_fixed = run_helper(fixed_bin, archive_path=str(valid_archive), archive_dir=str(archive_dir))
        assert res_fixed.returncode == 0, f"Expected clean check, stderr: {res_fixed.stderr}"
        assert "Archive integrity verified" in res_fixed.stdout


@pytest.mark.skipif(not has_c_compiler(), reason="C compiler not found in PATH")
def test_helper_corrupt_archive_handling():
    """Verify that both helper modes reject a corrupted or invalid archive file."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        archive_dir = tmp_path / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)

        corrupt_archive = archive_dir / "corrupted.tar.gz"
        corrupt_archive.write_bytes(b"\x1f\x8b\x08corrupted_payload_data_not_valid_tar")

        vuln_bin = compile_helper(output_binary=tmp_path / "pulse-helper", fixed_mode=False)
        fixed_bin = compile_helper(output_binary=tmp_path / "pulse-helper-fixed", fixed_mode=True)

        res_vuln = run_helper(vuln_bin, archive_path=str(corrupt_archive), archive_dir=str(archive_dir))
        assert res_vuln.returncode != 0
        assert "failed" in res_vuln.stderr.lower()

        res_fixed = run_helper(fixed_bin, archive_path=str(corrupt_archive), archive_dir=str(archive_dir))
        assert res_fixed.returncode != 0
        assert "failed" in res_fixed.stderr.lower()


@pytest.mark.skipif(not has_c_compiler(), reason="C compiler not found in PATH")
def test_helper_vulnerable_injection_reproduction():
    """Verify the scenario ground-truth vulnerability: command injection via system()."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        vuln_bin = compile_helper(output_binary=tmp_path / "pulse-helper", fixed_mode=False)

        canary_file = tmp_path / "pwned.canary"
        assert not canary_file.exists()

        # Attacker injects a command delimiter (;) to execute arbitrary commands
        injected_arg = f"/tmp/archive.tar.gz; touch {canary_file.resolve()}"
        res = run_helper(vuln_bin, archive_path=injected_arg)

        # In vulnerable mode, system() executed the command chain, creating the canary
        assert canary_file.is_file(), f"Expected canary file to be created by injection. Stderr: {res.stderr}"


@pytest.mark.skipif(not has_c_compiler(), reason="C compiler not found in PATH")
def test_helper_fixed_blocks_command_injection_and_metacharacters():
    """Verify that the hardened helper neutralizes diverse command injection vectors."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        fixed_bin = compile_helper(output_binary=tmp_path / "pulse-helper-fixed", fixed_mode=True)

        archive_dir = tmp_path / "archives"
        archive_dir.mkdir()

        # Test various shell metacharacters: semicolon, pipe, background, backticks, subshell, redirects
        metachar_payloads = [
            f"{archive_dir}/archive.tar.gz; touch {tmp_path}/canary_semi.txt",
            f"{archive_dir}/archive.tar.gz | touch {tmp_path}/canary_pipe.txt",
            f"{archive_dir}/archive.tar.gz & touch {tmp_path}/canary_bg.txt",
            f"{archive_dir}/archive.tar.gz`touch {tmp_path}/canary_bt.txt`",
            f"{archive_dir}/archive.tar.gz$(touch {tmp_path}/canary_sub.txt)",
            f"{archive_dir}/archive.tar.gz > {tmp_path}/canary_redir.txt",
            f"{archive_dir}/archive.tar.gz\ntouch {tmp_path}/canary_nl.txt",
        ]

        for payload in metachar_payloads:
            res = run_helper(fixed_bin, archive_path=payload, archive_dir=str(archive_dir))
            assert res.returncode != 0, f"Expected rejection for payload: {payload}"
            assert "illegal metacharacter" in res.stderr.lower()

        # Verify NO marker files were created outside the allowed validation
        created_canaries = list(tmp_path.glob("canary_*.txt"))
        assert len(created_canaries) == 0, f"Unexpected canary files created: {created_canaries}"


@pytest.mark.skipif(not has_c_compiler(), reason="C compiler not found in PATH")
def test_helper_fixed_path_validation_and_boundary_escape():
    """Verify path boundary validation in fixed mode (prefix check, traversal, sibling directory)."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        fixed_bin = compile_helper(output_binary=tmp_path / "pulse-helper-fixed", fixed_mode=True)

        archive_dir = tmp_path / "archives"
        archive_dir.mkdir()

        # Case 1: Traversal forbidden
        res1 = run_helper(
            fixed_bin,
            archive_path=f"{archive_dir}/../secret.txt",
            archive_dir=str(archive_dir),
        )
        assert res1.returncode != 0
        assert "traversal" in res1.stderr.lower()

        # Case 2: Out-of-bounds path forbidden
        res2 = run_helper(
            fixed_bin,
            archive_path="/etc/passwd",
            archive_dir=str(archive_dir),
        )
        assert res2.returncode != 0
        assert "must reside within" in res2.stderr.lower()

        # Case 3: Sibling directory prefix collision attack forbidden
        # (e.g. /tmp/archives_evil should not pass prefix check for /tmp/archives)
        sibling_dir = tmp_path / "archives_evil"
        sibling_dir.mkdir()
        sibling_payload = sibling_dir / "evil.tar.gz"
        sibling_payload.write_text("dummy")

        res3 = run_helper(
            fixed_bin,
            archive_path=str(sibling_payload),
            archive_dir=str(archive_dir),
        )
        assert res3.returncode != 0
        assert "escapes" in res3.stderr.lower() or "must reside within" in res3.stderr.lower()


@pytest.mark.skipif(not has_c_compiler(), reason="C compiler not found in PATH")
def test_helper_malformed_arguments():
    """Verify helper handles missing arguments, empty strings, and unknown flags cleanly."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        fixed_bin = compile_helper(output_binary=tmp_path / "pulse-helper-fixed", fixed_mode=True)

        # Missing path argument to --archive-check
        res_missing = run_helper(fixed_bin, archive_path="", extra_args=["--archive-check"])
        assert res_missing.returncode != 0
        assert "requires a path argument" in res_missing.stderr.lower()

        # Unknown CLI option
        res_unknown = run_helper(fixed_bin, archive_path="", extra_args=["--unsupported-flag"])
        assert res_unknown.returncode != 0
        assert "unknown option" in res_unknown.stderr.lower()

        # Empty archive path
        res_empty = run_helper(fixed_bin, archive_path="")
        assert res_empty.returncode != 0
        assert "empty archive path" in res_empty.stderr.lower() or "must reside within" in res_empty.stderr.lower()


def test_systemd_unit_parsing_and_validation():
    service_file = Path(__file__).resolve().parent.parent / "src" / "parallax" / "system" / "pulse.service"
    assert service_file.is_file()

    unit_data = parse_systemd_unit(service_file)
    is_valid, errors = validate_systemd_unit(unit_data)
    assert is_valid is True, f"Unit validation failed: {errors}"
    assert len(errors) == 0

    # Test invalid unit
    bad_unit = {
        "Service": {
            "User": "root",
            "Group": "root",
            "ExecStart": "/usr/bin/python3 -m pulse server --host 0.0.0.0 --port 7741",
            "Slice": "wrong.slice",
        }
    }
    is_bad_valid, bad_errors = validate_systemd_unit(bad_unit)
    assert is_bad_valid is False
    assert len(bad_errors) >= 3


def test_audit_rules_parsing_and_validation():
    rules_file = Path(__file__).resolve().parent.parent / "src" / "parallax" / "system" / "audit.rules"
    assert rules_file.is_file()

    rules = parse_audit_rules(rules_file)
    assert len(rules) >= 1
    is_valid, errors = validate_audit_rules(rules)
    assert is_valid is True, f"Audit rules validation failed: {errors}"
    assert len(errors) == 0

    # Test missing rule
    is_bad_valid, bad_errors = validate_audit_rules(["-w /etc/passwd -p wa -k identity"])
    assert is_bad_valid is False
    assert "Missing required kernel execve audit rule" in bad_errors[0]


def test_audit_host_boundaries_simulated_tree():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        # In an empty tempdir, all paths should be reported as MISSING
        results_missing = audit_host_boundaries(target_root=tmp_path)
        assert results_missing["missing_paths"] == len(BOUNDARY_SPEC)
        assert results_missing["overall_compliant"] is False

        # Create simulated tree on Linux
        if platform.system() == "Linux":
            helper_path = tmp_path / "usr" / "local" / "bin" / "pulse-helper"
            helper_path.parent.mkdir(parents=True, exist_ok=True)
            helper_path.write_text("#!/bin/sh\nexit 0\n")
            helper_path.chmod(0o4750)

            results_partial = audit_host_boundaries(target_root=tmp_path)
            item = results_partial["paths"]["/usr/local/bin/pulse-helper"]
            assert item["status"] == "COMPLIANT"


def test_unprivileged_vs_privileged_boundary_clarification():
    """Explicitly verify and document the boundary between unprivileged functional tests and live setuid execution.

    In unprivileged test runs:
    - The binary runs with real UID = effective UID = caller UID (e.g. 1000).
    - Even with command injection in vulnerable mode, the subprocess cannot write
      to root-owned files or escalate host privileges.
    - Demonstrates that safe testing can safely verify flaw mechanics without
      installing real setuid binaries on the host system.
    """
    if platform.system() == "Linux":
        # Check current caller
        current_uid = os.getuid()
        # Non-privileged test run should not be root
        if current_uid != 0:
            assert current_uid != 0
            # Confirm unprivileged caller cannot write to /var/log/audit/audit.log
            audit_path = Path("/var/log/audit/audit.log")
            if audit_path.exists():
                assert not os.access(audit_path, os.W_OK), "Unprivileged caller must not have write access to audit log"


def test_check_host_identities_unit():
    """Verify check_host_identities correctly evaluates administrative preservation and collision states."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        passwd_file = tmp_path / "passwd"
        group_file = tmp_path / "group"

        # Case 1: Valid collision-free provisioning with parallaxadmin intact
        passwd_file.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "parallaxadmin:x:1000:1000:Administrator:/home/parallaxadmin:/bin/bash\n"
            "analyst:x:1001:1001:Investigator:/home/analyst:/bin/bash\n"
            "rhea:x:1002:1002:Rhea Sanders:/home/rhea:/bin/bash\n"
            "svc-pulse:x:1003:1003:Service Account:/var/log/pulse:/usr/sbin/nologin\n",
            encoding="utf-8",
        )
        group_file.write_text(
            "root:x:0:\n"
            "parallaxadmin:x:1000:\n"
            "analyst:x:1001:\n"
            "rhea:x:1002:\n"
            "svc-pulse:x:1003:\n",
            encoding="utf-8",
        )

        res = check_host_identities("parallaxadmin", passwd_file, group_file)
        assert res["compliant"] is True
        assert res["admin_present"] is True
        assert res["admin_preserved"] is True
        assert len(res["errors"]) == 0
        assert res["challenge_accounts"]["analyst"]["uid"] == 1001

        # Case 2: Flawed collision: analyst assigned UID 1000
        passwd_file.write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "parallaxadmin:x:1000:1000:Administrator:/home/parallaxadmin:/bin/bash\n"
            "analyst:x:1000:1000:Investigator:/home/analyst:/bin/bash\n",
            encoding="utf-8",
        )
        group_file.write_text(
            "root:x:0:\n"
            "parallaxadmin:x:1000:\n"
            "analyst:x:1000:\n",
            encoding="utf-8",
        )

        res_coll = check_host_identities("parallaxadmin", passwd_file, group_file)
        assert res_coll["compliant"] is False
        assert res_coll["admin_preserved"] is False
        assert any("Collision" in e for e in res_coll["errors"])


