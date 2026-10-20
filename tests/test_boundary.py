"""Tests for Linux security boundaries, systemd/auditd specs, and pulse-helper execution."""

from __future__ import annotations

from pathlib import Path
import stat
import tempfile
import pytest

from parallax.system.boundary import (
    ANALYST_USER,
    BOUNDARY_SPEC,
    RHEA_USER,
    SVC_PULSE_USER,
    audit_host_boundaries,
    compile_helper,
    parse_audit_rules,
    parse_systemd_unit,
    run_helper,
    validate_audit_rules,
    validate_systemd_unit,
)


def test_ground_truth_identities():
    assert ANALYST_USER == "analyst"
    assert RHEA_USER == "rhea"
    assert SVC_PULSE_USER == "svc-pulse"
    assert "/usr/local/bin/pulse-helper" in BOUNDARY_SPEC
    assert BOUNDARY_SPEC["/usr/local/bin/pulse-helper"]["expected_mode"] == 0o4750


def test_compile_helper_both_modes():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        vuln_bin = compile_helper(output_binary=tmp_path / "pulse-helper", fixed_mode=False)
        assert vuln_bin.is_file()
        assert vuln_bin.stat().st_mode & stat.S_IXUSR

        fixed_bin = compile_helper(output_binary=tmp_path / "pulse-helper-fixed", fixed_mode=True)
        assert fixed_bin.is_file()
        assert fixed_bin.stat().st_mode & stat.S_IXUSR


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


def test_helper_fixed_blocks_command_injection():
    """Verify that the hardened helper neutralizes the command injection vector."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        fixed_bin = compile_helper(output_binary=tmp_path / "pulse-helper-fixed", fixed_mode=True)

        canary_file = tmp_path / "pwned.canary"
        assert not canary_file.exists()

        archive_dir = tmp_path / "archives"
        archive_dir.mkdir()

        # Attacker attempts shell metacharacter injection
        injected_arg = f"{archive_dir}/archive.tar.gz; touch {canary_file.resolve()}"
        res = run_helper(
            fixed_bin,
            archive_path=injected_arg,
            archive_dir=str(archive_dir),
        )

        assert res.returncode != 0
        assert not canary_file.exists(), "Hardened helper must not execute injected command"
        assert "illegal metacharacter" in res.stderr.lower()


def test_helper_fixed_path_validation():
    """Verify path boundary validation in fixed mode (prefix check and traversal check)."""
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

        # Create one compliant file (simulating correct mode)
        helper_path = tmp_path / "usr" / "local" / "bin" / "pulse-helper"
        helper_path.parent.mkdir(parents=True, exist_ok=True)
        helper_path.write_text("#!/bin/sh\nexit 0\n")
        helper_path.chmod(0o4750)

        results_partial = audit_host_boundaries(target_root=tmp_path)
        item = results_partial["paths"]["/usr/local/bin/pulse-helper"]
        assert item["status"] == "COMPLIANT"
