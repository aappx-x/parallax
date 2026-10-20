"""Tests for repeatable lab verification suite."""

from __future__ import annotations

import sys
from unittest.mock import patch

from parallax.verify import LabVerifier, run_verification


def test_verify_environment():
    verifier = LabVerifier()
    res = verifier.verify_environment()
    assert res.passed is True
    assert "OS=" in res.details
    assert "Python=" in res.details
    assert "parallax=" in res.details


def test_verify_server_lifecycle():
    verifier = LabVerifier()
    res = verifier.verify_server_lifecycle()
    assert res.passed is True
    assert "Clean startup" in res.details


def test_verify_vulnerable_flaw():
    verifier = LabVerifier()
    res = verifier.verify_vulnerable_flaw()
    assert res.passed is True
    assert "helper_path=" in res.details


def test_verify_corrected_defense():
    verifier = LabVerifier()
    res = verifier.verify_corrected_defense()
    assert res.passed is True
    assert "403" in res.details


def test_verify_manifest_subsystem():
    verifier = LabVerifier()
    res = verifier.verify_manifest_subsystem()
    assert res.passed is True


def test_verify_workspace_evidence():
    verifier = LabVerifier()
    res = verifier.verify_workspace_evidence()
    assert res.passed is True
    assert "verified against SHA-256 manifest" in res.details


def test_verify_privileged_helper():
    verifier = LabVerifier()
    res = verifier.verify_privileged_helper()
    assert res.passed is True
    assert "C helper compiled cleanly" in res.details


def test_verify_linux_boundaries():
    verifier = LabVerifier()
    res = verifier.verify_linux_boundaries()
    assert res.passed is True
    assert "Specs valid" in res.details


def test_run_verification_runner():
    exit_code = run_verification(host="127.0.0.1", verbose=False)
    assert exit_code == 0


def test_pulse_cli_verify_subcommand():
    from parallax.pulse.__main__ import main

    test_args = ["parallax.pulse", "verify"]
    with patch.object(sys, "argv", test_args):
        ret = main()
        assert ret == 0
