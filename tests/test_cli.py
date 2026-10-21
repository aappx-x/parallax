"""Tests for the PARALLAX terminal CLI interface."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch
import pytest

from parallax.cli import main
from parallax.evidence import FULL_VAULT_PASSPHRASE, VAULT_PLAINTEXT_HEADER, generate_encrypted_vault


class TestCLIInterface:
    """Test CLI commands and command-line execution."""

    def test_cli_help(self, capsys):
        ret = main([])
        assert ret == 0
        captured = capsys.readouterr()
        assert "PARALLAX" in captured.out or "usage:" in captured.out

    def test_cli_list_command(self, capsys):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p_file = Path(tmp_dir) / ".progress.json"
            ret = main(["--progress-file", str(p_file), "list"])
            assert ret == 0
            captured = capsys.readouterr()
            assert "P01" in captured.out
            assert "P15" in captured.out
            assert "0/15 objectives completed" in captured.out

    def test_cli_inspect_command(self, capsys):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p_file = Path(tmp_dir) / ".progress.json"
            ret = main(["--progress-file", str(p_file), "inspect", "P01"])
            assert ret == 0
            captured = capsys.readouterr()
            assert "Objective P01: Service Port Discovery" in captured.out
            assert "Question:" in captured.out
            assert "7741" in captured.out

    def test_cli_submit_rejection_and_success(self, capsys):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p_file = Path(tmp_dir) / ".progress.json"

            # Rejected submission
            ret_bad = main([
                "--progress-file", str(p_file),
                "submit", "P01",
                "--evidence", "EV-CFG-001",
                "--answer", "wrong port 9999",
            ])
            assert ret_bad == 1
            captured_bad = capsys.readouterr()
            assert "Submission Rejected" in captured_bad.out

            # Accepted submission
            ret_good = main([
                "--progress-file", str(p_file),
                "submit", "P01",
                "--evidence", "EV-CFG-001",
                "--answer", "daemon was listening on TCP 7741",
            ])
            assert ret_good == 0
            captured_good = capsys.readouterr()
            assert "Objective P01 COMPLETED!" in captured_good.out

    def test_cli_report_locked_then_unlocked(self, capsys):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p_file = Path(tmp_dir) / ".progress.json"

            # Report locked initially
            ret_locked = main(["--progress-file", str(p_file), "report"])
            assert ret_locked == 1
            captured_locked = capsys.readouterr()
            assert "Final Verdict is LOCKED" in captured_locked.out

    def test_cli_reset_command(self, capsys):
        with tempfile.TemporaryDirectory() as tmp_dir:
            p_file = Path(tmp_dir) / ".progress.json"

            # Submit P01
            main([
                "--progress-file", str(p_file),
                "submit", "P01",
                "--evidence", "EV-CFG-001",
                "--answer", "port 7741",
            ])
            assert p_file.is_file()

            # Reset
            ret = main(["--progress-file", str(p_file), "reset"])
            assert ret == 0
            captured = capsys.readouterr()
            assert "has been reset" in captured.out
            assert not p_file.is_file()

    def test_cli_decrypt_command(self, capsys):
        with tempfile.TemporaryDirectory() as tmp_dir:
            vault_file = Path(tmp_dir) / "test_vault.enc"
            vault_file.write_bytes(generate_encrypted_vault())

            # Decrypt preview
            ret = main(["decrypt", str(vault_file), "--key", FULL_VAULT_PASSPHRASE])
            assert ret == 0
            captured = capsys.readouterr()
            assert "Decryption successful!" in captured.out
            assert VAULT_PLAINTEXT_HEADER in captured.out

            # Decrypt to file
            out_file = Path(tmp_dir) / "decrypted.tar"
            ret_out = main(["decrypt", str(vault_file), "--key", FULL_VAULT_PASSPHRASE, "--output", str(out_file)])
            assert ret_out == 0
            assert out_file.is_file()
            assert VAULT_PLAINTEXT_HEADER.encode("utf-8") in out_file.read_bytes()
